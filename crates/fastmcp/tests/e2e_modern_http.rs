//! Public modern HTTP round trip: shipped client against shipped server.
//!
//! Both ends of these tests are real shipped surfaces — the turnkey
//! `Server::bind_http`/`serve` lifecycle on one side and facade client
//! connection lifecycles on the other — joined over one real localhost socket.
//! The fixture uses the lower server builder only to select the explicit
//! Auto, ModernOnly, or LegacyOnly server policy under test; no scripted peer,
//! fixture transcript, or mock stands in for either endpoint.
//!
//! What this proves (and only this): the shipped dual-era HTTP server and
//! facade clients can complete Auto classification plus typed ModernOnly and
//! LegacyOnly tool, resource, and prompt round trips against each other. The
//! cross-era refusal cases additionally prove that a rejected connection does
//! not change later matched-era handler observables. It is not an aggregate
//! MCP 2026-07-28 conformance claim.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fastmcp_rust::{
    CanonicalHttpUrl, ClientHttpConnectionError, ClientHttpResponse, ClientProtocolPlan, Content,
    Cx, HttpNonquiescentShutdown, HttpServerShutdown, HttpShutdownSettlement, JsonRpcMessage,
    JsonRpcRequest, McpContext, McpError, McpResult, Middleware, MiddlewareDecision,
    ModernHttpResponseKind, ModernHttpResponseStream, PromptHandler, PromptMessage, ProtocolEra,
    ProtocolPolicy, ResourceHandler, Role, SseLimits, ToolHandler, auto, core, legacy_2024, modern,
    prompt, resource, tool,
};
use fastmcp_server::ServerBuilder;
use serde_json::json;

const PUBLIC_HTTP_TOOL_NAME: &str = "public-http-e2e-tool";
const PUBLIC_HTTP_RESOURCE_URI: &str = "test://public-http-e2e/resource";
const PUBLIC_HTTP_PROMPT_NAME: &str = "public-http-e2e-prompt";
const PUBLIC_HTTP_TOOL_ARGUMENT: &str = "cross-era";
const PUBLIC_HTTP_TOOL_TEXT: &str = "tool:cross-era";
const PUBLIC_HTTP_RESOURCE_TEXT: &str = "resource:deterministic";
const PUBLIC_HTTP_PROMPT_TEXT: &str = "prompt:cross-era";

/// The deterministic user handler exercised through both public HTTP facades.
#[tool(name = "public-http-e2e-tool")]
fn public_http_value(_ctx: &McpContext, value: String) -> String {
    format!("tool:{value}")
}

/// The deterministic resource exercised through both public HTTP facades.
#[resource(uri = "test://public-http-e2e/resource")]
fn public_http_snapshot(_ctx: &McpContext) -> String {
    PUBLIC_HTTP_RESOURCE_TEXT.to_owned()
}

/// The deterministic prompt exercised through both public HTTP facades.
#[prompt(name = "public-http-e2e-prompt")]
fn public_http_instruction(_ctx: &McpContext, subject: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("prompt:{subject}"),
        },
    }]
}

#[derive(Default)]
struct PublicHttpHandlerCallCounters {
    tool: AtomicUsize,
    resource: AtomicUsize,
    prompt: AtomicUsize,
}

#[derive(Debug, Eq, PartialEq)]
struct PublicHttpHandlerCallSnapshot {
    tool: usize,
    resource: usize,
    prompt: usize,
}

impl PublicHttpHandlerCallCounters {
    fn snapshot(&self) -> PublicHttpHandlerCallSnapshot {
        PublicHttpHandlerCallSnapshot {
            tool: self.tool.load(Ordering::SeqCst),
            resource: self.resource.load(Ordering::SeqCst),
            prompt: self.prompt.load(Ordering::SeqCst),
        }
    }
}

struct CountingPublicHttpValue {
    counters: Arc<PublicHttpHandlerCallCounters>,
}

impl ToolHandler for CountingPublicHttpValue {
    fn definition(&self) -> fastmcp_rust::Tool {
        PublicHttpValue.definition()
    }

    fn call(&self, context: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        self.counters.tool.fetch_add(1, Ordering::SeqCst);
        PublicHttpValue.call(context, arguments)
    }
}

struct CountingPublicHttpSnapshot {
    counters: Arc<PublicHttpHandlerCallCounters>,
}

impl ResourceHandler for CountingPublicHttpSnapshot {
    fn definition(&self) -> fastmcp_rust::Resource {
        PublicHttpSnapshotResource.definition()
    }

    fn read(&self, context: &McpContext) -> McpResult<Vec<fastmcp_rust::ResourceContent>> {
        self.counters.resource.fetch_add(1, Ordering::SeqCst);
        PublicHttpSnapshotResource.read(context)
    }
}

struct CountingPublicHttpInstruction {
    counters: Arc<PublicHttpHandlerCallCounters>,
}

impl PromptHandler for CountingPublicHttpInstruction {
    fn definition(&self) -> fastmcp_rust::Prompt {
        PublicHttpInstructionPrompt.definition()
    }

    fn get(
        &self,
        context: &McpContext,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        self.counters.prompt.fetch_add(1, Ordering::SeqCst);
        PublicHttpInstructionPrompt.get(context, arguments)
    }
}

fn runtime_block_on<F: std::future::Future>(future: F) -> F::Output {
    core::block_on(future)
}

/// Runs one public HTTP operation on the facade-owned runtime. The operation
/// itself is bounded against the supplied caller-owned context clock, so a
/// stalled peer cannot hold this test thread indefinitely.
fn runtime_block_on_bounded<F: std::future::Future>(cx: &Cx, future: F) -> F::Output {
    runtime_block_on(async {
        asupersync::time::timeout(cx.now(), HTTP_OPERATION_BOUND, future)
            .await
            .expect("public HTTP operation stays within its caller-owned deadline")
    })
}

const HTTP_SERVER_STARTUP_BOUND: Duration = Duration::from_secs(2);
const HTTP_SERVER_TEARDOWN_BOUND: Duration = Duration::from_secs(2);
const HTTP_OPERATION_BOUND: Duration = Duration::from_secs(2);

/// Owns one real public HTTP server composition and proves its teardown.
///
/// The fixture composes one policy-selected server with deterministic public
/// tool, resource, and prompt handlers. Its clients use only shipped facade
/// HTTP clients and real localhost routes; no transcript or mock peer is
/// involved.
struct HttpServerFixture {
    address: SocketAddr,
    server_cx: Cx,
    finished: mpsc::Receiver<Result<HttpServerShutdown, String>>,
    shutdown_completion: Option<Result<HttpServerShutdown, String>>,
    join: Option<JoinHandle<()>>,
    nonquiescent: Option<HttpNonquiescentShutdown>,
    handler_calls: Arc<PublicHttpHandlerCallCounters>,
}

/// Retains a just-spawned fixture until the ready handshake succeeds and it
/// can be transferred into `HttpServerFixture`.
struct HttpServerStartupGuard {
    server_cx: Option<Cx>,
    server_cx_rx: Option<mpsc::Receiver<Cx>>,
    finished: Option<mpsc::Receiver<Result<HttpServerShutdown, String>>>,
    join: Option<JoinHandle<()>>,
}

impl HttpServerStartupGuard {
    fn capture_server_cx(&mut self) {
        if self.server_cx.is_some() {
            return;
        }
        let Some(server_cx_rx) = self.server_cx_rx.as_ref() else {
            return;
        };
        if let Ok(server_cx) = server_cx_rx.try_recv() {
            self.server_cx = Some(server_cx);
            self.server_cx_rx = None;
        }
    }

    fn into_parts(
        mut self,
    ) -> (
        Cx,
        mpsc::Receiver<Result<HttpServerShutdown, String>>,
        Option<JoinHandle<()>>,
    ) {
        (
            self.server_cx
                .take()
                .expect("startup guard retains the runtime-installed server context"),
            self.finished
                .take()
                .expect("startup guard retains completion"),
            self.join.take(),
        )
    }

    fn resume_thread_panic_if_finished(&mut self) {
        let Some(handle) = self.join.as_ref() else {
            return;
        };
        if !handle.is_finished() {
            return;
        }
        let handle = self
            .join
            .take()
            .expect("finished startup thread retains its join handle");
        if let Err(payload) = handle.join() {
            std::panic::resume_unwind(payload);
        }
    }
}

impl Drop for HttpServerStartupGuard {
    fn drop(&mut self) {
        if self.join.is_none() {
            return;
        }
        self.capture_server_cx();
        // If the context has not arrived yet, dropping this receiver makes
        // the server task fail closed before it binds a listener.
        self.server_cx_rx = None;
        if let Some(server_cx) = self.server_cx.as_ref() {
            server_cx.set_cancel_requested(true);
        }
        let Some(finished) = self.finished.as_ref() else {
            return;
        };
        let mut shutdown_completion = None;
        let settlement =
            await_http_server_shutdown(finished, &mut shutdown_completion, &mut self.join);
        if settlement.is_err() && self.join.is_some() {
            eprintln!(
                "public HTTP server startup left a live unjoinable thread after bounded settlement"
            );
            std::process::abort();
        }
    }
}

impl HttpServerFixture {
    fn spawn() -> Self {
        Self::spawn_with_policy(ProtocolPolicy::Auto)
    }

    fn spawn_with_policy(protocol_policy: ProtocolPolicy) -> Self {
        Self::spawn_with_policy_and_middleware(protocol_policy, None)
    }

    fn spawn_with_middleware(middleware: Option<Arc<dyn Middleware>>) -> Self {
        Self::spawn_with_policy_and_middleware(ProtocolPolicy::Auto, middleware)
    }

    fn spawn_with_policy_and_middleware(
        protocol_policy: ProtocolPolicy,
        middleware: Option<Arc<dyn Middleware>>,
    ) -> Self {
        let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
        let tool_calls = Arc::clone(&handler_calls);
        let resource_calls = Arc::clone(&handler_calls);
        let prompt_calls = Arc::clone(&handler_calls);
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
        let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
        let (finished_tx, finished_rx) =
            mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
        let join = Some(thread::spawn(move || {
            let ready_for_spawn_failure = ready_tx.clone();
            let finished_for_spawn_failure = finished_tx.clone();
            let outcome = runtime_block_on(async move {
                let cx = Cx::current().expect("facade runtime installs an ambient server context");
                if server_cx_tx.send(cx.clone()).is_err() {
                    cx.set_cancel_requested(true);
                    return Err("HTTP E2E server control receiver went away".to_owned());
                }
                let builder = ServerBuilder::new("facade-http-example", "1.0.0")
                    .protocol_policy(protocol_policy)
                    .expect("the fixture selects an available protocol policy");
                let builder = builder
                    .tool(CountingPublicHttpValue {
                        counters: tool_calls,
                    })
                    .resource(CountingPublicHttpSnapshot {
                        counters: resource_calls,
                    })
                    .prompt(CountingPublicHttpInstruction {
                        counters: prompt_calls,
                    });
                let server = match middleware {
                    Some(middleware) => builder.middleware(middleware).build(),
                    None => builder.build(),
                };
                let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                    Ok(bound) => bound,
                    Err(error) => {
                        let message = format!("facade HTTP server bind failed: {error}");
                        let _ = ready_tx.send(Err(message.clone()));
                        return Err(message);
                    }
                };
                let address = match bound.local_addr() {
                    Ok(address) => address,
                    Err(error) => {
                        let message = format!("facade HTTP server address failed: {error}");
                        let _ = ready_tx.send(Err(message.clone()));
                        return Err(message);
                    }
                };
                if ready_tx.send(Ok(address)).is_err() {
                    cx.set_cancel_requested(true);
                    return Err("HTTP E2E startup receiver went away".to_owned());
                }
                bound
                    .serve(&cx)
                    .await
                    .map_err(|error| format!("facade HTTP server stopped unexpectedly: {error}"))
            });
            if let Err(message) = &outcome {
                let _ = ready_for_spawn_failure.send(Err(message.clone()));
            }
            let _ = finished_for_spawn_failure.send(outcome);
        }));

        let mut startup = HttpServerStartupGuard {
            server_cx: None,
            server_cx_rx: Some(server_cx_rx),
            finished: Some(finished_rx),
            join,
        };
        let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
        let address = loop {
            startup.capture_server_cx();
            let remaining = startup_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!("public HTTP server startup exceeded its bound");
            }
            match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
                Ok(Ok(address)) => break address,
                Ok(Err(error)) => panic!("public HTTP server failed to start: {error}"),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    startup.resume_thread_panic_if_finished();
                    panic!("public HTTP server startup readiness channel disconnected")
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        };
        startup.capture_server_cx();
        let (server_cx, finished, join) = startup.into_parts();

        Self {
            address,
            server_cx,
            finished,
            shutdown_completion: None,
            join,
            nonquiescent: None,
            handler_calls,
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn handler_call_snapshot(&self) -> PublicHttpHandlerCallSnapshot {
        self.handler_calls.snapshot()
    }

    fn settle(&mut self) -> Result<(), String> {
        if let Some(shutdown) = self.nonquiescent.as_mut() {
            return match runtime_block_on(shutdown.settle_for(HTTP_SERVER_TEARDOWN_BOUND)) {
                HttpShutdownSettlement::Settled => {
                    self.nonquiescent = None;
                    Err("facade HTTP server stopped nonquiescently but settled during fixture cleanup"
                        .to_owned())
                }
                HttpShutdownSettlement::Failed { failures } => Err(format!(
                    "facade HTTP server child settlement observed {failures} terminal failure(s)"
                )),
                HttpShutdownSettlement::Pending { remaining } => Err(format!(
                    "facade HTTP server remains nonquiescent after bounded fixture cleanup ({remaining} retained children)"
                )),
            };
        }
        self.server_cx.set_cancel_requested(true);
        match await_http_server_shutdown(
            &self.finished,
            &mut self.shutdown_completion,
            &mut self.join,
        )? {
            HttpServerShutdown::Quiescent => Ok(()),
            HttpServerShutdown::Nonquiescent(shutdown) => {
                self.nonquiescent = Some(shutdown);
                self.settle()
            }
        }
    }

    fn shutdown(mut self) {
        self.settle()
            .unwrap_or_else(|error| panic!("public HTTP server teardown failed: {error}"));
    }
}

impl Drop for HttpServerFixture {
    fn drop(&mut self) {
        if self.join.is_none() && self.nonquiescent.is_none() {
            return;
        }
        if let Err(error) = self.settle() {
            eprintln!("public HTTP server fixture drop failed: {error}");
            // A `JoinHandle` dropped after a failed bounded settlement detaches
            // a live server. Aborting is fail-closed in both normal and panic
            // unwinding paths, after shutdown has already been requested.
            std::process::abort();
        }
    }
}

/// Signals shutdown without blocking, waits for the owned thread's bounded
/// completion report, then joins only after the thread is known to have exited.
/// A timed-out owner remains retained for a controlled retry rather than being
/// detached.
fn await_http_server_shutdown(
    finished: &mpsc::Receiver<Result<HttpServerShutdown, String>>,
    completion: &mut Option<Result<HttpServerShutdown, String>>,
    join: &mut Option<JoinHandle<()>>,
) -> Result<HttpServerShutdown, String> {
    let completion_result = if completion.is_some() {
        Ok(())
    } else {
        finished
            .recv_timeout(HTTP_SERVER_TEARDOWN_BOUND)
            .map(|shutdown| *completion = Some(shutdown))
            .map_err(|error| format!("public HTTP server teardown exceeded its bound: {error}"))
    };
    let join_result = join_finished_thread(join, HTTP_SERVER_TEARDOWN_BOUND, "HTTP server");
    match (completion_result, join_result) {
        (Ok(()), Ok(())) => match completion
            .take()
            .expect("a completed server shutdown retains its completion report")
        {
            Ok(shutdown) => Ok(shutdown),
            Err(completion) => Err(format!("public HTTP server teardown failed: {completion}")),
        },
        (Ok(()), Err(join)) => Err(join),
        (Err(completion), Ok(())) => Err(completion),
        (Err(completion), Err(join)) => Err(format!(
            "{completion}; owned thread settlement failed: {join}"
        )),
    }
}

/// This helper is separately bounded so planted timeout tests can prove that
/// both an unread completion and a received-but-unjoined completion retain
/// their owner for a later controlled retry.
fn settle_http_server_with_bound(
    shutdown: &mpsc::SyncSender<()>,
    finished: &mpsc::Receiver<Result<(), String>>,
    completion: &mut Option<Result<(), String>>,
    join: &mut Option<JoinHandle<()>>,
    completion_bound: Duration,
) -> Result<(), String> {
    match shutdown.try_send(()) {
        Ok(()) | Err(mpsc::TrySendError::Full(())) | Err(mpsc::TrySendError::Disconnected(())) => {}
    }
    let completion_result = if completion.is_some() {
        Ok(())
    } else {
        finished
            .recv_timeout(completion_bound)
            .map(|reported_completion| *completion = Some(reported_completion))
            .map_err(|error| format!("public HTTP server teardown exceeded its bound: {error}"))
    };
    let join_result = join_finished_thread(join, completion_bound, "HTTP server");
    match (completion_result, join_result) {
        (Ok(()), Ok(())) => match completion
            .take()
            .expect("a completed server shutdown retains its completion report")
        {
            Ok(()) => Ok(()),
            Err(completion) => Err(format!("public HTTP server teardown failed: {completion}")),
        },
        (Ok(()), Err(join)) => Err(join),
        (Err(completion), Ok(())) => Err(completion),
        (Err(completion), Err(join)) => Err(format!(
            "{completion}; owned thread settlement failed: {join}"
        )),
    }
}

fn join_finished_thread(
    join: &mut Option<JoinHandle<()>>,
    completion_bound: Duration,
    owner: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + completion_bound;
    loop {
        let Some(handle) = join.as_ref() else {
            return Ok(());
        };
        if handle.is_finished() {
            return join
                .take()
                .expect("completed thread retains its join handle")
                .join()
                .map_err(|_| format!("{owner} thread panicked during settlement"));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{owner} reported completion but did not exit within its bounded settlement window"
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn e2e_http_fixture_planted_teardown_timeout_retains_owner_for_controlled_retry() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (shutdown_tx, shutdown_rx) = mpsc::sync_channel::<()>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let joined = Arc::new(AtomicBool::new(false));
    let joined_by_server = Arc::clone(&joined);
    let mut completion = None;
    let mut server = Some(thread::spawn(move || {
        shutdown_rx
            .recv()
            .expect("the bounded settlement path sends one shutdown signal");
        release_rx
            .recv()
            .expect("the test releases the planted server after the deadline");
        joined_by_server.store(true, Ordering::SeqCst);
        let _ = finished_tx.send(Ok(()));
    }));

    let settlement = settle_http_server_with_bound(
        &shutdown_tx,
        &finished_rx,
        &mut completion,
        &mut server,
        Duration::ZERO,
    );

    assert!(
        !joined.load(Ordering::SeqCst),
        "a timeout must not make an unbounded join attempt"
    );
    assert!(matches!(settlement, Err(error) if error.contains("exceeded its bound")));
    assert!(
        server.is_some(),
        "the timed-out owner stays retained for an explicit controlled retry"
    );
    release_tx
        .send(())
        .expect("the retained server remains controllable after its deadline");
    settle_http_server_with_bound(
        &shutdown_tx,
        &finished_rx,
        &mut completion,
        &mut server,
        HTTP_SERVER_TEARDOWN_BOUND,
    )
    .expect("the released server settles without detaching its owner");
    assert!(joined.load(Ordering::SeqCst));
    assert!(server.is_none(), "settlement joins the retained owner");
}

#[test]
fn e2e_http_fixture_post_completion_join_timeout_retains_completion_for_retry() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (shutdown_tx, shutdown_rx) = mpsc::sync_channel::<()>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let (completion_reported_tx, completion_reported_rx) = mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let joined = Arc::new(AtomicBool::new(false));
    let joined_by_server = Arc::clone(&joined);
    let mut completion = None;
    let mut server = Some(thread::spawn(move || {
        shutdown_rx
            .recv()
            .expect("the controlled test sends one shutdown signal");
        finished_tx
            .send(Ok(()))
            .expect("the completion receiver remains available before the join timeout");
        completion_reported_tx
            .send(())
            .expect("the test observes the queued completion before settlement");
        release_rx
            .recv()
            .expect("the test releases the server after its bounded join timeout");
        joined_by_server.store(true, Ordering::SeqCst);
    }));

    shutdown_tx
        .send(())
        .expect("the test initiates shutdown before waiting for the completion report");
    completion_reported_rx
        .recv_timeout(HTTP_SERVER_TEARDOWN_BOUND)
        .expect("the planted server reports completion within the bound");

    let settlement = settle_http_server_with_bound(
        &shutdown_tx,
        &finished_rx,
        &mut completion,
        &mut server,
        Duration::ZERO,
    );

    assert!(matches!(settlement, Err(error) if error.contains("reported completion")));
    assert!(
        matches!(completion.as_ref(), Some(Ok(()))),
        "a failed bounded join retains the already-received completion for retry"
    );
    assert!(
        server.is_some(),
        "a post-completion join timeout retains the owned thread for controlled retry"
    );
    assert!(
        !joined.load(Ordering::SeqCst),
        "a received completion must not permit an unbounded join"
    );

    release_tx
        .send(())
        .expect("the retained server remains controllable after the join timeout");
    settle_http_server_with_bound(
        &shutdown_tx,
        &finished_rx,
        &mut completion,
        &mut server,
        HTTP_SERVER_TEARDOWN_BOUND,
    )
    .expect("retry consumes the retained completion only after joining the released owner");
    assert!(joined.load(Ordering::SeqCst));
    assert!(
        completion.is_none(),
        "successful settlement consumes the retained completion"
    );
    assert!(server.is_none(), "retry joins the retained owner");
}

#[test]
fn e2e_http_fixture_reported_teardown_failure_still_joins_owner() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (shutdown_tx, shutdown_rx) = mpsc::sync_channel::<()>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let joined = Arc::new(AtomicBool::new(false));
    let joined_by_server = Arc::clone(&joined);
    let mut completion = None;
    let mut server = Some(thread::spawn(move || {
        shutdown_rx
            .recv()
            .expect("the bounded settlement path sends one shutdown signal");
        joined_by_server.store(true, Ordering::SeqCst);
        let _ = finished_tx.send(Err("planted server failure".to_owned()));
    }));

    let settlement = settle_http_server_with_bound(
        &shutdown_tx,
        &finished_rx,
        &mut completion,
        &mut server,
        HTTP_SERVER_TEARDOWN_BOUND,
    );

    assert!(matches!(settlement, Err(error) if error.contains("planted server failure")));
    assert!(joined.load(Ordering::SeqCst));
    assert!(
        server.is_none(),
        "a reported server failure still joins its owner instead of detaching it"
    );
}

#[test]
fn e2e_http_startup_guard_preserves_planted_startup_error() {
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let startup = HttpServerStartupGuard {
        server_cx: Some(Cx::for_request()),
        server_cx_rx: None,
        finished: Some(finished_rx),
        join: Some(thread::spawn(move || {
            let _ = finished_tx.send(Err("planted startup failure".to_owned()));
        })),
    };

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _startup = startup;
        panic!("original startup diagnostic");
    }))
    .expect_err("the enclosing startup failure must propagate");
    assert_eq!(
        *panic
            .downcast::<&str>()
            .expect("the original startup diagnostic is retained"),
        "original startup diagnostic"
    );
}

#[test]
fn e2e_http_startup_guard_resumes_planted_pre_readiness_panic() {
    let (_finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: None,
        finished: Some(finished_rx),
        join: Some(thread::spawn(|| panic!("planted pre-readiness panic"))),
    };
    let deadline = Instant::now() + HTTP_SERVER_TEARDOWN_BOUND;
    while !startup
        .join
        .as_ref()
        .expect("startup guard retains the spawned thread")
        .is_finished()
    {
        assert!(
            Instant::now() < deadline,
            "the planted pre-readiness panic finishes within the bound"
        );
        thread::sleep(Duration::from_millis(1));
    }

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        startup.resume_thread_panic_if_finished();
    }))
    .expect_err("the original pre-readiness panic must be resumed");
    assert_eq!(
        *panic
            .downcast::<&str>()
            .expect("the original pre-readiness panic is retained"),
        "planted pre-readiness panic"
    );
    assert!(startup.join.is_none());
}

fn plan(addr: SocketAddr, policy: ProtocolPolicy) -> ClientProtocolPlan {
    plan_with_modern_post_path(addr, policy, "/mcp")
}

/// Builds one immutable public endpoint plan while allowing an Auto probe to
/// target a live server route that is intentionally not mounted as modern.
/// This supports real 404 fallback coverage without substituting a scripted
/// HTTP peer.
fn plan_with_modern_post_path(
    addr: SocketAddr,
    policy: ProtocolPolicy,
    modern_post_path: &str,
) -> ClientProtocolPlan {
    let modern_target = CanonicalHttpUrl::parse(&format!("http://{addr}{modern_post_path}"))
        .expect("local modern target must be canonical");
    let legacy_sse = CanonicalHttpUrl::parse(&format!("http://{addr}/sse"))
        .expect("legacy SSE target must be canonical");
    let legacy_message = CanonicalHttpUrl::parse(&format!("http://{addr}/messages"))
        .expect("legacy message target must be canonical");
    ClientProtocolPlan::http(
        policy,
        (!matches!(policy, ProtocolPolicy::LegacyOnly)).then_some(modern_target),
        (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_sse),
        (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_message),
        "credential-partition-e2e-http".to_owned(),
        "security-partition-e2e-http".to_owned(),
        "native-h1-e2e-http".to_owned(),
        1,
        1,
        0,
    )
    .expect("the complete HTTP plan must be accepted")
}

/// Consumes whichever response lane the real server selected and returns the
/// final correlated JSON-RPC response document.
fn final_response_document(cx: &Cx, response: ModernHttpResponseStream) -> serde_json::Value {
    match response.metadata().kind() {
        ModernHttpResponseKind::Json => {
            let bytes = runtime_block_on_bounded(cx, response.read_to_end(cx, 1 << 20))
                .expect("immediate JSON body reads to end");
            serde_json::from_slice(&bytes).expect("immediate JSON response parses")
        }
        ModernHttpResponseKind::Sse => {
            let mut stream = response
                .into_sse_stream(SseLimits::new(65_536, 1 << 20, 64).expect("nonzero SSE limits"))
                .expect("SSE response admits the shipped parser");
            let mut terminal = None;
            while let Some(event) = runtime_block_on_bounded(cx, stream.next_event(cx))
                .expect("SSE stream stays readable")
            {
                let value: serde_json::Value =
                    serde_json::from_str(&event).expect("SSE payload is one JSON document");
                if value.get("id").is_some() {
                    terminal = Some(value);
                }
            }
            terminal.expect("SSE stream carried a final correlated response")
        }
        ModernHttpResponseKind::EmptyAcknowledgement => {
            panic!("a correlated request cannot complete with an empty acknowledgement")
        }
        ModernHttpResponseKind::HttpFailure => panic!(
            "unexpected HTTP failure status {} from the shipped server",
            response.metadata().status()
        ),
    }
}

#[derive(Debug, PartialEq)]
struct PublicHttpHandlerObservables {
    tool: serde_json::Value,
    resource: serde_json::Value,
    prompt: serde_json::Value,
}

fn public_http_target(address: SocketAddr, path: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(&format!("http://{address}{path}"))
        .expect("a fixture route must form a canonical HTTP target")
}

fn assert_public_handler_observables(observables: &PublicHttpHandlerObservables) {
    assert_eq!(
        observables.tool["content"][0]["type"],
        json!("text"),
        "the public tool result must retain text content"
    );
    assert_eq!(
        observables.tool["content"][0]["text"],
        json!(PUBLIC_HTTP_TOOL_TEXT),
        "the public tool result must retain the deterministic handler value"
    );
    assert_eq!(
        observables.resource["contents"][0]["uri"],
        json!(PUBLIC_HTTP_RESOURCE_URI),
        "the public resource result must retain the registered URI"
    );
    assert_eq!(
        observables.resource["contents"][0]["text"],
        json!(PUBLIC_HTTP_RESOURCE_TEXT),
        "the public resource result must retain the deterministic handler value"
    );
    assert_eq!(
        observables.prompt["messages"][0]["role"],
        json!("user"),
        "the public prompt result must retain its message role"
    );
    assert_eq!(
        observables.prompt["messages"][0]["content"]["type"],
        json!("text"),
        "the public prompt result must retain text content"
    );
    assert_eq!(
        observables.prompt["messages"][0]["content"]["text"],
        json!(PUBLIC_HTTP_PROMPT_TEXT),
        "the public prompt result must retain the deterministic handler value"
    );
}

fn invoke_modern_public_handlers(cx: &Cx, address: SocketAddr) -> PublicHttpHandlerObservables {
    let mut client = runtime_block_on_bounded(
        cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-modern-handler-client", "1.0.0")
            .connect_http_with_cx(public_http_target(address, "/mcp"), cx),
    )
    .expect("the ModernOnly public facade connects to the live modern route");

    let tool = runtime_block_on_bounded(
        cx,
        client.call_tool_with_mrtr_retry(
            cx,
            Instant::now() + HTTP_SERVER_TEARDOWN_BOUND,
            PUBLIC_HTTP_TOOL_NAME,
            json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
            SseLimits::new(65_536, 1 << 20, 64).expect("nonzero SSE limits"),
            1 << 20,
            |_| {
                Err(McpError::invalid_request(
                    "the deterministic public tool must not request MRTR input",
                ))
            },
        ),
    )
    .expect("the ModernOnly public facade invokes the live deterministic tool");
    let modern::FinalCoreResult::ToolsCall { result: tool, .. } = tool else {
        panic!("the deterministic public tool must complete without MRTR input");
    };
    let tool = serde_json::to_value(tool.payload)
        .expect("the typed modern tool result serializes for its observable assertion");

    let resource = runtime_block_on_bounded(cx, client.read_resource(cx, PUBLIC_HTTP_RESOURCE_URI))
        .expect("the ModernOnly public facade reads the live deterministic resource");
    let resource = serde_json::to_value(resource)
        .expect("the typed modern resource result serializes for its observable assertion");

    let prompt = runtime_block_on_bounded(
        cx,
        client.get_prompt(
            cx,
            PUBLIC_HTTP_PROMPT_NAME,
            HashMap::from([("subject".to_owned(), PUBLIC_HTTP_TOOL_ARGUMENT.to_owned())]),
        ),
    )
    .expect("the ModernOnly public facade gets the live deterministic prompt");
    let prompt = serde_json::to_value(prompt)
        .expect("the typed modern prompt result serializes for its observable assertion");

    let observables = PublicHttpHandlerObservables {
        tool,
        resource,
        prompt,
    };
    assert_public_handler_observables(&observables);
    observables
}

fn invoke_legacy_public_handlers(cx: &Cx, address: SocketAddr) -> PublicHttpHandlerObservables {
    let mut client = runtime_block_on_bounded(
        cx,
        legacy_2024::http_client_builder(
            public_http_target(address, "/sse"),
            public_http_target(address, "/messages"),
        )
        .expect("the exact legacy HTTP endpoints form one public facade plan")
        .client_info("e2e-public-legacy-handler-client", "1.0.0")
        .connect_http_client_with_cx(cx),
    )
    .expect("the LegacyOnly public facade connects to the live exact-legacy routes");
    assert_eq!(client.protocol_policy(), ProtocolPolicy::LegacyOnly);

    let tool = runtime_block_on_bounded(
        cx,
        client.call_tool(
            cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_TOOL_NAME.to_owned(),
                arguments: Some(json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT })),
                meta: None,
            },
        ),
    )
    .expect("the LegacyOnly public facade invokes the live deterministic tool");
    let tool = serde_json::to_value(tool)
        .expect("the typed legacy tool result serializes for its observable assertion");

    let resource = runtime_block_on_bounded(
        cx,
        client.read_resource(
            cx,
            legacy_2024::ReadResourceParams {
                uri: PUBLIC_HTTP_RESOURCE_URI.to_owned(),
                meta: None,
            },
        ),
    )
    .expect("the LegacyOnly public facade reads the live deterministic resource");
    let resource = serde_json::to_value(resource)
        .expect("the typed legacy resource result serializes for its observable assertion");

    let prompt = runtime_block_on_bounded(
        cx,
        client.get_prompt(
            cx,
            legacy_2024::GetPromptParams {
                name: PUBLIC_HTTP_PROMPT_NAME.to_owned(),
                arguments: Some(HashMap::from([(
                    "subject".to_owned(),
                    PUBLIC_HTTP_TOOL_ARGUMENT.to_owned(),
                )])),
                meta: None,
            },
        ),
    )
    .expect("the LegacyOnly public facade gets the live deterministic prompt");
    let prompt = serde_json::to_value(prompt)
        .expect("the typed legacy prompt result serializes for its observable assertion");

    let observables = PublicHttpHandlerObservables {
        tool,
        resource,
        prompt,
    };
    assert_public_handler_observables(&observables);
    observables
}

#[derive(Default)]
struct OverlapFinalMethodGate {
    state: Mutex<OverlapFinalMethodGateState>,
    entered: Condvar,
    released: Condvar,
}

#[derive(Default)]
struct OverlapFinalMethodGateState {
    modern_tools_list_entered: bool,
    legacy_ping_entered: bool,
    modern_request_id: Option<serde_json::Value>,
    legacy_request_id: Option<serde_json::Value>,
    released: bool,
}

impl OverlapFinalMethodGate {
    fn wait_for_cross_era_requests(&self) -> Result<(), String> {
        let deadline = Instant::now() + HTTP_SERVER_TEARDOWN_BOUND;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !(state.modern_tools_list_entered && state.legacy_ping_entered) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(
                    "the modern tools/list and legacy ping requests did not both reach the overlap gate"
                        .to_owned(),
                );
            }
            let (next, timeout) = self
                .entered
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
            if timeout.timed_out()
                && !(state.modern_tools_list_entered && state.legacy_ping_entered)
            {
                return Err(
                    "the modern tools/list and legacy ping requests did not both reach the overlap gate"
                        .to_owned(),
                );
            }
        }
        if state.modern_request_id != state.legacy_request_id {
            return Err(format!(
                "the overlapping modern and legacy requests used different IDs: modern={:?}, legacy={:?}",
                state.modern_request_id, state.legacy_request_id
            ));
        }
        Ok(())
    }

    fn release(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.released = true;
        self.released.notify_all();
    }
}

impl Middleware for OverlapFinalMethodGate {
    fn on_request(
        &self,
        _ctx: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let request_id = serde_json::to_value(&request.id).map_err(|error| {
            McpError::internal_error(format!("overlap request ID serializes: {error}"))
        })?;
        match request.method.as_str() {
            "tools/list" => {
                state.modern_tools_list_entered = true;
                state.modern_request_id = Some(request_id);
            }
            "ping" => {
                state.legacy_ping_entered = true;
                state.legacy_request_id = Some(request_id);
            }
            _ => return Ok(MiddlewareDecision::Continue),
        }
        self.entered.notify_all();
        while !state.released {
            state = self
                .released
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        Ok(MiddlewareDecision::Continue)
    }
}

enum OverlapWorkerCompletion {
    Modern(Result<serde_json::Value, String>),
    Legacy(Result<serde_json::Value, String>),
}

/// Owns the planted stalled worker through both the deadline observation and
/// panic unwinding. Dropping it releases the worker before a bounded join.
struct StalledOverlapWorker {
    release: mpsc::SyncSender<()>,
    join: Option<JoinHandle<()>>,
}

impl StalledOverlapWorker {
    fn release(&self) {
        match self.release.try_send(()) {
            Ok(())
            | Err(mpsc::TrySendError::Full(()))
            | Err(mpsc::TrySendError::Disconnected(())) => {}
        }
    }

    fn settle(&mut self) -> Result<(), String> {
        self.release();
        join_finished_thread(
            &mut self.join,
            HTTP_SERVER_TEARDOWN_BOUND,
            "stalled overlap worker",
        )
    }
}

impl Drop for StalledOverlapWorker {
    fn drop(&mut self) {
        if self.join.is_none() {
            return;
        }
        if let Err(error) = self.settle() {
            eprintln!("stalled overlap worker settlement failed: {error}");
            std::process::abort();
        }
    }
}

/// Collects the two request outcomes within a deadline. Every caller must
/// then drive the workers to completion and join their retained owners.
fn collect_overlap_worker_results(
    completed: &mpsc::Receiver<OverlapWorkerCompletion>,
    completion_bound: Duration,
) -> (
    Result<serde_json::Value, String>,
    Result<serde_json::Value, String>,
) {
    let deadline = Instant::now() + completion_bound;
    let mut modern = None;
    let mut legacy = None;

    while modern.is_none() || legacy.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match completed.recv_timeout(remaining) {
            Ok(OverlapWorkerCompletion::Modern(result)) if modern.is_none() => {
                modern = Some(result);
            }
            Ok(OverlapWorkerCompletion::Legacy(result)) if legacy.is_none() => {
                legacy = Some(result);
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    (
        modern.unwrap_or_else(|| {
            Err("the modern overlap worker did not complete before the bounded deadline".to_owned())
        }),
        legacy.unwrap_or_else(|| {
            Err("the legacy overlap worker did not complete before the bounded deadline".to_owned())
        }),
    )
}

#[test]
fn e2e_overlap_worker_timeout_releases_fixture_teardown() {
    let mut server = HttpServerFixture::spawn();
    let (completed_tx, completed_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let stalled_completed_tx = completed_tx.clone();
    let mut stalled_worker = StalledOverlapWorker {
        release: release_tx,
        join: Some(thread::spawn(move || {
            release_rx
                .recv()
                .expect("the test releases the single stalled worker after its deadline");
            let _ = stalled_completed_tx.send(OverlapWorkerCompletion::Modern(Ok(json!({}))));
        })),
    };

    completed_tx
        .send(OverlapWorkerCompletion::Legacy(Ok(json!({}))))
        .expect("the non-stalled worker completion reaches the collector");
    drop(completed_tx);

    let (modern, legacy) = collect_overlap_worker_results(&completed_rx, Duration::from_millis(20));
    assert!(
        matches!(modern, Err(error) if error.contains("modern overlap worker")),
        "only the deliberately stalled modern worker may exceed the completion deadline"
    );
    assert!(
        legacy.is_ok(),
        "the unchanged legacy worker completion is retained"
    );

    stalled_worker.release();
    let completion = completed_rx
        .recv_timeout(HTTP_SERVER_TEARDOWN_BOUND)
        .expect("the released worker reports completion within its bounded cleanup window");
    assert!(matches!(completion, OverlapWorkerCompletion::Modern(Ok(_))));
    stalled_worker
        .settle()
        .expect("the released worker joins without detaching");
    assert!(stalled_worker.join.is_none());
    let teardown = server.settle();
    teardown.expect("the bounded fixture teardown runs after a worker completion timeout");
}

#[test]
fn e2e_public_http_typed_facades_invoke_real_handlers_in_each_exact_era() {
    let cx = Cx::for_request();

    let modern_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::ModernOnly);
    let modern = invoke_modern_public_handlers(&cx, modern_server.address());
    assert_public_handler_observables(&modern);
    modern_server.shutdown();

    let legacy_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::LegacyOnly);
    let legacy = invoke_legacy_public_handlers(&cx, legacy_server.address());
    assert_public_handler_observables(&legacy);
    legacy_server.shutdown();
}

#[test]
fn e2e_public_http_cross_era_refusals_leave_handler_observables_unchanged() {
    let cx = Cx::for_request();

    let modern_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::ModernOnly);
    let modern_before = invoke_modern_public_handlers(&cx, modern_server.address());
    let modern_calls_before_refusal = modern_server.handler_call_snapshot();
    // Keep the legacy facade configuration identical to its matched-era
    // control; the endpoint's live server policy is the only intentional
    // protocol-selection variable.
    let legacy_refusal = match runtime_block_on_bounded(
        &cx,
        legacy_2024::http_client_builder(
            public_http_target(modern_server.address(), "/sse"),
            public_http_target(modern_server.address(), "/messages"),
        )
        .expect("the exact legacy HTTP endpoints form one public facade plan")
        .client_info("e2e-public-legacy-handler-client", "1.0.0")
        .connect_http_client_with_cx(&cx),
    ) {
        Err(error) => error,
        Ok(_) => {
            panic!(
                "a LegacyOnly public facade must reject the ModernOnly server's live SSE refusal"
            )
        }
    };
    assert!(matches!(
        legacy_refusal,
        legacy_2024::HttpClientConnectError::Connect(legacy_2024::HttpClientError::Connection(
            ClientHttpConnectionError::Modern(fastmcp_rust::ModernHttpClientError::LegacySse(
                fastmcp_rust::LegacySseHttpClientError::SseGetRejected { status: 400 }
            ))
        ))
    ));
    assert_eq!(
        modern_server.handler_call_snapshot(),
        modern_calls_before_refusal,
        "the refused exact-legacy connection must not invoke a ModernOnly handler"
    );
    let modern_after = invoke_modern_public_handlers(&cx, modern_server.address());
    assert_eq!(
        modern_after, modern_before,
        "the refused exact-legacy connection must not alter later ModernOnly handler observables"
    );
    modern_server.shutdown();

    let legacy_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::LegacyOnly);
    let legacy_before = invoke_legacy_public_handlers(&cx, legacy_server.address());
    let legacy_calls_before_refusal = legacy_server.handler_call_snapshot();
    // Keep the modern facade configuration identical to its matched-era
    // control; the endpoint's live server policy is the only intentional
    // protocol-selection variable.
    let modern_refusal = match runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-modern-handler-client", "1.0.0")
            .connect_http_with_cx(public_http_target(legacy_server.address(), "/mcp"), &cx),
    ) {
        Err(error) => error,
        Ok(_) => {
            panic!(
                "a ModernOnly public facade must reject the LegacyOnly server's live probe refusal"
            )
        }
    };
    assert!(matches!(
        modern_refusal,
        modern::HttpClientConnectError::Connect(
            modern::HttpClientError::Connection(ClientHttpConnectionError::Modern(
                fastmcp_rust::ModernHttpClientError::Negotiation(
                    fastmcp_rust::ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
                        status: 400,
                        ..
                    }
                )
            ))
        )
    ));
    assert_eq!(
        legacy_server.handler_call_snapshot(),
        legacy_calls_before_refusal,
        "the refused modern connection must not invoke a LegacyOnly handler"
    );
    let legacy_after = invoke_legacy_public_handlers(&cx, legacy_server.address());
    assert_eq!(
        legacy_after, legacy_before,
        "the refused modern connection must not alter later LegacyOnly handler observables"
    );
    legacy_server.shutdown();
}

#[test]
fn e2e_public_http_auto_selects_modern_on_the_shipped_facade_server() {
    let server = HttpServerFixture::spawn();
    let cx = Cx::for_request();
    let builder = auto::client_builder()
        .client_info("e2e-modern-http-client", "1.0.0")
        .protocol_plan(plan(server.address(), ProtocolPolicy::Auto));
    assert_eq!(
        builder.selected_protocol_plan().policy(),
        ProtocolPolicy::Auto
    );

    let mut client = runtime_block_on_bounded(&cx, builder.connect_http_client_with_cx(&cx))
        .expect("the public Auto facade client completes live modern discovery");
    assert_eq!(
        client.selected_protocol_era(),
        ProtocolEra::Modern2026,
        "a live modern discovery response must never downgrade Auto"
    );
    assert_eq!(client.protocol_plan().policy(), ProtocolPolicy::Auto);
    assert!(
        client.server_discovery().is_some(),
        "modern selection exposes the public discovery result"
    );
    assert_eq!(
        client.connection().protocol_version(),
        Some(fastmcp_rust::modern::PROTOCOL_VERSION),
        "the public HTTP connection reports the exact modern negotiated version"
    );

    let response = runtime_block_on_bounded(
        &cx,
        client.request(&cx, "tools/list", json!({ "cursor": null })),
    )
    .expect("the Auto-selected modern connection serves requests");
    let ClientHttpResponse::Modern(response) = response else {
        panic!("the selected modern HTTP client must retain the modern response lane");
    };
    let document = final_response_document(&cx, response);
    assert_eq!(document["id"], json!(2));
    assert!(
        document.get("error").is_none(),
        "tools/list over the Auto-selected connection must not fail: {document}"
    );
    assert!(
        document["result"]["tools"].is_array(),
        "the modern tools/list response must carry its tools result: {document}"
    );
    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_modern_only_selects_modern_and_refuses_legacy_only() {
    let modern_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::ModernOnly);
    let cx = Cx::for_request();
    let builder = auto::client_builder()
        .client_info("e2e-modern-only-http-client", "1.0.0")
        .protocol_plan(plan(modern_server.address(), ProtocolPolicy::ModernOnly));

    let mut client = runtime_block_on_bounded(&cx, builder.connect_http_client_with_cx(&cx))
        .expect("a ModernOnly facade plan selects the real ModernOnly endpoint");
    assert_eq!(client.selected_protocol_era(), ProtocolEra::Modern2026);
    assert_eq!(
        client.connection().protocol_version(),
        Some(fastmcp_rust::modern::PROTOCOL_VERSION),
        "the positive ModernOnly connection reports the exact modern version"
    );
    assert!(
        client.server_discovery().is_some(),
        "the positive ModernOnly connection retains modern discovery"
    );
    let response = runtime_block_on_bounded(
        &cx,
        client.request(&cx, "tools/list", json!({ "cursor": null })),
    )
    .expect("the selected ModernOnly connection serves tools/list");
    let ClientHttpResponse::Modern(response) = response else {
        panic!("the ModernOnly connection must retain the modern response lane");
    };
    let document = final_response_document(&cx, response);
    assert_eq!(document["id"], json!(2));
    assert!(
        document.get("error").is_none(),
        "the positive ModernOnly tools/list response must not fail: {document}"
    );
    assert!(
        document["result"]["tools"].is_array(),
        "the positive ModernOnly tools/list response carries its result: {document}"
    );
    drop(client);
    modern_server.shutdown();

    // This differs from the positive case only in the live server policy.
    // A ModernOnly plan has no configured legacy fallback and must not create
    // a client after the LegacyOnly endpoint refuses its modern request.
    let legacy_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::LegacyOnly);
    let refusal = match runtime_block_on_bounded(
        &cx,
        auto::client_builder()
            .client_info("e2e-modern-only-http-client", "1.0.0")
            .protocol_plan(plan(legacy_server.address(), ProtocolPolicy::ModernOnly))
            .connect_http_client_with_cx(&cx),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a ModernOnly facade plan must reject the LegacyOnly endpoint's live 400"),
    };
    assert!(matches!(
        refusal,
        auto::HttpClientError::Connection(auto::ClientHttpConnectionError::Modern(
            fastmcp_rust::ModernHttpClientError::Negotiation(
                auto::ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
                    status: 400,
                    ..
                }
            )
        ))
    ));
    legacy_server.shutdown();
}

#[test]
fn e2e_public_http_legacy_only_selects_legacy_and_refuses_modern_only() {
    let legacy_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::LegacyOnly);
    let cx = Cx::for_request();
    let builder = auto::client_builder()
        .client_info("e2e-legacy-only-http-client", "1.0.0")
        .protocol_plan(plan(legacy_server.address(), ProtocolPolicy::LegacyOnly));

    let mut client = runtime_block_on_bounded(&cx, builder.connect_http_client_with_cx(&cx))
        .expect("a LegacyOnly facade plan selects the real exact-legacy endpoint");
    assert_eq!(client.selected_protocol_era(), ProtocolEra::Legacy2024);
    assert_eq!(
        client.connection().protocol_version(),
        Some(fastmcp_rust::legacy_2024::PROTOCOL_VERSION),
        "the positive LegacyOnly connection reports the exact 2024-11-05 version"
    );
    assert!(
        client.server_discovery().is_none(),
        "the positive LegacyOnly connection cannot retain modern discovery"
    );
    let response = runtime_block_on_bounded(&cx, client.request(&cx, "ping", json!({})))
        .expect("the selected LegacyOnly connection serves ping");
    let ClientHttpResponse::Legacy(JsonRpcMessage::Response(ping)) = response else {
        panic!("the LegacyOnly connection must retain the exact-legacy response lane");
    };
    assert!(
        ping.error.is_none(),
        "the positive exact-legacy ping must not fail"
    );
    assert_eq!(ping.result, Some(json!({})));
    drop(client);
    legacy_server.shutdown();

    // This differs from the positive case only in the live server policy.
    // A LegacyOnly plan has no configured modern route and must not manufacture
    // an exact-legacy session after the ModernOnly endpoint refuses its SSE GET.
    let modern_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::ModernOnly);
    let refusal = match runtime_block_on_bounded(
        &cx,
        auto::client_builder()
            .client_info("e2e-legacy-only-http-client", "1.0.0")
            .protocol_plan(plan(modern_server.address(), ProtocolPolicy::LegacyOnly))
            .connect_http_client_with_cx(&cx),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a LegacyOnly facade plan must reject the ModernOnly endpoint's live 400"),
    };
    assert!(matches!(
        refusal,
        auto::HttpClientError::Connection(auto::ClientHttpConnectionError::Modern(
            fastmcp_rust::ModernHttpClientError::LegacySse(
                fastmcp_rust::LegacySseHttpClientError::SseGetRejected { status: 400 }
            )
        ))
    ));
    modern_server.shutdown();
}

#[test]
fn e2e_public_http_auto_falls_back_to_exact_legacy_on_live_eligible_refusal() {
    let server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::LegacyOnly);
    let cx = Cx::for_request();

    // This differs from the matched Auto-modern positive only in the live
    // server policy. The LegacyOnly endpoint returns its real modern-route
    // refusal, after which Auto may open the configured exact-legacy routes.
    let builder = auto::client_builder()
        .client_info("e2e-modern-http-client", "1.0.0")
        .protocol_plan(plan(server.address(), ProtocolPolicy::Auto));
    assert_eq!(
        builder.selected_protocol_plan().policy(),
        ProtocolPolicy::Auto
    );
    let mut client = runtime_block_on_bounded(&cx, builder.connect_http_client_with_cx(&cx))
        .expect("an eligible live modern-route refusal completes the exact legacy lifecycle");
    assert_eq!(
        client.selected_protocol_era(),
        ProtocolEra::Legacy2024,
        "Auto must expose exact legacy selection only after its eligible live refusal"
    );
    assert_eq!(client.protocol_plan().policy(), ProtocolPolicy::Auto);
    assert!(
        client.server_discovery().is_none(),
        "exact legacy fallback cannot expose modern discovery state"
    );
    assert_eq!(
        client.connection().protocol_version(),
        Some(fastmcp_rust::legacy_2024::PROTOCOL_VERSION),
        "the public HTTP connection retains the exact validated legacy initialize wire version"
    );
    assert_eq!(
        client.server_info().name,
        "facade-http-example",
        "the legacy initialization result comes from the shipped facade server composition"
    );
    let ping = runtime_block_on_bounded(&cx, client.request(&cx, "ping", json!({})))
        .expect("the initialized exact-legacy fallback remains usable");
    let ClientHttpResponse::Legacy(JsonRpcMessage::Response(ping)) = ping else {
        panic!("the exact-legacy fallback must answer ping through its legacy response lane");
    };
    assert!(ping.error.is_none(), "legacy ping must not fail: {ping:?}");
    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_auto_isolates_live_modern_and_legacy_clients() {
    let gate = Arc::new(OverlapFinalMethodGate::default());
    let mut server =
        HttpServerFixture::spawn_with_middleware(Some(Arc::clone(&gate) as Arc<dyn Middleware>));
    let address = server.address();

    let (completed_tx, completed_rx) = mpsc::channel();
    let modern_completed_tx = completed_tx.clone();
    let mut modern_worker = Some(thread::spawn(move || {
        let result = (|| -> Result<serde_json::Value, String> {
            let cx = Cx::for_request();
            let builder = auto::client_builder()
                .client_info("e2e-isolated-modern-client", "1.0.0")
                .protocol_plan(plan(address, ProtocolPolicy::Auto));
            let mut client =
                runtime_block_on_bounded(&cx, builder.connect_http_client_with_cx(&cx)).map_err(
                    |error| format!("the first Auto client did not select modern: {error}"),
                )?;
            if client.selected_protocol_era() != ProtocolEra::Modern2026 {
                return Err("the first client did not retain an independent modern era".to_owned());
            }
            let response = runtime_block_on_bounded(
                &cx,
                client.request(&cx, "tools/list", json!({ "cursor": null })),
            )
            .map_err(|error| format!("the modern tools/list request failed: {error}"))?;
            let ClientHttpResponse::Modern(response) = response else {
                return Err("the first client did not retain its modern response lane".to_owned());
            };
            Ok(final_response_document(&cx, response))
        })();
        let _ = modern_completed_tx.send(OverlapWorkerCompletion::Modern(result));
    }));
    let legacy_completed_tx = completed_tx.clone();
    let mut legacy_worker = Some(thread::spawn(move || {
        let result = (|| -> Result<serde_json::Value, String> {
            let cx = Cx::for_request();
            let builder = auto::client_builder()
                .client_info("e2e-isolated-legacy-client", "1.0.0")
                .protocol_plan(plan_with_modern_post_path(
                    address,
                    ProtocolPolicy::Auto,
                    "/modern-unavailable",
                ));
            let mut client =
                runtime_block_on_bounded(&cx, builder.connect_http_client_with_cx(&cx)).map_err(
                    |error| format!("the second Auto client did not select legacy: {error}"),
                )?;
            if client.selected_protocol_era() != ProtocolEra::Legacy2024 {
                return Err("the second client inherited a foreign protocol era".to_owned());
            }
            let response = runtime_block_on_bounded(&cx, client.request(&cx, "ping", json!({})))
                .map_err(|error| format!("the legacy ping request failed: {error}"))?;
            let ClientHttpResponse::Legacy(JsonRpcMessage::Response(response)) = response else {
                return Err("the second client did not retain its legacy response lane".to_owned());
            };
            serde_json::to_value(response)
                .map_err(|error| format!("the legacy response did not serialize: {error}"))
        })();
        let _ = legacy_completed_tx.send(OverlapWorkerCompletion::Legacy(result));
    }));
    drop(completed_tx);

    let admission = gate.wait_for_cross_era_requests();
    gate.release();
    let (modern_document, legacy_document) =
        collect_overlap_worker_results(&completed_rx, HTTP_SERVER_TEARDOWN_BOUND);
    let modern_join = join_finished_thread(
        &mut modern_worker,
        HTTP_SERVER_TEARDOWN_BOUND,
        "modern overlap worker",
    );
    let legacy_join = join_finished_thread(
        &mut legacy_worker,
        HTTP_SERVER_TEARDOWN_BOUND,
        "legacy overlap worker",
    );
    let teardown = server.settle();

    admission.expect(
        "the modern tools/list and legacy ping requests must reach the server before either response runs",
    );
    teardown.expect("the bounded server teardown runs after overlap completion collection");
    modern_join.expect("the modern overlap worker joins without detaching");
    legacy_join.expect("the legacy overlap worker joins without detaching");
    let modern_document = modern_document.expect("the overlapping modern request completes");
    assert_eq!(modern_document["id"], json!(2));
    assert!(
        modern_document.get("error").is_none(),
        "the isolated modern tools/list request must not fail: {modern_document}"
    );
    assert!(
        modern_document["result"]["tools"].is_array(),
        "the isolated modern tools/list response must carry its tools result: {modern_document}"
    );

    let legacy_document = legacy_document.expect("the overlapping legacy request completes");
    assert_eq!(
        legacy_document["id"],
        json!(2),
        "both clients reuse their local final-request id without cross-client correlation"
    );
    assert!(
        legacy_document.get("error").is_none(),
        "the isolated legacy ping must not fail: {legacy_document}"
    );
    assert_eq!(
        legacy_document["result"],
        json!({}),
        "the isolated legacy response must remain the ping acknowledgement: {legacy_document}"
    );
}
