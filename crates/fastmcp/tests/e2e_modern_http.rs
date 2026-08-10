//! Public modern HTTP round trip: shipped client against shipped server.
//!
//! Both ends of these tests are real shipped-facade surfaces — the turnkey
//! `Server::bind_http`/`serve` lifecycle on one side and
//! `auto::client_builder()` connection lifecycle on the other — joined over
//! one real localhost socket. No scripted peer, fixture transcript, mock, or
//! direct FastMCP component-crate import stands in for either endpoint.
//!
//! What this proves (and only this): the shipped dual-era HTTP server and
//! facade clients can complete Auto classification and a round trip against
//! each other — modern discovery plus `tools/list` over the live modern lane,
//! then exact 2024-11-05 HTTP+SSE fallback after a real LegacyOnly endpoint
//! refuses the modern request. It is not an aggregate MCP 2026-07-28
//! conformance claim.

use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use asupersync::CancelKind;
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::reactor::create_reactor;
use fastmcp_rust::{
    CanonicalHttpUrl, ClientHttpResponse, ClientProtocolPlan, Cx, JsonRpcMessage, JsonRpcRequest,
    McpContext, McpError, McpResult, Middleware, MiddlewareDecision, ModernHttpResponseKind,
    ModernHttpResponseStream, ProtocolEra, ProtocolPolicy, Server, SseLimits, auto,
};
use serde_json::json;

fn runtime_block_on<F: std::future::Future>(future: F) -> F::Output {
    RuntimeBuilder::current_thread()
        .build()
        .expect("native runtime must build")
        .block_on(future)
}

fn runtime_block_on_bounded<F: std::future::Future>(cx: &Cx, future: F) -> F::Output {
    runtime_block_on(async {
        asupersync::time::timeout(cx.now(), HTTP_SERVER_TEARDOWN_BOUND, future)
            .await
            .expect("public HTTP operation stays within its bound")
    })
}

const HTTP_SERVER_STARTUP_BOUND: Duration = Duration::from_secs(2);
const HTTP_SERVER_TEARDOWN_BOUND: Duration = Duration::from_secs(2);
/// Hard ceiling for the server task itself. This bounds the owned thread even
/// if cancellation is not observed by a future regression in server teardown.
const HTTP_SERVER_THREAD_BOUND: Duration = Duration::from_secs(4);

/// Owns one real public HTTP server composition and proves its teardown.
///
/// The fixture deliberately uses the minimal `Server::new(...).build()`
/// composition published in the facade examples, rather than a test-local
/// handler. Its clients use only protocol-defined final methods, so the test
/// does not need a bespoke test tool.
struct HttpServerFixture {
    address: SocketAddr,
    shutdown: mpsc::SyncSender<()>,
    finished: mpsc::Receiver<Result<(), String>>,
    join: Option<JoinHandle<()>>,
}

/// Retains a just-spawned fixture until the ready handshake succeeds and it
/// can be transferred into `HttpServerFixture`.
struct HttpServerStartupGuard {
    shutdown: Option<mpsc::SyncSender<()>>,
    finished: Option<mpsc::Receiver<Result<(), String>>>,
    join: Option<JoinHandle<()>>,
}

impl HttpServerStartupGuard {
    fn into_parts(
        mut self,
    ) -> (
        mpsc::SyncSender<()>,
        mpsc::Receiver<Result<(), String>>,
        Option<JoinHandle<()>>,
    ) {
        (
            self.shutdown
                .take()
                .expect("startup guard retains shutdown"),
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
        let Some(shutdown) = self.shutdown.as_ref() else {
            return;
        };
        let Some(finished) = self.finished.as_ref() else {
            return;
        };
        let settlement = settle_http_server(shutdown, finished, &mut self.join);
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
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
        let (shutdown_tx, shutdown_rx) = mpsc::sync_channel::<()>(1);
        let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let join = Some(thread::spawn(move || {
            let ready_for_spawn_failure = ready_tx.clone();
            let finished_for_spawn_failure = finished_tx.clone();
            let (task_done_tx, task_done_rx) = mpsc::channel::<()>();
            let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(create_reactor().expect("server reactor initializes"))
                .blocking_threads(4, 64)
                .build()
                .expect("server runtime builds");
            let server_task = runtime.handle().try_spawn_with_cx(move |cx| {
                let server_cx_tx = server_cx_tx;
                async move {
                    if server_cx_tx.send(cx.clone()).is_err() {
                        cx.cancel_with(
                            CancelKind::User,
                            Some("HTTP E2E server control receiver went away"),
                        );
                        let _ = finished_tx
                            .send(Err("HTTP E2E server control receiver went away".to_owned()));
                        let _ = task_done_tx.send(());
                        return;
                    }
                    let outcome =
                        match asupersync::time::timeout(cx.now(), HTTP_SERVER_THREAD_BOUND, async {
                            let builder = Server::new("facade-http-example", "1.0.0")
                                .protocol_policy(protocol_policy);
                            let server = match middleware {
                                Some(middleware) => builder.middleware(middleware).build(),
                                None => builder.build(),
                            };
                            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                                Ok(bound) => bound,
                                Err(error) => {
                                    let message =
                                        format!("facade HTTP server bind failed: {error}");
                                    let _ = ready_tx.send(Err(message.clone()));
                                    return Err(message);
                                }
                            };
                            let address = match bound.local_addr() {
                                Ok(address) => address,
                                Err(error) => {
                                    let message =
                                        format!("facade HTTP server address failed: {error}");
                                    let _ = ready_tx.send(Err(message.clone()));
                                    return Err(message);
                                }
                            };
                            if ready_tx.send(Ok(address)).is_err() {
                                cx.cancel_with(
                                    CancelKind::User,
                                    Some("HTTP E2E startup receiver went away"),
                                );
                                return Err("HTTP E2E startup receiver went away".to_owned());
                            }
                            bound.serve(&cx).await.map_err(|error| {
                                format!("facade HTTP server stopped unexpectedly: {error}")
                            })
                        })
                        .await
                        {
                            Ok(outcome) => outcome,
                            Err(_) => {
                                cx.cancel_with(
                                    CancelKind::User,
                                    Some("HTTP E2E server task hard deadline exceeded"),
                                );
                                Err("facade HTTP server exceeded its hard task deadline".to_owned())
                            }
                        };
                    let _ = finished_tx.send(outcome);
                    let _ = task_done_tx.send(());
                }
            });
            if let Err(error) = server_task {
                let message = format!("facade HTTP server task was not admitted: {error}");
                let _ = ready_for_spawn_failure.send(Err(message.clone()));
                let _ = finished_for_spawn_failure.send(Err(message));
                return;
            }
            runtime.block_on(async move {
                let mut server_cx = None;
                let mut shutdown_requested = false;
                loop {
                    match shutdown_rx.try_recv() {
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                            shutdown_requested = true;
                        }
                        Err(mpsc::TryRecvError::Empty) => {}
                    }
                    if server_cx.is_none() {
                        if let Ok(cx) = server_cx_rx.try_recv() {
                            server_cx = Some(cx);
                        }
                    }
                    if shutdown_requested {
                        if let Some(cx) = server_cx.as_ref() {
                            cx.cancel_with(
                                CancelKind::User,
                                Some("HTTP E2E fixture shutdown requested"),
                            );
                        }
                    }
                    match task_done_rx.try_recv() {
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                        Err(mpsc::TryRecvError::Empty) => {
                            let cx = Cx::current().expect("server runtime installs an ambient Cx");
                            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                        }
                    }
                }
            });
        }));

        let mut startup = HttpServerStartupGuard {
            shutdown: Some(shutdown_tx),
            finished: Some(finished_rx),
            join,
        };
        let address = match ready_rx.recv_timeout(HTTP_SERVER_STARTUP_BOUND) {
            Ok(Ok(address)) => address,
            Ok(Err(error)) => panic!("public HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("public HTTP server startup readiness channel disconnected")
            }
            Err(error) => {
                drop(ready_rx);
                panic!("public HTTP server startup exceeded its bound: {error}");
            }
        };
        let (shutdown, finished, join) = startup.into_parts();

        Self {
            address,
            shutdown,
            finished,
            join,
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn settle(&mut self) -> Result<(), String> {
        settle_http_server(&self.shutdown, &self.finished, &mut self.join)
    }

    fn shutdown(mut self) {
        self.settle()
            .unwrap_or_else(|error| panic!("public HTTP server teardown failed: {error}"));
    }
}

impl Drop for HttpServerFixture {
    fn drop(&mut self) {
        if self.join.is_none() {
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
fn settle_http_server(
    shutdown: &mpsc::SyncSender<()>,
    finished: &mpsc::Receiver<Result<(), String>>,
    join: &mut Option<JoinHandle<()>>,
) -> Result<(), String> {
    settle_http_server_with_bound(shutdown, finished, join, HTTP_SERVER_TEARDOWN_BOUND)
}

/// This helper is separately bounded so the planted timeout test can prove
/// that a deadline retains ownership until a later controlled settlement.
fn settle_http_server_with_bound(
    shutdown: &mpsc::SyncSender<()>,
    finished: &mpsc::Receiver<Result<(), String>>,
    join: &mut Option<JoinHandle<()>>,
    completion_bound: Duration,
) -> Result<(), String> {
    match shutdown.try_send(()) {
        Ok(()) | Err(mpsc::TrySendError::Full(())) | Err(mpsc::TrySendError::Disconnected(())) => {}
    }
    let completion = finished
        .recv_timeout(completion_bound)
        .map_err(|error| format!("public HTTP server teardown exceeded its bound: {error}"));
    let join_result = join_finished_thread(join, completion_bound, "HTTP server");
    let completion = completion?;
    completion.map_err(|error| format!("public HTTP server teardown failed: {error}"))?;
    join_result
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

    let settlement =
        settle_http_server_with_bound(&shutdown_tx, &finished_rx, &mut server, Duration::ZERO);

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
        &mut server,
        HTTP_SERVER_TEARDOWN_BOUND,
    )
    .expect("the released server settles without detaching its owner");
    assert!(joined.load(Ordering::SeqCst));
    assert!(server.is_none(), "settlement joins the retained owner");
}

#[test]
fn e2e_http_fixture_reported_teardown_failure_still_joins_owner() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (shutdown_tx, shutdown_rx) = mpsc::sync_channel::<()>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let joined = Arc::new(AtomicBool::new(false));
    let joined_by_server = Arc::clone(&joined);
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
    let (shutdown_tx, shutdown_rx) = mpsc::sync_channel::<()>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let startup = HttpServerStartupGuard {
        shutdown: Some(shutdown_tx),
        finished: Some(finished_rx),
        join: Some(thread::spawn(move || {
            shutdown_rx
                .recv()
                .expect("startup guard requests bounded shutdown");
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
    let (shutdown_tx, _shutdown_rx) = mpsc::sync_channel::<()>(1);
    let (_finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let mut startup = HttpServerStartupGuard {
        shutdown: Some(shutdown_tx),
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
    let refusal = runtime_block_on_bounded(
        &cx,
        auto::client_builder()
            .client_info("e2e-modern-only-http-client", "1.0.0")
            .protocol_plan(plan(legacy_server.address(), ProtocolPolicy::ModernOnly))
            .connect_http_client_with_cx(&cx),
    )
    .expect_err("a ModernOnly facade plan must reject the LegacyOnly endpoint's live 400");
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
    assert!(ping.error.is_none(), "the positive exact-legacy ping must not fail");
    assert_eq!(ping.result, Some(json!({})));
    drop(client);
    legacy_server.shutdown();

    // This differs from the positive case only in the live server policy.
    // A LegacyOnly plan has no configured modern route and must not manufacture
    // an exact-legacy session after the ModernOnly endpoint refuses its SSE GET.
    let modern_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::ModernOnly);
    let refusal = runtime_block_on_bounded(
        &cx,
        auto::client_builder()
            .client_info("e2e-legacy-only-http-client", "1.0.0")
            .protocol_plan(plan(modern_server.address(), ProtocolPolicy::LegacyOnly))
            .connect_http_client_with_cx(&cx),
    )
    .expect_err("a LegacyOnly facade plan must reject the ModernOnly endpoint's live 400");
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
