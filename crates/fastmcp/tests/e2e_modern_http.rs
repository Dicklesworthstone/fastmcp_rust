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
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fastmcp_rust::server::FinalMethodOutcome;
use fastmcp_rust::{
    AuthContext, CacheScope, CacheTtl, CanonicalHttpUrl, ClientCapabilities,
    ClientHttpConnectionError, ClientHttpResponse, ClientProtocolPlan, CompletionHandler, Content,
    ContentBlock, CoreResult, Cx, EmbeddedResourceContents, FinalCoreResult,
    FinalElicitationContextExt, FinalEmbeddedRootsListParams, FinalResourceTemplate,
    FinalRootsContextExt, FinalSamplingContextExt, FinalToolOutcome, HttpNonquiescentShutdown,
    HttpServerShutdown, HttpShutdownSettlement, JsonRpcMessage, JsonRpcRequest, McpContext,
    McpError, McpErrorCode, McpRequestCancellation, McpResult, Middleware, MiddlewareDecision,
    ModernHttpResponseKind, ModernHttpResponseStream, Prompt, PromptHandler, PromptMessage,
    ProtocolEra, ProtocolPolicy, Resource, ResourceContent, ResourceHandler, ResourceTemplate,
    Role, SseLimits, StaticTokenVerifier, TokenAuthProvider, Tool, ToolHandler, auto, core,
    legacy_2024, modern, prompt, providers, resource, tool,
};
#[cfg(feature = "proxy")]
use fastmcp_rust::{ClientInfo, ProxyClient};
#[cfg(feature = "tasks")]
use fastmcp_rust::{FinalTaskId, FinalTaskWorkDescriptor, FinalToolCallOutcome, RequestId};
use fastmcp_server::ServerBuilder;
use serde_json::json;

const PUBLIC_HTTP_TOOL_NAME: &str = "public-http-e2e-tool";
const PUBLIC_HTTP_TASK_TOOL_NAME: &str = "public-http-e2e-task";
const PUBLIC_HTTP_LOG_TOOL_NAME: &str = "public-http-e2e-log";
const PUBLIC_HTTP_HANDLER_LOG_TEXT: &str = "public-http-handler-info";
const PUBLIC_HTTP_CURSOR_SECONDARY_TOOL_NAME: &str = "public-http-e2e-cursor-secondary";
const PUBLIC_HTTP_RESOURCE_URI: &str = "test://public-http-e2e/resource";
const PUBLIC_HTTP_PROMPT_NAME: &str = "public-http-e2e-prompt";
const PUBLIC_HTTP_TOOL_ARGUMENT: &str = "cross-era";
const PUBLIC_HTTP_TOOL_TEXT: &str = "tool:cross-era";
const PUBLIC_HTTP_RESOURCE_TEXT: &str = "resource:deterministic";
const PUBLIC_HTTP_PROMPT_TEXT: &str = "prompt:cross-era";
const PUBLIC_HTTP_COMPLETION_VALUE: &str = "cross-era-completion";

/// The deterministic user handler exercised through both public HTTP facades.
#[tool(name = "public-http-e2e-tool", tags = ["cursor"])]
fn public_http_value(_ctx: &McpContext, value: String) -> String {
    format!("tool:{value}")
}

/// Additional catalog entries make the public cursor test cross a real page
/// boundary while keeping the ordinary tool handler deterministic.
#[tool(name = "public-http-e2e-cursor-secondary", tags = ["cursor"])]
fn public_http_cursor_secondary(_ctx: &McpContext) -> String {
    "cursor-secondary".to_owned()
}

/// Deliberately outside the cursor query used by the positive continuation.
#[tool(name = "public-http-e2e-cursor-other", tags = ["other"])]
fn public_http_cursor_other(_ctx: &McpContext) -> String {
    "cursor-other".to_owned()
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

/// Live modern HTTP tool whose official Tasks create is visible through a prefixed gateway.
#[cfg(all(feature = "proxy", feature = "tasks"))]
struct PublicHttpTaskTool;

#[cfg(all(feature = "proxy", feature = "tasks"))]
impl ToolHandler for PublicHttpTaskTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_TASK_TOOL_NAME.to_owned(),
            description: Some("Creates one official final Tasks operation".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("exact-2024 Tasks are unavailable")])
    }

    fn declares_final_tasks(&self) -> bool {
        true
    }

    fn call_final_outcome(
        &self,
        _ctx: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        Ok(FinalToolOutcome::CreateTask {
            work_descriptor: FinalTaskWorkDescriptor::new(json!({
                "operation": "public-http-e2e-task",
            }))?,
            status_message: Some("working through the public HTTP as_proxy Tasks relay".to_owned()),
        })
    }
}

#[derive(Default)]
struct PublicHttpHandlerCallCounters {
    tool: AtomicUsize,
    resource: AtomicUsize,
    prompt: AtomicUsize,
    completion: AtomicUsize,
}

#[derive(Debug, Eq, PartialEq)]
struct PublicHttpHandlerCallSnapshot {
    tool: usize,
    resource: usize,
    prompt: usize,
    completion: usize,
}

impl PublicHttpHandlerCallCounters {
    fn snapshot(&self) -> PublicHttpHandlerCallSnapshot {
        PublicHttpHandlerCallSnapshot {
            tool: self.tool.load(Ordering::SeqCst),
            resource: self.resource.load(Ordering::SeqCst),
            prompt: self.prompt.load(Ordering::SeqCst),
            completion: self.completion.load(Ordering::SeqCst),
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

struct CountingPublicHttpCompletion {
    counters: Arc<PublicHttpHandlerCallCounters>,
}

impl CompletionHandler for CountingPublicHttpCompletion {
    fn complete_legacy(
        &self,
        _context: &McpContext,
        _params: legacy_2024::LegacyCompletionParams,
    ) -> McpResult<legacy_2024::CompletionValues> {
        Ok(legacy_2024::CompletionValues {
            values: vec![PUBLIC_HTTP_COMPLETION_VALUE.to_owned()],
            total: Some(1),
            has_more: Some(false),
        })
    }

    fn complete_final(
        &self,
        context: &McpContext,
        params: modern::FinalCompletionParams,
    ) -> McpResult<modern::FinalCompletionValues> {
        context.report_progress(0.5, Some("completion-halfway"));
        self.counters.completion.fetch_add(1, Ordering::SeqCst);
        if !matches!(
            &params.reference,
            modern::FinalCompletionReference::PromptWithTitle { name, title }
                if name == PUBLIC_HTTP_PROMPT_NAME && title == "Public HTTP E2E Prompt"
        ) || params.argument.name != "subject"
            || params.argument.value != "cross-era"
            || params
                .context
                .as_ref()
                .and_then(|context| context.arguments.as_ref())
                .and_then(|arguments| arguments.get("region"))
                .map(String::as_str)
                != Some("us-east-1")
        {
            return Err(McpError::invalid_params(
                "the completion fixture requires the exact modern request shape",
            ));
        }
        Ok(modern::FinalCompletionValues {
            values: vec![PUBLIC_HTTP_COMPLETION_VALUE.to_owned()],
            total: Some(modern::JsonInteger::from(1_i64)),
            has_more: Some(false),
        })
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

    fn spawn_modern_with_page_size(page_size: usize) -> Self {
        spawn_modern_facade_http_server(false, Some(page_size), false)
    }

    fn spawn_with_middleware(middleware: Option<Arc<dyn Middleware>>) -> Self {
        Self::spawn_with_policy_and_middleware(ProtocolPolicy::Auto, middleware)
    }

    fn spawn_with_policy_and_middleware(
        protocol_policy: ProtocolPolicy,
        middleware: Option<Arc<dyn Middleware>>,
    ) -> Self {
        Self::spawn_with_configuration(protocol_policy, middleware, None)
    }

    fn spawn_with_configuration(
        protocol_policy: ProtocolPolicy,
        middleware: Option<Arc<dyn Middleware>>,
        page_size: Option<usize>,
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
                let builder = match page_size {
                    Some(page_size) => builder.list_page_size(page_size),
                    None => builder,
                };
                let builder = builder
                    .tool(CountingPublicHttpValue {
                        counters: tool_calls,
                    })
                    .tool(PublicHttpCursorSecondary)
                    .tool(PublicHttpCursorOther)
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

/// Starts the public ModernOnly facade with optional native bearer admission.
///
/// This fixture intentionally uses the facade builder instead of the lower
/// server crate so the test covers the public modern API's HTTP delegation.
fn spawn_modern_facade_http_server(
    with_native_bearer_auth: bool,
    page_size: Option<usize>,
    with_resource: bool,
) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let tool_calls = Arc::clone(&handler_calls);
    let resource_calls = Arc::clone(&handler_calls);
    let prompt_calls = Arc::clone(&handler_calls);
    let completion_calls = Arc::clone(&handler_calls);
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("authenticated HTTP server control receiver went away".to_owned());
            }
            let builder = modern::ServerBuilder::new("facade-native-http-auth", "1.0.0");
            let builder = if with_native_bearer_auth {
                let verifier = StaticTokenVerifier::new([(
                    "alpha",
                    AuthContext::with_subject("e2e-native-http-principal"),
                )])
                .expect("the deterministic native bearer verifier is valid")
                .with_allowed_schemes(["Bearer"])
                .expect("the bearer scheme allowlist is valid");
                builder.auth_provider(TokenAuthProvider::new(verifier))
            } else {
                builder
            };
            let builder = builder.tool(CountingPublicHttpValue {
                counters: tool_calls,
            });
            let builder = match page_size {
                Some(page_size) => builder
                    .list_page_size(page_size)
                    .tool(PublicHttpCursorSecondary)
                    .tool(PublicHttpCursorOther),
                None => builder,
            };
            let builder = if with_resource {
                builder.resource(CountingPublicHttpSnapshot {
                    counters: resource_calls,
                })
            } else {
                let _ = resource_calls;
                builder
            };
            let server = builder
                .prompt(CountingPublicHttpInstruction {
                    counters: prompt_calls,
                })
                .prompt_completion_handler(
                    PUBLIC_HTTP_PROMPT_NAME,
                    CountingPublicHttpCompletion {
                        counters: completion_calls,
                    },
                )
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("authenticated facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("authenticated facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("authenticated HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("authenticated facade HTTP server stopped unexpectedly: {error}")
            })
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
            panic!("authenticated facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("authenticated facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("authenticated facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

/// Starts a public ModernOnly facade whose catalog is composed with `mount()`.
///
/// Tools and prompts come from a prefixed child (`child/...`). The resource
/// stays unprefixed so its exact final URI remains absolute.
fn spawn_modern_mounted_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("mounted HTTP server control receiver went away".to_owned());
            }
            let child = modern::ServerBuilder::new("facade-mounted-child", "1.0.0")
                .tool(PublicHttpValue)
                .prompt(PublicHttpInstructionPrompt)
                .resource(PublicHttpSnapshotResource)
                .build();
            let server = modern::ServerBuilder::new("facade-mounted-parent", "1.0.0")
                .mount(child, Some("child"))
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("mounted facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("mounted facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("mounted HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("mounted facade HTTP server stopped unexpectedly: {error}")
            })
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
            panic!("mounted facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("mounted facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("mounted facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
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
        Ok(()) | Err(mpsc::TrySendError::Full(()) | mpsc::TrySendError::Disconnected(())) => {}
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
    assert_eq!(
        client.protocol_policy(),
        legacy_2024::ProtocolPolicy::LegacyOnly
    );

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
            Ok(()) | Err(mpsc::TrySendError::Full(()) | mpsc::TrySendError::Disconnected(())) => {}
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
fn e2e_public_sse_constructor_invokes_live_legacy_handlers() {
    let cx = Cx::for_request();
    let server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::LegacyOnly);
    let mut client = runtime_block_on_bounded(
        &cx,
        fastmcp_rust::Client::sse_with_cx(
            public_http_target(server.address(), "/sse"),
            public_http_target(server.address(), "/messages"),
            &cx,
        ),
    )
    .expect("Client::sse_with_cx connects exact-2024 SSE without probing modern HTTP");

    let result = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_TOOL_NAME,
            json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        ),
    )
    .expect("the standalone SSE constructor must invoke the live legacy tool");
    let CoreResult::Legacy(legacy_2024::LegacyCoreResult::ToolsCall(result)) = result else {
        panic!("Client::sse must stay on the exact-2024 tool result: {result:?}");
    };
    let tool = serde_json::to_value(result)
        .expect("the exact-2024 SSE tool result serializes for its observable assertion");
    assert_eq!(
        tool["content"][0]["text"],
        json!(PUBLIC_HTTP_TOOL_TEXT),
        "Client::sse must retain the live handler value"
    );
    drop(client);
    server.shutdown();
}

#[cfg(feature = "proxy")]
fn spawn_modern_http_proxy_gateway(upstream: SocketAddr) -> HttpServerFixture {
    spawn_modern_http_proxy_gateway_with_prefix(upstream, None)
}

#[cfg(feature = "proxy")]
fn spawn_modern_http_proxy_gateway_with_prefix(
    upstream: SocketAddr,
    prefix: Option<&'static str>,
) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(
                asupersync::runtime::reactor::create_reactor()
                    .expect("proxy gateway HTTP server reactor initializes"),
            )
            .build()
            .expect("proxy gateway HTTP server installs an owned runtime");
        let outcome = runtime.block_on(async move {
            let cx =
                Cx::current().expect("owned gateway runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("proxy gateway HTTP server control receiver went away".to_owned());
            }
            let plan = ClientProtocolPlan::http(
                ProtocolPolicy::ModernOnly,
                Some(public_http_target(upstream, "/mcp")),
                None,
                None,
                "e2e-http-proxy-gateway".to_owned(),
                "e2e-http-proxy-gateway".to_owned(),
                "modern-http".to_owned(),
                0,
                0,
                0,
            )
            .map_err(|error| format!("proxy gateway HTTP plan failed: {error}"))?;
            let mut registry = ProxyClient::upstream_binding_registry();
            let proxy = registry
                .connect_http_with_protocol_plan(
                    "e2e-live-upstream",
                    "native-h1:e2e-live-upstream",
                    1,
                    plan,
                    ClientInfo {
                        name: "e2e-http-proxy".to_owned(),
                        version: "1.0.0".to_owned(),
                    },
                    ClientCapabilities::default(),
                    cx.clone(),
                )
                .map_err(|error| format!("live HTTP proxy upstream connect failed: {error}"))?;
            let catalog = proxy
                .catalog_typed()
                .map_err(|error| format!("live HTTP proxy catalog failed: {error}"))?;
            let tool_names = catalog
                .final_tools()
                .map(|tools| {
                    tools
                        .iter()
                        .map(|tool| tool.name.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !tool_names.contains(&PUBLIC_HTTP_TOOL_NAME) {
                return Err(format!(
                    "live HTTP proxy catalog omitted {PUBLIC_HTTP_TOOL_NAME}: {tool_names:?}"
                ));
            }
            let prompt_names = catalog
                .final_prompts()
                .map(|prompts| {
                    prompts
                        .iter()
                        .map(|prompt| prompt.name.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !prompt_names.contains(&PUBLIC_HTTP_PROMPT_NAME) {
                return Err(format!(
                    "live HTTP proxy catalog omitted {PUBLIC_HTTP_PROMPT_NAME}: {prompt_names:?}"
                ));
            }
            let resource_uris = catalog
                .final_resources()
                .map(|resources| {
                    resources
                        .iter()
                        .map(|resource| resource.uri.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !resource_uris.contains(&PUBLIC_HTTP_RESOURCE_URI) {
                return Err(format!(
                    "live HTTP proxy catalog omitted {PUBLIC_HTTP_RESOURCE_URI}: {resource_uris:?}"
                ));
            }
            let server = match prefix {
                Some(prefix) => {
                    let server = modern::ServerBuilder::new("e2e-http-gateway", "1.0.0")
                        .as_proxy_typed(prefix, proxy, catalog)
                        .map_err(|error| format!("as_proxy_typed install failed: {error}"))?
                        .build();
                    if server.final_task_runtime().is_some() {
                        return Err(
                            "as_proxy_typed must install the route-bound Tasks relay instead of the default in-memory store"
                                .to_owned(),
                        );
                    }
                    server
                }
                None => modern::ServerBuilder::new("e2e-http-gateway", "1.0.0")
                    .proxy_typed(proxy, catalog)
                    .map_err(|error| format!("proxy_typed install failed: {error}"))?
                    .build(),
            };
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("proxy gateway HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("proxy gateway HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("proxy gateway HTTP server startup receiver went away".to_owned());
            }
            bound
                .serve(&cx)
                .await
                .map_err(|error| format!("proxy gateway HTTP server stopped unexpectedly: {error}"))
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
            panic!("proxy gateway HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("proxy gateway HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("proxy gateway HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[cfg(feature = "proxy")]
#[test]
fn e2e_public_http_proxy_gateway_forwards_live_bind_http_tool() {
    let cx = Cx::for_request();
    let upstream = spawn_modern_facade_http_server(false, None, true);
    let gateway = spawn_modern_http_proxy_gateway(upstream.address());
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-proxy-client", "1.0.0")
            .connect_http_with_cx(public_http_target(gateway.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live HTTP proxy gateway");

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("the live HTTP gateway must advertise the upstream tools/list catalog");
    assert!(
        listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOOL_NAME),
        "proxy_typed must retain the live upstream tool name: {listed:?}"
    );

    let result = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_TOOL_NAME,
            json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        ),
    )
    .expect("the live HTTP gateway must forward tools/call to the upstream bind_http server");
    assert!(
        result.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == PUBLIC_HTTP_TOOL_TEXT,
            _ => false,
        }),
        "the proxied live tool must retain the upstream handler value: {result:?}"
    );

    let listed_prompts = runtime_block_on_bounded(&cx, client.list_prompts(&cx, None))
        .expect("the live HTTP gateway must advertise the upstream prompts/list catalog");
    assert!(
        listed_prompts
            .prompts
            .iter()
            .any(|prompt| prompt.name == PUBLIC_HTTP_PROMPT_NAME),
        "proxy_typed must retain the live upstream prompt name: {listed_prompts:?}"
    );
    let prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            PUBLIC_HTTP_PROMPT_NAME,
            HashMap::from([("subject".to_owned(), PUBLIC_HTTP_TOOL_ARGUMENT.to_owned())]),
        ),
    )
    .expect("the live HTTP gateway must forward prompts/get to the upstream bind_http server");
    let prompt = serde_json::to_value(prompt)
        .expect("the proxied prompt result serializes for its observable assertion");
    assert_eq!(
        prompt["messages"][0]["content"]["text"],
        json!(PUBLIC_HTTP_PROMPT_TEXT),
        "the proxied live prompt must retain the upstream handler value: {prompt:?}"
    );

    let listed_resources = runtime_block_on_bounded(&cx, client.list_resources(&cx, None))
        .expect("the live HTTP gateway must advertise the upstream resources/list catalog");
    assert!(
        listed_resources
            .resources
            .iter()
            .any(|resource| resource.uri.as_str() == PUBLIC_HTTP_RESOURCE_URI),
        "proxy_typed must retain the live upstream resource URI: {listed_resources:?}"
    );
    let resource =
        runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_RESOURCE_URI)).expect(
            "the live HTTP gateway must forward resources/read to the upstream bind_http server",
        );
    assert!(
        matches!(
            resource.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == PUBLIC_HTTP_RESOURCE_TEXT
        ),
        "the proxied live resource must retain the upstream handler value: {:?}",
        resource.contents
    );

    let completion = runtime_block_on_bounded(
        &cx,
        client.complete(
            &cx,
            modern::CompletionParams {
                reference: modern::CompletionReference::PromptWithTitle {
                    name: PUBLIC_HTTP_PROMPT_NAME.to_owned(),
                    title: "Public HTTP E2E Prompt".to_owned(),
                },
                argument: modern::FinalCompletionArgument {
                    name: "subject".to_owned(),
                    value: "cross-era".to_owned(),
                },
                context: Some(modern::FinalCompletionContext {
                    arguments: Some(std::collections::BTreeMap::from([(
                        "region".to_owned(),
                        "us-east-1".to_owned(),
                    )])),
                }),
            },
        ),
    )
    .expect(
        "the live HTTP gateway must forward completion/complete to the upstream bind_http server",
    );
    assert_eq!(
        completion.completion.values,
        vec![PUBLIC_HTTP_COMPLETION_VALUE.to_owned()],
        "the proxied live completion must retain the upstream provider values: {completion:?}"
    );

    drop(client);
    gateway.shutdown();
    upstream.shutdown();
}

#[cfg(feature = "proxy")]
#[test]
fn e2e_public_http_prefixed_as_proxy_forwards_prefixed_tool_and_unprefixed_resource() {
    const PREFIXED_TOOL_NAME: &str = "ext/public-http-e2e-tool";
    const PREFIXED_PROMPT_NAME: &str = "ext/public-http-e2e-prompt";

    let cx = Cx::for_request();
    let upstream = spawn_modern_facade_http_server(false, None, true);
    let gateway = spawn_modern_http_proxy_gateway_with_prefix(upstream.address(), Some("ext"));
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-as-proxy-client", "1.0.0")
            .connect_http_with_cx(public_http_target(gateway.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live prefixed as_proxy HTTP gateway");

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("the live prefixed gateway must advertise the upstream tools/list catalog");
    assert!(
        listed
            .tools
            .iter()
            .any(|tool| tool.name == PREFIXED_TOOL_NAME),
        "as_proxy_typed must prefix the live upstream tool name: {listed:?}"
    );
    assert!(
        !listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOOL_NAME),
        "a nonempty as_proxy prefix must not keep the unprefixed upstream tool: {listed:?}"
    );

    let result = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PREFIXED_TOOL_NAME,
            json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        ),
    )
    .expect("the live prefixed gateway must forward tools/call to the upstream bind_http server");
    assert!(
        result.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == PUBLIC_HTTP_TOOL_TEXT,
            _ => false,
        }),
        "the prefixed live tool must retain the upstream handler value: {result:?}"
    );

    let listed_prompts = runtime_block_on_bounded(&cx, client.list_prompts(&cx, None))
        .expect("the live prefixed gateway must advertise the upstream prompts/list catalog");
    assert!(
        listed_prompts
            .prompts
            .iter()
            .any(|prompt| prompt.name == PREFIXED_PROMPT_NAME),
        "as_proxy_typed must prefix the live upstream prompt name: {listed_prompts:?}"
    );
    let prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            PREFIXED_PROMPT_NAME,
            HashMap::from([("subject".to_owned(), PUBLIC_HTTP_TOOL_ARGUMENT.to_owned())]),
        ),
    )
    .expect("the live prefixed gateway must forward prompts/get to the upstream bind_http server");
    let prompt = serde_json::to_value(prompt)
        .expect("the prefixed prompt result serializes for its observable assertion");
    assert_eq!(
        prompt["messages"][0]["content"]["text"],
        json!(PUBLIC_HTTP_PROMPT_TEXT),
        "the prefixed live prompt must retain the upstream handler value: {prompt:?}"
    );

    let listed_resources = runtime_block_on_bounded(&cx, client.list_resources(&cx, None)).expect(
        "the live prefixed gateway must advertise the exact upstream resources/list catalog",
    );
    assert!(
        listed_resources
            .resources
            .iter()
            .any(|resource| resource.uri.as_str() == PUBLIC_HTTP_RESOURCE_URI),
        "as_proxy_typed must keep the exact final resource URI: {listed_resources:?}"
    );
    assert!(
        listed_resources
            .resources
            .iter()
            .all(|resource| { !resource.uri.as_str().starts_with("ext/") }),
        "a nonempty as_proxy prefix must not invent a non-absolute modern resource URI: {listed_resources:?}"
    );
    let resource = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_RESOURCE_URI),
    )
    .expect(
        "the live prefixed gateway must forward resources/read to the upstream bind_http server",
    );
    assert!(
        matches!(
            resource.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == PUBLIC_HTTP_RESOURCE_TEXT
        ),
        "the prefixed live resource must retain the upstream handler value: {:?}",
        resource.contents
    );

    let completion = runtime_block_on_bounded(
        &cx,
        client.complete(
            &cx,
            modern::CompletionParams {
                reference: modern::CompletionReference::PromptWithTitle {
                    name: PREFIXED_PROMPT_NAME.to_owned(),
                    title: "Public HTTP E2E Prompt".to_owned(),
                },
                argument: modern::FinalCompletionArgument {
                    name: "subject".to_owned(),
                    value: "cross-era".to_owned(),
                },
                context: Some(modern::FinalCompletionContext {
                    arguments: Some(std::collections::BTreeMap::from([(
                        "region".to_owned(),
                        "us-east-1".to_owned(),
                    )])),
                }),
            },
        ),
    )
    .expect(
        "the live prefixed gateway must forward completion/complete to the upstream bind_http server",
    );
    assert_eq!(
        completion.completion.values,
        vec![PUBLIC_HTTP_COMPLETION_VALUE.to_owned()],
        "the prefixed live completion must retain the upstream provider values: {completion:?}"
    );

    drop(client);
    gateway.shutdown();
    upstream.shutdown();
}

#[cfg(all(feature = "proxy", feature = "tasks"))]
fn spawn_modern_task_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("task HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-task", "1.0.0")
                .tool(PublicHttpTaskTool)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("task facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("task facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("task HTTP server startup receiver went away".to_owned());
            }
            bound
                .serve(&cx)
                .await
                .map_err(|error| format!("task facade HTTP server stopped unexpectedly: {error}"))
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
            panic!("task facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("task facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("task facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[cfg(all(feature = "proxy", feature = "tasks"))]
fn spawn_modern_http_task_proxy_gateway(upstream: SocketAddr) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(
                asupersync::runtime::reactor::create_reactor()
                    .expect("task proxy gateway HTTP server reactor initializes"),
            )
            .build()
            .expect("task proxy gateway HTTP server installs an owned runtime");
        let outcome = runtime.block_on(async move {
            let cx =
                Cx::current().expect("owned gateway runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("task proxy gateway HTTP server control receiver went away".to_owned());
            }
            let plan = ClientProtocolPlan::http(
                ProtocolPolicy::ModernOnly,
                Some(public_http_target(upstream, "/mcp")),
                None,
                None,
                "e2e-http-task-proxy-gateway".to_owned(),
                "e2e-http-task-proxy-gateway".to_owned(),
                "modern-http".to_owned(),
                0,
                0,
                0,
            )
            .map_err(|error| format!("task proxy gateway HTTP plan failed: {error}"))?;
            let mut registry = ProxyClient::upstream_binding_registry();
            let proxy = registry
                .connect_http_with_protocol_plan(
                    "e2e-live-task-upstream",
                    "native-h1:e2e-live-task-upstream",
                    1,
                    plan,
                    ClientInfo {
                        name: "e2e-http-task-proxy".to_owned(),
                        version: "1.0.0".to_owned(),
                    },
                    ClientCapabilities::default(),
                    cx.clone(),
                )
                .map_err(|error| format!("live HTTP task proxy upstream connect failed: {error}"))?;
            let catalog = proxy
                .catalog_typed()
                .map_err(|error| format!("live HTTP task proxy catalog failed: {error}"))?;
            let tool_names = catalog
                .final_tools()
                .map(|tools| {
                    tools
                        .iter()
                        .map(|tool| tool.name.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !tool_names.contains(&PUBLIC_HTTP_TASK_TOOL_NAME) {
                return Err(format!(
                    "live HTTP task proxy catalog omitted {PUBLIC_HTTP_TASK_TOOL_NAME}: {tool_names:?}"
                ));
            }
            let server = modern::ServerBuilder::new("e2e-http-task-gateway", "1.0.0")
                .as_proxy_typed("ext", proxy, catalog)
                .map_err(|error| format!("as_proxy_typed task install failed: {error}"))?
                .build();
            if server.final_task_runtime().is_some() {
                return Err(
                    "as_proxy_typed must install the route-bound Tasks relay instead of the default in-memory store"
                        .to_owned(),
                );
            }
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("task proxy gateway HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("task proxy gateway HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("task proxy gateway HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("task proxy gateway HTTP server stopped unexpectedly: {error}")
            })
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
            panic!("task proxy gateway HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("task proxy gateway HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("task proxy gateway HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[cfg(all(feature = "proxy", feature = "tasks"))]
#[test]
fn e2e_public_http_prefixed_as_proxy_gets_upstream_created_task() {
    let cx = Cx::for_request();
    let upstream = spawn_modern_task_http_server();
    let gateway = spawn_modern_http_task_proxy_gateway(upstream.address());

    let mut upstream_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-task-upstream-client", "1.0.0")
            .connect_http_with_cx(public_http_target(upstream.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live task upstream HTTP server");
    let created = runtime_block_on_bounded(
        &cx,
        upstream_client.call_tool_outcome(
            &cx,
            RequestId::Number(2),
            PUBLIC_HTTP_TASK_TOOL_NAME,
            json!({}),
            1 << 20,
        ),
    )
    .expect("the live upstream must create one official Task");
    let FinalToolCallOutcome::Task(created) = created else {
        panic!(
            "the task-capable live tool must return the official Task result branch: {created:?}"
        );
    };
    let task_id = created.task.base().task_id.clone();
    drop(upstream_client);

    let mut gateway_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-task-gateway-client", "1.0.0")
            .connect_http_with_cx(public_http_target(gateway.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live prefixed as_proxy Tasks gateway");

    let observed = runtime_block_on_bounded(
        &cx,
        gateway_client.get_task(&cx, RequestId::Number(4), task_id.clone(), 1 << 20),
    )
    .expect("the live prefixed gateway must forward tasks/get to the upstream store");
    assert_eq!(
        observed.task.base().task_id,
        task_id,
        "as_proxy_typed must return the upstream-created Task rather than a disconnected local store: {observed:?}"
    );

    let missing = FinalTaskId::parse("missing-upstream-task")
        .expect("the planted-missing task id is a valid official TaskId");
    let missing = runtime_block_on_bounded(
        &cx,
        gateway_client.get_task(&cx, RequestId::Number(5), missing, 1 << 20),
    )
    .expect_err("changing only the task id must not invent a Task on the gateway");
    let _ = missing;

    drop(gateway_client);
    gateway.shutdown();
    upstream.shutdown();
}

#[cfg(feature = "proxy")]
fn spawn_modern_http_template_proxy_gateway(
    upstream: SocketAddr,
    expected_template: &'static str,
) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(
                asupersync::runtime::reactor::create_reactor()
                    .expect("template proxy gateway HTTP server reactor initializes"),
            )
            .build()
            .expect("template proxy gateway HTTP server installs an owned runtime");
        let outcome = runtime.block_on(async move {
            let cx =
                Cx::current().expect("owned gateway runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err(
                    "template proxy gateway HTTP server control receiver went away".to_owned(),
                );
            }
            let plan = ClientProtocolPlan::http(
                ProtocolPolicy::ModernOnly,
                Some(public_http_target(upstream, "/mcp")),
                None,
                None,
                "e2e-http-template-proxy-gateway".to_owned(),
                "e2e-http-template-proxy-gateway".to_owned(),
                "modern-http".to_owned(),
                0,
                0,
                0,
            )
            .map_err(|error| format!("template proxy gateway HTTP plan failed: {error}"))?;
            let mut registry = ProxyClient::upstream_binding_registry();
            let proxy = registry
                .connect_http_with_protocol_plan(
                    "e2e-live-template-upstream",
                    "native-h1:e2e-live-template-upstream",
                    1,
                    plan,
                    ClientInfo {
                        name: "e2e-http-template-proxy".to_owned(),
                        version: "1.0.0".to_owned(),
                    },
                    ClientCapabilities::default(),
                    cx.clone(),
                )
                .map_err(|error| {
                    format!("live HTTP template proxy upstream connect failed: {error}")
                })?;
            let catalog = proxy
                .catalog_typed()
                .map_err(|error| format!("live HTTP template proxy catalog failed: {error}"))?;
            let templates = catalog
                .final_resource_templates()
                .map(|templates| {
                    templates
                        .iter()
                        .map(|template| template.uri_template.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !templates.contains(&expected_template) {
                return Err(format!(
                    "live HTTP template proxy catalog omitted {expected_template}: {templates:?}"
                ));
            }
            let server = modern::ServerBuilder::new("e2e-http-template-gateway", "1.0.0")
                .as_proxy_typed("ext", proxy, catalog)
                .map_err(|error| format!("as_proxy_typed template install failed: {error}"))?
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message =
                        format!("template proxy gateway HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("template proxy gateway HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err(
                    "template proxy gateway HTTP server startup receiver went away".to_owned(),
                );
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("template proxy gateway HTTP server stopped unexpectedly: {error}")
            })
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
            panic!("template proxy gateway HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("template proxy gateway HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("template proxy gateway HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[cfg(feature = "proxy")]
#[test]
fn e2e_public_http_prefixed_as_proxy_forwards_unprefixed_resource_template() {
    let cx = Cx::for_request();
    let (upstream, reads) = spawn_modern_template_http_server();
    let gateway =
        spawn_modern_http_template_proxy_gateway(upstream.address(), PUBLIC_HTTP_TEMPLATE);
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-as-proxy-template-client", "1.0.0")
            .connect_http_with_cx(public_http_target(gateway.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live template as_proxy HTTP gateway");

    let listed = runtime_block_on_bounded(&cx, client.list_resource_templates(&cx, None))
        .expect("the live prefixed gateway must advertise the exact upstream resource template");
    assert!(
        listed
            .resource_templates
            .iter()
            .any(|template| template.uri_template == PUBLIC_HTTP_TEMPLATE
                && template.name == PUBLIC_HTTP_TEMPLATE_NAME),
        "as_proxy_typed must keep the exact final resource template: {:?}",
        listed.resource_templates
    );
    assert!(
        listed
            .resource_templates
            .iter()
            .all(|template| !template.uri_template.starts_with("ext/")),
        "a nonempty as_proxy prefix must not invent a non-absolute template URI: {:?}",
        listed.resource_templates
    );

    let matched = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_TEMPLATE_MATCHED_URI),
    )
    .expect("the live prefixed gateway must expand a URI that matches the upstream template");
    assert!(
        matches!(
            matched.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == "item:alpha"
        ),
        "the proxied matched template read must retain the extracted id: {:?}",
        matched.contents
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "a matching proxied resources/read must invoke the upstream templated handler once"
    );

    let unmatched = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_TEMPLATE_UNMATCHED_URI),
    )
    .expect_err(
        "changing only the path that the template cannot bind must refuse before upstream dispatch",
    );
    assert!(
        matches!(
            unmatched,
            modern::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::InvalidParams
        ),
        "an unmatched proxied template URI must stay InvalidParams: {unmatched:?}"
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "the unmatched URI must leave the upstream templated handler uninvoked"
    );

    drop(client);
    gateway.shutdown();
    upstream.shutdown();
}

#[test]
fn e2e_public_http_mount_forwards_prefixed_tool_and_unprefixed_resource() {
    const MOUNTED_TOOL_NAME: &str = "child/public-http-e2e-tool";
    const MOUNTED_PROMPT_NAME: &str = "child/public-http-e2e-prompt";

    let cx = Cx::for_request();
    let server = spawn_modern_mounted_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-mount-client", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live mounted HTTP server");

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("the mounted parent must advertise the prefixed child tools/list catalog");
    assert!(
        listed
            .tools
            .iter()
            .any(|tool| tool.name == MOUNTED_TOOL_NAME),
        "mount() must rewrite the child tool name: {listed:?}"
    );
    assert!(
        !listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOOL_NAME),
        "a nonempty mount prefix must not keep the unprefixed child tool: {listed:?}"
    );

    let result = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            MOUNTED_TOOL_NAME,
            json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        ),
    )
    .expect("the mounted parent must dispatch tools/call through the prefixed child handler");
    assert!(
        result.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == PUBLIC_HTTP_TOOL_TEXT,
            _ => false,
        }),
        "the mounted live tool must retain the child handler value: {result:?}"
    );

    let listed_prompts = runtime_block_on_bounded(&cx, client.list_prompts(&cx, None))
        .expect("the mounted parent must advertise the prefixed child prompts/list catalog");
    assert!(
        listed_prompts
            .prompts
            .iter()
            .any(|prompt| prompt.name == MOUNTED_PROMPT_NAME),
        "mount() must rewrite the child prompt name: {listed_prompts:?}"
    );
    let prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            MOUNTED_PROMPT_NAME,
            HashMap::from([("subject".to_owned(), PUBLIC_HTTP_TOOL_ARGUMENT.to_owned())]),
        ),
    )
    .expect("the mounted parent must dispatch prompts/get through the prefixed child handler");
    let prompt = serde_json::to_value(prompt)
        .expect("the mounted prompt result serializes for its observable assertion");
    assert_eq!(
        prompt["messages"][0]["content"]["text"],
        json!(PUBLIC_HTTP_PROMPT_TEXT),
        "the mounted live prompt must retain the child handler value: {prompt:?}"
    );

    let listed_resources = runtime_block_on_bounded(&cx, client.list_resources(&cx, None))
        .expect("the unprefixed mount must advertise the exact child resources/list catalog");
    assert!(
        listed_resources
            .resources
            .iter()
            .any(|resource| resource.uri.as_str() == PUBLIC_HTTP_RESOURCE_URI),
        "an unprefixed mount must keep the exact final resource URI: {listed_resources:?}"
    );
    assert!(
        listed_resources
            .resources
            .iter()
            .all(|resource| { !resource.uri.as_str().starts_with("child/") }),
        "a nonempty prefix must not invent a non-absolute modern resource URI: {listed_resources:?}"
    );
    let resource =
        runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_RESOURCE_URI))
            .expect("the unprefixed mount must dispatch resources/read through the child handler");
    assert!(
        matches!(
            resource.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == PUBLIC_HTTP_RESOURCE_TEXT
        ),
        "the mounted live resource must retain the child handler value: {:?}",
        resource.contents
    );

    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_FS_PREFIX: &str = "e2e";
const PUBLIC_HTTP_FS_TEMPLATE: &str = "file:///e2e/{+path}";
const PUBLIC_HTTP_FS_FILE_NAME: &str = "note.txt";
const PUBLIC_HTTP_FS_FILE_URI: &str = "file:///e2e/note.txt";
const PUBLIC_HTTP_FS_FILE_TEXT: &str = "filesystem:deterministic";

/// Starts a public ModernOnly facade whose catalog is one live FilesystemProvider.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_modern_filesystem_http_server() -> HttpServerFixture {
    spawn_modern_filesystem_http_server_named("direct")
}

fn spawn_modern_filesystem_http_server_named(label: &'static str) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let root = std::env::temp_dir().join(format!(
        "fastmcp-public-http-fs-e2e-{}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("the filesystem e2e root is created");
    std::fs::write(
        root.join(PUBLIC_HTTP_FS_FILE_NAME),
        PUBLIC_HTTP_FS_FILE_TEXT,
    )
    .expect("the filesystem e2e file is written");
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("filesystem HTTP server control receiver went away".to_owned());
            }
            let handler = providers::FilesystemProvider::new(&root)
                .with_prefix(PUBLIC_HTTP_FS_PREFIX)
                .with_exclude(&[])
                .build()
                .map_err(|error| format!("FilesystemProvider::build failed: {error}"))?;
            let server = if label == "mounted" {
                let child = modern::ServerBuilder::new("facade-filesystem-child", "1.0.0")
                    .resource(handler)
                    .build();
                modern::ServerBuilder::new("facade-filesystem-parent", "1.0.0")
                    .mount(child, Some("child"))
                    .build()
            } else {
                modern::ServerBuilder::new("facade-filesystem-http", "1.0.0")
                    .resource(handler)
                    .build()
            };
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("filesystem facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("filesystem facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("filesystem HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("filesystem facade HTTP server stopped unexpectedly: {error}")
            })
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
            panic!("filesystem facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("filesystem facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("filesystem facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn e2e_public_http_filesystem_provider_lists_and_reads_live_file() {
    let cx = Cx::for_request();
    let server = spawn_modern_filesystem_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-fs-client", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live filesystem HTTP server");

    let listed = runtime_block_on_bounded(&cx, client.list_resource_templates(&cx, None))
        .expect("live bind_http must list the FilesystemProvider template");
    assert!(
        listed
            .resource_templates
            .iter()
            .any(|template| template.uri_template == PUBLIC_HTTP_FS_TEMPLATE
                && template.name == PUBLIC_HTTP_FS_PREFIX),
        "FilesystemProvider must advertise its reversible file template: {:?}",
        listed.resource_templates
    );

    let unmatched =
        runtime_block_on_bounded(&cx, client.read_resource(&cx, "file:///other/note.txt"))
            .expect_err(
                "changing only the prefix the template cannot bind must refuse before dispatch",
            );
    assert!(
        matches!(
            unmatched,
            modern::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::InvalidParams
        ),
        "an unmatched filesystem URI must stay InvalidParams: {unmatched:?}"
    );

    let file = runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_FS_FILE_URI))
        .expect("resources/read must expand the live file URI through the filesystem handler");
    assert!(
        matches!(
            file.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == PUBLIC_HTTP_FS_FILE_TEXT
        ),
        "the live filesystem read must retain the file bytes: {:?}",
        file.contents
    );

    drop(client);
    server.shutdown();
}

#[cfg(all(feature = "proxy", any(target_os = "linux", target_os = "macos")))]
#[test]
fn e2e_public_http_prefixed_as_proxy_forwards_filesystem_template() {
    let cx = Cx::for_request();
    let upstream = spawn_modern_filesystem_http_server_named("as-proxy");
    let gateway =
        spawn_modern_http_template_proxy_gateway(upstream.address(), PUBLIC_HTTP_FS_TEMPLATE);
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-as-proxy-fs-client", "1.0.0")
            .connect_http_with_cx(public_http_target(gateway.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live filesystem as_proxy HTTP gateway");

    let listed = runtime_block_on_bounded(&cx, client.list_resource_templates(&cx, None))
        .expect("the live prefixed gateway must advertise the exact filesystem template");
    assert!(
        listed
            .resource_templates
            .iter()
            .any(|template| template.uri_template == PUBLIC_HTTP_FS_TEMPLATE
                && template.name == PUBLIC_HTTP_FS_PREFIX),
        "as_proxy_typed must keep the exact filesystem template: {:?}",
        listed.resource_templates
    );
    assert!(
        listed
            .resource_templates
            .iter()
            .all(|template| !template.uri_template.starts_with("ext/")),
        "a nonempty as_proxy prefix must not invent a non-absolute filesystem template URI: {:?}",
        listed.resource_templates
    );

    let unmatched = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, "file:///other/note.txt"),
    )
    .expect_err(
        "changing only the prefix the template cannot bind must refuse before upstream dispatch",
    );
    assert!(
        matches!(
            unmatched,
            modern::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::InvalidParams
        ),
        "an unmatched proxied filesystem URI must stay InvalidParams: {unmatched:?}"
    );

    let file = runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_FS_FILE_URI))
        .expect("the live prefixed gateway must expand the live file URI through the upstream filesystem handler");
    assert!(
        matches!(
            file.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == PUBLIC_HTTP_FS_FILE_TEXT
        ),
        "the proxied live filesystem read must retain the file bytes: {:?}",
        file.contents
    );

    drop(client);
    gateway.shutdown();
    upstream.shutdown();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn e2e_public_http_mount_forwards_unprefixed_filesystem_template() {
    let cx = Cx::for_request();
    let server = spawn_modern_filesystem_http_server_named("mounted");
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-mount-fs-client", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live mounted filesystem HTTP server");

    let listed = runtime_block_on_bounded(&cx, client.list_resource_templates(&cx, None))
        .expect("the mounted parent must advertise the exact filesystem template");
    assert!(
        listed
            .resource_templates
            .iter()
            .any(|template| template.uri_template == PUBLIC_HTTP_FS_TEMPLATE
                && template.name == PUBLIC_HTTP_FS_PREFIX),
        "mount() must keep the exact filesystem template: {:?}",
        listed.resource_templates
    );
    assert!(
        listed
            .resource_templates
            .iter()
            .all(|template| !template.uri_template.starts_with("child/")),
        "a nonempty mount prefix must not invent a non-absolute filesystem template URI: {:?}",
        listed.resource_templates
    );

    let unmatched = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, "file:///other/note.txt"),
    )
    .expect_err(
        "changing only the prefix the template cannot bind must refuse before the child handler",
    );
    assert!(
        matches!(
            unmatched,
            modern::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::InvalidParams
        ),
        "an unmatched mounted filesystem URI must stay InvalidParams: {unmatched:?}"
    );

    let file = runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_FS_FILE_URI))
        .expect(
            "the mounted parent must expand the live file URI through the child filesystem handler",
        );
    assert!(
        matches!(
            file.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == PUBLIC_HTTP_FS_FILE_TEXT
        ),
        "the mounted live filesystem read must retain the file bytes: {:?}",
        file.contents
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_modern_facade_native_http_negotiates_then_dispatches_authenticated_tool() {
    const MAX_NATIVE_HTTP_RESPONSE_BYTES: usize = 1 << 20;

    fn exchange(
        address: SocketAddr,
        protocol_version: &str,
        method: &str,
        tool_name: Option<&str>,
        body: &[u8],
    ) -> Vec<u8> {
        let mut stream = std::net::TcpStream::connect_timeout(&address, HTTP_OPERATION_BOUND)
            .expect("native HTTP client connects to the public facade listener");
        stream
            .set_read_timeout(Some(HTTP_OPERATION_BOUND))
            .expect("native HTTP client read deadline is configured");
        stream
            .set_write_timeout(Some(HTTP_OPERATION_BOUND))
            .expect("native HTTP client write deadline is configured");
        let tool_name_header =
            tool_name.map_or_else(String::new, |name| format!("Mcp-Name: {name}\r\n"));
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer alpha\r\nAccept: application/json\r\nContent-Type: application/json\r\nMCP-Protocol-Version: {protocol_version}\r\nMcp-Method: {method}\r\n{tool_name_header}Content-Length: {}\r\n\r\n",
            body.len(),
        );
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.write_all(body))
            .expect("native HTTP request commits to the public facade listener");
        let mut response = Vec::new();
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let read = stream
                .read(&mut buffer)
                .expect("native HTTP response reads within its configured deadline");
            if read == 0 {
                break;
            }
            assert!(
                response
                    .len()
                    .checked_add(read)
                    .is_some_and(|size| size <= MAX_NATIVE_HTTP_RESPONSE_BYTES),
                "native HTTP response exceeds the test's bounded response budget"
            );
            response.extend_from_slice(&buffer[..read]);
        }
        response
    }

    fn chunked_response_body(body: &[u8]) -> Vec<u8> {
        let mut cursor = 0;
        let mut decoded = Vec::new();
        loop {
            let size_end = body[cursor..]
                .windows(2)
                .position(|window| window == b"\r\n")
                .map(|offset| cursor + offset)
                .expect("chunked response contains a complete chunk-size line");
            let size_line = std::str::from_utf8(&body[cursor..size_end])
                .expect("chunked response chunk size is ASCII");
            let size = usize::from_str_radix(size_line.split(';').next().unwrap_or_default(), 16)
                .expect("chunked response chunk size is hexadecimal");
            cursor = size_end + 2;
            if size == 0 {
                loop {
                    let trailer_end = body[cursor..]
                        .windows(2)
                        .position(|window| window == b"\r\n")
                        .map(|offset| cursor + offset)
                        .expect("chunked response contains a complete trailer line");
                    let trailer = &body[cursor..trailer_end];
                    cursor = trailer_end + 2;
                    if trailer.is_empty() {
                        assert_eq!(
                            cursor,
                            body.len(),
                            "chunked response has no bytes after its terminal trailer"
                        );
                        return decoded;
                    }
                    assert!(
                        trailer.contains(&b':'),
                        "chunked response trailer has an HTTP field delimiter"
                    );
                }
            }
            let chunk_end = cursor
                .checked_add(size)
                .expect("chunked response chunk length does not overflow");
            assert!(
                chunk_end.checked_add(2).is_some_and(|terminator_end| {
                    terminator_end <= body.len() && &body[chunk_end..terminator_end] == b"\r\n"
                }),
                "chunked response contains a complete chunk body and terminator"
            );
            decoded.extend_from_slice(&body[cursor..chunk_end]);
            cursor = chunk_end + 2;
        }
    }

    fn response_body(response: &[u8]) -> Vec<u8> {
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("native HTTP response contains a complete header terminator");
        let headers = std::str::from_utf8(&response[..header_end])
            .expect("native HTTP response headers are ASCII");
        let mut content_length = None;
        let mut chunked = false;
        for header in headers.lines().skip(1) {
            let (name, value) = header
                .split_once(':')
                .expect("native HTTP response header has a field delimiter");
            if name.eq_ignore_ascii_case("content-length") {
                assert!(
                    content_length.is_none(),
                    "native HTTP response has one Content-Length field"
                );
                content_length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .expect("native HTTP Content-Length is a valid byte count"),
                );
            }
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"))
            {
                chunked = true;
            }
        }
        let body = &response[header_end + 4..];
        if chunked {
            assert!(
                content_length.is_none(),
                "chunked native HTTP response does not also carry Content-Length"
            );
            return chunked_response_body(body);
        }
        let content_length =
            content_length.expect("native HTTP response uses Content-Length or chunked framing");
        assert_eq!(
            body.len(),
            content_length,
            "native HTTP response body is complete according to Content-Length"
        );
        body.to_vec()
    }

    let server = spawn_modern_facade_http_server(true, None, false);
    let discovery = JsonRpcRequest::new(
        "server/discover",
        Some(json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": modern::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })),
        1_i64,
    );
    let discovery_body =
        serde_json::to_vec(&discovery).expect("exact-modern discovery request serializes");
    let discovery_response = exchange(
        server.address(),
        modern::PROTOCOL_VERSION,
        "server/discover",
        None,
        &discovery_body,
    );
    assert!(
        discovery_response.starts_with(b"HTTP/1.1 200"),
        "authenticated exact-modern discovery must succeed: {}",
        String::from_utf8_lossy(&discovery_response)
    );
    let discovery_body = response_body(&discovery_response);
    let discovery: serde_json::Value = serde_json::from_slice(&discovery_body)
        .expect("authenticated discovery response is JSON-RPC");
    assert_eq!(discovery["id"], json!(1));
    assert!(
        discovery.get("error").is_none(),
        "authenticated discovery must negotiate the modern era: {discovery}"
    );
    assert_eq!(discovery["result"]["resultType"], json!("complete"));
    assert_eq!(
        discovery["result"]["supportedVersions"],
        json!([modern::PROTOCOL_VERSION]),
        "the public server advertises only its exact final wire version"
    );
    assert_eq!(
        discovery["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        json!("facade-native-http-auth"),
        "final server identity belongs in result metadata, never a legacy initialize field"
    );
    assert_eq!(
        discovery["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["version"],
        json!("1.0.0")
    );
    assert_eq!(discovery["result"]["capabilities"]["tools"], json!({}));
    assert_eq!(discovery["result"]["capabilities"]["prompts"], json!({}));
    assert_eq!(
        discovery["result"]["capabilities"]["completions"],
        json!({})
    );
    assert_eq!(discovery["result"]["cacheScope"], json!("private"));
    assert!(
        discovery["result"]["ttlMs"].is_u64(),
        "final discovery exposes a nonnegative cache lifetime"
    );

    let tool = JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "name": PUBLIC_HTTP_TOOL_NAME,
            "arguments": {"value": PUBLIC_HTTP_TOOL_ARGUMENT},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": modern::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })),
        2_i64,
    );
    let tool_body = serde_json::to_vec(&tool).expect("exact-modern tool request serializes");
    let tool_response = exchange(
        server.address(),
        modern::PROTOCOL_VERSION,
        "tools/call",
        Some(PUBLIC_HTTP_TOOL_NAME),
        &tool_body,
    );
    assert!(
        tool_response.starts_with(b"HTTP/1.1 200"),
        "authenticated exact-modern tool call must succeed: {}",
        String::from_utf8_lossy(&tool_response)
    );
    let tool_response_body = response_body(&tool_response);
    let tool: serde_json::Value = serde_json::from_slice(&tool_response_body)
        .expect("authenticated tool response is JSON-RPC");
    assert_eq!(tool["id"], json!(2));
    assert!(
        tool.get("error").is_none(),
        "authenticated exact-modern tool call must reach the handler: {tool}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the authenticated exact-modern tool call invokes the facade handler once"
    );

    // RH-5 near-negative: retain the valid bearer and exact JSON-RPC body,
    // changing only the native MCP-Protocol-Version header to an unsupported
    // date. Strict admission must reject before the handler can run again.
    let rejection = exchange(
        server.address(),
        "2025-11-25",
        "tools/call",
        Some(PUBLIC_HTTP_TOOL_NAME),
        &tool_body,
    );
    assert!(
        rejection.starts_with(b"HTTP/1.1 400"),
        "the one-variable unsupported-era request must fail before dispatch: {}",
        String::from_utf8_lossy(&rejection)
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "changing only MCP-Protocol-Version must not invoke the authenticated handler"
    );
    server.shutdown();
}

#[test]
fn e2e_public_http_final_cursor_query_kind_and_cache_identity_are_live_and_fail_closed() {
    fn tools_page(result: CoreResult) -> fastmcp_rust::FinalListToolsResult {
        let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = result else {
            panic!("tools/list must retain its exact final result vocabulary");
        };
        result.payload
    }

    fn typed_page_identity(page: &fastmcp_rust::FinalListToolsResult) -> serde_json::Value {
        serde_json::to_value(page).expect("a typed final tools page retains an exact JSON identity")
    }

    let cx = Cx::for_request();
    let server = HttpServerFixture::spawn_modern_with_page_size(1);

    let admitted_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-final-cursor-cache-admission-client", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the public typed HTTP client admits the live final discovery response");
    let discovery = admitted_client.server_discovery();
    assert_eq!(discovery.result_type(), "complete");
    assert_eq!(discovery.supported_versions().len(), 1);
    assert_eq!(
        discovery.supported_versions().first().map(String::as_str),
        Some(modern::PROTOCOL_VERSION),
        "typed HTTP admission retains the exact live final discovery version"
    );
    assert_eq!(
        discovery
            .server_info()
            .expect("typed HTTP admission retains the discovered server identity")
            .name,
        "facade-native-http-auth"
    );
    drop(admitted_client);

    let mut client = runtime_block_on_bounded(
        &cx,
        auto::client_builder()
            .client_info("e2e-final-cursor-cache-client", "1.0.0")
            .protocol_plan(plan(server.address(), ProtocolPolicy::ModernOnly))
            .connect_http_client_with_cx(&cx),
    )
    .expect("the public HTTP client completes live modern discovery");

    let first = tools_page(
        runtime_block_on_bounded(
            &cx,
            client.request_final_core(&cx, "tools/list", json!({ "includeTags": ["cursor"] })),
        )
        .expect("the filtered first public tools page is admitted"),
    );
    assert_eq!(
        first.tools.len(),
        1,
        "page size creates a real continuation"
    );
    assert_eq!(
        first.ttl_ms,
        CacheTtl::milliseconds(5 * 60 * 1_000),
        "the typed first page retains its exact final ttlMs"
    );
    assert_eq!(
        first.cache_scope,
        CacheScope::Private,
        "the typed first page retains its exact final cacheScope"
    );
    let first_identity = typed_page_identity(&first);
    let cursor = first
        .next_cursor
        .clone()
        .expect("the first filtered page carries an opaque cursor");
    assert_eq!(client.final_result_cache_stats().fills, 1);
    assert_eq!(client.final_result_cache_stats().hits, 0);

    let replay = tools_page(
        runtime_block_on_bounded(
            &cx,
            client.request_final_core(&cx, "tools/list", json!({ "includeTags": ["cursor"] })),
        )
        .expect("the identical public list request uses its local final cache"),
    );
    assert_eq!(
        typed_page_identity(&replay),
        first_identity,
        "the cache replay retains the complete typed first-page identity"
    );
    assert_eq!(client.final_result_cache_stats().fills, 1);
    assert_eq!(
        client.final_result_cache_stats().hits,
        1,
        "an identical final request is a public cache hit"
    );

    let second = tools_page(
        runtime_block_on_bounded(
            &cx,
            client.request_final_core(
                &cx,
                "tools/list",
                json!({ "cursor": cursor.clone(), "includeTags": ["cursor"] }),
            ),
        )
        .expect("the exact cursor/query continuation reaches the second live page"),
    );
    assert_eq!(second.tools.len(), 1);
    assert_eq!(
        second.tools[0].name, PUBLIC_HTTP_CURSOR_SECONDARY_TOOL_NAME,
        "the sole valid continuation retains the exact cursor-secondary tool identity"
    );
    assert!(second.next_cursor.is_none());
    assert_eq!(
        second.ttl_ms,
        CacheTtl::milliseconds(5 * 60 * 1_000),
        "the typed continuation page retains its exact final ttlMs"
    );
    assert_eq!(
        second.cache_scope,
        CacheScope::Private,
        "the typed continuation page retains its exact final cacheScope"
    );
    assert_ne!(
        typed_page_identity(&second),
        first_identity,
        "the continuation must retain a complete typed page identity distinct from page one"
    );

    // RH-5: only the query changes. The retained cursor must not cross into a
    // different filtered catalog, and the prior cached first page stays live.
    let query_rejection = runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "tools/list",
            json!({ "cursor": cursor.clone(), "includeTags": ["other"] }),
        ),
    )
    .expect_err("changing only includeTags rejects the cursor before page projection");
    assert!(matches!(
        query_rejection,
        fastmcp_rust::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::InvalidParams
    ));

    // RH-5: only the catalog method changes. A tools cursor cannot select a
    // resources page, and this rejection must not flush the cached tools page.
    let kind_rejection = runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "resources/list",
            json!({ "cursor": cursor.clone(), "includeTags": ["cursor"] }),
        ),
    )
    .expect_err("changing only the catalog kind rejects the tools cursor");
    assert!(matches!(
        kind_rejection,
        fastmcp_rust::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::InvalidParams
    ));

    // RH-5: only wire presence changes from an absent cursor to the explicitly
    // present empty cursor. The cache must not replay the absent-cursor page.
    let empty_cursor_rejection = runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "tools/list",
            json!({ "cursor": "", "includeTags": ["cursor"] }),
        ),
    )
    .expect_err("an explicit empty cursor is not the absent-cursor cache identity");
    assert!(matches!(
        empty_cursor_rejection,
        fastmcp_rust::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::InvalidParams
    ));

    let before_unchanged_retry = client.final_result_cache_stats();
    let unchanged_retry = tools_page(
        runtime_block_on_bounded(
            &cx,
            client.request_final_core(&cx, "tools/list", json!({ "includeTags": ["cursor"] })),
        )
        .expect("cursor rejections leave the already-cached first page unchanged"),
    );
    assert_eq!(
        typed_page_identity(&unchanged_retry),
        first_identity,
        "cursor rejections leave the complete cached typed first-page identity unchanged"
    );
    assert_eq!(
        client.final_result_cache_stats().fills,
        before_unchanged_retry.fills,
        "rejected cursor variations cannot overwrite the admitted cached page"
    );
    assert_eq!(
        client.final_result_cache_stats().hits,
        before_unchanged_retry.hits + 1,
        "the unchanged original request still resolves from its prior cache entry"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_modern_facade_native_http_completion_returns_typed_result_and_rejects_undeclared_argument() {
    let cx = Cx::for_request();
    let server = spawn_modern_facade_http_server(false, None, false);
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-modern-completion-client", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the live completion provider");
    let params = modern::CompletionParams {
        reference: modern::CompletionReference::PromptWithTitle {
            name: PUBLIC_HTTP_PROMPT_NAME.to_owned(),
            title: "Public HTTP E2E Prompt".to_owned(),
        },
        argument: modern::FinalCompletionArgument {
            name: "subject".to_owned(),
            value: "cross-era".to_owned(),
        },
        context: Some(modern::FinalCompletionContext {
            arguments: Some(std::collections::BTreeMap::from([(
                "region".to_owned(),
                "us-east-1".to_owned(),
            )])),
        }),
    };

    runtime_block_on_bounded(&cx, client.complete(&cx, params.clone()))
        .expect("a completion/complete without a progress token still completes");
    assert!(
        client.take_progress_notifications().is_empty(),
        "without a progressToken the completion handler must not emit request-scoped progress"
    );

    let marker = modern::ProgressMarker::from("http-completion-progress");
    let result = runtime_block_on_bounded(
        &cx,
        client.complete_with_progress_marker(&cx, params.clone(), marker.clone()),
    )
    .expect("the typed modern HTTP completion reaches the live facade provider");
    assert_eq!(
        result.completion.values,
        vec![PUBLIC_HTTP_COMPLETION_VALUE.to_owned()],
        "the exact FinalCompletionResult retains the provider values"
    );
    assert_eq!(
        result.completion.total,
        Some(modern::JsonInteger::from(1_i64)),
        "the exact FinalCompletionResult retains its JSON-integer total"
    );
    assert_eq!(
        result.completion.has_more,
        Some(false),
        "the exact FinalCompletionResult retains the terminal pagination flag"
    );
    let progress = client.take_progress_notifications();
    assert!(
        progress.iter().any(|notification| {
            notification.progress_token == marker
                && notification.message.as_deref() == Some("completion-halfway")
        }),
        "live bind_http must retain completion notifications/progress after a progressToken: {progress:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().completion,
        2,
        "the accepted typed completion invokes the registered provider once per successful request"
    );

    // RH-5 near-negative: retain the target, title, completion context, and
    // prefix, changing only the completion argument name. Router validation
    // must reject before the registered provider can run again.
    let mut undeclared_argument = params;
    undeclared_argument.argument.name = "undeclared".to_owned();
    let error = runtime_block_on_bounded(&cx, client.complete(&cx, undeclared_argument))
        .expect_err("only an undeclared completion argument is rejected");
    assert!(matches!(
        error,
        modern::HttpClientError::CoreResult(error) if error.code == McpErrorCode::InvalidParams
    ));
    assert_eq!(
        server.handler_call_snapshot().completion,
        2,
        "changing only the argument name leaves provider state unchanged"
    );

    drop(client);
    server.shutdown();
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
        legacy_2024::HttpClientError::Connection(ClientHttpConnectionError::Modern(
            fastmcp_rust::ModernHttpClientError::LegacySse(
                fastmcp_rust::LegacySseHttpClientError::SseGetRejected { status: 400 }
            )
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

const PUBLIC_HTTP_SAMPLING_TOOL_NAME: &str = "public-http-e2e-sampling";
const PUBLIC_HTTP_ROOTS_TOOL_NAME: &str = "public-http-e2e-roots";
const PUBLIC_HTTP_URL_ELICITATION_TOOL_NAME: &str = "public-http-e2e-url-elicitation";
const PUBLIC_HTTP_ELICITATION_RESOURCE_URI: &str = "test://public-http-e2e/elicitation";
const PUBLIC_HTTP_ELICITATION_PROMPT_NAME: &str = "public-http-e2e-elicitation-prompt";

/// Live modern HTTP tool that returns framework-issued MRTR sampling input.
struct PublicHttpSamplingTool;

impl ToolHandler for PublicHttpSamplingTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_SAMPLING_TOOL_NAME.to_owned(),
            description: Some("Proves live facade HTTP final sampling input_required".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("exact legacy result")])
    }

    fn declares_final_mrtr(&self) -> bool {
        true
    }

    fn call_final_outcome(
        &self,
        ctx: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        let sampling = ctx.final_sampling(
            "sample",
            serde_json::from_value(json!({
                "messages": [{
                    "role": "assistant",
                    "content": {
                        "type": "tool_use",
                        "id": "weather-request",
                        "name": "weather",
                        "input": {"city": "Boston"},
                    },
                }],
                "maxTokens": 16,
                "tools": [{
                    "name": "weather",
                    "inputSchema": {"type": "object"},
                }],
                "toolChoice": {"mode": "required"},
            }))
            .map_err(|error| McpError::internal_error(error.to_string()))?,
        )?;
        Ok(FinalToolOutcome::InputRequired(
            sampling.into_input_required()?,
        ))
    }
}

/// Live modern HTTP tool that returns framework-issued MRTR roots input.
struct PublicHttpRootsTool;

impl ToolHandler for PublicHttpRootsTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_ROOTS_TOOL_NAME.to_owned(),
            description: Some("Proves live facade HTTP final roots input_required".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("exact legacy result")])
    }

    fn declares_final_mrtr(&self) -> bool {
        true
    }

    fn call_final_outcome(
        &self,
        ctx: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        let roots = ctx.final_roots("roots", FinalEmbeddedRootsListParams::default())?;
        Ok(FinalToolOutcome::InputRequired(
            roots.into_input_required()?,
        ))
    }
}

/// Live modern HTTP tool that returns framework-issued MRTR URL elicitation.
struct PublicHttpUrlElicitationTool;

impl ToolHandler for PublicHttpUrlElicitationTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_URL_ELICITATION_TOOL_NAME.to_owned(),
            description: Some(
                "Proves live facade HTTP final URL elicitation input_required".to_owned(),
            ),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("exact legacy result")])
    }

    fn declares_final_mrtr(&self) -> bool {
        true
    }

    fn call_final_outcome(
        &self,
        ctx: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        let elicitation = ctx.final_elicitation_url(
            "approval",
            "Approve this operation",
            "https://example.com/approve",
        )?;
        Ok(FinalToolOutcome::InputRequired(
            elicitation.into_input_required()?,
        ))
    }
}

fn public_http_form_elicitation(ctx: &McpContext) -> McpResult<fastmcp_rust::InputRequiredResult> {
    ctx.final_elicitation_form(
        "approval",
        "Approve this operation",
        json!({
            "type": "object",
            "properties": {"approved": {"type": "boolean"}},
            "required": ["approved"],
        }),
    )?
    .into_input_required()
}

/// Live modern HTTP resource that returns framework-issued MRTR elicitation.
struct PublicHttpElicitationResource;

impl ResourceHandler for PublicHttpElicitationResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: PUBLIC_HTTP_ELICITATION_RESOURCE_URI.to_owned(),
            name: "public-http-e2e-elicitation".to_owned(),
            description: Some("Proves live facade HTTP resource input_required".to_owned()),
            mime_type: None,
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Ok(vec![ResourceContent {
            uri: PUBLIC_HTTP_ELICITATION_RESOURCE_URI.to_owned(),
            mime_type: None,
            text: Some("exact legacy resource".to_owned()),
            blob: None,
        }])
    }

    fn declares_final_mrtr(&self) -> bool {
        true
    }

    fn read_final_outcome(
        &self,
        ctx: &McpContext,
    ) -> McpResult<FinalMethodOutcome<fastmcp_rust::FinalReadResourceResult>> {
        public_http_form_elicitation(ctx).map(FinalMethodOutcome::InputRequired)
    }
}

/// Live modern HTTP prompt that returns framework-issued MRTR elicitation.
struct PublicHttpElicitationPrompt;

impl PromptHandler for PublicHttpElicitationPrompt {
    fn definition(&self) -> Prompt {
        Prompt {
            name: PUBLIC_HTTP_ELICITATION_PROMPT_NAME.to_owned(),
            description: Some("Proves live facade HTTP prompt input_required".to_owned()),
            arguments: Vec::new(),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn get(
        &self,
        _ctx: &McpContext,
        _arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        Ok(vec![PromptMessage {
            role: Role::User,
            content: Content::text("exact legacy prompt"),
        }])
    }

    fn declares_final_mrtr(&self) -> bool {
        true
    }

    fn get_final_outcome(
        &self,
        ctx: &McpContext,
        _arguments: HashMap<String, String>,
    ) -> McpResult<FinalMethodOutcome<fastmcp_rust::FinalGetPromptResult>> {
        public_http_form_elicitation(ctx).map(FinalMethodOutcome::InputRequired)
    }
}

/// Starts one ModernOnly facade whose only tool is live final sampling.
fn spawn_modern_sampling_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("sampling HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-sampling", "1.0.0")
                .tool(PublicHttpSamplingTool)
                .tool(PublicHttpRootsTool)
                .tool(PublicHttpUrlElicitationTool)
                .resource(PublicHttpElicitationResource)
                .prompt(PublicHttpElicitationPrompt)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("sampling facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("sampling facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("sampling HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("sampling facade HTTP server stopped unexpectedly: {error}")
            })
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
            panic!("sampling facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("sampling facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("sampling facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

fn assert_live_input_required(result: &fastmcp_rust::InputRequiredResult, key: &str, kind: &str) {
    assert!(
        result.request_state().is_some(),
        "{kind} must return framework-issued requestState"
    );
    assert!(
        result
            .input_requests()
            .is_some_and(|requests| requests.get(key).is_some()),
        "{kind} must retain its {key} input request"
    );
}

#[test]
fn e2e_public_http_result_verbs_return_live_input_required() {
    let cx = Cx::for_request();
    let server = spawn_modern_sampling_http_server();
    let mut capabilities = ClientCapabilities::default();
    capabilities.sampling = Some(Default::default());
    capabilities.roots = serde_json::from_value(json!({})).expect("roots capability is valid");
    capabilities.elicitation = serde_json::from_value(json!({"form": {}, "url": {}}))
        .expect("form and url elicitation capabilities are valid");
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-mrtr-client", "1.0.0")
            .capabilities(capabilities)
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the live MRTR route");

    let tool = runtime_block_on_bounded(
        &cx,
        client.call_tool_result(&cx, PUBLIC_HTTP_SAMPLING_TOOL_NAME, json!({})),
    )
    .expect("live bind_http final sampling must return a typed tools/call result");
    let FinalCoreResult::ToolsCallInputRequired { result, .. } = tool else {
        panic!("live bind_http final sampling must keep input_required: {tool:?}");
    };
    assert_live_input_required(&result, "sample", "tools/call");

    let roots = runtime_block_on_bounded(
        &cx,
        client.call_tool_result(&cx, PUBLIC_HTTP_ROOTS_TOOL_NAME, json!({})),
    )
    .expect("live bind_http final roots must return a typed tools/call result");
    let FinalCoreResult::ToolsCallInputRequired { result, .. } = roots else {
        panic!("live bind_http final roots must keep input_required: {roots:?}");
    };
    assert_live_input_required(&result, "roots", "tools/call");

    let mut no_roots_capabilities = ClientCapabilities::default();
    no_roots_capabilities.sampling = Some(Default::default());
    no_roots_capabilities.elicitation =
        serde_json::from_value(json!({"form": {}})).expect("form elicitation capability is valid");
    let mut no_roots_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-mrtr-no-roots", "1.0.0")
            .capabilities(no_roots_capabilities)
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects without advertising roots");
    let missing_roots = runtime_block_on_bounded(
        &cx,
        no_roots_client.call_tool_result(&cx, PUBLIC_HTTP_ROOTS_TOOL_NAME, json!({})),
    )
    .expect("live bind_http ctx.final_roots must return a typed tools/call result");
    let FinalCoreResult::ToolsCall { result, .. } = missing_roots else {
        panic!("missing roots capability must fail closed as a tool error: {missing_roots:?}");
    };
    assert!(
        result.payload.is_error,
        "missing roots capability must fail closed: {result:?}"
    );
    assert!(
        result.payload.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text.contains("not advertised by the client"),
            _ => false,
        }),
        "missing roots capability must name the capability gate: {result:?}"
    );

    let url_elicitation = runtime_block_on_bounded(
        &cx,
        client.call_tool_result(&cx, PUBLIC_HTTP_URL_ELICITATION_TOOL_NAME, json!({})),
    )
    .expect("live bind_http final URL elicitation must return a typed tools/call result");
    let FinalCoreResult::ToolsCallInputRequired { result, .. } = url_elicitation else {
        panic!(
            "live bind_http final URL elicitation must keep input_required: {url_elicitation:?}"
        );
    };
    assert_live_input_required(&result, "approval", "tools/call");

    let mut no_url_capabilities = ClientCapabilities::default();
    no_url_capabilities.sampling = Some(Default::default());
    no_url_capabilities.roots =
        serde_json::from_value(json!({})).expect("roots capability is valid");
    no_url_capabilities.elicitation =
        serde_json::from_value(json!({"form": {}})).expect("form elicitation capability is valid");
    let mut no_url_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-mrtr-no-url", "1.0.0")
            .capabilities(no_url_capabilities)
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects without advertising URL elicitation");
    let missing_url = runtime_block_on_bounded(
        &cx,
        no_url_client.call_tool_result(&cx, PUBLIC_HTTP_URL_ELICITATION_TOOL_NAME, json!({})),
    )
    .expect("live bind_http ctx.final_elicitation_url must return a typed tools/call result");
    let FinalCoreResult::ToolsCall { result, .. } = missing_url else {
        panic!(
            "missing URL elicitation capability must fail closed as a tool error: {missing_url:?}"
        );
    };
    assert!(
        result.payload.is_error,
        "missing URL elicitation capability must fail closed: {result:?}"
    );
    assert!(
        result.payload.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text.contains("not advertised by the client"),
            _ => false,
        }),
        "missing URL elicitation capability must name the capability gate: {result:?}"
    );

    let resource = runtime_block_on_bounded(
        &cx,
        client.read_resource_result(&cx, PUBLIC_HTTP_ELICITATION_RESOURCE_URI),
    )
    .expect("live bind_http final resource elicitation must return a typed resources/read result");
    let FinalCoreResult::ResourcesReadInputRequired { result, .. } = resource else {
        panic!("live bind_http resource elicitation must keep input_required: {resource:?}");
    };
    assert_live_input_required(&result, "approval", "resources/read");

    let prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt_result(&cx, PUBLIC_HTTP_ELICITATION_PROMPT_NAME, HashMap::new()),
    )
    .expect("live bind_http final prompt elicitation must return a typed prompts/get result");
    let FinalCoreResult::PromptsGetInputRequired { result, .. } = prompt else {
        panic!("live bind_http prompt elicitation must keep input_required: {prompt:?}");
    };
    assert_live_input_required(&result, "approval", "prompts/get");
    server.shutdown();
}

#[test]
fn e2e_public_http_typed_verbs_honor_pre_send_cancellation() {
    let cx = Cx::for_request();
    let server = spawn_modern_facade_http_server(false, None, false);
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-pre-send-cancel", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before pre-send cancellation");
    runtime_block_on_bounded(&cx, client.ping(&cx))
        .expect("live bind_http modern ping completes before local cancellation");
    let cancellation = McpRequestCancellation::new();
    cancellation.cancel();
    let ping = runtime_block_on_bounded(&cx, client.ping_with_cancellation(&cx, &cancellation))
        .expect_err("pre-send HTTP ping cancellation must reject locally");
    assert!(matches!(
        ping,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));

    let list = runtime_block_on_bounded(
        &cx,
        client.list_tools_with_cancellation(&cx, &cancellation, None),
    )
    .expect_err("pre-send HTTP list_tools cancellation must reject locally");
    assert!(matches!(
        list,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));
    let resources = runtime_block_on_bounded(
        &cx,
        client.list_resources_with_cancellation(&cx, &cancellation, None),
    )
    .expect_err("pre-send HTTP list_resources cancellation must reject locally");
    assert!(matches!(
        resources,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));
    let templates = runtime_block_on_bounded(
        &cx,
        client.list_resource_templates_with_cancellation(&cx, &cancellation, None),
    )
    .expect_err("pre-send HTTP list_resource_templates cancellation must reject locally");
    assert!(matches!(
        templates,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));
    let prompts = runtime_block_on_bounded(
        &cx,
        client.list_prompts_with_cancellation(&cx, &cancellation, None),
    )
    .expect_err("pre-send HTTP list_prompts cancellation must reject locally");
    assert!(matches!(
        prompts,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));

    let call = runtime_block_on_bounded(
        &cx,
        client.call_tool_with_cancellation(
            &cx,
            &cancellation,
            PUBLIC_HTTP_TOOL_NAME,
            json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        ),
    )
    .expect_err("pre-send HTTP call_tool cancellation must reject locally");
    assert!(matches!(
        call,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));

    let resource = runtime_block_on_bounded(
        &cx,
        client.read_resource_with_cancellation(&cx, &cancellation, PUBLIC_HTTP_RESOURCE_URI),
    )
    .expect_err("pre-send HTTP read_resource cancellation must reject locally");
    assert!(matches!(
        resource,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));

    let prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt_with_cancellation(
            &cx,
            &cancellation,
            PUBLIC_HTTP_PROMPT_NAME,
            HashMap::from([("subject".to_owned(), PUBLIC_HTTP_TOOL_ARGUMENT.to_owned())]),
        ),
    )
    .expect_err("pre-send HTTP get_prompt cancellation must reject locally");
    assert!(matches!(
        prompt,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));
    let completion = runtime_block_on_bounded(
        &cx,
        client.complete_with_cancellation(
            &cx,
            &cancellation,
            modern::CompletionParams {
                reference: modern::CompletionReference::PromptWithTitle {
                    name: PUBLIC_HTTP_PROMPT_NAME.to_owned(),
                    title: "Public HTTP E2E Prompt".to_owned(),
                },
                argument: modern::FinalCompletionArgument {
                    name: "subject".to_owned(),
                    value: "cross-era".to_owned(),
                },
                context: None,
            },
        ),
    )
    .expect_err("pre-send HTTP complete cancellation must reject locally");
    assert!(matches!(
        completion,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));

    runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("the same HTTP session remains usable after local cancellation");
    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_set_log_level_stamps_request_metadata() {
    let cx = Cx::for_request();
    let server = spawn_modern_facade_http_server(false, None, false);
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-log-level", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before logLevel configuration");
    runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("JSON tools/list succeeds before request logLevel is configured");
    assert_eq!(client.log_level(), None);

    client
        .set_log_level(modern::LoggingLevel::Info)
        .expect("modern HTTP set_log_level stores request metadata locally");
    assert_eq!(client.log_level(), Some(modern::LoggingLevel::Info));
    runtime_block_on_bounded(&cx, client.list_tools(&cx, None)).expect(
        "info logLevel is request metadata; the public JSON+SSE Accept still completes tools/list",
    );

    client
        .set_log_level(modern::LoggingLevel::Emergency)
        .expect("emergency logLevel still stores request metadata locally");
    runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("changing only the logLevel rank cannot break the same public tools/list verb");
    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_set_log_level_retains_request_scoped_message_notifications() {
    let cx = Cx::for_request();
    let server = spawn_modern_facade_http_server(false, None, false);
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-log-notify", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before log notification retention");

    assert!(
        client.take_server_notifications().is_empty(),
        "no request has produced a request-scoped log yet"
    );

    client
        .set_log_level(modern::LoggingLevel::Info)
        .expect("info logLevel is stored as request metadata");
    runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("info logLevel forces the request-owned SSE body that can carry logs");
    let info_notifications = client.take_server_notifications();
    assert!(
        info_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.level == modern::LoggingLevel::Info
        )),
        "live bind_http must retain notifications/message after set_log_level(Info): {info_notifications:?}"
    );
    assert!(
        client.take_server_notifications().is_empty(),
        "take_server_notifications must drain the retained queue"
    );

    client
        .set_log_level(modern::LoggingLevel::Emergency)
        .expect("emergency logLevel still stores request metadata locally");
    runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("raising the floor cannot break the same public tools/list verb");
    let emergency_notifications = client.take_server_notifications();
    assert!(
        !emergency_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.level == modern::LoggingLevel::Info
        )),
        "raising only the logLevel floor must suppress the info notification: {emergency_notifications:?}"
    );
    drop(client);
    server.shutdown();
}

/// Live modern HTTP tool that emits `ctx.info` so request-scoped logs are observable.
struct PublicHttpLogTool;

impl ToolHandler for PublicHttpLogTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_LOG_TOOL_NAME.to_owned(),
            description: Some("Proves live facade HTTP handler log notifications".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        ctx.info(PUBLIC_HTTP_HANDLER_LOG_TEXT);
        Ok(vec![Content::text("logged")])
    }
}

const PUBLIC_HTTP_LOG_RESOURCE_URI: &str = "test://public-http-e2e/log";
const PUBLIC_HTTP_RESOURCE_LOG_TEXT: &str = "public-http-resource-info";

/// Live modern HTTP resource that emits `ctx.info` on read.
struct PublicHttpLogResource;

impl ResourceHandler for PublicHttpLogResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: PUBLIC_HTTP_LOG_RESOURCE_URI.to_owned(),
            name: "public-http-e2e-log".to_owned(),
            description: Some("Proves live facade HTTP resource log notifications".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        ctx.info(PUBLIC_HTTP_RESOURCE_LOG_TEXT);
        Ok(vec![ResourceContent {
            uri: PUBLIC_HTTP_LOG_RESOURCE_URI.to_owned(),
            mime_type: None,
            text: Some("logged".to_owned()),
            blob: None,
        }])
    }
}

const PUBLIC_HTTP_LOG_PROMPT_NAME: &str = "public-http-e2e-log-prompt";
const PUBLIC_HTTP_PROMPT_LOG_TEXT: &str = "public-http-prompt-info";

/// Live modern HTTP prompt that emits `ctx.info` on get.
struct PublicHttpLogPrompt;

impl PromptHandler for PublicHttpLogPrompt {
    fn definition(&self) -> Prompt {
        Prompt {
            name: PUBLIC_HTTP_LOG_PROMPT_NAME.to_owned(),
            description: Some("Proves live facade HTTP prompt log notifications".to_owned()),
            arguments: Vec::new(),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn get(
        &self,
        ctx: &McpContext,
        _arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        ctx.info(PUBLIC_HTTP_PROMPT_LOG_TEXT);
        Ok(vec![PromptMessage {
            role: Role::User,
            content: Content::text("logged"),
        }])
    }
}

fn spawn_modern_log_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("log HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-log", "1.0.0")
                .tool(PublicHttpLogTool)
                .resource(PublicHttpLogResource)
                .prompt(PublicHttpLogPrompt)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("log facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("log facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("log HTTP server startup receiver went away".to_owned());
            }
            bound
                .serve(&cx)
                .await
                .map_err(|error| format!("log facade HTTP server stopped unexpectedly: {error}"))
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
            panic!("log facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("log facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("log facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_ctx_info_is_retained_after_set_log_level() {
    let cx = Cx::for_request();
    let server = spawn_modern_log_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-ctx-info", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before handler log emission");

    client
        .set_log_level(modern::LoggingLevel::Info)
        .expect("info logLevel is stored as request metadata");
    runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_LOG_TOOL_NAME, json!({})),
    )
    .expect("ctx.info must not prevent the same tools/call from completing");
    let info_notifications = client.take_server_notifications();
    assert!(
        info_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.level == modern::LoggingLevel::Info
                    && message.data == json!(PUBLIC_HTTP_HANDLER_LOG_TEXT)
        )),
        "live bind_http must retain ctx.info after set_log_level(Info): {info_notifications:?}"
    );

    runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_LOG_RESOURCE_URI))
        .expect("ctx.info must not prevent the same resources/read from completing");
    let resource_notifications = client.take_server_notifications();
    assert!(
        resource_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.level == modern::LoggingLevel::Info
                    && message.data == json!(PUBLIC_HTTP_RESOURCE_LOG_TEXT)
        )),
        "live bind_http must retain resource ctx.info after set_log_level(Info): {resource_notifications:?}"
    );

    runtime_block_on_bounded(
        &cx,
        client.get_prompt(&cx, PUBLIC_HTTP_LOG_PROMPT_NAME, HashMap::new()),
    )
    .expect("ctx.info must not prevent the same prompts/get from completing");
    let prompt_notifications = client.take_server_notifications();
    assert!(
        prompt_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.level == modern::LoggingLevel::Info
                    && message.data == json!(PUBLIC_HTTP_PROMPT_LOG_TEXT)
        )),
        "live bind_http must retain prompt ctx.info after set_log_level(Info): {prompt_notifications:?}"
    );

    client
        .set_log_level(modern::LoggingLevel::Emergency)
        .expect("emergency logLevel still stores request metadata locally");
    runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_LOG_TOOL_NAME, json!({})),
    )
    .expect("raising only the logLevel floor cannot break the same public tools/call");
    let emergency_notifications = client.take_server_notifications();
    assert!(
        !emergency_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.data == json!(PUBLIC_HTTP_HANDLER_LOG_TEXT)
        )),
        "raising only the logLevel floor must suppress ctx.info: {emergency_notifications:?}"
    );
    runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_LOG_RESOURCE_URI))
        .expect("raising only the logLevel floor cannot break resources/read");
    runtime_block_on_bounded(
        &cx,
        client.get_prompt(&cx, PUBLIC_HTTP_LOG_PROMPT_NAME, HashMap::new()),
    )
    .expect("raising only the logLevel floor cannot break prompts/get");
    let emergency_follow = client.take_server_notifications();
    assert!(
        !emergency_follow.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.data == json!(PUBLIC_HTTP_RESOURCE_LOG_TEXT)
                    || message.data == json!(PUBLIC_HTTP_PROMPT_LOG_TEXT)
        )),
        "raising only the logLevel floor must suppress resource and prompt ctx.info: {emergency_follow:?}"
    );
    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_PROGRESS_TOOL_NAME: &str = "public-http-e2e-progress";

/// Live modern HTTP tool that reports progress when the request carries a token.
struct PublicHttpProgressTool;

impl ToolHandler for PublicHttpProgressTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_PROGRESS_TOOL_NAME.to_owned(),
            description: Some("Proves live facade HTTP progress notifications".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        ctx.report_progress(0.5, Some("halfway"));
        Ok(vec![Content::text("progressed")])
    }
}

const PUBLIC_HTTP_PROGRESS_RESOURCE_URI: &str = "test://public-http-e2e/progress";
const PUBLIC_HTTP_PROGRESS_PROMPT_NAME: &str = "public-http-e2e-progress-prompt";

/// Live modern HTTP resource that reports progress when the request carries a token.
struct PublicHttpProgressResource;

impl ResourceHandler for PublicHttpProgressResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: PUBLIC_HTTP_PROGRESS_RESOURCE_URI.to_owned(),
            name: "public-http-e2e-progress".to_owned(),
            description: Some("Proves live facade HTTP resource progress notifications".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        ctx.report_progress(0.5, Some("resource-halfway"));
        Ok(vec![ResourceContent {
            uri: PUBLIC_HTTP_PROGRESS_RESOURCE_URI.to_owned(),
            mime_type: None,
            text: Some("progressed".to_owned()),
            blob: None,
        }])
    }
}

/// Live modern HTTP prompt that reports progress when the request carries a token.
struct PublicHttpProgressPrompt;

impl PromptHandler for PublicHttpProgressPrompt {
    fn definition(&self) -> Prompt {
        Prompt {
            name: PUBLIC_HTTP_PROGRESS_PROMPT_NAME.to_owned(),
            description: Some("Proves live facade HTTP prompt progress notifications".to_owned()),
            arguments: Vec::new(),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn get(
        &self,
        ctx: &McpContext,
        _arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        ctx.report_progress(0.5, Some("prompt-halfway"));
        Ok(vec![PromptMessage {
            role: Role::User,
            content: Content::text("progressed"),
        }])
    }
}

fn spawn_modern_progress_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("progress HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-progress", "1.0.0")
                .tool(PublicHttpProgressTool)
                .resource(PublicHttpProgressResource)
                .prompt(PublicHttpProgressPrompt)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("progress facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("progress facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("progress HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("progress facade HTTP server stopped unexpectedly: {error}")
            })
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
            panic!("progress facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("progress facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("progress facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_progress_marker_is_retained_from_request_sse() {
    let cx = Cx::for_request();
    let server = spawn_modern_progress_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-progress", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before progress emission");

    runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_PROGRESS_TOOL_NAME, json!({})),
    )
    .expect("a tools/call without a progress token still completes");
    assert!(
        client.take_progress_notifications().is_empty(),
        "without a progressToken the handler must not emit request-scoped progress"
    );

    let marker = modern::ProgressMarker::from("http-progress");
    runtime_block_on_bounded(
        &cx,
        client.call_tool_with_progress_marker(
            &cx,
            PUBLIC_HTTP_PROGRESS_TOOL_NAME,
            json!({}),
            marker.clone(),
        ),
    )
    .expect("a progressToken must not prevent the same tools/call from completing");
    let progress = client.take_progress_notifications();
    assert!(
        progress.iter().any(|notification| {
            notification.progress_token == marker
                && notification.message.as_deref() == Some("halfway")
        }),
        "live bind_http must retain notifications/progress after a progressToken: {progress:?}"
    );
    assert!(
        client.take_progress_notifications().is_empty(),
        "take_progress_notifications must drain the retained queue"
    );

    runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_PROGRESS_RESOURCE_URI),
    )
    .expect("a resources/read without a progress token still completes");
    assert!(
        client.take_progress_notifications().is_empty(),
        "without a progressToken the resource handler must not emit request-scoped progress"
    );

    let resource_marker = modern::ProgressMarker::from("http-resource-progress");
    runtime_block_on_bounded(
        &cx,
        client.read_resource_with_progress_marker(
            &cx,
            PUBLIC_HTTP_PROGRESS_RESOURCE_URI,
            resource_marker.clone(),
        ),
    )
    .expect("a progressToken must not prevent the same resources/read from completing");
    let resource_progress = client.take_progress_notifications();
    assert!(
        resource_progress.iter().any(|notification| {
            notification.progress_token == resource_marker
                && notification.message.as_deref() == Some("resource-halfway")
        }),
        "live bind_http must retain resource notifications/progress after a progressToken: {resource_progress:?}"
    );

    runtime_block_on_bounded(
        &cx,
        client.get_prompt(&cx, PUBLIC_HTTP_PROGRESS_PROMPT_NAME, HashMap::new()),
    )
    .expect("a prompts/get without a progress token still completes");
    assert!(
        client.take_progress_notifications().is_empty(),
        "without a progressToken the prompt handler must not emit request-scoped progress"
    );

    let prompt_marker = modern::ProgressMarker::from("http-prompt-progress");
    runtime_block_on_bounded(
        &cx,
        client.get_prompt_with_progress_marker(
            &cx,
            PUBLIC_HTTP_PROGRESS_PROMPT_NAME,
            HashMap::new(),
            prompt_marker.clone(),
        ),
    )
    .expect("a progressToken must not prevent the same prompts/get from completing");
    let prompt_progress = client.take_progress_notifications();
    assert!(
        prompt_progress.iter().any(|notification| {
            notification.progress_token == prompt_marker
                && notification.message.as_deref() == Some("prompt-halfway")
        }),
        "live bind_http must retain prompt notifications/progress after a progressToken: {prompt_progress:?}"
    );
    assert!(
        client.take_progress_notifications().is_empty(),
        "take_progress_notifications must drain the retained resource and prompt queues"
    );
    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_TEMPLATE: &str = "test://public-http-e2e/item/{id}";
const PUBLIC_HTTP_TEMPLATE_NAME: &str = "public-http-e2e-item";
const PUBLIC_HTTP_TEMPLATE_MATCHED_URI: &str = "test://public-http-e2e/item/alpha";
const PUBLIC_HTTP_TEMPLATE_UNMATCHED_URI: &str = "test://public-http-e2e/other/alpha";

/// Live modern HTTP resource whose RFC 6570 template expands on `resources/read`.
struct PublicHttpTemplatedResource {
    reads: Arc<AtomicUsize>,
}

impl ResourceHandler for PublicHttpTemplatedResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: PUBLIC_HTTP_TEMPLATE.to_owned(),
            name: PUBLIC_HTTP_TEMPLATE_NAME.to_owned(),
            description: Some("Proves live facade HTTP RFC 6570 resource templates".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn template(&self) -> Option<ResourceTemplate> {
        Some(ResourceTemplate {
            uri_template: PUBLIC_HTTP_TEMPLATE.to_owned(),
            name: PUBLIC_HTTP_TEMPLATE_NAME.to_owned(),
            description: Some("Proves live facade HTTP RFC 6570 resource templates".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        })
    }

    fn final_template_definition(&self) -> Option<FinalResourceTemplate> {
        Some(FinalResourceTemplate {
            uri_template: PUBLIC_HTTP_TEMPLATE.to_owned(),
            name: PUBLIC_HTTP_TEMPLATE_NAME.to_owned(),
            title: Some("Public HTTP E2E Item".to_owned()),
            description: Some("Proves live facade HTTP RFC 6570 resource templates".to_owned()),
            icons: None,
            mime_type: Some("text/plain".to_owned()),
            annotations: None,
            meta: None,
        })
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Err(McpError::invalid_request(
            "templated resource requires a matched URI",
        ))
    }

    fn read_with_uri(
        &self,
        _ctx: &McpContext,
        uri: &str,
        params: &HashMap<String, String>,
    ) -> McpResult<Vec<ResourceContent>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let id = params
            .get("id")
            .ok_or_else(|| McpError::invalid_params("templated resource is missing id"))?;
        Ok(vec![ResourceContent {
            uri: uri.to_owned(),
            mime_type: Some("text/plain".to_owned()),
            text: Some(format!("item:{id}")),
            blob: None,
        }])
    }
}

struct PublicHttpLossyTemplatedResource;

impl ResourceHandler for PublicHttpLossyTemplatedResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: "test://public-http-e2e/item/{id:3}".to_owned(),
            name: "lossy-prefix".to_owned(),
            description: Some("Must fail closed instead of guessing a reverse match".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn template(&self) -> Option<ResourceTemplate> {
        Some(ResourceTemplate {
            uri_template: "test://public-http-e2e/item/{id:3}".to_owned(),
            name: "lossy-prefix".to_owned(),
            description: Some("Must fail closed instead of guessing a reverse match".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        })
    }

    fn final_template_definition(&self) -> Option<FinalResourceTemplate> {
        Some(FinalResourceTemplate {
            uri_template: "test://public-http-e2e/item/{id:3}".to_owned(),
            name: "lossy-prefix".to_owned(),
            title: None,
            description: Some("Must fail closed instead of guessing a reverse match".to_owned()),
            icons: None,
            mime_type: Some("text/plain".to_owned()),
            annotations: None,
            meta: None,
        })
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Err(McpError::internal_error(
            "a lossy prefix template must not become a readable handler",
        ))
    }
}

fn spawn_modern_template_http_server() -> (HttpServerFixture, Arc<AtomicUsize>) {
    let reads = Arc::new(AtomicUsize::new(0));
    let handler_reads = Arc::clone(&reads);
    (
        spawn_modern_resource_http_server(
            "facade-http-template",
            PublicHttpTemplatedResource {
                reads: handler_reads,
            },
        ),
        reads,
    )
}

fn spawn_modern_lossy_template_http_server() -> HttpServerFixture {
    spawn_modern_resource_http_server("lossy-template", PublicHttpLossyTemplatedResource)
}

fn spawn_modern_resource_http_server<H: ResourceHandler + 'static>(
    name: &'static str,
    handler: H,
) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("template HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new(name, "1.0.0")
                .resource(handler)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("template facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("template facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("template HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("template facade HTTP server stopped unexpectedly: {error}")
            })
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
            panic!("template facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("template facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("template facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_resource_template_lists_and_reads_matched_uri() {
    let cx = Cx::for_request();
    let lossy_server = spawn_modern_lossy_template_http_server();
    let mut lossy_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-lossy-template", "1.0.0")
            .connect_http_with_cx(public_http_target(lossy_server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade still connects when a lossy template is refused");
    let lossy_listed =
        runtime_block_on_bounded(&cx, lossy_client.list_resource_templates(&cx, None))
            .expect("refusing a lossy template must still serve resources/templates/list");
    assert!(
        lossy_listed.resource_templates.is_empty(),
        "a lossy prefix modifier must not be advertised as a reverse-matchable template: {:?}",
        lossy_listed.resource_templates
    );
    let lossy_read = runtime_block_on_bounded(
        &cx,
        lossy_client.read_resource(&cx, "test://public-http-e2e/item/alp"),
    )
    .expect_err("a dropped lossy template must not guess a three-character prefix match");
    assert!(
        matches!(
            lossy_read,
            modern::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::InvalidParams
        ),
        "the unregistered lossy template must stay InvalidParams: {lossy_read:?}"
    );
    drop(lossy_client);
    lossy_server.shutdown();

    let (server, reads) = spawn_modern_template_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-template", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before template expansion");

    let listed = runtime_block_on_bounded(&cx, client.list_resource_templates(&cx, None))
        .expect("live bind_http must list the registered RFC 6570 template");
    assert!(
        listed
            .resource_templates
            .iter()
            .any(|template| template.uri_template == PUBLIC_HTTP_TEMPLATE
                && template.name == PUBLIC_HTTP_TEMPLATE_NAME),
        "resources/templates/list must retain the reversible template: {:?}",
        listed.resource_templates
    );

    let matched = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_TEMPLATE_MATCHED_URI),
    )
    .expect("resources/read must expand a URI that matches the registered template");
    assert!(
        matches!(
            matched.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == "item:alpha"
        ),
        "the matched template read must retain the extracted id: {:?}",
        matched.contents
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "a matching resources/read must invoke the templated handler once"
    );

    let unmatched = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_TEMPLATE_UNMATCHED_URI),
    )
    .expect_err("changing only the path that the template cannot bind must refuse before dispatch");
    assert!(
        matches!(
            unmatched,
            modern::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::InvalidParams
        ),
        "an unmatched template URI must stay InvalidParams: {unmatched:?}"
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "the unmatched URI must leave the templated handler uninvoked"
    );

    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_WATCH_RESOURCE_URI: &str = "test://public-http-e2e/watched";
const PUBLIC_HTTP_TOUCH_TOOL_NAME: &str = "public-http-e2e-touch";

/// Live modern HTTP resource whose update events are published to listeners.
struct PublicHttpWatchResource;

impl ResourceHandler for PublicHttpWatchResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: PUBLIC_HTTP_WATCH_RESOURCE_URI.to_owned(),
            name: "public-http-e2e-watched".to_owned(),
            description: Some("Proves live facade HTTP resources/updated listen".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Ok(vec![ResourceContent {
            uri: PUBLIC_HTTP_WATCH_RESOURCE_URI.to_owned(),
            mime_type: None,
            text: Some("watched".to_owned()),
            blob: None,
        }])
    }
}

/// Live modern HTTP tool that publishes `notifications/resources/updated`.
struct PublicHttpTouchTool;

impl ToolHandler for PublicHttpTouchTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_TOUCH_TOOL_NAME.to_owned(),
            description: Some("Proves live facade HTTP resource-update publication".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let delivered = ctx.notify_resource_updated(PUBLIC_HTTP_WATCH_RESOURCE_URI);
        Ok(vec![Content::text(if delivered {
            "notified"
        } else {
            "silent"
        })])
    }
}

const PUBLIC_HTTP_HIDE_TOOL_NAME: &str = "public-http-e2e-hide";

/// Live modern HTTP tool that disables a peer tool and publishes `tools/list_changed`.
struct PublicHttpHideTool;

impl ToolHandler for PublicHttpHideTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_HIDE_TOOL_NAME.to_owned(),
            description: Some("Proves live facade HTTP tools/list_changed publication".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let delivered = ctx.disable_tool(PUBLIC_HTTP_TOUCH_TOOL_NAME);
        Ok(vec![Content::text(if delivered {
            "hidden"
        } else {
            "silent"
        })])
    }
}

const PUBLIC_HTTP_TOGGLE_TOOL_NAME: &str = "public-http-e2e-toggle";
const PUBLIC_HTTP_CATALOG_PROMPT_NAME: &str = "public-http-e2e-catalog-prompt";
const PUBLIC_HTTP_HIDE_CATALOG_TOOL_NAME: &str = "public-http-e2e-hide-catalog";

/// Live modern HTTP tool that disables then re-enables a peer in one request.
struct PublicHttpToggleTool;

impl ToolHandler for PublicHttpToggleTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_TOGGLE_TOOL_NAME.to_owned(),
            description: Some(
                "Proves live facade HTTP enable_tool list_changed publication".to_owned(),
            ),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let hidden = ctx.disable_tool(PUBLIC_HTTP_TOUCH_TOOL_NAME);
        let shown = ctx.enable_tool(PUBLIC_HTTP_TOUCH_TOOL_NAME);
        Ok(vec![Content::text(if hidden && shown {
            "toggled"
        } else {
            "stuck"
        })])
    }
}

/// Live modern HTTP prompt used as a catalog-mutation subject.
struct PublicHttpCatalogPrompt;

impl PromptHandler for PublicHttpCatalogPrompt {
    fn definition(&self) -> Prompt {
        Prompt {
            name: PUBLIC_HTTP_CATALOG_PROMPT_NAME.to_owned(),
            description: Some(
                "Proves live facade HTTP prompts/list_changed publication".to_owned(),
            ),
            arguments: Vec::new(),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn get(
        &self,
        _ctx: &McpContext,
        _arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        Ok(vec![PromptMessage {
            role: Role::User,
            content: Content::text("catalog"),
        }])
    }
}

/// Live modern HTTP tool that disables a resource and a prompt.
struct PublicHttpHideCatalogTool;

impl ToolHandler for PublicHttpHideCatalogTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_HIDE_CATALOG_TOOL_NAME.to_owned(),
            description: Some(
                "Proves live facade HTTP resource and prompt list_changed publication".to_owned(),
            ),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let resource = ctx.disable_resource(PUBLIC_HTTP_WATCH_RESOURCE_URI);
        let prompt = ctx.disable_prompt(PUBLIC_HTTP_CATALOG_PROMPT_NAME);
        Ok(vec![Content::text(if resource && prompt {
            "hidden"
        } else {
            "silent"
        })])
    }
}

fn spawn_modern_subscription_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("subscription HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-subscription", "1.0.0")
                .resource(PublicHttpWatchResource)
                .prompt(PublicHttpCatalogPrompt)
                .tool(PublicHttpTouchTool)
                .tool(PublicHttpHideTool)
                .tool(PublicHttpToggleTool)
                .tool(PublicHttpHideCatalogTool)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("subscription facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("subscription facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("subscription HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("subscription facade HTTP server stopped unexpectedly: {error}")
            })
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
            panic!("subscription facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("subscription facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("subscription facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_resource_updated_is_retained_on_incremental_listen() {
    let cx = Cx::for_request();
    let server = spawn_modern_subscription_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-listen", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before subscriptions/listen");

    let limits = modern::SseLimits::new(64 * 1024, 2 * 1024 * 1024, 256)
        .expect("subscription SSE limits must be nonzero");
    let filter = modern::SubscriptionFilter {
        resource_subscriptions: Some(vec![PUBLIC_HTTP_WATCH_RESOURCE_URI.to_owned()]),
        ..modern::SubscriptionFilter::default()
    };
    runtime_block_on_bounded(
        &cx,
        client.start_subscriptions_listener(&cx, filter, limits),
    )
    .expect("live bind_http must admit an incremental subscriptions/listen");

    let acknowledgement = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must emit its acknowledgement");
    assert!(
        matches!(
            acknowledgement,
            Some(modern::ModernHttpSubscriptionListenEvent::Acknowledged { .. })
        ),
        "the first incremental listen record must be the accepted filter: {acknowledgement:?}"
    );

    let touched = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOUCH_TOOL_NAME, json!({})),
    )
    .expect("touching the watched resource must complete");
    assert!(
        touched.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "notified",
            _ => false,
        }),
        "a matching incremental listener must count as notify_resource_updated delivery: {touched:?}"
    );

    let updated = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must retain resources/updated after the handler publish");
    assert!(
        matches!(
            updated,
            Some(modern::ModernHttpSubscriptionListenEvent::Notification(
                modern::ServerNotification::ResourceUpdated(ref params)
            )) if params.uri.as_str() == PUBLIC_HTTP_WATCH_RESOURCE_URI
        ),
        "live bind_http must retain notifications/resources/updated on the incremental listener: {updated:?}"
    );
    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_tools_list_changed_is_retained_on_incremental_listen() {
    let cx = Cx::for_request();
    let server = spawn_modern_subscription_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-list-changed", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before subscriptions/listen");

    let limits = modern::SseLimits::new(64 * 1024, 2 * 1024 * 1024, 256)
        .expect("subscription SSE limits must be nonzero");
    let filter = modern::SubscriptionFilter {
        tools_list_changed: Some(true),
        ..modern::SubscriptionFilter::default()
    };
    runtime_block_on_bounded(
        &cx,
        client.start_subscriptions_listener(&cx, filter, limits),
    )
    .expect("live bind_http must admit an incremental subscriptions/listen");

    let acknowledgement = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must emit its acknowledgement");
    assert!(
        matches!(
            acknowledgement,
            Some(modern::ModernHttpSubscriptionListenEvent::Acknowledged { .. })
        ),
        "the first incremental listen record must be the accepted filter: {acknowledgement:?}"
    );

    let hidden = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_HIDE_TOOL_NAME, json!({})),
    )
    .expect("disabling a peer tool must complete");
    assert!(
        hidden.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "request-local SessionState must let disable_tool publish list_changed: {hidden:?}"
    );

    let changed = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must retain tools/list_changed after the handler mutation");
    assert!(
        matches!(
            changed,
            Some(modern::ModernHttpSubscriptionListenEvent::Notification(
                modern::ServerNotification::ToolsListChanged(_)
            ))
        ),
        "live bind_http must retain notifications/tools/list_changed on the incremental listener: {changed:?}"
    );

    let toggled = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOGGLE_TOOL_NAME, json!({})),
    )
    .expect("disable then enable in one request must complete");
    assert!(
        toggled.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "toggled",
            _ => false,
        }),
        "request-local SessionState must let enable_tool reverse the same-request disable: {toggled:?}"
    );
    let first_toggle = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("disable inside the toggle must publish tools/list_changed");
    let second_toggle = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("enable_tool must publish a second tools/list_changed");
    assert!(
        matches!(
            first_toggle,
            Some(modern::ModernHttpSubscriptionListenEvent::Notification(
                modern::ServerNotification::ToolsListChanged(_)
            ))
        ),
        "the toggle disable must publish tools/list_changed: {first_toggle:?}"
    );
    assert!(
        matches!(
            second_toggle,
            Some(modern::ModernHttpSubscriptionListenEvent::Notification(
                modern::ServerNotification::ToolsListChanged(_)
            ))
        ),
        "live bind_http must retain enable_tool notifications/tools/list_changed: {second_toggle:?}"
    );

    runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("a later POST on the same HTTP client must still list tools");
    drop(client);

    let mut other_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-list-changed-other", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("a second ModernOnly facade client connects after the first disable");
    let other_tools = runtime_block_on_bounded(&cx, other_client.list_tools(&cx, None))
        .expect("a later POST from another HTTP client must still list tools");
    assert!(
        other_tools
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOUCH_TOOL_NAME),
        "disable_tool must not invent a process-wide HTTP session: {other_tools:?}"
    );
    drop(other_client);
    server.shutdown();
}

#[test]
fn e2e_public_http_resource_and_prompt_list_changed_are_retained_on_incremental_listen() {
    let cx = Cx::for_request();
    let server = spawn_modern_subscription_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-catalog-changed", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before subscriptions/listen");

    let limits = modern::SseLimits::new(64 * 1024, 2 * 1024 * 1024, 256)
        .expect("subscription SSE limits must be nonzero");
    let filter = modern::SubscriptionFilter {
        resources_list_changed: Some(true),
        prompts_list_changed: Some(true),
        ..modern::SubscriptionFilter::default()
    };
    runtime_block_on_bounded(
        &cx,
        client.start_subscriptions_listener(&cx, filter, limits),
    )
    .expect("live bind_http must admit an incremental subscriptions/listen");

    let acknowledgement = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must emit its acknowledgement");
    assert!(
        matches!(
            acknowledgement,
            Some(modern::ModernHttpSubscriptionListenEvent::Acknowledged { .. })
        ),
        "the first incremental listen record must be the accepted filter: {acknowledgement:?}"
    );

    let hidden = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_HIDE_CATALOG_TOOL_NAME, json!({})),
    )
    .expect("disabling a resource and a prompt must complete");
    assert!(
        hidden.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "request-local SessionState must let disable_resource and disable_prompt publish: {hidden:?}"
    );

    let first = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must retain the first catalog mutation");
    let second = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must retain the second catalog mutation");
    let kinds = [first, second];
    assert!(
        kinds.iter().any(|event| matches!(
            event,
            Some(modern::ModernHttpSubscriptionListenEvent::Notification(
                modern::ServerNotification::ResourcesListChanged(_)
            ))
        )),
        "live bind_http must retain notifications/resources/list_changed: {kinds:?}"
    );
    assert!(
        kinds.iter().any(|event| matches!(
            event,
            Some(modern::ModernHttpSubscriptionListenEvent::Notification(
                modern::ServerNotification::PromptsListChanged(_)
            ))
        )),
        "live bind_http must retain notifications/prompts/list_changed: {kinds:?}"
    );
    drop(client);
    server.shutdown();
}

#[cfg(any())]
mod unproven_live_websocket_bind {
    #![allow(dead_code, unused_imports)]
    use super::*;

    const PUBLIC_WS_LOG_TOOL_NAME: &str = "public-ws-e2e-log";
    const PUBLIC_WS_HANDLER_LOG_TEXT: &str = "public-ws-handler-info";
    const WS_SERVER_TEARDOWN_BOUND: Duration = Duration::from_secs(6);

    /// Live modern WebSocket tool that emits `ctx.info` and optional progress.
    struct PublicWebSocketLogTool;

    impl ToolHandler for PublicWebSocketLogTool {
        fn definition(&self) -> Tool {
            Tool {
                name: PUBLIC_WS_LOG_TOOL_NAME.to_owned(),
                description: Some(
                    "Proves live facade WebSocket handler log and progress".to_owned(),
                ),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
            ctx.info(PUBLIC_WS_HANDLER_LOG_TEXT);
            ctx.report_progress(0.5, Some("halfway"));
            Ok(vec![Content::text("logged")])
        }
    }

    /// Owns one real public `bind_websocket` listener and proves its teardown.
    #[allow(dead_code)]
    struct WebSocketServerFixture {
        address: SocketAddr,
        server_cx: Cx,
        finished: mpsc::Receiver<Result<WebSocketServerShutdown, String>>,
        shutdown_completion: Option<Result<WebSocketServerShutdown, String>>,
        join: Option<JoinHandle<()>>,
        nonquiescent: Option<WebSocketNonquiescentShutdown>,
    }

    #[allow(dead_code)]
    impl Drop for WebSocketServerFixture {
        fn drop(&mut self) {
            if self.join.is_none() && self.nonquiescent.is_none() {
                return;
            }
            if let Err(error) = self.settle() {
                eprintln!("public WebSocket server fixture drop failed: {error}");
                std::process::abort();
            }
        }
    }

    #[allow(dead_code)]
    impl WebSocketServerFixture {
        fn address(&self) -> SocketAddr {
            self.address
        }

        fn settle(&mut self) -> Result<(), String> {
            if let Some(shutdown) = self.nonquiescent.as_mut() {
                return match runtime_block_on(shutdown.settle_for(WS_SERVER_TEARDOWN_BOUND)) {
                    Ok(true) => {
                        self.nonquiescent = None;
                        Err(
                        "facade WebSocket server stopped nonquiescently but settled during fixture cleanup"
                            .to_owned(),
                    )
                    }
                    Ok(false) => Err(format!(
                        "facade WebSocket server remains nonquiescent after bounded fixture cleanup ({} retained connections)",
                        shutdown.remaining_connections()
                    )),
                    Err(error) => Err(format!(
                        "facade WebSocket server child settlement failed: {error}"
                    )),
                };
            }
            self.server_cx.set_cancel_requested(true);
            match await_websocket_server_shutdown(
                &self.finished,
                &mut self.shutdown_completion,
                &mut self.join,
            )? {
                WebSocketServerShutdown::Quiescent => Ok(()),
                WebSocketServerShutdown::Nonquiescent(shutdown) => {
                    self.nonquiescent = Some(shutdown);
                    self.settle()
                }
            }
        }

        fn shutdown(mut self) {
            self.settle()
                .unwrap_or_else(|error| panic!("public WebSocket server teardown failed: {error}"));
        }
    }

    #[allow(dead_code)]
    fn await_websocket_server_shutdown(
        finished: &mpsc::Receiver<Result<WebSocketServerShutdown, String>>,
        completion: &mut Option<Result<WebSocketServerShutdown, String>>,
        join: &mut Option<JoinHandle<()>>,
    ) -> Result<WebSocketServerShutdown, String> {
        let completion_result = if completion.is_some() {
            Ok(())
        } else {
            finished
                .recv_timeout(WS_SERVER_TEARDOWN_BOUND)
                .map(|shutdown| *completion = Some(shutdown))
                .map_err(|error| {
                    format!("public WebSocket server teardown exceeded its bound: {error}")
                })
        };
        let join_result = join_finished_thread(join, WS_SERVER_TEARDOWN_BOUND, "WebSocket server");
        match (completion_result, join_result) {
            (Ok(()), Ok(())) => match completion
                .take()
                .expect("a completed WebSocket shutdown retains its completion report")
            {
                Ok(shutdown) => Ok(shutdown),
                Err(completion) => Err(format!(
                    "public WebSocket server teardown failed: {completion}"
                )),
            },
            (Ok(()), Err(join)) => Err(join),
            (Err(completion), Ok(())) => Err(completion),
            (Err(completion), Err(join)) => Err(format!(
                "{completion}; owned thread settlement failed: {join}"
            )),
        }
    }

    #[allow(dead_code)]
    fn spawn_modern_log_websocket_server() -> WebSocketServerFixture {
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
        let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
        let (finished_tx, finished_rx) =
            mpsc::sync_channel::<Result<WebSocketServerShutdown, String>>(1);
        let join = Some(thread::spawn(move || {
            let ready_for_spawn_failure = ready_tx.clone();
            let finished_for_spawn_failure = finished_tx.clone();
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .build()
                .expect("log facade WebSocket server installs an owned runtime");
            let outcome = runtime.block_on(async move {
                let cx = Cx::current()
                    .expect("owned WebSocket runtime installs an ambient server context");
                if server_cx_tx.send(cx.clone()).is_err() {
                    cx.set_cancel_requested(true);
                    return Err("log WebSocket server control receiver went away".to_owned());
                }
                let server = modern::ServerBuilder::new("facade-ws-log", "1.0.0")
                    .tool(PublicWebSocketLogTool)
                    .build();
                let bound = match server.bind_websocket(&cx, "127.0.0.1:0").await {
                    Ok(bound) => bound,
                    Err(error) => {
                        let message = format!("log facade WebSocket server bind failed: {error}");
                        let _ = ready_tx.send(Err(message.clone()));
                        return Err(message);
                    }
                };
                let address = match bound.local_addr() {
                    Ok(address) => address,
                    Err(error) => {
                        let message =
                            format!("log facade WebSocket server address failed: {error}");
                        let _ = ready_tx.send(Err(message.clone()));
                        return Err(message);
                    }
                };
                if ready_tx.send(Ok(address)).is_err() {
                    cx.set_cancel_requested(true);
                    return Err("log WebSocket server startup receiver went away".to_owned());
                }
                bound.serve(&cx).await.map_err(|error| {
                    format!("log facade WebSocket server stopped unexpectedly: {error}")
                })
            });
            if let Err(message) = &outcome {
                let _ = ready_for_spawn_failure.send(Err(message.clone()));
            }
            let _ = finished_for_spawn_failure.send(outcome);
        }));

        let mut server_cx = None;
        let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
        let address = loop {
            if server_cx.is_none() {
                if let Ok(cx) = server_cx_rx.try_recv() {
                    server_cx = Some(cx);
                }
            }
            let remaining = startup_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                if let Some(cx) = server_cx.as_ref() {
                    cx.set_cancel_requested(true);
                }
                panic!("log facade WebSocket server startup exceeded its bound");
            }
            match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
                Ok(Ok(address)) => break address,
                Ok(Err(error)) => panic!("log facade WebSocket server failed to start: {error}"),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("log facade WebSocket server readiness channel disconnected")
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        };
        if server_cx.is_none() {
            if let Ok(cx) = server_cx_rx.try_recv() {
                server_cx = Some(cx);
            }
        }

        WebSocketServerFixture {
            address,
            server_cx: server_cx.expect("startup retains the runtime-installed server context"),
            finished: finished_rx,
            shutdown_completion: None,
            join,
            nonquiescent: None,
        }
    }

    #[test]
    fn e2e_public_websocket_bind_retains_ping_log_and_progress() {
        runtime_block_on(async {
            let cx = Cx::current().expect("facade runtime installs a client context");
            asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
            let server = modern::ServerBuilder::new("facade-ws-log", "1.0.0")
                .tool(PublicWebSocketLogTool)
                .build();
            let bound = server
                .bind_websocket(&cx, "127.0.0.1:0")
                .await
                .expect("public bind_websocket must bind a localhost listener");
            let address = bound
                .local_addr()
                .expect("public bind_websocket publishes its bound address");
            let serve_cx = cx.clone();
            let mut server_task = cx
                .spawn(move |task_cx| async move { bound.serve(&task_cx).await })
                .expect("public bind_websocket serve must be spawnable on the caller runtime");

            let transport = AsyncWsClientTransport::connect(&cx, &format!("ws://{address}/mcp"))
                .await
                .expect("public bind_websocket must complete RFC 6455 upgrade");
            let mut client = modern::ClientBuilder::new()
                .client_info("e2e-public-ws-bind", "1.0.0")
                .connect_websocket_with_cx(&cx, transport)
                .await
                .expect("the ModernOnly public facade negotiates over bind_websocket");

            client
                .ping(&cx)
                .await
                .expect("live bind_websocket must answer modern ping");

            client
                .set_log_level(modern::LoggingLevel::Info)
                .expect("info logLevel is stored as request metadata");
            client
                .call_tool(&cx, PUBLIC_WS_LOG_TOOL_NAME, json!({}))
                .await
                .expect("ctx.info must not prevent the same tools/call from completing");
            let info_notifications = client.take_server_notifications();
            assert!(
                info_notifications.iter().any(|notification| matches!(
                    notification,
                    modern::ServerNotification::Message(message)
                        if message.level == modern::LoggingLevel::Info
                            && message.data == json!(PUBLIC_WS_HANDLER_LOG_TEXT)
                )),
                "live bind_websocket must retain ctx.info after set_log_level(Info): {info_notifications:?}"
            );
            assert!(
                client.take_progress_notifications().is_empty(),
                "without a progressToken the handler must not emit request-scoped progress"
            );

            let marker = modern::ProgressMarker::from("ws-progress");
            client
                .call_tool_with_progress_marker(
                    &cx,
                    PUBLIC_WS_LOG_TOOL_NAME,
                    json!({}),
                    marker.clone(),
                )
                .await
                .expect("a progressToken must not prevent the same tools/call from completing");
            let progress = client.take_progress_notifications();
            assert!(
                progress.iter().any(|notification| {
                    notification.progress_token == marker
                        && notification.message.as_deref() == Some("halfway")
                }),
                "live bind_websocket must retain notifications/progress after a progressToken: {progress:?}"
            );
            assert!(
                client.take_progress_notifications().is_empty(),
                "take_progress_notifications must drain the retained queue"
            );

            client
                .set_log_level(modern::LoggingLevel::Emergency)
                .expect("emergency logLevel still stores request metadata locally");
            client
                .call_tool(&cx, PUBLIC_WS_LOG_TOOL_NAME, json!({}))
                .await
                .expect("raising only the logLevel floor cannot break the same public tools/call");
            let emergency_notifications = client.take_server_notifications();
            assert!(
                !emergency_notifications.iter().any(|notification| matches!(
                    notification,
                    modern::ServerNotification::Message(message)
                        if message.data == json!(PUBLIC_WS_HANDLER_LOG_TEXT)
                )),
                "raising only the logLevel floor must suppress ctx.info: {emergency_notifications:?}"
            );

            client
                .close(&cx)
                .await
                .expect("the public WebSocket client closes after the live bind proof");
            serve_cx.set_cancel_requested(true);
            match server_task.join(&cx).await {
                Ok(Ok(_)) | Err(_) => {}
                Ok(Err(error)) => panic!("public bind_websocket serve failed: {error}"),
            }
        })
        .await
        .expect("live bind_websocket proof stays within its caller-owned deadline");
        });
    }
}
