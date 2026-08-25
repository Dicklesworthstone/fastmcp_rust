//! E2E Full MCP Workflow Tests (bd-275)
//!
//! Comprehensive tests for complete MCP workflows with trace logging.
//! Covers:
//! - Server startup -> connect -> initialize -> operate -> shutdown
//! - Multiple sequential clients
//! - Interleaved tool/resource/prompt operations
//! - Error recovery during workflows
//! - Server with various handler configurations
//! - Resource template listing
//! - Client info propagation

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::Poll;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fastmcp_protocol::{LegacyContent, LegacyPromptMessage, LegacyResourceContent, Tool};
use fastmcp_rust::modern::{MAX_MRTR_CONTINUATION_ROUNDS, MAX_MRTR_INPUT_RESPONSES};
use fastmcp_rust::server::FinalMethodOutcome;
use fastmcp_rust::testing::prelude::*;
use fastmcp_rust::{
    ApplicationTaskSupervisor, AuthorizedTaskServiceRunner, BoxFuture, CacheScope, CacheTtl,
    CanonicalHttpUrl, ClientHttpConnectionError, ClientProtocolPlan, CompleteResult, ContentBlock,
    CoreResult, CoreResultDiscriminatorPolicy, Cx, DecodedResult, FinalCallToolResult,
    FinalCoreResult, FinalGetPromptResult, FinalPromptMessage, FinalReadResourceResult,
    FinalResourceReadCacheHintProvenance, FinalTask, FinalTaskInputRequests,
    FinalTaskInputResponses, FinalTaskRuntime, FinalTaskRuntimeConfig, FinalTaskSupervisorFuture,
    FinalTaskSupervisorHandoff, FinalTaskWatchEvent, FinalTaskWorkDescriptor, FinalToolCallOutcome,
    FinalToolOutcome, HttpServerShutdown, Implementation, InMemoryFinalTaskStore,
    InputRequiredResult, McpContext, McpError, McpErrorCode, McpOutcome, McpResult,
    MrtrCompletedInputs, MrtrInputRequest, MrtrInputRequests, Outcome, Prompt, PromptHandler,
    PromptMessage, ProtocolPolicy, RequestId, Resource, ResourceContent, ResourceHandler,
    ResourceTemplate, ResultMeta, ResultPeerEra, Role, SseLimits, ToolHandler, Transport, auto,
    decode_peer_result, legacy_2024, modern, prompt, resource, tool,
};
use fastmcp_server::Server;
use serde_json::json;

#[cfg(feature = "proxy")]
struct FacadeProxyBoundaryBackend;

#[cfg(feature = "proxy")]
impl fastmcp_rust::ProxyBackend for FacadeProxyBoundaryBackend {
    fn list_tools(&mut self) -> McpResult<Vec<fastmcp_rust::Tool>> {
        Ok(Vec::new())
    }

    fn list_resources(&mut self) -> McpResult<Vec<fastmcp_rust::Resource>> {
        Ok(Vec::new())
    }

    fn list_resource_templates(&mut self) -> McpResult<Vec<fastmcp_rust::ResourceTemplate>> {
        Ok(Vec::new())
    }

    fn list_prompts(&mut self) -> McpResult<Vec<fastmcp_rust::Prompt>> {
        Ok(Vec::new())
    }

    fn call_tool(
        &mut self,
        _name: &str,
        _arguments: serde_json::Value,
    ) -> McpResult<Vec<fastmcp_rust::Content>> {
        Ok(Vec::new())
    }

    fn call_tool_with_progress(
        &mut self,
        _name: &str,
        _arguments: serde_json::Value,
        _on_progress: fastmcp_rust::ProxyProgressCallback<'_>,
    ) -> McpResult<Vec<fastmcp_rust::Content>> {
        Ok(Vec::new())
    }

    fn read_resource(&mut self, _uri: &str) -> McpResult<Vec<ResourceContent>> {
        Ok(Vec::new())
    }

    fn get_prompt(
        &mut self,
        _name: &str,
        _arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        Ok(Vec::new())
    }
}

// ============================================================================
// Shared handler implementations (macro-based)
// ============================================================================

/// Echoes back the input.
#[tool(name = "echo", version = "1.0.0", annotations(read_only, idempotent))]
fn echo_tool(_ctx: &McpContext, message: String) -> String {
    message
}

/// Returns the call count (not truly stateful, returns arg).
#[tool(name = "counter")]
fn counter_tool(_ctx: &McpContext, value: i64) -> String {
    value.to_string()
}

/// Fails if 'fail' argument is true.
#[tool(name = "fail_on_demand")]
fn fail_on_demand_tool(
    _ctx: &McpContext,
    fail: bool,
    message: Option<String>,
) -> McpResult<String> {
    if fail {
        let msg = message.as_deref().unwrap_or("Requested failure");
        return Err(McpError::tool_error(msg));
    }
    Ok("Success".to_string())
}

/// Current server status.
#[resource(
    uri = "app://status",
    name = "Server Status",
    mime_type = "application/json",
    tags = ["status"]
)]
fn status(_ctx: &McpContext) -> String {
    json!({
        "status": "healthy",
        "uptime_seconds": 42
    })
    .to_string()
}

/// Project README file.
#[resource(
    uri = "file:///README.md",
    name = "README",
    mime_type = "text/markdown",
    version = "1.0.0",
    tags = ["docs"]
)]
fn readme() -> String {
    "# Test Project\n\nThis is a test project.".to_string()
}

/// Get help on a topic.
#[prompt(name = "help")]
fn help_prompt(_ctx: &McpContext, topic: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("Help me understand: {topic}"),
        },
    }]
}

/// Default system prompt.
#[prompt(name = "system_prompt")]
fn system_prompt_handler() -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::Assistant,
        content: Content::Text {
            text: "You are a helpful assistant.".to_string(),
        },
    }]
}

// ============================================================================
// Helper: build full workflow server
// ============================================================================

const MEMORY_SERVER_TEARDOWN_BOUND: Duration = Duration::from_secs(2);

/// Owns memory-transport server threads until their paired clients close.
///
/// Declare this before the client owners so normal and unwinding drops close
/// the client transports before this bounded settlement runs. A server that
/// does not stop within the bound aborts the test process rather than silently
/// detaching a live server thread.
struct ThreadJoins(Vec<JoinHandle<()>>);

impl ThreadJoins {
    fn new(handles: Vec<JoinHandle<()>>) -> Self {
        Self(handles)
    }

    fn push(&mut self, handle: JoinHandle<()>) {
        self.0.push(handle);
    }
}

impl Drop for ThreadJoins {
    fn drop(&mut self) {
        let deadline = Instant::now() + MEMORY_SERVER_TEARDOWN_BOUND;
        while self.0.iter().any(|handle| !handle.is_finished()) {
            if Instant::now() >= deadline {
                eprintln!(
                    "memory-transport server teardown exceeded its bounded settlement window"
                );
                std::process::abort();
            }
            thread::sleep(Duration::from_millis(1));
        }
        for handle in self.0.drain(..) {
            if handle.join().is_err() {
                eprintln!("memory-transport server thread panicked during settlement");
                std::process::abort();
            }
        }
    }
}

fn spawn_thread<T>(f: impl FnOnce() -> T + Send + 'static) -> JoinHandle<T>
where
    T: Send + 'static,
{
    std::thread::spawn(f)
}

fn join_thread_with_bound<T>(handle: JoinHandle<T>, owner: &str) -> std::thread::Result<T> {
    let deadline = Instant::now() + MEMORY_SERVER_TEARDOWN_BOUND;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            eprintln!("{owner} exceeded its bounded settlement window");
            std::process::abort();
        }
        thread::sleep(Duration::from_millis(1));
    }
    handle.join()
}

/// Retains every concurrent test worker until all of them have crossed a
/// bounded join. If one worker panics, the remaining owners still settle
/// before that first panic is resumed.
struct WorkerJoins<T>(Vec<JoinHandle<T>>);

impl<T> WorkerJoins<T> {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, handle: JoinHandle<T>) {
        self.0.push(handle);
    }

    fn join_all(mut self, owner: &str) -> Vec<T> {
        let mut values = Vec::with_capacity(self.0.len());
        let mut first_panic = None;
        for handle in self.0.drain(..) {
            match join_thread_with_bound(handle, owner) {
                Ok(value) => values.push(value),
                Err(payload) if first_panic.is_none() => first_panic = Some(payload),
                Err(_) => {}
            }
        }
        if let Some(payload) = first_panic {
            std::panic::resume_unwind(payload);
        }
        values
    }
}

impl<T> Drop for WorkerJoins<T> {
    fn drop(&mut self) {
        let mut first_panic = None;
        for handle in self.0.drain(..) {
            match join_thread_with_bound(handle, "concurrent E2E worker") {
                Ok(_) => {}
                Err(payload) if first_panic.is_none() => first_panic = Some(payload),
                Err(_) => {}
            }
        }
        if !std::thread::panicking() {
            if let Some(payload) = first_panic {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

struct TestHarness {
    client: Option<TestClient>,
    _joins: ThreadJoins,
}

impl TestHarness {
    fn new(client: TestClient, server_thread: JoinHandle<()>) -> Self {
        Self {
            client: Some(client),
            _joins: ThreadJoins::new(vec![server_thread]),
        }
    }
}

impl Deref for TestHarness {
    type Target = TestClient;

    fn deref(&self) -> &Self::Target {
        self.client.as_ref().expect("client missing")
    }
}

impl DerefMut for TestHarness {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.client.as_mut().expect("client missing")
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        // Drop client first so transports close before joining threads.
        self.client.take();
    }
}

fn setup_workflow_server() -> TestHarness {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("workflow-test-server")
        .with_version("2.0.0")
        .build_server_builder();

    let server = builder
        .tool(EchoTool)
        .tool(CounterTool)
        .tool(FailOnDemandTool)
        .resource(StatusResource)
        .resource(ReadmeResource)
        .resource_template(ResourceTemplate {
            uri_template: "file:///{path}".to_string(),
            name: "File Path".to_string(),
            description: Some("Access files by path".to_string()),
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        })
        .prompt(HelpPromptPrompt)
        .prompt(SystemPromptHandlerPrompt)
        .build();

    let handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server
            .run_transport_returning_with_cx(&cx, server_transport)
            .expect("workflow server loop");
    });

    TestHarness::new(TestClient::new(client_transport), handle)
}

const CALLER_OWNED_LIFECYCLE_TOOL: &str = "caller_owned_lifecycle_tool";

/// A real handler whose call count makes era admission observable before any
/// handler state can be mutated.
struct CallerOwnedLifecycleTool {
    calls: Arc<AtomicUsize>,
}

impl ToolHandler for CallerOwnedLifecycleTool {
    fn definition(&self) -> Tool {
        Tool {
            name: CALLER_OWNED_LIFECYCLE_TOOL.to_owned(),
            description: Some("counts caller-owned lifecycle test calls".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![Content::text("caller-owned lifecycle call")])
    }
}

fn lifecycle_modern_opening(id: i64) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest::new(
        "server/discover",
        Some(json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": modern::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })),
        id,
    ))
}

fn lifecycle_legacy_opening(id: i64) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest::new(
        "initialize",
        Some(json!({
            "protocolVersion": legacy_2024::PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "caller-owned-lifecycle-peer", "version": "1.0.0"},
        })),
        id,
    ))
}

fn lifecycle_tool_request(id: i64, modern_era: bool) -> JsonRpcMessage {
    let mut params = json!({
        "name": CALLER_OWNED_LIFECYCLE_TOOL,
        "arguments": {},
    });
    if modern_era {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": modern::PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
        });
    }
    JsonRpcMessage::Request(JsonRpcRequest::new("tools/call", Some(params), id))
}

fn lifecycle_response(
    peer: &mut fastmcp_rust::memory::MemoryTransport,
    cx: &Cx,
    id: i64,
    description: &str,
) -> JsonRpcResponse {
    let JsonRpcMessage::Response(response) = peer
        .recv(cx)
        .unwrap_or_else(|error| panic!("{description}: peer did not receive a response: {error}"))
    else {
        panic!("{description}: peer received a request instead of a response");
    };
    assert_eq!(response.id, Some(id.into()), "{description}: response id");
    response
}

/// Couples a live peer with its worker so assertions cannot detach the worker
/// on an unwind path. The peer is dropped before `ThreadJoins`, which makes
/// EOF available before its bounded settlement runs.
struct LifecycleThreadHarness {
    peer: Option<fastmcp_rust::memory::MemoryTransport>,
    joins: ThreadJoins,
    outcome: mpsc::Receiver<McpResult<()>>,
}

impl LifecycleThreadHarness {
    fn spawn<F>(cx: &Cx, runner: F) -> Self
    where
        F: FnOnce(&Cx, fastmcp_rust::memory::MemoryTransport) -> McpResult<()> + Send + 'static,
    {
        let (peer, server_transport) = fastmcp_rust::memory::create_memory_transport_pair();
        // This must be unbounded: an assertion can unwind before it observes
        // the result, and the worker must still be able to exit so the RAII
        // join guard can settle it instead of waiting on a blocked send.
        let (outcome_tx, outcome) = mpsc::channel();
        let server_cx = cx.clone();
        let handle = spawn_thread(move || {
            let _ = outcome_tx.send(runner(&server_cx, server_transport));
        });
        Self {
            peer: Some(peer),
            joins: ThreadJoins::new(vec![handle]),
            outcome,
        }
    }

    fn peer_mut(&mut self) -> &mut fastmcp_rust::memory::MemoryTransport {
        self.peer
            .as_mut()
            .expect("lifecycle peer must remain owned")
    }

    fn settle(mut self, owner: &str) -> McpResult<()> {
        let outcome = self
            .outcome
            .recv_timeout(MEMORY_SERVER_TEARDOWN_BOUND)
            .unwrap_or_else(|error| panic!("{owner} did not report a bounded result: {error}"));
        self.peer.take();
        drop(self);
        outcome
    }
}

impl Drop for LifecycleThreadHarness {
    fn drop(&mut self) {
        // Fields then drop in declaration order: peer (closed) before joins.
        self.peer.take();
    }
}

fn assert_lifecycle_opening(
    peer: &mut fastmcp_rust::memory::MemoryTransport,
    cx: &Cx,
    facade: &str,
    server_name: &str,
    opening: JsonRpcMessage,
    opening_is_modern: bool,
) {
    peer.send(cx, &opening)
        .unwrap_or_else(|error| panic!("{facade}: send era-correct opening: {error}"));
    let opening_response = lifecycle_response(peer, cx, 1, "era-correct opening response");
    assert!(
        opening_response.error.is_none(),
        "{facade}: era-correct opening must succeed: {opening_response:?}"
    );
    let opening_result = opening_response
        .result
        .as_ref()
        .expect("era-correct opening must carry a result");
    if opening_is_modern {
        assert_eq!(opening_result["resultType"], json!("complete"));
        assert_eq!(
            opening_result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            json!(server_name),
            "{facade}: final discovery must identify its facade server"
        );
    } else {
        assert_eq!(
            opening_result["protocolVersion"],
            json!(legacy_2024::PROTOCOL_VERSION),
            "{facade}: exact-2024 initialize response must pin 2024-11-05"
        );
    }
}

fn assert_live_facade_era_admission<F>(
    facade: &str,
    server_name: &str,
    opening: JsonRpcMessage,
    opening_is_modern: bool,
    calls: Arc<AtomicUsize>,
    runner: F,
) where
    F: FnOnce(&Cx, fastmcp_rust::memory::MemoryTransport) -> McpResult<()> + Send + 'static,
{
    let cx = Cx::for_testing();
    let mut harness = LifecycleThreadHarness::spawn(&cx, runner);

    assert_lifecycle_opening(
        harness.peer_mut(),
        &cx,
        facade,
        server_name,
        opening,
        opening_is_modern,
    );

    if !opening_is_modern {
        harness
            .peer_mut()
            .send(
                &cx,
                &JsonRpcMessage::Request(JsonRpcRequest::initialized_notification()),
            )
            .unwrap_or_else(|error| panic!("{facade}: send exact-2024 initialized: {error}"));
    }

    // RH-5: the accepted request and the refused request below have the same
    // id, method, tool name, and arguments. Only the prohibited era metadata
    // changes, so the counter is an unchanged-state proof of early refusal.
    harness
        .peer_mut()
        .send(&cx, &lifecycle_tool_request(2, opening_is_modern))
        .unwrap_or_else(|error| panic!("{facade}: send era-correct tool request: {error}"));
    let accepted = lifecycle_response(harness.peer_mut(), &cx, 2, "era-correct tool response");
    assert!(
        accepted.error.is_none(),
        "{facade}: era-correct tool request must reach the handler: {accepted:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "{facade}: era-correct tool request must mutate the real handler exactly once"
    );
    let expected_result_type = opening_is_modern.then(|| json!("complete"));
    assert_eq!(
        accepted
            .result
            .as_ref()
            .and_then(|result| result.get("resultType")),
        expected_result_type.as_ref(),
        "{facade}: successful tool response must retain its era-specific framing"
    );

    harness
        .peer_mut()
        .send(&cx, &lifecycle_tool_request(2, !opening_is_modern))
        .unwrap_or_else(|error| panic!("{facade}: send opposite-era tool request: {error}"));
    let refused = lifecycle_response(harness.peer_mut(), &cx, 2, "opposite-era refusal response");
    let error = refused
        .error
        .as_ref()
        .expect("opposite-era request must receive a JSON-RPC refusal");
    assert_eq!(
        error.code.as_i32(),
        Some(McpErrorCode::InvalidRequest.into())
    );
    assert_eq!(
        error.message,
        "Request does not match the connection's negotiated MCP protocol era"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "{facade}: opposite-era refusal must not mutate the handler"
    );
    let outcome = harness.settle("caller-owned facade era refusal");
    assert!(
        outcome.is_err(),
        "{facade}: opposite-era refusal must terminate the mismatched connection"
    );
}

fn assert_live_facade_cancellation<F>(
    facade: &str,
    server_name: &str,
    opening: JsonRpcMessage,
    opening_is_modern: bool,
    runner: F,
) where
    F: FnOnce(&Cx, fastmcp_rust::memory::MemoryTransport) -> McpResult<()> + Send + 'static,
{
    let cx = Cx::for_testing();
    let mut harness = LifecycleThreadHarness::spawn(&cx, runner);

    assert_lifecycle_opening(
        harness.peer_mut(),
        &cx,
        facade,
        server_name,
        opening,
        opening_is_modern,
    );
    if !opening_is_modern {
        harness
            .peer_mut()
            .send(
                &cx,
                &JsonRpcMessage::Request(JsonRpcRequest::initialized_notification()),
            )
            .unwrap_or_else(|error| panic!("{facade}: send exact-2024 initialized: {error}"));
    }

    // Keep the peer open through cancellation settlement: the completed
    // worker must have observed this exact caller Cx rather than peer EOF.
    cx.set_cancel_requested(true);
    assert!(
        cx.is_cancel_requested(),
        "{facade}: cancellation must be requested on the caller-owned Cx"
    );
    let deadline = Instant::now() + MEMORY_SERVER_TEARDOWN_BOUND;
    while !harness.joins.0[0].is_finished() {
        assert!(
            Instant::now() < deadline,
            "{facade}: caller-owned cancellation exceeded its bounded settlement window"
        );
        thread::sleep(Duration::from_millis(1));
    }
    let outcome = harness.settle("caller-owned facade cancellation");
    outcome.unwrap_or_else(|error| {
        panic!("{facade}: cancellation of the supplied Cx must settle cleanly: {error}")
    });
}

#[test]
fn public_facade_servers_forward_caller_owned_structured_lifecycles() {
    // These function-item references prove the terminal, caller-owned stdio
    // entry point remains available from every policy-pinned facade. The
    // returning transport checks below are the runtime proof because they can
    // settle without terminating the test process.
    let _ = auto::Server::run_stdio_with_cx;
    let _ = modern::Server::run_stdio_with_cx;
    let _ = legacy_2024::Server::run_stdio_with_cx;

    let auto_calls = Arc::new(AtomicUsize::new(0));
    let auto_handler_calls = Arc::clone(&auto_calls);
    assert_live_facade_era_admission(
        "Auto facade",
        "facade-auto-lifecycle",
        lifecycle_modern_opening(1),
        true,
        auto_calls,
        move |cx, transport| {
            auto::server_builder("facade-auto-lifecycle", "1.0.0")
                .tool(CallerOwnedLifecycleTool {
                    calls: auto_handler_calls,
                })
                .build()
                .run_transport_returning_with_cx(cx, transport)
        },
    );
    assert_live_facade_cancellation(
        "Auto facade",
        "facade-auto-cancellation",
        lifecycle_modern_opening(1),
        true,
        |cx, transport| {
            auto::server_builder("facade-auto-cancellation", "1.0.0")
                .build()
                .run_transport_returning_with_cx(cx, transport)
        },
    );

    let modern_calls = Arc::new(AtomicUsize::new(0));
    let modern_handler_calls = Arc::clone(&modern_calls);
    assert_live_facade_era_admission(
        "modern facade",
        "facade-modern-lifecycle",
        lifecycle_modern_opening(1),
        true,
        modern_calls,
        move |cx, transport| {
            modern::server_builder("facade-modern-lifecycle", "1.0.0")
                .tool(CallerOwnedLifecycleTool {
                    calls: modern_handler_calls,
                })
                .build()
                .run_transport_returning_with_cx(cx, transport)
        },
    );
    assert_live_facade_cancellation(
        "modern facade",
        "facade-modern-cancellation",
        lifecycle_modern_opening(1),
        true,
        |cx, transport| {
            modern::server_builder("facade-modern-cancellation", "1.0.0")
                .build()
                .run_transport_returning_with_cx(cx, transport)
        },
    );

    let legacy_calls = Arc::new(AtomicUsize::new(0));
    let legacy_handler_calls = Arc::clone(&legacy_calls);
    assert_live_facade_era_admission(
        "exact-2024 facade",
        "facade-legacy-lifecycle",
        lifecycle_legacy_opening(1),
        false,
        legacy_calls,
        move |cx, transport| {
            legacy_2024::server_builder("facade-legacy-lifecycle", "1.0.0")
                .tool(CallerOwnedLifecycleTool {
                    calls: legacy_handler_calls,
                })
                .build()
                .run_transport_returning_with_cx(cx, transport)
        },
    );
    assert_live_facade_cancellation(
        "exact-2024 facade",
        "facade-legacy-cancellation",
        lifecycle_legacy_opening(1),
        false,
        |cx, transport| {
            legacy_2024::server_builder("facade-legacy-cancellation", "1.0.0")
                .build()
                .run_transport_returning_with_cx(cx, transport)
        },
    );
}

#[cfg(feature = "proxy")]
#[test]
fn public_facade_proxy_builders_preserve_pinned_eras() {
    // Compile-proof every advertised proxy registration path from each public
    // builder. The runtime checks below exercise the policy boundaries before
    // the unbound fixture backend can be consulted.
    let _ = auto::ServerBuilder::proxy;
    let _ = auto::ServerBuilder::as_proxy;
    let _ = auto::ServerBuilder::as_proxy_raw;
    let _ = auto::ServerBuilder::proxy_typed;
    let _ = auto::ServerBuilder::as_proxy_typed;
    let _ = modern::ServerBuilder::proxy;
    let _ = modern::ServerBuilder::as_proxy;
    let _ = modern::ServerBuilder::as_proxy_raw;
    let _ = modern::ServerBuilder::proxy_typed;
    let _ = modern::ServerBuilder::as_proxy_typed;
    let _ = legacy_2024::ServerBuilder::proxy;
    let _ = legacy_2024::ServerBuilder::as_proxy;
    let _ = legacy_2024::ServerBuilder::as_proxy_raw;
    let _ = legacy_2024::ServerBuilder::proxy_typed;
    let _ = legacy_2024::ServerBuilder::as_proxy_typed;

    let legacy_catalog = fastmcp_rust::ProxyCatalog {
        tool_catalog_era: Some(fastmcp_rust::ProtocolEra::Legacy2024),
        ..Default::default()
    };
    assert!(
        modern::server_builder("facade-modern-proxy", "1.0.0")
            .proxy(
                fastmcp_rust::ProxyClient::from_backend(FacadeProxyBoundaryBackend),
                legacy_catalog,
            )
            .is_err()
    );

    let final_catalog = fastmcp_rust::ProxyCatalog {
        tool_catalog_era: Some(fastmcp_rust::ProtocolEra::Modern2026),
        ..Default::default()
    };
    assert!(
        legacy_2024::server_builder("facade-legacy-proxy", "1.0.0")
            .proxy(
                fastmcp_rust::ProxyClient::from_backend(FacadeProxyBoundaryBackend),
                final_catalog,
            )
            .is_err()
    );
}

// ============================================================================
// Full lifecycle workflow tests
// ============================================================================

#[test]
fn workflow_complete_lifecycle() {
    let mut client = setup_workflow_server();

    // Phase 1: Initialize
    let init = client.initialize().unwrap();
    assert_eq!(init.server_info.name, "workflow-test-server");
    assert_eq!(init.server_info.version, "2.0.0");
    assert!(init.capabilities.tools.is_some());
    assert!(init.capabilities.resources.is_some());
    assert!(init.capabilities.prompts.is_some());

    // Phase 2: Discover capabilities
    let tools = client.list_tools().unwrap();
    assert_eq!(tools.len(), 3);

    let resources = client.list_resources().unwrap();
    assert_eq!(resources.len(), 2);

    let templates = client.list_resource_templates().unwrap();
    assert_eq!(templates.len(), 1);
    assert!(templates[0].uri_template.contains("{path}"));

    let prompts = client.list_prompts().unwrap();
    assert_eq!(prompts.len(), 2);

    // Phase 3: Execute operations
    let echo_result = client
        .call_tool("echo", json!({"message": "workflow test"}))
        .unwrap();
    assert!(
        matches!(echo_result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = echo_result.first() else {
        return;
    };
    assert_eq!(text, "workflow test");

    let status = client.read_resource("app://status").unwrap();
    let LegacyResourceContent::Text { text, .. } = &status[0] else {
        return;
    };
    let status_json: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(status_json["status"], "healthy");

    let mut args = HashMap::new();
    args.insert("topic".to_string(), "MCP protocol".to_string());
    let help = client.get_prompt("help", args).unwrap();
    let LegacyPromptMessage { content, .. } = &help[0];
    assert!(
        content
            .as_text()
            .is_some_and(|t| t.contains("MCP protocol"))
    );

    // Phase 4: Close
    client.close();
}

#[test]
fn workflow_discover_then_operate() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // First discover all available tools
    let tools = client.list_tools().unwrap();
    let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

    // Then call each tool that we find
    for name in &tool_names {
        let result = match *name {
            "echo" => client.call_tool("echo", json!({"message": "test"})),
            "counter" => client.call_tool("counter", json!({"value": 1})),
            "fail_on_demand" => client.call_tool("fail_on_demand", json!({"fail": false})),
            _ => continue,
        };
        assert!(result.is_ok(), "Tool {name} failed: {result:?}");
    }

    // Discover resources and read each one
    let resources = client.list_resources().unwrap();
    for resource in &resources {
        let content = client.read_resource(&resource.uri).unwrap();
        assert!(
            !content.is_empty(),
            "Resource {} returned empty",
            resource.uri
        );
    }
}

// ============================================================================
// Error recovery tests
// ============================================================================

#[test]
fn workflow_error_recovery_continues_after_tool_error() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // Successful call
    let result = client
        .call_tool("fail_on_demand", json!({"fail": false}))
        .unwrap();
    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert_eq!(text, "Success");

    // Failed call
    let err = client
        .call_tool("fail_on_demand", json!({"fail": true, "message": "boom"}))
        .unwrap_err();
    assert!(err.message.contains("boom") || err.message.contains("Requested failure"));

    // Should still work after the error
    let result = client
        .call_tool("echo", json!({"message": "still alive"}))
        .unwrap();
    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert_eq!(text, "still alive");
}

#[test]
fn workflow_error_recovery_alternating_success_failure() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    for i in 0..5 {
        let should_fail = i % 2 == 1;
        let result = client.call_tool(
            "fail_on_demand",
            json!({"fail": should_fail, "message": format!("iteration {i}")}),
        );

        if should_fail {
            assert!(result.is_err(), "Iteration {i} should have failed");
        } else {
            assert!(result.is_ok(), "Iteration {i} should have succeeded");
        }
    }

    // Final verification: server still responsive
    let tools = client.list_tools().unwrap();
    assert_eq!(tools.len(), 3);
}

#[test]
fn workflow_unknown_tool_doesnt_break_session() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // Call a valid tool
    let result = client
        .call_tool("echo", json!({"message": "before"}))
        .unwrap();
    assert_eq!(result.len(), 1);

    // Call an unknown tool (should fail)
    let err = client.call_tool("nonexistent", json!({}));
    assert!(err.is_err());

    // Call a valid tool again (should still work)
    let result = client
        .call_tool("echo", json!({"message": "after"}))
        .unwrap();
    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert_eq!(text, "after");
}

#[test]
fn workflow_unknown_resource_doesnt_break_session() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // Read a valid resource
    let content = client.read_resource("app://status").unwrap();
    assert!(!content.is_empty());

    // Try to read an unknown resource (should fail)
    let err = client.read_resource("app://nonexistent");
    assert!(err.is_err());

    // Read a valid resource again (should still work)
    let content = client.read_resource("file:///README.md").unwrap();
    let LegacyResourceContent::Text { text, .. } = &content[0] else {
        return;
    };
    assert!(text.contains("Test Project"));
}

// ============================================================================
// Multiple sequential clients
// ============================================================================

#[test]
fn workflow_sequential_clients_same_server() {
    // Each client gets its own server - test that server setup pattern works repeatedly
    for i in 0..3 {
        let mut client = setup_workflow_server();
        let init = client.initialize().unwrap();
        assert_eq!(init.server_info.name, "workflow-test-server");

        let result = client
            .call_tool("echo", json!({"message": format!("client-{i}")}))
            .unwrap();
        assert!(
            matches!(result.first(), Some(LegacyContent::Text { .. })),
            "expected text content"
        );
        let Some(LegacyContent::Text { text, .. }) = result.first() else {
            return;
        };
        assert_eq!(text, &format!("client-{i}"));

        client.close();
    }
}

#[test]
fn workflow_two_independent_servers() {
    // Server A: tools only
    let (builder_a, client_a_transport, server_a_transport) = TestServer::builder()
        .with_name("server-a")
        .build_server_builder();
    let server_a = builder_a.tool(EchoTool).build();
    let handle_a = spawn_thread(move || {
        let cx = Cx::for_testing();
        server_a
            .run_transport_returning_with_cx(&cx, server_a_transport)
            .expect("server A loop");
    });

    // Server B: resources only
    let (builder_b, client_b_transport, server_b_transport) = TestServer::builder()
        .with_name("server-b")
        .build_server_builder();
    let server_b = builder_b.resource(StatusResource).build();
    let handle_b = spawn_thread(move || {
        let cx = Cx::for_testing();
        server_b
            .run_transport_returning_with_cx(&cx, server_b_transport)
            .expect("server B loop");
    });

    let _joins = ThreadJoins::new(vec![handle_a, handle_b]);

    // Client A
    let mut client_a = TestClient::new(client_a_transport);
    let init_a = client_a.initialize().unwrap();
    assert_eq!(init_a.server_info.name, "server-a");
    assert!(init_a.capabilities.tools.is_some());
    assert!(init_a.capabilities.resources.is_none());

    // Client B
    let mut client_b = TestClient::new(client_b_transport);
    let init_b = client_b.initialize().unwrap();
    assert_eq!(init_b.server_info.name, "server-b");
    assert!(init_b.capabilities.tools.is_none());
    assert!(init_b.capabilities.resources.is_some());

    // Use both
    let echo = client_a
        .call_tool("echo", json!({"message": "from A"}))
        .unwrap();
    assert!(
        matches!(echo.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = echo.first() else {
        return;
    };
    assert_eq!(text, "from A");

    let status = client_b.read_resource("app://status").unwrap();
    assert!(!status.is_empty());
}

// ============================================================================
// Resource template tests
// ============================================================================

#[test]
fn workflow_list_resource_templates() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    let templates = client.list_resource_templates().unwrap();
    assert_eq!(templates.len(), 1);
    assert_eq!(templates[0].name, "File Path");
    assert!(templates[0].uri_template.contains("{path}"));
}

// ============================================================================
// No-args prompt test
// ============================================================================

#[test]
fn workflow_get_prompt_without_arguments() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    let messages = client.get_prompt("system_prompt", HashMap::new()).unwrap();
    assert_eq!(messages.len(), 1);
    let Some(LegacyPromptMessage { role, content, .. }) = messages.first() else {
        return;
    };
    assert!(matches!(*role, Role::Assistant));
    assert!(
        matches!(content, LegacyContent::Text { .. }),
        "expected text content"
    );
    let LegacyContent::Text { text, .. } = content else {
        return;
    };
    assert!(text.contains("helpful assistant"));
}

// ============================================================================
// Heavy sequential operations
// ============================================================================

#[test]
fn workflow_many_sequential_tool_calls() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // 20 sequential tool calls
    for i in 0..20 {
        let msg = format!("message-{i}");
        let result = client.call_tool("echo", json!({"message": msg})).unwrap();
        assert!(
            matches!(result.first(), Some(LegacyContent::Text { .. })),
            "expected text content"
        );
        let Some(LegacyContent::Text { text, .. }) = result.first() else {
            return;
        };
        assert_eq!(text, &msg);
    }
}

#[test]
fn workflow_interleaved_list_and_call() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // Interleave list and call operations
    for _ in 0..5 {
        let tools = client.list_tools().unwrap();
        assert_eq!(tools.len(), 3);

        let result = client.call_tool("counter", json!({"value": 42})).unwrap();
        assert!(
            matches!(result.first(), Some(LegacyContent::Text { .. })),
            "expected text content"
        );
        let Some(LegacyContent::Text { text, .. }) = result.first() else {
            return;
        };
        assert_eq!(text, "42");

        let resources = client.list_resources().unwrap();
        assert_eq!(resources.len(), 2);

        let content = client.read_resource("app://status").unwrap();
        assert!(!content.is_empty());
    }
}

// ============================================================================
// Server info and capability verification
// ============================================================================

#[test]
fn workflow_server_name_and_version() {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("custom-name")
        .with_version("9.8.7")
        .build_server_builder();

    let server = builder.tool(EchoTool).build();
    let handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server
            .run_transport_returning_with_cx(&cx, server_transport)
            .expect("workflow server loop");
    });
    let _joins = ThreadJoins::new(vec![handle]);

    let mut client = TestClient::new(client_transport);
    let init = client.initialize().unwrap();

    assert_eq!(init.server_info.name, "custom-name");
    assert_eq!(init.server_info.version, "9.8.7");
}

#[test]
fn workflow_capabilities_match_handlers() {
    let (builder, client_transport, server_transport) =
        TestServer::builder().build_server_builder();

    let server = builder.tool(EchoTool).resource(StatusResource).build();
    let handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server
            .run_transport_returning_with_cx(&cx, server_transport)
            .expect("workflow server loop");
    });
    let _joins = ThreadJoins::new(vec![handle]);

    let mut client = TestClient::new(client_transport);
    let init = client.initialize().unwrap();

    // Has tools and resources, but NOT prompts
    assert!(init.capabilities.tools.is_some());
    assert!(init.capabilities.resources.is_some());
    assert!(init.capabilities.prompts.is_none());
}

// ============================================================================
// Client info tests
// ============================================================================

#[test]
fn workflow_custom_client_info_accepted() {
    let (builder, client_transport, server_transport) =
        TestServer::builder().build_server_builder();

    let server = builder.tool(EchoTool).build();
    let handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server
            .run_transport_returning_with_cx(&cx, server_transport)
            .expect("workflow server loop");
    });
    let _joins = ThreadJoins::new(vec![handle]);

    let mut client =
        TestClient::new(client_transport).with_client_info("my-custom-client", "5.0.0");

    // Should initialize successfully with custom client info
    let init = client.initialize().unwrap();
    assert!(init.capabilities.tools.is_some());

    // And should work normally
    let result = client
        .call_tool("echo", json!({"message": "custom client"}))
        .unwrap();
    assert_eq!(result.len(), 1);
}

// ============================================================================
// Annotation verification
// ============================================================================

#[test]
fn workflow_tool_annotations_preserved() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    let tools = client.list_tools().unwrap();
    let echo = tools.iter().find(|t| t.name == "echo").unwrap();

    let annotations = echo.annotations.as_ref().unwrap();
    assert_eq!(annotations.read_only, Some(true));
    assert_eq!(annotations.idempotent, Some(true));
}

#[test]
fn workflow_tool_descriptions_preserved() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    let tools = client.list_tools().unwrap();
    let echo = tools.iter().find(|t| t.name == "echo").unwrap();
    assert_eq!(echo.description.as_deref(), Some("Echoes back the input"));
    assert_eq!(echo.version.as_deref(), Some("1.0.0"));
}

#[test]
fn workflow_resource_metadata_preserved() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    let resources = client.list_resources().unwrap();
    let readme = resources.iter().find(|r| r.name == "README").unwrap();
    assert_eq!(readme.mime_type.as_deref(), Some("text/markdown"));
    assert_eq!(readme.description.as_deref(), Some("Project README file"));
    assert_eq!(readme.version.as_deref(), Some("1.0.0"));
}

#[test]
fn workflow_prompt_arguments_preserved() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    let prompts = client.list_prompts().unwrap();
    let help = prompts.iter().find(|p| p.name == "help").unwrap();

    assert_eq!(help.arguments.len(), 1);
    assert_eq!(help.arguments[0].name, "topic");
    assert!(help.arguments[0].required);

    let system = prompts.iter().find(|p| p.name == "system_prompt").unwrap();
    assert!(system.arguments.is_empty());
}

// ============================================================================
// Content type helper for assertions
// ============================================================================

trait LegacyContentExt {
    fn as_text(&self) -> Option<&str>;
}

impl LegacyContentExt for LegacyContent {
    fn as_text(&self) -> Option<&str> {
        match self {
            LegacyContent::Text { text, .. } => Some(text),
            _ => None,
        }
    }
}

// ============================================================================
// Background Tasks E2E Tests (bd-og1)
// ============================================================================

// ============================================================================
// Final Tasks public-facade HTTP E2E tests
// ============================================================================

const FINAL_TASKS_E2E_BOUND: Duration = Duration::from_secs(2);
const FINAL_TASKS_HTTP_RESPONSE_MAX_BYTES: usize = 1 << 20;
const FINAL_TASKS_SERVER_BOUND: Duration = Duration::from_secs(4);

fn final_tasks_runtime_block_on<F: Future>(future: F) -> F::Output {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("final Tasks E2E runtime builds")
        .block_on(future)
}

fn final_tasks_runtime_block_on_bounded<F: Future>(cx: &Cx, future: F) -> F::Output {
    final_tasks_runtime_block_on(async {
        asupersync::time::timeout(cx.now(), FINAL_TASKS_E2E_BOUND, future)
            .await
            .expect("final Tasks public HTTP operation stays within its bound")
    })
}

struct FinalTasksHttpFixture {
    address: SocketAddr,
    shutdown: mpsc::SyncSender<()>,
    finished: mpsc::Receiver<Result<(), String>>,
    join: Option<JoinHandle<()>>,
}

/// Retains the spawned final-Tasks server until readiness has succeeded and
/// ownership can move into the fixture returned to the test.
struct FinalTasksHttpStartupGuard {
    shutdown: Option<mpsc::SyncSender<()>>,
    finished: Option<mpsc::Receiver<Result<(), String>>>,
    join: Option<JoinHandle<()>>,
}

impl FinalTasksHttpStartupGuard {
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

impl Drop for FinalTasksHttpStartupGuard {
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
        let settlement = settle_final_tasks_http_server(shutdown, finished, &mut self.join);
        if settlement.is_err() && self.join.is_some() {
            eprintln!(
                "final Tasks HTTP server startup left a live unjoinable thread after bounded settlement"
            );
            std::process::abort();
        }
    }
}

impl FinalTasksHttpFixture {
    fn spawn(server: auto::Server, runner: AuthorizedTaskServiceRunner) -> Self {
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(1);
        let (finished_tx, finished_rx) = mpsc::sync_channel(1);
        let join = Some(thread::spawn(move || {
            let (task_done_tx, task_done_rx) = mpsc::channel();
            let (server_cx_tx, server_cx_rx) = mpsc::sync_channel(1);
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .with_reactor(
                    asupersync::runtime::reactor::create_reactor()
                        .expect("final Tasks E2E server reactor initializes"),
                )
                .blocking_threads(4, 64)
                .build()
                .expect("final Tasks E2E server runtime builds");
            runtime
                    .handle()
                    .try_spawn_with_cx(move |cx| async move {
                        let _ = server_cx_tx.send(cx.clone());
                        let mut service = Box::pin(runner.run(&cx));
                        let service_ready = std::future::poll_fn(|task_context| {
                            match service.as_mut().poll(task_context) {
                                Poll::Pending => Poll::Ready(Ok(())),
                                Poll::Ready(Ok(())) => Poll::Ready(Err(
                                    "final Tasks service stopped before HTTP startup".to_owned(),
                                )),
                                Poll::Ready(Err(error)) => Poll::Ready(Err(format!(
                                    "final Tasks service failed before HTTP startup: {error}"
                                ))),
                            }
                        })
                        .await;
                        if let Err(error) = service_ready {
                            let _ = ready_tx.send(Err(error.clone()));
                            let _ = finished_tx.send(Err(error));
                            let _ = task_done_tx.send(());
                            return;
                        }
                        let outcome =
                            asupersync::time::timeout(cx.now(), FINAL_TASKS_SERVER_BOUND, async {
                                let bound = server.bind_http(&cx, "127.0.0.1:0").await.map_err(
                                    |error| format!("final Tasks E2E bind failed: {error}"),
                                )?;
                                let address = bound.local_addr().map_err(|error| {
                                    format!("final Tasks E2E address failed: {error}")
                                })?;
                                ready_tx.send(Ok(address)).map_err(|_| {
                                    "final Tasks E2E startup receiver went away".to_owned()
                                })?;
                                let mut serving = Box::pin(bound.serve(&cx));
                                let mut service_stopped = false;
                                std::future::poll_fn(|task_context| {
                                    if !service_stopped {
                                        match service.as_mut().poll(task_context) {
                                            Poll::Ready(Ok(())) if cx.checkpoint().is_ok() => {
                                                return Poll::Ready(Err(
                                                    "final Tasks service stopped while HTTP server remained live"
                                                        .to_owned(),
                                                ));
                                            }
                                            Poll::Ready(Err(error)) if cx.checkpoint().is_ok() => {
                                                return Poll::Ready(Err(format!(
                                                    "final Tasks service failed while HTTP server remained live: {error}"
                                                )));
                                            }
                                            Poll::Ready(_) => service_stopped = true,
                                            Poll::Pending => {}
                                        }
                                    }
                                    match serving.as_mut().poll(task_context) {
                                        Poll::Ready(Ok(HttpServerShutdown::Quiescent)) => {
                                            Poll::Ready(Ok(()))
                                        }
                                        Poll::Ready(Ok(HttpServerShutdown::Nonquiescent(
                                            mut shutdown,
                                        ))) => Poll::Ready(Err(format!(
                                            "final Tasks E2E server stopped nonquiescently: {:?}",
                                            shutdown.poll_settlement()
                                        ))),
                                        Poll::Ready(Err(error)) => Poll::Ready(Err(format!(
                                            "final Tasks E2E server stopped: {error}"
                                        ))),
                                        Poll::Pending => Poll::Pending,
                                    }
                                })
                                .await
                            })
                            .await
                            .unwrap_or_else(|_| {
                                Err("final Tasks E2E server exceeded its deadline".to_owned())
                            });
                        let _ = finished_tx.send(outcome);
                        let _ = task_done_tx.send(());
                    })
                    .expect("final Tasks E2E server task is admitted");
            runtime.block_on(async move {
                let mut server_cx = None;
                loop {
                    if let Ok(cx) = server_cx_rx.try_recv() {
                        server_cx = Some(cx);
                    }
                    match shutdown_rx.try_recv() {
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                            if let Some(cx) = server_cx.as_ref() {
                                cx.cancel_with(
                                    asupersync::CancelKind::User,
                                    Some("final Tasks E2E fixture shutdown"),
                                );
                            }
                        }
                        Err(mpsc::TryRecvError::Empty) => {}
                    }
                    if task_done_rx.try_recv().is_ok() {
                        break;
                    }
                    let cx = Cx::current().expect("server runtime installs an ambient Cx");
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                }
            });
        }));
        let mut startup = FinalTasksHttpStartupGuard {
            shutdown: Some(shutdown_tx),
            finished: Some(finished_rx),
            join,
        };
        let address = match ready_rx.recv_timeout(FINAL_TASKS_E2E_BOUND) {
            Ok(Ok(address)) => address,
            Ok(Err(error)) => panic!("final Tasks E2E server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("final Tasks E2E server startup readiness channel disconnected")
            }
            Err(error) => panic!("final Tasks E2E server startup exceeded its bound: {error}"),
        };
        let (shutdown, finished, join) = startup.into_parts();
        Self {
            address,
            shutdown,
            finished,
            join,
        }
    }

    fn plan(&self, policy: ProtocolPolicy) -> ClientProtocolPlan {
        let modern = CanonicalHttpUrl::parse(&format!("http://{}/mcp", self.address))
            .expect("final Tasks modern endpoint is canonical");
        let legacy_sse = CanonicalHttpUrl::parse(&format!("http://{}/sse", self.address))
            .expect("final Tasks legacy SSE endpoint is canonical");
        let legacy_message = CanonicalHttpUrl::parse(&format!("http://{}/messages", self.address))
            .expect("final Tasks legacy message endpoint is canonical");
        ClientProtocolPlan::http(
            policy,
            (!matches!(policy, ProtocolPolicy::LegacyOnly)).then_some(modern),
            (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_sse),
            (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_message),
            "final-tasks-e2e-credential".to_owned(),
            "final-tasks-e2e-security".to_owned(),
            "final-tasks-e2e-native-h1".to_owned(),
            1,
            1,
            0,
        )
        .expect("final Tasks HTTP plan is valid")
    }

    fn shutdown(mut self) {
        settle_final_tasks_http_server(&self.shutdown, &self.finished, &mut self.join)
            .unwrap_or_else(|error| panic!("final Tasks E2E server teardown failed: {error}"));
    }
}

impl Drop for FinalTasksHttpFixture {
    fn drop(&mut self) {
        if self.join.is_none() {
            return;
        }
        if let Err(error) =
            settle_final_tasks_http_server(&self.shutdown, &self.finished, &mut self.join)
        {
            eprintln!("final Tasks HTTP server fixture drop failed: {error}");
            std::process::abort();
        }
    }
}

fn settle_final_tasks_http_server(
    shutdown: &mpsc::SyncSender<()>,
    finished: &mpsc::Receiver<Result<(), String>>,
    join: &mut Option<JoinHandle<()>>,
) -> Result<(), String> {
    match shutdown.try_send(()) {
        Ok(()) | Err(mpsc::TrySendError::Full(())) | Err(mpsc::TrySendError::Disconnected(())) => {}
    }
    let outcome = finished
        .recv_timeout(FINAL_TASKS_E2E_BOUND)
        .map_err(|error| format!("final Tasks E2E server teardown exceeded its bound: {error}"));
    let join_result = join_final_tasks_thread(join);
    let outcome = outcome?;
    outcome.map_err(|error| format!("final Tasks E2E server teardown failed: {error}"))?;
    join_result
}

fn join_final_tasks_thread(join: &mut Option<JoinHandle<()>>) -> Result<(), String> {
    let deadline = Instant::now() + FINAL_TASKS_E2E_BOUND;
    loop {
        let Some(handle) = join.as_ref() else {
            return Ok(());
        };
        if handle.is_finished() {
            return join
                .take()
                .expect("completed final Tasks server retains its join handle")
                .join()
                .map_err(|_| "final Tasks E2E server thread panicked".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("final Tasks E2E server reported completion but did not exit".to_owned());
        }
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn workflow_final_tasks_startup_guard_preserves_planted_startup_error() {
    let (shutdown_tx, shutdown_rx) = mpsc::sync_channel::<()>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let startup = FinalTasksHttpStartupGuard {
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
fn workflow_final_tasks_startup_guard_resumes_planted_pre_readiness_panic() {
    let (shutdown_tx, _shutdown_rx) = mpsc::sync_channel::<()>(1);
    let (_finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let mut startup = FinalTasksHttpStartupGuard {
        shutdown: Some(shutdown_tx),
        finished: Some(finished_rx),
        join: Some(thread::spawn(|| panic!("planted pre-readiness panic"))),
    };
    let deadline = Instant::now() + FINAL_TASKS_E2E_BOUND;
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

struct E2eFinalTaskSupervisor {
    input_required: mpsc::SyncSender<()>,
    cancelled: mpsc::SyncSender<()>,
}

impl ApplicationTaskSupervisor for E2eFinalTaskSupervisor {
    fn resume<'a>(
        &'a self,
        cx: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
        let input_required = self.input_required.clone();
        let cancelled = self.cancelled.clone();
        Box::pin(async move {
            match handoff {
                FinalTaskSupervisorHandoff::Initial(initial) => {
                    let requests: FinalTaskInputRequests = serde_json::from_value(json!({
                        "roots": {"method": "roots/list"}
                    }))
                    .expect("the public final roots input descriptor is typed");
                    initial.require_input(
                        requests,
                        Some("awaiting roots from live supervisor".to_owned()),
                    )?;
                    input_required.send(()).map_err(|_| {
                        McpError::internal_error("E2E input-required observer dropped")
                    })?;
                }
                FinalTaskSupervisorHandoff::Resumed(accepted) => loop {
                    if accepted.is_cancellation_requested()? {
                        accepted
                            .honor_cancellation(Some("cancelled by live supervisor".to_owned()))?;
                        cancelled.send(()).map_err(|_| {
                            McpError::internal_error("E2E cancellation observer dropped")
                        })?;
                        break;
                    }
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                },
            }
            Ok(())
        })
    }
}

fn state_only_mrtr_input_required() -> InputRequiredResult {
    let wire = serde_json::json!({
        "resultType": "input_required",
        "requestState": "handler-forged-state",
    })
    .to_string();
    let (decoded, diagnostic) =
        decode_peer_result(&wire, ResultPeerEra::Modern, &CoreResultDiscriminatorPolicy)
            .expect("state-only final input-required result decodes");
    assert!(diagnostic.is_none());
    let DecodedResult::InputRequired(result) = decoded else {
        panic!("state-only final result retains the input-required branch");
    };
    assert!(result.input_requests().is_none());
    result
}

fn state_only_mrtr_complete_result() -> CompleteResult<FinalCallToolResult> {
    CompleteResult::new(
        FinalCallToolResult {
            content: vec![ContentBlock::text("state-only MRTR resumed")],
            is_error: false,
            structured_content: None,
        },
        ResultMeta::server_generated(Implementation {
            name: "state-only-mrtr-e2e".to_owned(),
            version: "1.0.0".to_owned(),
            title: None,
            description: None,
            website_url: None,
            icons: Vec::new(),
            additional: BTreeMap::new(),
        }),
    )
}

struct PublicStateOnlyMrtrTool {
    initial_calls: Arc<std::sync::atomic::AtomicUsize>,
    resumed_calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl ToolHandler for PublicStateOnlyMrtrTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "public-state-only-mrtr".to_owned(),
            description: Some("Proves state-only MRTR over the public HTTP facade".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("legacy state-only MRTR")])
    }

    fn call_final_outcome(
        &self,
        _ctx: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        self.initial_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(FinalToolOutcome::InputRequired(
            state_only_mrtr_input_required(),
        ))
    }

    fn call_final_outcome_async_resuming_in_request<'a>(
        &'a self,
        _ctx: &'a McpContext,
        _request_cx: &'a Cx,
        _arguments: serde_json::Value,
        resume_inputs: Option<&'a MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        Box::pin(async move {
            let Some(resume_inputs) = resume_inputs else {
                return Outcome::Err(McpError::internal_error(
                    "state-only MRTR resume inputs were not supplied",
                ));
            };
            if !resume_inputs.responses().is_empty() {
                return Outcome::Err(McpError::internal_error(
                    "state-only MRTR resume unexpectedly carried input responses",
                ));
            }
            self.resumed_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Outcome::Ok(FinalToolOutcome::Complete(state_only_mrtr_complete_result()))
        })
    }
}

fn typed_roots_input_required() -> InputRequiredResult {
    let requests = MrtrInputRequests::new([("roots".to_owned(), MrtrInputRequest::roots())])
        .expect("the E2E handler's typed roots request is valid");
    let wire = serde_json::json!({
        "resultType": "input_required",
        "inputRequests": requests,
        // This handler-authored value is deliberately forged. The framework
        // must replace it with its session-bound opaque request state.
        "requestState": "handler-forged-resource-prompt-state",
    })
    .to_string();
    let (decoded, diagnostic) =
        decode_peer_result(&wire, ResultPeerEra::Modern, &CoreResultDiscriminatorPolicy)
            .expect("typed resource/prompt input-required result decodes");
    assert!(diagnostic.is_none());
    let DecodedResult::InputRequired(result) = decoded else {
        panic!("the typed resource/prompt result remains input_required");
    };
    assert!(
        result
            .input_requests()
            .and_then(|requests| requests.get("roots"))
            .is_some(),
        "the handler emits one typed roots request"
    );
    result
}

fn public_mrtr_result_meta() -> ResultMeta {
    ResultMeta::server_generated(Implementation {
        name: "public-resource-prompt-mrtr-e2e".to_owned(),
        version: "1.0.0".to_owned(),
        title: None,
        description: None,
        website_url: None,
        icons: Vec::new(),
        additional: BTreeMap::new(),
    })
}

struct PublicTypedMrtrResource {
    uri: &'static str,
    name: &'static str,
    initial_calls: Arc<AtomicUsize>,
    resumed_calls: Arc<AtomicUsize>,
    legacy_calls: Arc<AtomicUsize>,
    input_required_after_resume: Arc<AtomicUsize>,
}

impl ResourceHandler for PublicTypedMrtrResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: self.uri.to_owned(),
            name: self.name.to_owned(),
            description: Some("public modern typed MRTR resource proof".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        self.legacy_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![ResourceContent {
            uri: self.uri.to_owned(),
            mime_type: Some("text/plain".to_owned()),
            text: Some("exact legacy resource result".to_owned()),
            blob: None,
        }])
    }

    fn declares_final_mrtr(&self) -> bool {
        true
    }

    fn final_resource_read_cache_hint_provenance(&self) -> FinalResourceReadCacheHintProvenance {
        FinalResourceReadCacheHintProvenance::Explicit
    }

    fn read_final_outcome(
        &self,
        _ctx: &McpContext,
    ) -> McpResult<FinalMethodOutcome<FinalReadResourceResult>> {
        self.initial_calls.fetch_add(1, Ordering::SeqCst);
        Ok(FinalMethodOutcome::InputRequired(
            typed_roots_input_required(),
        ))
    }

    fn read_final_outcome_async_with_uri_resuming_in_request<'a>(
        &'a self,
        _ctx: &'a McpContext,
        _request_cx: &'a Cx,
        _uri: &'a str,
        _params: &'a HashMap<String, String>,
        resume_inputs: Option<&'a MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>> {
        Box::pin(async move {
            let Some(resume_inputs) = resume_inputs else {
                return Outcome::Err(McpError::internal_error(
                    "resource MRTR resume inputs were not supplied",
                ));
            };
            match resume_inputs.roots("roots") {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Outcome::Err(McpError::internal_error(
                        "resource MRTR typed roots input was not supplied",
                    ));
                }
                Err(error) => return Outcome::Err(error),
            }
            self.resumed_calls.fetch_add(1, Ordering::SeqCst);
            if self
                .input_required_after_resume
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return Outcome::Ok(FinalMethodOutcome::InputRequired(
                    typed_roots_input_required(),
                ));
            }
            Outcome::Ok(FinalMethodOutcome::Complete(CompleteResult::new(
                FinalReadResourceResult {
                    contents: Vec::new(),
                    ttl_ms: CacheTtl::milliseconds(17),
                    cache_scope: CacheScope::Private,
                },
                public_mrtr_result_meta(),
            )))
        })
    }
}

struct PublicTypedMrtrPrompt {
    initial_calls: Arc<AtomicUsize>,
    resumed_calls: Arc<AtomicUsize>,
    legacy_calls: Arc<AtomicUsize>,
}

impl PromptHandler for PublicTypedMrtrPrompt {
    fn definition(&self) -> Prompt {
        Prompt {
            name: "public-typed-mrtr-prompt".to_owned(),
            description: Some("public modern typed MRTR prompt proof".to_owned()),
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
        self.legacy_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![PromptMessage {
            role: Role::Assistant,
            content: Content::text("exact legacy prompt result"),
        }])
    }

    fn declares_final_mrtr(&self) -> bool {
        true
    }

    fn get_final_outcome(
        &self,
        _ctx: &McpContext,
        _arguments: HashMap<String, String>,
    ) -> McpResult<FinalMethodOutcome<FinalGetPromptResult>> {
        self.initial_calls.fetch_add(1, Ordering::SeqCst);
        Ok(FinalMethodOutcome::InputRequired(
            typed_roots_input_required(),
        ))
    }

    fn get_final_outcome_async_resuming_in_request<'a>(
        &'a self,
        _ctx: &'a McpContext,
        _request_cx: &'a Cx,
        _arguments: HashMap<String, String>,
        resume_inputs: Option<&'a MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalGetPromptResult>>> {
        Box::pin(async move {
            let Some(resume_inputs) = resume_inputs else {
                return Outcome::Err(McpError::internal_error(
                    "prompt MRTR resume inputs were not supplied",
                ));
            };
            match resume_inputs.roots("roots") {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Outcome::Err(McpError::internal_error(
                        "prompt MRTR typed roots input was not supplied",
                    ));
                }
                Err(error) => return Outcome::Err(error),
            }
            self.resumed_calls.fetch_add(1, Ordering::SeqCst);
            Outcome::Ok(FinalMethodOutcome::Complete(CompleteResult::new(
                FinalGetPromptResult {
                    description: Some("exact final prompt result".to_owned()),
                    messages: vec![FinalPromptMessage {
                        role: Role::Assistant,
                        content: ContentBlock::text("exact final prompt content"),
                    }],
                },
                public_mrtr_result_meta(),
            )))
        })
    }
}

struct PublicFinalTaskTool {
    calls: Arc<AtomicUsize>,
}

impl ToolHandler for PublicFinalTaskTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "public-final-task".to_owned(),
            description: Some("Creates one official final Tasks operation".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("exact legacy completion")])
    }

    fn declares_final_tasks(&self) -> bool {
        true
    }

    fn call_final_outcome(
        &self,
        _ctx: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(FinalToolOutcome::CreateTask {
            work_descriptor: FinalTaskWorkDescriptor::new(json!({
                "operation": "public-final-task-e2e",
            }))?,
            status_message: Some("working through the public final API".to_owned()),
        })
    }
}

fn final_tasks_native_http_post(
    address: SocketAddr,
    mcp_name: &str,
    body: &serde_json::Value,
) -> (u16, Option<serde_json::Value>) {
    let body = serde_json::to_vec(body).expect("final Tasks native HTTP request serializes");
    let mut stream = std::net::TcpStream::connect_timeout(&address, FINAL_TASKS_E2E_BOUND)
        .expect("native final Tasks probe connects to the facade listener");
    stream
        .set_read_timeout(Some(FINAL_TASKS_E2E_BOUND))
        .expect("native final Tasks probe read deadline configures");
    stream
        .set_write_timeout(Some(FINAL_TASKS_E2E_BOUND))
        .expect("native final Tasks probe write deadline configures");
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nAccept: application/json\r\nContent-Type: application/json\r\nMCP-Protocol-Version: {}\r\nMcp-Method: tools/call\r\nMcp-Name: {mcp_name}\r\nContent-Length: {}\r\n\r\n",
        modern::PROTOCOL_VERSION,
        body.len(),
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.write_all(&body))
        .expect("native final Tasks probe commits one bounded request");

    let mut response = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = stream
            .read(&mut buffer)
            .expect("native final Tasks probe reads within its configured deadline");
        if read == 0 {
            break;
        }
        assert!(
            response
                .len()
                .checked_add(read)
                .is_some_and(|size| size <= FINAL_TASKS_HTTP_RESPONSE_MAX_BYTES),
            "native final Tasks response exceeds its bounded response budget"
        );
        response.extend_from_slice(&buffer[..read]);
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("native final Tasks response has complete headers");
    let headers = std::str::from_utf8(&response[..header_end])
        .expect("native final Tasks response headers are ASCII");
    let status = headers
        .split_whitespace()
        .nth(1)
        .expect("native final Tasks response has a status")
        .parse::<u16>()
        .expect("native final Tasks response status is numeric");
    let mut content_length = None;
    let mut chunked = false;
    for header in headers.lines().skip(1) {
        let (name, value) = header
            .split_once(':')
            .expect("native final Tasks response header has a field delimiter");
        if name.eq_ignore_ascii_case("content-length") {
            assert!(
                content_length.is_none(),
                "native final Tasks response has one Content-Length field"
            );
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .expect("native final Tasks response Content-Length is valid"),
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
    let body = if chunked {
        assert!(
            content_length.is_none(),
            "chunked native final Tasks response does not carry Content-Length"
        );
        final_tasks_chunked_response_body(body)
    } else {
        let content_length = content_length
            .expect("native final Tasks response uses Content-Length or chunked framing");
        assert_eq!(
            body.len(),
            content_length,
            "native final Tasks response body is complete"
        );
        body.to_vec()
    };
    let json = (!body.is_empty())
        .then(|| serde_json::from_slice(&body).expect("native final Tasks JSON response parses"));
    (status, json)
}

fn final_tasks_chunked_response_body(body: &[u8]) -> Vec<u8> {
    let mut cursor = 0;
    let mut decoded = Vec::new();
    loop {
        let size_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|offset| cursor + offset)
            .expect("chunked final Tasks response has a complete chunk-size line");
        let size_line = std::str::from_utf8(&body[cursor..size_end])
            .expect("chunked final Tasks chunk size is ASCII");
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or_default(), 16)
            .expect("chunked final Tasks chunk size is hexadecimal");
        cursor = size_end + 2;
        if size == 0 {
            loop {
                let trailer_end = body[cursor..]
                    .windows(2)
                    .position(|window| window == b"\r\n")
                    .map(|offset| cursor + offset)
                    .expect("chunked final Tasks response has a complete trailer line");
                let trailer = &body[cursor..trailer_end];
                cursor = trailer_end + 2;
                if trailer.is_empty() {
                    assert_eq!(
                        cursor,
                        body.len(),
                        "chunked final Tasks response has no bytes after trailers"
                    );
                    return decoded;
                }
                assert!(
                    trailer.contains(&b':'),
                    "chunked final Tasks trailer has an HTTP field delimiter"
                );
            }
        }
        let chunk_end = cursor
            .checked_add(size)
            .expect("chunked final Tasks chunk length does not overflow");
        assert!(
            chunk_end.checked_add(2).is_some_and(|terminator_end| {
                terminator_end <= body.len() && &body[chunk_end..terminator_end] == b"\r\n"
            }),
            "chunked final Tasks response has a complete chunk body and terminator"
        );
        decoded.extend_from_slice(&body[cursor..chunk_end]);
        cursor = chunk_end + 2;
    }
}

#[test]
fn workflow_final_tasks_public_facade_lifecycle_and_legacy_negative() {
    let store = Arc::new(InMemoryFinalTaskStore::new(8).expect("bounded public final Task store"));
    let delivered_notifications = Arc::new(AtomicUsize::new(0));
    let notification_counter = Arc::clone(&delivered_notifications);
    let runtime = FinalTaskRuntime::new(
        store.clone(),
        FinalTaskRuntimeConfig::new(60_000, Some(1_000)).expect("finite final Tasks policy"),
        Arc::new(move |_| {
            notification_counter.fetch_add(1, Ordering::SeqCst);
        }),
    );
    let (input_required_tx, input_required_rx) = mpsc::sync_channel(1);
    let (cancelled_tx, cancelled_rx) = mpsc::sync_channel(1);
    let runner = runtime
        .install_task_service(
            1,
            Arc::new(E2eFinalTaskSupervisor {
                input_required: input_required_tx,
                cancelled: cancelled_tx,
            }),
        )
        .expect("application-owned final Task service installs");

    let task_handler_calls = Arc::new(AtomicUsize::new(0));
    let server = auto::server_builder("final-tasks-e2e", "1.0.0")
        .tool(PublicFinalTaskTool {
            calls: Arc::clone(&task_handler_calls),
        })
        .final_tasks(runtime.clone())
        .expect("official final Tasks extension installs through the public facade")
        .build();
    let fixture = FinalTasksHttpFixture::spawn(server, runner);
    let cx = Cx::for_request();
    let admitted_request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": modern::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {
                    "extensions": {"io.modelcontextprotocol/tasks": {}}
                },
            },
            "name": "public-final-task",
            "arguments": {},
        },
    });
    let mut missing_capability = admitted_request.clone();
    missing_capability["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
    let (status, missing_capability_response) =
        final_tasks_native_http_post(fixture.address, "public-final-task", &missing_capability);
    assert_eq!(
        status, 400,
        "the native HTTP boundary maps missing Tasks capability to its canonical refusal"
    );
    assert!(
        missing_capability_response
            .as_ref()
            .and_then(|response| response.get("error"))
            .is_some(),
        "changing only the Tasks capability rejects task creation"
    );
    assert_eq!(
        task_handler_calls.load(Ordering::SeqCst),
        0,
        "missing Tasks capability rejects before the task-capable handler"
    );
    assert_eq!(
        store.task_count(),
        0,
        "rejected capability preserves the task store"
    );
    assert_eq!(
        delivered_notifications.load(Ordering::SeqCst),
        0,
        "rejected capability emits no task notification"
    );

    let (status, _) =
        final_tasks_native_http_post(fixture.address, "other-task", &admitted_request);
    assert_eq!(
        status, 400,
        "changing only Mcp-Name rejects before final dispatch"
    );
    assert_eq!(
        task_handler_calls.load(Ordering::SeqCst),
        0,
        "Mcp-Name rejection does not invoke the task-capable handler"
    );
    assert_eq!(
        store.task_count(),
        0,
        "Mcp-Name rejection preserves the task store"
    );
    assert_eq!(
        delivered_notifications.load(Ordering::SeqCst),
        0,
        "Mcp-Name rejection emits no task notification"
    );

    let modern_builder = auto::client_builder()
        .client_info("final-tasks-e2e-client", "1.0.0")
        .protocol_plan(fixture.plan(ProtocolPolicy::ModernOnly));
    let modern =
        final_tasks_runtime_block_on_bounded(&cx, modern_builder.connect_http_client_with_cx(&cx))
            .expect("public HTTP facade selects the final protocol");

    let created = final_tasks_runtime_block_on_bounded(
        &cx,
        modern.connection().call_tool_final_outcome(
            &cx,
            RequestId::Number(2),
            "public-final-task",
            json!({}),
            1 << 20,
        ),
    )
    .expect("public final tools/call creates a task");
    let FinalToolCallOutcome::Task(created) = created else {
        panic!("the task-capable final tool must return the task result branch");
    };
    let task_id = created.task.base().task_id.clone();
    assert!(matches!(created.task, FinalTask::Working(_)));
    assert_eq!(task_handler_calls.load(Ordering::SeqCst), 1);

    input_required_rx
        .recv_timeout(FINAL_TASKS_E2E_BOUND)
        .expect("the live supervisor moves the task to input_required within its bound");
    let input_required = final_tasks_runtime_block_on_bounded(
        &cx,
        modern
            .connection()
            .get_task_final(&cx, RequestId::Number(4), task_id.clone(), 1 << 20),
    )
    .expect("official tasks/get observes input_required");
    assert!(matches!(
        input_required.task,
        FinalTask::InputRequired { .. }
    ));

    let modern_endpoint = CanonicalHttpUrl::parse(&format!("http://{}/mcp", fixture.address))
        .expect("public modern final Tasks endpoint is canonical");
    let mut task_watcher_client = final_tasks_runtime_block_on_bounded(
        &cx,
        modern::client_builder()
            .client_info("final-tasks-watch-client", "1.0.0")
            .connect_http_with_cx(modern_endpoint, &cx),
    )
    .expect("modern facade connects to the real final Tasks listener");
    let mut task_handle = final_tasks_runtime_block_on_bounded(
        &cx,
        task_watcher_client.attach_final_task(&cx, task_id.clone()),
    )
    .expect("modern facade attaches the exact input-required task");
    let mut task_watch = final_tasks_runtime_block_on_bounded(
        &cx,
        task_watcher_client.watch_final_task(
            &cx,
            &mut task_handle,
            SseLimits::new(1_024, 8_192, 16).expect("bounded final Tasks SSE limits"),
        ),
    )
    .expect("modern facade opens one live task subscription");
    assert!(matches!(
        final_tasks_runtime_block_on_bounded(&cx, task_watch.next_event(&cx))
            .expect("live task subscription acknowledgement is admitted"),
        Some(FinalTaskWatchEvent::Acknowledged { .. })
    ));

    let responses: FinalTaskInputResponses =
        serde_json::from_value(json!({"roots": {"roots": []}}))
            .expect("the public final roots response is typed");
    final_tasks_runtime_block_on_bounded(
        &cx,
        modern.connection().update_task_final(
            &cx,
            RequestId::Number(5),
            &input_required.task,
            responses,
            1 << 20,
        ),
    )
    .expect("official tasks/update accepts matching typed input");
    let task_notification = final_tasks_runtime_block_on_bounded(&cx, task_watch.next_event(&cx))
        .expect("live task subscription observes the post-update status");
    assert!(matches!(
        task_notification,
        Some(FinalTaskWatchEvent::TaskUpdated(ref notification))
            if matches!(&notification.params.task, FinalTask::Working(_))
    ));
    drop(task_watch);
    let resumed = final_tasks_runtime_block_on_bounded(
        &cx,
        modern
            .connection()
            .get_task_final(&cx, RequestId::Number(6), task_id.clone(), 1 << 20),
    )
    .expect("official tasks/get observes the resumed working task");
    assert!(matches!(resumed.task, FinalTask::Working(_)));

    final_tasks_runtime_block_on_bounded(
        &cx,
        modern
            .connection()
            .cancel_task_final(&cx, RequestId::Number(7), task_id.clone(), 1 << 20),
    )
    .expect("official tasks/cancel acknowledges the cancellation intent");
    cancelled_rx
        .recv_timeout(FINAL_TASKS_E2E_BOUND)
        .expect("the live supervisor honors cancellation within its bound");
    let cancelled = final_tasks_runtime_block_on_bounded(
        &cx,
        modern
            .connection()
            .get_task_final(&cx, RequestId::Number(8), task_id.clone(), 1 << 20),
    )
    .expect("official tasks/get returns the cancelled task");
    assert!(matches!(cancelled.task, FinalTask::Cancelled(_)));

    let legacy_builder = auto::client_builder()
        .client_info("final-tasks-e2e-client", "1.0.0")
        .protocol_plan(fixture.plan(ProtocolPolicy::LegacyOnly));
    let legacy =
        final_tasks_runtime_block_on_bounded(&cx, legacy_builder.connect_http_client_with_cx(&cx))
            .expect("the real facade server retains its exact legacy route");
    let legacy_error = final_tasks_runtime_block_on_bounded(
        &cx,
        legacy
            .connection()
            .get_task_final(&cx, RequestId::Number(8), task_id, 1 << 20),
    )
    .expect_err("exact legacy selection rejects the official final Tasks method");
    assert!(matches!(
        legacy_error,
        ClientHttpConnectionError::FinalTasksRequiresModern { .. }
    ));

    drop(legacy);
    drop(modern);
    drop(task_handle);
    drop(task_watcher_client);
    fixture.shutdown();
}

struct HoldingInitialTaskSupervisor;

impl ApplicationTaskSupervisor for HoldingInitialTaskSupervisor {
    fn resume<'a>(
        &'a self,
        cx: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
        Box::pin(async move {
            // Keep the first server's claim live until its caller-owned
            // service context is cancelled. The runner then returns the
            // durable work to the retained store for the reconstructed server.
            let _handoff = handoff;
            loop {
                cx.checkpoint()
                    .map_err(|error| McpError::internal_error(error.to_string()))?;
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
        })
    }
}

#[test]
fn workflow_final_tasks_public_facade_rebuild_recovers_retained_work() {
    let store = Arc::new(InMemoryFinalTaskStore::new(8).expect("bounded retained task store"));
    let policy = FinalTaskRuntimeConfig::new(60_000, Some(1_000))
        .expect("finite retained final Tasks policy");
    let first_runtime = FinalTaskRuntime::new(store.clone(), policy.clone(), Arc::new(|_| {}));
    let first_runner = first_runtime
        .install_task_service(1, Arc::new(HoldingInitialTaskSupervisor))
        .expect("first caller-owned service installs");
    let first_server = auto::server_builder("final-tasks-rebuild-a", "1.0.0")
        .tool(PublicFinalTaskTool {
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .final_tasks(first_runtime)
        .expect("first public facade server installs final Tasks")
        .build();
    let first_fixture = FinalTasksHttpFixture::spawn(first_server, first_runner);
    let cx = Cx::for_request();
    let first_client = final_tasks_runtime_block_on_bounded(
        &cx,
        auto::client_builder()
            .client_info("final-tasks-rebuild-client", "1.0.0")
            .protocol_plan(first_fixture.plan(ProtocolPolicy::ModernOnly))
            .connect_http_client_with_cx(&cx),
    )
    .expect("first public facade client discovers final Tasks");
    let created = final_tasks_runtime_block_on_bounded(
        &cx,
        first_client.connection().call_tool_final_outcome(
            &cx,
            RequestId::Number(2),
            "public-final-task",
            json!({}),
            1 << 20,
        ),
    )
    .expect("first facade server durably creates the task before caller-owned service shutdown");
    let FinalToolCallOutcome::Task(created) = created else {
        panic!("first public facade call returns the final Task branch");
    };
    let task_id = created.task.base().task_id.clone();
    assert_eq!(
        store.task_count(),
        1,
        "the retained application store owns the task"
    );
    drop(first_client);
    first_fixture.shutdown();

    let (input_required_tx, input_required_rx) = mpsc::sync_channel(1);
    let (cancelled_tx, _cancelled_rx) = mpsc::sync_channel(1);
    let recovered_runtime = FinalTaskRuntime::new(store.clone(), policy, Arc::new(|_| {}));
    let recovered_runner = recovered_runtime
        .install_task_service(
            1,
            Arc::new(E2eFinalTaskSupervisor {
                input_required: input_required_tx,
                cancelled: cancelled_tx,
            }),
        )
        .expect("reconstructed caller-owned service installs");
    let recovered_server = auto::server_builder("final-tasks-rebuild-b", "1.0.0")
        .tool(PublicFinalTaskTool {
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .final_tasks(recovered_runtime)
        .expect("reconstructed public facade server installs final Tasks")
        .build();
    let recovered_fixture = FinalTasksHttpFixture::spawn(recovered_server, recovered_runner);
    input_required_rx
        .recv_timeout(FINAL_TASKS_E2E_BOUND)
        .expect("reconstructed service recovers the retained initial work");
    let recovered_client = final_tasks_runtime_block_on_bounded(
        &cx,
        auto::client_builder()
            .client_info("final-tasks-rebuild-client", "1.0.0")
            .protocol_plan(recovered_fixture.plan(ProtocolPolicy::ModernOnly))
            .connect_http_client_with_cx(&cx),
    )
    .expect("reconstructed public facade client discovers final Tasks");
    let recovered = final_tasks_runtime_block_on_bounded(
        &cx,
        recovered_client
            .connection()
            .get_task_final(&cx, RequestId::Number(4), task_id, 1 << 20),
    )
    .expect("reconstructed public facade server reads the retained task");
    assert!(matches!(recovered.task, FinalTask::InputRequired { .. }));
    assert_eq!(
        store.task_count(),
        1,
        "reconstructed server preserves the one retained task without duplication"
    );
    drop(recovered_client);
    recovered_fixture.shutdown();
}

struct LegacyTasksIsolationTool {
    calls: Arc<AtomicUsize>,
}

impl ToolHandler for LegacyTasksIsolationTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "legacy-task-isolation-tool".to_owned(),
            description: Some("proves exact legacy Tasks isolation".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![Content::text("exact legacy tool")])
    }
}

#[test]
fn workflow_exact_legacy_facade_rejects_final_tasks_without_mutation() {
    let cx = Cx::for_testing();
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let mut harness = LifecycleThreadHarness::spawn(&cx, move |cx, transport| {
        legacy_2024::server_builder("legacy-tasks-isolation", "1.0.0")
            .tool(LegacyTasksIsolationTool {
                calls: handler_calls,
            })
            .build()
            .run_transport_returning_with_cx(cx, transport)
    });
    assert_lifecycle_opening(
        harness.peer_mut(),
        &cx,
        "exact legacy Tasks isolation",
        "legacy-tasks-isolation",
        lifecycle_legacy_opening(1),
        false,
    );
    harness
        .peer_mut()
        .send(
            &cx,
            &JsonRpcMessage::Request(JsonRpcRequest::initialized_notification()),
        )
        .expect("send exact-2024 initialized before the legacy Tasks rejection");
    harness
        .peer_mut()
        .send(
            &cx,
            &JsonRpcMessage::Request(JsonRpcRequest::new(
                "tasks/get",
                Some(json!({"taskId": "legacy-forbidden-task"})),
                2_i64,
            )),
        )
        .expect("send the exact final Tasks RPC to the legacy facade server");
    let response = lifecycle_response(harness.peer_mut(), &cx, 2, "legacy Tasks refusal");
    let error = response
        .error
        .expect("exact legacy Tasks RPC must receive a refusal");
    assert_eq!(
        error.code.as_i32(),
        Some(McpErrorCode::MethodNotFound.into())
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "exact legacy Tasks rejection does not reach an application handler"
    );
    harness.peer.take();
    harness
        .settle("exact legacy Tasks isolation")
        .expect("exact legacy server settles after the peer closes");
}

#[test]
fn workflow_public_http_state_only_mrtr_rejects_explicit_empty_without_consuming_state() {
    // Reuse the existing bounded HTTP fixture's idle service owner. This
    // server deliberately exposes no Tasks capability; the service is only
    // responsible for the fixture lifecycle while MRTR remains ordinary
    // final-core transport state.
    let runtime = FinalTaskRuntime::in_memory(
        FinalTaskRuntimeConfig::new(60_000, Some(1_000)).expect("finite fixture task policy"),
        Arc::new(|_| {}),
    );
    let (input_required, _input_required_observer) = mpsc::sync_channel::<()>(1);
    let (cancelled, _cancelled_observer) = mpsc::sync_channel::<()>(1);
    let runner = runtime
        .install_task_service(
            1,
            Arc::new(E2eFinalTaskSupervisor {
                input_required,
                cancelled,
            }),
        )
        .expect("bounded fixture service installs");
    let initial_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let resumed_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server = auto::server_builder("public-state-only-mrtr", "1.0.0")
        .tool(PublicStateOnlyMrtrTool {
            initial_calls: Arc::clone(&initial_calls),
            resumed_calls: Arc::clone(&resumed_calls),
        })
        .build();
    let fixture = FinalTasksHttpFixture::spawn(server, runner);
    let cx = Cx::for_request();
    let mut client = final_tasks_runtime_block_on_bounded(
        &cx,
        auto::client_builder()
            .client_info("public-state-only-mrtr-client", "1.0.0")
            .protocol_plan(fixture.plan(ProtocolPolicy::ModernOnly))
            .connect_http_client_with_cx(&cx),
    )
    .expect("public HTTP client selects the live modern server");

    let initial = final_tasks_runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "tools/call",
            json!({ "name": "public-state-only-mrtr", "arguments": {} }),
        ),
    )
    .expect("the live server issues a state-only continuation");
    let CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { result, .. }) = initial else {
        panic!("the initial public HTTP result is state-only input_required");
    };
    assert!(
        result.input_requests().is_none(),
        "the real server omits inputRequests rather than manufacturing an empty map"
    );
    let request_state = result
        .request_state()
        .expect("the real state-only result carries framework-issued state")
        .to_owned();

    let explicit_empty = final_tasks_runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "tools/call",
            json!({
                "name": "public-state-only-mrtr",
                "arguments": {},
                "inputResponses": {},
                "requestState": request_state,
            }),
        ),
    )
    .expect_err("only adding an explicit empty response map must reject");
    let auto::HttpClientError::CoreResult(explicit_empty) = explicit_empty else {
        panic!("the live server rejection remains a public core error");
    };
    assert_eq!(explicit_empty.code, McpErrorCode::InvalidParams);
    assert_eq!(
        explicit_empty.message, "Invalid MRTR input request or response map",
        "the explicit empty map reaches the server's state-only continuation admission"
    );
    assert_eq!(initial_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(resumed_calls.load(std::sync::atomic::Ordering::SeqCst), 0);

    let completed = final_tasks_runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "tools/call",
            json!({
                "name": "public-state-only-mrtr",
                "arguments": {},
                "requestState": request_state,
            }),
        ),
    )
    .expect("the unchanged absent-member retry consumes the retained continuation");
    assert!(matches!(
        completed,
        CoreResult::Final(FinalCoreResult::ToolsCall { .. })
    ));
    assert_eq!(initial_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(resumed_calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    let mut callback_count = 0;
    let automatic = final_tasks_runtime_block_on_bounded(
        &cx,
        client.call_tool_with_mrtr_retry(
            &cx,
            Instant::now() + FINAL_TASKS_E2E_BOUND,
            "public-state-only-mrtr",
            json!({}),
            SseLimits::new(1_024, 8_192, 8).expect("bounded state-only SSE limits"),
            1 << 20,
            |input_required| {
                callback_count += 1;
                assert!(input_required.input_requests().is_none());
                assert!(input_required.request_state().is_some());
                Ok(BTreeMap::new())
            },
        ),
    )
    .expect("the public MRTR helper sends the state-only retry without inputResponses");
    assert!(matches!(automatic, FinalCoreResult::ToolsCall { .. }));
    assert_eq!(callback_count, 1);
    assert_eq!(initial_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(resumed_calls.load(std::sync::atomic::Ordering::SeqCst), 2);

    fixture.shutdown();
}

#[test]
fn workflow_public_http_resource_and_prompt_mrtr_preserve_typed_state_and_bounds() {
    let runtime = FinalTaskRuntime::in_memory(
        FinalTaskRuntimeConfig::new(60_000, Some(1_000)).expect("finite fixture task policy"),
        Arc::new(|_| {}),
    );
    let (input_required, _input_required_observer) = mpsc::sync_channel::<()>(1);
    let (cancelled, _cancelled_observer) = mpsc::sync_channel::<()>(1);
    let runner = runtime
        .install_task_service(
            1,
            Arc::new(E2eFinalTaskSupervisor {
                input_required,
                cancelled,
            }),
        )
        .expect("bounded fixture service installs");

    let resource_initial = Arc::new(AtomicUsize::new(0));
    let resource_resumed = Arc::new(AtomicUsize::new(0));
    let resource_legacy = Arc::new(AtomicUsize::new(0));
    let round_initial = Arc::new(AtomicUsize::new(0));
    let round_resumed = Arc::new(AtomicUsize::new(0));
    let prompt_initial = Arc::new(AtomicUsize::new(0));
    let prompt_resumed = Arc::new(AtomicUsize::new(0));
    let prompt_legacy = Arc::new(AtomicUsize::new(0));
    let server = auto::server_builder("public-resource-prompt-mrtr", "1.0.0")
        .resource(PublicTypedMrtrResource {
            uri: "file:///public-typed-mrtr-resource",
            name: "public-typed-mrtr-resource",
            initial_calls: Arc::clone(&resource_initial),
            resumed_calls: Arc::clone(&resource_resumed),
            legacy_calls: Arc::clone(&resource_legacy),
            input_required_after_resume: Arc::new(AtomicUsize::new(0)),
        })
        .resource(PublicTypedMrtrResource {
            uri: "file:///public-round-bound-mrtr-resource",
            name: "public-round-bound-mrtr-resource",
            initial_calls: Arc::clone(&round_initial),
            resumed_calls: Arc::clone(&round_resumed),
            legacy_calls: Arc::new(AtomicUsize::new(0)),
            input_required_after_resume: Arc::new(AtomicUsize::new(MAX_MRTR_CONTINUATION_ROUNDS)),
        })
        .prompt(PublicTypedMrtrPrompt {
            initial_calls: Arc::clone(&prompt_initial),
            resumed_calls: Arc::clone(&prompt_resumed),
            legacy_calls: Arc::clone(&prompt_legacy),
        })
        .build();
    let fixture = FinalTasksHttpFixture::spawn(server, runner);
    let cx = Cx::for_request();
    let mut client = final_tasks_runtime_block_on_bounded(
        &cx,
        auto::client_builder()
            .client_info("public-resource-prompt-mrtr-client", "1.0.0")
            .protocol_plan(fixture.plan(ProtocolPolicy::ModernOnly))
            .connect_http_client_with_cx(&cx),
    )
    .expect("public HTTP client selects the live modern server");

    let resource_initial_result = final_tasks_runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "resources/read",
            json!({"uri": "file:///public-typed-mrtr-resource"}),
        ),
    )
    .expect("modern resource handler emits typed input_required");
    let CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { result, .. }) =
        resource_initial_result
    else {
        panic!("public resource result remains a typed input_required result");
    };
    let resource_state = result
        .request_state()
        .expect("framework issues public resource retry state")
        .to_owned();
    assert_ne!(resource_state, "handler-forged-resource-prompt-state");
    assert!(
        result
            .input_requests()
            .and_then(|requests| requests.get("roots"))
            .is_some(),
        "public resource input_required retains the typed roots descriptor"
    );

    let bad_resource_state = final_tasks_runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "resources/read",
            json!({
                "uri": "file:///public-typed-mrtr-resource",
                "inputResponses": {"roots": {"roots": []}},
                "requestState": format!("{resource_state}-bad"),
            }),
        ),
    )
    .expect_err("changing only resource requestState rejects without consuming the exchange");
    let auto::HttpClientError::CoreResult(bad_resource_state) = bad_resource_state else {
        panic!("resource requestState rejection remains a public core error");
    };
    assert_eq!(bad_resource_state.code, McpErrorCode::InvalidParams);
    assert_eq!(resource_initial.load(Ordering::SeqCst), 1);
    assert_eq!(resource_resumed.load(Ordering::SeqCst), 0);

    let resource_complete = final_tasks_runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "resources/read",
            json!({
                "uri": "file:///public-typed-mrtr-resource",
                "inputResponses": {"roots": {"roots": []}},
                "requestState": resource_state,
            }),
        ),
    )
    .expect("same-session resource retry consumes the retained typed exchange");
    let CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. }) = resource_complete else {
        panic!("resource continuation returns FinalReadResourceResult");
    };
    let FinalReadResourceResult {
        contents,
        ttl_ms,
        cache_scope,
    } = result.payload;
    assert!(contents.is_empty());
    assert_eq!(ttl_ms, CacheTtl::milliseconds(17));
    assert_eq!(cache_scope, CacheScope::Private);
    assert_eq!(resource_initial.load(Ordering::SeqCst), 1);
    assert_eq!(resource_resumed.load(Ordering::SeqCst), 1);
    assert_eq!(resource_legacy.load(Ordering::SeqCst), 0);

    let prompt_initial_result = final_tasks_runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "prompts/get",
            json!({"name": "public-typed-mrtr-prompt", "arguments": {}}),
        ),
    )
    .expect("modern prompt handler emits typed input_required");
    let CoreResult::Final(FinalCoreResult::PromptsGetInputRequired { result, .. }) =
        prompt_initial_result
    else {
        panic!("public prompt result remains a typed input_required result");
    };
    let prompt_state = result
        .request_state()
        .expect("framework issues public prompt retry state")
        .to_owned();

    let bad_prompt_inputs = final_tasks_runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "prompts/get",
            json!({
                "name": "public-typed-mrtr-prompt",
                "arguments": {},
                "inputResponses": {"not-roots": {"roots": []}},
                "requestState": prompt_state,
            }),
        ),
    )
    .expect_err("changing only prompt inputResponses rejects without consuming the exchange");
    let auto::HttpClientError::CoreResult(bad_prompt_inputs) = bad_prompt_inputs else {
        panic!("prompt inputResponses rejection remains a public core error");
    };
    assert_eq!(bad_prompt_inputs.code, McpErrorCode::InvalidParams);
    assert_eq!(prompt_initial.load(Ordering::SeqCst), 1);
    assert_eq!(prompt_resumed.load(Ordering::SeqCst), 0);

    let prompt_complete = final_tasks_runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "prompts/get",
            json!({
                "name": "public-typed-mrtr-prompt",
                "arguments": {},
                "inputResponses": {"roots": {"roots": []}},
                "requestState": prompt_state,
            }),
        ),
    )
    .expect("same-session prompt retry consumes the retained typed exchange");
    let CoreResult::Final(FinalCoreResult::PromptsGet { result, .. }) = prompt_complete else {
        panic!("prompt continuation returns FinalGetPromptResult");
    };
    let FinalGetPromptResult {
        description,
        messages,
    } = result.payload;
    assert_eq!(description.as_deref(), Some("exact final prompt result"));
    assert!(matches!(
        messages.as_slice(),
        [FinalPromptMessage {
            role: Role::Assistant,
            content: ContentBlock::Text { text, .. },
        }] if text == "exact final prompt content"
    ));
    assert_eq!(prompt_initial.load(Ordering::SeqCst), 1);
    assert_eq!(prompt_resumed.load(Ordering::SeqCst), 1);
    assert_eq!(prompt_legacy.load(Ordering::SeqCst), 0);

    let mut oversized_state = None;
    let oversized = final_tasks_runtime_block_on_bounded(
        &cx,
        client.read_resource_with_mrtr_retry(
            &cx,
            Instant::now() + FINAL_TASKS_E2E_BOUND,
            "file:///public-typed-mrtr-resource",
            SseLimits::new(1_024, 8_192, 8).expect("bounded resource MRTR SSE limits"),
            1 << 20,
            |input_required| {
                oversized_state = input_required.request_state().map(str::to_owned);
                Ok((0..=MAX_MRTR_INPUT_RESPONSES)
                    .map(|index| (format!("roots-{index}"), json!({"roots": []})))
                    .collect())
            },
        ),
    )
    .expect_err("shared client input-response bound rejects before a retry POST");
    assert!(
        oversized
            .to_string()
            .contains("inputResponses must not exceed")
    );
    assert_eq!(resource_initial.load(Ordering::SeqCst), 2);
    assert_eq!(resource_resumed.load(Ordering::SeqCst), 1);
    let oversized_state = oversized_state.expect("bounded input rejection retains issued state");

    let retained_after_input_bound = final_tasks_runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "resources/read",
            json!({
                "uri": "file:///public-typed-mrtr-resource",
                "inputResponses": {"roots": {"roots": []}},
                "requestState": oversized_state,
            }),
        ),
    )
    .expect("input-bound rejection preserves the issued resource exchange");
    assert!(matches!(
        retained_after_input_bound,
        CoreResult::Final(FinalCoreResult::ResourcesRead { .. })
    ));
    assert_eq!(resource_resumed.load(Ordering::SeqCst), 2);

    let mut round_callbacks = 0;
    let round_bound = final_tasks_runtime_block_on_bounded(
        &cx,
        client.read_resource_with_mrtr_retry(
            &cx,
            Instant::now() + FINAL_TASKS_E2E_BOUND,
            "file:///public-round-bound-mrtr-resource",
            SseLimits::new(1_024, 8_192, 8).expect("bounded round-limit SSE limits"),
            1 << 20,
            |_| {
                round_callbacks += 1;
                Ok(BTreeMap::from([("roots".to_owned(), json!({"roots": []}))]))
            },
        ),
    )
    .expect_err("shared client round bound stops before a fifth response callback");
    assert!(
        round_bound
            .to_string()
            .contains("continuation-round limit exceeded")
    );
    assert_eq!(round_callbacks, MAX_MRTR_CONTINUATION_ROUNDS);
    assert_eq!(round_initial.load(Ordering::SeqCst), 1);
    assert_eq!(
        round_resumed.load(Ordering::SeqCst),
        MAX_MRTR_CONTINUATION_ROUNDS,
        "the shared driver never dispatches a fifth continuation"
    );

    let cancelled_cx = Cx::for_request();
    cancelled_cx.set_cancel_requested(true);
    let cancelled = final_tasks_runtime_block_on_bounded(
        &cx,
        client.get_prompt_with_mrtr_retry(
            &cancelled_cx,
            Instant::now() + FINAL_TASKS_E2E_BOUND,
            "public-typed-mrtr-prompt",
            HashMap::new(),
            SseLimits::new(1_024, 8_192, 8).expect("bounded cancellation SSE limits"),
            1 << 20,
            |_| Ok(BTreeMap::from([("roots".to_owned(), json!({"roots": []}))])),
        ),
    )
    .expect_err("a cancelled caller context cannot dispatch more prompt MRTR work");
    assert!(cancelled.to_string().contains("cancel"));
    assert_eq!(prompt_initial.load(Ordering::SeqCst), 1);
    assert_eq!(prompt_resumed.load(Ordering::SeqCst), 1);

    let mut legacy = final_tasks_runtime_block_on_bounded(
        &cx,
        auto::client_builder()
            .client_info("public-resource-prompt-mrtr-legacy-client", "1.0.0")
            .protocol_plan(fixture.plan(ProtocolPolicy::LegacyOnly))
            .connect_http_client_with_cx(&cx),
    )
    .expect("the fixture retains its exact legacy HTTP route");
    let legacy_resource = final_tasks_runtime_block_on_bounded(
        &cx,
        legacy.read_resource_with_mrtr_retry(
            &cx,
            Instant::now() + FINAL_TASKS_E2E_BOUND,
            "file:///public-typed-mrtr-resource",
            SseLimits::new(1_024, 8_192, 8).expect("bounded legacy resource SSE limits"),
            1 << 20,
            |_| Ok(BTreeMap::from([("roots".to_owned(), json!({"roots": []}))])),
        ),
    )
    .expect_err("exact legacy selection rejects public resource MRTR before dispatch");
    assert!(matches!(
        legacy_resource,
        auto::HttpClientError::Connection(ClientHttpConnectionError::MrtrRequiresModern)
    ));
    let legacy_prompt = final_tasks_runtime_block_on_bounded(
        &cx,
        legacy.get_prompt_with_mrtr_retry(
            &cx,
            Instant::now() + FINAL_TASKS_E2E_BOUND,
            "public-typed-mrtr-prompt",
            HashMap::new(),
            SseLimits::new(1_024, 8_192, 8).expect("bounded legacy prompt SSE limits"),
            1 << 20,
            |_| Ok(BTreeMap::from([("roots".to_owned(), json!({"roots": []}))])),
        ),
    )
    .expect_err("exact legacy selection rejects public prompt MRTR before dispatch");
    assert!(matches!(
        legacy_prompt,
        auto::HttpClientError::Connection(ClientHttpConnectionError::MrtrRequiresModern)
    ));
    assert_eq!(
        resource_legacy.load(Ordering::SeqCst),
        0,
        "exact legacy resource MRTR rejection must not enter the legacy resource handler"
    );
    assert_eq!(
        prompt_legacy.load(Ordering::SeqCst),
        0,
        "exact legacy prompt MRTR rejection must not enter the legacy prompt handler"
    );
    assert_eq!(resource_initial.load(Ordering::SeqCst), 2);
    assert_eq!(resource_resumed.load(Ordering::SeqCst), 2);
    assert_eq!(prompt_initial.load(Ordering::SeqCst), 1);
    assert_eq!(prompt_resumed.load(Ordering::SeqCst), 1);

    drop(legacy);
    fixture.shutdown();
}

// ============================================================================
// Multiple Concurrent Clients E2E Tests (bd-1s1)
// ============================================================================

/// Tool that stores a value in session state and returns it.
struct SessionStoreHandler;

impl ToolHandler for SessionStoreHandler {
    fn definition(&self) -> Tool {
        Tool {
            name: "session_store".to_string(),
            description: Some("Store and retrieve a value in session state".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string" },
                    "value": { "type": "string" }
                },
                "required": ["key", "value"]
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let key = arguments["key"].as_str().unwrap_or("default").to_string();
        let value = arguments["value"].as_str().unwrap_or("").to_string();

        // Store value in session state
        ctx.set_state(&key, value.clone());

        Ok(vec![Content::Text {
            text: format!("Stored: {key}={value}"),
        }])
    }
}

/// Tool that retrieves a value from session state.
struct SessionGetHandler;

impl ToolHandler for SessionGetHandler {
    fn definition(&self) -> Tool {
        Tool {
            name: "session_get".to_string(),
            description: Some("Get a value from session state".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string" }
                },
                "required": ["key"]
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let key = arguments["key"].as_str().unwrap_or("default");

        let value: Option<String> = ctx.get_state(key);
        let result = value.unwrap_or_else(|| "NOT_FOUND".to_string());

        Ok(vec![Content::Text { text: result }])
    }
}

#[test]
fn workflow_concurrent_clients_isolation() {
    use fastmcp_transport::memory::create_memory_transport_pair;

    // Create multiple client-server transport pairs
    let mut server_joins = ThreadJoins::new(Vec::new());
    let mut clients_and_servers = Vec::new();

    for client_num in 0..3 {
        let (client_transport, server_transport) = create_memory_transport_pair();

        let server = Server::new("concurrent-server", "1.0.0")
            .tool(EchoTool)
            .tool(SessionStoreHandler)
            .tool(SessionGetHandler)
            .build();

        // Spawn server thread
        let handle = spawn_thread(move || {
            let cx = Cx::for_testing();
            server.run_transport_with_cx(&cx, server_transport);
        });
        server_joins.push(handle);

        let client = TestClient::new(client_transport)
            .with_client_info(format!("client-{}", client_num), "1.0.0");

        clients_and_servers.push((client_num, client));
    }

    // Initialize all clients
    for (_num, client) in &mut clients_and_servers {
        client.initialize().unwrap();
    }

    // Each client stores a unique value
    for (num, client) in &mut clients_and_servers {
        let result = client
            .call_tool(
                "session_store",
                json!({"key": "client_value", "value": format!("value_from_client_{}", num)}),
            )
            .unwrap();

        assert!(
            matches!(result.first(), Some(LegacyContent::Text { .. })),
            "expected text content"
        );
        let Some(LegacyContent::Text { text, .. }) = result.first() else {
            return;
        };
        assert!(text.contains(&format!("value_from_client_{}", num)));
    }

    // Each client retrieves its own stored value (should not see other clients' values)
    for (num, client) in &mut clients_and_servers {
        let result = client
            .call_tool("session_get", json!({"key": "client_value"}))
            .unwrap();

        assert!(
            matches!(result.first(), Some(LegacyContent::Text { .. })),
            "expected text content"
        );
        let Some(LegacyContent::Text { text, .. }) = result.first() else {
            return;
        };
        // Each client should see only its own value
        assert_eq!(
            text,
            &format!("value_from_client_{}", num),
            "Client {} should see its own value, not another client's",
            num
        );
    }

    drop(clients_and_servers);
    drop(server_joins);
}

#[test]
fn workflow_concurrent_interleaved_operations() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let operation_counter = Arc::new(AtomicUsize::new(0));
    let mut workers = WorkerJoins::new();

    for client_num in 0..4 {
        let counter = Arc::clone(&operation_counter);

        let handle = spawn_thread(move || {
            let (client_transport, server_transport) = create_memory_transport_pair();

            let server = Server::new("interleaved-server", "1.0.0")
                .tool(EchoTool)
                .build();

            let server_handle = spawn_thread(move || {
                let cx = Cx::for_testing();
                server.run_transport_with_cx(&cx, server_transport);
            });
            let _server_join = ThreadJoins::new(vec![server_handle]);

            let mut client = TestClient::new(client_transport)
                .with_client_info(format!("client-{}", client_num), "1.0.0");

            client.initialize().unwrap();

            // Perform multiple operations
            for op in 0..5 {
                let op_num = counter.fetch_add(1, Ordering::SeqCst);
                let result = client
                    .call_tool(
                        "echo",
                        json!({"message": format!("client_{}_op_{}", client_num, op)}),
                    )
                    .unwrap();

                assert!(
                    matches!(result.first(), Some(LegacyContent::Text { .. })),
                    "expected text content"
                );
                let Some(LegacyContent::Text { text, .. }) = result.first() else {
                    std::panic::panic_any("expected text content".to_string());
                };
                assert!(
                    text.contains(&format!("client_{}_op_{}", client_num, op)),
                    "Operation {} result mismatch",
                    op_num
                );
            }

            client_num
        });

        workers.push(handle);
    }

    // Wait for all threads to complete
    let completed_clients = workers.join_all("interleaved client worker");

    // Verify all clients completed
    assert_eq!(completed_clients.len(), 4);

    // Verify total operations (4 clients * 5 ops = 20)
    assert_eq!(operation_counter.load(Ordering::SeqCst), 20);
}

#[test]
fn workflow_concurrent_no_crosstalk() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::sync::Mutex;
    use std::thread;

    let results = Arc::new(Mutex::new(Vec::new()));
    let mut workers = WorkerJoins::new();

    for client_num in 0..3 {
        let results = Arc::clone(&results);

        let handle = spawn_thread(move || {
            let (client_transport, server_transport) = create_memory_transport_pair();

            let server = Server::new("crosstalk-server", "1.0.0")
                .tool(SessionStoreHandler)
                .tool(SessionGetHandler)
                .build();

            let server_handle = spawn_thread(move || {
                let cx = Cx::for_testing();
                server.run_transport_with_cx(&cx, server_transport);
            });
            let _server_join = ThreadJoins::new(vec![server_handle]);

            let mut client = TestClient::new(client_transport);
            client.initialize().unwrap();

            // Store a per-client value (ensure no cross-talk).
            let value = format!("value_{}", client_num);
            client
                .call_tool("session_store", json!({"key": "value", "value": &value}))
                .unwrap();

            // Sleep briefly to allow interleaving
            thread::sleep(std::time::Duration::from_millis(10));

            // Retrieve and verify our value
            let result = client
                .call_tool("session_get", json!({"key": "value"}))
                .unwrap();

            assert!(
                matches!(result.first(), Some(LegacyContent::Text { .. })),
                "expected text content"
            );
            let Some(LegacyContent::Text { text, .. }) = result.first() else {
                return;
            };
            let retrieved = text.clone();

            results
                .lock()
                .unwrap()
                .push((client_num, value.clone(), retrieved));
        });

        workers.push(handle);
    }

    // Wait for all threads
    workers.join_all("crosstalk client worker");

    // Verify each client got its own value back
    let results = results.lock().unwrap();
    assert_eq!(results.len(), 3);

    for (client_num, expected, actual) in results.iter() {
        assert_eq!(
            expected, actual,
            "Client {} got wrong value: expected '{}', got '{}'",
            client_num, expected, actual
        );
    }
}

#[test]
fn workflow_concurrent_session_state_persistence() {
    use fastmcp_transport::memory::create_memory_transport_pair;

    // Test that session state persists across multiple calls within the same session
    let (client_transport, server_transport) = create_memory_transport_pair();

    let server = Server::new("persistence-server", "1.0.0")
        .tool(SessionStoreHandler)
        .tool(SessionGetHandler)
        .build();

    let server_handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server.run_transport_with_cx(&cx, server_transport);
    });
    let _server_join = ThreadJoins::new(vec![server_handle]);

    let mut client = TestClient::new(client_transport);
    client.initialize().unwrap();

    // Store multiple values
    for i in 0..5 {
        client
            .call_tool(
                "session_store",
                json!({"key": format!("key_{}", i), "value": format!("value_{}", i)}),
            )
            .unwrap();
    }

    // Retrieve all values
    for i in 0..5 {
        let result = client
            .call_tool("session_get", json!({"key": format!("key_{}", i)}))
            .unwrap();

        assert!(
            matches!(result.first(), Some(LegacyContent::Text { .. })),
            "expected text content"
        );
        let Some(LegacyContent::Text { text, .. }) = result.first() else {
            return;
        };
        assert_eq!(text, &format!("value_{}", i), "Key {} has wrong value", i);
    }

    // Verify non-existent key returns NOT_FOUND
    let result = client
        .call_tool("session_get", json!({"key": "nonexistent"}))
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert_eq!(text, "NOT_FOUND");
}

#[test]
fn workflow_concurrent_stress_test() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NUM_CLIENTS: usize = 5;
    const OPS_PER_CLIENT: usize = 10;

    let success_count = Arc::new(AtomicUsize::new(0));
    let mut workers = WorkerJoins::new();

    for client_num in 0..NUM_CLIENTS {
        let success = Arc::clone(&success_count);

        let handle = spawn_thread(move || {
            let (client_transport, server_transport) = create_memory_transport_pair();

            let server = Server::new("stress-server", "1.0.0")
                .tool(EchoTool)
                .tool(SessionStoreHandler)
                .tool(SessionGetHandler)
                .build();

            let server_handle = spawn_thread(move || {
                let cx = Cx::for_testing();
                server.run_transport_with_cx(&cx, server_transport);
            });
            let _server_join = ThreadJoins::new(vec![server_handle]);

            let mut client = TestClient::new(client_transport);
            if client.initialize().is_err() {
                return;
            }

            for op in 0..OPS_PER_CLIENT {
                // Alternate between different operations
                let result = match op % 3 {
                    0 => client.call_tool(
                        "echo",
                        json!({"message": format!("c{}op{}", client_num, op)}),
                    ),
                    1 => client.call_tool(
                        "session_store",
                        json!({"key": "k", "value": format!("v{}", op)}),
                    ),
                    _ => client.call_tool("session_get", json!({"key": "k"})),
                };

                if result.is_ok() {
                    success.fetch_add(1, Ordering::SeqCst);
                }
            }
        });

        workers.push(handle);
    }

    // Wait for all threads
    workers.join_all("stress client worker");

    // Verify most operations succeeded
    let total_success = success_count.load(Ordering::SeqCst);
    let expected_total = NUM_CLIENTS * OPS_PER_CLIENT;

    assert!(
        total_success >= expected_total * 90 / 100,
        "Expected at least 90% success rate, got {}/{}",
        total_success,
        expected_total
    );
}

// ============================================================================
// Client Session Management E2E Tests (bd-2ms)
// ============================================================================

#[test]
fn session_initialization_stores_server_info() {
    let mut client = setup_workflow_server();

    // Before initialization, no server info
    assert!(client.server_info().is_none());
    assert!(client.server_capabilities().is_none());
    assert!(client.protocol_version().is_none());
    assert!(!client.is_initialized());

    // Initialize
    let init_result = client.initialize().unwrap();

    // After initialization, all session info is available
    assert!(client.is_initialized());
    assert!(client.server_info().is_some());
    assert!(client.server_capabilities().is_some());
    assert!(client.protocol_version().is_some());

    // Verify the stored info matches what was returned
    let server_info = client.server_info().unwrap();
    assert_eq!(server_info.name, init_result.server_info.name);
    assert_eq!(server_info.version, init_result.server_info.version);
}

#[test]
fn session_capabilities_reflect_server_handlers() {
    use fastmcp_transport::memory::create_memory_transport_pair;

    // Server with only tools
    let (client_transport, server_transport) = create_memory_transport_pair();
    let server = Server::new("tools-only", "1.0.0").tool(EchoTool).build();
    let server_handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server.run_transport_with_cx(&cx, server_transport);
    });

    // Server with only resources
    let (client_transport2, server_transport2) = create_memory_transport_pair();
    let server2 = Server::new("resources-only", "1.0.0")
        .resource(StatusResource)
        .build();
    let server_handle2 = spawn_thread(move || {
        let cx = Cx::for_testing();
        server2.run_transport_with_cx(&cx, server_transport2);
    });

    // Server with only prompts
    let (client_transport3, server_transport3) = create_memory_transport_pair();
    let server3 = Server::new("prompts-only", "1.0.0")
        .prompt(HelpPromptPrompt)
        .build();
    let server_handle3 = spawn_thread(move || {
        let cx = Cx::for_testing();
        server3.run_transport_with_cx(&cx, server_transport3);
    });
    let _server_joins = ThreadJoins::new(vec![server_handle, server_handle2, server_handle3]);

    let mut client = TestClient::new(client_transport);
    client.initialize().unwrap();

    let caps = client.server_capabilities().unwrap();
    assert!(caps.tools.is_some());
    assert!(caps.resources.is_none());
    assert!(caps.prompts.is_none());

    let mut client2 = TestClient::new(client_transport2);
    client2.initialize().unwrap();

    let caps2 = client2.server_capabilities().unwrap();
    assert!(caps2.tools.is_none());
    assert!(caps2.resources.is_some());
    assert!(caps2.prompts.is_none());

    let mut client3 = TestClient::new(client_transport3);
    client3.initialize().unwrap();

    let caps3 = client3.server_capabilities().unwrap();
    assert!(caps3.tools.is_none());
    assert!(caps3.resources.is_none());
    assert!(caps3.prompts.is_some());
}

#[test]
fn session_protocol_version_negotiated() {
    let mut client = setup_workflow_server();
    let init_result = client.initialize().unwrap();

    // Protocol version should be set
    assert!(!init_result.protocol_version.is_empty());

    // Stored version should match returned version
    let stored_version = client.protocol_version().unwrap();
    assert_eq!(stored_version, init_result.protocol_version);
}

#[test]
fn session_operations_fail_before_init() {
    use fastmcp_transport::memory::create_memory_transport_pair;

    let (client_transport, server_transport) = create_memory_transport_pair();
    let server = Server::new("test-server", "1.0.0").tool(EchoTool).build();
    let server_handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server.run_transport_with_cx(&cx, server_transport);
    });
    let _server_join = ThreadJoins::new(vec![server_handle]);

    let mut client = TestClient::new(client_transport);

    // All operations should fail before initialization
    assert!(client.list_tools().is_err());
    assert!(client.list_resources().is_err());
    assert!(client.list_prompts().is_err());
    assert!(
        client
            .call_tool("echo", json!({"message": "test"}))
            .is_err()
    );
    assert!(client.read_resource("app://test").is_err());
}

#[test]
fn session_close_graceful() {
    use fastmcp_transport::memory::create_memory_transport_pair;

    let (client_transport, server_transport) = create_memory_transport_pair();
    let server = Server::new("close-test", "1.0.0").tool(EchoTool).build();
    let server_handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server.run_transport_with_cx(&cx, server_transport);
    });
    let _server_join = ThreadJoins::new(vec![server_handle]);

    let mut client = TestClient::new(client_transport);
    client.initialize().unwrap();

    // Perform some operations
    let result = client
        .call_tool("echo", json!({"message": "before close"}))
        .unwrap();
    assert!(!result.is_empty());

    // Close the client - this consumes it
    client.close();

    // Client is now consumed, no further operations possible
    // (This is enforced by Rust's ownership system - client is moved)
}

#[test]
fn session_state_isolated_per_client() {
    use fastmcp_transport::memory::create_memory_transport_pair;

    // Create two separate client-server pairs
    let (client_a_transport, server_a_transport) = create_memory_transport_pair();
    let (client_b_transport, server_b_transport) = create_memory_transport_pair();

    let server_a = Server::new("server-a", "1.0.0")
        .tool(SessionStoreHandler)
        .tool(SessionGetHandler)
        .build();

    let server_b = Server::new("server-b", "1.0.0")
        .tool(SessionStoreHandler)
        .tool(SessionGetHandler)
        .build();

    let server_a_handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server_a.run_transport_with_cx(&cx, server_a_transport);
    });
    let server_b_handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server_b.run_transport_with_cx(&cx, server_b_transport);
    });
    let _server_joins = ThreadJoins::new(vec![server_a_handle, server_b_handle]);

    let mut client_a = TestClient::new(client_a_transport);
    let mut client_b = TestClient::new(client_b_transport);

    client_a.initialize().unwrap();
    client_b.initialize().unwrap();

    // Store different values in each session
    client_a
        .call_tool(
            "session_store",
            json!({"key": "shared_key", "value": "value_a"}),
        )
        .unwrap();

    client_b
        .call_tool(
            "session_store",
            json!({"key": "shared_key", "value": "value_b"}),
        )
        .unwrap();

    // Each client retrieves only its own value
    let result_a = client_a
        .call_tool("session_get", json!({"key": "shared_key"}))
        .unwrap();

    let result_b = client_b
        .call_tool("session_get", json!({"key": "shared_key"}))
        .unwrap();

    assert!(
        matches!(
            (&result_a[0], &result_b[0]),
            (LegacyContent::Text { .. }, LegacyContent::Text { .. })
        ),
        "expected text content"
    );
    let (LegacyContent::Text { text: text_a, .. }, LegacyContent::Text { text: text_b, .. }) =
        (&result_a[0], &result_b[0])
    else {
        return;
    };
    assert_eq!(text_a, "value_a", "Client A should see its own value");
    assert_eq!(text_b, "value_b", "Client B should see its own value");
}

#[test]
fn session_reinitialize_fails() {
    let mut client = setup_workflow_server();

    // First initialization succeeds
    client.initialize().unwrap();
    assert!(client.is_initialized());

    // Second initialization should succeed (idempotent) but returns same info
    // Note: In actual MCP protocol, re-initializing isn't well-defined,
    // but our TestClient should handle it gracefully
    let second_init = client.initialize();

    // The result depends on server implementation - may succeed or fail
    // The important thing is the client remains in a usable state
    if second_init.is_ok() {
        // If it succeeded, client should still work
        let tools = client.list_tools();
        assert!(tools.is_ok());
    }
}

#[test]
fn session_tracks_client_info() {
    use fastmcp_transport::memory::create_memory_transport_pair;

    let (client_transport, server_transport) = create_memory_transport_pair();
    let server = Server::new("client-info-test", "1.0.0")
        .tool(EchoTool)
        .build();
    let server_handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server.run_transport_with_cx(&cx, server_transport);
    });
    let _server_join = ThreadJoins::new(vec![server_handle]);

    let mut client =
        TestClient::new(client_transport).with_client_info("custom-client-name", "2.5.0");

    // Verify client info is set before initialization
    let init = client.initialize().unwrap();

    // Server responded (indicating it received our client info)
    assert!(init.capabilities.tools.is_some());

    // Client should still work after initialization
    let result = client
        .call_tool("echo", json!({"message": "test"}))
        .unwrap();
    assert!(!result.is_empty());
}

#[test]
fn session_multiple_clients_independent_lifecycle() {
    use fastmcp_transport::memory::create_memory_transport_pair;

    // Create multiple independent client-server pairs
    let mut server_joins = ThreadJoins::new(Vec::new());
    let mut clients = Vec::new();

    for i in 0..3 {
        let (client_transport, server_transport) = create_memory_transport_pair();
        let server = Server::new(&format!("lifecycle-server-{}", i), "1.0.0")
            .tool(EchoTool)
            .build();
        let handle = spawn_thread(move || {
            let cx = Cx::for_testing();
            server
                .run_transport_returning_with_cx(&cx, server_transport)
                .expect("lifecycle server loop");
        });
        server_joins.push(handle);

        let client = TestClient::new(client_transport)
            .with_client_info(format!("lifecycle-client-{}", i), "1.0.0");
        clients.push((i, client));
    }

    // Initialize clients in order
    for (i, client) in &mut clients {
        let init = client.initialize().unwrap();
        assert_eq!(init.server_info.name, format!("lifecycle-server-{}", i));
    }

    // All clients should work independently
    for (i, client) in &mut clients {
        let result = client
            .call_tool("echo", json!({"message": format!("from-client-{}", i)}))
            .unwrap();
        assert!(
            matches!(result.first(), Some(LegacyContent::Text { .. })),
            "expected text content"
        );
        let Some(LegacyContent::Text { text, .. }) = result.first() else {
            return;
        };
        assert!(text.contains(&format!("from-client-{}", i)));
    }

    // Close clients in reverse order (shouldn't affect others)
    while let Some((_, mut client)) = clients.pop() {
        client.close();
    }
}

#[test]
fn session_state_persists_across_operations() {
    use fastmcp_transport::memory::create_memory_transport_pair;

    let (client_transport, server_transport) = create_memory_transport_pair();
    let server = Server::new("persistence-test", "1.0.0")
        .tool(SessionStoreHandler)
        .tool(SessionGetHandler)
        .tool(EchoTool)
        .build();
    let handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server
            .run_transport_returning_with_cx(&cx, server_transport)
            .expect("persistence server loop");
    });
    let _joins = ThreadJoins::new(vec![handle]);

    let mut client = TestClient::new(client_transport);
    client.initialize().unwrap();

    // Store a value
    client
        .call_tool(
            "session_store",
            json!({"key": "persistent", "value": "stored_value"}),
        )
        .unwrap();

    // Perform unrelated operations
    client.list_tools().unwrap();
    client
        .call_tool("echo", json!({"message": "interleaved"}))
        .unwrap();
    client.list_tools().unwrap();

    // Value should still be there
    let result = client
        .call_tool("session_get", json!({"key": "persistent"}))
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert_eq!(text, "stored_value", "Session state should persist");
}

#[test]
fn session_server_info_accessors() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // Verify all accessors return correct data
    let server_info = client.server_info().unwrap();
    assert_eq!(server_info.name, "workflow-test-server");
    assert_eq!(server_info.version, "2.0.0");

    let caps = client.server_capabilities().unwrap();
    assert!(caps.tools.is_some());
    assert!(caps.resources.is_some());
    assert!(caps.prompts.is_some());

    // Protocol version should be non-empty
    let version = client.protocol_version().unwrap();
    assert!(!version.is_empty());
}

// ============================================================================
// Tool Invocation E2E Tests (bd-3vh)
// ============================================================================

/// Tool that accepts various argument types for testing.
struct TypesToolHandler;

impl ToolHandler for TypesToolHandler {
    fn definition(&self) -> Tool {
        Tool {
            name: "types_test".to_string(),
            description: Some("Tests various argument types".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "string_val": { "type": "string" },
                    "int_val": { "type": "integer" },
                    "float_val": { "type": "number" },
                    "bool_val": { "type": "boolean" },
                    "array_val": { "type": "array", "items": { "type": "string" } },
                    "object_val": { "type": "object" },
                    "null_val": { "type": "null" }
                },
                "required": []
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        // Echo back the type of each provided value
        let mut result = Vec::new();

        if let Some(v) = arguments.get("string_val") {
            result.push(format!(
                "string_val: {}",
                v.as_str().unwrap_or("(not string)")
            ));
        }
        if let Some(v) = arguments.get("int_val") {
            result.push(format!(
                "int_val: {}",
                v.as_i64()
                    .map(|n| n.to_string())
                    .unwrap_or("(not int)".to_string())
            ));
        }
        if let Some(v) = arguments.get("float_val") {
            result.push(format!(
                "float_val: {}",
                v.as_f64()
                    .map(|n| n.to_string())
                    .unwrap_or("(not float)".to_string())
            ));
        }
        if let Some(v) = arguments.get("bool_val") {
            result.push(format!(
                "bool_val: {}",
                v.as_bool()
                    .map(|b| b.to_string())
                    .unwrap_or("(not bool)".to_string())
            ));
        }
        if let Some(v) = arguments.get("array_val") {
            let arr_len = v.as_array().map(|a| a.len()).unwrap_or(0);
            result.push(format!("array_val: [len={}]", arr_len));
        }
        if let Some(v) = arguments.get("object_val") {
            let obj_keys = v.as_object().map(|o| o.len()).unwrap_or(0);
            result.push(format!("object_val: {{keys={}}}", obj_keys));
        }
        if arguments
            .get("null_val")
            .map(|v| v.is_null())
            .unwrap_or(false)
        {
            result.push("null_val: null".to_string());
        }

        if result.is_empty() {
            result.push("(no arguments provided)".to_string());
        }

        Ok(vec![Content::Text {
            text: result.join(", "),
        }])
    }
}

/// Tool with required and optional arguments.
#[tool(name = "required_args")]
fn required_args_tool(
    _ctx: &McpContext,
    required_field: String,
    optional_field: Option<String>,
) -> String {
    let optional = optional_field.as_deref().unwrap_or("(not provided)");
    format!("required: {}, optional: {}", required_field, optional)
}

/// Tool that returns multiple content items.
#[tool(name = "multi_content")]
fn multi_content_tool(_ctx: &McpContext, count: Option<i64>) -> Vec<Content> {
    let count = count.unwrap_or(1) as usize;
    let count = count.min(10); // Limit to 10

    (0..count)
        .map(|i| Content::Text {
            text: format!("Item {}", i + 1),
        })
        .collect()
}

fn setup_tool_test_server() -> TestHarness {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("tool-test-server")
        .with_version("1.0.0")
        .build_server_builder();

    let server = builder
        .tool(EchoTool)
        .tool(TypesToolHandler)
        .tool(RequiredArgsTool)
        .tool(MultiContentTool)
        .tool(FailOnDemandTool)
        .build();

    let handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server.run_transport_with_cx(&cx, server_transport);
    });

    TestHarness::new(TestClient::new(client_transport), handle)
}

#[test]
fn tool_call_string_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"string_val": "hello world"}))
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("string_val: hello world"));
}

#[test]
fn tool_call_integer_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"int_val": 42}))
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("int_val: 42"));
}

#[test]
fn tool_call_float_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"float_val": 3.14159}))
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("float_val: 3.14159"));
}

#[test]
fn tool_call_boolean_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"bool_val": true}))
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("bool_val: true"));

    let result = client
        .call_tool("types_test", json!({"bool_val": false}))
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("bool_val: false"));
}

#[test]
fn tool_call_array_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"array_val": ["a", "b", "c"]}))
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("array_val: [len=3]"));
}

#[test]
fn tool_call_object_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool(
            "types_test",
            json!({"object_val": {"key1": "val1", "key2": "val2"}}),
        )
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("object_val: {keys=2}"));
}

#[test]
fn tool_call_null_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"null_val": null}))
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("null_val: null"));
}

#[test]
fn tool_call_multiple_argument_types() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool(
            "types_test",
            json!({
                "string_val": "test",
                "int_val": 100,
                "bool_val": true,
                "array_val": [1, 2, 3]
            }),
        )
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("string_val: test"));
    assert!(text.contains("int_val: 100"));
    assert!(text.contains("bool_val: true"));
    assert!(text.contains("array_val: [len=3]"));
}

#[test]
fn tool_call_empty_arguments() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client.call_tool("types_test", json!({})).unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("(no arguments provided)"));
}

#[test]
fn tool_call_required_argument_provided() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("required_args", json!({"required_field": "value123"}))
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("required: value123"));
    assert!(text.contains("optional: (not provided)"));
}

#[test]
fn tool_call_required_and_optional_arguments() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool(
            "required_args",
            json!({
                "required_field": "required_value",
                "optional_field": "optional_value"
            }),
        )
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("required: required_value"));
    assert!(text.contains("optional: optional_value"));
}

#[test]
fn tool_call_missing_required_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client.call_tool("required_args", json!({"optional_field": "only optional"}));

    assert!(
        result.is_err(),
        "Should fail when required argument is missing"
    );
}

#[test]
fn tool_call_returns_multiple_content() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("multi_content", json!({"count": 3}))
        .unwrap();

    assert_eq!(result.len(), 3, "Should return 3 content items");

    for (i, content) in result.iter().enumerate() {
        assert!(
            matches!(content, LegacyContent::Text { .. }),
            "expected text content"
        );
        let LegacyContent::Text { text, .. } = content else {
            return;
        };
        assert_eq!(text, &format!("Item {}", i + 1));
    }
}

#[test]
fn tool_call_error_returns_mcp_error() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client.call_tool(
        "fail_on_demand",
        json!({"fail": true, "message": "test error"}),
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.message.contains("test error") || err.message.contains("Requested failure"));
}

#[test]
fn tool_call_nonexistent_tool_error() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client.call_tool("nonexistent_tool", json!({}));

    assert!(result.is_err(), "Calling nonexistent tool should fail");
}

#[test]
fn tool_call_unicode_arguments() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("echo", json!({"message": "こんにちは世界 🌍 مرحبا"}))
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert_eq!(text, "こんにちは世界 🌍 مرحبا");
}

#[test]
fn tool_call_special_characters() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool(
            "echo",
            json!({"message": "Line 1\nLine 2\tTabbed \"quoted\" 'single'"}),
        )
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("Line 1"));
    assert!(text.contains("Line 2"));
    assert!(text.contains("quoted"));
}

#[test]
fn tool_call_large_string_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let large_string = "x".repeat(10_000);
    let result = client
        .call_tool("echo", json!({"message": &large_string}))
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert_eq!(text.len(), 10_000);
}

#[test]
fn tool_call_nested_object_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool(
            "types_test",
            json!({
                "object_val": {
                    "level1": {
                        "level2": {
                            "level3": "deep value"
                        }
                    }
                }
            }),
        )
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("object_val: {keys=1}"));
}

#[test]
fn tool_call_negative_numbers() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"int_val": -42, "float_val": -3.14}))
        .unwrap();

    assert!(
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
        return;
    };
    assert!(text.contains("int_val: -42"));
    assert!(text.contains("float_val: -3.14"));
}

#[test]
fn tool_call_sequential_success() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    // Call multiple tools in sequence
    for i in 0..10 {
        let result = client
            .call_tool("echo", json!({"message": format!("call_{}", i)}))
            .unwrap();

        assert!(
            matches!(result.first(), Some(LegacyContent::Text { .. })),
            "expected text content"
        );
        let Some(LegacyContent::Text { text, .. }) = result.first() else {
            return;
        };
        assert_eq!(text, &format!("call_{}", i));
    }
}

#[test]
fn tool_call_alternating_success_failure() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    for i in 0..6 {
        let should_fail = i % 2 == 1;
        let result = client.call_tool("fail_on_demand", json!({"fail": should_fail}));

        if should_fail {
            assert!(result.is_err(), "Iteration {} should fail", i);
        } else {
            assert!(result.is_ok(), "Iteration {} should succeed", i);
        }
    }

    // Verify client is still functional after alternating failures
    let tools = client.list_tools().unwrap();
    assert!(!tools.is_empty());
}

// ============================================================================
// Resource Reading E2E Tests (bd-bte)
// ============================================================================

/// Resource that returns plain text content.
#[resource(uri = "text://plain", name = "Plain Text", mime_type = "text/plain")]
fn plain_text() -> String {
    "Hello, World!".to_string()
}

/// Resource that returns JSON content.
#[resource(
    uri = "data://config.json",
    name = "JSON Config",
    mime_type = "application/json"
)]
fn json_config() -> String {
    json!({
        "name": "test-config",
        "version": "1.0.0",
        "settings": {
            "debug": true,
            "max_connections": 100
        }
    })
    .to_string()
}

/// Resource that returns binary content.
#[resource(
    uri = "binary://data.bin",
    name = "Binary Data",
    mime_type = "application/octet-stream"
)]
fn binary_data() -> Vec<ResourceContent> {
    let binary_data: Vec<u8> = (0..255u8).collect();
    let blob = base64_encode(&binary_data);

    vec![ResourceContent {
        uri: "binary://data.bin".to_string(),
        mime_type: Some("application/octet-stream".to_string()),
        text: None,
        blob: Some(blob),
    }]
}

/// Simple base64 encoding for tests (no external dependency).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = data.get(i + 1).map(|&x| x as usize).unwrap_or(0);
        let b2 = data.get(i + 2).map(|&x| x as usize).unwrap_or(0);

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[b2 & 0x3F] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

/// Resource that returns Unicode content.
#[resource(
    uri = "text://unicode",
    name = "Unicode Text",
    mime_type = "text/plain; charset=utf-8"
)]
fn unicode_text() -> String {
    "日本語 中文 العربية 🌍🌎🌏 Ελληνικά".to_string()
}

/// Resource that returns large content.
#[resource(uri = "data://large", name = "Large Content", mime_type = "text/plain")]
fn large_content() -> String {
    "x".repeat(100_000)
}

/// Resource that returns multiple content items.
#[resource(uri = "data://multi", name = "Multi Content")]
fn multi_content_items() -> Vec<ResourceContent> {
    vec![
        ResourceContent {
            uri: "data://multi/part1".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some("Part 1".to_string()),
            blob: None,
        },
        ResourceContent {
            uri: "data://multi/part2".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some("Part 2".to_string()),
            blob: None,
        },
        ResourceContent {
            uri: "data://multi/part3".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some("Part 3".to_string()),
            blob: None,
        },
    ]
}

/// Resource that always fails.
#[resource(uri = "error://fail", name = "Failing Resource")]
fn failing_res() -> McpResult<String> {
    Err(McpError::resource_not_found(
        "Resource read failed intentionally",
    ))
}

fn setup_resource_test_server() -> TestHarness {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("resource-test-server")
        .with_version("1.0.0")
        .build_server_builder();

    let server = builder
        .resource(PlainTextResource)
        .resource(JsonConfigResource)
        .resource(BinaryDataResource)
        .resource(UnicodeTextResource)
        .resource(LargeContentResource)
        .resource(MultiContentItemsResource)
        .resource(FailingResResource)
        .build();

    let handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server.run_transport_with_cx(&cx, server_transport);
    });

    TestHarness::new(TestClient::new(client_transport), handle)
}

#[test]
fn resource_read_plain_text() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let content = client.read_resource("text://plain").unwrap();

    assert_eq!(content.len(), 1);
    assert!(matches!(&content[0], LegacyResourceContent::Text { .. }));
    let LegacyResourceContent::Text {
        uri,
        mime_type,
        text,
        ..
    } = &content[0]
    else {
        return;
    };
    assert_eq!(uri, "text://plain");
    assert_eq!(mime_type.as_deref(), Some("text/plain"));
    assert_eq!(text, "Hello, World!");
}

#[test]
fn resource_read_json() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let content = client.read_resource("data://config.json").unwrap();

    assert_eq!(content.len(), 1);
    let LegacyResourceContent::Text {
        mime_type, text, ..
    } = &content[0]
    else {
        return;
    };
    assert_eq!(mime_type.as_deref(), Some("application/json"));

    let json: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(json["name"], "test-config");
    assert_eq!(json["version"], "1.0.0");
    assert_eq!(json["settings"]["debug"], true);
    assert_eq!(json["settings"]["max_connections"], 100);
}

#[test]
fn resource_read_binary() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let content = client.read_resource("binary://data.bin").unwrap();

    assert_eq!(content.len(), 1);
    assert!(matches!(&content[0], LegacyResourceContent::Blob { .. }));
    let LegacyResourceContent::Blob {
        mime_type, blob, ..
    } = &content[0]
    else {
        return;
    };
    assert_eq!(mime_type.as_deref(), Some("application/octet-stream"));

    // Verify blob is base64 encoded
    assert!(!blob.is_empty());
    // Base64 uses only alphanumeric chars and +/=
    assert!(
        blob.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    );
}

#[test]
fn resource_read_unicode() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let content = client.read_resource("text://unicode").unwrap();

    assert_eq!(content.len(), 1);
    let LegacyResourceContent::Text { text, .. } = &content[0] else {
        return;
    };
    assert!(text.contains("日本語"));
    assert!(text.contains("中文"));
    assert!(text.contains("العربية"));
    assert!(text.contains("🌍"));
    assert!(text.contains("Ελληνικά"));
}

#[test]
fn resource_read_large_content() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let content = client.read_resource("data://large").unwrap();

    assert_eq!(content.len(), 1);
    let LegacyResourceContent::Text { text, .. } = &content[0] else {
        return;
    };
    assert_eq!(text.len(), 100_000);
    assert!(text.chars().all(|c| c == 'x'));
}

#[test]
fn resource_read_multiple_content_items() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let content = client.read_resource("data://multi").unwrap();

    assert_eq!(content.len(), 3, "Should return 3 content items");

    let [
        LegacyResourceContent::Text { text: first, .. },
        LegacyResourceContent::Text { text: second, .. },
        LegacyResourceContent::Text { text: third, .. },
    ] = content.as_slice()
    else {
        return;
    };
    assert_eq!(first, "Part 1");
    assert_eq!(second, "Part 2");
    assert_eq!(third, "Part 3");
}

#[test]
fn resource_read_nonexistent() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let result = client.read_resource("nonexistent://resource");

    assert!(result.is_err(), "Reading nonexistent resource should fail");
}

#[test]
fn resource_read_failing() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let result = client.read_resource("error://fail");

    assert!(
        result.is_err(),
        "Reading failing resource should return error"
    );
}

#[test]
fn resource_list_all() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let resources = client.list_resources().unwrap();

    assert_eq!(resources.len(), 7, "Should have 7 resources registered");

    let uris: Vec<&str> = resources.iter().map(|r| r.uri.as_str()).collect();
    assert!(uris.contains(&"text://plain"));
    assert!(uris.contains(&"data://config.json"));
    assert!(uris.contains(&"binary://data.bin"));
    assert!(uris.contains(&"text://unicode"));
    assert!(uris.contains(&"data://large"));
    assert!(uris.contains(&"data://multi"));
    assert!(uris.contains(&"error://fail"));
}

#[test]
fn resource_read_sequential() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    // Read multiple resources in sequence
    let content1 = client.read_resource("text://plain").unwrap();
    let content2 = client.read_resource("data://config.json").unwrap();
    let content3 = client.read_resource("text://unicode").unwrap();

    let LegacyResourceContent::Text { text: text1, .. } = &content1[0] else {
        return;
    };
    let LegacyResourceContent::Text { text: text2, .. } = &content2[0] else {
        return;
    };
    let LegacyResourceContent::Text { text: text3, .. } = &content3[0] else {
        return;
    };
    assert_eq!(text1, "Hello, World!");
    assert!(text2.contains("test-config"));
    assert!(text3.contains("日本語"));
}

#[test]
fn resource_read_after_error() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    // First read a valid resource
    let content = client.read_resource("text://plain").unwrap();
    assert!(!content.is_empty());

    // Try to read a failing resource
    let result = client.read_resource("error://fail");
    assert!(result.is_err());

    // Session should still work - read another valid resource
    let content = client.read_resource("text://unicode").unwrap();
    assert!(!content.is_empty());
}

#[test]
fn resource_metadata_preserved() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let resources = client.list_resources().unwrap();

    let plain_text = resources.iter().find(|r| r.uri == "text://plain").unwrap();
    assert_eq!(plain_text.name, "Plain Text");
    assert_eq!(
        plain_text.description.as_deref(),
        Some("Returns plain text content")
    );
    assert_eq!(plain_text.mime_type.as_deref(), Some("text/plain"));

    let json_resource = resources
        .iter()
        .find(|r| r.uri == "data://config.json")
        .unwrap();
    assert_eq!(json_resource.name, "JSON Config");
    assert_eq!(json_resource.mime_type.as_deref(), Some("application/json"));
}

#[test]
fn resource_read_before_init_fails() {
    use fastmcp_transport::memory::create_memory_transport_pair;

    let (client_transport, server_transport) = create_memory_transport_pair();
    let server = Server::new("test", "1.0.0")
        .resource(PlainTextResource)
        .build();
    let server_handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server.run_transport_with_cx(&cx, server_transport);
    });
    let _server_join = ThreadJoins::new(vec![server_handle]);

    let mut client = TestClient::new(client_transport);

    // Should fail before initialization
    assert!(client.read_resource("text://plain").is_err());
}
