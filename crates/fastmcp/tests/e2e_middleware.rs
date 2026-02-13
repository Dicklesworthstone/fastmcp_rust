//! E2E Middleware Integration Tests (bd-j29)
//!
//! Goals:
//! - Verify middleware chain ordering (request in registration order, response/error in reverse)
//! - Verify short-circuit semantics still run the entered response stack
//! - Verify error propagation invokes `on_error` in reverse order and can rewrite errors
//! - Verify built-in middleware behaves correctly in an end-to-end server/client flow:
//!   - Response caching with TTL for `tools/call`
//!   - Rate limiting
//! - Verify response transformations are observable by clients (no mocks)

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fastmcp_protocol::JsonRpcRequest;
use fastmcp_rust::testing::prelude::*;
use fastmcp_rust::{McpContext, McpError, McpErrorCode, McpResult};

use fastmcp_server::Middleware;
use fastmcp_server::MiddlewareDecision;
use fastmcp_server::caching::ResponseCachingMiddleware;
use fastmcp_server::rate_limiting::SlidingWindowRateLimitingMiddleware;

// ============================================================================
// Test Middleware
// ============================================================================

#[derive(Clone)]
struct RecordingMw {
    name: &'static str,
    events: Arc<Mutex<Vec<String>>>,
}

impl RecordingMw {
    fn new(name: &'static str, events: Arc<Mutex<Vec<String>>>) -> Self {
        Self { name, events }
    }

    fn push(&self, phase: &str) {
        let mut guard = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.push(format!("{}:{}", self.name, phase));
    }
}

impl Middleware for RecordingMw {
    fn on_request(
        &self,
        _ctx: &McpContext,
        _request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        self.push("req");
        Ok(MiddlewareDecision::Continue)
    }

    fn on_response(
        &self,
        _ctx: &McpContext,
        _request: &JsonRpcRequest,
        response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        self.push("resp");
        Ok(response)
    }

    fn on_error(&self, _ctx: &McpContext, _request: &JsonRpcRequest, error: McpError) -> McpError {
        self.push("err");
        error
    }
}

#[derive(Clone)]
struct ShortCircuitMw {
    name: &'static str,
    events: Arc<Mutex<Vec<String>>>,
    // If true, short-circuit the request.
    respond: bool,
}

impl ShortCircuitMw {
    fn new(name: &'static str, events: Arc<Mutex<Vec<String>>>, respond: bool) -> Self {
        Self {
            name,
            events,
            respond,
        }
    }

    fn push(&self, phase: &str) {
        let mut guard = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.push(format!("{}:{}", self.name, phase));
    }
}

impl Middleware for ShortCircuitMw {
    fn on_request(
        &self,
        _ctx: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        self.push("req");

        if self.respond {
            // Short-circuit only tool calls; other methods must pass so the client can initialize.
            if request.method == "tools/call" {
                return Ok(MiddlewareDecision::Respond(serde_json::json!({
                    "content": [{"type": "text", "text": "short-circuit"}]
                })));
            }
        }

        Ok(MiddlewareDecision::Continue)
    }

    fn on_response(
        &self,
        _ctx: &McpContext,
        _request: &JsonRpcRequest,
        response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        self.push("resp");
        Ok(response)
    }

    fn on_error(&self, _ctx: &McpContext, _request: &JsonRpcRequest, error: McpError) -> McpError {
        self.push("err");
        error
    }
}

#[derive(Clone)]
struct RewriteErrorMw {
    name: &'static str,
    events: Arc<Mutex<Vec<String>>>,
    prefix: &'static str,
}

impl RewriteErrorMw {
    fn new(name: &'static str, events: Arc<Mutex<Vec<String>>>, prefix: &'static str) -> Self {
        Self {
            name,
            events,
            prefix,
        }
    }

    fn push(&self, phase: &str) {
        let mut guard = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.push(format!("{}:{}", self.name, phase));
    }
}

impl Middleware for RewriteErrorMw {
    fn on_request(
        &self,
        _ctx: &McpContext,
        _request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        self.push("req");
        Ok(MiddlewareDecision::Continue)
    }

    fn on_response(
        &self,
        _ctx: &McpContext,
        _request: &JsonRpcRequest,
        response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        self.push("resp");
        Ok(response)
    }

    fn on_error(&self, _ctx: &McpContext, _request: &JsonRpcRequest, error: McpError) -> McpError {
        self.push("err");
        McpError {
            code: error.code,
            message: format!("{}{}", self.prefix, error.message),
            data: error.data,
        }
    }
}

#[derive(Clone)]
struct PrefixTextMw {
    prefix: &'static str,
}

impl Middleware for PrefixTextMw {
    fn on_response(
        &self,
        _ctx: &McpContext,
        request: &JsonRpcRequest,
        mut response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        // Transform only tools/call responses, preserving the CallToolResult shape.
        if request.method != "tools/call" {
            return Ok(response);
        }

        let Some(obj) = response.as_object_mut() else {
            return Ok(response);
        };
        let Some(content) = obj.get_mut("content") else {
            return Ok(response);
        };
        let Some(items) = content.as_array_mut() else {
            return Ok(response);
        };

        for item in items {
            let Some(item_obj) = item.as_object_mut() else {
                continue;
            };
            let item_type = item_obj.get("type").and_then(|v| v.as_str());
            if item_type != Some("text") {
                continue;
            }
            if let Some(text_val) = item_obj.get_mut("text") {
                if let Some(text) = text_val.as_str() {
                    *text_val = serde_json::Value::String(format!("{}{}", self.prefix, text));
                }
            }
        }

        Ok(response)
    }
}

// ============================================================================
// Test Handlers
// ============================================================================

thread_local! {
    static ECHO_TOOL_CALLS: RefCell<Option<Arc<AtomicUsize>>> = const { RefCell::new(None) };
}

fn set_echo_tool_calls(calls: Option<Arc<AtomicUsize>>) {
    ECHO_TOOL_CALLS.with(|slot| {
        *slot.borrow_mut() = calls;
    });
}

#[fastmcp_rust::tool(
    name = "echo",
    description = "Echo tool",
    version = "1.0.0",
    tags = ["middleware"],
    annotations(read_only, idempotent)
)]
fn echo_tool(_ctx: &McpContext, message: String) -> String {
    ECHO_TOOL_CALLS.with(|slot| {
        if let Some(calls) = slot.borrow().as_ref() {
            calls.fetch_add(1, Ordering::SeqCst);
        }
    });
    message
}

#[fastmcp_rust::tool(
    name = "fail",
    description = "Always fails",
    version = "1.0.0",
    tags = ["middleware"]
)]
fn failing_tool() -> McpResult<String> {
    Err(McpError::tool_error("boom"))
}

// ============================================================================
// Helpers
// ============================================================================

fn spawn_middleware_server(
    name: &str,
    echo_calls: Option<Arc<AtomicUsize>>,
    build: impl FnOnce(fastmcp_server::ServerBuilder) -> fastmcp_server::Server,
) -> (
    fastmcp_transport::memory::MemoryTransport,
    std::thread::JoinHandle<()>,
) {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name(name)
        .with_version("1.0.0")
        .build_server_builder();

    let server = build(builder);

    let handle = std::thread::spawn(move || {
        set_echo_tool_calls(echo_calls);
        let cx = Cx::for_testing();
        server.run_transport_returning_with_cx(&cx, server_transport);
        set_echo_tool_calls(None);
    });

    (client_transport, handle)
}

fn take_events(events: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    let mut guard = events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let out = guard.clone();
    guard.clear();
    out
}

fn first_text(contents: &[Content]) -> Option<String> {
    contents.first().and_then(|c| match c {
        Content::Text { text } => Some(text.clone()),
        _ => None,
    })
}

fn init_trace(name: &str) -> TestTrace {
    TestTrace::builder(name).build()
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn middleware_ordering_success_request_in_order_response_in_reverse() {
    let mut trace = init_trace("bd-j29_ordering_success");

    let events = Arc::new(Mutex::new(Vec::<String>::new()));
    let calls = Arc::new(AtomicUsize::new(0));

    let (transport, server_handle) =
        spawn_middleware_server("mw-order-success", Some(Arc::clone(&calls)), |builder| {
            builder
                .middleware(RecordingMw::new("A", Arc::clone(&events)))
                .middleware(RecordingMw::new("B", Arc::clone(&events)))
                .tool(EchoTool)
                .build()
        });

    let mut client = TestClient::new(transport);
    let init_res = client.initialize();
    trace.log_with_data(
        TraceLevel::Info,
        "initialize",
        serde_json::json!({"ok": init_res.is_ok()}),
    );
    assert!(init_res.is_ok());

    // Barrier: initialize sends an `initialized` notification (no response); force the server loop
    // to drain it deterministically by awaiting a `ping` response.
    let ping = client.send_request_json("ping", json!({}));
    assert!(ping.is_ok());

    // Clear so we only assert the tool call flow.
    let _ = take_events(&events);

    let call_res = client.call_tool("echo", json!({"message": "hi"}));
    trace.log_with_data(
        TraceLevel::Info,
        "tool_call",
        serde_json::json!({"ok": call_res.is_ok()}),
    );
    assert!(call_res.is_ok());

    drop(client);
    let _ = server_handle.join();

    let got = take_events(&events);
    trace.log_with_data(
        TraceLevel::Info,
        "events",
        serde_json::json!({"events": got}),
    );

    let expected = vec![
        "A:req".to_string(),
        "B:req".to_string(),
        "B:resp".to_string(),
        "A:resp".to_string(),
    ];
    assert_eq!(expected, got);

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn middleware_short_circuit_still_runs_entered_response_stack() {
    let mut trace = init_trace("bd-j29_short_circuit");

    let events = Arc::new(Mutex::new(Vec::<String>::new()));
    let calls = Arc::new(AtomicUsize::new(0));

    let (transport, server_handle) =
        spawn_middleware_server("mw-short-circuit", Some(Arc::clone(&calls)), |builder| {
            builder
                .middleware(ShortCircuitMw::new("A", Arc::clone(&events), false))
                .middleware(ShortCircuitMw::new("B", Arc::clone(&events), true))
                .tool(EchoTool)
                .build()
        });

    let mut client = TestClient::new(transport);
    let init_res = client.initialize();
    assert!(init_res.is_ok());

    // Barrier: drain the `initialized` notification by awaiting a `ping` response.
    assert!(client.send_request_json("ping", json!({})).is_ok());

    // Clear so we only capture the tool call.
    let _ = take_events(&events);

    let call_res = client.call_tool("echo", json!({"message": "ignored"}));
    if let Err(e) = &call_res {
        trace.log_with_data(
            TraceLevel::Error,
            "unexpected tool error",
            serde_json::json!({"message": e.message, "code": i32::from(e.code)}),
        );
    }
    assert!(call_res.is_ok(), "unexpected tool error: {call_res:?}");
    let Ok(contents) = call_res else {
        return;
    };
    let text = first_text(&contents).unwrap_or_default();
    trace.log_with_data(
        TraceLevel::Info,
        "short_circuit_result",
        serde_json::json!({"text": text}),
    );
    assert_eq!(text, "short-circuit".to_string());

    drop(client);
    let _ = server_handle.join();

    let got = take_events(&events);
    trace.log_with_data(
        TraceLevel::Info,
        "events",
        serde_json::json!({"events": got}),
    );

    let expected = vec![
        "A:req".to_string(),
        "B:req".to_string(),
        "B:resp".to_string(),
        "A:resp".to_string(),
    ];
    assert_eq!(expected, got);

    // Tool handler must not have run (request was short-circuited).
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn middleware_error_path_calls_on_error_in_reverse_and_can_rewrite() {
    let mut trace = init_trace("bd-j29_error_rewrite");

    let events = Arc::new(Mutex::new(Vec::<String>::new()));

    let (transport, server_handle) = spawn_middleware_server("mw-error-rewrite", None, |builder| {
        builder
            .middleware(RecordingMw::new("A", Arc::clone(&events)))
            .middleware(RewriteErrorMw::new("B", Arc::clone(&events), "mw:"))
            .tool(FailingTool)
            .build()
    });

    let mut client = TestClient::new(transport);
    let init_res = client.initialize();
    assert!(init_res.is_ok());

    // Barrier: drain the `initialized` notification by awaiting a `ping` response.
    assert!(client.send_request_json("ping", json!({})).is_ok());

    // Clear so we only capture the failing request.
    let _ = take_events(&events);

    // Send invalid params to force an actual dispatch error (not an "isError" tool result).
    let err = client.send_request_json("tools/call", json!({}));
    assert!(err.is_err());
    let (err_code, err_message) = match err {
        Ok(_) => (None, None),
        Err(e) => {
            trace.log_with_data(
                TraceLevel::Info,
                "error",
                serde_json::json!({"code": i32::from(e.code), "message": e.message}),
            );
            (Some(e.code), Some(e.message))
        }
    };

    drop(client);
    let _ = server_handle.join();

    let got = take_events(&events);
    trace.log_with_data(
        TraceLevel::Info,
        "events",
        serde_json::json!({"events": got}),
    );

    // Requests run in order; on_error runs in reverse order for entered middleware.
    let expected = vec![
        "A:req".to_string(),
        "B:req".to_string(),
        "B:err".to_string(),
        "A:err".to_string(),
    ];
    assert_eq!(expected, got);

    assert!(
        err_code.is_some() && err_message.is_some(),
        "expected error from invalid tools/call params"
    );
    let Some(message) = err_message else {
        return;
    };
    assert!(
        message.starts_with("mw:"),
        "error message not rewritten: {message}"
    );
}

#[test]
fn middleware_response_transformation_is_observable_in_client() {
    let mut trace = init_trace("bd-j29_response_transform");

    let calls = Arc::new(AtomicUsize::new(0));

    let (transport, server_handle) =
        spawn_middleware_server("mw-transform", Some(Arc::clone(&calls)), |builder| {
            builder
                .middleware(PrefixTextMw { prefix: "mw:" })
                .tool(EchoTool)
                .build()
        });

    let mut client = TestClient::new(transport);
    assert!(client.initialize().is_ok());

    let res = client.call_tool("echo", json!({"message": "hello"}));
    if let Err(e) = &res {
        trace.log_with_data(
            TraceLevel::Error,
            "unexpected tool error",
            serde_json::json!({"message": e.message, "code": i32::from(e.code)}),
        );
    }
    assert!(res.is_ok(), "unexpected tool error: {res:?}");
    let Ok(contents) = res else {
        return;
    };
    let text = first_text(&contents).unwrap_or_default();
    trace.log_with_data(
        TraceLevel::Info,
        "transformed_text",
        serde_json::json!({"text": text}),
    );
    assert_eq!(text, "mw:hello".to_string());

    drop(client);
    let _ = server_handle.join();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn caching_middleware_caches_tools_call_until_ttl_expires() {
    let mut trace = init_trace("bd-j29_caching_ttl");

    let calls = Arc::new(AtomicUsize::new(0));

    let caching = ResponseCachingMiddleware::new().call_ttl_secs(1);

    let (transport, server_handle) =
        spawn_middleware_server("mw-caching", Some(Arc::clone(&calls)), |builder| {
            builder.middleware(caching).tool(EchoTool).build()
        });

    let mut client = TestClient::new(transport);
    assert!(client.initialize().is_ok());

    let res1 = client.call_tool("echo", json!({"message": "a"}));
    if let Err(e) = &res1 {
        trace.log_with_data(
            TraceLevel::Error,
            "unexpected tool error",
            serde_json::json!({"message": e.message, "code": i32::from(e.code)}),
        );
    }
    assert!(res1.is_ok(), "unexpected tool error: {res1:?}");
    let Ok(v1) = res1 else {
        return;
    };
    let text1 = first_text(&v1).unwrap_or_default();

    let res2 = client.call_tool("echo", json!({"message": "a"}));
    if let Err(e) = &res2 {
        trace.log_with_data(
            TraceLevel::Error,
            "unexpected tool error",
            serde_json::json!({"message": e.message, "code": i32::from(e.code)}),
        );
    }
    assert!(res2.is_ok(), "unexpected tool error: {res2:?}");
    let Ok(v2) = res2 else {
        return;
    };
    let text2 = first_text(&v2).unwrap_or_default();

    trace.log_with_data(
        TraceLevel::Info,
        "cache_results",
        serde_json::json!({"t1": text1, "t2": text2, "calls": calls.load(Ordering::SeqCst)}),
    );

    // Same response and handler executed once (second is served from cache).
    assert_eq!(text1, "a".to_string());
    assert_eq!(text2, "a".to_string());
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // After TTL, entry should expire and handler should run again.
    std::thread::sleep(Duration::from_millis(1200));

    let res3 = client.call_tool("echo", json!({"message": "a"}));
    if let Err(e) = &res3 {
        trace.log_with_data(
            TraceLevel::Error,
            "unexpected tool error",
            serde_json::json!({"message": e.message, "code": i32::from(e.code)}),
        );
    }
    assert!(res3.is_ok(), "unexpected tool error: {res3:?}");
    if let Ok(v) = res3 {
        let _ = first_text(&v);
    }

    drop(client);
    let _ = server_handle.join();

    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn rate_limiting_middleware_blocks_second_tool_call_deterministically() {
    let mut trace = init_trace("bd-j29_rate_limiting");

    // Allow 1 request per minute, but isolate buckets by method so initialization doesn't
    // consume the quota for tool calls.
    let limiter = SlidingWindowRateLimitingMiddleware::new(1, 60)
        .client_id_extractor(|_, req| Some(req.method.clone()));

    let calls = Arc::new(AtomicUsize::new(0));
    let (transport, server_handle) =
        spawn_middleware_server("mw-rate-limit", Some(Arc::clone(&calls)), |builder| {
            builder.middleware(limiter).tool(EchoTool).build()
        });

    let mut client = TestClient::new(transport);
    assert!(client.initialize().is_ok());

    let ok = client.call_tool("echo", json!({"message": "x"}));
    assert!(ok.is_ok());

    let limited = client.call_tool("echo", json!({"message": "y"}));
    assert!(limited.is_err());

    if let Err(e) = limited {
        trace.log_with_data(
            TraceLevel::Info,
            "rate_limit_error",
            serde_json::json!({"code": i32::from(e.code), "message": e.message}),
        );
        assert_eq!(
            e.code,
            McpErrorCode::Custom(fastmcp_server::rate_limiting::RATE_LIMIT_ERROR_CODE)
        );
        assert!(e.message.to_lowercase().contains("rate limit"));
    }

    drop(client);
    let _ = server_handle.join();

    // Only the first tool call should have been executed.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
