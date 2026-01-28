//! Comprehensive tests for the MCP server using Lab runtime patterns.
//!
//! These tests verify:
//! - Request/response cycle
//! - Tool invocation with cancellation
//! - Resource reading with budget exhaustion
//! - Multi-handler registration
//! - Error handling

use std::collections::HashMap;
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use asupersync::{Budget, CancelKind, Cx};
use fastmcp_core::logging::{info, targets};
use fastmcp_core::{AuthContext, McpContext, McpError, McpErrorCode, McpResult, SessionState};
use fastmcp_protocol::{
    CallToolParams, CancelTaskParams, CancelledParams, ClientCapabilities, ClientInfo, Content,
    GetPromptParams, GetTaskParams, InitializeParams, JsonRpcResponse, ListTasksParams, LogLevel,
    LogMessageParams, Prompt, PromptArgument, PromptMessage, ReadResourceParams, RequestId,
    Resource, ResourceContent, ResourceTemplate, ResourceUpdatedNotificationParams, Role,
    ServerCapabilities, ServerInfo, SetLogLevelParams, SubmitTaskParams, TaskId, TaskStatus,
    TaskStatusNotificationParams, Tool,
};

use crate::bidirectional::{PendingRequests, RequestSender, TransportSendFn};
use crate::handler::{PromptHandler, ResourceHandler, ToolHandler, UriParams};
use crate::router::Router;
use crate::session::Session;
use crate::{
    ActiveRequest, ActiveRequestGuard, AuthRequest, Middleware, MiddlewareDecision,
    NotificationSender, RequestCompletion, Server, StaticTokenVerifier, TaskManager,
    TokenAuthProvider,
};

/// Creates a mock request sender for tests that does nothing.
fn create_test_request_sender() -> RequestSender {
    let pending = Arc::new(PendingRequests::new());
    let send_fn: TransportSendFn = Arc::new(|_| Ok(()));
    RequestSender::new(pending, send_fn)
}

// ============================================================================
// Test Tool Handlers
// ============================================================================

/// A simple tool that greets a user.
struct GreetTool;

impl ToolHandler for GreetTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "greet".to_string(),
            description: Some("Greets a user by name".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"}
                },
                "required": ["name"]
            }),
            icon: None,
        }
    }

    fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let name = arguments
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("World");
        Ok(vec![Content::Text {
            text: format!("Hello, {name}!"),
        }])
    }
}

/// A tool that checks cancellation.
struct CancellationCheckTool;

impl ToolHandler for CancellationCheckTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "cancellation_check".to_string(),
            description: Some("Tool that checks cancellation status".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            icon: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        // Check for cancellation
        if ctx.is_cancelled() {
            return Err(McpError::request_cancelled());
        }
        Ok(vec![Content::Text {
            text: "Not cancelled".to_string(),
        }])
    }
}

/// A tool that simulates slow work.
struct SlowTool;

impl ToolHandler for SlowTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "slow_tool".to_string(),
            description: Some("Simulates a slow operation".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            icon: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        // Simulate work with checkpoint checks
        for i in 0..5 {
            if ctx.checkpoint().is_err() {
                return Err(McpError::request_cancelled());
            }
            // Normally we'd do work here
            let _ = i;
        }
        Ok(vec![Content::Text {
            text: "Slow work completed".to_string(),
        }])
    }
}

/// A tool that blocks until the request is cancelled.
struct BlockingTool {
    barrier: Arc<Barrier>,
}

impl ToolHandler for BlockingTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "block_until_cancelled".to_string(),
            description: Some("Blocks until cancellation is observed".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            icon: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        self.barrier.wait();
        while !ctx.is_cancelled() {
            std::thread::yield_now();
        }
        Err(McpError::request_cancelled())
    }
}

#[derive(Debug, Clone)]
struct RequestEvent {
    request_id: i64,
    phase: &'static str,
    elapsed: Duration,
}

fn record_event(
    events: &Arc<std::sync::Mutex<Vec<RequestEvent>>>,
    request_id: i64,
    phase: &'static str,
    start: Instant,
) {
    let elapsed = start.elapsed();
    let mut guard = events.lock().expect("events lock poisoned");
    guard.push(RequestEvent {
        request_id,
        phase,
        elapsed,
    });
    info!(
        target: targets::SESSION,
        "e2e event request_id={} phase={} elapsed_ms={}",
        request_id,
        phase,
        elapsed.as_millis()
    );
}

/// A tool that logs start/cancel/finish events with timing.
struct LoggingBlockingTool {
    barrier: Arc<Barrier>,
    events: Arc<std::sync::Mutex<Vec<RequestEvent>>>,
    start: Instant,
}

#[derive(Debug)]
struct RecordingMiddleware {
    name: &'static str,
    events: Arc<std::sync::Mutex<Vec<String>>>,
}

impl RecordingMiddleware {
    fn new(name: &'static str, events: Arc<std::sync::Mutex<Vec<String>>>) -> Self {
        Self { name, events }
    }

    fn record(&self, phase: &str) {
        let mut guard = self.events.lock().expect("events lock poisoned");
        guard.push(format!("{}:{}", self.name, phase));
    }
}

impl Middleware for RecordingMiddleware {
    fn on_request(
        &self,
        _ctx: &McpContext,
        _request: &fastmcp_protocol::JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        self.record("req");
        Ok(MiddlewareDecision::Continue)
    }

    fn on_response(
        &self,
        _ctx: &McpContext,
        _request: &fastmcp_protocol::JsonRpcRequest,
        response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        self.record("resp");
        Ok(response)
    }

    fn on_error(
        &self,
        _ctx: &McpContext,
        _request: &fastmcp_protocol::JsonRpcRequest,
        error: McpError,
    ) -> McpError {
        self.record("err");
        error
    }
}

#[derive(Debug)]
struct StepMiddleware {
    name: &'static str,
    events: Arc<std::sync::Mutex<Vec<String>>>,
    respond: bool,
}

impl StepMiddleware {
    fn new(name: &'static str, events: Arc<std::sync::Mutex<Vec<String>>>, respond: bool) -> Self {
        Self {
            name,
            events,
            respond,
        }
    }

    fn record(&self, phase: &str) {
        let mut guard = self.events.lock().expect("events lock poisoned");
        guard.push(format!("{}:{}", self.name, phase));
    }
}

impl Middleware for StepMiddleware {
    fn on_request(
        &self,
        _ctx: &McpContext,
        _request: &fastmcp_protocol::JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        self.record("req");
        if self.respond {
            return Ok(MiddlewareDecision::Respond(serde_json::json!({
                "steps": [format!("{}:respond", self.name)]
            })));
        }
        Ok(MiddlewareDecision::Continue)
    }

    fn on_response(
        &self,
        _ctx: &McpContext,
        _request: &fastmcp_protocol::JsonRpcRequest,
        response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        self.record("resp");
        Ok(push_step(response, &format!("{}:resp", self.name)))
    }

    fn on_error(
        &self,
        _ctx: &McpContext,
        _request: &fastmcp_protocol::JsonRpcRequest,
        error: McpError,
    ) -> McpError {
        self.record("err");
        error
    }
}

#[test]
fn request_id_to_u64_number() {
    let id = RequestId::Number(42);
    assert_eq!(crate::request_id_to_u64(Some(&id)), 42);
}

#[test]
fn request_id_to_u64_negative_number() {
    let id = RequestId::Number(-1);
    assert_eq!(crate::request_id_to_u64(Some(&id)), (-1i64) as u64);
}

#[test]
fn request_id_to_u64_string_stable_nonzero() {
    let id = RequestId::String("abc".to_string());
    let first = crate::request_id_to_u64(Some(&id));
    let second = crate::request_id_to_u64(Some(&id));
    assert_eq!(first, second);
    assert_ne!(first, 0);
}

#[test]
fn request_id_to_u64_none_is_zero() {
    assert_eq!(crate::request_id_to_u64(None), 0);
}

#[derive(Debug)]
struct FailingRequestMiddleware {
    name: &'static str,
    events: Arc<std::sync::Mutex<Vec<String>>>,
    error: McpError,
}

impl FailingRequestMiddleware {
    fn new(
        name: &'static str,
        events: Arc<std::sync::Mutex<Vec<String>>>,
        error: McpError,
    ) -> Self {
        Self {
            name,
            events,
            error,
        }
    }

    fn record(&self, phase: &str) {
        let mut guard = self.events.lock().expect("events lock poisoned");
        guard.push(format!("{}:{}", self.name, phase));
    }
}

impl Middleware for FailingRequestMiddleware {
    fn on_request(
        &self,
        _ctx: &McpContext,
        _request: &fastmcp_protocol::JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        self.record("req");
        Err(self.error.clone())
    }

    fn on_response(
        &self,
        _ctx: &McpContext,
        _request: &fastmcp_protocol::JsonRpcRequest,
        response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        self.record("resp");
        Ok(response)
    }

    fn on_error(
        &self,
        _ctx: &McpContext,
        _request: &fastmcp_protocol::JsonRpcRequest,
        error: McpError,
    ) -> McpError {
        self.record("err");
        error
    }
}

fn push_step(value: serde_json::Value, step: &str) -> serde_json::Value {
    let mut obj = match value {
        serde_json::Value::Object(map) => map,
        other => {
            let mut map = serde_json::Map::new();
            map.insert("value".to_string(), other);
            map
        }
    };
    let mut steps = obj
        .get("steps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    steps.push(serde_json::Value::String(step.to_string()));
    obj.insert("steps".to_string(), serde_json::Value::Array(steps));
    serde_json::Value::Object(obj)
}

impl ToolHandler for LoggingBlockingTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "block_until_cancelled_logged".to_string(),
            description: Some("Blocks until cancellation; records timing logs".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "request_id": { "type": "integer" } }
            }),
            icon: None,
        }
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let request_id = arguments
            .get("request_id")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| McpError::invalid_params("missing request_id"))?;

        record_event(&self.events, request_id, "start", self.start);
        self.barrier.wait();

        loop {
            if ctx.checkpoint().is_err() || ctx.is_cancelled() {
                record_event(&self.events, request_id, "cancelled", self.start);
                break;
            }
            std::thread::yield_now();
        }

        record_event(&self.events, request_id, "finish", self.start);
        Err(McpError::request_cancelled())
    }
}

/// A tool that returns an error.
struct ErrorTool;

impl ToolHandler for ErrorTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "error_tool".to_string(),
            description: Some("Always returns an error".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            icon: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Err(McpError::internal_error("Intentional error for testing"))
    }
}

// ============================================================================
// Test Resource Handlers
// ============================================================================

/// A simple static resource.
struct StaticResource {
    uri: String,
    content: String,
}

impl ResourceHandler for StaticResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: self.uri.clone(),
            name: "Static Resource".to_string(),
            description: Some("A static test resource".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Ok(vec![ResourceContent {
            uri: self.uri.clone(),
            mime_type: Some("text/plain".to_string()),
            text: Some(self.content.clone()),
            blob: None,
        }])
    }
}

/// A resource that checks cancellation.
struct CancellableResource;

impl ResourceHandler for CancellableResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: "resource://cancellable".to_string(),
            name: "Cancellable Resource".to_string(),
            description: Some("A resource that checks cancellation".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
        }
    }

    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        if ctx.is_cancelled() {
            return Err(McpError::request_cancelled());
        }
        Ok(vec![ResourceContent {
            uri: "resource://cancellable".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some("Resource content".to_string()),
            blob: None,
        }])
    }
}

/// A resource with a URI template that echoes the matched parameter.
struct TemplateResource;

impl ResourceHandler for TemplateResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: "resource://{id}".to_string(),
            name: "Template Resource".to_string(),
            description: Some("Template resource for tests".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
        }
    }

    fn template(&self) -> Option<ResourceTemplate> {
        Some(ResourceTemplate {
            uri_template: "resource://{id}".to_string(),
            name: "Template Resource".to_string(),
            description: Some("Template resource for tests".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
        })
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Err(McpError::invalid_params(
            "uri parameters required for template resource",
        ))
    }

    fn read_with_uri(
        &self,
        _ctx: &McpContext,
        uri: &str,
        params: &UriParams,
    ) -> McpResult<Vec<ResourceContent>> {
        let id = params
            .get("id")
            .ok_or_else(|| McpError::invalid_params("missing uri parameter: id"))?;
        Ok(vec![ResourceContent {
            uri: uri.to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some(format!("Template {id}")),
            blob: None,
        }])
    }
}

/// A more specific template resource for precedence tests.
struct SpecificTemplateResource;

impl ResourceHandler for SpecificTemplateResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: "resource://foo/{id}".to_string(),
            name: "Specific Template Resource".to_string(),
            description: Some("Specific template resource for tests".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
        }
    }

    fn template(&self) -> Option<ResourceTemplate> {
        Some(ResourceTemplate {
            uri_template: "resource://foo/{id}".to_string(),
            name: "Specific Template Resource".to_string(),
            description: Some("Specific template resource for tests".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
        })
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Err(McpError::invalid_params(
            "uri parameters required for specific template resource",
        ))
    }

    fn read_with_uri(
        &self,
        _ctx: &McpContext,
        uri: &str,
        params: &UriParams,
    ) -> McpResult<Vec<ResourceContent>> {
        let id = params
            .get("id")
            .ok_or_else(|| McpError::invalid_params("missing uri parameter: id"))?;
        Ok(vec![ResourceContent {
            uri: uri.to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some(format!("Specific {id}")),
            blob: None,
        }])
    }
}

#[derive(Debug, Clone)]
struct TemplateLogEntry {
    template: String,
    uri: String,
    params: UriParams,
    response: String,
}

/// A template resource that logs chosen template, params, and response payload.
struct LoggingTemplateResource {
    template: &'static str,
    events: Arc<std::sync::Mutex<Vec<TemplateLogEntry>>>,
}

impl ResourceHandler for LoggingTemplateResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: self.template.to_string(),
            name: "Logging Template Resource".to_string(),
            description: Some("Template resource that logs matches".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
        }
    }

    fn template(&self) -> Option<ResourceTemplate> {
        Some(ResourceTemplate {
            uri_template: self.template.to_string(),
            name: "Logging Template Resource".to_string(),
            description: Some("Template resource that logs matches".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
        })
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Err(McpError::invalid_params(
            "uri parameters required for logging template resource",
        ))
    }

    fn read_with_uri(
        &self,
        _ctx: &McpContext,
        uri: &str,
        params: &UriParams,
    ) -> McpResult<Vec<ResourceContent>> {
        let response = format!(
            "Logged {}",
            params.get("path").map(String::as_str).unwrap_or_default()
        );
        let entry = TemplateLogEntry {
            template: self.template.to_string(),
            uri: uri.to_string(),
            params: params.clone(),
            response: response.clone(),
        };
        let mut guard = self.events.lock().expect("template log lock poisoned");
        guard.push(entry);

        info!(
            target: targets::SESSION,
            "e2e template={} uri={} params={:?} response={}",
            self.template,
            uri,
            params,
            response
        );

        Ok(vec![ResourceContent {
            uri: uri.to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some(response),
            blob: None,
        }])
    }
}

// ============================================================================
// Test Prompt Handlers
// ============================================================================

/// A simple greeting prompt.
struct GreetingPrompt;

impl PromptHandler for GreetingPrompt {
    fn definition(&self) -> Prompt {
        Prompt {
            name: "greeting".to_string(),
            description: Some("A simple greeting prompt".to_string()),
            arguments: vec![PromptArgument {
                name: "name".to_string(),
                description: Some("Name to greet".to_string()),
                required: true,
            }],
            icon: None,
        }
    }

    fn get(
        &self,
        _ctx: &McpContext,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        let name = arguments.get("name").map_or("User", String::as_str);
        Ok(vec![PromptMessage {
            role: Role::User,
            content: Content::Text {
                text: format!("Please greet {name} warmly."),
            },
        }])
    }
}

// ============================================================================
// Router Tests
// ============================================================================

#[cfg(test)]
mod router_tests {
    use super::*;
    use fastmcp_protocol::ListResourceTemplatesParams;

    /// Creates a test router with all handlers registered.
    fn create_test_router() -> Router {
        let mut router = Router::new();

        // Register tools
        router.add_tool(GreetTool);
        router.add_tool(CancellationCheckTool);
        router.add_tool(SlowTool);
        router.add_tool(ErrorTool);

        // Register resources
        router.add_resource(StaticResource {
            uri: "resource://test".to_string(),
            content: "Test content".to_string(),
        });
        router.add_resource(CancellableResource);
        router.add_resource(TemplateResource);

        // Register resource templates
        router.add_resource_template(ResourceTemplate {
            uri_template: "resource://{name}".to_string(),
            name: "Manual Template".to_string(),
            description: Some("Resource template for manual listing".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
        });

        // Register prompts
        router.add_prompt(GreetingPrompt);

        router
    }

    /// Creates a test session.
    fn create_test_session() -> Session {
        Session::new(
            ServerInfo {
                name: "test-server".to_string(),
                version: "1.0.0".to_string(),
            },
            ServerCapabilities::default(),
        )
    }

    #[test]
    fn test_middleware_ordering_on_response() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server = Server::new("test-server", "1.0.0")
            .tool(GreetTool)
            .middleware(RecordingMiddleware::new("A", Arc::clone(&events)))
            .middleware(RecordingMiddleware::new("B", Arc::clone(&events)))
            .build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();
        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let sender: NotificationSender = Arc::new(|_| {});
        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": "Ada"})),
            meta: None,
        };
        let request = fastmcp_protocol::JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::to_value(params).expect("params")),
            1,
        );
        let response = server
            .handle_request(
                &cx,
                &mut session,
                request,
                &sender,
                &create_test_request_sender(),
            )
            .expect("response");

        assert!(response.error.is_none(), "expected successful response");
        let recorded = events.lock().expect("events lock poisoned").clone();
        assert_eq!(recorded, vec!["A:req", "B:req", "B:resp", "A:resp"]);
    }

    #[test]
    fn test_middleware_short_circuit_runs_response_stack() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server = Server::new("test-server", "1.0.0")
            .tool(GreetTool)
            .middleware(StepMiddleware::new("A", Arc::clone(&events), false))
            .middleware(StepMiddleware::new("B", Arc::clone(&events), true))
            .build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();
        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let sender: NotificationSender = Arc::new(|_| {});
        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": "Ignored"})),
            meta: None,
        };
        let request = fastmcp_protocol::JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::to_value(params).expect("params")),
            2,
        );
        let response = server
            .handle_request(
                &cx,
                &mut session,
                request,
                &sender,
                &create_test_request_sender(),
            )
            .expect("response");

        let result = response.result.expect("short-circuit result");
        let steps = result
            .get("steps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect::<Vec<_>>();
        assert_eq!(
            steps,
            vec![
                "B:respond".to_string(),
                "B:resp".to_string(),
                "A:resp".to_string()
            ]
        );

        let recorded = events.lock().expect("events lock poisoned").clone();
        assert_eq!(recorded, vec!["A:req", "B:req", "B:resp", "A:resp"]);
    }

    #[test]
    fn test_middleware_error_propagation_order() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server = Server::new("test-server", "1.0.0")
            .tool(GreetTool)
            .middleware(RecordingMiddleware::new("A", Arc::clone(&events)))
            .middleware(FailingRequestMiddleware::new(
                "B",
                Arc::clone(&events),
                McpError::invalid_request("middleware error"),
            ))
            .build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();
        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let sender: NotificationSender = Arc::new(|_| {});
        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": "Ada"})),
            meta: None,
        };
        let request = fastmcp_protocol::JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::to_value(params).expect("params")),
            3,
        );
        let response = server
            .handle_request(
                &cx,
                &mut session,
                request,
                &sender,
                &create_test_request_sender(),
            )
            .expect("response");

        assert!(response.is_error(), "expected error response");
        let recorded = events.lock().expect("events lock poisoned").clone();
        assert_eq!(recorded, vec!["A:req", "B:req", "B:err", "A:err"]);
    }

    #[test]
    fn test_middleware_response_mutation() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server = Server::new("test-server", "1.0.0")
            .tool(GreetTool)
            .middleware(StepMiddleware::new("A", Arc::clone(&events), false))
            .middleware(StepMiddleware::new("B", Arc::clone(&events), false))
            .build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();
        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let sender: NotificationSender = Arc::new(|_| {});
        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": "Ada"})),
            meta: None,
        };
        let request = fastmcp_protocol::JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::to_value(params).expect("params")),
            4,
        );
        let response = server
            .handle_request(
                &cx,
                &mut session,
                request,
                &sender,
                &create_test_request_sender(),
            )
            .expect("response");

        let result = response.result.expect("result");
        let steps = result
            .get("steps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect::<Vec<_>>();
        assert_eq!(steps, vec!["B:resp".to_string(), "A:resp".to_string()]);
    }

    #[test]
    fn test_e2e_middleware_stack_logging() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server = Server::new("test-server", "1.0.0")
            .tool(GreetTool)
            .middleware(StepMiddleware::new("A", Arc::clone(&events), false))
            .middleware(StepMiddleware::new("B", Arc::clone(&events), false))
            .build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();
        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let sender: NotificationSender = Arc::new(|_| {});
        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": "E2E"})),
            meta: None,
        };
        let request = fastmcp_protocol::JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::to_value(params).expect("params")),
            5,
        );
        let response = server
            .handle_request(
                &cx,
                &mut session,
                request,
                &sender,
                &create_test_request_sender(),
            )
            .expect("response");

        let ts = chrono::Utc::now().to_rfc3339();
        let recorded = events.lock().expect("events lock poisoned").clone();
        info!(
            target: targets::SESSION,
            "e2e middleware hooks ts={} order={:?}",
            ts,
            recorded
        );
        info!(
            target: targets::SESSION,
            "e2e middleware response ts={} payload={:?}",
            ts,
            response.result
        );

        assert_eq!(recorded, vec!["A:req", "B:req", "B:resp", "A:resp"]);
        assert!(
            response.result.is_some(),
            "expected middleware response payload"
        );
    }

    #[test]
    fn test_auth_request_access_token_parsing() {
        let params = serde_json::json!({"authorization": "Bearer alpha"});
        let request = AuthRequest {
            method: "tools/list",
            params: Some(&params),
            request_id: 10,
        };
        let access = request.access_token().expect("missing access credential");
        assert_eq!(access.scheme, "Bearer");
        assert_eq!(access.token, "alpha");

        let params = serde_json::json!({"auth": {"token": "beta"}});
        let request = AuthRequest {
            method: "tools/list",
            params: Some(&params),
            request_id: 11,
        };
        let access = request.access_token().expect("missing access credential");
        assert_eq!(access.scheme, "Bearer");
        assert_eq!(access.token, "beta");
    }

    #[test]
    fn test_token_auth_provider_allows_and_denies() {
        let verifier =
            StaticTokenVerifier::new([("good-token", AuthContext::with_subject("user-1"))])
                .with_allowed_schemes(["Bearer"]);
        let provider = TokenAuthProvider::new(verifier);

        let server = Server::new("test-server", "1.0.0")
            .tool(GreetTool)
            .auth_provider(provider)
            .build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();
        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let sender: NotificationSender = Arc::new(|_| {});
        let request = fastmcp_protocol::JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "name": "greet",
                "arguments": { "name": "Ada" },
                "auth": "Bearer good-token"
            })),
            6,
        );
        let response = server
            .handle_request(
                &cx,
                &mut session,
                request,
                &sender,
                &create_test_request_sender(),
            )
            .expect("response");
        assert!(response.error.is_none(), "expected authorized response");

        let request = fastmcp_protocol::JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "name": "greet",
                "arguments": { "name": "Ada" },
                "auth": "Bearer bad-token"
            })),
            7,
        );
        let response = server
            .handle_request(
                &cx,
                &mut session,
                request,
                &sender,
                &create_test_request_sender(),
            )
            .expect("response");
        assert!(response.is_error(), "expected auth error");
        let error = response.error.expect("error payload");
        assert_eq!(error.code, i32::from(McpErrorCode::ResourceForbidden));
    }

    #[test]
    fn test_auth_provider_protects_resource_access() {
        let verifier = StaticTokenVerifier::new([(
            "resource-token",
            AuthContext::with_subject("resource-user"),
        )]);
        let provider = TokenAuthProvider::new(verifier);

        let server = Server::new("test-server", "1.0.0")
            .resource(StaticResource {
                uri: "resource://secure".to_string(),
                content: "secret".to_string(),
            })
            .auth_provider(provider)
            .build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();
        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let sender: NotificationSender = Arc::new(|_| {});
        let request = fastmcp_protocol::JsonRpcRequest::new(
            "resources/read",
            Some(serde_json::json!({"uri": "resource://secure"})),
            8,
        );
        let response = server
            .handle_request(
                &cx,
                &mut session,
                request,
                &sender,
                &create_test_request_sender(),
            )
            .expect("response");
        assert!(response.is_error(), "expected auth error");

        let request = fastmcp_protocol::JsonRpcRequest::new(
            "resources/read",
            Some(serde_json::json!({
                "uri": "resource://secure",
                "auth": "Bearer resource-token"
            })),
            9,
        );
        let response = server
            .handle_request(
                &cx,
                &mut session,
                request,
                &sender,
                &create_test_request_sender(),
            )
            .expect("response");
        assert!(response.error.is_none(), "expected authorized response");
    }

    #[test]
    fn test_e2e_auth_decisions_logged() {
        let verifier = StaticTokenVerifier::new([("good", AuthContext::with_subject("user-e2e"))]);
        let provider = TokenAuthProvider::new(verifier);

        let server = Server::new("test-server", "1.0.0")
            .tool(GreetTool)
            .auth_provider(provider)
            .build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();
        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let sender: NotificationSender = Arc::new(|_| {});
        let ts = chrono::Utc::now().to_rfc3339();

        let unauthorized = fastmcp_protocol::JsonRpcRequest::new(
            "tools/list",
            Some(serde_json::json!({ "cursor": null })),
            12,
        );
        let unauthorized_response = server
            .handle_request(
                &cx,
                &mut session,
                unauthorized,
                &sender,
                &create_test_request_sender(),
            )
            .expect("response");
        info!(
            target: targets::SESSION,
            "e2e auth unauthorized ts={} error={:?}",
            ts,
            unauthorized_response.error
        );
        assert!(unauthorized_response.is_error());

        let authorized = fastmcp_protocol::JsonRpcRequest::new(
            "tools/list",
            Some(serde_json::json!({ "cursor": null, "auth": "Bearer good" })),
            13,
        );
        let authorized_response = server
            .handle_request(
                &cx,
                &mut session,
                authorized,
                &sender,
                &create_test_request_sender(),
            )
            .expect("response");
        info!(
            target: targets::SESSION,
            "e2e auth authorized ts={} result={:?}",
            ts,
            authorized_response.result
        );
        assert!(authorized_response.error.is_none());
    }

    #[test]
    fn test_router_tool_list() {
        let router = create_test_router();
        let tools = router.tools();

        assert_eq!(tools.len(), 4);

        let tool_names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(tool_names.contains(&"greet"));
        assert!(tool_names.contains(&"cancellation_check"));
        assert!(tool_names.contains(&"slow_tool"));
        assert!(tool_names.contains(&"error_tool"));
    }

    #[test]
    fn test_router_resource_list() {
        let router = create_test_router();
        let resources = router.resources();

        assert_eq!(resources.len(), 2);

        let resource_uris: Vec<_> = resources.iter().map(|r| r.uri.as_str()).collect();
        assert!(resource_uris.contains(&"resource://test"));
        assert!(resource_uris.contains(&"resource://cancellable"));
    }

    #[test]
    fn test_router_resource_template_list() {
        let router = create_test_router();
        let templates = router.resource_templates();

        assert_eq!(templates.len(), 2);

        let template_uris: Vec<_> = templates
            .iter()
            .map(|template| template.uri_template.as_str())
            .collect();
        assert!(template_uris.contains(&"resource://{id}"));
        assert!(template_uris.contains(&"resource://{name}"));
    }

    #[test]
    fn test_handle_resource_templates_list_sorted() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let params = ListResourceTemplatesParams { cursor: None };

        let result = router.handle_resource_templates_list(&cx, params);
        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result.err());
        let templates = result.unwrap().resource_templates;

        assert_eq!(templates.len(), 2);
        assert_eq!(templates[0].uri_template, "resource://{id}");
        assert_eq!(templates[0].name, "Template Resource");
        assert_eq!(
            templates[0].description.as_deref(),
            Some("Template resource for tests")
        );
        assert_eq!(templates[0].mime_type.as_deref(), Some("text/plain"));
        assert_eq!(templates[1].uri_template, "resource://{name}");
        assert_eq!(templates[1].name, "Manual Template");
        assert_eq!(
            templates[1].description.as_deref(),
            Some("Resource template for manual listing")
        );
        assert_eq!(templates[1].mime_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn test_e2e_resource_templates_list_logs_response() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let params = ListResourceTemplatesParams { cursor: None };

        let result = router
            .handle_resource_templates_list(&cx, params)
            .expect("resource templates list");

        info!(
            target: targets::SESSION,
            "e2e resources/templates/list response={:?}",
            result
        );

        assert!(!result.resource_templates.is_empty());
    }

    #[test]
    fn test_handle_tasks_submit_get_list_cancel() {
        let router = Router::new();
        let manager = TaskManager::new_for_testing();
        manager.register_handler("demo_task", |_cx, _params| async {
            Ok(serde_json::json!({"ok": true}))
        });
        let shared = manager.into_shared();

        let cx = Cx::for_testing();

        let submit = router
            .handle_tasks_submit(
                &cx,
                SubmitTaskParams {
                    task_type: "demo_task".to_string(),
                    params: None,
                },
                Some(&shared),
            )
            .expect("submit task");

        assert_eq!(submit.task.status, TaskStatus::Pending);
        let task_id = submit.task.id.clone();

        let list = router
            .handle_tasks_list(
                &cx,
                ListTasksParams {
                    status: None,
                    cursor: None,
                },
                Some(&shared),
            )
            .expect("list tasks");
        assert_eq!(list.tasks.len(), 1);

        let get = router
            .handle_tasks_get(
                &cx,
                GetTaskParams {
                    id: task_id.clone(),
                },
                Some(&shared),
            )
            .expect("get task");
        assert_eq!(get.task.id, task_id);
        assert!(get.result.is_none());

        let cancel = router
            .handle_tasks_cancel(
                &cx,
                CancelTaskParams {
                    id: task_id.clone(),
                    reason: Some("stop".to_string()),
                },
                Some(&shared),
            )
            .expect("cancel task");
        assert_eq!(cancel.task.status, TaskStatus::Cancelled);

        let list_cancelled = router
            .handle_tasks_list(
                &cx,
                ListTasksParams {
                    status: Some(TaskStatus::Cancelled),
                    cursor: None,
                },
                Some(&shared),
            )
            .expect("list cancelled");
        assert_eq!(list_cancelled.tasks.len(), 1);
    }

    #[test]
    fn test_e2e_task_manager_state_logging() {
        let router = Router::new();
        let manager = TaskManager::new_for_testing();
        manager.register_handler("log_task", |_cx, _params| async {
            Ok(serde_json::json!({"ok": true}))
        });
        let shared = manager.into_shared();

        let cx = Cx::for_testing();
        let submit = router
            .handle_tasks_submit(
                &cx,
                SubmitTaskParams {
                    task_type: "log_task".to_string(),
                    params: Some(serde_json::json!({"payload": 1})),
                },
                Some(&shared),
            )
            .expect("submit task");

        info!(
            target: targets::SESSION,
            "e2e task transition ts={} status={:?} id={}",
            chrono::Utc::now().to_rfc3339(),
            submit.task.status,
            submit.task.id
        );

        shared.start_task(&submit.task.id).expect("start task");
        info!(
            target: targets::SESSION,
            "e2e task transition ts={} status={:?} id={}",
            chrono::Utc::now().to_rfc3339(),
            TaskStatus::Running,
            submit.task.id
        );

        shared.complete_task(&submit.task.id, serde_json::json!({"ok": true}));
        info!(
            target: targets::SESSION,
            "e2e task transition ts={} status={:?} id={}",
            chrono::Utc::now().to_rfc3339(),
            TaskStatus::Completed,
            submit.task.id
        );

        let get = router
            .handle_tasks_get(
                &cx,
                GetTaskParams {
                    id: submit.task.id.clone(),
                },
                Some(&shared),
            )
            .expect("get task after completion");

        info!(
            target: targets::SESSION,
            "e2e tasks/get response={:?}",
            get
        );
    }

    #[test]
    fn test_e2e_task_lifecycle_with_cancel_logging() {
        let router = Router::new();
        let manager = TaskManager::new_for_testing();
        manager.register_handler("long_task", |_cx, _params| async {
            Ok(serde_json::json!({"ok": true}))
        });
        let shared = manager.into_shared();

        let cx = Cx::for_testing();
        let submit = router
            .handle_tasks_submit(
                &cx,
                SubmitTaskParams {
                    task_type: "long_task".to_string(),
                    params: Some(serde_json::json!({"duration": 10})),
                },
                Some(&shared),
            )
            .expect("submit long task");

        info!(
            target: targets::SESSION,
            "e2e task submit ts={} id={}",
            chrono::Utc::now().to_rfc3339(),
            submit.task.id
        );

        shared.start_task(&submit.task.id).expect("start long task");
        shared.update_progress(&submit.task.id, 0.2, Some("starting".to_string()));

        let list = router
            .handle_tasks_list(
                &cx,
                ListTasksParams {
                    status: None,
                    cursor: None,
                },
                Some(&shared),
            )
            .expect("list tasks");
        info!(
            target: targets::SESSION,
            "e2e tasks/list ts={} count={}",
            chrono::Utc::now().to_rfc3339(),
            list.tasks.len()
        );

        let get = router
            .handle_tasks_get(
                &cx,
                GetTaskParams {
                    id: submit.task.id.clone(),
                },
                Some(&shared),
            )
            .expect("get task");
        info!(
            target: targets::SESSION,
            "e2e tasks/get ts={} status={:?}",
            chrono::Utc::now().to_rfc3339(),
            get.task.status
        );

        let cancel = router
            .handle_tasks_cancel(
                &cx,
                CancelTaskParams {
                    id: submit.task.id.clone(),
                    reason: Some("test cancel".to_string()),
                },
                Some(&shared),
            )
            .expect("cancel task");
        info!(
            target: targets::SESSION,
            "e2e task cancel ts={} status={:?}",
            chrono::Utc::now().to_rfc3339(),
            cancel.task.status
        );

        assert_eq!(cancel.task.status, TaskStatus::Cancelled);
    }

    #[test]
    fn test_e2e_task_status_notifications_logged() {
        let manager = TaskManager::new_for_testing();
        manager.register_handler("notify_task", |_cx, _params| async {
            Ok(serde_json::json!({"ok": true}))
        });
        let shared = manager.into_shared();

        let server = Server::new("test-server", "1.0.0")
            .with_task_manager(shared.clone())
            .build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();
        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let notifications: Arc<std::sync::Mutex<Vec<TaskStatusNotificationParams>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let notifications_clone = Arc::clone(&notifications);
        let sender: NotificationSender = Arc::new(move |request| {
            if request.method != "notifications/tasks/status" {
                return;
            }
            let params: TaskStatusNotificationParams = request
                .params
                .as_ref()
                .and_then(|value| serde_json::from_value(value.clone()).ok())
                .expect("task status params");
            notifications_clone
                .lock()
                .expect("notifications lock poisoned")
                .push(params);
        });

        let submit = fastmcp_protocol::JsonRpcRequest::new(
            "tasks/submit",
            Some(serde_json::json!({"taskType": "notify_task"})),
            20,
        );
        let response = server
            .handle_request(
                &cx,
                &mut session,
                submit,
                &sender,
                &create_test_request_sender(),
            )
            .expect("submit response");
        let task_id = response
            .result
            .as_ref()
            .and_then(|value| value.get("task"))
            .and_then(|value| value.get("id"))
            .and_then(|value| value.as_str())
            .map(TaskId::from_string)
            .expect("task id");

        shared.start_task(&task_id).expect("start task");
        shared.update_progress(&task_id, 0.25, Some("quarter".to_string()));
        shared.complete_task(&task_id, serde_json::json!({"ok": true}));

        let recorded = notifications.lock().expect("notifications lock poisoned");
        info!(
            target: targets::SESSION,
            "e2e task notifications ts={} count={}",
            chrono::Utc::now().to_rfc3339(),
            recorded.len()
        );
        assert!(
            recorded.iter().any(|evt| evt.status == TaskStatus::Pending),
            "expected pending notification"
        );
        assert!(
            recorded.iter().any(|evt| evt.status == TaskStatus::Running),
            "expected running notification"
        );
        assert!(
            recorded.iter().any(|evt| evt.progress == Some(0.25)),
            "expected progress notification"
        );
        assert!(
            recorded
                .iter()
                .any(|evt| evt.status == TaskStatus::Completed),
            "expected completed notification"
        );
    }

    #[test]
    fn test_router_prompt_list() {
        let router = create_test_router();
        let prompts = router.prompts();

        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "greeting");
    }

    #[test]
    fn test_notification_does_not_return_response() {
        let server = Server::new("test-server", "1.0.0").build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();

        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let sender: NotificationSender = std::sync::Arc::new(|_| {});
        let params = CancelledParams {
            request_id: RequestId::Number(1),
            reason: Some("unit test".to_string()),
            await_cleanup: None,
        };
        let request = fastmcp_protocol::JsonRpcRequest::notification(
            "notifications/cancelled",
            Some(serde_json::to_value(params).unwrap()),
        );

        let response = server.handle_request(
            &cx,
            &mut session,
            request,
            &sender,
            &create_test_request_sender(),
        );
        assert!(response.is_none());
    }

    #[test]
    fn test_cancelled_notification_marks_request_cancelled() {
        let server = Server::new("test-server", "1.0.0").build();
        let request_id = RequestId::Number(99);
        let cx = Cx::for_testing();

        let completion = Arc::new(RequestCompletion::new());
        {
            let mut guard = server
                .active_requests
                .lock()
                .expect("active_requests lock poisoned");
            guard.insert(
                request_id.clone(),
                ActiveRequest::new(cx.clone(), completion),
            );
        }

        let params = CancelledParams {
            request_id: request_id.clone(),
            reason: Some("test cancellation".to_string()),
            await_cleanup: None,
        };
        server.handle_cancelled_notification(params);

        assert!(cx.is_cancel_requested());
    }

    #[test]
    fn test_cancelled_notification_await_cleanup_waits_for_completion() {
        let server = Server::new("test-server", "1.0.0").build();
        let request_id = RequestId::Number(100);
        let cx = Cx::for_testing();
        let completion = Arc::new(RequestCompletion::new());

        {
            let mut guard = server
                .active_requests
                .lock()
                .expect("active_requests lock poisoned");
            guard.insert(
                request_id.clone(),
                ActiveRequest::new(cx.clone(), completion.clone()),
            );
        }

        let completion_for_thread = completion.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            completion_for_thread.mark_done();
        });

        let params = CancelledParams {
            request_id: request_id.clone(),
            reason: Some("await cleanup".to_string()),
            await_cleanup: Some(true),
        };
        server.handle_cancelled_notification(params);

        assert!(completion.is_done());
        assert!(cx.is_cancel_requested());
    }

    #[test]
    fn test_active_request_guard_registers_and_cleans_up() {
        let server = Server::new("test-server", "1.0.0").build();
        let request_id = RequestId::Number(77);
        let cx = Cx::for_testing();

        let guard =
            ActiveRequestGuard::new(&server.active_requests, request_id.clone(), cx.clone());
        {
            let guard_map = server
                .active_requests
                .lock()
                .expect("active_requests lock poisoned");
            let entry = guard_map.get(&request_id).expect("active request missing");
            assert_eq!(entry.region_id, cx.region_id());
            assert!(!entry.completion.is_done());
        }
        drop(guard);

        let guard_map = server
            .active_requests
            .lock()
            .expect("active_requests lock poisoned");
        assert!(!guard_map.contains_key(&request_id));
    }

    #[test]
    fn test_active_request_registry_concurrent_add_remove() {
        let server = Arc::new(Server::new("test-server", "1.0.0").build());
        let thread_count = 4usize;
        let ready = Arc::new(Barrier::new(thread_count + 1));
        let mut release_txs = Vec::new();
        let mut handles = Vec::new();
        let mut cxs = Vec::new();

        for i in 0..thread_count {
            let request_id =
                RequestId::Number(i64::try_from(i + 1).expect("request id fits in i64"));
            let cx = Cx::for_testing();
            cxs.push(cx.clone());

            let (release_tx, release_rx) = mpsc::channel::<()>();
            release_txs.push(release_tx);

            let server = Arc::clone(&server);
            let ready = Arc::clone(&ready);
            let handle = thread::spawn(move || {
                let _guard =
                    ActiveRequestGuard::new(&server.active_requests, request_id, cx.clone());
                ready.wait();
                let _ = release_rx.recv();
            });
            handles.push(handle);
        }

        ready.wait();

        {
            let guard = server
                .active_requests
                .lock()
                .expect("active_requests lock poisoned");
            assert_eq!(guard.len(), thread_count);
        }

        server.cancel_active_requests(CancelKind::User, false);

        for cx in &cxs {
            assert!(cx.is_cancel_requested());
        }

        for tx in release_txs {
            tx.send(()).expect("release send failed");
        }
        for handle in handles {
            handle.join().expect("worker join failed");
        }

        let guard = server
            .active_requests
            .lock()
            .expect("active_requests lock poisoned");
        assert!(guard.is_empty());
    }

    #[test]
    fn test_cancel_active_requests_waits_for_guard_drop() {
        let server = Arc::new(Server::new("test-server", "1.0.0").build());
        let request_id = RequestId::Number(500);
        let cx = Cx::for_testing();

        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let server_for_worker = Arc::clone(&server);
        let cx_for_worker = cx.clone();
        let worker = thread::spawn(move || {
            let _guard = ActiveRequestGuard::new(
                &server_for_worker.active_requests,
                request_id,
                cx_for_worker,
            );
            ready_tx.send(()).expect("ready send failed");
            let _ = release_rx.recv();
        });

        ready_rx.recv().expect("ready recv failed");

        let (done_tx, done_rx) = mpsc::channel::<()>();
        let server_for_cancel = Arc::clone(&server);
        let canceler = thread::spawn(move || {
            server_for_cancel.cancel_active_requests(CancelKind::User, true);
            done_tx.send(()).expect("done send failed");
        });

        thread::sleep(Duration::from_millis(25));
        assert!(done_rx.try_recv().is_err());

        release_tx.send(()).expect("release send failed");
        worker.join().expect("worker join failed");
        done_rx.recv().expect("done recv failed");
        canceler.join().expect("cancel join failed");

        let guard = server
            .active_requests
            .lock()
            .expect("active_requests lock poisoned");
        assert!(guard.is_empty());
        assert!(cx.is_cancel_requested());
    }

    #[test]
    fn test_server_cancels_inflight_requests() {
        let thread_count = 3usize;
        let barrier = Arc::new(Barrier::new(thread_count + 1));
        let server = Arc::new(
            Server::new("test-server", "1.0.0")
                .tool(BlockingTool {
                    barrier: Arc::clone(&barrier),
                })
                .build(),
        );
        let sender: NotificationSender = Arc::new(|_| {});
        let (tx, rx) = mpsc::channel::<JsonRpcResponse>();

        for i in 0..thread_count {
            let server = Arc::clone(&server);
            let sender = Arc::clone(&sender);
            let tx = tx.clone();
            thread::spawn(move || {
                let cx = Cx::for_testing();
                let mut session = create_test_session();
                session.initialize(
                    ClientInfo {
                        name: "test-client".to_string(),
                        version: "1.0.0".to_string(),
                    },
                    ClientCapabilities::default(),
                    "2024-11-05".to_string(),
                );

                let params = CallToolParams {
                    name: "block_until_cancelled".to_string(),
                    arguments: Some(serde_json::json!({})),
                    meta: None,
                };
                let request = fastmcp_protocol::JsonRpcRequest::new(
                    "tools/call",
                    Some(serde_json::to_value(params).expect("params")),
                    i64::try_from(i + 1).expect("request id fits in i64"),
                );
                let response = server
                    .handle_request(
                        &cx,
                        &mut session,
                        request,
                        &sender,
                        &create_test_request_sender(),
                    )
                    .expect("response");
                tx.send(response).expect("response send failed");
            });
        }

        barrier.wait();

        let start = Instant::now();
        loop {
            let count = server
                .active_requests
                .lock()
                .expect("active_requests lock poisoned")
                .len();
            if count == thread_count {
                break;
            }
            if start.elapsed() > Duration::from_secs(1) {
                assert!(
                    start.elapsed() <= Duration::from_secs(1),
                    "active requests did not register in time"
                );
            }
            thread::yield_now();
        }

        server.cancel_active_requests(CancelKind::User, true);

        for _ in 0..thread_count {
            let response = rx
                .recv_timeout(Duration::from_secs(2))
                .expect("response recv timeout");
            let err = response.error.expect("expected error");
            assert_eq!(err.code, i32::from(McpErrorCode::RequestCancelled));
        }
    }

    #[test]
    fn test_e2e_cancel_drain_logs() {
        let thread_count = 3usize;
        let barrier = Arc::new(Barrier::new(thread_count + 1));
        let events: Arc<std::sync::Mutex<Vec<RequestEvent>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let start = Instant::now();
        let server = Arc::new(
            Server::new("test-server", "1.0.0")
                .tool(LoggingBlockingTool {
                    barrier: Arc::clone(&barrier),
                    events: Arc::clone(&events),
                    start,
                })
                .build(),
        );
        let sender: NotificationSender = Arc::new(|_| {});
        let (tx, rx) = mpsc::channel::<JsonRpcResponse>();

        for i in 0..thread_count {
            let server = Arc::clone(&server);
            let sender = Arc::clone(&sender);
            let tx = tx.clone();
            thread::spawn(move || {
                let cx = Cx::for_testing();
                let mut session = create_test_session();
                session.initialize(
                    ClientInfo {
                        name: "test-client".to_string(),
                        version: "1.0.0".to_string(),
                    },
                    ClientCapabilities::default(),
                    "2024-11-05".to_string(),
                );

                let request_id = i64::try_from(i + 1).expect("request id fits in i64");
                let params = CallToolParams {
                    name: "block_until_cancelled_logged".to_string(),
                    arguments: Some(serde_json::json!({ "request_id": request_id })),
                    meta: None,
                };
                let request = fastmcp_protocol::JsonRpcRequest::new(
                    "tools/call",
                    Some(serde_json::to_value(params).expect("params")),
                    request_id,
                );
                let response = server
                    .handle_request(
                        &cx,
                        &mut session,
                        request,
                        &sender,
                        &create_test_request_sender(),
                    )
                    .expect("response");
                tx.send(response).expect("response send failed");
            });
        }

        barrier.wait();

        let start_wait = Instant::now();
        loop {
            let count = server
                .active_requests
                .lock()
                .expect("active_requests lock poisoned")
                .len();
            if count == thread_count {
                break;
            }
            if start_wait.elapsed() > Duration::from_secs(1) {
                assert!(
                    start_wait.elapsed() <= Duration::from_secs(1),
                    "active requests did not register in time"
                );
            }
            thread::yield_now();
        }

        server.cancel_active_requests(CancelKind::User, true);

        for _ in 0..thread_count {
            let response = rx
                .recv_timeout(Duration::from_secs(2))
                .expect("response recv timeout");
            let err = response.error.expect("expected error");
            assert_eq!(err.code, i32::from(McpErrorCode::RequestCancelled));
        }

        let mut by_request: HashMap<i64, Vec<&RequestEvent>> = HashMap::new();
        let guard = events.lock().expect("events lock poisoned");
        for event in guard.iter() {
            by_request.entry(event.request_id).or_default().push(event);
        }
        assert_eq!(by_request.len(), thread_count);
        for (request_id, events) in by_request {
            let mut phases: Vec<&'static str> = events.iter().map(|e| e.phase).collect();
            phases.sort_unstable();
            phases.dedup();
            assert!(
                phases.contains(&"start")
                    && phases.contains(&"cancelled")
                    && phases.contains(&"finish"),
                "missing phases for request {}: {:?}",
                request_id,
                phases
            );
        }
    }

    #[test]
    fn test_resources_subscribe_and_unsubscribe() {
        let server = Server::new("test-server", "1.0.0")
            .resource(StaticResource {
                uri: "resource://test".to_string(),
                content: "Test content".to_string(),
            })
            .build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();
        let notifications = Arc::new(std::sync::Mutex::new(Vec::new()));

        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let notifications_for_sender = Arc::clone(&notifications);
        let sender: NotificationSender = std::sync::Arc::new(move |req| {
            notifications_for_sender
                .lock()
                .expect("notifications lock poisoned")
                .push(req);
        });
        let subscribe = fastmcp_protocol::JsonRpcRequest::new(
            "resources/subscribe",
            Some(
                serde_json::to_value(fastmcp_protocol::SubscribeResourceParams {
                    uri: "resource://test".to_string(),
                })
                .unwrap(),
            ),
            1i64,
        );
        let response = server
            .handle_request(
                &cx,
                &mut session,
                subscribe,
                &sender,
                &create_test_request_sender(),
            )
            .expect("response");
        assert!(response.error.is_none());
        assert!(session.is_resource_subscribed("resource://test"));

        assert!(session.notify_resource_updated("resource://test", &sender));
        let guard = notifications.lock().expect("notifications lock poisoned");
        assert_eq!(guard.len(), 1);
        assert_eq!(guard[0].method, "notifications/resources/updated");
        let params = guard[0].params.clone().expect("notification params");
        let parsed: ResourceUpdatedNotificationParams =
            serde_json::from_value(params).expect("parse notification params");
        assert_eq!(parsed.uri, "resource://test");
        info!(
            target: targets::SESSION,
            "e2e resource update notification ts={} uri={}",
            chrono::Utc::now().to_rfc3339(),
            parsed.uri
        );
        drop(guard);

        let unsubscribe = fastmcp_protocol::JsonRpcRequest::new(
            "resources/unsubscribe",
            Some(
                serde_json::to_value(fastmcp_protocol::UnsubscribeResourceParams {
                    uri: "resource://test".to_string(),
                })
                .unwrap(),
            ),
            2i64,
        );
        let response = server
            .handle_request(
                &cx,
                &mut session,
                unsubscribe,
                &sender,
                &create_test_request_sender(),
            )
            .expect("response");
        assert!(response.error.is_none());
        assert!(!session.is_resource_subscribed("resource://test"));

        assert!(!session.notify_resource_updated("resource://test", &sender));
        assert_eq!(
            notifications
                .lock()
                .expect("notifications lock poisoned")
                .len(),
            1
        );
    }

    #[test]
    fn test_logging_set_level_emits_notifications() {
        let server = Server::new("test-server", "1.0.0").tool(GreetTool).build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();
        let notifications = Arc::new(std::sync::Mutex::new(Vec::new()));

        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let notifications_for_sender = Arc::clone(&notifications);
        let sender: NotificationSender = std::sync::Arc::new(move |req| {
            notifications_for_sender
                .lock()
                .expect("notifications lock poisoned")
                .push(req);
        });

        let set_level = fastmcp_protocol::JsonRpcRequest::new(
            "logging/setLevel",
            Some(
                serde_json::to_value(SetLogLevelParams {
                    level: LogLevel::Info,
                })
                .expect("set level params"),
            ),
            1i64,
        );
        let _ = server
            .handle_request(
                &cx,
                &mut session,
                set_level,
                &sender,
                &create_test_request_sender(),
            )
            .expect("set level response");

        let call = fastmcp_protocol::JsonRpcRequest::new(
            "tools/call",
            Some(
                serde_json::to_value(CallToolParams {
                    name: "greet".to_string(),
                    arguments: Some(serde_json::json!({"name": "Ada"})),
                    meta: None,
                })
                .expect("tool params"),
            ),
            2i64,
        );
        let _ = server
            .handle_request(
                &cx,
                &mut session,
                call,
                &sender,
                &create_test_request_sender(),
            )
            .expect("tool call response");

        let guard = notifications.lock().expect("notifications lock poisoned");
        let mut logs = guard
            .iter()
            .filter(|req| req.method == "notifications/message")
            .map(|req| {
                serde_json::from_value::<LogMessageParams>(req.params.clone().expect("log params"))
                    .expect("parse log params")
            })
            .collect::<Vec<_>>();

        assert_eq!(logs.len(), 1);
        let log = logs.pop().expect("log message");
        assert_eq!(log.level, LogLevel::Info);
        let text = log.data.as_str().expect("log data string");
        assert!(text.contains("Handled tools/call"));
        info!(
            target: targets::SESSION,
            "e2e log notification {}",
            text
        );
    }

    #[test]
    fn test_logging_set_level_filters_notifications() {
        let server = Server::new("test-server", "1.0.0").tool(GreetTool).build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();
        let notifications = Arc::new(std::sync::Mutex::new(Vec::new()));

        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let notifications_for_sender = Arc::clone(&notifications);
        let sender: NotificationSender = std::sync::Arc::new(move |req| {
            notifications_for_sender
                .lock()
                .expect("notifications lock poisoned")
                .push(req);
        });

        let set_level = fastmcp_protocol::JsonRpcRequest::new(
            "logging/setLevel",
            Some(
                serde_json::to_value(SetLogLevelParams {
                    level: LogLevel::Error,
                })
                .expect("set level params"),
            ),
            1i64,
        );
        let _ = server
            .handle_request(
                &cx,
                &mut session,
                set_level,
                &sender,
                &create_test_request_sender(),
            )
            .expect("set level response");

        let call = fastmcp_protocol::JsonRpcRequest::new(
            "tools/call",
            Some(
                serde_json::to_value(CallToolParams {
                    name: "greet".to_string(),
                    arguments: Some(serde_json::json!({"name": "Ada"})),
                    meta: None,
                })
                .expect("tool params"),
            ),
            2i64,
        );
        let _ = server
            .handle_request(
                &cx,
                &mut session,
                call,
                &sender,
                &create_test_request_sender(),
            )
            .expect("tool call response");

        let guard = notifications.lock().expect("notifications lock poisoned");
        let log_count = guard
            .iter()
            .filter(|req| req.method == "notifications/message")
            .count();
        assert_eq!(log_count, 0);
    }

    #[test]
    fn test_handle_initialize() {
        let router = create_test_router();
        let mut session = create_test_session();
        let cx = Cx::for_testing();

        let params = InitializeParams {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ClientCapabilities::default(),
            client_info: ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
        };

        let result = router.handle_initialize(&cx, &mut session, params, Some("Test instructions"));

        assert!(result.is_ok());
        let init_result = result.unwrap();
        assert_eq!(init_result.server_info.name, "test-server");
        assert_eq!(
            init_result.instructions,
            Some("Test instructions".to_string())
        );
        assert!(session.is_initialized());
    }

    #[test]
    fn test_handle_tools_call_success() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": "Alice"})),
            meta: None,
        };

        let result =
            router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None, None);

        assert!(result.is_ok());
        let call_result = result.unwrap();
        assert!(!call_result.is_error);
        assert_eq!(call_result.content.len(), 1);

        assert!(matches!(call_result.content[0], Content::Text { .. }));
        let Content::Text { text } = &call_result.content[0] else {
            return;
        };
        assert_eq!(text, "Hello, Alice!");
    }

    #[test]
    fn test_handle_tools_call_not_found() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = CallToolParams {
            name: "nonexistent".to_string(),
            arguments: None,
            meta: None,
        };

        let result =
            router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None, None);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("nonexistent"));
    }

    #[test]
    fn test_handle_tools_call_with_error() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = CallToolParams {
            name: "error_tool".to_string(),
            arguments: None,
            meta: None,
        };

        let result =
            router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None, None);

        // Tool errors are returned as content with is_error=true
        assert!(result.is_ok());
        let call_result = result.unwrap();
        assert!(call_result.is_error);
        assert_eq!(call_result.content.len(), 1);
    }

    #[test]
    fn test_handle_tools_call_with_cancellation() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let budget = Budget::INFINITE;

        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": "Alice"})),
            meta: None,
        };

        let result =
            router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None, None);

        // Request should be cancelled before handler runs
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_tools_call_with_exhausted_budget() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::unlimited().with_poll_quota(0);

        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": "Alice"})),
            meta: None,
        };

        let result =
            router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None, None);

        // Request should fail due to exhausted budget
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("budget") || err.message.contains("exhausted"));
    }

    #[test]
    fn test_handle_resources_read_success() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = ReadResourceParams {
            uri: "resource://test".to_string(),
            meta: None,
        };

        let result =
            router.handle_resources_read(&cx, 1, &params, &budget, SessionState::new(), None, None);

        assert!(result.is_ok());
        let read_result = result.unwrap();
        assert_eq!(read_result.contents.len(), 1);
        assert_eq!(
            read_result.contents[0].text,
            Some("Test content".to_string())
        );
    }

    #[test]
    fn test_handle_resources_read_template_match() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = ReadResourceParams {
            uri: "resource://abc".to_string(),
            meta: None,
        };

        let result =
            router.handle_resources_read(&cx, 1, &params, &budget, SessionState::new(), None, None);

        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result.err());
        let read_result = result.unwrap();
        assert_eq!(
            read_result.contents[0].text,
            Some("Template abc".to_string())
        );
    }

    #[test]
    fn test_handle_resources_read_template_match_percent_decoded() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = ReadResourceParams {
            uri: "resource://hello%20world".to_string(),
            meta: None,
        };

        let result =
            router.handle_resources_read(&cx, 1, &params, &budget, SessionState::new(), None, None);

        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result.err());
        let read_result = result.unwrap();
        assert_eq!(
            read_result.contents[0].text,
            Some("Template hello world".to_string())
        );
    }

    #[test]
    fn test_handle_resources_read_template_match_with_slash() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = ReadResourceParams {
            uri: "resource://foo/bar".to_string(),
            meta: None,
        };

        let result =
            router.handle_resources_read(&cx, 1, &params, &budget, SessionState::new(), None, None);

        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result.err());
        let read_result = result.unwrap();
        assert_eq!(
            read_result.contents[0].text,
            Some("Template foo/bar".to_string())
        );
    }

    #[test]
    fn test_handle_resources_read_template_precedence() {
        let mut router = Router::new();
        router.add_resource(TemplateResource);
        router.add_resource(SpecificTemplateResource);

        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = ReadResourceParams {
            uri: "resource://foo/123".to_string(),
            meta: None,
        };

        let result =
            router.handle_resources_read(&cx, 1, &params, &budget, SessionState::new(), None, None);

        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result.err());
        let read_result = result.unwrap();
        assert_eq!(
            read_result.contents[0].text,
            Some("Specific 123".to_string())
        );
    }

    #[test]
    fn test_e2e_template_logging() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = Router::new();
        router.add_resource(LoggingTemplateResource {
            template: "file://{path}",
            events: events.clone(),
        });

        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let params = ReadResourceParams {
            uri: "file://dir%2Ffile.txt".to_string(),
            meta: None,
        };

        let result =
            router.handle_resources_read(&cx, 1, &params, &budget, SessionState::new(), None, None);

        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result.err());
        let read_result = result.unwrap();
        assert_eq!(
            read_result.contents[0].text.as_deref(),
            Some("Logged dir/file.txt")
        );

        let guard = events.lock().expect("template log lock poisoned");
        assert_eq!(guard.len(), 1);
        let entry = &guard[0];
        assert_eq!(entry.template, "file://{path}");
        assert_eq!(entry.uri, "file://dir%2Ffile.txt");
        assert_eq!(
            entry.params.get("path").map(String::as_str),
            Some("dir/file.txt")
        );
        assert_eq!(entry.response, "Logged dir/file.txt");
    }

    #[test]
    fn test_handle_resources_read_not_found() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        // Use a scheme that doesn't match any registered resources or templates
        let params = ReadResourceParams {
            uri: "file://nonexistent".to_string(),
            meta: None,
        };

        let result =
            router.handle_resources_read(&cx, 1, &params, &budget, SessionState::new(), None, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_handle_resources_read_with_cancellation() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let budget = Budget::INFINITE;

        let params = ReadResourceParams {
            uri: "resource://test".to_string(),
            meta: None,
        };

        let result =
            router.handle_resources_read(&cx, 1, &params, &budget, SessionState::new(), None, None);

        // Should be cancelled
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_prompts_get_success() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = GetPromptParams {
            name: "greeting".to_string(),
            arguments: Some({
                let mut map = HashMap::new();
                map.insert("name".to_string(), "Bob".to_string());
                map
            }),
            meta: None,
        };

        let result =
            router.handle_prompts_get(&cx, 1, params, &budget, SessionState::new(), None, None);

        assert!(result.is_ok());
        let get_result = result.unwrap();
        assert_eq!(get_result.messages.len(), 1);

        assert!(matches!(
            get_result.messages[0].content,
            Content::Text { .. }
        ));
        let Content::Text { text } = &get_result.messages[0].content else {
            return;
        };
        assert!(text.contains("Bob"));
    }

    #[test]
    fn test_handle_prompts_get_not_found() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = GetPromptParams {
            name: "nonexistent".to_string(),
            arguments: None,
            meta: None,
        };

        let result =
            router.handle_prompts_get(&cx, 1, params, &budget, SessionState::new(), None, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_handle_tools_call_validation_missing_required() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        // greet tool requires 'name' field, so passing empty object should fail validation
        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({})),
            meta: None,
        };

        let result =
            router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None, None);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("validation") || err.message.contains("required"));
    }

    #[test]
    fn test_handle_tools_call_validation_wrong_type() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        // greet tool expects 'name' to be a string, not a number
        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": 123})),
            meta: None,
        };

        let result =
            router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None, None);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("validation") || err.message.contains("type"));
    }

    #[test]
    fn test_handle_tools_call_validation_passes() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        // Valid arguments that satisfy the schema
        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": "Alice"})),
            meta: None,
        };

        let result =
            router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None, None);

        assert!(result.is_ok());
        let call_result = result.unwrap();
        assert!(!call_result.is_error);
    }
}

// ============================================================================
// Session Tests
// ============================================================================

#[cfg(test)]
mod session_tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new(
            ServerInfo {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
            ServerCapabilities::default(),
        );

        assert!(!session.is_initialized());
        assert!(session.client_info().is_none());
        assert!(session.client_capabilities().is_none());
        assert!(session.protocol_version().is_none());
    }

    #[test]
    fn test_session_initialization() {
        let mut session = Session::new(
            ServerInfo {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
            ServerCapabilities::default(),
        );

        session.initialize(
            ClientInfo {
                name: "client".to_string(),
                version: "2.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        assert!(session.is_initialized());
        assert_eq!(session.client_info().unwrap().name, "client");
        assert_eq!(session.protocol_version(), Some("2024-11-05"));
    }
}

// ============================================================================
// Cancellation Tests
// ============================================================================

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    #[test]
    fn test_tool_observes_cancellation() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx.clone(), 1);

        // Initially not cancelled
        assert!(!ctx.is_cancelled());

        // Set cancellation
        cx.set_cancel_requested(true);

        // Now tool should observe cancellation
        assert!(ctx.is_cancelled());
    }

    #[test]
    fn test_checkpoint_fails_when_cancelled() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx.clone(), 1);

        // Checkpoint succeeds initially
        assert!(ctx.checkpoint().is_ok());

        // Set cancellation
        cx.set_cancel_requested(true);

        // Checkpoint now fails
        assert!(ctx.checkpoint().is_err());
    }

    #[test]
    fn test_masked_section_defers_cancellation() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx.clone(), 1);

        cx.set_cancel_requested(true);

        // Inside masked section, checkpoint should succeed
        ctx.masked(|| {
            assert!(ctx.checkpoint().is_ok());
        });

        // Outside masked section, checkpoint should fail
        assert!(ctx.checkpoint().is_err());
    }
}

// ============================================================================
// Budget Tests
// ============================================================================

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn test_infinite_budget_not_exhausted() {
        let budget = Budget::INFINITE;
        assert!(!budget.is_exhausted());
    }

    #[test]
    fn test_exhausted_budget() {
        let budget = Budget::unlimited().with_poll_quota(0);
        assert!(budget.is_exhausted());
    }

    #[test]
    fn test_deadline_budget() {
        // A budget with a deadline far in the future
        let budget = Budget::with_deadline_secs(3600);
        assert!(!budget.is_exhausted());
    }
}

// ============================================================================
// Handler Definition Tests
// ============================================================================

#[cfg(test)]
mod handler_definition_tests {
    use super::*;

    #[test]
    fn test_tool_definition() {
        let tool = GreetTool;
        let def = tool.definition();

        assert_eq!(def.name, "greet");
        assert!(def.description.is_some());
        assert!(def.input_schema["type"] == "object");
    }

    #[test]
    fn test_resource_definition() {
        let resource = StaticResource {
            uri: "resource://foo".to_string(),
            content: "bar".to_string(),
        };
        let def = resource.definition();

        assert_eq!(def.uri, "resource://foo");
        assert_eq!(def.mime_type, Some("text/plain".to_string()));
    }

    #[test]
    fn test_prompt_definition() {
        let prompt = GreetingPrompt;
        let def = prompt.definition();

        assert_eq!(def.name, "greeting");
        assert!(!def.arguments.is_empty());
        assert_eq!(def.arguments.len(), 1);
    }
}

// ============================================================================
// Multiple Handler Tests
// ============================================================================

#[cfg(test)]
mod multi_handler_tests {
    use super::*;

    /// Second greeting tool with different behavior.
    struct FormalGreetTool;

    impl ToolHandler for FormalGreetTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "formal_greet".to_string(),
                description: Some("Formally greets a user".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"}
                    }
                }),
                icon: None,
            }
        }

        fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
            let name = arguments
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Sir/Madam");
            Ok(vec![Content::Text {
                text: format!("Good day, {name}."),
            }])
        }
    }

    #[test]
    fn test_multiple_tools() {
        let mut router = Router::new();
        router.add_tool(GreetTool);
        router.add_tool(FormalGreetTool);

        let tools = router.tools();
        assert_eq!(tools.len(), 2);

        // Call both tools
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let result1 = router.handle_tools_call(
            &cx,
            1,
            CallToolParams {
                name: "greet".to_string(),
                arguments: Some(serde_json::json!({"name": "Alice"})),
                meta: None,
            },
            &budget,
            SessionState::new(),
            None,
            None,
        );
        assert!(result1.is_ok());

        let result2 = router.handle_tools_call(
            &cx,
            2,
            CallToolParams {
                name: "formal_greet".to_string(),
                arguments: Some(serde_json::json!({"name": "Alice"})),
                meta: None,
            },
            &budget,
            SessionState::new(),
            None,
            None,
        );
        assert!(result2.is_ok());

        // Verify different outputs
        if let Content::Text { text: text1 } = &result1.unwrap().content[0] {
            if let Content::Text { text: text2 } = &result2.unwrap().content[0] {
                assert_eq!(text1, "Hello, Alice!");
                assert_eq!(text2, "Good day, Alice.");
            }
        }
    }

    #[test]
    fn test_multiple_resources() {
        let mut router = Router::new();
        router.add_resource(StaticResource {
            uri: "resource://a".to_string(),
            content: "Content A".to_string(),
        });
        router.add_resource(StaticResource {
            uri: "resource://b".to_string(),
            content: "Content B".to_string(),
        });

        let resources = router.resources();
        assert_eq!(resources.len(), 2);

        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let result_a = router.handle_resources_read(
            &cx,
            1,
            &ReadResourceParams {
                uri: "resource://a".to_string(),
                meta: None,
            },
            &budget,
            SessionState::new(),
            None,
            None,
        );
        let result_b = router.handle_resources_read(
            &cx,
            2,
            &ReadResourceParams {
                uri: "resource://b".to_string(),
                meta: None,
            },
            &budget,
            SessionState::new(),
            None,
            None,
        );

        assert_eq!(
            result_a.unwrap().contents[0].text,
            Some("Content A".to_string())
        );
        assert_eq!(
            result_b.unwrap().contents[0].text,
            Some("Content B".to_string())
        );
    }
}

// ============================================================================
// Session State Tests
// ============================================================================

mod session_state_tests {
    use super::*;

    /// Tool that increments a counter in session state.
    struct CounterTool;

    impl ToolHandler for CounterTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "increment".to_string(),
                description: Some("Increments a counter in session state".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
                icon: None,
            }
        }

        fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
            let count: i32 = ctx.get_state("counter").unwrap_or(0);
            let new_count = count + 1;
            ctx.set_state("counter", new_count);
            Ok(vec![Content::Text {
                text: format!("Counter: {new_count}"),
            }])
        }
    }

    #[test]
    fn test_session_state_persists_across_calls() {
        let mut router = Router::new();
        router.add_tool(CounterTool);

        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        // Create a shared session state
        let state = SessionState::new();

        // First call - counter should be 1
        let params = CallToolParams {
            name: "increment".to_string(),
            arguments: None,
            meta: None,
        };
        let result1 =
            router.handle_tools_call(&cx, 1, params.clone(), &budget, state.clone(), None, None);
        assert!(result1.is_ok());
        if let Content::Text { text } = &result1.unwrap().content[0] {
            assert_eq!(text, "Counter: 1");
        }

        // Second call with same state - counter should be 2
        let result2 =
            router.handle_tools_call(&cx, 2, params.clone(), &budget, state.clone(), None, None);
        assert!(result2.is_ok());
        if let Content::Text { text } = &result2.unwrap().content[0] {
            assert_eq!(text, "Counter: 2");
        }

        // Third call - counter should be 3
        let result3 = router.handle_tools_call(&cx, 3, params, &budget, state.clone(), None, None);
        assert!(result3.is_ok());
        if let Content::Text { text } = &result3.unwrap().content[0] {
            assert_eq!(text, "Counter: 3");
        }
    }

    #[test]
    fn test_different_session_states_are_independent() {
        let mut router = Router::new();
        router.add_tool(CounterTool);

        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        // Create two separate session states
        let state1 = SessionState::new();
        let state2 = SessionState::new();

        let params = CallToolParams {
            name: "increment".to_string(),
            arguments: None,
            meta: None,
        };

        // Call with state1 twice
        router
            .handle_tools_call(&cx, 1, params.clone(), &budget, state1.clone(), None, None)
            .unwrap();
        let result1 = router
            .handle_tools_call(&cx, 2, params.clone(), &budget, state1.clone(), None, None)
            .unwrap();

        // Call with state2 once
        let result2 = router
            .handle_tools_call(&cx, 3, params, &budget, state2.clone(), None, None)
            .unwrap();

        // state1 should have counter=2, state2 should have counter=1
        if let Content::Text { text } = &result1.content[0] {
            assert_eq!(text, "Counter: 2");
        }
        if let Content::Text { text } = &result2.content[0] {
            assert_eq!(text, "Counter: 1");
        }
    }
}

// ============================================================================
// Console Config Integration Tests
// ============================================================================

mod console_config_tests {
    use crate::{BannerStyle, ConsoleConfig, Server, TrafficVerbosity};

    #[test]
    fn test_server_default_console_config() {
        let server = Server::new("test", "1.0.0").build();
        let config = server.console_config();

        // Default config should show banner
        assert!(config.show_banner);
        assert_eq!(config.banner_style, BannerStyle::Full);
    }

    #[test]
    fn test_server_with_console_config() {
        let config = ConsoleConfig::new()
            .with_banner(BannerStyle::Compact)
            .plain_mode();

        let server = Server::new("test", "1.0.0")
            .with_console_config(config)
            .build();

        assert_eq!(server.console_config().banner_style, BannerStyle::Compact);
        assert!(server.console_config().force_plain);
    }

    #[test]
    fn test_server_without_banner() {
        let server = Server::new("test", "1.0.0").without_banner().build();

        assert!(!server.console_config().show_banner);
        assert_eq!(server.console_config().banner_style, BannerStyle::None);
    }

    #[test]
    fn test_server_with_banner_style() {
        let server = Server::new("test", "1.0.0")
            .with_banner(BannerStyle::Minimal)
            .build();

        assert!(server.console_config().show_banner);
        assert_eq!(server.console_config().banner_style, BannerStyle::Minimal);
    }

    #[test]
    fn test_server_with_traffic_logging() {
        let server = Server::new("test", "1.0.0")
            .with_traffic_logging(TrafficVerbosity::Summary)
            .build();

        assert!(server.console_config().show_request_traffic);
        assert_eq!(
            server.console_config().traffic_verbosity,
            TrafficVerbosity::Summary
        );
    }

    #[test]
    fn test_server_with_periodic_stats() {
        let server = Server::new("test", "1.0.0").with_periodic_stats(30).build();

        assert!(server.console_config().show_stats_periodic);
        assert_eq!(server.console_config().stats_interval_secs, 30);
    }

    #[test]
    fn test_server_plain_mode() {
        let server = Server::new("test", "1.0.0").plain_mode().build();

        assert!(server.console_config().force_plain);
    }

    #[test]
    fn test_server_force_color() {
        let server = Server::new("test", "1.0.0").force_color().build();

        assert_eq!(server.console_config().force_color, Some(true));
    }

    #[test]
    fn test_console_config_chaining() {
        let server = Server::new("test", "1.0.0")
            .with_banner(BannerStyle::Compact)
            .with_traffic_logging(TrafficVerbosity::Headers)
            .with_periodic_stats(60)
            .plain_mode()
            .build();

        let config = server.console_config();
        assert_eq!(config.banner_style, BannerStyle::Compact);
        assert_eq!(config.traffic_verbosity, TrafficVerbosity::Headers);
        assert!(config.show_stats_periodic);
        assert_eq!(config.stats_interval_secs, 60);
        assert!(config.force_plain);
    }
}

/// Tests for lifecycle hooks (on_startup, on_shutdown).
mod lifespan_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_on_startup_hook_builder() {
        let startup_called = Arc::new(AtomicBool::new(false));
        let startup_called_clone = startup_called.clone();

        let server = Server::new("test", "1.0.0")
            .on_startup(move || {
                startup_called_clone.store(true, Ordering::SeqCst);
                Ok::<(), std::io::Error>(())
            })
            .build();

        // The hook is stored but not called until run
        // Verify that the lifespan is stored (we can't call run_startup_hook directly
        // since it's private, but we verify the builder works)
        assert!(!startup_called.load(Ordering::SeqCst));

        // Manually trigger the startup hook via the public interface
        // (In production, this would be called by run_loop)
        let startup_success = server.run_startup_hook();
        assert!(startup_success);
        assert!(startup_called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_on_shutdown_hook_builder() {
        let shutdown_called = Arc::new(AtomicBool::new(false));
        let shutdown_called_clone = shutdown_called.clone();

        let server = Server::new("test", "1.0.0")
            .on_shutdown(move || {
                shutdown_called_clone.store(true, Ordering::SeqCst);
            })
            .build();

        // The hook is stored but not called until shutdown
        assert!(!shutdown_called.load(Ordering::SeqCst));

        // Manually trigger the shutdown hook
        server.run_shutdown_hook();
        assert!(shutdown_called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_startup_hook_failure() {
        let server = Server::new("test", "1.0.0")
            .on_startup(|| Err(std::io::Error::other("startup failed")))
            .build();

        // Startup should return false on failure
        let startup_success = server.run_startup_hook();
        assert!(!startup_success);
    }

    #[test]
    fn test_no_hooks_is_ok() {
        let server = Server::new("test", "1.0.0").build();

        // No hooks configured should be fine
        let startup_success = server.run_startup_hook();
        assert!(startup_success);

        // Shutdown hook should also be a no-op
        server.run_shutdown_hook();
    }

    #[test]
    fn test_hooks_only_run_once() {
        let startup_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let startup_count_clone = startup_count.clone();

        let shutdown_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let shutdown_count_clone = shutdown_count.clone();

        let server = Server::new("test", "1.0.0")
            .on_startup(move || {
                startup_count_clone.fetch_add(1, Ordering::SeqCst);
                Ok::<(), std::io::Error>(())
            })
            .on_shutdown(move || {
                shutdown_count_clone.fetch_add(1, Ordering::SeqCst);
            })
            .build();

        // Call startup multiple times
        server.run_startup_hook();
        server.run_startup_hook();
        server.run_startup_hook();

        // Should only have run once (hook is taken)
        assert_eq!(startup_count.load(Ordering::SeqCst), 1);

        // Same for shutdown
        server.run_shutdown_hook();
        server.run_shutdown_hook();
        server.run_shutdown_hook();

        assert_eq!(shutdown_count.load(Ordering::SeqCst), 1);
    }
}

/// Deterministic LabRuntime tests for cancel/timeout handling.
mod lab_runtime_tests {
    use super::*;
    use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget};
    use asupersync::lab::{LabConfig, LabRuntime};
    use std::sync::{Arc, Mutex};

    fn with_lab_runtime<T>(f: impl FnOnce(&mut LabRuntime) -> T) -> T {
        let mut runtime = LabRuntime::new(LabConfig::new(42).max_steps(2000));
        f(&mut runtime)
    }

    #[test]
    fn test_lab_runtime_cancelled_tool_call() {
        with_lab_runtime(|runtime| {
            let events = Arc::new(Mutex::new(Vec::new()));
            let events_for_task = Arc::clone(&events);

            LabRuntimeTarget::block_on(runtime, async move {
                let mut router = Router::new();
                router.add_tool(CancellationCheckTool);

                let cx = Cx::for_testing();
                cx.cancel_with(CancelKind::User, None);

                let params = CallToolParams {
                    name: "cancellation_check".to_string(),
                    arguments: Some(serde_json::json!({})),
                    meta: None,
                };
                let result = router.handle_tools_call(
                    &cx,
                    1,
                    params,
                    &Budget::INFINITE,
                    SessionState::new(),
                    None,
                    None,
                );

                let err = result.as_ref().err().map(|e| e.message.clone());
                events_for_task
                    .lock()
                    .expect("events lock poisoned")
                    .push(format!("cancelled_result={err:?}"));
                info!(
                    target: targets::SESSION,
                    "lab cancel outcome ts={} err={:?}",
                    chrono::Utc::now().to_rfc3339(),
                    err
                );

                assert!(result.is_err());
            });

            assert_eq!(events.lock().expect("events lock poisoned").len(), 1);
        });
    }

    #[test]
    fn test_lab_runtime_budget_exhaustion_resource_read() {
        with_lab_runtime(|runtime| {
            let events = Arc::new(Mutex::new(Vec::new()));
            let events_for_task = Arc::clone(&events);

            LabRuntimeTarget::block_on(runtime, async move {
                let mut router = Router::new();
                router.add_resource(StaticResource {
                    uri: "resource://test".to_string(),
                    content: "Test content".to_string(),
                });

                let cx = Cx::for_testing();
                let budget = Budget::unlimited().with_poll_quota(0);
                let params = ReadResourceParams {
                    uri: "resource://test".to_string(),
                    meta: None,
                };

                let result = router.handle_resources_read(
                    &cx,
                    1,
                    &params,
                    &budget,
                    SessionState::new(),
                    None,
                    None,
                );

                let err = result.as_ref().err().map(|e| e.message.clone());
                events_for_task
                    .lock()
                    .expect("events lock poisoned")
                    .push(format!("budget_result={err:?}"));
                info!(
                    target: targets::SESSION,
                    "lab budget outcome ts={} err={:?}",
                    chrono::Utc::now().to_rfc3339(),
                    err
                );

                assert!(result.is_err());
            });

            assert_eq!(events.lock().expect("events lock poisoned").len(), 1);
        });
    }

    #[test]
    fn test_lab_runtime_deadline_progression() {
        with_lab_runtime(|runtime| {
            let budget = Budget::with_deadline_secs(1);
            let start = runtime.now();
            assert!(!budget.is_past_deadline(start));

            runtime.advance_time(Duration::from_secs(2).as_nanos() as u64);
            let end = runtime.now();
            assert!(budget.is_past_deadline(end));
            info!(
                target: targets::SESSION,
                "lab deadline progression start={:?} end={:?}",
                start,
                end
            );
        });
    }
}

// ============================================================================
// Mount/Composition Tests
// ============================================================================

mod mount_tests {
    use super::*;
    use crate::Router;

    /// A simple tool for mount tests.
    struct QueryTool;

    impl ToolHandler for QueryTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "query".to_string(),
                description: Some("Executes a query".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string"}
                    }
                }),
                icon: None,
            }
        }

        fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
            let sql = arguments.get("sql").and_then(|v| v.as_str()).unwrap_or("");
            Ok(vec![Content::Text {
                text: format!("Query result: {sql}"),
            }])
        }
    }

    /// Another tool for mount tests.
    struct InsertTool;

    impl ToolHandler for InsertTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "insert".to_string(),
                description: Some("Inserts data".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
                icon: None,
            }
        }

        fn call(
            &self,
            _ctx: &McpContext,
            _arguments: serde_json::Value,
        ) -> McpResult<Vec<Content>> {
            Ok(vec![Content::Text {
                text: "Inserted".to_string(),
            }])
        }
    }

    /// A resource for mount tests.
    struct ConfigResource;

    impl ResourceHandler for ConfigResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "config://app".to_string(),
                name: "App Config".to_string(),
                description: Some("Application configuration".to_string()),
                mime_type: Some("application/json".to_string()),
                icon: None,
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![ResourceContent {
                uri: "config://app".to_string(),
                text: Some(r#"{"debug": true}"#.to_string()),
                mime_type: Some("application/json".to_string()),
                blob: None,
            }])
        }
    }

    /// A prompt for mount tests.
    struct GreetingPrompt;

    impl PromptHandler for GreetingPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "greeting".to_string(),
                description: Some("A greeting prompt".to_string()),
                arguments: Vec::new(),
                icon: None,
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _arguments: HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Ok(vec![PromptMessage {
                role: Role::User,
                content: Content::Text {
                    text: "Hello!".to_string(),
                },
            }])
        }
    }

    #[test]
    fn test_mount_with_prefix_renames_tools() {
        let mut main_router = Router::new();
        let mut db_router = Router::new();
        db_router.add_tool(QueryTool);
        db_router.add_tool(InsertTool);

        let result = main_router.mount(db_router, Some("db"));

        assert_eq!(result.tools, 2);
        assert!(main_router.get_tool("db/query").is_some());
        assert!(main_router.get_tool("db/insert").is_some());
        assert!(main_router.get_tool("query").is_none());
        assert!(main_router.get_tool("insert").is_none());
    }

    #[test]
    fn test_mount_without_prefix_keeps_names() {
        let mut main_router = Router::new();
        let mut other_router = Router::new();
        other_router.add_tool(QueryTool);

        let result = main_router.mount(other_router, None);

        assert_eq!(result.tools, 1);
        assert!(main_router.get_tool("query").is_some());
    }

    #[test]
    fn test_mount_resources_with_prefix() {
        let mut main_router = Router::new();
        let mut other_router = Router::new();
        other_router.add_resource(ConfigResource);

        let result = main_router.mount(other_router, Some("service"));

        assert_eq!(result.resources, 1);
        assert!(main_router.get_resource("service/config://app").is_some());
        assert!(main_router.get_resource("config://app").is_none());
    }

    #[test]
    fn test_mount_prompts_with_prefix() {
        let mut main_router = Router::new();
        let mut other_router = Router::new();
        other_router.add_prompt(GreetingPrompt);

        let result = main_router.mount(other_router, Some("templates"));

        assert_eq!(result.prompts, 1);
        assert!(main_router.get_prompt("templates/greeting").is_some());
        assert!(main_router.get_prompt("greeting").is_none());
    }

    #[test]
    fn test_mount_conflict_generates_warning() {
        let mut main_router = Router::new();
        main_router.add_tool(QueryTool);

        let mut other_router = Router::new();
        other_router.add_tool(QueryTool);

        // Mount without prefix, causing a conflict
        let result = main_router.mount(other_router, None);

        assert_eq!(result.tools, 1);
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("already exists"));
    }

    #[test]
    fn test_mount_preserves_tool_definition() {
        let mut main_router = Router::new();
        let mut db_router = Router::new();
        db_router.add_tool(QueryTool);

        main_router.mount(db_router, Some("db"));

        let tools = main_router.tools();
        let tool = tools.iter().find(|t| t.name == "db/query").unwrap();
        assert_eq!(tool.description, Some("Executes a query".to_string()));
    }

    #[test]
    fn test_mount_all_components() {
        let mut main_router = Router::new();
        let mut other_router = Router::new();
        other_router.add_tool(QueryTool);
        other_router.add_resource(ConfigResource);
        other_router.add_prompt(GreetingPrompt);

        let result = main_router.mount(other_router, Some("sub"));

        assert_eq!(result.tools, 1);
        assert_eq!(result.resources, 1);
        assert_eq!(result.prompts, 1);
        assert!(result.has_components());
    }

    #[test]
    fn test_selective_mount_tools_only() {
        let db_server = Server::new("db", "1.0")
            .tool(QueryTool)
            .resource(ConfigResource)
            .prompt(GreetingPrompt)
            .build();

        let main = Server::new("main", "1.0")
            .mount_tools(db_server, Some("db"))
            .build();

        let tools = main.tools();
        let resources = main.resources();
        let prompts = main.prompts();

        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "db/query");
        assert!(resources.is_empty());
        assert!(prompts.is_empty());
    }

    #[test]
    fn test_selective_mount_resources_only() {
        let data_server = Server::new("data", "1.0")
            .tool(QueryTool)
            .resource(ConfigResource)
            .build();

        let main = Server::new("main", "1.0")
            .mount_resources(data_server, Some("data"))
            .build();

        let tools = main.tools();
        let resources = main.resources();

        assert!(tools.is_empty());
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].uri, "data/config://app");
    }

    #[test]
    fn test_selective_mount_prompts_only() {
        let templates_server = Server::new("templates", "1.0")
            .tool(QueryTool)
            .prompt(GreetingPrompt)
            .build();

        let main = Server::new("main", "1.0")
            .mount_prompts(templates_server, Some("tmpl"))
            .build();

        let tools = main.tools();
        let prompts = main.prompts();

        assert!(tools.is_empty());
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "tmpl/greeting");
    }

    #[test]
    fn test_full_mount_via_server_builder() {
        let db_server = Server::new("db", "1.0")
            .tool(QueryTool)
            .tool(InsertTool)
            .build();

        let api_server = Server::new("api", "1.0").prompt(GreetingPrompt).build();

        let main = Server::new("main", "1.0")
            .tool(GreetTool)
            .mount(db_server, Some("db"))
            .mount(api_server, Some("api"))
            .build();

        let tools = main.tools();
        let prompts = main.prompts();

        // Should have original greet + mounted db/query and db/insert
        assert_eq!(tools.len(), 3);
        let tool_names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(tool_names.contains(&"greet"));
        assert!(tool_names.contains(&"db/query"));
        assert!(tool_names.contains(&"db/insert"));

        // Should have api/greeting
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "api/greeting");
    }

    #[test]
    fn test_nested_mounting() {
        // Create inner server
        let inner = Server::new("inner", "1.0").tool(QueryTool).build();

        // Mount inner into middle
        let middle = Server::new("middle", "1.0")
            .mount(inner, Some("inner"))
            .build();

        // Mount middle into outer
        let outer = Server::new("outer", "1.0")
            .mount(middle, Some("middle"))
            .build();

        let tools = outer.tools();
        assert_eq!(tools.len(), 1);
        // Tool should be at middle/inner/query
        assert_eq!(tools[0].name, "middle/inner/query");
    }

    #[test]
    fn test_prefix_validation_rejects_slashes() {
        let mut router = Router::new();
        let mut other = Router::new();
        other.add_tool(QueryTool);

        let result = router.mount(other, Some("bad/prefix"));

        // Should still mount but generate a warning
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("slash"));
    }

    #[test]
    fn test_mounted_tool_can_be_called() {
        let db_server = Server::new("db", "1.0").tool(QueryTool).build();

        let main = Server::new("main", "1.0")
            .mount(db_server, Some("db"))
            .build();

        // Get the tool handler
        let tools = main.tools();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "db/query");

        // Verify the definition is correct
        let tool = &tools[0];
        assert_eq!(tool.description, Some("Executes a query".to_string()));
    }

    #[test]
    fn test_mount_empty_router() {
        let mut main_router = Router::new();
        let empty_router = Router::new();

        let result = main_router.mount(empty_router, Some("empty"));

        assert_eq!(result.tools, 0);
        assert_eq!(result.resources, 0);
        assert_eq!(result.prompts, 0);
        assert!(!result.has_components());
    }
}

// ============================================================================
// Duplicate Behavior Tests
// ============================================================================

mod duplicate_behavior_tests {
    use super::*;
    use crate::{DuplicateBehavior, Router};

    /// A simple tool for duplicate tests.
    struct DupTool {
        id: u32,
    }

    impl DupTool {
        fn new(id: u32) -> Self {
            Self { id }
        }
    }

    impl ToolHandler for DupTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "dup_tool".to_string(),
                description: Some(format!("Tool #{}", self.id)),
                input_schema: serde_json::json!({"type": "object"}),
                icon: None,
            }
        }

        fn call(
            &self,
            _ctx: &McpContext,
            _arguments: serde_json::Value,
        ) -> McpResult<Vec<Content>> {
            Ok(vec![Content::Text {
                text: format!("Tool #{}", self.id),
            }])
        }
    }

    #[test]
    fn test_duplicate_behavior_error_returns_error() {
        let mut router = Router::new();
        router.add_tool(DupTool::new(1));

        let result = router.add_tool_with_behavior(DupTool::new(2), DuplicateBehavior::Error);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("already exists"));
    }

    #[test]
    fn test_duplicate_behavior_warn_keeps_original() {
        let mut router = Router::new();
        router.add_tool(DupTool::new(1));

        let result = router.add_tool_with_behavior(DupTool::new(2), DuplicateBehavior::Warn);
        assert!(result.is_ok());

        // Original should be kept
        let tool = router.get_tool("dup_tool").unwrap();
        assert_eq!(tool.definition().description, Some("Tool #1".to_string()));
    }

    #[test]
    fn test_duplicate_behavior_replace_replaces() {
        let mut router = Router::new();
        router.add_tool(DupTool::new(1));

        let result = router.add_tool_with_behavior(DupTool::new(2), DuplicateBehavior::Replace);
        assert!(result.is_ok());

        // New one should replace original
        let tool = router.get_tool("dup_tool").unwrap();
        assert_eq!(tool.definition().description, Some("Tool #2".to_string()));
    }

    #[test]
    fn test_duplicate_behavior_ignore_keeps_original() {
        let mut router = Router::new();
        router.add_tool(DupTool::new(1));

        let result = router.add_tool_with_behavior(DupTool::new(2), DuplicateBehavior::Ignore);
        assert!(result.is_ok());

        // Original should be kept
        let tool = router.get_tool("dup_tool").unwrap();
        assert_eq!(tool.definition().description, Some("Tool #1".to_string()));
    }

    #[test]
    fn test_duplicate_behavior_default_is_warn() {
        assert_eq!(DuplicateBehavior::default(), DuplicateBehavior::Warn);
    }

    #[test]
    fn test_no_duplicate_succeeds_for_all_behaviors() {
        for behavior in [
            DuplicateBehavior::Error,
            DuplicateBehavior::Warn,
            DuplicateBehavior::Replace,
            DuplicateBehavior::Ignore,
        ] {
            let mut router = Router::new();
            let result = router.add_tool_with_behavior(DupTool::new(1), behavior);
            assert!(result.is_ok(), "Failed for {:?}", behavior);
        }
    }

    #[test]
    fn test_server_builder_on_duplicate() {
        // Create server with strict duplicate checking
        let server = Server::new("test", "1.0")
            .on_duplicate(DuplicateBehavior::Replace)
            .tool(DupTool::new(1))
            .tool(DupTool::new(2)) // Should replace
            .build();

        let tools = server.tools();
        assert_eq!(tools.len(), 1);
        // The replaced tool should have id 2
        assert_eq!(tools[0].description, Some("Tool #2".to_string()));
    }

    #[test]
    fn test_server_builder_error_behavior_logs_but_continues() {
        // Create server with error behavior
        let server = Server::new("test", "1.0")
            .on_duplicate(DuplicateBehavior::Error)
            .tool(DupTool::new(1))
            .tool(DupTool::new(2)) // Should fail silently in builder
            .build();

        let tools = server.tools();
        // Only first tool should be registered
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].description, Some("Tool #1".to_string()));
    }
}

// ============================================================================
// Cross-Component Resource Reading Tests (ctx.read_resource)
// ============================================================================

mod ctx_read_resource_tests {
    use super::*;
    use crate::RouterResourceReader;
    use fastmcp_core::{
        MAX_RESOURCE_READ_DEPTH, ResourceContentItem, ResourceReadResult, ResourceReader,
    };

    /// A simple resource that returns static config data.
    struct ConfigResource {
        config_json: String,
    }

    impl ConfigResource {
        fn new(json: &str) -> Self {
            Self {
                config_json: json.to_string(),
            }
        }
    }

    impl ResourceHandler for ConfigResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "config://app".to_string(),
                name: "app_config".to_string(),
                description: Some("Application configuration".to_string()),
                mime_type: Some("application/json".to_string()),
                icon: None,
            }
        }

        fn template(&self) -> Option<ResourceTemplate> {
            None
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![ResourceContent {
                uri: "config://app".to_string(),
                mime_type: Some("application/json".to_string()),
                text: Some(self.config_json.clone()),
                blob: None,
            }])
        }
    }

    /// A resource that reads another resource.
    struct NestedResource {
        inner_uri: String,
    }

    impl NestedResource {
        fn new(inner_uri: &str) -> Self {
            Self {
                inner_uri: inner_uri.to_string(),
            }
        }
    }

    impl ResourceHandler for NestedResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "nested://wrapper".to_string(),
                name: "nested_wrapper".to_string(),
                description: Some("Wraps another resource".to_string()),
                mime_type: Some("text/plain".to_string()),
                icon: None,
            }
        }

        fn template(&self) -> Option<ResourceTemplate> {
            None
        }

        fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            // Read the inner resource using ctx
            let inner_uri = self.inner_uri.clone();
            let inner_result = fastmcp_core::block_on(ctx.read_resource(&inner_uri))?;

            let text = inner_result.first_text().unwrap_or("(no content)");
            Ok(vec![ResourceContent {
                uri: "nested://wrapper".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some(format!("Wrapped: {}", text)),
                blob: None,
            }])
        }
    }

    #[test]
    fn test_resource_content_item_constructors() {
        let text_item = ResourceContentItem::text("file://test", "hello world");
        assert_eq!(text_item.uri, "file://test");
        assert_eq!(text_item.as_text(), Some("hello world"));
        assert!(text_item.is_text());
        assert!(!text_item.is_blob());

        let json_item = ResourceContentItem::json("config://app", r#"{"key": "value"}"#);
        assert_eq!(json_item.mime_type, Some("application/json".to_string()));

        let blob_item = ResourceContentItem::blob("image://test", "image/png", "base64data");
        assert_eq!(blob_item.as_blob(), Some("base64data"));
        assert!(blob_item.is_blob());
        assert!(!blob_item.is_text());
    }

    #[test]
    fn test_resource_read_result_constructors() {
        let result = ResourceReadResult::text("file://test", "content");
        assert_eq!(result.first_text(), Some("content"));
        assert_eq!(result.contents.len(), 1);

        let multi = ResourceReadResult::new(vec![
            ResourceContentItem::text("file://a", "A"),
            ResourceContentItem::text("file://b", "B"),
        ]);
        assert_eq!(multi.contents.len(), 2);
        assert_eq!(multi.first_text(), Some("A"));
    }

    #[test]
    fn test_ctx_read_resource_without_reader_fails() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);

        // Without a resource reader, should fail
        assert!(!ctx.can_read_resources());

        let result = fastmcp_core::block_on(ctx.read_resource("config://app"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("no router"));
    }

    #[test]
    fn test_router_resource_reader_reads_resource() {
        let mut router = Router::new();
        router.add_resource(ConfigResource::new(r#"{"db": "postgres"}"#));

        let router_arc = Arc::new(router);
        let reader = RouterResourceReader::new(router_arc, SessionState::new());

        let cx = Cx::for_testing();
        let result = fastmcp_core::block_on(reader.read_resource(&cx, "config://app", 0));

        assert!(result.is_ok());
        let read_result = result.unwrap();
        assert_eq!(read_result.first_text(), Some(r#"{"db": "postgres"}"#));
    }

    #[test]
    fn test_router_resource_reader_not_found() {
        let router = Router::new(); // No resources
        let router_arc = Arc::new(router);
        let reader = RouterResourceReader::new(router_arc, SessionState::new());

        let cx = Cx::for_testing();
        let result = fastmcp_core::block_on(reader.read_resource(&cx, "config://missing", 0));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("not found"));
    }

    #[test]
    fn test_router_resource_reader_depth_limit() {
        let router = Router::new();
        let router_arc = Arc::new(router);
        let reader = RouterResourceReader::new(router_arc, SessionState::new());

        let cx = Cx::for_testing();
        // Call with depth at limit
        let result = fastmcp_core::block_on(reader.read_resource(
            &cx,
            "any://uri",
            MAX_RESOURCE_READ_DEPTH + 1,
        ));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("depth"));
    }

    #[test]
    fn test_ctx_with_resource_reader() {
        let mut router = Router::new();
        router.add_resource(ConfigResource::new(r#"{"name": "test"}"#));

        let router_arc = Arc::new(router);
        let reader: Arc<dyn ResourceReader> =
            Arc::new(RouterResourceReader::new(router_arc, SessionState::new()));

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1).with_resource_reader(reader);

        assert!(ctx.can_read_resources());
        assert_eq!(ctx.resource_read_depth(), 0);

        // Read the resource
        let result = fastmcp_core::block_on(ctx.read_resource("config://app"));
        assert!(result.is_ok());
        let read_result = result.unwrap();
        assert!(read_result.first_text().unwrap().contains("test"));
    }

    #[test]
    fn test_ctx_read_resource_text() {
        let mut router = Router::new();
        router.add_resource(ConfigResource::new(r#"{"value": 42}"#));

        let router_arc = Arc::new(router);
        let reader: Arc<dyn ResourceReader> =
            Arc::new(RouterResourceReader::new(router_arc, SessionState::new()));

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1).with_resource_reader(reader);

        let result = fastmcp_core::block_on(ctx.read_resource_text("config://app"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), r#"{"value": 42}"#);
    }

    #[test]
    fn test_ctx_read_resource_json() {
        let mut router = Router::new();
        router.add_resource(ConfigResource::new(
            r#"{"database": "postgres", "port": 5432}"#,
        ));

        let router_arc = Arc::new(router);
        let reader: Arc<dyn ResourceReader> =
            Arc::new(RouterResourceReader::new(router_arc, SessionState::new()));

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1).with_resource_reader(reader);

        #[derive(Debug, serde::Deserialize)]
        struct DbConfig {
            database: String,
            port: u16,
        }

        let result: McpResult<DbConfig> =
            fastmcp_core::block_on(ctx.read_resource_json("config://app"));
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.database, "postgres");
        assert_eq!(config.port, 5432);
    }

    #[test]
    fn test_ctx_read_resource_json_parse_error() {
        let mut router = Router::new();
        router.add_resource(ConfigResource::new("not valid json"));

        let router_arc = Arc::new(router);
        let reader: Arc<dyn ResourceReader> =
            Arc::new(RouterResourceReader::new(router_arc, SessionState::new()));

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1).with_resource_reader(reader);

        #[derive(Debug, serde::Deserialize)]
        struct Config {
            value: i32,
        }

        let result: McpResult<Config> =
            fastmcp_core::block_on(ctx.read_resource_json("config://app"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("JSON"));
    }

    #[test]
    fn test_resource_read_depth_increments() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1).with_resource_read_depth(5);

        assert_eq!(ctx.resource_read_depth(), 5);
    }

    #[test]
    fn test_max_resource_read_depth_constant() {
        // Verify the constant is reasonable
        assert_eq!(MAX_RESOURCE_READ_DEPTH, 10);
    }

    /// A resource that reads session state and then reads another resource.
    struct SessionStateResource;

    impl ResourceHandler for SessionStateResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "session://state".to_string(),
                name: "session_state".to_string(),
                description: Some("Returns session state value".to_string()),
                mime_type: Some("text/plain".to_string()),
                icon: None,
            }
        }

        fn template(&self) -> Option<ResourceTemplate> {
            None
        }

        fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            let value: Option<String> = ctx.get_state("test_key");
            Ok(vec![ResourceContent {
                uri: "session://state".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some(value.unwrap_or_else(|| "no_value".to_string())),
                blob: None,
            }])
        }
    }

    /// A resource that sets session state and reads another resource to verify propagation.
    struct NestedSessionResource;

    impl ResourceHandler for NestedSessionResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "nested://session".to_string(),
                name: "nested_session".to_string(),
                description: Some("Sets state then reads another resource".to_string()),
                mime_type: Some("text/plain".to_string()),
                icon: None,
            }
        }

        fn template(&self) -> Option<ResourceTemplate> {
            None
        }

        fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            // Set a value in session state
            ctx.set_state("test_key", "propagated_value");

            // Read another resource - it should see our session state
            let inner_result = fastmcp_core::block_on(ctx.read_resource("session://state"))?;
            let text = inner_result.first_text().unwrap_or("(no content)");

            Ok(vec![ResourceContent {
                uri: "nested://session".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some(format!("Inner saw: {}", text)),
                blob: None,
            }])
        }
    }

    #[test]
    fn test_session_state_propagates_through_nested_reads() {
        let mut router = Router::new();
        router.add_resource(SessionStateResource);
        router.add_resource(NestedSessionResource);

        let router_arc = Arc::new(router);
        let session_state = SessionState::new();
        let reader: Arc<dyn ResourceReader> =
            Arc::new(RouterResourceReader::new(router_arc, session_state.clone()));

        let cx = Cx::for_testing();
        let ctx = McpContext::with_state(cx, 1, session_state).with_resource_reader(reader);

        // Read the nested resource - it sets state then reads another resource
        let result = fastmcp_core::block_on(ctx.read_resource("nested://session"));
        assert!(result.is_ok());
        let read_result = result.unwrap();

        // The inner resource should have seen the propagated value
        let text = read_result.first_text().unwrap();
        assert!(
            text.contains("propagated_value"),
            "Expected session state to propagate, got: {}",
            text
        );
    }
}

// ============================================================================
// Cross-Component Tool Calling Tests (ctx.call_tool)
// ============================================================================

mod ctx_call_tool_tests {
    use super::*;
    use crate::RouterToolCaller;
    use fastmcp_core::{MAX_TOOL_CALL_DEPTH, ToolCallResult, ToolCaller, ToolContentItem};

    /// A simple tool that adds two numbers.
    struct AddTool;

    impl ToolHandler for AddTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "add".to_string(),
                description: Some("Adds two numbers".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "a": {"type": "integer"},
                        "b": {"type": "integer"}
                    },
                    "required": ["a", "b"]
                }),
                icon: None,
            }
        }

        fn call(&self, _ctx: &McpContext, args: serde_json::Value) -> McpResult<Vec<Content>> {
            let a = args["a"].as_i64().unwrap_or(0);
            let b = args["b"].as_i64().unwrap_or(0);
            let sum = a + b;
            Ok(vec![Content::Text {
                text: sum.to_string(),
            }])
        }
    }

    /// A tool that returns JSON.
    struct JsonTool;

    impl ToolHandler for JsonTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "compute".to_string(),
                description: Some("Returns a JSON result".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
                icon: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::Text {
                text: r#"{"value": 42}"#.to_string(),
            }])
        }
    }

    /// A tool that always fails.
    struct FailingTool;

    impl ToolHandler for FailingTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "failing".to_string(),
                description: Some("Always fails".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
                icon: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Err(McpError::new(
                McpErrorCode::InternalError,
                "Something went wrong",
            ))
        }
    }

    #[test]
    fn test_tool_content_item_constructors() {
        let text_item = ToolContentItem::text("hello world");
        assert_eq!(text_item.as_text(), Some("hello world"));
        assert!(text_item.is_text());
    }

    #[test]
    fn test_tool_call_result_constructors() {
        let success = ToolCallResult::text("result");
        assert!(!success.is_error);
        assert_eq!(success.first_text(), Some("result"));

        let error = ToolCallResult::error("failed");
        assert!(error.is_error);
        assert_eq!(error.first_text(), Some("failed"));

        let multi =
            ToolCallResult::success(vec![ToolContentItem::text("a"), ToolContentItem::text("b")]);
        assert_eq!(multi.content.len(), 2);
        assert_eq!(multi.first_text(), Some("a"));
    }

    #[test]
    fn test_ctx_call_tool_without_caller_fails() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);

        // Without a tool caller, should fail
        assert!(!ctx.can_call_tools());

        let result =
            fastmcp_core::block_on(ctx.call_tool("add", serde_json::json!({"a": 1, "b": 2})));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("no router"));
    }

    #[test]
    fn test_router_tool_caller_calls_tool() {
        let mut router = Router::new();
        router.add_tool(AddTool);

        let router_arc = Arc::new(router);
        let caller = RouterToolCaller::new(router_arc, SessionState::new());

        let cx = Cx::for_testing();
        let result = fastmcp_core::block_on(caller.call_tool(
            &cx,
            "add",
            serde_json::json!({"a": 5, "b": 3}),
            0,
        ));

        assert!(result.is_ok());
        let call_result = result.unwrap();
        assert!(!call_result.is_error);
        assert_eq!(call_result.first_text(), Some("8"));
    }

    #[test]
    fn test_router_tool_caller_not_found() {
        let router = Router::new(); // No tools
        let router_arc = Arc::new(router);
        let caller = RouterToolCaller::new(router_arc, SessionState::new());

        let cx = Cx::for_testing();
        let result =
            fastmcp_core::block_on(caller.call_tool(&cx, "nonexistent", serde_json::json!({}), 0));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("not found"));
    }

    #[test]
    fn test_router_tool_caller_depth_limit() {
        let router = Router::new();
        let router_arc = Arc::new(router);
        let caller = RouterToolCaller::new(router_arc, SessionState::new());

        let cx = Cx::for_testing();
        // Call with depth at limit
        let result = fastmcp_core::block_on(caller.call_tool(
            &cx,
            "any_tool",
            serde_json::json!({}),
            MAX_TOOL_CALL_DEPTH + 1,
        ));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("depth"));
    }

    #[test]
    fn test_ctx_with_tool_caller() {
        let mut router = Router::new();
        router.add_tool(AddTool);

        let router_arc = Arc::new(router);
        let caller: Arc<dyn ToolCaller> =
            Arc::new(RouterToolCaller::new(router_arc, SessionState::new()));

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1).with_tool_caller(caller);

        assert!(ctx.can_call_tools());
        assert_eq!(ctx.tool_call_depth(), 0);

        // Call the tool
        let result =
            fastmcp_core::block_on(ctx.call_tool("add", serde_json::json!({"a": 10, "b": 5})));
        assert!(result.is_ok());
        let call_result = result.unwrap();
        assert_eq!(call_result.first_text(), Some("15"));
    }

    #[test]
    fn test_ctx_call_tool_text() {
        let mut router = Router::new();
        router.add_tool(AddTool);

        let router_arc = Arc::new(router);
        let caller: Arc<dyn ToolCaller> =
            Arc::new(RouterToolCaller::new(router_arc, SessionState::new()));

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1).with_tool_caller(caller);

        let result =
            fastmcp_core::block_on(ctx.call_tool_text("add", serde_json::json!({"a": 7, "b": 3})));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "10");
    }

    #[test]
    fn test_ctx_call_tool_json() {
        let mut router = Router::new();
        router.add_tool(JsonTool);

        let router_arc = Arc::new(router);
        let caller: Arc<dyn ToolCaller> =
            Arc::new(RouterToolCaller::new(router_arc, SessionState::new()));

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1).with_tool_caller(caller);

        #[derive(Debug, serde::Deserialize)]
        struct Result {
            value: i32,
        }

        let result: McpResult<Result> =
            fastmcp_core::block_on(ctx.call_tool_json("compute", serde_json::json!({})));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().value, 42);
    }

    #[test]
    fn test_ctx_call_tool_returns_error_result() {
        let mut router = Router::new();
        router.add_tool(FailingTool);

        let router_arc = Arc::new(router);
        let caller: Arc<dyn ToolCaller> =
            Arc::new(RouterToolCaller::new(router_arc, SessionState::new()));

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1).with_tool_caller(caller);

        // call_tool returns the error as is_error=true
        let result = fastmcp_core::block_on(ctx.call_tool("failing", serde_json::json!({})));
        assert!(result.is_ok());
        let call_result = result.unwrap();
        assert!(call_result.is_error);
    }

    #[test]
    fn test_ctx_call_tool_text_propagates_error() {
        let mut router = Router::new();
        router.add_tool(FailingTool);

        let router_arc = Arc::new(router);
        let caller: Arc<dyn ToolCaller> =
            Arc::new(RouterToolCaller::new(router_arc, SessionState::new()));

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1).with_tool_caller(caller);

        // call_tool_text converts is_error=true to Err
        let result = fastmcp_core::block_on(ctx.call_tool_text("failing", serde_json::json!({})));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("failed"));
    }

    #[test]
    fn test_tool_call_depth_increments() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1).with_tool_call_depth(5);

        assert_eq!(ctx.tool_call_depth(), 5);
    }

    #[test]
    fn test_max_tool_call_depth_constant() {
        // Verify the constant is reasonable
        assert_eq!(MAX_TOOL_CALL_DEPTH, 10);
    }

    #[test]
    fn test_tool_validation_error() {
        let mut router = Router::new();
        router.add_tool(AddTool);

        let router_arc = Arc::new(router);
        let caller = RouterToolCaller::new(router_arc, SessionState::new());

        let cx = Cx::for_testing();
        // Missing required parameters
        let result = fastmcp_core::block_on(caller.call_tool(
            &cx,
            "add",
            serde_json::json!({}), // Missing a and b
            0,
        ));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("validation"));
    }

    /// A tool that reads session state.
    struct GetStateTool;

    impl ToolHandler for GetStateTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "get_state".to_string(),
                description: Some("Returns session state value".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
                icon: None,
            }
        }

        fn call(&self, ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            let value: Option<String> = ctx.get_state("tool_test_key");
            Ok(vec![Content::Text {
                text: value.unwrap_or_else(|| "no_value".to_string()),
            }])
        }
    }

    /// A tool that sets session state and calls another tool to verify propagation.
    struct NestedStateTool;

    impl ToolHandler for NestedStateTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "nested_state".to_string(),
                description: Some("Sets state then calls another tool".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
                icon: None,
            }
        }

        fn call(&self, ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            // Set a value in session state
            ctx.set_state("tool_test_key", "tool_propagated_value");

            // Call another tool - it should see our session state
            let inner_result =
                fastmcp_core::block_on(ctx.call_tool("get_state", serde_json::json!({})))?;
            let text = inner_result.first_text().unwrap_or("(no content)");

            Ok(vec![Content::Text {
                text: format!("Inner tool saw: {}", text),
            }])
        }
    }

    #[test]
    fn test_session_state_propagates_through_nested_tool_calls() {
        use crate::RouterResourceReader;

        let mut router = Router::new();
        router.add_tool(GetStateTool);
        router.add_tool(NestedStateTool);

        let router_arc = Arc::new(router);
        let session_state = SessionState::new();
        let caller: Arc<dyn ToolCaller> = Arc::new(RouterToolCaller::new(
            router_arc.clone(),
            session_state.clone(),
        ));
        let reader: Arc<dyn fastmcp_core::ResourceReader> =
            Arc::new(RouterResourceReader::new(router_arc, session_state.clone()));

        let cx = Cx::for_testing();
        let ctx = McpContext::with_state(cx, 1, session_state)
            .with_tool_caller(caller)
            .with_resource_reader(reader);

        // Call the nested tool - it sets state then calls another tool
        let result = fastmcp_core::block_on(ctx.call_tool("nested_state", serde_json::json!({})));
        assert!(result.is_ok());
        let call_result = result.unwrap();

        // The inner tool should have seen the propagated value
        let text = call_result.first_text().unwrap();
        assert!(
            text.contains("tool_propagated_value"),
            "Expected session state to propagate through tool calls, got: {}",
            text
        );
    }
}
