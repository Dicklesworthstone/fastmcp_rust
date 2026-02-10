//! Middleware hooks for request/response interception.
//!
//! This provides a minimal, synchronous middleware system for MCP requests.
//! Middleware can short-circuit requests, transform responses, and rewrite errors.
//!
//! # Ordering Semantics
//!
//! - `on_request` runs **in registration order** (first registered, first called).
//! - `on_response` runs **in reverse order** for middleware whose `on_request` ran.
//! - `on_error` runs **in reverse order** for middleware whose `on_request` ran.
//!
//! If a middleware returns `Respond` from `on_request`, the response is still
//! passed through `on_response` for the already-entered middleware stack.
//! If any `on_request` or `on_response` returns an error, `on_error` is invoked
//! for the entered middleware stack to allow error rewriting.

use fastmcp_core::{McpContext, McpError, McpResult};
use fastmcp_protocol::JsonRpcRequest;

/// Result of middleware request interception.
#[derive(Debug, Clone)]
pub enum MiddlewareDecision {
    /// Continue normal dispatch.
    Continue,
    /// Short-circuit dispatch and return this JSON value as the result.
    Respond(serde_json::Value),
}

/// Middleware hook trait for request/response interception.
///
/// This is intentionally minimal: synchronous hooks only, with simple
/// short-circuit and response transform capabilities. See the module-level
/// documentation for ordering semantics.
pub trait Middleware: Send + Sync {
    /// Invoked before routing the request.
    ///
    /// Return `Respond` to skip normal dispatch and return a custom result.
    fn on_request(
        &self,
        _ctx: &McpContext,
        _request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        Ok(MiddlewareDecision::Continue)
    }

    /// Invoked after a successful handler result is produced.
    ///
    /// Middleware can transform the response value (or return an error).
    fn on_response(
        &self,
        _ctx: &McpContext,
        _request: &JsonRpcRequest,
        response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        Ok(response)
    }

    /// Invoked when a handler or middleware returns an error.
    ///
    /// Middleware may rewrite the error before it is sent to the client.
    fn on_error(&self, _ctx: &McpContext, _request: &JsonRpcRequest, error: McpError) -> McpError {
        error
    }
}

// ============================================================================
// Utility Middleware Implementations
// ============================================================================
//
// These are intentionally small, deterministic middleware implementations that are
// useful for testing ordering/stack semantics without relying on mocks.

use std::sync::{Arc, Mutex};

/// Records request/response/error phases into a shared log.
///
/// Primarily intended for tests that assert middleware ordering semantics.
#[derive(Debug, Clone)]
pub(crate) struct RecordingMiddleware {
    name: &'static str,
    events: Arc<Mutex<Vec<String>>>,
}

impl RecordingMiddleware {
    pub(crate) fn new(name: &'static str, events: Arc<Mutex<Vec<String>>>) -> Self {
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
        _request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        self.record("req");
        Ok(MiddlewareDecision::Continue)
    }

    fn on_response(
        &self,
        _ctx: &McpContext,
        _request: &JsonRpcRequest,
        response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        self.record("resp");
        Ok(response)
    }

    fn on_error(&self, _ctx: &McpContext, _request: &JsonRpcRequest, error: McpError) -> McpError {
        self.record("err");
        error
    }
}

/// Middleware that can optionally short-circuit requests and appends step markers to responses.
///
/// Primarily intended for tests that verify short-circuit semantics still run the entered
/// response stack in reverse order.
#[derive(Debug, Clone)]
pub(crate) struct StepMiddleware {
    name: &'static str,
    events: Arc<Mutex<Vec<String>>>,
    respond: bool,
}

impl StepMiddleware {
    pub(crate) fn new(name: &'static str, events: Arc<Mutex<Vec<String>>>, respond: bool) -> Self {
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
        _request: &JsonRpcRequest,
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
        _request: &JsonRpcRequest,
        response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        self.record("resp");
        Ok(push_step(response, &format!("{}:resp", self.name)))
    }

    fn on_error(&self, _ctx: &McpContext, _request: &JsonRpcRequest, error: McpError) -> McpError {
        self.record("err");
        error
    }
}

/// Middleware that fails in `on_request` with a configured error.
///
/// Primarily intended for tests that verify error stack ordering and rewriting.
#[derive(Debug, Clone)]
pub(crate) struct FailingRequestMiddleware {
    name: &'static str,
    events: Arc<Mutex<Vec<String>>>,
    error: McpError,
}

impl FailingRequestMiddleware {
    pub(crate) fn new(
        name: &'static str,
        events: Arc<Mutex<Vec<String>>>,
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
        _request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        self.record("req");
        Err(self.error.clone())
    }

    fn on_response(
        &self,
        _ctx: &McpContext,
        _request: &JsonRpcRequest,
        response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        self.record("resp");
        Ok(response)
    }

    fn on_error(&self, _ctx: &McpContext, _request: &JsonRpcRequest, error: McpError) -> McpError {
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
