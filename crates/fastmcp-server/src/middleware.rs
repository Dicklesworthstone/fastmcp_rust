//! Middleware hooks for request/response interception.
//!
//! This provides a minimal, synchronous middleware system for MCP requests.
//! Middleware can short-circuit requests, transform responses, and rewrite errors.

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
/// short-circuit and response transform capabilities.
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
    fn on_error(
        &self,
        _ctx: &McpContext,
        _request: &JsonRpcRequest,
        error: McpError,
    ) -> McpError {
        error
    }
}
