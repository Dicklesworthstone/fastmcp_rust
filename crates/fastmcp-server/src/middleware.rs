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

use std::sync::Arc;

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

impl<T> Middleware for Arc<T>
where
    T: Middleware + ?Sized,
{
    fn on_request(
        &self,
        ctx: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        (**self).on_request(ctx, request)
    }

    fn on_response(
        &self,
        ctx: &McpContext,
        request: &JsonRpcRequest,
        response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        (**self).on_response(ctx, request, response)
    }

    fn on_error(&self, ctx: &McpContext, request: &JsonRpcRequest, error: McpError) -> McpError {
        (**self).on_error(ctx, request, error)
    }
}
