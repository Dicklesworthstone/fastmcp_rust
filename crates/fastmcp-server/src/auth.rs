//! Authentication provider hooks for MCP servers.
//!
//! Auth providers are transport-agnostic and operate on the JSON-RPC
//! request payload. They may populate [`AuthContext`] to be stored in
//! session state for downstream handlers.

use fastmcp_core::{AuthContext, McpContext, McpResult};

/// Authentication request view used by providers.
#[derive(Debug, Clone, Copy)]
pub struct AuthRequest<'a> {
    /// JSON-RPC method name.
    pub method: &'a str,
    /// Raw params payload (if present).
    pub params: Option<&'a serde_json::Value>,
    /// Internal request ID (u64) used for tracing.
    pub request_id: u64,
}

/// Authentication provider interface.
///
/// Implementations decide whether a request is allowed and may return
/// an [`AuthContext`] describing the authenticated subject.
pub trait AuthProvider: Send + Sync {
    /// Authenticate an incoming request.
    ///
    /// Return `Ok(AuthContext)` to allow, or an `Err(McpError)` to deny.
    fn authenticate(&self, ctx: &McpContext, request: AuthRequest<'_>) -> McpResult<AuthContext>;
}

/// Default allow-all provider (returns anonymous auth context).
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllAuthProvider;

impl AuthProvider for AllowAllAuthProvider {
    fn authenticate(&self, _ctx: &McpContext, _request: AuthRequest<'_>) -> McpResult<AuthContext> {
        Ok(AuthContext::anonymous())
    }
}
