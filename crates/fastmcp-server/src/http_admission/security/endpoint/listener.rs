//! Caller-owned, origin-guarded native HTTP listener.
//!
//! Unlike the embedding adapter, this path owns socket admission, bounded H1
//! decoding and response writes. Select it with `Server::bind_secured_http` or
//! `Server::serve_secured_http`. It is modern MCP only, even in a legacy build.
//! Hosted OAuth authorization/token routes must use a separate listener; bind
//! refuses that combination rather than silently dropping or weakening routes.
//!
//! The supplied origin policy is the single CORS authority for this listener.
//! Its exact allowlist also configures the existing downstream request handler.
//! Authentication, authorization and protocol admission are never bypassed.

mod connection;
mod ingress;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::{McpError, McpResult};
use fastmcp_protocol::protocol_policy::ProtocolPolicy;

use super::super::HttpSecurityPolicy;
use crate::{
    BoundHttpServer, HTTP_ACCEPT_CANCEL_POLL, HttpConnectionChildren,
    HttpListenerShutdown, HttpNonquiescentShutdown, HttpServerShutdown,
    MODERN_HTTP_SESSION_REAP_INTERVAL, Server, detach_live_modern_http_sessions,
    expire_live_modern_http_sessions, finish_live_modern_http_sessions,
    take_unsettled_retired_modern_http_dispatches,
};

/// Finite request-read and individual response-write bounds. Request time is
/// shared by the head and body, not renewed for each trickled byte. Each SSE
/// frame has a finite write allowance; a subscription's execution lifetime is
/// still owned by the server's existing request and response-body policies.
#[derive(Clone, Copy, Debug)]
pub struct SecuredHttpIoLimits {
    request_timeout: Duration,
    write_timeout: Duration,
}

impl Default for SecuredHttpIoLimits {
    fn default() -> Self {
        Self { request_timeout: Duration::from_secs(60), write_timeout: Duration::from_secs(15) }
    }
}

impl SecuredHttpIoLimits {
    pub fn new(request_timeout: Duration, write_timeout: Duration) -> McpResult<Self> {
        if request_timeout.is_zero() || write_timeout.is_zero()
            || request_timeout > Duration::from_secs(900)
            || write_timeout > Duration::from_secs(300)
        {
            return Err(McpError::invalid_request("invalid secured HTTP I/O limits"));
        }
        Ok(Self { request_timeout, write_timeout })
    }

    pub fn request_timeout(self) -> Duration { self.request_timeout }
    pub fn write_timeout(self) -> Duration { self.write_timeout }
}

/// Native bound socket and immutable security policy. Accepted connection
/// children use the ordinary listener's limiter, response-body registry,
/// termination receipts and caller-owned nonquiescent shutdown outcome.
#[must_use = "serve the bound listener on its caller-owned context"]
pub struct BoundSecuredHttpServer {
    inner: BoundHttpServer,
    policy: Arc<HttpSecurityPolicy>,
    io: SecuredHttpIoLimits,
}

impl Server {
    /// Binds a modern-only secured MCP listener without starting an accept loop.
    ///
    /// The policy path must match the configured MCP path. Selecting this API
    /// explicitly selects its CORS policy: the same exact origins are installed
    /// on the downstream handler, replacing its older CORS allowlist. The lower
    /// of the existing server body limit and policy body limit always wins.
    /// Host validation uses the configured public authority, never Forwarded.
    /// TLS termination remains the deployment's responsibility, as for bind_http.
    ///
    /// Unsupported protocol policies, route mismatches and co-hosted OAuth routes
    /// fail before a socket is bound or any startup hook runs.
    pub async fn bind_secured_http(
        mut self,
        cx: &Cx,
        addr: impl Into<String>,
        policy: HttpSecurityPolicy,
    ) -> McpResult<BoundSecuredHttpServer> {
        if cx.checkpoint().is_err() { return Err(McpError::request_cancelled()); }
        if self.protocol_policy != ProtocolPolicy::ModernOnly {
            return Err(McpError::invalid_request("secured HTTP requires ModernOnly policy"));
        }
        if self.http_config.handler_config.base_path != policy.endpoint().path() {
            return Err(McpError::invalid_request("secured HTTP policy does not match the MCP route"));
        }
        if self.oauth_http_routes.is_some() {
            return Err(McpError::invalid_request("secured MCP listener requires separate OAuth routes"));
        }
        self.http_config.handler_config.allow_cors = true;
        self.http_config.handler_config.cors_origins = policy.origins.clone();
        self.http_config.handler_config.max_body_size = self.http_config.handler_config.max_body_size
            .min(policy.endpoint().limits().max_body_bytes());
        let inner = self.bind_http(cx, addr).await?;
        Ok(BoundSecuredHttpServer { inner, policy: Arc::new(policy), io: SecuredHttpIoLimits::default() })
    }

    /// Binds and serves the secured native listener on the caller's runtime.
    pub async fn serve_secured_http(
        self,
        cx: &Cx,
        addr: impl Into<String>,
        policy: HttpSecurityPolicy,
    ) -> McpResult<HttpServerShutdown> {
        self.bind_secured_http(cx, addr, policy).await?.serve(cx).await
    }
}

impl BoundSecuredHttpServer {
    pub fn local_addr(&self) -> McpResult<SocketAddr> { self.inner.local_addr() }

    /// Changes only this not-yet-served listener's finite I/O limits.
    pub fn with_io_limits(mut self, limits: SecuredHttpIoLimits) -> Self {
        self.io = limits;
        self
    }

    /// Accepts secured HTTP requests until caller cancellation or listener error.
    /// Capacity refusal drops the socket without spawning an error-writing task.
    /// Shutdown retains the native two-phase terminal drain and transfers any
    /// noncooperating children to `HttpServerShutdown::Nonquiescent`.
    ///
    /// No legacy session, runtime, detached task or process-global retention is
    /// created. The listener and all connection children stay in the caller's
    /// region. As with the existing listener, settle a nonquiescent outcome.
    #[allow(clippy::manual_async_fn)]
    pub fn serve(self, cx: &Cx) -> impl Future<Output = McpResult<HttpServerShutdown>> + Send + '_ {
        async move {
            let bound = self.inner;
            let server = Arc::clone(&bound.endpoint.server);
            server.init_rich_logging();
            if let Some(stats) = &server.stats { stats.connection_opened(); }
            if !server.run_startup_hook() {
                server.graceful_shutdown_returning();
                return Err(McpError::internal_error("secured HTTP startup hook failed"));
            }
            let scope = cx.scope();
            let shutdown = HttpListenerShutdown::new(cx);
            let sessions = Arc::clone(&bound.modern_sessions);
            let mut children = HttpConnectionChildren::default();
            let reaper = cx.spawn_in(&scope, move |reaper_cx| async move {
                let chunk = Duration::from_millis(100);
                let mut parked = Duration::ZERO;
                loop {
                    asupersync::time::sleep(reaper_cx.now(), chunk).await;
                    if reaper_cx.checkpoint().is_err() { break; }
                    parked += chunk;
                    if parked >= MODERN_HTTP_SESSION_REAP_INTERVAL {
                        parked = Duration::ZERO;
                        expire_live_modern_http_sessions(&sessions);
                    }
                }
            });
            let mut reaper = match reaper {
                Ok(reaper) => reaper,
                Err(_) => {
                    server.graceful_shutdown_returning();
                    return Err(McpError::internal_error("secured HTTP reaper admission failed"));
                }
            };
            let result = loop {
                children.reap_finished();
                if cx.checkpoint().is_err() { break Ok(()); }
                let accepted = match asupersync::time::timeout(
                    cx.now(), HTTP_ACCEPT_CANCEL_POLL, bound.listener.accept(),
                ).await {
                    Ok(accepted) => accepted,
                    Err(_) => continue,
                };
                let (stream, _) = match accepted {
                    Ok(connection) => connection,
                    Err(_) if cx.checkpoint().is_err() => break Ok(()),
                    Err(_) => break Err(McpError::internal_error("secured HTTP accept failed")),
                };
                let Some(permit) = bound.connection_limiter.try_acquire() else {
                    drop(stream);
                    continue;
                };
                let endpoint = Arc::clone(&bound.endpoint);
                let sessions = Arc::clone(&bound.modern_sessions);
                let policy = Arc::clone(&self.policy);
                let io = self.io;
                let stopping = shutdown.clone();
                match cx.spawn_in(&scope, move |connection_cx| async move {
                    let _permit = permit;
                    let connection: std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> = Box::pin(
                        connection::serve(&connection_cx, stream, endpoint, sessions, stopping, policy, io),
                    );
                    connection.await;
                }) {
                    Ok(child) => children.tasks.push(child),
                    Err(_) => break Err(McpError::internal_error("secured HTTP connection admission failed")),
                }
            };
            shutdown.request();
            let _ = server.router.close_stateless_mrtr_exchanges();
            let terminal = server.final_subscriptions.terminate_with_receipt();
            reaper.abort();
            let _ = reaper.join(cx).await;
            let closing = detach_live_modern_http_sessions(&bound.modern_sessions);
            children.drain_terminal_controls(&terminal).await;
            children.tasks.extend(finish_live_modern_http_sessions(&bound.modern_sessions, closing).await);
            server.cancel_active_requests(asupersync::types::CancelKind::Shutdown, false);
            let _ = children.drain_cooperative_shutdown().await;
            children.tasks.extend(take_unsettled_retired_modern_http_dispatches(&bound.modern_sessions));
            children.reap_finished();
            server.graceful_shutdown_returning();
            if children.tasks.is_empty() {
                if !children.terminal_failures.is_empty() {
                    return Err(McpError::internal_error("secured HTTP child settlement failed"));
                }
                result?;
                Ok(HttpServerShutdown::Quiescent)
            } else {
                Ok(HttpServerShutdown::Nonquiescent(HttpNonquiescentShutdown {
                    children, listener_error: result.err(),
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secured_io_bounds_are_finite_and_defaults_are_admissible() {
        let limits = SecuredHttpIoLimits::default();
        assert!(SecuredHttpIoLimits::new(limits.request_timeout(), limits.write_timeout()).is_ok());
        assert!(SecuredHttpIoLimits::new(Duration::ZERO, Duration::from_secs(1)).is_err());
        assert!(SecuredHttpIoLimits::new(Duration::from_secs(1), Duration::ZERO).is_err());
        assert!(SecuredHttpIoLimits::new(Duration::from_secs(901), Duration::from_secs(1)).is_err());
        assert!(SecuredHttpIoLimits::new(Duration::from_secs(1), Duration::from_secs(301)).is_err());
    }
}
