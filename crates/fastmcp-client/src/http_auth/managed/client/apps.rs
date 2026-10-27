//! Bounded Apps Hosts whose entire lifetime stays inside a managed OAuth grant.
//!
//! Authenticated discovery, Host effects, MRTR and opted-in Tasks retain the
//! original credential lifetime. No raw client, bridge or stream escapes.

use super::callbacks::CallbackBoundary;
use super::{ManagedHttpClient, ManagedHttpClientError};
use crate::http_auth::managed::{OAuthSessionError, deadline_after};
use crate::mcp_apps::{
    McpAppsHostError, McpAppsViewTool, McpAppsWireBridgeTransport, McpAppsWireHostConfiguration,
    McpAppsWireHostEffects,
};
use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    McpAppsBridgeLifecycle, McpAppsCancelledControlParams, McpAppsDisplayMode,
    McpAppsDisplayModeParams, McpAppsJsonRpcRequestId, McpAppsProgressControlParams,
    McpAppsRoutedMethod, McpAppsSamplingParams, McpAppsSamplingResult,
    McpAppsUpdateModelContextParams,
};
use serde_json::Value;
use std::fmt;
use std::future::{Future, poll_fn};
use std::task::Poll;

/// Work limit for one credential-bound View.
///
/// The managed client's operation timeout independently bounds the entire
/// session. A bridge turn may receive matching cancellation while waiting for
/// a result, or expire an outstanding request; this is not an exact frame count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedMcpAppsLimits {
    maximum_turns: usize,
}

impl ManagedMcpAppsLimits {
    /// Allows between one and 4,096 bridge turns.
    pub fn new(maximum_turns: usize) -> Result<Self, ManagedMcpAppsError> {
        if !(1..=4_096).contains(&maximum_turns) {
            return Err(ManagedMcpAppsError::InvalidPolicy);
        }
        Ok(Self { maximum_turns })
    }
}

impl Default for ManagedMcpAppsLimits {
    fn default() -> Self {
        Self { maximum_turns: 256 }
    }
}

/// Why a session finished. Neither outcome retains a live View.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedMcpAppsOutcome {
    /// The ordinary graceful teardown exchange completed.
    ViewClosed { processed_turns: usize },
    /// Local work policy ended the session without claiming peer teardown.
    TurnLimit { processed_turns: usize },
}

/// Sanitized failures; peer data, credentials and callback messages are omitted.
#[derive(Debug)]
pub enum ManagedMcpAppsError {
    InvalidPolicy,
    Managed(ManagedHttpClientError),
    NotNegotiated,
    Bridge,
}

impl fmt::Display for ManagedMcpAppsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid managed Apps session policy",
            Self::Managed(_) => "managed Apps authorization or transport failed",
            Self::NotNegotiated => "authenticated peer did not activate MCP Apps",
            Self::Bridge => "managed Apps bridge failed",
        })
    }
}
impl std::error::Error for ManagedMcpAppsError {}
impl From<OAuthSessionError> for ManagedMcpAppsError {
    fn from(error: OAuthSessionError) -> Self {
        Self::Managed(ManagedHttpClientError::Session(error))
    }
}

impl ManagedHttpClient {
    /// Serves one View after authenticated Apps discovery under this login.
    ///
    /// Select Apps on the supplied ClientBuilder before constructing this
    /// client. The embedder supplies its isolated carrier and explicit Host
    /// effects/consent policy. No renderer, browser authentication, credentials
    /// or catalog authorization is fabricated. Admitted tool calls and resource
    /// reads are forwarded; same-server catalog listing remains disabled because
    /// this runner has no catalog binding.
    ///
    /// The original operation timeout covers acquisition, discovery, View
    /// input, callbacks and continuations. Credential expiry, revocation,
    /// login closure or cancellation drops the whole bridge. A View never
    /// refreshes or silently rebinds to a different credential. A later
    /// explicit session must negotiate and initialize its own View again.
    ///
    /// Tasks additionally require this client's explicit with_tasks selection
    /// and per-call Host consent. Local cancellation stops observation; it does
    /// not implicitly issue durable remote tasks/cancel.
    ///
    /// Every started session retires this client's connection and catalog
    /// cursors on return, failure or abandonment. Sibling clients sharing the
    /// login remain usable. No raw client, bridge or stream is returned.
    pub async fn serve_mcp_apps_wire_host<T, E>(
        &mut self,
        cx: &Cx,
        transport: T,
        configuration: McpAppsWireHostConfiguration,
        effects: E,
        limits: ManagedMcpAppsLimits,
    ) -> Result<ManagedMcpAppsOutcome, ManagedMcpAppsError>
    where
        T: McpAppsWireBridgeTransport,
        E: McpAppsWireHostEffects,
    {
        self.serve_mcp_apps_wire_host_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            transport,
            configuration,
            effects,
            limits,
        )
        .await
    }

    /// Explicit-cancellation counterpart of Self::serve_mcp_apps_wire_host.
    #[allow(clippy::too_many_arguments)]
    pub async fn serve_mcp_apps_wire_host_with_cancellation<T, E>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        transport: T,
        configuration: McpAppsWireHostConfiguration,
        effects: E,
        limits: ManagedMcpAppsLimits,
    ) -> Result<ManagedMcpAppsOutcome, ManagedMcpAppsError>
    where
        T: McpAppsWireBridgeTransport,
        E: McpAppsWireHostEffects,
    {
        if self.closed {
            return Err(ManagedMcpAppsError::Managed(ManagedHttpClientError::Closed));
        }
        // Take custody before any await. Abandonment cannot restore consumed
        // response state or previously issued catalog cursors.
        let previous = self.connection.take();
        self.session.check(cx, cancellation)?;
        let deadline = deadline_after(cx, self.operation_timeout)?;
        let session = self.session.clone();
        let builder = self.builder.clone();
        #[cfg(feature = "tasks")]
        let tasks_enabled = self.tasks_enabled;
        let guarded = session.await_active(
            cx,
            cancellation,
            deadline,
            None,
            Box::pin(async {
                let snapshot = session
                    .credential_with_cancellation(cx, cancellation)
                    .await?;
                let reusable = previous.filter(|old| old.generation == snapshot.generation());
                session
                    .await_credential(
                        cx,
                        cancellation,
                        deadline,
                        snapshot.expires_at(),
                        &snapshot.credential.revoked,
                        Box::pin(async {
                            let mut client = match reusable {
                                Some(connection) => connection.client,
                                None => match builder
                                    .http_bearer_credential(snapshot.credential().clone())
                                    .connect_http_client_with_cx(cx)
                                    .await
                                {
                                    Ok(client) => client,
                                    Err(_) => {
                                        return Ok(Err(ManagedMcpAppsError::Managed(
                                            ManagedHttpClientError::Connection,
                                        )));
                                    }
                                },
                            };
                            if !client.mcp_apps_active() {
                                return Ok(Err(ManagedMcpAppsError::NotNegotiated));
                            }
                            let boundary =
                                CallbackBoundary::new(&session, cancellation, deadline, &snapshot);
                            if boundary.install(cx, &mut client).is_err() {
                                return Ok(Err(ManagedMcpAppsError::Bridge));
                            }
                            let transport = GuardedTransport {
                                inner: transport,
                                boundary: boundary.clone(),
                            };
                            let effects = GuardedEffects {
                                inner: effects,
                                cx,
                                boundary: boundary.clone(),
                                #[cfg(feature = "tasks")]
                                tasks_enabled,
                            };
                            let host = match client.mcp_apps_wire_host(transport, configuration) {
                                Ok(host) => host,
                                Err(_) => return Ok(Err(ManagedMcpAppsError::Bridge)),
                            };
                            let mut host = host.with_effects(effects);
                            for processed_turns in 1..=limits.maximum_turns {
                                // Includes deferred frames that do not revisit the
                                // carrier. Boxing avoids retaining the large Host
                                // processing future inline in the managed runner.
                                if guarded_call(&boundary, cx, || Box::pin(host.process_next(cx)))
                                    .await
                                    .and_then(std::convert::identity)
                                    .is_err()
                                {
                                    return Ok(Err(ManagedMcpAppsError::Bridge));
                                }
                                if host.lifecycle() == McpAppsBridgeLifecycle::Closed {
                                    return Ok(Ok(ManagedMcpAppsOutcome::ViewClosed {
                                        processed_turns,
                                    }));
                                }
                            }
                            Ok(Ok(ManagedMcpAppsOutcome::TurnLimit {
                                processed_turns: limits.maximum_turns,
                            }))
                        }),
                    )
                    .await
            }),
        );
        // Both guards recheck authority before publishing any completed value.
        // Their precise cancellation/expiry reason wins over a bridge refusal.
        Box::pin(guarded).await?
    }
}

// Check callback construction, each poll and destruction of a ready future.
// A future's constructor, poll or Drop may revoke the login in the same poll;
// no returned answer may then authorize a continuation or View disclosure.
async fn guarded_call<T, F>(
    boundary: &CallbackBoundary,
    cx: &Cx,
    construct: impl FnOnce() -> F,
) -> Result<T, McpAppsHostError>
where
    F: Future<Output = T>,
{
    boundary.check(cx).map_err(McpAppsHostError::Core)?;
    let mut future = Some(Box::pin(construct()));
    boundary.check(cx).map_err(McpAppsHostError::Core)?;
    poll_fn(|task| {
        boundary.check(cx).map_err(McpAppsHostError::Core)?;
        let result = future
            .as_mut()
            .expect("guard is polled only until completion")
            .as_mut()
            .poll(task);
        if result.is_ready() {
            drop(future.take());
        }
        boundary.check(cx).map_err(McpAppsHostError::Core)?;
        match result {
            Poll::Ready(value) => Poll::Ready(Ok(value)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

struct GuardedTransport<T> {
    inner: T,
    boundary: CallbackBoundary,
}
impl<T: McpAppsWireBridgeTransport> McpAppsWireBridgeTransport for GuardedTransport<T> {
    async fn send_to_view(&mut self, cx: &Cx, frame: String) -> Result<(), McpAppsHostError> {
        guarded_call(&self.boundary, cx, || self.inner.send_to_view(cx, frame)).await?
    }
    async fn receive_from_view(&mut self, cx: &Cx) -> Result<String, McpAppsHostError> {
        guarded_call(&self.boundary, cx, || self.inner.receive_from_view(cx)).await?
    }
}

struct GuardedEffects<'a, E> {
    inner: E,
    cx: &'a Cx,
    boundary: CallbackBoundary,
    #[cfg(feature = "tasks")]
    tasks_enabled: bool,
}
impl<E: McpAppsWireHostEffects> McpAppsWireHostEffects for GuardedEffects<'_, E> {
    async fn operation(
        &mut self,
        method: McpAppsRoutedMethod,
        params: Option<&Value>,
    ) -> Result<Value, McpAppsHostError> {
        guarded_call(&self.boundary, self.cx, || {
            self.inner.operation(method, params)
        })
        .await?
    }
    async fn approve_view_tool_call(
        &mut self,
        cx: &Cx,
        tool: &McpAppsViewTool,
        params: &fastmcp_protocol::McpAppsToolCallParams,
    ) -> Result<(), McpAppsHostError> {
        guarded_call(&self.boundary, cx, || {
            self.inner.approve_view_tool_call(cx, tool, params)
        })
        .await?
    }
    async fn sampling_create_message(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: &McpAppsSamplingParams,
    ) -> Result<McpAppsSamplingResult, McpAppsHostError> {
        guarded_call(&self.boundary, cx, || {
            self.inner.sampling_create_message(cx, cancellation, params)
        })
        .await?
    }
    async fn resolve_server_input(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: McpAppsRoutedMethod,
        params: &Value,
        input_required: &fastmcp_protocol::InputRequiredResult,
    ) -> Result<fastmcp_protocol::FinalInputResponses, McpAppsHostError> {
        guarded_call(&self.boundary, cx, || {
            self.inner
                .resolve_server_input(cx, cancellation, method, params, input_required)
        })
        .await?
    }
    #[cfg(feature = "tasks")]
    async fn server_task_policy(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: &Value,
    ) -> Result<Option<crate::mcp_apps::McpAppsServerTaskPolicy>, McpAppsHostError> {
        self.boundary.check(cx).map_err(McpAppsHostError::Core)?;
        if !self.tasks_enabled {
            return Ok(None);
        }
        guarded_call(&self.boundary, cx, || {
            self.inner.server_task_policy(cx, cancellation, params)
        })
        .await?
    }
    #[cfg(feature = "tasks")]
    async fn approve_server_task(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: &Value,
        task: &crate::FinalTask,
    ) -> Result<(), McpAppsHostError> {
        self.boundary.check(cx).map_err(McpAppsHostError::Core)?;
        if !self.tasks_enabled {
            return Err(McpAppsHostError::Core(
                fastmcp_core::McpError::invalid_request(
                    "Managed Apps Tasks require explicit local selection",
                ),
            ));
        }
        guarded_call(&self.boundary, cx, || {
            self.inner
                .approve_server_task(cx, cancellation, params, task)
        })
        .await?
    }
    async fn update_model_context(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: &McpAppsUpdateModelContextParams,
    ) -> Result<(), McpAppsHostError> {
        guarded_call(&self.boundary, cx, || {
            self.inner.update_model_context(cx, cancellation, params)
        })
        .await?
    }
    async fn request_display_mode(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: McpAppsDisplayModeParams,
        current: Option<McpAppsDisplayMode>,
    ) -> Result<McpAppsDisplayModeParams, McpAppsHostError> {
        guarded_call(&self.boundary, cx, || {
            self.inner
                .request_display_mode(cx, cancellation, params, current)
        })
        .await?
    }
    async fn notification(
        &mut self,
        method: McpAppsRoutedMethod,
        params: Option<&Value>,
    ) -> Result<(), McpAppsHostError> {
        guarded_call(&self.boundary, self.cx, || {
            self.inner.notification(method, params)
        })
        .await?
    }
    async fn progress(
        &mut self,
        request_id: &McpAppsJsonRpcRequestId,
        params: &McpAppsProgressControlParams,
    ) -> Result<(), McpAppsHostError> {
        guarded_call(&self.boundary, self.cx, || {
            self.inner.progress(request_id, params)
        })
        .await?
    }
    fn cancelled(
        &mut self,
        cx: &Cx,
        request_id: &McpAppsJsonRpcRequestId,
        params: &McpAppsCancelledControlParams,
    ) -> Result<(), McpAppsHostError> {
        self.boundary.check(cx).map_err(McpAppsHostError::Core)?;
        let result = self.inner.cancelled(cx, request_id, params);
        self.boundary.check(cx).map_err(McpAppsHostError::Core)?;
        result
    }
    async fn approve_view_teardown(&mut self) -> bool {
        guarded_call(&self.boundary, self.cx, || {
            self.inner.approve_view_teardown()
        })
        .await
        .unwrap_or(false)
    }
}
