//! Native modern WebSocket requests for a composed proxy.
//!
//! The connection has one receive owner. Prepared requests only clone its
//! async mutex; they acquire it on the caller's runtime after the proxy route
//! mutex has been released. No reader task, private runtime, or synchronous
//! transport adapter is introduced here.

#[cfg(test)]
mod tests;
#[cfg(feature = "tasks")]
mod tasks;
#[cfg(feature = "tasks")]
pub use tasks::{PreparedProxyWebSocketTaskListener, PreparedProxyWebSocketTaskRequest};

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::task::Poll;

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::sync::{LockError, Mutex, OwnedMutexGuard};
use fastmcp_client::{StdioSubscriptionEvent, WebSocketCatalogSubscriptionOwner, WebSocketClient};
use fastmcp_core::{McpContext, McpError, McpErrorCode, McpRequestCancellation, McpResult};
use fastmcp_protocol::common_types::Implementation;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    ClientCapabilities, Content, CoreRequest, CoreResult, FINAL_LOG_LEVEL_META_KEY,
    FinalProgressNotificationParams, FinalRequestMeta, JsonRpcError, Prompt, PromptMessage,
    Resource, ResourceContent, ResourceTemplate, ServerDiscoverResult, SubscriptionFilter, Tool,
};

use super::{
    ProgressCallback, ProxyAsyncRequest, ProxyBackend, ProxyCatalogListener,
    ProxyCatalogListenerEvent, ProxyNativeCatalogCleanup, ProxyPollTimer,
    await_proxy_operation_or_cancellation, await_proxy_request_or_cancellation, catalog_capability,
    discovery_supports_final_capability, discovery_supports_final_completion,
    inbound_client_capabilities, inbound_identity_implementation, inbound_logging_level,
    relay_upstream_log_message,
};
use crate::handler::BoxFuture;

/// A modern WebSocket upstream owned by a proxy route.
///
/// Construct this from an already negotiated [`WebSocketClient`], or use
/// [`super::ProxyClient::from_websocket`]. Catalogs and requests execute through
/// the proxy's asynchronous APIs and retain final protocol models, including
/// open result members and `input_required` outcomes.
///
/// Clones share one connection and serialize its receive turns with a
/// cancellation-aware mutex. Per-request identity, capabilities, logging, and
/// progress metadata are reconstructed from the current [`McpContext`]; they
/// never mutate the shared client session. Catalog and resource subscriptions
/// share bounded receive turns with ordinary requests; dropping their owner
/// retires only that listen before the connection's next operation. This
/// adapter relays Tasks only when the upstream admits the full official
/// extension and the gateway configures a positive Task retention ceiling.
pub struct ProxyWebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    client: Arc<Mutex<WebSocketClient<IO>>>,
    discovery: Arc<ServerDiscoverResult>,
    client_implementation: Implementation,
    client_capabilities: ClientCapabilities,
    instructions: Option<String>,
}

impl<IO> Clone for ProxyWebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn clone(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
            discovery: Arc::clone(&self.discovery),
            client_implementation: self.client_implementation.clone(),
            client_capabilities: self.client_capabilities.clone(),
            instructions: self.instructions.clone(),
        }
    }
}

impl<IO> std::fmt::Debug for ProxyWebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyWebSocketClient")
            .field("era", &ProtocolEra::Modern2026)
            .field("implementation", &self.discovery.implementation())
            .finish_non_exhaustive()
    }
}

impl<IO> ProxyWebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Takes ownership of a successfully negotiated modern connection.
    ///
    /// Exact-2024, closed, and occupied connections are rejected. Finish any
    /// earlier request or subscription before transferring its ownership. The
    /// retained discovery snapshot determines catalog and completion
    /// availability; missing discovery is an error rather than an empty
    /// upstream catalog.
    pub fn new(client: WebSocketClient<IO>) -> McpResult<Self> {
        if client.selected_protocol_era() != ProtocolEra::Modern2026 {
            return Err(McpError::invalid_request(
                "Proxy WebSocket upstream requires MCP 2026-07-28",
            ));
        }
        if client.is_closed() {
            return Err(McpError::invalid_request(
                "Proxy WebSocket upstream connection is closed",
            ));
        }
        if client.has_pending_protocol_work() {
            return Err(McpError::invalid_request(
                "Proxy WebSocket upstream still owns a request, subscription, or cleanup",
            ));
        }
        let session = client.session();
        let discovery = session.server_discovery().cloned().ok_or_else(|| {
            McpError::invalid_request("Proxy WebSocket upstream has no modern discovery snapshot")
        })?;
        let client_implementation = session.modern_client_implementation();
        let mut client_capabilities = session.client_capabilities().clone();
        // This adapter owns core requests and catalog subscriptions. A locally
        // configured extension must not implicitly activate another relay.
        client_capabilities.extensions = None;
        let instructions = session.instructions().map(str::to_owned);
        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            discovery: Arc::new(discovery),
            client_implementation,
            client_capabilities,
            instructions,
        })
    }

    /// Closes the shared upstream connection on the caller's runtime.
    ///
    /// Keep a clone before installing this backend when explicit connection
    /// shutdown is needed. All clones observe the native client's terminal
    /// state, and repeated closes retain any native cleanup failure.
    pub async fn close(&self, cx: &Cx) -> McpResult<()> {
        let mut client = OwnedMutexGuard::lock(Arc::clone(&self.client), cx)
            .await
            .map_err(websocket_lock_error)?;
        client.close(cx).await
    }
}

/// Sealed native ownership proof for cancellation-aware WebSocket execution.
///
/// The proxy may await this owner's bounded native cancellation cleanup
/// instead of dropping its future when cancellation wins. Its private field
/// prevents custom backends from opting arbitrary work into that exception.
#[doc(hidden)]
pub struct PreparedProxyWebSocketRequest {
    execution: Box<dyn ProxyAsyncRequest>,
}

impl PreparedProxyWebSocketRequest {
    pub(super) fn into_execution(self) -> Box<dyn ProxyAsyncRequest> {
        self.execution
    }
}

/// Sealed opening for a request-owned native WebSocket catalog listener.
#[doc(hidden)]
pub struct PreparedProxyWebSocketCatalogListener {
    opening: Box<dyn WebSocketCatalogOpening>,
}

impl PreparedProxyWebSocketCatalogListener {
    pub(super) async fn open(self, ctx: &McpContext) -> McpResult<Box<dyn ProxyCatalogListener>> {
        self.opening.open(ctx).await
    }
}

trait WebSocketCatalogOpening: Send {
    fn open(
        self: Box<Self>,
        ctx: &McpContext,
    ) -> BoxFuture<'_, McpResult<Box<dyn ProxyCatalogListener>>>;
}

struct WebSocketCatalogRequest<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    backend: ProxyWebSocketClient<IO>,
    notifications: SubscriptionFilter,
}

impl<IO> WebSocketCatalogOpening for WebSocketCatalogRequest<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn open(
        self: Box<Self>,
        ctx: &McpContext,
    ) -> BoxFuture<'_, McpResult<Box<dyn ProxyCatalogListener>>> {
        Box::pin(async move {
            ctx.ensure_live()?;
            let metadata = self.backend.request_metadata(ctx)?;
            let backend_client = Arc::clone(&self.backend.client);
            let mut client = await_proxy_request_or_cancellation(ctx, async {
                OwnedMutexGuard::lock(Arc::clone(&backend_client), ctx.cx())
                    .await
                    .map_err(websocket_lock_error)
            })
            .await?;
            ctx.ensure_live()?;
            // A dropped send retains the native client's uncertainty guard;
            // after commitment the returned owner marks this exact listen for
            // retirement if cancellation wins before its acknowledgement.
            let owner = await_proxy_request_or_cancellation(ctx, async {
                client
                    .open_owned_subscriptions_listener(ctx.cx(), self.notifications, metadata)
                    .await
            })
            .await?;
            drop(client);
            ctx.ensure_live()?;
            Ok(Box::new(WebSocketCatalogListener {
                client: backend_client,
                _owner: owner,
            }) as Box<dyn ProxyCatalogListener>)
        })
    }
}

struct WebSocketCatalogListener<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    client: Arc<Mutex<WebSocketClient<IO>>>,
    _owner: WebSocketCatalogSubscriptionOwner,
}

impl<IO> ProxyCatalogListener for WebSocketCatalogListener<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn native_cleanup(&self) -> Option<ProxyNativeCatalogCleanup> {
        Some(ProxyNativeCatalogCleanup { _private: () })
    }

    fn next_async<'a>(
        &'a mut self,
        cx: &'a Cx,
        request_cancellation: &'a McpRequestCancellation,
    ) -> BoxFuture<'a, McpResult<ProxyCatalogListenerEvent>> {
        Box::pin(async move {
            loop {
                let mut client = await_proxy_operation_or_cancellation(
                    cx,
                    request_cancellation,
                    Box::pin(async {
                        OwnedMutexGuard::lock(Arc::clone(&self.client), cx)
                            .await
                            .map_err(websocket_lock_error)
                    }),
                )
                .await?;
                // Only the native receive is time-sliced. A selected timeout
                // or cancellation retains its bounded control-write cleanup;
                // dropping that write just to yield the mutex is not safe.
                let event = client
                    .poll_subscription_event(cx, request_cancellation)
                    .await?;
                drop(client);
                if let Some(event) = event {
                    return Ok(match event {
                        StdioSubscriptionEvent::Acknowledged(filter) => {
                            ProxyCatalogListenerEvent::Acknowledged(filter)
                        }
                        StdioSubscriptionEvent::Notification(notification) => {
                            ProxyCatalogListenerEvent::Notification(notification)
                        }
                        StdioSubscriptionEvent::Terminal => ProxyCatalogListenerEvent::Terminal,
                    });
                }
                // Let queued ordinary requests acquire the sole receive owner
                // before the listener begins another bounded ingress turn.
                asupersync::runtime::yield_now().await;
            }
        })
    }
}

struct WebSocketCoreRequest<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    backend: ProxyWebSocketClient<IO>,
    allow_tasks: bool,
}

impl<IO> ProxyAsyncRequest for WebSocketCoreRequest<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn client_implementation(&self) -> Implementation {
        self.backend.client_implementation.clone()
    }

    fn client_capabilities(&self) -> ClientCapabilities {
        self.backend.client_capabilities.clone()
    }

    fn execute<'a>(
        self: Box<Self>,
        ctx: &'a McpContext,
        request: CoreRequest,
        on_progress: &'a mut (dyn FnMut(FinalProgressNotificationParams) + Send),
    ) -> BoxFuture<'a, McpResult<CoreResult>> {
        Box::pin(async move {
            ctx.checkpoint()?;
            let (request, parameters) =
                self.backend.prepare_parameters(ctx, request, self.allow_tasks)?;

            // A waiter owns no wire state yet, so cancellation may drop this
            // acquisition immediately. Once acquired, the native client owns
            // bounded retirement and cancellation-frame cleanup through the
            // end of its request future.
            let mut client = await_proxy_request_or_cancellation(ctx, async {
                OwnedMutexGuard::lock(Arc::clone(&self.backend.client), ctx.cx())
                    .await
                    .map_err(websocket_lock_error)
            })
            .await?;
            ctx.checkpoint()?;

            // Notifications retained before this request belong to an earlier
            // owner and must never be replayed into this caller's context.
            let _ = client.take_final_server_notifications();
            let _ = client.take_final_progress_notifications();
            let cancellation = McpRequestCancellation::new();
            let mut forward_log = |message| relay_upstream_log_message(ctx, &message);
            let outcome = drive_native_request_with_priority(
                ctx,
                &cancellation,
                client.request_with_raw_result_and_progress_and_logs(
                    ctx.cx(),
                    request.method(),
                    parameters,
                    &cancellation,
                    on_progress,
                    &mut forward_log,
                ),
                |outcome| {
                    self.allow_tasks
                        && outcome.as_ref().is_ok_and(|response| {
                            response.response.error.is_none()
                                && response.response.result.as_ref().is_some_and(|result| {
                                    result.get("resultType").and_then(serde_json::Value::as_str)
                                        == Some("task")
                                })
                        })
                },
            )
            .await;
            // Live callbacks consume matching progress and requested logs as
            // they are admitted. Native listener events use their separate
            // owned queue, so discarding these unowned notifications cannot
            // steal a catalog or resource update from its downstream request.
            let _ = client.take_final_server_notifications();
            let _ = client.take_final_progress_notifications();
            drop(client);

            // Preserve native cancellation cleanup failures before consulting
            // the caller's cancellation again. A lost cancellation write must
            // not be disguised as an ordinary cancelled request.
            let response = outcome?;
            if let Some(error) = response.response.error.as_ref() {
                return Err(websocket_upstream_rpc_error(request.method(), error));
            }
            let source = response.raw_result.as_deref().ok_or_else(|| {
                McpError::invalid_request(
                    "Proxy WebSocket upstream omitted its exact result source",
                )
            })?;
            request
                .decode_response_result(&response.response, source)
                .map_err(|error| {
                    McpError::invalid_request(format!(
                        "Proxy WebSocket upstream returned an invalid {} result: {error}",
                        request.method()
                    ))
                })
        })
    }
}

impl<IO> ProxyWebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn request_metadata(&self, ctx: &McpContext) -> McpResult<FinalRequestMeta> {
        let mut capabilities =
            inbound_client_capabilities(ctx).unwrap_or_else(|| self.client_capabilities.clone());
        capabilities.extensions = None;
        let mut metadata = FinalRequestMeta::new(capabilities);
        metadata.client_info = Some(
            inbound_identity_implementation(ctx)
                .unwrap_or_else(|| self.client_implementation.clone()),
        );
        if let Some(marker) = ctx.progress_marker() {
            metadata
                .additional_metadata
                .insert("progressToken".to_owned(), marker.clone());
        }
        if let Some(level) = inbound_logging_level(ctx) {
            metadata.additional_metadata.insert(
                FINAL_LOG_LEVEL_META_KEY.to_owned(),
                serde_json::to_value(level).map_err(McpError::from)?,
            );
        }
        Ok(metadata)
    }

    fn prepare_parameters(
        &self,
        ctx: &McpContext,
        request: CoreRequest,
        allow_tasks: bool,
    ) -> McpResult<(CoreRequest, Option<serde_json::Value>)> {
        if request.era() != ProtocolEra::Modern2026 {
            return Err(McpError::invalid_request(
                "Proxy WebSocket request contradicts the selected modern era",
            ));
        }
        let method = request.method();
        if !matches!(
            method,
            "tools/list"
                | "resources/list"
                | "resources/templates/list"
                | "prompts/list"
                | "tools/call"
                | "resources/read"
                | "prompts/get"
                | "completion/complete"
        ) {
            return Err(McpError::invalid_request(
                "Proxy WebSocket upstream does not implement this core method",
            ));
        }
        let mut parameters = request.encode_params().map_err(|error| {
            McpError::invalid_params(format!("Proxy WebSocket parameters are invalid: {error}"))
        })?;
        let object = parameters
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| {
                McpError::invalid_params("Proxy WebSocket request parameters must be an object")
            })?;

        let metadata = self.request_metadata(ctx)?;
        #[cfg(feature = "tasks")]
        let metadata = if allow_tasks {
            self.task_request_metadata(ctx)?
        } else {
            metadata
        };
        #[cfg(not(feature = "tasks"))]
        let _ = allow_tasks;
        object.insert(
            "_meta".to_owned(),
            serde_json::to_value(metadata).map_err(McpError::from)?,
        );
        let request = CoreRequest::decode(ProtocolEra::Modern2026, method, parameters.as_ref())
            .map_err(|error| {
                McpError::invalid_params(format!(
                    "Proxy WebSocket request metadata is invalid: {error}"
                ))
            })?;
        Ok((request, parameters))
    }
}

impl<IO> ProxyBackend for ProxyWebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn async_protocol_era(&self) -> Option<ProtocolEra> {
        Some(ProtocolEra::Modern2026)
    }

    fn supports_catalog_method(&self, method: &str) -> McpResult<bool> {
        discovery_supports_final_capability(&self.discovery, catalog_capability(method)?)
    }

    fn prepare_native_websocket_request(
        &mut self,
    ) -> McpResult<Option<PreparedProxyWebSocketRequest>> {
        Ok(Some(PreparedProxyWebSocketRequest {
            execution: Box::new(WebSocketCoreRequest {
                backend: self.clone(),
                allow_tasks: false,
            }),
        }))
    }

    #[cfg(feature = "tasks")]
    fn prepare_native_websocket_tasks_core_request(
        &mut self,
    ) -> McpResult<Option<PreparedProxyWebSocketRequest>> {
        super::discovery_admits_final_tasks_relay(&self.discovery)?;
        Ok(Some(PreparedProxyWebSocketRequest {
            execution: Box::new(WebSocketCoreRequest {
                backend: self.clone(),
                allow_tasks: true,
            }),
        }))
    }

    #[cfg(feature = "tasks")]
    fn supports_final_tasks_relay(&mut self) -> McpResult<bool> {
        Ok(super::discovery_admits_final_tasks_relay(&self.discovery).is_ok())
    }

    #[cfg(feature = "tasks")]
    fn start_final_task_request(
        &mut self,
        operation: super::ProxyFinalTaskOperation,
    ) -> McpResult<Option<super::ProxyFinalTaskRequest>> {
        super::discovery_admits_final_tasks_relay(&self.discovery)?;
        Ok(Some(super::ProxyFinalTaskRequest {
            kind: super::ProxyFinalTaskRequestKind::WebSocket(
                PreparedProxyWebSocketTaskRequest::new(self.clone(), operation),
            ),
        }))
    }

    #[cfg(feature = "tasks")]
    fn start_final_task_listener(
        &mut self,
        notifications: SubscriptionFilter,
    ) -> McpResult<Option<super::ProxyFinalTaskListenerRequest>> {
        super::discovery_admits_final_tasks_relay(&self.discovery)?;
        Ok(Some(super::ProxyFinalTaskListenerRequest {
            kind: super::ProxyFinalTaskListenerRequestKind::WebSocket(
                PreparedProxyWebSocketTaskListener::new(self.clone(), notifications),
            ),
        }))
    }

    fn supports_catalog_listener(&mut self) -> McpResult<bool> {
        Ok(true)
    }

    fn prepare_native_websocket_catalog_listener(
        &mut self,
        notifications: SubscriptionFilter,
    ) -> McpResult<Option<PreparedProxyWebSocketCatalogListener>> {
        Ok(Some(PreparedProxyWebSocketCatalogListener {
            opening: Box::new(WebSocketCatalogRequest {
                backend: self.clone(),
                notifications,
            }),
        }))
    }

    fn supports_completion(&mut self) -> McpResult<bool> {
        discovery_supports_final_completion(&self.discovery)
    }

    fn upstream_instructions(&self) -> McpResult<Option<String>> {
        Ok(self.instructions.clone())
    }

    fn upstream_implementation(&self) -> McpResult<Option<Implementation>> {
        Ok(self.discovery.implementation().cloned())
    }

    fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
        Err(websocket_requires_async())
    }

    fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        Err(websocket_requires_async())
    }

    fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
        Err(websocket_requires_async())
    }

    fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
        Err(websocket_requires_async())
    }

    fn call_tool(&mut self, _name: &str, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Err(websocket_requires_async())
    }

    fn call_tool_with_progress(
        &mut self,
        _name: &str,
        _arguments: serde_json::Value,
        _on_progress: ProgressCallback<'_>,
    ) -> McpResult<Vec<Content>> {
        Err(websocket_requires_async())
    }

    fn read_resource(&mut self, _uri: &str) -> McpResult<Vec<ResourceContent>> {
        Err(websocket_requires_async())
    }

    fn get_prompt(
        &mut self,
        _name: &str,
        _arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        Err(websocket_requires_async())
    }
}

fn websocket_requires_async() -> McpError {
    McpError::invalid_request(
        "Native WebSocket proxy requests require the asynchronous ProxyClient APIs",
    )
}

fn websocket_lock_error(error: LockError) -> McpError {
    match error {
        LockError::Cancelled => McpError::request_cancelled(),
        LockError::TimedOut(_) => {
            McpError::internal_error("Timed out acquiring the proxy WebSocket connection")
        }
        LockError::Poisoned | LockError::PolledAfterCompletion => {
            McpError::internal_error("Proxy WebSocket connection lock is unavailable")
        }
    }
}

/// Converts request-local deadlines into native cancellation without revoking
/// the future that owns cleanup. The private wire token deliberately does not
/// change the context's cause: a deadline must remain a deadline downstream.
async fn drive_native_request<T>(
    ctx: &McpContext,
    wire_cancellation: &McpRequestCancellation,
    operation: impl Future<Output = McpResult<T>>,
) -> McpResult<T> {
    drive_native_request_with_priority(ctx, wire_cancellation, operation, |_| false).await
}

async fn drive_native_request_with_priority<T>(
    ctx: &McpContext,
    wire_cancellation: &McpRequestCancellation,
    operation: impl Future<Output = McpResult<T>>,
    keep_committed_result: impl Fn(&McpResult<T>) -> bool,
) -> McpResult<T> {
    let mut operation = std::pin::pin!(operation);
    let request_cancellation = ctx.request_cancellation();
    let mut cancelled = std::pin::pin!(request_cancellation.cancelled());
    let mut timer = ProxyPollTimer::new(ctx.cx());
    let mut cancellation_error = None;
    std::future::poll_fn(|task_cx| {
        if cancellation_error.is_none()
            && (ctx.ensure_live().is_err() || cancelled.as_mut().poll(task_cx).is_ready())
        {
            cancellation_error = Some(McpError::request_cancelled());
            wire_cancellation.cancel();
        }

        if let Poll::Ready(result) = operation.as_mut().poll(task_cx) {
            // A committed Task must reach the route registry even when its
            // creation response races downstream cancellation. Otherwise the
            // gateway would lose authority to clean up live upstream work.
            if keep_committed_result(&result) {
                return Poll::Ready(result);
            }
            if cancellation_error.is_none()
                && (ctx.ensure_live().is_err() || cancelled.as_mut().poll(task_cx).is_ready())
            {
                cancellation_error = Some(McpError::request_cancelled());
            }
            return Poll::Ready(match (result, cancellation_error.take()) {
                // Native cleanup can report a failed cancellation write or
                // terminal transport retirement. That is the actionable
                // failure and must survive the original cancellation cause.
                (Err(error), _) if error.code != McpErrorCode::RequestCancelled => Err(error),
                (_, Some(error)) => Err(error),
                (result, None) => result,
            });
        }

        if cancellation_error.is_some() {
            // Native cleanup has its own bounded caller-runtime timer. It
            // retains exclusive transport ownership until it returns.
            return Poll::Pending;
        }
        if ctx.ensure_live().is_err() || cancelled.as_mut().poll(task_cx).is_ready() {
            cancellation_error = Some(McpError::request_cancelled());
            wire_cancellation.cancel();
            task_cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        match timer.poll(ctx.cx(), Some(ctx), task_cx) {
            Poll::Ready(Ok(())) => {
                timer.restart(ctx.cx());
                task_cx.waker().wake_by_ref();
            }
            Poll::Ready(Err(error)) => {
                cancellation_error = Some(error);
                wire_cancellation.cancel();
                task_cx.waker().wake_by_ref();
            }
            Poll::Pending => {}
        }
        Poll::Pending
    })
    .await
}

fn websocket_upstream_rpc_error(method: &str, error: &JsonRpcError) -> McpError {
    let code = error
        .code
        .as_i32()
        .map(McpErrorCode::from)
        .unwrap_or(McpErrorCode::InternalError);
    match code {
        McpErrorCode::InternalError | McpErrorCode::Custom(_) => McpError::internal_error(format!(
            "Proxy WebSocket upstream rejected {method}: {} ({})",
            error.message, error.code
        )),
        code => McpError {
            code,
            message: error.message.clone(),
            data: error.data.clone(),
        },
    }
}
