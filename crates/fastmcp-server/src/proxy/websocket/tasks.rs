//! Official Tasks on a route-owned native WebSocket connection.

use fastmcp_client::{
    FinalToolCallOutcome, StdioTaskSubscriptionEvent, WebSocketTaskSubscriptionOwner,
};
use fastmcp_protocol::FinalCoreResult;

use super::*;
use crate::proxy::{
    ProxyFinalTaskListener, ProxyFinalTaskListenerEvent, ProxyFinalTaskOperation,
    ProxyFinalTaskResponse,
};

/// Sealed native execution owner for a Tasks-capable gateway route.
#[doc(hidden)]
pub struct PreparedProxyWebSocketTaskRequest {
    execution: Box<dyn WebSocketTaskExecution>,
}

impl PreparedProxyWebSocketTaskRequest {
    pub(super) fn new<IO>(
        backend: ProxyWebSocketClient<IO>,
        operation: ProxyFinalTaskOperation,
    ) -> Self
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            execution: Box::new(WebSocketTaskRequest { backend, operation }),
        }
    }

    pub(in crate::proxy) async fn execute(
        self,
        ctx: &McpContext,
        on_progress: &mut (dyn FnMut(FinalProgressNotificationParams) + Send),
    ) -> McpResult<ProxyFinalTaskResponse> {
        self.execution.execute(ctx, on_progress).await
    }
}

trait WebSocketTaskExecution: Send {
    fn execute<'a>(
        self: Box<Self>,
        ctx: &'a McpContext,
        on_progress: &'a mut (dyn FnMut(FinalProgressNotificationParams) + Send),
    ) -> BoxFuture<'a, McpResult<ProxyFinalTaskResponse>>;
}

struct WebSocketTaskRequest<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    backend: ProxyWebSocketClient<IO>,
    operation: ProxyFinalTaskOperation,
}

impl<IO> WebSocketTaskExecution for WebSocketTaskRequest<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn execute<'a>(
        self: Box<Self>,
        ctx: &'a McpContext,
        on_progress: &'a mut (dyn FnMut(FinalProgressNotificationParams) + Send),
    ) -> BoxFuture<'a, McpResult<ProxyFinalTaskResponse>> {
        Box::pin(async move {
            ctx.ensure_live()?;
            let Self { backend, operation } = *self;
            let metadata = backend.task_request_metadata(ctx)?;
            if let ProxyFinalTaskOperation::CallTool { name, arguments } = operation {
                let params = serde_json::json!({
                    "name": name, "arguments": arguments, "_meta": metadata,
                });
                let request =
                    CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params))
                        .map_err(|error| {
                            McpError::invalid_params(format!(
                                "Invalid proxy Tasks tool call: {error}"
                            ))
                        })?;
                let result = Box::new(WebSocketCoreRequest {
                    backend,
                    allow_tasks: true,
                })
                .execute(ctx, request, on_progress)
                .await?;
                let outcome = match result {
                    CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) => {
                        FinalToolCallOutcome::Complete(result)
                    }
                    CoreResult::Final(FinalCoreResult::ToolsCallInputRequired {
                        result, ..
                    }) => FinalToolCallOutcome::InputRequired(result),
                    CoreResult::Final(FinalCoreResult::ToolsCallTask { result }) => {
                        FinalToolCallOutcome::Task(result)
                    }
                    _ => {
                        return Err(McpError::invalid_request(
                            "Unexpected proxy Tasks tool result",
                        ));
                    }
                };
                return Ok(ProxyFinalTaskResponse::CallTool(outcome));
            }

            let mut client = await_proxy_request_or_cancellation(ctx, async {
                OwnedMutexGuard::lock(Arc::clone(&backend.client), ctx.cx())
                    .await
                    .map_err(websocket_lock_error)
            })
            .await?;
            ctx.ensure_live()?;
            let _ = client.take_final_server_notifications();
            let _ = client.take_final_progress_notifications();
            let cancellation = McpRequestCancellation::new();
            let mut forward_log = |message| relay_upstream_log_message(ctx, &message);
            let outcome = drive_native_request(ctx, &cancellation, async {
                match operation {
                    ProxyFinalTaskOperation::Get { task_id } => client
                        .get_task_final_with_metadata(
                            ctx.cx(),
                            task_id,
                            metadata,
                            &cancellation,
                            &mut forward_log,
                        )
                        .await
                        .map(ProxyFinalTaskResponse::Get),
                    ProxyFinalTaskOperation::Update {
                        task,
                        input_responses,
                    } => client
                        .update_task_final_with_metadata(
                            ctx.cx(),
                            &task,
                            input_responses,
                            metadata,
                            &cancellation,
                            &mut forward_log,
                        )
                        .await
                        .map(ProxyFinalTaskResponse::Update),
                    ProxyFinalTaskOperation::Cancel { task_id } => client
                        .cancel_task_final_with_metadata(
                            ctx.cx(),
                            task_id,
                            metadata,
                            &cancellation,
                            &mut forward_log,
                        )
                        .await
                        .map(ProxyFinalTaskResponse::Cancel),
                    ProxyFinalTaskOperation::CallTool { .. } => unreachable!("handled above"),
                }
            })
            .await;
            let _ = client.take_final_server_notifications();
            let _ = client.take_final_progress_notifications();
            drop(client);
            outcome
        })
    }
}

impl<IO> ProxyWebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub(super) fn task_request_metadata(&self, ctx: &McpContext) -> McpResult<FinalRequestMeta> {
        crate::proxy::discovery_admits_final_tasks_relay(&self.discovery)?;
        let mut metadata = self.request_metadata(ctx)?;
        metadata.client_capabilities.extensions = Some(std::collections::BTreeMap::from([(
            fastmcp_protocol::TASKS_EXTENSION.to_owned(),
            serde_json::json!({}),
        )]));
        Ok(metadata)
    }
}

/// Sealed opening for an independently owned native Tasks subscription.
#[doc(hidden)]
pub struct PreparedProxyWebSocketTaskListener {
    opening: Box<dyn WebSocketTaskOpening>,
}

impl PreparedProxyWebSocketTaskListener {
    pub(super) fn new<IO>(
        backend: ProxyWebSocketClient<IO>,
        notifications: SubscriptionFilter,
    ) -> Self
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            opening: Box::new(WebSocketTaskListenerRequest {
                backend,
                notifications,
            }),
        }
    }

    pub(in crate::proxy) async fn open(
        self,
        ctx: &McpContext,
    ) -> McpResult<Box<dyn ProxyFinalTaskListener>> {
        self.opening.open(ctx).await
    }
}

trait WebSocketTaskOpening: Send {
    fn open(
        self: Box<Self>,
        ctx: &McpContext,
    ) -> BoxFuture<'_, McpResult<Box<dyn ProxyFinalTaskListener>>>;
}

struct WebSocketTaskListenerRequest<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    backend: ProxyWebSocketClient<IO>,
    notifications: SubscriptionFilter,
}

impl<IO> WebSocketTaskOpening for WebSocketTaskListenerRequest<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn open(
        self: Box<Self>,
        ctx: &McpContext,
    ) -> BoxFuture<'_, McpResult<Box<dyn ProxyFinalTaskListener>>> {
        Box::pin(async move {
            ctx.ensure_live()?;
            let metadata = self.backend.task_request_metadata(ctx)?;
            let backend_client = Arc::clone(&self.backend.client);
            let mut client = await_proxy_request_or_cancellation(ctx, async {
                OwnedMutexGuard::lock(Arc::clone(&backend_client), ctx.cx())
                    .await
                    .map_err(websocket_lock_error)
            })
            .await?;
            ctx.ensure_live()?;
            let owner = await_proxy_request_or_cancellation(ctx, async {
                client
                    .open_owned_final_task_subscription_listener(
                        ctx.cx(),
                        self.notifications,
                        metadata,
                    )
                    .await
            })
            .await?;
            drop(client);
            ctx.ensure_live()?;
            Ok(Box::new(WebSocketTaskListener {
                client: backend_client,
                _owner: owner,
                context: ctx.clone(),
            }) as Box<dyn ProxyFinalTaskListener>)
        })
    }
}

struct WebSocketTaskListener<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    client: Arc<Mutex<WebSocketClient<IO>>>,
    _owner: WebSocketTaskSubscriptionOwner,
    context: McpContext,
}

impl<IO> ProxyFinalTaskListener for WebSocketTaskListener<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn next(
        &mut self,
        _cx: &Cx,
        _cancellation: &McpRequestCancellation,
    ) -> McpResult<ProxyFinalTaskListenerEvent> {
        Err(websocket_requires_async())
    }

    fn native_cleanup(&self) -> Option<ProxyNativeCatalogCleanup> {
        Some(ProxyNativeCatalogCleanup { _private: () })
    }

    fn next_async<'a>(
        &'a mut self,
        cx: &'a Cx,
        cancellation: &'a McpRequestCancellation,
    ) -> BoxFuture<'a, McpResult<ProxyFinalTaskListenerEvent>> {
        Box::pin(async move {
            let context = self.context.clone().with_request_cx(cx.clone());
            let wire_cancellation = McpRequestCancellation::new();
            // The MCP operation deadline can be earlier than its caller Cx or
            // the native subscription timeout. Keep driving the selected read
            // after that deadline so its bounded cancellation write completes.
            drive_native_listener(&context, &wire_cancellation, cancellation, async {
                loop {
                    let mut client = await_proxy_operation_or_cancellation(
                        cx,
                        &wire_cancellation,
                        Box::pin(async {
                            OwnedMutexGuard::lock(Arc::clone(&self.client), cx)
                                .await
                                .map_err(websocket_lock_error)
                        }),
                    )
                    .await?;
                    let event = client
                        .poll_final_task_subscription_event(cx, &wire_cancellation)
                        .await?;
                    drop(client);
                    if let Some(event) = event {
                        return Ok(match event {
                            StdioTaskSubscriptionEvent::Acknowledged(filter) => {
                                ProxyFinalTaskListenerEvent::Acknowledged(filter)
                            }
                            StdioTaskSubscriptionEvent::Notification(notification) => {
                                ProxyFinalTaskListenerEvent::Notification(notification)
                            }
                            StdioTaskSubscriptionEvent::Terminal => {
                                ProxyFinalTaskListenerEvent::Terminal
                            }
                        });
                    }
                    asupersync::runtime::yield_now().await;
                }
            })
            .await
        })
    }
}
