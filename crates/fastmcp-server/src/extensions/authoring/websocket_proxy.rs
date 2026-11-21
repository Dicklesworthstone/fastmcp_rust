//! Typed finite extension requests over one caller-owned native WebSocket.

use std::future::Future;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::sync::{Mutex, OwnedMutexGuard, TryLockError};
use fastmcp_client::{ClientBuilder, WebSocketClient};
use fastmcp_core::{McpErrorCode, McpRequestCancellation};
use fastmcp_protocol::extensions::ClientExtensionDiscovery;
use fastmcp_protocol::protocol_policy::ProtocolPolicy;
use fastmcp_transport::websocket::AsyncWsClientTransport;

use super::{
    AdmittedSchema, Arc, AuthorizedNotificationPayload, BTreeMap, BoxFuture, DeserializeOwned,
    ErasedExtensionHandler, ExtensionBuilder, ExtensionDescriptor, ExtensionNegotiationError,
    ExtensionRegistration, ExtensionSettings, ExtensionSettingsCompatibilityResolver,
    HandlerBinding, JsonSchemaType, MAX_AUTHORING_SETTINGS_BYTES, MAX_SCHEMA_INSTANCE_BYTES,
    MAX_STDIO_EXTENSION_NOTIFICATION_PARAMS_BYTES, McpContext, McpError, McpResult,
    NegotiatedExtension, NotificationBinding, PendingMethod, PendingNotification, PhantomData,
    ProtocolDescriptor, Serialize, SettingsResolver, Value, encode_bytes, encode_value,
    ensure_live, notification_authorizer, poll_live, retain_schema_identity, unbound_handler,
};

const MAX_PENDING_OPERATIONS: usize = 64;
const CLOSE_LOCK_TIMEOUT_NANOS: u64 = 350_000_000;

/// An independently negotiated WebSocket upstream for a typed extension.
///
/// Construct this through [ExtensionRegistration::connect_websocket_upstream].
/// Clones share one native connection and admit at most 64 running or waiting
/// operations. The cancellation-aware mutex preserves its single receive owner;
/// no thread, reader task, or private runtime is created. Each request receives
/// a fresh upstream ID and the upstream client's own metadata. Client
/// notifications receive fresh message-local activation proof and allocate no ID.
///
/// This adapter supports finite request/result exchanges and standalone client
/// notifications. Contracts declaring request-owned server notifications are
/// rejected before discovery; use the HTTP or stdio notification-aware routes
/// for those contracts. Tasks and catalog subscriptions are not enabled here.
///
/// An awaited request cancellation is settled by the native client before the
/// connection is reused. Dropping a sent request retains its native retirement
/// state for the next operation or [Self::close]. An interrupted notification
/// write makes the connection terminal, so a partial frame is never replayed.
pub struct ExtensionWebSocketUpstream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    client: Arc<Mutex<WebSocketClient<IO>>>,
    descriptor: Arc<ExtensionDescriptor>,
    protocol: ProtocolDescriptor,
    negotiated: NegotiatedExtension,
    pending: Arc<AtomicUsize>,
}

impl<IO> Clone for ExtensionWebSocketUpstream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn clone(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
            descriptor: Arc::clone(&self.descriptor),
            protocol: self.protocol.clone(),
            negotiated: self.negotiated.clone(),
            pending: Arc::clone(&self.pending),
        }
    }
}

impl<IO> std::fmt::Debug for ExtensionWebSocketUpstream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExtensionWebSocketUpstream")
            .field("extension", &self.descriptor.id())
            .finish_non_exhaustive()
    }
}

impl<IO> ExtensionWebSocketUpstream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// The complete immutable declaration admitted on the upstream leg.
    #[must_use]
    pub fn descriptor(&self) -> &ExtensionDescriptor {
        &self.descriptor
    }

    /// Closes the shared native connection on the caller's runtime.
    ///
    /// Cleanup can acquire an idle connection even if the caller is cancelled.
    /// Contended acquisition requires the caller's timer driver and masks
    /// cancellation for at most 350 milliseconds, bounded further by the
    /// caller's deadline; it retains all other caller budgets and capabilities.
    /// Failure to acquire returns an error and may be retried after the active
    /// operation releases its connection.
    ///
    /// Once acquired, native cleanup uses its retained connection context.
    /// All clones observe that terminal state. Native retirement or close
    /// failures are returned, including failures retained from an earlier call.
    pub async fn close(&self, cx: &Cx) -> McpResult<()> {
        let mut client = lock_for_close(Arc::clone(&self.client), cx).await?;
        client.close(cx).await
    }

    fn reserve(&self) -> McpResult<OperationPermit> {
        reserve_operation(&self.pending)
    }
}

async fn lock_for_close<T>(client: Arc<Mutex<T>>, cx: &Cx) -> McpResult<OwnedMutexGuard<T>> {
    match OwnedMutexGuard::try_lock(Arc::clone(&client)) {
        Ok(client) => return Ok(client),
        Err(TryLockError::Poisoned) => return Err(upstream_unavailable()),
        Err(TryLockError::Locked) => {}
    }
    // Sleep can install an ambient fallback timer when the caller has no time
    // driver or its TIME authority is masked. Cleanup must not gain that
    // authority or create a background timer on the caller's behalf.
    if cx.timer_driver().is_none() {
        return Err(McpError::internal_error(
            "WebSocket extension upstream close requires a caller timer while busy",
        ));
    }
    let bound = cx.now().saturating_add_nanos(CLOSE_LOCK_TIMEOUT_NANOS);
    let deadline = cx
        .budget()
        .deadline
        .map_or(bound, |deadline| deadline.min(bound));
    let mut locking = std::pin::pin!(OwnedMutexGuard::lock(client, cx));
    let mut elapsed = std::pin::pin!(asupersync::time::sleep_until(deadline));
    std::future::poll_fn(|task| {
        // Mask only each short cleanup poll. In particular, the timer must
        // observe that same context rather than a cancelled ambient task.
        let _current = Cx::set_current(Some(cx.clone()));
        cx.masked(|| {
            if cx.now() >= deadline || elapsed.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(McpError::internal_error(
                    "WebSocket extension upstream close acquisition timed out",
                )));
            }
            locking
                .as_mut()
                .poll(task)
                .map(|result| result.map_err(|_| upstream_unavailable()))
        })
    })
    .await
}

struct OperationPermit(Arc<AtomicUsize>);

impl Drop for OperationPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn reserve_operation(pending: &Arc<AtomicUsize>) -> McpResult<OperationPermit> {
    pending
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < MAX_PENDING_OPERATIONS).then(|| count + 1)
        })
        .map_err(|_| {
            McpError::invalid_request("WebSocket extension upstream operation capacity exhausted")
        })?;
    Ok(OperationPermit(Arc::clone(pending)))
}

fn upstream_unavailable() -> McpError {
    McpError::internal_error("WebSocket extension upstream is unavailable")
}

struct WebSocketSettingsResolver {
    descriptor: ProtocolDescriptor,
    resolve: Arc<SettingsResolver>,
    effective: Arc<OnceLock<ExtensionSettings>>,
}

impl ExtensionSettingsCompatibilityResolver for WebSocketSettingsResolver {
    fn resolve(
        &mut self,
        descriptor: &ProtocolDescriptor,
        client: &ExtensionSettings,
        server: &ExtensionSettings,
    ) -> Result<ExtensionSettings, ExtensionNegotiationError> {
        let rejected =
            || ExtensionNegotiationError::SettingsCompatibilityRejected(descriptor.id.to_string());
        if descriptor != &self.descriptor {
            return Err(rejected());
        }
        let effective = (self.resolve)(client, server).map_err(|_| rejected())?;
        if self
            .effective
            .get()
            .is_some_and(|expected| expected != &effective)
        {
            return Err(rejected());
        }
        Ok(effective)
    }
}

impl ExtensionRegistration {
    /// Negotiates this complete typed contract over an owned native WebSocket.
    ///
    /// The builder must select modern-only WebSocket operation and have no
    /// extension registry. The caller owns Upgrade/TLS and supplies the actual
    /// transport; its identity, credentials and timeout policy are retained.
    /// Local settings and unsupported server-notification declarations are
    /// checked before the first discovery frame. No declaration handler runs.
    ///
    /// Build a second registration with the same complete contract using
    /// [ExtensionBuilder::typed_websocket_proxy_request] and, when declared,
    /// [ExtensionBuilder::typed_websocket_proxy_notification]. Both legs must
    /// independently admit identical effective settings and schema identities.
    pub async fn connect_websocket_upstream<ClientSettings, IO>(
        self,
        cx: &Cx,
        builder: ClientBuilder,
        transport: AsyncWsClientTransport<IO>,
        client_settings: &ClientSettings,
    ) -> McpResult<ExtensionWebSocketUpstream<IO>>
    where
        ClientSettings: Serialize + Sync + ?Sized,
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if builder.selected_protocol_plan().policy() != ProtocolPolicy::ModernOnly {
            return Err(McpError::invalid_params(
                "WebSocket extension proxy requires a modern-only client plan",
            ));
        }
        if self.descriptor.request_notification.is_some() {
            return Err(McpError::invalid_params(
                "WebSocket extension proxy does not relay request-owned server notifications",
            ));
        }
        let value = encode_value(client_settings, MAX_AUTHORING_SETTINGS_BYTES)?;
        self.client_schema.validate(&value).map_err(|_| {
            McpError::invalid_params("proxy client settings do not satisfy their schema")
        })?;
        let settings = ExtensionSettings::new(value)
            .map_err(|_| McpError::invalid_params("invalid proxy client settings object"))?;
        let discovery = ClientExtensionDiscovery {
            extensions: BTreeMap::from([(self.descriptor.id.clone(), settings)]),
        };
        let descriptors = self.handlers.descriptor_registry().clone();
        let protocol = self.resolver.descriptor;
        let resolver_protocol = protocol.clone();
        let resolve: Arc<SettingsResolver> = Arc::from(self.resolver.resolve);
        let effective = Arc::new(OnceLock::new());
        let resolver_effective = Arc::clone(&effective);
        let builder = builder.extension_registry(descriptors, discovery, move || {
            WebSocketSettingsResolver {
                descriptor: resolver_protocol.clone(),
                resolve: Arc::clone(&resolve),
                effective: Arc::clone(&resolver_effective),
            }
        })?;
        drop(self.handlers);
        let mut client = Box::pin(builder.connect_websocket_with_cx(cx, transport)).await?;
        let admitted = (|| {
            cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
            if cx
                .budget()
                .deadline
                .is_some_and(|deadline| cx.now() >= deadline)
            {
                return Err(McpError::request_cancelled());
            }
            let negotiated = client
                .session()
                .negotiated_extensions()
                .and_then(|extensions| extensions.active(&self.descriptor.id).cloned())
                .ok_or_else(|| {
                    McpError::invalid_request(
                        "WebSocket upstream did not activate the typed extension",
                    )
                })?;
            effective
                .set(negotiated.effective_settings().settings().clone())
                .map_err(|_| upstream_unavailable())?;
            Ok(negotiated)
        })();
        let negotiated = match admitted {
            Ok(negotiated) => negotiated,
            Err(error) => {
                client.close(cx).await?;
                return Err(error);
            }
        };
        Ok(ExtensionWebSocketUpstream {
            client: Arc::new(Mutex::new(client)),
            descriptor: self.descriptor,
            protocol,
            negotiated,
            pending: Arc::new(AtomicUsize::new(0)),
        })
    }
}

impl<ClientSettings, ServerSettings, Settings>
    ExtensionBuilder<ClientSettings, ServerSettings, Settings>
where
    Settings: DeserializeOwned + Send + Sync + 'static,
{
    /// Registers a finite typed request forwarded to an independent WebSocket.
    ///
    /// Complete descriptor/schema identities and effective settings must agree
    /// on both legs. Typed application data is bounded and revalidated; it
    /// cannot inject upstream metadata. Requests share a bounded native
    /// connection, with cancellation-aware admission and native retirement.
    pub fn typed_websocket_proxy_request<Request, Response, IO>(
        mut self,
        method: impl Into<String>,
        parameter_schema_id: impl Into<String>,
        result_schema_id: impl Into<String>,
        upstream: ExtensionWebSocketUpstream<IO>,
    ) -> McpResult<Self>
    where
        Request: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
        Response: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let method = method.into();
        if self.descriptor.request_notification.is_some()
            || upstream.descriptor.request_notification.is_some()
        {
            return Err(McpError::invalid_params(
                "WebSocket extension proxy does not relay request-owned server notifications",
            ));
        }
        if upstream.descriptor.id != self.descriptor.id
            || !upstream
                .descriptor
                .methods
                .iter()
                .any(|entry| entry.name == method)
        {
            return Err(McpError::invalid_params(
                "WebSocket upstream does not own this extension method",
            ));
        }
        let (method, parameter_schema, result_schema, total) = self
            .prepare_method::<Request, Response>(
                method,
                parameter_schema_id.into(),
                result_schema_id.into(),
            )?;
        let index = self.pending.len();
        let effective_schema = Arc::clone(&self.effective_schema.admitted);
        retain_schema_identity(
            &mut self.schema_identities,
            &method.parameter_schema_id,
            parameter_schema.digest,
        )?;
        retain_schema_identity(
            &mut self.schema_identities,
            &method.result_schema_id,
            result_schema.digest,
        )?;
        self.proxy_contracts.push(upstream.protocol.clone());
        self.pending.push(PendingMethod {
            parameter_digest: parameter_schema.digest,
            result_digest: result_schema.digest,
            factory: Box::new(move |descriptor| {
                Box::new(
                    TypedWebSocketProxyHandler::<Request, Response, Settings, IO> {
                        binding: HandlerBinding {
                            descriptor,
                            method_index: index,
                            parameter_schema: parameter_schema.admitted,
                            result_schema: result_schema.admitted,
                            effective_schema,
                        },
                        upstream,
                        marker: PhantomData,
                    },
                )
            }),
        });
        self.descriptor.methods.push(method);
        self.schema_bytes = total;
        Ok(self)
    }

    /// Registers a typed client notification forwarded with fresh local proof.
    ///
    /// Authentication, current-message activation, schema validation and
    /// `authorize` run before forwarding. Successful completion means the
    /// native frame committed, not that the peer acknowledged it. No request
    /// ID, response waiter, automatic retry or background task is created.
    pub fn typed_websocket_proxy_notification<Notification, Authorize, IO>(
        mut self,
        method: impl Into<String>,
        parameter_schema_id: impl Into<String>,
        activation_metadata_key: impl Into<String>,
        authorize: Authorize,
        upstream: ExtensionWebSocketUpstream<IO>,
    ) -> McpResult<Self>
    where
        Notification: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
        Authorize: Fn(&Notification) -> McpResult<()> + Send + Sync + 'static,
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (notification, parameter_schema, total) = self.prepare_notification::<Notification>(
            method.into(),
            parameter_schema_id.into(),
            activation_metadata_key.into(),
        )?;
        if self.descriptor.request_notification.is_some()
            || upstream.descriptor.request_notification.is_some()
            || upstream.descriptor.id != self.descriptor.id
            || upstream.descriptor.notification.as_ref() != Some(&notification)
        {
            return Err(McpError::invalid_params(
                "WebSocket upstream does not own this typed client notification contract",
            ));
        }
        retain_schema_identity(
            &mut self.schema_identities,
            &notification.parameter_schema_id,
            parameter_schema.digest,
        )?;
        let effective_schema = Arc::clone(&self.effective_schema.admitted);
        self.proxy_contracts.push(upstream.protocol.clone());
        self.pending_notification = Some(PendingNotification {
            parameter_digest: parameter_schema.digest,
            authorize: notification_authorizer::<Notification, Authorize>(
                Arc::clone(&parameter_schema.admitted),
                authorize,
            ),
            factory: Box::new(move |descriptor| {
                Box::new(
                    TypedWebSocketProxyNotification::<Notification, Settings, IO> {
                        binding: NotificationBinding {
                            descriptor,
                            effective_schema,
                        },
                        parameter_schema: parameter_schema.admitted,
                        upstream,
                        marker: PhantomData,
                    },
                )
            }),
        });
        self.descriptor.notification = Some(notification);
        self.schema_bytes = total;
        Ok(self)
    }
}

fn admit_settings(
    downstream: &NegotiatedExtension,
    upstream: &NegotiatedExtension,
) -> McpResult<()> {
    if downstream.effective_settings().settings() != upstream.effective_settings().settings() {
        return Err(McpError::invalid_request(
            "WebSocket extension proxy requires identical effective settings on both legs",
        ));
    }
    Ok(())
}

fn application_parameters<T: Serialize>(
    value: &T,
    limit: usize,
    schema: &AdmittedSchema,
) -> McpResult<Value> {
    let source = encode_bytes(value, limit)?;
    fastmcp_protocol::admit_raw_jsonrpc_document(&source, limit)
        .map_err(|_| McpError::invalid_params("typed proxy serialization is invalid JSON"))?;
    let value: Value = serde_json::from_slice(&source)
        .map_err(|_| McpError::invalid_params("typed proxy serialization is invalid JSON"))?;
    if !value.is_object() || value.get("_meta").is_some() {
        return Err(McpError::invalid_params(
            "typed proxy serialization cannot supply framework metadata",
        ));
    }
    schema.validate(&value).map_err(|_| {
        McpError::invalid_params("serialized proxy parameters do not satisfy their schema")
    })?;
    Ok(value)
}

struct TypedWebSocketProxyHandler<Request, Response, Settings, IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    binding: HandlerBinding,
    upstream: ExtensionWebSocketUpstream<IO>,
    marker: PhantomData<fn(Request, Settings) -> Response>,
}

impl<Request, Response, Settings, IO> TypedWebSocketProxyHandler<Request, Response, Settings, IO>
where
    Request: DeserializeOwned + Serialize + Send + 'static,
    Response: DeserializeOwned + Serialize + Send + 'static,
    Settings: DeserializeOwned + Send + Sync + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn prepare(
        &self,
        context: &McpContext,
        negotiated: &NegotiatedExtension,
        parameters: Value,
    ) -> McpResult<Value> {
        let (request, _settings) = self
            .binding
            .decode::<Request, Settings>(context, negotiated, parameters)?;
        admit_settings(negotiated, &self.upstream.negotiated)?;
        application_parameters(
            &request,
            MAX_SCHEMA_INSTANCE_BYTES,
            &self.binding.parameter_schema,
        )
    }

    async fn forward(&self, context: &McpContext, parameters: Value) -> McpResult<Value> {
        ensure_live(context)?;
        let _permit = self.upstream.reserve()?;
        let mut client = poll_live(context, async {
            OwnedMutexGuard::lock(Arc::clone(&self.upstream.client), context.cx())
                .await
                .map_err(|_| upstream_unavailable())
        })
        .await?;
        ensure_live(context)?;
        let cancellation = McpRequestCancellation::default();
        let method = &self.binding.descriptor.methods[self.binding.method_index];
        let mut result = settle_native_request(
            context,
            &cancellation,
            client.request_final_extension_with_cancellation(
                context.cx(),
                &cancellation,
                &self.binding.descriptor.id,
                &method.name,
                parameters,
            ),
        )
        .await
        .map_err(safe_upstream_error)?;
        drop(client);
        let object = result.as_object_mut().ok_or_else(|| {
            McpError::invalid_request("WebSocket extension upstream result must be an object")
        })?;
        object.remove("_meta");
        self.binding.result_schema.validate(&result).map_err(|_| {
            McpError::invalid_request("WebSocket extension upstream result violates its schema")
        })?;
        let response: Response = serde_json::from_value(result).map_err(|_| {
            McpError::invalid_request("WebSocket extension upstream typed result was rejected")
        })?;
        let result = self.binding.encode(context, &response)?;
        if result.get("_meta").is_some() {
            return Err(McpError::internal_error(
                "typed proxy result serialization cannot supply framework metadata",
            ));
        }
        Ok(result)
    }
}

impl<Request, Response, Settings, IO> ErasedExtensionHandler
    for TypedWebSocketProxyHandler<Request, Response, Settings, IO>
where
    Request: DeserializeOwned + Serialize + Send + 'static,
    Response: DeserializeOwned + Serialize + Send + 'static,
    Settings: DeserializeOwned + Send + Sync + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn invoke(&self, _context: &McpContext, _parameters: Value) -> McpResult<Value> {
        Err(unbound_handler())
    }

    fn invoke_admitted(
        &self,
        _context: &McpContext,
        _negotiated: &NegotiatedExtension,
        _parameters: Value,
    ) -> McpResult<Value> {
        Err(McpError::invalid_request(
            "WebSocket extension proxy requires asynchronous dispatch",
        ))
    }

    fn invoke_admitted_async<'a>(
        &'a self,
        context: &'a McpContext,
        negotiated: &'a NegotiatedExtension,
        parameters: Value,
    ) -> BoxFuture<'a, McpResult<Value>> {
        Box::pin(async move {
            let parameters = self.prepare(context, negotiated, parameters)?;
            self.forward(context, parameters).await
        })
    }

    fn invoke_response_async<'a>(
        &'a self,
        context: &'a McpContext,
        negotiated: &'a NegotiatedExtension,
        parameters: Value,
        id: fastmcp_protocol::RequestId,
        handler_admission: Option<crate::FinalHandlerAdmission>,
    ) -> BoxFuture<'a, McpResult<fastmcp_protocol::JsonRpcResponse>> {
        Box::pin(async move {
            let parameters = self.prepare(context, negotiated, parameters)?;
            if let Some(admit) = handler_admission {
                admit();
                ensure_live(context)?;
            }
            self.forward(context, parameters)
                .await
                .map(|result| fastmcp_protocol::JsonRpcResponse::success(id, result))
        })
    }
}

struct TypedWebSocketProxyNotification<Notification, Settings, IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    binding: NotificationBinding,
    parameter_schema: Arc<AdmittedSchema>,
    upstream: ExtensionWebSocketUpstream<IO>,
    marker: PhantomData<fn(Notification, Settings)>,
}

impl<Notification, Settings, IO> ErasedExtensionHandler
    for TypedWebSocketProxyNotification<Notification, Settings, IO>
where
    Notification: Serialize + Send + 'static,
    Settings: DeserializeOwned + Send + Sync + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn invoke(&self, _context: &McpContext, _parameters: Value) -> McpResult<Value> {
        Err(unbound_handler())
    }

    fn invoke_authorized_notification_async<'a>(
        &'a self,
        context: &'a McpContext,
        negotiated: &'a NegotiatedExtension,
        _parameters: &'a Value,
        authorized: AuthorizedNotificationPayload,
    ) -> BoxFuture<'a, McpResult<Value>> {
        Box::pin(async move {
            let (notification, _settings) = self
                .binding
                .prepare::<Notification, Settings>(context, negotiated, authorized)?;
            admit_settings(negotiated, &self.upstream.negotiated)?;
            let parameters = application_parameters(
                &notification,
                MAX_STDIO_EXTENSION_NOTIFICATION_PARAMS_BYTES,
                &self.parameter_schema,
            )?;
            let method = self
                .binding
                .descriptor
                .notification
                .as_ref()
                .ok_or_else(upstream_unavailable)?;
            ensure_live(context)?;
            let _permit = self.upstream.reserve()?;
            let mut client = poll_live(context, async {
                OwnedMutexGuard::lock(Arc::clone(&self.upstream.client), context.cx())
                    .await
                    .map_err(|_| upstream_unavailable())
            })
            .await?;
            poll_live(
                context,
                client.notify_final_extension(
                    context.cx(),
                    &self.binding.descriptor.id,
                    &method.name,
                    parameters,
                ),
            )
            .await
            .map_err(safe_upstream_error)?;
            ensure_live(context)?;
            Ok(Value::Null)
        })
    }
}

fn safe_upstream_error(error: McpError) -> McpError {
    if error.code == McpErrorCode::RequestCancelled {
        return McpError::request_cancelled();
    }
    // Do not reflect an upstream peer's diagnostic or arbitrary error data
    // across the downstream gateway boundary.
    McpError::invalid_request("WebSocket extension upstream operation failed")
}

/// Signal native request retirement and keep polling the cleanup owner. Merely
/// dropping a sent future cannot establish that its cancellation frame committed.
async fn settle_native_request<T>(
    context: &McpContext,
    cancellation: &McpRequestCancellation,
    operation: impl Future<Output = McpResult<T>>,
) -> McpResult<T> {
    let mut operation = std::pin::pin!(operation);
    let mut cancelled = std::pin::pin!(context.request_cancelled());
    let mut deadline = context
        .budget()
        .deadline
        .map(asupersync::time::sleep_until)
        .map(Box::pin);
    let mut interrupted = false;
    std::future::poll_fn(|task| {
        if !interrupted
            && (ensure_live(context).is_err()
                || cancelled.as_mut().poll(task).is_ready()
                || deadline
                    .as_mut()
                    .is_some_and(|deadline| deadline.as_mut().poll(task).is_ready()))
        {
            interrupted = true;
            cancellation.cancel();
        }
        match operation.as_mut().poll(task) {
            Poll::Ready(Err(error)) if error.code != McpErrorCode::RequestCancelled => {
                Poll::Ready(Err(error))
            }
            Poll::Ready(result) => {
                if interrupted || ensure_live(context).is_err() {
                    Poll::Ready(Err(McpError::request_cancelled()))
                } else {
                    Poll::Ready(result)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_proxy_operation_capacity_is_shared_and_released_exactly_once() {
        let pending = Arc::new(AtomicUsize::new(0));
        let mut permits = (0..MAX_PENDING_OPERATIONS)
            .map(|_| reserve_operation(&pending).unwrap())
            .collect::<Vec<_>>();
        assert!(reserve_operation(&pending).is_err());
        assert_eq!(pending.load(Ordering::Acquire), MAX_PENDING_OPERATIONS);
        drop(permits.pop());
        let replacement = reserve_operation(&pending).unwrap();
        assert!(reserve_operation(&pending).is_err());
        drop(permits);
        assert_eq!(pending.load(Ordering::Acquire), 1);
        drop(replacement);
        assert_eq!(pending.load(Ordering::Acquire), 0);
    }

    #[test]
    fn websocket_proxy_close_lock_survives_cancelled_caller_and_retains_bound() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let child = cx
                .open_child_region(asupersync::cx::child_region::ChildRegionSpec::inherit())
                .await
                .unwrap();
            let cancelled = child.cx();
            cancelled.cancel_with(
                asupersync::types::CancelKind::Shutdown,
                Some("exercise cancellation-resilient close acquisition"),
            );
            let client = Arc::new(Mutex::new(()));
            let driverless = Cx::for_testing();
            driverless.cancel_with(
                asupersync::types::CancelKind::Shutdown,
                Some("exercise driverless close acquisition"),
            );
            assert!(driverless.timer_driver().is_none());
            drop(
                lock_for_close(Arc::clone(&client), &driverless)
                    .await
                    .unwrap(),
            );
            let held = OwnedMutexGuard::lock(Arc::clone(&client), &cx)
                .await
                .unwrap();
            let missing_timer = match lock_for_close(Arc::clone(&client), &driverless).await {
                Err(error) => error,
                Ok(_) => panic!("a held connection cannot be acquired without a caller timer"),
            };
            assert_eq!(
                missing_timer.message,
                "WebSocket extension upstream close requires a caller timer while busy"
            );
            let mut closing = Box::pin(lock_for_close(Arc::clone(&client), cancelled));
            assert!(
                std::future::poll_fn(|task| Poll::Ready(closing.as_mut().poll(task)))
                    .await
                    .is_pending(),
                "cancellation must not abandon a bounded cleanup waiter"
            );
            drop(held);
            drop(closing.await.unwrap());

            let held = OwnedMutexGuard::lock(Arc::clone(&client), &cx)
                .await
                .unwrap();
            let result = asupersync::time::timeout(
                cx.now(),
                std::time::Duration::from_secs(2),
                lock_for_close(Arc::clone(&client), cancelled),
            )
            .await
            .expect("a cancelled close cannot wait indefinitely for another operation");
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("a held connection cannot be acquired"),
            };
            assert_eq!(
                error.message,
                "WebSocket extension upstream close acquisition timed out"
            );
            drop(held);
            drop(lock_for_close(client, cancelled).await.unwrap());
            assert!(cancelled.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
            child.close().await.unwrap();
        });
        assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(1)));
    }
}
