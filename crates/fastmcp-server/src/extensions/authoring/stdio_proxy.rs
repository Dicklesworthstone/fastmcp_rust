//! Framework-owned typed forwarding to a native Unix stdio subprocess.

use std::sync::{Mutex, OnceLock, TryLockError};

use fastmcp_client::{Client, ClientBuilder, StdioRequestExecution, StdioRequestExecutor};
use fastmcp_core::Cx;
use fastmcp_protocol::extensions::ClientExtensionDiscovery;
use fastmcp_protocol::protocol_policy::ProtocolPolicy;
use fastmcp_protocol::JsonRpcRequest;

use super::{
    AdmittedSchema, Arc, AuthorizedNotificationPayload, BTreeMap, BoxFuture, DeserializeOwned,
    ErasedExtensionHandler, ExtensionBuilder, ExtensionDescriptor, ExtensionNegotiationError,
    ExtensionRegistration, ExtensionSettings, ExtensionSettingsCompatibilityResolver,
    HandlerBinding, JsonSchemaType, MAX_AUTHORING_SETTINGS_BYTES, MAX_SCHEMA_INSTANCE_BYTES,
    MAX_STDIO_EXTENSION_NOTIFICATION_PARAMS_BYTES, McpContext, McpError, McpResult,
    NegotiatedExtension, NotificationBinding, PendingMethod, PendingNotification, PhantomData,
    ProtocolDescriptor, Serialize, SettingsResolver, Value, compile_schema, encode_bytes,
    encode_value, ensure_live, notification_authorizer, poll_live, retain_schema_identity,
    unbound_handler,
};

const MAX_INTERMEDIATE_EVENTS: usize = 64;

struct StdioConnection {
    client: Mutex<Client>,
    executor: StdioRequestExecutor,
}

/// An independently negotiated native Unix stdio extension upstream.
///
/// Construct this with [ExtensionRegistration::connect_stdio_upstream]. Clones
/// share the owned subprocess, one ingress driver, a bounded response registry
/// and fresh upstream request IDs. Every call owns its execution, cancellation
/// token and deadlines. Each synchronous receive turn waits at most the native
/// client's polling slice before releasing the client lock and yielding the
/// caller's runtime. No detached task, second reader or private runtime is used.
///
/// Typed client notifications obtain fresh leg-local activation proof and
/// consume no request IDs. Request-owned server notifications require the
/// explicit notification-aware route and the declaration's exact-ID codec.
/// At most 64 intermediate events are accepted per forwarded request.
///
/// The last shared owner drops the native client's subprocess owner. For
/// observable cleanup, drop all installed routes and call [Self::close_with_cx].
#[derive(Clone)]
pub struct ExtensionStdioUpstream {
    connection: Arc<StdioConnection>,
    descriptor: Arc<ExtensionDescriptor>,
    protocol: ProtocolDescriptor,
    negotiated: NegotiatedExtension,
}

impl std::fmt::Debug for ExtensionStdioUpstream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExtensionStdioUpstream")
            .field("extension", &self.descriptor.id())
            .finish_non_exhaustive()
    }
}

impl ExtensionStdioUpstream {
    /// The immutable authored declaration admitted on the upstream leg.
    #[must_use]
    pub fn descriptor(&self) -> &ExtensionDescriptor {
        &self.descriptor
    }

    /// Closes the subprocess after all other handles and installed routes drop.
    ///
    /// Consumes the last handle and awaits the native client's cleanup under
    /// the supplied context, preserving any cleanup failure. A still-shared
    /// connection is refused without interrupting its routes or requests.
    pub async fn close_with_cx(self, cx: &Cx) -> McpResult<()> {
        let connection = Arc::try_unwrap(self.connection).map_err(|_| {
            McpError::invalid_request("stdio extension upstream still has live routes or handles")
        })?;
        let mut client = connection
            .client
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        client.close_with_cx(cx).await
    }

    fn drive_slice(&self) -> McpResult<()> {
        match self.connection.client.try_lock() {
            Ok(mut client) => client.drive_yielding_stdio_slice().map_err(|_| {
                McpError::invalid_request("stdio extension upstream connection failed")
            }),
            // Another request already owns the sole bounded ingress turn.
            Err(TryLockError::WouldBlock) => Ok(()),
            Err(TryLockError::Poisoned(_)) => Err(McpError::internal_error(
                "stdio extension upstream is unavailable",
            )),
        }
    }
}

/// Retires this request even when the upstream has no sibling driver.
///
/// Created immediately after publication, before the first cancellation await.
/// Drop serializes one bounded cancellation publication with the connection's
/// receive turn. No lock is held across an await, and no cleanup task is spawned.
struct StdioProxyExecution {
    connection: Arc<StdioConnection>,
    request: Option<StdioRequestExecution>,
}

impl Drop for StdioProxyExecution {
    fn drop(&mut self) {
        let Some(mut request) = self.request.take() else {
            return;
        };
        let mut client = self
            .connection
            .client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if client.cancel_yielding_stdio_request(&mut request).is_err() {
            // The native client makes failed control publication terminal for
            // the connection. Drop cannot return that failure or retry the write.
            log::warn!("stdio extension proxy could not publish request retirement");
        }
    }
}

struct StdioSettingsResolver {
    descriptor: ProtocolDescriptor,
    resolve: Arc<SettingsResolver>,
    effective: Arc<OnceLock<ExtensionSettings>>,
}

impl ExtensionSettingsCompatibilityResolver for StdioSettingsResolver {
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
        if self.effective.get().is_some_and(|expected| expected != &effective) {
            return Err(rejected());
        }
        Ok(effective)
    }
}

impl ExtensionRegistration {
    /// Connects this complete typed contract to a native Unix stdio subprocess.
    ///
    /// The builder must select modern-only stdio and have no extension registry.
    /// Its executable, arguments, environment, process-group ownership, identity
    /// and timeout policies remain authoritative. Client settings are validated
    /// before spawning; discovery completes on the caller's runtime even when
    /// the builder otherwise defers initialization. No declaration handler runs.
    ///
    /// Build a second registration with the same complete contract using the
    /// typed stdio proxy routes. Both legs independently negotiate and must
    /// produce identical effective settings. Every standalone notification gets
    /// a fresh compatibility decision pinned to the original upstream settings.
    /// A failure after connection awaits native subprocess cleanup.
    ///
    /// This API is Unix-only because its receive turns require the native
    /// client's bounded pipe support. Generic blocking transports and
    /// exact-2024 fallback are not admitted by this constructor.
    pub async fn connect_stdio_upstream<ClientSettings>(
        self,
        cx: &Cx,
        builder: ClientBuilder,
        command: &str,
        args: &[&str],
        client_settings: &ClientSettings,
    ) -> McpResult<ExtensionStdioUpstream>
    where
        ClientSettings: Serialize + Sync + ?Sized,
    {
        if builder.selected_protocol_plan().policy() != ProtocolPolicy::ModernOnly
            || builder.selected_protocol_plan().modern_post_target().is_some()
        {
            return Err(McpError::invalid_params(
                "stdio extension proxy requires a modern-only stdio client plan",
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
            StdioSettingsResolver {
                descriptor: resolver_protocol.clone(),
                resolve: Arc::clone(&resolve),
                effective: Arc::clone(&resolver_effective),
            }
        })?;
        drop(self.handlers);
        let mut client = Box::pin(builder.connect_stdio_with_cx(cx, command, args)).await?;
        let initialized = client.ensure_initialized_with_cx(cx).await.and_then(|()| {
            cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
            if cx.budget().deadline.is_some_and(|deadline| cx.now() >= deadline) {
                return Err(McpError::request_cancelled());
            }
            let negotiated = client
                .negotiated_extensions()
                .and_then(|extensions| extensions.active(&self.descriptor.id).cloned())
                .ok_or_else(|| {
                    McpError::invalid_request("stdio upstream did not activate the typed extension")
                })?;
            let executor = client.multiplexed_stdio_executor()?;
            effective
                .set(negotiated.effective_settings().settings().clone())
                .map_err(|_| McpError::internal_error("stdio upstream settings are already sealed"))?;
            Ok((negotiated, executor))
        });
        let (negotiated, executor) = match initialized {
            Ok(initialized) => initialized,
            Err(error) => {
                client.close_with_cx(cx).await?;
                return Err(error);
            }
        };
        Ok(ExtensionStdioUpstream {
            connection: Arc::new(StdioConnection {
                client: Mutex::new(client),
                executor,
            }),
            descriptor: self.descriptor,
            protocol,
            negotiated,
        })
    }
}

impl<ClientSettings, ServerSettings, Settings>
    ExtensionBuilder<ClientSettings, ServerSettings, Settings>
where
    Settings: DeserializeOwned + Send + Sync + 'static,
{
    /// Registers a typed request forwarded to an independently negotiated child.
    ///
    /// Exact contract/schema identities and effective settings must match both
    /// legs. Only revalidated typed application data crosses; the child's own
    /// client supplies fresh request IDs, identity, capabilities and settings.
    /// Cancellation or dropping a downstream call retires only its execution
    /// and services its cancellation without waiting for a later request.
    pub fn typed_stdio_proxy_request<Request, Response>(
        self,
        method: impl Into<String>,
        parameter_schema_id: impl Into<String>,
        result_schema_id: impl Into<String>,
        upstream: ExtensionStdioUpstream,
    ) -> McpResult<Self>
    where
        Request: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
        Response: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
    {
        if self.descriptor.request_notification.is_some()
            || upstream.descriptor.request_notification.is_some()
        {
            return Err(McpError::invalid_params(
                "Request-owned notifications require the typed notification proxy route",
            ));
        }
        self.register_stdio_proxy_request::<Request, Response>(
            method.into(),
            parameter_schema_id.into(),
            result_schema_id.into(),
            upstream,
            None,
        )
    }

    /// Registers a typed request together with its owned server notifications.
    ///
    /// First declare the notification with [Self::typed_request_notification].
    /// The native client admits its exact upstream request-ID correlation; this
    /// adapter consumes upstream metadata and validates the typed notification
    /// before the downstream request's own sink stamps its correlation. A
    /// missing sink is refused before dispatch. Progress counts against the
    /// same 64-event budget but is not relayed as an extension notification.
    pub fn typed_stdio_proxy_request_with_notifications<Request, Response, Notification>(
        self,
        method: impl Into<String>,
        parameter_schema_id: impl Into<String>,
        result_schema_id: impl Into<String>,
        upstream: ExtensionStdioUpstream,
    ) -> McpResult<Self>
    where
        Request: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
        Response: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
        Notification: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
    {
        let declaration = self.descriptor.request_notification.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "stdio notification proxy requires a typed notification declaration",
            )
        })?;
        if upstream.descriptor.request_notification.as_ref() != Some(declaration) {
            return Err(McpError::invalid_params(
                "stdio notification proxy requires matching notification declarations",
            ));
        }
        let schema = self.request_notification_schema.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "stdio notification proxy requires an admitted notification schema",
            )
        })?;
        if compile_schema::<Notification>()?.digest != schema.digest {
            return Err(McpError::invalid_params(
                "stdio notification proxy type does not match its declared schema",
            ));
        }
        let notification = StdioProxyNotification {
            method: declaration.name.clone(),
            schema: Arc::clone(&schema.admitted),
            codec: reencode_notification::<Notification>,
        };
        self.register_stdio_proxy_request::<Request, Response>(
            method.into(),
            parameter_schema_id.into(),
            result_schema_id.into(),
            upstream,
            Some(notification),
        )
    }

    /// Registers an authorized typed client notification forwarded to the child.
    ///
    /// Normal downstream authentication, message-local proof and the authorize
    /// policy run before forwarding. Typed application data is bounded and
    /// revalidated; the upstream client reconstructs proof from its own settings
    /// and rechecks compatibility. A successful result means bounded publication
    /// to the pipe, not acknowledgement by the peer. No request ID, waiter,
    /// retry or background task is created.
    pub fn typed_stdio_proxy_notification<Notification, Authorize>(
        mut self,
        method: impl Into<String>,
        parameter_schema_id: impl Into<String>,
        activation_metadata_key: impl Into<String>,
        authorize: Authorize,
        upstream: ExtensionStdioUpstream,
    ) -> McpResult<Self>
    where
        Notification: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
        Authorize: Fn(&Notification) -> McpResult<()> + Send + Sync + 'static,
    {
        let (notification, parameter_schema, total) = self.prepare_notification::<Notification>(
            method.into(),
            parameter_schema_id.into(),
            activation_metadata_key.into(),
        )?;
        if upstream.descriptor.id != self.descriptor.id
            || upstream.descriptor.notification.as_ref() != Some(&notification)
        {
            return Err(McpError::invalid_params(
                "stdio upstream does not own this typed client notification",
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
                Box::new(TypedStdioProxyNotification::<Notification, Settings> {
                    binding: NotificationBinding {
                        descriptor,
                        effective_schema,
                    },
                    parameter_schema: parameter_schema.admitted,
                    upstream,
                    marker: PhantomData,
                })
            }),
        });
        self.descriptor.notification = Some(notification);
        self.schema_bytes = total;
        Ok(self)
    }

    fn register_stdio_proxy_request<Request, Response>(
        mut self,
        method: String,
        parameter_schema_id: String,
        result_schema_id: String,
        upstream: ExtensionStdioUpstream,
        notification: Option<StdioProxyNotification>,
    ) -> McpResult<Self>
    where
        Request: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
        Response: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
    {
        if upstream.descriptor.id != self.descriptor.id
            || !upstream.descriptor.methods.iter().any(|entry| entry.name == method)
        {
            return Err(McpError::invalid_params(
                "stdio upstream does not own this extension method",
            ));
        }
        let (method, parameter_schema, result_schema, total) = self
            .prepare_method::<Request, Response>(method, parameter_schema_id, result_schema_id)?;
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
                Box::new(TypedStdioProxyHandler::<Request, Response, Settings> {
                    binding: HandlerBinding {
                        descriptor,
                        method_index: index,
                        parameter_schema: parameter_schema.admitted,
                        result_schema: result_schema.admitted,
                        effective_schema,
                    },
                    upstream,
                    notification,
                    marker: PhantomData,
                })
            }),
        });
        self.descriptor.methods.push(method);
        self.schema_bytes = total;
        Ok(self)
    }
}

struct TypedStdioProxyNotification<Notification, Settings> {
    binding: NotificationBinding,
    parameter_schema: Arc<AdmittedSchema>,
    upstream: ExtensionStdioUpstream,
    marker: PhantomData<fn(Notification, Settings)>,
}

impl<Notification, Settings> ErasedExtensionHandler
    for TypedStdioProxyNotification<Notification, Settings>
where
    Notification: Serialize + Send + 'static,
    Settings: DeserializeOwned + Send + Sync + 'static,
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
            let (notification, _settings) = self.binding.prepare::<Notification, Settings>(
                context, negotiated, authorized,
            )?;
            admit_settings(negotiated, &self.upstream.negotiated)?;
            let parameters = encode_application_value(
                &notification,
                MAX_STDIO_EXTENSION_NOTIFICATION_PARAMS_BYTES,
            )?;
            admit_application_parameters(&parameters, &self.parameter_schema)?;
            ensure_live(context)?;
            let method = self.binding.descriptor.notification.as_ref().ok_or_else(|| {
                McpError::internal_error("typed notification descriptor is unavailable")
            })?;
            self.upstream
                .connection
                .executor
                .notify_final_extension(
                    context.cx(),
                    &self.binding.descriptor.id,
                    &method.name,
                    parameters,
                )
                .map_err(|_| {
                    McpError::invalid_request(
                        "stdio extension upstream notification was not published",
                    )
                })?;
            ensure_live(context)?;
            Ok(Value::Null)
        })
    }
}

fn admit_settings(
    downstream: &NegotiatedExtension,
    upstream: &NegotiatedExtension,
) -> McpResult<()> {
    if downstream.effective_settings().settings() != upstream.effective_settings().settings() {
        return Err(McpError::invalid_request(
            "stdio extension proxy requires identical effective settings on both legs",
        ));
    }
    Ok(())
}

fn encode_application_value<T: Serialize>(value: &T, limit: usize) -> McpResult<Value> {
    let source = encode_bytes(value, limit)?;
    fastmcp_protocol::admit_raw_jsonrpc_document(&source, limit).map_err(|_| {
        McpError::invalid_params("typed proxy serialization is invalid JSON")
    })?;
    serde_json::from_slice(&source).map_err(|_| {
        McpError::invalid_params("typed proxy serialization is invalid JSON")
    })
}

fn admit_application_parameters(parameters: &Value, schema: &AdmittedSchema) -> McpResult<()> {
    if !parameters.is_object() || parameters.get("_meta").is_some() {
        return Err(McpError::invalid_params(
            "typed proxy serialization cannot supply framework metadata",
        ));
    }
    schema.validate(parameters).map_err(|_| {
        McpError::invalid_params("serialized proxy parameters do not satisfy their schema")
    })
}

struct StdioProxyNotification {
    method: String,
    schema: Arc<AdmittedSchema>,
    codec: fn(Value) -> McpResult<Value>,
}

impl StdioProxyNotification {
    fn relay(&self, context: &McpContext, notification: JsonRpcRequest) -> McpResult<()> {
        ensure_live(context)?;
        if notification.id.is_some() || notification.method != self.method {
            return Err(McpError::invalid_request(
                "stdio notification proxy received another owner or method",
            ));
        }
        // Native ingress already admitted exact JSON and request-ID ownership.
        // Bound the retained value before consuming leg-local metadata.
        let parameters = notification.params.ok_or_else(|| {
            McpError::invalid_request("stdio notification proxy requires notification parameters")
        })?;
        let mut parameters = encode_application_value(
            &parameters,
            MAX_STDIO_EXTENSION_NOTIFICATION_PARAMS_BYTES,
        )?;
        let object = parameters.as_object_mut().ok_or_else(|| {
            McpError::invalid_request("stdio upstream notification parameters must be an object")
        })?;
        object.remove("_meta");
        self.schema.validate(&parameters).map_err(|_| {
            McpError::invalid_request("stdio upstream notification does not satisfy its typed schema")
        })?;
        let parameters = (self.codec)(parameters)?;
        admit_application_parameters(&parameters, &self.schema)?;
        ensure_live(context)?;
        context.emit_request_extension_notification(parameters)
    }
}

fn reencode_notification<Notification: DeserializeOwned + Serialize>(
    parameters: Value,
) -> McpResult<Value> {
    let notification: Notification = serde_json::from_value(parameters).map_err(|_| {
        McpError::invalid_request("stdio upstream notification typed decoding failed")
    })?;
    encode_application_value(&notification, MAX_STDIO_EXTENSION_NOTIFICATION_PARAMS_BYTES)
}

struct TypedStdioProxyHandler<Request, Response, Settings> {
    binding: HandlerBinding,
    upstream: ExtensionStdioUpstream,
    notification: Option<StdioProxyNotification>,
    marker: PhantomData<fn(Request, Settings) -> Response>,
}

impl<Request, Response, Settings> TypedStdioProxyHandler<Request, Response, Settings>
where
    Request: DeserializeOwned + Serialize + Send + 'static,
    Response: DeserializeOwned + Serialize + Send + 'static,
    Settings: DeserializeOwned + Send + Sync + 'static,
{
    fn prepare(
        &self,
        context: &McpContext,
        negotiated: &NegotiatedExtension,
        parameters: Value,
    ) -> McpResult<Value> {
        let (request, _settings) =
            self.binding.decode::<Request, Settings>(context, negotiated, parameters)?;
        admit_settings(negotiated, &self.upstream.negotiated)?;
        if self.notification.is_some() {
            context.ensure_request_extension_notifications_available()?;
        }
        let parameters = encode_application_value(&request, MAX_SCHEMA_INSTANCE_BYTES)?;
        admit_application_parameters(&parameters, &self.binding.parameter_schema)?;
        ensure_live(context)?;
        Ok(parameters)
    }

    async fn forward(&self, context: &McpContext, parameters: Value) -> McpResult<Value> {
        ensure_live(context)?;
        let method = &self.binding.descriptor.methods[self.binding.method_index];
        let request = self
            .upstream
            .connection
            .executor
            .execute_final_extension_with_cancellation(
                context.cx(),
                &context.request_cancellation(),
                &self.binding.descriptor.id,
                &method.name,
                parameters,
            )
            .map_err(|_| {
                McpError::invalid_request("stdio extension upstream request was rejected")
            })?;
        let execution = StdioProxyExecution {
            connection: Arc::clone(&self.upstream.connection),
            request: Some(request),
        };
        poll_live(context, self.receive(context, execution)).await
    }

    async fn receive(
        &self,
        context: &McpContext,
        mut execution: StdioProxyExecution,
    ) -> McpResult<Value> {
        let mut intermediate_events = 0usize;
        loop {
            ensure_live(context)?;
            let request = execution.request.as_mut().ok_or_else(|| {
                McpError::internal_error("stdio extension execution is already terminal")
            })?;
            let terminal = self
                .upstream
                .connection
                .executor
                .try_take_response_with_raw_result_and_stream(request)
                .map_err(|_| {
                    McpError::invalid_request("stdio extension upstream response failed")
                })?;
            let (terminal, notifications) = match terminal {
                Some((response, source, notifications)) => {
                    execution.request = None;
                    (Some((response, source)), notifications)
                }
                None => (
                    None,
                    request.take_stream_notifications().map_err(|_| {
                        McpError::invalid_request("stdio extension upstream notification failed")
                    })?,
                ),
            };
            for notification in notifications {
                if intermediate_events == MAX_INTERMEDIATE_EVENTS {
                    return Err(McpError::invalid_request(
                        "stdio extension upstream exceeded its intermediate-event budget",
                    ));
                }
                intermediate_events += 1;
                if notification.method == "notifications/progress" {
                    continue;
                }
                let relay = self.notification.as_ref().ok_or_else(|| {
                    McpError::invalid_request(
                        "stdio request-only proxy does not relay extension notifications",
                    )
                })?;
                relay.relay(context, notification)?;
            }
            if let Some((_response, source)) = terminal {
                let source = source.ok_or_else(|| {
                    McpError::invalid_request("stdio extension upstream lost its admitted result")
                })?;
                let mut result: Value = serde_json::from_str(&source).map_err(|_| {
                    McpError::invalid_request("stdio extension upstream result is invalid JSON")
                })?;
                let object = result.as_object_mut().ok_or_else(|| {
                    McpError::invalid_request("stdio extension upstream result must be an object")
                })?;
                object.remove("_meta");
                self.binding.result_schema.validate(&result).map_err(|_| {
                    McpError::invalid_request(
                        "stdio extension upstream result does not satisfy its schema",
                    )
                })?;
                let response: Response = serde_json::from_value(result).map_err(|_| {
                    McpError::invalid_request("stdio extension upstream typed result was rejected")
                })?;
                let result = self.binding.encode(context, &response)?;
                if result.get("_meta").is_some() {
                    return Err(McpError::internal_error(
                        "typed proxy result serialization cannot supply framework metadata",
                    ));
                }
                return Ok(result);
            }
            self.upstream.drive_slice()?;
            asupersync::runtime::yield_now().await;
        }
    }
}

impl<Request, Response, Settings> ErasedExtensionHandler
    for TypedStdioProxyHandler<Request, Response, Settings>
where
    Request: DeserializeOwned + Serialize + Send + 'static,
    Response: DeserializeOwned + Serialize + Send + 'static,
    Settings: DeserializeOwned + Send + Sync + 'static,
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
            "stdio extension proxy requires asynchronous dispatch",
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
