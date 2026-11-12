//! Framework-owned typed HTTP forwarding for authored request contracts.

use std::sync::Mutex;

use fastmcp_client::{
    ClientBuilder, HttpClient, ModernHttpExtensionEvent, ModernHttpExtensionExecution,
};
use fastmcp_core::{Cx, DEFAULT_JSON_RPC_MAX_BODY_BYTES};
use fastmcp_protocol::extensions::{
    ClientExtensionDiscovery, MAX_STDIO_EXTENSION_NOTIFICATION_PARAMS_BYTES,
};
use fastmcp_protocol::protocol_policy::ProtocolPolicy;
use fastmcp_protocol::{AdmittedSchema, JsonRpcRequest};

use super::{
    Arc, BTreeMap, BoxFuture, DeserializeOwned, ErasedExtensionHandler, ExtensionBuilder,
    ExtensionDescriptor, ExtensionNegotiationError, ExtensionRegistration, ExtensionSettings,
    ExtensionSettingsCompatibilityResolver, HandlerBinding, JsonSchemaType,
    MAX_AUTHORING_SETTINGS_BYTES, MAX_SCHEMA_INSTANCE_BYTES, McpContext, McpError, McpResult,
    NegotiatedExtension, PendingMethod, PhantomData, ProtocolDescriptor, Serialize,
    SettingsResolver, Value, compile_schema, encode_bytes, encode_value, ensure_live, poll_live,
    retain_schema_identity, unbound_handler,
};

// Progress and core notifications are admitted by the client but not relayed.
// Bound the total work even when a peer keeps sending valid nonterminal events.
const MAX_INTERMEDIATE_EVENTS: usize = 64;

/// A negotiated HTTP upstream for one complete authored extension contract.
///
/// Construct this handle with [`ExtensionRegistration::connect_http_upstream`].
/// Clones share bounded request accounting and a fresh request ID allocator.
/// They expose no client, credentials, registry, resolver, or execution control.
/// Each forwarded request owns its response stream and cancellation lifetime.
///
/// Request-owned server notifications require the explicit typed notification
/// route. Standalone client notifications are not supported. All intermediate
/// events share a 64-event budget; core progress and log notifications are
/// consumed without being forwarded to the downstream caller.
#[derive(Clone)]
pub struct ExtensionHttpUpstream {
    client: Arc<Mutex<HttpClient>>,
    descriptor: Arc<ExtensionDescriptor>,
    protocol: ProtocolDescriptor,
    negotiated: NegotiatedExtension,
}

impl std::fmt::Debug for ExtensionHttpUpstream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExtensionHttpUpstream")
            .field("extension", &self.descriptor.id())
            .finish_non_exhaustive()
    }
}

impl ExtensionHttpUpstream {
    /// The immutable authored declaration admitted on the upstream leg.
    #[must_use]
    pub fn descriptor(&self) -> &ExtensionDescriptor {
        &self.descriptor
    }
}

struct ProxySettingsResolver {
    descriptor: ProtocolDescriptor,
    resolve: Arc<SettingsResolver>,
}

impl ExtensionSettingsCompatibilityResolver for ProxySettingsResolver {
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
        (self.resolve)(client, server).map_err(|_| rejected())
    }
}

impl ExtensionRegistration {
    /// Connects this sealed declaration to an independently negotiated upstream.
    ///
    /// The supplied builder must select a modern-only HTTP plan and must not
    /// already contain an extension registry. Its identity, credentials, TLS
    /// policy and request timeouts remain authoritative for the upstream leg.
    /// Client settings are validated against this declaration's client schema;
    /// the original typed resolver admits the upstream's discovered settings.
    ///
    /// This consumes the registration without invoking its handlers. Build a
    /// second registration with the same complete contract for the gateway,
    /// using [`ExtensionBuilder::typed_http_proxy_request`] or
    /// [`ExtensionBuilder::typed_http_proxy_request_with_notifications`].
    /// All methods and schemas, including their order and descriptor version,
    /// must match. Request-owned server notifications require the latter typed
    /// route. Standalone client notification declarations remain unsupported.
    ///
    /// # Errors
    ///
    /// Returns an error if the declaration includes client notifications, the
    /// builder does not select a modern-only HTTP plan, client settings fail
    /// validation, or the upstream connection fails to negotiate the extension.
    pub async fn connect_http_upstream<ClientSettings>(
        self,
        cx: &Cx,
        builder: ClientBuilder,
        client_settings: &ClientSettings,
    ) -> McpResult<ExtensionHttpUpstream>
    where
        ClientSettings: Serialize + Sync + ?Sized,
    {
        if self.descriptor.notification.is_some() {
            return Err(McpError::invalid_params(
                "HTTP extension proxy does not support client notification declarations",
            ));
        }
        if builder.selected_protocol_plan().policy() != ProtocolPolicy::ModernOnly
            || builder.selected_protocol_plan().modern_post_target().is_none()
        {
            return Err(McpError::invalid_params(
                "HTTP extension proxy requires a modern-only HTTP client plan",
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
        // Each negotiation owns a fresh resolver. Only immutable callback
        // configuration is shared, never a mutable resolver or its state.
        let builder = builder.extension_registry(descriptors, discovery, move || {
            ProxySettingsResolver {
                descriptor: resolver_protocol.clone(),
                resolve: Arc::clone(&resolve),
            }
        })?;
        // No application callback from the declaration survives into forwarding.
        drop(self.handlers);
        let connected = Box::pin(builder.connect_http_client_with_cx(cx)).await;
        cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
        if cx.budget().deadline.is_some_and(|deadline| cx.now() >= deadline) {
            return Err(McpError::request_cancelled());
        }
        let client = connected
            .map_err(|_| McpError::invalid_request("HTTP extension upstream connection failed"))?;
        let negotiated = client
            .negotiated_extensions()
            .and_then(|extensions| extensions.active(&self.descriptor.id).cloned())
            .ok_or_else(|| {
                McpError::invalid_request("HTTP upstream did not activate the typed extension")
            })?;
        Ok(ExtensionHttpUpstream {
            client: Arc::new(Mutex::new(client)),
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
    /// Registers a typed client-to-server request forwarded to modern HTTP.
    ///
    /// Request and result types must implement both serialization directions.
    /// Normal downstream admission decodes application parameters and strips
    /// framework metadata. The proxy revalidates typed serialization, checks
    /// exact effective-settings equality between the two independently admitted
    /// legs, and starts a fresh request with the upstream client's own identity.
    ///
    /// Build-time validation compares the complete compiled contract against
    /// the upstream declaration, including every schema digest and method.
    /// Adding a notification or changing a schema after this call fails build.
    /// A cancelled/dropped downstream request drops only its owned upstream
    /// execution; sibling requests remain usable.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream does not own the request-only extension
    /// method or if method schema registration fails.
    pub fn typed_http_proxy_request<Request, Response>(
        self,
        method: impl Into<String>,
        parameter_schema_id: impl Into<String>,
        result_schema_id: impl Into<String>,
        upstream: ExtensionHttpUpstream,
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
        self.register_http_proxy_request::<Request, Response>(
            method.into(),
            parameter_schema_id.into(),
            result_schema_id.into(),
            upstream,
            None,
        )
    }

    /// Registers a typed request and its request-owned server notifications.
    ///
    /// First declare the notification with [`Self::typed_request_notification`].
    /// Its compiled schema must match `Notification` exactly. Both the complete
    /// authored contract and the independently resolved settings on each leg
    /// remain subject to the ordinary typed proxy checks.
    ///
    /// Every upstream notification is decoded and re-encoded through this Rust
    /// type. Upstream metadata is consumed locally; the downstream request's
    /// existing sink supplies its own method and correlation. HTTP uses its
    /// owned SSE body, while memory and stdio stamp the downstream request ID.
    /// A missing sink is refused before upstream dispatch. At most 64 total
    /// intermediate events are accepted, including core progress/log events.
    /// Cancellation or output backpressure closes only the owning execution.
    ///
    /// # Errors
    ///
    /// Returns an error if either notification declaration is missing or
    /// differs, the notification type has another schema, or request method
    /// registration fails. Standalone client notifications are not forwarded.
    pub fn typed_http_proxy_request_with_notifications<Request, Response, Notification>(
        self,
        method: impl Into<String>,
        parameter_schema_id: impl Into<String>,
        result_schema_id: impl Into<String>,
        upstream: ExtensionHttpUpstream,
    ) -> McpResult<Self>
    where
        Request: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
        Response: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
        Notification: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
    {
        let declaration = self.descriptor.request_notification.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "HTTP notification proxy requires a typed notification declaration",
            )
        })?;
        if upstream.descriptor.request_notification.as_ref() != Some(declaration) {
            return Err(McpError::invalid_params(
                "HTTP notification proxy requires matching notification declarations",
            ));
        }
        let schema = self.request_notification_schema.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "HTTP notification proxy requires an admitted notification schema",
            )
        })?;
        if compile_schema::<Notification>()?.digest != schema.digest {
            return Err(McpError::invalid_params(
                "HTTP notification proxy type does not match its declared schema",
            ));
        }
        let notification = HttpProxyNotification {
            method: declaration.name.clone(),
            schema: Arc::clone(&schema.admitted),
            codec: reencode_notification::<Notification>,
        };
        self.register_http_proxy_request::<Request, Response>(
            method.into(),
            parameter_schema_id.into(),
            result_schema_id.into(),
            upstream,
            Some(notification),
        )
    }

    fn register_http_proxy_request<Request, Response>(
        mut self,
        method: String,
        parameter_schema_id: String,
        result_schema_id: String,
        upstream: ExtensionHttpUpstream,
        notification: Option<HttpProxyNotification>,
    ) -> McpResult<Self>
    where
        Request: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
        Response: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
    {
        if upstream.descriptor.id != self.descriptor.id
            || !upstream.descriptor.methods.iter().any(|entry| entry.name == method)
            || self.descriptor.notification.is_some()
        {
            return Err(McpError::invalid_params(
                "HTTP upstream does not own this request-only extension method",
            ));
        }
        let (method, parameter_schema, result_schema, total) = self
            .prepare_method::<Request, Response>(
                method,
                parameter_schema_id,
                result_schema_id,
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
                Box::new(TypedHttpProxyHandler::<Request, Response, Settings> {
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

struct TypedHttpProxyHandler<Request, Response, Settings> {
    binding: HandlerBinding,
    upstream: ExtensionHttpUpstream,
    notification: Option<HttpProxyNotification>,
    marker: PhantomData<fn(Request, Settings) -> Response>,
}

struct HttpProxyNotification {
    method: String,
    schema: Arc<AdmittedSchema>,
    codec: fn(Value) -> McpResult<Value>,
}

impl HttpProxyNotification {
    fn relay(
        &self,
        context: &McpContext,
        notification: JsonRpcRequest,
        raw_params: Option<&str>,
    ) -> McpResult<()> {
        ensure_live(context)?;
        if notification.id.is_some() || notification.method != self.method {
            return Err(McpError::invalid_request(
                "HTTP notification proxy received another owner or method",
            ));
        }
        let source = raw_params.ok_or_else(|| {
            McpError::invalid_request("HTTP notification proxy requires notification parameters")
        })?;
        fastmcp_protocol::admit_raw_jsonrpc_document(
            source.as_bytes(),
            MAX_STDIO_EXTENSION_NOTIFICATION_PARAMS_BYTES,
        )
        .map_err(|_| {
            McpError::invalid_request("HTTP upstream notification exceeds its wire bounds")
        })?;
        let mut parameters: Value = serde_json::from_str(source).map_err(|_| {
            McpError::invalid_request("HTTP upstream notification parameters are invalid")
        })?;
        if notification.params.as_ref() != Some(&parameters) {
            return Err(McpError::invalid_request(
                "HTTP upstream notification source does not match its payload",
            ));
        }
        let object = parameters.as_object_mut().ok_or_else(|| {
            McpError::invalid_request("HTTP upstream notification parameters must be an object")
        })?;
        object.remove("_meta");
        self.schema.validate(&parameters).map_err(|_| {
            McpError::invalid_request("HTTP upstream notification does not satisfy its typed schema")
        })?;
        let parameters = (self.codec)(parameters)?;
        ensure_live(context)?;
        if !parameters.is_object() || parameters.get("_meta").is_some() {
            return Err(McpError::invalid_request(
                "Typed notification serialization cannot supply framework metadata",
            ));
        }
        self.schema.validate(&parameters).map_err(|_| {
            McpError::invalid_request(
                "Re-encoded HTTP notification does not satisfy its typed schema",
            )
        })?;
        context.emit_request_extension_notification(parameters)
    }
}

fn reencode_notification<Notification: DeserializeOwned + Serialize>(
    parameters: Value,
) -> McpResult<Value> {
    let notification: Notification = serde_json::from_value(parameters).map_err(|_| {
        McpError::invalid_request("HTTP upstream notification typed decoding failed")
    })?;
    let source = encode_bytes(&notification, MAX_STDIO_EXTENSION_NOTIFICATION_PARAMS_BYTES)?;
    fastmcp_protocol::admit_raw_jsonrpc_document(
        &source,
        MAX_STDIO_EXTENSION_NOTIFICATION_PARAMS_BYTES,
    )
    .map_err(|_| {
        McpError::invalid_request("Re-encoded HTTP notification exceeds its wire bounds")
    })?;
    serde_json::from_slice(&source).map_err(|_| {
        McpError::invalid_request("Re-encoded HTTP notification is not valid JSON")
    })
}

impl<Request, Response, Settings> TypedHttpProxyHandler<Request, Response, Settings>
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
        if negotiated.effective_settings().settings()
            != self.upstream.negotiated.effective_settings().settings()
        {
            return Err(McpError::invalid_request(
                "HTTP extension proxy requires identical effective settings on both legs",
            ));
        }
        if self.notification.is_some() {
            context.ensure_request_extension_notifications_available()?;
        }
        let parameters = encode_value(&request, MAX_SCHEMA_INSTANCE_BYTES)?;
        let object = parameters.as_object().ok_or_else(|| {
            McpError::invalid_params("serialized proxy request must be an object")
        })?;
        if object.contains_key("_meta") {
            return Err(McpError::invalid_params(
                "typed proxy request serialization cannot supply framework metadata",
            ));
        }
        self.binding.parameter_schema.validate(&parameters).map_err(|_| {
            McpError::invalid_params("serialized proxy request does not satisfy its schema")
        })?;
        ensure_live(context)?;
        Ok(parameters)
    }

    async fn forward(&self, context: &McpContext, parameters: Value) -> McpResult<Value> {
        ensure_live(context)?;
        let method = &self.binding.descriptor.methods[self.binding.method_index];
        // The lock covers only synchronous admission and allocation. Every
        // execution is owned, so no client lock is held across network awaits.
        let execution = {
            let client = self.upstream.client.lock().map_err(|_| {
                McpError::internal_error("HTTP extension upstream is unavailable")
            })?;
            client
                .execute_final_extension(
                    context.cx(),
                    &self.binding.descriptor.id,
                    &method.name,
                    parameters,
                    response_limits(),
                )
        };
        ensure_live(context)?;
        let execution = execution.map_err(|_| {
            McpError::invalid_request("HTTP extension upstream request was rejected")
        })?;
        poll_live(context, self.receive(context, execution)).await
    }

    async fn receive(
        &self,
        context: &McpContext,
        mut execution: ModernHttpExtensionExecution,
    ) -> McpResult<Value> {
        for event_index in 0..=MAX_INTERMEDIATE_EVENTS {
            ensure_live(context)?;
            let event = execution.next_event(context.cx()).await;
            ensure_live(context)?;
            let event = event.map_err(|_| {
                McpError::invalid_request("HTTP extension upstream response failed")
            })?;
            match event {
                Some(ModernHttpExtensionEvent::Terminal(mut result)) => {
                    let object = result.as_object_mut().ok_or_else(|| {
                        McpError::invalid_request("HTTP extension upstream result must be an object")
                    })?;
                    // Upstream protocol metadata is not gateway identity or
                    // downstream authority. Only typed application data crosses.
                    object.remove("_meta");
                    self.binding.result_schema.validate(&result).map_err(|_| {
                        McpError::invalid_request(
                            "HTTP extension upstream result does not satisfy its schema",
                        )
                    })?;
                    let response: Response = serde_json::from_value(result).map_err(|_| {
                        McpError::invalid_request("HTTP extension upstream typed result was rejected")
                    })?;
                    let result = self.binding.encode(context, &response)?;
                    if result.get("_meta").is_some() {
                        return Err(McpError::internal_error(
                            "typed proxy result serialization cannot supply framework metadata",
                        ));
                    }
                    return Ok(result);
                }
                Some(ModernHttpExtensionEvent::Progress(_)
                    | ModernHttpExtensionEvent::Notification(_)) => {}
                Some(ModernHttpExtensionEvent::ExtensionNotification {
                    notification,
                    raw_params,
                }) => {
                    if event_index == MAX_INTERMEDIATE_EVENTS {
                        break;
                    }
                    let relay = self.notification.as_ref().ok_or_else(|| {
                        McpError::invalid_request(
                            "HTTP request-only proxy does not relay extension notifications",
                        )
                    })?;
                    relay.relay(context, notification, raw_params.as_deref())?;
                }
                None => {
                    return Err(McpError::invalid_request(
                        "HTTP extension upstream ended without a terminal result",
                    ));
                }
            }
        }
        Err(McpError::invalid_request(
            "HTTP extension upstream exceeded its intermediate-event budget",
        ))
    }
}

impl<Request, Response, Settings> ErasedExtensionHandler
    for TypedHttpProxyHandler<Request, Response, Settings>
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
            "HTTP extension proxy requires asynchronous dispatch",
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

fn response_limits() -> fastmcp_client::sse::SseLimits {
    // Match the shared JSON-RPC body bound, including a complete single-line
    // result. A 64 KiB SSE line cap would reject valid typed extension payloads.
    fastmcp_client::sse::SseLimits::with_data_lines(
        DEFAULT_JSON_RPC_MAX_BODY_BYTES + b"data: \r\n".len(),
        fastmcp_client::http_executor::MAX_PENDING_MODERN_HTTP_SSE_EVENT_BYTES,
        64,
        4096,
    )
    .expect("shared HTTP response bounds are nonzero")
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::schema::SchemaGenerator;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Notice {
        value: u32,
    }

    impl JsonSchemaType for Notice {
        fn schema_body(_generator: &mut SchemaGenerator) -> Value {
            json!({
                "type": "object",
                "properties": {"value": {"type": "integer", "minimum": 0}},
                "required": ["value"],
                "additionalProperties": false
            })
        }
    }

    #[test]
    fn notification_proxy_consumes_upstream_metadata_and_refuses_invalid_frames_before_emission() {
        let values = Arc::new(Mutex::new(Vec::new()));
        let received = Arc::clone(&values);
        let context = McpContext::new(Cx::for_testing(), 41)
            .with_request_extension_notification_sender(Arc::new(move |parameters| {
                received.lock().unwrap().push(parameters);
                Ok(())
            }));
        let relay = HttpProxyNotification {
            method: "com.example/notice".to_owned(),
            schema: compile_schema::<Notice>().unwrap().admitted,
            codec: reencode_notification::<Notice>,
        };
        let parameters = json!({
            "value": 7,
            "_meta": {"com.example/upstream-owner": "must-not-cross"}
        });
        let source = serde_json::to_string(&parameters).unwrap();
        let notification = JsonRpcRequest::notification(
            "com.example/notice",
            Some(parameters.clone()),
        );
        relay.relay(&context, notification.clone(), Some(&source)).unwrap();
        assert_eq!(*values.lock().unwrap(), vec![json!({"value": 7})]);

        let wrong_method = JsonRpcRequest::notification(
            "com.example/another-notice",
            Some(parameters.clone()),
        );
        assert!(relay.relay(&context, wrong_method, Some(&source)).is_err());
        let wrong_role = JsonRpcRequest::new(
            "com.example/notice",
            Some(parameters),
            41_i64,
        );
        assert!(relay.relay(&context, wrong_role, Some(&source)).is_err());
        let different_source = serde_json::to_string(&json!({"value": 8})).unwrap();
        assert!(relay.relay(&context, notification, Some(&different_source)).is_err());
        for parameters in [
            json!({"value": "wrong-type"}),
            json!({
                "value": 7,
                "_meta": {"com.example/padding": "x".repeat(
                    MAX_STDIO_EXTENSION_NOTIFICATION_PARAMS_BYTES
                )}
            }),
        ] {
            let source = serde_json::to_string(&parameters).unwrap();
            let notification = JsonRpcRequest::notification(
                "com.example/notice",
                Some(parameters),
            );
            assert!(relay.relay(&context, notification, Some(&source)).is_err());
        }
        assert_eq!(
            *values.lock().unwrap(),
            vec![json!({"value": 7})],
            "every refusal leaves the downstream output unchanged"
        );
    }
}
