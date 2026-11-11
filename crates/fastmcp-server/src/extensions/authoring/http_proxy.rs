//! Framework-owned typed HTTP forwarding for authored request contracts.

use std::sync::Mutex;

use fastmcp_client::{
    ClientBuilder, HttpClient, ModernHttpExtensionEvent, ModernHttpExtensionExecution,
};
use fastmcp_core::{Cx, DEFAULT_JSON_RPC_MAX_BODY_BYTES};
use fastmcp_protocol::extensions::ClientExtensionDiscovery;
use fastmcp_protocol::protocol_policy::ProtocolPolicy;

use super::*;

// Progress and core notifications are admitted by the client but not relayed.
// Bound the total work even when a peer keeps sending valid nonterminal events.
const MAX_INTERMEDIATE_EVENTS: usize = 64;

/// A negotiated HTTP upstream for one complete authored extension contract.
///
/// Construct this handle with [ExtensionRegistration::connect_http_upstream].
/// Clones share bounded request accounting and a fresh request ID allocator.
/// They expose no client, credentials, registry, resolver, or execution control.
/// Each forwarded request owns its response stream and cancellation lifetime.
///
/// This request/result surface rejects contracts declaring notifications.
/// Core progress and log notifications are consumed within a 64-event budget;
/// they are not forwarded to the downstream caller.
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
    /// using [ExtensionBuilder::typed_http_proxy_request] for routed methods.
    /// All methods and schemas, including their order and descriptor version,
    /// must match. Neither client nor server notification declarations are
    /// supported by this request/result route.
    pub async fn connect_http_upstream<ClientSettings>(
        self,
        cx: &Cx,
        builder: ClientBuilder,
        client_settings: &ClientSettings,
    ) -> McpResult<ExtensionHttpUpstream>
    where
        ClientSettings: Serialize + Sync + ?Sized,
    {
        if self.descriptor.notification.is_some()
            || self.descriptor.request_notification.is_some()
        {
            return Err(McpError::invalid_params(
                "HTTP extension proxy does not support notification declarations",
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
    pub fn typed_http_proxy_request<Request, Response>(
        mut self,
        method: impl Into<String>,
        parameter_schema_id: impl Into<String>,
        result_schema_id: impl Into<String>,
        upstream: ExtensionHttpUpstream,
    ) -> McpResult<Self>
    where
        Request: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
        Response: DeserializeOwned + Serialize + JsonSchemaType + Send + 'static,
    {
        let method = method.into();
        if upstream.descriptor.id != self.descriptor.id
            || !upstream.descriptor.methods.iter().any(|entry| entry.name == method)
            || self.descriptor.notification.is_some()
            || self.descriptor.request_notification.is_some()
        {
            return Err(McpError::invalid_params(
                "HTTP upstream does not own this request-only extension method",
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
                Box::new(TypedHttpProxyHandler::<Request, Response, Settings> {
                    binding: HandlerBinding {
                        descriptor,
                        method_index: index,
                        parameter_schema: parameter_schema.admitted,
                        result_schema: result_schema.admitted,
                        effective_schema,
                    },
                    upstream,
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
    marker: PhantomData<fn(Request, Settings) -> Response>,
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
        for _ in 0..=MAX_INTERMEDIATE_EVENTS {
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
                Some(ModernHttpExtensionEvent::ExtensionNotification { .. }) => {
                    return Err(McpError::invalid_request(
                        "HTTP extension proxy does not relay extension notifications",
                    ));
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
