//! Typed server handlers for negotiated MCP extensions.
//!
//! This registry deliberately owns neither JSON-RPC decoding nor server/router
//! dispatch. It binds a typed handler to an extension capability and request
//! method, then delegates current-exchange admission to the frozen protocol
//! descriptor registry before invoking that handler. Router integration owns
//! the wire boundary separately.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use fastmcp_core::{McpContext, McpError, McpResult};
use fastmcp_protocol::extensions::{
    ExtensionDispatchError, ExtensionRegistryError, MAX_EXTENSION_MEMBER_NAME_BYTES,
    NegotiatedExtensionSet, ServerExtensionDiscovery,
};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    ExtensionDescriptorRegistry, ExtensionDirection, ExtensionId, ExtensionRegistryReceipt,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// A typed implementation for one client-to-server extension request.
///
/// The supplied [`McpContext`] is the caller's request context. Implementations
/// must preserve its cancellation and budget ownership rather than creating a
/// detached runtime context.
pub trait ExtensionHandler<Request, Response>: Send + Sync {
    /// Handles one already-admitted extension request.
    fn handle(&self, context: &McpContext, request: Request) -> McpResult<Response>;
}

impl<Request, Response, Handler> ExtensionHandler<Request, Response> for Handler
where
    Handler: Fn(&McpContext, Request) -> McpResult<Response> + Send + Sync,
{
    fn handle(&self, context: &McpContext, request: Request) -> McpResult<Response> {
        self(context, request)
    }
}

/// Object-safe bridge that retains each registered handler's Rust types.
trait ErasedExtensionHandler: Send + Sync {
    fn invoke(&self, context: &McpContext, parameters: Value) -> McpResult<Value>;
}

/// Typed serde adapter retained behind the heterogeneous handler map.
struct SerdeExtensionHandler<Request, Response, Handler> {
    handler: Handler,
    marker: PhantomData<fn(Request) -> Response>,
}

impl<Request, Response, Handler> ErasedExtensionHandler
    for SerdeExtensionHandler<Request, Response, Handler>
where
    Request: DeserializeOwned,
    Response: Serialize,
    Handler: ExtensionHandler<Request, Response>,
{
    fn invoke(&self, context: &McpContext, parameters: Value) -> McpResult<Value> {
        let request = serde_json::from_value(parameters)
            .map_err(|error| McpError::invalid_params(error.to_string()))?;
        let response = self.handler.handle(context, request)?;
        serde_json::to_value(response).map_err(|_| {
            McpError::internal_error("typed extension handler response serialization failed")
        })
    }
}

/// A stable server-side location for one extension request handler.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExtensionHandlerKey {
    extension_id: ExtensionId,
    method: String,
}

impl ExtensionHandlerKey {
    /// Creates a handler location from its capability and exact request method.
    #[must_use]
    pub fn new(extension_id: ExtensionId, method: impl Into<String>) -> Self {
        Self {
            extension_id,
            method: method.into(),
        }
    }

    /// Returns the owning extension capability.
    #[must_use]
    pub const fn extension_id(&self) -> &ExtensionId {
        &self.extension_id
    }

    /// Returns the exact client-to-server method spelling.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }
}

/// Failure while registering a typed extension handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtensionHandlerRegistrationError {
    /// Handler mutation was attempted after the registry was frozen.
    Frozen,
    /// The handler's capability is absent from the protocol descriptor registry.
    UnregisteredExtension(String),
    /// The handler method is empty and cannot name an RPC request.
    EmptyMethodName,
    /// The handler method exceeds the protocol's bounded member-name limit.
    MethodNameTooLong(String),
    /// A handler is already registered for this exact extension request location.
    DuplicateHandler(ExtensionHandlerKey),
    /// Server discovery metadata is already registered for this extension.
    DuplicateServerMetadata(ExtensionId),
}

impl fmt::Display for ExtensionHandlerRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frozen => formatter.write_str("extension handler registry is frozen"),
            Self::UnregisteredExtension(id) => {
                write!(formatter, "extension handler has no descriptor: {id}")
            }
            Self::EmptyMethodName => formatter.write_str("extension handler method is empty"),
            Self::MethodNameTooLong(method) => {
                write!(
                    formatter,
                    "extension handler method exceeds its byte limit: {method}"
                )
            }
            Self::DuplicateHandler(key) => write!(
                formatter,
                "extension handler is already registered: {}/{}",
                key.extension_id(),
                key.method()
            ),
            Self::DuplicateServerMetadata(id) => {
                write!(formatter, "extension server metadata is already registered: {id}")
            }
        }
    }
}

impl std::error::Error for ExtensionHandlerRegistrationError {}

/// Failure while looking up a registered extension handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtensionHandlerLookupError {
    /// Lookup is unavailable until the capability and handler registries are frozen together.
    RegistryNotFrozen,
    /// No typed handler is registered for the admitted capability and request method.
    HandlerNotFound(ExtensionHandlerKey),
}

impl fmt::Display for ExtensionHandlerLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryNotFrozen => {
                formatter.write_str("extension handler registry must be frozen before lookup")
            }
            Self::HandlerNotFound(key) => write!(
                formatter,
                "no extension handler is registered: {}/{}",
                key.extension_id(),
                key.method()
            ),
        }
    }
}

impl std::error::Error for ExtensionHandlerLookupError {}

/// Failure while admitting or invoking a typed extension handler.
#[derive(Debug)]
pub enum ExtensionHandlerInvocationError {
    /// Invocation is unavailable until the capability and handler registries are frozen together.
    RegistryNotFrozen,
    /// The current exchange did not admit this capability and client-to-server request method.
    Protocol(ExtensionDispatchError),
    /// No handler was registered for an otherwise admitted extension request method.
    HandlerNotFound(ExtensionHandlerKey),
    /// The admitted typed handler returned an MCP error.
    Handler(McpError),
}

impl fmt::Display for ExtensionHandlerInvocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryNotFrozen => {
                formatter.write_str("extension handler registry must be frozen before invocation")
            }
            Self::Protocol(error) => {
                write!(formatter, "extension request was not admitted: {error}")
            }
            Self::HandlerNotFound(key) => write!(
                formatter,
                "no extension handler is registered: {}/{}",
                key.extension_id(),
                key.method()
            ),
            Self::Handler(error) => write!(formatter, "extension handler failed: {error}"),
        }
    }
}

impl std::error::Error for ExtensionHandlerInvocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Handler(error) => Some(error),
            Self::RegistryNotFrozen | Self::HandlerNotFound(_) => None,
        }
    }
}

/// Frozen, typed server handlers bound to one protocol descriptor registry.
///
/// The map is erased only internally. Each [`Self::register`] call fixes that
/// method's own decoded request and encoded response types in a serde adapter,
/// so one registry can hold heterogeneous extension methods without weakening
/// a handler's typed Rust boundary. Method ownership, direction, negotiated
/// capability activation, and descriptor receipt are still enforced by the
/// protocol registry at every invocation.
pub struct ExtensionHandlerRegistry {
    descriptor_registry: ExtensionDescriptorRegistry,
    handlers: BTreeMap<ExtensionHandlerKey, Box<dyn ErasedExtensionHandler>>,
    server_metadata: BTreeMap<ExtensionId, fastmcp_protocol::ExtensionSettings>,
    frozen: bool,
}

impl ExtensionHandlerRegistry {
    /// Starts a handler registry around the supplied protocol descriptor registry.
    #[must_use]
    pub fn new(descriptor_registry: ExtensionDescriptorRegistry) -> Self {
        Self {
            descriptor_registry,
            handlers: BTreeMap::new(),
            server_metadata: BTreeMap::new(),
            frozen: false,
        }
    }

    /// Returns the protocol descriptor registry that governs handler admission.
    #[must_use]
    pub const fn descriptor_registry(&self) -> &ExtensionDescriptorRegistry {
        &self.descriptor_registry
    }

    /// Returns the mutable descriptor registry before handler freeze.
    ///
    /// Builder-only composition must add every descriptor before typed handlers
    /// are frozen under their shared receipt. Once frozen, neither descriptor
    /// nor handler mutation is admitted.
    pub(crate) fn descriptor_registry_mut(
        &mut self,
    ) -> Result<&mut ExtensionDescriptorRegistry, ExtensionHandlerRegistrationError> {
        if self.frozen {
            return Err(ExtensionHandlerRegistrationError::Frozen);
        }
        Ok(&mut self.descriptor_registry)
    }

    /// Returns whether handler registration has been frozen.
    #[must_use]
    pub const fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Returns the number of registered typed handlers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Returns whether no typed handlers have been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Returns the number of descriptor-bound server metadata entries.
    #[must_use]
    pub fn server_metadata_len(&self) -> usize {
        self.server_metadata.len()
    }

    /// Registers the exact server discovery settings for one extension.
    ///
    /// This is intentionally separate from request-handler registration: an
    /// extension such as MCP Apps can need a server discovery marker before it
    /// owns a client-to-server extension method. The marker is accepted only
    /// for a descriptor already linked into this registry, and is immutable
    /// once the descriptor receipt is frozen.
    pub fn register_server_metadata(
        &mut self,
        extension_id: ExtensionId,
        settings: fastmcp_protocol::ExtensionSettings,
    ) -> Result<(), ExtensionHandlerRegistrationError> {
        if self.frozen {
            return Err(ExtensionHandlerRegistrationError::Frozen);
        }
        if self.descriptor_registry.descriptor(&extension_id).is_none() {
            return Err(ExtensionHandlerRegistrationError::UnregisteredExtension(
                extension_id.to_string(),
            ));
        }
        if self.server_metadata.contains_key(&extension_id) {
            return Err(ExtensionHandlerRegistrationError::DuplicateServerMetadata(
                extension_id,
            ));
        }

        self.server_metadata.insert(extension_id, settings);
        Ok(())
    }

    /// Registers one typed handler for an extension request method.
    ///
    /// Descriptor existence is checked immediately. Exact method ownership and
    /// client-to-server direction remain request-specific protocol checks, so
    /// [`Self::invoke`] performs them against the current negotiated extension
    /// set before this handler can run.
    pub fn register<Request, Response, Handler>(
        &mut self,
        extension_id: ExtensionId,
        method: impl Into<String>,
        handler: Handler,
    ) -> Result<(), ExtensionHandlerRegistrationError>
    where
        Request: DeserializeOwned + 'static,
        Response: Serialize + 'static,
        Handler: ExtensionHandler<Request, Response> + 'static,
    {
        if self.frozen {
            return Err(ExtensionHandlerRegistrationError::Frozen);
        }
        if self.descriptor_registry.descriptor(&extension_id).is_none() {
            return Err(ExtensionHandlerRegistrationError::UnregisteredExtension(
                extension_id.to_string(),
            ));
        }

        let key = ExtensionHandlerKey::new(extension_id, method);
        if key.method().is_empty() {
            return Err(ExtensionHandlerRegistrationError::EmptyMethodName);
        }
        if key.method().len() > MAX_EXTENSION_MEMBER_NAME_BYTES {
            return Err(ExtensionHandlerRegistrationError::MethodNameTooLong(
                key.method().to_owned(),
            ));
        }
        if self.handlers.contains_key(&key) {
            return Err(ExtensionHandlerRegistrationError::DuplicateHandler(key));
        }

        self.handlers.insert(
            key,
            Box::new(SerdeExtensionHandler::<Request, Response, Handler> {
                handler,
                marker: PhantomData,
            }),
        );
        Ok(())
    }

    /// Freezes protocol descriptors and typed handlers under one immutable receipt.
    pub fn freeze(&mut self) -> Result<ExtensionRegistryReceipt, ExtensionRegistryError> {
        let receipt = self.descriptor_registry.freeze()?;
        self.frozen = true;
        Ok(receipt)
    }

    /// Returns the server discovery data bound to this frozen registry.
    ///
    /// Callers pass this value to the server builder together with this same
    /// registry. Requiring the shared frozen state prevents server metadata
    /// from being assembled from a descriptor set that can still change.
    pub fn server_discovery(
        &self,
    ) -> Result<ServerExtensionDiscovery, ExtensionHandlerLookupError> {
        if !self.frozen {
            return Err(ExtensionHandlerLookupError::RegistryNotFrozen);
        }
        Ok(ServerExtensionDiscovery {
            extensions: self.server_metadata.clone(),
        })
    }

    /// Looks up one handler after freezing has made the registry immutable.
    pub fn lookup(
        &self,
        extension_id: &ExtensionId,
        method: &str,
    ) -> Result<&ExtensionHandlerKey, ExtensionHandlerLookupError> {
        if !self.frozen {
            return Err(ExtensionHandlerLookupError::RegistryNotFrozen);
        }
        let key = ExtensionHandlerKey::new(extension_id.clone(), method);
        self.handlers
            .get_key_value(&key)
            .map(|(registered_key, _)| registered_key)
            .ok_or(ExtensionHandlerLookupError::HandlerNotFound(key))
    }

    /// Admits and invokes one typed client-to-server extension request.
    ///
    /// The protocol admission call binds this invocation to the exact frozen
    /// descriptor receipt, current negotiated extension set, modern era, and
    /// client-to-server ownership before the handler is looked up or executed.
    pub fn invoke(
        &self,
        negotiated: &NegotiatedExtensionSet,
        protocol_era: ProtocolEra,
        extension_id: &ExtensionId,
        method: &str,
        context: &McpContext,
        parameters: Value,
    ) -> Result<Value, ExtensionHandlerInvocationError> {
        if !self.frozen {
            return Err(ExtensionHandlerInvocationError::RegistryNotFrozen);
        }

        negotiated
            .admit_method(
                &self.descriptor_registry,
                protocol_era,
                extension_id,
                method,
                ExtensionDirection::ClientToServer,
            )
            .map_err(ExtensionHandlerInvocationError::Protocol)?;
        let key = self
            .lookup(extension_id, method)
            .map_err(|error| match error {
                ExtensionHandlerLookupError::RegistryNotFrozen => {
                    ExtensionHandlerInvocationError::RegistryNotFrozen
                }
                ExtensionHandlerLookupError::HandlerNotFound(key) => {
                    ExtensionHandlerInvocationError::HandlerNotFound(key)
                }
            })?;
        let handler = self
            .handlers
            .get(key)
            .ok_or_else(|| ExtensionHandlerInvocationError::HandlerNotFound(key.clone()))?;
        handler
            .invoke(context, parameters)
            .map_err(ExtensionHandlerInvocationError::Handler)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use asupersync::Cx;
    use fastmcp_core::{McpContext, McpErrorCode, McpResult};
    use fastmcp_protocol::extensions::{
        ClientExtensionDiscovery, ExtensionFallbackPolicy, ExtensionLocalEnablement,
        ExtensionNegotiationResolver, ExtensionSettings, ExtensionSettingsSchema,
        ServerExtensionDiscovery, official_tasks_empty_settings, register_official_tasks_extension,
    };
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use fastmcp_protocol::{ExtensionDescriptor, ExtensionDescriptorRegistry, ExtensionId};
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use super::{
        ExtensionHandlerInvocationError, ExtensionHandlerKey, ExtensionHandlerRegistrationError,
        ExtensionHandlerRegistry,
    };

    fn tasks_descriptors() -> (ExtensionDescriptorRegistry, ExtensionId) {
        let mut descriptors = ExtensionDescriptorRegistry::new();
        let id = register_official_tasks_extension(&mut descriptors)
            .expect("official Tasks descriptor registers");
        (descriptors, id)
    }

    fn official_apps_metadata_descriptor() -> ExtensionDescriptor {
        ExtensionDescriptor {
            id: ExtensionId::parse("io.modelcontextprotocol/ui")
                .expect("official Apps identifier is valid"),
            client_settings: ExtensionSettingsSchema {
                schema_id: "apps-2026-01-26-client-mime-types-v1".to_owned(),
                codec_id: "apps-2026-01-26-client-mime-types-v1".to_owned(),
            },
            server_settings: ExtensionSettingsSchema {
                schema_id: "fastmcp-2026-07-28-apps-empty-server-marker-v1".to_owned(),
                codec_id: "fastmcp-2026-07-28-apps-empty-server-marker-v1".to_owned(),
            },
            resolver: ExtensionNegotiationResolver {
                id: "fastmcp-apps-bilateral-resolver-v1".to_owned(),
                version: 1,
                fallback: ExtensionFallbackPolicy::ServerInactiveFallback,
            },
            method: None,
            notification: None,
            result_discriminator: None,
            routing_headers: Vec::new(),
            stdio_correlation: None,
        }
    }

    #[derive(Deserialize)]
    struct GetTaskRequest {
        value: u32,
    }

    #[derive(Debug, PartialEq, Serialize)]
    struct GetTaskResponse {
        next: u32,
    }

    #[derive(Deserialize)]
    struct UpdateTaskRequest {
        title: String,
    }

    #[derive(Debug, PartialEq, Serialize)]
    struct UpdateTaskResponse {
        updated_title: String,
    }

    fn get_task(context: &McpContext, request: GetTaskRequest) -> McpResult<GetTaskResponse> {
        assert_eq!(context.request_id(), 71);
        Ok(GetTaskResponse {
            next: request.value + 1,
        })
    }

    fn alternate_get_task(
        context: &McpContext,
        request: GetTaskRequest,
    ) -> McpResult<GetTaskResponse> {
        assert_eq!(context.request_id(), 71);
        Ok(GetTaskResponse {
            next: request.value + 2,
        })
    }

    fn update_task(
        context: &McpContext,
        request: UpdateTaskRequest,
    ) -> McpResult<UpdateTaskResponse> {
        assert_eq!(context.request_id(), 71);
        Ok(UpdateTaskResponse {
            updated_title: request.title.to_uppercase(),
        })
    }

    fn negotiated_tasks(
        descriptors: &ExtensionDescriptorRegistry,
        id: &ExtensionId,
    ) -> fastmcp_protocol::extensions::NegotiatedExtensionSet {
        let client = ClientExtensionDiscovery {
            extensions: BTreeMap::from([(id.clone(), official_tasks_empty_settings())]),
        };
        let server = ServerExtensionDiscovery {
            extensions: BTreeMap::from([(id.clone(), official_tasks_empty_settings())]),
        };
        let mut local = ExtensionLocalEnablement::default();
        local.enable(id.clone());
        let mut resolver =
            |_descriptor: &fastmcp_protocol::ExtensionDescriptor,
             _client: &ExtensionSettings,
             _server: &ExtensionSettings| { Ok(official_tasks_empty_settings()) };

        descriptors
            .negotiate(
                ProtocolEra::Modern2026,
                &local,
                &client,
                &server,
                &mut resolver,
            )
            .expect("bilaterally advertised official Tasks negotiates")
    }

    #[test]
    fn extension_handler_registry_freezes_and_looks_up_registered_handler() {
        let (descriptors, id) = tasks_descriptors();
        let mut handlers = ExtensionHandlerRegistry::new(descriptors);
        handlers
            .register(id.clone(), "tasks/get", get_task)
            .expect("typed Tasks handler registers");

        let receipt = handlers.freeze().expect("handler registry freezes");

        assert!(handlers.is_frozen());
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers.descriptor_registry().receipt(), Some(&receipt));
        let registered = handlers
            .lookup(&id, "tasks/get")
            .expect("frozen registry finds its handler registration");
        assert_eq!(registered.extension_id(), &id);
        assert_eq!(registered.method(), "tasks/get");
    }

    #[test]
    fn official_apps_server_metadata_is_emitted_from_the_frozen_registry() {
        let apps = official_apps_metadata_descriptor();
        let apps_id = apps.id.clone();
        let mut descriptors = ExtensionDescriptorRegistry::new();
        descriptors
            .register(apps)
            .expect("the compile-linked official Apps descriptor registers");
        let mut handlers = ExtensionHandlerRegistry::new(descriptors);

        handlers
            .register_server_metadata(
                apps_id.clone(),
                ExtensionSettings::new(json!({}))
                    .expect("the official Apps server marker is an object"),
            )
            .expect("the descriptor-bound official Apps marker registers");
        let receipt = handlers.freeze().expect("Apps metadata registry freezes");
        let discovery = handlers
            .server_discovery()
            .expect("frozen Apps metadata can enter server discovery");

        assert_eq!(handlers.descriptor_registry().receipt(), Some(&receipt));
        assert_eq!(handlers.server_metadata_len(), 1);
        assert_eq!(
            discovery
                .extensions
                .get(&apps_id)
                .map(|settings| serde_json::Value::Object(settings.as_object().clone())),
            Some(json!({})),
            "the official Apps server marker is emitted only through the frozen descriptor registry"
        );
    }

    #[test]
    fn unnegotiated_extension_metadata_is_rejected_without_mutating_the_registry() {
        let apps = official_apps_metadata_descriptor();
        let apps_id = apps.id.clone();
        let mut descriptors = ExtensionDescriptorRegistry::new();
        descriptors
            .register(apps)
            .expect("the compile-linked official Apps descriptor registers");
        let mut handlers = ExtensionHandlerRegistry::new(descriptors);
        let unnegotiated = ExtensionId::parse("com.example/unnegotiated-ui")
            .expect("one different extension identifier is valid");
        let marker = ExtensionSettings::new(json!({}))
            .expect("the unchanged official Apps server marker is an object");

        assert_eq!(
            handlers.register_server_metadata(unnegotiated.clone(), marker),
            Err(ExtensionHandlerRegistrationError::UnregisteredExtension(
                unnegotiated.to_string()
            )),
            "only the extension identifier differs from the registered Apps metadata path"
        );
        assert_eq!(handlers.server_metadata_len(), 0);
        assert!(handlers.descriptor_registry().descriptor(&apps_id).is_some());

        handlers.freeze().expect("unchanged registry still freezes");
        assert!(
            handlers
                .server_discovery()
                .expect("unchanged frozen registry still exports discovery")
                .extensions
                .is_empty(),
            "the rejected unnegotiated extension cannot alter advertised metadata"
        );
    }

    #[test]
    fn extension_handler_registry_rejects_duplicate_key_one_variable_negative() {
        let (descriptors, id) = tasks_descriptors();
        let mut handlers = ExtensionHandlerRegistry::new(descriptors);
        handlers
            .register(id.clone(), "tasks/get", get_task)
            .expect("baseline handler registers");

        assert_eq!(
            handlers.register(id.clone(), "tasks/get", alternate_get_task),
            Err(ExtensionHandlerRegistrationError::DuplicateHandler(
                ExtensionHandlerKey::new(id, "tasks/get")
            )),
            "only the handler implementation changes from the registered request location"
        );
    }

    #[test]
    fn extension_handler_registry_erases_heterogeneous_types_and_rejects_malformed_input() {
        let (descriptors, id) = tasks_descriptors();
        let mut handlers = ExtensionHandlerRegistry::new(descriptors);
        let get_calls = Arc::new(AtomicUsize::new(0));
        let counted_get_calls = Arc::clone(&get_calls);
        handlers
            .register(
                id.clone(),
                "tasks/get",
                move |context: &McpContext, request: GetTaskRequest| {
                    counted_get_calls.fetch_add(1, Ordering::Relaxed);
                    get_task(context, request)
                },
            )
            .expect("typed Tasks get handler registers");
        handlers
            .register(id.clone(), "tasks/update", update_task)
            .expect("differently typed Tasks update handler registers");
        handlers.freeze().expect("handler registry freezes");
        let negotiated = negotiated_tasks(handlers.descriptor_registry(), &id);
        let context = McpContext::new(Cx::for_testing(), 71);

        assert_eq!(
            handlers
                .invoke(
                    &negotiated,
                    ProtocolEra::Modern2026,
                    &id,
                    "tasks/get",
                    &context,
                    json!({"value": 41}),
                )
                .expect("negotiated protocol admission invokes the typed get handler"),
            json!({"next": 42})
        );
        assert_eq!(
            handlers
                .invoke(
                    &negotiated,
                    ProtocolEra::Modern2026,
                    &id,
                    "tasks/update",
                    &context,
                    json!({"title": "review"}),
                )
                .expect("the same registry invokes the differently typed update handler"),
            json!({"updated_title": "REVIEW"})
        );
        assert_eq!(get_calls.load(Ordering::Relaxed), 1);

        let error = handlers
            .invoke(
                &negotiated,
                ProtocolEra::Modern2026,
                &id,
                "tasks/get",
                &context,
                json!({"unexpected": true}),
            )
            .expect_err("one malformed request field shape must reject before the handler runs");
        let ExtensionHandlerInvocationError::Handler(error) = error else {
            panic!("malformed parameters must reach the typed serde admission boundary");
        };
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            get_calls.load(Ordering::Relaxed),
            1,
            "failed typed decoding cannot invoke the registered handler"
        );
    }
}
