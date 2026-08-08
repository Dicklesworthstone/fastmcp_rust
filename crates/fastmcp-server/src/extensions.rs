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
    NegotiatedExtensionSet,
};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    ExtensionDescriptorRegistry, ExtensionDirection, ExtensionId, ExtensionRegistryReceipt,
};

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
/// A registry is parameterized by the decoded request and response types, so
/// a caller cannot register a handler with an incompatible request/result
/// shape. Method ownership, direction, negotiated capability activation, and
/// descriptor receipt are still enforced by the protocol registry at every
/// invocation.
pub struct ExtensionHandlerRegistry<Request, Response> {
    descriptor_registry: ExtensionDescriptorRegistry,
    handlers: BTreeMap<ExtensionHandlerKey, Box<dyn ExtensionHandler<Request, Response>>>,
    frozen: bool,
    marker: PhantomData<fn(Request) -> Response>,
}

impl<Request, Response> ExtensionHandlerRegistry<Request, Response> {
    /// Starts a handler registry around the supplied protocol descriptor registry.
    #[must_use]
    pub fn new(descriptor_registry: ExtensionDescriptorRegistry) -> Self {
        Self {
            descriptor_registry,
            handlers: BTreeMap::new(),
            frozen: false,
            marker: PhantomData,
        }
    }

    /// Returns the protocol descriptor registry that governs handler admission.
    #[must_use]
    pub const fn descriptor_registry(&self) -> &ExtensionDescriptorRegistry {
        &self.descriptor_registry
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

    /// Registers one typed handler for an extension request method.
    ///
    /// Descriptor existence is checked immediately. Exact method ownership and
    /// client-to-server direction remain request-specific protocol checks, so
    /// [`Self::invoke`] performs them against the current negotiated extension
    /// set before this handler can run.
    pub fn register<Handler>(
        &mut self,
        extension_id: ExtensionId,
        method: impl Into<String>,
        handler: Handler,
    ) -> Result<(), ExtensionHandlerRegistrationError>
    where
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

        self.handlers.insert(key, Box::new(handler));
        Ok(())
    }

    /// Freezes protocol descriptors and typed handlers under one immutable receipt.
    pub fn freeze(&mut self) -> Result<ExtensionRegistryReceipt, ExtensionRegistryError> {
        let receipt = self.descriptor_registry.freeze()?;
        self.frozen = true;
        Ok(receipt)
    }

    /// Looks up one handler after freezing has made the registry immutable.
    pub fn lookup(
        &self,
        extension_id: &ExtensionId,
        method: &str,
    ) -> Result<&dyn ExtensionHandler<Request, Response>, ExtensionHandlerLookupError> {
        if !self.frozen {
            return Err(ExtensionHandlerLookupError::RegistryNotFrozen);
        }
        let key = ExtensionHandlerKey::new(extension_id.clone(), method);
        self.handlers
            .get(&key)
            .map(Box::as_ref)
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
        request: Request,
    ) -> Result<Response, ExtensionHandlerInvocationError> {
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
        let handler = self
            .lookup(extension_id, method)
            .map_err(|error| match error {
                ExtensionHandlerLookupError::RegistryNotFrozen => {
                    ExtensionHandlerInvocationError::RegistryNotFrozen
                }
                ExtensionHandlerLookupError::HandlerNotFound(key) => {
                    ExtensionHandlerInvocationError::HandlerNotFound(key)
                }
            })?;
        handler
            .handle(context, request)
            .map_err(ExtensionHandlerInvocationError::Handler)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use asupersync::Cx;
    use fastmcp_core::{McpContext, McpResult};
    use fastmcp_protocol::extensions::{
        ClientExtensionDiscovery, ExtensionLocalEnablement, ExtensionSettings,
        ServerExtensionDiscovery, official_tasks_empty_settings, register_official_tasks_extension,
    };
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use fastmcp_protocol::{ExtensionDescriptorRegistry, ExtensionId};

    use super::{ExtensionHandlerRegistrationError, ExtensionHandlerRegistry};

    fn tasks_descriptors() -> (ExtensionDescriptorRegistry, ExtensionId) {
        let mut descriptors = ExtensionDescriptorRegistry::new();
        let id = register_official_tasks_extension(&mut descriptors)
            .expect("official Tasks descriptor registers");
        (descriptors, id)
    }

    fn increment_task(context: &McpContext, value: u32) -> McpResult<u32> {
        assert_eq!(context.request_id(), 71);
        Ok(value + 1)
    }

    fn decrement_task(context: &McpContext, value: u32) -> McpResult<u32> {
        assert_eq!(context.request_id(), 71);
        Ok(value - 1)
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
        let mut handlers = ExtensionHandlerRegistry::<u32, u32>::new(descriptors);
        handlers
            .register(id.clone(), "tasks/get", increment_task)
            .expect("typed Tasks handler registers");

        let receipt = handlers.freeze().expect("handler registry freezes");

        assert!(handlers.is_frozen());
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers.descriptor_registry().receipt(), Some(&receipt));
        assert_eq!(
            handlers
                .lookup(&id, "tasks/get")
                .expect("frozen registry finds its handler")
                .handle(&McpContext::new(Cx::for_testing(), 71), 4)
                .expect("lookup returns the original typed handler"),
            5
        );
    }

    #[test]
    fn extension_handler_registry_rejects_duplicate_key_one_variable_negative() {
        let (descriptors, id) = tasks_descriptors();
        let mut handlers = ExtensionHandlerRegistry::<u32, u32>::new(descriptors);
        handlers
            .register(id.clone(), "tasks/get", increment_task)
            .expect("baseline handler registers");

        assert_eq!(
            handlers.register(id.clone(), "tasks/get", decrement_task),
            Err(ExtensionHandlerRegistrationError::DuplicateHandler(
                super::ExtensionHandlerKey::new(id, "tasks/get")
            )),
            "only the handler implementation changes from the registered request location"
        );
    }

    #[test]
    fn extension_handler_registry_admits_and_invokes_negotiated_handler() {
        let (descriptors, id) = tasks_descriptors();
        let mut handlers = ExtensionHandlerRegistry::<u32, u32>::new(descriptors);
        handlers
            .register(id.clone(), "tasks/get", increment_task)
            .expect("typed Tasks handler registers");
        handlers.freeze().expect("handler registry freezes");
        let negotiated = negotiated_tasks(handlers.descriptor_registry(), &id);

        assert_eq!(
            handlers
                .invoke(
                    &negotiated,
                    ProtocolEra::Modern2026,
                    &id,
                    "tasks/get",
                    &McpContext::new(Cx::for_testing(), 71),
                    41,
                )
                .expect("negotiated protocol admission invokes the typed handler"),
            42
        );
    }
}
