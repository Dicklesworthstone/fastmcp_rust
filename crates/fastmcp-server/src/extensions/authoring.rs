//! Sealed, compile-linked authoring of typed client-to-server extensions.
//!
//! Installation uses the ordinary frozen extension registry. A handler receives
//! only its admitted descriptor, typed effective settings, and observations of
//! its request lifetime. Neither the registration nor the handler context grants
//! access to the registry, raw protocol data, credentials, or an executor.
//!
//! This initial surface supports modern client-to-server requests with bilateral
//! settings. It does not install notification handlers or legacy fallbacks.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use fastmcp_core::{McpContext, McpError, McpResult, sha256_bounded};
use fastmcp_protocol::extensions::{
    ExtensionDescriptor as ProtocolDescriptor, ExtensionDescriptorRegistry,
    ExtensionHttpEraDisposition, ExtensionId, ExtensionMethodDescriptor, ExtensionNegotiationError,
    ExtensionNegotiationResolver, ExtensionSettings, ExtensionSettingsCompatibilityResolver,
    ExtensionSettingsSchema, MAX_EXTENSION_MEMBER_NAME_BYTES,
    MAX_EXTENSION_REGISTRY_CANONICAL_BYTES, NegotiatedExtension, ServerExtensionDiscovery,
};
use fastmcp_protocol::schema::{
    AdmittedSchema, JsonSchemaType, MAX_SCHEMA_INSTANCE_BYTES, SchemaGenerator, admit_final_schema,
};
use serde::de::DeserializeOwned;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use serde_json::Value;

use super::{ErasedExtensionHandler, ExtensionHandlerRegistry};
use crate::BoxFuture;

pub use fastmcp_protocol::{ExtensionDirection, ExtensionFallbackPolicy};

/// Maximum request methods retained by one authoring registration.
pub const MAX_AUTHORING_METHODS: usize = 64;
/// Aggregate encoded schema budget for one registration, including settings.
pub const MAX_AUTHORING_SCHEMA_BYTES: usize = 2 * 1024 * 1024;
/// Complete encoded client, server, or effective settings object budget.
pub const MAX_AUTHORING_SETTINGS_BYTES: usize = 64 * 1024;

/// An immutable, typed request entry in an extension descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionMethod {
    name: String,
    parameter_schema_id: String,
    result_schema_id: String,
}

impl ExtensionMethod {
    /// Exact extension-owned request method.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Identity of the compiled parameter schema.
    #[must_use]
    pub fn parameter_schema_id(&self) -> &str {
        &self.parameter_schema_id
    }

    /// Identity of the compiled response schema.
    #[must_use]
    pub fn result_schema_id(&self) -> &str {
        &self.result_schema_id
    }

    /// Direction of the installed request entry.
    #[must_use]
    pub const fn direction(&self) -> ExtensionDirection {
        ExtensionDirection::ClientToServer
    }

    /// Both peers must advertise compatible current-request settings.
    #[must_use]
    pub const fn fallback(&self) -> ExtensionFallbackPolicy {
        ExtensionFallbackPolicy::RejectOneSided
    }

    fn protocol_method(&self) -> ExtensionMethodDescriptor {
        ExtensionMethodDescriptor {
            name: self.name.clone(),
            direction: self.direction(),
            http_era_disposition: Some(ExtensionHttpEraDisposition::ModernExclusive),
            legacy_fallback: false,
        }
    }
}

/// The sealed, immutable declaration supplied to an extension handler.
///
/// Construction belongs to [`ExtensionBuilder`]. Its ordered method entries and
/// every generated schema are bound into the frozen registry's resolver/codec
/// identity, so reusing a schema name cannot conceal a changed contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionDescriptor {
    id: ExtensionId,
    version: u32,
    client_settings_schema_id: String,
    server_settings_schema_id: String,
    methods: Vec<ExtensionMethod>,
}

impl ExtensionDescriptor {
    /// Exact validated extension identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    /// Nonzero descriptor/resolver contract version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Identity of the compiled client settings schema.
    #[must_use]
    pub fn client_settings_schema_id(&self) -> &str {
        &self.client_settings_schema_id
    }

    /// Identity of the compiled server settings schema.
    #[must_use]
    pub fn server_settings_schema_id(&self) -> &str {
        &self.server_settings_schema_id
    }

    /// Request entries in their declaration order.
    #[must_use]
    pub fn methods(&self) -> &[ExtensionMethod] {
        &self.methods
    }
}

/// A borrowed, admitted extension invocation with no runtime authority.
///
/// There is no public constructor, cloning operation, or access to the internal
/// request context. The framework creates this value only after negotiation,
/// direction/method admission, and typed parameter/settings validation. Its
/// lifetime prevents retention beyond the handler's request.
///
/// Raw runtime and authentication authority are not available from the context:
///
/// ```compile_fail
/// use fastmcp_server::extensions::authoring::ExtensionContext;
/// fn raw_runtime(context: ExtensionContext<'_, ()>) {
///     let _ = context.cx();
/// }
/// ```
///
/// ```compile_fail
/// use fastmcp_server::extensions::authoring::ExtensionContext;
/// fn credentials(context: ExtensionContext<'_, ()>) {
///     let _ = context.auth_context();
/// }
/// ```
///
/// The invocation cannot be cloned or retained after its borrowed request:
///
/// ```compile_fail
/// use fastmcp_server::extensions::authoring::ExtensionContext;
/// fn duplicate(context: ExtensionContext<'_, ()>) {
///     let _ = context.clone();
/// }
/// ```
///
/// ```compile_fail
/// use fastmcp_server::extensions::authoring::ExtensionContext;
/// fn retain(context: ExtensionContext<'_, ()>) -> ExtensionContext<'static, ()> {
///     context
/// }
/// ```
pub struct ExtensionContext<'a, Settings> {
    context: &'a McpContext,
    descriptor: &'a ExtensionDescriptor,
    method: &'a ExtensionMethod,
    settings: &'a Settings,
}

impl<Settings> ExtensionContext<'_, Settings> {
    /// Frozen declaration admitted for this invocation.
    #[must_use]
    pub const fn descriptor(&self) -> &ExtensionDescriptor {
        self.descriptor
    }

    /// Typed settings resolved for the current request.
    #[must_use]
    pub const fn settings(&self) -> &Settings {
        self.settings
    }

    /// Exact admitted method name.
    #[must_use]
    pub fn method(&self) -> &str {
        self.method.name()
    }

    /// Immutable schema and direction metadata for the admitted method.
    #[must_use]
    pub const fn method_descriptor(&self) -> &ExtensionMethod {
        self.method
    }

    /// Checks cancellation/deadline and charges the ordinary request checkpoint.
    pub fn checkpoint(&self) -> McpResult<()> {
        self.context
            .checkpoint()
            .map_err(|_| McpError::request_cancelled())
    }

    /// Whether the request is no longer live.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.context.is_cancelled()
    }

    /// Whether the request's own deadline has elapsed.
    #[must_use]
    pub fn deadline_expired(&self) -> bool {
        self.context.deadline_expired()
    }

    /// Remaining monotonic time, if this request has a finite deadline.
    ///
    /// This is an observation, not permission to extend a deadline or run work
    /// after cancellation. An elapsed deadline reports zero.
    #[must_use]
    pub fn remaining_time(&self) -> Option<Duration> {
        self.context.budget().deadline.map(|deadline| {
            Duration::from_nanos(
                deadline
                    .as_nanos()
                    .saturating_sub(self.context.cx().now().as_nanos()),
            )
        })
    }
}

/// An asynchronous typed extension handler polled by the caller-owned runtime.
///
/// The response is the handler's typed response sink: the framework validates
/// and serializes it only while the request is still live. Returning a value
/// never grants a transport write or detached-task capability.
pub trait ExtensionHandler<Request, Response, Settings>: Send + Sync {
    /// Executes one admitted request with the sealed, borrowed context.
    fn handle<'a>(
        &'a self,
        context: ExtensionContext<'a, Settings>,
        request: Request,
    ) -> BoxFuture<'a, McpResult<Response>>;
}

impl<Request, Response, Settings, Handler> ExtensionHandler<Request, Response, Settings> for Handler
where
    Handler: for<'a> Fn(ExtensionContext<'a, Settings>, Request) -> BoxFuture<'a, McpResult<Response>>
        + Send
        + Sync,
{
    fn handle<'a>(
        &'a self,
        context: ExtensionContext<'a, Settings>,
        request: Request,
    ) -> BoxFuture<'a, McpResult<Response>> {
        self(context, request)
    }
}

#[derive(Clone)]
struct CompiledSchema {
    admitted: Arc<AdmittedSchema>,
    digest: [u8; 32],
    bytes: usize,
}

type SettingsResolver =
    dyn Fn(&ExtensionSettings, &ExtensionSettings) -> McpResult<ExtensionSettings> + Send + Sync;
type HandlerFactory =
    dyn FnOnce(Arc<ExtensionDescriptor>) -> Box<dyn ErasedExtensionHandler> + Send;

struct PendingMethod {
    parameter_digest: [u8; 32],
    result_digest: [u8; 32],
    factory: Box<HandlerFactory>,
}

/// Typed construction of an immutable extension registration.
///
/// Client, server, and effective settings are separate Rust types. The resolver
/// receives independently validated values and must explicitly decide whether
/// they are compatible. All schemas are generated/admitted during construction;
/// handlers never receive schemas, a registry, or arbitrary codec authority.
pub struct ExtensionBuilder<ClientSettings, ServerSettings, Settings> {
    descriptor: ExtensionDescriptor,
    server_settings: ExtensionSettings,
    resolve: Box<SettingsResolver>,
    client_schema: CompiledSchema,
    server_schema: CompiledSchema,
    effective_schema: CompiledSchema,
    schema_bytes: usize,
    schema_identities: BTreeMap<String, [u8; 32]>,
    pending: Vec<PendingMethod>,
    marker: PhantomData<fn(ClientSettings, ServerSettings) -> Settings>,
}

impl<ClientSettings, ServerSettings, Settings>
    ExtensionBuilder<ClientSettings, ServerSettings, Settings>
where
    ClientSettings: DeserializeOwned + JsonSchemaType + Send + Sync,
    ServerSettings: DeserializeOwned + Serialize + JsonSchemaType + Send + Sync,
    Settings: DeserializeOwned + Serialize + JsonSchemaType + Send + Sync,
{
    /// Admits an application-owned descriptor and typed server configuration.
    ///
    /// The exact official `io.modelcontextprotocol` namespace is reserved for
    /// the framework's official extension implementations. Version zero,
    /// malformed/oversized schema identities, non-object settings, unsupported
    /// schemas, and configuration outside its schema are rejected immediately.
    pub fn new<Resolver>(
        id: impl Into<String>,
        version: u32,
        client_settings_schema_id: impl Into<String>,
        server_settings_schema_id: impl Into<String>,
        server_settings: ServerSettings,
        resolver: Resolver,
    ) -> McpResult<Self>
    where
        Resolver: Fn(ClientSettings, ServerSettings) -> McpResult<Settings> + Send + Sync + 'static,
    {
        let id = ExtensionId::parse(id)
            .map_err(|_| McpError::invalid_params("invalid extension authoring identifier"))?;
        if id.as_str().starts_with("io.modelcontextprotocol/") {
            return Err(McpError::invalid_params(
                "official extension identifiers cannot be registered through authoring",
            ));
        }
        if version == 0 {
            return Err(McpError::invalid_params(
                "extension descriptor version must be nonzero",
            ));
        }
        let client_settings_schema_id = checked_identity(client_settings_schema_id.into())?;
        let server_settings_schema_id = checked_identity(server_settings_schema_id.into())?;
        let client_schema = compile_schema::<ClientSettings>()?;
        let server_schema = compile_schema::<ServerSettings>()?;
        let effective_schema = compile_schema::<Settings>()?;
        let schema_bytes = add_schema_bytes(
            add_schema_bytes(client_schema.bytes, server_schema.bytes)?,
            effective_schema.bytes,
        )?;
        let mut schema_identities =
            BTreeMap::from([(client_settings_schema_id.clone(), client_schema.digest)]);
        retain_schema_identity(
            &mut schema_identities,
            &server_settings_schema_id,
            server_schema.digest,
        )?;
        let server_value =
            encode_value(&server_settings, MAX_AUTHORING_SETTINGS_BYTES).map_err(|_| {
                McpError::invalid_params("extension server settings exceed their budget")
            })?;
        server_schema
            .admitted
            .validate(&server_value)
            .map_err(|_| {
                McpError::invalid_params("extension server settings do not satisfy their schema")
            })?;
        let server_settings = ExtensionSettings::new(server_value)
            .map_err(|_| McpError::invalid_params("invalid extension server settings object"))?;
        let client_validation = Arc::clone(&client_schema.admitted);
        let server_validation = Arc::clone(&server_schema.admitted);
        let effective_validation = Arc::clone(&effective_schema.admitted);
        let resolve = Box::new(
            move |client: &ExtensionSettings, server: &ExtensionSettings| {
                let client = decode_settings::<ClientSettings>(client, &client_validation)?;
                let server = decode_settings::<ServerSettings>(server, &server_validation)?;
                let effective = resolver(client, server)?;
                let value = encode_value(&effective, MAX_AUTHORING_SETTINGS_BYTES)?;
                effective_validation.validate(&value).map_err(|_| {
                    McpError::invalid_params(
                        "effective extension settings do not satisfy their schema",
                    )
                })?;
                ExtensionSettings::new(value).map_err(|_| {
                    McpError::invalid_params("invalid effective extension settings object")
                })
            },
        );
        Ok(Self {
            descriptor: ExtensionDescriptor {
                id,
                version,
                client_settings_schema_id,
                server_settings_schema_id,
                methods: Vec::new(),
            },
            server_settings,
            resolve,
            client_schema,
            server_schema,
            effective_schema,
            schema_bytes,
            schema_identities,
            pending: Vec::new(),
            marker: PhantomData,
        })
    }
}

impl<ClientSettings, ServerSettings, Settings>
    ExtensionBuilder<ClientSettings, ServerSettings, Settings>
{
    /// Returns the descriptor being assembled, without permitting mutation.
    #[must_use]
    pub const fn descriptor(&self) -> &ExtensionDescriptor {
        &self.descriptor
    }

    /// Seals typed construction into a one-shot server registration.
    ///
    /// The registration has no public registry/codec access. Install it with
    /// the server builder before building/freezing the server.
    pub fn build(self) -> McpResult<ExtensionRegistration> {
        let first = self.descriptor.methods.first().ok_or_else(|| {
            McpError::invalid_params("extension authoring requires at least one request method")
        })?;
        let digest = self.contract_digest()?;
        let digest = hex_digest(&digest);
        let protocol = ProtocolDescriptor {
            id: self.descriptor.id.clone(),
            client_settings: ExtensionSettingsSchema {
                schema_id: self.descriptor.client_settings_schema_id.clone(),
                codec_id: format!("fastmcp.ext-dev.client.v1.{digest}"),
            },
            server_settings: ExtensionSettingsSchema {
                schema_id: self.descriptor.server_settings_schema_id.clone(),
                codec_id: format!("fastmcp.ext-dev.server.v1.{digest}"),
            },
            resolver: ExtensionNegotiationResolver {
                id: format!("fastmcp.ext-dev.resolver.v1.{digest}"),
                version: self.descriptor.version,
                fallback: ExtensionFallbackPolicy::RejectOneSided,
            },
            method: Some(first.protocol_method()),
            notification: None,
            result_discriminator: None,
            routing_headers: Vec::new(),
            stdio_correlation: None,
        };
        let mut descriptors = ExtensionDescriptorRegistry::new();
        descriptors.register(protocol.clone()).map_err(|_| {
            McpError::invalid_params("extension descriptor conflicts with the protocol registry")
        })?;
        for method in self.descriptor.methods.iter().skip(1) {
            descriptors
                .register_method(&self.descriptor.id, method.protocol_method())
                .map_err(|_| {
                    McpError::invalid_params("extension method registration was rejected")
                })?;
        }
        let descriptor = Arc::new(self.descriptor);
        let mut handlers = ExtensionHandlerRegistry::new(descriptors);
        handlers
            .register_server_metadata(descriptor.id.clone(), self.server_settings.clone())
            .map_err(|_| {
                McpError::invalid_params("extension discovery registration was rejected")
            })?;
        for (method, pending) in descriptor.methods.iter().zip(self.pending) {
            handlers
                .register_handler(
                    descriptor.id.clone(),
                    method.name.clone(),
                    (pending.factory)(Arc::clone(&descriptor)),
                )
                .map_err(|_| {
                    McpError::invalid_params("extension handler registration was rejected")
                })?;
        }
        let discovery = ServerExtensionDiscovery {
            extensions: BTreeMap::from([(descriptor.id.clone(), self.server_settings)]),
        };
        Ok(ExtensionRegistration {
            descriptor,
            handlers,
            discovery,
            resolver: AuthoringSettingsResolver {
                descriptor: protocol,
                resolve: self.resolve,
            },
        })
    }

    fn prepare_method<Request: JsonSchemaType, Response: JsonSchemaType>(
        &self,
        method: String,
        parameter_schema_id: String,
        result_schema_id: String,
    ) -> McpResult<(ExtensionMethod, CompiledSchema, CompiledSchema, usize)> {
        if self.pending.len() >= MAX_AUTHORING_METHODS {
            return Err(McpError::invalid_params("extension method budget exceeded"));
        }
        let method = checked_identity(method)?;
        let prefix = self
            .descriptor
            .id
            .as_str()
            .split_once('/')
            .map(|(prefix, _)| prefix);
        if method.split_once('/').map(|(prefix, _)| prefix) != prefix || method.ends_with('/') {
            return Err(McpError::invalid_params(
                "extension request method must use its owning identifier namespace",
            ));
        }
        if self
            .descriptor
            .methods
            .iter()
            .any(|entry| entry.name == method)
        {
            return Err(McpError::invalid_params(
                "duplicate extension request method",
            ));
        }
        let parameter_schema_id = checked_identity(parameter_schema_id)?;
        let result_schema_id = checked_identity(result_schema_id)?;
        let parameter_schema = compile_schema::<Request>()?;
        let result_schema = compile_schema::<Response>()?;
        for (identity, digest) in [
            (&parameter_schema_id, parameter_schema.digest),
            (&result_schema_id, result_schema.digest),
        ] {
            if self
                .schema_identities
                .get(identity)
                .is_some_and(|existing| existing != &digest)
            {
                return Err(McpError::invalid_params(
                    "extension schema identity names conflicting schemas",
                ));
            }
        }
        if parameter_schema_id == result_schema_id
            && parameter_schema.digest != result_schema.digest
        {
            return Err(McpError::invalid_params(
                "extension schema identity names conflicting schemas",
            ));
        }
        let total = add_schema_bytes(
            add_schema_bytes(self.schema_bytes, parameter_schema.bytes)?,
            result_schema.bytes,
        )?;
        Ok((
            ExtensionMethod {
                name: method,
                parameter_schema_id,
                result_schema_id,
            },
            parameter_schema,
            result_schema,
            total,
        ))
    }

    fn contract_digest(&self) -> McpResult<[u8; 32]> {
        let methods: Vec<_> = self
            .descriptor
            .methods
            .iter()
            .zip(&self.pending)
            .map(|(method, pending)| {
                (
                    method.name.as_str(),
                    "client-to-server",
                    method.parameter_schema_id.as_str(),
                    method.result_schema_id.as_str(),
                    "reject-one-sided",
                    pending.parameter_digest,
                    pending.result_digest,
                )
            })
            .collect();
        let subject = (
            "fastmcp.ext-dev.authoring-contract.v1",
            self.descriptor.id.as_str(),
            self.descriptor.version,
            self.descriptor.client_settings_schema_id.as_str(),
            self.descriptor.server_settings_schema_id.as_str(),
            self.client_schema.digest,
            self.server_schema.digest,
            self.effective_schema.digest,
            methods,
        );
        let bytes = encode_bytes(&subject, MAX_EXTENSION_REGISTRY_CANONICAL_BYTES)?;
        sha256_bounded(&bytes, MAX_EXTENSION_REGISTRY_CANONICAL_BYTES)
            .map(|digest| digest.into_bytes())
            .map_err(|_| {
                McpError::invalid_params("extension descriptor contract exceeds its budget")
            })
    }
}

impl<ClientSettings, ServerSettings, Settings>
    ExtensionBuilder<ClientSettings, ServerSettings, Settings>
where
    Settings: DeserializeOwned + Send + Sync + 'static,
{
    /// Registers an asynchronous typed request and its exact schema identities.
    ///
    /// Framework `_meta` is admitted by the normal protocol path and removed
    /// before the typed parameter schema/decoder runs. Application types can
    /// therefore reject unknown fields without rejecting valid MCP metadata.
    pub fn typed_request<Request, Response, Handler>(
        mut self,
        method: impl Into<String>,
        parameter_schema_id: impl Into<String>,
        result_schema_id: impl Into<String>,
        handler: Handler,
    ) -> McpResult<Self>
    where
        Request: DeserializeOwned + JsonSchemaType + Send + 'static,
        Response: Serialize + JsonSchemaType + Send + 'static,
        Handler: ExtensionHandler<Request, Response, Settings> + 'static,
    {
        let (method, parameter_schema, result_schema, total) = self
            .prepare_method::<Request, Response>(
                method.into(),
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
        self.pending.push(PendingMethod {
            parameter_digest: parameter_schema.digest,
            result_digest: result_schema.digest,
            factory: Box::new(move |descriptor| {
                Box::new(TypedAsyncHandler::<Request, Response, Settings, Handler> {
                    binding: HandlerBinding {
                        descriptor,
                        method_index: index,
                        parameter_schema: parameter_schema.admitted,
                        result_schema: result_schema.admitted,
                        effective_schema,
                    },
                    handler,
                    marker: PhantomData,
                })
            }),
        });
        self.descriptor.methods.push(method);
        self.schema_bytes = total;
        Ok(self)
    }

    /// Registers a synchronous callback with the same sealed typed admission.
    ///
    /// Both synchronous and asynchronous framework dispatch can invoke this
    /// callback. No private runtime or `block_on` bridge is constructed.
    pub fn typed_request_sync<Request, Response, Handler>(
        mut self,
        method: impl Into<String>,
        parameter_schema_id: impl Into<String>,
        result_schema_id: impl Into<String>,
        handler: Handler,
    ) -> McpResult<Self>
    where
        Request: DeserializeOwned + JsonSchemaType + Send + 'static,
        Response: Serialize + JsonSchemaType + Send + 'static,
        Handler: for<'a> Fn(ExtensionContext<'a, Settings>, Request) -> McpResult<Response>
            + Send
            + Sync
            + 'static,
    {
        let (method, parameter_schema, result_schema, total) = self
            .prepare_method::<Request, Response>(
                method.into(),
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
        self.pending.push(PendingMethod {
            parameter_digest: parameter_schema.digest,
            result_digest: result_schema.digest,
            factory: Box::new(move |descriptor| {
                Box::new(TypedSyncHandler::<Request, Response, Settings, Handler> {
                    binding: HandlerBinding {
                        descriptor,
                        method_index: index,
                        parameter_schema: parameter_schema.admitted,
                        result_schema: result_schema.admitted,
                        effective_schema,
                    },
                    handler,
                    marker: PhantomData,
                })
            }),
        });
        self.descriptor.methods.push(method);
        self.schema_bytes = total;
        Ok(self)
    }
}

/// One-shot installation produced by a typed authoring builder.
///
/// The framework consumes this registration before freeze. Application code
/// can inspect the immutable descriptor but cannot obtain or mutate its raw
/// registry, resolver, codecs, or handlers.
pub struct ExtensionRegistration {
    descriptor: Arc<ExtensionDescriptor>,
    handlers: ExtensionHandlerRegistry,
    discovery: ServerExtensionDiscovery,
    resolver: AuthoringSettingsResolver,
}

impl ExtensionRegistration {
    /// The immutable declaration that will be installed.
    #[must_use]
    pub fn descriptor(&self) -> &ExtensionDescriptor {
        &self.descriptor
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ExtensionHandlerRegistry,
        ServerExtensionDiscovery,
        AuthoringSettingsResolver,
    ) {
        (self.handlers, self.discovery, self.resolver)
    }
}

pub(crate) struct AuthoringSettingsResolver {
    descriptor: ProtocolDescriptor,
    resolve: Box<SettingsResolver>,
}

impl ExtensionSettingsCompatibilityResolver for AuthoringSettingsResolver {
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

struct HandlerBinding {
    descriptor: Arc<ExtensionDescriptor>,
    method_index: usize,
    parameter_schema: Arc<AdmittedSchema>,
    result_schema: Arc<AdmittedSchema>,
    effective_schema: Arc<AdmittedSchema>,
}

impl HandlerBinding {
    fn decode<Request: DeserializeOwned, Settings: DeserializeOwned>(
        &self,
        context: &McpContext,
        negotiated: &NegotiatedExtension,
        parameters: Value,
    ) -> McpResult<(Request, Settings)> {
        ensure_live(context)?;
        if negotiated.id() != &self.descriptor.id {
            return Err(McpError::invalid_request(
                "extension handler has no matching admitted descriptor",
            ));
        }
        let Value::Object(mut parameters) = parameters else {
            return Err(McpError::invalid_params(
                "extension request parameters must be an object",
            ));
        };
        parameters.remove("_meta");
        let parameters = Value::Object(parameters);
        self.parameter_schema.validate(&parameters).map_err(|_| {
            McpError::invalid_params("extension request does not satisfy its parameter schema")
        })?;
        let request = serde_json::from_value(parameters)
            .map_err(|_| McpError::invalid_params("extension request typed decoding failed"))?;
        let settings = decode_settings(
            negotiated.effective_settings().settings(),
            &self.effective_schema,
        )?;
        ensure_live(context)?;
        Ok((request, settings))
    }

    fn context<'a, Settings>(
        &'a self,
        context: &'a McpContext,
        settings: &'a Settings,
    ) -> ExtensionContext<'a, Settings> {
        ExtensionContext {
            context,
            descriptor: &self.descriptor,
            method: &self.descriptor.methods[self.method_index],
            settings,
        }
    }

    fn encode<Response: Serialize>(
        &self,
        context: &McpContext,
        response: &Response,
    ) -> McpResult<Value> {
        ensure_live(context)?;
        let value = encode_value(response, MAX_SCHEMA_INSTANCE_BYTES).map_err(|_| {
            McpError::internal_error("extension response serialization exceeded its budget")
        })?;
        self.result_schema.validate(&value).map_err(|_| {
            McpError::internal_error("extension response does not satisfy its result schema")
        })?;
        ensure_live(context)?;
        Ok(value)
    }
}

struct TypedAsyncHandler<Request, Response, Settings, Handler> {
    binding: HandlerBinding,
    handler: Handler,
    marker: PhantomData<fn(Request, Settings) -> Response>,
}

impl<Request, Response, Settings, Handler> ErasedExtensionHandler
    for TypedAsyncHandler<Request, Response, Settings, Handler>
where
    Request: DeserializeOwned + Send + 'static,
    Response: Serialize + Send + 'static,
    Settings: DeserializeOwned + Send + Sync + 'static,
    Handler: ExtensionHandler<Request, Response, Settings>,
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
            "asynchronous extension handler requires asynchronous dispatch",
        ))
    }

    fn invoke_admitted_async<'a>(
        &'a self,
        context: &'a McpContext,
        negotiated: &'a NegotiatedExtension,
        parameters: Value,
    ) -> BoxFuture<'a, McpResult<Value>> {
        Box::pin(async move {
            let (request, settings) = self.binding.decode(context, negotiated, parameters)?;
            let response = self
                .handler
                .handle(self.binding.context(context, &settings), request)
                .await?;
            self.binding.encode(context, &response)
        })
    }
}

struct TypedSyncHandler<Request, Response, Settings, Handler> {
    binding: HandlerBinding,
    handler: Handler,
    marker: PhantomData<fn(Request, Settings) -> Response>,
}

impl<Request, Response, Settings, Handler> ErasedExtensionHandler
    for TypedSyncHandler<Request, Response, Settings, Handler>
where
    Request: DeserializeOwned,
    Response: Serialize,
    Settings: DeserializeOwned,
    Handler:
        for<'a> Fn(ExtensionContext<'a, Settings>, Request) -> McpResult<Response> + Send + Sync,
{
    fn invoke(&self, _context: &McpContext, _parameters: Value) -> McpResult<Value> {
        Err(unbound_handler())
    }

    fn invoke_admitted(
        &self,
        context: &McpContext,
        negotiated: &NegotiatedExtension,
        parameters: Value,
    ) -> McpResult<Value> {
        let (request, settings) = self.binding.decode(context, negotiated, parameters)?;
        let response = (self.handler)(self.binding.context(context, &settings), request)?;
        self.binding.encode(context, &response)
    }

    fn invoke_admitted_async<'a>(
        &'a self,
        context: &'a McpContext,
        negotiated: &'a NegotiatedExtension,
        parameters: Value,
    ) -> BoxFuture<'a, McpResult<Value>> {
        Box::pin(async move { self.invoke_admitted(context, negotiated, parameters) })
    }
}

fn unbound_handler() -> McpError {
    McpError::invalid_request("sealed extension handler requires current-request admission")
}

fn ensure_live(context: &McpContext) -> McpResult<()> {
    context
        .ensure_live()
        .map_err(|_| McpError::request_cancelled())
}

fn checked_identity(value: String) -> McpResult<String> {
    if value.is_empty()
        || value.len() > MAX_EXTENSION_MEMBER_NAME_BYTES
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        Err(McpError::invalid_params(
            "invalid or oversized extension contract identity",
        ))
    } else {
        Ok(value)
    }
}

fn add_schema_bytes(retained: usize, added: usize) -> McpResult<usize> {
    retained
        .checked_add(added)
        .filter(|total| *total <= MAX_AUTHORING_SCHEMA_BYTES)
        .ok_or_else(|| McpError::invalid_params("extension aggregate schema budget exceeded"))
}

fn retain_schema_identity(
    identities: &mut BTreeMap<String, [u8; 32]>,
    identity: &str,
    digest: [u8; 32],
) -> McpResult<()> {
    if identities
        .get(identity)
        .is_some_and(|existing| existing != &digest)
    {
        return Err(McpError::invalid_params(
            "extension schema identity names conflicting schemas",
        ));
    }
    identities.insert(identity.to_owned(), digest);
    Ok(())
}

fn compile_schema<T: JsonSchemaType>() -> McpResult<CompiledSchema> {
    let mut generator = SchemaGenerator::default();
    let root = generator.subschema_for::<T>();
    let schema = generator
        .finish(root)
        .map_err(|_| McpError::invalid_params("extension schema generation failed"))?;
    let admitted = admit_final_schema(schema)
        .map_err(|_| McpError::invalid_params("extension schema admission failed"))?;
    let canonical = encode_bytes(
        &CanonicalSchema(admitted.schema()),
        MAX_AUTHORING_SCHEMA_BYTES,
    )?;
    let digest = sha256_bounded(&canonical, MAX_AUTHORING_SCHEMA_BYTES)
        .map_err(|_| McpError::invalid_params("extension schema exceeds its budget"))?
        .into_bytes();
    Ok(CompiledSchema {
        admitted: Arc::new(admitted),
        digest,
        bytes: canonical.len(),
    })
}

fn decode_settings<T: DeserializeOwned>(
    settings: &ExtensionSettings,
    schema: &AdmittedSchema,
) -> McpResult<T> {
    let value = encode_value(settings.as_object(), MAX_AUTHORING_SETTINGS_BYTES)?;
    schema.validate(&value).map_err(|_| {
        McpError::invalid_params("extension settings do not satisfy their declared schema")
    })?;
    serde_json::from_value(value)
        .map_err(|_| McpError::invalid_params("extension settings typed decoding failed"))
}

/// Serializes map entries in key order even if serde_json enables preserve_order.
struct CanonicalSchema<'a>(&'a Value);

impl Serialize for CanonicalSchema<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(value) => serializer.serialize_bool(*value),
            Value::Number(value) => value.serialize(serializer),
            Value::String(value) => serializer.serialize_str(value),
            Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&CanonicalSchema(value))?;
                }
                sequence.end()
            }
            Value::Object(values) => {
                let mut entries: Vec<_> = values.iter().collect();
                entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, &CanonicalSchema(value))?;
                }
                map.end()
            }
        }
    }
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("extension JSON byte budget exceeded"));
        }
        let required = self.bytes.len() + bytes.len();
        if required > self.bytes.capacity() {
            let capacity = required
                .max(self.bytes.capacity().saturating_mul(2))
                .max(256)
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|_| io::Error::other("extension JSON allocation refused"))?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_bytes<T: Serialize + ?Sized>(value: &T, limit: usize) -> McpResult<Vec<u8>> {
    let mut writer = BoundedJsonWriter {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| McpError::invalid_params("extension JSON encoding exceeded its budget"))?;
    Ok(writer.bytes)
}

fn encode_value<T: Serialize + ?Sized>(value: &T, limit: usize) -> McpResult<Value> {
    serde_json::from_slice(&encode_bytes(value, limit)?)
        .map_err(|_| McpError::invalid_params("extension JSON encoding was rejected"))
}

fn hex_digest(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use fastmcp_core::McpErrorCode;
    use fastmcp_protocol::JsonRpcRequest;
    use fastmcp_protocol::extensions::{
        ClientExtensionDiscovery, ExtensionLocalEnablement, NegotiatedExtensionSet,
    };
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use serde::Deserialize;
    use serde_json::json;

    use super::*;
    use crate::extensions::ExtensionHandlerInvocationError;

    const ID: &str = "dev.example/scaling";
    const METHOD: &str = "dev.example/scale";

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct ClientSettings {
        scale: u32,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct ServerSettings {
        maximum: u32,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Settings {
        scale: u32,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        value: i64,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TighterInput {
        value: i64,
    }

    #[derive(Serialize)]
    struct Output {
        product: i64,
    }

    macro_rules! object_schema {
        ($ty:ty, $property:literal, $schema:expr) => {
            impl JsonSchemaType for $ty {
                fn schema_body(_generator: &mut SchemaGenerator) -> Value {
                    json!({
                        "type": "object",
                        "properties": { $property: $schema },
                        "required": [$property],
                        "additionalProperties": false,
                    })
                }
            }
        };
    }

    object_schema!(
        ClientSettings,
        "scale",
        json!({"type":"integer", "minimum":1})
    );
    object_schema!(
        ServerSettings,
        "maximum",
        json!({"type":"integer", "minimum":1})
    );
    object_schema!(Settings, "scale", json!({"type":"integer", "minimum":1}));
    object_schema!(
        Input,
        "value",
        json!({"type":"integer", "minimum":0, "maximum":100})
    );
    object_schema!(
        TighterInput,
        "value",
        json!({"type":"integer", "minimum":0, "maximum":10})
    );
    object_schema!(Output, "product", json!({"type":"integer", "minimum":0}));

    type Builder = ExtensionBuilder<ClientSettings, ServerSettings, Settings>;

    fn builder_version(version: u32) -> Builder {
        Builder::new(
            ID,
            version,
            "scale-client-v1",
            "scale-server-v1",
            ServerSettings { maximum: 4 },
            |client, server| {
                if client.scale > server.maximum {
                    return Err(McpError::invalid_params("incompatible scale settings"));
                }
                Ok(Settings {
                    scale: client.scale,
                })
            },
        )
        .expect("typed settings and schemas admit")
    }

    fn builder() -> Builder {
        builder_version(1)
    }

    fn multiply(context: ExtensionContext<'_, Settings>, request: Input) -> McpResult<Output> {
        context.checkpoint()?;
        Ok(Output {
            product: request.value * i64::from(context.settings().scale),
        })
    }

    fn registration(calls: Arc<AtomicUsize>) -> ExtensionRegistration {
        builder()
            .typed_request_sync::<Input, Output, _>(
                METHOD,
                "scale-input-v1",
                "scale-output-v1",
                move |context, input| {
                    assert_eq!(context.descriptor().id(), ID);
                    assert_eq!(context.descriptor().version(), 1);
                    assert_eq!(context.method(), METHOD);
                    assert_eq!(
                        context.method_descriptor().parameter_schema_id(),
                        "scale-input-v1"
                    );
                    assert!(!context.is_cancelled());
                    assert!(!context.deadline_expired());
                    calls.fetch_add(1, Ordering::SeqCst);
                    multiply(context, input)
                },
            )
            .expect("typed request registers")
            .build()
            .expect("registration seals")
    }

    struct Harness {
        handlers: ExtensionHandlerRegistry,
        discovery: ServerExtensionDiscovery,
        resolver: AuthoringSettingsResolver,
        id: ExtensionId,
        context: McpContext,
    }

    impl Harness {
        fn new(registration: ExtensionRegistration) -> Self {
            let id = ExtensionId::parse(registration.descriptor().id()).expect("validated ID");
            let (mut handlers, discovery, resolver) = registration.into_parts();
            handlers
                .freeze()
                .expect("production descriptor registry freezes");
            Self {
                handlers,
                discovery,
                resolver,
                id,
                context: McpContext::new(asupersync::Cx::for_testing(), 41),
            }
        }

        fn negotiate(
            &mut self,
            client: Value,
        ) -> Result<NegotiatedExtensionSet, ExtensionNegotiationError> {
            let mut local = ExtensionLocalEnablement::default();
            local.enable(self.id.clone());
            self.handlers.descriptor_registry().negotiate(
                ProtocolEra::Modern2026,
                &local,
                &ClientExtensionDiscovery {
                    extensions: BTreeMap::from([(
                        self.id.clone(),
                        ExtensionSettings::new(client).expect("bounded settings object"),
                    )]),
                },
                &self.discovery,
                &mut self.resolver,
            )
        }

        fn invoke(
            &mut self,
            input: Value,
            scale: u32,
        ) -> Result<Value, ExtensionHandlerInvocationError> {
            let negotiated = self
                .negotiate(json!({"scale": scale}))
                .expect("settings negotiate");
            self.handlers.invoke(
                &self.context,
                &negotiated,
                ProtocolEra::Modern2026,
                &self.id,
                &request(input, scale),
            )
        }
    }

    fn request(mut input: Value, scale: u32) -> JsonRpcRequest {
        input["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": { (ID): { "scale": scale } },
            },
        });
        JsonRpcRequest::new(METHOD, Some(input), 41_i64)
    }

    #[test]
    fn typed_authoring_sync_dispatch_preserves_descriptor_and_effective_settings() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registration = registration(Arc::clone(&calls));
        let descriptor = registration.descriptor();
        assert_eq!(descriptor.client_settings_schema_id(), "scale-client-v1");
        assert_eq!(descriptor.server_settings_schema_id(), "scale-server-v1");
        assert_eq!(descriptor.methods().len(), 1);
        assert_eq!(
            descriptor.methods()[0].direction(),
            ExtensionDirection::ClientToServer
        );
        assert_eq!(
            descriptor.methods()[0].fallback(),
            ExtensionFallbackPolicy::RejectOneSided
        );
        let mut harness = Harness::new(registration);
        assert_eq!(
            harness
                .invoke(json!({"value": 7}), 3)
                .expect("live typed request"),
            json!({"product":21})
        );
        assert_eq!(
            harness
                .invoke(json!({"value": 7}), 2)
                .expect("new effective settings"),
            json!({"product":14})
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn typed_authoring_rejects_schema_invalid_and_unknown_parameters_before_effects() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut harness = Harness::new(registration(Arc::clone(&calls)));
        assert_eq!(
            harness
                .invoke(json!({"value": 100}), 1)
                .expect("upper boundary"),
            json!({"product":100})
        );
        for input in [
            json!({"value":101}),
            json!({"value":100, "extra":"payload-canary"}),
            json!({"value":"payload-canary"}),
        ] {
            let error = harness
                .invoke(input, 1)
                .expect_err("invalid parameters rejected");
            assert!(
                matches!(error, ExtensionHandlerInvocationError::Handler(ref error)
                if error.code == McpErrorCode::InvalidParams)
            );
            assert!(!error.to_string().contains("payload-canary"));
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "no rejected request reaches application code"
            );
        }
    }

    #[test]
    fn typed_authoring_settings_require_both_schema_and_compatibility() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut harness = Harness::new(registration(Arc::clone(&calls)));
        harness
            .negotiate(json!({"scale":4}))
            .expect("highest compatible setting");
        for settings in [
            json!({"scale":0}),
            json!({"scale":5}),
            json!({"scale":4,"extra":"settings-canary"}),
            json!({"scale":"settings-canary"}),
        ] {
            let error = harness.negotiate(settings).expect_err("settings refused");
            assert!(matches!(
                error,
                ExtensionNegotiationError::SettingsCompatibilityRejected(_)
            ));
            assert!(!error.to_string().contains("settings-canary"));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            harness
                .invoke(json!({"value":2}), 4)
                .expect("registry remains usable"),
            json!({"product":8})
        );
    }

    #[test]
    fn typed_authoring_rejects_cancelled_and_expired_requests_before_effects() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut harness = Harness::new(registration(Arc::clone(&calls)));
        harness
            .invoke(json!({"value":1}), 1)
            .expect("live baseline");
        assert!(harness.context.request_cancellation().cancel());
        let cancelled = harness
            .invoke(json!({"value":1}), 1)
            .expect_err("cancelled request");
        assert!(
            matches!(cancelled, ExtensionHandlerInvocationError::Handler(ref error)
            if error.code == McpErrorCode::RequestCancelled)
        );
        harness.context = McpContext::new(
            asupersync::Cx::for_testing_with_budget(
                asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
            ),
            41,
        );
        let expired = harness
            .invoke(json!({"value":1}), 1)
            .expect_err("expired request");
        assert!(
            matches!(expired, ExtensionHandlerInvocationError::Handler(ref error)
            if error.code == McpErrorCode::RequestCancelled)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn typed_authoring_does_not_publish_a_response_after_handler_cancellation() {
        let context = McpContext::new(asupersync::Cx::for_testing(), 41);
        let cancellation = context.request_cancellation();
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let registration = builder()
            .typed_request_sync::<Input, Output, _>(
                METHOD,
                "scale-input-v1",
                "scale-output-v1",
                move |context, input| {
                    let response = multiply(context, input)?;
                    callback_calls.fetch_add(1, Ordering::SeqCst);
                    assert!(cancellation.cancel());
                    Ok(response)
                },
            )
            .expect("typed callback installs")
            .build()
            .expect("registration seals");
        let mut harness = Harness::new(registration);
        harness.context = context;
        let error = harness
            .invoke(json!({"value":3}), 2)
            .expect_err("late result is withheld");
        assert!(
            matches!(error, ExtensionHandlerInvocationError::Handler(ref error)
            if error.code == McpErrorCode::RequestCancelled)
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "cancellation happened inside the handler"
        );
    }

    #[test]
    fn typed_authoring_validates_the_declared_response_schema() {
        let registration = builder()
            .typed_request_sync::<Input, Output, _>(
                METHOD,
                "scale-input-v1",
                "nonnegative-output-v1",
                |context, input| {
                    context.checkpoint()?;
                    Ok(Output {
                        product: input.value - 1,
                    })
                },
            )
            .expect("typed callback installs")
            .build()
            .expect("registration seals");
        let mut harness = Harness::new(registration);
        assert_eq!(
            harness.invoke(json!({"value":1}), 1).expect("valid output"),
            json!({"product":0})
        );
        let error = harness
            .invoke(json!({"value":0}), 1)
            .expect_err("negative output refused");
        assert!(
            matches!(error, ExtensionHandlerInvocationError::Handler(ref error)
            if error.code == McpErrorCode::InternalError)
        );
    }

    struct AsyncMultiply(Arc<AtomicUsize>);

    impl ExtensionHandler<Input, Output, Settings> for AsyncMultiply {
        fn handle<'a>(
            &'a self,
            context: ExtensionContext<'a, Settings>,
            input: Input,
        ) -> BoxFuture<'a, McpResult<Output>> {
            Box::pin(async move {
                context.checkpoint()?;
                asupersync::runtime::yield_now().await;
                let response = multiply(context, input)?;
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(response)
            })
        }
    }

    #[test]
    fn typed_authoring_async_handler_uses_the_callers_runtime() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registration = builder()
            .typed_request::<Input, Output, _>(
                METHOD,
                "scale-input-v1",
                "scale-output-v1",
                AsyncMultiply(Arc::clone(&calls)),
            )
            .expect("async callback installs")
            .build()
            .expect("registration seals");
        let mut harness = Harness::new(registration);
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("test caller owns its runtime");
        harness.context = McpContext::new(
            runtime.request_cx_with_budget(asupersync::Budget::default()),
            41,
        );
        assert!(
            harness.invoke(json!({"value":7}), 3).is_err(),
            "sync invocation never creates a runtime"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let negotiated = harness
            .negotiate(json!({"scale":3}))
            .expect("settings negotiate");
        let request = request(json!({"value":7}), 3);
        let result = runtime
            .block_on(harness.handlers.invoke_async(
                &harness.context,
                &negotiated,
                ProtocolEra::Modern2026,
                &harness.id,
                &request,
            ))
            .expect("async handler completes on borrowed caller context");
        assert_eq!(result, json!({"product":21}));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn typed_authoring_refuses_unbound_erased_invocation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut harness = Harness::new(registration(Arc::clone(&calls)));
        let handler = harness
            .handlers
            .handlers
            .values()
            .next()
            .expect("registered callback");
        assert!(
            handler
                .invoke(&harness.context, json!({"value":1}))
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            harness
                .invoke(json!({"value":1}), 2)
                .expect("same callback with admission"),
            json!({"product":2})
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    fn receipt(registration: ExtensionRegistration) -> [u8; 32] {
        let (mut handlers, _, _) = registration.into_parts();
        *handlers.freeze().expect("frozen registry receipt").digest()
    }

    fn ordinary_registration(builder: Builder) -> ExtensionRegistration {
        builder
            .typed_request_sync::<Input, Output, _>(METHOD, "input-v1", "output-v1", multiply)
            .expect("typed callback registers")
            .build()
            .expect("registration seals")
    }

    #[test]
    fn typed_authoring_registry_receipt_binds_schema_contents_and_version() {
        let baseline = receipt(ordinary_registration(builder()));
        assert_eq!(
            baseline,
            receipt(ordinary_registration(builder())),
            "same contract is stable"
        );
        assert_ne!(
            baseline,
            receipt(ordinary_registration(builder_version(2))),
            "version changes the frozen contract"
        );
        let changed_schema = builder()
            .typed_request_sync::<TighterInput, Output, _>(
                METHOD,
                "input-v1",
                "output-v1",
                |context, input| {
                    context.checkpoint()?;
                    Ok(Output {
                        product: input.value * i64::from(context.settings().scale),
                    })
                },
            )
            .expect("changed schema is independently admissible")
            .build()
            .expect("registration seals");
        assert_ne!(
            baseline,
            receipt(changed_schema),
            "same schema ID cannot hide changed schema bytes"
        );
    }

    #[test]
    fn typed_authoring_rejects_conflicting_schema_identities() {
        for (second_identity, accepted) in [("input-v1", false), ("tighter-input-v1", true)] {
            let builder = builder()
                .typed_request_sync::<Input, Output, _>(METHOD, "input-v1", "output-v1", multiply)
                .expect("baseline request installs");
            let result = builder.typed_request_sync::<TighterInput, Output, _>(
                "dev.example/tighter",
                second_identity,
                "output-v1",
                |context, input| {
                    context.checkpoint()?;
                    Ok(Output {
                        product: input.value,
                    })
                },
            );
            assert_eq!(
                result.is_ok(),
                accepted,
                "only the conflicting schema identity changes"
            );
        }
    }

    #[test]
    fn typed_authoring_rejects_official_namespaces_and_foreign_methods() {
        let official = Builder::new(
            "io.modelcontextprotocol/tasks",
            1,
            "client-v1",
            "server-v1",
            ServerSettings { maximum: 4 },
            |client, _server| {
                Ok(Settings {
                    scale: client.scale,
                })
            },
        );
        assert!(
            official.is_err(),
            "authoring cannot impersonate an official implementation"
        );
        assert!(
            builder()
                .typed_request_sync::<Input, Output, _>(
                    "other.example/scale",
                    "input-v1",
                    "output-v1",
                    multiply,
                )
                .is_err(),
            "only owner-namespaced methods are accepted"
        );
        assert!(
            builder()
                .typed_request_sync::<Input, Output, _>(
                    "tasks/get",
                    "input-v1",
                    "output-v1",
                    multiply,
                )
                .is_err(),
            "official methods are unavailable to application authoring"
        );
        ordinary_registration(builder());
    }

    #[test]
    fn typed_authoring_json_writer_enforces_encoded_byte_budget_before_growth() {
        let value = "abcdefghijklmnop";
        let bytes = encode_bytes(value, 18).expect("quotes plus sixteen bytes fit exactly");
        assert_eq!(bytes.len(), 18);
        assert!(
            encode_bytes(value, 17).is_err(),
            "one byte over is rejected"
        );
        let mut writer = BoundedJsonWriter {
            bytes: Vec::new(),
            limit: 17,
        };
        writer
            .write_all(b"abcdefghijklmnop")
            .expect("sixteen admitted bytes");
        assert!(writer.write_all(b"xy").is_err());
        assert_eq!(
            writer.bytes, b"abcdefghijklmnop",
            "failed write changes no buffered bytes"
        );
        assert!(
            writer.bytes.capacity() <= 17,
            "allocator capacity is bounded too"
        );
    }
}
