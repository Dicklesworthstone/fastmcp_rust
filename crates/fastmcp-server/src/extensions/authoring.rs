//! Sealed, compile-linked authoring of typed client-to-server extensions.
//!
//! Installation uses the ordinary frozen extension registry. A handler receives
//! only its admitted descriptor, typed effective settings, and observations of
//! its request lifetime. Neither the registration nor the handler context grants
//! access to the registry, raw protocol data, credentials, or an executor.
//!
//! Requests use bilateral settings. A notification supplies its own bounded
//! settings proof in an explicitly registered metadata field on every message.
//! HTTP and modern stream transports run that message inside the owning
//! transport's scope. Neither path installs legacy fallbacks or grants
//! transport authority.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use fastmcp_core::{McpContext, McpError, McpResult, sha256_bounded};
use fastmcp_protocol::extensions::{
    ExtensionDescriptor as ProtocolDescriptor, ExtensionDescriptorRegistry,
    ExtensionHttpEraDisposition, ExtensionId, ExtensionMethodDescriptor, ExtensionNegotiationError,
    ExtensionNegotiationResolver, ExtensionNotificationDescriptor, ExtensionSettings,
    ExtensionSettingsCompatibilityResolver, ExtensionSettingsSchema,
    MAX_EXTENSION_MEMBER_NAME_BYTES, MAX_EXTENSION_REGISTRY_CANONICAL_BYTES, NegotiatedExtension,
    NotificationActivationProofDescriptor, NotificationActivationProofLocation,
    ServerExtensionDiscovery, StdioCorrelationCodec, StdioCorrelationDescriptor,
    MAX_STDIO_EXTENSION_NOTIFICATION_PARAMS_BYTES,
};
use fastmcp_protocol::schema::{
    AdmittedSchema, JsonSchemaType, MAX_SCHEMA_INSTANCE_BYTES, SchemaGenerator, admit_final_schema,
};
use serde::de::DeserializeOwned;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use serde_json::Value;

use super::{
    AuthorizedNotificationPayload, ErasedExtensionHandler, ExtensionHandlerRegistry,
    NotificationAuthorizer, RegisteredNotificationHandler,
};
use crate::BoxFuture;

pub use fastmcp_protocol::{ExtensionDirection, ExtensionFallbackPolicy};

/// Maximum request and notification entries retained by one registration.
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

/// An immutable typed notification with current-message activation settings.
///
/// The proof is always inside notification-role `params._meta`. Application
/// parameters are decoded separately, so the settings object cannot supply
/// application fields or turn request metadata into notification authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionNotification {
    name: String,
    parameter_schema_id: String,
    activation_metadata_key: String,
}

impl ExtensionNotification {
    /// Exact extension-owned notification name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Identity of the compiled application-parameter schema.
    #[must_use]
    pub fn parameter_schema_id(&self) -> &str {
        &self.parameter_schema_id
    }

    /// Exact namespaced key inside `params._meta` carrying client settings.
    #[must_use]
    pub fn activation_metadata_key(&self) -> &str {
        &self.activation_metadata_key
    }

    /// Direction of this compiled notification entry.
    #[must_use]
    pub const fn direction(&self) -> ExtensionDirection {
        ExtensionDirection::ClientToServer
    }

    /// Both current-message and configured server settings must be compatible.
    #[must_use]
    pub const fn fallback(&self) -> ExtensionFallbackPolicy {
        ExtensionFallbackPolicy::RejectOneSided
    }

    fn protocol_notification(&self) -> ExtensionNotificationDescriptor {
        ExtensionNotificationDescriptor {
            name: self.name.clone(),
            direction: self.direction(),
            activation_proof: Some(NotificationActivationProofDescriptor::SelfContained {
                location: NotificationActivationProofLocation::Metadata,
                key: self.activation_metadata_key.clone(),
            }),
        }
    }
}

/// One typed server-to-client notification owned by an admitted request.
///
/// The framework stamps the exact request ID into the registered metadata key.
/// This declaration neither creates a subscription nor grants a broadcast sink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionRequestNotification {
    name: String,
    parameter_schema_id: String,
    correlation_metadata_key: String,
}

impl ExtensionRequestNotification {
    /// Exact extension-owned notification method.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Identity of the compiled application-parameter schema.
    #[must_use]
    pub fn parameter_schema_id(&self) -> &str {
        &self.parameter_schema_id
    }

    /// Framework-owned metadata member carrying the exact originating ID.
    #[must_use]
    pub fn correlation_metadata_key(&self) -> &str {
        &self.correlation_metadata_key
    }

    /// Notifications travel from the server to the requesting client.
    #[must_use]
    pub const fn direction(&self) -> ExtensionDirection {
        ExtensionDirection::ServerToClient
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
    notification: Option<ExtensionNotification>,
    request_notification: Option<ExtensionRequestNotification>,
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

    /// The optional notification declared alongside this extension's requests.
    ///
    /// The protocol registry supports one notification per extension descriptor.
    #[must_use]
    pub const fn notification(&self) -> Option<&ExtensionNotification> {
        self.notification.as_ref()
    }

    /// The optional request-owned server-to-client notification declaration.
    #[must_use]
    pub const fn request_notification(&self) -> Option<&ExtensionRequestNotification> {
        self.request_notification.as_ref()
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

    /// Emits this extension's registered typed notification for this request.
    ///
    /// Available on modern stdio and memory transports only. Parameters must
    /// satisfy the installed schema and cannot contain `_meta`; the framework
    /// supplies the immutable method, metadata key and exact originating ID.
    /// Cancellation, request completion or missing bilateral negotiation closes
    /// this capability. Emission uses the transport's bounded output queue;
    /// success acknowledges submission, never peer delivery or a replay promise.
    pub fn notify<Notification: Serialize>(&self, parameters: &Notification) -> McpResult<()> {
        ensure_live(self.context)?;
        if self.descriptor.request_notification.is_none() {
            return Err(McpError::invalid_request(
                "This extension has no request notification declaration",
            ));
        }
        let value = encode_value(parameters, MAX_STDIO_EXTENSION_NOTIFICATION_PARAMS_BYTES)
            .map_err(|_| McpError::invalid_params("Extension notification exceeds its byte budget"))?;
        self.context.emit_request_extension_notification(value)
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

/// A borrowed notification invocation without runtime or credential authority.
///
/// The framework constructs it only after current-message proof admission,
/// transport authentication, the explicit operation policy, settings negotiation,
/// and parameter-schema validation. No request/discovery from an earlier
/// exchange can activate this context. It cannot be constructed or cloned by
/// application code, retained beyond the callback, or used to send a response.
///
/// ```compile_fail
/// use fastmcp_server::extensions::authoring::ExtensionNotificationContext;
/// fn raw_runtime(context: ExtensionNotificationContext<'_, ()>) {
///     let _ = context.cx();
/// }
/// ```
///
/// ```compile_fail
/// use fastmcp_server::extensions::authoring::ExtensionNotificationContext;
/// fn credentials(context: ExtensionNotificationContext<'_, ()>) {
///     let _ = context.auth();
/// }
/// ```
pub struct ExtensionNotificationContext<'a, Settings> {
    context: &'a McpContext,
    descriptor: &'a ExtensionDescriptor,
    notification: &'a ExtensionNotification,
    settings: &'a Settings,
}

impl<Settings> ExtensionNotificationContext<'_, Settings> {
    /// Frozen declaration admitted for this invocation.
    #[must_use]
    pub const fn descriptor(&self) -> &ExtensionDescriptor {
        self.descriptor
    }

    /// Typed settings resolved from this notification's own activation proof.
    #[must_use]
    pub const fn settings(&self) -> &Settings {
        self.settings
    }

    /// Exact admitted notification method.
    #[must_use]
    pub fn method(&self) -> &str {
        self.notification.name()
    }

    /// Immutable schema, direction, and activation-proof metadata.
    #[must_use]
    pub const fn notification_descriptor(&self) -> &ExtensionNotification {
        self.notification
    }

    /// Checks cancellation/deadline and charges the ordinary request checkpoint.
    pub fn checkpoint(&self) -> McpResult<()> {
        self.context
            .checkpoint()
            .map_err(|_| McpError::request_cancelled())
    }

    /// Whether this notification's request lifetime is no longer live.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.context.is_cancelled()
    }

    /// Whether the request's own deadline has elapsed.
    #[must_use]
    pub fn deadline_expired(&self) -> bool {
        self.context.deadline_expired()
    }

    /// Remaining monotonic lifetime; this cannot extend the request deadline.
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

/// An asynchronous notification callback polled on the caller-owned runtime.
///
/// Completion produces no JSON-RPC result. HTTP acknowledges only after this
/// callback and its request lifetime have settled. Modern stream transports
/// send no JSON-RPC response, including when the callback fails. The callback
/// receives no write or detached-task capability.
pub trait ExtensionNotificationHandler<Notification, Settings>: Send + Sync {
    /// Executes one admitted notification using the sealed borrowed context.
    fn handle<'a>(
        &'a self,
        context: ExtensionNotificationContext<'a, Settings>,
        notification: Notification,
    ) -> BoxFuture<'a, McpResult<()>>;
}

impl<Notification, Settings, Handler> ExtensionNotificationHandler<Notification, Settings>
    for Handler
where
    Handler: for<'a> Fn(
            ExtensionNotificationContext<'a, Settings>,
            Notification,
        ) -> BoxFuture<'a, McpResult<()>>
        + Send
        + Sync,
{
    fn handle<'a>(
        &'a self,
        context: ExtensionNotificationContext<'a, Settings>,
        notification: Notification,
    ) -> BoxFuture<'a, McpResult<()>> {
        self(context, notification)
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

struct PendingNotification {
    parameter_digest: [u8; 32],
    authorize: Box<NotificationAuthorizer>,
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
    pending_notification: Option<PendingNotification>,
    request_notification_schema: Option<CompiledSchema>,
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
                notification: None,
                request_notification: None,
            },
            server_settings,
            resolve,
            client_schema,
            server_schema,
            effective_schema,
            schema_bytes,
            schema_identities,
            pending: Vec::new(),
            pending_notification: None,
            request_notification_schema: None,
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
        if self.descriptor.methods.is_empty() && self.descriptor.notification.is_none() {
            return Err(McpError::invalid_params(
                "extension authoring requires a request or notification method",
            ));
        }
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
            method: self.descriptor.methods.first().map(ExtensionMethod::protocol_method),
            notification: self
                .descriptor
                .notification
                .as_ref()
                .map(ExtensionNotification::protocol_notification)
                .or_else(|| self.descriptor.request_notification.as_ref().map(|notification| {
                    ExtensionNotificationDescriptor {
                        name: notification.name.clone(),
                        direction: ExtensionDirection::ServerToClient,
                        activation_proof: None,
                    }
                })),
            result_discriminator: None,
            routing_headers: Vec::new(),
            stdio_correlation: self.descriptor.request_notification.as_ref().map(|notification| {
                StdioCorrelationDescriptor {
                    metadata_key: notification.correlation_metadata_key.clone(),
                    methods: vec![notification.name.clone()],
                    direction: ExtensionDirection::ServerToClient,
                    codec: StdioCorrelationCodec::RequestId,
                }
            }),
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
        if let Some(pending) = self.pending_notification {
            let notification = descriptor.notification.as_ref().ok_or_else(|| {
                McpError::internal_error("typed notification descriptor is unavailable")
            })?;
            handlers
                .register_notification_handler(
                    descriptor.id.clone(),
                    notification.name.clone(),
                    RegisteredNotificationHandler {
                        authorize: pending.authorize,
                        handler: (pending.factory)(Arc::clone(&descriptor)),
                    },
                )
                .map_err(|_| {
                    McpError::invalid_params("extension notification registration was rejected")
                })?;
        }
        if let Some(schema) = self.request_notification_schema {
            handlers.register_request_notification_schema(descriptor.id.clone(), schema.admitted)?;
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
        if self.pending.len() + usize::from(self.descriptor.notification.is_some()
            || self.descriptor.request_notification.is_some())
            >= MAX_AUTHORING_METHODS
        {
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
            || self
                .descriptor
                .notification
                .as_ref()
                .is_some_and(|entry| entry.name == method)
            || self.descriptor.request_notification.as_ref()
                .is_some_and(|entry| entry.name == method)
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

    fn prepare_notification<Notification: JsonSchemaType>(
        &self,
        method: String,
        parameter_schema_id: String,
        activation_metadata_key: String,
    ) -> McpResult<(ExtensionNotification, CompiledSchema, usize)> {
        if self.descriptor.notification.is_some() || self.descriptor.request_notification.is_some() {
            return Err(McpError::invalid_params(
                "extension authoring supports one notification per descriptor",
            ));
        }
        if self.pending.len() >= MAX_AUTHORING_METHODS {
            return Err(McpError::invalid_params("extension method budget exceeded"));
        }
        let method = checked_identity(method)?;
        let activation_metadata_key = checked_identity(activation_metadata_key)?;
        let prefix = self
            .descriptor
            .id
            .as_str()
            .split_once('/')
            .map(|(prefix, _)| prefix);
        for name in [&method, &activation_metadata_key] {
            if name.split_once('/').map(|(prefix, _)| prefix) != prefix || name.ends_with('/') {
                return Err(McpError::invalid_params(
                    "extension notification and activation key must use their owning namespace",
                ));
            }
        }
        if self
            .descriptor
            .methods
            .iter()
            .any(|entry| entry.name == method)
        {
            return Err(McpError::invalid_params("duplicate extension method name"));
        }
        let parameter_schema_id = checked_identity(parameter_schema_id)?;
        let parameter_schema = compile_schema::<Notification>()?;
        if self
            .schema_identities
            .get(&parameter_schema_id)
            .is_some_and(|existing| existing != &parameter_schema.digest)
        {
            return Err(McpError::invalid_params(
                "extension schema identity names conflicting schemas",
            ));
        }
        let total = add_schema_bytes(self.schema_bytes, parameter_schema.bytes)?;
        Ok((
            ExtensionNotification {
                name: method,
                parameter_schema_id,
                activation_metadata_key,
            },
            parameter_schema,
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
        let notification = self
            .descriptor
            .notification
            .as_ref()
            .zip(self.pending_notification.as_ref())
            .map(|(notification, pending)| {
                (
                    notification.name.as_str(),
                    "client-to-server",
                    notification.parameter_schema_id.as_str(),
                    "metadata",
                    notification.activation_metadata_key.as_str(),
                    "reject-one-sided",
                    pending.parameter_digest,
                )
            });
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
            notification,
        );
        let bytes = if let Some((notification, schema)) = self.descriptor.request_notification
            .as_ref().zip(self.request_notification_schema.as_ref())
        {
            encode_bytes(&(
                subject,
                "request-notification-v1",
                notification.name.as_str(),
                notification.parameter_schema_id.as_str(),
                notification.correlation_metadata_key.as_str(),
                "request-id",
                schema.digest,
            ), MAX_EXTENSION_REGISTRY_CANONICAL_BYTES)?
        } else {
            // Preserve the existing fingerprint for descriptors without this capability.
            encode_bytes(&subject, MAX_EXTENSION_REGISTRY_CANONICAL_BYTES)?
        };
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
    /// Declares one typed server notification emitted during this extension's requests.
    ///
    /// Install at least one request handler and call [`ExtensionContext::notify`]
    /// from that handler. Modern stdio and memory dispatch retain the admitted
    /// bilateral settings and exact request ID; callers cannot supply a method,
    /// correlation key or destination. Parameters must be an object satisfying
    /// `Notification`'s schema and must not contain `_meta`.
    ///
    /// The registry currently supports one notification per extension, so this
    /// declaration is mutually exclusive with a client-to-server notification.
    /// HTTP, WebSocket and subscription publication are not enabled by it.
    pub fn typed_request_notification<Notification>(
        mut self,
        method: impl Into<String>,
        parameter_schema_id: impl Into<String>,
        correlation_metadata_key: impl Into<String>,
    ) -> McpResult<Self>
    where
        Notification: Serialize + JsonSchemaType,
    {
        let (notification, schema, total) = self.prepare_notification::<Notification>(
            method.into(),
            parameter_schema_id.into(),
            correlation_metadata_key.into(),
        )?;
        retain_schema_identity(
            &mut self.schema_identities,
            &notification.parameter_schema_id,
            schema.digest,
        )?;
        self.descriptor.request_notification = Some(ExtensionRequestNotification {
            name: notification.name,
            parameter_schema_id: notification.parameter_schema_id,
            correlation_metadata_key: notification.activation_metadata_key,
        });
        self.request_notification_schema = Some(schema);
        self.schema_bytes = total;
        Ok(self)
    }

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

    /// Registers one typed asynchronous client-to-server notification.
    ///
    /// Every message supplies this extension's typed client settings in the
    /// exact `params._meta[activation_metadata_key]` field. The framework admits
    /// that proof, authenticates the transport, validates application parameters,
    /// and runs the explicit `authorize` policy before settings negotiation and
    /// handler dispatch. The policy receives only typed application parameters;
    /// endpoint identity/scope rules remain part of transport authorization.
    /// There is no implicit public allow policy and no prior-request activation.
    ///
    /// The handler receives a sealed notification context and returns `()`.
    /// HTTP emits an empty 202 only after scoped completion; modern stdio,
    /// memory, and WebSocket transports complete within the owning scope
    /// without emitting a JSON-RPC response. Each message must supply its own
    /// activation proof. This registration does not enable legacy ingress.
    pub fn typed_notification<Notification, Handler, Authorize>(
        mut self,
        method: impl Into<String>,
        parameter_schema_id: impl Into<String>,
        activation_metadata_key: impl Into<String>,
        authorize: Authorize,
        handler: Handler,
    ) -> McpResult<Self>
    where
        Notification: DeserializeOwned + JsonSchemaType + Send + 'static,
        Handler: ExtensionNotificationHandler<Notification, Settings> + 'static,
        Authorize: Fn(&Notification) -> McpResult<()> + Send + Sync + 'static,
    {
        let (notification, parameter_schema, total) = self.prepare_notification::<Notification>(
            method.into(),
            parameter_schema_id.into(),
            activation_metadata_key.into(),
        )?;
        let policy_schema = Arc::clone(&parameter_schema.admitted);
        let effective_schema = Arc::clone(&self.effective_schema.admitted);
        retain_schema_identity(
            &mut self.schema_identities,
            &notification.parameter_schema_id,
            parameter_schema.digest,
        )?;
        self.pending_notification = Some(PendingNotification {
            parameter_digest: parameter_schema.digest,
            authorize: notification_authorizer::<Notification, Authorize>(policy_schema, authorize),
            factory: Box::new(move |descriptor| {
                Box::new(TypedAsyncNotification::<Notification, Settings, Handler> {
                    binding: NotificationBinding {
                        descriptor,
                        effective_schema,
                    },
                    handler,
                    marker: PhantomData,
                })
            }),
        });
        self.descriptor.notification = Some(notification);
        self.schema_bytes = total;
        Ok(self)
    }

    /// Registers a synchronous notification with the same admission and policy.
    ///
    /// The callback still runs inside the transport-owned asynchronous
    /// lifetime. No response value, runtime bridge, or detached worker is added.
    pub fn typed_notification_sync<Notification, Handler, Authorize>(
        mut self,
        method: impl Into<String>,
        parameter_schema_id: impl Into<String>,
        activation_metadata_key: impl Into<String>,
        authorize: Authorize,
        handler: Handler,
    ) -> McpResult<Self>
    where
        Notification: DeserializeOwned + JsonSchemaType + Send + 'static,
        Handler: for<'a> Fn(ExtensionNotificationContext<'a, Settings>, Notification) -> McpResult<()>
            + Send
            + Sync
            + 'static,
        Authorize: Fn(&Notification) -> McpResult<()> + Send + Sync + 'static,
    {
        let (notification, parameter_schema, total) = self.prepare_notification::<Notification>(
            method.into(),
            parameter_schema_id.into(),
            activation_metadata_key.into(),
        )?;
        let policy_schema = Arc::clone(&parameter_schema.admitted);
        let effective_schema = Arc::clone(&self.effective_schema.admitted);
        retain_schema_identity(
            &mut self.schema_identities,
            &notification.parameter_schema_id,
            parameter_schema.digest,
        )?;
        self.pending_notification = Some(PendingNotification {
            parameter_digest: parameter_schema.digest,
            authorize: notification_authorizer::<Notification, Authorize>(policy_schema, authorize),
            factory: Box::new(move |descriptor| {
                Box::new(TypedSyncNotification::<Notification, Settings, Handler> {
                    binding: NotificationBinding {
                        descriptor,
                        effective_schema,
                    },
                    handler,
                    marker: PhantomData,
                })
            }),
        });
        self.descriptor.notification = Some(notification);
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
        let request = decode_parameters(context, &self.parameter_schema, parameters)?;
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

fn decode_parameters<Parameters: DeserializeOwned>(
    context: &McpContext,
    schema: &AdmittedSchema,
    parameters: Value,
) -> McpResult<Parameters> {
    ensure_live(context)?;
    let Value::Object(mut parameters) = parameters else {
        return Err(McpError::invalid_params(
            "extension request parameters must be an object",
        ));
    };
    parameters.remove("_meta");
    let parameters = Value::Object(parameters);
    schema.validate(&parameters).map_err(|_| {
        McpError::invalid_params("extension request does not satisfy its parameter schema")
    })?;
    let typed = serde_json::from_value(parameters)
        .map_err(|_| McpError::invalid_params("extension request typed decoding failed"))?;
    ensure_live(context)?;
    Ok(typed)
}

fn notification_authorizer<Notification, Authorize>(
    schema: Arc<AdmittedSchema>,
    authorize: Authorize,
) -> Box<NotificationAuthorizer>
where
    Notification: DeserializeOwned + Send + 'static,
    Authorize: Fn(&Notification) -> McpResult<()> + Send + Sync + 'static,
{
    Box::new(
        move |context, parameters| -> McpResult<AuthorizedNotificationPayload> {
            let notification = decode_parameters(context, &schema, parameters.clone())?;
            authorize(&notification)?;
            ensure_live(context)?;
            Ok(Some(Box::new(notification)))
        },
    )
}

struct NotificationBinding {
    descriptor: Arc<ExtensionDescriptor>,
    effective_schema: Arc<AdmittedSchema>,
}

impl NotificationBinding {
    fn prepare<Notification: Send + 'static, Settings: DeserializeOwned>(
        &self,
        context: &McpContext,
        negotiated: &NegotiatedExtension,
        authorized: AuthorizedNotificationPayload,
    ) -> McpResult<(Notification, Settings)> {
        ensure_live(context)?;
        if negotiated.id() != &self.descriptor.id {
            return Err(McpError::invalid_request(
                "extension notification has no matching admitted descriptor",
            ));
        }
        let notification = authorized
            .and_then(|value| value.downcast::<Notification>().ok())
            .ok_or_else(|| {
                McpError::invalid_request(
                    "extension notification requires its authorized typed payload",
                )
            })?;
        let settings = decode_settings(
            negotiated.effective_settings().settings(),
            &self.effective_schema,
        )?;
        ensure_live(context)?;
        Ok((*notification, settings))
    }

    fn context<'a, Settings>(
        &'a self,
        context: &'a McpContext,
        settings: &'a Settings,
    ) -> McpResult<ExtensionNotificationContext<'a, Settings>> {
        let notification = self.descriptor.notification.as_ref().ok_or_else(|| {
            McpError::internal_error("typed notification descriptor is unavailable")
        })?;
        Ok(ExtensionNotificationContext {
            context,
            descriptor: &self.descriptor,
            notification,
            settings,
        })
    }
}

struct TypedAsyncNotification<Notification, Settings, Handler> {
    binding: NotificationBinding,
    handler: Handler,
    marker: PhantomData<fn(Notification, Settings)>,
}

impl<Notification, Settings, Handler> ErasedExtensionHandler
    for TypedAsyncNotification<Notification, Settings, Handler>
where
    Notification: DeserializeOwned + Send + 'static,
    Settings: DeserializeOwned + Send + Sync + 'static,
    Handler: ExtensionNotificationHandler<Notification, Settings>,
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
            let (notification, settings) = self.binding.prepare(context, negotiated, authorized)?;
            self.handler
                .handle(self.binding.context(context, &settings)?, notification)
                .await?;
            ensure_live(context)?;
            Ok(Value::Null)
        })
    }
}

struct TypedSyncNotification<Notification, Settings, Handler> {
    binding: NotificationBinding,
    handler: Handler,
    marker: PhantomData<fn(Notification, Settings)>,
}

impl<Notification, Settings, Handler> ErasedExtensionHandler
    for TypedSyncNotification<Notification, Settings, Handler>
where
    Notification: DeserializeOwned + Send + 'static,
    Settings: DeserializeOwned,
    Handler: for<'a> Fn(ExtensionNotificationContext<'a, Settings>, Notification) -> McpResult<()>
        + Send
        + Sync,
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
            let (notification, settings) = self.binding.prepare(context, negotiated, authorized)?;
            (self.handler)(self.binding.context(context, &settings)?, notification)?;
            ensure_live(context)?;
            Ok(Value::Null)
        })
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

    const NOTIFICATION: &str = "dev.example/changed";
    const ACTIVATION: &str = "dev.example/activation";

    fn notification_frame(value: i64, scale: u32) -> JsonRpcRequest {
        JsonRpcRequest::notification(
            NOTIFICATION,
            Some(json!({"value": value, "_meta": {(ACTIVATION): {"scale": scale}}})),
        )
    }

    fn notification_registration(
        calls: Arc<AtomicUsize>,
        authorized: Arc<AtomicUsize>,
    ) -> ExtensionRegistration {
        builder()
            .typed_notification_sync::<Input, _, _>(
                NOTIFICATION,
                "notification-input-v1",
                ACTIVATION,
                move |input| {
                    authorized.fetch_add(1, Ordering::SeqCst);
                    if input.value == 13 {
                        return Err(McpError::new(
                            McpErrorCode::ResourceForbidden,
                            "operation denied",
                        ));
                    }
                    Ok(())
                },
                move |context, input| {
                    context.checkpoint()?;
                    assert_eq!(context.descriptor().id(), ID);
                    assert_eq!(context.method(), NOTIFICATION);
                    assert_eq!(
                        context.notification_descriptor().activation_metadata_key(),
                        ACTIVATION
                    );
                    assert_eq!(
                        context.notification_descriptor().direction(),
                        ExtensionDirection::ClientToServer
                    );
                    assert_eq!(
                        context.notification_descriptor().parameter_schema_id(),
                        "notification-input-v1"
                    );
                    assert!(!context.is_cancelled());
                    assert!(!context.deadline_expired());
                    calls.fetch_add(
                        usize::try_from(input.value).expect("schema bounds nonnegative input")
                            * usize::try_from(context.settings().scale).expect("bounded scale"),
                        Ordering::SeqCst,
                    );
                    Ok(())
                },
            )
            .expect("typed notification installs")
            .build()
            .expect("notification-only registration seals")
    }

    impl Harness {
        async fn notify(&mut self, notification: &JsonRpcRequest) -> McpResult<()> {
            let settings = self
                .handlers
                .descriptor_registry()
                .notification_activation_settings(
                    &self.id,
                    &notification.method,
                    notification.params.as_ref().unwrap_or(&Value::Null),
                )
                .map_err(|_| McpError::invalid_params("invalid notification activation"))?;
            let context = self.context.clone();
            let authorized =
                self.handlers
                    .authorize_notification(&context, &self.id, notification)?;
            let negotiated = self
                .negotiate(Value::Object(settings.as_object().clone()))
                .map_err(|_| McpError::invalid_params("incompatible notification settings"))?;
            self.handlers
                .invoke_notification_async(
                    &context,
                    &negotiated,
                    &self.id,
                    notification,
                    authorized,
                )
                .await
        }
    }

    #[test]
    fn typed_notification_authoring_admits_current_proof_and_settings() {
        let calls = Arc::new(AtomicUsize::new(0));
        let authorized = Arc::new(AtomicUsize::new(0));
        let mut harness = Harness::new(notification_registration(
            Arc::clone(&calls),
            Arc::clone(&authorized),
        ));
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        harness.context = McpContext::new(
            runtime.request_cx_with_budget(asupersync::Budget::default()),
            41,
        );
        runtime.block_on(async {
            harness
                .notify(&notification_frame(7, 3))
                .await
                .expect("first proof admits");
            harness
                .notify(&notification_frame(7, 2))
                .await
                .expect("fresh settings are used");
        });
        assert_eq!(calls.load(Ordering::SeqCst), 35);
        assert_eq!(authorized.load(Ordering::SeqCst), 2);
        let notification = harness
            .handlers
            .descriptor_registry()
            .notification_descriptor(&harness.id, NOTIFICATION)
            .unwrap();
        assert_eq!(notification.direction, ExtensionDirection::ClientToServer);
        assert!(
            harness
                .handlers
                .descriptor_registry()
                .method_descriptor(&harness.id, NOTIFICATION)
                .is_none()
        );
        let negotiated = harness.negotiate(json!({"scale": 2})).unwrap();
        assert!(
            negotiated
                .admit_notification(
                    harness.handlers.descriptor_registry(),
                    ProtocolEra::Legacy2024,
                    &harness.id,
                    NOTIFICATION,
                    ExtensionDirection::ClientToServer,
                )
                .is_err()
        );
        assert!(
            negotiated
                .admit_notification(
                    harness.handlers.descriptor_registry(),
                    ProtocolEra::Modern2026,
                    &harness.id,
                    NOTIFICATION,
                    ExtensionDirection::ServerToClient,
                )
                .is_err()
        );
    }

    #[test]
    fn typed_notification_authoring_rejects_invalid_activation_before_effects() {
        let calls = Arc::new(AtomicUsize::new(0));
        let authorized = Arc::new(AtomicUsize::new(0));
        let mut harness = Harness::new(notification_registration(
            Arc::clone(&calls),
            Arc::clone(&authorized),
        ));
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        harness.context = McpContext::new(
            runtime.request_cx_with_budget(asupersync::Budget::default()),
            41,
        );
        runtime.block_on(async {
            harness.notify(&notification_frame(1, 1)).await.unwrap();
            let baseline = notification_frame(7, 2);
            let mut missing = baseline.clone();
            missing.params.as_mut().unwrap()["_meta"]
                .as_object_mut()
                .unwrap()
                .remove(ACTIVATION);
            let mut request_shaped = baseline.clone();
            request_shaped.id = Some(42_i64.into());
            let mut wrong_method = baseline.clone();
            wrong_method.method = "dev.example/unregistered".to_owned();
            let mut bad_type = baseline.clone();
            bad_type.params.as_mut().unwrap()["value"] = json!("payload-canary");
            let mut extra = baseline.clone();
            extra.params.as_mut().unwrap()["unknown"] = json!(true);
            let mut wrong_proof = baseline.clone();
            wrong_proof.params.as_mut().unwrap()["_meta"][ACTIVATION] = json!({"scale":"bad"});
            let mut oversized = baseline.clone();
            oversized.params.as_mut().unwrap()["_meta"][ACTIVATION]["padding"] =
                json!("x".repeat(MAX_AUTHORING_SETTINGS_BYTES));
            for rejected in [
                missing,
                request_shaped,
                wrong_method,
                bad_type,
                extra,
                wrong_proof,
                oversized,
                notification_frame(101, 2),
                notification_frame(7, 5),
                notification_frame(13, 2),
            ] {
                let before = calls.load(Ordering::SeqCst);
                assert!(harness.notify(&rejected).await.is_err(), "{rejected:?}");
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    before,
                    "refusal invokes no handler"
                );
                harness
                    .notify(&notification_frame(1, 1))
                    .await
                    .expect("same owner remains usable");
            }
            let before = calls.load(Ordering::SeqCst);
            assert!(harness.context.request_cancellation().cancel());
            assert!(harness.notify(&baseline).await.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), before);
        });
    }

    fn inert_notification(builder: Builder, key: &str) -> McpResult<Builder> {
        builder.typed_notification_sync::<Input, _, _>(
            NOTIFICATION,
            "input-v1",
            key,
            |_| Ok(()),
            |context, _| context.checkpoint(),
        )
    }

    #[test]
    fn typed_notification_authoring_bounds_and_binds_contract() {
        let baseline = receipt(
            inert_notification(builder(), ACTIVATION)
                .unwrap()
                .build()
                .unwrap(),
        );
        assert_eq!(
            baseline,
            receipt(
                inert_notification(builder(), ACTIVATION)
                    .unwrap()
                    .build()
                    .unwrap()
            )
        );
        assert_ne!(
            baseline,
            receipt(
                inert_notification(builder(), "dev.example/another-proof")
                    .unwrap()
                    .build()
                    .unwrap()
            )
        );
        assert_ne!(
            baseline,
            receipt(
                inert_notification(builder_version(2), ACTIVATION)
                    .unwrap()
                    .build()
                    .unwrap()
            )
        );
        assert!(inert_notification(builder(), "foreign.example/activation").is_err());
        assert!(
            inert_notification(
                inert_notification(builder(), ACTIVATION).unwrap(),
                ACTIVATION
            )
            .is_err()
        );

        let different_schema = builder()
            .typed_notification_sync::<TighterInput, _, _>(
                NOTIFICATION,
                "input-v1",
                ACTIVATION,
                |_| Ok(()),
                |context, _| context.checkpoint(),
            )
            .unwrap()
            .build()
            .unwrap();
        assert_ne!(
            baseline,
            receipt(different_schema),
            "same schema name cannot conceal new bounds"
        );

        for request_count in [MAX_AUTHORING_METHODS - 1, MAX_AUTHORING_METHODS] {
            let mut candidate = builder();
            for index in 0..request_count {
                candidate = candidate
                    .typed_request_sync::<Input, Output, _>(
                        format!("dev.example/request-{index}"),
                        "input-v1",
                        "output-v1",
                        multiply,
                    )
                    .unwrap();
            }
            assert_eq!(
                inert_notification(candidate, ACTIVATION).is_ok(),
                request_count < MAX_AUTHORING_METHODS
            );
        }
        let mut candidate = inert_notification(builder(), ACTIVATION).unwrap();
        for index in 0..MAX_AUTHORING_METHODS - 1 {
            candidate = candidate
                .typed_request_sync::<Input, Output, _>(
                    format!("dev.example/request-{index}"),
                    "input-v1",
                    "output-v1",
                    multiply,
                )
                .unwrap();
        }
        assert!(
            candidate
                .typed_request_sync::<Input, Output, _>(
                    "dev.example/overflow",
                    "input-v1",
                    "output-v1",
                    multiply,
                )
                .is_err(),
            "notification also charges the shared entry budget"
        );
    }

    #[test]
    fn typed_notification_authoring_preserves_request_registration() {
        let combined = inert_notification(builder(), ACTIVATION)
            .unwrap()
            .typed_request_sync::<Input, Output, _>(METHOD, "input-v1", "output-v1", multiply)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(combined.descriptor().methods().len(), 1);
        assert_eq!(
            combined.descriptor().notification().unwrap().name(),
            NOTIFICATION
        );
        let mut harness = Harness::new(combined);
        assert_eq!(
            harness.invoke(json!({"value": 3}), 2).unwrap(),
            json!({"product": 6})
        );
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime
            .block_on(harness.notify(&notification_frame(3, 2)))
            .unwrap();
        let wrong_envelope =
            JsonRpcRequest::new(NOTIFICATION, notification_frame(3, 2).params, 41_i64);
        let negotiated = harness.negotiate(json!({"scale":2})).unwrap();
        assert!(
            harness
                .handlers
                .invoke(
                    &harness.context,
                    &negotiated,
                    ProtocolEra::Modern2026,
                    &harness.id,
                    &wrong_envelope
                )
                .is_err()
        );
        assert!(
            inert_notification(builder(), ACTIVATION)
                .unwrap()
                .typed_request_sync::<Input, Output, _>(
                    NOTIFICATION,
                    "input-v1",
                    "output-v1",
                    multiply,
                )
                .is_err(),
            "request and notification names cannot alias"
        );
    }

    #[test]
    fn typed_notification_authoring_authorizes_exact_decoded_value_once() {
        static DECODED: AtomicUsize = AtomicUsize::new(0);

        struct StatefulInput {
            value: i64,
        }

        impl<'de> Deserialize<'de> for StatefulInput {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let input = Input::deserialize(deserializer)?;
                let prior = DECODED.fetch_add(1, Ordering::SeqCst);
                Ok(Self {
                    value: input.value + i64::try_from(prior).expect("bounded test decoding count"),
                })
            }
        }

        impl JsonSchemaType for StatefulInput {
            fn schema_body(generator: &mut SchemaGenerator) -> Value {
                Input::schema_body(generator)
            }
        }

        DECODED.store(0, Ordering::SeqCst);
        let policy_calls = Arc::new(AtomicUsize::new(0));
        let execution_calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(AtomicUsize::new(0));
        let policy = Arc::clone(&policy_calls);
        let executions = Arc::clone(&execution_calls);
        let effect = Arc::clone(&observed);
        let registration = builder()
            .typed_notification_sync::<StatefulInput, _, _>(
                NOTIFICATION,
                "stateful-input-v1",
                ACTIVATION,
                move |input| {
                    policy.fetch_add(1, Ordering::SeqCst);
                    if input.value != 7 {
                        return Err(McpError::new(
                            McpErrorCode::ResourceForbidden,
                            "typed operation denied",
                        ));
                    }
                    Ok(())
                },
                move |context, input| {
                    context.checkpoint()?;
                    executions.fetch_add(1, Ordering::SeqCst);
                    effect.store(usize::try_from(input.value).unwrap(), Ordering::SeqCst);
                    Ok(())
                },
            )
            .unwrap()
            .build()
            .unwrap();
        let mut harness = Harness::new(registration);
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        harness.context = McpContext::new(
            runtime.request_cx_with_budget(asupersync::Budget::default()),
            41,
        );
        let frame = notification_frame(7, 2);
        runtime.block_on(harness.notify(&frame)).unwrap();
        assert_eq!(
            DECODED.load(Ordering::SeqCst),
            1,
            "the authorized value is never deserialized again"
        );
        assert_eq!(
            policy_calls.load(Ordering::SeqCst),
            1,
            "operation policy is not repeated"
        );
        assert_eq!(execution_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            observed.load(Ordering::SeqCst),
            7,
            "execution receives exactly the approved instance"
        );

        // Even identical bytes on another invocation cannot reuse custody.
        DECODED.store(0, Ordering::SeqCst);
        let negotiated = harness.negotiate(json!({"scale":2})).unwrap();
        let authorized = harness
            .handlers
            .authorize_notification(&harness.context, &harness.id, &frame)
            .unwrap();
        let cloned_frame = frame.clone();
        assert!(
            runtime
                .block_on(harness.handlers.invoke_notification_async(
                    &harness.context,
                    &negotiated,
                    &harness.id,
                    &cloned_frame,
                    authorized,
                ))
                .is_err()
        );
        assert_eq!(observed.load(Ordering::SeqCst), 7);
        assert_eq!(DECODED.load(Ordering::SeqCst), 1);
        assert_eq!(
            execution_calls.load(Ordering::SeqCst),
            1,
            "a cloned invocation cannot consume another invocation's authorization"
        );
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
