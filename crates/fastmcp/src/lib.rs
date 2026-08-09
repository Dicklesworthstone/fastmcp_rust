//! FastMCP: cancel-aware MCP framework for Rust.
//!
//! FastMCP is a Rust implementation of the Model Context Protocol (MCP),
//! providing explicit cancellation, budget, server, and client surfaces.
//!
//! # Features
//!
//! - **Cancellation-aware**: Built on asupersync contexts and checkpoints
//! - **Simple**: Familiar API inspired by FastMCP (Python)
//! - **MCP tools/resources/prompts**: ergonomic macros and handler APIs
//!
//! # Protocol status (FND-01)
//!
//! **MCP 2026-07-28 support is under implementation and remains unverified.**  
//! **Aggregate MCP 2026-07-28 support is not claimed by FND-01.**  
//! The primary public surface is [`modern`], which names the exact
//! `2026-07-28` vocabulary. Exact `2024-11-05` access is explicit through
//! [`legacy_2024`]. The root-level [`PROTOCOL_VERSION`] remains available for
//! existing exact-2024 consumers while they move to that module; it is not the
//! default selected by [`auto::client_builder`].
//! Toolchain: pinned `nightly-2026-07-11` / rustc 1.99.0-nightly
//! (`rust-version = "1.99"`). Do not assume JWT/OIDC production readiness,
//! Redis Tasks, Apps media rendering, or aggregate release-gate evidence from
//! this façade alone.
//! Release publication remains quarantined; these crate docs do not supply
//! publication authority or provider-side release-safety evidence.
//!
//! # Quick Start
//!
//! ```ignore
//! use fastmcp_rust::prelude::*;
//!
//! #[tool]
//! async fn greet(ctx: &McpContext, name: String) -> McpResult<String> {
//!     ctx.checkpoint()?;
//!     Ok(format!("Hello, {name}!"))
//! }
//!
//! fn main() {
//!     Server::new("my-server", "1.0.0")
//!         .tool(Greet)
//!         .build()
//!         .run_stdio();
//! }
//! ```
//!
//! # Architecture
//!
//! FastMCP is organized into focused crates:
//!
//! - `fastmcp-core`: Core types and asupersync integration
//! - `fastmcp-protocol`: MCP protocol types and JSON-RPC
//! - `fastmcp-transport`: Transport implementations (stdio, SSE)
//! - `fastmcp-server`: Server implementation
//! - `fastmcp-client`: Client implementation
//! - `fastmcp-derive`: Procedural macros (#[tool], #[resource], #[prompt])
//!
//! # Role in the System
//!
//! This crate is the **public façade** of the workspace. It is published as
//! `fastmcp-rust` on crates.io and imported as `fastmcp_rust`. It re-exports the
//! pieces you need for day-to-day server and client development so that most
//! applications can depend on a single crate and write
//! `use fastmcp_rust::prelude::*;`. New code should name its policy explicitly
//! through [`modern`], [`auto`], or [`legacy_2024`] rather than inferring an
//! era from the historical root re-exports.
//!
//! Concretely, `fastmcp_rust` glues together:
//! - **Core runtime + context** from `fastmcp-core`
//! - **Protocol models** from `fastmcp-protocol`
//! - **Transports** from `fastmcp-transport`
//! - **Server/client** APIs from `fastmcp-server` and `fastmcp-client`
//! - **Macros** from `fastmcp-derive`
//!
//! # When to Use `fastmcp_rust`
//!
//! - **You are building an MCP server or client** and want the canonical,
//!   batteries-included API surface.
//! - **You want a single dependency** rather than wiring the sub-crates
//!   yourself.
//!
//! Use the sub-crates directly only when you need a narrower dependency surface
//! (for example, a custom transport that depends on `fastmcp-transport` but not
//! the full server stack).
//!
//! # Asupersync Integration
//!
//! FastMCP uses [asupersync](https://github.com/Dicklesworthstone/asupersync) for:
//!
//! - **Context propagation**: Requests carry an asupersync capability context
//! - **Cooperative cancellation**: Explicit checkpoints surface cancellation
//! - **Request budgets**: Deadline, poll, and cost limits travel with the context
//! - **Deterministic test support**: Asupersync's lab runtime is available to tests

#![forbid(unsafe_code)]
#![allow(dead_code)]

// `proc-macro-crate` reports `FoundCrate::Itself` for every target belonging
// to this package, including examples and integration tests. Keep one
// canonical absolute self-name so macro expansion is correct in all of them.
extern crate self as fastmcp_rust;

/// Implementation paths used by FastMCP's procedural macros.
///
/// This is public because macro expansions live in downstream crates. It is
/// deliberately hidden from the supported application API: users should use
/// the facade re-exports above rather than couple themselves to these names.
#[doc(hidden)]
pub mod __private {
    pub use fastmcp_core as core;
    pub use fastmcp_protocol as protocol;
    pub use fastmcp_server as server;
    pub use serde_json;
}

/// Re-export the runtime package used by the facade's public `Cx` and lab
/// types. This keeps deterministic macro and handler tests on a facade-only
/// dependency path.
pub use asupersync;

/// Complete component namespaces for advanced consumers.
///
/// The root, [`modern`], and [`legacy_2024`] exports are the ergonomic API.
/// These namespaces retain every implemented public item without requiring an
/// application to name a FastMCP component crate directly.
pub use fastmcp_client as client;
pub use fastmcp_core as core;
pub use fastmcp_derive as derive;
pub use fastmcp_protocol as protocol;
pub use fastmcp_server as server;

/// JSON values and objects used by the protocol's schema-open and exact legacy
/// adapter surfaces. Re-exporting these keeps one-crate consumers from having
/// to name FastMCP's transitive serialization crate to implement an adapter.
pub use serde_json::{self, Map as JsonMap, Value as JsonValue, json};

// Re-export core types
pub use fastmcp_core::{
    AccessToken, AuthContext, Budget, CancelledError, ClientCapabilityInfo, Cx, ElicitationAction,
    ElicitationMode, ElicitationRequest, ElicitationResponse, ElicitationSender, IntoOutcome,
    LabConfig, LabRuntime, MAX_RESOURCE_READ_DEPTH, MAX_TOOL_CALL_DEPTH, McpContext,
    McpContextLeaseGuard, McpError, McpErrorCode, McpOutcome, McpRequestCancellation, McpResult,
    NoOpElicitationSender, NoOpNotificationSender, NoOpSamplingSender, Outcome, OutcomeExt,
    ProgressReporter, RegionId, ResourceContentItem, ResourceReadResult, ResourceReader, ResultExt,
    SamplingRequest, SamplingRequestMessage, SamplingResponse, SamplingRole, SamplingSender,
    SamplingStopReason, Scope, ServerCapabilityInfo, TaskId, ToolCallResult, ToolCaller,
    ToolContentItem, cancelled, err, ok,
};
pub use fastmcp_core::{
    DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS, DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND,
    DEFAULT_LOGICAL_EXCHANGE_MAX_ROUNDS, DEFAULT_LOGICAL_EXCHANGE_MAX_STATE_BYTES,
    DEFAULT_LOGICAL_EXCHANGE_MAX_WALL_CLOCK, DISABLED_PROMPTS_KEY, DISABLED_RESOURCES_KEY,
    DISABLED_TOOLS_KEY, HARD_LOGICAL_EXCHANGE_MAX_INPUTS,
    HARD_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND, HARD_LOGICAL_EXCHANGE_MAX_ROUNDS,
    HARD_LOGICAL_EXCHANGE_MAX_STATE_BYTES, HARD_LOGICAL_EXCHANGE_MAX_WALL_CLOCK,
    LogicalExchangeBudget, LogicalExchangeBudgetError, LogicalExchangeBudgetResource,
    MAX_ACCESS_SCHEME_BYTES, MAX_ACCESS_TOKEN_BYTES, ParseDurationError, ProtocolLimit,
    ProtocolLimits, ProtocolLimitsBuilder, ProtocolLimitsError, SessionState, block_on,
    parse_duration,
};
// The established root `NotificationSender` is the server router callback;
// expose the McpContext progress capability without changing that legacy name.
pub use fastmcp_core::NotificationSender as ContextNotificationSender;

// FND-01: sealed crypto + URI primitives live in core (no ambient sha2/hmac/getrandom edges).
pub use fastmcp_core::{
    ABSOLUTE_URI_HARD_MAX_BYTES, AbsoluteUri, AbsoluteUriComponent, AbsoluteUriError,
    AbsoluteUriScheme, AuthorityErrorKind, CANONICAL_HTTP_URL_POLICY, CANONICAL_URL_HARD_MAX_BYTES,
    CanonicalHttpUrl, CanonicalHttpUrlError, CanonicalResourceId, CanonicalResourceIdError,
    CanonicalResourceIdPolicy, CanonicalUrlPolicy, CryptoInputTooLongError,
    DEFAULT_ABSOLUTE_URI_MAX_BYTES, DEFAULT_CANONICAL_URL_MAX_BYTES, DefaultPortPolicy,
    DotSegmentPolicy, EPHEMERAL_KEY_MATERIAL_BYTES, EphemeralKeyMaterial, FragmentPolicy,
    HMAC_SHA256_KEY_BYTES, HMAC_SHA256_TAG_BYTES, HmacSha256Key, HmacSha256Tag,
    HmacVerificationError, IdnaPolicy, NONCE_DOMAIN_MATERIAL_BYTES, NonceDomainMaterial,
    PercentEncodingPolicy, QueryPolicy, RandomDrawError, ResourceEndpointPathPolicy,
    SECURITY_IDENTIFIER_BYTES, SHA256_DIGEST_BYTES, SchemeHostCasePolicy, SecurityIdentifier,
    Sha256Digest, SyntaxViolationPolicy, TrailingSlashPolicy, UriComponentState, UserinfoPolicy,
    WEBSOCKET_MASK_BYTES, WebSocketMask, draw_ephemeral_key_material, draw_hmac_sha256_key,
    draw_nonce_domain_material, draw_security_identifier, draw_websocket_mask, sha256_bounded,
};

// Module re-exports for namespaced access (`fastmcp_rust::crypto`, `fastmcp_rust::uri`).
pub use fastmcp_core::{crypto, uri};

// Re-export logging module
pub use fastmcp_core::logging;

// Re-export protocol types shared by both eras. Exact legacy initialization
// types live in `legacy_2024`; modern discovery types live in `modern`.
pub use fastmcp_protocol::{
    CallToolParams, CallToolResult, ClientCapabilities, ClientInfo, ClientIngressFailureScope,
    Content, CorrelationKey, GetPromptParams, GetPromptResult, JSONRPC_VERSION,
    JsonRpcAdmissionError, JsonRpcEndpointRole, JsonRpcError, JsonRpcMessage,
    JsonRpcMessageDirection, JsonRpcRequest, JsonRpcResponse, JsonRpcResponseAdmission,
    ListPromptsParams, ListPromptsResult, ListResourceTemplatesParams, ListResourceTemplatesResult,
    ListResourcesParams, ListResourcesResult, ListToolsParams, ListToolsResult, LogLevel,
    MAX_JSONRPC_STRING_ID_ENCODED_BYTES, MAX_RAW_JSON_AGGREGATE_NUMBER_BYTES,
    MAX_RAW_JSON_CONTAINER_ENTRIES, MAX_RAW_JSON_EXPONENT, MAX_RAW_JSON_NESTING_DEPTH,
    MAX_RAW_JSON_NUMBER_BYTES, ProgressMarker, Prompt, PromptArgument, PromptMessage,
    RawJsonAdmissionError, RawJsonRpcDisposition, ReadResourceParams, ReadResourceResult,
    RequestId, Resource, ResourceContent, ResourceTemplate, ResourcesCapability, Role,
    ServerCapabilities, ServerInfo, SubscribeResourceParams, Tool, ToolAnnotations,
    ToolsCapability, UncorrelatedJsonRpcErrorResponse, UnsubscribeResourceParams,
    admit_raw_jsonrpc_document, decode_strict_jsonrpc_message, decode_strict_jsonrpc_response,
    dispose_raw_jsonrpc_failure,
};
pub use fastmcp_protocol::{
    MAX_MCP_APPS_BRIDGE_IN_FLIGHT, MAX_MCP_APPS_BRIDGE_TEXT_BYTES,
    MCP_APPS_HOST_VIEW_PROTOCOL_VERSION, McpAppsBridgeError, McpAppsBridgeImplementation,
    McpAppsBridgeRequestId, McpAppsCancelledNotification, McpAppsDisplayModeParams,
    McpAppsDownloadContent, McpAppsDownloadFileParams, McpAppsHostCapabilities, McpAppsHostContext,
    McpAppsHostNotification, McpAppsHostRequest, McpAppsHostResponse, McpAppsHostToView,
    McpAppsInitializeParams, McpAppsInitializeResult, McpAppsListParams,
    McpAppsLogMessageNotification, McpAppsMessageParams, McpAppsMessageRole, McpAppsOpenLinkParams,
    McpAppsOperationResult, McpAppsPingParams, McpAppsProgressNotification,
    McpAppsResourceReadParams, McpAppsResourceTeardownParams, McpAppsSandboxSignal,
    McpAppsToolCallParams, McpAppsUpdateModelContextParams, McpAppsViewCapabilities,
    McpAppsViewNotification, McpAppsViewRequest, McpAppsViewResponse, McpAppsViewToHost,
};

pub use fastmcp_protocol::{
    MAX_URI_TEMPLATE_BYTES, MAX_URI_TEMPLATE_COMPOSITE_ITEMS,
    MAX_URI_TEMPLATE_EXPANSION_OUTPUT_BYTES, MAX_URI_TEMPLATE_EXPRESSIONS, MAX_URI_TEMPLATE_PARTS,
    MAX_URI_TEMPLATE_PREFIX_LENGTH, MAX_URI_TEMPLATE_VALUE_BYTES,
    MAX_URI_TEMPLATE_VARIABLE_NAME_BYTES, MAX_URI_TEMPLATE_VARIABLES_PER_EXPRESSION, TemplateValue,
    TemplateValues, UriTemplate, UriTemplateError, UriTemplateExpansionLimits,
    UriTemplateExpression, UriTemplateModifier, UriTemplateOperator, UriTemplatePart,
};
pub use fastmcp_protocol::{common_types, extensions, methods, protocol_policy};
// Final common wire vocabulary. `FinalAbsoluteUri` avoids colliding with the
// established core URI type; `modern::AbsoluteUri` retains the exact name.
pub use fastmcp_protocol::common_types::{
    AbsoluteUri as FinalAbsoluteUri, AnnotationAudience, Annotations, CancellationNotification,
    CancellationRequestId, CommonTypeError, CommonWireDirection, ContentBlock,
    EmbeddedResourceContents, FinalCommonTypesSchema, IconTheme, Implementation, JsonInteger,
    LoggingLevel, MAX_ABSOLUTE_URI_BYTES,
    MAX_CANCELLATION_REASON_BYTES as MAX_FINAL_CANCELLATION_REASON_BYTES,
    MAX_CONTENT_ENCODED_BYTES, MAX_CURSOR_BYTES, MAX_ICON_DATA_URI_DECODED_BYTES,
    MAX_ICON_DATA_URI_ENCODED_BYTES, MAX_ICON_DATA_URI_PREFIX_BYTES, MAX_ICON_SIZE_BYTES,
    MAX_ICON_SIZE_ENTRIES, MAX_METADATA_ENTRIES, MAX_METADATA_KEY_BYTES, MAX_METADATA_VALUE_BYTES,
    MAX_TRACE_FIELD_BYTES, OpaqueCursor, OpenMetadata, RawIcon, RawIconSourceUri, ResourceLink,
    SamplingContentBlock, TraceContext, UntrustedCancellationReason,
};

// Final typed core dispatch, result vocabulary, and bounded exact-JSON helpers.
pub use fastmcp_protocol::methods::Final2026Peer;
pub use fastmcp_protocol::{
    CacheScope, CacheTtl, CacheableResult, CancellationSender, CancellationWireCodecError,
    CancellationWireMessage, ClientNotification, CompleteResult, CompleteResultPayload,
    CoreDispatchError, CoreRequest, CoreResult, CoreResultDiscriminatorPolicy, DecodedResult,
    ExactJsonMember, ExactJsonObject, ExactJsonValue, FINAL_CLIENT_CAPABILITIES_META_KEY,
    FINAL_CLIENT_INFO_META_KEY, FINAL_PROTOCOL_VERSION_META_KEY, FINAL_SERVER_INFO_META_KEY,
    FinalArguments, FinalCallToolParams, FinalCallToolResult, FinalCancelledNotificationParams,
    FinalCompletionArgument, FinalCompletionContext, FinalCompletionParams,
    FinalCompletionReference, FinalCompletionResult, FinalCompletionValues, FinalCoreRequest,
    FinalCoreResult, FinalCreateMessageInputRequiredResult, FinalCreateMessageParams,
    FinalCreateMessageResult, FinalEmbeddedCreateMessageParams, FinalEmbeddedElicitationParams,
    FinalEmbeddedElicitationResult, FinalEmbeddedFormElicitationParams, FinalEmbeddedInputKind,
    FinalEmbeddedInputRequest, FinalEmbeddedInputResponse, FinalEmbeddedRootsListParams,
    FinalEmbeddedRootsListResult, FinalEmbeddedUrlElicitationParams, FinalEmptyNotificationParams,
    FinalEmptyParams, FinalEmptyResult, FinalGetPromptParams, FinalGetPromptResult,
    FinalInputRequiredResultType, FinalListParams, FinalListPromptsResult,
    FinalListResourceTemplatesResult, FinalListResourcesResult, FinalListToolsResult,
    FinalLogMessageParams, FinalNotificationError, FinalProgressNotificationParams,
    FinalPromptMessage, FinalReadResourceParams, FinalReadResourceResult, FinalRequestMeta,
    FinalResourceUpdatedNotificationParams, FinalSubscriptionsAcknowledgedNotificationParams,
    FinalSubscriptionsListenParams, FinalSubscriptionsListenResult, IncludeContext,
    InputRequiredResult, LegacyCoreRequest, LegacyCoreResult, LegacyEmptyResult,
    MAX_RESULT_CONTAINER_MEMBERS, MAX_RESULT_DEPTH, MAX_RESULT_ENCODED_BYTES,
    MAX_RESULT_NUMBER_BYTES, MAX_RESULT_STRING_BYTES, MetadataView, PaginatedResult,
    RawResultEnvelope, ResultDecodeError, ResultDecodeErrorKind, ResultDiscriminatorDecision,
    ResultDiscriminatorPolicy, ResultMeta, ResultPeerDiagnostic, ResultPeerEra, ServerNotification,
    TypedCompleteMembers, UnknownResultMembers, decode_peer_result, decode_peer_result_for_era,
    decode_typed_complete, encode_complete_result, encode_result, exact_json_from_serde,
    exact_json_to_serde, parse_exact_json,
};

// Exact final component and sampling models. These are deliberately separate
// from their legacy equivalents because their wire members differ.
pub use fastmcp_protocol::{
    FinalBaseMetadata, FinalPrompt, FinalPromptArgument, FinalResource, FinalResourceTemplate,
    FinalSamplingMessage, FinalSamplingMessageContent, FinalSamplingMessageContentBlock, FinalTool,
    FinalToolAnnotations, FinalToolChoice, FinalToolChoiceMode, ModelHint, ModelPreferences,
    StopReason,
};

// Final MCP Apps metadata, lifecycle, and result-projection vocabulary.
pub use fastmcp_protocol::{
    MAX_MCP_APPS_CSP_DOMAIN_BYTES, MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE,
    MAX_MCP_APPS_TOOL_VISIBILITY_ENTRIES, MAX_MCP_APPS_UI_METADATA_MEMBERS,
    MCP_APPS_DEPRECATED_RESOURCE_URI_METADATA_KEY, MCP_APPS_UI_METADATA_KEY, McpAppsDisplayMode,
    McpAppsLifecycleError, McpAppsMetadataError, McpAppsResourceBinding,
    McpAppsResourceBindingError, McpAppsResourceCsp, McpAppsResourceMetadata,
    McpAppsResourcePermission, McpAppsResourcePermissions, McpAppsResultProjectionError,
    McpAppsToolMetadata, McpAppsToolResult, McpAppsToolVisibility, McpAppsViewLifecycle,
    project_final_core_tools_call_result,
};

// Final extension vocabulary.
pub use fastmcp_protocol::extensions::{
    ClientExtensionDiscovery, EffectiveExtensionSettings, ExtensionDescriptor,
    ExtensionDescriptorRegistry, ExtensionDirection, ExtensionDiscovery, ExtensionDispatchError,
    ExtensionFallbackPolicy, ExtensionHttpEraDisposition, ExtensionId, ExtensionInactiveReason,
    ExtensionLocalEnablement, ExtensionMethodDescriptor, ExtensionNegotiationError,
    ExtensionNegotiationResolver, ExtensionNotificationDescriptor, ExtensionPeer,
    ExtensionRegistryError, ExtensionRegistryReceipt, ExtensionRoutingHeaderDescriptor,
    ExtensionSettings, ExtensionSettingsCompatibilityResolver, ExtensionSettingsResolution,
    ExtensionSettingsSchema, MAX_EXTENSION_DESCRIPTORS, MAX_EXTENSION_ID_BYTES,
    MAX_EXTENSION_MEMBER_NAME_BYTES, MAX_EXTENSION_REGISTRY_CANONICAL_BYTES,
    MAX_EXTENSION_ROUTING_HEADER_BYTES, MAX_EXTENSION_ROUTING_HEADERS,
    MAX_EXTENSION_SETTINGS_ENTRIES, MAX_EXTENSION_SETTINGS_KEY_BYTES,
    MAX_EXTENSION_SETTINGS_NESTING, MAX_EXTENSION_SETTINGS_VALUE_BYTES,
    MAX_MCP_APPS_MIME_TYPE_BYTES, MAX_MCP_APPS_MIME_TYPES, MAX_STDIO_CORRELATION_METHODS,
    MCP_APPS_ACTIVATION_PREDICATE_ID, MCP_APPS_CLIENT_SETTINGS_SCHEMA_ID,
    MCP_APPS_DOWNLOAD_FILE_METHOD, MCP_APPS_HOST_CONTEXT_CHANGED_NOTIFICATION,
    MCP_APPS_HTML_MIME_TYPE, MCP_APPS_INITIALIZE_METHOD, MCP_APPS_INITIALIZED_NOTIFICATION,
    MCP_APPS_MESSAGE_METHOD, MCP_APPS_NEGOTIATION_RESOLVER_ID, MCP_APPS_OPEN_LINK_METHOD,
    MCP_APPS_REQUEST_DISPLAY_MODE_METHOD, MCP_APPS_REQUEST_TEARDOWN_NOTIFICATION,
    MCP_APPS_RESOURCE_TEARDOWN_METHOD, MCP_APPS_SANDBOX_PROXY_READY_NOTIFICATION,
    MCP_APPS_SANDBOX_RESOURCE_READY_NOTIFICATION, MCP_APPS_SERVER_SETTINGS_SCHEMA_ID,
    MCP_APPS_SIZE_CHANGED_NOTIFICATION, MCP_APPS_TOOL_CANCELLED_NOTIFICATION,
    MCP_APPS_TOOL_INPUT_NOTIFICATION, MCP_APPS_TOOL_INPUT_PARTIAL_NOTIFICATION,
    MCP_APPS_TOOL_RESULT_NOTIFICATION, MCP_APPS_UPDATE_MODEL_CONTEXT_METHOD, McpAppsClientSettings,
    McpAppsNegotiationResolver, NegotiatedExtension, NegotiatedExtensionSet,
    OFFICIAL_MCP_APPS_EXTENSION_ID, OFFICIAL_TASKS_EMPTY_SETTINGS_CODEC_ID,
    OFFICIAL_TASKS_EMPTY_SETTINGS_SCHEMA_ID, OFFICIAL_TASKS_EXTENSION_ID, OFFICIAL_TASKS_METHODS,
    OFFICIAL_TASKS_NOTIFICATION, OFFICIAL_TASKS_RESULT_DISCRIMINATOR,
    OfficialTasksNegotiationResolver, ServerExtensionDiscovery, StdioCorrelationDescriptor,
    official_mcp_apps_descriptor, official_mcp_apps_empty_server_settings,
    official_mcp_apps_extension_id, official_mcp_apps_negotiation_resolver,
    official_tasks_descriptor, official_tasks_empty_settings, official_tasks_extension_id,
    register_official_mcp_apps_extension, register_official_tasks_extension,
    resolve_official_mcp_apps_settings,
};

pub use fastmcp_protocol::schema;
pub use fastmcp_protocol::schema::FINAL_JSON_SCHEMA_DIALECT;
pub use fastmcp_protocol::tasks_extension;
pub use fastmcp_protocol::tasks_extension::TASK_UPDATE;
pub use fastmcp_protocol::{
    AdmittedSchema, FinalCoreResultType, SchemaAdmissionError, ValidationError, ValidationResult,
    admit_final_schema, validate, validate_final_core_result, validate_strict,
};
pub use fastmcp_protocol::{
    CompleteTaskResult, CreateTaskResult, EmptyTaskResult, FinalCancelTaskParams,
    FinalCancelTaskResult, FinalGetTaskParams, FinalGetTaskResult, FinalTaskCallToolResult,
    FinalTaskError, FinalTaskId, FinalTaskStatus, FinalTaskStatusNotificationParams,
    MAX_TASK_ID_BYTES, MAX_TASK_INPUT_MAP_ENTRIES, MAX_TASK_SUBSCRIPTION_IDS,
    RELATED_TASK_META_KEY, TASK_CANCEL, TASK_GET, TASK_STATUS_NOTIFICATION,
    TASK_SUBSCRIPTION_IDS_KEY, TASKS_EXTENSION, TaskBase as FinalTaskBase,
    TaskDuration as FinalTaskDuration, TaskInputLedger as FinalTaskInputLedger,
    TaskInputRequests as FinalTaskInputRequests, TaskMethodRequest as FinalTaskMethodRequest,
    TaskRequestMeta as FinalTaskRequestMeta, TaskTimestamp as FinalTaskTimestamp, TaskWireError,
    UpdateTaskParams as FinalUpdateTaskParams, set_task_subscription_ids, task_subscription_ids,
};

// Final `server/discover` vocabulary.
pub use fastmcp_protocol::{
    DiscoveryCacheHints, MAX_SERVER_INSTRUCTIONS_BYTES, SERVER_DISCOVER_METHOD,
    SERVER_DISCOVER_SUPPORTED_VERSIONS, ServerBehavior, ServerBehaviorRegistry,
    ServerDiscoverCapabilities, ServerDiscoverRequest, ServerDiscoverResult, ServerDiscoveryError,
    ServerInstructionError, ServerInstructions,
};

// Final protocol-version admission vocabulary.
pub use fastmcp_protocol::{
    FINAL_PROTOCOL_VERSION, FinalHttpRequestMetadata, FinalProtocolVersion, FinalRequestAdmission,
    HEADER_MISMATCH_ERROR_CODE, HeaderMismatchError, HeaderMismatchReason, MCP_METHOD_HEADER,
    MCP_NAME_HEADER, MCP_PROTOCOL_VERSION_HEADER, MISSING_REQUIRED_CLIENT_CAPABILITY_ERROR_CODE,
    MissingRequiredClientCapabilityError, ProtocolVersionError, RequestAdmissionError,
    RequestVersionMetadata, RequiredCapabilitiesError, SUPPORTED_FINAL_PROTOCOL_VERSIONS,
    UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE, UnsupportedProtocolVersionError,
    admit_final_http_request, admit_final_request, validate_final_protocol_version,
};

/// Historical exact-2024 protocol constant retained for existing consumers.
///
/// New exact-2024 code should import [`legacy_2024::PROTOCOL_VERSION`]; new
/// modern code should import [`modern::PROTOCOL_VERSION`].
pub use fastmcp_protocol::PROTOCOL_VERSION;

/// Immutable protocol-policy primitives shared by the explicit era modules.
pub use fastmcp_protocol::protocol_policy::{
    HttpEndpointBundle, HttpEndpointBundleError, HttpEndpointBundleKey, HttpEraCache,
    HttpEraDecision, HttpModernProbe, HttpProbeBody, HttpRouteKind, LEGACY_PROTOCOL_VERSION,
    LegacyAdapterReceiptIssuer, LegacyClientAdapterInstalledReceipt, LegacyReceiptBinding,
    LegacyServerAdapterInstalledReceipt, MODERN_PROTOCOL_VERSION, ModernVersionSupport,
    ProtocolEra, ProtocolPolicy, ProtocolPolicyError, ProtocolPolicySelection, ProtocolRole,
    ProtocolVersion, ProtocolVersionError as ProtocolPolicyVersionError, StdioEraClassifier,
    StdioEraDecision, StdioEraRejection, StdioEraState, StdioOpeningFrame,
};

// Re-export transport types
pub use fastmcp_transport::http::{
    DualEraHttpEndpoint, DualEraHttpEndpointConfig, DualEraHttpEndpointError,
    DualEraHttpEndpointResponse, DualEraHttpJsonResponse, DualEraHttpLegacySseResponse,
    DualEraHttpSession, DualEraHttpSseResponse,
};
pub use fastmcp_transport::{
    AsyncLineReader, AsyncStdin, AsyncStdioTransport, AsyncStdout, Codec, CodecError, HttpError,
    HttpHandlerConfig, HttpMethod, HttpRequest, HttpRequestHandler, HttpResponse,
    HttpResponseRepresentation, HttpStatus, InvalidMessageKind, ModernHttpRequestAdmission,
    ModernSseDecoder, ModernSseEndOfStream, ModernSseLimits, ModernSseParseError, SendPermit,
    StdioTransport, StreamableHttpRequestCancellation, StreamableHttpRequestResponseStream,
    StreamableHttpResponseStream, StreamableHttpTransport, Transport, TransportError,
    TransportRecvHalf, TransportSendHalf, TwoPhaseTransport,
};

// Re-export transport modules
pub use fastmcp_transport as transport;
pub use fastmcp_transport::{event_store, http, memory, websocket};

// Re-export server types
// FND-01: JWT verifier is not a facade feature (FACADE-NO-JSONWEBTOKEN).
pub use fastmcp_server::{
    AllowAllAuthProvider, ApplicationTaskSupervisor, AuthProvider, AuthRequest,
    AuthorizedTaskServiceRunner, BannerStyle, BidirectionalSenders, BoundHttpServer, BoxFuture,
    CompletionHandler, ConsoleConfig, DEFAULT_IN_MEMORY_FINAL_TASKS, FinalTaskAcceptedInput,
    FinalTaskInitialWork, FinalTaskNotificationEmitter, FinalTaskRetentionAuthority,
    FinalTaskRuntime, FinalTaskRuntimeConfig, FinalTaskSnapshot, FinalTaskStore,
    FinalTaskSupervisorFuture, FinalTaskSupervisorHandoff, FinalTaskWorkDescriptor,
    FinalToolOutcome, HttpServerConfig, InMemoryFinalTaskStore, InboundRequestContext,
    InboundRequestTransport, Middleware, MiddlewareDecision, MountResult, NotificationSender,
    PendingRequests, ProgressNotificationSender, PromptHandler, ProxyBackend, ProxyCatalog,
    ProxyClient, ProxyPromptCatalog, ProxyResourceCatalog, ProxyResourceTemplateCatalog,
    ProxyToolCatalog, ProxyTypedCatalog, RequestSender, ResourceHandler, Router, Server,
    ServerBuilder, ServerHttpEndpoint, ServerHttpEndpointResponse, ServerHttpSession, ServerStats,
    Session, StaticTokenVerifier, StatsSnapshot, TagFilters, TokenAuthProvider, TokenVerifier,
    ToolErrorKind, ToolHandler, TrafficVerbosity, TransportElicitationSender,
    TransportRootsProvider, TransportSamplingSender, create_context_with_progress,
    create_context_with_progress_and_senders,
};
pub use fastmcp_server::{
    DuplicateBehavior, LifespanHooks, LoggingConfig, ServerLaunchPolicyError, ShutdownHook,
    StartupHook,
};
pub use fastmcp_server::{
    ExtensionHandler, ExtensionHandlerInvocationError, ExtensionHandlerKey,
    ExtensionHandlerLookupError, ExtensionHandlerRegistrationError, ExtensionHandlerRegistry,
};

// Re-export bidirectional module for namespaced access (e.g. bidirectional::RequestSender)
pub use fastmcp_server::bidirectional;
pub use fastmcp_server::bidirectional::{
    DEFAULT_MAX_MRTR_INPUT_REQUESTS_PER_ROUND, DEFAULT_MAX_MRTR_INPUT_REQUESTS_TOTAL,
    DEFAULT_MAX_MRTR_REQUEST_STATE_BYTES, DEFAULT_MAX_MRTR_REQUEST_STATES, DEFAULT_MAX_MRTR_ROUNDS,
    DEFAULT_MRTR_REQUEST_STATE_TTL, HARD_MAX_MRTR_INPUT_REQUESTS_PER_ROUND,
    HARD_MAX_MRTR_INPUT_REQUESTS_TOTAL, HARD_MAX_MRTR_REQUEST_STATE_BYTES,
    HARD_MAX_MRTR_REQUEST_STATE_TTL, HARD_MAX_MRTR_REQUEST_STATES, HARD_MAX_MRTR_ROUNDS,
    MrtrCompletedInputs, MrtrExchangeRegistry, MrtrInputKind, MrtrInputRequest, MrtrInputRequests,
    MrtrInputRequired, MrtrInputResponse, MrtrInputResponses, MrtrRequestState, MrtrRetry,
};

// Re-export server middleware modules (no Docket/Redis in FND-01 surface).
pub use fastmcp_server::providers;
pub use fastmcp_server::{caching, oauth, oidc, rate_limiting, transform};

// Re-export client types
pub use fastmcp_client::{
    BoundedListPage, CachePartitionKey, CancellationRequested, Client, ClientBuilder,
    ClientHttpConnection, ClientHttpConnectionError, ClientHttpNegotiation,
    ClientHttpNegotiationDecision, ClientHttpNegotiationError, ClientHttpNegotiationState,
    ClientHttpResponse, ClientProtocolPlan, ClientProtocolPlanError, ClientSession,
    CompletionContext, CompletionParams, CompletionReference, DEFAULT_FINAL_CACHE_CAPACITY,
    DEFAULT_FINAL_CACHE_MAX_BYTES, ExecutionTerminalReason, ExecutionTerminalRecord,
    ExecutionTerminalState, FinalCacheGeneration, FinalCacheInsert, FinalCacheKey,
    FinalCacheLookup, FinalCacheMiss, FinalCacheResultSet, FinalCacheStats,
    FinalCacheTtlDiagnostic, FinalResultCache, FinalTask, FinalTaskInputResponses,
    FinalTaskStatusNotification, FinalToolCallOutcome, FinalUpdateTaskResult, HttpClient,
    HttpClientError, HttpSubscriptionListener, ListPageLimits, MAX_FINAL_CACHE_CAPACITY,
    MAX_FINAL_CACHE_MAX_BYTES, McpAppsBridgeTransport, McpAppsHost, McpAppsHostConfiguration,
    McpAppsHostError, McpAppsHostPolicy, McpAppsInMemoryHostTransport,
    McpAppsInMemoryViewTransport, OpaquePagination, PaginationBounds, PendingRequestRecord,
    ProgressCallback, Request, RequestExecution, RequestExecutor, RequestTimeoutPolicy,
    RequestTimeoutSource, SubscriptionFilter, SubscriptionListenCollector, mcp_apps_in_memory_pair,
};

// Public client HTTP execution and configuration surfaces.
pub use fastmcp_client::http_auth;
pub use fastmcp_client::http_auth::{BearerBindingError, BoundBearerCredential};
pub use fastmcp_client::http_executor::{
    LegacySseHttpClient, LegacySseHttpClientError, MAX_MODERN_HTTP_PROBE_BODY_BYTES,
    MODERN_MCP_ACCEPT, MODERN_MCP_ACCEPT_ENCODING, MODERN_MCP_CONTENT_TYPE, ModernHttpClient,
    ModernHttpClientError, ModernHttpConnectOutcome, ModernHttpExecutor, ModernHttpExecutorError,
    ModernHttpRequest, ModernHttpResponseKind, ModernHttpResponseMetadata,
    ModernHttpResponseStream, ModernHttpSseResponseStream, ModernHttpSubscriptionListenCollector,
    ModernHttpSubscriptionListenError, ModernHttpSubscriptionListenEvent,
    ModernHttpSubscriptionListener, validate_response_head,
};
pub use fastmcp_client::mcp_config::{
    ConfigError, ConfigLoader, HttpEndpointConfig, HttpEndpointConfigError, McpConfig,
    ServerConfig, claude_desktop_config_path, default_config_paths,
};
pub use fastmcp_client::sse;
pub use fastmcp_client::sse::{SseEndOfStream, SseLimits, SseParseError};
pub use fastmcp_client::{http_executor, mcp_config};

// Re-export macros
pub use fastmcp_derive::{JsonSchema, prompt, resource, tool};

/// Auto-policy composition helpers.
///
/// The returned client builder captures [`ProtocolPolicy::Auto`] before any
/// subprocess or HTTP side effect. The caller may replace that immutable plan
/// with an explicit plan before connecting.
pub mod auto {
    pub use fastmcp_client::http_executor::{
        ModernHttpSubscriptionListenCollector, ModernHttpSubscriptionListenError,
        ModernHttpSubscriptionListenEvent, ModernHttpSubscriptionListener,
    };
    pub use fastmcp_client::sse::{SseEndOfStream, SseLimits, SseParseError};
    pub use fastmcp_client::{
        Client, ClientBuilder, ClientHttpConnection, ClientHttpConnectionError,
        ClientHttpNegotiation, ClientHttpNegotiationDecision, ClientHttpNegotiationError,
        ClientHttpNegotiationState, ClientHttpResponse, ClientProtocolPlan,
        ClientProtocolPlanError, ClientSession, FinalTask, FinalTaskInputResponses,
        FinalTaskStatusNotification, FinalToolCallOutcome, FinalUpdateTaskResult, HttpClient,
        HttpClientError, HttpSubscriptionListener, SubscriptionFilter, SubscriptionListenCollector,
    };
    pub use fastmcp_core::{CanonicalHttpUrl, Cx, McpError, McpResult};
    pub use fastmcp_protocol::extensions::{
        ExtensionDescriptor, ExtensionDescriptorRegistry, ExtensionNegotiationError,
        ExtensionSettings, ExtensionSettingsCompatibilityResolver, ExtensionSettingsResolution,
        OFFICIAL_TASKS_EXTENSION_ID, OFFICIAL_TASKS_RESULT_DISCRIMINATOR,
        OfficialTasksNegotiationResolver, official_tasks_descriptor, official_tasks_empty_settings,
        register_official_tasks_extension,
    };
    pub use fastmcp_protocol::protocol_policy::{
        HttpEndpointBundle, HttpEndpointBundleError, ProtocolEra, ProtocolPolicy, ProtocolVersion,
    };
    pub use fastmcp_protocol::schema::FINAL_JSON_SCHEMA_DIALECT;
    pub use fastmcp_protocol::tasks_extension::TASK_UPDATE;
    pub use fastmcp_protocol::{
        AdmittedSchema, ClientCapabilities, ClientInfo, FinalCallToolResult, FinalCancelTaskResult,
        FinalCoreResultType, FinalGetPromptResult, FinalGetTaskResult, FinalReadResourceResult,
        FinalTaskId, RequestId, SchemaAdmissionError, TemplateValue, TemplateValues, UriTemplate,
        UriTemplateError, UriTemplateExpansionLimits, ValidationError, ValidationResult,
        admit_final_schema, validate_final_core_result,
    };
    pub use fastmcp_protocol::{schema, tasks_extension};
    pub use serde_json::{Map as JsonMap, Value as JsonValue};

    /// Creates the public client builder with its immutable Auto stdio plan.
    #[must_use]
    pub fn client_builder() -> ClientBuilder {
        ClientBuilder::new()
    }
}

/// Primary MCP 2026-07-28 public vocabulary.
///
/// This module deliberately names the modern discovery, extension, endpoint,
/// and policy surfaces instead of relying on the legacy root constant. The
/// underlying server/client implementations retain their own qualification
/// boundaries; re-exporting a type here does not claim aggregate protocol
/// conformance. In particular, it does not expose the legacy reverse JSON-RPC
/// transport senders, policy-reset APIs, dual-era HTTP connectors, or the
/// era-less server dispatcher. Use the root exports for intentionally
/// unqualified integration seams, or
/// [`legacy_2024`](crate::legacy_2024) for exact-2024 APIs.
///
/// ```compile_fail
/// use fastmcp_rust::modern::{ClientBuilder, ProtocolPolicy};
///
/// let _ = ClientBuilder::new().protocol_plan(ProtocolPolicy::LegacyOnly);
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::{ClientBuilder, ReverseRequestHandlers};
///
/// let _ = ClientBuilder::new().reverse_request_handlers(ReverseRequestHandlers::new());
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::{CoreRequest, CoreResult, decode_peer_result};
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::CancellationWireMessage;
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::{
///     CancellationRequested, McpRequestCancellation, StreamableHttpRequestCancellation,
/// };
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::ResourceTemplate;
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::{ClientHttpConnection, DualEraHttpEndpoint};
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::ServerBuilder;
///
/// let server = ServerBuilder::new("final-only", "1.0.0").build();
/// let _ = server.dispatch_request;
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::{ModernHttpClient, ModernHttpConnectOutcome};
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::ModernHttpExecutor;
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::BoundHttpServer;
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::Client;
///
/// fn escape(client: Client) {
///     let _ = client.inner;
/// }
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::HttpClient;
///
/// fn escape(client: HttpClient) {
///     let _ = client.inner;
/// }
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::{Client, HttpClient, HttpServer, Server};
///
/// fn escape(client: Client, http_client: HttpClient, server: Server, http_server: HttpServer) {
///     let _ = std::ops::Deref::deref(&client);
///     let _ = std::ops::Deref::deref(&http_client);
///     let _ = std::ops::Deref::deref(&server);
///     let _ = std::ops::Deref::deref(&http_server);
/// }
/// ```
pub mod modern {
    pub use fastmcp_client::http_executor::{
        MAX_MODERN_HTTP_PROBE_BODY_BYTES, MODERN_MCP_ACCEPT, MODERN_MCP_ACCEPT_ENCODING,
        MODERN_MCP_CONTENT_TYPE, ModernHttpClientError, ModernHttpSubscriptionListenCollector,
        ModernHttpSubscriptionListenError, ModernHttpSubscriptionListenEvent,
        ModernHttpSubscriptionListener,
    };
    pub use fastmcp_client::{
        BoundedListPage, CachePartitionKey, CompletionContext, CompletionParams,
        CompletionReference, DEFAULT_FINAL_CACHE_CAPACITY, DEFAULT_FINAL_CACHE_MAX_BYTES,
        ExecutionTerminalReason, ExecutionTerminalRecord, ExecutionTerminalState,
        FinalCacheGeneration, FinalCacheInsert, FinalCacheKey, FinalCacheLookup, FinalCacheMiss,
        FinalCacheResultSet, FinalCacheStats, FinalCacheTtlDiagnostic, FinalResultCache, FinalTask,
        FinalTaskInputResponses, FinalTaskStatusNotification, FinalToolCallOutcome,
        FinalUpdateTaskResult, ListPageLimits, MAX_FINAL_CACHE_CAPACITY, MAX_FINAL_CACHE_MAX_BYTES,
        OpaquePagination, PaginationBounds, PendingRequestRecord, ProgressCallback,
        RequestTimeoutPolicy, RequestTimeoutSource, SubscriptionFilter,
        SubscriptionListenCollector,
    };
    pub use fastmcp_core::{
        CanonicalHttpUrl, ClientCapabilityInfo, Cx, MAX_RESOURCE_READ_DEPTH, MAX_TOOL_CALL_DEPTH,
        McpContext, McpContextLeaseGuard, McpError, McpOutcome, McpResult, NoOpNotificationSender,
        NotificationSender, Outcome, ProgressReporter, ResourceContentItem, ResourceReadResult,
        ResourceReader, ServerCapabilityInfo, ToolCallResult, ToolCaller, ToolContentItem,
    };
    pub use fastmcp_derive::{JsonSchema, prompt, resource, tool};
    pub use fastmcp_protocol::common_types::{
        AbsoluteUri, AnnotationAudience, Annotations, CancellationNotification,
        CancellationRequestId, CommonTypeError, CommonWireDirection, ContentBlock,
        EmbeddedResourceContents, FinalCommonTypesSchema, IconTheme, Implementation, JsonInteger,
        LoggingLevel, OpaqueCursor, OpenMetadata, RawIcon, RawIconSourceUri, ResourceLink,
        SamplingContentBlock, TraceContext, UntrustedCancellationReason,
    };
    pub use fastmcp_protocol::extensions::{
        ClientExtensionDiscovery, EffectiveExtensionSettings, ExtensionDescriptor,
        ExtensionDescriptorRegistry, ExtensionDirection, ExtensionDiscovery,
        ExtensionDispatchError, ExtensionFallbackPolicy, ExtensionHttpEraDisposition, ExtensionId,
        ExtensionInactiveReason, ExtensionLocalEnablement, ExtensionMethodDescriptor,
        ExtensionNegotiationError, ExtensionNegotiationResolver, ExtensionNotificationDescriptor,
        ExtensionPeer, ExtensionRegistryError, ExtensionRegistryReceipt,
        ExtensionRoutingHeaderDescriptor, ExtensionSettings,
        ExtensionSettingsCompatibilityResolver, ExtensionSettingsResolution,
        ExtensionSettingsSchema, MAX_EXTENSION_DESCRIPTORS, MAX_EXTENSION_ID_BYTES,
        MAX_EXTENSION_MEMBER_NAME_BYTES, MAX_EXTENSION_REGISTRY_CANONICAL_BYTES,
        MAX_EXTENSION_ROUTING_HEADER_BYTES, MAX_EXTENSION_ROUTING_HEADERS,
        MAX_EXTENSION_SETTINGS_ENTRIES, MAX_EXTENSION_SETTINGS_KEY_BYTES,
        MAX_EXTENSION_SETTINGS_NESTING, MAX_EXTENSION_SETTINGS_VALUE_BYTES,
        MAX_MCP_APPS_MIME_TYPE_BYTES, MAX_MCP_APPS_MIME_TYPES, MAX_STDIO_CORRELATION_METHODS,
        MCP_APPS_ACTIVATION_PREDICATE_ID, MCP_APPS_CLIENT_SETTINGS_SCHEMA_ID,
        MCP_APPS_DOWNLOAD_FILE_METHOD, MCP_APPS_HOST_CONTEXT_CHANGED_NOTIFICATION,
        MCP_APPS_HTML_MIME_TYPE, MCP_APPS_INITIALIZE_METHOD, MCP_APPS_INITIALIZED_NOTIFICATION,
        MCP_APPS_MESSAGE_METHOD, MCP_APPS_NEGOTIATION_RESOLVER_ID, MCP_APPS_OPEN_LINK_METHOD,
        MCP_APPS_REQUEST_DISPLAY_MODE_METHOD, MCP_APPS_REQUEST_TEARDOWN_NOTIFICATION,
        MCP_APPS_RESOURCE_TEARDOWN_METHOD, MCP_APPS_SANDBOX_PROXY_READY_NOTIFICATION,
        MCP_APPS_SANDBOX_RESOURCE_READY_NOTIFICATION, MCP_APPS_SERVER_SETTINGS_SCHEMA_ID,
        MCP_APPS_SIZE_CHANGED_NOTIFICATION, MCP_APPS_TOOL_CANCELLED_NOTIFICATION,
        MCP_APPS_TOOL_INPUT_NOTIFICATION, MCP_APPS_TOOL_INPUT_PARTIAL_NOTIFICATION,
        MCP_APPS_TOOL_RESULT_NOTIFICATION, MCP_APPS_UPDATE_MODEL_CONTEXT_METHOD,
        McpAppsClientSettings, McpAppsNegotiationResolver, NegotiatedExtension,
        NegotiatedExtensionSet, OFFICIAL_MCP_APPS_EXTENSION_ID,
        OFFICIAL_TASKS_EMPTY_SETTINGS_CODEC_ID, OFFICIAL_TASKS_EMPTY_SETTINGS_SCHEMA_ID,
        OFFICIAL_TASKS_EXTENSION_ID, OFFICIAL_TASKS_METHODS, OFFICIAL_TASKS_NOTIFICATION,
        OFFICIAL_TASKS_RESULT_DISCRIMINATOR, OfficialTasksNegotiationResolver,
        ServerExtensionDiscovery, StdioCorrelationDescriptor, official_mcp_apps_descriptor,
        official_mcp_apps_empty_server_settings, official_mcp_apps_extension_id,
        official_mcp_apps_negotiation_resolver, official_tasks_descriptor,
        official_tasks_empty_settings, official_tasks_extension_id,
        register_official_mcp_apps_extension, register_official_tasks_extension,
        resolve_official_mcp_apps_settings,
    };
    pub use fastmcp_protocol::methods::Final2026Peer;
    pub use fastmcp_protocol::protocol_policy::MODERN_PROTOCOL_VERSION;
    pub use fastmcp_protocol::schema::FINAL_JSON_SCHEMA_DIALECT;
    pub use fastmcp_protocol::tasks_extension::TASK_UPDATE;
    pub use fastmcp_protocol::{
        AdmittedSchema, CacheScope, CacheTtl, CacheableResult, ClientCapabilities, ClientInfo,
        ClientNotification, CompleteResult, CompleteResultPayload, CompleteTaskResult,
        CreateTaskResult, DiscoveryCacheHints, EmptyTaskResult, ExactJsonMember, ExactJsonObject,
        ExactJsonValue, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_CLIENT_INFO_META_KEY,
        FINAL_PROTOCOL_VERSION as PROTOCOL_VERSION, FINAL_PROTOCOL_VERSION_META_KEY,
        FINAL_SERVER_INFO_META_KEY, FinalArguments, FinalBaseMetadata, FinalCallToolParams,
        FinalCallToolResult, FinalCancelTaskParams, FinalCancelTaskResult,
        FinalCancelledNotificationParams, FinalCompletionArgument, FinalCompletionContext,
        FinalCompletionParams, FinalCompletionReference, FinalCompletionResult,
        FinalCompletionValues, FinalCoreResultType, FinalCreateMessageInputRequiredResult,
        FinalCreateMessageParams, FinalCreateMessageResult, FinalEmbeddedCreateMessageParams,
        FinalEmbeddedElicitationParams, FinalEmbeddedElicitationResult,
        FinalEmbeddedFormElicitationParams, FinalEmbeddedInputKind, FinalEmbeddedInputRequest,
        FinalEmbeddedInputResponse, FinalEmbeddedRootsListParams, FinalEmbeddedRootsListResult,
        FinalEmbeddedUrlElicitationParams, FinalEmptyNotificationParams, FinalEmptyParams,
        FinalEmptyResult, FinalGetPromptParams, FinalGetPromptResult, FinalGetTaskParams,
        FinalGetTaskResult, FinalHttpRequestMetadata, FinalInputRequiredResultType,
        FinalListParams, FinalListPromptsResult, FinalListResourceTemplatesResult,
        FinalListResourcesResult, FinalListToolsResult, FinalLogMessageParams,
        FinalNotificationError, FinalProgressNotificationParams, FinalPrompt, FinalPromptArgument,
        FinalPromptMessage, FinalProtocolVersion, FinalReadResourceParams, FinalReadResourceResult,
        FinalRequestAdmission, FinalRequestMeta, FinalResource, FinalResourceTemplate,
        FinalResourceUpdatedNotificationParams, FinalSamplingMessage, FinalSamplingMessageContent,
        FinalSamplingMessageContentBlock, FinalSubscriptionsAcknowledgedNotificationParams,
        FinalSubscriptionsListenParams, FinalSubscriptionsListenResult, FinalTaskCallToolResult,
        FinalTaskError, FinalTaskId, FinalTaskStatus, FinalTaskStatusNotificationParams, FinalTool,
        FinalToolAnnotations, FinalToolChoice, FinalToolChoiceMode, HEADER_MISMATCH_ERROR_CODE,
        HeaderMismatchError, HeaderMismatchReason, IncludeContext, InputRequiredResult,
        MAX_MCP_APPS_CSP_DOMAIN_BYTES, MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE,
        MAX_MCP_APPS_TOOL_VISIBILITY_ENTRIES, MAX_MCP_APPS_UI_METADATA_MEMBERS,
        MAX_RESULT_CONTAINER_MEMBERS, MAX_RESULT_DEPTH, MAX_RESULT_ENCODED_BYTES,
        MAX_RESULT_NUMBER_BYTES, MAX_RESULT_STRING_BYTES, MAX_TASK_ID_BYTES,
        MAX_TASK_INPUT_MAP_ENTRIES, MAX_TASK_SUBSCRIPTION_IDS,
        MCP_APPS_DEPRECATED_RESOURCE_URI_METADATA_KEY, MCP_APPS_UI_METADATA_KEY, MCP_METHOD_HEADER,
        MCP_NAME_HEADER, MCP_PROTOCOL_VERSION_HEADER,
        MISSING_REQUIRED_CLIENT_CAPABILITY_ERROR_CODE, McpAppsDisplayMode, McpAppsLifecycleError,
        McpAppsMetadataError, McpAppsResourceBinding, McpAppsResourceBindingError,
        McpAppsResourceCsp, McpAppsResourceMetadata, McpAppsResourcePermission,
        McpAppsResourcePermissions, McpAppsResultProjectionError, McpAppsToolMetadata,
        McpAppsToolResult, McpAppsToolVisibility, McpAppsViewLifecycle, MetadataView,
        MissingRequiredClientCapabilityError, ModelHint, ModelPreferences, PaginatedResult,
        ProgressMarker, ProtocolVersionError as FinalProtocolVersionError, RELATED_TASK_META_KEY,
        RawResultEnvelope, RequestAdmissionError, RequestId, RequestVersionMetadata,
        RequiredCapabilitiesError, SERVER_DISCOVER_METHOD, SERVER_DISCOVER_SUPPORTED_VERSIONS,
        SUPPORTED_FINAL_PROTOCOL_VERSIONS, SchemaAdmissionError, ServerBehavior,
        ServerBehaviorRegistry, ServerDiscoverCapabilities, ServerDiscoverRequest,
        ServerDiscoverResult, ServerDiscoveryError, ServerInstructionError, ServerInstructions,
        ServerNotification, StopReason, TASK_CANCEL, TASK_GET, TASK_STATUS_NOTIFICATION,
        TASK_SUBSCRIPTION_IDS_KEY, TASKS_EXTENSION, TaskBase as FinalTaskBase,
        TaskDuration as FinalTaskDuration, TaskInputLedger as FinalTaskInputLedger,
        TaskInputRequests as FinalTaskInputRequests, TaskMethodRequest as FinalTaskMethodRequest,
        TaskRequestMeta as FinalTaskRequestMeta, TaskTimestamp as FinalTaskTimestamp,
        TaskWireError, TemplateValue, TemplateValues, TypedCompleteMembers,
        UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE, UnknownResultMembers,
        UnsupportedProtocolVersionError, UpdateTaskParams as FinalUpdateTaskParams, UriTemplate,
        UriTemplateError, UriTemplateExpansionLimits, UriTemplateExpression, UriTemplateModifier,
        UriTemplateOperator, UriTemplatePart, ValidationError, ValidationResult,
        admit_final_http_request, admit_final_request, admit_final_schema, decode_typed_complete,
        encode_complete_result, encode_result, exact_json_from_serde, exact_json_to_serde,
        parse_exact_json, project_final_core_tools_call_result, set_task_subscription_ids,
        task_subscription_ids, validate_final_core_result, validate_final_protocol_version,
    };
    pub use fastmcp_protocol::{common_types, extensions, schema, tasks_extension};
    pub use fastmcp_server::bidirectional::{
        DEFAULT_MAX_MRTR_INPUT_REQUESTS_PER_ROUND, DEFAULT_MAX_MRTR_INPUT_REQUESTS_TOTAL,
        DEFAULT_MAX_MRTR_REQUEST_STATE_BYTES, DEFAULT_MAX_MRTR_REQUEST_STATES,
        DEFAULT_MAX_MRTR_ROUNDS, DEFAULT_MRTR_REQUEST_STATE_TTL,
        HARD_MAX_MRTR_INPUT_REQUESTS_PER_ROUND, HARD_MAX_MRTR_INPUT_REQUESTS_TOTAL,
        HARD_MAX_MRTR_REQUEST_STATE_BYTES, HARD_MAX_MRTR_REQUEST_STATE_TTL,
        HARD_MAX_MRTR_REQUEST_STATES, HARD_MAX_MRTR_ROUNDS, MrtrCompletedInputs,
        MrtrExchangeRegistry, MrtrInputKind, MrtrInputRequest, MrtrInputRequests,
        MrtrInputRequired, MrtrInputResponse, MrtrInputResponses, MrtrRequestState, MrtrRetry,
    };
    pub use fastmcp_server::{
        ApplicationTaskSupervisor, AuthProvider, AuthRequest, AuthorizedTaskServiceRunner,
        BoxFuture, CompletionHandler, DEFAULT_IN_MEMORY_FINAL_TASKS, DuplicateBehavior,
        ExtensionHandler, ExtensionHandlerInvocationError, ExtensionHandlerKey,
        ExtensionHandlerLookupError, ExtensionHandlerRegistrationError, ExtensionHandlerRegistry,
        FinalTaskAcceptedInput, FinalTaskInitialWork, FinalTaskNotificationEmitter,
        FinalTaskRetentionAuthority, FinalTaskRuntime, FinalTaskRuntimeConfig, FinalTaskSnapshot,
        FinalTaskStore, FinalTaskSupervisorFuture, FinalTaskSupervisorHandoff,
        FinalTaskWorkDescriptor, FinalToolOutcome, InMemoryFinalTaskStore, LifespanHooks,
        LoggingConfig, Middleware, MiddlewareDecision, MountResult, ProgressNotificationSender,
        PromptHandler, ResourceHandler, ShutdownHook, StartupHook, TagFilters, ToolErrorKind,
        ToolHandler, create_context_with_progress,
    };
    pub use fastmcp_transport::{
        ModernHttpRequestAdmission, SendPermit, StreamableHttpRequestResponseStream,
        StreamableHttpResponseStream, StreamableHttpTransport, TransportError,
    };
    pub use serde_json::{Map as JsonMap, Value as JsonValue};

    /// A non-resettable marker for the modern facade's sole protocol policy.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ModernOnly;

    /// Final-only facade over the underlying client builder.
    #[derive(Clone)]
    pub struct ClientBuilder {
        inner: fastmcp_client::ClientBuilder,
    }

    impl ClientBuilder {
        /// Creates a builder permanently pinned to MCP 2026-07-28 stdio.
        #[must_use]
        pub fn new() -> Self {
            Self {
                inner: fastmcp_client::ClientBuilder::new().protocol_plan(
                    fastmcp_client::ClientProtocolPlan::stdio(
                        fastmcp_protocol::protocol_policy::ProtocolPolicy::ModernOnly,
                    ),
                ),
            }
        }

        /// Returns the sole policy admitted by this facade.
        #[must_use]
        pub const fn protocol_policy(&self) -> ModernOnly {
            ModernOnly
        }

        /// Sets the client identity for final discovery.
        #[must_use]
        pub fn client_info(self, name: impl Into<String>, version: impl Into<String>) -> Self {
            Self {
                inner: self.inner.client_info(name, version),
            }
        }

        /// Sets the ordinary request timeout policy.
        #[must_use]
        pub fn request_timeout_policy(self, policy: RequestTimeoutPolicy) -> Self {
            Self {
                inner: self.inner.request_timeout_policy(policy),
            }
        }

        /// Configures final discovery capabilities.
        #[must_use]
        pub fn capabilities(self, capabilities: ClientCapabilities) -> Self {
            Self {
                inner: self.inner.capabilities(capabilities),
            }
        }

        /// Configures the MCP Apps MIME types advertised during final discovery.
        #[must_use]
        pub fn mcp_apps(self, settings: McpAppsClientSettings) -> Self {
            Self {
                inner: self.inner.mcp_apps(settings),
            }
        }

        /// Adds one environment variable to the final-only stdio subprocess.
        #[must_use]
        pub fn env(self, key: impl Into<String>, value: impl Into<String>) -> Self {
            Self {
                inner: self.inner.env(key, value),
            }
        }

        /// Connects the final-only stdio plan using the current capability context.
        pub fn connect_stdio(self, command: &str, args: &[&str]) -> McpResult<Client> {
            self.inner
                .connect_stdio(command, args)
                .map(Client::from_inner)
        }

        /// Connects the final-only stdio plan with an explicit capability context.
        pub fn connect_stdio_with_cx(
            self,
            command: &str,
            args: &[&str],
            cx: &Cx,
        ) -> McpResult<Client> {
            self.inner
                .connect_stdio_with_cx(command, args, cx)
                .map(Client::from_inner)
        }
    }

    impl Default for ClientBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Final-only facade over a connected client.
    pub struct Client {
        inner: fastmcp_client::Client,
    }

    impl Client {
        fn from_inner(inner: fastmcp_client::Client) -> Self {
            Self { inner }
        }

        /// Returns the pinned final protocol version.
        #[must_use]
        pub const fn protocol_version(&self) -> &'static str {
            MODERN_PROTOCOL_VERSION
        }

        /// Lists one exact final page of tools without a legacy projection.
        pub fn list_tools(&mut self, cursor: Option<&str>) -> McpResult<FinalListToolsResult> {
            match self.inner.list_tools_typed(cursor)? {
                fastmcp_protocol::CoreResult::Final(
                    fastmcp_protocol::FinalCoreResult::ToolsList { result, .. },
                ) => Ok(result.payload),
                _ => Err(McpError::internal_error(
                    "Modern client received a non-final tools/list result",
                )),
            }
        }

        /// Calls one tool and retains the exact final content vocabulary.
        pub fn call_tool(
            &mut self,
            name: &str,
            arguments: JsonValue,
        ) -> McpResult<FinalCallToolResult> {
            self.inner.call_tool_final(name, arguments)
        }

        /// Calls one tool with the official Tasks result discriminator enabled.
        pub fn call_tool_outcome(
            &mut self,
            name: &str,
            arguments: JsonValue,
        ) -> McpResult<FinalToolCallOutcome> {
            self.inner.call_tool_final_outcome(name, arguments)
        }

        /// Lists one exact final page of resources without a legacy projection.
        pub fn list_resources(
            &mut self,
            cursor: Option<&str>,
        ) -> McpResult<FinalListResourcesResult> {
            match self.inner.list_resources_typed(cursor)? {
                fastmcp_protocol::CoreResult::Final(
                    fastmcp_protocol::FinalCoreResult::ResourcesList { result, .. },
                ) => Ok(result.payload),
                _ => Err(McpError::internal_error(
                    "Modern client received a non-final resources/list result",
                )),
            }
        }

        /// Lists one exact final page of resource templates.
        pub fn list_resource_templates(
            &mut self,
            cursor: Option<&str>,
        ) -> McpResult<FinalListResourceTemplatesResult> {
            match self.inner.list_resource_templates_typed(cursor)? {
                fastmcp_protocol::CoreResult::Final(
                    fastmcp_protocol::FinalCoreResult::ResourceTemplatesList { result, .. },
                ) => Ok(result.payload),
                _ => Err(McpError::internal_error(
                    "Modern client received a non-final resources/templates/list result",
                )),
            }
        }

        /// Reads one resource with its exact final cache metadata and contents.
        pub fn read_resource(&mut self, uri: &str) -> McpResult<FinalReadResourceResult> {
            self.inner.read_resource_final(uri)
        }

        /// Lists one exact final page of prompts without a legacy projection.
        pub fn list_prompts(&mut self, cursor: Option<&str>) -> McpResult<FinalListPromptsResult> {
            match self.inner.list_prompts_typed(cursor)? {
                fastmcp_protocol::CoreResult::Final(
                    fastmcp_protocol::FinalCoreResult::PromptsList { result, .. },
                ) => Ok(result.payload),
                _ => Err(McpError::internal_error(
                    "Modern client received a non-final prompts/list result",
                )),
            }
        }

        /// Gets one prompt with its exact final message vocabulary.
        pub fn get_prompt(
            &mut self,
            name: &str,
            arguments: std::collections::HashMap<String, String>,
        ) -> McpResult<FinalGetPromptResult> {
            self.inner.get_prompt_final(name, arguments)
        }

        /// Completes a prompt or resource-template argument using final context.
        pub fn complete(&mut self, params: CompletionParams) -> McpResult<FinalCompletionResult> {
            match self.inner.complete(params)? {
                fastmcp_protocol::CoreResult::Final(
                    fastmcp_protocol::FinalCoreResult::Completion { result, .. },
                ) => Ok(result.payload),
                _ => Err(McpError::internal_error(
                    "Modern client received a non-final completion/complete result",
                )),
            }
        }

        /// Opens and collects one typed final subscriptions listener.
        pub fn listen_subscriptions(
            &mut self,
            notifications: SubscriptionFilter,
        ) -> McpResult<SubscriptionListenCollector> {
            self.inner.listen_subscriptions_typed(notifications)
        }

        /// Drains exact final progress notifications, preserving JSON number lexemes.
        #[must_use]
        pub fn take_progress_notifications(&mut self) -> Vec<FinalProgressNotificationParams> {
            self.inner.take_final_progress_notifications()
        }

        /// Reads one task through the official final Tasks extension.
        pub fn get_task(&mut self, task_id: FinalTaskId) -> McpResult<FinalGetTaskResult> {
            self.inner.get_task_final(task_id)
        }

        /// Supplies responses to one input-required final task.
        pub fn update_task(
            &mut self,
            task: &FinalTask,
            input_responses: FinalTaskInputResponses,
        ) -> McpResult<FinalUpdateTaskResult> {
            self.inner.update_task_final(task, input_responses)
        }

        /// Requests cancellation through the official final Tasks extension.
        pub fn cancel_task(&mut self, task_id: FinalTaskId) -> McpResult<FinalCancelTaskResult> {
            self.inner.cancel_task_final(task_id)
        }

        /// Closes the owned final client connection.
        pub fn close(&mut self) -> McpResult<()> {
            self.inner.close()
        }
    }

    /// Failure while connecting the facade's immutable modern HTTP client.
    #[derive(Debug)]
    pub enum HttpClientConnectError {
        /// The supplied endpoint cannot form the facade's fixed modern plan.
        Plan(fastmcp_protocol::protocol_policy::HttpEndpointBundleError),
        /// The final `server/discover` probe or modern transport failed.
        Connect(ModernHttpClientError),
        /// A legacy selection contradicts the facade's fixed `ModernOnly` plan.
        UnexpectedLegacySelection,
    }

    impl std::fmt::Display for HttpClientConnectError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Plan(error) => error.fmt(formatter),
                Self::Connect(error) => error.fmt(formatter),
                Self::UnexpectedLegacySelection => {
                    formatter.write_str("ModernOnly HTTP connection selected legacy")
                }
            }
        }
    }

    impl std::error::Error for HttpClientConnectError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Plan(error) => Some(error),
                Self::Connect(error) => Some(error),
                Self::UnexpectedLegacySelection => None,
            }
        }
    }

    /// Final-only HTTP client whose protocol plan is fixed by this facade.
    ///
    /// This wrapper intentionally has no generic request dispatcher, no
    /// protocol-plan setter, and no accessor for its underlying HTTP client.
    #[derive(Clone)]
    pub struct HttpClient {
        inner: fastmcp_client::http_executor::ModernHttpClient,
    }

    impl HttpClient {
        /// Connects to one canonical final HTTP endpoint with a fixed
        /// `ModernOnly` plan. Callers cannot supply a plan or legacy routes.
        pub async fn connect(
            cx: &Cx,
            endpoint: CanonicalHttpUrl,
            client_info: ClientInfo,
            client_capabilities: ClientCapabilities,
        ) -> Result<Self, HttpClientConnectError> {
            let plan = fastmcp_client::ClientProtocolPlan::http(
                fastmcp_protocol::protocol_policy::ProtocolPolicy::ModernOnly,
                Some(endpoint),
                None,
                None,
                "fastmcp-rust-modern-facade".to_owned(),
                "fastmcp-rust-modern-facade".to_owned(),
                "modern-http".to_owned(),
                0,
                0,
                0,
            )
            .map_err(HttpClientConnectError::Plan)?;
            let outcome = fastmcp_client::http_executor::ModernHttpClient::connect(
                cx,
                plan,
                client_info,
                client_capabilities,
            )
            .await
            .map_err(HttpClientConnectError::Connect)?;
            match outcome {
                fastmcp_client::http_executor::ModernHttpConnectOutcome::Modern(inner) => {
                    Ok(Self { inner })
                }
                fastmcp_client::http_executor::ModernHttpConnectOutcome::LegacySse(_) => {
                    Err(HttpClientConnectError::UnexpectedLegacySelection)
                }
            }
        }

        /// Returns the exact final discovery response that admitted this connection.
        #[must_use]
        pub const fn server_discovery(&self) -> &ServerDiscoverResult {
            self.inner.server_discovery()
        }

        /// Returns whether final discovery activated the official MCP Apps extension.
        #[must_use]
        pub const fn mcp_apps_active(&self) -> bool {
            self.inner.mcp_apps_active()
        }

        /// Calls one final tool and retains its official Tasks outcome branch.
        pub async fn call_tool_outcome(
            &self,
            cx: &Cx,
            request_id: RequestId,
            name: &str,
            arguments: JsonValue,
            maximum_response_bytes: usize,
        ) -> Result<FinalToolCallOutcome, ModernHttpClientError> {
            self.inner
                .call_tool_final_outcome(cx, request_id, name, arguments, maximum_response_bytes)
                .await
        }

        /// Opens and collects one typed final subscriptions listener.
        pub async fn listen_subscriptions(
            &self,
            cx: &Cx,
            request_id: RequestId,
            notifications: SubscriptionFilter,
            limits: fastmcp_client::sse::SseLimits,
        ) -> Result<ModernHttpSubscriptionListenCollector, ModernHttpSubscriptionListenError>
        {
            self.inner
                .listen_subscriptions_typed(cx, request_id, notifications, limits)
                .await
        }

        /// Reads one task through the official final Tasks extension.
        pub async fn get_task(
            &self,
            cx: &Cx,
            request_id: RequestId,
            task_id: FinalTaskId,
            maximum_response_bytes: usize,
        ) -> Result<FinalGetTaskResult, ModernHttpClientError> {
            self.inner
                .get_task_final(cx, request_id, task_id, maximum_response_bytes)
                .await
        }

        /// Supplies responses to one input-required final task.
        pub async fn update_task(
            &self,
            cx: &Cx,
            request_id: RequestId,
            task: &FinalTask,
            input_responses: FinalTaskInputResponses,
            maximum_response_bytes: usize,
        ) -> Result<FinalUpdateTaskResult, ModernHttpClientError> {
            self.inner
                .update_task_final(
                    cx,
                    request_id,
                    task,
                    input_responses,
                    maximum_response_bytes,
                )
                .await
        }

        /// Requests cancellation through the official final Tasks extension.
        pub async fn cancel_task(
            &self,
            cx: &Cx,
            request_id: RequestId,
            task_id: FinalTaskId,
            maximum_response_bytes: usize,
        ) -> Result<FinalCancelTaskResult, ModernHttpClientError> {
            self.inner
                .cancel_task_final(cx, request_id, task_id, maximum_response_bytes)
                .await
        }
    }

    /// Internal registration bridge that lets the router retain an exact final
    /// template while satisfying its concrete template matcher contract.
    struct FinalResourceTemplateRegistration {
        definition: FinalResourceTemplate,
    }

    impl FinalResourceTemplateRegistration {
        fn new(definition: FinalResourceTemplate) -> Self {
            Self { definition }
        }

        fn legacy_template(&self) -> fastmcp_protocol::ResourceTemplate {
            fastmcp_protocol::ResourceTemplate {
                uri_template: self.definition.uri_template.clone(),
                name: self.definition.name.clone(),
                description: self.definition.description.clone(),
                mime_type: self.definition.mime_type.clone(),
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }
    }

    impl ResourceHandler for FinalResourceTemplateRegistration {
        fn definition(&self) -> fastmcp_protocol::Resource {
            fastmcp_protocol::Resource {
                uri: self.definition.uri_template.clone(),
                name: self.definition.name.clone(),
                description: self.definition.description.clone(),
                mime_type: self.definition.mime_type.clone(),
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn template(&self) -> Option<fastmcp_protocol::ResourceTemplate> {
            Some(self.legacy_template())
        }

        fn final_template_definition(&self) -> Option<FinalResourceTemplate> {
            Some(self.definition.clone())
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<fastmcp_protocol::ResourceContent>> {
            Err(McpError::invalid_request(
                "resource template registration does not provide resource content",
            ))
        }
    }

    /// Final-only facade over the underlying server builder.
    pub struct ServerBuilder {
        inner: fastmcp_server::ServerBuilder,
    }

    impl ServerBuilder {
        /// Creates a builder pinned to MCP 2026-07-28.
        #[must_use]
        pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
            Self {
                inner: fastmcp_server::ServerBuilder::new(name, version)
                    .protocol_policy(fastmcp_protocol::protocol_policy::ProtocolPolicy::ModernOnly),
            }
        }

        /// Returns the sole policy admitted by this facade.
        #[must_use]
        pub const fn protocol_policy(&self) -> ModernOnly {
            ModernOnly
        }

        /// Installs the official MCP Apps discovery marker.
        pub fn mcp_apps(self) -> Result<Self, fastmcp_server::ServerExtensionConfigurationError> {
            self.inner.mcp_apps().map(|inner| Self { inner })
        }

        /// Registers one tool handler.
        #[must_use]
        pub fn tool<H: ToolHandler + 'static>(self, handler: H) -> Self {
            Self {
                inner: self.inner.tool(handler),
            }
        }

        /// Registers one resource handler.
        #[must_use]
        pub fn resource<H: ResourceHandler + 'static>(self, handler: H) -> Self {
            Self {
                inner: self.inner.resource(handler),
            }
        }

        /// Registers one exact final resource template for final discovery.
        ///
        /// The template remains exact through router admission; no
        /// legacy-shaped template is accepted or exposed by this facade.
        #[must_use]
        pub fn resource_template(self, template: FinalResourceTemplate) -> Self {
            Self {
                inner: self
                    .inner
                    .resource(FinalResourceTemplateRegistration::new(template)),
            }
        }

        /// Registers one prompt handler.
        #[must_use]
        pub fn prompt<H: PromptHandler + 'static>(self, handler: H) -> Self {
            Self {
                inner: self.inner.prompt(handler),
            }
        }

        /// Builds a server with no facade-exposed legacy dispatcher.
        #[must_use]
        pub fn build(self) -> Server {
            Server {
                inner: self.inner.build(),
            }
        }
    }

    /// Final-only facade over a built server.
    pub struct Server {
        inner: fastmcp_server::Server,
    }

    /// A bound final-only HTTP server lifecycle.
    ///
    /// The listener can only originate from a [`Server`] built by this module;
    /// its underlying dual-era listener is never exposed.
    pub struct HttpServer {
        inner: fastmcp_server::BoundHttpServer,
    }

    impl HttpServer {
        /// Returns the address selected for this final-only listener.
        pub fn local_addr(&self) -> McpResult<std::net::SocketAddr> {
            self.inner.local_addr()
        }

        /// Serves final HTTP requests until the caller-owned context is cancelled.
        pub async fn serve(self, cx: &Cx) -> McpResult<()> {
            self.inner.serve(cx).await
        }
    }

    impl Server {
        /// Returns final discovery metadata.
        pub fn server_discovery(&self) -> McpResult<ServerDiscoverResult> {
            self.inner.server_discovery()
        }

        /// Publishes a final catalog or resource change notification.
        pub fn publish_subscription_notification(
            &self,
            notification: ServerNotification,
        ) -> McpResult<usize> {
            self.inner.publish_subscription_notification(notification)
        }

        /// Binds this facade-pinned server to a caller-owned final HTTP listener.
        pub async fn bind_http(self, cx: &Cx, addr: impl Into<String>) -> McpResult<HttpServer> {
            self.inner
                .bind_http(cx, addr)
                .await
                .map(|inner| HttpServer { inner })
        }

        /// Binds and serves this facade-pinned server over final HTTP.
        pub async fn serve_http(self, cx: &Cx, addr: impl Into<String>) -> McpResult<()> {
            self.inner.serve_http(cx, addr).await
        }

        /// Runs this final-only server over stdio.
        pub fn run_stdio(self) -> ! {
            self.inner.run_stdio()
        }
    }

    /// Creates a client builder pinned to the ModernOnly stdio plan.
    #[must_use]
    pub fn client_builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Creates a server builder pinned to MCP 2026-07-28.
    #[must_use]
    pub fn server_builder(name: impl Into<String>, version: impl Into<String>) -> ServerBuilder {
        ServerBuilder::new(name, version)
    }
}

/// Exact MCP 2024-11-05 public vocabulary.
///
/// This module keeps legacy lifecycle and transport access explicit. It is
/// intentionally disjoint from [`modern`]; selecting between the two remains
/// the responsibility of the immutable policy and the transport-specific
/// negotiation layer.
pub mod legacy_2024 {
    pub use fastmcp_client::http_executor::{LegacySseHttpClient, LegacySseHttpClientError};
    pub use fastmcp_client::{
        Client, ClientBuilder, ClientProtocolPlan, ClientProtocolPlanError, ClientSession,
        CreateMessageParams as LegacyCreateMessageParams,
        CreateMessageResult as LegacyCreateMessageResult,
        ElicitRequestParams as LegacyElicitRequestParams, ElicitResult as LegacyElicitResult,
        HttpClient, HttpClientError, ListRootsParams as LegacyListRootsParams,
        ListRootsResult as LegacyListRootsResult, Request, RequestExecution, RequestExecutor,
        RequestTimeoutPolicy, RequestTimeoutSource,
        ReverseRequestHandlers as LegacyReverseRequestHandlers,
        RootsRequestHandler as LegacyRootsRequestHandler,
        SamplingRequestHandler as LegacySamplingRequestHandler,
    };
    pub use fastmcp_core::{CanonicalHttpUrl, Cx, McpContext, McpError, McpOutcome, McpResult};
    pub use fastmcp_derive::{JsonSchema, prompt, resource, tool};
    pub use fastmcp_protocol::methods;
    pub use fastmcp_protocol::protocol_policy::{
        LEGACY_PROTOCOL_VERSION, LegacyAdapterReceiptIssuer, LegacyClientAdapterInstalledReceipt,
        LegacyReceiptBinding,
        LegacyServerAdapterInstalledReceipt as PolicyServerAdapterInstalledReceipt, ProtocolEra,
        ProtocolPolicy, ProtocolVersion,
    };
    pub use fastmcp_protocol::{
        CallToolParams, CallToolResult, CancellationSender, CancellationWireCodecError,
        CancellationWireMessage, CancelledParams, ClientCapabilities, ClientInfo, CompletionValues,
        CreateMessageParams, CreateMessageResult, ElicitAction, ElicitCompleteNotificationParams,
        ElicitContentValue, ElicitMode, ElicitRequestFormParams, ElicitRequestParams,
        ElicitRequestUrlParams, ElicitRequestedSchema, ElicitResult, ElicitationCapability,
        ElicitationRequiredErrorData, FormElicitationCapability, GetPromptParams, GetPromptResult,
        Icon, IncludeContext, InitializeParams, InitializeResult, JsonRpcMessage, JsonRpcRequest,
        JsonRpcResponse, LegacyCompletionArgument, LegacyCompletionParams,
        LegacyCompletionReference, LegacyCompletionResult, LegacyContent, LegacyCoreRequest,
        LegacyCoreResult, LegacyEmptyResult, LegacyMetadata, LegacyOpaqueMetadata,
        LegacyPromptMessage, LegacyResourceContent, ListPromptsParams, ListPromptsResult,
        ListResourceTemplatesParams, ListResourceTemplatesResult, ListResourcesParams,
        ListResourcesResult, ListRootsParams, ListRootsResult, ListToolsParams, ListToolsResult,
        LogLevel, LogMessageParams, LoggingCapability, PROTOCOL_VERSION, ProgressMarker,
        ProgressParams, Prompt, PromptArgument, PromptsCapability, ReadResourceParams,
        ReadResourceResult, RequestId, RequestMeta, Resource, ResourceContent, ResourceTemplate,
        ResourceUpdatedNotificationParams, ResourcesCapability, Root, RootsCapability,
        SamplingCapability, SamplingContent, SamplingMessage, ServerCapabilities, ServerInfo,
        SetLogLevelParams, SubscribeResourceParams, TaskId, TaskInfo, TaskResult, TaskStatus,
        TaskStatusNotificationParams, TasksCapability, Tool, ToolAnnotations, ToolsCapability,
        UnsubscribeResourceParams, UrlElicitationCapability,
    };
    pub use fastmcp_server::legacy_2024::{
        LEGACY_2024_MAX_ADAPTER_RESERVATIONS, Legacy2024AdapterError, Legacy2024Handler,
        Legacy2024HandlerError, Legacy2024Lifecycle, Legacy2024LiveServerLifecycle,
        Legacy2024Outbound, Legacy2024ServerAdapter, Legacy2024ServerConfig, Legacy2024ServerInfo,
        Legacy2024StateSnapshot, LegacyAuthenticatedPeerPartition, LegacyPeerBinding,
        LegacyServerAdapterInstalledReceipt,
        LegacyServerAdapterInstalledReceipt as ServerAdapterInstalledReceipt,
        legacy_2024_a_digest_preimage, legacy_2024_b_digest_preimage,
    };
    pub use fastmcp_server::{
        CompletionHandler, PromptHandler, ResourceHandler, ToolErrorKind, ToolHandler,
    };
    pub use fastmcp_transport::sse::{
        LegacySseClientTransport, LegacySseMessagePost, LegacySsePostSink, LegacySseServerTransport,
    };
    pub use serde_json::{self, Map as JsonMap, Value as JsonValue, json};

    /// Creates a client builder pinned to the exact MCP 2024-11-05 stdio plan.
    ///
    /// The historical root [`Client::stdio`] behavior remains unchanged; this
    /// names the same explicit legacy selection in the dual-era facade.
    #[must_use]
    pub fn client_builder() -> ClientBuilder {
        ClientBuilder::new().protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly))
    }
}

// REL-QUAR-00 release-quarantine evidence surface
pub mod release_quarantine;

// Testing module
pub mod testing;

/// Prelude module for convenient imports.
///
/// ```ignore
/// use fastmcp_rust::prelude::*;
/// ```
pub mod prelude {
    pub use crate::{
        // Context and errors
        AccessToken,
        AdmittedSchema,
        AuthContext,
        BoundHttpServer,
        // Client
        BoundedListPage,
        CancellationSender,
        CancellationWireCodecError,
        CancellationWireMessage,
        CanonicalHttpUrl,
        Client,
        ClientBuilder,
        ClientCapabilities,
        ClientHttpConnection,
        ClientHttpConnectionError,
        ClientHttpNegotiation,
        ClientHttpNegotiationDecision,
        ClientHttpNegotiationError,
        ClientHttpNegotiationState,
        ClientHttpResponse,
        ClientInfo,
        ClientNotification,
        ClientProtocolPlan,
        ClientProtocolPlanError,
        ClientSession,
        CompleteResult,
        CompletionContext,
        CompletionHandler,
        CompletionParams,
        CompletionReference,
        ConfigError,
        ConfigLoader,
        // Protocol types
        Content,
        ContentBlock,
        Cx,
        DecodedResult,
        DualEraHttpEndpoint,
        DualEraHttpEndpointConfig,
        DualEraHttpEndpointError,
        DuplicateBehavior,
        ExtensionDescriptor,
        ExtensionDescriptorRegistry,
        ExtensionSettings,
        ExtensionSettingsCompatibilityResolver,
        ExtensionSettingsResolution,
        FINAL_JSON_SCHEMA_DIALECT,
        FINAL_PROTOCOL_VERSION,
        Final2026Peer,
        FinalAbsoluteUri,
        FinalArguments,
        FinalCallToolResult,
        FinalCancelledNotificationParams,
        FinalCoreResultType,
        FinalCreateMessageParams,
        FinalCreateMessageResult,
        FinalEmbeddedCreateMessageParams,
        FinalEmbeddedElicitationParams,
        FinalEmbeddedElicitationResult,
        FinalEmbeddedFormElicitationParams,
        FinalEmbeddedInputKind,
        FinalEmbeddedInputRequest,
        FinalEmbeddedInputResponse,
        FinalEmbeddedRootsListParams,
        FinalEmbeddedRootsListResult,
        FinalEmbeddedUrlElicitationParams,
        FinalEmptyNotificationParams,
        FinalGetPromptResult,
        FinalLogMessageParams,
        FinalNotificationError,
        FinalProgressNotificationParams,
        FinalProtocolVersion,
        FinalReadResourceResult,
        FinalResourceUpdatedNotificationParams,
        FinalSubscriptionsAcknowledgedNotificationParams,
        FinalTask,
        FinalTaskCallToolResult,
        FinalTaskId,
        FinalTaskInputResponses,
        FinalTaskStatusNotification,
        FinalToolCallOutcome,
        FinalToolOutcome,
        FinalUpdateTaskResult,
        HttpClient,
        HttpClientError,
        HttpEndpointBundle,
        HttpEndpointBundleError,
        HttpEndpointConfig,
        HttpEndpointConfigError,
        HttpError,
        HttpHandlerConfig,
        HttpMethod,
        HttpRequest,
        HttpRequestHandler,
        HttpResponse,
        HttpServerConfig,
        HttpStatus,
        HttpSubscriptionListener,
        // Server
        InboundRequestContext,
        InboundRequestTransport,
        JsonMap,
        JsonSchema,
        JsonValue,
        ListPageLimits,
        LoggingConfig,
        MAX_MCP_APPS_CSP_DOMAIN_BYTES,
        MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE,
        MAX_MCP_APPS_TOOL_VISIBILITY_ENTRIES,
        MAX_MCP_APPS_UI_METADATA_MEMBERS,
        MCP_APPS_DEPRECATED_RESOURCE_URI_METADATA_KEY,
        MCP_APPS_UI_METADATA_KEY,
        McpAppsClientSettings,
        McpAppsDisplayMode,
        McpAppsLifecycleError,
        McpAppsMetadataError,
        McpAppsNegotiationResolver,
        McpAppsResourceBinding,
        McpAppsResourceBindingError,
        McpAppsResourceCsp,
        McpAppsResourceMetadata,
        McpAppsResourcePermission,
        McpAppsResourcePermissions,
        McpAppsResultProjectionError,
        McpAppsToolMetadata,
        McpAppsToolResult,
        McpAppsToolVisibility,
        McpAppsViewLifecycle,
        McpConfig,
        McpContext,
        McpError,
        McpOutcome,
        McpResult,
        Middleware,
        MiddlewareDecision,
        ModernHttpClient,
        ModernHttpClientError,
        ModernHttpConnectOutcome,
        ModernHttpExecutor,
        ModernHttpExecutorError,
        ModernHttpRequest,
        ModernHttpResponseStream,
        ModernHttpSubscriptionListenCollector,
        ModernHttpSubscriptionListenError,
        ModernHttpSubscriptionListenEvent,
        ModernHttpSubscriptionListener,
        NegotiatedExtensionSet,
        OFFICIAL_TASKS_RESULT_DISCRIMINATOR,
        OfficialTasksNegotiationResolver,
        // Outcome types (4-valued result)
        Outcome,
        OutcomeExt,
        ProgressMarker,
        Prompt,
        PromptArgument,
        PromptMessage,
        ProtocolEra,
        ProtocolPolicy,
        ProtocolVersion,
        ProxyBackend,
        ProxyCatalog,
        ProxyClient,
        ProxyPromptCatalog,
        ProxyResourceCatalog,
        ProxyResourceTemplateCatalog,
        ProxyToolCatalog,
        ProxyTypedCatalog,
        RequestAdmissionError,
        RequestId,
        RequestTimeoutPolicy,
        RequestTimeoutSource,
        Resource,
        ResourceContent,
        ResultExt,
        Role,
        SchemaAdmissionError,
        Server,
        ServerBehavior,
        ServerBehaviorRegistry,
        ServerConfig,
        ServerDiscoverRequest,
        ServerDiscoverResult,
        ServerHttpEndpoint,
        ServerHttpEndpointResponse,
        ServerHttpSession,
        ServerNotification,
        SseEndOfStream,
        SseLimits,
        SseParseError,
        StaticTokenVerifier,
        SubscriptionFilter,
        SubscriptionListenCollector,
        TASK_UPDATE,
        TemplateValue,
        TemplateValues,
        TokenAuthProvider,
        TokenVerifier,
        Tool,
        TransportRecvHalf,
        TransportSendHalf,
        TwoPhaseTransport,
        UriTemplate,
        UriTemplateError,
        UriTemplateExpansionLimits,
        ValidationError,
        ValidationResult,
        admit_final_schema,
        auto,
        cancelled,
        err,
        legacy_2024,
        modern,
        official_tasks_descriptor,
        official_tasks_empty_settings,
        ok,
        project_final_core_tools_call_result,
        // Macros
        prompt,
        providers::FilesystemProvider,
        register_official_tasks_extension,
        resource,
        schema,
        tasks_extension,
        tool,
        validate_final_core_result,
    };
    pub use crate::{
        ApplicationTaskSupervisor, AuthorizedTaskServiceRunner, CachePartitionKey,
        ClientCapabilityInfo, ContextNotificationSender, DEFAULT_FINAL_CACHE_CAPACITY,
        DEFAULT_FINAL_CACHE_MAX_BYTES, DEFAULT_IN_MEMORY_FINAL_TASKS, ElicitationAction,
        ElicitationMode, ElicitationRequest, ElicitationResponse, ElicitationSender,
        FinalCacheGeneration, FinalCacheInsert, FinalCacheKey, FinalCacheLookup, FinalCacheMiss,
        FinalCacheResultSet, FinalCacheStats, FinalCacheTtlDiagnostic, FinalResultCache,
        FinalTaskAcceptedInput, FinalTaskInitialWork, FinalTaskRetentionAuthority,
        FinalTaskSnapshot, FinalTaskSupervisorFuture, FinalTaskSupervisorHandoff,
        FinalTaskWorkDescriptor, InMemoryFinalTaskStore, JsonRpcAdmissionError, JsonRpcMessage,
        MAX_FINAL_CACHE_CAPACITY, MAX_FINAL_CACHE_MAX_BYTES, MAX_RESOURCE_READ_DEPTH,
        MAX_TOOL_CALL_DEPTH, McpContextLeaseGuard, McpRequestCancellation, NoOpElicitationSender,
        NoOpNotificationSender, NoOpSamplingSender, PendingRequests, ProgressReporter,
        PromptHandler, RequestSender, ResourceContentItem, ResourceHandler, ResourceReadResult,
        ResourceReader, SamplingRequest, SamplingRequestMessage, SamplingResponse, SamplingRole,
        SamplingSender, SamplingStopReason, ServerCapabilityInfo, ToolCallResult, ToolCaller,
        ToolContentItem, ToolHandler, TransportElicitationSender, TransportRootsProvider,
        TransportSamplingSender, block_on, decode_strict_jsonrpc_message,
    };
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{RequestTimeoutPolicy, RequestTimeoutSource};

    #[test]
    fn facade_reexports_client_timeout_types() {
        let policy = RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(5))
            .expect("facade timeout policy must validate");

        assert_eq!(policy.idle_timeout(), Duration::from_secs(2));
        assert_eq!(policy.absolute_timeout(), Duration::from_secs(5));
        assert_ne!(RequestTimeoutSource::Idle, RequestTimeoutSource::Absolute);
    }

    #[test]
    fn facade_component_namespaces_and_era_modules_cover_the_complete_surface() {
        let _: Option<super::client::FinalResultCache> = None;
        let _: Option<super::core::ProtocolLimits> = None;
        let _: Option<super::protocol::uri_template::UriTemplate> = None;
        let _: Option<super::server::ServerLaunchPolicyError> = None;
        let _: Option<super::transport::ModernSseDecoder> = None;
        let _: Option<super::asupersync::Cx> = None;
        let _: Option<super::serde_json::Value> = None;

        let _: Option<super::legacy_2024::InitializeParams> = None;
        let _: Option<super::legacy_2024::TaskInfo> = None;
        let _: Option<super::modern::FinalCallToolParams> = None;
    }

    #[test]
    fn final_cache_api_is_reexported_from_root_modern_and_prelude() {
        use super::{
            CachePartitionKey, DEFAULT_FINAL_CACHE_CAPACITY, DEFAULT_FINAL_CACHE_MAX_BYTES,
            FinalCacheGeneration, FinalCacheInsert, FinalCacheKey, FinalCacheLookup,
            FinalCacheMiss, FinalCacheResultSet, FinalCacheStats, FinalCacheTtlDiagnostic,
            FinalResultCache, MAX_FINAL_CACHE_CAPACITY, MAX_FINAL_CACHE_MAX_BYTES, modern, prelude,
        };

        let _: Option<CachePartitionKey> = None;
        let _: Option<FinalCacheGeneration> = None;
        let _: Option<FinalCacheInsert> = None;
        let _: Option<FinalCacheKey> = None;
        let _: Option<FinalCacheLookup> = None;
        let _: Option<FinalCacheMiss> = None;
        let _: Option<FinalCacheResultSet> = None;
        let _: Option<FinalCacheStats> = None;
        let _: Option<FinalCacheTtlDiagnostic> = None;
        let _: Option<FinalResultCache> = None;
        let _: usize = DEFAULT_FINAL_CACHE_CAPACITY;
        let _: usize = DEFAULT_FINAL_CACHE_MAX_BYTES;
        let _: usize = MAX_FINAL_CACHE_CAPACITY;
        let _: usize = MAX_FINAL_CACHE_MAX_BYTES;

        let _: Option<modern::CachePartitionKey> = None;
        let _: Option<modern::FinalCacheGeneration> = None;
        let _: Option<modern::FinalCacheInsert> = None;
        let _: Option<modern::FinalCacheKey> = None;
        let _: Option<modern::FinalCacheLookup> = None;
        let _: Option<modern::FinalCacheMiss> = None;
        let _: Option<modern::FinalCacheResultSet> = None;
        let _: Option<modern::FinalCacheStats> = None;
        let _: Option<modern::FinalCacheTtlDiagnostic> = None;
        let _: Option<modern::FinalResultCache> = None;
        let _: usize = modern::DEFAULT_FINAL_CACHE_CAPACITY;
        let _: usize = modern::DEFAULT_FINAL_CACHE_MAX_BYTES;
        let _: usize = modern::MAX_FINAL_CACHE_CAPACITY;
        let _: usize = modern::MAX_FINAL_CACHE_MAX_BYTES;

        let _: Option<prelude::CachePartitionKey> = None;
        let _: Option<prelude::FinalCacheGeneration> = None;
        let _: Option<prelude::FinalCacheInsert> = None;
        let _: Option<prelude::FinalCacheKey> = None;
        let _: Option<prelude::FinalCacheLookup> = None;
        let _: Option<prelude::FinalCacheMiss> = None;
        let _: Option<prelude::FinalCacheResultSet> = None;
        let _: Option<prelude::FinalCacheStats> = None;
        let _: Option<prelude::FinalCacheTtlDiagnostic> = None;
        let _: Option<prelude::FinalResultCache> = None;
        let _: usize = prelude::DEFAULT_FINAL_CACHE_CAPACITY;
        let _: usize = prelude::DEFAULT_FINAL_CACHE_MAX_BYTES;
        let _: usize = prelude::MAX_FINAL_CACHE_CAPACITY;
        let _: usize = prelude::MAX_FINAL_CACHE_MAX_BYTES;
    }

    #[test]
    fn facade_reexports_rfc6570_and_era_selected_cancellation_types() {
        use super::{
            CancellationWireMessage, TemplateValue, TemplateValues, UriTemplate, auto, legacy_2024,
            modern, prelude,
        };

        let template = UriTemplate::parse("https://example.test/{path}{?query}")
            .expect("facade URI template parses");
        let mut values = TemplateValues::new();
        values.insert("path".to_owned(), TemplateValue::scalar("reports/2026"));
        values.insert("query".to_owned(), TemplateValue::scalar("open"));
        assert_eq!(
            template.expand(&values).expect("facade template expands"),
            "https://example.test/reports%2F2026?query=open"
        );

        let _: Option<modern::UriTemplate> = None;
        let _: Option<auto::UriTemplate> = None;
        let _: Option<prelude::UriTemplate> = None;
        let _: Option<CancellationWireMessage> = None;
        let _: Option<legacy_2024::CancellationWireMessage> = None;
        let _: Option<prelude::CancellationWireMessage> = None;
    }

    #[test]
    fn prelude_reexports_client_timeout_configuration_surface() {
        use super::prelude::{
            Client, ClientBuilder, ClientHttpNegotiation, ClientSession, CompleteResult,
            HttpClient, HttpClientError, McpConfig, ModernHttpRequest, RequestTimeoutPolicy,
            RequestTimeoutSource, legacy_2024, modern,
        };

        let _: ClientBuilder = Client::builder();
        let policy = RequestTimeoutPolicy::new(Duration::from_secs(3), Duration::from_secs(7))
            .expect("prelude timeout policy must validate");

        assert_eq!(policy.idle_timeout(), Duration::from_secs(3));
        assert_eq!(policy.absolute_timeout(), Duration::from_secs(7));
        let source: RequestTimeoutSource = RequestTimeoutSource::Idle;
        assert!(matches!(source, RequestTimeoutSource::Idle));
        let _ = std::mem::size_of::<ClientSession>();
        let _: Option<ClientHttpNegotiation> = None;
        let _: Option<CompleteResult<()>> = None;
        assert!(McpConfig::new().server_names().is_empty());
        assert!(
            ModernHttpRequest::new(
                "https://mcp.example.test/mcp",
                b"{}".to_vec(),
                modern::PROTOCOL_VERSION,
                modern::SERVER_DISCOVER_METHOD,
                None,
            )
            .is_ok()
        );

        let _: Option<modern::FinalCallToolParams> = None;
        let _: Option<modern::FinalCallToolResult> = None;
        let _: Option<modern::ClientInfo> = None;
        let _: Option<modern::RequestId> = None;
        let _: Option<modern::HttpClient> = None;
        let _: Option<modern::MrtrExchangeRegistry> = None;
        let _: Option<legacy_2024::CallToolParams> = None;
        let _: Option<legacy_2024::LegacySseHttpClient> = None;
        let _: Option<HttpClient> = None;
        let _: Option<HttpClientError> = None;
    }

    #[test]
    fn facade_exports_lifecycle_owning_http_client_types_in_every_client_surface() {
        use super::{HttpClient, HttpClientError, auto, legacy_2024, modern};

        let _: Option<HttpClient> = None;
        let _: Option<HttpClientError> = None;
        let _: Option<auto::HttpClient> = None;
        let _: Option<auto::HttpClientError> = None;
        let _: Option<modern::HttpClient> = None;
        let _: Option<modern::HttpClientConnectError> = None;
        let _: Option<legacy_2024::HttpClient> = None;
        let _: Option<legacy_2024::HttpClientError> = None;
    }

    #[test]
    fn api_01_public_auto_and_modern_surfaces_compile() {
        use super::{auto, modern};

        let auto_builder = auto::client_builder();
        assert_eq!(
            auto_builder.selected_protocol_plan().policy(),
            auto::ProtocolPolicy::Auto
        );

        let explicit_modern_builder = modern::client_builder();
        assert_eq!(
            explicit_modern_builder.protocol_policy(),
            modern::ModernOnly
        );
        let _: modern::ClientBuilder = explicit_modern_builder;

        let explicit_modern_server_builder = modern::server_builder("final-only", "1.0.0");
        assert_eq!(
            explicit_modern_server_builder.protocol_policy(),
            modern::ModernOnly
        );
        let _: modern::Server = explicit_modern_server_builder.build();

        let _: Option<modern::ServerBuilder> = None;
        let _: Option<modern::ServerDiscoverRequest> = None;
        let _: Option<modern::ExtensionDescriptorRegistry> = None;
        let _: Option<modern::Cx> = None;
        assert_eq!(modern::PROTOCOL_VERSION, "2026-07-28");
    }

    #[test]
    fn api_01_exact_2024_surface_remains_explicit_and_available() {
        use super::legacy_2024;

        let partition = legacy_2024::LegacyAuthenticatedPeerPartition::from_authenticated_transport(
            [0_u8; legacy_2024::LegacyAuthenticatedPeerPartition::BYTE_LEN],
        );
        let binding = legacy_2024::LegacyPeerBinding::from_authenticated_transport(partition, 7);

        assert_eq!(binding.generation(), 7);
        assert_eq!(legacy_2024::PROTOCOL_VERSION, "2024-11-05");
        let _: Option<legacy_2024::InitializeParams> = None;
        let _: Option<legacy_2024::CallToolParams> = None;
        let _: Option<legacy_2024::Legacy2024Lifecycle> = None;
        let _: Option<legacy_2024::LegacySseHttpClient> = None;
        let _: Option<legacy_2024::LegacySseMessagePost> = None;
    }

    #[test]
    fn exact_legacy_result_item_vocabulary_matches_result_fields() {
        use super::legacy_2024;

        fn call_tool_items(result: legacy_2024::CallToolResult) -> Vec<legacy_2024::LegacyContent> {
            result.content
        }

        fn read_resource_items(
            result: legacy_2024::ReadResourceResult,
        ) -> Vec<legacy_2024::LegacyResourceContent> {
            result.contents
        }

        fn get_prompt_items(
            result: legacy_2024::GetPromptResult,
        ) -> Vec<legacy_2024::LegacyPromptMessage> {
            result.messages
        }

        let _: fn(legacy_2024::CallToolResult) -> Vec<legacy_2024::LegacyContent> = call_tool_items;
        let _: fn(legacy_2024::ReadResourceResult) -> Vec<legacy_2024::LegacyResourceContent> =
            read_resource_items;
        let _: fn(legacy_2024::GetPromptResult) -> Vec<legacy_2024::LegacyPromptMessage> =
            get_prompt_items;

        let _: Option<super::Content> = None;
        let _: Option<super::ResourceContent> = None;
        let _: Option<super::PromptMessage> = None;
    }

    #[test]
    fn api_02_facade_exposes_shipped_final_product_surface() {
        use super::{legacy_2024, modern};

        let uri = modern::AbsoluteUri::parse("https://mcp.example.test/final")
            .expect("facade must expose final common URI admission");
        assert_eq!(uri.as_str(), "https://mcp.example.test/final");

        let behaviors =
            modern::ServerBehaviorRegistry::from_behaviors([modern::ServerBehavior::ToolsList]);
        assert!(behaviors.contains(modern::ServerBehavior::ToolsList));
        assert!(
            modern::ExtensionDescriptorRegistry::new()
                .receipt()
                .is_none()
        );
        assert!(matches!(
            modern::parse_exact_json(r#"{"complete":true}"#),
            Ok(modern::ExactJsonValue::Object(_))
        ));

        let _: Option<modern::CompleteResult<()>> = None;
        let _: Option<modern::ContentBlock> = None;
        let final_meta = modern::FinalRequestMeta::new(modern::ClientCapabilities::default());
        assert_eq!(final_meta.protocol_version, modern::PROTOCOL_VERSION);
        let _: Option<modern::ClientInfo> = None;
        let _: Option<modern::RequestId> = None;
        let _: &str = modern::FINAL_PROTOCOL_VERSION_META_KEY;
        let _: &str = modern::FINAL_CLIENT_CAPABILITIES_META_KEY;
        let _: &str = modern::FINAL_CLIENT_INFO_META_KEY;
        let _: &str = modern::FINAL_SERVER_INFO_META_KEY;
        let _: Option<modern::FinalListParams> = None;
        let _: Option<modern::FinalCallToolParams> = None;
        let _: Option<modern::FinalReadResourceParams> = None;
        let _: Option<modern::FinalGetPromptParams> = None;
        let _: Option<modern::FinalEmptyParams> = None;
        let _: Option<modern::FinalListToolsResult> = None;
        let _: Option<modern::FinalCallToolResult> = None;
        let _: Option<modern::FinalListResourcesResult> = None;
        let _: Option<modern::FinalListResourceTemplatesResult> = None;
        let _: Option<modern::FinalReadResourceResult> = None;
        let _: Option<modern::FinalListPromptsResult> = None;
        let _: Option<modern::FinalPromptMessage> = None;
        let _: Option<modern::FinalGetPromptResult> = None;
        let _: Option<modern::FinalEmptyResult> = None;
        let _: Option<modern::FinalCoreRequest> = None;
        let _: Option<modern::FinalCoreResult> = None;
        let _: Option<modern::ClientNotification> = None;
        let _: Option<modern::ServerNotification> = None;
        let _: Option<modern::FinalNotificationError> = None;
        let _: Option<modern::Final2026Peer> = None;
        let _: Option<modern::FinalCancelledNotificationParams> = None;
        let _: Option<modern::FinalProgressNotificationParams> = None;
        let _: Option<modern::FinalLogMessageParams> = None;
        let _: Option<modern::FinalResourceUpdatedNotificationParams> = None;
        let _: Option<modern::FinalEmptyNotificationParams> = None;
        let _: Option<modern::FinalSubscriptionsAcknowledgedNotificationParams> = None;
        let _: Option<modern::HttpClient> = None;
        let _: Option<modern::HttpClientConnectError> = None;
        let _: Option<modern::ModernHttpClientError> = None;
        let _: Option<super::FinalRequestMeta> = None;
        let _: Option<super::ClientNotification> = None;
        let _: Option<super::ServerNotification> = None;
        let _: Option<super::FinalNotificationError> = None;
        let _: Option<super::Final2026Peer> = None;
        let _: Option<super::FinalCancelledNotificationParams> = None;
        let _: Option<super::FinalProgressNotificationParams> = None;
        let _: Option<super::FinalLogMessageParams> = None;
        let _: Option<super::FinalResourceUpdatedNotificationParams> = None;
        let _: Option<super::FinalEmptyNotificationParams> = None;
        let _: Option<super::FinalSubscriptionsAcknowledgedNotificationParams> = None;
        let _: Option<super::ModernHttpClient> = None;
        let _: Option<super::MrtrExchangeRegistry> = None;
        let _: Option<super::FinalToolOutcome> = None;
        let _: Option<modern::FinalToolOutcome> = None;
        let _: Option<super::LegacySseHttpClient> = None;
        let mrtr_requests = modern::MrtrInputRequests::new([(
            "roots".to_owned(),
            modern::MrtrInputRequest::roots(),
        )])
        .expect("facade must expose final MRTR request construction");
        assert_eq!(mrtr_requests.len(), 1);
        let _mrtr_registry = modern::MrtrExchangeRegistry::new();
        assert_eq!(
            modern::DEFAULT_MAX_MRTR_ROUNDS,
            super::DEFAULT_MAX_MRTR_ROUNDS
        );
        let _: Option<legacy_2024::Legacy2024LiveServerLifecycle<(), ()>> = None;
        let _: Option<legacy_2024::LegacySseHttpClientError> = None;
    }

    #[test]
    fn prelude_reexports_final_directional_notification_surface() {
        use super::prelude::{
            ClientNotification, Final2026Peer, FinalCancelledNotificationParams,
            FinalEmptyNotificationParams, FinalLogMessageParams, FinalNotificationError,
            FinalProgressNotificationParams, FinalResourceUpdatedNotificationParams,
            FinalSubscriptionsAcknowledgedNotificationParams, FinalToolOutcome, ServerNotification,
        };

        let _: Option<ClientNotification> = None;
        let _: Option<ServerNotification> = None;
        let _: Option<FinalNotificationError> = None;
        let _: Option<Final2026Peer> = None;
        let _: Option<FinalCancelledNotificationParams> = None;
        let _: Option<FinalProgressNotificationParams> = None;
        let _: Option<FinalLogMessageParams> = None;
        let _: Option<FinalResourceUpdatedNotificationParams> = None;
        let _: Option<FinalEmptyNotificationParams> = None;
        let _: Option<FinalSubscriptionsAcknowledgedNotificationParams> = None;
        let _: Option<FinalToolOutcome> = None;
    }

    #[test]
    fn modern_facade_exposes_final_only_client_and_http_contracts() {
        use std::collections::HashMap;

        use super::{
            Client, FinalCallToolResult, FinalGetPromptResult, FinalReadResourceResult,
            FinalToolCallOutcome,
        };
        use super::{JsonValue, McpResult, auto, legacy_2024, modern};

        let _: fn(&mut Client, &str, JsonValue) -> McpResult<FinalCallToolResult> =
            Client::call_tool_final;
        let _: fn(&mut Client, &str, JsonValue) -> McpResult<FinalToolCallOutcome> =
            Client::call_tool_final_outcome;
        let _: fn(&mut Client, &str) -> McpResult<FinalReadResourceResult> =
            Client::read_resource_final;
        let _: fn(&mut Client, &str, HashMap<String, String>) -> McpResult<FinalGetPromptResult> =
            Client::get_prompt_final;
        let _: fn(
            &mut Client,
            modern::SubscriptionFilter,
        ) -> McpResult<modern::SubscriptionListenCollector> = Client::listen_subscriptions_typed;
        let _: fn(
            &mut auto::Client,
            &str,
            auto::JsonValue,
        ) -> auto::McpResult<auto::FinalCallToolResult> = auto::Client::call_tool_final;
        let _: fn(&mut modern::Client, &str) -> modern::McpResult<modern::FinalReadResourceResult> =
            modern::Client::read_resource;
        let _: fn(
            &mut modern::Client,
            Option<&str>,
        ) -> modern::McpResult<modern::FinalListToolsResult> = modern::Client::list_tools;
        let _: fn(
            &mut modern::Client,
            Option<&str>,
        ) -> modern::McpResult<modern::FinalListResourcesResult> = modern::Client::list_resources;
        let _: fn(
            &mut modern::Client,
            Option<&str>,
        ) -> modern::McpResult<modern::FinalListResourceTemplatesResult> =
            modern::Client::list_resource_templates;
        let _: fn(
            &mut modern::Client,
            Option<&str>,
        ) -> modern::McpResult<modern::FinalListPromptsResult> = modern::Client::list_prompts;
        let _: fn(
            &mut modern::Client,
            modern::CompletionParams,
        ) -> modern::McpResult<modern::FinalCompletionResult> = modern::Client::complete;
        let _: fn(
            &mut modern::Client,
            modern::SubscriptionFilter,
        ) -> modern::McpResult<modern::SubscriptionListenCollector> =
            modern::Client::listen_subscriptions;
        let _: fn(&mut modern::Client) -> Vec<modern::FinalProgressNotificationParams> =
            modern::Client::take_progress_notifications;
        let _: fn(
            &mut modern::Client,
            modern::FinalTaskId,
        ) -> modern::McpResult<modern::FinalGetTaskResult> = modern::Client::get_task;
        let _: fn(
            &mut modern::Client,
            &modern::FinalTask,
            modern::FinalTaskInputResponses,
        ) -> modern::McpResult<modern::FinalUpdateTaskResult> = modern::Client::update_task;
        let _: fn(
            &mut modern::Client,
            modern::FinalTaskId,
        ) -> modern::McpResult<modern::FinalCancelTaskResult> = modern::Client::cancel_task;
        let _: fn(modern::ServerBuilder, modern::FinalResourceTemplate) -> modern::ServerBuilder =
            modern::ServerBuilder::resource_template;
        let _ = modern::HttpClient::connect;
        let _ = modern::Server::bind_http;
        let _ = modern::Server::serve_http;

        let auto_builder = auto::client_builder();
        assert_eq!(
            auto_builder.selected_protocol_plan().policy(),
            auto::ProtocolPolicy::Auto
        );
        let legacy_builder = legacy_2024::client_builder();
        assert_eq!(
            legacy_builder.selected_protocol_plan().policy(),
            legacy_2024::ProtocolPolicy::LegacyOnly
        );
        let _: fn(&str, &[&str]) -> McpResult<legacy_2024::Client> = legacy_2024::Client::stdio;

        let _: Option<auto::ClientHttpConnection> = None;
        let _: Option<auto::ModernHttpSubscriptionListenCollector> = None;
        let _: Option<auto::ModernHttpSubscriptionListenError> = None;
        let _: Option<auto::SseLimits> = None;
        let _: Option<modern::HttpServer> = None;
    }

    #[test]
    fn api_03_facade_exposes_modern_tasks_extension_contracts() {
        use super::{
            Client, FinalCancelTaskResult, FinalGetTaskResult, FinalTask, FinalTaskId,
            FinalTaskInputResponses, FinalUpdateTaskResult, McpResult, SubscriptionFilter, auto,
            modern,
        };

        let task_id = modern::FinalTaskId::parse("task-42")
            .expect("facade must expose final task identifier admission");
        let mut filter = SubscriptionFilter::default();
        modern::set_task_subscription_ids(&mut filter, vec![task_id.clone()])
            .expect("facade must compose the negotiated Tasks subscription fragment");
        let selected = modern::task_subscription_ids(&filter)
            .expect("facade must decode the negotiated Tasks subscription fragment")
            .expect("Tasks subscription fragment must remain present");
        assert_eq!(selected, vec![task_id]);

        let _: fn(&mut Client, FinalTaskId) -> McpResult<FinalGetTaskResult> =
            Client::get_task_final;
        let _: fn(
            &mut Client,
            &FinalTask,
            FinalTaskInputResponses,
        ) -> McpResult<FinalUpdateTaskResult> = Client::update_task_final;
        let _: fn(&mut Client, FinalTaskId) -> McpResult<FinalCancelTaskResult> =
            Client::cancel_task_final;
        let _: fn(
            &mut auto::Client,
            auto::FinalTaskId,
        ) -> auto::McpResult<auto::FinalGetTaskResult> = auto::Client::get_task_final;
        let _: Option<auto::FinalTask> = None;
        let _: Option<auto::FinalTaskInputResponses> = None;
        let _: Option<auto::FinalUpdateTaskResult> = None;
        let _: Option<modern::FinalTaskStatusNotification> = None;
        assert_eq!(super::TASK_UPDATE, "tasks/update");
        assert_eq!(modern::TASK_UPDATE, super::TASK_UPDATE);
        assert_eq!(super::prelude::TASK_UPDATE, super::TASK_UPDATE);
        let _: Option<modern::FinalTaskRuntime> = None;
        let _: Option<modern::ExtensionHandlerRegistry> = None;
    }

    #[test]
    fn api_03_facade_exposes_schema_admission_reverse_handlers_and_tasks_resolver() {
        use super::{
            AdmittedSchema, ExtensionSettingsCompatibilityResolver, FinalCoreResultType,
            OfficialTasksNegotiationResolver, SchemaAdmissionError, ValidationResult,
            admit_final_schema, auto, legacy_2024, modern, prelude, validate_final_core_result,
        };

        let _: fn(super::JsonValue) -> Result<AdmittedSchema, SchemaAdmissionError> =
            admit_final_schema;
        let _: fn(&AdmittedSchema, &super::JsonValue, FinalCoreResultType) -> ValidationResult =
            validate_final_core_result;
        let descriptor = modern::official_tasks_descriptor();
        let settings = modern::official_tasks_empty_settings();
        let mut resolver = OfficialTasksNegotiationResolver;
        let effective = resolver
            .resolve(&descriptor, &settings, &settings)
            .expect("the official Tasks resolver must accept its own empty settings");
        assert!(effective.as_object().is_empty());
        assert_eq!(
            modern::OFFICIAL_TASKS_RESULT_DISCRIMINATOR,
            super::OFFICIAL_TASKS_RESULT_DISCRIMINATOR
        );
        assert_eq!(auto::TASK_UPDATE, super::TASK_UPDATE);
        assert_eq!(prelude::TASK_UPDATE, super::TASK_UPDATE);
        assert_eq!(
            auto::FINAL_JSON_SCHEMA_DIALECT,
            super::FINAL_JSON_SCHEMA_DIALECT
        );
        assert_eq!(
            modern::FINAL_JSON_SCHEMA_DIALECT,
            super::FINAL_JSON_SCHEMA_DIALECT
        );
        assert_eq!(
            prelude::FINAL_JSON_SCHEMA_DIALECT,
            super::FINAL_JSON_SCHEMA_DIALECT
        );

        let _: fn(auto::JsonValue) -> Result<auto::AdmittedSchema, auto::SchemaAdmissionError> =
            auto::admit_final_schema;
        let _: fn(
            modern::JsonValue,
        ) -> Result<modern::AdmittedSchema, modern::SchemaAdmissionError> =
            modern::admit_final_schema;
        let _: fn(
            prelude::JsonValue,
        ) -> Result<prelude::AdmittedSchema, prelude::SchemaAdmissionError> =
            prelude::admit_final_schema;
        let _: Option<auto::AdmittedSchema> = None;
        let _: Option<auto::OfficialTasksNegotiationResolver> = None;
        let _: Option<auto::FinalTaskStatusNotification> = None;
        let _: Option<modern::AdmittedSchema> = None;
        let _: Option<modern::OfficialTasksNegotiationResolver> = None;
        let _: Option<prelude::AdmittedSchema> = None;
        let _: Option<prelude::OfficialTasksNegotiationResolver> = None;
        let _: Option<legacy_2024::LegacyReverseRequestHandlers> = None;
        let _: Option<legacy_2024::LegacySamplingRequestHandler> = None;
        let _: Option<legacy_2024::LegacyRootsRequestHandler> = None;
        let _: Option<legacy_2024::LegacyCreateMessageParams> = None;
        let _: Option<legacy_2024::LegacyCreateMessageResult> = None;
        let _: Option<legacy_2024::LegacyListRootsParams> = None;
        let _: Option<legacy_2024::LegacyListRootsResult> = None;
        let _: Option<legacy_2024::LegacyElicitRequestParams> = None;
        let _: Option<legacy_2024::LegacyElicitResult> = None;
    }

    #[test]
    fn api_03_facade_separates_reverse_request_wire_eras() {
        use super::{
            FinalCreateMessageParams, FinalCreateMessageResult, FinalEmbeddedCreateMessageParams,
            FinalEmbeddedElicitationParams, FinalEmbeddedElicitationResult,
            FinalEmbeddedRootsListParams, FinalEmbeddedRootsListResult, RequestSender, Server,
            ServerBuilder, TransportElicitationSender, TransportRootsProvider,
            TransportSamplingSender, legacy_2024, modern, prelude,
        };

        let _: Option<FinalCreateMessageParams> = None;
        let _: Option<FinalCreateMessageResult> = None;
        let _: Option<FinalEmbeddedCreateMessageParams> = None;
        let _: Option<FinalEmbeddedRootsListParams> = None;
        let _: Option<FinalEmbeddedRootsListResult> = None;
        let _: Option<FinalEmbeddedElicitationParams> = None;
        let _: Option<FinalEmbeddedElicitationResult> = None;

        let _: Option<modern::FinalCreateMessageParams> = None;
        let _: Option<modern::FinalCreateMessageResult> = None;
        let _: Option<modern::FinalEmbeddedRootsListParams> = None;
        let _: Option<modern::FinalEmbeddedElicitationParams> = None;
        let _: Option<prelude::FinalCreateMessageParams> = None;
        let _: Option<prelude::FinalCreateMessageResult> = None;
        let _: Option<prelude::FinalEmbeddedRootsListParams> = None;
        let _: Option<prelude::FinalEmbeddedElicitationParams> = None;

        let _: Option<legacy_2024::LegacyReverseRequestHandlers> = None;
        let _: Option<legacy_2024::LegacyCreateMessageParams> = None;
        let _: Option<legacy_2024::LegacyCreateMessageResult> = None;
        let _: Option<legacy_2024::LegacyListRootsParams> = None;
        let _: Option<legacy_2024::LegacyListRootsResult> = None;
        let _: Option<legacy_2024::LegacyElicitRequestParams> = None;
        let _: Option<legacy_2024::LegacyElicitResult> = None;

        // The intentionally unqualified integration surface retains legacy
        // reverse-JSON-RPC machinery; `modern` compile-fail docs above lock
        // that machinery out of the final-era namespace.
        let _: Option<RequestSender> = None;
        let _: Option<TransportSamplingSender> = None;
        let _: Option<TransportElicitationSender> = None;
        let _: Option<TransportRootsProvider> = None;
        let _: Option<Server> = None;
        let _: Option<ServerBuilder> = None;
    }

    #[test]
    fn api_03_facade_tasks_resolver_rejects_one_dimension_invalid_descriptor() {
        use super::{
            ExtensionSettingsCompatibilityResolver, OfficialTasksNegotiationResolver, modern,
        };

        let mut descriptor = modern::official_tasks_descriptor();
        descriptor.resolver.version = 2;
        let settings = modern::official_tasks_empty_settings();
        let error = OfficialTasksNegotiationResolver
            .resolve(&descriptor, &settings, &settings)
            .expect_err("changing only the Tasks resolver version must reject");

        assert!(matches!(
            error,
            modern::ExtensionNegotiationError::SettingsCompatibilityRejected(id)
                if id == modern::OFFICIAL_TASKS_EXTENSION_ID
        ));
    }

    #[test]
    fn api_03_facade_exposes_apps_and_dual_era_configuration() {
        use super::{
            Client, DuplicateBehavior, LoggingConfig, McpResult, ServerBuilder, legacy_2024, modern,
        };

        let settings =
            modern::McpAppsClientSettings::new(vec![modern::MCP_APPS_HTML_MIME_TYPE.to_owned()])
                .expect("facade must expose MCP Apps client settings admission");
        assert!(settings.supports_mcp_apps_html());

        let mut registry = modern::ExtensionDescriptorRegistry::new();
        let apps_id = modern::register_official_mcp_apps_extension(&mut registry)
            .expect("facade must expose MCP Apps descriptor registration");
        assert_eq!(apps_id.as_str(), modern::OFFICIAL_MCP_APPS_EXTENSION_ID);

        let _: fn(&mut Client, legacy_2024::LegacyReverseRequestHandlers) -> McpResult<()> =
            Client::set_reverse_request_handlers;
        let _: fn(ServerBuilder, DuplicateBehavior) -> ServerBuilder = ServerBuilder::on_duplicate;
        let _: fn(ServerBuilder, LoggingConfig) -> ServerBuilder = ServerBuilder::logging;
        let _: Option<modern::ExtensionSettingsResolution> = None;
        let _: Option<modern::McpAppsNegotiationResolver> = None;
        use super::prelude::{
            DuplicateBehavior as PreludeDuplicateBehavior, LoggingConfig as PreludeLoggingConfig,
            McpAppsClientSettings as PreludeMcpAppsClientSettings,
        };

        let _: Option<PreludeDuplicateBehavior> = None;
        let _: Option<PreludeLoggingConfig> = None;
        let _: Option<PreludeMcpAppsClientSettings> = None;
    }

    #[test]
    fn api_03_facade_exposes_split_transport_contracts() {
        use std::io::Cursor;

        use super::{
            AsyncStdioTransport, StdioTransport, Transport, TransportRecvHalf, TransportSendHalf,
            TwoPhaseTransport, modern, transport,
        };

        fn requires_two_phase_transport<T: TwoPhaseTransport>() {}
        fn requires_split_halves<R: TransportRecvHalf, W: TransportSendHalf>() {}

        requires_two_phase_transport::<StdioTransport<Cursor<Vec<u8>>, Vec<u8>>>();
        let _: Option<AsyncStdioTransport> = None;
        let _: Option<transport::websocket::WsFrame> = None;
        let _: Option<modern::transport::sse::SseEvent> = None;
        let _: Option<&dyn Transport> = None;
        let _ = requires_split_halves::<
            transport::websocket::WsServerRecvHalf<Cursor<Vec<u8>>, Vec<u8>>,
            transport::websocket::WsServerSendHalf<Vec<u8>>,
        >;
    }

    #[test]
    fn api_03_tasks_policy_rejects_one_dimension_invalid_identifier() {
        use super::modern;

        let admitted = modern::FinalTaskId::parse("task-42")
            .expect("baseline final task identifier must be admitted");
        let rejected = modern::FinalTaskId::parse(format!("{}\u{0000}", admitted.as_str()))
            .expect_err("changing only the identifier to include a control code point must reject");

        assert_eq!(rejected, modern::TaskWireError::Invalid("taskId"));
    }

    #[test]
    fn prelude_reexports_final_typed_and_http_endpoints() {
        use std::collections::HashMap;

        use super::prelude::{
            BoundHttpServer, Client, DualEraHttpEndpoint, DualEraHttpEndpointConfig,
            DualEraHttpEndpointError, FinalCallToolResult, FinalGetPromptResult,
            FinalReadResourceResult, FinalToolCallOutcome, JsonValue, McpResult, ModernHttpClient,
            ModernHttpClientError, ModernHttpConnectOutcome, ModernHttpSubscriptionListenCollector,
            ModernHttpSubscriptionListenError, ServerHttpEndpoint, ServerHttpEndpointResponse,
            ServerHttpSession, SseLimits, SubscriptionListenCollector, auto,
        };

        let _: fn(&mut Client, &str, JsonValue) -> McpResult<FinalCallToolResult> =
            Client::call_tool_final;
        let _: fn(&mut Client, &str, JsonValue) -> McpResult<FinalToolCallOutcome> =
            Client::call_tool_final_outcome;
        let _: fn(&mut Client, &str) -> McpResult<FinalReadResourceResult> =
            Client::read_resource_final;
        let _: fn(&mut Client, &str, HashMap<String, String>) -> McpResult<FinalGetPromptResult> =
            Client::get_prompt_final;
        let _: Option<FinalCallToolResult> = None;
        let _: Option<FinalReadResourceResult> = None;
        let _: Option<FinalGetPromptResult> = None;
        let _: Option<SubscriptionListenCollector> = None;
        let _: Option<ModernHttpSubscriptionListenCollector> = None;
        let _: Option<ModernHttpSubscriptionListenError> = None;
        let _: Option<SseLimits> = None;
        let _: Option<ModernHttpClient> = None;
        let _: Option<ModernHttpClientError> = None;
        let _: Option<ModernHttpConnectOutcome> = None;
        let _: Option<ServerHttpEndpoint> = None;
        let _: Option<ServerHttpSession> = None;
        let _: Option<ServerHttpEndpointResponse> = None;
        let _: Option<BoundHttpServer> = None;
        let _: Option<DualEraHttpEndpoint> = None;
        let _: Option<DualEraHttpEndpointConfig> = None;
        let _: Option<DualEraHttpEndpointError> = None;
        assert_eq!(
            auto::client_builder().selected_protocol_plan().policy(),
            auto::ProtocolPolicy::Auto
        );
    }

    #[test]
    fn api_02_rejects_one_field_legacy_version_in_final_request() {
        use super::{legacy_2024, modern};

        let final_request = modern::FinalHttpRequestMetadata {
            version: modern::RequestVersionMetadata {
                header_version: Some(modern::PROTOCOL_VERSION),
                body_version: Some(modern::PROTOCOL_VERSION),
            },
            header_method: Some(modern::SERVER_DISCOVER_METHOD),
            body_method: Some(modern::SERVER_DISCOVER_METHOD),
            header_name: None,
            body_name: None,
        };
        assert!(modern::admit_final_http_request(final_request).is_ok());

        let legacy_version_in_final_request = modern::FinalHttpRequestMetadata {
            version: modern::RequestVersionMetadata {
                body_version: Some(legacy_2024::PROTOCOL_VERSION),
                ..final_request.version
            },
            ..final_request
        };
        let error = modern::admit_final_http_request(legacy_version_in_final_request)
            .expect_err("changing only the body version to legacy must be rejected");

        assert!(matches!(
            error,
            modern::RequestAdmissionError::HeaderMismatch(header)
                if header.reason() == modern::HeaderMismatchReason::HeaderBodyVersionMismatch
        ));
    }
}
