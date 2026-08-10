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
//! `legacy_2024`. The root-level `PROTOCOL_VERSION` remains available for
//! existing exact-2024 consumers while they move to that module; it is not the
//! default selected by `auto::client_builder`.
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
//! through `modern`, `auto`, or `legacy_2024` rather than inferring an
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

/// Re-export the runtime package used by the facade's deterministic lab
/// helpers. Production callers receive `Cx` directly from this facade and do
/// not need a test-internals runtime dependency.
#[cfg(feature = "testing-lab")]
pub use asupersync;

/// Curated supported client namespace for advanced consumers.
///
/// The root, `modern`, and `legacy_2024` exports are the ergonomic API.
/// This namespace intentionally mirrors only the client surface selected by
/// the facade. It is not a crate alias: in particular, enabling a dependency's
/// `websocket-experimental` feature cannot expose that caller-upgraded
/// experimental transport through `fastmcp_rust::client`.
pub mod client {
    pub use crate::{
        BearerBindingError, BoundBearerCredential, ConfigError, ConfigLoader, HttpEndpointConfig,
        HttpEndpointConfigError, MAX_MODERN_HTTP_PROBE_BODY_BYTES, MODERN_MCP_ACCEPT,
        MODERN_MCP_ACCEPT_ENCODING, MODERN_MCP_CONTENT_TYPE, McpConfig, ModernHttpClient,
        ModernHttpClientError, ModernHttpConnectOutcome, ModernHttpExecutor,
        ModernHttpExecutorError, ModernHttpRequest, ModernHttpResponseKind,
        ModernHttpResponseMetadata, ModernHttpResponseStream, ModernHttpSseResponseStream,
        ModernHttpSubscriptionListenCollector, ModernHttpSubscriptionListenError,
        ModernHttpSubscriptionListenEvent, ModernHttpSubscriptionListener, ServerConfig,
        SseEndOfStream, SseLimits, SseParseError, claude_desktop_config_path, default_config_paths,
        validate_response_head,
    };
    pub use crate::{
        BoundedListPage, CachePartitionKey, CancellationRequested, Client, ClientBuilder,
        ClientHttpConnection, ClientHttpConnectionError, ClientHttpNegotiation,
        ClientHttpNegotiationDecision, ClientHttpNegotiationError, ClientHttpNegotiationState,
        ClientHttpResponse, ClientProtocolPlan, ClientProtocolPlanError, ClientSession,
        CompletionContext, CompletionParams, CompletionReference, DEFAULT_FINAL_CACHE_CAPACITY,
        DEFAULT_FINAL_CACHE_MAX_BYTES, ExecutionTerminalReason, ExecutionTerminalRecord,
        ExecutionTerminalState, FinalCacheGeneration, FinalCacheInsert, FinalCacheKey,
        FinalCacheLookup, FinalCacheMiss, FinalCacheResultSet, FinalCacheStats,
        FinalCacheTtlDiagnostic, FinalResultCache, FinalTask, FinalTaskHandle,
        FinalTaskInputResponses, FinalTaskStatusNotification, FinalTaskWatch, FinalTaskWatchEvent,
        FinalToolCallOutcome, FinalUpdateTaskResult, HttpClient, HttpClientError,
        HttpSubscriptionListener, ListPageLimits, MAX_FINAL_CACHE_CAPACITY,
        MAX_FINAL_CACHE_MAX_BYTES, McpAppsBridgeTransport, McpAppsClientWirePolicy, McpAppsHost,
        McpAppsHostConfiguration, McpAppsHostError, McpAppsHostPolicy, McpAppsHttpClientWirePolicy,
        McpAppsInMemoryHostTransport, McpAppsInMemoryViewTransport,
        McpAppsInMemoryWireHostTransport, McpAppsInMemoryWireViewTransport,
        McpAppsWireBridgeTransport, McpAppsWireHost, McpAppsWireHostConfiguration,
        McpAppsWireHostPolicy, OpaquePagination, PaginationBounds, PendingRequestRecord,
        ProgressCallback, Request, RequestExecution, RequestExecutor, RequestTimeoutPolicy,
        RequestTimeoutSource, ReverseRequest, ReverseRequestCancellation, StdioRequestExecution,
        StdioRequestExecutor, SubscriptionFilter, SubscriptionListenCollector,
        mcp_apps_in_memory_pair, mcp_apps_in_memory_wire_pair,
    };
    /// Exact-2024 client staging is present only with the legacy adapter.
    #[cfg(feature = "legacy-2024-11-05")]
    pub use crate::{
        LegacyHttpRequest, LegacyHttpRequestCommit, LegacySseHttpClient, LegacySseHttpClientError,
    };
    pub use fastmcp_client::{http_auth, http_executor, mcp_apps, mcp_config, sse};
}

/// Complete component namespaces for advanced consumers.
///
/// The remaining component namespaces retain their implemented public items
/// without requiring an application to name a FastMCP component crate directly.
pub use fastmcp_core as core;
pub use fastmcp_derive as derive;
pub use fastmcp_protocol as protocol;
pub use fastmcp_server as server;

/// JSON values and objects used by the protocol's schema-open and exact legacy
/// adapter surfaces. Re-exporting these keeps one-crate consumers from having
/// to name FastMCP's transitive serialization crate to implement an adapter.
pub use serde_json::{self, Map as JsonMap, Value as JsonValue, json};

#[cfg(feature = "testing-lab")]
pub use asupersync::{LabConfig, LabRuntime};

// Re-export core types
pub use fastmcp_core::{
    AccessToken, AuthContext, Budget, CancelledError, ClientCapabilityInfo, ClientRoot, Cx,
    ElicitationAction, ElicitationMode, ElicitationRequest, ElicitationResponse, ElicitationSender,
    IntoOutcome, MAX_RESOURCE_READ_DEPTH, MAX_TOOL_CALL_DEPTH, McpContext, McpContextLeaseGuard,
    McpError, McpErrorCode, McpOutcome, McpRequestCancellation, McpResult, NoOpElicitationSender,
    NoOpNotificationSender, NoOpSamplingSender, Outcome, OutcomeExt, ProgressReporter, RegionId,
    ResourceContentItem, ResourceReadResult, ResourceReader, ResultExt, RootsProvider,
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
    MAX_URI_TEMPLATE_VARIABLE_NAME_BYTES, MAX_URI_TEMPLATE_VARIABLES_PER_EXPRESSION,
    ReversibleResourceTemplate, TemplateValue, TemplateValues, UriTemplate, UriTemplateError,
    UriTemplateExpansionLimits, UriTemplateExpression, UriTemplateModifier, UriTemplateOperator,
    UriTemplatePart,
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
    CacheScope, CacheTtl, CacheTtlConversionError, CacheableResult, CancellationSender,
    CancellationWireCodecError, CancellationWireMessage, ClientNotification, CompleteResult,
    CompleteResultPayload, CoreDispatchError, CoreRequest, CoreResult,
    CoreResultDiscriminatorPolicy, DecodedResult, ExactJsonMember, ExactJsonObject, ExactJsonValue,
    FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_CLIENT_INFO_META_KEY,
    FINAL_PROTOCOL_VERSION_META_KEY, FINAL_SERVER_INFO_META_KEY, FinalArguments,
    FinalCallToolParams, FinalCallToolResult, FinalCancelledNotificationParams,
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
/// modern code should import [`modern::PROTOCOL_VERSION`]. This constant is
/// unavailable in the deliberately stripped ModernOnly profile.
#[cfg(feature = "legacy-2024-11-05")]
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
    DualEraHttpSession, DualEraHttpSseResponse, StreamableHttpRequestIngress,
    StreamableHttpRequestResponseMessage, StreamableHttpRequestResponseSender,
};
pub use fastmcp_transport::sse::SseEvent;
pub use fastmcp_transport::{
    AsyncLineReader, AsyncStdin, AsyncStdioTransport, AsyncStdout, Codec, CodecError, HttpError,
    HttpHandlerConfig, HttpMethod, HttpRequest, HttpRequestHandler, HttpResponse,
    HttpResponseRepresentation, HttpStatus, InvalidMessageKind, MemoryRecvHalf, MemorySendHalf,
    ModernHttpRequestAdmission, ModernSseDecoder, ModernSseEndOfStream, ModernSseLimits,
    ModernSseParseError, SendPermit, StdioTransport, StreamableHttpRequestCancellation,
    StreamableHttpRequestResponseStream, StreamableHttpResponseStream, StreamableHttpTransport,
    Transport, TransportError, TransportRecvHalf, TransportSendHalf, TwoPhaseTransport,
};

/// Curated transport diagnostics exposed by the facade.
///
/// The facade intentionally does not re-export the blocking WebSocket module:
/// already-upgraded async WebSocket adaptation remains a lower-crate concern.
///
/// ```compile_fail
/// use fastmcp_rust::transport::websocket;
/// ```
pub mod transport {
    pub use fastmcp_transport::{
        MemoryRecvHalf, MemorySendHalf, ModernSseDecoder, ModernSseEndOfStream, ModernSseLimits,
        ModernSseParseError, TransportError,
    };
    pub use fastmcp_transport::{http, memory, sse};
}

pub use fastmcp_transport::{event_store, http, memory};

// Re-export server types
// FND-01: JWT verifier is not a facade feature (FACADE-NO-JSONWEBTOKEN).
pub use fastmcp_server::{
    AllowAllAuthProvider, ApplicationTaskSupervisor, AuthProvider, AuthRequest,
    AuthorizedTaskServiceRunner, BannerStyle, BidirectionalSenders, BoundHttpServer, BoxFuture,
    CompletionHandler, ConsoleConfig, DEFAULT_IN_MEMORY_FINAL_TASKS, FinalProgressCallback,
    FinalResourceReadCacheHintProvenance, FinalTaskAcceptedInput, FinalTaskInitialWork,
    FinalTaskNotificationEmitter, FinalTaskRetentionAuthority, FinalTaskRuntime,
    FinalTaskRuntimeConfig, FinalTaskSnapshot, FinalTaskStore, FinalTaskSupervisorFuture,
    FinalTaskSupervisorHandoff, FinalTaskWorkDescriptor, FinalToolOutcome,
    FinalToolSchemaAuthority, HttpNonquiescentShutdown, HttpServerConfig, HttpServerShutdown,
    HttpShutdownSettlement, InMemoryFinalTaskStore, InboundRequestContext, InboundRequestTransport,
    Middleware, MiddlewareDecision, MountResult, NotificationSender, PendingRequests,
    ProgressNotificationSender, PromptHandler, ProxyBackend, ProxyCatalog, ProxyCatalogCacheHint,
    ProxyClient, ProxyFinalCatalog, ProxyFinalTaskListener, ProxyFinalTaskListenerEvent,
    ProxyPromptCatalog, ProxyResourceCatalog, ProxyResourceTemplateCatalog, ProxyToolCatalog,
    ProxyTypedCatalog, ProxyUpstreamAdapter, ProxyUpstreamBinding, ProxyUpstreamBindingRegistry,
    RequestSender, ResourceHandler, Router, Server, ServerBuilder, ServerHttpEndpoint,
    ServerHttpEndpointResponse, ServerHttpRequestCancellation, ServerHttpSession,
    ServerHttpSseResponse, ServerStats, Session, StaticTokenVerifier, StatsSnapshot, TagFilters,
    TokenAuthProvider, TokenVerifier, ToolErrorKind, ToolHandler, TrafficVerbosity,
    TransportElicitationSender, TransportRootsProvider, TransportSamplingSender,
    create_context_with_progress, create_context_with_progress_and_senders,
};

/// Proxy-backend legacy progress callback.
///
/// This intentionally differs from the client [`ProgressCallback`]: proxy
/// backends preserve an owned optional message from their legacy handler API.
pub type ProxyProgressCallback<'a> = &'a mut dyn FnMut(f64, Option<f64>, Option<String>);
pub use fastmcp_server::{
    DuplicateBehavior, LifespanHooks, LoggingConfig, ServerExtensionConfigurationError,
    ServerLaunchPolicyError, ShutdownHook, StartupHook,
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
    FinalCacheTtlDiagnostic, FinalResultCache, FinalTask, FinalTaskHandle, FinalTaskInputResponses,
    FinalTaskStatusNotification, FinalTaskWatch, FinalTaskWatchEvent, FinalToolCallOutcome,
    FinalUpdateTaskResult, HttpClient, HttpClientError, HttpSubscriptionListener, ListPageLimits,
    MAX_FINAL_CACHE_CAPACITY, MAX_FINAL_CACHE_MAX_BYTES, McpAppsBridgeTransport,
    McpAppsClientWirePolicy, McpAppsHost, McpAppsHostConfiguration, McpAppsHostError,
    McpAppsHostPolicy, McpAppsHttpClientWirePolicy, McpAppsInMemoryHostTransport,
    McpAppsInMemoryViewTransport, McpAppsInMemoryWireHostTransport,
    McpAppsInMemoryWireViewTransport, McpAppsWireBridgeTransport, McpAppsWireHost,
    McpAppsWireHostConfiguration, McpAppsWireHostPolicy, OpaquePagination, PaginationBounds,
    PendingRequestRecord, ProgressCallback, Request, RequestExecution, RequestExecutor,
    RequestTimeoutPolicy, RequestTimeoutSource, ReverseRequest, ReverseRequestCancellation,
    StdioRequestExecution, StdioRequestExecutor, SubscriptionFilter, SubscriptionListenCollector,
    mcp_apps_in_memory_pair, mcp_apps_in_memory_wire_pair,
};

/// Exact-2024 HTTP request staging is available only with its adapter profile.
#[cfg(feature = "legacy-2024-11-05")]
pub use fastmcp_client::{LegacyHttpRequest, LegacyHttpRequestCommit};

// Public client HTTP execution and configuration surfaces.
pub use fastmcp_client::http_auth;
pub use fastmcp_client::http_auth::{BearerBindingError, BoundBearerCredential};
/// Exact-2024 SSE client support is available only with its adapter profile.
#[cfg(feature = "legacy-2024-11-05")]
pub use fastmcp_client::http_executor::{LegacySseHttpClient, LegacySseHttpClientError};
pub use fastmcp_client::http_executor::{
    MAX_MODERN_HTTP_PROBE_BODY_BYTES, MODERN_MCP_ACCEPT, MODERN_MCP_ACCEPT_ENCODING,
    MODERN_MCP_CONTENT_TYPE, ModernHttpClient, ModernHttpClientError, ModernHttpConnectOutcome,
    ModernHttpExecutor, ModernHttpExecutorError, ModernHttpRequest, ModernHttpResponseKind,
    ModernHttpResponseMetadata, ModernHttpResponseStream, ModernHttpSseResponseStream,
    ModernHttpSubscriptionListenCollector, ModernHttpSubscriptionListenError,
    ModernHttpSubscriptionListenEvent, ModernHttpSubscriptionListener, validate_response_head,
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
///
/// ```compile_fail
/// use fastmcp_rust::auto::connect_websocket_with_cx;
/// ```
#[cfg(feature = "legacy-2024-11-05")]
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
        HttpClientError, HttpSubscriptionListener, McpAppsClientWirePolicy, McpAppsHostError,
        McpAppsInMemoryWireHostTransport, McpAppsInMemoryWireViewTransport,
        McpAppsWireBridgeTransport, McpAppsWireHost, McpAppsWireHostConfiguration,
        McpAppsWireHostPolicy, Request, RequestExecution, RequestExecutor, ReverseRequest,
        ReverseRequestCancellation, StdioRequestExecution, StdioRequestExecutor,
        SubscriptionFilter, SubscriptionListenCollector, mcp_apps_in_memory_wire_pair,
    };
    pub use fastmcp_core::{CanonicalHttpUrl, Cx, McpError, McpResult};
    pub use fastmcp_protocol::extensions::{
        ExtensionDescriptor, ExtensionDescriptorRegistry, ExtensionNegotiationError,
        ExtensionSettings, ExtensionSettingsCompatibilityResolver, ExtensionSettingsResolution,
        McpAppsClientSettings, OFFICIAL_TASKS_EXTENSION_ID, OFFICIAL_TASKS_RESULT_DISCRIMINATOR,
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
        FinalTaskId, JsonRpcRequest, JsonRpcResponse, RequestId, ReversibleResourceTemplate,
        SchemaAdmissionError, TemplateValue, TemplateValues, UriTemplate, UriTemplateError,
        UriTemplateExpansionLimits, ValidationError, ValidationResult, admit_final_schema,
        validate_final_core_result,
    };
    pub use fastmcp_protocol::{schema, tasks_extension};
    pub use fastmcp_transport::Transport;
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
/// `legacy_2024` for exact-2024 APIs.
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
/// use fastmcp_rust::modern::ServerBuilder;
///
/// let _ = ServerBuilder::new("final-only", "1.0.0").resource_subscriptions();
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::modern::connect_websocket_with_cx;
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
    pub use fastmcp_client::sse::SseLimits;
    pub use fastmcp_client::{
        BoundedListPage, CachePartitionKey, CompletionContext, CompletionParams,
        CompletionReference, DEFAULT_FINAL_CACHE_CAPACITY, DEFAULT_FINAL_CACHE_MAX_BYTES,
        ExecutionTerminalReason, ExecutionTerminalRecord, ExecutionTerminalState,
        FinalCacheGeneration, FinalCacheInsert, FinalCacheKey, FinalCacheLookup, FinalCacheMiss,
        FinalCacheResultSet, FinalCacheStats, FinalCacheTtlDiagnostic, FinalResultCache, FinalTask,
        FinalTaskHandle, FinalTaskInputResponses, FinalTaskStatusNotification, FinalTaskWatch,
        FinalTaskWatchEvent, FinalToolCallOutcome, FinalUpdateTaskResult, HttpClientError,
        HttpSubscriptionListener, ListPageLimits, MAX_FINAL_CACHE_CAPACITY,
        MAX_FINAL_CACHE_MAX_BYTES, MAX_MRTR_CONTINUATION_ROUNDS, MAX_MRTR_INPUT_RESPONSES,
        MAX_MRTR_TOTAL_INPUT_RESPONSES, McpAppsClientWirePolicy, McpAppsHostError,
        McpAppsHttpClientWirePolicy, McpAppsInMemoryWireHostTransport,
        McpAppsInMemoryWireViewTransport, McpAppsWireBridgeTransport, McpAppsWireHost,
        McpAppsWireHostConfiguration, McpAppsWireHostPolicy, MrtrInputResponses, OpaquePagination,
        PaginationBounds, PendingRequestRecord, ProgressCallback, RequestTimeoutPolicy,
        RequestTimeoutSource, SubscriptionFilter, SubscriptionListenCollector,
        mcp_apps_in_memory_wire_pair,
    };
    pub use fastmcp_core::{
        CanonicalHttpUrl, ClientCapabilityInfo, ClientRoot, Cx, MAX_RESOURCE_READ_DEPTH,
        MAX_TOOL_CALL_DEPTH, McpContext, McpContextLeaseGuard, McpError, McpOutcome, McpResult,
        NoOpNotificationSender, NotificationSender, Outcome, ProgressReporter, ResourceContentItem,
        ResourceReadResult, ResourceReader, RootsProvider, ServerCapabilityInfo, ToolCallResult,
        ToolCaller, ToolContentItem,
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
        AdmittedSchema, CacheScope, CacheTtl, CacheTtlConversionError, CacheableResult,
        ClientCapabilities, ClientInfo, ClientNotification, CompleteResult, CompleteResultPayload,
        CompleteTaskResult, CreateTaskResult, DiscoveryCacheHints, EmptyTaskResult,
        ExactJsonMember, ExactJsonObject, ExactJsonValue, FINAL_CLIENT_CAPABILITIES_META_KEY,
        FINAL_CLIENT_INFO_META_KEY, FINAL_PROTOCOL_VERSION as PROTOCOL_VERSION,
        FINAL_PROTOCOL_VERSION_META_KEY, FINAL_SERVER_INFO_META_KEY, FinalArguments,
        FinalBaseMetadata, FinalCallToolParams, FinalCallToolResult, FinalCancelTaskParams,
        FinalCancelTaskResult, FinalCancelledNotificationParams, FinalCompletionArgument,
        FinalCompletionContext, FinalCompletionParams, FinalCompletionReference,
        FinalCompletionResult, FinalCompletionValues, FinalCoreRequest, FinalCoreResult,
        FinalCoreResultType, FinalCreateMessageInputRequiredResult, FinalCreateMessageParams,
        FinalCreateMessageResult, FinalEmbeddedCreateMessageParams, FinalEmbeddedElicitationParams,
        FinalEmbeddedElicitationResult, FinalEmbeddedFormElicitationParams, FinalEmbeddedInputKind,
        FinalEmbeddedInputRequest, FinalEmbeddedInputResponse, FinalEmbeddedRootsListParams,
        FinalEmbeddedRootsListResult, FinalEmbeddedUrlElicitationParams,
        FinalEmptyNotificationParams, FinalEmptyParams, FinalEmptyResult, FinalGetPromptParams,
        FinalGetPromptResult, FinalGetTaskParams, FinalGetTaskResult, FinalHttpRequestMetadata,
        FinalInputRequiredResultType, FinalListParams, FinalListPromptsResult,
        FinalListResourceTemplatesResult, FinalListResourcesResult, FinalListToolsResult,
        FinalLogMessageParams, FinalNotificationError, FinalProgressNotificationParams,
        FinalPrompt, FinalPromptArgument, FinalPromptMessage, FinalProtocolVersion,
        FinalReadResourceParams, FinalReadResourceResult, FinalRequestAdmission, FinalRequestMeta,
        FinalResource, FinalResourceTemplate, FinalResourceUpdatedNotificationParams,
        FinalSamplingMessage, FinalSamplingMessageContent, FinalSamplingMessageContentBlock,
        FinalSubscriptionsAcknowledgedNotificationParams, FinalSubscriptionsListenParams,
        FinalSubscriptionsListenResult, FinalTaskCallToolResult, FinalTaskError, FinalTaskId,
        FinalTaskStatus, FinalTaskStatusNotificationParams, FinalTool, FinalToolAnnotations,
        FinalToolChoice, FinalToolChoiceMode, HEADER_MISMATCH_ERROR_CODE, HeaderMismatchError,
        HeaderMismatchReason, IncludeContext, InputRequiredResult, MAX_MCP_APPS_CSP_DOMAIN_BYTES,
        MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE, MAX_MCP_APPS_TOOL_VISIBILITY_ENTRIES,
        MAX_MCP_APPS_UI_METADATA_MEMBERS, MAX_RESULT_CONTAINER_MEMBERS, MAX_RESULT_DEPTH,
        MAX_RESULT_ENCODED_BYTES, MAX_RESULT_NUMBER_BYTES, MAX_RESULT_STRING_BYTES,
        MAX_TASK_ID_BYTES, MAX_TASK_INPUT_MAP_ENTRIES, MAX_TASK_SUBSCRIPTION_IDS,
        MCP_APPS_DEPRECATED_RESOURCE_URI_METADATA_KEY, MCP_APPS_UI_METADATA_KEY, MCP_METHOD_HEADER,
        MCP_NAME_HEADER, MCP_PROTOCOL_VERSION_HEADER,
        MISSING_REQUIRED_CLIENT_CAPABILITY_ERROR_CODE, McpAppsBridgeImplementation,
        McpAppsDisplayMode, McpAppsLifecycleError, McpAppsMetadataError,
        McpAppsPinnedHostCapabilities, McpAppsPinnedHostContext, McpAppsResourceBinding,
        McpAppsResourceBindingError, McpAppsResourceCsp, McpAppsResourceMetadata,
        McpAppsResourcePermission, McpAppsResourcePermissions, McpAppsResultProjectionError,
        McpAppsToolMetadata, McpAppsToolResult, McpAppsToolVisibility, McpAppsViewLifecycle,
        MetadataView, MissingRequiredClientCapabilityError, ModelHint, ModelPreferences,
        PaginatedResult, ProgressMarker, ProtocolVersionError as FinalProtocolVersionError,
        RELATED_TASK_META_KEY, RawResultEnvelope, RequestAdmissionError, RequestId,
        RequestVersionMetadata, RequiredCapabilitiesError, ReversibleResourceTemplate,
        SERVER_DISCOVER_METHOD, SERVER_DISCOVER_SUPPORTED_VERSIONS,
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
        MrtrInputRequired, MrtrInputResponse, MrtrInputResponses as ServerMrtrInputResponses,
        MrtrRequestState, MrtrRetry,
    };
    pub use fastmcp_server::providers::McpAppsUiResource;
    pub use fastmcp_server::{
        ApplicationTaskSupervisor, AuthProvider, AuthRequest, AuthorizedTaskServiceRunner,
        BannerStyle, BoxFuture, CompletionHandler, ConsoleConfig, DEFAULT_IN_MEMORY_FINAL_TASKS,
        DuplicateBehavior, ExtensionHandler, ExtensionHandlerInvocationError, ExtensionHandlerKey,
        ExtensionHandlerLookupError, ExtensionHandlerRegistrationError, ExtensionHandlerRegistry,
        FinalMethodOutcome, FinalProgressCallback, FinalResourceReadCacheHintProvenance,
        FinalTaskAcceptedInput, FinalTaskInitialWork, FinalTaskNotificationEmitter,
        FinalTaskRetentionAuthority, FinalTaskRuntime, FinalTaskRuntimeConfig, FinalTaskSnapshot,
        FinalTaskStore, FinalTaskSupervisorFuture, FinalTaskSupervisorHandoff,
        FinalTaskWorkDescriptor, FinalToolOutcome, FinalToolSchemaAuthority,
        HttpNonquiescentShutdown, HttpServerShutdown, HttpShutdownSettlement,
        InMemoryFinalTaskStore, LifespanHooks, LoggingConfig, Middleware, MiddlewareDecision,
        MountResult, ProgressNotificationSender, PromptHandler, ProxyUpstreamAdapter,
        ProxyUpstreamBinding, ProxyUpstreamBindingRegistry, ResourceHandler,
        ServerExtensionConfigurationError, ShutdownHook, StartupHook, TagFilters, ToolErrorKind,
        ToolHandler, TrafficVerbosity, create_context_with_progress,
    };
    pub use fastmcp_transport::http::{
        StreamableHttpRequestIngress, StreamableHttpRequestResponseMessage,
        StreamableHttpRequestResponseSender,
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

        /// Sets the bounded connection retry count without changing the
        /// final-only protocol selection.
        #[must_use]
        pub fn max_retries(self, retries: u32) -> Self {
            Self {
                inner: self.inner.max_retries(retries),
            }
        }

        /// Sets the connection retry delay without changing the final-only
        /// protocol selection.
        #[must_use]
        pub fn retry_delay_ms(self, delay: u64) -> Self {
            Self {
                inner: self.inner.retry_delay_ms(delay),
            }
        }

        /// Sets a validated bounded connection retry policy.
        pub fn connection_retry_policy(
            self,
            max_attempts: u32,
            retry_delay: std::time::Duration,
            total_elapsed: std::time::Duration,
        ) -> McpResult<Self> {
            self.inner
                .connection_retry_policy(max_attempts, retry_delay, total_elapsed)
                .map(|inner| Self { inner })
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

        /// Installs final-only client extension settings before connection.
        pub fn extension_registry<F, R>(
            self,
            descriptors: ExtensionDescriptorRegistry,
            client_discovery: ClientExtensionDiscovery,
            resolver_factory: F,
        ) -> McpResult<Self>
        where
            F: Fn() -> R + Send + Sync + 'static,
            R: ExtensionSettingsCompatibilityResolver + Send + 'static,
        {
            self.inner
                .extension_registry(descriptors, client_discovery, resolver_factory)
                .map(|inner| Self { inner })
        }

        /// Sets the working directory for the final-only stdio subprocess.
        #[must_use]
        pub fn working_dir(self, path: impl Into<std::path::PathBuf>) -> Self {
            Self {
                inner: self.inner.working_dir(path),
            }
        }

        /// Adds one environment variable to the final-only stdio subprocess.
        #[must_use]
        pub fn env(self, key: impl Into<String>, value: impl Into<String>) -> Self {
            Self {
                inner: self.inner.env(key, value),
            }
        }

        /// Adds several environment variables to the final-only stdio subprocess.
        #[must_use]
        pub fn envs<I, K, V>(self, vars: I) -> Self
        where
            I: IntoIterator<Item = (K, V)>,
            K: Into<String>,
            V: Into<String>,
        {
            Self {
                inner: self.inner.envs(vars),
            }
        }

        /// Selects whether the final-only subprocess inherits the parent environment.
        #[must_use]
        pub fn inherit_env(self, inherit: bool) -> Self {
            Self {
                inner: self.inner.inherit_env(inherit),
            }
        }

        /// Defers final discovery until the first client operation.
        #[must_use]
        pub fn auto_initialize(self, enabled: bool) -> Self {
            Self {
                inner: self.inner.auto_initialize(enabled),
            }
        }

        /// Selects private process-group ownership for the final-only child.
        #[must_use]
        pub fn owned_process_group(self, enabled: bool) -> Self {
            Self {
                inner: self.inner.owned_process_group(enabled),
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

        /// Connects this configured final-only builder over one final HTTP endpoint.
        ///
        /// The builder retains its client identity, capabilities, timeout policy,
        /// and MCP Apps configuration; only its immutable transport plan changes.
        pub fn connect_http(
            self,
            endpoint: CanonicalHttpUrl,
        ) -> Result<HttpClient, HttpClientConnectError> {
            let plan = modern_http_plan(endpoint).map_err(HttpClientConnectError::Plan)?;
            self.inner
                .protocol_plan(plan)
                .connect_http_client()
                .map_err(HttpClientConnectError::Connect)
                .and_then(HttpClient::from_inner)
        }

        /// Connects this configured final-only builder over one final HTTP endpoint
        /// with an explicit cancellation context.
        pub async fn connect_http_with_cx(
            self,
            endpoint: CanonicalHttpUrl,
            cx: &Cx,
        ) -> Result<HttpClient, HttpClientConnectError> {
            let plan = modern_http_plan(endpoint).map_err(HttpClientConnectError::Plan)?;
            self.inner
                .protocol_plan(plan)
                .connect_http_client_with_cx(cx)
                .await
                .map_err(HttpClientConnectError::Connect)
                .and_then(HttpClient::from_inner)
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

        /// Returns the exact final discovery result that admitted this client.
        ///
        /// When construction deferred discovery, this performs that required
        /// modern lifecycle step before returning. The sealed modern facade
        /// can never return a legacy initialization result here.
        pub fn server_discovery(&mut self) -> McpResult<&ServerDiscoverResult> {
            self.inner.ensure_initialized()?;
            self.inner.server_discovery().ok_or_else(|| {
                McpError::internal_error(
                    "ModernOnly client completed initialization without server/discover",
                )
            })
        }

        /// Starts the closed Apps wire bridge after final discovery activated Apps.
        ///
        /// The wrapped client remains pinned to the modern protocol era, while
        /// the underlying activation receipt rejects a missing or inactive Apps
        /// negotiation before the Host is constructed.
        pub fn mcp_apps_wire_host<'client, T>(
            &'client mut self,
            transport: T,
            configuration: McpAppsWireHostConfiguration,
        ) -> Result<McpAppsWireHost<T, McpAppsClientWirePolicy<'client>>, McpAppsHostError>
        where
            T: McpAppsWireBridgeTransport,
        {
            self.inner.mcp_apps_wire_host(transport, configuration)
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

        /// Calls one tool through final-only stdio until a terminal final result arrives.
        ///
        /// The existing client driver bounds continuation rounds and total
        /// input responses using the connection's timeout policy. The responder
        /// runs once per admitted `input_required` result; intermediate results
        /// never escape this final-only facade.
        pub fn call_tool_with_mrtr_retry<F>(
            &mut self,
            name: &str,
            arguments: JsonValue,
            respond: F,
        ) -> McpResult<FinalCoreResult>
        where
            F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
        {
            final_stdio_mrtr_result(
                "tools/call",
                self.inner
                    .call_tool_with_mrtr_retry(name, arguments, respond)?,
            )
        }

        /// Reads one resource through final-only stdio until a terminal final result arrives.
        ///
        /// See [`Self::call_tool_with_mrtr_retry`] for the shared bounded
        /// continuation and responder semantics.
        pub fn read_resource_with_mrtr_retry<F>(
            &mut self,
            uri: &str,
            respond: F,
        ) -> McpResult<FinalCoreResult>
        where
            F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
        {
            final_stdio_mrtr_result(
                "resources/read",
                self.inner.read_resource_with_mrtr_retry(uri, respond)?,
            )
        }

        /// Gets one prompt through final-only stdio until a terminal final result arrives.
        ///
        /// See [`Self::call_tool_with_mrtr_retry`] for the shared bounded
        /// continuation and responder semantics.
        pub fn get_prompt_with_mrtr_retry<F>(
            &mut self,
            name: &str,
            arguments: std::collections::HashMap<String, String>,
            respond: F,
        ) -> McpResult<FinalCoreResult>
        where
            F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
        {
            final_stdio_mrtr_result(
                "prompts/get",
                self.inner
                    .get_prompt_with_mrtr_retry(name, arguments, respond)?,
            )
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

        /// Drains every admitted final server notification received outside a
        /// request-owned subscription listener.
        ///
        /// The component client keeps progress in a distinct typed queue to
        /// preserve its exact numeric representation. Reconstituting the
        /// [`ServerNotification::Progress`] branch here gives facade callers
        /// one exhaustive final server-notification surface.
        #[must_use]
        pub fn take_server_notifications(&mut self) -> Vec<ServerNotification> {
            let mut notifications = self.inner.take_final_server_notifications();
            notifications.extend(
                self.inner
                    .take_final_progress_notifications()
                    .into_iter()
                    .map(ServerNotification::Progress),
            );
            notifications
        }

        /// Sends the typed final wire cancellation notification for one
        /// client-owned live request.
        ///
        /// The inner client verifies ownership and atomically tombstones the
        /// request before committing the fixed final notification. This
        /// facade exposes no arbitrary notification writer and therefore
        /// cannot cross into the legacy protocol era.
        pub fn cancel_request(
            &mut self,
            request_id: RequestId,
            reason: Option<String>,
        ) -> McpResult<()> {
            self.inner.cancel_request(request_id, reason)
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
        /// The final `server/discover` lifecycle or HTTP transport failed.
        Connect(HttpClientError),
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
    /// Its typed HTTP methods return only final result vocabulary.
    ///
    /// ```compile_fail
    /// use fastmcp_rust::{legacy_2024, modern};
    ///
    /// fn cannot_downgrade(client: modern::HttpClient) {
    ///     let _: legacy_2024::HttpClient = client;
    /// }
    /// ```
    pub struct HttpClient {
        inner: fastmcp_client::HttpClient,
    }

    impl HttpClient {
        fn from_inner(inner: fastmcp_client::HttpClient) -> Result<Self, HttpClientConnectError> {
            if inner.selected_protocol_era()
                == fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026
            {
                Ok(Self { inner })
            } else {
                Err(HttpClientConnectError::UnexpectedLegacySelection)
            }
        }

        /// Connects to one canonical final HTTP endpoint with a fixed
        /// `ModernOnly` plan. Callers cannot supply a plan or legacy routes.
        pub async fn connect(
            cx: &Cx,
            endpoint: CanonicalHttpUrl,
            client_info: ClientInfo,
            client_capabilities: ClientCapabilities,
        ) -> Result<Self, HttpClientConnectError> {
            ClientBuilder::new()
                .client_info(client_info.name, client_info.version)
                .capabilities(client_capabilities)
                .connect_http_with_cx(endpoint, cx)
                .await
        }

        /// Returns the exact final discovery response that admitted this connection.
        #[must_use]
        pub fn server_discovery(&self) -> ServerDiscoverResult {
            self.inner.server_discovery().expect(
                "the modern facade only retains an HTTP client admitted by final server/discover",
            )
        }

        /// Returns whether final discovery activated the official MCP Apps extension.
        #[must_use]
        pub fn mcp_apps_active(&self) -> bool {
            self.inner.mcp_apps_active()
        }

        /// Starts the closed Apps wire bridge after final discovery activated Apps.
        ///
        /// This wrapper can only contain a modern HTTP connection. The
        /// underlying activation receipt still rejects missing or inactive Apps
        /// negotiation before constructing the Host.
        pub fn mcp_apps_wire_host<'client, T>(
            &'client mut self,
            transport: T,
            configuration: McpAppsWireHostConfiguration,
        ) -> Result<McpAppsWireHost<T, McpAppsHttpClientWirePolicy<'client>>, McpAppsHostError>
        where
            T: McpAppsWireBridgeTransport,
        {
            self.inner.mcp_apps_wire_host(transport, configuration)
        }

        /// Attaches a durable final Task and retains its latest admitted snapshot.
        ///
        /// Follow-up handle operations remain bound to this modern-only client,
        /// preserving its negotiated connection and private request-ID allocator.
        pub async fn attach_final_task(
            &mut self,
            cx: &Cx,
            task_id: FinalTaskId,
        ) -> Result<FinalTaskHandle, HttpClientError> {
            self.inner.attach_final_task(cx, task_id).await
        }

        /// Polls a task handle through `tasks/get` and updates its snapshot.
        pub async fn poll_final_task<'handle>(
            &mut self,
            cx: &Cx,
            handle: &'handle mut FinalTaskHandle,
        ) -> Result<&'handle FinalTask, HttpClientError> {
            handle.poll(cx, &mut self.inner).await
        }

        /// Supplies input for an `input_required` task handle.
        ///
        /// The empty `tasks/update` acknowledgement does not replace the
        /// handle's snapshot; call [`Self::poll_final_task`] or
        /// [`Self::watch_final_task`] to observe its next state.
        pub async fn resume_final_task(
            &mut self,
            cx: &Cx,
            handle: &mut FinalTaskHandle,
            input_responses: FinalTaskInputResponses,
        ) -> Result<FinalUpdateTaskResult, HttpClientError> {
            handle
                .resume_input(cx, &mut self.inner, input_responses)
                .await
        }

        /// Requests cancellation for the exact task owned by a handle.
        ///
        /// The acknowledgement does not replace the handle's snapshot; poll
        /// or watch it to observe the resulting terminal state.
        pub async fn cancel_final_task(
            &mut self,
            cx: &Cx,
            handle: &FinalTaskHandle,
        ) -> Result<FinalCancelTaskResult, HttpClientError> {
            handle.cancel(cx, &mut self.inner).await
        }

        /// Opens one caller-driven final task watch for this handle.
        pub async fn watch_final_task<'client, 'handle>(
            &'client mut self,
            cx: &Cx,
            handle: &'handle mut FinalTaskHandle,
            limits: SseLimits,
        ) -> Result<FinalTaskWatch<'client, 'handle>, HttpClientError> {
            handle.watch(cx, &mut self.inner, limits).await
        }

        /// Calls one final tool and retains its official Tasks outcome branch.
        pub async fn call_tool_outcome(
            &mut self,
            cx: &Cx,
            request_id: RequestId,
            name: &str,
            arguments: JsonValue,
            maximum_response_bytes: usize,
        ) -> Result<FinalToolCallOutcome, HttpClientError> {
            self.inner
                .connection()
                .call_tool_final_outcome(cx, request_id, name, arguments, maximum_response_bytes)
                .await
                .map_err(HttpClientError::Connection)
        }

        /// Lists one exact final page of tools through the policy-bound HTTP client.
        ///
        /// ```compile_fail
        /// use fastmcp_rust::modern::{
        ///     Cx, FinalListResourcesResult, HttpClient, HttpClientError,
        /// };
        ///
        /// async fn wrong_result_type(
        ///     client: &mut HttpClient,
        ///     cx: &Cx,
        /// ) -> Result<FinalListResourcesResult, HttpClientError> {
        ///     client.list_tools(cx, None).await
        /// }
        /// ```
        pub async fn list_tools(
            &mut self,
            cx: &Cx,
            cursor: Option<&str>,
        ) -> Result<FinalListToolsResult, HttpClientError> {
            match self
                .inner
                .request_final_core(cx, "tools/list", final_list_parameters(cursor))
                .await?
            {
                fastmcp_protocol::CoreResult::Final(
                    fastmcp_protocol::FinalCoreResult::ToolsList { result, .. },
                ) => Ok(result.payload),
                _ => Err(unexpected_modern_http_result("tools/list")),
            }
        }

        /// Lists one exact final page of resources through the policy-bound HTTP client.
        pub async fn list_resources(
            &mut self,
            cx: &Cx,
            cursor: Option<&str>,
        ) -> Result<FinalListResourcesResult, HttpClientError> {
            match self
                .inner
                .request_final_core(cx, "resources/list", final_list_parameters(cursor))
                .await?
            {
                fastmcp_protocol::CoreResult::Final(
                    fastmcp_protocol::FinalCoreResult::ResourcesList { result, .. },
                ) => Ok(result.payload),
                _ => Err(unexpected_modern_http_result("resources/list")),
            }
        }

        /// Lists one exact final page of resource templates through the policy-bound HTTP client.
        pub async fn list_resource_templates(
            &mut self,
            cx: &Cx,
            cursor: Option<&str>,
        ) -> Result<FinalListResourceTemplatesResult, HttpClientError> {
            match self
                .inner
                .request_final_core(
                    cx,
                    "resources/templates/list",
                    final_list_parameters(cursor),
                )
                .await?
            {
                fastmcp_protocol::CoreResult::Final(
                    fastmcp_protocol::FinalCoreResult::ResourceTemplatesList { result, .. },
                ) => Ok(result.payload),
                _ => Err(unexpected_modern_http_result("resources/templates/list")),
            }
        }

        /// Lists one exact final page of prompts through the policy-bound HTTP client.
        ///
        /// ```compile_fail
        /// use fastmcp_rust::modern::{Cx, FinalListToolsResult, HttpClient, HttpClientError};
        ///
        /// async fn wrong_result_type(
        ///     client: &mut HttpClient,
        ///     cx: &Cx,
        /// ) -> Result<FinalListToolsResult, HttpClientError> {
        ///     client.list_prompts(cx, None).await
        /// }
        /// ```
        pub async fn list_prompts(
            &mut self,
            cx: &Cx,
            cursor: Option<&str>,
        ) -> Result<FinalListPromptsResult, HttpClientError> {
            match self
                .inner
                .request_final_core(cx, "prompts/list", final_list_parameters(cursor))
                .await?
            {
                fastmcp_protocol::CoreResult::Final(
                    fastmcp_protocol::FinalCoreResult::PromptsList { result, .. },
                ) => Ok(result.payload),
                _ => Err(unexpected_modern_http_result("prompts/list")),
            }
        }

        /// Reads one resource and retains its exact final cache metadata and contents.
        pub async fn read_resource(
            &mut self,
            cx: &Cx,
            uri: &str,
        ) -> Result<FinalReadResourceResult, HttpClientError> {
            match self
                .inner
                .request_final_core(cx, "resources/read", serde_json::json!({ "uri": uri }))
                .await?
            {
                fastmcp_protocol::CoreResult::Final(
                    fastmcp_protocol::FinalCoreResult::ResourcesRead { result, .. },
                ) => Ok(result.payload),
                _ => Err(unexpected_modern_http_result("resources/read")),
            }
        }

        /// Gets one prompt and accepts only its terminal complete final result.
        ///
        /// Use [`Self::get_prompt_with_mrtr_retry`] when the peer can return
        /// `input_required` continuations.
        ///
        /// ```compile_fail
        /// use std::collections::HashMap;
        ///
        /// use fastmcp_rust::modern::{
        ///     Cx, FinalReadResourceResult, HttpClient, HttpClientError,
        /// };
        ///
        /// async fn wrong_result_type(
        ///     client: &mut HttpClient,
        ///     cx: &Cx,
        /// ) -> Result<FinalReadResourceResult, HttpClientError> {
        ///     client.get_prompt(cx, "report", HashMap::new()).await
        /// }
        /// ```
        pub async fn get_prompt(
            &mut self,
            cx: &Cx,
            name: &str,
            arguments: std::collections::HashMap<String, String>,
        ) -> Result<FinalGetPromptResult, HttpClientError> {
            let mut parameters = serde_json::json!({ "name": name });
            if !arguments.is_empty() {
                let parameters = parameters.as_object_mut().ok_or_else(|| {
                    HttpClientError::CoreResult(McpError::internal_error(
                        "final HTTP prompt parameters must remain an object",
                    ))
                })?;
                parameters.insert(
                    "arguments".to_owned(),
                    serde_json::to_value(arguments).map_err(|error| {
                        HttpClientError::CoreResult(McpError::internal_error(format!(
                            "final HTTP prompt arguments could not serialize: {error}"
                        )))
                    })?,
                );
            }
            match self
                .inner
                .request_final_core(cx, "prompts/get", parameters)
                .await?
            {
                fastmcp_protocol::CoreResult::Final(
                    fastmcp_protocol::FinalCoreResult::PromptsGet { result, .. },
                ) => Ok(result.payload),
                _ => Err(unexpected_modern_http_result("prompts/get")),
            }
        }

        /// Completes a prompt or resource-template argument using final context.
        pub async fn complete(
            &mut self,
            cx: &Cx,
            params: CompletionParams,
        ) -> Result<FinalCompletionResult, HttpClientError> {
            let parameters = serde_json::to_value(params).map_err(|error| {
                HttpClientError::CoreResult(McpError::internal_error(format!(
                    "final HTTP completion parameters could not serialize: {error}"
                )))
            })?;
            match self
                .inner
                .request_final_core(cx, "completion/complete", parameters)
                .await?
            {
                fastmcp_protocol::CoreResult::Final(
                    fastmcp_protocol::FinalCoreResult::Completion { result, .. },
                ) => Ok(result.payload),
                _ => Err(unexpected_modern_http_result("completion/complete")),
            }
        }

        /// Calls a tool through modern HTTP until one terminal final result arrives.
        ///
        /// `deadline` bounds the initial request and every continuation. The
        /// responder runs once per admitted `input_required` result, and this
        /// method never returns an intermediate input-required result.
        pub async fn call_tool_with_mrtr_retry<F>(
            &mut self,
            cx: &Cx,
            deadline: std::time::Instant,
            name: &str,
            arguments: JsonValue,
            sse_limits: SseLimits,
            maximum_response_bytes: usize,
            respond: F,
        ) -> Result<FinalCoreResult, HttpClientError>
        where
            F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
        {
            self.inner
                .call_tool_with_mrtr_retry(
                    cx,
                    deadline,
                    name,
                    arguments,
                    sse_limits,
                    maximum_response_bytes,
                    respond,
                )
                .await
        }

        /// Reads a resource through modern HTTP until one terminal final result arrives.
        ///
        /// See [`Self::call_tool_with_mrtr_retry`] for the shared
        /// deadline and responder semantics.
        pub async fn read_resource_with_mrtr_retry<F>(
            &mut self,
            cx: &Cx,
            deadline: std::time::Instant,
            uri: &str,
            sse_limits: SseLimits,
            maximum_response_bytes: usize,
            respond: F,
        ) -> Result<FinalCoreResult, HttpClientError>
        where
            F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
        {
            self.inner
                .read_resource_with_mrtr_retry(
                    cx,
                    deadline,
                    uri,
                    sse_limits,
                    maximum_response_bytes,
                    respond,
                )
                .await
        }

        /// Gets a prompt through modern HTTP until one terminal final result arrives.
        ///
        /// See [`Self::call_tool_with_mrtr_retry`] for the shared
        /// deadline and responder semantics.
        pub async fn get_prompt_with_mrtr_retry<F>(
            &mut self,
            cx: &Cx,
            deadline: std::time::Instant,
            name: &str,
            arguments: std::collections::HashMap<String, String>,
            sse_limits: SseLimits,
            maximum_response_bytes: usize,
            respond: F,
        ) -> Result<FinalCoreResult, HttpClientError>
        where
            F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
        {
            self.inner
                .get_prompt_with_mrtr_retry(
                    cx,
                    deadline,
                    name,
                    arguments,
                    sse_limits,
                    maximum_response_bytes,
                    respond,
                )
                .await
        }

        /// Opens a live final subscriptions listener.
        ///
        /// The listener owns this client's final-result cache borrow until it is
        /// dropped or collected, so accepted catalog and resource notifications
        /// invalidate cached results before [`HttpSubscriptionListener::next_event`]
        /// yields them.
        ///
        /// ```compile_fail
        /// use fastmcp_rust::modern::{Cx, HttpClient, HttpClientError, SseLimits, SubscriptionFilter};
        ///
        /// async fn cannot_request_while_listener_owns_the_cache(
        ///     client: &mut HttpClient,
        ///     cx: &Cx,
        ///     filter: SubscriptionFilter,
        ///     limits: SseLimits,
        /// ) -> Result<(), HttpClientError> {
        ///     let mut listener = client.open_subscriptions_listener(cx, filter, limits).await?;
        ///     let _ = client.list_tools(cx, None).await?;
        ///     let _ = listener.next_event(cx).await?;
        ///     Ok(())
        /// }
        /// ```
        pub async fn open_subscriptions_listener(
            &mut self,
            cx: &Cx,
            notifications: SubscriptionFilter,
            limits: SseLimits,
        ) -> Result<HttpSubscriptionListener<'_>, HttpClientError> {
            self.inner
                .open_subscriptions_listener(cx, notifications, limits)
                .await
        }

        /// Opens and collects one typed final subscriptions listener.
        pub async fn listen_subscriptions(
            &mut self,
            cx: &Cx,
            notifications: SubscriptionFilter,
            limits: fastmcp_client::sse::SseLimits,
        ) -> Result<ModernHttpSubscriptionListenCollector, HttpClientError> {
            self.inner
                .listen_subscriptions_typed(cx, notifications, limits)
                .await
        }

        /// Reads one task through the official final Tasks extension.
        pub async fn get_task(
            &mut self,
            cx: &Cx,
            request_id: RequestId,
            task_id: FinalTaskId,
            maximum_response_bytes: usize,
        ) -> Result<FinalGetTaskResult, HttpClientError> {
            self.inner
                .connection()
                .get_task_final(cx, request_id, task_id, maximum_response_bytes)
                .await
                .map_err(HttpClientError::Connection)
        }

        /// Supplies responses to one input-required final task.
        pub async fn update_task(
            &mut self,
            cx: &Cx,
            request_id: RequestId,
            task: &FinalTask,
            input_responses: FinalTaskInputResponses,
            maximum_response_bytes: usize,
        ) -> Result<FinalUpdateTaskResult, HttpClientError> {
            self.inner
                .connection()
                .update_task_final(
                    cx,
                    request_id,
                    task,
                    input_responses,
                    maximum_response_bytes,
                )
                .await
                .map_err(HttpClientError::Connection)
        }

        /// Requests cancellation through the official final Tasks extension.
        pub async fn cancel_task(
            &mut self,
            cx: &Cx,
            request_id: RequestId,
            task_id: FinalTaskId,
            maximum_response_bytes: usize,
        ) -> Result<FinalCancelTaskResult, HttpClientError> {
            self.inner
                .connection()
                .cancel_task_final(cx, request_id, task_id, maximum_response_bytes)
                .await
                .map_err(HttpClientError::Connection)
        }
    }

    fn final_list_parameters(cursor: Option<&str>) -> JsonValue {
        cursor.map_or_else(
            || serde_json::json!({}),
            |cursor| serde_json::json!({ "cursor": cursor }),
        )
    }

    fn final_stdio_mrtr_result(
        method: &'static str,
        result: fastmcp_protocol::CoreResult,
    ) -> McpResult<FinalCoreResult> {
        match result {
            fastmcp_protocol::CoreResult::Final(result) => Ok(result),
            fastmcp_protocol::CoreResult::Legacy(_) => Err(McpError::internal_error(format!(
                "ModernOnly stdio client received a non-final {method} result"
            ))),
        }
    }

    fn unexpected_modern_http_result(method: &'static str) -> HttpClientError {
        HttpClientError::CoreResult(McpError::internal_error(format!(
            "ModernOnly HTTP client received a non-final {method} result"
        )))
    }

    fn modern_http_plan(
        endpoint: CanonicalHttpUrl,
    ) -> Result<
        fastmcp_client::ClientProtocolPlan,
        fastmcp_protocol::protocol_policy::HttpEndpointBundleError,
    > {
        fastmcp_client::ClientProtocolPlan::http(
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

        /// Sets duplicate-registration behavior without changing the modern-only policy.
        #[must_use]
        pub fn on_duplicate(self, behavior: DuplicateBehavior) -> Self {
            Self {
                inner: self.inner.on_duplicate(behavior),
            }
        }

        /// Installs an authentication provider without changing the modern-only policy.
        #[must_use]
        pub fn auth_provider<P: AuthProvider + 'static>(self, provider: P) -> Self {
            Self {
                inner: self.inner.auth_provider(provider),
            }
        }

        /// Disables statistics collection.
        #[must_use]
        pub fn without_stats(self) -> Self {
            Self {
                inner: self.inner.without_stats(),
            }
        }

        /// Sets the server-owned request deadline in seconds.
        #[must_use]
        pub fn request_timeout(self, seconds: u64) -> Self {
            Self {
                inner: self.inner.request_timeout(seconds),
            }
        }

        /// Sets the bounded number of in-flight server-to-client requests.
        pub fn max_bidirectional_requests_per_connection(self, maximum: usize) -> McpResult<Self> {
            self.inner
                .max_bidirectional_requests_per_connection(maximum)
                .map(|inner| Self { inner })
        }

        /// Sets the final catalog page size.
        #[must_use]
        pub fn list_page_size(self, page_size: usize) -> Self {
            Self {
                inner: self.inner.list_page_size(page_size),
            }
        }

        /// Enables or disables internal-error detail masking.
        #[must_use]
        pub fn mask_error_details(self, enabled: bool) -> Self {
            Self {
                inner: self.inner.mask_error_details(enabled),
            }
        }

        /// Selects internal-error masking from the launch environment.
        #[must_use]
        pub fn auto_mask_errors(self) -> Self {
            Self {
                inner: self.inner.auto_mask_errors(),
            }
        }

        /// Enables or disables strict tool-input validation.
        #[must_use]
        pub fn strict_input_validation(self, enabled: bool) -> Self {
            Self {
                inner: self.inner.strict_input_validation(enabled),
            }
        }

        /// Installs era-neutral middleware without exposing a legacy dispatcher.
        #[must_use]
        pub fn middleware<M: Middleware + 'static>(self, middleware: M) -> Self {
            Self {
                inner: self.inner.middleware(middleware),
            }
        }

        /// Installs the official MCP Apps discovery marker.
        pub fn mcp_apps(self) -> Result<Self, ServerExtensionConfigurationError> {
            self.inner.mcp_apps().map(|inner| Self { inner })
        }

        /// Registers one final-only `ui://` HTML document for a negotiated MCP Apps View.
        ///
        /// This forwarding surface preserves the underlying builder's Apps
        /// opt-in requirement and excludes the document from exact-2024
        /// resource discovery and reads.
        pub fn mcp_apps_ui_resource(self, resource: McpAppsUiResource) -> McpResult<Self> {
            self.inner
                .mcp_apps_ui_resource(resource)
                .map(|inner| Self { inner })
        }

        /// Registers one final-only tool carrying typed MCP Apps UI metadata.
        ///
        /// This requires [`Self::mcp_apps`] and a previously registered linked
        /// [`McpAppsUiResource`]. The tool is absent from exact MCP 2024-11-05
        /// discovery and dispatch.
        pub fn mcp_apps_tool<H: ToolHandler + 'static>(self, handler: H) -> McpResult<Self> {
            self.inner
                .mcp_apps_tool(handler)
                .map(|inner| Self { inner })
        }

        /// Installs final-only extension handlers and discovery settings.
        pub fn extension_registry<R>(
            self,
            handlers: ExtensionHandlerRegistry,
            server_discovery: ServerExtensionDiscovery,
            resolver: R,
        ) -> Result<Self, ServerExtensionConfigurationError>
        where
            R: ExtensionSettingsCompatibilityResolver + Send + 'static,
        {
            self.inner
                .extension_registry(handlers, server_discovery, resolver)
                .map(|inner| Self { inner })
        }

        /// Installs the official final Tasks extension around application-owned state.
        pub fn final_tasks(
            self,
            task_runtime: FinalTaskRuntime,
        ) -> Result<Self, ServerExtensionConfigurationError> {
            self.inner
                .final_tasks(task_runtime)
                .map(|inner| Self { inner })
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

        /// Registers the server-wide final `completion/complete` handler.
        #[must_use]
        pub fn completion_handler<H: CompletionHandler + 'static>(self, handler: H) -> Self {
            Self {
                inner: self.inner.completion_handler(handler),
            }
        }

        /// Registers a final completion provider for one exact prompt name.
        ///
        /// The provider is reachable only after the named prompt has passed
        /// final catalog admission; it takes precedence over a server-wide
        /// completion fallback for that prompt.
        #[must_use]
        pub fn prompt_completion_handler<H: CompletionHandler + 'static>(
            self,
            prompt_name: impl Into<String>,
            handler: H,
        ) -> Self {
            Self {
                inner: self.inner.prompt_completion_handler(prompt_name, handler),
            }
        }

        /// Registers a final completion provider for one exact resource-template URI.
        ///
        /// The provider is reachable only after the template has passed final
        /// catalog admission; it takes precedence over a server-wide completion
        /// fallback for that template.
        #[must_use]
        pub fn resource_template_completion_handler<H: CompletionHandler + 'static>(
            self,
            uri_template: impl Into<String>,
            handler: H,
        ) -> Self {
            Self {
                inner: self
                    .inner
                    .resource_template_completion_handler(uri_template, handler),
            }
        }

        /// Sets the server instructions returned through final discovery.
        #[must_use]
        pub fn instructions(self, instructions: impl Into<String>) -> Self {
            Self {
                inner: self.inner.instructions(instructions),
            }
        }

        /// Sets the console configuration without changing the modern-only policy.
        #[must_use]
        pub fn with_console_config(self, config: ConsoleConfig) -> Self {
            Self {
                inner: self.inner.with_console_config(config),
            }
        }

        /// Selects a console banner style.
        #[must_use]
        pub fn with_banner(self, style: BannerStyle) -> Self {
            Self {
                inner: self.inner.with_banner(style),
            }
        }

        /// Disables the startup banner.
        #[must_use]
        pub fn without_banner(self) -> Self {
            Self {
                inner: self.inner.without_banner(),
            }
        }

        /// Sets request/response traffic logging verbosity.
        #[must_use]
        pub fn with_traffic_logging(self, verbosity: TrafficVerbosity) -> Self {
            Self {
                inner: self.inner.with_traffic_logging(verbosity),
            }
        }

        /// Builds a server with no facade-exposed legacy dispatcher.
        #[must_use]
        pub fn build(self) -> Server {
            self.try_build()
                .unwrap_or_else(|error| panic!("ModernOnly facade server build rejected: {error}"))
        }

        /// Builds a final-only server after validating the reserved launch policy.
        pub fn try_build(self) -> McpResult<Server> {
            let inner = self
                .inner
                .try_build()
                .map_err(|error| McpError::invalid_params(error.to_string()))?;
            if inner.protocol_policy()
                != fastmcp_protocol::protocol_policy::ProtocolPolicy::ModernOnly
            {
                return Err(McpError::invalid_request(
                    "ModernOnly facade server rejected a conflicting reserved launch policy",
                ));
            }
            Ok(Server { inner })
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
        ///
        /// The returned shutdown outcome retains any child that did not
        /// cooperate with the bounded listener drain, so the caller can settle
        /// it explicitly rather than losing ownership at shutdown.
        pub async fn serve(self, cx: &Cx) -> McpResult<HttpServerShutdown> {
            self.inner.serve(cx).await
        }
    }

    impl Server {
        /// Returns final discovery metadata.
        pub fn server_discovery(&self) -> McpResult<ServerDiscoverResult> {
            self.inner.server_discovery()
        }

        /// Returns application-owned final Tasks state when configured.
        #[must_use]
        pub fn final_task_runtime(&self) -> Option<&FinalTaskRuntime> {
            self.inner.final_task_runtime()
        }

        /// Publishes a final catalog or resource change notification.
        pub fn publish_subscription_notification(
            &self,
            notification: ServerNotification,
        ) -> McpResult<usize> {
            self.inner.publish_subscription_notification(notification)
        }

        /// Publishes one typed final Tasks status notification.
        pub fn publish_task_status_notification(
            &self,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<usize> {
            self.inner.publish_task_status_notification(notification)
        }

        /// Binds this facade-pinned server to a caller-owned final HTTP listener.
        pub async fn bind_http(self, cx: &Cx, addr: impl Into<String>) -> McpResult<HttpServer> {
            self.inner
                .bind_http(cx, addr)
                .await
                .map(|inner| HttpServer { inner })
        }

        /// Binds and serves this facade-pinned server over final HTTP.
        pub async fn serve_http(
            self,
            cx: &Cx,
            addr: impl Into<String>,
        ) -> McpResult<HttpServerShutdown> {
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
///
/// ```compile_fail
/// use fastmcp_rust::legacy_2024;
///
/// let _ = legacy_2024::LegacySseHttpClient::connect;
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::legacy_2024::ElicitRequestParams;
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::legacy_2024::FinalTaskId;
/// ```
///
/// ```compile_fail
/// use fastmcp_rust::legacy_2024::connect_websocket_with_cx;
/// ```
#[cfg(feature = "legacy-2024-11-05")]
pub mod legacy_2024 {
    pub use fastmcp_client::{
        CreateMessageParams as LegacyCreateMessageParams,
        CreateMessageResult as LegacyCreateMessageResult, HttpClientError,
        ListRootsParams as LegacyListRootsParams, ListRootsResult as LegacyListRootsResult,
        RequestTimeoutPolicy, RequestTimeoutSource, ReverseRequest, ReverseRequestCancellation,
        ReverseRequestHandlers as LegacyReverseRequestHandlers,
        RootsRequestHandler as LegacyRootsRequestHandler,
        SamplingRequestHandler as LegacySamplingRequestHandler,
    };
    pub use fastmcp_core::{
        CanonicalHttpUrl, ClientRoot, Cx, McpContext, McpError, McpOutcome, McpResult,
        RootsProvider,
    };
    pub use fastmcp_derive::{JsonSchema, prompt, resource, tool};
    pub use fastmcp_protocol::common_types::JsonInteger;
    pub use fastmcp_protocol::protocol_policy::{
        HttpEndpointBundleError, LEGACY_PROTOCOL_VERSION, LegacyAdapterReceiptIssuer,
        LegacyClientAdapterInstalledReceipt, LegacyReceiptBinding,
        LegacyServerAdapterInstalledReceipt as PolicyServerAdapterInstalledReceipt, ProtocolPolicy,
    };
    pub use fastmcp_protocol::{
        CallToolParams, CallToolResult, CancellationSender, CancellationWireCodecError,
        CancellationWireMessage, CancelledParams, ClientCapabilities, ClientInfo, CompletionValues,
        CreateMessageParams, CreateMessageResult, GetPromptParams, GetPromptResult, Icon,
        IncludeContext, InitializeParams, InitializeResult, JsonRpcMessage, JsonRpcRequest,
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
        SetLogLevelParams, SubscribeResourceParams, Tool, ToolAnnotations, ToolsCapability,
        UnsubscribeResourceParams,
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
        AuthProvider, BannerStyle, CompletionHandler, ConsoleConfig, DuplicateBehavior,
        HttpNonquiescentShutdown, HttpServerShutdown, HttpShutdownSettlement, Middleware,
        PromptHandler, ResourceHandler, ServerLaunchPolicyError, ToolErrorKind, ToolHandler,
        TrafficVerbosity,
    };
    pub use fastmcp_transport::sse::{
        LegacySseClientTransport, LegacySseMessagePost, LegacySsePostSink, LegacySseServerTransport,
    };
    pub use serde_json::{self, Map as JsonMap, Value as JsonValue, json};

    /// The exact client-originated legacy notification exposed by this
    /// facade.
    ///
    /// `notifications/roots/list_changed` is capability-gated by the
    /// client's advertised `roots.listChanged` value. Its sealed HTTP
    /// operation is available on [`HttpClient::roots_list_changed`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ClientNotification {
        /// `notifications/roots/list_changed`.
        RootsListChanged,
    }

    impl ClientNotification {
        /// Returns the exact legacy method literal.
        #[must_use]
        pub const fn method(self) -> &'static str {
            match self {
                Self::RootsListChanged => methods::NOTIFICATIONS_ROOTS_LIST_CHANGED,
            }
        }

        /// Encodes this notification without exposing a generic wire writer.
        #[must_use]
        pub fn encode(self) -> JsonRpcRequest {
            JsonRpcRequest::notification(self.method(), None)
        }
    }

    /// Typed exact-2024 notifications that a server may originate.
    ///
    /// The enum deliberately excludes `notifications/roots/list_changed`:
    /// that method is client-to-server only in the pinned 2024 schema.
    #[derive(Debug, Clone)]
    pub enum ServerNotification {
        /// `notifications/cancelled`.
        Cancelled(CancelledParams),
        /// `notifications/progress`.
        Progress(ProgressParams),
        /// `notifications/message`.
        Message(LogMessageParams),
        /// `notifications/prompts/list_changed`.
        PromptsListChanged,
        /// `notifications/resources/list_changed`.
        ResourcesListChanged,
        /// `notifications/resources/updated`.
        ResourceUpdated(ResourceUpdatedNotificationParams),
        /// `notifications/tools/list_changed`.
        ToolsListChanged,
    }

    impl ServerNotification {
        /// Decodes one exact legacy server notification from an admitted
        /// JSON-RPC notification envelope.
        ///
        /// The pinned legacy envelope parser validates the JSON-RPC shape and
        /// method parameters before this direction-specific projection.
        pub fn decode(request: &JsonRpcRequest) -> McpResult<Self> {
            let wire = serde_json::to_value(request).map_err(|error| {
                McpError::internal_error(format!(
                    "Legacy notification could not be represented: {error}"
                ))
            })?;
            let envelope = fastmcp_protocol::methods::decode_legacy_2024_11_05_envelope(wire)
                .map_err(|error| {
                    McpError::invalid_params(format!(
                        "Invalid MCP 2024-11-05 notification: {error}"
                    ))
                })?;
            let fastmcp_protocol::methods::Legacy2024Envelope::Notification { method, params } =
                envelope
            else {
                return Err(McpError::invalid_params(
                    "MCP 2024-11-05 server notification requires a notification envelope",
                ));
            };

            match method.name {
                methods::NOTIFICATIONS_CANCELLED => {
                    decode_legacy_server_notification_params(params, method.name)
                        .map(Self::Cancelled)
                }
                methods::NOTIFICATIONS_PROGRESS => {
                    decode_legacy_server_notification_params(params, method.name)
                        .map(Self::Progress)
                }
                methods::NOTIFICATIONS_MESSAGE => {
                    decode_legacy_server_notification_params(params, method.name).map(Self::Message)
                }
                methods::NOTIFICATIONS_PROMPTS_LIST_CHANGED => Ok(Self::PromptsListChanged),
                methods::NOTIFICATIONS_RESOURCES_LIST_CHANGED => Ok(Self::ResourcesListChanged),
                methods::NOTIFICATIONS_RESOURCES_UPDATED => {
                    decode_legacy_server_notification_params(params, method.name)
                        .map(Self::ResourceUpdated)
                }
                methods::NOTIFICATIONS_TOOLS_LIST_CHANGED => Ok(Self::ToolsListChanged),
                _ => Err(McpError::invalid_params(
                    "notification direction is not server-to-client in exact MCP 2024-11-05",
                )),
            }
        }

        /// Returns the exact legacy method literal.
        #[must_use]
        pub const fn method(&self) -> &'static str {
            match self {
                Self::Cancelled(_) => methods::NOTIFICATIONS_CANCELLED,
                Self::Progress(_) => methods::NOTIFICATIONS_PROGRESS,
                Self::Message(_) => methods::NOTIFICATIONS_MESSAGE,
                Self::PromptsListChanged => methods::NOTIFICATIONS_PROMPTS_LIST_CHANGED,
                Self::ResourcesListChanged => methods::NOTIFICATIONS_RESOURCES_LIST_CHANGED,
                Self::ResourceUpdated(_) => methods::NOTIFICATIONS_RESOURCES_UPDATED,
                Self::ToolsListChanged => methods::NOTIFICATIONS_TOOLS_LIST_CHANGED,
            }
        }
    }

    fn decode_legacy_server_notification_params<T>(
        params: Option<serde_json::Value>,
        method: &str,
    ) -> McpResult<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let params = params.ok_or_else(|| {
            McpError::invalid_params(format!(
                "MCP 2024-11-05 {method} requires notification parameters"
            ))
        })?;
        serde_json::from_value(params).map_err(|_| {
            McpError::invalid_params(format!(
                "MCP 2024-11-05 {method} notification parameters are invalid"
            ))
        })
    }

    /// Exact MCP 2024-11-05 method vocabulary.
    ///
    /// This intentionally does not re-export the mixed-era protocol methods
    /// module: final discovery and subscription constants cannot be named from
    /// the LegacyOnly facade.
    ///
    /// ```compile_fail
    /// use fastmcp_rust::legacy_2024;
    ///
    /// let _ = legacy_2024::methods::SERVER_DISCOVER;
    /// ```
    pub mod methods {
        pub use fastmcp_protocol::methods::{
            COMPLETION_COMPLETE, INITIALIZE, LEGACY_2024_11_05_METHODS,
            LEGACY_2024_11_05_PROTOCOL_VERSION, LEGACY_2024_11_05_SCHEMA_JSON,
            LEGACY_2024_11_05_SCHEMA_SHA256, LOGGING_SET_LEVEL, Legacy2024Capability,
            Legacy2024Direction, Legacy2024Envelope, Legacy2024EnvelopeError,
            Legacy2024EnvelopeKind, Legacy2024ListChangedCapability, Legacy2024Method,
            Legacy2024ResourcesCapability, Legacy2024ResultDisposition, Legacy2024ResultKind,
            Legacy2024ServerCapabilities, Legacy2024WireError, NOTIFICATIONS_CANCELLED,
            NOTIFICATIONS_INITIALIZED, NOTIFICATIONS_MESSAGE, NOTIFICATIONS_PROGRESS,
            NOTIFICATIONS_PROMPTS_LIST_CHANGED, NOTIFICATIONS_RESOURCES_LIST_CHANGED,
            NOTIFICATIONS_RESOURCES_UPDATED, NOTIFICATIONS_ROOTS_LIST_CHANGED,
            NOTIFICATIONS_TOOLS_LIST_CHANGED, PING, PROMPTS_GET, PROMPTS_LIST, RESOURCES_LIST,
            RESOURCES_READ, RESOURCES_SUBSCRIBE, RESOURCES_TEMPLATES_LIST, RESOURCES_UNSUBSCRIBE,
            ROOTS_LIST, SAMPLING_CREATE_MESSAGE, TOOLS_CALL, TOOLS_LIST,
            classify_legacy_2024_result, decode_legacy_2024_11_05_client_capabilities,
            decode_legacy_2024_11_05_envelope, decode_legacy_2024_11_05_envelope_classified,
            decode_legacy_2024_11_05_server_capabilities, legacy_2024_11_05_method,
            legacy_2024_11_05_schema, translate_legacy_2024_result,
            validate_legacy_2024_11_05_initialize_result, validate_legacy_2024_11_05_method_params,
        };
    }

    /// Failure while constructing or connecting the exact MCP 2024-11-05 HTTP plan.
    #[derive(Debug)]
    pub enum HttpClientConnectError {
        /// The supplied SSE and message endpoints cannot form an exact legacy plan.
        Plan(fastmcp_protocol::protocol_policy::HttpEndpointBundleError),
        /// The legacy HTTP lifecycle or transport failed.
        Connect(HttpClientError),
    }

    impl std::fmt::Display for HttpClientConnectError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Plan(error) => error.fmt(formatter),
                Self::Connect(error) => error.fmt(formatter),
            }
        }
    }

    impl std::error::Error for HttpClientConnectError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Plan(error) => Some(error),
                Self::Connect(error) => Some(error),
            }
        }
    }

    /// An exact MCP 2024-11-05 server builder.
    ///
    /// It forwards only configuration and exact-2024 registration methods;
    /// callers cannot reset its policy or register a final-only component
    /// through this namespace.
    pub struct ServerBuilder {
        inner: fastmcp_server::ServerBuilder,
    }

    impl ServerBuilder {
        /// Creates a builder permanently pinned to exact MCP 2024-11-05.
        #[must_use]
        pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
            Self {
                inner: fastmcp_server::ServerBuilder::new(name, version)
                    .protocol_policy(fastmcp_protocol::protocol_policy::ProtocolPolicy::LegacyOnly),
            }
        }

        /// Returns the sole policy admitted by this builder.
        #[must_use]
        pub const fn protocol_policy(&self) -> ProtocolPolicy {
            ProtocolPolicy::LegacyOnly
        }

        /// Sets duplicate-registration behavior.
        #[must_use]
        pub fn on_duplicate(self, behavior: DuplicateBehavior) -> Self {
            Self {
                inner: self.inner.on_duplicate(behavior),
            }
        }

        /// Installs an authentication provider.
        #[must_use]
        pub fn auth_provider<P: AuthProvider + 'static>(self, provider: P) -> Self {
            Self {
                inner: self.inner.auth_provider(provider),
            }
        }

        /// Disables statistics collection.
        #[must_use]
        pub fn without_stats(self) -> Self {
            Self {
                inner: self.inner.without_stats(),
            }
        }

        /// Sets the server-owned request deadline in seconds.
        #[must_use]
        pub fn request_timeout(self, seconds: u64) -> Self {
            Self {
                inner: self.inner.request_timeout(seconds),
            }
        }

        /// Sets the bounded number of in-flight server-to-client requests.
        pub fn max_bidirectional_requests_per_connection(self, maximum: usize) -> McpResult<Self> {
            self.inner
                .max_bidirectional_requests_per_connection(maximum)
                .map(|inner| Self { inner })
        }

        /// Sets the exact-2024 catalog page size.
        #[must_use]
        pub fn list_page_size(self, page_size: usize) -> Self {
            Self {
                inner: self.inner.list_page_size(page_size),
            }
        }

        /// Enables or disables internal-error detail masking.
        #[must_use]
        pub fn mask_error_details(self, enabled: bool) -> Self {
            Self {
                inner: self.inner.mask_error_details(enabled),
            }
        }

        /// Selects internal-error masking from the launch environment.
        #[must_use]
        pub fn auto_mask_errors(self) -> Self {
            Self {
                inner: self.inner.auto_mask_errors(),
            }
        }

        /// Enables or disables strict tool-input validation.
        #[must_use]
        pub fn strict_input_validation(self, enabled: bool) -> Self {
            Self {
                inner: self.inner.strict_input_validation(enabled),
            }
        }

        /// Installs era-neutral middleware.
        #[must_use]
        pub fn middleware<M: Middleware + 'static>(self, middleware: M) -> Self {
            Self {
                inner: self.inner.middleware(middleware),
            }
        }

        /// Registers an exact-2024-only tool handler.
        #[must_use]
        pub fn tool<H: ToolHandler + 'static>(self, handler: H) -> Self {
            Self {
                inner: self.inner.legacy_tool(handler),
            }
        }

        /// Registers an exact-2024-only resource handler.
        #[must_use]
        pub fn resource<H: ResourceHandler + 'static>(self, handler: H) -> Self {
            Self {
                inner: self.inner.legacy_resource(handler),
            }
        }

        /// Advertises resource-subscription support for registered resources.
        #[must_use]
        pub fn resource_subscriptions(self) -> Self {
            Self {
                inner: self.inner.resource_subscriptions(),
            }
        }

        /// Registers an exact-2024 resource template.
        #[must_use]
        pub fn resource_template(self, template: ResourceTemplate) -> Self {
            Self {
                inner: self.inner.legacy_resource_template(template),
            }
        }

        /// Registers an exact-2024-only prompt handler.
        #[must_use]
        pub fn prompt<H: PromptHandler + 'static>(self, handler: H) -> Self {
            Self {
                inner: self.inner.legacy_prompt(handler),
            }
        }

        /// Registers the exact-2024 completion handler.
        #[must_use]
        pub fn completion_handler<H: CompletionHandler + 'static>(self, handler: H) -> Self {
            Self {
                inner: self.inner.legacy_completion_handler(handler),
            }
        }

        /// Sets server instructions.
        #[must_use]
        pub fn instructions(self, instructions: impl Into<String>) -> Self {
            Self {
                inner: self.inner.instructions(instructions),
            }
        }

        /// Sets the console configuration.
        #[must_use]
        pub fn with_console_config(self, config: ConsoleConfig) -> Self {
            Self {
                inner: self.inner.with_console_config(config),
            }
        }

        /// Selects a console banner style.
        #[must_use]
        pub fn with_banner(self, style: BannerStyle) -> Self {
            Self {
                inner: self.inner.with_banner(style),
            }
        }

        /// Disables the startup banner.
        #[must_use]
        pub fn without_banner(self) -> Self {
            Self {
                inner: self.inner.without_banner(),
            }
        }

        /// Sets request/response traffic logging verbosity.
        #[must_use]
        pub fn with_traffic_logging(self, verbosity: TrafficVerbosity) -> Self {
            Self {
                inner: self.inner.with_traffic_logging(verbosity),
            }
        }

        /// Builds an exact-2024 server.
        #[must_use]
        pub fn build(self) -> Server {
            self.try_build()
                .unwrap_or_else(|error| panic!("LegacyOnly facade server build rejected: {error}"))
        }

        /// Builds an exact-2024 server after validating launch policy input.
        pub fn try_build(self) -> McpResult<Server> {
            let inner = self
                .inner
                .try_build()
                .map_err(|error| McpError::invalid_params(error.to_string()))?;
            if inner.protocol_policy()
                != fastmcp_protocol::protocol_policy::ProtocolPolicy::LegacyOnly
            {
                return Err(McpError::invalid_request(
                    "LegacyOnly facade server rejected a conflicting reserved launch policy",
                ));
            }
            Ok(Server { inner })
        }
    }

    /// A server built by the exact-2024 facade.
    pub struct Server {
        inner: fastmcp_server::Server,
    }

    /// A bound exact-2024 HTTP+SSE server lifecycle.
    ///
    /// This wrapper can arise only from a [`Server`] built by the
    /// [`legacy_2024`] facade. Its inner listener is intentionally private so
    /// callers cannot change the preselected `LegacyOnly` protocol policy.
    pub struct HttpServer {
        inner: fastmcp_server::BoundHttpServer,
    }

    impl HttpServer {
        /// Returns the address selected for this exact legacy listener.
        pub fn local_addr(&self) -> McpResult<std::net::SocketAddr> {
            self.inner.local_addr()
        }

        /// Serves only the exact MCP 2024-11-05 HTTP+SSE routes until the
        /// caller-owned context is cancelled.
        pub async fn serve(self, cx: &Cx) -> McpResult<HttpServerShutdown> {
            self.inner.serve(cx).await
        }
    }

    impl Server {
        /// Runs this exact-2024 server over stdio.
        pub fn run_stdio(self) -> ! {
            self.inner.run_stdio()
        }

        /// Binds this `LegacyOnly` server to the exact 2024 HTTP+SSE route
        /// pair on a caller-owned context.
        pub async fn bind_http(self, cx: &Cx, addr: impl Into<String>) -> McpResult<HttpServer> {
            self.inner
                .bind_http(cx, addr)
                .await
                .map(|inner| HttpServer { inner })
        }

        /// Binds and serves this `LegacyOnly` server over the exact 2024
        /// HTTP+SSE transport.
        pub async fn serve_http(
            self,
            cx: &Cx,
            addr: impl Into<String>,
        ) -> McpResult<HttpServerShutdown> {
            self.inner.serve_http(cx, addr).await
        }
    }

    /// Creates a server builder pinned to exact MCP 2024-11-05.
    #[must_use]
    pub fn server_builder(name: impl Into<String>, version: impl Into<String>) -> ServerBuilder {
        ServerBuilder::new(name, version)
    }

    /// A sealed exact-2024 stdio client.
    ///
    /// The root client now defaults to bounded `Auto` selection. This wrapper
    /// keeps both construction and callable operations in the exact legacy
    /// vocabulary, so a facade-only consumer cannot reach final methods by
    /// dereferencing an otherwise legacy-selected connection.
    ///
    /// ```compile_fail
    /// use fastmcp_rust::{JsonValue, legacy_2024};
    ///
    /// fn cannot_call_final(client: &mut legacy_2024::Client) {
    ///     let _ = client.call_tool_final("tool", JsonValue::Null);
    /// }
    /// ```
    pub struct Client {
        inner: fastmcp_client::Client,
    }

    impl Client {
        fn from_inner(inner: fastmcp_client::Client) -> Self {
            Self { inner }
        }

        /// Opens one exact MCP 2024-11-05 stdio client.
        pub fn stdio(command: &str, args: &[&str]) -> McpResult<Self> {
            fastmcp_client::Client::stdio_with_protocol_plan(
                command,
                args,
                fastmcp_client::ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            )
            .map(Self::from_inner)
        }

        /// Opens one exact MCP 2024-11-05 stdio client with `cx`.
        pub fn stdio_with_cx(command: &str, args: &[&str], cx: Cx) -> McpResult<Self> {
            fastmcp_client::Client::stdio_with_protocol_plan_with_cx(
                command,
                args,
                fastmcp_client::ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
                cx,
            )
            .map(Self::from_inner)
        }

        /// Creates a builder whose transport plan is sealed to exact legacy.
        #[must_use]
        pub fn builder() -> ClientBuilder {
            ClientBuilder::new()
        }

        /// Ensures the exact legacy initialization lifecycle has completed.
        pub fn ensure_initialized(&mut self) -> McpResult<()> {
            self.inner.ensure_initialized()
        }

        /// Returns whether the exact legacy initialization lifecycle completed.
        #[must_use]
        pub fn is_initialized(&self) -> bool {
            self.inner.is_initialized()
        }

        /// Returns the negotiated exact MCP 2024-11-05 version.
        #[must_use]
        pub fn protocol_version(&self) -> &str {
            self.inner.protocol_version()
        }

        /// Returns the initialized server identity.
        #[must_use]
        pub fn server_info(&self) -> &ServerInfo {
            self.inner.server_info()
        }

        /// Returns the initialized exact-2024 server capabilities.
        #[must_use]
        pub fn server_capabilities(&self) -> &ServerCapabilities {
            self.inner.server_capabilities()
        }

        /// Sends `notifications/roots/list_changed` on this exact-2024 stdio
        /// connection.
        ///
        /// This requires the client to have advertised `roots.listChanged`
        /// during initialization. The sealed facade intentionally offers no
        /// modern equivalent.
        pub fn roots_list_changed(&mut self) -> McpResult<()> {
            self.inner.roots_list_changed()
        }

        /// Direction-checks one exact legacy server notification supplied by
        /// a caller-owned ingress adapter.
        ///
        /// This is useful for stdio integrations that retain server
        /// notifications alongside ordinary request dispatch while preserving
        /// the facade's exact typed notification vocabulary.
        pub fn decode_server_notification(
            notification: &JsonRpcRequest,
        ) -> McpResult<ServerNotification> {
            ServerNotification::decode(notification)
        }

        /// Installs exact-2024 reverse request handlers.
        pub fn set_reverse_request_handlers(
            &mut self,
            handlers: LegacyReverseRequestHandlers,
        ) -> McpResult<()> {
            self.inner.set_reverse_request_handlers(handlers)
        }

        /// Sends the exact-2024 `ping` request.
        pub fn ping(&mut self) -> McpResult<()> {
            self.inner.ping()
        }

        /// Lists exact-2024 tools.
        pub fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
            self.inner.list_tools()
        }

        /// Calls one exact-2024 tool without final-result projection.
        pub fn call_tool(&mut self, name: &str, arguments: JsonValue) -> McpResult<CallToolResult> {
            self.inner.call_tool_legacy(name, arguments)
        }

        /// Lists exact-2024 resources.
        pub fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
            self.inner.list_resources()
        }

        /// Lists exact-2024 resource templates.
        pub fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
            self.inner.list_resource_templates()
        }

        /// Reads one exact-2024 resource.
        pub fn read_resource(&mut self, uri: &str) -> McpResult<ReadResourceResult> {
            self.inner.read_resource_legacy(uri)
        }

        /// Starts an exact-2024 resource subscription.
        pub fn subscribe_resource(&mut self, uri: &str) -> McpResult<()> {
            self.inner.subscribe_resource_legacy(uri)
        }

        /// Ends an exact-2024 resource subscription.
        pub fn unsubscribe_resource(&mut self, uri: &str) -> McpResult<()> {
            self.inner.unsubscribe_resource_legacy(uri)
        }

        /// Lists exact-2024 prompts.
        pub fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
            self.inner.list_prompts()
        }

        /// Gets one exact-2024 prompt.
        pub fn get_prompt(
            &mut self,
            name: &str,
            arguments: std::collections::HashMap<String, String>,
        ) -> McpResult<GetPromptResult> {
            self.inner.get_prompt_legacy(name, arguments)
        }

        /// Completes one exact-2024 prompt or resource-template argument.
        pub fn complete(
            &mut self,
            params: LegacyCompletionParams,
        ) -> McpResult<LegacyCompletionResult> {
            let reference = match params.reference {
                LegacyCompletionReference::Prompt { name } => {
                    fastmcp_client::CompletionReference::Prompt { name }
                }
                LegacyCompletionReference::Resource { uri } => {
                    fastmcp_client::CompletionReference::Resource { uri }
                }
            };
            let result = self.inner.complete(fastmcp_client::CompletionParams {
                reference,
                argument: fastmcp_client::CompletionArgument {
                    name: params.argument.name,
                    value: params.argument.value,
                },
                context: None,
            })?;
            match result {
                fastmcp_protocol::CoreResult::Legacy(LegacyCoreResult::Completion(result)) => {
                    Ok(result)
                }
                fastmcp_protocol::CoreResult::Final(_) => Err(McpError::internal_error(
                    "LegacyOnly facade received a final completion result",
                )),
                _ => Err(McpError::internal_error(
                    "LegacyOnly facade received an unexpected completion result",
                )),
            }
        }

        /// Sends the exact-2024 cancellation notification for one live request.
        pub fn cancel_request(
            &mut self,
            request_id: RequestId,
            reason: Option<String>,
        ) -> McpResult<()> {
            self.inner.cancel_request(request_id, reason)
        }

        /// Sends exact-2024 `logging/setLevel`.
        pub fn set_log_level(&mut self, level: LogLevel) -> McpResult<()> {
            self.inner.set_log_level(level)
        }

        /// Closes the exact legacy client and its owned subprocess resources.
        pub fn close(&mut self) -> McpResult<()> {
            self.inner.close()
        }
    }

    /// A builder sealed to exact MCP 2024-11-05.
    ///
    /// This wrapper intentionally has no raw protocol-plan surface: callers
    /// that need modern or Auto negotiation must select the root, `modern`,
    /// or `auto` namespace explicitly.
    ///
    /// ```compile_fail
    /// use fastmcp_rust::{legacy_2024, ProtocolPolicy};
    ///
    /// let _ = legacy_2024::ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly);
    /// ```
    ///
    /// ```compile_fail
    /// use fastmcp_rust::legacy_2024;
    ///
    /// let _ = legacy_2024::ProtocolEra::Modern2026;
    /// ```
    #[derive(Clone)]
    pub struct ClientBuilder {
        inner: fastmcp_client::ClientBuilder,
    }

    impl ClientBuilder {
        fn from_inner(inner: fastmcp_client::ClientBuilder) -> Self {
            Self { inner }
        }

        /// Creates an exact-2024 stdio builder.
        #[must_use]
        pub fn new() -> Self {
            Self::from_inner(fastmcp_client::ClientBuilder::new().protocol_plan(
                fastmcp_client::ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            ))
        }

        /// Sets the legacy client identity.
        #[must_use]
        pub fn client_info(self, name: impl Into<String>, version: impl Into<String>) -> Self {
            Self::from_inner(self.inner.client_info(name, version))
        }

        /// Sets the ordinary-request timeout policy.
        #[must_use]
        pub fn request_timeout_policy(self, policy: RequestTimeoutPolicy) -> Self {
            Self::from_inner(self.inner.request_timeout_policy(policy))
        }

        /// Sets the bounded connection retry count.
        #[must_use]
        pub fn max_retries(self, retries: u32) -> Self {
            Self::from_inner(self.inner.max_retries(retries))
        }

        /// Sets the retry delay in milliseconds.
        #[must_use]
        pub fn retry_delay_ms(self, delay: u64) -> Self {
            Self::from_inner(self.inner.retry_delay_ms(delay))
        }

        /// Sets a validated bounded connection retry policy.
        pub fn connection_retry_policy(
            self,
            max_attempts: u32,
            retry_delay: std::time::Duration,
            total_elapsed: std::time::Duration,
        ) -> McpResult<Self> {
            self.inner
                .connection_retry_policy(max_attempts, retry_delay, total_elapsed)
                .map(Self::from_inner)
        }

        /// Sets the subprocess working directory.
        #[must_use]
        pub fn working_dir(self, path: impl Into<std::path::PathBuf>) -> Self {
            Self::from_inner(self.inner.working_dir(path))
        }

        /// Adds a subprocess environment variable.
        #[must_use]
        pub fn env(self, key: impl Into<String>, value: impl Into<String>) -> Self {
            Self::from_inner(self.inner.env(key, value))
        }

        /// Adds several subprocess environment variables.
        #[must_use]
        pub fn envs<I, K, V>(self, vars: I) -> Self
        where
            I: IntoIterator<Item = (K, V)>,
            K: Into<String>,
            V: Into<String>,
        {
            Self::from_inner(self.inner.envs(vars))
        }

        /// Selects whether the subprocess inherits the parent environment.
        #[must_use]
        pub fn inherit_env(self, inherit: bool) -> Self {
            Self::from_inner(self.inner.inherit_env(inherit))
        }

        /// Sets exact-2024 initialization capabilities.
        #[must_use]
        pub fn capabilities(self, capabilities: ClientCapabilities) -> Self {
            Self::from_inner(self.inner.capabilities(capabilities))
        }

        /// Sets exact-2024 reverse request handlers.
        #[must_use]
        pub fn reverse_request_handlers(self, handlers: LegacyReverseRequestHandlers) -> Self {
            Self::from_inner(self.inner.reverse_request_handlers(handlers))
        }

        /// Defers exact legacy initialization until the first request.
        #[must_use]
        pub fn auto_initialize(self, enabled: bool) -> Self {
            Self::from_inner(self.inner.auto_initialize(enabled))
        }

        /// Selects private process-group ownership for the legacy child.
        #[must_use]
        pub fn owned_process_group(self, enabled: bool) -> Self {
            Self::from_inner(self.inner.owned_process_group(enabled))
        }

        /// Returns the sole policy admitted by this builder.
        #[must_use]
        pub const fn protocol_policy(&self) -> ProtocolPolicy {
            ProtocolPolicy::LegacyOnly
        }

        /// Connects the sealed exact-2024 stdio plan.
        ///
        /// The returned facade client has already completed an immutable
        /// legacy selection; no Auto negotiation occurs in this entry point.
        pub fn connect_stdio(self, command: &str, args: &[&str]) -> McpResult<Client> {
            self.inner
                .connect_stdio(command, args)
                .map(Client::from_inner)
        }

        /// Connects the sealed exact-2024 stdio plan with `cx`.
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

        /// Connects and initializes the sealed exact-2024 HTTP+SSE plan.
        pub fn connect_http(self) -> Result<HttpClient, HttpClientError> {
            self.inner.connect_http_client().map(HttpClient::from_inner)
        }

        /// Connects and initializes the sealed exact-2024 HTTP+SSE plan with `cx`.
        pub async fn connect_http_with_cx(self, cx: &Cx) -> Result<HttpClient, HttpClientError> {
            self.inner
                .connect_http_client_with_cx(cx)
                .await
                .map(HttpClient::from_inner)
        }

        /// Connects a ready exact-2024 HTTP client.
        pub fn connect_http_client(self) -> Result<HttpClient, HttpClientError> {
            self.inner.connect_http_client().map(HttpClient::from_inner)
        }

        /// Connects a ready exact-2024 HTTP client with `cx`.
        pub async fn connect_http_client_with_cx(
            self,
            cx: &Cx,
        ) -> Result<HttpClient, HttpClientError> {
            self.inner
                .connect_http_client_with_cx(cx)
                .await
                .map(HttpClient::from_inner)
        }
    }

    /// A ready HTTP client produced only by a sealed exact-2024 plan.
    ///
    /// This wrapper intentionally withholds its mutable transport and generic
    /// request dispatcher. Its methods name only exact-2024 requests and
    /// reject an unexpected final result before it reaches the caller.
    ///
    /// ```compile_fail
    /// use fastmcp_rust::legacy_2024;
    ///
    /// fn cannot_reach_transport(client: &mut legacy_2024::HttpClient) {
    ///     let _ = client.connection_mut();
    /// }
    /// ```
    pub struct HttpClient {
        inner: fastmcp_client::HttpClient,
    }

    impl HttpClient {
        fn from_inner(inner: fastmcp_client::HttpClient) -> Self {
            Self { inner }
        }

        fn unexpected_result(method: &'static str) -> HttpClientError {
            HttpClientError::CoreResult(McpError::internal_error(format!(
                "LegacyOnly facade received an unexpected result for {method}"
            )))
        }

        fn encode_params<T: serde::Serialize>(params: T) -> Result<JsonValue, HttpClientError> {
            serde_json::to_value(params).map_err(|error| {
                HttpClientError::CoreResult(McpError::invalid_params(format!(
                    "LegacyOnly facade could not encode legacy request parameters: {error}"
                )))
            })
        }

        async fn request_legacy_core(
            &mut self,
            cx: &Cx,
            method: &'static str,
            parameters: JsonValue,
        ) -> Result<LegacyCoreResult, HttpClientError> {
            match self
                .inner
                .request_final_core(cx, method, parameters)
                .await?
            {
                fastmcp_protocol::CoreResult::Legacy(result) => Ok(result),
                fastmcp_protocol::CoreResult::Final(_) => {
                    Err(HttpClientError::CoreResult(McpError::internal_error(
                        format!("LegacyOnly facade received a final result for {method}"),
                    )))
                }
            }
        }

        async fn request_legacy_empty(
            &mut self,
            cx: &Cx,
            method: &'static str,
            parameters: JsonValue,
        ) -> Result<(), HttpClientError> {
            let response = self.inner.request(cx, method, parameters).await?;
            let fastmcp_client::ClientHttpResponse::Legacy(JsonRpcMessage::Response(response)) =
                response
            else {
                return Err(Self::unexpected_result(method));
            };
            if let Some(error) = response.error {
                return Err(HttpClientError::CoreResult(McpError::invalid_request(
                    error.message,
                )));
            }
            let result = response
                .result
                .ok_or_else(|| Self::unexpected_result(method))?;
            serde_json::from_value::<LegacyEmptyResult>(result)
                .map(|_| ())
                .map_err(|_| Self::unexpected_result(method))
        }

        /// Returns the sole policy admitted by this HTTP client.
        #[must_use]
        pub const fn protocol_policy(&self) -> ProtocolPolicy {
            ProtocolPolicy::LegacyOnly
        }

        /// Returns the negotiated exact-2024 version after initialization.
        #[must_use]
        pub fn protocol_version(&self) -> Option<&str> {
            self.inner.connection().protocol_version()
        }

        /// Returns the exact legacy server identity admitted at initialization.
        #[must_use]
        pub fn server_info(&self) -> &ServerInfo {
            self.inner.server_info()
        }

        /// Returns the exact-2024 server capabilities admitted at initialization.
        #[must_use]
        pub fn server_capabilities(&self) -> &ServerCapabilities {
            self.inner.legacy_server_capabilities().expect(
                "LegacyOnly facade only retains HTTP clients admitted by exact legacy initialization",
            )
        }

        /// Pops one exact-2024 server notification retained by the legacy SSE stream.
        pub fn take_notification(&mut self) -> Option<JsonRpcRequest> {
            self.inner.take_legacy_notification()
        }

        /// Pops and direction-checks one typed exact-2024 server notification
        /// retained by the legacy SSE stream.
        ///
        /// This preserves the sealed HTTP client's fixed legacy transport
        /// plan while avoiding a raw JSON-RPC envelope at the application
        /// boundary. Use [`Self::take_notification`] only when inspecting a
        /// malformed peer frame is specifically required.
        pub fn take_server_notification(&mut self) -> McpResult<Option<ServerNotification>> {
            self.inner
                .take_legacy_notification()
                .map(|notification| ServerNotification::decode(&notification))
                .transpose()
        }

        /// Sends the capability-gated exact-2024 roots-change notification.
        ///
        /// The caller must have advertised `roots.listChanged` during legacy
        /// initialization. The sealed client writes only this exact client
        /// notification; it exposes no generic notification escape hatch.
        pub async fn roots_list_changed(&mut self, cx: &Cx) -> Result<(), HttpClientError> {
            if self.inner.selected_protocol_era()
                != fastmcp_protocol::protocol_policy::ProtocolEra::Legacy2024
            {
                return Err(HttpClientError::CoreResult(McpError::method_not_found(
                    methods::NOTIFICATIONS_ROOTS_LIST_CHANGED,
                )));
            }
            if !self
                .inner
                .client_capabilities()
                .roots
                .as_ref()
                .is_some_and(|roots| roots.list_changed)
            {
                return Err(HttpClientError::CoreResult(McpError::invalid_request(
                    "MCP 2024-11-05 roots/list_changed requires advertised roots.listChanged",
                )));
            }
            self.inner
                .notify(cx, ClientNotification::RootsListChanged.method(), None)
                .await
        }

        /// Sends exact-2024 `ping`.
        pub async fn ping(&mut self, cx: &Cx) -> Result<(), HttpClientError> {
            match self
                .request_legacy_core(cx, methods::PING, serde_json::json!({}))
                .await?
            {
                LegacyCoreResult::Ping(_) => Ok(()),
                _ => Err(Self::unexpected_result(methods::PING)),
            }
        }

        /// Lists one exact-2024 tools page.
        pub async fn list_tools(
            &mut self,
            cx: &Cx,
            params: ListToolsParams,
        ) -> Result<ListToolsResult, HttpClientError> {
            match self
                .request_legacy_core(cx, methods::TOOLS_LIST, Self::encode_params(params)?)
                .await?
            {
                LegacyCoreResult::ToolsList(result) => Ok(result),
                _ => Err(Self::unexpected_result(methods::TOOLS_LIST)),
            }
        }

        /// Calls one exact-2024 tool.
        pub async fn call_tool(
            &mut self,
            cx: &Cx,
            params: CallToolParams,
        ) -> Result<CallToolResult, HttpClientError> {
            match self
                .request_legacy_core(cx, methods::TOOLS_CALL, Self::encode_params(params)?)
                .await?
            {
                LegacyCoreResult::ToolsCall(result) => Ok(result),
                _ => Err(Self::unexpected_result(methods::TOOLS_CALL)),
            }
        }

        /// Lists one exact-2024 resources page.
        pub async fn list_resources(
            &mut self,
            cx: &Cx,
            params: ListResourcesParams,
        ) -> Result<ListResourcesResult, HttpClientError> {
            match self
                .request_legacy_core(cx, methods::RESOURCES_LIST, Self::encode_params(params)?)
                .await?
            {
                LegacyCoreResult::ResourcesList(result) => Ok(result),
                _ => Err(Self::unexpected_result(methods::RESOURCES_LIST)),
            }
        }

        /// Lists one exact-2024 resource-templates page.
        pub async fn list_resource_templates(
            &mut self,
            cx: &Cx,
            params: ListResourceTemplatesParams,
        ) -> Result<ListResourceTemplatesResult, HttpClientError> {
            match self
                .request_legacy_core(
                    cx,
                    methods::RESOURCES_TEMPLATES_LIST,
                    Self::encode_params(params)?,
                )
                .await?
            {
                LegacyCoreResult::ResourceTemplatesList(result) => Ok(result),
                _ => Err(Self::unexpected_result(methods::RESOURCES_TEMPLATES_LIST)),
            }
        }

        /// Reads one exact-2024 resource.
        pub async fn read_resource(
            &mut self,
            cx: &Cx,
            params: ReadResourceParams,
        ) -> Result<ReadResourceResult, HttpClientError> {
            match self
                .request_legacy_core(cx, methods::RESOURCES_READ, Self::encode_params(params)?)
                .await?
            {
                LegacyCoreResult::ResourcesRead(result) => Ok(result),
                _ => Err(Self::unexpected_result(methods::RESOURCES_READ)),
            }
        }

        /// Starts one exact-2024 resource subscription.
        pub async fn subscribe_resource(
            &mut self,
            cx: &Cx,
            params: SubscribeResourceParams,
        ) -> Result<(), HttpClientError> {
            self.request_legacy_empty(
                cx,
                methods::RESOURCES_SUBSCRIBE,
                Self::encode_params(params)?,
            )
            .await
        }

        /// Ends one exact-2024 resource subscription.
        pub async fn unsubscribe_resource(
            &mut self,
            cx: &Cx,
            params: UnsubscribeResourceParams,
        ) -> Result<(), HttpClientError> {
            self.request_legacy_empty(
                cx,
                methods::RESOURCES_UNSUBSCRIBE,
                Self::encode_params(params)?,
            )
            .await
        }

        /// Lists one exact-2024 prompts page.
        pub async fn list_prompts(
            &mut self,
            cx: &Cx,
            params: ListPromptsParams,
        ) -> Result<ListPromptsResult, HttpClientError> {
            match self
                .request_legacy_core(cx, methods::PROMPTS_LIST, Self::encode_params(params)?)
                .await?
            {
                LegacyCoreResult::PromptsList(result) => Ok(result),
                _ => Err(Self::unexpected_result(methods::PROMPTS_LIST)),
            }
        }

        /// Gets one exact-2024 prompt.
        pub async fn get_prompt(
            &mut self,
            cx: &Cx,
            params: GetPromptParams,
        ) -> Result<GetPromptResult, HttpClientError> {
            match self
                .request_legacy_core(cx, methods::PROMPTS_GET, Self::encode_params(params)?)
                .await?
            {
                LegacyCoreResult::PromptsGet(result) => Ok(result),
                _ => Err(Self::unexpected_result(methods::PROMPTS_GET)),
            }
        }

        /// Completes one exact-2024 prompt or resource-template argument.
        pub async fn complete(
            &mut self,
            cx: &Cx,
            params: LegacyCompletionParams,
        ) -> Result<LegacyCompletionResult, HttpClientError> {
            match self
                .request_legacy_core(
                    cx,
                    methods::COMPLETION_COMPLETE,
                    Self::encode_params(params)?,
                )
                .await?
            {
                LegacyCoreResult::Completion(result) => Ok(result),
                _ => Err(Self::unexpected_result(methods::COMPLETION_COMPLETE)),
            }
        }

        /// Sends exact-2024 `logging/setLevel`.
        pub async fn set_log_level(
            &mut self,
            cx: &Cx,
            level: LogLevel,
        ) -> Result<(), HttpClientError> {
            match self
                .request_legacy_core(
                    cx,
                    methods::LOGGING_SET_LEVEL,
                    Self::encode_params(SetLogLevelParams { level })?,
                )
                .await?
            {
                LegacyCoreResult::SetLogLevel(_) => Ok(()),
                _ => Err(Self::unexpected_result(methods::LOGGING_SET_LEVEL)),
            }
        }

        /// Sends the exact-2024 cancellation notification for one live request.
        pub async fn cancel_request(
            &mut self,
            cx: &Cx,
            request_id: RequestId,
            reason: Option<String>,
        ) -> Result<(), HttpClientError> {
            self.inner
                .notify(
                    cx,
                    methods::NOTIFICATIONS_CANCELLED,
                    Some(Self::encode_params(CancelledParams { request_id, reason })?),
                )
                .await
        }
    }

    /// Creates a client builder pinned to the exact MCP 2024-11-05 stdio plan.
    #[must_use]
    pub fn client_builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Creates a client builder pinned to exact MCP 2024-11-05 HTTP+SSE.
    ///
    /// Callers may further configure client identity, capabilities, timeouts,
    /// and legacy reverse callbacks before connecting with the component's
    /// `connect_http_client` or `connect_http_client_with_cx` method.
    pub fn http_client_builder(
        sse_endpoint: CanonicalHttpUrl,
        message_post_endpoint: CanonicalHttpUrl,
    ) -> Result<ClientBuilder, fastmcp_protocol::protocol_policy::HttpEndpointBundleError> {
        legacy_http_plan(sse_endpoint, message_post_endpoint).map(|plan| {
            ClientBuilder::from_inner(fastmcp_client::ClientBuilder::new().protocol_plan(plan))
        })
    }

    /// Connects the default exact-2024 builder over its required SSE and
    /// message-post endpoints using the current capability context.
    pub fn connect_http(
        sse_endpoint: CanonicalHttpUrl,
        message_post_endpoint: CanonicalHttpUrl,
    ) -> Result<HttpClient, HttpClientConnectError> {
        http_client_builder(sse_endpoint, message_post_endpoint)
            .map_err(HttpClientConnectError::Plan)?
            .connect_http_client()
            .map_err(HttpClientConnectError::Connect)
    }

    /// Connects the default exact-2024 builder over its required SSE and
    /// message-post endpoints with an explicit cancellation context.
    pub async fn connect_http_with_cx(
        sse_endpoint: CanonicalHttpUrl,
        message_post_endpoint: CanonicalHttpUrl,
        cx: &Cx,
    ) -> Result<HttpClient, HttpClientConnectError> {
        http_client_builder(sse_endpoint, message_post_endpoint)
            .map_err(HttpClientConnectError::Plan)?
            .connect_http_client_with_cx(cx)
            .await
            .map_err(HttpClientConnectError::Connect)
    }

    fn legacy_http_plan(
        sse_endpoint: CanonicalHttpUrl,
        message_post_endpoint: CanonicalHttpUrl,
    ) -> Result<ClientProtocolPlan, fastmcp_protocol::protocol_policy::HttpEndpointBundleError>
    {
        ClientProtocolPlan::http(
            ProtocolPolicy::LegacyOnly,
            None,
            Some(sse_endpoint),
            Some(message_post_endpoint),
            "fastmcp-rust-legacy-2024-facade".to_owned(),
            "fastmcp-rust-legacy-2024-facade".to_owned(),
            "legacy-2024-http-sse".to_owned(),
            0,
            0,
            0,
        )
    }
}

// REL-QUAR-00 release-quarantine evidence surface
pub mod release_quarantine;

// Testing helpers are opt-in and do not widen the production facade.
#[cfg(any(feature = "testing", feature = "testing-lab"))]
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
        CacheTtl,
        CacheTtlConversionError,
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
        ClientRoot,
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
        DiscoveryCacheHints,
        DualEraHttpEndpoint,
        DualEraHttpEndpointConfig,
        DualEraHttpEndpointError,
        DualEraHttpLegacySseResponse,
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
        FinalProgressCallback,
        FinalProgressNotificationParams,
        FinalProtocolVersion,
        FinalReadResourceResult,
        FinalResource,
        FinalResourceUpdatedNotificationParams,
        FinalSubscriptionsAcknowledgedNotificationParams,
        FinalTask,
        FinalTaskCallToolResult,
        FinalTaskHandle,
        FinalTaskId,
        FinalTaskInputResponses,
        FinalTaskStatusNotification,
        FinalTaskWatch,
        FinalTaskWatchEvent,
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
        HttpNonquiescentShutdown,
        HttpRequest,
        HttpRequestHandler,
        HttpResponse,
        HttpServerConfig,
        HttpServerShutdown,
        HttpShutdownSettlement,
        HttpStatus,
        HttpSubscriptionListener,
        // Server
        InboundRequestContext,
        InboundRequestTransport,
        JsonInteger,
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
        MemoryRecvHalf,
        MemorySendHalf,
        Middleware,
        MiddlewareDecision,
        ModernHttpClient,
        ModernHttpClientError,
        ModernHttpConnectOutcome,
        ModernHttpExecutor,
        ModernHttpExecutorError,
        ModernHttpRequest,
        ModernHttpResponseKind,
        ModernHttpResponseMetadata,
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
        ProgressCallback,
        ProgressMarker,
        Prompt,
        PromptArgument,
        PromptMessage,
        ProtocolEra,
        ProtocolPolicy,
        ProtocolVersion,
        ProxyBackend,
        ProxyCatalog,
        ProxyCatalogCacheHint,
        ProxyClient,
        ProxyFinalCatalog,
        ProxyFinalTaskListener,
        ProxyFinalTaskListenerEvent,
        ProxyProgressCallback,
        ProxyPromptCatalog,
        ProxyResourceCatalog,
        ProxyResourceTemplateCatalog,
        ProxyToolCatalog,
        ProxyTypedCatalog,
        ProxyUpstreamAdapter,
        ProxyUpstreamBinding,
        ProxyUpstreamBindingRegistry,
        RequestAdmissionError,
        RequestId,
        RequestTimeoutPolicy,
        RequestTimeoutSource,
        Resource,
        ResourceContent,
        ResultExt,
        ReversibleResourceTemplate,
        Role,
        RootsProvider,
        SchemaAdmissionError,
        Server,
        ServerBehavior,
        ServerBehaviorRegistry,
        ServerConfig,
        ServerDiscoverRequest,
        ServerDiscoverResult,
        ServerHttpEndpoint,
        ServerHttpEndpointResponse,
        ServerHttpRequestCancellation,
        ServerHttpSession,
        ServerHttpSseResponse,
        ServerNotification,
        SseEndOfStream,
        SseEvent,
        SseLimits,
        SseParseError,
        StaticTokenVerifier,
        StreamableHttpRequestIngress,
        StreamableHttpRequestResponseMessage,
        StreamableHttpRequestResponseSender,
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
        cancelled,
        err,
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
        FinalCacheResultSet, FinalCacheStats, FinalCacheTtlDiagnostic,
        FinalResourceReadCacheHintProvenance, FinalResultCache, FinalTaskAcceptedInput,
        FinalTaskInitialWork, FinalTaskNotificationEmitter, FinalTaskRetentionAuthority,
        FinalTaskRuntime, FinalTaskRuntimeConfig, FinalTaskSnapshot, FinalTaskStore,
        FinalTaskSupervisorFuture, FinalTaskSupervisorHandoff, FinalTaskWorkDescriptor,
        FinalToolSchemaAuthority, InMemoryFinalTaskStore, JsonRpcAdmissionError, JsonRpcMessage,
        JsonRpcRequest, JsonRpcResponse, MAX_FINAL_CACHE_CAPACITY, MAX_FINAL_CACHE_MAX_BYTES,
        MAX_RESOURCE_READ_DEPTH, MAX_TOOL_CALL_DEPTH, McpContextLeaseGuard, McpRequestCancellation,
        NoOpElicitationSender, NoOpNotificationSender, NoOpSamplingSender, PendingRequests,
        ProgressReporter, PromptHandler, Request, RequestExecution, RequestExecutor, RequestSender,
        ResourceContentItem, ResourceHandler, ResourceReadResult, ResourceReader, ReverseRequest,
        ReverseRequestCancellation, SamplingRequest, SamplingRequestMessage, SamplingResponse,
        SamplingRole, SamplingSender, SamplingStopReason, ServerCapabilityInfo,
        StdioRequestExecution, StdioRequestExecutor, ToolCallResult, ToolCaller, ToolContentItem,
        ToolHandler, Transport, TransportElicitationSender, TransportRootsProvider,
        TransportSamplingSender, block_on, decode_strict_jsonrpc_message,
    };
    #[cfg(feature = "legacy-2024-11-05")]
    pub use crate::{auto, legacy_2024};
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
    fn final_task_watch_api_is_reexported_from_root_modern_and_prelude() {
        use super::{FinalTaskHandle, FinalTaskWatch, FinalTaskWatchEvent, modern, prelude};

        let _: Option<FinalTaskHandle> = None;
        let _: Option<FinalTaskWatch<'_, '_>> = None;
        let _: Option<FinalTaskWatchEvent> = None;

        let _: Option<modern::FinalTaskHandle> = None;
        let _: Option<modern::FinalTaskWatch<'_, '_>> = None;
        let _: Option<modern::FinalTaskWatchEvent> = None;

        let _: Option<prelude::FinalTaskHandle> = None;
        let _: Option<prelude::FinalTaskWatch<'_, '_>> = None;
        let _: Option<prelude::FinalTaskWatchEvent> = None;
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
    fn modern_facade_server_builder_forwards_final_only_mcp_apps_ui_resources() {
        use super::modern;

        let resource = modern::McpAppsUiResource::try_new(
            modern::AbsoluteUri::parse("ui://facade/dashboard").expect("facade UI URI is absolute"),
            "facade-dashboard",
            "<main>facade</main>",
        )
        .expect("facade UI document is valid");
        let server = modern::server_builder("facade-ui", "1.0")
            .mcp_apps()
            .expect("facade Apps opt-in succeeds")
            .mcp_apps_ui_resource(resource.clone())
            .expect("facade forwards the final-only UI resource")
            .build();
        let discovery = serde_json::to_value(
            server
                .server_discovery()
                .expect("facade UI server has final discovery"),
        )
        .expect("facade UI discovery serializes");
        assert_eq!(
            discovery["capabilities"]["extensions"]["io.modelcontextprotocol/ui"],
            serde_json::json!({})
        );
        assert_eq!(
            discovery["capabilities"]["resources"],
            serde_json::json!({})
        );

        let error = match modern::server_builder("facade-ui", "1.0").mcp_apps_ui_resource(resource)
        {
            Ok(_) => panic!("changing only the missing facade Apps opt-in must reject"),
            Err(error) => error,
        };
        assert_eq!(error.code, super::McpErrorCode::InvalidRequest);
    }

    #[test]
    fn modern_facade_server_builder_forwards_target_completion_providers() {
        use std::collections::HashMap;

        use super::modern;

        struct FacadeCompletion;

        impl super::CompletionHandler for FacadeCompletion {
            fn complete_legacy(
                &self,
                _ctx: &super::McpContext,
                _params: super::legacy_2024::LegacyCompletionParams,
            ) -> super::McpResult<super::legacy_2024::CompletionValues> {
                Ok(super::legacy_2024::CompletionValues {
                    values: vec!["legacy".to_owned()],
                    total: Some(1),
                    has_more: Some(false),
                })
            }

            fn complete_final(
                &self,
                _ctx: &super::McpContext,
                _params: super::FinalCompletionParams,
            ) -> super::McpResult<super::FinalCompletionValues> {
                Ok(super::FinalCompletionValues {
                    values: vec!["final".to_owned()],
                    total: Some(super::JsonInteger::from(1_i64)),
                    has_more: Some(false),
                })
            }
        }

        struct FacadePrompt;

        impl super::PromptHandler for FacadePrompt {
            fn definition(&self) -> super::Prompt {
                super::Prompt {
                    name: "facade-prompt".to_owned(),
                    description: None,
                    arguments: Vec::new(),
                    icon: None,
                    version: None,
                    tags: Vec::new(),
                }
            }

            fn get(
                &self,
                _ctx: &super::McpContext,
                _arguments: HashMap<String, String>,
            ) -> super::McpResult<Vec<super::PromptMessage>> {
                Ok(Vec::new())
            }
        }

        let prompt_server = modern::server_builder("facade", "1.0")
            .prompt(FacadePrompt)
            .prompt_completion_handler("facade-prompt", FacadeCompletion)
            .build();
        let prompt_discovery = serde_json::to_value(
            prompt_server
                .server_discovery()
                .expect("the prompt provider facade server discovers"),
        )
        .expect("discovery serializes");
        assert_eq!(
            prompt_discovery["capabilities"]["completions"],
            serde_json::json!({}),
            "the modern facade forwards an admitted prompt-specific provider"
        );

        let template_uri = "mcp://facade/{id}";
        let template_server = modern::server_builder("facade", "1.0")
            .resource_template(super::FinalResourceTemplate {
                uri_template: template_uri.to_owned(),
                name: "facade-template".to_owned(),
                title: None,
                description: None,
                icons: None,
                mime_type: None,
                annotations: None,
                meta: None,
            })
            .resource_template_completion_handler(template_uri, FacadeCompletion)
            .build();
        let template_discovery = serde_json::to_value(
            template_server
                .server_discovery()
                .expect("the template provider facade server discovers"),
        )
        .expect("discovery serializes");
        assert_eq!(
            template_discovery["capabilities"]["completions"],
            serde_json::json!({}),
            "the modern facade forwards an admitted template-specific provider"
        );
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
        let _: for<'a> fn(
            &'a mut modern::Client,
        ) -> modern::McpResult<&'a modern::ServerDiscoverResult> = modern::Client::server_discovery;
        let _: fn(&mut modern::Client) -> Vec<modern::FinalProgressNotificationParams> =
            modern::Client::take_progress_notifications;
        let _: fn(&mut modern::Client) -> Vec<modern::ServerNotification> =
            modern::Client::take_server_notifications;
        let _: fn(&mut modern::Client, modern::RequestId, Option<String>) -> modern::McpResult<()> =
            modern::Client::cancel_request;
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
        async fn bind_modern_http(
            server: modern::Server,
            cx: &modern::Cx,
        ) -> modern::McpResult<modern::HttpServer> {
            server.bind_http(cx, "127.0.0.1:0").await
        }

        async fn serve_modern_http(
            server: modern::Server,
            cx: &modern::Cx,
        ) -> modern::McpResult<modern::HttpServerShutdown> {
            server.serve_http(cx, "127.0.0.1:0").await
        }

        async fn list_modern_http_tools(
            client: &mut modern::HttpClient,
            cx: &modern::Cx,
            cursor: Option<&str>,
        ) -> Result<modern::FinalListToolsResult, modern::HttpClientError> {
            client.list_tools(cx, cursor).await
        }

        async fn list_modern_http_prompts(
            client: &mut modern::HttpClient,
            cx: &modern::Cx,
            cursor: Option<&str>,
        ) -> Result<modern::FinalListPromptsResult, modern::HttpClientError> {
            client.list_prompts(cx, cursor).await
        }

        async fn get_modern_http_prompt(
            client: &mut modern::HttpClient,
            cx: &modern::Cx,
            name: &str,
            arguments: HashMap<String, String>,
        ) -> Result<modern::FinalGetPromptResult, modern::HttpClientError> {
            client.get_prompt(cx, name, arguments).await
        }

        async fn get_modern_http_prompt_with_mrtr<F>(
            client: &mut modern::HttpClient,
            cx: &modern::Cx,
            deadline: std::time::Instant,
            name: &str,
            arguments: HashMap<String, String>,
            limits: modern::SseLimits,
            maximum_response_bytes: usize,
            respond: F,
        ) -> Result<modern::FinalCoreResult, modern::HttpClientError>
        where
            F: FnMut(&modern::InputRequiredResult) -> modern::McpResult<modern::MrtrInputResponses>,
        {
            client
                .get_prompt_with_mrtr_retry(
                    cx,
                    deadline,
                    name,
                    arguments,
                    limits,
                    maximum_response_bytes,
                    respond,
                )
                .await
        }

        async fn open_modern_http_subscriptions_listener<'client>(
            client: &'client mut modern::HttpClient,
            cx: &modern::Cx,
            filter: modern::SubscriptionFilter,
            limits: modern::SseLimits,
        ) -> Result<modern::HttpSubscriptionListener<'client>, modern::HttpClientError> {
            client.open_subscriptions_listener(cx, filter, limits).await
        }

        async fn receive_modern_http_subscription_event(
            client: &mut modern::HttpClient,
            cx: &modern::Cx,
            filter: modern::SubscriptionFilter,
            limits: modern::SseLimits,
        ) -> Result<Option<modern::ModernHttpSubscriptionListenEvent>, modern::HttpClientError>
        {
            let mut listener = client
                .open_subscriptions_listener(cx, filter, limits)
                .await?;
            let event = listener.next_event(cx).await?;
            drop(listener);
            let _: modern::FinalListToolsResult = client.list_tools(cx, None).await?;
            Ok(event)
        }

        let _ = modern::HttpClient::connect;
        let _ = bind_modern_http;
        let _ = serve_modern_http;
        let _ = list_modern_http_tools;
        let _ = list_modern_http_prompts;
        let _ = get_modern_http_prompt;
        let _ = get_modern_http_prompt_with_mrtr::<
            fn(&modern::InputRequiredResult) -> modern::McpResult<modern::MrtrInputResponses>,
        >;
        let _ = open_modern_http_subscriptions_listener;
        let _ = receive_modern_http_subscription_event;

        let auto_builder = auto::client_builder();
        assert_eq!(
            auto_builder.selected_protocol_plan().policy(),
            auto::ProtocolPolicy::Auto
        );
        let legacy_builder = legacy_2024::client_builder();
        assert_eq!(
            legacy_builder.protocol_policy(),
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
    fn legacy_facade_client_constructors_are_exact_while_root_remains_auto() {
        use super::{ClientBuilder as RootClientBuilder, ProtocolPolicy, auto, legacy_2024};

        let legacy = legacy_2024::Client::builder();
        assert_eq!(legacy.protocol_policy(), ProtocolPolicy::LegacyOnly);
        let _: fn(&str, &[&str]) -> super::McpResult<legacy_2024::Client> =
            legacy_2024::Client::stdio;
        let _: fn(&str, &[&str], super::Cx) -> super::McpResult<legacy_2024::Client> =
            legacy_2024::Client::stdio_with_cx;

        // Only the selected namespace differs: root and `auto` retain their
        // public bounded-Auto entry points.
        assert_eq!(
            RootClientBuilder::new().selected_protocol_plan().policy(),
            ProtocolPolicy::Auto
        );
        assert_eq!(
            auto::client_builder().selected_protocol_plan().policy(),
            ProtocolPolicy::Auto
        );
    }

    #[test]
    fn legacy_facade_client_and_http_wrappers_expose_only_exact_operations() {
        use super::{Cx, McpResult, legacy_2024};

        let _: fn(&mut legacy_2024::Client) -> McpResult<()> =
            legacy_2024::Client::ensure_initialized;
        let _: fn(&legacy_2024::Client) -> bool = legacy_2024::Client::is_initialized;
        let _: fn(&mut legacy_2024::Client) -> McpResult<()> = legacy_2024::Client::ping;
        let _: fn(
            &mut legacy_2024::Client,
            &str,
            legacy_2024::JsonValue,
        ) -> McpResult<legacy_2024::CallToolResult> = legacy_2024::Client::call_tool;
        let _: fn(&mut legacy_2024::Client) -> McpResult<Vec<legacy_2024::Resource>> =
            legacy_2024::Client::list_resources;
        let _: fn(&mut legacy_2024::Client, &str) -> McpResult<legacy_2024::ReadResourceResult> =
            legacy_2024::Client::read_resource;
        let _: fn(&mut legacy_2024::Client) -> McpResult<Vec<legacy_2024::Prompt>> =
            legacy_2024::Client::list_prompts;
        let _: fn(
            &mut legacy_2024::Client,
            &str,
            std::collections::HashMap<String, String>,
        ) -> McpResult<legacy_2024::GetPromptResult> = legacy_2024::Client::get_prompt;
        let _: fn(
            &mut legacy_2024::Client,
            legacy_2024::LegacyCompletionParams,
        ) -> McpResult<legacy_2024::LegacyCompletionResult> = legacy_2024::Client::complete;
        let _: fn(
            &mut legacy_2024::Client,
            legacy_2024::RequestId,
            Option<String>,
        ) -> McpResult<()> = legacy_2024::Client::cancel_request;
        let _: fn(&mut legacy_2024::Client) -> McpResult<()> =
            legacy_2024::Client::roots_list_changed;
        let _: fn(&legacy_2024::JsonRpcRequest) -> McpResult<legacy_2024::ServerNotification> =
            legacy_2024::Client::decode_server_notification;
        let _: fn(&mut legacy_2024::Client) -> McpResult<()> = legacy_2024::Client::close;
        let _: fn(legacy_2024::ClientBuilder, &str, &[&str]) -> McpResult<legacy_2024::Client> =
            legacy_2024::ClientBuilder::connect_stdio;

        fn legacy_builder_connects_http(builder: legacy_2024::ClientBuilder) {
            let _: Result<legacy_2024::HttpClient, legacy_2024::HttpClientError> =
                builder.connect_http();
        }

        fn legacy_builder_connects_http_with_cx(builder: legacy_2024::ClientBuilder, cx: &Cx) {
            std::mem::drop(builder.connect_http_with_cx(cx));
        }

        fn legacy_http_requests(client: &mut legacy_2024::HttpClient, cx: &Cx) {
            std::mem::drop(client.ping(cx));
            std::mem::drop(client.list_tools(cx, legacy_2024::ListToolsParams::default()));
            std::mem::drop(client.call_tool(
                cx,
                legacy_2024::CallToolParams {
                    name: "tool".to_owned(),
                    arguments: None,
                    meta: None,
                },
            ));
            std::mem::drop(client.list_resources(cx, legacy_2024::ListResourcesParams::default()));
            std::mem::drop(
                client.list_resource_templates(
                    cx,
                    legacy_2024::ListResourceTemplatesParams::default(),
                ),
            );
            std::mem::drop(client.read_resource(
                cx,
                legacy_2024::ReadResourceParams {
                    uri: "test://resource".to_owned(),
                    meta: None,
                },
            ));
            std::mem::drop(client.subscribe_resource(
                cx,
                legacy_2024::SubscribeResourceParams {
                    uri: "test://resource".to_owned(),
                },
            ));
            std::mem::drop(client.unsubscribe_resource(
                cx,
                legacy_2024::UnsubscribeResourceParams {
                    uri: "test://resource".to_owned(),
                },
            ));
            std::mem::drop(client.list_prompts(cx, legacy_2024::ListPromptsParams::default()));
            std::mem::drop(client.get_prompt(
                cx,
                legacy_2024::GetPromptParams {
                    name: "prompt".to_owned(),
                    arguments: None,
                    meta: None,
                },
            ));
            std::mem::drop(client.complete(
                cx,
                legacy_2024::LegacyCompletionParams {
                    reference: legacy_2024::LegacyCompletionReference::Prompt {
                        name: "prompt".to_owned(),
                    },
                    argument: legacy_2024::LegacyCompletionArgument {
                        name: "argument".to_owned(),
                        value: "value".to_owned(),
                    },
                },
            ));
            std::mem::drop(client.set_log_level(cx, legacy_2024::LogLevel::Info));
            std::mem::drop(client.cancel_request(cx, legacy_2024::RequestId::Number(1), None));
            std::mem::drop(client.roots_list_changed(cx));
        }

        let _: fn(legacy_2024::ClientBuilder) = legacy_builder_connects_http;
        let _: fn(legacy_2024::ClientBuilder, &Cx) = legacy_builder_connects_http_with_cx;
        let _: fn(&mut legacy_2024::HttpClient, &Cx) = legacy_http_requests;
        let _: fn(&legacy_2024::HttpClient) -> Option<&str> =
            legacy_2024::HttpClient::protocol_version;
        let _: fn(
            &mut legacy_2024::HttpClient,
        ) -> McpResult<Option<legacy_2024::ServerNotification>> =
            legacy_2024::HttpClient::take_server_notification;
        let _: fn(legacy_2024::ClientNotification) -> legacy_2024::JsonRpcRequest =
            legacy_2024::ClientNotification::encode;
        let _: fn(&legacy_2024::JsonRpcRequest) -> McpResult<legacy_2024::ServerNotification> =
            legacy_2024::ServerNotification::decode;

        async fn bind_legacy_http(
            server: legacy_2024::Server,
            cx: &Cx,
        ) -> McpResult<legacy_2024::HttpServer> {
            server.bind_http(cx, "127.0.0.1:0").await
        }

        async fn serve_legacy_http(
            server: legacy_2024::Server,
            cx: &Cx,
        ) -> McpResult<legacy_2024::HttpServerShutdown> {
            server.serve_http(cx, "127.0.0.1:0").await
        }

        let _ = bind_legacy_http;
        let _ = serve_legacy_http;
        let _: Option<legacy_2024::HttpServer> = None;
    }

    #[test]
    fn legacy_facade_notifications_are_typed_and_direction_checked() {
        use super::{JsonRpcRequest, JsonValue, legacy_2024};

        let roots_changed = legacy_2024::ClientNotification::RootsListChanged.encode();
        assert_eq!(
            roots_changed.method,
            legacy_2024::methods::NOTIFICATIONS_ROOTS_LIST_CHANGED
        );
        assert!(roots_changed.id.is_none());
        assert!(roots_changed.params.is_none());

        let message = JsonRpcRequest::notification(
            legacy_2024::methods::NOTIFICATIONS_MESSAGE,
            Some(serde_json::json!({
                "level": "info",
                "data": {"event": "catalog-refresh"},
            })),
        );
        let notification = legacy_2024::ServerNotification::decode(&message)
            .expect("exact server log notification must decode");
        assert!(matches!(
            notification,
            legacy_2024::ServerNotification::Message(_)
        ));

        let wrong_direction = JsonRpcRequest::notification(
            legacy_2024::methods::NOTIFICATIONS_ROOTS_LIST_CHANGED,
            None,
        );
        assert!(legacy_2024::ServerNotification::decode(&wrong_direction).is_err());

        let _: JsonValue = serde_json::json!({"checked": true});
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
            AsyncStdioTransport, MemoryRecvHalf, MemorySendHalf, StdioTransport, Transport,
            TransportRecvHalf, TransportSendHalf, TwoPhaseTransport, prelude, transport,
        };

        fn requires_two_phase_transport<T: TwoPhaseTransport>() {}
        fn requires_split_halves<R: TransportRecvHalf, W: TransportSendHalf>() {}

        requires_two_phase_transport::<StdioTransport<Cursor<Vec<u8>>, Vec<u8>>>();
        let _: Option<AsyncStdioTransport> = None;
        let _ = requires_split_halves::<MemoryRecvHalf, MemorySendHalf>;
        let _ = requires_split_halves::<prelude::MemoryRecvHalf, prelude::MemorySendHalf>;
        let _: Option<transport::MemoryRecvHalf> = None;
        let _: Option<transport::MemorySendHalf> = None;
        let _: Option<transport::sse::SseEvent> = None;
        let _: Option<&dyn Transport> = None;
    }

    #[test]
    fn facade_reexports_transport_ingress_sse_payload_and_progress_types() {
        use super::{
            DualEraHttpLegacySseResponse, ProgressCallback, ServerHttpSseResponse,
            StreamableHttpRequestIngress, StreamableHttpRequestResponseMessage,
            StreamableHttpRequestResponseSender, modern, prelude,
        };

        let _: Option<StreamableHttpRequestIngress> = None;
        let _: Option<StreamableHttpRequestResponseMessage> = None;
        let _: Option<StreamableHttpRequestResponseSender> = None;
        let _: Option<ServerHttpSseResponse> = None;
        let _: Option<DualEraHttpLegacySseResponse> = None;
        let _: Option<ProgressCallback<'_>> = None;

        let _: Option<modern::StreamableHttpRequestIngress> = None;
        let _: Option<modern::StreamableHttpRequestResponseMessage> = None;
        let _: Option<modern::StreamableHttpRequestResponseSender> = None;

        let _: Option<prelude::StreamableHttpRequestIngress> = None;
        let _: Option<prelude::StreamableHttpRequestResponseMessage> = None;
        let _: Option<prelude::StreamableHttpRequestResponseSender> = None;
        let _: Option<prelude::ServerHttpSseResponse> = None;
        let _: Option<prelude::DualEraHttpLegacySseResponse> = None;
        let _: Option<prelude::ProgressCallback<'_>> = None;
    }

    #[test]
    fn facade_closes_modern_task_handle_and_sse_response_method_signatures() {
        use super::{
            Cx, DualEraHttpEndpointError, FinalCancelTaskResult, FinalTask, FinalTaskHandle,
            FinalTaskId, FinalTaskInputResponses, FinalTaskWatch, FinalUpdateTaskResult,
            HttpClientError, ServerHttpRequestCancellation, ServerHttpSseResponse, SseEvent,
            SseLimits, modern, prelude,
        };

        async fn drive_task_handle(
            client: &mut modern::HttpClient,
            cx: &Cx,
            task_id: FinalTaskId,
            input_responses: FinalTaskInputResponses,
            limits: SseLimits,
        ) -> Result<(), HttpClientError> {
            let mut handle: FinalTaskHandle = client.attach_final_task(cx, task_id).await?;
            let _: &FinalTask = client.poll_final_task(cx, &mut handle).await?;
            let _: FinalUpdateTaskResult = client
                .resume_final_task(cx, &mut handle, input_responses)
                .await?;
            let _: FinalCancelTaskResult = client.cancel_final_task(cx, &handle).await?;
            let watch: FinalTaskWatch<'_, '_> =
                client.watch_final_task(cx, &mut handle, limits).await?;
            drop(watch);
            Ok(())
        }

        let _ = drive_task_handle;

        let _: fn(&ServerHttpSseResponse) -> ServerHttpRequestCancellation =
            ServerHttpSseResponse::cancellation;
        let _: fn(&ServerHttpSseResponse, &Cx) -> Result<SseEvent, DualEraHttpEndpointError> =
            ServerHttpSseResponse::recv_event;
        let _: fn(&prelude::ServerHttpSseResponse) -> prelude::ServerHttpRequestCancellation =
            prelude::ServerHttpSseResponse::cancellation;
        let _: fn(
            &prelude::ServerHttpSseResponse,
            &Cx,
        ) -> Result<prelude::SseEvent, prelude::DualEraHttpEndpointError> =
            prelude::ServerHttpSseResponse::recv_event;
    }

    #[test]
    fn facade_reexports_final_proxy_listener_and_modern_progress_binding_surface() {
        use super::{
            FinalProgressCallback, ProxyBackend, ProxyFinalTaskListener,
            ProxyFinalTaskListenerEvent, ProxyUpstreamAdapter, ProxyUpstreamBinding,
            ProxyUpstreamBindingRegistry, modern, prelude,
        };

        let _: Option<FinalProgressCallback<'_>> = None;
        let _: Option<Box<dyn ProxyBackend>> = None;
        let _: Option<Box<dyn ProxyFinalTaskListener>> = None;
        let _: Option<ProxyFinalTaskListenerEvent> = None;
        let _: Option<ProxyUpstreamAdapter> = None;
        let _: Option<ProxyUpstreamBinding> = None;
        let _: Option<ProxyUpstreamBindingRegistry> = None;

        let _: Option<modern::FinalProgressCallback<'_>> = None;
        let _: Option<modern::ProxyUpstreamAdapter> = None;
        let _: Option<modern::ProxyUpstreamBinding> = None;
        let _: Option<modern::ProxyUpstreamBindingRegistry> = None;

        let _: Option<Box<dyn prelude::ProxyBackend>> = None;
        let _: Option<Box<dyn prelude::ProxyFinalTaskListener>> = None;
        let _: Option<prelude::ProxyFinalTaskListenerEvent> = None;
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
            FinalReadResourceResult, FinalToolCallOutcome, HttpNonquiescentShutdown,
            HttpServerShutdown, HttpShutdownSettlement, JsonValue, McpResult, ModernHttpClient,
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
        let _: Option<HttpServerShutdown> = None;
        let _: Option<HttpNonquiescentShutdown> = None;
        let _: Option<HttpShutdownSettlement> = None;
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
