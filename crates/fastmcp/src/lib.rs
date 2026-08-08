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

// Re-export core types
pub use fastmcp_core::{
    AccessToken, AuthContext, Budget, CancelledError, Cx, IntoOutcome, LabConfig, LabRuntime,
    McpContext, McpError, McpErrorCode, McpOutcome, McpResult, Outcome, OutcomeExt, RegionId,
    ResultExt, Scope, TaskId, cancelled, err, ok,
};

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
    CallToolParams, CallToolResult, ClientCapabilities, ClientInfo, Content, GetPromptParams,
    GetPromptResult, JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse,
    ListPromptsParams, ListPromptsResult, ListResourceTemplatesParams, ListResourceTemplatesResult,
    ListResourcesParams, ListResourcesResult, ListToolsParams, ListToolsResult, LogLevel, Prompt,
    PromptArgument, PromptMessage, ReadResourceParams, ReadResourceResult, RequestId, Resource,
    ResourceContent, ResourceTemplate, ResourcesCapability, Role, ServerCapabilities, ServerInfo,
    SubscribeResourceParams, Tool, ToolAnnotations, ToolsCapability, UnsubscribeResourceParams,
};

pub use fastmcp_protocol::common_types;
// Final common wire vocabulary. `FinalAbsoluteUri` avoids colliding with the
// established core URI type; `modern::AbsoluteUri` retains the exact name.
pub use fastmcp_protocol::common_types::{
    AbsoluteUri as FinalAbsoluteUri, AnnotationAudience, Annotations, CancellationNotification,
    CancellationRequestId, CommonTypeError, CommonWireDirection, ContentBlock,
    EmbeddedResourceContents, FinalCommonTypesSchema, IconTheme, Implementation, LoggingLevel,
    OpaqueCursor, OpenMetadata, RawIcon, RawIconSourceUri, ResourceLink, TraceContext,
    UntrustedCancellationReason,
};

// Final typed core dispatch, result vocabulary, and bounded exact-JSON helpers.
pub use fastmcp_protocol::{
    CacheScope, CacheTtl, CacheableResult, CompleteResult, CompleteResultPayload,
    CoreDispatchError, CoreRequest, CoreResult, CoreResultDiscriminatorPolicy, DecodedResult,
    ExactJsonMember, ExactJsonObject, ExactJsonValue, FINAL_CLIENT_CAPABILITIES_META_KEY,
    FINAL_CLIENT_INFO_META_KEY, FINAL_PROTOCOL_VERSION_META_KEY, FINAL_SERVER_INFO_META_KEY,
    FinalCallToolParams, FinalCallToolResult, FinalCoreRequest, FinalCoreResult, FinalEmptyParams,
    FinalEmptyResult, FinalGetPromptParams, FinalGetPromptResult, FinalListParams,
    FinalListPromptsResult, FinalListResourceTemplatesResult, FinalListResourcesResult,
    FinalListToolsResult, FinalPromptMessage, FinalReadResourceParams, FinalReadResourceResult,
    FinalRequestMeta, FinalSetLogLevelParams, InputRequiredResult, LegacyCoreRequest,
    LegacyCoreResult, LegacyEmptyResult, MetadataView, PaginatedResult, RawResultEnvelope,
    ResultDecodeError, ResultDecodeErrorKind, ResultDiscriminatorDecision,
    ResultDiscriminatorPolicy, ResultMeta, ResultPeerDiagnostic, ResultPeerEra,
    TypedCompleteMembers, UnknownResultMembers, decode_peer_result, decode_typed_complete,
    encode_result, parse_exact_json,
};

pub use fastmcp_protocol::extensions;
// Final extension vocabulary.
pub use fastmcp_protocol::extensions::{
    ClientExtensionDiscovery, EffectiveExtensionSettings, ExtensionDescriptor,
    ExtensionDescriptorRegistry, ExtensionDirection, ExtensionDiscovery, ExtensionDispatchError,
    ExtensionFallbackPolicy, ExtensionHttpEraDisposition, ExtensionId, ExtensionInactiveReason,
    ExtensionLocalEnablement, ExtensionMethodDescriptor, ExtensionNegotiationError,
    ExtensionNegotiationResolver, ExtensionNotificationDescriptor, ExtensionPeer,
    ExtensionRegistryError, ExtensionRegistryReceipt, ExtensionRoutingHeaderDescriptor,
    ExtensionSettings, ExtensionSettingsCompatibilityResolver, ExtensionSettingsSchema,
    NegotiatedExtension, NegotiatedExtensionSet, ServerExtensionDiscovery,
    StdioCorrelationDescriptor,
};

// Final `server/discover` vocabulary.
pub use fastmcp_protocol::{
    DiscoveryCacheHints, SERVER_DISCOVER_METHOD, SERVER_DISCOVER_SUPPORTED_VERSIONS,
    ServerBehavior, ServerBehaviorRegistry, ServerDiscoverCapabilities, ServerDiscoverRequest,
    ServerDiscoverResult, ServerDiscoveryError, ServerInstructionError, ServerInstructions,
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
    LegacyClientAdapterInstalledReceipt, LegacyReceiptBinding, LegacyServerAdapterInstalledReceipt,
    MODERN_PROTOCOL_VERSION, ModernVersionSupport, ProtocolEra, ProtocolPolicy,
    ProtocolPolicyError, ProtocolPolicySelection, ProtocolRole, ProtocolVersion,
    ProtocolVersionError as ProtocolPolicyVersionError, StdioEraClassifier, StdioEraDecision,
    StdioEraRejection, StdioEraState, StdioOpeningFrame,
};

// Re-export transport types
pub use fastmcp_transport::{Codec, StdioTransport, Transport, TransportError};

// Re-export transport modules
pub use fastmcp_transport::{event_store, http, memory};

// Re-export server types
// FND-01: JWT verifier is not a facade feature (FACADE-NO-JSONWEBTOKEN).
pub use fastmcp_server::{
    AllowAllAuthProvider, AuthProvider, AuthRequest, BannerStyle, BidirectionalSenders, BoxFuture,
    ConsoleConfig, HttpServerConfig, InboundRequestContext, InboundRequestTransport, Middleware,
    MiddlewareDecision, MountResult, NotificationSender, PendingRequests,
    ProgressNotificationSender, PromptHandler, ProxyBackend, ProxyCatalog, ProxyClient,
    RequestSender, ResourceHandler, Router, Server, ServerBuilder, ServerStats, Session,
    StaticTokenVerifier, StatsSnapshot, TagFilters, TokenAuthProvider, TokenVerifier, ToolHandler,
    TrafficVerbosity, TransportElicitationSender, TransportRootsProvider, TransportSamplingSender,
    create_context_with_progress, create_context_with_progress_and_senders,
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
    BoundedListPage, Client, ClientBuilder, ClientHttpNegotiation, ClientHttpNegotiationDecision,
    ClientHttpNegotiationError, ClientHttpNegotiationState, ClientProtocolPlan,
    ClientProtocolPlanError, ClientSession, ListPageLimits, RequestTimeoutPolicy,
    RequestTimeoutSource,
};

// Public client HTTP execution and configuration surfaces.
pub use fastmcp_client::http_executor::{
    LegacySseHttpClient, LegacySseHttpClientError, MODERN_MCP_ACCEPT, MODERN_MCP_ACCEPT_ENCODING,
    MODERN_MCP_CONTENT_TYPE, ModernHttpClient, ModernHttpClientError, ModernHttpConnectOutcome,
    ModernHttpExecutor, ModernHttpExecutorError, ModernHttpRequest, ModernHttpResponseKind,
    ModernHttpResponseMetadata, ModernHttpResponseStream, ModernHttpSseResponseStream,
    validate_response_head,
};
pub use fastmcp_client::mcp_config::{
    ConfigError, ConfigLoader, HttpEndpointConfig, HttpEndpointConfigError, McpConfig,
    ServerConfig, claude_desktop_config_path, default_config_paths,
};
pub use fastmcp_client::{http_executor, mcp_config};

// Re-export macros
pub use fastmcp_derive::{JsonSchema, prompt, resource, tool};

/// Auto-policy composition helpers.
///
/// The returned client builder captures [`ProtocolPolicy::Auto`] before any
/// subprocess or HTTP side effect. The caller may replace that immutable plan
/// with an explicit plan before connecting.
pub mod auto {
    pub use fastmcp_client::{ClientBuilder, ClientProtocolPlan};
    pub use fastmcp_protocol::protocol_policy::{
        HttpEndpointBundle, HttpEndpointBundleError, ProtocolEra, ProtocolPolicy, ProtocolVersion,
    };

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
/// conformance.
pub mod modern {
    pub use fastmcp_client::http_executor::{
        MODERN_MCP_ACCEPT, MODERN_MCP_ACCEPT_ENCODING, MODERN_MCP_CONTENT_TYPE, ModernHttpClient,
        ModernHttpClientError, ModernHttpConnectOutcome, ModernHttpExecutor,
        ModernHttpExecutorError, ModernHttpRequest, ModernHttpResponseKind,
        ModernHttpResponseMetadata, ModernHttpResponseStream, ModernHttpSseResponseStream,
        validate_response_head,
    };
    pub use fastmcp_client::mcp_config::{
        ConfigError, ConfigLoader, HttpEndpointConfig, HttpEndpointConfigError, McpConfig,
        ServerConfig, claude_desktop_config_path, default_config_paths,
    };
    pub use fastmcp_client::{
        Client, ClientBuilder, ClientHttpNegotiation, ClientHttpNegotiationDecision,
        ClientHttpNegotiationError, ClientHttpNegotiationState, ClientProtocolPlan,
        ClientProtocolPlanError, ClientSession,
    };
    pub use fastmcp_client::{http_executor, mcp_config};
    pub use fastmcp_core::{Cx, McpContext, McpError, McpOutcome, McpResult, Outcome};
    pub use fastmcp_derive::{JsonSchema, prompt, resource, tool};
    pub use fastmcp_protocol::common_types::{
        AbsoluteUri, AnnotationAudience, Annotations, CancellationNotification,
        CancellationRequestId, CommonTypeError, CommonWireDirection, ContentBlock,
        EmbeddedResourceContents, FinalCommonTypesSchema, IconTheme, Implementation, LoggingLevel,
        OpaqueCursor, OpenMetadata, RawIcon, RawIconSourceUri, ResourceLink, TraceContext,
        UntrustedCancellationReason,
    };
    pub use fastmcp_protocol::extensions::{
        ClientExtensionDiscovery, EffectiveExtensionSettings, ExtensionDescriptor,
        ExtensionDescriptorRegistry, ExtensionDirection, ExtensionDiscovery,
        ExtensionDispatchError, ExtensionFallbackPolicy, ExtensionHttpEraDisposition, ExtensionId,
        ExtensionInactiveReason, ExtensionLocalEnablement, ExtensionMethodDescriptor,
        ExtensionNegotiationError, ExtensionNegotiationResolver, ExtensionNotificationDescriptor,
        ExtensionPeer, ExtensionRegistryError, ExtensionRegistryReceipt,
        ExtensionRoutingHeaderDescriptor, ExtensionSettings,
        ExtensionSettingsCompatibilityResolver, ExtensionSettingsSchema, NegotiatedExtension,
        NegotiatedExtensionSet, ServerExtensionDiscovery, StdioCorrelationDescriptor,
    };
    pub use fastmcp_protocol::protocol_policy::{
        HttpEndpointBundle, HttpEndpointBundleError, HttpEndpointBundleKey, HttpEraCache,
        HttpEraDecision, HttpModernProbe, HttpProbeBody, HttpRouteKind, MODERN_PROTOCOL_VERSION,
        ModernVersionSupport, ProtocolEra, ProtocolPolicy, ProtocolPolicyError,
        ProtocolPolicySelection, ProtocolRole, ProtocolVersion, ProtocolVersionError,
        StdioEraClassifier, StdioEraDecision, StdioEraRejection, StdioEraState, StdioOpeningFrame,
    };
    pub use fastmcp_protocol::{
        CacheScope, CacheTtl, CacheableResult, ClientCapabilities, ClientInfo, CompleteResult,
        CompleteResultPayload, CompletionValues, CoreDispatchError, CoreRequest, CoreResult,
        CoreResultDiscriminatorPolicy, DecodedResult, DiscoveryCacheHints, ExactJsonMember,
        ExactJsonObject, ExactJsonValue, FINAL_CLIENT_CAPABILITIES_META_KEY,
        FINAL_CLIENT_INFO_META_KEY, FINAL_PROTOCOL_VERSION as PROTOCOL_VERSION,
        FINAL_PROTOCOL_VERSION_META_KEY, FINAL_SERVER_INFO_META_KEY, FinalCallToolParams,
        FinalCallToolResult, FinalCompletionArgument, FinalCompletionContext,
        FinalCompletionParams, FinalCompletionReference, FinalCompletionResult, FinalCoreRequest,
        FinalCoreResult, FinalEmptyParams, FinalEmptyResult, FinalGetPromptParams,
        FinalGetPromptResult, FinalHttpRequestMetadata, FinalListParams, FinalListPromptsResult,
        FinalListResourceTemplatesResult, FinalListResourcesResult, FinalListToolsResult,
        FinalPromptMessage, FinalProtocolVersion, FinalReadResourceParams, FinalReadResourceResult,
        FinalRequestAdmission, FinalRequestMeta, FinalSetLogLevelParams,
        HEADER_MISMATCH_ERROR_CODE, HeaderMismatchError, HeaderMismatchReason, InputRequiredResult,
        MCP_METHOD_HEADER, MCP_NAME_HEADER, MCP_PROTOCOL_VERSION_HEADER,
        MISSING_REQUIRED_CLIENT_CAPABILITY_ERROR_CODE, MetadataView,
        MissingRequiredClientCapabilityError, PaginatedResult,
        ProtocolVersionError as FinalProtocolVersionError, RawResultEnvelope,
        RequestAdmissionError, RequestId, RequestVersionMetadata, RequiredCapabilitiesError,
        ResultDecodeError, ResultDecodeErrorKind, ResultDiscriminatorDecision,
        ResultDiscriminatorPolicy, ResultMeta, ResultPeerDiagnostic, ResultPeerEra,
        SERVER_DISCOVER_METHOD, SERVER_DISCOVER_SUPPORTED_VERSIONS,
        SUPPORTED_FINAL_PROTOCOL_VERSIONS, ServerBehavior, ServerBehaviorRegistry,
        ServerDiscoverCapabilities, ServerDiscoverRequest, ServerDiscoverResult,
        ServerDiscoveryError, ServerInstructionError, ServerInstructions, TypedCompleteMembers,
        UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE, UnknownResultMembers,
        UnsupportedProtocolVersionError, admit_final_http_request, admit_final_request,
        decode_peer_result, decode_typed_complete, encode_result, parse_exact_json,
        validate_final_protocol_version,
    };
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
        AuthProvider, AuthRequest, BidirectionalSenders, BoxFuture, HttpServerConfig,
        InboundRequestContext, InboundRequestTransport, Middleware, MiddlewareDecision,
        MountResult, ProgressNotificationSender, PromptHandler, ResourceHandler, Router, Server,
        ServerBuilder, TagFilters, ToolHandler, create_context_with_progress,
        create_context_with_progress_and_senders,
    };
    pub use fastmcp_transport::{Codec, StdioTransport, Transport, TransportError, http, memory};

    /// Creates a client builder pinned to the ModernOnly stdio plan.
    #[must_use]
    pub fn client_builder() -> ClientBuilder {
        ClientBuilder::new().protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
    }
}

/// Exact MCP 2024-11-05 public vocabulary.
///
/// This module keeps legacy lifecycle and transport access explicit. It is
/// intentionally disjoint from [`modern`]; selecting between the two remains
/// the responsibility of the immutable policy and the transport-specific
/// negotiation layer.
pub mod legacy_2024 {
    pub use fastmcp_client::ClientProtocolPlan;
    pub use fastmcp_client::http_executor::{LegacySseHttpClient, LegacySseHttpClientError};
    pub use fastmcp_core::Cx;
    pub use fastmcp_protocol::methods;
    pub use fastmcp_protocol::protocol_policy::{
        LEGACY_PROTOCOL_VERSION, LegacyClientAdapterInstalledReceipt,
        LegacyServerAdapterInstalledReceipt, ProtocolEra, ProtocolPolicy, ProtocolVersion,
    };
    pub use fastmcp_protocol::{
        CallToolParams, CallToolResult, CancelledParams, CompletionValues, GetPromptParams,
        GetPromptResult, InitializeParams, InitializeResult, JsonRpcMessage, JsonRpcRequest,
        LegacyCompletionArgument, LegacyCompletionParams, LegacyCompletionReference,
        LegacyCompletionResult, LegacyCoreRequest, LegacyCoreResult, LegacyEmptyResult,
        ListPromptsParams, ListPromptsResult, ListResourceTemplatesParams,
        ListResourceTemplatesResult, ListResourcesParams, ListResourcesResult, ListToolsParams,
        ListToolsResult, PROTOCOL_VERSION, ReadResourceParams, ReadResourceResult, RequestId,
        SetLogLevelParams,
    };
    pub use fastmcp_server::legacy_2024::{
        LEGACY_2024_MAX_ADAPTER_RESERVATIONS, Legacy2024AdapterError, Legacy2024Handler,
        Legacy2024HandlerError, Legacy2024Lifecycle, Legacy2024LiveServerLifecycle,
        Legacy2024Outbound, Legacy2024ServerAdapter, Legacy2024ServerConfig, Legacy2024ServerInfo,
        Legacy2024StateSnapshot, LegacyAuthenticatedPeerPartition, LegacyPeerBinding,
        LegacyServerAdapterInstalledReceipt as ServerAdapterInstalledReceipt,
        legacy_2024_a_digest_preimage, legacy_2024_b_digest_preimage,
    };
    pub use fastmcp_transport::sse::{
        LegacySseClientTransport, LegacySseMessagePost, LegacySsePostSink, LegacySseServerTransport,
    };
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
        AuthContext,
        // Client
        BoundedListPage,
        Client,
        ClientBuilder,
        ClientHttpNegotiation,
        ClientHttpNegotiationDecision,
        ClientHttpNegotiationError,
        ClientHttpNegotiationState,
        ClientProtocolPlan,
        ClientSession,
        CompleteResult,
        ConfigError,
        ConfigLoader,
        // Protocol types
        Content,
        ContentBlock,
        DecodedResult,
        ExtensionDescriptor,
        ExtensionDescriptorRegistry,
        FINAL_PROTOCOL_VERSION,
        FinalAbsoluteUri,
        FinalProtocolVersion,
        HttpEndpointConfig,
        HttpEndpointConfigError,
        // Server
        InboundRequestContext,
        InboundRequestTransport,
        JsonSchema,
        ListPageLimits,
        McpConfig,
        McpContext,
        McpError,
        McpOutcome,
        McpResult,
        Middleware,
        MiddlewareDecision,
        ModernHttpExecutor,
        ModernHttpExecutorError,
        ModernHttpRequest,
        NegotiatedExtensionSet,
        // Outcome types (4-valued result)
        Outcome,
        OutcomeExt,
        Prompt,
        PromptArgument,
        PromptMessage,
        ProtocolEra,
        ProtocolPolicy,
        ProtocolVersion,
        ProxyBackend,
        ProxyCatalog,
        ProxyClient,
        RequestAdmissionError,
        RequestTimeoutPolicy,
        RequestTimeoutSource,
        Resource,
        ResourceContent,
        ResultExt,
        Role,
        Server,
        ServerBehavior,
        ServerBehaviorRegistry,
        ServerConfig,
        ServerDiscoverRequest,
        ServerDiscoverResult,
        StaticTokenVerifier,
        TokenAuthProvider,
        TokenVerifier,
        Tool,
        cancelled,
        err,
        legacy_2024,
        modern,
        ok,
        // Macros
        prompt,
        providers::FilesystemProvider,
        resource,
        tool,
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
    fn prelude_reexports_client_timeout_configuration_surface() {
        use super::prelude::{
            Client, ClientBuilder, ClientHttpNegotiation, ClientSession, CompleteResult, McpConfig,
            ModernHttpRequest, RequestTimeoutPolicy, RequestTimeoutSource, legacy_2024, modern,
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
        let _: Option<modern::CoreRequest> = None;
        let _: Option<modern::CoreResult> = None;
        let _: Option<modern::ModernHttpClient> = None;
        let _: Option<modern::MrtrExchangeRegistry> = None;
        let _: Option<legacy_2024::CallToolParams> = None;
        let _: Option<legacy_2024::LegacySseHttpClient> = None;
    }

    #[test]
    fn api_01_public_auto_and_modern_surfaces_compile() {
        use super::{auto, modern};

        let auto_builder = auto::client_builder();
        assert_eq!(
            auto_builder.selected_protocol_plan().policy(),
            modern::ProtocolPolicy::Auto
        );

        let explicit_modern_builder = modern::client_builder();
        assert_eq!(
            explicit_modern_builder.selected_protocol_plan().policy(),
            modern::ProtocolPolicy::ModernOnly
        );

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
    fn api_02_facade_exposes_shipped_final_product_surface() {
        use super::{legacy_2024, modern};

        let uri = modern::AbsoluteUri::parse("https://mcp.example.test/final")
            .expect("facade must expose final common URI admission");
        assert_eq!(uri.as_str(), "https://mcp.example.test/final");

        let request = modern::ModernHttpRequest::new(
            "https://mcp.example.test/mcp",
            br#"{}"#.to_vec(),
            modern::PROTOCOL_VERSION,
            modern::SERVER_DISCOVER_METHOD,
            None,
        )
        .expect("facade must expose modern HTTP request construction");
        assert!(request.headers().iter().any(
            |(name, value)| name == "MCP-Protocol-Version" && value == modern::PROTOCOL_VERSION
        ));
        let _executor = modern::ModernHttpExecutor::new();

        let mut config = modern::McpConfig::new();
        config.add_server("final", modern::ServerConfig::new("final-mcp"));
        assert_eq!(config.server_names(), vec!["final"]);

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
        let _: Option<modern::ClientHttpNegotiation> = None;
        let _: Option<modern::HttpEndpointConfig> = None;
        let _: Option<modern::InboundRequestContext> = None;
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
        let _: Option<modern::FinalSetLogLevelParams> = None;
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
        let _: Option<modern::CoreRequest> = None;
        let _: Option<modern::CoreResult> = None;
        let _: Option<modern::CoreDispatchError> = None;
        let _: Option<modern::ModernHttpClient> = None;
        let _: Option<modern::ModernHttpConnectOutcome> = None;
        let _: Option<modern::ModernHttpClientError> = None;
        let _: Option<modern::ModernHttpSseResponseStream> = None;
        let _: Option<super::FinalRequestMeta> = None;
        let _: Option<super::ModernHttpClient> = None;
        let _: Option<super::MrtrExchangeRegistry> = None;
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
