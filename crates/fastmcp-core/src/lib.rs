//! Core types and traits for FastMCP.
//!
//! This crate provides the fundamental building blocks:
//! - [`McpContext`] wrapping asupersync's [`Cx`]
//! - Error types for MCP operations
//! - Capability traits for progress, sampling, elicitation, and nested calls
//!
//! MCP 2026-07-28 support is under implementation and remains unverified. The
//! public protocol constant is still `2024-11-05`; this crate's primitives are
//! not aggregate conformance or release evidence.
//!
//! # Design Principles
//!
//! - Serde-backed protocol and context types
//! - No runtime reflection (compile-time via macros)
//! - `Send + Sync` bounds on concurrency-facing APIs where required
//! - Explicit cancellation and budget surfaces through asupersync
//!
//! # Role in the System
//!
//! `fastmcp-core` is the **foundation layer** shared by every other crate.
//! It defines:
//! - `McpContext`, the capability-carrying handle that wraps asupersync's `Cx`
//! - The FastMCP error model (`McpError`, `McpErrorCode`, `McpResult`)
//! - Budget and cancellation primitives used by handlers and transports
//! - Outcome bridging utilities so server/client code can stay 4-valued
//!
//! If you are implementing a new transport, handler, or runtime adapter, this
//! is the crate that gives you the shared primitives used everywhere else.
//!
//! # Asupersync Integration
//!
//! This crate uses [asupersync](https://github.com/Dicklesworthstone/asupersync) as its async
//! runtime foundation, providing:
//!
//! - **Context propagation**: `McpContext` carries an asupersync `Cx`
//! - **Cooperative cancellation**: Explicit checkpoints surface cancellation
//! - **Budgets**: Deadline, poll, and cost dimensions travel with contexts
//! - **Deterministic test support**: The lab runtime is available to tests

#![forbid(unsafe_code)]
// Allow dead code during Phase 0 development
#![allow(dead_code)]

mod auth;
pub mod combinator;
mod context;
pub mod crypto;
mod duration;
mod error;
pub mod logging;
pub mod runtime;
mod state;
pub mod uri;

pub use auth::{AccessToken, AuthContext, MAX_ACCESS_SCHEME_BYTES, MAX_ACCESS_TOKEN_BYTES};
pub use context::{
    CancelledError, ClientCapabilityInfo, ElicitationAction, ElicitationMode, ElicitationRequest,
    ElicitationResponse, ElicitationSender, IntoOutcome, MAX_RESOURCE_READ_DEPTH,
    MAX_TOOL_CALL_DEPTH, McpContext, McpContextLeaseGuard, McpRequestCancellation,
    NoOpElicitationSender, NoOpNotificationSender, NoOpSamplingSender, NotificationSender,
    ProgressReporter, ResourceContentItem, ResourceReadResult, ResourceReader, SamplingRequest,
    SamplingRequestMessage, SamplingResponse, SamplingRole, SamplingSender, SamplingStopReason,
    ServerCapabilityInfo, ToolCallResult, ToolCaller, ToolContentItem,
};
pub use crypto::{
    CryptoInputTooLongError, EPHEMERAL_KEY_MATERIAL_BYTES, EphemeralKeyMaterial,
    HMAC_SHA256_KEY_BYTES, HMAC_SHA256_TAG_BYTES, HmacSha256Key, HmacSha256Tag,
    HmacVerificationError, NONCE_DOMAIN_MATERIAL_BYTES, NonceDomainMaterial, RandomDrawError,
    SECURITY_IDENTIFIER_BYTES, SHA256_DIGEST_BYTES, SecurityIdentifier, Sha256Digest,
    WEBSOCKET_MASK_BYTES, WebSocketMask, draw_ephemeral_key_material, draw_hmac_sha256_key,
    draw_nonce_domain_material, draw_security_identifier, draw_websocket_mask, sha256_bounded,
};
pub use duration::{ParseDurationError, parse_duration};
pub use error::{
    McpError, McpErrorCode, McpOutcome, McpResult, OutcomeExt, ResultExt, cancelled, err, ok,
};
pub use runtime::block_on;
pub use state::{DISABLED_PROMPTS_KEY, DISABLED_RESOURCES_KEY, DISABLED_TOOLS_KEY, SessionState};
pub use uri::{
    ABSOLUTE_URI_HARD_MAX_BYTES, AbsoluteUri, AbsoluteUriComponent, AbsoluteUriError,
    AbsoluteUriScheme, AuthorityErrorKind, CANONICAL_HTTP_URL_POLICY, CANONICAL_URL_HARD_MAX_BYTES,
    CanonicalHttpUrl, CanonicalHttpUrlError, CanonicalResourceId, CanonicalResourceIdError,
    CanonicalResourceIdPolicy, CanonicalUrlPolicy, DEFAULT_ABSOLUTE_URI_MAX_BYTES,
    DEFAULT_CANONICAL_URL_MAX_BYTES, DefaultPortPolicy, DotSegmentPolicy, FragmentPolicy,
    IdnaPolicy, PercentEncodingPolicy, QueryPolicy, ResourceEndpointPathPolicy,
    SchemeHostCasePolicy, SyntaxViolationPolicy, TrailingSlashPolicy, UriComponentState,
    UserinfoPolicy,
};

// Re-export key asupersync types for convenience
pub use asupersync::{Budget, Cx, LabConfig, LabRuntime, Outcome, RegionId, Scope, TaskId};
