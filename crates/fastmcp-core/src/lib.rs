//! Core types and traits for FastMCP.
//!
//! This crate provides the fundamental building blocks:
//! - [`McpContext`] wrapping asupersync's [`Cx`]
//! - Error types for MCP operations
//! - Core traits for tool, resource, and prompt handlers
//!
//! # Design Principles
//!
//! - Zero-copy where possible
//! - No runtime reflection (compile-time via macros)
//! - All types support `Send + Sync`
//! - Cancel-correct via asupersync integration
//!
//! # Role in the System
//!
//! `fastmcp-core` is the **foundation layer** shared by every other crate.
//! It defines:
//! - `McpContext`, the capability-carrying handle that wraps asupersync's `Cx`
//! - The FastMCP error model (`McpError`, `McpErrorCode`, `McpResult`)
//! - Budget/cancellation semantics that handlers and transports must obey
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
//! - **Structured concurrency**: Tool handlers run in regions
//! - **Cancel-correctness**: Graceful cancellation via checkpoints
//! - **Budgeted timeouts**: Request timeouts via budget exhaustion
//! - **Deterministic testing**: Lab runtime for reproducible tests

#![forbid(unsafe_code)]
// Allow dead code during Phase 0 development
#![allow(dead_code)]

mod auth;
pub mod combinator;
mod context;
mod duration;
mod error;
pub mod logging;
pub mod runtime;
mod state;

pub use auth::{AUTH_STATE_KEY, AccessToken, AuthContext};
pub use context::{
    CancelledError, ClientCapabilityInfo, ElicitationAction, ElicitationMode, ElicitationRequest,
    ElicitationResponse, ElicitationSender, IntoOutcome, MAX_RESOURCE_READ_DEPTH,
    MAX_TOOL_CALL_DEPTH, McpContext, NoOpElicitationSender, NoOpNotificationSender,
    NoOpSamplingSender, NotificationSender, ProgressReporter, ResourceContentItem,
    ResourceReadResult, ResourceReader, SamplingRequest, SamplingRequestMessage, SamplingResponse,
    SamplingRole, SamplingSender, SamplingStopReason, ServerCapabilityInfo, ToolCallResult,
    ToolCaller, ToolContentItem,
};
pub use duration::{ParseDurationError, parse_duration};
pub use error::{
    McpError, McpErrorCode, McpOutcome, McpResult, OutcomeExt, ResultExt, cancelled, err, ok,
};
pub use runtime::block_on;
pub use state::{DISABLED_PROMPTS_KEY, DISABLED_RESOURCES_KEY, DISABLED_TOOLS_KEY, SessionState};

// Re-export key asupersync types for convenience
pub use asupersync::{Budget, Cx, LabConfig, LabRuntime, Outcome, RegionId, Scope, TaskId};
