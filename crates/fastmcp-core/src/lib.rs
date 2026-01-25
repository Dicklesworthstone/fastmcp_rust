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

mod context;
mod error;
pub mod logging;
pub mod runtime;

pub use context::{
    CancelledError, IntoOutcome, McpContext, NoOpNotificationSender, NotificationSender,
    ProgressReporter,
};
pub use error::{
    McpError, McpErrorCode, McpOutcome, McpResult, OutcomeExt, ResultExt, cancelled, err, ok,
};
pub use runtime::block_on;

// Re-export key asupersync types for convenience
pub use asupersync::{Budget, Cx, LabConfig, LabRuntime, Outcome, RegionId, Scope, TaskId};
