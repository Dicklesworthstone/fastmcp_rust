//! Structured logging for FastMCP.
//!
//! This module provides structured logging support built on the standard
//! [`log`] facade. All FastMCP crates use these logging utilities.
//!
//! # Log Levels
//!
//! - **error**: Unrecoverable errors, transport failures
//! - **warn**: Recoverable issues, deprecation warnings
//! - **info**: Server lifecycle events (start, stop, client connect)
//! - **debug**: Request/response flow, handler invocations
//! - **trace**: Wire-level message details, internal state
//!
//! # Usage
//!
//! The log macros are re-exported for convenience:
//!
//! ```ignore
//! use fastmcp_core::logging::{error, warn, info, debug, trace};
//!
//! info!("Server started on {}", transport);
//! debug!(target: "mcp::request", method = %method, "Handling request");
//! error!("Transport error: {}", err);
//! ```
//!
//! # Initialization
//!
//! FastMCP does not include a log implementation. Applications should
//! initialize logging using their preferred backend:
//!
//! ```ignore
//! // Using env_logger (simple)
//! env_logger::init();
//!
//! // Using simple_logger
//! simple_logger::init_with_level(log::Level::Info).unwrap();
//! ```
//!
//! # Log Targets
//!
//! FastMCP uses hierarchical log targets for filtering:
//!
//! - `fastmcp`: Root target for all FastMCP logs
//! - `fastmcp::server`: Server lifecycle and request handling
//! - `fastmcp::transport`: Transport layer messages
//! - `fastmcp::router`: Request routing and dispatch
//! - `fastmcp::handler`: Tool/resource/prompt handler execution
//!
//! Example filter: `RUST_LOG=fastmcp::server=debug,fastmcp::transport=trace`

// Re-export log macros for ergonomic use
pub use log::{debug, error, info, trace, warn};

// Re-export log level types for programmatic use
pub use log::{Level, LevelFilter};

/// Log targets used by FastMCP components.
///
/// Use these constants with the `target:` argument to log macros
/// for consistent filtering.
pub mod targets {
    /// Root target for all FastMCP logs.
    pub const FASTMCP: &str = "fastmcp";

    /// Server lifecycle and request handling.
    pub const SERVER: &str = "fastmcp::server";

    /// Transport layer (stdio, SSE, WebSocket).
    pub const TRANSPORT: &str = "fastmcp::transport";

    /// Request routing and method dispatch.
    pub const ROUTER: &str = "fastmcp::router";

    /// Tool, resource, and prompt handler execution.
    pub const HANDLER: &str = "fastmcp::handler";

    /// Client connections and sessions.
    pub const SESSION: &str = "fastmcp::session";

    /// Codec operations (JSON encoding/decoding).
    pub const CODEC: &str = "fastmcp::codec";
}

/// Returns whether logging is enabled at the given level for the given target.
///
/// This is useful for conditionally computing expensive log message data:
///
/// ```ignore
/// use fastmcp_core::logging::{is_enabled, Level, targets};
///
/// if is_enabled(Level::Debug, targets::HANDLER) {
///     let stats = compute_expensive_stats();
///     debug!(target: targets::HANDLER, "Handler stats: {:?}", stats);
/// }
/// ```
#[inline]
#[must_use]
pub fn is_enabled(level: Level, target: &str) -> bool {
    log::log_enabled!(target: target, level)
}

/// Logs a server lifecycle event at INFO level.
///
/// This is a convenience macro for common server events.
#[macro_export]
macro_rules! log_server {
    ($($arg:tt)*) => {
        log::info!(target: "fastmcp::server", $($arg)*)
    };
}

/// Logs a transport event at DEBUG level.
#[macro_export]
macro_rules! log_transport {
    ($($arg:tt)*) => {
        log::debug!(target: "fastmcp::transport", $($arg)*)
    };
}

/// Logs a request routing event at DEBUG level.
#[macro_export]
macro_rules! log_router {
    ($($arg:tt)*) => {
        log::debug!(target: "fastmcp::router", $($arg)*)
    };
}

/// Logs a handler execution event at DEBUG level.
#[macro_export]
macro_rules! log_handler {
    ($($arg:tt)*) => {
        log::debug!(target: "fastmcp::handler", $($arg)*)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_targets_are_hierarchical() {
        // Verify targets follow the fastmcp:: prefix pattern
        assert!(targets::SERVER.starts_with(targets::FASTMCP));
        assert!(targets::TRANSPORT.starts_with(targets::FASTMCP));
        assert!(targets::ROUTER.starts_with(targets::FASTMCP));
        assert!(targets::HANDLER.starts_with(targets::FASTMCP));
        assert!(targets::SESSION.starts_with(targets::FASTMCP));
        assert!(targets::CODEC.starts_with(targets::FASTMCP));
    }

    #[test]
    fn level_ordering() {
        // Verify log level ordering (lower = more severe)
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
        assert!(Level::Debug < Level::Trace);
    }
}
