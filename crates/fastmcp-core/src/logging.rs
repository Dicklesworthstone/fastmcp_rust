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
//! - `fastmcp_rust`: Root target for all FastMCP logs
//! - `fastmcp_rust::server`: Server lifecycle and request handling
//! - `fastmcp_rust::transport`: Transport layer messages
//! - `fastmcp_rust::router`: Request routing and dispatch
//! - `fastmcp_rust::handler`: Tool/resource/prompt handler execution
//!
//! Example filter: `RUST_LOG=fastmcp_rust::server=debug,fastmcp_rust::transport=trace`

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
    pub const FASTMCP: &str = "fastmcp_rust";

    /// Server lifecycle and request handling.
    pub const SERVER: &str = "fastmcp_rust::server";

    /// Transport layer (stdio, SSE, WebSocket).
    pub const TRANSPORT: &str = "fastmcp_rust::transport";

    /// Request routing and method dispatch.
    pub const ROUTER: &str = "fastmcp_rust::router";

    /// Tool, resource, and prompt handler execution.
    pub const HANDLER: &str = "fastmcp_rust::handler";

    /// Client connections and sessions.
    pub const SESSION: &str = "fastmcp_rust::session";

    /// Codec operations (JSON encoding/decoding).
    pub const CODEC: &str = "fastmcp_rust::codec";
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
        log::info!(target: "fastmcp_rust::server", $($arg)*)
    };
}

/// Logs a transport event at DEBUG level.
#[macro_export]
macro_rules! log_transport {
    ($($arg:tt)*) => {
        log::debug!(target: "fastmcp_rust::transport", $($arg)*)
    };
}

/// Logs a request routing event at DEBUG level.
#[macro_export]
macro_rules! log_router {
    ($($arg:tt)*) => {
        log::debug!(target: "fastmcp_rust::router", $($arg)*)
    };
}

/// Logs a handler execution event at DEBUG level.
#[macro_export]
macro_rules! log_handler {
    ($($arg:tt)*) => {
        log::debug!(target: "fastmcp_rust::handler", $($arg)*)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_targets_are_hierarchical() {
        // Verify targets follow the fastmcp_rust:: prefix pattern
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

    #[test]
    fn is_enabled_returns_bool_without_panic() {
        // Without a logger installed, is_enabled returns false but must not panic
        let result = is_enabled(Level::Info, targets::FASTMCP);
        assert!(!result); // no logger configured in test
    }

    #[test]
    fn target_constants_have_expected_values() {
        assert_eq!(targets::FASTMCP, "fastmcp_rust");
        assert_eq!(targets::SERVER, "fastmcp_rust::server");
        assert_eq!(targets::TRANSPORT, "fastmcp_rust::transport");
        assert_eq!(targets::ROUTER, "fastmcp_rust::router");
        assert_eq!(targets::HANDLER, "fastmcp_rust::handler");
        assert_eq!(targets::SESSION, "fastmcp_rust::session");
        assert_eq!(targets::CODEC, "fastmcp_rust::codec");
    }

    #[test]
    fn target_constants_are_all_distinct() {
        let all = [
            targets::FASTMCP,
            targets::SERVER,
            targets::TRANSPORT,
            targets::ROUTER,
            targets::HANDLER,
            targets::SESSION,
            targets::CODEC,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "targets at {} and {} collide", i, j);
            }
        }
    }

    #[test]
    fn log_macros_compile_and_do_not_panic() {
        // Macros expand to log calls; without a logger they are no-ops
        log_server!("test server event: {}", 42);
        log_transport!("test transport event");
        log_router!("test router event: {}", "route");
        log_handler!("test handler event");
    }
}
