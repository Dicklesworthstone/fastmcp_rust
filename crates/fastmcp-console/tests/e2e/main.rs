//! End-to-end tests for fastmcp-console.
//!
//! These tests spawn actual server processes and verify:
//! - Protocol correctness (stdout = JSON-RPC only)
//! - Agent mode (no ANSI codes in stdout)
//! - Human mode (rich output in stderr)
//! - Configuration options via environment variables
//!
//! # Test Infrastructure
//!
//! - `helpers.rs` - Utilities for spawning servers and capturing output
//! - `server_lifecycle.rs` - Startup, request handling, shutdown tests
//! - `agent_mode.rs` - Tests for agent detection and plain output
//! - `human_mode.rs` - Tests for rich terminal output
//! - `error_display.rs` - Error formatting tests
//! - `configuration.rs` - Environment variable configuration tests

mod helpers;

mod server_lifecycle;
mod agent_mode;
mod human_mode;
mod configuration;

// Re-export helpers for use in tests
pub use helpers::*;
