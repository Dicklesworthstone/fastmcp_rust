//! Test harness infrastructure for FastMCP.
//!
//! This module provides utilities for writing comprehensive tests without mocks:
//!
//! - [`TestServer`]: Builder for creating test servers with real handlers
//! - Assertion helpers for validating JSON-RPC and MCP compliance
//! - Timing utilities for performance measurements
//! - [`fixtures`]: Test data generators for tools, resources, prompts, and messages
//!
//! With the `testing-lab` feature, [`lab`] also exposes deterministic-runtime
//! helpers such as `TestContext`, `TestClient`, and `LabRuntime`.
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_rust::testing::prelude::*;
//!
//! #[test]
//! fn test_tool_call() {
//!     // Create a test server with real handlers
//!     let (router, client_transport, server_transport) = TestServer::builder()
//!         .build();
//!
//!     // Create a test client
//! }
//! ```
//!
//! # Design Philosophy
//!
//! - **No mocks**: All tests use real implementations via MemoryTransport
//! - **Production-faithful by default**: ordinary helpers require only public
//!   production APIs
//! - **Lab isolation**: deterministic runtime helpers require `testing-lab`
//! - **Comprehensive logging**: Built-in trace support for debugging
//! - **Resource cleanup**: Automatic cleanup of spawned tasks

mod assertions;
#[cfg(feature = "testing-lab")]
mod client;
#[cfg(feature = "testing-lab")]
mod context;
pub mod fixtures;
mod server;
mod timing;
mod trace;

pub use assertions::*;
pub use server::*;
pub use timing::*;
pub use trace::*;

/// Deterministic test helpers, available only with `testing-lab`.
///
/// This is the sole facade path that exposes lab runtime configuration and
/// helpers that obtain a runtime-installed context on the caller's behalf.
#[cfg(feature = "testing-lab")]
pub mod lab {
    pub use super::client::*;
    pub use super::context::*;
    pub use crate::{LabConfig, LabRuntime};
}

/// Prelude for convenient imports in tests.
///
/// ```ignore
/// use fastmcp_rust::testing::prelude::*;
/// ```
pub mod prelude {
    pub use super::{
        // Timing
        Stopwatch,
        // Server
        TestServer,
        TestServerBuilder,
        // Trace
        TestTrace,
        TestTraceBuilder,
        TestTraceOutput,
        Timer,
        TimingStats,
        TraceEntry,
        TraceLevel,
        TraceSummary,
        // Assertions
        assert_content_valid,
        assert_is_notification,
        assert_is_request,
        assert_json_rpc_error,
        assert_json_rpc_success,
        assert_json_rpc_valid,
        assert_mcp_compliant,
        assert_prompt_valid,
        assert_resource_valid,
        assert_tool_valid,
        is_trace_enabled,
        measure_duration,
    };

    #[cfg(feature = "testing-lab")]
    pub use super::lab::{LabConfig, LabRuntime, TestClient, TestContext};

    // Re-export commonly used types
    pub use crate::{
        Content, Cx, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, McpContext, McpError,
        McpErrorCode, McpResult, Prompt, Resource, Tool,
    };

    pub use serde_json::json;
}
