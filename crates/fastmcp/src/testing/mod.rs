//! Test harness infrastructure for FastMCP.
//!
//! This module provides utilities for writing comprehensive tests without mocks:
//!
//! - [`TestContext`]: Wrapper around `Cx::for_testing()` with helper methods
//! - [`TestServer`]: Builder for creating test servers with real handlers
//! - [`TestClient`]: Client for in-process testing with MemoryTransport
//! - Assertion helpers for validating JSON-RPC and MCP compliance
//! - Timing utilities for performance measurements
//!
//! # Example
//!
//! ```ignore
//! use fastmcp::testing::prelude::*;
//!
//! #[test]
//! fn test_tool_call() {
//!     let ctx = TestContext::new();
//!
//!     // Create a test server with real handlers
//!     let (router, client_transport, server_transport) = TestServer::builder()
//!         .build();
//!
//!     // Create a test client
//!     let mut client = TestClient::new(client_transport);
//!     client.initialize().unwrap();
//!
//!     // Call tool and verify
//!     let result = client.call_tool("my_tool", json!({"arg": "value"}));
//!     assert!(result.is_ok());
//! }
//! ```
//!
//! # Design Philosophy
//!
//! - **No mocks**: All tests use real implementations via MemoryTransport
//! - **Deterministic**: Uses asupersync Lab runtime for reproducibility
//! - **Comprehensive logging**: Built-in trace support for debugging
//! - **Resource cleanup**: Automatic cleanup of spawned tasks

mod assertions;
mod client;
mod context;
mod server;
mod timing;
mod trace;

pub use assertions::*;
pub use client::*;
pub use context::*;
pub use server::*;
pub use timing::*;
pub use trace::*;

/// Prelude for convenient imports in tests.
///
/// ```ignore
/// use fastmcp::testing::prelude::*;
/// ```
pub mod prelude {
    pub use super::{
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
        // Client
        TestClient,
        // Context
        TestContext,
        // Server
        TestServer,
        TestServerBuilder,
        // Timing
        Stopwatch,
        Timer,
        TimingStats,
        measure_duration,
        // Trace
        TestTrace,
        TestTraceBuilder,
        TestTraceOutput,
        TraceEntry,
        TraceLevel,
        TraceSummary,
        is_trace_enabled,
    };

    // Re-export commonly used types
    pub use crate::{
        Content, Cx, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, McpContext, McpError,
        McpErrorCode, McpResult, Prompt, Resource, Tool,
    };

    pub use serde_json::json;
}
