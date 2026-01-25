//! FastMCP: Fast, cancel-correct MCP framework for Rust.
//!
//! FastMCP is a Rust implementation of the Model Context Protocol (MCP),
//! providing a high-performance, cancel-correct framework for building
//! MCP servers and clients.
//!
//! # Features
//!
//! - **Fast**: Zero-copy parsing, minimal allocations
//! - **Cancel-correct**: Built on asupersync for structured concurrency
//! - **Simple**: Familiar API inspired by FastMCP (Python)
//! - **Complete**: Tools, resources, prompts, and all MCP features
//!
//! # Quick Start
//!
//! ```ignore
//! use fastmcp::prelude::*;
//!
//! #[tool]
//! async fn greet(ctx: &McpContext, name: String) -> String {
//!     format!("Hello, {name}!")
//! }
//!
//! fn main() {
//!     Server::new("my-server", "1.0.0")
//!         .tool(greet)
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
//! - `fastmcp-macros`: Procedural macros (#[tool], #[resource], #[prompt])
//!
//! # Asupersync Integration
//!
//! FastMCP uses [asupersync](https://github.com/Dicklesworthstone/asupersync) for:
//!
//! - **Structured concurrency**: All tasks belong to regions
//! - **Cancel-correctness**: Graceful cancellation via checkpoints
//! - **Budgeted timeouts**: Resource limits for requests
//! - **Deterministic testing**: Lab runtime for reproducible tests

#![forbid(unsafe_code)]
#![allow(dead_code)]

// Re-export core types
pub use fastmcp_core::{
    Budget, CancelledError, Cx, IntoOutcome, LabConfig, LabRuntime, McpContext, McpError,
    McpErrorCode, McpOutcome, McpResult, Outcome, OutcomeExt, RegionId, ResultExt, Scope, TaskId,
    cancelled, err, ok,
};

// Re-export logging module
pub use fastmcp_core::logging;

// Re-export protocol types
pub use fastmcp_protocol::{
    CallToolParams, CallToolResult, CancelledParams, ClientCapabilities, ClientInfo, Content,
    GetPromptParams, GetPromptResult, InitializeParams, InitializeResult, JsonRpcError,
    JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, ListPromptsParams, ListPromptsResult,
    ListResourceTemplatesParams, ListResourceTemplatesResult, ListResourcesParams,
    ListResourcesResult, ListToolsParams, ListToolsResult, LogLevel, PROTOCOL_VERSION, Prompt,
    PromptArgument, PromptMessage, ReadResourceParams, ReadResourceResult, Resource,
    ResourceContent, ResourceTemplate, ResourcesCapability, Role, ServerCapabilities, ServerInfo,
    SubscribeResourceParams, Tool, ToolsCapability, UnsubscribeResourceParams,
};

// Re-export transport types
pub use fastmcp_transport::{Codec, StdioTransport, Transport, TransportError};

// Re-export server types
pub use fastmcp_server::{
    PromptHandler, ResourceHandler, Router, Server, ServerBuilder, Session, ToolHandler,
};

// Re-export client types
pub use fastmcp_client::{Client, ClientBuilder, ClientSession};

// Re-export macros
pub use fastmcp_macros::{JsonSchema, prompt, resource, tool};

/// Prelude module for convenient imports.
///
/// ```ignore
/// use fastmcp::prelude::*;
/// ```
pub mod prelude {
    pub use crate::{
        // Client
        Client,
        // Protocol types
        Content,
        JsonSchema,
        // Context and errors
        McpContext,
        McpError,
        McpOutcome,
        McpResult,
        // Outcome types (4-valued result)
        Outcome,
        OutcomeExt,
        Prompt,
        PromptArgument,
        PromptMessage,
        Resource,
        ResourceContent,
        ResultExt,
        Role,
        // Server
        Server,
        Tool,
        cancelled,
        err,
        ok,
        // Macros
        prompt,
        resource,
        tool,
    };
}
