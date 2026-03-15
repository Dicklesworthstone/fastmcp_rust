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
//! use fastmcp_rust::prelude::*;
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
//! - `fastmcp-derive`: Procedural macros (#[tool], #[resource], #[prompt])
//!
//! # Role in the System
//!
//! This crate is the **public façade** of the workspace. It is published as
//! `fastmcp-rust` on crates.io and imported as `fastmcp_rust`. It re-exports the
//! pieces you need for day-to-day server and client development so that most
//! applications can depend on a single crate and write `use fastmcp_rust::prelude::*;`.
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
//! - **Structured concurrency**: All tasks belong to regions
//! - **Cancel-correctness**: Graceful cancellation via checkpoints
//! - **Budgeted timeouts**: Resource limits for requests
//! - **Deterministic testing**: Lab runtime for reproducible tests

#![forbid(unsafe_code)]
#![allow(dead_code)]

// Re-export core types
pub use fastmcp_core::{
    AUTH_STATE_KEY, AccessToken, AuthContext, Budget, CancelledError, Cx, IntoOutcome, LabConfig,
    LabRuntime, McpContext, McpError, McpErrorCode, McpOutcome, McpResult, Outcome, OutcomeExt,
    RegionId, ResultExt, Scope, TaskId, cancelled, err, ok,
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
    SubscribeResourceParams, Tool, ToolAnnotations, ToolsCapability, UnsubscribeResourceParams,
};

// Re-export transport types
pub use fastmcp_transport::{Codec, StdioTransport, Transport, TransportError};

// Re-export transport modules
pub use fastmcp_transport::{event_store, http, memory};

// Re-export server types
#[cfg(feature = "jwt")]
pub use fastmcp_server::JwtTokenVerifier;
pub use fastmcp_server::{
    AllowAllAuthProvider, AuthProvider, AuthRequest, HttpServerConfig, NotificationSender,
    PendingRequests, PromptHandler, ProxyBackend, ProxyCatalog, ProxyClient, RequestSender,
    ResourceHandler, Router, Server, ServerBuilder, Session, SharedTaskManager,
    StaticTokenVerifier, TaskManager, TokenAuthProvider, TokenVerifier, ToolHandler,
    TransportElicitationSender, TransportRootsProvider, TransportSamplingSender,
};

// Re-export bidirectional module for namespaced access (e.g. bidirectional::RequestSender)
pub use fastmcp_server::bidirectional;

// Re-export server middleware modules
pub use fastmcp_server::{caching, docket, oauth, oidc, rate_limiting, transform};

// Re-export client types
pub use fastmcp_client::{Client, ClientBuilder, ClientSession};

// Re-export client configuration module
pub use fastmcp_client::mcp_config;

// Re-export macros
pub use fastmcp_derive::{JsonSchema, prompt, resource, tool};

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
        Client,
        // Protocol types
        Content,
        JsonSchema,
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
        // Server
        ProxyBackend,
        ProxyCatalog,
        ProxyClient,
        Resource,
        ResourceContent,
        ResultExt,
        Role,
        Server,
        StaticTokenVerifier,
        TokenAuthProvider,
        TokenVerifier,
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
