//! MCP server implementation for FastMCP.
//!
//! This crate provides the server-side implementation:
//! - Server builder pattern
//! - Tool, resource, and prompt registration
//! - Request routing and dispatching
//! - Session management
//!
//! # Example
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

#![forbid(unsafe_code)]
#![allow(dead_code)]

mod builder;
mod handler;
mod router;
mod session;

#[cfg(test)]
mod tests;

pub use builder::ServerBuilder;
pub use handler::{
    BoxFuture, ProgressNotificationSender, PromptHandler, ResourceHandler, ToolHandler,
    create_context_with_progress,
};
pub use router::{NotificationSender, Router};
pub use session::Session;

use std::io::Write;
use std::sync::Arc;

use asupersync::{Budget, Cx};
use fastmcp_console::{banner::StartupBanner, console};
use fastmcp_core::logging::{error, info, targets};
use fastmcp_core::McpError;
use fastmcp_protocol::{
    CallToolParams, GetPromptParams, InitializeParams, JsonRpcError, JsonRpcMessage,
    JsonRpcRequest, JsonRpcResponse, ListPromptsParams, ListResourcesParams, ListToolsParams,
    Prompt, ReadResourceParams, RequestId, Resource, ServerCapabilities, ServerInfo, Tool,
};
use fastmcp_transport::{Codec, StdioTransport, Transport, TransportError};

/// An MCP server instance.
///
/// Servers are built using [`ServerBuilder`] and can run on various
/// transports (stdio, SSE, WebSocket).
pub struct Server {
    info: ServerInfo,
    capabilities: ServerCapabilities,
    router: Router,
    instructions: Option<String>,
    /// Request timeout in seconds (0 = no timeout).
    request_timeout_secs: u64,
}

impl Server {
    /// Creates a new server builder.
    #[must_use]
    #[allow(clippy::new_ret_no_self)]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> ServerBuilder {
        ServerBuilder::new(name, version)
    }

    /// Returns the server info.
    #[must_use]
    pub fn info(&self) -> &ServerInfo {
        &self.info
    }

    /// Returns the server capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &ServerCapabilities {
        &self.capabilities
    }

    /// Lists all registered tools.
    #[must_use]
    pub fn tools(&self) -> Vec<Tool> {
        self.router.tools()
    }

    /// Lists all registered resources.
    #[must_use]
    pub fn resources(&self) -> Vec<Resource> {
        self.router.resources()
    }

    /// Lists all registered prompts.
    #[must_use]
    pub fn prompts(&self) -> Vec<Prompt> {
        self.router.prompts()
    }

    /// Runs the server on stdio transport.
    ///
    /// This is the primary way to run MCP servers as subprocesses.
    /// Creates a testing Cx and runs the server loop.
    pub fn run_stdio(self) -> ! {
        // Create a Cx for the server (for now, use testing Cx)
        let cx = Cx::for_testing();
        self.run_stdio_with_cx(&cx)
    }

    /// Runs the server on stdio with a provided Cx.
    ///
    /// This allows integration with a real asupersync runtime.
    pub fn run_stdio_with_cx(self, cx: &Cx) -> ! {
        let mut transport = StdioTransport::stdio();
        let mut session = Session::new(self.info.clone(), self.capabilities.clone());

        if !banner_suppressed() {
            let render_banner = || {
                let mut banner = StartupBanner::new(&self.info.name, &self.info.version)
                    .tools(self.router.tools_count())
                    .resources(self.router.resources_count())
                    .prompts(self.router.prompts_count())
                    .transport("stdio");

                if let Some(desc) = self.instructions.as_deref().filter(|d| !d.is_empty()) {
                    banner = banner.description(desc);
                }

                banner.render(console());
            };

            if let Err(err) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(render_banner))
            {
                eprintln!("Warning: banner rendering failed: {err:?}");
            }
        }

        // Create a notification sender that writes to a separate stdout handle.
        // This allows progress notifications to be sent during handler execution
        // while the main transport is blocked on recv().
        let notification_sender = create_notification_sender();

        // Main request loop
        loop {
            // Check for cancellation
            if cx.is_cancel_requested() {
                info!(target: targets::SERVER, "Cancellation requested, shutting down");
                std::process::exit(0);
            }

            // Receive next message
            let message = match transport.recv(cx) {
                Ok(msg) => msg,
                Err(TransportError::Closed) => {
                    // Clean shutdown
                    std::process::exit(0);
                }
                Err(TransportError::Cancelled) => {
                    info!(target: targets::SERVER, "Transport cancelled");
                    std::process::exit(0);
                }
                Err(e) => {
                    error!(target: targets::TRANSPORT, "Transport error: {}", e);
                    continue;
                }
            };

            // Handle the message
            let response = match message {
                JsonRpcMessage::Request(request) => {
                    self.handle_request(cx, &mut session, request, &notification_sender)
                }
                JsonRpcMessage::Response(_) => {
                    // Servers don't expect responses
                    continue;
                }
            };

            // Send response
            if let Err(e) = transport.send(cx, &JsonRpcMessage::Response(response)) {
                error!(target: targets::TRANSPORT, "Failed to send response: {}", e);
            }
        }
    }

    /// Handles a single JSON-RPC request.
    fn handle_request(
        &self,
        cx: &Cx,
        session: &mut Session,
        request: JsonRpcRequest,
        notification_sender: &NotificationSender,
    ) -> JsonRpcResponse {
        let id = request.id.clone();

        // Generate internal request ID for tracing
        let request_id = request_id_to_u64(id.as_ref());

        // Create a budget for this request based on timeout configuration
        let budget = self.create_request_budget();

        // Check if budget is already exhausted (should not happen, but be defensive)
        if budget.is_exhausted() {
            return JsonRpcResponse::error(
                id,
                JsonRpcError {
                    code: -32000,
                    message: "Request budget exhausted".to_string(),
                    data: None,
                },
            );
        }

        // Dispatch based on method, passing the budget and notification sender
        let result = self.dispatch_method(
            cx,
            session,
            &request.method,
            request.params,
            request_id,
            &budget,
            notification_sender,
        );

        // For success, we need a non-None id; use a fallback for notifications
        let response_id = id.clone().unwrap_or(RequestId::Number(0));

        match result {
            Ok(value) => JsonRpcResponse::success(response_id, value),
            Err(e) => JsonRpcResponse::error(
                id,
                JsonRpcError {
                    code: e.code.into(),
                    message: e.message,
                    data: e.data,
                },
            ),
        }
    }

    /// Creates a budget for a new request based on server configuration.
    fn create_request_budget(&self) -> Budget {
        if self.request_timeout_secs == 0 {
            // No timeout - unlimited budget
            Budget::INFINITE
        } else {
            // Create budget with deadline
            Budget::with_deadline_secs(self.request_timeout_secs)
        }
    }

    /// Dispatches a request to the appropriate handler.
    #[allow(clippy::too_many_arguments)]
    fn dispatch_method(
        &self,
        cx: &Cx,
        session: &mut Session,
        method: &str,
        params: Option<serde_json::Value>,
        request_id: u64,
        budget: &Budget,
        notification_sender: &NotificationSender,
    ) -> Result<serde_json::Value, McpError> {
        // Check cancellation before dispatch
        if cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }

        // Check budget before dispatch (for poll-based exhaustion)
        if budget.is_exhausted() {
            return Err(McpError::internal_error("Request budget exhausted"));
        }

        match method {
            "initialize" => {
                let params: InitializeParams = parse_params(params)?;
                let result = self.router.handle_initialize(
                    cx,
                    session,
                    params,
                    self.instructions.as_deref(),
                )?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "initialized" => {
                // Notification, no response needed (but we send empty ok)
                Ok(serde_json::Value::Null)
            }
            "tools/list" => {
                let params: ListToolsParams = parse_params_or_default(params)?;
                let result = self.router.handle_tools_list(cx, params)?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "tools/call" => {
                let params: CallToolParams = parse_params(params)?;
                let result = self.router.handle_tools_call(
                    cx,
                    request_id,
                    params,
                    budget,
                    Some(notification_sender),
                )?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "resources/list" => {
                let params: ListResourcesParams = parse_params_or_default(params)?;
                let result = self.router.handle_resources_list(cx, params)?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "resources/read" => {
                let params: ReadResourceParams = parse_params(params)?;
                let result = self.router.handle_resources_read(
                    cx,
                    request_id,
                    &params,
                    budget,
                    Some(notification_sender),
                )?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "prompts/list" => {
                let params: ListPromptsParams = parse_params_or_default(params)?;
                let result = self.router.handle_prompts_list(cx, params)?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "prompts/get" => {
                let params: GetPromptParams = parse_params(params)?;
                let result = self.router.handle_prompts_get(
                    cx,
                    request_id,
                    params,
                    budget,
                    Some(notification_sender),
                )?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "ping" => {
                // Simple ping-pong for health checks
                Ok(serde_json::json!({}))
            }
            _ => Err(McpError::method_not_found(method)),
        }
    }
}

fn banner_suppressed() -> bool {
    std::env::var("FASTMCP_NO_BANNER")
        .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Parses required parameters from JSON.
fn parse_params<T: serde::de::DeserializeOwned>(
    params: Option<serde_json::Value>,
) -> Result<T, McpError> {
    let value = params.ok_or_else(|| McpError::invalid_params("Missing required parameters"))?;
    serde_json::from_value(value).map_err(|e| McpError::invalid_params(e.to_string()))
}

/// Parses optional parameters from JSON, using default if not provided.
fn parse_params_or_default<T: serde::de::DeserializeOwned + Default>(
    params: Option<serde_json::Value>,
) -> Result<T, McpError> {
    match params {
        Some(value) => {
            serde_json::from_value(value).map_err(|e| McpError::invalid_params(e.to_string()))
        }
        None => Ok(T::default()),
    }
}

/// Converts a JSON-RPC RequestId to a u64 for internal tracking.
///
/// If the ID is a number, uses that number. If it's a string or absent,
/// uses 0 as a fallback.
fn request_id_to_u64(id: Option<&RequestId>) -> u64 {
    match id {
        Some(RequestId::Number(n)) => (*n).try_into().unwrap_or(0),
        Some(RequestId::String(_)) | None => 0,
    }
}

/// Creates a notification sender that writes JSON-RPC notifications to stdout.
///
/// This creates a separate stdout handle for sending notifications, allowing
/// notifications (like progress updates) to be sent during handler execution
/// independently of the main transport.
///
/// The sender uses NDJSON format (newline-delimited JSON) to match the
/// standard MCP transport format.
fn create_notification_sender() -> NotificationSender {
    use std::sync::Mutex;

    // Create a Mutex-wrapped stdout handle for thread-safe writes.
    // Each notification write is atomic at the stdout level.
    let stdout = Mutex::new(std::io::stdout());
    let codec = Codec::new();

    Arc::new(move |request: JsonRpcRequest| {
        // Encode the notification to JSON
        let bytes = match codec.encode_request(&request) {
            Ok(b) => b,
            Err(e) => {
                log::error!(target: "fastmcp::server", "Failed to encode notification: {}", e);
                return;
            }
        };

        // Write to stdout atomically
        if let Ok(mut stdout) = stdout.lock() {
            if let Err(e) = stdout.write_all(&bytes) {
                log::error!(target: "fastmcp::transport", "Failed to send notification: {}", e);
            }
            if let Err(e) = stdout.flush() {
                log::error!(target: "fastmcp::transport", "Failed to flush notification: {}", e);
            }
        } else {
            log::warn!(target: "fastmcp::server", "Failed to acquire stdout lock for notification");
        }
    })
}
