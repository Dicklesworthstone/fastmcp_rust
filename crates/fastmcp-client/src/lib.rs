//! MCP client implementation for FastMCP.
//!
//! This crate provides the client-side implementation:
//! - Client builder pattern
//! - Tool invocation
//! - Resource reading
//! - Prompt fetching
//!
//! # Example
//!
//! ```ignore
//! use fastmcp::Client;
//!
//! let client = Client::stdio("uvx", &["my-mcp-server"]).await?;
//!
//! // List tools
//! let tools = client.list_tools().await?;
//!
//! // Call a tool
//! let result = client.call_tool("greet", json!({"name": "World"})).await?;
//! ```

#![forbid(unsafe_code)]
#![allow(dead_code)]

mod builder;
mod session;

pub use builder::ClientBuilder;
pub use session::ClientSession;

use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Cx;
use fastmcp_core::{McpError, McpResult};
use fastmcp_protocol::{
    CallToolParams, CallToolResult, CancelledParams, ClientCapabilities, ClientInfo, Content,
    GetPromptParams, GetPromptResult, InitializeParams, InitializeResult, JsonRpcMessage,
    JsonRpcRequest, ListPromptsParams, ListPromptsResult, ListResourceTemplatesParams,
    ListResourceTemplatesResult, ListResourcesParams, ListResourcesResult, ListToolsParams,
    ListToolsResult, PROTOCOL_VERSION, ProgressParams, ProgressToken, Prompt, PromptMessage,
    ReadResourceParams, ReadResourceResult, RequestId, RequestMeta, Resource, ResourceContent,
    ResourceTemplate, ServerCapabilities, ServerInfo, Tool,
};

/// Callback for receiving progress notifications during tool execution.
///
/// The callback receives the progress value, optional total, and optional message.
pub type ProgressCallback<'a> = &'a mut dyn FnMut(f64, Option<f64>, Option<&str>);
use fastmcp_transport::{StdioTransport, Transport, TransportError};

/// An MCP client instance.
///
/// Clients are built using [`ClientBuilder`] and can connect to servers
/// via various transports (stdio subprocess, SSE, WebSocket).
pub struct Client {
    /// The subprocess running the MCP server.
    child: Child,
    /// Transport for communication.
    transport: StdioTransport<ChildStdout, ChildStdin>,
    /// Capability context for cancellation.
    cx: Cx,
    /// Session state after initialization.
    session: ClientSession,
    /// Request ID counter.
    next_id: AtomicU64,
}

impl Client {
    /// Creates a client connecting to a subprocess via stdio.
    ///
    /// # Arguments
    ///
    /// * `command` - The command to run (e.g., "uvx", "npx")
    /// * `args` - Arguments to pass to the command
    ///
    /// # Errors
    ///
    /// Returns an error if the subprocess fails to start or initialization fails.
    pub fn stdio(command: &str, args: &[&str]) -> McpResult<Self> {
        Self::stdio_with_cx(command, args, Cx::for_testing())
    }

    /// Creates a client with a provided Cx for cancellation support.
    pub fn stdio_with_cx(command: &str, args: &[&str], cx: Cx) -> McpResult<Self> {
        // Spawn the subprocess
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| McpError::internal_error(format!("Failed to spawn subprocess: {e}")))?;

        // Get stdin/stdout handles
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| McpError::internal_error("Failed to get subprocess stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| McpError::internal_error("Failed to get subprocess stdout"))?;

        // Create transport
        let transport = StdioTransport::new(stdout, stdin);

        // Create client info
        let client_info = ClientInfo {
            name: "fastmcp-client".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        let client_capabilities = ClientCapabilities::default();

        // Create a temporary client for initialization
        let mut client = Self {
            child,
            transport,
            cx,
            session: ClientSession::new(
                client_info.clone(),
                client_capabilities.clone(),
                ServerInfo {
                    name: String::new(),
                    version: String::new(),
                },
                ServerCapabilities::default(),
                String::new(),
            ),
            next_id: AtomicU64::new(1),
        };

        // Perform initialization handshake
        let init_result = client.initialize(client_info, client_capabilities)?;

        // Update session with server response
        client.session = ClientSession::new(
            client.session.client_info().clone(),
            client.session.client_capabilities().clone(),
            init_result.server_info,
            init_result.capabilities,
            init_result.protocol_version,
        );

        // Send initialized notification
        client.send_notification("initialized", serde_json::json!({}))?;

        Ok(client)
    }

    /// Creates a new client builder.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Creates a client from its component parts.
    ///
    /// This is an internal constructor used by the builder.
    pub(crate) fn from_parts(
        child: Child,
        transport: StdioTransport<ChildStdout, ChildStdin>,
        cx: Cx,
        session: ClientSession,
    ) -> Self {
        Self {
            child,
            transport,
            cx,
            session,
            next_id: AtomicU64::new(2), // Start at 2 since initialize used 1
        }
    }

    /// Returns the server info after initialization.
    #[must_use]
    pub fn server_info(&self) -> &ServerInfo {
        self.session.server_info()
    }

    /// Returns the server capabilities after initialization.
    #[must_use]
    pub fn server_capabilities(&self) -> &ServerCapabilities {
        self.session.server_capabilities()
    }

    /// Generates the next request ID.
    fn next_request_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Sends a request and waits for response.
    fn send_request<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        method: &str,
        params: P,
    ) -> McpResult<R> {
        let id = self.next_request_id();
        let params_value = serde_json::to_value(params)
            .map_err(|e| McpError::internal_error(format!("Failed to serialize params: {e}")))?;

        #[allow(clippy::cast_possible_wrap)]
        let request = JsonRpcRequest::new(method, Some(params_value), id as i64);

        // Send request
        self.transport
            .send(&self.cx, &JsonRpcMessage::Request(request))
            .map_err(transport_error_to_mcp)?;

        // Receive response
        let response = self.recv_response()?;

        // Check for error response
        if let Some(error) = response.error {
            return Err(McpError::new(
                fastmcp_core::McpErrorCode::from(error.code),
                error.message,
            ));
        }

        // Parse result
        let result = response
            .result
            .ok_or_else(|| McpError::internal_error("No result in response"))?;

        serde_json::from_value(result)
            .map_err(|e| McpError::internal_error(format!("Failed to deserialize response: {e}")))
    }

    /// Sends a notification (no response expected).
    fn send_notification<P: serde::Serialize>(&mut self, method: &str, params: P) -> McpResult<()> {
        let params_value = serde_json::to_value(params)
            .map_err(|e| McpError::internal_error(format!("Failed to serialize params: {e}")))?;

        // Create a notification (request without id)
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: Some(params_value),
            id: None,
        };

        self.transport
            .send(&self.cx, &JsonRpcMessage::Request(request))
            .map_err(transport_error_to_mcp)?;

        Ok(())
    }

    /// Sends a cancellation notification for a previously issued request.
    ///
    /// Set `await_cleanup` to request that the server wait for any cleanup
    /// before acknowledging completion (best-effort; server-dependent).
    ///
    /// # Errors
    ///
    /// Returns an error if the notification cannot be sent.
    pub fn cancel_request(
        &mut self,
        request_id: impl Into<RequestId>,
        reason: Option<String>,
        await_cleanup: bool,
    ) -> McpResult<()> {
        let params = CancelledParams {
            request_id: request_id.into(),
            reason,
            await_cleanup: if await_cleanup { Some(true) } else { None },
        };
        self.send_notification("notifications/cancelled", params)
    }

    /// Receives a response from the transport.
    fn recv_response(&mut self) -> McpResult<fastmcp_protocol::JsonRpcResponse> {
        loop {
            let message = self
                .transport
                .recv(&self.cx)
                .map_err(transport_error_to_mcp)?;

            match message {
                JsonRpcMessage::Response(response) => return Ok(response),
                JsonRpcMessage::Request(_) => {
                    // Server sending a request to client (e.g., notification)
                    // For now, ignore these - in a full implementation we'd handle them
                }
            }
        }
    }

    /// Performs the initialization handshake.
    fn initialize(
        &mut self,
        client_info: ClientInfo,
        capabilities: ClientCapabilities,
    ) -> McpResult<InitializeResult> {
        let params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities,
            client_info,
        };

        self.send_request("initialize", params)
    }

    /// Lists available tools.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
        let params = ListToolsParams { cursor: None };
        let result: ListToolsResult = self.send_request("tools/list", params)?;
        Ok(result.tools)
    }

    /// Calls a tool with the given arguments.
    ///
    /// # Errors
    ///
    /// Returns an error if the tool call fails.
    pub fn call_tool(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<Vec<Content>> {
        let params = CallToolParams {
            name: name.to_string(),
            arguments: Some(arguments),
            meta: None,
        };
        let result: CallToolResult = self.send_request("tools/call", params)?;

        if result.is_error {
            // Extract error message from content if available
            let error_msg = result
                .content
                .first()
                .and_then(|c| match c {
                    Content::Text { text } => Some(text.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| "Tool execution failed".to_string());
            return Err(McpError::tool_error(error_msg));
        }

        Ok(result.content)
    }

    /// Calls a tool with progress callback support.
    ///
    /// This method allows you to receive progress notifications during tool execution.
    /// The callback is invoked for each progress notification received from the server.
    ///
    /// # Arguments
    ///
    /// * `name` - The tool name to call
    /// * `arguments` - The tool arguments as JSON
    /// * `on_progress` - Callback invoked for each progress notification
    ///
    /// # Errors
    ///
    /// Returns an error if the tool call fails.
    pub fn call_tool_with_progress(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
        on_progress: ProgressCallback<'_>,
    ) -> McpResult<Vec<Content>> {
        // Generate a unique progress token based on request ID
        #[allow(clippy::cast_possible_wrap)]
        let progress_token = ProgressToken::Number(self.next_request_id() as i64);

        let params = CallToolParams {
            name: name.to_string(),
            arguments: Some(arguments),
            meta: Some(RequestMeta {
                progress_token: Some(progress_token.clone()),
            }),
        };

        let result: CallToolResult =
            self.send_request_with_progress("tools/call", params, &progress_token, on_progress)?;

        if result.is_error {
            // Extract error message from content if available
            let error_msg = result
                .content
                .first()
                .and_then(|c| match c {
                    Content::Text { text } => Some(text.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| "Tool execution failed".to_string());
            return Err(McpError::tool_error(error_msg));
        }

        Ok(result.content)
    }

    /// Sends a request and waits for response, handling progress notifications.
    fn send_request_with_progress<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        method: &str,
        params: P,
        expected_token: &ProgressToken,
        on_progress: ProgressCallback<'_>,
    ) -> McpResult<R> {
        let id = self.next_request_id();
        let params_value = serde_json::to_value(params)
            .map_err(|e| McpError::internal_error(format!("Failed to serialize params: {e}")))?;

        #[allow(clippy::cast_possible_wrap)]
        let request = JsonRpcRequest::new(method, Some(params_value), id as i64);

        // Send request
        self.transport
            .send(&self.cx, &JsonRpcMessage::Request(request))
            .map_err(transport_error_to_mcp)?;

        // Receive response, handling progress notifications
        let response = self.recv_response_with_progress(expected_token, on_progress)?;

        // Check for error response
        if let Some(error) = response.error {
            return Err(McpError::new(
                fastmcp_core::McpErrorCode::from(error.code),
                error.message,
            ));
        }

        // Parse result
        let result = response
            .result
            .ok_or_else(|| McpError::internal_error("No result in response"))?;

        serde_json::from_value(result)
            .map_err(|e| McpError::internal_error(format!("Failed to deserialize response: {e}")))
    }

    /// Receives a response from the transport, handling progress notifications.
    fn recv_response_with_progress(
        &mut self,
        expected_token: &ProgressToken,
        on_progress: ProgressCallback<'_>,
    ) -> McpResult<fastmcp_protocol::JsonRpcResponse> {
        loop {
            let message = self
                .transport
                .recv(&self.cx)
                .map_err(transport_error_to_mcp)?;

            match message {
                JsonRpcMessage::Response(response) => return Ok(response),
                JsonRpcMessage::Request(request) => {
                    // Check if this is a progress notification
                    if request.method == "notifications/progress" {
                        if let Some(params) = request.params {
                            if let Ok(progress) = serde_json::from_value::<ProgressParams>(params) {
                                // Only handle progress for our expected token
                                if progress.progress_token == *expected_token {
                                    on_progress(
                                        progress.progress,
                                        progress.total,
                                        progress.message.as_deref(),
                                    );
                                }
                            }
                        }
                    }
                    // Continue waiting for actual response
                }
            }
        }
    }

    /// Lists available resources.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        let params = ListResourcesParams { cursor: None };
        let result: ListResourcesResult = self.send_request("resources/list", params)?;
        Ok(result.resources)
    }

    /// Lists available resource templates.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
        let params = ListResourceTemplatesParams { cursor: None };
        let result: ListResourceTemplatesResult =
            self.send_request("resources/templates/list", params)?;
        Ok(result.resource_templates)
    }

    /// Reads a resource by URI.
    ///
    /// # Errors
    ///
    /// Returns an error if the resource cannot be read.
    pub fn read_resource(&mut self, uri: &str) -> McpResult<Vec<ResourceContent>> {
        let params = ReadResourceParams {
            uri: uri.to_string(),
            meta: None,
        };
        let result: ReadResourceResult = self.send_request("resources/read", params)?;
        Ok(result.contents)
    }

    /// Lists available prompts.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
        let params = ListPromptsParams { cursor: None };
        let result: ListPromptsResult = self.send_request("prompts/list", params)?;
        Ok(result.prompts)
    }

    /// Gets a prompt with the given arguments.
    ///
    /// # Errors
    ///
    /// Returns an error if the prompt cannot be retrieved.
    pub fn get_prompt(
        &mut self,
        name: &str,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        let params = GetPromptParams {
            name: name.to_string(),
            arguments: if arguments.is_empty() {
                None
            } else {
                Some(arguments)
            },
            meta: None,
        };
        let result: GetPromptResult = self.send_request("prompts/get", params)?;
        Ok(result.messages)
    }

    /// Closes the client connection.
    pub fn close(mut self) {
        // Close the transport
        let _ = self.transport.close();

        // Kill the subprocess if still running
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Converts a TransportError to McpError.
fn transport_error_to_mcp(e: TransportError) -> McpError {
    match e {
        TransportError::Cancelled => McpError::request_cancelled(),
        TransportError::Closed => McpError::internal_error("Transport closed"),
        TransportError::Timeout => McpError::internal_error("Request timed out"),
        TransportError::Io(io_err) => McpError::internal_error(format!("I/O error: {io_err}")),
        TransportError::Codec(codec_err) => {
            McpError::internal_error(format!("Codec error: {codec_err}"))
        }
    }
}
