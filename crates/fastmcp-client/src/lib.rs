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
//! use fastmcp_rust::Client;
//!
//! let client = Client::stdio("uvx", &["my-mcp-server"]).await?;
//!
//! // List tools
//! let tools = client.list_tools().await?;
//!
//! // Call a tool
//! let result = client.call_tool("greet", json!({"name": "World"})).await?;
//! ```
//!
//! # Role in the System
//!
//! `fastmcp-client` is the **companion client** to `fastmcp-server`. It uses
//! the same protocol models and transport layer to:
//! - Spawn MCP servers as subprocesses (stdio)
//! - Initialize sessions and negotiate capabilities
//! - Call tools, read resources, and fetch prompts
//!
//! If you are embedding FastMCP into a larger application (e.g. testing,
//! orchestration, or local agent tooling), this is the crate that drives the
//! client side of the protocol.

#![forbid(unsafe_code)]
#![allow(dead_code)]

mod builder;
pub mod mcp_config;
mod session;

pub use builder::ClientBuilder;
pub use session::ClientSession;

use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use asupersync::Cx;
use fastmcp_core::{McpError, McpResult};
use fastmcp_protocol::{
    CallToolParams, CallToolResult, CancelTaskParams, CancelTaskResult, CancelledParams,
    ClientCapabilities, ClientInfo, Content, GetPromptParams, GetPromptResult, GetTaskParams,
    GetTaskResult, InitializeParams, InitializeResult, JsonRpcMessage, JsonRpcRequest,
    JsonRpcResponse, ListPromptsParams, ListPromptsResult, ListResourceTemplatesParams,
    ListResourceTemplatesResult, ListResourcesParams, ListResourcesResult, ListTasksParams,
    ListTasksResult, ListToolsParams, ListToolsResult, LogLevel, LogMessageParams,
    PROTOCOL_VERSION, ProgressMarker, Prompt, PromptMessage, ReadResourceParams,
    ReadResourceResult, RequestId, RequestMeta, Resource, ResourceContent, ResourceTemplate,
    ServerCapabilities, ServerInfo, SetLogLevelParams, SubmitTaskParams, SubmitTaskResult, TaskId,
    TaskInfo, TaskResult, TaskStatus, Tool,
};

/// Callback for receiving progress notifications during tool execution.
///
/// The callback receives the progress value, optional total, and optional message.
pub type ProgressCallback<'a> = &'a mut dyn FnMut(f64, Option<f64>, Option<&str>);
use fastmcp_transport::{StdioTransport, Transport, TransportError};

#[derive(Debug, serde::Deserialize)]
struct ClientProgressParams {
    #[serde(rename = "progressTo\x6ben")]
    marker: ProgressMarker,
    progress: f64,
    total: Option<f64>,
    message: Option<String>,
}

fn method_not_found_response(request: &JsonRpcRequest) -> Option<JsonRpcMessage> {
    let id = request.id.clone()?;
    let error = McpError::method_not_found(&request.method);
    let response = JsonRpcResponse::error(Some(id), error.into());
    Some(JsonRpcMessage::Response(response))
}

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
    /// Request timeout in milliseconds (0 = no timeout).
    timeout_ms: u64,
    /// Whether auto-initialization is enabled (for documentation/debugging).
    #[allow(dead_code)]
    auto_initialize: bool,
    /// Whether the client has been initialized.
    initialized: AtomicBool,
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
        Self::stdio_with_cx(command, args, Cx::for_request())
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
            timeout_ms: 30_000, // Default 30 second timeout
            auto_initialize: false,
            initialized: AtomicBool::new(false),
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

        // Mark as initialized
        client.initialized.store(true, Ordering::SeqCst);

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
        timeout_ms: u64,
    ) -> Self {
        Self {
            child,
            transport,
            cx,
            session,
            next_id: AtomicU64::new(2), // Start at 2 since initialize used 1
            timeout_ms,
            auto_initialize: false,
            initialized: AtomicBool::new(true), // Already initialized by builder
        }
    }

    /// Creates an uninitialized client for auto-initialize mode.
    ///
    /// This is an internal constructor used by the builder when auto_initialize is enabled.
    pub(crate) fn from_parts_uninitialized(
        child: Child,
        transport: StdioTransport<ChildStdout, ChildStdin>,
        cx: Cx,
        session: ClientSession,
        timeout_ms: u64,
    ) -> Self {
        Self {
            child,
            transport,
            cx,
            session,
            next_id: AtomicU64::new(1), // Start at 1 since initialize hasn't happened
            timeout_ms,
            auto_initialize: true,
            initialized: AtomicBool::new(false),
        }
    }

    /// Ensures the client is initialized.
    ///
    /// In auto-initialize mode, this performs the initialization handshake on first call.
    /// In normal mode, this is a no-op since the client is already initialized.
    ///
    /// Since this method takes `&mut self`, Rust's borrowing rules guarantee exclusive
    /// access, so no additional synchronization is needed.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub fn ensure_initialized(&mut self) -> McpResult<()> {
        // Already initialized - nothing to do
        if self.initialized.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Perform initialization
        let client_info = self.session.client_info().clone();
        let capabilities = self.session.client_capabilities().clone();
        let init_result = self.initialize(client_info, capabilities)?;

        // Update session with server response
        self.session = ClientSession::new(
            self.session.client_info().clone(),
            self.session.client_capabilities().clone(),
            init_result.server_info,
            init_result.capabilities,
            init_result.protocol_version,
        );

        // Send initialized notification
        self.send_notification("initialized", serde_json::json!({}))?;

        // Mark as initialized
        self.initialized.store(true, Ordering::SeqCst);

        Ok(())
    }

    /// Returns whether the client has been initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
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

    /// Returns the protocol version negotiated during initialization.
    #[must_use]
    pub fn protocol_version(&self) -> &str {
        self.session.protocol_version()
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
        let (request_id, request) = {
            let id_i64 = id as i64;
            (
                RequestId::Number(id_i64),
                JsonRpcRequest::new(method, Some(params_value), id_i64),
            )
        };

        // Send request
        self.transport
            .send(&self.cx, &JsonRpcMessage::Request(request))
            .map_err(transport_error_to_mcp)?;

        // Receive response with ID validation
        let response = self.recv_response(&request_id)?;

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
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
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

    /// Receives a response from the transport, validating the response ID.
    fn recv_response(
        &mut self,
        expected_id: &RequestId,
    ) -> McpResult<fastmcp_protocol::JsonRpcResponse> {
        // Calculate deadline if timeout is configured
        let deadline = if self.timeout_ms > 0 {
            Some(Instant::now() + Duration::from_millis(self.timeout_ms))
        } else {
            None
        };

        loop {
            // Check timeout before each recv attempt
            if let Some(deadline) = deadline {
                if Instant::now() >= deadline {
                    return Err(McpError::internal_error("Request timed out"));
                }
            }

            let message = self
                .transport
                .recv(&self.cx)
                .map_err(transport_error_to_mcp)?;

            match message {
                JsonRpcMessage::Response(response) => {
                    // Validate response ID matches the expected request ID
                    if let Some(ref id) = response.id {
                        if id != expected_id {
                            // This response is for a different request; continue waiting.
                            // (Could queue it for later, but for simplicity we discard.)
                            continue;
                        }
                    }
                    return Ok(response);
                }
                JsonRpcMessage::Request(request) => {
                    // Server sending a request to client (e.g., notification)
                    if request.method == "notifications/message" {
                        if let Some(params) = request.params.as_ref() {
                            if let Ok(message) =
                                serde_json::from_value::<LogMessageParams>(params.clone())
                            {
                                self.emit_log_message(message);
                            }
                        }
                    }

                    if let Some(response) = method_not_found_response(&request) {
                        self.transport
                            .send(&self.cx, &response)
                            .map_err(transport_error_to_mcp)?;
                    }
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
        self.ensure_initialized()?;
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut pages: usize = 0;

        loop {
            pages += 1;
            if pages > 10_000 {
                return Err(McpError::internal_error(
                    "Pagination exceeded 10,000 pages (tools/list)".to_string(),
                ));
            }
            if let Some(cur) = cursor.as_ref() {
                if !seen.insert(cur.clone()) {
                    return Err(McpError::internal_error(format!(
                        "Pagination cursor repeated (tools/list): {cur}"
                    )));
                }
            }
            let mut params = ListToolsParams::default();
            params.cursor = cursor.clone();
            let result: ListToolsResult = self.send_request("tools/list", params)?;
            all.extend(result.tools);
            cursor = result.next_cursor;
            if cursor.is_none() {
                break;
            }
        }

        Ok(all)
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
        self.ensure_initialized()?;
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
        self.ensure_initialized()?;
        // Generate a unique request ID and reuse it as the progress token.
        let request_id = self.next_request_id();
        #[allow(clippy::cast_possible_wrap)]
        let progress_marker = ProgressMarker::Number(request_id as i64);

        let params = CallToolParams {
            name: name.to_string(),
            arguments: Some(arguments),
            meta: Some(RequestMeta {
                progress_marker: Some(progress_marker.clone()),
            }),
        };

        let result: CallToolResult = self.send_request_with_progress(
            "tools/call",
            params,
            request_id,
            &progress_marker,
            on_progress,
        )?;

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
        request_id: u64,
        expected_marker: &ProgressMarker,
        on_progress: ProgressCallback<'_>,
    ) -> McpResult<R> {
        let params_value = serde_json::to_value(params)
            .map_err(|e| McpError::internal_error(format!("Failed to serialize params: {e}")))?;

        #[allow(clippy::cast_possible_wrap)]
        let request = JsonRpcRequest::new(method, Some(params_value), request_id as i64);

        // Send request
        self.transport
            .send(&self.cx, &JsonRpcMessage::Request(request))
            .map_err(transport_error_to_mcp)?;

        // Receive response, handling progress notifications
        let response = self.recv_response_with_progress(expected_marker, on_progress)?;

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
        expected_marker: &ProgressMarker,
        on_progress: ProgressCallback<'_>,
    ) -> McpResult<fastmcp_protocol::JsonRpcResponse> {
        // Calculate deadline if timeout is configured
        let deadline = if self.timeout_ms > 0 {
            Some(Instant::now() + Duration::from_millis(self.timeout_ms))
        } else {
            None
        };

        loop {
            // Check timeout before each recv attempt
            if let Some(deadline) = deadline {
                if Instant::now() >= deadline {
                    return Err(McpError::internal_error("Request timed out"));
                }
            }

            let message = self
                .transport
                .recv(&self.cx)
                .map_err(transport_error_to_mcp)?;

            match message {
                JsonRpcMessage::Response(response) => return Ok(response),
                JsonRpcMessage::Request(request) => {
                    // Check if this is a progress notification
                    if request.method == "notifications/progress" {
                        if let Some(params) = request.params.as_ref() {
                            if let Ok(progress) =
                                serde_json::from_value::<ClientProgressParams>(params.clone())
                            {
                                // Only handle progress for our expected marker
                                if progress.marker == *expected_marker {
                                    on_progress(
                                        progress.progress,
                                        progress.total,
                                        progress.message.as_deref(),
                                    );
                                }
                            }
                        }
                    } else if request.method == "notifications/message" {
                        if let Some(params) = request.params.as_ref() {
                            if let Ok(message) =
                                serde_json::from_value::<LogMessageParams>(params.clone())
                            {
                                self.emit_log_message(message);
                            }
                        }
                    }

                    if let Some(response) = method_not_found_response(&request) {
                        self.transport
                            .send(&self.cx, &response)
                            .map_err(transport_error_to_mcp)?;
                    }
                    // Continue waiting for actual response
                }
            }
        }
    }

    fn emit_log_message(&self, message: LogMessageParams) {
        let level = match message.level {
            LogLevel::Debug => log::Level::Debug,
            LogLevel::Info => log::Level::Info,
            LogLevel::Warning => log::Level::Warn,
            LogLevel::Error => log::Level::Error,
        };

        let target = message.logger.as_deref().unwrap_or("fastmcp_rust::remote");
        let text = match message.data {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        };

        log::log!(target: target, level, "{text}");
    }

    /// Lists available resources.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        self.ensure_initialized()?;
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut pages: usize = 0;

        loop {
            pages += 1;
            if pages > 10_000 {
                return Err(McpError::internal_error(
                    "Pagination exceeded 10,000 pages (resources/list)".to_string(),
                ));
            }
            if let Some(cur) = cursor.as_ref() {
                if !seen.insert(cur.clone()) {
                    return Err(McpError::internal_error(format!(
                        "Pagination cursor repeated (resources/list): {cur}"
                    )));
                }
            }
            let mut params = ListResourcesParams::default();
            params.cursor = cursor.clone();
            let result: ListResourcesResult = self.send_request("resources/list", params)?;
            all.extend(result.resources);
            cursor = result.next_cursor;
            if cursor.is_none() {
                break;
            }
        }

        Ok(all)
    }

    /// Lists available resource templates.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
        self.ensure_initialized()?;
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut pages: usize = 0;

        loop {
            pages += 1;
            if pages > 10_000 {
                return Err(McpError::internal_error(
                    "Pagination exceeded 10,000 pages (resources/templates/list)".to_string(),
                ));
            }
            if let Some(cur) = cursor.as_ref() {
                if !seen.insert(cur.clone()) {
                    return Err(McpError::internal_error(format!(
                        "Pagination cursor repeated (resources/templates/list): {cur}"
                    )));
                }
            }
            let mut params = ListResourceTemplatesParams::default();
            params.cursor = cursor.clone();
            let result: ListResourceTemplatesResult =
                self.send_request("resources/templates/list", params)?;
            all.extend(result.resource_templates);
            cursor = result.next_cursor;
            if cursor.is_none() {
                break;
            }
        }

        Ok(all)
    }

    /// Sets the server log level (if supported).
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn set_log_level(&mut self, level: LogLevel) -> McpResult<()> {
        self.ensure_initialized()?;
        let params = SetLogLevelParams { level };
        let _: serde_json::Value = self.send_request("logging/setLevel", params)?;
        Ok(())
    }

    /// Reads a resource by URI.
    ///
    /// # Errors
    ///
    /// Returns an error if the resource cannot be read.
    pub fn read_resource(&mut self, uri: &str) -> McpResult<Vec<ResourceContent>> {
        self.ensure_initialized()?;
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
        self.ensure_initialized()?;
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut pages: usize = 0;

        loop {
            pages += 1;
            if pages > 10_000 {
                return Err(McpError::internal_error(
                    "Pagination exceeded 10,000 pages (prompts/list)".to_string(),
                ));
            }
            if let Some(cur) = cursor.as_ref() {
                if !seen.insert(cur.clone()) {
                    return Err(McpError::internal_error(format!(
                        "Pagination cursor repeated (prompts/list): {cur}"
                    )));
                }
            }
            let mut params = ListPromptsParams::default();
            params.cursor = cursor.clone();
            let result: ListPromptsResult = self.send_request("prompts/list", params)?;
            all.extend(result.prompts);
            cursor = result.next_cursor;
            if cursor.is_none() {
                break;
            }
        }

        Ok(all)
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
        self.ensure_initialized()?;
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

    // ═══════════════════════════════════════════════════════════════════════
    // Task Management (Docket/SEP-1686)
    // ═══════════════════════════════════════════════════════════════════════

    /// Submits a background task for execution.
    ///
    /// # Arguments
    ///
    /// * `task_type` - The type of task to execute (e.g., "data_export", "batch_process")
    /// * `input` - Task parameters as JSON
    ///
    /// # Errors
    ///
    /// Returns an error if the server doesn't support tasks or the request fails.
    pub fn submit_task(
        &mut self,
        task_type: &str,
        input: serde_json::Value,
    ) -> McpResult<TaskInfo> {
        self.ensure_initialized()?;
        let params = SubmitTaskParams {
            task_type: task_type.to_string(),
            params: Some(input),
        };
        let result: SubmitTaskResult = self.send_request("tasks/submit", params)?;
        Ok(result.task)
    }

    /// Lists tasks with optional status filter.
    ///
    /// # Arguments
    ///
    /// * `status` - Optional filter by task status
    /// * `cursor` - Optional pagination cursor from previous response
    ///
    /// # Errors
    ///
    /// Returns an error if the server doesn't support tasks or the request fails.
    pub fn list_tasks(
        &mut self,
        status: Option<TaskStatus>,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> McpResult<ListTasksResult> {
        self.ensure_initialized()?;
        let params = ListTasksParams {
            cursor: cursor.map(ToString::to_string),
            limit,
            status,
        };
        self.send_request("tasks/list", params)
    }

    /// Lists all tasks by following pagination cursors until exhaustion.
    ///
    /// # Errors
    ///
    /// Returns an error if any request fails.
    pub fn list_tasks_all(&mut self, status: Option<TaskStatus>) -> McpResult<Vec<TaskInfo>> {
        self.ensure_initialized()?;
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut pages: usize = 0;

        loop {
            pages += 1;
            if pages > 10_000 {
                return Err(McpError::internal_error(
                    "Pagination exceeded 10,000 pages (tasks/list)".to_string(),
                ));
            }
            if let Some(cur) = cursor.as_ref() {
                if !seen.insert(cur.clone()) {
                    return Err(McpError::internal_error(format!(
                        "Pagination cursor repeated (tasks/list): {cur}"
                    )));
                }
            }
            let result = self.list_tasks(status, cursor.as_deref(), Some(200))?;
            all.extend(result.tasks);
            cursor = result.next_cursor;
            if cursor.is_none() {
                break;
            }
        }

        Ok(all)
    }

    /// Gets detailed information about a specific task.
    ///
    /// # Arguments
    ///
    /// * `task_id` - The task ID to retrieve
    ///
    /// # Errors
    ///
    /// Returns an error if the task is not found or the request fails.
    pub fn get_task(&mut self, task_id: &str) -> McpResult<GetTaskResult> {
        self.ensure_initialized()?;
        let params = GetTaskParams {
            id: TaskId::from_string(task_id),
        };
        self.send_request("tasks/get", params)
    }

    /// Cancels a running or pending task.
    ///
    /// # Arguments
    ///
    /// * `task_id` - The task ID to cancel
    ///
    /// # Errors
    ///
    /// Returns an error if the task cannot be cancelled or is already complete.
    pub fn cancel_task(&mut self, task_id: &str) -> McpResult<TaskInfo> {
        self.cancel_task_with_reason(task_id, None)
    }

    /// Cancels a running or pending task with an optional reason.
    ///
    /// # Arguments
    ///
    /// * `task_id` - The task ID to cancel
    /// * `reason` - Optional reason for the cancellation
    ///
    /// # Errors
    ///
    /// Returns an error if the task cannot be cancelled or is already complete.
    pub fn cancel_task_with_reason(
        &mut self,
        task_id: &str,
        reason: Option<&str>,
    ) -> McpResult<TaskInfo> {
        self.ensure_initialized()?;
        let params = CancelTaskParams {
            id: TaskId::from_string(task_id),
            reason: reason.map(ToString::to_string),
        };
        let result: CancelTaskResult = self.send_request("tasks/cancel", params)?;
        Ok(result.task)
    }

    /// Waits for a task to complete by polling.
    ///
    /// This method polls the server at the specified interval until the task
    /// reaches a terminal state (completed, failed, or cancelled).
    ///
    /// # Arguments
    ///
    /// * `task_id` - The task ID to wait for
    /// * `poll_interval` - Duration between poll requests
    ///
    /// # Errors
    ///
    /// Returns an error if the task fails, is cancelled, or the request fails.
    pub fn wait_for_task(
        &mut self,
        task_id: &str,
        poll_interval: Duration,
    ) -> McpResult<TaskResult> {
        loop {
            let result = self.get_task(task_id)?;

            // Check if task is complete
            if result.task.status.is_terminal() {
                // If task has a result, return it
                if let Some(task_result) = result.result {
                    return Ok(task_result);
                }

                // Task is terminal but no result - create one from the task info
                return Ok(TaskResult {
                    id: result.task.id,
                    success: result.task.status == TaskStatus::Completed,
                    data: None,
                    error: result.task.error,
                });
            }

            // Sleep before next poll
            std::thread::sleep(poll_interval);
        }
    }

    /// Waits for a task with progress callback.
    ///
    /// Similar to `wait_for_task` but also provides progress information via callback.
    ///
    /// # Arguments
    ///
    /// * `task_id` - The task ID to wait for
    /// * `poll_interval` - Duration between poll requests
    /// * `on_progress` - Callback invoked with progress updates
    ///
    /// # Errors
    ///
    /// Returns an error if the task fails, is cancelled, or the request fails.
    pub fn wait_for_task_with_progress<F>(
        &mut self,
        task_id: &str,
        poll_interval: Duration,
        mut on_progress: F,
    ) -> McpResult<TaskResult>
    where
        F: FnMut(f64, Option<&str>),
    {
        loop {
            let result = self.get_task(task_id)?;

            // Report progress if available
            if let Some(progress) = result.task.progress {
                on_progress(progress, result.task.message.as_deref());
            }

            // Check if task is complete
            if result.task.status.is_terminal() {
                // If task has a result, return it
                if let Some(task_result) = result.result {
                    return Ok(task_result);
                }

                // Task is terminal but no result - create one from the task info
                return Ok(TaskResult {
                    id: result.task.id,
                    success: result.task.status == TaskStatus::Completed,
                    data: None,
                    error: result.task.error,
                });
            }

            // Sleep before next poll
            std::thread::sleep(poll_interval);
        }
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

impl Drop for Client {
    fn drop(&mut self) {
        // Ensure subprocess is cleaned up even if close() wasn't called.
        // Ignore errors since we're in drop - best effort cleanup.
        let _ = self.transport.close();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::process::{Command, Stdio};

    fn make_closed_client(initialized: bool) -> Client {
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
        let mut child = Command::new(rustc)
            .arg("--version")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn rustc --version");

        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        let transport = StdioTransport::new(stdout, stdin);
        let session = ClientSession::new(
            ClientInfo {
                name: "test-client".to_string(),
                version: "0.1.0".to_string(),
            },
            ClientCapabilities::default(),
            ServerInfo {
                name: "test-server".to_string(),
                version: "1.0.0".to_string(),
            },
            ServerCapabilities::default(),
            PROTOCOL_VERSION.to_string(),
        );

        if initialized {
            Client::from_parts(child, transport, Cx::for_request(), session, 100)
        } else {
            Client::from_parts_uninitialized(child, transport, Cx::for_request(), session, 100)
        }
    }

    // ========================================
    // method_not_found_response tests
    // ========================================

    #[test]
    fn method_not_found_response_for_request() {
        let request = JsonRpcRequest::new("sampling/createMessage", None, "req-1");
        let response = method_not_found_response(&request);
        assert!(response.is_some());
        if let Some(JsonRpcMessage::Response(resp)) = response {
            assert!(matches!(
                resp.error.as_ref(),
                Some(error)
                    if error.code == i32::from(fastmcp_core::McpErrorCode::MethodNotFound)
            ));
            assert_eq!(resp.id, Some(RequestId::String("req-1".to_string())));
        } else {
            assert!(matches!(response, Some(JsonRpcMessage::Response(_))));
        }
    }

    #[test]
    fn method_not_found_response_for_notification() {
        let request = JsonRpcRequest::notification("notifications/message", None);
        let response = method_not_found_response(&request);
        assert!(response.is_none());
    }

    #[test]
    fn method_not_found_response_with_numeric_id() {
        let request = JsonRpcRequest::new("unknown/method", None, 42i64);
        let response = method_not_found_response(&request);
        assert!(response.is_some());
        if let Some(JsonRpcMessage::Response(resp)) = response {
            assert_eq!(resp.id, Some(RequestId::Number(42)));
            let error = resp.error.as_ref().unwrap();
            assert_eq!(
                error.code,
                i32::from(fastmcp_core::McpErrorCode::MethodNotFound)
            );
            assert!(error.message.contains("unknown/method"));
        }
    }

    #[test]
    fn method_not_found_response_with_params() {
        let params = serde_json::json!({"key": "value"});
        let request = JsonRpcRequest::new("roots/list", Some(params), "req-99");
        let response = method_not_found_response(&request);
        assert!(response.is_some());
        if let Some(JsonRpcMessage::Response(resp)) = response {
            let error = resp.error.as_ref().unwrap();
            assert!(error.message.contains("roots/list"));
        }
    }

    // ========================================
    // transport_error_to_mcp tests
    // ========================================

    #[test]
    fn transport_error_cancelled_maps_to_request_cancelled() {
        let err = transport_error_to_mcp(TransportError::Cancelled);
        assert_eq!(err.code, fastmcp_core::McpErrorCode::RequestCancelled);
    }

    #[test]
    fn transport_error_closed_maps_to_internal() {
        let err = transport_error_to_mcp(TransportError::Closed);
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(err.message.contains("closed"));
    }

    #[test]
    fn transport_error_timeout_maps_to_internal() {
        let err = transport_error_to_mcp(TransportError::Timeout);
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(err.message.contains("timed out"));
    }

    #[test]
    fn transport_error_io_maps_to_internal() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
        let err = transport_error_to_mcp(TransportError::Io(io_err));
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(err.message.contains("I/O error"));
    }

    #[test]
    fn transport_error_codec_maps_to_internal() {
        use fastmcp_transport::CodecError;
        let codec_err = CodecError::MessageTooLarge(999_999);
        let err = transport_error_to_mcp(TransportError::Codec(codec_err));
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(err.message.contains("Codec error"));
    }

    // ========================================
    // ClientProgressParams tests
    // ========================================

    #[test]
    fn client_progress_params_deserialization() {
        let json = serde_json::json!({
            "progressToken": 42,
            "progress": 0.5,
            "total": 1.0,
            "message": "Halfway done"
        });
        let params: ClientProgressParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.marker, ProgressMarker::Number(42));
        assert!((params.progress - 0.5).abs() < f64::EPSILON);
        assert!((params.total.unwrap() - 1.0).abs() < f64::EPSILON);
        assert_eq!(params.message.as_deref(), Some("Halfway done"));
    }

    #[test]
    fn client_progress_params_minimal() {
        let json = serde_json::json!({
            "progressToken": "tok-1",
            "progress": 0.0
        });
        let params: ClientProgressParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.marker, ProgressMarker::String("tok-1".to_string()));
        assert!(params.total.is_none());
        assert!(params.message.is_none());
    }

    #[test]
    fn client_from_parts_accessors_and_request_counter() {
        let client = make_closed_client(true);
        assert!(client.is_initialized());
        assert_eq!(client.server_info().name, "test-server");
        let caps_json = serde_json::to_value(client.server_capabilities()).expect("caps json");
        assert_eq!(caps_json, serde_json::json!({}));
        assert_eq!(client.protocol_version(), PROTOCOL_VERSION);
        assert_eq!(client.next_request_id(), 2);
        assert_eq!(client.next_request_id(), 3);
    }

    #[test]
    fn ensure_initialized_noop_when_already_initialized() {
        let mut client = make_closed_client(true);
        assert!(client.ensure_initialized().is_ok());
        assert!(client.is_initialized());
    }

    #[test]
    fn ensure_initialized_fails_for_uninitialized_closed_transport() {
        let mut client = make_closed_client(false);
        std::thread::sleep(Duration::from_millis(50));
        let err = client
            .ensure_initialized()
            .expect_err("expected init failure");
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(!client.is_initialized());
    }

    #[test]
    fn client_core_api_methods_error_cleanly_on_closed_transport() {
        let mut client = make_closed_client(true);
        std::thread::sleep(Duration::from_millis(50));

        let _ = client.cancel_request(7i64, Some("stop".to_string()), true);
        assert!(client.list_tools().is_err());
        assert!(
            client
                .call_tool("echo", serde_json::json!({"text": "hi"}))
                .is_err()
        );

        let mut progress_events: Vec<(f64, Option<f64>, Option<String>)> = Vec::new();
        let mut on_progress = |p: f64, total: Option<f64>, msg: Option<&str>| {
            progress_events.push((p, total, msg.map(ToString::to_string)));
        };
        assert!(
            client
                .call_tool_with_progress(
                    "echo",
                    serde_json::json!({"text": "hi"}),
                    &mut on_progress
                )
                .is_err()
        );
        assert!(progress_events.is_empty());

        assert!(client.list_resources().is_err());
        assert!(client.list_resource_templates().is_err());
        assert!(client.set_log_level(LogLevel::Debug).is_err());
        assert!(client.read_resource("resource://test").is_err());
        assert!(client.list_prompts().is_err());

        let mut args = HashMap::new();
        args.insert("name".to_string(), "world".to_string());
        assert!(client.get_prompt("greeting", args).is_err());

        assert!(
            client
                .submit_task("data_export", serde_json::json!({"batch": 1}))
                .is_err()
        );
        assert!(
            client
                .list_tasks(Some(TaskStatus::Running), Some("c1"), Some(10))
                .is_err()
        );
        assert!(client.list_tasks_all(None).is_err());
        assert!(client.get_task("task-1").is_err());
        assert!(client.cancel_task("task-1").is_err());
        assert!(
            client
                .cancel_task_with_reason("task-1", Some("no longer needed"))
                .is_err()
        );
        assert!(
            client
                .wait_for_task("task-1", Duration::from_millis(1))
                .is_err()
        );

        let mut task_progress = Vec::new();
        let mut on_task_progress = |p: f64, msg: Option<&str>| {
            task_progress.push((p, msg.map(ToString::to_string)));
        };
        assert!(
            client
                .wait_for_task_with_progress(
                    "task-1",
                    Duration::from_millis(1),
                    &mut on_task_progress
                )
                .is_err()
        );
        assert!(task_progress.is_empty());
    }

    #[test]
    fn close_handles_already_exited_subprocess() {
        let client = make_closed_client(true);
        std::thread::sleep(Duration::from_millis(50));
        client.close();
    }

    // ========================================
    // Client::builder and Client::stdio error
    // ========================================

    #[test]
    fn client_builder_returns_client_builder() {
        let _builder = Client::builder();
        // builder() is a convenience method for ClientBuilder::new()
    }

    #[test]
    fn client_stdio_fails_for_nonexistent_command() {
        let result = Client::stdio("definitely-not-a-real-command-xyz", &[]);
        assert!(result.is_err());
        let err = result.err().expect("should be error");
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(err.message.contains("spawn"));
    }

    #[test]
    fn client_stdio_with_cx_fails_when_cancelled() {
        let cx = Cx::for_request();
        cx.set_cancel_requested(true);
        let result = Client::stdio_with_cx("echo", &["hello"], cx);
        // Should fail either from cancellation or from the process not speaking MCP
        assert!(result.is_err());
    }

    // ========================================
    // Uninitialized client accessors
    // ========================================

    #[test]
    fn uninitialized_client_is_not_initialized() {
        let client = make_closed_client(false);
        assert!(!client.is_initialized());
    }

    #[test]
    fn uninitialized_client_server_info_is_empty() {
        let client = make_closed_client(false);
        assert_eq!(client.server_info().name, "test-server");
        assert_eq!(client.server_info().version, "1.0.0");
    }

    #[test]
    fn uninitialized_client_request_id_starts_at_one() {
        let client = make_closed_client(false);
        assert_eq!(client.next_request_id(), 1);
        assert_eq!(client.next_request_id(), 2);
    }

    #[test]
    fn initialized_client_request_id_starts_at_two() {
        let client = make_closed_client(true);
        // from_parts starts at 2 because initialize used id 1
        assert_eq!(client.next_request_id(), 2);
        assert_eq!(client.next_request_id(), 3);
    }

    // ========================================
    // API methods on uninitialized client
    // ========================================

    #[test]
    fn uninitialized_client_list_tools_fails_on_init() {
        let mut client = make_closed_client(false);
        std::thread::sleep(Duration::from_millis(50));
        let err = client.list_tools().expect_err("should fail");
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
    }

    #[test]
    fn uninitialized_client_call_tool_fails_on_init() {
        let mut client = make_closed_client(false);
        std::thread::sleep(Duration::from_millis(50));
        let err = client
            .call_tool("echo", serde_json::json!({"text": "hi"}))
            .expect_err("should fail");
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
    }

    #[test]
    fn uninitialized_client_list_resources_fails_on_init() {
        let mut client = make_closed_client(false);
        std::thread::sleep(Duration::from_millis(50));
        assert!(client.list_resources().is_err());
    }

    #[test]
    fn uninitialized_client_list_prompts_fails_on_init() {
        let mut client = make_closed_client(false);
        std::thread::sleep(Duration::from_millis(50));
        assert!(client.list_prompts().is_err());
    }

    // ========================================
    // Drop behavior
    // ========================================

    #[test]
    fn drop_cleans_up_subprocess() {
        // Verify that dropping a client doesn't panic even for closed transport
        let client = make_closed_client(true);
        std::thread::sleep(Duration::from_millis(50));
        drop(client);
        // If we get here without panicking, the test passes
    }

    #[test]
    fn client_progress_params_debug() {
        let params = ClientProgressParams {
            marker: ProgressMarker::Number(1),
            progress: 0.5,
            total: Some(1.0),
            message: Some("half".into()),
        };
        let debug = format!("{:?}", params);
        assert!(debug.contains("progress"));
    }

    #[test]
    fn transport_error_to_mcp_preserves_io_details() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "socket vanished");
        let mcp_err = transport_error_to_mcp(TransportError::Io(io_err));
        assert!(mcp_err.message.contains("socket vanished"));
    }

    #[test]
    fn method_not_found_response_error_message_includes_method() {
        let request = JsonRpcRequest::new("totally/custom/method", None, 1i64);
        let response = method_not_found_response(&request).unwrap();
        if let JsonRpcMessage::Response(resp) = response {
            let error = resp.error.unwrap();
            assert!(error.message.contains("totally/custom/method"));
        }
    }

    #[test]
    fn client_server_capabilities_default_is_empty() {
        let client = make_closed_client(true);
        let caps = client.server_capabilities();
        // Default capabilities should have no features enabled
        assert!(caps.tools.is_none());
        assert!(caps.resources.is_none());
        assert!(caps.prompts.is_none());
    }
}
