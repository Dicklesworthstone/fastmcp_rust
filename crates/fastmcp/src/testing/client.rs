//! Test client for in-process MCP testing.
//!
//! Provides a client wrapper that works with MemoryTransport for
//! testing servers without subprocess spawning.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Cx;
use fastmcp_core::{McpError, McpResult};
use fastmcp_protocol::{
    CallToolParams, CallToolResult, ClientCapabilities, ClientInfo, Content, GetPromptParams,
    GetPromptResult, InitializeParams, InitializeResult, JsonRpcMessage, JsonRpcRequest,
    ListPromptsParams, ListPromptsResult, ListResourceTemplatesParams, ListResourceTemplatesResult,
    ListResourcesParams, ListResourcesResult, ListToolsParams, ListToolsResult, PROTOCOL_VERSION,
    Prompt, PromptMessage, ReadResourceParams, ReadResourceResult, RequestId, Resource,
    ResourceContent, ResourceTemplate, ServerCapabilities, ServerInfo, Tool,
};
use fastmcp_transport::memory::MemoryTransport;
use fastmcp_transport::Transport;

/// Test client for in-process MCP testing.
///
/// Unlike the production `Client`, this works with `MemoryTransport` for
/// fast, in-process testing without subprocess spawning.
///
/// # Example
///
/// ```ignore
/// use fastmcp::testing::prelude::*;
///
/// let (router, client_transport, server_transport) = TestServer::builder()
///     .with_tool(my_tool)
///     .build();
///
/// // Run server in background thread
/// std::thread::spawn(move || {
///     // server loop with server_transport
/// });
///
/// // Create test client
/// let mut client = TestClient::new(client_transport);
/// client.initialize().unwrap();
///
/// // Test operations
/// let tools = client.list_tools().unwrap();
/// assert!(!tools.is_empty());
/// ```
pub struct TestClient {
    /// Transport for communication.
    transport: MemoryTransport,
    /// Capability context for cancellation.
    cx: Cx,
    /// Client identification info.
    client_info: ClientInfo,
    /// Client capabilities.
    capabilities: ClientCapabilities,
    /// Server info after initialization.
    server_info: Option<ServerInfo>,
    /// Server capabilities after initialization.
    server_capabilities: Option<ServerCapabilities>,
    /// Protocol version after initialization.
    protocol_version: Option<String>,
    /// Request ID counter.
    next_id: AtomicU64,
    /// Whether client has been initialized.
    initialized: bool,
}

impl TestClient {
    /// Creates a new test client with the given transport.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (client_transport, server_transport) = create_memory_transport_pair();
    /// let client = TestClient::new(client_transport);
    /// ```
    #[must_use]
    pub fn new(transport: MemoryTransport) -> Self {
        Self {
            transport,
            cx: Cx::for_testing(),
            client_info: ClientInfo {
                name: "test-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            capabilities: ClientCapabilities::default(),
            server_info: None,
            server_capabilities: None,
            protocol_version: None,
            next_id: AtomicU64::new(1),
            initialized: false,
        }
    }

    /// Creates a new test client with custom Cx.
    #[must_use]
    pub fn with_cx(transport: MemoryTransport, cx: Cx) -> Self {
        Self {
            transport,
            cx,
            client_info: ClientInfo {
                name: "test-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            capabilities: ClientCapabilities::default(),
            server_info: None,
            server_capabilities: None,
            protocol_version: None,
            next_id: AtomicU64::new(1),
            initialized: false,
        }
    }

    /// Sets the client info for initialization.
    #[must_use]
    pub fn with_client_info(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.client_info = ClientInfo {
            name: name.into(),
            version: version.into(),
        };
        self
    }

    /// Sets the client capabilities for initialization.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: ClientCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Performs the MCP initialization handshake.
    ///
    /// Must be called before any other operations.
    ///
    /// # Errors
    ///
    /// Returns an error if the initialization fails.
    pub fn initialize(&mut self) -> McpResult<InitializeResult> {
        let params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: self.capabilities.clone(),
            client_info: self.client_info.clone(),
        };

        let result: InitializeResult = self.send_request("initialize", params)?;

        // Store server info
        self.server_info = Some(result.server_info.clone());
        self.server_capabilities = Some(result.capabilities.clone());
        self.protocol_version = Some(result.protocol_version.clone());

        // Send initialized notification
        self.send_notification("initialized", serde_json::json!({}))?;

        self.initialized = true;
        Ok(result)
    }

    /// Returns whether the client has been initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the server info after initialization.
    #[must_use]
    pub fn server_info(&self) -> Option<&ServerInfo> {
        self.server_info.as_ref()
    }

    /// Returns the server capabilities after initialization.
    #[must_use]
    pub fn server_capabilities(&self) -> Option<&ServerCapabilities> {
        self.server_capabilities.as_ref()
    }

    /// Returns the protocol version after initialization.
    #[must_use]
    pub fn protocol_version(&self) -> Option<&str> {
        self.protocol_version.as_deref()
    }

    /// Lists available tools.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
        self.ensure_initialized()?;
        let params = ListToolsParams::default();
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
        self.ensure_initialized()?;
        let params = CallToolParams {
            name: name.to_string(),
            arguments: Some(arguments),
            meta: None,
        };
        let result: CallToolResult = self.send_request("tools/call", params)?;

        if result.is_error {
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

    /// Lists available resources.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        self.ensure_initialized()?;
        let params = ListResourcesParams::default();
        let result: ListResourcesResult = self.send_request("resources/list", params)?;
        Ok(result.resources)
    }

    /// Lists available resource templates.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
        self.ensure_initialized()?;
        let params = ListResourceTemplatesParams::default();
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
        let params = ListPromptsParams::default();
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
        arguments: HashMap<String, String>,
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

    /// Sends a raw JSON-RPC request and returns the raw response.
    ///
    /// Useful for testing custom or non-standard methods.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn send_raw_request(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        let id = self.next_request_id();
        #[allow(clippy::cast_possible_wrap)]
        let request = JsonRpcRequest::new(method, Some(params), id as i64);

        self.transport
            .send(&self.cx, &JsonRpcMessage::Request(request))
            .map_err(|e| McpError::internal_error(format!("Transport error: {e:?}")))?;

        #[allow(clippy::cast_possible_wrap)]
        let response = self.recv_response(&RequestId::Number(id as i64))?;

        if let Some(error) = response.error {
            return Err(McpError::new(
                fastmcp_core::McpErrorCode::from(error.code),
                error.message,
            ));
        }

        response
            .result
            .ok_or_else(|| McpError::internal_error("No result in response"))
    }

    /// Closes the client connection.
    pub fn close(mut self) {
        let _ = self.transport.close();
    }

    /// Returns a reference to the transport for advanced testing.
    #[must_use]
    pub fn transport(&self) -> &MemoryTransport {
        &self.transport
    }

    /// Returns a mutable reference to the transport for advanced testing.
    pub fn transport_mut(&mut self) -> &mut MemoryTransport {
        &mut self.transport
    }

    // --- Private helpers ---

    fn ensure_initialized(&self) -> McpResult<()> {
        if !self.initialized {
            return Err(McpError::internal_error(
                "Client not initialized. Call initialize() first.",
            ));
        }
        Ok(())
    }

    fn next_request_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    fn send_request<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        method: &str,
        params: P,
    ) -> McpResult<R> {
        let id = self.next_request_id();
        let params_value = serde_json::to_value(params)
            .map_err(|e| McpError::internal_error(format!("Failed to serialize params: {e}")))?;

        #[allow(clippy::cast_possible_wrap)]
        let request_id = RequestId::Number(id as i64);
        #[allow(clippy::cast_possible_wrap)]
        let request = JsonRpcRequest::new(method, Some(params_value), id as i64);

        self.transport
            .send(&self.cx, &JsonRpcMessage::Request(request))
            .map_err(|e| McpError::internal_error(format!("Transport error: {e:?}")))?;

        let response = self.recv_response(&request_id)?;

        if let Some(error) = response.error {
            return Err(McpError::new(
                fastmcp_core::McpErrorCode::from(error.code),
                error.message,
            ));
        }

        let result = response
            .result
            .ok_or_else(|| McpError::internal_error("No result in response"))?;

        serde_json::from_value(result)
            .map_err(|e| McpError::internal_error(format!("Failed to deserialize response: {e}")))
    }

    fn send_notification<P: serde::Serialize>(&mut self, method: &str, params: P) -> McpResult<()> {
        let params_value = serde_json::to_value(params)
            .map_err(|e| McpError::internal_error(format!("Failed to serialize params: {e}")))?;

        let request = JsonRpcRequest {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            method: method.to_string(),
            params: Some(params_value),
            id: None,
        };

        self.transport
            .send(&self.cx, &JsonRpcMessage::Request(request))
            .map_err(|e| McpError::internal_error(format!("Transport error: {e:?}")))?;

        Ok(())
    }

    fn recv_response(
        &mut self,
        expected_id: &RequestId,
    ) -> McpResult<fastmcp_protocol::JsonRpcResponse> {
        loop {
            let message = self
                .transport
                .recv(&self.cx)
                .map_err(|e| McpError::internal_error(format!("Transport error: {e:?}")))?;

            match message {
                JsonRpcMessage::Response(response) => {
                    if let Some(ref id) = response.id {
                        if id != expected_id {
                            continue;
                        }
                    }
                    return Ok(response);
                }
                JsonRpcMessage::Request(_request) => {
                    // Ignore server-initiated requests for now
                    // (notifications, progress updates, etc.)
                    continue;
                }
            }
        }
    }
}

impl std::fmt::Debug for TestClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestClient")
            .field("client_info", &self.client_info)
            .field("initialized", &self.initialized)
            .field("server_info", &self.server_info)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_transport::memory::create_memory_transport_pair;

    #[test]
    fn test_client_creation() {
        let (client_transport, _server_transport) = create_memory_transport_pair();
        let client = TestClient::new(client_transport);
        assert!(!client.is_initialized());
    }

    #[test]
    fn test_client_with_info() {
        let (client_transport, _server_transport) = create_memory_transport_pair();
        let client = TestClient::new(client_transport).with_client_info("my-client", "2.0.0");
        assert_eq!(client.client_info.name, "my-client");
        assert_eq!(client.client_info.version, "2.0.0");
    }

    #[test]
    fn test_not_initialized_error() {
        let (client_transport, _server_transport) = create_memory_transport_pair();
        let mut client = TestClient::new(client_transport);
        let result = client.list_tools();
        assert!(result.is_err());
    }
}
