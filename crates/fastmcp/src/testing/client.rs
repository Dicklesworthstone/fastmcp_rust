//! Test client for in-process MCP testing.
//!
//! Provides a client wrapper that works with MemoryTransport for
//! testing servers without subprocess spawning.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Cx;
use fastmcp_core::{McpError, McpResult};
use fastmcp_protocol::{
    CallToolParams, CallToolResult, ClientCapabilities, ClientInfo,
    FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION, FINAL_PROTOCOL_VERSION_META_KEY,
    FINAL_SERVER_INFO_META_KEY, GetPromptParams, GetPromptResult, InitializeParams,
    InitializeResult, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, LegacyContent,
    LegacyPromptMessage, LegacyResourceContent, ListPromptsParams, ListPromptsResult,
    ListResourceTemplatesParams, ListResourceTemplatesResult, ListResourcesParams,
    ListResourcesResult, ListToolsParams, ListToolsResult, PROTOCOL_VERSION, Prompt,
    ReadResourceParams, ReadResourceResult, RequestId, Resource, ResourceTemplate,
    ServerCapabilities, ServerInfo, Tool,
};
use fastmcp_transport::Transport;
use fastmcp_transport::memory::MemoryTransport;

/// Protocol era selection for [`TestClient`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TestClientProtocolMode {
    /// Exact MCP `2024-11-05` (`initialize` + `notifications/initialized`).
    ///
    /// Default for [`TestClient::new`] so existing exact-2024 test harnesses
    /// keep their exact wire behavior.
    #[default]
    Legacy2024,
    /// Exact MCP `2026-07-28` (`server/discover` + `_meta` request headers).
    ///
    /// Never downgrades to `2024-11-05`.
    Modern2026,
    /// Modern-first negotiation: probes `server/discover` (`2026-07-28`) and
    /// falls back to exact `2024-11-05` `initialize` only when the peer
    /// replies `MethodNotFound` (`-32601`).
    Auto,
}

/// Test client for in-process MCP testing.
///
/// Unlike the production `Client`, this works with `MemoryTransport` for
/// fast, in-process testing without subprocess spawning. Supports exact
/// MCP `2024-11-05` ([`TestClient::new`]), exact MCP `2026-07-28`
/// ([`TestClient::new_modern`]), and modern-first negotiation
/// ([`TestClient::new_auto`]).
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::prelude::*;
///
/// let (builder, client_transport, server_transport) = TestServer::builder().build();
/// let server = builder.tool(my_tool).build();
/// // Run server in a background thread (omitted here). Prefer using the
/// // higher-level E2E harness helpers in this crate which join threads on drop.
///
/// // Create modern 2026-07-28 test client on the caller's context
/// let mut client = TestClient::new_modern(client_transport, cx.clone());
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
    /// Configured protocol era mode.
    protocol_mode: TestClientProtocolMode,
    /// Negotiated protocol era after initialization.
    negotiated_mode: Option<TestClientProtocolMode>,
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
    /// Creates a test client over `transport` that runs on the caller's `cx`.
    ///
    /// Defaults to [`TestClientProtocolMode::Legacy2024`] for existing exact-2024
    /// harness compatibility; use [`Self::new_modern`] for MCP `2026-07-28` or
    /// [`Self::new_auto`] for modern-first negotiation.
    ///
    /// The caller supplies the context: a library helper that built one would
    /// have to create or enter a runtime of its own (FND-04).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (client_transport, server_transport) = create_memory_transport_pair();
    /// let client = TestClient::new(client_transport, cx.clone());
    /// ```
    #[must_use]
    pub fn new(transport: MemoryTransport, cx: Cx) -> Self {
        Self {
            transport,
            cx,
            protocol_mode: TestClientProtocolMode::Legacy2024,
            negotiated_mode: None,
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

    /// Creates a test client configured strictly for MCP `2026-07-28` (`server/discover`).
    #[must_use]
    pub fn new_modern(transport: MemoryTransport, cx: Cx) -> Self {
        Self::new(transport, cx).with_protocol_mode(TestClientProtocolMode::Modern2026)
    }

    /// Creates a test client using modern-first (`2026-07-28` then `2024-11-05`) negotiation.
    #[must_use]
    pub fn new_auto(transport: MemoryTransport, cx: Cx) -> Self {
        Self::new(transport, cx).with_protocol_mode(TestClientProtocolMode::Auto)
    }

    /// Selects the protocol era mode before initialization.
    #[must_use]
    pub const fn with_protocol_mode(mut self, mode: TestClientProtocolMode) -> Self {
        self.protocol_mode = mode;
        self
    }

    /// Returns the configured protocol era mode.
    #[must_use]
    pub const fn protocol_mode(&self) -> TestClientProtocolMode {
        self.protocol_mode
    }

    /// Returns the negotiated protocol era after initialization (`Legacy2024` or `Modern2026`).
    #[must_use]
    pub const fn negotiated_mode(&self) -> Option<TestClientProtocolMode> {
        self.negotiated_mode
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

    /// Performs the MCP initialization or modern `server/discover` handshake
    /// according to [`Self::protocol_mode`].
    ///
    /// Must be called before any other operations.
    ///
    /// # Errors
    ///
    /// Returns an error if the initialization fails.
    pub fn initialize(&mut self) -> McpResult<InitializeResult> {
        match self.protocol_mode {
            TestClientProtocolMode::Legacy2024 => self.initialize_legacy(),
            TestClientProtocolMode::Modern2026 => self.initialize_modern(),
            TestClientProtocolMode::Auto => match self.initialize_modern() {
                Ok(result) => Ok(result),
                Err(error) if error.code == fastmcp_core::McpErrorCode::MethodNotFound => {
                    self.initialize_legacy()
                }
                Err(error) => Err(error),
            },
        }
    }

    fn initialize_legacy(&mut self) -> McpResult<InitializeResult> {
        let params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: self.capabilities.clone(),
            client_info: self.client_info.clone(),
        };

        let result: InitializeResult =
            self.send_request(fastmcp_protocol::methods::INITIALIZE, params)?;

        // Store server info
        self.server_info = Some(result.server_info.clone());
        self.server_capabilities = Some(result.capabilities.clone());
        self.protocol_version = Some(result.protocol_version.clone());

        // Complete the lifecycle with the exact MCP notification method.
        self.transport
            .send(
                &self.cx,
                &JsonRpcMessage::Request(JsonRpcRequest::initialized_notification()),
            )
            .map_err(|error| McpError::internal_error(format!("Transport error: {error:?}")))?;

        self.negotiated_mode = Some(TestClientProtocolMode::Legacy2024);
        self.initialized = true;
        Ok(result)
    }

    fn initialize_modern(&mut self) -> McpResult<InitializeResult> {
        let params = serde_json::json!({
            "_meta": self.modern_request_meta(),
        });
        let raw = self.send_raw_request(fastmcp_protocol::methods::SERVER_DISCOVER, params)?;
        let server_info: ServerInfo = raw
            .get("_meta")
            .and_then(|meta| meta.get(FINAL_SERVER_INFO_META_KEY))
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| {
                McpError::internal_error(format!(
                    "Failed to deserialize modern serverInfo: {error}"
                ))
            })?
            .ok_or_else(|| {
                McpError::internal_error("Modern server/discover response missing _meta serverInfo")
            })?;
        let capabilities: ServerCapabilities = raw
            .get("capabilities")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| {
                McpError::internal_error(format!(
                    "Failed to deserialize modern capabilities: {error}"
                ))
            })?
            .unwrap_or_default();
        let instructions = raw
            .get("instructions")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let result = InitializeResult {
            protocol_version: FINAL_PROTOCOL_VERSION.to_owned(),
            capabilities: capabilities.clone(),
            server_info: server_info.clone(),
            instructions,
        };
        self.server_info = Some(server_info);
        self.server_capabilities = Some(capabilities);
        self.protocol_version = Some(FINAL_PROTOCOL_VERSION.to_owned());
        self.negotiated_mode = Some(TestClientProtocolMode::Modern2026);
        self.initialized = true;
        Ok(result)
    }

    fn modern_request_meta(&self) -> serde_json::Value {
        let caps =
            serde_json::to_value(&self.capabilities).unwrap_or_else(|_| serde_json::json!({}));
        serde_json::json!({
            FINAL_PROTOCOL_VERSION_META_KEY: FINAL_PROTOCOL_VERSION,
            FINAL_CLIENT_CAPABILITIES_META_KEY: caps,
        })
    }

    const fn is_modern(&self) -> bool {
        matches!(
            self.negotiated_mode,
            Some(TestClientProtocolMode::Modern2026)
        )
    }

    fn send_modern_request(
        &mut self,
        method: &str,
        mut params: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        let meta = self.modern_request_meta();
        if let Some(obj) = params.as_object_mut() {
            match obj
                .get_mut("_meta")
                .and_then(serde_json::Value::as_object_mut)
            {
                Some(existing) => {
                    if let Some(meta_obj) = meta.as_object() {
                        for (k, v) in meta_obj {
                            existing.entry(k.clone()).or_insert_with(|| v.clone());
                        }
                    }
                }
                None => {
                    obj.insert("_meta".to_owned(), meta);
                }
            }
        }
        self.send_raw_request(method, params)
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
        if self.is_modern() {
            let raw = self.send_modern_request("tools/list", serde_json::json!({}))?;
            let tools = raw
                .get("tools")
                .cloned()
                .ok_or_else(|| McpError::internal_error("Modern tools/list missing tools array"))?;
            return serde_json::from_value(tools).map_err(|e| {
                McpError::internal_error(format!("Failed to deserialize modern tools: {e}"))
            });
        }
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
    ) -> McpResult<Vec<LegacyContent>> {
        self.ensure_initialized()?;
        let (content, is_error) = if self.is_modern() {
            let raw = self.send_modern_request(
                "tools/call",
                serde_json::json!({
                    "name": name,
                    "arguments": arguments,
                }),
            )?;
            let is_error = raw
                .get("isError")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let content: Vec<LegacyContent> = raw
                .get("content")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|e| {
                    McpError::internal_error(format!(
                        "Failed to deserialize modern tool content: {e}"
                    ))
                })?
                .unwrap_or_default();
            (content, is_error)
        } else {
            let params = CallToolParams {
                name: name.to_string(),
                arguments: Some(arguments),
                meta: None,
            };
            let result: CallToolResult = self.send_request("tools/call", params)?;
            (result.content, result.is_error)
        };

        if is_error {
            let error_msg = content
                .first()
                .and_then(|c| match c {
                    LegacyContent::Text { text, .. } => Some(text.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| "Tool execution failed".to_string());
            return Err(McpError::tool_error(error_msg));
        }

        Ok(content)
    }

    /// Lists available resources.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        self.ensure_initialized()?;
        if self.is_modern() {
            let raw = self.send_modern_request("resources/list", serde_json::json!({}))?;
            let resources = raw.get("resources").cloned().ok_or_else(|| {
                McpError::internal_error("Modern resources/list missing resources array")
            })?;
            return serde_json::from_value(resources).map_err(|e| {
                McpError::internal_error(format!("Failed to deserialize modern resources: {e}"))
            });
        }
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
        if self.is_modern() {
            let raw =
                self.send_modern_request("resources/templates/list", serde_json::json!({}))?;
            let templates = raw.get("resourceTemplates").cloned().ok_or_else(|| {
                McpError::internal_error(
                    "Modern resources/templates/list missing resourceTemplates array",
                )
            })?;
            return serde_json::from_value(templates).map_err(|e| {
                McpError::internal_error(format!(
                    "Failed to deserialize modern resource templates: {e}"
                ))
            });
        }
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
    pub fn read_resource(&mut self, uri: &str) -> McpResult<Vec<LegacyResourceContent>> {
        self.ensure_initialized()?;
        if self.is_modern() {
            let raw =
                self.send_modern_request("resources/read", serde_json::json!({ "uri": uri }))?;
            let contents = raw.get("contents").cloned().ok_or_else(|| {
                McpError::internal_error("Modern resources/read missing contents array")
            })?;
            return serde_json::from_value(contents).map_err(|e| {
                McpError::internal_error(format!(
                    "Failed to deserialize modern resource contents: {e}"
                ))
            });
        }
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
        if self.is_modern() {
            let raw = self.send_modern_request("prompts/list", serde_json::json!({}))?;
            let prompts = raw.get("prompts").cloned().ok_or_else(|| {
                McpError::internal_error("Modern prompts/list missing prompts array")
            })?;
            return serde_json::from_value(prompts).map_err(|e| {
                McpError::internal_error(format!("Failed to deserialize modern prompts: {e}"))
            });
        }
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
    ) -> McpResult<Vec<LegacyPromptMessage>> {
        self.ensure_initialized()?;
        if self.is_modern() {
            let mut body = serde_json::json!({ "name": name });
            if !arguments.is_empty() {
                body["arguments"] = serde_json::to_value(&arguments).map_err(|e| {
                    McpError::internal_error(format!("Failed to serialize prompt arguments: {e}"))
                })?;
            }
            let raw = self.send_modern_request("prompts/get", body)?;
            let messages = raw.get("messages").cloned().ok_or_else(|| {
                McpError::internal_error("Modern prompts/get missing messages array")
            })?;
            return serde_json::from_value(messages).map_err(|e| {
                McpError::internal_error(format!(
                    "Failed to deserialize modern prompt messages: {e}"
                ))
            });
        }
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
                error
                    .code
                    .as_i32()
                    .map(fastmcp_core::McpErrorCode::from)
                    .unwrap_or(fastmcp_core::McpErrorCode::InternalError),
                error.message,
            ));
        }

        response
            .result
            .ok_or_else(|| McpError::internal_error("No result in response"))
    }

    /// Closes the client connection.
    pub fn close(&mut self) {
        let _ = self.transport.close(&self.cx);
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

    /// Sends a raw JSON-RPC request with already-serialized params.
    ///
    /// This is intended for advanced E2E tests that need to inject protocol fields
    /// not covered by the typed helper methods (for example, auth metadata).
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response contains an error payload.
    pub fn send_request_json(
        &mut self,
        method: &str,
        params_value: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        self.ensure_initialized()?;

        let id = self.next_request_id();
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
                error
                    .code
                    .as_i32()
                    .map(fastmcp_core::McpErrorCode::from)
                    .unwrap_or(fastmcp_core::McpErrorCode::InternalError),
                error.message,
            ));
        }

        response
            .result
            .ok_or_else(|| McpError::internal_error("No result in response"))
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
                error
                    .code
                    .as_i32()
                    .map(fastmcp_core::McpErrorCode::from)
                    .unwrap_or(fastmcp_core::McpErrorCode::InternalError),
                error.message,
            ));
        }

        let result = response
            .result
            .ok_or_else(|| McpError::internal_error("No result in response"))?;

        serde_json::from_value(result)
            .map_err(|e| McpError::internal_error(format!("Failed to deserialize response: {e}")))
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
                JsonRpcMessage::Request(request) => {
                    // Notifications don't require a response.
                    let Some(id) = request.id.clone() else {
                        continue;
                    };

                    // This test client does not implement server-initiated protocols.
                    // To avoid deadlocks (server awaiting a response), respond with MethodNotFound.
                    let err = McpError::method_not_found(&request.method);
                    let response = JsonRpcResponse::error(Some(id), err.into());
                    self.transport
                        .send(&self.cx, &JsonRpcMessage::Response(response))
                        .map_err(|e| McpError::internal_error(format!("Transport error: {e:?}")))?;

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
        let client = TestClient::new(client_transport, Cx::for_testing());
        assert!(!client.is_initialized());
    }

    #[test]
    fn test_client_with_info() {
        let (client_transport, _server_transport) = create_memory_transport_pair();
        let client = TestClient::new(client_transport, Cx::for_testing())
            .with_client_info("my-client", "2.0.0");
        assert_eq!(client.client_info.name, "my-client");
        assert_eq!(client.client_info.version, "2.0.0");
    }

    #[test]
    fn test_not_initialized_error() {
        let (client_transport, _server_transport) = create_memory_transport_pair();
        let mut client = TestClient::new(client_transport, Cx::for_testing());
        let result = client.list_tools();
        assert!(result.is_err());
    }

    /// Constructing inside a running bridge must not enter a second one. The
    /// old constructor fetched its context with `block_on`, which panics as a
    /// nested bridge here.
    #[test]
    fn new_inside_an_active_bridge_runs_on_the_callers_cx() {
        let (ct, _st) = create_memory_transport_pair();
        let (client, caller) = fastmcp_core::block_on(async move {
            let caller = Cx::current().expect("the bridge installs a current cx");
            (TestClient::new(ct, caller.clone()), caller)
        });
        assert!(!client.cx.is_cancel_requested());
        caller.set_cancel_requested(true);
        assert!(
            client.cx.is_cancel_requested(),
            "the client holds the caller's cx itself, so the caller's cancel reaches it"
        );
    }

    #[test]
    fn new_with_an_independent_cx_does_not_share_the_callers_cancel() {
        let (ct, _st) = create_memory_transport_pair();
        let caller = Cx::for_testing();
        let client = TestClient::new(ct, Cx::for_testing());
        caller.set_cancel_requested(true);
        assert!(
            !client.cx.is_cancel_requested(),
            "CONTROL: a different cx is not cancelled by the caller's"
        );
    }

    // =========================================================================
    // Additional coverage tests (bd-8zle)
    // =========================================================================

    #[test]
    fn with_capabilities_sets_capabilities() {
        let (ct, _st) = create_memory_transport_pair();
        let caps = ClientCapabilities {
            sampling: Some(fastmcp_protocol::SamplingCapability::default()),
            ..Default::default()
        };
        let client = TestClient::new(ct, Cx::for_testing()).with_capabilities(caps);
        assert!(client.capabilities.sampling.is_some());
    }

    #[test]
    fn pre_init_getters_return_none() {
        let (ct, _st) = create_memory_transport_pair();
        let client = TestClient::new(ct, Cx::for_testing());
        assert!(client.server_info().is_none());
        assert!(client.server_capabilities().is_none());
        assert!(client.protocol_version().is_none());
    }

    #[test]
    fn debug_output_includes_key_fields() {
        let (ct, _st) = create_memory_transport_pair();
        let client = TestClient::new(ct, Cx::for_testing());
        let debug = format!("{client:?}");
        assert!(debug.contains("TestClient"));
        assert!(debug.contains("test-client"));
        assert!(debug.contains("initialized"));
    }

    #[test]
    fn transport_accessors() {
        let (ct, _st) = create_memory_transport_pair();
        let mut client = TestClient::new(ct, Cx::for_testing());
        // Immutable accessor
        let _ = client.transport();
        // Mutable accessor
        let _ = client.transport_mut();
    }

    #[test]
    fn close_does_not_panic() {
        let (ct, _st) = create_memory_transport_pair();
        let mut client = TestClient::new(ct, Cx::for_testing());
        client.close();
    }

    #[test]
    fn request_id_auto_increments() {
        let (ct, _st) = create_memory_transport_pair();
        let client = TestClient::new(ct, Cx::for_testing());
        let id1 = client.next_request_id();
        let id2 = client.next_request_id();
        let id3 = client.next_request_id();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn ensure_initialized_error_message() {
        let (ct, _st) = create_memory_transport_pair();
        let mut client = TestClient::new(ct, Cx::for_testing());
        let err = client.list_tools().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not initialized"), "error was: {msg}");
    }

    #[test]
    fn initialize_emits_spec_correct_lifecycle_notification() {
        let (client_transport, mut server_transport) = create_memory_transport_pair();
        let server_cx = Cx::for_testing();
        let response = InitializeResult {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            capabilities: ServerCapabilities::default(),
            server_info: ServerInfo {
                name: "test-server".to_owned(),
                version: "1.0.0".to_owned(),
            },
            instructions: None,
        };

        server_transport
            .send(
                &server_cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    RequestId::Number(1),
                    serde_json::to_value(response).expect("serialize initialize response"),
                )),
            )
            .expect("queue initialize response");

        let mut client = TestClient::new(client_transport, Cx::for_testing());
        client.initialize().expect("initialize test client");

        let request = server_transport
            .recv(&server_cx)
            .expect("receive initialize request");
        let request = match request {
            JsonRpcMessage::Request(request) => Some(request),
            JsonRpcMessage::Response(_) => None,
        }
        .expect("expected initialize request");
        assert_eq!(request.method, fastmcp_protocol::methods::INITIALIZE);
        assert_eq!(request.id, Some(RequestId::Number(1)));

        let notification = server_transport
            .recv(&server_cx)
            .expect("receive initialized notification");
        let notification = match notification {
            JsonRpcMessage::Request(notification) => Some(notification),
            JsonRpcMessage::Response(_) => None,
        }
        .expect("expected initialized notification");
        assert_eq!(
            notification.method,
            fastmcp_protocol::methods::NOTIFICATIONS_INITIALIZED
        );
        assert!(notification.id.is_none());
        assert!(notification.params.is_none());
    }

    #[test]
    fn modern_and_auto_test_client_positive_and_planted_negative() {
        use std::thread;

        use fastmcp_core::McpContext;
        use fastmcp_protocol::{Content, PromptMessage, ResourceContent, Role};
        use fastmcp_server::{PromptHandler, ResourceHandler, Server, ToolHandler};
        use serde_json::json;

        struct EchoTool;
        impl ToolHandler for EchoTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "echo".to_owned(),
                    description: Some("Echoes message".to_owned()),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: Vec::new(),
                    annotations: None,
                }
            }

            fn call(
                &self,
                _ctx: &McpContext,
                arguments: serde_json::Value,
            ) -> McpResult<Vec<Content>> {
                let msg = arguments
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                Ok(vec![Content::text(format!("modern:{msg}"))])
            }
        }

        struct InfoResource;
        impl ResourceHandler for InfoResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "test://info".to_owned(),
                    name: "info".to_owned(),
                    description: None,
                    mime_type: Some("text/plain".to_owned()),
                    icon: None,
                    version: None,
                    tags: Vec::new(),
                }
            }

            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![ResourceContent {
                    uri: "test://info".to_owned(),
                    mime_type: Some("text/plain".to_owned()),
                    text: Some("hello-resource".to_owned()),
                    blob: None,
                }])
            }
        }

        struct GreetPrompt;
        impl PromptHandler for GreetPrompt {
            fn definition(&self) -> Prompt {
                Prompt {
                    name: "greet".to_owned(),
                    description: Some("Greets user".to_owned()),
                    arguments: vec![fastmcp_protocol::PromptArgument {
                        name: "who".to_owned(),
                        description: Some("Target name".to_owned()),
                        required: false,
                    }],
                    icon: None,
                    version: None,
                    tags: Vec::new(),
                }
            }

            fn get(
                &self,
                _ctx: &McpContext,
                arguments: HashMap<String, String>,
            ) -> McpResult<Vec<PromptMessage>> {
                let who = arguments.get("who").map_or("world", String::as_str);
                Ok(vec![PromptMessage {
                    role: Role::User,
                    content: Content::text(format!("Hi, {who}")),
                }])
            }
        }

        // Positive 1: Modern2026 against a real FastMCP server over MemoryTransport.
        for mode in [
            TestClientProtocolMode::Modern2026,
            TestClientProtocolMode::Auto,
        ] {
            let (client_transport, server_transport) = create_memory_transport_pair();
            let server = Server::new("modern-test-server", "2.0.0")
                .tool(EchoTool)
                .resource(InfoResource)
                .prompt(GreetPrompt)
                .build();
            let handle = thread::spawn(move || {
                let rt = asupersync::runtime::RuntimeBuilder::current_thread()
                    .build()
                    .expect("test server runtime");
                rt.block_on(async move {
                    let cx = Cx::current().expect("runtime cx");
                    let _ = server.serve_memory(&cx, server_transport).await;
                });
            });

            let mut client =
                TestClient::new(client_transport, Cx::for_testing()).with_protocol_mode(mode);
            let init = client
                .initialize()
                .expect("modern server/discover succeeds");
            assert_eq!(init.protocol_version, FINAL_PROTOCOL_VERSION);
            assert_eq!(init.server_info.name, "modern-test-server");
            assert_eq!(client.protocol_version(), Some(FINAL_PROTOCOL_VERSION));
            assert_eq!(
                client.negotiated_mode(),
                Some(TestClientProtocolMode::Modern2026)
            );

            let tools = client.list_tools().expect("modern tools/list");
            assert_eq!(tools.len(), 1);
            assert_eq!(tools[0].name, "echo");

            let content = client
                .call_tool("echo", json!({"message": "2026"}))
                .expect("modern tools/call");
            assert!(matches!(
                content.first(),
                Some(LegacyContent::Text { text, .. }) if text == "modern:2026"
            ));

            let resources = client.list_resources().expect("modern resources/list");
            assert_eq!(resources.len(), 1);
            let contents = client
                .read_resource("test://info")
                .expect("modern resources/read");
            assert!(matches!(
                contents.first(),
                Some(fastmcp_protocol::LegacyResourceContent::Text { text, .. })
                    if text == "hello-resource"
            ));

            let prompts = client.list_prompts().expect("modern prompts/list");
            assert_eq!(prompts.len(), 1);
            let messages = client
                .get_prompt(
                    "greet",
                    HashMap::from([("who".to_owned(), "mcp".to_owned())]),
                )
                .expect("modern prompts/get");
            assert!(matches!(
                &messages[0].content,
                LegacyContent::Text { text, .. } if text == "Hi, mcp"
            ));

            client.close();
            handle.join().expect("server thread settles");
        }

        // Positive 2: Auto falls back cleanly to exact 2024-11-05 when peer
        // returns MethodNotFound (-32601) for server/discover.
        {
            let (client_transport, mut server_transport) = create_memory_transport_pair();
            let server_cx = Cx::for_testing();
            // Queue MethodNotFound for id=1 (server/discover), then legacy InitializeResult for id=2.
            server_transport
                .send(
                    &server_cx,
                    &JsonRpcMessage::Response(JsonRpcResponse::error(
                        Some(RequestId::Number(1)),
                        McpError::method_not_found(fastmcp_protocol::methods::SERVER_DISCOVER)
                            .into(),
                    )),
                )
                .unwrap();
            let legacy_init = InitializeResult {
                protocol_version: PROTOCOL_VERSION.to_owned(),
                capabilities: ServerCapabilities::default(),
                server_info: ServerInfo {
                    name: "legacy-peer".to_owned(),
                    version: "1.0.0".to_owned(),
                },
                instructions: None,
            };
            server_transport
                .send(
                    &server_cx,
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        RequestId::Number(2),
                        serde_json::to_value(legacy_init).unwrap(),
                    )),
                )
                .unwrap();

            let mut client = TestClient::new_auto(client_transport, Cx::for_testing());
            let init = client.initialize().expect("Auto falls back to 2024-11-05");
            assert_eq!(init.protocol_version, PROTOCOL_VERSION);
            assert_eq!(
                client.negotiated_mode(),
                Some(TestClientProtocolMode::Legacy2024)
            );
        }

        // Near-identical planted negative (RH-5): Modern2026 MUST fail closed
        // on the exact same MethodNotFound response without downgrading or
        // marking initialized.
        {
            let (client_transport, mut server_transport) = create_memory_transport_pair();
            let server_cx = Cx::for_testing();
            server_transport
                .send(
                    &server_cx,
                    &JsonRpcMessage::Response(JsonRpcResponse::error(
                        Some(RequestId::Number(1)),
                        McpError::method_not_found(fastmcp_protocol::methods::SERVER_DISCOVER)
                            .into(),
                    )),
                )
                .unwrap();

            let mut client = TestClient::new_modern(client_transport, Cx::for_testing());
            let err = client
                .initialize()
                .expect_err("Modern2026 must refuse legacy-only peer without silent downgrade");
            assert_eq!(err.code, fastmcp_core::McpErrorCode::MethodNotFound);
            assert!(!client.is_initialized());
            assert!(client.negotiated_mode().is_none());
            assert!(client.protocol_version().is_none());
        }
    }
}
