//! Test client for in-process MCP testing.
//!
//! Provides a client wrapper that works with MemoryTransport for
//! testing servers without subprocess spawning.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Cx;
use fastmcp_client::{MemoryClient, MemoryClientBuilder};
use fastmcp_core::{McpError, McpErrorCode, McpResult};
use fastmcp_protocol::{
    CallToolParams, CallToolResult, ClientCapabilities, ClientInfo, CoreRequest, CoreResult,
    FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_CLIENT_INFO_META_KEY, FINAL_PROTOCOL_VERSION,
    FINAL_PROTOCOL_VERSION_META_KEY, FinalCoreResult, GetPromptParams, GetPromptResult,
    InitializeParams, InitializeResult, JsonRpcError, JsonRpcMessage, JsonRpcRequest,
    JsonRpcResponse, LegacyContent, LegacyCoreResult,
    LegacyPromptMessage, LegacyResourceContent, ListPromptsParams, ListPromptsResult,
    ListResourceTemplatesParams, ListResourceTemplatesResult, ListResourcesParams,
    ListResourcesResult, ListToolsParams, ListToolsResult, PROTOCOL_VERSION, Prompt,
    ReadResourceParams, ReadResourceResult, RequestId, Resource, ResourceTemplate,
    ServerCapabilities, ServerDiscoverResult, ServerInfo, Tool,
};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_transport::{Transport, TransportError};
use fastmcp_transport::memory::MemoryTransport;

const MAX_INTERLEAVED_MESSAGES: usize = 128;

type LegacyTransportFactory = Box<dyn FnOnce(&Cx) -> McpResult<MemoryTransport> + Send>;

enum ModernProbe {
    Discovered(Box<ServerDiscoverResult>),
    LegacyCandidate(JsonRpcError),
}

struct TestClientResponse {
    response: JsonRpcResponse,
    result_source: Option<Box<serde_json::value::RawValue>>,
}

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
    /// replies with a correlated `MethodNotFound` (`-32601`) and a fresh
    /// endpoint factory was installed with [`TestClient::with_legacy_transport_factory`].
    Auto,
}

/// Test client for in-process MCP testing.
///
/// Synchronous convenience helpers over `MemoryTransport` for in-process
/// testing without subprocess spawning. Supports exact
/// MCP `2024-11-05` ([`TestClient::new`]), exact MCP `2026-07-28`
/// ([`TestClient::new_modern`]), and modern-first negotiation
/// ([`TestClient::new_auto`]).
///
/// [`Self::initialize_core`] and [`Self::request_core`] retain the complete typed
/// protocol result, including modern input requests, metadata, and open members.
/// For concurrent requests, subscriptions, Tasks, or reverse RPC, consume an
/// unused helper with [`Self::connect_modern_with`] to obtain the production
/// asynchronous [`MemoryClient`] on the same caller-owned context and endpoint.
/// Synchronous operations require the peer to be driven independently; they
/// must not block the executor thread that is also serving that peer.
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
    /// Complete modern discovery retained without a legacy-shaped projection.
    server_discovery: Option<ServerDiscoverResult>,
    /// Metadata frozen by the discovery attempt, never changed by later setters.
    modern_meta: Option<serde_json::Value>,
    /// A disposable probe cannot be reused for the exact-2024 lifecycle.
    legacy_transport_factory: Option<LegacyTransportFactory>,
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
            server_discovery: None,
            modern_meta: None,
            legacy_transport_factory: None,
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

    /// Supplies the fresh endpoint used by one eligible Auto fallback.
    ///
    /// The probed endpoint is closed before this factory runs. It receives the
    /// caller's context and must return an independently driven, fresh endpoint.
    /// Malformed replies, wrong IDs, unsupported modern versions, cancellation,
    /// and transport failures never invoke it. Without a factory, a legacy-only
    /// peer's error is returned and the probe endpoint is retired.
    #[must_use]
    pub fn with_legacy_transport_factory<F>(mut self, factory: F) -> Self
    where
        F: FnOnce(&Cx) -> McpResult<MemoryTransport> + Send + 'static,
    {
        self.legacy_transport_factory = Some(Box::new(factory));
        self
    }

    /// Consumes an unused helper and performs production modern discovery.
    ///
    /// No runtime, task, thread, or transport is created. The returned client
    /// exposes the production request executor and its cancellation, exact
    /// results, subscription, and terminal-state behavior. This explicitly
    /// selects modern-only operation regardless of the synchronous mode.
    pub async fn connect_modern(self) -> McpResult<MemoryClient> {
        self.connect_modern_with(Ok).await
    }

    /// Configures the production client before transferring this unused endpoint.
    ///
    /// The callback can install reverse request handlers, finite timeout policy,
    /// or explicitly selected Tasks/extension settings on the real builder.
    /// Discovery and all subsequent I/O run only when the caller polls them.
    pub async fn connect_modern_with<F>(self, configure: F) -> McpResult<MemoryClient>
    where
        F: FnOnce(MemoryClientBuilder) -> McpResult<MemoryClientBuilder>,
    {
        if self.initialized || self.transport.is_closed() || self.next_id.load(Ordering::SeqCst) != 1 {
            return Err(McpError::invalid_request(
                "Production Memory handoff requires an unused, open TestClient",
            ));
        }
        let builder = configure(
            MemoryClientBuilder::new(self.client_info).capabilities(self.capabilities),
        )?;
        builder.connect(&self.cx, self.transport).await
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
    /// Returns an error if initialization fails or a modern peer omits the
    /// identity required by this legacy-shaped return type. Use
    /// [`Self::initialize_core`] when the complete modern discovery is needed.
    pub fn initialize(&mut self) -> McpResult<InitializeResult> {
        match self.initialize_core()? {
            CoreResult::Legacy(LegacyCoreResult::Initialize(result)) => Ok(result),
            CoreResult::Final(FinalCoreResult::Discover(discovery)) => {
                let Some(server_info) = discovery.server_info().cloned() else {
                    self.close();
                    return Err(McpError::invalid_request(
                        "Modern discovery has no serverInfo; use initialize_core to retain its optional identity",
                    ));
                };
                Ok(InitializeResult {
                    protocol_version: FINAL_PROTOCOL_VERSION.to_owned(),
                    capabilities: self.server_capabilities.clone().unwrap_or_default(),
                    server_info,
                    instructions: discovery.instructions().map(|value| value.as_str().to_owned()),
                })
            }
            _ => unreachable!("initialization only admits its selected discovery result"),
        }
    }

    /// Negotiates once and returns the complete era-specific discovery result.
    ///
    /// Modern results use the same source-preserving core admission as the
    /// production client, including supported-version checks. A modern peer may
    /// omit its optional identity; it is never replaced by an invented identity.
    /// Any failed attempt retires its endpoint and cannot be retried in place.
    pub fn initialize_core(&mut self) -> McpResult<CoreResult> {
        self.ensure_open()?;
        if self.initialized {
            return Err(McpError::invalid_request("TestClient is already initialized"));
        }
        if self.next_id.load(Ordering::SeqCst) != 1 {
            self.close();
            return Err(McpError::invalid_request(
                "TestClient negotiation requires an unused endpoint",
            ));
        }
        let result = self.initialize_selected();
        if result.is_err() {
            self.close();
        }
        result
    }

    fn initialize_selected(&mut self) -> McpResult<CoreResult> {
        if self.protocol_mode == TestClientProtocolMode::Legacy2024 {
            return self.initialize_legacy().map(|result| {
                CoreResult::Legacy(LegacyCoreResult::Initialize(result))
            });
        }
        match self.probe_modern()? {
            ModernProbe::Discovered(discovery) => {
                let discovery = *discovery;
                let capabilities = serde_json::to_value(discovery.capabilities())
                    .and_then(serde_json::from_value)
                    .map_err(|_| McpError::invalid_request("Invalid modern discovery capabilities"))?;
                self.server_info = discovery.server_info().cloned();
                self.server_capabilities = Some(capabilities);
                self.protocol_version = Some(FINAL_PROTOCOL_VERSION.to_owned());
                self.server_discovery = Some(discovery.clone());
                self.negotiated_mode = Some(TestClientProtocolMode::Modern2026);
                self.initialized = true;
                Ok(CoreResult::Final(FinalCoreResult::Discover(discovery)))
            }
            ModernProbe::LegacyCandidate(error) => {
                if self.protocol_mode != TestClientProtocolMode::Auto {
                    return Err(Self::peer_error(error));
                }
                self.close();
                let Some(factory) = self.legacy_transport_factory.take() else {
                    return Err(Self::peer_error(error));
                };
                if !cfg!(feature = "legacy-2024-11-05") {
                    return Err(McpError::invalid_request(
                        "Auto fallback requires the legacy-2024-11-05 feature",
                    ));
                }

                self.cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
                self.transport = factory(&self.cx)?;
                self.ensure_open()?;
                self.initialize_legacy().map(|result| {
                    CoreResult::Legacy(LegacyCoreResult::Initialize(result))
                })
            }
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

        if result.protocol_version != PROTOCOL_VERSION {
            return Err(McpError::invalid_request(
                "Legacy TestClient requires exact MCP 2024-11-05",
            ));
        }

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

    fn probe_modern(&mut self) -> McpResult<ModernProbe> {
        if self.capabilities.extensions.as_ref().is_some_and(|settings| !settings.is_empty()) {
            return Err(McpError::invalid_params(
                "Extension capabilities require an explicitly configured production MemoryClient",
            ));
        }
        self.modern_meta = Some(self.modern_request_meta());
        let params = self.modern_parameters(serde_json::json!({}))?;
        let method = fastmcp_protocol::methods::SERVER_DISCOVER;
        let request = CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params))
            .map_err(|_| McpError::invalid_params("Invalid modern discovery parameters"))?;
        let mut received = self.exchange(method, params)?;
        if let Some(error) = received.response.error.take() {
            // Eligibility comes only from this exact, admitted, correlated
            // wire response, never from a flattened local or transport error.
            if error.code.as_i32() == Some(-32601) {
                return Ok(ModernProbe::LegacyCandidate(error));
            }
            return Err(Self::peer_error(error));
        }
        let CoreResult::Final(FinalCoreResult::Discover(discovery)) =
            self.decode_core_response(&request, received)?
        else {
            return Err(McpError::invalid_request("Unexpected modern discovery result"));
        };
        if !discovery
            .supported_versions()
            .iter()
            .any(|version| version == FINAL_PROTOCOL_VERSION)
        {
            return Err(McpError::invalid_request(
                "TestClient peer does not support MCP 2026-07-28",
            ));
        }
        Ok(ModernProbe::Discovered(Box::new(discovery)))
    }

    fn modern_request_meta(&self) -> serde_json::Value {
        if let Some(meta) = &self.modern_meta {
            return meta.clone();
        }
        serde_json::json!({
            FINAL_PROTOCOL_VERSION_META_KEY: FINAL_PROTOCOL_VERSION,
            FINAL_CLIENT_CAPABILITIES_META_KEY: self.capabilities,
            FINAL_CLIENT_INFO_META_KEY: self.client_info,
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
        params: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        let result = self.request_core(method, params)?;
        if matches!(
            result,
            CoreResult::Final(
                FinalCoreResult::ToolsCallInputRequired { .. }
                    | FinalCoreResult::ResourcesReadInputRequired { .. }
                    | FinalCoreResult::PromptsGetInputRequired { .. }
            )
        ) {
            return Err(McpError::invalid_request(
                "Modern operation requires input; use request_core to retain input requests and retry state",
            ));
        }
        let source = result.encode().map_err(|_| {
            McpError::internal_error("Failed to encode admitted TestClient result")
        })?;
        serde_json::from_str(&source)
            .map_err(|_| McpError::internal_error("Failed to project admitted TestClient result"))
    }

    fn modern_parameters(&self, mut params: serde_json::Value) -> McpResult<serde_json::Value> {
        let meta = self.modern_request_meta();
        let object = params.as_object_mut().ok_or_else(|| {
            McpError::invalid_params("Modern TestClient parameters must be an object")
        })?;
        let existing = object
            .entry("_meta")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .ok_or_else(|| McpError::invalid_params("Modern request _meta must be an object"))?;
        for (key, value) in meta.as_object().expect("local metadata is an object") {
            if existing.get(key).is_some_and(|supplied| supplied != value) {
                return Err(McpError::invalid_params(
                    "Request metadata contradicts the negotiated TestClient identity or capabilities",
                ));
            }
            existing.insert(key.clone(), value.clone());
        }
        Ok(params)
    }

    /// Returns the full admitted modern discovery snapshot, including cache
    /// hints, extension advertisements, peer diagnostics, and open members.
    #[must_use]
    pub fn server_discovery(&self) -> Option<&ServerDiscoverResult> {
        self.server_discovery.as_ref()
    }

    /// Sends one core request and retains its complete typed terminal result.
    ///
    /// Modern metadata is stamped from the negotiated snapshot. Caller-supplied
    /// contradictory reserved metadata is refused before sending. Result
    /// admission uses the original bounded transport source, preserving exact
    /// numbers and member order. Input-required results remain visible to the
    /// caller instead of becoming an empty successful legacy-shaped result.
    ///
    /// Use [`Self::connect_modern_with`] for subscriptions, Tasks, reverse RPC,
    /// or concurrent executions; this synchronous helper does not own them.
    pub fn request_core(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> McpResult<CoreResult> {
        self.ensure_initialized()?;
        if method == "subscriptions/listen" {
            return Err(McpError::invalid_request(
                "Subscriptions require the production MemoryClient handoff",
            ));
        }
        let era = if self.is_modern() {
            ProtocolEra::Modern2026
        } else {
            ProtocolEra::Legacy2024
        };
        let params = if self.is_modern() { self.modern_parameters(params)? } else { params };
        let request = CoreRequest::decode(era, method, Some(&params))
            .map_err(|_| McpError::invalid_params("Invalid TestClient core request"))?;
        let received = self.exchange(method, params)?;
        self.decode_core_response(&request, received)
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
        let response = self.exchange(method, params)?.response;
        if let Some(error) = response.error {
            return Err(Self::peer_error(error));
        }
        response
            .result
            .ok_or_else(|| McpError::internal_error("No result in response"))
    }

    /// Closes the client connection.
    pub fn close(&mut self) {
        let _ = self.transport.close(&self.cx);
        self.initialized = false;
        self.negotiated_mode = None;
        self.server_info = None;
        self.server_capabilities = None;
        self.protocol_version = None;
        self.server_discovery = None;
        self.modern_meta = None;
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
        self.send_raw_request(method, params_value)
    }

    // --- Private helpers ---

    fn ensure_open(&self) -> McpResult<()> {
        if self.transport.is_closed() {
            return Err(McpError::invalid_request("TestClient connection is closed"));
        }
        Ok(())
    }

    fn ensure_initialized(&self) -> McpResult<()> {
        self.ensure_open()?;
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
        let params_value = serde_json::to_value(params)
            .map_err(|e| McpError::internal_error(format!("Failed to serialize params: {e}")))?;
        let request = CoreRequest::decode(ProtocolEra::Legacy2024, method, Some(&params_value))
            .map_err(|_| McpError::invalid_params("Invalid or unavailable exact-2024 request"))?;
        let received = self.exchange(method, params_value)?;
        let result = self.decode_core_response(&request, received)?;
        let source = result.encode()
            .map_err(|_| McpError::internal_error("Failed to encode admitted exact-2024 result"))?;
        serde_json::from_str(&source)
            .map_err(|e| McpError::internal_error(format!("Failed to deserialize response: {e}")))
    }

    fn exchange(&mut self, method: &str, params: serde_json::Value) -> McpResult<TestClientResponse> {
        self.ensure_open()?;
        let id = match i64::try_from(self.next_request_id()) {
            Ok(id) => RequestId::Number(id),
            Err(_) => {
                self.close();
                return Err(McpError::invalid_request("TestClient request IDs exhausted"));
            }
        };
        let request = JsonRpcRequest::new(method, Some(params), id.clone());
        let result = self.transport.send(&self.cx, &JsonRpcMessage::Request(request))
            .map_err(Self::transport_error)
            .and_then(|()| self.recv_response(&id));
        if result.is_err() {
            self.close();
        }
        result
    }

    fn decode_core_response(
        &mut self,
        request: &CoreRequest,
        mut received: TestClientResponse,
    ) -> McpResult<CoreResult> {
        if let Some(error) = received.response.error.take() {
            return Err(Self::peer_error(error));
        }
        // A raw extension advertisement is not a Tasks execution owner.
        if received.response.result.as_ref().and_then(|result| result.get("resultType"))
            .and_then(serde_json::Value::as_str) == Some("task")
        {
            self.close();
            return Err(McpError::invalid_request(
                "Task results require an explicitly configured production MemoryClient",
            ));
        }
        let result = received.result_source.as_ref()
            .ok_or_else(|| McpError::invalid_request("Core response omitted its result source"))
            .and_then(|source| {
                request.decode_response_result(&received.response, source.get())
                    .map_err(|_| McpError::invalid_request("Peer response failed core result admission"))
            });
        if result.is_err() {
            self.close();
        }
        result
    }

    fn peer_error(error: JsonRpcError) -> McpError {
        let code = error.code.as_i32().map(McpErrorCode::from)
            .unwrap_or(McpErrorCode::InternalError);
        match error.data {
            Some(data) => McpError::with_data(code, error.message, data),
            None => McpError::new(code, error.message),
        }
    }

    fn transport_error(error: TransportError) -> McpError {
        if matches!(error, TransportError::Cancelled) {
            McpError::request_cancelled()
        } else {
            McpError::internal_error(format!("TestClient transport error: {error:?}"))
        }
    }

    fn recv_response(&mut self, expected_id: &RequestId) -> McpResult<TestClientResponse> {
        #[derive(serde::Deserialize)]
        struct ResponseSource {
            result: Option<Box<serde_json::value::RawValue>>,
        }
        for _ in 0..MAX_INTERLEAVED_MESSAGES {
            let (message, source) = self.transport.recv_with_source(&self.cx)
                .map_err(Self::transport_error)?.into_parts();
            match message {
                JsonRpcMessage::Response(response) => {
                    if response.id.as_ref() != Some(expected_id) {
                        return Err(McpError::invalid_request(
                            "TestClient response ID does not match its outstanding request",
                        ));
                    }
                    let source: ResponseSource = serde_json::from_slice(&source)
                        .map_err(|_| McpError::invalid_request("Invalid admitted response source"))?;
                    return Ok(TestClientResponse { response, result_source: source.result });
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
                        .map_err(Self::transport_error)?;

                    continue;
                }
            }
        }
        Err(McpError::invalid_request(
            "TestClient interleaved-message limit exceeded; use the production MemoryClient for streaming",
        ))
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
    #[cfg(feature = "legacy-2024-11-05")]
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

    fn discovery_fixture() -> serde_json::Value {
        serde_json::json!({
            "resultType": "complete",
            "supportedVersions": [FINAL_PROTOCOL_VERSION],
            "capabilities": {},
            "ttlMs": 0,
            "cacheScope": "private",
        })
    }

    fn modern_fixture() -> (TestClient, MemoryTransport) {
        let (transport, mut peer) = create_memory_transport_pair();
        let cx = Cx::for_testing();
        peer.send(&cx, &JsonRpcMessage::Response(JsonRpcResponse::success(
            RequestId::Number(1), discovery_fixture(),
        ))).unwrap();
        let mut client = TestClient::new_modern(transport, cx.clone());
        assert!(matches!(client.initialize_core().unwrap(), CoreResult::Final(FinalCoreResult::Discover(_))));
        let JsonRpcMessage::Request(request) = peer.recv(&cx).unwrap() else {
            panic!("expected the modern discovery request");
        };
        assert_eq!(request.method, "server/discover");
        assert_eq!(request.id, Some(RequestId::Number(1)));
        assert_eq!(request.params.unwrap()["_meta"][FINAL_CLIENT_INFO_META_KEY]["name"], "test-client");
        (client, peer)
    }

    #[test]
    fn modern_core_retains_optional_identity_input_state_and_exact_open_members() {
        let (mut client, mut peer) = modern_fixture();
        assert!(client.server_info().is_none());
        assert_eq!(client.server_discovery().unwrap().supported_versions(), [FINAL_PROTOCOL_VERSION]);
        let mut input = serde_json::json!({
            "resultType": "input_required", "requestState": "retry-opaque",
            "inputRequests": {"roots": {"method": "roots/list"}},
            "com.example/receipt": {},
        });
        input["com.example/receipt"]["exact"] = serde_json::Value::Number(
            serde_json::Number::from_string_unchecked("7.30e-2".to_owned()),
        );
        for id in [2, 3] {
            peer.send(&client.cx, &JsonRpcMessage::Response(JsonRpcResponse::success(
                RequestId::Number(id), input.clone(),
            ))).unwrap();
        }
        let error = client.call_tool("interactive", serde_json::json!({})).unwrap_err();
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(error.message.contains("requires input"));
        assert!(client.is_initialized(), "a valid input-required result is not a connection failure");
        let result = client.request_core("tools/call", serde_json::json!({
            "name": "interactive", "arguments": {},
        })).unwrap();
        assert!(result.encode().unwrap().contains("7.30e-2"));
        let CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { result, .. }) = result else {
            panic!("the full input-required result must remain caller-owned");
        };
        assert_eq!(result.request_state(), Some("retry-opaque"));
        assert_eq!(result.input_requests().unwrap().members().len(), 1);
        client.close();
        assert!(!client.is_initialized());
        assert!(client.server_discovery().is_none());
        assert!(client.request_core("tools/list", serde_json::json!({})).is_err());
    }

    #[test]
    fn modern_discovery_admission_failures_never_downgrade_or_reuse_the_endpoint() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;

        let mut unsupported = discovery_fixture();
        unsupported["supportedVersions"] = serde_json::json!(["2025-06-18"]);
        let mut discriminator = discovery_fixture();
        discriminator["resultType"] = serde_json::json!("input_required");
        let mut missing_cache = discovery_fixture();
        missing_cache.as_object_mut().unwrap().remove("ttlMs");
        let mut malformed_capabilities = discovery_fixture();
        malformed_capabilities["capabilities"] = serde_json::Value::Null;
        for result in [unsupported, discriminator, missing_cache, malformed_capabilities] {
            for mode in [TestClientProtocolMode::Modern2026, TestClientProtocolMode::Auto] {
                let (transport, mut peer) = create_memory_transport_pair();
                let cx = Cx::for_testing();
                peer.send(&cx, &JsonRpcMessage::Response(JsonRpcResponse::success(
                    RequestId::Number(1), result.clone(),
                ))).unwrap();
                let fallback_calls = Arc::new(AtomicUsize::new(0));
                let calls = Arc::clone(&fallback_calls);
                let mut client = TestClient::new(transport, cx.clone())
                    .with_protocol_mode(mode)
                    .with_legacy_transport_factory(move |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Err(McpError::internal_error("fallback must not run"))
                    });
                assert!(client.initialize_core().is_err());
                assert!(client.transport().is_closed());
                assert!(!client.is_initialized());
                assert!(client.protocol_version().is_none());
                assert!(client.initialize_core().is_err());
                assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
                assert!(matches!(peer.recv(&cx).unwrap(), JsonRpcMessage::Request(_)));
                assert!(matches!(peer.recv(&cx), Err(TransportError::Closed)));
            }
        }
    }

    #[test]
    fn mismatched_or_null_response_ids_are_terminal_and_never_authorize_fallback() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;

        for id in [None, Some(RequestId::Number(2)), Some(RequestId::String("1".to_owned()))] {
            let (transport, mut peer) = create_memory_transport_pair();
            let cx = Cx::for_testing();
            peer.send(&cx, &JsonRpcMessage::Response(JsonRpcResponse::error(
                id, McpError::method_not_found("server/discover").into(),
            ))).unwrap();
            let fallback_calls = Arc::new(AtomicUsize::new(0));
            let calls = Arc::clone(&fallback_calls);
            let mut client = TestClient::new_auto(transport, cx.clone())
                .with_legacy_transport_factory(move |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(McpError::internal_error("uncorrelated errors cannot authorize fallback"))
                });
            assert_eq!(client.initialize_core().unwrap_err().code, McpErrorCode::InvalidRequest);
            assert!(client.transport().is_closed());
            assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
            assert!(client.send_raw_request("initialize", serde_json::json!({})).is_err());
            assert!(matches!(peer.recv(&cx).unwrap(), JsonRpcMessage::Request(_)));
            assert!(matches!(peer.recv(&cx), Err(TransportError::Closed)));
        }
    }

    #[test]
    fn modern_core_rejects_wrong_results_and_conflicting_metadata_before_further_output() {
        let (mut client, mut peer) = modern_fixture();
        let error = client.request_core("tools/list", serde_json::json!({
            "_meta": {FINAL_PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION},
        })).unwrap_err();
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(client.next_id.load(Ordering::SeqCst), 2, "rejected parameters publish no request");
        assert!(client.is_initialized());
        // An untagged 2024-shaped tools/list lacks the final cache contract.
        peer.send(&client.cx, &JsonRpcMessage::Response(JsonRpcResponse::success(
            RequestId::Number(2), serde_json::json!({"tools": []}),
        ))).unwrap();
        assert_eq!(client.list_tools().unwrap_err().code, McpErrorCode::InvalidRequest);
        assert!(client.transport().is_closed());
        assert!(!client.is_initialized());
        assert!(client.server_discovery().is_none());
    }

    #[test]
    fn peer_errors_preserve_data_without_closing_a_negotiated_connection() {
        let (mut client, mut peer) = modern_fixture();
        let data = serde_json::json!({"reason": "bounded-refusal", "retry": false});
        peer.send(&client.cx, &JsonRpcMessage::Response(JsonRpcResponse::error(
            Some(RequestId::Number(2)),
            McpError::with_data(McpErrorCode::InvalidParams, "refused", data.clone()).into(),
        ))).unwrap();
        let error = client.request_core("tools/list", serde_json::json!({})).unwrap_err();
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(error.data, Some(data));
        assert!(client.is_initialized());
    }

    #[test]
    fn interleaved_traffic_and_cancellation_have_finite_terminal_boundaries() {
        let (transport, mut peer) =
            fastmcp_transport::memory::create_memory_transport_pair_with_capacity(MAX_INTERLEAVED_MESSAGES);
        let cx = Cx::for_testing();
        for _ in 0..MAX_INTERLEAVED_MESSAGES {
            peer.send(&cx, &JsonRpcMessage::Request(JsonRpcRequest::notification(
                "notifications/message", Some(serde_json::json!({"data": "bounded"})),
            ))).unwrap();
        }
        let mut client = TestClient::new_modern(transport, cx);
        let error = client.initialize_core().unwrap_err();
        assert!(error.message.contains("interleaved-message limit"));
        assert!(client.transport().is_closed());

        let (mut client, _peer) = modern_fixture();
        client.cx.set_cancel_requested(true);
        assert_eq!(client.list_tools().unwrap_err().code, McpErrorCode::RequestCancelled);
        assert!(client.transport().is_closed());
        assert!(!client.is_initialized());
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn legacy_initialization_refuses_a_different_protocol_version() {
        let (transport, mut peer) = create_memory_transport_pair();
        let cx = Cx::for_testing();
        peer.send(&cx, &JsonRpcMessage::Response(JsonRpcResponse::success(
            RequestId::Number(1), serde_json::json!({
                "protocolVersion": "2025-06-18", "capabilities": {},
                "serverInfo": {"name": "wrong-era", "version": "1"},
            }),
        ))).unwrap();
        let mut client = TestClient::new(transport, cx.clone());
        assert!(client.initialize().is_err());
        assert!(!client.is_initialized());
        assert!(matches!(peer.recv(&cx).unwrap(), JsonRpcMessage::Request(_)));
        assert!(matches!(peer.recv(&cx), Err(TransportError::Closed)), "no initialized notification follows a refused version");
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

        // A controlled fallback fixture exercises exact correlated eligibility;
        // the real-server modern/Auto positives above provide the live proof.
        #[cfg(feature = "legacy-2024-11-05")]
        {
            let (client_transport, mut server_transport) = create_memory_transport_pair();
            let (legacy_transport, mut legacy_peer) = create_memory_transport_pair();
            let server_cx = Cx::for_testing();
            // The probe and exact-2024 handshake use different endpoints.
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
            legacy_peer
                .send(
                    &server_cx,
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        RequestId::Number(2),
                        serde_json::to_value(legacy_init).unwrap(),
                    )),
                )
                .unwrap();

            let mut client = TestClient::new_auto(client_transport, Cx::for_testing())
                .with_legacy_transport_factory(move |_| Ok(legacy_transport));
            let init = client.initialize().expect("Auto falls back to 2024-11-05");
            assert_eq!(init.protocol_version, PROTOCOL_VERSION);
            assert_eq!(
                client.negotiated_mode(),
                Some(TestClientProtocolMode::Legacy2024)
            );
            let JsonRpcMessage::Request(probe) = server_transport.recv(&server_cx).unwrap() else {
                panic!("the disposable endpoint receives only its discovery probe");
            };
            assert_eq!(probe.method, "server/discover");
            assert!(matches!(server_transport.recv(&server_cx), Err(TransportError::Closed)));
            let JsonRpcMessage::Request(initialize) = legacy_peer.recv(&server_cx).unwrap() else {
                panic!("the fresh endpoint receives exact-2024 initialization");
            };
            assert_eq!(initialize.method, "initialize");
            assert_eq!(initialize.id, Some(RequestId::Number(2)));
            let JsonRpcMessage::Request(initialized) = legacy_peer.recv(&server_cx).unwrap() else {
                panic!("the fresh endpoint receives the initialized notification");
            };
            assert_eq!(initialized.method, "notifications/initialized");
            assert!(initialized.id.is_none());
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
