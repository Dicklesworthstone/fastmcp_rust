//! Server builder for configuring MCP servers.

use fastmcp_protocol::{
    PromptsCapability, ResourcesCapability, ServerCapabilities, ServerInfo, ToolsCapability,
};

use crate::{PromptHandler, ResourceHandler, Router, Server, ToolHandler};

/// Default request timeout in seconds.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Builder for configuring an MCP server.
pub struct ServerBuilder {
    info: ServerInfo,
    capabilities: ServerCapabilities,
    router: Router,
    instructions: Option<String>,
    /// Request timeout in seconds (0 = no timeout).
    request_timeout_secs: u64,
}

impl ServerBuilder {
    /// Creates a new server builder.
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            info: ServerInfo {
                name: name.into(),
                version: version.into(),
            },
            capabilities: ServerCapabilities::default(),
            router: Router::new(),
            instructions: None,
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
        }
    }

    /// Sets the request timeout in seconds.
    ///
    /// Set to 0 to disable timeout enforcement.
    /// Default is 30 seconds.
    #[must_use]
    pub fn request_timeout(mut self, secs: u64) -> Self {
        self.request_timeout_secs = secs;
        self
    }

    /// Registers a tool handler.
    #[must_use]
    pub fn tool<H: ToolHandler + 'static>(mut self, handler: H) -> Self {
        self.router.add_tool(handler);
        self.capabilities.tools = Some(ToolsCapability::default());
        self
    }

    /// Registers a resource handler.
    #[must_use]
    pub fn resource<H: ResourceHandler + 'static>(mut self, handler: H) -> Self {
        self.router.add_resource(handler);
        self.capabilities.resources = Some(ResourcesCapability::default());
        self
    }

    /// Registers a prompt handler.
    #[must_use]
    pub fn prompt<H: PromptHandler + 'static>(mut self, handler: H) -> Self {
        self.router.add_prompt(handler);
        self.capabilities.prompts = Some(PromptsCapability::default());
        self
    }

    /// Sets custom server instructions.
    #[must_use]
    pub fn instructions(mut self, instructions: impl Into<String>) -> Self {
        self.instructions = Some(instructions.into());
        self
    }

    /// Builds the server.
    #[must_use]
    pub fn build(self) -> Server {
        Server {
            info: self.info,
            capabilities: self.capabilities,
            router: self.router,
            instructions: self.instructions,
            request_timeout_secs: self.request_timeout_secs,
        }
    }
}
