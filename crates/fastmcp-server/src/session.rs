//! MCP session management.

use fastmcp_protocol::{ClientCapabilities, ClientInfo, ServerCapabilities, ServerInfo};

/// An MCP session between client and server.
///
/// Tracks the state of an initialized MCP connection.
#[derive(Debug)]
pub struct Session {
    /// Whether the session has been initialized.
    initialized: bool,
    /// Client info from initialization.
    client_info: Option<ClientInfo>,
    /// Client capabilities from initialization.
    client_capabilities: Option<ClientCapabilities>,
    /// Server info.
    server_info: ServerInfo,
    /// Server capabilities.
    server_capabilities: ServerCapabilities,
    /// Negotiated protocol version.
    protocol_version: Option<String>,
}

impl Session {
    /// Creates a new uninitialized session.
    #[must_use]
    pub fn new(server_info: ServerInfo, server_capabilities: ServerCapabilities) -> Self {
        Self {
            initialized: false,
            client_info: None,
            client_capabilities: None,
            server_info,
            server_capabilities,
            protocol_version: None,
        }
    }

    /// Returns whether the session has been initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Initializes the session with client info.
    pub fn initialize(
        &mut self,
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        protocol_version: String,
    ) {
        self.client_info = Some(client_info);
        self.client_capabilities = Some(client_capabilities);
        self.protocol_version = Some(protocol_version);
        self.initialized = true;
    }

    /// Returns the client info if initialized.
    #[must_use]
    pub fn client_info(&self) -> Option<&ClientInfo> {
        self.client_info.as_ref()
    }

    /// Returns the client capabilities if initialized.
    #[must_use]
    pub fn client_capabilities(&self) -> Option<&ClientCapabilities> {
        self.client_capabilities.as_ref()
    }

    /// Returns the server info.
    #[must_use]
    pub fn server_info(&self) -> &ServerInfo {
        &self.server_info
    }

    /// Returns the server capabilities.
    #[must_use]
    pub fn server_capabilities(&self) -> &ServerCapabilities {
        &self.server_capabilities
    }

    /// Returns the negotiated protocol version.
    #[must_use]
    pub fn protocol_version(&self) -> Option<&str> {
        self.protocol_version.as_deref()
    }
}
