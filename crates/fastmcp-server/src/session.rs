//! MCP session management.

use std::collections::HashSet;

use fastmcp_core::SessionState;
use fastmcp_core::logging::{debug, targets, warn};
use fastmcp_protocol::{
    ClientCapabilities, ClientInfo, JsonRpcRequest, LogLevel, ResourceUpdatedNotificationParams,
    ServerCapabilities, ServerInfo,
};

use crate::NotificationSender;

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
    /// Resource subscriptions for this session.
    resource_subscriptions: HashSet<String>,
    /// Session-scoped log level for log notifications.
    log_level: Option<LogLevel>,
    /// Per-session state storage.
    state: SessionState,
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
            resource_subscriptions: HashSet::new(),
            log_level: None,
            state: SessionState::new(),
        }
    }

    /// Returns a reference to the session state.
    ///
    /// Session state persists across requests within this session and can be
    /// used to store handler-specific data.
    #[must_use]
    pub fn state(&self) -> &SessionState {
        &self.state
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

    /// Subscribes to a resource URI for this session.
    pub fn subscribe_resource(&mut self, uri: String) {
        self.resource_subscriptions.insert(uri);
    }

    /// Unsubscribes from a resource URI for this session.
    pub fn unsubscribe_resource(&mut self, uri: &str) {
        self.resource_subscriptions.remove(uri);
    }

    /// Returns true if this session is subscribed to the given resource URI.
    #[must_use]
    pub fn is_resource_subscribed(&self, uri: &str) -> bool {
        self.resource_subscriptions.contains(uri)
    }

    /// Sets the session log level for log notifications.
    pub fn set_log_level(&mut self, level: LogLevel) {
        self.log_level = Some(level);
    }

    /// Returns the current session log level for log notifications.
    #[must_use]
    pub fn log_level(&self) -> Option<LogLevel> {
        self.log_level
    }

    /// Returns whether the client supports sampling (LLM completions).
    #[must_use]
    pub fn supports_sampling(&self) -> bool {
        self.client_capabilities
            .as_ref()
            .is_some_and(|caps| caps.sampling.is_some())
    }

    /// Returns whether the client supports elicitation (user input requests).
    #[must_use]
    pub fn supports_elicitation(&self) -> bool {
        self.client_capabilities
            .as_ref()
            .is_some_and(|caps| caps.elicitation.is_some())
    }

    /// Returns whether the client supports roots listing.
    #[must_use]
    pub fn supports_roots(&self) -> bool {
        self.client_capabilities
            .as_ref()
            .is_some_and(|caps| caps.roots.is_some())
    }

    /// Sends a resource updated notification if the session is subscribed.
    ///
    /// Returns true if a notification was sent.
    pub fn notify_resource_updated(&self, uri: &str, sender: &NotificationSender) -> bool {
        if !self.is_resource_subscribed(uri) {
            return false;
        }

        let params = ResourceUpdatedNotificationParams {
            uri: uri.to_string(),
        };
        let payload = match serde_json::to_value(params) {
            Ok(value) => value,
            Err(err) => {
                warn!(
                    target: targets::SESSION,
                    "failed to serialize resource update for {}: {}",
                    uri,
                    err
                );
                return false;
            }
        };

        debug!(
            target: targets::SESSION,
            "sending resource update notification for {}",
            uri
        );
        sender(JsonRpcRequest::notification(
            "notifications/resources/updated",
            Some(payload),
        ));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ElicitationCapability, RootsCapability, SamplingCapability};

    #[test]
    fn test_session_supports_sampling() {
        let mut session = Session::new(
            ServerInfo {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
            ServerCapabilities::default(),
        );

        // Before initialization, no capabilities
        assert!(!session.supports_sampling());

        // Initialize with sampling capability
        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0".to_string(),
            },
            ClientCapabilities {
                sampling: Some(SamplingCapability {}),
                elicitation: None,
                roots: None,
            },
            "2024-11-05".to_string(),
        );

        assert!(session.supports_sampling());
        assert!(!session.supports_elicitation());
        assert!(!session.supports_roots());
    }

    #[test]
    fn test_session_supports_elicitation() {
        let mut session = Session::new(
            ServerInfo {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
            ServerCapabilities::default(),
        );

        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0".to_string(),
            },
            ClientCapabilities {
                sampling: None,
                elicitation: Some(ElicitationCapability::form()),
                roots: None,
            },
            "2024-11-05".to_string(),
        );

        assert!(!session.supports_sampling());
        assert!(session.supports_elicitation());
        assert!(!session.supports_roots());
    }

    #[test]
    fn test_session_supports_roots() {
        let mut session = Session::new(
            ServerInfo {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
            ServerCapabilities::default(),
        );

        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0".to_string(),
            },
            ClientCapabilities {
                sampling: None,
                elicitation: None,
                roots: Some(RootsCapability { list_changed: true }),
            },
            "2024-11-05".to_string(),
        );

        assert!(!session.supports_sampling());
        assert!(!session.supports_elicitation());
        assert!(session.supports_roots());
    }

    #[test]
    fn test_session_supports_all_capabilities() {
        let mut session = Session::new(
            ServerInfo {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
            ServerCapabilities::default(),
        );

        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0".to_string(),
            },
            ClientCapabilities {
                sampling: Some(SamplingCapability {}),
                elicitation: Some(ElicitationCapability::both()),
                roots: Some(RootsCapability { list_changed: false }),
            },
            "2024-11-05".to_string(),
        );

        assert!(session.supports_sampling());
        assert!(session.supports_elicitation());
        assert!(session.supports_roots());
    }

    #[test]
    fn test_session_no_capabilities() {
        let mut session = Session::new(
            ServerInfo {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
            ServerCapabilities::default(),
        );

        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        assert!(!session.supports_sampling());
        assert!(!session.supports_elicitation());
        assert!(!session.supports_roots());
    }
}
