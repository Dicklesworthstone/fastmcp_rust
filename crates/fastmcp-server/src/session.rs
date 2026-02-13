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
    use std::sync::{Arc, Mutex};

    fn make_server_info() -> ServerInfo {
        ServerInfo {
            name: "test".to_string(),
            version: "1.0".to_string(),
        }
    }

    fn make_client_info() -> ClientInfo {
        ClientInfo {
            name: "test-client".to_string(),
            version: "1.0".to_string(),
        }
    }

    fn make_session() -> Session {
        Session::new(make_server_info(), ServerCapabilities::default())
    }

    // ── New session initial state ────────────────────────────────────

    #[test]
    fn new_session_is_not_initialized() {
        let session = make_session();
        assert!(!session.is_initialized());
    }

    #[test]
    fn new_session_has_no_client_info() {
        let session = make_session();
        assert!(session.client_info().is_none());
    }

    #[test]
    fn new_session_has_no_client_capabilities() {
        let session = make_session();
        assert!(session.client_capabilities().is_none());
    }

    #[test]
    fn new_session_has_no_protocol_version() {
        let session = make_session();
        assert!(session.protocol_version().is_none());
    }

    #[test]
    fn new_session_has_no_log_level() {
        let session = make_session();
        assert!(session.log_level().is_none());
    }

    #[test]
    fn new_session_returns_server_info() {
        let session = make_session();
        assert_eq!(session.server_info().name, "test");
        assert_eq!(session.server_info().version, "1.0");
    }

    #[test]
    fn new_session_returns_server_capabilities() {
        let caps = ServerCapabilities::default();
        let session = Session::new(make_server_info(), caps);
        // default caps should be accessible
        let _ = session.server_capabilities();
    }

    // ── Initialization lifecycle ─────────────────────────────────────

    #[test]
    fn initialize_sets_initialized_flag() {
        let mut session = make_session();
        session.initialize(
            make_client_info(),
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );
        assert!(session.is_initialized());
    }

    #[test]
    fn initialize_stores_client_info() {
        let mut session = make_session();
        session.initialize(
            make_client_info(),
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );
        let info = session.client_info().expect("client_info set");
        assert_eq!(info.name, "test-client");
        assert_eq!(info.version, "1.0");
    }

    #[test]
    fn initialize_stores_client_capabilities() {
        let mut session = make_session();
        let caps = ClientCapabilities {
            sampling: Some(SamplingCapability {}),
            elicitation: None,
            roots: None,
        };
        session.initialize(make_client_info(), caps, "2024-11-05".to_string());
        let stored = session.client_capabilities().expect("caps set");
        assert!(stored.sampling.is_some());
    }

    #[test]
    fn initialize_stores_protocol_version() {
        let mut session = make_session();
        session.initialize(
            make_client_info(),
            ClientCapabilities::default(),
            "2025-03-26".to_string(),
        );
        assert_eq!(session.protocol_version(), Some("2025-03-26"));
    }

    // ── Resource subscriptions ───────────────────────────────────────

    #[test]
    fn subscribe_and_check_resource() {
        let mut session = make_session();
        assert!(!session.is_resource_subscribed("file:///a.txt"));
        session.subscribe_resource("file:///a.txt".to_string());
        assert!(session.is_resource_subscribed("file:///a.txt"));
    }

    #[test]
    fn unsubscribe_resource_removes_it() {
        let mut session = make_session();
        session.subscribe_resource("file:///a.txt".to_string());
        session.unsubscribe_resource("file:///a.txt");
        assert!(!session.is_resource_subscribed("file:///a.txt"));
    }

    #[test]
    fn unsubscribe_nonexistent_resource_is_noop() {
        let mut session = make_session();
        // should not panic
        session.unsubscribe_resource("file:///does-not-exist");
        assert!(!session.is_resource_subscribed("file:///does-not-exist"));
    }

    #[test]
    fn multiple_subscriptions_are_independent() {
        let mut session = make_session();
        session.subscribe_resource("a://1".to_string());
        session.subscribe_resource("b://2".to_string());
        assert!(session.is_resource_subscribed("a://1"));
        assert!(session.is_resource_subscribed("b://2"));
        session.unsubscribe_resource("a://1");
        assert!(!session.is_resource_subscribed("a://1"));
        assert!(session.is_resource_subscribed("b://2"));
    }

    #[test]
    fn duplicate_subscribe_is_idempotent() {
        let mut session = make_session();
        session.subscribe_resource("r://x".to_string());
        session.subscribe_resource("r://x".to_string());
        assert!(session.is_resource_subscribed("r://x"));
        session.unsubscribe_resource("r://x");
        assert!(!session.is_resource_subscribed("r://x"));
    }

    // ── Log level ────────────────────────────────────────────────────

    #[test]
    fn set_log_level_and_read_back() {
        let mut session = make_session();
        session.set_log_level(LogLevel::Warning);
        assert_eq!(session.log_level(), Some(LogLevel::Warning));
    }

    #[test]
    fn set_log_level_overwrites_previous() {
        let mut session = make_session();
        session.set_log_level(LogLevel::Debug);
        session.set_log_level(LogLevel::Error);
        assert_eq!(session.log_level(), Some(LogLevel::Error));
    }

    // ── Session state ────────────────────────────────────────────────

    #[test]
    fn state_is_accessible() {
        let session = make_session();
        let state = session.state();
        // fresh state should have no stored values
        let val: Option<String> = state.get("key");
        assert!(val.is_none());
    }

    // ── notify_resource_updated ──────────────────────────────────────

    #[test]
    fn notify_resource_updated_returns_false_when_not_subscribed() {
        let session = make_session();
        let sender: NotificationSender = Arc::new(|_| {});
        assert!(!session.notify_resource_updated("file:///a.txt", &sender));
    }

    #[test]
    fn notify_resource_updated_sends_when_subscribed() {
        let mut session = make_session();
        session.subscribe_resource("file:///a.txt".to_string());

        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender: NotificationSender = Arc::new(move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        let result = session.notify_resource_updated("file:///a.txt", &sender);
        assert!(result);

        let messages = sent.lock().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].method, "notifications/resources/updated");
    }

    #[test]
    fn notify_resource_updated_includes_uri_in_params() {
        let mut session = make_session();
        session.subscribe_resource("test://res".to_string());

        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender: NotificationSender = Arc::new(move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        session.notify_resource_updated("test://res", &sender);

        let messages = sent.lock().unwrap();
        let params = messages[0].params.as_ref().expect("params present");
        let uri = params
            .get("uri")
            .and_then(|v| v.as_str())
            .expect("uri field");
        assert_eq!(uri, "test://res");
    }

    #[test]
    fn notify_resource_updated_does_not_fire_for_other_uri() {
        let mut session = make_session();
        session.subscribe_resource("file:///a.txt".to_string());

        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender: NotificationSender = Arc::new(move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        let result = session.notify_resource_updated("file:///b.txt", &sender);
        assert!(!result);
        assert!(sent.lock().unwrap().is_empty());
    }

    // ── Debug impl ───────────────────────────────────────────────────

    #[test]
    fn session_debug_format_includes_fields() {
        let session = make_session();
        let debug = format!("{:?}", session);
        assert!(debug.contains("Session"));
        assert!(debug.contains("initialized: false"));
    }

    // ── Existing capability tests ────────────────────────────────────

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
                roots: Some(RootsCapability {
                    list_changed: false,
                }),
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

    // ── Re-initialization ───────────────────────────────────────────

    #[test]
    fn reinitialize_overwrites_client_info() {
        let mut session = make_session();
        session.initialize(
            make_client_info(),
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );
        session.initialize(
            ClientInfo {
                name: "new-client".to_string(),
                version: "2.0".to_string(),
            },
            ClientCapabilities {
                sampling: Some(SamplingCapability {}),
                elicitation: None,
                roots: None,
            },
            "2025-03-26".to_string(),
        );
        assert!(session.is_initialized());
        let info = session.client_info().unwrap();
        assert_eq!(info.name, "new-client");
        assert_eq!(info.version, "2.0");
        assert_eq!(session.protocol_version(), Some("2025-03-26"));
        assert!(session.supports_sampling());
    }

    // ── State persistence through lifecycle ──────────────────────────

    #[test]
    fn state_persists_after_initialization() {
        let mut session = make_session();
        session.state().set("key", "before_init");
        session.initialize(
            make_client_info(),
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );
        let val: Option<String> = session.state().get("key");
        assert_eq!(val.as_deref(), Some("before_init"));
    }

    // ── Notification after unsubscribe ───────────────────────────────

    #[test]
    fn notify_resource_updated_after_unsubscribe_returns_false() {
        let mut session = make_session();
        session.subscribe_resource("r://x".to_string());

        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender: NotificationSender = Arc::new(move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        // First notification should fire
        assert!(session.notify_resource_updated("r://x", &sender));
        assert_eq!(sent.lock().unwrap().len(), 1);

        // Unsubscribe and try again
        session.unsubscribe_resource("r://x");
        assert!(!session.notify_resource_updated("r://x", &sender));
        // No new notifications sent
        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    // ── Subscribe → unsubscribe → re-subscribe ─────────────────────

    #[test]
    fn resubscribe_after_unsubscribe_works() {
        let mut session = make_session();
        session.subscribe_resource("r://x".to_string());
        session.unsubscribe_resource("r://x");
        assert!(!session.is_resource_subscribed("r://x"));
        session.subscribe_resource("r://x".to_string());
        assert!(session.is_resource_subscribed("r://x"));
    }

    // ── Debug format after initialization ───────────────────────────

    #[test]
    fn session_debug_after_init_shows_initialized_true() {
        let mut session = make_session();
        session.initialize(
            make_client_info(),
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );
        let debug = format!("{:?}", session);
        assert!(debug.contains("initialized: true"));
    }

    // ── Non-default server capabilities ─────────────────────────────

    #[test]
    fn session_with_custom_server_capabilities() {
        use fastmcp_protocol::{LoggingCapability, TasksCapability, ToolsCapability};
        let caps = ServerCapabilities {
            tools: Some(ToolsCapability { list_changed: true }),
            logging: Some(LoggingCapability {}),
            tasks: Some(TasksCapability {
                list_changed: false,
            }),
            ..ServerCapabilities::default()
        };
        let session = Session::new(make_server_info(), caps);
        assert!(session.server_capabilities().tools.is_some());
        assert!(session.server_capabilities().logging.is_some());
        assert!(session.server_capabilities().tasks.is_some());
    }

    // ── Log level with all variants ─────────────────────────────────

    #[test]
    fn set_log_level_all_variants() {
        let mut session = make_session();
        for level in [
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warning,
            LogLevel::Error,
        ] {
            session.set_log_level(level);
            assert_eq!(session.log_level(), Some(level));
        }
    }

    // ── Persistence across re-initialization ────────────────────────

    #[test]
    fn log_level_persists_across_reinitialization() {
        let mut session = make_session();
        session.set_log_level(LogLevel::Warning);
        session.initialize(
            make_client_info(),
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );
        assert_eq!(session.log_level(), Some(LogLevel::Warning));
        // Re-initialize with different client info
        session.initialize(
            ClientInfo {
                name: "other".to_string(),
                version: "2.0".to_string(),
            },
            ClientCapabilities::default(),
            "2025-03-26".to_string(),
        );
        assert_eq!(session.log_level(), Some(LogLevel::Warning));
    }

    #[test]
    fn resource_subscriptions_persist_across_reinitialization() {
        let mut session = make_session();
        session.subscribe_resource("file:///keep.txt".to_string());
        session.initialize(
            make_client_info(),
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );
        assert!(session.is_resource_subscribed("file:///keep.txt"));
    }

    #[test]
    fn state_set_after_init_persists_through_reinit() {
        let mut session = make_session();
        session.initialize(
            make_client_info(),
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );
        session.state().set("counter", 42);
        // Re-initialize
        session.initialize(
            ClientInfo {
                name: "new".to_string(),
                version: "3.0".to_string(),
            },
            ClientCapabilities::default(),
            "2025-03-26".to_string(),
        );
        let val: Option<i32> = session.state().get("counter");
        assert_eq!(val, Some(42));
    }

    #[test]
    fn notify_resource_updated_fires_independently_per_subscription() {
        let mut session = make_session();
        session.subscribe_resource("a://1".to_string());
        session.subscribe_resource("b://2".to_string());

        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender: NotificationSender = Arc::new(move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        // Notify first URI
        assert!(session.notify_resource_updated("a://1", &sender));
        assert_eq!(sent.lock().unwrap().len(), 1);
        let uri = sent.lock().unwrap()[0]
            .params
            .as_ref()
            .unwrap()
            .get("uri")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(uri, "a://1");

        // Notify second URI
        assert!(session.notify_resource_updated("b://2", &sender));
        assert_eq!(sent.lock().unwrap().len(), 2);
        let uri2 = sent.lock().unwrap()[1]
            .params
            .as_ref()
            .unwrap()
            .get("uri")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(uri2, "b://2");
    }

    #[test]
    fn supports_elicitation_and_roots_false_before_init() {
        let session = make_session();
        assert!(!session.supports_elicitation());
        assert!(!session.supports_roots());
    }
}
