//! Canonical MCP JSON-RPC method names.
//!
//! Centralizing these as constants prevents the class of typo bug where a method
//! name is spelled slightly wrong at a call site (e.g. the lifecycle notification
//! `notifications/initialized` being sent as bare `initialized`), which the wire
//! protocol silently ignores rather than rejecting.

/// Lifecycle `initialize` request.
pub const INITIALIZE: &str = "initialize";

/// Lifecycle `initialized` notification (spec-correct name).
pub const NOTIFICATIONS_INITIALIZED: &str = "notifications/initialized";

/// Tools list request.
pub const TOOLS_LIST: &str = "tools/list";

/// Tools call request.
pub const TOOLS_CALL: &str = "tools/call";

/// Resources list request.
pub const RESOURCES_LIST: &str = "resources/list";

/// Resource templates list request.
pub const RESOURCES_TEMPLATES_LIST: &str = "resources/templates/list";

/// Resources read request.
pub const RESOURCES_READ: &str = "resources/read";

/// Prompts list request.
pub const PROMPTS_LIST: &str = "prompts/list";

/// Prompts get request.
pub const PROMPTS_GET: &str = "prompts/get";

/// Logging set-level request.
pub const LOGGING_SET_LEVEL: &str = "logging/setLevel";

/// Cancellation notification.
pub const NOTIFICATIONS_CANCELLED: &str = "notifications/cancelled";

/// Logging message notification.
pub const NOTIFICATIONS_MESSAGE: &str = "notifications/message";

/// Ping request.
pub const PING: &str = "ping";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_constants_match_mcp_spec() {
        // Lifecycle: the initialized notification is `notifications/initialized`,
        // NOT bare `initialized`. https://modelcontextprotocol.io/specification
        assert_eq!(INITIALIZE, "initialize");
        assert_eq!(NOTIFICATIONS_INITIALIZED, "notifications/initialized");

        assert_eq!(TOOLS_LIST, "tools/list");
        assert_eq!(TOOLS_CALL, "tools/call");
        assert_eq!(RESOURCES_LIST, "resources/list");
        assert_eq!(RESOURCES_TEMPLATES_LIST, "resources/templates/list");
        assert_eq!(RESOURCES_READ, "resources/read");
        assert_eq!(PROMPTS_LIST, "prompts/list");
        assert_eq!(PROMPTS_GET, "prompts/get");
        assert_eq!(LOGGING_SET_LEVEL, "logging/setLevel");
        assert_eq!(NOTIFICATIONS_CANCELLED, "notifications/cancelled");
        assert_eq!(NOTIFICATIONS_MESSAGE, "notifications/message");
        assert_eq!(PING, "ping");
    }
}
