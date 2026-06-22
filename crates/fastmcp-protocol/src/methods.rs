//! Canonical MCP JSON-RPC method names.

/// Lifecycle initialize request.
pub const INITIALIZE: &str = "initialize";

/// Lifecycle initialized notification.
pub const NOTIFICATIONS_INITIALIZED: &str = "notifications/initialized";

/// Legacy initialized notification spelling accepted for compatibility.
pub const LEGACY_INITIALIZED: &str = "initialized";

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

/// Logging set level request.
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
        // Spec: https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
        assert_eq!(INITIALIZE, "initialize");
        assert_eq!(NOTIFICATIONS_INITIALIZED, "notifications/initialized");

        // Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
        assert_eq!(TOOLS_LIST, "tools/list");
        assert_eq!(TOOLS_CALL, "tools/call");

        // Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/resources
        assert_eq!(RESOURCES_LIST, "resources/list");
        assert_eq!(RESOURCES_TEMPLATES_LIST, "resources/templates/list");
        assert_eq!(RESOURCES_READ, "resources/read");

        // Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/prompts
        assert_eq!(PROMPTS_LIST, "prompts/list");
        assert_eq!(PROMPTS_GET, "prompts/get");

        // Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/logging
        assert_eq!(LOGGING_SET_LEVEL, "logging/setLevel");
        assert_eq!(NOTIFICATIONS_MESSAGE, "notifications/message");
    }
}
