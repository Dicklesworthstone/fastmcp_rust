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

/// Cancellation notification.
pub const NOTIFICATIONS_CANCELLED: &str = "notifications/cancelled";

/// Ping request.
pub const PING: &str = "ping";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_method_constants_match_mcp_spec() {
        // Spec: https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
        assert_eq!(INITIALIZE, "initialize");
        assert_eq!(NOTIFICATIONS_INITIALIZED, "notifications/initialized");
    }

    #[test]
    fn tool_method_constants_match_mcp_spec() {
        // Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
        assert_eq!(TOOLS_LIST, "tools/list");
        assert_eq!(TOOLS_CALL, "tools/call");
    }
}
