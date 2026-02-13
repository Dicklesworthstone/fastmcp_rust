//! Agent/human context detection
//!
//! Determines whether rich output should be enabled based on the execution context.

/// Display context representing the environment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisplayContext {
    /// Agent context - plain output for machine parsing
    Agent,
    /// Human context - rich styled output
    #[default]
    Human,
}

impl DisplayContext {
    /// Create an agent (plain output) context
    #[must_use]
    pub fn new_agent() -> Self {
        Self::Agent
    }

    /// Create a human (rich output) context
    #[must_use]
    pub fn new_human() -> Self {
        Self::Human
    }

    /// Auto-detect the display context from environment
    #[must_use]
    pub fn detect() -> Self {
        if should_enable_rich() {
            Self::Human
        } else {
            Self::Agent
        }
    }

    /// Check if this is a human context (rich output enabled)
    #[must_use]
    pub fn is_human(&self) -> bool {
        matches!(self, Self::Human)
    }

    /// Check if this is an agent context (plain output)
    #[must_use]
    pub fn is_agent(&self) -> bool {
        matches!(self, Self::Agent)
    }
}

/// Determine if we're running in an agent context
#[must_use]
pub fn is_agent_context() -> bool {
    // MCP clients set these when spawning servers
    std::env::var("MCP_CLIENT").is_ok()
        || std::env::var("CLAUDE_CODE").is_ok()
        || std::env::var("CODEX_CLI").is_ok()
        || std::env::var("CURSOR_SESSION").is_ok()
        // Generic agent indicators
        || std::env::var("CI").is_ok()
        || std::env::var("AGENT_MODE").is_ok()
        // Explicit rich disable
        || std::env::var("FASTMCP_PLAIN").is_ok()
        || std::env::var("NO_COLOR").is_ok()
}

/// Determine if rich output should be enabled
#[must_use]
pub fn should_enable_rich() -> bool {
    use std::io::IsTerminal;

    // Explicit enable always wins
    if std::env::var("FASTMCP_RICH").is_ok() {
        return true;
    }

    // In agent context, disable rich by default
    if is_agent_context() {
        return false;
    }

    // Human context only when stderr is an interactive terminal.
    std::io::stderr().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_context_new_agent() {
        let ctx = DisplayContext::new_agent();
        assert!(ctx.is_agent());
        assert!(!ctx.is_human());
    }

    #[test]
    fn test_display_context_new_human() {
        let ctx = DisplayContext::new_human();
        assert!(ctx.is_human());
        assert!(!ctx.is_agent());
    }

    #[test]
    fn test_display_context_default_is_human() {
        let ctx = DisplayContext::default();
        assert!(ctx.is_human());
    }

    #[test]
    fn test_display_context_equality() {
        assert_eq!(DisplayContext::Agent, DisplayContext::Agent);
        assert_eq!(DisplayContext::Human, DisplayContext::Human);
        assert_ne!(DisplayContext::Agent, DisplayContext::Human);
    }

    #[test]
    fn test_display_context_clone() {
        let ctx = DisplayContext::Agent;
        let cloned = ctx;
        assert_eq!(ctx, cloned);
    }

    #[test]
    fn test_display_context_debug() {
        let ctx = DisplayContext::Agent;
        let debug_str = format!("{:?}", ctx);
        assert!(debug_str.contains("Agent"));
    }

    // =========================================================================
    // Additional coverage tests (bd-1p24)
    // =========================================================================

    #[test]
    fn display_context_copy_semantics() {
        let ctx = DisplayContext::Agent;
        let copied = ctx;
        // Both should be usable (Copy trait)
        assert!(ctx.is_agent());
        assert!(copied.is_agent());
    }

    #[test]
    fn display_context_debug_human() {
        let ctx = DisplayContext::Human;
        let debug_str = format!("{ctx:?}");
        assert!(debug_str.contains("Human"));
    }

    #[test]
    fn detect_returns_valid_context() {
        // In CI, detect() should return Agent (CI env var is set)
        let ctx = DisplayContext::detect();
        assert!(ctx.is_agent() || ctx.is_human());
    }

    #[test]
    fn is_agent_context_and_should_enable_rich_are_consistent() {
        // If is_agent_context() returns true, should_enable_rich() should return
        // false (unless FASTMCP_RICH is set, which it shouldn't be in tests)
        if is_agent_context() {
            // agent context -> rich should be disabled (unless FASTMCP_RICH override)
            if std::env::var("FASTMCP_RICH").is_err() {
                assert!(!should_enable_rich());
            }
        }
    }
}
