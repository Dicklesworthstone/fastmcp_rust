//! Test context wrapper for asupersync integration.
//!
//! Provides a convenient wrapper around a FastMCP runtime-provided `Cx` with
//! helper methods for common test scenarios.

use std::time::Duration;

use asupersync::{Budget, Cx, time::wall_now};
use fastmcp_core::{McpContext, SessionState};

/// Test context wrapper providing convenient testing utilities.
///
/// Wraps the caller's `Cx` and provides helper methods for:
/// - Budget/timeout configuration
/// - Creating `McpContext` instances
/// - Running async operations with cleanup
///
/// # Example
///
/// ```ignore
/// let ctx = TestContext::new(cx.clone());
/// let mcp_ctx = ctx.mcp_context(1);  // Request ID 1
///
/// // With custom budget
/// let ctx = TestContext::new(cx.clone()).with_budget_secs(30);
/// ```
#[derive(Clone)]
pub struct TestContext {
    /// The underlying asupersync context.
    cx: Cx,
    /// Optional budget for timeout testing.
    budget: Option<Budget>,
    /// Session state for stateful tests.
    session_state: Option<SessionState>,
}

impl std::fmt::Debug for TestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestContext")
            .field("has_budget", &self.budget.is_some())
            .field("has_session_state", &self.session_state.is_some())
            .finish()
    }
}

impl TestContext {
    /// Creates a test context over the caller's `cx`.
    ///
    /// The caller supplies the context: a library helper that built one would
    /// have to create or enter a runtime of its own (FND-04).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ctx = TestContext::new(cx.clone());
    /// ```
    #[must_use]
    pub fn new(cx: Cx) -> Self {
        Self {
            cx,
            budget: None,
            session_state: None,
        }
    }

    /// Creates a test context with a budget timeout.
    ///
    /// # Arguments
    ///
    /// * `secs` - Timeout in seconds
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ctx = TestContext::new(cx.clone()).with_budget_secs(5);
    /// ```
    #[must_use]
    pub fn with_budget_secs(mut self, secs: u64) -> Self {
        self.budget = Some(Budget::new().with_timeout(wall_now(), Duration::from_secs(secs)));
        self
    }

    /// Creates a test context with a budget timeout in milliseconds.
    ///
    /// # Arguments
    ///
    /// * `ms` - Timeout in milliseconds
    #[must_use]
    pub fn with_budget_ms(mut self, ms: u64) -> Self {
        self.budget = Some(Budget::new().with_timeout(wall_now(), Duration::from_millis(ms)));
        self
    }

    /// Creates a test context with shared session state.
    ///
    /// Useful for testing state persistence across multiple contexts.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let state = SessionState::new();
    /// let ctx1 = TestContext::new(cx.clone()).with_session_state(state.clone());
    /// let ctx2 = TestContext::new(cx.clone()).with_session_state(state.clone());
    /// // Both contexts share the same session state
    /// ```
    #[must_use]
    pub fn with_session_state(mut self, state: SessionState) -> Self {
        self.session_state = Some(state);
        self
    }

    /// Returns the underlying `Cx`.
    #[must_use]
    pub fn cx(&self) -> &Cx {
        &self.cx
    }

    /// Returns a clone of the underlying `Cx`.
    #[must_use]
    pub fn cx_clone(&self) -> Cx {
        self.cx.clone()
    }

    /// Returns the budget if configured.
    #[must_use]
    pub fn budget(&self) -> Option<&Budget> {
        self.budget.as_ref()
    }

    /// Creates an `McpContext` for handler testing.
    ///
    /// # Arguments
    ///
    /// * `request_id` - The request ID for this context
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ctx = TestContext::new(cx.clone());
    /// let mcp_ctx = ctx.mcp_context(1);
    ///
    /// // Use in handler testing
    /// let result = my_tool_handler.call(&mcp_ctx, args)?;
    /// ```
    #[must_use]
    pub fn mcp_context(&self, request_id: u64) -> McpContext {
        if let Some(state) = &self.session_state {
            McpContext::with_state(self.cx.clone(), request_id, state.clone())
        } else {
            McpContext::new(self.cx.clone(), request_id)
        }
    }

    /// Creates an `McpContext` with shared session state.
    ///
    /// # Arguments
    ///
    /// * `request_id` - The request ID
    /// * `state` - Session state to attach
    #[must_use]
    pub fn mcp_context_with_state(&self, request_id: u64, state: SessionState) -> McpContext {
        McpContext::with_state(self.cx.clone(), request_id, state)
    }

    /// Checks if cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cx.is_cancel_requested()
    }

    /// Performs a cancellation checkpoint.
    ///
    /// Returns `Err(CancelledError)` if cancellation was requested.
    pub fn checkpoint(&self) -> fastmcp_core::McpResult<()> {
        if self.cx.is_cancel_requested() {
            Err(fastmcp_core::McpError::request_cancelled())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let ctx = TestContext::new(Cx::for_testing());
        assert!(ctx.budget().is_none());
        assert!(!ctx.is_cancelled());
    }

    #[test]
    fn test_context_with_budget() {
        let ctx = TestContext::new(Cx::for_testing()).with_budget_secs(10);
        assert!(ctx.budget().is_some());
    }

    #[test]
    fn test_context_with_session_state() {
        let state = SessionState::new();
        let ctx = TestContext::new(Cx::for_testing()).with_session_state(state);
        assert!(ctx.session_state.is_some());
    }

    #[test]
    fn test_mcp_context_creation() {
        let ctx = TestContext::new(Cx::for_testing());
        let mcp_ctx = ctx.mcp_context(42);
        assert_eq!(mcp_ctx.request_id(), 42);
    }

    #[test]
    fn test_mcp_context_with_shared_state() {
        let state = SessionState::new();

        // First context sets a value
        {
            let ctx = TestContext::new(Cx::for_testing()).with_session_state(state.clone());
            let mcp_ctx = ctx.mcp_context(1);
            mcp_ctx.set_state("test_key", "test_value".to_string());
        }

        // Second context can read the value
        {
            let ctx = TestContext::new(Cx::for_testing()).with_session_state(state.clone());
            let mcp_ctx = ctx.mcp_context(2);
            let value: Option<String> = mcp_ctx.get_state("test_key");
            assert_eq!(value, Some("test_value".to_string()));
        }
    }

    #[test]
    fn test_checkpoint_not_cancelled() {
        let ctx = TestContext::new(Cx::for_testing());
        assert!(ctx.checkpoint().is_ok());
    }

    // =========================================================================
    // Additional coverage tests (bd-1fnm)
    // =========================================================================

    /// Constructing inside a running bridge must not enter a second one. The
    /// old constructor fetched its context with `block_on`, which panics as a
    /// nested bridge here.
    #[test]
    fn new_inside_an_active_bridge_runs_on_the_callers_cx() {
        let (ctx, caller) = fastmcp_core::block_on(async {
            let caller = Cx::current().expect("the bridge installs a current cx");
            (TestContext::new(caller.clone()), caller)
        });
        assert!(!ctx.is_cancelled());
        caller.set_cancel_requested(true);
        assert!(
            ctx.is_cancelled(),
            "the context holds the caller's cx itself, so the caller's cancel reaches it"
        );
    }

    #[test]
    fn new_with_an_independent_cx_does_not_share_the_callers_cancel() {
        let caller = Cx::for_testing();
        let ctx = TestContext::new(Cx::for_testing());
        caller.set_cancel_requested(true);
        assert!(
            !ctx.is_cancelled(),
            "CONTROL: a different cx is not cancelled by the caller's"
        );
    }

    #[test]
    fn debug_output() {
        let ctx = TestContext::new(Cx::for_testing());
        let debug = format!("{ctx:?}");
        assert!(debug.contains("TestContext"));
        assert!(debug.contains("has_budget"));
        assert!(debug.contains("has_session_state"));
    }

    #[test]
    fn clone_produces_independent_context() {
        let ctx = TestContext::new(Cx::for_testing()).with_budget_secs(30);
        let cloned = ctx.clone();
        assert!(cloned.budget().is_some());
    }

    #[test]
    fn with_budget_ms_sets_budget() {
        let ctx = TestContext::new(Cx::for_testing()).with_budget_ms(5000);
        assert!(ctx.budget().is_some());
    }

    #[test]
    fn cx_and_cx_clone_accessors() {
        let ctx = TestContext::new(Cx::for_testing());
        let _cx_ref = ctx.cx();
        let _cx_owned = ctx.cx_clone();
    }

    #[test]
    fn mcp_context_with_state_method() {
        let state = SessionState::new();
        let ctx = TestContext::new(Cx::for_testing());
        let mcp_ctx = ctx.mcp_context_with_state(99, state);
        assert_eq!(mcp_ctx.request_id(), 99);
    }
}
