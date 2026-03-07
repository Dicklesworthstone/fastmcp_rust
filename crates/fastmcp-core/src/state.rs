//! Session state storage for per-session key-value data.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Thread-safe session state container for per-session key-value storage.
///
/// This allows handlers to store and retrieve state that persists across
/// requests within a single MCP session. The state is typed as JSON values
/// to support flexible data storage.
///
/// # Thread Safety
///
/// SessionState is designed for concurrent access from multiple handlers.
/// Operations are synchronized via an internal mutex.
///
/// # Example
///
/// ```ignore
/// // In a tool handler:
/// ctx.set_state("counter", 42);
/// let count: Option<i32> = ctx.get_state("counter");
/// ```
#[derive(Debug, Clone, Default)]
pub struct SessionState {
    inner: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    local: Option<Arc<Mutex<HashMap<String, serde_json::Value>>>>,
}

impl SessionState {
    /// Creates a new empty session state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a view with request-local overrides layered on top of the
    /// shared session state.
    ///
    /// Cloning the returned value preserves the same local override map,
    /// while ordinary writes continue to target the shared session state.
    #[must_use]
    pub fn with_local_overrides(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            local: Some(
                self.local
                    .as_ref()
                    .map_or_else(|| Arc::new(Mutex::new(HashMap::new())), Arc::clone),
            ),
        }
    }

    /// Creates an isolated snapshot of the current session state.
    ///
    /// Unlike [`Clone`], which shares the same underlying storage, this copies
    /// the current key-value map into a fresh container so later writes do not
    /// bleed across requests.
    #[must_use]
    pub fn snapshot(&self) -> Self {
        let mut snapshot = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(local) = &self.local {
            snapshot.extend(
                local
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone(),
            );
        }
        Self {
            inner: Arc::new(Mutex::new(snapshot)),
            local: None,
        }
    }

    /// Gets a value from session state by key.
    ///
    /// Returns `None` if the key doesn't exist or if deserialization fails.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The expected type of the value (must implement Deserialize)
    #[must_use]
    pub fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        let value = self.get_raw(key)?;
        serde_json::from_value(value).ok()
    }

    /// Gets a raw JSON value from session state by key.
    ///
    /// Returns `None` if the key doesn't exist.
    #[must_use]
    pub fn get_raw(&self, key: &str) -> Option<serde_json::Value> {
        if let Some(local) = &self.local {
            let guard = local.lock().ok()?;
            if let Some(value) = guard.get(key) {
                return Some(value.clone());
            }
        }
        let guard = self.inner.lock().ok()?;
        guard.get(key).cloned()
    }

    /// Sets a value in session state.
    ///
    /// The value is serialized to JSON for storage. Returns `true` if
    /// the value was successfully stored.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type of the value (must implement Serialize)
    pub fn set<T: serde::Serialize>(&self, key: impl Into<String>, value: T) -> bool {
        let Ok(json_value) = serde_json::to_value(value) else {
            return false;
        };
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        guard.insert(key.into(), json_value);
        true
    }

    /// Sets a raw JSON value in session state.
    ///
    /// Returns `true` if the value was successfully stored.
    pub fn set_raw(&self, key: impl Into<String>, value: serde_json::Value) -> bool {
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        guard.insert(key.into(), value);
        true
    }

    /// Sets a request-local raw JSON value layered over the shared session state.
    ///
    /// Returns `false` if this state does not have local overrides enabled.
    pub fn set_local_raw(&self, key: impl Into<String>, value: serde_json::Value) -> bool {
        let Some(local) = &self.local else {
            return false;
        };
        let Ok(mut guard) = local.lock() else {
            return false;
        };
        guard.insert(key.into(), value);
        true
    }

    /// Sets a request-local value layered over the shared session state.
    ///
    /// Returns `false` if serialization fails or local overrides are unavailable.
    pub fn set_local<T: serde::Serialize>(&self, key: impl Into<String>, value: T) -> bool {
        let Ok(json_value) = serde_json::to_value(value) else {
            return false;
        };
        self.set_local_raw(key, json_value)
    }

    /// Removes a value from session state.
    ///
    /// Returns the previous value if it existed.
    pub fn remove(&self, key: &str) -> Option<serde_json::Value> {
        if let Some(local) = &self.local {
            let mut guard = local.lock().ok()?;
            if let Some(value) = guard.remove(key) {
                return Some(value);
            }
        }
        let mut guard = self.inner.lock().ok()?;
        guard.remove(key)
    }

    /// Checks if a key exists in session state.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.get_raw(key).is_some()
    }

    /// Returns the number of entries in session state.
    #[must_use]
    pub fn len(&self) -> usize {
        let shared_keys = self
            .inner
            .lock()
            .map(|g| g.keys().cloned().collect::<std::collections::HashSet<_>>())
            .unwrap_or_default();
        if let Some(local) = &self.local {
            let local_keys = local
                .lock()
                .map(|g| g.keys().cloned().collect::<std::collections::HashSet<_>>())
                .unwrap_or_default();
            shared_keys.union(&local_keys).count()
        } else {
            shared_keys.len()
        }
    }

    /// Returns true if session state is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all session state.
    pub fn clear(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.clear();
        }
        if let Some(local) = &self.local
            && let Ok(mut guard) = local.lock()
        {
            guard.clear();
        }
    }
}

// ============================================================================
// Dynamic Component Enable/Disable Helpers
// ============================================================================

/// Session state key for disabled tools.
pub const DISABLED_TOOLS_KEY: &str = "fastmcp.disabled_tools";
/// Session state key for disabled resources.
pub const DISABLED_RESOURCES_KEY: &str = "fastmcp.disabled_resources";
/// Session state key for disabled prompts.
pub const DISABLED_PROMPTS_KEY: &str = "fastmcp.disabled_prompts";

impl SessionState {
    /// Returns whether a tool is enabled (not disabled) for this session.
    ///
    /// Tools are enabled by default unless explicitly disabled.
    #[must_use]
    pub fn is_tool_enabled(&self, name: &str) -> bool {
        !self.is_in_disabled_set(DISABLED_TOOLS_KEY, name)
    }

    /// Returns whether a resource is enabled (not disabled) for this session.
    ///
    /// Resources are enabled by default unless explicitly disabled.
    #[must_use]
    pub fn is_resource_enabled(&self, uri: &str) -> bool {
        !self.is_in_disabled_set(DISABLED_RESOURCES_KEY, uri)
    }

    /// Returns whether a prompt is enabled (not disabled) for this session.
    ///
    /// Prompts are enabled by default unless explicitly disabled.
    #[must_use]
    pub fn is_prompt_enabled(&self, name: &str) -> bool {
        !self.is_in_disabled_set(DISABLED_PROMPTS_KEY, name)
    }

    /// Returns the set of disabled tools.
    #[must_use]
    pub fn disabled_tools(&self) -> std::collections::HashSet<String> {
        self.get::<std::collections::HashSet<String>>(DISABLED_TOOLS_KEY)
            .unwrap_or_default()
    }

    /// Returns the set of disabled resources.
    #[must_use]
    pub fn disabled_resources(&self) -> std::collections::HashSet<String> {
        self.get::<std::collections::HashSet<String>>(DISABLED_RESOURCES_KEY)
            .unwrap_or_default()
    }

    /// Returns the set of disabled prompts.
    #[must_use]
    pub fn disabled_prompts(&self) -> std::collections::HashSet<String> {
        self.get::<std::collections::HashSet<String>>(DISABLED_PROMPTS_KEY)
            .unwrap_or_default()
    }

    // Helper: Check if a name is in a disabled set
    fn is_in_disabled_set(&self, key: &str, name: &str) -> bool {
        self.get::<std::collections::HashSet<String>>(key)
            .map(|set| set.contains(name))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state_new() {
        let state = SessionState::new();
        assert!(state.is_empty());
        assert_eq!(state.len(), 0);
    }

    #[test]
    fn test_session_state_set_get() {
        let state = SessionState::new();

        // Set a string value
        assert!(state.set("name", "Alice"));
        let name: Option<String> = state.get("name");
        assert_eq!(name, Some("Alice".to_string()));

        // Set a number value
        assert!(state.set("count", 42));
        let count: Option<i32> = state.get("count");
        assert_eq!(count, Some(42));
    }

    #[test]
    fn test_session_state_get_nonexistent() {
        let state = SessionState::new();
        let value: Option<String> = state.get("nonexistent");
        assert!(value.is_none());
    }

    #[test]
    fn test_session_state_type_mismatch() {
        let state = SessionState::new();
        state.set("count", 42);

        // Try to get as wrong type - should return None
        let value: Option<String> = state.get("count");
        assert!(value.is_none());
    }

    #[test]
    fn test_session_state_get_raw() {
        let state = SessionState::new();
        state.set("value", serde_json::json!({"nested": true}));

        let raw = state.get_raw("value");
        assert!(raw.is_some());
        assert_eq!(raw.unwrap()["nested"], serde_json::json!(true));
    }

    #[test]
    fn test_session_state_set_raw() {
        let state = SessionState::new();
        assert!(state.set_raw("key", serde_json::json!([1, 2, 3])));

        let value: Option<Vec<i32>> = state.get("key");
        assert_eq!(value, Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_session_state_remove() {
        let state = SessionState::new();
        state.set("key", "value");
        assert!(state.contains("key"));

        let removed = state.remove("key");
        assert!(removed.is_some());
        assert!(!state.contains("key"));
    }

    #[test]
    fn test_session_state_contains() {
        let state = SessionState::new();
        assert!(!state.contains("key"));

        state.set("key", "value");
        assert!(state.contains("key"));
    }

    #[test]
    fn test_session_state_len() {
        let state = SessionState::new();
        assert_eq!(state.len(), 0);

        state.set("a", 1);
        assert_eq!(state.len(), 1);

        state.set("b", 2);
        assert_eq!(state.len(), 2);

        state.remove("a");
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn test_session_state_clear() {
        let state = SessionState::new();
        state.set("a", 1);
        state.set("b", 2);
        assert_eq!(state.len(), 2);

        state.clear();
        assert!(state.is_empty());
    }

    #[test]
    fn test_session_state_clone() {
        let state = SessionState::new();
        state.set("key", "value");

        // Clone should share the same underlying state
        let cloned = state.clone();
        cloned.set("key2", "value2");

        assert!(state.contains("key2"));
    }

    #[test]
    fn test_session_state_snapshot_is_isolated() {
        let state = SessionState::new();
        state.set("counter", 1);

        let snapshot = state.snapshot();
        state.set("counter", 2);
        snapshot.set("only_in_snapshot", true);

        let live_counter: Option<i32> = state.get("counter");
        let snap_counter: Option<i32> = snapshot.get("counter");
        let live_only: Option<bool> = state.get("only_in_snapshot");
        let snap_only: Option<bool> = snapshot.get("only_in_snapshot");

        assert_eq!(live_counter, Some(2));
        assert_eq!(snap_counter, Some(1));
        assert_eq!(live_only, None);
        assert_eq!(snap_only, Some(true));
    }

    // ========================================================================
    // Dynamic Enable/Disable Tests
    // ========================================================================

    #[test]
    fn test_is_tool_enabled_default() {
        let state = SessionState::new();

        // Tools are enabled by default
        assert!(state.is_tool_enabled("any_tool"));
        assert!(state.is_tool_enabled("another_tool"));
    }

    #[test]
    fn test_is_tool_enabled_disabled() {
        let state = SessionState::new();

        // Manually disable a tool by setting the disabled set
        let mut disabled: std::collections::HashSet<String> = std::collections::HashSet::new();
        disabled.insert("my_tool".to_string());
        state.set(super::DISABLED_TOOLS_KEY, disabled);

        assert!(!state.is_tool_enabled("my_tool"));
        assert!(state.is_tool_enabled("other_tool"));
    }

    #[test]
    fn test_is_resource_enabled_default() {
        let state = SessionState::new();

        // Resources are enabled by default
        assert!(state.is_resource_enabled("file://path"));
        assert!(state.is_resource_enabled("http://example.com"));
    }

    #[test]
    fn test_is_resource_enabled_disabled() {
        let state = SessionState::new();

        // Manually disable a resource
        let mut disabled: std::collections::HashSet<String> = std::collections::HashSet::new();
        disabled.insert("file://secret".to_string());
        state.set(super::DISABLED_RESOURCES_KEY, disabled);

        assert!(!state.is_resource_enabled("file://secret"));
        assert!(state.is_resource_enabled("file://public"));
    }

    #[test]
    fn test_is_prompt_enabled_default() {
        let state = SessionState::new();

        // Prompts are enabled by default
        assert!(state.is_prompt_enabled("any_prompt"));
    }

    #[test]
    fn test_is_prompt_enabled_disabled() {
        let state = SessionState::new();

        // Manually disable a prompt
        let mut disabled: std::collections::HashSet<String> = std::collections::HashSet::new();
        disabled.insert("admin_prompt".to_string());
        state.set(super::DISABLED_PROMPTS_KEY, disabled);

        assert!(!state.is_prompt_enabled("admin_prompt"));
        assert!(state.is_prompt_enabled("user_prompt"));
    }

    #[test]
    fn test_disabled_sets_return_empty_by_default() {
        let state = SessionState::new();

        assert!(state.disabled_tools().is_empty());
        assert!(state.disabled_resources().is_empty());
        assert!(state.disabled_prompts().is_empty());
    }

    #[test]
    fn test_disabled_tools_returns_set() {
        let state = SessionState::new();

        let mut disabled: std::collections::HashSet<String> = std::collections::HashSet::new();
        disabled.insert("tool1".to_string());
        disabled.insert("tool2".to_string());
        state.set(super::DISABLED_TOOLS_KEY, disabled);

        let result = state.disabled_tools();
        assert_eq!(result.len(), 2);
        assert!(result.contains("tool1"));
        assert!(result.contains("tool2"));
    }
}
