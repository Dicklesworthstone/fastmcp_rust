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
}

impl SessionState {
    /// Creates a new empty session state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        let guard = self.inner.lock().ok()?;
        let value = guard.get(key)?;
        serde_json::from_value(value.clone()).ok()
    }

    /// Gets a raw JSON value from session state by key.
    ///
    /// Returns `None` if the key doesn't exist.
    #[must_use]
    pub fn get_raw(&self, key: &str) -> Option<serde_json::Value> {
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

    /// Removes a value from session state.
    ///
    /// Returns the previous value if it existed.
    pub fn remove(&self, key: &str) -> Option<serde_json::Value> {
        let mut guard = self.inner.lock().ok()?;
        guard.remove(key)
    }

    /// Checks if a key exists in session state.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.inner
            .lock()
            .map(|g| g.contains_key(key))
            .unwrap_or(false)
    }

    /// Returns the number of entries in session state.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
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
}
