//! Session state storage for per-session key-value data.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const CACHE_PARTITION_BYTES: usize = 32;

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
/// Its [`Debug`](std::fmt::Debug) output is deliberately redacted and reports
/// entry counts and local-override presence only; it never renders keys or
/// stored values.
///
/// # Example
///
/// ```ignore
/// // In a tool handler:
/// ctx.set_state("counter", 42);
/// let count: Option<i32> = ctx.get_state("counter");
/// ```
#[derive(Clone)]
pub struct SessionState {
    inner: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    local: Option<Arc<Mutex<HashMap<String, serde_json::Value>>>>,
    cache_partition: Option<[u8; CACHE_PARTITION_BYTES]>,
    revision: Arc<AtomicU64>,
    /// Request-local modern HTTP state is not a durable client session.
    /// Response caching must treat it as the stateless partition; otherwise
    /// every POST mints a unique identity and the cache never hits.
    ephemeral: bool,
}

impl Default for SessionState {
    fn default() -> Self {
        Self::from_map(HashMap::new())
    }
}

impl fmt::Debug for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shared_entries = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        let local_entries = self.local.as_ref().map_or(0, |local| {
            local
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len()
        });

        f.debug_struct("SessionState")
            .field("shared_entry_count", &shared_entries)
            .field("has_local_overrides", &self.local.is_some())
            .field("local_entry_count", &local_entries)
            .field("ephemeral", &self.ephemeral)
            .finish()
    }
}

impl SessionState {
    fn from_map(values: HashMap<String, serde_json::Value>) -> Self {
        Self::from_map_with_partition_draw(values, || {
            crate::crypto::draw_security_identifier().map(|identifier| *identifier.as_bytes())
        })
    }

    fn from_map_with_partition_draw<F, E>(
        values: HashMap<String, serde_json::Value>,
        draw: F,
    ) -> Self
    where
        F: FnOnce() -> Result<[u8; CACHE_PARTITION_BYTES], E>,
    {
        let cache_partition = draw().ok();
        Self {
            inner: Arc::new(Mutex::new(values)),
            local: None,
            cache_partition,
            revision: Arc::new(AtomicU64::new(0)),
            ephemeral: false,
        }
    }

    fn record_mutation(&self) {
        let _ = self
            .revision
            .try_update(Ordering::AcqRel, Ordering::Acquire, |revision| {
                revision.checked_add(1)
            });
    }

    /// Creates a new empty session state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates request-local session state that is not a durable client session.
    ///
    /// Modern Streamable HTTP opens a fresh bag on every POST so
    /// `disable_*` / `enable_*` can publish `list_changed` without inventing
    /// `Mcp-Session-Id`. Response caching must not treat that bag as a
    /// partition identity.
    #[must_use]
    pub fn ephemeral() -> Self {
        let mut state = Self::default();
        state.ephemeral = true;
        state
    }

    /// Returns whether this bag is request-local rather than a durable session.
    #[must_use]
    pub const fn is_ephemeral(&self) -> bool {
        self.ephemeral
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
            cache_partition: self.cache_partition,
            revision: Arc::clone(&self.revision),
            ephemeral: self.ephemeral,
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
        let mut snapshot = Self::from_map(snapshot);
        snapshot.ephemeral = self.ephemeral;
        snapshot
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
        // `Into<String>` is extension code. Evaluate it before acquiring the
        // shared-state mutex so a panicking conversion cannot poison every
        // clone of this session state.
        let key = key.into();
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        guard.insert(key, json_value);
        self.record_mutation();
        true
    }

    /// Sets a raw JSON value in session state.
    ///
    /// Returns `true` if the value was successfully stored.
    pub fn set_raw(&self, key: impl Into<String>, value: serde_json::Value) -> bool {
        let key = key.into();
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        guard.insert(key, value);
        self.record_mutation();
        true
    }

    /// Sets a request-local raw JSON value layered over the shared session state.
    ///
    /// Returns `false` if this state does not have local overrides enabled.
    pub fn set_local_raw(&self, key: impl Into<String>, value: serde_json::Value) -> bool {
        let Some(local) = &self.local else {
            return false;
        };
        let key = key.into();
        let Ok(mut guard) = local.lock() else {
            return false;
        };
        guard.insert(key, value);
        self.record_mutation();
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
                self.record_mutation();
                return Some(value);
            }
        }
        let mut guard = self.inner.lock().ok()?;
        let removed = guard.remove(key);
        if removed.is_some() {
            self.record_mutation();
        }
        removed
    }

    /// Checks if a key exists in session state.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.get_raw(key).is_some()
    }

    /// Returns the number of entries in session state.
    #[must_use]
    pub fn len(&self) -> usize {
        let shared = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(local) = &self.local else {
            return shared.len();
        };
        let local = local
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        shared.len()
            + local
                .keys()
                .filter(|key| !shared.contains_key(key.as_str()))
                .count()
    }

    /// Returns true if session state is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all session state.
    pub fn clear(&self) {
        let Ok(mut shared) = self.inner.lock() else {
            return;
        };
        let mut local = match &self.local {
            Some(local) => match local.lock() {
                Ok(local) => Some(local),
                Err(_) => return,
            },
            None => None,
        };
        let changed = !shared.is_empty() || local.as_ref().is_some_and(|local| !local.is_empty());
        shared.clear();
        if let Some(local) = local.as_mut() {
            local.clear();
        }
        if changed {
            self.record_mutation();
        }
    }

    /// Returns an opaque cache partition and its state revision.
    ///
    /// This internal integration hook fails closed for layered request-local
    /// views, entropy acquisition failure, and a saturated revision counter.
    /// Consumers must also partition by every response-relevant authorization
    /// fact before sharing cached responses.
    #[doc(hidden)]
    #[must_use]
    pub fn cache_partition(&self) -> Option<([u8; CACHE_PARTITION_BYTES], u64)> {
        if self.ephemeral || self.local.is_some() {
            return None;
        }
        self.cache_admission_revision()
    }

    /// Returns a request-internal cache admission token and state revision.
    ///
    /// Unlike [`Self::cache_partition`], this remains available for ephemeral
    /// modern HTTP state. Cache middleware must ignore the opaque token when
    /// constructing a cross-request key for such state, but can use the full
    /// value to reject a lookup or population if the request-local bag changes
    /// during dispatch. Layered local views remain ineligible because their
    /// identity cannot safely describe both storage layers.
    #[doc(hidden)]
    #[must_use]
    pub fn cache_admission_revision(&self) -> Option<([u8; CACHE_PARTITION_BYTES], u64)> {
        if self.local.is_some() {
            return None;
        }
        // Synchronize partition sampling with shared-state writers. Without
        // this lock, a reader could observe the old revision after a writer
        // changed the map but before it published the revision increment, and
        // incorrectly serve an old cached response.
        let _state_guard = self.inner.lock().ok()?;
        let revision = self.revision.load(Ordering::Acquire);
        if revision == u64::MAX {
            return None;
        }
        Some((self.cache_partition?, revision))
    }

    /// Returns the stable opaque identity of this state owner for retained
    /// continuation binding.
    ///
    /// Unlike [`Self::cache_partition`], this remains available for
    /// request-local state. A one-shot transport request must not use this
    /// value as a cross-request response-cache identity, but it still needs a
    /// unique identity so a continuation minted during that request cannot be
    /// replayed through another request. Transport admission remains
    /// responsible for deciding whether the identity is authorized for
    /// continuation ownership.
    #[doc(hidden)]
    #[must_use]
    pub fn retained_continuation_partition(&self) -> Option<[u8; CACHE_PARTITION_BYTES]> {
        self.cache_partition
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
    use std::cell::Cell;

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

        let layered = state.with_local_overrides();
        assert!(layered.set_local("b", 3));
        assert!(layered.set_local("c", 4));
        assert_eq!(layered.len(), 2, "overridden keys count exactly once");
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
    fn panicking_key_conversion_does_not_poison_state_mutexes() {
        struct PanickingKey;

        impl From<PanickingKey> for String {
            fn from(_value: PanickingKey) -> Self {
                panic!("session-state-key-conversion-canary")
            }
        }

        let typed = SessionState::new();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = typed.set(PanickingKey, true);
            }))
            .is_err()
        );
        assert!(typed.set("after-typed-panic", true));

        let raw = SessionState::new();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = raw.set_raw(PanickingKey, serde_json::Value::Null);
            }))
            .is_err()
        );
        assert!(raw.set_raw("after-raw-panic", serde_json::Value::Null));

        let layered = SessionState::new().with_local_overrides();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = layered.set_local_raw(PanickingKey, serde_json::Value::Null);
            }))
            .is_err()
        );
        assert!(layered.set_local_raw("after-local-panic", serde_json::Value::Null));
    }

    #[test]
    fn ephemeral_session_state_stays_request_local_across_clone_and_snapshot() {
        let state = SessionState::ephemeral();
        assert!(state.is_ephemeral());
        assert!(state.cache_partition().is_none());
        assert!(state.cache_admission_revision().is_some());
        assert!(state.retained_continuation_partition().is_some());
        assert!(state.clone().is_ephemeral());
        assert_eq!(
            state.clone().retained_continuation_partition(),
            state.retained_continuation_partition()
        );
        assert!(state.with_local_overrides().is_ephemeral());
        assert!(state.snapshot().is_ephemeral());
        assert!(!SessionState::new().is_ephemeral());
    }

    #[test]
    fn cache_partition_is_clone_stable_and_mutation_versioned() {
        let state = SessionState::new();
        let initial = state
            .cache_partition()
            .expect("test platform must provide cache-partition entropy");
        let cloned = state.clone();
        assert_eq!(cloned.cache_partition(), Some(initial));

        assert!(cloned.set("key", "value"));
        let mutated = state
            .cache_partition()
            .expect("ordinary mutation keeps the partition available");
        assert_eq!(mutated.0, initial.0);
        assert_eq!(mutated.1, initial.1 + 1);
    }

    #[test]
    fn cache_partition_injected_draw_stores_exact_partition_once() {
        let expected = [0x5a; CACHE_PARTITION_BYTES];
        let calls = Cell::new(0);
        let state = SessionState::from_map_with_partition_draw(HashMap::new(), || {
            calls.set(calls.get() + 1);
            Ok::<[u8; CACHE_PARTITION_BYTES], &'static str>(expected)
        });

        assert_eq!(calls.get(), 1);
        assert_eq!(state.cache_partition(), Some((expected, 0)));
    }

    #[test]
    fn cache_partition_injected_draw_failure_is_rejected_once() {
        let calls = Cell::new(0);
        let state = SessionState::from_map_with_partition_draw(HashMap::new(), || {
            calls.set(calls.get() + 1);
            Err::<[u8; CACHE_PARTITION_BYTES], _>("deterministic RNG failure")
        });

        assert_eq!(calls.get(), 1);
        assert_eq!(state.cache_partition(), None);
    }

    #[test]
    fn snapshots_and_local_overrides_cannot_alias_a_cache_partition() {
        let state = SessionState::new();
        let live = state
            .cache_partition()
            .expect("test platform must provide cache-partition entropy");
        let snapshot = state.snapshot();
        let snapshot_partition = snapshot
            .cache_partition()
            .expect("snapshot must acquire an independent partition");

        assert_ne!(snapshot_partition.0, live.0);
        assert!(state.with_local_overrides().cache_partition().is_none());
    }

    #[test]
    fn saturated_cache_revision_fails_closed() {
        let state = SessionState::new();
        state.revision.store(u64::MAX, Ordering::Release);

        assert!(state.cache_partition().is_none());
        assert!(state.set("still", "mutable"));
        assert!(state.cache_partition().is_none());
    }

    #[test]
    fn stable_revision_never_observes_a_different_concurrent_value() {
        const WRITES: u64 = 2_000;
        let state = SessionState::new();
        assert!(state.set("counter", 0_u64));
        let writer_state = state.clone();
        let writer = std::thread::spawn(move || {
            for value in 1..=WRITES {
                assert!(writer_state.set("counter", value));
            }
        });

        while !writer.is_finished() {
            let before = state
                .cache_partition()
                .expect("test platform must provide cache-partition entropy");
            let value: u64 = state.get("counter").expect("counter remains present");
            let after = state.cache_partition().expect("revision remains available");
            if before == after {
                assert_eq!(before.1, value + 1);
            }
        }
        writer.join().expect("writer thread");

        let final_partition = state.cache_partition().expect("final partition");
        assert_eq!(final_partition.1, WRITES + 1);
        assert_eq!(state.get::<u64>("counter"), Some(WRITES));
    }

    #[test]
    fn cache_partition_waits_for_in_flight_state_mutation_publication() {
        let state = SessionState::new();
        let mut writer_guard = state.inner.lock().expect("state mutex");
        let sampler_state = state.clone();
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let (sample_tx, sample_rx) = std::sync::mpsc::sync_channel(0);
        let sampler = std::thread::spawn(move || {
            started_tx.send(()).expect("announce sampler");
            sample_tx
                .send(sampler_state.cache_partition())
                .expect("publish sample");
        });
        started_rx.recv().expect("sampler started");
        assert!(
            sample_rx
                .recv_timeout(std::time::Duration::from_millis(20))
                .is_err(),
            "partition sampling must wait while a state write is in flight"
        );

        writer_guard.insert("key".to_string(), serde_json::json!("value"));
        state.record_mutation();
        drop(writer_guard);

        let partition = sample_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("sampler unblocked")
            .expect("partition entropy available");
        sampler.join().expect("sampler thread");
        assert_eq!(partition.1, 1);
    }

    #[test]
    fn session_state_debug_reports_only_safe_counts_and_booleans() {
        const SECRET_KEY: &str = "authorization_bearer_canary_7f129";
        const SECRET_VALUE: &str = "customer-pii-canary@example.invalid";
        const LOCAL_SECRET_KEY: &str = "local-secret-key-canary-e81a";
        const LOCAL_SECRET_VALUE: &str = "local-secret-value-canary-29bd";

        let state = SessionState::new();
        assert!(state.set(SECRET_KEY, SECRET_VALUE));
        let layered = state.with_local_overrides();
        assert!(layered.set_local(LOCAL_SECRET_KEY, LOCAL_SECRET_VALUE));

        let debug = format!("{layered:?}");
        assert!(debug.contains("SessionState"));
        assert!(debug.contains("shared_entry_count: 1"));
        assert!(debug.contains("has_local_overrides: true"));
        assert!(debug.contains("local_entry_count: 1"));
        assert!(debug.contains("ephemeral: false"));
        for canary in [
            SECRET_KEY,
            SECRET_VALUE,
            LOCAL_SECRET_KEY,
            LOCAL_SECRET_VALUE,
        ] {
            assert!(
                !debug.contains(canary),
                "SessionState Debug leaked canary: {canary}"
            );
        }
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
