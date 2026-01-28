//! Event store for SSE resumability.
//!
//! This module provides an [`EventStore`] that enables SSE polling and
//! resumability by storing events that can be replayed when clients reconnect.
//!
//! # SSE Resumability
//!
//! When a client disconnects from an SSE stream, it may miss events. The
//! `Last-Event-ID` header allows clients to indicate where they left off,
//! and the server can replay missed events using the EventStore.
//!
//! # Features
//!
//! - **TTL-based event retention**: Events automatically expire after a configurable duration
//! - **Per-stream event limits**: Prevents unbounded memory growth
//! - **Cursor-based resumption**: Replay events from any point using event IDs
//! - **Thread-safe**: Safe for concurrent access from multiple handlers
//!
//! # Example
//!
//! ```
//! use fastmcp_transport::event_store::{EventStore, EventStoreConfig};
//! use std::time::Duration;
//!
//! // Create event store with custom configuration
//! let store = EventStore::with_config(EventStoreConfig {
//!     max_events_per_stream: 100,
//!     ttl: Some(Duration::from_secs(3600)), // 1 hour
//! });
//!
//! // Store an event
//! let stream_id = "session-123";
//! let event_id = store.store_event(stream_id, Some(serde_json::json!({"method": "test"})));
//!
//! // Replay events after a specific ID
//! let events = store.get_events_after(stream_id, None); // Get all events
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Default maximum events per stream.
pub const DEFAULT_MAX_EVENTS_PER_STREAM: usize = 100;

/// Default TTL for events (1 hour).
pub const DEFAULT_TTL_SECS: u64 = 3600;

/// Unique identifier for an event.
pub type EventId = String;

/// Unique identifier for a stream (session).
pub type StreamId = String;

/// A stored event with metadata.
#[derive(Debug, Clone)]
pub struct EventEntry {
    /// Unique event identifier.
    pub id: EventId,
    /// Stream this event belongs to.
    pub stream_id: StreamId,
    /// Event data (None for priming events).
    pub data: Option<serde_json::Value>,
    /// When this event was stored.
    pub created_at: Instant,
}

impl EventEntry {
    /// Creates a new event entry.
    fn new(id: EventId, stream_id: StreamId, data: Option<serde_json::Value>) -> Self {
        Self {
            id,
            stream_id,
            data,
            created_at: Instant::now(),
        }
    }

    /// Returns true if this event has expired based on the given TTL.
    fn is_expired(&self, ttl: Option<Duration>) -> bool {
        match ttl {
            Some(ttl) => self.created_at.elapsed() > ttl,
            None => false,
        }
    }
}

/// Configuration for the event store.
#[derive(Debug, Clone)]
pub struct EventStoreConfig {
    /// Maximum number of events to retain per stream.
    pub max_events_per_stream: usize,
    /// Time-to-live for events. `None` means events never expire.
    pub ttl: Option<Duration>,
}

impl Default for EventStoreConfig {
    fn default() -> Self {
        Self {
            max_events_per_stream: DEFAULT_MAX_EVENTS_PER_STREAM,
            ttl: Some(Duration::from_secs(DEFAULT_TTL_SECS)),
        }
    }
}

impl EventStoreConfig {
    /// Creates a config with no TTL (events never expire).
    #[must_use]
    pub fn no_expiry() -> Self {
        Self {
            ttl: None,
            ..Default::default()
        }
    }

    /// Sets the maximum events per stream.
    #[must_use]
    pub fn max_events(mut self, max: usize) -> Self {
        self.max_events_per_stream = max;
        self
    }

    /// Sets the TTL for events.
    #[must_use]
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Disables TTL (events never expire).
    #[must_use]
    pub fn no_ttl(mut self) -> Self {
        self.ttl = None;
        self
    }
}

/// Internal storage for a single stream's events.
#[derive(Debug)]
struct StreamEvents {
    /// Events in insertion order (oldest first).
    events: VecDeque<EventEntry>,
    /// Map from event ID to index for fast lookup.
    index: HashMap<EventId, usize>,
}

impl StreamEvents {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            index: HashMap::new(),
        }
    }

    /// Adds an event, enforcing max events limit.
    fn push(&mut self, entry: EventEntry, max_events: usize) {
        // Remove oldest if at capacity
        while self.events.len() >= max_events {
            if let Some(oldest) = self.events.pop_front() {
                self.index.remove(&oldest.id);
            }
            // Rebuild index after removal (indices shifted)
            self.rebuild_index();
        }

        let idx = self.events.len();
        self.index.insert(entry.id.clone(), idx);
        self.events.push_back(entry);
    }

    /// Removes expired events.
    fn remove_expired(&mut self, ttl: Option<Duration>) {
        if ttl.is_none() {
            return;
        }

        let mut removed = false;
        while let Some(front) = self.events.front() {
            if front.is_expired(ttl) {
                if let Some(entry) = self.events.pop_front() {
                    self.index.remove(&entry.id);
                    removed = true;
                }
            } else {
                break;
            }
        }

        if removed {
            self.rebuild_index();
        }
    }

    /// Rebuilds the index after removals.
    fn rebuild_index(&mut self) {
        self.index.clear();
        for (idx, entry) in self.events.iter().enumerate() {
            self.index.insert(entry.id.clone(), idx);
        }
    }

    /// Gets events after the specified ID (exclusive).
    fn events_after(&self, after_id: Option<&str>) -> Vec<EventEntry> {
        match after_id {
            None => self.events.iter().cloned().collect(),
            Some(id) => {
                if let Some(&idx) = self.index.get(id) {
                    self.events.iter().skip(idx + 1).cloned().collect()
                } else {
                    // ID not found, return empty (client should reconnect fresh)
                    Vec::new()
                }
            }
        }
    }

    /// Finds the stream ID for a given event ID.
    fn contains(&self, event_id: &str) -> bool {
        self.index.contains_key(event_id)
    }
}

/// Thread-safe event store for SSE resumability.
///
/// Stores events per stream with automatic expiration and size limits.
/// Use this to enable clients to resume SSE streams after disconnection.
///
/// # Thread Safety
///
/// The EventStore uses `RwLock` internally and is safe for concurrent
/// access from multiple threads.
#[derive(Debug)]
pub struct EventStore {
    /// Configuration.
    config: EventStoreConfig,
    /// Per-stream event storage.
    streams: RwLock<HashMap<StreamId, StreamEvents>>,
    /// Counter for generating unique event IDs.
    event_counter: AtomicU64,
}

impl Default for EventStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EventStore {
    /// Creates a new event store with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(EventStoreConfig::default())
    }

    /// Creates a new event store with custom configuration.
    #[must_use]
    pub fn with_config(config: EventStoreConfig) -> Self {
        Self {
            config,
            streams: RwLock::new(HashMap::new()),
            event_counter: AtomicU64::new(0),
        }
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &EventStoreConfig {
        &self.config
    }

    /// Generates a unique event ID.
    fn generate_event_id(&self) -> EventId {
        let counter = self.event_counter.fetch_add(1, Ordering::Relaxed);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("{timestamp}-{counter}")
    }

    /// Stores an event and returns its ID.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The stream (session) this event belongs to
    /// * `data` - Event data, or `None` for a priming event
    ///
    /// # Returns
    ///
    /// The unique event ID that can be used for resumption.
    pub fn store_event(&self, stream_id: &str, data: Option<serde_json::Value>) -> EventId {
        let event_id = self.generate_event_id();
        let entry = EventEntry::new(event_id.clone(), stream_id.to_string(), data);

        let mut streams = self
            .streams
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let stream = streams
            .entry(stream_id.to_string())
            .or_insert_with(StreamEvents::new);

        // Clean up expired events first
        stream.remove_expired(self.config.ttl);

        // Add the new event
        stream.push(entry, self.config.max_events_per_stream);

        event_id
    }

    /// Stores a priming event (empty data) for SSE initialization.
    ///
    /// Per SSE spec, servers should send an event with just an ID to prime
    /// the client's `Last-Event-ID` tracking.
    pub fn store_priming_event(&self, stream_id: &str) -> EventId {
        self.store_event(stream_id, None)
    }

    /// Gets events after the specified event ID.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The stream to get events from
    /// * `after_id` - Get events after this ID (exclusive). `None` returns all events.
    ///
    /// # Returns
    ///
    /// Vector of events in chronological order.
    #[must_use]
    pub fn get_events_after(&self, stream_id: &str, after_id: Option<&str>) -> Vec<EventEntry> {
        let mut streams = self
            .streams
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(stream) = streams.get_mut(stream_id) {
            // Clean up expired events first
            stream.remove_expired(self.config.ttl);
            stream.events_after(after_id)
        } else {
            Vec::new()
        }
    }

    /// Replays events after a specific event ID using a callback.
    ///
    /// This is the primary method for SSE resumption. When a client reconnects
    /// with a `Last-Event-ID`, use this to replay missed events.
    ///
    /// # Arguments
    ///
    /// * `last_event_id` - The client's last received event ID
    /// * `callback` - Called for each event to replay
    ///
    /// # Returns
    ///
    /// The stream ID if the event was found, `None` otherwise.
    pub fn replay_events_after<F>(&self, last_event_id: &str, mut callback: F) -> Option<StreamId>
    where
        F: FnMut(&EventEntry),
    {
        let streams = self
            .streams
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Find which stream contains this event
        for (stream_id, stream) in streams.iter() {
            if stream.contains(last_event_id) {
                let events = stream.events_after(Some(last_event_id));
                for event in events {
                    callback(&event);
                }
                return Some(stream_id.clone());
            }
        }

        None
    }

    /// Looks up the stream ID for a given event ID.
    ///
    /// # Returns
    ///
    /// The stream ID if the event exists, `None` otherwise.
    #[must_use]
    pub fn find_stream_for_event(&self, event_id: &str) -> Option<StreamId> {
        let streams = self
            .streams
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        for (stream_id, stream) in streams.iter() {
            if stream.contains(event_id) {
                return Some(stream_id.clone());
            }
        }

        None
    }

    /// Removes all events for a stream.
    ///
    /// Call this when a session ends to free memory.
    pub fn clear_stream(&self, stream_id: &str) {
        let mut streams = self
            .streams
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        streams.remove(stream_id);
    }

    /// Removes all expired events across all streams.
    ///
    /// This is called automatically during operations, but you can call
    /// it manually for cleanup.
    pub fn cleanup_expired(&self) {
        if self.config.ttl.is_none() {
            return;
        }

        let mut streams = self
            .streams
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Remove expired events from each stream
        for stream in streams.values_mut() {
            stream.remove_expired(self.config.ttl);
        }

        // Remove empty streams
        streams.retain(|_, stream| !stream.events.is_empty());
    }

    /// Returns the number of streams currently stored.
    #[must_use]
    pub fn stream_count(&self) -> usize {
        let streams = self
            .streams
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        streams.len()
    }

    /// Returns the total number of events across all streams.
    #[must_use]
    pub fn event_count(&self) -> usize {
        let streams = self
            .streams
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        streams.values().map(|s| s.events.len()).sum()
    }

    /// Returns statistics about the event store.
    #[must_use]
    pub fn stats(&self) -> EventStoreStats {
        let streams = self
            .streams
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let total_events: usize = streams.values().map(|s| s.events.len()).sum();

        EventStoreStats {
            stream_count: streams.len(),
            total_events,
            max_events_per_stream: self.config.max_events_per_stream,
            ttl: self.config.ttl,
        }
    }
}

/// Statistics about the event store.
#[derive(Debug, Clone)]
pub struct EventStoreStats {
    /// Number of streams.
    pub stream_count: usize,
    /// Total events across all streams.
    pub total_events: usize,
    /// Configured max events per stream.
    pub max_events_per_stream: usize,
    /// Configured TTL.
    pub ttl: Option<Duration>,
}

/// A shared event store for use across multiple handlers.
pub type SharedEventStore = Arc<EventStore>;

/// Creates a shared event store with default configuration.
#[must_use]
pub fn create_shared_event_store() -> SharedEventStore {
    Arc::new(EventStore::new())
}

/// Creates a shared event store with custom configuration.
#[must_use]
pub fn create_shared_event_store_with_config(config: EventStoreConfig) -> SharedEventStore {
    Arc::new(EventStore::with_config(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_retrieve_event() {
        let store = EventStore::new();

        let event_id = store.store_event("stream1", Some(serde_json::json!({"test": true})));
        assert!(!event_id.is_empty());

        let events = store.get_events_after("stream1", None);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event_id);
        assert!(events[0].data.is_some());
    }

    #[test]
    fn test_store_priming_event() {
        let store = EventStore::new();

        let event_id = store.store_priming_event("stream1");
        assert!(!event_id.is_empty());

        let events = store.get_events_after("stream1", None);
        assert_eq!(events.len(), 1);
        assert!(events[0].data.is_none());
    }

    #[test]
    fn test_events_after_id() {
        let store = EventStore::new();

        let id1 = store.store_event("stream1", Some(serde_json::json!({"n": 1})));
        let id2 = store.store_event("stream1", Some(serde_json::json!({"n": 2})));
        let id3 = store.store_event("stream1", Some(serde_json::json!({"n": 3})));

        // Get events after id1 (should return id2 and id3)
        let events = store.get_events_after("stream1", Some(&id1));
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, id2);
        assert_eq!(events[1].id, id3);

        // Get events after id2 (should return id3)
        let events = store.get_events_after("stream1", Some(&id2));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, id3);

        // Get events after id3 (should return nothing)
        let events = store.get_events_after("stream1", Some(&id3));
        assert!(events.is_empty());
    }

    #[test]
    fn test_multiple_streams() {
        let store = EventStore::new();

        let id1 = store.store_event("stream1", Some(serde_json::json!({"stream": 1})));
        let id2 = store.store_event("stream2", Some(serde_json::json!({"stream": 2})));

        let events1 = store.get_events_after("stream1", None);
        let events2 = store.get_events_after("stream2", None);

        assert_eq!(events1.len(), 1);
        assert_eq!(events1[0].id, id1);

        assert_eq!(events2.len(), 1);
        assert_eq!(events2[0].id, id2);
    }

    #[test]
    fn test_max_events_limit() {
        let config = EventStoreConfig::default().max_events(3);
        let store = EventStore::with_config(config);

        let _id1 = store.store_event("stream1", Some(serde_json::json!({"n": 1})));
        let _id2 = store.store_event("stream1", Some(serde_json::json!({"n": 2})));
        let id3 = store.store_event("stream1", Some(serde_json::json!({"n": 3})));
        let id4 = store.store_event("stream1", Some(serde_json::json!({"n": 4})));

        // Should only have 3 events (oldest removed)
        let events = store.get_events_after("stream1", None);
        assert_eq!(events.len(), 3);

        // First event should be id2 (id1 was evicted)
        // Actually first should be id2 since we push id4 after id3
        // With max 3: after adding id4, we have id2, id3, id4
        assert_eq!(events[1].id, id3);
        assert_eq!(events[2].id, id4);
    }

    #[test]
    fn test_replay_events() {
        let store = EventStore::new();

        let id1 = store.store_event("stream1", Some(serde_json::json!({"n": 1})));
        let id2 = store.store_event("stream1", Some(serde_json::json!({"n": 2})));
        let id3 = store.store_event("stream1", Some(serde_json::json!({"n": 3})));

        let mut replayed = Vec::new();
        let stream_id = store.replay_events_after(&id1, |event| {
            replayed.push(event.id.clone());
        });

        assert_eq!(stream_id, Some("stream1".to_string()));
        assert_eq!(replayed, vec![id2, id3]);
    }

    #[test]
    fn test_replay_unknown_event_id() {
        let store = EventStore::new();
        store.store_event("stream1", Some(serde_json::json!({})));

        let mut replayed = Vec::new();
        let stream_id = store.replay_events_after("nonexistent", |event| {
            replayed.push(event.id.clone());
        });

        assert!(stream_id.is_none());
        assert!(replayed.is_empty());
    }

    #[test]
    fn test_find_stream_for_event() {
        let store = EventStore::new();

        let id1 = store.store_event("stream1", Some(serde_json::json!({})));
        let id2 = store.store_event("stream2", Some(serde_json::json!({})));

        assert_eq!(
            store.find_stream_for_event(&id1),
            Some("stream1".to_string())
        );
        assert_eq!(
            store.find_stream_for_event(&id2),
            Some("stream2".to_string())
        );
        assert_eq!(store.find_stream_for_event("nonexistent"), None);
    }

    #[test]
    fn test_clear_stream() {
        let store = EventStore::new();

        store.store_event("stream1", Some(serde_json::json!({})));
        store.store_event("stream2", Some(serde_json::json!({})));

        assert_eq!(store.stream_count(), 2);

        store.clear_stream("stream1");

        assert_eq!(store.stream_count(), 1);
        assert!(store.get_events_after("stream1", None).is_empty());
    }

    #[test]
    fn test_event_expiration() {
        let config = EventStoreConfig {
            max_events_per_stream: 100,
            ttl: Some(Duration::from_millis(10)),
        };
        let store = EventStore::with_config(config);

        store.store_event("stream1", Some(serde_json::json!({})));

        // Events should exist initially
        assert_eq!(store.get_events_after("stream1", None).len(), 1);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        // Events should be gone after cleanup
        store.cleanup_expired();
        assert!(store.get_events_after("stream1", None).is_empty());
    }

    #[test]
    fn test_no_expiration() {
        let config = EventStoreConfig::no_expiry();
        let store = EventStore::with_config(config);

        store.store_event("stream1", Some(serde_json::json!({})));

        // Even after cleanup, events should remain
        store.cleanup_expired();
        assert_eq!(store.get_events_after("stream1", None).len(), 1);
    }

    #[test]
    fn test_stats() {
        let store = EventStore::new();

        store.store_event("stream1", Some(serde_json::json!({})));
        store.store_event("stream1", Some(serde_json::json!({})));
        store.store_event("stream2", Some(serde_json::json!({})));

        let stats = store.stats();
        assert_eq!(stats.stream_count, 2);
        assert_eq!(stats.total_events, 3);
    }

    #[test]
    fn test_shared_event_store() {
        let store = create_shared_event_store();

        // Clone for multiple "handlers"
        let store1 = Arc::clone(&store);
        let store2 = Arc::clone(&store);

        store1.store_event("stream1", Some(serde_json::json!({"from": 1})));
        store2.store_event("stream1", Some(serde_json::json!({"from": 2})));

        assert_eq!(store.event_count(), 2);
    }

    #[test]
    fn test_unique_event_ids() {
        let store = EventStore::new();

        let id1 = store.store_event("stream1", None);
        let id2 = store.store_event("stream1", None);
        let id3 = store.store_event("stream2", None);

        // All IDs should be unique
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_config_builder() {
        let config = EventStoreConfig::default()
            .max_events(50)
            .ttl(Duration::from_secs(300));

        assert_eq!(config.max_events_per_stream, 50);
        assert_eq!(config.ttl, Some(Duration::from_secs(300)));

        let config = config.no_ttl();
        assert!(config.ttl.is_none());
    }
}
