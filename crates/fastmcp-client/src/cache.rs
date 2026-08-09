//! Client-local caching for cacheable MCP 2026-07-28 complete results.
//!
//! The cache deliberately accepts an already-canonical request projection as
//! opaque input. Canonicalization remains a protocol-layer concern; this
//! module only appends the client-local partition and invalidation generation
//! needed to decide whether a retained complete result is fresh.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use fastmcp_protocol::{CacheScope, CoreResult, FinalCoreResult, ServerNotification};

/// Default maximum number of retained final complete results per client.
pub const DEFAULT_FINAL_CACHE_CAPACITY: usize = 128;

/// Opaque client-local partition for a final cache entry.
///
/// A caller must include the access-token instance discriminator whenever it
/// uses one cache across multiple credentials. The stdio [`crate::Client`]
/// keeps one cache per connection, so its default partition never crosses a
/// connection boundary.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CachePartitionKey(String);

impl CachePartitionKey {
    /// Creates a partition from a caller-owned opaque discriminator.
    #[must_use]
    pub fn new(discriminator: impl Into<String>) -> Self {
        Self(discriminator.into())
    }
}

/// The result set whose generation controls a cached complete result.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum FinalCacheResultSet {
    /// Final server discovery data.
    ServerDiscovery,
    /// `tools/list` pages.
    Tools,
    /// `resources/list` pages.
    Resources,
    /// `resources/templates/list` pages.
    ResourceTemplates,
    /// `prompts/list` pages.
    Prompts,
    /// One exact `resources/read` URI.
    Resource(String),
}

/// The complete client-side identity for one cacheable final request.
///
/// `semantic_projection` must be produced by the shared protocol cache-key
/// projection when that adapter is available. This cache intentionally never
/// parses, normalizes, or infers semantics from it. An absent cursor and an
/// empty cursor are distinct identities.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FinalCacheKey {
    endpoint_configuration: String,
    protocol_version: String,
    normalized_capabilities: String,
    extension_settings: String,
    method: String,
    semantic_projection: String,
    cursor: Option<String>,
    representation_policy_revision: u64,
    limits_policy_revision: u64,
    partition: CachePartitionKey,
    result_set: FinalCacheResultSet,
}

impl FinalCacheKey {
    /// Creates a complete final cache identity from already-canonical inputs.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        endpoint_configuration: impl Into<String>,
        protocol_version: impl Into<String>,
        normalized_capabilities: impl Into<String>,
        extension_settings: impl Into<String>,
        method: impl Into<String>,
        semantic_projection: impl Into<String>,
        cursor: Option<String>,
        representation_policy_revision: u64,
        limits_policy_revision: u64,
        partition: CachePartitionKey,
        result_set: FinalCacheResultSet,
    ) -> Self {
        Self {
            endpoint_configuration: endpoint_configuration.into(),
            protocol_version: protocol_version.into(),
            normalized_capabilities: normalized_capabilities.into(),
            extension_settings: extension_settings.into(),
            method: method.into(),
            semantic_projection: semantic_projection.into(),
            cursor,
            representation_policy_revision,
            limits_policy_revision,
            partition,
            result_set,
        }
    }

    /// Returns the result set invalidated with this entry.
    #[must_use]
    pub const fn result_set(&self) -> &FinalCacheResultSet {
        &self.result_set
    }
}

/// A generation captured before a request is sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalCacheGeneration(u64);

/// Why a cache lookup did not return a fresh result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalCacheMiss {
    /// The caller disabled caching.
    Disabled,
    /// No entry exists for the exact key.
    Absent,
    /// The entry reached its per-page TTL.
    Stale,
    /// A notification advanced the result-set generation.
    Invalidated,
}

/// Result of looking up a final complete result.
#[derive(Clone, Debug)]
pub enum FinalCacheLookup {
    /// A complete validated result that remains fresh.
    Fresh(CoreResult),
    /// The caller must fetch a result before it can continue.
    Miss(FinalCacheMiss),
}

/// Result of attempting to retain a fetched result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalCacheInsert {
    /// The complete result was retained in the local credential partition.
    Stored,
    /// The result had no final complete cache hints or was otherwise ineligible.
    NotCacheable,
    /// A zero TTL makes the result immediately stale.
    ImmediatelyStale,
    /// An invalidation won while the request was in flight.
    InvalidatedDuringFetch,
    /// The monotonic expiry could not be represented.
    ExpiryOutOfRange,
}

/// Bounded, client-local cache counters with no key or result labels.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FinalCacheStats {
    /// Fresh complete results returned from the cache.
    pub hits: u64,
    /// Lookups that did not return a fresh result.
    pub misses: u64,
    /// Entries rejected because their TTL expired.
    pub stale: u64,
    /// Complete results retained after a fetch.
    pub fills: u64,
    /// Notification-driven result-set invalidations.
    pub invalidations: u64,
    /// Entries evicted because the bounded cache was full.
    pub evictions: u64,
}

#[derive(Clone, Debug)]
struct FinalCacheEntry {
    result: CoreResult,
    generation: FinalCacheGeneration,
    receipt: Instant,
    expires_at: Instant,
    scope: CacheScope,
}

/// A bounded cache of exact final complete results.
///
/// Peer `public` hints are retained as data but do not weaken the supplied
/// [`CachePartitionKey`]. Cross-principal reuse requires a separately
/// revisioned trust policy and is intentionally not inferred from peer data.
#[derive(Debug)]
pub struct FinalResultCache {
    enabled: bool,
    capacity: usize,
    entries: HashMap<FinalCacheKey, FinalCacheEntry>,
    generations: HashMap<FinalCacheResultSet, u64>,
    stats: FinalCacheStats,
}

impl FinalResultCache {
    /// Creates an enabled cache with at least one retained-entry slot.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            enabled: true,
            capacity: capacity.max(1),
            entries: HashMap::new(),
            generations: HashMap::new(),
            stats: FinalCacheStats::default(),
        }
    }

    /// Returns whether lookups and fills are enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enables or disables cache use without discarding retained entries.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns bounded aggregate cache counters.
    #[must_use]
    pub const fn stats(&self) -> FinalCacheStats {
        self.stats
    }

    /// Removes every retained entry while preserving configuration and counters.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Captures the result-set generation before a request begins.
    #[must_use]
    pub fn begin_fetch(&self, result_set: &FinalCacheResultSet) -> FinalCacheGeneration {
        FinalCacheGeneration(self.generation(result_set))
    }

    /// Looks up one complete result at the supplied monotonic instant.
    pub fn lookup_at(&mut self, key: &FinalCacheKey, now: Instant) -> FinalCacheLookup {
        if !self.enabled {
            self.stats.misses = self.stats.misses.saturating_add(1);
            return FinalCacheLookup::Miss(FinalCacheMiss::Disabled);
        }

        let Some(entry) = self.entries.get(key) else {
            self.stats.misses = self.stats.misses.saturating_add(1);
            return FinalCacheLookup::Miss(FinalCacheMiss::Absent);
        };
        let entry_generation = entry.generation;
        let expires_at = entry.expires_at;
        let result = entry.result.clone();

        let miss = if entry_generation != self.begin_fetch(key.result_set()) {
            Some(FinalCacheMiss::Invalidated)
        } else if now >= expires_at {
            Some(FinalCacheMiss::Stale)
        } else {
            None
        };

        if let Some(miss) = miss {
            self.entries.remove(key);
            self.stats.misses = self.stats.misses.saturating_add(1);
            if miss == FinalCacheMiss::Stale {
                self.stats.stale = self.stats.stale.saturating_add(1);
            }
            return FinalCacheLookup::Miss(miss);
        }

        self.stats.hits = self.stats.hits.saturating_add(1);
        FinalCacheLookup::Fresh(result)
    }

    /// Looks up one complete result using the current monotonic instant.
    pub fn lookup(&mut self, key: &FinalCacheKey) -> FinalCacheLookup {
        self.lookup_at(key, Instant::now())
    }

    /// Retains a fetched result only when its captured generation is current.
    pub fn insert_if_current_at(
        &mut self,
        key: FinalCacheKey,
        captured_generation: FinalCacheGeneration,
        result: CoreResult,
        receipt: Instant,
    ) -> FinalCacheInsert {
        if !self.enabled || captured_generation != self.begin_fetch(key.result_set()) {
            return FinalCacheInsert::InvalidatedDuringFetch;
        }

        let Some((ttl_ms, scope)) = final_cache_hints(&result) else {
            return FinalCacheInsert::NotCacheable;
        };
        if ttl_ms == 0 {
            return FinalCacheInsert::ImmediatelyStale;
        }
        let Some(expires_at) = receipt.checked_add(Duration::from_millis(ttl_ms)) else {
            return FinalCacheInsert::ExpiryOutOfRange;
        };

        if self.entries.len() >= self.capacity && !self.entries.contains_key(&key) {
            self.evict_oldest();
        }
        self.entries.insert(
            key,
            FinalCacheEntry {
                result,
                generation: captured_generation,
                receipt,
                expires_at,
                scope,
            },
        );
        self.stats.fills = self.stats.fills.saturating_add(1);
        FinalCacheInsert::Stored
    }

    /// Retains a fetched result using the current monotonic instant.
    pub fn insert_if_current(
        &mut self,
        key: FinalCacheKey,
        captured_generation: FinalCacheGeneration,
        result: CoreResult,
    ) -> FinalCacheInsert {
        self.insert_if_current_at(key, captured_generation, result, Instant::now())
    }

    /// Advances a result-set generation before removing its previous entries.
    pub fn invalidate_result_set(&mut self, result_set: &FinalCacheResultSet) {
        let generation = self.generation(result_set).saturating_add(1);
        self.generations.insert(result_set.clone(), generation);
        self.entries.retain(|key, _| key.result_set() != result_set);
        self.stats.invalidations = self.stats.invalidations.saturating_add(1);
    }

    /// Invalidates cacheable result sets selected by a final server notification.
    pub fn invalidate_notification(&mut self, notification: &ServerNotification) {
        match notification {
            ServerNotification::ToolsListChanged(_) => {
                self.invalidate_result_set(&FinalCacheResultSet::Tools);
            }
            ServerNotification::ResourcesListChanged(_) => {
                self.invalidate_result_set(&FinalCacheResultSet::Resources);
                self.invalidate_result_set(&FinalCacheResultSet::ResourceTemplates);
            }
            ServerNotification::PromptsListChanged(_) => {
                self.invalidate_result_set(&FinalCacheResultSet::Prompts);
            }
            ServerNotification::ResourceUpdated(params) => {
                self.invalidate_result_set(&FinalCacheResultSet::Resource(
                    params.uri.as_str().to_owned(),
                ));
            }
            ServerNotification::Cancelled(_)
            | ServerNotification::Progress(_)
            | ServerNotification::Message(_)
            | ServerNotification::SubscriptionsAcknowledged(_) => {}
        }
    }

    fn generation(&self, result_set: &FinalCacheResultSet) -> u64 {
        self.generations.get(result_set).copied().unwrap_or(0)
    }

    fn evict_oldest(&mut self) {
        let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.receipt)
            .map(|(key, _)| key.clone())
        else {
            return;
        };
        self.entries.remove(&oldest);
        self.stats.evictions = self.stats.evictions.saturating_add(1);
    }
}

impl Default for FinalResultCache {
    fn default() -> Self {
        Self::new(DEFAULT_FINAL_CACHE_CAPACITY)
    }
}

fn final_cache_hints(result: &CoreResult) -> Option<(u64, CacheScope)> {
    let CoreResult::Final(result) = result else {
        return None;
    };
    match result {
        FinalCoreResult::Discover(result) => {
            let hints = result.cache_hints();
            Some((
                hints.ttl_ms(),
                if hints.is_public() {
                    CacheScope::Public
                } else {
                    CacheScope::Private
                },
            ))
        }
        FinalCoreResult::ToolsList { result, .. } => {
            Some((result.payload.ttl_ms, result.payload.cache_scope))
        }
        FinalCoreResult::ResourcesList { result, .. } => {
            Some((result.payload.ttl_ms, result.payload.cache_scope))
        }
        FinalCoreResult::ResourceTemplatesList { result, .. } => {
            Some((result.payload.ttl_ms, result.payload.cache_scope))
        }
        FinalCoreResult::ResourcesRead { result, .. } => {
            Some((result.payload.ttl_ms, result.payload.cache_scope))
        }
        FinalCoreResult::PromptsList { result, .. } => {
            Some((result.payload.ttl_ms, result.payload.cache_scope))
        }
        FinalCoreResult::Completion { .. }
        | FinalCoreResult::ToolsCall { .. }
        | FinalCoreResult::ToolsCallTask { .. }
        | FinalCoreResult::ToolsCallInputRequired { .. }
        | FinalCoreResult::ResourcesReadInputRequired { .. }
        | FinalCoreResult::PromptsGet { .. }
        | FinalCoreResult::PromptsGetInputRequired { .. }
        | FinalCoreResult::SubscriptionsListen { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use fastmcp_protocol::{CoreRequest, FinalCoreRequest, FinalListParams, OpenMetadata};

    use super::*;

    fn key(partition: &str, cursor: Option<&str>) -> FinalCacheKey {
        FinalCacheKey::new(
            "stdio",
            "2026-07-28",
            "{}",
            "{}",
            "tools/list",
            "{\"includeTags\":null,\"excludeTags\":null}",
            cursor.map(ToOwned::to_owned),
            0,
            0,
            CachePartitionKey::new(partition),
            FinalCacheResultSet::Tools,
        )
    }

    fn tools_result(ttl_ms: u64, scope: &str, extra: Option<&str>) -> CoreResult {
        let request = CoreRequest::Final(FinalCoreRequest::ToolsList(FinalListParams {
            meta: OpenMetadata::default(),
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        }));
        let suffix = extra.map_or_else(String::new, |extra| format!(",{extra}"));
        request
            .decode_result(&format!(
                r#"{{"resultType":"complete","tools":[],"ttlMs":{ttl_ms},"cacheScope":"{scope}"{suffix}}}"#
            ))
            .expect("the cache fixture is an admitted final complete result")
    }

    fn notification(method: &str, params: Option<serde_json::Value>) -> ServerNotification {
        ServerNotification::decode(&fastmcp_protocol::JsonRpcRequest::notification(method, params))
            .expect("the cache fixture is an admitted final server notification")
    }

    #[test]
    fn ttl_is_per_page_and_never_returns_stale_as_fresh() {
        let mut cache = FinalResultCache::default();
        let key = key("credential-a", Some("opaque-page-2"));
        let receipt = Instant::now();
        let generation = cache.begin_fetch(key.result_set());
        assert_eq!(
            cache.insert_if_current_at(
                key.clone(),
                generation,
                tools_result(20, "private", None),
                receipt,
            ),
            FinalCacheInsert::Stored
        );
        assert!(matches!(
            cache.lookup_at(&key, receipt + Duration::from_millis(19)),
            FinalCacheLookup::Fresh(_)
        ));
        assert!(matches!(
            cache.lookup_at(&key, receipt + Duration::from_millis(20)),
            FinalCacheLookup::Miss(FinalCacheMiss::Stale)
        ));
        assert_eq!(cache.stats().stale, 1);
    }

    #[test]
    fn zero_ttl_and_input_required_never_create_fresh_entries() {
        let mut cache = FinalResultCache::default();
        let key = key("credential-a", None);
        let generation = cache.begin_fetch(key.result_set());
        assert_eq!(
            cache.insert_if_current(key.clone(), generation, tools_result(0, "private", None)),
            FinalCacheInsert::ImmediatelyStale
        );

        let request = CoreRequest::Final(FinalCoreRequest::ResourcesRead(
            fastmcp_protocol::FinalReadResourceParams {
                meta: OpenMetadata::default(),
                uri: serde_json::from_str("\"file:///input-required.txt\"")
                    .expect("absolute URI fixture"),
                input_responses: None,
                request_state: None,
            },
        ));
        let input_required = request
            .decode_result(
                r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"ttlMs":99,"cacheScope":"public"}"#,
            )
            .expect("inert cache-like extras remain a typed input-required result");
        let input_key = FinalCacheKey::new(
            "stdio",
            "2026-07-28",
            "{}",
            "{}",
            "resources/read",
            "{\"uri\":\"file:///input-required.txt\"}",
            None,
            0,
            0,
            CachePartitionKey::new("credential-a"),
            FinalCacheResultSet::Resource("file:///input-required.txt".to_owned()),
        );
        let generation = cache.begin_fetch(input_key.result_set());
        assert_eq!(
            cache.insert_if_current(input_key, generation, input_required),
            FinalCacheInsert::NotCacheable
        );
    }

    #[test]
    fn public_peer_hint_stays_in_the_local_credential_partition() {
        let mut cache = FinalResultCache::default();
        let private_key = key("credential-a", None);
        let generation = cache.begin_fetch(private_key.result_set());
        assert_eq!(
            cache.insert_if_current(
                private_key.clone(),
                generation,
                tools_result(100, "public", None),
            ),
            FinalCacheInsert::Stored
        );
        assert!(matches!(cache.lookup(&private_key), FinalCacheLookup::Fresh(_)));
        assert!(matches!(
            cache.lookup(&key("credential-b", None)),
            FinalCacheLookup::Miss(FinalCacheMiss::Absent)
        ));
    }

    #[test]
    fn notifications_advance_generation_before_late_fetch_can_fill() {
        let mut cache = FinalResultCache::default();
        let key = key("credential-a", None);
        let generation = cache.begin_fetch(key.result_set());
        cache.invalidate_notification(&notification("notifications/tools/list_changed", None));
        assert_eq!(
            cache.insert_if_current(key.clone(), generation, tools_result(100, "private", None)),
            FinalCacheInsert::InvalidatedDuringFetch
        );
        assert!(matches!(
            cache.lookup(&key),
            FinalCacheLookup::Miss(FinalCacheMiss::Absent)
        ));
    }

    #[test]
    fn resource_update_invalidates_only_the_exact_resource_and_replays_unknown_members() {
        let mut cache = FinalResultCache::default();
        let resource_key = FinalCacheKey::new(
            "stdio",
            "2026-07-28",
            "{}",
            "{}",
            "resources/read",
            "{\"uri\":\"file:///changed.txt\"}",
            None,
            0,
            0,
            CachePartitionKey::new("credential-a"),
            FinalCacheResultSet::Resource("file:///changed.txt".to_owned()),
        );
        let request = CoreRequest::Final(FinalCoreRequest::ResourcesRead(
            fastmcp_protocol::FinalReadResourceParams {
                meta: OpenMetadata::default(),
                uri: serde_json::from_str("\"file:///changed.txt\"")
                    .expect("absolute URI fixture"),
                input_responses: None,
                request_state: None,
            },
        ));
        let result = request
            .decode_result(
                r#"{"resultType":"complete","contents":[],"ttlMs":100,"cacheScope":"private","x-retained":9007199254740993123456789}"#,
            )
            .expect("complete resource result with an unknown number is admitted");
        let expected = result.encode().expect("complete result re-encodes");
        let generation = cache.begin_fetch(resource_key.result_set());
        assert_eq!(
            cache.insert_if_current(resource_key.clone(), generation, result),
            FinalCacheInsert::Stored
        );
        let FinalCacheLookup::Fresh(replayed) = cache.lookup(&resource_key) else {
            panic!("fresh cached resource result expected");
        };
        assert_eq!(replayed.encode().expect("cached result re-encodes"), expected);

        cache.invalidate_notification(&notification(
            "notifications/resources/updated",
            Some(serde_json::json!({"uri": "file:///changed.txt"})),
        ));
        assert!(matches!(
            cache.lookup(&resource_key),
            FinalCacheLookup::Miss(FinalCacheMiss::Absent)
        ));
    }
}
