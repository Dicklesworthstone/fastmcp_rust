//! Bounded complete catalog collection, with optional credential-local caching.
//!
//! The four core catalog methods share cursor handling, per-page protocol
//! admission, and whole-collection budgets. Only cursor changes between pages.
//! A returned collection contains every remaining page or no pages at all;
//! notifications are delivered immediately even when a later page fails.
//!
//! Caching is explicitly enabled with `with_cache_limits`. Each client owns one
//! cache bound to one managed login. Clones share that cache. All encoded request
//! parameters, including metadata, participate in its conservative exact-request
//! identity; this is not the general all-and-only-semantic cache projection.
//! Credentials never enter a cache key. Public peer hints do not enable sharing.
//!
//! Feed notifications received outside these catalog calls to
//! `invalidate_notification`, and call `clear` after a subscription gap or a
//! local policy change. Those operations also fence collections already running.
//! Observed invalidation, changed cache scope, or credential renewal prevents a
//! mixed collection. No server-side snapshot isolation or gap recovery is claimed.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    CacheScope, CoreRequest, CoreResult, FinalCoreRequest, FinalCoreResult,
    FinalListParams, RequestId, ServerNotification, FINAL_PROTOCOL_VERSION,
};

use super::{
    ManagedCoreError, ManagedCoreEvent, ManagedCoreLimits, ManagedOAuthSession,
    bounded_wait, call_deadline, check_call, prepare,
};
use crate::cache::{
    CachePartitionKey, FinalCacheGeneration, FinalCacheInsert, FinalCacheKey,
    FinalCacheLookup, FinalCacheResultSet, FinalCacheStats, FinalResultCache,
    MAX_FINAL_CACHE_CAPACITY, MAX_FINAL_CACHE_MAX_BYTES, final_cache_hints,
};

/// One budget spanning all pages, notifications, cache hits and host callbacks.
/// `core` supplies the request/frame/cumulative-payload/notification/time bounds.
/// State bytes account encoded IDs and decoded opaque cursors; their counts are
/// independently bounded by `maximum_pages`. Native transport bounds still apply.
#[derive(Clone, Copy, Debug)]
pub struct ManagedCatalogLimits {
    core: ManagedCoreLimits,
    maximum_pages: usize,
    maximum_items: usize,
    maximum_state_bytes: usize,
}

impl Default for ManagedCatalogLimits {
    fn default() -> Self {
        Self {
            core: ManagedCoreLimits::default(),
            maximum_pages: 128,
            maximum_items: 100_000,
            maximum_state_bytes: 1024 * 1024,
        }
    }
}

impl ManagedCatalogLimits {
    pub fn new(
        core: ManagedCoreLimits,
        maximum_pages: usize,
        maximum_items: usize,
        maximum_state_bytes: usize,
    ) -> Result<Self, ManagedCatalogError> {
        if !(1..=1024).contains(&maximum_pages)
            || maximum_items > 1_000_000
            || !(1..=8 * 1024 * 1024).contains(&maximum_state_bytes)
        {
            return Err(ManagedCatalogError::InvalidLimits);
        }
        Ok(Self { core, maximum_pages, maximum_items, maximum_state_bytes })
    }
}

/// Sanitized collection errors do not retain cursors, request IDs, metadata,
/// result contents or host-provided diagnostics.
#[derive(Debug)]
pub enum ManagedCatalogError {
    InvalidLimits,
    NotCatalog,
    InvalidPage,
    PageLimit,
    ItemLimit,
    StateLimit,
    RepeatedCursor,
    RepeatedRequestId,
    ScopeChanged,
    Invalidated,
    CredentialChanged,
    CacheUnavailable,
    AbortedByHost,
    Core(ManagedCoreError),
}

impl fmt::Display for ManagedCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => fmt::Display::fmt(error, f),
            other => f.write_str(match other {
                Self::InvalidLimits => "invalid managed catalog limits",
                Self::NotCatalog => "request is not a modern core catalog list",
                Self::InvalidPage => "catalog result does not match its requested catalog",
                Self::PageLimit => "catalog page limit exceeded",
                Self::ItemLimit => "catalog item limit exceeded",
                Self::StateLimit => "catalog traversal state limit exceeded",
                Self::RepeatedCursor => "catalog peer repeated an opaque cursor",
                Self::RepeatedRequestId => "catalog request ID was already used in this collection",
                Self::ScopeChanged => "catalog cache scope changed between pages",
                Self::Invalidated => "catalog was invalidated during collection",
                Self::CredentialChanged => "catalog credential changed during collection",
                Self::CacheUnavailable => "catalog cache state is unavailable",
                Self::AbortedByHost => "catalog collection stopped by the host",
                Self::Core(_) => unreachable!(),
            }),
        }
    }
}
impl std::error::Error for ManagedCatalogError {}
impl From<ManagedCoreError> for ManagedCatalogError {
    fn from(error: ManagedCoreError) -> Self { Self::Core(error) }
}

/// A fully traversed suffix of one catalog. Starting with an absent cursor
/// collects from the first page; a supplied cursor collects only its suffix.
/// Exact typed pages retain all admitted unknown result members and their wire
/// representation. There is deliberately no synthetic merged result or TTL.
pub struct CollectedCatalog {
    kind: CatalogKind,
    pages: Vec<CoreResult>,
    item_count: usize,
    credential_generation: u64,
}

impl CollectedCatalog {
    pub fn method(&self) -> &'static str { self.kind.method() }
    pub fn pages(&self) -> &[CoreResult] { &self.pages }
    pub fn into_pages(self) -> Vec<CoreResult> { self.pages }
    pub fn item_count(&self) -> usize { self.item_count }
    /// Local to this login, not an identity for cross-session result sharing.
    pub fn credential_generation(&self) -> u64 { self.credential_generation }
}

/// A catalog collector bound immutably to one managed login and limit policy.
/// No background worker, replay of failed requests, or detached fetch is used.
#[derive(Clone)]
pub struct ManagedCatalogClient {
    session: ManagedOAuthSession,
    limits: ManagedCatalogLimits,
    cache: Arc<Mutex<FinalResultCache>>,
}

impl ManagedCatalogClient {
    /// Creates an uncached collector. The invalidation generation remains active
    /// even while caching is disabled, so notifications still fence collections.
    pub fn new(session: ManagedOAuthSession, limits: ManagedCatalogLimits) -> Self {
        let mut cache = FinalResultCache::default();
        cache.set_enabled(false);
        Self { session, limits, cache: Arc::new(Mutex::new(cache)) }
    }

    /// Explicitly enables a fresh bounded cache for this returned client.
    /// Already-created clones keep their existing cache; clones created after
    /// this call share the new cache. The host must propagate external changes.
    pub fn with_cache_limits(mut self, entries: usize, bytes: usize) -> Result<Self, ManagedCatalogError> {
        if !(1..=MAX_FINAL_CACHE_CAPACITY).contains(&entries)
            || !(1..=MAX_FINAL_CACHE_MAX_BYTES).contains(&bytes)
        { return Err(ManagedCatalogError::InvalidLimits); }
        self.cache = Arc::new(Mutex::new(FinalResultCache::with_limits(entries, bytes)));
        Ok(self)
    }

    pub fn clear(&self) -> Result<(), ManagedCatalogError> {
        self.cache()?.clear();
        Ok(())
    }

    /// Invalidate before calling the application's notification observer. This
    /// method may also receive validated notifications from a separate listen.
    pub fn invalidate_notification(&self, notification: &ServerNotification) -> Result<(), ManagedCatalogError> {
        self.cache()?.invalidate_notification(notification);
        Ok(())
    }

    pub fn cache_stats(&self) -> Result<FinalCacheStats, ManagedCatalogError> {
        Ok(self.cache()?.stats())
    }

    /// Collect every remaining page. The ID supplier runs only for actual POSTs,
    /// never for cache hits. The notification observer is incremental and may
    /// stop the collection; it is called with no cache lock held.
    pub async fn collect<I, O>(
        &self,
        cx: &Cx,
        request: CoreRequest,
        next_id: I,
        observe: O,
    ) -> Result<CollectedCatalog, ManagedCatalogError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        O: FnMut(Box<ServerNotification>) -> Result<(), ManagedCatalogError>,
    {
        self.collect_with_cancellation(cx, &McpRequestCancellation::new(), request, next_id, observe).await
    }

    /// One cancellation domain and absolute deadline span the complete operation.
    /// Synchronous callbacks must cooperate; once they return, deadline checks
    /// prevent overdue IDs/notifications from causing a subsequent POST or fill.
    pub async fn collect_with_cancellation<I, O>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        mut request: CoreRequest,
        mut next_id: I,
        mut observe: O,
    ) -> Result<CollectedCatalog, ManagedCatalogError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        O: FnMut(Box<ServerNotification>) -> Result<(), ManagedCatalogError>,
    {
        let deadline = call_deadline(cx, cancellation, self.limits.core.timeout)?;
        let kind = CatalogKind::of(&request)?;
        // Reuse the actual RPC preparation boundary before any credential read.
        // The provisional ID does not escape into the transport or ID history.
        let _ = prepare(self.session.resource().as_str(), request.clone(), RequestId::Number(0), self.limits.core)?;
        let mut state = Traversal::new(list_params(&request)?.cursor.as_deref(), self.limits)?;
        bounded_wait(cx, cancellation, deadline, async {
            Ok(async {
                let credential = self.session.credential_with_cancellation(cx, cancellation).await
                    .map_err(ManagedCoreError::from)?;
                let generation = credential.generation();
                let result_set = kind.result_set();
                let cache_generation = self.cache()?.begin_fetch(&result_set);
                let mut pages = Vec::new();
                loop {
                    check_call(cx, cancellation, deadline)?;
                    self.require_generation(&result_set, cache_generation)?;
                    if pages.len() >= self.limits.maximum_pages { return Err(ManagedCatalogError::PageLimit); }
                    let key = cache_key(self.session.resource().as_str(), &request, generation)?;
                    let lookup = self.cache()?.lookup(&key);
                    let (result, receipt, fetched) = match lookup {
                        FinalCacheLookup::Fresh(result) => {
                            // A replay has no JSON-RPC envelope or notifications;
                            // charge its complete retained result to the same
                            // aggregate payload budget used by the RPC decoder.
                            let bytes = result.encode().map_err(|_| ManagedCatalogError::InvalidPage)?.len();
                            state.charge_bytes(bytes, self.limits.core.total_bytes)?;
                            (result, Instant::now(), false)
                        }
                        FinalCacheLookup::Miss(_) => {
                            let id = next_id()?;
                            check_call(cx, cancellation, deadline)?;
                            state.reserve_id(&id, self.limits.maximum_state_bytes)?;
                            // This is the existing one-POST core API, not a new
                            // response parser. Carry its counters across pages.
                            let mut call = Box::pin(self.session.request_core_with_cancellation(
                                cx, cancellation, request.clone(), id, self.limits.core,
                            )).await?;
                            if call.credential_generation() != generation {
                                return Err(ManagedCatalogError::CredentialChanged);
                            }
                            call.deadline = deadline;
                            call.decoder.bytes = state.bytes;
                            call.decoder.notifications = state.notifications;
                            let result = loop {
                                let event = call.next_event(cx).await?.ok_or(ManagedCatalogError::InvalidPage)?;
                                state.bytes = call.decoder.bytes;
                                state.notifications = call.decoder.notifications;
                                check_call(cx, cancellation, deadline)?;
                                match event {
                                    ManagedCoreEvent::Notification(notification) => {
                                        self.invalidate_notification(&notification)?;
                                        observe(notification)?;
                                        check_call(cx, cancellation, deadline)?;
                                        self.require_generation(&result_set, cache_generation)?;
                                    }
                                    ManagedCoreEvent::Result(result) => break *result,
                                }
                            };
                            (result, Instant::now(), true)
                        }
                    };
                    self.require_generation(&result_set, cache_generation)?;
                    let facts = page_facts(kind, &result)?;
                    let next = state.admit_page(facts, self.limits)?;
                    // Holding one shared cache guard makes the invalidation
                    // comparison and fill indivisible with respect to clears.
                    check_call(cx, cancellation, deadline)?;
                    {
                        let mut cache = self.cache()?;
                        if cache.begin_fetch(&result_set) != cache_generation {
                            return Err(ManagedCatalogError::Invalidated);
                        }
                        if fetched && cache.is_enabled() {
                            if cache.insert_if_current_at(key, cache_generation, result.clone(), receipt)
                                == FinalCacheInsert::InvalidatedDuringFetch
                            { return Err(ManagedCatalogError::Invalidated); }
                        }
                    }
                    pages.push(result);
                    let Some(cursor) = next else { break };
                    list_params_mut(&mut request)?.cursor = Some(cursor);
                }
                // Verify that a cached collection did not outlive its login or
                // cross a renewal while callbacks/other page fetches were active.
                let current = self.session.credential_with_cancellation(cx, cancellation).await
                    .map_err(ManagedCoreError::from)?;
                if current.generation() != generation { return Err(ManagedCatalogError::CredentialChanged); }
                self.require_generation(&result_set, cache_generation)?;
                check_call(cx, cancellation, deadline)?;
                Ok(CollectedCatalog { kind, pages, item_count: state.items, credential_generation: generation })
            }.await)
        }).await?
    }

    fn cache(&self) -> Result<MutexGuard<'_, FinalResultCache>, ManagedCatalogError> {
        self.cache.lock().map_err(|_| ManagedCatalogError::CacheUnavailable)
    }

    fn require_generation(&self, result_set: &FinalCacheResultSet, expected: FinalCacheGeneration) -> Result<(), ManagedCatalogError> {
        if self.cache()?.begin_fetch(result_set) != expected { return Err(ManagedCatalogError::Invalidated); }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum CatalogKind { Tools, Resources, Templates, Prompts }
impl CatalogKind {
    fn of(request: &CoreRequest) -> Result<Self, ManagedCatalogError> {
        match request {
            CoreRequest::Final(FinalCoreRequest::ToolsList(_)) => Ok(Self::Tools),
            CoreRequest::Final(FinalCoreRequest::ResourcesList(_)) => Ok(Self::Resources),
            CoreRequest::Final(FinalCoreRequest::ResourceTemplatesList(_)) => Ok(Self::Templates),
            CoreRequest::Final(FinalCoreRequest::PromptsList(_)) => Ok(Self::Prompts),
            _ => Err(ManagedCatalogError::NotCatalog),
        }
    }
    fn method(self) -> &'static str {
        match self { Self::Tools => "tools/list", Self::Resources => "resources/list", Self::Templates => "resources/templates/list", Self::Prompts => "prompts/list" }
    }
    fn result_set(self) -> FinalCacheResultSet {
        match self { Self::Tools => FinalCacheResultSet::Tools, Self::Resources => FinalCacheResultSet::Resources, Self::Templates => FinalCacheResultSet::ResourceTemplates, Self::Prompts => FinalCacheResultSet::Prompts }
    }
}

fn list_params(request: &CoreRequest) -> Result<&FinalListParams, ManagedCatalogError> {
    match request {
        CoreRequest::Final(FinalCoreRequest::ToolsList(params) | FinalCoreRequest::ResourcesList(params)
            | FinalCoreRequest::ResourceTemplatesList(params) | FinalCoreRequest::PromptsList(params)) => Ok(params),
        _ => Err(ManagedCatalogError::NotCatalog),
    }
}
fn list_params_mut(request: &mut CoreRequest) -> Result<&mut FinalListParams, ManagedCatalogError> {
    match request {
        CoreRequest::Final(FinalCoreRequest::ToolsList(params) | FinalCoreRequest::ResourcesList(params)
            | FinalCoreRequest::ResourceTemplatesList(params) | FinalCoreRequest::PromptsList(params)) => Ok(params),
        _ => Err(ManagedCatalogError::NotCatalog),
    }
}

fn cache_key(target: &str, request: &CoreRequest, generation: u64) -> Result<FinalCacheKey, ManagedCatalogError> {
    let kind = CatalogKind::of(request)?;
    let params = request.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    let encoded = serde_json::to_string(&params).map_err(|_| ManagedCoreError::InvalidRequest)?;
    Ok(FinalCacheKey::new(
        target, FINAL_PROTOCOL_VERSION, "included-in-exact-params", "core-only",
        kind.method(), encoded, list_params(request)?.cursor.clone(), 0, 0, 0, 0,
        CachePartitionKey::new(format!("managed-catalog-generation-{generation}")), kind.result_set(),
    ))
}

struct PageFacts<'a> { count: usize, cursor: Option<&'a str>, scope: CacheScope }
fn page_facts(kind: CatalogKind, result: &CoreResult) -> Result<PageFacts<'_>, ManagedCatalogError> {
    let (count, cursor) = match (kind, result) {
        (CatalogKind::Tools, CoreResult::Final(FinalCoreResult::ToolsList { result, .. })) => (result.payload.tools.len(), result.payload.next_cursor.as_deref()),
        (CatalogKind::Resources, CoreResult::Final(FinalCoreResult::ResourcesList { result, .. })) => (result.payload.resources.len(), result.payload.next_cursor.as_deref()),
        (CatalogKind::Templates, CoreResult::Final(FinalCoreResult::ResourceTemplatesList { result, .. })) => (result.payload.resource_templates.len(), result.payload.next_cursor.as_deref()),
        (CatalogKind::Prompts, CoreResult::Final(FinalCoreResult::PromptsList { result, .. })) => (result.payload.prompts.len(), result.payload.next_cursor.as_deref()),
        _ => return Err(ManagedCatalogError::InvalidPage),
    };
    let (_, scope) = final_cache_hints(result).ok_or(ManagedCatalogError::InvalidPage)?;
    Ok(PageFacts { count, cursor, scope })
}

#[derive(Default)]
struct Traversal {
    cursors: HashSet<String>,
    ids: Vec<RequestId>,
    state_bytes: usize,
    items: usize,
    bytes: usize,
    notifications: usize,
    scope: Option<CacheScope>,
}
impl Traversal {
    fn new(cursor: Option<&str>, limits: ManagedCatalogLimits) -> Result<Self, ManagedCatalogError> {
        let mut state = Self::default();
        if let Some(cursor) = cursor {
            state.charge_state(cursor.len().saturating_add(1), limits.maximum_state_bytes)?;
            state.cursors.insert(cursor.to_owned());
        }
        Ok(state)
    }
    fn charge_state(&mut self, bytes: usize, maximum: usize) -> Result<(), ManagedCatalogError> {
        if bytes > maximum.saturating_sub(self.state_bytes) { return Err(ManagedCatalogError::StateLimit); }
        self.state_bytes += bytes;
        Ok(())
    }
    fn reserve_id(&mut self, id: &RequestId, maximum: usize) -> Result<(), ManagedCatalogError> {
        id.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
        if self.ids.iter().any(|used| used.correlates_with(id)) { return Err(ManagedCatalogError::RepeatedRequestId); }
        let bytes = serde_json::to_string(id).map_err(|_| ManagedCoreError::InvalidRequest)?.len();
        self.charge_state(bytes, maximum)?;
        self.ids.push(id.clone());
        Ok(())
    }
    fn charge_bytes(&mut self, bytes: usize, maximum: usize) -> Result<(), ManagedCatalogError> {
        if bytes > maximum.saturating_sub(self.bytes) { return Err(ManagedCoreError::ResponseByteLimit.into()); }
        self.bytes += bytes;
        Ok(())
    }
    fn admit_page(&mut self, page: PageFacts<'_>, limits: ManagedCatalogLimits) -> Result<Option<String>, ManagedCatalogError> {
        if self.scope.is_some_and(|scope| scope != page.scope) { return Err(ManagedCatalogError::ScopeChanged); }
        if page.count > limits.maximum_items.saturating_sub(self.items) { return Err(ManagedCatalogError::ItemLimit); }
        if let Some(cursor) = page.cursor {
            if self.cursors.contains(cursor) { return Err(ManagedCatalogError::RepeatedCursor); }
            self.charge_state(cursor.len().saturating_add(1), limits.maximum_state_bytes)?;
            self.cursors.insert(cursor.to_owned());
        }
        self.items += page.count;
        self.scope = Some(page.scope);
        Ok(page.cursor.map(str::to_owned))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use serde_json::json;

    fn request(method: &str, params: serde_json::Value) -> CoreRequest {
        let mut params = params;
        params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
    }
    fn result(request: &CoreRequest, fields: &str) -> CoreResult {
        request.decode_result(&format!(r#"{{"resultType":"complete","ttlMs":60000,"cacheScope":"private",{fields}}}"#)).unwrap()
    }

    #[test]
    fn every_catalog_uses_its_typed_page_and_exact_unknown_members() {
        for (method, field) in [("tools/list", "tools"), ("resources/list", "resources"), ("resources/templates/list", "resourceTemplates"), ("prompts/list", "prompts")] {
            let request = request(method, json!({"includeTags":["x"],"excludeTags":[]}));
            let result = result(&request, &format!(r#""{field}":[],"nextCursor":"","x-retained":{{"z":900719925474099312345,"a":1.20e+4}}"#));
            let facts = page_facts(CatalogKind::of(&request).unwrap(), &result).unwrap();
            assert_eq!(facts.count, 0);
            assert_eq!(facts.cursor, Some(""));
            let encoded = result.encode().unwrap();
            assert!(encoded.contains("1.20e+4") && encoded.contains("900719925474099312345"));
        }
    }

    #[test]
    fn cursor_replacement_does_not_change_other_request_identity() {
        let mut request = request("tools/list", json!({"includeTags":["a","b"],"excludeTags":[]}));
        let baseline = request.encode_params().unwrap().unwrap();
        list_params_mut(&mut request).unwrap().cursor = Some("  opaque+/%\0  ".to_owned());
        let mut next = request.encode_params().unwrap().unwrap();
        assert_eq!(next["cursor"], "  opaque+/%\0  ");
        next.as_object_mut().unwrap().remove("cursor");
        assert_eq!(next, baseline);
    }

    #[test]
    fn exact_cache_identity_partitions_cursor_metadata_method_and_credential() {
        let mut request = request("tools/list", json!({}));
        let baseline = cache_key("https://mcp.example/mcp", &request, 1).unwrap();
        assert_ne!(baseline, cache_key("https://mcp.example/mcp", &request, 2).unwrap());
        assert_ne!(baseline, cache_key("https://other.example/mcp", &request, 1).unwrap());
        list_params_mut(&mut request).unwrap().cursor = Some(String::new());
        assert_ne!(baseline, cache_key("https://mcp.example/mcp", &request, 1).unwrap());
        let mut params = request.encode_params().unwrap().unwrap();
        params.as_object_mut().unwrap().remove("cursor");
        params["_meta"]["com.example/tenant"] = json!("other");
        let changed = CoreRequest::decode(ProtocolEra::Modern2026, "tools/list", Some(&params)).unwrap();
        assert_ne!(baseline, cache_key("https://mcp.example/mcp", &changed, 1).unwrap());
    }

    #[test]
    fn empty_cursor_is_a_real_page_and_repetition_does_not_mutate_state() {
        let limits = ManagedCatalogLimits::default();
        let mut state = Traversal::new(None, limits).unwrap();
        let page = || PageFacts { count: 1, cursor: Some(""), scope: CacheScope::Private };
        assert_eq!(state.admit_page(page(), limits).unwrap(), Some(String::new()));
        let before = (state.items, state.state_bytes);
        assert!(matches!(state.admit_page(page(), limits), Err(ManagedCatalogError::RepeatedCursor)));
        assert_eq!((state.items, state.state_bytes), before);
        let mut suffix = Traversal::new(Some(""), limits).unwrap();
        assert!(matches!(suffix.admit_page(page(), limits), Err(ManagedCatalogError::RepeatedCursor)));
    }

    #[test]
    fn failed_scope_item_and_state_admission_preserves_the_previous_page() {
        let mut limits = ManagedCatalogLimits::default();
        limits.maximum_items = 1;
        limits.maximum_state_bytes = 2;
        let mut state = Traversal::new(None, limits).unwrap();
        state.admit_page(PageFacts { count: 1, cursor: Some("x"), scope: CacheScope::Private }, limits).unwrap();
        for (count, cursor, scope) in [(0, None, CacheScope::Public), (1, None, CacheScope::Private), (0, Some("y"), CacheScope::Private)] {
            assert!(state.admit_page(PageFacts { count, cursor, scope }, limits).is_err());
            assert_eq!((state.items, state.state_bytes), (1, 2));
            assert_eq!(state.cursors.len(), 1);
        }
    }

    #[test]
    fn numeric_request_aliases_are_not_fresh_and_payload_budget_is_cumulative() {
        let mut state = Traversal::default();
        state.reserve_id(&RequestId::Number(2), 100).unwrap();
        let alias: RequestId = serde_json::from_str("2e0").unwrap();
        assert!(matches!(state.reserve_id(&alias, 100), Err(ManagedCatalogError::RepeatedRequestId)));
        state.reserve_id(&RequestId::String("2".to_owned()), 100).unwrap();
        state.charge_bytes(9, 10).unwrap();
        assert!(matches!(state.charge_bytes(2, 10), Err(ManagedCatalogError::Core(ManagedCoreError::ResponseByteLimit))));
        assert_eq!(state.bytes, 9);
    }

    #[test]
    fn shared_cache_fences_all_pages_after_invalidation_and_clear() {
        let request = request("tools/list", json!({}));
        let key = cache_key("https://mcp.example/mcp", &request, 1).unwrap();
        let mut cache = FinalResultCache::default();
        let generation = cache.begin_fetch(key.result_set());
        let result = result(&request, r#""tools":[]"#);
        assert_eq!(cache.insert_if_current(key.clone(), generation, result.clone()), FinalCacheInsert::Stored);
        cache.invalidate_result_set(&FinalCacheResultSet::Tools);
        assert_eq!(cache.insert_if_current(key.clone(), generation, result.clone()), FinalCacheInsert::InvalidatedDuringFetch);
        let generation = cache.begin_fetch(key.result_set());
        cache.clear();
        assert_eq!(cache.insert_if_current(key, generation, result), FinalCacheInsert::InvalidatedDuringFetch);
    }
}
