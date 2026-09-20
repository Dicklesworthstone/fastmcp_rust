//! Complete, bounded core catalog discovery for machine OAuth clients.
//!
//! Every page uses the existing same-token discovery/operation path and strict
//! incremental decoder. A collection returns all remaining pages or an error,
//! never a successful partial inventory. Only the opaque cursor changes between
//! requests. Notifications remain incremental even if a later page fails.
//!
//! One deadline, payload/notification budget and request-ID ledger span all
//! pages. A credential generation or cache-scope change rejects the collection.
//! Feed separately received notifications to `invalidate_notification`; `clear`
//! fences in-flight collections after a subscription gap or local policy change.
//! This is uncached discovery, not server-side snapshot isolation or replay.

/// Subscription-driven, bounded reconciliation of complete machine catalogs.
pub mod watch;

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    CacheScope, CoreRequest, CoreResult, FinalCoreRequest, FinalCoreResult,
    FinalListParams, RequestId, ServerNotification,
};

use super::{ClientCredentialsCoreError, ManagedCoreEvent, ManagedCoreLimits, preflight};
use super::super::{
    ClientCredentialsClient, ClientCredentialsError, ClientCredentialsSnapshot,
    OAuthDiscoveryError, active, check_context, check_token, discovery_deadline,
};
use crate::cache::{FinalCacheGeneration, FinalCacheResultSet, FinalResultCache, final_cache_hints};
use crate::http_auth::rpc::ManagedCoreError;
pub use crate::http_auth::rpc::catalog::ManagedCatalogError;

/// Whole-collection limits. The core byte and notification budgets do not reset
/// between pages. Discovery documents retain their separate machine-client bound.
/// The state bound charges both request IDs per page and every decoded cursor;
/// the page bound independently limits collection/ledger allocation overhead.
#[derive(Clone, Copy, Debug)]
pub struct ClientCredentialsCatalogLimits {
    core: ManagedCoreLimits,
    maximum_pages: usize,
    maximum_items: usize,
    maximum_state_bytes: usize,
}

impl Default for ClientCredentialsCatalogLimits {
    fn default() -> Self {
        Self {
            core: ManagedCoreLimits::default(), maximum_pages: 128,
            maximum_items: 100_000, maximum_state_bytes: 1024 * 1024,
        }
    }
}

impl ClientCredentialsCatalogLimits {
    pub fn new(
        core: ManagedCoreLimits,
        maximum_pages: usize,
        maximum_items: usize,
        maximum_state_bytes: usize,
    ) -> Result<Self, ClientCredentialsCatalogError> {
        if !(1..=1024).contains(&maximum_pages)
            || maximum_items > 1_000_000
            || !(1..=8 * 1024 * 1024).contains(&maximum_state_bytes)
        {
            return Err(ManagedCatalogError::InvalidLimits.into());
        }
        Ok(Self { core, maximum_pages, maximum_items, maximum_state_bytes })
    }
}

/// Sanitized errors retain neither tokens nor peer payloads, cursors, IDs or
/// application callback diagnostics. Existing core and catalog error kinds are
/// reused so callers can distinguish invalidation from a failed network attempt.
#[derive(Debug)]
pub enum ClientCredentialsCatalogError {
    Core(ClientCredentialsCoreError),
    Catalog(ManagedCatalogError),
}
impl fmt::Display for ClientCredentialsCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => fmt::Display::fmt(error, f),
            Self::Catalog(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ClientCredentialsCatalogError {}
impl From<ClientCredentialsCoreError> for ClientCredentialsCatalogError {
    fn from(error: ClientCredentialsCoreError) -> Self { Self::Core(error) }
}
impl From<ClientCredentialsError> for ClientCredentialsCatalogError {
    fn from(error: ClientCredentialsError) -> Self { Self::Core(error.into()) }
}
impl From<ManagedCoreError> for ClientCredentialsCatalogError {
    fn from(error: ManagedCoreError) -> Self { Self::Core(error.into()) }
}
impl From<ManagedCatalogError> for ClientCredentialsCatalogError {
    fn from(error: ManagedCatalogError) -> Self { Self::Catalog(error) }
}

/// Every page in an admitted catalog suffix, preserving exact typed results and
/// their unknown members. No merged result, synthetic TTL or cross-client cache
/// identity is invented. An absent initial cursor means the entire inventory.
pub struct CollectedMachineCatalog {
    kind: CatalogKind,
    pages: Vec<CoreResult>,
    item_count: usize,
    credential_generation: u64,
}
impl CollectedMachineCatalog {
    pub fn method(&self) -> &'static str { self.kind.method() }
    pub fn pages(&self) -> &[CoreResult] { &self.pages }
    pub fn into_pages(self) -> Vec<CoreResult> { self.pages }
    pub fn item_count(&self) -> usize { self.item_count }
    /// Local to the owning machine client, not an authorization identity.
    pub fn credential_generation(&self) -> u64 { self.credential_generation }
}

/// Immutable machine identity and collection policy. Clones share invalidation
/// fences, but not request IDs or partially collected pages. There is no worker,
/// automatic failed-POST retry, persistent storage or cached credential bypass.
#[derive(Clone)]
pub struct ClientCredentialsCatalogClient {
    client: ClientCredentialsClient,
    limits: ClientCredentialsCatalogLimits,
    invalidation: Arc<Mutex<FinalResultCache>>,
}
impl ClientCredentialsCatalogClient {
    pub fn new(client: ClientCredentialsClient, limits: ClientCredentialsCatalogLimits) -> Self {
        // Use the same result-set invalidation rules as other core clients.
        // No catalog page is inserted; the disabled cache holds only its fences.
        let mut invalidation = FinalResultCache::default();
        invalidation.set_enabled(false);
        Self { client, limits, invalidation: Arc::new(Mutex::new(invalidation)) }
    }

    /// Fence every in-flight collection, including those currently reading a
    /// response. Use after a lost subscription or a local authorization change.
    pub fn clear(&self) -> Result<(), ClientCredentialsCatalogError> {
        self.fences()?.clear();
        Ok(())
    }

    /// Accept only already-validated notifications from this machine endpoint.
    /// Invalidation occurs before the application's observer sees the event.
    pub fn invalidate_notification(&self, notification: &ServerNotification)
        -> Result<(), ClientCredentialsCatalogError>
    {
        self.fences()?.invalidate_notification(notification);
        Ok(())
    }

    /// Collect tools, resources, resource templates, or prompts. `next_ids`
    /// supplies a fresh discovery/operation pair for each page. No ID from either
    /// role can be reused during this collection, including numeric aliases.
    /// `observe` runs without a mutex held and must not block the async runtime.
    pub async fn collect<I, O>(
        &self, cx: &Cx, request: CoreRequest, next_ids: I, observe: O,
    ) -> Result<CollectedMachineCatalog, ClientCredentialsCatalogError>
    where
        I: FnMut() -> Result<(RequestId, RequestId), ClientCredentialsCatalogError>,
        O: FnMut(Box<ServerNotification>) -> Result<(), ClientCredentialsCatalogError>,
    {
        self.collect_with_cancellation(cx, &McpRequestCancellation::new(), request, next_ids, observe).await
    }

    /// Cancellation, machine-owner closure and one absolute deadline cover all
    /// grants, discovery, pages and callbacks. A started future that is dropped
    /// releases its current response; previously dispatched work is not undone.
    /// Callback side effects and delivered notifications cannot be recalled.
    pub async fn collect_with_cancellation<I, O>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        mut request: CoreRequest, mut next_ids: I, mut observe: O,
    ) -> Result<CollectedMachineCatalog, ClientCredentialsCatalogError>
    where
        I: FnMut() -> Result<(RequestId, RequestId), ClientCredentialsCatalogError>,
        O: FnMut(Box<ServerNotification>) -> Result<(), ClientCredentialsCatalogError>,
    {
        let deadline = discovery_deadline(cx, self.limits.core.timeout())
            .map_err(ClientCredentialsError::from)?;
        let kind = CatalogKind::of(&request)?;
        let mut state = Traversal::new(list_params(&request)?.cursor.as_deref(), self.limits)?;
        let generation = self.fences()?.begin_fetch(&kind.result_set());
        let owner = &self.client.inner.closed;
        Box::pin(active(cx, deadline, owner, cancellation, None, async {
            Ok(async {
                let mut pinned: Option<ClientCredentialsSnapshot> = None;
                let mut pages = Vec::new();
                loop {
                    self.check(cx, cancellation, deadline, pinned.as_ref(), kind, generation)?;
                    if pages.len() >= self.limits.maximum_pages {
                        return Err(ManagedCatalogError::PageLimit.into());
                    }
                    if state.bytes >= self.limits.core.total_bytes() {
                        return Err(ManagedCoreError::ResponseByteLimit.into());
                    }
                    let (discovery_id, request_id) = next_ids()?;
                    self.check(cx, cancellation, deadline, pinned.as_ref(), kind, generation)?;
                    state.reserve_ids(&discovery_id, &request_id, self.limits.maximum_state_bytes)?;
                    // Measure the actual stamped documents and supplied IDs
                    // before the first grant as well as before every later page.
                    preflight(self.client.resource(), &request, &discovery_id, &request_id, self.limits.core)?;
                    self.check(cx, cancellation, deadline, pinned.as_ref(), kind, generation)?;
                    let mut call = active(cx, deadline, owner, cancellation, pinned.as_ref(), async {
                        Ok(self.client.request_core_with_cancellation(
                            cx, cancellation, request.clone(), discovery_id, request_id, self.limits.core,
                        ).await)
                    }).await??;
                    if let Some(credential) = &pinned {
                        require_same_credential(credential, &call.snapshot)?;
                    } else {
                        pinned = Some(ClientCredentialsSnapshot {
                            bearer: call.snapshot.bearer.clone(), scopes: call.snapshot.scopes.clone(),
                            expires_at: call.snapshot.expires_at, generation: call.snapshot.generation,
                        });
                    }
                    // Never extend the per-POST/native deadline when imposing
                    // the enclosing collection lifetime.
                    call.deadline = call.deadline.min(deadline);
                    call.decoder.resume_usage(state.bytes, state.notifications)?;
                    self.check(cx, cancellation, deadline, pinned.as_ref(), kind, generation)?;
                    let result = loop {
                        let event = call.next_event(cx).await?.ok_or(ManagedCatalogError::InvalidPage)?;
                        (state.bytes, state.notifications) = call.decoder.usage();
                        self.check(cx, cancellation, deadline, pinned.as_ref(), kind, generation)?;
                        match event {
                            ManagedCoreEvent::Notification(notification) => {
                                self.invalidate_notification(&notification)?;
                                observe(notification)?;
                                self.check(cx, cancellation, deadline, pinned.as_ref(), kind, generation)?;
                            }
                            ManagedCoreEvent::Result(result) => break *result,
                        }
                    };
                    let next = state.admit_page(page_facts(kind, &result)?, self.limits)?;
                    self.check(cx, cancellation, deadline, pinned.as_ref(), kind, generation)?;
                    pages.push(result);
                    let Some(cursor) = next else { break };
                    list_params_mut(&mut request)?.cursor = Some(cursor);
                }
                let pinned = pinned.ok_or(ManagedCatalogError::InvalidPage)?;
                // Detect another caller's renewal before publishing a complete
                // collection; no cached path can bypass current token custody.
                let current = active(cx, deadline, owner, cancellation, Some(&pinned),
                    self.client.credential_with_cancellation(cx, cancellation)).await?;
                require_same_credential(&pinned, &current)?;
                self.check(cx, cancellation, deadline, Some(&pinned), kind, generation)?;
                Ok(CollectedMachineCatalog {
                    kind, pages, item_count: state.items, credential_generation: pinned.generation(),
                })
            }.await)
        })).await?
    }

    fn fences(&self) -> Result<MutexGuard<'_, FinalResultCache>, ClientCredentialsCatalogError> {
        self.invalidation.lock().map_err(|_| ManagedCatalogError::CacheUnavailable.into())
    }

    fn check(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time,
        credential: Option<&ClientCredentialsSnapshot>, kind: CatalogKind, generation: FinalCacheGeneration,
    ) -> Result<(), ClientCredentialsCatalogError> {
        if self.client.inner.closed.is_cancel_requested() { return Err(ClientCredentialsError::Closed.into()); }
        if cancellation.is_cancel_requested() { return Err(ClientCredentialsError::from(OAuthDiscoveryError::Cancelled).into()); }
        let deadline = cx.budget().deadline.map_or(deadline, |caller| caller.min(deadline));
        check_context(cx, deadline).map_err(ClientCredentialsError::from)?;
        if let Some(credential) = credential { check_token(&credential.bearer, credential.expires_at)?; }
        if self.fences()?.begin_fetch(&kind.result_set()) != generation {
            return Err(ManagedCatalogError::Invalidated.into());
        }
        Ok(())
    }
}

fn require_same_credential(
    pinned: &ClientCredentialsSnapshot, current: &ClientCredentialsSnapshot,
) -> Result<(), ClientCredentialsCatalogError> {
    check_token(&pinned.bearer, pinned.expires_at)?;
    check_token(&current.bearer, current.expires_at)?;
    if current.generation() != pinned.generation() {
        return Err(ManagedCatalogError::CredentialChanged.into());
    }
    Ok(())
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
        match self {
            Self::Tools => "tools/list", Self::Resources => "resources/list",
            Self::Templates => "resources/templates/list", Self::Prompts => "prompts/list",
        }
    }
    fn result_set(self) -> FinalCacheResultSet {
        match self {
            Self::Tools => FinalCacheResultSet::Tools, Self::Resources => FinalCacheResultSet::Resources,
            Self::Templates => FinalCacheResultSet::ResourceTemplates, Self::Prompts => FinalCacheResultSet::Prompts,
        }
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
    ids: Vec<RequestId>,
    cursors: HashSet<String>,
    state_bytes: usize,
    items: usize,
    bytes: usize,
    notifications: usize,
    scope: Option<CacheScope>,
}
impl Traversal {
    fn new(cursor: Option<&str>, limits: ClientCredentialsCatalogLimits) -> Result<Self, ManagedCatalogError> {
        let mut state = Self::default();
        if let Some(cursor) = cursor {
            let charge = cursor.len().checked_add(1).ok_or(ManagedCatalogError::StateLimit)?;
            if charge > limits.maximum_state_bytes { return Err(ManagedCatalogError::StateLimit); }
            state.state_bytes = charge;
            state.cursors.insert(cursor.to_owned());
        }
        Ok(state)
    }
    fn reserve_ids(&mut self, discovery: &RequestId, operation: &RequestId, maximum: usize)
        -> Result<(), ManagedCatalogError>
    {
        for id in [discovery, operation] {
            id.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
            if self.ids.iter().any(|used| used.correlates_with(id)) {
                return Err(ManagedCatalogError::RepeatedRequestId);
            }
        }
        if discovery.correlates_with(operation) { return Err(ManagedCatalogError::RepeatedRequestId); }
        let first = serde_json::to_string(discovery).map_err(|_| ManagedCoreError::InvalidRequest)?.len();
        let second = serde_json::to_string(operation).map_err(|_| ManagedCoreError::InvalidRequest)?.len();
        let charge = first.checked_add(second).ok_or(ManagedCatalogError::StateLimit)?;
        if charge > maximum.saturating_sub(self.state_bytes) { return Err(ManagedCatalogError::StateLimit); }
        // Both IDs are admitted atomically; a refused second ID cannot consume
        // the first ID or retained-state budget.
        self.ids.push(discovery.clone());
        self.ids.push(operation.clone());
        self.state_bytes += charge;
        Ok(())
    }
    fn admit_page(&mut self, page: PageFacts<'_>, limits: ClientCredentialsCatalogLimits)
        -> Result<Option<String>, ManagedCatalogError>
    {
        if self.scope.is_some_and(|scope| scope != page.scope) { return Err(ManagedCatalogError::ScopeChanged); }
        if page.count > limits.maximum_items.saturating_sub(self.items) { return Err(ManagedCatalogError::ItemLimit); }
        let charge = match page.cursor {
            Some(cursor) => {
                if self.cursors.contains(cursor) { return Err(ManagedCatalogError::RepeatedCursor); }
                cursor.len().checked_add(1).ok_or(ManagedCatalogError::StateLimit)?
            }
            None => 0,
        };
        if charge > limits.maximum_state_bytes.saturating_sub(self.state_bytes) {
            return Err(ManagedCatalogError::StateLimit);
        }
        if let Some(cursor) = page.cursor { self.cursors.insert(cursor.to_owned()); }
        self.state_bytes += charge;
        self.items += page.count;
        self.scope = Some(page.scope);
        Ok(page.cursor.map(str::to_owned))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use serde_json::json;

    fn request(method: &str) -> CoreRequest {
        CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&json!({
            "includeTags":["one","two"], "excludeTags":[],
            "_meta":FinalRequestMeta::new(ClientCapabilities::default()),
        }))).unwrap()
    }
    fn result(request: &CoreRequest, field: &str, cursor: Option<&str>) -> CoreResult {
        let cursor = cursor.map_or(String::new(), |value| format!(",\"nextCursor\":{}", serde_json::to_string(value).unwrap()));
        request.decode_result(&format!(r#"{{"resultType":"complete","ttlMs":0,"cacheScope":"private","{field}":[]{cursor},"x-exact":{{"z":900719925474099312345,"a":1.20e+4}}}}"#)).unwrap()
    }
    fn page(count: usize, cursor: Option<&str>, scope: CacheScope) -> PageFacts<'_> {
        PageFacts { count, cursor, scope }
    }

    #[test]
    fn machine_all_four_catalogs_retain_typed_pages_and_exact_members() {
        for (method, field) in [("tools/list","tools"), ("resources/list","resources"),
            ("resources/templates/list","resourceTemplates"), ("prompts/list","prompts")]
        {
            let request = request(method);
            let kind = CatalogKind::of(&request).unwrap();
            let first = result(&request, field, Some(""));
            let last = result(&request, field, None);
            let mut traversal = Traversal::default();
            assert_eq!(traversal.admit_page(page_facts(kind, &first).unwrap(), ClientCredentialsCatalogLimits::default()).unwrap(), Some(String::new()));
            assert_eq!(traversal.admit_page(page_facts(kind, &last).unwrap(), ClientCredentialsCatalogLimits::default()).unwrap(), None);
            let collected = CollectedMachineCatalog { kind, pages: vec![first,last], item_count: 0, credential_generation: 4 };
            assert_eq!(collected.method(), method);
            assert_eq!(collected.pages().len(), 2);
            assert_eq!(collected.credential_generation(), 4);
            let encoded = collected.pages()[0].encode().unwrap();
            assert!(encoded.contains("1.20e+4") && encoded.contains("900719925474099312345"));
            assert_eq!(collected.into_pages().len(), 2);
        }
    }

    #[test]
    fn machine_pagination_changes_only_the_exact_cursor() {
        let mut request = request("tools/list");
        let before = request.encode_params().unwrap().unwrap();
        list_params_mut(&mut request).unwrap().cursor = Some("  opaque+/%\0  ".to_owned());
        let mut after = request.encode_params().unwrap().unwrap();
        assert_eq!(after["cursor"], "  opaque+/%\0  ");
        after.as_object_mut().unwrap().remove("cursor");
        assert_eq!(before, after);
    }

    #[test]
    fn machine_cursor_cycles_and_empty_initial_cursors_are_rejected_unchanged() {
        let limits = ClientCredentialsCatalogLimits::default();
        let mut state = Traversal::new(Some(""), limits).unwrap();
        assert_eq!(state.state_bytes, 1);
        assert_eq!(state.admit_page(page(2, Some("next"), CacheScope::Private), limits).unwrap(), Some("next".to_owned()));
        let before = (state.state_bytes, state.items, state.cursors.clone());
        for cursor in ["", "next"] {
            assert!(matches!(state.admit_page(page(1, Some(cursor), CacheScope::Private), limits), Err(ManagedCatalogError::RepeatedCursor)));
            assert_eq!((state.state_bytes, state.items, state.cursors.clone()), before);
        }
        assert_eq!(state.admit_page(page(1, None, CacheScope::Private), limits).unwrap(), None);
        assert_eq!(state.items, 3);
    }

    #[test]
    fn machine_both_id_roles_are_fenced_including_numeric_aliases() {
        let mut state = Traversal::default();
        state.reserve_ids(&RequestId::Number(1), &RequestId::Number(2), 4096).unwrap();
        let before = state.state_bytes;
        for (first, second) in [("1.0","3"), ("3","2e0"), ("3","3.0")] {
            assert!(matches!(state.reserve_ids(&serde_json::from_str(first).unwrap(), &serde_json::from_str(second).unwrap(), 4096),
                Err(ManagedCatalogError::RepeatedRequestId)));
            assert_eq!(state.ids.len(), 2);
            assert_eq!(state.state_bytes, before);
        }
        state.reserve_ids(&RequestId::String("1".to_owned()), &RequestId::String("2".to_owned()), 4096).unwrap();
        assert_eq!(state.ids.len(), 4);
    }

    #[test]
    fn machine_id_pair_reservation_is_atomic_at_the_byte_boundary() {
        let mut state = Traversal::default();
        assert!(matches!(state.reserve_ids(&RequestId::Number(1), &RequestId::Number(2), 1), Err(ManagedCatalogError::StateLimit)));
        assert!(state.ids.is_empty());
        assert_eq!(state.state_bytes, 0);
        state.reserve_ids(&RequestId::Number(1), &RequestId::Number(2), 2).unwrap();
        assert_eq!(state.state_bytes, 2);
    }

    #[test]
    fn machine_item_scope_and_cursor_byte_refusals_do_not_admit_a_page() {
        let limits = ClientCredentialsCatalogLimits::new(ManagedCoreLimits::default(), 2, 2, 4).unwrap();
        let mut state = Traversal::default();
        state.admit_page(page(1, Some("a"), CacheScope::Private), limits).unwrap();
        for (facts, reason) in [(page(2, None, CacheScope::Private), "items"),
            (page(1, None, CacheScope::Public), "scope"), (page(1, Some("xx"), CacheScope::Private), "bytes")]
        {
            let error = state.admit_page(facts, limits).unwrap_err();
            match reason {
                "items" => assert!(matches!(error, ManagedCatalogError::ItemLimit)),
                "scope" => assert!(matches!(error, ManagedCatalogError::ScopeChanged)),
                _ => assert!(matches!(error, ManagedCatalogError::StateLimit)),
            }
            assert_eq!(state.items, 1);
            assert_eq!(state.state_bytes, 2);
            assert_eq!(state.cursors.len(), 1);
            assert_eq!(state.scope, Some(CacheScope::Private));
        }
        state.admit_page(page(1, Some("b"), CacheScope::Private), limits).unwrap();
        assert_eq!((state.items, state.state_bytes), (2, 4));
    }

    #[test]
    fn machine_page_kind_cannot_change_between_catalogs() {
        let tools = request("tools/list");
        let resources = request("resources/list");
        let result = result(&resources, "resources", None);
        assert!(page_facts(CatalogKind::of(&resources).unwrap(), &result).is_ok());
        assert!(matches!(page_facts(CatalogKind::of(&tools).unwrap(), &result), Err(ManagedCatalogError::InvalidPage)));
    }

    #[test]
    fn machine_catalog_limits_reject_zero_or_excessive_retention() {
        for (pages, items, state) in [(0,1,1),(1025,1,1),(1,1_000_001,1),(1,1,0),(1,1,8*1024*1024+1)] {
            assert!(ClientCredentialsCatalogLimits::new(ManagedCoreLimits::default(), pages, items, state).is_err());
        }
        let zero_items = ClientCredentialsCatalogLimits::new(ManagedCoreLimits::default(), 1, 0, 1).unwrap();
        assert!(Traversal::default().admit_page(page(0,None,CacheScope::Private), zero_items).is_ok());
    }

    fn snapshot(generation: u64) -> (ClientCredentialsSnapshot, McpRequestCancellation) {
        let owner = McpRequestCancellation::new();
        let expires_at = Instant::now() + Duration::from_secs(60);
        let bearer = crate::http_auth::BoundBearerCredential::bind_with_expiry(
            fastmcp_core::CanonicalHttpUrl::parse("https://machine.example/mcp").unwrap(), "catalog-test-token", expires_at,
        ).unwrap().for_owner(&owner).unwrap();
        (ClientCredentialsSnapshot { bearer, scopes: vec![], expires_at, generation }, owner)
    }

    #[test]
    fn machine_catalog_credential_binding_rejects_renewal_expiry_and_revocation() {
        let (pinned, _owner) = snapshot(1);
        let (mut current, _current_owner) = snapshot(1);
        assert!(require_same_credential(&pinned, &current).is_ok());
        current.generation = 2;
        assert!(matches!(require_same_credential(&pinned, &current), Err(ClientCredentialsCatalogError::Catalog(ManagedCatalogError::CredentialChanged))));
        current.generation = 1;
        current.bearer.revoke();
        assert!(require_same_credential(&pinned, &current).is_err());
        let (mut expired, _expired_owner) = snapshot(1);
        expired.expires_at = Instant::now();
        assert!(require_same_credential(&pinned, &expired).is_err());
        assert!(!pinned.bearer.is_revoked());
    }

    #[test]
    fn machine_catalog_payload_and_notification_usage_is_cumulative() {
        use crate::http_auth::rpc::CoreDecoder;
        let limits = ManagedCoreLimits::new(4096, 1024, 2048, 1, Duration::from_secs(1)).unwrap();
        let request = request("tools/list");
        let mut first = CoreDecoder::for_request(request.clone(), RequestId::Number(2), limits).unwrap();
        first.admit(br#"{"jsonrpc":"2.0","method":"notifications/prompts/list_changed"}"#, true).unwrap();
        let (bytes, notifications) = first.usage();
        let mut second = CoreDecoder::for_request(request, RequestId::Number(4), limits).unwrap();
        second.resume_usage(bytes, notifications).unwrap();
        assert!(matches!(second.admit(br#"{"jsonrpc":"2.0","method":"notifications/prompts/list_changed"}"#, true), Err(ManagedCoreError::NotificationLimit)));
        assert_eq!(second.usage(), (bytes, notifications));
        let terminal = br#"{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#;
        assert!(matches!(second.admit(terminal, false), Ok(ManagedCoreEvent::Result(_))));
        assert_eq!(second.usage(), (bytes + terminal.len(), notifications));
    }
}
