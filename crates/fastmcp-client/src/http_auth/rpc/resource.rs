//! Bounded resource reads with explicitly enabled, login-local result caching.
//!
//! This is a resources/read consumer of the existing managed core transport,
//! protocol result algebra and final-result cache, not a new wire codec. Only
//! ordinary complete reads may be replayed. Input-required results and requests
//! carrying either continuation field always bypass the cache, even when the
//! field is present-empty. Nothing here invokes a resolver or retries a POST.
//!
//! Cache identity includes every encoded parameter and the current credential
//! generation. Public hints never authorize cross-login sharing. Feed validated
//! external notifications to invalidate_notification and clear after a listen
//! gap or local policy change. An observed update fences pending fills as well
//! as retained values. Resource generations conservatively share the existing
//! cache's fixed-cardinality resource-read class.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    CoreRequest, CoreResult, FinalCoreRequest, FinalCoreResult, RequestId,
    ServerNotification, FINAL_PROTOCOL_VERSION,
};

use super::{
    ManagedCoreError, ManagedCoreEvent, ManagedCoreLimits, ManagedOAuthSession,
    bounded_wait, call_deadline, check_call, prepare,
};
use crate::cache::{
    CachePartitionKey, FinalCacheGeneration, FinalCacheInsert, FinalCacheKey,
    FinalCacheLookup, FinalCacheResultSet, FinalCacheStats, FinalResultCache,
    MAX_FINAL_CACHE_CAPACITY, MAX_FINAL_CACHE_MAX_BYTES,
};
use crate::http_auth::managed::OAuthCredentialSnapshot;

/// Subscribe-before-read reconciliation with bounded rereads and explicit input handoff.
pub mod watch;

/// Input/frame/response/notification/time limits come from the shared core
/// limits. Contents count additionally bounds the complete read's item vector.
#[derive(Clone, Copy, Debug)]
pub struct ManagedResourceLimits {
    core: ManagedCoreLimits,
    maximum_contents: usize,
}
impl Default for ManagedResourceLimits {
    fn default() -> Self {
        Self { core: ManagedCoreLimits::default(), maximum_contents: 1024 }
    }
}
impl ManagedResourceLimits {
    pub fn new(core: ManagedCoreLimits, maximum_contents: usize) -> Result<Self, ManagedResourceError> {
        if maximum_contents > 100_000 { return Err(ManagedResourceError::InvalidLimits); }
        Ok(Self { core, maximum_contents })
    }
}

/// Diagnostics omit resource URIs, request metadata, input answers and contents.
#[derive(Debug)]
pub enum ManagedResourceError {
    InvalidLimits,
    NotResourceRead,
    InvalidResult,
    ContentsLimit,
    Invalidated,
    CredentialChanged,
    CredentialUnavailable,
    CacheUnavailable,
    AbortedByHost,
    Core(ManagedCoreError),
}
impl fmt::Display for ManagedResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => fmt::Display::fmt(error, f),
            Self::InvalidLimits => f.write_str("invalid managed resource limits"),
            Self::NotResourceRead => f.write_str("request is not a modern core resource read"),
            Self::InvalidResult => f.write_str("result is not an admitted resource-read outcome"),
            Self::ContentsLimit => f.write_str("resource contents count exceeds its limit"),
            Self::Invalidated => f.write_str("resource read was invalidated before delivery"),
            Self::CredentialChanged => f.write_str("resource request used a different credential generation"),
            Self::CredentialUnavailable => f.write_str("resource credential is expired or locally revoked"),
            Self::CacheUnavailable => f.write_str("resource cache state is unavailable"),
            Self::AbortedByHost => f.write_str("resource read stopped by its host"),
        }
    }
}
impl std::error::Error for ManagedResourceError {}
impl From<ManagedCoreError> for ManagedResourceError {
    fn from(error: ManagedCoreError) -> Self { Self::Core(error) }
}

/// The exact typed outcome of one read. Complete and input-required remain
/// distinguishable in result(); no content, unknown member, TTL or state is
/// synthesized. Multiple content items retain their original order and URIs.
/// Already-returned data cannot be recalled by invalidation or credential revoke.
pub struct ManagedResourceRead {
    uri: String,
    result: CoreResult,
    credential_generation: u64,
    cache_hit: bool,
}
impl ManagedResourceRead {
    pub fn uri(&self) -> &str { &self.uri }
    pub fn result(&self) -> &CoreResult { &self.result }
    pub fn into_result(self) -> CoreResult { self.result }
    pub fn credential_generation(&self) -> u64 { self.credential_generation }
    pub fn is_cache_hit(&self) -> bool { self.cache_hit }
    pub fn is_complete(&self) -> bool {
        matches!(&self.result, CoreResult::Final(FinalCoreResult::ResourcesRead { .. }))
    }
}

/// Immutable consumer configuration and one cache belonging to one managed
/// login. Clones share invalidation and retained entries; separately constructed
/// consumers never share results merely because a peer marked them public.
#[derive(Clone)]
pub struct ManagedResourceClient {
    session: ManagedOAuthSession,
    limits: ManagedResourceLimits,
    cache: Arc<Mutex<FinalResultCache>>,
}
impl ManagedResourceClient {
    /// Starts uncached. Generation checks remain active with caching disabled.
    pub fn new(session: ManagedOAuthSession, limits: ManagedResourceLimits) -> Self {
        let mut cache = FinalResultCache::default();
        cache.set_enabled(false);
        Self { session, limits, cache: Arc::new(Mutex::new(cache)) }
    }

    /// Creates an explicitly enabled bounded cache for this returned consumer.
    /// Earlier clones keep their prior cache; later clones share the new one.
    pub fn with_cache_limits(mut self, entries: usize, bytes: usize) -> Result<Self, ManagedResourceError> {
        if !(1..=MAX_FINAL_CACHE_CAPACITY).contains(&entries)
            || !(1..=MAX_FINAL_CACHE_MAX_BYTES).contains(&bytes)
        { return Err(ManagedResourceError::InvalidLimits); }
        self.cache = Arc::new(Mutex::new(FinalResultCache::with_limits(entries, bytes)));
        Ok(self)
    }

    /// Retires both cached results and reads that already captured a generation.
    pub fn clear(&self) -> Result<(), ManagedResourceError> {
        self.cache()?.clear();
        Ok(())
    }

    /// Accepts already-validated server notifications, including those received
    /// on a separate subscription. Resource updates and resource-list changes
    /// invalidate reads; unrelated catalog changes do not. No URI map is grown.
    pub fn invalidate_notification(&self, notification: &ServerNotification) -> Result<(), ManagedResourceError> {
        self.cache()?.invalidate_notification(notification);
        Ok(())
    }

    pub fn cache_stats(&self) -> Result<FinalCacheStats, ManagedResourceError> {
        Ok(self.cache()?.stats())
    }

    /// Obtains one typed read outcome. next_id runs only for an actual POST;
    /// cached data does not allocate an ID or replay old notifications. observe
    /// is incremental and never called while the cache mutex is held.
    pub async fn read<I, O>(
        &self, cx: &Cx, request: CoreRequest, next_id: I, observe: O,
    ) -> Result<ManagedResourceRead, ManagedResourceError>
    where
        I: FnOnce() -> Result<RequestId, ManagedResourceError>,
        O: FnMut(Box<ServerNotification>) -> Result<(), ManagedResourceError>,
    {
        self.read_with_cancellation(cx, &McpRequestCancellation::new(), request, next_id, observe).await
    }

    /// One deadline covers credential acquisition, callbacks and response reads.
    /// Callback overrun, cancellation, invalidation, expiry or revocation cannot
    /// cause a later POST, fill or delivery. Synchronous host work must cooperate;
    /// it cannot be forcibly preempted by this async API.
    pub async fn read_with_cancellation<I, O>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        request: CoreRequest, next_id: I, mut observe: O,
    ) -> Result<ManagedResourceRead, ManagedResourceError>
    where
        I: FnOnce() -> Result<RequestId, ManagedResourceError>,
        O: FnMut(Box<ServerNotification>) -> Result<(), ManagedResourceError>,
    {
        let deadline = call_deadline(cx, cancellation, self.limits.core.timeout)?;
        let (uri, reusable) = read_identity(&request)?;
        let uri = uri.to_owned();
        // The shared encoder/profile check precedes even a cache hit or token
        // renewal. This provisional ID is never sent or supplied to the host.
        let _ = prepare(self.session.resource().as_str(), request.clone(), RequestId::Number(0), self.limits.core)?;
        let result_set = FinalCacheResultSet::Resource(uri.clone());
        let captured = self.cache()?.begin_fetch(&result_set);
        bounded_wait(cx, cancellation, deadline, async {
            Ok(async {
                let credential = self.session.credential_with_cancellation(cx, cancellation)
                    .await.map_err(ManagedCoreError::from)?;
                require_credential(&credential)?;
                self.require_generation(&result_set, captured)?;
                let key = if reusable {
                    Some(cache_key(self.session.resource().as_str(), &request, credential.generation())?)
                } else { None };
                // Continuation requests do not even look up retained data: a
                // complete answer to a previous one-shot continuation is not
                // permission to skip or duplicate its next explicit operation.
                let cached = match &key {
                    Some(key) => match self.cache()?.lookup(key) {
                        FinalCacheLookup::Fresh(result) => Some(result),
                        FinalCacheLookup::Miss(_) => None,
                    },
                    None => None,
                };
                let cache_hit = cached.is_some();
                let (result, receipt) = if let Some(result) = cached {
                    let bytes = result.encode().map_err(|_| ManagedResourceError::InvalidResult)?.len();
                    if bytes > self.limits.core.frame_bytes || bytes > self.limits.core.total_bytes {
                        return Err(ManagedCoreError::ResponseByteLimit.into());
                    }
                    (result, Instant::now())
                } else {
                    let id = next_id()?;
                    check_call(cx, cancellation, deadline)?;
                    require_credential(&credential)?;
                    self.require_generation(&result_set, captured)?;
                    let mut call = Box::pin(self.session.request_core_with_cancellation(
                        cx, cancellation, request, id, self.limits.core,
                    )).await?;
                    // A read may race another caller's renewal, but it must not
                    // populate or return a result in the prior token partition.
                    if call.credential_generation() != credential.generation() {
                        return Err(ManagedResourceError::CredentialChanged);
                    }
                    call.deadline = deadline;
                    let result = loop {
                        let event = call.next_event(cx).await?.ok_or(ManagedResourceError::InvalidResult)?;
                        check_call(cx, cancellation, deadline)?;
                        require_credential(&credential)?;
                        match event {
                            ManagedCoreEvent::Notification(notification) => {
                                self.invalidate_notification(&notification)?;
                                observe(notification)?;
                                check_call(cx, cancellation, deadline)?;
                                require_credential(&credential)?;
                                self.require_generation(&result_set, captured)?;
                            }
                            ManagedCoreEvent::Result(result) => break *result,
                        }
                    };
                    (result, Instant::now())
                };
                let complete = admit_result(&result, self.limits.maximum_contents)?;
                check_call(cx, cancellation, deadline)?;
                // Compare and fill under one lock: an external clear or update
                // cannot win and then have this old fetch repopulate the cache.
                {
                    let mut cache = self.cache()?;
                    if cache.begin_fetch(&result_set) != captured { return Err(ManagedResourceError::Invalidated); }
                    require_credential(&credential)?;
                    if complete && !cache_hit && cache.is_enabled() {
                        if let Some(key) = key {
                            if cache.insert_if_current_at(key, captured, result.clone(), receipt)
                                == FinalCacheInsert::InvalidatedDuringFetch
                            { return Err(ManagedResourceError::Invalidated); }
                        }
                    }
                }
                check_call(cx, cancellation, deadline)?;
                require_credential(&credential)?;
                self.require_generation(&result_set, captured)?;
                Ok(ManagedResourceRead {
                    uri, result, credential_generation: credential.generation(), cache_hit,
                })
            }.await)
        }).await?
    }

    fn cache(&self) -> Result<MutexGuard<'_, FinalResultCache>, ManagedResourceError> {
        self.cache.lock().map_err(|_| ManagedResourceError::CacheUnavailable)
    }
    fn require_generation(&self, result_set: &FinalCacheResultSet, captured: FinalCacheGeneration) -> Result<(), ManagedResourceError> {
        if self.cache()?.begin_fetch(result_set) != captured { return Err(ManagedResourceError::Invalidated); }
        Ok(())
    }
}

fn require_credential(credential: &OAuthCredentialSnapshot) -> Result<(), ManagedResourceError> {
    if credential.credential().is_revoked() || Instant::now() >= credential.expires_at() {
        return Err(ManagedResourceError::CredentialUnavailable);
    }
    Ok(())
}

fn read_identity(request: &CoreRequest) -> Result<(&str, bool), ManagedResourceError> {
    let CoreRequest::Final(FinalCoreRequest::ResourcesRead(params)) = request else {
        return Err(ManagedResourceError::NotResourceRead);
    };
    Ok((params.uri.as_str(), params.input_responses.is_none() && params.request_state.is_none()))
}

fn cache_key(target: &str, request: &CoreRequest, generation: u64) -> Result<FinalCacheKey, ManagedResourceError> {
    let (uri, reusable) = read_identity(request)?;
    if !reusable { return Err(ManagedCoreError::InvalidRequest.into()); }
    let params = request.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    let projection = serde_json::to_string(&params).map_err(|_| ManagedCoreError::InvalidRequest)?;
    Ok(FinalCacheKey::new(
        target, FINAL_PROTOCOL_VERSION, "included-in-exact-params", "core-only",
        "resources/read", projection, None, 0, 0, 0, 0,
        CachePartitionKey::new(format!("managed-resource-generation-{generation}")),
        FinalCacheResultSet::Resource(uri.to_owned()),
    ))
}

fn admit_result(result: &CoreResult, maximum_contents: usize) -> Result<bool, ManagedResourceError> {
    match result {
        CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. }) => {
            if result.payload.contents.len() > maximum_contents { return Err(ManagedResourceError::ContentsLimit); }
            Ok(true)
        }
        CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { .. }) => Ok(false),
        _ => Err(ManagedResourceError::InvalidResult),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, JsonRpcRequest};
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use serde_json::json;

    fn request(uri: &str) -> CoreRequest {
        decode(json!({"uri":uri}))
    }
    fn decode(mut params: serde_json::Value) -> CoreRequest {
        params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", Some(&params)).unwrap()
    }
    fn complete(request: &CoreRequest, ttl: u64, scope: &str) -> CoreResult {
        request.decode_result(&format!(r#"{{"resultType":"complete","contents":[{{"uri":"file:///one","text":"first"}},{{"uri":"file:///two","blob":"AAEC"}}],"ttlMs":{ttl},"cacheScope":"{scope}","x-exact":{{"z":900719925474099312345,"a":1.20e+4}}}}"#)).unwrap()
    }
    fn notification(method: &str, params: Option<serde_json::Value>) -> ServerNotification {
        ServerNotification::decode(&JsonRpcRequest::notification(method, params)).unwrap()
    }

    #[test]
    fn complete_read_retains_every_content_item_and_exact_unknown_payload() {
        let request = request("file:///one");
        let result = complete(&request, 60000, "private");
        assert!(admit_result(&result, 2).unwrap());
        assert!(matches!(admit_result(&result, 1), Err(ManagedResourceError::ContentsLimit)));
        let encoded = result.encode().unwrap();
        assert!(encoded.contains("file:///two") && encoded.contains("AAEC"));
        assert!(encoded.contains("900719925474099312345") && encoded.contains("1.20e+4"));
        assert!(encoded.find("first").unwrap() < encoded.find("AAEC").unwrap());
    }

    #[test]
    fn input_required_cache_lookalikes_remain_noncacheable() {
        let request = request("file:///one");
        let result = request.decode_result(r#"{"resultType":"input_required","requestState":"","ttlMs":60000,"cacheScope":"public"}"#).unwrap();
        assert!(!admit_result(&result, 0).unwrap());
        assert!(crate::cache::final_cache_hints(&result).is_none());
    }

    #[test]
    fn either_present_continuation_field_bypasses_cache_even_when_empty() {
        assert!(read_identity(&request("file:///one")).unwrap().1);
        for params in [
            json!({"uri":"file:///one","requestState":""}),
            json!({"uri":"file:///one","inputResponses":{}}),
            json!({"uri":"file:///one","requestState":"opaque","inputResponses":{}}),
        ] {
            let request = decode(params);
            assert!(!read_identity(&request).unwrap().1);
            assert!(cache_key("https://mcp.example/mcp", &request, 1).is_err());
        }
    }

    #[test]
    fn cache_identity_includes_uri_metadata_target_and_credential_generation() {
        let original = request("file:///one");
        let baseline = cache_key("https://mcp.example/mcp", &original, 1).unwrap();
        assert_ne!(baseline, cache_key("https://mcp.example/mcp", &original, 2).unwrap());
        assert_ne!(baseline, cache_key("https://other.example/mcp", &original, 1).unwrap());
        assert_ne!(baseline, cache_key("https://mcp.example/mcp", &request("file:///two"), 1).unwrap());
        let mut params = original.encode_params().unwrap().unwrap();
        params["_meta"]["com.example/tenant"] = json!("other");
        let changed = CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", Some(&params)).unwrap();
        assert_ne!(baseline, cache_key("https://mcp.example/mcp", &changed, 1).unwrap());
    }

    #[test]
    fn public_hints_cannot_cross_credential_partitions() {
        let request = request("file:///one");
        let key = cache_key("https://mcp.example/mcp", &request, 1).unwrap();
        let mut cache = FinalResultCache::default();
        let generation = cache.begin_fetch(key.result_set());
        assert_eq!(cache.insert_if_current(key.clone(), generation, complete(&request, 60000, "public")), FinalCacheInsert::Stored);
        assert!(matches!(cache.lookup(&key), FinalCacheLookup::Fresh(_)));
        let other = cache_key("https://mcp.example/mcp", &request, 2).unwrap();
        assert!(matches!(cache.lookup(&other), FinalCacheLookup::Miss(_)));
    }

    #[test]
    fn resource_and_catalog_notifications_fence_fills_but_tools_changes_do_not() {
        let request = request("file:///one");
        let key = cache_key("https://mcp.example/mcp", &request, 1).unwrap();
        for (method, params) in [
            ("notifications/resources/updated", Some(json!({"uri":"file:///one"}))),
            ("notifications/resources/list_changed", None),
        ] {
            let mut cache = FinalResultCache::default();
            let before = cache.begin_fetch(key.result_set());
            cache.invalidate_notification(&notification(method, params));
            assert_ne!(cache.begin_fetch(key.result_set()), before);
            assert_eq!(cache.insert_if_current(key.clone(), before, complete(&request, 60000, "private")), FinalCacheInsert::InvalidatedDuringFetch);
        }
        let mut cache = FinalResultCache::default();
        let before = cache.begin_fetch(key.result_set());
        cache.invalidate_notification(&notification("notifications/tools/list_changed", None));
        assert_eq!(cache.begin_fetch(key.result_set()), before);
    }

    #[test]
    fn zero_ttl_and_oversized_results_never_become_hits() {
        let request = request("file:///one");
        let key = cache_key("https://mcp.example/mcp", &request, 1).unwrap();
        let mut cache = FinalResultCache::with_limits(1, 1);
        let generation = cache.begin_fetch(key.result_set());
        assert_eq!(cache.insert_if_current(key.clone(), generation, complete(&request, 0, "private")), FinalCacheInsert::ImmediatelyStale);
        assert_eq!(cache.insert_if_current(key.clone(), generation, complete(&request, 60000, "private")), FinalCacheInsert::Oversized);
        assert!(matches!(cache.lookup(&key), FinalCacheLookup::Miss(_)));
    }

    #[test]
    fn non_read_requests_and_non_read_results_are_not_reinterpreted() {
        let params = json!({"_meta":FinalRequestMeta::new(ClientCapabilities::default())});
        let catalog = CoreRequest::decode(ProtocolEra::Modern2026, "resources/list", Some(&params)).unwrap();
        assert!(matches!(read_identity(&catalog), Err(ManagedResourceError::NotResourceRead)));
        let result = catalog.decode_result(r#"{"resultType":"complete","resources":[],"ttlMs":0,"cacheScope":"private"}"#).unwrap();
        assert!(matches!(admit_result(&result, 10), Err(ManagedResourceError::InvalidResult)));
        assert!(ManagedResourceLimits::new(ManagedCoreLimits::default(), 100_001).is_err());
    }
}
