//! Bounded resource reads and opt-in, credential-local caching for machine clients.
//!
//! Uses the existing same-token discovery/dispatch and incremental core decoder.
//! Only complete, ordinary reads are reusable: input-required results and either
//! present continuation field bypass caching. No resolver, automatic POST retry,
//! background runtime, persistent cache or cross-client sharing is introduced.
//!
//! Clones share a bounded cache and invalidation fences. Feed validated resource
//! notifications to `invalidate_notification`, and clear after a subscription
//! gap or local policy change. Public cache hints never broaden authorization.

/// Subscription-driven reconciliation with explicit input-required handoff.
pub mod watch;

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    CoreRequest, CoreResult, FinalCoreRequest, FinalCoreResult, RequestId,
    ServerNotification, FINAL_PROTOCOL_VERSION,
};

use super::{ClientCredentialsCoreError, ManagedCoreEvent, ManagedCoreLimits, preflight};
use super::super::{
    ClientCredentialsClient, ClientCredentialsError, ClientCredentialsSnapshot,
    OAuthDiscoveryError, active, check_context, check_token, discovery_deadline, prepare,
};
use crate::cache::{
    CachePartitionKey, FinalCacheGeneration, FinalCacheInsert, FinalCacheKey,
    FinalCacheLookup, FinalCacheResultSet, FinalCacheStats, FinalResultCache,
    MAX_FINAL_CACHE_CAPACITY, MAX_FINAL_CACHE_MAX_BYTES,
};
use crate::http_auth::rpc::ManagedCoreError;
pub use crate::http_auth::rpc::resource::ManagedResourceError;

/// Core wire/time bounds plus a limit on the returned content-item vector.
#[derive(Clone, Copy, Debug)]
pub struct ClientCredentialsResourceLimits {
    core: ManagedCoreLimits,
    maximum_contents: usize,
}
impl Default for ClientCredentialsResourceLimits {
    fn default() -> Self {
        Self { core: ManagedCoreLimits::default(), maximum_contents: 1024 }
    }
}
impl ClientCredentialsResourceLimits {
    pub fn new(core: ManagedCoreLimits, maximum_contents: usize) -> Result<Self, ClientCredentialsResourceError> {
        if maximum_contents > 100_000 { return Err(ManagedResourceError::InvalidLimits.into()); }
        Ok(Self { core, maximum_contents })
    }
}

/// Sanitized failures retain neither credentials nor URIs, metadata or contents.
#[derive(Debug)]
pub enum ClientCredentialsResourceError {
    Core(ClientCredentialsCoreError),
    Resource(ManagedResourceError),
}
impl fmt::Display for ClientCredentialsResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => fmt::Display::fmt(error, f),
            Self::Resource(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ClientCredentialsResourceError {}
impl From<ClientCredentialsCoreError> for ClientCredentialsResourceError {
    fn from(error: ClientCredentialsCoreError) -> Self { Self::Core(error) }
}
impl From<ClientCredentialsError> for ClientCredentialsResourceError {
    fn from(error: ClientCredentialsError) -> Self { Self::Core(error.into()) }
}
impl From<ManagedCoreError> for ClientCredentialsResourceError {
    fn from(error: ManagedCoreError) -> Self { Self::Core(error.into()) }
}
impl From<ManagedResourceError> for ClientCredentialsResourceError {
    fn from(error: ManagedResourceError) -> Self { Self::Resource(error) }
}

/// One exact typed read outcome, including explicit input-required handoff.
/// Already-delivered contents cannot be recalled by later invalidation.
pub struct ClientCredentialsResourceRead {
    uri: String,
    result: CoreResult,
    credential_generation: u64,
    cache_hit: bool,
}
impl ClientCredentialsResourceRead {
    pub fn uri(&self) -> &str { &self.uri }
    pub fn result(&self) -> &CoreResult { &self.result }
    pub fn into_result(self) -> CoreResult { self.result }
    /// Local to this machine owner, not an identity usable across clients.
    pub fn credential_generation(&self) -> u64 { self.credential_generation }
    pub fn is_cache_hit(&self) -> bool { self.cache_hit }
    pub fn is_complete(&self) -> bool {
        matches!(&self.result, CoreResult::Final(FinalCoreResult::ResourcesRead { .. }))
    }
}

/// Immutable machine identity and read policy. Separately constructed consumers
/// never share results, even when the server advertises public cache scope.
#[derive(Clone)]
pub struct ClientCredentialsResourceClient {
    client: ClientCredentialsClient,
    limits: ClientCredentialsResourceLimits,
    cache: Arc<Mutex<FinalResultCache>>,
}
impl ClientCredentialsResourceClient {
    /// Starts uncached; invalidation and credential fences are still enforced.
    pub fn new(client: ClientCredentialsClient, limits: ClientCredentialsResourceLimits) -> Self {
        let mut cache = FinalResultCache::default();
        cache.set_enabled(false);
        Self { client, limits, cache: Arc::new(Mutex::new(cache)) }
    }

    /// Enables a bounded cache for the returned consumer. Earlier clones retain
    /// their old cache; later clones share the newly configured cache.
    pub fn with_cache_limits(mut self, entries: usize, bytes: usize) -> Result<Self, ClientCredentialsResourceError> {
        if !(1..=MAX_FINAL_CACHE_CAPACITY).contains(&entries)
            || !(1..=MAX_FINAL_CACHE_MAX_BYTES).contains(&bytes)
        { return Err(ManagedResourceError::InvalidLimits.into()); }
        self.cache = Arc::new(Mutex::new(FinalResultCache::with_limits(entries, bytes)));
        Ok(self)
    }

    /// Retires retained entries AND reads that captured an earlier generation.
    pub fn clear(&self) -> Result<(), ClientCredentialsResourceError> {
        self.cache()?.clear();
        Ok(())
    }

    /// Accepts already-validated notifications from this machine endpoint.
    /// Resource updates and resource-list changes fence reads; unrelated catalog
    /// updates do not. The shared cache uses fixed-cardinality generations.
    pub fn invalidate_notification(&self, notification: &ServerNotification) -> Result<(), ClientCredentialsResourceError> {
        self.cache()?.invalidate_notification(notification);
        Ok(())
    }

    pub fn cache_stats(&self) -> Result<FinalCacheStats, ClientCredentialsResourceError> {
        Ok(self.cache()?.stats())
    }

    /// Gets one typed outcome. `next_ids` supplies a discovery/operation pair
    /// only on a cache miss. A hit allocates no IDs and replays no notifications.
    /// Observers run incrementally, without holding a cache mutex.
    pub async fn read<I, O>(
        &self, cx: &Cx, request: CoreRequest, next_ids: I, observe: O,
    ) -> Result<ClientCredentialsResourceRead, ClientCredentialsResourceError>
    where
        I: FnOnce() -> Result<(RequestId, RequestId), ClientCredentialsResourceError>,
        O: FnMut(Box<ServerNotification>) -> Result<(), ClientCredentialsResourceError>,
    {
        self.read_with_cancellation(cx, &McpRequestCancellation::new(), request, next_ids, observe).await
    }

    /// One deadline covers acquisition, discovery, callbacks and body reads.
    /// Cancellation, closure, expiry, renewal or invalidation cannot publish a
    /// stale read or refill an invalidated cache. Synchronous callbacks must
    /// cooperate with the runtime; their side effects cannot be rolled back.
    pub async fn read_with_cancellation<I, O>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        request: CoreRequest, next_ids: I, mut observe: O,
    ) -> Result<ClientCredentialsResourceRead, ClientCredentialsResourceError>
    where
        I: FnOnce() -> Result<(RequestId, RequestId), ClientCredentialsResourceError>,
        O: FnMut(Box<ServerNotification>) -> Result<(), ClientCredentialsResourceError>,
    {
        let deadline = discovery_deadline(cx, self.limits.core.timeout().min(self.client.inner.timeout))
            .map_err(ClientCredentialsError::from)?;
        let (uri, reusable) = read_identity(&request)?;
        let result_set = FinalCacheResultSet::Resource(uri.to_owned());
        let uri = uri.to_owned();
        // Validate the stamped profile even for hits, before credential work.
        // These provisional IDs are never dispatched or exposed to callbacks.
        preflight(self.client.resource(), &request, &RequestId::Number(0), &RequestId::Number(1), self.limits.core)?;
        let (_, stamped) = prepare(self.client.resource(), &request, &RequestId::Number(1))?;
        let captured = self.cache()?.begin_fetch(&result_set);
        let owner = &self.client.inner.closed;
        active(cx, deadline, owner, cancellation, None, async {
            Ok(async {
                let credential = self.client.credential_with_cancellation(cx, cancellation).await?;
                self.check(cx, cancellation, deadline, &credential, &result_set, captured)?;
                let key = if reusable {
                    Some(cache_key(self.client.resource().as_str(), &stamped, credential.generation())?)
                } else { None };
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
                    if bytes > self.limits.core.frame_bytes() || bytes > self.limits.core.total_bytes() {
                        return Err(ManagedCoreError::ResponseByteLimit.into());
                    }
                    (result, Instant::now())
                } else {
                    let (discovery_id, request_id) = next_ids()?;
                    self.check(cx, cancellation, deadline, &credential, &result_set, captured)?;
                    // The actual pair, including arbitrary-length IDs, must fit
                    // both wire documents before either authenticated POST.
                    preflight(self.client.resource(), &request, &discovery_id, &request_id, self.limits.core)?;
                    let mut call = active(cx, deadline, owner, cancellation, Some(&credential), async {
                        Ok(self.client.request_core_with_cancellation(
                            cx, cancellation, request, discovery_id, request_id, self.limits.core,
                        ).await)
                    }).await??;
                    require_same_credential(&credential, &call.snapshot)?;
                    call.deadline = call.deadline.min(deadline);
                    let result = loop {
                        let event = call.next_event(cx).await?.ok_or(ManagedResourceError::InvalidResult)?;
                        self.check(cx, cancellation, deadline, &credential, &result_set, captured)?;
                        match event {
                            ManagedCoreEvent::Notification(notification) => {
                                self.invalidate_notification(&notification)?;
                                observe(notification)?;
                                self.check(cx, cancellation, deadline, &credential, &result_set, captured)?;
                            }
                            ManagedCoreEvent::Result(result) => break *result,
                        }
                    };
                    (result, Instant::now())
                };
                let complete = admit_result(&result, self.limits.maximum_contents)?;
                // A different caller may have renewed while we decoded. Check
                // current custody on hits too, rather than trusting a cache key.
                let current = active(cx, deadline, owner, cancellation, Some(&credential),
                    self.client.credential_with_cancellation(cx, cancellation)).await?;
                require_same_credential(&credential, &current)?;
                self.check(cx, cancellation, deadline, &credential, &result_set, captured)?;
                {
                    let mut cache = self.cache()?;
                    if cache.begin_fetch(&result_set) != captured { return Err(ManagedResourceError::Invalidated.into()); }
                    check_token(&credential.bearer, credential.expires_at)?;
                    if complete && !cache_hit && cache.is_enabled() {
                        if let Some(key) = key {
                            if cache.insert_if_current_at(key, captured, result.clone(), receipt)
                                == FinalCacheInsert::InvalidatedDuringFetch
                            { return Err(ManagedResourceError::Invalidated.into()); }
                        }
                    }
                }
                self.check(cx, cancellation, deadline, &credential, &result_set, captured)?;
                Ok(ClientCredentialsResourceRead {
                    uri, result, credential_generation: credential.generation(), cache_hit,
                })
            }.await)
        }).await?
    }

    fn cache(&self) -> Result<MutexGuard<'_, FinalResultCache>, ClientCredentialsResourceError> {
        self.cache.lock().map_err(|_| ManagedResourceError::CacheUnavailable.into())
    }

    fn check(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time,
        credential: &ClientCredentialsSnapshot, result_set: &FinalCacheResultSet, captured: FinalCacheGeneration,
    ) -> Result<(), ClientCredentialsResourceError> {
        if self.client.inner.closed.is_cancel_requested() { return Err(ClientCredentialsError::Closed.into()); }
        if cancellation.is_cancel_requested() { return Err(ClientCredentialsError::from(OAuthDiscoveryError::Cancelled).into()); }
        let deadline = cx.budget().deadline.map_or(deadline, |caller| caller.min(deadline));
        check_context(cx, deadline).map_err(ClientCredentialsError::from)?;
        check_token(&credential.bearer, credential.expires_at)?;
        if self.cache()?.begin_fetch(result_set) != captured { return Err(ManagedResourceError::Invalidated.into()); }
        Ok(())
    }
}

fn require_same_credential(
    pinned: &ClientCredentialsSnapshot, current: &ClientCredentialsSnapshot,
) -> Result<(), ClientCredentialsResourceError> {
    check_token(&pinned.bearer, pinned.expires_at)?;
    check_token(&current.bearer, current.expires_at)?;
    if pinned.generation() != current.generation() { return Err(ManagedResourceError::CredentialChanged.into()); }
    Ok(())
}

fn read_identity(request: &CoreRequest) -> Result<(&str, bool), ManagedResourceError> {
    let CoreRequest::Final(FinalCoreRequest::ResourcesRead(params)) = request else {
        return Err(ManagedResourceError::NotResourceRead);
    };
    Ok((params.uri.as_str(), params.input_responses.is_none() && params.request_state.is_none()))
}

fn cache_key(target: &str, request: &CoreRequest, generation: u64) -> Result<FinalCacheKey, ClientCredentialsResourceError> {
    let (uri, reusable) = read_identity(request)?;
    if !reusable { return Err(ManagedCoreError::InvalidRequest.into()); }
    let params = request.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    let projection = serde_json::to_string(&params).map_err(|_| ManagedCoreError::InvalidRequest)?;
    Ok(FinalCacheKey::new(
        target, FINAL_PROTOCOL_VERSION, "included-in-exact-params", "machine-core-only",
        "resources/read", projection, None, 0, 0, 0, 0,
        CachePartitionKey::new(format!("machine-resource-generation-{generation}")),
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
mod tests;
