//! Subscribe-before-read reconciliation of one machine-authenticated resource.
//!
//! Both exact-URI updates and resource-list changes must be acknowledged before
//! reading. Observed changes interrupt only an obsolete ordinary read, allowing
//! bounded reconciliation with fresh IDs. Arbitrary transport/authentication
//! failures never authorize retry. Input-required hands control to the host.
//!
//! The monitor and reader stay in the caller's task. There is no worker, runtime,
//! reconnect loop or durable event history. A published value is consistent with
//! observed changes, not a server-atomic snapshot or an ongoing freshness promise.

use std::fmt;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::task::{Poll, Waker};
use std::time::Duration;

use asupersync::{Cx, types::Time};
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreRequest, FinalRequestMeta, RequestId, ServerNotification, SubscriptionFilter};

use super::{
    ClientCredentialsResourceClient, ClientCredentialsResourceError,
    ClientCredentialsResourceRead, ManagedResourceError, read_identity,
};
use super::super::{ClientCredentialsCoreError, preflight};
use super::super::super::{
    ClientCredentialsError, ClientCredentialsSnapshot, OAuthDiscoveryError,
    active, check_context, check_token, discovery_deadline,
};
use super::super::super::subscriptions::{
    ClientCredentialsCoreSubscriptionError, ClientCredentialsCoreSubscriptionLimits,
    ModernHttpSubscriptionListenEvent,
};
use crate::cache::{FinalCacheResultSet, FinalResultCache};
use crate::http_auth::rpc::ManagedCoreError;

pub use crate::http_auth::rpc::resource::watch::{
    ManagedResourceWatchControl as ClientCredentialsResourceWatchControl,
    ManagedResourceWatchOutcome as ClientCredentialsResourceWatchOutcome,
};

/// One lifetime and bounded read/ID/record budgets, including obsolete reads.
/// Individual reads additionally obey the resource consumer's own wire limits.
#[derive(Clone, Copy, Debug)]
pub struct ClientCredentialsResourceWatchLimits {
    timeout: Duration,
    reads: usize,
    id_bytes: usize,
    subscription_records: usize,
}
impl Default for ClientCredentialsResourceWatchLimits {
    fn default() -> Self {
        Self { timeout: Duration::from_mins(15), reads: 64, id_bytes: 1024 * 1024, subscription_records: 1024 }
    }
}
impl ClientCredentialsResourceWatchLimits {
    pub fn new(timeout: Duration, reads: usize, id_bytes: usize, subscription_records: usize) -> Result<Self, ClientCredentialsResourceWatchError> {
        if timeout.is_zero() || timeout > Duration::from_secs(3600)
            || !(1..=1024).contains(&reads) || !(1..=8 * 1024 * 1024).contains(&id_bytes)
            || !(2..=4096).contains(&subscription_records)
        { return Err(ClientCredentialsResourceWatchError::InvalidLimits); }
        Ok(Self { timeout, reads, id_bytes, subscription_records })
    }
}

pub enum ClientCredentialsResourceWatchEvent {
    Acknowledged { accepted_filter: SubscriptionFilter },
    Notification(Box<ServerNotification>),
    Snapshot(ClientCredentialsResourceRead),
    /// Ends this watch. The host alone decides whether to answer or continue.
    InputRequired(ClientCredentialsResourceRead),
}

#[derive(Debug)]
pub enum ClientCredentialsResourceWatchError {
    InvalidLimits,
    ContinuationNotAllowed,
    CoverageRefused,
    ReadLimit,
    UnexpectedEvent,
    Resource(ClientCredentialsResourceError),
    Subscription(ClientCredentialsCoreSubscriptionError),
}
impl fmt::Display for ClientCredentialsResourceWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid machine resource watch limits"),
            Self::ContinuationNotAllowed => f.write_str("machine resource watch cannot repeat a continuation"),
            Self::CoverageRefused => f.write_str("machine subscription omitted required resource coverage"),
            Self::ReadLimit => f.write_str("machine resource reconciliation budget exhausted"),
            Self::UnexpectedEvent => f.write_str("unexpected machine resource subscription event"),
            Self::Resource(error) => fmt::Display::fmt(error, f),
            Self::Subscription(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ClientCredentialsResourceWatchError {}
impl From<ClientCredentialsResourceError> for ClientCredentialsResourceWatchError {
    fn from(error: ClientCredentialsResourceError) -> Self { Self::Resource(error) }
}
impl From<ManagedResourceError> for ClientCredentialsResourceWatchError {
    fn from(error: ManagedResourceError) -> Self { Self::Resource(error.into()) }
}
impl From<ManagedCoreError> for ClientCredentialsResourceWatchError {
    fn from(error: ManagedCoreError) -> Self { Self::Resource(error.into()) }
}
impl From<ClientCredentialsCoreError> for ClientCredentialsResourceWatchError {
    fn from(error: ClientCredentialsCoreError) -> Self { Self::Resource(error.into()) }
}
impl From<ClientCredentialsError> for ClientCredentialsResourceWatchError {
    fn from(error: ClientCredentialsError) -> Self { Self::Resource(error.into()) }
}
impl From<ClientCredentialsCoreSubscriptionError> for ClientCredentialsResourceWatchError {
    fn from(error: ClientCredentialsCoreSubscriptionError) -> Self { Self::Subscription(error) }
}

impl ClientCredentialsResourceClient {
    /// Opens and acknowledges the change feed before the first read. The same
    /// machine credential generation must own the feed and every delivered read.
    /// Both callbacks are synchronous and must cooperate with the caller runtime.
    /// Fresh discovery/operation pairs are required across the entire watch.
    pub async fn watch<I, O>(
        &self, cx: &Cx, request: CoreRequest, limits: ClientCredentialsResourceWatchLimits,
        next_ids: I, observe: O,
    ) -> Result<ClientCredentialsResourceWatchOutcome, ClientCredentialsResourceWatchError>
    where
        I: FnMut() -> Result<(RequestId, RequestId), ClientCredentialsResourceError>,
        O: FnMut(ClientCredentialsResourceWatchEvent) -> Result<ClientCredentialsResourceWatchControl, ClientCredentialsResourceError>,
    {
        self.watch_with_cancellation(cx, &McpRequestCancellation::new(), request, limits, next_ids, observe).await
    }

    /// Cancellation or dropping this future retires both responses and fences
    /// this consumer's resource cache. Stop does not close the machine owner.
    /// Stream gaps are terminal; starting another watch is an explicit host act.
    /// Already-published snapshots must be retired by the host after a gap.
    #[allow(clippy::too_many_arguments)]
    pub async fn watch_with_cancellation<I, O>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, request: CoreRequest,
        limits: ClientCredentialsResourceWatchLimits, next_ids: I, observe: O,
    ) -> Result<ClientCredentialsResourceWatchOutcome, ClientCredentialsResourceWatchError>
    where
        I: FnMut() -> Result<(RequestId, RequestId), ClientCredentialsResourceError>,
        O: FnMut(ClientCredentialsResourceWatchEvent) -> Result<ClientCredentialsResourceWatchControl, ClientCredentialsResourceError>,
    {
        let deadline = discovery_deadline(cx, limits.timeout).map_err(ClientCredentialsError::from)?;
        let (metadata, filter) = listen_arguments(&request)?;
        let uri = read_identity(&request)?.0.to_owned();
        // Measure the selected profile before opening any subscription. These
        // IDs never escape; actual pairs are checked again by the native paths.
        preflight(self.client.resource(), &request, &RequestId::Number(0), &RequestId::Number(1), self.limits.core)?;
        let stream_limits = ClientCredentialsCoreSubscriptionLimits::new(
            self.limits.core.request_bytes().min(64 * 1024),
            self.limits.core.frame_bytes().min(64 * 1024), limits.subscription_records, limits.timeout,
        )?;
        let ids = Mutex::new(WatchIds { next: next_ids, used: Vec::new(), bytes: 0, limits });
        let observer = Observer {
            callback: Mutex::new(observe), stopped: AtomicBool::new(false), failed: AtomicBool::new(false),
        };
        let set = FinalCacheResultSet::Resource(uri.clone());
        let owner = &self.client.inner.closed;
        let _gap = InvalidateOnExit { cache: Arc::clone(&self.cache), set: set.clone() };
        self.cache()?.invalidate_result_set(&set);
        active(cx, deadline, owner, cancellation, None, async {
            Ok(async {
                let (discovery_id, listen_id) = issue_pair(&ids)?;
                check_binding(cx, cancellation, deadline, owner, None)?;
                let mut subscription = self.client.subscribe_core_with_cancellation(
                    cx, cancellation, metadata, discovery_id, listen_id, filter, stream_limits,
                ).await?;
                let binding = self.client.credential_with_cancellation(cx, cancellation).await?;
                if subscription.credential_generation() != binding.generation() {
                    return Err(ManagedResourceError::CredentialChanged.into());
                }
                active(cx, deadline, owner, cancellation, Some(&binding), async {
                    Ok(async {
                        let Some(ModernHttpSubscriptionListenEvent::Acknowledged { accepted_filter }) = subscription.next_event(cx).await? else {
                            return Err(ClientCredentialsResourceWatchError::UnexpectedEvent);
                        };
                        if !covers(&uri, &accepted_filter) { return Err(ClientCredentialsResourceWatchError::CoverageRefused); }
                        check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                        self.cache()?.invalidate_result_set(&set);
                        let continuing = observer.emit(ClientCredentialsResourceWatchEvent::Acknowledged { accepted_filter })?;
                        check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                        if !continuing { return Ok(ClientCredentialsResourceWatchOutcome::StoppedByHost); }
                        let signal = ChangeSignal::default();
                        let monitor = async {
                            loop {
                                check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                let event = subscription.next_event(cx).await?;
                                check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                match event {
                                    Some(ModernHttpSubscriptionListenEvent::Notification(notification)) => {
                                        self.invalidate_notification(&notification)?;
                                        if relevant(&notification) { signal.changed()?; }
                                        let continuing = observer.emit(ClientCredentialsResourceWatchEvent::Notification(Box::new(notification)))?;
                                        check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                        if !continuing { return Ok(ClientCredentialsResourceWatchOutcome::StoppedByHost); }
                                    }
                                    Some(ModernHttpSubscriptionListenEvent::Terminal { .. }) => return Ok(ClientCredentialsResourceWatchOutcome::SubscriptionEnded),
                                    _ => return Err(ClientCredentialsResourceWatchError::UnexpectedEvent),
                                }
                            }
                        };
                        let reads = async {
                            let mut published = None;
                            let mut attempts = 0;
                            loop {
                                let revision = signal.wait_after(published).await?;
                                check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                if attempts >= limits.reads { return Err(ClientCredentialsResourceWatchError::ReadLimit); }
                                let Some(local) = signal.begin(revision)? else { continue };
                                let generation = self.cache()?.begin_fetch(&set);
                                attempts += 1;
                                let read = self.read_with_cancellation(cx, &local, request.clone(), || {
                                    check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                    let pair = issue_pair(&ids)?;
                                    check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                    Ok(pair)
                                }, |notification| {
                                    // read invalidates before invoking this observer.
                                    if relevant(&notification) { signal.changed()?; }
                                    check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                    let continuing = observer.emit(ClientCredentialsResourceWatchEvent::Notification(notification))?;
                                    check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                    if continuing { Ok(()) } else { Err(ManagedResourceError::AbortedByHost.into()) }
                                }).await;
                                signal.finish()?;
                                check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                // Local cancellation may replace the callback's
                                // error at the enclosing credential boundary.
                                // Never mistake that for permission to reread.
                                observer.check_failure()?;
                                if observer.stopped.load(Ordering::Acquire) { return Ok(ClientCredentialsResourceWatchOutcome::StoppedByHost); }
                                let changed = signal.revision()? != revision;
                                let read = match read {
                                    Ok(read) => read,
                                    Err(error) if changed && is_invalidation_stop(&error, &local) => { yield_once().await; continue; }
                                    Err(error) => return Err(error.into()),
                                };
                                if read.credential_generation() != binding.generation() { return Err(ManagedResourceError::CredentialChanged.into()); }
                                // A received challenge must never be discarded
                                // in favor of an automatic ordinary reread.
                                if !read.is_complete() {
                                    let continuing = observer.emit(ClientCredentialsResourceWatchEvent::InputRequired(read))?;
                                    check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                    return Ok(if continuing { ClientCredentialsResourceWatchOutcome::InputRequired }
                                        else { ClientCredentialsResourceWatchOutcome::StoppedByHost });
                                }
                                // Keep the pending stream read alive; let a ready
                                // update/gap win before publishing a snapshot.
                                yield_once().await;
                                check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                if signal.revision()? != revision { continue; }
                                if self.cache()?.begin_fetch(&set) != generation { return Err(ManagedResourceError::Invalidated.into()); }
                                let continuing = observer.emit(ClientCredentialsResourceWatchEvent::Snapshot(read))?;
                                check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                if !continuing { return Ok(ClientCredentialsResourceWatchOutcome::StoppedByHost); }
                                published = Some(revision);
                            }
                        };
                        monitor_first(monitor, reads).await
                    }.await)
                }).await?
            }.await)
        }).await?
    }
}

fn listen_arguments(request: &CoreRequest) -> Result<(FinalRequestMeta, SubscriptionFilter), ClientCredentialsResourceWatchError> {
    let (uri, ordinary) = read_identity(request)?;
    if !ordinary { return Err(ClientCredentialsResourceWatchError::ContinuationNotAllowed); }
    let params = request.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    let metadata = serde_json::from_value(params["_meta"].clone()).map_err(|_| ManagedCoreError::InvalidRequest)?;
    let mut filter = SubscriptionFilter::default();
    filter.resources_list_changed = Some(true);
    filter.resource_subscriptions = Some(vec![uri.to_owned()]);
    Ok((metadata, filter))
}
fn covers(uri: &str, filter: &SubscriptionFilter) -> bool {
    filter.resources_list_changed == Some(true)
        && filter.resource_subscriptions.as_ref().is_some_and(|uris| uris.iter().any(|candidate| candidate == uri))
}
fn relevant(notification: &ServerNotification) -> bool {
    matches!(notification, ServerNotification::ResourceUpdated(_) | ServerNotification::ResourcesListChanged(_))
}
fn check_binding(
    cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time,
    owner: &McpRequestCancellation, binding: Option<&ClientCredentialsSnapshot>,
) -> Result<(), ClientCredentialsResourceError> {
    if owner.is_cancel_requested() { return Err(ClientCredentialsError::Closed.into()); }
    if cancellation.is_cancel_requested() { return Err(ClientCredentialsError::from(OAuthDiscoveryError::Cancelled).into()); }
    let deadline = cx.budget().deadline.map_or(deadline, |caller| caller.min(deadline));
    check_context(cx, deadline).map_err(ClientCredentialsError::from)?;
    if let Some(binding) = binding { check_token(&binding.bearer, binding.expires_at)?; }
    Ok(())
}

struct WatchIds<I> { next: I, used: Vec<RequestId>, bytes: usize, limits: ClientCredentialsResourceWatchLimits }
fn issue_pair<I>(ids: &Mutex<WatchIds<I>>) -> Result<(RequestId, RequestId), ClientCredentialsResourceError>
where I: FnMut() -> Result<(RequestId, RequestId), ClientCredentialsResourceError> {
    let mut ids = ids.lock().map_err(|_| ManagedResourceError::CacheUnavailable)?;
    // One opening pair and at most one pair per bounded read attempt.
    if ids.used.len() / 2 > ids.limits.reads { return Err(ManagedCoreError::RequestTooLarge.into()); }
    let pair = (ids.next)()?;
    pair.0.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
    pair.1.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
    if pair.0.correlates_with(&pair.1) || ids.used.iter().any(|used| used.correlates_with(&pair.0) || used.correlates_with(&pair.1)) {
        return Err(ManagedCoreError::InvalidRequest.into());
    }
    let mut budget = ByteBudget { bytes: 0, maximum: ids.limits.id_bytes.saturating_sub(ids.bytes) };
    serde_json::to_writer(&mut budget, &pair.0).map_err(|_| ManagedCoreError::RequestTooLarge)?;
    serde_json::to_writer(&mut budget, &pair.1).map_err(|_| ManagedCoreError::RequestTooLarge)?;
    // Reserve both roles atomically; rejected pairs never enter the ledger.
    ids.bytes += budget.bytes;
    ids.used.push(pair.0.clone());
    ids.used.push(pair.1.clone());
    Ok(pair)
}
struct ByteBudget { bytes: usize, maximum: usize }
impl Write for ByteBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes) { return Err(io::Error::other("request ID byte limit")); }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
struct Observer<O> { callback: Mutex<O>, stopped: AtomicBool, failed: AtomicBool }
impl<O> Observer<O>
where O: FnMut(ClientCredentialsResourceWatchEvent) -> Result<ClientCredentialsResourceWatchControl, ClientCredentialsResourceError> {
    fn emit(&self, event: ClientCredentialsResourceWatchEvent) -> Result<bool, ClientCredentialsResourceError> {
        let result = match self.callback.lock() {
            Ok(mut callback) => callback(event),
            Err(_) => Err(ManagedResourceError::CacheUnavailable.into()),
        };
        let control = match result {
            Ok(control) => control,
            Err(error) => {
                self.failed.store(true, Ordering::Release);
                return Err(error);
            }
        };
        let continuing = control == ClientCredentialsResourceWatchControl::Continue;
        if !continuing { self.stopped.store(true, Ordering::Release); }
        Ok(continuing)
    }
    fn check_failure(&self) -> Result<(), ClientCredentialsResourceError> {
        if self.failed.load(Ordering::Acquire) { return Err(ManagedResourceError::AbortedByHost.into()); }
        Ok(())
    }
}
#[derive(Default)]
struct ChangeState { revision: u64, active: Option<McpRequestCancellation>, waiter: Option<Waker> }
#[derive(Default)]
struct ChangeSignal(Mutex<ChangeState>);
impl ChangeSignal {
    fn revision(&self) -> Result<u64, ManagedResourceError> {
        Ok(self.0.lock().map_err(|_| ManagedResourceError::CacheUnavailable)?.revision)
    }
    fn changed(&self) -> Result<(), ManagedResourceError> {
        let (active, waiter) = {
            let mut state = self.0.lock().map_err(|_| ManagedResourceError::CacheUnavailable)?;
            state.revision = state.revision.checked_add(1).ok_or(ManagedResourceError::CacheUnavailable)?;
            (state.active.take(), state.waiter.take())
        };
        if let Some(active) = active { active.cancel(); }
        if let Some(waiter) = waiter { waiter.wake(); }
        Ok(())
    }
    fn begin(&self, revision: u64) -> Result<Option<McpRequestCancellation>, ManagedResourceError> {
        let mut state = self.0.lock().map_err(|_| ManagedResourceError::CacheUnavailable)?;
        if state.revision != revision { return Ok(None); }
        let local = McpRequestCancellation::new();
        state.active = Some(local.clone());
        Ok(Some(local))
    }
    fn finish(&self) -> Result<(), ManagedResourceError> {
        self.0.lock().map_err(|_| ManagedResourceError::CacheUnavailable)?.active = None;
        Ok(())
    }
    async fn wait_after(&self, previous: Option<u64>) -> Result<u64, ManagedResourceError> {
        poll_fn(|task| {
            let mut state = self.0.lock().map_err(|_| ManagedResourceError::CacheUnavailable)?;
            if previous != Some(state.revision) { return Poll::Ready(Ok(state.revision)); }
            state.waiter = Some(task.waker().clone());
            Poll::Pending
        }).await
    }
}
fn is_invalidation_stop(error: &ClientCredentialsResourceError, local: &McpRequestCancellation) -> bool {
    matches!(error, ClientCredentialsResourceError::Resource(ManagedResourceError::Invalidated))
        || (local.is_cancel_requested() && matches!(error,
            ClientCredentialsResourceError::Core(
                ClientCredentialsCoreError::Protocol(ManagedCoreError::Cancelled)
                | ClientCredentialsCoreError::Authentication(
                    ClientCredentialsError::Discovery(OAuthDiscoveryError::Cancelled)
                )
            )
        ))
}
async fn yield_once() {
    let mut yielded = false;
    poll_fn(|task| {
        if yielded { Poll::Ready(()) } else {
            yielded = true;
            task.waker().wake_by_ref();
            Poll::Pending
        }
    }).await;
}
async fn monitor_first<T, E>(
    monitor: impl Future<Output = Result<T, E>>, reads: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let mut monitor = Box::pin(monitor);
    let mut reads = Box::pin(reads);
    poll_fn(|task| {
        if let Poll::Ready(result) = monitor.as_mut().poll(task) { return Poll::Ready(result); }
        reads.as_mut().poll(task)
    }).await
}
struct InvalidateOnExit { cache: Arc<Mutex<FinalResultCache>>, set: FinalCacheResultSet }
impl Drop for InvalidateOnExit {
    fn drop(&mut self) {
        if let Ok(mut cache) = self.cache.lock() { cache.invalidate_result_set(&self.set); }
    }
}

#[cfg(test)]
mod tests;
