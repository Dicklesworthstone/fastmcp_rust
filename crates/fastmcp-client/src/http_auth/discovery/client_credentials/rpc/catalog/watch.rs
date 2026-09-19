//! Subscription-driven reconciliation of machine-authenticated core catalogs.
//!
//! Acknowledge coverage before the first inventory. Keep the subscription read
//! alive while collecting pages; observed changes cancel only the obsolete list
//! traversal. Only that locally superseded traversal may restart, with bounded
//! attempts and fresh IDs. No failed HTTP/authentication operation is retried.
//!
//! The monitor and collector run in the caller's task. There is no detached
//! worker, runtime creation, automatic reconnect, durable event replay or server
//! snapshot-isolation claim. The host must retire published inventories when
//! the watch ends. Already-delivered notifications/snapshots cannot be recalled.

use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::task::{Poll, Waker};
use std::time::Duration;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreRequest, FinalRequestMeta, RequestId, ServerNotification, SubscriptionFilter};

use super::{
    CatalogKind, ClientCredentialsCatalogClient, ClientCredentialsCatalogError,
    CollectedMachineCatalog, ManagedCatalogError, Traversal, list_params,
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
use crate::cache::FinalResultCache;
use crate::http_auth::rpc::ManagedCoreError;

pub use crate::http_auth::rpc::catalog::watch::{
    ManagedCatalogWatchControl as ClientCredentialsCatalogWatchControl,
    ManagedCatalogWatchOutcome as ClientCredentialsCatalogWatchOutcome,
};

/// Whole-watch limits. Discarded inventories count as collection attempts.
/// Every listen/discovery/page ID is retained in one bounded ledger. Each
/// inventory additionally obeys its collector's own page/item/payload bounds.
#[derive(Clone, Copy, Debug)]
pub struct ClientCredentialsCatalogWatchLimits {
    timeout: Duration,
    maximum_collections: usize,
    maximum_request_ids: usize,
    maximum_state_bytes: usize,
    subscription_records: usize,
}
impl Default for ClientCredentialsCatalogWatchLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_mins(15), maximum_collections: 64,
            maximum_request_ids: 4096, maximum_state_bytes: 1024 * 1024,
            subscription_records: 4096,
        }
    }
}
impl ClientCredentialsCatalogWatchLimits {
    pub fn new(
        timeout: Duration, maximum_collections: usize, maximum_request_ids: usize,
        maximum_state_bytes: usize, subscription_records: usize,
    ) -> Result<Self, ClientCredentialsCatalogWatchError> {
        if timeout.is_zero() || timeout > Duration::from_secs(3600)
            || !(1..=1024).contains(&maximum_collections)
            || !(4..=4096).contains(&maximum_request_ids)
            || !(1..=8 * 1024 * 1024).contains(&maximum_state_bytes)
            || !(2..=4096).contains(&subscription_records)
        { return Err(ClientCredentialsCatalogWatchError::InvalidLimits); }
        Ok(Self { timeout, maximum_collections, maximum_request_ids, maximum_state_bytes, subscription_records })
    }
}

/// Notifications follow invalidation and precede any replacement inventory.
/// The acknowledged filter is the peer's accepted coverage, not a snapshot.
pub enum ClientCredentialsCatalogWatchEvent {
    Acknowledged { accepted_filter: SubscriptionFilter },
    Notification(Box<ServerNotification>),
    Snapshot(CollectedMachineCatalog),
}

#[derive(Debug)]
pub enum ClientCredentialsCatalogWatchError {
    InvalidLimits,
    CursorNotAllowed,
    CoverageRefused,
    CollectionLimit,
    UnexpectedEvent,
    Catalog(ClientCredentialsCatalogError),
    Subscription(ClientCredentialsCoreSubscriptionError),
}
impl fmt::Display for ClientCredentialsCatalogWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid machine catalog watch limits"),
            Self::CursorNotAllowed => f.write_str("machine catalog watch requires the first page"),
            Self::CoverageRefused => f.write_str("machine subscription omitted the catalog change category"),
            Self::CollectionLimit => f.write_str("machine catalog reconciliation budget exhausted"),
            Self::UnexpectedEvent => f.write_str("unexpected machine catalog subscription event"),
            Self::Catalog(error) => fmt::Display::fmt(error, f),
            Self::Subscription(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ClientCredentialsCatalogWatchError {}
impl From<ClientCredentialsCatalogError> for ClientCredentialsCatalogWatchError {
    fn from(error: ClientCredentialsCatalogError) -> Self { Self::Catalog(error) }
}
impl From<ManagedCatalogError> for ClientCredentialsCatalogWatchError {
    fn from(error: ManagedCatalogError) -> Self { Self::Catalog(error.into()) }
}
impl From<ManagedCoreError> for ClientCredentialsCatalogWatchError {
    fn from(error: ManagedCoreError) -> Self { Self::Catalog(error.into()) }
}
impl From<ClientCredentialsCoreError> for ClientCredentialsCatalogWatchError {
    fn from(error: ClientCredentialsCoreError) -> Self { Self::Catalog(error.into()) }
}
impl From<ClientCredentialsError> for ClientCredentialsCatalogWatchError {
    fn from(error: ClientCredentialsError) -> Self { Self::Catalog(error.into()) }
}
impl From<ClientCredentialsCoreSubscriptionError> for ClientCredentialsCatalogWatchError {
    fn from(error: ClientCredentialsCoreSubscriptionError) -> Self { Self::Subscription(error) }
}

impl ClientCredentialsCatalogClient {
    /// Watches a complete catalog, delivering an initial inventory and bounded
    /// replacements after observed changes. A live feed is acknowledged before
    /// any list is dispatched. The same machine credential generation must own
    /// the subscription and every published inventory; renewal ends the watch.
    ///
    /// The ID supplier returns fresh discovery/operation pairs. Both synchronous
    /// callbacks must cooperate and return promptly. Neither runs under the
    /// invalidation lock. Stop affects this watch, not the machine owner or any
    /// sibling operation. A new watch is explicit and never bridges a stream gap.
    pub async fn watch<I, O>(
        &self, cx: &Cx, request: CoreRequest, limits: ClientCredentialsCatalogWatchLimits,
        next_ids: I, observe: O,
    ) -> Result<ClientCredentialsCatalogWatchOutcome, ClientCredentialsCatalogWatchError>
    where
        I: FnMut() -> Result<(RequestId, RequestId), ClientCredentialsCatalogError>,
        O: FnMut(ClientCredentialsCatalogWatchEvent) -> Result<ClientCredentialsCatalogWatchControl, ClientCredentialsCatalogError>,
    {
        self.watch_with_cancellation(cx, &McpRequestCancellation::new(), request, limits, next_ids, observe).await
    }

    /// One deadline and cancellation domain include opening, acknowledgment,
    /// idle change waits and all refreshes. Abandoning this future drops BOTH
    /// responses and invalidates this result set. A list completing does not
    /// drop a pending subscription read or leave its parser unusable.
    #[allow(clippy::too_many_arguments)]
    pub async fn watch_with_cancellation<I, O>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        request: CoreRequest, limits: ClientCredentialsCatalogWatchLimits, next_ids: I, observe: O,
    ) -> Result<ClientCredentialsCatalogWatchOutcome, ClientCredentialsCatalogWatchError>
    where
        I: FnMut() -> Result<(RequestId, RequestId), ClientCredentialsCatalogError>,
        O: FnMut(ClientCredentialsCatalogWatchEvent) -> Result<ClientCredentialsCatalogWatchControl, ClientCredentialsCatalogError>,
    {
        let deadline = discovery_deadline(cx, limits.timeout).map_err(ClientCredentialsError::from)?;
        let kind = CatalogKind::of(&request)?;
        let (metadata, filter) = listen_arguments(&request)?;
        // Validate catalog/profile selection before opening a subscription. The
        // provisional IDs never escape; actual pairs are rechecked per request.
        preflight(self.client.resource(), &request, &RequestId::Number(0), &RequestId::Number(1), self.limits.core)?;
        let subscription_limits = ClientCredentialsCoreSubscriptionLimits::new(
            self.limits.core.request_bytes().min(64 * 1024),
            self.limits.core.frame_bytes().min(64 * 1024), limits.subscription_records, limits.timeout,
        )?;
        let ids = Mutex::new(WatchIds { next: next_ids, history: Traversal::default(), limits });
        let observer = Observer { callback: Mutex::new(observe), stopped: AtomicBool::new(false) };
        let owner = &self.client.inner.closed;
        let _gap = InvalidateOnExit { invalidation: Arc::clone(&self.invalidation), kind };
        self.fences()?.invalidate_result_set(&kind.result_set());
        active(cx, deadline, owner, cancellation, None, async {
            Ok(async {
                let (discovery_id, listen_id) = issue_pair(&ids)?;
                check_binding(cx, cancellation, deadline, owner, None)?;
                // subscribe_core measures both actual stamped documents before
                // credential acquisition. It never uses a replacement token
                // between the discovery POST and the listen POST.
                let mut subscription = self.client.subscribe_core_with_cancellation(
                    cx, cancellation, metadata, discovery_id, listen_id, filter, subscription_limits,
                ).await?;
                let binding = self.client.credential_with_cancellation(cx, cancellation).await?;
                if binding.generation() != subscription.credential_generation() {
                    return Err(ManagedCatalogError::CredentialChanged.into());
                }
                active(cx, deadline, owner, cancellation, Some(&binding), async {
                    Ok(async {
                        let Some(ModernHttpSubscriptionListenEvent::Acknowledged { accepted_filter }) = subscription.next_event(cx).await? else {
                            return Err(ClientCredentialsCatalogWatchError::UnexpectedEvent);
                        };
                        if !covers(kind, &accepted_filter) { return Err(ClientCredentialsCatalogWatchError::CoverageRefused); }
                        check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                        self.fences()?.invalidate_result_set(&kind.result_set());
                        let continuing = observer.emit(ClientCredentialsCatalogWatchEvent::Acknowledged { accepted_filter })?;
                        check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                        if !continuing { return Ok(ClientCredentialsCatalogWatchOutcome::StoppedByHost); }
                        let signal = ChangeSignal::default();
                        let monitor = async {
                            loop {
                                check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                let event = subscription.next_event(cx).await?;
                                check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                match event {
                                    Some(ModernHttpSubscriptionListenEvent::Notification(notification)) => {
                                        self.invalidate_notification(&notification)?;
                                        if relevant(kind, &notification) { signal.changed()?; }
                                        let continuing = observer.emit(ClientCredentialsCatalogWatchEvent::Notification(Box::new(notification)))?;
                                        check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                        if !continuing { return Ok(ClientCredentialsCatalogWatchOutcome::StoppedByHost); }
                                    }
                                    Some(ModernHttpSubscriptionListenEvent::Terminal { .. }) => {
                                        return Ok(ClientCredentialsCatalogWatchOutcome::SubscriptionEnded);
                                    }
                                    _ => return Err(ClientCredentialsCatalogWatchError::UnexpectedEvent),
                                }
                            }
                        };
                        let reconcile = async {
                            let mut published = None;
                            let mut attempts = 0;
                            loop {
                                let revision = signal.wait_after(published).await?;
                                check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                if attempts >= limits.maximum_collections { return Err(ClientCredentialsCatalogWatchError::CollectionLimit); }
                                let Some(local_cancel) = signal.begin(revision)? else { continue };
                                let generation = self.fences()?.begin_fetch(&kind.result_set());
                                attempts += 1;
                                let result = self.collect_with_cancellation(
                                    cx, &local_cancel, request.clone(),
                                    || {
                                        check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                        let pair = issue_pair(&ids)?;
                                        check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                        Ok(pair)
                                    },
                                    |notification| {
                                        // collect invalidates before this callback.
                                        if relevant(kind, &notification) { signal.changed()?; }
                                        check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                        let continuing = observer.emit(ClientCredentialsCatalogWatchEvent::Notification(notification))?;
                                        check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                        if continuing { Ok(()) } else { Err(ManagedCatalogError::AbortedByHost.into()) }
                                    },
                                ).await;
                                signal.finish()?;
                                check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                if observer.stopped.load(Ordering::Acquire) { return Ok(ClientCredentialsCatalogWatchOutcome::StoppedByHost); }
                                let changed = signal.revision()? != revision;
                                let catalog = match result {
                                    Ok(catalog) => catalog,
                                    Err(error) if changed && is_invalidation_stop(&error, &local_cancel) => {
                                        yield_once().await;
                                        continue;
                                    }
                                    Err(error) => return Err(error.into()),
                                };
                                if catalog.credential_generation() != binding.generation() {
                                    return Err(ManagedCatalogError::CredentialChanged.into());
                                }
                                // Give the persistent monitor first refusal of
                                // currently-ready changes/gaps before publication.
                                yield_once().await;
                                check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                if signal.revision()? != revision { continue; }
                                if self.fences()?.begin_fetch(&kind.result_set()) != generation {
                                    return Err(ManagedCatalogError::Invalidated.into());
                                }
                                published = Some(revision);
                                let continuing = observer.emit(ClientCredentialsCatalogWatchEvent::Snapshot(catalog))?;
                                check_binding(cx, cancellation, deadline, owner, Some(&binding))?;
                                if !continuing { return Ok(ClientCredentialsCatalogWatchOutcome::StoppedByHost); }
                            }
                        };
                        monitor_first(monitor, reconcile).await
                    }.await)
                }).await?
            }.await)
        }).await?
    }
}

fn listen_arguments(request: &CoreRequest) -> Result<(FinalRequestMeta, SubscriptionFilter), ClientCredentialsCatalogWatchError> {
    let kind = CatalogKind::of(request)?;
    if list_params(request)?.cursor.is_some() { return Err(ClientCredentialsCatalogWatchError::CursorNotAllowed); }
    let params = request.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    let metadata = serde_json::from_value(params["_meta"].clone()).map_err(|_| ManagedCoreError::InvalidRequest)?;
    Ok((metadata, requested_filter(kind)))
}
fn requested_filter(kind: CatalogKind) -> SubscriptionFilter {
    let mut filter = SubscriptionFilter::default();
    match kind {
        CatalogKind::Tools => filter.tools_list_changed = Some(true),
        CatalogKind::Resources | CatalogKind::Templates => filter.resources_list_changed = Some(true),
        CatalogKind::Prompts => filter.prompts_list_changed = Some(true),
    }
    filter
}
fn covers(kind: CatalogKind, filter: &SubscriptionFilter) -> bool {
    match kind {
        CatalogKind::Tools => filter.tools_list_changed == Some(true),
        CatalogKind::Resources | CatalogKind::Templates => filter.resources_list_changed == Some(true),
        CatalogKind::Prompts => filter.prompts_list_changed == Some(true),
    }
}
fn relevant(kind: CatalogKind, notification: &ServerNotification) -> bool {
    matches!((kind, notification),
        (CatalogKind::Tools, ServerNotification::ToolsListChanged(_))
        | (CatalogKind::Resources | CatalogKind::Templates, ServerNotification::ResourcesListChanged(_))
        | (CatalogKind::Prompts, ServerNotification::PromptsListChanged(_))
    )
}
fn check_binding(
    cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time,
    owner: &McpRequestCancellation, binding: Option<&ClientCredentialsSnapshot>,
) -> Result<(), ClientCredentialsCatalogError> {
    if owner.is_cancel_requested() { return Err(ClientCredentialsError::Closed.into()); }
    if cancellation.is_cancel_requested() { return Err(ClientCredentialsError::from(OAuthDiscoveryError::Cancelled).into()); }
    let deadline = cx.budget().deadline.map_or(deadline, |caller| caller.min(deadline));
    check_context(cx, deadline).map_err(ClientCredentialsError::from)?;
    if let Some(binding) = binding { check_token(&binding.bearer, binding.expires_at)?; }
    Ok(())
}
struct WatchIds<I> { next: I, history: Traversal, limits: ClientCredentialsCatalogWatchLimits }
fn issue_pair<I>(ids: &Mutex<WatchIds<I>>) -> Result<(RequestId, RequestId), ClientCredentialsCatalogError>
where I: FnMut() -> Result<(RequestId, RequestId), ClientCredentialsCatalogError> {
    let mut ids = ids.lock().map_err(|_| ManagedCatalogError::CacheUnavailable)?;
    if ids.limits.maximum_request_ids.saturating_sub(ids.history.ids.len()) < 2 {
        return Err(ManagedCatalogError::StateLimit.into());
    }
    let pair = (ids.next)()?;
    let maximum = ids.limits.maximum_state_bytes;
    ids.history.reserve_ids(&pair.0, &pair.1, maximum)?;
    Ok(pair)
}
struct Observer<O> { callback: Mutex<O>, stopped: AtomicBool }
impl<O> Observer<O>
where O: FnMut(ClientCredentialsCatalogWatchEvent) -> Result<ClientCredentialsCatalogWatchControl, ClientCredentialsCatalogError> {
    fn emit(&self, event: ClientCredentialsCatalogWatchEvent) -> Result<bool, ClientCredentialsCatalogError> {
        let control = (self.callback.lock().map_err(|_| ManagedCatalogError::CacheUnavailable)?)(event)?;
        let continuing = control == ClientCredentialsCatalogWatchControl::Continue;
        if !continuing { self.stopped.store(true, Ordering::Release); }
        Ok(continuing)
    }
}
#[derive(Default)]
struct ChangeState { revision: u64, active: Option<McpRequestCancellation>, waiter: Option<Waker> }
#[derive(Default)]
struct ChangeSignal(Mutex<ChangeState>);
impl ChangeSignal {
    fn revision(&self) -> Result<u64, ManagedCatalogError> {
        Ok(self.0.lock().map_err(|_| ManagedCatalogError::CacheUnavailable)?.revision)
    }
    fn changed(&self) -> Result<(), ManagedCatalogError> {
        let (active, waiter) = {
            let mut state = self.0.lock().map_err(|_| ManagedCatalogError::CacheUnavailable)?;
            state.revision = state.revision.checked_add(1).ok_or(ManagedCatalogError::StateLimit)?;
            (state.active.take(), state.waiter.take())
        };
        if let Some(active) = active { active.cancel(); }
        if let Some(waiter) = waiter { waiter.wake(); }
        Ok(())
    }
    fn begin(&self, revision: u64) -> Result<Option<McpRequestCancellation>, ManagedCatalogError> {
        let mut state = self.0.lock().map_err(|_| ManagedCatalogError::CacheUnavailable)?;
        if state.revision != revision { return Ok(None); }
        let cancel = McpRequestCancellation::new();
        state.active = Some(cancel.clone());
        Ok(Some(cancel))
    }
    fn finish(&self) -> Result<(), ManagedCatalogError> {
        self.0.lock().map_err(|_| ManagedCatalogError::CacheUnavailable)?.active = None;
        Ok(())
    }
    async fn wait_after(&self, previous: Option<u64>) -> Result<u64, ManagedCatalogError> {
        poll_fn(|task| {
            let mut state = self.0.lock().map_err(|_| ManagedCatalogError::CacheUnavailable)?;
            if previous != Some(state.revision) { return Poll::Ready(Ok(state.revision)); }
            state.waiter = Some(task.waker().clone());
            Poll::Pending
        }).await
    }
}
fn is_invalidation_stop(error: &ClientCredentialsCatalogError, local: &McpRequestCancellation) -> bool {
    matches!(error, ClientCredentialsCatalogError::Catalog(ManagedCatalogError::Invalidated))
        || (local.is_cancel_requested() && matches!(error,
            ClientCredentialsCatalogError::Core(ClientCredentialsCoreError::Protocol(ManagedCoreError::Cancelled))
            | ClientCredentialsCatalogError::Core(ClientCredentialsCoreError::Authentication(
                ClientCredentialsError::Discovery(OAuthDiscoveryError::Cancelled)
            ))
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
    monitor: impl Future<Output = Result<T, E>>, reconcile: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    // Retain both futures across every page/publication. In particular, never
    // drop a pending subscription read merely because a list became ready.
    let mut monitor = Box::pin(monitor);
    let mut reconcile = Box::pin(reconcile);
    poll_fn(|task| {
        if let Poll::Ready(result) = monitor.as_mut().poll(task) { return Poll::Ready(result); }
        reconcile.as_mut().poll(task)
    }).await
}
struct InvalidateOnExit { invalidation: Arc<Mutex<FinalResultCache>>, kind: CatalogKind }
impl Drop for InvalidateOnExit {
    fn drop(&mut self) {
        if let Ok(mut fences) = self.invalidation.lock() {
            fences.invalidate_result_set(&self.kind.result_set());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::task::Wake;
    use fastmcp_protocol::{ClientCapabilities, JsonRpcRequest};
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use serde_json::json;

    struct Flag(AtomicBool);
    impl Wake for Flag { fn wake(self: Arc<Self>) { self.0.store(true, Ordering::Release); } }
    fn waker() -> Waker { Waker::from(Arc::new(Flag(AtomicBool::new(false)))) }
    fn request(method: &str) -> CoreRequest {
        CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&json!({
            "_meta":FinalRequestMeta::new(ClientCapabilities::default()), "includeTags":["selected"],
        }))).unwrap()
    }

    #[test]
    fn machine_watch_requires_its_own_accepted_change_category() {
        for (method, key) in [("tools/list","toolsListChanged"),("resources/list","resourcesListChanged"),
            ("resources/templates/list","resourcesListChanged"),("prompts/list","promptsListChanged")]
        {
            let request = request(method);
            let (metadata, filter) = listen_arguments(&request).unwrap();
            assert_eq!(serde_json::to_value(metadata).unwrap(), request.encode_params().unwrap().unwrap()["_meta"]);
            assert_eq!(serde_json::to_value(&filter).unwrap(), json!({key:true}));
            let kind = CatalogKind::of(&request).unwrap();
            assert!(covers(kind, &filter));
            assert!(!covers(kind, &SubscriptionFilter::default()));
        }
    }

    #[test]
    fn machine_watch_does_not_treat_a_catalog_suffix_as_a_full_inventory() {
        for cursor in ["", "opaque"] {
            let mut request = request("tools/list");
            super::super::list_params_mut(&mut request).unwrap().cursor = Some(cursor.to_owned());
            assert!(matches!(listen_arguments(&request), Err(ClientCredentialsCatalogWatchError::CursorNotAllowed)));
        }
    }

    #[test]
    fn machine_watch_changes_cancel_only_the_obsolete_traversal() {
        let signal = ChangeSignal::default();
        let first = signal.begin(0).unwrap().unwrap();
        let sibling = McpRequestCancellation::new();
        signal.changed().unwrap();
        signal.changed().unwrap();
        assert!(first.is_cancel_requested());
        assert!(!sibling.is_cancel_requested());
        assert_eq!(signal.revision().unwrap(), 2);
        assert!(signal.begin(0).unwrap().is_none());
        let next = signal.begin(2).unwrap().unwrap();
        signal.finish().unwrap();
        signal.changed().unwrap();
        assert!(!next.is_cancel_requested());
    }

    #[test]
    fn machine_watch_idle_change_wait_wakes_without_polling() {
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(flag.clone());
        let mut context = std::task::Context::from_waker(&waker);
        let signal = ChangeSignal::default();
        let mut waiting = Box::pin(signal.wait_after(Some(0)));
        assert!(waiting.as_mut().poll(&mut context).is_pending());
        signal.changed().unwrap();
        assert!(flag.0.load(Ordering::Acquire));
        assert!(matches!(waiting.as_mut().poll(&mut context), Poll::Ready(Ok(1))));
    }

    #[test]
    fn machine_watch_ready_gap_wins_over_a_ready_snapshot() {
        let published = AtomicBool::new(false);
        let mut race = Box::pin(monitor_first(async { Ok::<_, ()>(1) }, async {
            published.store(true, Ordering::Release);
            Ok(2)
        }));
        let waker = waker();
        let mut context = std::task::Context::from_waker(&waker);
        assert!(matches!(race.as_mut().poll(&mut context), Poll::Ready(Ok(1))));
        assert!(!published.load(Ordering::Acquire));
    }

    #[test]
    fn machine_watch_retains_pending_monitor_while_reconciliation_progresses() {
        struct PendingBody(Arc<AtomicBool>);
        impl Future for PendingBody {
            type Output = Result<(), ()>;
            fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Self::Output> { Poll::Pending }
        }
        impl Drop for PendingBody { fn drop(&mut self) { self.0.store(true, Ordering::Release); } }
        let closed = Arc::new(AtomicBool::new(false));
        let progress = AtomicUsize::new(0);
        let mut watch = Box::pin(monitor_first(PendingBody(closed.clone()), poll_fn(|_| {
            progress.fetch_add(1, Ordering::AcqRel);
            Poll::Pending::<Result<(), ()>>
        })));
        let waker = waker();
        let mut context = std::task::Context::from_waker(&waker);
        assert!(watch.as_mut().poll(&mut context).is_pending());
        assert!(watch.as_mut().poll(&mut context).is_pending());
        assert_eq!(progress.load(Ordering::Acquire), 2);
        assert!(!closed.load(Ordering::Acquire));
        drop(watch);
        assert!(closed.load(Ordering::Acquire));
    }

    #[test]
    fn machine_watch_never_retries_unrelated_failures_as_invalidation() {
        let cancel = McpRequestCancellation::new();
        let cancelled: ClientCredentialsCatalogError = ClientCredentialsError::from(OAuthDiscoveryError::Cancelled).into();
        assert!(!is_invalidation_stop(&cancelled, &cancel));
        cancel.cancel();
        assert!(is_invalidation_stop(&cancelled, &cancel));
        for error in [ManagedCatalogError::InvalidPage.into(), ManagedCatalogError::AbortedByHost.into(),
            ManagedCatalogError::CredentialChanged.into(), ClientCredentialsError::Transport.into(),
            ManagedCoreError::HttpStatus { status: 503 }.into()]
        { assert!(!is_invalidation_stop(&error, &cancel)); }
    }

    #[test]
    fn machine_watch_id_budget_covers_listen_and_every_discovery_pair() {
        let mut next = 0;
        let limits = ClientCredentialsCatalogWatchLimits::new(Duration::from_secs(1), 2, 4, 4096, 2).unwrap();
        let ids = Mutex::new(WatchIds { next: || {
            next += 2;
            Ok((RequestId::Number(next - 1), RequestId::Number(next)))
        }, history: Traversal::default(), limits });
        issue_pair(&ids).unwrap();
        issue_pair(&ids).unwrap();
        assert!(matches!(issue_pair(&ids), Err(ClientCredentialsCatalogError::Catalog(ManagedCatalogError::StateLimit))));
        assert_eq!(ids.lock().unwrap().history.ids.len(), 4);
        drop(ids);
        assert_eq!(next, 4);
    }

    #[test]
    fn machine_watch_exit_invalidates_only_its_own_catalog() {
        let fences = Arc::new(Mutex::new(FinalResultCache::default()));
        let tools = CatalogKind::Tools.result_set();
        let prompts = CatalogKind::Prompts.result_set();
        let before_tools = fences.lock().unwrap().begin_fetch(&tools);
        let before_prompts = fences.lock().unwrap().begin_fetch(&prompts);
        drop(InvalidateOnExit { invalidation: fences.clone(), kind: CatalogKind::Tools });
        assert_ne!(before_tools, fences.lock().unwrap().begin_fetch(&tools));
        assert_eq!(before_prompts, fences.lock().unwrap().begin_fetch(&prompts));
    }

    #[test]
    fn machine_watch_classifies_changes_and_rejects_unbounded_policies() {
        let tools = ServerNotification::decode(&JsonRpcRequest::notification("notifications/tools/list_changed", None)).unwrap();
        assert!(relevant(CatalogKind::Tools, &tools));
        assert!(!relevant(CatalogKind::Resources, &tools));
        for (timeout, collections, ids, bytes, records) in [
            (0,1,4,1,2),(3601,1,4,1,2),(1,0,4,1,2),(1,1025,4,1,2),
            (1,1,3,1,2),(1,1,4097,1,2),(1,1,4,0,2),(1,1,4,1,1),
        ] {
            assert!(ClientCredentialsCatalogWatchLimits::new(Duration::from_secs(timeout), collections, ids, bytes, records).is_err());
        }
    }
}
