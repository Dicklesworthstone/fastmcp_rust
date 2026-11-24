//! Caller-driven catalog reconciliation while a core subscription remains live.
//!
//! CACHE-03/SUB-03: acknowledge the change feed before fetching a full catalog,
//! invalidate before observing a change, and cancel an obsolete page traversal.
//! Ordinary watches restart a traversal only after observed invalidation.
//! Explicit recovery can replace an acknowledged, interrupted listen, report a
//! gap and collect afresh after a new ACK. It cannot recover missed history.
//!
//! Both futures are polled in the caller's task. No runtime, worker, unbounded
//! event queue, detached refresh or missed-event replay is created. Reconnects
//! require the opt-in recovery API. Snapshots reflect observed changes, not
//! an atomic server-side snapshot or a promise of perpetual freshness. The host
//! owns already-delivered snapshots and must retire them on a gap or watch end.

use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

use asupersync::{Cx, types::Time};
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{CoreRequest, RequestId, ServerNotification, SubscriptionFilter};

use super::super::BoundedWriter;
use super::{
    CatalogKind, CollectedCatalog, ManagedCatalogClient, ManagedCatalogError, ManagedCoreError,
    Traversal, bounded_wait, call_deadline, check_call, list_params, prepare, require_unrevoked,
};
use crate::http_auth::managed::subscriptions::{
    ManagedSubscription, ManagedSubscriptionError, ManagedSubscriptionEvent,
    ManagedSubscriptionLimits,
};
use crate::http_auth::managed::{OAuthCredentialSnapshot, OAuthSessionError};
use crate::http_executor::ModernHttpExecutorError;

/// Whole-watch bounds. Each traversal additionally retains its collector's
/// page/item/payload/notification limits; the subscription retains native HTTP
/// deadlines and frame limits. The listen POST also consumes one request ID.
#[derive(Clone, Copy, Debug)]
pub struct ManagedCatalogWatchLimits {
    timeout: Duration,
    maximum_collections: usize,
    maximum_request_ids: usize,
    maximum_state_bytes: usize,
    subscription_records: usize,
}

impl Default for ManagedCatalogWatchLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_mins(15),
            maximum_collections: 64,
            maximum_request_ids: 4096,
            maximum_state_bytes: 1024 * 1024,
            subscription_records: 4096,
        }
    }
}

impl ManagedCatalogWatchLimits {
    /// Collection attempts include discarded traversals. Reaching the limit
    /// prevents another GET-like list POST, rather than returning partial data.
    pub fn new(
        timeout: Duration,
        maximum_collections: usize,
        maximum_request_ids: usize,
        maximum_state_bytes: usize,
        subscription_records: usize,
    ) -> Result<Self, ManagedCatalogWatchError> {
        if timeout.is_zero()
            || timeout > Duration::from_secs(3600)
            || !(1..=1024).contains(&maximum_collections)
            || !(2..=4096).contains(&maximum_request_ids)
            || !(1..=8 * 1024 * 1024).contains(&maximum_state_bytes)
            || !(2..=4096).contains(&subscription_records)
        {
            return Err(ManagedCatalogWatchError::InvalidLimits);
        }
        Ok(Self {
            timeout,
            maximum_collections,
            maximum_request_ids,
            maximum_state_bytes,
            subscription_records,
        })
    }
}

/// Opt-in, finite reconnect policy for an acknowledged catalog change feed.
///
/// Only an interrupted subscription body or EOF without a valid terminal can
/// reconnect. Initial/replacement listen admission failures, MCP/SSE admission
/// errors, authorization errors, catalog-call failures and host failures remain
/// terminal. A valid peer completion/cancellation is not an interruption.
/// Reconnects use capped exponential backoff under the original watch deadline
/// and credential lifetime. Defaults apply only when passed to a recovery API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedCatalogWatchRecoveryPolicy {
    maximum_reconnects: usize,
    initial_backoff: Duration,
    maximum_backoff: Duration,
}

impl Default for ManagedCatalogWatchRecoveryPolicy {
    fn default() -> Self {
        Self {
            maximum_reconnects: 3,
            initial_backoff: Duration::from_millis(250),
            maximum_backoff: Duration::from_secs(5),
        }
    }
}

impl ManagedCatalogWatchRecoveryPolicy {
    /// At most 64 replacement listens, with nonzero backoff capped at 60 seconds.
    /// The reconnect count never resets after a successful replacement snapshot.
    /// Use the ordinary watch API when no reconnect is desired.
    pub fn new(
        maximum_reconnects: usize,
        initial_backoff: Duration,
        maximum_backoff: Duration,
    ) -> Result<Self, ManagedCatalogWatchError> {
        if !(1..=64).contains(&maximum_reconnects)
            || initial_backoff.is_zero()
            || initial_backoff > maximum_backoff
            || maximum_backoff > Duration::from_secs(60)
        {
            return Err(ManagedCatalogWatchError::InvalidRecoveryPolicy);
        }
        Ok(Self {
            maximum_reconnects,
            initial_backoff,
            maximum_backoff,
        })
    }

    fn delay(self, reconnect: usize) -> Duration {
        let mut delay = self.initial_backoff;
        for _ in 1..reconnect.min(self.maximum_reconnects) {
            delay = delay.saturating_mul(2).min(self.maximum_backoff);
        }
        delay
    }
}

/// Recovery observations keep the ordinary watch event vocabulary intact.
pub enum ManagedCatalogWatchRecoveryEvent {
    Watch(ManagedCatalogWatchEvent),
    /// The previous listen and any pending page response have been dropped and
    /// this catalog's cache invalidated. Retire previously published snapshots.
    /// Continuing permits the numbered replacement attempt after backoff. Its
    /// fresh ACK precedes a cursorless full collection, not missed-event replay.
    Gap {
        reconnect_attempt: usize,
    },
}

/// Changes are delivered after invalidation and before any replacement snapshot.
/// Snapshot pages retain their exact typed payloads; no merged TTL is invented.
pub enum ManagedCatalogWatchEvent {
    Acknowledged { accepted_filter: SubscriptionFilter },
    Notification(Box<ServerNotification>),
    Snapshot(CollectedCatalog),
}

/// The callback controls this watch only, never the shared login or remote work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedCatalogWatchControl {
    Continue,
    Stop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedCatalogWatchOutcome {
    StoppedByHost,
    /// The peer sent a valid subscription terminal. A new watch must acquire a
    /// new acknowledgment and fetch again; this outcome is not gap recovery.
    SubscriptionEnded,
}

/// Diagnostics retain no request IDs, filters, credentials or catalog payloads.
#[derive(Debug)]
pub enum ManagedCatalogWatchError {
    InvalidLimits,
    InvalidRecoveryPolicy,
    CursorNotAllowed,
    CoverageRefused,
    CollectionLimit,
    ReconnectLimit,
    UnexpectedEvent,
    Catalog(ManagedCatalogError),
    Subscription(ManagedSubscriptionError),
}

impl fmt::Display for ManagedCatalogWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid catalog watch limits"),
            Self::InvalidRecoveryPolicy => f.write_str("invalid catalog watch recovery policy"),
            Self::CursorNotAllowed => f.write_str("catalog watch must start at the first page"),
            Self::CoverageRefused => {
                f.write_str("subscription did not accept the catalog change filter")
            }
            Self::CollectionLimit => f.write_str("catalog watch reconciliation limit exceeded"),
            Self::ReconnectLimit => f.write_str("catalog watch reconnect limit exceeded"),
            Self::UnexpectedEvent => f.write_str("unexpected catalog subscription event"),
            Self::Catalog(error) => fmt::Display::fmt(error, f),
            Self::Subscription(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ManagedCatalogWatchError {}
impl From<ManagedCatalogError> for ManagedCatalogWatchError {
    fn from(error: ManagedCatalogError) -> Self {
        Self::Catalog(error)
    }
}
impl From<ManagedCoreError> for ManagedCatalogWatchError {
    fn from(error: ManagedCoreError) -> Self {
        Self::Catalog(error.into())
    }
}
impl From<ManagedSubscriptionError> for ManagedCatalogWatchError {
    fn from(error: ManagedSubscriptionError) -> Self {
        Self::Subscription(error)
    }
}

impl ManagedCatalogClient {
    /// Watches one complete core catalog with subscription-driven reconciliation.
    ///
    /// The first page is fetched only after the peer acknowledges the relevant
    /// change category. Changes arriving while pages are fetched cancel that
    /// traversal and schedule a fresh one from the first page. Requests preserve
    /// the list's metadata and filters. A single ID history spans listen plus
    /// every traversal, including numerically equivalent ID representations.
    /// Listen and page POSTs use the same opening credential; a sibling's
    /// renewal never rebinds the watch or extends that credential's expiry.
    ///
    /// The callback is synchronous and must cooperate. It runs without the
    /// cache lock and may inspect/clear the shared cache. Stop, failure, deadline,
    /// cancellation and Drop invalidate this catalog's cache generation. Other
    /// catalogs are not cleared. No snapshot survives a stream gap by assertion.
    pub async fn watch<I, O>(
        &self,
        cx: &Cx,
        request: CoreRequest,
        limits: ManagedCatalogWatchLimits,
        next_id: I,
        observe: O,
    ) -> Result<ManagedCatalogWatchOutcome, ManagedCatalogWatchError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        O: FnMut(
            ManagedCatalogWatchEvent,
        ) -> Result<ManagedCatalogWatchControl, ManagedCatalogError>,
    {
        Box::pin(self.watch_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            request,
            limits,
            next_id,
            observe,
        ))
        .await
    }

    /// Cancellation spans listen admission, acknowledgment, page reads, and idle
    /// waits between changes. Dropping this consuming future releases both live
    /// responses. Local invalidation cancels only the obsolete traversal, never
    /// the caller's context, subscription, shared session, or another collector.
    #[allow(clippy::too_many_arguments)]
    pub async fn watch_with_cancellation<I, O>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        limits: ManagedCatalogWatchLimits,
        next_id: I,
        observe: O,
    ) -> Result<ManagedCatalogWatchOutcome, ManagedCatalogWatchError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        O: FnMut(
            ManagedCatalogWatchEvent,
        ) -> Result<ManagedCatalogWatchControl, ManagedCatalogError>,
    {
        let deadline = call_deadline(cx, cancellation, limits.timeout)?;
        let ids = Mutex::new(WatchIds {
            next: next_id,
            history: Traversal::default(),
            limits,
        });
        let observer = Observer {
            callback: Mutex::new(observe),
            stopped: AtomicBool::new(false),
        };
        let collections = AtomicUsize::new(0);
        let records = AtomicUsize::new(0);
        let acknowledged = AtomicBool::new(false);
        Box::pin(self.watch_attempt(
            cx,
            cancellation,
            request,
            limits,
            &ids,
            &observer,
            WatchLifetime {
                deadline,
                binding: None,
                collections: &collections,
                records: &records,
                acknowledged: &acknowledged,
            },
        ))
        .await
    }

    /// Watches a complete catalog with explicit, bounded stream-gap recovery.
    ///
    /// A gap retires the old subscription, in-flight traversal and cached pages.
    /// The host receives Gap before backoff and can stop there. A replacement
    /// uses a fresh ID, must acknowledge coverage again, and collects from the
    /// first page. Listen/page IDs, collection attempts, subscription records,
    /// the original deadline and original credential span the whole operation.
    /// Concurrent renewal never substitutes a different grant or extends expiry.
    ///
    /// Only the subscription's interrupted HTTP body or missing terminal is
    /// recoverable after ACK. Native body-read failures can include HTTP framing
    /// failures; malformed MCP/SSE records remain terminal. Failed catalog calls
    /// are never retried as gaps. No mutation or previous request is replayed.
    /// Observed-gap recovery cannot supply server-side snapshot isolation or
    /// guarantee delivery of every change while a connection was absent.
    #[allow(clippy::too_many_arguments)]
    pub async fn watch_recovering<I, O>(
        &self,
        cx: &Cx,
        request: CoreRequest,
        limits: ManagedCatalogWatchLimits,
        recovery: ManagedCatalogWatchRecoveryPolicy,
        next_id: I,
        observe: O,
    ) -> Result<ManagedCatalogWatchOutcome, ManagedCatalogWatchError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        O: FnMut(
            ManagedCatalogWatchRecoveryEvent,
        ) -> Result<ManagedCatalogWatchControl, ManagedCatalogError>,
    {
        Box::pin(self.watch_recovering_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            request,
            limits,
            recovery,
            next_id,
            observe,
        ))
        .await
    }

    /// The caller owns the reconnect loop, including cancellable backoff. Drop,
    /// stop, session closure, token revocation/expiry or the original deadline
    /// release its responses without background tasks or a new token lookup.
    #[allow(clippy::too_many_arguments)]
    pub async fn watch_recovering_with_cancellation<I, O>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        limits: ManagedCatalogWatchLimits,
        recovery: ManagedCatalogWatchRecoveryPolicy,
        next_id: I,
        observe: O,
    ) -> Result<ManagedCatalogWatchOutcome, ManagedCatalogWatchError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        O: FnMut(
            ManagedCatalogWatchRecoveryEvent,
        ) -> Result<ManagedCatalogWatchControl, ManagedCatalogError>,
    {
        let deadline = call_deadline(cx, cancellation, limits.timeout)?;
        let kind = CatalogKind::of(&request)?;
        let listen = listen_request(&request)?;
        let _ = prepare(
            self.session.resource().as_str(),
            request.clone(),
            RequestId::Number(0),
            self.limits.core,
        )?;
        admit_listen_size(
            &listen,
            &RequestId::Number(0),
            self.limits.core.request_bytes.min(64 * 1024),
        )?;
        let ids = Mutex::new(WatchIds {
            next: next_id,
            history: Traversal::default(),
            limits,
        });
        let observer = Observer {
            callback: Mutex::new(observe),
            stopped: AtomicBool::new(false),
        };
        let relay = Observer {
            callback: Mutex::new(|event: ManagedCatalogWatchEvent| {
                observer
                    .emit(ManagedCatalogWatchRecoveryEvent::Watch(event))
                    .map(control)
            }),
            stopped: AtomicBool::new(false),
        };
        let collections = AtomicUsize::new(0);
        let records = AtomicUsize::new(0);
        let _gap = InvalidateOnExit { client: self, kind };
        self.cache()?.invalidate_result_set(&kind.result_set());
        Box::pin(bounded_wait(cx, cancellation, deadline, async {
            Ok(async {
                let binding = self
                    .session
                    .credential_with_cancellation(cx, cancellation)
                    .await
                    .map_err(ManagedCoreError::from)?;
                let mut reconnects = 0;
                loop {
                    check_binding(cx, cancellation, deadline, &binding)?;
                    let acknowledged = AtomicBool::new(false);
                    let result = Box::pin(self.watch_attempt(
                        cx,
                        cancellation,
                        request.clone(),
                        limits,
                        &ids,
                        &relay,
                        WatchLifetime {
                            deadline,
                            binding: Some(&binding),
                            collections: &collections,
                            records: &records,
                            acknowledged: &acknowledged,
                        },
                    ))
                    .await;
                    check_binding(cx, cancellation, deadline, &binding)?;
                    match result {
                        Ok(outcome) => return Ok(outcome),
                        Err(error)
                            if acknowledged.load(Ordering::Acquire)
                                && is_subscription_gap(&error) => {}
                        Err(error) => return Err(error),
                    }
                    if reconnects >= recovery.maximum_reconnects {
                        return Err(ManagedCatalogWatchError::ReconnectLimit);
                    }
                    reconnects += 1;
                    let continuing = observer.emit(ManagedCatalogWatchRecoveryEvent::Gap {
                        reconnect_attempt: reconnects,
                    })?;
                    check_binding(cx, cancellation, deadline, &binding)?;
                    if !continuing {
                        return Ok(ManagedCatalogWatchOutcome::StoppedByHost);
                    }
                    self.session
                        .wait_subscription_backoff(
                            cx,
                            cancellation,
                            &binding,
                            deadline,
                            recovery.delay(reconnects),
                        )
                        .await
                        .map_err(ManagedCoreError::from)?;
                }
            }
            .await)
        }))
        .await?
    }

    #[allow(clippy::too_many_arguments)]
    async fn watch_attempt<I, O>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        limits: ManagedCatalogWatchLimits,
        ids: &Mutex<WatchIds<I>>,
        observer: &Observer<O>,
        lifetime: WatchLifetime<'_>,
    ) -> Result<ManagedCatalogWatchOutcome, ManagedCatalogWatchError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        O: FnMut(
            ManagedCatalogWatchEvent,
        ) -> Result<ManagedCatalogWatchControl, ManagedCatalogError>,
    {
        let deadline = lifetime.deadline;
        check_call(cx, cancellation, deadline)?;
        let kind = CatalogKind::of(&request)?;
        let listen = listen_request(&request)?;
        let _ = prepare(
            self.session.resource().as_str(),
            request.clone(),
            RequestId::Number(0),
            self.limits.core,
        )?;
        let request_bytes = self.limits.core.request_bytes.min(64 * 1024);
        let subscription_limits = ManagedSubscriptionLimits::new(
            request_bytes,
            self.limits.core.frame_bytes.min(64 * 1024),
            limits.subscription_records,
            limits.timeout,
        )?;
        admit_listen_size(&listen, &RequestId::Number(0), request_bytes)?;
        if lifetime.records.load(Ordering::Acquire) >= limits.subscription_records {
            return Err(ManagedSubscriptionError::RecordLimit.into());
        }
        let listen_id = issue_id(ids, cx, cancellation, deadline)?;
        admit_listen_size(&listen, &listen_id, request_bytes)?;
        // Install cleanup before any I/O. It also fences fills from a sibling
        // traversal when this watch is abandoned during acknowledgment/read.
        let _gap = InvalidateOnExit { client: self, kind };
        self.cache()?.invalidate_result_set(&kind.result_set());
        Box::pin(bounded_wait(cx, cancellation, deadline, async {
            Ok(async {
                let acquired_binding;
                let binding = if let Some(binding) = lifetime.binding {
                    binding
                } else {
                    acquired_binding = self
                        .session
                        .credential_with_cancellation(cx, cancellation)
                        .await
                        .map_err(ManagedCoreError::from)?;
                    &acquired_binding
                };
                check_binding(cx, cancellation, deadline, binding)?;
                let mut subscription = Box::pin(self.session.subscribe_core_with_snapshot(
                    cx,
                    cancellation,
                    binding,
                    listen,
                    listen_id,
                    subscription_limits,
                    deadline,
                ))
                .await?;
                if subscription.credential_generation() != binding.generation() {
                    return Err(ManagedCatalogError::CredentialChanged.into());
                }
                let Some(ManagedSubscriptionEvent::Acknowledged { accepted_filter }) =
                    subscription_event(
                        cx,
                        &mut subscription,
                        lifetime.records,
                        limits.subscription_records,
                    )
                    .await?
                else {
                    return Err(ManagedCatalogWatchError::UnexpectedEvent);
                };
                if !covers(kind, &accepted_filter) {
                    return Err(ManagedCatalogWatchError::CoverageRefused);
                }
                check_binding(cx, cancellation, deadline, binding)?;
                // An old cache cannot bridge the pre-acknowledgment blind window.
                self.cache()?.invalidate_result_set(&kind.result_set());
                lifetime.acknowledged.store(true, Ordering::Release);
                let continuing =
                    observer.emit(ManagedCatalogWatchEvent::Acknowledged { accepted_filter })?;
                check_binding(cx, cancellation, deadline, binding)?;
                if !continuing {
                    return Ok(ManagedCatalogWatchOutcome::StoppedByHost);
                }
                let signal = ChangeSignal::default();
                let monitor = async {
                    loop {
                        check_binding(cx, cancellation, deadline, binding)?;
                        let event = subscription_event(
                            cx,
                            &mut subscription,
                            lifetime.records,
                            limits.subscription_records,
                        )
                        .await?;
                        check_binding(cx, cancellation, deadline, binding)?;
                        match event {
                            Some(ManagedSubscriptionEvent::Notification(notification)) => {
                                self.invalidate_notification(&notification)?;
                                if relevant(kind, &notification) {
                                    signal.changed()?;
                                }
                                let continuing = observer
                                    .emit(ManagedCatalogWatchEvent::Notification(notification))?;
                                check_binding(cx, cancellation, deadline, binding)?;
                                if !continuing {
                                    return Ok(ManagedCatalogWatchOutcome::StoppedByHost);
                                }
                            }
                            Some(
                                ManagedSubscriptionEvent::Terminal { .. }
                                | ManagedSubscriptionEvent::Cancelled { .. },
                            ) => {
                                return Ok(ManagedCatalogWatchOutcome::SubscriptionEnded);
                            }
                            _ => return Err(ManagedCatalogWatchError::UnexpectedEvent),
                        }
                    }
                };
                let reconcile = async {
                    let mut last_published = None;
                    loop {
                        let revision = signal.wait_after(last_published).await?;
                        check_binding(cx, cancellation, deadline, binding)?;
                        if lifetime.collections.load(Ordering::Acquire)
                            >= limits.maximum_collections
                        {
                            return Err(ManagedCatalogWatchError::CollectionLimit);
                        }
                        let Some(local_cancel) = signal.begin(revision)? else {
                            continue;
                        };
                        lifetime.collections.fetch_add(1, Ordering::AcqRel);
                        let result = Box::pin(self.collect_with_binding(
                            cx,
                            &local_cancel,
                            request.clone(),
                            || {
                                check_binding(cx, cancellation, deadline, binding)?;
                                let id = issue_id(ids, cx, cancellation, deadline)?;
                                check_binding(cx, cancellation, deadline, binding)?;
                                Ok(id)
                            },
                            |notification| {
                                // collect has already invalidated before calling
                                // this observer. Coalesce scheduling, not delivery.
                                if relevant(kind, &notification) {
                                    signal.changed()?;
                                }
                                check_binding(cx, cancellation, deadline, binding)?;
                                let continuing = observer
                                    .emit(ManagedCatalogWatchEvent::Notification(notification))?;
                                check_binding(cx, cancellation, deadline, binding)?;
                                if continuing {
                                    Ok(())
                                } else {
                                    Err(ManagedCatalogError::AbortedByHost)
                                }
                            },
                            Some(binding),
                            deadline,
                        ))
                        .await;
                        signal.finish()?;
                        check_binding(cx, cancellation, deadline, binding)?;
                        if observer.stopped.load(Ordering::Acquire) {
                            return Ok(ManagedCatalogWatchOutcome::StoppedByHost);
                        }
                        let changed = signal.revision()? != revision;
                        let catalog = match result {
                            Ok(catalog) => catalog,
                            Err(error)
                                if changed && is_invalidation_stop(&error, &local_cancel) =>
                            {
                                // Retry only a locally superseded read traversal.
                                // No failed mutation or arbitrary I/O is replayed.
                                yield_once().await;
                                continue;
                            }
                            Err(error) => return Err(error.into()),
                        };
                        if catalog.credential_generation() != binding.generation() {
                            return Err(ManagedCatalogError::CredentialChanged.into());
                        }
                        // The collector may deliberately rebuild its cache
                        // generation under the selected whole-catalog policy.
                        // Retain its admitted generation, rather than assuming
                        // the generation from before collection must survive.
                        // Another clone's clear after admission still fences
                        // publication, even if it happens before this yield.
                        let cache_generation = catalog.cache_generation;
                        // Let the monitor drain currently ready notifications
                        // before publishing a candidate. Crucially, its pending
                        // read is never dropped just because a list completed.
                        yield_once().await;
                        check_binding(cx, cancellation, deadline, binding)?;
                        if signal.revision()? != revision {
                            continue;
                        }
                        // An external clear during the publication yield is
                        // terminal, not a reason to override host policy by retry.
                        self.require_generation(&kind.result_set(), cache_generation)?;
                        last_published = Some(revision);
                        let continuing =
                            observer.emit(ManagedCatalogWatchEvent::Snapshot(catalog))?;
                        check_binding(cx, cancellation, deadline, binding)?;
                        if !continuing {
                            return Ok(ManagedCatalogWatchOutcome::StoppedByHost);
                        }
                    }
                };
                // Monitor-first polling makes an already-ready gap/notification
                // win over a ready snapshot. Both losing futures remain owned
                // until the WHOLE watch finishes, not merely until a page wins.
                // Box the independently large HTTP state machines rather than
                // multiplying their stack footprint inside the caller's future.
                let mut monitor = Box::pin(monitor);
                let mut reconcile = Box::pin(reconcile);
                poll_fn(|task| {
                    check_binding(cx, cancellation, deadline, binding)?;
                    if let Poll::Ready(result) = monitor.as_mut().poll(task) {
                        return Poll::Ready(result);
                    }
                    reconcile.as_mut().poll(task)
                })
                .await
            }
            .await)
        }))
        .await?
    }
}

struct WatchLifetime<'a> {
    deadline: Time,
    binding: Option<&'a OAuthCredentialSnapshot>,
    collections: &'a AtomicUsize,
    records: &'a AtomicUsize,
    acknowledged: &'a AtomicBool,
}

fn control(continuing: bool) -> ManagedCatalogWatchControl {
    if continuing {
        ManagedCatalogWatchControl::Continue
    } else {
        ManagedCatalogWatchControl::Stop
    }
}

// Only subscription-side failures can authorize reconnect. In particular, an
// identical transport error inside Catalog never retries a list POST.
fn is_subscription_gap(error: &ManagedCatalogWatchError) -> bool {
    matches!(
        error,
        ManagedCatalogWatchError::Subscription(
            ManagedSubscriptionError::MissingTerminal
                | ManagedSubscriptionError::Session(OAuthSessionError::Http(
                    ModernHttpExecutorError::ResponseBodyReadFailed
                ))
        )
    )
}

async fn subscription_event(
    cx: &Cx,
    subscription: &mut ManagedSubscription,
    records: &AtomicUsize,
    maximum: usize,
) -> Result<Option<ManagedSubscriptionEvent>, ManagedSubscriptionError> {
    if records.load(Ordering::Acquire) >= maximum {
        return Err(ManagedSubscriptionError::RecordLimit);
    }
    let event = subscription.next_event(cx).await?;
    if event.is_some() {
        records.fetch_add(1, Ordering::AcqRel);
    }
    Ok(event)
}

fn listen_request(request: &CoreRequest) -> Result<CoreRequest, ManagedCatalogWatchError> {
    let kind = CatalogKind::of(request)?;
    if list_params(request)?.cursor.is_some() {
        return Err(ManagedCatalogWatchError::CursorNotAllowed);
    }
    let params = request
        .encode_params()
        .map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    CoreRequest::decode(
        ProtocolEra::Modern2026,
        "subscriptions/listen",
        Some(&serde_json::json!({
            "_meta": params["_meta"], "notifications": requested_filter(kind),
        })),
    )
    .map_err(|_| ManagedCoreError::InvalidRequest.into())
}

fn requested_filter(kind: CatalogKind) -> SubscriptionFilter {
    let mut filter = SubscriptionFilter::default();
    match kind {
        CatalogKind::Tools => filter.tools_list_changed = Some(true),
        CatalogKind::Resources | CatalogKind::Templates => {
            filter.resources_list_changed = Some(true);
        }
        CatalogKind::Prompts => filter.prompts_list_changed = Some(true),
    }
    filter
}

fn covers(kind: CatalogKind, filter: &SubscriptionFilter) -> bool {
    match kind {
        CatalogKind::Tools => filter.tools_list_changed == Some(true),
        CatalogKind::Resources | CatalogKind::Templates => {
            filter.resources_list_changed == Some(true)
        }
        CatalogKind::Prompts => filter.prompts_list_changed == Some(true),
    }
}

fn relevant(kind: CatalogKind, notification: &ServerNotification) -> bool {
    matches!(
        (kind, notification),
        (CatalogKind::Tools, ServerNotification::ToolsListChanged(_))
            | (
                CatalogKind::Resources | CatalogKind::Templates,
                ServerNotification::ResourcesListChanged(_)
            )
            | (
                CatalogKind::Prompts,
                ServerNotification::PromptsListChanged(_)
            )
    )
}

fn admit_listen_size(
    request: &CoreRequest,
    id: &RequestId,
    maximum: usize,
) -> Result<(), ManagedCoreError> {
    let params = request
        .encode_params()
        .map_err(|_| ManagedCoreError::InvalidRequest)?;
    let envelope =
        serde_json::json!({"jsonrpc":"2.0","id":id,"method":request.method(),"params":params});
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut writer, &envelope).map_err(|_| ManagedCoreError::RequestTooLarge)
}

fn check_binding(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    deadline: Time,
    binding: &OAuthCredentialSnapshot,
) -> Result<(), ManagedCatalogError> {
    check_call(
        cx,
        cancellation,
        cx.budget()
            .deadline
            .map_or(deadline, |parent| parent.min(deadline)),
    )?;
    require_unrevoked(binding.credential())?;
    if Instant::now() >= binding.expires_at() {
        return Err(ManagedCoreError::Session(OAuthSessionError::LoginRequired).into());
    }
    Ok(())
}

struct WatchIds<I> {
    next: I,
    history: Traversal,
    limits: ManagedCatalogWatchLimits,
}
fn issue_id<I>(
    ids: &Mutex<WatchIds<I>>,
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    deadline: Time,
) -> Result<RequestId, ManagedCatalogError>
where
    I: FnMut() -> Result<RequestId, ManagedCatalogError>,
{
    check_call(cx, cancellation, deadline)?;
    let mut ids = ids
        .lock()
        .map_err(|_| ManagedCatalogError::CacheUnavailable)?;
    if ids.history.ids.len() >= ids.limits.maximum_request_ids {
        return Err(ManagedCatalogError::StateLimit);
    }
    let id = (ids.next)()?;
    check_call(cx, cancellation, deadline)?;
    let maximum = ids.limits.maximum_state_bytes;
    ids.history.reserve_id(&id, maximum)?;
    Ok(id)
}

struct Observer<O> {
    callback: Mutex<O>,
    stopped: AtomicBool,
}
impl<O> Observer<O> {
    fn emit<E>(&self, event: E) -> Result<bool, ManagedCatalogError>
    where
        O: FnMut(E) -> Result<ManagedCatalogWatchControl, ManagedCatalogError>,
    {
        let control = (self
            .callback
            .lock()
            .map_err(|_| ManagedCatalogError::CacheUnavailable)?)(event)?;
        let continuing = control == ManagedCatalogWatchControl::Continue;
        if !continuing {
            self.stopped.store(true, Ordering::Release);
        }
        Ok(continuing)
    }
}

#[derive(Default)]
struct ChangeState {
    revision: u64,
    active: Option<McpRequestCancellation>,
    waiter: Option<Waker>,
}
#[derive(Default)]
struct ChangeSignal(Mutex<ChangeState>);
impl ChangeSignal {
    fn revision(&self) -> Result<u64, ManagedCatalogError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| ManagedCatalogError::CacheUnavailable)?
            .revision)
    }
    fn changed(&self) -> Result<(), ManagedCatalogError> {
        let (active, waiter) = {
            let mut state = self
                .0
                .lock()
                .map_err(|_| ManagedCatalogError::CacheUnavailable)?;
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or(ManagedCatalogError::StateLimit)?;
            (state.active.take(), state.waiter.take())
        };
        if let Some(active) = active {
            active.cancel();
        }
        if let Some(waiter) = waiter {
            waiter.wake();
        }
        Ok(())
    }
    fn begin(&self, revision: u64) -> Result<Option<McpRequestCancellation>, ManagedCatalogError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| ManagedCatalogError::CacheUnavailable)?;
        if state.revision != revision {
            return Ok(None);
        }
        let cancellation = McpRequestCancellation::new();
        state.active = Some(cancellation.clone());
        Ok(Some(cancellation))
    }
    fn finish(&self) -> Result<(), ManagedCatalogError> {
        self.0
            .lock()
            .map_err(|_| ManagedCatalogError::CacheUnavailable)?
            .active = None;
        Ok(())
    }
    async fn wait_after(&self, previous: Option<u64>) -> Result<u64, ManagedCatalogError> {
        poll_fn(|task| {
            let mut state = self
                .0
                .lock()
                .map_err(|_| ManagedCatalogError::CacheUnavailable)?;
            if previous != Some(state.revision) {
                return Poll::Ready(Ok(state.revision));
            }
            state.waiter = Some(task.waker().clone());
            Poll::Pending
        })
        .await
    }
}

fn is_invalidation_stop(
    error: &ManagedCatalogError,
    local_cancel: &McpRequestCancellation,
) -> bool {
    matches!(error, ManagedCatalogError::Invalidated)
        || (local_cancel.is_cancel_requested()
            && matches!(
                error,
                ManagedCatalogError::Core(
                    ManagedCoreError::Cancelled
                        | ManagedCoreError::Session(OAuthSessionError::Cancelled)
                )
            ))
}

async fn yield_once() {
    let mut yielded = false;
    poll_fn(|task| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            task.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

struct InvalidateOnExit<'a> {
    client: &'a ManagedCatalogClient,
    kind: CatalogKind,
}
impl Drop for InvalidateOnExit<'_> {
    fn drop(&mut self) {
        // A poisoned cache already fails closed on all reads. Drop never
        // recovers it permissively or panics while unwinding a host callback.
        if let Ok(mut cache) = self.client.cache() {
            cache.invalidate_result_set(&self.kind.result_set());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, JsonRpcRequest};
    use serde_json::json;

    fn list(method: &str) -> CoreRequest {
        CoreRequest::decode(
            ProtocolEra::Modern2026,
            method,
            Some(&json!({
                "_meta": FinalRequestMeta::new(ClientCapabilities::default()),
                "includeTags":["selected"], "excludeTags":[],
            })),
        )
        .unwrap()
    }

    #[test]
    fn recovery_policy_is_finite_and_backoff_saturates_at_its_cap() {
        for (attempts, initial, maximum) in [
            (0, Duration::from_millis(1), Duration::from_secs(1)),
            (65, Duration::from_millis(1), Duration::from_secs(1)),
            (1, Duration::ZERO, Duration::from_secs(1)),
            (1, Duration::from_secs(2), Duration::from_secs(1)),
            (1, Duration::from_secs(1), Duration::from_secs(61)),
        ] {
            assert!(matches!(
                ManagedCatalogWatchRecoveryPolicy::new(attempts, initial, maximum),
                Err(ManagedCatalogWatchError::InvalidRecoveryPolicy)
            ));
        }
        let policy = ManagedCatalogWatchRecoveryPolicy::new(
            64,
            Duration::from_millis(1),
            Duration::from_millis(3),
        )
        .unwrap();
        assert_eq!(policy.delay(1), Duration::from_millis(1));
        assert_eq!(policy.delay(2), Duration::from_millis(2));
        assert_eq!(policy.delay(3), Duration::from_millis(3));
        assert_eq!(policy.delay(usize::MAX), Duration::from_millis(3));
    }

    #[test]
    fn only_subscription_interruption_is_a_recovery_candidate() {
        assert!(is_subscription_gap(
            &ManagedCatalogWatchError::Subscription(ManagedSubscriptionError::MissingTerminal)
        ));
        assert!(is_subscription_gap(
            &ManagedCatalogWatchError::Subscription(ManagedSubscriptionError::Session(
                OAuthSessionError::Http(ModernHttpExecutorError::ResponseBodyReadFailed)
            ))
        ));
        assert!(!is_subscription_gap(&ManagedCatalogWatchError::Catalog(
            ManagedCoreError::Session(OAuthSessionError::Http(
                ModernHttpExecutorError::ResponseBodyReadFailed,
            ))
            .into(),
        )));
        for error in [
            ManagedSubscriptionError::InvalidResponse,
            ManagedSubscriptionError::RecordLimit,
            ManagedSubscriptionError::Session(OAuthSessionError::LoginRequired),
            ManagedSubscriptionError::Session(OAuthSessionError::Cancelled),
            ManagedSubscriptionError::Session(OAuthSessionError::AuthorizationRejected {
                status: 401,
            }),
        ] {
            assert!(!is_subscription_gap(
                &ManagedCatalogWatchError::Subscription(error)
            ));
        }
    }

    #[test]
    fn all_catalogs_subscribe_to_their_own_change_category_and_preserve_metadata() {
        for (method, key) in [
            ("tools/list", "toolsListChanged"),
            ("resources/list", "resourcesListChanged"),
            ("resources/templates/list", "resourcesListChanged"),
            ("prompts/list", "promptsListChanged"),
        ] {
            let request = list(method);
            let listen = listen_request(&request).unwrap();
            let params = listen.encode_params().unwrap().unwrap();
            assert_eq!(listen.method(), "subscriptions/listen");
            assert_eq!(
                params["_meta"],
                request.encode_params().unwrap().unwrap()["_meta"]
            );
            assert_eq!(params["notifications"], json!({key:true}));
            assert!(params.get("cursor").is_none());
            assert!(params.get("includeTags").is_none());
            let kind = CatalogKind::of(&request).unwrap();
            assert!(covers(kind, &requested_filter(kind)));
            assert!(!covers(kind, &SubscriptionFilter::default()));
        }
    }

    #[test]
    fn a_suffix_is_not_silently_presented_as_a_complete_watched_catalog() {
        for cursor in ["", "opaque"] {
            let mut request = list("tools/list");
            super::super::list_params_mut(&mut request).unwrap().cursor = Some(cursor.to_owned());
            assert!(matches!(
                listen_request(&request),
                Err(ManagedCatalogWatchError::CursorNotAllowed)
            ));
        }
    }

    #[test]
    fn only_the_matching_change_schedules_catalog_reconciliation() {
        let tools = ServerNotification::decode(&JsonRpcRequest::notification(
            "notifications/tools/list_changed",
            None,
        ))
        .unwrap();
        let resources = ServerNotification::decode(&JsonRpcRequest::notification(
            "notifications/resources/list_changed",
            None,
        ))
        .unwrap();
        assert!(relevant(CatalogKind::Tools, &tools));
        assert!(!relevant(CatalogKind::Prompts, &tools));
        assert!(relevant(CatalogKind::Templates, &resources));
        assert!(!relevant(CatalogKind::Tools, &resources));
    }

    #[test]
    fn invalidation_cancels_only_the_obsolete_traversal_and_coalesces_pending_changes() {
        let signal = ChangeSignal::default();
        let first = signal.begin(0).unwrap().unwrap();
        let sibling = McpRequestCancellation::new();
        signal.changed().unwrap();
        signal.changed().unwrap();
        assert!(first.is_cancel_requested());
        assert!(!sibling.is_cancel_requested());
        assert_eq!(signal.revision().unwrap(), 2);
        assert!(signal.begin(0).unwrap().is_none());
        let replacement = signal.begin(2).unwrap().unwrap();
        assert!(!replacement.is_cancel_requested());
        signal.finish().unwrap();
        signal.changed().unwrap();
        assert!(!replacement.is_cancel_requested());
    }

    #[test]
    fn pending_change_wait_is_woken_without_a_polling_timer() {
        use std::sync::Arc;
        use std::task::Wake;
        struct Flag(AtomicBool);
        impl Wake for Flag {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Release);
            }
        }
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(flag.clone());
        let mut task = std::task::Context::from_waker(&waker);
        let signal = ChangeSignal::default();
        let mut wait = Box::pin(signal.wait_after(Some(0)));
        assert!(wait.as_mut().poll(&mut task).is_pending());
        signal.changed().unwrap();
        assert!(flag.0.load(Ordering::Acquire));
        assert!(matches!(wait.as_mut().poll(&mut task), Poll::Ready(Ok(1))));
    }

    #[test]
    fn unrelated_errors_cannot_be_laundered_into_invalidation_retries() {
        let cancelled = McpRequestCancellation::new();
        assert!(!is_invalidation_stop(
            &ManagedCoreError::Cancelled.into(),
            &cancelled
        ));
        cancelled.cancel();
        assert!(is_invalidation_stop(
            &ManagedCoreError::Cancelled.into(),
            &cancelled
        ));
        for error in [
            ManagedCatalogError::InvalidPage,
            ManagedCatalogError::AbortedByHost,
            ManagedCoreError::InvalidResponse.into(),
            ManagedCoreError::HttpStatus { status: 500 }.into(),
        ] {
            assert!(!is_invalidation_stop(&error, &cancelled));
        }
    }

    #[test]
    fn watch_budget_and_listen_bytes_have_real_boundaries() {
        let defaults = ManagedCatalogWatchLimits::default();
        assert!(ManagedCatalogWatchLimits::new(Duration::ZERO, 1, 2, 1, 2).is_err());
        assert!(ManagedCatalogWatchLimits::new(defaults.timeout, 0, 2, 1, 2).is_err());
        assert!(ManagedCatalogWatchLimits::new(defaults.timeout, 1, 1, 1, 2).is_err());
        assert!(ManagedCatalogWatchLimits::new(defaults.timeout, 1, 2, 0, 2).is_err());
        let request = listen_request(&list("tools/list")).unwrap();
        assert!(admit_listen_size(&request, &RequestId::Number(1), 4096).is_ok());
        assert!(matches!(
            admit_listen_size(&request, &RequestId::Number(1), 1),
            Err(ManagedCoreError::RequestTooLarge)
        ));
    }
}
