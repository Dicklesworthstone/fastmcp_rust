//! Subscribe-before-read reconciliation for one exact resource URI.
//!
//! The change stream and read remain owned by the caller's future. A change
//! invalidates before delivery, interrupts an obsolete read and permits a
//! bounded reread. Arbitrary I/O errors never permit replay. No worker, runtime,
//! reconnect loop or missed-event history is created. Input-required is surfaced
//! to the host and stops automatic reading; answers are never synthesized.

use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::{Mutex, atomic::{AtomicBool, Ordering}};
use std::task::{Poll, Waker};
use std::time::Duration;

use asupersync::{Cx, types::Time};
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreRequest, RequestId, ServerNotification, SubscriptionFilter};
use fastmcp_protocol::protocol_policy::ProtocolEra;

use super::{
    ManagedResourceClient, ManagedResourceError, ManagedResourceRead,
    ManagedCoreError, FinalCacheResultSet, OAuthCredentialSnapshot,
    bounded_wait, call_deadline, check_call, prepare, read_identity, require_credential,
};
use super::super::BoundedWriter;
use crate::http_auth::managed::subscriptions::{
    ManagedSubscriptionError, ManagedSubscriptionEvent, ManagedSubscriptionLimits,
};

/// The finite watch lifetime includes every read and callback. Each read also
/// retains its own core byte/notification/time limits. Together these bounds
/// cap aggregate work; a new read never resets the whole-watch deadline.
#[derive(Clone, Copy, Debug)]
pub struct ManagedResourceWatchLimits {
    timeout: Duration,
    reads: usize,
    id_bytes: usize,
    subscription_records: usize,
}
impl Default for ManagedResourceWatchLimits {
    fn default() -> Self {
        Self { timeout: Duration::from_mins(15), reads: 64, id_bytes: 1024 * 1024, subscription_records: 1024 }
    }
}
impl ManagedResourceWatchLimits {
    pub fn new(timeout: Duration, reads: usize, id_bytes: usize, subscription_records: usize) -> Result<Self, ManagedResourceWatchError> {
        if timeout.is_zero() || timeout > Duration::from_secs(3600)
            || !(1..=1024).contains(&reads) || !(1..=8 * 1024 * 1024).contains(&id_bytes)
            || !(2..=4096).contains(&subscription_records)
        { return Err(ManagedResourceWatchError::InvalidLimits); }
        Ok(Self { timeout, reads, id_bytes, subscription_records })
    }
}

pub enum ManagedResourceWatchEvent {
    Acknowledged { accepted_filter: SubscriptionFilter },
    Notification(Box<ServerNotification>),
    /// A complete result consistent with changes observed by this driver. This
    /// is not a server-atomic snapshot or a promise of ongoing freshness.
    Snapshot(ManagedResourceRead),
    /// The driver ends after delivering this challenge. Continuation belongs
    /// to an explicit host action, never automatic replay of the watched read.
    InputRequired(ManagedResourceRead),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedResourceWatchControl { Continue, Stop }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedResourceWatchOutcome { StoppedByHost, SubscriptionEnded, InputRequired }

#[derive(Debug)]
pub enum ManagedResourceWatchError {
    InvalidLimits,
    ContinuationNotAllowed,
    CoverageRefused,
    ReadLimit,
    UnexpectedEvent,
    Resource(ManagedResourceError),
    Subscription(ManagedSubscriptionError),
}
impl fmt::Display for ManagedResourceWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid resource watch limits"),
            Self::ContinuationNotAllowed => f.write_str("resource watch cannot repeat a continuation request"),
            Self::CoverageRefused => f.write_str("subscription did not cover resource and catalog changes"),
            Self::ReadLimit => f.write_str("resource watch reread limit exceeded"),
            Self::UnexpectedEvent => f.write_str("unexpected resource subscription event"),
            Self::Resource(error) => fmt::Display::fmt(error, f),
            Self::Subscription(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ManagedResourceWatchError {}
impl From<ManagedResourceError> for ManagedResourceWatchError {
    fn from(error: ManagedResourceError) -> Self { Self::Resource(error) }
}
impl From<ManagedCoreError> for ManagedResourceWatchError {
    fn from(error: ManagedCoreError) -> Self { Self::Resource(error.into()) }
}
impl From<ManagedSubscriptionError> for ManagedResourceWatchError {
    fn from(error: ManagedSubscriptionError) -> Self { Self::Subscription(error) }
}

impl ManagedResourceClient {
    /// Opens a finite change stream, requires acknowledgment, then reads and
    /// reconciles the resource. Both its exact URI and resourcesListChanged
    /// must be accepted. Metadata is preserved on both request types.
    ///
    /// Old cache generations are invalidated before listening, at acknowledgment
    /// and on every exit. Because resource generations are fixed-cardinality,
    /// this conservatively clears other reads in this consumer's resource cache.
    /// Already-delivered snapshots remain the host's responsibility after a gap.
    pub async fn watch<I, O>(
        &self, cx: &Cx, request: CoreRequest, limits: ManagedResourceWatchLimits,
        next_id: I, observe: O,
    ) -> Result<ManagedResourceWatchOutcome, ManagedResourceWatchError>
    where
        I: FnMut() -> Result<RequestId, ManagedResourceError>,
        O: FnMut(ManagedResourceWatchEvent) -> Result<ManagedResourceWatchControl, ManagedResourceError>,
    {
        self.watch_with_cancellation(cx, &McpRequestCancellation::new(), request, limits, next_id, observe).await
    }

    /// Cancellation owns the entire watch. A local invalidation interrupts only
    /// its obsolete read; the subscription, login and caller context survive.
    /// The opening token lifetime is never extended by shared-session renewal.
    #[allow(clippy::too_many_arguments)]
    pub async fn watch_with_cancellation<I, O>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, request: CoreRequest,
        limits: ManagedResourceWatchLimits, next_id: I, observe: O,
    ) -> Result<ManagedResourceWatchOutcome, ManagedResourceWatchError>
    where
        I: FnMut() -> Result<RequestId, ManagedResourceError>,
        O: FnMut(ManagedResourceWatchEvent) -> Result<ManagedResourceWatchControl, ManagedResourceError>,
    {
        let deadline = call_deadline(cx, cancellation, limits.timeout)?;
        let (uri, ordinary) = read_identity(&request)?;
        if !ordinary { return Err(ManagedResourceWatchError::ContinuationNotAllowed); }
        let uri = uri.to_owned();
        let _ = prepare(self.session.resource().as_str(), request.clone(), RequestId::Number(0), self.limits.core)?;
        let listen = listen_request(&request)?;
        let request_bytes = self.limits.core.request_bytes.min(64 * 1024);
        let stream_limits = ManagedSubscriptionLimits::new(request_bytes,
            self.limits.core.frame_bytes.min(64 * 1024), limits.subscription_records, limits.timeout)?;
        admit_listen_size(&listen, &RequestId::Number(0), request_bytes)?;
        let ids = Mutex::new(Ids { next: next_id, used: Vec::new(), bytes: 0, limits });
        let observer = Observer { callback: Mutex::new(observe), stopped: AtomicBool::new(false) };
        let set = FinalCacheResultSet::Resource(uri.clone());
        let _gap = InvalidateOnExit { client: self, set: set.clone() };
        self.cache()?.invalidate_result_set(&set);
        Box::pin(bounded_wait(cx, cancellation, deadline, async {
            Ok(async {
                let binding = self.session.credential_with_cancellation(cx, cancellation)
                    .await.map_err(ManagedCoreError::from)?;
                check_binding(cx, cancellation, deadline, &binding)?;
                let listen_id = issue_id(&ids)?;
                check_binding(cx, cancellation, deadline, &binding)?;
                admit_listen_size(&listen, &listen_id, request_bytes)?;
                let mut subscription = self.session.subscribe_core_with_cancellation(
                    cx, cancellation, listen, listen_id, stream_limits,
                ).await?;
                if subscription.credential_generation() != binding.generation() {
                    return Err(ManagedResourceError::CredentialChanged.into());
                }
                let Some(ManagedSubscriptionEvent::Acknowledged { accepted_filter }) = subscription.next_event(cx).await? else {
                    return Err(ManagedResourceWatchError::UnexpectedEvent);
                };
                if !covers(&uri, &accepted_filter) { return Err(ManagedResourceWatchError::CoverageRefused); }
                check_binding(cx, cancellation, deadline, &binding)?;
                self.cache()?.invalidate_result_set(&set);
                let continuing = observer.emit(ManagedResourceWatchEvent::Acknowledged { accepted_filter })?;
                check_binding(cx, cancellation, deadline, &binding)?;
                if !continuing { return Ok(ManagedResourceWatchOutcome::StoppedByHost); }
                let signal = Signal::default();
                let monitor = async {
                    loop {
                        let event = subscription.next_event(cx).await?;
                        check_binding(cx, cancellation, deadline, &binding)?;
                        match event {
                            Some(ManagedSubscriptionEvent::Notification(notification)) => {
                                self.invalidate_notification(&notification)?;
                                if relevant(&notification) { signal.changed()?; }
                                let continuing = observer.emit(ManagedResourceWatchEvent::Notification(notification))?;
                                check_binding(cx, cancellation, deadline, &binding)?;
                                if !continuing { return Ok(ManagedResourceWatchOutcome::StoppedByHost); }
                            }
                            Some(ManagedSubscriptionEvent::Terminal { .. }) => return Ok(ManagedResourceWatchOutcome::SubscriptionEnded),
                            _ => return Err(ManagedResourceWatchError::UnexpectedEvent),
                        }
                    }
                };
                let reads = async {
                    let mut published = None;
                    let mut attempts = 0;
                    loop {
                        let revision = signal.wait_after(published).await?;
                        check_binding(cx, cancellation, deadline, &binding)?;
                        if attempts >= limits.reads { return Err(ManagedResourceWatchError::ReadLimit); }
                        let Some(local) = signal.begin(revision)? else { continue };
                        let generation = self.cache()?.begin_fetch(&set);
                        attempts += 1;
                        let read = Box::pin(self.read_with_cancellation(cx, &local, request.clone(), || {
                            check_binding(cx, cancellation, deadline, &binding)?;
                            let id = issue_id(&ids)?;
                            check_binding(cx, cancellation, deadline, &binding)?;
                            Ok(id)
                        }, |notification| {
                            // The reader already invalidated this before calling
                            // us. Coalesce reread scheduling, never notifications.
                            if relevant(&notification) { signal.changed()?; }
                            let continuing = observer.emit(ManagedResourceWatchEvent::Notification(notification))?;
                            check_binding(cx, cancellation, deadline, &binding)?;
                            if continuing { Ok(()) } else { Err(ManagedResourceError::AbortedByHost) }
                        })).await;
                        signal.finish()?;
                        check_binding(cx, cancellation, deadline, &binding)?;
                        if observer.stopped.load(Ordering::Acquire) { return Ok(ManagedResourceWatchOutcome::StoppedByHost); }
                        let changed = signal.revision()? != revision;
                        let read = match read {
                            Ok(read) => read,
                            Err(error) if changed && locally_superseded(&error, &local) => { yield_once().await; continue; }
                            Err(error) => return Err(error.into()),
                        };
                        if read.credential_generation() != binding.generation() { return Err(ManagedResourceError::CredentialChanged.into()); }
                        // Retain the monitor's pending stream read across this
                        // yield. Dropping it here would silently close the feed.
                        yield_once().await;
                        check_binding(cx, cancellation, deadline, &binding)?;
                        if signal.revision()? != revision { continue; }
                        self.require_generation(&set, generation)?;
                        let complete = read.is_complete();
                        let event = if complete { ManagedResourceWatchEvent::Snapshot(read) }
                            else { ManagedResourceWatchEvent::InputRequired(read) };
                        let continuing = observer.emit(event)?;
                        check_binding(cx, cancellation, deadline, &binding)?;
                        if !continuing { return Ok(ManagedResourceWatchOutcome::StoppedByHost); }
                        if !complete { return Ok(ManagedResourceWatchOutcome::InputRequired); }
                        published = Some(revision);
                    }
                };
                let mut monitor = Box::pin(monitor);
                let mut reads = Box::pin(reads);
                // A ready gap/update wins before a ready snapshot. Both owned
                // futures stay alive until the entire watch settles.
                poll_fn(|task| {
                    check_binding(cx, cancellation, deadline, &binding)?;
                    if let Poll::Ready(result) = monitor.as_mut().poll(task) { return Poll::Ready(result); }
                    reads.as_mut().poll(task)
                }).await
            }.await)
        })).await?
    }
}

fn listen_request(request: &CoreRequest) -> Result<CoreRequest, ManagedResourceWatchError> {
    let (uri, ordinary) = read_identity(request)?;
    if !ordinary { return Err(ManagedResourceWatchError::ContinuationNotAllowed); }
    let params = request.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    CoreRequest::decode(ProtocolEra::Modern2026, "subscriptions/listen", Some(&serde_json::json!({
        "_meta":params["_meta"], "notifications":{"resourcesListChanged":true,"resourceSubscriptions":[uri]},
    }))).map_err(|_| ManagedCoreError::InvalidRequest.into())
}
fn covers(uri: &str, filter: &SubscriptionFilter) -> bool {
    filter.resources_list_changed == Some(true)
        && filter.resource_subscriptions.as_ref().is_some_and(|uris| uris.iter().any(|candidate| candidate == uri))
}
fn relevant(notification: &ServerNotification) -> bool {
    matches!(notification, ServerNotification::ResourceUpdated(_) | ServerNotification::ResourcesListChanged(_))
}
fn check_binding(cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time, credential: &OAuthCredentialSnapshot) -> Result<(), ManagedResourceError> {
    check_call(cx, cancellation, deadline)?;
    require_credential(credential)
}
fn locally_superseded(error: &ManagedResourceError, local: &McpRequestCancellation) -> bool {
    matches!(error, ManagedResourceError::Invalidated)
        || (local.is_cancel_requested() && matches!(error, ManagedResourceError::Core(ManagedCoreError::Cancelled)))
}
fn admit_listen_size(request: &CoreRequest, id: &RequestId, maximum: usize) -> Result<(), ManagedResourceWatchError> {
    let params = request.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?;
    let mut writer = BoundedWriter { bytes: Vec::new(), maximum };
    serde_json::to_writer(&mut writer, &serde_json::json!({"jsonrpc":"2.0","id":id,"method":"subscriptions/listen","params":params}))
        .map_err(|_| ManagedCoreError::RequestTooLarge)?;
    Ok(())
}
struct Ids<I> { next: I, used: Vec<RequestId>, bytes: usize, limits: ManagedResourceWatchLimits }
fn issue_id<I: FnMut() -> Result<RequestId, ManagedResourceError>>(ids: &Mutex<Ids<I>>) -> Result<RequestId, ManagedResourceError> {
    let mut ids = ids.lock().map_err(|_| ManagedResourceError::CacheUnavailable)?;
    if ids.used.len() > ids.limits.reads { return Err(ManagedCoreError::InvalidRequest.into()); }
    let id = (ids.next)()?;
    id.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
    if ids.used.iter().any(|used| used.correlates_with(&id)) { return Err(ManagedCoreError::InvalidRequest.into()); }
    let mut writer = BoundedWriter { bytes: Vec::new(), maximum: ids.limits.id_bytes.saturating_sub(ids.bytes) };
    serde_json::to_writer(&mut writer, &id).map_err(|_| ManagedCoreError::RequestTooLarge)?;
    ids.bytes += writer.bytes.len();
    ids.used.push(id.clone());
    Ok(id)
}
struct Observer<O> { callback: Mutex<O>, stopped: AtomicBool }
impl<O> Observer<O>
where O: FnMut(ManagedResourceWatchEvent) -> Result<ManagedResourceWatchControl, ManagedResourceError> {
    fn emit(&self, event: ManagedResourceWatchEvent) -> Result<bool, ManagedResourceError> {
        let control = (self.callback.lock().map_err(|_| ManagedResourceError::CacheUnavailable)?)(event)?;
        if control == ManagedResourceWatchControl::Stop { self.stopped.store(true, Ordering::Release); }
        Ok(control == ManagedResourceWatchControl::Continue)
    }
}
#[derive(Default)]
struct Signal(Mutex<SignalState>);
#[derive(Default)]
struct SignalState { revision: u64, active: Option<McpRequestCancellation>, waker: Option<Waker> }
impl Signal {
    fn revision(&self) -> Result<u64, ManagedResourceError> {
        Ok(self.0.lock().map_err(|_| ManagedResourceError::CacheUnavailable)?.revision)
    }
    fn changed(&self) -> Result<(), ManagedResourceError> {
        let (active, waker) = {
            let mut state = self.0.lock().map_err(|_| ManagedResourceError::CacheUnavailable)?;
            state.revision = state.revision.checked_add(1).ok_or(ManagedResourceError::Invalidated)?;
            (state.active.clone(), state.waker.take())
        };
        if let Some(active) = active { active.cancel(); }
        if let Some(waker) = waker { waker.wake(); }
        Ok(())
    }
    async fn wait_after(&self, published: Option<u64>) -> Result<u64, ManagedResourceError> {
        poll_fn(|task| {
            let mut state = self.0.lock().map_err(|_| ManagedResourceError::CacheUnavailable)?;
            if published != Some(state.revision) { return Poll::Ready(Ok(state.revision)); }
            state.waker = Some(task.waker().clone());
            Poll::Pending
        }).await
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
}
async fn yield_once() {
    let mut yielded = false;
    poll_fn(|task| {
        if yielded { Poll::Ready(()) }
        else { yielded = true; task.waker().wake_by_ref(); Poll::Pending }
    }).await;
}
struct InvalidateOnExit<'a> { client: &'a ManagedResourceClient, set: FinalCacheResultSet }
impl Drop for InvalidateOnExit<'_> {
    fn drop(&mut self) {
        if let Ok(mut cache) = self.client.cache.lock() { cache.invalidate_result_set(&self.set); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::json;
    fn request(extra: Option<(&str, serde_json::Value)>) -> CoreRequest {
        let mut params = json!({"uri":"file:///one","_meta":FinalRequestMeta::new(ClientCapabilities::default())});
        if let Some((key, value)) = extra { params[key] = value; }
        CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", Some(&params)).unwrap()
    }
    #[test]
    fn watch_requests_both_resource_and_visibility_coverage_without_changing_metadata() {
        let original = request(None);
        let listen = listen_request(&original).unwrap().encode_params().unwrap().unwrap();
        assert_eq!(listen["notifications"], json!({"resourcesListChanged":true,"resourceSubscriptions":["file:///one"]}));
        assert_eq!(listen["_meta"], original.encode_params().unwrap().unwrap()["_meta"]);
        assert!(listen.get("uri").is_none());
        let filter: SubscriptionFilter = serde_json::from_value(listen["notifications"].clone()).unwrap();
        assert!(covers("file:///one", &filter));
        assert!(!covers("file:///other", &filter));
        for filter in [json!({}), json!({"resourcesListChanged":true}), json!({"resourceSubscriptions":["file:///one"]})] {
            assert!(!covers("file:///one", &serde_json::from_value(filter).unwrap()));
        }
    }
    #[test]
    fn present_empty_continuations_cannot_be_repeated_by_a_watch() {
        for extra in [("requestState", json!("")), ("inputResponses", json!({}))] {
            assert!(matches!(listen_request(&request(Some(extra))), Err(ManagedResourceWatchError::ContinuationNotAllowed)));
        }
    }
    #[test]
    fn watch_id_history_rejects_numeric_aliases_and_over_budget_ids() {
        let mut values = vec![RequestId::Number(1), serde_json::from_str("1e0").unwrap()].into_iter();
        let ids = Mutex::new(Ids { next: || Ok(values.next().unwrap()), used: Vec::new(), bytes: 0, limits: ManagedResourceWatchLimits::default() });
        assert!(issue_id(&ids).is_ok());
        assert!(issue_id(&ids).is_err());
        let limits = ManagedResourceWatchLimits::new(Duration::from_secs(1), 1, 1, 2).unwrap();
        let ids = Mutex::new(Ids { next: || Ok(RequestId::String("too-long".into())), used: Vec::new(), bytes: 0, limits });
        assert!(issue_id(&ids).is_err());
        assert!(ids.lock().unwrap().used.is_empty());
    }
    #[test]
    fn only_invalidation_or_its_owned_cancellation_can_trigger_reread() {
        let local = McpRequestCancellation::new();
        assert!(locally_superseded(&ManagedResourceError::Invalidated, &local));
        assert!(!locally_superseded(&ManagedCoreError::Cancelled.into(), &local));
        local.cancel();
        assert!(locally_superseded(&ManagedCoreError::Cancelled.into(), &local));
        for error in [ManagedCoreError::TimedOut, ManagedCoreError::InvalidResult, ManagedCoreError::MissingTerminal] {
            assert!(!locally_superseded(&error.into(), &local));
        }
    }
    #[test]
    fn signal_invalidates_active_read_but_not_caller_and_never_reuses_old_revision() {
        let signal = Signal::default();
        let first = signal.begin(0).unwrap().unwrap();
        signal.changed().unwrap();
        assert!(first.is_cancel_requested());
        assert_eq!(signal.revision().unwrap(), 1);
        assert!(signal.begin(0).unwrap().is_none());
        signal.finish().unwrap();
        let second = signal.begin(1).unwrap().unwrap();
        assert!(!second.is_cancel_requested());
    }
}
