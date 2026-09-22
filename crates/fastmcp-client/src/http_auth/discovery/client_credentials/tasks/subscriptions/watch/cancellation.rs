//! Explicit remote cancellation for a machine-authenticated Task observation.
//!
//! Every handle clone shares one attempt. Only a validated cancellation ACK
//! stops observation; failure and abandonment retain uncertainty, never retry
//! authority. An ACK is not a terminal Task or proof of remote quiescence.
//! The opening credential and deadline own the attempt, including idle waits.

use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::Poll;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::RequestId;
use fastmcp_protocol::tasks_extension::{Task, TaskId};

use super::{
    ClientCredentialsError, ClientCredentialsSnapshot, ClientCredentialsTaskWatch,
    ClientCredentialsTaskWatchError, ClientCredentialsTaskWatchPolicy,
    ClientCredentialsTasksClient, ManagedTaskEvent, ManagedTaskRequest,
    ManagedTaskSnapshot, WatchIds, WatchState, active, check_watch, copy_binding,
    discovery_deadline, prepare_pinned, request_pinned,
};

pub use crate::http_auth::managed::tasks::watch::cancellation::TaskCancellationState;

const LIVE: u8 = 0;
const CANCEL_REQUESTED: u8 = 1;
const TERMINAL_DELIVERED: u8 = 2;
const CLOSED: u8 = 3;
const READY: u8 = 0;
const UNCONFIRMED: u8 = 1;
const ACKNOWLEDGED: u8 = 2;

/// Closed diagnostics: no credential, Task ID, input answer or peer body.
#[derive(Debug)]
pub enum ClientCredentialsTaskCancellationError {
    Closed,
    AlreadyAttempted,
    NotAttempted(ClientCredentialsTaskWatchError),
    Unconfirmed(ClientCredentialsTaskWatchError),
}
impl fmt::Display for ClientCredentialsTaskCancellationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("machine Task cancellation owner is closed"),
            Self::AlreadyAttempted => f.write_str("machine Task cancellation was already attempted; it will not be replayed"),
            Self::NotAttempted(error) => write!(f, "machine Task cancellation did not start: {error}"),
            Self::Unconfirmed(error) => write!(f, "machine Task cancellation acknowledgement is unknown: {error}"),
        }
    }
}
impl std::error::Error for ClientCredentialsTaskCancellationError {}

/// A cancellation ACK stops this owner, not the remote Task's lifecycle.
/// Applications may explicitly get/watch the Task again to learn its outcome.
#[derive(Debug)]
pub enum CancellableClientCredentialsTaskWatchError {
    CancellationRequested,
    Closed,
    Watch(ClientCredentialsTaskWatchError),
}
impl fmt::Display for CancellableClientCredentialsTaskWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CancellationRequested => f.write_str("machine Task cancellation acknowledged; observation stopped"),
            Self::Closed => f.write_str("cancellable machine Task watch is closed"),
            Self::Watch(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for CancellableClientCredentialsTaskWatchError {}
impl From<ClientCredentialsTaskWatchError> for CancellableClientCredentialsTaskWatchError {
    fn from(error: ClientCredentialsTaskWatchError) -> Self { Self::Watch(error) }
}
impl From<ClientCredentialsError> for CancellableClientCredentialsTaskWatchError {
    fn from(error: ClientCredentialsError) -> Self { Self::Watch(error.into()) }
}

struct Control {
    completion: AtomicU8,
    attempt: AtomicU8,
    acknowledged: McpRequestCancellation,
    closed: McpRequestCancellation,
}
impl Control {
    fn new() -> Self {
        Self {
            completion: AtomicU8::new(LIVE), attempt: AtomicU8::new(READY),
            acknowledged: McpRequestCancellation::new(), closed: McpRequestCancellation::new(),
        }
    }
    fn claim(&self) -> Result<(), ClientCredentialsTaskCancellationError> {
        if self.completion.load(Ordering::Acquire) != LIVE {
            return Err(ClientCredentialsTaskCancellationError::Closed);
        }
        self.attempt.compare_exchange(READY, UNCONFIRMED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ClientCredentialsTaskCancellationError::AlreadyAttempted)?;
        Ok(())
    }
    fn state(&self) -> TaskCancellationState {
        match self.attempt.load(Ordering::Acquire) {
            READY => TaskCancellationState::Ready,
            UNCONFIRMED => TaskCancellationState::Unconfirmed,
            ACKNOWLEDGED => TaskCancellationState::Acknowledged,
            _ => unreachable!("private cancellation state"),
        }
    }
    fn acknowledge(&self) {
        // Retain the receipt even if a terminal or close already won. A final
        // lifetime check must not erase an ACK admitted at the wire boundary.
        self.attempt.store(ACKNOWLEDGED, Ordering::Release);
        if self.completion.compare_exchange(LIVE, CANCEL_REQUESTED, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            self.acknowledged.cancel();
        }
    }
    fn terminal(&self) -> Result<(), CancellableClientCredentialsTaskWatchError> {
        self.completion.compare_exchange(LIVE, TERMINAL_DELIVERED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|state| if state == CANCEL_REQUESTED {
                CancellableClientCredentialsTaskWatchError::CancellationRequested
            } else { CancellableClientCredentialsTaskWatchError::Closed })?;
        self.closed.cancel();
        Ok(())
    }
    fn close(&self) {
        let _ = self.completion.compare_exchange(LIVE, CLOSED, Ordering::AcqRel, Ordering::Acquire);
        self.closed.cancel();
    }
}

struct CancelScope {
    control: Arc<Control>,
    client: ClientCredentialsTasksClient,
    task_id: TaskId,
    ids: (RequestId, RequestId),
    cancellation: McpRequestCancellation,
    deadline: Time,
    binding: Option<Arc<ClientCredentialsSnapshot>>,
}

/// One explicit remote-cancel capability tied to an admitted single-Task watch.
/// Clones cannot multiply attempts or exchange the original credential. Close
/// and drop of the observation owner retire admission without sending a POST.
#[derive(Clone)]
pub struct ClientCredentialsTaskCancelHandle { scope: Arc<CancelScope> }
impl fmt::Debug for ClientCredentialsTaskCancelHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCredentialsTaskCancelHandle")
            .field("state", &self.state()).finish_non_exhaustive()
    }
}
impl ClientCredentialsTaskCancelHandle {
    pub fn state(&self) -> TaskCancellationState { self.scope.control.state() }

    // Local-only admission, before opening a socket or acquiring a grant. The
    // enclosing owner publishes this handle only after ACK and binding pinning.
    pub(super) fn for_observation(
        client: &ClientCredentialsTasksClient, task_id: TaskId, prefix: &str,
        cancellation: &McpRequestCancellation, deadline: Time,
    ) -> Result<Self, CancellableClientCredentialsTaskWatchError> {
        let ids = cancellation_ids(prefix)?;
        let _ = prepare_pinned(client, &ids, ManagedTaskRequest::Cancel(task_id.clone()))?;
        Ok(Self { scope: Arc::new(CancelScope {
            control: Arc::new(Control::new()), client: client.clone(), task_id,
            ids, cancellation: cancellation.clone(), deadline, binding: None,
        }) })
    }
    pub(super) fn pin_binding(
        &mut self, binding: ClientCredentialsSnapshot, deadline: Time,
    ) -> Result<(), CancellableClientCredentialsTaskWatchError> {
        let scope = Arc::get_mut(&mut self.scope).ok_or(CancellableClientCredentialsTaskWatchError::Closed)?;
        // Never permit even an unshared admitted scope to change its authority.
        if scope.binding.is_some() { return Err(CancellableClientCredentialsTaskWatchError::Closed); }
        scope.binding = Some(Arc::new(binding));
        scope.deadline = scope.deadline.min(deadline);
        Ok(())
    }
    pub(super) fn cancellation_requested(&self) -> bool {
        self.scope.control.completion.load(Ordering::Acquire) == CANCEL_REQUESTED
    }
    pub(super) fn close_observation(&self) { self.scope.control.close(); }
    pub(super) fn select_terminal(&self) -> Result<(), CancellableClientCredentialsTaskWatchError> {
        self.scope.control.terminal()
    }
    pub(super) fn read_lease(&self) -> ReadLease {
        ReadLease { control: Arc::clone(&self.scope.control), armed: true }
    }
    pub(super) async fn until_acknowledged<T>(
        &self, work: impl Future<Output = T>,
    ) -> Result<T, CancellableClientCredentialsTaskWatchError> {
        until_signal(&self.scope.control.acknowledged, work).await
            .map_err(|()| CancellableClientCredentialsTaskWatchError::CancellationRequested)
    }

    /// Request cancellation once. Success is only a fully validated ACK.
    pub async fn request_cancel(&self, cx: &Cx) -> Result<(), ClientCredentialsTaskCancellationError> {
        self.request_cancel_with_cancellation(cx, &McpRequestCancellation::new()).await
    }

    /// The supplied token bounds this attempt without cancelling observation or
    /// siblings. The original watch token, deadline and credential still apply.
    /// Local preflight failure does not spend the attempt. After admission even
    /// discovery failure or a dropped future is Unconfirmed, never retryable.
    /// Failed cancellation does not stop observation; an admitted ACK does.
    /// No token renewal, Task creation or mutation replay is performed.
    pub async fn request_cancel_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
    ) -> Result<(), ClientCredentialsTaskCancellationError> {
        let scope = &self.scope;
        if scope.control.state() != TaskCancellationState::Ready {
            return Err(ClientCredentialsTaskCancellationError::AlreadyAttempted);
        }
        if scope.control.completion.load(Ordering::Acquire) != LIVE {
            return Err(ClientCredentialsTaskCancellationError::Closed);
        }
        let binding = scope.binding.as_deref().ok_or(ClientCredentialsTaskCancellationError::Closed)?;
        let owner = &scope.client.client.inner.closed;
        let deadline = (|| {
            check_watch(cx, scope.deadline, owner, &scope.cancellation, binding)?;
            check_watch(cx, scope.deadline, owner, cancellation, binding)?;
            let call_deadline = discovery_deadline(cx,
                scope.client.limits.timeout.min(scope.client.client.inner.timeout))
                .map_err(ClientCredentialsError::from)?;
            Ok::<_, ClientCredentialsTaskWatchError>(scope.deadline.min(call_deadline))
        })().map_err(ClientCredentialsTaskCancellationError::NotAttempted)?;
        scope.control.claim()?;
        let attempted = Box::pin(active(cx, deadline, owner, &scope.cancellation, Some(binding), async {
            Ok(async {
                let mut call = request_pinned(&scope.client, cx, cancellation, binding, deadline,
                    scope.ids.clone(), ManagedTaskRequest::Cancel(scope.task_id.clone())).await?;
                if !matches!(call.next_event(cx).await?, Some(ManagedTaskEvent::Cancelled(_))) {
                    return Err(ClientCredentialsTaskWatchError::UnexpectedEvent);
                }
                // There is no suspension between decoder admission and receipt.
                scope.control.acknowledge();
                Ok::<(), ClientCredentialsTaskWatchError>(())
            }.await)
        }));
        let result = until_signal(&scope.control.closed, attempted).await;
        if scope.control.state() == TaskCancellationState::Acknowledged { return Ok(()); }
        let error = match result {
            Err(()) => ClientCredentialsTaskWatchError::Closed,
            Ok(Err(error)) => error.into(),
            Ok(Ok(Err(error))) => error,
            Ok(Ok(Ok(()))) => ClientCredentialsTaskWatchError::UnexpectedEvent,
        };
        Err(ClientCredentialsTaskCancellationError::Unconfirmed(error))
    }
}

/// Notification-driven single-Task observation with an independent cancel
/// handle. Terminal delivery and acknowledged cancellation elect one outcome.
/// CancellationRequested is never successful EOF or a fabricated Cancelled Task.
/// Abandoning a polled read releases observation and permanently closes cancel
/// admission; an unpolled future has no effect. This owner does not reconnect.
#[must_use = "retain observation custody and poll snapshots or explicitly close"]
pub struct CancellableClientCredentialsTaskWatch {
    remote_cancel: ClientCredentialsTaskCancelHandle,
    observation: Option<ClientCredentialsTaskWatch>,
}
impl CancellableClientCredentialsTaskWatch {
    pub fn cancel_handle(&self) -> ClientCredentialsTaskCancelHandle { self.remote_cancel.clone() }
    pub fn close(&mut self) {
        self.remote_cancel.close_observation();
        self.observation = None;
    }
    pub async fn next_snapshot(&mut self, cx: &Cx)
        -> Result<Option<ManagedTaskSnapshot>, CancellableClientCredentialsTaskWatchError>
    {
        match self.remote_cancel.scope.control.completion.load(Ordering::Acquire) {
            CANCEL_REQUESTED => {
                self.close();
                return Err(CancellableClientCredentialsTaskWatchError::CancellationRequested);
            }
            TERMINAL_DELIVERED => return Ok(None),
            CLOSED => return Err(CancellableClientCredentialsTaskWatchError::Closed),
            _ => {},
        }
        let mut observation = self.observation.take().ok_or(CancellableClientCredentialsTaskWatchError::Closed)?;
        let handle = self.remote_cancel.clone();
        let mut lease = handle.read_lease();
        let scope = Arc::clone(&handle.scope);
        let binding = scope.binding.as_deref().ok_or(CancellableClientCredentialsTaskWatchError::Closed)?;
        let read = Box::pin(active(cx, scope.deadline, &scope.client.client.inner.closed,
            &scope.cancellation, Some(binding), async { Ok(observation.next_snapshot(cx).await) }));
        let snapshot = handle.until_acknowledged(read).await???;
        if handle.cancellation_requested() {
            return Err(CancellableClientCredentialsTaskWatchError::CancellationRequested);
        }
        let snapshot = snapshot.ok_or(ClientCredentialsTaskWatchError::UnexpectedEvent)?;
        if matches!(&*snapshot.task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
            handle.select_terminal()?;
        } else {
            self.observation = Some(observation);
            lease.disarm();
        }
        Ok(Some(snapshot))
    }
}
impl Drop for CancellableClientCredentialsTaskWatch {
    fn drop(&mut self) { self.remote_cancel.close_observation(); }
}
impl fmt::Debug for CancellableClientCredentialsTaskWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancellableClientCredentialsTaskWatch")
            .field("cancellation", &self.remote_cancel.state()).finish_non_exhaustive()
    }
}

pub(super) struct ReadLease { control: Arc<Control>, armed: bool }
impl ReadLease { pub(super) fn disarm(&mut self) { self.armed = false; } }
impl Drop for ReadLease {
    fn drop(&mut self) { if self.armed { self.control.close(); } }
}

async fn until_signal<T>(signal: &McpRequestCancellation, work: impl Future<Output = T>) -> Result<T, ()> {
    let mut stopped = std::pin::pin!(signal.cancelled());
    let mut work = std::pin::pin!(work);
    poll_fn(|task| {
        if stopped.as_mut().poll(task).is_ready() { return Poll::Ready(Err(())); }
        let result = work.as_mut().poll(task);
        if signal.is_cancel_requested() { return Poll::Ready(Err(())); }
        result.map(Ok)
    }).await
}

fn cancellation_ids(prefix: &str) -> Result<(RequestId, RequestId), ClientCredentialsTaskWatchError> {
    let _ = WatchIds::new(prefix.to_owned())?;
    // Normal watch IDs have numeric suffixes. This pair cannot alias reads,
    // reconnects or input updates generated from the same validated prefix.
    Ok((RequestId::String(format!("{prefix}:cancel:discovery")),
        RequestId::String(format!("{prefix}:cancel:operation"))))
}

impl ClientCredentialsTasksClient {
    /// Watch one existing Task with explicit remote cancellation. Opening only
    /// admits observation; no cancel POST occurs until a handle is polled.
    /// The selection must be acknowledged before the handle becomes available.
    pub async fn watch_task_cancellable(
        &self, cx: &Cx, task_id: TaskId, id_prefix: String,
        policy: ClientCredentialsTaskWatchPolicy,
    ) -> Result<CancellableClientCredentialsTaskWatch, CancellableClientCredentialsTaskWatchError> {
        self.watch_task_cancellable_with_cancellation(cx, &McpRequestCancellation::new(),
            task_id, id_prefix, policy).await
    }
    /// One caller-owned deadline includes admission and later pauses. Both
    /// observation and cancellation stay pinned to the opening credential;
    /// expiry/revocation fails closed instead of refreshing mutation authority.
    pub async fn watch_task_cancellable_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, task_id: TaskId,
        id_prefix: String, policy: ClientCredentialsTaskWatchPolicy,
    ) -> Result<CancellableClientCredentialsTaskWatch, CancellableClientCredentialsTaskWatchError> {
        let _ = WatchState::new(vec![task_id.clone()], policy.maximum_snapshots)?;
        let deadline = discovery_deadline(cx, policy.timeout).map_err(ClientCredentialsError::from)?;
        let mut handle = ClientCredentialsTaskCancelHandle::for_observation(
            self, task_id.clone(), &id_prefix, cancellation, deadline,
        )?;
        let owner = &self.client.inner.closed;
        let mut observation = Box::pin(active(cx, deadline, owner, cancellation, None, async {
            Ok(self.watch_tasks_with_cancellation(cx, cancellation,
                vec![task_id], id_prefix, policy).await)
        })).await??;
        observation.deadline = observation.deadline.min(deadline);
        check_watch(cx, observation.deadline, owner, cancellation, &observation.binding)?;
        handle.pin_binding(copy_binding(&observation.binding), observation.deadline)?;
        Ok(CancellableClientCredentialsTaskWatch { remote_cancel: handle, observation: Some(observation) })
    }
}

#[cfg(test)]
mod tests;
