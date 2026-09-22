//! Remote cancellation coordinated with one caller-owned Task observation.
//!
//! The independently cloneable handle issues at most ONE cancellation attempt.
//! Only an admitted `tasks/cancel` acknowledgement stops the high-level watch.
//! The empty acknowledgement is not a terminal Task snapshot. Failed or lost
//! cancellation replies leave observation available for explicit reconciliation.
//! No mutation retry, Task creation, storage deletion or background task is added.

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
    ManagedTaskEvent, ManagedTaskRequest, ManagedTaskRequestIds, ManagedTaskSnapshot,
    ManagedTaskWatch, ManagedTaskWatchError, ManagedTaskWatchPolicy, ManagedTasksClient,
    ManagedTasksError, OAuthSessionError, WatchIds, deadline_after, prepare,
};
use super::recovery::{
    ManagedTaskRecoveryError, ManagedTaskRecoveryPolicy, RecoveringManagedTaskWatch,
};

const LIVE: u8 = 0;
const CANCEL_REQUESTED: u8 = 1;
const TERMINAL_DELIVERED: u8 = 2;
const CLOSED: u8 = 3;
const READY: u8 = 0;
const UNCONFIRMED: u8 = 1;
const ACKNOWLEDGED: u8 = 2;

/// Evidence about the single cancellation attempt, not remote Task status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskCancellationState {
    /// No polled request passed local admission.
    Ready,
    /// An attempt started but no valid acknowledgement was observed. It may
    /// have reached the peer; failure or abandonment never resets this state.
    Unconfirmed,
    /// The exact cancellation response was fully admitted. This does not mean
    /// the Task reached `cancelled`, nor that remote work has quiesced.
    Acknowledged,
}

/// Diagnostics exclude Task IDs, request prefixes, peer bodies and credentials.
#[derive(Debug)]
pub enum TaskCancellationError {
    Closed,
    AlreadyAttempted,
    NotAttempted(ManagedTasksError),
    Unconfirmed(ManagedTasksError),
}
impl fmt::Display for TaskCancellationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("Task cancellation observation owner is closed"),
            Self::AlreadyAttempted => f.write_str("Task cancellation was already attempted; it will not be replayed"),
            Self::NotAttempted(error) => write!(f, "Task cancellation did not start: {error}"),
            Self::Unconfirmed(error) => write!(f, "Task cancellation acknowledgement is unknown: {error}"),
        }
    }
}
impl std::error::Error for TaskCancellationError {}

/// CancellationRequested is local high-level disposition, NEVER successful EOF
/// or a fabricated `Task::Cancelled`. Raw Task get/watch APIs remain available
/// for an application that explicitly chooses to inspect the remote outcome.
#[derive(Debug)]
pub enum CancellableTaskWatchError {
    CancellationRequested,
    Closed,
    Watch(ManagedTaskWatchError),
    Recovery(ManagedTaskRecoveryError),
    Session(OAuthSessionError),
}
impl fmt::Display for CancellableTaskWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CancellationRequested => f.write_str("Task cancellation acknowledged; high-level observation stopped"),
            Self::Closed => f.write_str("cancellable Task watch is closed"),
            Self::Watch(error) => error.fmt(f),
            Self::Recovery(error) => error.fmt(f),
            Self::Session(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for CancellableTaskWatchError {}
impl From<ManagedTaskWatchError> for CancellableTaskWatchError {
    fn from(error: ManagedTaskWatchError) -> Self { Self::Watch(error) }
}
impl From<ManagedTasksError> for CancellableTaskWatchError {
    fn from(error: ManagedTasksError) -> Self { Self::Watch(error.into()) }
}
impl From<ManagedTaskRecoveryError> for CancellableTaskWatchError {
    fn from(error: ManagedTaskRecoveryError) -> Self {
        match error {
            ManagedTaskRecoveryError::Watch(error) => Self::Watch(error),
            error => Self::Recovery(error),
        }
    }
}
impl From<OAuthSessionError> for CancellableTaskWatchError {
    fn from(error: OAuthSessionError) -> Self { Self::Session(error) }
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

    fn claim(&self) -> Result<(), TaskCancellationError> {
        if self.completion.load(Ordering::Acquire) != LIVE {
            return Err(TaskCancellationError::Closed);
        }
        self.attempt.compare_exchange(READY, UNCONFIRMED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| TaskCancellationError::AlreadyAttempted)?;
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
        // Retain the receipt even when a previously selected terminal or close
        // wins the observation race. A later lifetime check cannot erase it.
        self.attempt.store(ACKNOWLEDGED, Ordering::Release);
        if self.completion.compare_exchange(LIVE, CANCEL_REQUESTED, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            self.acknowledged.cancel();
        }
    }

    fn terminal(&self) -> Result<(), CancellableTaskWatchError> {
        self.completion.compare_exchange(LIVE, TERMINAL_DELIVERED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|state| if state == CANCEL_REQUESTED {
                CancellableTaskWatchError::CancellationRequested
            } else { CancellableTaskWatchError::Closed })?;
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
    client: ManagedTasksClient,
    task_id: TaskId,
    ids: ManagedTaskRequestIds,
    cancellation: McpRequestCancellation,
    deadline: Time,
}

/// Cloneable authority for one explicit remote-cancel attempt. Clones share
/// admission and the exact IDs; they cannot multiply attempts. Constructed only
/// by a successfully admitted single-Task watch at its configured resource.
/// The handle never cancels the ambient Cx, shared request token, or login.
#[derive(Clone)]
pub struct ManagedTaskCancelHandle {
    scope: Arc<CancelScope>,
}
impl fmt::Debug for ManagedTaskCancelHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedTaskCancelHandle").field("state", &self.state()).finish_non_exhaustive()
    }
}
impl ManagedTaskCancelHandle {
    pub fn state(&self) -> TaskCancellationState { self.scope.control.state() }

    // Shared by plain/recovering and persistence-gated owners. This is local
    // preparation only: callers publish the handle AFTER successful admission.
    // The owner must close this scope on drop and arm a lease for each read.
    pub(super) fn for_observation(
        client: &ManagedTasksClient, task_id: TaskId, prefix: &str,
        cancellation: &McpRequestCancellation, deadline: Time,
    ) -> Result<Self, CancellableTaskWatchError> {
        let ids = cancellation_ids(prefix)?;
        let prepared = prepare(client.session.resource().as_str(), &client.metadata, &ids.operation,
            ManagedTaskRequest::Cancel(task_id.clone()), client.limits)?;
        let _ = client.prepare_round(ids.clone(), prepared)?;
        Ok(Self { scope: Arc::new(CancelScope {
            control: Arc::new(Control::new()), client: client.clone(), task_id,
            ids, cancellation: cancellation.clone(), deadline,
        }) })
    }

    pub(super) fn cancellation_requested(&self) -> bool {
        self.scope.control.completion.load(Ordering::Acquire) == CANCEL_REQUESTED
    }

    pub(super) fn close_observation(&self) { self.scope.control.close(); }

    // Select only after the enclosing owner's complete snapshot admission.
    // Persisted owners validate saved controls BEFORE electing the terminal.
    pub(super) fn select_terminal(&self) -> Result<(), CancellableTaskWatchError> {
        self.scope.control.terminal()
    }

    pub(super) fn read_lease(&self) -> ReadLease {
        ReadLease { control: Arc::clone(&self.scope.control), armed: true }
    }

    // Also wraps persistence, not just network reads. A dropped/failed save is
    // not a rollback receipt; the enclosing owner retains its pending change.
    pub(super) async fn until_acknowledged<T>(
        &self, work: impl Future<Output = T>,
    ) -> Result<T, CancellableTaskWatchError> {
        until_signal(&self.scope.control.acknowledged, work).await
            .map_err(|()| CancellableTaskWatchError::CancellationRequested)
    }

    /// Request remote cancellation while another caller polls next_snapshot.
    /// Success records an ACK only. No remote terminal or rollback is implied.
    pub async fn request_cancel(&self, cx: &Cx) -> Result<(), TaskCancellationError> {
        self.request_cancel_with_cancellation(cx, &McpRequestCancellation::new()).await
    }

    /// The supplied token cancels ONLY this attempt's wait; the original watch
    /// cancellation and deadline still bound it. A local preflight failure does
    /// not spend the attempt. After admission, even discovery failure or an
    /// abandoned future leaves Unconfirmed rather than enabling a hidden retry.
    /// Observation continues unless an actual acknowledgement was admitted.
    ///
    /// Closing/dropping the observation owner wakes an outstanding cancellation
    /// wait. A socket/provider operation already committed cannot be undone.
    /// An ACK admitted before that wake is returned as acknowledged even if a
    /// final outer lifetime check loses the race; inspect state after any drop.
    pub async fn request_cancel_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
    ) -> Result<(), TaskCancellationError> {
        let scope = &self.scope;
        if scope.control.state() != TaskCancellationState::Ready {
            return Err(TaskCancellationError::AlreadyAttempted);
        }
        if scope.control.completion.load(Ordering::Acquire) != LIVE {
            return Err(TaskCancellationError::Closed);
        }
        let deadline = (|| {
            scope.client.session.check(cx, &scope.cancellation)?;
            scope.client.session.check(cx, cancellation)?;
            let deadline = scope.deadline.min(deadline_after(cx, scope.client.limits.timeout)?);
            if cx.now() >= deadline { return Err(OAuthSessionError::TimedOut); }
            Ok(deadline)
        })().map_err(|error| TaskCancellationError::NotAttempted(error.into()))?;
        scope.control.claim()?;
        let attempted = Box::pin(scope.client.session.await_active(cx, &scope.cancellation, deadline, None, async {
            Ok(async {
                let mut call = scope.client.request_with_cancellation(
                    cx, cancellation, scope.ids.clone(), ManagedTaskRequest::Cancel(scope.task_id.clone()),
                ).await?;
                if !matches!(call.next_event(cx).await?, Some(ManagedTaskEvent::Cancelled(_))) {
                    return Err(ManagedTasksError::InvalidResponse);
                }
                // No await separates fully admitted ACK and its shared receipt.
                // Only this production boundary can wake high-level observation.
                scope.control.acknowledge();
                Ok::<(), ManagedTasksError>(())
            }.await)
        }));
        let result = until_signal(&scope.control.closed, attempted).await;
        if scope.control.state() == TaskCancellationState::Acknowledged { return Ok(()); }
        let error = match result {
            Err(()) => OAuthSessionError::Closed.into(),
            Ok(Err(error)) => error.into(),
            Ok(Ok(Err(error))) => error,
            Ok(Ok(Ok(()))) => ManagedTasksError::InvalidResponse,
        };
        Err(TaskCancellationError::Unconfirmed(error))
    }
}

enum Observation {
    Plain(Box<ManagedTaskWatch>),
    Recovering(Box<RecoveringManagedTaskWatch>),
}
impl Observation {
    async fn next(&mut self, cx: &Cx) -> Result<Option<ManagedTaskSnapshot>, CancellableTaskWatchError> {
        match self {
            Self::Plain(watch) => Ok(watch.next_snapshot(cx).await?),
            Self::Recovering(watch) => Ok(watch.next_snapshot(cx).await?),
        }
    }
}

/// One existing watch plus an independently driven remote-cancel handle.
/// Observation, including optional reconnect backoff and fresh gets, is dropped
/// promptly after a validated cancellation ACK. No snapshot or checkpoint is
/// synthesized/deleted. Unpolled owners retain their sockets until next poll,
/// close or drop; cancellation cannot execute code in an unpolled future.
///
/// Terminal delivery and acknowledged cancellation have one atomic election.
/// A terminal selected first remains terminal; otherwise cancellation wins and
/// the result is CancellationRequested, never EOF. Failed/abandoned reads retire
/// both observation and future cancel admission, without revoking the session.
#[must_use = "retain observation custody and poll snapshots or explicitly close"]
pub struct CancellableManagedTaskWatch {
    scope: Arc<CancelScope>,
    observation: Option<Observation>,
}
impl CancellableManagedTaskWatch {
    pub fn cancel_handle(&self) -> ManagedTaskCancelHandle {
        ManagedTaskCancelHandle { scope: Arc::clone(&self.scope) }
    }

    pub fn close(&mut self) {
        self.scope.control.close();
        self.observation = None;
    }

    pub async fn next_snapshot(&mut self, cx: &Cx) -> Result<Option<ManagedTaskSnapshot>, CancellableTaskWatchError> {
        match self.scope.control.completion.load(Ordering::Acquire) {
            CANCEL_REQUESTED => {
                self.close();
                return Err(CancellableTaskWatchError::CancellationRequested);
            }
            TERMINAL_DELIVERED => return Ok(None),
            CLOSED => return Err(CancellableTaskWatchError::Closed),
            _ => {},
        }
        let mut observation = self.observation.take().ok_or(CancellableTaskWatchError::Closed)?;
        // Before the first await, the read owns ALL transport custody and its
        // abandonment closes cancellation admission too. No detached cleanup.
        let handle = self.cancel_handle();
        let mut lease = handle.read_lease();
        let scope = Arc::clone(&self.scope);
        let read = Box::pin(scope.client.session.await_active(cx, &scope.cancellation, scope.deadline, None, async {
            Ok(observation.next(cx).await)
        }));
        let result = handle.until_acknowledged(read).await??;
        let snapshot = result?;
        if handle.cancellation_requested() {
            return Err(CancellableTaskWatchError::CancellationRequested);
        }
        let Some(snapshot) = snapshot else {
            return Err(ManagedTaskWatchError::UnexpectedEvent.into());
        };
        if matches!(&*snapshot.task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
            handle.select_terminal()?;
        } else {
            self.observation = Some(observation);
            lease.disarm();
        }
        Ok(Some(snapshot))
    }
}
impl Drop for CancellableManagedTaskWatch {
    fn drop(&mut self) { self.scope.control.close(); }
}
impl fmt::Debug for CancellableManagedTaskWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancellableManagedTaskWatch")
            .field("cancellation", &self.scope.control.state()).finish_non_exhaustive()
    }
}

pub(super) struct ReadLease { control: Arc<Control>, armed: bool }
impl ReadLease {
    pub(super) fn disarm(&mut self) { self.armed = false; }
}
impl Drop for ReadLease {
    fn drop(&mut self) { if self.armed { self.control.close(); } }
}

// Race an owned future against a wakeable signal. Observe the signal before
// AND after polling so a ready result cannot bypass a simultaneously selected
// stop. Dropping this future drops both the work and wake registration.
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

fn cancellation_ids(prefix: &str) -> Result<ManagedTaskRequestIds, CancellableTaskWatchError> {
    let _ = WatchIds::new(prefix.to_owned())?;
    // WatchIds emits only numeric suffixes. This disjoint reservation cannot
    // alias any initial/reconnect/get identity from the same watch prefix.
    Ok(ManagedTaskRequestIds::new(
        RequestId::String(format!("{prefix}:cancel:discovery")),
        RequestId::String(format!("{prefix}:cancel:operation")),
    )?)
}

impl ManagedTasksClient {
    /// Watch one existing Task and expose an explicit remote cancellation handle.
    /// `recovery = None` keeps the ordinary non-reconnecting watch; Some uses the
    /// existing bounded recovering watch unchanged. Both stop on an admitted
    /// cancellation ACK, including during idle SSE, a get, or recovery backoff.
    ///
    /// Use a distinct prefix for concurrent owners. Cancellation has its own
    /// reserved IDs and adds at most one discovery/cancel pair. It shares the
    /// original watch deadline, but never consumes or cancels a sibling token.
    /// Current owner authorization and Tasks support are rediscovered for the
    /// cancellation request; a Task ID or handle alone is not authorization.
    pub async fn watch_task_cancellable(
        &self, cx: &Cx, task_id: TaskId, id_prefix: String,
        policy: ManagedTaskWatchPolicy, recovery: Option<ManagedTaskRecoveryPolicy>,
    ) -> Result<CancellableManagedTaskWatch, CancellableTaskWatchError> {
        self.watch_task_cancellable_with_cancellation(
            cx, &McpRequestCancellation::new(), task_id, id_prefix, policy, recovery,
        ).await
    }

    /// Local cancellation closes observation, not the remote Task. Remote
    /// cancellation happens only when the handle's request_cancel is polled.
    #[allow(clippy::too_many_arguments)]
    pub async fn watch_task_cancellable_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, task_id: TaskId,
        id_prefix: String, policy: ManagedTaskWatchPolicy,
        recovery: Option<ManagedTaskRecoveryPolicy>,
    ) -> Result<CancellableManagedTaskWatch, CancellableTaskWatchError> {
        self.session.check(cx, cancellation)?;
        if let Some(recovery) = recovery { recovery.connection_policy(policy)?; }
        // Complete cancellation encoding and limits are checked BEFORE opening
        // observation. No half-admitted owner can later discover invalid IDs.
        let deadline = deadline_after(cx, policy.timeout)?;
        let handle = ManagedTaskCancelHandle::for_observation(
            self, task_id.clone(), &id_prefix, cancellation, deadline,
        )?;
        let observation = Box::pin(self.session.await_active(cx, cancellation, deadline, None, async {
            Ok(match recovery {
                Some(recovery) => self.watch_tasks_recovering_with_cancellation(
                    cx, cancellation, vec![task_id.clone()], id_prefix, policy, recovery,
                ).await.map(|watch| Observation::Recovering(Box::new(watch)))
                    .map_err(CancellableTaskWatchError::from),
                None => self.watch_tasks_with_cancellation(
                    cx, cancellation, vec![task_id.clone()], id_prefix, policy,
                ).await.map(|watch| Observation::Plain(Box::new(watch)))
                    .map_err(CancellableTaskWatchError::from),
            })
        })).await??;
        self.session.check(cx, cancellation)?;
        if cx.now() >= deadline { return Err(OAuthSessionError::TimedOut.into()); }
        Ok(CancellableManagedTaskWatch {
            scope: handle.scope,
            observation: Some(observation),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Wake, Waker};

    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }

    #[test]
    fn shared_attempt_admission_does_not_stop_observation_until_acknowledged() {
        let control = Arc::new(Control::new());
        let other = Arc::clone(&control);
        control.claim().unwrap();
        assert_eq!(other.state(), TaskCancellationState::Unconfirmed);
        assert!(matches!(other.claim(), Err(TaskCancellationError::AlreadyAttempted)));
        assert_eq!(control.completion.load(Ordering::Acquire), LIVE);
        assert!(!control.acknowledged.is_cancel_requested());
        other.acknowledge();
        assert_eq!(control.state(), TaskCancellationState::Acknowledged);
        assert_eq!(control.completion.load(Ordering::Acquire), CANCEL_REQUESTED);
        assert!(control.acknowledged.is_cancel_requested());
        assert!(!control.closed.is_cancel_requested());
    }

    #[test]
    fn terminal_and_acknowledged_cancellation_have_exactly_one_winner() {
        let terminal_first = Control::new();
        terminal_first.claim().unwrap();
        terminal_first.terminal().unwrap();
        terminal_first.acknowledge();
        assert_eq!(terminal_first.completion.load(Ordering::Acquire), TERMINAL_DELIVERED);
        assert_eq!(terminal_first.state(), TaskCancellationState::Acknowledged);
        assert!(!terminal_first.acknowledged.is_cancel_requested());
        let cancel_first = Control::new();
        cancel_first.claim().unwrap();
        cancel_first.acknowledge();
        assert!(matches!(cancel_first.terminal(), Err(CancellableTaskWatchError::CancellationRequested)));
        cancel_first.close();
        assert_eq!(cancel_first.completion.load(Ordering::Acquire), CANCEL_REQUESTED);
        assert_eq!(cancel_first.state(), TaskCancellationState::Acknowledged);
    }

    #[test]
    fn idle_observation_is_woken_by_ack_not_merely_by_attempt_admission() {
        let control = Control::new();
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let mut read = Box::pin(until_signal(&control.acknowledged, std::future::pending::<()>()));
        assert!(read.as_mut().poll(&mut cx).is_pending());
        let before = wakes.0.load(Ordering::SeqCst);
        control.claim().unwrap();
        assert_eq!(wakes.0.load(Ordering::SeqCst), before);
        assert!(read.as_mut().poll(&mut cx).is_pending());
        control.acknowledge();
        assert!(wakes.0.load(Ordering::SeqCst) > before);
        assert!(matches!(read.as_mut().poll(&mut cx), Poll::Ready(Err(()))));
    }

    #[test]
    fn signal_during_ready_poll_withholds_output_and_releases_work() {
        struct Work<'a> { signal: &'a McpRequestCancellation, dropped: &'a Cell<bool> }
        impl Future for Work<'_> {
            type Output = usize;
            fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<usize> {
                self.signal.cancel();
                Poll::Ready(7)
            }
        }
        impl Drop for Work<'_> { fn drop(&mut self) { self.dropped.set(true); } }
        let signal = McpRequestCancellation::new();
        let dropped = Cell::new(false);
        let mut cx = Context::from_waker(Waker::noop());
        let mut guarded = Box::pin(until_signal(&signal, Work { signal: &signal, dropped: &dropped }));
        assert!(matches!(guarded.as_mut().poll(&mut cx), Poll::Ready(Err(()))));
        drop(guarded);
        assert!(dropped.get());
        let fresh = McpRequestCancellation::new();
        let mut baseline = Box::pin(until_signal(&fresh, std::future::ready(7)));
        assert!(matches!(baseline.as_mut().poll(&mut cx), Poll::Ready(Ok(7))));
    }

    #[test]
    fn abandoned_read_retires_cancel_admission_without_selecting_remote_cancellation() {
        let control = Arc::new(Control::new());
        let unrelated = McpRequestCancellation::new();
        drop(ReadLease { control: Arc::clone(&control), armed: true });
        assert_eq!(control.completion.load(Ordering::Acquire), CLOSED);
        assert!(control.closed.is_cancel_requested());
        assert!(!control.acknowledged.is_cancel_requested());
        assert!(matches!(control.claim(), Err(TaskCancellationError::Closed)));
        assert!(!unrelated.is_cancel_requested());
        let retained = Arc::new(Control::new());
        drop(ReadLease { control: Arc::clone(&retained), armed: false });
        assert!(retained.claim().is_ok());
    }

    #[test]
    fn dropped_signal_wait_removes_its_wake_registration() {
        let signal = McpRequestCancellation::new();
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let mut wait = Box::pin(until_signal(&signal, std::future::pending::<()>()));
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        drop(wait);
        let before = wakes.0.load(Ordering::SeqCst);
        signal.cancel();
        assert_eq!(wakes.0.load(Ordering::SeqCst), before);
    }

    #[test]
    fn cancellation_id_reservation_is_disjoint_from_watch_and_reconnect_ids() {
        let cancel = cancellation_ids("watch").unwrap();
        let mut observation = WatchIds::new("watch".to_owned()).unwrap();
        for _ in 0..32 {
            let next = observation.next_pair().unwrap();
            for id in [&next.discovery, &next.operation] {
                assert!(!cancel.discovery.correlates_with(id));
                assert!(!cancel.operation.correlates_with(id));
            }
        }
        for invalid in ["".to_owned(), "a:b".to_owned(), "x".repeat(129)] {
            assert!(cancellation_ids(&invalid).is_err());
        }
        assert!(cancellation_ids(&"x".repeat(128)).is_ok());
    }
}
