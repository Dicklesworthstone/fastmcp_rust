//! Persistence-gated observation of an already-recorded Task.
//!
//! One caller-owned watch reconciles fresh authenticated snapshots with the
//! saved controls, awaits an explicit host persistence callback, then publishes
//! each active snapshot. Terminal cleanup requires explicit acknowledgement
//! AFTER result delivery so a crash cannot erase the only saved lookup hint.
//! The callback receives only a conditional control-record change,
//! never the application Task, inputs, results, credentials or request state.
//! No creating call or input answer is replayed. This is not durable execution.
//! Explicit remote cancellation also stops pending persistence, retaining its
//! disposition and pending snapshot rather than pretending a write rolled back.

use std::fmt;
use std::future::Future;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::tasks_extension::Task;

use crate::http_auth::managed::{OAuthSessionError, deadline_after};
use crate::http_auth::managed::tasks::ManagedTasksClient;
use crate::http_auth::managed::tasks::watch::{ManagedTaskSnapshot, ManagedTaskWatchPolicy};
use crate::http_auth::managed::tasks::watch::cancellation::{
    CancellableTaskWatchError, ManagedTaskCancelHandle,
};
use crate::http_auth::managed::tasks::watch::recovery::{
    ManagedTaskRecoveryError, ManagedTaskRecoveryPolicy, RecoveringManagedTaskWatch,
};
use super::{admit_record, reconcile_controls};
use super::super::{TaskResumeBinding, TaskResumeError, TaskResumeKey, TaskResumeRecord, checkpoint, wall_now};

/// An immutable compare-and-replace (or compare-and-remove) of one saved record.
/// The expected version includes exact controls and original retention, not
/// just the Task ID. This is a local persistence command, not remote authority.
#[derive(Clone)]
pub struct TaskResumeChange {
    previous: TaskResumeRecord,
    replacement: Option<TaskResumeRecord>,
}

impl fmt::Debug for TaskResumeChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskResumeChange")
            .field("removes_record", &self.replacement.is_none())
            .finish_non_exhaustive()
    }
}

impl TaskResumeChange {
    /// Prepares controls from a freshly authenticated observation. The caller
    /// must obtain `task` through live authorization; this method performs no
    /// network I/O and cannot establish that an arbitrary Task value is trusted.
    pub fn from_snapshot(
        cx: &Cx,
        current: &TaskResumeBinding,
        previous: &TaskResumeRecord,
        task: &Task,
    ) -> Result<Self, TaskResumeError> {
        previous.admit(cx, current)?;
        Self::prepare_at(current, previous, task, wall_now())
    }

    /// Explicitly discard exactly these local lookup controls. This supports
    /// expired records, unavailable restart outcomes and deliberate host
    /// disposition without claiming that the remote Task stopped or completed.
    /// Current host-verified binding is still mandatory; stored identity is not
    /// authorization. No network, storage or cancellation effect happens here.
    ///
    /// Handle or durably save any terminal result BEFORE preparing its removal.
    /// A failed/abandoned observation or cancel request is not an instruction to
    /// discard its checkpoint. The host must make that disposition explicitly.
    /// Applying the command compares the entire physical record, including
    /// expired-but-unpruned controls. It never deletes a changed/newer version.
    pub fn discard(
        cx: &Cx, current: &TaskResumeBinding, previous: &TaskResumeRecord,
    ) -> Result<Self, TaskResumeError> {
        checkpoint(cx)?;
        if previous.binding != current.digest { return Err(TaskResumeError::Unavailable); }
        previous.validate()?;
        Ok(Self { previous: previous.clone(), replacement: None })
    }

    fn prepare_at(
        current: &TaskResumeBinding, previous: &TaskResumeRecord, task: &Task, now: i128,
    ) -> Result<Self, TaskResumeError> {
        let replacement = reconcile_controls(previous, current, task, now)?;
        Ok(Self { previous: previous.clone(), replacement })
    }

    pub fn key(&self) -> TaskResumeKey { self.previous.key() }
    pub fn previous(&self) -> &TaskResumeRecord { &self.previous }
    pub fn replacement(&self) -> Option<&TaskResumeRecord> { self.replacement.as_ref() }

    #[cfg(any(target_os = "linux", test))]
    fn admit_expected(&self, actual: Option<&TaskResumeRecord>) -> Result<(), TaskResumeError> {
        if actual != Some(&self.previous) { return Err(TaskResumeError::ConflictingSnapshot); }
        Ok(())
    }

    /// Applies this exact transition to the existing protected Linux store.
    /// Run in the host's OWNED blocking lane, never directly in an async poll.
    /// Exclusive mutable custody spans comparison and the synchronized write;
    /// SecureAtomicFile still enforces its file-version/process checks.
    ///
    /// Missing or changed records fail before protection or mutation, including
    /// a stale terminal trying to delete newer controls. Unchanged controls
    /// acknowledge the already-durable record without rewriting the manifest.
    /// Uncertain writes retain the store's existing quarantine/reconciliation
    /// behavior. This operation is not automatically retried or idempotent.
    /// Expiration still forbids replacement/resumption, but does not prevent
    /// current-owner removal of the exact expired physical version.
    #[cfg(target_os = "linux")]
    pub fn apply<P: super::super::store::TaskResumeProtector>(
        &self,
        cx: &Cx,
        current: &TaskResumeBinding,
        store: &mut super::super::store::TaskResumeStore<P>,
    ) -> Result<(), super::super::store::TaskResumeStoreError> {
        let Some(record) = &self.replacement else {
            return store.remove_expected(cx, current, &self.previous);
        };
        self.previous.admit(cx, current)?;
        let actual = store.get(cx, current, self.key())?;
        self.admit_expected(actual.as_ref())?;
        if record != &self.previous { store.put(cx, current, record.clone())?; }
        Ok(())
    }
}

/// What the caller observed about the persistence callback, not a storage probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskResumePersistenceState {
    /// No callback was invoked for this snapshot.
    NotAttempted,
    /// The callback started, but no success was observed. It may have committed;
    /// reconcile the storage provider before deciding on any further write.
    Unconfirmed,
    /// The callback returned success. Publication can still fail a final
    /// cancellation, login-lifetime or retention check after that acknowledgement.
    Acknowledged,
}

/// Retained after persistence failure or abandonment; never implicitly replayed.
/// The fresh application snapshot is separate from the payload-free change.
/// Inspecting it does not grant permission to submit inputs or recreate a Task.
pub struct PendingTaskResumeSnapshot {
    snapshot: ManagedTaskSnapshot,
    change: TaskResumeChange,
    persistence: TaskResumePersistenceState,
}
impl PendingTaskResumeSnapshot {
    pub fn snapshot(&self) -> &ManagedTaskSnapshot { &self.snapshot }
    pub fn change(&self) -> &TaskResumeChange { &self.change }
    pub fn persistence(&self) -> TaskResumePersistenceState { self.persistence }
    pub fn into_parts(self) -> (ManagedTaskSnapshot, TaskResumeChange, TaskResumePersistenceState) {
        (self.snapshot, self.change, self.persistence)
    }
}
impl fmt::Debug for PendingTaskResumeSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingTaskResumeSnapshot")
            .field("persistence", &self.persistence).finish_non_exhaustive()
    }
}

/// Host storage errors remain typed sources but are not formatted automatically:
/// a provider's diagnostics can contain paths, record data or other secrets.
pub enum PersistedTaskWatchError<E> {
    Resume(TaskResumeError),
    Recovery(ManagedTaskRecoveryError),
    Session(OAuthSessionError),
    Persistence(E),
    /// A validated remote cancel acknowledgement stopped this observer. It is
    /// not a terminal Task, a storage rollback receipt or permission to delete.
    CancellationRequested,
    TerminalAcknowledgementRequired,
    NoTerminal,
    Closed,
}
impl<E> fmt::Debug for PersistedTaskWatchError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resume(error) => f.debug_tuple("Resume").field(error).finish(),
            Self::Recovery(error) => f.debug_tuple("Recovery").field(error).finish(),
            Self::Session(error) => f.debug_tuple("Session").field(error).finish(),
            Self::Persistence(_) => f.write_str("Persistence(<host error>)"),
            Self::CancellationRequested => f.write_str("CancellationRequested"),
            Self::TerminalAcknowledgementRequired => f.write_str("TerminalAcknowledgementRequired"),
            Self::NoTerminal => f.write_str("NoTerminal"),
            Self::Closed => f.write_str("Closed"),
        }
    }
}
impl<E> fmt::Display for PersistedTaskWatchError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resume(error) => error.fmt(f),
            Self::Recovery(error) => error.fmt(f),
            Self::Session(error) => error.fmt(f),
            Self::Persistence(_) => f.write_str("Task observation persistence was not acknowledged"),
            Self::CancellationRequested => f.write_str("Task cancellation acknowledged; persisted observation stopped"),
            Self::TerminalAcknowledgementRequired => f.write_str("acknowledge the delivered terminal before completing observation"),
            Self::NoTerminal => f.write_str("no terminal Task snapshot has been delivered"),
            Self::Closed => f.write_str("persisted Task watch is closed"),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for PersistedTaskWatchError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resume(error) => Some(error),
            Self::Recovery(error) => Some(error),
            Self::Session(error) => Some(error),
            Self::Persistence(error) => Some(error),
            Self::CancellationRequested | Self::TerminalAcknowledgementRequired
            | Self::NoTerminal | Self::Closed => None,
        }
    }
}
impl<E> From<TaskResumeError> for PersistedTaskWatchError<E> {
    fn from(error: TaskResumeError) -> Self { Self::Resume(error) }
}
impl<E> From<ManagedTaskRecoveryError> for PersistedTaskWatchError<E> {
    fn from(error: ManagedTaskRecoveryError) -> Self { Self::Recovery(error) }
}
impl<E> From<OAuthSessionError> for PersistedTaskWatchError<E> {
    fn from(error: OAuthSessionError) -> Self { Self::Session(error) }
}
impl<E> From<CancellableTaskWatchError> for PersistedTaskWatchError<E> {
    fn from(error: CancellableTaskWatchError) -> Self {
        match error {
            CancellableTaskWatchError::CancellationRequested => Self::CancellationRequested,
            CancellableTaskWatchError::Closed => Self::Closed,
            CancellableTaskWatchError::Watch(error) => Self::Recovery(ManagedTaskRecoveryError::Watch(error)),
            CancellableTaskWatchError::Recovery(error) => Self::Recovery(error),
            CancellableTaskWatchError::Session(error) => Self::Session(error),
        }
    }
}

impl ManagedTasksClient {
    /// Resumes ONE already-persisted Task with persistence-gated observation.
    /// The host supplies its current verified binding and a protected record
    /// loaded under that binding. First acknowledgement and every subsequent
    /// snapshot use the existing recovering watch, not saved application state.
    ///
    /// `persist` must conditionally apply the supplied change and return success
    /// ONLY after durable acknowledgement. On Linux, `change.apply` performs the
    /// exact comparison and uses TaskResumeStore's protected atomic replacement.
    /// Dispatch synchronous storage in a caller-owned blocking lane and join it;
    /// do not detach a writer. Other providers must enforce the same contract.
    /// No blocking work, protector, executor or retry worker is installed here.
    ///
    /// The original retention and finite watch deadline also bound persistence
    /// and caller pauses. No callback is invoked during admission. Unavailable
    /// Tasks and authorization failures keep the saved record unchanged; only a
    /// freshly validated terminal snapshot permits conditional removal, and
    /// only AFTER the caller explicitly acknowledges handling its result.
    ///
    /// The returned owner's cancel_handle permits one explicit authenticated
    /// remote cancel request. A validated ACK stops reads, recovery and pending
    /// persistence without deleting the checkpoint. Merely obtaining or dropping
    /// the handle performs no request. Failed attempts do not stop observation.
    #[allow(clippy::too_many_arguments)]
    pub async fn resume_task_watch_persisted<P, F, E>(
        &self, cx: &Cx, current: TaskResumeBinding, record: TaskResumeRecord,
        id_prefix: String, policy: ManagedTaskWatchPolicy,
        recovery: ManagedTaskRecoveryPolicy, persist: P,
    ) -> Result<PersistedManagedTaskWatch<P>, PersistedTaskWatchError<E>>
    where
        P: FnMut(TaskResumeChange) -> F,
        F: Future<Output = Result<(), E>>,
    {
        self.resume_task_watch_persisted_with_cancellation(
            cx, &McpRequestCancellation::new(), current, record,
            id_prefix, policy, recovery, persist,
        ).await
    }

    /// One cancellation domain covers admission, recovery and persistence. A
    /// cancelled/abandoned persistence can have committed; inspect pending()
    /// and reconcile the provider rather than retrying a change blindly.
    #[allow(clippy::too_many_arguments)]
    pub async fn resume_task_watch_persisted_with_cancellation<P, F, E>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        current: TaskResumeBinding, record: TaskResumeRecord,
        id_prefix: String, policy: ManagedTaskWatchPolicy,
        recovery: ManagedTaskRecoveryPolicy, persist: P,
    ) -> Result<PersistedManagedTaskWatch<P>, PersistedTaskWatchError<E>>
    where
        P: FnMut(TaskResumeChange) -> F,
        F: Future<Output = Result<(), E>>,
    {
        self.session.check(cx, cancellation)?;
        let anchor = cx.now();
        let now = wall_now();
        admit_record(&record, &current, self.session.resource().as_str(), now)?;
        let remaining = record.retain_until.checked_sub(now).ok_or(TaskResumeError::Unavailable)?;
        let retention_deadline = anchor.saturating_add_nanos(u64::try_from(remaining).unwrap_or(u64::MAX));
        let deadline = retention_deadline.min(deadline_after(cx, policy.timeout)?);
        let remote_cancel = ManagedTaskCancelHandle::for_observation(
            self, record.task_id().clone(), &id_prefix, cancellation, deadline,
        )?;
        let watch = Box::pin(self.session.await_active(cx, cancellation, deadline, None, async {
            Ok(self.watch_tasks_recovering_with_cancellation(
                cx, cancellation, vec![record.task_id().clone()], id_prefix, policy, recovery,
            ).await)
        })).await??;
        let result = PersistedManagedTaskWatch {
            client: self.clone(), current, record, cancellation: cancellation.clone(),
            deadline, watch: Some(watch), remote_cancel, persist, pending: None, terminal_cleanup: None,
            cleanup_state: TaskResumePersistenceState::NotAttempted, closed: false, finished: false,
        };
        result.check::<E>(cx)?;
        Ok(result)
    }
}

/// Exactly one in-flight read/change. An ACTIVE snapshot is published only
/// after its conditional storage change has been acknowledged. A TERMINAL is
/// delivered without deleting the record; call acknowledge_terminal only after
/// handling or durably storing that result. Until then, restart can re-read it.
/// This is NOT exactly-once delivery: a crash can redeliver a terminal. Persist
/// results separately for a durable result inbox; this store excludes payloads.
///
/// An abandoned POLLED read closes observation permanently. During persistence
/// its pending snapshot/change remains inspectable on this owner, but a failed
/// owner never performs another read or write. An unpolled future has no effect.
/// Remote cancellation retains that same pending custody and cannot be mistaken
/// for terminal cleanup. An independently running storage job can still commit;
/// the host must retain its job handle and reconcile its actual outcome.
#[must_use = "poll snapshots, close explicitly, or drop the observation owner"]
pub struct PersistedManagedTaskWatch<P> {
    client: ManagedTasksClient,
    current: TaskResumeBinding,
    record: TaskResumeRecord,
    cancellation: McpRequestCancellation,
    deadline: Time,
    watch: Option<RecoveringManagedTaskWatch>,
    remote_cancel: ManagedTaskCancelHandle,
    persist: P,
    pending: Option<PendingTaskResumeSnapshot>,
    terminal_cleanup: Option<TaskResumeChange>,
    cleanup_state: TaskResumePersistenceState,
    closed: bool,
    finished: bool,
}

impl<P> PersistedManagedTaskWatch<P> {
    /// Initial loaded record, then the record for the last published active
    /// snapshot. A pending acknowledged change may already supersede it in storage.
    pub fn last_published_record(&self) -> &TaskResumeRecord { &self.record }
    pub fn pending(&self) -> Option<&PendingTaskResumeSnapshot> { self.pending.as_ref() }
    pub fn take_pending(&mut self) -> Option<PendingTaskResumeSnapshot> { self.pending.take() }
    /// Conditional cleanup for the terminal already delivered to the caller.
    /// Exposed for diagnostics, never replayed by a failed/abandoned owner.
    pub fn terminal_cleanup(&self) -> Option<&TaskResumeChange> { self.terminal_cleanup.as_ref() }
    pub fn cleanup_state(&self) -> TaskResumePersistenceState { self.cleanup_state }

    /// A separate, cloneable caller-driven handle sharing one cancel attempt.
    /// ACK means CancellationRequested, not Task::Cancelled or record deletion.
    /// It is bound to this owner's original retention/deadline and login; close,
    /// drop, failed observation or terminal delivery retires further admission.
    pub fn cancel_handle(&self) -> ManagedTaskCancelHandle { self.remote_cancel.clone() }

    pub fn close(&mut self) {
        self.remote_cancel.close_observation();
        self.watch = None;
        self.closed = true;
    }

    /// Call only AFTER consuming or durably recording the terminal payload.
    /// Success means conditional removal was acknowledged; next_snapshot then
    /// returns EOF. No implicit cleanup occurs on close, drop or cancellation.
    ///
    /// Exactly one attempt is allowed. Error/drop can leave a committed write;
    /// inspect cleanup_state and reconcile the provider, never retry blindly.
    pub async fn acknowledge_terminal<F, E>(&mut self, cx: &Cx)
        -> Result<(), PersistedTaskWatchError<E>>
    where
        P: FnMut(TaskResumeChange) -> F,
        F: Future<Output = Result<(), E>>,
    {
        if self.finished { return Ok(()); }
        if self.closed { return Err(PersistedTaskWatchError::Closed); }
        let change = self.terminal_cleanup.clone().ok_or(PersistedTaskWatchError::NoTerminal)?;
        // Retire the write opportunity before the first await, even if the
        // lifetime guard refuses it without invoking the host callback.
        self.closed = true;
        self.check::<E>(cx)?;
        let client = self.client.clone();
        let cancellation = self.cancellation.clone();
        let persist = &mut self.persist;
        let state = &mut self.cleanup_state;
        Box::pin(client.session.await_active(cx, &cancellation, self.deadline, None, async {
            Ok(persist_change(state, persist, change).await)
        })).await?.map_err(PersistedTaskWatchError::Persistence)?;
        // Do not rewrite a successfully acknowledged storage commit as a
        // failure merely because retention expires immediately afterwards.
        // await_active already rechecks cancellation/session/deadline.
        self.finished = true;
        Ok(())
    }

    fn check<E>(&self, cx: &Cx) -> Result<(), PersistedTaskWatchError<E>> {
        if self.remote_cancel.cancellation_requested() {
            return Err(PersistedTaskWatchError::CancellationRequested);
        }
        self.client.session.check(cx, &self.cancellation)?;
        self.record.admit(cx, &self.current)?;
        if cx.now() >= self.deadline { return Err(OAuthSessionError::TimedOut.into()); }
        Ok(())
    }

    pub async fn next_snapshot<F, E>(
        &mut self, cx: &Cx,
    ) -> Result<Option<ManagedTaskSnapshot>, PersistedTaskWatchError<E>>
    where
        P: FnMut(TaskResumeChange) -> F,
        F: Future<Output = Result<(), E>>,
    {
        if self.finished { return Ok(None); }
        if self.remote_cancel.cancellation_requested() {
            self.close();
            return Err(PersistedTaskWatchError::CancellationRequested);
        }
        if self.closed { return Err(PersistedTaskWatchError::Closed); }
        if self.terminal_cleanup.is_some() {
            return Err(PersistedTaskWatchError::TerminalAcknowledgementRequired);
        }
        // One lease spans the read AND persistence. Error/drop also closes a
        // concurrent cancel attempt, while retaining pending storage custody.
        let mut watch = self.watch.take().ok_or(PersistedTaskWatchError::Closed)?;
        let remote_cancel = self.remote_cancel.clone();
        let mut lease = remote_cancel.read_lease();
        self.check::<E>(cx)?;
        let client = self.client.clone();
        let cancellation = self.cancellation.clone();
        let deadline = self.deadline;
        let read = Box::pin(client.session.await_active(cx, &cancellation, deadline, None, async {
            Ok(watch.next_snapshot(cx).await)
        }));
        let snapshot = remote_cancel.until_acknowledged(read).await???
            .ok_or(TaskResumeError::InvalidRecord)?;
        let change = TaskResumeChange::from_snapshot(cx, &self.current, &self.record, &snapshot.task)?;
        if change.replacement.is_none() {
            self.check::<E>(cx)?;
            // Elect only after validating against the saved controls. A stale
            // or conflicting terminal must not disable live cancel authority
            // as though it had been delivered. Failure still retires the owner.
            remote_cancel.select_terminal()?;
            self.terminal_cleanup = Some(change);
            // The remote watch/socket is released, but the protected record
            // remains until the caller acknowledges the delivered result.
            return Ok(Some(snapshot));
        }
        self.pending = Some(PendingTaskResumeSnapshot {
            snapshot, change, persistence: TaskResumePersistenceState::NotAttempted,
        });
        self.check::<E>(cx)?;
        let pending = self.pending.as_mut().ok_or(TaskResumeError::InvalidRecord)?;
        let persist = &mut self.persist;
        // Invoke INSIDE both guards. Keep pending in self so cancellation or
        // abandonment cannot discard a committed-but-unacknowledged write.
        let writing = Box::pin(client.session.await_active(cx, &cancellation, deadline, None, async {
            Ok(persist_change(&mut pending.persistence, persist, pending.change.clone()).await)
        }));
        remote_cancel.until_acknowledged(writing).await??
            .map_err(PersistedTaskWatchError::Persistence)?;
        self.check::<E>(cx)?;
        let pending = self.pending.take().ok_or(TaskResumeError::InvalidRecord)?;
        self.record = pending.change.replacement.ok_or(TaskResumeError::InvalidRecord)?;
        self.watch = Some(watch);
        lease.disarm();
        Ok(Some(pending.snapshot))
    }
}

impl<P> Drop for PersistedManagedTaskWatch<P> {
    fn drop(&mut self) { self.remote_cancel.close_observation(); }
}

// Shared by active-record publication and explicit terminal cleanup. Mark the
// attempt before entering host code and the acknowledgement before returning
// to a lifetime guard which may itself reject delivery.
async fn persist_change<P, F, E>(
    state: &mut TaskResumePersistenceState, persist: &mut P, change: TaskResumeChange,
) -> Result<(), E>
where
    P: FnMut(TaskResumeChange) -> F,
    F: Future<Output = Result<(), E>>,
{
    *state = TaskResumePersistenceState::Unconfirmed;
    let result = persist(change).await;
    if result.is_ok() { *state = TaskResumePersistenceState::Acknowledged; }
    result
}

#[cfg(test)]
mod tests;
