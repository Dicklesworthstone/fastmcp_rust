//! Restart machine-authenticated Tasks from protected, payload-free controls.
//!
//! Reuse the existing checkpoint codec, bounded staging, control reconciliation
//! and conditional storage commands. Only current machine discovery/get uses the
//! network. Saved records cannot select an issuer, renew mutation authority,
//! restore input answers, create a Task, or install a subscription.

use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::RequestId;
use fastmcp_protocol::tasks_extension::Task;

use super::{
    ClientCredentialsError, ClientCredentialsTasksClient, ClientCredentialsTasksError,
    ClientCredentialsTaskWatchError, ManagedTaskEvent, ManagedTaskRequest,
    ManagedTasksError, OAuthDiscoveryError, WatchIds, active, check_context, discovery_deadline,
};
use crate::http_auth::managed::tasks::watch::checkpoint::resume::client::{
    lifecycle::TaskResumeChange, restart::{TaskResumeRestartPlan, TaskResumeRestartPolicy},
    resume_read_deadline,
};
pub use crate::http_auth::managed::tasks::watch::checkpoint::resume::{
    TaskResumeBinding, TaskResumeError, TaskResumeRecord,
};

/// A live, authorized observation, not saved application state or input authority.
/// Failed and cancelled Tasks are terminals, not successful tool execution.
pub enum ClientCredentialsTaskResumeReconciliation {
    Active { task: Box<Task>, record: TaskResumeRecord },
    Terminal(Box<Task>),
}

/// Redacted failures retain typed transport/authentication causes. Only local
/// expiry and HTTP 401/403/404 are deliberately merged as Unavailable.
#[derive(Debug)]
pub enum ClientCredentialsTaskResumeError {
    Resume(TaskResumeError),
    Task(ClientCredentialsTasksError),
    Identity(ClientCredentialsTaskWatchError),
    Closed,
}
impl fmt::Display for ClientCredentialsTaskResumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resume(error) => error.fmt(f),
            Self::Task(error) => error.fmt(f),
            Self::Identity(error) => error.fmt(f),
            Self::Closed => f.write_str("machine Task restart is closed; retain its unfinished records"),
        }
    }
}
impl std::error::Error for ClientCredentialsTaskResumeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resume(error) => Some(error),
            Self::Task(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::Closed => None,
        }
    }
}
impl From<TaskResumeError> for ClientCredentialsTaskResumeError {
    fn from(error: TaskResumeError) -> Self { Self::Resume(error) }
}
impl From<ClientCredentialsTasksError> for ClientCredentialsTaskResumeError {
    fn from(error: ClientCredentialsTasksError) -> Self { Self::Task(error) }
}
impl From<ClientCredentialsError> for ClientCredentialsTaskResumeError {
    fn from(error: ClientCredentialsError) -> Self { Self::Task(error.into()) }
}
impl From<ClientCredentialsTaskWatchError> for ClientCredentialsTaskResumeError {
    fn from(error: ClientCredentialsTaskWatchError) -> Self { Self::Identity(error) }
}

impl ClientCredentialsTasksClient {
    /// Read one restored checkpoint through this CURRENT machine registration.
    /// The host must associate the supplied owner/auth/profile binding with this
    /// client independently of the saved record. Wrong binding, resource and
    /// expired controls fail before credential acquisition or network contact.
    ///
    /// The existing request path negotiates both extensions with the exact token
    /// used for tasks/get. Its normal credential acquisition is read authority
    /// only: no input journal, old token, mutation, watch or retry is installed.
    /// Retention, client limits and caller cancellation bound the entire read.
    pub async fn reconcile_task_resume(
        &self, cx: &Cx, current: &TaskResumeBinding, record: &TaskResumeRecord,
        discovery_id: RequestId, request_id: RequestId,
    ) -> Result<ClientCredentialsTaskResumeReconciliation, ClientCredentialsTaskResumeError> {
        Box::pin(self.reconcile_task_resume_with_cancellation(cx, &McpRequestCancellation::new(),
            current, record, discovery_id, request_id)).await
    }

    /// Drop/cancellation releases the owned response; storage is never changed.
    /// Terminal handling and checkpoint removal remain explicit host decisions.
    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_task_resume_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        current: &TaskResumeBinding, record: &TaskResumeRecord,
        discovery_id: RequestId, request_id: RequestId,
    ) -> Result<ClientCredentialsTaskResumeReconciliation, ClientCredentialsTaskResumeError> {
        let call_deadline = discovery_deadline(cx, self.limits.timeout.min(self.client.inner.timeout))
            .map_err(ClientCredentialsError::from)?;
        check_run(self, cx, cancellation, call_deadline)?;
        let retention_deadline = resume_read_deadline(cx, current, record, self.client.resource().as_str())?;
        let deadline = call_deadline.min(retention_deadline);
        let observed = Box::pin(active(cx, deadline, &self.client.inner.closed, cancellation, None, async {
            Ok(async {
                let mut call = self.request_with_cancellation(cx, cancellation, discovery_id, request_id,
                    ManagedTaskRequest::Get(record.task_id().clone())).await?;
                let Some(ManagedTaskEvent::Snapshot(snapshot)) = call.next_event(cx).await? else {
                    return Err(ClientCredentialsTasksError::from(ManagedTasksError::InvalidResponse));
                };
                Ok::<_, ClientCredentialsTasksError>(snapshot.task)
            }.await)
        })).await;
        check_run(self, cx, cancellation, call_deadline)?;
        if cx.now() >= retention_deadline { return Err(TaskResumeError::Unavailable.into()); }
        record.admit(cx, current)?;
        let task = match observed {
            Ok(Ok(task)) => task,
            Ok(Err(error)) => return Err(classify_unavailable(error)),
            Err(error) => return Err(classify_unavailable(error.into())),
        };
        // This is the SAME complete identity/time/status/retention comparator
        // as managed reconciliation and protected-store conditional writes.
        let change = TaskResumeChange::from_snapshot(cx, current, record, &task)?;
        let result = match change.replacement() {
            Some(record) => ClientCredentialsTaskResumeReconciliation::Active {
                task: Box::new(task), record: record.clone(),
            },
            None => ClientCredentialsTaskResumeReconciliation::Terminal(Box::new(task)),
        };
        check_run(self, cx, cancellation, call_deadline)?;
        if cx.now() >= retention_deadline { return Err(TaskResumeError::Unavailable.into()); }
        record.admit(cx, current)?;
        Ok(result)
    }
}

fn classify_unavailable(error: ClientCredentialsTasksError) -> ClientCredentialsTaskResumeError {
    match error {
        ClientCredentialsTasksError::Protocol(ManagedTasksError::HttpStatus { status: 401 | 403 | 404 }) =>
            TaskResumeError::Unavailable.into(),
        error => error.into(),
    }
}

/// Staging uses the shared checkpoint planner's exact count, byte, duplicate
/// and owner checks. The separate machine timeout spans staging and every read,
/// including caller pauses; it never restarts after a successful item.
#[derive(Clone, Copy, Debug)]
pub struct ClientCredentialsTaskRestartPolicy {
    staging: TaskResumeRestartPolicy,
    timeout: Duration,
}
impl Default for ClientCredentialsTaskRestartPolicy {
    fn default() -> Self {
        Self { staging: TaskResumeRestartPolicy::default(), timeout: Duration::from_mins(15) }
    }
}
impl ClientCredentialsTaskRestartPolicy {
    pub fn new(maximum_records: usize, maximum_bytes: usize, timeout: Duration) -> Result<Self, TaskResumeError> {
        Ok(Self { staging: TaskResumeRestartPolicy::new(maximum_records, maximum_bytes, timeout)?, timeout })
    }
}

pub enum ClientCredentialsTaskRestartOutcome {
    Reconciled(ClientCredentialsTaskResumeReconciliation),
    Unavailable,
}

/// The exact staged version accompanies the fresh result. Application payloads
/// never enter a storage command, and receiving an item never removes a record.
pub struct ClientCredentialsTaskRestartItem {
    pub previous: TaskResumeRecord,
    pub outcome: ClientCredentialsTaskRestartOutcome,
}
impl ClientCredentialsTaskRestartItem {
    /// Prepare, but do not apply, an exact-version storage change. Handle or
    /// durably save a terminal result BEFORE choosing to remove its lookup hint.
    /// Unavailable is explicit local disposal, not proof of remote completion.
    /// Publicly assembled items are not authentication evidence.
    ///
    /// Apply with TaskResumeChange::apply in the host's blocking lane. A stale
    /// item cannot delete/overwrite newer controls. On uncertain storage failure
    /// reconcile the provider, never repeat Task creation or blindly replay.
    pub fn storage_change(&self, cx: &Cx, current: &TaskResumeBinding) -> Result<TaskResumeChange, TaskResumeError> {
        match &self.outcome {
            ClientCredentialsTaskRestartOutcome::Unavailable => TaskResumeChange::discard(cx, current, &self.previous),
            ClientCredentialsTaskRestartOutcome::Reconciled(ClientCredentialsTaskResumeReconciliation::Active { task, record }) => {
                let change = TaskResumeChange::from_snapshot(cx, current, &self.previous, task)?;
                if change.replacement() != Some(record) { return Err(TaskResumeError::ConflictingSnapshot); }
                Ok(change)
            }
            ClientCredentialsTaskRestartOutcome::Reconciled(ClientCredentialsTaskResumeReconciliation::Terminal(task)) => {
                let change = TaskResumeChange::from_snapshot(cx, current, &self.previous, task)?;
                if change.replacement().is_some() { return Err(TaskResumeError::InvalidRecord); }
                Ok(change)
            }
        }
    }
}

impl ClientCredentialsTasksClient {
    /// Stage already-decrypted checkpoint records before any credential or
    /// network work. Provider enumeration must run in the host's owned blocking
    /// lane: this iterator is synchronous and must return promptly. A protected
    /// store may first be enumerated with TaskResumeRestartPlan::load_store;
    /// pass plan.records().cloned() to start this separately budgeted run.
    ///
    /// Equal duplicates coalesce but charge the shared planner's count/bytes;
    /// conflicting versions reject the whole selection. Records are visited in
    /// opaque-key order. Expired records remain explicit Unavailable items.
    /// All input journals and mutations stay outside this read-only owner.
    pub fn prepare_task_restart(
        &self, cx: &Cx, current: TaskResumeBinding,
        records: impl IntoIterator<Item = TaskResumeRecord>, id_prefix: String,
        policy: ClientCredentialsTaskRestartPolicy,
    ) -> Result<ClientCredentialsTaskRestart, ClientCredentialsTaskResumeError> {
        self.prepare_task_restart_with_cancellation(cx, &McpRequestCancellation::new(),
            current, records, id_prefix, policy)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_task_restart_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, current: TaskResumeBinding,
        records: impl IntoIterator<Item = TaskResumeRecord>, id_prefix: String,
        policy: ClientCredentialsTaskRestartPolicy,
    ) -> Result<ClientCredentialsTaskRestart, ClientCredentialsTaskResumeError> {
        let deadline = discovery_deadline(cx, policy.timeout).map_err(ClientCredentialsError::from)?;
        check_run(self, cx, cancellation, deadline)?;
        if current.resource().as_str() != self.client.resource().as_str() {
            return Err(TaskResumeError::Unavailable.into());
        }
        let ids = WatchIds::new(id_prefix)?;
        let plan = TaskResumeRestartPlan::from_records(cx, &current, records, policy.staging)?;
        check_run(self, cx, cancellation, deadline)?;
        let records: VecDeque<_> = plan.records().cloned().collect();
        let finished = records.is_empty();
        Ok(ClientCredentialsTaskRestart {
            client: self.clone(), current, records, ids, cancellation: cancellation.clone(), deadline,
            pending_record: None, pending_outcome: None, ready: !finished, finished,
            attempted: 0, delivered: 0,
        })
    }
}

/// Sequential restart without a worker, mutation retry or implicit watch.
/// A failed or abandoned POLLED read permanently closes this owner. Its pending
/// record, any returned outcome, and unvisited records remain inspectable.
/// Unpolled futures do nothing. Completion is elected with the last delivery.
#[must_use = "drive restart reads or retain the pending and unvisited checkpoints"]
pub struct ClientCredentialsTaskRestart {
    client: ClientCredentialsTasksClient,
    current: TaskResumeBinding,
    records: VecDeque<TaskResumeRecord>,
    ids: WatchIds,
    cancellation: McpRequestCancellation,
    deadline: Time,
    pending_record: Option<TaskResumeRecord>,
    pending_outcome: Option<ClientCredentialsTaskRestartOutcome>,
    ready: bool,
    finished: bool,
    attempted: usize,
    delivered: usize,
}
impl fmt::Debug for ClientCredentialsTaskRestart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCredentialsTaskRestart").field("remaining", &self.remaining())
            .field("attempted", &self.attempted).field("delivered", &self.delivered)
            .field("ready", &self.ready).finish_non_exhaustive()
    }
}
impl ClientCredentialsTaskRestart {
    pub fn remaining(&self) -> usize { self.records.len() + usize::from(self.pending_record.is_some()) }
    /// Reconciliation calls begun, not successful POSTs. Locally expired records
    /// consume no call; failed credential acquisition can consume one call.
    pub fn attempted(&self) -> usize { self.attempted }
    pub fn delivered(&self) -> usize { self.delivered }
    pub fn pending_record(&self) -> Option<&TaskResumeRecord> { self.pending_record.as_ref() }
    pub fn pending_outcome(&self) -> Option<&ClientCredentialsTaskRestartOutcome> { self.pending_outcome.as_ref() }
    pub fn unvisited(&self) -> impl ExactSizeIterator<Item = &TaskResumeRecord> { self.records.iter() }
    pub fn close(&mut self) { self.ready = false; }
    pub fn take_pending(&mut self) -> Option<(TaskResumeRecord, Option<ClientCredentialsTaskRestartOutcome>)> {
        self.ready = false;
        self.pending_record.take().map(|record| (record, self.pending_outcome.take()))
    }

    pub async fn next_reconciled(&mut self, cx: &Cx)
        -> Result<Option<ClientCredentialsTaskRestartItem>, ClientCredentialsTaskResumeError>
    {
        if self.finished { return Ok(None); }
        if !self.ready { return Err(ClientCredentialsTaskResumeError::Closed); }
        self.ready = false;
        check_run(&self.client, cx, &self.cancellation, self.deadline)?;
        let Some(record) = self.records.pop_front() else { self.finished = true; return Ok(None); };
        self.pending_record = Some(record);
        let pending = self.pending_record.as_ref().ok_or(TaskResumeError::InvalidRecord)?;
        match pending.admit(cx, &self.current) {
            Err(TaskResumeError::Unavailable) => self.pending_outcome = Some(ClientCredentialsTaskRestartOutcome::Unavailable),
            Err(error) => return Err(error.into()),
            Ok(()) => {
                let (discovery_id, request_id) = self.ids.next_pair()?;
                self.attempted += 1;
                let client = self.client.clone();
                let cancellation = self.cancellation.clone();
                let current = &self.current;
                let outcome = &mut self.pending_outcome;
                Box::pin(active(cx, self.deadline, &client.client.inner.closed, &cancellation, None, async {
                    let observed = Box::pin(client.reconcile_task_resume_with_cancellation(cx, &cancellation,
                        current, pending, discovery_id, request_id)).await;
                    let observed = match observed {
                        Ok(value) => ClientCredentialsTaskRestartOutcome::Reconciled(value),
                        Err(ClientCredentialsTaskResumeError::Resume(TaskResumeError::Unavailable)) =>
                            ClientCredentialsTaskRestartOutcome::Unavailable,
                        Err(error) => return Ok(Err(error)),
                    };
                    // Retain an admitted result before the outer guard checks
                    // lifetime again. Cancellation cannot erase this evidence.
                    *outcome = Some(observed);
                    Ok(Ok(()))
                })).await??;
            }
        }
        check_run(&self.client, cx, &self.cancellation, self.deadline)?;
        let previous = self.pending_record.take().ok_or(TaskResumeError::InvalidRecord)?;
        let outcome = self.pending_outcome.take().ok_or(TaskResumeError::InvalidRecord)?;
        self.delivered += 1;
        self.finished = self.records.is_empty();
        self.ready = !self.finished;
        Ok(Some(ClientCredentialsTaskRestartItem { previous, outcome }))
    }
}

fn check_run(client: &ClientCredentialsTasksClient, cx: &Cx,
    cancellation: &McpRequestCancellation, deadline: Time,
) -> Result<(), ClientCredentialsError> {
    if client.client.inner.closed.is_cancel_requested() { return Err(ClientCredentialsError::Closed); }
    if cancellation.is_cancel_requested() { return Err(OAuthDiscoveryError::Cancelled.into()); }
    check_context(cx, cx.budget().deadline.map_or(deadline, |parent| parent.min(deadline)))
        .map_err(ClientCredentialsError::from)
}

/// Persistence-gated continued observation after explicit checkpoint recovery.
pub mod lifecycle {
    use std::future::Future;

    #[allow(
        clippy::wildcard_imports,
        reason = "the nested #[cfg(test)] module reaches this file's own imports (Duration, \
                  OAuthDiscoveryError) through this glob; a list computed from the non-test \
                  unit omits them and would break the lib-test build"
    )]
    use super::*;
    use super::super::{
        ClientCredentialsSnapshot, ClientCredentialsTaskWatch, ClientCredentialsTaskWatchPolicy,
        ManagedTaskSnapshot, check_watch, copy_binding,
    };
    use super::super::cancellation::{
        CancellableClientCredentialsTaskWatchError, ClientCredentialsTaskCancelHandle,
    };
    use super::super::recovery::{
        ClientCredentialsTaskRecoveryError, ClientCredentialsTaskRecoveryPolicy, RecoveryState,
    };
    pub use crate::http_auth::managed::tasks::watch::checkpoint::resume::client::lifecycle::TaskResumePersistenceState;

    /// Provider errors are retained as typed sources, never formatted implicitly.
    /// Failure after a save starts is not evidence that storage stayed unchanged.
    pub enum PersistedClientCredentialsTaskWatchError<E> {
        Resume(TaskResumeError),
        Watch(ClientCredentialsTaskWatchError),
        Recovery(ClientCredentialsTaskRecoveryError),
        Authentication(ClientCredentialsError),
        Persistence(E),
        CancellationRequested,
        TerminalAcknowledgementRequired,
        NoTerminal,
        Closed,
    }
    impl<E> fmt::Debug for PersistedClientCredentialsTaskWatchError<E> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Resume(error) => f.debug_tuple("Resume").field(error).finish(),
                Self::Watch(error) => f.debug_tuple("Watch").field(error).finish(),
                Self::Recovery(error) => f.debug_tuple("Recovery").field(error).finish(),
                Self::Authentication(error) => f.debug_tuple("Authentication").field(error).finish(),
                Self::Persistence(_) => f.write_str("Persistence(<host error>)"),
                Self::CancellationRequested => f.write_str("CancellationRequested"),
                Self::TerminalAcknowledgementRequired => f.write_str("TerminalAcknowledgementRequired"),
                Self::NoTerminal => f.write_str("NoTerminal"),
                Self::Closed => f.write_str("Closed"),
            }
        }
    }
    impl<E> fmt::Display for PersistedClientCredentialsTaskWatchError<E> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Resume(error) => error.fmt(f),
                Self::Watch(error) => error.fmt(f),
                Self::Recovery(error) => error.fmt(f),
                Self::Authentication(error) => error.fmt(f),
                Self::Persistence(_) => f.write_str("machine Task checkpoint persistence failed"),
                Self::CancellationRequested => f.write_str("machine Task cancellation acknowledged; checkpoint retained"),
                Self::TerminalAcknowledgementRequired => f.write_str("acknowledge handling the terminal Task before checkpoint cleanup"),
                Self::NoTerminal => f.write_str("no terminal Task has been delivered"),
                Self::Closed => f.write_str("persisted machine Task watch is closed"),
            }
        }
    }
    impl<E: std::error::Error + 'static> std::error::Error for PersistedClientCredentialsTaskWatchError<E> {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Resume(error) => Some(error), Self::Watch(error) => Some(error),
                Self::Recovery(error) => Some(error), Self::Authentication(error) => Some(error),
                Self::Persistence(error) => Some(error),
                Self::CancellationRequested | Self::TerminalAcknowledgementRequired
                | Self::NoTerminal | Self::Closed => None,
            }
        }
    }
    impl<E> From<TaskResumeError> for PersistedClientCredentialsTaskWatchError<E> {
        fn from(error: TaskResumeError) -> Self { Self::Resume(error) }
    }
    impl<E> From<ClientCredentialsError> for PersistedClientCredentialsTaskWatchError<E> {
        fn from(error: ClientCredentialsError) -> Self { Self::Authentication(error) }
    }
    impl<E> From<ClientCredentialsTaskWatchError> for PersistedClientCredentialsTaskWatchError<E> {
        fn from(error: ClientCredentialsTaskWatchError) -> Self { Self::Watch(error) }
    }
    impl<E> From<ClientCredentialsTaskRecoveryError> for PersistedClientCredentialsTaskWatchError<E> {
        fn from(error: ClientCredentialsTaskRecoveryError) -> Self {
            match error { ClientCredentialsTaskRecoveryError::Watch(error) => Self::Watch(error),
                error => Self::Recovery(error) }
        }
    }
    impl<E> From<CancellableClientCredentialsTaskWatchError> for PersistedClientCredentialsTaskWatchError<E> {
        fn from(error: CancellableClientCredentialsTaskWatchError) -> Self {
            match error {
                CancellableClientCredentialsTaskWatchError::CancellationRequested => Self::CancellationRequested,
                CancellableClientCredentialsTaskWatchError::Closed => Self::Closed,
                CancellableClientCredentialsTaskWatchError::Watch(error) => Self::Watch(error),
                CancellableClientCredentialsTaskWatchError::Recovery(error) => error.into(),
            }
        }
    }

    /// Retained custody of a fresh snapshot and its separate payload-free change.
    /// Acknowledged means the callback returned success, not that publication won
    /// a later cancellation/expiry race. No state here authorizes a write retry.
    pub struct PendingClientCredentialsTaskResumeSnapshot {
        snapshot: ManagedTaskSnapshot,
        change: TaskResumeChange,
        persistence: TaskResumePersistenceState,
    }
    impl PendingClientCredentialsTaskResumeSnapshot {
        pub fn snapshot(&self) -> &ManagedTaskSnapshot { &self.snapshot }
        pub fn change(&self) -> &TaskResumeChange { &self.change }
        pub fn persistence(&self) -> TaskResumePersistenceState { self.persistence }
        pub fn into_parts(self) -> (ManagedTaskSnapshot, TaskResumeChange, TaskResumePersistenceState) {
            (self.snapshot, self.change, self.persistence)
        }
    }
    impl fmt::Debug for PendingClientCredentialsTaskResumeSnapshot {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PendingClientCredentialsTaskResumeSnapshot")
                .field("persistence", &self.persistence).finish_non_exhaustive()
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Phase { Observing, TerminalPending, Closed, Finished }

    /// One caller-polled, persistence-gated machine Task observation.
    ///
    /// Active snapshots are delivered only after an acknowledged conditional
    /// save. A terminal is delivered BEFORE cleanup; explicitly acknowledge it
    /// only after handling or durably recording its payload. Drop never deletes
    /// a checkpoint. This permits terminal redelivery after a crash, not an
    /// exactly-once or crash-durable result-inbox guarantee.
    ///
    /// Failed or abandoned polled reads permanently close this owner. Pending
    /// snapshots, storage dispositions and reconnection counts stay inspectable.
    /// No implicit creation, input execution, credential renewal, storage retry,
    /// runtime or background worker is installed.
    #[must_use = "retain checkpoint custody until snapshots and terminal handling are acknowledged"]
    pub struct PersistedClientCredentialsTaskWatch<P> {
        client: ClientCredentialsTasksClient,
        current: TaskResumeBinding,
        record: TaskResumeRecord,
        cancellation: McpRequestCancellation,
        deadline: Time,
        binding: ClientCredentialsSnapshot,
        watch: Option<ClientCredentialsTaskWatch>,
        recovery: RecoveryState,
        remote_cancel: ClientCredentialsTaskCancelHandle,
        persist: P,
        pending: Option<PendingClientCredentialsTaskResumeSnapshot>,
        terminal_cleanup: Option<TaskResumeChange>,
        cleanup_state: TaskResumePersistenceState,
        phase: Phase,
    }

    impl ClientCredentialsTasksClient {
        /// Resume an already-persisted Task and checkpoint each fresh active
        /// snapshot before delivering it. Admission negotiates both extensions
        /// and requires the complete listen ACK, but invokes no storage callback.
        ///
        /// The host independently verifies that current identifies this machine
        /// registration. The checkpoint cannot choose an account or resource.
        /// persist must compare the entire expected record and acknowledge only
        /// a durable commit. TaskResumeChange::apply supplies that operation for
        /// the existing Linux protected store; run blocking I/O in the host's
        /// owned blocking lane and retain/join its job, never detach a writer.
        ///
        /// Recovery is bounded by the supplied policy and original retention,
        /// record/snapshot budgets and deadline. Observation, explicit cancellation
        /// and persistence all retain the opening credential; expiry/revocation
        /// fails closed, not by acquiring new mutation authority.
        #[allow(clippy::too_many_arguments)]
        pub async fn resume_task_watch_persisted<P, F, E>(
            &self, cx: &Cx, current: TaskResumeBinding, record: TaskResumeRecord,
            id_prefix: String, policy: ClientCredentialsTaskWatchPolicy,
            recovery: ClientCredentialsTaskRecoveryPolicy, persist: P,
        ) -> Result<PersistedClientCredentialsTaskWatch<P>, PersistedClientCredentialsTaskWatchError<E>>
        where P: FnMut(TaskResumeChange) -> F, F: Future<Output = Result<(), E>>,
        {
            self.resume_task_watch_persisted_with_cancellation(cx, &McpRequestCancellation::new(),
                current, record, id_prefix, policy, recovery, persist).await
        }

        /// Local cancellation releases only this observation. Explicit remote
        /// cancellation uses the returned one-attempt handle; a valid ACK stops
        /// pending reads/saves without deleting the checkpoint or claiming rollback.
        #[allow(clippy::too_many_arguments)]
        pub async fn resume_task_watch_persisted_with_cancellation<P, F, E>(
            &self, cx: &Cx, cancellation: &McpRequestCancellation,
            current: TaskResumeBinding, record: TaskResumeRecord, id_prefix: String,
            policy: ClientCredentialsTaskWatchPolicy, recovery: ClientCredentialsTaskRecoveryPolicy,
            persist: P,
        ) -> Result<PersistedClientCredentialsTaskWatch<P>, PersistedClientCredentialsTaskWatchError<E>>
        where P: FnMut(TaskResumeChange) -> F, F: Future<Output = Result<(), E>>,
        {
            let deadline = discovery_deadline(cx, policy.timeout).map_err(ClientCredentialsError::from)?;
            check_run(self, cx, cancellation, deadline)?;
            let deadline = deadline.min(resume_read_deadline(cx, &current, &record, self.client.resource().as_str())?);
            let connection_policy = recovery.connection_policy(policy)?;
            let mut remote_cancel = ClientCredentialsTaskCancelHandle::for_observation(
                self, record.task_id().clone(), &id_prefix, cancellation, deadline,
            )?;
            let mut watch = Box::pin(active(cx, deadline, &self.client.inner.closed, cancellation, None, async {
                Ok(self.watch_tasks_with_cancellation(cx, cancellation, vec![record.task_id().clone()],
                    id_prefix, connection_policy).await)
            })).await??;
            watch.deadline = watch.deadline.min(deadline);
            let binding = copy_binding(&watch.binding);
            remote_cancel.pin_binding(copy_binding(&binding), watch.deadline)?;
            let recovery = RecoveryState::new(&watch, connection_policy, recovery);
            let result = PersistedClientCredentialsTaskWatch {
                client: self.clone(), current, record, cancellation: cancellation.clone(),
                deadline: watch.deadline, binding, watch: Some(watch), recovery, remote_cancel,
                persist, pending: None, terminal_cleanup: None,
                cleanup_state: TaskResumePersistenceState::NotAttempted, phase: Phase::Observing,
            };
            result.check::<E>(cx)?;
            Ok(result)
        }
    }

    impl<P> PersistedClientCredentialsTaskWatch<P> {
        /// The last delivered active version, not a claim about current storage.
        /// A pending acknowledged save may have superseded it without publication.
        pub fn last_published_record(&self) -> &TaskResumeRecord { &self.record }
        pub fn pending(&self) -> Option<&PendingClientCredentialsTaskResumeSnapshot> { self.pending.as_ref() }
        /// End observation before exporting pending custody; never retry its save.
        pub fn take_pending(&mut self) -> Option<PendingClientCredentialsTaskResumeSnapshot> {
            self.close(); self.pending.take()
        }
        pub fn terminal_cleanup(&self) -> Option<&TaskResumeChange> { self.terminal_cleanup.as_ref() }
        pub fn cleanup_state(&self) -> TaskResumePersistenceState { self.cleanup_state }
        pub fn reconnection_attempts(&self) -> usize { self.recovery.reconnection_attempts() }
        pub fn cancel_handle(&self) -> ClientCredentialsTaskCancelHandle { self.remote_cancel.clone() }
        pub fn close(&mut self) {
            self.remote_cancel.close_observation();
            self.watch = None;
            if self.phase != Phase::Finished { self.phase = Phase::Closed; }
        }

        fn check<E>(&self, cx: &Cx) -> Result<(), PersistedClientCredentialsTaskWatchError<E>> {
            if self.remote_cancel.cancellation_requested() {
                return Err(PersistedClientCredentialsTaskWatchError::CancellationRequested);
            }
            check_watch(cx, self.deadline, &self.client.client.inner.closed, &self.cancellation, &self.binding)?;
            self.record.admit(cx, &self.current)?;
            Ok(())
        }

        pub async fn next_snapshot<F, E>(&mut self, cx: &Cx)
            -> Result<Option<ManagedTaskSnapshot>, PersistedClientCredentialsTaskWatchError<E>>
        where P: FnMut(TaskResumeChange) -> F, F: Future<Output = Result<(), E>>,
        {
            if self.phase == Phase::Finished { return Ok(None); }
            if self.remote_cancel.cancellation_requested() {
                self.close(); return Err(PersistedClientCredentialsTaskWatchError::CancellationRequested);
            }
            match self.phase {
                Phase::Closed => return Err(PersistedClientCredentialsTaskWatchError::Closed),
                Phase::TerminalPending => return Err(PersistedClientCredentialsTaskWatchError::TerminalAcknowledgementRequired),
                _ => {},
            }
            // Retire admission BEFORE suspension. Errors, panic and future drop
            // cannot make a partially read stream or a pending write reusable.
            let mut watch = self.watch.take().ok_or(PersistedClientCredentialsTaskWatchError::Closed)?;
            self.phase = Phase::Closed;
            let remote = self.remote_cancel.clone();
            let mut lease = remote.read_lease();
            self.check::<E>(cx)?;
            let client = self.client.clone();
            let cancellation = self.cancellation.clone();
            let deadline = self.deadline;
            let binding = &self.binding;
            let recovery = &mut self.recovery;
            let read = Box::pin(active(cx, deadline, &client.client.inner.closed, &cancellation, Some(binding), async {
                Ok(Box::pin(recovery.next_snapshot(cx, &mut watch, Some(binding))).await)
            }));
            let snapshot = remote.until_acknowledged(read).await???
                .ok_or(TaskResumeError::InvalidRecord)?;
            let change = TaskResumeChange::from_snapshot(cx, &self.current, &self.record, &snapshot.task)?;
            if change.replacement().is_none() {
                self.check::<E>(cx)?;
                // Only a fully reconciled terminal may win over remote cancel.
                // No storage command runs until explicit result acknowledgement.
                remote.select_terminal()?;
                self.terminal_cleanup = Some(change);
                self.phase = Phase::TerminalPending;
                return Ok(Some(snapshot));
            }
            self.pending = Some(PendingClientCredentialsTaskResumeSnapshot {
                snapshot, change, persistence: TaskResumePersistenceState::NotAttempted,
            });
            self.check::<E>(cx)?;
            let pending = self.pending.as_mut().ok_or(TaskResumeError::InvalidRecord)?;
            let persist = &mut self.persist;
            let writing = Box::pin(active(cx, deadline, &client.client.inner.closed, &cancellation, Some(&self.binding), async {
                Ok(persist_change(&mut pending.persistence, persist, pending.change.clone()).await)
            }));
            remote.until_acknowledged(writing).await??
                .map_err(PersistedClientCredentialsTaskWatchError::Persistence)?;
            self.check::<E>(cx)?;
            let next = self.pending.as_ref().and_then(|pending| pending.change.replacement())
                .ok_or(TaskResumeError::InvalidRecord)?.clone();
            let pending = self.pending.take().ok_or(TaskResumeError::InvalidRecord)?;
            self.record = next;
            self.watch = Some(watch);
            self.phase = Phase::Observing;
            lease.disarm();
            Ok(Some(pending.snapshot))
        }

        /// Acknowledge handling or separately persisting the delivered terminal
        /// result, then conditionally remove its exact checkpoint. Exactly one
        /// cleanup attempt is allowed; errors/drop retain its disposition and
        /// command for explicit provider reconciliation, not an automatic retry.
        /// Original credential, retention, cancellation and deadline still apply.
        pub async fn acknowledge_terminal<F, E>(&mut self, cx: &Cx)
            -> Result<(), PersistedClientCredentialsTaskWatchError<E>>
        where P: FnMut(TaskResumeChange) -> F, F: Future<Output = Result<(), E>>,
        {
            match self.phase {
                Phase::Finished => return Ok(()),
                Phase::Closed => return Err(PersistedClientCredentialsTaskWatchError::Closed),
                Phase::Observing => return Err(PersistedClientCredentialsTaskWatchError::NoTerminal),
                Phase::TerminalPending => {},
            }
            let change = self.terminal_cleanup.clone().ok_or(TaskResumeError::InvalidRecord)?;
            self.phase = Phase::Closed;
            self.check::<E>(cx)?;
            let client = self.client.clone();
            let cancellation = self.cancellation.clone();
            let persist = &mut self.persist;
            let state = &mut self.cleanup_state;
            Box::pin(active(cx, self.deadline, &client.client.inner.closed, &cancellation, Some(&self.binding), async {
                Ok(persist_change(state, persist, change).await)
            })).await?.map_err(PersistedClientCredentialsTaskWatchError::Persistence)?;
            self.phase = Phase::Finished;
            Ok(())
        }
    }
    impl<P> Drop for PersistedClientCredentialsTaskWatch<P> {
        fn drop(&mut self) { self.remote_cancel.close_observation(); }
    }
    impl<P> fmt::Debug for PersistedClientCredentialsTaskWatch<P> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PersistedClientCredentialsTaskWatch").field("phase", &self.phase)
                .field("cleanup_state", &self.cleanup_state)
                .field("reconnection_attempts", &self.reconnection_attempts()).finish_non_exhaustive()
        }
    }

    async fn persist_change<P, F, E>(state: &mut TaskResumePersistenceState, persist: &mut P, change: TaskResumeChange)
        -> Result<(), E>
    where P: FnMut(TaskResumeChange) -> F, F: Future<Output = Result<(), E>>,
    {
        // Mark before calling host code (which can panic), and retain the receipt
        // before returning to lifetime guards. They can still withhold delivery.
        *state = TaskResumePersistenceState::Unconfirmed;
        let result = persist(change).await;
        if result.is_ok() { *state = TaskResumePersistenceState::Acknowledged; }
        result
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use super::super::super::tests::{consumer, runtime};
        use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
        use serde_json::json;
        use std::cell::Cell;
        use std::future::ready;
        use std::task::{Context, Poll, Waker};

        fn owner(client: &ClientCredentialsTasksClient, subject: &str) -> TaskResumeBinding {
            let resource = client.client.resource();
            let facts = PartitionDescriptor::from_verified_facts("fixture", 1, "https://issuer.example",
                resource.as_str(), "tenant", subject, "client", 1, 1, &[b"bound-resource".as_slice()]).unwrap();
            TaskResumeBinding::from_verified_owner(resource.clone(), "persisted-machine",
                &DurableOwnerKey::derive(&facts, 1).unwrap(), [1; 32], [2; 32], [3; 32]).unwrap()
        }
        fn saved(cx: &Cx, binding: &TaskResumeBinding) -> TaskResumeRecord {
            let task = serde_json::from_value(json!({"taskId":"private-task", "status":"working",
                "createdAt":"2020-01-01T00:00:00Z", "lastUpdatedAt":"2020-01-01T00:00:01Z", "ttlMs":null})).unwrap();
            TaskResumeRecord::capture(cx, binding, &task, Duration::from_secs(3600)).unwrap()
        }
        fn change(cx: &Cx) -> TaskResumeChange {
            let binding = owner(&consumer(), "one");
            TaskResumeChange::discard(cx, &binding, &saved(cx, &binding)).unwrap()
        }

        #[test]
        fn persisted_machine_admission_refuses_before_grant_or_provider_entry() {
            runtime().block_on(async {
                let cx = Cx::current().unwrap();
                let client = consumer();
                let current = owner(&client, "one");
                let record = saved(&cx, &current);
                let before = record.encode().unwrap();
                let calls = Cell::new(0);
                for dimension in 0..5 {
                    let binding = if dimension == 0 { owner(&client, "other") } else { current.clone() };
                    let cancellation = McpRequestCancellation::new();
                    if dimension == 2 { cancellation.cancel(); }
                    let prefix = if dimension == 1 { "invalid:prefix" } else { "persisted" };
                    let policy = ClientCredentialsTaskWatchPolicy::new(Duration::from_secs(10), 4,
                        if dimension == 3 { 2 } else { 32 }).unwrap();
                    let mut record = record.clone();
                    if dimension == 4 {
                        let mut encoded = record.encode().unwrap();
                        let end = encoded.len();
                        encoded[end - 16..].copy_from_slice(&1_577_836_802_000_000_000_i128.to_be_bytes());
                        record = TaskResumeRecord::decode(&encoded).unwrap();
                    }
                    let result = Box::pin(client.resume_task_watch_persisted_with_cancellation(&cx, &cancellation,
                        binding, record, prefix.to_owned(), policy, ClientCredentialsTaskRecoveryPolicy::default(),
                        |_| { calls.set(calls.get() + 1); ready(Ok::<(), ()>(())) })).await;
                    match (dimension, result) {
                        (0 | 4, Err(PersistedClientCredentialsTaskWatchError::Resume(TaskResumeError::Unavailable))) => {},
                        (1, Err(PersistedClientCredentialsTaskWatchError::Watch(ClientCredentialsTaskWatchError::InvalidIdPrefix))) => {},
                        (2, Err(PersistedClientCredentialsTaskWatchError::Authentication(
                            ClientCredentialsError::Discovery(OAuthDiscoveryError::Cancelled)))) => {},
                        (3, Err(PersistedClientCredentialsTaskWatchError::Recovery(ClientCredentialsTaskRecoveryError::InvalidPolicy))) => {},
                        (_, value) => panic!("unexpected preflight outcome: {value:?}"),
                    }
                }
                assert_eq!(calls.get(), 0);
                assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
                assert_eq!(record.encode().unwrap(), before);
            });
        }

        #[test]
        fn persisted_machine_save_receipt_distinguishes_unpolled_failed_and_acknowledged() {
            let cx = Cx::for_testing();
            for fail in [false, true] {
                let mut state = TaskResumePersistenceState::NotAttempted;
                let calls = Cell::new(0);
                let mut provider = |_| { calls.set(calls.get() + 1); ready(if fail { Err(7) } else { Ok(()) }) };
                drop(persist_change(&mut state, &mut provider, change(&cx)));
                assert_eq!(calls.get(), 0);
                assert_eq!(state, TaskResumePersistenceState::NotAttempted);
                let mut future = Box::pin(persist_change(&mut state, &mut provider, change(&cx)));
                assert_eq!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(if fail { Err(7) } else { Ok(()) }));
                drop(future);
                assert_eq!(calls.get(), 1);
                assert_eq!(state, if fail { TaskResumePersistenceState::Unconfirmed } else { TaskResumePersistenceState::Acknowledged });
            }
        }

        #[test]
        fn persisted_machine_abandoned_save_releases_future_and_keeps_uncertainty() {
            struct Probe<'a>(&'a Cell<bool>);
            impl Drop for Probe<'_> { fn drop(&mut self) { self.0.set(true); } }
            let cx = Cx::for_testing();
            let dropped = Cell::new(false);
            let mut state = TaskResumePersistenceState::NotAttempted;
            let mut provider = |_| {
                let probe = Probe(&dropped);
                async move { let _probe = probe; std::future::pending::<Result<(), ()>>().await }
            };
            let mut future = Box::pin(persist_change(&mut state, &mut provider, change(&cx)));
            assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            drop(future);
            assert!(dropped.get());
            assert_eq!(state, TaskResumePersistenceState::Unconfirmed);
        }

        #[test]
        fn persisted_machine_ready_save_ack_survives_outer_cancellation() {
            runtime().block_on(async {
                let cx = Cx::current().unwrap();
                let cancellation = McpRequestCancellation::new();
                let owner = McpRequestCancellation::new();
                let mut state = TaskResumePersistenceState::NotAttempted;
                let mut provider = |_| { cancellation.cancel(); ready(Ok::<(), ()>(())) };
                let result = active(&cx, cx.now().saturating_add_nanos(1_000_000_000), &owner, &cancellation, None,
                    async { Ok(persist_change(&mut state, &mut provider, change(&cx)).await) }).await;
                assert!(result.is_err());
                assert_eq!(state, TaskResumePersistenceState::Acknowledged);
                assert!(!owner.is_cancel_requested());
            });
        }

        #[test]
        fn persisted_machine_provider_diagnostics_are_not_implicitly_formatted() {
            struct Secret;
            impl fmt::Debug for Secret { fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result { panic!("private provider data"); } }
            let error = PersistedClientCredentialsTaskWatchError::Persistence(Secret);
            assert_eq!(format!("{error:?}"), "Persistence(<host error>)");
            assert_eq!(format!("{error}"), "machine Task checkpoint persistence failed");
        }
    }
}

#[cfg(test)]
mod tests;
