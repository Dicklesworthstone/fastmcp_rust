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
        self.reconcile_task_resume_with_cancellation(cx, &McpRequestCancellation::new(),
            current, record, discovery_id, request_id).await
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
        let observed = active(cx, deadline, &self.client.inner.closed, cancellation, None, async {
            Ok(async {
                let mut call = self.request_with_cancellation(cx, cancellation, discovery_id, request_id,
                    ManagedTaskRequest::Get(record.task_id().clone())).await?;
                let Some(ManagedTaskEvent::Snapshot(snapshot)) = call.next_event(cx).await? else {
                    return Err(ClientCredentialsTasksError::from(ManagedTasksError::InvalidResponse));
                };
                Ok::<_, ClientCredentialsTasksError>(snapshot.task)
            }.await)
        }).await;
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
        Self { staging: TaskResumeRestartPolicy::default(), timeout: Duration::from_secs(900) }
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
                active(cx, self.deadline, &client.client.inner.closed, &cancellation, None, async {
                    let observed = client.reconcile_task_resume_with_cancellation(cx, &cancellation,
                        current, pending, discovery_id, request_id).await;
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
                }).await??;
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

#[cfg(test)]
mod tests;
