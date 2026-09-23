//! Authoritative, read-only reconciliation of protected Task checkpoints.
//!
//! Stored state never becomes a live snapshot. The selected managed login
//! performs fresh Tasks discovery and one bounded tasks/get at its configured
//! resource. Successful reconciliation returns current state, not permission to
//! replay the creating call or any old input answer. The caller explicitly
//! persists an updated control record or removes the terminal/unavailable one.

/// Initial insert-only checkpoints for newly accepted Tasks.
pub mod creation;
/// Persistence-gated Task observation and explicit terminal acknowledgement.
pub mod lifecycle;
/// Bounded restart enumeration and sequential authenticated reconciliation.
pub mod restart;

use std::fmt;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::tasks_extension::{Task, TaskStatus};

use crate::http_auth::managed::{OAuthSessionError, deadline_after};
use crate::http_auth::managed::tasks::{
    ManagedTaskEvent, ManagedTaskRequest, ManagedTaskRequestIds, ManagedTasksClient,
    ManagedTasksError,
};
use super::{
    MAX_RETENTION, TaskResumeBinding, TaskResumeError, TaskResumeRecord,
    timestamp_nanos, wall_now,
};
use super::super::ManagedTaskWatchCheckpoint;

/// A fresh remote observation, deliberately neither Clone nor serializable.
/// A terminal Task may be failed/cancelled or contain a tool-level error.
#[allow(
    clippy::large_enum_variant,
    reason = "one value per reconciliation, returned by value and held at most in a restart's \
              single pending slot (MAX_RESTART_RECORDS = 128 bounds the stream); boxing `record` \
              would add a heap allocation per Active result and change a public field that \
              callers destructure"
)]
pub enum TaskResumeReconciliation {
    Active {
        /// Current application state; NEVER passed to the checkpoint store.
        task: Box<Task>,
        /// Updated controls retaining the original checkpoint expiry.
        record: TaskResumeRecord,
        /// Selection for the existing explicit resume_task_watch APIs. Starting
        /// a watch is a separate host decision with its own finite budget and
        /// fresh authentication; no old input ledger is revived.
        selection: ManagedTaskWatchCheckpoint,
    },
    /// Remove the old checkpoint explicitly. The result is caller-owned and is
    /// not written into a resume record or reported as successful execution.
    Terminal(Box<Task>),
}

#[derive(Debug)]
pub enum TaskResumeReconciliationError {
    Resume(TaskResumeError),
    Task(ManagedTasksError),
}
impl fmt::Display for TaskResumeReconciliationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::Resume(error) => error.fmt(f), Self::Task(error) => error.fmt(f) }
    }
}
impl std::error::Error for TaskResumeReconciliationError {}
impl From<TaskResumeError> for TaskResumeReconciliationError {
    fn from(error: TaskResumeError) -> Self { Self::Resume(error) }
}
impl From<ManagedTasksError> for TaskResumeReconciliationError {
    fn from(error: ManagedTasksError) -> Self { Self::Task(error) }
}

impl ManagedTasksClient {
    /// Reconciles one restored control record using THIS selected managed login.
    /// The host must associate current verified owner/profile facts with that
    /// login; a key obtained from the record itself is not current authority.
    /// Wrong binding/resource and expired records are refused before renewal,
    /// discovery or network contact. HTTP 401/403/404 share Unavailable with
    /// absent local records; other typed failures are not silently retried.
    ///
    /// All I/O uses the existing Tasks validators and native transport. The
    /// deadline is the minimum of the client/caller budget and the record's
    /// remaining retention, anchored monotonically at admission. Moving the
    /// wall clock backwards cannot extend this operation after it starts.
    /// Clock integrity across process restart remains a host responsibility.
    ///
    /// This method neither creates/updates/cancels a Task nor invokes input
    /// callbacks. It does not perform blocking storage on the async executor.
    /// A returned Active record must be persisted explicitly in the store's
    /// caller-owned blocking lane; a failed persistence does not erase `task`.
    pub async fn reconcile_task_resume(
        &self,
        cx: &Cx,
        current: &TaskResumeBinding,
        record: &TaskResumeRecord,
        ids: ManagedTaskRequestIds,
    ) -> Result<TaskResumeReconciliation, TaskResumeReconciliationError> {
        Box::pin(self.reconcile_task_resume_with_cancellation(
            cx, &McpRequestCancellation::new(), current, record, ids,
        )).await
    }

    /// Dropping/cancelling the future closes only its owned observation. No
    /// mutation or resumed watch is installed, and the saved record is unchanged.
    pub async fn reconcile_task_resume_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        current: &TaskResumeBinding,
        record: &TaskResumeRecord,
        ids: ManagedTaskRequestIds,
    ) -> Result<TaskResumeReconciliation, TaskResumeReconciliationError> {
        self.session.check(cx, cancellation).map_err(ManagedTasksError::from)?;
        let retention_deadline = resume_read_deadline(cx, current, record, self.session.resource().as_str())?;
        let deadline = retention_deadline.min(deadline_after(cx, self.limits.timeout).map_err(ManagedTasksError::from)?);
        let observed = Box::pin(self.session.await_active(cx, cancellation, deadline, None, async {
            Ok(async {
                let mut call = self.request_with_cancellation(cx, cancellation, ids,
                    ManagedTaskRequest::Get(record.task_id.clone())).await?;
                let Some(ManagedTaskEvent::Snapshot(snapshot)) = call.next_event(cx).await? else {
                    return Err(ManagedTasksError::InvalidResponse);
                };
                Ok::<_, ManagedTasksError>(snapshot.task)
            }.await)
        })).await;
        self.session.check(cx, cancellation).map_err(ManagedTasksError::from)?;
        if cx.now() >= retention_deadline { return Err(TaskResumeError::Unavailable.into()); }
        record.admit(cx, current)?;
        let task = match observed {
            Ok(Ok(task)) => task,
            Ok(Err(error)) => return Err(classify_unavailable(error)),
            Err(error) => return Err(classify_unavailable(error.into())),
        };
        let next = reconcile_controls(record, current, &task, wall_now())?;
        let outcome = match next {
            Some(record) => {
                let selection = self.task_watch_checkpoint(vec![task.base().task_id.clone()])
                    .map_err(|_| TaskResumeError::InvalidRecord)?;
                TaskResumeReconciliation::Active { task: Box::new(task), record, selection }
            }
            None => TaskResumeReconciliation::Terminal(Box::new(task)),
        };
        self.session.check(cx, cancellation).map_err(ManagedTasksError::from)?;
        if cx.now() >= retention_deadline { return Err(TaskResumeError::Unavailable.into()); }
        record.admit(cx, current)?;
        Ok(outcome)
    }
}

// Authentication-independent retention admission shared by managed and machine
// restart. Return a monotonic bound once; later wall-clock rollback cannot
// extend the read. Stored records never choose the configured endpoint.
pub(crate) fn resume_read_deadline(
    cx: &Cx,
    current: &TaskResumeBinding,
    record: &TaskResumeRecord,
    resource: &str,
) -> Result<asupersync::types::Time, TaskResumeError> {
    super::checkpoint(cx)?;
    let now = wall_now();
    admit_record(record, current, resource, now)?;
    let remaining = record.retain_until.checked_sub(now).ok_or(TaskResumeError::Unavailable)?;
    Ok(cx.now().saturating_add_nanos(u64::try_from(remaining).unwrap_or(u64::MAX)))
}

fn admit_record(
    record: &TaskResumeRecord,
    current: &TaskResumeBinding,
    resource: &str,
    now: i128,
) -> Result<(), TaskResumeError> {
    if current.resource.as_str() != resource { return Err(TaskResumeError::Unavailable); }
    record.admit_at(current, now)
}

fn classify_unavailable(error: ManagedTasksError) -> TaskResumeReconciliationError {
    match error {
        ManagedTasksError::HttpStatus { status: 401 | 403 | 404 }
        | ManagedTasksError::Session(OAuthSessionError::AuthorizationRejected { status: 401 | 403 | 404 }) => {
            TaskResumeError::Unavailable.into()
        }
        error => error.into(),
    }
}

// One control comparison is shared by live reconciliation and its paired
// mutation tests. Regressed or conflicting snapshots are not allowed to
// overwrite the saved record or invoke an input resolver. A caller may make
// a later explicit read; there is no unbounded reconciliation/retry loop.
fn reconcile_controls(
    previous: &TaskResumeRecord,
    binding: &TaskResumeBinding,
    task: &Task,
    now: i128,
) -> Result<Option<TaskResumeRecord>, TaskResumeError> {
    previous.admit_at(binding, now)?;
    let base = task.base();
    let ttl = base.ttl_ms.as_ref().map(|ttl| ttl.try_as_millis())
        .transpose().map_err(|_| TaskResumeError::InvalidRecord)?;
    if base.task_id != previous.task_id || ttl != previous.ttl_ms
        || timestamp_nanos(&base.created_at)? != timestamp_nanos(&previous.created_at)?
    { return Err(TaskResumeError::ConflictingSnapshot); }
    let old_time = timestamp_nanos(&previous.updated_at)?;
    let updated = timestamp_nanos(&base.last_updated_at)?;
    if updated < old_time { return Err(TaskResumeError::StaleSnapshot); }
    let poll = base.poll_interval_ms.as_ref().map(|hint| hint.try_as_millis())
        .transpose().map_err(|_| TaskResumeError::InvalidRecord)?;
    if updated == old_time && (base.status != previous.status || poll != previous.poll_interval_ms) {
        return Err(TaskResumeError::ConflictingSnapshot);
    }
    let expected = match task {
        Task::Working(_) => TaskStatus::Working,
        Task::InputRequired { .. } => TaskStatus::InputRequired,
        Task::Completed { .. } => TaskStatus::Completed,
        Task::Failed { .. } => TaskStatus::Failed,
        Task::Cancelled(_) => TaskStatus::Cancelled,
    };
    if base.status != expected { return Err(TaskResumeError::InvalidRecord); }
    if let Some(ttl) = ttl {
        let expiry = timestamp_nanos(&base.created_at)? + i128::from(ttl) * 1_000_000;
        if now >= expiry || updated >= expiry { return Err(TaskResumeError::Unavailable); }
    }
    if matches!(task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
        return Ok(None);
    }
    let mut next = TaskResumeRecord::capture_at(binding, task, MAX_RETENTION, now)?;
    next.retain_until = next.retain_until.min(previous.retain_until);
    next.admit_at(binding, now)?;
    Ok(Some(next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::{binding, now, record};
    use fastmcp_protocol::tasks_extension::TaskTimestamp;
    use serde_json::json;

    fn current() -> Task {
        serde_json::from_value(json!({"taskId":"opaque / ID", "status":"input_required",
            "createdAt":"2026-09-21T00:00:00Z", "lastUpdatedAt":"2026-09-21T00:00:02Z",
            "ttlMs":60000, "pollIntervalMs":3000, "statusMessage":"SECRET-MESSAGE",
            "inputRequests":{"SECRET-REQUEST":{"method":"roots/list"}}})).unwrap()
    }

    #[test]
    fn fresh_controls_preserve_identity_retention_and_exclude_application_inputs() {
        let previous = record();
        let before = previous.encode().unwrap();
        let task = current();
        let next = reconcile_controls(&previous, &binding(1), &task, now() + 1_000_000_000).unwrap().unwrap();
        assert_eq!(next.key(), previous.key());
        assert_eq!(next.retain_until, previous.retain_until);
        assert_eq!(next.poll_interval_ms, Some(3000));
        assert_eq!(next.updated_at.as_str(), "2026-09-21T00:00:02Z");
        assert_eq!(previous.encode().unwrap(), before);
        assert!(!next.encode().unwrap().windows(6).any(|bytes| bytes == b"SECRET"));
        assert!(matches!(task, Task::InputRequired { input_requests, .. } if input_requests.contains_key("SECRET-REQUEST")));
    }

    #[test]
    fn offset_equivalent_creation_is_not_confused_with_a_different_task() {
        let mut task = current();
        if let Task::InputRequired { base, .. } = &mut task {
            base.created_at = TaskTimestamp::parse("2026-09-20T20:00:00-04:00").unwrap();
        }
        let next = reconcile_controls(&record(), &binding(1), &task, now()).unwrap().unwrap();
        assert_eq!(next.created_at.as_str(), "2026-09-20T20:00:00-04:00");
    }

    #[test]
    fn changed_identity_ttl_and_regressed_snapshots_cannot_replace_saved_controls() {
        let previous = record();
        let before = previous.encode().unwrap();
        for dimension in 0..4 {
            let mut task = current();
            if let Task::InputRequired { base, .. } = &mut task {
                match dimension {
                    0 => base.task_id = fastmcp_protocol::tasks_extension::TaskId::parse("other").unwrap(),
                    1 => base.ttl_ms = None,
                    2 => base.created_at = TaskTimestamp::parse("2026-09-20T00:00:00Z").unwrap(),
                    _ => base.last_updated_at = TaskTimestamp::parse("2026-09-21T00:00:00Z").unwrap(),
                }
            }
            let error = reconcile_controls(&previous, &binding(1), &task, now()).unwrap_err();
            assert_eq!(error, if dimension == 3 { TaskResumeError::StaleSnapshot } else { TaskResumeError::ConflictingSnapshot });
            assert_eq!(previous.encode().unwrap(), before);
        }
        assert!(reconcile_controls(&previous, &binding(1), &current(), now()).is_ok());
    }

    #[test]
    fn equal_timestamp_conflict_and_expired_terminal_do_not_bypass_admission() {
        let previous = record();
        let mut task = current();
        if let Task::InputRequired { base, .. } = &mut task { base.last_updated_at = previous.updated_at.clone(); }
        assert!(matches!(reconcile_controls(&previous, &binding(1), &task, now()), Err(TaskResumeError::ConflictingSnapshot)));
        let mut base = current().base().clone();
        base.status = TaskStatus::Cancelled;
        let terminal = Task::Cancelled(base);
        assert!(reconcile_controls(&previous, &binding(1), &terminal, now()).unwrap().is_none());
        assert!(matches!(reconcile_controls(&previous, &binding(1), &terminal, previous.retain_until), Err(TaskResumeError::Unavailable)));
    }

    #[test]
    fn preflight_rejects_wrong_owner_and_endpoint_without_interpreting_saved_state() {
        let previous = record();
        assert!(admit_record(&previous, &binding(1), "https://mcp.example/mcp", now()).is_ok());
        for resource in ["https://mcp.example/other", "https://mcp.example/mcp?tenant=other", "http://mcp.example/mcp"] {
            assert_eq!(admit_record(&previous, &binding(1), resource, now()), Err(TaskResumeError::Unavailable));
        }
        assert_eq!(admit_record(&previous, &binding(2), "https://mcp.example/mcp", now()), Err(TaskResumeError::Unavailable));
    }

    #[test]
    fn http_unavailable_is_nondisclosing_but_operational_errors_are_not_hidden() {
        for status in [401, 403, 404] {
            let error = classify_unavailable(ManagedTasksError::HttpStatus { status });
            assert!(matches!(error, TaskResumeReconciliationError::Resume(TaskResumeError::Unavailable)));
        }
        assert!(matches!(classify_unavailable(ManagedTasksError::HttpStatus { status: 503 }),
            TaskResumeReconciliationError::Task(ManagedTasksError::HttpStatus { status: 503 })));
        assert!(matches!(classify_unavailable(ManagedTasksError::Session(OAuthSessionError::Cancelled)),
            TaskResumeReconciliationError::Task(ManagedTasksError::Session(OAuthSessionError::Cancelled))));
    }
}