//! Initial, insert-only checkpoints for newly accepted Tasks.
//!
//! This is not a transaction with the remote tool. It contains only the
//! existing resume controls and never arguments, input descriptors or results.
//! A host must supply CURRENT verified ownership and a durable protector.

use std::fmt;
use std::time::Duration;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_protocol::tasks_extension::Task;

use super::super::{
    MAX_RETENTION, TaskResumeBinding, TaskResumeError, TaskResumeKey,
    TaskResumeRecord, checkpoint, wall_now,
};

/// Validated before a creating call can have effects. The bound is a host
/// retention ceiling, not a requested remote TTL or a Task-creation guarantee.
#[derive(Clone, Copy, Debug)]
pub struct TaskResumeCapturePolicy {
    maximum_retention: Duration,
}

impl TaskResumeCapturePolicy {
    pub fn new(maximum_retention: Duration) -> Result<Self, TaskResumeError> {
        if maximum_retention.is_zero() || maximum_retention > MAX_RETENTION {
            return Err(TaskResumeError::InvalidRetention);
        }
        Ok(Self { maximum_retention })
    }

    pub fn maximum_retention(&self) -> Duration { self.maximum_retention }
}

/// One conditional INSERT, not an update or evidence of remote authorization.
/// Reapplying it to an existing slot fails, even when its controls are identical.
/// After an uncertain write, inspect/reconcile storage rather than retrying it.
#[derive(Clone)]
pub struct TaskResumeInsert {
    record: TaskResumeRecord,
}

impl fmt::Debug for TaskResumeInsert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskResumeInsert(<control record>)")
    }
}

impl TaskResumeInsert {
    /// Capture a freshly authenticated nonterminal Task. This local operation
    /// cannot authenticate an arbitrary Task value supplied by the caller.
    /// Remote TTL and host retention are enforced by the existing record codec.
    pub fn capture(
        cx: &Cx, current: &TaskResumeBinding, task: &Task, policy: TaskResumeCapturePolicy,
    ) -> Result<Self, TaskResumeError> {
        Ok(Self { record: TaskResumeRecord::capture(cx, current, task, policy.maximum_retention)? })
    }

    pub fn record(&self) -> &TaskResumeRecord { &self.record }
    pub fn key(&self) -> TaskResumeKey { self.record.key() }

    /// Anchor the remaining checkpoint lifetime to this operation's monotonic
    /// clock. The caller must keep this deadline, not recalculate it on retries
    /// or after a wall-clock change. The caller's deadline may be tighter.
    pub fn retention_deadline(&self, cx: &Cx, current: &TaskResumeBinding) -> Result<Time, TaskResumeError> {
        checkpoint(cx)?;
        // Sample monotonic time FIRST; time spent checking wall-clock expiry
        // must not extend the admitted retention interval.
        let anchor = cx.now();
        let remaining = self.remaining_at(current, wall_now())?;
        let deadline = anchor.saturating_add_nanos(remaining);
        Ok(cx.budget().deadline.map_or(deadline, |budget| budget.min(deadline)))
    }

    fn remaining_at(&self, current: &TaskResumeBinding, now: i128) -> Result<u64, TaskResumeError> {
        self.record.admit_at(current, now)?;
        let remaining = self.record.retain_until.checked_sub(now).ok_or(TaskResumeError::Unavailable)?;
        Ok(u64::try_from(remaining).unwrap_or(u64::MAX))
    }

    /// Synchronously perform an insert-only protected atomic write. Execute in
    /// the host's OWNED blocking lane, never directly inside an async poll.
    /// Existing slots, including expired-but-unpruned slots, cannot be replaced.
    #[cfg(target_os = "linux")]
    pub fn apply<P: super::super::store::TaskResumeProtector>(
        &self, cx: &Cx, current: &TaskResumeBinding,
        store: &mut super::super::store::TaskResumeStore<P>,
    ) -> Result<(), super::super::store::TaskResumeStoreError> {
        store.insert(cx, current, self.record.clone())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::tests::{binding, now, record};

    #[test]
    fn invalid_retention_is_rejected_without_a_task_or_storage_provider() {
        for duration in [Duration::ZERO, MAX_RETENTION + Duration::from_nanos(1)] {
            assert!(matches!(TaskResumeCapturePolicy::new(duration), Err(TaskResumeError::InvalidRetention)));
        }
        for duration in [Duration::from_nanos(1), MAX_RETENTION] {
            assert_eq!(TaskResumeCapturePolicy::new(duration).unwrap().maximum_retention(), duration);
        }
    }

    #[test]
    fn initial_insert_keeps_exact_controls_but_no_application_payload() {
        let insert = TaskResumeInsert { record: record() };
        assert_eq!(insert.key(), record().key());
        assert_eq!(insert.record().encode().unwrap(), record().encode().unwrap());
        assert!(!insert.record().encode().unwrap().windows(6).any(|part| part == b"SECRET"));
        assert!(!format!("{insert:?}").contains("opaque / ID"));
    }

    #[test]
    fn remaining_retention_uses_original_expiry_and_current_binding() {
        let insert = TaskResumeInsert { record: record() };
        assert_eq!(insert.remaining_at(&binding(1), now()).unwrap(), 59_000_000_000);
        assert_eq!(insert.remaining_at(&binding(1), insert.record.retain_until - 1).unwrap(), 1);
        assert_eq!(insert.remaining_at(&binding(1), insert.record.retain_until), Err(TaskResumeError::Unavailable));
        assert_eq!(insert.remaining_at(&binding(2), now()), Err(TaskResumeError::Unavailable));
    }
}
