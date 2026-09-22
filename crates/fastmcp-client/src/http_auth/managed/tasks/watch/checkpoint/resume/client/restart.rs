//! Bounded restart enumeration followed by freshly authorized reconciliation.
//!
//! Load the complete finite plan BEFORE starting network work or changing the
//! source store. Its generation-bound cursors must not survive our own writes.
//! A plan contains only payload-free controls, never old application results or
//! permission to replay creation/input. One caller-owned restart reconciles one
//! record at a time, without opening watches or spawning background work.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::Duration;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;

use crate::http_auth::managed::{OAuthSessionError, deadline_after};
use crate::http_auth::managed::tasks::ManagedTasksClient;
use crate::http_auth::managed::tasks::watch::{ManagedTaskWatchError, WatchIds};
use super::{TaskResumeReconciliation, TaskResumeReconciliationError};
use super::lifecycle::TaskResumeChange;
use super::super::{TaskResumeBinding, TaskResumeError, TaskResumeKey, TaskResumeRecord, checkpoint};

const MAX_RESTART_RECORDS: usize = 128;
const MAX_RESTART_BYTES: usize = 1024 * 1024;

/// Finite staging and execution limits. Counts/bytes charge duplicate records
/// too, so an infinite iterator of identical records cannot evade admission.
/// The timeout starts when prepare_task_restart is called, not on each read.
#[derive(Clone, Copy, Debug)]
pub struct TaskResumeRestartPolicy {
    maximum_records: usize,
    maximum_bytes: usize,
    timeout: Duration,
}
impl Default for TaskResumeRestartPolicy {
    fn default() -> Self {
        Self { maximum_records: 128, maximum_bytes: 512 * 1024, timeout: Duration::from_secs(900) }
    }
}
impl TaskResumeRestartPolicy {
    pub fn new(maximum_records: usize, maximum_bytes: usize, timeout: Duration) -> Result<Self, TaskResumeError> {
        if !(1..=MAX_RESTART_RECORDS).contains(&maximum_records)
            || !(64..=MAX_RESTART_BYTES).contains(&maximum_bytes)
            || timeout.is_zero() || timeout > Duration::from_secs(3600)
        { return Err(TaskResumeError::Capacity); }
        Ok(Self { maximum_records, maximum_bytes, timeout })
    }
}

/// One fully staged owner-bound selection. It is not Clone or serializable and
/// cannot create requests by itself. Its records are ordered by opaque key,
/// independent of provider page order. Only exactly equal duplicates coalesce;
/// a conflicting version for the same key rejects the ENTIRE plan.
///
/// Local expiry may change after staging. Every record is re-admitted when it
/// is reached; an expired record produces Unavailable without network contact.
/// No state in this plan is evidence that the remote Task is still active.
pub struct TaskResumeRestartPlan {
    binding: [u8; 32],
    records: BTreeMap<TaskResumeKey, TaskResumeRecord>,
    charged_records: usize,
    charged_bytes: usize,
    policy: TaskResumeRestartPolicy,
}
impl fmt::Debug for TaskResumeRestartPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskResumeRestartPlan").field("records", &self.records.len())
            .field("charged_bytes", &self.charged_bytes).finish_non_exhaustive()
    }
}
impl TaskResumeRestartPlan {
    /// Stage records already opened by the host's protected provider. Structural
    /// validation and current binding are mandatory; the codec cannot establish
    /// integrity/confidentiality of bytes read from an arbitrary source.
    ///
    /// Iterator pulls are synchronous: perform provider/file work in the host's
    /// owned blocking lane. At most maximum_records + 1 items are pulled, and
    /// the excess item is never retained. No partial plan escapes on failure.
    pub fn from_records(
        cx: &Cx, current: &TaskResumeBinding,
        records: impl IntoIterator<Item = TaskResumeRecord>, policy: TaskResumeRestartPolicy,
    ) -> Result<Self, TaskResumeError> {
        checkpoint(cx)?;
        let mut plan = Self::empty(current, policy);
        for record in records {
            checkpoint(cx)?;
            plan.charge_record()?;
            plan.stage(record)?;
        }
        checkpoint(cx)?;
        Ok(plan)
    }

    /// Load ALL live pages from the existing protected Linux store before any
    /// reconciliation or host write. Immutable store custody spans enumeration
    /// and record lookup, so this operation cannot invalidate its own cursors.
    /// The source is unchanged on success or failure; expiry pruning is separate.
    /// A key expiring between page and get is omitted but still charges a slot.
    ///
    /// This is synchronous storage work, for the host's owned blocking lane.
    /// Do not call it inside an async poll. No runtime, writer or protector is
    /// installed here; the already-open store enforces its own provider policy.
    #[cfg(target_os = "linux")]
    pub fn load_store<P: super::super::store::TaskResumeProtector>(
        cx: &Cx, current: &TaskResumeBinding,
        store: &super::super::store::TaskResumeStore<P>,
        page_size: usize, policy: TaskResumeRestartPolicy,
    ) -> Result<Self, super::super::store::TaskResumeStoreError> {
        checkpoint(cx)?;
        if !(1..=MAX_RESTART_RECORDS).contains(&page_size) { return Err(TaskResumeError::Capacity.into()); }
        let mut plan = Self::empty(current, policy);
        let mut cursor = None;
        loop {
            let page = store.page(cx, current, cursor.as_ref(), page_size)?;
            for key in page.keys {
                plan.charge_record()?;
                if let Some(record) = store.get(cx, current, key)? {
                    if record.key() != key { return Err(TaskResumeError::ConflictingSnapshot.into()); }
                    plan.stage(record)?;
                }
            }
            cursor = page.next;
            if cursor.is_none() { break; }
            // Never present a full budget's prefix as a complete enumeration.
            if plan.charged_records >= policy.maximum_records { return Err(TaskResumeError::Capacity.into()); }
        }
        checkpoint(cx)?;
        Ok(plan)
    }

    pub fn len(&self) -> usize { self.records.len() }
    pub fn is_empty(&self) -> bool { self.records.is_empty() }
    pub fn charged_records(&self) -> usize { self.charged_records }
    pub fn charged_bytes(&self) -> usize { self.charged_bytes }
    pub fn records(&self) -> impl ExactSizeIterator<Item = &TaskResumeRecord> { self.records.values() }

    fn empty(current: &TaskResumeBinding, policy: TaskResumeRestartPolicy) -> Self {
        Self { binding: *current.associated_data(), records: BTreeMap::new(),
            charged_records: 0, charged_bytes: 0, policy }
    }
    fn charge_record(&mut self) -> Result<(), TaskResumeError> {
        if self.charged_records >= self.policy.maximum_records { return Err(TaskResumeError::Capacity); }
        self.charged_records += 1;
        Ok(())
    }
    fn stage(&mut self, record: TaskResumeRecord) -> Result<(), TaskResumeError> {
        record.validate()?;
        if record.binding != self.binding { return Err(TaskResumeError::Unavailable); }
        // The fixed-schema encoded length is measured without serializing or
        // copying a payload. Reserve complete bytes BEFORE retaining the record.
        let bytes = self.charged_bytes.checked_add(record_bytes(&record))
            .filter(|bytes| *bytes <= self.policy.maximum_bytes).ok_or(TaskResumeError::TooLarge)?;
        let key = record.key();
        if let Some(previous) = self.records.get(&key) {
            if previous != &record { return Err(TaskResumeError::ConflictingSnapshot); }
        } else { self.records.insert(key, record); }
        self.charged_bytes = bytes;
        Ok(())
    }
}

// FMTRSM01's fixed fields, three length-prefixed texts, and optional u64s.
// A codec parity regression below binds this admission calculation to encode().
fn record_bytes(record: &TaskResumeRecord) -> usize {
    8 + 32 + 1 + 3 * 2 + 2 + 16
        + record.task_id.as_str().len() + record.created_at.as_str().len() + record.updated_at.as_str().len()
        + usize::from(record.ttl_ms.is_some()) * 8 + usize::from(record.poll_interval_ms.is_some()) * 8
}

/// A fresh response or a nondisclosing unavailable disposition. Unavailable is
/// shared by local expiry and remote 401/403/404. It does not delete the record
/// and must not be used as permission to repeat a creating call.
pub enum TaskResumeRestartOutcome {
    Reconciled(TaskResumeReconciliation),
    Unavailable,
}
/// The exact staged version accompanies its fresh outcome for conditional
/// persistence. Save active controls with the existing TaskResumeChange, and
/// acknowledge handling a terminal result BEFORE choosing to remove its hint.
pub struct TaskResumeRestartItem {
    pub previous: TaskResumeRecord,
    pub outcome: TaskResumeRestartOutcome,
}

impl TaskResumeRestartItem {
    /// Explicitly prepare this delivered outcome's conditional storage change.
    /// Active records are compared with their fresh Task and watch selection;
    /// terminal Tasks prepare removal only after full control reconciliation.
    /// Unavailable (including expired) records prepare exact-version disposal,
    /// without distinguishing absent, forbidden and expired remote identities.
    ///
    /// Call only AFTER handling or durably recording a terminal result. This
    /// method neither invokes storage nor consumes the item: the real result
    /// remains available if preparing/applying its checkpoint change fails.
    /// No payload, input or credential is passed to the resulting command.
    ///
    /// Apply the command in the host's owned storage lane before starting a new
    /// persistence-backed watch from an active record. Missing/changed expected
    /// versions fail rather than deleting or overwriting newer work. After an
    /// uncertain write reconcile storage, never repeat creation or blindly retry.
    /// A terminal whose retention has since expired requires an explicit host
    /// disposition through TaskResumeChange::discard instead of renewed resume
    /// authority. Neither this method nor discard proves remote quiescence.
    ///
    /// Publicly assembled items are not authentication evidence. Current owner
    /// facts and the selected managed login remain the host's responsibility.
    pub fn storage_change(
        &self, cx: &Cx, current: &TaskResumeBinding,
    ) -> Result<TaskResumeChange, TaskResumeError> {
        checkpoint(cx)?;
        if self.previous.binding != current.digest { return Err(TaskResumeError::Unavailable); }
        self.previous.validate()?;
        match &self.outcome {
            TaskResumeRestartOutcome::Unavailable => TaskResumeChange::discard(cx, current, &self.previous),
            TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Active { task, record, selection }) => {
                if selection.resource().as_str() != current.resource().as_str()
                    || selection.task_ids().len() != 1
                    || selection.task_ids().first() != Some(self.previous.task_id())
                { return Err(TaskResumeError::ConflictingSnapshot); }
                let change = TaskResumeChange::from_snapshot(cx, current, &self.previous, task)?;
                if change.replacement() != Some(record) { return Err(TaskResumeError::ConflictingSnapshot); }
                Ok(change)
            }
            TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Terminal(task)) => {
                let change = TaskResumeChange::from_snapshot(cx, current, &self.previous, task)?;
                if change.replacement().is_some() { return Err(TaskResumeError::InvalidRecord); }
                Ok(change)
            }
        }
    }
}

#[derive(Debug)]
pub enum TaskResumeRestartError {
    Resume(TaskResumeError),
    Reconciliation(TaskResumeReconciliationError),
    Identity(ManagedTaskWatchError),
    Session(OAuthSessionError),
    Closed,
}
impl fmt::Display for TaskResumeRestartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resume(error) => error.fmt(f),
            Self::Reconciliation(error) => error.fmt(f),
            Self::Identity(error) => error.fmt(f),
            Self::Session(error) => error.fmt(f),
            Self::Closed => f.write_str("Task restart owner is closed; reconcile its pending read explicitly"),
        }
    }
}
impl std::error::Error for TaskResumeRestartError {}
impl From<TaskResumeError> for TaskResumeRestartError {
    fn from(error: TaskResumeError) -> Self { Self::Resume(error) }
}
impl From<TaskResumeReconciliationError> for TaskResumeRestartError {
    fn from(error: TaskResumeReconciliationError) -> Self { Self::Reconciliation(error) }
}
impl From<ManagedTaskWatchError> for TaskResumeRestartError {
    fn from(error: ManagedTaskWatchError) -> Self { Self::Identity(error) }
}
impl From<OAuthSessionError> for TaskResumeRestartError {
    fn from(error: OAuthSessionError) -> Self { Self::Session(error) }
}

impl ManagedTasksClient {
    /// Prepare one finite restart using CURRENT host-verified owner facts and
    /// this client's configured resource. No credentials, network requests,
    /// callbacks or watches are created. Use a distinct id_prefix for concurrent
    /// operations; generated IDs are reserved for the entire restart.
    ///
    /// Subsequent persistence can invalidate source-store cursors safely: all
    /// selected controls are already staged. They are still only lookup hints.
    /// A record changed by another actor must not be overwritten by the host;
    /// use the exact staged previous version for conditional persistence.
    pub fn prepare_task_restart(
        &self, cx: &Cx, current: TaskResumeBinding, plan: TaskResumeRestartPlan, id_prefix: String,
    ) -> Result<ManagedTaskRestart, TaskResumeRestartError> {
        self.prepare_task_restart_with_cancellation(cx, &McpRequestCancellation::new(), current, plan, id_prefix)
    }

    pub fn prepare_task_restart_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        current: TaskResumeBinding, plan: TaskResumeRestartPlan, id_prefix: String,
    ) -> Result<ManagedTaskRestart, TaskResumeRestartError> {
        self.session.check(cx, cancellation)?;
        admit_client(plan.binding, &current, self.session.resource().as_str())?;
        let ids = WatchIds::new(id_prefix)?;
        let deadline = deadline_after(cx, plan.policy.timeout)?;
        let finished = plan.records.is_empty();
        Ok(ManagedTaskRestart {
            client: self.clone(), current, records: plan.records.into_values().collect(),
            ids, cancellation: cancellation.clone(), deadline,
            pending_record: None, pending_outcome: None, ready: !finished, finished,
            attempted: 0, delivered: 0,
        })
    }
}

fn admit_client(binding: [u8; 32], current: &TaskResumeBinding, resource: &str) -> Result<(), TaskResumeError> {
    if binding != *current.associated_data() || resource != current.resource().as_str() {
        return Err(TaskResumeError::Unavailable);
    }
    Ok(())
}

/// Sequential, caller-driven restart custody. Each eligible record receives
/// fresh authenticated discovery and exactly one tasks/get, through the existing
/// reconciliation API. Never restores input ledgers, replays a tool call,
/// installs a subscription or writes storage. The caller decides what to watch.
///
/// A failed or abandoned POLLED read closes this owner permanently. Its current
/// record and any fully returned reconciliation stay inspectable; unvisited
/// records are retained. There is no hidden retry or silent skip of operational
/// errors. Unavailable records are explicit items and do not stop other records.
#[must_use = "drive reconciliations or retain/export the remaining control records"]
pub struct ManagedTaskRestart {
    client: ManagedTasksClient,
    current: TaskResumeBinding,
    records: VecDeque<TaskResumeRecord>,
    ids: WatchIds,
    cancellation: McpRequestCancellation,
    deadline: Time,
    pending_record: Option<TaskResumeRecord>,
    pending_outcome: Option<TaskResumeRestartOutcome>,
    ready: bool,
    finished: bool,
    attempted: usize,
    delivered: usize,
}
impl fmt::Debug for ManagedTaskRestart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedTaskRestart").field("remaining", &self.remaining())
            .field("attempted", &self.attempted).field("delivered", &self.delivered)
            .field("ready", &self.ready).finish_non_exhaustive()
    }
}
impl ManagedTaskRestart {
    pub fn remaining(&self) -> usize { self.records.len() + usize::from(self.pending_record.is_some()) }
    /// Reconciliation calls started; local expired records consume no request.
    pub fn attempted(&self) -> usize { self.attempted }
    pub fn delivered(&self) -> usize { self.delivered }
    pub fn pending_record(&self) -> Option<&TaskResumeRecord> { self.pending_record.as_ref() }
    pub fn pending_outcome(&self) -> Option<&TaskResumeRestartOutcome> { self.pending_outcome.as_ref() }
    pub fn unvisited(&self) -> impl ExactSizeIterator<Item = &TaskResumeRecord> { self.records.iter() }
    pub fn close(&mut self) { self.ready = false; }

    /// Extract a failed/abandoned read's custody without retrying it. Remaining
    /// records stay on the closed owner. No result here confers mutation authority.
    pub fn take_pending(&mut self) -> Option<(TaskResumeRecord, Option<TaskResumeRestartOutcome>)> {
        self.ready = false;
        self.pending_record.take().map(|record| (record, self.pending_outcome.take()))
    }

    pub async fn next_reconciled(&mut self, cx: &Cx) -> Result<Option<TaskResumeRestartItem>, TaskResumeRestartError> {
        if self.finished { return Ok(None); }
        if !self.ready { return Err(TaskResumeRestartError::Closed); }
        // Consume this read opportunity before any fallible work or suspension.
        // On abandonment the record remains in self, never only in the future.
        self.ready = false;
        self.check(cx)?;
        let Some(record) = self.records.pop_front() else { self.finished = true; return Ok(None); };
        self.pending_record = Some(record);
        let pending = self.pending_record.as_ref().ok_or(TaskResumeError::InvalidRecord)?;
        match pending.admit(cx, &self.current) {
            Err(TaskResumeError::Unavailable) => self.pending_outcome = Some(TaskResumeRestartOutcome::Unavailable),
            Err(error) => return Err(error.into()),
            Ok(()) => {
                let ids = self.ids.next_pair()?;
                self.attempted += 1;
                let client = self.client.clone();
                let cancellation = self.cancellation.clone();
                let current = &self.current;
                let outcome = &mut self.pending_outcome;
                Box::pin(client.session.await_active(cx, &cancellation, self.deadline, None, async {
                    let observed = client.reconcile_task_resume_with_cancellation(cx, &cancellation, current, pending, ids).await;
                    let observed = match observed {
                        Ok(value) => TaskResumeRestartOutcome::Reconciled(value),
                        Err(TaskResumeReconciliationError::Resume(TaskResumeError::Unavailable)) => TaskResumeRestartOutcome::Unavailable,
                        Err(error) => return Ok(Err(error)),
                    };
                    // Save before returning through the outer lifetime guard.
                    // Late cancellation must not erase an already-returned result.
                    *outcome = Some(observed);
                    Ok(Ok(()))
                })).await??;
            }
        }
        self.check(cx)?;
        let previous = self.pending_record.take().ok_or(TaskResumeError::InvalidRecord)?;
        let outcome = self.pending_outcome.take().ok_or(TaskResumeError::InvalidRecord)?;
        self.delivered += 1;
        // Completion is elected with the last delivery, not a later read which
        // might occur after the login closes or the original deadline expires.
        self.finished = self.records.is_empty();
        self.ready = !self.finished;
        Ok(Some(TaskResumeRestartItem { previous, outcome }))
    }

    fn check(&self, cx: &Cx) -> Result<(), TaskResumeRestartError> {
        self.client.session.check(cx, &self.cancellation)?;
        let deadline = cx.budget().deadline.map_or(self.deadline, |parent| parent.min(self.deadline));
        if cx.now() >= deadline { return Err(OAuthSessionError::TimedOut.into()); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::tests::{binding, record};
    use std::cell::Cell;
    use fastmcp_protocol::tasks_extension::TaskId;

    #[test]
    fn finite_policy_rejects_zero_and_overflowing_dimensions() {
        for (count, bytes, timeout) in [(0, 1024, 1), (129, 1024, 1), (1, 63, 1),
            (1, MAX_RESTART_BYTES + 1, 1), (1, 1024, 0), (1, 1024, 3601)] {
            assert!(TaskResumeRestartPolicy::new(count, bytes, Duration::from_secs(timeout)).is_err());
        }
        assert!(TaskResumeRestartPolicy::new(128, MAX_RESTART_BYTES, Duration::from_secs(3600)).is_ok());
    }

    #[test]
    fn exact_duplicates_coalesce_but_still_charge_both_records_and_bytes() {
        let cx = Cx::for_testing();
        let one = record();
        let size = one.encode().unwrap().len();
        let plan = TaskResumeRestartPlan::from_records(&cx, &binding(1), [one.clone(), one], TaskResumeRestartPolicy::default()).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan.charged_records(), 2);
        assert_eq!(plan.charged_bytes(), size * 2);
        assert!(!format!("{plan:?}").contains("opaque / ID"));
    }

    #[test]
    fn duplicate_iterators_cannot_evade_the_scan_limit() {
        let cx = Cx::for_testing();
        let pulls = Cell::new(0);
        let records = std::iter::repeat_with(|| { pulls.set(pulls.get() + 1); record() });
        let policy = TaskResumeRestartPolicy::new(2, 4096, Duration::from_secs(1)).unwrap();
        assert!(matches!(TaskResumeRestartPlan::from_records(&cx, &binding(1), records, policy), Err(TaskResumeError::Capacity)));
        assert_eq!(pulls.get(), 3);
    }

    #[test]
    fn different_versions_of_the_same_key_reject_the_whole_plan() {
        let cx = Cx::for_testing();
        let original = record();
        let before = original.encode().unwrap();
        let mut changed = original.clone();
        changed.poll_interval_ms = Some(3000);
        assert!(matches!(TaskResumeRestartPlan::from_records(&cx, &binding(1), [original.clone(), changed],
            TaskResumeRestartPolicy::default()), Err(TaskResumeError::ConflictingSnapshot)));
        assert_eq!(original.encode().unwrap(), before);
        assert!(TaskResumeRestartPlan::from_records(&cx, &binding(1), [original], TaskResumeRestartPolicy::default()).is_ok());
    }

    #[test]
    fn owner_binding_and_resource_are_checked_independently_of_record_contents() {
        let cx = Cx::for_testing();
        assert!(matches!(TaskResumeRestartPlan::from_records(&cx, &binding(2), [record()],
            TaskResumeRestartPolicy::default()), Err(TaskResumeError::Unavailable)));
        let owner = binding(1);
        assert!(admit_client(*owner.associated_data(), &owner, owner.resource().as_str()).is_ok());
        assert!(admit_client(*owner.associated_data(), &binding(2), owner.resource().as_str()).is_err());
        assert!(admit_client(*owner.associated_data(), &owner, "https://mcp.example/other").is_err());
    }

    #[test]
    fn byte_reservation_matches_the_fixed_codec_before_staging() {
        let cx = Cx::for_testing();
        for ttl in [None, Some(60000)] {
            for poll in [None, Some(2000)] {
                let mut one = record();
                one.ttl_ms = ttl;
                one.poll_interval_ms = poll;
                assert_eq!(record_bytes(&one), one.encode().unwrap().len());
                let size = record_bytes(&one);
                let exact = TaskResumeRestartPolicy::new(1, size, Duration::from_secs(1)).unwrap();
                assert!(TaskResumeRestartPlan::from_records(&cx, &binding(1), [one.clone()], exact).is_ok());
                let short = TaskResumeRestartPolicy::new(1, size - 1, Duration::from_secs(1)).unwrap();
                assert!(matches!(TaskResumeRestartPlan::from_records(&cx, &binding(1), [one], short), Err(TaskResumeError::TooLarge)));
            }
        }
    }

    #[test]
    fn staging_is_deterministic_and_keeps_distinct_unicode_identities() {
        let cx = Cx::for_testing();
        let records: Vec<_> = ["é", "e\u{301}", "a/b", "a%2Fb"].into_iter().map(|id| {
            let mut value = record(); value.task_id = TaskId::parse(id).unwrap(); value
        }).collect();
        let first = TaskResumeRestartPlan::from_records(&cx, &binding(1), records.clone(), TaskResumeRestartPolicy::default()).unwrap();
        let second = TaskResumeRestartPlan::from_records(&cx, &binding(1), records.into_iter().rev(), TaskResumeRestartPolicy::default()).unwrap();
        assert_eq!(first.len(), 4);
        assert_eq!(first.records().map(TaskResumeRecord::key).collect::<Vec<_>>(),
            second.records().map(TaskResumeRecord::key).collect::<Vec<_>>());
    }

    #[test]
    fn expired_controls_can_be_staged_but_are_never_live_authority() {
        let cx = Cx::for_testing();
        let mut expired = record();
        let expiry = super::super::super::timestamp_nanos(&expired.created_at).unwrap() + 2_000_000_000;
        expired.retain_until = expiry;
        let plan = TaskResumeRestartPlan::from_records(&cx, &binding(1), [expired], TaskResumeRestartPolicy::default()).unwrap();
        assert_eq!(plan.len(), 1);
        let staged = plan.records().next().unwrap();
        assert!(staged.admit_at(&binding(1), expiry - 1).is_ok());
        assert_eq!(staged.admit_at(&binding(1), expiry), Err(TaskResumeError::Unavailable));
    }

    fn handoff_task(status: &str, second: u8) -> fastmcp_protocol::tasks_extension::Task {
        use serde_json::json;
        let mut value = json!({"taskId":"handoff", "status":status,
            "createdAt":"2020-01-01T00:00:00Z", "lastUpdatedAt":format!("2020-01-01T00:00:{second:02}Z"),
            "ttlMs":null, "pollIntervalMs":10});
        match status {
            "input_required" => value["inputRequests"] = json!({"PRIVATE-INPUT":{"method":"roots/list"}}),
            "completed" => value["result"] = json!({"content":[{"type":"text","text":"PRIVATE-RESULT"}]}),
            _ => {},
        }
        serde_json::from_value(value).unwrap()
    }

    fn handoff_item(cx: &Cx, terminal: bool) -> TaskResumeRestartItem {
        use crate::http_auth::managed::tasks::watch::checkpoint::ManagedTaskWatchCheckpoint;
        let owner = binding(1);
        let previous = TaskResumeRecord::capture(cx, &owner, &handoff_task("working", 1), Duration::from_secs(60)).unwrap();
        let task = handoff_task(if terminal { "completed" } else { "input_required" }, 2);
        let outcome = if terminal {
            TaskResumeReconciliation::Terminal(Box::new(task))
        } else {
            let record = super::super::reconcile_controls(&previous, &owner, &task, super::super::super::wall_now()).unwrap().unwrap();
            let selection = ManagedTaskWatchCheckpoint::decode(&serde_json::to_vec(&serde_json::json!({
                "format":"fastmcp/task-watch", "version":1, "protocolVersion":"2026-07-28",
                "resource":owner.resource().as_str(), "taskIds":["handoff"],
            })).unwrap()).unwrap();
            TaskResumeReconciliation::Active { task: Box::new(task), record, selection }
        };
        TaskResumeRestartItem { previous, outcome: TaskResumeRestartOutcome::Reconciled(outcome) }
    }

    #[test]
    fn unavailable_disposal_keeps_exact_controls_and_requires_current_owner() {
        let cx = Cx::for_testing();
        let item = TaskResumeRestartItem { previous: record(), outcome: TaskResumeRestartOutcome::Unavailable };
        let encoded = item.previous.encode().unwrap();
        let change = item.storage_change(&cx, &binding(1)).unwrap();
        assert_eq!(change.previous().encode().unwrap(), encoded);
        assert!(change.replacement().is_none());
        assert!(matches!(item.storage_change(&cx, &binding(2)), Err(TaskResumeError::Unavailable)));
        assert_eq!(item.previous.encode().unwrap(), encoded);
        assert!(!format!("{change:?}").contains("opaque"));
        assert!(item.storage_change(&cx, &binding(1)).is_ok());
    }

    #[test]
    fn active_restart_handoff_carries_only_the_validated_record_change() {
        let cx = Cx::for_testing();
        let item = handoff_item(&cx, false);
        let original = item.previous.encode().unwrap();
        let change = item.storage_change(&cx, &binding(1)).unwrap();
        let TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Active { task, record, .. }) = &item.outcome
            else { panic!("active fixture required"); };
        assert_eq!(change.replacement(), Some(record));
        assert_eq!(change.previous().encode().unwrap(), original);
        assert!(!record.encode().unwrap().windows(7).any(|part| part == b"PRIVATE"));
        assert!(serde_json::to_string(task).unwrap().contains("PRIVATE-INPUT"));
    }

    #[test]
    fn inconsistent_active_record_or_selection_cannot_prepare_persistence() {
        let cx = Cx::for_testing();
        for field in 0..3 {
            let mut item = handoff_item(&cx, false);
            let original = item.previous.encode().unwrap();
            if let TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Active { record, selection, .. }) = &mut item.outcome {
                match field {
                    0 => record.poll_interval_ms = Some(20),
                    1 => record.retain_until -= 1,
                    _ => *selection = crate::http_auth::managed::tasks::watch::checkpoint::ManagedTaskWatchCheckpoint::decode(
                        br#"{"format":"fastmcp/task-watch","version":1,"protocolVersion":"2026-07-28","resource":"https://mcp.example/other","taskIds":["handoff"]}"#,
                    ).unwrap(),
                }
            }
            assert!(matches!(item.storage_change(&cx, &binding(1)), Err(TaskResumeError::ConflictingSnapshot)));
            assert_eq!(item.previous.encode().unwrap(), original);
        }
        assert!(handoff_item(&cx, false).storage_change(&cx, &binding(1)).is_ok());
    }

    #[test]
    fn terminal_handoff_preserves_result_and_rejects_fabricated_terminal_kind() {
        let cx = Cx::for_testing();
        let mut item = handoff_item(&cx, true);
        let change = item.storage_change(&cx, &binding(1)).unwrap();
        assert!(change.replacement().is_none());
        let TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Terminal(task)) = &item.outcome
            else { panic!("terminal fixture required"); };
        assert!(serde_json::to_string(task).unwrap().contains("PRIVATE-RESULT"));
        assert!(!format!("{change:?}").contains("PRIVATE"));
        item.outcome = TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Terminal(Box::new(handoff_task("working", 2))));
        assert!(matches!(item.storage_change(&cx, &binding(1)), Err(TaskResumeError::InvalidRecord)));
    }

    #[test]
    fn explicit_discard_does_not_relax_live_expiry_or_structural_validation() {
        let cx = Cx::for_testing();
        let mut previous = record();
        previous.retain_until = super::super::super::timestamp_nanos(&previous.created_at).unwrap() + 2_000_000_000;
        assert_eq!(previous.admit_at(&binding(1), previous.retain_until), Err(TaskResumeError::Unavailable));
        assert!(TaskResumeChange::discard(&cx, &binding(1), &previous).unwrap().replacement().is_none());
        previous.poll_interval_ms = Some(0);
        assert!(matches!(TaskResumeChange::discard(&cx, &binding(1), &previous), Err(TaskResumeError::InvalidRecord)));
        assert!(matches!(TaskResumeChange::discard(&cx, &binding(2), &previous), Err(TaskResumeError::Unavailable)));
    }
}
