//! Notification-driven observation of authenticated Tasks.
//!
//! A watch subscribes and verifies the acknowledgement BEFORE taking its first
//! snapshots. Notifications are invalidations, not authoritative replacements:
//! each one causes a freshly authorized `tasks/get`. A queued old notification
//! therefore cannot replace a newer snapshot, and a completion between listen
//! admission and the first get is still observed. No polling, reconnect,
//! mutation replay, event-history recovery or background worker is installed.

use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::tasks_extension::{Task, TaskId, task_subscription_ids};
use fastmcp_protocol::{CoreRequest, RequestId, SubscriptionFilter};

use super::{
    BoundedWriter, ManagedTaskEvent, ManagedTaskRequest, ManagedTaskRequestIds,
    ManagedTasksClient, ManagedTasksError, OAuthSessionError, deadline_after,
};
use super::super::subscriptions::{
    ManagedSubscription, ManagedSubscriptionError, ManagedSubscriptionEvent,
    ManagedSubscriptionLimits,
};

const MAX_WATCH_TASKS: usize = 128;
const MAX_SELECTION_BYTES: usize = 64 * 1024;

/// One finite budget for discovery, acknowledgement, all snapshot reads and
/// caller pauses. Native transport and original subscription-token deadlines
/// still apply and can end observation earlier. Renewal does not extend an
/// existing subscription; resubscribing after a gap is an explicit new watch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedTaskWatchPolicy {
    timeout: Duration,
    maximum_snapshots: usize,
    maximum_records: usize,
}

impl Default for ManagedTaskWatchPolicy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_mins(15),
            maximum_snapshots: 1024,
            maximum_records: 2048,
        }
    }
}

impl ManagedTaskWatchPolicy {
    /// Records include the subscription acknowledgement, non-Task activity,
    /// duplicate/late notifications and a possible subscription terminal.
    /// Every initial or notification-triggered get consumes one snapshot slot.
    pub fn new(
        timeout: Duration,
        maximum_snapshots: usize,
        maximum_records: usize,
    ) -> Result<Self, ManagedTaskWatchError> {
        if timeout.is_zero()
            || timeout > Duration::from_secs(3600)
            || !(1..=4096).contains(&maximum_snapshots)
            || !(2..=4096).contains(&maximum_records)
        {
            return Err(ManagedTaskWatchError::InvalidPolicy);
        }
        Ok(Self { timeout, maximum_snapshots, maximum_records })
    }
}

/// Why a fresh, authenticated snapshot was requested. In particular, a change
/// notification's embedded snapshot is never passed through as current state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedTaskSnapshotCause {
    Initial,
    ChangeNotification,
}

/// One current Task, including input-required, completed, failed or cancelled
/// states. A terminal Task is not necessarily a successful tool execution.
pub struct ManagedTaskSnapshot {
    pub task: Box<Task>,
    pub cause: ManagedTaskSnapshotCause,
}

/// Errors never retain the task selection, ID prefix, credential or peer body.
#[derive(Debug)]
pub enum ManagedTaskWatchError {
    InvalidPolicy,
    InvalidSelection,
    InvalidIdPrefix,
    IdentityExhausted,
    IncompleteAcknowledgement,
    SnapshotLimit,
    UnexpectedEvent,
    Interrupted,
    Closed,
    Session(OAuthSessionError),
    Task(ManagedTasksError),
    Subscription(ManagedSubscriptionError),
}

impl fmt::Display for ManagedTaskWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(error) => fmt::Display::fmt(error, f),
            Self::Task(error) => fmt::Display::fmt(error, f),
            Self::Subscription(error) => fmt::Display::fmt(error, f),
            Self::InvalidPolicy => f.write_str("invalid managed Task watch policy"),
            Self::InvalidSelection => f.write_str("invalid managed Task watch selection"),
            Self::InvalidIdPrefix => f.write_str("invalid managed Task watch identity prefix"),
            Self::IdentityExhausted => f.write_str("managed Task watch identities exhausted"),
            Self::IncompleteAcknowledgement => f.write_str("Task watch did not acknowledge the complete selection"),
            Self::SnapshotLimit => f.write_str("managed Task watch snapshot budget exhausted"),
            Self::UnexpectedEvent => f.write_str("unexpected managed Task watch event"),
            Self::Interrupted => f.write_str("Task subscription ended before all tasks were terminal"),
            Self::Closed => f.write_str("managed Task watch is closed"),
        }
    }
}

impl std::error::Error for ManagedTaskWatchError {}
impl From<OAuthSessionError> for ManagedTaskWatchError {
    fn from(error: OAuthSessionError) -> Self { Self::Session(error) }
}
impl From<ManagedTasksError> for ManagedTaskWatchError {
    fn from(error: ManagedTasksError) -> Self { Self::Task(error) }
}
impl From<ManagedSubscriptionError> for ManagedTaskWatchError {
    fn from(error: ManagedSubscriptionError) -> Self { Self::Subscription(error) }
}

impl ManagedTasksClient {
    /// Opens one authenticated subscription for 1..=128 distinct task IDs.
    /// The complete selection must be acknowledged before any `tasks/get`.
    /// The first `next_snapshot` calls reconcile all selected tasks in order;
    /// subsequent calls sleep on the live subscription rather than polling.
    ///
    /// Use a different `id_prefix` for concurrent watches in the same endpoint
    /// namespace. Within this watch all discovery, listen and get identities
    /// are generated uniquely. The prefix is bounded to 128 ASCII alphanumeric,
    /// underscore, dash or dot bytes; it is not an idempotency key.
    ///
    /// Each snapshot uses ordinary credential-bound Tasks discovery and get.
    /// Input-required snapshots are delivered to the host for explicit updates.
    /// Closing/dropping/cancelling this watch stops observation, not the remote
    /// tasks. A failed watch never creates, updates or cancels any task.
    pub async fn watch_tasks(
        &self,
        cx: &Cx,
        task_ids: Vec<TaskId>,
        id_prefix: String,
        policy: ManagedTaskWatchPolicy,
    ) -> Result<ManagedTaskWatch, ManagedTaskWatchError> {
        self.watch_tasks_with_cancellation(
            cx, &McpRequestCancellation::new(), task_ids, id_prefix, policy,
        ).await
    }

    /// Retains the supplied cancellation domain across admission, every get,
    /// response read and idle subscription wait. The caller's Cx is never
    /// cancelled. All waits remain driven by this caller, with no orphan task.
    pub async fn watch_tasks_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_ids: Vec<TaskId>,
        id_prefix: String,
        policy: ManagedTaskWatchPolicy,
    ) -> Result<ManagedTaskWatch, ManagedTaskWatchError> {
        self.session.check(cx, cancellation)?;
        let state = WatchState::new(task_ids, policy.maximum_snapshots)?;
        let mut ids = WatchIds::new(id_prefix)?;
        let listen_ids = ids.next_pair()?;
        let request = listen_request(&self.metadata, &state.task_ids)?;
        let limits = ManagedSubscriptionLimits::new(
            self.limits.request_bytes.min(MAX_SELECTION_BYTES),
            self.limits.frame_bytes.min(MAX_SELECTION_BYTES),
            policy.maximum_records,
            policy.timeout,
        )?;
        let deadline = deadline_after(cx, policy.timeout)?;
        let subscription = Box::pin(self.session.await_active(cx, cancellation, deadline, None, async {
            Ok(async {
                let mut subscription = self.session.subscribe_tasks_with_cancellation(
                    cx, cancellation, request, listen_ids.discovery, listen_ids.operation, limits,
                ).await?;
                let Some(ManagedSubscriptionEvent::Acknowledged { accepted_filter }) =
                    subscription.next_event(cx).await?
                else {
                    return Err(ManagedTaskWatchError::UnexpectedEvent);
                };
                state.admit_acknowledgement(&accepted_filter)?;
                Ok(subscription)
            }.await)
        })).await??;
        self.session.check(cx, cancellation)?;
        Ok(ManagedTaskWatch {
            client: self.clone(), cancellation: cancellation.clone(),
            subscription: Some(subscription), state, ids, deadline, finished: false,
        })
    }
}

/// An owned, bounded, non-Clone observation stream. Exactly one fresh terminal
/// snapshot is delivered per selected task. Successful EOF means all selected
/// tasks have delivered a terminal snapshot, not that the SSE body disconnected.
///
/// An abandoned polled read permanently closes this watch: that read owns the
/// subscription and get socket, so partial framing is never reused. Keeping an
/// unpolled watch retains its socket until next poll, explicit close or drop.
pub struct ManagedTaskWatch {
    client: ManagedTasksClient,
    cancellation: McpRequestCancellation,
    subscription: Option<ManagedSubscription>,
    state: WatchState,
    ids: WatchIds,
    deadline: Time,
    finished: bool,
}

impl ManagedTaskWatch {
    /// Number of selected tasks without a delivered terminal snapshot.
    pub fn remaining_tasks(&self) -> usize {
        self.state.terminal.iter().filter(|terminal| !**terminal).count()
    }

    /// Releases observation immediately, without issuing a remote mutation or
    /// cancelling the supplied shared cancellation domain.
    pub fn close(&mut self) {
        self.subscription = None;
    }

    /// Receives a current task snapshot. Late notifications for a task whose
    /// terminal was already delivered consume stream budget but cause neither
    /// another get nor a second terminal delivery. Other admitted non-Task
    /// activity also consumes stream budget and cannot trigger a snapshot.
    pub async fn next_snapshot(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ManagedTaskSnapshot>, ManagedTaskWatchError> {
        if self.finished { return Ok(None); }
        // Transfer custody before the first await. Error/drop does not put this
        // response back into the watch, even while reconciling an initial get.
        let mut subscription = self.subscription.take().ok_or(ManagedTaskWatchError::Closed)?;
        let client = self.client.clone();
        let cancellation = self.cancellation.clone();
        let deadline = self.deadline;
        let snapshot = Box::pin(client.session.await_active(cx, &cancellation, deadline, None, async {
            Ok(async {
                let (task_id, cause) = match self.state.initial.pop_front() {
                    Some(id) => (id, ManagedTaskSnapshotCause::Initial),
                    None => loop {
                        match subscription.next_event(cx).await? {
                            Some(ManagedSubscriptionEvent::TaskNotification(notification)) => {
                                let id = &notification.params.task.base().task_id;
                                if self.state.needs_snapshot(id)? {
                                    break (id.clone(), ManagedTaskSnapshotCause::ChangeNotification);
                                }
                            }
                            Some(ManagedSubscriptionEvent::Notification(_)) => {},
                            Some(ManagedSubscriptionEvent::Terminal { .. }) | None => {
                                return Err(ManagedTaskWatchError::Interrupted);
                            }
                            Some(ManagedSubscriptionEvent::Acknowledged { .. }) => {
                                return Err(ManagedTaskWatchError::UnexpectedEvent);
                            }
                        }
                    },
                };
                self.state.reserve_snapshot()?;
                let ids = self.ids.next_pair()?;
                let mut call = client.request_with_cancellation(
                    cx, &cancellation, ids, ManagedTaskRequest::Get(task_id),
                ).await?;
                let Some(ManagedTaskEvent::Snapshot(result)) = call.next_event(cx).await? else {
                    return Err(ManagedTaskWatchError::UnexpectedEvent);
                };
                Ok(ManagedTaskSnapshot { task: Box::new(result.task), cause })
            }.await)
        })).await??;
        client.session.check(cx, &cancellation)?;
        if cx.now() >= deadline {
            return Err(OAuthSessionError::TimedOut.into());
        }
        // Publication and the terminal ledger change together, after the last
        // lifetime check. Notification payloads never mutate this ledger.
        self.finished = self.state.record_snapshot(&snapshot.task)?;
        if !self.finished {
            self.subscription = Some(subscription);
        }
        Ok(Some(snapshot))
    }
}

fn listen_request(metadata: &serde_json::Value, task_ids: &[TaskId]) -> Result<CoreRequest, ManagedTaskWatchError> {
    CoreRequest::decode(ProtocolEra::Modern2026, "subscriptions/listen", Some(&serde_json::json!({
        "_meta": metadata, "notifications": {"taskIds": task_ids},
    }))).map_err(|_| ManagedTaskWatchError::InvalidSelection)
}

struct WatchIds {
    prefix: String,
    next: u64,
}

impl WatchIds {
    fn new(prefix: String) -> Result<Self, ManagedTaskWatchError> {
        if prefix.is_empty() || prefix.len() > 128
            || !prefix.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(ManagedTaskWatchError::InvalidIdPrefix);
        }
        Ok(Self { prefix, next: 0 })
    }

    fn next_pair(&mut self) -> Result<ManagedTaskRequestIds, ManagedTaskWatchError> {
        let following = self.next.checked_add(2).ok_or(ManagedTaskWatchError::IdentityExhausted)?;
        let ids = ManagedTaskRequestIds::new(
            RequestId::String(format!("{}:{}", self.prefix, self.next)),
            RequestId::String(format!("{}:{}", self.prefix, self.next + 1)),
        )?;
        self.next = following;
        Ok(ids)
    }
}

struct WatchState {
    task_ids: Vec<TaskId>,
    initial: VecDeque<TaskId>,
    terminal: Vec<bool>,
    snapshots: usize,
    maximum_snapshots: usize,
}

impl WatchState {
    fn new(task_ids: Vec<TaskId>, maximum_snapshots: usize) -> Result<Self, ManagedTaskWatchError> {
        if task_ids.is_empty() || task_ids.len() > MAX_WATCH_TASKS || task_ids.len() > maximum_snapshots {
            return Err(ManagedTaskWatchError::InvalidSelection);
        }
        for (index, id) in task_ids.iter().enumerate() {
            if task_ids[..index].contains(id) { return Err(ManagedTaskWatchError::InvalidSelection); }
        }
        let mut writer = BoundedWriter { bytes: Vec::new(), maximum: MAX_SELECTION_BYTES };
        serde_json::to_writer(&mut writer, &task_ids).map_err(|_| ManagedTaskWatchError::InvalidSelection)?;
        Ok(Self {
            terminal: vec![false; task_ids.len()], initial: task_ids.iter().cloned().collect(),
            task_ids, snapshots: 0, maximum_snapshots,
        })
    }

    fn admit_acknowledgement(&self, filter: &SubscriptionFilter) -> Result<(), ManagedTaskWatchError> {
        let accepted = task_subscription_ids(filter).map_err(|_| ManagedTaskWatchError::IncompleteAcknowledgement)?
            .ok_or(ManagedTaskWatchError::IncompleteAcknowledgement)?;
        if accepted.len() != self.task_ids.len()
            || self.task_ids.iter().any(|id| !accepted.contains(id))
        {
            return Err(ManagedTaskWatchError::IncompleteAcknowledgement);
        }
        Ok(())
    }

    fn needs_snapshot(&self, task_id: &TaskId) -> Result<bool, ManagedTaskWatchError> {
        let index = self.task_ids.iter().position(|id| id == task_id)
            .ok_or(ManagedTaskWatchError::UnexpectedEvent)?;
        Ok(!self.terminal[index])
    }

    fn reserve_snapshot(&mut self) -> Result<(), ManagedTaskWatchError> {
        if self.snapshots >= self.maximum_snapshots { return Err(ManagedTaskWatchError::SnapshotLimit); }
        self.snapshots += 1;
        Ok(())
    }

    fn record_snapshot(&mut self, task: &Task) -> Result<bool, ManagedTaskWatchError> {
        let index = self.task_ids.iter().position(|id| id == &task.base().task_id)
            .ok_or(ManagedTaskWatchError::UnexpectedEvent)?;
        if self.terminal[index] { return Err(ManagedTaskWatchError::UnexpectedEvent); }
        self.terminal[index] = matches!(task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_));
        Ok(self.terminal.iter().all(|terminal| *terminal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, FINAL_CLIENT_CAPABILITIES_META_KEY};
    use serde_json::json;

    fn id(value: &str) -> TaskId { TaskId::parse(value).unwrap() }
    fn task(value: &str, status: &str) -> Task {
        serde_json::from_value(json!({
            "taskId":value, "status":status, "createdAt":"2026-09-17T00:00:00Z",
            "lastUpdatedAt":"2026-09-17T00:00:00Z", "ttlMs":60000,
        })).unwrap()
    }
    fn filter(ids: serde_json::Value) -> SubscriptionFilter {
        serde_json::from_value(json!({"taskIds":ids})).unwrap()
    }

    #[test]
    fn selection_is_nonempty_unique_and_fits_the_initial_snapshot_budget() {
        assert!(WatchState::new(vec![id("one"), id("two")], 2).is_ok());
        assert!(WatchState::new(vec![], 2).is_err());
        assert!(WatchState::new(vec![id("one"), id("one")], 2).is_err());
        assert!(WatchState::new(vec![id("one"), id("two")], 1).is_err());
        assert!(WatchState::new((0..129).map(|n| id(&format!("task-{n}"))).collect(), 129).is_err());
    }

    #[test]
    fn acknowledgement_must_cover_every_selected_task_before_reconciliation() {
        let state = WatchState::new(vec![id("one"), id("two")], 8).unwrap();
        assert!(state.admit_acknowledgement(&filter(json!(["two", "one"]))).is_ok());
        for ids in [json!([]), json!(["one"]), json!(["one", "one"]), json!(["one", "other"])] {
            assert!(matches!(state.admit_acknowledgement(&filter(ids)), Err(ManagedTaskWatchError::IncompleteAcknowledgement)));
            assert_eq!(state.initial.len(), 2);
            assert_eq!(state.snapshots, 0);
            assert_eq!(state.terminal, [false, false]);
        }
    }

    #[test]
    fn notification_is_only_an_invalidation_and_cannot_publish_a_terminal() {
        let mut state = WatchState::new(vec![id("one")], 8).unwrap();
        let notification_task = task("one", "cancelled");
        assert!(state.needs_snapshot(&notification_task.base().task_id).unwrap());
        assert_eq!(state.terminal, [false]);
        assert_eq!(state.initial.pop_front(), Some(id("one")));
        assert!(!state.record_snapshot(&task("one", "working")).unwrap());
        assert!(state.record_snapshot(&task("one", "cancelled")).unwrap());
        assert!(!state.needs_snapshot(&id("one")).unwrap());
    }

    #[test]
    fn terminal_delivery_is_per_task_and_stale_events_cannot_regress_it() {
        let mut state = WatchState::new(vec![id("one"), id("two")], 8).unwrap();
        assert!(!state.record_snapshot(&task("one", "cancelled")).unwrap());
        assert!(!state.needs_snapshot(&id("one")).unwrap());
        assert!(state.needs_snapshot(&id("two")).unwrap());
        assert!(state.record_snapshot(&task("one", "working")).is_err());
        assert!(state.record_snapshot(&task("other", "cancelled")).is_err());
        assert_eq!(state.terminal, [true, false]);
        assert!(state.record_snapshot(&task("two", "cancelled")).unwrap());
    }

    #[test]
    fn snapshot_capacity_and_identity_exhaustion_are_checked_before_effects() {
        let mut state = WatchState::new(vec![id("one")], 1).unwrap();
        state.reserve_snapshot().unwrap();
        assert!(matches!(state.reserve_snapshot(), Err(ManagedTaskWatchError::SnapshotLimit)));
        assert_eq!(state.snapshots, 1);
        let mut ids = WatchIds::new("watch".to_owned()).unwrap();
        let first = ids.next_pair().unwrap();
        let second = ids.next_pair().unwrap();
        assert_eq!(first.discovery, RequestId::String("watch:0".to_owned()));
        assert_eq!(first.operation, RequestId::String("watch:1".to_owned()));
        assert_eq!(second.discovery, RequestId::String("watch:2".to_owned()));
        assert_eq!(second.operation, RequestId::String("watch:3".to_owned()));
        ids.next = u64::MAX - 1;
        assert!(matches!(ids.next_pair(), Err(ManagedTaskWatchError::IdentityExhausted)));
        assert_eq!(ids.next, u64::MAX - 1);
    }

    #[test]
    fn policy_and_identity_admission_have_finite_hard_ceilings() {
        assert!(ManagedTaskWatchPolicy::new(Duration::from_secs(1), 1, 2).is_ok());
        assert!(ManagedTaskWatchPolicy::new(Duration::ZERO, 1, 2).is_err());
        assert!(ManagedTaskWatchPolicy::new(Duration::from_secs(3601), 1, 2).is_err());
        assert!(ManagedTaskWatchPolicy::new(Duration::from_secs(1), 0, 2).is_err());
        assert!(ManagedTaskWatchPolicy::new(Duration::from_secs(1), 4097, 2).is_err());
        assert!(ManagedTaskWatchPolicy::new(Duration::from_secs(1), 1, 1).is_err());
        assert!(ManagedTaskWatchPolicy::new(Duration::from_secs(1), 1, 4097).is_err());
        for prefix in ["".to_owned(), "x".repeat(129), "line\nbreak".to_owned(), "a:b".to_owned()] {
            assert!(WatchIds::new(prefix).is_err());
        }
    }

    #[test]
    fn listen_uses_the_existing_tasks_metadata_and_only_the_requested_filter() {
        let metadata = super::super::tasks_metadata(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        let request = listen_request(&metadata, &[id("one"), id("two")]).unwrap();
        let params = request.encode_params().unwrap().unwrap();
        assert_eq!(params["notifications"], json!({"taskIds":["one", "two"]}));
        assert_eq!(params["_meta"], metadata);
        assert_eq!(params["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
            json!({"io.modelcontextprotocol/tasks":{}}));
    }
}
