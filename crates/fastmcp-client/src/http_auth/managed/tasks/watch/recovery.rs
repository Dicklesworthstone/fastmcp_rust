//! Opt-in, bounded recovery of observation after a Task stream interruption.
//!
//! Recovery opens a NEW authenticated listen and then reconciles unfinished
//! tasks with fresh `tasks/get` calls. It does not replay missed notifications,
//! creating calls, input answers or cancellation. No runtime, background worker,
//! durable resume store or cross-login recovery authority is introduced.

use std::fmt;
use std::time::Duration;

use asupersync::Cx;
use asupersync::time::Sleep;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::tasks_extension::{Task, TaskId};

use super::{
    ManagedSubscriptionEvent, ManagedSubscriptionLimits, ManagedTaskSnapshot,
    ManagedTaskSnapshotCause, ManagedTaskWatch, ManagedTaskWatchError,
    ManagedTaskWatchPolicy, ManagedTasksClient, ManagedTasksError,
    OAuthSessionError, WatchState, MAX_SELECTION_BYTES, listen_request,
};
use crate::http_auth::managed::subscriptions::ManagedSubscriptionError;
use crate::http_auth::rpc::interaction::recovery::recovery_http_interruption;

const MAX_RECONNECTIONS: usize = 16;

/// Explicit recovery policy for an observation-only watch.
///
/// `minimum_delay` is also the fallback minimum interval before reconciliation
/// reads. A peer's last admitted `pollIntervalMs` can only lengthen that wait.
/// Backoff doubles across interruptions, including failed reconnects, up to
/// `maximum_delay`. Success does not reset the attempt counter or backoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedTaskRecoveryPolicy {
    maximum_reconnections: usize,
    minimum_delay: Duration,
    maximum_delay: Duration,
}

impl Default for ManagedTaskRecoveryPolicy {
    fn default() -> Self {
        Self {
            maximum_reconnections: 4,
            minimum_delay: Duration::from_secs(1),
            maximum_delay: Duration::from_secs(30),
        }
    }
}

impl ManagedTaskRecoveryPolicy {
    pub fn new(
        maximum_reconnections: usize,
        minimum_delay: Duration,
        maximum_delay: Duration,
    ) -> Result<Self, ManagedTaskRecoveryError> {
        if !(1..=MAX_RECONNECTIONS).contains(&maximum_reconnections)
            || minimum_delay.is_zero()
            || minimum_delay > maximum_delay
            || maximum_delay > Duration::from_secs(60)
        {
            return Err(ManagedTaskRecoveryError::InvalidPolicy);
        }
        Ok(Self { maximum_reconnections, minimum_delay, maximum_delay })
    }

    // Partition, rather than multiply, the original stream-record budget.
    // A closed/failed connection does not refund its reservation: malformed or
    // incomplete input may have consumed work the caller could not observe.
    fn connection_policy(
        self,
        mut watch: ManagedTaskWatchPolicy,
    ) -> Result<ManagedTaskWatchPolicy, ManagedTaskRecoveryError> {
        watch.maximum_records /= self.maximum_reconnections + 1;
        if watch.maximum_records < 2 {
            return Err(ManagedTaskRecoveryError::InvalidPolicy);
        }
        Ok(watch)
    }

    fn delay(self, reconnection: usize) -> Duration {
        let shift = reconnection.saturating_sub(1).min(MAX_RECONNECTIONS) as u32;
        self.minimum_delay.saturating_mul(1u32 << shift).min(self.maximum_delay)
    }
}

/// Recovery never retains Task IDs, notification bodies or bearer material in
/// its additional diagnostics. Non-transient failures keep their typed cause.
#[derive(Debug)]
pub enum ManagedTaskRecoveryError {
    InvalidPolicy,
    RecoveryLimit,
    Watch(ManagedTaskWatchError),
}

impl fmt::Display for ManagedTaskRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => f.write_str("invalid managed Task recovery policy or record reservation"),
            Self::RecoveryLimit => f.write_str("managed Task reconnection budget exhausted"),
            Self::Watch(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ManagedTaskRecoveryError {}
impl From<ManagedTaskWatchError> for ManagedTaskRecoveryError {
    fn from(error: ManagedTaskWatchError) -> Self { Self::Watch(error) }
}
impl From<OAuthSessionError> for ManagedTaskRecoveryError {
    fn from(error: OAuthSessionError) -> Self { Self::Watch(error.into()) }
}

impl ManagedTasksClient {
    /// Opens an observation-only watch with bounded interruption recovery.
    /// Initial discovery/listen admission is attempted once. After admission,
    /// only interrupted transport reads/sends or an ended subscription can
    /// reconnect. Invalid wire data, remote errors, authorization, expiry,
    /// cancellation and resource-limit errors are terminal.
    ///
    /// The original watch deadline and snapshot budget span every connection,
    /// caller pause and backoff. Its record budget is divided equally among
    /// the initial connection and all allowed reconnects; unused reservations
    /// are not recycled. There must be at least two records per connection.
    /// Every new connection revalidates Tasks using the same managed login and
    /// configured endpoint. A terminal Task already delivered is never revived.
    pub async fn watch_tasks_recovering(
        &self,
        cx: &Cx,
        task_ids: Vec<TaskId>,
        id_prefix: String,
        watch_policy: ManagedTaskWatchPolicy,
        recovery_policy: ManagedTaskRecoveryPolicy,
    ) -> Result<RecoveringManagedTaskWatch, ManagedTaskRecoveryError> {
        self.watch_tasks_recovering_with_cancellation(
            cx, &McpRequestCancellation::new(), task_ids, id_prefix,
            watch_policy, recovery_policy,
        ).await
    }

    /// The same request-local cancellation domain owns initial admission,
    /// response reads, backoff, rediscovery and all reconciliation gets.
    /// Neither local cancellation nor recovery sends `tasks/cancel`.
    #[allow(clippy::too_many_arguments)]
    pub async fn watch_tasks_recovering_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_ids: Vec<TaskId>,
        id_prefix: String,
        watch_policy: ManagedTaskWatchPolicy,
        recovery_policy: ManagedTaskRecoveryPolicy,
    ) -> Result<RecoveringManagedTaskWatch, ManagedTaskRecoveryError> {
        let connection_policy = recovery_policy.connection_policy(watch_policy)?;
        let watch = self.watch_tasks_with_cancellation(
            cx, cancellation, task_ids, id_prefix, connection_policy,
        ).await?;
        Ok(RecoveringManagedTaskWatch {
            read_intervals: vec![recovery_policy.minimum_delay; watch.state.task_ids.len()],
            watch: Some(watch), connection_policy, recovery_policy,
            reconnections: 0, finished: false,
        })
    }
}

/// Exclusive, volatile observation custody; there is no mutation/host-input API.
///
/// Every reconnect acknowledges exactly the unfinished selection before any
/// reconciliation read. Notifications remain invalidations, not authoritative
/// snapshots. Completion during a gap is recovered as current state, but an
/// intermediate transition during that gap can be missed. No Last-Event-ID or
/// restart-persistence claim is made.
///
/// Dropping a POLLED `next_snapshot` future permanently closes this owner,
/// including during backoff or admission. An unpolled future does nothing.
#[must_use = "poll snapshots, close explicitly, or drop the observation owner"]
pub struct RecoveringManagedTaskWatch {
    watch: Option<ManagedTaskWatch>,
    connection_policy: ManagedTaskWatchPolicy,
    recovery_policy: ManagedTaskRecoveryPolicy,
    read_intervals: Vec<Duration>,
    reconnections: usize,
    finished: bool,
}

impl RecoveringManagedTaskWatch {
    /// Attempts started after the initial connection, not just successful ones.
    pub fn reconnection_attempts(&self) -> usize { self.reconnections }

    pub fn close(&mut self) { self.watch = None; }

    pub async fn next_snapshot(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ManagedTaskSnapshot>, ManagedTaskRecoveryError> {
        if self.finished { return Ok(None); }
        // Move the ENTIRE watch before awaiting. Cancellation/drop may not put
        // an old response, half-read decoder or retry opportunity back into it.
        let mut watch = self.watch.take().ok_or(ManagedTaskWatchError::Closed)?;
        let client = watch.client.clone();
        let cancellation = watch.cancellation.clone();
        let deadline = watch.deadline;
        let snapshot = Box::pin(client.session.await_active(cx, &cancellation, deadline, None, async {
            Ok(self.next_active(cx, &mut watch).await)
        })).await??;
        client.session.check(cx, &cancellation)?;
        if cx.now() >= deadline { return Err(OAuthSessionError::TimedOut.into()); }
        self.finished = watch.finished;
        if !self.finished { self.watch = Some(watch); }
        Ok(snapshot)
    }

    async fn next_active(
        &mut self,
        cx: &Cx,
        watch: &mut ManagedTaskWatch,
    ) -> Result<Option<ManagedTaskSnapshot>, ManagedTaskRecoveryError> {
        loop {
            match watch.next_snapshot(cx).await {
                Ok(mut snapshot) => {
                    if let Some(snapshot) = &mut snapshot {
                        if self.reconnections > 0 && snapshot.cause == ManagedTaskSnapshotCause::Initial {
                            snapshot.cause = ManagedTaskSnapshotCause::Reconnected;
                        }
                        let index = watch.state.task_ids.iter().position(|id| id == &snapshot.task.base().task_id)
                            .ok_or(ManagedTaskWatchError::UnexpectedEvent)?;
                        if !watch.state.terminal[index] {
                            self.read_intervals[index] = read_interval(&snapshot.task, self.recovery_policy.minimum_delay)?;
                        }
                    }
                    return Ok(snapshot);
                }
                Err(error) if recoverable(&error) => {},
                Err(error) => return Err(error.into()),
            }
            loop {
                let pending = unfinished_selection(&watch.state)?;
                if self.reconnections >= self.recovery_policy.maximum_reconnections {
                    return Err(ManagedTaskRecoveryError::RecoveryLimit);
                }
                self.reconnections += 1;
                let mut delay = self.recovery_policy.delay(self.reconnections);
                for (index, terminal) in watch.state.terminal.iter().enumerate() {
                    if !terminal { delay = delay.max(self.read_intervals[index]); }
                }
                let due = cx.now().saturating_add_nanos(
                    u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX),
                );
                if cx.now() < due { Sleep::new(due).await; }
                watch.client.session.check(cx, &watch.cancellation)?;
                if cx.now() >= watch.deadline { return Err(OAuthSessionError::TimedOut.into()); }
                match reconnect(watch, cx, pending, self.connection_policy).await {
                    Ok(()) => break,
                    Err(error) if recoverable(&error) => {},
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
}

// A failed GET is safe to reconcile; no creating call or update ever reaches
// this classifier. All security/protocol/budget failures deliberately remain
// outside the allowlist, including HTTP status codes and OAuth renewal errors.
fn recoverable(error: &ManagedTaskWatchError) -> bool {
    match error {
        ManagedTaskWatchError::Interrupted
        | ManagedTaskWatchError::Subscription(ManagedSubscriptionError::MissingTerminal)
        | ManagedTaskWatchError::Task(ManagedTasksError::MissingTerminal) => true,
        ManagedTaskWatchError::Subscription(ManagedSubscriptionError::Session(OAuthSessionError::Http(error)))
        | ManagedTaskWatchError::Task(ManagedTasksError::Session(OAuthSessionError::Http(error))) => {
            recovery_http_interruption(error)
        }
        _ => false,
    }
}

fn unfinished_selection(state: &WatchState) -> Result<Vec<TaskId>, ManagedTaskWatchError> {
    let pending: Vec<_> = state.task_ids.iter().zip(&state.terminal)
        .filter(|(_, terminal)| !**terminal).map(|(id, _)| id.clone()).collect();
    if pending.is_empty() { return Err(ManagedTaskWatchError::UnexpectedEvent); }
    if state.snapshots.checked_add(pending.len()).is_none_or(|needed| needed > state.maximum_snapshots) {
        return Err(ManagedTaskWatchError::SnapshotLimit);
    }
    Ok(pending)
}

fn read_interval(task: &Task, minimum: Duration) -> Result<Duration, ManagedTaskWatchError> {
    let peer = task.base().poll_interval_ms.as_ref().map(|hint| hint.try_as_millis())
        .transpose().map_err(|_| ManagedTaskWatchError::UnexpectedEvent)?
        .map(Duration::from_millis).unwrap_or(minimum);
    Ok(peer.max(minimum))
}

async fn reconnect(
    watch: &mut ManagedTaskWatch,
    cx: &Cx,
    pending: Vec<TaskId>,
    policy: ManagedTaskWatchPolicy,
) -> Result<(), ManagedTaskWatchError> {
    let selection = WatchState::new(pending, watch.state.maximum_snapshots)?;
    let ids = watch.ids.next_pair()?;
    let request = listen_request(&watch.client.metadata, &selection.task_ids)?;
    let limits = ManagedSubscriptionLimits::new(
        watch.client.limits.request_bytes.min(MAX_SELECTION_BYTES),
        watch.client.limits.frame_bytes.min(MAX_SELECTION_BYTES),
        policy.maximum_records, policy.timeout,
    )?;
    let mut subscription = watch.client.session.subscribe_tasks_with_cancellation(
        cx, &watch.cancellation, request, ids.discovery, ids.operation, limits,
    ).await?;
    let Some(ManagedSubscriptionEvent::Acknowledged { accepted_filter }) = subscription.next_event(cx).await? else {
        return Err(ManagedTaskWatchError::UnexpectedEvent);
    };
    selection.admit_acknowledgement(&accepted_filter)?;
    watch.client.session.check(cx, &watch.cancellation)?;
    if cx.now() >= watch.deadline { return Err(OAuthSessionError::TimedOut.into()); }
    // Commit only the new initial-read queue and fully admitted response.
    // The original IDs, consumed snapshots, terminal ledger and deadline stay.
    watch.state.initial = selection.initial;
    watch.subscription = Some(subscription);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_executor::ModernHttpExecutorError;
    use serde_json::json;

    fn id(text: &str) -> TaskId { TaskId::parse(text).unwrap() }
    fn working(interval: Option<u64>) -> Task {
        let mut value = json!({
            "taskId":"one", "status":"working", "createdAt":"2026-09-17T00:00:00Z",
            "lastUpdatedAt":"2026-09-17T00:00:00Z", "ttlMs":60000,
        });
        if let Some(interval) = interval { value["pollIntervalMs"] = interval.into(); }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn recovery_partitions_instead_of_resetting_the_original_record_budget() {
        for retries in 1..=MAX_RECONNECTIONS {
            let recovery = ManagedTaskRecoveryPolicy::new(retries, Duration::from_secs(1), Duration::from_secs(30)).unwrap();
            let watch = ManagedTaskWatchPolicy::new(Duration::from_secs(60), 100, 101).unwrap();
            let per = recovery.connection_policy(watch).unwrap();
            assert!(per.maximum_records * (retries + 1) <= watch.maximum_records);
            assert_eq!(per.maximum_snapshots, watch.maximum_snapshots);
            assert_eq!(per.timeout, watch.timeout);
        }
        let tiny = ManagedTaskWatchPolicy::new(Duration::from_secs(60), 100, 9).unwrap();
        assert!(matches!(ManagedTaskRecoveryPolicy::default().connection_policy(tiny), Err(ManagedTaskRecoveryError::InvalidPolicy)));
    }

    #[test]
    fn recovery_policy_and_backoff_have_finite_nonzero_bounds() {
        for (count, low, high) in [(0, 1, 2), (17, 1, 2), (1, 0, 2), (1, 3, 2), (1, 1, 61)] {
            assert!(ManagedTaskRecoveryPolicy::new(count, Duration::from_secs(low), Duration::from_secs(high)).is_err());
        }
        let policy = ManagedTaskRecoveryPolicy::new(4, Duration::from_secs(2), Duration::from_secs(5)).unwrap();
        assert_eq!((1..=4).map(|n| policy.delay(n)).collect::<Vec<_>>(),
            vec![Duration::from_secs(2), Duration::from_secs(4), Duration::from_secs(5), Duration::from_secs(5)]);
    }

    #[test]
    fn reconnection_excludes_delivered_terminals_and_retains_consumed_snapshots() {
        let mut state = WatchState::new(vec![id("one"), id("two")], 3).unwrap();
        state.terminal[0] = true;
        state.snapshots = 2;
        assert_eq!(unfinished_selection(&state).unwrap(), vec![id("two")]);
        state.snapshots = 3;
        assert!(matches!(unfinished_selection(&state), Err(ManagedTaskWatchError::SnapshotLimit)));
        assert_eq!(state.terminal, [true, false]);
        assert_eq!(state.snapshots, 3);
    }

    #[test]
    fn recovery_allowlist_excludes_authentication_protocol_and_budget_failures() {
        assert!(recoverable(&ManagedTaskWatchError::Interrupted));
        assert!(recoverable(&ManagedSubscriptionError::MissingTerminal.into()));
        assert!(recoverable(&ManagedTasksError::MissingTerminal.into()));
        assert!(recoverable(&ManagedSubscriptionError::Session(OAuthSessionError::Http(
            ModernHttpExecutorError::ResponseBodyReadFailed,
        )).into()));
        for error in [
            ManagedTaskWatchError::IncompleteAcknowledgement,
            ManagedTaskWatchError::SnapshotLimit,
            ManagedTaskWatchError::Closed,
            ManagedTaskWatchError::UnexpectedEvent,
            ManagedSubscriptionError::InvalidResponse.into(),
            ManagedSubscriptionError::Negotiation.into(),
            ManagedSubscriptionError::RecordLimit.into(),
            ManagedTasksError::TaskIdMismatch.into(),
            ManagedTasksError::RecordLimit.into(),
            ManagedTasksError::HttpStatus { status: 503 }.into(),
            OAuthSessionError::Cancelled.into(),
            OAuthSessionError::TimedOut.into(),
            OAuthSessionError::LoginRequired.into(),
            OAuthSessionError::AuthorizationRejected { status: 401 }.into(),
        ] {
            assert!(!recoverable(&error), "must not retry {error}");
        }
    }

    #[test]
    fn reconciliation_honors_peer_minimum_and_clears_absent_snapshot_hint() {
        let minimum = Duration::from_secs(1);
        assert_eq!(read_interval(&working(Some(3000)), minimum).unwrap(), Duration::from_secs(3));
        assert_eq!(read_interval(&working(None), minimum).unwrap(), minimum);
        assert_eq!(read_interval(&working(Some(1)), minimum).unwrap(), minimum);
    }
}
