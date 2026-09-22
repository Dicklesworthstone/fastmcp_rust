//! Bounded recovery of machine-authenticated Task observation.
//!
//! Each replacement listen is freshly authenticated and acknowledges exactly
//! the unfinished selection before reconciliation gets. Only ended streams and
//! natural credential expiry are recoverable. Revocation, failed grants, HTTP
//! refusals, malformed responses and opaque transport failures stay terminal.
//! No creating call, input answer or cancellation can enter this owner.

use std::fmt;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::time::Sleep;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::tasks_extension::{Task, TaskId};

use super::{
    ClientCredentialsError, ClientCredentialsSnapshot, ClientCredentialsSubscriptionLimits,
    ClientCredentialsTaskWatch, ClientCredentialsTaskWatchError, ClientCredentialsTaskWatchPolicy,
    ClientCredentialsTasksClient, ClientCredentialsTasksError, ManagedTaskSnapshot,
    ManagedTaskSnapshotCause, ManagedTasksError, ModernHttpSubscriptionListenEvent,
    OAuthDiscoveryError, WatchState, MAX_SELECTION_BYTES, active, check_watch, copy_binding,
};

const MAX_RECONNECTIONS: usize = 16;

/// Opt-in recovery of observation under the same immutable machine registration.
/// Attempts, including unsuccessful opens, consume one budget across the watch.
/// Backoff doubles without resetting after success. A Task's admitted polling
/// interval can lengthen the delay but never extend the original deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientCredentialsTaskRecoveryPolicy {
    maximum_reconnections: usize,
    minimum_delay: Duration,
    maximum_delay: Duration,
}

impl Default for ClientCredentialsTaskRecoveryPolicy {
    fn default() -> Self {
        Self {
            maximum_reconnections: 4,
            minimum_delay: Duration::from_secs(1),
            maximum_delay: Duration::from_secs(30),
        }
    }
}

impl ClientCredentialsTaskRecoveryPolicy {
    pub fn new(
        maximum_reconnections: usize,
        minimum_delay: Duration,
        maximum_delay: Duration,
    ) -> Result<Self, ClientCredentialsTaskRecoveryError> {
        if !(1..=MAX_RECONNECTIONS).contains(&maximum_reconnections)
            || minimum_delay.is_zero()
            || minimum_delay > maximum_delay
            || maximum_delay > Duration::from_secs(60)
        {
            return Err(ClientCredentialsTaskRecoveryError::InvalidPolicy);
        }
        Ok(Self { maximum_reconnections, minimum_delay, maximum_delay })
    }

    fn connection_policy(
        self,
        mut watch: ClientCredentialsTaskWatchPolicy,
    ) -> Result<ClientCredentialsTaskWatchPolicy, ClientCredentialsTaskRecoveryError> {
        // Reserve rather than multiply the original record budget. A failed
        // connection does not refund records that may already have been read.
        watch.maximum_records /= self.maximum_reconnections + 1;
        if watch.maximum_records < 2 {
            return Err(ClientCredentialsTaskRecoveryError::InvalidPolicy);
        }
        Ok(watch)
    }

    fn delay(self, attempt: usize) -> Duration {
        let shift = attempt.saturating_sub(1).min(MAX_RECONNECTIONS) as u32;
        self.minimum_delay.saturating_mul(1_u32 << shift).min(self.maximum_delay)
    }
}

/// Fixed diagnostics, with the typed final cause retained even on exhaustion.
#[derive(Debug)]
pub enum ClientCredentialsTaskRecoveryError {
    InvalidPolicy,
    RecoveryLimit { last_error: ClientCredentialsTaskWatchError },
    Watch(ClientCredentialsTaskWatchError),
}

impl fmt::Display for ClientCredentialsTaskRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => f.write_str("invalid machine Task recovery policy or record reservation"),
            Self::RecoveryLimit { .. } => f.write_str("machine Task reconnection budget exhausted"),
            Self::Watch(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ClientCredentialsTaskRecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RecoveryLimit { last_error } | Self::Watch(last_error) => Some(last_error),
            Self::InvalidPolicy => None,
        }
    }
}
impl From<ClientCredentialsTaskWatchError> for ClientCredentialsTaskRecoveryError {
    fn from(error: ClientCredentialsTaskWatchError) -> Self { Self::Watch(error) }
}
impl From<ClientCredentialsError> for ClientCredentialsTaskRecoveryError {
    fn from(error: ClientCredentialsError) -> Self { Self::Watch(error.into()) }
}

impl ClientCredentialsTasksClient {
    /// Watches existing Tasks with bounded recovery after an admitted stream
    /// ends or its credential naturally expires. Initial admission is attempted
    /// once. Each replacement may acquire a token through the SAME machine
    /// client, then negotiates both extensions and acknowledges the unfinished
    /// selection before fetching current state. Revocation never authorizes
    /// renewal. Grant failures and ambiguous transport errors are not retried.
    ///
    /// Snapshot and correlation counters, the original watch deadline, caller
    /// cancellation and delivered terminal states survive every replacement.
    /// The record budget is partitioned among the initial connection and all
    /// allowed reconnects, with at least two records reserved for each.
    pub async fn watch_tasks_recovering(
        &self,
        cx: &Cx,
        task_ids: Vec<TaskId>,
        id_prefix: String,
        watch_policy: ClientCredentialsTaskWatchPolicy,
        recovery_policy: ClientCredentialsTaskRecoveryPolicy,
    ) -> Result<RecoveringClientCredentialsTaskWatch, ClientCredentialsTaskRecoveryError> {
        self.watch_tasks_recovering_with_cancellation(
            cx, &McpRequestCancellation::new(), task_ids, id_prefix,
            watch_policy, recovery_policy,
        ).await
    }

    /// Cancellation includes backoff, token acquisition, discovery, ACK and
    /// reconciliation. It ends only observation; no `tasks/cancel` is sent.
    #[allow(clippy::too_many_arguments)]
    pub async fn watch_tasks_recovering_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_ids: Vec<TaskId>,
        id_prefix: String,
        watch_policy: ClientCredentialsTaskWatchPolicy,
        recovery_policy: ClientCredentialsTaskRecoveryPolicy,
    ) -> Result<RecoveringClientCredentialsTaskWatch, ClientCredentialsTaskRecoveryError> {
        let connection_policy = recovery_policy.connection_policy(watch_policy)?;
        let watch = self.watch_tasks_with_cancellation(
            cx, cancellation, task_ids, id_prefix, connection_policy,
        ).await?;
        let intervals = vec![recovery_policy.minimum_delay; watch.state.task_ids.len()];
        Ok(RecoveringClientCredentialsTaskWatch {
            watch: Some(watch), connection_policy, policy: recovery_policy,
            intervals, reconnections: 0, finished: false,
        })
    }
}

/// Exclusive, caller-polled observation owner. Recovery reconciles current
/// snapshots, not event history: intermediate changes during a gap may be lost.
/// Already-delivered terminal Tasks are never selected again. Reconciliation
/// snapshots carry `Reconnected`, not `Initial` or a replayed notification.
///
/// Dropping a polled read permanently closes this owner, including during
/// backoff and reauthorization. An unpolled read has no effect. There is no
/// background task, mutation API, persistence or exactly-once execution claim.
#[must_use = "poll snapshots, close explicitly, or drop the observation owner"]
pub struct RecoveringClientCredentialsTaskWatch {
    watch: Option<ClientCredentialsTaskWatch>,
    connection_policy: ClientCredentialsTaskWatchPolicy,
    policy: ClientCredentialsTaskRecoveryPolicy,
    intervals: Vec<Duration>,
    reconnections: usize,
    finished: bool,
}

impl RecoveringClientCredentialsTaskWatch {
    pub fn reconnection_attempts(&self) -> usize { self.reconnections }

    /// Releases local observation only, without changing the machine client,
    /// the caller's cancellation domain or any remote Task.
    pub fn close(&mut self) { self.watch = None; }

    pub async fn next_snapshot(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ManagedTaskSnapshot>, ClientCredentialsTaskRecoveryError> {
        if self.finished { return Ok(None); }
        // Take the entire owner before the first await. An abandoned read must
        // not leave a partial response or an unused retry opportunity reusable.
        let mut watch = self.watch.take().ok_or(ClientCredentialsTaskWatchError::Closed)?;
        let owner = watch.client.client.inner.closed.clone();
        let cancellation = watch.cancellation.clone();
        let deadline = watch.deadline;
        let snapshot = Box::pin(active(cx, deadline, &owner, &cancellation, None, async {
            Ok(self.next_inner(cx, &mut watch).await)
        })).await??;
        self.finished = watch.finished;
        if !self.finished { self.watch = Some(watch); }
        Ok(snapshot)
    }

    async fn next_inner(
        &mut self,
        cx: &Cx,
        watch: &mut ClientCredentialsTaskWatch,
    ) -> Result<Option<ManagedTaskSnapshot>, ClientCredentialsTaskRecoveryError> {
        loop {
            match watch.next_snapshot(cx).await {
                Ok(mut snapshot) => {
                    if let Some(snapshot) = &mut snapshot {
                        if self.reconnections > 0 && snapshot.cause == ManagedTaskSnapshotCause::Initial {
                            snapshot.cause = ManagedTaskSnapshotCause::Reconnected;
                        }
                        let index = watch.state.task_ids.iter()
                            .position(|id| id == &snapshot.task.base().task_id)
                            .ok_or(ClientCredentialsTaskWatchError::UnexpectedEvent)?;
                        if !watch.state.terminal[index] {
                            self.intervals[index] = read_interval(&snapshot.task, self.policy.minimum_delay)?;
                        }
                    }
                    return Ok(snapshot);
                }
                Err(error) => self.reconnect_after(cx, watch, error).await?,
            }
        }
    }

    async fn reconnect_after(
        &mut self,
        cx: &Cx,
        watch: &mut ClientCredentialsTaskWatch,
        mut error: ClientCredentialsTaskWatchError,
    ) -> Result<(), ClientCredentialsTaskRecoveryError> {
        if !recoverable(&error, &watch.binding, Instant::now()) {
            return Err(error.into());
        }
        watch.close();
        loop {
            // A revocation racing a disconnected stream or backoff must never
            // become an invitation to replace the revoked credential.
            if watch.binding.bearer.is_revoked() {
                return Err(ClientCredentialsError::Expired.into());
            }
            let pending = pending_indices(&watch.state)?;
            if self.reconnections >= self.policy.maximum_reconnections {
                return Err(ClientCredentialsTaskRecoveryError::RecoveryLimit { last_error: error });
            }
            self.reconnections += 1;
            let delay = pending.iter().fold(self.policy.delay(self.reconnections), |delay, index| {
                delay.max(self.intervals[*index])
            });
            let due = cx.now().saturating_add_nanos(
                u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX),
            );
            if due >= watch.deadline {
                return Err(ClientCredentialsError::from(OAuthDiscoveryError::TimedOut).into());
            }
            Sleep::new(due).await;
            match reconnect(watch, cx, &pending, self.connection_policy).await {
                Ok(()) => return Ok(()),
                // An ended replacement before ACK may consume another reserved
                // connection. Never loop on grant, expiry, security or opaque
                // transport errors arising during this new authorization.
                Err(next) if interrupted(&next) => error = next,
                Err(next) => return Err(next.into()),
            }
        }
    }
}

fn interrupted(error: &ClientCredentialsTaskWatchError) -> bool {
    matches!(error,
        ClientCredentialsTaskWatchError::Interrupted
        | ClientCredentialsTaskWatchError::Task(ClientCredentialsTasksError::Protocol(
            ManagedTasksError::MissingTerminal
        ))
    )
}

fn recoverable(
    error: &ClientCredentialsTaskWatchError,
    binding: &ClientCredentialsSnapshot,
    now: Instant,
) -> bool {
    if binding.bearer.is_revoked() { return false; }
    interrupted(error) || (now >= binding.expires_at && matches!(error,
        ClientCredentialsTaskWatchError::Task(ClientCredentialsTasksError::Authentication(
            ClientCredentialsError::Expired
            | ClientCredentialsError::Discovery(OAuthDiscoveryError::TimedOut)
        ))
    ))
}

fn pending_indices(state: &WatchState) -> Result<Vec<usize>, ClientCredentialsTaskWatchError> {
    let pending: Vec<_> = state.terminal.iter().enumerate()
        .filter(|(_, terminal)| !**terminal).map(|(index, _)| index).collect();
    if pending.is_empty() { return Err(ClientCredentialsTaskWatchError::UnexpectedEvent); }
    if state.snapshots.checked_add(pending.len())
        .is_none_or(|needed| needed > state.maximum_snapshots)
    {
        return Err(ClientCredentialsTaskWatchError::SnapshotLimit);
    }
    Ok(pending)
}

fn read_interval(task: &Task, minimum: Duration) -> Result<Duration, ClientCredentialsTaskWatchError> {
    let peer = task.base().poll_interval_ms.as_ref().map(|hint| hint.try_as_millis())
        .transpose().map_err(|_| ClientCredentialsTaskWatchError::UnexpectedEvent)?
        .map(Duration::from_millis).unwrap_or(minimum);
    Ok(peer.max(minimum))
}

async fn reconnect(
    watch: &mut ClientCredentialsTaskWatch,
    cx: &Cx,
    pending: &[usize],
    policy: ClientCredentialsTaskWatchPolicy,
) -> Result<(), ClientCredentialsTaskWatchError> {
    if watch.binding.bearer.is_revoked() { return Err(ClientCredentialsError::Expired.into()); }
    let selected: Vec<_> = pending.iter().map(|index| watch.state.task_ids[*index].clone()).collect();
    let selection = WatchState::new(selected, watch.state.maximum_snapshots - watch.state.snapshots)?;
    let (discovery_id, request_id) = watch.ids.next_pair()?;
    let limits = ClientCredentialsSubscriptionLimits::new(
        watch.client.limits.request_bytes.min(MAX_SELECTION_BYTES),
        watch.client.limits.frame_bytes.min(MAX_SELECTION_BYTES),
        policy.maximum_records, policy.timeout,
    )?;
    let mut subscription = watch.client.subscribe_with_cancellation(
        cx, &watch.cancellation, discovery_id, request_id, selection.filter()?, limits,
    ).await?;
    let Some(ModernHttpSubscriptionListenEvent::Acknowledged { accepted_filter }) =
        subscription.next_event(cx).await?
    else { return Err(ClientCredentialsTaskWatchError::UnexpectedEvent); };
    selection.admit_acknowledgement(&accepted_filter)?;
    if watch.binding.bearer.is_revoked() { return Err(ClientCredentialsError::Expired.into()); }
    let binding = copy_binding(&subscription.snapshot);
    check_watch(cx, watch.deadline, &watch.client.client.inner.closed, &watch.cancellation, &binding)?;
    // Retain global counters and terminal states. Only the response owner,
    // pinned credential and unfinished initial-read queue are replaced.
    watch.binding = binding;
    watch.subscription = Some(subscription);
    watch.state.initial = pending.iter().copied().collect();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_auth::BoundBearerCredential;
    use super::super::tests::{consumer, runtime};

    fn id(value: &str) -> TaskId { TaskId::parse(value).unwrap() }
    fn binding(now: Instant) -> ClientCredentialsSnapshot {
        let client = consumer();
        let expires_at = now + Duration::from_secs(10);
        let bearer = BoundBearerCredential::bind_with_expiry(
            client.client.resource().clone(), "recovery-test-access", expires_at,
        ).unwrap();
        ClientCredentialsSnapshot { bearer, scopes: vec![], expires_at, generation: 1 }
    }

    #[test]
    fn record_reservations_partition_instead_of_multiplying_the_budget() {
        let recovery = ClientCredentialsTaskRecoveryPolicy::default();
        let watch = ClientCredentialsTaskWatchPolicy::new(Duration::from_secs(30), 16, 11).unwrap();
        let connection = recovery.connection_policy(watch).unwrap();
        assert_eq!(connection.maximum_records, 2);
        assert!(connection.maximum_records * (recovery.maximum_reconnections + 1) <= watch.maximum_records);
        assert_eq!(connection.maximum_snapshots, watch.maximum_snapshots);
        assert_eq!(connection.timeout, watch.timeout);
        let too_small = ClientCredentialsTaskWatchPolicy::new(Duration::from_secs(30), 16, 9).unwrap();
        assert!(matches!(recovery.connection_policy(too_small), Err(ClientCredentialsTaskRecoveryError::InvalidPolicy)));
    }

    #[test]
    fn policy_rejects_unbounded_or_busy_reconnection_and_caps_backoff() {
        let second = Duration::from_secs(1);
        for (count, minimum, maximum) in [
            (0, second, second), (17, second, second),
            (1, Duration::ZERO, second), (1, second, Duration::ZERO),
            (1, second, Duration::from_secs(61)),
        ] {
            assert!(ClientCredentialsTaskRecoveryPolicy::new(count, minimum, maximum).is_err());
        }
        let policy = ClientCredentialsTaskRecoveryPolicy::new(16, second, Duration::from_secs(3)).unwrap();
        assert_eq!(policy.delay(1), second);
        assert_eq!(policy.delay(2), Duration::from_secs(2));
        assert_eq!(policy.delay(3), Duration::from_secs(3));
        assert_eq!(policy.delay(usize::MAX), Duration::from_secs(3));
    }

    #[test]
    fn reconciliation_retains_terminal_state_and_consumed_snapshot_budget() {
        let mut state = WatchState::new(vec![id("one"), id("two")], 4).unwrap();
        state.terminal[0] = true;
        state.snapshots = 3;
        assert_eq!(pending_indices(&state).unwrap(), [1]);
        assert_eq!(state.terminal, [true, false]);
        assert_eq!(state.snapshots, 3);
        state.snapshots = 4;
        assert!(matches!(pending_indices(&state), Err(ClientCredentialsTaskWatchError::SnapshotLimit)));
        assert_eq!(state.snapshots, 4);
        state.terminal[1] = true;
        assert!(matches!(pending_indices(&state), Err(ClientCredentialsTaskWatchError::UnexpectedEvent)));
    }

    #[test]
    fn only_natural_expiry_not_revocation_or_arbitrary_timeouts_authorizes_renewal() {
        let now = Instant::now();
        let binding = binding(now);
        for error in [
            ClientCredentialsTaskWatchError::from(ClientCredentialsError::Expired),
            ClientCredentialsTaskWatchError::from(ClientCredentialsError::from(OAuthDiscoveryError::TimedOut)),
        ] {
            assert!(!recoverable(&error, &binding, now));
            assert!(recoverable(&error, &binding, binding.expires_at));
        }
        binding.bearer.revoke();
        assert!(!recoverable(&ClientCredentialsError::Expired.into(), &binding, binding.expires_at));
        assert!(!recoverable(&ClientCredentialsTaskWatchError::Interrupted, &binding, binding.expires_at));
    }

    #[test]
    fn recovery_does_not_reinterpret_security_protocol_or_resource_failures() {
        let binding = binding(Instant::now());
        let now = binding.expires_at;
        assert!(recoverable(&ClientCredentialsTaskWatchError::Interrupted, &binding, now));
        assert!(recoverable(&ManagedTasksError::MissingTerminal.into(), &binding, now));
        for error in [
            ClientCredentialsError::Transport.into(),
            ClientCredentialsError::TokenEndpointRejected.into(),
            ClientCredentialsError::InvalidToken.into(),
            ClientCredentialsError::Negotiation.into(),
            ClientCredentialsError::Closed.into(),
            ClientCredentialsError::from(OAuthDiscoveryError::Cancelled).into(),
            ManagedTasksError::HttpStatus { status: 401 }.into(),
            ManagedTasksError::HttpStatus { status: 503 }.into(),
            ManagedTasksError::Remote { code: serde_json::from_str("-32603").unwrap() }.into(),
            ManagedTasksError::InvalidResponse.into(),
            ClientCredentialsTaskWatchError::IncompleteAcknowledgement,
            ClientCredentialsTaskWatchError::SnapshotLimit,
        ] {
            assert!(!recoverable(&error, &binding, now));
        }
    }

    #[test]
    fn exhausted_recovery_retains_the_exact_typed_cause_without_peer_text() {
        let error = ClientCredentialsTaskRecoveryError::RecoveryLimit {
            last_error: ManagedTasksError::MissingTerminal.into(),
        };
        assert!(std::error::Error::source(&error).is_some());
        assert!(matches!(error, ClientCredentialsTaskRecoveryError::RecoveryLimit {
            last_error: ClientCredentialsTaskWatchError::Task(ClientCredentialsTasksError::Protocol(
                ManagedTasksError::MissingTerminal
            ))
        }));
    }

    #[test]
    fn public_recovery_preflight_and_cancellation_do_not_acquire_credentials() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let client = consumer();
            let policy = ClientCredentialsTaskRecoveryPolicy::default();
            let too_small = ClientCredentialsTaskWatchPolicy::new(Duration::from_secs(1), 1, 2).unwrap();
            assert!(matches!(Box::pin(client.watch_tasks_recovering(
                &cx, vec![id("one")], "safe".to_owned(), too_small, policy,
            )).await, Err(ClientCredentialsTaskRecoveryError::InvalidPolicy)));
            for closed in [false, true] {
                let client = consumer();
                let cancel = McpRequestCancellation::new();
                if closed { client.client.close(); } else { cancel.cancel(); }
                let result = Box::pin(client.watch_tasks_recovering_with_cancellation(
                    &cx, &cancel, vec![id("one")], "safe".to_owned(),
                    ClientCredentialsTaskWatchPolicy::default(), policy,
                )).await;
                match result {
                    Err(ClientCredentialsTaskRecoveryError::Watch(ClientCredentialsTaskWatchError::Task(
                        ClientCredentialsTasksError::Authentication(error),
                    ))) => {
                        if closed { assert!(matches!(error, ClientCredentialsError::Closed)); }
                        else { assert!(matches!(error, ClientCredentialsError::Discovery(OAuthDiscoveryError::Cancelled))); }
                    }
                    _ => panic!("cancelled or closed owner must fail before acquisition"),
                }
                assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
            }
            assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
        });
    }
}
