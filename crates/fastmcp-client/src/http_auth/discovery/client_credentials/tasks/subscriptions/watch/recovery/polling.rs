//! Caller-driven liveness fallback. No notification parser is retained after
//! a timer abandons its read; every fallback result comes from a fresh Get.

use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_protocol::tasks_extension::Task;

use super::{ClientCredentialsTaskRecoveryError, RecoveryState, read_interval};
use super::super::{
    ClientCredentialsError, ClientCredentialsSnapshot, ClientCredentialsTaskWatch,
    ClientCredentialsTaskWatchError, ManagedTaskEvent, ManagedTaskRequest, ManagedTaskSnapshot,
    ManagedTaskSnapshotCause, OAuthDiscoveryError, active, check_watch, copy_binding, request_pinned,
};

#[derive(Clone, Copy)]
struct Slot {
    interval: Duration,
    due: Option<Time>,
}

// One slot per already-admitted selection (at most 128), never per event.
// Deadlines survive caller pauses. A tie rotates rather than starving a Task
// whose peer selected the same interval as an earlier selection member.
pub(super) struct PollFallback {
    minimum: Duration,
    slots: Vec<Slot>,
    cursor: usize,
    active: bool,
    attempts: usize,
}

impl PollFallback {
    pub(super) fn new(count: usize, minimum: Duration) -> Self {
        Self {
            minimum, slots: vec![Slot { interval: minimum, due: None }; count],
            cursor: 0, active: false, attempts: 0,
        }
    }

    pub(super) fn start(&mut self) { self.active = true; }
    pub(super) fn attempts(&self) -> usize { self.attempts }

    pub(super) fn record(&mut self, index: usize, task: &Task)
        -> Result<(), ClientCredentialsTaskWatchError>
    {
        let interval = read_interval(task, self.minimum)?;
        let slot = self.slots.get_mut(index).ok_or(ClientCredentialsTaskWatchError::UnexpectedEvent)?;
        slot.interval = interval;
        // A post-update snapshot can arrive outside next_snapshot. Without its
        // clock, conservatively anchor this new hint at the NEXT read admission;
        // never poll immediately using an old, already-due deadline.
        slot.due = None;
        Ok(())
    }

    fn anchor(&mut self, index: usize, now: Time) -> Result<(), ClientCredentialsTaskWatchError> {
        let slot = self.slots.get_mut(index).ok_or(ClientCredentialsTaskWatchError::UnexpectedEvent)?;
        slot.due = Some(after(now, slot.interval));
        Ok(())
    }

    fn next(&mut self, terminal: &[bool], now: Time)
        -> Result<(usize, Time), ClientCredentialsTaskWatchError>
    {
        if terminal.len() != self.slots.len() || self.slots.is_empty() {
            return Err(ClientCredentialsTaskWatchError::UnexpectedEvent);
        }
        let mut next: Option<(usize, Time)> = None;
        for offset in 0..self.slots.len() {
            let index = (self.cursor + offset) % self.slots.len();
            if terminal[index] { continue; }
            let slot = &mut self.slots[index];
            let interval = slot.interval;
            let due = *slot.due.get_or_insert_with(|| after(now, interval));
            if next.is_none_or(|(_, earliest)| due < earliest) { next = Some((index, due)); }
        }
        next.ok_or(ClientCredentialsTaskWatchError::UnexpectedEvent)
    }

    fn reserve(&mut self, index: usize) -> Result<(), ClientCredentialsTaskWatchError> {
        if index >= self.slots.len() { return Err(ClientCredentialsTaskWatchError::UnexpectedEvent); }
        self.attempts = self.attempts.checked_add(1).ok_or(ClientCredentialsTaskWatchError::SnapshotLimit)?;
        self.cursor = (index + 1) % self.slots.len();
        Ok(())
    }
}

fn after(now: Time, interval: Duration) -> Time {
    now.saturating_add_nanos(u64::try_from(interval.as_nanos()).unwrap_or(u64::MAX))
}

// Poll the existing operation FIRST: a ready result, protocol refusal or
// cancellation is never laundered into a timer-triggered network attempt.
// Both futures are destroyed before returning, including on abandonment.
pub(super) async fn until_due<F: Future>(operation: F, due: Time) -> Option<F::Output> {
    let mut operation = std::pin::pin!(operation);
    let mut timer = std::pin::pin!(Sleep::new(due));
    poll_fn(|cx| {
        if let Poll::Ready(result) = operation.as_mut().poll(cx) { return Poll::Ready(Some(result)); }
        if timer.as_mut().poll(cx).is_ready() { Poll::Ready(None) } else { Poll::Pending }
    }).await
}

impl RecoveryState {
    pub(super) fn polling_active(&self) -> bool {
        self.polling.as_ref().is_some_and(|polling| polling.active)
    }

    pub(super) fn fallback_deadline(&mut self, cx: &Cx, watch: &ClientCredentialsTaskWatch)
        -> Result<Option<Time>, ClientCredentialsTaskWatchError>
    {
        // An admission failure, Closed owner, or unfinished initial selection
        // is never permission to enter polling instead of its original path.
        if watch.finished || !watch.state.initial.is_empty() || watch.subscription.is_none() {
            return Ok(None);
        }
        self.polling.as_mut().map(|polling| polling.next(&watch.state.terminal, cx.now())
            .map(|(_, due)| due)).transpose()
    }

    pub(super) fn anchor_poll(&mut self, cx: &Cx, watch: &ClientCredentialsTaskWatch, task: &Task)
        -> Result<(), ClientCredentialsTaskWatchError>
    {
        let Some(polling) = &mut self.polling else { return Ok(()); };
        let index = watch.state.task_ids.iter().position(|id| id == &task.base().task_id)
            .ok_or(ClientCredentialsTaskWatchError::UnexpectedEvent)?;
        if !watch.state.terminal[index] { polling.anchor(index, cx.now())?; }
        Ok(())
    }

    pub(super) async fn polling_snapshot(
        &mut self, cx: &Cx, watch: &mut ClientCredentialsTaskWatch,
        pinned: Option<&ClientCredentialsSnapshot>,
    ) -> Result<Option<ManagedTaskSnapshot>, ClientCredentialsTaskRecoveryError> {
        if watch.finished { return Ok(None); }
        let client = watch.client.clone();
        let cancellation = watch.cancellation.clone();
        let binding = copy_binding(pinned.unwrap_or(&watch.binding));
        let deadline = cx.budget().deadline.map_or(watch.deadline, |parent| parent.min(watch.deadline));
        check_watch(cx, deadline, &client.client.inner.closed, &cancellation, &binding)?;
        let polling = self.polling.as_mut().filter(|polling| polling.active)
            .ok_or(ClientCredentialsTaskWatchError::Closed)?;
        let (index, due) = polling.next(&watch.state.terminal, cx.now())?;
        if due >= deadline {
            return Err(ClientCredentialsError::from(OAuthDiscoveryError::TimedOut).into());
        }
        // No fresh credential is acquired, including in the read-only wrapper.
        // A timer or error cannot transform an expired/revoked subscription's
        // authority into a new grant. One original bound includes the sleep.
        let snapshot = Box::pin(active(cx, deadline, &client.client.inner.closed, &cancellation, Some(&binding), async {
            Ok(async {
                Sleep::new(due).await;
                check_watch(cx, deadline, &client.client.inner.closed, &cancellation, &binding)?;
                watch.state.reserve_snapshot()?;
                let ids = watch.ids.next_pair()?;
                self.polling.as_mut().ok_or(ClientCredentialsTaskWatchError::Closed)?.reserve(index)?;
                let mut call = request_pinned(&client, cx, &cancellation, &binding, deadline, ids,
                    ManagedTaskRequest::Get(watch.state.task_ids[index].clone())).await?;
                let Some(ManagedTaskEvent::Snapshot(result)) = call.next_event(cx).await? else {
                    return Err(ClientCredentialsTaskWatchError::UnexpectedEvent);
                };
                check_watch(cx, deadline, &client.client.inner.closed, &cancellation, &binding)?;
                watch.finished = watch.state.record_snapshot(&result.task)?;
                self.record_snapshot(watch, &result.task)?;
                self.anchor_poll(cx, watch, &result.task)?;
                Ok::<_, ClientCredentialsTaskWatchError>(ManagedTaskSnapshot {
                    task: Box::new(result.task), cause: ManagedTaskSnapshotCause::PollingFallback,
                })
            }.await)
        })).await??;
        Ok(Some(snapshot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::task::{Context, Waker};
    use std::time::Instant;
    use fastmcp_core::McpRequestCancellation;
    use fastmcp_protocol::tasks_extension::TaskId;
    use super::super::ClientCredentialsTaskRecoveryPolicy;
    use super::super::super::tests::{consumer, runtime};
    use super::super::super::{
        ClientCredentialsTaskWatchPolicy, ClientCredentialsTasksError, ManagedTasksError, WatchState,
    };
    use crate::http_auth::BoundBearerCredential;

    fn local_watch(cx: &Cx) -> ClientCredentialsTaskWatch {
        let client = consumer();
        let expires_at = Instant::now() + Duration::from_secs(10);
        let bearer = BoundBearerCredential::bind_with_expiry(
            client.client.resource().clone(), "polling-test-access", expires_at,
        ).unwrap();
        ClientCredentialsTaskWatch {
            client, cancellation: McpRequestCancellation::new(),
            binding: ClientCredentialsSnapshot { bearer, scopes: vec![], expires_at, generation: 1 },
            subscription: None, state: WatchState::new(vec![TaskId::parse("one").unwrap()], 8).unwrap(),
            ids: super::super::super::WatchIds::new("fallback".to_owned()).unwrap(),
            deadline: cx.now().saturating_add_nanos(5_000_000_000), finished: false,
        }
    }

    fn task(id: &str, interval: Option<u64>) -> Task {
        let mut value = serde_json::json!({"taskId":id, "status":"working", "ttlMs":null,
            "createdAt":"2020-01-01T00:00:00Z", "lastUpdatedAt":"2020-01-01T00:00:01Z"});
        if let Some(interval) = interval { value["pollIntervalMs"] = serde_json::json!(interval); }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn fallback_is_explicit_and_has_a_positive_bounded_local_interval() {
        let original = ClientCredentialsTaskRecoveryPolicy::default();
        assert_eq!(original.polling_fallback_interval(), None);
        for interval in [Duration::ZERO, Duration::from_nanos(1), Duration::from_micros(999),
            Duration::from_secs(60) + Duration::from_nanos(1)]
        { assert!(original.with_polling_fallback(interval).is_err()); }
        for interval in [Duration::from_millis(1), Duration::from_secs(1), Duration::from_secs(60)] {
            let policy = original.with_polling_fallback(interval).unwrap();
            assert_eq!(policy.polling_fallback_interval(), Some(interval));
            assert_eq!(policy.maximum_reconnections, original.maximum_reconnections);
            assert_eq!(policy.delay(2), original.delay(2));
        }
        assert_eq!(original.polling_fallback_interval(), None);
    }

    #[test]
    fn independent_due_times_respect_peer_hints_and_rotate_ties() {
        let now = Cx::for_testing().now();
        let minimum = Duration::from_secs(1);
        let mut polling = PollFallback::new(3, minimum);
        polling.record(0, &task("one", Some(3000))).unwrap();
        polling.record(1, &task("two", Some(0))).unwrap();
        polling.record(2, &task("three", None)).unwrap();
        assert_eq!(polling.next(&[false; 3], now).unwrap(), (1, after(now, minimum)));
        polling.reserve(1).unwrap();
        assert_eq!(polling.next(&[false; 3], now).unwrap().0, 2);
        polling.reserve(2).unwrap();
        polling.anchor(1, after(now, minimum)).unwrap();
        polling.anchor(2, after(now, minimum)).unwrap();
        assert_eq!(polling.next(&[false, true, true], now).unwrap(), (0, after(now, Duration::from_secs(3))));
        assert!(polling.next(&[true; 3], now).is_err());
        assert!(polling.next(&[false; 2], now).is_err());
        assert_eq!(polling.attempts(), 2);
    }

    #[test]
    fn caller_pauses_do_not_reset_due_times_and_external_snapshots_reanchor_conservatively() {
        let now = Cx::for_testing().now();
        let mut polling = PollFallback::new(1, Duration::from_secs(1));
        polling.record(0, &task("one", Some(5000))).unwrap();
        polling.anchor(0, now).unwrap();
        let later = after(now, Duration::from_secs(10));
        assert_eq!(polling.next(&[false], later).unwrap().1, after(now, Duration::from_secs(5)));
        // A separately reconciled update must not use the old already-due slot.
        polling.record(0, &task("one", Some(8000))).unwrap();
        assert_eq!(polling.next(&[false], later).unwrap().1, after(later, Duration::from_secs(8)));
        assert_eq!(polling.next(&[false], after(later, Duration::from_secs(2))).unwrap().1,
            after(later, Duration::from_secs(8)));
        assert_eq!(polling.attempts(), 0);
    }

    #[test]
    fn long_peer_hints_are_not_clamped_to_the_local_policy_ceiling() {
        let now = Cx::for_testing().now();
        let mut polling = PollFallback::new(1, Duration::from_secs(1));
        polling.record(0, &task("one", Some(120_000))).unwrap();
        assert_eq!(polling.next(&[false], now).unwrap().1, after(now, Duration::from_secs(120)));
        assert!(polling.record(1, &task("other", None)).is_err());
        assert_eq!(polling.next(&[false], now).unwrap().1, after(now, Duration::from_secs(120)));
    }

    #[test]
    fn ready_results_and_refusals_win_over_an_elapsed_fallback_timer() {
        let now = Cx::for_testing().now();
        for result in [Ok(7), Err("refused")] {
            let mut read = Box::pin(until_due(std::future::ready(result), now));
            assert_eq!(read.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Some(result)));
        }
    }

    #[test]
    fn fallback_timer_destroys_the_entered_read_instead_of_reusing_partial_state() {
        struct Pending<'a>(&'a Cell<bool>);
        impl Future for Pending<'_> {
            type Output = ();
            fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> { Poll::Pending }
        }
        impl Drop for Pending<'_> { fn drop(&mut self) { self.0.set(true); } }
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let dropped = Cell::new(false);
            assert!(until_due(Pending(&dropped), cx.now()).await.is_none());
            assert!(dropped.get());
        });
    }

    #[test]
    fn fallback_authority_and_budget_failures_do_not_acquire_or_send() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            for failure in 0..5 {
                let mut watch = local_watch(&cx);
                watch.state.initial.clear();
                let policy = ClientCredentialsTaskRecoveryPolicy::default()
                    .with_polling_fallback(Duration::from_millis(1)).unwrap();
                let mut recovery = RecoveryState::new(&watch, policy.connection_policy(
                    ClientCredentialsTaskWatchPolicy::default()).unwrap(), policy);
                let polling = recovery.polling.as_mut().unwrap();
                polling.start();
                polling.slots[0].due = Some(cx.now());
                match failure {
                    0 => { watch.binding.bearer.revoke(); },
                    1 => watch.binding.expires_at = Instant::now(),
                    2 => { watch.cancellation.cancel(); },
                    3 => { watch.deadline = cx.now(); },
                    _ => watch.state.snapshots = watch.state.maximum_snapshots,
                }
                let snapshots = watch.state.snapshots;
                assert!(Box::pin(recovery.next_snapshot(&cx, &mut watch, None)).await.is_err());
                assert_eq!(watch.ids.next, 0);
                assert_eq!(watch.state.snapshots, snapshots);
                assert_eq!(recovery.polling.as_ref().unwrap().attempts(), 0);
                assert_eq!(recovery.reconnection_attempts(), 0);
                assert!(watch.client.client.inner.state.try_lock_owned().unwrap().current.is_none());
            }
        });
    }

    #[test]
    fn switched_polling_does_not_reconnect_after_a_failed_post_update_read() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let mut watch = local_watch(&cx);
            let policy = ClientCredentialsTaskRecoveryPolicy::default()
                .with_polling_fallback(Duration::from_secs(1)).unwrap();
            let mut recovery = RecoveryState::new(&watch, policy.connection_policy(
                ClientCredentialsTaskWatchPolicy::default()).unwrap(), policy);
            recovery.polling.as_mut().unwrap().start();
            let error = recovery.reconnect_after(&cx, &mut watch, None, ManagedTasksError::MissingTerminal.into())
                .await.unwrap_err();
            assert!(matches!(error, ClientCredentialsTaskRecoveryError::Watch(
                ClientCredentialsTaskWatchError::Task(ClientCredentialsTasksError::Protocol(ManagedTasksError::MissingTerminal)))));
            assert_eq!(recovery.reconnection_attempts(), 0);
            assert_eq!(watch.ids.next, 0);
        });
    }
}
