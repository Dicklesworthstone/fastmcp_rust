//! Retention admission and shared HTTP/stdio observation-state-machine tests.
//! These tests exercise the real wait driver; scripted transports isolate its
//! timing and custody rules without claiming live transport qualification.

use super::*;
use asupersync::runtime::RuntimeBuilder;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Waker};

fn task(status: &str, ttl: Option<u64>, poll: u64) -> FinalTask {
    // Anchoring the test Task at the epoch lets finite deadlines be expressed
    // exactly without adding a date-formatting dependency to the client.
    let mut value = json!({
        "taskId":"retained-task", "status":status,
        "createdAt":"1970-01-01T00:00:00Z",
        "lastUpdatedAt":"1970-01-01T00:00:00Z",
        "ttlMs":ttl, "pollIntervalMs":poll
    });
    if status == "input_required" {
        value["inputRequests"] = json!({"roots":{"method":"roots/list"}});
    } else if status == "completed" {
        value["result"] = json!({
            "content":[{"type":"text","text":"retained result"}],
            "futurePayload":{"number":7,"items":[true,null]}
        });
    }
    serde_json::from_str(&value.to_string()).unwrap()
}

fn expiry_after(duration: Duration) -> u64 {
    u64::try_from(
        (wall_now_nanos() + i128::try_from(duration.as_nanos()).unwrap()) / 1_000_000,
    )
    .unwrap()
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("local admission must finish without a timer or transport"),
    }
}

struct NoReads;
impl TaskWaitTransport for NoReads {
    type Error = McpError;

    async fn read_task(
        &mut self,
        _: &Cx,
        _: &McpRequestCancellation,
        _: FinalTaskId,
    ) -> McpResult<FinalTask> {
        panic!("this disposition must not issue a Task request")
    }
}

#[test]
fn retention_uses_creation_instant_not_update_time_or_timestamp_spelling() {
    let initial = task("working", Some(1000), 1);
    assert_eq!(retention_deadline(&initial).unwrap(), Some(1_000_000_000));
    let mut value = serde_json::to_value(&initial).unwrap();
    value["createdAt"] = json!("1970-01-01T01:00:00+01:00");
    value["lastUpdatedAt"] = json!("1970-01-02T00:00:00Z");
    let updated: FinalTask = serde_json::from_str(&value.to_string()).unwrap();
    assert_eq!(retention_deadline(&updated).unwrap(), retention_deadline(&initial).unwrap());
    admit_identity(&initial, &updated).unwrap();
    value["ttlMs"] = json!(1001);
    let extended: FinalTask = serde_json::from_str(&value.to_string()).unwrap();
    admit_identity(&initial, &extended).unwrap();
    assert_eq!(retention_deadline(&extended).unwrap(), Some(1_001_000_000));
    assert_eq!(retention_deadline(&initial).unwrap(), Some(1_000_000_000));
}

#[test]
fn authoritative_retention_changes_preserve_the_original_wait_ceiling() {
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let wall_now = 500_000_000_000;
    let mut budget = WaitBudget::at_wall_time(
        &cx,
        Duration::from_secs(600),
        &task("working", Some(1_000_000), 1),
        wall_now,
    )
    .unwrap();
    let original_runtime = budget.local_runtime_deadline;
    let original_wall = budget.local_wall_deadline;
    let first_expiry = budget.runtime_deadline;
    assert_eq!(budget.deadline_outcome, FinalTaskWaitOutcome::TaskExpired);

    // A fresh extension can recover the unused portion of the original
    // caller budget, but cannot start a new local timeout.
    budget
        .refresh_retention_at_wall_time(&cx, &task("working", Some(1_500_000), 1), wall_now)
        .unwrap();
    assert_eq!(
        budget.deadline_outcome,
        FinalTaskWaitOutcome::DeadlineElapsed
    );
    assert_eq!(budget.runtime_deadline, original_runtime);
    assert_eq!(budget.wall_deadline, original_wall);
    assert!(budget.runtime_deadline > first_expiry);

    budget
        .refresh_retention_at_wall_time(&cx, &task("working", Some(900_000), 1), wall_now)
        .unwrap();
    assert_eq!(budget.deadline_outcome, FinalTaskWaitOutcome::TaskExpired);
    assert!(budget.runtime_deadline < first_expiry);
    assert_eq!(
        budget.stop_at_wall_time(&cx, &cancellation, 900_000_000_000),
        Some(FinalTaskWaitOutcome::TaskExpired),
    );

    budget
        .refresh_retention_at_wall_time(&cx, &task("working", None, 1), wall_now)
        .unwrap();
    assert_eq!(budget.retention_deadline, None);
    assert_eq!(budget.runtime_deadline, original_runtime);
    assert_eq!(budget.wall_deadline, original_wall);

    // Replacing null retention with a finite snapshot is also authoritative.
    budget
        .refresh_retention_at_wall_time(&cx, &task("working", Some(800_000), 1), wall_now)
        .unwrap();
    let admitted_runtime = budget.runtime_deadline;
    let admitted_wall = budget.wall_deadline;
    budget
        .refresh_retention_at_wall_time(
            &cx,
            &task("working", Some(800_000), 7),
            wall_now - 100_000_000_000,
        )
        .unwrap();
    assert_eq!(budget.runtime_deadline, admitted_runtime);
    assert_eq!(budget.wall_deadline, admitted_wall);
    assert_eq!(budget.local_runtime_deadline, original_runtime);
    assert_eq!(budget.local_wall_deadline, original_wall);

    budget.local_runtime_deadline = cx.now();
    budget
        .refresh_retention_at_wall_time(&cx, &task("working", Some(u64::MAX), 1), wall_now)
        .unwrap();
    assert_eq!(
        budget.stop_at_wall_time(&cx, &cancellation, wall_now),
        Some(FinalTaskWaitOutcome::DeadlineElapsed),
        "a retention extension cannot revive an exhausted caller budget",
    );
}

#[test]
fn input_retention_remaining_admits_null_and_long_lifetimes_without_narrowing() {
    assert_eq!(
        input_retention_remaining(&task("input_required", None, 1)).unwrap(),
        None
    );
    assert!(input_retention_remaining(&task("input_required", Some(1), 1)).is_err());
    let remaining = input_retention_remaining(&task("input_required", Some(u64::MAX), 1))
        .unwrap()
        .unwrap();
    assert!(remaining.as_nanos() > u128::from(u64::MAX));
    assert!(remaining <= Duration::from_millis(u64::MAX));
}

#[test]
fn retention_and_local_timeout_choose_distinct_nonresettable_deadlines() {
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let finite = task("working", Some(1_000_000), 1);
    let mut retention = WaitBudget::at_wall_time(
        &cx, Duration::from_secs(600), &finite, 500_000_000_000,
    ).unwrap();
    assert_eq!(retention.deadline_outcome, FinalTaskWaitOutcome::TaskExpired);
    assert_eq!(retention.stop_at_wall_time(&cx, &cancellation, 999_999_999_999), None);
    assert_eq!(
        retention.stop_at_wall_time(&cx, &cancellation, 1_000_000_000_000),
        Some(FinalTaskWaitOutcome::TaskExpired),
    );
    // Advance the monotonic bound, then move the wall clock backwards. The
    // already-admitted deadline still wins, with its original disposition.
    retention.runtime_deadline = cx.now();
    assert_eq!(
        retention.stop_at_wall_time(&cx, &cancellation, 499_000_000_000),
        Some(FinalTaskWaitOutcome::TaskExpired),
    );
    let mut local = WaitBudget::at_wall_time(
        &cx, Duration::from_secs(60), &finite, 500_000_000_000,
    ).unwrap();
    assert_eq!(local.deadline_outcome, FinalTaskWaitOutcome::DeadlineElapsed);
    local.wall_deadline = Instant::now();
    assert_eq!(
        local.stop_at_wall_time(&cx, &cancellation, 500_000_000_000),
        Some(FinalTaskWaitOutcome::DeadlineElapsed),
    );
    cancellation.cancel();
    assert_eq!(
        retention.stop_at_wall_time(&cx, &cancellation, 1_000_000_000_000),
        Some(FinalTaskWaitOutcome::ObservationCancelled),
    );
}

#[test]
fn null_and_maximum_ttls_preserve_finite_local_limits_without_overflow() {
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    for ttl in [None, Some(u64::MAX)] {
        let task = task("working", ttl, 1);
        let budget = WaitBudget::at_wall_time(
            &cx, Duration::from_secs(60), &task, 0,
        ).unwrap();
        assert_eq!(budget.deadline_outcome, FinalTaskWaitOutcome::DeadlineElapsed);
        assert_eq!(budget.stop_at_wall_time(&cx, &cancellation, 0), None);
        assert!(budget.remaining(&cx) <= Duration::from_secs(60));
    }
    assert_eq!(retention_deadline(&task("working", None, 1)).unwrap(), None);
    assert_eq!(
        retention_deadline(&task("working", Some(u64::MAX), 1)).unwrap(),
        Some(i128::from(u64::MAX) * 1_000_000),
    );
}

#[test]
fn expired_working_and_input_snapshots_refuse_before_timer_or_transport() {
    let cx = Cx::for_request();
    assert!(cx.timer_driver().is_none());
    for status in ["working", "input_required"] {
        let mut handle = FinalTaskHandle::new(task(status, Some(1), 1));
        let before = serde_json::to_vec(handle.task()).unwrap();
        let cancellation = McpRequestCancellation::new();
        let outcome = ready(wait_for_task(
            &mut handle, &cx, &mut NoReads, &cancellation, FinalTaskWaitPolicy::default(),
        )).unwrap();
        assert_eq!(outcome, FinalTaskWaitOutcome::TaskExpired);
        assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
        assert!(!cancellation.is_cancel_requested());
    }
    let mut input = FinalTaskHandle::new(task("input_required", None, 1));
    assert_eq!(
        ready(wait_for_task(
            &mut input, &cx, &mut NoReads, &McpRequestCancellation::new(),
            FinalTaskWaitPolicy::default(),
        )).unwrap(),
        FinalTaskWaitOutcome::InputRequired,
    );
}

#[test]
fn already_delivered_terminal_results_survive_remote_retention_expiry() {
    let cx = Cx::for_request();
    let mut handle = FinalTaskHandle::new(task("completed", Some(1), 1));
    let before = serde_json::to_vec(handle.task()).unwrap();
    let cancellation = McpRequestCancellation::new();
    cancellation.cancel();
    assert_eq!(
        ready(wait_for_task(
            &mut handle, &cx, &mut NoReads, &cancellation, FinalTaskWaitPolicy::default(),
        )).unwrap(),
        FinalTaskWaitOutcome::Completed,
    );
    assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
}

#[test]
fn peer_delay_beyond_retention_does_not_trigger_an_early_read() {
    RuntimeBuilder::current_thread().build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let cancellation = McpRequestCancellation::new();
        let mut handle = FinalTaskHandle::new(task(
            "working", Some(expiry_after(Duration::from_millis(100))), 60_000,
        ));
        let before = serde_json::to_vec(handle.task()).unwrap();
        let outcome = wait_for_task(
            &mut handle, &cx, &mut NoReads, &cancellation, FinalTaskWaitPolicy::default(),
        ).await.unwrap();
        assert_eq!(outcome, FinalTaskWaitOutcome::TaskExpired);
        assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
        assert!(cx.checkpoint().is_ok());
        assert!(!cancellation.is_cancel_requested());
    });
}

struct PendingRead {
    reads: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}
struct ReadOwner(Arc<AtomicUsize>);
impl Drop for ReadOwner {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
impl TaskWaitTransport for PendingRead {
    type Error = McpError;

    async fn read_task(
        &mut self,
        _: &Cx,
        _: &McpRequestCancellation,
        _: FinalTaskId,
    ) -> McpResult<FinalTask> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let _owner = ReadOwner(Arc::clone(&self.drops));
        std::future::pending().await
    }
}

#[test]
fn retention_interrupts_a_pending_read_and_releases_only_its_owner() {
    RuntimeBuilder::current_thread().build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let cancellation = McpRequestCancellation::new();
        let mut handle = FinalTaskHandle::new(task(
            "working", Some(expiry_after(Duration::from_millis(500))), 1,
        ));
        let before = serde_json::to_vec(handle.task()).unwrap();
        let mut transport = PendingRead {
            reads: Arc::new(AtomicUsize::new(0)),
            drops: Arc::new(AtomicUsize::new(0)),
        };
        let outcome = wait_for_task(
            &mut handle, &cx, &mut transport, &cancellation, FinalTaskWaitPolicy::default(),
        ).await.unwrap();
        assert_eq!(outcome, FinalTaskWaitOutcome::TaskExpired);
        assert_eq!(transport.reads.load(Ordering::SeqCst), 1);
        assert_eq!(transport.drops.load(Ordering::SeqCst), 1);
        assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
        assert!(!cancellation.is_cancel_requested());
        assert!(cx.checkpoint().is_ok());
    });
}

struct ReadyRead {
    result: FinalTask,
    calls: usize,
}
impl TaskWaitTransport for ReadyRead {
    type Error = McpError;

    async fn read_task(
        &mut self,
        _: &Cx,
        _: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> McpResult<FinalTask> {
        assert_eq!(&task_id, &self.result.base().task_id);
        self.calls += 1;
        Ok(self.result.clone())
    }
}

#[test]
fn live_finite_task_completes_and_preserves_the_exact_admitted_payload() {
    RuntimeBuilder::current_thread().build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let ttl = Some(expiry_after(Duration::from_secs(30)));
        let mut handle = FinalTaskHandle::new(task("working", ttl, 1));
        let final_task = task("completed", ttl, 1);
        let expected = serde_json::to_vec(&final_task).unwrap();
        let mut transport = ReadyRead { result: final_task, calls: 0 };
        let cancellation = McpRequestCancellation::new();
        assert_eq!(
            wait_for_task(
                &mut handle, &cx, &mut transport, &cancellation, FinalTaskWaitPolicy::default(),
            ).await.unwrap(),
            FinalTaskWaitOutcome::Completed,
        );
        assert_eq!(transport.calls, 1);
        assert_eq!(serde_json::to_vec(handle.task()).unwrap(), expected);
    });
}

#[test]
fn a_fresh_working_snapshot_does_not_restart_the_retention_clock() {
    RuntimeBuilder::current_thread().build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let ttl = Some(expiry_after(Duration::from_millis(500)));
        let mut handle = FinalTaskHandle::new(task("working", ttl, 1));
        let mut transport = ReadyRead { result: task("working", ttl, 60_000), calls: 0 };
        let expected = serde_json::to_vec(&transport.result).unwrap();
        let cancellation = McpRequestCancellation::new();
        assert_eq!(
            wait_for_task(
                &mut handle, &cx, &mut transport, &cancellation, FinalTaskWaitPolicy::default(),
            ).await.unwrap(),
            FinalTaskWaitOutcome::TaskExpired,
        );
        assert_eq!(transport.calls, 1);
        assert_eq!(serde_json::to_vec(handle.task()).unwrap(), expected);
        assert!(!cancellation.is_cancel_requested());
        assert!(cx.checkpoint().is_ok());
    });
}

struct RetentionUpdates {
    snapshots: std::collections::VecDeque<FinalTask>,
    calls: usize,
}

impl TaskWaitTransport for RetentionUpdates {
    type Error = McpError;

    async fn read_task(
        &mut self,
        _: &Cx,
        _: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> McpResult<FinalTask> {
        let next = self
            .snapshots
            .pop_front()
            .expect("no extra reconciliation read");
        assert_eq!(&task_id, &next.base().task_id);
        self.calls += 1;
        Ok(next)
    }
}

#[test]
fn shared_wait_admits_finite_null_and_shortened_retention_through_completion() {
    RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let short_ttl = Some(expiry_after(Duration::from_secs(30)));
            let long_ttl = Some(expiry_after(Duration::from_secs(60)));
            let final_task = task("completed", short_ttl, 1);
            let expected = serde_json::to_vec(&final_task).unwrap();
            let mut handle = FinalTaskHandle::new(task("working", short_ttl, 1));
            let mut transport = RetentionUpdates {
                snapshots: std::collections::VecDeque::from([
                    task("working", long_ttl, 1),
                    task("working", None, 1),
                    task("working", long_ttl, 1),
                    final_task,
                ]),
                calls: 0,
            };
            let cancellation = McpRequestCancellation::new();
            assert_eq!(
                wait_for_task(
                    &mut handle,
                    &cx,
                    &mut transport,
                    &cancellation,
                    FinalTaskWaitPolicy::default(),
                )
                .await
                .unwrap(),
                FinalTaskWaitOutcome::Completed,
            );
            assert_eq!(transport.calls, 4);
            assert!(transport.snapshots.is_empty());
            assert_eq!(serde_json::to_vec(handle.task()).unwrap(), expected);
            assert!(!cancellation.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
        });
}

#[test]
fn shared_wait_retention_extension_does_not_restart_the_caller_timeout() {
    RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let mut handle = FinalTaskHandle::new(task(
                "working",
                Some(expiry_after(Duration::from_secs(30))),
                1,
            ));
            let mut transport = ReadyRead {
                result: task("working", None, 60_000),
                calls: 0,
            };
            let expected = serde_json::to_vec(&transport.result).unwrap();
            let cancellation = McpRequestCancellation::new();
            let policy =
                FinalTaskWaitPolicy::new(Duration::from_millis(100), 8, Duration::from_millis(1))
                    .unwrap();
            assert_eq!(
                wait_for_task(&mut handle, &cx, &mut transport, &cancellation, policy)
                    .await
                    .unwrap(),
                FinalTaskWaitOutcome::DeadlineElapsed,
            );
            assert_eq!(transport.calls, 1);
            assert_eq!(serde_json::to_vec(handle.task()).unwrap(), expected);
            assert!(cx.checkpoint().is_ok());
        });
}
