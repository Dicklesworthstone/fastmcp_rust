use super::*;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;
use fastmcp_core::runtime::ProcessGenerationGuard;

fn lane() -> CredentialIoLane {
    CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(), CredentialIoLimits::default()).unwrap()
}
fn immediate<T>(value: T) -> CredentialSlotTask<T> {
    let lane = lane();
    ready(lane.process(), lane.reserve_job(CONTROL_BYTES).unwrap(), value)
}
fn empty<T>() -> (oneshot::Sender<Result<T, CredentialIoError>>, CredentialSlotTask<T>) {
    let lane = lane();
    let (sender, receiver) = oneshot::channel();
    (sender, CredentialSlotTask { process: lane.process(), worker: None, receiver,
        lease: Some(lane.reserve_job(CONTROL_BYTES).unwrap()), received: false })
}
fn runtime(blocking: bool) -> asupersync::runtime::Runtime {
    let builder = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap());
    let builder = if blocking { builder.blocking_threads(1, 2) } else { builder.blocking_threads(0, 0) };
    builder.build().unwrap()
}
async fn wait_released(cx: &Cx, lane: &CredentialIoLane) {
    asupersync::time::timeout_at(cx.now().saturating_add_nanos(2_000_000_000), async {
        while lane.snapshot().unwrap() != CredentialIoSnapshot::default() {
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
        }
    }).await.unwrap();
}

#[test]
fn completion_is_delivered_once_without_a_clone_or_second_receive() {
    runtime(true).block_on(async {
        let cx = Cx::current().unwrap();
        let mut pending = immediate(vec![0, 255, 7]);
        assert_eq!(pending.wait(&cx).await.unwrap(), vec![0, 255, 7]);
        assert_eq!(pending.wait(&cx).await.unwrap_err(), CredentialIoError::AlreadyReceived);
    });
}

#[test]
fn failed_wait_admission_preserves_an_already_committed_handoff() {
    runtime(true).block_on(async {
        let cx = Cx::current().unwrap();
        let exhausted = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
        let mut pending = immediate("retained-result");
        assert_eq!(pending.wait(&exhausted).await.unwrap_err(), CredentialIoError::WaitCancelled);
        assert!(!pending.received);
        assert!(pending.lease.is_some());
        assert_eq!(pending.wait(&cx).await.unwrap(), "retained-result");
    });
}

#[test]
fn abandoned_wait_does_not_consume_or_resubmit_the_operation() {
    runtime(true).block_on(async {
        let cx = Cx::current().unwrap();
        let (sender, mut pending) = empty();
        let mut wait = Box::pin(pending.wait(&cx));
        poll_fn(|context| {
            assert!(wait.as_mut().poll(context).is_pending());
            Poll::Ready(())
        }).await;
        drop(wait);
        sender.send_blocking(Ok(73)).unwrap();
        assert_eq!(pending.wait(&cx).await.unwrap(), 73);
    });
}

#[test]
fn worker_runs_outside_the_single_threaded_runtime_poller() {
    runtime(true).block_on(async {
        let cx = Cx::current().unwrap();
        let lane = lane();
        let poller = std::thread::current().id();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let mut pending = submit(&cx, &lane, CONTROL_BYTES, move |worker| {
            worker.checkpoint().unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
            std::thread::current().id()
        }).unwrap();
        assert_ne!(pending.wait(&cx).await.unwrap(), poller);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        wait_released(&cx, &lane).await;
    });
}

#[test]
fn missing_blocking_pool_refuses_instead_of_falling_back_inline() {
    runtime(false).block_on(async {
        let cx = Cx::current().unwrap();
        let lane = lane();
        let called = Arc::new(AtomicBool::new(false));
        let observed = called.clone();
        let result = submit(&cx, &lane, CONTROL_BYTES, move |_| observed.store(true, Ordering::SeqCst));
        assert!(matches!(result, Err(CredentialIoError::BlockingPoolUnavailable)));
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
    });
}

#[test]
fn pre_submission_cancellation_cannot_enter_the_worker() {
    let called = Arc::new(AtomicBool::new(false));
    let observed = called.clone();
    let lane = lane();
    let cx = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
    let result = submit(&cx, &lane, CONTROL_BYTES, move |_| observed.store(true, Ordering::SeqCst));
    assert!(matches!(result, Err(CredentialIoError::SubmissionCancelled)));
    assert!(!called.load(Ordering::SeqCst));
    assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
}

#[test]
fn stopped_worker_is_terminal_not_permission_to_submit_again() {
    runtime(true).block_on(async {
        let cx = Cx::current().unwrap();
        let (sender, mut pending) = empty::<()>();
        drop(sender);
        assert_eq!(pending.wait(&cx).await.unwrap_err(), CredentialIoError::WorkerStopped);
        assert!(pending.lease.is_none());
        assert_eq!(pending.wait(&cx).await.unwrap_err(), CredentialIoError::AlreadyReceived);
    });
}

#[test]
fn provider_panic_is_redacted_and_never_returns_a_mutated_owner() {
    runtime(true).block_on(async {
        let cx = Cx::current().unwrap();
        let lane = lane();
        let mut pending = submit(&cx, &lane, CONTROL_BYTES, |_| -> () { panic!("private provider diagnostic"); }).unwrap();
        let error = pending.wait(&cx).await.unwrap_err();
        assert_eq!(error, CredentialIoError::WorkerPanicked);
        assert!(!format!("{error:?} {error}").contains("private provider diagnostic"));
        assert_eq!(pending.wait(&cx).await.unwrap_err(), CredentialIoError::AlreadyReceived);
        wait_released(&cx, &lane).await;
    });
}

#[test]
fn dropping_a_ready_task_discards_its_handoff_exactly_once() {
    struct Handoff(Arc<AtomicUsize>);
    impl Drop for Handoff {
        fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let pending = immediate(Handoff(dropped.clone()));
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    drop(pending);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn unread_completion_retains_capacity_until_handoff_or_discard() {
    runtime(true).block_on(async {
        let cx = Cx::current().unwrap();
        let lane = CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(),
            CredentialIoLimits::new(2, 1, CONTROL_BYTES).unwrap()).unwrap();
        let mut pending = ready(lane.process(), lane.reserve_job(CONTROL_BYTES).unwrap(), vec![1, 2, 3]);
        let called = Arc::new(AtomicBool::new(false));
        let observed = called.clone();
        assert!(matches!(submit(&cx, &lane, CONTROL_BYTES, move |_| observed.store(true, Ordering::SeqCst)),
            Err(CredentialIoError::CapacityExceeded)));
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(pending.wait(&cx).await.unwrap(), vec![1, 2, 3]);
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
        drop(ready(lane.process(), lane.reserve_job(CONTROL_BYTES).unwrap(), ()));
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
    });
}

#[test]
fn dropped_task_cannot_release_a_running_nonpreemptible_workers_charge() {
    runtime(true).block_on(async {
        let cx = Cx::current().unwrap();
        let lane = CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(),
            CredentialIoLimits::new(2, 1, CONTROL_BYTES).unwrap()).unwrap();
        let (entered, mut entry) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let pending = submit(&cx, &lane, CONTROL_BYTES, move |_| {
            entered.send_blocking(()).unwrap();
            released.recv_timeout(Duration::from_secs(5)).unwrap();
        }).unwrap();
        entry.recv(&cx).await.unwrap();
        drop(pending);
        assert_eq!(lane.snapshot().unwrap().operations, 1);
        assert_eq!(lane.snapshot().unwrap().reserved_bytes, CONTROL_BYTES);
        assert!(matches!(submit(&cx, &lane, CONTROL_BYTES, |_| ()), Err(CredentialIoError::CapacityExceeded)));
        release.send(()).unwrap();
        wait_released(&cx, &lane).await;
        let mut next = submit(&cx, &lane, CONTROL_BYTES, |_| 42).unwrap();
        assert_eq!(next.wait(&cx).await.unwrap(), 42);
        wait_released(&cx, &lane).await;
    });
}
