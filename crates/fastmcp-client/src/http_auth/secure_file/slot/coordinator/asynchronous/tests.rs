use super::*;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;

fn process() -> Arc<ProcessBoundToken> {
    Arc::new(ProcessGenerationGuard::install().unwrap().token())
}
fn runtime(blocking: bool) -> asupersync::runtime::Runtime {
    let builder = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap());
    let builder = if blocking { builder.blocking_threads(1, 2) } else { builder.blocking_threads(0, 0) };
    builder.build().unwrap()
}

#[test]
fn completion_is_delivered_once_without_a_clone_or_second_receive() {
    runtime(true).block_on(async {
        let cx = Cx::current().unwrap();
        let mut pending = ready(process(), vec![0, 255, 7]);
        assert_eq!(pending.wait(&cx).await.unwrap(), vec![0, 255, 7]);
        assert_eq!(pending.wait(&cx).await.unwrap_err(), CredentialIoError::AlreadyReceived);
    });
}

#[test]
fn failed_wait_admission_preserves_an_already_committed_handoff() {
    runtime(true).block_on(async {
        let cx = Cx::current().unwrap();
        let exhausted = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
        let mut pending = ready(process(), "retained-result");
        assert_eq!(pending.wait(&exhausted).await.unwrap_err(), CredentialIoError::WaitCancelled);
        assert!(!pending.received);
        assert_eq!(pending.wait(&cx).await.unwrap(), "retained-result");
    });
}

#[test]
fn abandoned_wait_does_not_consume_or_resubmit_the_operation() {
    runtime(true).block_on(async {
        let cx = Cx::current().unwrap();
        let (sender, receiver) = oneshot::channel();
        let mut pending = CredentialSlotTask { process: process(), worker: None, receiver, received: false };
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
        let poller = std::thread::current().id();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let mut pending = submit(&cx, process(), move |worker| {
            worker.checkpoint().unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
            std::thread::current().id()
        }).unwrap();
        assert_ne!(pending.wait(&cx).await.unwrap(), poller);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn missing_blocking_pool_refuses_instead_of_falling_back_inline() {
    runtime(false).block_on(async {
        let cx = Cx::current().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let observed = called.clone();
        let result = submit(&cx, process(), move |_| observed.store(true, Ordering::SeqCst));
        assert!(matches!(result, Err(CredentialIoError::BlockingPoolUnavailable)));
        assert!(!called.load(Ordering::SeqCst));
    });
}

#[test]
fn pre_submission_cancellation_cannot_enter_the_worker() {
    let called = Arc::new(AtomicBool::new(false));
    let observed = called.clone();
    let cx = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
    let result = submit(&cx, process(), move |_| observed.store(true, Ordering::SeqCst));
    assert!(matches!(result, Err(CredentialIoError::SubmissionCancelled)));
    assert!(!called.load(Ordering::SeqCst));
}

#[test]
fn stopped_worker_is_terminal_not_permission_to_submit_again() {
    runtime(true).block_on(async {
        let cx = Cx::current().unwrap();
        let (sender, receiver) = oneshot::channel::<Result<(), CredentialIoError>>();
        drop(sender);
        let mut pending = CredentialSlotTask { process: process(), worker: None, receiver, received: false };
        assert_eq!(pending.wait(&cx).await.unwrap_err(), CredentialIoError::WorkerStopped);
        assert_eq!(pending.wait(&cx).await.unwrap_err(), CredentialIoError::AlreadyReceived);
    });
}

#[test]
fn provider_panic_is_redacted_and_never_returns_a_mutated_owner() {
    runtime(true).block_on(async {
        let cx = Cx::current().unwrap();
        let mut pending = submit(&cx, process(), |_| -> () { panic!("private provider diagnostic"); }).unwrap();
        let error = pending.wait(&cx).await.unwrap_err();
        assert_eq!(error, CredentialIoError::WorkerPanicked);
        assert!(!format!("{error:?} {error}").contains("private provider diagnostic"));
        assert_eq!(pending.wait(&cx).await.unwrap_err(), CredentialIoError::AlreadyReceived);
    });
}

#[test]
fn dropping_a_ready_task_discards_its_handoff_exactly_once() {
    struct Handoff(Arc<AtomicUsize>);
    impl Drop for Handoff {
        fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let pending = ready(process(), Handoff(dropped.clone()));
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    drop(pending);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}
