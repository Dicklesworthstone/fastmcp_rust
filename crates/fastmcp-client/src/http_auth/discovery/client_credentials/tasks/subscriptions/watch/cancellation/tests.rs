use super::*;
use std::cell::Cell;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Wake, Waker};
use std::time::{Duration, Instant};
use crate::http_auth::BoundBearerCredential;

struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn machine_cancel_clones_share_one_attempt_without_stopping_observation() {
    let control = Arc::new(Control::new());
    let other = Arc::clone(&control);
    control.claim().unwrap();
    assert_eq!(other.state(), TaskCancellationState::Unconfirmed);
    assert!(matches!(other.claim(), Err(ClientCredentialsTaskCancellationError::AlreadyAttempted)));
    assert_eq!(control.completion.load(Ordering::Acquire), LIVE);
    assert!(!control.acknowledged.is_cancel_requested());
    other.acknowledge();
    assert_eq!(control.state(), TaskCancellationState::Acknowledged);
    assert_eq!(control.completion.load(Ordering::Acquire), CANCEL_REQUESTED);
}

#[test]
fn machine_cancel_terminal_and_ack_have_one_winner_without_losing_receipts() {
    let terminal_first = Control::new();
    terminal_first.claim().unwrap();
    terminal_first.terminal().unwrap();
    terminal_first.acknowledge();
    assert_eq!(terminal_first.completion.load(Ordering::Acquire), TERMINAL_DELIVERED);
    assert_eq!(terminal_first.state(), TaskCancellationState::Acknowledged);
    assert!(!terminal_first.acknowledged.is_cancel_requested());
    let cancel_first = Control::new();
    cancel_first.claim().unwrap();
    cancel_first.acknowledge();
    assert!(matches!(cancel_first.terminal(), Err(CancellableClientCredentialsTaskWatchError::CancellationRequested)));
    cancel_first.close();
    assert_eq!(cancel_first.completion.load(Ordering::Acquire), CANCEL_REQUESTED);
    assert_eq!(cancel_first.state(), TaskCancellationState::Acknowledged);
}

#[test]
fn machine_cancel_only_an_ack_wakes_idle_observation() {
    let control = Control::new();
    let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    let mut read = Box::pin(until_signal(&control.acknowledged, std::future::pending::<()>()));
    assert!(read.as_mut().poll(&mut cx).is_pending());
    let before = wakes.0.load(Ordering::SeqCst);
    control.claim().unwrap();
    assert_eq!(wakes.0.load(Ordering::SeqCst), before);
    assert!(read.as_mut().poll(&mut cx).is_pending());
    control.acknowledge();
    assert!(wakes.0.load(Ordering::SeqCst) > before);
    assert!(matches!(read.as_mut().poll(&mut cx), Poll::Ready(Err(()))));
}

#[test]
fn machine_cancel_signal_during_ready_poll_withholds_output_and_releases_work() {
    struct Work<'a> { signal: &'a McpRequestCancellation, dropped: &'a Cell<bool> }
    impl Future for Work<'_> {
        type Output = usize;
        fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<usize> {
            self.signal.cancel();
            Poll::Ready(7)
        }
    }
    impl Drop for Work<'_> { fn drop(&mut self) { self.dropped.set(true); } }
    let signal = McpRequestCancellation::new();
    let dropped = Cell::new(false);
    let mut cx = Context::from_waker(Waker::noop());
    let mut work = Box::pin(until_signal(&signal, Work { signal: &signal, dropped: &dropped }));
    assert!(matches!(work.as_mut().poll(&mut cx), Poll::Ready(Err(()))));
    drop(work);
    assert!(dropped.get());
}

#[test]
fn machine_cancel_abandoned_read_retires_admission_and_wakes_pending_attempt() {
    let control = Arc::new(Control::new());
    control.claim().unwrap();
    let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    let mut attempt = Box::pin(until_signal(&control.closed, std::future::pending::<()>()));
    assert!(attempt.as_mut().poll(&mut cx).is_pending());
    let before = wakes.0.load(Ordering::SeqCst);
    drop(ReadLease { control: Arc::clone(&control), armed: true });
    assert!(wakes.0.load(Ordering::SeqCst) > before);
    assert!(matches!(attempt.as_mut().poll(&mut cx), Poll::Ready(Err(()))));
    assert_eq!(control.state(), TaskCancellationState::Unconfirmed);
    assert!(matches!(control.claim(), Err(ClientCredentialsTaskCancellationError::Closed)));
    assert!(!control.acknowledged.is_cancel_requested());
}

#[test]
fn machine_cancel_disarmed_read_lease_preserves_future_admission() {
    let control = Arc::new(Control::new());
    let mut lease = ReadLease { control: Arc::clone(&control), armed: true };
    lease.disarm();
    drop(lease);
    assert!(!control.closed.is_cancel_requested());
    control.claim().unwrap();
}

#[test]
fn machine_cancel_ids_are_disjoint_from_every_numeric_watch_suffix() {
    let reserved = cancellation_ids("machine-watch").unwrap();
    assert_eq!(reserved.0, RequestId::String("machine-watch:cancel:discovery".to_owned()));
    assert_eq!(reserved.1, RequestId::String("machine-watch:cancel:operation".to_owned()));
    let mut ids = WatchIds::new("machine-watch".to_owned()).unwrap();
    for _ in 0..128 {
        let pair = ids.next_pair().unwrap();
        for normal in [&pair.0, &pair.1] {
            assert!(!normal.correlates_with(&reserved.0));
            assert!(!normal.correlates_with(&reserved.1));
        }
    }
    for invalid in ["".to_owned(), "bad:prefix".to_owned(), "x".repeat(129)] {
        assert!(cancellation_ids(&invalid).is_err());
    }
}

fn consumer() -> ClientCredentialsTasksClient { super::super::tests::consumer() }
fn binding(client: &ClientCredentialsTasksClient) -> ClientCredentialsSnapshot {
    let expires_at = Instant::now() + Duration::from_secs(600);
    let bearer = BoundBearerCredential::bind_with_expiry(client.client.resource().clone(), "fixture-access", expires_at)
        .unwrap().for_owner(&client.client.inner.closed).unwrap();
    ClientCredentialsSnapshot { bearer, scopes: vec![], expires_at, generation: 11 }
}
fn handle(client: &ClientCredentialsTasksClient, cx: &Cx) -> ClientCredentialsTaskCancelHandle {
    let deadline = cx.now().saturating_add_nanos(1_000_000_000);
    let mut handle = ClientCredentialsTaskCancelHandle::for_observation(client, TaskId::parse("one").unwrap(),
        "cancel-test", &McpRequestCancellation::new(), deadline).unwrap();
    handle.pin_binding(binding(client), deadline).unwrap();
    handle
}

#[test]
fn machine_cancel_preparation_preserves_metadata_and_never_embeds_credentials() {
    let client = consumer();
    let ids = cancellation_ids("machine").unwrap();
    let (prepared, _, discovery) = prepare_pinned(&client, &ids,
        ManagedTaskRequest::Cancel(TaskId::parse("one").unwrap())).unwrap();
    for (wire, expected) in [(&discovery, &ids.0), (&prepared.wire, &ids.1)] {
        let body: serde_json::Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(body["id"], serde_json::to_value(expected).unwrap());
        assert_eq!(body["params"]["_meta"], client.metadata);
        assert!(!wire.headers().iter().any(|(name, _)| name.eq_ignore_ascii_case("authorization")));
    }
    let body: serde_json::Value = serde_json::from_slice(prepared.wire.body()).unwrap();
    assert_eq!(body["params"]["taskId"], "one");
}

#[test]
fn machine_cancel_preflight_expiry_revocation_and_local_stop_do_not_spend_attempt() {
    super::super::tests::runtime().block_on(async {
        let cx = Cx::current().unwrap();
        for case in 0..4 {
            let client = consumer();
            let mut handle = handle(&client, &cx);
            let cancel = McpRequestCancellation::new();
            match case {
                0 => {
                    let scope = Arc::get_mut(&mut handle.scope).unwrap();
                    Arc::get_mut(scope.binding.as_mut().unwrap()).unwrap().expires_at = Instant::now();
                }
                1 => handle.scope.binding.as_ref().unwrap().bearer.revoke(),
                2 => cancel.cancel(),
                _ => client.client.close(),
            }
            assert!(matches!(handle.request_cancel_with_cancellation(&cx, &cancel).await,
                Err(ClientCredentialsTaskCancellationError::NotAttempted(_))));
            assert_eq!(handle.state(), TaskCancellationState::Ready);
            assert!(!handle.cancellation_requested());
            assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
        }
    });
}

#[test]
fn machine_cancel_owner_close_and_unpolled_attempt_never_send_or_renew() {
    super::super::tests::runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let client = consumer();
        let handle = handle(&client, &cx);
        let future = handle.request_cancel(&cx);
        drop(future);
        assert_eq!(handle.state(), TaskCancellationState::Ready);
        handle.close_observation();
        assert!(matches!(handle.request_cancel(&cx).await, Err(ClientCredentialsTaskCancellationError::Closed)));
        assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
        assert!(!client.client.inner.closed.is_cancel_requested());
    });
}

#[test]
fn machine_cancel_public_admission_rejects_invalid_ids_and_precancellation_before_grant() {
    super::super::tests::runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let client = consumer();
        let task = TaskId::parse("one").unwrap();
        assert!(matches!(Box::pin(client.watch_task_cancellable(&cx, task.clone(), "bad:prefix".to_owned(),
            ClientCredentialsTaskWatchPolicy::default())).await,
            Err(CancellableClientCredentialsTaskWatchError::Watch(ClientCredentialsTaskWatchError::InvalidIdPrefix))));
        let cancel = McpRequestCancellation::new();
        cancel.cancel();
        assert!(Box::pin(client.watch_task_cancellable_with_cancellation(&cx, &cancel, task,
            "good".to_owned(), ClientCredentialsTaskWatchPolicy::default())).await.is_err());
        assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
    });
}
