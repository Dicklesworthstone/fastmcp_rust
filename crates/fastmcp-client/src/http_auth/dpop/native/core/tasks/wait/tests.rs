//! Real codec/accounting and caller-owned timer tests for the polling driver.

use super::*;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Instant;

use asupersync::Budget;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::time::{TimerDriverHandle, VirtualClock};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::ClientCapabilities;
use fastmcp_protocol::dpop::DpopKey;
use serde_json::{Value, json};

use super::super::{DpopCoreError, DpopHttpResponse, FINAL_PROTOCOL_VERSION, Prepared, TASKS_EXTENSION};
use crate::http_auth::dpop::native::DpopHttpPolicy;

fn id() -> TaskId {
    TaskId::parse("private-task").unwrap()
}

fn working(hint: Option<&str>) -> Task {
    let hint = hint.map_or_else(String::new, |value| format!(",\"pollIntervalMs\":{value}"));
    serde_json::from_str(&format!(
        r#"{{"taskId":"private-task","status":"working","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":null{hint}}}"#,
    ))
    .unwrap()
}

fn byte_error(error: &DpopTaskWaitError) -> bool {
    matches!(error, DpopTaskWaitError::Task(DpopTasksError::Core(
        DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit)
    )))
}

#[test]
fn policy_and_prefix_bounds_are_explicit_and_refused_not_clamped() {
    assert!(DpopTaskWaitPolicy::new(1, Duration::from_nanos(1)).is_ok());
    assert!(DpopTaskWaitPolicy::new(1024, Duration::from_mins(1)).is_ok());
    for (polls, interval) in [
        (0, Duration::from_secs(1)),
        (1025, Duration::from_secs(1)),
        (1, Duration::ZERO),
        (1, Duration::from_secs(61)),
        (usize::MAX, Duration::MAX),
    ] {
        assert!(matches!(
            DpopTaskWaitPolicy::new(polls, interval),
            Err(DpopTaskWaitError::InvalidPolicy)
        ));
    }
    for prefix in ["", "private id", "line\nbreak", "雪", &"a".repeat(129)] {
        let error = PollState::new(prefix, DpopTaskWaitPolicy::default(), ManagedCoreLimits::default())
            .err().unwrap();
        assert!(matches!(error, DpopTaskWaitError::InvalidIdPrefix));
        assert!(!format!("{error:?} {error}").contains("private id"));
    }
    assert!(PollState::new(&"a".repeat(128), DpopTaskWaitPolicy::default(),
        ManagedCoreLimits::default()).is_ok());
}

#[test]
fn poll_identities_are_unique_and_every_operation_is_observation_only() {
    let mut state = PollState::new(
        "selected.namespace",
        DpopTaskWaitPolicy::new(1024, Duration::from_secs(1)).unwrap(),
        ManagedCoreLimits::default(),
    ).unwrap();
    let mut ids = HashSet::new();
    for index in 0..1024 {
        let (operation, _) = state.begin(&id()).unwrap();
        for request_id in [&operation.discovery_id, &operation.operation_id] {
            request_id.validate().unwrap();
            assert!(ids.insert(serde_json::to_string(request_id).unwrap()));
        }
        assert_eq!(operation.discovery_id, RequestId::String(format!("selected.namespace.{index}.discover")));
        assert_eq!(operation.operation_id, RequestId::String(format!("selected.namespace.{index}.get")));
        assert!(matches!(operation.request, ManagedTaskRequest::Get(actual) if actual == id()));
    }
    let before = state.started;
    assert!(matches!(state.begin(&id()), Err(DpopTaskWaitError::PollLimit)));
    assert_eq!(state.started, before);
    assert_eq!(ids.len(), 2048);
}

#[test]
fn spent_response_bytes_narrow_the_next_pair_and_never_replenish() {
    let limits = ManagedCoreLimits::new(4096, 1000, 1500, 0, Duration::from_secs(10)).unwrap();
    let mut state = PollState::new("poll", DpopTaskWaitPolicy::default(), limits).unwrap();
    let (_, first) = state.begin(&id()).unwrap();
    assert_eq!((first.frame_bytes(), first.total_bytes()), (1000, 1500));
    state.record(1100).unwrap();
    let (_, next) = state.begin(&id()).unwrap();
    assert_eq!((next.frame_bytes(), next.total_bytes()), (400, 400));
    assert_eq!(next.request_bytes(), limits.request_bytes());
    assert_eq!(next.timeout(), limits.timeout());
    let before = state.remaining_bytes;
    assert!(byte_error(&state.record(401).unwrap_err()));
    assert_eq!(state.remaining_bytes, before);
    state.record(400).unwrap();
    assert!(byte_error(&state.begin(&id()).err().unwrap()));
    assert_eq!(state.started, 2);
}

fn response(id: &RequestId, value: Value) -> DpopHttpResponse {
    DpopHttpResponse {
        status: 200,
        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        body: serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":value})).unwrap(),
    }
}

#[test]
fn shared_discovery_and_get_admission_enforce_the_remaining_aggregate_byte() {
    let discovery = json!({
        "resultType":"complete","supportedVersions":[FINAL_PROTOCOL_VERSION],
        "capabilities":{"extensions":{TASKS_EXTENSION:{}}},
        "ttlMs":0,"cacheScope":"private",
        "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"peer","version":"1"}},
    });
    let mut snapshot = serde_json::to_value(working(None)).unwrap();
    snapshot["resultType"] = json!("complete");
    let first_id = RequestId::String("poll.0.discover".to_owned());
    let last_id = RequestId::String("poll.0.get".to_owned());
    let first_size = response(&first_id, discovery.clone()).body.len();
    let last_size = response(&last_id, snapshot.clone()).body.len();
    for exact in [false, true] {
        let total = first_size + last_size - usize::from(!exact);
        let limits = ManagedCoreLimits::new(4096, first_size.max(last_size), total, 0,
            Duration::from_secs(10)).unwrap();
        let mut state = PollState::new("poll", DpopTaskWaitPolicy::default(), limits).unwrap();
        let (operation, narrowed) = state.begin(&id()).unwrap();
        let prepared = Prepared::new("https://mcp.example/mcp",
            FinalRequestMeta::new(ClientCapabilities::default()), operation, narrowed, 4096).unwrap();
        let admitted = prepared.admit(response(&first_id, discovery.clone())).unwrap();
        let result = admitted.finish(response(&last_id, snapshot.clone()));
        if exact {
            assert!(matches!(result, Ok(ManagedTaskEvent::Snapshot(_))));
            state.record(first_size + last_size).unwrap();
            assert!(byte_error(&state.begin(&id()).err().unwrap()));
        } else {
            assert!(matches!(result, Err(DpopTasksError::Core(DpopCoreError::Protocol(
                ManagedCoreError::ResponseByteLimit
            )))));
            // Failed pairs do not produce a snapshot or authorize another poll.
            assert_eq!(state.remaining_bytes, total);
        }
    }
}

#[test]
fn opaque_peer_intervals_lengthen_local_minimum_without_overflow_or_shortening() {
    let now = Time::from_nanos(5_000_000_000);
    for (hint, nanos) in [(None, 1_000_000_000), (Some("1"), 1_000_000_000),
        (Some("2500"), 2_500_000_000), (Some("2.5e3"), 2_500_000_000)] {
        assert_eq!(next_poll_time(now, &working(hint), Duration::from_secs(1)).unwrap(),
            now.saturating_add_nanos(nanos));
    }
    assert_eq!(next_poll_time(now, &working(Some("18446744073709551615")),
        Duration::from_secs(1)).unwrap(), Time::from_nanos(u64::MAX));
    assert!(matches!(next_poll_time(now, &working(Some("18446744073709551616")),
        Duration::from_secs(1)), Err(DpopTaskWaitError::InvalidPollInterval)));
}

fn environment() -> (Runtime, Cx, TimerDriverHandle, Arc<VirtualClock>, DpopHttpClient, DpopCredential) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 0)
        .with_timer_driver(timer.clone()).build().unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(),
        CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap()).unwrap();
    let credential = session.admit_token_response(&issuer, 200,
        br#"{"access_token":"private-token","token_type":"DPoP","expires_in":300}"#,
        Instant::now(), Duration::from_secs(300)).unwrap();
    let client = DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap();
    (runtime, cx, timer, clock, client, credential)
}

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}
fn poll<T>(future: Pin<&mut impl Future<Output = T>>, waker: &Waker) -> Poll<T> {
    future.poll(&mut Context::from_waker(waker))
}

#[test]
fn silent_poll_interval_wakes_on_each_owner_stop_without_advancing_the_clock() {
    for action in 0..4 {
        let (runtime, cx, timer, _, client, credential) = environment();
        let cancellation = McpRequestCancellation::new();
        let bounds = WaitBounds::new(&cx, Duration::from_secs(30), &credential).unwrap();
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut interval = Box::pin(pause(&cx, &cancellation, &client.session, &credential,
            bounds, Time::from_nanos(20_000_000_000)));
        assert!(poll(interval.as_mut(), &waker).is_pending());
        assert!(timer.pending_count() > 0);
        let before = wakes.0.load(Ordering::SeqCst);
        match action {
            0 => { cancellation.cancel(); }
            1 => { credential.revoke(); }
            2 => { client.close(); }
            _ => { cx.set_cancel_requested(true); }
        }
        assert!(wakes.0.load(Ordering::SeqCst) > before, "stop must wake a silent timer wait");
        assert!(matches!(poll(interval.as_mut(), &waker), Poll::Ready(Err(_))));
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(cx.now(), Time::ZERO);
        assert_eq!(cx.is_cancel_requested(), action == 3);
        assert_eq!(client.revocation_handle().is_revoked(), action == 2);
        drop(interval);
        drop((client, credential, cx));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}

#[test]
fn poll_interval_uses_original_deadline_and_not_the_foreign_ambient_clock() {
    let (runtime, cx, timer, clock, client, credential) = environment();
    let foreign = Cx::for_testing_with_budget(Budget::INFINITE.with_deadline(Time::ZERO));
    foreign.set_cancel_requested(true);
    let cancellation = McpRequestCancellation::new();
    let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut interval = Box::pin(pause(&cx, &cancellation, &client.session, &credential,
        bounds, Time::from_nanos(u64::MAX)));
    {
        let _ambient = Cx::set_current(Some(foreign.clone()));
        assert!(poll(interval.as_mut(), &waker).is_pending());
    }
    clock.advance(9_999_999_999);
    assert_eq!(timer.process_timers(), 0);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    clock.advance(1);
    assert!(timer.process_timers() > 0);
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(poll(interval.as_mut(), &waker), Poll::Ready(Err(DpopHttpError::TimedOut))));
    assert_eq!(timer.pending_count(), 0);
    assert!(cx.checkpoint().is_ok());
    drop(interval);
    drop((client, credential, cx, foreign));
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn interval_abandonment_or_lost_time_authority_retires_both_timer_and_stop_wakers() {
    use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
    for narrowed in [false, true] {
        let (runtime, cx, timer, clock, client, credential) = environment();
        let cancellation = McpRequestCancellation::new();
        let bounds = WaitBounds::new(&cx, Duration::from_secs(30), &credential).unwrap();
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut interval = Box::pin(pause(&cx, &cancellation, &client.session, &credential,
            bounds, Time::from_nanos(20_000_000_000)));
        assert!(poll(interval.as_mut(), &waker).is_pending());
        if narrowed {
            let _caller = Cx::set_current(Some(cx.clone()));
            let _denied = Cx::push_restriction(CapSet::<true, false, true, true, true>::MASK);
            assert!(matches!(poll(interval.as_mut(), &waker),
                Poll::Ready(Err(DpopHttpError::RuntimeUnavailable))));
            assert_eq!(timer.pending_count(), 0);
        }
        drop(interval);
        assert_eq!(timer.pending_count(), 0);
        assert!(!client.revocation_handle().is_revoked());
        let before = wakes.0.load(Ordering::SeqCst);
        clock.advance(30_000_000_000);
        assert_eq!(timer.process_timers(), 0);
        cancellation.cancel();
        credential.revoke();
        client.close();
        assert_eq!(wakes.0.load(Ordering::SeqCst), before);
        drop((client, credential, cx));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}

#[test]
fn precancelled_public_wait_never_polls_the_network_and_keeps_the_session_live() {
    let (runtime, cx, _, _, mut client, credential) = environment();
    let cancellation = McpRequestCancellation::new();
    cancellation.cancel();
    let mut call = Box::pin(client.wait_task_with_cancellation(&cx, &cancellation, &credential,
        FinalRequestMeta::new(ClientCapabilities::default()), id(), "wait", DpopTaskWaitPolicy::default(),
        ManagedCoreLimits::default()));
    assert!(matches!(poll(call.as_mut(), Waker::noop()),
        Poll::Ready(Err(DpopTaskWaitError::Task(DpopTasksError::Core(
            DpopCoreError::Transport(DpopHttpError::Cancelled)
        ))))));
    drop(call);
    assert!(!client.revocation_handle().is_revoked());
    assert!(cx.checkpoint().is_ok());
    drop((client, credential, cx));
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}
