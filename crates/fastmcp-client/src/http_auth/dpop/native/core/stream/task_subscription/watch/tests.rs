mod fallback;

use super::*;
use std::future::Future;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::ClientCapabilities;
use fastmcp_protocol::dpop::DpopKey;
use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::DpopHttpPolicy;
use crate::http_auth::dpop::native::core::DpopCoreError;

fn limits(notifications: usize) -> DpopStreamLimits {
    DpopStreamLimits::new(
        ManagedCoreLimits::new(8192, 8192, 32768, notifications, Duration::from_secs(60)).unwrap(),
        Duration::from_secs(10),
    ).unwrap()
}

fn state(notifications: usize) -> WatchState {
    WatchState::new("watch", DpopTaskWatchPolicy::new(2).unwrap(), limits(notifications)).unwrap()
}

fn task() -> TaskId { TaskId::parse("task-one").unwrap() }

fn decoder(state: &WatchState) -> TaskSubscriptionDecoder {
    let selected = state.selection(FinalRequestMeta::new(ClientCapabilities::default()), &task()).unwrap();
    let id = selected.discovery_id.clone();
    let prepared = Prepared::new("https://mcp.example/mcp", selected,
        state.remaining_limits().unwrap().core, 8192).unwrap();
    let body = serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":id, "result":{
        "resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION],
        "capabilities":{"extensions":{TASKS_EXTENSION:{}}}, "ttlMs":0, "cacheScope":"private",
        "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"watch-peer","version":"1"}}
    }})).unwrap();
    prepared.admit(DpopHttpResponse { status:200, headers:vec![], body }).unwrap().1
}

fn ack(ids: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged",
        "params":{"notifications":{"taskIds":ids},
            "_meta":{FINAL_SUBSCRIPTION_ID_META_KEY:"watch.listen"}}})).unwrap()
}

#[test]
fn policy_prefix_and_snapshot_budget_refuse_without_advancing_identity() {
    for count in [0, 1025, usize::MAX] { assert!(DpopTaskWatchPolicy::new(count).is_err()); }
    for count in [1, 1024] { assert!(DpopTaskWatchPolicy::new(count).is_ok()); }
    for prefix in [String::new(), "a".repeat(129), "bad/key".to_owned(), "雪".to_owned()] {
        assert!(matches!(WatchState::new(&prefix, DpopTaskWatchPolicy::default(), limits(1)),
            Err(DpopTaskWatchError::InvalidIdPrefix)));
    }
    let mut state = state(1);
    for _ in 0..2 { state.snapshot_request(&task()).unwrap(); }
    let before = (state.snapshots, state.usage);
    assert!(matches!(state.snapshot_request(&task()), Err(DpopTaskWatchError::SnapshotLimit)));
    assert_eq!((state.snapshots, state.usage), before);
    let selection = state.selection(FinalRequestMeta::new(ClientCapabilities::default()), &task()).unwrap();
    assert_eq!(selection.discovery_id, RequestId::String("watch.listen.discover".to_owned()));
    assert_eq!(selection.subscription_id, RequestId::String("watch.listen".to_owned()));
    assert_eq!(selection.task_ids, vec![task()]);
}

#[test]
fn byte_and_notification_admission_is_atomic_and_never_replenishes() {
    let mut state = state(2);
    state.charge((10, 2)).unwrap();
    let before = state.usage;
    assert!(state.charge((7, 1)).is_err());
    assert_eq!(state.usage, before);
    assert_eq!(state.remaining_limits().unwrap().core.notifications(), 0);
    assert!(state.charge((usize::MAX, 0)).is_err());
    assert_eq!(state.usage, before);
    state.charge((32758, 0)).unwrap();
    assert_eq!(state.usage, (32768, 2));
    assert!(state.remaining_limits().is_err());
    assert!(state.charge((1, 0)).is_err());
    assert_eq!(state.usage, (32768, 2));
}

#[test]
fn acknowledgement_must_include_the_watched_task_not_merely_be_valid() {
    for included in [false, true] {
        let state = state(2);
        let mut decoder = decoder(&state);
        assert!(matches!(WatchState::require_acknowledged(&decoder, &task()),
            Err(DpopTaskWatchError::TaskNotAcknowledged)));
        let wire = ack(if included { &["task-one"] } else { &[] });
        assert!(matches!(decoder.admit(&wire, true).unwrap(), StreamEvent::Notification(_)));
        let before = decoder.usage();
        assert_eq!(WatchState::require_acknowledged(&decoder, &task()).is_ok(), included);
        assert_eq!(decoder.usage(), before, "watch selection checks cannot mutate wire admission");
    }
}

#[test]
fn snapshot_discovery_ack_and_later_snapshot_share_the_decoder_budget() {
    let mut state = state(3);
    state.charge((17, 1)).unwrap();
    let mut decoder = decoder(&state);
    let discovery_usage = decoder.usage();
    state.charge(discovery_usage).unwrap();
    decoder.limits = state.limits.core;
    decoder.bytes = state.usage.0;
    decoder.notifications = state.usage.1;
    let wire = ack(&["task-one"]);
    decoder.admit(&wire, true).unwrap();
    state.usage = decoder.usage();
    assert_eq!(state.usage, (17 + discovery_usage.0 + wire.len(), 2));
    // A subsequent get notification is real usage even though the watch does
    // not forward request-scoped progress to application code.
    state.charge((23, 1)).unwrap();
    decoder.bytes = state.usage.0;
    decoder.notifications = state.usage.1;
    let before = decoder.usage();
    let status = serde_json::to_vec(&json!({"jsonrpc":"2.0", "method":TASK_STATUS_NOTIFICATION,
        "params":{"taskId":"task-one", "status":"cancelled", "ttlMs":null,
            "createdAt":"2026-09-16T00:00:00Z", "lastUpdatedAt":"2026-09-16T00:00:00Z",
            "_meta":{FINAL_SUBSCRIPTION_ID_META_KEY:"watch.listen"}}})).unwrap();
    assert!(matches!(decoder.admit(&status, true), Err(DpopStreamError::Core(
        DpopCoreError::Protocol(ManagedCoreError::NotificationLimit)))));
    assert_eq!(decoder.usage(), before);
    // Exhausting notification slots still allows the listen's terminal.
    let terminal = serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":"watch.listen",
        "result":{"resultType":"complete",
            "_meta":{FINAL_SUBSCRIPTION_ID_META_KEY:"watch.listen"}}})).unwrap();
    assert!(matches!(decoder.admit(&terminal, true).unwrap(), StreamEvent::Result(_)));
}

#[test]
fn public_watch_honors_precancellation_before_runtime_or_prefix_admission() {
    for cancel_cx in [false, true] {
        for prefix in ["watch", ""] {
            let cx = Cx::for_testing();
            let cancellation = McpRequestCancellation::new();
            if cancel_cx { cx.set_cancel_requested(true); } else { cancellation.cancel(); }
            let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
            let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(),
                CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap()).unwrap();
            let credential = session.admit_token_response(&issuer, 200,
                br#"{"access_token":"watch-test-token","token_type":"DPoP","expires_in":60}"#,
                Instant::now(), Duration::from_secs(60)).unwrap();
            let mut client = DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap();
            let mut operation = Box::pin(client.watch_task_with_cancellation(
                &cx, &cancellation, &credential, FinalRequestMeta::new(ClientCapabilities::default()),
                task(), prefix, DpopTaskWatchPolicy::default(), limits(2),
            ));
            assert!(matches!(operation.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                    DpopCoreError::Transport(DpopHttpError::Cancelled)))))));
            drop(operation);
            assert!(!client.revocation_handle().is_revoked());
            let fresh = Cx::for_testing();
            let fresh_cancellation = McpRequestCancellation::new();
            let mut operation = Box::pin(client.watch_task_with_cancellation(
                &fresh, &fresh_cancellation, &credential,
                FinalRequestMeta::new(ClientCapabilities::default()), task(), "fresh",
                DpopTaskWatchPolicy::default(), limits(2),
            ));
            assert!(matches!(operation.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                    DpopCoreError::Transport(DpopHttpError::RuntimeUnavailable)))))));
        }
    }
}

#[test]
fn reconnect_policy_bounds_and_delay_are_explicit() {
    for count in [0, 65, usize::MAX] {
        assert!(DpopTaskReconnectPolicy::new(count, Duration::from_millis(1)).is_err());
    }
    for delay in [Duration::ZERO, Duration::from_nanos(999_999), Duration::from_secs(61)] {
        assert!(DpopTaskReconnectPolicy::new(1, delay).is_err());
    }
    for count in [1, 64] {
        for delay in [Duration::from_millis(1), Duration::from_secs(60)] {
            assert!(DpopTaskReconnectPolicy::new(count, delay).is_ok());
        }
    }
    let now = Cx::for_testing().now();
    let mut ordinary = state(2);
    assert!(ordinary.begin_reconnect(now).unwrap().is_none());
    assert_eq!(ordinary.reconnects, 0);
    let policy = DpopTaskWatchPolicy::new(8).unwrap()
        .with_reconnects(2, Duration::from_millis(17)).unwrap();
    let mut reconnecting = WatchState::new("watch", policy, limits(4)).unwrap();
    reconnecting.charge((91, 1)).unwrap();
    for ordinal in 1..=2 {
        let before = (reconnecting.snapshots, reconnecting.usage);
        assert_eq!(reconnecting.begin_reconnect(now).unwrap(), Some(now.saturating_add_nanos(17_000_000)));
        assert_eq!((reconnecting.snapshots, reconnecting.usage), before);
        let selected = reconnecting.selection(FinalRequestMeta::new(ClientCapabilities::default()), &task()).unwrap();
        assert_eq!(selected.subscription_id, RequestId::String(format!("watch.listen.{ordinal}")));
        assert_eq!(selected.discovery_id, RequestId::String(format!("watch.listen.{ordinal}.discover")));
        assert_eq!(selected.task_ids, vec![task()]);
    }
    assert!(matches!(reconnecting.begin_reconnect(now), Err(DpopTaskWatchError::ReconnectLimit)));
    assert_eq!(reconnecting.reconnects, 2);
    reconnecting.policy = policy.with_polling_fallback(1, Duration::from_millis(1)).unwrap();
    assert!(reconnecting.begin_reconnect(now).unwrap().is_none());
    assert_eq!(reconnecting.reconnects, 2);
    assert_eq!(reconnecting.usage, (91, 1));
}

#[test]
fn reconnect_cannot_replenish_or_partially_advance_exhausted_admission() {
    for dimension in 0..3 {
        let policy = DpopTaskWatchPolicy::new(2).unwrap()
            .with_reconnects(1, Duration::from_millis(1)).unwrap();
        let mut watch = WatchState::new("watch", policy, limits(2)).unwrap();
        match dimension {
            0 => { for _ in 0..2 { watch.snapshot_request(&task()).unwrap(); } }
            1 => watch.charge((32768, 0)).unwrap(),
            _ => watch.charge((17, 2)).unwrap(),
        }
        let before = (watch.reconnects, watch.snapshots, watch.usage);
        assert!(watch.begin_reconnect(Cx::for_testing().now()).is_err());
        assert_eq!((watch.reconnects, watch.snapshots, watch.usage), before);
        let selected = watch.selection(FinalRequestMeta::new(ClientCapabilities::default()), &task()).unwrap();
        assert_eq!(selected.subscription_id, RequestId::String("watch.listen".to_owned()));
    }
}

#[test]
fn successor_requires_its_own_acknowledgement_and_preserves_cumulative_usage() {
    let policy = DpopTaskWatchPolicy::new(8).unwrap()
        .with_reconnects(2, Duration::from_millis(1)).unwrap();
    let mut watch = WatchState::new("watch", policy, limits(3)).unwrap();
    // Simulate admitted earlier discovery, get and acknowledgement charges.
    watch.charge((500, 1)).unwrap();
    watch.snapshot_request(&task()).unwrap();
    watch.begin_reconnect(Cx::for_testing().now()).unwrap().unwrap();
    let mut successor = decoder(&watch);
    assert!(WatchState::require_acknowledged(&successor, &task()).is_err());
    assert!(successor.admit(&ack(&["task-one"]), true).is_err(),
        "an old listen's ACK cannot authorize the successor");
    assert!(WatchState::require_acknowledged(&successor, &task()).is_err());
    let mut successor = decoder(&watch);
    watch.charge(successor.usage()).unwrap();
    successor.limits = watch.limits.core;
    successor.bytes = watch.usage.0;
    successor.notifications = watch.usage.1;
    let fresh = serde_json::to_vec(&json!({"jsonrpc":"2.0",
        "method":"notifications/subscriptions/acknowledged",
        "params":{"notifications":{"taskIds":["task-one"]},
            "_meta":{FINAL_SUBSCRIPTION_ID_META_KEY:"watch.listen.1"}}})).unwrap();
    let before = watch.usage;
    assert!(matches!(successor.admit(&fresh, true).unwrap(), StreamEvent::Notification(_)));
    WatchState::require_acknowledged(&successor, &task()).unwrap();
    watch.usage = successor.usage();
    assert_eq!(watch.usage, (before.0 + fresh.len(), before.1 + 1));
    assert_eq!(watch.remaining_limits().unwrap().core.notifications(), 1);
    assert_eq!(watch.snapshots, 1, "fresh ACK cannot reset the snapshot counter");
}
