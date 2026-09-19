use super::*;
use std::cell::Cell;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Wake};

use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::JsonRpcRequest;
use serde_json::json;

use super::super::ClientCredentialsResourceLimits;
use super::super::tests::{complete, consumer, ordinary, prime, runtime};

struct Flag(AtomicBool);
impl Wake for Flag { fn wake(self: Arc<Self>) { self.0.store(true, Ordering::Release); } }
fn waker() -> Waker { Waker::from(Arc::new(Flag(AtomicBool::new(false)))) }
fn ledger(
    pairs: Vec<(RequestId, RequestId)>, limits: ClientCredentialsResourceWatchLimits,
) -> Mutex<WatchIds<impl FnMut() -> Result<(RequestId, RequestId), ClientCredentialsResourceError>>> {
    let mut pairs = pairs.into_iter();
    Mutex::new(WatchIds {
        next: move || pairs.next().ok_or_else(|| ManagedResourceError::AbortedByHost.into()),
        used: Vec::new(), bytes: 0, limits,
    })
}

#[test]
fn machine_resource_watch_requires_exact_uri_and_catalog_coverage() {
    let request = ordinary();
    let (metadata, filter) = listen_arguments(&request).unwrap();
    assert_eq!(serde_json::to_value(metadata).unwrap(), request.encode_params().unwrap().unwrap()["_meta"]);
    assert_eq!(serde_json::to_value(&filter).unwrap(), json!({
        "resourcesListChanged":true, "resourceSubscriptions":["file:///one"],
    }));
    assert!(covers("file:///one", &filter));
    assert!(!covers("file:///other", &filter));
    let mut missing_catalog = filter.clone();
    missing_catalog.resources_list_changed = Some(false);
    assert!(!covers("file:///one", &missing_catalog));
    let mut missing_uri = filter.clone();
    missing_uri.resource_subscriptions = Some(vec![]);
    assert!(!covers("file:///one", &missing_uri));
    assert!(!covers("file:///one", &SubscriptionFilter::default()));
}

#[test]
fn machine_resource_watch_preserves_host_metadata_but_refuses_continuations() {
    let mut params = ordinary().encode_params().unwrap().unwrap();
    params["_meta"]["com.example/tenant"] = json!({"name":"tenant-a"});
    let request = CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", Some(&params)).unwrap();
    let (metadata, _) = listen_arguments(&request).unwrap();
    assert_eq!(serde_json::to_value(metadata).unwrap(), params["_meta"]);
    for (field, value) in [("requestState", json!("")), ("inputResponses", json!({}))] {
        let mut continuation = params.clone();
        continuation[field] = value;
        let request = CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", Some(&continuation)).unwrap();
        assert!(matches!(listen_arguments(&request), Err(ClientCredentialsResourceWatchError::ContinuationNotAllowed)));
    }
}

#[test]
fn machine_resource_watch_only_resource_notifications_schedule_reads() {
    for (method, params, expected) in [
        ("notifications/resources/updated", Some(json!({"uri":"file:///one"})), true),
        ("notifications/resources/list_changed", None, true),
        ("notifications/tools/list_changed", None, false),
        ("notifications/prompts/list_changed", None, false),
    ] {
        let notification = ServerNotification::decode(&JsonRpcRequest::notification(method, params)).unwrap();
        assert_eq!(relevant(&notification), expected);
    }
}

#[test]
fn machine_resource_watch_changes_cancel_only_the_obsolete_read_and_coalesce() {
    let signal = ChangeSignal::default();
    let first = signal.begin(0).unwrap().unwrap();
    let sibling = McpRequestCancellation::new();
    signal.changed().unwrap();
    signal.changed().unwrap();
    assert!(first.is_cancel_requested());
    assert!(!sibling.is_cancel_requested());
    assert_eq!(signal.revision().unwrap(), 2);
    assert!(signal.begin(0).unwrap().is_none());
    let next = signal.begin(2).unwrap().unwrap();
    signal.finish().unwrap();
    signal.changed().unwrap();
    assert!(!next.is_cancel_requested());
}

#[test]
fn machine_resource_watch_idle_wait_is_woken_by_change_without_busy_polling() {
    let flag = Arc::new(Flag(AtomicBool::new(false)));
    let waker = Waker::from(flag.clone());
    let mut context = Context::from_waker(&waker);
    let signal = ChangeSignal::default();
    let mut waiting = Box::pin(signal.wait_after(Some(0)));
    assert!(waiting.as_mut().poll(&mut context).is_pending());
    signal.changed().unwrap();
    assert!(flag.0.load(Ordering::Acquire));
    assert!(matches!(waiting.as_mut().poll(&mut context), Poll::Ready(Ok(1))));
}

#[test]
fn machine_resource_watch_ready_gap_wins_before_a_ready_snapshot() {
    let published = AtomicBool::new(false);
    let mut race = Box::pin(monitor_first(async { Ok::<_, ()>(1) }, async {
        published.store(true, Ordering::Release);
        Ok(2)
    }));
    let waker = waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(race.as_mut().poll(&mut context), Poll::Ready(Ok(1))));
    assert!(!published.load(Ordering::Acquire));
}

#[test]
fn machine_resource_watch_does_not_drop_a_pending_feed_when_reads_yield() {
    struct DropFlag(Arc<AtomicUsize>);
    impl Drop for DropFlag { fn drop(&mut self) { self.0.fetch_add(1, Ordering::AcqRel); } }
    let drops = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&drops);
    let monitor = async move {
        let _guard = DropFlag(observed);
        std::future::pending::<Result<usize, ()>>().await
    };
    let reads = async { yield_once().await; Ok(1) };
    let mut race = Box::pin(monitor_first(monitor, reads));
    let waker = waker();
    let mut context = Context::from_waker(&waker);
    assert!(race.as_mut().poll(&mut context).is_pending());
    assert_eq!(drops.load(Ordering::Acquire), 0);
    assert!(matches!(race.as_mut().poll(&mut context), Poll::Ready(Ok(1))));
    drop(race);
    assert_eq!(drops.load(Ordering::Acquire), 1);
}

#[test]
fn machine_resource_watch_pair_reservations_reject_aliases_atomically() {
    let ids = ledger(vec![
        (RequestId::Number(1), RequestId::Number(2)),
        (serde_json::from_str("1.0").unwrap(), RequestId::Number(3)),
        (RequestId::Number(3), serde_json::from_str("3e0").unwrap()),
        (RequestId::String("1".to_owned()), RequestId::String("2".to_owned())),
    ], ClientCredentialsResourceWatchLimits::default());
    issue_pair(&ids).unwrap();
    let before = ids.lock().unwrap().bytes;
    for _ in 0..2 {
        assert!(matches!(issue_pair(&ids), Err(ClientCredentialsResourceError::Core(
            ClientCredentialsCoreError::Protocol(ManagedCoreError::InvalidRequest)))));
        let state = ids.lock().unwrap();
        assert_eq!(state.used.len(), 2);
        assert_eq!(state.bytes, before);
    }
    issue_pair(&ids).unwrap();
    assert_eq!(ids.lock().unwrap().used.len(), 4);
}

#[test]
fn machine_resource_watch_id_byte_and_count_limits_prevent_partial_reservations() {
    let limits = ClientCredentialsResourceWatchLimits::new(Duration::from_secs(1), 1, 3, 2).unwrap();
    let ids = ledger(vec![
        (RequestId::Number(1), RequestId::Number(222)),
        (RequestId::Number(1), RequestId::Number(2)),
        (RequestId::Number(3), RequestId::Number(4)),
    ], limits);
    assert!(issue_pair(&ids).is_err());
    {
        let state = ids.lock().unwrap();
        assert_eq!((state.used.len(), state.bytes), (0, 0));
    }
    issue_pair(&ids).unwrap();
    assert!(issue_pair(&ids).is_err());
    let state = ids.lock().unwrap();
    assert_eq!((state.used.len(), state.bytes), (2, 2));
    drop(state);
    let calls = Cell::new(0);
    let ids = Mutex::new(WatchIds {
        next: || {
            calls.set(calls.get() + 1);
            let id = calls.get() * 2;
            Ok((RequestId::Number(id), RequestId::Number(id + 1)))
        }, used: Vec::new(), bytes: 0,
        limits: ClientCredentialsResourceWatchLimits::new(Duration::from_secs(1), 1, 1024, 2).unwrap(),
    });
    issue_pair(&ids).unwrap(); // subscription
    issue_pair(&ids).unwrap(); // the one permitted read
    assert!(issue_pair(&ids).is_err());
    assert_eq!(calls.get(), 2);
}

#[test]
fn machine_resource_watch_never_retries_transport_auth_or_host_failures() {
    let local = McpRequestCancellation::new();
    let cancelled = ClientCredentialsResourceError::from(ManagedCoreError::Cancelled);
    assert!(!is_invalidation_stop(&cancelled, &local));
    local.cancel();
    assert!(is_invalidation_stop(&cancelled, &local));
    assert!(is_invalidation_stop(&ManagedResourceError::Invalidated.into(), &local));
    for error in [
        ClientCredentialsResourceError::from(ClientCredentialsError::Transport),
        ClientCredentialsResourceError::from(ClientCredentialsError::Expired),
        ClientCredentialsResourceError::from(ClientCredentialsError::Closed),
        ClientCredentialsResourceError::from(ManagedCoreError::InvalidResponse),
        ClientCredentialsResourceError::from(ManagedResourceError::AbortedByHost),
        ClientCredentialsResourceError::from(ManagedResourceError::CredentialChanged),
    ] { assert!(!is_invalidation_stop(&error, &local)); }
}

#[test]
fn machine_resource_watch_observer_error_survives_local_cancellation_masking() {
    let observer = Observer {
        callback: Mutex::new(|_: ClientCredentialsResourceWatchEvent| {
            Err(ManagedResourceError::AbortedByHost.into())
        }),
        stopped: AtomicBool::new(false), failed: AtomicBool::new(false),
    };
    let local = McpRequestCancellation::new();
    local.cancel();
    assert!(observer.emit(ClientCredentialsResourceWatchEvent::Acknowledged {
        accepted_filter: SubscriptionFilter::default(),
    }).is_err());
    // The credential boundary may report cancellation instead of the callback
    // error. The sticky check runs before the driver's restart classifier.
    assert!(is_invalidation_stop(&ManagedCoreError::Cancelled.into(), &local));
    assert!(matches!(observer.check_failure(),
        Err(ClientCredentialsResourceError::Resource(ManagedResourceError::AbortedByHost))));
}

#[test]
fn machine_resource_watch_aborted_opening_fences_preexisting_cache() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let client = consumer(ClientCredentialsResourceLimits::default());
        let request = ordinary();
        prime(&client, &request, complete(&request, 60000, "public"));
        let calls = Cell::new(0);
        let result = client.watch(&cx, request.clone(), ClientCredentialsResourceWatchLimits::default(), || {
            calls.set(calls.get() + 1);
            Err(ManagedResourceError::AbortedByHost.into())
        }, |_| panic!("failed opening cannot emit watch events")).await;
        assert!(matches!(result, Err(ClientCredentialsResourceWatchError::Resource(
            ClientCredentialsResourceError::Resource(ManagedResourceError::AbortedByHost)))));
        assert_eq!(calls.get(), 1);
        assert!(!client.client.inner.closed.is_cancel_requested());
        let result = client.read(&cx, request, || Err(ManagedResourceError::AbortedByHost.into()), |_| Ok(())).await;
        assert!(matches!(result, Err(ClientCredentialsResourceError::Resource(ManagedResourceError::AbortedByHost))));
    });
}

#[test]
fn machine_resource_watch_id_callback_cancellation_prevents_listen_dispatch() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let client = consumer(ClientCredentialsResourceLimits::default());
        let cancellation = McpRequestCancellation::new();
        let result = client.watch_with_cancellation(&cx, &cancellation, ordinary(),
            ClientCredentialsResourceWatchLimits::default(), || {
                cancellation.cancel();
                Ok((RequestId::Number(1), RequestId::Number(2)))
            }, |_| panic!("cancelled opening cannot emit watch events")).await;
        assert!(result.is_err());
        assert!(!client.client.inner.closed.is_cancel_requested());
    });
}

#[test]
fn machine_resource_watch_gap_guard_fences_inflight_generations() {
    let client = consumer(ClientCredentialsResourceLimits::default());
    let set = FinalCacheResultSet::Resource("file:///one".to_owned());
    let before = client.cache().unwrap().begin_fetch(&set);
    let tools = client.cache().unwrap().begin_fetch(&FinalCacheResultSet::Tools);
    drop(InvalidateOnExit { cache: Arc::clone(&client.cache), set: set.clone() });
    assert_ne!(before, client.cache().unwrap().begin_fetch(&set));
    assert_eq!(tools, client.cache().unwrap().begin_fetch(&FinalCacheResultSet::Tools));
}

#[test]
fn machine_resource_watch_limits_are_finite_and_leave_room_for_ack_and_terminal() {
    for (seconds, reads, bytes, records) in [(0,1,1,2),(3601,1,1,2),(1,0,1,2),
        (1,1025,1,2),(1,1,0,2),(1,1,8*1024*1024+1,2),(1,1,1,1),(1,1,1,4097)]
    {
        assert!(ClientCredentialsResourceWatchLimits::new(Duration::from_secs(seconds), reads, bytes, records).is_err());
    }
    assert!(ClientCredentialsResourceWatchLimits::new(Duration::from_secs(3600), 1024, 8*1024*1024, 4096).is_ok());
}
