//! Portable, bounded-peer coverage for the public Memory Task watch surface.

use super::*;
use std::future::poll_fn;
use std::pin::pin;

use asupersync::runtime::RuntimeBuilder;
use fastmcp_core::McpErrorCode;
use fastmcp_protocol::{
    ClientInfo, CoreResult, DiscoveryCacheHints, FinalCoreResult, JsonRpcMessage, JsonRpcRequest,
    JsonRpcResponse, ServerBehavior, ServerBehaviorRegistry, ServerDiscoverCapabilities,
    ServerDiscoverResult, ServerInfo,
};
use fastmcp_transport::memory::{MemoryTransport, create_memory_transport_pair_with_capacity};
use serde_json::{Value, json};

const CREATED: &str = "2026-07-28T00:00:00Z";
const TASK_ID: &str = "memory-watch-task";

fn run<F: Future<Output = ()>>(test: impl FnOnce(Cx) -> F) {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(8), test(cx))
            .await
            .expect("Memory Task watches must progress on the caller runtime");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn opaque_result() -> Value {
    // Memory has a typed sender: these are the exact numeric lexemes in its
    // committed canonical encoding, not an imagined pre-serialization source.
    let mut result = json!({"content": [], "x-first": null, "x-zero": null, "x-last": null});
    for (key, lexeme) in [
        ("x-first", "1.20e+4"),
        ("x-zero", "-0"),
        ("x-last", "123456789012345678901234567890"),
    ] {
        result[key] = Value::Number(serde_json::Number::from_string_unchecked(lexeme.to_owned()));
    }
    result
}

fn task(status: &str, ttl_ms: Option<u64>, updated_second: u8) -> Value {
    let mut task = json!({
        "taskId": TASK_ID, "status": status, "createdAt": CREATED,
        "lastUpdatedAt": format!("2026-07-28T00:00:{updated_second:02}Z"), "ttlMs": ttl_ms,
    });
    if status == "completed" {
        task["result"] = opaque_result();
    }
    task
}

fn live_ttl(remaining: Duration) -> u64 {
    let created = fastmcp_protocol::TaskTimestamp::parse(CREATED).unwrap();
    let elapsed = wall_now_nanos() - timestamp_nanos(&created).unwrap();
    u64::try_from(elapsed / 1_000_000).unwrap()
        + u64::try_from(remaining.as_millis()).unwrap()
}

fn response(id: i64, result: Value) -> JsonRpcMessage {
    JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), result))
}

fn task_response(id: i64, mut task: Value) -> JsonRpcMessage {
    task["resultType"] = json!("complete");
    response(id, task)
}

fn notification(method: &str, id: i64, mut params: Value) -> JsonRpcMessage {
    params["_meta"] = json!({"io.modelcontextprotocol/subscriptionId": id});
    JsonRpcMessage::Request(JsonRpcRequest::notification(method, Some(params)))
}

fn acknowledgement(id: i64, ids: Value) -> JsonRpcMessage {
    notification(
        "notifications/subscriptions/acknowledged",
        id,
        json!({"notifications": {"taskIds": ids}}),
    )
}

fn task_notification(id: i64, mut task: Value) -> JsonRpcMessage {
    task["diagnostic"] = json!({"opaque": true});
    notification("notifications/tasks", id, task)
}

fn tools_response(id: i64) -> JsonRpcMessage {
    response(id, json!({"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"}))
}

async fn receive(
    cx: &Cx,
    peer: &mut MemoryTransport,
    method: &str,
    id: Option<i64>,
) -> JsonRpcRequest {
    let JsonRpcMessage::Request(request) = peer.recv_async(cx).await.unwrap() else {
        panic!("expected a Memory client request");
    };
    assert_eq!(request.method, method);
    assert_eq!(request.id, id.map(RequestId::Number));
    request
}

async fn receive_cancel(cx: &Cx, peer: &mut MemoryTransport, id: i64) {
    let request = receive(cx, peer, "notifications/cancelled", None).await;
    let params = request.params.unwrap();
    assert_eq!(params["requestId"], id);
    assert!(params.get("_meta").is_none(), "client cancellation is id-only");
}

async fn attached(cx: &Cx, initial: Value) -> (MemoryClient, FinalTaskHandle, MemoryTransport) {
    let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
    let capabilities = ServerDiscoverCapabilities::from_registry(
        &ServerBehaviorRegistry::from_behaviors([
            ServerBehavior::ToolsList,
            ServerBehavior::ToolsListChangedNotification,
            ServerBehavior::SubscriptionsListen,
        ]),
        std::collections::BTreeMap::from([(
            fastmcp_protocol::TASKS_EXTENSION.to_owned(), json!({}),
        )]),
    ).unwrap();
    let discovery = ServerDiscoverResult::new(
        capabilities,
        ServerInfo { name: "memory-watch-peer".to_owned(), version: "1".to_owned() },
        None,
        DiscoveryCacheHints::private_ttl_ms(0),
    );
    let mut discovery = serde_json::to_value(discovery).unwrap();
    discovery["supportedVersions"] = json!([crate::MODERN_PROTOCOL_VERSION]);
    peer.send_async(cx, &response(1, discovery)).await.unwrap();
    let mut client = MemoryClient::builder(ClientInfo {
        name: "memory-watch-client".to_owned(), version: "1".to_owned(),
    }).with_tasks().connect(cx, transport).await.unwrap();
    receive(cx, &mut peer, "server/discover", Some(1)).await;
    peer.send_async(cx, &task_response(2, initial)).await.unwrap();
    let handle = client.attach_final_task(
        cx, &McpRequestCancellation::new(), FinalTaskId::parse(TASK_ID).unwrap(),
    ).await.unwrap();
    let request = receive(cx, &mut peer, "tasks/get", Some(2)).await;
    assert_eq!(request.params.unwrap()["taskId"], TASK_ID);
    (client, handle, peer)
}

async fn listen(cx: &Cx, peer: &mut MemoryTransport, id: i64) {
    let request = receive(cx, peer, "subscriptions/listen", Some(id)).await;
    assert_eq!(request.params.unwrap()["notifications"]["taskIds"], json!([TASK_ID]));
}

async fn assert_tools(cx: &Cx, client: &mut MemoryClient) {
    assert!(matches!(
        client.list_tools(cx, &McpRequestCancellation::new(), None).await.unwrap(),
        CoreResult::Final(FinalCoreResult::ToolsList { .. }),
    ));
}

/// Strictly checks every subsequent outbound method: observation must never
/// send tasks/update, tasks/cancel, a second reconciliation, or a creating call.
async fn finish(
    cx: &Cx,
    client: &mut MemoryClient,
    mut peer: MemoryTransport,
    cancellations: Vec<i64>,
    next_id: i64,
) {
    let mut server = cx.spawn(move |peer_cx| async move {
        for id in cancellations {
            receive_cancel(&peer_cx, &mut peer, id).await;
        }
        receive(&peer_cx, &mut peer, "tools/list", Some(next_id)).await;
        peer.send_async(&peer_cx, &tools_response(next_id)).await.unwrap();
        peer
    }).unwrap();
    assert_tools(cx, client).await;
    let mut peer = server.join(cx).await.unwrap();
    client.close(cx).unwrap();
    assert!(peer.recv_async(cx).await.is_err(), "no implicit effects after observation");
}

#[test]
fn memory_task_watch_renews_skips_duplicates_reconciles_and_retains_exact_completion() {
    run(|cx| async move {
        let initial = task("working", Some(live_ttl(Duration::from_secs(30))), 1);
        let (mut client, mut handle, mut peer) = attached(&cx, initial).await;
        let live = McpRequestCancellation::new();
        let mut watch = handle.watch_with_memory(&cx, &mut client, &live).await.unwrap();
        listen(&cx, &mut peer, 3).await;
        let mut server = cx.spawn(move |peer_cx| async move {
            let renewed = task("working", Some(live_ttl(Duration::from_secs(60))), 2);
            for event in [
                acknowledgement(3, json!([TASK_ID, TASK_ID])),
                task_notification(3, renewed.clone()),
                task_notification(3, renewed),
                task_notification(3, task("working", None, 2)),
            ] {
                peer.send_async(&peer_cx, &event).await.unwrap();
            }
            let read = receive(&peer_cx, &mut peer, "tasks/get", Some(4)).await;
            assert_eq!(read.params.unwrap()["taskId"], TASK_ID);
            let mut authoritative = task("working", None, 1);
            authoritative["createdAt"] = json!("2026-07-28T00:00:00+00:00");
            peer.send_async(&peer_cx, &task_response(4, authoritative)).await.unwrap();
            for _ in 0..2 {
                peer.send_async(&peer_cx, &task_notification(3, task("completed", None, 3))).await.unwrap();
            }
            receive_cancel(&peer_cx, &mut peer, 3).await;
            receive(&peer_cx, &mut peer, "tools/list", Some(5)).await;
            peer.send_async(&peer_cx, &tools_response(5)).await.unwrap();
            peer
        }).unwrap();
        assert!(matches!(watch.next_event(&cx, &live).await.unwrap(),
            Some(FinalTaskWatchEvent::Acknowledged { .. })));
        let Some(FinalTaskWatchEvent::TaskUpdated(renewed)) =
            watch.next_event(&cx, &live).await.unwrap()
        else { panic!("renewal must be a live update"); };
        assert_eq!(serde_json::to_value(renewed).unwrap()["params"]["diagnostic"], json!({"opaque": true}));
        assert!(watch.task().base().ttl_ms.is_some());
        let Some(FinalTaskWatchEvent::TaskReconciled { observed, authoritative }) =
            watch.next_event(&cx, &live).await.unwrap()
        else { panic!("duplicate must be skipped before one authoritative read"); };
        assert!(observed.params.task.base().ttl_ms.is_none());
        assert!(authoritative.base().ttl_ms.is_none());
        assert_eq!(authoritative.base().created_at.as_str(), "2026-07-28T00:00:00+00:00");
        assert!(matches!(watch.next_event(&cx, &live).await.unwrap(),
            Some(FinalTaskWatchEvent::TaskUpdated(_))));
        let FinalTask::Completed { result, .. } = watch.task() else {
            panic!("completion must replace the retained working snapshot");
        };
        assert_eq!(serde_json::to_string(result).unwrap(), serde_json::to_string(&opaque_result()).unwrap());
        assert_eq!(watch.stop_reason(), Some(FinalTaskWaitOutcome::Completed));
        assert!(watch.next_event(&cx, &live).await.unwrap().is_none());
        drop(watch);
        // A terminal handle never creates another subscription, even though a
        // late duplicate completion remains in the bounded inbound channel.
        let mut terminal = handle.watch_with_memory(&cx, &mut client, &live).await.unwrap();
        assert_eq!(terminal.stop_reason(), Some(FinalTaskWaitOutcome::Completed));
        assert!(terminal.next_event(&cx, &live).await.unwrap().is_none());
        drop(terminal);
        assert_tools(&cx, &mut client).await;
        let mut peer = server.join(&cx).await.unwrap();
        client.close(&cx).unwrap();
        assert!(peer.recv_async(&cx).await.is_err());
    });
}

#[test]
fn memory_task_watch_event_drop_and_owner_drop_preserve_catalog_and_sibling_requests() {
    run(|cx| async move {
        for cancel in [false, true] {
            let (mut client, mut handle, mut peer) = attached(&cx, task("working", None, 1)).await;
            let before = serde_json::to_vec(handle.task()).unwrap();
            let live = McpRequestCancellation::new();
            let mut catalog = client.subscribe(&cx, &live, SubscriptionFilter {
                tools_list_changed: Some(true), ..SubscriptionFilter::default()
            }).await.unwrap();
            receive(&cx, &mut peer, "subscriptions/listen", Some(3)).await;
            let mut sibling = client.execute_core(&cx, &live, "tools/list", json!({})).await.unwrap();
            receive(&cx, &mut peer, "tools/list", Some(4)).await;
            let original = McpRequestCancellation::new();
            let mut watch = handle.watch_with_memory(&cx, &mut client, &original).await.unwrap();
            listen(&cx, &mut peer, 5).await;
            for event in [
                notification("notifications/subscriptions/acknowledged", 3,
                    json!({"notifications":{"toolsListChanged":true}})),
                notification("notifications/tools/list_changed", 3, json!({})),
                tools_response(4),
            ] {
                peer.send_async(&cx, &event).await.unwrap();
                let mut waiting = pin!(watch.next_event(&cx, &original));
                poll_fn(|task_cx| {
                    assert!(waiting.as_mut().poll(task_cx).is_pending());
                    Poll::Ready(())
                }).await;
                // Each dropped event future retains this watch and every
                // independently owned event routed during the same poll.
            }
            peer.send_async(&cx, &acknowledgement(5, json!([TASK_ID]))).await.unwrap();
            assert!(matches!(watch.next_event(&cx, &original).await.unwrap(),
                Some(FinalTaskWatchEvent::Acknowledged { .. })));
            if cancel {
                original.cancel();
                assert!(watch.next_event(&cx, &original).await.unwrap().is_none());
                assert_eq!(watch.stop_reason(), Some(FinalTaskWaitOutcome::ObservationCancelled));
            }
            drop(watch);
            assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
            assert!(matches!(client.next_event(&cx, &live, &mut sibling).await.unwrap(),
                Some(crate::MemoryRequestEvent::Result(result))
                    if matches!(*result, CoreResult::Final(FinalCoreResult::ToolsList { .. }))));
            assert!(matches!(client.next_subscription_event(&cx, &live, &mut catalog).await.unwrap(),
                Some(MemorySubscriptionEvent::Acknowledged { .. })));
            assert!(matches!(client.next_subscription_event(&cx, &live, &mut catalog).await.unwrap(),
                Some(MemorySubscriptionEvent::Notification(_))));
            assert_eq!(catalog.accepted_filter().unwrap().tools_list_changed, Some(true));
            // Holding the independent catalog owner across this ordinary call
            // proves only the Task listener's cancellation is emitted.
            finish(&cx, &mut client, peer, vec![5], 6).await;
            drop(catalog);
        }
    });
}

#[test]
fn memory_task_watch_rejects_changed_identity_in_notifications_and_reconciliation() {
    run(|cx| async move {
        for reconcile in [false, true] {
            for field in ["taskId", "createdAt"] {
                let (mut client, mut handle, mut peer) = attached(&cx, task("working", None, 1)).await;
                let before = serde_json::to_vec(handle.task()).unwrap();
                let live = McpRequestCancellation::new();
                let mut watch = handle.watch_with_memory(&cx, &mut client, &live).await.unwrap();
                listen(&cx, &mut peer, 3).await;
                peer.send_async(&cx, &acknowledgement(3, json!([TASK_ID]))).await.unwrap();
                watch.next_event(&cx, &live).await.unwrap();
                let mut changed = task("completed", None, 2);
                changed[field] = json!(if field == "taskId" { "another-task" } else { "2026-07-28T00:00:01Z" });
                let mut server = cx.spawn(move |peer_cx| async move {
                    if reconcile {
                        let mut ambiguous = task("working", None, 1);
                        ambiguous["statusMessage"] = json!("authoritative read required");
                        peer.send_async(&peer_cx, &task_notification(3, ambiguous)).await.unwrap();
                        receive(&peer_cx, &mut peer, "tasks/get", Some(4)).await;
                        peer.send_async(&peer_cx, &task_response(4, changed)).await.unwrap();
                    } else {
                        peer.send_async(&peer_cx, &task_notification(3, changed)).await.unwrap();
                    }
                    peer
                }).unwrap();
                assert_eq!(watch.next_event(&cx, &live).await.unwrap_err().code, McpErrorCode::InvalidRequest);
                assert!(watch.next_event(&cx, &live).await.unwrap().is_none());
                drop(watch);
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                let peer = server.join(&cx).await.unwrap();
                finish(&cx, &mut client, peer, vec![3], if reconcile { 5 } else { 4 }).await;
            }
        }
    });
}

#[test]
fn memory_task_watch_empty_acceptance_and_peer_termination_keep_the_task_nonterminal() {
    run(|cx| async move {
        for mode in ["empty", "complete", "peer-cancel"] {
            let (mut client, mut handle, mut peer) = attached(&cx, task("working", None, 1)).await;
            let before = serde_json::to_vec(handle.task()).unwrap();
            let live = McpRequestCancellation::new();
            let mut watch = handle.watch_with_memory(&cx, &mut client, &live).await.unwrap();
            listen(&cx, &mut peer, 3).await;
            peer.send_async(&cx, &acknowledgement(3, if mode == "empty" { json!([]) } else { json!([TASK_ID]) })).await.unwrap();
            assert!(matches!(watch.next_event(&cx, &live).await.unwrap(),
                Some(FinalTaskWatchEvent::Acknowledged { .. })));
            if mode == "complete" {
                peer.send_async(&cx, &response(3, json!({
                    "resultType":"complete", "_meta":{"io.modelcontextprotocol/subscriptionId":3},
                }))).await.unwrap();
            } else if mode == "peer-cancel" {
                peer.send_async(&cx, &notification("notifications/cancelled", 3, json!({"requestId":3}))).await.unwrap();
            }
            assert!(watch.next_event(&cx, &live).await.unwrap().is_none());
            assert_eq!(watch.stop_reason(), None);
            assert!(watch.next_event(&cx, &live).await.unwrap().is_none());
            drop(watch);
            assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
            finish(&cx, &mut client, peer, if mode == "empty" { vec![3] } else { vec![] }, 4).await;
        }
    });
}

#[test]
fn memory_task_watch_drop_during_reconciliation_retires_read_and_listen_without_replay() {
    run(|cx| async move {
        let (mut client, mut handle, mut peer) = attached(&cx, task("working", None, 1)).await;
        let before = serde_json::to_vec(handle.task()).unwrap();
        let live = McpRequestCancellation::new();
        let mut sibling = client.execute_core(&cx, &live, "tools/list", json!({})).await.unwrap();
        receive(&cx, &mut peer, "tools/list", Some(3)).await;
        let mut watch = handle.watch_with_memory(&cx, &mut client, &live).await.unwrap();
        listen(&cx, &mut peer, 4).await;
        peer.send_async(&cx, &acknowledgement(4, json!([TASK_ID]))).await.unwrap();
        watch.next_event(&cx, &live).await.unwrap();
        let mut ambiguous = task("working", None, 1);
        ambiguous["statusMessage"] = json!("requires reconciliation");
        peer.send_async(&cx, &task_notification(4, ambiguous)).await.unwrap();
        {
            let mut waiting = pin!(watch.next_event(&cx, &live));
            let mut read = pin!(peer.recv_async(&cx));
            let sent = poll_fn(|task_cx| {
                assert!(waiting.as_mut().poll(task_cx).is_pending());
                read.as_mut().poll(task_cx)
            }).await.unwrap();
            let JsonRpcMessage::Request(sent) = sent else { panic!("expected authoritative read"); };
            assert_eq!(sent.method, "tasks/get");
            assert_eq!(sent.id, Some(RequestId::Number(5)));
        }
        assert!(watch.next_event(&cx, &live).await.unwrap().is_none());
        assert_eq!(watch.stop_reason(), None);
        drop(watch);
        assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
        let mut server = cx.spawn(move |peer_cx| async move {
            // The dropped get is retired before the remaining listen owner.
            receive_cancel(&peer_cx, &mut peer, 5).await;
            receive_cancel(&peer_cx, &mut peer, 4).await;
            peer.send_async(&peer_cx, &task_response(5, task("completed", None, 2))).await.unwrap();
            peer.send_async(&peer_cx, &tools_response(3)).await.unwrap();
            peer
        }).unwrap();
        assert!(matches!(client.next_event(&cx, &live, &mut sibling).await.unwrap(),
            Some(crate::MemoryRequestEvent::Result(_))));
        assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before, "a late get cannot update the retained handle");
        let peer = server.join(&cx).await.unwrap();
        finish(&cx, &mut client, peer, vec![], 6).await;
    });
}

#[test]
fn memory_task_watch_open_drop_under_backpressure_consumes_no_id_or_sibling() {
    run(|cx| async move {
        for cancel in [false, true] {
            let (mut client, mut handle, mut peer) = attached(&cx, task("working", None, 1)).await;
            let live = McpRequestCancellation::new();
            let mut sibling = client.execute_core(&cx, &live, "tools/list", json!({})).await.unwrap();
            // Keep id 3 in the one-slot outbound channel while opening the watch.
            let original = McpRequestCancellation::new();
            {
                let mut opening = pin!(handle.watch_with_memory(&cx, &mut client, &original));
                poll_fn(|task_cx| {
                    assert!(opening.as_mut().poll(task_cx).is_pending());
                    Poll::Ready(())
                }).await;
                if cancel {
                    original.cancel();
                    let stopped = opening.await.unwrap();
                    assert_eq!(stopped.stop_reason(), Some(FinalTaskWaitOutcome::ObservationCancelled));
                }
            }
            receive(&cx, &mut peer, "tools/list", Some(3)).await;
            peer.send_async(&cx, &tools_response(3)).await.unwrap();
            assert!(matches!(client.next_event(&cx, &live, &mut sibling).await.unwrap(),
                Some(crate::MemoryRequestEvent::Result(_))));
            let watch = handle.watch_with_memory(&cx, &mut client, &live).await.unwrap();
            listen(&cx, &mut peer, 4).await;
            drop(watch);
            finish(&cx, &mut client, peer, vec![4], 5).await;
        }
    });
}

#[test]
fn memory_task_watch_terminal_and_expired_admission_never_open_a_listener() {
    run(|cx| async move {
        for (status, cancel, expected) in [
            ("working", false, FinalTaskWaitOutcome::TaskExpired),
            ("working", true, FinalTaskWaitOutcome::ObservationCancelled),
            ("completed", true, FinalTaskWaitOutcome::Completed),
        ] {
            let (mut client, mut handle, peer) = attached(&cx, task(status, Some(1), 1)).await;
            let cancellation = McpRequestCancellation::new();
            if cancel { cancellation.cancel(); }
            let mut watch = handle.watch_with_memory(&cx, &mut client, &cancellation).await.unwrap();
            assert_eq!(watch.stop_reason(), Some(expected));
            assert!(watch.next_event(&cx, &cancellation).await.unwrap().is_none());
            drop(watch);
            finish(&cx, &mut client, peer, vec![], 3).await;
        }
    });
}

#[test]
fn memory_task_watch_pending_events_obey_original_retention_and_caller_deadline() {
    run(|cx| async move {
        for retention in [false, true] {
            let ttl = retention.then(|| live_ttl(Duration::from_millis(250)));
            let (mut client, mut handle, mut peer) = attached(&cx, task("working", ttl, 1)).await;
            let before = serde_json::to_vec(handle.task()).unwrap();
            let scope = cx.scope_with_budget(asupersync::Budget::INFINITE.with_deadline(
                cx.now() + if retention { Duration::from_secs(2) } else { Duration::from_millis(100) },
            ));
            // Memory publication requires a registered obligation holder.
            // spawn_in admits a real task with this scope's original budget;
            // a request-only Cx or region principal cannot publish the listen.
            let mut observer = cx.spawn_in(&scope, move |caller| async move {
                let live = McpRequestCancellation::new();
                let mut watch = handle.watch_with_memory(&caller, &mut client, &live).await.unwrap();
                listen(&caller, &mut peer, 3).await;
                peer.send_async(&caller, &acknowledgement(3, json!([TASK_ID]))).await.unwrap();
                assert!(matches!(watch.next_event(&caller, &live).await.unwrap(),
                    Some(FinalTaskWatchEvent::Acknowledged { .. })));
                let started = Instant::now();
                assert!(watch.next_event(&caller, &live).await.unwrap().is_none());
                assert_eq!(watch.stop_reason(), Some(if retention {
                    FinalTaskWaitOutcome::TaskExpired
                } else { FinalTaskWaitOutcome::DeadlineElapsed }));
                assert!(started.elapsed() < Duration::from_secs(1));
                assert!(!live.is_cancel_requested());
                drop(watch);
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                // Acknowledge any delivered task deadline before returning
                // the connection through the ordinary spawn join policy.
                let _ = caller.checkpoint();
                (client, peer)
            }).unwrap();
            let (mut client, peer) = observer.join(&cx).await.unwrap();
            assert!(cx.checkpoint().is_ok(), "the observing task cannot cancel its parent");
            // The healthy root services the deferred id-only cancellation and
            // proves the same connection can publish the next ordinary call.
            finish(&cx, &mut client, peer, vec![3], 4).await;
        }
    });
}

#[test]
fn memory_task_watch_keeps_its_opening_clock_during_foreign_waiter_reconciliation() {
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use std::sync::Arc;

    run(|cx| async move {
        let foreign_clock = Arc::new(VirtualClock::new());
        foreign_clock.advance(3_600_000_000_000);
        let foreign_timer = TimerDriverHandle::with_virtual_clock(foreign_clock);
        let foreign_runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(foreign_timer.clone())
            .build()
            .unwrap();
        let foreign = foreign_runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let (mut client, mut handle, mut peer) = attached(&cx, task("working", None, 1)).await;
        let live = McpRequestCancellation::new();
        let mut sibling = client
            .execute_core(&cx, &live, "tools/list", json!({}))
            .await
            .unwrap();
        receive(&cx, &mut peer, "tools/list", Some(3)).await;
        let mut watch = handle
            .watch_with_memory(&cx, &mut client, &live)
            .await
            .unwrap();
        listen(&cx, &mut peer, 4).await;
        peer.send_async(&cx, &acknowledgement(4, json!([TASK_ID])))
            .await
            .unwrap();
        assert!(matches!(
            watch.next_event(&foreign, &live).await.unwrap(),
            Some(FinalTaskWatchEvent::Acknowledged { .. })
        ));
        assert_eq!(
            watch.stop_reason(),
            None,
            "a foreign clock cannot expire the opening budget"
        );
        let mut ambiguous = task("working", None, 1);
        ambiguous["statusMessage"] = json!("requires an owner-bound read");
        peer.send_async(&cx, &task_notification(4, ambiguous))
            .await
            .unwrap();
        let mut server = cx
            .spawn(move |peer_cx| async move {
                receive(&peer_cx, &mut peer, "tasks/get", Some(5)).await;
                peer.send_async(&peer_cx, &task_response(5, task("completed", None, 2)))
                    .await
                    .unwrap();
                receive_cancel(&peer_cx, &mut peer, 4).await;
                peer.send_async(&peer_cx, &tools_response(3)).await.unwrap();
                peer
            })
            .unwrap();
        assert!(matches!(
            watch.next_event(&foreign, &live).await.unwrap(),
            Some(FinalTaskWatchEvent::TaskReconciled {
                authoritative: FinalTask::Completed { .. },
                ..
            })
        ));
        assert_eq!(watch.stop_reason(), Some(FinalTaskWaitOutcome::Completed));
        drop(watch);
        assert!(matches!(
            client.next_event(&cx, &live, &mut sibling).await.unwrap(),
            Some(crate::MemoryRequestEvent::Result(_))
        ));
        let peer = server.join(&cx).await.unwrap();
        finish(&cx, &mut client, peer, vec![], 6).await;
        assert_eq!(foreign_timer.pending_count(), 0);
        drop(foreign);
        assert!(foreign_runtime.shutdown_timeout(Duration::from_secs(1)));
    });
}

#[test]
fn memory_task_watch_retains_opening_cancellation_with_a_fresh_waiter_token() {
    run(|cx| async move {
        let (mut client, mut handle, mut peer) = attached(&cx, task("working", None, 1)).await;
        let live = McpRequestCancellation::new();
        let origin = McpRequestCancellation::new();
        let mut sibling = client
            .execute_core(&cx, &live, "tools/list", json!({}))
            .await
            .unwrap();
        receive(&cx, &mut peer, "tools/list", Some(3)).await;
        let mut watch = handle
            .watch_with_memory(&cx, &mut client, &origin)
            .await
            .unwrap();
        listen(&cx, &mut peer, 4).await;
        peer.send_async(&cx, &acknowledgement(4, json!([TASK_ID])))
            .await
            .unwrap();
        watch.next_event(&cx, &live).await.unwrap();
        origin.cancel();
        assert!(watch.next_event(&cx, &live).await.unwrap().is_none());
        assert_eq!(
            watch.stop_reason(),
            Some(FinalTaskWaitOutcome::ObservationCancelled)
        );
        assert!(!live.is_cancel_requested());
        assert!(cx.checkpoint().is_ok());
        drop(watch);
        let mut server = cx
            .spawn(move |peer_cx| async move {
                receive_cancel(&peer_cx, &mut peer, 4).await;
                peer.send_async(&peer_cx, &tools_response(3)).await.unwrap();
                peer
            })
            .unwrap();
        assert!(matches!(
            client.next_event(&cx, &live, &mut sibling).await.unwrap(),
            Some(crate::MemoryRequestEvent::Result(_))
        ));
        let peer = server.join(&cx).await.unwrap();
        finish(&cx, &mut client, peer, vec![], 5).await;
    });
}

mod watch_caller_lifetime {
    use super::*;
    use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Waker};

    const NO_IO: CapMask = CapSet::<true, true, true, false, true>::MASK;

    fn clock_runtime(
        offset: u64,
    ) -> (
        asupersync::runtime::Runtime,
        Arc<VirtualClock>,
        TimerDriverHandle,
    ) {
        let clock = Arc::new(VirtualClock::new());
        clock.advance(offset);
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        (runtime, clock, timer)
    }

    fn poll_as<F: Future>(future: Pin<&mut F>, caller: &Cx) -> Poll<F::Output> {
        let _caller = Cx::set_current(Some(caller.clone()));
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    fn ready_as<F: Future>(future: F, caller: &Cx) -> F::Output {
        match poll_as(pin!(future), caller) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("this watch operation must be immediately decidable"),
        }
    }

    #[derive(Default)]
    struct Observed {
        calls: Vec<(&'static str, Cx)>,
        cancelled: usize,
    }

    struct Probe {
        observed: Arc<Mutex<Observed>>,
        events: VecDeque<StdioTaskSubscriptionEvent>,
        cancel_on_read: Option<McpRequestCancellation>,
    }

    impl Probe {
        fn record(&self, method: &'static str, cx: &Cx) {
            let active = Cx::current().unwrap();
            assert_eq!(active.task_id(), cx.task_id());
            assert_eq!(active.now(), cx.now());
            assert_eq!(active.capabilities().io, cx.capabilities().io);
            self.observed.lock().unwrap().calls.push((method, active));
        }
    }

    impl TaskWaitTransport for Probe {
        type Error = McpError;

        fn read_task(
            &mut self,
            cx: &Cx,
            _: &McpRequestCancellation,
            _: FinalTaskId,
        ) -> impl std::future::Future<Output = McpResult<FinalTask>> {
            self.record("read", cx);
            if let Some(cancellation) = &self.cancel_on_read {
                cancellation.cancel();
            }
            std::future::ready(Ok(serde_json::from_value(task("completed", None, 2)).unwrap()))
        }
    }

    impl TaskWatchTransport for Probe {
        type Owner = RequestId;

        fn watch_timeout(&self) -> Duration {
            Duration::from_secs(30)
        }
        fn live_watch_id(&self) -> Option<RequestId> {
            None
        }

        fn open_watch(
            &mut self,
            cx: &Cx,
            _: &McpRequestCancellation,
            _: SubscriptionFilter,
            owner: &mut Option<RequestId>,
        ) -> impl std::future::Future<Output = McpResult<()>> {
            self.record("open", cx);
            *owner = Some(RequestId::Number(17));
            std::future::ready(Ok(()))
        }

        async fn next_watch_event(
            &mut self,
            cx: &Cx,
            _: &McpRequestCancellation,
            _: &mut RequestId,
        ) -> McpResult<StdioTaskSubscriptionEvent> {
            self.record("event", cx);
            match self.events.pop_front() {
                Some(event) => Ok(event),
                None => std::future::pending().await,
            }
        }

        fn cancel_watch(
            &mut self,
            _: &Cx,
            _: &mut RequestId,
        ) -> impl std::future::Future<Output = McpResult<()>> {
            self.observed.lock().unwrap().cancelled += 1;
            std::future::ready(Ok(()))
        }

        fn abandon_watch(&mut self, _: RequestId) {
            self.observed.lock().unwrap().cancelled += 1;
        }
    }

    fn probe() -> (Probe, Arc<Mutex<Observed>>, FinalTaskHandle) {
        let observed = Arc::new(Mutex::new(Observed::default()));
        let mut accepted = SubscriptionFilter::default();
        fastmcp_protocol::set_task_subscription_ids(
            &mut accepted,
            vec![FinalTaskId::parse(TASK_ID).unwrap()],
        )
        .unwrap();
        let mut ambiguous = task("working", None, 1);
        ambiguous["statusMessage"] = json!("conflicting timestamp");
        let notification =
            serde_json::from_value(serde_json::to_value(task_notification(17, ambiguous)).unwrap())
                .unwrap();
        (
            Probe {
                observed: Arc::clone(&observed),
                cancel_on_read: None,
                events: VecDeque::from([
                    StdioTaskSubscriptionEvent::Acknowledged(accepted),
                    StdioTaskSubscriptionEvent::Notification(notification),
                ]),
            },
            observed,
            FinalTaskHandle::new(serde_json::from_value(task("working", None, 1)).unwrap()),
        )
    }

    #[test]
    fn watch_origin_deadline_is_not_replaced_by_an_ahead_or_behind_waiter_clock() {
        for (owner_offset, waiter_offset) in [(0, 3_600_000_000_000), (3_600_000_000_000, 0)] {
            let (runtime, clock, timer) = clock_runtime(owner_offset);
            let owner = runtime.request_cx_with_budget(
                asupersync::Budget::INFINITE
                    .with_deadline(Time::from_nanos(owner_offset + 1_000_000_000)),
            );
            let (waiter_runtime, _, waiter_timer) = clock_runtime(waiter_offset);
            let waiter = waiter_runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let (mut probe, observed, mut handle) = probe();
            let live = McpRequestCancellation::new();
            let mut watch = ready_as(
                open_task_stream_watch(&mut handle, &owner, &mut probe, &live),
                &owner,
            )
            .unwrap();
            assert!(matches!(
                ready_as(next_task_stream_event(&mut watch, &waiter, &live), &waiter).unwrap(),
                Some(FinalTaskWatchEvent::Acknowledged { .. })
            ));
            clock.advance(1_000_000_000);
            assert!(
                ready_as(next_task_stream_event(&mut watch, &waiter, &live), &waiter)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                watch.stop_reason(),
                Some(FinalTaskWaitOutcome::DeadlineElapsed)
            );
            drop(watch);
            let observed = observed.lock().unwrap();
            assert_eq!(
                observed
                    .calls
                    .iter()
                    .map(|(method, _)| *method)
                    .collect::<Vec<_>>(),
                ["open", "event"]
            );
            assert_eq!(observed.cancelled, 1);
            assert_eq!(timer.pending_count(), 0);
            assert_eq!(waiter_timer.pending_count(), 0);
            drop(observed);
            drop(owner);
            drop(waiter);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
            assert!(waiter_runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn watch_reconciliation_retains_opening_authority_and_meets_waiter_effects() {
        for restricted_origin in [true, false] {
            let (runtime, _, timer) = clock_runtime(0);
            let owner = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let (waiter_runtime, _, waiter_timer) = clock_runtime(3_600_000_000_000);
            let waiter = waiter_runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let (mut probe, observed, mut handle) = probe();
            let live = McpRequestCancellation::new();
            let mut watch = {
                let _owner = Cx::set_current(Some(owner.clone()));
                let _restriction = Cx::push_restriction(if restricted_origin {
                    NO_IO
                } else {
                    CapMask::all()
                });
                ready_as(
                    open_task_stream_watch(&mut handle, &owner, &mut probe, &live),
                    &Cx::current().unwrap(),
                )
                .unwrap()
            };
            let waiter = if restricted_origin {
                waiter
            } else {
                let _waiter = Cx::set_current(Some(waiter));
                let _restriction = Cx::push_restriction(NO_IO);
                Cx::current().unwrap()
            };
            ready_as(next_task_stream_event(&mut watch, &waiter, &live), &waiter).unwrap();
            assert!(matches!(
                ready_as(next_task_stream_event(&mut watch, &waiter, &live), &waiter).unwrap(),
                Some(FinalTaskWatchEvent::TaskReconciled { .. })
            ));
            drop(watch);
            let observed = observed.lock().unwrap();
            let read = observed
                .calls
                .iter()
                .find(|(method, _)| *method == "read")
                .unwrap();
            assert_eq!(read.1.task_id(), owner.task_id());
            assert_eq!(read.1.now(), owner.now());
            assert!(
                !read.1.capabilities().io,
                "neither a later waiter nor reconciliation may restore denied effects"
            );
            assert_eq!(observed.cancelled, 1);
            assert_eq!(timer.pending_count(), 0);
            assert_eq!(waiter_timer.pending_count(), 0);
            drop(observed);
            drop(owner);
            drop(waiter);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
            assert!(waiter_runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn waiter_cancellation_during_reconciliation_preserves_the_admitted_snapshot() {
        let (runtime, _, timer) = clock_runtime(0);
        let owner = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let (waiter_runtime, _, waiter_timer) = clock_runtime(3_600_000_000_000);
        let waiter = waiter_runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let (mut probe, observed, mut handle) = probe();
        let before = serde_json::to_vec(handle.task()).unwrap();
        let origin_token = McpRequestCancellation::new();
        let waiter_token = McpRequestCancellation::new();
        probe.cancel_on_read = Some(waiter_token.clone());
        let mut watch = ready_as(
            open_task_stream_watch(&mut handle, &owner, &mut probe, &origin_token),
            &owner,
        )
        .unwrap();
        ready_as(
            next_task_stream_event(&mut watch, &waiter, &waiter_token),
            &waiter,
        )
        .unwrap();
        assert!(
            ready_as(
                next_task_stream_event(&mut watch, &waiter, &waiter_token),
                &waiter
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            watch.stop_reason(),
            Some(FinalTaskWaitOutcome::ObservationCancelled)
        );
        assert_eq!(serde_json::to_vec(watch.task()).unwrap(), before);
        assert!(!origin_token.is_cancel_requested());
        assert!(owner.checkpoint().is_ok());
        drop(watch);
        assert_eq!(observed.lock().unwrap().cancelled, 1);
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(waiter_timer.pending_count(), 0);
        drop(owner);
        drop(waiter);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        assert!(waiter_runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn pending_watch_waiter_deadline_uses_its_own_clock_and_releases_both_timers() {
        let (runtime, _, owner_timer) = clock_runtime(3_600_000_000_000);
        let owner = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let (waiter_runtime, waiter_clock, waiter_timer) = clock_runtime(0);
        let waiter = waiter_runtime.request_cx_with_budget(
            asupersync::Budget::INFINITE.with_deadline(Time::from_nanos(1_000_000_000)),
        );
        let (mut probe, observed, mut handle) = probe();
        probe.events.clear();
        let live = McpRequestCancellation::new();
        let mut watch = ready_as(
            open_task_stream_watch(&mut handle, &owner, &mut probe, &live),
            &owner,
        )
        .unwrap();
        {
            let mut waiting = Box::pin(next_task_stream_event(&mut watch, &waiter, &live));
            assert!(poll_as(waiting.as_mut(), &waiter).is_pending());
            assert!(owner_timer.pending_count() > 0);
            assert!(waiter_timer.pending_count() > 0);
            waiter_clock.advance(1_000_000_000);
            let _ = waiter_timer.process_timers();
            assert!(matches!(
                poll_as(waiting.as_mut(), &waiter),
                Poll::Ready(Ok(None))
            ));
        }
        assert_eq!(
            watch.stop_reason(),
            Some(FinalTaskWaitOutcome::DeadlineElapsed)
        );
        assert_eq!(owner.now().as_nanos(), 3_600_000_000_000);
        assert!(!live.is_cancel_requested());
        assert!(owner.checkpoint().is_ok());
        drop(watch);
        assert_eq!(observed.lock().unwrap().cancelled, 1);
        assert_eq!(owner_timer.pending_count(), 0);
        assert_eq!(waiter_timer.pending_count(), 0);
        drop(owner);
        drop(waiter);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        assert!(waiter_runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn waiter_cancellation_cannot_hide_an_already_committed_event() {
        let (runtime, _, timer) = clock_runtime(0);
        let waiter = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let cancellation = McpRequestCancellation::new();
        let committed = std::cell::Cell::new(false);
        let operation = poll_fn(|_| {
            committed.set(true);
            cancellation.cancel();
            Poll::Ready("committed event")
        });
        assert_eq!(
            ready_as(
                guard_task_watch_waiter(&waiter, &cancellation, operation),
                &waiter,
            ),
            Ok("committed event")
        );
        assert!(committed.get());
        assert!(cancellation.is_cancel_requested());
        assert_eq!(timer.pending_count(), 0);
        drop(waiter);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn waiter_cancellation_during_an_uncommitted_poll_stops_observation() {
        let (runtime, _, timer) = clock_runtime(0);
        let waiter = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let cancellation = McpRequestCancellation::new();
        let polls = std::cell::Cell::new(0);
        let operation = poll_fn(|_| {
            polls.set(polls.get() + 1);
            cancellation.cancel();
            Poll::<()>::Pending
        });
        assert_eq!(
            ready_as(
                guard_task_watch_waiter(&waiter, &cancellation, operation),
                &waiter,
            ),
            Err(FinalTaskWaitOutcome::ObservationCancelled)
        );
        assert_eq!(polls.get(), 1);
        assert_eq!(timer.pending_count(), 0);
        drop(waiter);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}
