use super::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;

use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_protocol::{ClientCapabilities, ClientInfo, ServerDiscoverResult, ServerInfo};
use serde_json::{Value, json};

mod memory {
    use super::*;
    use std::future::poll_fn;
    use std::pin::pin;

    use fastmcp_core::McpErrorCode;
    use fastmcp_protocol::{CoreResult, FinalCoreResult, JsonRpcMessage, JsonRpcRequest};
    use fastmcp_transport::memory::{MemoryTransport, create_memory_transport_pair_with_capacity};

    fn run_memory<F: Future<Output = ()>>(test: impl FnOnce(Cx) -> F) {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(cx.blocking_pool_handle().is_none());
            asupersync::time::timeout(cx.now(), Duration::from_secs(8), test(cx))
                .await
                .expect("Memory Task handles must progress on the caller runtime");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    async fn receive(
        cx: &Cx,
        peer: &mut MemoryTransport,
        method: &str,
        id: Option<i64>,
    ) -> JsonRpcRequest {
        let JsonRpcMessage::Request(request) = peer.recv_async(cx).await.unwrap() else {
            panic!("expected the caller's Memory request");
        };
        assert_eq!(request.method, method);
        assert_eq!(request.id, id.map(fastmcp_protocol::RequestId::Number));
        request
    }

    async fn reply_task(cx: &Cx, peer: &mut MemoryTransport, id: u64, task: Value) {
        peer.send_async(cx, &serde_json::from_value(response(id, task)).unwrap())
            .await
            .unwrap();
    }

    async fn reply_empty(cx: &Cx, peer: &mut MemoryTransport, id: i64) {
        peer.send_async(
            cx,
            &JsonRpcMessage::Response(fastmcp_protocol::JsonRpcResponse::success(
                fastmcp_protocol::RequestId::Number(id),
                json!({"resultType":"complete"}),
            )),
        )
        .await
        .unwrap();
    }

    async fn reply_tools(cx: &Cx, peer: &mut MemoryTransport, id: i64) {
        peer.send_async(
            cx,
            &JsonRpcMessage::Response(fastmcp_protocol::JsonRpcResponse::success(
                fastmcp_protocol::RequestId::Number(id),
                json!({"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}),
            )),
        )
        .await
        .unwrap();
    }

    async fn attached(cx: &Cx, initial: Value) -> (MemoryClient, FinalTaskHandle, MemoryTransport) {
        let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
        peer.send_async(cx, &serde_json::from_value(discovery()).unwrap())
            .await
            .unwrap();
        let mut client = MemoryClient::builder(ClientInfo {
            name: "task-handle-memory-client".to_owned(),
            version: "1".to_owned(),
        })
        .capabilities(ClientCapabilities {
            roots: Some(fastmcp_protocol::RootsCapability::default()),
            ..ClientCapabilities::default()
        })
        .with_tasks()
        .connect(cx, transport)
        .await
        .unwrap();
        receive(cx, &mut peer, "server/discover", Some(1)).await;
        reply_task(cx, &mut peer, 2, initial).await;
        let handle = client
            .attach_final_task(
                cx,
                &McpRequestCancellation::new(),
                FinalTaskId::parse("wait-task").unwrap(),
            )
            .await
            .unwrap();
        let attached = receive(cx, &mut peer, "tasks/get", Some(2)).await;
        assert_eq!(attached.params.unwrap()["taskId"], "wait-task");
        (client, handle, peer)
    }

    async fn just_created(
        cx: &Cx,
        mut initial: Value,
    ) -> (
        MemoryClient,
        fastmcp_protocol::CreateTaskResult,
        MemoryTransport,
    ) {
        let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
        peer.send_async(cx, &serde_json::from_value(discovery()).unwrap())
            .await
            .unwrap();
        let mut client = MemoryClient::builder(ClientInfo {
            name: "created-task-memory-client".to_owned(),
            version: "1".to_owned(),
        })
        .with_tasks()
        .connect(cx, transport)
        .await
        .unwrap();
        receive(cx, &mut peer, "server/discover", Some(1)).await;
        initial["resultType"] = json!("task");
        initial["_meta"] = json!({"creation-note": "retained"});
        initial["x-creation"] = json!({"opaque": [1, true, "unchanged"]});
        peer.send_async(
            cx,
            &JsonRpcMessage::Response(fastmcp_protocol::JsonRpcResponse::success(
                fastmcp_protocol::RequestId::Number(2),
                initial,
            )),
        )
        .await
        .unwrap();
        let crate::FinalToolCallOutcome::Task(created) = client
            .call_tool_final_outcome(
                cx,
                &McpRequestCancellation::new(),
                "start-work",
                json!({"value": 7}),
            )
            .await
            .unwrap()
        else {
            panic!("the negotiated creating call must retain its Task result");
        };
        let request = receive(cx, &mut peer, "tools/call", Some(2)).await;
        let parameters = request.params.unwrap();
        assert_eq!(parameters["name"], "start-work");
        assert_eq!(parameters["arguments"], json!({"value": 7}));
        assert_eq!(
            parameters["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
                [fastmcp_protocol::TASKS_EXTENSION],
            json!({}),
        );
        (client, created, peer)
    }

    #[test]
    fn public_memory_created_task_wait_preserves_receipt_and_initial_poll_floor() {
        run_memory(|cx| async move {
            let (mut client, created, mut peer) =
                just_created(&cx, task("working", Some(80))).await;
            let received_at = Instant::now();
            let receipt = serde_json::to_vec(&created).unwrap();
            let mut handle = FinalTaskHandle::from_created(&created).unwrap();
            let mut server = cx
                .spawn(move |peer_cx| async move {
                    let get = receive(&peer_cx, &mut peer, "tasks/get", Some(3)).await;
                    assert_eq!(get.params.unwrap()["taskId"], "wait-task");
                    assert!(
                        received_at.elapsed() >= Duration::from_millis(80),
                        "creation adoption must not perform an early attachment read",
                    );
                    reply_task(&peer_cx, &mut peer, 3, task("completed", None)).await;
                    receive(&peer_cx, &mut peer, "tools/list", Some(4)).await;
                    reply_tools(&peer_cx, &mut peer, 4).await;
                    peer
                })
                .unwrap();
            let cancellation = McpRequestCancellation::new();
            assert_eq!(
                handle
                    .wait_with_memory(&cx, &mut client, &cancellation, policy(2000, 2, 1))
                    .await
                    .unwrap(),
                FinalTaskWaitOutcome::Completed,
            );
            assert!(matches!(handle.task(), FinalTask::Completed { .. }));
            assert_eq!(serde_json::to_vec(&created).unwrap(), receipt);
            assert_eq!(
                created.additional["x-creation"],
                json!({"opaque": [1, true, "unchanged"]}),
            );
            assert!(matches!(
                client.list_tools(&cx, &cancellation, None).await.unwrap(),
                CoreResult::Final(FinalCoreResult::ToolsList { .. }),
            ));
            let _peer = server.join(&cx).await.unwrap();
            assert!(client.take_cancellation_events().is_empty());
            assert!(cx.checkpoint().is_ok());
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn public_memory_created_task_wait_never_shortens_initial_floor_to_fit_budget() {
        run_memory(|cx| async move {
            let (mut client, created, mut peer) =
                just_created(&cx, task("working", Some(500))).await;
            let receipt = serde_json::to_vec(&created).unwrap();
            let mut handle = FinalTaskHandle::from_created(&created).unwrap();
            let snapshot = serde_json::to_vec(handle.task()).unwrap();
            let cancellation = McpRequestCancellation::new();
            assert_eq!(
                handle
                    .wait_with_memory(&cx, &mut client, &cancellation, policy(40, 2, 1))
                    .await
                    .unwrap(),
                FinalTaskWaitOutcome::DeadlineElapsed,
            );
            assert_eq!(serde_json::to_vec(handle.task()).unwrap(), snapshot);
            assert_eq!(serde_json::to_vec(&created).unwrap(), receipt);
            assert!(
                client.take_cancellation_events().is_empty(),
                "no Task read or creating call was dispatched or cancelled",
            );
            // ID 3 and the next method prove adoption and the expired wait
            // neither allocated a read nor repeated the creating call.
            assert_core_usable(&cx, &mut client, &mut peer, 3).await;
            assert!(!cancellation.is_cancel_requested());
            client.close(&cx).unwrap();
        });
    }

    fn answers() -> FinalTaskInputResponses {
        serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap()
    }

    async fn assert_core_usable(
        cx: &Cx,
        client: &mut MemoryClient,
        peer: &mut MemoryTransport,
        expected_id: i64,
    ) {
        reply_tools(cx, peer, expected_id).await;
        assert!(matches!(
            client
                .list_tools(cx, &McpRequestCancellation::new(), None)
                .await
                .unwrap(),
            CoreResult::Final(FinalCoreResult::ToolsList { .. }),
        ));
        receive(cx, peer, "tools/list", Some(expected_id)).await;
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn public_memory_task_handle_wait_pauses_resumes_and_retains_exact_terminal_result() {
        run_memory(|cx| async move {
            let (mut client, mut handle, mut peer) = attached(&cx, task("working", Some(1))).await;
            let mut server = cx
                .spawn(move |peer_cx| async move {
                    receive(&peer_cx, &mut peer, "tasks/get", Some(3)).await;
                    reply_task(&peer_cx, &mut peer, 3, task("working", None)).await;
                    let suggestion_cleared = Instant::now();
                    receive(&peer_cx, &mut peer, "tasks/get", Some(4)).await;
                    assert!(
                        suggestion_cleared.elapsed() >= Duration::from_millis(20),
                        "an absent fresh suggestion must restore the configured fallback",
                    );
                    reply_task(&peer_cx, &mut peer, 4, task("input_required", None)).await;
                    let update = receive(&peer_cx, &mut peer, "tasks/update", Some(5)).await;
                    assert_eq!(
                        update.params.unwrap()["inputResponses"],
                        json!({"roots":{"roots":[]}})
                    );
                    reply_empty(&peer_cx, &mut peer, 5).await;
                    receive(&peer_cx, &mut peer, "tasks/get", Some(6)).await;
                    reply_task(&peer_cx, &mut peer, 6, task("working", Some(1))).await;
                    receive(&peer_cx, &mut peer, "tasks/get", Some(7)).await;
                    let mut complete = task("completed", None);
                    complete["result"]["exact"] = Value::Number(
                        serde_json::Number::from_string_unchecked("7.30e-2".to_owned()),
                    );
                    complete["result"]["resultTypeLookalike"] = json!("input_required");
                    reply_task(&peer_cx, &mut peer, 7, complete).await;
                    peer
                })
                .unwrap();
            let cancellation = McpRequestCancellation::new();
            let policy = policy(2000, 4, 20);
            assert_eq!(
                handle
                    .wait_with_memory(&cx, &mut client, &cancellation, policy)
                    .await
                    .unwrap(),
                FinalTaskWaitOutcome::InputRequired,
            );
            let before = serde_json::to_vec(handle.task()).unwrap();
            handle
                .resume_input_with_memory(&cx, &mut client, &cancellation, answers())
                .await
                .unwrap();
            assert_eq!(
                serde_json::to_vec(handle.task()).unwrap(),
                before,
                "an acknowledgement must not fabricate a successor Task snapshot"
            );
            handle
                .poll_with_memory(&cx, &mut client, &cancellation)
                .await
                .unwrap();
            assert!(matches!(handle.task(), FinalTask::Working(_)));
            assert_eq!(
                handle
                    .wait_with_memory(&cx, &mut client, &cancellation, policy)
                    .await
                    .unwrap(),
                FinalTaskWaitOutcome::Completed,
            );
            let result = serde_json::to_value(handle.task()).unwrap();
            assert_eq!(result["result"]["opaque"], json!({"x":[1,true,"kept"]}));
            assert_eq!(result["result"]["resultTypeLookalike"], "input_required");
            assert!(
                serde_json::to_string(handle.task())
                    .unwrap()
                    .contains("7.30e-2")
            );
            let terminal = serde_json::to_vec(handle.task()).unwrap();
            cancellation.cancel();
            assert_eq!(
                handle
                    .wait_with_memory(&cx, &mut client, &cancellation, policy)
                    .await
                    .unwrap(),
                FinalTaskWaitOutcome::Completed,
                "already delivered terminal data remains available without another request",
            );
            handle
                .poll_with_memory(&cx, &mut client, &cancellation)
                .await
                .unwrap();
            assert_eq!(serde_json::to_vec(handle.task()).unwrap(), terminal);
            let mut peer = server.join(&cx).await.unwrap();
            assert_core_usable(&cx, &mut client, &mut peer, 8).await;
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn public_memory_task_wait_honors_poll_limit_peer_floor_and_original_retention() {
        run_memory(|cx| async move {
            for mode in [
                "poll-limit",
                "peer-floor",
                "expired-working",
                "expired-input",
                "cancelled",
            ] {
                let mut initial = task(
                    if mode == "expired-input" {
                        "input_required"
                    } else {
                        "working"
                    },
                    Some(1),
                );
                if mode == "peer-floor" {
                    initial["pollIntervalMs"] = json!(600_001);
                }
                if mode.starts_with("expired-") {
                    initial["ttlMs"] = json!(1);
                    initial["lastUpdatedAt"] = json!("2040-01-01T00:00:00Z");
                }
                let (mut client, mut handle, peer) = attached(&cx, initial).await;
                let mut peer = Some(peer);
                let before = serde_json::to_vec(handle.task()).unwrap();
                let cancellation = McpRequestCancellation::new();
                if mode == "cancelled" {
                    cancellation.cancel();
                }
                let server = if mode == "poll-limit" {
                    let mut peer = peer.take().unwrap();
                    Some(
                        cx.spawn(move |peer_cx| async move {
                            for id in [3, 4] {
                                receive(&peer_cx, &mut peer, "tasks/get", Some(id)).await;
                                reply_task(
                                    &peer_cx,
                                    &mut peer,
                                    u64::try_from(id).unwrap(),
                                    task("working", Some(1)),
                                )
                                .await;
                            }
                            peer
                        })
                        .unwrap(),
                    )
                } else {
                    None
                };
                let outcome = handle
                    .wait_with_memory(&cx, &mut client, &cancellation, policy(30, 2, 1))
                    .await
                    .unwrap();
                assert_eq!(
                    outcome,
                    match mode {
                        "poll-limit" => FinalTaskWaitOutcome::PollLimitReached,
                        "peer-floor" => FinalTaskWaitOutcome::DeadlineElapsed,
                        "cancelled" => FinalTaskWaitOutcome::ObservationCancelled,
                        _ => FinalTaskWaitOutcome::TaskExpired,
                    }
                );
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                // This branch is deliberately separate: the spawned peer owns
                // its transport only when authoritative polls are expected.
                if let Some(mut server) = server {
                    let mut peer = server.join(&cx).await.unwrap();
                    assert_core_usable(&cx, &mut client, &mut peer, 5).await;
                } else {
                    assert_core_usable(&cx, &mut client, peer.as_mut().unwrap(), 3).await;
                }
                assert!(
                    client.take_cancellation_events().is_empty(),
                    "a local stop between reads must never request remote Task cancellation"
                );
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn public_memory_task_poll_rejects_changed_identity_without_replacing_snapshot() {
        run_memory(|cx| async move {
            for changed in ["task-id", "created-at", "shape"] {
                let (mut client, mut handle, mut peer) =
                    attached(&cx, task("working", Some(1))).await;
                let before = serde_json::to_vec(handle.task()).unwrap();
                let mut candidate = task("completed", None);
                match changed {
                    "task-id" => candidate["taskId"] = json!("another-task"),
                    "created-at" => candidate["createdAt"] = json!("2026-07-28T12:00:00.001Z"),
                    _ => {
                        candidate.as_object_mut().unwrap().remove("result");
                    }
                }
                let mut server = cx
                    .spawn(move |peer_cx| async move {
                        receive(&peer_cx, &mut peer, "tasks/get", Some(3)).await;
                        reply_task(&peer_cx, &mut peer, 3, candidate).await;
                        receive(&peer_cx, &mut peer, "tasks/get", Some(4)).await;
                        let mut complete = task("completed", None);
                        complete["createdAt"] = json!("2026-07-28T12:00:00+00:00");
                        reply_task(&peer_cx, &mut peer, 4, complete).await;
                        peer
                    })
                    .unwrap();
                let cancellation = McpRequestCancellation::new();
                assert_eq!(
                    handle
                        .poll_with_memory(&cx, &mut client, &cancellation)
                        .await
                        .unwrap_err()
                        .code,
                    McpErrorCode::InvalidRequest,
                );
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                handle
                    .poll_with_memory(&cx, &mut client, &cancellation)
                    .await
                    .unwrap();
                assert!(matches!(handle.task(), FinalTask::Completed { .. }));
                // `created_at` is a TaskTimestamp, not a String: the type was
                // strengthened to retain the canonical final spelling. Compare
                // through as_str() so the assertion still checks that exact
                // spelling rather than only that some timestamp arrived.
                assert_eq!(
                    handle.task().base().created_at.as_str(),
                    "2026-07-28T12:00:00+00:00"
                );
                let mut peer = server.join(&cx).await.unwrap();
                assert_core_usable(&cx, &mut client, &mut peer, 5).await;
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn public_memory_task_wait_cancel_or_drop_retires_only_its_read_and_preserves_siblings() {
        run_memory(|cx| async move {
            for abandon in [false, true] {
                let (mut client, mut handle, mut peer) =
                    attached(&cx, task("working", Some(1))).await;
                let before = serde_json::to_vec(handle.task()).unwrap();
                let live = McpRequestCancellation::new();
                let mut sibling = client
                    .execute_core(&cx, &live, "tools/list", json!({}))
                    .await
                    .unwrap();
                receive(&cx, &mut peer, "tools/list", Some(3)).await;
                let original = McpRequestCancellation::new();
                {
                    let mut waiting = pin!(handle.wait_with_memory(
                        &cx,
                        &mut client,
                        &original,
                        policy(2000, 4, 1),
                    ));
                    let mut request = pin!(peer.recv_async(&cx));
                    let sent = poll_fn(|task_cx| {
                        assert!(waiting.as_mut().poll(task_cx).is_pending());
                        request.as_mut().poll(task_cx)
                    })
                    .await
                    .unwrap();
                    let JsonRpcMessage::Request(sent) = sent else {
                        panic!("expected one Task read");
                    };
                    assert_eq!(sent.method, "tasks/get");
                    assert_eq!(sent.id, Some(fastmcp_protocol::RequestId::Number(4)));
                    if !abandon {
                        original.cancel();
                        assert_eq!(
                            waiting.await.unwrap(),
                            FinalTaskWaitOutcome::ObservationCancelled
                        );
                    }
                }
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                let mut server = cx
                    .spawn(move |peer_cx| async move {
                        let cancellation =
                            receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                        assert_eq!(cancellation.params.unwrap()["requestId"], 4);
                        reply_task(&peer_cx, &mut peer, 4, task("failed", None)).await;
                        reply_tools(&peer_cx, &mut peer, 3).await;
                        receive(&peer_cx, &mut peer, "tasks/get", Some(5)).await;
                        reply_task(&peer_cx, &mut peer, 5, task("completed", None)).await;
                        peer
                    })
                    .unwrap();
                let Some(crate::MemoryRequestEvent::Result(result)) =
                    client.next_event(&cx, &live, &mut sibling).await.unwrap()
                else {
                    panic!("the unrelated core request must still complete");
                };
                assert!(matches!(
                    *result,
                    CoreResult::Final(FinalCoreResult::ToolsList { .. })
                ));
                assert_eq!(
                    serde_json::to_vec(handle.task()).unwrap(),
                    before,
                    "a late reply to a retired read must not become the retained Task"
                );
                handle
                    .poll_with_memory(&cx, &mut client, &live)
                    .await
                    .unwrap();
                assert!(matches!(handle.task(), FinalTask::Completed { .. }));
                assert_eq!(client.take_cancellation_events().len(), 1);
                let mut peer = server.join(&cx).await.unwrap();
                assert_core_usable(&cx, &mut client, &mut peer, 6).await;
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn public_memory_task_input_refuses_stale_or_wrong_inputs_and_never_replays_updates() {
        run_memory(|cx| async move {
            for abandon in [false, true] {
                let (mut client, mut handle, mut peer) =
                    attached(&cx, task("input_required", None)).await;
                let before = serde_json::to_vec(handle.task()).unwrap();
                let cancellation = McpRequestCancellation::new();
                let wrong = serde_json::from_value(json!({"roots":{"action":"accept"}})).unwrap();
                assert_eq!(
                    handle
                        .resume_input_with_memory(&cx, &mut client, &cancellation, wrong)
                        .await
                        .unwrap_err()
                        .code,
                    McpErrorCode::InvalidParams,
                );
                for phase in ["working", "completed", "cancelled", "input_required"] {
                    let mut value = task(phase, None);
                    if phase == "input_required" {
                        value["ttlMs"] = json!(1);
                    }
                    let mut stale = FinalTaskHandle::new(snapshot(&value));
                    assert!(
                        stale
                            .resume_input_with_memory(&cx, &mut client, &cancellation, answers())
                            .await
                            .is_err()
                    );
                }
                {
                    let mut update = pin!(handle.resume_input_with_memory(
                        &cx,
                        &mut client,
                        &cancellation,
                        answers(),
                    ));
                    let mut request = pin!(peer.recv_async(&cx));
                    let sent = poll_fn(|task_cx| {
                        assert!(update.as_mut().poll(task_cx).is_pending());
                        request.as_mut().poll(task_cx)
                    })
                    .await
                    .unwrap();
                    let JsonRpcMessage::Request(sent) = sent else {
                        panic!("expected one explicit input update");
                    };
                    assert_eq!(sent.method, "tasks/update");
                    assert_eq!(
                        sent.id,
                        Some(fastmcp_protocol::RequestId::Number(3)),
                        "all refused input submissions must leave the allocator untouched"
                    );
                    if !abandon {
                        cancellation.cancel();
                        assert_eq!(
                            update.await.unwrap_err().code,
                            McpErrorCode::RequestCancelled
                        );
                    }
                }
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                let mut server = cx
                    .spawn(move |peer_cx| async move {
                        let cancel =
                            receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                        assert_eq!(cancel.params.unwrap()["requestId"], 3);
                        reply_empty(&peer_cx, &mut peer, 3).await;
                        // Recovery is an explicit read; no second update is sent.
                        receive(&peer_cx, &mut peer, "tasks/get", Some(4)).await;
                        reply_task(&peer_cx, &mut peer, 4, task("input_required", None)).await;
                        receive(&peer_cx, &mut peer, "tasks/update", Some(5)).await;
                        reply_empty(&peer_cx, &mut peer, 5).await;
                        peer
                    })
                    .unwrap();
                let live = McpRequestCancellation::new();
                handle
                    .poll_with_memory(&cx, &mut client, &live)
                    .await
                    .unwrap();
                handle
                    .resume_input_with_memory(&cx, &mut client, &live, answers())
                    .await
                    .unwrap();
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                let mut peer = server.join(&cx).await.unwrap();
                assert_core_usable(&cx, &mut client, &mut peer, 6).await;
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn public_memory_task_wait_caller_deadline_bounds_sleep_and_pending_read() {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
                for pending_read in [false, true] {
                    let initial = task("working", Some(if pending_read { 1 } else { 500 }));
                    let (mut client, mut handle, peer) = attached(&cx, initial).await;
                    let mut peer = Some(peer);
                    let before = serde_json::to_vec(handle.task()).unwrap();
                    let server = if pending_read {
                        let mut peer = peer.take().unwrap();
                        Some(
                            cx.spawn(move |peer_cx| async move {
                                receive(&peer_cx, &mut peer, "tasks/get", Some(3)).await;
                                let cancelled =
                                    receive(&peer_cx, &mut peer, "notifications/cancelled", None)
                                        .await;
                                assert_eq!(cancelled.params.unwrap()["requestId"], 3);
                                reply_task(&peer_cx, &mut peer, 3, task("completed", None)).await;
                                receive(&peer_cx, &mut peer, "tools/list", Some(4)).await;
                                reply_tools(&peer_cx, &mut peer, 4).await;
                                peer
                            })
                            .unwrap(),
                        )
                    } else {
                        None
                    };
                    // The earlier caller is a child task whose budget carries
                    // the deadline. A runtime request Cx cannot be that
                    // caller: it is not a registered task, so the memory
                    // transport's checked send obligation refuses it.
                    let limited = cx.scope_with_budget(
                        asupersync::Budget::INFINITE
                            .with_deadline(cx.now() + Duration::from_millis(80)),
                    );
                    // Its deadline also classifies the child as cancelled, so
                    // the join reports that and the child hands its client,
                    // handle and outcome back through this slot.
                    let cancellation = McpRequestCancellation::new();
                    let limited_cancellation = cancellation.clone();
                    let returned = std::sync::Arc::new(std::sync::Mutex::new(None));
                    let slot = std::sync::Arc::clone(&returned);
                    let mut waiting = cx
                        .spawn_in(&limited, move |limited| async move {
                            let started = Instant::now();
                            let outcome = handle
                                .wait_with_memory(
                                    &limited,
                                    &mut client,
                                    &limited_cancellation,
                                    policy(2000, 8, 1),
                                )
                                .await;
                            *slot.lock().unwrap() =
                                Some((client, handle, outcome, started.elapsed()));
                        })
                        .unwrap();
                    match waiting.join(&cx).await {
                        Ok(()) => {}
                        Err(asupersync::runtime::JoinError::Cancelled(reason)) => {
                            assert_eq!(reason.kind, asupersync::types::CancelKind::Deadline);
                        }
                        Err(error) => panic!("the limited caller failed: {error:?}"),
                    }
                    let (returned_client, returned_handle, outcome, elapsed) = returned
                        .lock()
                        .unwrap()
                        .take()
                        .expect("the limited caller returns its client after the wait");
                    client = returned_client;
                    handle = returned_handle;
                    assert_eq!(outcome.unwrap(), FinalTaskWaitOutcome::DeadlineElapsed);
                    assert!(
                        elapsed < Duration::from_secs(1),
                        "the earlier caller budget must wake the operation, not a later watchdog"
                    );
                    assert!(!cancellation.is_cancel_requested());
                    assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                    if let Some(mut server) = server {
                        assert!(matches!(
                            client.list_tools(&cx, &cancellation, None).await.unwrap(),
                            CoreResult::Final(FinalCoreResult::ToolsList { .. }),
                        ));
                        let _peer = server.join(&cx).await.unwrap();
                    } else {
                        assert_core_usable(&cx, &mut client, peer.as_mut().unwrap(), 3).await;
                    }
                    assert_eq!(
                        client.take_cancellation_events().len(),
                        usize::from(pending_read)
                    );
                    assert!(cx.checkpoint().is_ok());
                    client.close(&cx).unwrap();
                }
            })
            .await
            .expect("caller deadline must release the Memory Task observer");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn public_memory_task_input_rechecks_retention_after_waiting_for_channel_capacity() {
        run_memory(|cx| async move {
            for expire_while_full in [false, true] {
                let mut initial = task("input_required", None);
                let elapsed = wall_now_nanos()
                    // timestamp_nanos takes &TaskTimestamp since the field was
                    // strengthened; parse the fixture's wire string into one
                    // rather than widening the function back to &str.
                    .checked_sub(
                        timestamp_nanos(
                            &fastmcp_protocol::TaskTimestamp::parse(
                                initial["createdAt"].as_str().unwrap(),
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap();
                initial["ttlMs"] = json!(u64::try_from(elapsed / 1_000_000).unwrap() + 500);
                let (mut client, mut handle, mut peer) = attached(&cx, initial).await;
                let before = serde_json::to_vec(handle.task()).unwrap();
                let remaining = input_retention_remaining(handle.task()).unwrap().unwrap();
                let cancellation = McpRequestCancellation::new();
                // Leave the only request slot occupied. The update must wait
                // after passing its initial input/retention admission.
                let mut sibling = client
                    .execute_core(&cx, &cancellation, "tools/list", json!({}))
                    .await
                    .unwrap();
                {
                    let mut update = pin!(handle.resume_input_with_memory(
                        &cx,
                        &mut client,
                        &cancellation,
                        answers(),
                    ));
                    poll_fn(|task_cx| {
                        assert!(update.as_mut().poll(task_cx).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    if expire_while_full {
                        asupersync::time::sleep(cx.now(), remaining + Duration::from_millis(5))
                            .await;
                    }
                    receive(&cx, &mut peer, "tools/list", Some(3)).await;
                    if expire_while_full {
                        assert_eq!(update.await.unwrap_err().code, McpErrorCode::InvalidRequest);
                        reply_tools(&cx, &mut peer, 3).await;
                    } else {
                        // Route the sibling response while the explicit input
                        // update is published through the newly available slot.
                        reply_tools(&cx, &mut peer, 3).await;
                        poll_fn(|task_cx| {
                            assert!(update.as_mut().poll(task_cx).is_pending());
                            Poll::Ready(())
                        })
                        .await;
                        receive(&cx, &mut peer, "tasks/update", Some(4)).await;
                        reply_empty(&cx, &mut peer, 4).await;
                        update.await.unwrap();
                    }
                }
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                let Some(crate::MemoryRequestEvent::Result(result)) = client
                    .next_event(&cx, &cancellation, &mut sibling)
                    .await
                    .unwrap()
                else {
                    panic!("input admission must preserve the unrelated request");
                };
                assert!(matches!(
                    *result,
                    CoreResult::Final(FinalCoreResult::ToolsList { .. })
                ));
                assert_core_usable(
                    &cx,
                    &mut client,
                    &mut peer,
                    if expire_while_full { 4 } else { 5 },
                )
                .await;
                assert!(
                    client.take_cancellation_events().is_empty(),
                    "an expired unpublished update has no request owner to cancel"
                );
                client.close(&cx).unwrap();
            }
        });
    }
}

struct Reply {
    task: Option<Value>,
    minimum_delay: Duration,
    hold: Duration,
    cancel: Option<McpRequestCancellation>,
}

impl Reply {
    fn disconnect(minimum_ms: u64) -> Self {
        Self {
            task: None,
            minimum_delay: Duration::from_millis(minimum_ms),
            hold: Duration::ZERO,
            cancel: None,
        }
    }

    fn new(task: Value, minimum_ms: u64) -> Self {
        Self {
            task: Some(task),
            minimum_delay: Duration::from_millis(minimum_ms),
            hold: Duration::ZERO,
            cancel: None,
        }
    }
}

fn task(status: &str, poll: Option<u64>) -> Value {
    let mut task = json!({
        "taskId": "wait-task",
        "status": status,
        "createdAt": "2026-07-28T12:00:00Z",
        "lastUpdatedAt": "2026-07-28T12:00:01Z",
        "ttlMs": null
    });
    if let Some(poll) = poll {
        task["pollIntervalMs"] = json!(poll);
    }
    match status {
        "input_required" => {
            task["inputRequests"] = json!({
                "roots": {"method": "roots/list"}
            });
        }
        "completed" => {
            task["result"] = json!({
                "content": [{"type": "text", "text": "finished"}],
                "opaque": {"x": [1, true, "kept"]}
            });
        }
        "failed" => {
            task["error"] = json!({
                "code": -32000,
                "message": "application failed",
                "opaque": [false, 7]
            });
        }
        _ => {}
    }
    task
}

fn snapshot(value: &Value) -> FinalTask {
    serde_json::from_str(&value.to_string()).unwrap()
}

fn response(id: u64, mut task: Value) -> Value {
    task["resultType"] = json!("complete");
    json!({"jsonrpc": "2.0", "id": id, "result": task})
}

fn discovery() -> Value {
    let capabilities = fastmcp_protocol::ServerDiscoverCapabilities::from_registry(
        &fastmcp_protocol::ServerBehaviorRegistry::from_behaviors([
            fastmcp_protocol::ServerBehavior::ToolsList,
        ]),
        std::collections::BTreeMap::from([(
            fastmcp_protocol::TASKS_EXTENSION.to_owned(),
            json!({}),
        )]),
    )
    .unwrap();
    let result = ServerDiscoverResult::new(
        capabilities,
        ServerInfo {
            name: "task-wait-peer".to_owned(),
            version: "1".to_owned(),
        },
        None,
        fastmcp_protocol::DiscoveryCacheHints::private_ttl_ms(0),
    );
    let mut response = json!({"jsonrpc": "2.0", "id": 1, "result": result});
    response["result"]["supportedVersions"] = json!([crate::MODERN_PROTOCOL_VERSION]);
    response
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "public Task wait peer received no expected request"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("Task wait accept: {error}"),
        }
    }
}

fn read(stream: &mut TcpStream) -> Value {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let end = loop {
        let count = stream.read(&mut buffer).unwrap();
        assert!(count > 0, "request ended before its headers");
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() <= 128 * 1024);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let length = std::str::from_utf8(&bytes[..end])
        .unwrap()
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    assert!(length <= 64 * 1024);
    while bytes.len() < end + length {
        let count = stream.read(&mut buffer).unwrap();
        assert!(count > 0, "request ended before its body");
        bytes.extend_from_slice(&buffer[..count]);
    }
    serde_json::from_slice(&bytes[end..end + length]).unwrap()
}

fn write(stream: &mut TcpStream, value: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).unwrap();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()
}

fn peer(initial: Value, replies: Vec<Reply>) -> (String, JoinHandle<Vec<Duration>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = format!("http://{}/mcp", listener.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let mut discover = accept(&listener);
        let request = read(&mut discover);
        assert_eq!(request["id"], 1);
        assert_eq!(request["method"], "server/discover");
        write(&mut discover, &discovery()).unwrap();
        drop(discover);

        let mut attach = accept(&listener);
        let request = read(&mut attach);
        assert_eq!(request["id"], 2);
        assert_eq!(request["method"], "tasks/get");
        assert_eq!(request["params"]["taskId"], "wait-task");
        write(&mut attach, &response(2, initial)).unwrap();
        let mut sent = Instant::now();
        drop(attach);
        let mut delays = Vec::new();
        let next_id = 3 + replies.len() as u64;
        for (index, reply) in replies.into_iter().enumerate() {
            let mut poll = accept(&listener);
            let request = read(&mut poll);
            let elapsed = sent.elapsed();
            // Permit only sub-millisecond response-flush/receipt skew.
            assert!(
                elapsed + Duration::from_millis(2) >= reply.minimum_delay,
                "client polled before the advertised minimum"
            );
            delays.push(elapsed);
            assert_eq!(request["id"], 3 + index as u64);
            assert_eq!(request["method"], "tasks/get");
            assert_eq!(request["params"]["taskId"], "wait-task");
            assert!(request["params"].get("inputResponses").is_none());
            if let Some(cancel) = reply.cancel {
                cancel.cancel();
            }
            if !reply.hold.is_zero() {
                std::thread::sleep(reply.hold);
            }
            if let Some(task) = reply.task {
                let result = write(&mut poll, &response(3 + index as u64, task));
                if reply.hold.is_zero() {
                    result.unwrap();
                }
            }
            sent = Instant::now();
        }

        // A healthy sibling request follows every outcome. An extra poll,
        // input update or remote cancellation is a hard protocol failure.
        let mut sentinel = accept(&listener);
        let request = read(&mut sentinel);
        assert_eq!(request["id"], next_id);
        assert_eq!(
            request["method"], "tools/list",
            "the wait must stop without another Task or input-effect request"
        );
        write(
            &mut sentinel,
            &json!({
                "jsonrpc": "2.0", "id": next_id,
                "result": {"resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private"}
            }),
        )
        .unwrap();
        delays
    });
    (target, peer)
}

fn plan(target: &str) -> crate::ClientProtocolPlan {
    crate::ClientProtocolPlan::http(
        crate::ProtocolPolicy::ModernOnly,
        Some(crate::CanonicalHttpUrl::parse(target).unwrap()),
        None,
        None,
        "task-wait-credential".to_owned(),
        "task-wait-security".to_owned(),
        "task-wait-transport".to_owned(),
        1,
        1,
        0,
    )
    .unwrap()
}

fn run(
    initial: Value,
    replies: Vec<Reply>,
    policy: FinalTaskWaitPolicy,
    cancellation: McpRequestCancellation,
    cancel_after: Option<Duration>,
    expected: Result<FinalTaskWaitOutcome, ()>,
) -> (FinalTask, Vec<Duration>) {
    run_http_wait(
        initial, replies, policy, cancellation, cancel_after, None, expected,
    )
}

fn run_http_wait(
    initial: Value,
    replies: Vec<Reply>,
    policy: FinalTaskWaitPolicy,
    cancellation: McpRequestCancellation,
    cancel_after: Option<Duration>,
    maximum_retries: Option<u8>,
    expected: Result<FinalTaskWaitOutcome, ()>,
) -> (FinalTask, Vec<Duration>) {
    let before = serde_json::to_vec(&snapshot(&initial)).unwrap();
    let (target, peer) = peer(initial, replies);
    let retained = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let mut client = HttpClient::connect(
                &cx,
                plan(&target),
                ClientInfo {
                    name: "task-wait-client".to_owned(),
                    version: "1".to_owned(),
                },
                ClientCapabilities {
                    roots: Some(fastmcp_protocol::RootsCapability::default()),
                    ..ClientCapabilities::default()
                },
            )
            .await
            .unwrap();
            let mut handle = client
                .attach_final_task(&cx, FinalTaskId::parse("wait-task").unwrap())
                .await
                .unwrap();
            let cancel_thread = cancel_after.map(|delay| {
                let cancellation = cancellation.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(delay);
                    cancellation.cancel();
                })
            });
            let result = match maximum_retries {
                Some(limit) => handle
                    .wait_with_http_recovery(&cx, &mut client, &cancellation, policy, limit)
                    .await,
                None => handle.wait(&cx, &mut client, &cancellation, policy).await,
            };
            match expected {
                Ok(expected) => {
                    assert_eq!(result.unwrap(), expected);
                    if matches!(
                        expected,
                        FinalTaskWaitOutcome::Completed
                            | FinalTaskWaitOutcome::Failed
                            | FinalTaskWaitOutcome::Cancelled
                            | FinalTaskWaitOutcome::InputRequired
                    ) {
                        assert_eq!(
                            handle
                                .wait(&cx, &mut client, &cancellation, policy)
                                .await
                                .unwrap(),
                            expected,
                            "retained terminal/input snapshots require no second get"
                        );
                    }
                }
                Err(()) => {
                    assert!(result.is_err());
                    assert_eq!(
                        serde_json::to_vec(handle.task()).unwrap(),
                        before,
                        "a rejected identity must not mutate the retained snapshot"
                    );
                }
            }
            if let Some(thread) = cancel_thread {
                thread.join().unwrap();
            }
            assert!(
                cx.checkpoint().is_ok(),
                "the caller and sibling requests remain usable"
            );
            client.list_tools(&cx, None).await.unwrap();
            handle.task().clone()
        });
    (retained, peer.join().unwrap())
}

fn policy(timeout_ms: u64, polls: usize, fallback_ms: u64) -> FinalTaskWaitPolicy {
    FinalTaskWaitPolicy::new(
        Duration::from_millis(timeout_ms),
        polls,
        Duration::from_millis(fallback_ms),
    )
    .unwrap()
}

#[test]
fn public_http_wait_recovers_dropped_reads_with_bounded_backoff() {
    let (retained, _) = run_http_wait(
        task("working", Some(120)),
        vec![
            Reply::disconnect(120),
            Reply::disconnect(120),
            Reply::new(task("completed", None), 200),
        ],
        policy(5000, 3, 1),
        McpRequestCancellation::new(),
        None,
        Some(2),
        Ok(FinalTaskWaitOutcome::Completed),
    );
    assert!(matches!(retained, FinalTask::Completed { .. }));
}

#[test]
fn public_http_wait_recovery_stops_at_attempt_limits() {
    // Each scripted peer expects a sibling tools/list immediately after the
    // last permitted read, including when the original fail-fast API is used.
    for (polls, retries) in [(10, Some(0)), (1, Some(5)), (10, None)] {
        run_http_wait(
            task("working", Some(1)),
            vec![Reply::disconnect(1)],
            policy(5000, polls, 1),
            McpRequestCancellation::new(),
            None,
            retries,
            Err(()),
        );
    }
}

#[test]
fn cancelling_during_task_recovery_backoff_stops_before_another_read() {
    use std::cell::Cell;

    struct Disconnected<'a>(&'a Cell<usize>);

    impl TaskWaitTransport for Disconnected<'_> {
        type Error = McpError;

        async fn read_task(
            &mut self,
            _: &Cx,
            _: &McpRequestCancellation,
            _: FinalTaskId,
        ) -> McpResult<FinalTask> {
            self.0.set(self.0.get() + 1);
            Err(McpError::internal_error("scripted read failed"))
        }
    }

    RuntimeBuilder::current_thread().build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let cancellation = McpRequestCancellation::new();
        let reads = Cell::new(0);
        let mut transport = Disconnected(&reads);
        let mut handle = FinalTaskHandle::new(snapshot(&task("working", Some(1))));
        let outcome = {
            let mut wait = std::pin::pin!(wait_for_task_with_retries(
                &mut handle, &cx, &mut transport, &cancellation, policy(5000, 3, 1), 2, |_| true,
            ));
            std::future::poll_fn(|task_cx| {
                let result = wait.as_mut().poll(task_cx);
                if result.is_pending() && reads.get() == 1 && !cancellation.is_cancel_requested() {
                    // The failed read returned synchronously; the wait just
                    // yielded on its recovery timer. Cancel at that boundary.
                    cancellation.cancel();
                    task_cx.waker().wake_by_ref();
                }
                result
            }).await.unwrap()
        };
        assert_eq!(outcome, FinalTaskWaitOutcome::ObservationCancelled);
        assert_eq!(reads.get(), 1);
        assert!(matches!(handle.task(), FinalTask::Working(_)));
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn public_http_wait_recovery_refuses_invalid_task_replies() {
    let mut changed = task("completed", None);
    changed["taskId"] = json!("unrelated-task");
    run_http_wait(
        task("working", Some(1)),
        vec![Reply::new(changed, 1)],
        policy(5000, 10, 1),
        McpRequestCancellation::new(),
        None,
        Some(3),
        Err(()),
    );
}

#[test]
fn public_http_wait_returns_every_task_outcome_and_preserves_payloads() {
    for (status, expected) in [
        ("completed", FinalTaskWaitOutcome::Completed),
        ("failed", FinalTaskWaitOutcome::Failed),
        ("cancelled", FinalTaskWaitOutcome::Cancelled),
        ("input_required", FinalTaskWaitOutcome::InputRequired),
    ] {
        let final_task = task(status, None);
        let (retained, delays) = run(
            task("working", Some(25)),
            vec![Reply::new(final_task.clone(), 25)],
            policy(1000, 8, 10),
            McpRequestCancellation::new(),
            None,
            Ok(expected),
        );
        assert_eq!(delays.len(), 1);
        assert_eq!(serde_json::to_value(retained).unwrap(), final_task);
    }
}

#[test]
fn public_http_wait_replaces_present_and_absent_poll_suggestions() {
    let (retained, delays) = run(
        task("working", Some(30)),
        vec![
            Reply::new(task("working", None), 30),
            Reply::new(task("working", Some(45)), 10),
            Reply::new(task("completed", None), 45),
        ],
        policy(1500, 8, 10),
        McpRequestCancellation::new(),
        None,
        Ok(FinalTaskWaitOutcome::Completed),
    );
    assert_eq!(delays.len(), 3);
    assert!(matches!(retained, FinalTask::Completed { .. }));
    let default = FinalTaskWaitPolicy::default();
    assert_eq!(
        next_delay(&snapshot(&task("working", None)), default).unwrap(),
        Duration::from_secs(1)
    );
    assert_eq!(
        next_delay(&snapshot(&task("working", Some(600001))), default).unwrap(),
        Duration::from_millis(600001)
    );
    assert_eq!(
        next_delay(&snapshot(&task("working", None)), policy(1000, 8, 10)).unwrap(),
        Duration::from_millis(10),
        "absence clears the previous suggestion"
    );
}

#[test]
fn public_http_wait_stops_at_poll_budget_and_never_shortens_server_minimum() {
    run(
        task("working", Some(10)),
        vec![Reply::new(task("working", Some(10)), 10)],
        policy(1000, 1, 1),
        McpRequestCancellation::new(),
        None,
        Ok(FinalTaskWaitOutcome::PollLimitReached),
    );
    for interval in [600001, u64::MAX] {
        run(
            task("working", Some(interval)),
            vec![],
            policy(30, 8, 1),
            McpRequestCancellation::new(),
            None,
            Ok(FinalTaskWaitOutcome::DeadlineElapsed),
        );
    }
    // A fresh snapshot can move the next poll beyond the same original budget.
    run(
        task("working", Some(10)),
        vec![Reply::new(task("working", Some(600001)), 10)],
        policy(50, 8, 1),
        McpRequestCancellation::new(),
        None,
        Ok(FinalTaskWaitOutcome::DeadlineElapsed),
    );
}

#[test]
fn public_http_wait_cancels_sleep_and_inflight_read_without_cancelling_task() {
    for cancelled_before in [false, true] {
        let cancellation = McpRequestCancellation::new();
        if cancelled_before {
            cancellation.cancel();
        }
        let (retained, _) = run(
            task("working", Some(600001)),
            vec![],
            policy(1000, 8, 1),
            cancellation,
            (!cancelled_before).then_some(Duration::from_millis(15)),
            Ok(FinalTaskWaitOutcome::ObservationCancelled),
        );
        assert!(matches!(retained, FinalTask::Working(_)));
    }
    let cancellation = McpRequestCancellation::new();
    let mut reply = Reply::new(task("completed", None), 5);
    reply.cancel = Some(cancellation.clone());
    reply.hold = Duration::from_millis(40);
    let (retained, _) = run(
        task("working", Some(5)),
        vec![reply],
        policy(1000, 8, 1),
        cancellation,
        None,
        Ok(FinalTaskWaitOutcome::ObservationCancelled),
    );
    assert!(
        matches!(retained, FinalTask::Working(_)),
        "a completing or late read cannot publish after cancellation"
    );
}

#[test]
fn public_http_wait_deadline_includes_pending_response_without_reset() {
    let mut reply = Reply::new(task("completed", None), 5);
    reply.hold = Duration::from_millis(90);
    let (retained, _) = run(
        task("working", Some(5)),
        vec![reply],
        policy(35, 8, 1),
        McpRequestCancellation::new(),
        None,
        Ok(FinalTaskWaitOutcome::DeadlineElapsed),
    );
    assert!(matches!(retained, FinalTask::Working(_)));
}

#[test]
fn public_http_wait_rejects_changed_identity_and_retains_original_snapshot() {
    for field in ["taskId", "createdAt"] {
        let mut changed = task("completed", None);
        changed[field] = match field {
            "taskId" => json!("foreign-task"),
            "createdAt" => json!("2026-07-28T12:00:02Z"),
            _ => unreachable!(),
        };
        run(
            task("working", Some(5)),
            vec![Reply::new(changed, 5)],
            policy(1000, 8, 1),
            McpRequestCancellation::new(),
            None,
            Err(()),
        );
    }
    let mut equivalent = task("completed", None);
    equivalent["createdAt"] = json!("2026-07-28T08:00:00-04:00");
    run(
        task("working", Some(5)),
        vec![Reply::new(equivalent, 5)],
        policy(1000, 8, 1),
        McpRequestCancellation::new(),
        None,
        Ok(FinalTaskWaitOutcome::Completed),
    );
}

fn run_http_task_identity_case(
    initial: Value,
    through_watch: bool,
    reconcile: bool,
    candidate: Value,
    admitted: bool,
) {
    let before = serde_json::to_vec(&snapshot(&initial)).unwrap();
    let expected = serde_json::to_vec(&snapshot(&candidate)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = format!("http://{}/mcp", listener.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let mut discover = accept(&listener);
        assert_eq!(read(&mut discover)["method"], "server/discover");
        write(&mut discover, &discovery()).unwrap();
        let mut attach = accept(&listener);
        assert_eq!(read(&mut attach)["method"], "tasks/get");
        write(&mut attach, &response(2, initial.clone())).unwrap();

        let mut observe = accept(&listener);
        let request = read(&mut observe);
        assert_eq!(request["id"], 3);
        if through_watch {
            assert_eq!(request["method"], "subscriptions/listen");
            assert_eq!(
                request["params"]["notifications"]["taskIds"],
                json!(["wait-task"])
            );
            let mut notified = if reconcile {
                let mut ambiguous = initial;
                ambiguous["statusMessage"] = json!("requires authoritative reconciliation");
                ambiguous
            } else {
                candidate.clone()
            };
            notified["_meta"] = json!({"io.modelcontextprotocol/subscriptionId": 3});
            let acknowledged = json!({
                "jsonrpc": "2.0",
                "method": "notifications/subscriptions/acknowledged",
                "params": {
                    "_meta": {"io.modelcontextprotocol/subscriptionId": 3},
                    "notifications": {"taskIds": ["wait-task"]}
                }
            });
            let notification = json!({
                "jsonrpc": "2.0", "method": "notifications/tasks", "params": notified
            });
            let terminal = json!({"jsonrpc":"2.0", "id":3,
                "result":{"resultType":"complete",
                    "_meta":{"io.modelcontextprotocol/subscriptionId":3}}});
            let body =
                format!("data: {acknowledged}\n\ndata: {notification}\n\ndata: {terminal}\n\n");
            write!(
                observe,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            )
            .unwrap();
            observe.flush().unwrap();
            if reconcile {
                let mut get = accept(&listener);
                let request = read(&mut get);
                assert_eq!(request["id"], 4);
                assert_eq!(request["method"], "tasks/get");
                write(&mut get, &response(4, candidate)).unwrap();
            }
        } else {
            assert_eq!(request["method"], "tasks/get");
            write(&mut observe, &response(3, candidate)).unwrap();
        }

        // A changed identity must not provoke an extra reconciliation or
        // consume the next request's response. The same client stays usable.
        let expected_id = if reconcile { 5 } else { 4 };
        let mut sibling = accept(&listener);
        let request = read(&mut sibling);
        assert_eq!(request["method"], "tools/list");
        assert_eq!(request["id"], expected_id);
        write(
            &mut sibling,
            &json!({"jsonrpc":"2.0", "id":expected_id,
                "result":{"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"}}),
        )
        .unwrap();
    });

    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let mut client = HttpClient::connect(
                &cx,
                plan(&target),
                ClientInfo {
                    name: "task-identity-client".to_owned(),
                    version: "1".to_owned(),
                },
                ClientCapabilities::default(),
            )
            .await
            .unwrap();
            let mut handle = client
                .attach_final_task(&cx, FinalTaskId::parse("wait-task").unwrap())
                .await
                .unwrap();
            if through_watch {
                let mut watch = handle
                    .watch(
                        &cx,
                        &mut client,
                        crate::sse::SseLimits::new(4096, 8192, 8).unwrap(),
                    )
                    .await
                    .unwrap();
                assert!(matches!(
                    watch.next_event(&cx).await.unwrap(),
                    Some(crate::FinalTaskWatchEvent::Acknowledged { .. })
                ));
                let event = watch.next_event(&cx).await;
                if admitted {
                    if reconcile {
                        assert!(matches!(
                            event.unwrap(),
                            Some(crate::FinalTaskWatchEvent::TaskReconciled { .. })
                        ));
                    } else {
                        assert!(matches!(
                            event.unwrap(),
                            Some(crate::FinalTaskWatchEvent::TaskUpdated(_))
                        ));
                    }
                } else {
                    assert!(
                        event.is_err(),
                        "a changed identity must not replace the handle"
                    );
                    assert!(watch.next_event(&cx).await.unwrap().is_none());
                }
            } else {
                assert_eq!(handle.poll(&cx, &mut client).await.is_ok(), admitted);
            }
            assert_eq!(
                serde_json::to_vec(handle.task()).unwrap(),
                if admitted { expected } else { before },
                "a refused snapshot must leave the exact retained state unchanged"
            );
            assert!(cx.checkpoint().is_ok());
            client.list_tools(&cx, None).await.unwrap();
        });
    peer.join().unwrap();
}

#[test]
fn public_http_task_poll_preserves_creation_identity() {
    let mut changed = task("working", None);
    changed["lastUpdatedAt"] = json!("2026-07-28T12:00:02Z");
    changed["createdAt"] = json!("2026-07-28T12:00:01Z");
    run_http_task_identity_case(task("working", None), false, false, changed, false);
    let mut equivalent = task("working", None);
    equivalent["createdAt"] = json!("2026-07-28T08:00:00-04:00");
    equivalent["lastUpdatedAt"] = json!("2026-07-28T12:00:02Z");
    run_http_task_identity_case(task("working", None), false, false, equivalent, true);
}

#[test]
fn public_http_task_watch_preserves_identity_before_and_after_reconciliation() {
    for (reconcile, updated) in [
        (false, "2026-07-28T12:00:02Z"),
        (false, "2026-07-28T12:00:01Z"),
        (true, "2026-07-28T12:00:01Z"),
    ] {
        let mut changed = task("working", None);
        changed["lastUpdatedAt"] = json!(updated);
        changed["createdAt"] = json!("2026-07-28T12:00:01Z");
        run_http_task_identity_case(task("working", None), true, reconcile, changed, false);
    }
    let mut equivalent = task("working", None);
    equivalent["createdAt"] = json!("2026-07-28T08:00:00-04:00");
    equivalent["lastUpdatedAt"] = json!("2026-07-28T12:00:02Z");
    run_http_task_identity_case(task("working", None), true, false, equivalent, true);
}

#[test]
fn public_http_task_poll_and_watch_accept_authoritative_retention_changes() {
    for (previous_ttl, next_ttl) in [
        (None, Some(u64::MAX / 2)),
        (Some(u64::MAX / 2), Some(u64::MAX)),
        (Some(u64::MAX), Some(u64::MAX / 2)),
        (Some(u64::MAX), None),
    ] {
        for (through_watch, reconcile) in [(false, false), (true, false), (true, true)] {
            let mut initial = task("working", None);
            initial["ttlMs"] = json!(previous_ttl);
            let mut candidate = initial.clone();
            candidate["ttlMs"] = json!(next_ttl);
            candidate["lastUpdatedAt"] = json!("2026-07-28T12:00:02Z");
            run_http_task_identity_case(initial, through_watch, reconcile, candidate, true);
        }
    }
}

#[test]
fn public_http_task_watch_preflight_refuses_expiry_and_denied_time_without_request_ids() {
    use asupersync::cx::{CapSet, CapSetRuntimeMask};

    for (status, reason, deny_time) in [
        ("working", FinalTaskWaitOutcome::TaskExpired, false),
        ("completed", FinalTaskWaitOutcome::Completed, false),
        ("working", FinalTaskWaitOutcome::TimerUnavailable, true),
    ] {
        let mut initial = task(status, None);
        initial["createdAt"] = json!("1970-01-01T00:00:00Z");
        initial["ttlMs"] = if deny_time { Value::Null } else { json!(1) };
        let created = creation_receipt(initial);
        let mut handle = FinalTaskHandle::from_created(&created).unwrap();
        let retained = serde_json::to_vec(handle.task()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = format!("http://{}/mcp", listener.local_addr().unwrap());
        let peer = std::thread::spawn(move || {
            let mut discover = accept(&listener);
            assert_eq!(read(&mut discover)["method"], "server/discover");
            write(&mut discover, &discovery()).unwrap();
            let mut sibling = accept(&listener);
            let request = read(&mut sibling);
            assert_eq!(request["method"], "tools/list");
            assert_eq!(request["id"], 2, "a refused watch allocates no request ID");
            write(
                &mut sibling,
                &json!({"jsonrpc":"2.0", "id":2,
                    "result":{"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"}}),
            )
            .unwrap();
        });
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let mut client = HttpClient::connect(
                    &cx,
                    plan(&target),
                    ClientInfo {
                        name: "expired-task-watch".to_owned(),
                        version: "1".to_owned(),
                    },
                    ClientCapabilities::default(),
                )
                .await
                .unwrap();
                let driverless = Cx::for_request();
                let opening_caller = if deny_time {
                    with_caller(&driverless, || {
                        let _denied = Cx::push_restriction(
                            <CapSet<true, false, true, true, true> as CapSetRuntimeMask>::MASK,
                        );
                        Cx::current().unwrap()
                    })
                } else {
                    driverless.clone()
                };
                assert_eq!(opening_caller.capabilities().time, !deny_time);
                let mut watch = handle
                    .watch(
                        &opening_caller,
                        &mut client,
                        crate::sse::SseLimits::new(4096, 8192, 8).unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(watch.stop_reason(), Some(reason));
                assert!(watch.next_event(&cx).await.unwrap().is_none());
                assert_eq!(serde_json::to_vec(watch.task()).unwrap(), retained);
                drop(watch);
                assert!(driverless.checkpoint().is_ok());
                client.list_tools(&cx, None).await.unwrap();
            });
        peer.join().unwrap();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpTaskWatchRetentionCase {
    Silent,
    Shortened,
    Renewed,
    Removed,
    ExpiredNotification,
    ExpiredReconciliation,
    ReconciliationExpires,
    OpeningCallerCancelled,
}

fn write_http_task_watch_event(stream: &mut TcpStream, event: Value) {
    write!(stream, "data: {event}\n\n").unwrap();
    stream.flush().unwrap();
}

fn http_task_watch_notification(mut task: Value) -> Value {
    task["_meta"] = json!({"io.modelcontextprotocol/subscriptionId":3});
    json!({"jsonrpc":"2.0", "method":"notifications/tasks", "params":task})
}

fn assert_http_task_watch_socket_closed(stream: &mut TcpStream) {
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("stopping Task observation must close its owned socket: {other:?}"),
    }
}

fn run_http_task_watch_retention_case(case: HttpTaskWatchRetentionCase) {
    use HttpTaskWatchRetentionCase as Case;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = format!("http://{}/mcp", listener.local_addr().unwrap());
    let opening_caller = Cx::for_request();
    let stopped_caller = opening_caller.clone();
    let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
    let reconcile = matches!(
        case,
        Case::ExpiredReconciliation | Case::ReconciliationExpires | Case::OpeningCallerCancelled
    );
    let peer = std::thread::spawn(move || {
        let mut discover = accept(&listener);
        assert_eq!(read(&mut discover)["method"], "server/discover");
        write(&mut discover, &discovery()).unwrap();
        let mut attach = accept(&listener);
        assert_eq!(read(&mut attach)["method"], "tasks/get");
        let mut initial = task("working", None);
        initial["createdAt"] = json!("1970-01-01T00:00:00Z");
        if matches!(
            case,
            Case::Silent | Case::Renewed | Case::Removed | Case::ReconciliationExpires
        ) {
            initial["ttlMs"] = json!(u64::try_from(wall_now_nanos() / 1_000_000).unwrap() + 2_000);
        }
        write(&mut attach, &response(2, initial.clone())).unwrap();
        let mut stream = accept(&listener);
        let request = read(&mut stream);
        assert_eq!(request["method"], "subscriptions/listen");
        assert_eq!(request["id"], 3);
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n").unwrap();
        write_http_task_watch_event(
            &mut stream,
            json!({
                "jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged",
                "params":{"_meta":{"io.modelcontextprotocol/subscriptionId":3}, "notifications":{"taskIds":["wait-task"]}}
            }),
        );
        match case {
            Case::Silent => {}
            Case::Shortened | Case::Renewed | Case::Removed => {
                let mut updated = initial.clone();
                updated["lastUpdatedAt"] = json!("2026-07-28T12:00:02Z");
                updated["ttlMs"] = match case {
                    Case::Shortened => {
                        json!(u64::try_from(wall_now_nanos() / 1_000_000).unwrap() + 1_000)
                    }
                    Case::Renewed => {
                        json!(u64::try_from(wall_now_nanos() / 1_000_000).unwrap() + 60_000)
                    }
                    Case::Removed => Value::Null,
                    _ => unreachable!(),
                };
                write_http_task_watch_event(
                    &mut stream,
                    http_task_watch_notification(updated.clone()),
                );
                if case != Case::Shortened {
                    release_receiver
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap();
                    let mut completed = task("completed", None);
                    completed["createdAt"] = updated["createdAt"].clone();
                    completed["ttlMs"] = updated["ttlMs"].clone();
                    completed["lastUpdatedAt"] = json!("2026-07-28T12:00:03Z");
                    write_http_task_watch_event(
                        &mut stream,
                        http_task_watch_notification(completed),
                    );
                }
            }
            Case::ExpiredNotification => {
                let mut completed = task("completed", None);
                completed["createdAt"] = initial["createdAt"].clone();
                completed["lastUpdatedAt"] = json!("2026-07-28T12:00:02Z");
                completed["ttlMs"] = json!(1);
                write_http_task_watch_event(&mut stream, http_task_watch_notification(completed));
            }
            Case::ExpiredReconciliation
            | Case::ReconciliationExpires
            | Case::OpeningCallerCancelled => {
                let mut ambiguous = initial.clone();
                ambiguous["status"] = json!("cancelled");
                write_http_task_watch_event(&mut stream, http_task_watch_notification(ambiguous));
                let mut get = accept(&listener);
                let request = read(&mut get);
                assert_eq!(request["method"], "tasks/get");
                assert_eq!(request["id"], 4);
                let mut completed = task("completed", None);
                completed["createdAt"] = initial["createdAt"].clone();
                completed["lastUpdatedAt"] = json!("2026-07-28T12:00:02Z");
                if case == Case::ExpiredReconciliation {
                    completed["ttlMs"] = json!(1);
                    write(&mut get, &response(4, completed)).unwrap();
                } else {
                    if case == Case::OpeningCallerCancelled {
                        stopped_caller.set_cancel_requested(true);
                    }
                    assert_http_task_watch_socket_closed(&mut get);
                    // A late terminal, even one removing the TTL, cannot
                    // resurrect the exhausted observation or replace state.
                    let _ = write(&mut get, &response(4, completed));
                }
            }
        }
        assert_http_task_watch_socket_closed(&mut stream);
        let mut sibling = accept(&listener);
        let request = read(&mut sibling);
        let expected_id = if reconcile { 5 } else { 4 };
        assert_eq!(request["method"], "tools/list");
        assert_eq!(request["id"], expected_id);
        write(
            &mut sibling,
            &json!({"jsonrpc":"2.0", "id":expected_id,
                "result":{"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"}}),
        )
        .unwrap();
    });
    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let mut client = HttpClient::connect(
                &cx,
                plan(&target),
                ClientInfo {
                    name: "retained-http-task-watch".to_owned(),
                    version: "1".to_owned(),
                },
                ClientCapabilities::default(),
            )
            .await
            .unwrap();
            let mut handle = client
                .attach_final_task(&cx, FinalTaskId::parse("wait-task").unwrap())
                .await
                .unwrap();
            let original_expiry = retention_deadline(handle.task()).unwrap();
            let initial = serde_json::to_vec(handle.task()).unwrap();
            assert!(opening_caller.timer_driver().is_none());
            let mut watch = handle
                .watch(
                    &opening_caller,
                    &mut client,
                    crate::sse::SseLimits::new(4096, 8192, 8).unwrap(),
                )
                .await
                .unwrap();
            assert!(matches!(
                watch.next_event(&cx).await.unwrap(),
                Some(FinalTaskWatchEvent::Acknowledged { .. })
            ));
            let mut expected = initial;
            if matches!(case, Case::Shortened | Case::Renewed | Case::Removed) {
                assert!(matches!(
                    watch.next_event(&cx).await.unwrap(),
                    Some(FinalTaskWatchEvent::TaskUpdated(_))
                ));
                assert!(matches!(watch.task(), FinalTask::Working(_)));
                expected = serde_json::to_vec(watch.task()).unwrap();
                if case != Case::Shortened {
                    let delay = original_expiry
                        .unwrap()
                        .saturating_sub(wall_now_nanos())
                        .max(0)
                        + 50_000_000;
                    asupersync::time::sleep(
                        cx.now(),
                        Duration::from_nanos(u64::try_from(delay).unwrap()),
                    )
                    .await;
                    release_sender.send(()).unwrap();
                }
            }
            let observed = watch.next_event(&cx).await;
            if matches!(case, Case::Renewed | Case::Removed) {
                assert!(matches!(
                    observed.unwrap(),
                    Some(FinalTaskWatchEvent::TaskUpdated(_))
                ));
                assert!(matches!(watch.task(), FinalTask::Completed { .. }));
                assert_eq!(watch.stop_reason(), Some(FinalTaskWaitOutcome::Completed));
            } else if case == Case::OpeningCallerCancelled {
                assert!(matches!(
                    observed,
                    Err(HttpClientError::Connection(
                        crate::ClientHttpConnectionError::Modern(
                            crate::ModernHttpClientError::Executor(
                                crate::http_executor::ModernHttpExecutorError::Cancelled
                            )
                        )
                    ))
                ));
                assert_eq!(
                    watch.stop_reason(),
                    Some(FinalTaskWaitOutcome::ObservationCancelled)
                );
                assert_eq!(serde_json::to_vec(watch.task()).unwrap(), expected);
            } else {
                assert!(
                    observed.unwrap().is_none(),
                    "expired observation must not yield a late event: {case:?}"
                );
                assert_eq!(watch.stop_reason(), Some(FinalTaskWaitOutcome::TaskExpired));
                assert_eq!(serde_json::to_vec(watch.task()).unwrap(), expected);
            }
            assert!(watch.next_event(&cx).await.unwrap().is_none());
            drop(watch);
            assert!(
                cx.checkpoint().is_ok(),
                "stopping observation must preserve the healthy waiter"
            );
            client.list_tools(&cx, None).await.unwrap();
        });
    peer.join().unwrap();
}

#[test]
fn public_http_task_watch_silent_stream_stops_at_retention() {
    run_http_task_watch_retention_case(HttpTaskWatchRetentionCase::Silent);
}

#[test]
fn public_http_task_watch_authoritative_ttl_changes_adjust_retention() {
    for case in [
        HttpTaskWatchRetentionCase::Shortened,
        HttpTaskWatchRetentionCase::Renewed,
        HttpTaskWatchRetentionCase::Removed,
    ] {
        run_http_task_watch_retention_case(case);
    }
}

#[test]
fn public_http_task_watch_expired_updates_cannot_publish_terminal_state() {
    for case in [
        HttpTaskWatchRetentionCase::ExpiredNotification,
        HttpTaskWatchRetentionCase::ExpiredReconciliation,
        HttpTaskWatchRetentionCase::ReconciliationExpires,
    ] {
        run_http_task_watch_retention_case(case);
    }
}

#[test]
fn public_http_task_watch_reconciliation_retains_opening_caller_cancellation() {
    run_http_task_watch_retention_case(HttpTaskWatchRetentionCase::OpeningCallerCancelled);
}

#[test]
fn public_http_task_input_expiry_refuses_before_request_allocation() {
    let live_expiry_ms = u64::try_from(wall_now_nanos() / 1_000_000).unwrap() + 300_000;
    for ttl_ms in [None, Some(live_expiry_ms), Some(1)] {
        let expired = ttl_ms == Some(1);
        let mut initial = task("input_required", None);
        initial["createdAt"] = json!("1970-01-01T00:00:00Z");
        initial["ttlMs"] = json!(ttl_ms);
        let before = serde_json::to_vec(&snapshot(&initial)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = format!("http://{}/mcp", listener.local_addr().unwrap());
        let peer = std::thread::spawn(move || {
            let mut discover = accept(&listener);
            assert_eq!(read(&mut discover)["method"], "server/discover");
            write(&mut discover, &discovery()).unwrap();
            let mut attach = accept(&listener);
            assert_eq!(read(&mut attach)["method"], "tasks/get");
            write(&mut attach, &response(2, initial)).unwrap();
            if !expired {
                let mut update = accept(&listener);
                let request = read(&mut update);
                assert_eq!(request["id"], 3);
                assert_eq!(request["method"], "tasks/update");
                assert_eq!(request["params"]["taskId"], "wait-task");
                assert_eq!(
                    request["params"]["inputResponses"],
                    json!({"roots":{"roots":[]}})
                );
                write(
                    &mut update,
                    &json!({"jsonrpc":"2.0", "id":3,
                    "result":{"resultType":"complete"}}),
                )
                .unwrap();
            }
            let expected_id = if expired { 3 } else { 4 };
            let mut sibling = accept(&listener);
            let request = read(&mut sibling);
            assert_eq!(
                request["method"], "tools/list",
                "expired input must not be transmitted or retried"
            );
            assert_eq!(
                request["id"], expected_id,
                "local refusal must not consume a request ID"
            );
            write(
                &mut sibling,
                &json!({"jsonrpc":"2.0", "id":expected_id,
                    "result":{"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"}}),
            )
            .unwrap();
        });
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let mut client = HttpClient::connect(
                    &cx,
                    plan(&target),
                    ClientInfo {
                        name: "task-input-client".to_owned(),
                        version: "1".to_owned(),
                    },
                    ClientCapabilities {
                        roots: Some(fastmcp_protocol::RootsCapability::default()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
                let mut handle = client
                    .attach_final_task(&cx, FinalTaskId::parse("wait-task").unwrap())
                    .await
                    .unwrap();
                let inputs = serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap();
                let updated = handle.resume_input(&cx, &mut client, inputs).await;
                assert_eq!(updated.is_ok(), !expired);
                assert_eq!(
                    serde_json::to_vec(handle.task()).unwrap(),
                    before,
                    "an update acknowledgement or refusal cannot invent a Task state"
                );
                assert!(cx.checkpoint().is_ok());
                client.list_tools(&cx, None).await.unwrap();
            });
        peer.join().unwrap();
    }
}

#[test]
fn task_wait_policy_and_missing_timer_fail_before_transport_activity() {
    for (timeout, polls, fallback) in [
        (Duration::ZERO, 1, Duration::from_secs(1)),
        (Duration::from_secs(86401), 1, Duration::from_secs(1)),
        (Duration::from_secs(1), 0, Duration::from_secs(1)),
        (Duration::from_secs(1), 4097, Duration::from_secs(1)),
        (Duration::from_secs(1), 1, Duration::ZERO),
        (Duration::from_secs(1), 1, Duration::from_secs(301)),
    ] {
        assert!(FinalTaskWaitPolicy::new(timeout, polls, fallback).is_err());
    }
    assert!(
        FinalTaskWaitPolicy::new(Duration::from_hours(24), 4096, Duration::from_mins(5),).is_ok()
    );

    struct NoReads;
    impl TaskWaitTransport for NoReads {
        type Error = McpError;
        fn read_task(
            &mut self,
            _: &Cx,
            _: &McpRequestCancellation,
            _: FinalTaskId,
        ) -> impl std::future::Future<Output = McpResult<FinalTask>> {
            std::future::poll_fn(|_| {
                panic!("unavailable timer must refuse before a transport read")
            })
        }
    }
    let cx = Cx::for_request();
    assert!(cx.timer_driver().is_none());
    let mut handle = FinalTaskHandle::new(snapshot(&task("working", Some(1))));
    let cancellation = McpRequestCancellation::new();
    let mut transport = NoReads;
    let mut wait = std::pin::pin!(wait_for_task(
        &mut handle,
        &cx,
        &mut transport,
        &cancellation,
        policy(1000, 8, 1),
    ));
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    assert!(matches!(
        wait.as_mut().poll(&mut context),
        Poll::Ready(Ok(FinalTaskWaitOutcome::TimerUnavailable))
    ));
}

#[test]
fn public_http_task_watch_acknowledgements_use_exact_set_subsets() {
    for mode in ["duplicates", "empty", "absent", "foreign"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = format!("http://{}/mcp", listener.local_addr().unwrap());
        let peer = std::thread::spawn(move || {
            let mut discover = accept(&listener);
            assert_eq!(read(&mut discover)["method"], "server/discover");
            write(&mut discover, &discovery()).unwrap();
            let mut attach = accept(&listener);
            assert_eq!(read(&mut attach)["method"], "tasks/get");
            write(&mut attach, &response(2, task("working", None))).unwrap();

            let mut observe = accept(&listener);
            let request = read(&mut observe);
            assert_eq!(request["id"], 3);
            assert_eq!(request["method"], "subscriptions/listen");
            assert_eq!(
                request["params"]["notifications"]["taskIds"],
                json!(["wait-task"])
            );
            let accepted = match mode {
                "duplicates" => json!({"taskIds":["wait-task", "wait-task"]}),
                "empty" => json!({"taskIds":[]}),
                "absent" => json!({}),
                "foreign" => json!({"taskIds":["wait-task", "foreign-task"]}),
                _ => unreachable!(),
            };
            let acknowledged = json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged", "params":{
                "_meta":{"io.modelcontextprotocol/subscriptionId":3}, "notifications":accepted
            }});
            let mut body = format!("data: {acknowledged}\n\n");
            if mode == "duplicates" {
                let mut completed = task("completed", None);
                completed["lastUpdatedAt"] = json!("2026-07-28T12:00:02Z");
                completed["_meta"] = json!({"io.modelcontextprotocol/subscriptionId":3});
                let notification =
                    json!({"jsonrpc":"2.0", "method":"notifications/tasks", "params":completed});
                body.push_str(&format!("data: {notification}\n\n"));
            }
            let terminal = json!({"jsonrpc":"2.0", "id":3, "result":{
                "resultType":"complete", "_meta":{"io.modelcontextprotocol/subscriptionId":3}
            }});
            body.push_str(&format!("data: {terminal}\n\n"));
            // Keep a valid live response open through the next independent
            // request. Empty acceptance must exhaust before the queued
            // normal terminal, and cannot rely on an early transport EOF.
            write!(observe,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n",
                body.len(),
            ).unwrap();
            observe.flush().unwrap();

            let mut sibling = accept(&listener);
            let request = read(&mut sibling);
            assert_eq!(
                request["method"], "tools/list",
                "no implicit Task cancellation or extra observation request"
            );
            assert_eq!(request["id"], 4);
            write(
                &mut sibling,
                &json!({"jsonrpc":"2.0", "id":4, "result":{
                    "resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"
                }}),
            )
            .unwrap();
            drop(observe);
        });
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let mut client = HttpClient::connect(
                    &cx,
                    plan(&target),
                    ClientInfo {
                        name: "task-ack-client".to_owned(),
                        version: "1".to_owned(),
                    },
                    ClientCapabilities::default(),
                )
                .await
                .unwrap();
                let mut handle = client
                    .attach_final_task(&cx, FinalTaskId::parse("wait-task").unwrap())
                    .await
                    .unwrap();
                let before = serde_json::to_vec(handle.task()).unwrap();
                let mut watch = handle
                    .watch(
                        &cx,
                        &mut client,
                        crate::sse::SseLimits::new(4096, 8192, 8).unwrap(),
                    )
                    .await
                    .unwrap();
                let acknowledged = watch.next_event(&cx).await;
                if mode == "foreign" {
                    assert!(
                        acknowledged.is_err(),
                        "a distinct unrequested ID must not widen the watch"
                    );
                } else {
                    let Some(crate::FinalTaskWatchEvent::Acknowledged { accepted_filter }) =
                        acknowledged.unwrap()
                    else {
                        panic!("valid accepted subsets must reach the caller");
                    };
                    let accepted = fastmcp_protocol::task_subscription_ids(&accepted_filter)
                        .unwrap()
                        .unwrap_or_default();
                    assert_eq!(accepted.is_empty(), mode != "duplicates");
                    assert!(
                        accepted
                            .iter()
                            .all(|id| id == &FinalTaskId::parse("wait-task").unwrap())
                    );
                }
                if mode == "duplicates" {
                    let Some(crate::FinalTaskWatchEvent::TaskUpdated(notification)) =
                        watch.next_event(&cx).await.unwrap()
                    else {
                        panic!("duplicate accepted IDs must permit the owned Task event");
                    };
                    assert!(matches!(
                        notification.params.task,
                        FinalTask::Completed { .. }
                    ));
                }
                let exhausted = asupersync::time::timeout_at(
                    cx.now() + Duration::from_millis(250),
                    watch.next_event(&cx),
                )
                .await
                .expect("exhausted watches must not wait for peer data")
                .unwrap();
                assert!(exhausted.is_none());
                drop(watch);
                if mode == "duplicates" {
                    assert!(matches!(handle.task(), FinalTask::Completed { .. }));
                    assert_eq!(
                        serde_json::to_value(handle.task()).unwrap()["result"]["opaque"],
                        json!({"x":[1,true,"kept"]})
                    );
                } else {
                    assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                }
                assert!(cx.checkpoint().is_ok());
                client.list_tools(&cx, None).await.unwrap();
            });
        peer.join().unwrap();
    }
}

fn creation_receipt(mut task: Value) -> fastmcp_protocol::CreateTaskResult {
    task["resultType"] = json!("task");
    task["_meta"] = json!({"creation-receipt": {"generation": 9}});
    task["x-creation-envelope"] = json!({"opaque": [false, 7, "kept"]});
    serde_json::from_str(&task.to_string()).unwrap()
}

#[test]
fn created_task_handle_retains_every_status_without_consuming_creation_receipt() {
    for status in [
        "working",
        "input_required",
        "completed",
        "failed",
        "cancelled",
    ] {
        let mut initial = task(status, Some(25));
        initial["createdAt"] = json!("2026-07-28T08:00:00-04:00");
        let created = creation_receipt(initial);
        let receipt = serde_json::to_vec(&created).unwrap();
        let snapshot = serde_json::to_vec(&created.task).unwrap();
        let handle = FinalTaskHandle::from_created(&created).unwrap();
        assert_eq!(handle.task_id(), &FinalTaskId::parse("wait-task").unwrap());
        assert_eq!(
            handle.task().base().created_at.as_str(),
            "2026-07-28T08:00:00-04:00",
            "adoption must preserve the admitted creation spelling",
        );
        assert_eq!(serde_json::to_vec(handle.task()).unwrap(), snapshot);
        assert_eq!(serde_json::to_vec(&created).unwrap(), receipt);
        assert_eq!(
            created.additional["x-creation-envelope"],
            json!({"opaque": [false, 7, "kept"]}),
        );
        assert_eq!(
            serde_json::to_value(created.meta.as_ref().unwrap()).unwrap(),
            json!({"creation-receipt": {"generation": 9}}),
        );
    }
}

#[test]
fn created_task_handle_preserves_exact_completed_result_source() {
    const RESULT: &str = r#"{"z-first":1.20e+4,"content":[{"type":"text","text":"finished"}],"wide":123456789012345678901234567890,"a-last":{"opaque":true}}"#;
    let wire = format!(
        r#"{{"resultType":"task","taskId":"wait-task","status":"completed","createdAt":"2026-07-28T12:00:00.000Z","lastUpdatedAt":"2026-07-28T12:00:01Z","ttlMs":null,"result":{RESULT},"_meta":{{"receipt":"original"}},"x-creation-envelope":{{"kept":true}}}}"#,
    );
    let created: fastmcp_protocol::CreateTaskResult = serde_json::from_str(&wire).unwrap();
    let receipt = serde_json::to_string(&created).unwrap();
    let handle = FinalTaskHandle::from_created(&created).unwrap();
    let retained = serde_json::to_string(handle.task()).unwrap();
    assert!(
        retained.contains(RESULT),
        "Task adoption must not rebuild nested result numbers or member order",
    );
    let handle = handle
        .into_driver(FinalTaskDrivePolicy::default())
        .into_handle();
    assert_eq!(serde_json::to_string(handle.task()).unwrap(), retained);
    assert_eq!(serde_json::to_string(&created).unwrap(), receipt);
}

#[test]
fn created_task_handle_rejects_locally_mutated_status_and_payload() {
    use fastmcp_protocol::tasks_extension::TaskStatus;

    for status in [
        "working",
        "input_required",
        "completed",
        "failed",
        "cancelled",
    ] {
        let mut created = creation_receipt(task(status, None));
        assert!(FinalTaskHandle::from_created(&created).is_ok());
        let base = match &mut created.task {
            FinalTask::Working(base) | FinalTask::Cancelled(base) => base,
            FinalTask::InputRequired { base, .. }
            | FinalTask::Completed { base, .. }
            | FinalTask::Failed { base, .. } => base,
        };
        base.status = if status == "working" {
            TaskStatus::Cancelled
        } else {
            TaskStatus::Working
        };
        let before = serde_json::to_vec(&created.task).unwrap();
        assert!(FinalTaskHandle::from_created(&created).is_err());
        assert_eq!(serde_json::to_vec(&created.task).unwrap(), before);
    }

    let mut completed = creation_receipt(task("completed", None));
    let FinalTask::Completed { result, .. } = &mut completed.task else {
        unreachable!();
    };
    result.additional.insert("content".to_owned(), json!([]));
    assert!(
        FinalTaskHandle::from_created(&completed).is_err(),
        "a public-field mutation cannot smuggle a colliding completed payload",
    );

    let mut failed = creation_receipt(task("failed", None));
    let FinalTask::Failed { error, .. } = &mut failed.task else {
        unreachable!();
    };
    error.additional.insert("code".to_owned(), json!(0));
    assert!(FinalTaskHandle::from_created(&failed).is_err());

    let mut input = creation_receipt(task("input_required", None));
    let FinalTask::InputRequired { input_requests, .. } = &mut input.task else {
        unreachable!();
    };
    let descriptor = input_requests["roots"].clone();
    for index in 0..128 {
        input_requests.insert(format!("extra-{index}"), descriptor.clone());
    }
    assert_eq!(input_requests.len(), 129);
    assert!(
        FinalTaskHandle::from_created(&input).is_err(),
        "typed local input cannot bypass the Task input-ledger bound",
    );
}

#[test]
fn created_task_handle_preserves_expired_data_and_waits_without_reads() {
    struct NoReads;
    impl TaskWaitTransport for NoReads {
        type Error = McpError;
        fn read_task(
            &mut self,
            _: &Cx,
            _: &McpRequestCancellation,
            _: FinalTaskId,
        ) -> impl std::future::Future<Output = McpResult<FinalTask>> {
            std::future::poll_fn(|_| panic!("expired or terminal Tasks must not be polled"))
        }
    }

    for (status, expected) in [
        ("working", FinalTaskWaitOutcome::TaskExpired),
        ("input_required", FinalTaskWaitOutcome::TaskExpired),
        ("completed", FinalTaskWaitOutcome::Completed),
        ("failed", FinalTaskWaitOutcome::Failed),
        ("cancelled", FinalTaskWaitOutcome::Cancelled),
    ] {
        let mut initial = task(status, Some(25));
        initial["createdAt"] = json!("1970-01-01T00:00:00Z");
        initial["ttlMs"] = json!(1);
        let created = creation_receipt(initial);
        let receipt = serde_json::to_vec(&created).unwrap();
        let mut handle = FinalTaskHandle::from_created(&created).unwrap();
        let snapshot = serde_json::to_vec(handle.task()).unwrap();
        let cx = Cx::for_request();
        let cancellation = McpRequestCancellation::new();
        let mut transport = NoReads;
        let observed = {
            let mut wait = std::pin::pin!(wait_for_task(
                &mut handle,
                &cx,
                &mut transport,
                &cancellation,
                policy(1000, 2, 1),
            ));
            let waker = std::task::Waker::noop();
            let mut context = std::task::Context::from_waker(waker);
            wait.as_mut().poll(&mut context)
        };
        assert!(matches!(observed, Poll::Ready(Ok(outcome)) if outcome == expected));
        assert_eq!(serde_json::to_vec(handle.task()).unwrap(), snapshot);
        assert_eq!(serde_json::to_vec(&created).unwrap(), receipt);
    }
}

#[test]
fn public_http_task_creating_call_preserves_typed_outcomes_without_replay() {
    for expected in ["complete", "task", "input_required"] {
        let result = match expected {
            "complete" => json!({
                "resultType": "complete",
                "content": [{"type": "text", "text": "synchronous"}],
                "x-call": {"retained": true},
            }),
            "task" => {
                let mut result = task("working", Some(80));
                result["resultType"] = json!("task");
                result["_meta"] = json!({"receipt": "creation"});
                result["x-call"] = json!({"retained": true});
                result
            }
            "input_required" => json!({
                "resultType": "input_required",
                "inputRequests": {"roots": {"method": "roots/list"}},
                "requestState": "one-use",
            }),
            _ => unreachable!(),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = format!("http://{}/mcp", listener.local_addr().unwrap());
        let peer = std::thread::spawn(move || {
            let mut discover = accept(&listener);
            let request = read(&mut discover);
            assert_eq!(request["method"], "server/discover");
            assert_eq!(request["id"], 1);
            write(&mut discover, &discovery()).unwrap();
            drop(discover);

            let mut call = accept(&listener);
            let request = read(&mut call);
            assert_eq!(request["method"], "tools/call");
            assert_eq!(request["id"], 2);
            assert_eq!(request["params"]["name"], "start-work");
            assert_eq!(request["params"]["arguments"], json!({"value": 7}));
            assert_eq!(
                request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
                    [fastmcp_protocol::TASKS_EXTENSION],
                json!({}),
            );
            write(
                &mut call,
                &json!({"jsonrpc": "2.0", "id": 2, "result": result}),
            )
            .unwrap();
            drop(call);

            let mut sibling = accept(&listener);
            let request = read(&mut sibling);
            assert_eq!(
                request["method"], "tools/list",
                "typed Task outcomes must not trigger a retry, callback, or attachment read",
            );
            assert_eq!(request["id"], 3);
            write(
                &mut sibling,
                &json!({"jsonrpc": "2.0", "id": 3, "result": {
                    "resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private"
                }}),
            )
            .unwrap();
        });
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let mut client = HttpClient::connect(
                    &cx,
                    plan(&target),
                    ClientInfo {
                        name: "task-creating-http-client".to_owned(),
                        version: "1".to_owned(),
                    },
                    ClientCapabilities {
                        roots: Some(fastmcp_protocol::RootsCapability::default()),
                        ..ClientCapabilities::default()
                    },
                )
                .await
                .unwrap();
                let cancellation = McpRequestCancellation::new();
                let outcome = client
                    .call_tool_final_outcome_with_cancellation(
                        &cx,
                        &cancellation,
                        "start-work",
                        json!({"value": 7}),
                    )
                    .await
                    .unwrap();
                match (expected, outcome) {
                    ("complete", crate::FinalToolCallOutcome::Complete(result)) => {
                        assert!(!result.payload.is_error);
                    }
                    ("task", crate::FinalToolCallOutcome::Task(created)) => {
                        assert_eq!(created.task.base().task_id.as_str(), "wait-task");
                        assert_eq!(created.additional["x-call"], json!({"retained": true}));
                        let receipt = serde_json::to_vec(&created).unwrap();
                        let handle = FinalTaskHandle::from_created(&created).unwrap();
                        assert!(matches!(handle.task(), FinalTask::Working(_)));
                        assert_eq!(serde_json::to_vec(&created).unwrap(), receipt);
                    }
                    ("input_required", crate::FinalToolCallOutcome::InputRequired(_)) => {}
                    _ => panic!("the Task-capable HTTP call changed the peer's outcome"),
                }
                assert!(cx.checkpoint().is_ok());
                assert!(!cancellation.is_cancel_requested());
                client.list_tools(&cx, None).await.unwrap();
            });
        peer.join().unwrap();
    }
}

#[test]
fn public_http_task_creating_call_refuses_absent_negotiation_and_precancellation_without_ids() {
    for cancelled in [false, true] {
        let mut advertised = discovery();
        if !cancelled {
            advertised["result"]["capabilities"]
                .as_object_mut()
                .unwrap()
                .remove("extensions");
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = format!("http://{}/mcp", listener.local_addr().unwrap());
        let peer = std::thread::spawn(move || {
            let mut discover = accept(&listener);
            let request = read(&mut discover);
            assert_eq!(request["method"], "server/discover");
            assert_eq!(request["id"], 1);
            write(&mut discover, &advertised).unwrap();
            drop(discover);

            let mut sibling = accept(&listener);
            let request = read(&mut sibling);
            assert_eq!(
                request["method"], "tools/list",
                "a refused Task-creating call must not publish tool effects",
            );
            assert_eq!(request["id"], 2, "refusal must precede ID allocation");
            write(
                &mut sibling,
                &json!({"jsonrpc": "2.0", "id": 2, "result": {
                    "resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private"
                }}),
            )
            .unwrap();
        });
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let mut client = HttpClient::connect(
                    &cx,
                    plan(&target),
                    ClientInfo {
                        name: "task-refusal-http-client".to_owned(),
                        version: "1".to_owned(),
                    },
                    ClientCapabilities::default(),
                )
                .await
                .unwrap();
                let cancellation = McpRequestCancellation::new();
                if cancelled {
                    cancellation.cancel();
                }
                let result = client
                    .call_tool_final_outcome_with_cancellation(
                        &cx,
                        &cancellation,
                        "start-work",
                        json!({}),
                    )
                    .await;
                let Err(HttpClientError::CoreResult(error)) = result else {
                    panic!("Task negotiation and local cancellation must refuse before transport");
                };
                assert_eq!(
                    error.code,
                    if cancelled {
                        fastmcp_core::McpErrorCode::RequestCancelled
                    } else {
                        fastmcp_core::McpErrorCode::InvalidParams
                    },
                );
                assert!(cx.checkpoint().is_ok());
                client.list_tools(&cx, None).await.unwrap();
            });
        peer.join().unwrap();
    }
}
