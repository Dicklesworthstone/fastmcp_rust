//! Live transport coverage for caller-owned Task subscription watches.

use super::*;
use asupersync::runtime::RuntimeBuilder;
use fastmcp_protocol::{
    DiscoveryCacheHints, ServerBehavior, ServerBehaviorRegistry, ServerDiscoverCapabilities,
    ServerDiscoverResult, ServerInfo,
};
use serde_json::json;

const CREATED: &str = "2026-07-28T00:00:00Z";
const EXACT_RESULT: &str =
    r#"{"x-first":1.20e+4,"content":[],"x-zero":-0,"x-last":123456789012345678901234567890}"#;

fn discovery() -> String {
    let capabilities = ServerDiscoverCapabilities::from_registry(
        &ServerBehaviorRegistry::from_behaviors([
            ServerBehavior::ToolsList,
            ServerBehavior::ToolsListChangedNotification,
            ServerBehavior::SubscriptionsListen,
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
            name: "task-stream-peer".to_owned(),
            version: "1".to_owned(),
        },
        None,
        DiscoveryCacheHints::private_ttl_ms(0),
    );
    let mut response = json!({"jsonrpc":"2.0", "id":1, "result":result});
    response["result"]["supportedVersions"] = json!([crate::MODERN_PROTOCOL_VERSION]);
    response.to_string()
}

fn live_ttl(seconds: u64) -> u64 {
    let created = fastmcp_protocol::TaskTimestamp::parse(CREATED).unwrap();
    let remaining = wall_now_nanos() - timestamp_nanos(&created).unwrap();
    u64::try_from(remaining / 1_000_000).unwrap() + seconds * 1_000
}

fn task(status: &str, ttl: Option<u64>, updated_second: u8) -> String {
    let ttl = ttl.map_or_else(|| "null".to_owned(), |value| value.to_string());
    let result = if status == "completed" {
        format!(r#", "result":{EXACT_RESULT}"#)
    } else {
        String::new()
    };
    format!(
        r#"{{"taskId":"stream-task","status":"{status}","createdAt":"{CREATED}","lastUpdatedAt":"2026-07-28T00:00:{updated_second:02}Z","ttlMs":{ttl}{result}}}"#
    )
}

fn response(id: i64, task: &str) -> String {
    let result = format!(r#"{{"resultType":"complete",{}"#, &task[1..]);
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#)
}

fn notification(id: i64, task: &str) -> String {
    let params = format!(
        r#"{{"_meta":{{"io.modelcontextprotocol/subscriptionId":{id}}},"diagnostic":{{"opaque":true}},{}"#,
        &task[1..]
    );
    format!(r#"{{"jsonrpc":"2.0","method":"notifications/tasks","params":{params}}}"#)
}

fn ack(id: i64, tasks: serde_json::Value) -> String {
    json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged", "params":{
        "_meta":{"io.modelcontextprotocol/subscriptionId":id}, "notifications":{"taskIds":tasks}
    }})
    .to_string()
}

fn completion(id: i64) -> String {
    json!({"jsonrpc":"2.0", "id":id, "result":{
        "resultType":"complete", "_meta":{"io.modelcontextprotocol/subscriptionId":id}
    }})
    .to_string()
}

fn assert_completed(task: &FinalTask) {
    let FinalTask::Completed { result, .. } = task else {
        panic!("terminal completion expected")
    };
    assert_eq!(serde_json::to_string(result).unwrap(), EXACT_RESULT);
}

#[cfg(unix)]
mod stdio {
    use super::*;
    use crate::{
        ClientBuilder, ClientProtocolPlan, ProtocolPolicy, RequestTimeoutPolicy,
        StdioSubscriptionEvent,
    };

    const START: &str = r#"
IFS= read -r discover || exit 81
case "$discover" in *'"method":"server/discover"'*) ;; *) exit 82 ;; esac
printf '%s\n' "$1"
IFS= read -r attach || exit 83
case "$attach" in *'"id":2'*) ;; *) exit 84 ;; esac
"#;

    async fn connect(cx: &Cx, script: &str) -> (Client, FinalTaskHandle) {
        let mut client = ClientBuilder::new()
            .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
            .request_timeout_policy(
                RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(2)).unwrap(),
            )
            .connect_stdio_with_cx(cx, "sh", &["-c", script, "task-stream-peer", &discovery()])
            .await
            .unwrap();
        let handle = client
            .attach_final_task_with_cx(
                cx,
                &McpRequestCancellation::new(),
                FinalTaskId::parse("stream-task").unwrap(),
            )
            .await
            .unwrap();
        (client, handle)
    }

    #[test]
    fn public_stdio_task_stream_watch_renews_reconciles_and_preserves_completion() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let initial = task("working", Some(live_ttl(60)), 1);
                let renewed = task("working", Some(live_ttl(120)), 2);
                let ambiguous = task("working", None, 2);
                let authoritative =
                    task("working", None, 1).replace(CREATED, "2026-07-28T00:00:00+00:00");
                let completed = task("completed", None, 3);
                let script = format!(
                    r#"{START}
printf '%s\n' '{}'
IFS= read -r listen || exit 85
case "$listen" in *'"taskIds":["stream-task"]'*) ;; *) exit 86 ;; esac
printf '%s\n' '{}' '{}' '{}' '{}'
IFS= read -r reconcile || exit 87
case "$reconcile" in *'"method":"tasks/get"'*) ;; *) exit 88 ;; esac
case "$reconcile" in *'"id":4'*) ;; *) exit 89 ;; esac
printf '%s\n' '{}' '{}' '{}'
IFS= read -r cancel || exit 90
case "$cancel" in *'"method":"notifications/cancelled"'*) ;; *) exit 91 ;; esac
case "$cancel" in *'"requestId":3'*) ;; *) exit 92 ;; esac
IFS= read -r sibling || exit 93
case "$sibling" in *'"id":5'*) ;; *) exit 94 ;; esac
printf '%s\n' '{}'
exec sleep 10
"#,
                    response(2, &initial),
                    ack(3, json!(["stream-task", "stream-task"])),
                    notification(3, &renewed),
                    notification(3, &renewed),
                    notification(3, &ambiguous),
                    response(4, &authoritative),
                    notification(3, &completed),
                    notification(3, &completed),
                    response(5, &task("cancelled", None, 4))
                );
                let (mut client, mut handle) = connect(&cx, &script).await;
                let live = McpRequestCancellation::new();
                let mut watch = handle
                    .watch_with_stdio(&cx, &mut client, &live)
                    .await
                    .unwrap();
                assert!(matches!(
                    watch.next_event(&cx, &live).await.unwrap(),
                    Some(FinalTaskWatchEvent::Acknowledged { .. })
                ));
                let Some(FinalTaskWatchEvent::TaskUpdated(renewed_event)) =
                    watch.next_event(&cx, &live).await.unwrap()
                else {
                    panic!("renewal is a live update")
                };
                assert_eq!(
                    serde_json::to_value(renewed_event).unwrap()["params"]["diagnostic"],
                    json!({"opaque":true})
                );
                assert!(watch.task().base().ttl_ms.is_some());
                let Some(FinalTaskWatchEvent::TaskReconciled {
                    observed,
                    authoritative,
                }) = watch.next_event(&cx, &live).await.unwrap()
                else {
                    panic!("one duplicate is skipped before the ambiguous update")
                };
                assert!(observed.params.task.base().ttl_ms.is_none());
                assert!(authoritative.base().ttl_ms.is_none());
                assert_eq!(
                    authoritative.base().created_at.as_str(),
                    "2026-07-28T00:00:00+00:00"
                );
                assert!(matches!(
                    watch.next_event(&cx, &live).await.unwrap(),
                    Some(FinalTaskWatchEvent::TaskUpdated(_))
                ));
                assert_completed(watch.task());
                assert_eq!(watch.stop_reason(), Some(FinalTaskWaitOutcome::Completed));
                assert!(watch.next_event(&cx, &live).await.unwrap().is_none());
                drop(watch);
                let mut terminal_watch = handle
                    .watch_with_stdio(&cx, &mut client, &live)
                    .await
                    .unwrap();
                assert!(
                    terminal_watch
                        .next_event(&cx, &live)
                        .await
                        .unwrap()
                        .is_none()
                );
                drop(terminal_watch);
                client
                    .get_task_final_with_cx(&cx, &live, handle.task_id().clone())
                    .await
                    .unwrap();
                assert_completed(handle.task());
                client.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn public_stdio_task_stream_watch_cancel_and_drop_preserve_catalog_and_next_request() {
        RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            for cancel in [true, false] {
                let script = format!(r#"{START}
printf '%s\n' '{}'
IFS= read -r catalog || exit 85
case "$catalog" in *'"id":3'*) ;; *) exit 86 ;; esac
printf '%s\n' '{{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{{"_meta":{{"io.modelcontextprotocol/subscriptionId":3}},"notifications":{{"toolsListChanged":true}}}}}}'
IFS= read -r tasks || exit 87
case "$tasks" in *'"id":4'*) ;; *) exit 88 ;; esac
printf '%s\n' '{}'
IFS= read -r cancel || exit 89
case "$cancel" in *'"method":"notifications/cancelled"'*) ;; *) exit 90 ;; esac
case "$cancel" in *'"requestId":4'*) ;; *) exit 91 ;; esac
IFS= read -r sibling || exit 92
case "$sibling" in *'"id":5'*) ;; *) exit 93 ;; esac
printf '%s\n' '{{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{{"_meta":{{"io.modelcontextprotocol/subscriptionId":3}}}}}}' '{}' '{}'
exec sleep 10
"#, response(2, &task("working", None, 1)), ack(4, json!(["stream-task"])), completion(3), response(5, &task("cancelled", None, 2)));
                let (mut client, mut handle) = connect(&cx, &script).await;
                let live = McpRequestCancellation::new();
                client.open_subscriptions_listener_with_cx(&cx, &live, SubscriptionFilter { tools_list_changed: Some(true), ..SubscriptionFilter::default() }).await.unwrap();
                let before = serde_json::to_vec(handle.task()).unwrap();
                let observing = McpRequestCancellation::new();
                let mut watch = handle.watch_with_stdio(&cx, &mut client, &observing).await.unwrap();
                assert!(matches!(watch.next_event(&cx, &observing).await.unwrap(), Some(FinalTaskWatchEvent::Acknowledged { .. })));
                let mut pending = Box::pin(watch.next_event(&cx, &observing));
                assert!(std::future::poll_fn(|context| Poll::Ready(pending.as_mut().poll(context))).await.is_pending());
                if cancel {
                    observing.cancel();
                    assert!(pending.await.unwrap().is_none());
                    assert_eq!(watch.stop_reason(), Some(FinalTaskWaitOutcome::ObservationCancelled));
                } else {
                    drop(pending);
                }
                drop(watch);
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                client.get_task_final_with_cx(&cx, &live, handle.task_id().clone()).await.unwrap();
                assert!(matches!(client.next_subscription_event_with_cx(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Acknowledged(_)));
                assert!(matches!(client.next_subscription_event_with_cx(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Notification(_)));
                assert!(matches!(client.next_subscription_event_with_cx(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Terminal));
                client.close_with_cx(&cx).await.unwrap();
            }
        });
    }

    #[test]
    fn public_stdio_task_stream_watch_accepts_empty_subset_and_refuses_rewritten_creation() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                for empty in [true, false] {
                    let initial = task("working", None, 1);
                    let forged = task("working", None, 2).replace(CREATED, "2026-07-28T00:00:01Z");
                    let script = format!(
                        r#"{START}
printf '%s\n' '{}'
IFS= read -r listen || exit 85
printf '%s\n' '{}'
{}
IFS= read -r cancel || exit 86
case "$cancel" in *'"requestId":3'*) ;; *) exit 87 ;; esac
IFS= read -r sibling || exit 88
case "$sibling" in *'"id":4'*) ;; *) exit 89 ;; esac
printf '%s\n' '{}'
exec sleep 10
"#,
                        response(2, &initial),
                        ack(
                            3,
                            if empty {
                                json!([])
                            } else {
                                json!(["stream-task"])
                            }
                        ),
                        if empty {
                            String::new()
                        } else {
                            format!("printf '%s\\n' '{}'", notification(3, &forged))
                        },
                        response(4, &task("cancelled", None, 3))
                    );
                    let (mut client, mut handle) = connect(&cx, &script).await;
                    let live = McpRequestCancellation::new();
                    let before = serde_json::to_vec(handle.task()).unwrap();
                    let mut watch = handle
                        .watch_with_stdio(&cx, &mut client, &live)
                        .await
                        .unwrap();
                    assert!(matches!(
                        watch.next_event(&cx, &live).await.unwrap(),
                        Some(FinalTaskWatchEvent::Acknowledged { .. })
                    ));
                    if empty {
                        assert!(watch.next_event(&cx, &live).await.unwrap().is_none());
                    } else {
                        assert_eq!(
                            watch.next_event(&cx, &live).await.unwrap_err().code,
                            fastmcp_core::McpErrorCode::InvalidRequest
                        );
                    }
                    drop(watch);
                    assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                    client
                        .get_task_final_with_cx(&cx, &live, handle.task_id().clone())
                        .await
                        .unwrap();
                    client.close_with_cx(&cx).await.unwrap();
                }
            });
    }
}

#[cfg(feature = "websocket-experimental")]
mod websocket {
    use super::*;
    use crate::{
        AsyncWsClientTransport, ClientBuilder, ClientProtocolPlan, ProtocolPolicy,
        RequestTimeoutPolicy, StdioSubscriptionEvent, SubscriptionTimeoutPolicy, TransportError,
    };
    use asupersync::io::AsyncWriteExt;
    use asupersync::net::tcp::VirtualTcpStream;
    use fastmcp_protocol::JsonRpcMessage;
    use fastmcp_transport::websocket::AsyncWsServerTransport;

    async fn frame(peer: &mut VirtualTcpStream, source: &str) {
        let payload = source.as_bytes();
        let mut bytes = vec![0x81];
        if payload.len() <= 125 {
            bytes.push(u8::try_from(payload.len()).unwrap());
        } else {
            bytes.push(126);
            bytes.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        }
        bytes.extend_from_slice(payload);
        peer.write_all(&bytes).await.unwrap();
    }

    async fn connect(
        cx: &Cx,
        initial: &str,
    ) -> (
        WebSocketClient<VirtualTcpStream>,
        FinalTaskHandle,
        VirtualTcpStream,
    ) {
        let (client_io, mut peer) = VirtualTcpStream::pair(
            "127.0.0.1:45201".parse().unwrap(),
            "127.0.0.1:45202".parse().unwrap(),
        );
        frame(&mut peer, &discovery()).await;
        frame(&mut peer, &response(2, initial)).await;
        let mut client = ClientBuilder::new()
            .protocol_plan(ClientProtocolPlan::websocket(ProtocolPolicy::ModernOnly))
            .request_timeout_policy(
                RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(2)).unwrap(),
            )
            .subscription_timeout_policy(
                SubscriptionTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(3))
                    .unwrap(),
            )
            .connect_websocket_with_cx(cx, AsyncWsClientTransport::from_upgraded(client_io))
            .await
            .unwrap();
        let handle = client
            .attach_final_task(
                cx,
                &McpRequestCancellation::new(),
                FinalTaskId::parse("stream-task").unwrap(),
            )
            .await
            .unwrap();
        (client, handle, peer)
    }

    async fn finish(
        cx: &Cx,
        client: &mut WebSocketClient<VirtualTcpStream>,
        mut peer: VirtualTcpStream,
        expected: &[(&str, Option<i64>, Option<i64>)],
    ) {
        let next_id = client.next_id;
        frame(&mut peer, &format!(r#"{{"jsonrpc":"2.0","id":{next_id},"result":{{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}}}"#)).await;
        client.list_tools(cx, None).await.unwrap();
        client.close(cx).await.unwrap();
        let mut peer = AsyncWsServerTransport::from_upgraded(peer);
        for (method, request_id, cancelled_id) in expected {
            let JsonRpcMessage::Request(request) = peer.recv(cx).await.unwrap() else {
                panic!("unexpected client response")
            };
            assert_eq!(request.method.as_str(), *method);
            assert_eq!(request.id, request_id.map(RequestId::Number));
            if let Some(id) = cancelled_id {
                assert_eq!(request.params.as_ref().unwrap()["requestId"], json!(id));
            }
            if *method == "subscriptions/listen" && *request_id == Some(3) && cancelled_id.is_none()
            {
                // The lifecycle fixture has no catalog listener.
                if let Some(ids) = request.params.as_ref().unwrap()["notifications"].get("taskIds")
                {
                    assert_eq!(ids, &json!(["stream-task"]));
                }
            }
        }
        assert!(
            matches!(peer.recv(cx).await, Err(TransportError::Closed)),
            "no implicit Task update, cancellation or retry follows"
        );
    }

    #[test]
    fn public_websocket_task_stream_watch_renews_reconciles_and_preserves_completion() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let initial = task("working", Some(live_ttl(60)), 1);
                let renewed = task("working", Some(live_ttl(120)), 2);
                let (mut client, mut handle, mut peer) = connect(&cx, &initial).await;
                for source in [
                    ack(3, json!(["stream-task", "stream-task"])),
                    notification(3, &renewed),
                    notification(3, &renewed),
                    notification(3, &task("working", None, 2)),
                    response(
                        4,
                        &task("working", None, 1).replace(CREATED, "2026-07-28T00:00:00+00:00"),
                    ),
                    notification(3, &task("completed", None, 3)),
                    notification(3, &task("completed", None, 3)),
                ] {
                    frame(&mut peer, &source).await;
                }
                let live = McpRequestCancellation::new();
                let mut watch = handle
                    .watch_with_websocket(&cx, &mut client, &live)
                    .await
                    .unwrap();
                assert!(matches!(
                    watch.next_event(&cx, &live).await.unwrap(),
                    Some(FinalTaskWatchEvent::Acknowledged { .. })
                ));
                assert!(matches!(
                    watch.next_event(&cx, &live).await.unwrap(),
                    Some(FinalTaskWatchEvent::TaskUpdated(_))
                ));
                assert!(watch.task().base().ttl_ms.is_some());
                let Some(FinalTaskWatchEvent::TaskReconciled {
                    observed,
                    authoritative,
                }) = watch.next_event(&cx, &live).await.unwrap()
                else {
                    panic!("one conflict must produce one authoritative event")
                };
                assert!(observed.params.task.base().ttl_ms.is_none());
                assert!(authoritative.base().ttl_ms.is_none());
                assert_eq!(
                    authoritative.base().created_at.as_str(),
                    "2026-07-28T00:00:00+00:00"
                );
                let Some(FinalTaskWatchEvent::TaskUpdated(completed)) =
                    watch.next_event(&cx, &live).await.unwrap()
                else {
                    panic!("terminal event")
                };
                assert_completed(&completed.params.task);
                assert_eq!(
                    serde_json::to_value(completed).unwrap()["params"]["diagnostic"],
                    json!({"opaque":true})
                );
                assert_completed(watch.task());
                assert_eq!(watch.stop_reason(), Some(FinalTaskWaitOutcome::Completed));
                assert!(watch.next_event(&cx, &live).await.unwrap().is_none());
                drop(watch);
                let mut terminal_watch = handle
                    .watch_with_websocket(&cx, &mut client, &live)
                    .await
                    .unwrap();
                assert!(
                    terminal_watch
                        .next_event(&cx, &live)
                        .await
                        .unwrap()
                        .is_none()
                );
                drop(terminal_watch);
                finish(
                    &cx,
                    &mut client,
                    peer,
                    &[
                        ("server/discover", Some(1), None),
                        ("tasks/get", Some(2), None),
                        ("subscriptions/listen", Some(3), None),
                        ("tasks/get", Some(4), None),
                        ("notifications/cancelled", None, Some(3)),
                        ("tools/list", Some(5), None),
                    ],
                )
                .await;
                assert_completed(handle.task());
            });
    }

    #[test]
    fn public_websocket_task_stream_watch_cancel_and_drop_isolate_owned_requests() {
        RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            for mode in ["cancel", "drop", "drop-reconciliation"] {
                let (mut client, mut handle, mut peer) = connect(&cx, &task("working", None, 1)).await;
                client.open_subscriptions_listener(&cx, SubscriptionFilter { tools_list_changed: Some(true), ..SubscriptionFilter::default() }).await.unwrap();
                frame(&mut peer, r#"{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":3},"notifications":{"toolsListChanged":true}}}"#).await;
                frame(&mut peer, &ack(4, json!(["stream-task"]))).await;
                if mode == "drop-reconciliation" {
                    let ambiguous = task("working", Some(live_ttl(60)), 1);
                    frame(&mut peer, &notification(4, &ambiguous)).await;
                }
                let live = McpRequestCancellation::new();
                let observing = McpRequestCancellation::new();
                let before = serde_json::to_vec(handle.task()).unwrap();
                let mut watch = handle.watch_with_websocket(&cx, &mut client, &observing).await.unwrap();
                assert!(matches!(watch.next_event(&cx, &observing).await.unwrap(), Some(FinalTaskWatchEvent::Acknowledged { .. })));
                let mut pending = Box::pin(watch.next_event(&cx, &observing));
                assert!(std::future::poll_fn(|context| Poll::Ready(pending.as_mut().poll(context))).await.is_pending());
                if mode == "cancel" {
                    observing.cancel();
                    assert!(pending.await.unwrap().is_none());
                    assert_eq!(watch.stop_reason(), Some(FinalTaskWaitOutcome::ObservationCancelled));
                } else {
                    drop(pending);
                }
                drop(watch);
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                let mut trace = vec![
                    ("server/discover", Some(1), None), ("tasks/get", Some(2), None),
                    ("subscriptions/listen", Some(3), None), ("subscriptions/listen", Some(4), None),
                ];
                if mode == "drop-reconciliation" {
                    trace.extend([("tasks/get", Some(5), None), ("notifications/cancelled", None, Some(5))]);
                    frame(&mut peer, &response(5, &task("completed", None, 2))).await;
                }
                trace.push(("notifications/cancelled", None, Some(4)));
                frame(&mut peer, r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":3}}}"#).await;
                frame(&mut peer, &completion(3)).await;
                // Driving the catalog retires only the abandoned Task owners,
                // then delivers the independent catalog acknowledgement/data.
                assert!(matches!(client.next_subscription_event(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Acknowledged(_)));
                assert!(matches!(client.next_subscription_event(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Notification(_)));
                assert!(matches!(client.next_subscription_event(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Terminal));
                trace.push(("tools/list", Some(if mode == "drop-reconciliation" { 6 } else { 5 }), None));
                finish(&cx, &mut client, peer, &trace).await;
            }
        });
    }

    #[test]
    fn public_websocket_task_stream_watch_empty_completion_and_identity_admission() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                for mode in [
                    "empty",
                    "completed-listen",
                    "changed-creation",
                    "cancelled-before-open",
                    "expired-before-open",
                    "expires-during-watch",
                ] {
                    let initial = task(
                        "working",
                        match mode {
                            "expired-before-open" => Some(1),
                            "expires-during-watch" => Some(live_ttl(1)),
                            _ => None,
                        },
                        1,
                    );
                    let (mut client, mut handle, mut peer) = connect(&cx, &initial).await;
                    let observing = McpRequestCancellation::new();
                    if mode == "cancelled-before-open" {
                        observing.cancel();
                    }
                    let before = serde_json::to_vec(handle.task()).unwrap();
                    let mut trace = vec![
                        ("server/discover", Some(1), None),
                        ("tasks/get", Some(2), None),
                    ];
                    let opens = !mode.ends_with("before-open");
                    if opens {
                        frame(
                            &mut peer,
                            &ack(
                                3,
                                if mode == "empty" {
                                    json!([])
                                } else {
                                    json!(["stream-task"])
                                },
                            ),
                        )
                        .await;
                        trace.push(("subscriptions/listen", Some(3), None));
                        if mode == "changed-creation" {
                            frame(
                                &mut peer,
                                &notification(
                                    3,
                                    &task("working", None, 2)
                                        .replace(CREATED, "2026-07-28T00:00:01Z"),
                                ),
                            )
                            .await;
                        }
                        if mode == "completed-listen" {
                            frame(&mut peer, &completion(3)).await;
                        }
                    }
                    let mut watch = handle
                        .watch_with_websocket(&cx, &mut client, &observing)
                        .await
                        .unwrap();
                    if opens {
                        assert!(matches!(
                            watch.next_event(&cx, &observing).await.unwrap(),
                            Some(FinalTaskWatchEvent::Acknowledged { .. })
                        ));
                    }
                    if mode == "changed-creation" {
                        assert_eq!(
                            watch.next_event(&cx, &observing).await.unwrap_err().code,
                            fastmcp_core::McpErrorCode::InvalidRequest
                        );
                    } else {
                        assert!(watch.next_event(&cx, &observing).await.unwrap().is_none());
                    }
                    if !opens || mode == "expires-during-watch" {
                        assert_eq!(
                            watch.stop_reason(),
                            Some(if mode.contains("expire") {
                                FinalTaskWaitOutcome::TaskExpired
                            } else {
                                FinalTaskWaitOutcome::ObservationCancelled
                            })
                        );
                    }
                    drop(watch);
                    assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                    if opens && mode != "completed-listen" {
                        trace.push(("notifications/cancelled", None, Some(3)));
                    }
                    trace.push(("tools/list", Some(if opens { 4 } else { 3 }), None));
                    finish(&cx, &mut client, peer, &trace).await;
                }
            });
    }

    #[test]
    fn public_websocket_dropped_task_watch_cannot_deliver_a_queued_terminal_owner() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let (mut client, mut handle, mut peer) =
                    connect(&cx, &task("working", None, 1)).await;
                let live = McpRequestCancellation::new();
                for source in [
                    ack(3, json!(["stream-task"])),
                    notification(3, &task("working", Some(live_ttl(60)), 1)),
                    completion(3),
                    response(4, &task("working", None, 2)),
                ] {
                    frame(&mut peer, &source).await;
                }
                let mut watch = handle
                    .watch_with_websocket(&cx, &mut client, &live)
                    .await
                    .unwrap();
                assert!(matches!(
                    watch.next_event(&cx, &live).await.unwrap(),
                    Some(FinalTaskWatchEvent::Acknowledged { .. })
                ));
                assert!(matches!(
                    watch.next_event(&cx, &live).await.unwrap(),
                    Some(FinalTaskWatchEvent::TaskReconciled { .. })
                ));
                drop(watch);
                let error = client
                    .next_final_task_subscription_event(&cx, &live)
                    .await
                    .expect_err("the dropped watch's queued terminal must not regain an observer");
                assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidRequest);
                assert!(client.live_task_subscription.is_none());
                finish(
                    &cx,
                    &mut client,
                    peer,
                    &[
                        ("server/discover", Some(1), None),
                        ("tasks/get", Some(2), None),
                        ("subscriptions/listen", Some(3), None),
                        ("tasks/get", Some(4), None),
                        ("notifications/cancelled", None, Some(3)),
                        ("tools/list", Some(5), None),
                    ],
                )
                .await;
            });
    }
}
