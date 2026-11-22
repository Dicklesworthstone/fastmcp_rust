//! Native gateway Tasks creation, controls, status ownership and exact results.

use super::*;
use asupersync::io::AsyncWriteExt;
use fastmcp_core::{AuthContext, ClientCapabilityInfo, Outcome, SessionState};
use fastmcp_protocol::{FinalTaskId, Task, set_task_subscription_ids, task_subscription_ids};

use crate::handler::{FinalToolOutcome, ToolHandler};
use crate::proxy::{
    ProxyClient, ProxyFinalTaskListenerEvent, ProxyTaskRetentionPolicy, ProxyToolHandler,
    ProxyUpstreamAdapter, ProxyUpstreamBinding,
};

const EXACT_RESULT: &str =
    r#"{"x-first":1.20e+4,"content":[],"x-zero":-0,"x-last":123456789012345678901234567890}"#;

async fn frame(peer: &mut VirtualTcpStream, source: &str) {
    let bytes = source.as_bytes();
    let mut frame = vec![0x81];
    if bytes.len() <= 125 {
        frame.push(u8::try_from(bytes.len()).unwrap());
    } else {
        frame.push(126);
        frame.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
    }
    frame.extend_from_slice(bytes);
    peer.write_all(&frame).await.unwrap();
}

fn discovery(tasks: bool) -> String {
    let mut capabilities = json!({"tools": {}});
    if tasks {
        capabilities["extensions"] = json!({"io.modelcontextprotocol/tasks": {}});
    }
    json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {
            "resultType": "complete", "supportedVersions": ["2026-07-28"],
            "capabilities": capabilities, "ttlMs": 0, "cacheScope": "private",
            "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "upstream", "version": "1"}}
        }
    })
    .to_string()
}

fn task(timestamp: &str, status: &str) -> String {
    let extra = match status {
        "input_required" => r#", "inputRequests":{"roots":{"method":"roots/list"}}"#.to_owned(),
        "completed" => format!(r#", "result":{EXACT_RESULT}"#),
        _ => String::new(),
    };
    format!(
        r#"{{"taskId":"upstream-only","status":"{status}","createdAt":"{timestamp}","lastUpdatedAt":"{timestamp}","ttlMs":600000{extra}}}"#
    )
}

fn task_response(id: u64, kind: &str, task: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"result":{{"resultType":"{kind}",{} }} }}"#,
        &task[1..task.len() - 1]
    )
}

fn acknowledgement(id: u64, filter: &SubscriptionFilter) -> String {
    json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged",
        "params":{"notifications":filter,"_meta":{"io.modelcontextprotocol/subscriptionId":id}}})
    .to_string()
}

fn status_notification(id: u64, task: &str) -> String {
    let params = format!(
        r#"{{"_meta":{{"io.modelcontextprotocol/subscriptionId":{id}}},{}"#,
        &task[1..]
    );
    format!(r#"{{"jsonrpc":"2.0","method":"notifications/tasks","params":{params}}}"#)
}

fn task_filter(id: FinalTaskId) -> SubscriptionFilter {
    let mut filter = SubscriptionFilter::default();
    set_task_subscription_ids(&mut filter, vec![id]).unwrap();
    filter
}

fn context(cx: &Cx, owner: &str) -> McpContext {
    McpContext::with_state(cx.clone(), 1, SessionState::new())
        .with_auth(AuthContext::with_subject(owner))
        .with_client_capabilities(ClientCapabilityInfo::new().with_tasks().with_roots(false))
}

async fn connect(cx: &Cx, tasks: bool) -> (WebSocketClient<VirtualTcpStream>, VirtualTcpStream) {
    let (io, mut peer) = VirtualTcpStream::pair(
        "127.0.0.1:45201".parse().unwrap(),
        "127.0.0.1:45202".parse().unwrap(),
    );
    frame(&mut peer, &discovery(tasks)).await;
    let client = WebSocketClient::connect_with_cx(
        cx,
        ClientProtocolPlan::websocket(ProtocolPolicy::ModernOnly),
        ClientInfo {
            name: "gateway".to_owned(),
            version: "1".to_owned(),
        },
        ClientCapabilities::default(),
        AsyncWsClientTransport::from_upgraded(io),
    )
    .await
    .unwrap();
    (client, peer)
}

fn retained_proxy(
    client: WebSocketClient<VirtualTcpStream>,
) -> (ProxyClient, ProxyWebSocketClient<VirtualTcpStream>) {
    let backend = ProxyWebSocketClient::new(client).unwrap();
    let proxy = ProxyClient::from_backend_with_upstream_binding(
        backend.clone(),
        ProxyUpstreamBinding {
            era: ProtocolEra::Modern2026,
            adapter: ProxyUpstreamAdapter::ModernWebSocket,
            policy: ProtocolPolicy::ModernOnly,
            configuration_generation: 1,
        },
        "2026-07-28",
    )
    .unwrap()
    .with_task_retention_policy(
        ProxyTaskRetentionPolicy::new(Duration::from_secs(3600), Duration::from_secs(3600))
            .unwrap(),
    )
    .unwrap();
    (proxy, backend)
}

struct Access;

impl crate::TaskAccessAuthorizer for Access {
    fn authorize(
        &self,
        _ctx: &McpContext,
        _action: crate::TaskAccessAction,
        _original: &crate::FinalTaskOperation,
    ) -> McpResult<()> {
        Ok(())
    }
}

async fn receive(
    cx: &Cx,
    peer: &mut AsyncWsServerTransport<VirtualTcpStream>,
    method: &str,
    id: Option<i64>,
) -> fastmcp_protocol::JsonRpcRequest {
    let JsonRpcMessage::Request(request) = peer.recv(cx).await.unwrap() else {
        panic!("expected request")
    };
    assert_eq!(request.method, method);
    assert_eq!(request.id, id.map(RequestId::Number));
    request
}

#[test]
fn websocket_tasks_proxy_operation_deadline_cancels_ack_and_stream_waits() {
    run(|cx| async move {
        for acknowledged in [false, true] {
            let (client, mut peer) = connect(&cx, true).await;
            let (proxy, backend) = retained_proxy(client);
            let ctx = context(&cx, "owner")
                .with_operation_deadline(Some(cx.now().saturating_add_nanos(100_000_000)));
            let filter = task_filter(FinalTaskId::parse("upstream-only").unwrap());
            if acknowledged {
                frame(&mut peer, &acknowledgement(2, &filter)).await;
            }
            let mut listener = proxy
                .open_final_task_listener_async(&ctx, filter)
                .await
                .unwrap();
            let cancellation = McpRequestCancellation::new();
            if acknowledged {
                assert!(matches!(
                    listener.next_async(&cx, &cancellation).await.unwrap(),
                    ProxyFinalTaskListenerEvent::Acknowledged(_)
                ));
            }
            assert_eq!(
                listener
                    .next_async(&cx, &cancellation)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::RequestCancelled,
                "the MCP deadline interrupts a silent native listener"
            );
            assert!(cx.now() >= ctx.budget().deadline.unwrap());
            assert!(cx.checkpoint().is_ok());
            assert!(!cancellation.is_cancel_requested());
            assert!(!ctx.request_cancellation().is_cancel_requested());
            drop(listener);
            frame(&mut peer, r#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#).await;
            proxy.catalog_typed_with_cx(&cx).await.unwrap();
            backend.close(&cx).await.unwrap();
            let mut peer = AsyncWsServerTransport::from_upgraded(peer);
            receive(&cx, &mut peer, "server/discover", Some(1)).await;
            receive(&cx, &mut peer, "subscriptions/listen", Some(2)).await;
            let cancelled = receive(&cx, &mut peer, "notifications/cancelled", None).await;
            assert_eq!(cancelled.params.unwrap()["requestId"], 2);
            receive(&cx, &mut peer, "tools/list", Some(3)).await;
        }
    });
}

#[test]
fn websocket_tasks_proxy_retains_both_request_and_listener_cancellation() {
    run(|cx| async move {
        for managed in [false, true] {
            for cancel_opening_request in [false, true] {
                let (client, mut peer) = connect(&cx, true).await;
                let (proxy, backend) = retained_proxy(client);
                let opening_cancellation = McpRequestCancellation::new();
                let ctx =
                    context(&cx, "owner").with_request_cancellation(opening_cancellation.clone());
                let (ctx, lease) = if managed {
                    let (scoped, lease) = ctx.begin_request_scope().unwrap();
                    (scoped, Some(lease))
                } else {
                    (ctx, None)
                };
                let filter = task_filter(FinalTaskId::parse("upstream-only").unwrap());
                frame(&mut peer, &acknowledgement(2, &filter)).await;
                let mut listener = proxy
                    .open_final_task_listener_async(&ctx, filter)
                    .await
                    .unwrap();
                let listener_cancellation = McpRequestCancellation::new();
                assert!(matches!(
                    listener
                        .next_async(&cx, &listener_cancellation)
                        .await
                        .unwrap(),
                    ProxyFinalTaskListenerEvent::Acknowledged(_)
                ));
                {
                    let mut waiting = Box::pin(listener.next_async(&cx, &listener_cancellation));
                    assert!(
                        std::future::poll_fn(|task_cx| Poll::Ready(waiting.as_mut().poll(task_cx)))
                            .await
                            .is_pending()
                    );
                    let selected = if cancel_opening_request {
                        &opening_cancellation
                    } else {
                        &listener_cancellation
                    };
                    assert!(selected.cancel());
                    assert_eq!(
                        waiting.await.unwrap_err().code,
                        McpErrorCode::RequestCancelled
                    );
                }
                assert_eq!(
                    opening_cancellation.is_cancel_requested(),
                    cancel_opening_request
                );
                assert_eq!(
                    listener_cancellation.is_cancel_requested(),
                    !cancel_opening_request
                );
                assert_eq!(ctx.ensure_live().is_err(), cancel_opening_request);
                assert!(cx.checkpoint().is_ok());
                drop(listener);
                frame(&mut peer, r#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#).await;
                proxy.catalog_typed_with_cx(&cx).await.unwrap();
                backend.close(&cx).await.unwrap();
                drop(lease);
                let mut peer = AsyncWsServerTransport::from_upgraded(peer);
                receive(&cx, &mut peer, "server/discover", Some(1)).await;
                receive(&cx, &mut peer, "subscriptions/listen", Some(2)).await;
                let cancelled = receive(&cx, &mut peer, "notifications/cancelled", None).await;
                assert_eq!(cancelled.params.unwrap()["requestId"], 2);
                receive(&cx, &mut peer, "tools/list", Some(3)).await;
            }
        }
    });
}

#[test]
fn websocket_tasks_proxy_resumes_bound_inputs_into_a_task() {
    use crate::bidirectional::{
        MrtrExchangeBinding, MrtrExchangeRegistry, MrtrInputRequest, MrtrInputRequests, MrtrRetry,
    };

    run(|cx| async move {
        let (client, mut peer) = connect(&cx, true).await;
        let (proxy, backend) = retained_proxy(client);
        let relay = proxy.final_tasks_relay().unwrap().unwrap();
        relay
            .install_access_authorizers(vec![Arc::new(Access)])
            .unwrap();
        let ctx = context(&cx, "owner").with_client_implementation(
            fastmcp_core::ClientImplementationInfo::new("downstream-caller", "2"),
        );
        let handler = ProxyToolHandler::from_final_with_task_relay(
            serde_json::from_value(json!({"name":"work","inputSchema":{"type":"object"}})).unwrap(),
            proxy.clone(),
            Arc::clone(&relay),
        )
        .unwrap();
        frame(&mut peer, r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"input_required","requestState":"upstream-private-continuation","inputRequests":{"roots":{"method":"roots/list"}}}}"#).await;
        let Outcome::Ok(FinalToolOutcome::InputRequired(required)) = handler
            .call_final_outcome_async(&ctx, json!({"value":73}))
            .await
        else {
            panic!("first native round retains the upstream MRTR branch")
        };
        assert_eq!(
            required.request_state(),
            Some("upstream-private-continuation")
        );
        let registry = MrtrExchangeRegistry::new();
        let binding = MrtrExchangeBinding::new(
            "tools/call",
            "work".to_owned(),
            [7; 32],
            [9; 32],
            None,
            [11; 32],
        );
        let issued = registry
            .issue_bound(
                ctx.request_cancellation().clone(),
                binding.clone(),
                MrtrInputRequests::new([("roots".to_owned(), MrtrInputRequest::roots())]).unwrap(),
                required.request_state().map(str::to_owned),
            )
            .unwrap();
        let wire = serde_json::to_value(issued).unwrap();
        let state = wire["requestState"].as_str().unwrap();
        assert_ne!(state, "upstream-private-continuation");
        assert!(
            registry
                .accept_wire_bound(
                    state,
                    &binding,
                    &std::collections::BTreeMap::from([(
                        "roots".to_owned(),
                        json!({"action":"decline"})
                    )]),
                )
                .is_err()
        );
        assert_eq!(
            registry.active_len(),
            1,
            "wrong-kind input cannot consume the exchange"
        );
        let roots = json!({"roots":[{"uri":"file:///allowed","name":"allowed"}]});
        let MrtrRetry::Complete(resume) = registry
            .accept_wire_bound(
                state,
                &binding,
                &std::collections::BTreeMap::from([("roots".to_owned(), roots.clone())]),
            )
            .unwrap()
        else {
            panic!("typed retry completes the bound exchange")
        };
        assert_eq!(registry.active_len(), 0);
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        frame(
            &mut peer,
            &task_response(3, "task", &task(&timestamp, "working")),
        )
        .await;
        let Outcome::Ok(FinalToolOutcome::CreateTask {
            work_descriptor, ..
        }) = handler
            .call_final_outcome_async_resuming_in_request(
                &ctx,
                &cx,
                json!({"value":73}),
                Some(&resume),
            )
            .await
        else {
            panic!("resumed native call retains its Task branch")
        };
        let registration = Arc::new(());
        let admitted = relay
            .admit_carried_task_for_operation(
                &ctx,
                &work_descriptor,
                crate::FinalTaskOperation::for_tool("work", &registration).unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_ne!(admitted.task.base().task_id.as_str(), "upstream-only");
        assert_eq!(
            proxy.final_task_registry_snapshot_for_test().unwrap()["pendingCreations"],
            0
        );
        backend.close(&cx).await.unwrap();
        let mut peer = AsyncWsServerTransport::from_upgraded(peer);
        receive(&cx, &mut peer, "server/discover", Some(1)).await;
        let initial = receive(&cx, &mut peer, "tools/call", Some(2)).await;
        assert!(initial.params.unwrap().get("requestState").is_none());
        let resumed = receive(&cx, &mut peer, "tools/call", Some(3)).await;
        let params = resumed.params.unwrap();
        assert_eq!(params["requestState"], "upstream-private-continuation");
        assert_eq!(params["inputResponses"], json!({"roots":roots}));
        assert_eq!(params["arguments"], json!({"value":73}));
        assert_eq!(
            params["_meta"][fastmcp_protocol::FINAL_CLIENT_INFO_META_KEY]["name"],
            "downstream-caller"
        );
        assert_eq!(
            params["_meta"][fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
            json!({"io.modelcontextprotocol/tasks":{}})
        );
    });
}

#[test]
fn websocket_tasks_proxy_partial_open_cannot_append_another_request() {
    run(|cx| async move {
        for cancelled in [false, true] {
            let (io, mut peer) = VirtualTcpStream::pair(
                "127.0.0.1:45311".parse().unwrap(),
                "127.0.0.1:45312".parse().unwrap(),
            );
            frame(&mut peer, &discovery(true)).await;
            let gate = Arc::new(ControlGate::default());
            let client = WebSocketClient::connect_with_cx(
                &cx,
                ClientProtocolPlan::websocket(ProtocolPolicy::ModernOnly),
                ClientInfo {
                    name: "gateway".to_owned(),
                    version: "1".to_owned(),
                },
                ClientCapabilities::default(),
                AsyncWsClientTransport::from_upgraded(GatedIo {
                    inner: io,
                    gate: Arc::clone(&gate),
                }),
            )
            .await
            .unwrap();
            let proxy = ProxyClient::from_websocket(client, 1).unwrap();
            let ctx = context(&cx, "owner");
            let filter = task_filter(FinalTaskId::parse("upstream-only").unwrap());
            gate.armed.store(true, Ordering::Release);
            {
                let mut opening = Box::pin(proxy.open_final_task_listener_async(&ctx, filter));
                std::future::poll_fn(|task_cx| {
                    assert!(opening.as_mut().poll(task_cx).is_pending());
                    if gate.parked.load(Ordering::Acquire) {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                assert_eq!(gate.accepted.load(Ordering::Acquire), 1);
                if cancelled {
                    ctx.request_cancellation().cancel();
                    assert_eq!(
                        opening.await.err().unwrap().code,
                        McpErrorCode::RequestCancelled
                    );
                }
            }
            gate.release();
            assert!(
                proxy
                    .get_final_task(
                        &context(&cx, "owner"),
                        FinalTaskId::parse("upstream-only").unwrap(),
                    )
                    .await
                    .is_err(),
                "next operation retires the uncertain request writer"
            );
            assert!(proxy.catalog_typed_with_cx(&cx).await.is_err());
            let mut peer = AsyncWsServerTransport::from_upgraded(peer);
            receive(&cx, &mut peer, "server/discover", Some(1)).await;
            assert!(
                peer.recv(&cx).await.is_err(),
                "no frame follows the partial abandoned send"
            );
        }
    });
}

#[test]
fn websocket_tasks_proxy_lifecycle_maps_handles_and_preserves_exact_completed_result() {
    run(|cx| async move {
        let (client, mut peer) = connect(&cx, true).await;
        let (proxy, backend) = retained_proxy(client);
        let relay = proxy
            .final_tasks_relay()
            .unwrap()
            .expect("complete native Tasks relay");
        relay
            .install_access_authorizers(vec![Arc::new(Access)])
            .unwrap();
        let ctx = context(&cx, "owner");
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let input = task(&timestamp, "input_required");
        frame(&mut peer, &task_response(2, "task", &input)).await;
        let handler = ProxyToolHandler::from_final_with_task_relay(
            serde_json::from_value(json!({"name":"work", "inputSchema":{"type":"object"}}))
                .unwrap(),
            proxy.clone(),
            Arc::clone(&relay),
        )
        .unwrap();
        let Outcome::Ok(FinalToolOutcome::CreateTask {
            work_descriptor, ..
        }) = handler.call_final_outcome_async(&ctx, json!({})).await
        else {
            panic!("gateway Task creation must preserve upstream commitment")
        };
        let registration = Arc::new(());
        let created = relay
            .admit_carried_task_for_operation(
                &ctx,
                &work_descriptor,
                crate::FinalTaskOperation::for_tool("work", &registration).unwrap(),
            )
            .unwrap()
            .unwrap();
        let handle = created.task.base().task_id.clone();
        assert_ne!(handle.as_str(), "upstream-only");
        assert_eq!(handle.as_str().len(), 43);
        let params =
            json!({"taskId":handle,"_meta":FinalRequestMeta::new(ClientCapabilities::default())});
        let foreign = context(&cx, "other-owner");
        assert!(relay.dispatch_get(&foreign, params.clone()).await.is_err());
        assert!(
            relay
                .dispatch_cancel(&foreign, params.clone())
                .await
                .is_err()
        );
        assert!(
            relay
                .open_listener_async(&foreign, task_filter(handle.clone()))
                .await
                .is_err()
        );

        frame(&mut peer, &task_response(3, "complete", &input)).await;
        let snapshot = relay.dispatch_get(&ctx, params.clone()).await.unwrap();
        assert_eq!(snapshot.task.base().task_id, handle);
        let update = json!({"taskId":handle,"inputResponses":{"roots":{"roots":[]}},
            "_meta":FinalRequestMeta::new(ClientCapabilities::default())});
        assert!(
            relay
                .dispatch_update(&foreign, update.clone())
                .await
                .is_err()
        );
        frame(
            &mut peer,
            r#"{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete"}}"#,
        )
        .await;
        relay.dispatch_update(&ctx, update).await.unwrap();
        frame(
            &mut peer,
            r#"{"jsonrpc":"2.0","id":5,"result":{"resultType":"complete"}}"#,
        )
        .await;
        relay.dispatch_cancel(&ctx, params).await.unwrap();

        let upstream_filter = task_filter(FinalTaskId::parse("upstream-only").unwrap());
        frame(&mut peer, &acknowledgement(6, &upstream_filter)).await;
        let mut listener = relay
            .open_listener_async(&ctx, task_filter(handle.clone()))
            .await
            .unwrap();
        let cancellation = McpRequestCancellation::new();
        let ProxyFinalTaskListenerEvent::Acknowledged(filter) =
            listener.next_async(&cx, &cancellation).await.unwrap()
        else {
            panic!("one downstream acknowledgement")
        };
        assert_eq!(
            task_subscription_ids(&filter).unwrap().unwrap(),
            vec![handle.clone()]
        );
        let completed = task(&timestamp, "completed");
        frame(&mut peer, &status_notification(6, &completed)).await;
        // Differing status notifications are hints: the relay performs a fresh
        // route-authorized get before replacing the retained Task snapshot.
        frame(&mut peer, &task_response(7, "complete", &completed)).await;
        let ProxyFinalTaskListenerEvent::Notification(notification) =
            listener.next_async(&cx, &cancellation).await.unwrap()
        else {
            panic!("completed Task notification")
        };
        assert_eq!(notification.params.task.base().task_id, handle);
        let Task::Completed { result, .. } = notification.params.task else {
            panic!("completed Task")
        };
        assert_eq!(serde_json::to_string(&result).unwrap(), EXACT_RESULT);
        frame(&mut peer, r#"{"jsonrpc":"2.0","id":6,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":6}}}"#).await;
        assert!(matches!(
            listener.next_async(&cx, &cancellation).await.unwrap(),
            ProxyFinalTaskListenerEvent::Terminal
        ));
        drop(listener);
        frame(&mut peer, r#"{"jsonrpc":"2.0","id":8,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#).await;
        proxy.catalog_typed_with_cx(&cx).await.unwrap();
        backend.close(&cx).await.unwrap();

        let mut peer = AsyncWsServerTransport::from_upgraded(peer);
        for (method, id) in [
            ("server/discover", 1),
            ("tools/call", 2),
            ("tasks/get", 3),
            ("tasks/update", 4),
            ("tasks/cancel", 5),
            ("subscriptions/listen", 6),
            ("tasks/get", 7),
            ("tools/list", 8),
        ] {
            let request = receive(&cx, &mut peer, method, Some(id)).await;
            if matches!(method, "tasks/get" | "tasks/update" | "tasks/cancel") {
                assert_eq!(request.params.as_ref().unwrap()["taskId"], "upstream-only");
            }
            if (2..=7).contains(&id) {
                assert_eq!(
                    request.params.as_ref().unwrap()["_meta"]
                        [fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
                    json!({"io.modelcontextprotocol/tasks":{}})
                );
            }
        }
    });
}

#[test]
fn websocket_tasks_proxy_requires_upstream_support_and_explicit_retention() {
    run(|cx| async move {
        for supported in [false, true] {
            let (client, peer) = connect(&cx, supported).await;
            let proxy = ProxyClient::from_websocket(client, 1).unwrap();
            if supported {
                assert!(
                    proxy.final_tasks_relay().is_err(),
                    "retention ceiling is mandatory before task production"
                );
            } else {
                assert!(proxy.final_tasks_relay().unwrap().is_none());
            }
            let proxy = proxy
                .with_task_retention_policy(
                    ProxyTaskRetentionPolicy::new(
                        Duration::from_secs(3600),
                        Duration::from_secs(3600),
                    )
                    .unwrap(),
                )
                .unwrap();
            assert_eq!(proxy.final_tasks_relay().unwrap().is_some(), supported);
            let mut peer = AsyncWsServerTransport::from_upgraded(peer);
            receive(&cx, &mut peer, "server/discover", Some(1)).await;
        }
    });
}

#[test]
fn websocket_tasks_detached_owner_drop_preserves_sibling_catalog_and_connection() {
    run(|cx| async move {
        for abandon in [false, true] {
            let (client, mut peer) = connect(&cx, true).await;
            let (proxy, backend) = retained_proxy(client);
            let ctx = context(&cx, "owner");
            let catalog_filter = SubscriptionFilter {
                tools_list_changed: Some(true),
                ..SubscriptionFilter::default()
            };
            frame(&mut peer, &acknowledgement(2, &catalog_filter)).await;
            let mut catalog = proxy
                .open_catalog_listener_async(&ctx, catalog_filter)
                .await
                .unwrap();
            let cancellation = McpRequestCancellation::new();
            assert!(matches!(
                catalog.next_async(&cx, &cancellation).await.unwrap(),
                ProxyCatalogListenerEvent::Acknowledged(_)
            ));
            let filter = task_filter(FinalTaskId::parse("upstream-only").unwrap());
            frame(&mut peer, &acknowledgement(3, &filter)).await;
            let mut tasks = Some(
                proxy
                    .open_final_task_listener_async(&ctx, filter)
                    .await
                    .unwrap(),
            );
            assert!(matches!(
                tasks
                    .as_mut()
                    .unwrap()
                    .next_async(&cx, &cancellation)
                    .await
                    .unwrap(),
                ProxyFinalTaskListenerEvent::Acknowledged(_)
            ));
            if abandon {
                drop(tasks.take());
            }
            frame(&mut peer, r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":2}}}"#).await;
            if !abandon {
                let timestamp =
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                frame(
                    &mut peer,
                    &status_notification(3, &task(&timestamp, "working")),
                )
                .await;
            }
            frame(&mut peer, r#"{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#).await;
            proxy.catalog_typed_with_cx(&cx).await.unwrap();
            assert!(matches!(
                catalog.next_async(&cx, &cancellation).await.unwrap(),
                ProxyCatalogListenerEvent::Notification(_)
            ));
            if let Some(tasks) = tasks.as_mut() {
                assert!(matches!(
                    tasks.next_async(&cx, &cancellation).await.unwrap(),
                    ProxyFinalTaskListenerEvent::Notification(_)
                ));
            }
            backend.close(&cx).await.unwrap();
            let mut peer = AsyncWsServerTransport::from_upgraded(peer);
            receive(&cx, &mut peer, "server/discover", Some(1)).await;
            receive(&cx, &mut peer, "subscriptions/listen", Some(2)).await;
            receive(&cx, &mut peer, "subscriptions/listen", Some(3)).await;
            if abandon {
                let cancelled = receive(&cx, &mut peer, "notifications/cancelled", None).await;
                assert_eq!(cancelled.params.unwrap()["requestId"], 3);
            }
            receive(&cx, &mut peer, "tools/list", Some(4)).await;
        }
    });
}

#[test]
fn websocket_tasks_bounded_poll_releases_ingress_for_task_control() {
    run(|cx| async move {
        let (mut client, mut peer) = connect(&cx, true).await;
        let filter = task_filter(FinalTaskId::parse("upstream-only").unwrap());
        let mut capabilities = ClientCapabilities::default();
        capabilities.extensions = Some(std::collections::BTreeMap::from([(
            fastmcp_protocol::TASKS_EXTENSION.to_owned(),
            json!({}),
        )]));
        frame(&mut peer, &acknowledgement(2, &filter)).await;
        let owner = client
            .open_owned_final_task_subscription_listener(
                &cx,
                filter,
                FinalRequestMeta::new(capabilities),
            )
            .await
            .unwrap();
        let cancellation = McpRequestCancellation::new();
        assert!(
            client
                .poll_final_task_subscription_event(&cx, &cancellation)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            client
                .poll_final_task_subscription_event(&cx, &cancellation)
                .await
                .unwrap()
                .is_none(),
            "a silent listener must yield the sole connection before a control needs it"
        );
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        frame(
            &mut peer,
            &task_response(3, "complete", &task(&timestamp, "working")),
        )
        .await;
        let result = client
            .get_task_final(&cx, FinalTaskId::parse("upstream-only").unwrap())
            .await
            .unwrap();
        assert_eq!(result.task.base().task_id.as_str(), "upstream-only");
        drop(owner);
        frame(&mut peer, r#"{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#).await;
        client.list_tools(&cx, None).await.unwrap();
        client.close(&cx).await.unwrap();
        let mut peer = AsyncWsServerTransport::from_upgraded(peer);
        for (method, id) in [
            ("server/discover", Some(1)),
            ("subscriptions/listen", Some(2)),
            ("tasks/get", Some(3)),
            ("notifications/cancelled", None),
            ("tools/list", Some(4)),
        ] {
            receive(&cx, &mut peer, method, id).await;
        }
    });
}

#[test]
fn websocket_tasks_proxy_epilogue_finishes_a_partial_native_cancel_write() {
    run(|cx| async move {
        let (io, mut peer) = VirtualTcpStream::pair(
            "127.0.0.1:45301".parse().unwrap(),
            "127.0.0.1:45302".parse().unwrap(),
        );
        frame(&mut peer, &discovery(true)).await;
        let gate = Arc::new(ControlGate::default());
        let native = WebSocketClient::connect_with_cx(
            &cx,
            ClientProtocolPlan::websocket(ProtocolPolicy::ModernOnly),
            ClientInfo {
                name: "gateway".to_owned(),
                version: "1".to_owned(),
            },
            ClientCapabilities::default(),
            AsyncWsClientTransport::from_upgraded(GatedIo {
                inner: io,
                gate: Arc::clone(&gate),
            }),
        )
        .await
        .unwrap();
        let mut backend = ProxyWebSocketClient::new(native).unwrap();
        let filter = task_filter(FinalTaskId::parse("upstream-only").unwrap());
        frame(&mut peer, &acknowledgement(2, &filter)).await;
        let ctx = context(&cx, "owner");
        let mut listener = backend
            .start_final_task_listener(filter.clone())
            .unwrap()
            .unwrap()
            .open(&ctx)
            .await
            .unwrap();
        let cancellation = McpRequestCancellation::new();
        assert!(matches!(
            listener.next_async(&cx, &cancellation).await.unwrap(),
            ProxyFinalTaskListenerEvent::Acknowledged(_)
        ));
        let mut mux = crate::proxy::MultiplexedProxyFinalTaskListener::new(
            vec![listener],
            filter,
            ctx,
            Vec::new(),
        );
        assert!(matches!(
            mux.next_event(&cx, &cancellation).await.unwrap(),
            ProxyFinalTaskListenerEvent::Acknowledged(_)
        ));
        {
            let mut wait = Box::pin(mux.next_event(&cx, &cancellation));
            assert!(
                std::future::poll_fn(|task_cx| Poll::Ready(wait.as_mut().poll(task_cx)))
                    .await
                    .is_pending()
            );
        }
        gate.armed.store(true, Ordering::Release);
        mux.turns[0].as_ref().unwrap().cancellation.cancel();
        {
            let mut wait = Box::pin(mux.next_event(&cx, &cancellation));
            std::future::poll_fn(|task_cx| {
                assert!(wait.as_mut().poll(task_cx).is_pending());
                if gate.parked.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        assert_eq!(gate.accepted.load(Ordering::Acquire), 1);
        let mut cleanup = Box::pin(crate::proxy::finish_proxy_task_listener(&mut mux));
        assert!(
            std::future::poll_fn(|task_cx| Poll::Ready(cleanup.as_mut().poll(task_cx)))
                .await
                .is_pending(),
            "epilogue retains the exact partial cancellation frame"
        );
        gate.release();
        cleanup.await;
        frame(&mut peer, r#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#).await;
        let proxy = ProxyClient::from_backend_with_upstream_binding(
            backend.clone(),
            ProxyUpstreamBinding {
                era: ProtocolEra::Modern2026,
                adapter: ProxyUpstreamAdapter::ModernWebSocket,
                policy: ProtocolPolicy::ModernOnly,
                configuration_generation: 1,
            },
            "2026-07-28",
        )
        .unwrap();
        proxy.catalog_typed_with_cx(&cx).await.unwrap();
        backend.close(&cx).await.unwrap();
        let mut peer = AsyncWsServerTransport::from_upgraded(peer);
        receive(&cx, &mut peer, "server/discover", Some(1)).await;
        receive(&cx, &mut peer, "subscriptions/listen", Some(2)).await;
        let cancelled = receive(&cx, &mut peer, "notifications/cancelled", None).await;
        assert_eq!(cancelled.params.unwrap()["requestId"], 2);
        receive(&cx, &mut peer, "tools/list", Some(3)).await;
    });
}
