//! Creating calls and subscribed continuations share one native DPoP lifecycle.

use super::*;
use fastmcp_protocol::{CoreResult, FinalCoreResult};
use crate::http_auth::dpop::native::core::stream::task_subscription::watch::input::start::
    DpopTaskSubscriptionExecutionOutcome;
use crate::http_auth::dpop::native::core::tasks::ManagedTaskRequest;

fn call() -> ManagedTaskRequest {
    ManagedTaskRequest::CallTool {
        name: "work".to_owned(), arguments: Some(json!({"number":7})),
    }
}

fn created(status: &str) -> Value {
    let mut result = task_result(status);
    result["resultType"] = json!("task");
    result["_meta"] = json!({"example.com/creation":"retained"});
    result
}

fn response(prefix: &str, discovery: bool, result: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0",
        "id":format!("{prefix}.create.{}", if discovery { "discover" } else { "call" }),
        "result":result})).unwrap()
}

async fn creation(peer: &mut Peer, prefix: &str) -> TlsStream<TcpStream> {
    let (mut discovery, _) = peer.receive_named(
        &format!("{prefix}.create.discover"), "server/discover",
    ).await;
    json_reply(&mut discovery, &response(prefix, true, &discovery_result())).await;
    let (socket, _) = peer.listener.accept().await.unwrap();
    let mut socket = peer.acceptor.accept(socket).await.unwrap();
    let (head, body) = read(&mut socket).await;
    assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
    assert_eq!(body["id"], format!("{prefix}.create.call"));
    assert_eq!(body["method"], "tools/call");
    assert_eq!(body["params"]["name"], "work");
    assert_eq!(body["params"]["arguments"], json!({"number":7}));
    assert!(body["params"].get("taskId").is_none());
    assert!(body["params"].get("inputResponses").is_none());
    assert_eq!(header(&head, "authorization"), "DPoP stream-task-token");
    assert_eq!(header(&head, "accept"), "application/json, text/event-stream");
    assert_eq!(header(&head, "mcp-method"), "tools/call");
    assert_eq!(header(&head, "mcp-name"), "work");
    assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
        json!({TASKS_EXTENSION:{}}));
    let proof = claims(header(&head, "dpop"));
    assert_eq!(proof["htm"], "POST");
    assert_eq!(proof["htu"], peer.target.split('?').next().unwrap());
    assert_eq!(proof["nonce"], "stream-next");
    assert!(proof["ath"].as_str().is_some_and(|hash| !hash.is_empty()));
    assert!(peer.proofs.insert(proof["jti"].as_str().unwrap().to_owned()));
    socket
}

async fn creation_reply(peer: &mut Peer, prefix: &str, result: &Value, json: bool) {
    let mut socket = creation(peer, prefix).await;
    let bytes = response(prefix, false, result);
    if json { json_reply(&mut socket, &bytes).await; }
    else { streamed_reply(&mut socket, &bytes, None, false).await; }
}

#[test]
fn immediate_results_and_terminal_creation_need_no_successor_and_keep_the_original_result() {
    for json in [false, true] {
        for kind in 0..3 {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let cancellation = McpRequestCancellation::new();
                let mut observed = 0;
                let result = match kind {
                    0 => json!({"resultType":"complete", "content":[], "isError":true,
                        "_meta":{"example.com/creation":"retained"}}),
                    1 => json!({"resultType":"input_required", "requestState":"opaque",
                        "inputRequests":{"roots":{"method":"roots/list"}},
                        "_meta":{"example.com/creation":"retained"}}),
                    _ => created("cancelled"),
                };
                let application = client.start_and_drive_task_with_subscription(
                    &cx, &cancellation, &credential, driver_metadata(), call(),
                    "immediate", policy(2, 1), watch_limits(8),
                    |_| -> std::future::Ready<Result<ManagedTaskInputAction, ManagedTaskDriverError>> {
                        panic!("immediate tool results are not Task-input continuations")
                    },
                    |_| { observed += 1; Ok(()) },
                );
                let (result, ()) = pair(application, creation_reply(&mut peer, "immediate", &result, json)).await;
                let result = result.unwrap();
                assert!(!format!("{result:?}").contains("retained"));
                let DpopTaskSubscriptionExecutionOutcome::Initial(initial) = result else {
                    panic!("an immediate result cannot invent an observed Task")
                };
                assert!(matches!((kind, &*initial),
                    (0, FinalCoreResult::ToolsCall { .. })
                    | (1, FinalCoreResult::ToolsCallInputRequired { .. })
                    | (2, FinalCoreResult::ToolsCallTask { .. })));
                assert!(CoreResult::Final(*initial).encode().unwrap().contains("retained"));
                assert_eq!(observed, usize::from(kind == 2));
                peer.no_extra(1);
                followup(&mut peer, &mut client, &credential).await;
                peer.no_extra(2);
            });
        }
    }
}

#[test]
fn creation_then_subscribed_input_updates_without_replaying_tools_call_or_waiting_for_status() {
    for json in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let creation_observed = McpRequestCancellation::new();
            let (mut snapshots, mut resolved) = (0, 0);
            let application = client.start_and_drive_task_with_subscription(
                &cx, &cancellation, &credential, driver_metadata(), call(),
                "start", policy(3, 1), watch_limits(8),
                |requests| {
                    assert_eq!(requests.keys().map(String::as_str).collect::<Vec<_>>(), ["one"]);
                    resolved += 1;
                    std::future::ready(Ok(ManagedTaskInputAction::Respond(answer("one"))))
                },
                |task| {
                    assert_eq!(task.base().task_id.as_str(), "task-one");
                    snapshots += 1;
                    creation_observed.cancel();
                    Ok(())
                },
            );
            let server = async {
                creation_reply(&mut peer, "start", &created("working"), json).await;
                creation_observed.cancelled().await;
                peer.watch_snapshot_reply("start", 0, "working").await;
                let mut listen = peer.watch_listen("start").await;
                listen.write_all(HEAD).await.unwrap();
                event(&mut listen, &watch_ack("start", true)).await;
                get_reply(&mut peer, "start", 1, &input_task(&["one"]), true).await;
                acknowledge(&mut peer, "start", 0, "one", json).await;
                // No notification is emitted for the completed update.
                peer.watch_snapshot_reply("start", 2, "cancelled").await;
                assert_watch_closed(&mut listen).await;
            };
            let (result, ()) = pair(application, server).await;
            let DpopTaskSubscriptionExecutionOutcome::Observed { initial, outcome } = result.unwrap() else {
                panic!("a nonterminal creating call must enter the bounded Task lifecycle")
            };
            assert!(CoreResult::Final(*initial).encode().unwrap().contains("retained"));
            assert!(matches!(outcome, DpopTaskWaitOutcome::Terminal(snapshot)
                if matches!(snapshot.task, Task::Cancelled(_))));
            assert_eq!((snapshots, resolved), (4, 1));
            peer.no_extra(6);
            followup(&mut peer, &mut client, &credential).await;
            peer.no_extra(7);
        });
    }
}

#[test]
fn creating_response_bytes_and_notifications_are_not_replenished_by_the_watch_handoff() {
    for quota in [Quota::Exact, Quota::ByteShort, Quota::NotificationShort] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let payloads = [response("budget", true, &discovery_result()),
                progress(json!("work"), "1"), response("budget", false, &created("working")),
                wait_response("budget", 0, true, &discovery_result()),
                wait_response("budget", 0, false, &task_result("cancelled"))];
            let total: usize = payloads.iter().map(Vec::len).sum();
            let maximum = payloads.iter().map(Vec::len).max().unwrap();
            let core = ManagedCoreLimits::new(8192, maximum,
                total - usize::from(matches!(quota, Quota::ByteShort)),
                usize::from(!matches!(quota, Quota::NotificationShort)), Duration::from_secs(10)).unwrap();
            let application = client.start_and_drive_task_with_subscription(
                &cx, &cancellation, &credential, driver_metadata(), call(), "budget", policy(1, 0),
                DpopStreamLimits::new(core, Duration::from_secs(5)).unwrap(),
                |_| std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller)), |_| Ok(()),
            );
            let server = async {
                creation_reply(&mut peer, "budget", &created("working"), false).await;
                if !matches!(quota, Quota::NotificationShort) {
                    peer.watch_snapshot_reply("budget", 0, "cancelled").await;
                }
            };
            let (result, ()) = pair(application, server).await;
            match quota {
                Quota::Exact => assert!(matches!(result.unwrap(), DpopTaskSubscriptionExecutionOutcome::Observed { .. })),
                Quota::ByteShort => assert!(matches!(result, Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                    DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit)))))),
                Quota::NotificationShort => assert!(matches!(result, Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                    DpopCoreError::Protocol(ManagedCoreError::NotificationLimit)))))),
            }
            peer.no_extra(if matches!(quota, Quota::NotificationShort) { 1 } else { 2 });
        });
    }
}

#[test]
fn an_uncertain_creation_never_publishes_a_task_or_dispatches_a_successor() {
    for failure in 0..4 {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let mut observed = 0;
            let application = client.start_and_drive_task_with_subscription(
                &cx, &cancellation, &credential, driver_metadata(), call(), "uncertain-start", policy(3, 1), watch_limits(8),
                |_| -> std::future::Ready<Result<ManagedTaskInputAction, ManagedTaskDriverError>> {
                    panic!("an uncertain creating call cannot request Task input")
                },
                |_| { observed += 1; Ok(()) },
            );
            let server = async {
                let mut socket = creation(&mut peer, "uncertain-start").await;
                let good = response("uncertain-start", false, &created("working"));
                let mut wire = HEAD.to_vec();
                if failure != 3 {
                    let selected = if failure == 2 {
                        response("foreign", false, &created("working"))
                    } else { good.clone() };
                    wire.extend_from_slice(&event_chunk(&selected));
                }
                if failure == 0 { wire.extend_from_slice(&event_chunk(&good)); }
                if failure == 1 { wire.extend_from_slice(&chunk(b"data: unfinished")); }
                wire.extend_from_slice(b"0\r\n\r\n");
                socket.write_all(&wire).await.unwrap();
                let _ = socket.shutdown().await;
            };
            let (result, ()) = pair(application, server).await;
            assert!(result.is_err());
            assert_eq!(observed, 0);
            peer.no_extra(1);
            followup(&mut peer, &mut client, &credential).await;
            peer.no_extra(2);
        });
    }
}

#[test]
fn refusal_cancellation_revocation_or_panic_in_the_creation_observer_stops_before_the_first_get() {
    for disposition in 0..4 {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let application = client.start_and_drive_task_with_subscription(
                &cx, &cancellation, &credential, driver_metadata(), call(), "handoff", policy(2, 0), watch_limits(4),
                |_| std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller)),
                |_| {
                    match disposition {
                        0 => return Err(ManagedTaskDriverError::AbortedByHost),
                        1 => { cancellation.cancel(); }
                        2 => { credential.revoke(); }
                        _ => panic!("private-creation-observer-canary"),
                    }
                    Ok(())
                },
            );
            let (result, ()) = pair(application, creation_reply(&mut peer, "handoff", &created("working"), true)).await;
            let error = result.err().unwrap();
            assert!(!format!("{error:?} {error}").contains("canary"));
            match disposition {
                0 => assert!(matches!(error, DpopTaskWatchError::Driver(ManagedTaskDriverError::AbortedByHost))),
                1 => assert!(matches!(error, DpopTaskWatchError::Stream(DpopStreamError::Core(
                    DpopCoreError::Transport(DpopHttpError::Cancelled))))),
                2 => assert!(matches!(error, DpopTaskWatchError::Stream(DpopStreamError::Core(
                    DpopCoreError::Transport(DpopHttpError::Authorization(_)))))),
                _ => assert!(matches!(error, DpopTaskWatchError::Stream(DpopStreamError::ObserverPanicked))),
            }
            peer.no_extra(1);
            assert!(!client.revocation_handle().is_revoked());
            assert!(cx.checkpoint().is_ok());
        });
    }
}

#[test]
fn invalid_creation_selection_is_refused_before_discovery_or_host_work() {
    for case in 0..3 {
        run(async {
            let cx = Cx::current().unwrap();
            let (peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let request = match case {
                0 => ManagedTaskRequest::Get(TaskId::parse("task-one").unwrap()),
                1 => ManagedTaskRequest::Cancel(TaskId::parse("task-one").unwrap()),
                _ => call(),
            };
            let result = client.start_and_drive_task_with_subscription(
                &cx, &cancellation, &credential, driver_metadata(), request,
                if case == 2 { "" } else { "preflight" }, policy(2, 1), watch_limits(4),
                |_| -> std::future::Ready<Result<ManagedTaskInputAction, ManagedTaskDriverError>> {
                    panic!("invalid creation cannot invoke a resolver")
                },
                |_| panic!("invalid creation cannot publish a Task"),
            ).await;
            if case == 2 { assert!(matches!(result, Err(DpopTaskWatchError::InvalidIdPrefix))); }
            else { assert!(matches!(result, Err(DpopTaskWatchError::UnexpectedResponse))); }
            peer.no_extra(0);
        });
    }
}

#[test]
fn a_valid_creation_without_http_eof_remains_provisional_until_cancel_or_idle() {
    for idle in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let selected = DpopStreamLimits::new(watch_limits(4).core,
                if idle { Duration::from_secs(1) } else { Duration::from_secs(5) }).unwrap();
            let mut observed = 0;
            let application = async {
                let start = client.start_and_drive_task_with_subscription(
                    &cx, &cancellation, &credential, driver_metadata(), call(), "provisional", policy(2, 0), selected,
                    |_| std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller)),
                    |_| { observed += 1; Ok(()) },
                );
                if idle {
                    asupersync::time::timeout_at(cx.now().saturating_add_nanos(3_000_000_000), start)
                        .await.expect("creation idle must win before the overall ten-second deadline")
                } else { start.await }
            };
            let server = async {
                let mut socket = creation(&mut peer, "provisional").await;
                socket.write_all(HEAD).await.unwrap();
                event(&mut socket, &response("provisional", false, &created("working"))).await;
                // Leave the valid result uncommitted: no final HTTP chunk.
                asupersync::time::Sleep::new(cx.now().saturating_add_nanos(10_000_000)).await;
                if !idle { cancellation.cancel(); }
                assert_watch_closed(&mut socket).await;
            };
            let (result, ()) = pair(application, server).await;
            let expected = if idle { DpopHttpError::TimedOut } else { DpopHttpError::Cancelled };
            assert!(matches!(result, Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                DpopCoreError::Transport(error)))) if error == expected));
            assert_eq!(observed, 0);
            peer.no_extra(1);
            assert!(cx.checkpoint().is_ok());
            assert!(!client.revocation_handle().is_revoked());
            followup(&mut peer, &mut client, &credential).await;
            peer.no_extra(2);
        });
    }
}
