//! The creating tool and every Task operation traverse the parent's TLS peer.

use super::*;
use crate::http_auth::dpop::native::core::tasks::{DpopTaskOperation, ManagedTaskRequest};
use crate::http_auth::dpop::native::core::tasks::driver::start::DpopTaskExecutionOutcome;
use fastmcp_protocol::FinalCoreResult;

fn operation() -> DpopTaskOperation {
    DpopTaskOperation::new(
        RequestId::String("seed-discover".to_owned()),
        RequestId::String("seed-tool".to_owned()),
        ManagedTaskRequest::CallTool {
            name: "echo".to_owned(), arguments: Some(json!({"private":"body-only"})),
        },
    ).unwrap()
}

fn initial_response(discovery: bool, result: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0",
        "id":if discovery { "seed-discover" } else { "seed-tool" },
        "result":result,
    })).unwrap()
}

fn created(status: &str) -> Value {
    let mut value = task_result(status);
    value["resultType"] = json!("task");
    value
}

async fn initial_round(peer: &mut Peer) -> TlsStream<TcpStream> {
    let (mut socket, _) = peer.receive_named("seed-discover", "server/discover").await;
    json_reply(&mut socket, &initial_response(true, &discovery_result())).await;
    let (socket, _) = peer.listener.accept().await.unwrap();
    let mut socket = peer.acceptor.accept(socket).await.unwrap();
    let (head, body) = read(&mut socket).await;
    assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
    assert_eq!(header(&head, "accept"), "application/json, text/event-stream");
    assert_eq!(header(&head, "authorization"), "DPoP stream-task-token");
    assert_eq!(header(&head, "mcp-method"), "tools/call");
    assert_eq!(header(&head, "mcp-name"), "echo");
    assert_eq!(body["id"], "seed-tool");
    assert_eq!(body["method"], "tools/call");
    assert_eq!(body["params"]["name"], "echo");
    assert_eq!(body["params"]["arguments"], json!({"private":"body-only"}));
    assert!(body["params"].get("taskId").is_none());
    assert!(!head.contains("body-only"));
    assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
        json!({TASKS_EXTENSION:{}}));
    let proof = claims(header(&head, "dpop"));
    assert_eq!(proof["htm"], "POST");
    assert_eq!(proof["htu"], peer.target.split('?').next().unwrap());
    assert_eq!(proof["nonce"], "stream-next");
    assert!(proof["ath"].as_str().is_some_and(|value| !value.is_empty()));
    assert!(peer.proofs.insert(proof["jti"].as_str().unwrap().to_owned()));
    socket
}

#[test]
fn creating_input_task_uses_the_shared_ledger_across_json_sse_and_mixed_rounds() {
    for explicit_events in [false, true] {
        for json_rounds in [[false; 4], [true; 4], [false, true, false, true]] {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let cancellation = McpRequestCancellation::new();
                let (mut resolves, mut snapshots, mut notifications) = (0, 0, 0);
                let resolve = |requests: TaskInputRequests| {
                    resolves += 1;
                    assert_eq!(requests.keys().map(String::as_str).collect::<Vec<_>>(), ["roots"]);
                    std::future::ready(Ok(ManagedTaskInputAction::Respond(
                        serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap(),
                    )))
                };
                let observe = |task: &Task| {
                    assert_eq!(task.base().task_id.as_str(), "task-one");
                    snapshots += 1;
                    Ok(())
                };
                let application: Pin<Box<dyn Future<Output = Result<
                    DpopTaskExecutionOutcome, DpopTaskDriverError,
                >> + '_>> = if explicit_events {
                    Box::pin(client.start_and_drive_task_with_events(
                        &cx, &cancellation, &credential, driver_metadata(), operation(), "run",
                        driver_policy(2, 1, Duration::from_secs(10)), limits(4), resolve, observe,
                        |_| { notifications += 1; true },
                    ))
                } else {
                    Box::pin(client.start_and_drive_task(
                        &cx, &cancellation, &credential, driver_metadata(), operation(), "run",
                        driver_policy(2, 1, Duration::from_secs(10)), limits(4).core, resolve, observe,
                    ))
                };
                let server = async {
                    let mut socket = initial_round(&mut peer).await;
                    let bytes = initial_response(false, &created("input_required"));
                    if json_rounds[0] { json_reply(&mut socket, &bytes).await; }
                    else { streamed_reply(&mut socket, &bytes, None, false).await; }
                    for (round, method, result) in [
                        (0, "tasks/update", json!({"resultType":"complete"})),
                        (1, "tasks/get", task_result("input_required")),
                        (2, "tasks/get", task_result("cancelled")),
                    ] {
                        // First successor is the explicit answer, not a get or
                        // another tools/call. Later stale input is not answered twice.
                        let (mut socket, body) = peer.round("run", round, method).await;
                        if round == 0 {
                            assert_eq!(body["params"]["inputResponses"], json!({"roots":{"roots":[]}}));
                        } else { assert!(body["params"].get("inputResponses").is_none()); }
                        let bytes = driver_response("run", round, false, &result);
                        if json_rounds[round + 1] { json_reply(&mut socket, &bytes).await; }
                        else { streamed_reply(&mut socket, &bytes, None, false).await; }
                    }
                };
                let (result, ()) = pair(application, server).await;
                let DpopTaskExecutionOutcome::Task { initial, outcome } = result.unwrap() else {
                    panic!("creation must enter the Task driver");
                };
                assert!(matches!(*initial, FinalCoreResult::ToolsCallTask { result }
                    if matches!(result.task, Task::InputRequired { .. })));
                assert!(matches!(outcome, ManagedTaskRunOutcome::Terminal(task)
                    if matches!(*task, Task::Cancelled(_))));
                assert_eq!((resolves, snapshots), (1, 3));
                let expected = if explicit_events { json_rounds.iter().filter(|json| !**json).count() } else { 0 };
                assert_eq!(notifications, expected);
                peer.no_extra(4);
                assert!(cx.checkpoint().is_ok());
                assert!(!client.revocation_handle().is_revoked());
            });
        }
    }
}

#[test]
fn immediate_completion_request_input_and_terminal_creation_need_no_task_post() {
    for kind in 0..4 {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let mut snapshots = 0;
            let application = client.start_and_drive_task(
                &cx, &cancellation, &credential, driver_metadata(), operation(), "run",
                driver_policy(1, 0, Duration::from_secs(10)), limits(1).core, no_input,
                |_| { snapshots += 1; Ok(()) },
            );
            let server = async {
                let mut socket = initial_round(&mut peer).await;
                let result = match kind {
                    0 => json!({"resultType":"complete","content":[],"isError":true}),
                    1 => json!({"resultType":"input_required","requestState":"private-state",
                        "inputRequests":{"roots":{"method":"roots/list"}}}),
                    2 => created("cancelled"),
                    _ => created("input_required"),
                };
                streamed_reply(&mut socket, &initial_response(false, &result), None, false).await;
            };
            let (result, ()) = pair(application, server).await;
            let result = result.unwrap();
            assert!(!format!("{result:?}").contains("private-state"));
            match (kind, result) {
                (0, DpopTaskExecutionOutcome::Tool(result)) => {
                    assert!(matches!(*result, FinalCoreResult::ToolsCall { .. }));
                    assert_eq!(snapshots, 0);
                }
                (1, DpopTaskExecutionOutcome::Tool(result)) => {
                    assert!(matches!(*result, FinalCoreResult::ToolsCallInputRequired { .. }));
                    assert_eq!(snapshots, 0);
                }
                (2, DpopTaskExecutionOutcome::Task { outcome, .. }) => {
                    assert!(matches!(outcome, ManagedTaskRunOutcome::Terminal(task)
                        if matches!(*task, Task::Cancelled(_))));
                    assert_eq!(snapshots, 1);
                }
                (3, DpopTaskExecutionOutcome::Task { outcome, .. }) => {
                    assert!(matches!(outcome, ManagedTaskRunOutcome::InputRequired(_)));
                    assert_eq!(snapshots, 1);
                }
                _ => panic!("immediate method and Task outcomes must stay distinct"),
            }
            peer.no_extra(1);
        });
    }
}

#[test]
fn creation_and_polling_share_exact_payload_and_notification_quotas() {
    for budget in [Budget::Exact, Budget::ByteShort, Budget::NotificationShort] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let frames = [
                initial_response(true, &discovery_result()),
                progress(json!("work"), "1"),
                initial_response(false, &created("working")),
                driver_response("run", 0, true, &discovery_result()),
                progress(json!("work"), "1"),
                driver_response("run", 0, false, &task_result("cancelled")),
            ];
            let total: usize = frames.iter().map(Vec::len).sum();
            let maximum = frames.iter().map(Vec::len).max().unwrap();
            let core = ManagedCoreLimits::new(8192, maximum,
                total - usize::from(matches!(budget, Budget::ByteShort)),
                if matches!(budget, Budget::NotificationShort) { 1 } else { 2 },
                Duration::from_secs(10)).unwrap();
            let (mut snapshots, mut notifications) = (0, 0);
            let application = client.start_and_drive_task_with_events(
                &cx, &cancellation, &credential, driver_metadata(), operation(), "run",
                driver_policy(1, 0, Duration::from_secs(10)),
                DpopStreamLimits::new(core, Duration::from_secs(5)).unwrap(), no_input,
                |_| { snapshots += 1; Ok(()) }, |_| { notifications += 1; true },
            );
            let server = async {
                let mut socket = initial_round(&mut peer).await;
                streamed_reply(&mut socket, &frames[2], None, false).await;
                let (mut socket, _) = peer.round("run", 0, "tasks/get").await;
                streamed_reply(&mut socket, &frames[5], None, false).await;
            };
            let (result, ()) = pair(application, server).await;
            match budget {
                Budget::Exact => {
                    assert!(matches!(result.unwrap(), DpopTaskExecutionOutcome::Task {
                        outcome: ManagedTaskRunOutcome::Terminal(_), ..
                    }));
                    assert_eq!((snapshots, notifications), (2, 2));
                }
                Budget::ByteShort => {
                    assert!(matches!(result, Err(DpopTaskDriverError::Task(DpopTasksError::Core(
                        DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit),
                    )))));
                    assert_eq!((snapshots, notifications), (1, 2));
                }
                Budget::NotificationShort => {
                    assert!(matches!(result, Err(DpopTaskDriverError::Task(DpopTasksError::Core(
                        DpopCoreError::Protocol(ManagedCoreError::NotificationLimit),
                    )))));
                    assert_eq!((snapshots, notifications), (1, 1));
                }
            }
            peer.no_extra(2);
            wait_follow_up(&mut peer, &mut client, &cx, &credential).await;
            peer.no_extra(3);
        });
    }
}

#[test]
fn uncertain_creation_or_update_never_replays_the_tool_or_advances_the_lifecycle() {
    for bad_creation in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let (mut resolves, mut snapshots) = (0, 0);
            let application = client.start_and_drive_task(
                &cx, &cancellation, &credential, driver_metadata(), operation(), "run",
                driver_policy(2, 1, Duration::from_secs(10)), limits(4).core,
                |_| {
                    resolves += 1;
                    std::future::ready(Ok(ManagedTaskInputAction::Respond(
                        serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap(),
                    )))
                }, |_| { snapshots += 1; Ok(()) },
            );
            let server = async {
                let mut socket = initial_round(&mut peer).await;
                streamed_reply(&mut socket, &initial_response(false, &created("input_required")),
                    None, bad_creation).await;
                if !bad_creation {
                    let (mut socket, _) = peer.round("run", 0, "tasks/update").await;
                    streamed_reply(&mut socket,
                        &driver_response("run", 0, false, &json!({"resultType":"complete"})),
                        None, true).await;
                }
            };
            let (result, ()) = pair(application, server).await;
            assert!(matches!(result, Err(DpopTaskDriverError::Task(DpopTasksError::Core(
                DpopCoreError::Protocol(ManagedCoreError::InvalidResponse),
            )))));
            let accepted = usize::from(!bad_creation);
            assert_eq!((resolves, snapshots), (accepted, accepted));
            peer.no_extra(1 + accepted);
            // Recovery is an explicit get using a fresh request, never a
            // recreation or a replay of the uncertain input update.
            wait_follow_up(&mut peer, &mut client, &cx, &credential).await;
            peer.no_extra(2 + accepted);
        });
    }
}

#[test]
fn creation_poll_hint_cannot_reset_the_original_execution_deadline() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let cancellation = McpRequestCancellation::new();
        let mut snapshots = 0;
        let driver = client.start_and_drive_task(
            &cx, &cancellation, &credential, driver_metadata(), operation(), "run",
            driver_policy(2, 0, Duration::from_secs(2)), limits(2).core, no_input,
            |_| { snapshots += 1; Ok(()) },
        );
        let outer_deadline = cx.now().saturating_add_nanos(3_000_000_000);
        let application = async {
            asupersync::time::timeout_at(outer_deadline, driver).await
                .expect("the original two-second deadline must include tool execution")
        };
        let server = async {
            let mut socket = initial_round(&mut peer).await;
            // A fresh two-second driver deadline after this creating pair
            // would outlive the three-second test cap and fail, not pass late.
            asupersync::time::Sleep::new(cx.now().saturating_add_nanos(1_500_000_000)).await;
            let mut task = created("working");
            task["pollIntervalMs"] = json!(60000);
            streamed_reply(&mut socket, &initial_response(false, &task), None, false).await;
        };
        let (result, ()) = pair(application, server).await;
        assert!(matches!(result, Err(DpopTaskDriverError::Task(DpopTasksError::Core(
            DpopCoreError::Transport(DpopHttpError::TimedOut),
        )))));
        assert_eq!(snapshots, 1);
        peer.no_extra(1);
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn host_stop_or_local_cancel_at_creation_precedes_input_resolution_and_successor_posts() {
    for cancel in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let mut snapshots = 0;
            let application = client.start_and_drive_task(
                &cx, &cancellation, &credential, driver_metadata(), operation(), "run",
                driver_policy(2, 1, Duration::from_secs(10)), limits(2).core, no_input,
                |_| {
                    snapshots += 1;
                    if cancel { cancellation.cancel(); Ok(()) }
                    else { Err(ManagedTaskDriverError::AbortedByHost) }
                },
            );
            let server = async {
                let mut socket = initial_round(&mut peer).await;
                streamed_reply(&mut socket, &initial_response(false, &created("input_required")),
                    None, false).await;
            };
            let (result, ()) = pair(application, server).await;
            if cancel {
                assert!(matches!(result, Err(DpopTaskDriverError::Task(DpopTasksError::Core(
                    DpopCoreError::Transport(DpopHttpError::Cancelled),
                )))));
            } else {
                assert!(matches!(result, Err(DpopTaskDriverError::Driver(
                    ManagedTaskDriverError::AbortedByHost,
                ))));
            }
            assert_eq!(snapshots, 1);
            peer.no_extra(1);
            wait_follow_up(&mut peer, &mut client, &cx, &credential).await;
            peer.no_extra(2);
        });
    }
}
