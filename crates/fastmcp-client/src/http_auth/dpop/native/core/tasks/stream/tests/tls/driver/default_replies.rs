//! Default and explicit JSON-only Task drivers through the existing HTTPS peer.
//!
//! These cases exercise public methods, not a substitute Task loop or parser.

mod start;

use super::*;
use crate::http_auth::dpop::native::core::tasks::driver::ManagedTaskDriverError;
use fastmcp_protocol::tasks_extension::TaskInputRequests;
use std::future::{Future, Ready};
use std::pin::Pin;

fn no_input(_: TaskInputRequests) -> Ready<Result<ManagedTaskInputAction, ManagedTaskDriverError>> {
    panic!("an observation-only run must not resolve host input")
}

#[test]
fn default_drivers_negotiate_json_sse_and_mixed_input_lifecycles() {
    for cancellable in [false, true] {
        for json_rounds in [
            [false; 4],
            [true; 4],
            [false, true, true, false],
        ] {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let cancellation = McpRequestCancellation::new();
                let (mut resolves, mut snapshots) = (0, 0);
                let resolve = |requests: TaskInputRequests| {
                    resolves += 1;
                    assert_eq!(
                        requests.keys().map(String::as_str).collect::<Vec<_>>(),
                        ["roots"],
                    );
                    std::future::ready(Ok(ManagedTaskInputAction::Respond(
                        serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap(),
                    )))
                };
                let observe = |_: &Task| {
                    snapshots += 1;
                    Ok(())
                };
                let application: Pin<Box<dyn Future<Output = Result<
                    ManagedTaskRunOutcome, DpopTaskDriverError,
                >> + '_>> = if cancellable {
                    Box::pin(client.drive_task_with_cancellation(
                        &cx, &cancellation, &credential, driver_metadata(),
                        TaskId::parse("task-one").unwrap(), "defaults",
                        driver_policy(3, 1, Duration::from_secs(10)),
                        ManagedCoreLimits::default(), resolve, observe,
                    ))
                } else {
                    Box::pin(client.drive_task(
                        &cx, &credential, driver_metadata(),
                        TaskId::parse("task-one").unwrap(), "defaults",
                        driver_policy(3, 1, Duration::from_secs(10)),
                        ManagedCoreLimits::default(), resolve, observe,
                    ))
                };
                let server = async {
                    for (round, method, result) in [
                        (0, "tasks/get", task_result("input_required")),
                        (1, "tasks/update", json!({"resultType":"complete"})),
                        (2, "tasks/get", task_result("input_required")),
                        (3, "tasks/get", task_result("cancelled")),
                    ] {
                        // The existing peer asserts the actual Accept, DPoP,
                        // nonce, method/name mirrors and request identities.
                        let (mut socket, body) = peer.round("defaults", round, method).await;
                        if method == "tasks/update" {
                            assert_eq!(body["params"]["inputResponses"],
                                json!({"roots":{"roots":[]}}));
                        } else {
                            assert!(body["params"].get("inputResponses").is_none());
                        }
                        let bytes = driver_response("defaults", round, false, &result);
                        if json_rounds[round] {
                            json_reply(&mut socket, &bytes).await;
                        } else {
                            streamed_reply(&mut socket, &bytes, None, false).await;
                        }
                    }
                };
                let (result, ()) = pair(application, server).await;
                assert!(matches!(result.unwrap(), ManagedTaskRunOutcome::Terminal(task)
                    if matches!(*task, Task::Cancelled(_))));
                // In particular, an acknowledged stale input is not resolved
                // or posted twice just because the representation changed.
                assert_eq!((resolves, snapshots), (1, 3));
                peer.no_extra(4);
                assert!(!client.revocation_handle().is_revoked());
                assert!(cx.checkpoint().is_ok());
            });
        }
    }
}

#[test]
fn discarded_default_notifications_still_consume_the_run_budget() {
    for budget in [Budget::Exact, Budget::ByteShort, Budget::NotificationShort] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let (mut total, mut maximum) = (0_usize, 0_usize);
            for (round, status) in [(0, "working"), (1, "cancelled")] {
                for bytes in [
                    driver_response("default-quota", round, true, &discovery_result()),
                    progress(json!("work"), "1"),
                    driver_response("default-quota", round, false, &task_result(status)),
                ] {
                    total += bytes.len();
                    maximum = maximum.max(bytes.len());
                }
            }
            let core = ManagedCoreLimits::new(
                8192, maximum,
                total - usize::from(matches!(budget, Budget::ByteShort)),
                if matches!(budget, Budget::NotificationShort) { 1 } else { 2 },
                Duration::from_secs(10),
            ).unwrap();
            let mut snapshots = 0;
            let application = client.drive_task_with_cancellation(
                &cx, &cancellation, &credential, driver_metadata(),
                TaskId::parse("task-one").unwrap(), "default-quota",
                driver_policy(2, 0, Duration::from_secs(10)), core, no_input,
                |_| { snapshots += 1; Ok(()) },
            );
            let server = async {
                for (round, status) in [(0, "working"), (1, "cancelled")] {
                    let (mut socket, _) = peer.round("default-quota", round, "tasks/get").await;
                    streamed_reply(
                        &mut socket,
                        &driver_response("default-quota", round, false, &task_result(status)),
                        None, false,
                    ).await;
                }
            };
            let (result, ()) = pair(application, server).await;
            match budget {
                Budget::Exact => {
                    assert!(matches!(result.unwrap(), ManagedTaskRunOutcome::Terminal(task)
                        if matches!(*task, Task::Cancelled(_))));
                    assert_eq!(snapshots, 2);
                }
                Budget::ByteShort => {
                    assert!(matches!(result, Err(DpopTaskDriverError::Task(DpopTasksError::Core(
                        DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit),
                    )))));
                    assert_eq!(snapshots, 1);
                }
                Budget::NotificationShort => {
                    assert!(matches!(result, Err(DpopTaskDriverError::Task(DpopTasksError::Core(
                        DpopCoreError::Protocol(ManagedCoreError::NotificationLimit),
                    )))));
                    assert_eq!(snapshots, 1);
                }
            }
            peer.no_extra(2);
        });
    }
}

#[test]
fn default_driver_never_replays_an_uncertain_streamed_update() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let (mut resolves, mut snapshots) = (0, 0);
        let application = client.drive_task(
            &cx, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
            "default-tail", driver_policy(3, 1, Duration::from_secs(10)),
            ManagedCoreLimits::default(),
            |_| {
                resolves += 1;
                std::future::ready(Ok(ManagedTaskInputAction::Respond(
                    serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap(),
                )))
            },
            |_| { snapshots += 1; Ok(()) },
        );
        let server = async {
            for (round, method, result) in [
                (0, "tasks/get", task_result("input_required")),
                (1, "tasks/update", json!({"resultType":"complete"})),
            ] {
                let (mut socket, _) = peer.round("default-tail", round, method).await;
                streamed_reply(
                    &mut socket, &driver_response("default-tail", round, false, &result),
                    None, round == 1,
                ).await;
            }
        };
        let (result, ()) = pair(application, server).await;
        assert!(matches!(result, Err(DpopTaskDriverError::Task(DpopTasksError::Core(
            DpopCoreError::Protocol(ManagedCoreError::InvalidResponse),
        )))));
        assert_eq!((resolves, snapshots), (1, 1));
        peer.no_extra(2);
        assert!(!client.revocation_handle().is_revoked());
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn explicit_json_only_driver_retains_the_original_accept_contract() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let cancellation = McpRequestCancellation::new();
        let mut snapshots = 0;
        let application = client.drive_task_json_with_cancellation(
            &cx, &cancellation, &credential, driver_metadata(),
            TaskId::parse("task-one").unwrap(), "json-only",
            driver_policy(1, 0, Duration::from_secs(10)), ManagedCoreLimits::default(),
            no_input, |_| { snapshots += 1; Ok(()) },
        );
        let server = async {
            let (mut socket, _) = peer.receive("json-only", 0, "server/discover").await;
            json_reply(
                &mut socket, &driver_response("json-only", 0, true, &discovery_result()),
            ).await;

            // This explicit representation policy differs in its actual
            // operation Accept header. Credential custody stays unchanged.
            let (socket, _) = peer.listener.accept().await.unwrap();
            let mut socket = peer.acceptor.accept(socket).await.unwrap();
            let (head, body) = read(&mut socket).await;
            assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
            assert_eq!(header(&head, "accept"), "application/json");
            assert_eq!(header(&head, "authorization"), "DPoP stream-task-token");
            assert_eq!(header(&head, "mcp-method"), "tasks/get");
            assert_eq!(header(&head, "mcp-name"), "task-one");
            assert_eq!(body["id"], "json-only.0.task");
            assert_eq!(body["method"], "tasks/get");
            assert_eq!(body["params"]["taskId"], "task-one");
            assert!(body["params"].get("inputResponses").is_none());
            let proof = claims(header(&head, "dpop"));
            assert_eq!(proof["htm"], "POST");
            assert_eq!(proof["htu"], peer.target.split('?').next().unwrap());
            assert_eq!(proof["nonce"], "stream-next");
            assert!(proof["ath"].as_str().is_some_and(|hash| !hash.is_empty()));
            assert!(peer.proofs.insert(proof["jti"].as_str().unwrap().to_owned()));
            json_reply(
                &mut socket,
                &driver_response("json-only", 0, false, &task_result("cancelled")),
            ).await;
        };
        let (result, ()) = pair(application, server).await;
        assert!(matches!(result.unwrap(), ManagedTaskRunOutcome::Terminal(task)
            if matches!(*task, Task::Cancelled(_))));
        assert_eq!(snapshots, 1);
        peer.no_extra(1);
        assert!(!client.revocation_handle().is_revoked());
        assert!(cx.checkpoint().is_ok());
    });
}
