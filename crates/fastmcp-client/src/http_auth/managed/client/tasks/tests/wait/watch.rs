//! Watch the shipped managed client through the existing OAuth/TLS peer.
//! Only the peer's timing/state or one admitted limit changes in each pair.

use super::super::*;

const PAYLOAD_BYTES: usize = 64 * 1024;
const SUB_ID: &str = "io.modelcontextprotocol/subscriptionId";

fn state(status: &str) -> Value {
    let mut value = task(status, "complete");
    if status == "failed" {
        value["error"] = json!({"code":-32001,"message":"failed","data":{"retained":true}});
    }
    value
}

fn assert_state(result: FinalGetTaskResult, status: &str) {
    let task = serde_json::to_value(result.task).unwrap();
    assert_eq!(task["taskId"], "task-1");
    assert_eq!(task["status"], status);
    match status {
        "completed" => assert_eq!(task["result"]["content"][0]["text"], "done"),
        "input_required" => assert_eq!(task["inputRequests"]["roots"]["method"], "roots/list"),
        "failed" => assert_eq!(task["error"]["data"]["retained"], true),
        "cancelled" => {}
        _ => panic!("a successful watch must never return Working"),
    }
}

async fn get(peer: &Peer, status: &str) -> Value {
    let request = peer
        .rpc("tasks/get", "access-one", state(status), false)
        .await;
    assert_eq!(request["params"]["taskId"], "task-1");
    request["id"].clone()
}

fn frame(value: &Value) -> String {
    format!("data: {}\n\n", serde_json::to_string(value).unwrap())
}

async fn open(peer: &Peer, accepts_task: bool) -> (Tls, Value) {
    let (mut stream, request) = peer.request("subscriptions/listen", "access-one").await;
    assert_eq!(
        request["params"]["notifications"],
        json!({"taskIds":["task-1"]})
    );
    let ack = frame(&json!({
        "jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged",
        "params":{"_meta":{SUB_ID:request["id"]},
            "notifications":{"taskIds":if accepts_task {json!(["task-1"])} else {json!([])}}}
    }));
    // Deliberately leave the body unfinished. Waiting for EOF rather than
    // incremental ACK admission deadlocks at the following tasks/get.
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        ack.len() + 4_096,
    );
    stream
        .write_all(format!("{head}{ack}").as_bytes())
        .await
        .unwrap();
    (stream, request["id"].clone())
}

async fn event(stream: &mut Tls, request_id: &Value, status: &str) {
    let mut params = state(status);
    params.as_object_mut().unwrap().remove("resultType");
    params["_meta"] = json!({SUB_ID:request_id});
    let wire = frame(&json!({
        "jsonrpc":"2.0", "method":"notifications/tasks", "params":params
    }));
    stream.write_all(wire.as_bytes()).await.unwrap();
}

async fn end(stream: &mut Tls, request_id: &Value) {
    let wire = frame(&json!({"jsonrpc":"2.0", "id":request_id,
        "result":{"resultType":"complete", "_meta":{SUB_ID:request_id}}}));
    stream.write_all(wire.as_bytes()).await.unwrap();
}

async fn released(stream: &mut Tls) {
    let mut byte = [0];
    match stream.read(&mut byte).await {
        Ok(0) | Err(_) => {}
        Ok(_) => panic!("a retired watch must not send more bytes on its owned response"),
    }
}

#[test]
fn watch_returns_each_actionable_first_snapshot_without_a_subscription() {
    for status in ["input_required", "completed", "failed", "cancelled"] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session).with_tasks();
            let (result, ()) = Box::pin(pair(
                client.watch_task_final(&cx, id(), 8, PAYLOAD_BYTES),
                async {
                    peer.discovery("access-one", true).await;
                    get(&peer, status).await;
                },
            ))
            .await;
            assert_state(result.unwrap(), status);
            assert_eq!(client.cached_credential_generation(), Some(1));
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn watch_reconciles_completion_before_ack_without_any_status_notification() {
    for status in ["input_required", "completed", "failed", "cancelled"] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session).with_tasks();
            let (result, ()) = Box::pin(pair(
                client.watch_task_final(&cx, id(), 1, PAYLOAD_BYTES),
                async {
                    peer.discovery("access-one", true).await;
                    let first = get(&peer, "working").await;
                    let (mut stream, listen) = open(&peer, true).await;
                    // This task finished before listener admission. No status
                    // event is sent, so the post-ACK snapshot is indispensable.
                    let second = get(&peer, status).await;
                    let ids: BTreeSet<_> = [first, listen, second]
                        .into_iter()
                        .map(|id| id.to_string())
                        .collect();
                    assert_eq!(ids.len(), 3);
                    released(&mut stream).await;
                },
            ))
            .await;
            assert_state(result.unwrap(), status);
            assert_eq!(client.cached_credential_generation(), Some(1));
            peer.no_more(&cx).await;
            // Normal completion retires the listen, not reusable discovery.
            let (next, _) =
                Box::pin(pair(client.get_task_final(&cx, id()), get(&peer, status))).await;
            assert_state(next.unwrap(), status);
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn watch_after_working_ack_stays_quiet_and_reconciles_stale_notification() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session).with_tasks();
        let (result, ()) = Box::pin(pair(
            client.watch_task_final(&cx, id(), 2, PAYLOAD_BYTES),
            async {
                peer.discovery("access-one", true).await;
                let first = get(&peer, "working").await;
                let (mut stream, listen) = open(&peer, true).await;
                let second = get(&peer, "working").await;
                // The unchanged-state control must wait, not report completion
                // or silently convert this stream into periodic polling.
                peer.no_more(&cx).await;
                event(&mut stream, &listen, "working").await;
                let third = get(&peer, "input_required").await;
                let ids: BTreeSet<_> = [first, listen, second, third]
                    .into_iter()
                    .map(|id| id.to_string())
                    .collect();
                assert_eq!(ids.len(), 4);
                released(&mut stream).await;
            },
        ))
        .await;
        assert_state(result.unwrap(), "input_required");
        assert_eq!(client.cached_credential_generation(), Some(1));
        peer.no_more(&cx).await;
    });
}

#[test]
fn watch_subscription_terminal_requires_an_actionable_final_snapshot() {
    for completed in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session).with_tasks();
            let (result, ()) = Box::pin(pair(
                client.watch_task_final(&cx, id(), 1, PAYLOAD_BYTES),
                async {
                    peer.discovery("access-one", true).await;
                    get(&peer, "working").await;
                    let (mut stream, listen) = open(&peer, true).await;
                    get(&peer, "working").await;
                    end(&mut stream, &listen).await;
                    get(&peer, if completed { "completed" } else { "working" }).await;
                    released(&mut stream).await;
                },
            ))
            .await;
            if completed {
                assert_state(result.unwrap(), "completed");
            } else {
                assert!(
                    result.is_err(),
                    "stream completion cannot imply task completion"
                );
            }
            assert_eq!(
                client.cached_credential_generation(),
                completed.then_some(1)
            );
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn watch_requires_its_task_in_the_acknowledged_subset_before_reconciliation() {
    for accepts_task in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session).with_tasks();
            let (result, ()) = Box::pin(pair(
                client.watch_task_final(&cx, id(), 2, PAYLOAD_BYTES),
                async {
                    peer.discovery("access-one", true).await;
                    get(&peer, "working").await;
                    let (mut stream, _) = open(&peer, accepts_task).await;
                    if accepts_task {
                        get(&peer, "completed").await;
                    }
                    released(&mut stream).await;
                    peer.no_more(&cx).await;
                },
            ))
            .await;
            if accepts_task {
                assert_state(result.unwrap(), "completed");
            } else {
                assert!(result.is_err());
            }
            assert_eq!(
                client.cached_credential_generation(),
                accepts_task.then_some(1)
            );
        });
    }
}

#[test]
fn watch_notification_limit_refuses_before_an_extra_reconciliation() {
    for max_notifications in [1, 2] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session).with_tasks();
            let (result, ()) = Box::pin(pair(
                client.watch_task_final(&cx, id(), max_notifications, PAYLOAD_BYTES),
                async {
                    peer.discovery("access-one", true).await;
                    get(&peer, "working").await;
                    let (mut stream, listen) = open(&peer, true).await;
                    get(&peer, "working").await;
                    event(&mut stream, &listen, "working").await;
                    if max_notifications == 2 {
                        get(&peer, "completed").await;
                    }
                    released(&mut stream).await;
                    peer.no_more(&cx).await;
                },
            ))
            .await;
            if max_notifications == 2 {
                assert_state(result.unwrap(), "completed");
            } else {
                assert!(result.is_err());
            }
            assert_eq!(
                client.cached_credential_generation(),
                (max_notifications == 2).then_some(1)
            );
        });
    }
}

#[test]
fn watch_cancellation_logout_and_revocation_release_both_owned_responses() {
    for during_get in [false, true] {
        for cause in 0..3 {
            run(async {
                let cx = Cx::current().unwrap();
                let peer = Peer::new().await;
                let session = peer.login(&cx).await;
                let token = session.credential(&cx).await.unwrap();
                let mut client = peer.client(session.clone()).with_tasks();
                let cancellation = McpRequestCancellation::new();
                let (result, ()) = Box::pin(pair(
                    client.watch_task_final_with_cancellation(
                        &cx,
                        &cancellation,
                        id(),
                        8,
                        PAYLOAD_BYTES,
                    ),
                    async {
                        peer.discovery("access-one", true).await;
                        get(&peer, "working").await;
                        let (mut stream, _) = open(&peer, true).await;
                        let mut pending = if during_get {
                            // Both the listen and a silent reconciliation POST
                            // are owned when the original authority is revoked.
                            Some(peer.request("tasks/get", "access-one").await.0)
                        } else {
                            get(&peer, "working").await;
                            None
                        };
                        peer.no_more(&cx).await;
                        match cause {
                            0 => {
                                cancellation.cancel();
                            }
                            1 => session.close(),
                            _ => token.credential().revoke(),
                        }
                        if let Some(pending) = &mut pending {
                            released(pending).await;
                        }
                        released(&mut stream).await;
                    },
                ))
                .await;
                match (cause, result) {
                    (0, Err(ManagedHttpClientError::Session(OAuthSessionError::Cancelled)))
                    | (1, Err(ManagedHttpClientError::Session(OAuthSessionError::Closed)))
                    | (2, Err(ManagedHttpClientError::Session(OAuthSessionError::LoginRequired))) =>
                        {}
                    _ => panic!("wrong watch lifetime disposition"),
                }
                assert_eq!(client.cached_credential_generation(), None);
                assert!(!cx.is_cancel_requested());
                peer.no_more(&cx).await;
                if cause == 0 {
                    assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
                    let (next, ()) = Box::pin(pair(client.get_task_final(&cx, id()), async {
                        peer.discovery("access-one", true).await;
                        get(&peer, "completed").await;
                    }))
                    .await;
                    assert_state(next.unwrap(), "completed");
                }
            });
        }
    }
}

#[test]
fn watch_deadline_covers_a_quiet_acknowledged_stream() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session.clone()).with_tasks();
        let (primed, ()) = Box::pin(pair(client.get_task_final(&cx, id()), async {
            peer.discovery("access-one", true).await;
            get(&peer, "working").await;
        }))
        .await;
        primed.unwrap();
        client.operation_timeout = Duration::from_secs(2);
        let (result, ()) = Box::pin(pair(
            client.watch_task_final(&cx, id(), 8, PAYLOAD_BYTES),
            async {
                get(&peer, "working").await;
                let (mut stream, _) = open(&peer, true).await;
                get(&peer, "working").await;
                peer.no_more(&cx).await;
                released(&mut stream).await;
            },
        ))
        .await;
        assert!(matches!(
            result,
            Err(ManagedHttpClientError::Session(OAuthSessionError::TimedOut))
        ));
        assert_eq!(client.cached_credential_generation(), None);
        assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
        assert!(!cx.is_cancel_requested());
        peer.no_more(&cx).await;
    });
}

#[test]
fn abandoning_watch_during_reconciliation_drops_both_responses_without_remote_cancel() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session.clone()).with_tasks();
        let (mut listen, mut pending) = {
            let mut watch = Box::pin(client.watch_task_final(&cx, id(), 8, PAYLOAD_BYTES));
            let mut server = Box::pin(async {
                peer.discovery("access-one", true).await;
                get(&peer, "working").await;
                let (stream, _) = open(&peer, true).await;
                let (pending, _) = peer.request("tasks/get", "access-one").await;
                (stream, pending)
            });
            poll_fn(|task| {
                assert!(watch.as_mut().poll(task).is_pending());
                server.as_mut().poll(task)
            })
            .await
            // The pending watch drops here, before checking either live socket.
        };
        released(&mut listen).await;
        released(&mut pending).await;
        assert_eq!(client.cached_credential_generation(), None);
        assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
        assert!(!cx.is_cancel_requested());
        peer.no_more(&cx).await;
        let (next, ()) = Box::pin(pair(client.get_task_final(&cx, id()), async {
            peer.discovery("access-one", true).await;
            get(&peer, "completed").await;
        }))
        .await;
        assert_state(next.unwrap(), "completed");
    });
}

#[test]
fn watch_invalid_limits_and_precancellation_never_open_a_connection() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut disabled = peer.client(session.clone());
        assert!(matches!(
            disabled.watch_task_final(&cx, id(), 1, PAYLOAD_BYTES).await,
            Err(ManagedHttpClientError::InvalidPolicy)
        ));
        let mut client = peer.client(session).with_tasks();
        for (count, bytes) in [(0, 1), (1, 0), (1025, 1), (1, 128 * 1024 * 1024 + 1)] {
            assert!(matches!(
                client.watch_task_final(&cx, id(), count, bytes).await,
                Err(ManagedHttpClientError::InvalidPolicy)
            ));
        }
        let cancellation = McpRequestCancellation::new();
        cancellation.cancel();
        assert!(matches!(
            client
                .watch_task_final_with_cancellation(&cx, &cancellation, id(), 8, PAYLOAD_BYTES)
                .await,
            Err(ManagedHttpClientError::Session(
                OAuthSessionError::Cancelled
            ))
        ));
        assert_eq!(client.cached_credential_generation(), None);
        peer.no_more(&cx).await;
        let (result, ()) = Box::pin(pair(
            client.watch_task_final(&cx, id(), 1, PAYLOAD_BYTES),
            async {
                peer.discovery("access-one", true).await;
                get(&peer, "completed").await;
            },
        ))
        .await;
        assert_state(result.unwrap(), "completed");
    });
}

#[test]
fn watch_exact_snapshot_payload_budget_excludes_the_transport_envelope() {
    let value: FinalGetTaskResult = serde_json::from_value(state("completed")).unwrap();
    let length = serde_json::to_vec(&value).unwrap().len();
    for (budget, fits) in [(length, true), (length - 1, false)] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session).with_tasks();
            let (result, ()) =
                Box::pin(pair(client.watch_task_final(&cx, id(), 1, budget), async {
                    peer.discovery("access-one", true).await;
                    get(&peer, "completed").await;
                }))
                .await;
            if fits {
                assert_state(result.unwrap(), "completed");
            } else {
                assert!(result.is_err());
            }
            assert_eq!(client.cached_credential_generation(), fits.then_some(1));
            peer.no_more(&cx).await;
        });
    }
}
