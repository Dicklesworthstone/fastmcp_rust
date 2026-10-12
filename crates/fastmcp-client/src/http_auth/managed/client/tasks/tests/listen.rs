//! Live Tasks subscriptions using the existing real OAuth callback and TLS peer.

use super::*;
use crate::http_executor::ModernHttpSubscriptionListenEvent as Event;
use asupersync::channel::oneshot;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const PAYLOAD_BYTES: usize = 64 * 1024;
const SUB_ID: &str = "io.modelcontextprotocol/subscriptionId";

fn acknowledgement(request_id: &Value, ids: Value) -> Value {
    json!({
        "jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged",
        "params":{"_meta":{SUB_ID:request_id}, "notifications":{"taskIds":ids}}
    })
}

fn status_event(request_id: &Value, status: &str) -> Value {
    let mut params = task(status, "complete");
    params.as_object_mut().unwrap().remove("resultType");
    params["_meta"] = json!({SUB_ID:request_id, "x-observation":"retained"});
    json!({"jsonrpc":"2.0", "method":"notifications/tasks", "params":params})
}

fn terminal(request_id: &Value) -> Value {
    json!({"jsonrpc":"2.0", "id":request_id,
        "result":{"resultType":"complete", "_meta":{SUB_ID:request_id}}})
}

fn sse_frame(value: &Value) -> String {
    format!("data: {}\n\n", serde_json::to_string(value).unwrap())
}

fn sse_head(length: usize) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {length}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    )
}

async fn finite_stream(stream: &mut Tls, frames: &[Value]) {
    let body: String = frames.iter().map(sse_frame).collect();
    // One small write also makes buffered-event tests exercise coalescing.
    stream
        .write_all(format!("{}{body}", sse_head(body.len())).as_bytes())
        .await
        .unwrap();
    // A negative/host-stop client may already have retired its response.
    let _ = stream.shutdown().await;
}

async fn assert_released(stream: &mut Tls) {
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte).await {
        Ok(0) | Err(_) => {}
        Ok(_) => panic!("a retired subscription must not send another request"),
    }
}

#[test]
fn managed_task_listen_delivers_before_eof_and_retains_exact_requested_ids() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session).with_tasks();
        let (acknowledged, mut receipt) = oneshot::channel::<()>();
        let mut acknowledged = Some(acknowledged);
        let mut observed = Vec::new();
        let mut observer = |event: &Event| {
            match event {
                Event::Acknowledged { accepted_filter } => {
                    assert_eq!(
                        serde_json::to_value(accepted_filter).unwrap(),
                        json!({"taskIds":["task-1"]})
                    );
                    observed.push("ack".to_owned());
                    acknowledged.take().unwrap().send_blocking(()).unwrap();
                }
                Event::TaskNotification(notification) => {
                    assert_eq!(notification.params.task.base().task_id, id());
                    assert_eq!(
                        notification
                            .params
                            .meta
                            .as_ref()
                            .unwrap()
                            .get("x-observation"),
                        Some(&json!("retained"))
                    );
                    let task = serde_json::to_value(&notification.params.task).unwrap();
                    observed.push(task["status"].as_str().unwrap().to_owned());
                }
                _ => panic!("only the acknowledgement and Tasks events reach observers"),
            }
            ControlFlow::Continue(())
        };
        let (result, ()) = pair(
            client.listen_task_events(
                &cx,
                vec![id(), id(), FinalTaskId::parse("task-2").unwrap()],
                3,
                PAYLOAD_BYTES,
                &mut observer,
            ),
            async {
                peer.discovery("access-one", true).await;
                let (mut stream, request) =
                    peer.request("subscriptions/listen", "access-one").await;
                assert_eq!(
                    request["params"]["notifications"],
                    json!({"taskIds":["task-1","task-1","task-2"]})
                );
                let ack = sse_frame(&acknowledgement(&request["id"], json!(["task-1"])));
                let rest: String = [
                    status_event(&request["id"], "working"),
                    status_event(&request["id"], "completed"),
                    terminal(&request["id"]),
                ]
                .iter()
                .map(sse_frame)
                .collect();
                stream
                    .write_all(format!("{}{ack}", sse_head(ack.len() + rest.len())).as_bytes())
                    .await
                    .unwrap();
                // The terminal body has NOT been sent. A collector instead of
                // incremental delivery deadlocks here and hits the fixture guard.
                receipt.recv(&cx).await.unwrap();
                stream.write_all(rest.as_bytes()).await.unwrap();
                let _ = stream.shutdown().await;
            },
        )
        .await;
        assert!(result.unwrap().is_some());
        assert_eq!(observed, ["ack", "working", "completed"]);
        assert_eq!(client.cached_credential_generation(), Some(1));
        peer.no_more(&cx).await;
    });
}

#[test]
fn managed_task_listen_rejects_foreign_or_unacknowledged_events_and_premature_eof() {
    for case in 0..6 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session).with_tasks();
            let mut observations = 0;
            let mut observer = |_: &Event| {
                observations += 1;
                ControlFlow::Continue(())
            };
            let (result, ()) = pair(
                client.listen_task_events(&cx, vec![id()], 8, PAYLOAD_BYTES, &mut observer),
                async {
                    peer.discovery("access-one", true).await;
                    let (mut stream, request) =
                        peer.request("subscriptions/listen", "access-one").await;
                    let ack = acknowledgement(&request["id"], json!(["task-1"]));
                    let mut notification = status_event(&request["id"], "working");
                    let frames = match case {
                        0 => vec![acknowledgement(&request["id"], json!(["unrequested"]))],
                        1 => {
                            notification["params"]["taskId"] = json!("unrequested");
                            vec![ack, notification]
                        }
                        2 => {
                            notification["params"]["_meta"][SUB_ID] = json!("foreign-subscription");
                            vec![ack, notification]
                        }
                        3 => vec![notification],
                        4 => vec![ack.clone(), ack],
                        5 => vec![ack, notification], // valid prefix, missing terminal
                        _ => unreachable!(),
                    };
                    finite_stream(&mut stream, &frames).await;
                },
            )
            .await;
            assert!(result.is_err(), "case {case}");
            assert_eq!(
                observations,
                match case {
                    0 | 3 => 0,
                    5 => 2,
                    _ => 1,
                }
            );
            assert_eq!(client.cached_credential_generation(), None);
            assert!(!cx.is_cancel_requested());
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn managed_task_listen_host_stop_is_not_a_peer_terminal_or_remote_task_cancel() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session.clone()).with_tasks();
        let mut observations = 0;
        let mut observer = |event: &Event| {
            observations += 1;
            if matches!(event, Event::TaskNotification(_)) {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        };
        let (result, ()) = pair(
            client.listen_task_events(&cx, vec![id()], 8, PAYLOAD_BYTES, &mut observer),
            async {
                peer.discovery("access-one", true).await;
                let (mut stream, request) =
                    peer.request("subscriptions/listen", "access-one").await;
                finite_stream(
                    &mut stream,
                    &[
                        acknowledgement(&request["id"], json!(["task-1"])),
                        status_event(&request["id"], "working"),
                        status_event(&request["id"], "completed"),
                        terminal(&request["id"]),
                    ],
                )
                .await;
            },
        )
        .await;
        assert!(result.unwrap().is_none());
        assert_eq!(
            observations, 2,
            "buffered later events are not published after host stop"
        );
        assert_eq!(client.cached_credential_generation(), Some(1));
        assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
        peer.no_more(&cx).await;
        let (next, _) = pair(
            client.get_task_final(&cx, id()),
            peer.rpc(
                "tasks/get",
                "access-one",
                task("working", "complete"),
                false,
            ),
        )
        .await;
        assert!(
            next.is_ok(),
            "a normal local stop retains usable discovery, not the live stream"
        );
    });
}

#[test]
fn managed_task_listen_callback_cancellation_or_logout_stops_coalesced_later_events() {
    for logout in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session.clone()).with_tasks();
            let cancellation = McpRequestCancellation::new();
            let mut observations = 0;
            let mut observer = |_: &Event| {
                observations += 1;
                if logout {
                    session.close();
                } else {
                    cancellation.cancel();
                }
                ControlFlow::Continue(())
            };
            let (result, ()) = pair(
                client.listen_task_events_with_cancellation(
                    &cx,
                    &cancellation,
                    vec![id()],
                    8,
                    PAYLOAD_BYTES,
                    &mut observer,
                ),
                async {
                    peer.discovery("access-one", true).await;
                    let (mut stream, request) =
                        peer.request("subscriptions/listen", "access-one").await;
                    finite_stream(
                        &mut stream,
                        &[
                            acknowledgement(&request["id"], json!(["task-1"])),
                            status_event(&request["id"], "working"),
                            status_event(&request["id"], "completed"),
                            terminal(&request["id"]),
                        ],
                    )
                    .await;
                },
            )
            .await;
            if logout {
                assert!(matches!(
                    result,
                    Err(ManagedHttpClientError::Session(OAuthSessionError::Closed))
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(ManagedHttpClientError::Session(
                        OAuthSessionError::Cancelled
                    ))
                ));
            }
            assert_eq!(observations, 1);
            assert_eq!(client.cached_credential_generation(), None);
            assert!(!cx.is_cancel_requested());
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn managed_task_listen_idle_cancellation_logout_and_deadline_release_the_response() {
    for cause in 0..3 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session.clone()).with_tasks();
            let (primed, ()) = pair(client.get_task_final(&cx, id()), async {
                peer.discovery("access-one", true).await;
                peer.rpc(
                    "tasks/get",
                    "access-one",
                    task("working", "complete"),
                    false,
                )
                .await;
            })
            .await;
            primed.unwrap();
            if cause == 2 {
                client.operation_timeout = Duration::from_secs(2);
            }
            let cancellation = McpRequestCancellation::new();
            let (observed, mut receipt) = oneshot::channel::<()>();
            let mut observed = Some(observed);
            let mut observer = |event: &Event| {
                assert!(matches!(event, Event::Acknowledged { .. }));
                observed.take().unwrap().send_blocking(()).unwrap();
                ControlFlow::Continue(())
            };
            let (result, ()) = pair(
                client.listen_task_events_with_cancellation(
                    &cx,
                    &cancellation,
                    vec![id()],
                    8,
                    PAYLOAD_BYTES,
                    &mut observer,
                ),
                async {
                    let (mut stream, request) =
                        peer.request("subscriptions/listen", "access-one").await;
                    let ack = sse_frame(&acknowledgement(&request["id"], json!(["task-1"])));
                    stream
                        .write_all(format!("{}{ack}", sse_head(ack.len() + 1024)).as_bytes())
                        .await
                        .unwrap();
                    receipt.recv(&cx).await.unwrap();
                    match cause {
                        0 => {
                            cancellation.cancel();
                        }
                        1 => {
                            session.close();
                        }
                        2 => {} // no peer activity; the original deadline must wake it
                        _ => unreachable!(),
                    }
                    assert_released(&mut stream).await;
                },
            )
            .await;
            match cause {
                0 => assert!(matches!(
                    result,
                    Err(ManagedHttpClientError::Session(
                        OAuthSessionError::Cancelled
                    ))
                )),
                1 => assert!(matches!(
                    result,
                    Err(ManagedHttpClientError::Session(OAuthSessionError::Closed))
                )),
                2 => assert!(matches!(
                    result,
                    Err(ManagedHttpClientError::Session(OAuthSessionError::TimedOut))
                )),
                _ => unreachable!(),
            }
            assert_eq!(client.cached_credential_generation(), None);
            assert!(!cx.is_cancel_requested());
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn managed_task_listen_limits_and_activation_refuse_before_unapproved_contact() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session);
        let mut observer =
            |_: &Event| -> ControlFlow<()> { panic!("refused listen invoked observer") };
        assert!(matches!(
            client
                .listen_task_events(&cx, vec![id()], 8, PAYLOAD_BYTES, &mut observer)
                .await,
            Err(ManagedHttpClientError::InvalidPolicy)
        ));
        let mut client = client.with_tasks();
        for (ids, count, bytes) in [
            (vec![], 8, PAYLOAD_BYTES),
            (vec![id(); 129], 8, PAYLOAD_BYTES),
            (vec![id()], 0, PAYLOAD_BYTES),
            (vec![id()], 1025, PAYLOAD_BYTES),
            (vec![id()], 8, 0),
            (vec![id()], 8, 128 * 1024 * 1024 + 1),
        ] {
            assert!(matches!(
                client
                    .listen_task_events(&cx, ids, count, bytes, &mut observer)
                    .await,
                Err(ManagedHttpClientError::InvalidPolicy)
            ));
        }
        let cancelled = McpRequestCancellation::new();
        cancelled.cancel();
        assert!(matches!(
            client
                .listen_task_events_with_cancellation(
                    &cx,
                    &cancelled,
                    vec![id()],
                    8,
                    PAYLOAD_BYTES,
                    &mut observer,
                )
                .await,
            Err(ManagedHttpClientError::Session(
                OAuthSessionError::Cancelled
            ))
        ));
        peer.no_more(&cx).await;
        let (unsupported, ()) = pair(
            client.listen_task_events(&cx, vec![id()], 8, PAYLOAD_BYTES, &mut observer),
            peer.discovery("access-one", false),
        )
        .await;
        assert!(unsupported.is_err());
        assert_eq!(client.cached_credential_generation(), None);
        peer.no_more(&cx).await;
    });
}

#[test]
fn managed_task_listen_counts_acknowledgement_and_refuses_excess_before_callback() {
    for (count, bytes, expected, succeeds) in [
        (1, PAYLOAD_BYTES, 1, false),
        (2, PAYLOAD_BYTES, 2, true),
        (2, 1, 0, false),
    ] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session).with_tasks();
            let mut observations = 0;
            let mut observer = |_: &Event| {
                observations += 1;
                ControlFlow::Continue(())
            };
            let (result, ()) = pair(
                client.listen_task_events(&cx, vec![id()], count, bytes, &mut observer),
                async {
                    peer.discovery("access-one", true).await;
                    let (mut stream, request) =
                        peer.request("subscriptions/listen", "access-one").await;
                    finite_stream(
                        &mut stream,
                        &[
                            acknowledgement(&request["id"], json!(["task-1"])),
                            status_event(&request["id"], "working"),
                            terminal(&request["id"]),
                        ],
                    )
                    .await;
                },
            )
            .await;
            assert_eq!(result.is_ok(), succeeds);
            assert_eq!(observations, expected);
            assert_eq!(
                client.cached_credential_generation(),
                if succeeds { Some(1) } else { None }
            );
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn managed_task_listen_abandonment_drops_the_live_socket_without_task_cancellation() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session.clone()).with_tasks();
        let observed = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&observed);
        let mut observer = move |_: &Event| {
            marker.store(true, Ordering::SeqCst);
            ControlFlow::Continue(())
        };
        let mut stream = {
            let mut operation = Box::pin(client.listen_task_events(
                &cx,
                vec![id()],
                8,
                PAYLOAD_BYTES,
                &mut observer,
            ));
            let mut server = Box::pin(async {
                peer.discovery("access-one", true).await;
                let (mut stream, request) =
                    peer.request("subscriptions/listen", "access-one").await;
                let ack = sse_frame(&acknowledgement(&request["id"], json!(["task-1"])));
                stream
                    .write_all(format!("{}{ack}", sse_head(ack.len() + 1024)).as_bytes())
                    .await
                    .unwrap();
                stream
            });
            let stream = poll_fn(|task| {
                assert!(operation.as_mut().poll(task).is_pending());
                server.as_mut().poll(task)
            })
            .await;
            poll_fn(|task| {
                assert!(operation.as_mut().poll(task).is_pending());
                if observed.load(Ordering::SeqCst) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            stream
        };
        assert_released(&mut stream).await;
        assert_eq!(client.cached_credential_generation(), None);
        assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
        assert!(!cx.is_cancel_requested());
        peer.no_more(&cx).await;
        let (next, ()) = pair(client.get_task_final(&cx, id()), async {
            peer.discovery("access-one", true).await;
            peer.rpc(
                "tasks/get",
                "access-one",
                task("working", "complete"),
                false,
            )
            .await;
        })
        .await;
        assert!(next.is_ok());
    });
}

#[test]
fn managed_task_listen_does_not_renew_or_replay_midstream() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session.clone()).with_tasks();
        let mut observations = 0;
        let mut observer = |event: &Event| {
            observations += 1;
            if matches!(event, Event::Acknowledged { .. }) {
                renew(&session);
            }
            ControlFlow::Continue(())
        };
        let (result, ()) = pair(
            client.listen_task_events(&cx, vec![id()], 8, PAYLOAD_BYTES, &mut observer),
            async {
                peer.discovery("access-one", true).await;
                let (mut stream, request) =
                    peer.request("subscriptions/listen", "access-one").await;
                finite_stream(
                    &mut stream,
                    &[
                        acknowledgement(&request["id"], json!(["task-1"])),
                        status_event(&request["id"], "completed"),
                        terminal(&request["id"]),
                    ],
                )
                .await;
            },
        )
        .await;
        assert!(result.unwrap().is_some());
        assert_eq!(observations, 2);
        assert_eq!(client.cached_credential_generation(), Some(1));
        peer.no_more(&cx).await;
        let (next, ()) = pair(client.get_task_final(&cx, id()), async {
            peer.token(true).await;
            peer.discovery("access-two", true).await;
            peer.rpc(
                "tasks/get",
                "access-two",
                task("completed", "complete"),
                false,
            )
            .await;
        })
        .await;
        assert!(next.is_ok());
        assert_eq!(client.cached_credential_generation(), Some(2));
    });
}
