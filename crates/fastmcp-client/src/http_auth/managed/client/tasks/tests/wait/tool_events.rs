//! Observe public managed tool calls through the existing native OAuth/TLS peer.

use super::super::*;
use asupersync::channel::oneshot;
use fastmcp_protocol::{JsonRpcRequest, ProgressMarker, ServerNotification};

const EVENT_BYTES: usize = 64 * 1024;

fn marker() -> ProgressMarker {
    serde_json::from_value(json!("progress-雪")).unwrap()
}

fn progress(value: u64) -> Value {
    json!({"jsonrpc":"2.0", "method":"notifications/progress", "params":{
        "progressToken":"progress-雪", "progress":value
    }})
}

fn outcome(kind: usize) -> Value {
    match kind {
        0 => json!({"resultType":"complete", "content":[], "isError":true}),
        1 => task("working", "task"),
        2 => json!({"resultType":"input_required", "requestState":"opaque-state",
            "inputRequests":{"roots":{"method":"roots/list"}}}),
        _ => unreachable!(),
    }
}

fn assert_outcome(value: FinalToolCallOutcome, kind: usize) {
    match (value, kind) {
        (FinalToolCallOutcome::Complete(result), 0) => assert!(result.payload.is_error),
        (FinalToolCallOutcome::Task(result), 1) => assert_eq!(result.task.base().task_id, id()),
        (FinalToolCallOutcome::InputRequired(result), 2) => {
            let encoded = fastmcp_protocol::encode_result(
                &fastmcp_protocol::DecodedResult::InputRequired(result),
            );
            assert_eq!(serde_json::from_str::<Value>(&encoded).unwrap(), outcome(2));
        }
        _ => panic!("the exact tool outcome must be retained"),
    }
}

fn terminal(request: &Value, kind: usize) -> Value {
    json!({"jsonrpc":"2.0", "id":request["id"], "result":outcome(kind)})
}

fn frame(value: &Value) -> String {
    format!("data: {value}\n\n")
}

fn head(length: usize) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
    )
}

async fn frames(stream: &mut Tls, values: &[Value]) {
    let body: String = values.iter().map(frame).collect();
    stream
        .write_all(format!("{}{body}", head(body.len())).as_bytes())
        .await
        .unwrap();
    // Negative cases may already have disposed the response owner.
    let _ = stream.shutdown().await;
}

async fn request(peer: &Peer) -> (Tls, Value) {
    let (stream, request) = peer.request("tools/call", "access-one").await;
    assert_eq!(request["params"]["name"], "build");
    assert_eq!(request["params"]["arguments"], json!({"input":7}));
    assert_eq!(request["params"]["_meta"]["progressToken"], "progress-雪");
    (stream, request)
}

async fn released(stream: &mut Tls) {
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte).await {
        Ok(0) | Err(_) => {}
        Ok(_) => panic!("a retired tool response must not receive more request bytes"),
    }
}

#[test]
fn live_tool_notifications_precede_the_terminal_and_preserve_every_outcome() {
    for kind in 0..3 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session.clone()).with_tasks();
            let marker = marker();
            let (delivered, mut receipt) = oneshot::channel::<()>();
            let mut delivered = Some(delivered);
            let mut observed = Vec::new();
            let mut observer = |notification: &ServerNotification| {
                let wire = serde_json::to_value(notification.encode().unwrap()).unwrap();
                observed.push(wire);
                if let Some(delivered) = delivered.take() {
                    delivered.send_blocking(()).unwrap();
                }
                Ok(())
            };
            let (result, ()) = Box::pin(pair(
                client.call_tool_final_outcome_with_events(
                    &cx,
                    "build",
                    json!({"input":7}),
                    Some(&marker),
                    4,
                    EVENT_BYTES,
                    &mut observer,
                ),
                async {
                    peer.discovery("access-one", true).await;
                    let (mut stream, request) = request(&peer).await;
                    let first = frame(&progress(9_007_199_254_740_992));
                    let rest: String = [
                        json!({"jsonrpc":"2.0", "method":"notifications/message",
                            "params":{"level":"info", "data":"working"}}),
                        json!({"jsonrpc":"2.0", "method":"notifications/tools/list_changed",
                            "params":{}}),
                        progress(9_007_199_254_740_993),
                        terminal(&request, kind),
                    ]
                    .iter()
                    .map(frame)
                    .collect();
                    stream
                        .write_all(format!("{}{first}", head(first.len() + rest.len())).as_bytes())
                        .await
                        .unwrap();
                    // The terminal has NOT been sent. A collector cannot satisfy
                    // this rendezvous, even though all notifications are small.
                    receipt.recv(&cx).await.unwrap();
                    stream.write_all(rest.as_bytes()).await.unwrap();
                    let _ = stream.shutdown().await;
                },
            ))
            .await;
            assert_outcome(result.unwrap(), kind);
            assert_eq!(observed.len(), 4);
            assert_eq!(
                observed[0]["params"]["progress"],
                json!(9_007_199_254_740_992_u64)
            );
            assert_eq!(observed[1]["method"], "notifications/message");
            assert_eq!(observed[2]["method"], "notifications/tools/list_changed");
            assert_eq!(
                observed[3]["params"]["progress"],
                json!(9_007_199_254_740_993_u64)
            );
            assert_eq!(client.cached_credential_generation(), None);
            peer.no_more(&cx).await;
            // A catalog event was delivered; stale ordinary caches cannot survive.
            let (next, ()) = Box::pin(pair(client.get_task_final(&cx, id()), async {
                peer.discovery("access-one", true).await;
                peer.rpc("tasks/get", "access-one", task("working", "complete"), false)
                    .await;
            }))
            .await;
            assert!(next.is_ok());
            assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
        });
    }
}

#[test]
fn live_tool_json_outcomes_need_no_notification_allowance_or_second_post() {
    for kind in 0..3 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session).with_tasks();
            let mut count = 0;
            let mut observer = |_: &ServerNotification| {
                count += 1;
                Ok(())
            };
            let (result, ()) = Box::pin(pair(
                client.call_tool_final_outcome_with_events(
                    &cx,
                    "build",
                    json!({}),
                    None,
                    0,
                    1,
                    &mut observer,
                ),
                async {
                    peer.discovery("access-one", true).await;
                    let request = peer
                        .rpc("tools/call", "access-one", outcome(kind), false)
                        .await;
                    assert!(request["params"]["_meta"].get("progressToken").is_none());
                },
            ))
            .await;
            assert_outcome(result.unwrap(), kind);
            assert_eq!(count, 0);
            assert_eq!(client.cached_credential_generation(), None);
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn live_tool_progress_is_incremental_beyond_the_old_collector_queue_limit() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session).with_tasks();
        let marker = marker();
        let mut count = 0;
        let mut observer = |_: &ServerNotification| {
            count += 1;
            Ok(())
        };
        let (result, ()) = Box::pin(pair(
            client.call_tool_final_outcome_with_events(
                &cx,
                "build",
                json!({"input":7}),
                Some(&marker),
                65,
                EVENT_BYTES,
                &mut observer,
            ),
            async {
                peer.discovery("access-one", true).await;
                let (mut stream, request) = request(&peer).await;
                let mut values: Vec<_> = (1..=65).map(progress).collect();
                values.push(terminal(&request, 0));
                frames(&mut stream, &values).await;
            },
        ))
        .await;
        assert_outcome(result.unwrap(), 0);
        assert_eq!(count, 65);
        peer.no_more(&cx).await;
    });
}

#[test]
fn live_tool_limits_are_exact_and_fail_before_the_unadmitted_callback() {
    let encoded_bytes = |value: Value| {
        let request: JsonRpcRequest = serde_json::from_value(value).unwrap();
        serde_json::to_vec(
            &ServerNotification::decode(&request)
                .unwrap()
                .encode()
                .unwrap(),
        )
        .unwrap()
        .len()
    };
    let exact = encoded_bytes(progress(1)) + encoded_bytes(progress(2));
    for (count_limit, byte_limit, expected_calls, succeeds) in [
        (2, exact, 2, true),
        (2, exact - 1, 1, false),
        (1, exact, 1, false),
        (0, exact, 0, false),
    ] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session).with_tasks();
            let marker = marker();
            let mut count = 0;
            let mut observer = |_: &ServerNotification| {
                count += 1;
                Ok(())
            };
            let (result, ()) = Box::pin(pair(
                client.call_tool_final_outcome_with_events(
                    &cx,
                    "build",
                    json!({"input":7}),
                    Some(&marker),
                    count_limit,
                    byte_limit,
                    &mut observer,
                ),
                async {
                    peer.discovery("access-one", true).await;
                    let (mut stream, request) = request(&peer).await;
                    frames(&mut stream, &[progress(1), progress(2), terminal(&request, 0)]).await;
                },
            ))
            .await;
            assert_eq!(result.is_ok(), succeeds);
            assert_eq!(count, expected_calls);
            assert_eq!(client.cached_credential_generation(), None);
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn live_tool_rejects_foreign_or_regressing_progress_and_uncorrelated_terminals() {
    for case in 0..5 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session).with_tasks();
            let marker = marker();
            let mut count = 0;
            let mut observer = |_: &ServerNotification| {
                count += 1;
                Ok(())
            };
            let (result, ()) = Box::pin(pair(
                client.call_tool_final_outcome_with_events(
                    &cx,
                    "build",
                    json!({"input":7}),
                    Some(&marker),
                    8,
                    EVENT_BYTES,
                    &mut observer,
                ),
                async {
                    peer.discovery("access-one", true).await;
                    let (mut stream, request) = request(&peer).await;
                    let mut invalid = progress(3);
                    match case {
                        0 => invalid["params"]["progressToken"] = json!("foreign"),
                        1 => invalid["params"]["progress"] = json!(2),
                        2 => invalid["params"]["progress"] = json!(1),
                        3 => invalid["params"]["progress"] = json!(-1),
                        _ => {
                            invalid = terminal(&request, 0);
                            invalid["id"] = json!("foreign-response");
                        }
                    }
                    frames(&mut stream, &[progress(2), invalid, terminal(&request, 0)]).await;
                },
            ))
            .await;
            assert!(result.is_err(), "case {case}");
            assert_eq!(count, 1, "case {case}");
            assert_eq!(client.cached_credential_generation(), None);
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn live_tool_ready_observer_stop_blocks_buffered_events_and_terminal_delivery() {
    for cause in 0..5 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let credential = session.credential(&cx).await.unwrap().credential().clone();
            let mut client = peer.client(session.clone()).with_tasks();
            let cancellation = McpRequestCancellation::new();
            let marker = marker();
            let mut count = 0;
            let mut observer = |_: &ServerNotification| {
                count += 1;
                match cause {
                    0 => {
                        cancellation.cancel();
                    }
                    1 => {
                        session.close();
                    }
                    2 => {
                        credential.revoke();
                    }
                    3 => return Err(McpError::invalid_params("private-observer-error")),
                    _ => panic!("private-observer-panic"),
                }
                Ok(())
            };
            let (result, ()) = Box::pin(pair(
                client.call_tool_final_outcome_with_events_and_cancellation(
                    &cx,
                    &cancellation,
                    "build",
                    json!({"input":7}),
                    Some(&marker),
                    8,
                    EVENT_BYTES,
                    &mut observer,
                ),
                async {
                    peer.discovery("access-one", true).await;
                    let (mut stream, request) = request(&peer).await;
                    frames(&mut stream, &[progress(1), progress(2), terminal(&request, 0)]).await;
                },
            ))
            .await;
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("stopped observers must not publish the buffered terminal"),
            };
            assert_eq!(count, 1);
            assert!(!format!("{error:?} {error}").contains("private-observer"));
            assert_eq!(client.cached_credential_generation(), None);
            assert!(!cx.is_cancel_requested());
            peer.no_more(&cx).await;
            if cause == 0 {
                assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
            }
        });
    }
}

#[test]
fn live_tool_quiet_response_is_released_on_cancellation_logout_revocation_or_deadline() {
    for cause in 0..4 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let credential = session.credential(&cx).await.unwrap().credential().clone();
            let mut client = peer.client(session.clone()).with_tasks();
            let (primed, ()) = Box::pin(pair(client.get_task_final(&cx, id()), async {
                peer.discovery("access-one", true).await;
                peer.rpc("tasks/get", "access-one", task("working", "complete"), false)
                    .await;
            }))
            .await;
            primed.unwrap();
            if cause == 3 {
                client.operation_timeout = Duration::from_secs(2);
            }
            let cancellation = McpRequestCancellation::new();
            let marker = marker();
            let (observed, mut receipt) = oneshot::channel::<()>();
            let mut observed = Some(observed);
            let mut observer = |_: &ServerNotification| {
                observed.take().unwrap().send_blocking(()).unwrap();
                Ok(())
            };
            let (result, ()) = Box::pin(pair(
                client.call_tool_final_outcome_with_events_and_cancellation(
                    &cx,
                    &cancellation,
                    "build",
                    json!({"input":7}),
                    Some(&marker),
                    8,
                    EVENT_BYTES,
                    &mut observer,
                ),
                async {
                    let (mut stream, _) = request(&peer).await;
                    let first = frame(&progress(1));
                    stream
                        .write_all(format!("{}{first}", head(first.len() + 4096)).as_bytes())
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
                        2 => {
                            credential.revoke();
                        }
                        _ => {}
                    }
                    released(&mut stream).await;
                },
            ))
            .await;
            assert!(matches!(result, Err(ManagedHttpClientError::Session(_))));
            assert_eq!(client.cached_credential_generation(), None);
            assert!(!cx.is_cancel_requested());
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn live_tool_abandonment_releases_owned_stream_without_replay_or_remote_cancel() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session.clone()).with_tasks();
        let marker = marker();
        let (observed, mut receipt) = oneshot::channel::<()>();
        let mut observed = Some(observed);
        let mut observer = |_: &ServerNotification| {
            observed.take().unwrap().send_blocking(()).unwrap();
            Ok(())
        };
        let mut stream = {
            let mut operation = Box::pin(client.call_tool_final_outcome_with_events(
                &cx,
                "build",
                json!({"input":7}),
                Some(&marker),
                8,
                EVENT_BYTES,
                &mut observer,
            ));
            let mut server = Box::pin(async {
                peer.discovery("access-one", true).await;
                let (mut stream, _) = request(&peer).await;
                let first = frame(&progress(1));
                stream
                    .write_all(format!("{}{first}", head(first.len() + 4096)).as_bytes())
                    .await
                    .unwrap();
                receipt.recv(&cx).await.unwrap();
                stream
            });
            poll_fn(|task| {
                assert!(operation.as_mut().poll(task).is_pending());
                server.as_mut().poll(task)
            })
            .await
        };
        released(&mut stream).await;
        assert_eq!(client.cached_credential_generation(), None);
        assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
        assert!(!cx.is_cancel_requested());
        peer.no_more(&cx).await;
    });
}

#[test]
fn live_tool_local_policy_refuses_without_contact_or_retiring_an_existing_connection() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session);
        let mut observer = |_: &ServerNotification| {
            panic!("a refused operation cannot call the host")
        };
        assert!(matches!(
            client
                .call_tool_final_outcome_with_events(
                    &cx, "build", json!({}), None, 1, 1024, &mut observer,
                )
                .await,
            Err(ManagedHttpClientError::InvalidPolicy)
        ));
        peer.no_more(&cx).await;
        let mut client = client.with_tasks();
        let (primed, ()) = Box::pin(pair(client.get_task_final(&cx, id()), async {
            peer.discovery("access-one", true).await;
            peer.rpc("tasks/get", "access-one", task("working", "complete"), false)
                .await;
        }))
        .await;
        primed.unwrap();
        for (count, bytes) in [(4097, 1), (1, 0), (1, 128 * 1024 * 1024 + 1)] {
            assert!(matches!(
                client
                    .call_tool_final_outcome_with_events(
                        &cx, "build", json!({}), None, count, bytes, &mut observer,
                    )
                    .await,
                Err(ManagedHttpClientError::InvalidPolicy)
            ));
            assert_eq!(client.cached_credential_generation(), Some(1));
        }
        peer.no_more(&cx).await;
    });
}
