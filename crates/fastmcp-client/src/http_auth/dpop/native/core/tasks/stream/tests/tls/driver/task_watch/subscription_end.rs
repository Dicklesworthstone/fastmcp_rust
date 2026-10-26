//! Exercise both public listeners and Task reconciliation on the existing
//! resource-bound TLS peer. No alternate transport, credentials or trust roots.
use super::*;
use crate::http_auth::dpop::native::core::stream::task_subscription::{
    DpopTaskSubscription, DpopTaskSubscriptionEvent,
};
use fastmcp_protocol::{CoreResult, FinalSubscriptionsListenParams};

#[derive(Clone, Copy)]
enum Ending { Cancel, Complete, CancelComplete, CompleteCancel }

const ENDINGS: [Ending; 4] = [Ending::Cancel, Ending::Complete,
    Ending::CancelComplete, Ending::CompleteCancel];

fn cancellation(prefix: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","method":"notifications/cancelled",
        "params":{"requestId":format!("{prefix}.listen"),"reason":"peer-only-canary",
            "_meta":{FINAL_SUBSCRIPTION_ID_META_KEY:format!("{prefix}.listen")}}})).unwrap()
}

fn terminal_wire(prefix: &str, ending: Ending) -> Vec<u8> {
    let cancel = event_chunk(&cancellation(prefix));
    let complete = event_chunk(&watch_terminal(prefix));
    match ending {
        Ending::Cancel => cancel,
        Ending::Complete => complete,
        Ending::CancelComplete => [cancel, complete].concat(),
        Ending::CompleteCancel => [complete, cancel].concat(),
    }
}

fn core_params() -> FinalSubscriptionsListenParams {
    serde_json::from_value(json!({"_meta":driver_metadata(),
        "notifications":{"toolsListChanged":true}})).unwrap()
}

fn acknowledgement(prefix: &str, tasks: bool) -> Vec<u8> {
    if tasks { watch_ack(prefix, true) } else {
        serde_json::to_vec(&json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged",
            "params":{"notifications":{"toolsListChanged":true},
                "_meta":{FINAL_SUBSCRIPTION_ID_META_KEY:format!("{prefix}.listen")}}})).unwrap()
    }
}

impl Peer {
    async fn core_listen_for_termination(&mut self, prefix: &str) -> TlsStream<TcpStream> {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut socket = self.acceptor.accept(socket).await.unwrap();
        let (head, body) = read(&mut socket).await;
        assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
        assert_eq!(body["id"], format!("{prefix}.listen"));
        assert_eq!(body["method"], "subscriptions/listen");
        assert_eq!(body["params"]["notifications"], json!({"toolsListChanged":true}));
        assert!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
            .as_object().is_none_or(serde_json::Map::is_empty));
        assert_eq!(header(&head, "authorization"), "DPoP stream-task-token");
        assert_eq!(header(&head, "mcp-method"), "subscriptions/listen");
        assert_eq!(header(&head, "accept"), "application/json, text/event-stream");
        assert!(!head.lines().any(|line| line.split_once(':')
            .is_some_and(|(name, _)| name.eq_ignore_ascii_case("mcp-name"))));
        assert!(admit_final_http_request(FinalHttpRequestMetadata {
            version: RequestVersionMetadata {
                header_version: Some(header(&head, "mcp-protocol-version")),
                body_version: body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"].as_str(),
            },
            header_method: Some("subscriptions/listen"), body_method: Some("subscriptions/listen"),
            header_name: None, body_name: None,
        }).is_ok());
        let proof = claims(header(&head, "dpop"));
        assert_eq!(proof["htm"], "POST");
        assert_eq!(proof["htu"], self.target.split('?').next().unwrap());
        if self.proofs.is_empty() { assert!(proof.get("nonce").is_none()); }
        else { assert_eq!(proof["nonce"], "stream-next"); }
        assert!(proof["ath"].as_str().is_some_and(|value| !value.is_empty()));
        assert!(self.proofs.insert(proof["jti"].as_str().unwrap().to_owned()));
        socket
    }

    fn only_requests(&self, count: usize) {
        assert_eq!(self.proofs.len(), count);
        assert!(self.listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(),
            "no hidden discovery, reconnect, mutation or remote cancellation");
    }
}

#[allow(clippy::too_many_arguments)]
async fn listen(
    client: &mut DpopHttpClient, cx: &Cx, cancellation: &McpRequestCancellation,
    credential: &DpopCredential, tasks: bool, prefix: &str, selected: DpopStreamLimits,
    observed: &McpRequestCancellation, calls: &mut usize,
) -> Result<CoreResult, DpopStreamError> {
    if tasks {
        let selection = DpopTaskSubscription::new(
            RequestId::String(format!("{prefix}.listen.discover")),
            RequestId::String(format!("{prefix}.listen")), driver_metadata(),
            vec![TaskId::parse("task-one").unwrap()],
        ).unwrap();
        client.listen_tasks_with_events(cx, cancellation, credential, selection, selected, |event| {
            assert!(matches!(event, DpopTaskSubscriptionEvent::Acknowledged(_)));
            *calls += 1;
            observed.cancel();
            true
        }).await
    } else {
        client.listen_core_with_events(cx, cancellation, credential, core_params(),
            RequestId::String(format!("{prefix}.listen")), selected, |event| {
                assert!(matches!(event, ServerNotification::SubscriptionsAcknowledged(_)));
                *calls += 1;
                observed.cancel();
                true
            }).await
    }
}

#[test]
fn public_core_and_task_listeners_publish_the_first_terminal_without_http_eof() {
    for tasks in [false, true] {
        for ending in ENDINGS {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let cancellation = McpRequestCancellation::new();
                let observed = McpRequestCancellation::new();
                let finished = McpRequestCancellation::new();
                let mut calls = 0;
                let application = async {
                    let result = listen(&mut client, &cx, &cancellation, &credential,
                        tasks, "end", watch_limits(1), &observed, &mut calls).await;
                    finished.cancel();
                    result
                };
                let server = async {
                    let mut socket = if tasks { peer.watch_listen("end").await }
                        else { peer.core_listen_for_termination("end").await };
                    socket.write_all(HEAD).await.unwrap();
                    event(&mut socket, &acknowledgement("end", tasks)).await;
                    observed.cancelled().await;
                    socket.write_all(&terminal_wire("end", ending)).await.unwrap();
                    socket.flush().await.unwrap();
                    // Deliberately omit the HTTP terminal chunk. The admitted
                    // first terminal must release the response on its own.
                    assert_watch_closed(&mut socket).await;
                    assert!(finished.is_cancel_requested());
                };
                let (result, ()) = pair(application, server).await;
                if matches!(ending, Ending::Cancel | Ending::CancelComplete) {
                    assert!(matches!(result, Err(DpopStreamError::SubscriptionCancelled)));
                } else { assert!(matches!(result.unwrap(), CoreResult::Final(_))); }
                assert_eq!(calls, 1, "teardown signals are not application notifications");
                let requests = if tasks { 2 } else { 1 };
                peer.only_requests(requests);
                assert!(!cancellation.is_cancel_requested());
                assert!(cx.checkpoint().is_ok());
                assert!(!client.revocation_handle().is_revoked());
                followup(&mut peer, &mut client, &credential).await;
                peer.only_requests(requests + 2);
            });
        }
    }
}

#[test]
fn watch_reconciles_completion_but_peer_cancellation_stops_without_recovery() {
    for ending in ENDINGS {
        for final_status in ["working", "input_required", "cancelled"] {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let cancellation = McpRequestCancellation::new();
                let cancelled = matches!(ending, Ending::Cancel | Ending::CancelComplete);
                let policy = if cancelled {
                    watch_policy(3).with_reconnects(1, Duration::from_millis(1)).unwrap()
                        .with_polling_fallback(1, Duration::from_millis(1)).unwrap()
                } else { watch_policy(3) };
                let application = client.watch_task_with_cancellation(
                    &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                    "reconcile", policy, watch_limits(1),
                );
                let server = async {
                    peer.watch_snapshot_reply("reconcile", 0, "working").await;
                    let mut socket = peer.watch_listen("reconcile").await;
                    socket.write_all(HEAD).await.unwrap();
                    event(&mut socket, &watch_ack("reconcile", true)).await;
                    peer.watch_snapshot_reply("reconcile", 1, "working").await;
                    socket.write_all(&terminal_wire("reconcile", ending)).await.unwrap();
                    socket.flush().await.unwrap();
                    assert_watch_closed(&mut socket).await;
                    // Completion permits explicit reconciliation. Cancellation
                    // cannot turn configured recovery into successor requests.
                    if !cancelled {
                        peer.watch_snapshot_reply("reconcile", 2, final_status).await;
                    }
                };
                let (result, ()) = pair(application, server).await;
                if cancelled {
                    assert!(matches!(result, Err(DpopTaskWatchError::Stream(
                        DpopStreamError::SubscriptionCancelled))));
                } else { match final_status {
                    "working" => assert!(matches!(result, Err(DpopTaskWatchError::SubscriptionEndedWhileWorking))),
                    "input_required" => assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::InputRequired(_))),
                    _ => assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::Terminal(snapshot)
                        if matches!(snapshot.task, Task::Cancelled(_)))),
                }}
                let requests = if cancelled { 6 } else { 8 };
                peer.only_requests(requests);
                assert!(!cancellation.is_cancel_requested());
                assert!(cx.checkpoint().is_ok());
                followup(&mut peer, &mut client, &credential).await;
                peer.only_requests(requests + 2);
            });
        }
    }
}

#[test]
fn invalid_watch_termination_never_schedules_a_final_get_or_replays_the_listen() {
    for failure in 0..6 {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let application = client.watch_task_with_cancellation(
                &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                "invalid-end", watch_policy(3), watch_limits(4),
            );
            let server = async {
                peer.watch_snapshot_reply("invalid-end", 0, "working").await;
                let mut socket = peer.watch_listen("invalid-end").await;
                socket.write_all(HEAD).await.unwrap();
                event(&mut socket, &watch_ack("invalid-end", true)).await;
                peer.watch_snapshot_reply("invalid-end", 1, "working").await;
                let mut invalid: Value = serde_json::from_slice(&self::cancellation("invalid-end")).unwrap();
                match failure {
                    0 => invalid["params"]["requestId"] = json!("foreign.listen"),
                    1 => invalid["params"]["_meta"][FINAL_SUBSCRIPTION_ID_META_KEY] = json!("foreign.listen"),
                    2 => { invalid["params"].as_object_mut().unwrap().remove("_meta"); }
                    3 => invalid["params"]["_meta"][FINAL_SUBSCRIPTION_ID_META_KEY] = Value::Null,
                    4 => invalid["params"]["requestId"] = json!(41),
                    _ => invalid["params"]["_meta"] = json!({}),
                }
                let mut wire = event_chunk(&serde_json::to_vec(&invalid).unwrap());
                wire.extend_from_slice(b"0\r\n\r\n");
                socket.write_all(&wire).await.unwrap();
                let _ = socket.shutdown().await;
            };
            let (result, ()) = pair(application, server).await;
            assert!(result.is_err());
            assert!(matches!(result, Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                DpopCoreError::Protocol(ManagedCoreError::ResponseIdMismatch))))));
            peer.only_requests(6);
            followup(&mut peer, &mut client, &credential).await;
            peer.only_requests(8);
        });
    }
}

#[test]
fn local_cancellation_and_idle_expiry_retire_a_listen_before_any_terminal() {
    for tasks in [false, true] {
        for idle in [false, true] {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let cancellation = McpRequestCancellation::new();
                let observed = McpRequestCancellation::new();
                let mut calls = 0;
                let selected = DpopStreamLimits::new(watch_limits(1).core,
                    if idle { Duration::from_secs(1) } else { Duration::from_secs(5) }).unwrap();
                let application = async {
                    let listening = listen(&mut client, &cx, &cancellation, &credential,
                        tasks, "silent-end", selected, &observed, &mut calls);
                    if idle {
                        asupersync::time::timeout_at(cx.now().saturating_add_nanos(3_000_000_000), listening)
                            .await.expect("idle expiry must precede the absolute request deadline")
                    } else { listening.await }
                };
                let server = async {
                    let mut socket = if tasks { peer.watch_listen("silent-end").await }
                        else { peer.core_listen_for_termination("silent-end").await };
                    socket.write_all(HEAD).await.unwrap();
                    event(&mut socket, &acknowledgement("silent-end", tasks)).await;
                    observed.cancelled().await;
                    if !idle {
                        cancellation.cancel();
                    }
                    assert_watch_closed(&mut socket).await;
                };
                let (result, ()) = pair(application, server).await;
                let expected = if idle { DpopHttpError::TimedOut } else { DpopHttpError::Cancelled };
                assert!(matches!(result, Err(DpopStreamError::Core(DpopCoreError::Transport(error)))
                    if error == expected));
                assert_eq!(calls, 1);
                let requests = if tasks { 2 } else { 1 };
                peer.only_requests(requests);
                assert!(cx.checkpoint().is_ok());
                assert!(!client.revocation_handle().is_revoked());
                followup(&mut peer, &mut client, &credential).await;
                peer.only_requests(requests + 2);
            });
        }
    }
}

#[test]
fn buffered_core_and_tasks_terminals_cannot_outlive_original_request_or_credential_authority() {
    for tasks in [false, true] {
        for ending in [Ending::Cancel, Ending::Complete] {
            for retire in 0..3 {
                run(async {
                    let cx = Cx::current().unwrap();
                    let (mut peer, mut client, credential) = Peer::new().await;
                    let cancellation = McpRequestCancellation::new();
                    let revocation = client.revocation_handle();
                    let mut calls = 0;
                    let mut after_ack = || {
                        calls += 1;
                        match retire {
                            0 => { cancellation.cancel(); }
                            1 => { credential.revoke(); }
                            _ => { revocation.revoke(); }
                        }
                    };
                    let application = async {
                        if tasks {
                            let selection = DpopTaskSubscription::new(
                                RequestId::String("retired.listen.discover".to_owned()),
                                RequestId::String("retired.listen".to_owned()), driver_metadata(),
                                vec![TaskId::parse("task-one").unwrap()],
                            ).unwrap();
                            client.listen_tasks_with_events(&cx, &cancellation, &credential,
                                selection, watch_limits(1), |event| {
                                    assert!(matches!(event, DpopTaskSubscriptionEvent::Acknowledged(_)));
                                    after_ack();
                                    true
                                }).await
                        } else {
                            client.listen_core_with_events(&cx, &cancellation, &credential,
                                core_params(), RequestId::String("retired.listen".to_owned()),
                                watch_limits(1), |event| {
                                    assert!(matches!(event, ServerNotification::SubscriptionsAcknowledged(_)));
                                    after_ack();
                                    true
                                }).await
                        }
                    };
                    let server = async {
                        let mut socket = if tasks { peer.watch_listen("retired").await }
                            else { peer.core_listen_for_termination("retired").await };
                        socket.write_all(HEAD).await.unwrap();
                        let mut wire = event_chunk(&acknowledgement("retired", tasks));
                        wire.extend_from_slice(&terminal_wire("retired", ending));
                        socket.write_all(&wire).await.unwrap();
                        socket.flush().await.unwrap();
                        assert_watch_closed(&mut socket).await;
                    };
                    let (result, ()) = pair(application, server).await;
                    if retire == 0 {
                        assert!(matches!(result, Err(DpopStreamError::Core(DpopCoreError::Transport(
                            DpopHttpError::Cancelled)))));
                    } else {
                        assert!(matches!(result, Err(DpopStreamError::Core(DpopCoreError::Transport(
                            DpopHttpError::Authorization(_))))));
                    }
                    assert_eq!(calls, 1);
                    peer.only_requests(if tasks { 2 } else { 1 });
                    assert!(cx.checkpoint().is_ok());
                });
            }
        }
    }
}
