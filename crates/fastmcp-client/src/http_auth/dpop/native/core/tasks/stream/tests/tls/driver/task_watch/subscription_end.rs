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
        "params":{"requestId":format!("{prefix}.listen"),"reason":"peer-only-canary"}})).unwrap()
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
fn public_core_and_task_listeners_publish_the_first_terminal_only_after_clean_eof() {
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
                    // The first signal and its optional counterpart are available,
                    // but neither result nor peer cancellation may settle yet.
                    asupersync::time::Sleep::new(cx.now().saturating_add_nanos(10_000_000)).await;
                    assert!(!finished.is_cancel_requested(), "terminal escaped before HTTP EOF");
                    socket.write_all(b"0\r\n\r\n").await.unwrap();
                    let _ = socket.shutdown().await;
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
fn watch_reconciles_each_peer_ending_without_equating_subscription_and_task_cancellation() {
    for ending in ENDINGS {
        for final_status in ["working", "input_required", "cancelled"] {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let cancellation = McpRequestCancellation::new();
                let application = client.watch_task_with_cancellation(
                    &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                    "reconcile", watch_policy(3), watch_limits(1),
                );
                let server = async {
                    peer.watch_snapshot_reply("reconcile", 0, "working").await;
                    let mut socket = peer.watch_listen("reconcile").await;
                    socket.write_all(HEAD).await.unwrap();
                    event(&mut socket, &watch_ack("reconcile", true)).await;
                    peer.watch_snapshot_reply("reconcile", 1, "working").await;
                    let mut wire = terminal_wire("reconcile", ending);
                    wire.extend_from_slice(b"0\r\n\r\n");
                    socket.write_all(&wire).await.unwrap();
                    let _ = socket.shutdown().await;
                    // A fresh get is mandatory after either terminal signal;
                    // the listen's state is not an authoritative Task snapshot.
                    peer.watch_snapshot_reply("reconcile", 2, final_status).await;
                };
                let (result, ()) = pair(application, server).await;
                match final_status {
                    "working" => assert!(matches!(result, Err(DpopTaskWatchError::SubscriptionEndedWhileWorking))),
                    "input_required" => assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::InputRequired(_))),
                    _ => assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::Terminal(snapshot)
                        if matches!(snapshot.task, Task::Cancelled(_)))),
                }
                peer.only_requests(8);
                assert!(!cancellation.is_cancel_requested());
                assert!(cx.checkpoint().is_ok());
                followup(&mut peer, &mut client, &credential).await;
                peer.only_requests(10);
            });
        }
    }
}

#[test]
fn invalid_watch_termination_never_schedules_a_final_get_or_replays_the_listen() {
    for failure in 0..4 {
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
                let mut wire = terminal_wire("invalid-end", Ending::Cancel);
                match failure {
                    0 => wire.extend_from_slice(&event_chunk(&watch_terminal("foreign"))),
                    1 => wire.extend_from_slice(&terminal_wire("invalid-end", Ending::Cancel)),
                    2 => wire.extend_from_slice(&event_chunk(&watch_status("invalid-end", "cancelled"))),
                    _ => wire.extend_from_slice(&chunk(b"data: unfinished")),
                }
                wire.extend_from_slice(b"0\r\n\r\n");
                socket.write_all(&wire).await.unwrap();
                let _ = socket.shutdown().await;
            };
            let (result, ()) = pair(application, server).await;
            assert!(result.is_err());
            assert!(!matches!(result, Err(DpopTaskWatchError::SubscriptionEndedWhileWorking)),
                "invalid EOF is not a successfully reconciled Working snapshot");
            peer.only_requests(6);
            followup(&mut peer, &mut client, &credential).await;
            peer.only_requests(8);
        });
    }
}

#[test]
fn local_cancellation_and_idle_expiry_win_while_a_remote_terminal_lacks_eof() {
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
                    socket.write_all(&terminal_wire("silent-end", Ending::Cancel)).await.unwrap();
                    if !idle {
                        asupersync::time::Sleep::new(cx.now().saturating_add_nanos(10_000_000)).await;
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
