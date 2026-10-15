//! Public event-driven watches through the existing real TLS and DPoP fixture.

use super::*;
use crate::http_auth::dpop::native::core::stream::task_subscription::watch::{
    DpopTaskWatchError, DpopTaskWatchPolicy,
};
use fastmcp_protocol::FINAL_SUBSCRIPTION_ID_META_KEY;

fn watch_policy(maximum: usize) -> DpopTaskWatchPolicy {
    DpopTaskWatchPolicy::new(maximum).unwrap()
}

fn watch_limits(notifications: usize) -> DpopStreamLimits {
    DpopStreamLimits::new(
        ManagedCoreLimits::new(8192, 8192, 65536, notifications, Duration::from_secs(10)).unwrap(),
        Duration::from_secs(5),
    ).unwrap()
}

fn watch_ack(prefix: &str, selected: bool) -> Vec<u8> {
    let ids: Vec<&str> = if selected { vec!["task-one"] } else { vec![] };
    serde_json::to_vec(&json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged",
        "params":{"notifications":{"taskIds":ids},
            "_meta":{FINAL_SUBSCRIPTION_ID_META_KEY:format!("{prefix}.listen")}}})).unwrap()
}

fn watch_status(prefix: &str, status: &str) -> Vec<u8> {
    let mut params = task_result(status);
    params.as_object_mut().unwrap().remove("resultType");
    params["_meta"] = json!({FINAL_SUBSCRIPTION_ID_META_KEY:format!("{prefix}.listen")});
    serde_json::to_vec(&json!({"jsonrpc":"2.0", "method":"notifications/tasks", "params":params})).unwrap()
}

fn watch_terminal(prefix: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":format!("{prefix}.listen"),
        "result":{"resultType":"complete",
            "_meta":{FINAL_SUBSCRIPTION_ID_META_KEY:format!("{prefix}.listen")}}})).unwrap()
}

fn watch_discovery(prefix: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":format!("{prefix}.listen.discover"),
        "result":discovery_result()})).unwrap()
}

impl Peer {
    async fn watch_listen(&mut self, prefix: &str) -> TlsStream<TcpStream> {
        let (mut discovery, _) = self.receive_named(
            &format!("{prefix}.listen.discover"), "server/discover",
        ).await;
        json_reply(&mut discovery, &watch_discovery(prefix)).await;
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut socket = self.acceptor.accept(socket).await.unwrap();
        let (head, body) = read(&mut socket).await;
        assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
        assert_eq!(body["id"], format!("{prefix}.listen"));
        assert_eq!(body["method"], "subscriptions/listen");
        assert_eq!(body["params"]["notifications"], json!({"taskIds":["task-one"]}));
        assert_eq!(header(&head, "authorization"), "DPoP stream-task-token");
        assert_eq!(header(&head, "mcp-method"), "subscriptions/listen");
        assert_eq!(header(&head, "accept"), "application/json, text/event-stream");
        assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
            json!({TASKS_EXTENSION:{}}));
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
        assert_eq!(proof["nonce"], "stream-next");
        assert!(proof["ath"].as_str().is_some_and(|hash| !hash.is_empty()));
        assert!(self.proofs.insert(proof["jti"].as_str().unwrap().to_owned()));
        socket
    }

    async fn watch_snapshot_reply(&mut self, prefix: &str, round: usize, status: &str) {
        let mut socket = self.wait_round(prefix, round).await;
        json_reply(&mut socket, &wait_response(prefix, round, false, &task_result(status))).await;
    }
}

async fn assert_watch_closed(socket: &mut TlsStream<TcpStream>) {
    let mut byte = [0_u8; 1];
    assert!(matches!(socket.read(&mut byte).await, Ok(0) | Err(_)),
        "stopping observation must retire the listen socket");
}

async fn followup(peer: &mut Peer, client: &mut DpopHttpClient, credential: &DpopCredential) {
    let cx = Cx::current().unwrap();
    let cancellation = McpRequestCancellation::new();
    let request = client.wait_task_with_cancellation(
        &cx, &cancellation, credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
        "followup", DpopTaskWaitPolicy::new(1, Duration::from_millis(1)).unwrap(),
        ManagedCoreLimits::default(),
    );
    let (result, ()) = pair(request, peer.watch_snapshot_reply("followup", 0, "cancelled")).await;
    assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::Terminal(_)));
}

#[test]
fn watch_closes_the_get_ack_race_without_requiring_a_status_event() {
    for stale_hint in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let application = client.watch_task_with_cancellation(
                &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                "race", watch_policy(2), watch_limits(4),
            );
            let server = async {
                peer.watch_snapshot_reply("race", 0, "working").await;
                let mut listen = peer.watch_listen("race").await;
                let mut wire = HEAD.to_vec();
                wire.extend_from_slice(&event_chunk(&watch_ack("race", true)));
                if stale_hint { wire.extend_from_slice(&event_chunk(&watch_status("race", "working"))); }
                listen.write_all(&wire).await.unwrap();
                // There is deliberately no completion event and no stream EOF.
                // The authoritative get must run while this socket is open.
                peer.watch_snapshot_reply("race", 1, "cancelled").await;
                assert_watch_closed(&mut listen).await;
            };
            let (result, ()) = pair(application, server).await;
            assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::Terminal(snapshot)
                if matches!(snapshot.task, Task::Cancelled(_))));
            peer.no_extra(3);
            assert!(!client.revocation_handle().is_revoked());
            assert!(cx.checkpoint().is_ok());
            followup(&mut peer, &mut client, &credential).await;
            peer.no_extra(4);
        });
    }
}

#[test]
fn watch_reconciles_events_and_stream_end_but_never_treats_a_hint_as_success() {
    for still_working in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let application = client.watch_task_with_cancellation(
                &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                "hints", watch_policy(4), watch_limits(4),
            );
            let server = async {
                peer.watch_snapshot_reply("hints", 0, "working").await;
                let mut listen = peer.watch_listen("hints").await;
                listen.write_all(HEAD).await.unwrap();
                event(&mut listen, &watch_ack("hints", true)).await;
                peer.watch_snapshot_reply("hints", 1, "working").await;
                // A quiet interval may not generate another discovery/get.
                asupersync::time::Sleep::new(cx.now().saturating_add_nanos(10_000_000)).await;
                peer.no_extra(3);
                // Even a terminal notification is only a hint. The newer get
                // still says Working and therefore must not return that hint.
                event(&mut listen, &watch_status("hints", "cancelled")).await;
                peer.watch_snapshot_reply("hints", 2, "working").await;
                let mut end = event_chunk(&watch_terminal("hints"));
                end.extend_from_slice(b"0\r\n\r\n");
                listen.write_all(&end).await.unwrap();
                let _ = listen.shutdown().await;
                peer.watch_snapshot_reply("hints", 3,
                    if still_working { "working" } else { "input_required" }).await;
            };
            let (result, ()) = pair(application, server).await;
            if still_working {
                assert!(matches!(result, Err(DpopTaskWatchError::SubscriptionEndedWhileWorking)));
            } else {
                assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::InputRequired(_)));
            }
            peer.no_extra(5);
            followup(&mut peer, &mut client, &credential).await;
            peer.no_extra(6);
        });
    }
}

#[derive(Clone, Copy)]
enum WatchRefusal { MissingTask, EarlyEof, WrongTask, SnapshotLimit }

#[test]
fn watch_refusals_stop_before_an_unauthorized_or_unbudgeted_reconciliation() {
    for case in [WatchRefusal::MissingTask, WatchRefusal::EarlyEof,
        WatchRefusal::WrongTask, WatchRefusal::SnapshotLimit]
    {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let application = client.watch_task_with_cancellation(
                &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                "refused", watch_policy(if matches!(case, WatchRefusal::SnapshotLimit) { 1 } else { 4 }),
                watch_limits(4),
            );
            let server = async {
                peer.watch_snapshot_reply("refused", 0, "working").await;
                if matches!(case, WatchRefusal::SnapshotLimit) { return; }
                let mut listen = peer.watch_listen("refused").await;
                let mut wire = HEAD.to_vec();
                if matches!(case, WatchRefusal::MissingTask) {
                    wire.extend_from_slice(&event_chunk(&watch_ack("refused", false)));
                } else if matches!(case, WatchRefusal::WrongTask) {
                    wire.extend_from_slice(&event_chunk(&watch_ack("refused", true)));
                    listen.write_all(&wire).await.unwrap();
                    peer.watch_snapshot_reply("refused", 1, "working").await;
                    wire.clear();
                    let mut status: Value = serde_json::from_slice(&watch_status("refused", "working")).unwrap();
                    status["params"]["taskId"] = json!("foreign-task");
                    wire.extend_from_slice(&event_chunk(&serde_json::to_vec(&status).unwrap()));
                }
                wire.extend_from_slice(b"0\r\n\r\n");
                listen.write_all(&wire).await.unwrap();
                let _ = listen.shutdown().await;
            };
            let (result, ()) = pair(application, server).await;
            match case {
                WatchRefusal::MissingTask => assert!(matches!(result,
                    Err(DpopTaskWatchError::TaskNotAcknowledged))),
                WatchRefusal::SnapshotLimit => assert!(matches!(result,
                    Err(DpopTaskWatchError::SnapshotLimit))),
                WatchRefusal::EarlyEof | WatchRefusal::WrongTask => assert!(result.is_err()),
            }
            peer.no_extra(match case {
                WatchRefusal::SnapshotLimit => 1,
                WatchRefusal::WrongTask => 3,
                _ => 2,
            });
            followup(&mut peer, &mut client, &credential).await;
        });
    }
}

#[test]
fn watch_enforces_one_exact_budget_across_get_listen_and_post_ack_get() {
    for short in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let first = watch_discovery("quota");
            let acknowledgement = watch_ack("quota", true);
            let mut total = first.len() + acknowledgement.len();
            let mut maximum = first.len().max(acknowledgement.len());
            for (round, status) in [(0, "working"), (1, "cancelled")] {
                for bytes in [
                    wait_response("quota", round, true, &discovery_result()),
                    wait_response("quota", round, false, &task_result(status)),
                ] {
                    total += bytes.len();
                    maximum = maximum.max(bytes.len());
                }
            }
            let core = ManagedCoreLimits::new(8192, maximum, total - usize::from(short),
                1, Duration::from_secs(10)).unwrap();
            let selected = DpopStreamLimits::new(core, Duration::from_secs(5)).unwrap();
            let application = client.watch_task_with_cancellation(
                &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                "quota", watch_policy(2), selected,
            );
            let server = async {
                peer.watch_snapshot_reply("quota", 0, "working").await;
                let mut listen = peer.watch_listen("quota").await;
                listen.write_all(HEAD).await.unwrap();
                event(&mut listen, &watch_ack("quota", true)).await;
                peer.watch_snapshot_reply("quota", 1, "cancelled").await;
                assert_watch_closed(&mut listen).await;
            };
            let (result, ()) = pair(application, server).await;
            if short {
                assert!(matches!(result, Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                    DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit))))));
            } else { assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::Terminal(_))); }
            peer.no_extra(3);
        });
    }
}

#[test]
fn quiet_watch_cancellation_and_idle_timeout_close_only_owned_requests() {
    for idle_timeout in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let selected = if idle_timeout {
                DpopStreamLimits::new(watch_limits(4).core, Duration::from_secs(1)).unwrap()
            } else { watch_limits(4) };
            let application = async {
                let watch = client.watch_task_with_cancellation(
                    &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                    "quiet", watch_policy(4), selected,
                );
                if idle_timeout {
                    // The much later absolute deadline cannot satisfy the idle test.
                    asupersync::time::timeout_at(cx.now().saturating_add_nanos(3_000_000_000), watch)
                        .await.expect("the one-second listen idle deadline must win")
                } else { watch.await }
            };
            let server = async {
                peer.watch_snapshot_reply("quiet", 0, "working").await;
                let mut listen = peer.watch_listen("quiet").await;
                listen.write_all(HEAD).await.unwrap();
                event(&mut listen, &watch_ack("quiet", true)).await;
                peer.watch_snapshot_reply("quiet", 1, "working").await;
                if !idle_timeout { cancellation.cancel(); }
                assert_watch_closed(&mut listen).await;
            };
            let (result, ()) = pair(application, server).await;
            let expected = if idle_timeout { DpopHttpError::TimedOut } else { DpopHttpError::Cancelled };
            assert!(matches!(result, Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                DpopCoreError::Transport(error)))) if error == expected));
            peer.no_extra(3);
            assert!(!client.revocation_handle().is_revoked());
            assert!(cx.checkpoint().is_ok());
            followup(&mut peer, &mut client, &credential).await;
        });
    }
}

#[test]
fn already_finished_or_input_required_tasks_need_no_subscription() {
    for status in ["cancelled", "input_required"] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let application = client.watch_task_with_cancellation(
                &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                "ready", watch_policy(1), watch_limits(0),
            );
            let (result, ()) = pair(application, peer.watch_snapshot_reply("ready", 0, status)).await;
            if status == "cancelled" {
                assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::Terminal(_)));
            } else { assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::InputRequired(_))); }
            peer.no_extra(1);
        });
    }
}

#[derive(Clone, Copy)]
enum ReconciliationPhase { Discovery, GetHead, GetBody }

#[derive(Clone, Copy)]
enum WatchRetirement { Cancel, Credential, Session, Abandon, Idle }

#[test]
fn watch_retirement_releases_the_listen_and_stalled_reconciliation_together() {
    for phase in [ReconciliationPhase::Discovery, ReconciliationPhase::GetHead,
        ReconciliationPhase::GetBody]
    {
        for retirement in [WatchRetirement::Cancel, WatchRetirement::Credential,
            WatchRetirement::Session, WatchRetirement::Abandon, WatchRetirement::Idle]
        {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let cancellation = McpRequestCancellation::new();
                let reached = McpRequestCancellation::new();
                let session = client.revocation_handle();
                let idle = matches!(retirement, WatchRetirement::Idle);
                let selected = if idle {
                    DpopStreamLimits::new(watch_limits(4).core, Duration::from_secs(1)).unwrap()
                } else { watch_limits(4) };
                let application = async {
                    let mut watch = Box::pin(client.watch_task_with_cancellation(
                        &cx, &cancellation, &credential, driver_metadata(),
                        TaskId::parse("task-one").unwrap(), "retire", watch_policy(4), selected,
                    ));
                    if matches!(retirement, WatchRetirement::Abandon) {
                        let mut ready = std::pin::pin!(reached.cancelled());
                        poll_fn(|context| {
                            assert!(watch.as_mut().poll(context).is_pending(),
                                "no complete authoritative snapshot is available");
                            ready.as_mut().poll(context)
                        }).await;
                        drop(watch);
                    } else {
                        let result = if idle {
                            asupersync::time::timeout_at(
                                cx.now().saturating_add_nanos(3_000_000_000), watch,
                            ).await.expect("listen idle also bounds a silent reconciliation")
                        } else { watch.await };
                        let error = result.err().expect("unfinished reconciliation cannot succeed");
                        match retirement {
                            WatchRetirement::Cancel => assert!(matches!(error,
                                DpopTaskWatchError::Stream(DpopStreamError::Core(
                                    DpopCoreError::Transport(DpopHttpError::Cancelled))))),
                            WatchRetirement::Credential | WatchRetirement::Session => assert!(matches!(error,
                                DpopTaskWatchError::Stream(DpopStreamError::Core(
                                    DpopCoreError::Transport(DpopHttpError::Authorization(_)))))),
                            WatchRetirement::Idle => assert!(matches!(error,
                                DpopTaskWatchError::Stream(DpopStreamError::Core(
                                    DpopCoreError::Transport(DpopHttpError::TimedOut))))),
                            WatchRetirement::Abandon => unreachable!(),
                        }
                    }
                };
                let server = async {
                    peer.watch_snapshot_reply("retire", 0, "working").await;
                    let mut listen = peer.watch_listen("retire").await;
                    listen.write_all(HEAD).await.unwrap();
                    event(&mut listen, &watch_ack("retire", true)).await;
                    let mut stalled = match phase {
                        ReconciliationPhase::Discovery => {
                            peer.receive_named("retire.1.discover", "server/discover").await.0
                        }
                        ReconciliationPhase::GetHead | ReconciliationPhase::GetBody => {
                            peer.wait_round("retire", 1).await
                        }
                    };
                    if matches!(phase, ReconciliationPhase::GetBody) {
                        // Supply a valid incremental reply but never its terminal
                        // or HTTP EOF. The listen remains open at the same time.
                        stalled.write_all(HEAD).await.unwrap();
                        event(&mut stalled, &progress(json!("work"), "1")).await;
                    }
                    reached.cancel();
                    match retirement {
                        WatchRetirement::Cancel => { cancellation.cancel(); }
                        WatchRetirement::Credential => { credential.revoke(); }
                        WatchRetirement::Session => { session.revoke(); }
                        WatchRetirement::Abandon | WatchRetirement::Idle => {}
                    }
                    // Peer I/O uses its still-live ambient Cx, so an error here
                    // is socket retirement, not cancellation of the test server.
                    pair(assert_watch_closed(&mut listen), assert_watch_closed(&mut stalled)).await;
                };
                pair(application, server).await;
                let requests = if matches!(phase, ReconciliationPhase::Discovery) { 5 } else { 6 };
                assert_eq!(peer.proofs.len(), requests);
                assert!(peer.listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(),
                    "retirement must not reconnect, retry, get or cancel remotely");
                assert!(cx.checkpoint().is_ok());
                assert_eq!(client.revocation_handle().is_revoked(),
                    matches!(retirement, WatchRetirement::Session));
                if matches!(retirement, WatchRetirement::Cancel | WatchRetirement::Abandon | WatchRetirement::Idle) {
                    followup(&mut peer, &mut client, &credential).await;
                    assert_eq!(peer.proofs.len(), requests + 2);
                }
            });
        }
    }
}
