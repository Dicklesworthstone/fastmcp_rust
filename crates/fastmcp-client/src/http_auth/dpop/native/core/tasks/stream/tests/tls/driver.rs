//! Public streamed lifecycle runs on the parent's real, resource-bound TLS peer.
//! No new transport, root certificate, token exchange or scheduler is substituted.

mod default_replies;
mod task_watch;

use super::*;
use asupersync::net::TcpStream;
use asupersync::tls::TlsStream;
use crate::http_auth::dpop::native::core::tasks::driver::{
    DpopTaskDriverError, ManagedTaskDriverPolicy,
    ManagedTaskInputAction, ManagedTaskRunOutcome,
};
use crate::http_auth::dpop::native::core::tasks::wait::{
    DpopTaskWaitError, DpopTaskWaitOutcome, DpopTaskWaitPolicy,
};

fn driver_metadata() -> FinalRequestMeta {
    let mut meta = metadata();
    meta.client_capabilities = serde_json::from_value(json!({"roots":{}})).unwrap();
    meta
}

fn driver_policy(polls: usize, updates: usize, timeout: Duration) -> ManagedTaskDriverPolicy {
    ManagedTaskDriverPolicy::new(Duration::from_millis(1), timeout, polls, updates, 1, 8192).unwrap()
}

fn task_result(status: &str) -> Value {
    let mut result = json!({
        "resultType":"complete", "taskId":"task-one", "status":status,
        "createdAt":"2026-09-16T00:00:00Z", "lastUpdatedAt":"2026-09-16T00:00:00Z",
        "ttlMs":60000, "pollIntervalMs":1,
    });
    if status == "input_required" {
        result["inputRequests"] = json!({"roots":{"method":"roots/list"}});
    }
    result
}

fn driver_response(prefix: &str, round: usize, discovery: bool, result: &Value) -> Vec<u8> {
    let suffix = if discovery { "discover" } else { "task" };
    serde_json::to_vec(&json!({
        "jsonrpc":"2.0", "id":format!("{prefix}.{round}.{suffix}"), "result":result,
    })).unwrap()
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    target: String,
    proofs: BTreeSet<String>,
}

impl Peer {
    async fn new() -> (Self, DpopHttpClient, DpopCredential) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
        let (client, credential, acceptor) = configured(&target);
        (Self { listener, acceptor, target, proofs: BTreeSet::new() }, client, credential)
    }

    async fn receive(&mut self, prefix: &str, round: usize, method: &str) -> (TlsStream<TcpStream>, Value) {
        let suffix = if method == "server/discover" { "discover" } else { "task" };
        self.receive_named(&format!("{prefix}.{round}.{suffix}"), method).await
    }

    async fn receive_named(&mut self, request_id: &str, method: &str) -> (TlsStream<TcpStream>, Value) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut socket = self.acceptor.accept(socket).await.unwrap();
        let (head, body) = read(&mut socket).await;
        let discovery = method == "server/discover";
        assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
        assert_eq!(body["id"], request_id);
        assert_eq!(body["method"], method, "no replay, remote cancellation or hidden request");
        assert_eq!(header(&head, "authorization"), "DPoP stream-task-token");
        assert_eq!(header(&head, "mcp-method"), method);
        assert_eq!(header(&head, "accept"), if discovery { "application/json" }
            else { "application/json, text/event-stream" });
        assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
            json!({TASKS_EXTENSION:{}}));
        let proof = claims(header(&head, "dpop"));
        assert_eq!(proof["htm"], "POST");
        assert_eq!(proof["htu"], self.target.split('?').next().unwrap());
        assert!(proof["ath"].as_str().is_some_and(|hash| !hash.is_empty()));
        if self.proofs.is_empty() { assert!(proof.get("nonce").is_none()); }
        else { assert_eq!(proof["nonce"], "stream-next"); }
        assert!(self.proofs.insert(proof["jti"].as_str().unwrap().to_owned()));
        if discovery {
            assert!(body["params"].get("taskId").is_none());
            assert!(body["params"].get("inputResponses").is_none());
        } else {
            assert_eq!(body["params"]["taskId"], "task-one");
            assert!(admit_final_http_request(FinalHttpRequestMetadata {
                version: RequestVersionMetadata {
                    header_version: Some(header(&head, "mcp-protocol-version")),
                    body_version: body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"].as_str(),
                },
                header_method: Some(header(&head, "mcp-method")),
                body_method: body["method"].as_str(),
                header_name: Some(header(&head, "mcp-name")),
                body_name: body["params"]["taskId"].as_str(),
            }).is_ok());
        }
        (socket, body)
    }

    async fn round(&mut self, prefix: &str, round: usize, method: &str) -> (TlsStream<TcpStream>, Value) {
        let (mut socket, _) = self.receive(prefix, round, "server/discover").await;
        json_reply(&mut socket, &driver_response(prefix, round, true, &discovery_result())).await;
        self.receive(prefix, round, method).await
    }

    async fn wait_round(&mut self, prefix: &str, round: usize) -> TlsStream<TcpStream> {
        let (mut discovery, _) = self.receive_named(
            &format!("{prefix}.{round}.discover"), "server/discover",
        ).await;
        json_reply(&mut discovery, &wait_response(prefix, round, true, &discovery_result())).await;
        let (socket, body) = self.receive_named(&format!("{prefix}.{round}.get"), "tasks/get").await;
        assert!(body["params"].get("inputResponses").is_none());
        socket
    }

    fn no_extra(&self, pairs: usize) {
        assert_eq!(self.proofs.len(), pairs * 2);
        assert!(self.listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
    }
}

const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nDPoP-Nonce: stream-next\r\nConnection: close\r\n\r\n";

async fn streamed_reply(
    socket: &mut TlsStream<TcpStream>, terminal: &[u8],
    first_observed: Option<&McpRequestCancellation>, trailing_ack: bool,
) {
    if let Some(observed) = first_observed {
        socket.write_all(HEAD).await.unwrap();
        event(socket, &progress(json!("work"), "1")).await;
        // A collector which buffers the complete response cannot pass: the
        // terminal does not exist until the high-level notification callback ran.
        observed.cancelled().await;
        let mut tail = event_chunk(terminal);
        if trailing_ack { tail.extend_from_slice(&event_chunk(terminal)); }
        tail.extend_from_slice(b"0\r\n\r\n");
        socket.write_all(&tail).await.unwrap();
    } else {
        let mut wire = HEAD.to_vec();
        wire.extend_from_slice(&event_chunk(&progress(json!("work"), "1")));
        wire.extend_from_slice(&event_chunk(terminal));
        if trailing_ack { wire.extend_from_slice(&event_chunk(terminal)); }
        wire.extend_from_slice(b"0\r\n\r\n");
        // One write keeps intentional quota/tail rejection from racing the
        // fixture's separate trailer write and obscuring the product error.
        socket.write_all(&wire).await.unwrap();
    }
    let _ = socket.shutdown().await;
}

#[test]
fn streamed_driver_resolves_once_and_ignores_acknowledged_stale_inputs() {
    for (json_rounds, expected_notifications) in [
        ([false; 4], 4),
        ([true; 4], 0),
        ([false, true, true, false], 2),
    ] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let observed = McpRequestCancellation::new();
            let (mut resolves, mut snapshots, mut notifications) = (0, 0, 0);
            let application = client.drive_task_with_events(
                &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                "lifecycle", driver_policy(3, 1, Duration::from_secs(10)), limits(4),
                |requests| {
                    resolves += 1;
                    assert_eq!(requests.keys().map(String::as_str).collect::<Vec<_>>(), ["roots"]);
                    std::future::ready(Ok(ManagedTaskInputAction::Respond(
                        serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap(),
                    )))
                },
                |_| { snapshots += 1; Ok(()) },
                |_| { notifications += 1; observed.cancel(); true },
            );
            let server = async {
                for (round, method, result) in [
                    (0, "tasks/get", task_result("input_required")),
                    (1, "tasks/update", json!({"resultType":"complete"})),
                    (2, "tasks/get", task_result("input_required")),
                    (3, "tasks/get", task_result("cancelled")),
                ] {
                    let (mut socket, body) = peer.round("lifecycle", round, method).await;
                    if method == "tasks/update" {
                        assert_eq!(body["params"]["inputResponses"], json!({"roots":{"roots":[]}}));
                    }
                    let bytes = driver_response("lifecycle", round, false, &result);
                    if json_rounds[round] { json_reply(&mut socket, &bytes).await; }
                    else { streamed_reply(&mut socket, &bytes, if round == 0 { Some(&observed) } else { None }, false).await; }
                }
            };
            let (result, ()) = pair(application, server).await;
            assert!(matches!(result.unwrap(), ManagedTaskRunOutcome::Terminal(task)
                if matches!(*task, Task::Cancelled(_))));
            assert_eq!((resolves, snapshots, notifications), (1, 3, expected_notifications));
            peer.no_extra(4);
            assert!(!client.revocation_handle().is_revoked());
            assert!(cx.checkpoint().is_ok());
        });
    }
}

#[test]
fn streamed_update_with_a_trailing_record_stops_before_reconciliation_or_replay() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let cancellation = McpRequestCancellation::new();
        let (mut resolves, mut snapshots, mut notifications) = (0, 0, 0);
        let application = client.drive_task_with_events(
            &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
            "uncertain", driver_policy(3, 1, Duration::from_secs(10)), limits(4),
            |_| {
                resolves += 1;
                std::future::ready(Ok(ManagedTaskInputAction::Respond(
                    serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap(),
                )))
            },
            |_| { snapshots += 1; Ok(()) },
            |_| { notifications += 1; true },
        );
        let server = async {
            for (round, method, result) in [
                (0, "tasks/get", task_result("input_required")),
                (1, "tasks/update", json!({"resultType":"complete"})),
            ] {
                let (mut socket, _) = peer.round("uncertain", round, method).await;
                streamed_reply(&mut socket, &driver_response("uncertain", round, false, &result),
                    None, round == 1).await;
            }
        };
        let (result, ()) = pair(application, server).await;
        assert!(matches!(result, Err(DpopTaskDriverError::Task(DpopTasksError::Core(
            DpopCoreError::Protocol(ManagedCoreError::InvalidResponse))))));
        assert_eq!((resolves, snapshots, notifications), (1, 1, 2));
        peer.no_extra(2);
    });
}

#[derive(Clone, Copy)]
enum Budget { Exact, ByteShort, NotificationShort }

#[test]
fn streamed_driver_enforces_exact_whole_run_bytes_and_notification_counts() {
    for budget in [Budget::Exact, Budget::ByteShort, Budget::NotificationShort] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let mut total = 0_usize;
            let mut maximum = 0_usize;
            for (round, status) in [(0, "working"), (1, "cancelled")] {
                for bytes in [
                    driver_response("quota", round, true, &discovery_result()),
                    progress(json!("work"), "1"),
                    driver_response("quota", round, false, &task_result(status)),
                ] {
                    total += bytes.len();
                    maximum = maximum.max(bytes.len());
                }
            }
            let core = ManagedCoreLimits::new(8192, maximum,
                total - usize::from(matches!(budget, Budget::ByteShort)),
                if matches!(budget, Budget::NotificationShort) { 1 } else { 2 },
                Duration::from_secs(10)).unwrap();
            let selected = DpopStreamLimits::new(core, Duration::from_secs(5)).unwrap();
            let (mut snapshots, mut notifications) = (0, 0);
            let application = client.drive_task_with_events(
                &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                "quota", driver_policy(2, 0, Duration::from_secs(10)), selected,
                |_| {
                    panic!("observation-only driver resolved input");
                    #[allow(unreachable_code)]
                    std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller))
                },
                |_| { snapshots += 1; Ok(()) },
                |_| { notifications += 1; true },
            );
            let server = async {
                for (round, status) in [(0, "working"), (1, "cancelled")] {
                    let (mut socket, _) = peer.round("quota", round, "tasks/get").await;
                    streamed_reply(&mut socket,
                        &driver_response("quota", round, false, &task_result(status)), None, false).await;
                }
            };
            let (result, ()) = pair(application, server).await;
            match budget {
                Budget::Exact => {
                    assert!(matches!(result.unwrap(), ManagedTaskRunOutcome::Terminal(_)));
                    assert_eq!((snapshots, notifications), (2, 2));
                }
                Budget::ByteShort => {
                    assert!(matches!(result, Err(DpopTaskDriverError::Task(DpopTasksError::Core(
                        DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit))))));
                    assert_eq!((snapshots, notifications), (1, 2));
                }
                Budget::NotificationShort => {
                    assert!(matches!(result, Err(DpopTaskDriverError::Task(DpopTasksError::Core(
                        DpopCoreError::Protocol(ManagedCoreError::NotificationLimit))))));
                    assert_eq!((snapshots, notifications), (1, 1));
                }
            }
            peer.no_extra(2);
        });
    }
}

#[derive(Clone, Copy)]
enum Stop { Decline, Cancel, Revoke, Abandon, Idle }

#[test]
fn streamed_driver_releases_silent_replies_on_host_stop_cancel_revoke_drop_and_idle() {
    for stop in [Stop::Decline, Stop::Cancel, Stop::Revoke, Stop::Abandon, Stop::Idle] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let observed = McpRequestCancellation::new();
            let selected = DpopStreamLimits::new(limits(4).core,
                if matches!(stop, Stop::Idle) { Duration::from_secs(1) } else { Duration::from_secs(5) }).unwrap();
            let application = async {
                let mut drive = Box::pin(client.drive_task_with_events(
                    &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                    "stop", driver_policy(2, 0, Duration::from_secs(10)), selected,
                    |_| {
                        panic!("silent stream cannot ask for input");
                        #[allow(unreachable_code)]
                        std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller))
                    },
                    |_| panic!("no terminal means no snapshot publication"),
                    |_| {
                        observed.cancel();
                        if matches!(stop, Stop::Cancel) { cancellation.cancel(); }
                        if matches!(stop, Stop::Revoke) { credential.revoke(); }
                        !matches!(stop, Stop::Decline)
                    },
                ));
                if matches!(stop, Stop::Abandon) {
                    poll_fn(|task| {
                        assert!(drive.as_mut().poll(task).is_pending());
                        if observed.is_cancel_requested() { Poll::Ready(()) } else { Poll::Pending }
                    }).await;
                    drop(drive);
                } else {
                    let result = if matches!(stop, Stop::Idle) {
                        // A reset/lost idle timer must not pass merely by waiting
                        // for the much later ten-second absolute driver deadline.
                        asupersync::time::timeout_at(cx.now().saturating_add_nanos(3_000_000_000), drive)
                            .await.expect("the one-second idle cap must win before the absolute deadline")
                    } else { drive.await };
                    let error = result.err().expect("a silent stopped stream cannot succeed");
                    match stop {
                        Stop::Decline => assert!(matches!(error, DpopTaskDriverError::Stream(DpopStreamError::ObserverStopped))),
                        Stop::Cancel => assert!(matches!(error, DpopTaskDriverError::Task(DpopTasksError::Core(
                            DpopCoreError::Transport(DpopHttpError::Cancelled))))),
                        Stop::Revoke => assert!(matches!(error, DpopTaskDriverError::Task(DpopTasksError::Core(
                            DpopCoreError::Transport(DpopHttpError::Authorization(_)))))),
                        Stop::Idle => assert!(matches!(error, DpopTaskDriverError::Task(DpopTasksError::Core(
                            DpopCoreError::Transport(DpopHttpError::TimedOut))))),
                        Stop::Abandon => unreachable!(),
                    }
                }
            };
            let server = async {
                let (mut socket, _) = peer.round("stop", 0, "tasks/get").await;
                socket.write_all(HEAD).await.unwrap();
                event(&mut socket, &progress(json!("work"), "1")).await;
                observed.cancelled().await;
                let mut byte = [0];
                assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0),
                    "abandonment/stop must release the owned response without a peer terminal");
            };
            pair(application, server).await;
            peer.no_extra(1);
            assert!(cx.checkpoint().is_ok());
            assert!(!client.revocation_handle().is_revoked());
        });
    }
}

#[test]
fn streamed_driver_keeps_the_original_deadline_while_honoring_a_long_poll_hint() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let cancellation = McpRequestCancellation::new();
        let mut snapshots = 0;
        let application = client.drive_task_with_events(
            &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
            "deadline", driver_policy(2, 0, Duration::from_secs(2)), limits(4),
            |_| std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller)),
            |_| { snapshots += 1; Ok(()) }, |_| true,
        );
        let server = async {
            let (mut socket, _) = peer.round("deadline", 0, "tasks/get").await;
            let mut task = task_result("working");
            task["pollIntervalMs"] = json!(60000);
            streamed_reply(&mut socket, &driver_response("deadline", 0, false, &task), None, false).await;
        };
        let (result, ()) = pair(application, server).await;
        assert!(matches!(result, Err(DpopTaskDriverError::Task(DpopTasksError::Core(
            DpopCoreError::Transport(DpopHttpError::TimedOut))))));
        assert_eq!(snapshots, 1, "the first stream must complete before the bounded poll wait");
        peer.no_extra(1);
        assert!(cx.checkpoint().is_ok());
    });
}

fn wait_policy(polls: usize) -> DpopTaskWaitPolicy {
    DpopTaskWaitPolicy::new(polls, Duration::from_millis(1)).unwrap()
}

fn wait_response(prefix: &str, round: usize, discovery: bool, result: &Value) -> Vec<u8> {
    let suffix = if discovery { "discover" } else { "get" };
    serde_json::to_vec(&json!({
        "jsonrpc":"2.0", "id":format!("{prefix}.{round}.{suffix}"), "result":result,
    })).unwrap()
}

async fn wait_follow_up(peer: &mut Peer, client: &mut DpopHttpClient, cx: &Cx, credential: &DpopCredential) {
    let application = client.wait_task(
        cx, credential, metadata(), TaskId::parse("task-one").unwrap(),
        "after", wait_policy(1), limits(0).core,
    );
    let server = async {
        let mut socket = peer.wait_round("after", 0).await;
        json_reply(&mut socket, &wait_response("after", 0, false, &task_result("cancelled"))).await;
    };
    let (result, ()) = pair(application, server).await;
    assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::Terminal(snapshot)
        if matches!(snapshot.task, Task::Cancelled(_))));
    assert!(cx.checkpoint().is_ok());
    assert!(!client.revocation_handle().is_revoked());
}

#[test]
fn public_waiter_preserves_json_sse_progress_and_input_handoff_without_mutation() {
    for explicit_events in [false, true] {
        for json_rounds in [[false, false], [true, true], [false, true]] {
            for final_status in ["cancelled", "input_required"] {
                run(async {
                    let cx = Cx::current().unwrap();
                    let (mut peer, mut client, credential) = Peer::new().await;
                    let cancellation = McpRequestCancellation::new();
                    let observed = McpRequestCancellation::new();
                    let mut notifications = 0;
                    let application = async {
                        if explicit_events {
                            client.wait_task_with_events(
                                &cx, &cancellation, &credential, metadata(), TaskId::parse("task-one").unwrap(),
                                "observe", wait_policy(2), limits(2),
                                |notification| {
                                    assert!(matches!(notification, ServerNotification::Progress(_)));
                                    notifications += 1;
                                    observed.cancel();
                                    true
                                },
                            ).await
                        } else {
                            client.wait_task_with_cancellation(
                                &cx, &cancellation, &credential, metadata(), TaskId::parse("task-one").unwrap(),
                                "observe", wait_policy(2), limits(2).core,
                            ).await
                        }
                    };
                    let server = async {
                        for (round, status) in [(0, "working"), (1, final_status)] {
                            let mut socket = peer.wait_round("observe", round).await;
                            let bytes = wait_response("observe", round, false, &task_result(status));
                            if json_rounds[round] { json_reply(&mut socket, &bytes).await; }
                            else {
                                streamed_reply(&mut socket, &bytes,
                                    if explicit_events && round == 0 { Some(&observed) } else { None }, false).await;
                            }
                        }
                    };
                    let (result, ()) = pair(application, server).await;
                    match (final_status, result.unwrap()) {
                        ("cancelled", DpopTaskWaitOutcome::Terminal(snapshot)) => {
                            assert!(matches!(snapshot.task, Task::Cancelled(_)));
                        }
                        ("input_required", DpopTaskWaitOutcome::InputRequired(snapshot)) => {
                            assert!(matches!(snapshot.task, Task::InputRequired { .. }));
                        }
                        _ => panic!("waiter must preserve the selected Task outcome"),
                    }
                    let expected = if explicit_events { json_rounds.iter().filter(|json| !**json).count() } else { 0 };
                    assert_eq!(notifications, expected);
                    peer.no_extra(2);
                    wait_follow_up(&mut peer, &mut client, &cx, &credential).await;
                    peer.no_extra(3);
                });
            }
        }
    }
}

#[test]
fn public_waiter_charges_notifications_and_bytes_across_actual_https_polls() {
    for budget in [Budget::Exact, Budget::ByteShort, Budget::NotificationShort] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let mut total = 0;
            let mut maximum = 0;
            for (round, status) in [(0, "working"), (1, "cancelled")] {
                for bytes in [
                    wait_response("quota", round, true, &discovery_result()),
                    progress(json!("work"), "1"),
                    wait_response("quota", round, false, &task_result(status)),
                ] {
                    total += bytes.len();
                    maximum = maximum.max(bytes.len());
                }
            }
            let core = ManagedCoreLimits::new(8192, maximum,
                total - usize::from(matches!(budget, Budget::ByteShort)),
                if matches!(budget, Budget::NotificationShort) { 1 } else { 2 },
                Duration::from_secs(10)).unwrap();
            let mut notifications = 0;
            let application = client.wait_task_with_events(
                &cx, &cancellation, &credential, metadata(), TaskId::parse("task-one").unwrap(),
                "quota", wait_policy(2), DpopStreamLimits::new(core, Duration::from_secs(5)).unwrap(),
                |_| { notifications += 1; true },
            );
            let server = async {
                for (round, status) in [(0, "working"), (1, "cancelled")] {
                    let mut socket = peer.wait_round("quota", round).await;
                    streamed_reply(&mut socket, &wait_response("quota", round, false, &task_result(status)), None, false).await;
                }
            };
            let (result, ()) = pair(application, server).await;
            match budget {
                Budget::Exact => {
                    assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::Terminal(_)));
                    assert_eq!(notifications, 2);
                }
                Budget::ByteShort => {
                    assert!(matches!(result, Err(DpopTaskWaitError::Task(DpopTasksError::Core(
                        DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit))))));
                    assert_eq!(notifications, 2);
                }
                Budget::NotificationShort => {
                    assert!(matches!(result, Err(DpopTaskWaitError::Task(DpopTasksError::Core(
                        DpopCoreError::Protocol(ManagedCoreError::NotificationLimit))))));
                    assert_eq!(notifications, 1);
                }
            }
            peer.no_extra(2);
            wait_follow_up(&mut peer, &mut client, &cx, &credential).await;
            peer.no_extra(3);
        });
    }
}

#[derive(Clone, Copy)]
enum WaitFailure {
    DuplicateTerminal, IncompleteTail, MissingTerminal, ForeignId, WrongTask,
    Decline, Cancel, Revoke, Abandon, Idle,
}

#[test]
fn public_waiter_withholds_provisional_snapshots_and_retires_failed_streams() {
    for failure in [WaitFailure::DuplicateTerminal, WaitFailure::IncompleteTail,
        WaitFailure::MissingTerminal, WaitFailure::ForeignId, WaitFailure::WrongTask,
        WaitFailure::Decline, WaitFailure::Cancel, WaitFailure::Revoke,
        WaitFailure::Abandon, WaitFailure::Idle]
    {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let observed = McpRequestCancellation::new();
            let selected = DpopStreamLimits::new(limits(4).core,
                if matches!(failure, WaitFailure::Idle) { Duration::from_secs(1) } else { Duration::from_secs(5) }).unwrap();
            let mut notifications = 0;
            let application = async {
                let mut waiting = Box::pin(client.wait_task_with_events(
                    &cx, &cancellation, &credential, metadata(), TaskId::parse("task-one").unwrap(),
                    "refused", wait_policy(2), selected,
                    |_| {
                        notifications += 1;
                        observed.cancel();
                        if matches!(failure, WaitFailure::Cancel) { cancellation.cancel(); }
                        if matches!(failure, WaitFailure::Revoke) { credential.revoke(); }
                        !matches!(failure, WaitFailure::Decline)
                    },
                ));
                if matches!(failure, WaitFailure::Abandon) {
                    poll_fn(|task| {
                        assert!(waiting.as_mut().poll(task).is_pending());
                        if observed.is_cancel_requested() { Poll::Ready(()) } else { Poll::Pending }
                    }).await;
                    drop(waiting);
                } else {
                    let result = if matches!(failure, WaitFailure::Idle) {
                        asupersync::time::timeout_at(cx.now().saturating_add_nanos(3_000_000_000), waiting)
                            .await.expect("one-second idle cap must beat the absolute wait deadline")
                    } else { waiting.await };
                    let error = result.err().expect("refused stream cannot publish its provisional snapshot");
                    match failure {
                        WaitFailure::Decline => assert!(matches!(error,
                            DpopTaskWaitError::Stream(DpopStreamError::ObserverStopped))),
                        WaitFailure::Cancel => assert!(matches!(error, DpopTaskWaitError::Task(DpopTasksError::Core(
                            DpopCoreError::Transport(DpopHttpError::Cancelled))))),
                        WaitFailure::Revoke => assert!(matches!(error, DpopTaskWaitError::Task(DpopTasksError::Core(
                            DpopCoreError::Transport(DpopHttpError::Authorization(_)))))),
                        WaitFailure::Idle => assert!(matches!(error, DpopTaskWaitError::Task(DpopTasksError::Core(
                            DpopCoreError::Transport(DpopHttpError::TimedOut))))),
                        WaitFailure::ForeignId => assert!(matches!(error, DpopTaskWaitError::Task(DpopTasksError::Task(
                            ManagedTasksError::ResponseIdMismatch)))),
                        WaitFailure::WrongTask => assert!(matches!(error, DpopTaskWaitError::Task(DpopTasksError::Task(
                            ManagedTasksError::TaskIdMismatch)))),
                        WaitFailure::DuplicateTerminal | WaitFailure::IncompleteTail | WaitFailure::MissingTerminal => {}
                        WaitFailure::Abandon => unreachable!(),
                    }
                }
            };
            let server = async {
                let mut socket = peer.wait_round("refused", 0).await;
                socket.write_all(HEAD).await.unwrap();
                event(&mut socket, &progress(json!("work"), "1")).await;
                observed.cancelled().await;
                if matches!(failure, WaitFailure::Decline | WaitFailure::Cancel | WaitFailure::Revoke
                    | WaitFailure::Abandon | WaitFailure::Idle)
                {
                    let mut byte = [0];
                    assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0),
                        "the waiter must drop the silent response without a peer terminal");
                    return;
                }
                let mut result = task_result("cancelled");
                if matches!(failure, WaitFailure::WrongTask) { result["taskId"] = json!("task-two"); }
                let mut envelope: Value = serde_json::from_slice(&wait_response("refused", 0, false, &result)).unwrap();
                if matches!(failure, WaitFailure::ForeignId) { envelope["id"] = json!("foreign"); }
                let terminal = serde_json::to_vec(&envelope).unwrap();
                let mut tail = Vec::new();
                if !matches!(failure, WaitFailure::MissingTerminal) {
                    tail.extend_from_slice(&event_chunk(&terminal));
                }
                if matches!(failure, WaitFailure::DuplicateTerminal) {
                    tail.extend_from_slice(&event_chunk(&terminal));
                }
                if matches!(failure, WaitFailure::IncompleteTail) {
                    tail.extend_from_slice(&chunk(b"data: unfinished"));
                }
                tail.extend_from_slice(b"0\r\n\r\n");
                socket.write_all(&tail).await.unwrap();
                let _ = socket.shutdown().await;
            };
            pair(application, server).await;
            assert_eq!(notifications, 1);
            peer.no_extra(1);
            assert!(cx.checkpoint().is_ok());
            assert!(!client.revocation_handle().is_revoked());
            if !matches!(failure, WaitFailure::Revoke) {
                wait_follow_up(&mut peer, &mut client, &cx, &credential).await;
                peer.no_extra(2);
            }
        });
    }
}

#[test]
fn public_waiter_retains_its_original_deadline_after_a_streamed_working_snapshot() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let cancellation = McpRequestCancellation::new();
        let core = ManagedCoreLimits::new(8192, 8192, 32768, 4, Duration::from_secs(2)).unwrap();
        let mut notifications = 0;
        let application = client.wait_task_with_events(
            &cx, &cancellation, &credential, metadata(), TaskId::parse("task-one").unwrap(),
            "deadline", wait_policy(2), DpopStreamLimits::new(core, Duration::from_secs(2)).unwrap(),
            |_| { notifications += 1; true },
        );
        let server = async {
            let mut socket = peer.wait_round("deadline", 0).await;
            let mut task = task_result("working");
            task["pollIntervalMs"] = json!(60000);
            streamed_reply(&mut socket, &wait_response("deadline", 0, false, &task), None, false).await;
        };
        let (result, ()) = pair(application, server).await;
        assert!(matches!(result, Err(DpopTaskWaitError::Task(DpopTasksError::Core(
            DpopCoreError::Transport(DpopHttpError::TimedOut))))));
        assert_eq!(notifications, 1);
        peer.no_extra(1);
        wait_follow_up(&mut peer, &mut client, &cx, &credential).await;
        peer.no_extra(2);
    });
}
