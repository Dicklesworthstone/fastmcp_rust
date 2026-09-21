//! Public recovering Task watches against the existing OAuth/MCP TLS fixture.
//! Run the whole oauth_interaction target with tasks,native-tls-roots; a
//! feature-disabled or filtered target is not verification of these cases.
use super::*;
use fastmcp_client::http_auth::managed::OAuthSessionError;
use fastmcp_client::http_auth::managed::subscriptions::ManagedSubscriptionError;
use fastmcp_client::http_auth::managed::tasks::{ManagedTasksClient, ManagedTasksLimits};
use fastmcp_client::http_auth::managed::tasks::watch::{
    ManagedTaskSnapshotCause, ManagedTaskWatchError, ManagedTaskWatchPolicy,
};
use fastmcp_client::http_auth::managed::tasks::watch::recovery::{
    ManagedTaskRecoveryError, ManagedTaskRecoveryPolicy,
};
use fastmcp_protocol::tasks_extension::{Task, TaskId};
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, FINAL_SUBSCRIPTION_ID_META_KEY};

const RECOVERY_CASE: &str = "FASTMCP_TEST_TASK_WATCH_RECOVERY_CASE";
const DISCOVER: &str = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{"listChanged":true},"extensions":{"io.modelcontextprotocol/tasks":{}}},"ttlMs":0,"cacheScope":"private"}"#;

#[derive(Clone, Copy)]
enum RecoveryCase {
    Complete, PartialAck, Revoked, TerminalSelection, AttemptLimit,
    SnapshotLimit, Cancel, DropRead, Deadline, InvalidWire,
}

fn isolated_recovery(name: &str, case: RecoveryCase) {
    let exact = format!("driver::task_watch_recovery::{name}");
    if let Ok(selected) = std::env::var(RECOVERY_CASE) {
        assert_eq!(selected, exact);
        run_recovery(case);
        return;
    }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
        .env(RECOVERY_CASE, &exact).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
        .spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "Task watch recovery HTTPS case failed");
            return;
        }
        assert!(Instant::now() < end, "Task watch recovery child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn identifier(number: usize) -> Value { json!(format!("recovery:{number}")) }
fn reply(number: usize, result: Value) -> String {
    json!({"jsonrpc":"2.0", "id":identifier(number), "result":result}).to_string()
}
fn acknowledge(number: usize, accepted: &[&str]) -> String {
    json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged", "params":{
        "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):identifier(number)},
        "notifications":{"taskIds":accepted},
    }}).to_string()
}
fn snapshot(task: &str, status: &str, hint: u64) -> Value {
    let mut result = json!({
        "resultType":"complete", "taskId":task, "status":status,
        "createdAt":"2026-09-17T00:00:00Z", "lastUpdatedAt":"2026-09-17T00:00:01Z",
        "ttlMs":null, "pollIntervalMs":hint,
    });
    if status == "completed" { result["result"] = json!({"content":[]}); }
    result
}

async fn request(peer: &Peer, number: usize, method: &str) -> (TlsStream<TcpStream>, Value) {
    let (tls, bytes) = peer.request(false).await;
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["id"], identifier(number), "identities must never reset on reconnect");
    assert_eq!(value["method"], method);
    assert!(matches!(method, "server/discover" | "subscriptions/listen" | "tasks/get"));
    assert_eq!(value["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
        json!({"io.modelcontextprotocol/tasks":{}}));
    // Peer::request also checks the exact bearer, routing headers, and absence
    // of legacy session IDs and Last-Event-ID on EVERY actual TLS POST.
    (tls, value)
}
async fn discover(peer: &Peer, number: usize) -> Value {
    let (mut tls, discovery) = request(peer, number, "server/discover").await;
    json_reply(&mut tls, &reply(number, serde_json::from_str(DISCOVER).unwrap())).await;
    discovery
}
async fn listen(peer: &Peer, number: usize, selection: &[&str], accepted: &[&str], ended: bool) -> TlsStream<TcpStream> {
    let discovery = discover(peer, number).await;
    let (mut tls, listen) = request(peer, number + 1, "subscriptions/listen").await;
    assert_eq!(listen["params"]["notifications"], json!({"taskIds":selection}));
    assert_eq!(listen["params"]["_meta"], discovery["params"]["_meta"]);
    sse_head(&mut tls).await;
    // A well-framed HTTP EOF without a subscription terminal models a lost
    // observation channel. It is not authority to replay a task mutation.
    event(&mut tls, &acknowledge(number + 1, accepted), ended).await;
    tls
}
async fn get(peer: &Peer, number: usize, task: &str, status: &str, hint: u64) {
    let discovery = discover(peer, number).await;
    let (mut tls, get) = request(peer, number + 1, "tasks/get").await;
    assert_eq!(get["params"]["taskId"], task);
    assert_eq!(get["params"]["_meta"], discovery["params"]["_meta"]);
    assert!(get["params"].get("inputResponses").is_none());
    assert!(get["params"].get("requestState").is_none());
    json_reply(&mut tls, &reply(number + 1, snapshot(task, status, hint))).await;
}

fn run_recovery(case: RecoveryCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            let ((), login) = pair(Box::pin(peer.login()), Box::pin(ManagedOAuthSession::authorize(
                &cx, peer.client(), OAuthSessionPolicy::default(), browser,
            ))).await;
            let session = login.unwrap();
            let client = ManagedTasksClient::new(session.clone(),
                FinalRequestMeta::new(ClientCapabilities::default()), ManagedTasksLimits::default()).unwrap();
            let cancellation = McpRequestCancellation::new();
            let long_delay = matches!(case, RecoveryCase::Cancel | RecoveryCase::DropRead | RecoveryCase::Deadline);
            let delay = if long_delay { Duration::from_secs(60) } else { Duration::from_millis(10) };
            let policy = ManagedTaskRecoveryPolicy::new(2, delay, delay).unwrap();
            let timeout = if matches!(case, RecoveryCase::Deadline) { Duration::from_secs(2) } else { Duration::from_secs(15) };
            let snapshots = if matches!(case, RecoveryCase::SnapshotLimit) { 1 } else { 16 };
            let watch_policy = ManagedTaskWatchPolicy::new(timeout, snapshots, 60).unwrap();
            let selection = if matches!(case, RecoveryCase::TerminalSelection) { vec!["task-one", "task-two"] } else { vec!["task-one"] };
            let task_ids = selection.iter().map(|id| TaskId::parse(*id).unwrap()).collect();
            let (mut original, watch) = pair(
                Box::pin(listen(&peer, 0, &selection, &selection, !matches!(case, RecoveryCase::InvalidWire))),
                Box::pin(client.watch_tasks_recovering_with_cancellation(
                    &cx, &cancellation, task_ids, "recovery".to_owned(), watch_policy, policy,
                )),
            ).await;
            let mut watch = watch.unwrap();
            let initial_status = if matches!(case, RecoveryCase::TerminalSelection) { "completed" } else { "working" };
            let ((), initial) = pair(Box::pin(get(&peer, 2, "task-one", initial_status, 10)), Box::pin(watch.next_snapshot(&cx))).await;
            let initial = initial.unwrap().unwrap();
            assert_eq!(initial.cause, ManagedTaskSnapshotCause::Initial);
            assert_eq!(initial.task.base().task_id, TaskId::parse("task-one").unwrap());
            assert_eq!(watch.reconnection_attempts(), 0);
            if matches!(case, RecoveryCase::InvalidWire) {
                // An admitted stream followed by bad protocol data is NOT a
                // transient interruption and must not reopen a clean stream.
                event(&mut original, "{not-json", true).await;
            }
            drop(original);
            match case {
                RecoveryCase::Complete => {
                    let server = Box::pin(async {
                        let stream = listen(&peer, 4, &selection, &selection, false).await;
                        get(&peer, 6, "task-one", "completed", 10).await;
                        stream
                    });
                    let (stream, terminal) = pair(server, Box::pin(watch.next_snapshot(&cx))).await;
                    let terminal = terminal.unwrap().unwrap();
                    assert_eq!(terminal.cause, ManagedTaskSnapshotCause::Reconnected);
                    assert!(matches!(*terminal.task, Task::Completed { .. }));
                    assert!(watch.next_snapshot(&cx).await.unwrap().is_none());
                    assert_eq!(watch.reconnection_attempts(), 1);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 8);
                    drop(stream);
                }
                RecoveryCase::PartialAck => {
                    let (stream, failure) = pair(
                        Box::pin(listen(&peer, 4, &selection, &[], false)),
                        Box::pin(watch.next_snapshot(&cx)),
                    ).await;
                    assert!(matches!(failure, Err(ManagedTaskRecoveryError::Watch(ManagedTaskWatchError::IncompleteAcknowledgement))));
                    assert_eq!(watch.reconnection_attempts(), 1);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 6, "no get after rejected ACK");
                    drop(stream);
                }
                RecoveryCase::Revoked => {
                    let server = Box::pin(async {
                        let (mut tls, _) = request(&peer, 4, "server/discover").await;
                        tls.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                        tls.flush().await.unwrap();
                    });
                    let ((), failure) = pair(server, Box::pin(watch.next_snapshot(&cx))).await;
                    assert!(matches!(failure, Err(ManagedTaskRecoveryError::Watch(ManagedTaskWatchError::Subscription(
                        ManagedSubscriptionError::Session(OAuthSessionError::AuthorizationRejected { status: 401 })
                    )))));
                    assert_eq!(watch.reconnection_attempts(), 1);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 5, "no listen or get after authorization failure");
                }
                RecoveryCase::TerminalSelection => {
                    assert!(matches!(*initial.task, Task::Completed { .. }));
                    let ((), second) = pair(Box::pin(get(&peer, 4, "task-two", "working", 10)), Box::pin(watch.next_snapshot(&cx))).await;
                    assert!(matches!(*second.unwrap().unwrap().task, Task::Working(_)));
                    let server = Box::pin(async {
                        let stream = listen(&peer, 6, &["task-two"], &["task-two"], false).await;
                        get(&peer, 8, "task-two", "completed", 10).await;
                        stream
                    });
                    let (stream, final_task) = pair(server, Box::pin(watch.next_snapshot(&cx))).await;
                    let final_task = final_task.unwrap().unwrap();
                    assert_eq!(final_task.task.base().task_id, TaskId::parse("task-two").unwrap());
                    assert_eq!(final_task.cause, ManagedTaskSnapshotCause::Reconnected);
                    assert!(matches!(*final_task.task, Task::Completed { .. }));
                    assert!(watch.next_snapshot(&cx).await.unwrap().is_none());
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 10);
                    drop(stream);
                }
                RecoveryCase::AttemptLimit => {
                    for attempt in 1..=2 {
                        let base = 4 * attempt;
                        let server = Box::pin(async {
                            let stream = listen(&peer, base, &selection, &selection, true).await;
                            get(&peer, base + 2, "task-one", "working", 10).await;
                            stream
                        });
                        let (stream, current) = pair(server, Box::pin(watch.next_snapshot(&cx))).await;
                        assert_eq!(current.unwrap().unwrap().cause, ManagedTaskSnapshotCause::Reconnected);
                        assert_eq!(watch.reconnection_attempts(), attempt);
                        drop(stream);
                    }
                    assert!(matches!(watch.next_snapshot(&cx).await, Err(ManagedTaskRecoveryError::RecoveryLimit)));
                    assert_eq!(watch.reconnection_attempts(), 2);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 12, "successful reconnects must not replenish attempts");
                }
                RecoveryCase::SnapshotLimit => {
                    assert!(matches!(watch.next_snapshot(&cx).await, Err(ManagedTaskRecoveryError::Watch(ManagedTaskWatchError::SnapshotLimit))));
                    assert_eq!(watch.reconnection_attempts(), 0);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 4, "reserve reconciliation capacity before reconnect");
                }
                RecoveryCase::Cancel => {
                    let cancel = Box::pin(async {
                        Sleep::new(cx.now().saturating_add_nanos(50_000_000)).await;
                        cancellation.cancel();
                    });
                    let (failure, ()) = pair(Box::pin(watch.next_snapshot(&cx)), cancel).await;
                    assert!(matches!(failure, Err(ManagedTaskRecoveryError::Watch(ManagedTaskWatchError::Session(OAuthSessionError::Cancelled)))));
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 4);
                    assert!(cx.checkpoint().is_ok(), "the ambient caller and siblings stay alive");
                }
                RecoveryCase::DropRead => {
                    let mut reading = Box::pin(watch.next_snapshot(&cx));
                    let mut pause = Box::pin(Sleep::new(cx.now().saturating_add_nanos(50_000_000)));
                    poll_fn(|task| {
                        assert!(reading.as_mut().poll(task).is_pending());
                        pause.as_mut().poll(task)
                    }).await;
                    drop(reading);
                    assert!(!cancellation.is_cancel_requested());
                    assert!(cx.checkpoint().is_ok());
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 4);
                }
                RecoveryCase::Deadline => {
                    assert!(matches!(watch.next_snapshot(&cx).await, Err(ManagedTaskRecoveryError::Watch(ManagedTaskWatchError::Session(OAuthSessionError::TimedOut)))));
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 4, "backoff cannot extend the original deadline");
                    assert!(cx.checkpoint().is_ok());
                }
                RecoveryCase::InvalidWire => {
                    assert!(matches!(watch.next_snapshot(&cx).await, Err(ManagedTaskRecoveryError::Watch(ManagedTaskWatchError::Subscription(ManagedSubscriptionError::InvalidResponse)))));
                    assert_eq!(watch.reconnection_attempts(), 0);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 4);
                }
            }
            if !matches!(case, RecoveryCase::Complete | RecoveryCase::TerminalSelection) {
                assert!(matches!(watch.next_snapshot(&cx).await, Err(ManagedTaskRecoveryError::Watch(ManagedTaskWatchError::Closed))),
                    "a failed or abandoned owner cannot reopen on its next poll");
            }
            peer.quiet();
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
            watch.close();
            session.close();
        });
        Box::pin(asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario)).await
            .expect("Task recovery fixture must settle within its bound");
    }));
}

#[test]
fn completion_during_gap_is_reconciled_without_mutation_replay() {
    isolated_recovery("completion_during_gap_is_reconciled_without_mutation_replay", RecoveryCase::Complete);
}
#[test]
fn partial_reconnect_acknowledgement_prevents_task_reads() {
    isolated_recovery("partial_reconnect_acknowledgement_prevents_task_reads", RecoveryCase::PartialAck);
}
#[test]
fn revoked_authority_stops_recovery_before_listen_or_get() {
    isolated_recovery("revoked_authority_stops_recovery_before_listen_or_get", RecoveryCase::Revoked);
}
#[test]
fn delivered_terminal_is_excluded_from_reconnected_selection() {
    isolated_recovery("delivered_terminal_is_excluded_from_reconnected_selection", RecoveryCase::TerminalSelection);
}
#[test]
fn successful_connections_do_not_reset_lifetime_attempt_limit() {
    isolated_recovery("successful_connections_do_not_reset_lifetime_attempt_limit", RecoveryCase::AttemptLimit);
}
#[test]
fn exhausted_snapshot_budget_refuses_recovery_before_any_new_post() {
    isolated_recovery("exhausted_snapshot_budget_refuses_recovery_before_any_new_post", RecoveryCase::SnapshotLimit);
}
#[test]
fn cancellation_interrupts_recovery_without_cancelling_remote_tasks() {
    isolated_recovery("cancellation_interrupts_recovery_without_cancelling_remote_tasks", RecoveryCase::Cancel);
}
#[test]
fn abandoned_recovery_read_permanently_retires_the_owner() {
    isolated_recovery("abandoned_recovery_read_permanently_retires_the_owner", RecoveryCase::DropRead);
}
#[test]
fn recovery_backoff_cannot_renew_the_original_deadline() {
    isolated_recovery("recovery_backoff_cannot_renew_the_original_deadline", RecoveryCase::Deadline);
}
#[test]
fn invalid_live_protocol_is_not_reclassified_as_a_recoverable_disconnect() {
    isolated_recovery("invalid_live_protocol_is_not_reclassified_as_a_recoverable_disconnect", RecoveryCase::InvalidWire);
}
