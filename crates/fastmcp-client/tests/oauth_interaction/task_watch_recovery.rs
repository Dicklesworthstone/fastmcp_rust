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

// Keep the existing observation-only fixture and its method allowlist intact.
// Input-driving cases share its wire helpers but explicitly admit updates in
// their own helper; observation-only tests cannot accidentally start mutating.
mod input_drive {
    use super::*;
    use std::cell::Cell;
    use fastmcp_client::http_auth::managed::tasks::ManagedTasksError;
    use fastmcp_client::http_auth::managed::tasks::watch::drive::{
        ManagedTaskDriverError, ManagedTaskInputAction, ManagedTaskRunOutcome,
        ManagedTaskWatchDriveError, ManagedTaskWatchDrivePolicy,
    };
    use fastmcp_protocol::tasks_extension::{TaskInputRequests, TaskInputResponses};

    const INPUT_CASE: &str = "FASTMCP_TEST_RECOVERING_TASK_INPUT_CASE";
    #[derive(Clone, Copy)]
    enum Case {
        LostGet, LostStream, LostUpdate, ChangedDescriptor, UpdateLimit,
        InputLimit, PartialAck, Cancel, Drop, Deadline, Disabled, PeerFloor,
    }

    fn isolated(name: &str, case: Case) {
        let exact = format!("driver::task_watch_recovery::input_drive::{name}");
        if let Ok(selected) = std::env::var(INPUT_CASE) {
            assert_eq!(selected, exact);
            run(case);
            return;
        }
        let roots = RootFile::create();
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
        }
        let mut child = Child(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
            .env(INPUT_CASE, &exact).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
            .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
            .spawn().unwrap());
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "recovering Task input HTTPS case failed");
                return;
            }
            assert!(Instant::now() < end, "recovering Task input child exceeded its bound");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    async fn lose_reply(mut tls: TlsStream<TcpStream>) {
        // Valid JSON media type and response head, but fewer body bytes than
        // promised. This loses the REPLY after the peer has read the request.
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{\"jsonrpc\":").await.unwrap();
        tls.flush().await.unwrap();
    }

    fn input_snapshot(case: Case, recovered: bool) -> Value {
        let hint = if matches!(case, Case::PeerFloor) { 150 } else { 10 };
        let mut value = snapshot("task-one", "input_required", hint);
        value["inputRequests"] = json!({
            "one":{"method":"roots/list"}, "two":{"method":"roots/list"},
        });
        if recovered && matches!(case, Case::ChangedDescriptor) {
            value["inputRequests"]["two"] = json!({
                "method":"sampling/createMessage", "params":{"messages":[],"maxTokens":1},
            });
        }
        if recovered && matches!(case, Case::InputLimit) {
            value["inputRequests"]["three"] = json!({"method":"roots/list"});
        }
        value
    }

    async fn input_get(peer: &Peer, number: usize, value: Option<Value>) {
        let discovered = discover(peer, number).await;
        let (mut tls, get) = request(peer, number + 1, "tasks/get").await;
        assert_eq!(get["params"]["taskId"], "task-one");
        assert_eq!(get["params"]["_meta"], discovered["params"]["_meta"]);
        assert!(get["params"].get("inputResponses").is_none());
        assert!(get["params"].get("requestState").is_none());
        match value {
            Some(value) => json_reply(&mut tls, &reply(number + 1, value)).await,
            None => lose_reply(tls).await,
        }
    }

    async fn update(peer: &Peer, number: usize, key: &str, acknowledged: bool) {
        let discovered = discover(peer, number).await;
        let (mut tls, bytes) = peer.request(false).await;
        let update: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(update["id"], identifier(number + 1));
        assert_eq!(update["method"], "tasks/update");
        assert_eq!(update["params"]["taskId"], "task-one");
        assert_eq!(update["params"]["_meta"], discovered["params"]["_meta"]);
        assert_eq!(update["params"]["inputResponses"], json!({key:{"roots":[]}}));
        assert!(update["params"].get("requestState").is_none());
        if acknowledged {
            json_reply(&mut tls, &reply(number + 1, json!({"resultType":"complete"}))).await;
        } else {
            lose_reply(tls).await;
        }
    }

    fn run(case: Case) {
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
            let cx = Cx::current().unwrap();
            let scenario = Box::pin(async {
                let peer = Peer::new().await;
                let ((), login) = pair(Box::pin(peer.login()), Box::pin(ManagedOAuthSession::authorize(
                    &cx, peer.client(), OAuthSessionPolicy::default(), browser,
                ))).await;
                let session = login.unwrap();
                let capabilities: ClientCapabilities = serde_json::from_value(json!({"roots":{}})).unwrap();
                let client = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(capabilities), ManagedTasksLimits::default()).unwrap();
                let cancellation = McpRequestCancellation::new();
                let timeout = if matches!(case, Case::Deadline) { Duration::from_secs(3) } else { Duration::from_secs(15) };
                let watch = ManagedTaskWatchPolicy::new(timeout, 16, 60).unwrap();
                let mut policy = ManagedTaskWatchDrivePolicy::new(watch,
                    if matches!(case, Case::UpdateLimit) { 1 } else { 4 },
                    if matches!(case, Case::InputLimit) { 2 } else { 8 }, 65536).unwrap();
                let delay = if matches!(case, Case::Cancel | Case::Drop | Case::Deadline) {
                    Duration::from_secs(60)
                } else { Duration::from_millis(10) };
                if !matches!(case, Case::Disabled) {
                    policy = policy.with_recovery(ManagedTaskRecoveryPolicy::new(2, delay, delay).unwrap()).unwrap();
                }
                let resolutions = Cell::new(0);
                let observations = Cell::new(0);
                let (lost_tx, mut lost_rx) = oneshot::channel::<()>();
                let server = Box::pin(async {
                    let mut original = listen(&peer, 0, &["task-one"], &["task-one"], matches!(case, Case::LostStream)).await;
                    input_get(&peer, 2, Some(input_snapshot(case, false))).await;
                    update(&peer, 4, "one", !matches!(case, Case::LostUpdate)).await;
                    if matches!(case, Case::LostUpdate) { return 6; }
                    if matches!(case, Case::LostStream) {
                        // The get succeeds, then the listen ends while the task
                        // is still working. Recovery must retain answer one.
                        get(&peer, 6, "task-one", "working", 10).await;
                    } else {
                        input_get(&peer, 6, None).await;
                    }
                    let lost_at = Instant::now();
                    if matches!(case, Case::Cancel | Case::Drop) {
                        lost_tx.send(&cx, ()).unwrap();
                        return 8;
                    }
                    if matches!(case, Case::Deadline | Case::Disabled) { return 8; }
                    // Keep the old stream peer alive: the client, not this
                    // fixture dropping its socket, must retire old custody.
                    let mut byte = [0; 1];
                    match original.read(&mut byte).await {
                        Ok(0) | Err(_) => {},
                        Ok(_) => panic!("old observation connection received unexpected data"),
                    }
                    let accepted: &[&str] = if matches!(case, Case::PartialAck) { &[] } else { &["task-one"] };
                    let stream = listen(&peer, 8, &["task-one"], accepted, false).await;
                    if matches!(case, Case::PeerFloor) {
                        assert!(lost_at.elapsed() >= Duration::from_millis(150), "recovery must honor the peer's last polling floor");
                    }
                    if matches!(case, Case::PartialAck) { return 10; }
                    // Re-report the ALREADY acknowledged input alongside the
                    // unresolved input. Only two may reach the second callback.
                    input_get(&peer, 10, Some(input_snapshot(case, true))).await;
                    if matches!(case, Case::ChangedDescriptor | Case::UpdateLimit | Case::InputLimit) { return 12; }
                    update(&peer, 12, "two", true).await;
                    get(&peer, 14, "task-one", "completed", 10).await;
                    drop(stream);
                    16
                });
                let consumer = Box::pin(async {
                    let mut operation = Box::pin(client.drive_task_watching_with_cancellation(
                        &cx, &cancellation, TaskId::parse("task-one").unwrap(), "recovery".to_owned(), policy,
                        |pending: TaskInputRequests| {
                            let round = resolutions.get();
                            let actual = pending.keys().map(String::as_str).collect::<Vec<_>>();
                            let key = match round {
                                0 => { assert_eq!(actual, ["one", "two"]); "one" }
                                1 => { assert_eq!(actual, ["two"], "acknowledged answers must survive recovery"); "two" }
                                _ => panic!("no repeated host resolution is allowed"),
                            };
                            resolutions.set(round + 1);
                            let response: TaskInputResponses = serde_json::from_value(json!({key:{"roots":[]}})).unwrap();
                            std::future::ready(Ok(ManagedTaskInputAction::Respond(response)))
                        },
                        |task| {
                            assert_eq!(task.base().task_id, TaskId::parse("task-one").unwrap());
                            observations.set(observations.get() + 1);
                            Ok(())
                        },
                    ));
                    if matches!(case, Case::Drop) {
                        let mut until_lost = Box::pin(async {
                            lost_rx.recv(&cx).await.unwrap();
                            Sleep::new(cx.now().saturating_add_nanos(50_000_000)).await;
                        });
                        poll_fn(|task| {
                            assert!(operation.as_mut().poll(task).is_pending());
                            until_lost.as_mut().poll(task)
                        }).await;
                        drop(operation);
                        return None;
                    }
                    if matches!(case, Case::Cancel) {
                        let cancel = Box::pin(async {
                            lost_rx.recv(&cx).await.unwrap();
                            Sleep::new(cx.now().saturating_add_nanos(50_000_000)).await;
                            cancellation.cancel();
                        });
                        let (result, ()) = pair(operation, cancel).await;
                        Some(result)
                    } else {
                        Some(operation.await)
                    }
                });
                let (posts, outcome) = pair(server, consumer).await;
                match case {
                    Case::LostGet | Case::LostStream | Case::PeerFloor => {
                        let ManagedTaskRunOutcome::Terminal(task) = outcome.unwrap().unwrap() else { panic!("terminal result required") };
                        assert!(matches!(*task, Task::Completed { .. }));
                        assert_eq!(resolutions.get(), 2);
                        assert_eq!(observations.get(), if matches!(case, Case::LostStream) { 4 } else { 3 });
                    }
                    Case::LostUpdate | Case::Disabled => {
                        assert!(matches!(outcome.unwrap(), Err(ManagedTaskWatchDriveError::Watch(
                            ManagedTaskWatchError::Task(ManagedTasksError::Session(OAuthSessionError::Http(_)))
                        ))));
                        assert_eq!(resolutions.get(), 1);
                        assert_eq!(observations.get(), 1);
                    }
                    Case::ChangedDescriptor | Case::UpdateLimit | Case::InputLimit => {
                        let error = outcome.unwrap().err().unwrap();
                        assert!(matches!((case, error),
                            (Case::ChangedDescriptor, ManagedTaskWatchDriveError::Input(ManagedTaskDriverError::InputKeyReused))
                            | (Case::UpdateLimit, ManagedTaskWatchDriveError::Input(ManagedTaskDriverError::UpdateLimit))
                            | (Case::InputLimit, ManagedTaskWatchDriveError::Input(ManagedTaskDriverError::InputLimit))));
                        assert_eq!(resolutions.get(), 1, "reconnection cannot reset the input/update limits");
                        assert_eq!(observations.get(), 2);
                    }
                    Case::PartialAck => {
                        assert!(matches!(outcome.unwrap(), Err(ManagedTaskWatchDriveError::Watch(ManagedTaskWatchError::IncompleteAcknowledgement))));
                        assert_eq!(resolutions.get(), 1);
                        assert_eq!(observations.get(), 1);
                    }
                    Case::Cancel | Case::Deadline => {
                        let error = outcome.unwrap().err().unwrap();
                        assert!(matches!((case, error),
                            (Case::Cancel, ManagedTaskWatchDriveError::Watch(ManagedTaskWatchError::Session(OAuthSessionError::Cancelled)))
                            | (Case::Deadline, ManagedTaskWatchDriveError::Watch(ManagedTaskWatchError::Session(OAuthSessionError::TimedOut)))));
                        assert_eq!(resolutions.get(), 1);
                        assert_eq!(observations.get(), 1);
                    }
                    Case::Drop => {
                        assert!(outcome.is_none());
                        assert_eq!(resolutions.get(), 1);
                        assert_eq!(observations.get(), 1);
                    }
                }
                assert_eq!(peer.posts.load(Ordering::SeqCst), posts, "no unrequested mutation or retry may be emitted");
                assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
                assert_eq!(cancellation.is_cancel_requested(), matches!(case, Case::Cancel));
                assert!(cx.checkpoint().is_ok(), "caller and sibling authority remains live");
                peer.quiet();
                session.close();
            });
            Box::pin(asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario)).await
                .expect("recovering Task input fixture must settle within its bound");
        }));
    }

    #[test]
    fn acknowledged_partial_answer_survives_lost_reconciliation_reply() {
        isolated("acknowledged_partial_answer_survives_lost_reconciliation_reply", Case::LostGet);
    }
    #[test]
    fn acknowledged_partial_answer_survives_lost_subscription() {
        isolated("acknowledged_partial_answer_survives_lost_subscription", Case::LostStream);
    }
    #[test]
    fn uncertain_update_is_not_replayed_or_followed_by_reconciliation() {
        isolated("uncertain_update_is_not_replayed_or_followed_by_reconciliation", Case::LostUpdate);
    }
    #[test]
    fn changed_unanswered_descriptor_is_rejected_after_reconnect() {
        isolated("changed_unanswered_descriptor_is_rejected_after_reconnect", Case::ChangedDescriptor);
    }
    #[test]
    fn acknowledged_update_count_is_not_reset_by_recovery() {
        isolated("acknowledged_update_count_is_not_reset_by_recovery", Case::UpdateLimit);
    }
    #[test]
    fn input_key_budget_is_not_reset_by_recovery() {
        isolated("input_key_budget_is_not_reset_by_recovery", Case::InputLimit);
    }
    #[test]
    fn partial_reconnect_ack_cannot_restart_host_resolution() {
        isolated("partial_reconnect_ack_cannot_restart_host_resolution", Case::PartialAck);
    }
    #[test]
    fn cancellation_stops_recovery_after_an_acknowledged_update() {
        isolated("cancellation_stops_recovery_after_an_acknowledged_update", Case::Cancel);
    }
    #[test]
    fn abandoned_input_recovery_releases_work_without_remote_cancellation() {
        isolated("abandoned_input_recovery_releases_work_without_remote_cancellation", Case::Drop);
    }
    #[test]
    fn original_driver_deadline_bounds_recovery_after_input() {
        isolated("original_driver_deadline_bounds_recovery_after_input", Case::Deadline);
    }
    #[test]
    fn ordinary_driver_does_not_silently_opt_into_recovery() {
        isolated("ordinary_driver_does_not_silently_opt_into_recovery", Case::Disabled);
    }
    #[test]
    fn recovering_input_driver_honors_the_last_peer_polling_floor() {
        isolated("recovering_input_driver_honors_the_last_peer_polling_floor", Case::PeerFloor);
    }
}
