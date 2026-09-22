//! Remote Task cancellation through the existing OAuth/native-TLS fixture.
//! Run the complete oauth_interaction target with tasks,native-tls-roots.
//! The peer records real requests; an empty cancellation ACK never supplies a
//! terminal snapshot, and a lost ACK never becomes permission to send again.
use super::*;
use fastmcp_client::http_auth::managed::OAuthSessionError;
use fastmcp_client::http_auth::managed::tasks::{
    ManagedTaskEvent, ManagedTaskRequest, ManagedTaskRequestIds, ManagedTasksClient,
    ManagedTasksError, ManagedTasksLimits,
};
use fastmcp_client::http_auth::managed::tasks::watch::ManagedTaskWatchPolicy;
use fastmcp_client::http_auth::managed::tasks::watch::cancellation::{
    CancellableTaskWatchError, TaskCancellationError, TaskCancellationState,
};
use fastmcp_client::http_auth::managed::tasks::watch::recovery::ManagedTaskRecoveryPolicy;
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, FINAL_SUBSCRIPTION_ID_META_KEY};
use fastmcp_protocol::tasks_extension::{Task, TaskId};

const CASE_ENV: &str = "FASTMCP_TEST_TASK_REMOTE_CANCELLATION";
const TASK_ID: &str = "opaque task / cancellation";
const PREFIX: &str = "cancelwatch";
const CANCEL_DISCOVERY: &str = "cancelwatch:cancel:discovery";
const CANCEL_OPERATION: &str = "cancelwatch:cancel:operation";
const DISCOVER: &str = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"extensions":{"io.modelcontextprotocol/tasks":{}}},"ttlMs":0,"cacheScope":"private"}"#;

#[derive(Clone, Copy)]
enum Case {
    IdleAck, GetAck, BackoffAck, WrongAck, LostAck, Refused,
    DropAttempt, CancelAttempt, CloseOwner, DropRead, Terminal,
    PreCancelled, Unpolled, Deadline,
}

fn isolated(name: &str, case: Case) {
    let exact = format!("driver::task_cancellation::{name}");
    if let Ok(selected) = std::env::var(CASE_ENV) {
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
        .env(CASE_ENV, &exact).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "Task cancellation HTTPS case failed");
            return;
        }
        assert!(Instant::now() < deadline, "Task cancellation child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn result(id: &str, value: Value) -> String {
    json!({"jsonrpc":"2.0", "id":id, "result":value}).to_string()
}
fn task(status: &str) -> Value {
    let mut value = json!({"taskId":TASK_ID, "status":status,
        "createdAt":"2020-01-01T00:00:00Z", "lastUpdatedAt":"2020-01-01T00:00:01Z",
        "ttlMs":null, "pollIntervalMs":10});
    if status == "completed" { value["result"] = json!({"content":[]}); }
    value
}
async fn request(peer: &Peer, id: &str, method: &str) -> (TlsStream<TcpStream>, Value) {
    let (tls, bytes) = peer.request(false).await;
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["id"], id);
    assert_eq!(value["method"], method);
    assert!(matches!(method, "server/discover" | "subscriptions/listen" | "tasks/get" | "tasks/cancel"));
    assert_eq!(value["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
        json!({"io.modelcontextprotocol/tasks":{}}));
    assert!(value["params"].get("requestState").is_none());
    assert!(value["params"].get("inputResponses").is_none());
    // Peer::request checks exact bearer and routing headers on every TLS POST.
    (tls, value)
}
async fn discover(peer: &Peer, id: &str) -> Value {
    let (mut tls, value) = request(peer, id, "server/discover").await;
    json_reply(&mut tls, &result(id, serde_json::from_str(DISCOVER).unwrap())).await;
    value
}
async fn listen(peer: &Peer, ended: bool) -> TlsStream<TcpStream> {
    let discovery = discover(peer, "cancelwatch:0").await;
    let (mut tls, value) = request(peer, "cancelwatch:1", "subscriptions/listen").await;
    assert_eq!(value["params"]["_meta"], discovery["params"]["_meta"]);
    assert_eq!(value["params"]["notifications"], json!({"taskIds":[TASK_ID]}));
    sse_head(&mut tls).await;
    let acknowledgement = json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged",
        "params":{"_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):"cancelwatch:1"},
            "notifications":{"taskIds":[TASK_ID]}}}).to_string();
    event(&mut tls, &acknowledgement, ended).await;
    tls
}
async fn get_head(peer: &Peer, first: &str, second: &str) -> TlsStream<TcpStream> {
    let discovery = discover(peer, first).await;
    let (tls, value) = request(peer, second, "tasks/get").await;
    assert_eq!(value["params"]["_meta"], discovery["params"]["_meta"]);
    assert_eq!(value["params"]["taskId"], TASK_ID);
    tls
}
async fn get(peer: &Peer, first: &str, second: &str, status: &str) {
    let mut tls = get_head(peer, first, second).await;
    let mut snapshot = task(status);
    snapshot["resultType"] = json!("complete");
    json_reply(&mut tls, &result(second, snapshot)).await;
}
async fn cancel_head(peer: &Peer) -> TlsStream<TcpStream> {
    let discovery = discover(peer, CANCEL_DISCOVERY).await;
    let (tls, value) = request(peer, CANCEL_OPERATION, "tasks/cancel").await;
    assert_eq!(value["params"]["_meta"], discovery["params"]["_meta"]);
    assert_eq!(value["params"]["taskId"], TASK_ID);
    assert_eq!(value["params"].as_object().unwrap().len(), 2, "only taskId and request metadata");
    tls
}
async fn ack(tls: &mut TlsStream<TcpStream>) {
    json_reply(tls, &result(CANCEL_OPERATION, json!({"resultType":"complete"}))).await;
}
async fn require_close(mut tls: TlsStream<TcpStream>) {
    let mut byte = [0; 1];
    match tls.read(&mut byte).await {
        Ok(0) | Err(_) => {},
        Ok(_) => panic!("client must close its owned response, not replay a request"),
    }
}
async fn notify(tls: &mut TlsStream<TcpStream>) {
    let mut params = task("working");
    params["_meta"] = json!({(FINAL_SUBSCRIPTION_ID_META_KEY):"cancelwatch:1"});
    event(tls, &json!({"jsonrpc":"2.0", "method":"notifications/tasks", "params":params}).to_string(), false).await;
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
            let client = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(ClientCapabilities::default()),
                ManagedTasksLimits::new(65536, 65536, 32, Duration::from_secs(15)).unwrap()).unwrap();
            let shared = McpRequestCancellation::new();
            let timeout = if matches!(case, Case::Deadline) { Duration::from_secs(3) } else { Duration::from_secs(15) };
            let policy = ManagedTaskWatchPolicy::new(timeout, 16, 60).unwrap();
            let recovery = if matches!(case, Case::BackoffAck) {
                Some(ManagedTaskRecoveryPolicy::new(2, Duration::from_secs(60), Duration::from_secs(60)).unwrap())
            } else { None };
            let (mut stream, watched) = pair(Box::pin(listen(&peer, recovery.is_some())),
                Box::pin(client.watch_task_cancellable_with_cancellation(
                    &cx, &shared, TaskId::parse(TASK_ID).unwrap(), PREFIX.to_owned(), policy, recovery,
                ))).await;
            let mut watch = watched.unwrap();
            let handle = watch.cancel_handle();
            let clone = handle.clone();
            assert_eq!(handle.state(), TaskCancellationState::Ready);
            assert!(!format!("{watch:?} {handle:?}").contains(TASK_ID));

            if matches!(case, Case::GetAck) {
                let (entered_tx, mut entered_rx) = oneshot::channel::<()>();
                let server = Box::pin(async {
                    let get = get_head(&peer, "cancelwatch:2", "cancelwatch:3").await;
                    entered_tx.send(&cx, ()).unwrap();
                    let mut cancel = cancel_head(&peer).await;
                    ack(&mut cancel).await;
                    require_close(get).await;
                });
                let consumer = Box::pin(async {
                    let cancel = Box::pin(async {
                        entered_rx.recv(&cx).await.unwrap();
                        handle.request_cancel(&cx).await
                    });
                    pair(Box::pin(watch.next_snapshot(&cx)), cancel).await
                });
                let ((), (snapshot, cancellation)) = pair(server, consumer).await;
                assert!(matches!(snapshot, Err(CancellableTaskWatchError::CancellationRequested)));
                cancellation.unwrap();
                assert_eq!(handle.state(), TaskCancellationState::Acknowledged);
                assert_eq!(peer.posts.load(Ordering::SeqCst), 6);
            } else {
                let status = if matches!(case, Case::Terminal) { "completed" } else { "working" };
                let ((), first) = pair(Box::pin(get(&peer, "cancelwatch:2", "cancelwatch:3", status)),
                    Box::pin(watch.next_snapshot(&cx))).await;
                let first = first.unwrap().unwrap();
                assert_eq!(first.task.base().task_id.as_str(), TASK_ID);
                if matches!(case, Case::Terminal) {
                    assert!(matches!(*first.task, Task::Completed { .. }));
                    assert!(watch.next_snapshot(&cx).await.unwrap().is_none());
                    assert!(matches!(handle.request_cancel(&cx).await, Err(TaskCancellationError::Closed)));
                } else if matches!(case, Case::DropRead) {
                    let mut read = Box::pin(watch.next_snapshot(&cx));
                    poll_fn(|task| { assert!(read.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                    drop(read);
                    assert!(matches!(watch.next_snapshot(&cx).await, Err(CancellableTaskWatchError::Closed)));
                    assert!(matches!(handle.request_cancel(&cx).await, Err(TaskCancellationError::Closed)));
                } else if matches!(case, Case::Deadline) {
                    Sleep::new(cx.now().saturating_add_nanos(3_100_000_000)).await;
                    assert!(matches!(handle.request_cancel(&cx).await,
                        Err(TaskCancellationError::NotAttempted(ManagedTasksError::Session(OAuthSessionError::TimedOut)))));
                    assert_eq!(handle.state(), TaskCancellationState::Ready);
                    assert!(matches!(watch.next_snapshot(&cx).await,
                        Err(CancellableTaskWatchError::Session(OAuthSessionError::TimedOut))));
                } else if matches!(case, Case::CloseOwner) {
                    let (entered_tx, mut entered_rx) = oneshot::channel::<()>();
                    let server = Box::pin(async {
                        let tls = cancel_head(&peer).await;
                        entered_tx.send(&cx, ()).unwrap();
                        require_close(tls).await;
                    });
                    let consumer = Box::pin(async {
                        let close = Box::pin(async { entered_rx.recv(&cx).await.unwrap(); watch.close(); });
                        pair(Box::pin(handle.request_cancel(&cx)), close).await.0
                    });
                    let ((), cancelled) = pair(server, consumer).await;
                    assert!(matches!(cancelled, Err(TaskCancellationError::Unconfirmed(_))));
                    assert_eq!(handle.state(), TaskCancellationState::Unconfirmed);
                    assert!(matches!(watch.next_snapshot(&cx).await, Err(CancellableTaskWatchError::Closed)));
                    assert!(matches!(clone.request_cancel(&cx).await, Err(TaskCancellationError::AlreadyAttempted)));
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 6);
                } else {
                    if matches!(case, Case::PreCancelled) {
                        let stopped = McpRequestCancellation::new();
                        stopped.cancel();
                        assert!(matches!(handle.request_cancel_with_cancellation(&cx, &stopped).await,
                            Err(TaskCancellationError::NotAttempted(ManagedTasksError::Session(OAuthSessionError::Cancelled)))));
                        assert_eq!(handle.state(), TaskCancellationState::Ready);
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 4);
                    }
                    if matches!(case, Case::Unpolled) {
                        drop(Box::pin(handle.request_cancel(&cx)));
                        assert_eq!(clone.state(), TaskCancellationState::Ready);
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 4);
                    }
                    let succeeds = matches!(case, Case::IdleAck | Case::BackoffAck | Case::PreCancelled | Case::Unpolled);
                    let (entered_tx, mut entered_rx) = oneshot::channel::<()>();
                    let local = McpRequestCancellation::new();
                    let server = Box::pin(async {
                        if matches!(case, Case::Refused) {
                            let (mut tls, _) = request(&peer, CANCEL_DISCOVERY, "server/discover").await;
                            tls.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                            tls.flush().await.unwrap();
                            return;
                        }
                        let mut tls = cancel_head(&peer).await;
                        match case {
                            Case::WrongAck => json_reply(&mut tls, &result("wrong-ack-id", json!({"resultType":"complete"}))).await,
                            Case::LostAck => {
                                tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{\"jsonrpc\":").await.unwrap();
                                tls.flush().await.unwrap();
                            }
                            Case::DropAttempt | Case::CancelAttempt => {
                                entered_tx.send(&cx, ()).unwrap();
                                require_close(tls).await;
                            }
                            _ => ack(&mut tls).await,
                        }
                    });
                    let attempt = Box::pin(async {
                        let mut cancel = Box::pin(handle.request_cancel_with_cancellation(&cx, &local));
                        if matches!(case, Case::DropAttempt | Case::CancelAttempt) {
                            let mut entered = Box::pin(entered_rx.recv(&cx));
                            poll_fn(|task| {
                                assert!(cancel.as_mut().poll(task).is_pending());
                                match entered.as_mut().poll(task) {
                                    Poll::Ready(value) => { value.unwrap(); Poll::Ready(()) }
                                    Poll::Pending => Poll::Pending,
                                }
                            }).await;
                            assert!(matches!(clone.request_cancel(&cx).await, Err(TaskCancellationError::AlreadyAttempted)));
                            if matches!(case, Case::DropAttempt) { drop(cancel); return None; }
                            local.cancel();
                        }
                        Some(cancel.await)
                    });
                    let consumer = Box::pin(async {
                        if succeeds {
                            let (observed, cancelled) = pair(Box::pin(watch.next_snapshot(&cx)), attempt).await;
                            assert!(matches!(observed, Err(CancellableTaskWatchError::CancellationRequested)));
                            cancelled.unwrap().unwrap();
                        } else {
                            let cancelled = attempt.await;
                            if matches!(case, Case::DropAttempt) { assert!(cancelled.is_none()); }
                            else { assert!(matches!(cancelled.unwrap(), Err(TaskCancellationError::Unconfirmed(_)))); }
                        }
                    });
                    pair(server, consumer).await;
                    assert!(matches!(clone.request_cancel(&cx).await, Err(TaskCancellationError::AlreadyAttempted)));
                    if succeeds {
                        assert_eq!(handle.state(), TaskCancellationState::Acknowledged);
                        assert!(matches!(watch.next_snapshot(&cx).await, Err(CancellableTaskWatchError::CancellationRequested)));
                        // The peer is STILL working after its empty cancel ACK.
                        // A separately chosen low-level read must remain usable.
                        let inspect = Box::pin(async {
                            let ids = ManagedTaskRequestIds::new(RequestId::String("inspect:0".to_owned()),
                                RequestId::String("inspect:1".to_owned())).unwrap();
                            let mut call = client.request(&cx, ids, ManagedTaskRequest::Get(TaskId::parse(TASK_ID).unwrap())).await.unwrap();
                            assert!(matches!(call.next_event(&cx).await.unwrap(),
                                Some(ManagedTaskEvent::Snapshot(snapshot)) if matches!(snapshot.task, Task::Working(_))));
                        });
                        pair(Box::pin(get(&peer, "inspect:0", "inspect:1", "working")), inspect).await;
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 8, "no recovery/poll/mutation after acknowledged cancellation");
                    } else {
                        assert_eq!(handle.state(), TaskCancellationState::Unconfirmed);
                        // No acknowledgement means no cancellation disposition.
                        // Continue THIS original watch to a real terminal result.
                        notify(&mut stream).await;
                        let ((), observed) = pair(Box::pin(get(&peer, "cancelwatch:4", "cancelwatch:5", "completed")),
                            Box::pin(watch.next_snapshot(&cx))).await;
                        assert!(matches!(*observed.unwrap().unwrap().task, Task::Completed { .. }));
                        assert!(watch.next_snapshot(&cx).await.unwrap().is_none());
                        assert_eq!(peer.posts.load(Ordering::SeqCst), if matches!(case, Case::Refused) { 7 } else { 8 });
                    }
                }
                if matches!(case, Case::Terminal | Case::DropRead | Case::Deadline) {
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 4, "local disposition must not send remote cancellation");
                }
            }
            require_close(stream).await;
            assert!(!shared.is_cancel_requested(), "remote cancellation cannot cancel sibling observation authority");
            assert!(cx.checkpoint().is_ok());
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
            peer.quiet();
            session.close();
        });
        Box::pin(asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario)).await
            .expect("Task cancellation fixture must settle within its bound");
    }));
}

#[test]
fn acknowledged_cancel_stops_idle_observation_without_fabricating_terminal() {
    isolated("acknowledged_cancel_stops_idle_observation_without_fabricating_terminal", Case::IdleAck);
}
#[test]
fn acknowledged_cancel_closes_an_inflight_snapshot_read() {
    isolated("acknowledged_cancel_closes_an_inflight_snapshot_read", Case::GetAck);
}
#[test]
fn acknowledged_cancel_interrupts_recovery_backoff_without_reconnect() {
    isolated("acknowledged_cancel_interrupts_recovery_backoff_without_reconnect", Case::BackoffAck);
}
#[test]
fn wrong_cancel_ack_identity_leaves_original_observation_usable() {
    isolated("wrong_cancel_ack_identity_leaves_original_observation_usable", Case::WrongAck);
}
#[test]
fn lost_cancel_reply_is_not_replayed_and_does_not_end_observation() {
    isolated("lost_cancel_reply_is_not_replayed_and_does_not_end_observation", Case::LostAck);
}
#[test]
fn current_authorization_refusal_sends_no_remote_cancel() {
    isolated("current_authorization_refusal_sends_no_remote_cancel", Case::Refused);
}
#[test]
fn dropped_cancel_attempt_retains_uncertainty_across_handle_clones() {
    isolated("dropped_cancel_attempt_retains_uncertainty_across_handle_clones", Case::DropAttempt);
}
#[test]
fn local_attempt_cancellation_does_not_cancel_observation() {
    isolated("local_attempt_cancellation_does_not_cancel_observation", Case::CancelAttempt);
}
#[test]
fn closing_watch_wakes_and_releases_an_outstanding_cancel_request() {
    isolated("closing_watch_wakes_and_releases_an_outstanding_cancel_request", Case::CloseOwner);
}
#[test]
fn abandoning_observation_retires_future_remote_cancel_admission() {
    isolated("abandoning_observation_retires_future_remote_cancel_admission", Case::DropRead);
}
#[test]
fn delivered_terminal_prevents_a_later_cancel_attempt() {
    isolated("delivered_terminal_prevents_a_later_cancel_attempt", Case::Terminal);
}
#[test]
fn pre_cancelled_attempt_preserves_the_unused_cancel_opportunity() {
    isolated("pre_cancelled_attempt_preserves_the_unused_cancel_opportunity", Case::PreCancelled);
}
#[test]
fn unpolled_cancel_has_no_effect_on_observation_or_attempt_budget() {
    isolated("unpolled_cancel_has_no_effect_on_observation_or_attempt_budget", Case::Unpolled);
}
#[test]
fn remote_cancel_cannot_extend_the_original_watch_deadline() {
    isolated("remote_cancel_cannot_extend_the_original_watch_deadline", Case::Deadline);
}

// The original observation-only helpers and tests above remain unchanged.
// This child adds explicit input updates to the fixture, never to its parent's
// no-input request allowlist. All tests use the shipped owned driver over TLS.
mod input_driver {
    use super::*;
    use std::cell::Cell;
    use fastmcp_client::http_auth::managed::tasks::watch::drive::{
        ManagedTaskInputAction, ManagedTaskRunOutcome, ManagedTaskWatchDriveError,
        ManagedTaskWatchDrivePolicy, TaskInputUpdateState,
    };
    use fastmcp_protocol::tasks_extension::{TaskInputRequests, TaskInputResponses};

    const INPUT_ENV: &str = "FASTMCP_TEST_TASK_INPUT_CANCELLATION";
    #[derive(Clone, Copy)]
    enum InputCase {
        BeforeFirst, Resolver, ReadyResolver, Update, GetAfterUpdate, Backoff,
        WrongAck, LostAck, Refused, DropResolver, DropUpdate, Terminal, Return,
        LocalCancel, Deadline, ExpiredCredential,
    }

    fn isolated_input(name: &str, case: InputCase) {
        let exact = format!("driver::task_cancellation::input_driver::{name}");
        if let Ok(selected) = std::env::var(INPUT_ENV) {
            assert_eq!(selected, exact);
            RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
                let cx = Cx::current().unwrap();
                let peer = Peer::new().await;
                Box::pin(asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario(&peer, &cx, case)))
                    .await.expect("owned input cancellation must settle within its bound");
            }));
            return;
        }
        let roots = RootFile::create();
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
        }
        let mut child = Child(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
            .env(INPUT_ENV, &exact).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
            .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "owned input cancellation HTTPS case failed");
                return;
            }
            assert!(Instant::now() < end, "owned input cancellation child exceeded its bound");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn no_resolver(_: TaskInputRequests) -> std::future::Ready<Result<ManagedTaskInputAction, ManagedTaskWatchDriveError>> {
        panic!("closed or terminal driver must not invoke a resolver")
    }
    fn no_observer(_: &Task) -> Result<(), ManagedTaskWatchDriveError> {
        panic!("closed driver must not publish a snapshot")
    }
    fn resolver_waits(case: InputCase) -> bool {
        matches!(case, InputCase::Resolver | InputCase::WrongAck | InputCase::LostAck
            | InputCase::Refused | InputCase::DropResolver | InputCase::LocalCancel | InputCase::Deadline)
    }
    fn failed_cancel(case: InputCase) -> bool {
        matches!(case, InputCase::WrongAck | InputCase::LostAck | InputCase::Refused)
    }

    async fn input_get(peer: &Peer) {
        let mut tls = get_head(peer, "cancelwatch:2", "cancelwatch:3").await;
        let mut snapshot = task("input_required");
        snapshot["inputRequests"] = json!({"ask":{"method":"roots/list"}});
        snapshot["resultType"] = json!("complete");
        json_reply(&mut tls, &result("cancelwatch:3", snapshot)).await;
    }
    async fn update_head(peer: &Peer) -> TlsStream<TcpStream> {
        let discovery = discover(peer, "cancelwatch:4").await;
        let (tls, bytes) = peer.request(false).await;
        let update: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(update["id"], "cancelwatch:5");
        assert_eq!(update["method"], "tasks/update");
        assert_eq!(update["params"]["_meta"], discovery["params"]["_meta"]);
        assert_eq!(update["params"]["taskId"], TASK_ID);
        assert_eq!(update["params"]["inputResponses"], json!({"ask":{"roots":[]}}));
        assert_eq!(update["params"].as_object().unwrap().len(), 3);
        assert!(update["params"].get("requestState").is_none());
        tls
    }
    async fn update_ack(tls: &mut TlsStream<TcpStream>) {
        json_reply(tls, &result("cancelwatch:5", json!({"resultType":"complete"}))).await;
    }
    async fn lose_reply(mut tls: TlsStream<TcpStream>) {
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{\"jsonrpc\":").await.unwrap();
        tls.flush().await.unwrap();
    }

    async fn scenario(peer: &Peer, cx: &Cx, case: InputCase) {
        let issuer = Box::pin(async {
            if matches!(case, InputCase::ExpiredCredential) {
                let (mut tls, _) = peer.request(true).await;
                // Renewable credentials make a hidden re-acquisition observable:
                // the peer admits NO refresh exchange after original expiry.
                json_reply(&mut tls, r#"{"access_token":"interaction-access","token_type":"Bearer","expires_in":5,"refresh_token":"interaction-refresh"}"#).await;
            } else { peer.login().await; }
        });
        let ((), login) = pair(issuer, Box::pin(ManagedOAuthSession::authorize(
            cx, peer.client(), OAuthSessionPolicy::default(), browser,
        ))).await;
        let session = login.unwrap();
        let expiry = session.credential(cx).await.unwrap().expires_at();
        let caps: ClientCapabilities = serde_json::from_value(json!({"roots":{}})).unwrap();
        let client = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(caps),
            ManagedTasksLimits::new(65536, 65536, 32, Duration::from_secs(15)).unwrap()).unwrap();
        let shared = McpRequestCancellation::new();
        let timeout = if matches!(case, InputCase::Deadline) { Duration::from_secs(3) } else { Duration::from_secs(15) };
        let mut policy = ManagedTaskWatchDrivePolicy::new(
            ManagedTaskWatchPolicy::new(timeout, 16, 60).unwrap(), 4, 8, 65536,
        ).unwrap();
        if matches!(case, InputCase::Backoff) {
            policy = policy.with_recovery(ManagedTaskRecoveryPolicy::new(
                2, Duration::from_secs(60), Duration::from_secs(60),
            ).unwrap()).unwrap();
        }
        let (stream, admitted) = pair(Box::pin(listen(peer, matches!(case, InputCase::Backoff))),
            Box::pin(client.watch_task_inputs_with_cancellation(cx, &shared,
                TaskId::parse(TASK_ID).unwrap(), PREFIX.to_owned(), policy))).await;
        let mut driver = admitted.unwrap();
        let handle = driver.cancel_handle();
        drop(Box::pin(driver.drive(cx, no_resolver, no_observer)));
        assert_eq!(peer.posts.load(Ordering::SeqCst), 2, "unpolled drive cannot read or mutate");
        assert_eq!(driver.update_state(), TaskInputUpdateState::NotAttempted);
        assert_eq!(handle.state(), TaskCancellationState::Ready);
        assert!(!format!("{driver:?} {handle:?}").contains(TASK_ID));

        if matches!(case, InputCase::BeforeFirst) {
            let server = Box::pin(async { let mut tls = cancel_head(peer).await; ack(&mut tls).await; });
            let ((), accepted) = pair(server, Box::pin(handle.request_cancel(cx))).await;
            accepted.unwrap();
            assert!(matches!(driver.drive(cx, no_resolver, no_observer).await,
                Err(ManagedTaskWatchDriveError::CancellationRequested)));
            assert_eq!(driver.acknowledged_updates(), 0);
            assert_eq!(driver.update_state(), TaskInputUpdateState::NotAttempted);
            assert_eq!(peer.posts.load(Ordering::SeqCst), 4);
        } else if matches!(case, InputCase::ExpiredCredential) {
            let wait = expiry.saturating_duration_since(Instant::now()) + Duration::from_millis(20);
            Sleep::new(cx.now().saturating_add_nanos(u64::try_from(wait.as_nanos()).unwrap())).await;
            assert!(matches!(handle.request_cancel(cx).await,
                Err(TaskCancellationError::NotAttempted(ManagedTasksError::Session(OAuthSessionError::LoginRequired)))));
            assert_eq!(handle.state(), TaskCancellationState::Ready);
            assert!(matches!(driver.drive(cx, no_resolver, no_observer).await,
                Err(ManagedTaskWatchDriveError::Watch(ManagedTaskWatchError::Session(OAuthSessionError::LoginRequired)))));
            assert_eq!(peer.posts.load(Ordering::SeqCst), 2, "expired input authority cannot renew even while unpolled");
        } else {
            let phase = McpRequestCancellation::new();
            let cancel_entered = McpRequestCancellation::new();
            let release_resolver = McpRequestCancellation::new();
            let resolutions = Cell::new(0);
            let observations = Cell::new(0);
            let resolver_dropped = Cell::new(false);
            let accepted_updates = Cell::new(0);
            let server = Box::pin(async {
                if matches!(case, InputCase::Terminal) {
                    get(peer, "cancelwatch:2", "cancelwatch:3", "completed").await;
                    return 4;
                }
                input_get(peer).await;
                match case {
                    InputCase::Return | InputCase::LocalCancel | InputCase::Deadline => 4,
                    InputCase::Update | InputCase::DropUpdate => {
                        let update = update_head(peer).await;
                        accepted_updates.set(1);
                        phase.cancel();
                        if matches!(case, InputCase::Update) {
                            let mut cancel = cancel_head(peer).await;
                            ack(&mut cancel).await;
                        }
                        require_close(update).await;
                        if matches!(case, InputCase::Update) { 8 } else { 6 }
                    }
                    InputCase::GetAfterUpdate | InputCase::Backoff => {
                        let mut update = update_head(peer).await;
                        accepted_updates.set(1);
                        update_ack(&mut update).await;
                        let get = get_head(peer, "cancelwatch:6", "cancelwatch:7").await;
                        if matches!(case, InputCase::Backoff) {
                            lose_reply(get).await;
                            phase.cancel();
                            let mut cancel = cancel_head(peer).await;
                            ack(&mut cancel).await;
                        } else {
                            phase.cancel();
                            let mut cancel = cancel_head(peer).await;
                            ack(&mut cancel).await;
                            require_close(get).await;
                        }
                        10
                    }
                    InputCase::Refused => {
                        let (mut tls, _) = request(peer, CANCEL_DISCOVERY, "server/discover").await;
                        tls.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                        tls.flush().await.unwrap();
                        drop(tls);
                        let mut update = update_head(peer).await;
                        accepted_updates.set(1);
                        update_ack(&mut update).await;
                        get(peer, "cancelwatch:6", "cancelwatch:7", "completed").await;
                        9
                    }
                    _ => {
                        let mut cancel = cancel_head(peer).await;
                        match case {
                            InputCase::WrongAck => json_reply(&mut cancel,
                                &result("foreign-cancel-reply", json!({"resultType":"complete"}))).await,
                            InputCase::LostAck => lose_reply(cancel).await,
                            InputCase::DropResolver => {
                                cancel_entered.cancel();
                                require_close(cancel).await;
                            }
                            _ => ack(&mut cancel).await,
                        }
                        if failed_cancel(case) {
                            let mut update = update_head(peer).await;
                            accepted_updates.set(1);
                            update_ack(&mut update).await;
                            get(peer, "cancelwatch:6", "cancelwatch:7", "completed").await;
                            10
                        } else { 6 }
                    }
                }
            });
            let consumer = Box::pin(async {
                let mut driving = Box::pin(driver.drive(cx, |pending: TaskInputRequests| {
                    assert_eq!(pending.keys().map(String::as_str).collect::<Vec<_>>(), ["ask"]);
                    resolutions.set(resolutions.get() + 1);
                    assert_eq!(resolutions.get(), 1, "resolver work must never be replayed");
                    let handle = handle.clone();
                    let phase = &phase;
                    let release = &release_resolver;
                    let dropped = &resolver_dropped;
                    async move {
                        struct DropProof<'a>(&'a Cell<bool>);
                        impl Drop for DropProof<'_> { fn drop(&mut self) { self.0.set(true); } }
                        let _proof = DropProof(dropped);
                        if resolver_waits(case) {
                            phase.cancel();
                            release.cancelled().await;
                        }
                        if matches!(case, InputCase::ReadyResolver) {
                            // The real cancel ACK is admitted INSIDE the resolver
                            // poll that returns valid answers. No update may follow.
                            handle.request_cancel(cx).await.unwrap();
                        }
                        if matches!(case, InputCase::Return) {
                            return Ok(ManagedTaskInputAction::ReturnToCaller);
                        }
                        let responses: TaskInputResponses = serde_json::from_value(json!({"ask":{"roots":[]}})).unwrap();
                        Ok(ManagedTaskInputAction::Respond(responses))
                    }
                }, |task| {
                    assert_eq!(task.base().task_id.as_str(), TASK_ID);
                    observations.set(observations.get() + 1);
                    Ok(())
                }));
                if matches!(case, InputCase::DropResolver) {
                    let mut attempt = Box::pin(async { phase.cancelled().await; handle.request_cancel(cx).await });
                    let mut entered = Box::pin(cancel_entered.cancelled());
                    poll_fn(|task| {
                        assert!(driving.as_mut().poll(task).is_pending());
                        assert!(attempt.as_mut().poll(task).is_pending());
                        entered.as_mut().poll(task)
                    }).await;
                    drop(driving);
                    assert!(matches!(attempt.await, Err(TaskCancellationError::Unconfirmed(_))));
                    None
                } else if matches!(case, InputCase::DropUpdate) {
                    let mut entered = Box::pin(phase.cancelled());
                    poll_fn(|task| {
                        assert!(driving.as_mut().poll(task).is_pending());
                        entered.as_mut().poll(task)
                    }).await;
                    drop(driving);
                    None
                } else {
                    let control = Box::pin(async {
                        if matches!(case, InputCase::Terminal | InputCase::Return | InputCase::ReadyResolver | InputCase::Deadline) { return; }
                        phase.cancelled().await;
                        if matches!(case, InputCase::LocalCancel) { shared.cancel(); return; }
                        let cancelled = handle.request_cancel(cx).await;
                        if failed_cancel(case) {
                            assert!(matches!(cancelled, Err(TaskCancellationError::Unconfirmed(_))));
                            assert_eq!(handle.state(), TaskCancellationState::Unconfirmed);
                            release_resolver.cancel();
                        } else { cancelled.unwrap(); }
                    });
                    Some(pair(driving, control).await.0)
                }
            });
            let (expected_posts, outcome) = pair(server, consumer).await;
            if failed_cancel(case) || matches!(case, InputCase::Terminal) {
                assert!(matches!(outcome.unwrap().unwrap(), ManagedTaskRunOutcome::Terminal(task)
                    if matches!(*task, Task::Completed { .. })));
                assert_eq!(handle.state(), if failed_cancel(case) { TaskCancellationState::Unconfirmed } else { TaskCancellationState::Ready });
            } else {
                match case {
                    InputCase::Return => assert!(matches!(outcome.unwrap().unwrap(), ManagedTaskRunOutcome::InputRequired(_))),
                    InputCase::DropResolver | InputCase::DropUpdate => assert!(outcome.is_none()),
                    InputCase::LocalCancel => assert!(matches!(outcome.unwrap(), Err(ManagedTaskWatchDriveError::Watch(
                        ManagedTaskWatchError::Session(OAuthSessionError::Cancelled))))),
                    InputCase::Deadline => assert!(matches!(outcome.unwrap(), Err(ManagedTaskWatchDriveError::Watch(
                        ManagedTaskWatchError::Session(OAuthSessionError::TimedOut))))),
                    _ => assert!(matches!(outcome.unwrap(), Err(ManagedTaskWatchDriveError::CancellationRequested))),
                }
            }
            let acknowledged = failed_cancel(case) || matches!(case, InputCase::GetAfterUpdate | InputCase::Backoff);
            let uncertain = matches!(case, InputCase::Update | InputCase::DropUpdate);
            assert_eq!(driver.update_state(), if acknowledged { TaskInputUpdateState::Acknowledged }
                else if uncertain { TaskInputUpdateState::Unconfirmed } else { TaskInputUpdateState::NotAttempted });
            assert_eq!(driver.acknowledged_updates(), usize::from(acknowledged));
            assert_eq!(accepted_updates.get(), usize::from(acknowledged || uncertain));
            assert_eq!(driver.last_update_request_id(),
                (acknowledged || uncertain).then_some(&RequestId::String("cancelwatch:5".to_owned())));
            assert_eq!(resolutions.get(), usize::from(!matches!(case, InputCase::Terminal)));
            assert_eq!(resolver_dropped.get(), !matches!(case, InputCase::Terminal));
            assert_eq!(observations.get(), if failed_cancel(case) { 2 } else { 1 });
            assert_eq!(peer.posts.load(Ordering::SeqCst), expected_posts);
            assert_eq!(shared.is_cancel_requested(), matches!(case, InputCase::LocalCancel));
        }
        let before = peer.posts.load(Ordering::SeqCst);
        let replay = driver.drive(cx, no_resolver, no_observer).await;
        assert!(matches!(replay, Err(ManagedTaskWatchDriveError::CancellationRequested)
            | Err(ManagedTaskWatchDriveError::Watch(ManagedTaskWatchError::Closed))));
        let cancel_again = handle.clone().request_cancel(cx).await;
        assert!(matches!(cancel_again, Err(TaskCancellationError::Closed | TaskCancellationError::AlreadyAttempted)));
        let state = driver.update_state();
        let count = driver.acknowledged_updates();
        driver.close();
        assert_eq!(driver.update_state(), state);
        assert_eq!(driver.acknowledged_updates(), count);
        require_close(stream).await;
        assert_eq!(peer.posts.load(Ordering::SeqCst), before, "no closed-owner update, cancel or observation replay");
        assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
        assert!(cx.checkpoint().is_ok());
        peer.quiet();
        session.close();
    }

    #[test]
    fn cancel_before_driving_prevents_initial_get_and_callbacks() { isolated_input("cancel_before_driving_prevents_initial_get_and_callbacks", InputCase::BeforeFirst); }
    #[test]
    fn admitted_cancel_interrupts_pending_input_resolver() { isolated_input("admitted_cancel_interrupts_pending_input_resolver", InputCase::Resolver); }
    #[test]
    fn cancel_inside_ready_resolver_prevents_answer_dispatch() { isolated_input("cancel_inside_ready_resolver_prevents_answer_dispatch", InputCase::ReadyResolver); }
    #[test]
    fn cancel_during_update_preserves_unconfirmed_mutation() { isolated_input("cancel_during_update_preserves_unconfirmed_mutation", InputCase::Update); }
    #[test]
    fn cancel_after_update_ack_preserves_receipt_while_closing_get() { isolated_input("cancel_after_update_ack_preserves_receipt_while_closing_get", InputCase::GetAfterUpdate); }
    #[test]
    fn cancel_after_lost_reconciliation_stops_backoff_without_replay() { isolated_input("cancel_after_lost_reconciliation_stops_backoff_without_replay", InputCase::Backoff); }
    #[test]
    fn wrong_cancel_ack_does_not_discard_pending_input() { isolated_input("wrong_cancel_ack_does_not_discard_pending_input", InputCase::WrongAck); }
    #[test]
    fn lost_cancel_ack_does_not_discard_pending_input() { isolated_input("lost_cancel_ack_does_not_discard_pending_input", InputCase::LostAck); }
    #[test]
    fn rejected_cancel_discovery_leaves_input_driver_usable() { isolated_input("rejected_cancel_discovery_leaves_input_driver_usable", InputCase::Refused); }
    #[test]
    fn dropped_driver_releases_resolver_and_outstanding_cancel() { isolated_input("dropped_driver_releases_resolver_and_outstanding_cancel", InputCase::DropResolver); }
    #[test]
    fn dropped_update_wait_keeps_uncertainty_and_retires_owner() { isolated_input("dropped_update_wait_keeps_uncertainty_and_retires_owner", InputCase::DropUpdate); }
    #[test]
    fn terminal_delivery_retires_input_driver_cancel_authority() { isolated_input("terminal_delivery_retires_input_driver_cancel_authority", InputCase::Terminal); }
    #[test]
    fn explicit_input_handoff_closes_run_without_sending_answers() { isolated_input("explicit_input_handoff_closes_run_without_sending_answers", InputCase::Return); }
    #[test]
    fn local_cancellation_is_not_remote_cancellation() { isolated_input("local_cancellation_is_not_remote_cancellation", InputCase::LocalCancel); }
    #[test]
    fn input_resolver_cannot_extend_original_driver_deadline() { isolated_input("input_resolver_cannot_extend_original_driver_deadline", InputCase::Deadline); }
    #[test]
    fn unpolled_expired_driver_cannot_renew_cancel_authority() { isolated_input("unpolled_expired_driver_cannot_renew_cancel_authority", InputCase::ExpiredCredential); }
}
