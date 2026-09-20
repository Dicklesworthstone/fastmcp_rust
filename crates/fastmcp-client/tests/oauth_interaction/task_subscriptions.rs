//! Public TASK-03 subscription composition over the parent's loopback TLS peer.
//! This module is included by driver.rs only with tasks + native-tls-roots.
//! Browser input and the issuer are fixtures; all HTTP exchanges use real TLS.
use super::*;
use fastmcp_client::http_auth::managed::OAuthSessionError;
use fastmcp_client::http_auth::managed::subscriptions::{
    ManagedSubscription, ManagedSubscriptionError, ManagedSubscriptionEvent,
    ManagedSubscriptionLimits,
};
use fastmcp_client::http_auth::managed::tasks::{
    ManagedTaskEvent, ManagedTaskRequest, ManagedTaskRequestIds,
    ManagedTasksClient, ManagedTasksLimits,
};
use fastmcp_protocol::tasks_extension::{Task, TASKS_EXTENSION, task_subscription_ids};
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, FINAL_SUBSCRIPTION_ID_META_KEY};

const WATCH_CASE: &str = "FASTMCP_TEST_TASK_SUBSCRIPTION_CASE";
const DISCOVER: &str = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{"listChanged":true},"extensions":{"io.modelcontextprotocol/tasks":{}}},"ttlMs":0,"cacheScope":"private"}"#;

#[derive(Clone, Copy)]
enum WatchCase {
    Live, Narrowed, BadAck, BadTask, Truncated, Discovery, Preflight,
    Cancel, Close, DropRead, Expiry, Deadline, Limit, NoReplay,
}

fn isolated_watch(name: &str, case: WatchCase) {
    let exact_name = format!("driver::task_subscriptions::{name}");
    if let Ok(selected) = std::env::var(WATCH_CASE) {
        assert_eq!(selected, exact_name);
        run_watch(case);
        return;
    }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &exact_name, "--nocapture", "--test-threads=1"])
        .env(WATCH_CASE, &exact_name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "managed Task subscription HTTPS case failed");
            return;
        }
        assert!(Instant::now() < end, "managed Task subscription child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn filter() -> Value { json!({"taskIds":["task-one","task-two"],"toolsListChanged":true}) }
fn watch_request(filter: Value, extensions: Value) -> CoreRequest {
    CoreRequest::decode(ProtocolEra::Modern2026, "subscriptions/listen", Some(&json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{"extensions":extensions},
            "com.example/identity":"retained"
        },
        "notifications":filter
    }))).unwrap()
}
fn requested() -> CoreRequest { watch_request(filter(), json!({TASKS_EXTENSION:{}})) }
fn ack(id: i64, accepted: Value) -> String {
    json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged", "params":{
        "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):id}, "notifications":accepted,
    }}).to_string()
}
fn done(id: i64) -> String {
    terminal(id, &json!({"resultType":"complete","_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):id}}).to_string())
}
fn task_event(id: i64, task: &str, status: &str) -> String {
    let extra = match status {
        "input_required" => r#", "inputRequests":{"roots":{"method":"roots/list"}}"#,
        "completed" => r#", "result":{"content":[],"x-exact":{"z":900719925474099312345,"a":1.20e+4}}"#,
        _ => "",
    };
    format!(r#"{{"jsonrpc":"2.0","method":"notifications/tasks","params":{{"_meta":{{"io.modelcontextprotocol/subscriptionId":{id}}},"taskId":{},"status":"{status}","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:01Z","ttlMs":60000{extra}}}}}"#, serde_json::to_string(task).unwrap())
}
async fn begin_watch(peer: &Peer, first_id: i64, discovery: &str) -> TlsStream<TcpStream> {
    let discovered = peer.response(first_id, discovery).await;
    assert_eq!(discovered["method"], "server/discover");
    let (mut tls, bytes) = peer.request(false).await;
    let listen: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(listen["method"], "subscriptions/listen");
    assert_eq!(listen["id"], first_id + 1);
    assert_eq!(listen["params"]["notifications"], filter());
    assert_eq!(listen["params"]["_meta"], discovered["params"]["_meta"]);
    assert_eq!(listen["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"], json!({TASKS_EXTENSION:{}}));
    // Peer::request checks that BOTH discovery and listen carry the exact
    // admitted access token and never carry legacy session/replay headers.
    sse_head(&mut tls).await;
    tls
}
async fn consume_ack(watch: &mut ManagedSubscription, cx: &Cx) -> Value {
    let Some(ManagedSubscriptionEvent::Acknowledged { accepted_filter }) = watch.next_event(cx).await.unwrap() else { panic!("first record must be the ACK") };
    assert_eq!(watch.credential_generation(), 1);
    assert!(watch.accepted_filter().is_some());
    serde_json::to_value(accepted_filter).unwrap()
}
async fn consume_task(watch: &mut ManagedSubscription, cx: &Cx) -> Task {
    let Some(ManagedSubscriptionEvent::TaskNotification(event)) = watch.next_event(cx).await.unwrap() else { panic!("typed Task notification required") };
    event.params.task
}
async fn consume_done(watch: &mut ManagedSubscription, cx: &Cx, id: i64) {
    let Some(ManagedSubscriptionEvent::Terminal { subscription_id, .. }) = watch.next_event(cx).await.unwrap() else { panic!("subscription terminal required") };
    assert!(subscription_id.correlates_with(&RequestId::Number(id)));
    assert!(watch.next_event(cx).await.unwrap().is_none());
}
async fn reopen_after_gap(peer: &Peer, session: &ManagedOAuthSession, cx: &Cx) {
    let server = Box::pin(async {
        let mut tls = begin_watch(peer, 51, DISCOVER).await;
        event(&mut tls, &ack(52, filter()), false).await;
        event(&mut tls, &done(52), true).await;
    });
    let client = Box::pin(async {
        let mut watch = session.subscribe_tasks(cx, requested(), RequestId::Number(51), RequestId::Number(52), ManagedSubscriptionLimits::default()).await.unwrap();
        consume_ack(&mut watch, cx).await;
        // No event from the failed listen is manufactured or replayed.
        consume_done(&mut watch, cx, 52).await;
    });
    pair(server, client).await;
}

fn run_watch(case: WatchCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            let login = Box::pin(async {
                let (mut tls, _) = peer.request(true).await;
                let seconds = if matches!(case, WatchCase::Expiry) { 2 } else { 300 };
                json_reply(&mut tls, &json!({"access_token":"interaction-access","token_type":"Bearer","expires_in":seconds}).to_string()).await;
            });
            let policy = OAuthSessionPolicy::new(Duration::ZERO, Duration::from_secs(30), Duration::from_secs(20), 64).unwrap();
            let ((), login) = pair(login, Box::pin(ManagedOAuthSession::authorize(&cx, peer.client(), policy, browser))).await;
            let session = login.unwrap();
            let limits = ManagedSubscriptionLimits::new(65536, 65536,
                if matches!(case, WatchCase::Limit) { 2 } else { 32 },
                if matches!(case, WatchCase::Deadline) { Duration::from_secs(1) } else { Duration::from_secs(15) },
            ).unwrap();
            let cancellation = McpRequestCancellation::new();
            match case {
                WatchCase::Live => {
                    let (release_tx, mut release_rx) = oneshot::channel::<()>();
                    let server = Box::pin(async {
                        let mut tls = begin_watch(&peer, 1, DISCOVER).await;
                        event(&mut tls, &ack(2, filter()), false).await;
                        event(&mut tls, &task_event(2, "task-one", "working"), false).await;
                        event(&mut tls, CHANGED, false).await;
                        event(&mut tls, &task_event(2, "task-one", "input_required"), false).await;
                        // Keep the watch live while the host answers its input
                        // using a separate authenticated Task update operation.
                        let discovered = peer.response(3, DISCOVER).await;
                        assert_eq!(discovered["method"], "server/discover");
                        let updated = peer.response(4, r#"{"resultType":"complete"}"#).await;
                        assert_eq!(updated["method"], "tasks/update");
                        assert_eq!(updated["params"]["taskId"], "task-one");
                        assert_eq!(updated["params"]["inputResponses"], json!({"roots":{"roots":[]}}));
                        event(&mut tls, &task_event(2, "task-one", "completed"), false).await;
                        event(&mut tls, &task_event(2, "task-two", "cancelled"), false).await;
                        release_rx.recv(&cx).await.unwrap();
                        event(&mut tls, &done(2), true).await;
                    });
                    let application = Box::pin(async {
                        let mut watch = session.subscribe_tasks(&cx, requested(), RequestId::Number(1), RequestId::Number(2), limits).await.unwrap();
                        assert_eq!(consume_ack(&mut watch, &cx).await, filter());
                        assert!(matches!(consume_task(&mut watch, &cx).await, Task::Working(_)));
                        assert!(matches!(watch.next_event(&cx).await.unwrap(), Some(ManagedSubscriptionEvent::Notification(_))));
                        let input = consume_task(&mut watch, &cx).await;
                        assert!(matches!(input, Task::InputRequired { .. }));
                        let tasks = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(ClientCapabilities::default()), ManagedTasksLimits::default()).unwrap();
                        let mut update = tasks.request(&cx, ManagedTaskRequestIds::new(RequestId::Number(3), RequestId::Number(4)).unwrap(), ManagedTaskRequest::Update {
                            task:Box::new(input), input_responses:serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap(),
                        }).await.unwrap();
                        assert!(matches!(update.next_event(&cx).await.unwrap(), Some(ManagedTaskEvent::Updated(_))));
                        let completed = consume_task(&mut watch, &cx).await;
                        assert!(matches!(completed, Task::Completed { .. }));
                        let encoded = serde_json::to_string(&completed).unwrap();
                        assert!(encoded.contains("900719925474099312345"));
                        assert!(encoded.contains("1.20e+4"));
                        assert!(matches!(consume_task(&mut watch, &cx).await, Task::Cancelled(_)));
                        // Task completion did not close a multi-task subscription.
                        release_tx.send(&cx, ()).unwrap();
                        consume_done(&mut watch, &cx, 2).await;
                    });
                    pair(server, application).await;
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 4);
                }
                WatchCase::Narrowed | WatchCase::BadAck | WatchCase::BadTask | WatchCase::Truncated => {
                    let variants = if matches!(case, WatchCase::BadTask) { 3 } else { 1 };
                    for variant in 0..variants {
                        let first = 1 + variant * 2;
                        let listen_id = first + 1;
                        let server = Box::pin(async {
                            let mut tls = begin_watch(&peer, first, DISCOVER).await;
                            if matches!(case, WatchCase::BadAck) {
                                event(&mut tls, &ack(listen_id, json!({"taskIds":["unrequested"]})), true).await;
                            } else if matches!(case, WatchCase::Narrowed) {
                                event(&mut tls, &ack(listen_id, json!({"taskIds":["task-one"]})), false).await;
                                event(&mut tls, &task_event(listen_id, "task-two", "working"), true).await;
                            } else {
                                event(&mut tls, &ack(listen_id, filter()), false).await;
                                let payload = if matches!(case, WatchCase::Truncated) {
                                    task_event(listen_id, "task-one", "working")
                                } else {
                                    match variant {
                                        0 => task_event(listen_id + 1, "task-one", "working"),
                                        1 => task_event(listen_id, "unknown", "working"),
                                        _ => task_event(listen_id, "task-one", "completed").replace("\"content\":[]", "\"content\":false"),
                                    }
                                };
                                event(&mut tls, &payload, true).await;
                            }
                        });
                        let application = Box::pin(async {
                            let mut watch = session.subscribe_tasks(&cx, requested(), RequestId::Number(first), RequestId::Number(listen_id), limits).await.unwrap();
                            if !matches!(case, WatchCase::BadAck) {
                                let accepted = consume_ack(&mut watch, &cx).await;
                                if matches!(case, WatchCase::Narrowed) {
                                    assert_eq!(accepted, json!({"taskIds":["task-one"]}));
                                    assert_eq!(task_subscription_ids(watch.accepted_filter().unwrap()).unwrap().unwrap().len(), 1);
                                }
                            }
                            if matches!(case, WatchCase::Truncated) { consume_task(&mut watch, &cx).await; }
                            let error = watch.next_event(&cx).await.err().unwrap();
                            assert!(matches!(error, ManagedSubscriptionError::InvalidResponse | ManagedSubscriptionError::MissingTerminal));
                            if matches!(case, WatchCase::BadAck) { assert!(watch.accepted_filter().is_none()); }
                            assert!(matches!(watch.next_event(&cx).await, Err(ManagedSubscriptionError::Closed)));
                        });
                        pair(server, application).await;
                        peer.quiet();
                    }
                    reopen_after_gap(&peer, &session, &cx).await;
                    assert_eq!(peer.posts.load(Ordering::SeqCst), (2 * variants + 2) as usize);
                }
                WatchCase::Discovery => {
                    for (index, (from, to)) in [
                        ("2026-07-28", "2024-11-05"),
                        ("\"io.modelcontextprotocol/tasks\":{}", "\"com.example/other\":{}"),
                        ("\"io.modelcontextprotocol/tasks\":{}", "\"io.modelcontextprotocol/tasks\":{\"extra\":true}"),
                    ].into_iter().enumerate() {
                        let response = DISCOVER.replace(from, to);
                        let id = 1 + index as i64 * 2;
                        let (request, outcome) = pair(Box::pin(peer.response(id, &response)), Box::pin(session.subscribe_tasks(&cx, requested(), RequestId::Number(id), RequestId::Number(id+1), limits))).await;
                        assert_eq!(request["method"], "server/discover");
                        assert!(matches!(outcome, Err(ManagedSubscriptionError::Negotiation)));
                        assert_eq!(peer.posts.load(Ordering::SeqCst), index + 1);
                        peer.quiet();
                    }
                    reopen_after_gap(&peer, &session, &cx).await;
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 5);
                }
                WatchCase::Preflight => {
                    let repeated: RequestId = serde_json::from_str("1e0").unwrap();
                    assert!(matches!(session.subscribe_tasks(&cx, requested(), RequestId::Number(1), repeated, limits).await, Err(ManagedSubscriptionError::InvalidRequest)));
                    for (filter, settings) in [
                        (json!({"taskIds":[""]}), json!({TASKS_EXTENSION:{}})),
                        (json!({"taskIds":["task-one"]}), json!({})),
                        (json!({"taskIds":["task-one"],"unknown":true}), json!({TASKS_EXTENSION:{}})),
                    ] {
                        assert!(session.subscribe_tasks(&cx, watch_request(filter, settings), RequestId::Number(1), RequestId::Number(2), limits).await.is_err());
                    }
                    assert!(matches!(session.subscribe_core(&cx, requested(), RequestId::Number(2), limits).await, Err(ManagedSubscriptionError::UnsupportedExtension)));
                    let tiny = ManagedSubscriptionLimits::new(1,65536,8,Duration::from_secs(1)).unwrap();
                    assert!(matches!(session.subscribe_tasks(&cx, requested(), RequestId::Number(1), RequestId::Number(2), tiny).await, Err(ManagedSubscriptionError::RequestTooLarge)));
                    cancellation.cancel();
                    assert!(matches!(session.subscribe_tasks_with_cancellation(&cx, &cancellation, requested(), RequestId::Number(1), RequestId::Number(2), limits).await, Err(ManagedSubscriptionError::Session(OAuthSessionError::Cancelled))));
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
                }
                WatchCase::NoReplay => {
                    for status in [0, 307, 403] {
                        let server = Box::pin(async {
                            peer.response(1, DISCOVER).await;
                            let (mut tls, _) = peer.request(false).await;
                            if status == 307 {
                                tls.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://127.0.0.1:9/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                                tls.flush().await.unwrap();
                            } else if status == 403 {
                                tls.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                                tls.flush().await.unwrap();
                            }
                        });
                        let ((), result) = pair(server, Box::pin(session.subscribe_tasks(&cx, requested(), RequestId::Number(1), RequestId::Number(2), limits))).await;
                        assert!(result.is_err());
                        peer.quiet();
                    }
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 6);
                }
                WatchCase::Cancel | WatchCase::Close | WatchCase::DropRead | WatchCase::Expiry | WatchCase::Deadline | WatchCase::Limit => {
                    let server = Box::pin(async {
                        let mut tls = begin_watch(&peer, 1, DISCOVER).await;
                        event(&mut tls, &ack(2, filter()), false).await;
                        if matches!(case, WatchCase::Limit) { event(&mut tls, &task_event(2,"task-one","working"), false).await; }
                        let mut byte = [0];
                        assert!(!matches!(tls.read(&mut byte).await, Ok(n) if n > 0), "local termination must release the owned TLS stream");
                    });
                    let application = Box::pin(async {
                        let mut watch = session.subscribe_tasks_with_cancellation(&cx, &cancellation, requested(), RequestId::Number(1), RequestId::Number(2), limits).await.unwrap();
                        consume_ack(&mut watch, &cx).await;
                        if matches!(case, WatchCase::Limit) {
                            consume_task(&mut watch, &cx).await;
                            assert!(matches!(watch.next_event(&cx).await, Err(ManagedSubscriptionError::RecordLimit)));
                        } else if matches!(case, WatchCase::Deadline) {
                            Sleep::new(cx.now().saturating_add_nanos(1_100_000_000)).await;
                            assert!(matches!(watch.next_event(&cx).await, Err(ManagedSubscriptionError::Session(OAuthSessionError::TimedOut))));
                        } else {
                            let mut reading = Box::pin(watch.next_event(&cx));
                            poll_fn(|task| { assert!(reading.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                            match case {
                                WatchCase::Cancel => { cancellation.cancel(); },
                                WatchCase::Close => session.close(),
                                _ => {},
                            }
                            if matches!(case, WatchCase::DropRead) { drop(reading); }
                            else {
                                let error = reading.await.err().unwrap();
                                match case {
                                    WatchCase::Cancel => assert!(matches!(error, ManagedSubscriptionError::Session(OAuthSessionError::Cancelled))),
                                    WatchCase::Close => assert!(matches!(error, ManagedSubscriptionError::Session(OAuthSessionError::Closed))),
                                    _ => assert!(matches!(error, ManagedSubscriptionError::Session(OAuthSessionError::LoginRequired))),
                                }
                            }
                        }
                        assert!(matches!(watch.next_event(&cx).await, Err(ManagedSubscriptionError::Closed)));
                        assert!(cx.checkpoint().is_ok());
                    });
                    pair(server, application).await;
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                    if !matches!(case, WatchCase::Close | WatchCase::Expiry) {
                        reopen_after_gap(&peer, &session, &cx).await;
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 4);
                    }
                }
            }
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1, "no watch failure replays an OAuth grant");
            peer.quiet();
            session.close();
        });
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario).await.expect("Task watch fixture must settle within its bound");
    }));
}

#[test]
fn task_watch_delivers_mixed_events_and_allows_live_input_update() { isolated_watch("task_watch_delivers_mixed_events_and_allows_live_input_update", WatchCase::Live); }
#[test]
fn task_watch_enforces_the_narrowed_accepted_ids() { isolated_watch("task_watch_enforces_the_narrowed_accepted_ids", WatchCase::Narrowed); }
#[test]
fn task_watch_rejects_widened_ack_without_publication() { isolated_watch("task_watch_rejects_widened_ack_without_publication", WatchCase::BadAck); }
#[test]
fn task_watch_rejects_foreign_ids_and_malformed_snapshots() { isolated_watch("task_watch_rejects_foreign_ids_and_malformed_snapshots", WatchCase::BadTask); }
#[test]
fn task_watch_requires_its_own_terminal_result() { isolated_watch("task_watch_requires_its_own_terminal_result", WatchCase::Truncated); }
#[test]
fn task_watch_discovery_failures_prevent_the_listen_post() { isolated_watch("task_watch_discovery_failures_prevent_the_listen_post", WatchCase::Discovery); }
#[test]
fn task_watch_preflight_refusals_make_no_peer_contact() { isolated_watch("task_watch_preflight_refusals_make_no_peer_contact", WatchCase::Preflight); }
#[test]
fn task_watch_does_not_retry_lost_redirected_or_forbidden_requests() { isolated_watch("task_watch_does_not_retry_lost_redirected_or_forbidden_requests", WatchCase::NoReplay); }
#[test]
fn task_watch_cancellation_does_not_cancel_sibling_calls() { isolated_watch("task_watch_cancellation_does_not_cancel_sibling_calls", WatchCase::Cancel); }
#[test]
fn task_watch_session_closure_wakes_idle_reads() { isolated_watch("task_watch_session_closure_wakes_idle_reads", WatchCase::Close); }
#[test]
fn task_watch_abandoned_read_cannot_resume() { isolated_watch("task_watch_abandoned_read_cannot_resume", WatchCase::DropRead); }
#[test]
fn task_watch_original_token_expiry_is_terminal() { isolated_watch("task_watch_original_token_expiry_is_terminal", WatchCase::Expiry); }
#[test]
fn task_watch_deadline_includes_consumer_pauses() { isolated_watch("task_watch_deadline_includes_consumer_pauses", WatchCase::Deadline); }
#[test]
fn task_watch_bounds_records_without_claiming_completion() { isolated_watch("task_watch_bounds_records_without_claiming_completion", WatchCase::Limit); }
