//! Uses the parent's real TLS/OAuth fixture, not an injected executor.
//! Enabled by `tasks,native-tls-roots` on the oauth_interaction target.
use super::*;
use fastmcp_client::http_auth::managed::OAuthSessionError;
use fastmcp_client::http_auth::managed::tasks::{
    ManagedTaskCall, ManagedTaskEvent, ManagedTaskRequest, ManagedTaskRequestIds,
    ManagedTasksClient, ManagedTasksError, ManagedTasksLimits,
};
use fastmcp_protocol::tasks_extension::{GetTaskResult, Task, TaskId, TaskInputResponses, TASKS_EXTENSION};
use fastmcp_protocol::{ClientCapabilities, FinalCoreResult, FinalRequestMeta, ServerNotification};

const TASK_CASE: &str = "FASTMCP_TEST_MANAGED_TASK_CASE";
const DISCOVERY: &str = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"extensions":{"io.modelcontextprotocol/tasks":{}}},"ttlMs":0,"cacheScope":"private"}"#;
const WORKING: &str = r#"{"resultType":"complete","taskId":"task-one","status":"working","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":60000}"#;
const CREATED: &str = r#"{"resultType":"task","taskId":"task-one","status":"working","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":60000}"#;
const INPUT: &str = r#"{"resultType":"complete","taskId":"task-one","status":"input_required","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:01Z","ttlMs":60000,"inputRequests":{"roots":{"method":"roots/list"}}}"#;
const COMPLETED: &str = r#"{"resultType":"complete","taskId":"task-one","status":"completed","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:02Z","ttlMs":60000,"result":{"content":[{"type":"text","text":"done"}],"x-exact":{"z":900719925474099312345,"a":1.20e+4}}}"#;

#[derive(Clone, Copy)]
enum TaskCase { Lifecycle, Discovery, Preflight, Streaming, InvalidResult, NoReplay, Cancel, Close, DropRead, Expiry, Deadline }

fn isolated_task(name: &str, case: TaskCase) {
    if let Ok(selected) = std::env::var(TASK_CASE) {
        assert_eq!(selected, name);
        run_tasks(case);
        return;
    }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(TASK_CASE, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success(), "managed Tasks HTTPS case failed"); return; }
        assert!(Instant::now() < end, "managed Tasks child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn task_id() -> TaskId { TaskId::parse("task-one").unwrap() }
fn ids(number: i64) -> ManagedTaskRequestIds { ManagedTaskRequestIds::new(RequestId::Number(number), RequestId::Number(number + 1)).unwrap() }
fn tool() -> ManagedTaskRequest { ManagedTaskRequest::CallTool { name: "echo".to_owned(), arguments: Some(json!({"subject":"work"})) } }
fn task_answers(key: &str) -> TaskInputResponses { serde_json::from_value(json!({key:{"roots":[]}})).unwrap() }
fn input_task() -> Task { serde_json::from_str::<GetTaskResult>(INPUT).unwrap().task }

async fn discovery(peer: &Peer, number: i64, result: &str) {
    let request = peer.response(number, result).await;
    assert_eq!(request["method"], "server/discover");
}
async fn operation(peer: &Peer, number: i64, method: &str, result: &str) -> Value {
    discovery(peer, number, DISCOVERY).await;
    let request = peer.response(number + 1, result).await;
    assert_eq!(request["method"], method);
    assert_eq!(request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"], json!({TASKS_EXTENSION:{}}));
    request
}
async fn first_progress(call: &mut ManagedTaskCall, cx: &Cx) {
    let Some(ManagedTaskEvent::Notification(notification)) = call.next_event(cx).await.unwrap() else { panic!("progress expected before terminal") };
    assert!(matches!(*notification, ServerNotification::Progress(_)));
}
async fn begin_task_stream(peer: &Peer) -> TlsStream<TcpStream> {
    discovery(peer, 1, DISCOVERY).await;
    let (mut tls, body) = peer.request(false).await;
    let request: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(request["id"], 2);
    assert_eq!(request["method"], "tools/call");
    assert_eq!(request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"], json!({TASKS_EXTENSION:{}}));
    sse_head(&mut tls).await;
    event(&mut tls, r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"owned","progress":1}}"#, false).await;
    tls
}

fn run_tasks(case: TaskCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        // Box the whole scenario and the paired branch futures; a case matrix
        // must not inline every native TLS state machine onto a test stack.
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            let login = async {
                let (mut tls, _) = peer.request(true).await;
                let expiry = if matches!(case, TaskCase::Expiry) { 2 } else { 300 };
                json_reply(&mut tls, &json!({"access_token":"interaction-access","token_type":"Bearer","expires_in":expiry}).to_string()).await;
            };
            let ((), login) = pair(Box::pin(login), Box::pin(ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser))).await;
            let session = login.unwrap();
            let mut metadata = FinalRequestMeta::new(ClientCapabilities::default());
            metadata.additional_metadata.insert("progressToken".to_owned(), json!("owned"));
            let limits = if matches!(case, TaskCase::Deadline) {
                ManagedTasksLimits::new(65536, 65536, 64, Duration::from_secs(1)).unwrap()
            } else { ManagedTasksLimits::default() };
            let client = ManagedTasksClient::new(session.clone(), metadata.clone(), limits).unwrap();
            match case {
                TaskCase::Lifecycle => {
                    let server = Box::pin(async {
                        let created = operation(&peer, 1, "tools/call", CREATED).await;
                        assert_eq!(created["params"]["arguments"], json!({"subject":"work"}));
                        operation(&peer, 3, "tasks/get", INPUT).await;
                        let update = operation(&peer, 5, "tasks/update", r#"{"resultType":"complete"}"#).await;
                        assert_eq!(update["params"]["taskId"], "task-one");
                        assert_eq!(update["params"]["inputResponses"], json!({"roots":{"roots":[]}}));
                        operation(&peer, 7, "tasks/get", COMPLETED).await;
                        operation(&peer, 9, "tasks/cancel", r#"{"resultType":"complete"}"#).await;
                    });
                    let application = Box::pin(async {
                        let mut create = client.request(&cx, ids(1), tool()).await.unwrap();
                        let Some(ManagedTaskEvent::ToolResult(created)) = create.next_event(&cx).await.unwrap() else { panic!("Task create result") };
                        assert!(matches!(*created, FinalCoreResult::ToolsCallTask { .. }));
                        assert!(create.next_event(&cx).await.unwrap().is_none());
                        let mut get = client.request(&cx, ids(3), ManagedTaskRequest::Get(task_id())).await.unwrap();
                        let Some(ManagedTaskEvent::Snapshot(snapshot)) = get.next_event(&cx).await.unwrap() else { panic!("Task get result") };
                        assert!(matches!(snapshot.task, Task::InputRequired { .. }));
                        let mut update = client.request(&cx, ids(5), ManagedTaskRequest::Update { task:Box::new(snapshot.task), input_responses:task_answers("roots") }).await.unwrap();
                        assert!(matches!(update.next_event(&cx).await.unwrap(), Some(ManagedTaskEvent::Updated(_))));
                        let mut complete = client.request(&cx, ids(7), ManagedTaskRequest::Get(task_id())).await.unwrap();
                        let Some(ManagedTaskEvent::Snapshot(snapshot)) = complete.next_event(&cx).await.unwrap() else { panic!("completed Task snapshot") };
                        assert!(matches!(snapshot.task, Task::Completed { .. }));
                        let encoded = serde_json::to_string(&snapshot).unwrap();
                        assert!(encoded.contains("900719925474099312345"));
                        assert!(encoded.contains("1.20e+4"));
                        let mut cancel = client.request(&cx, ids(9), ManagedTaskRequest::Cancel(task_id())).await.unwrap();
                        assert!(matches!(cancel.next_event(&cx).await.unwrap(), Some(ManagedTaskEvent::Cancelled(_))));
                        assert_eq!(cancel.credential_generation(), 1);
                    });
                    pair(server, application).await;
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 10);
                }
                TaskCase::Discovery => {
                    for (index, (from, to)) in [
                        ("\"io.modelcontextprotocol/tasks\":{}", "\"com.example/other\":{}"),
                        ("\"io.modelcontextprotocol/tasks\":{}", "\"io.modelcontextprotocol/tasks\":{\"invented\":true}"),
                        ("2026-07-28", "2024-11-05"),
                    ].into_iter().enumerate() {
                        let response = DISCOVERY.replace(from, to);
                        let number = 1 + 2 * index as i64;
                        let ((), result) = pair(Box::pin(discovery(&peer, number, &response)), Box::pin(client.request(&cx, ids(number), ManagedTaskRequest::Cancel(task_id())))).await;
                        assert!(matches!(result, Err(ManagedTasksError::Negotiation)));
                        assert_eq!(peer.posts.load(Ordering::SeqCst), index + 1);
                    }
                    let response = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":false,"ttlMs":0,"cacheScope":"private"}"#;
                    let ((), result) = pair(Box::pin(discovery(&peer, 7, response)), Box::pin(client.request(&cx, ids(7), ManagedTaskRequest::Cancel(task_id())))).await;
                    assert!(matches!(result, Err(ManagedTasksError::InvalidResponse)));
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 4, "discovery only, no Task operation");
                }
                TaskCase::Preflight => {
                    assert!(matches!(client.request(&cx, ids(1), ManagedTaskRequest::Update { task:Box::new(input_task()), input_responses:task_answers("other") }).await, Err(ManagedTasksError::InvalidInputResponses)));
                    assert!(matches!(client.request(&cx, ids(3), ManagedTaskRequest::CallTool { name:"echo".to_owned(), arguments:Some(Value::Null) }).await, Err(ManagedTasksError::InvalidRequest)));
                    let tiny = ManagedTasksClient::new(session.clone(), metadata, ManagedTasksLimits::new(1, 1024, 1, Duration::from_secs(1)).unwrap()).unwrap();
                    assert!(matches!(tiny.request(&cx, ids(5), ManagedTaskRequest::Cancel(task_id())).await, Err(ManagedTasksError::RequestTooLarge)));
                    let cancellation = McpRequestCancellation::new();
                    cancellation.cancel();
                    assert!(matches!(client.request_with_cancellation(&cx, &cancellation, ids(7), tool()).await, Err(ManagedTasksError::Session(OAuthSessionError::Cancelled))));
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
                }
                TaskCase::Streaming => {
                    let (tx, mut rx) = oneshot::channel::<()>();
                    let server = Box::pin(async {
                        let mut tls = begin_task_stream(&peer).await;
                        rx.recv(&cx).await.unwrap();
                        event(&mut tls, &terminal(2, CREATED), true).await;
                    });
                    let application = Box::pin(async {
                        let mut call = client.request(&cx, ids(1), tool()).await.unwrap();
                        first_progress(&mut call, &cx).await;
                        tx.send(&cx, ()).unwrap();
                        let Some(ManagedTaskEvent::ToolResult(task)) = call.next_event(&cx).await.unwrap() else { panic!("streamed Task result") };
                        assert!(matches!(*task, FinalCoreResult::ToolsCallTask { .. }));
                        assert!(call.next_event(&cx).await.unwrap().is_none());
                    });
                    pair(server, application).await;
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                }
                TaskCase::InvalidResult => {
                    for (index, response) in [
                        terminal(999, WORKING), terminal(4, &WORKING.replace("task-one", "other-task")),
                        r#"{"jsonrpc":"2.0","id":6,"id":6,"result":{"resultType":"complete"}}"#.to_owned(),
                        format!("[{}]", terminal(8, WORKING)),
                    ].into_iter().enumerate() {
                        let number = 1 + 2 * index as i64;
                        let server = Box::pin(async {
                            discovery(&peer, number, DISCOVERY).await;
                            let (mut tls, _) = peer.request(false).await;
                            json_reply(&mut tls, &response).await;
                        });
                        let application = Box::pin(async {
                            let mut call = client.request(&cx, ids(number), ManagedTaskRequest::Get(task_id())).await.unwrap();
                            let error = call.next_event(&cx).await.err().unwrap();
                            match index {
                                0 => assert!(matches!(error, ManagedTasksError::ResponseIdMismatch)),
                                1 => assert!(matches!(error, ManagedTasksError::TaskIdMismatch)),
                                _ => assert!(matches!(error, ManagedTasksError::InvalidResponse)),
                            }
                            assert!(matches!(call.next_event(&cx).await, Err(ManagedTasksError::Closed)));
                        });
                        pair(server, application).await;
                    }
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 8);
                }
                TaskCase::NoReplay => {
                    for (index, status) in [None, Some(401_u16), Some(307), Some(500)].into_iter().enumerate() {
                        let number = 1 + 2 * index as i64;
                        let server = Box::pin(async {
                            discovery(&peer, number, DISCOVERY).await;
                            let (mut tls, body) = peer.request(false).await;
                            assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["method"], "tasks/cancel");
                            if let Some(status) = status {
                                tls.write_all(format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\nprivate-peer-error").as_bytes()).await.unwrap();
                                tls.flush().await.unwrap();
                            }
                        });
                        let ((), result) = pair(server, Box::pin(client.request(&cx, ids(number), ManagedTaskRequest::Cancel(task_id())))).await;
                        let error = result.err().expect("failed mutation cannot yield a usable response");
                        assert!(!format!("{error:?} {error}").contains("private-peer-error"));
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 2 * (index + 1));
                        peer.quiet();
                    }
                }
                TaskCase::Cancel | TaskCase::Close | TaskCase::DropRead | TaskCase::Expiry | TaskCase::Deadline => {
                    let cancellation = McpRequestCancellation::new();
                    let server = Box::pin(async {
                        let mut tls = begin_task_stream(&peer).await;
                        let mut byte = [0];
                        assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0), "terminal read closes its connection");
                    });
                    let application = Box::pin(async {
                        let mut call = client.request_with_cancellation(&cx, &cancellation, ids(1), tool()).await.unwrap();
                        first_progress(&mut call, &cx).await;
                        if matches!(case, TaskCase::Deadline) {
                            Sleep::new(cx.now().saturating_add_nanos(1_100_000_000)).await;
                            assert!(matches!(call.next_event(&cx).await, Err(ManagedTasksError::Session(OAuthSessionError::TimedOut))));
                        } else {
                            let mut reading = Box::pin(call.next_event(&cx));
                            poll_fn(|task| { assert!(reading.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                            match case {
                                TaskCase::Cancel => { cancellation.cancel(); },
                                TaskCase::Close => session.close(),
                                _ => {},
                            }
                            if matches!(case, TaskCase::DropRead) { drop(reading); }
                            else {
                                let error = reading.await.err().unwrap();
                                match case {
                                    TaskCase::Cancel => assert!(matches!(error, ManagedTasksError::Session(OAuthSessionError::Cancelled))),
                                    TaskCase::Close => assert!(matches!(error, ManagedTasksError::Session(OAuthSessionError::Closed))),
                                    _ => assert!(matches!(error, ManagedTasksError::Session(OAuthSessionError::LoginRequired))),
                                }
                            }
                        }
                        assert!(matches!(call.next_event(&cx).await, Err(ManagedTasksError::Closed)));
                        assert!(cx.checkpoint().is_ok());
                    });
                    pair(server, application).await;
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                }
            }
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
            peer.quiet();
            session.close();
        });
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario).await.expect("managed Tasks case must settle within its bound");
    }));
}

#[test]
fn managed_tasks_complete_create_get_input_update_get_cancel() { isolated_task("tasks::managed_tasks_complete_create_get_input_update_get_cancel", TaskCase::Lifecycle); }
#[test]
fn managed_tasks_require_fresh_exact_discovery_before_each_post() { isolated_task("tasks::managed_tasks_require_fresh_exact_discovery_before_each_post", TaskCase::Discovery); }
#[test]
fn managed_tasks_invalid_input_has_no_discovery_or_mutation_effect() { isolated_task("tasks::managed_tasks_invalid_input_has_no_discovery_or_mutation_effect", TaskCase::Preflight); }
#[test]
fn managed_tasks_stream_progress_before_the_created_task() { isolated_task("tasks::managed_tasks_stream_progress_before_the_created_task", TaskCase::Streaming); }
#[test]
fn managed_tasks_reject_foreign_ids_and_malformed_results() { isolated_task("tasks::managed_tasks_reject_foreign_ids_and_malformed_results", TaskCase::InvalidResult); }
#[test]
fn managed_tasks_never_retry_uncertain_or_rejected_mutations() { isolated_task("tasks::managed_tasks_never_retry_uncertain_or_rejected_mutations", TaskCase::NoReplay); }
#[test]
fn managed_tasks_cancellation_closes_only_the_owned_read() { isolated_task("tasks::managed_tasks_cancellation_closes_only_the_owned_read", TaskCase::Cancel); }
#[test]
fn managed_tasks_session_closure_wakes_the_owned_read() { isolated_task("tasks::managed_tasks_session_closure_wakes_the_owned_read", TaskCase::Close); }
#[test]
fn managed_tasks_abandoned_read_cannot_resume() { isolated_task("tasks::managed_tasks_abandoned_read_cannot_resume", TaskCase::DropRead); }
#[test]
fn managed_tasks_original_credential_expiry_is_terminal() { isolated_task("tasks::managed_tasks_original_credential_expiry_is_terminal", TaskCase::Expiry); }
#[test]
fn managed_tasks_deadline_includes_consumer_pauses() { isolated_task("tasks::managed_tasks_deadline_includes_consumer_pauses", TaskCase::Deadline); }
