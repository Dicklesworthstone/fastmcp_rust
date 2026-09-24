//! Real TLS Tasks + machine OAuth composition. The parent fixture supplies
//! isolated trust, resource/issuer discovery and the actual Basic token grant.
//! This is client interoperability against a local peer, not server conformance.

#[path = "subscriptions.rs"]
mod subscriptions;

use super::*;
use fastmcp_client::http_auth::discovery::client_credentials::tasks::{
    ClientCredentialsTasksClient, ClientCredentialsTasksError as TaskError,
    ClientCredentialsTasksLimits, ManagedTaskEvent, ManagedTaskRequest, ManagedTasksError,
};
use fastmcp_protocol::tasks_extension::{Task, TaskId, TASKS_EXTENSION};

const TASK_CHILD: &str = "FASTMCP_TEST_MACHINE_TASKS_CASE";
const PROGRESS: &str = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"work","progress":1}}"#;
#[derive(Clone, Copy)]
enum TaskCase {
    Lifecycle, MissingTasks, MissingAuth, WrongResponse, WrongTask, InvalidProgress,
    Truncated, Cancel, Close, Abandon, Expiry, Deadline, RecordLimit,
    Denied, Redirect, LostMutation, Preflight, Renewal,
}

fn isolated_task(name: &str, case: TaskCase) {
    if let Ok(selected) = std::env::var(TASK_CHILD) { assert_eq!(selected, name); run_tasks(case); return; }
    let roots = RootFile::create();
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(TASK_CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success(), "machine Tasks TLS case failed"); return; }
        assert!(Instant::now() < end, "machine Tasks child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn metadata() -> FinalRequestMeta {
    let mut metadata = core("tools/call").encode_params().unwrap().unwrap()["_meta"].clone();
    metadata["progressToken"] = json!("work");
    metadata["io.modelcontextprotocol/clientCapabilities"]["roots"] = json!({});
    serde_json::from_value(metadata).unwrap()
}
fn task_id() -> TaskId { TaskId::parse("machine-task").unwrap() }
fn call_tool() -> ManagedTaskRequest { ManagedTaskRequest::CallTool { name:"compute".to_owned(), arguments:Some(json!({"n":7})) } }
fn task(status: &str, discriminator: &str) -> String {
    let mut task = json!({"resultType":discriminator,"taskId":"machine-task","status":status,
        "createdAt":"2026-09-17T00:00:00Z","lastUpdatedAt":"2026-09-17T00:00:00Z","ttlMs":60000});
    if status == "input_required" { task["inputRequests"] = json!({"roots":{"method":"roots/list"}}); }
    task.to_string()
}
fn discovery() -> Value {
    let mut result: Value = serde_json::from_str(DISCOVERY).unwrap();
    result["capabilities"]["extensions"][TASKS_EXTENSION] = json!({});
    result
}

async fn rpc(peer: &Peer, id: i64, method: &str, token: &str) -> (TlsStream<TcpStream>, Value) {
    let (tls, start, headers, bytes) = peer.request().await;
    assert_eq!(start, "POST /mcp HTTP/1.1");
    assert_eq!(headers["authorization"], format!("Bearer {token}"));
    assert!(!headers.values().any(|value| value.contains("service-secret") || value == BASIC));
    assert_eq!(headers["mcp-method"], method);
    assert_eq!(headers["mcp-protocol-version"], "2026-07-28");
    assert!(!headers.contains_key("mcp-session-id") && !headers.contains_key("last-event-id"));
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["id"], id);
    assert_eq!(body["method"], method);
    let metadata = &body["params"]["_meta"];
    assert_eq!(metadata["com.example/tenant"], "unchanged");
    assert_eq!(metadata["io.modelcontextprotocol/clientCapabilities"]["extensions"],
        json!({CLIENT_CREDENTIALS_EXTENSION:{},TASKS_EXTENSION:{}}));
    if method == "tools/call" { assert_eq!(headers["mcp-name"], "compute"); }
    peer.rpcs.fetch_add(1, Ordering::SeqCst);
    (tls, body)
}
async fn discover(peer: &Peer, id: i64, token: &str, document: &Value) {
    let (mut tls, _) = rpc(peer, id, "server/discover", token).await;
    json_reply(&mut tls, &terminal(id, &document.to_string())).await;
}
async fn operation(peer: &Peer, id: i64, method: &str, token: &str, result: &str) -> Value {
    discover(peer, id, token, &discovery()).await;
    let (mut tls, request) = rpc(peer, id+1, method, token).await;
    json_reply(&mut tls, &terminal(id+1, result)).await;
    request
}
async fn result(client: &ClientCredentialsTasksClient, cx: &Cx, id: i64, request: ManagedTaskRequest) -> ManagedTaskEvent {
    let mut call = client.request(cx, RequestId::Number(id), RequestId::Number(id+1), request).await.unwrap();
    assert!(call.request_id().correlates_with(&RequestId::Number(id+1)));
    let result = call.next_event(cx).await.unwrap().expect("one terminal event");
    assert!(call.next_event(cx).await.unwrap().is_none());
    result
}

fn run_tasks(case: TaskCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            let plan = peer.plan(Duration::from_secs(15));
            let ((), client) = pair(peer.metadata(Case::Complete), plan.discover(&cx)).await;
            let client = client.unwrap();
            let limits = match case {
                TaskCase::Deadline => ClientCredentialsTasksLimits::new(65536,65536,64,Duration::from_secs(1)).unwrap(),
                TaskCase::RecordLimit => ClientCredentialsTasksLimits::new(65536,65536,1,Duration::from_secs(15)).unwrap(),
                _ => ClientCredentialsTasksLimits::default(),
            };
            let tasks = ClientCredentialsTasksClient::new(client.clone(), metadata(), limits).unwrap();
            match case {
                TaskCase::Lifecycle => {
                    let server = async {
                        peer.grant("access-one",300).await;
                        discover(&peer,1,"access-one",&discovery()).await;
                        let (mut stream, request) = rpc(&peer,2,"tools/call","access-one").await;
                        assert_eq!(request["params"]["arguments"],json!({"n":7}));
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
                        event(&mut stream,PROGRESS,false).await;
                        event(&mut stream,&terminal(2,&task("working","task")),true).await;
                        operation(&peer,3,"tasks/get","access-one",&task("input_required","complete")).await;
                        let update=operation(&peer,5,"tasks/update","access-one",r#"{"resultType":"complete"}"#).await;
                        assert_eq!(update["params"]["taskId"],"machine-task");
                        assert_eq!(update["params"]["inputResponses"],json!({"roots":{"roots":[]}}));
                        operation(&peer,7,"tasks/get","access-one",&task("working","complete")).await;
                        let cancelled=operation(&peer,9,"tasks/cancel","access-one",r#"{"resultType":"complete"}"#).await;
                        assert_eq!(cancelled["params"]["taskId"],"machine-task");
                        operation(&peer,11,"tasks/get","access-one",&task("cancelled","complete")).await;
                    };
                    let application = async {
                        let mut call=tasks.request(&cx,RequestId::Number(1),RequestId::Number(2),call_tool()).await.unwrap();
                        assert_eq!(call.credential_generation(),1);
                        assert!(matches!(call.next_event(&cx).await.unwrap(),Some(ManagedTaskEvent::Notification(_))));
                        let Some(ManagedTaskEvent::ToolResult(value))=call.next_event(&cx).await.unwrap() else { panic!("task creation result required") };
                        assert!(matches!(*value,FinalCoreResult::ToolsCallTask { .. }));
                        assert!(call.next_event(&cx).await.unwrap().is_none());
                        let ManagedTaskEvent::Snapshot(snapshot)=result(&tasks,&cx,3,ManagedTaskRequest::Get(task_id())).await else { panic!("snapshot required") };
                        assert!(matches!(&snapshot.task,Task::InputRequired { .. }));
                        let responses=serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap();
                        assert!(matches!(result(&tasks,&cx,5,ManagedTaskRequest::Update { task:Box::new(snapshot.task),input_responses:responses }).await,ManagedTaskEvent::Updated(_)));
                        assert!(matches!(result(&tasks,&cx,7,ManagedTaskRequest::Get(task_id())).await,ManagedTaskEvent::Snapshot(_)));
                        assert!(matches!(result(&tasks,&cx,9,ManagedTaskRequest::Cancel(task_id())).await,ManagedTaskEvent::Cancelled(_)));
                        let ManagedTaskEvent::Snapshot(snapshot)=result(&tasks,&cx,11,ManagedTaskRequest::Get(task_id())).await else { panic!("terminal snapshot required") };
                        assert!(matches!(snapshot.task,Task::Cancelled(_)));
                    };
                    Box::pin(pair(server,application)).await;
                    assert_eq!(peer.grants.load(Ordering::SeqCst),1);
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst),12);
                }
                TaskCase::MissingTasks | TaskCase::MissingAuth => {
                    acquire(&peer,&cx,&client,"access-one",300).await;
                    let mut missing=discovery();
                    let key=if matches!(case,TaskCase::MissingTasks) { TASKS_EXTENSION } else { CLIENT_CREDENTIALS_EXTENSION };
                    missing["capabilities"]["extensions"].as_object_mut().unwrap().remove(key);
                    let ((), rejected)=Box::pin(pair(discover(&peer,1,"access-one",&missing),
                        tasks.request(&cx,RequestId::Number(1),RequestId::Number(2),ManagedTaskRequest::Cancel(task_id())))).await;
                    match case {
                        TaskCase::MissingTasks => assert!(matches!(rejected,Err(TaskError::Protocol(ManagedTasksError::Negotiation)))),
                        _ => assert!(matches!(rejected,Err(TaskError::Authentication(Error::Negotiation)))),
                    }
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst),1,"no mutation on partial negotiation");
                    peer.quiet();
                    let good=task("working","complete");
                    let (_, snapshot)=Box::pin(pair(operation(&peer,3,"tasks/get","access-one",&good),
                        result(&tasks,&cx,3,ManagedTaskRequest::Get(task_id())))).await;
                    assert!(matches!(snapshot,ManagedTaskEvent::Snapshot(_)));
                    assert_eq!(client.credential(&cx).await.unwrap().generation(),1);
                    assert_eq!(peer.grants.load(Ordering::SeqCst),1);
                }
                TaskCase::WrongResponse | TaskCase::WrongTask => {
                    acquire(&peer,&cx,&client,"access-one",300).await;
                    let server=async {
                        discover(&peer,1,"access-one",&discovery()).await;
                        let (mut tls,_)=rpc(&peer,2,"tasks/get","access-one").await;
                        let mut wrong:Value=serde_json::from_str(&task("working","complete")).unwrap();
                        let response_id=if matches!(case,TaskCase::WrongResponse) { 99 } else { wrong["taskId"]=json!("foreign-task"); 2 };
                        json_reply(&mut tls,&terminal(response_id,&wrong.to_string())).await;
                    };
                    let application=async {
                        let mut call=tasks.request(&cx,RequestId::Number(1),RequestId::Number(2),ManagedTaskRequest::Get(task_id())).await.unwrap();
                        let error=call.next_event(&cx).await.err().unwrap();
                        match case {
                            TaskCase::WrongResponse=>assert!(matches!(error,TaskError::Protocol(ManagedTasksError::ResponseIdMismatch))),
                            _=>assert!(matches!(error,TaskError::Protocol(ManagedTasksError::TaskIdMismatch))),
                        }
                        assert!(matches!(call.next_event(&cx).await,Err(TaskError::Protocol(ManagedTasksError::Closed))));
                    };
                    Box::pin(pair(server,application)).await;
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst),2);
                    let good=task("working","complete");
                    let (_, snapshot)=Box::pin(pair(operation(&peer,3,"tasks/get","access-one",&good),result(&tasks,&cx,3,ManagedTaskRequest::Get(task_id())))).await;
                    assert!(matches!(snapshot,ManagedTaskEvent::Snapshot(_)));
                }
                TaskCase::InvalidProgress | TaskCase::Truncated | TaskCase::Cancel | TaskCase::Close
                | TaskCase::Abandon | TaskCase::Expiry | TaskCase::Deadline | TaskCase::RecordLimit => {
                    acquire(&peer,&cx,&client,"access-one",if matches!(case,TaskCase::Expiry) { 2 } else { 300 }).await;
                    let cancellation=McpRequestCancellation::new();
                    let server=async {
                        discover(&peer,1,"access-one",&discovery()).await;
                        let (mut tls,_)=rpc(&peer,2,"tools/call","access-one").await;
                        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
                        event(&mut tls,PROGRESS,matches!(case,TaskCase::Truncated)).await;
                        if matches!(case,TaskCase::Truncated) { return; }
                        if matches!(case,TaskCase::InvalidProgress) {
                            event(&mut tls,r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"foreign","progress":2}}"#,true).await;
                        } else { closed(tls).await; }
                    };
                    let application=async {
                        let mut call=tasks.request_with_cancellation(&cx,&cancellation,RequestId::Number(1),RequestId::Number(2),call_tool()).await.unwrap();
                        assert!(matches!(call.next_event(&cx).await.unwrap(),Some(ManagedTaskEvent::Notification(_))));
                        let mut reading=Box::pin(call.next_event(&cx));
                        if matches!(case,TaskCase::Cancel | TaskCase::Close | TaskCase::Abandon) {
                            poll_fn(|task| { assert!(reading.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                        }
                        if matches!(case,TaskCase::Abandon) { drop(reading); }
                        else {
                            match case { TaskCase::Cancel=>{cancellation.cancel();},TaskCase::Close=>client.close(),_=>{} }
                            let error=reading.await.err().expect("stream must reject the tested condition");
                            match case {
                                TaskCase::InvalidProgress=>assert!(matches!(error,TaskError::Protocol(ManagedTasksError::InvalidProgress))),
                                TaskCase::Truncated=>assert!(matches!(error,TaskError::Protocol(ManagedTasksError::MissingTerminal))),
                                TaskCase::RecordLimit=>assert!(matches!(error,TaskError::Protocol(ManagedTasksError::RecordLimit))),
                                TaskCase::Close=>assert!(matches!(error,TaskError::Authentication(Error::Closed))),
                                TaskCase::Cancel=>assert!(matches!(error,TaskError::Authentication(Error::Discovery(OAuthDiscoveryError::Cancelled)))),
                                TaskCase::Deadline=>assert!(matches!(error,TaskError::Authentication(Error::Discovery(OAuthDiscoveryError::TimedOut)))),
                                _=>assert!(matches!(error,TaskError::Authentication(_))),
                            }
                        }
                        assert!(matches!(call.next_event(&cx).await,Err(TaskError::Protocol(ManagedTasksError::Closed))));
                    };
                    Box::pin(pair(server,application)).await;
                    assert_eq!(peer.grants.load(Ordering::SeqCst),1,"a live response never renews its credential");
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst),2,"interruption never sends tasks/cancel or replays the tool");
                }
                TaskCase::Denied | TaskCase::Redirect | TaskCase::LostMutation => {
                    acquire(&peer,&cx,&client,"access-one",300).await;
                    let server=async {
                        discover(&peer,1,"access-one",&discovery()).await;
                        let (mut tls,_)=rpc(&peer,2,"tasks/cancel","access-one").await;
                        if matches!(case,TaskCase::LostMutation) { return; }
                        let response=if matches!(case,TaskCase::Denied) {
                            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        } else {
                            "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://elsewhere.invalid/mcp\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        };
                        tls.write_all(response.as_bytes()).await.unwrap(); tls.flush().await.unwrap();
                    };
                    let ((), outcome)=Box::pin(pair(server,tasks.request(&cx,RequestId::Number(1),RequestId::Number(2),ManagedTaskRequest::Cancel(task_id())))).await;
                    assert!(outcome.is_err());
                    assert_eq!(peer.grants.load(Ordering::SeqCst),1);
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst),2,"uncertain mutation is never automatically replayed");
                }
                TaskCase::Preflight => {
                    let cancellation=McpRequestCancellation::new(); cancellation.cancel();
                    assert!(matches!(tasks.request_with_cancellation(&cx,&cancellation,RequestId::Number(1),RequestId::Number(2),call_tool()).await,
                        Err(TaskError::Authentication(Error::Discovery(OAuthDiscoveryError::Cancelled)))));
                    let alias:RequestId=serde_json::from_str("1e0").unwrap();
                    assert!(matches!(tasks.request(&cx,RequestId::Number(1),alias,call_tool()).await,Err(TaskError::Protocol(ManagedTasksError::InvalidRequest))));
                    let mut input:Value=serde_json::from_str(&task("input_required","complete")).unwrap();
                    input.as_object_mut().unwrap().remove("resultType");
                    let input:Task=serde_json::from_value(input).unwrap();
                    let invalid=ManagedTaskRequest::Update {task:Box::new(input),input_responses:serde_json::from_value(json!({"roots":{"action":"accept"}})).unwrap()};
                    assert!(matches!(tasks.request(&cx,RequestId::Number(1),RequestId::Number(2),invalid).await,Err(TaskError::Protocol(ManagedTasksError::InvalidInputResponses))));
                    assert_eq!(peer.grants.load(Ordering::SeqCst),0);
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst),0);
                    peer.quiet();
                    let server=async { peer.grant("access-one",300).await; operation(&peer,3,"tasks/get","access-one",&task("working","complete")).await; };
                    let ((),snapshot)=Box::pin(pair(server,result(&tasks,&cx,3,ManagedTaskRequest::Get(task_id())))).await;
                    assert!(matches!(snapshot,ManagedTaskEvent::Snapshot(_)));
                }
                TaskCase::Renewal => {
                    acquire(&peer,&cx,&client,"access-one",1).await;
                    let working=task("working","complete");
                    Box::pin(pair(operation(&peer,1,"tasks/get","access-one",&working),result(&tasks,&cx,1,ManagedTaskRequest::Get(task_id())))).await;
                    Sleep::new(cx.now().saturating_add_nanos(1_100_000_000)).await;
                    let server=async { peer.grant("access-two",300).await; operation(&peer,3,"tasks/get","access-two",&working).await; };
                    let application=async {
                        let mut call=tasks.request(&cx,RequestId::Number(3),RequestId::Number(4),ManagedTaskRequest::Get(task_id())).await.unwrap();
                        assert_eq!(call.credential_generation(),2);
                        assert!(matches!(call.next_event(&cx).await.unwrap(),Some(ManagedTaskEvent::Snapshot(_))));
                    };
                    Box::pin(pair(server,application)).await;
                    assert_eq!(peer.grants.load(Ordering::SeqCst),2);
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst),4,"renewed credentials require fresh composed discovery");
                }
            }
            assert!(cx.checkpoint().is_ok());
            peer.quiet();
            client.close();
        });
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000),scenario).await.expect("machine Tasks fixture must settle");
    }));
}

#[test]
fn explicit_resource_ca_survives_machine_task_create_input_update_and_cancel() {
    assert_fixture_requires_explicit_tls_trust();
    run_tasks(TaskCase::Lifecycle);
}

#[test]
fn machine_tasks_complete_the_create_input_update_cancel_lifecycle() { isolated_task("tasks::machine_tasks_complete_the_create_input_update_cancel_lifecycle",TaskCase::Lifecycle); }
#[test]
fn missing_tasks_advertisement_prevents_mutation_and_preserves_the_client() { isolated_task("tasks::missing_tasks_advertisement_prevents_mutation_and_preserves_the_client",TaskCase::MissingTasks); }
#[test]
fn missing_machine_auth_advertisement_prevents_mutation_and_preserves_the_client() { isolated_task("tasks::missing_machine_auth_advertisement_prevents_mutation_and_preserves_the_client",TaskCase::MissingAuth); }
#[test]
fn wrong_response_identity_closes_only_its_task_call() { isolated_task("tasks::wrong_response_identity_closes_only_its_task_call",TaskCase::WrongResponse); }
#[test]
fn wrong_task_identity_closes_only_its_task_call() { isolated_task("tasks::wrong_task_identity_closes_only_its_task_call",TaskCase::WrongTask); }
#[test]
fn foreign_progress_is_not_delivered_as_owned_activity() { isolated_task("tasks::foreign_progress_is_not_delivered_as_owned_activity",TaskCase::InvalidProgress); }
#[test]
fn truncated_task_stream_is_not_successful_completion() { isolated_task("tasks::truncated_task_stream_is_not_successful_completion",TaskCase::Truncated); }
#[test]
fn cancelling_a_task_call_does_not_cancel_the_remote_task() { isolated_task("tasks::cancelling_a_task_call_does_not_cancel_the_remote_task",TaskCase::Cancel); }
#[test]
fn machine_owner_close_wakes_an_idle_task_read() { isolated_task("tasks::machine_owner_close_wakes_an_idle_task_read",TaskCase::Close); }
#[test]
fn abandoned_task_reads_release_the_socket_and_cannot_be_reused() { isolated_task("tasks::abandoned_task_reads_release_the_socket_and_cannot_be_reused",TaskCase::Abandon); }
#[test]
fn task_streams_cannot_outlive_the_opening_machine_token() { isolated_task("tasks::task_streams_cannot_outlive_the_opening_machine_token",TaskCase::Expiry); }
#[test]
fn task_call_deadlines_include_idle_stream_reads() { isolated_task("tasks::task_call_deadlines_include_idle_stream_reads",TaskCase::Deadline); }
#[test]
fn task_record_limit_closes_the_stream_without_an_extra_request() { isolated_task("tasks::task_record_limit_closes_the_stream_without_an_extra_request",TaskCase::RecordLimit); }
#[test]
fn denied_task_mutations_are_not_replayed() { isolated_task("tasks::denied_task_mutations_are_not_replayed",TaskCase::Denied); }
#[test]
fn task_mutation_redirects_are_not_followed() { isolated_task("tasks::task_mutation_redirects_are_not_followed",TaskCase::Redirect); }
#[test]
fn lost_task_mutation_replies_do_not_cause_replay() { isolated_task("tasks::lost_task_mutation_replies_do_not_cause_replay",TaskCase::LostMutation); }
#[test]
fn cancelled_and_invalid_task_requests_fail_before_credential_acquisition() { isolated_task("tasks::cancelled_and_invalid_task_requests_fail_before_credential_acquisition",TaskCase::Preflight); }
#[test]
fn token_renewal_renegotiates_tasks_under_the_replacement_credential() { isolated_task("tasks::token_renewal_renegotiates_tasks_under_the_replacement_credential",TaskCase::Renewal); }
