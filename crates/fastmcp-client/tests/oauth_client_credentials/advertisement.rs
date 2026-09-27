//! Optional machine-auth advertisements through the public TLS client.
//!
//! The parent supplies real issuer/resource discovery, Basic/Post grants and
//! explicitly scoped CA trust. No credentials or response owners are injected.
//! Peers script protocol replies: this is not native-server or issuer qualification.

use super::*;

const TOKEN: &str = "optional-advertisement-access";

fn run_machine<F, Fut>(post: bool, scenario: F)
where
    F: FnOnce(Cx, Peer, ClientCredentialsClient) -> Fut,
    Fut: Future<Output = ()>,
{
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
        .build().unwrap().block_on(async move {
            let cx = Cx::current().unwrap();
            let deadline = cx.now().saturating_add_nanos(30_000_000_000);
            asupersync::time::timeout_at(deadline, Box::pin(async {
                let peer = Peer::new().await;
                let mut plan = peer.plan(Duration::from_secs(10));
                let client = if post {
                    plan = plan.with_secret_authentication(ClientSecretAuthenticationMethod::Post).unwrap();
                    let ((), client) = pair(post_metadata(&peer, PostCase::Lifecycle), plan.discover(&cx)).await;
                    let client = client.unwrap();
                    let ((), token) = pair(post_grant(&peer, "service-client", "service-secret", TOKEN, 300),
                        client.credential(&cx)).await;
                    assert_eq!(token.unwrap().generation(), 1);
                    client
                } else {
                    let ((), client) = pair(peer.metadata(Case::Complete), plan.discover(&cx)).await;
                    let client = client.unwrap();
                    acquire(&peer, &cx, &client, TOKEN, 300).await;
                    client
                };
                scenario(cx, peer, client).await;
            })).await.expect("optional-advertisement TLS case must settle");
        });
}

fn discovery_document(capabilities: Value) -> String {
    json!({"resultType":"complete","supportedVersions":["2026-07-28"],
        "capabilities":capabilities,"ttlMs":0,"cacheScope":"private"}).to_string()
}

async fn operation(peer: &Peer, id: i64, capabilities: Value, method: &str, result: &str) {
    peer.discovery(id, TOKEN, &discovery_document(capabilities)).await;
    json_reply(&mut peer.rpc(id + 1, method, TOKEN).await, &terminal(id + 1, result)).await;
}

#[test]
fn absent_and_exact_machine_advertisements_both_allow_authenticated_core_calls() {
    for post in [false, true] {
        run_machine(post, |cx, peer, client| async move {
            for (index, capabilities) in [json!({}), json!({"extensions":{}}),
                json!({"extensions":{CLIENT_CREDENTIALS_EXTENSION:{}}}),
                json!({"extensions":{"com.example/independent":{}}})].into_iter().enumerate()
            {
                let id = 1 + 2 * index as i64;
                let request = core("tools/call");
                let before = request.encode_params().unwrap();
                let ((), response) = pair(operation(&peer, id, capabilities, "tools/call", CALL),
                    client.execute_core(&cx, request.clone(), RequestId::Number(id), RequestId::Number(id + 1))).await;
                let response = response.unwrap();
                assert_eq!(response.credential_generation(), 1);
                let result = response.read_json_result(&cx, 4096).await.unwrap();
                assert!(matches!(&result, CoreResult::Final(FinalCoreResult::ToolsCall { .. })));
                assert!(result.encode().unwrap().contains("1.20e+4"));
                assert_eq!(request.encode_params().unwrap(), before);
                peer.quiet();
            }
            assert_eq!(peer.gets.load(Ordering::SeqCst), 2);
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 8);
            assert!(cx.checkpoint().is_ok());
            client.close();
        });
    }
}

#[test]
fn earlier_machine_admission_cannot_hide_a_later_malformed_advertisement() {
    for post in [false, true] {
        run_machine(post, |cx, peer, client| async move {
            let ((), admitted) = pair(operation(&peer, 1, json!({}), "tools/call", CALL),
                client.execute_core(&cx, core("tools/call"), RequestId::Number(1), RequestId::Number(2))).await;
            assert!(admitted.unwrap().read_json_result(&cx, 4096).await.is_ok());
            let bad = [json!({"extensions":null}), json!({"extensions":[]}),
                json!({"extensions":{CLIENT_CREDENTIALS_EXTENSION:null}}),
                json!({"extensions":{CLIENT_CREDENTIALS_EXTENSION:{"enabled":true}}})];
            for (index, capabilities) in bad.into_iter().enumerate() {
                let id = 3 + 2 * index as i64;
                let document = discovery_document(capabilities);
                let ((), refused) = pair(peer.discovery(id, TOKEN, &document), client.execute_core(
                    &cx, core("tools/call"), RequestId::Number(id), RequestId::Number(id + 1),
                )).await;
                assert!(matches!(refused, Err(Error::Negotiation)));
                assert_eq!(peer.rpcs.load(Ordering::SeqCst), 3 + index,
                    "malformed current discovery must not dispatch the operation");
                peer.quiet();
            }
            let ((), admitted) = pair(operation(&peer, 11, json!({"extensions":{}}), "tools/call", CALL),
                client.execute_core(&cx, core("tools/call"), RequestId::Number(11), RequestId::Number(12))).await;
            assert!(admitted.unwrap().read_json_result(&cx, 4096).await.is_ok());
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 8);
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            assert_eq!(client.credential(&cx).await.unwrap().generation(), 1);
            peer.quiet();
            client.close();
        });
    }
}

use fastmcp_client::http_auth::discovery::client_credentials::rpc::{
    ClientCredentialsCoreError, ManagedCoreEvent, ManagedCoreLimits,
};
use fastmcp_client::http_auth::discovery::client_credentials::rpc::interaction::{
    ClientCredentialsInteractionError, ManagedInteractionEvent, ManagedInteractionLimits,
};
use fastmcp_client::http_auth::discovery::client_credentials::subscriptions::{
    ClientCredentialsCoreSubscriptionError, ClientCredentialsCoreSubscriptionLimits,
};
use fastmcp_client::http_executor::ModernHttpSubscriptionListenEvent as ListenEvent;
use fastmcp_protocol::{SubscriptionFilter, FINAL_SUBSCRIPTION_ID_META_KEY};

fn interactive_request(method: &str) -> CoreRequest {
    let mut params = match method {
        "tools/call" => json!({"name":"mutate","arguments":{"delta":1}}),
        "resources/read" => json!({"uri":"file:///watched"}),
        "prompts/get" => json!({"name":"explain","arguments":{"question":"unchanged"}}),
        _ => panic!("fixture method is not interactive"),
    };
    params["_meta"] = core("tools/call").encode_params().unwrap().unwrap()["_meta"].clone();
    params["_meta"]["io.modelcontextprotocol/clientCapabilities"]["roots"] = json!({});
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}

fn complete(method: &str) -> &'static str {
    match method {
        "tools/call" => CALL,
        "resources/read" => r#"{"resultType":"complete","contents":[{"uri":"file:///watched","text":"hello"}],"ttlMs":0,"cacheScope":"private","x-exact":1.20e+4}"#,
        "prompts/get" => r#"{"resultType":"complete","messages":[],"x-exact":1.20e+4}"#,
        _ => panic!("fixture method is not interactive"),
    }
}

fn client_metadata() -> FinalRequestMeta {
    serde_json::from_value(interactive_request("tools/call").encode_params().unwrap().unwrap()["_meta"].clone()).unwrap()
}

// Keep request assertions on the actual wire, including both the discovery
// and operation declaration. Return the admitted fixture document so callers
// can assert original arguments and exactly the current continuation answers.
async fn rpc_document(peer: &Peer, id: i64, method: &str, extensions: Value)
    -> (TlsStream<TcpStream>, Value)
{
    let (socket, start, headers, bytes) = peer.request().await;
    assert_eq!(start, "POST /mcp HTTP/1.1");
    assert_eq!(headers["authorization"], format!("Bearer {TOKEN}"));
    assert_eq!(headers["mcp-method"], method);
    assert_eq!(headers["mcp-protocol-version"], "2026-07-28");
    assert!(!headers.contains_key("mcp-session-id") && !headers.contains_key("last-event-id"));
    let request: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(request["id"], id);
    assert_eq!(request["method"], method);
    assert_eq!(request["params"]["_meta"]["com.example/tenant"], "unchanged");
    assert_eq!(request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"], extensions);
    peer.rpcs.fetch_add(1, Ordering::SeqCst);
    (socket, request)
}

async fn stream_head(socket: &mut TlsStream<TcpStream>) {
    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
    socket.flush().await.unwrap();
}
fn acknowledged(id: i64, filter: &SubscriptionFilter) -> String {
    json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged",
        "params":{"_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):id},"notifications":filter}}).to_string()
}
fn listen_terminal(id: i64) -> String {
    terminal(id, &json!({"resultType":"complete","_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):id}}).to_string())
}

#[test]
fn typed_machine_tool_resource_and_prompt_streams_work_without_auth_advertisements() {
    for post in [false, true] {
        run_machine(post, |cx, peer, client| async move {
            for (index, method) in ["tools/call", "resources/read", "prompts/get"].into_iter().enumerate() {
                let id = 1 + 2 * index as i64;
                let server = async {
                    peer.discovery(id, TOKEN, &discovery_document(json!({}))).await;
                    let mut socket = peer.rpc(id + 1, method, TOKEN).await;
                    stream_head(&mut socket).await;
                    event(&mut socket, NOTICE, false).await;
                    event(&mut socket, &terminal(id + 1, complete(method)), true).await;
                };
                let application = async {
                    let mut call = client.request_core(&cx, interactive_request(method),
                        RequestId::Number(id), RequestId::Number(id + 1), ManagedCoreLimits::default()).await.unwrap();
                    assert_eq!(call.credential_generation(), 1);
                    assert!(matches!(call.next_event(&cx).await.unwrap(), Some(ManagedCoreEvent::Notification(_))));
                    let Some(ManagedCoreEvent::Result(result)) = call.next_event(&cx).await.unwrap() else {
                        panic!("typed terminal required after streamed activity");
                    };
                    assert_eq!(result.era(), ProtocolEra::Modern2026);
                    assert!(result.encode().unwrap().contains("1.20e+4"));
                    assert!(call.next_event(&cx).await.unwrap().is_none());
                };
                pair(server, application).await;
                peer.quiet();
            }
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 6);
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            client.close();
        });
    }
}

#[test]
fn partial_machine_continuations_keep_exact_answers_without_server_auth_advertisements() {
    for post in [false, true] {
        run_machine(post, |cx, peer, client| async move {
            for (index, method) in ["tools/call", "resources/read", "prompts/get"].into_iter().enumerate() {
                let first = 1 + 6 * index as i64;
                let original = interactive_request(method);
                let mut expected = original.encode_params().unwrap().unwrap();
                expected["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"] = json!({CLIENT_CREDENTIALS_EXTENSION:{}});
                let server = async {
                    for round in 0..3 {
                        let id = first + 2 * round;
                        peer.discovery(id, TOKEN, &discovery_document(json!({}))).await;
                        let (mut socket, request) = rpc_document(&peer, id + 1, method,
                            json!({CLIENT_CREDENTIALS_EXTENSION:{}})).await;
                        let mut params = expected.clone();
                        if round > 0 {
                            params["requestState"] = json!(if round == 1 { "opaque-one" } else { "opaque-two" });
                            params["inputResponses"] = if round == 1 { json!({"a":{"roots":[]}}) } else { json!({"z":{"roots":[]}}) };
                        }
                        assert_eq!(request["params"], params);
                        let result = match round {
                            0 => json!({"resultType":"input_required","requestState":"opaque-one",
                                "inputRequests":{"a":{"method":"roots/list"},"z":{"method":"roots/list"}}}).to_string(),
                            1 => json!({"resultType":"input_required","requestState":"opaque-two",
                                "inputRequests":{"z":{"method":"roots/list"}}}).to_string(),
                            _ => complete(method).to_owned(),
                        };
                        json_reply(&mut socket, &terminal(id + 1, &result)).await;
                    }
                };
                let application = async {
                    let mut interaction = client.start_core_interaction(&cx, original,
                        RequestId::Number(first), RequestId::Number(first + 1), ManagedInteractionLimits::default()).await.unwrap();
                    assert!(matches!(interaction.next_event(&cx).await.unwrap(), Some(ManagedInteractionEvent::InputRequired(_))));
                    interaction.resume_partial(&cx, RequestId::Number(first + 2), RequestId::Number(first + 3),
                        serde_json::from_value(json!({"a":{"roots":[]}})).unwrap()).await.unwrap();
                    assert!(matches!(interaction.next_event(&cx).await.unwrap(), Some(ManagedInteractionEvent::InputRequired(_))));
                    interaction.resume(&cx, RequestId::Number(first + 4), RequestId::Number(first + 5),
                        Some(serde_json::from_value(json!({"z":{"roots":[]}})).unwrap())).await.unwrap();
                    let Some(ManagedInteractionEvent::Complete(result)) = interaction.next_event(&cx).await.unwrap() else {
                        panic!("both selected inputs must lead to completion");
                    };
                    assert!(result.encode().unwrap().contains("1.20e+4"));
                    assert_eq!(interaction.continuation_count(), 2);
                    assert_eq!(interaction.credential_generation(), 1);
                    assert!(interaction.pending_input().is_none());
                    assert!(interaction.next_event(&cx).await.unwrap().is_none());
                };
                pair(server, application).await;
                peer.quiet();
            }
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 18);
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            client.close();
        });
    }
}

#[test]
fn malformed_current_discovery_retires_the_continuation_without_replaying_answers() {
    for post in [false, true] {
        run_machine(post, |cx, peer, client| async move {
            let challenge = r#"{"resultType":"input_required","requestState":"opaque","inputRequests":{"roots":{"method":"roots/list"}}}"#;
            let ((), interaction) = pair(operation(&peer, 1, json!({}), "tools/call", challenge),
                client.start_core_interaction(&cx, interactive_request("tools/call"), RequestId::Number(1),
                    RequestId::Number(2), ManagedInteractionLimits::default())).await;
            let mut interaction = interaction.unwrap();
            assert!(matches!(interaction.next_event(&cx).await.unwrap(), Some(ManagedInteractionEvent::InputRequired(_))));
            let malformed = discovery_document(json!({"extensions":{CLIENT_CREDENTIALS_EXTENSION:null}}));
            let answers = || Some(serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap());
            let ((), refused) = pair(peer.discovery(3, TOKEN, &malformed),
                interaction.resume(&cx, RequestId::Number(3), RequestId::Number(4), answers())).await;
            assert!(matches!(refused, Err(ClientCredentialsInteractionError::Core(
                ClientCredentialsCoreError::Authentication(Error::Negotiation)))));
            assert!(interaction.pending_input().is_none());
            assert!(interaction.resume(&cx, RequestId::Number(5), RequestId::Number(6), answers()).await.is_err());
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 3, "no answer-bearing POST after failed discovery");
            peer.quiet();
            let ((), response) = pair(operation(&peer, 7, json!({}), "tools/call", CALL),
                client.execute_core(&cx, core("tools/call"), RequestId::Number(7), RequestId::Number(8))).await;
            assert!(response.unwrap().read_json_result(&cx, 4096).await.is_ok());
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 5);
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            client.close();
        });
    }
}

#[test]
fn core_machine_subscriptions_admit_absence_but_recheck_the_next_advertisement() {
    for post in [false, true] {
        run_machine(post, |cx, peer, client| async move {
            let filter: SubscriptionFilter = serde_json::from_value(json!({
                "toolsListChanged":true,"resourceSubscriptions":["file:///watched"]})).unwrap();
            let server = async {
                peer.discovery(1, TOKEN, &discovery_document(json!({}))).await;
                let (mut socket, request) = rpc_document(&peer, 2, "subscriptions/listen", json!({CLIENT_CREDENTIALS_EXTENSION:{}})).await;
                assert_eq!(request["params"]["notifications"], serde_json::to_value(&filter).unwrap());
                stream_head(&mut socket).await;
                event(&mut socket, &acknowledged(2, &filter), false).await;
                event(&mut socket, NOTICE, false).await;
                event(&mut socket, &json!({"jsonrpc":"2.0","method":"notifications/resources/updated",
                    "params":{"uri":"file:///watched"}}).to_string(), false).await;
                event(&mut socket, &listen_terminal(2), true).await;
            };
            let application = async {
                let mut listen = client.subscribe_core(&cx, client_metadata(), RequestId::Number(1), RequestId::Number(2),
                    filter.clone(), ClientCredentialsCoreSubscriptionLimits::default()).await.unwrap();
                assert!(matches!(listen.next_event(&cx).await.unwrap(), Some(ListenEvent::Acknowledged { .. })));
                assert_eq!(serde_json::to_value(listen.accepted_filter().unwrap()).unwrap(), serde_json::to_value(&filter).unwrap());
                for _ in 0..2 { assert!(matches!(listen.next_event(&cx).await.unwrap(), Some(ListenEvent::Notification(_)))); }
                assert!(matches!(listen.next_event(&cx).await.unwrap(), Some(ListenEvent::Terminal { .. })));
                assert!(listen.next_event(&cx).await.unwrap().is_none());
                assert_eq!(listen.credential_generation(), 1);
            };
            pair(server, application).await;
            let bad = discovery_document(json!({"extensions":null}));
            let ((), refused) = pair(peer.discovery(3, TOKEN, &bad), client.subscribe_core(&cx, client_metadata(),
                RequestId::Number(3), RequestId::Number(4), filter, ClientCredentialsCoreSubscriptionLimits::default())).await;
            assert!(matches!(refused, Err(ClientCredentialsCoreSubscriptionError::Authentication(Error::Negotiation))));
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 3);
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            peer.quiet();
            client.close();
        });
    }
}

#[cfg(feature = "tasks")]
mod task_composition {
    use super::*;
    use fastmcp_client::http_auth::discovery::client_credentials::tasks::{
        ClientCredentialsTasksClient, ClientCredentialsTasksError, ClientCredentialsTasksLimits,
        ManagedTaskEvent, ManagedTaskRequest, ManagedTasksError,
    };
    use fastmcp_client::http_auth::discovery::client_credentials::tasks::subscriptions::ClientCredentialsSubscriptionLimits;
    use fastmcp_protocol::tasks_extension::{Task, TaskId, TASKS_EXTENSION};

    fn declarations() -> Value { json!({CLIENT_CREDENTIALS_EXTENSION:{},TASKS_EXTENSION:{}}) }
    fn capabilities() -> Value { json!({"extensions":{TASKS_EXTENSION:{}}}) }
    fn task_id() -> TaskId { TaskId::parse("optional-task").unwrap() }
    fn task(status: &str, result_type: &str) -> Value {
        let mut result = json!({"resultType":result_type,"taskId":"optional-task","status":status,
            "createdAt":"2026-09-27T00:00:00Z","lastUpdatedAt":"2026-09-27T00:00:00Z","ttlMs":60000});
        if status == "input_required" { result["inputRequests"] = json!({"roots":{"method":"roots/list"}}); }
        result
    }
    async fn discovery(peer: &Peer, id: i64, caps: Value) {
        let (mut socket, _) = rpc_document(peer, id, "server/discover", declarations()).await;
        json_reply(&mut socket, &terminal(id, &discovery_document(caps))).await;
    }
    async fn task_operation(peer: &Peer, id: i64, method: &str, result: Value) -> Value {
        discovery(peer, id, capabilities()).await;
        let (mut socket, request) = rpc_document(peer, id + 1, method, declarations()).await;
        json_reply(&mut socket, &terminal(id + 1, &result.to_string())).await;
        request
    }
    async fn result(tasks: &ClientCredentialsTasksClient, cx: &Cx, id: i64, request: ManagedTaskRequest) -> ManagedTaskEvent {
        let mut call = tasks.request(cx, RequestId::Number(id), RequestId::Number(id + 1), request).await.unwrap();
        assert_eq!(call.credential_generation(), 1);
        let event = call.next_event(cx).await.unwrap().unwrap();
        assert!(call.next_event(cx).await.unwrap().is_none());
        event
    }

    #[test]
    fn tasks_without_auth_advertisement_keep_creation_input_update_and_cancel() {
        for post in [false, true] {
            run_machine(post, |cx, peer, client| async move {
                let tasks = ClientCredentialsTasksClient::new(client.clone(), client_metadata(), ClientCredentialsTasksLimits::default()).unwrap();
                let server = async {
                    let request = task_operation(&peer, 1, "tools/call", task("working", "task")).await;
                    assert_eq!(request["params"]["name"], "compute");
                    assert_eq!(request["params"]["arguments"], json!({"n":7}));
                    let request = task_operation(&peer, 3, "tasks/get", task("input_required", "complete")).await;
                    assert_eq!(request["params"]["taskId"], "optional-task");
                    let request = task_operation(&peer, 5, "tasks/update", json!({"resultType":"complete"})).await;
                    assert_eq!(request["params"]["inputResponses"], json!({"roots":{"roots":[]}}));
                    let request = task_operation(&peer, 7, "tasks/cancel", json!({"resultType":"complete"})).await;
                    assert_eq!(request["params"]["taskId"], "optional-task");
                };
                let application = async {
                    let event = result(&tasks, &cx, 1, ManagedTaskRequest::CallTool {
                        name:"compute".to_owned(),arguments:Some(json!({"n":7})) }).await;
                    assert!(matches!(event, ManagedTaskEvent::ToolResult(value) if matches!(*value, FinalCoreResult::ToolsCallTask { .. })));
                    let ManagedTaskEvent::Snapshot(snapshot) = result(&tasks, &cx, 3, ManagedTaskRequest::Get(task_id())).await else {
                        panic!("native Task snapshot required");
                    };
                    assert!(matches!(&snapshot.task, Task::InputRequired { .. }));
                    assert!(matches!(result(&tasks, &cx, 5, ManagedTaskRequest::Update {
                        task:Box::new(snapshot.task), input_responses:serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap()
                    }).await, ManagedTaskEvent::Updated(_)));
                    assert!(matches!(result(&tasks, &cx, 7, ManagedTaskRequest::Cancel(task_id())).await, ManagedTaskEvent::Cancelled(_)));
                };
                pair(server, application).await;
                // The auth profile's optional advertisement must not relax the
                // separate, mandatory Tasks negotiation on the very next call.
                let ((), refused) = pair(discovery(&peer, 9, json!({})), tasks.request(&cx,
                    RequestId::Number(9), RequestId::Number(10), ManagedTaskRequest::Cancel(task_id()))).await;
                assert!(matches!(refused, Err(ClientCredentialsTasksError::Protocol(ManagedTasksError::Negotiation))));
                assert_eq!(peer.rpcs.load(Ordering::SeqCst), 9);
                assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
                peer.quiet();
                client.close();
            });
        }
    }

    #[test]
    fn task_listens_without_auth_advertisement_keep_ack_and_event_ownership() {
        for post in [false, true] {
            run_machine(post, |cx, peer, client| async move {
                let tasks = ClientCredentialsTasksClient::new(client.clone(), client_metadata(), ClientCredentialsTasksLimits::default()).unwrap();
                let filter: SubscriptionFilter = serde_json::from_value(json!({"taskIds":["optional-task"],
                    "toolsListChanged":true,"resourceSubscriptions":["file:///watched"]})).unwrap();
                let server = async {
                    discovery(&peer, 1, capabilities()).await;
                    let (mut socket, request) = rpc_document(&peer, 2, "subscriptions/listen", declarations()).await;
                    assert_eq!(request["params"]["notifications"], serde_json::to_value(&filter).unwrap());
                    stream_head(&mut socket).await;
                    event(&mut socket, &acknowledged(2, &filter), false).await;
                    event(&mut socket, NOTICE, false).await;
                    let mut notification = task("cancelled", "complete");
                    notification.as_object_mut().unwrap().remove("resultType");
                    notification["_meta"] = json!({(FINAL_SUBSCRIPTION_ID_META_KEY):2});
                    event(&mut socket, &json!({"jsonrpc":"2.0","method":"notifications/tasks","params":notification}).to_string(), false).await;
                    event(&mut socket, &listen_terminal(2), true).await;
                };
                let application = async {
                    let mut listen = tasks.subscribe(&cx, RequestId::Number(1), RequestId::Number(2), filter.clone(),
                        ClientCredentialsSubscriptionLimits::default()).await.unwrap();
                    assert!(matches!(listen.next_event(&cx).await.unwrap(), Some(ListenEvent::Acknowledged { .. })));
                    assert_eq!(serde_json::to_value(listen.accepted_filter().unwrap()).unwrap(), serde_json::to_value(&filter).unwrap());
                    assert!(matches!(listen.next_event(&cx).await.unwrap(), Some(ListenEvent::Notification(_))));
                    let Some(ListenEvent::TaskNotification(notification)) = listen.next_event(&cx).await.unwrap() else {
                        panic!("selected Task notification required");
                    };
                    assert_eq!(notification.params.task.base().task_id, task_id());
                    assert!(matches!(notification.params.task, Task::Cancelled(_)));
                    assert!(matches!(listen.next_event(&cx).await.unwrap(), Some(ListenEvent::Terminal { .. })));
                    assert!(listen.next_event(&cx).await.unwrap().is_none());
                    assert_eq!(listen.credential_generation(), 1);
                };
                pair(server, application).await;
                let ((), refused) = pair(discovery(&peer, 3, json!({})), tasks.subscribe(&cx,
                    RequestId::Number(3), RequestId::Number(4), filter, ClientCredentialsSubscriptionLimits::default())).await;
                assert!(matches!(refused, Err(ClientCredentialsTasksError::Protocol(ManagedTasksError::Negotiation))));
                assert_eq!(peer.rpcs.load(Ordering::SeqCst), 3);
                assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
                peer.quiet();
                client.close();
            });
        }
    }
}
