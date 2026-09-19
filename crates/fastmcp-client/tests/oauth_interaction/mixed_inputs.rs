//! Public mixed-input resolution followed by real OAuth-authenticated TLS
//! continuation POSTs. The existing fixture supplies issuer and MCP sockets;
//! the model, roots and UI host below are deterministic callbacks, not live
//! third-party services. The peer models server replies, not its MRTR registry.
//! This module inherits the inline CA; no external PEM/key file is included.
use super::*;
use fastmcp_client::http_auth::sampling::{
    SamplingHost, SamplingHostError, SamplingHostFuture,
};
use fastmcp_client::http_auth::sampling::inputs::mixed::{
    CoreInputError, CoreInputHost, CoreInputHostError, CoreInputHostFuture,
    CoreInputLimits, CoreInputRequest, CoreInputStage,
    resolve_core_inputs, resolve_selected_core_inputs,
};
use fastmcp_protocol::common_types::SamplingContentBlock;
use fastmcp_protocol::{
    FinalCreateMessageResult, FinalEmbeddedCreateMessageParams,
    FinalEmbeddedElicitationResult, FinalEmbeddedFormElicitationParams,
    FinalEmbeddedRootsListParams, FinalEmbeddedRootsListResult,
    FinalEmbeddedUrlElicitationParams, FINAL_CLIENT_CAPABILITIES_META_KEY,
};

const MIXED: &str = r#"{"resultType":"input_required","requestState":"first+/%","inputRequests":{
    "z/roots":{"method":"roots/list"},
    "a/form":{"method":"elicitation/create","params":{"mode":"form","message":"Quantity?","requestedSchema":{"type":"object","properties":{"quantity":{"type":"integer","minimum":1}},"required":["quantity"],"additionalProperties":false}}},
    "q/url":{"method":"elicitation/create","params":{"mode":"url","message":"Approve navigation","url":"https://example.test/confirm?opaque=%2F"}},
    "b/sample":{"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"weather"}}],"maxTokens":64,"tools":[{"name":"weather","inputSchema":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}]}}
}}"#;
const REMAINING: &str = r#"{"resultType":"input_required","requestState":"successor+/%","inputRequests":{
    "z/roots":{"method":"roots/list"},
    "q/url":{"method":"elicitation/create","params":{"mode":"url","message":"Approve navigation","url":"https://example.test/confirm?opaque=%2F"}},
    "b/sample":{"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"weather"}}],"maxTokens":64,"tools":[{"name":"weather","inputSchema":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}]}}
}}"#;

#[derive(Clone, Copy)]
enum MixedCase {
    Managed(&'static str), Partial, Machine, MachinePartial,
    Denied, InvalidForm, ToolDenied, LostReply,
}

#[derive(Default)]
struct Host {
    calls: Vec<&'static str>,
    approvals: Vec<Vec<String>>,
    models: usize,
    tools: usize,
    deny: bool,
    invalid_form: bool,
    deny_tools: bool,
}
impl SamplingHost for Host {
    fn sample<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedCreateMessageParams) -> SamplingHostFuture<'a, FinalCreateMessageResult>
    {
        self.calls.push("sample");
        self.models += 1;
        let content = if self.models == 1 {
            assert_eq!(request.messages.len(),1);
            json!([{"type":"tool_use","id":"approved-call","name":"weather","input":{"city":"Paris"}}])
        } else {
            assert_eq!(self.models,2,"no model callback replay");
            let wire = serde_json::to_value(request).unwrap();
            assert_eq!(wire["messages"][2]["content"][0]["toolUseId"],"approved-call");
            assert_eq!(wire["messages"][2]["content"][0]["content"][0]["text"],"sunny");
            json!([{"type":"text","text":"approved answer"}])
        };
        let value = serde_json::from_value(json!({"role":"assistant","model":"fixture-model","content":content})).unwrap();
        Box::pin(std::future::ready(Ok(value)))
    }
    fn approve_tools<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        calls: &'a [SamplingContentBlock]) -> SamplingHostFuture<'a, ()>
    {
        self.calls.push("tools");
        assert_eq!(calls.len(),1);
        Box::pin(std::future::ready(if self.deny_tools {Err(SamplingHostError::Denied)} else {Ok(())}))
    }
    fn execute_tool<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        call: &'a SamplingContentBlock) -> SamplingHostFuture<'a, SamplingContentBlock>
    {
        self.calls.push("execute");
        self.tools += 1;
        let SamplingContentBlock::ToolUse { id, name, .. } = call else { panic!("admitted tool call required"); };
        assert_eq!(name,"weather");
        assert_eq!(self.tools,1,"no tool effect replay");
        Box::pin(std::future::ready(Ok(serde_json::from_value(json!({
            "type":"tool_result","toolUseId":id,"content":[{"type":"text","text":"sunny"}],"structuredContent":null
        })).unwrap())))
    }
}
impl CoreInputHost for Host {
    fn approve_inputs<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        requests: &'a [CoreInputRequest]) -> CoreInputHostFuture<'a, ()>
    {
        self.calls.push("approve");
        self.approvals.push(requests.iter().map(|request|request.key().to_owned()).collect());
        Box::pin(std::future::ready(if self.deny {Err(CoreInputHostError::Denied)} else {Ok(())}))
    }
    fn roots<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedRootsListParams) -> CoreInputHostFuture<'a, FinalEmbeddedRootsListResult>
    {
        self.calls.push("roots");
        Box::pin(std::future::ready(Ok(serde_json::from_value(json!({"roots":[{"uri":"file:///approved/%2F","name":"Approved root"}]})).unwrap())))
    }
    fn form<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedFormElicitationParams) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>
    {
        self.calls.push("form");
        assert_eq!(request.message,"Quantity?");
        Box::pin(std::future::ready(Ok(serde_json::from_value(json!({"action":"accept",
            "content":{"quantity": if self.invalid_form {0} else {7}}
        })).unwrap())))
    }
    fn url<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedUrlElicitationParams) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>
    {
        self.calls.push("url");
        assert_eq!(request.url.as_str(),"https://example.test/confirm?opaque=%2F");
        Box::pin(std::future::ready(Ok(serde_json::from_value(json!({"action":"accept"})).unwrap())))
    }
}

fn mixed_request(method: &str) -> CoreRequest {
    let mut params = core(method,true).encode_params().unwrap().unwrap();
    params["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY] = json!({
        "roots":{},"sampling":{"tools":{}},"elicitation":{"form":{},"url":{}}
    });
    CoreRequest::decode(ProtocolEra::Modern2026,method,Some(&params)).unwrap()
}
fn assert_reply(wire: &Value, original: &Value, state: &str, expected: &FinalInputResponses) {
    let mut params = wire["params"].clone();
    assert_eq!(params["requestState"],state);
    assert_eq!(params["inputResponses"],serde_json::to_value(expected).unwrap());
    params.as_object_mut().unwrap().remove("requestState");
    params.as_object_mut().unwrap().remove("inputResponses");
    assert_eq!(&params,original,"resolver cannot rewrite original arguments or metadata");
}
fn assert_effects(host: &Host, partial: bool) {
    assert_eq!(host.models,2);
    assert_eq!(host.tools,1);
    if partial {
        assert_eq!(host.calls,["approve","form","approve","roots","url","sample","tools","execute","sample"]);
        assert_eq!(host.approvals,vec![vec!["a/form"],vec!["z/roots","q/url","b/sample"]]);
    } else {
        assert_eq!(host.calls,["approve","roots","form","url","sample","tools","execute","sample"]);
        assert_eq!(host.approvals,vec![vec!["z/roots","a/form","q/url","b/sample"]]);
    }
}

fn isolated_mixed(name: &str, case: MixedCase) {
    let name = format!("{}::{name}",module_path!().split_once("::").unwrap().1);
    if let Ok(selected) = std::env::var(CHILD) {
        assert_eq!(selected,name);
        run_mixed(case);
        return;
    }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact",&name,"--nocapture","--test-threads=1"])
        .env(CHILD,&name).env("SSL_CERT_FILE",&roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success()); return; }
        assert!(Instant::now()<end,"mixed-input TLS child exceeded its lifetime");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run_mixed(case: MixedCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let limits = ManagedInteractionLimits::new(
                ManagedCoreLimits::new(8192,8192,32768,8,Duration::from_secs(15)).unwrap(),4,16).unwrap();
            let method = match case {MixedCase::Managed(method)=>method,_=>"tools/call"};
            let request = mixed_request(method);
            let mut expected = request.encode_params().unwrap().unwrap();
            let mut host = Host {deny:matches!(case,MixedCase::Denied),invalid_form:matches!(case,MixedCase::InvalidForm),
                deny_tools:matches!(case,MixedCase::ToolDenied),..Host::default()};
            if matches!(case,MixedCase::Machine|MixedCase::MachinePartial) {
                let plan = plan(&peer);
                let ((),client) = pair(metadata(&peer),plan.discover(&cx)).await;
                let client = client.unwrap();
                expected["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"] = json!({CLIENT_CREDENTIALS_EXTENSION:{}});
                let server = async {grant(&peer).await;round(&peer,60,MIXED).await};
                let (wire,operation) = pair(server,client.start_core_interaction_with_cancellation(
                    &cx,&cancellation,request.clone(),RequestId::Number(60),RequestId::Number(61),limits)).await;
                assert_eq!(wire["params"],expected);
                let mut operation = operation.unwrap();
                challenge(&mut operation,&cx).await;
                let partial = matches!(case,MixedCase::MachinePartial);
                let reply = if partial {
                    resolve_selected_core_inputs(&cx,&cancellation,&request,operation.pending_input().unwrap().clone(),
                        RequestId::Number(63),CoreInputLimits::default(),&["a/form"],&mut host).await.unwrap()
                } else {
                    resolve_core_inputs(&cx,&cancellation,&request,operation.pending_input().unwrap().clone(),
                        RequestId::Number(63),CoreInputLimits::default(),&mut host).await.unwrap()
                };
                let responses = reply.input_responses.unwrap();
                let (wire,resumed) = pair(round(&peer,62,if partial {REMAINING} else {complete(method)}),
                    operation.resume_partial(&cx,RequestId::Number(62),reply.request_id,responses.clone())).await;
                resumed.unwrap();
                assert_reply(&wire,&expected,"first+/%",&responses);
                if partial {
                    assert_eq!(host.calls,["approve","form"]);
                    challenge(&mut operation,&cx).await;
                    let reply = resolve_core_inputs(&cx,&cancellation,&request,operation.pending_input().unwrap().clone(),
                        RequestId::Number(65),CoreInputLimits::default(),&mut host).await.unwrap();
                    let responses = reply.input_responses.unwrap();
                    assert!(responses.get("a/form").is_none());
                    let (wire,resumed) = pair(round(&peer,64,complete(method)),operation.resume(
                        &cx,RequestId::Number(64),reply.request_id,Some(responses.clone()))).await;
                    resumed.unwrap();
                    assert_reply(&wire,&expected,"successor+/%",&responses);
                }
                complete_machine(&mut operation,&cx).await;
                assert_effects(&host,partial);
                assert_eq!(peer.posts.load(Ordering::SeqCst),if partial {6} else {4});
                client.close();
            } else {
                let ((),session) = pair(peer.login(),ManagedOAuthSession::authorize(
                    &cx,peer.client(),OAuthSessionPolicy::default(),browser)).await;
                let session = session.unwrap();
                let (wire,operation) = pair(peer.response(41,MIXED),session.start_core_interaction_with_cancellation(
                    &cx,&cancellation,request.clone(),RequestId::Number(41),limits)).await;
                assert_eq!(wire["params"],expected);
                let mut operation = operation.unwrap();
                pending(&mut operation,&cx).await;
                let partial = matches!(case,MixedCase::Partial);
                let reply = if partial {
                    resolve_selected_core_inputs(&cx,&cancellation,&request,operation.pending_input().unwrap().clone(),
                        RequestId::Number(42),CoreInputLimits::default(),&["a/form"],&mut host).await
                } else {
                    resolve_core_inputs(&cx,&cancellation,&request,operation.pending_input().unwrap().clone(),
                        RequestId::Number(42),CoreInputLimits::default(),&mut host).await
                };
                if matches!(case,MixedCase::Denied|MixedCase::InvalidForm|MixedCase::ToolDenied) {
                    let error = reply.err().expect("invalid or refused host reply must not be returned");
                    match case {
                        MixedCase::Denied => {
                            assert_eq!(error,CoreInputError::Host {stage:CoreInputStage::Approval,reason:CoreInputHostError::Denied});
                            assert_eq!(host.calls,["approve"]);
                        }
                        MixedCase::InvalidForm => {
                            assert_eq!(error,CoreInputError::InvalidFormContent);
                            assert_eq!(host.calls,["approve","roots","form"]);
                        }
                        MixedCase::ToolDenied => {
                            assert!(matches!(error,CoreInputError::Sampling(_)));
                            assert_eq!(host.tools,0);
                            assert_eq!(host.models,1);
                        }
                        _=>unreachable!(),
                    }
                    assert_eq!(operation.continuation_count(),0);
                    assert_eq!(peer.posts.load(Ordering::SeqCst),1);
                    operation.close();
                } else {
                    let reply = reply.unwrap();
                    let responses = reply.input_responses.unwrap();
                    if matches!(case,MixedCase::LostReply) {
                        let server = async {
                            let (socket,body)=peer.request(false).await;
                            let wire:Value=serde_json::from_slice(&body).unwrap();
                            assert_reply(&wire,&expected,"first+/%",&responses);
                            drop(socket); // The server consumed the continuation, but its reply was lost.
                        };
                        let ((),resumed)=pair(server,operation.resume(&cx,reply.request_id,Some(responses.clone()))).await;
                        if resumed.is_ok() { assert!(operation.next_event(&cx).await.is_err()); }
                        assert!(operation.pending_input().is_none());
                        assert!(matches!(operation.resume(&cx,RequestId::Number(43),Some(responses)).await,Err(ManagedInteractionError::Closed)));
                        assert_effects(&host,false);
                        assert_eq!(peer.posts.load(Ordering::SeqCst),2);
                    } else {
                        let (wire,resumed)=pair(peer.response(42,if partial {REMAINING} else {complete(method)}),
                            operation.resume_partial(&cx,reply.request_id,responses.clone())).await;
                        resumed.unwrap();
                        assert_reply(&wire,&expected,"first+/%",&responses);
                        if partial {
                            assert_eq!(host.calls,["approve","form"]);
                            pending(&mut operation,&cx).await;
                            let reply=resolve_core_inputs(&cx,&cancellation,&request,operation.pending_input().unwrap().clone(),
                                RequestId::Number(43),CoreInputLimits::default(),&mut host).await.unwrap();
                            let responses=reply.input_responses.unwrap();
                            assert!(responses.get("a/form").is_none());
                            let (wire,resumed)=pair(peer.response(43,complete(method)),
                                operation.resume(&cx,reply.request_id,Some(responses.clone()))).await;
                            resumed.unwrap();
                            assert_reply(&wire,&expected,"successor+/%",&responses);
                        }
                        finished(&mut operation,&cx).await;
                        assert_effects(&host,partial);
                        assert_eq!(peer.posts.load(Ordering::SeqCst),if partial {3} else {2});
                    }
                }
                session.close();
            }
            assert_eq!(peer.tokens.load(Ordering::SeqCst),1);
            peer.quiet();
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000),Box::pin(scenario)).await.unwrap();
    });
}

#[test]
fn mixed_tool_reply_resolves_all_kinds_and_sampling_tools() {isolated_mixed("mixed_tool_reply_resolves_all_kinds_and_sampling_tools",MixedCase::Managed("tools/call"));}
#[test]
fn mixed_resource_reply_resolves_all_kinds_and_sampling_tools() {isolated_mixed("mixed_resource_reply_resolves_all_kinds_and_sampling_tools",MixedCase::Managed("resources/read"));}
#[test]
fn mixed_prompt_reply_resolves_all_kinds_and_sampling_tools() {isolated_mixed("mixed_prompt_reply_resolves_all_kinds_and_sampling_tools",MixedCase::Managed("prompts/get"));}
#[test]
fn selected_form_then_remaining_inputs_use_exact_successor() {isolated_mixed("selected_form_then_remaining_inputs_use_exact_successor",MixedCase::Partial);}
#[test]
fn machine_mixed_inputs_follow_real_discovery_and_grant() {isolated_mixed("machine_mixed_inputs_follow_real_discovery_and_grant",MixedCase::Machine);}
#[test]
fn machine_selected_form_never_reexecutes_omitted_or_answered_inputs() {isolated_mixed("machine_selected_form_never_reexecutes_omitted_or_answered_inputs",MixedCase::MachinePartial);}
#[test]
fn batch_denial_prevents_all_input_effects_and_continuation_post() {isolated_mixed("batch_denial_prevents_all_input_effects_and_continuation_post",MixedCase::Denied);}
#[test]
fn invalid_form_prevents_later_host_effects_and_continuation_post() {isolated_mixed("invalid_form_prevents_later_host_effects_and_continuation_post",MixedCase::InvalidForm);}
#[test]
fn sampling_tool_denial_prevents_execution_and_continuation_post() {isolated_mixed("sampling_tool_denial_prevents_execution_and_continuation_post",MixedCase::ToolDenied);}
#[test]
fn lost_continuation_reply_does_not_replay_host_or_server_work() {isolated_mixed("lost_continuation_reply_does_not_replay_host_or_server_work",MixedCase::LostReply);}
