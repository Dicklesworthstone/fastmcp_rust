//! Actual OAuth/MCP TLS execution of the cumulative typed-host APIs.
//! Reuses the enclosing fixture's inline CA, issuer discovery and token grant.
//! The server and model are deterministic peers, not third-party qualification
//! or the native server continuation registry.
use super::*;
use std::sync::Arc;
use fastmcp_client::http_auth::sampling::{SamplingHost, SamplingHostFuture};
use fastmcp_client::http_auth::sampling::inputs::mixed::{
    CoreInputHost, CoreInputHostFuture, CoreInputRequest, CoreInputLimits, CoreInputError,
};
use fastmcp_client::http_auth::sampling::inputs::mixed::session::{CoreInputSessionError};
use fastmcp_client::http_auth::sampling::inputs::mixed::session::execution::{
    CoreInputExecutionError, CoreInputExecutionLimits, CoreInputSelection,
};
use fastmcp_client::http_auth::sampling::{SamplingRunLimits, inputs::{SamplingInputLimits, SamplingInputError}};
use fastmcp_protocol::{
    FinalCreateMessageResult, FinalEmbeddedCreateMessageParams, FinalEmbeddedElicitationResult,
    FinalEmbeddedFormElicitationParams, FinalEmbeddedRootsListParams,
    FinalEmbeddedRootsListResult, FinalEmbeddedUrlElicitationParams,
};
use fastmcp_protocol::common_types::SamplingContentBlock;
use fastmcp_protocol::sampling::SamplingToolLoopLimits;

const FIRST_INPUTS: &str = r#"{"resultType":"input_required","requestState":"owned-first","inputRequests":{
    "root":{"method":"roots/list"},
    "sample":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16,
        "tools":[{"name":"fixture","inputSchema":{"type":"object"}}]}}
}}"#;
const NEXT_INPUTS: &str = r#"{"resultType":"input_required","requestState":"owned-next","inputRequests":{
    "sample":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16,
        "tools":[{"name":"fixture","inputSchema":{"type":"object"}}]}}
}}"#;

#[derive(Clone, Copy)]
enum ExecutionCase { Complete(&'static str), Machine, MachinePartial, ModelLimit, Partial, LostReply, OwnerClose, MachineClose, NotifyRefusal }
struct Probe(Arc<AtomicUsize>);
impl Drop for Probe { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
#[derive(Default)]
struct Host {
    models: usize, tools: usize, roots: usize, approvals: usize,
    close: Option<Box<dyn FnOnce() + Send>>, drops: Arc<AtomicUsize>,
}
impl SamplingHost for Host {
    fn sample<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedCreateMessageParams) -> SamplingHostFuture<'a, FinalCreateMessageResult>
    {
        let first = self.models % 2 == 0;
        self.models += 1;
        assert_eq!(request.messages.len(), if first {0} else {2});
        let content = if first { json!({"type":"tool_use","id":"fixture-use","name":"fixture","input":{}}) }
            else { json!({"type":"text","text":"done"}) };
        Box::pin(std::future::ready(Ok(serde_json::from_value(json!({"role":"assistant","model":"fixture-model",
            "content":content,"stopReason":if first {"toolUse"} else {"endTurn"}})).unwrap())))
    }
    fn approve_tools<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        calls: &'a [SamplingContentBlock]) -> SamplingHostFuture<'a, ()>
    { assert_eq!(calls.len(), 1); Box::pin(std::future::ready(Ok(()))) }
    fn execute_tool<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a SamplingContentBlock) -> SamplingHostFuture<'a, SamplingContentBlock>
    {
        self.tools += 1;
        Box::pin(std::future::ready(Ok(serde_json::from_value(json!({"type":"tool_result","toolUseId":"fixture-use",
            "content":[{"type":"text","text":"effect"}]})).unwrap())))
    }
}
impl CoreInputHost for Host {
    fn approve_inputs<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        requests: &'a [CoreInputRequest]) -> CoreInputHostFuture<'a, ()>
    { assert!(!requests.is_empty()); self.approvals += 1; Box::pin(std::future::ready(Ok(()))) }
    fn roots<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedRootsListParams) -> CoreInputHostFuture<'a, FinalEmbeddedRootsListResult>
    {
        self.roots += 1;
        if let Some(close) = self.close.take() {
            close();
            let probe = Probe(self.drops.clone());
            return Box::pin(async move { let _probe = probe; std::future::pending().await });
        }
        Box::pin(std::future::ready(Ok(serde_json::from_value(json!({"roots":[]})).unwrap())))
    }
    fn form<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedFormElicitationParams) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>
    { panic!("fixture requests no form") }
    fn url<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedUrlElicitationParams) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>
    { panic!("fixture requests no URL") }
}
fn request(method: &str) -> CoreRequest {
    let mut params = core(method, true).encode_params().unwrap().unwrap();
    params["_meta"]["io.modelcontextprotocol/clientCapabilities"]["sampling"] = json!({"tools":{}});
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}
async fn response(peer: &Peer, index: usize, result: &str) -> Value {
    let (mut socket, body) = peer.request(false).await;
    let request: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(request["id"], format!("owned:{index}"));
    let id = serde_json::to_string(&request["id"]).unwrap();
    json_reply(&mut socket, &format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#)).await;
    request
}
async fn exchange(peer: &Peer, machine: bool, index: usize, result: &str) -> Value {
    if machine {
        let discovery = response(peer, index * 2, DISCOVERY).await;
        assert_eq!(discovery["method"], "server/discover");
        assert_eq!(discovery["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"], json!({CLIENT_CREDENTIALS_EXTENSION:{}}));
        response(peer, index * 2 + 1, result).await
    } else { response(peer, index, result).await }
}
fn assert_continuation(wire: &Value, original: &Value, state: &str, has_root: bool, has_sample: bool) {
    assert_eq!(wire["params"]["requestState"], state);
    let replies = wire["params"]["inputResponses"].as_object().unwrap();
    assert_eq!(replies.contains_key("root"), has_root);
    assert_eq!(replies.contains_key("sample"), has_sample);
    if has_sample { assert_eq!(replies["sample"]["model"], "fixture-model"); }
    let mut params = wire["params"].clone();
    params.as_object_mut().unwrap().remove("requestState");
    params.as_object_mut().unwrap().remove("inputResponses");
    assert_eq!(&params, original);
}
fn isolated_execution(name: &str, case: ExecutionCase) {
    if let Ok(selected) = std::env::var(CHILD) { assert_eq!(selected, name); run_execution(case); return; }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success()); return; }
        assert!(Instant::now() < end, "typed-host execution exceeded its child bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn run_execution(case: ExecutionCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let is_machine = matches!(case, ExecutionCase::Machine | ExecutionCase::MachinePartial | ExecutionCase::MachineClose);
            let is_partial = matches!(case, ExecutionCase::Partial | ExecutionCase::MachinePartial);
            let method = match case { ExecutionCase::Complete(method) => method, _ => "tools/call" };
            let managed = if is_machine { None } else {
                Some(Box::pin(pair(peer.login(), ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser))).await.1.unwrap())
            };
            let machine = if is_machine {
                Some(pair(metadata(&peer), plan(&peer).discover(&cx)).await.1.unwrap())
            } else { None };
            let request = request(method);
            let mut expected = request.encode_params().unwrap().unwrap();
            if is_machine {
                expected["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"] = json!({CLIENT_CREDENTIALS_EXTENSION:{}});
            }
            let mut host = Host::default();
            if matches!(case, ExecutionCase::OwnerClose) {
                let closer = managed.as_ref().unwrap().clone();
                host.close = Some(Box::new(move || closer.close()));
            }
            if matches!(case, ExecutionCase::MachineClose) {
                let closer = machine.as_ref().unwrap().clone();
                host.close = Some(Box::new(move || closer.close()));
            }
            let input_limits = CoreInputLimits::new(SamplingInputLimits::new(
                SamplingRunLimits::new(SamplingToolLoopLimits::default(), Duration::from_secs(10), 4096).unwrap(),
                8, if matches!(case, ExecutionCase::ModelLimit) || is_partial {2} else {4}, 2, 16384, 16384,
            ).unwrap(), 16, 16).unwrap();
            let limits = CoreInputExecutionLimits::new(ManagedInteractionLimits::new(
                ManagedCoreLimits::new(16384, 16384, 65536, 4, Duration::from_secs(10)).unwrap(), 2, 8).unwrap(), input_limits, 2).unwrap();
            let cancellation = McpRequestCancellation::new();
            let mut selections = 0;
            let mut notifications = 0;
            let selector = |_: &fastmcp_protocol::InputRequiredResult| {
                selections += 1;
                Ok(if is_partial && selections == 1 {
                    CoreInputSelection::Keys(vec!["root".to_owned()])
                } else { CoreInputSelection::All })
            };
            let notifier = |_: Box<fastmcp_protocol::ServerNotification>| {
                notifications += 1;
                Err(CoreInputExecutionError::AbortedByHost)
            };
            let server = async {
                if is_machine { grant(&peer).await; }
                assert_eq!(exchange(&peer, is_machine, 0, FIRST_INPUTS).await["params"], expected);
                if matches!(case, ExecutionCase::OwnerClose | ExecutionCase::MachineClose) { return; }
                if matches!(case, ExecutionCase::LostReply | ExecutionCase::NotifyRefusal) {
                    let (mut socket, body) = peer.request(false).await;
                    let wire: Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(wire["id"], "owned:1");
                    assert_continuation(&wire, &expected, "owned-first", true, true);
                    if matches!(case, ExecutionCase::NotifyRefusal) {
                        sse_head(&mut socket).await;
                        event(&mut socket, CHANGED, false).await;
                        let mut byte = [0];
                        assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0));
                    }
                    // LostReply closes after consuming the POST without a reply.
                    return;
                }
                let wire = exchange(&peer, is_machine, 1, NEXT_INPUTS).await;
                assert_continuation(&wire, &expected, "owned-first", true, !is_partial);
                if matches!(case, ExecutionCase::ModelLimit) { return; }
                let wire = exchange(&peer, is_machine, 2, complete(method)).await;
                assert_continuation(&wire, &expected, "owned-next", false, true);
            };
            let application = async {
                if let Some(client) = &machine {
                    if is_partial {
                        Box::pin(client.execute_core_with_selected_input_host(&cx, &cancellation, request,
                            "owned".to_owned(), limits, &mut host, selector, notifier)).await
                    } else {
                        Box::pin(client.execute_core_with_input_host(&cx, &cancellation, request,
                            "owned".to_owned(), limits, &mut host, notifier)).await
                    }
                } else if matches!(case, ExecutionCase::Complete("tools/call")) {
                    Box::pin(managed.as_ref().unwrap().execute_core_with_input_host(&cx, &cancellation,
                        request, "owned".to_owned(), limits, &mut host, notifier)).await
                } else {
                    Box::pin(managed.as_ref().unwrap().execute_core_with_selected_input_host(&cx, &cancellation,
                        request, "owned".to_owned(), limits, &mut host, selector, notifier)).await
                }
            };
            let ((), result) = Box::pin(pair(server, application)).await;
            let expected_posts = match case {
                ExecutionCase::ModelLimit => {
                    assert!(matches!(result, Err(CoreInputExecutionError::Input(CoreInputSessionError::Input(
                        CoreInputError::Sampling(SamplingInputError::ModelRoundLimit))))));
                    assert_eq!((host.models, host.tools, host.approvals), (2, 1, 1));
                    2
                }
                ExecutionCase::OwnerClose | ExecutionCase::MachineClose => {
                    assert!(matches!(result, Err(CoreInputExecutionError::OwnerClosed)));
                    assert_eq!((host.roots, host.models, host.tools), (1, 0, 0));
                    assert_eq!(host.drops.load(Ordering::SeqCst), 1);
                    if is_machine {2} else {1}
                }
                ExecutionCase::LostReply | ExecutionCase::NotifyRefusal => {
                    assert!(result.is_err());
                    if matches!(case, ExecutionCase::NotifyRefusal) {
                        assert!(matches!(result, Err(CoreInputExecutionError::AbortedByHost)));
                        assert_eq!(notifications, 1);
                    }
                    assert_eq!((host.models, host.tools), (2, 1));
                    2
                }
                _ => {
                    let result = result.unwrap();
                    assert!(result.result.encode().unwrap().contains("1.20e+4"));
                    assert_eq!(result.continuations, 2);
                    let (models, tools, selected) = if is_partial {(2,1,2)} else {(4,2,3)};
                    assert_eq!((host.models, host.tools, host.roots), (models, tools, 1));
                    assert_eq!((result.usage.model_rounds, result.usage.tool_calls, result.usage.selected_inputs), (models, tools, selected));
                    assert_eq!(result.usage.resolutions, 2);
                    assert_eq!(result.credential_generation, 1);
                    if is_machine {6} else {3}
                }
            };
            assert_eq!(peer.posts.load(Ordering::SeqCst), expected_posts);
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
            peer.quiet();
            if let Some(client) = &managed { client.close(); }
            if let Some(client) = &machine { client.close(); }
        };
        Box::pin(asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario)).await.unwrap();
    });
}

#[test]
fn managed_host_execution_completes_tool_with_cumulative_usage() { isolated_execution("driver::machine_partial::host_execution::managed_host_execution_completes_tool_with_cumulative_usage", ExecutionCase::Complete("tools/call")); }
#[test]
fn managed_host_execution_completes_resource_with_cumulative_usage() { isolated_execution("driver::machine_partial::host_execution::managed_host_execution_completes_resource_with_cumulative_usage", ExecutionCase::Complete("resources/read")); }
#[test]
fn managed_host_execution_completes_prompt_with_cumulative_usage() { isolated_execution("driver::machine_partial::host_execution::managed_host_execution_completes_prompt_with_cumulative_usage", ExecutionCase::Complete("prompts/get")); }
#[test]
fn machine_host_execution_keeps_fresh_discovery_and_one_grant() { isolated_execution("driver::machine_partial::host_execution::machine_host_execution_keeps_fresh_discovery_and_one_grant", ExecutionCase::Machine); }
#[test]
fn machine_selected_host_execution_preserves_the_deferred_sampling_budget() { isolated_execution("driver::machine_partial::host_execution::machine_selected_host_execution_preserves_the_deferred_sampling_budget", ExecutionCase::MachinePartial); }
#[test]
fn host_execution_stops_at_the_whole_operation_model_budget() { isolated_execution("driver::machine_partial::host_execution::host_execution_stops_at_the_whole_operation_model_budget", ExecutionCase::ModelLimit); }
#[test]
fn selected_host_execution_defers_sampling_without_spending_its_budget() { isolated_execution("driver::machine_partial::host_execution::selected_host_execution_defers_sampling_without_spending_its_budget", ExecutionCase::Partial); }
#[test]
fn lost_continuation_reply_never_replays_host_effects() { isolated_execution("driver::machine_partial::host_execution::lost_continuation_reply_never_replays_host_effects", ExecutionCase::LostReply); }
#[test]
fn managed_owner_close_drops_an_idle_typed_host() { isolated_execution("driver::machine_partial::host_execution::managed_owner_close_drops_an_idle_typed_host", ExecutionCase::OwnerClose); }
#[test]
fn machine_owner_close_drops_an_idle_typed_host() { isolated_execution("driver::machine_partial::host_execution::machine_owner_close_drops_an_idle_typed_host", ExecutionCase::MachineClose); }
#[test]
fn notification_refusal_stops_execution_without_more_host_calls() { isolated_execution("driver::machine_partial::host_execution::notification_refusal_stops_execution_without_more_host_calls", ExecutionCase::NotifyRefusal); }
