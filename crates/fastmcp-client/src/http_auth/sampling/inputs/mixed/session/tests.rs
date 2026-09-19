use super::*;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::time::Duration;
use std::task::Poll;
use std::future::{Future, poll_fn};

use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::sampling::SamplingToolLoopLimits;
use serde_json::{Value, json};
use crate::http_auth::rpc::interaction::input_required;
use crate::http_auth::sampling::{SamplingRunLimits, inputs::SamplingInputLimits};

fn original() -> CoreRequest {
    let mut metadata = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    metadata[fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY] = json!({
        "roots":{},"sampling":{"tools":{}},"elicitation":{"form":{},"url":{}}
    });
    CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&json!({
        "_meta":metadata,"name":"host-session","arguments":{"private":"never-format-this"}
    }))).unwrap()
}
fn challenge(inputs: Value) -> InputRequiredResult {
    input_required(&original().decode_result(&json!({
        "resultType":"input_required","requestState":"server-owned","inputRequests":inputs
    }).to_string()).unwrap()).unwrap().clone()
}
fn roots() -> InputRequiredResult { challenge(json!({"root":{"method":"roots/list"}})) }
fn sampling() -> InputRequiredResult { challenge(json!({"sample":{"method":"sampling/createMessage","params":{
    "messages":[],"maxTokens":16,"tools":[{"name":"fixture","inputSchema":{"type":"object"}}]
}}})) }
fn limits(models: usize, tools: usize, inputs: usize, reply_bytes: usize) -> CoreInputLimits {
    let run = SamplingRunLimits::new(SamplingToolLoopLimits::default(), Duration::from_secs(5), 4096).unwrap();
    CoreInputLimits::new(SamplingInputLimits::new(run, inputs, models, tools, 8192, reply_bytes).unwrap(), 8, 8).unwrap()
}
fn run(f: impl std::ops::AsyncFnOnce(Cx)) {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build().unwrap().block_on(async { f(Cx::current().unwrap()).await });
}
#[derive(Default)]
struct Host {
    calls: Vec<&'static str>,
    models: usize,
    looping: bool,
    root_count: usize,
    deny: bool,
    pending: bool,
    cancel: bool,
    drops: Arc<AtomicUsize>,
}
struct DropProbe(Arc<AtomicUsize>);
impl Drop for DropProbe { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
impl SamplingHost for Host {
    fn sample<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedCreateMessageParams) -> SamplingHostFuture<'a, FinalCreateMessageResult>
    {
        self.calls.push("model");
        let use_tool = self.looping && self.models % 2 == 0;
        self.models += 1;
        let content = if use_tool { json!({"type":"tool_use","id":"owned-use","name":"fixture","input":{}}) }
            else { json!({"type":"text","text":"done"}) };
        let result = serde_json::from_value(json!({"role":"assistant","model":"fixture","content":content,
            "stopReason":if use_tool {"toolUse"} else {"endTurn"}})).unwrap();
        Box::pin(std::future::ready(Ok(result)))
    }
    fn approve_tools<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a [SamplingContentBlock]) -> SamplingHostFuture<'a, ()>
    { self.calls.push("approve-tools"); Box::pin(std::future::ready(Ok(()))) }
    fn execute_tool<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a SamplingContentBlock) -> SamplingHostFuture<'a, SamplingContentBlock>
    {
        self.calls.push("tool");
        Box::pin(std::future::ready(Ok(serde_json::from_value(json!({"type":"tool_result","toolUseId":"owned-use",
            "content":[{"type":"text","text":"result"}]})).unwrap())))
    }
}
impl CoreInputHost for Host {
    fn approve_inputs<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a [CoreInputRequest]) -> CoreInputHostFuture<'a, ()>
    {
        self.calls.push("approve-inputs");
        Box::pin(std::future::ready(if self.deny { Err(CoreInputHostError::Denied) } else { Ok(()) }))
    }
    fn roots<'a>(&'a mut self, _: &'a Cx, cancellation: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedRootsListParams) -> CoreInputHostFuture<'a, FinalEmbeddedRootsListResult>
    {
        self.calls.push("roots");
        if self.cancel { cancellation.cancel(); }
        let count = self.root_count;
        let pending = self.pending;
        let drops = self.drops.clone();
        Box::pin(async move {
            let _probe = DropProbe(drops);
            if pending { std::future::pending::<()>().await; }
            Ok(serde_json::from_value(json!({"roots":(0..count).map(|_| json!({"uri":"file:///fixture"})).collect::<Vec<_>>()})).unwrap())
        })
    }
    fn form<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedFormElicitationParams) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>
    {
        self.calls.push("form");
        Box::pin(std::future::ready(Ok(serde_json::from_value(json!({"action":"accept","content":{"value":2}})).unwrap())))
    }
    fn url<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedUrlElicitationParams) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>
    { panic!("unselected URL must not execute") }
}

#[test]
fn session_model_budget_is_not_reset_for_a_successor_challenge() {
    run(async |cx| {
        let mut session = CoreInputSession::new(&cx, &McpRequestCancellation::new(), original(), limits(1, 0, 8, 4096), 8).unwrap();
        let mut host = Host::default();
        session.resolve(&cx, sampling(), RequestId::Number(1), &mut host).await.unwrap();
        let before = host.calls.clone();
        assert_eq!(session.resolve(&cx, sampling(), RequestId::Number(2), &mut host).await.err(),
            Some(CoreInputSessionError::Input(CoreInputError::Sampling(SamplingInputError::ModelRoundLimit))));
        assert_eq!(host.calls, before, "no second approval/model call fits the remaining global budget");
        assert_eq!(session.usage().model_rounds, 1);
        assert!(session.is_closed());
    });
}

#[test]
fn session_tool_budget_stops_the_next_batch_before_tool_approval_or_effect() {
    run(async |cx| {
        let mut session = CoreInputSession::new(&cx, &McpRequestCancellation::new(), original(), limits(4, 1, 8, 4096), 8).unwrap();
        let mut host = Host { looping: true, ..Host::default() };
        session.resolve(&cx, sampling(), RequestId::Number(1), &mut host).await.unwrap();
        assert_eq!(session.usage().model_rounds, 2);
        assert_eq!(session.usage().tool_calls, 1);
        assert_eq!(session.resolve(&cx, sampling(), RequestId::Number(2), &mut host).await.err(),
            Some(CoreInputSessionError::Input(CoreInputError::Sampling(SamplingInputError::ToolCallLimit))));
        assert_eq!(host.calls.iter().filter(|call| **call == "tool").count(), 1);
        assert_eq!(host.calls.iter().filter(|call| **call == "approve-tools").count(), 1);
        assert_eq!(session.usage().model_rounds, 3);
    });
}

#[test]
fn session_selection_preserves_omitted_budget_for_later_rounds() {
    run(async |cx| {
        let mut session = CoreInputSession::new(&cx, &McpRequestCancellation::new(), original(), limits(1, 0, 2, 4096), 2).unwrap();
        let mut host = Host::default();
        let mixed = challenge(json!({"root":{"method":"roots/list"},"sample":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}}}));
        let reply = session.resolve_selected(&cx, mixed, RequestId::Number(1), &["root"], &mut host).await.unwrap();
        assert_eq!(reply.input_responses.unwrap().len(), 1);
        assert_eq!(session.usage().selected_inputs, 1);
        assert_eq!(session.usage().model_rounds, 0);
        session.resolve(&cx, sampling(), RequestId::Number(2), &mut host).await.unwrap();
        assert_eq!(session.usage().selected_inputs, 2);
        assert_eq!(session.usage().model_rounds, 1);
        assert_eq!(host.calls, ["approve-inputs", "roots", "approve-inputs", "model"]);
    });
}

#[test]
fn session_selected_input_count_is_charged_before_a_later_host_batch() {
    run(async |cx| {
        let mut session = CoreInputSession::new(&cx, &McpRequestCancellation::new(), original(), limits(0, 0, 1, 4096), 2).unwrap();
        let mut host = Host::default();
        session.resolve(&cx, roots(), RequestId::Number(1), &mut host).await.unwrap();
        assert_eq!(session.resolve(&cx, roots(), RequestId::Number(2), &mut host).await.err(),
            Some(CoreInputSessionError::Input(CoreInputError::InputLimit)));
        assert_eq!(host.calls, ["approve-inputs", "roots"]);
        assert_eq!(session.usage().selected_inputs, 1);
    });
}

#[test]
fn session_cumulative_reply_bound_accounts_for_present_empty_maps() {
    run(async |cx| {
        let mut session = CoreInputSession::new(&cx, &McpRequestCancellation::new(), original(), limits(0, 0, 0, 3), 4).unwrap();
        let mut host = Host::default();
        session.resolve(&cx, challenge(json!({})), RequestId::Number(1), &mut host).await.unwrap();
        assert_eq!(session.usage().reply_bytes, 2);
        assert_eq!(session.resolve(&cx, challenge(json!({})), RequestId::Number(2), &mut host).await.err(),
            Some(CoreInputSessionError::Input(CoreInputError::ReplyByteLimit)));
        assert!(host.calls.is_empty());
    });
}

#[test]
fn session_cumulative_descriptor_bytes_include_omitted_siblings() {
    run(async |cx| {
        let mut policy = limits(1, 0, 8, 4096);
        let batch = challenge(json!({"root":{"method":"roots/list"},"sample":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}}}));
        let size = input_size(&batch, 8192).unwrap();
        policy.sampling.input_bytes = size;
        let mut session = CoreInputSession::new(&cx, &McpRequestCancellation::new(), original(), policy, 4).unwrap();
        let mut host = Host::default();
        session.resolve_selected(&cx, batch, RequestId::Number(1), &["root"], &mut host).await.unwrap();
        assert_eq!(session.usage().input_bytes, size);
        assert_eq!(session.usage().model_rounds, 0);
        assert_eq!(session.resolve(&cx, sampling(), RequestId::Number(2), &mut host).await.err(),
            Some(CoreInputSessionError::Input(CoreInputError::InputByteLimit)));
        assert_eq!(host.calls, ["approve-inputs", "roots"]);
    });
}

#[test]
fn session_roots_and_form_fields_cannot_reset_across_rounds() {
    run(async |cx| {
        for form in [false, true] {
            let mut policy = limits(0, 0, 8, 4096);
            policy.roots = 1; policy.form_fields = 1;
            let batch = if form { challenge(json!({"form":{"method":"elicitation/create","params":{
                "mode":"form","message":"Value","requestedSchema":{"type":"object","properties":{"value":{"type":"integer"}},"required":["value"]}
            }}})) } else { roots() };
            let mut session = CoreInputSession::new(&cx, &McpRequestCancellation::new(), original(), policy, 4).unwrap();
            let mut host = Host { root_count: 1, ..Host::default() };
            session.resolve(&cx, batch.clone(), RequestId::Number(1), &mut host).await.unwrap();
            assert_eq!(session.resolve(&cx, batch, RequestId::Number(2), &mut host).await.err(),
                Some(CoreInputSessionError::Input(if form {CoreInputError::FormFieldLimit} else {CoreInputError::RootLimit})));
            assert!(session.is_closed());
        }
    });
}

#[test]
fn session_failed_host_cannot_be_reentered_and_diagnostics_are_redacted() {
    run(async |cx| {
        let mut session = CoreInputSession::new(&cx, &McpRequestCancellation::new(), original(), limits(1, 0, 8, 4096), 8).unwrap();
        let mut host = Host { deny: true, ..Host::default() };
        assert!(session.resolve(&cx, roots(), RequestId::Number(1), &mut host).await.is_err());
        host.deny = false;
        assert_eq!(session.resolve(&cx, roots(), RequestId::Number(2), &mut host).await.err(), Some(CoreInputSessionError::Closed));
        assert_eq!(host.calls, ["approve-inputs"]);
        assert_eq!(session.usage().selected_inputs, 1);
        assert!(!format!("{session:?}").contains("never-format-this"));
    });
}

#[test]
fn session_abandoned_resolution_drops_pending_host_and_retires_the_owner() {
    run(async |cx| {
        let mut session = CoreInputSession::new(&cx, &McpRequestCancellation::new(), original(), limits(0, 0, 8, 4096), 8).unwrap();
        let mut host = Host { pending: true, ..Host::default() };
        let drops = host.drops.clone();
        let mut future = Box::pin(session.resolve(&cx, roots(), RequestId::Number(1), &mut host));
        // The resolver yields cooperatively before invoking the roots host.
        for _ in 0..3 {
            poll_fn(|cx| { assert!(future.as_mut().poll(cx).is_pending()); Poll::Ready(()) }).await;
        }
        drop(future);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(session.resolve(&cx, roots(), RequestId::Number(2), &mut host).await.err(), Some(CoreInputSessionError::Closed));
        assert_eq!(host.calls, ["approve-inputs", "roots"]);
    });
}

#[test]
fn session_cancellation_discards_a_ready_host_answer() {
    run(async |cx| {
        let cancellation = McpRequestCancellation::new();
        let mut session = CoreInputSession::new(&cx, &cancellation, original(), limits(0, 0, 8, 4096), 8).unwrap();
        let mut host = Host { cancel: true, ..Host::default() };
        assert_eq!(session.resolve(&cx, roots(), RequestId::Number(1), &mut host).await.err(),
            Some(CoreInputSessionError::Input(CoreInputError::Sampling(SamplingInputError::Run(SamplingRunError::Cancelled)))));
        assert_eq!(session.usage().reply_bytes, 0);
        assert!(session.is_closed());
    });
}

#[test]
fn session_deadline_includes_caller_pauses_and_does_not_restart_on_resolve() {
    run(async |cx| {
        let mut policy = limits(0, 0, 8, 4096);
        policy.sampling.run.timeout = Duration::from_millis(10);
        let mut session = CoreInputSession::new(&cx, &McpRequestCancellation::new(), original(), policy, 8).unwrap();
        let mut host = Host::default();
        asupersync::time::sleep(cx.now(), Duration::from_millis(20)).await;
        assert_eq!(session.resolve(&cx, roots(), RequestId::Number(1), &mut host).await.err(),
            Some(CoreInputSessionError::Input(CoreInputError::Sampling(SamplingInputError::Run(SamplingRunError::TimedOut)))));
        assert!(host.calls.is_empty());
    });
}

#[test]
fn session_request_ids_and_resolution_limits_bound_state_only_rounds() {
    run(async |cx| {
        let batch = input_required(&original().decode_result(r#"{"resultType":"input_required","requestState":"opaque"}"#).unwrap()).unwrap().clone();
        let mut host = Host::default();
        let mut session = CoreInputSession::new(&cx, &McpRequestCancellation::new(), original(), limits(0, 0, 0, 4096), 1).unwrap();
        let reply = session.resolve(&cx, batch.clone(), RequestId::Number(1), &mut host).await.unwrap();
        assert!(reply.input_responses.is_none());
        assert_eq!(session.resolve(&cx, batch.clone(), RequestId::Number(2), &mut host).await.err(), Some(CoreInputSessionError::ResolutionLimit));
        let mut session = CoreInputSession::new(&cx, &McpRequestCancellation::new(), original(), limits(0, 0, 0, 4096), 8).unwrap();
        session.resolve(&cx, batch.clone(), RequestId::Number(1), &mut host).await.unwrap();
        assert_eq!(session.resolve(&cx, batch, serde_json::from_str("1e0").unwrap(), &mut host).await.err(), Some(CoreInputSessionError::RepeatedRequestId));
        assert!(host.calls.is_empty());
    });
}
