use super::*;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::time::Duration;

use fastmcp_protocol::{ClientCapabilities, FinalCreateMessageResult, FinalEmbeddedCreateMessageParams, FinalRequestMeta};
use fastmcp_protocol::common_types::SamplingContentBlock;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use serde_json::{Value, json};
use crate::http_auth::rpc::interaction::input_required;
use crate::http_auth::sampling::{SamplingHostError, SamplingHostFuture, SamplingRunLimits};

const MIXED: &str = r#"{"resultType":"input_required","requestState":"opaque+/%","inputRequests":{
    "z/root~\n":{"method":"roots/list"},
    "a/form":{"method":"elicitation/create","params":{"mode":"form","message":"Quantity?","requestedSchema":{"type":"object","properties":{"quantity":{"type":"integer","minimum":1}},"required":["quantity"],"additionalProperties":false}}},
    "q/url":{"method":"elicitation/create","params":{"mode":"url","message":"Confirm navigation","url":"https://example.test/action?opaque=%2F"}},
    "b/sample":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}}
}}"#;
const ROOTS: &str = r#"{"resultType":"input_required","inputRequests":{"root":{"method":"roots/list"}}}"#;

fn original(caps: Value) -> CoreRequest {
    let mut meta = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    meta[fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY] = caps;
    CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&json!({
        "_meta":meta,"name":"effect","arguments":{"unchanged":"yes"}
    }))).unwrap()
}
fn all() -> CoreRequest { original(json!({"roots":{},"sampling":{"tools":{},"context":{}},"elicitation":{"form":{},"url":{}}})) }
fn input(source: &str) -> InputRequiredResult {
    input_required(&all().decode_result(source).unwrap()).unwrap().clone()
}
fn run(f: impl std::ops::AsyncFnOnce(Cx)) {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build().unwrap().block_on(async { f(Cx::current().unwrap()).await });
}

struct PendingDrop(Arc<AtomicUsize>);
impl Drop for PendingDrop { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
struct Host {
    calls: Vec<&'static str>,
    approved: Vec<String>,
    roots: FinalEmbeddedRootsListResult,
    form: FinalEmbeddedElicitationResult,
    url: FinalEmbeddedElicitationResult,
    denied: Option<&'static str>,
    cancel: Option<&'static str>,
    hang: Option<&'static str>,
    drops: Arc<AtomicUsize>,
}
impl Default for Host {
    fn default() -> Self {
        Self { calls: vec![], approved: vec![],
            roots: serde_json::from_value(json!({"roots":[{"uri":"file:///workspace/%2F","name":"Approved"}]})).unwrap(),
            form: serde_json::from_str(r#"{"action":"accept","content":{"quantity":900719925474099312345}}"#).unwrap(),
            url: serde_json::from_value(json!({"action":"accept"})).unwrap(),
            denied: None, cancel: None, hang: None, drops: Arc::new(AtomicUsize::new(0)) }
    }
}
impl Host {
    fn respond<T: Send + 'static>(&mut self, label: &'static str, cancellation: &McpRequestCancellation, value: T)
        -> CoreInputHostFuture<'static, T>
    {
        self.calls.push(label);
        if self.cancel == Some(label) { cancellation.cancel(); }
        let denied = self.denied == Some(label);
        let hang = self.hang == Some(label);
        let drops = self.drops.clone();
        Box::pin(async move {
            if denied { return Err(CoreInputHostError::Denied); }
            if hang {
                let _guard = PendingDrop(drops);
                std::future::pending::<()>().await;
            }
            Ok(value)
        })
    }
}
impl SamplingHost for Host {
    fn sample<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation, _: &'a FinalEmbeddedCreateMessageParams)
        -> SamplingHostFuture<'a, FinalCreateMessageResult>
    {
        self.calls.push("sample");
        Box::pin(std::future::ready(Ok(serde_json::from_value(json!({
            "role":"assistant","model":"test-model","content":{"type":"text","text":"answer"},"stopReason":"endTurn"
        })).unwrap())))
    }
    fn approve_tools<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation, _: &'a [SamplingContentBlock])
        -> SamplingHostFuture<'a, ()>
    { self.calls.push("tools"); Box::pin(std::future::ready(Err(SamplingHostError::Denied))) }
    fn execute_tool<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation, _: &'a SamplingContentBlock)
        -> SamplingHostFuture<'a, SamplingContentBlock>
    { self.calls.push("execute"); Box::pin(std::future::ready(Err(SamplingHostError::Denied))) }
}
impl CoreInputHost for Host {
    fn approve_inputs<'a>(&'a mut self, _: &'a Cx, cancellation: &'a McpRequestCancellation, requests: &'a [CoreInputRequest])
        -> CoreInputHostFuture<'a, ()>
    {
        self.approved = requests.iter().map(|request| request.key().to_owned()).collect();
        self.respond("approve", cancellation, ())
    }
    fn roots<'a>(&'a mut self, _: &'a Cx, cancellation: &'a McpRequestCancellation, _: &'a FinalEmbeddedRootsListParams)
        -> CoreInputHostFuture<'a, FinalEmbeddedRootsListResult>
    { self.respond("roots", cancellation, self.roots.clone()) }
    fn form<'a>(&'a mut self, _: &'a Cx, cancellation: &'a McpRequestCancellation, _: &'a FinalEmbeddedFormElicitationParams)
        -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>
    { self.respond("form", cancellation, self.form.clone()) }
    fn url<'a>(&'a mut self, _: &'a Cx, cancellation: &'a McpRequestCancellation, request: &'a FinalEmbeddedUrlElicitationParams)
        -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>
    {
        assert_eq!(request.url.as_str(), "https://example.test/action?opaque=%2F");
        self.respond("url", cancellation, self.url.clone())
    }
}
async fn resolve(cx: &Cx, original: &CoreRequest, source: &str, limits: CoreInputLimits, host: &mut Host)
    -> Result<ManagedInputReply, CoreInputError>
{
    resolve_core_inputs(cx, &McpRequestCancellation::new(), original, input(source), RequestId::Number(42), limits, host).await
}

#[test]
fn mixed_inputs_preserve_keys_order_exact_integer_and_response_kinds() {
    run(async |cx| {
        let mut host = Host::default();
        let request = all();
        let before = request.encode_params().unwrap();
        let reply = resolve(&cx, &request, MIXED, CoreInputLimits::default(), &mut host).await.unwrap();
        let responses = reply.input_responses.unwrap();
        assert_eq!(host.calls, ["approve","roots","form","url","sample"]);
        assert_eq!(host.approved, ["z/root~\n","a/form","q/url","b/sample"]);
        assert_eq!(responses.entries().iter().map(|(key, _)| key.as_str()).collect::<Vec<_>>(), host.approved);
        responses.validate_against_input_required(&input(MIXED)).unwrap();
        let encoded = serde_json::to_string(&responses).unwrap();
        assert!(encoded.contains("900719925474099312345"));
        assert!(encoded.contains("file:///workspace/%2F"));
        assert_eq!(request.encode_params().unwrap(), before);
    });
}

#[test]
fn unsupported_later_capability_refuses_before_approval_or_earlier_effects() {
    run(async |cx| {
        let mut host = Host::default();
        let request = original(json!({"roots":{},"sampling":{},"elicitation":{"form":{}}}));
        assert_eq!(resolve(&cx, &request, MIXED, CoreInputLimits::default(), &mut host).await.err(),
            Some(CoreInputError::CapabilityNotAdvertised));
        assert!(host.calls.is_empty());
    });
}

#[test]
fn whole_batch_denial_performs_no_input_effect_and_retains_no_answers() {
    run(async |cx| {
        let mut host = Host { denied: Some("approve"), ..Host::default() };
        assert_eq!(resolve(&cx, &all(), MIXED, CoreInputLimits::default(), &mut host).await.err(),
            Some(CoreInputError::Host { stage: CoreInputStage::Approval, reason: CoreInputHostError::Denied }));
        assert_eq!(host.calls, ["approve"]);
    });
}

#[test]
fn host_failure_stops_later_inputs_without_retrying_prior_callbacks() {
    run(async |cx| {
        let mut host = Host { denied: Some("form"), ..Host::default() };
        assert_eq!(resolve(&cx, &all(), MIXED, CoreInputLimits::default(), &mut host).await.err(),
            Some(CoreInputError::Host { stage: CoreInputStage::Form, reason: CoreInputHostError::Denied }));
        assert_eq!(host.calls, ["approve","roots","form"]);
    });
}

#[test]
fn accepted_form_answers_must_match_the_requested_schema() {
    run(async |cx| {
        for content in [json!({}), json!({"quantity":0}), json!({"quantity":"1"}), json!({"quantity":1,"extra":true})] {
            let mut host = Host::default();
            host.form = serde_json::from_value(json!({"action":"accept","content":content})).unwrap();
            assert_eq!(resolve(&cx, &all(), MIXED, CoreInputLimits::default(), &mut host).await.err(), Some(CoreInputError::InvalidFormContent));
            assert_eq!(host.calls, ["approve","roots","form"]);
        }
    });
}

#[test]
fn form_decline_cancel_and_url_actions_are_replies_not_transport_errors() {
    run(async |cx| {
        for action in ["decline","cancel"] {
            let mut host = Host::default();
            host.form = serde_json::from_value(json!({"action":action})).unwrap();
            host.url = host.form.clone();
            let reply = resolve(&cx, &all(), MIXED, CoreInputLimits::default(), &mut host).await.unwrap();
            let wire = serde_json::to_value(reply.input_responses.unwrap()).unwrap();
            for key in ["a/form","q/url"] {
                assert_eq!(wire[key]["action"], action);
                assert!(wire[key].get("content").is_none());
            }
        }
    });
}

#[test]
fn wrong_elicitation_content_presence_is_rejected_before_later_effects() {
    run(async |cx| {
        for (form, url) in [(json!({"action":"accept"}),false),
            (json!({"action":"decline","content":{}}),false),
            (json!({"action":"accept","content":{}}),true)]
        {
            let mut host = Host::default();
            let invalid = serde_json::from_value(form).unwrap();
            if url { host.url = invalid; } else { host.form = invalid; }
            assert_eq!(resolve(&cx, &all(), MIXED, CoreInputLimits::default(), &mut host).await.err(), Some(CoreInputError::InvalidResponse));
            assert!(!host.calls.contains(&"sample"));
        }
    });
}

#[test]
fn malformed_or_nonfile_roots_cannot_enter_the_reply_map() {
    run(async |cx| {
        for uri in ["../private", "https://example.test/root", "file:///bad%GG"] {
            let mut host = Host::default();
            host.roots.roots[0].uri = uri.to_owned();
            assert_eq!(resolve(&cx, &all(), ROOTS, CoreInputLimits::default(), &mut host).await.err(), Some(CoreInputError::InvalidResponse));
            assert_eq!(host.calls, ["approve","roots"]);
        }
    });
}

#[test]
fn roots_and_form_fields_have_whole_challenge_budgets() {
    run(async |cx| {
        let twice = r#"{"resultType":"input_required","inputRequests":{"one":{"method":"roots/list"},"two":{"method":"roots/list"}}}"#;
        let mut host = Host::default();
        let limits = CoreInputLimits::new(SamplingInputLimits::default(), 1, 256).unwrap();
        assert_eq!(resolve(&cx, &all(), twice, limits, &mut host).await.err(), Some(CoreInputError::RootLimit));
        assert_eq!(host.calls, ["approve","roots","roots"]);
        let mut host = Host::default();
        let limits = CoreInputLimits::new(SamplingInputLimits::default(), 256, 0).unwrap();
        assert_eq!(resolve(&cx, &all(), MIXED, limits, &mut host).await.err(), Some(CoreInputError::FormFieldLimit));
        assert_eq!(host.calls, ["approve","roots","form"]);
    });
}

#[test]
fn input_and_minimum_reply_bytes_refuse_before_callbacks() {
    run(async |cx| {
        for (input_bytes, reply_bytes, error) in [(2,4096,CoreInputError::InputByteLimit),(4096,2,CoreInputError::ReplyByteLimit)] {
            let sampling = SamplingInputLimits::new(SamplingRunLimits::default(), 8, 8, 8, input_bytes, reply_bytes).unwrap();
            let mut host = Host::default();
            assert_eq!(resolve(&cx, &all(), MIXED, CoreInputLimits::new(sampling,256,256).unwrap(), &mut host).await.err(), Some(error));
            assert!(host.calls.is_empty());
        }
    });
}

#[test]
fn nonfinite_form_number_is_not_silently_replaced_by_null() {
    run(async |cx| {
        let mut host = Host::default();
        host.form.content.as_mut().unwrap().insert("quantity".to_owned(), ElicitContentValue::Float(f64::NAN));
        assert_eq!(resolve(&cx, &all(), MIXED, CoreInputLimits::default(), &mut host).await.err(), Some(CoreInputError::InvalidFormContent));
        assert!(!host.calls.contains(&"url"));
    });
}

#[test]
fn state_only_and_present_empty_maps_do_not_invoke_hosts() {
    run(async |cx| {
        for (source, present) in [(r#"{"resultType":"input_required","requestState":""}"#,false),
            (r#"{"resultType":"input_required","inputRequests":{}}"#,true)]
        {
            let mut host = Host::default();
            let reply = resolve(&cx, &all(), source, CoreInputLimits::default(), &mut host).await.unwrap();
            assert_eq!(reply.input_responses.is_some(),present);
            assert!(reply.input_responses.is_none_or(|responses|responses.is_empty()));
            assert!(host.calls.is_empty());
        }
    });
}

#[test]
fn cancellation_before_or_during_a_ready_callback_prevents_following_work() {
    run(async |cx| {
        for precancelled in [true,false] {
            let cancellation = McpRequestCancellation::new();
            let mut host = Host { cancel: Some("roots"), ..Host::default() };
            if precancelled { cancellation.cancel(); }
            let result = resolve_core_inputs(&cx,&cancellation,&all(),input(MIXED),RequestId::Number(42),CoreInputLimits::default(),&mut host).await;
            assert_eq!(result.err(),Some(CoreInputError::Sampling(SamplingInputError::Run(SamplingRunError::Cancelled))));
            assert_eq!(host.calls,if precancelled {vec![]} else {vec!["approve","roots"]});
        }
    });
}

#[test]
fn pending_host_timeout_and_abandonment_drop_the_host_future() {
    run(async |cx| {
        let limits = CoreInputLimits::new(SamplingInputLimits::new(
            SamplingRunLimits::new(fastmcp_protocol::sampling::SamplingToolLoopLimits::default(),Duration::from_millis(30),4096).unwrap(),
            8,8,8,4096,4096).unwrap(),256,256).unwrap();
        let mut host = Host { hang: Some("roots"), ..Host::default() };
        assert_eq!(resolve(&cx,&all(),ROOTS,limits,&mut host).await.err(),
            Some(CoreInputError::Sampling(SamplingInputError::Run(SamplingRunError::TimedOut))));
        assert_eq!(host.drops.load(Ordering::SeqCst),1);
        assert_eq!(host.calls,["approve","roots"]);

        let request = all();
        let mut host = Host { hang: Some("approve"), ..Host::default() };
        let drops = host.drops.clone();
        let mut future = Box::pin(resolve(&cx,&request,ROOTS,CoreInputLimits::default(),&mut host));
        std::future::poll_fn(|context| {
            assert!(future.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        }).await;
        drop(future);
        assert_eq!(drops.load(Ordering::SeqCst),1);
        assert_eq!(host.calls,["approve"]);
    });
}

#[test]
fn model_budget_counts_sampling_siblings_before_approval() {
    run(async |cx| {
        let twice = r#"{"resultType":"input_required","inputRequests":{"a":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}},"b":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}}}}"#;
        let sampling = SamplingInputLimits::new(SamplingRunLimits::default(),8,1,8,4096,4096).unwrap();
        let mut host = Host::default();
        assert_eq!(resolve(&cx,&all(),twice,CoreInputLimits::new(sampling,256,256).unwrap(),&mut host).await.err(),
            Some(CoreInputError::Sampling(SamplingInputError::ModelRoundLimit)));
        assert!(host.calls.is_empty());
    });
}

#[test]
fn selected_inputs_preserve_server_order_without_invoking_omitted_hosts() {
    run(async |cx| {
        let mut host = Host::default();
        let reply = resolve_selected_core_inputs(&cx,&McpRequestCancellation::new(),&all(),input(MIXED),
            RequestId::Number(42),CoreInputLimits::default(),&["q/url","z/root~\n"],&mut host).await.unwrap();
        assert_eq!(host.calls,["approve","roots","url"]);
        assert_eq!(host.approved,["z/root~\n","q/url"]);
        let responses = reply.input_responses.unwrap();
        assert_eq!(responses.entries().iter().map(|(key,_)|key.as_str()).collect::<Vec<_>>(),["z/root~\n","q/url"]);
        validate_partial_responses(&input(MIXED),&responses).unwrap();
        assert!(responses.validate_against_input_required(&input(MIXED)).is_err(),"full-map validation stays exhaustive");
    });
}

#[test]
fn selected_inputs_refuse_empty_unknown_and_duplicate_keys_before_approval() {
    run(async |cx| {
        for selection in [vec![],vec!["unknown"],vec!["a/form","a/form"],vec!["z/root~\n","unknown"]] {
            let mut host = Host::default();
            let result = resolve_selected_core_inputs(&cx,&McpRequestCancellation::new(),&all(),input(MIXED),
                RequestId::Number(42),CoreInputLimits::default(),&selection,&mut host).await;
            assert_eq!(result.err(),Some(CoreInputError::InvalidSelection));
            assert!(host.calls.is_empty());
        }
    });
}

#[test]
fn omitted_sampling_requires_no_model_budget_or_model_callback() {
    run(async |cx| {
        let sampling = SamplingInputLimits::new(SamplingRunLimits::default(),8,0,0,4096,4096).unwrap();
        let limits = CoreInputLimits::new(sampling,256,256).unwrap();
        let mut host = Host::default();
        let reply = resolve_selected_core_inputs(&cx,&McpRequestCancellation::new(),&all(),input(MIXED),
            RequestId::Number(42),limits,&["a/form"],&mut host).await.unwrap();
        assert_eq!(reply.input_responses.unwrap().len(),1);
        assert_eq!(host.calls,["approve","form"]);
        let mut control = Host::default();
        assert_eq!(resolve(&cx,&all(),MIXED,limits,&mut control).await.err(),
            Some(CoreInputError::Sampling(SamplingInputError::ModelRoundLimit)));
        assert!(control.calls.is_empty());
    });
}

#[test]
fn selected_subset_requires_state_but_full_selection_does_not() {
    run(async |cx| {
        for replacement in ["", "\"requestState\":\"\","] {
            let source = MIXED.replace("\"requestState\":\"opaque+/%\",",replacement);
            let mut host = Host::default();
            let result = resolve_selected_core_inputs(&cx,&McpRequestCancellation::new(),&all(),input(&source),
                RequestId::Number(42),CoreInputLimits::default(),&["a/form"],&mut host).await;
            assert_eq!(result.err(),Some(CoreInputError::PartialStateRequired));
            assert!(host.calls.is_empty());
            let reply = resolve_selected_core_inputs(&cx,&McpRequestCancellation::new(),&all(),input(&source),
                RequestId::Number(43),CoreInputLimits::default(),&["a/form","q/url","b/sample","z/root~\n"],&mut host).await.unwrap();
            assert_eq!(reply.input_responses.unwrap().len(),4);
        }
    });
}

#[test]
fn omitted_inputs_still_require_advertised_capabilities() {
    run(async |cx| {
        let mut host = Host::default();
        let request = original(json!({"roots":{}}));
        let result = resolve_selected_core_inputs(&cx,&McpRequestCancellation::new(),&request,input(MIXED),
            RequestId::Number(42),CoreInputLimits::default(),&["z/root~\n"],&mut host).await;
        assert_eq!(result.err(),Some(CoreInputError::CapabilityNotAdvertised));
        assert!(host.calls.is_empty());
    });
}
