//! Public execution tests. The model/tool host is deterministic test code, not
//! a claim about a third-party provider or live MCP interoperability.

use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use asupersync::{Budget, Cx, Time};
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use fastmcp_client::http_auth::sampling::{
    SamplingHost, SamplingHostError, SamplingHostFuture, SamplingRunError,
    SamplingRunLimits, SamplingStage, run_sampling_tool_loop,
};
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::common_types::SamplingContentBlock;
use fastmcp_protocol::sampling::{SamplingToolLoopError, SamplingToolLoopLimits};
use fastmcp_protocol::{FinalCreateMessageResult, FinalEmbeddedCreateMessageParams};
use serde_json::{Value, json};

fn request() -> FinalEmbeddedCreateMessageParams {
    serde_json::from_value(json!({
        "messages":[{"role":"user","content":{"type":"text","text":"weather"}}],
        "maxTokens":100,"metadata":{"private":"retained"},
        "tools":[{"name":"weather","inputSchema":{"type":"object",
            "properties":{"city":{"type":"string"}},"required":["city"]}}]
    })).unwrap()
}
fn call(id: &str) -> Value {
    json!({"type":"tool_use","id":id,"name":"weather","input":{"city":"Paris"}})
}
fn response(content: Value) -> FinalCreateMessageResult {
    serde_json::from_value(json!({"role":"assistant","model":"test-model","content":content})).unwrap()
}
fn final_response() -> FinalCreateMessageResult {
    serde_json::from_value(json!({"role":"assistant","model":"final-model",
        "content":[{"type":"text","text":"done","_meta":{"marker":"untouched"}}],
        "stopReason":"future-provider-reason","_meta":{"trace":"retained"}})).unwrap()
}
fn answer(id: &str) -> SamplingContentBlock {
    serde_json::from_value(json!({"type":"tool_result","toolUseId":id,
        "content":[{"type":"text","text":"sunny"}],"structuredContent":null})).unwrap()
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}
struct Pending<T> {
    polls: Arc<AtomicUsize>, drops: Arc<AtomicUsize>, output: PhantomData<fn() -> T>,
}
impl<T> Future for Pending<T> {
    type Output = Result<T, SamplingHostError>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}
impl<T> Drop for Pending<T> {
    fn drop(&mut self) { self.drops.fetch_add(1, Ordering::SeqCst); }
}

struct Host {
    models: VecDeque<FinalCreateMessageResult>,
    answers: VecDeque<SamplingContentBlock>,
    requests: Vec<Value>,
    approvals: usize,
    calls: Vec<String>,
    fail: Option<(SamplingStage, SamplingHostError)>,
    pending: Option<SamplingStage>,
    cancel_after: Option<SamplingStage>,
    cancel_current: bool,
    pending_model_index: Option<usize>,
    after_first_model: Option<(Arc<VirtualClock>, u64)>,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}
impl Host {
    fn new(models: Vec<FinalCreateMessageResult>, answers: Vec<SamplingContentBlock>) -> Self {
        Self {
            models: models.into(), answers: answers.into(), requests: Vec::new(),
            approvals: 0, calls: Vec::new(), fail: None, pending: None,
            cancel_after: None, cancel_current: false,
            pending_model_index: None, after_first_model: None,
            polls: Arc::new(AtomicUsize::new(0)), drops: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn operation<T: Send + 'static>(
        &self, stage: SamplingStage, cancellation: &McpRequestCancellation,
        value: T,
    ) -> SamplingHostFuture<'static, T> {
        assert!(Cx::current().unwrap().timer_driver().is_some(), "caller driver must be installed");
        if self.pending == Some(stage) {
            return Box::pin(Pending {
                polls: self.polls.clone(), drops: self.drops.clone(), output: PhantomData,
            });
        }
        if self.cancel_after == Some(stage) { cancellation.cancel(); }
        if self.cancel_current { Cx::current().unwrap().set_cancel_requested(true); }
        let result = match self.fail {
            Some((failed_stage, reason)) if failed_stage == stage => Err(reason),
            _ => Ok(value),
        };
        Box::pin(std::future::ready(result))
    }
}
impl SamplingHost for Host {
    fn sample<'a>(
        &'a mut self, _: &'a Cx, cancellation: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedCreateMessageParams,
    ) -> SamplingHostFuture<'a, FinalCreateMessageResult> {
        self.requests.push(serde_json::to_value(request).unwrap());
        if self.requests.len() == 1 {
            if let Some((clock, nanos)) = &self.after_first_model { clock.advance(*nanos); }
        }
        if self.pending_model_index == Some(self.requests.len()) { self.pending = Some(SamplingStage::Model); }
        let value = self.models.pop_front().expect("unexpected extra model invocation");
        self.operation(SamplingStage::Model, cancellation, value)
    }
    fn approve_tools<'a>(
        &'a mut self, _: &'a Cx, cancellation: &'a McpRequestCancellation,
        calls: &'a [SamplingContentBlock],
    ) -> SamplingHostFuture<'a, ()> {
        assert!(!calls.is_empty());
        assert!(calls.iter().all(|call| matches!(call, SamplingContentBlock::ToolUse { .. })));
        self.approvals += 1;
        self.operation(SamplingStage::Approval, cancellation, ())
    }
    fn execute_tool<'a>(
        &'a mut self, _: &'a Cx, cancellation: &'a McpRequestCancellation,
        call: &'a SamplingContentBlock,
    ) -> SamplingHostFuture<'a, SamplingContentBlock> {
        let SamplingContentBlock::ToolUse { id, .. } = call else { panic!("not an admitted call") };
        self.calls.push(id.clone());
        let value = self.answers.pop_front().expect("unexpected extra tool invocation");
        self.operation(SamplingStage::Tool, cancellation, value)
    }
}

fn with_cx(test: impl FnOnce(Cx, Arc<VirtualClock>, TimerDriverHandle)) {
    with_budget(Budget::INFINITE, test);
}
fn with_budget(budget: Budget, test: impl FnOnce(Cx, Arc<VirtualClock>, TimerDriverHandle)) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
    let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 0)
        .with_timer_driver(timer.clone()).build().unwrap();
    test(runtime.request_cx_with_budget(budget), clock, timer);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}
fn complete<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut task = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut task) { return value; }
    }
    panic!("deterministic ready host did not finish within its poll bound");
}
fn two_calls() -> Host {
    Host::new(vec![response(json!([call("a"), call("b")])), final_response()],
        vec![answer("a"), answer("b")])
}

#[test]
fn complete_conversation_preserves_exact_transcript_and_runs_tools_in_model_order() {
    with_cx(|cx, _, timer| {
        let mut host = two_calls();
        let result = complete(run_sampling_tool_loop(&cx, &McpRequestCancellation::new(),
            request(), SamplingRunLimits::default(), &mut host)).unwrap();
        assert_eq!(result.response, final_response());
        assert_eq!(result.model_rounds, 2);
        assert_eq!(result.executed_tools, 2);
        assert_eq!(host.calls, ["a", "b"]);
        assert_eq!(host.approvals, 1);
        assert_eq!(host.requests.len(), 2);
        let next = &host.requests[1];
        assert_eq!(next["metadata"], json!({"private":"retained"}));
        assert_eq!(next["messages"][1]["content"], json!([call("a"),call("b")]));
        assert_eq!(next["messages"][2]["role"], "user");
        for (index, id) in ["a", "b"].iter().enumerate() {
            assert_eq!(next["messages"][2]["content"][index]["toolUseId"], *id);
            assert_eq!(next["messages"][2]["content"][index].get("structuredContent"), Some(&Value::Null));
        }
        assert_eq!(timer.pending_count(), 0);
    });
}

#[test]
fn whole_batch_denial_runs_no_tool_and_does_not_retry_the_model() {
    with_cx(|cx, _, _| {
        let mut host = two_calls();
        host.fail = Some((SamplingStage::Approval, SamplingHostError::Denied));
        let error = complete(run_sampling_tool_loop(&cx, &McpRequestCancellation::new(),
            request(), SamplingRunLimits::default(), &mut host)).err().unwrap();
        assert_eq!(error, SamplingRunError::Host { stage: SamplingStage::Approval, reason: SamplingHostError::Denied });
        assert_eq!(host.approvals, 1);
        assert!(host.calls.is_empty());
        assert_eq!(host.requests.len(), 1);
    });
}

#[test]
fn malformed_later_call_prevents_even_the_valid_first_tool_from_being_approved() {
    with_cx(|cx, _, _| {
        let mut bad = call("b");
        bad["input"]["city"] = json!(7);
        let mut host = Host::new(vec![response(json!([call("a"), bad]))], vec![]);
        let error = complete(run_sampling_tool_loop(&cx, &McpRequestCancellation::new(),
            request(), SamplingRunLimits::default(), &mut host)).err().unwrap();
        assert_eq!(error, SamplingRunError::Protocol(SamplingToolLoopError::InvalidToolInput));
        assert_eq!(host.approvals, 0);
        assert!(host.calls.is_empty());
    });
}

#[test]
fn invalid_history_and_missing_timer_never_invoke_the_host() {
    with_cx(|cx, _, _| {
        let mut input = request();
        input.messages.clear();
        let mut host = Host::new(vec![], vec![]);
        assert_eq!(complete(run_sampling_tool_loop(&cx, &McpRequestCancellation::new(),
            input, SamplingRunLimits::default(), &mut host)).err(),
            Some(SamplingRunError::Protocol(SamplingToolLoopError::InvalidRequest)));
        assert!(host.requests.is_empty());
    });
    let mut host = Host::new(vec![], vec![]);
    assert_eq!(complete(run_sampling_tool_loop(&Cx::for_testing(), &McpRequestCancellation::new(),
        request(), SamplingRunLimits::default(), &mut host)).err(), Some(SamplingRunError::RuntimeUnavailable));
    assert!(host.requests.is_empty());
}

#[test]
fn foreign_result_id_stops_before_the_next_tool_and_cannot_be_used_for_its_sibling() {
    with_cx(|cx, _, _| {
        let mut host = two_calls();
        host.answers[0] = answer("b");
        assert_eq!(complete(run_sampling_tool_loop(&cx, &McpRequestCancellation::new(),
            request(), SamplingRunLimits::default(), &mut host)).err(),
            Some(SamplingRunError::Protocol(SamplingToolLoopError::InvalidToolResults)));
        assert_eq!(host.calls, ["a"]);
        assert_eq!(host.requests.len(), 1);
    });
}

#[test]
fn invalid_structured_output_stops_before_a_second_tool_side_effect() {
    with_cx(|cx, _, _| {
        let mut input = request();
        input.tools.as_mut().unwrap()[0].output_schema = Some(json!({"type":"integer"}));
        let mut host = two_calls();
        assert_eq!(complete(run_sampling_tool_loop(&cx, &McpRequestCancellation::new(),
            input, SamplingRunLimits::default(), &mut host)).err(),
            Some(SamplingRunError::Protocol(SamplingToolLoopError::InvalidToolOutput)));
        assert_eq!(host.calls, ["a"]);
        assert_eq!(host.requests.len(), 1);
    });
}

#[test]
fn explicit_application_error_is_a_correlated_result_not_a_host_transport_retry() {
    with_cx(|cx, _, _| {
        let mut input = request();
        input.tools.as_mut().unwrap()[0].output_schema = Some(json!({"type":"integer"}));
        let error: SamplingContentBlock = serde_json::from_value(json!({
            "type":"tool_result","toolUseId":"a","content":[],"isError":true
        })).unwrap();
        let mut host = Host::new(vec![response(call("a")), final_response()], vec![error]);
        assert!(complete(run_sampling_tool_loop(&cx, &McpRequestCancellation::new(),
            input, SamplingRunLimits::default(), &mut host)).is_ok());
        assert_eq!(host.requests[1]["messages"][2]["content"][0]["isError"], true);
        assert_eq!(host.calls, ["a"]);
    });
}

#[test]
fn round_limit_refuses_before_tool_approval_and_execution() {
    with_cx(|cx, _, _| {
        let mut host = two_calls();
        let limits = SamplingRunLimits::new(SamplingToolLoopLimits::new(1, 8, 4096).unwrap(),
            Duration::from_secs(1), 4096).unwrap();
        assert_eq!(complete(run_sampling_tool_loop(&cx, &McpRequestCancellation::new(),
            request(), limits, &mut host)).err(), Some(SamplingRunError::Protocol(SamplingToolLoopError::RoundLimit)));
        assert_eq!(host.approvals, 0);
        assert!(host.calls.is_empty());
    });
}

#[test]
fn tool_result_bytes_are_shared_across_model_rounds() {
    with_cx(|cx, _, _| {
        let size = serde_json::to_vec(&answer("a")).unwrap().len();
        for (maximum, succeeds) in [(size * 2, true), (size * 2 - 1, false)] {
            let mut host = Host::new(vec![response(call("a")), response(call("b")), final_response()],
                vec![answer("a"), answer("b")]);
            let limits = SamplingRunLimits::new(SamplingToolLoopLimits::default(), Duration::from_secs(1), maximum).unwrap();
            let result = complete(run_sampling_tool_loop(&cx, &McpRequestCancellation::new(), request(), limits, &mut host));
            if succeeds { assert_eq!(result.unwrap().executed_tools, 2); }
            else { assert_eq!(result.err(), Some(SamplingRunError::ToolResultByteLimit)); }
            assert_eq!(host.requests.len(), if succeeds { 3 } else { 2 });
        }
    });
}

#[test]
fn host_failures_never_retry_any_model_or_tool_invocation() {
    with_cx(|cx, _, _| {
        for stage in [SamplingStage::Model, SamplingStage::Approval, SamplingStage::Tool] {
            let mut host = two_calls();
            host.fail = Some((stage, SamplingHostError::Failed));
            assert_eq!(complete(run_sampling_tool_loop(&cx, &McpRequestCancellation::new(),
                request(), SamplingRunLimits::default(), &mut host)).err(),
                Some(SamplingRunError::Host { stage, reason: SamplingHostError::Failed }));
            assert_eq!(host.requests.len(), 1);
            assert_eq!(host.calls.len(), usize::from(stage == SamplingStage::Tool));
        }
    });
}

#[test]
fn cancellation_wakes_each_pending_host_stage_and_drops_the_owned_future() {
    with_cx(|cx, _, timer| {
        for stage in [SamplingStage::Model, SamplingStage::Approval, SamplingStage::Tool] {
            let cancellation = McpRequestCancellation::new();
            let mut host = two_calls();
            host.pending = Some(stage);
            let polls = host.polls.clone();
            let drops = host.drops.clone();
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(counter.clone());
            let mut task = Context::from_waker(&waker);
            let mut future = Box::pin(run_sampling_tool_loop(&cx, &cancellation, request(), SamplingRunLimits::default(), &mut host));
            for _ in 0..4 {
                assert!(future.as_mut().poll(&mut task).is_pending());
                if polls.load(Ordering::SeqCst) > 0 { break; }
            }
            assert_eq!(polls.load(Ordering::SeqCst), 1);
            let before = counter.0.load(Ordering::SeqCst);
            cancellation.cancel();
            assert!(counter.0.load(Ordering::SeqCst) > before, "cancellation needs a real wakeup");
            let Poll::Ready(result) = future.as_mut().poll(&mut task) else { panic!("cancel did not settle") };
            assert_eq!(result.err(), Some(SamplingRunError::Cancelled));
            assert_eq!(polls.load(Ordering::SeqCst), 1);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            drop(future);
            assert_eq!(host.requests.len(), 1);
            assert_eq!(timer.pending_count(), 0);
        }
    });
}

#[test]
fn parent_cancellation_wakes_without_a_host_wakeup() {
    with_cx(|cx, _, timer| {
        let mut host = two_calls();
        host.pending = Some(SamplingStage::Model);
        let cancellation = McpRequestCancellation::new();
        let counter = Arc::new(WakeCount::default());
        let waker = Waker::from(counter.clone());
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(run_sampling_tool_loop(&cx, &cancellation, request(), SamplingRunLimits::default(), &mut host));
        assert!(future.as_mut().poll(&mut task).is_pending());
        assert_eq!(counter.0.load(Ordering::SeqCst), 0);
        cx.set_cancel_requested(true);
        assert!(counter.0.load(Ordering::SeqCst) > 0);
        let Poll::Ready(result) = future.as_mut().poll(&mut task) else { panic!("parent cancellation stuck") };
        assert_eq!(result.err(), Some(SamplingRunError::Cancelled));
        drop(future);
        assert_eq!(timer.pending_count(), 0);
    });
}

#[test]
fn absolute_and_shorter_parent_deadlines_wake_pending_model_without_repolling_it() {
    for parent in [None, Some(Time::from_nanos(3_000_000))] {
        let budget = parent.map_or(Budget::INFINITE, |end| Budget::INFINITE.with_deadline(end));
        with_budget(budget, |cx, clock, timer| {
            let mut host = two_calls();
            host.pending = Some(SamplingStage::Model);
            let cancellation = McpRequestCancellation::new();
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(counter.clone());
            let mut task = Context::from_waker(&waker);
            let limits = SamplingRunLimits::new(SamplingToolLoopLimits::default(), Duration::from_millis(5), 4096).unwrap();
            let mut future = Box::pin(run_sampling_tool_loop(&cx, &cancellation, request(), limits, &mut host));
            assert!(future.as_mut().poll(&mut task).is_pending());
            assert!(timer.pending_count() > 0);
            clock.advance(parent.map_or(5_000_000, |end| end.as_nanos()));
            assert!(timer.process_timers() > 0);
            assert!(counter.0.load(Ordering::SeqCst) > 0);
            let Poll::Ready(result) = future.as_mut().poll(&mut task) else { panic!("deadline stuck") };
            assert_eq!(result.err(), Some(SamplingRunError::TimedOut));
            drop(future);
            assert_eq!(host.polls.load(Ordering::SeqCst), 1);
            assert_eq!(host.drops.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
        });
    }
}

#[test]
fn a_host_cancelling_during_ready_completion_cannot_publish_or_start_a_sibling() {
    with_cx(|cx, _, _| {
        for stage in [SamplingStage::Model, SamplingStage::Approval, SamplingStage::Tool] {
            let cancellation = McpRequestCancellation::new();
            let mut host = two_calls();
            host.cancel_after = Some(stage);
            assert_eq!(complete(run_sampling_tool_loop(&cx, &cancellation, request(), SamplingRunLimits::default(), &mut host)).err(),
                Some(SamplingRunError::Cancelled));
            assert_eq!(host.requests.len(), 1);
            assert_eq!(host.calls.len(), usize::from(stage == SamplingStage::Tool));
        }
    });
}

#[test]
fn dropping_the_run_releases_host_timer_and_cancel_registrations() {
    with_cx(|cx, _, timer| {
        let cancellation = McpRequestCancellation::new();
        let mut host = two_calls();
        host.pending = Some(SamplingStage::Model);
        let counter = Arc::new(WakeCount::default());
        let waker = Waker::from(counter.clone());
        let mut future = Box::pin(run_sampling_tool_loop(&cx, &cancellation, request(), SamplingRunLimits::default(), &mut host));
        assert!(future.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        drop(future);
        assert_eq!(host.drops.load(Ordering::SeqCst), 1);
        assert_eq!(timer.pending_count(), 0);
        let before = counter.0.load(Ordering::SeqCst);
        cancellation.cancel();
        cx.set_cancel_requested(true);
        assert_eq!(counter.0.load(Ordering::SeqCst), before);
    });
}

#[test]
fn host_polling_uses_the_caller_and_restores_an_unrelated_ambient_context() {
    with_cx(|cx, _, _| {
        let ambient = Cx::for_testing();
        let _guard = Cx::set_current(Some(ambient.clone()));
        let mut host = Host::new(vec![final_response()], vec![]);
        host.cancel_current = true;
        assert_eq!(complete(run_sampling_tool_loop(&cx, &McpRequestCancellation::new(),
            request(), SamplingRunLimits::default(), &mut host)).err(), Some(SamplingRunError::Cancelled));
        assert!(cx.is_cancel_requested());
        assert!(!ambient.is_cancel_requested());
        Cx::current().unwrap().set_cancel_requested(true);
        assert!(ambient.is_cancel_requested());
    });
}

mod embedded_inputs {
    use super::*;
    use fastmcp_client::http_auth::sampling::inputs::{
        SamplingInputError, SamplingInputLimits, resolve_sampling_inputs,
    };
    use fastmcp_protocol::{
        ClientCapabilities, CoreRequest, ExactJsonValue, FinalEmbeddedInputRequest,
        FinalRequestMeta, InputRequiredResult, RequestId, ResultMeta, exact_json_to_serde,
        parse_exact_json,
    };
    use fastmcp_protocol::protocol_policy::ProtocolEra;

    fn original(capabilities: Value) -> CoreRequest {
        let mut meta = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        meta[fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY] = capabilities;
        CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&json!({
            "_meta":meta,"name":"effect","arguments":{"unchanged":"yes"}
        }))).unwrap()
    }

    fn all() -> CoreRequest {
        original(json!({"roots":{},"sampling":{"tools":{},"context":{}}}))
    }

    fn descriptor() -> String {
        serde_json::to_string(&FinalEmbeddedInputRequest::Sampling(request())).unwrap()
    }

    fn plain_descriptor() -> Value {
        json!({"method":"sampling/createMessage","params":{
            "messages":[{"role":"user","content":{"type":"text","text":"weather"}}],
            "maxTokens":100
        }})
    }

    fn challenge(raw: Option<&str>, state: Option<&str>) -> InputRequiredResult {
        let map = raw.map(|raw| match parse_exact_json(raw).unwrap() {
            ExactJsonValue::Object(map) => map,
            _ => panic!("test descriptors must be an object"),
        });
        // bd-seclh: `ResultMeta::empty()` rather than `Default` — the same value
        // (all three fields None), with the intent named. Its doc states the wire
        // consequence: "preserves the absence of the optional `_meta` member".
        // No assertion in this file reads result metadata, so empty is correct
        // here and not merely compiling. 54 sites use the named constructors;
        // this was the only `Default`.
        InputRequiredResult::new(map, state.map(str::to_owned), ResultMeta::empty()).unwrap()
    }

    fn two_inputs() -> String {
        format!(r#"{{"z/first~\n":{},"a-second":{}}}"#, descriptor(), descriptor())
    }

    fn limits(run: SamplingRunLimits, rounds: usize, tools: usize) -> SamplingInputLimits {
        SamplingInputLimits::new(run, 8, rounds, tools, 1_048_576, 1_048_576).unwrap()
    }

    #[test]
    fn embedded_replies_preserve_keys_order_and_exact_results_without_carrying_request_state() {
        with_cx(|cx, _, _| {
            let input = challenge(Some(&two_inputs()), Some("  opaque\0/%  "));
            let retained = input.clone();
            let mut host = Host::new(vec![final_response(), final_response()], vec![]);
            let reply = complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                &all(), input, RequestId::Number(55), SamplingInputLimits::default(), &mut host)).unwrap();
            assert!(reply.request_id.correlates_with(&RequestId::Number(55)));
            let responses = reply.input_responses.unwrap();
            responses.validate_against_input_required(&retained).unwrap();
            assert_eq!(responses.entries().iter().map(|(key, _)| key.as_str()).collect::<Vec<_>>(),
                ["z/first~\n", "a-second"]);
            let value = serde_json::to_value(&responses).unwrap();
            for key in ["z/first~\n", "a-second"] {
                assert_eq!(value[key], serde_json::to_value(final_response()).unwrap());
            }
            assert_eq!(retained.request_state(), Some("  opaque\0/%  "));
            assert_eq!(host.requests.len(), 2);
            assert!(host.calls.is_empty());
        });
    }

    #[test]
    fn state_only_and_present_empty_maps_remain_distinct_without_host_work() {
        with_cx(|cx, _, _| {
            for raw in [None, Some("{}")] {
                let mut host = Host::new(vec![], vec![]);
                let limits = SamplingInputLimits::new(SamplingRunLimits::default(), 0, 0, 0, 2, 2).unwrap();
                let reply = complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                    &original(json!({})), challenge(raw, Some("")), RequestId::Number(56), limits, &mut host)).unwrap();
                assert_eq!(reply.input_responses.is_some(), raw.is_some());
                if let Some(responses) = reply.input_responses { assert!(responses.is_empty()); }
                assert!(host.requests.is_empty());
                assert_eq!(host.approvals, 0);
            }
        });
    }

    #[test]
    fn later_unsupported_or_invalid_descriptors_refuse_before_the_first_model_call() {
        with_cx(|cx, _, _| {
            for (later, expected) in [
                (r#"{"method":"roots/list"}"#.to_owned(), SamplingInputError::UnsupportedInput),
                (r#"{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":1}}"#.to_owned(),
                    SamplingInputError::Run(SamplingRunError::Protocol(SamplingToolLoopError::InvalidRequest))),
            ] {
                let raw = format!(r#"{{"first":{},"later":{later}}}"#, descriptor());
                let mut host = Host::new(vec![], vec![]);
                assert_eq!(complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                    &all(), challenge(Some(&raw), None), RequestId::Number(57), SamplingInputLimits::default(), &mut host)).err(), Some(expected));
                assert!(host.requests.is_empty());
                assert!(host.calls.is_empty());
            }
        });
    }

    #[test]
    fn sampling_requires_the_original_requests_actual_base_capability() {
        with_cx(|cx, _, _| {
            let raw = json!({"input":plain_descriptor()}).to_string();
            for (capabilities, succeeds) in [
                (json!({}), false),
                (json!({"unknown":{"sampling":{}}}), false),
                (json!({"sampling":{}}), true),
                (json!({"sampling":{"unknown":{}}}), true),
            ] {
                let original = original(capabilities);
                let before = original.encode_params().unwrap();
                let mut host = Host::new(vec![final_response()], vec![]);
                let result = complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                    &original, challenge(Some(&raw), None), RequestId::Number(70),
                    SamplingInputLimits::default(), &mut host));
                if succeeds {
                    assert_eq!(result.unwrap().input_responses.unwrap().len(), 1);
                    assert_eq!(host.requests.len(), 1);
                } else {
                    assert_eq!(result.err(), Some(SamplingInputError::CapabilityNotAdvertised));
                    assert!(host.requests.is_empty());
                }
                assert_eq!(host.approvals, 0);
                assert!(host.calls.is_empty());
                assert_eq!(original.encode_params().unwrap(), before);
            }
        });
    }

    #[test]
    fn tool_choice_only_later_sibling_requires_tools_before_any_host_effect() {
        with_cx(|cx, _, _| {
            for choice in [json!({}), json!({"mode":"none"})] {
                let first = plain_descriptor();
                let mut later = first.clone();
                later["params"]["toolChoice"] = choice.clone();
                let raw = format!(r#"{{"first":{first},"later":{later}}}"#);
                for (capabilities, succeeds) in [
                    (json!({"sampling":{}}), false),
                    (json!({"sampling":{"unknown":{"tools":{}}}}), false),
                    (json!({"sampling":{"tools":{}}}), true),
                ] {
                    let original = original(capabilities);
                    let mut host = Host::new(vec![final_response(), final_response()], vec![]);
                    let input = challenge(Some(&raw), Some("opaque"));
                    let retained = input.clone();
                    let result = complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                        &original, input, RequestId::Number(71), SamplingInputLimits::default(), &mut host));
                    if succeeds {
                        result.unwrap().input_responses.unwrap().validate_against_input_required(&retained).unwrap();
                        assert_eq!(host.requests.len(), 2);
                        assert_eq!(host.requests[1]["toolChoice"], choice);
                        assert!(host.requests[1].get("tools").is_none());
                    } else {
                        assert_eq!(result.err(), Some(SamplingInputError::CapabilityNotAdvertised));
                        assert!(host.requests.is_empty());
                    }
                    assert_eq!(host.approvals, 0);
                    assert!(host.calls.is_empty());
                    assert_eq!(retained.request_state(), Some("opaque"));
                }
            }
        });
    }

    #[test]
    fn malformed_sampling_presence_in_a_later_sibling_prevents_all_host_callbacks() {
        with_cx(|cx, _, _| {
            let first = plain_descriptor();
            let mut invalid = vec![json!({"method":"sampling/createMessage","params":[]})];
            for field in ["tools", "toolChoice", "includeContext"] {
                let mut later = first.clone();
                later["params"][field] = Value::Null;
                invalid.push(later);
            }
            for choice in [json!([]), json!(["auto"]), json!({"mode":null})] {
                let mut later = first.clone();
                later["params"]["toolChoice"] = choice;
                invalid.push(later);
            }
            for later in invalid {
                let raw = format!(r#"{{"first":{first},"later":{later}}}"#);
                let mut host = Host::new(vec![], vec![]);
                let result = complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                    &all(), challenge(Some(&raw), None), RequestId::Number(72),
                    SamplingInputLimits::default(), &mut host));
                assert_eq!(result.err(), Some(SamplingInputError::InvalidInput));
                assert!(host.requests.is_empty());
                assert_eq!(host.approvals, 0);
                assert!(host.calls.is_empty());
            }
        });
    }

    #[test]
    fn advisory_context_is_omitted_without_a_grant_and_preserved_with_one() {
        with_cx(|cx, _, _| {
            for hint in [None, Some("none"), Some("thisServer"), Some("allServers")] {
                let mut descriptor = plain_descriptor();
                if let Some(hint) = hint { descriptor["params"]["includeContext"] = json!(hint); }
                let raw = json!({"input":descriptor.clone()}).to_string();
                for (capabilities, context_advertised) in [
                    (json!({"sampling":{}}), false),
                    (json!({"sampling":{"unknown":{"context":{}}}}), false),
                    (json!({"sampling":{"context":{}}}), true),
                ] {
                    let original = original(capabilities);
                    let before = original.encode_params().unwrap();
                    let input = challenge(Some(&raw), Some("  opaque\0  "));
                    let retained = input.clone();
                    let mut host = Host::new(vec![final_response()], vec![]);
                    let reply = complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                        &original, input, RequestId::Number(73), SamplingInputLimits::default(), &mut host)).unwrap();
                    reply.input_responses.unwrap().validate_against_input_required(&retained).unwrap();
                    let ignored = !context_advertised && hint.is_some_and(|hint| hint != "none");
                    let expected = if ignored { None } else { hint.map(|hint| json!(hint)) };
                    assert_eq!(host.requests.len(), 1);
                    assert_eq!(host.requests[0].get("includeContext"), expected.as_ref());
                    assert_eq!(host.requests[0]["messages"], descriptor["params"]["messages"]);
                    assert_eq!(host.approvals, 0);
                    assert!(host.calls.is_empty());
                    let retained_descriptor = exact_json_to_serde(
                        retained.input_requests().unwrap().get("input").unwrap()).unwrap();
                    assert_eq!(retained_descriptor, descriptor);
                    assert_eq!(retained.request_state(), Some("  opaque\0  "));
                    assert_eq!(original.encode_params().unwrap(), before);
                }
            }
        });
    }

    #[test]
    fn continuation_request_cannot_replace_the_original_admission_context() {
        with_cx(|cx, _, _| {
            let mut params = all().encode_params().unwrap().unwrap();
            params["requestState"] = json!("already-a-continuation");
            let continuation = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap();
            let raw = json!({"input":plain_descriptor()}).to_string();
            let mut host = Host::new(vec![], vec![]);
            assert_eq!(complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                &continuation, challenge(Some(&raw), None), RequestId::Number(74),
                SamplingInputLimits::default(), &mut host)).err(), Some(SamplingInputError::InvalidRequest));
            assert!(host.requests.is_empty());
            assert_eq!(host.approvals, 0);
            assert!(host.calls.is_empty());
            assert_eq!(continuation.encode_params().unwrap().unwrap(), params);
        });
    }

    #[test]
    fn global_model_budget_stops_a_tool_batch_that_cannot_have_its_results_consumed() {
        with_cx(|cx, _, _| {
            let mut host = Host::new(vec![response(call("a")), final_response(), response(call("b"))],
                vec![answer("a")]);
            let error = complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                &all(), challenge(Some(&two_inputs()), None), RequestId::Number(58),
                limits(SamplingRunLimits::default(), 3, 8), &mut host)).err().unwrap();
            assert_eq!(error, SamplingInputError::ModelRoundLimit);
            assert_eq!(host.requests.len(), 3);
            assert_eq!(host.approvals, 1);
            assert_eq!(host.calls, ["a"]);
        });
    }

    #[test]
    fn tool_budget_is_shared_across_input_keys_and_refuses_the_whole_later_batch() {
        with_cx(|cx, _, _| {
            let mut host = Host::new(vec![response(call("a")), final_response(),
                response(json!([call("b"), call("c")]))], vec![answer("a")]);
            let error = complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                &all(), challenge(Some(&two_inputs()), None), RequestId::Number(59),
                limits(SamplingRunLimits::default(), 8, 2), &mut host)).err().unwrap();
            assert_eq!(error, SamplingInputError::ToolCallLimit);
            assert_eq!(host.approvals, 1);
            assert_eq!(host.calls, ["a"]);
        });
    }

    #[test]
    fn tool_result_byte_budget_is_not_reset_by_the_next_input_key() {
        with_cx(|cx, _, _| {
            let size = serde_json::to_vec(&answer("a")).unwrap().len();
            let run = SamplingRunLimits::new(SamplingToolLoopLimits::default(),
                Duration::from_secs(1), size * 2 - 1).unwrap();
            let mut host = Host::new(vec![response(call("a")), final_response(), response(call("b"))],
                vec![answer("a"), answer("b")]);
            let error = complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                &all(), challenge(Some(&two_inputs()), None), RequestId::Number(60), limits(run, 8, 8), &mut host)).err().unwrap();
            assert_eq!(error, SamplingInputError::ToolResultByteLimit);
            assert_eq!(host.requests.len(), 3);
            assert_eq!(host.calls, ["a", "b"]);
        });
    }

    #[test]
    fn input_count_and_encoded_input_bytes_are_checked_before_host_work() {
        with_cx(|cx, _, _| {
            let raw = two_inputs();
            for (maximum, succeeds) in [(raw.len(), true), (raw.len() - 1, false)] {
                let limits = SamplingInputLimits::new(SamplingRunLimits::default(), 2, 2, 0,
                    maximum, 4096).unwrap();
                let mut host = Host::new(vec![final_response(), final_response()], vec![]);
                let result = complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                    &all(), challenge(Some(&raw), None), RequestId::Number(61), limits, &mut host));
                if succeeds { assert!(result.is_ok()); assert_eq!(host.requests.len(), 2); }
                else { assert_eq!(result.err(), Some(SamplingInputError::InputByteLimit)); assert!(host.requests.is_empty()); }
            }
            let limits = SamplingInputLimits::new(SamplingRunLimits::default(), 1, 2, 0, 4096, 4096).unwrap();
            let mut host = Host::new(vec![], vec![]);
            assert_eq!(complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                &all(), challenge(Some(&raw), None), RequestId::Number(62), limits, &mut host)).err(), Some(SamplingInputError::InputLimit));
            assert!(host.requests.is_empty());
        });
    }

    #[test]
    fn aggregate_reply_limit_counts_escaped_keys_and_map_framing_exactly() {
        with_cx(|cx, _, _| {
            let expected = format!(r#"{{"z/first~\n":{},"a-second":{}}}"#,
                serde_json::to_string(&final_response()).unwrap(), serde_json::to_string(&final_response()).unwrap());
            for (maximum, succeeds) in [(expected.len(), true), (expected.len() - 1, false)] {
                let limits = SamplingInputLimits::new(SamplingRunLimits::default(), 2, 2, 0, 4096, maximum).unwrap();
                let mut host = Host::new(vec![final_response(), final_response()], vec![]);
                let result = complete(resolve_sampling_inputs(&cx, &McpRequestCancellation::new(),
                    &all(), challenge(Some(&two_inputs()), None), RequestId::Number(63), limits, &mut host));
                if succeeds { assert_eq!(serde_json::to_string(&result.unwrap().input_responses.unwrap()).unwrap(), expected); }
                else { assert_eq!(result.err(), Some(SamplingInputError::ReplyByteLimit)); }
                assert_eq!(host.requests.len(), 2);
            }
        });
    }

    #[test]
    fn second_input_cannot_reset_the_whole_challenge_deadline() {
        with_cx(|cx, clock, timer| {
            let mut host = Host::new(vec![final_response(), final_response()], vec![]);
            host.after_first_model = Some((clock.clone(), 3_000_000));
            host.pending_model_index = Some(2);
            let cancellation = McpRequestCancellation::new();
            let original = all();
            let run = SamplingRunLimits::new(SamplingToolLoopLimits::default(), Duration::from_millis(5), 4096).unwrap();
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(counter.clone());
            let mut task = Context::from_waker(&waker);
            let mut future = Box::pin(resolve_sampling_inputs(&cx, &cancellation,
                &original, challenge(Some(&two_inputs()), None), RequestId::Number(64), limits(run, 8, 8), &mut host));
            assert!(future.as_mut().poll(&mut task).is_pending());
            assert_eq!(cx.now().as_nanos(), 3_000_000);
            clock.advance(2_000_000);
            assert!(timer.process_timers() > 0);
            assert!(counter.0.load(Ordering::SeqCst) > 0);
            let Poll::Ready(result) = future.as_mut().poll(&mut task) else { panic!("batch deadline reset") };
            assert_eq!(result.err(), Some(SamplingInputError::Run(SamplingRunError::TimedOut)));
            drop(future);
            assert_eq!(host.requests.len(), 2);
            assert_eq!(host.polls.load(Ordering::SeqCst), 1);
            assert_eq!(host.drops.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
        });
    }

    #[test]
    fn cancellation_on_a_later_sibling_discards_the_complete_partial_reply() {
        with_cx(|cx, _, timer| {
            let mut host = Host::new(vec![final_response(), final_response()], vec![]);
            host.pending_model_index = Some(2);
            let cancellation = McpRequestCancellation::new();
            let original = all();
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(counter.clone());
            let mut task = Context::from_waker(&waker);
            let mut future = Box::pin(resolve_sampling_inputs(&cx, &cancellation,
                &original, challenge(Some(&two_inputs()), None), RequestId::Number(65), SamplingInputLimits::default(), &mut host));
            assert!(future.as_mut().poll(&mut task).is_pending());
            cancellation.cancel();
            assert!(counter.0.load(Ordering::SeqCst) > 0);
            let Poll::Ready(result) = future.as_mut().poll(&mut task) else { panic!("batch cancellation stuck") };
            assert_eq!(result.err(), Some(SamplingInputError::Run(SamplingRunError::Cancelled)));
            drop(future);
            assert_eq!(host.requests.len(), 2);
            assert_eq!(host.drops.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
        });
    }
}
