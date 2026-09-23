use super::*;
use crate::http_auth::rpc::interaction::{InputSelection, continuation_request_selected, input_required};
use fastmcp_protocol::{ClientCapabilities, CoreResult, FinalRequestMeta, FinalTool};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use serde_json::json;
use std::future::Future;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll, Waker};

fn contract() -> Arc<ToolContract> {
    Arc::new(ToolContract::admit(FinalTool {
        name: "calculate".to_owned(), title: None, description: None, icons: None,
        input_schema: json!({"type":"object", "properties":{"count":{"type":"integer"}},
            "required":["count"], "additionalProperties":false}),
        output_schema: Some(json!({"type":"object", "properties":{"total":{"type":"integer"}},
            "required":["total"], "additionalProperties":false})),
        annotations: None, meta: None,
    }).unwrap())
}

fn request() -> CoreRequest {
    let mut params = json!({"name":"calculate","arguments":{"count":2}});
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap()
}

fn result(raw: &str) -> CoreResult { request().decode_result(raw).unwrap() }

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("local admission must not wait for I/O"),
    }
}

#[test]
fn completion_validation_preserves_lossless_output() {
    let result = result(r#"{"resultType":"complete","content":[],"structuredContent":{"total":2},"x-exact":{"n":900719925474099312345,"d":1.20e+4}}"#);
    let before = result.encode().unwrap();
    let event = ManagedInteractionEvent::Complete(Box::new(result));
    assert!(admit_event(&contract(), &event).unwrap());
    let ManagedInteractionEvent::Complete(result) = event else { panic!("complete expected") };
    assert_eq!(result.encode().unwrap(), before);
}

#[test]
fn final_result_cannot_bypass_output_schema_after_input_rounds() {
    for raw in [
        r#"{"resultType":"complete","content":[],"structuredContent":{"total":"private-canary"}}"#,
        r#"{"resultType":"complete","content":[]}"#,
    ] {
        let event = ManagedInteractionEvent::Complete(Box::new(result(raw)));
        let error = admit_event(&contract(), &event).err().unwrap();
        assert!(matches!(&error, ManagedToolError::InvalidStructuredOutput | ManagedToolError::MissingStructuredOutput));
        assert!(!format!("{error:?} {error}").contains("private-canary"));
    }
}

#[test]
fn suspended_work_is_not_completed_or_subject_to_output_requirements() {
    let result = result(r#"{"resultType":"input_required","requestState":" unchanged state "}"#);
    let input = input_required(&result).unwrap().clone();
    let event = ManagedInteractionEvent::InputRequired(Box::new(input));
    assert!(!admit_event(&contract(), &event).unwrap());
    let ManagedInteractionEvent::InputRequired(input) = event else { panic!("input expected") };
    assert_eq!(input.request_state(), Some(" unchanged state "));
}

#[test]
fn tool_execution_errors_still_complete_without_success_output() {
    let result = result(r#"{"resultType":"complete","content":[{"type":"text","text":"tool failed"}],"isError":true}"#);
    assert!(admit_event(&contract(), &ManagedInteractionEvent::Complete(Box::new(result))).unwrap());
}

#[test]
fn invalidation_fences_both_new_host_work_and_final_publication() {
    let contract = contract();
    let shared = contract.clone();
    let input = result(r#"{"resultType":"input_required","requestState":"state"}"#);
    let input = input_required(&input).unwrap().clone();
    let complete = result(r#"{"resultType":"complete","content":[],"structuredContent":{"total":2}}"#);
    shared.invalidated.store(true, Ordering::Release);
    for event in [
        ManagedInteractionEvent::InputRequired(Box::new(input)),
        ManagedInteractionEvent::Complete(Box::new(complete)),
    ] {
        assert!(matches!(admit_event(&contract, &event), Err(ManagedToolError::Invalidated)));
    }
}

#[test]
fn retained_cancellation_fences_schema_publication_without_cancelling_siblings() {
    let cx = Cx::for_testing();
    let contract = contract();
    let cancellation = McpRequestCancellation::new();
    let sibling = McpRequestCancellation::new();
    check_tool_call(&cx, &cancellation, &contract).unwrap();
    cancellation.cancel();
    assert!(matches!(check_tool_call(&cx, &cancellation, &contract),
        Err(ManagedToolError::Core(ManagedCoreError::Cancelled))));
    check_tool_call(&cx, &sibling, &contract).unwrap();
    assert!(!sibling.is_cancel_requested());
}

#[test]
fn closed_and_successfully_completed_interactions_have_distinct_eof() {
    let cx = Cx::for_testing();
    let mut interaction = ManagedToolInteraction {
        operation: None, contract: contract(), cancellation: McpRequestCancellation::new(), finished: false,
    };
    assert!(matches!(ready(interaction.next_event(&cx)),
        Err(ManagedToolInteractionError::Tool(ManagedToolError::Closed))));
    interaction.finished = true;
    assert!(ready(interaction.next_event(&cx)).unwrap().is_none());
    interaction.close();
    assert!(ready(interaction.next_event(&cx)).unwrap().is_none());
    assert!(interaction.pending_input().is_none());
}

#[test]
fn complete_and_partial_continuations_retain_the_original_schema_bound_arguments() {
    let contract = contract();
    let original = request();
    let before = original.encode_params().unwrap().unwrap();
    let result = original.decode_result(r#"{"resultType":"input_required","inputRequests":{"one":{"method":"roots/list"},"two":{"method":"roots/list"}},"requestState":" opaque+/%\u0000 "}"#).unwrap();
    let input = input_required(&result).unwrap();
    for (selection, answers) in [
        (InputSelection::Complete, json!({"one":{"roots":[]},"two":{"roots":[]}})),
        (InputSelection::Partial, json!({"two":{"roots":[]}})),
    ] {
        let responses: FinalInputResponses = serde_json::from_value(answers.clone()).unwrap();
        let next = continuation_request_selected(&original, input, Some(responses), selection).unwrap();
        contract.validate_request(&next).unwrap();
        let mut after = next.encode_params().unwrap().unwrap();
        assert_eq!(after["arguments"], before["arguments"]);
        assert_eq!(after["inputResponses"], answers);
        assert_eq!(after["requestState"], " opaque+/%\0 ");
        after.as_object_mut().unwrap().remove("inputResponses");
        after.as_object_mut().unwrap().remove("requestState");
        assert_eq!(after, before);
    }
    assert_eq!(original.encode_params().unwrap().unwrap(), before);
}

#[test]
fn invalid_partial_answers_leave_the_current_challenge_and_contract_unchanged() {
    let contract = contract();
    let original = request();
    let result = original.decode_result(r#"{"resultType":"input_required","inputRequests":{"one":{"method":"roots/list"},"two":{"method":"roots/list"}},"requestState":"state"}"#).unwrap();
    let before = result.encode().unwrap();
    let input = input_required(&result).unwrap();
    let foreign: FinalInputResponses = serde_json::from_value(json!({"foreign":{"roots":[]}})).unwrap();
    assert!(matches!(continuation_request_selected(&original, input, Some(foreign), InputSelection::Partial),
        Err(ManagedInteractionError::InvalidInputResponses)));
    assert_eq!(result.encode().unwrap(), before);
    contract.validate_request(&original).unwrap();
    let correct: FinalInputResponses = serde_json::from_value(json!({"one":{"roots":[]}})).unwrap();
    let next = continuation_request_selected(&original, input, Some(correct), InputSelection::Partial).unwrap();
    contract.validate_request(&next).unwrap();
    assert_eq!(next.encode_params().unwrap().unwrap()["inputResponses"], json!({"one":{"roots":[]}}));
}
