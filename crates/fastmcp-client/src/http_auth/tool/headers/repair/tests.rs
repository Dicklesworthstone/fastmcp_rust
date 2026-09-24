use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::{ClientCapabilities, CoreResult, FinalRequestMeta};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use serde_json::{Value, json};
use crate::http_auth::rpc::ManagedCoreError;
use crate::http_executor::parameter_headers::ReviewedToolHeaders;

fn definition(field: &str) -> FinalTool {
    serde_json::from_value(json!({"name":"calculate", "inputSchema":{
        "type":"object", "properties":{"count":{"type":"integer","minimum":1,"x-mcp-header":field}},
        "required":["count"],"additionalProperties":false
    }, "outputSchema":{"type":"object","properties":{"total":{"type":"integer"}},"required":["total"]}})).unwrap()
}
fn annotated_definition() -> FinalTool {
    let mut tool = definition("Fresh");
    // Unknown keyword values are opaque annotation data under the default
    // dialect. These members must not become validation or header authority.
    let annotation = json!({
        "minimum":"annotation-private-canary",
        "$ref":"https://unresolved.example/schema",
        "x-mcp-header":"Ignored"
    });
    tool.input_schema["unrecognizedValidationKeyword"] = annotation.clone();
    tool.output_schema.as_mut().unwrap()["unrecognizedValidationKeyword"] = annotation;
    tool
}
fn source() -> ToolContract { ToolContract::admit(definition("Old")).unwrap() }
fn request(count: Value) -> CoreRequest {
    CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&json!({
        "name":"calculate","arguments":{"count":count},
        "_meta":FinalRequestMeta::new(ClientCapabilities::default())
    }))).unwrap()
}
fn result(raw: &str) -> CoreResult { request(json!(2)).decode_result(raw).unwrap() }
fn review() -> ReviewedToolHeaders {
    ReviewedToolHeaders::new(CanonicalHttpUrl::parse("https://tools.example/mcp").unwrap(),
        "calculate", definition("Fresh").input_schema, |_| true).unwrap()
}

#[test]
fn replacement_is_admitted_before_approval_and_does_not_mutate_the_old_contract_or_request() {
    let cx = Cx::for_testing();
    let cancel = McpRequestCancellation::new();
    let source = source();
    let original = request(json!(2));
    let before = original.encode_params().unwrap();
    let fresh = definition("Fresh");
    let mut calls = 0;
    let replacement = approve_definition(&cx, &cancel, &source, &original, &fresh, |tool| {
        calls += 1;
        assert_eq!(tool.input_schema, fresh.input_schema);
        true
    }).unwrap().unwrap();
    assert_eq!(calls, 1);
    assert_eq!(replacement.input.schema(), &fresh.input_schema);
    assert_eq!(source.input.schema(), &definition("Old").input_schema);
    assert_eq!(original.encode_params().unwrap(), before);
    source.check().unwrap();
}

#[test]
fn a_new_input_constraint_refuses_the_immutable_invocation_before_host_approval() {
    let cx = Cx::for_testing();
    let cancel = McpRequestCancellation::new();
    let source = source();
    let mut fresh = definition("Fresh");
    fresh.input_schema["properties"]["count"]["minimum"] = json!(10);
    let mut called = false;
    assert!(matches!(approve_definition(&cx, &cancel, &source, &request(json!(2)), &fresh,
        |_| { called = true; true }), Err(ManagedToolError::InvalidArguments)));
    assert!(!called);
    assert!(approve_definition(&cx, &cancel, &source, &request(json!(10)), &fresh, |_| true).unwrap().is_some());
}

#[test]
fn opaque_input_and_output_annotations_survive_repair_without_bypassing_constraints() {
    let cx = Cx::for_testing();
    let cancel = McpRequestCancellation::new();
    let source = source();
    let original = request(json!(2));
    let before = original.encode_params().unwrap();
    let fresh = annotated_definition();
    let mut calls = 0;
    let replacement = approve_definition(&cx, &cancel, &source, &original, &fresh, |tool| {
        calls += 1;
        assert_eq!(tool.input_schema, fresh.input_schema);
        assert_eq!(tool.output_schema, fresh.output_schema);
        true
    }).unwrap().unwrap();
    assert_eq!(calls, 1);
    assert_eq!(replacement.input.schema(), &fresh.input_schema);
    assert_eq!(replacement.output.as_ref().unwrap().schema(), fresh.output_schema.as_ref().unwrap());
    replacement.validate_request(&original).unwrap();
    assert!(matches!(replacement.validate_request(&request(json!(0))),
        Err(ManagedToolError::InvalidArguments)));
    replacement.validate_result(&result(r#"{"resultType":"complete","content":[],"structuredContent":{"total":2}}"#)).unwrap();
    assert!(matches!(replacement.validate_result(&result(r#"{"resultType":"complete","content":[],"structuredContent":{"total":"2"}}"#)),
        Err(ManagedToolError::InvalidStructuredOutput)));
    let resource = CanonicalHttpUrl::parse("https://tools.example/mcp").unwrap();
    let mut disclosures = 0;
    let reviewed = replacement.review_headers(&resource, |_| { disclosures += 1; true }).unwrap();
    assert_eq!(disclosures, 1);
    assert_eq!(reviewed.bindings(), review().bindings());
    assert_eq!(source.input.schema(), &definition("Old").input_schema);
    assert_eq!(original.encode_params().unwrap(), before);
    source.check().unwrap();
}

// SCH-01 admits schemas as Draft 2020-12, where an unknown keyword is an
// annotation. Malformed means a real assertion with an invalid value. Both
// roles carry the unknown keyword, so a pair differs only in `minimum`.
fn with_minimum(minimum: Value) -> [FinalTool; 2] {
    let mut input = definition("Fresh");
    input.input_schema["properties"]["count"]["minimum"] = minimum.clone();
    input.input_schema["unrecognizedValidationKeyword"] = json!(true);
    let mut output = definition("Fresh");
    output.output_schema = Some(json!({"type":"object","unrecognizedValidationKeyword":true,
        "properties":{"total":{"type":"integer","minimum":minimum}}}));
    [input, output]
}

#[test]
fn malformed_input_output_and_wrong_identity_never_reach_approval() {
    let cx = Cx::for_testing();
    let cancel = McpRequestCancellation::new();
    let source = source();
    let [input, output] = with_minimum(json!("not-a-number"));
    let mut named = definition("Fresh");
    named.name = "foreign-private-canary".to_owned();
    let mut calls = 0;
    for (fresh, role) in [(input, "input"), (output, "output"), (named, "identity")] {
        let error = approve_definition(&cx, &cancel, &source, &request(json!(2)), &fresh,
            |_| { calls += 1; true }).err().unwrap();
        assert!(match role {
            "input" => matches!(error, ManagedToolError::InvalidInputSchema),
            "output" => matches!(error, ManagedToolError::InvalidOutputSchema),
            _ => matches!(error, ManagedToolError::RequestMismatch),
        }, "{role}: {error:?}");
        assert!(!format!("{error:?} {error}").contains("private-canary"));
    }
    assert_eq!(calls, 0);
    source.check().unwrap();
}

#[test]
fn unknown_keyword_annotations_reach_approval_with_their_constraints() {
    let cx = Cx::for_testing();
    let cancel = McpRequestCancellation::new();
    let source = source();
    let [input, output] = with_minimum(json!(1));
    // eb5160e3's former "malformed" input and output fixtures, verbatim.
    let mut former_input = definition("Fresh");
    former_input.input_schema["unrecognizedValidationKeyword"] = json!(true);
    let mut former_output = definition("Fresh");
    former_output.output_schema = Some(json!({"type":"object","unrecognizedValidationKeyword":true}));
    let mut calls = 0;
    for fresh in [input, output, former_input, former_output] {
        let replacement = approve_definition(&cx, &cancel, &source, &request(json!(2)), &fresh,
            |_| { calls += 1; true }).unwrap().unwrap();
        assert_eq!(replacement.input.schema(), &fresh.input_schema);
        assert!(matches!(approve_definition(&cx, &cancel, &source, &request(json!(0)), &fresh, |_| true),
            Err(ManagedToolError::InvalidArguments)));
    }
    assert_eq!(calls, 4);
    source.check().unwrap();
}

#[test]
fn replacement_output_not_old_output_governs_successful_publication() {
    let cx = Cx::for_testing();
    let cancel = McpRequestCancellation::new();
    let source = source();
    let mut fresh = definition("Fresh");
    fresh.output_schema = Some(json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}));
    let replacement = approve_definition(&cx, &cancel, &source, &request(json!(2)), &fresh, |_| true).unwrap().unwrap();
    let correct = result(r#"{"resultType":"complete","content":[],"structuredContent":{"text":"ok"},"x-exact":1.20e+4}"#);
    let before = correct.encode().unwrap();
    replacement.validate_result(&correct).unwrap();
    assert_eq!(correct.encode().unwrap(), before);
    assert!(source.validate_result(&correct).is_err());
    assert!(matches!(replacement.validate_result(&result(r#"{"resultType":"complete","content":[]}"#)),
        Err(ManagedToolError::MissingStructuredOutput)));
    assert!(matches!(replacement.validate_result(&result(r#"{"resultType":"complete","content":[],"structuredContent":{"total":2}}"#)),
        Err(ManagedToolError::InvalidStructuredOutput)));
    for raw in [r#"{"resultType":"input_required","requestState":"opaque"}"#,
        r#"{"resultType":"complete","content":[],"isError":true}"#] {
        replacement.validate_result(&result(raw)).unwrap();
    }
}

#[test]
fn declining_replacement_does_not_retire_or_rewrite_the_original_contract() {
    let cx = Cx::for_testing();
    let cancel = McpRequestCancellation::new();
    let source = source();
    assert!(approve_definition(&cx, &cancel, &source, &request(json!(2)), &definition("Fresh"), |_| false).unwrap().is_none());
    source.validate_request(&request(json!(2))).unwrap();
    assert_eq!(source.input.schema(), &definition("Old").input_schema);
    assert!(!cancel.is_cancel_requested());
}

#[test]
fn retired_tool_and_catalog_contracts_enter_no_host_callback() {
    let cx = Cx::for_testing();
    let cancel = McpRequestCancellation::new();
    let review = review();
    for catalog in [false, true] {
        let mut source = source();
        if catalog { source.catalog_invalidated = Some(Arc::new(AtomicBool::new(true))); }
        else { source.invalidate(); }
        let mut calls = 0;
        assert!(matches!(approve_definition(&cx, &cancel, &source, &request(json!(2)), &definition("Fresh"),
            |_| { calls += 1; true }), Err(ManagedToolError::Invalidated)));
        assert!(matches!(supply_id(&cx, &cancel, &source, &mut || { calls += 1; Ok(RequestId::Number(12)) }),
            Err(ManagedCatalogError::AbortedByHost)));
        assert!(!review_binding(&cx, &cancel, &source, &mut |_| { calls += 1; true }, &review.bindings()[0]));
        assert_eq!(calls, 0);
    }
}

#[test]
fn definition_callback_invalidation_cannot_publish_a_replacement_contract() {
    let cx = Cx::for_testing();
    let cancel = McpRequestCancellation::new();
    for catalog in [false, true] {
        let mut source = source();
        let flag = Arc::new(AtomicBool::new(false));
        if catalog { source.catalog_invalidated = Some(Arc::clone(&flag)); }
        let outcome = approve_definition(&cx, &cancel, &source, &request(json!(2)), &definition("Fresh"), |_| {
            if catalog { flag.store(true, Ordering::Release); } else { source.invalidate(); }
            true
        });
        assert!(matches!(outcome, Err(ManagedToolError::Invalidated)));
        assert!(!cancel.is_cancel_requested());
    }
}

#[test]
fn id_and_disclosure_callbacks_cannot_return_usable_values_after_invalidation() {
    let cx = Cx::for_testing();
    let cancel = McpRequestCancellation::new();
    let first = source();
    assert!(matches!(supply_id(&cx, &cancel, &first, &mut || {
        first.invalidate(); Ok(RequestId::Number(12))
    }), Err(ManagedCatalogError::AbortedByHost)));
    let second = source();
    let review = review();
    assert!(!review_binding(&cx, &cancel, &second, &mut |_| { second.invalidate(); true }, &review.bindings()[0]));
    assert!(!cancel.is_cancel_requested());
    assert!(cx.checkpoint().is_ok());
}

#[test]
fn callback_cancellation_is_distinct_from_invalidation_and_leaves_the_contract_usable() {
    let cx = Cx::for_testing();
    let cancel = McpRequestCancellation::new();
    let source = source();
    assert!(matches!(approve_definition(&cx, &cancel, &source, &request(json!(2)), &definition("Fresh"), |_| {
        cancel.cancel(); true
    }), Err(ManagedToolError::Core(ManagedCoreError::Cancelled))));
    source.check().unwrap();
    assert!(cx.checkpoint().is_ok());
}

#[test]
fn schema_repair_diagnostics_never_embed_definition_or_invocation_values() {
    let cx = Cx::for_testing();
    let cancel = McpRequestCancellation::new();
    let source = source();
    let error = approve_definition(&cx, &cancel, &source, &request(json!("sensitive-value-canary")),
        &definition("Fresh"), |_| panic!("invalid input must be refused first")).err().unwrap();
    let error = ManagedToolRepairError::from(error);
    assert!(!format!("{error:?} {error}").contains("sensitive-value-canary"));
}
