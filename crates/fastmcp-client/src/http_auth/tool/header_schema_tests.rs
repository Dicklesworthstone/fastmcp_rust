//! Regression coverage for annotation-aware contracts without disclosure.

use super::*;
use fastmcp_protocol::http_headers::{MAX_MCP_HEADER_VALUE_BYTES, MAX_PARAMETER_HEADER_INTEGER};
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
use serde_json::json;

fn schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "count": {"type": "integer", "minimum": 1, "x-mcp-header": "Count"},
            "region": {"type": "string", "x-mcp-header": "Region"},
            "payload": {"type": "object", "default": {"x-mcp-header": "literal-data"}}
        },
        "required": ["count"],
        "additionalProperties": false
    })
}

fn definition(input_schema: Value, output_schema: Option<Value>) -> FinalTool {
    FinalTool {
        name: "calculate".to_owned(),
        title: None,
        description: None,
        icons: None,
        input_schema,
        output_schema,
        annotations: None,
        meta: None,
    }
}

fn request(mut params: Value) -> CoreRequest {
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap()
}

fn result(raw: &str) -> CoreResult {
    request(json!({"name": "calculate", "arguments": {"count": 2}}))
        .decode_result(raw).unwrap()
}

#[test]
fn annotated_contract_retains_source_and_exact_invocation() {
    let source = schema();
    let contract = ToolContract::admit(definition(source.clone(), None)).unwrap();
    let request = request(json!({
        "name": "calculate",
        "arguments": {"count": 2, "region": "eu", "payload": {"x-mcp-header": "body-only"}},
        "requestState": " opaque continuation "
    }));
    let before = request.encode_params().unwrap();
    contract.validate_request(&request).unwrap();
    assert_eq!(contract.input.schema(), &source);
    assert_eq!(request.encode_params().unwrap(), before);
    assert_eq!(contract.input.header_plan().bindings().len(), 2);
    assert_eq!(source["properties"]["payload"]["default"]["x-mcp-header"], "literal-data");
}

#[test]
fn annotations_do_not_weaken_required_type_or_range_validation() {
    let contract = ToolContract::admit(definition(schema(), None)).unwrap();
    for arguments in [
        json!({}),
        json!({"count": 0}),
        json!({"count": "2"}),
        json!({"count": null}),
        json!({"count": 2, "region": false}),
        json!({"count": 2, "extra": true}),
    ] {
        let request = request(json!({"name": "calculate", "arguments": arguments}));
        assert!(matches!(contract.validate_request(&request), Err(ManagedToolError::InvalidArguments)));
    }
    assert!(matches!(contract.validate_request(&request(json!({"name": "calculate"}))),
        Err(ManagedToolError::InvalidArguments)));
}

#[test]
fn annotation_admission_does_not_apply_header_representation_limits_to_body_values() {
    let contract = ToolContract::admit(definition(schema(), None)).unwrap();
    for region in [
        "x".repeat(MAX_MCP_HEADER_VALUE_BYTES + 1),
        "雪\r\nPrivate: value\0".to_owned(),
        "=?base64?YWJj?=".to_owned(),
    ] {
        let request = request(json!({"name": "calculate", "arguments": {
            "count": MAX_PARAMETER_HEADER_INTEGER + 1,
            "region": region
        }}));
        let before = request.encode_params().unwrap();
        contract.validate_request(&request).unwrap();
        assert_eq!(request.encode_params().unwrap(), before);
    }
}

#[test]
fn unknown_schema_annotations_preserve_contracts_without_header_authority() {
    let mut source = schema();
    source["x-ui"] = json!({
        "$id": "https://annotations.example/data",
        "$ref": "https://unregistered.example/schema",
        "type": 42,
        "properties": {"hidden": {"x-mcp-header": "Invalid\r\nHeader"}}
    });
    source["properties"]["count"]["x-unit"] = json!("items");
    let contract = ToolContract::admit(definition(source.clone(), None)).unwrap();
    assert_eq!(contract.input.schema(), &source);
    assert_eq!(contract.input.header_plan().bindings().len(), 2);

    let accepted = request(json!({"name": "calculate", "arguments": {"count": 2}}));
    let before = accepted.encode_params().unwrap();
    contract.validate_request(&accepted).unwrap();
    assert_eq!(accepted.encode_params().unwrap(), before);
    for arguments in [json!({"count": 0}), json!({"count": "2"}), json!({})] {
        let rejected = request(json!({"name": "calculate", "arguments": arguments}));
        assert!(matches!(contract.validate_request(&rejected), Err(ManagedToolError::InvalidArguments)));
    }
}

#[test]
fn malformed_annotations_and_recognized_validation_keywords_still_fail_closed() {
    let mut malformed = schema();
    malformed["properties"]["count"]["minimum"] = json!("not-a-number");
    for source in [
        malformed,
        json!({"type": "object", "properties": {"x": {"type": "object", "x-mcp-header": "X"}}}),
        json!({"type": "object", "properties": {"x": {"type": "string", "x-mcp-header": "X\r\nBad"}}}),
        json!({"type": "object", "properties": {
            "x": {"type": "string", "x-mcp-header": "Same"},
            "y": {"type": "string", "x-mcp-header": "same"}
        }}),
        json!({"type": "object", "$defs": {"hidden": {"type": "string", "x-mcp-header": "Hidden"}}}),
    ] {
        assert!(matches!(ToolContract::admit(definition(source, None)), Err(ManagedToolError::InvalidInputSchema)));
    }
}

#[test]
fn annotated_input_does_not_relax_output_schema_or_lossless_result_validation() {
    let output = json!({"type": "object", "properties": {"total": {"type": "integer"}}, "required": ["total"]});
    let contract = ToolContract::admit(definition(schema(), Some(output))).unwrap();
    let valid = result(r#"{"resultType":"complete","content":[],"structuredContent":{"total":2},"x-exact":1.20e+4}"#);
    let before = valid.encode().unwrap();
    contract.validate_result(&valid).unwrap();
    assert_eq!(valid.encode().unwrap(), before);
    assert!(matches!(contract.validate_result(&result(r#"{"resultType":"complete","content":[]}"#)),
        Err(ManagedToolError::MissingStructuredOutput)));
    assert!(matches!(contract.validate_result(&result(r#"{"resultType":"complete","content":[],"structuredContent":{"total":"wrong"}}"#)),
        Err(ManagedToolError::InvalidStructuredOutput)));
    for raw in [
        r#"{"resultType":"input_required","requestState":"opaque"}"#,
        r#"{"resultType":"complete","content":[],"isError":true}"#,
    ] {
        let result = result(raw);
        let before = result.encode().unwrap();
        contract.validate_result(&result).unwrap();
        assert_eq!(result.encode().unwrap(), before);
    }
}

#[test]
fn annotated_source_is_charged_to_the_existing_combined_schema_budget() {
    let mut properties = serde_json::Map::new();
    for index in 0..100 {
        properties.insert(format!("field{index}"), json!({"type": "string", "description": "d".repeat(3072)}));
    }
    let output = json!({"type": "object", "properties": properties});
    let mut input = output.clone();
    input["properties"]["field0"]["x-mcp-header"] = json!("Field");
    assert!(ToolContract::admit(definition(input.clone(), None)).is_ok());
    assert!(matches!(ToolContract::admit(definition(input, Some(output))), Err(ManagedToolError::SchemaTooLarge)));
}

#[test]
fn annotated_contract_invalidation_is_shared_and_diagnostics_remain_redacted() {
    let contract = Arc::new(ToolContract::admit(definition(schema(), None)).unwrap());
    let clone = Arc::clone(&contract);
    let invalid = request(json!({"name": "calculate", "arguments": {"count": "private-canary"}}));
    let error = contract.validate_request(&invalid).err().unwrap();
    assert!(!format!("{error:?} {error}").contains("private-canary"));
    contract.invalidated.store(true, Ordering::Release);
    let valid = request(json!({"name": "calculate", "arguments": {"count": 2}}));
    assert!(matches!(clone.validate_request(&valid), Err(ManagedToolError::Invalidated)));
    assert!(matches!(clone.validate_result(&result(r#"{"resultType":"complete","content":[]}"#)),
        Err(ManagedToolError::Invalidated)));
}
