use super::*;
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
use serde_json::json;

fn tool(input_schema: Value, output_schema: Option<Value>) -> FinalTool {
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

fn contract() -> ToolContract {
    ToolContract::admit(tool(
        json!({"type":"object", "properties":{"count":{"type":"integer","minimum":1}},
            "required":["count"], "additionalProperties":false}),
        Some(json!({"type":"object", "properties":{"total":{"type":"integer","minimum":1}},
            "required":["total"], "additionalProperties":false})),
    )).unwrap()
}

fn request(method: &str, mut params: Value) -> CoreRequest {
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}

fn result(raw: &str) -> CoreResult {
    request("tools/call", json!({"name":"calculate","arguments":{"count":2}}))
        .decode_result(raw).unwrap()
}

#[test]
fn admitted_arguments_preserve_the_entire_original_request() {
    let contract = contract();
    let request = request("tools/call", json!({
        "name":"calculate", "arguments":{"count":2},
        "requestState":" opaque continuation ",
    }));
    let before = request.encode_params().unwrap();
    contract.validate_request(&request).unwrap();
    assert_eq!(request.encode_params().unwrap(), before);
}

#[test]
fn wrong_method_name_and_argument_schema_are_refused() {
    let contract = contract();
    for request in [
        request("tools/list", json!({})),
        request("tools/call", json!({"name":"Calculate","arguments":{"count":1}})),
    ] {
        assert!(matches!(contract.validate_request(&request), Err(ManagedToolError::RequestMismatch)));
    }
    for arguments in [json!({}), json!({"count":0}), json!({"count":"1"}), json!({"count":1,"secret":"x"})] {
        let request = request("tools/call", json!({"name":"calculate","arguments":arguments}));
        assert!(matches!(contract.validate_request(&request), Err(ManagedToolError::InvalidArguments)));
    }
}

#[test]
fn omitted_arguments_cannot_bypass_required_properties() {
    let request = request("tools/call", json!({"name":"calculate"}));
    assert!(matches!(contract().validate_request(&request), Err(ManagedToolError::InvalidArguments)));
    let empty = ToolContract::admit(tool(json!({"type":"object"}), None)).unwrap();
    empty.validate_request(&request).unwrap();
    assert!(request.encode_params().unwrap().unwrap().get("arguments").is_none());
}

#[test]
fn rust_constructed_definitions_receive_the_same_root_shape_checks() {
    for input in [json!(true), json!({}), json!({"type":"array"}), json!({"type":["object","null"]})] {
        assert!(matches!(ToolContract::admit(tool(input, None)), Err(ManagedToolError::InvalidInputSchema)));
    }
    for output in [json!(true), json!(null), json!([])] {
        assert!(matches!(ToolContract::admit(tool(json!({"type":"object"}), Some(output))),
            Err(ManagedToolError::InvalidOutputSchema)));
    }
    let bad_dialect = json!({"type":"object","$schema":"https://json-schema.org/draft-07/schema"});
    assert!(matches!(ToolContract::admit(tool(bad_dialect.clone(), None)), Err(ManagedToolError::InvalidInputSchema)));
    assert!(matches!(ToolContract::admit(tool(json!({"type":"object"}), Some(bad_dialect))),
        Err(ManagedToolError::InvalidOutputSchema)));
}

#[test]
fn tool_name_limits_are_byte_exact_and_do_not_normalize_names() {
    for name in [String::new(), "x".repeat(MAX_MANAGED_TOOL_NAME_BYTES + 1), "bad\r\nname".to_owned(), "bad\u{7f}name".to_owned()] {
        let mut definition = tool(json!({"type":"object"}), None);
        definition.name = name;
        assert!(matches!(ToolContract::admit(definition), Err(ManagedToolError::InvalidDefinition)));
    }
    let mut definition = tool(json!({"type":"object"}), None);
    definition.name = "é".repeat(MAX_MANAGED_TOOL_NAME_BYTES / 2);
    let admitted = ToolContract::admit(definition).unwrap();
    assert_eq!(admitted.name.len(), MAX_MANAGED_TOOL_NAME_BYTES);
}

#[test]
fn both_schemas_share_one_retained_byte_budget() {
    let mut properties = serde_json::Map::new();
    for i in 0..100 {
        properties.insert(format!("field{i}"), json!({"type":"string","description":"d".repeat(3072)}));
    }
    let schema = json!({"type":"object","properties":properties});
    assert!(ToolContract::admit(tool(schema.clone(), None)).is_ok());
    assert!(matches!(ToolContract::admit(tool(schema.clone(), Some(schema))), Err(ManagedToolError::SchemaTooLarge)));
}

#[test]
fn schema_counter_refuses_the_first_excess_byte_without_advancing() {
    let mut bytes = SchemaBytes(MAX_MANAGED_TOOL_SCHEMA_BYTES - 1);
    assert_eq!(bytes.write(b"x").unwrap(), 1);
    assert_eq!(bytes.0, MAX_MANAGED_TOOL_SCHEMA_BYTES);
    assert!(bytes.write(b"y").is_err());
    assert_eq!(bytes.0, MAX_MANAGED_TOOL_SCHEMA_BYTES);
}

#[test]
fn successful_structured_results_must_match_the_output_schema() {
    let contract = contract();
    contract.validate_result(&result(r#"{"resultType":"complete","content":[],"structuredContent":{"total":2}}"#)).unwrap();
    for raw in [
        r#"{"resultType":"complete","content":[],"structuredContent":{"total":"2"}}"#,
        r#"{"resultType":"complete","content":[],"structuredContent":{"total":0}}"#,
        r#"{"resultType":"complete","content":[],"structuredContent":{"total":2,"secret":"x"}}"#,
    ] {
        assert!(matches!(contract.validate_result(&result(raw)), Err(ManagedToolError::InvalidStructuredOutput)));
    }
    assert!(matches!(contract.validate_result(&result(r#"{"resultType":"complete","content":[]}"#)),
        Err(ManagedToolError::MissingStructuredOutput)));
}

#[test]
fn absent_output_schema_does_not_invent_a_structured_output_requirement() {
    let contract = ToolContract::admit(tool(json!({"type":"object"}), None)).unwrap();
    contract.validate_result(&result(r#"{"resultType":"complete","content":[]}"#)).unwrap();
}

#[test]
fn tool_errors_and_input_required_are_not_misclassified_as_output_failures() {
    let contract = contract();
    for raw in [
        r#"{"resultType":"complete","content":[{"type":"text","text":"execution failed"}],"isError":true}"#,
        r#"{"resultType":"input_required","requestState":"opaque-state"}"#,
    ] {
        let result = result(raw);
        let before = result.encode().unwrap();
        contract.validate_result(&result).unwrap();
        assert_eq!(result.encode().unwrap(), before);
    }
}

#[test]
fn validation_preserves_exact_unknown_result_members() {
    let result = result(r#"{"resultType":"complete","content":[],"structuredContent":{"total":2},"x-exact":{"z":900719925474099312345,"a":1.20e+4}}"#);
    let before = result.encode().unwrap();
    contract().validate_result(&result).unwrap();
    assert_eq!(result.encode().unwrap(), before);
    assert!(before.contains("900719925474099312345"));
    assert!(before.contains("1.20e+4"));
}

#[test]
fn shared_invalidation_blocks_request_and_result_admission_but_not_other_contracts() {
    let original = Arc::new(contract());
    let clone = original.clone();
    let independent = contract();
    let request = request("tools/call", json!({"name":"calculate","arguments":{"count":2}}));
    original.validate_request(&request).unwrap();
    clone.invalidated.store(true, Ordering::Release);
    for contract in [&original, &clone] {
        assert!(matches!(contract.validate_request(&request), Err(ManagedToolError::Invalidated)));
        assert!(matches!(contract.validate_result(&result(r#"{"resultType":"complete","content":[],"structuredContent":{"total":2}}"#)),
            Err(ManagedToolError::Invalidated)));
    }
    independent.validate_request(&request).unwrap();
}

#[test]
fn schema_failures_do_not_disclose_peer_values_or_paths() {
    let contract = contract();
    let invalid = request("tools/call", json!({"name":"calculate","arguments":{"count":"private-canary"}}));
    let error = contract.validate_request(&invalid).err().unwrap();
    assert!(!format!("{error:?} {error}").contains("private-canary"));
    let invalid = result(r#"{"resultType":"complete","content":[],"structuredContent":{"total":"private-canary"}}"#);
    let error = contract.validate_result(&invalid).err().unwrap();
    assert!(!format!("{error:?} {error}").contains("private-canary"));
}
