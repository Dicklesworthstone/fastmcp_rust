use super::*;

#[test]
fn name_sentinel_encoding_does_not_change_legacy_request_headers() {
    let name = "=?base64?YWJj?=";
    for version in ["2024-11-05", "2025-06-18"] {
        let request = ModernHttpRequest::new(
            "https://tools.example/mcp", b"{}".to_vec(), version,
            "tools/call", Some(name.to_owned()),
        ).unwrap();
        let fields = request.headers();
        assert_eq!(fields.iter().find(|(field, _)| field == "Mcp-Name").unwrap().1, name);
        assert!(!fields.iter().any(|(field, _)| field.starts_with("Mcp-Param-")));
    }
    let request = ModernHttpRequest::new(
        "https://tools.example/mcp", b"{}".to_vec(), FINAL_PROTOCOL_VERSION,
        "tools/call", Some(name.to_owned()),
    ).unwrap();
    let fields = request.headers();
    assert_eq!(fields.iter().find(|(field, _)| field == "Mcp-Name").unwrap().1,
        fastmcp_protocol::http_headers::encode_mcp_header_value(name).unwrap());
    assert_eq!(request.body(), b"{}");
}

use crate::http_auth::BoundBearerCredential;
use fastmcp_protocol::http_headers::{
    MAX_PARAMETER_HEADER_INTEGER, ParameterHeaderType, decode_mcp_header_value,
};
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
use serde_json::json;

const TARGET: &str = "https://tools.example/mcp";

fn schema() -> Value {
    json!({"type":"object", "properties":{
        "region":{"type":"string","x-mcp-header":"Region"},
        "count":{"type":"integer","x-mcp-header":"Count"},
        "verbose":{"type":"boolean","x-mcp-header":"Verbose"},
        "options":{"type":"object","properties":{
            "a/b~.0":{"type":"string","x-mcp-header":"Nested"}
        }}
    }})
}

fn plan() -> ReviewedToolHeaders {
    ReviewedToolHeaders::new(CanonicalHttpUrl::parse(TARGET).unwrap(), "lookup", schema(), |_| true).unwrap()
}

fn body(arguments: Option<Value>) -> Vec<u8> {
    let mut params = json!({
        "name":"lookup", "_meta":FinalRequestMeta::new(ClientCapabilities::default()),
    });
    if let Some(arguments) = arguments { params["arguments"] = arguments; }
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":17,"method":"tools/call","params":params})).unwrap()
}

fn wire(target: &str, body: Vec<u8>) -> ModernHttpRequest {
    ModernHttpRequest::new(target, body, FINAL_PROTOCOL_VERSION, "tools/call", Some("lookup".to_owned())).unwrap()
}

fn parameters(request: &ModernHttpRequest) -> Vec<(String, String)> {
    let mut fields: Vec<_> = request.headers().into_iter()
        .filter(|(name, _)| name.starts_with("Mcp-Param-")).collect();
    fields.sort();
    fields
}

#[test]
fn native_projection_uses_exact_paths_and_leaves_the_actual_body_unchanged() {
    let review = plan();
    let before = body(Some(json!({"region":"eu", "count":2, "verbose":false,
        "options":{"a/b~.0":"nested"}, "private":"body-only-canary"})));
    let before = [b" \n".as_slice(), before.as_slice(), b"\n ".as_slice()].concat();
    let request = wire(TARGET, before.clone()).with_reviewed_tool_headers(&review).unwrap();
    assert_eq!(request.body(), before);
    assert_eq!(parameters(&request), vec![
        ("Mcp-Param-Count".to_owned(), "2".to_owned()),
        ("Mcp-Param-Nested".to_owned(), "nested".to_owned()),
        ("Mcp-Param-Region".to_owned(), "eu".to_owned()),
        ("Mcp-Param-Verbose".to_owned(), "false".to_owned()),
    ]);
    assert_eq!(review.schema(), &schema());
    assert!(!format!("{request:?} {review:?}").contains("body-only-canary"));
    assert!(!request.headers().iter().any(|(_, value)| value.contains("body-only-canary")));
}

#[test]
fn review_is_explicit_and_partial_approval_does_not_install_a_plan() {
    let mut visited = Vec::new();
    let result = ReviewedToolHeaders::new(CanonicalHttpUrl::parse(TARGET).unwrap(), "lookup", schema(), |binding| {
        visited.push((binding.property_path().to_vec(), binding.parameter_type()));
        binding.header_name() != "Mcp-Param-Region"
    });
    assert!(matches!(result, Err(ToolHeaderDispatchError::DisclosureDenied)));
    assert!(!visited.is_empty());
    assert!(visited.iter().any(|(path, kind)| path == &["region".to_owned()] && *kind == ParameterHeaderType::String));
    assert!(parameters(&wire(TARGET, body(Some(json!({"region":"eu"}))))).is_empty());
}

#[test]
fn malformed_schema_is_rejected_before_any_review_callback() {
    for source in [
        json!({"type":"string"}),
        json!({"type":"object","properties":{"x":{"type":"object","x-mcp-header":"X"}}}),
        json!({"type":"object","properties":{
            "x":{"type":"string","x-mcp-header":"Same"},
            "y":{"type":"string","x-mcp-header":"same"}
        }}),
        json!({"type":"object","properties":{"x":{"type":"string","x-mcp-header":"X\r\nBad"}}}),
    ] {
        let mut calls = 0;
        assert!(ReviewedToolHeaders::new(CanonicalHttpUrl::parse(TARGET).unwrap(), "lookup", source, |_| {
            calls += 1;
            true
        }).is_err());
        assert_eq!(calls, 0);
    }
}

#[test]
fn approved_values_with_unicode_controls_or_sentinels_remain_one_safe_field() {
    for value in ["雪", " a ", "\t", "a\r\nInjected: yes", "\0", "=?base64?YWJj?=", "=?base64?="] {
        let request = wire(TARGET, body(Some(json!({"region":value}))))
            .with_reviewed_tool_headers(&plan()).unwrap();
        let fields = parameters(&request);
        assert_eq!(fields.len(), 1);
        assert!(!fields[0].1.contains(['\r', '\n', '\0']));
        assert_eq!(decode_mcp_header_value(fields[0].1.as_bytes()).unwrap(), value);
    }
}

#[test]
fn null_and_absent_fields_are_omitted_without_rewriting_arguments() {
    for arguments in [None, Some(json!({})), Some(json!({"region":null,"options":null}))] {
        let before = body(arguments);
        let request = wire(TARGET, before.clone()).with_reviewed_tool_headers(&plan()).unwrap();
        assert!(parameters(&request).is_empty());
        assert_eq!(request.body(), before);
        assert!(matches!(request.with_reviewed_tool_headers(&plan()), Err(ToolHeaderDispatchError::AlreadyProjected)));
    }
}

#[test]
fn one_invalid_sibling_refuses_the_complete_projection() {
    for arguments in [
        json!({"region":"valid","count":"2"}),
        json!({"region":"valid","count":MAX_PARAMETER_HEADER_INTEGER + 1}),
        json!({"region":"valid","verbose":1}),
        json!({"region":"valid","options":{"a/b~.0":42}}),
    ] {
        let original = wire(TARGET, body(Some(arguments)));
        assert!(original.clone().with_reviewed_tool_headers(&plan()).is_err());
        assert!(parameters(&original).is_empty());
    }
}

#[test]
fn binding_refuses_cleartext_userinfo_fragments_and_hostile_tool_names() {
    for target in ["http://tools.example/mcp", "http://localhost/mcp", "https://user@tools.example/mcp", "https://tools.example/mcp#"] {
        assert!(matches!(ReviewedToolHeaders::new(CanonicalHttpUrl::parse(target).unwrap(), "lookup", schema(), |_| true),
            Err(ToolHeaderDispatchError::InvalidBinding)));
    }
    for name in ["", "bad\r\nname"] {
        assert!(matches!(ReviewedToolHeaders::new(CanonicalHttpUrl::parse(TARGET).unwrap(), name, schema(), |_| true),
            Err(ToolHeaderDispatchError::InvalidBinding)));
    }
}

#[test]
fn a_plan_cannot_cross_an_endpoint_path_query_authority_or_scheme() {
    let review = plan();
    for target in ["https://other.example/mcp", "https://tools.example/other", "https://tools.example/mcp?q=1", "http://tools.example/mcp"] {
        assert!(matches!(wire(target, body(None)).with_reviewed_tool_headers(&review), Err(ToolHeaderDispatchError::TargetMismatch)));
    }
    assert!(wire("https://TOOLS.EXAMPLE:443/mcp", body(None)).with_reviewed_tool_headers(&review).is_ok());
}

#[test]
fn wrong_operation_name_and_version_cannot_project() {
    let review = plan();
    for request in [
        ModernHttpRequest::new(TARGET, body(None), FINAL_PROTOCOL_VERSION, "prompts/get", Some("lookup".to_owned())).unwrap(),
        ModernHttpRequest::new(TARGET, body(None), FINAL_PROTOCOL_VERSION, "tools/call", Some("other".to_owned())).unwrap(),
        ModernHttpRequest::new(TARGET, body(None), "2024-11-05", "tools/call", Some("lookup".to_owned())).unwrap(),
    ] {
        assert!(matches!(request.with_reviewed_tool_headers(&review), Err(ToolHeaderDispatchError::OperationMismatch)));
    }
}

#[test]
fn inconsistent_raw_body_and_metadata_cannot_be_hidden_by_valid_routing_headers() {
    let original: Value = serde_json::from_slice(&body(Some(json!({"region":"eu"})))).unwrap();
    let mut variants = Vec::new();
    let mut value = original.clone();
    value["method"] = json!("prompts/get");
    variants.push(value);
    let mut value = original.clone();
    value["params"]["name"] = json!("other");
    variants.push(value);
    let mut value = original.clone();
    value["params"]["_meta"][FINAL_PROTOCOL_VERSION_META_KEY] = json!("2024-11-05");
    variants.push(value);
    let mut value = original.clone();
    value["params"].as_object_mut().unwrap().remove("_meta");
    variants.push(value);
    let mut value = original;
    value.as_object_mut().unwrap().remove("id");
    variants.push(value);
    for value in variants {
        assert!(wire(TARGET, serde_json::to_vec(&value).unwrap()).with_reviewed_tool_headers(&plan()).is_err());
    }
}

#[test]
fn raw_duplicate_members_batches_and_trailing_documents_are_rejected() {
    let valid = String::from_utf8(body(Some(json!({"region":"eu"})))).unwrap();
    let duplicate_id = valid.replacen("\"id\":17", "\"id\":17,\"id\":17", 1);
    let duplicate_argument = valid.replacen("\"region\":\"eu\"", "\"region\":\"eu\",\"region\":\"us\"", 1);
    assert_ne!(duplicate_id, valid);
    assert_ne!(duplicate_argument, valid);
    for invalid in [duplicate_id, duplicate_argument, format!("[{valid}]"), format!("{valid}{valid}")] {
        assert!(matches!(wire(TARGET, invalid.into_bytes()).with_reviewed_tool_headers(&plan()), Err(ToolHeaderDispatchError::InvalidRequest)));
    }
}

#[test]
fn source_size_is_bounded_before_decoding_or_projection() {
    let mut source = body(None);
    source.resize(MAX_TOOL_HEADER_REQUEST_BYTES, b' ');
    assert!(wire(TARGET, source.clone()).with_reviewed_tool_headers(&plan()).is_ok());
    source.push(b' ');
    assert!(matches!(wire(TARGET, source).with_reviewed_tool_headers(&plan()), Err(ToolHeaderDispatchError::RequestTooLarge)));
}

#[test]
fn fresh_credential_serialization_retains_headers_without_reusing_old_authorization() {
    let resource = CanonicalHttpUrl::parse(TARGET).unwrap();
    let old = BoundBearerCredential::bind(resource.clone(), "old-test-credential").unwrap();
    let fresh = BoundBearerCredential::bind(resource, "fresh-test-credential").unwrap();
    let request = wire(TARGET, body(Some(json!({"region":"eu"}))))
        .with_authorization(&old).with_reviewed_tool_headers(&plan()).unwrap();
    let fields = request.headers_with_credential(Some(&fresh));
    assert!(fields.iter().any(|(name, value)| name == "Mcp-Param-Region" && value == "eu"));
    assert!(fields.iter().any(|(name, value)| name == "Authorization" && value == "Bearer fresh-test-credential"));
    assert!(!fields.iter().any(|(_, value)| value.contains("old-test-credential")));
    fresh.revoke();
    let fields = request.headers_with_credential(Some(&fresh));
    assert!(!fields.iter().any(|(name, _)| name == "Authorization"));
    assert!(fields.iter().any(|(name, value)| name == "Mcp-Param-Region" && value == "eu"));
}

#[test]
fn mcp_name_encoding_preserves_logical_identity_and_keeps_wire_fields_safe() {
    for name in ["lookup", "雪", " lookup ", "=?base64?YWJj?="] {
        let mut document: Value = serde_json::from_slice(&body(None)).unwrap();
        document["params"]["name"] = json!(name);
        let source = serde_json::to_vec(&document).unwrap();
        let review = ReviewedToolHeaders::new(CanonicalHttpUrl::parse(TARGET).unwrap(), name, schema(), |_| true).unwrap();
        let request = ModernHttpRequest::new(TARGET, source.clone(), FINAL_PROTOCOL_VERSION, "tools/call", Some(name.to_owned()))
            .unwrap().with_reviewed_tool_headers(&review).unwrap();
        let headers = request.headers();
        let encoded = &headers.iter().find(|(key, _)| key == "Mcp-Name").unwrap().1;
        assert_eq!(decode_mcp_header_value(encoded.as_bytes()).unwrap(), name);
        assert_eq!(request.name.as_deref(), Some(name));
        assert_eq!(request.body(), source);
    }
}

const GATEWAY_UPSTREAM: &str = "http://127.0.0.1:9/mcp";

fn gateway_for(catalog: &[(&str, Value)]) -> GatewayToolHeaders {
    let gateway = GatewayToolHeaders::default();
    gateway.replace(catalog.iter().map(|(name, schema)| (*name, schema)));
    gateway
}

#[test]
fn gateway_recomputes_mirrors_from_the_exact_body_without_a_review_or_https() {
    let gateway = gateway_for(&[("lookup", schema())]);
    for region in ["eu-west", "us-east"] {
        let before = body(Some(json!({"region":region, "private":"body-only-canary"})));
        let request = wire(GATEWAY_UPSTREAM, before.clone()).with_gateway_tool_headers(&gateway).unwrap();
        assert_eq!(parameters(&request), vec![("Mcp-Param-Region".to_owned(), region.to_owned())]);
        assert_eq!(request.body(), before);
        assert!(!format!("{request:?} {gateway:?}").contains(region));
    }
    assert_eq!(format!("{gateway:?}"), "GatewayToolHeaders { plan_count: 1 }");
}

#[test]
fn gateway_leaves_unplanned_tools_other_methods_and_removed_plans_unprojected() {
    let arguments = json!({"region":"eu-west"});
    let unannotated = json!({"type":"object","properties":{"region":{"type":"string"}}});
    for gateway in [gateway_for(&[]), gateway_for(&[("other", schema())]), gateway_for(&[("lookup", unannotated)])] {
        let request = wire(GATEWAY_UPSTREAM, body(Some(arguments.clone()))).with_gateway_tool_headers(&gateway).unwrap();
        assert!(parameters(&request).is_empty());
        assert!(request.parameter_headers.is_none());
    }
    let gateway = gateway_for(&[("lookup", schema())]);
    let prompt = ModernHttpRequest::new(GATEWAY_UPSTREAM, body(Some(arguments.clone())), FINAL_PROTOCOL_VERSION,
        "prompts/get", Some("lookup".to_owned())).unwrap().with_gateway_tool_headers(&gateway).unwrap();
    assert!(parameters(&prompt).is_empty());
    let planned = wire(GATEWAY_UPSTREAM, body(Some(arguments.clone()))).with_gateway_tool_headers(&gateway).unwrap();
    assert_eq!(parameters(&planned).len(), 1);
    gateway.replace([("other", &schema())]);
    let removed = wire(GATEWAY_UPSTREAM, body(Some(arguments))).with_gateway_tool_headers(&gateway).unwrap();
    assert!(parameters(&removed).is_empty());
}

#[test]
fn gateway_refuses_a_projection_the_body_cannot_support_and_never_merges_a_reviewed_plan() {
    let gateway = gateway_for(&[("lookup", schema())]);
    let original = wire(GATEWAY_UPSTREAM, body(Some(json!({"region":"valid","count":"2"}))));
    assert!(matches!(original.with_gateway_tool_headers(&gateway),
        Err(ToolHeaderDispatchError::Projection(_))));
    let reviewed = wire(TARGET, body(Some(json!({"region":"eu"})))).with_reviewed_tool_headers(&plan()).unwrap();
    assert!(matches!(reviewed.with_gateway_tool_headers(&gateway), Err(ToolHeaderDispatchError::AlreadyProjected)));
}
