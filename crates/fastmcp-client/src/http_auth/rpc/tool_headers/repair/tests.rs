use super::*;
use serde_json::Value;
use std::cell::Cell;
use std::time::Duration;

const TARGET: &str = "https://tools.example/mcp?tenant=one";

fn resource() -> CanonicalHttpUrl { CanonicalHttpUrl::parse(TARGET).unwrap() }

fn request(method: &str, mut params: Value) -> CoreRequest {
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}

fn tool(name: &str, header: &str) -> FinalTool {
    serde_json::from_value(json!({"name":name,"inputSchema":{"type":"object","properties":{
        "region":{"type":"string","x-mcp-header":header},
        "count":{"type":"integer","x-mcp-header":"Count"}
    }}})).unwrap()
}

fn page(tools: Vec<FinalTool>) -> CoreResult {
    request("tools/list", json!({})).decode_result(&json!({
        "resultType":"complete","tools":tools,"ttlMs":0,"cacheScope":"private"
    }).to_string()).unwrap()
}

fn rejection(id: i64, code: i64) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"error":{
        "code":code,"message":"private-peer-canary","data":{"secret":"private-data-canary"}
    }})).unwrap()
}

fn limits() -> ToolHeaderRepairLimits {
    ToolHeaderRepairLimits::new(
        ManagedCoreLimits::new(4096, 4096, 65536, 4, Duration::from_secs(10)).unwrap(),
        16384, 4, 16,
    ).unwrap()
}

#[test]
fn only_the_exact_http_error_representation_can_enter_repair_admission() {
    let json = Some(ModernHttpErrorBodyAdmission::JsonRpcError);
    assert!(admit_rejection_head(400, json).is_ok());
    for (status, kind) in [(200, json), (401, json), (403, json), (500, json),
        (400, None), (400, Some(ModernHttpErrorBodyAdmission::Opaque))]
    {
        assert!(matches!(admit_rejection_head(status, kind), Err(ManagedCoreError::HttpStatus { .. })));
    }
}

#[test]
fn complete_correlated_header_rejection_is_admitted_without_retaining_private_data() {
    let frame = rejection(17, -32020);
    let before = frame.clone();
    assert!(admit_rejection_body(&frame, &RequestId::Number(17), frame.len()).is_ok());
    assert_eq!(frame, before);
    assert!(matches!(admit_rejection_body(&frame, &RequestId::Number(18), frame.len()),
        Err(ManagedCoreError::ResponseIdMismatch)));
    let other = rejection(17, -32602);
    let error = admit_rejection_body(&other, &RequestId::Number(17), other.len()).err().unwrap();
    assert!(matches!(error, ManagedCoreError::Remote { .. }));
    assert!(!format!("{error:?} {error}").contains("private-"));
    assert!(admit_rejection_body(&frame, &RequestId::Number(17), frame.len() - 1).is_err());
}

#[test]
fn malformed_duplicate_batched_or_unfinished_error_frames_never_authorize_repair() {
    let valid = String::from_utf8(rejection(17, -32020)).unwrap();
    for invalid in [
        format!("[{valid}]"), format!("{valid}{valid}"), valid[..valid.len() - 1].to_owned(),
        valid.replacen("\"id\":17", "\"id\":17,\"id\":17", 1),
        valid.replacen("\"code\":-32020", "\"code\":-32020,\"code\":-32020", 1),
        valid.replacen("\"id\":17", "\"id\":null", 1),
        r#"{"jsonrpc":"2.0","id":17,"result":{"resultType":"complete","content":[]}}"#.to_owned(),
        r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#.to_owned(),
        r#"{"jsonrpc":"2.0","id":17,"error":{"code":-32020,"message":"x"},"result":{}}"#.to_owned(),
    ] {
        assert!(admit_rejection_body(invalid.as_bytes(), &RequestId::Number(17), 4096).is_err());
    }
}

#[test]
fn repair_configuration_is_https_and_exact_endpoint_bound() {
    let contract = ToolHeaderRepairContract::for_configured_endpoint(resource()).unwrap();
    assert!(contract.admit_endpoint(&CanonicalHttpUrl::parse("https://TOOLS.EXAMPLE:443/mcp?tenant=one").unwrap()).is_ok());
    for target in ["https://other.example/mcp?tenant=one", "https://tools.example/mcp?tenant=two", "https://tools.example/other?tenant=one"] {
        assert!(matches!(contract.admit_endpoint(&CanonicalHttpUrl::parse(target).unwrap()), Err(ToolHeaderRepairError::EndpointMismatch)));
    }
    for target in ["http://localhost/mcp", "https://user@tools.example/mcp", "https://tools.example/mcp#fragment"] {
        assert!(matches!(ToolHeaderRepairContract::for_configured_endpoint(CanonicalHttpUrl::parse(target).unwrap()),
            Err(ToolHeaderRepairError::InvalidContract)));
    }
    assert!(!format!("{contract:?}").contains("tenant"));
}

#[test]
fn continuation_or_foreign_method_cannot_enter_the_initial_retry_path() {
    assert!(admit_initial(&request("tools/call", json!({"name":"lookup"}))).is_ok());
    for request in [
        request("tools/list", json!({})),
        request("prompts/get", json!({"name":"lookup"})),
        request("tools/call", json!({"name":"lookup","requestState":""})),
        request("tools/call", json!({"name":"lookup","inputResponses":{}})),
    ] {
        assert!(matches!(admit_initial(&request), Err(ToolHeaderRepairError::InitialToolCallRequired)));
    }
}

#[test]
fn full_catalog_selection_checks_later_pages_and_duplicate_siblings() {
    let selected = select_tool(vec![page(vec![tool("other", "Region")]), page(vec![tool("lookup", "Fresh")])], "lookup", 2).unwrap();
    assert_eq!(selected.input_schema, tool("lookup", "Fresh").input_schema);
    assert!(matches!(select_tool(vec![page(vec![tool("Lookup", "Region")])], "lookup", 1), Err(ToolHeaderRepairError::ToolUnavailable)));
    assert!(matches!(select_tool(vec![page(vec![])], "lookup", 1), Err(ToolHeaderRepairError::ToolUnavailable)));
    for duplicate in ["lookup", "other"] {
        assert!(matches!(select_tool(vec![page(vec![tool("lookup", "Region"), tool("other", "Region")]),
            page(vec![tool(duplicate, "Fresh")])], "lookup", 3), Err(ToolHeaderRepairError::DuplicateTool)));
    }
    assert!(matches!(select_tool(vec![page(vec![tool("lookup", "Region"), tool("other", "Region")])], "lookup", 1),
        Err(ToolHeaderRepairError::Catalog(ManagedCatalogError::ItemLimit))));
}

#[test]
fn one_id_ledger_spans_rejection_catalog_pages_and_retry_without_mutating_on_refusal() {
    let mut ledger = IdLedger::default();
    for id in [RequestId::Number(1), RequestId::Number(2), RequestId::String("3".to_owned())] { ledger.reserve(&id).unwrap(); }
    let before = (ledger.ids.clone(), ledger.bytes);
    for id in &before.0 {
        assert!(matches!(ledger.reserve(id), Err(ManagedCatalogError::RepeatedRequestId)));
        assert_eq!((ledger.ids.clone(), ledger.bytes), before);
    }
    // The string "3" is not the numeric correlation identity 3.
    ledger.reserve(&RequestId::Number(3)).unwrap();
    for id in 4..=(MAX_REPAIR_PAGES + 1) { ledger.reserve(&RequestId::Number(id as i64)).unwrap(); }
    let before = (ledger.ids.clone(), ledger.bytes);
    assert!(matches!(ledger.reserve(&RequestId::Number(1000)), Err(ManagedCatalogError::StateLimit)));
    assert_eq!((ledger.ids, ledger.bytes), before);
}

#[test]
fn id_byte_accounting_and_response_reservations_have_exact_bounds() {
    let mut bytes = IdBytes(MAX_REPAIR_ID_BYTES - 1);
    assert_eq!(bytes.write(b"a").unwrap(), 1);
    assert!(bytes.write(b"b").is_err());
    assert_eq!(bytes.0, MAX_REPAIR_ID_BYTES);
    let limits = limits();
    assert_eq!(limits.retry_charge(117).unwrap(), limits.catalog_bytes + 117);
    assert!(matches!(limits.retry_charge(limits.core.total_bytes), Err(ManagedCoreError::ResponseByteLimit)));
    let exact = ManagedCoreLimits::new(4096, 4096, 12288, 0, Duration::from_secs(1)).unwrap();
    assert!(ToolHeaderRepairLimits::new(exact, 4096, 1, 1).is_ok());
    assert!(ToolHeaderRepairLimits::new(exact, 4097, 1, 1).is_err());
    for (bytes, pages, tools) in [(0, 1, 1), (1, 0, 1), (1, 65, 1), (1, 1, 0), (1, 1, MAX_REPAIR_TOOLS + 1)] {
        assert!(matches!(ToolHeaderRepairLimits::new(limits.core, bytes, pages, tools), Err(ToolHeaderRepairError::InvalidLimits)));
    }
}

#[test]
fn definition_and_each_disclosure_need_new_approval_and_do_not_modify_the_source() {
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let definition = tool("lookup", "Fresh");
    let before = serde_json::to_value(&definition).unwrap();
    let mut fields = Vec::new();
    let reviewed = approve_replacement(&cx, &cancellation, Time::from_nanos(u64::MAX), &resource(), &definition,
        |received| received.input_schema == before["inputSchema"],
        &mut |binding: &ParameterHeaderBinding| { fields.push(binding.header_name().to_owned()); true },
    ).unwrap();
    assert_eq!(fields, ["Mcp-Param-Count", "Mcp-Param-Fresh"]);
    assert_eq!(reviewed.schema(), &definition.input_schema);
    assert_eq!(serde_json::to_value(&definition).unwrap(), before);
    let callbacks = Cell::new(0);
    assert!(matches!(approve_replacement(&cx, &cancellation, Time::from_nanos(u64::MAX), &resource(), &definition,
        |_| false, &mut |_: &ParameterHeaderBinding| { callbacks.set(callbacks.get() + 1); true }),
        Err(ToolHeaderRepairError::DefinitionDeclined)));
    assert_eq!(callbacks.get(), 0);
    assert!(matches!(approve_replacement(&cx, &cancellation, Time::from_nanos(u64::MAX), &resource(), &definition,
        |_| true, &mut |_: &ParameterHeaderBinding| { callbacks.set(callbacks.get() + 1); false }),
        Err(ToolHeaderRepairError::Headers(ToolHeaderDispatchError::DisclosureDenied))));
    assert_eq!(callbacks.get(), 1);
}

#[test]
fn cancellation_during_definition_or_header_review_stops_all_later_host_work() {
    let cx = Cx::for_testing();
    for cancel_definition in [false, true] {
        let cancellation = McpRequestCancellation::new();
        let callbacks = Cell::new(0);
        let outcome = approve_replacement(&cx, &cancellation, Time::from_nanos(u64::MAX), &resource(), &tool("lookup", "Fresh"),
            |_| { if cancel_definition { cancellation.cancel(); } true },
            &mut |_: &ParameterHeaderBinding| { callbacks.set(callbacks.get() + 1); cancellation.cancel(); true });
        assert!(matches!(outcome, Err(ToolHeaderRepairError::Core(ManagedCoreError::Cancelled))));
        assert_eq!(callbacks.get(), usize::from(!cancel_definition));
        assert!(cx.checkpoint().is_ok());
    }
    let cancellation = McpRequestCancellation::new();
    cancellation.cancel();
    assert!(matches!(approve_replacement(&cx, &cancellation, Time::from_nanos(u64::MAX), &resource(), &tool("lookup", "Fresh"),
        |_| panic!("pre-cancelled review must not run"), &mut |_: &ParameterHeaderBinding| panic!("no header callback")),
        Err(ToolHeaderRepairError::Core(ManagedCoreError::Cancelled))));
}

#[test]
fn refreshed_header_projection_changes_only_mirrors_and_rpc_identity_not_parameters() {
    let original = request("tools/call", json!({"name":"lookup","arguments":{"region":"雪","count":null,"private":"body-only"}}));
    let before = original.encode_params().unwrap().unwrap();
    let old = ReviewedToolHeaders::new(resource(), "lookup", tool("lookup", "Old").input_schema, |_| true).unwrap();
    let fresh = ReviewedToolHeaders::new(resource(), "lookup", tool("lookup", "Fresh").input_schema, |_| true).unwrap();
    let (first, _) = prepare_optional(TARGET, original.clone(), RequestId::Number(1), limits().core, Some(&old)).unwrap();
    let (second, _) = prepare_optional(TARGET, original.clone(), RequestId::Number(4), limits().core, Some(&fresh)).unwrap();
    let first_body: Value = serde_json::from_slice(first.body()).unwrap();
    let second_body: Value = serde_json::from_slice(second.body()).unwrap();
    assert_ne!(first_body["id"], second_body["id"]);
    assert_eq!(first_body["params"], before);
    assert_eq!(second_body["params"], before);
    assert_eq!(original.encode_params().unwrap().unwrap(), before);
    let fields = second.headers();
    assert!(!fields.iter().any(|(name, _)| name == "Mcp-Param-Old" || name == "Mcp-Param-Count"));
    let (_, value) = fields.iter().find(|(name, _)| name == "Mcp-Param-Fresh").unwrap();
    assert_eq!(fastmcp_protocol::http_headers::decode_mcp_header_value(value.as_bytes()).unwrap(), "雪");
    assert!(!fields.iter().any(|(_, value)| value.contains("body-only")));
}
