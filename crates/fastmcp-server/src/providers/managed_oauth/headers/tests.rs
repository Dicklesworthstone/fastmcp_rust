//! Unit coverage of catalog review and backend selection. Native OAuth/TLS
//! dispatch is covered separately; the recording backend is not live evidence.
use super::*;
use super::super::{build_tools, core_request, ToolHandler};
use fastmcp_client::http_auth::rpc::ManagedCoreError;
use fastmcp_client::http_executor::ModernHttpRequest;
use fastmcp_client::http_executor::parameter_headers::ToolHeaderDispatchError;
use fastmcp_core::{McpErrorCode, block_on};
use fastmcp_protocol::FINAL_PROTOCOL_VERSION;
use fastmcp_protocol::http_headers::decode_mcp_header_value;
use serde_json::{Value, json};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

const TARGET: &str = "https://upstream.example/mcp?tenant=one";

struct Recorded {
    id: RequestId,
    params: Value,
    headers: Vec<(String, String)>,
}

struct Backend {
    seen: Arc<Mutex<Vec<Recorded>>>,
    reviewed: Option<Arc<ReviewedToolHeaders>>,
}

impl CoreBackend for Backend {
    fn with_reviewed_headers(&self, reviewed: Arc<ReviewedToolHeaders>) -> McpResult<Arc<dyn CoreBackend>> {
        admit_resource(&resource(), &reviewed)?;
        Ok(Arc::new(Self { seen: Arc::clone(&self.seen), reviewed: Some(reviewed) }))
    }

    fn execute<'a>(
        &'a self, _: &'a McpContext, _: &'a Cx, request: CoreRequest,
        id: RequestId, _: ManagedCoreLimits,
    ) -> BoxFuture<'a, McpResult<FinalCoreResult>> {
        Box::pin(async move {
            let params = request.encode_params().unwrap().unwrap();
            let body = serde_json::to_vec(&json!({
                "jsonrpc":"2.0", "id":id, "method":request.method(), "params":params
            })).unwrap();
            let wire = ModernHttpRequest::new(TARGET, body, FINAL_PROTOCOL_VERSION,
                request.method(), params["name"].as_str().map(str::to_owned)).unwrap();
            let wire = match &self.reviewed {
                Some(reviewed) => wire.with_reviewed_tool_headers(reviewed)
                    .map_err(|_| McpError::invalid_params(HEADER_FAILURE))?,
                None => wire,
            };
            self.seen.lock().unwrap().push(Recorded { id, params, headers: wire.headers() });
            let result = request.decode_result(r#"{"resultType":"complete","content":[],"structuredContent":{"total":2},"x-exact":1.20e+4}"#).unwrap();
            let CoreResult::Final(result) = result else { unreachable!() };
            Ok(result)
        })
    }
}

fn resource() -> CanonicalHttpUrl { CanonicalHttpUrl::parse(TARGET).unwrap() }

fn definition(name: &str) -> FinalTool {
    serde_json::from_value(json!({
        "name":name, "title":"Upstream title", "_meta":{"com.example/source":7},
        "inputSchema":{"type":"object", "properties":{
            "count":{"type":"integer", "x-mcp-header":"Count"},
            "options":{"type":"object", "properties":{
                "a/b~.0":{"type":"string", "x-mcp-header":"Region"}
            }},
            "private":{"type":"string"}
        }}
    })).unwrap()
}

fn fixture() -> (Arc<Forwarder>, Arc<Mutex<Vec<Recorded>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let forwarder = Arc::new(Forwarder {
        backend: Arc::new(Backend { seen: Arc::clone(&seen), reviewed: None }),
        next_id: Arc::new(AtomicU64::new(1)), limits: ManagedCoreLimits::default(),
    });
    (forwarder, seen)
}

#[test]
fn reviews_original_upstream_identity_but_keeps_namespaced_catalog_unchanged() {
    let (forwarder, seen) = fixture();
    let cx = Cx::for_testing();
    let tools = build_tools(Arc::clone(&forwarder), vec![definition("lookup")], Some("remote")).unwrap();
    let before = serde_json::to_value(tools[0].catalog_definition()).unwrap();
    let mut visited = Vec::new();
    let tools = review_tools(&cx, &resource(), tools, |tool, binding| {
        assert_eq!(serde_json::to_value(tool).unwrap(), serde_json::to_value(definition("lookup")).unwrap());
        visited.push((binding.header_name().to_owned(), binding.property_path().to_vec()));
        true
    }).unwrap();
    assert_eq!(visited, vec![
        ("Mcp-Param-Count".to_owned(), vec!["count".to_owned()]),
        ("Mcp-Param-Region".to_owned(), vec!["options".to_owned(), "a/b~.0".to_owned()]),
    ]);
    assert_eq!(serde_json::to_value(tools[0].catalog_definition()).unwrap(), before);
    assert!(Arc::ptr_eq(&tools[0].forwarder.next_id, &forwarder.next_id));
    assert!(tools[0].upstream_final_tool_schema_registration().is_some());
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn reviewed_handler_retains_arguments_and_projects_only_approved_paths() {
    let (forwarder, seen) = fixture();
    let cx = Cx::for_testing();
    let tools = build_tools(forwarder, vec![definition("lookup")], Some("remote")).unwrap();
    let tools = review_tools(&cx, &resource(), tools, |_, _| true).unwrap();
    let arguments = json!({"count":2,"options":{"a/b~.0":"雪\r\n"},"private":"private-canary",
        "_meta":{"authorization":"body-only-canary"}});
    let ctx = McpContext::new(cx.clone(), 1);
    let result = block_on(tools[0].call_final_async_in_request(&ctx, &cx, arguments.clone())).unwrap();
    assert_eq!(result.payload.structured_content, Some(json!({"total":2})));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].params["name"], "lookup");
    assert_eq!(seen[0].params["arguments"], arguments);
    let fields = &seen[0].headers;
    assert!(fields.iter().any(|(name, value)| name == "Mcp-Name" && value == "lookup"));
    assert!(fields.iter().any(|(name, value)| name == "Mcp-Param-Count" && value == "2"));
    let region = &fields.iter().find(|(name, _)| name == "Mcp-Param-Region").unwrap().1;
    assert_eq!(decode_mcp_header_value(region.as_bytes()).unwrap(), "雪\r\n");
    assert!(!fields.iter().any(|(_, value)| value.contains("canary")));
}

#[test]
fn review_does_not_reconfigure_ordinary_handlers_or_split_the_id_allocator() {
    let (forwarder, seen) = fixture();
    let cx = Cx::for_testing();
    let ordinary = build_tools(Arc::clone(&forwarder), vec![definition("lookup")], None).unwrap();
    let selected = build_tools(Arc::clone(&forwarder), vec![definition("lookup")], None).unwrap();
    let reviewed = review_tools(&cx, &resource(), selected, |_, _| true).unwrap();
    let ctx = McpContext::new(cx.clone(), 1);
    block_on(ordinary[0].call_final_async(&ctx, json!({"count":2}))).unwrap();
    block_on(reviewed[0].call_final_async(&ctx, json!({"count":2}))).unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(!seen[0].headers.iter().any(|(name, _)| name.starts_with("Mcp-Param-")));
    assert!(seen[1].headers.iter().any(|(name, _)| name == "Mcp-Param-Count"));
    assert!(!seen[0].id.correlates_with(&seen[1].id));
    assert_eq!(forwarder.next_id.load(Ordering::Relaxed), 3);
}

#[test]
fn disclosure_refusal_returns_no_partial_handlers_or_network_work() {
    let (forwarder, seen) = fixture();
    let cx = Cx::for_testing();
    let tools = build_tools(Arc::clone(&forwarder), vec![definition("one"), definition("two")], None).unwrap();
    let mut visits = 0;
    let outcome = review_tools(&cx, &resource(), tools, |tool, _| { visits += 1; tool.name != "two" });
    assert!(outcome.is_err());
    assert_eq!(visits, 3);
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(forwarder.next_id.load(Ordering::Relaxed), 1);
    // The same provider remains body-only and can obtain a separately reviewed set.
    let fresh = build_tools(forwarder, vec![definition("two")], None).unwrap();
    assert!(review_tools(&cx, &resource(), fresh, |_, _| true).is_ok());
}

#[test]
fn malformed_annotation_rejects_before_its_first_callback() {
    let (forwarder, _) = fixture();
    let mut invalid = definition("private-name-canary");
    invalid.input_schema["properties"]["count"]["x-mcp-header"] = json!("Invalid\r\nName");
    let tools = build_tools(forwarder, vec![invalid], None).unwrap();
    let mut visits = 0;
    let error = review_tools(&Cx::for_testing(), &resource(), tools, |_, _| { visits += 1; true }).err().unwrap();
    assert_eq!(visits, 0);
    assert!(!error.to_string().contains("private-name-canary"));
}

#[test]
fn empty_projection_still_installs_an_explicit_plan_without_callbacks() {
    let (forwarder, seen) = fixture();
    let mut definition = definition("lookup");
    definition.input_schema = json!({"type":"object"});
    let tools = build_tools(forwarder, vec![definition], None).unwrap();
    let cx = Cx::for_testing();
    let tools = review_tools(&cx, &resource(), tools, |_, _| panic!("no annotated bindings")).unwrap();
    let ctx = McpContext::new(cx.clone(), 1);
    block_on(tools[0].call_final_async(&ctx, json!({"count":2}))).unwrap();
    assert!(!seen.lock().unwrap()[0].headers.iter().any(|(name, _)| name.starts_with("Mcp-Param-")));
}

#[test]
fn a_backend_without_header_support_cannot_silently_replace_the_selected_policy() {
    struct Unsupported;
    impl CoreBackend for Unsupported {
        fn execute<'a>(&'a self, _: &'a McpContext, _: &'a Cx, _: CoreRequest,
            _: RequestId, _: ManagedCoreLimits) -> BoxFuture<'a, McpResult<FinalCoreResult>> {
            panic!("review must fail before execution")
        }
    }
    let forwarder = Arc::new(Forwarder {
        backend: Arc::new(Unsupported), next_id: Arc::new(AtomicU64::new(1)), limits: ManagedCoreLimits::default(),
    });
    let tools = build_tools(forwarder, vec![definition("lookup")], None).unwrap();
    assert!(review_tools(&Cx::for_testing(), &resource(), tools, |_, _| true).is_err());
}

#[test]
fn header_type_refusal_does_not_reach_the_recorded_dispatch() {
    let (forwarder, seen) = fixture();
    let cx = Cx::for_testing();
    let tools = build_tools(forwarder, vec![definition("lookup")], None).unwrap();
    let tools = review_tools(&cx, &resource(), tools, |_, _| true).unwrap();
    let ctx = McpContext::new(cx.clone(), 1);
    assert!(block_on(tools[0].call_final_async(&ctx, json!({"count":"private-type-canary"}))).is_err());
    assert!(seen.lock().unwrap().is_empty());
    block_on(tools[0].call_final_async(&ctx, json!({"count":2}))).unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn endpoint_binding_includes_path_query_and_authority() {
    let reviewed = ReviewedToolHeaders::new(resource(), "lookup", definition("lookup").input_schema, |_| true).unwrap();
    admit_resource(&resource(), &reviewed).unwrap();
    for target in ["https://upstream.example/other?tenant=one", "https://upstream.example/mcp?tenant=two", "https://other.example/mcp?tenant=one"] {
        assert!(admit_resource(&CanonicalHttpUrl::parse(target).unwrap(), &reviewed).is_err());
    }
}

#[test]
fn header_errors_are_redacted_but_transport_cancellation_is_preserved() {
    for error in [ToolHeaderDispatchError::DisclosureDenied, ToolHeaderDispatchError::TargetMismatch, ToolHeaderDispatchError::InvalidRequest] {
        assert_eq!(header_error(ManagedToolHeaderError::Headers(error)).code, McpErrorCode::InvalidParams);
    }
    assert_eq!(header_error(ManagedToolHeaderError::Core(ManagedCoreError::Cancelled)).code, McpErrorCode::RequestCancelled);
    // The prepared request remains the normal modern request shape.
    assert!(core_request("tools/call", json!({"name":"lookup","arguments":{"count":2}}), None).is_ok());
}
