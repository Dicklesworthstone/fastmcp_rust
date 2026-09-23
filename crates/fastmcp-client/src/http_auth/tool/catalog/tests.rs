use super::*;
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, FinalTool};
use serde_json::{Value, json};

fn tool(name: &str) -> FinalTool {
    FinalTool {
        name: name.to_owned(), title: None, description: None, icons: None,
        input_schema: json!({"type":"object","properties":{
            "count":{"type":"integer","minimum":1,"x-mcp-header":"Count"}
        },"required":["count"],"additionalProperties":false}),
        output_schema: None, annotations: None, meta: None,
    }
}

fn request(method: &str, mut params: Value) -> CoreRequest {
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}

fn page(tools: Vec<FinalTool>) -> CoreResult {
    request("tools/list", json!({})).decode_result(&json!({
        "resultType":"complete","tools":tools,"ttlMs":0,"cacheScope":"private"
    }).to_string()).unwrap()
}

fn limits(tools: usize, bytes: usize) -> ManagedToolCatalogLimits {
    ManagedToolCatalogLimits::new(ManagedCatalogLimits::default(), ManagedCatalogWatchLimits::default(), tools, bytes).unwrap()
}

#[test]
fn all_pages_become_one_schema_checked_case_sensitive_catalog() {
    let pages = [page(vec![tool("alpha")]), page(vec![tool("Alpha"), tool("beta")])];
    let before: Vec<_> = pages.iter().map(|page| page.encode().unwrap()).collect();
    let (contracts, invalidated) = admit_contracts(&pages, ManagedToolCatalogLimits::default()).unwrap();
    assert_eq!(contracts.len(), 3);
    assert!(!invalidated.load(Ordering::Acquire));
    for (name, contract) in &contracts {
        contract.validate_request(&request("tools/call", json!({"name":name,"arguments":{"count":2}}))).unwrap();
        assert!(matches!(contract.validate_request(&request("tools/call", json!({"name":name,"arguments":{"count":0}}))),
            Err(ManagedToolError::InvalidArguments)));
        assert_eq!(contract.input.schema(), &tool(name).input_schema);
    }
    assert_eq!(pages.iter().map(|page| page.encode().unwrap()).collect::<Vec<_>>(), before);
}

#[test]
fn duplicate_names_across_pages_refuse_the_entire_catalog() {
    let error = admit_contracts(&[page(vec![tool("duplicate-canary")]), page(vec![tool("duplicate-canary")])],
        ManagedToolCatalogLimits::default()).err().unwrap();
    assert!(matches!(error, ManagedToolCatalogError::DuplicateTool));
    assert!(!format!("{error:?} {error}").contains("duplicate-canary"));
}

#[test]
fn one_invalid_definition_does_not_publish_valid_siblings() {
    let mut invalid = tool("bad");
    invalid.input_schema["unknownValidationKeyword"] = json!(true);
    assert!(matches!(admit_contracts(&[page(vec![tool("good"), invalid])], ManagedToolCatalogLimits::default()),
        Err(ManagedToolCatalogError::Tool(ManagedToolError::InvalidInputSchema))));
}

#[test]
fn catalog_count_and_definition_byte_bounds_are_exact() {
    let tools = vec![tool("alpha"), tool("beta")];
    let bytes = tools.iter().map(|tool| serde_json::to_vec(tool).unwrap().len()).sum();
    let pages = [page(tools)];
    assert!(admit_contracts(&pages, limits(2, bytes)).is_ok());
    assert!(matches!(admit_contracts(&pages, limits(1, bytes)), Err(ManagedToolCatalogError::ToolLimit)));
    assert!(matches!(admit_contracts(&pages, limits(2, bytes - 1)), Err(ManagedToolCatalogError::DefinitionBudget)));
}

#[test]
fn definition_byte_overflow_does_not_advance_the_counter() {
    let mut bytes = DefinitionBytes { used: 2, maximum: 3 };
    assert_eq!(bytes.write(b"a").unwrap(), 1);
    assert!(bytes.write(b"b").is_err());
    assert_eq!(bytes.used, 3);
}

#[test]
fn a_complete_empty_catalog_is_valid_but_no_page_or_foreign_pages_are_not() {
    let (contracts, _) = admit_contracts(&[page(vec![])], ManagedToolCatalogLimits::default()).unwrap();
    assert!(contracts.is_empty());
    assert!(matches!(admit_contracts(&[], ManagedToolCatalogLimits::default()), Err(ManagedToolCatalogError::InvalidSnapshot)));
    let foreign = request("prompts/list", json!({})).decode_result(
        r#"{"resultType":"complete","prompts":[],"ttlMs":0,"cacheScope":"private"}"#,
    ).unwrap();
    assert!(matches!(admit_contracts(&[foreign], ManagedToolCatalogLimits::default()), Err(ManagedToolCatalogError::InvalidSnapshot)));
}

#[test]
fn observed_change_atomically_retires_every_contract_before_delivery() {
    let (contracts, invalidated) = admit_contracts(&[page(vec![tool("alpha"), tool("beta")])],
        ManagedToolCatalogLimits::default()).unwrap();
    let mut active = ActiveCatalog::default();
    active.install(Arc::clone(&invalidated));
    active.observe_notification(&ServerNotification::PromptsListChanged(None));
    assert!(contracts.values().all(|contract| contract.check().is_ok()));
    active.observe_notification(&ServerNotification::ToolsListChanged(None));
    assert!(invalidated.load(Ordering::Acquire));
    for contract in contracts.values() {
        assert!(matches!(contract.check(), Err(ManagedToolError::Invalidated)));
        assert!(matches!(contract.validate_request(&request("tools/call", json!({"name":contract.name.as_str(),"arguments":{"count":2}}))),
            Err(ManagedToolError::Invalidated)));
        let result = request("tools/call", json!({"name":contract.name.as_str()})).decode_result(
            r#"{"resultType":"complete","content":[]}"#,
        ).unwrap();
        assert!(matches!(contract.validate_result(&result), Err(ManagedToolError::Invalidated)));
    }
}

#[test]
fn individual_invalidation_does_not_retire_sibling_tools() {
    let (contracts, invalidated) = admit_contracts(&[page(vec![tool("alpha"), tool("beta")])],
        ManagedToolCatalogLimits::default()).unwrap();
    contracts["alpha"].invalidated.store(true, Ordering::Release);
    assert!(contracts["alpha"].is_invalidated());
    assert!(!contracts["beta"].is_invalidated());
    assert!(!invalidated.load(Ordering::Acquire));
    invalidated.store(true, Ordering::Release);
    assert!(contracts["beta"].is_invalidated());
}

#[test]
fn replacement_and_guard_drop_retire_snapshots_irreversibly() {
    let (_, first) = admit_contracts(&[page(vec![tool("alpha")])], ManagedToolCatalogLimits::default()).unwrap();
    let (_, second) = admit_contracts(&[page(vec![tool("alpha")])], ManagedToolCatalogLimits::default()).unwrap();
    let mut active = ActiveCatalog::default();
    active.install(Arc::clone(&first));
    active.install(Arc::clone(&second));
    assert!(first.load(Ordering::Acquire));
    assert!(!second.load(Ordering::Acquire));
    drop(active);
    assert!(second.load(Ordering::Acquire));
    assert!(first.load(Ordering::Acquire));
}

#[test]
fn failed_replacement_cannot_restore_the_previous_snapshot() {
    let (_, first) = admit_contracts(&[page(vec![tool("alpha")])], ManagedToolCatalogLimits::default()).unwrap();
    let mut active = ActiveCatalog::default();
    active.install(Arc::clone(&first));
    active.invalidate();
    let mut invalid = tool("alpha");
    invalid.input_schema["properties"]["count"]["x-mcp-header"] = json!("Invalid\r\nHeader");
    assert!(admit_contracts(&[page(vec![invalid])], ManagedToolCatalogLimits::default()).is_err());
    assert!(first.load(Ordering::Acquire));
    assert!(active.0.is_none());
}

#[test]
fn watch_binding_limits_have_hard_nonzero_bounds() {
    for (tools, bytes) in [(0, 1), (1025, 1), (1, 0), (1, 1 + 8 * 1024 * 1024)] {
        assert!(matches!(ManagedToolCatalogLimits::new(ManagedCatalogLimits::default(), ManagedCatalogWatchLimits::default(), tools, bytes),
            Err(ManagedToolCatalogError::InvalidLimits)));
    }
    assert!(ManagedToolCatalogLimits::new(ManagedCatalogLimits::default(), ManagedCatalogWatchLimits::default(), 1024, 8 * 1024 * 1024).is_ok());
}
