use super::*;

use std::sync::atomic::{AtomicBool, Ordering};

use fastmcp_protocol::{FinalTool, CoreRequest, ClientCapabilities, FinalRequestMeta};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use serde_json::{Value, json};

fn resource() -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse("https://tools.example/mcp?tenant=one").unwrap()
}

fn definition() -> FinalTool {
    FinalTool {
        name: "calculate".to_owned(), title: None, description: None, icons: None,
        input_schema: json!({"type":"object", "properties": {
            "count":{"type":"integer","minimum":1,"x-mcp-header":"Count"},
            "options":{"type":"object","properties":{
                "a/b~.0":{"type":"string","x-mcp-header":"Region"}
            }},
            "private":{"type":"string"}
        }, "required":["count"], "additionalProperties":false}),
        output_schema: None, annotations: None, meta: None,
    }
}

fn contract() -> ToolContract { ToolContract::admit(definition()).unwrap() }

fn request(arguments: Value) -> CoreRequest {
    let params = json!({"name":"calculate", "arguments":arguments,
        "_meta":FinalRequestMeta::new(ClientCapabilities::default())});
    CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap()
}

#[test]
fn contract_supplies_the_exact_schema_resource_and_literal_paths_to_review() {
    let contract = contract();
    let mut visited = Vec::new();
    let reviewed = contract.review_headers(&resource(), |binding| {
        visited.push((binding.header_name().to_owned(), binding.property_path().to_vec()));
        true
    }).unwrap();
    assert_eq!(reviewed.resource(), &resource());
    assert_eq!(reviewed.tool_name(), "calculate");
    assert_eq!(reviewed.schema(), &definition().input_schema);
    assert_eq!(visited, vec![
        ("Mcp-Param-Count".to_owned(), vec!["count".to_owned()]),
        ("Mcp-Param-Region".to_owned(), vec!["options".to_owned(), "a/b~.0".to_owned()]),
    ]);
    contract.admit_headers(&resource(), &reviewed).unwrap();
}

#[test]
fn one_refused_binding_refuses_the_plan_without_invalidating_the_contract() {
    let contract = contract();
    let mut visits = 0;
    let outcome = contract.review_headers(&resource(), |binding| {
        visits += 1;
        binding.header_name() != "Mcp-Param-Region"
    });
    assert!(matches!(outcome, Err(ManagedToolError::Headers(ToolHeaderDispatchError::DisclosureDenied))));
    assert_eq!(visits, 2);
    assert!(!contract.is_invalidated());
    contract.validate_request(&request(json!({"count":2}))).unwrap();
    assert!(contract.review_headers(&resource(), |_| true).is_ok());
}

#[test]
fn previously_invalidated_contracts_do_not_run_review_callbacks() {
    for catalog in [false, true] {
        let mut contract = contract();
        if catalog {
            contract.catalog_invalidated = Some(Arc::new(AtomicBool::new(true)));
        } else {
            contract.invalidated.store(true, Ordering::Release);
        }
        let mut visits = 0;
        let outcome = contract.review_headers(&resource(), |_| { visits += 1; true });
        assert!(matches!(outcome, Err(ManagedToolError::Invalidated)));
        assert_eq!(visits, 0);
    }
}

#[test]
fn individual_invalidation_during_review_stops_callbacks_and_refuses_publication() {
    let contract = contract();
    let mut visits = 0;
    let outcome = contract.review_headers(&resource(), |_| {
        visits += 1;
        contract.invalidated.store(true, Ordering::Release);
        true
    });
    assert!(matches!(outcome, Err(ManagedToolError::Invalidated)));
    assert_eq!(visits, 1);
    assert!(matches!(contract.validate_request(&request(json!({"count":2}))), Err(ManagedToolError::Invalidated)));
}

#[test]
fn catalog_invalidation_during_review_cannot_be_disguised_as_disclosure_denial() {
    for approve in [false, true] {
        let flag = Arc::new(AtomicBool::new(false));
        let mut contract = contract();
        contract.catalog_invalidated = Some(Arc::clone(&flag));
        let mut visits = 0;
        let outcome = contract.review_headers(&resource(), |_| {
            visits += 1;
            flag.store(true, Ordering::Release);
            approve
        });
        assert!(matches!(outcome, Err(ManagedToolError::Invalidated)));
        assert_eq!(visits, 1);
    }
}

#[test]
fn externally_reviewed_plans_must_match_resource_name_and_complete_schema() {
    let contract = contract();
    let mut stronger = definition().input_schema;
    stronger["properties"]["count"]["minimum"] = json!(10);
    let mut description = definition().input_schema;
    description["description"] = json!("different-source-canary");
    for (target, name, schema) in [
        ("https://tools.example/mcp?tenant=two", "calculate", definition().input_schema),
        ("https://tools.example/other?tenant=one", "calculate", definition().input_schema),
        ("https://other.example/mcp?tenant=one", "calculate", definition().input_schema),
        ("https://tools.example/mcp?tenant=one", "Calculate", definition().input_schema),
        ("https://tools.example/mcp?tenant=one", "calculate", stronger),
        ("https://tools.example/mcp?tenant=one", "calculate", description),
    ] {
        let reviewed = ReviewedToolHeaders::new(CanonicalHttpUrl::parse(target).unwrap(), name, schema, |_| true).unwrap();
        let error = contract.admit_headers(&resource(), &reviewed).err().unwrap();
        assert!(matches!(error, ManagedToolError::HeaderBindingMismatch));
        assert!(!format!("{error:?} {error}").contains("different-source-canary"));
    }
}

#[test]
fn invalid_resource_is_refused_before_any_callback() {
    let contract = contract();
    let mut visits = 0;
    let outcome = contract.review_headers(&CanonicalHttpUrl::parse("http://127.0.0.1/mcp").unwrap(), |_| {
        visits += 1;
        true
    });
    assert!(matches!(outcome, Err(ManagedToolError::Headers(ToolHeaderDispatchError::InvalidBinding))));
    assert_eq!(visits, 0);
    assert!(!contract.is_invalidated());
}

#[test]
fn approval_does_not_weaken_input_validation_or_reactivate_retired_handles() {
    let flag = Arc::new(AtomicBool::new(false));
    let mut contract = contract();
    contract.catalog_invalidated = Some(Arc::clone(&flag));
    let reviewed = contract.review_headers(&resource(), |_| true).unwrap();
    for arguments in [json!({}), json!({"count":0}), json!({"count":"private-value-canary"})] {
        let error = contract.validate_request(&request(arguments)).err().unwrap();
        assert!(matches!(error, ManagedToolError::InvalidArguments));
        assert!(!format!("{error:?} {error}").contains("private-value-canary"));
    }
    flag.store(true, Ordering::Release);
    assert!(matches!(contract.admit_headers(&resource(), &reviewed), Err(ManagedToolError::Invalidated)));
    let fresh = ToolContract::admit(definition()).unwrap();
    fresh.validate_request(&request(json!({"count":2}))).unwrap();
    assert!(contract.is_invalidated());
}
