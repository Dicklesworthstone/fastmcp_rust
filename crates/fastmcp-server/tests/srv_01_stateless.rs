//! Frozen SRV-01 public stateless-dispatch harnesses.
//!
//! Each test is deliberately at this integration crate's root so the frozen
//! runner can select its literal ID with `--exact`.

use asupersync::Cx;
use fastmcp_core::{McpContext, McpError, McpErrorCode, McpResult};
use fastmcp_derive::tool;
use fastmcp_protocol::JsonRpcRequest;
use fastmcp_server::{InboundRequestContext, InboundRequestTransport, Server};

#[tool(name = "greet", description = "Greets a user by name")]
fn greet(ctx: &McpContext, name: String) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(format!("Hello, {name}!"))
}

#[tool(name = "declined", description = "Returns a typed caller refusal")]
fn declined_tool(_ctx: &McpContext) -> McpResult<String> {
    Err(McpError::invalid_params("caller input was declined"))
}

fn stateless_public_catalog_snapshot(server: &Server) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "info": server.info(),
        "capabilities": server.capabilities(),
        "tools": server.tools(),
        "resources": server.resources(),
        "resourceTemplates": server.resource_templates(),
        "prompts": server.prompts(),
    }))
    .expect("public stateless catalog must serialize")
}

#[test]
fn srv_01_a_positive() {
    let server = Server::new("stateless-public-handler", "1.0.0")
        .tool(Greet)
        .build();
    let inbound =
        InboundRequestContext::new(Cx::for_testing(), 71, InboundRequestTransport::Memory);
    let request = JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "greet",
            "arguments": { "name": "stateless client" },
        })),
        71_i64,
    );
    let catalog_before = stateless_public_catalog_snapshot(&server);

    let response = server
        .dispatch_stateless(&inbound, &request)
        .expect("request with an id must receive a response");

    assert!(response.error.is_none());
    assert_eq!(
        response
            .result
            .as_ref()
            .and_then(|result| result.pointer("/content/0/text"))
            .and_then(serde_json::Value::as_str),
        Some("Hello, stateless client!")
    );
    assert_eq!(inbound.request_id(), 71);
    assert_eq!(inbound.transport(), InboundRequestTransport::Memory);
    assert_eq!(stateless_public_catalog_snapshot(&server), catalog_before);
}

#[test]
fn srv_01_a_planted_negative() {
    let server = Server::new("stateless-forbidden-mutation", "1.0.0")
        .tool(Greet)
        .build();
    let inbound =
        InboundRequestContext::new(Cx::for_testing(), 72, InboundRequestTransport::Memory);
    let baseline = JsonRpcRequest::new("tools/list", None, 72_i64);
    let mut planted = baseline.clone();
    planted.method = "logging/setLevel".to_string();

    // The forbidden dimension is only the method: request identity and
    // parameters are byte-for-byte identical to the accepted baseline.
    assert_eq!(baseline.jsonrpc, planted.jsonrpc);
    assert_eq!(baseline.id, planted.id);
    assert_eq!(baseline.params, planted.params);
    let planted_input_before =
        serde_json::to_vec(&planted).expect("planted request must serialize");
    let catalog_before = stateless_public_catalog_snapshot(&server);

    let baseline_response = server
        .dispatch_stateless(&inbound, &baseline)
        .expect("stateless tools/list baseline must respond");
    assert!(baseline_response.error.is_none());

    let planted_response = server
        .dispatch_stateless(&inbound, &planted)
        .expect("planted request with an id must receive a response");
    assert_eq!(
        planted_response.error.as_ref().map(|error| error.code),
        Some(McpErrorCode::MethodNotFound.into())
    );
    assert_eq!(
        serde_json::to_vec(&planted).expect("planted request remains serializable"),
        planted_input_before,
        "forbidden stateless mutation changed caller input"
    );
    assert_eq!(
        stateless_public_catalog_snapshot(&server),
        catalog_before,
        "forbidden stateless mutation changed the public catalog"
    );
    assert_eq!(inbound.request_id(), 72);
    assert_eq!(inbound.transport(), InboundRequestTransport::Memory);
}

#[test]
fn srv_01_b_positive() {
    let server = Server::new("stateless-handler-result", "1.0.0")
        .tool(DeclinedTool)
        .build();
    let inbound =
        InboundRequestContext::new(Cx::for_testing(), 73, InboundRequestTransport::Memory);
    let request = JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "declined",
            "arguments": {},
        })),
        73_i64,
    );

    let response = server
        .dispatch_stateless(&inbound, &request)
        .expect("handler request with an id must receive a response");

    assert!(response.error.is_none());
    assert_eq!(
        response
            .result
            .as_ref()
            .and_then(|result| result.get("isError"))
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "a handler error must convert to CallToolResult rather than a JSON-RPC failure"
    );
    assert_eq!(
        response
            .result
            .as_ref()
            .and_then(|result| result.pointer("/content/0/text"))
            .and_then(serde_json::Value::as_str),
        Some("caller input was declined")
    );
}

#[test]
fn srv_01_b_planted_negative() {
    let server = Server::new("stateless-handler-refusal", "1.0.0")
        .tool(DeclinedTool)
        .build();
    let inbound =
        InboundRequestContext::new(Cx::for_testing(), 74, InboundRequestTransport::Memory);
    let baseline = JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "declined",
            "arguments": {},
        })),
        74_i64,
    );
    let mut planted = baseline.clone();
    planted
        .params
        .as_mut()
        .and_then(|params| params.as_object_mut())
        .expect("tools/call test parameters must be an object")
        .insert("name".to_string(), serde_json::json!("missing-handler"));

    // The handler name is the sole planted dimension. The method, request
    // identity, and argument object remain the accepted baseline values.
    assert_eq!(baseline.method, planted.method);
    assert_eq!(baseline.jsonrpc, planted.jsonrpc);
    assert_eq!(baseline.id, planted.id);
    assert_eq!(
        baseline
            .params
            .as_ref()
            .and_then(|params| params.get("name"))
            .and_then(serde_json::Value::as_str),
        Some("declined")
    );
    assert_eq!(
        planted
            .params
            .as_ref()
            .and_then(|params| params.get("name"))
            .and_then(serde_json::Value::as_str),
        Some("missing-handler")
    );
    assert_eq!(
        baseline
            .params
            .as_ref()
            .and_then(|params| params.get("arguments")),
        planted
            .params
            .as_ref()
            .and_then(|params| params.get("arguments"))
    );
    let planted_input_before =
        serde_json::to_vec(&planted).expect("planted request must serialize");
    let catalog_before = stateless_public_catalog_snapshot(&server);

    let baseline_response = server
        .dispatch_stateless(&inbound, &baseline)
        .expect("accepted handler baseline must receive a response");
    assert!(baseline_response.error.is_none());
    assert_eq!(
        baseline_response
            .result
            .as_ref()
            .and_then(|result| result.get("isError"))
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );

    let planted_response = server
        .dispatch_stateless(&inbound, &planted)
        .expect("planted handler request with an id must receive a response");
    assert_eq!(
        planted_response.error.as_ref().map(|error| error.code),
        Some(McpErrorCode::MethodNotFound.into())
    );
    assert_eq!(
        serde_json::to_vec(&planted).expect("planted request remains serializable"),
        planted_input_before,
        "typed handler refusal changed caller input"
    );
    assert_eq!(
        stateless_public_catalog_snapshot(&server),
        catalog_before,
        "typed handler refusal changed the public catalog"
    );
}
