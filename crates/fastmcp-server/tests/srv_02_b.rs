//! Frozen SRV-02 B public server-dispatch harnesses.
//!
//! The root test IDs are intentionally unqualified so the frozen exact runner
//! discovers and starts each one through the shipped server surface.

use asupersync::Cx;
use fastmcp_core::{McpContext, McpResult};
use fastmcp_derive::tool;
use fastmcp_protocol::protocol_policy::ProtocolPolicy;
use fastmcp_protocol::{JsonRpcRequest, MAX_SERVER_INSTRUCTIONS_BYTES};
use fastmcp_server::{InboundRequestContext, InboundRequestTransport, Server};
use fastmcp_transport::http::HttpStatus;
use serde_json::json;

#[tool(name = "discoverable", description = "SRV-02 catalog fixture")]
fn discoverable(ctx: &McpContext) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok("available".to_owned())
}

fn public_catalog_snapshot(server: &Server) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "info": server.info(),
        "capabilities": server.capabilities(),
        "tools": server.tools(),
        "resources": server.resources(),
        "resourceTemplates": server.resource_templates(),
        "prompts": server.prompts(),
    }))
    .expect("public catalog snapshot must serialize")
}

#[test]
fn srv_02_b_positive() {
    let server = Server::new("discoverable-server", "1.0.0")
        .instructions("")
        .tool(Discoverable)
        .build();
    let stdio = InboundRequestContext::new(Cx::for_testing(), 401, InboundRequestTransport::Stdio);
    let discover = JsonRpcRequest::new("server/discover", None, 401_i64);

    let first_response = server
        .dispatch_with_protocol_policy(ProtocolPolicy::ModernOnly, &stdio, &discover)
        .expect("first discovery request has an id");
    let first_result = first_response
        .result
        .as_ref()
        .expect("first discovery request succeeds");

    assert_eq!(first_result["protocolVersions"], json!(["2026-07-28"]));
    assert_eq!(
        first_result["serverInfo"]["name"],
        json!("discoverable-server")
    );
    assert_eq!(first_result["instructions"], json!(""));
    assert_eq!(first_result["cacheHints"]["maxAgeSeconds"], json!(60));
    assert!(first_result["capabilities"].get("tools").is_some());
    assert!(first_result["capabilities"].get("logging").is_none());
    assert!(first_result["capabilities"].get("completions").is_none());
    assert!(first_result["capabilities"].get("resources").is_none());
    assert!(first_result["capabilities"].get("prompts").is_none());
    assert!(first_result["capabilities"].get("subscriptions").is_none());
    assert!(first_result.get("extensions").is_none());

    let instructionless = Server::new("discoverable-server", "1.0.0")
        .tool(Discoverable)
        .build();
    let instructionless_wire = serde_json::to_value(
        instructionless
            .server_discovery()
            .expect("instructionless discovery result is constructed"),
    )
    .expect("instructionless discovery result serializes");
    assert!(instructionless_wire.get("instructions").is_none());
    assert_eq!(
        instructionless_wire["capabilities"], first_result["capabilities"],
        "instructions cannot alter the advertised behavior registry"
    );

    let oversized = Server::new("bounded-instructions", "1.0.0")
        .instructions("x".repeat(MAX_SERVER_INSTRUCTIONS_BYTES + 1))
        .build();
    assert!(
        oversized.server_discovery().is_err(),
        "oversized local instructions are refused before discovery copies them"
    );

    let auto = InboundRequestContext::new(Cx::for_testing(), 402, InboundRequestTransport::Http);
    let auto_discover = JsonRpcRequest::new("server/discover", None, 402_i64);
    let auto_response = server
        .dispatch_with_protocol_policy(ProtocolPolicy::Auto, &auto, &auto_discover)
        .expect("Auto-composed discovery request has an id");
    assert_eq!(
        auto_response
            .result
            .as_ref()
            .and_then(|result| result.get("protocolVersions")),
        Some(&json!(["2026-07-28"]))
    );

    let initialize = JsonRpcRequest::new("initialize", None, 403_i64);
    let stdio_initialize =
        InboundRequestContext::new(Cx::for_testing(), 403, InboundRequestTransport::Stdio);
    let http_initialize =
        InboundRequestContext::new(Cx::for_testing(), 403, InboundRequestTransport::Http);
    let stdio_error = server
        .dispatch_with_protocol_policy(ProtocolPolicy::ModernOnly, &stdio_initialize, &initialize)
        .and_then(|response| response.error)
        .expect("ModernOnly stdio initialize is rejected");
    let http_response = server.dispatch_http_with_protocol_policy(
        ProtocolPolicy::ModernOnly,
        &http_initialize,
        &initialize,
    );
    assert_eq!(http_response.status, HttpStatus::BAD_REQUEST);
    let http_error =
        serde_json::from_slice::<fastmcp_protocol::JsonRpcResponse>(&http_response.body)
            .expect("ModernOnly HTTP response is JSON-RPC")
            .error
            .expect("ModernOnly HTTP initialize is rejected");
    assert_eq!(stdio_error.code, (-32601).into());
    assert_eq!(
        stdio_error.message,
        "Initialization-based MCP is not enabled"
    );
    assert_eq!(stdio_error.data, Some(json!({"supported": ["2026-07-28"]})));
    assert_eq!(http_error.code, stdio_error.code);
    assert_eq!(http_error.message, stdio_error.message);
    assert_eq!(http_error.data, stdio_error.data);
}

#[test]
fn srv_02_b_planted_negative() {
    let server = Server::new("discover-negative", "1.0.0").build();
    let inbound =
        InboundRequestContext::new(Cx::for_testing(), 404, InboundRequestTransport::Memory);
    let baseline = JsonRpcRequest::new("server/discover", None, 404_i64);
    let mut planted = baseline.clone();
    planted.method = "initialize".to_owned();

    assert_eq!(baseline.jsonrpc, planted.jsonrpc);
    assert_eq!(baseline.id, planted.id);
    assert_eq!(baseline.params, planted.params);
    let input_before = serde_json::to_vec(&planted).expect("planted request must serialize");
    let catalog_before = public_catalog_snapshot(&server);

    let baseline_response = server
        .dispatch_with_protocol_policy(ProtocolPolicy::ModernOnly, &inbound, &baseline)
        .expect("baseline discovery request responds");
    assert!(baseline_response.error.is_none());

    let planted_response = server
        .dispatch_with_protocol_policy(ProtocolPolicy::ModernOnly, &inbound, &planted)
        .expect("planted initialize request responds");
    let planted_error = planted_response
        .error
        .expect("ModernOnly initialize reaches the typed refusal boundary");
    assert_eq!(planted_error.code, (-32601).into());
    assert_eq!(
        planted_error.message,
        "Initialization-based MCP is not enabled"
    );
    assert_eq!(
        planted_error.data,
        Some(json!({"supported": ["2026-07-28"]}))
    );
    assert_eq!(
        serde_json::to_vec(&planted).expect("planted request remains serializable"),
        input_before,
        "typed ModernOnly refusal changed caller input"
    );
    assert_eq!(
        public_catalog_snapshot(&server),
        catalog_before,
        "typed ModernOnly refusal changed public server state"
    );
}
