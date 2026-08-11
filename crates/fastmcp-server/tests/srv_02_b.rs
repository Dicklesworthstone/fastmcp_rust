//! Frozen SRV-02 B public server-dispatch harnesses.
//!
//! The root test IDs are intentionally unqualified so the frozen exact runner
//! discovers and starts each one through the shipped server surface.

use asupersync::Cx;
use fastmcp_core::{McpContext, McpResult};
use fastmcp_derive::tool;
#[cfg(not(feature = "legacy-2024-11-05"))]
use fastmcp_protocol::JsonRpcMessage;
#[cfg(not(feature = "legacy-2024-11-05"))]
use fastmcp_protocol::protocol_policy::MODERN_PROTOCOL_VERSION;
use fastmcp_protocol::protocol_policy::ProtocolPolicy;
#[cfg(not(feature = "legacy-2024-11-05"))]
use fastmcp_protocol::{
    FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION_META_KEY, SERVER_DISCOVER_METHOD,
};
use fastmcp_protocol::{JsonRpcRequest, MAX_SERVER_INSTRUCTIONS_BYTES};
#[cfg(not(feature = "legacy-2024-11-05"))]
use fastmcp_server::ServerHttpEndpointResponse;
#[cfg(not(feature = "legacy-2024-11-05"))]
use fastmcp_server::{HttpServerConfig, ServerHttpEndpointError};
use fastmcp_server::{InboundRequestContext, InboundRequestTransport, Server};
use fastmcp_transport::http::HttpStatus;
#[cfg(not(feature = "legacy-2024-11-05"))]
use fastmcp_transport::http::{HttpMethod, HttpRequest};
#[cfg(not(feature = "legacy-2024-11-05"))]
use fastmcp_transport::{Transport, TransportError};
use serde_json::json;
#[cfg(not(feature = "legacy-2024-11-05"))]
use std::collections::VecDeque;
#[cfg(not(feature = "legacy-2024-11-05"))]
use std::sync::{Arc, Mutex};

#[cfg(not(feature = "legacy-2024-11-05"))]
#[derive(Default)]
struct FeatureOffTransportState {
    incoming: VecDeque<JsonRpcMessage>,
    outgoing: Vec<JsonRpcMessage>,
    recv_calls: usize,
    close_calls: usize,
}

/// A one-frame ordinary public transport, deliberately not a test-only server
/// adapter. The integration crate links the server as a production dependency.
#[cfg(not(feature = "legacy-2024-11-05"))]
struct FeatureOffTransport {
    state: Arc<Mutex<FeatureOffTransportState>>,
}

#[cfg(not(feature = "legacy-2024-11-05"))]
impl FeatureOffTransport {
    fn single_request(request: JsonRpcRequest) -> (Self, Arc<Mutex<FeatureOffTransportState>>) {
        let state = Arc::new(Mutex::new(FeatureOffTransportState {
            incoming: VecDeque::from([JsonRpcMessage::Request(request)]),
            ..FeatureOffTransportState::default()
        }));
        (
            Self {
                state: Arc::clone(&state),
            },
            state,
        )
    }
}

#[cfg(not(feature = "legacy-2024-11-05"))]
impl Transport for FeatureOffTransport {
    fn send(&mut self, _cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        let mut state = self
            .state
            .lock()
            .expect("feature-off transport mutex must not be poisoned");
        state.outgoing.push(message.clone());
        Ok(())
    }

    fn recv(&mut self, _cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        let mut state = self
            .state
            .lock()
            .expect("feature-off transport mutex must not be poisoned");
        state.recv_calls += 1;
        state.incoming.pop_front().ok_or(TransportError::Closed)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.state
            .lock()
            .expect("feature-off transport mutex must not be poisoned")
            .close_calls += 1;
        Ok(())
    }
}

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
    assert_eq!(stdio_error.code.as_i32(), Some(-32601));
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
    assert_eq!(planted_error.code.as_i32(), Some(-32601));
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

// This integration target compiles `fastmcp-server` as an ordinary dependency.
// Therefore `cargo test -p fastmcp-server --no-default-features --test srv_02_b`
// exercises the shipped `modern_http_only` composition rather than the
// unit-test-only dual-era adapter retained for legacy contract tests.
#[cfg(not(feature = "legacy-2024-11-05"))]
#[test]
fn srv_02_b_feature_off_http_modern_positive_and_legacy_route_refusal() {
    let cx = Cx::for_testing();
    let endpoint = Server::new("feature-off-modern-http", "1.0.0")
        .protocol_policy(ProtocolPolicy::Auto)
        .expect("Auto is available in every server feature set")
        .build_http_endpoint()
        .expect("feature-off server must construct its modern HTTP endpoint");
    let mut session = endpoint
        .open_session(&cx)
        .expect("feature-off server must open a modern HTTP session");
    let discovery = JsonRpcRequest::new(
        SERVER_DISCOVER_METHOD,
        Some(json!({
            "_meta": {
                FINAL_PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_VERSION,
                FINAL_CLIENT_CAPABILITIES_META_KEY: {},
            },
        })),
        4_101_i64,
    );
    let modern_request = HttpRequest::new(HttpMethod::Post, "/mcp")
        .with_header("content-type", "application/json")
        .with_header("accept", "application/json")
        .with_header("mcp-protocol-version", MODERN_PROTOCOL_VERSION)
        .with_header("mcp-method", SERVER_DISCOVER_METHOD)
        .with_body(
            serde_json::to_vec(&discovery).expect("modern discovery request must serialize"),
        );

    let modern_response = session
        .handle(&cx, modern_request.clone())
        .expect("feature-off modern request must reach modern_http_only");
    let ServerHttpEndpointResponse::Immediate(modern_response) = modern_response else {
        panic!("ordinary modern discovery must retain its JSON response representation");
    };
    assert_eq!(modern_response.status, HttpStatus::OK);
    let modern_response: fastmcp_protocol::JsonRpcResponse =
        serde_json::from_slice(&modern_response.body)
            .expect("feature-off modern response must remain JSON-RPC");
    assert_eq!(modern_response.id, Some(4_101_i64.into()));
    assert!(modern_response.error.is_none());
    assert_eq!(
        modern_response
            .result
            .as_ref()
            .and_then(|result| result["protocolVersions"].as_array())
            .and_then(|versions| versions.first())
            .and_then(serde_json::Value::as_str),
        Some(MODERN_PROTOCOL_VERSION),
        "the feature-off production path must retain final-era discovery",
    );

    // This reaches the same final-era capability through the public stdio
    // entry point. Unlike a lib unit test, the server linked by this
    // integration target is the shipped no-default-features dependency.
    let (modern_transport, modern_transport_state) =
        FeatureOffTransport::single_request(discovery.clone());
    let modern_stdio_result = Server::new("feature-off-modern-stdio", "1.0.0")
        .protocol_policy(ProtocolPolicy::Auto)
        .expect("Auto is available in every server feature set")
        .build()
        .run_transport_returning_with_cx(&cx, modern_transport);
    assert!(
        modern_stdio_result.is_ok(),
        "public feature-off stdio must deliver final server/discover"
    );
    let modern_transport_state = modern_transport_state
        .lock()
        .expect("feature-off transport mutex must not be poisoned");
    assert_eq!(
        modern_transport_state.recv_calls, 2,
        "one request then clean EOF"
    );
    assert_eq!(modern_transport_state.close_calls, 1);
    let [JsonRpcMessage::Response(modern_stdio_response)] =
        modern_transport_state.outgoing.as_slice()
    else {
        panic!("public modern stdio discovery must emit one JSON-RPC response");
    };
    assert_eq!(modern_stdio_response.id, Some(4_101_i64.into()));
    assert_eq!(
        modern_stdio_response
            .result
            .as_ref()
            .and_then(|result| result["protocolVersions"].as_array())
            .and_then(|versions| versions.first())
            .and_then(serde_json::Value::as_str),
        Some(MODERN_PROTOCOL_VERSION),
    );

    // This is deliberately the same fully admitted modern request except for
    // the path. `/messages` is the historical exact-2024 ingress, which must
    // be absent before it can pin an era, allocate request authority, or
    // enter an adapter in the feature-off library.
    let mut legacy_route_request = modern_request.clone();
    legacy_route_request.path = "/messages".to_owned();
    let legacy_refusal = session
        .handle(&cx, legacy_route_request)
        .expect("a disabled legacy route must be a normal HTTP response");
    assert!(matches!(
        legacy_refusal,
        ServerHttpEndpointResponse::Immediate(response) if response.status == HttpStatus::NOT_FOUND
    ));

    // The refusal must not disturb the previously selected modern HTTP era.
    let modern_after_refusal = session
        .handle(&cx, modern_request)
        .expect("legacy-route refusal must not poison the selected modern session");
    assert!(matches!(
        modern_after_refusal,
        ServerHttpEndpointResponse::Immediate(response) if response.status == HttpStatus::OK
    ));

    let legacy_only =
        Server::new("feature-off-legacy-only", "1.0.0").protocol_policy(ProtocolPolicy::LegacyOnly);
    assert!(matches!(
        legacy_only,
        Err(fastmcp_server::ServerLaunchPolicyError::FeatureUnavailable)
    ));

    let legacy_http_endpoint = Server::new("feature-off-legacy-only-http", "1.0.0")
        .protocol_policy(ProtocolPolicy::LegacyOnly)
        .map(|builder| builder.build_http_endpoint());
    assert!(matches!(
        legacy_http_endpoint,
        Err(fastmcp_server::ServerLaunchPolicyError::FeatureUnavailable)
    ));

    // The legacy selection fails before a server or transport exists, so no
    // deferred stdio refusal can perform I/O after construction.
    let legacy_stdio = Server::new("feature-off-legacy-only-stdio", "1.0.0")
        .protocol_policy(ProtocolPolicy::LegacyOnly);
    assert!(matches!(
        legacy_stdio,
        Err(fastmcp_server::ServerLaunchPolicyError::FeatureUnavailable)
    ));
}

#[cfg(not(feature = "legacy-2024-11-05"))]
#[test]
fn srv_02_b_feature_off_endpoint_uses_the_public_modern_error_contract() {
    let result = Server::new("feature-off-invalid-http-config", "1.0.0")
        .http_config(HttpServerConfig::new().request_capacity(0))
        .build_http_endpoint();

    match result {
        Err(ServerHttpEndpointError::InvalidConfiguration(message)) => {
            assert!(message.contains("modern HTTP request capacity must be nonzero"));
        }
        Err(error) => panic!("expected the public configuration error, got {error}"),
        Ok(_) => panic!("zero modern request capacity must be rejected"),
    }
}
