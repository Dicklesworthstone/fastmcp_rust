//! Frozen SRV-01 public stateless-dispatch harnesses.
//!
//! Each test is deliberately at this integration crate's root so the frozen
//! runner can select its literal ID with `--exact`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use fastmcp_core::{McpContext, McpError, McpErrorCode, McpResult};
use fastmcp_derive::tool;
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest};
use fastmcp_server::{InboundRequestContext, InboundRequestTransport, Server};
use fastmcp_transport::{Transport, TransportError};

#[tool(name = "greet", description = "Greets a user by name")]
fn greet(ctx: &McpContext, name: String) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(format!("Hello, {name}!"))
}

#[tool(name = "declined", description = "Returns a typed caller refusal")]
fn declined_tool(_ctx: &McpContext) -> McpResult<String> {
    Err(McpError::invalid_params("caller input was declined"))
}

#[derive(Default)]
struct RuntimeTransportState {
    incoming: VecDeque<JsonRpcMessage>,
    outgoing: Vec<JsonRpcMessage>,
    closed: bool,
}

struct RuntimeTransport {
    state: Arc<Mutex<RuntimeTransportState>>,
}

#[derive(Clone)]
struct RuntimeTransportProbe(Arc<Mutex<RuntimeTransportState>>);

impl RuntimeTransport {
    fn single_request(request: JsonRpcRequest) -> (Self, RuntimeTransportProbe) {
        let state = Arc::new(Mutex::new(RuntimeTransportState {
            incoming: VecDeque::from([JsonRpcMessage::Request(request)]),
            ..RuntimeTransportState::default()
        }));
        (
            Self {
                state: Arc::clone(&state),
            },
            RuntimeTransportProbe(state),
        )
    }
}

impl RuntimeTransportProbe {
    fn outgoing(&self) -> Vec<JsonRpcMessage> {
        self.0
            .lock()
            .expect("runtime transport probe mutex must not be poisoned")
            .outgoing
            .clone()
    }
}

impl Transport for RuntimeTransport {
    fn send(&mut self, _cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        self.state
            .lock()
            .expect("runtime transport state mutex must not be poisoned")
            .outgoing
            .push(message.clone());
        Ok(())
    }

    fn recv(&mut self, _cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        self.state
            .lock()
            .expect("runtime transport state mutex must not be poisoned")
            .incoming
            .pop_front()
            .ok_or(TransportError::Closed)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.state
            .lock()
            .expect("runtime transport state mutex must not be poisoned")
            .closed = true;
        Ok(())
    }
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
    let server = Server::new("stateless-public-runtime", "1.0.0")
        .tool(Greet)
        .build();
    let request = JsonRpcRequest::new(
        "server/discover",
        Some(serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })),
        71_i64,
    );
    let request_before = serde_json::to_vec(&request).expect("runtime request must serialize");
    let (transport, probe) = RuntimeTransport::single_request(request.clone());

    server
        .run_transport_returning_with_cx(&Cx::for_testing(), transport)
        .expect("the public server transport runtime admits one exact modern request");

    let outgoing = probe.outgoing();
    assert_eq!(outgoing.len(), 1, "the runtime emits one response");
    let JsonRpcMessage::Response(response) = &outgoing[0] else {
        panic!("the runtime emits a JSON-RPC response");
    };
    assert!(
        response.error.is_none(),
        "modern discovery is not legacy-initialized"
    );
    assert_eq!(
        response
            .result
            .as_ref()
            .and_then(|result| result.get("supportedVersions")),
        Some(&serde_json::json!(["2026-07-28"]))
    );
    assert_eq!(response.id, request.id);
    assert_eq!(
        serde_json::to_vec(&request).expect("runtime request remains serializable"),
        request_before,
        "runtime admission cannot mutate caller-owned modern metadata"
    );

    #[cfg(feature = "legacy-2024-11-05")]
    {
        let legacy_initialize = JsonRpcRequest::new(
            "initialize",
            Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "exact-legacy-client", "version": "1.0.0"},
            })),
            72_i64,
        );
        let (legacy_transport, legacy_probe) = RuntimeTransport::single_request(legacy_initialize);
        Server::new("exact-legacy-runtime", "1.0.0")
            .tool(Greet)
            .build()
            .run_transport_returning_with_cx(&Cx::for_testing(), legacy_transport)
            .expect("the same public runtime preserves exact MCP 2024-11-05 initialization");
        let legacy_outgoing = legacy_probe.outgoing();
        assert_eq!(legacy_outgoing.len(), 1);
        let JsonRpcMessage::Response(legacy_response) = &legacy_outgoing[0] else {
            panic!("the exact legacy runtime emits a JSON-RPC response");
        };
        assert_eq!(
            legacy_response
                .result
                .as_ref()
                .and_then(|result| result.get("protocolVersion")),
            Some(&serde_json::json!("2024-11-05"))
        );
    }
}

#[test]
fn srv_01_a_planted_negative() {
    let baseline = JsonRpcRequest::new(
        "server/discover",
        Some(serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })),
        72_i64,
    );
    let mut planted = baseline.clone();
    planted
        .params
        .as_mut()
        .and_then(|params| params.pointer_mut("/_meta/io.modelcontextprotocol~1protocolVersion"))
        .expect("modern metadata must contain the planted version field")
        .clone_from(&serde_json::json!("2025-11-25"));

    // The forbidden dimension is only the negotiated modern version.
    assert_eq!(baseline.jsonrpc, planted.jsonrpc);
    assert_eq!(baseline.id, planted.id);
    assert_eq!(baseline.method, planted.method);
    let planted_input_before =
        serde_json::to_vec(&planted).expect("planted request must serialize");
    let (transport, probe) = RuntimeTransport::single_request(planted.clone());

    let error = Server::new("stateless-runtime-version-refusal", "1.0.0")
        .tool(Greet)
        .build()
        .run_transport_returning_with_cx(&Cx::for_testing(), transport)
        .expect_err("a one-field unsupported version is refused by the public runtime");
    assert_eq!(error.code, McpErrorCode::InternalError);
    let outgoing = probe.outgoing();
    assert_eq!(outgoing.len(), 1, "the runtime emits one typed refusal");
    let JsonRpcMessage::Response(planted_response) = &outgoing[0] else {
        panic!("the planted runtime result is a JSON-RPC response");
    };
    assert_eq!(
        planted_response
            .error
            .as_ref()
            .map(|error| error.code.clone()),
        Some(McpErrorCode::InvalidRequest.into())
    );
    assert_eq!(
        serde_json::to_vec(&planted).expect("planted request remains serializable"),
        planted_input_before,
        "rejected version admission changed caller input"
    );
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
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
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
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
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
        planted_response
            .error
            .as_ref()
            .map(|error| error.code.clone()),
        Some(McpErrorCode::InvalidParams.into())
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
