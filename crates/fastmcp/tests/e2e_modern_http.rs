//! Public modern HTTP round trip: shipped client against shipped server.
//!
//! Both ends of these tests are real shipped surfaces — the turnkey
//! `Server::bind_http`/`serve` lifecycle on one side and
//! `ModernHttpClient::connect`/`request` on the other — joined over one real
//! localhost socket. No scripted peer, no fixture transcript, no mock
//! stands in for either endpoint.
//!
//! What this proves (and only this): the shipped dual-era HTTP server and
//! the shipped HTTP clients can complete era negotiation and a round trip
//! against each other — modern discovery plus `tools/call` over whichever
//! JSON or request-scoped SSE lane the server selects, the `Auto` policy
//! selecting the modern era against a live modern server without touching a
//! legacy path, and the exact 2024-11-05 HTTP+SSE lane completing
//! `initialize` through the server's session-scoped advertised message
//! endpoint. It is not an aggregate MCP 2026-07-28 conformance claim.

use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread;

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use fastmcp_client::http_executor::{
    ModernHttpClient, ModernHttpResponseKind, ModernHttpResponseStream,
};
use fastmcp_client::sse::SseLimits;
use fastmcp_client::{CanonicalHttpUrl, ClientProtocolPlan, ProtocolEra, ProtocolPolicy};
use fastmcp_protocol::{ClientCapabilities, ClientInfo, JsonRpcMessage, JsonRpcRequest, RequestId};
use fastmcp_rust::{McpContext, ServerBuilder, tool};
use serde_json::json;

/// Echoes back the input, proving handler dispatch crossed the wire.
#[tool(name = "echo", version = "1.0.0", annotations(read_only, idempotent))]
fn echo_tool(_ctx: &McpContext, message: String) -> String {
    message
}

fn runtime_block_on<F: std::future::Future>(future: F) -> F::Output {
    RuntimeBuilder::current_thread()
        .build()
        .expect("native runtime must build")
        .block_on(future)
}

/// Binds the real turnkey server on an ephemeral port and serves it from a
/// detached acceptor thread for the remainder of the test process.
fn spawn_echo_server() -> SocketAddr {
    let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
    thread::spawn(move || {
        runtime_block_on(async move {
            let cx = Cx::for_request();
            let server = ServerBuilder::new("e2e-modern-http", "1.0.0")
                .tool(EchoTool)
                .build();
            let bound = server
                .bind_http(&cx, "127.0.0.1:0")
                .await
                .expect("turnkey server binds an ephemeral port");
            addr_tx
                .send(bound.local_addr().expect("bound address is known"))
                .expect("address channel delivers");
            let _ = bound.serve(&cx).await;
        });
    });
    addr_rx
        .recv()
        .expect("server thread reports its bound address")
}

fn client_info() -> ClientInfo {
    ClientInfo {
        name: "e2e-modern-http-client".to_owned(),
        version: "1.0.0".to_owned(),
    }
}

fn plan(addr: SocketAddr, policy: ProtocolPolicy) -> ClientProtocolPlan {
    let modern_target = CanonicalHttpUrl::parse(&format!("http://{addr}/mcp"))
        .expect("local modern target must be canonical");
    let legacy_sse = CanonicalHttpUrl::parse(&format!("http://{addr}/sse"))
        .expect("legacy SSE target must be canonical");
    let legacy_message = CanonicalHttpUrl::parse(&format!("http://{addr}/messages"))
        .expect("legacy message target must be canonical");
    ClientProtocolPlan::http(
        policy,
        (!matches!(policy, ProtocolPolicy::LegacyOnly)).then_some(modern_target),
        (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_sse),
        (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_message),
        "credential-partition-e2e-http".to_owned(),
        "security-partition-e2e-http".to_owned(),
        "native-h1-e2e-http".to_owned(),
        1,
        1,
        0,
    )
    .expect("the complete HTTP plan must be accepted")
}

/// Consumes whichever response lane the real server selected and returns the
/// final correlated JSON-RPC response document.
fn final_response_document(cx: &Cx, response: ModernHttpResponseStream) -> serde_json::Value {
    match response.metadata().kind() {
        ModernHttpResponseKind::Json => {
            let bytes = runtime_block_on(response.read_to_end(cx, 1 << 20))
                .expect("immediate JSON body reads to end");
            serde_json::from_slice(&bytes).expect("immediate JSON response parses")
        }
        ModernHttpResponseKind::Sse => {
            let mut stream = response
                .into_sse_stream(SseLimits::new(65_536, 1 << 20, 64).expect("nonzero SSE limits"))
                .expect("SSE response admits the shipped parser");
            let mut terminal = None;
            while let Some(event) =
                runtime_block_on(stream.next_event(cx)).expect("SSE stream stays readable")
            {
                let value: serde_json::Value =
                    serde_json::from_str(&event).expect("SSE payload is one JSON document");
                if value.get("id").is_some() {
                    terminal = Some(value);
                }
            }
            terminal.expect("SSE stream carried a final correlated response")
        }
        ModernHttpResponseKind::EmptyAcknowledgement => {
            panic!("a correlated request cannot complete with an empty acknowledgement")
        }
        ModernHttpResponseKind::HttpFailure => panic!(
            "unexpected HTTP failure status {} from the shipped server",
            response.metadata().status()
        ),
    }
}

#[test]
fn modern_only_round_trip_reaches_the_shipped_tool() {
    let addr = spawn_echo_server();
    let cx = Cx::for_request();

    let outcome = runtime_block_on(ModernHttpClient::connect(
        &cx,
        plan(addr, ProtocolPolicy::ModernOnly),
        client_info(),
        ClientCapabilities::default(),
    ))
    .expect("the shipped client connects to the shipped server");
    assert_eq!(outcome.selected_era(), Some(ProtocolEra::Modern2026));
    let client = outcome
        .into_modern()
        .expect("modern-only negotiation yields a modern client");
    assert!(
        client
            .server_discovery()
            .supported_versions()
            .iter()
            .any(|version| version == "2026-07-28"),
        "live discovery must advertise the final protocol revision"
    );

    let response = runtime_block_on(client.request(
        &cx,
        "tools/call",
        json!({"name": "echo", "arguments": {"message": "round trip e2e"}}),
        Some(RequestId::Number(2)),
    ))
    .expect("tools/call crosses the real socket");
    let document = final_response_document(&cx, response);

    assert_eq!(document["jsonrpc"], json!("2.0"));
    assert_eq!(document["id"], json!(2));
    assert!(
        document.get("error").is_none(),
        "echo must not fail: {document}"
    );
    let result = document
        .get("result")
        .expect("terminal response carries a result");
    assert!(
        serde_json::to_string(result)
            .expect("result reserializes")
            .contains("round trip e2e"),
        "the echoed text must round-trip through the live handler: {result}"
    );
}

#[test]
fn auto_policy_selects_the_modern_era_against_the_live_server() {
    let addr = spawn_echo_server();
    let cx = Cx::for_request();

    let outcome = runtime_block_on(ModernHttpClient::connect(
        &cx,
        plan(addr, ProtocolPolicy::Auto),
        client_info(),
        ClientCapabilities::default(),
    ))
    .expect("Auto negotiation completes against the live server");
    assert_eq!(
        outcome.selected_era(),
        Some(ProtocolEra::Modern2026),
        "a live modern discovery response must never downgrade Auto"
    );
    let client = outcome
        .into_modern()
        .expect("Auto against a modern server yields the modern client");

    // One request proves the negotiated connection is actually usable.
    let response = runtime_block_on(client.request(
        &cx,
        "tools/call",
        json!({"name": "echo", "arguments": {"message": "auto era"}}),
        Some(RequestId::Number(3)),
    ))
    .expect("the Auto-selected modern connection serves requests");
    let document = final_response_document(&cx, response);
    assert_eq!(document["id"], json!(3));
    assert!(
        document.get("error").is_none(),
        "echo over the Auto-selected connection must not fail: {document}"
    );
}

#[test]
fn legacy_only_initialize_round_trips_against_the_same_shipped_server() {
    let addr = spawn_echo_server();
    let cx = Cx::for_request();

    // The same turnkey server serves the exact 2024-11-05 HTTP+SSE lane:
    // its SSE stream advertises a session-scoped message endpoint that the
    // shipped legacy client must admit as the configured resource.
    let outcome = runtime_block_on(ModernHttpClient::connect(
        &cx,
        plan(addr, ProtocolPolicy::LegacyOnly),
        client_info(),
        ClientCapabilities::default(),
    ))
    .expect("legacy-only connect opens the shipped legacy SSE lane");
    assert_eq!(outcome.selected_era(), Some(ProtocolEra::Legacy2024));
    let mut legacy = outcome
        .into_legacy_sse()
        .expect("legacy-only negotiation yields the legacy client");
    assert!(
        legacy
            .advertised_message_post_target()
            .starts_with(legacy.configured_message_post_target()),
        "the advertised endpoint extends the configured resource"
    );

    runtime_block_on(legacy.send(
        &cx,
        &JsonRpcMessage::Request(JsonRpcRequest::new(
            "initialize",
            Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "e2e-legacy-http-client", "version": "1.0.0"}
            })),
            RequestId::Number(11),
        )),
    ))
    .expect("legacy initialize POSTs to the advertised session endpoint");

    let mut initialize_response = None;
    for _ in 0..8 {
        match runtime_block_on(legacy.next_message(&cx))
            .expect("legacy SSE messages decode as strict JSON-RPC")
        {
            Some(message) => {
                let value = serde_json::to_value(message).expect("legacy message reserializes");
                if value.get("id") == Some(&json!(11)) {
                    initialize_response = Some(value);
                    break;
                }
            }
            None => break,
        }
    }
    let document =
        initialize_response.expect("the live legacy lane delivered the initialize response");
    assert!(
        document.get("error").is_none(),
        "legacy initialize must not fail: {document}"
    );
    assert_eq!(
        document["result"]["protocolVersion"],
        json!("2024-11-05"),
        "the legacy lane must negotiate the exact 2024-11-05 revision"
    );
}
