//! Frozen SRV-01 public stateless-dispatch harnesses.
//!
//! Each test is deliberately at this integration crate's root so the frozen
//! runner can select its literal ID with `--exact`.

use std::collections::VecDeque;
use std::io::{BufWriter, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// An actual buffered stdout transport: only close commits the queued reply.
/// This integration crate links the shipped server, including its feature-off
/// pump, rather than selecting the server's `cfg(test)` dispatcher.
struct ProcessOwnedTransport {
    request: Option<JsonRpcRequest>,
    output: BufWriter<std::io::Stdout>,
    scenario: String,
    fail_close: bool,
    shutdown_calls: Arc<AtomicUsize>,
    close_calls: usize,
}

impl Transport for ProcessOwnedTransport {
    fn send(&mut self, _cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        if self.scenario == "send" {
            return Err(TransportError::Io(std::io::Error::other(
                "process transport send failed",
            )));
        }
        serde_json::to_writer(&mut self.output, message)
            .map_err(|error| TransportError::Io(std::io::Error::other(error)))?;
        self.output.write_all(b"\n")?;
        Ok(())
    }

    fn recv(&mut self, _cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        if let Some(request) = self.request.take() {
            return Ok(JsonRpcMessage::Request(request));
        }
        match self.scenario.as_str() {
            "cancel" => Err(TransportError::Cancelled),
            "receive" => Err(TransportError::Io(std::io::Error::other(
                "process transport receive failed",
            ))),
            _ => Err(TransportError::Closed),
        }
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.close_calls += 1;
        self.output.flush()?;
        serde_json::to_writer(
            &mut self.output,
            &serde_json::json!({
                "event": "transport_closed",
                "closeCalls": self.close_calls,
                "shutdownCalls": self.shutdown_calls.load(Ordering::Acquire),
            }),
        )
        .map_err(|error| TransportError::Io(std::io::Error::other(error)))?;
        self.output.write_all(b"\n")?;
        self.output.flush()?;
        if self.fail_close {
            return Err(TransportError::Io(std::io::Error::other(
                "process transport close failed",
            )));
        }
        Ok(())
    }
}

fn run_process_owned_transport_child(scenario: String, fail_close: bool) -> ! {
    let shutdown_calls = Arc::new(AtomicUsize::new(0));
    let hook_calls = Arc::clone(&shutdown_calls);
    let startup_fails = scenario == "startup";
    let transport = ProcessOwnedTransport {
        request: Some(JsonRpcRequest::new(
            "server/discover",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            })),
            917_i64,
        )),
        output: BufWriter::with_capacity(64 * 1024, std::io::stdout()),
        scenario,
        fail_close,
        shutdown_calls,
        close_calls: 0,
    };
    let server = Server::new("process-close-public-runtime", "1.0.0")
        .on_startup(move || -> Result<(), std::io::Error> {
            if startup_fails {
                Err(std::io::Error::other("process startup failed"))
            } else {
                Ok(())
            }
        })
        .on_shutdown(move || {
            hook_calls.fetch_add(1, Ordering::AcqRel);
        })
        .build();
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("process transport runtime must build");
    runtime.block_on(async {
        let cx = Cx::current().expect("the caller runtime installs its context");
        server.run_transport_with_cx(&cx, transport);
    });
    panic!("process-owned server must exit rather than return");
}

fn run_process_owned_transport_test(test_name: &str, fail_close: bool) {
    const CHILD_SCENARIO: &str = "FASTMCP_PROCESS_CLOSE_TEST_SCENARIO";
    if let Ok(scenario) = std::env::var(CHILD_SCENARIO) {
        run_process_owned_transport_child(scenario, fail_close);
    }

    for scenario in ["eof", "cancel", "startup", "receive", "send"] {
        let mut child =
            Command::new(std::env::current_exe().expect("locate integration executable"))
                .args(["--exact", test_name, "--nocapture"])
                .env(CHILD_SCENARIO, scenario)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn process-owned server test");
        let deadline = Instant::now() + Duration::from_secs(10);
        let timed_out = loop {
            if child.try_wait().expect("observe server process").is_some() {
                break false;
            }
            if Instant::now() >= deadline {
                child.kill().expect("stop this nonterminating test child");
                break true;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let output = child.wait_with_output().expect("reap server test child");
        let stdout = String::from_utf8(output.stdout).expect("server stdout is UTF-8");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !timed_out,
            "{scenario}: process did not terminate: {stderr}"
        );
        let expected_code =
            i32::from(fail_close || matches!(scenario, "startup" | "receive" | "send"));
        assert_eq!(
            output.status.code(),
            Some(expected_code),
            "{scenario}: {stderr}"
        );
        let frames: Vec<serde_json::Value> = stdout
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        let closes: Vec<_> = frames
            .iter()
            .filter(|frame| frame["event"] == "transport_closed")
            .collect();
        assert_eq!(
            closes.len(),
            1,
            "{scenario}: close must commit exactly once: {stdout}"
        );
        assert_eq!(closes[0]["closeCalls"], 1, "{scenario}");
        assert_eq!(
            closes[0]["shutdownCalls"], 1,
            "{scenario}: cleanup must precede close"
        );
        let responses: Vec<_> = frames.iter().filter(|frame| frame["id"] == 917).collect();
        if matches!(scenario, "startup" | "send") {
            assert!(
                responses.is_empty(),
                "{scenario}: no response was committed"
            );
        } else {
            assert_eq!(
                responses.len(),
                1,
                "{scenario}: queued discovery response was lost: {stdout}"
            );
            assert_eq!(
                responses[0]["result"]["supportedVersions"],
                serde_json::json!(["2026-07-28"])
            );
            assert!(responses[0].get("error").is_none(), "{scenario}");
            assert_eq!(
                frames.first(),
                Some(responses[0]),
                "{scenario}: flush must precede close completion"
            );
        }
    }
}

#[test]
fn process_owned_custom_transport_flushes_pending_data_before_exit() {
    run_process_owned_transport_test(
        "process_owned_custom_transport_flushes_pending_data_before_exit",
        false,
    );
}

#[test]
fn process_owned_custom_transport_close_failure_changes_exit_status() {
    run_process_owned_transport_test(
        "process_owned_custom_transport_close_failure_changes_exit_status",
        true,
    );
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

#[test]
fn srv_01_i_positive() {
    let server = Server::new("stateless-integration-runtime", "1.0.0")
        .tool(Greet)
        .build();
    let inbound =
        InboundRequestContext::new(Cx::for_testing(), 75, InboundRequestTransport::Memory);
    let request = JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "greet",
            "arguments": {"name": "FastMCP"},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })),
        75_i64,
    );

    let response = server
        .dispatch_stateless(&inbound, &request)
        .expect("stateless integration dispatch with id must receive response");

    assert!(response.error.is_none());
    assert_eq!(
        response
            .result
            .as_ref()
            .and_then(|result| result.pointer("/content/0/text"))
            .and_then(serde_json::Value::as_str),
        Some("Hello, FastMCP!")
    );
    assert_eq!(response.id, request.id);
}

#[test]
fn srv_01_i_planted_negative() {
    let server = Server::new("stateless-integration-refusal", "1.0.0")
        .tool(Greet)
        .build();
    let inbound =
        InboundRequestContext::new(Cx::for_testing(), 76, InboundRequestTransport::Memory);
    let baseline = JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "greet",
            "arguments": {"name": "FastMCP"},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })),
        76_i64,
    );
    let mut planted = baseline.clone();
    planted
        .params
        .as_mut()
        .and_then(|params| params.pointer_mut("/_meta/io.modelcontextprotocol~1protocolVersion"))
        .expect("modern metadata must contain protocolVersion")
        .clone_from(&serde_json::json!("2025-11-25"));

    assert_eq!(baseline.method, planted.method);
    assert_eq!(baseline.jsonrpc, planted.jsonrpc);
    assert_eq!(baseline.id, planted.id);
    let planted_input_before =
        serde_json::to_vec(&planted).expect("planted request must serialize");
    let catalog_before = stateless_public_catalog_snapshot(&server);

    let baseline_response = server
        .dispatch_stateless(&inbound, &baseline)
        .expect("baseline request receives response");
    assert!(baseline_response.error.is_none());

    let (transport, probe) = RuntimeTransport::single_request(planted.clone());
    let error = Server::new("stateless-integration-refusal-rt", "1.0.0")
        .tool(Greet)
        .build()
        .run_transport_returning_with_cx(&Cx::for_testing(), transport)
        .expect_err("unsupported 2025-11-25 must fail at runtime version admission boundary");
    assert_eq!(error.code, McpErrorCode::InternalError);
    let outgoing = probe.outgoing();
    assert_eq!(outgoing.len(), 1);
    let JsonRpcMessage::Response(refusal) = &outgoing[0] else {
        panic!("emits JSON-RPC response");
    };
    assert_eq!(
        refusal.error.as_ref().map(|err| err.code.clone()),
        Some(McpErrorCode::InvalidRequest.into())
    );
    assert_eq!(
        serde_json::to_vec(&planted).expect("planted request remains serializable"),
        planted_input_before,
        "typed refusal changed caller input"
    );
    assert_eq!(
        stateless_public_catalog_snapshot(&server),
        catalog_before,
        "typed refusal changed server catalog"
    );
}
