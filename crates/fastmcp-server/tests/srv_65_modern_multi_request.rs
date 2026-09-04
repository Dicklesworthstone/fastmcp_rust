//! GitHub #65: one server process must answer more than one modern request.
//!
//! A no-default-features server (the production `run_loop_pump_with_policy`
//! branch, not the `cfg(test)` dual-era implementation) answered
//! `server/discover` on stdio and then stopped producing responses: the next
//! `tools/list` on the same connection never got a reply and the process kept
//! waiting on stdin.
//!
//! This target is an ordinary integration test, so the library it links is the
//! one a downstream consumer gets. Built with `--no-default-features` it
//! exercises the shipped no-legacy dispatcher; built with the crate's default
//! `legacy-2024-11-05` it exercises the dual-era one. Both must handle the same
//! sequence, so the assertion is meaningful under either profile and the
//! `--no-default-features` run is the one that pins the regression.
//!
//! Every scenario runs on a real asupersync runtime (`fastmcp_core::block_on`),
//! never `Cx::for_testing`, and is bounded by a join deadline on a worker
//! thread: a regression fails the test instead of hanging CI.

use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::{McpContext, McpResult, block_on};
use fastmcp_derive::tool;
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};
use fastmcp_server::Server;
use fastmcp_transport::{Transport, TransportError, TransportRecvHalf, TransportSendHalf};

/// A regression must fail, not hang. Generous next to the milliseconds a
/// scripted in-memory transport needs (a healthy run finishes in well under a
/// second), and far below any CI job timeout, with enough slack that a loaded
/// shared runner cannot turn scheduling latency into a false red.
const SCENARIO_DEADLINE: Duration = Duration::from_secs(60);

const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";

#[tool(name = "echo", description = "Returns its argument unchanged")]
fn echo(ctx: &McpContext, value: String) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(value)
}

/// The exact `_meta` envelope the reporter's wire transcript carries.
fn modern_meta() -> serde_json::Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {"tools": {"listChanged": true}},
        "io.modelcontextprotocol/clientInfo": {
            "name": "stdio-multi-request-repro",
            "version": "0.0.1",
        },
    })
}

fn modern_request(method: &str, id: i64, extra: Option<serde_json::Value>) -> JsonRpcRequest {
    let mut params = serde_json::json!({ "_meta": modern_meta() });
    if let Some(serde_json::Value::Object(fields)) = extra {
        let object = params
            .as_object_mut()
            .expect("modern request params are a JSON object");
        for (key, value) in fields {
            object.insert(key, value);
        }
    }
    JsonRpcRequest::new(method, Some(params), id)
}

#[derive(Default)]
struct ScriptedState {
    incoming: VecDeque<JsonRpcMessage>,
    outgoing: Vec<JsonRpcMessage>,
    closed: bool,
}

/// An in-memory full-duplex stand-in for the stdio pipe: it replays a fixed
/// request script and then reports `Closed`, exactly as a client that writes
/// its requests and closes stdin does.
struct ScriptedTransport {
    state: Arc<Mutex<ScriptedState>>,
}

#[derive(Clone)]
struct ScriptedProbe(Arc<Mutex<ScriptedState>>);

impl ScriptedTransport {
    fn new(requests: Vec<JsonRpcRequest>) -> (Self, ScriptedProbe) {
        let state = Arc::new(Mutex::new(ScriptedState {
            incoming: requests.into_iter().map(JsonRpcMessage::Request).collect(),
            ..ScriptedState::default()
        }));
        (
            Self {
                state: Arc::clone(&state),
            },
            ScriptedProbe(state),
        )
    }
}

impl ScriptedProbe {
    fn responses(&self) -> Vec<JsonRpcResponse> {
        self.0
            .lock()
            .expect("scripted transport mutex must not be poisoned")
            .outgoing
            .iter()
            .filter_map(|message| match message {
                JsonRpcMessage::Response(response) => Some(response.clone()),
                _ => None,
            })
            .collect()
    }

    fn closed(&self) -> bool {
        self.0
            .lock()
            .expect("scripted transport mutex must not be poisoned")
            .closed
    }
}

impl Transport for ScriptedTransport {
    fn send(&mut self, _cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        self.state
            .lock()
            .expect("scripted transport mutex must not be poisoned")
            .outgoing
            .push(message.clone());
        Ok(())
    }

    fn recv(&mut self, _cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        self.state
            .lock()
            .expect("scripted transport mutex must not be poisoned")
            .incoming
            .pop_front()
            .ok_or(TransportError::Closed)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.state
            .lock()
            .expect("scripted transport mutex must not be poisoned")
            .closed = true;
        Ok(())
    }
}

struct ScenarioOutcome {
    run: McpResult<()>,
    responses: Vec<JsonRpcResponse>,
    closed: bool,
}

/// Run one request script through the public transport runtime on a real
/// asupersync runtime, bounded by [`SCENARIO_DEADLINE`].
///
/// The pump is driven on its own thread and the outcome is handed back over a
/// channel, so a dispatcher that stops answering fails the assertion below
/// instead of parking the test process forever.
fn run_scenario(label: &'static str, requests: Vec<JsonRpcRequest>) -> ScenarioOutcome {
    let (transport, probe) = ScriptedTransport::new(requests);
    let (tx, rx) = mpsc::channel();
    let probe_for_thread = probe.clone();
    let worker = std::thread::Builder::new()
        .name(format!("srv-65-{label}"))
        .spawn(move || {
            let run = block_on(async move {
                let cx = Cx::current().expect("the asupersync runtime installs a current Cx");
                Server::new("srv-65-multi-request", "1.0.0")
                    .tool(Echo)
                    .build()
                    .run_transport_returning_with_cx(&cx, transport)
            });
            // Send before the thread ends so the receiver never waits on a
            // join that a panicking dispatcher would never complete.
            let _ = tx.send(ScenarioOutcome {
                run,
                responses: probe_for_thread.responses(),
                closed: probe_for_thread.closed(),
            });
        })
        .expect("the scenario worker thread must start");

    match rx.recv_timeout(SCENARIO_DEADLINE) {
        Ok(outcome) => {
            worker.join().expect("the scenario worker must not panic");
            outcome
        }
        Err(timeout) => panic!(
            "[{label}] the server stopped answering ({timeout}): no outcome within \
             {SCENARIO_DEADLINE:?}. Responses observed so far: {:?}",
            probe
                .responses()
                .iter()
                .map(|response| response.id.clone())
                .collect::<Vec<_>>()
        ),
    }
}

/// The receive half of [`ScriptedTransport`], for the split entry point.
struct ScriptedRecvHalf {
    state: Arc<Mutex<ScriptedState>>,
}

/// The send half of [`ScriptedTransport`], for the split entry point.
struct ScriptedSendHalf {
    state: Arc<Mutex<ScriptedState>>,
}

impl TransportRecvHalf for ScriptedRecvHalf {
    fn recv(&mut self, _cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        self.state
            .lock()
            .expect("scripted transport mutex must not be poisoned")
            .incoming
            .pop_front()
            .ok_or(TransportError::Closed)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.state
            .lock()
            .expect("scripted transport mutex must not be poisoned")
            .closed = true;
        Ok(())
    }
}

impl TransportSendHalf for ScriptedSendHalf {
    fn send(&mut self, _cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        self.state
            .lock()
            .expect("scripted transport mutex must not be poisoned")
            .outgoing
            .push(message.clone());
        Ok(())
    }

    fn close(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

fn scripted_halves(
    requests: Vec<JsonRpcRequest>,
) -> (ScriptedRecvHalf, ScriptedSendHalf, ScriptedProbe) {
    let state = Arc::new(Mutex::new(ScriptedState {
        incoming: requests.into_iter().map(JsonRpcMessage::Request).collect(),
        ..ScriptedState::default()
    }));
    (
        ScriptedRecvHalf {
            state: Arc::clone(&state),
        },
        ScriptedSendHalf {
            state: Arc::clone(&state),
        },
        ScriptedProbe(state),
    )
}

/// Run a request script in the exact arrangement `Server::run_stdio_with_cx`
/// uses: the receive pump is a caller-owned BLOCKING child, and the caller's
/// runtime context is handed in separately as the dispatch context.
///
/// This is the shape the report was filed against — the production no-legacy
/// pump names that parameter `_dispatch_cx` and drives request futures from the
/// blocking receive-pump context instead — so the multi-request contract has to
/// hold here, not only on the simpler same-context transport entry point.
fn run_stdio_shaped_scenario(
    label: &'static str,
    requests: Vec<JsonRpcRequest>,
) -> ScenarioOutcome {
    let (recv_half, send_half, probe) = scripted_halves(requests);
    let (tx, rx) = mpsc::channel();
    let probe_for_thread = probe.clone();
    let worker = std::thread::Builder::new()
        .name(format!("srv-65-stdio-{label}"))
        .spawn(move || {
            let run = block_on(async move {
                let cx = Cx::current().expect("the asupersync runtime installs a current Cx");
                let dispatch_cx = cx.clone();
                let server = Server::new("srv-65-stdio-shaped", "1.0.0")
                    .tool(Echo)
                    .build();
                let mut pump = match cx.spawn_blocking(move |pump_cx| {
                    server.run_split_transport_returning_with_dispatch_cx(
                        &pump_cx,
                        &dispatch_cx,
                        recv_half,
                        send_half,
                    )
                }) {
                    Ok(pump) => pump,
                    Err(error) => {
                        panic!(
                            "the caller runtime must admit the pump as a blocking child: {error:?}"
                        )
                    }
                };
                pump.join(&cx)
                    .await
                    .expect("the caller-owned pump must report a final status")
            });
            let _ = tx.send(ScenarioOutcome {
                run,
                responses: probe_for_thread.responses(),
                closed: probe_for_thread.closed(),
            });
        })
        .expect("the scenario worker thread must start");

    match rx.recv_timeout(SCENARIO_DEADLINE) {
        Ok(outcome) => {
            worker.join().expect("the scenario worker must not panic");
            outcome
        }
        Err(timeout) => panic!(
            "[{label}] the stdio-shaped pump stopped answering ({timeout}): no outcome \
             within {SCENARIO_DEADLINE:?}. Responses observed so far: {:?}",
            probe
                .responses()
                .iter()
                .map(|response| response.id.clone())
                .collect::<Vec<_>>()
        ),
    }
}

/// Find the response correlated to `expected_id`.
///
/// JSON-RPC responses are correlated by id, not by arrival order, and the
/// dual-era dispatcher answers concurrently — so the contract under test is
/// "every request is answered", never "answers arrive in request order".
fn response_for<'a>(
    responses: &'a [JsonRpcResponse],
    expected_id: i64,
    label: &str,
) -> &'a JsonRpcResponse {
    let wanted = JsonRpcRequest::new("probe", None, expected_id).id;
    responses
        .iter()
        .find(|response| response.id == wanted)
        .unwrap_or_else(|| {
            panic!(
                "{label}: no response correlated to request id {expected_id}; got {:?}",
                responses
                    .iter()
                    .map(|response| response.id.clone())
                    .collect::<Vec<_>>()
            )
        })
}

fn assert_ok_response(response: &JsonRpcResponse, label: &str) {
    assert!(
        response.error.is_none(),
        "{label}: expected a result, got error {:?}",
        response.error
    );
}

/// Acceptance criterion 3: one process answers
/// `server/discover -> tools/list -> tools/call -> tools/list`.
#[test]
fn srv_65_one_process_answers_a_modern_request_sequence() {
    let outcome = run_scenario(
        "sequence",
        vec![
            modern_request("server/discover", 1, None),
            modern_request("tools/list", 2, None),
            modern_request(
                "tools/call",
                3,
                Some(serde_json::json!({
                    "name": "echo",
                    "arguments": {"value": "pong"},
                })),
            ),
            modern_request("tools/list", 4, None),
        ],
    );

    assert!(
        outcome.run.is_ok(),
        "the modern transport runtime must close cleanly: {:?}",
        outcome.run.as_ref().err()
    );
    assert_eq!(
        outcome.responses.len(),
        4,
        "every modern request on one connection must be answered; got ids {:?}",
        outcome
            .responses
            .iter()
            .map(|response| response.id.clone())
            .collect::<Vec<_>>()
    );
    for expected_id in [1_i64, 2, 3, 4] {
        assert_ok_response(
            response_for(&outcome.responses, expected_id, "modern request sequence"),
            "modern request sequence",
        );
    }
    let discover = response_for(&outcome.responses, 1, "modern request sequence")
        .result
        .as_ref()
        .expect("server/discover returns a result");
    assert_eq!(
        discover.get("supportedVersions"),
        Some(&serde_json::json!([MODERN_PROTOCOL_VERSION])),
        "the first response must still be the modern discovery result"
    );
    let tools = response_for(&outcome.responses, 2, "modern request sequence")
        .result
        .as_ref()
        .and_then(|result| result.get("tools"))
        .and_then(serde_json::Value::as_array)
        .expect("tools/list returns a tools array");
    assert!(
        tools
            .iter()
            .any(|tool| tool.get("name") == Some(&serde_json::json!("echo"))),
        "the second response must be this server's real tool catalog: {tools:?}"
    );
    assert!(
        outcome.closed,
        "the runtime must close the transport it owned"
    );
}

/// The minimal transcript from the report: discover then tools/list.
#[test]
fn srv_65_second_request_after_discover_is_answered() {
    let outcome = run_scenario(
        "discover-then-list",
        vec![
            modern_request("server/discover", 1, None),
            modern_request("tools/list", 2, None),
        ],
    );

    assert!(
        outcome.run.is_ok(),
        "the two-request transcript must close cleanly: {:?}",
        outcome.run.as_ref().err()
    );
    assert_eq!(
        outcome.responses.len(),
        2,
        "the reported transcript produced only the server/discover response"
    );
    assert_ok_response(
        response_for(&outcome.responses, 1, "discover then list"),
        "server/discover",
    );
    assert_ok_response(
        response_for(&outcome.responses, 2, "discover then list"),
        "tools/list after discover",
    );
}

/// Planted negative: the era gate must still refuse a second request that
/// drops the modern protocol version, so the fix above cannot be a blanket
/// "answer everything" relaxation.
#[test]
fn srv_65_second_request_without_modern_metadata_is_refused() {
    let outcome = run_scenario(
        "downgrade",
        vec![
            modern_request("server/discover", 1, None),
            JsonRpcRequest::new("tools/list", Some(serde_json::json!({})), 2_i64),
        ],
    );

    assert_eq!(
        outcome.responses.len(),
        2,
        "the refusal itself must be delivered, not silently dropped"
    );
    assert_ok_response(
        response_for(&outcome.responses, 1, "downgrade"),
        "server/discover",
    );
    assert!(
        response_for(&outcome.responses, 2, "downgrade")
            .error
            .is_some(),
        "a second request without the 2026-07-28 envelope must be refused, not served"
    );
}

/// Acceptance criterion 4, in the arrangement the report used: the blocking
/// receive pump plus a separate caller-owned dispatch context must still admit
/// every request on the connection, not just the first.
#[test]
fn srv_65_stdio_shaped_pump_answers_a_modern_request_sequence() {
    let outcome = run_stdio_shaped_scenario(
        "sequence",
        vec![
            modern_request("server/discover", 1, None),
            modern_request("tools/list", 2, None),
            modern_request(
                "tools/call",
                3,
                Some(serde_json::json!({
                    "name": "echo",
                    "arguments": {"value": "pong"},
                })),
            ),
            modern_request("tools/list", 4, None),
        ],
    );

    assert!(
        outcome.run.is_ok(),
        "the stdio-shaped pump must close cleanly: {:?}",
        outcome.run.as_ref().err()
    );
    assert_eq!(
        outcome.responses.len(),
        4,
        "the stdio-shaped pump answered only {} of 4 modern requests (ids {:?})",
        outcome.responses.len(),
        outcome
            .responses
            .iter()
            .map(|response| response.id.clone())
            .collect::<Vec<_>>()
    );
    for expected_id in [1_i64, 2, 3, 4] {
        assert_ok_response(
            response_for(
                &outcome.responses,
                expected_id,
                "stdio-shaped request sequence",
            ),
            "stdio-shaped request sequence",
        );
    }
    assert!(
        outcome.closed,
        "the stdio-shaped runtime must close the receive half it owned"
    );
}
