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
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::{McpContext, McpOutcome, McpResult, block_on};
use fastmcp_derive::tool;
use fastmcp_protocol::{Content, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, Tool};
use fastmcp_server::{FinalToolOutcome, Server, ToolHandler};
use fastmcp_transport::{Codec, Transport, TransportError, TransportRecvHalf, TransportSendHalf};

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

#[derive(Default)]
struct PendingControl {
    entered: AtomicUsize,
    active: AtomicUsize,
    released: AtomicBool,
}

struct PendingTool(Arc<PendingControl>);

struct ActiveInvocation(Arc<PendingControl>);

impl Drop for ActiveInvocation {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ToolHandler for PendingTool {
    fn execution_mode(&self) -> fastmcp_server::ToolExecutionMode {
        fastmcp_server::ToolExecutionMode::Async
    }

    fn definition(&self) -> Tool {
        let mut definition = Echo.definition();
        definition.name = "pending".to_owned();
        definition
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Echo.call(ctx, arguments)
    }

    fn call_final_outcome_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: serde_json::Value,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = McpOutcome<FinalToolOutcome>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.0.active.fetch_add(1, Ordering::AcqRel);
            let _active = ActiveInvocation(Arc::clone(&self.0));
            self.0.entered.fetch_add(1, Ordering::AcqRel);
            while !self.0.released.load(Ordering::Acquire) {
                if let Err(error) = ctx.checkpoint() {
                    return McpOutcome::Err(error.into());
                }
                asupersync::time::sleep(ctx.cx().now(), Duration::from_millis(5)).await;
            }
            match Echo.call_final(ctx, arguments) {
                Ok(result) => McpOutcome::Ok(FinalToolOutcome::Complete(result)),
                Err(error) => McpOutcome::Err(error),
            }
        })
    }
}

struct WireRecv(BufReader<TcpStream>);
struct WireSend(TcpStream, Arc<AtomicUsize>);

fn read_wire(reader: &mut BufReader<TcpStream>) -> Result<JsonRpcMessage, TransportError> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(TransportError::Closed);
    }
    Codec::new()
        .decode_complete_message(line.as_bytes())
        .map_err(TransportError::Codec)
}

fn write_wire(stream: &mut TcpStream, message: &JsonRpcMessage) -> Result<(), TransportError> {
    let codec = Codec::new();
    let bytes = match message {
        JsonRpcMessage::Request(request) => codec.encode_request(request),
        JsonRpcMessage::Response(response) => codec.encode_response(response),
    }
    .map_err(TransportError::Codec)?;
    stream.write_all(&bytes)?;
    Ok(())
}

impl TransportRecvHalf for WireRecv {
    fn recv(&mut self, _cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        read_wire(&mut self.0)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.0.get_ref().shutdown(Shutdown::Read)?;
        Ok(())
    }
}

impl TransportSendHalf for WireSend {
    fn send(&mut self, _cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        eprintln!(
            "modern-pump outbound={}",
            serde_json::to_string(message).unwrap()
        );
        write_wire(&mut self.0, message)?;
        self.1.fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.0.shutdown(Shutdown::Write)?;
        Ok(())
    }
}

/// Real socket bytes and the public split runner. A single async worker owns
/// the request children while the receive pump occupies a blocking worker.
/// Cleanup releases even a regressed sequential handler before joining it.
struct WireScenario {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    control: Arc<PendingControl>,
    shutdown: Arc<AtomicBool>,
    shutdown_active: Arc<AtomicUsize>,
    outcome: mpsc::Receiver<McpResult<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
    subject: String,
    input_closed: bool,
}

impl WireScenario {
    fn start() -> Self {
        Self::start_with_dispatch(true)
    }

    fn start_with_dispatch(separate_dispatch: bool) -> Self {
        Self::start_with_options(separate_dispatch, false)
    }

    fn start_with_options(separate_dispatch: bool, hold_first_poll: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let writer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_socket, peer) = listener.accept().unwrap();
        writer
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        writer
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        server_socket
            .set_read_timeout(Some(SCENARIO_DEADLINE))
            .unwrap();
        server_socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let reader = BufReader::new(writer.try_clone().unwrap());
        let control = Arc::new(PendingControl::default());
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_active = Arc::new(AtomicUsize::new(usize::MAX));
        let shutdown_probe = Arc::clone(&shutdown);
        let shutdown_active_probe = Arc::clone(&shutdown_active);
        let shutdown_control = Arc::clone(&control);
        let server = Server::new("modern-owned-pump", "1.0.0")
            .tool(Echo)
            .tool(PendingTool(Arc::clone(&control)))
            .on_shutdown(move || {
                shutdown_active_probe.store(
                    shutdown_control.active.load(Ordering::Acquire),
                    Ordering::Release,
                );
                shutdown_probe.store(true, Ordering::Release);
            })
            .build();
        let response_count = Arc::new(AtomicUsize::new(0));
        let recv = WireRecv(BufReader::new(server_socket.try_clone().unwrap()));
        let send = WireSend(server_socket, Arc::clone(&response_count));
        let (tx, outcome) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .blocking_threads(0, 4)
                .build()
                .unwrap();
            let result = runtime.block_on(async move {
                let root = Cx::current().unwrap();
                if !separate_dispatch {
                    return server.run_split_transport_returning_with_cx(&root, recv, send);
                }
                let dispatch_cx = root.clone();
                let (started_tx, started_rx) = mpsc::sync_channel(1);
                let (ingress_tx, ingress_rx) = mpsc::sync_channel(1);
                let mut pump = root
                    .spawn_blocking(move |pump_cx| {
                        if hold_first_poll {
                            started_tx.send(()).unwrap();
                            ingress_rx
                                .recv_timeout(Duration::from_secs(3))
                                .expect("scheduler worker must permit ingress");
                        }
                        server.run_split_transport_returning_with_dispatch_cx(
                            &pump_cx,
                            &dispatch_cx,
                            recv,
                            send,
                        )
                    })
                    .unwrap();
                if hold_first_poll {
                    // block_on uses the caller thread. Let spawn_blocking's
                    // async wrapper run on the separate scheduler worker and
                    // start the pump before deliberately occupying that worker.
                    started_rx
                        .recv_timeout(Duration::from_secs(3))
                        .expect("blocking pump must start before holding the worker");
                    let mut held_worker = root
                        .spawn(move |_cx| async move {
                            // No input reaches dispatch until this task owns
                            // the only worker. The auth probe is answered by
                            // the blocking pump without polling a request child.
                            ingress_tx.send(()).unwrap();
                            let deadline = std::time::Instant::now() + Duration::from_secs(3);
                            while response_count.load(Ordering::Acquire) == 0
                                && std::time::Instant::now() < deadline
                            {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            assert_eq!(response_count.load(Ordering::Acquire), 1);
                        })
                        .expect("hold task must run on the scheduler worker");
                    held_worker
                        .join(&root)
                        .await
                        .expect("held worker must join");
                }
                pump.join(&root).await.expect("pump child must join")
            });
            let _ = tx.send(result);
        });
        Self {
            reader,
            writer,
            control,
            shutdown,
            shutdown_active,
            outcome,
            worker: Some(worker),
            subject: format!("socket-{peer}"),
            input_closed: false,
        }
    }

    fn send(&mut self, request: JsonRpcRequest) {
        write_wire(&mut self.writer, &JsonRpcMessage::Request(request)).unwrap();
    }

    fn response(&mut self, id: i64) -> JsonRpcResponse {
        let message = read_wire(&mut self.reader)
            .expect("request must receive a response within the wire deadline");
        let JsonRpcMessage::Response(response) = message else {
            panic!("expected response, got {message:?}");
        };
        assert_eq!(response.id, Some(id.into()), "wrong correlated response");
        response
    }

    fn pending(&mut self, id: i64) {
        self.send(modern_request(
            "tools/call",
            id,
            Some(serde_json::json!({
                "name": "pending", "arguments": {"value": self.subject},
            })),
        ));
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while self.control.entered.load(Ordering::Acquire) == 0
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            self.control.entered.load(Ordering::Acquire),
            1,
            "pending handler must actually start; shutdown={}",
            self.shutdown.load(Ordering::Acquire)
        );
    }

    fn cancel(&mut self, id: i64) {
        let mut request = modern_request(
            "notifications/cancelled",
            0,
            Some(serde_json::json!({"requestId": id})),
        );
        request.id = None;
        self.send(request);
    }

    fn close_input(&mut self) {
        assert!(!self.input_closed, "input EOF is emitted exactly once");
        self.writer.shutdown(Shutdown::Write).unwrap();
        self.input_closed = true;
    }

    fn finish(&mut self) {
        self.control.released.store(true, Ordering::Release);
        if !self.input_closed {
            self.close_input();
        }
        let result = self
            .outcome
            .recv_timeout(SCENARIO_DEADLINE)
            .expect("pump must settle before cleanup");
        self.worker.take().unwrap().join().unwrap();
        assert!(result.is_ok(), "returning pump failed: {result:?}");
        assert!(self.shutdown.load(Ordering::Acquire));
        assert_eq!(
            self.shutdown_active.load(Ordering::Acquire),
            0,
            "shutdown must follow handler cleanup"
        );
    }
}

impl Drop for WireScenario {
    fn drop(&mut self) {
        self.control.released.store(true, Ordering::Release);
        let _ = self.writer.shutdown(Shutdown::Write);
        if self.worker.is_some() && self.outcome.recv_timeout(SCENARIO_DEADLINE).is_ok() {
            let _ = self.worker.take().unwrap().join();
        }
    }
}

#[test]
fn srv_65_modern_pending_request_allows_other_requests() {
    // The no-legacy synchronous split entry point must also make progress
    // when its caller supplies the same context for ingress and dispatch.
    // The unchanged dual-era pump requires a separate dispatch Cx.
    let dispatch_modes: &[bool] = if cfg!(feature = "legacy-2024-11-05") {
        &[true]
    } else {
        &[true, false]
    };
    for &separate_dispatch in dispatch_modes {
        let mut wire = WireScenario::start_with_dispatch(separate_dispatch);
        wire.pending(10);
        wire.send(modern_request("tools/list", 11, None));
        assert_ok_response(&wire.response(11), "catalog while handler pending");
        assert_eq!(wire.control.active.load(Ordering::Acquire), 1);
        wire.control.released.store(true, Ordering::Release);
        let response = wire.response(10);
        assert_ok_response(&response, "released handler");
        assert_eq!(response.result.unwrap()["content"][0]["text"], wire.subject);
        wire.finish();
    }
}

#[test]
fn srv_65_modern_cancellation_preserves_unrelated_request() {
    if !cfg!(feature = "legacy-2024-11-05") {
        for cancellation_id in [50, 999] {
            let mut queued = WireScenario::start_with_options(true, true);
            queued.control.released.store(true, Ordering::Release);
            queued.send(modern_request(
                "tools/call",
                50,
                Some(serde_json::json!({
                    "name": "pending", "arguments": {"value": queued.subject},
                })),
            ));
            queued.cancel(cancellation_id);
            // Admission rejects credentials without an auth provider on the
            // pump itself, before submitting an async child. Its response
            // proves the preceding cancellation was processed while the
            // original request still could not receive its first poll.
            queued.send(modern_request(
                "tools/list",
                52,
                Some(serde_json::json!({"token": "unadmitted-peer"})),
            ));
            assert_eq!(
                queued.response(52).error.unwrap().code,
                fastmcp_core::McpErrorCode::ResourceForbidden.into()
            );
            queued.send(modern_request("tools/list", 51, None));
            let responses = (0..2)
                .map(|_| match read_wire(&mut queued.reader).unwrap() {
                    JsonRpcMessage::Response(response) => response,
                    message => panic!("expected correlated response, got {message:?}"),
                })
                .collect::<Vec<_>>();
            let original = response_for(&responses, 50, "pre-poll cancellation");
            if cancellation_id == 50 {
                assert_eq!(
                    original.error.as_ref().unwrap().code,
                    fastmcp_core::McpErrorCode::RequestCancelled.into()
                );
                assert_eq!(queued.control.entered.load(Ordering::Acquire), 0);
            } else {
                assert_ok_response(original, "unknown target preserves queued request");
                assert_eq!(
                    original.result.as_ref().unwrap()["content"][0]["text"],
                    queued.subject
                );
                assert_eq!(queued.control.entered.load(Ordering::Acquire), 1);
            }
            assert_ok_response(
                response_for(&responses, 51, "pre-poll cancellation"),
                "catalog survives pre-poll cancellation",
            );
            queued.finish();
        }
    }
    let mut wire = WireScenario::start();
    wire.pending(20);
    let mut unauthenticated = modern_request(
        "notifications/cancelled",
        0,
        Some(serde_json::json!({"requestId": 20, "token": "unadmitted-peer"})),
    );
    unauthenticated.id = None;
    wire.send(unauthenticated);
    wire.send(modern_request("tools/list", 23, None));
    assert_ok_response(&wire.response(23), "catalog after rejected credentials");
    assert_eq!(
        wire.control.active.load(Ordering::Acquire),
        1,
        "unauthenticated cancellation must leave the handler running"
    );
    wire.cancel(999);
    wire.send(modern_request("tools/list", 21, None));
    assert_ok_response(&wire.response(21), "catalog after unrelated cancellation");
    assert_eq!(
        wire.control.active.load(Ordering::Acquire),
        1,
        "unknown ID must not cancel the active request"
    );
    wire.cancel(20);
    let response = wire.response(20);
    assert_eq!(
        response.error.unwrap().code,
        fastmcp_core::McpErrorCode::RequestCancelled.into()
    );
    assert_eq!(wire.control.active.load(Ordering::Acquire), 0);
    wire.send(modern_request("tools/list", 22, None));
    assert_ok_response(&wire.response(22), "catalog after target cancellation");
    wire.finish();
}

#[test]
fn srv_65_modern_duplicate_id_does_not_enter_handler() {
    let mut wire = WireScenario::start();
    wire.pending(30);
    wire.send(modern_request(
        "tools/call",
        30,
        Some(serde_json::json!({
            "name": "pending", "arguments": {"value": wire.subject},
        })),
    ));
    let duplicate = wire.response(30);
    assert_eq!(
        duplicate.error.unwrap().code,
        fastmcp_core::McpErrorCode::InvalidRequest.into()
    );
    assert_eq!(wire.control.entered.load(Ordering::Acquire), 1);
    assert_eq!(wire.control.active.load(Ordering::Acquire), 1);
    wire.control.released.store(true, Ordering::Release);
    assert_ok_response(
        &wire.response(30),
        "original request survives duplicate refusal",
    );
    wire.finish();
}

#[test]
fn srv_65_modern_subscription_drains_before_shutdown() {
    let mut wire = WireScenario::start();
    wire.send(modern_request(
        "subscriptions/listen",
        40,
        Some(serde_json::json!({
            "notifications": {"toolsListChanged": true},
        })),
    ));
    let acknowledgement = read_wire(&mut wire.reader).unwrap();
    assert!(
        matches!(acknowledgement, JsonRpcMessage::Request(request) if request.method == "notifications/subscriptions/acknowledged")
    );
    wire.send(modern_request("tools/list", 41, None));
    assert_ok_response(&wire.response(41), "catalog while subscription pending");
    wire.close_input();
    let cancellation = read_wire(&mut wire.reader).unwrap();
    assert!(
        matches!(cancellation, JsonRpcMessage::Request(request) if request.method == "notifications/cancelled" && request.params.as_ref().unwrap()["requestId"] == 40)
    );
    let completion = wire.response(40);
    assert_ok_response(&completion, "graceful subscription completion");
    let result = completion.result.unwrap();
    assert_eq!(result["resultType"], "complete");
    assert_eq!(
        result["_meta"]["io.modelcontextprotocol/subscriptionId"],
        40
    );
    wire.finish();
}
