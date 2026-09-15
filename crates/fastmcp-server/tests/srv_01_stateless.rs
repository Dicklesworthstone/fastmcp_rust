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

#[cfg(feature = "tasks")]
#[test]
fn task_service_recovers_expired_dispatch_without_new_event() {
    assert_task_service_recovers_without_new_event(true);
}

#[cfg(feature = "tasks")]
#[test]
fn task_service_preserves_live_dispatch_without_new_event() {
    assert_task_service_recovers_without_new_event(false);
}

/// Exercises the shipped owner generation and runner, rather than the
/// server library's test-only fixed dispatch owner. Only lease age differs.
/// The 30-second boundary belongs to this concrete in-memory backend; this
/// test does not impose that lease duration on custom stores.
#[cfg(feature = "tasks")]
fn assert_task_service_recovers_without_new_event(expired: bool) {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    use asupersync::runtime::RuntimeBuilder;
    use fastmcp_protocol::tasks_extension::{
        FinalTaskCallToolResult, Task, TaskStatusNotification, TaskStatusNotificationParams,
    };
    use fastmcp_server::{
        ApplicationTaskSupervisor, FinalTaskRuntime, FinalTaskRuntimeConfig, FinalTaskStore,
        FinalTaskSupervisorFuture, FinalTaskSupervisorHandoff, FinalTaskWorkDescriptor,
        InMemoryFinalTaskStore,
    };

    struct CompleteRecoveredTask(Arc<AtomicUsize>);

    impl ApplicationTaskSupervisor for CompleteRecoveredTask {
        fn resume<'a>(
            &'a self,
            cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            Box::pin(async move {
                cx.checkpoint()
                    .expect("caller-owned supervisor remains live");
                self.0.fetch_add(1, Ordering::SeqCst);
                let FinalTaskSupervisorHandoff::Initial(work) = handoff else {
                    panic!("the retained initial descriptor must reach the initial hook");
                };
                assert_eq!(
                    work.work_descriptor(),
                    &FinalTaskWorkDescriptor::new(serde_json::json!({"operation": "recover"}))?
                );
                let result: FinalTaskCallToolResult = serde_json::from_value(serde_json::json!({
                    "content": [{"type": "text", "text": "recovered successfully"}]
                }))
                .expect("valid completed tool result");
                work.complete_task(result, None)?;
                Ok(())
            })
        }
    }

    let initial_time = Instant::now();
    let elapsed_ms = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(
        InMemoryFinalTaskStore::with_clock(2, {
            let elapsed_ms = Arc::clone(&elapsed_ms);
            Arc::new(move || {
                initial_time + Duration::from_millis(elapsed_ms.load(Ordering::SeqCst) as u64)
            })
        })
        .expect("bounded process-local store"),
    );
    let task: Task = serde_json::from_value(serde_json::json!({
        "taskId": "retained-operation", "status": "working",
        "createdAt": "2026-07-28T12:00:00.000Z",
        "lastUpdatedAt": "2026-07-28T12:00:00.000Z", "ttlMs": 60000
    }))
    .expect("valid retained task");
    let task_id = task.base().task_id.clone();
    let notification = TaskStatusNotification::new(TaskStatusNotificationParams {
        task: task.clone(),
        meta: None,
        additional: std::collections::BTreeMap::default(),
    });
    store
        .create_task_with_work(
            task.clone(),
            notification.clone(),
            FinalTaskWorkDescriptor::new(serde_json::json!({"operation": "recover"}))
                .expect("bounded work descriptor"),
        )
        .expect("retained work exists before the new service starts");
    let snapshot = store.get_task_snapshot(&task_id).unwrap().unwrap();
    let previous_owner = "previous-application-instance";
    assert!(
        store
            .take_initial_work_handoff_for_owner_if_current(&snapshot, previous_owner)
            .unwrap()
            .is_some()
    );
    let old_fence = store
        .begin_handoff_dispatch_for_owner_if_current(
            &task_id,
            snapshot.generation(),
            previous_owner,
        )
        .unwrap()
        .expect("previous owner elected its dispatch");
    let calls = Arc::new(AtomicUsize::new(0));
    let emitted = Arc::new(AtomicUsize::new(0));
    let runtime = FinalTaskRuntime::new(
        store.clone(),
        FinalTaskRuntimeConfig::new(60000, None).unwrap(),
        {
            let emitted = Arc::clone(&emitted);
            Arc::new(move |_| {
                emitted.fetch_add(1, Ordering::SeqCst);
            })
        },
    );
    let mut runner = runtime
        .install_task_service(1, Arc::new(CompleteRecoveredTask(Arc::clone(&calls))))
        .unwrap();
    let application = RuntimeBuilder::current_thread().build().unwrap();
    application.block_on(async {
        let cx = Cx::current().expect("application-owned runtime context");
        let mut service = std::pin::pin!(runner.run_service(&cx));
        let mut observation_bound =
            std::pin::pin!(asupersync::time::sleep(cx.now(), Duration::from_secs(3)));
        let mut entered = false;
        poll_fn(|task_cx| {
            // Check the independent observation bound before polling the
            // service: its timeout wake must not itself trigger a late scan
            // and masquerade as the service's own recovery wake.
            if observation_bound.as_mut().poll(task_cx).is_ready() {
                assert!(
                    !expired,
                    "expired work remained stranded without a new event"
                );
                return Poll::Ready(());
            }
            if let Poll::Ready(result) = service.as_mut().poll(task_cx) {
                panic!("service must remain ready while its caller is live: {result:?}");
            }
            if !entered {
                assert!(runtime.is_task_service_ready());
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                // No store method or channel signal follows this advancement.
                // The runner's own timer must cause the next recovery scan.
                elapsed_ms.store(if expired { 30000 } else { 29999 }, Ordering::SeqCst);
                entered = true;
            }
            if expired && calls.load(Ordering::SeqCst) == 1 {
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await;
    });
    assert!(
        !runtime.is_task_service_ready(),
        "dropping the run revokes readiness"
    );
    let current = store.get_task_snapshot(&task_id).unwrap().unwrap();
    if expired {
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(emitted.load(Ordering::SeqCst), 1);
        let value = serde_json::to_value(current.task()).unwrap();
        assert_eq!(value["status"], "completed");
        assert_eq!(
            value["result"]["content"][0]["text"],
            "recovered successfully"
        );
        assert!(
            !store
                .renew_handoff_dispatch_if_current(
                    &task_id,
                    snapshot.generation(),
                    previous_owner,
                    old_fence
                )
                .unwrap(),
            "late predecessor cannot regain the recovered operation"
        );
    } else {
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(emitted.load(Ordering::SeqCst), 0);
        assert_eq!(current.generation(), snapshot.generation());
        assert_eq!(
            serde_json::to_value(current.task()).unwrap(),
            serde_json::to_value(task).unwrap()
        );
        assert_eq!(
            serde_json::to_value(store.latest_notification(&task_id)).unwrap(),
            serde_json::to_value(Some(notification)).unwrap(),
        );
    }
}

#[cfg(feature = "tasks")]
#[test]
fn task_service_fresh_input_key_completes_second_round() {
    assert_task_service_two_round_input_keys(false);
}

#[cfg(feature = "tasks")]
#[test]
fn task_service_reused_input_key_rejects_without_transition() {
    assert_task_service_two_round_input_keys(true);
}

/// Validates multi-round task input lifecycle and cross-round key uniqueness.
///
/// When `reused` is false, round 1 requests `roots_a` and round 2 requests fresh
/// `roots_b`. Replaying round 1's `roots_a` response during round 2 must be ignored
/// by the outstanding-key filter, leaving the task in `InputRequired` without
/// triggering a premature resumption. Only the fresh `roots_b` response returns the
/// task to `Working` and completes it.
///
/// When `reused` is true, round 2 attempts to reuse `roots_a`. The store must
/// reject the transition with an invalid parameter error, leaving task status,
/// generation, and latest notification unmutated. The same authorized handoff must
/// then successfully issue fresh `roots_b` and complete, proving the rejection did
/// not invalidate the handoff authority or fence.
#[cfg(feature = "tasks")]
fn assert_task_service_two_round_input_keys(reused: bool) {
    use std::future::{Future, poll_fn};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::Poll;
    use std::time::Duration;

    use asupersync::CancelKind;
    use asupersync::runtime::RuntimeBuilder;
    use fastmcp_core::{McpError, McpErrorCode};
    use fastmcp_protocol::tasks_extension::{
        FinalTaskCallToolResult, Task, TaskInputRequests, TaskInputResponses,
        TaskStatusNotification, TaskStatusNotificationParams,
    };
    use fastmcp_server::{
        ApplicationTaskSupervisor, FinalTaskRuntime, FinalTaskRuntimeConfig,
        FinalTaskSnapshot, FinalTaskStore, FinalTaskSupervisorFuture,
        FinalTaskSupervisorHandoff, FinalTaskWorkDescriptor, InMemoryFinalTaskStore,
    };

    struct TwoRoundSupervisor {
        calls: Arc<AtomicUsize>,
        resumed_calls: Arc<AtomicUsize>,
        reused: bool,
        observed_rejection: Arc<Mutex<Option<McpError>>>,
        store: Arc<InMemoryFinalTaskStore>,
        emitted: Arc<AtomicUsize>,
    }

    impl ApplicationTaskSupervisor for TwoRoundSupervisor {
        fn resume<'a>(
            &'a self,
            cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            Box::pin(async move {
                cx.checkpoint()
                    .expect("caller-owned supervisor remains live");
                self.calls.fetch_add(1, Ordering::SeqCst);
                match handoff {
                    FinalTaskSupervisorHandoff::Initial(initial) => {
                        let roots_a: TaskInputRequests = serde_json::from_value(serde_json::json!({
                            "roots_a": {"method": "roots/list"}
                        }))
                        .expect("valid roots_a request");
                        initial
                            .require_input(roots_a, Some("awaiting roots_a".to_owned()))
                            .expect("initial require_input enters input_required");
                    }
                    FinalTaskSupervisorHandoff::Resumed(accepted) => {
                        let resumptions = self.resumed_calls.fetch_add(1, Ordering::SeqCst);
                        if resumptions == 0 {
                            assert!(
                                accepted.input_responses().contains_key("roots_a"),
                                "first resumption must carry roots_a input response"
                            );
                            let roots_a: TaskInputRequests = serde_json::from_value(serde_json::json!({
                                "roots_a": {"method": "roots/list"}
                            }))
                            .expect("valid roots_a request");
                            let roots_b: TaskInputRequests = serde_json::from_value(serde_json::json!({
                                "roots_b": {"method": "roots/list"}
                            }))
                            .expect("valid roots_b request");

                            if self.reused {
                                let task_id = accepted.task_id().clone();
                                let pre_snapshot = self
                                    .store
                                    .get_task_snapshot(&task_id)
                                    .expect("read pre-snapshot")
                                    .expect("task exists");
                                let pre_notification = self
                                    .store
                                    .latest_notification(&task_id)
                                    .expect("read pre-notification");
                                let pre_emitted = self.emitted.load(Ordering::SeqCst);
                                assert_eq!(
                                    pre_emitted, 2,
                                    "exactly 2 notifications emitted before duplicate attempt"
                                );

                                // Attempting to reuse roots_a must fail closed.
                                let rejection = accepted
                                    .require_input(roots_a, Some("attempt reused roots_a".to_owned()))
                                    .expect_err("reusing input key across rounds must reject");
                                assert_eq!(rejection.code, McpErrorCode::InvalidParams);
                                assert_eq!(
                                    rejection.message,
                                    "Task input request keys cannot be reused"
                                );

                                // Invariance: task status, generation, notification, and emitted count remain unchanged.
                                let post_snapshot = self
                                    .store
                                    .get_task_snapshot(&task_id)
                                    .expect("read post-snapshot")
                                    .expect("task exists");
                                assert_eq!(pre_snapshot.generation(), post_snapshot.generation());
                                assert_eq!(
                                    serde_json::to_value(pre_snapshot.task()).unwrap(),
                                    serde_json::to_value(post_snapshot.task()).unwrap()
                                );
                                assert_eq!(
                                    pre_snapshot.authenticated_principal(),
                                    post_snapshot.authenticated_principal()
                                );
                                let post_notification = self
                                    .store
                                    .latest_notification(&task_id)
                                    .expect("read post-notification");
                                assert_eq!(
                                    serde_json::to_value(&pre_notification).unwrap(),
                                    serde_json::to_value(&post_notification).unwrap()
                                );
                                assert_eq!(
                                    self.emitted.load(Ordering::SeqCst),
                                    pre_emitted,
                                    "rejected duplicate input key reuse must not emit any notification"
                                );
                                *self.observed_rejection.lock().unwrap() = Some(rejection);

                                // Same authorized handoff issues fresh roots_b successfully.
                                accepted
                                    .require_input(
                                        roots_b,
                                        Some("awaiting roots_b after rejected duplicate".to_owned()),
                                    )
                                    .expect("fresh key under same handoff must succeed");
                            } else {
                                accepted
                                    .require_input(roots_b, Some("awaiting roots_b".to_owned()))
                                    .expect("fresh key roots_b must succeed");
                            }
                        } else if resumptions == 1 {
                            assert!(
                                accepted.input_responses().contains_key("roots_b"),
                                "second resumption must carry roots_b input response"
                            );
                            let result: FinalTaskCallToolResult = serde_json::from_value(serde_json::json!({
                                "content": [{"type": "text", "text": "two rounds completed successfully"}]
                            }))
                            .expect("valid completed tool result");
                            accepted
                                .complete_task(result, Some("completed two rounds".to_owned()))
                                .expect("terminal complete_task must succeed");
                        } else {
                            panic!("unexpected extra resumption: {resumptions}");
                        }
                    }
                }
                Ok(())
            })
        }
    }

    let store = Arc::new(InMemoryFinalTaskStore::new(4).expect("bounded store"));
    let task: Task = serde_json::from_value(serde_json::json!({
        "taskId": "two-round-input-task", "status": "working",
        "createdAt": "2026-07-28T12:00:00.000Z",
        "lastUpdatedAt": "2026-07-28T12:00:00.000Z", "ttlMs": 60000
    }))
    .expect("valid task");
    let task_id = task.base().task_id.clone();
    let notification = TaskStatusNotification::new(TaskStatusNotificationParams {
        task: task.clone(),
        meta: None,
        additional: std::collections::BTreeMap::default(),
    });
    store
        .create_task_with_work(
            task.clone(),
            notification.clone(),
            FinalTaskWorkDescriptor::new(serde_json::json!({"operation": "two-round-test"}))
                .expect("bounded work descriptor"),
        )
        .expect("initial task-with-work created");

    let calls = Arc::new(AtomicUsize::new(0));
    let resumed_calls = Arc::new(AtomicUsize::new(0));
    let observed_rejection = Arc::new(Mutex::new(None));
    let emitted = Arc::new(AtomicUsize::new(0));

    let runtime = FinalTaskRuntime::new(
        store.clone(),
        FinalTaskRuntimeConfig::new(60000, None).unwrap(),
        {
            let emitted = Arc::clone(&emitted);
            Arc::new(move |_| {
                emitted.fetch_add(1, Ordering::SeqCst);
            })
        },
    );

    let supervisor = Arc::new(TwoRoundSupervisor {
        calls: Arc::clone(&calls),
        resumed_calls: Arc::clone(&resumed_calls),
        reused,
        observed_rejection: Arc::clone(&observed_rejection),
        store: Arc::clone(&store),
        emitted: Arc::clone(&emitted),
    });
    let mut runner = runtime
        .install_task_service(1, supervisor)
        .expect("install task service");

    let roots_a_response: TaskInputResponses = serde_json::from_value(serde_json::json!({
        "roots_a": {"roots": [{"uri": "file:///first-round", "name": "first-round"}]}
    }))
    .expect("valid roots_a response");

    let roots_b_response: TaskInputResponses = serde_json::from_value(serde_json::json!({
        "roots_b": {"roots": [{"uri": "file:///second-round", "name": "second-round"}]}
    }))
    .expect("valid roots_b response");

    let application = RuntimeBuilder::current_thread().build().unwrap();
    application.block_on(async {
        let cx = Cx::current().expect("application-owned runtime context");
        let mut service = std::pin::pin!(runner.run_service(&cx));
        let mut observation_bound =
            std::pin::pin!(asupersync::time::sleep(cx.now(), Duration::from_secs(5)));
        let mut step = 0usize;
        let mut replay_ticks = 0usize;
        let mut baseline_snapshot: Option<FinalTaskSnapshot> = None;
        let mut baseline_notification: Option<TaskStatusNotification> = None;
        let mut baseline_emitted = 0usize;

        poll_fn(|task_cx| {
            if observation_bound.as_mut().poll(task_cx).is_ready() {
                panic!("test timed out waiting for two-round progression");
            }
            if step < 3 {
                if let Poll::Ready(result) = service.as_mut().poll(task_cx) {
                    panic!("service must remain live and pending while caller is live: {result:?}");
                }
            } else {
                if let Poll::Ready(result) = service.as_mut().poll(task_cx) {
                    assert!(
                        result.is_ok(),
                        "service natural shutdown must succeed: {result:?}"
                    );
                    return Poll::Ready(());
                }
                task_cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            let current = store.get_task_snapshot(&task_id).unwrap().unwrap();
            match current.task() {
                Task::InputRequired { base: _, input_requests } => {
                    if step == 0 && input_requests.contains_key("roots_a") {
                        assert_eq!(
                            emitted.load(Ordering::SeqCst),
                            1,
                            "round 1 require_input must have emitted 1 notification"
                        );
                        runtime
                            .update_task(&task_id, &roots_a_response)
                            .expect("round 1 input update succeeds");
                        assert_eq!(
                            emitted.load(Ordering::SeqCst),
                            2,
                            "round 1 update_task must have emitted second notification"
                        );
                        step = 1;
                        task_cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    if step == 1 && input_requests.contains_key("roots_b") {
                        if !reused && replay_ticks < 4 {
                            if replay_ticks == 0 {
                                // Baseline before stale replay.
                                let base_snap = store.get_task_snapshot(&task_id).unwrap().unwrap();
                                let base_notif = store
                                    .latest_notification(&task_id)
                                    .expect("read baseline notification");
                                let base_emit = emitted.load(Ordering::SeqCst);
                                assert_eq!(
                                    base_emit, 3,
                                    "must have emitted exactly 3 notifications before stale replay"
                                );
                                assert_eq!(
                                    resumed_calls.load(Ordering::SeqCst),
                                    1,
                                    "supervisor must have resumed exactly once before stale replay"
                                );
                                baseline_snapshot = Some(base_snap);
                                baseline_notification = Some(base_notif);
                                baseline_emitted = base_emit;

                                // Submit stale round 1 roots_a response.
                                runtime
                                    .update_task(&task_id, &roots_a_response)
                                    .expect("replayed update ignored cleanly");
                                replay_ticks = 1;
                                task_cx.waker().wake_by_ref();
                                return Poll::Pending;
                            }

                            // Ticks 1, 2, 3: poll service slice and assert full invariance.
                            let base_snap = baseline_snapshot.as_ref().unwrap();
                            let base_notif = baseline_notification.as_ref().unwrap();
                            let current_snap = store.get_task_snapshot(&task_id).unwrap().unwrap();
                            let current_notif = store
                                .latest_notification(&task_id)
                                .expect("read current notification");

                            assert_eq!(
                                resumed_calls.load(Ordering::SeqCst),
                                1,
                                "stale replay must not trigger supervisor resumption"
                            );
                            assert_eq!(
                                emitted.load(Ordering::SeqCst),
                                baseline_emitted,
                                "stale replay must not emit any notification"
                            );
                            assert_eq!(
                                current_snap.generation(),
                                base_snap.generation(),
                                "stale replay must not advance generation"
                            );
                            assert_eq!(
                                serde_json::to_value(current_snap.task()).unwrap(),
                                serde_json::to_value(base_snap.task()).unwrap(),
                                "stale replay must not mutate task state"
                            );
                            assert_eq!(
                                current_snap.authenticated_principal(),
                                base_snap.authenticated_principal(),
                                "stale replay must not mutate authenticated principal"
                            );
                            assert_eq!(
                                serde_json::to_value(&current_notif).unwrap(),
                                serde_json::to_value(base_notif).unwrap(),
                                "stale replay must not replace latest notification"
                            );

                            replay_ticks += 1;
                            task_cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }

                        // Replay slice verified (or in reused mode): submit fresh round 2 roots_b response.
                        runtime
                            .update_task(&task_id, &roots_b_response)
                            .expect("round 2 input update succeeds");
                        assert_eq!(
                            emitted.load(Ordering::SeqCst),
                            4,
                            "round 2 update_task must have emitted fourth notification"
                        );
                        step = 2;
                        task_cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Task::Completed { .. } => {
                    if step == 2 {
                        assert_eq!(
                            emitted.load(Ordering::SeqCst),
                            5,
                            "completion must have emitted fifth notification"
                        );
                        assert_eq!(calls.load(Ordering::SeqCst), 3);
                        assert_eq!(resumed_calls.load(Ordering::SeqCst), 2);

                        // Explicit caller cancellation to initiate owned natural service shutdown.
                        cx.cancel_with(CancelKind::User, None);
                        step = 3;
                        task_cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                _ => {}
            }
            Poll::Pending
        })
        .await;
    });

    assert!(
        !runtime.is_task_service_ready(),
        "natural service shutdown revokes readiness"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(resumed_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        emitted.load(Ordering::SeqCst),
        5,
        "completed task must have emitted exactly 5 notifications in total"
    );
    if reused {
        let rejection = observed_rejection
            .lock()
            .unwrap()
            .take()
            .expect("reused input key must have produced McpError::invalid_params");
        assert_eq!(rejection.code, McpErrorCode::InvalidParams);
        assert_eq!(
            rejection.message,
            "Task input request keys cannot be reused"
        );
    } else {
        assert!(
            observed_rejection.lock().unwrap().is_none(),
            "fresh input keys must never produce a rejection"
        );
    }
    let final_snapshot = store.get_task_snapshot(&task_id).unwrap().unwrap();
    let value = serde_json::to_value(final_snapshot.task()).unwrap();
    assert_eq!(value["status"], "completed");
    assert_eq!(
        value["result"]["content"][0]["text"],
        "two rounds completed successfully"
    );
    let latest_notif = store.latest_notification(&task_id).unwrap();
    assert_eq!(
        serde_json::to_value(&latest_notif.params.task).unwrap()["status"],
        "completed"
    );
}
