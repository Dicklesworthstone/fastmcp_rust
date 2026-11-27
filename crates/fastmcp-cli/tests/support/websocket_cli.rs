//! The shipped CLI against a real framework WebSocket listener. All test
//! payloads are chosen by the caller; discovery, framing, dispatch, Tasks and
//! result admission use the same production code as an application server.

use super::*;
use serde_json::{Value, json};

struct Fixture {
    root: TestTempDir,
    endpoint: String,
    process: ProcessGroupGuard,
}

impl Fixture {
    fn start() -> Self {
        let root = TestTempDir::new("websocket-cli");
        let ready = root.join("backend.ready");
        let mut command = Command::new(env!("CARGO_BIN_EXE_fastmcp_cli_e2e_server"));
        command
            .arg("--websocket-ready")
            .arg(&ready)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(root.join("backend.stdout")).unwrap())
            .stderr(std::fs::File::create(root.join("backend.stderr")).unwrap());
        let process = ProcessGroupGuard::spawn(&mut command);
        let started = Instant::now();
        let endpoint = loop {
            if let Ok(endpoint) = std::fs::read_to_string(&ready)
                && endpoint.starts_with("ws://")
                && endpoint.ends_with("/mcp")
            {
                break endpoint;
            }
            assert!(
                started.elapsed() < Duration::from_secs(15),
                "real WebSocket fixture did not bind: {}",
                std::fs::read_to_string(root.join("backend.stderr")).unwrap_or_default(),
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        Self {
            root,
            endpoint,
            process,
        }
    }

    fn run(&self, arguments: &[&str], timeout: u64) -> Output {
        self.run_with_policy(arguments, timeout, Some("modern-only"))
    }

    fn run_with_policy(&self, arguments: &[&str], timeout: u64, policy: Option<&str>) -> Output {
        let mut command = Command::new(get_binary_path());
        command.args(arguments).args([
            "--websocket-url",
            &self.endpoint,
            "--timeout",
            &timeout.to_string(),
        ]);
        if let Some(policy) = policy {
            command.args(["--protocol-policy", policy]);
        }
        run_with_deadline(command, Duration::from_secs(15)).expect("bounded WebSocket CLI child")
    }

    #[cfg(feature = "tasks")]
    fn create_input_task(&self) -> String {
        let arguments = json!({
            "message": self.root.file_name().unwrap().to_string_lossy(),
        })
        .to_string();
        let output = self.run(
            &[
                "call",
                "background_with_input",
                "--wait",
                "--arguments",
                &arguments,
                "--json",
            ],
            5,
        );
        // The real --wait command stops at input-required and preserves its
        // accepted receipt. Subsequent commands attach without recreating work.
        assert!(!output.status.success());
        let documents: Vec<Value> = stdout_str(&output)
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let result = &documents[0];
        assert_eq!(result["resultType"], "task");
        let id = result["taskId"].as_str().unwrap().to_owned();
        self.wait_for_task_status(&id, "input_required");
        id
    }

    #[cfg(feature = "tasks")]
    fn wait_for_task_status(&self, id: &str, status: &str) -> Value {
        let started = Instant::now();
        loop {
            let output = run_task_cli(&self.endpoint, &["get", id], 5);
            assert!(output.status.success(), "{}", stderr_str(&output));
            let document: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(document["event"], "snapshot");
            assert_eq!(document["data"]["taskId"], id);
            if document["data"]["status"] == status {
                return document["data"].clone();
            }
            assert!(started.elapsed() < Duration::from_secs(5), "{document}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn requests(&self) -> Vec<Value> {
        std::fs::read_to_string(self.root.join("backend.requests.jsonl"))
            .unwrap_or_default()
            .split_inclusive('\n')
            // The live fixture may still be appending its final record.
            .filter(|line| line.ends_with('\n'))
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn stop(mut self) {
        self.process
            .kill_and_reap()
            .expect("real WebSocket fixture cleanup");
    }
}

#[cfg(feature = "tasks")]
fn run_task_cli(endpoint: &str, arguments: &[&str], timeout: u64) -> Output {
    let mut command = Command::new(get_binary_path());
    command.arg("tasks").args(arguments).args([
        "--websocket-url",
        endpoint,
        "--json",
        "--timeout",
        &timeout.to_string(),
    ]);
    run_with_deadline(command, Duration::from_secs(15)).expect("bounded WebSocket Tasks CLI child")
}

#[cfg(feature = "tasks")]
#[test]
fn websocket_cli_tasks_get_watch_and_cancel_existing_work() {
    let fixture = Fixture::start();
    let id = fixture.create_input_task();
    let endpoint = fixture.endpoint.clone();
    let watch_id = id.clone();
    let previous_listeners = fixture
        .requests()
        .iter()
        .filter(|request| request["method"] == "subscriptions/listen")
        .count();
    std::thread::scope(|scope| {
        let watch = scope.spawn(move || run_task_cli(&endpoint, &["watch", &watch_id], 8));
        let started = Instant::now();
        while fixture
            .requests()
            .iter()
            .filter(|request| request["method"] == "subscriptions/listen")
            .count()
            <= previous_listeners
        {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "watch did not open its listener"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = run_task_cli(&fixture.endpoint, &["cancel", &id], 5);
        assert!(output.status.success(), "{}", stderr_str(&output));
        let document: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(document["event"], "cancellation-acknowledged");
        let output = watch.join().expect("watch thread completes");
        assert!(output.status.success(), "{}", stderr_str(&output));
        let documents: Vec<Value> = stdout_str(&output)
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(documents[0]["event"], "snapshot");
        assert!(
            documents
                .iter()
                .any(|event| event["event"] == "watch-acknowledged")
        );
        assert!(documents.iter().any(|event| {
            event["event"] == "task-updated"
                && event["data"]["status"] == "cancelled"
                && event["data"]["taskId"] == id
        }));
        let last = documents.last().unwrap();
        assert_eq!(last["event"], "watch-ended");
        assert_eq!(last["data"]["reason"], "task-terminal");
    });
    fixture.wait_for_task_status(&id, "cancelled");
    let wrong_id = format!("missing-{id}");
    let refused = run_task_cli(&fixture.endpoint, &["get", &wrong_id], 5);
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    let requests = fixture.requests();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "tools/call")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "tasks/cancel")
            .count(),
        1
    );
    assert!(
        !requests
            .iter()
            .any(|r| r["method"] == "tasks/update" || r["method"] == "initialize")
    );
    fixture.stop();
}

#[cfg(feature = "tasks")]
#[test]
fn websocket_cli_tasks_update_resumes_only_matching_input() {
    let fixture = Fixture::start();
    let id = fixture.create_input_task();
    let before = fixture.wait_for_task_status(&id, "input_required");
    let input = fixture.root.join("responses.json");
    std::fs::write(&input, br#"{"foreign":{"roots":[]}}"#).unwrap();
    let output = run_task_cli(
        &fixture.endpoint,
        &["update", &id, "--input-file", input.to_str().unwrap()],
        5,
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        !fixture
            .requests()
            .iter()
            .any(|r| r["method"] == "tasks/update")
    );
    assert_eq!(fixture.wait_for_task_status(&id, "input_required"), before);

    let responses = json!({"roots": {"roots": [{
        "uri": format!("file://{}", fixture.root.as_ref().display()),
        "name": "explicit caller-selected root",
    }]}});
    std::fs::write(&input, serde_json::to_vec(&responses).unwrap()).unwrap();
    let output = run_task_cli(
        &fixture.endpoint,
        &["update", &id, "--input-file", input.to_str().unwrap()],
        5,
    );
    assert!(output.status.success(), "{}", stderr_str(&output));
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["event"], "update-acknowledged");
    let completed = fixture.wait_for_task_status(&id, "completed");
    let accepted: Value =
        serde_json::from_str(completed["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(accepted, responses);
    let requests = fixture.requests();
    let updates: Vec<_> = requests
        .iter()
        .filter(|r| r["method"] == "tasks/update")
        .collect();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0]["params"]["inputResponses"], responses);
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "tools/call")
            .count(),
        1
    );
    assert!(
        !requests
            .iter()
            .any(|r| r["method"] == "tasks/cancel" || r["method"] == "initialize")
    );
    fixture.stop();
}

#[cfg(feature = "tasks")]
#[test]
fn websocket_cli_tasks_watch_timeout_preserves_remote_work() {
    let fixture = Fixture::start();
    let id = fixture.create_input_task();
    let before = fixture.wait_for_task_status(&id, "input_required");
    let started = Instant::now();
    let output = run_task_cli(&fixture.endpoint, &["watch", &id], 1);
    assert!(!output.status.success());
    assert!(started.elapsed() < Duration::from_secs(8));
    let documents: Vec<Value> = stdout_str(&output)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(documents[0]["event"], "snapshot");
    assert_eq!(documents[0]["data"]["taskId"], id);
    assert!(
        !documents
            .iter()
            .any(|event| event["event"] == "watch-ended")
    );
    assert_eq!(fixture.wait_for_task_status(&id, "input_required"), before);
    assert!(
        !fixture
            .requests()
            .iter()
            .any(|r| r["method"] == "tasks/cancel" || r["method"] == "tasks/update")
    );
    fixture.stop();
}

#[cfg(feature = "tasks")]
#[test]
fn websocket_cli_tasks_incompatible_options_fail_before_contact() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("ws://{}/mcp", listener.local_addr().unwrap());
    for extra in [
        vec!["--http-url", "http://127.0.0.1:1/mcp"],
        vec!["--server", "unused-child"],
        vec!["--bearer-token-file", "/no-credential-read"],
        vec!["--protocol-policy", "legacy-only"],
        vec!["--timeout", "0"],
    ] {
        let mut command = Command::new(get_binary_path());
        command.args(["tasks", "get", "unused-task", "--websocket-url", &endpoint]);
        command.args(extra);
        let output = run_with_deadline(command, Duration::from_secs(5)).unwrap();
        assert!(!output.status.success());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn websocket_cli_inspect_reads_the_real_catalog() {
    let fixture = Fixture::start();
    let output = fixture.run(&["inspect", "--format", "json", "--max-pages", "2"], 5);
    assert!(output.status.success(), "{}", stderr_str(&output));
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["server"]["name"], "fastmcp-cli-e2e-server");
    assert_eq!(document["protocol"]["policy"], "modern-only");
    assert_eq!(document["protocol"]["version"], "2026-07-28");
    let names: Vec<_> = document["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"echo"));
    assert!(names.contains(&"delayed_echo"));
    assert_eq!(document["resources"][0]["uri"], "test://status");
    assert_eq!(document["prompts"][0]["name"], "greeting");
    assert!(
        !fixture
            .requests()
            .iter()
            .any(|request| request["method"] == "initialize")
    );
    fixture.stop();
}

fn run_connectivity_test(endpoint: &str, idle: u64, absolute: u64) -> Output {
    run_connectivity_test_with_policy(endpoint, idle, absolute, Some("modern-only"))
}

fn run_connectivity_test_with_policy(
    endpoint: &str,
    idle: u64,
    absolute: u64,
    policy: Option<&str>,
) -> Output {
    let mut command = Command::new(get_binary_path());
    command.args([
        "test",
        "--websocket-url",
        endpoint,
        "--idle-timeout",
        &idle.to_string(),
        "--absolute-timeout",
        &absolute.to_string(),
        "--json",
    ]);
    if let Some(policy) = policy {
        command.args(["--protocol-policy", policy]);
    }
    run_with_deadline(command, Duration::from_secs(15)).expect("bounded WebSocket connectivity test")
}

#[test]
fn websocket_cli_test_probes_real_catalogs_and_closes() {
    let fixture = Fixture::start();
    let output = run_connectivity_test(&fixture.endpoint, 2, 3);
    assert!(output.status.success(), "{}", stderr_str(&output));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "fastmcp.cli.test/v1");
    assert_eq!(report["success"], true);
    let tests = report["tests"].as_array().unwrap();
    let names: Vec<_> = tests.iter().map(|test| test["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["initialize", "ping", "list_tools", "list_resources", "list_prompts", "cleanup"]);
    for test in tests {
        assert_eq!(test["success"], true, "{test}");
        assert_ne!(test["skipped"], true, "{test}");
    }
    assert_eq!(tests[0]["details"], "protocol 2026-07-28 over WebSocket");
    assert_eq!(tests[3]["details"], "1 resources");
    assert_eq!(tests[4]["details"], "1 prompts");
    assert_eq!(tests[5]["details"], "WebSocket connection closed");
    let methods: Vec<_> = fixture
        .requests()
        .iter()
        .map(|request| request["method"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        methods,
        ["server/discover", "server/discover", "tools/list", "resources/list", "prompts/list"]
    );
    fixture.stop();
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn websocket_cli_default_auto_and_explicit_legacy_use_real_server_verbs() {
    for policy in [None, Some("legacy-only")] {
        let fixture = Fixture::start();
        let modern = policy.is_none();
        let version = if modern { "2026-07-28" } else { "2024-11-05" };
        let output = fixture.run_with_policy(
            &["inspect", "--format", "json", "--max-pages", "2"],
            5,
            policy,
        );
        assert!(output.status.success(), "{}", stderr_str(&output));
        let document: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(document["protocol"]["policy"], policy.unwrap_or("auto"));
        assert_eq!(document["protocol"]["version"], version);
        assert_eq!(
            document["schema"],
            if modern {
                "fastmcp.cli.inspect/v2"
            } else {
                "fastmcp.cli.inspect/v1"
            }
        );
        assert_eq!(document["server"]["name"], "fastmcp-cli-e2e-server");
        assert!(
            document["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["name"] == "echo")
        );
        assert_eq!(document["resources"][0]["uri"], "test://status");
        assert_eq!(document["prompts"][0]["name"], "greeting");
        if modern {
            assert!(document["capabilities"]["tools"].is_object());
        } else {
            assert_eq!(document["capabilities"]["tools"], true);
        }

        let message = format!("selected {version} {}", fixture.root.display());
        let arguments = json!({"message": message}).to_string();
        let output = fixture.run_with_policy(
            &["call", "echo", "--arguments", &arguments, "--json"],
            5,
            policy,
        );
        assert!(output.status.success(), "{}", stderr_str(&output));
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["content"][0]["text"], message);
        assert_eq!(result.get("resultType").is_some(), modern);

        let output = fixture.run_with_policy(&["read", "test://status", "--json"], 5, policy);
        assert!(output.status.success(), "{}", stderr_str(&output));
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["contents"][0]["uri"], "test://status");
        assert_eq!(result["contents"][0]["text"], "ready");
        assert_eq!(result.get("resultType").is_some(), modern);

        let arguments = json!({"name": message}).to_string();
        let output = fixture.run_with_policy(
            &["prompt", "greeting", "--arguments", &arguments, "--json"],
            5,
            policy,
        );
        assert!(output.status.success(), "{}", stderr_str(&output));
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            result["messages"][0]["content"]["text"],
            format!("Hello, {message}!")
        );
        assert_eq!(result.get("resultType").is_some(), modern);

        let output = run_connectivity_test_with_policy(&fixture.endpoint, 2, 3, policy);
        assert!(output.status.success(), "{}", stderr_str(&output));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["success"], true);
        let tests = report["tests"].as_array().unwrap();
        assert_eq!(tests.len(), 6);
        assert_eq!(
            tests[0]["details"],
            format!("protocol {version} over WebSocket")
        );
        assert!(
            tests
                .iter()
                .all(|test| test["success"] == true && test["skipped"] != true)
        );
        let requests = fixture.requests();
        let forbidden = if modern {
            "initialize"
        } else {
            "server/discover"
        };
        assert!(
            !requests
                .iter()
                .any(|request| request["method"] == forbidden)
        );
        for method in ["tools/call", "resources/read", "prompts/get"] {
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| request["method"] == method)
                    .count(),
                1
            );
        }
        fixture.stop();
    }
}

#[cfg(feature = "legacy-2024-11-05")]
#[derive(Clone, Copy, Debug)]
enum PolicyPeerMode {
    LegacyFallback,
    ModernOnlyRefusal,
    UpgradeUnauthorized,
    DiscoveryForbidden,
    MalformedDiscovery,
    ApplicationRefusal,
}

#[cfg(feature = "legacy-2024-11-05")]
struct PolicyPeer {
    endpoint: String,
    finished: mpsc::SyncSender<()>,
    worker: std::thread::JoinHandle<Vec<Vec<Value>>>,
}

#[cfg(feature = "legacy-2024-11-05")]
impl PolicyPeer {
    fn start(mode: PolicyPeerMode) -> Self {
        let (ready, address) = mpsc::sync_channel(1);
        let (finished, child_finished) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            use asupersync::io::AsyncWriteExt as _;

            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                .build()
                .unwrap();
            runtime.block_on(async {
                let cx = asupersync::Cx::current().unwrap();
                let listener =
                    fastmcp_transport::websocket::WebSocketListener::bind("127.0.0.1:0")
                        .await
                        .unwrap();
                ready.send(listener.local_addr().unwrap()).unwrap();
                asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
                    let attempts = if matches!(mode, PolicyPeerMode::LegacyFallback) { 2 } else { 1 };
                    let mut connections = Vec::new();
                    for attempt in 0..attempts {
                        let upgrade = listener.accept(&cx).await.unwrap();
                        assert_eq!(upgrade.path(), "/mcp?route=kept%2Fexact&tenant=cli");
                        if matches!(mode, PolicyPeerMode::UpgradeUnauthorized) {
                            let mut stream = upgrade.into_stream();
                            stream.write_all(
                                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\nWWW-Authenticate: Bearer\r\n\r\n"
                            ).await.unwrap();
                            connections.push(Vec::new());
                            continue;
                        }
                        let mut transport =
                            upgrade.into_admission().unwrap().complete(&cx).await.unwrap();
                        let mut requests = Vec::new();
                        let mut initialized = false;
                        loop {
                            let request = match transport.recv(&cx).await {
                                Ok(fastmcp_protocol::JsonRpcMessage::Request(request)) => request,
                                Err(fastmcp_transport::TransportError::Closed) => break,
                                other => panic!("expected an MCP request or explicit close: {other:?}"),
                            };
                            requests.push(serde_json::to_value(&request).unwrap());
                            let response = if attempt == 0 {
                                if requests.len() == 1 {
                                    assert_eq!(request.method, "server/discover");
                                    assert_eq!(request.id, Some(fastmcp_protocol::RequestId::Number(1)));
                                    let mut response = json!({
                                        "jsonrpc": "2.0", "id": request.id,
                                        "result": {
                                            "resultType": "complete",
                                            "supportedVersions": ["2026-07-28"],
                                            "capabilities": {"tools": {}},
                                            "ttlMs": 0, "cacheScope": "private",
                                        },
                                    });
                                    match mode {
                                        PolicyPeerMode::LegacyFallback | PolicyPeerMode::ModernOnlyRefusal => {
                                            response = json!({
                                                "jsonrpc": "2.0", "id": request.id,
                                                "error": {"code": -32601, "message": "unknown discovery"},
                                            });
                                        }
                                        PolicyPeerMode::DiscoveryForbidden => {
                                            response = json!({
                                                "jsonrpc": "2.0", "id": request.id,
                                                "error": {"code": -32002, "message": "access denied"},
                                            });
                                        }
                                        PolicyPeerMode::MalformedDiscovery => {
                                            response["result"]["cacheScope"] = json!("invalid");
                                        }
                                        PolicyPeerMode::ApplicationRefusal => {}
                                        PolicyPeerMode::UpgradeUnauthorized => unreachable!(),
                                    }
                                    response
                                } else {
                                    assert!(matches!(mode, PolicyPeerMode::ApplicationRefusal));
                                    assert_eq!(requests.len(), 2);
                                    assert_eq!(request.method, "tools/call");
                                    json!({
                                        "jsonrpc": "2.0", "id": request.id,
                                        "error": {"code": -32601, "message": "unknown application tool"},
                                    })
                                }
                            } else {
                                if request.method == "notifications/initialized" {
                                    assert_eq!(requests.len(), 2);
                                    assert!(request.id.is_none());
                                    initialized = true;
                                    continue;
                                }
                                if request.method == "initialize" {
                                    assert_eq!(requests.len(), 1);
                                    assert_eq!(
                                        request.params.as_ref().unwrap()["protocolVersion"],
                                        "2024-11-05"
                                    );
                                } else {
                                    assert!(initialized, "legacy application traffic must follow initialization");
                                }
                                json!({
                                    "jsonrpc": "2.0", "id": request.id,
                                    "result": legacy_policy_result(&request),
                                })
                            };
                            transport.send(
                                &cx,
                                &serde_json::from_value(response).unwrap(),
                            ).await.unwrap();
                        }
                        connections.push(requests);
                    }
                    // Keep the listener alive until the actual CLI has exited.
                    // An unintended fallback then remains observable in its
                    // accept queue even if that extra handshake timed out.
                    child_finished.recv_timeout(Duration::from_secs(10))
                        .expect("CLI must finish before the no-extra-connection check");
                    assert!(
                        asupersync::time::timeout(
                            cx.now(), Duration::from_millis(100), listener.accept(&cx),
                        ).await.is_err(),
                        "a terminal refusal must not open another WebSocket connection",
                    );
                    connections
                }).await.expect("policy peer must observe bounded CLI cleanup")
            })
        });
        let address = address.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            endpoint: format!("ws://{address}/mcp?route=kept%2Fexact&tenant=cli"),
            finished,
            worker,
        }
    }

    fn finish(self) -> Vec<Vec<Value>> {
        let _ = self.finished.send(());
        self.worker.join().expect("native WebSocket policy peer")
    }
}

#[cfg(feature = "legacy-2024-11-05")]
fn legacy_policy_result(request: &fastmcp_protocol::JsonRpcRequest) -> Value {
    let parameters = request.params.clone().unwrap_or_else(|| json!({}));
    match request.method.as_str() {
        "initialize" => json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": "legacy-policy-peer", "version": "1"},
        }),
        "ping" => json!({}),
        "tools/list" => json!({"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]}),
        "resources/list" => json!({"resources": [{"uri": "test://status", "name": "status"}]}),
        "resources/templates/list" => json!({"resourceTemplates": []}),
        "prompts/list" => json!({"prompts": [{"name": "greeting"}]}),
        "tools/call" => json!({
            "content": [{"type": "text", "text": parameters["arguments"]["message"]}],
            "isError": false,
        }),
        "resources/read" => json!({
            "contents": [{"uri": parameters["uri"], "text": "ready"}],
        }),
        "prompts/get" => json!({"messages": [{
            "role": "user", "content": {
                "type": "text",
                "text": format!("Hello, {}!", parameters["arguments"]["name"].as_str().unwrap()),
            },
        }]}),
        "completion/complete" => json!({"completion": {
            "values": ["Alice"], "total": 1, "hasMore": false,
        }}),
        method => panic!("unexpected legacy operation {method}"),
    }
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn websocket_cli_auto_fallback_opens_fresh_legacy_connections_for_every_command() {
    let message = format!(
        "exact fallback {}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    );
    let call_arguments = json!({"message": message}).to_string();
    let prompt_arguments = json!({"name": message}).to_string();
    for arguments in [
        vec!["inspect", "--format", "json", "--max-pages", "2"],
        vec!["call", "echo", "--arguments", &call_arguments, "--json"],
        vec!["read", "test://status", "--json"],
        vec![
            "prompt",
            "greeting",
            "--arguments",
            &prompt_arguments,
            "--json",
        ],
        vec![
            "complete",
            "--prompt",
            "greeting",
            "--argument",
            "name",
            "--value",
            "Al",
            "--json",
        ],
        vec![
            "test",
            "--idle-timeout",
            "2",
            "--absolute-timeout",
            "3",
            "--json",
        ],
    ] {
        let peer = PolicyPeer::start(PolicyPeerMode::LegacyFallback);
        let mut command = Command::new(get_binary_path());
        command.args(&arguments).args([
            "--websocket-url",
            &peer.endpoint,
            "--protocol-policy",
            "auto",
        ]);
        if arguments[0] != "test" {
            command.args(["--timeout", "5"]);
        }
        let output = run_with_deadline(command, Duration::from_secs(15)).unwrap();
        let connections = peer.finish();
        assert!(
            output.status.success(),
            "{}: {}",
            arguments[0],
            stderr_str(&output)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        match arguments[0] {
            "inspect" => {
                assert_eq!(result["schema"], "fastmcp.cli.inspect/v1");
                assert_eq!(result["protocol"]["policy"], "auto");
                assert_eq!(result["protocol"]["version"], "2024-11-05");
                assert_eq!(result["server"]["name"], "legacy-policy-peer");
                assert_eq!(result["capabilities"]["tools"], true);
                assert_eq!(result["tools"][0]["name"], "echo");
                assert_eq!(result["resources"][0]["uri"], "test://status");
                assert_eq!(result["prompts"][0]["name"], "greeting");
            }
            "call" => assert_eq!(result["content"][0]["text"], message),
            "read" => assert_eq!(result["contents"][0]["text"], "ready"),
            "prompt" => {
                assert_eq!(
                    result["messages"][0]["content"]["text"],
                    format!("Hello, {message}!")
                );
            }
            "complete" => assert_eq!(result["completion"]["values"], json!(["Alice"])),
            "test" => {
                assert_eq!(result["success"], true);
                assert_eq!(
                    result["tests"][0]["details"],
                    "protocol 2024-11-05 over WebSocket"
                );
                assert!(
                    result["tests"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|test| test["success"] == true && test["skipped"] != true)
                );
            }
            _ => unreachable!(),
        }
        assert_eq!(connections.len(), 2);
        assert_eq!(
            connections[0].len(),
            1,
            "no operation may run on the refused connection"
        );
        assert_eq!(connections[0][0]["method"], "server/discover");
        assert_eq!(connections[1][0]["method"], "initialize");
        assert_eq!(
            connections[1][0]["id"], 1,
            "the second transport has a fresh allocator"
        );
        assert_eq!(connections[1][1]["method"], "notifications/initialized");
        assert!(
            !connections[1]
                .iter()
                .any(|request| request["method"] == "server/discover")
        );
        if arguments[0] == "call" {
            let calls: Vec<_> = connections[1]
                .iter()
                .filter(|request| request["method"] == "tools/call")
                .collect();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0]["params"]["arguments"]["message"], message);
        }
    }
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn websocket_cli_refusals_never_downgrade_or_replay_application_work() {
    for (mode, policy, expected_requests) in [
        (PolicyPeerMode::UpgradeUnauthorized, "auto", 0),
        (PolicyPeerMode::DiscoveryForbidden, "auto", 1),
        (PolicyPeerMode::MalformedDiscovery, "auto", 1),
        (PolicyPeerMode::ApplicationRefusal, "auto", 2),
        (PolicyPeerMode::ModernOnlyRefusal, "modern-only", 1),
    ] {
        let peer = PolicyPeer::start(mode);
        let mut command = Command::new(get_binary_path());
        command.args([
            "call",
            "echo",
            "--arguments",
            r#"{"message":"one action"}"#,
            "--json",
            "--websocket-url",
            &peer.endpoint,
            "--protocol-policy",
            policy,
            "--timeout",
            "3",
        ]);
        let output = run_with_deadline(command, Duration::from_secs(15)).unwrap();
        let connections = peer.finish();
        assert!(!output.status.success(), "{mode:?}");
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].len(), expected_requests, "{mode:?}");
        let calls = connections[0]
            .iter()
            .filter(|request| request["method"] == "tools/call")
            .count();
        assert_eq!(
            calls,
            usize::from(matches!(mode, PolicyPeerMode::ApplicationRefusal))
        );
        assert!(
            !connections[0]
                .iter()
                .any(|request| request["method"] == "initialize")
        );
    }
}

#[derive(Clone, Copy)]
enum ConnectivityPeerMode {
    NoCatalogs,
    QuietLiveness,
    ForgedTimeout,
}

/// The positive full-server case above uses the shipped framework fixture.
/// These peers vary only the advertised catalog or liveness behavior through
/// production HTTP Upgrade and WebSocket framing, and observe actual closure.
fn connectivity_peer(mode: ConnectivityPeerMode) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let (ready, address) = mpsc::sync_channel(1);
    let peer = std::thread::spawn(move || {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = asupersync::Cx::current().unwrap();
            let listener = fastmcp_transport::websocket::WebSocketListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            ready.send(listener.local_addr().unwrap()).unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(10), async {
                let upgrade = listener.accept(&cx).await.unwrap();
                assert_eq!(upgrade.path(), "/mcp");
                let mut transport = upgrade.into_admission().unwrap().complete(&cx).await.unwrap();
                let mut methods = Vec::new();
                for index in 0..2 {
                    let fastmcp_protocol::JsonRpcMessage::Request(request) =
                        transport.recv(&cx).await.unwrap()
                    else {
                        panic!("connectivity probe must be a request");
                    };
                    assert_eq!(request.method, "server/discover");
                    assert_eq!(request.id, Some(fastmcp_protocol::RequestId::Number(index + 1)));
                    methods.push(request.method);
                    if index == 1 && matches!(mode, ConnectivityPeerMode::QuietLiveness) {
                        continue;
                    }
                    let response = if index == 1
                        && matches!(mode, ConnectivityPeerMode::ForgedTimeout)
                    {
                        json!({"jsonrpc": "2.0", "id": index + 1, "error": {
                            "code": -32603,
                            "message": "Request timed out at the absolute deadline",
                            "data": {
                                "timeoutSource": "absolute",
                                "fastmcpCleanupUnverified": true,
                                "secret": "untrusted-peer-secret",
                            },
                        }})
                    } else {
                        json!({"jsonrpc": "2.0", "id": index + 1, "result": {
                            "resultType": "complete",
                            "supportedVersions": ["2026-07-28"],
                            "capabilities": {},
                            "_meta": {"io.modelcontextprotocol/serverInfo": {
                                "name": "connectivity-peer", "version": "1",
                            }},
                            "ttlMs": 0,
                            "cacheScope": "private",
                        }})
                    };
                    transport.send(&cx, &serde_json::from_value(response).unwrap()).await.unwrap();
                }
                loop {
                    match transport.recv(&cx).await {
                        Err(fastmcp_transport::TransportError::Closed) => break,
                        Ok(fastmcp_protocol::JsonRpcMessage::Request(request)) => {
                            assert_eq!(request.method, "notifications/cancelled");
                        }
                        other => panic!("expected an explicit WebSocket close, got {other:?}"),
                    }
                }
                methods.push("close".to_owned());
                methods
            })
            .await
            .expect("native test peer must observe bounded client cleanup")
        })
    });
    let address = address.recv_timeout(Duration::from_secs(5)).unwrap();
    (format!("ws://{address}/mcp"), peer)
}

#[test]
fn websocket_cli_test_unadvertised_catalogs_are_skipped() {
    let (endpoint, peer) = connectivity_peer(ConnectivityPeerMode::NoCatalogs);
    let output = run_connectivity_test(&endpoint, 2, 3);
    assert!(output.status.success(), "{}", stderr_str(&output));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let tests = report["tests"].as_array().unwrap();
    assert_eq!(tests.len(), 6);
    for test in &tests[2..5] {
        assert_eq!(test["success"], true);
        assert_eq!(test["skipped"], true);
        assert!(test["details"].as_str().unwrap().starts_with("server did not advertise"));
    }
    assert_eq!(tests[5]["success"], true);
    assert_eq!(peer.join().unwrap(), ["server/discover", "server/discover", "close"]);
}

#[test]
fn websocket_cli_test_probe_timeout_retains_cleanup() {
    for mode in [ConnectivityPeerMode::QuietLiveness, ConnectivityPeerMode::ForgedTimeout] {
        let (endpoint, peer) = connectivity_peer(mode);
        let started = Instant::now();
        let output = run_connectivity_test(&endpoint, 1, 2);
        assert!(!output.status.success());
        assert!(started.elapsed() < Duration::from_secs(8));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["schema"], "fastmcp.cli.test/v1");
        assert_eq!(report["success"], false);
        let tests = report["tests"].as_array().unwrap();
        assert_eq!(tests[0]["success"], true);
        assert_eq!(tests[1]["name"], "ping");
        assert_eq!(tests[1]["success"], false);
        assert_eq!(tests[1]["timeout_source"], Value::Null);
        assert!(tests[1]["error"]
            .as_str()
            .unwrap()
            .ends_with("] WebSocket MCP probe failed"));
        assert_eq!(tests[5]["name"], "cleanup");
        assert_eq!(tests[5]["success"], true);
        assert!(!stdout_str(&output).contains("untrusted-peer-secret"));
        assert!(!stdout_str(&output).contains("subprocess cleanup"));
        assert!(!stdout_str(&output).contains("fastmcpCleanupUnverified"));
        assert_eq!(peer.join().unwrap(), ["server/discover", "server/discover", "close"]);
    }
}

#[test]
fn websocket_cli_test_upgrade_timeout_is_bounded() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("ws://{}/mcp", listener.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let started = Instant::now();
        let (stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(started.elapsed() < Duration::from_secs(5));
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("quiet upgrade accept failed: {error}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut request = Vec::new();
        stream.take(16_384).read_to_end(&mut request).unwrap();
        assert!(request.len() < 16_384, "deadline must close the pending upgrade socket");
        assert!(request.starts_with(b"GET /mcp HTTP/1.1\r\n"));
    });
    let started = Instant::now();
    let output = run_connectivity_test(&endpoint, 1, 1);
    assert!(!output.status.success());
    assert!(started.elapsed() < Duration::from_secs(8));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "fastmcp.cli.test/v1");
    assert_eq!(report["success"], false);
    assert_eq!(report["tests"].as_array().unwrap().len(), 1);
    assert_eq!(report["tests"][0]["name"], "initialize");
    assert_eq!(report["tests"][0]["success"], false);
    assert_eq!(report["tests"][0]["timeout_source"], "absolute");
    peer.join().unwrap();
}

#[test]
fn websocket_cli_test_invalid_options_fail_before_contact() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("ws://{}/mcp", listener.local_addr().unwrap());
    for extra in [
        vec!["--protocol-policy", "unknown"],
        vec!["--http-url", "http://127.0.0.1:1/mcp"],
        vec!["--legacy-sse-url", "http://127.0.0.1:1/sse"],
        vec!["--legacy-message-url", "http://127.0.0.1:1/messages"],
        vec!["--bearer-token-file", "/no-credential-read"],
        vec!["unused-child"],
        vec!["--idle-timeout", "0"],
        vec!["--absolute-timeout", "0"],
    ] {
        let mut command = Command::new(get_binary_path());
        command.args(["test", "--websocket-url", &endpoint, "--json"]);
        command.args(extra);
        let output = run_with_deadline(command, Duration::from_secs(5)).unwrap();
        assert!(!output.status.success());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    for endpoint in [
        format!("http://{}/mcp", listener.local_addr().unwrap()),
        format!("ws://{}/mcp\r\ninjected", listener.local_addr().unwrap()),
        "ws:///missing-host".to_owned(),
    ] {
        let output = run_connectivity_test(&endpoint, 1, 1);
        assert!(!output.status.success());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn websocket_cli_operations_preserve_real_results_and_caller_arguments() {
    let fixture = Fixture::start();
    let message = format!(
        "exact \\ text 🦀 {}",
        fixture.root.file_name().unwrap().to_str().unwrap()
    );
    let arguments = json!({"message": message}).to_string();
    let output = fixture.run(&["call", "echo", "--arguments", &arguments, "--json"], 5);
    assert!(output.status.success(), "{}", stderr_str(&output));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["content"][0]["text"], message);

    let output = fixture.run(&["read", "test://status", "--json"], 5);
    assert!(output.status.success(), "{}", stderr_str(&output));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["contents"][0]["uri"], "test://status");
    assert_eq!(result["contents"][0]["text"], "ready");

    let arguments = json!({"name": message}).to_string();
    let output = fixture.run(
        &["prompt", "greeting", "--arguments", &arguments, "--json"],
        5,
    );
    assert!(output.status.success(), "{}", stderr_str(&output));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["resultType"], "complete");
    assert_eq!(
        result["messages"][0]["content"]["text"],
        format!("Hello, {message}!")
    );
    let requests = fixture.requests();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["method"] == "tools/call")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["method"] == "resources/read")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["method"] == "prompts/get")
            .count(),
        1
    );
    let called = requests
        .iter()
        .find(|request| request["method"] == "tools/call")
        .unwrap();
    assert_eq!(called["params"]["arguments"]["message"], message);
    fixture.stop();
}

#[test]
fn websocket_cli_missing_resource_is_a_failure_without_a_partial_result() {
    let fixture = Fixture::start();
    let output = fixture.run(&["read", "test://missing", "--json"], 5);
    assert!(!output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(result["resultType"], "complete");
    assert!(!stdout_str(&output).contains("ready"));
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request["method"] == "resources/read")
            .count(),
        1
    );
    fixture.stop();
}

#[test]
fn websocket_cli_timeout_stops_observation_without_replaying_the_tool() {
    let fixture = Fixture::start();
    let arguments =
        json!({"message": "must not become a late result", "delay_ms": 5_000}).to_string();
    let started = Instant::now();
    let output = fixture.run(
        &["call", "delayed_echo", "--arguments", &arguments, "--json"],
        1,
    );
    assert!(!output.status.success());
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "request/close must remain bounded"
    );
    assert!(!stdout_str(&output).contains("must not become a late result"));
    let requests = fixture.requests();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["method"] == "tools/call")
            .count(),
        1
    );
    assert!(
        !requests
            .iter()
            .any(|request| request["method"] == "initialize")
    );
    fixture.stop();
}

#[test]
fn websocket_cli_incompatible_options_fail_before_contact() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("ws://{}/mcp", listener.local_addr().unwrap());
    for arguments in [
        vec![
            "call",
            "echo",
            "--protocol-policy",
            "modern-only",
            "--input-capability",
            "roots",
            "--json",
        ],
        vec![
            "read",
            "test://status",
            "--protocol-policy",
            "modern-only",
            "--http-url",
            "http://127.0.0.1:1/mcp",
            "--json",
        ],
    ] {
        let mut command = Command::new(get_binary_path());
        command.args(arguments).args(["--websocket-url", &endpoint]);
        let output =
            run_with_deadline(command, Duration::from_secs(5)).expect("pre-contact rejection");
        assert!(!output.status.success());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[cfg(feature = "tasks")]
fn call_wait(is_error: bool, delay_ms: u64, timeout: u64) -> (Fixture, Output, Vec<Value>) {
    let fixture = Fixture::start();
    let arguments = json!({
        "message": "work completed on its creating connection",
        "is_error": is_error,
        "delay_ms": delay_ms,
    })
    .to_string();
    let output = fixture.run(
        &[
            "call",
            "background",
            "--wait",
            "--arguments",
            &arguments,
            "--json",
        ],
        timeout,
    );
    let documents = stdout_str(&output)
        .lines()
        .map(|line| serde_json::from_str(line).expect("one exact JSON object per receipt"))
        .collect();
    (fixture, output, documents)
}

#[cfg(feature = "tasks")]
fn assert_single_task_creation(fixture: &Fixture) {
    let requests = fixture.requests();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["method"] == "tools/call")
            .count(),
        1
    );
    assert!(
        requests
            .iter()
            .any(|request| request["method"] == "tasks/get")
    );
    assert!(
        !requests
            .iter()
            .any(|request| request["method"] == "tasks/cancel"
                || request["method"] == "tasks/update")
    );
    // A reconnect would start a fresh allocator at one. Every observed RPC on
    // the retained connection must keep its monotonically increasing ID.
    let ids: Vec<_> = requests
        .iter()
        .filter_map(|request| request["id"].as_u64())
        .collect();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]), "{requests:?}");
}

#[cfg(feature = "tasks")]
#[test]
fn websocket_cli_call_wait_creates_and_observes_a_real_task() {
    let (fixture, output, documents) = call_wait(false, 300, 5);
    assert!(output.status.success(), "{}", stderr_str(&output));
    assert_eq!(documents.len(), 2);
    assert_eq!(documents[0]["resultType"], "task");
    assert_eq!(documents[1]["status"], "completed");
    assert!(documents[0]["taskId"].is_string());
    assert_eq!(documents[0]["taskId"], documents[1]["taskId"]);
    assert_eq!(
        documents[1]["result"]["content"][0]["text"],
        "work completed on its creating connection"
    );
    assert_single_task_creation(&fixture);
    fixture.stop();
}

#[cfg(feature = "tasks")]
#[test]
fn websocket_cli_call_wait_preserves_real_task_tool_errors() {
    let (fixture, output, documents) = call_wait(true, 300, 5);
    assert!(!output.status.success());
    assert_eq!(documents.len(), 2);
    assert_eq!(documents[1]["status"], "completed");
    assert_eq!(documents[1]["result"]["isError"], true);
    assert!(documents[0]["taskId"].is_string());
    assert_eq!(documents[0]["taskId"], documents[1]["taskId"]);
    assert_single_task_creation(&fixture);
    fixture.stop();
}

#[cfg(feature = "tasks")]
#[test]
fn websocket_cli_call_wait_timeout_retains_the_task_receipt_without_cancelling_work() {
    let started = Instant::now();
    let (fixture, output, documents) = call_wait(false, 5_000, 1);
    assert!(!output.status.success());
    assert!(started.elapsed() < Duration::from_secs(8));
    assert_eq!(documents.len(), 2);
    assert_eq!(documents[0]["resultType"], "task");
    assert_eq!(documents[1]["status"], "working");
    assert!(documents[0]["taskId"].is_string());
    assert_eq!(documents[0]["taskId"], documents[1]["taskId"]);
    assert_single_task_creation(&fixture);
    fixture.stop();
}
