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
        let mut command = Command::new(get_binary_path());
        command.args(arguments).args([
            "--websocket-url",
            &self.endpoint,
            "--protocol-policy",
            "modern-only",
            "--timeout",
            &timeout.to_string(),
        ]);
        run_with_deadline(command, Duration::from_secs(15)).expect("bounded WebSocket CLI child")
    }

    fn requests(&self) -> Vec<Value> {
        std::fs::read_to_string(self.root.join("backend.requests.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn stop(mut self) {
        self.process
            .kill_and_reap()
            .expect("real WebSocket fixture cleanup");
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
        vec!["call", "echo", "--protocol-policy", "auto", "--json"],
        vec![
            "inspect",
            "--protocol-policy",
            "legacy-only",
            "--format",
            "json",
        ],
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
    assert_eq!(documents[0]["task"]["taskId"], documents[1]["taskId"]);
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
    assert_eq!(documents[0]["task"]["taskId"], documents[1]["taskId"]);
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
    assert_eq!(documents[0]["task"]["taskId"], documents[1]["taskId"]);
    assert_single_task_creation(&fixture);
    fixture.stop();
}
