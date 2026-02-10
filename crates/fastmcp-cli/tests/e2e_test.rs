//! E2E tests for `fastmcp test`.

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn fastmcp_bin() -> String {
    env!("CARGO_BIN_EXE_fastmcp").to_string()
}

fn stdout_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn run_cli(args: &[&str]) -> Output {
    Command::new(fastmcp_bin())
        .args(args)
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .output()
        .expect("run fastmcp")
}

#[cfg(unix)]
fn run_with_deadline(mut cmd: Command, deadline: Duration) -> Output {
    let start = Instant::now();
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn command");

    while start.elapsed() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return child.wait_with_output().expect("wait_with_output");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = child.kill();
    child
        .wait_with_output()
        .expect("wait_with_output after kill")
}

#[cfg(unix)]
#[test]
fn e2e_test_json_report_against_echo_server_example() {
    // Use the workspace example server as the subprocess being tested.
    // This exercises:
    // - stdio subprocess spawning
    // - initialization
    // - tools/resources/prompts listing
    let output = run_cli(&[
        "test",
        "--json",
        "--timeout",
        "30",
        "cargo",
        "--",
        "run",
        "-p",
        "fastmcp-rust",
        "--example",
        "echo_server",
    ]);

    assert!(output.status.success());

    let out = stdout_str(&output);
    let json: serde_json::Value = serde_json::from_str(&out).expect("parse test json");
    assert_eq!(json.get("success").and_then(|v| v.as_bool()), Some(true));
    assert!(json.get("tests").and_then(|v| v.as_array()).is_some());
    assert!(json.get("total_duration_ms").is_some());
}

#[cfg(unix)]
#[test]
fn e2e_test_timeout_fails_for_non_responsive_process() {
    // A process that doesn't speak MCP should fail. With a small timeout it should
    // fail quickly (either via timeout or invalid protocol).
    let mut cmd = Command::new(fastmcp_bin());
    cmd.args(["test", "--timeout", "1", "sh", "--", "-c", "sleep 5"])
        .env("FASTMCP_CHECK_FOR_UPDATES", "0");

    let output = run_with_deadline(cmd, Duration::from_secs(10));
    assert!(!output.status.success());
}
