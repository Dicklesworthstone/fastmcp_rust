//! Server lifecycle tests.
//!
//! Tests for server startup, request handling, and shutdown behavior.

use super::helpers::*;

#[test]
fn test_server_starts_and_exits_cleanly() {
    let runner = TestServerRunner::new(E2ETestConfig::default());
    let result = runner.run_demo_mode();

    result.print_diagnostics();

    // Server should exit cleanly with code 0
    assert_eq!(
        result.exit_code, 0,
        "Server should exit cleanly, got exit code {}",
        result.exit_code
    );
}

#[test]
fn test_server_handles_initialize() {
    let runner = TestServerRunner::new(E2ETestConfig::default());
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();

    // Should have a valid JSON-RPC response
    assert!(
        !result.stdout.is_empty(),
        "Should have JSON-RPC response in stdout"
    );
    result.assert_stdout_valid_jsonrpc();

    // Should have initialize result
    assert!(
        result.stdout_contains("protocolVersion"),
        "Response should contain protocolVersion"
    );
    assert!(
        result.stdout_contains("serverInfo"),
        "Response should contain serverInfo"
    );
}

#[test]
fn test_server_handles_multiple_requests() {
    let runner = TestServerRunner::new(E2ETestConfig::default());
    let result = runner.run_with_messages(&[
        &jsonrpc::initialize(1),
        &jsonrpc::tools_list(2),
        &jsonrpc::ping(3),
    ]);

    result.print_diagnostics();

    // Should have multiple valid JSON-RPC responses
    assert!(
        result.stdout.len() >= 3,
        "Should have at least 3 responses, got {}",
        result.stdout.len()
    );
    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_server_handles_tool_call() {
    let runner = TestServerRunner::new(E2ETestConfig::default());
    let result = runner.run_with_messages(&[
        &jsonrpc::initialize(1),
        &jsonrpc::tools_call(2, "echo", serde_json::json!({"message": "hello world"})),
    ]);

    result.print_diagnostics();

    // Should have valid responses
    result.assert_stdout_valid_jsonrpc();

    // Should have tool result with content
    assert!(
        result.stdout_contains("content"),
        "Tool response should contain content"
    );
    assert!(
        result.stdout_contains("hello world"),
        "Tool response should contain echoed message"
    );
}

#[test]
fn test_server_handles_ping() {
    let runner = TestServerRunner::new(E2ETestConfig::default());
    let result = runner.run_with_messages(&[&jsonrpc::ping(1)]);

    result.print_diagnostics();

    // Should have valid JSON-RPC response
    result.assert_stdout_valid_jsonrpc();

    // Ping response should be empty object
    assert!(
        result.stdout_contains("result"),
        "Ping should return a result"
    );
}

#[test]
fn test_server_logs_to_stderr() {
    let runner = TestServerRunner::new(E2ETestConfig::default());
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();

    // Server should log activity to stderr
    assert!(
        !result.stderr.is_empty(),
        "Server should output logs to stderr"
    );

    // Should log something about receiving message
    assert!(
        result.stderr_contains_ci("received") || result.stderr_contains_ci("context"),
        "Server should log received messages or context"
    );
}

#[test]
fn test_stdout_only_contains_jsonrpc() {
    let runner = TestServerRunner::new(E2ETestConfig::default());
    let result = runner.run_with_messages(&[
        &jsonrpc::initialize(1),
        &jsonrpc::tools_list(2),
    ]);

    result.print_diagnostics();

    // Critical: stdout must ONLY contain valid JSON-RPC
    for (i, line) in result.stdout.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(
            parsed.is_ok(),
            "stdout line {} must be valid JSON:\n{}",
            i + 1,
            line
        );

        let value = parsed.unwrap();
        assert!(
            value.get("jsonrpc").is_some(),
            "stdout line {} must be JSON-RPC (missing 'jsonrpc' field):\n{}",
            i + 1,
            line
        );
    }
}

#[test]
fn test_server_handles_unknown_method() {
    let runner = TestServerRunner::new(E2ETestConfig::default());
    let result = runner.run_with_messages(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"unknown/method","params":{}}"#,
    ]);

    result.print_diagnostics();

    result.assert_stdout_valid_jsonrpc();

    // Should return error for unknown method
    assert!(
        result.stdout_contains("error"),
        "Should return error for unknown method"
    );
    assert!(
        result.stdout_contains("-32601") || result.stdout_contains("not found"),
        "Should return method not found error"
    );
}
