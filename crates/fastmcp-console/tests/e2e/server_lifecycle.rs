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

    // Validate the result correlated to the initialize request, rather than
    // accepting matching text from an unrelated notification.
    let initialize = result.response_result(1);
    assert_eq!(
        initialize
            .get("protocolVersion")
            .and_then(serde_json::Value::as_str),
        Some("2024-11-05"),
        "Initialize response should contain the negotiated protocol version"
    );
    assert_eq!(
        initialize
            .get("serverInfo")
            .and_then(|server_info| server_info.get("name"))
            .and_then(serde_json::Value::as_str),
        Some("test-server"),
        "Initialize response should contain the fixture server identity"
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

    // Validate the result correlated to the tool call itself.
    let tool_result = result.response_result(2);
    assert_eq!(
        tool_result
            .get("isError")
            .and_then(serde_json::Value::as_bool),
        Some(false),
        "Echo tool call should not report an application error"
    );
    let content = tool_result
        .get("content")
        .and_then(serde_json::Value::as_array)
        .expect("Tool response should contain a content array");
    assert_eq!(content.len(), 1, "Echo tool should return one content item");
    assert_eq!(
        content[0].get("type").and_then(serde_json::Value::as_str),
        Some("text"),
        "Echo tool should return text content"
    );
    assert_eq!(
        content[0].get("text").and_then(serde_json::Value::as_str),
        Some("hello world"),
        "Tool response should contain the echoed message"
    );
}

#[test]
fn test_server_handles_ping() {
    let runner = TestServerRunner::new(E2ETestConfig::default());
    let result = runner.run_with_messages(&[&jsonrpc::ping(1)]);

    result.print_diagnostics();

    // Should have valid JSON-RPC response
    result.assert_stdout_valid_jsonrpc();

    // Ping has an exact empty-object result.
    assert_eq!(result.response_result(1), serde_json::json!({}));
}

#[test]
fn test_server_logs_to_stderr() {
    let runner = TestServerRunner::new(E2ETestConfig::default());
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();
    result.assert_stdout_valid_jsonrpc();

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
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1), &jsonrpc::tools_list(2)]);

    result.print_diagnostics();
    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_server_handles_unknown_method() {
    let runner = TestServerRunner::new(E2ETestConfig::default());
    let result = runner.run_with_expected_error(
        r#"{"jsonrpc":"2.0","id":1,"method":"unknown/method","params":{}}"#,
        -32601,
    );

    result.print_diagnostics();

    result.assert_stdout_valid_jsonrpc();

    // The helper requires a valid error object with the exact Method Not Found
    // code and rejects any result-bearing or malformed response.
}
