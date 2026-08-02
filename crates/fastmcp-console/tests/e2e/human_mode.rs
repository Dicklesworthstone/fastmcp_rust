//! Human mode tests.
//!
//! Tests that verify the server provides rich output when running in human context.

use super::helpers::*;

#[test]
fn test_human_mode_has_rich_stderr() {
    let config = E2ETestConfig::human_mode();

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();
    result.assert_human_context();

    // FASTMCP_RICH is an explicit override, so accepting plain output here
    // would make this test a false positive.
    assert!(
        result.stderr_has_ansi_codes(),
        "forced human mode must render rich ANSI output to stderr"
    );

    // stdout should NEVER have ANSI codes (even in human mode)
    result.assert_stdout_no_ansi();
    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_force_color_enables_rich() {
    let config = E2ETestConfig::default().with_env("FASTMCP_RICH", "1");

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();
    result.assert_human_context();
    assert!(
        result.stderr_has_ansi_codes(),
        "FASTMCP_RICH must force rich ANSI output"
    );

    // stdout should NEVER have ANSI codes
    result.assert_stdout_no_ansi();
    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_human_mode_shows_server_name() {
    let config = E2ETestConfig::human_mode();

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();
    result.assert_human_context();
    result.assert_stdout_valid_jsonrpc();

    // Server should identify itself in some way
    assert!(
        result.stderr_contains_ci("test-server") || result.stderr_contains_ci("context"),
        "Server should identify itself in stderr"
    );

    // stdout should still be clean
    result.assert_stdout_no_ansi();
}

#[test]
fn test_human_mode_with_tool_call() {
    let config = E2ETestConfig::human_mode();

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[
        &jsonrpc::initialize(1),
        &jsonrpc::tools_call(2, "echo", serde_json::json!({"message": "test message"})),
    ]);

    result.print_diagnostics();
    result.assert_human_context();

    // Should have valid responses
    result.assert_stdout_valid_jsonrpc();
    result.assert_stdout_no_ansi();

    // Should have tool response content
    assert!(
        result.stdout_contains("test message"),
        "Tool response should contain the echoed message"
    );
}

#[test]
fn test_default_mode_without_agent_env_is_plain_when_stderr_is_piped() {
    // The harness pipes stderr, so the honest default is agent/plain mode.
    let config = E2ETestConfig::default();

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();
    result.assert_agent_context();

    // stdout should ALWAYS be clean JSON-RPC
    result.assert_stdout_no_ansi();
    result.assert_stdout_valid_jsonrpc();

    // Server should start successfully
    assert_eq!(result.exit_code, 0, "Server should exit cleanly");
}

#[test]
fn test_rich_mode_still_respects_protocol() {
    let config = E2ETestConfig::human_mode();

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[
        &jsonrpc::initialize(1),
        &jsonrpc::tools_list(2),
        &jsonrpc::ping(3),
    ]);

    result.print_diagnostics();
    result.assert_human_context();

    // Even in rich mode, the protocol must be correct
    result.assert_stdout_valid_jsonrpc();
    result.assert_stdout_no_ansi();

    // All requests should get responses
    assert!(
        result.stdout.len() >= 3,
        "Should have responses for all requests"
    );
}
