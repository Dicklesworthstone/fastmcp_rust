//! Agent mode tests.
//!
//! Tests that verify the server behaves correctly when running in agent context.
//! The critical requirement is that stdout must NEVER contain ANSI codes.

use super::helpers::*;

#[test]
fn test_mcp_client_env_triggers_agent_mode() {
    let config = E2ETestConfig::default()
        .with_env("MCP_CLIENT", "claude-desktop");

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();

    // CRITICAL: stdout must NEVER have ANSI codes
    result.assert_stdout_no_ansi();
    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_claude_code_env_triggers_agent_mode() {
    let config = E2ETestConfig::default()
        .with_env("CLAUDE_CODE", "1");

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();

    // CRITICAL: stdout must NEVER have ANSI codes
    result.assert_stdout_no_ansi();
    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_codex_cli_env_triggers_agent_mode() {
    let config = E2ETestConfig::default()
        .with_env("CODEX_CLI", "1");

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();

    // CRITICAL: stdout must NEVER have ANSI codes
    result.assert_stdout_no_ansi();
    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_ci_env_triggers_agent_mode() {
    let config = E2ETestConfig::ci_mode();

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();

    // CRITICAL: stdout must NEVER have ANSI codes
    result.assert_stdout_no_ansi();
    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_agent_mode_env_triggers_agent_mode() {
    let config = E2ETestConfig::default()
        .with_env("AGENT_MODE", "1");

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();

    // CRITICAL: stdout must NEVER have ANSI codes
    result.assert_stdout_no_ansi();
    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_no_color_disables_ansi() {
    let config = E2ETestConfig::no_color_mode();

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();

    // CRITICAL: stdout must NEVER have ANSI codes
    result.assert_stdout_no_ansi();
    result.assert_stdout_valid_jsonrpc();

    // stderr should also have no ANSI in NO_COLOR mode
    assert!(
        !result.stderr_has_ansi_codes(),
        "NO_COLOR should disable ANSI in stderr too"
    );
}

#[test]
fn test_fastmcp_plain_env_triggers_plain_mode() {
    let config = E2ETestConfig::default()
        .with_env("FASTMCP_PLAIN", "1");

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();

    // CRITICAL: stdout must NEVER have ANSI codes
    result.assert_stdout_no_ansi();
    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_agent_mode_with_multiple_requests() {
    let config = E2ETestConfig::agent_mode();

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[
        &jsonrpc::initialize(1),
        &jsonrpc::tools_list(2),
        &jsonrpc::tools_call(3, "echo", serde_json::json!({"message": "test"})),
        &jsonrpc::ping(4),
    ]);

    result.print_diagnostics();

    // CRITICAL: stdout must NEVER have ANSI codes (even with many requests)
    result.assert_stdout_no_ansi();
    result.assert_stdout_valid_jsonrpc();

    // Should have all responses
    assert!(
        result.stdout.len() >= 4,
        "Should have at least 4 responses"
    );
}

#[test]
fn test_agent_mode_stdout_is_pure_jsonrpc() {
    let config = E2ETestConfig::agent_mode();

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();

    // Every non-empty line in stdout must be valid JSON-RPC
    for line in &result.stdout {
        if line.trim().is_empty() {
            continue;
        }

        let parsed: serde_json::Value = serde_json::from_str(line)
            .expect("stdout must be valid JSON");

        assert!(
            parsed.get("jsonrpc").is_some(),
            "stdout must only contain JSON-RPC messages"
        );
    }
}

#[test]
fn test_agent_mode_logs_to_stderr() {
    let config = E2ETestConfig::agent_mode();

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();

    // Server should still log to stderr (even in agent mode)
    // This is informational and doesn't affect the protocol
    assert!(
        !result.stderr.is_empty(),
        "Server should output diagnostic info to stderr"
    );
}
