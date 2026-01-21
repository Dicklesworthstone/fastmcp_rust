//! Configuration tests.
//!
//! Tests for environment variable configuration options.

use super::helpers::*;

#[test]
fn test_banner_style_none() {
    let config = E2ETestConfig::default()
        .with_env("FASTMCP_BANNER", "none");

    let runner = TestServerRunner::new(config);
    let result = runner.run_demo_mode();

    result.print_diagnostics();

    // With banner=none, should not show the fancy FastMCP banner
    // (though may still have log output)
    assert_eq!(
        result.exit_code, 0,
        "Server should exit cleanly"
    );
}

#[test]
fn test_banner_style_compact() {
    let config = E2ETestConfig::default()
        .with_env("FASTMCP_BANNER", "compact");

    let runner = TestServerRunner::new(config);
    let result = runner.run_demo_mode();

    result.print_diagnostics();

    assert_eq!(
        result.exit_code, 0,
        "Server should exit cleanly"
    );
}

#[test]
fn test_banner_style_minimal() {
    let config = E2ETestConfig::default()
        .with_env("FASTMCP_BANNER", "minimal");

    let runner = TestServerRunner::new(config);
    let result = runner.run_demo_mode();

    result.print_diagnostics();

    assert_eq!(
        result.exit_code, 0,
        "Server should exit cleanly"
    );
}

#[test]
fn test_no_banner_env() {
    let config = E2ETestConfig::default()
        .with_env("FASTMCP_NO_BANNER", "1");

    let runner = TestServerRunner::new(config);
    let result = runner.run_demo_mode();

    result.print_diagnostics();

    assert_eq!(
        result.exit_code, 0,
        "Server should exit cleanly with no banner"
    );
}

#[test]
fn test_log_level_debug() {
    let config = E2ETestConfig::default()
        .with_env("FASTMCP_LOG", "debug");

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::ping(1)]);

    result.print_diagnostics();

    // Should have valid responses
    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_log_level_error() {
    let config = E2ETestConfig::default()
        .with_env("FASTMCP_LOG", "error");

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::ping(1)]);

    result.print_diagnostics();

    // Should have valid responses
    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_log_timestamps_disabled() {
    let config = E2ETestConfig::default()
        .with_env("FASTMCP_LOG_TIMESTAMPS", "0");

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::ping(1)]);

    result.print_diagnostics();

    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_log_targets_disabled() {
    let config = E2ETestConfig::default()
        .with_env("FASTMCP_LOG_TARGETS", "0");

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::ping(1)]);

    result.print_diagnostics();

    result.assert_stdout_valid_jsonrpc();
}

#[test]
fn test_multiple_config_options() {
    let config = E2ETestConfig::default()
        .with_env("FASTMCP_LOG", "warn")
        .with_env("FASTMCP_BANNER", "compact")
        .with_env("FASTMCP_LOG_TIMESTAMPS", "0");

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();

    result.assert_stdout_valid_jsonrpc();
    result.assert_stdout_no_ansi();
}

#[test]
fn test_rich_overrides_agent_env() {
    // FASTMCP_RICH=1 should enable rich even when agent env vars are set
    let config = E2ETestConfig::default()
        .with_env("MCP_CLIENT", "test-agent")
        .with_env("FASTMCP_RICH", "1");

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[&jsonrpc::initialize(1)]);

    result.print_diagnostics();

    // Protocol should still be correct
    result.assert_stdout_valid_jsonrpc();
    result.assert_stdout_no_ansi();
}

#[test]
fn test_agent_mode_with_all_options() {
    let config = E2ETestConfig::agent_mode()
        .with_env("FASTMCP_LOG", "debug")
        .with_env("FASTMCP_BANNER", "none");

    let runner = TestServerRunner::new(config);
    let result = runner.run_with_messages(&[
        &jsonrpc::initialize(1),
        &jsonrpc::tools_list(2),
    ]);

    result.print_diagnostics();

    // Must maintain protocol integrity
    result.assert_stdout_valid_jsonrpc();
    result.assert_stdout_no_ansi();
}
