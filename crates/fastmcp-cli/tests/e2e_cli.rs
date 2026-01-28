//! E2E tests for fastmcp CLI command execution.
//!
//! These tests spawn the actual CLI binary and verify:
//! - Exit codes
//! - stdout/stderr output
//! - Command behavior

use std::process::{Command, Output};

/// Path to the compiled binary (in debug or release mode).
fn get_binary_path() -> String {
    // Use cargo-built binary path
    env!("CARGO_BIN_EXE_fastmcp").to_string()
}

/// Helper to run the CLI and capture output.
fn run_cli(args: &[&str]) -> Output {
    Command::new(get_binary_path())
        .args(args)
        .output()
        .expect("Failed to execute CLI binary")
}

/// Helper to get stdout as string.
fn stdout_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Helper to get stderr as string.
fn stderr_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

// =============================================================================
// Help Command Tests
// =============================================================================

#[test]
fn e2e_cli_help_shows_usage() {
    let output = run_cli(&["--help"]);

    assert!(output.status.success(), "help should exit 0");

    let stdout = stdout_str(&output);
    assert!(stdout.contains("fastmcp"), "Should mention fastmcp");
    assert!(stdout.contains("run"), "Should list run command");
    assert!(stdout.contains("inspect"), "Should list inspect command");
    assert!(stdout.contains("install"), "Should list install command");
    assert!(stdout.contains("list"), "Should list list command");
    assert!(stdout.contains("test"), "Should list test command");
    assert!(stdout.contains("dev"), "Should list dev command");
    assert!(stdout.contains("tasks"), "Should list tasks command");
}

#[test]
fn e2e_cli_run_help() {
    let output = run_cli(&["run", "--help"]);

    assert!(output.status.success());

    let stdout = stdout_str(&output);
    assert!(stdout.contains("Run an MCP server"));
    assert!(stdout.contains("--cwd"));
    assert!(stdout.contains("--env"));
}

#[test]
fn e2e_cli_inspect_help() {
    let output = run_cli(&["inspect", "--help"]);

    assert!(output.status.success());

    let stdout = stdout_str(&output);
    assert!(stdout.contains("Inspect"));
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("--output"));
}

#[test]
fn e2e_cli_install_help() {
    let output = run_cli(&["install", "--help"]);

    assert!(output.status.success());

    let stdout = stdout_str(&output);
    assert!(stdout.contains("Install"));
    assert!(stdout.contains("--target"));
    assert!(stdout.contains("--dry-run"));
}

#[test]
fn e2e_cli_list_help() {
    let output = run_cli(&["list", "--help"]);

    assert!(output.status.success());

    let stdout = stdout_str(&output);
    assert!(stdout.contains("List"));
    assert!(stdout.contains("--target"));
    assert!(stdout.contains("--format"));
}

#[test]
fn e2e_cli_test_help() {
    let output = run_cli(&["test", "--help"]);

    assert!(output.status.success());

    let stdout = stdout_str(&output);
    assert!(stdout.contains("Test"));
    assert!(stdout.contains("--timeout"));
    assert!(stdout.contains("--verbose"));
}

#[test]
fn e2e_cli_dev_help() {
    let output = run_cli(&["dev", "--help"]);

    assert!(output.status.success());

    let stdout = stdout_str(&output);
    assert!(stdout.contains("development mode"));
    assert!(stdout.contains("--host"));
    assert!(stdout.contains("--port"));
    assert!(stdout.contains("--transport"));
}

#[test]
fn e2e_cli_tasks_help() {
    let output = run_cli(&["tasks", "--help"]);

    assert!(output.status.success());

    let stdout = stdout_str(&output);
    assert!(stdout.contains("background tasks"));
    assert!(stdout.contains("list"));
    assert!(stdout.contains("show"));
    assert!(stdout.contains("cancel"));
    assert!(stdout.contains("stats"));
}

// =============================================================================
// Version Command Tests
// =============================================================================

#[test]
fn e2e_cli_version() {
    let output = run_cli(&["--version"]);

    assert!(output.status.success());

    let stdout = stdout_str(&output);
    // Version output should contain the binary name and version
    assert!(stdout.contains("fastmcp") || stdout.contains("0."));
}

// =============================================================================
// Exit Code Tests
// =============================================================================

#[test]
fn e2e_cli_no_args_fails() {
    let output = run_cli(&[]);

    // No subcommand should fail with non-zero exit
    assert!(!output.status.success());

    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("Usage") || stderr.contains("error") || stderr.contains("USAGE"),
        "Should show usage hint: {stderr}"
    );
}

#[test]
fn e2e_cli_invalid_subcommand_fails() {
    let output = run_cli(&["not-a-command"]);

    assert!(!output.status.success());

    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("not-a-command") || stderr.contains("error"),
        "Should mention invalid command"
    );
}

#[test]
fn e2e_cli_run_missing_server_fails() {
    let output = run_cli(&["run"]);

    assert!(!output.status.success());

    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("required") || stderr.contains("<SERVER>"),
        "Should indicate missing required arg"
    );
}

#[test]
fn e2e_cli_inspect_missing_server_fails() {
    let output = run_cli(&["inspect"]);

    assert!(!output.status.success());
}

#[test]
fn e2e_cli_install_missing_args_fails() {
    let output = run_cli(&["install"]);

    assert!(!output.status.success());
}

#[test]
fn e2e_cli_test_missing_server_fails() {
    let output = run_cli(&["test"]);

    assert!(!output.status.success());
}

#[test]
fn e2e_cli_dev_missing_target_fails() {
    let output = run_cli(&["dev"]);

    assert!(!output.status.success());
}

#[test]
fn e2e_cli_tasks_missing_subcommand_fails() {
    let output = run_cli(&["tasks"]);

    assert!(!output.status.success());
}

// =============================================================================
// Invalid Option Tests
// =============================================================================

#[test]
fn e2e_cli_inspect_invalid_format_fails() {
    let output = run_cli(&["inspect", "-f", "invalid", "./server"]);

    assert!(!output.status.success());

    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("invalid") || stderr.contains("error"),
        "Should reject invalid format"
    );
}

#[test]
fn e2e_cli_list_invalid_format_fails() {
    let output = run_cli(&["list", "-f", "invalid"]);

    assert!(!output.status.success());
}

#[test]
fn e2e_cli_dev_invalid_transport_fails() {
    let output = run_cli(&["dev", "--transport", "websocket", "."]);

    assert!(!output.status.success());
}

#[test]
fn e2e_cli_install_invalid_target_fails() {
    let output = run_cli(&["install", "-t", "invalid", "name", "./server"]);

    assert!(!output.status.success());
}

// =============================================================================
// Install Dry-Run Tests
// =============================================================================

#[test]
fn e2e_cli_install_dry_run_outputs_config() {
    let output = run_cli(&[
        "install",
        "--dry-run",
        "my-test-server",
        "/path/to/server",
        "--",
        "--config",
        "config.json",
    ]);

    // Dry run should succeed
    assert!(output.status.success());

    let stdout = stdout_str(&output);
    // Should output the configuration
    assert!(
        stdout.contains("my-test-server") || stdout.contains("/path/to/server"),
        "Should show server config"
    );
}

#[test]
fn e2e_cli_install_dry_run_cursor() {
    let output = run_cli(&[
        "install",
        "--dry-run",
        "-t",
        "cursor",
        "test-server",
        "/bin/server",
    ]);

    assert!(output.status.success());
}

#[test]
fn e2e_cli_install_dry_run_cline() {
    let output = run_cli(&[
        "install",
        "--dry-run",
        "-t",
        "cline",
        "test-server",
        "/bin/server",
    ]);

    assert!(output.status.success());
}

// =============================================================================
// List Command Tests
// =============================================================================

#[test]
fn e2e_cli_list_default() {
    // This may or may not find servers, but should not error
    let output = run_cli(&["list"]);

    // Either succeeds (with or without servers) or fails gracefully
    // The exit code depends on whether config files exist
    let stdout = stdout_str(&output);
    let stderr = stderr_str(&output);

    // Should not panic or produce garbage output
    assert!(
        stdout.is_ascii() || stdout.is_empty(),
        "Output should be valid text"
    );
    assert!(
        stderr.is_ascii() || stderr.is_empty(),
        "Stderr should be valid text"
    );
}

#[test]
fn e2e_cli_list_json_format() {
    let output = run_cli(&["list", "-f", "json"]);

    // If it succeeds, output should be valid JSON
    if output.status.success() {
        let stdout = stdout_str(&output);
        if !stdout.is_empty() {
            // Should be parseable as JSON
            assert!(
                stdout.starts_with('[') || stdout.starts_with('{'),
                "JSON output should start with [ or {{"
            );
        }
    }
}

// =============================================================================
// Concurrent Execution Tests
// =============================================================================

#[test]
fn e2e_cli_concurrent_help() {
    use std::thread;

    // Launch multiple help commands concurrently
    let handles: Vec<_> = (0..4)
        .map(|_| {
            thread::spawn(|| {
                let output = run_cli(&["--help"]);
                assert!(output.status.success());
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }
}

// =============================================================================
// Environment Variable Tests
// =============================================================================

#[test]
fn e2e_cli_run_env_parsing() {
    // Just verify the argument parsing works (won't actually run server)
    let output = run_cli(&["run", "--help"]);

    let stdout = stdout_str(&output);
    assert!(stdout.contains("-e") || stdout.contains("--env"));
}

// =============================================================================
// Output Format Tests
// =============================================================================

#[test]
fn e2e_cli_tasks_list_json_option() {
    let output = run_cli(&["tasks", "list", "--help"]);

    assert!(output.status.success());

    let stdout = stdout_str(&output);
    assert!(stdout.contains("--json"), "Should support --json output");
}

#[test]
fn e2e_cli_test_json_option() {
    let output = run_cli(&["test", "--help"]);

    assert!(output.status.success());

    let stdout = stdout_str(&output);
    assert!(stdout.contains("--json"), "Should support --json output");
}
