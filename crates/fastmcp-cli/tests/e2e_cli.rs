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
        // Keep E2E output deterministic: no network checks and no "update available" noise.
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
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

#[cfg(unix)]
fn inspect_echo_server(format: &str) -> Output {
    run_cli(&[
        "inspect",
        "-f",
        format,
        "cargo",
        "--",
        "run",
        "-q",
        "-p",
        "fastmcp-rust",
        "--example",
        "echo_server",
    ])
}

#[cfg(unix)]
fn inspect_json_stdout(output: &Output) -> serde_json::Value {
    let stdout = stdout_str(output);
    serde_json::from_str(&stdout).expect("inspect output should be valid JSON")
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

// =============================================================================
// Run Command Execution Tests (bd-23x)
// =============================================================================

#[cfg(unix)]
#[test]
fn e2e_cli_run_propagates_exit_code() {
    let output = run_cli(&["run", "sh", "--", "-c", "exit 42"]);

    assert_eq!(
        output.status.code(),
        Some(42),
        "expected exit code propagation"
    );

    // The child process is responsible for its own stderr; we should not add an extra
    // wrapper error line for normal non-zero exits.
    assert!(
        !stderr_str(&output).contains("Error:"),
        "unexpected wrapper error output: {}",
        stderr_str(&output)
    );
}

#[cfg(unix)]
#[test]
fn e2e_cli_run_inherits_stdout_and_stderr() {
    let output = run_cli(&[
        "run",
        "sh",
        "--",
        "-c",
        "echo RUN_STDOUT; echo RUN_STDERR 1>&2",
    ]);

    assert!(output.status.success());
    assert!(stdout_str(&output).contains("RUN_STDOUT"));
    assert!(stderr_str(&output).contains("RUN_STDERR"));
}

#[cfg(unix)]
#[test]
fn e2e_cli_run_respects_cwd() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "fastmcp-cli-run-cwd-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp cwd");

    let output = run_cli(&[
        "run",
        "-C",
        dir.to_str().expect("cwd utf-8"),
        "sh",
        "--",
        "-c",
        "pwd",
    ]);

    assert!(output.status.success());

    let expected = std::fs::canonicalize(&dir).expect("canonicalize temp cwd");
    assert_eq!(stdout_str(&output).trim(), expected.to_str().unwrap());
}

#[cfg(unix)]
#[test]
fn e2e_cli_run_sets_env_vars_and_warns_on_invalid_format() {
    let output = run_cli(&["run", "-e", "FOO=bar", "sh", "--", "-c", "echo $FOO"]);

    assert!(output.status.success());
    assert_eq!(stdout_str(&output).trim(), "bar");

    let output = run_cli(&["run", "-e", "NOT_A_PAIR", "sh", "--", "-c", "echo ok"]);
    assert!(output.status.success());
    assert!(stdout_str(&output).contains("ok"));
    assert!(
        stderr_str(&output).contains("Warning: Invalid env var format"),
        "expected invalid env var warning, got: {}",
        stderr_str(&output)
    );
}

#[test]
fn e2e_cli_inspect_missing_server_fails() {
    let output = run_cli(&["inspect"]);

    assert!(!output.status.success());
}

#[cfg(unix)]
#[test]
fn e2e_cli_inspect_text_lists_server_capabilities_and_items() {
    let output = inspect_echo_server("text");
    assert!(
        output.status.success(),
        "inspect text should succeed, stderr: {}",
        stderr_str(&output)
    );

    let stdout = stdout_str(&output);
    assert!(stdout.contains("Server: echo-server v1.0.0"));
    assert!(stdout.contains("Capabilities: tools=true resources=true prompts=true"));

    assert!(stdout.contains("Tools (4):"));
    assert!(stdout.contains("  - echo: Echo the input message back."));
    assert!(stdout.contains("  - add: Calculate the sum of two numbers"));
    assert!(stdout.contains("  - reverse: Reverse a string."));
    assert!(stdout.contains("  - word_count: Count the number of words in text"));

    assert!(stdout.contains("Resources (2):"));
    assert!(stdout.contains("  - info://server"));
    assert!(stdout.contains("  - info://time"));

    assert!(stdout.contains("Prompts (2):"));
    assert!(stdout.contains("  - greeting: Generate a friendly greeting"));
    assert!(stdout.contains("  - review_code: A code review prompt."));
}

#[cfg(unix)]
#[test]
fn e2e_cli_inspect_json_lists_tools_resources_and_prompts() {
    let output = inspect_echo_server("json");
    assert!(
        output.status.success(),
        "inspect json should succeed, stderr: {}",
        stderr_str(&output)
    );

    let json = inspect_json_stdout(&output);

    assert_eq!(json["server"]["name"], "echo-server");
    assert_eq!(json["server"]["version"], "1.0.0");
    assert_eq!(json["capabilities"]["tools"], true);
    assert_eq!(json["capabilities"]["resources"], true);
    assert_eq!(json["capabilities"]["prompts"], true);

    let tools = json["tools"]
        .as_array()
        .expect("tools should be an array in inspect json");
    assert!(tools.iter().any(|tool| tool["name"] == "echo"));
    assert!(tools.iter().any(|tool| tool["name"] == "add"));
    assert!(tools.iter().any(|tool| tool["name"] == "reverse"));
    assert!(tools.iter().any(|tool| tool["name"] == "word_count"));

    let resources = json["resources"]
        .as_array()
        .expect("resources should be an array in inspect json");
    assert!(
        resources
            .iter()
            .any(|resource| resource["uri"] == "info://server")
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource["uri"] == "info://time")
    );

    let prompts = json["prompts"]
        .as_array()
        .expect("prompts should be an array in inspect json");
    assert!(prompts.iter().any(|prompt| prompt["name"] == "greeting"));
    assert!(prompts.iter().any(|prompt| prompt["name"] == "review_code"));
}

#[cfg(unix)]
#[test]
fn e2e_cli_inspect_mcp_format_outputs_json_payload() {
    let output = inspect_echo_server("mcp");
    assert!(
        output.status.success(),
        "inspect mcp should succeed, stderr: {}",
        stderr_str(&output)
    );

    let json = inspect_json_stdout(&output);
    assert_eq!(json["server"]["name"], "echo-server");
    assert!(
        json["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty())
    );
    assert!(
        json["resources"]
            .as_array()
            .is_some_and(|resources| !resources.is_empty())
    );
    assert!(
        json["prompts"]
            .as_array()
            .is_some_and(|prompts| !prompts.is_empty())
    );
}

#[cfg(unix)]
#[test]
fn e2e_cli_inspect_output_file_writes_payload() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time should be after epoch")
        .as_nanos();
    let output_path = std::env::temp_dir().join(format!(
        "fastmcp-cli-inspect-output-{}-{nanos}.json",
        std::process::id()
    ));

    let output = run_cli(&[
        "inspect",
        "-f",
        "json",
        "-o",
        output_path
            .to_str()
            .expect("temp output path should be valid utf-8"),
        "cargo",
        "--",
        "run",
        "-q",
        "-p",
        "fastmcp-rust",
        "--example",
        "echo_server",
    ]);

    assert!(
        output.status.success(),
        "inspect with output file should succeed, stderr: {}",
        stderr_str(&output)
    );
    assert_eq!(
        stdout_str(&output).trim(),
        "",
        "stdout should be empty when --output is used"
    );

    let contents = std::fs::read_to_string(&output_path)
        .expect("inspect --output should create and populate output file");
    let json: serde_json::Value =
        serde_json::from_str(&contents).expect("output file should contain valid json");
    assert_eq!(json["server"]["name"], "echo-server");
    assert!(
        json["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty())
    );
}

#[test]
fn e2e_cli_inspect_unreachable_server_fails_with_error() {
    let output = run_cli(&["inspect", "definitely_missing_server_command_abc123"]);

    assert!(!output.status.success());

    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("Failed to spawn subprocess")
            || stderr.contains("No such file")
            || stderr.contains("not found"),
        "inspect unreachable server should explain spawn failure; stderr: {stderr}"
    );
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

#[cfg(unix)]
#[test]
fn e2e_cli_tasks_list_against_echo_server_succeeds() {
    let output = run_cli(&[
        "tasks",
        "list",
        "cargo",
        "--",
        "run",
        "-q",
        "-p",
        "fastmcp-rust",
        "--example",
        "echo_server",
    ]);

    assert!(
        output.status.success(),
        "tasks list should succeed, stderr: {}",
        stderr_str(&output)
    );
    assert!(
        stdout_str(&output).contains("No tasks found."),
        "expected empty task list output, got stdout: {}",
        stdout_str(&output)
    );
}

#[cfg(unix)]
#[test]
fn e2e_cli_tasks_list_json_against_echo_server_outputs_array() {
    let output = run_cli(&[
        "tasks",
        "list",
        "--json",
        "cargo",
        "--",
        "run",
        "-q",
        "-p",
        "fastmcp-rust",
        "--example",
        "echo_server",
    ]);

    assert!(
        output.status.success(),
        "tasks list --json should succeed, stderr: {}",
        stderr_str(&output)
    );

    let stdout = stdout_str(&output);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("tasks list --json should produce valid json");
    assert_eq!(
        json.as_array().map(std::vec::Vec::len),
        Some(0),
        "expected empty task array for fresh echo server"
    );
}

#[cfg(unix)]
#[test]
fn e2e_cli_tasks_list_with_status_filter_succeeds() {
    let output = run_cli(&[
        "tasks",
        "list",
        "--status",
        "pending",
        "cargo",
        "--",
        "run",
        "-q",
        "-p",
        "fastmcp-rust",
        "--example",
        "echo_server",
    ]);

    assert!(
        output.status.success(),
        "tasks list --status pending should succeed, stderr: {}",
        stderr_str(&output)
    );
    assert!(stdout_str(&output).contains("No tasks found."));
}

#[cfg(unix)]
#[test]
fn e2e_cli_tasks_stats_json_against_echo_server_outputs_zero_counts() {
    let output = run_cli(&[
        "tasks",
        "stats",
        "--json",
        "cargo",
        "--",
        "run",
        "-q",
        "-p",
        "fastmcp-rust",
        "--example",
        "echo_server",
    ]);

    assert!(
        output.status.success(),
        "tasks stats --json should succeed, stderr: {}",
        stderr_str(&output)
    );

    let stdout = stdout_str(&output);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("tasks stats --json should produce valid json");
    for key in [
        "total",
        "active",
        "pending",
        "running",
        "completed",
        "failed",
        "cancelled",
    ] {
        assert_eq!(json[key], 0, "expected {key} to be 0 for fresh echo server");
    }
}

#[cfg(unix)]
#[test]
fn e2e_cli_tasks_show_unknown_id_fails_with_not_found_error() {
    let output = run_cli(&[
        "tasks",
        "show",
        "cargo",
        "task-999",
        "--",
        "run",
        "-q",
        "-p",
        "fastmcp-rust",
        "--example",
        "echo_server",
    ]);

    assert!(!output.status.success());
    assert!(
        stderr_str(&output).contains("Task not found"),
        "expected task-not-found error, stderr: {}",
        stderr_str(&output)
    );
}

#[cfg(unix)]
#[test]
fn e2e_cli_tasks_cancel_unknown_id_fails_with_not_found_error() {
    let output = run_cli(&[
        "tasks",
        "cancel",
        "cargo",
        "task-999",
        "--",
        "run",
        "-q",
        "-p",
        "fastmcp-rust",
        "--example",
        "echo_server",
    ]);

    assert!(!output.status.success());
    assert!(
        stderr_str(&output).contains("Task not found"),
        "expected task-not-found error, stderr: {}",
        stderr_str(&output)
    );
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
