//! Test utilities for E2E tests.
//!
//! Provides infrastructure for spawning server processes and capturing their output.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Build the test server binary once before tests run.
/// This avoids cargo lock contention when tests run in parallel.
static TEST_SERVER_PATH: OnceLock<PathBuf> = OnceLock::new();
const CAPTURE_DRAIN_DEADLINE: Duration = Duration::from_secs(1);
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CAPTURE_LINES: usize = 32 * 1024;
const MAX_STDIN_BYTES: usize = 8 * 1024 * 1024;
const PROCESS_CLEANUP_DEADLINE: Duration = Duration::from_secs(2);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Ensure the test server binary is built and return its path.
fn get_test_server_binary() -> PathBuf {
    TEST_SERVER_PATH
        .get_or_init(|| {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let binary_name = format!("test_server{}", std::env::consts::EXE_SUFFIX);
            let current_executable = std::env::current_exe().ok();
            let configured_target_dir = std::env::var_os("CARGO_TARGET_DIR")
                .or_else(|| option_env!("CARGO_TARGET_DIR").map(OsString::from));
            let configured_target = std::env::var_os("CARGO_BUILD_TARGET")
                .or_else(|| option_env!("CARGO_BUILD_TARGET").map(OsString::from));
            let candidates = test_server_binary_candidates(
                &manifest_dir,
                configured_target_dir.as_deref(),
                configured_target.as_deref(),
                current_executable.as_deref(),
                &binary_name,
            );
            if let Some(binary_path) = candidates.iter().find(|candidate| candidate.is_file()) {
                eprintln!(
                    "[E2E] Using Cargo-built test_server at {}",
                    binary_path.display()
                );
                return binary_path.clone();
            }

            // A target-selected integration-test command does not necessarily
            // build examples. Its outer Cargo process still owns the active
            // target lock, so a nested build must use an independent target
            // root instead of waiting on that lock until the fixture timeout.
            let fixture_target_dir = e2e_fixture_target_dir(
                &manifest_dir,
                configured_target_dir.as_deref(),
            );
            eprintln!(
                "[E2E] Building test_server in isolated target {}...",
                fixture_target_dir.display()
            );
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let mut command = Command::new(cargo);
            command
                .args([
                    "build",
                    "--locked",
                    "--offline",
                    "--message-format=json-render-diagnostics",
                    "--package",
                    "fastmcp-console",
                    "--example",
                    "test_server",
                    "--target-dir",
                ])
                .arg(&fixture_target_dir)
                .current_dir(&manifest_dir)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            configure_process_group(&mut command);
            let mut child = command.spawn().expect("Failed to start test_server build");
            let output = capture_with_timeout(&mut child, Duration::from_mins(15));

            assert!(
                output.exit_code == 0,
                "Failed to build test_server (exit {}; {} stdout lines, {} stderr lines)",
                output.exit_code,
                output.stdout.len(),
                output.stderr.len()
            );

            let fixture_candidates = test_server_binary_candidates(
                &manifest_dir,
                Some(fixture_target_dir.as_os_str()),
                configured_target.as_deref(),
                None,
                &binary_name,
            );
            let binary_path = cargo_example_executable(&output.stdout, "test_server")
                .expect("Cargo stdout must contain only valid JSON message records")
                .map(|path| {
                    if path.is_absolute() {
                        path
                    } else {
                        manifest_dir.join(path)
                    }
                })
                .unwrap_or_else(|| {
                    let searched = fixture_candidates
                        .iter()
                        .map(|candidate| candidate.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    panic!(
                        "Cargo emitted no executable artifact for test_server; expected layouts: {searched}"
                    )
                });
            assert!(
                binary_path.is_file(),
                "Cargo reported a test_server executable that is not a file: {}",
                binary_path.display()
            );

            eprintln!("[E2E] Built test_server at {}", binary_path.display());
            binary_path
        })
        .clone()
}

fn cargo_example_executable(
    stdout: &[String],
    example_name: &str,
) -> Result<Option<PathBuf>, String> {
    let mut executable = None;
    for (index, line) in stdout.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let message = serde_json::from_str::<serde_json::Value>(line).map_err(|error| {
            format!(
                "Cargo stdout record {} is invalid JSON ({:?} at line {}, column {})",
                index + 1,
                error.classify(),
                error.line(),
                error.column()
            )
        })?;
        let object = message
            .as_object()
            .ok_or_else(|| format!("Cargo stdout record {} is not a JSON object", index + 1))?;
        let reason = object
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("Cargo stdout record {} has no string reason", index + 1))?;
        if reason != "compiler-artifact" {
            continue;
        }
        let target = object
            .get("target")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                format!(
                    "Cargo compiler-artifact record {} has no target object",
                    index + 1
                )
            })?;
        let is_requested_example = target.get("name").and_then(serde_json::Value::as_str)
            == Some(example_name)
            && target
                .get("kind")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("example")));
        if is_requested_example {
            executable = object
                .get("executable")
                .and_then(serde_json::Value::as_str)
                .map(PathBuf::from);
        }
    }
    Ok(executable)
}

fn test_server_binary_candidates(
    manifest_dir: &Path,
    configured_target_dir: Option<&std::ffi::OsStr>,
    configured_target: Option<&std::ffi::OsStr>,
    current_executable: Option<&Path>,
    binary_name: &str,
) -> Vec<PathBuf> {
    let mut profile_directories = Vec::new();

    // The running integration test is Cargo's most authoritative description
    // of the active target root and optional target-triple directory. A test
    // binary normally lives in `<target-prefix>/<profile>/deps`; the nested
    // build always uses the dev profile, alongside that profile directory.
    if let Some(target_prefix) = current_executable
        .and_then(Path::parent)
        .filter(|directory| {
            directory
                .file_name()
                .is_some_and(|name| name == std::ffi::OsStr::new("deps"))
        })
        .and_then(Path::parent)
        .and_then(Path::parent)
    {
        push_unique_path(&mut profile_directories, target_prefix.join("debug"));
    }

    let target_dir = cargo_target_dir(manifest_dir, configured_target_dir);
    if let Some(target) = configured_target.filter(|target| !target.is_empty()) {
        push_unique_path(
            &mut profile_directories,
            target_dir.join(target).join("debug"),
        );
    }
    push_unique_path(&mut profile_directories, target_dir.join("debug"));

    profile_directories
        .into_iter()
        .map(|profile| profile.join("examples").join(binary_name))
        .collect()
}

fn cargo_target_dir(
    manifest_dir: &Path,
    configured_target_dir: Option<&std::ffi::OsStr>,
) -> PathBuf {
    configured_target_dir.map_or_else(
        || manifest_dir.join("../../target"),
        |configured| {
            let configured = PathBuf::from(configured);
            if configured.is_absolute() {
                configured
            } else {
                // Environment-supplied relative target directories are resolved
                // from the nested Cargo command's working directory.
                manifest_dir.join(configured)
            }
        },
    )
}

fn e2e_fixture_target_dir(
    manifest_dir: &Path,
    configured_target_dir: Option<&std::ffi::OsStr>,
) -> PathBuf {
    cargo_target_dir(manifest_dir, configured_target_dir).join("fastmcp-console-e2e-fixture")
}

fn push_unique_path(paths: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !paths.contains(&candidate) {
        paths.push(candidate);
    }
}

/// Configuration for E2E test runs.
#[derive(Debug, Clone)]
pub struct E2ETestConfig {
    /// Timeout for test operations.
    pub timeout: Duration,
    /// Environment variables to set.
    pub env_vars: Vec<(String, String)>,
    /// Environment variables to clear.
    pub clear_env: Vec<String>,
}

impl Default for E2ETestConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            env_vars: vec![],
            clear_env: vec![
                "MCP_CLIENT".into(),
                "CLAUDE_CODE".into(),
                "CODEX_CLI".into(),
                "CURSOR_SESSION".into(),
                "CI".into(),
                "AGENT_MODE".into(),
                "FASTMCP_PLAIN".into(),
                "NO_COLOR".into(),
                "FASTMCP_RICH".into(),
                "FASTMCP_FORCE_COLOR".into(),
                "FASTMCP_BANNER".into(),
                "FASTMCP_NO_BANNER".into(),
                "FASTMCP_LOG".into(),
                "FASTMCP_LOG_TIMESTAMPS".into(),
                "FASTMCP_LOG_TARGETS".into(),
                "FASTMCP_LOG_FILE_LINE".into(),
                "FASTMCP_TRAFFIC".into(),
            ],
        }
    }
}

impl E2ETestConfig {
    /// Create config for agent mode testing.
    #[must_use]
    pub fn agent_mode() -> Self {
        Self {
            env_vars: vec![("MCP_CLIENT".into(), "test-agent".into())],
            ..Default::default()
        }
    }

    /// Create config for human mode testing.
    #[must_use]
    pub fn human_mode() -> Self {
        Self {
            env_vars: vec![("FASTMCP_RICH".into(), "1".into())],
            ..Default::default()
        }
    }

    /// Create config for CI mode testing.
    #[must_use]
    pub fn ci_mode() -> Self {
        Self {
            env_vars: vec![("CI".into(), "1".into())],
            ..Default::default()
        }
    }

    /// Create config for NO_COLOR mode.
    #[must_use]
    pub fn no_color_mode() -> Self {
        let mut config = Self::default();
        config.env_vars.push(("NO_COLOR".into(), "1".into()));
        // Remove NO_COLOR from clear_env since we want to set it
        config.clear_env.retain(|k| k != "NO_COLOR");
        config
    }

    /// Add an environment variable.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.push((key.into(), value.into()));
        self
    }

    /// Clear an environment variable.
    #[must_use]
    pub fn without_env(mut self, key: impl Into<String>) -> Self {
        self.clear_env.push(key.into());
        self
    }
}

/// Result of running a test server.
#[derive(Debug)]
pub struct TestServerResult {
    /// Lines from stdout.
    pub stdout: Vec<String>,
    /// Lines from stderr.
    pub stderr: Vec<String>,
    /// Exit code.
    pub exit_code: i32,
    /// Duration of the test run.
    pub duration: Duration,
    response_expectations: Vec<ResponseExpectation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedResponseKind {
    Success,
    Error { code: i64 },
}

#[derive(Debug, Clone, PartialEq)]
struct ResponseExpectation {
    id: serde_json::Value,
    kind: ExpectedResponseKind,
}

impl TestServerResult {
    /// Check if stderr contains a string (for rich output).
    #[must_use]
    pub fn stderr_contains(&self, needle: &str) -> bool {
        self.stderr.iter().any(|line| line.contains(needle))
    }

    /// Check if stderr contains a string (case-insensitive).
    #[must_use]
    pub fn stderr_contains_ci(&self, needle: &str) -> bool {
        let lower = needle.to_lowercase();
        self.stderr
            .iter()
            .any(|line| line.to_lowercase().contains(&lower))
    }

    /// Assert that the fixture actually detected agent mode.
    pub fn assert_agent_context(&self) {
        assert!(
            self.stderr_contains("[test_server] Context: Agent"),
            "fixture did not report the expected agent display context"
        );
    }

    /// Assert that the fixture actually detected human mode.
    pub fn assert_human_context(&self) {
        assert!(
            self.stderr_contains("[test_server] Context: Human"),
            "fixture did not report the expected human display context"
        );
    }

    /// Check if stdout contains a string (for JSON-RPC).
    #[must_use]
    pub fn stdout_contains(&self, needle: &str) -> bool {
        self.stdout.iter().any(|line| line.contains(needle))
    }

    /// Check that stdout contains only valid JSON-RPC and matches expectations.
    #[must_use]
    pub fn stdout_is_valid_jsonrpc(&self) -> bool {
        self.exit_code == 0
            && validate_jsonrpc_output(&self.stdout, &self.response_expectations).is_ok()
    }

    /// Check for ANSI escape codes in stderr.
    #[must_use]
    pub fn stderr_has_ansi_codes(&self) -> bool {
        let combined = self.stderr.join("\n");
        contains_ansi(&combined)
    }

    /// Check for ANSI escape codes in stdout.
    #[must_use]
    pub fn stdout_has_ansi_codes(&self) -> bool {
        let combined = self.stdout.join("\n");
        contains_ansi(&combined)
    }

    /// Assert no ANSI in stdout (critical for agent mode).
    ///
    /// # Panics
    ///
    /// Panics if stdout contains ANSI codes.
    pub fn assert_stdout_no_ansi(&self) {
        let combined = self.stdout.join("\n");
        assert!(
            !contains_ansi(&combined),
            "stdout must not contain ANSI codes ({} lines, {} bytes)",
            self.stdout.len(),
            combined.len()
        );
    }

    /// Assert stdout is valid JSON-RPC and every request got its expected reply.
    ///
    /// # Panics
    ///
    /// Panics for malformed output, missing/duplicate replies, or the wrong
    /// success-versus-error response kind.
    pub fn assert_stdout_valid_jsonrpc(&self) {
        assert_eq!(
            self.exit_code,
            0,
            "server did not exit successfully (exit {}; {} stdout lines, {} stderr lines)",
            self.exit_code,
            self.stdout.len(),
            self.stderr.len()
        );
        if let Err(error) = validate_jsonrpc_output(&self.stdout, &self.response_expectations) {
            panic!("invalid JSON-RPC stdout: {error}");
        }
    }

    /// Return the successful response result correlated to a numeric request ID.
    ///
    /// This first validates the complete stdout stream, then selects the exact
    /// response envelope by ID. Notifications and unrelated responses therefore
    /// cannot satisfy payload assertions.
    ///
    /// # Panics
    ///
    /// Panics if stdout is invalid, the process failed, the response is absent,
    /// or the correlated response is not a success response.
    #[must_use]
    pub fn response_result(&self, id: u64) -> serde_json::Value {
        self.assert_stdout_valid_jsonrpc();
        let expected_id = serde_json::Value::from(id);
        self.stdout
            .iter()
            .find_map(|line| {
                let message = serde_json::from_str::<serde_json::Value>(line)
                    .expect("stdout was validated immediately before response lookup");
                (message.get("id") == Some(&expected_id)).then(|| {
                    message
                        .get("result")
                        .expect("validated success response must contain result")
                        .clone()
                })
            })
            .unwrap_or_else(|| panic!("stdout contained no response correlated to request id {id}"))
    }

    /// Print detailed diagnostics for debugging.
    pub fn print_diagnostics(&self) {
        eprintln!("\n=== E2E Test Result ===");
        eprintln!("Exit code: {exit_code}", exit_code = self.exit_code);
        eprintln!("Duration: {:?}", self.duration);
        eprintln!("\n--- STDOUT ({} lines) ---", self.stdout.len());
        for (i, line) in self.stdout.iter().enumerate() {
            eprintln!("{:4}: {}", i + 1, jsonrpc_message_metadata(line));
        }
        eprintln!("\n--- STDERR ({} lines) ---", self.stderr.len());
        for (i, line) in self.stderr.iter().enumerate() {
            eprintln!("{:4}: text bytes={}", i + 1, line.len());
        }
        eprintln!("======================\n");
    }

    /// Get combined stdout as a single string.
    #[must_use]
    pub fn stdout_string(&self) -> String {
        self.stdout.join("\n")
    }

    /// Get combined stderr as a single string.
    #[must_use]
    pub fn stderr_string(&self) -> String {
        self.stderr.join("\n")
    }
}

fn validate_jsonrpc_output(
    stdout: &[String],
    expectations: &[ResponseExpectation],
) -> Result<(), String> {
    let mut message_count = 0_usize;
    let mut matched_responses = vec![false; expectations.len()];

    for (line_index, line) in stdout.iter().enumerate() {
        if line.trim().is_empty() {
            return Err(format!(
                "stdout line {} is an empty record, not a JSON-RPC message",
                line_index + 1
            ));
        }
        message_count += 1;
        let line_number = line_index + 1;
        let metadata = jsonrpc_message_metadata(line);
        let message = serde_json::from_str::<serde_json::Value>(line)
            .map_err(|_| format!("stdout line {line_number} is not valid JSON ({metadata})"))?;
        let object = message.as_object().ok_or_else(|| {
            format!("stdout line {line_number} is not a JSON-RPC object ({metadata})")
        })?;
        if object.get("jsonrpc").and_then(serde_json::Value::as_str) != Some("2.0") {
            return Err(format!(
                "stdout line {line_number} is not JSON-RPC 2.0 ({metadata})"
            ));
        }

        if let Some(response_id) = object.get("id") {
            if !matches!(
                response_id,
                serde_json::Value::String(_)
                    | serde_json::Value::Number(_)
                    | serde_json::Value::Null
            ) {
                return Err(format!(
                    "stdout response line {line_number} has a non-scalar id ({metadata})"
                ));
            }
            if object.contains_key("method") || object.contains_key("params") {
                return Err(format!(
                    "stdout response line {line_number} contains a request field ({metadata})"
                ));
            }
            let Some((expected_index, expectation)) =
                expectations
                    .iter()
                    .enumerate()
                    .find(|(index, expectation)| {
                        !matched_responses[*index] && expectation.id == *response_id
                    })
            else {
                return Err(format!(
                    "stdout line {line_number} has an unexpected or duplicate response id ({metadata})"
                ));
            };
            validate_response_object(object, expectation.kind, line_number, &metadata)?;
            matched_responses[expected_index] = true;
        } else {
            validate_notification_object(object, line_number, &metadata)?;
        }
    }

    if message_count == 0 {
        return Err("server produced no JSON-RPC messages".into());
    }
    if let Some((index, expectation)) = expectations
        .iter()
        .enumerate()
        .find(|(index, _)| !matched_responses[*index])
    {
        return Err(format!(
            "request expectation {index} (id {}) received no correlated response",
            jsonrpc_id_metadata(&expectation.id)
        ));
    }
    Ok(())
}

fn validate_response_object(
    object: &serde_json::Map<String, serde_json::Value>,
    expected_kind: ExpectedResponseKind,
    line_number: usize,
    metadata: &str,
) -> Result<(), String> {
    match expected_kind {
        ExpectedResponseKind::Success => {
            if !object.contains_key("result") || object.contains_key("error") {
                return Err(format!(
                    "stdout response line {line_number} must contain result and no error ({metadata})"
                ));
            }
        }
        ExpectedResponseKind::Error { code } => {
            if object.contains_key("result") {
                return Err(format!(
                    "stdout error response line {line_number} must not contain result ({metadata})"
                ));
            }
            let error = object
                .get("error")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| {
                    format!(
                        "stdout error response line {line_number} has no valid error object ({metadata})"
                    )
                })?;
            let actual_code = error
                .get("code")
                .and_then(serde_json::Value::as_i64)
                .ok_or_else(|| {
                    format!(
                        "stdout error response line {line_number} has no integer error code ({metadata})"
                    )
                })?;
            if actual_code != code {
                return Err(format!(
                    "stdout error response line {line_number} has code {actual_code}, expected {code} ({metadata})"
                ));
            }
            if !error
                .get("message")
                .is_some_and(serde_json::Value::is_string)
            {
                return Err(format!(
                    "stdout error response line {line_number} has no string error message ({metadata})"
                ));
            }
        }
    }
    Ok(())
}

fn validate_notification_object(
    object: &serde_json::Map<String, serde_json::Value>,
    line_number: usize,
    metadata: &str,
) -> Result<(), String> {
    if object.contains_key("result") || object.contains_key("error") {
        return Err(format!(
            "stdout notification line {line_number} contains a response field ({metadata})"
        ));
    }
    if !object
        .get("method")
        .is_some_and(serde_json::Value::is_string)
    {
        return Err(format!(
            "stdout line {line_number} is neither a response nor a valid notification ({metadata})"
        ));
    }
    if object
        .get("params")
        .is_some_and(|params| !params.is_object() && !params.is_array())
    {
        return Err(format!(
            "stdout notification line {line_number} has invalid params ({metadata})"
        ));
    }
    Ok(())
}

fn jsonrpc_id_metadata(id: &serde_json::Value) -> String {
    match id {
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Null => "null".into(),
        serde_json::Value::String(_) => "<string>".into(),
        _ => "<non-scalar>".into(),
    }
}

/// Check if a string contains ANSI escape codes.
fn contains_ansi(s: &str) -> bool {
    s.chars()
        .any(|character| character == '\u{001b}' || ('\u{0080}'..='\u{009f}').contains(&character))
}

/// Runner for test servers.
pub struct TestServerRunner {
    config: E2ETestConfig,
}

impl TestServerRunner {
    /// Create a new test runner with the given configuration.
    #[must_use]
    pub fn new(config: E2ETestConfig) -> Self {
        Self { config }
    }

    /// Run a test server and capture output.
    ///
    /// This starts the server with the given arguments and waits for it to complete
    /// (either by EOF on stdin or by timeout).
    pub fn run_demo_mode(&self) -> TestServerResult {
        self.run_with_response_expectations(&[], Vec::new())
    }

    /// Run a test server with JSON-RPC messages.
    ///
    /// Sends the given messages to stdin and captures output.
    pub fn run_with_messages(&self, messages: &[&str]) -> TestServerResult {
        let expectations = expected_success_responses(messages);
        self.run_with_response_expectations(messages, expectations)
    }

    /// Run one request that is expected to return a JSON-RPC error response.
    pub fn run_with_expected_error(
        &self,
        message: &str,
        expected_error_code: i64,
    ) -> TestServerResult {
        let expectation = response_expectation_for_request(
            message,
            0,
            ExpectedResponseKind::Error {
                code: expected_error_code,
            },
        )
        .unwrap_or_else(|| panic!("an error-response test request must contain an id"));
        self.run_with_response_expectations(&[message], vec![expectation])
    }

    fn run_with_response_expectations(
        &self,
        messages: &[&str],
        response_expectations: Vec<ResponseExpectation>,
    ) -> TestServerResult {
        let start = std::time::Instant::now();

        // Get the pre-built binary path (builds once on first call)
        let binary_path = get_test_server_binary();

        // Build command - use the pre-built binary directly
        let mut cmd = Command::new(&binary_path);
        cmd.current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Clear environment variables first (clean slate)
        for key in &self.config.clear_env {
            cmd.env_remove(key);
        }

        // Then set environment variables (overrides take effect)
        for (key, value) in &self.config.env_vars {
            cmd.env(key, value);
        }
        configure_process_group(&mut cmd);

        eprintln!("[E2E] Starting server with {} messages", messages.len());
        eprintln!("[E2E] Binary: {}", binary_path.display());
        let environment_keys = self
            .config
            .env_vars
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<Vec<_>>();
        eprintln!(
            "[E2E] Environment overrides: {} keys {:?}",
            environment_keys.len(),
            environment_keys
        );
        eprintln!(
            "[E2E] Cleared environment: {} keys {:?}",
            self.config.clear_env.len(),
            self.config.clear_env
        );

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[E2E] Failed to spawn: {}", e);
                return TestServerResult {
                    stdout: vec![],
                    stderr: vec![format!("Failed to spawn: {}", e)],
                    exit_code: -1,
                    duration: start.elapsed(),
                    response_expectations,
                };
            }
        };

        // Establish the absolute deadline and start both drainers before any
        // potentially blocking stdin write. If the peer stops reading, killing
        // the owned process group closes the pipe and releases the writer.
        let deadline = Instant::now()
            .checked_add(self.config.timeout)
            .unwrap_or_else(Instant::now);
        let stdout_capture = capture_pipe(child.stdout.take());
        let stderr_capture = capture_pipe(child.stderr.take());
        let writer = write_messages(child.stdin.take(), messages);

        let mut result = capture_with_deadline(
            &mut child,
            stdout_capture,
            stderr_capture,
            writer,
            deadline,
            self.config.timeout,
        );
        result.response_expectations = response_expectations;

        let duration = start.elapsed();
        eprintln!(
            "[E2E] Server completed in {:?} with exit code {:?}",
            duration, result.exit_code
        );

        result
    }
}

fn expected_success_responses(messages: &[&str]) -> Vec<ResponseExpectation> {
    let mut expectations = Vec::new();
    for (index, message) in messages.iter().enumerate() {
        if let Some(expectation) =
            response_expectation_for_request(message, index, ExpectedResponseKind::Success)
        {
            assert!(
                !expectations
                    .iter()
                    .any(|existing: &ResponseExpectation| existing.id == expectation.id),
                "JSON-RPC test request {index} reuses an earlier request id"
            );
            expectations.push(expectation);
        }
    }
    expectations
}

fn response_expectation_for_request(
    message: &str,
    index: usize,
    kind: ExpectedResponseKind,
) -> Option<ResponseExpectation> {
    let metadata = jsonrpc_message_metadata(message);
    let request = serde_json::from_str::<serde_json::Value>(message)
        .unwrap_or_else(|_| panic!("JSON-RPC test request {index} is invalid JSON ({metadata})"));
    let object = request
        .as_object()
        .unwrap_or_else(|| panic!("JSON-RPC test request {index} is not an object ({metadata})"));
    assert_eq!(
        object.get("jsonrpc").and_then(serde_json::Value::as_str),
        Some("2.0"),
        "JSON-RPC test request {index} has the wrong protocol version ({metadata})"
    );
    assert!(
        object
            .get("method")
            .is_some_and(serde_json::Value::is_string),
        "JSON-RPC test request {index} has no string method ({metadata})"
    );
    assert!(
        !object.contains_key("result") && !object.contains_key("error"),
        "JSON-RPC test request {index} contains a response field ({metadata})"
    );
    assert!(
        object
            .get("params")
            .is_none_or(|params| params.is_object() || params.is_array()),
        "JSON-RPC test request {index} has invalid params ({metadata})"
    );
    object.get("id").map(|id| {
        assert!(
            matches!(
                id,
                serde_json::Value::String(_)
                    | serde_json::Value::Number(_)
                    | serde_json::Value::Null
            ),
            "JSON-RPC test request {index} has a non-scalar id ({metadata})"
        );
        ResponseExpectation {
            id: id.clone(),
            kind,
        }
    })
}

struct WriteOutcome {
    error: Option<String>,
}

fn write_messages(
    stdin: Option<impl Write + Send + 'static>,
    messages: &[&str],
) -> mpsc::Receiver<WriteOutcome> {
    let input_bytes = messages.iter().try_fold(0_usize, |total, message| {
        total
            .checked_add(message.len())
            .and_then(|total| total.checked_add(1))
    });
    if input_bytes.is_none_or(|bytes| bytes > MAX_STDIN_BYTES) {
        drop(stdin);
        let (sender, receiver) = mpsc::sync_channel(1);
        let _ = sender.send(WriteOutcome {
            error: Some(format!(
                "JSON-RPC input exceeds the {MAX_STDIN_BYTES}-byte harness limit"
            )),
        });
        return receiver;
    }
    let owned_messages = messages
        .iter()
        .map(|message| (*message).to_owned())
        .collect::<Vec<_>>();
    let (sender, receiver) = mpsc::sync_channel(1);
    let spawn_result = thread::Builder::new()
        .name("fastmcp-e2e-stdin-writer".into())
        .spawn(move || {
            let Some(mut stdin) = stdin else {
                let _ = sender.send(WriteOutcome {
                    error: Some("test server stdin was not piped".into()),
                });
                return;
            };
            let error = owned_messages
                .iter()
                .enumerate()
                .find_map(|(index, message)| {
                    eprintln!("[E2E] Sending {}", jsonrpc_message_metadata(message));
                    writeln!(stdin, "{message}")
                        .err()
                        .map(|error| format!("failed to write JSON-RPC message {index}: {error}"))
                });
            drop(stdin);
            let _ = sender.send(WriteOutcome { error });
        });
    if let Err(error) = spawn_result {
        let (fallback_sender, fallback_receiver) = mpsc::sync_channel(1);
        let _ = fallback_sender.send(WriteOutcome {
            error: Some(format!("failed to spawn stdin writer: {error}")),
        });
        return fallback_receiver;
    }
    receiver
}

fn jsonrpc_message_metadata(message: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(message).ok();
    let method_bytes = parsed
        .as_ref()
        .and_then(|value| value.get("method"))
        .and_then(serde_json::Value::as_str)
        .map(str::len);
    let id = match parsed.as_ref().and_then(|value| value.get("id")) {
        Some(serde_json::Value::Number(number)) => number.to_string(),
        Some(serde_json::Value::Null) => "null".into(),
        Some(serde_json::Value::String(_)) => "<string>".into(),
        Some(_) => "<non-scalar>".into(),
        None => "<none>".into(),
    };
    format!(
        "JSON-RPC method_present={} method_bytes={} id={id} bytes={}",
        method_bytes.is_some(),
        method_bytes.unwrap_or(0),
        message.len()
    )
}

/// Capture stdout and stderr from a child process with timeout.
fn capture_with_timeout(child: &mut Child, timeout: Duration) -> TestServerResult {
    let started_at = Instant::now();
    let stdout_capture = capture_pipe(child.stdout.take());
    let stderr_capture = capture_pipe(child.stderr.take());
    let (writer_sender, writer) = mpsc::sync_channel(1);
    let _ = writer_sender.send(WriteOutcome { error: None });
    let deadline = started_at.checked_add(timeout).unwrap_or(started_at);
    capture_with_deadline(
        child,
        stdout_capture,
        stderr_capture,
        writer,
        deadline,
        timeout,
    )
}

fn capture_with_deadline(
    child: &mut Child,
    stdout_capture: PipeCapture,
    stderr_capture: PipeCapture,
    writer: mpsc::Receiver<WriteOutcome>,
    deadline: Instant,
    timeout: Duration,
) -> TestServerResult {
    let started_at = Instant::now();
    let process_group = OwnedProcessGroup::for_child(child);
    let mut supervision = ChildSupervision::SignalSafe;
    let mut harness_errors = Vec::new();
    let (stdout_bytes, stdout_error) =
        finish_capture(stdout_capture, "stdout", remaining(deadline));
    let mut cleanup_started = false;
    if let Some(error) = stdout_error {
        harness_errors.push(error);
        request_process_termination(child, process_group, &mut supervision, &mut harness_errors);
        cleanup_started = true;
    }

    let stderr_wait = if cleanup_started {
        CAPTURE_DRAIN_DEADLINE
    } else {
        remaining(deadline)
    };
    let (stderr_bytes, stderr_error) = finish_capture(stderr_capture, "stderr", stderr_wait);
    if let Some(error) = stderr_error {
        harness_errors.push(error);
        if !cleanup_started {
            request_process_termination(
                child,
                process_group,
                &mut supervision,
                &mut harness_errors,
            );
            cleanup_started = true;
        }
    }

    match writer.recv_timeout(if cleanup_started {
        CAPTURE_DRAIN_DEADLINE
    } else {
        remaining(deadline)
    }) {
        Ok(WriteOutcome { error: Some(error) }) => harness_errors.push(error),
        Ok(WriteOutcome { error: None }) => {}
        Err(mpsc::RecvTimeoutError::Timeout) => {
            harness_errors.push("stdin writer did not finish before the deadline".into());
            if !cleanup_started {
                request_process_termination(
                    child,
                    process_group,
                    &mut supervision,
                    &mut harness_errors,
                );
                cleanup_started = true;
            }
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            harness_errors.push("stdin writer disconnected without reporting completion".into());
        }
    }

    let (stdout, stdout_lines_truncated) = match captured_jsonrpc_lines(&stdout_bytes) {
        Ok(captured) => captured,
        Err(error) => {
            harness_errors.push(error);
            (Vec::new(), false)
        }
    };
    let (mut stderr, stderr_lines_truncated) = match captured_lines(&stderr_bytes) {
        Ok(captured) => captured,
        Err(error) => {
            harness_errors.push(error);
            (Vec::new(), false)
        }
    };
    if stdout_lines_truncated {
        harness_errors.push(format!(
            "stdout exceeded the {MAX_CAPTURE_LINES}-line capture limit"
        ));
    }
    if stderr_lines_truncated {
        harness_errors.push(format!(
            "stderr exceeded the {MAX_CAPTURE_LINES}-line capture limit"
        ));
    }

    let (status, timed_out) = if harness_errors.is_empty() {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if let Err(error) = ensure_group_absent_after_leader_exit(process_group) {
                        harness_errors.push(error);
                    }
                    break (status.code().unwrap_or(-1), false);
                }
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(PROCESS_POLL_INTERVAL);
                }
                Ok(None) => {
                    request_process_termination(
                        child,
                        process_group,
                        &mut supervision,
                        &mut harness_errors,
                    );
                    reap_disarmed_child(
                        child,
                        process_group,
                        &mut supervision,
                        &mut harness_errors,
                    );
                    break (-1, true);
                }
                Err(error) => {
                    supervision = ChildSupervision::SignalDisarmed;
                    harness_errors.push(format!(
                        "failed to inspect test server: {error}; numeric signaling permanently disarmed"
                    ));
                    reap_disarmed_child(
                        child,
                        process_group,
                        &mut supervision,
                        &mut harness_errors,
                    );
                    break (-1, false);
                }
            }
        }
    } else {
        if !cleanup_started {
            request_process_termination(
                child,
                process_group,
                &mut supervision,
                &mut harness_errors,
            );
        }
        reap_disarmed_child(child, process_group, &mut supervision, &mut harness_errors);
        (-1, false)
    };

    if timed_out {
        stderr.push(format!(
            "test server exceeded its {:?} execution deadline",
            timeout
        ));
    }
    stderr.extend(
        harness_errors
            .iter()
            .map(|error| format!("test harness error: {error}")),
    );

    TestServerResult {
        stdout,
        stderr,
        exit_code: if harness_errors.is_empty() {
            status
        } else {
            -1
        },
        duration: started_at.elapsed(),
        response_expectations: Vec::new(),
    }
}

struct PipeCapture {
    completion: mpsc::Receiver<CaptureOutcome>,
    retained: Arc<Mutex<Vec<u8>>>,
}

struct CaptureOutcome {
    truncated: bool,
    read_error: Option<String>,
}

fn capture_pipe<R>(pipe: Option<R>) -> PipeCapture
where
    R: Read + Send + 'static,
{
    let (completion, completed) = mpsc::sync_channel(1);
    let retained = Arc::new(Mutex::new(Vec::new()));
    let thread_retained = Arc::clone(&retained);
    let thread_completion = completion.clone();
    let spawn_result = thread::Builder::new()
        .name("fastmcp-e2e-pipe-capture".into())
        .spawn(move || {
            let Some(mut pipe) = pipe else {
                let _ = thread_completion.send(CaptureOutcome {
                    truncated: false,
                    read_error: None,
                });
                return;
            };
            let mut buffer = [0_u8; 8 * 1024];
            let mut truncated = false;
            let read_error = loop {
                match pipe.read(&mut buffer) {
                    Ok(0) => break None,
                    Ok(read) => {
                        let mut bytes = thread_retained
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let retained_bytes = (MAX_CAPTURE_BYTES - bytes.len()).min(read);
                        bytes.extend_from_slice(&buffer[..retained_bytes]);
                        truncated |= retained_bytes < read;
                    }
                    Err(error) => break Some(error.to_string()),
                }
            };
            let _ = thread_completion.send(CaptureOutcome {
                truncated,
                read_error,
            });
        });
    if let Err(error) = spawn_result {
        let _ = completion.send(CaptureOutcome {
            truncated: false,
            read_error: Some(format!("failed to spawn capture thread: {error}")),
        });
    }
    PipeCapture {
        completion: completed,
        retained,
    }
}

fn finish_capture(capture: PipeCapture, stream: &str, wait: Duration) -> (Vec<u8>, Option<String>) {
    let completion = capture.completion.recv_timeout(wait);
    let error = match completion {
        Ok(CaptureOutcome {
            truncated,
            read_error,
        }) => match (read_error, truncated) {
            (Some(error), _) => Some(format!("failed to capture {stream}: {error}")),
            (None, true) => Some(format!(
                "{stream} exceeded the {MAX_CAPTURE_BYTES}-byte capture limit"
            )),
            (None, false) => None,
        },
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // A detached descendant can keep an inherited pipe open even after
            // the owned process group is killed. Safe Rust has no portable way
            // to cancel that blocked read, so return promptly while preserving
            // all evidence observed before the deadline.
            Some(format!("{stream} did not close within {wait:?}"))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Some(format!("{stream} capture thread disconnected"))
        }
    };
    let bytes = capture
        .retained
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    (bytes, error)
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn captured_lines(bytes: &[u8]) -> Result<(Vec<String>, bool), String> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        format!(
            "stderr is not valid UTF-8 at byte {}; terminal text was not lossily repaired",
            error.valid_up_to()
        )
    })?;
    Ok(capture_text_lines(text))
}

fn captured_jsonrpc_lines(bytes: &[u8]) -> Result<(Vec<String>, bool), String> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        format!(
            "stdout is not valid UTF-8 at byte {}; JSON-RPC text was not lossily repaired",
            error.valid_up_to()
        )
    })?;
    Ok(capture_text_lines(text))
}

fn capture_text_lines(text: &str) -> (Vec<String>, bool) {
    let mut lines = text.lines();
    let captured = lines
        .by_ref()
        .take(MAX_CAPTURE_LINES)
        .map(str::to_owned)
        .collect();
    (captured, lines.next().is_some())
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {
    panic!("console subprocess E2E tests require Unix process-group ownership")
}

#[derive(Debug, Clone, Copy)]
struct OwnedProcessGroup {
    id: u32,
}

impl OwnedProcessGroup {
    fn for_child(child: &Child) -> Self {
        Self { id: child.id() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessGroupPresence {
    Present,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildSupervision {
    /// The exact leader was last observed unreaped, so its numeric PID/PGID
    /// cannot be reused and owned-group signaling remains safe.
    SignalSafe,
    /// A wait/probe/signal uncertainty occurred. Status may still be observed
    /// and the exact child may still be reaped, but no numeric signal is safe.
    SignalDisarmed,
    /// The exact child leader has been reaped. The former PGID is observation-only.
    Reaped,
}

struct TerminationReport {
    supervision: ChildSupervision,
    error: Option<String>,
}

fn request_process_termination(
    child: &mut Child,
    process_group: OwnedProcessGroup,
    supervision: &mut ChildSupervision,
    harness_errors: &mut Vec<String>,
) {
    if *supervision != ChildSupervision::SignalSafe {
        return;
    }
    let report = terminate_process_tree(child, process_group);
    *supervision = report.supervision;
    if let Some(error) = report.error {
        harness_errors.push(error);
    }
}

fn reap_disarmed_child(
    child: &mut Child,
    process_group: OwnedProcessGroup,
    supervision: &mut ChildSupervision,
    harness_errors: &mut Vec<String>,
) {
    if *supervision != ChildSupervision::SignalDisarmed {
        return;
    }

    let started_at = Instant::now();
    let deadline = started_at
        .checked_add(PROCESS_CLEANUP_DEADLINE)
        .unwrap_or(started_at);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                *supervision = ChildSupervision::Reaped;
                if let Err(error) =
                    ensure_group_absent_after_leader_exit_until(process_group, deadline)
                {
                    harness_errors.push(error);
                }
                return;
            }
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(PROCESS_POLL_INTERVAL);
            }
            Ok(None) => {
                harness_errors.push(format!(
                    "exact child remained live or unreaped through the {PROCESS_CLEANUP_DEADLINE:?} no-signal supervision window; numeric signaling remains disarmed"
                ));
                return;
            }
            Err(error) => {
                harness_errors.push(format!(
                    "failed to reap exact child during no-signal supervision: {error}; ownership remains uncertain and no signal was sent"
                ));
                return;
            }
        }
    }
}

fn terminate_process_tree(
    child: &mut Child,
    process_group: OwnedProcessGroup,
) -> TerminationReport {
    match child.try_wait() {
        Ok(Some(_)) => {
            return TerminationReport {
                supervision: ChildSupervision::Reaped,
                error: ensure_group_absent_after_leader_exit(process_group).err(),
            };
        }
        Ok(None) => {}
        Err(error) => {
            // Once the child handle cannot establish leader state, do not send
            // any numeric PID or process-group signal.
            return TerminationReport {
                supervision: ChildSupervision::SignalDisarmed,
                error: Some(format!(
                    "failed to establish child ownership before cleanup: {error}; numeric signaling permanently disarmed"
                )),
            };
        }
    }

    match process_group_presence(process_group) {
        Ok(ProcessGroupPresence::Present) => {
            terminate_owned_process_group_with_leader(child, process_group)
        }
        Ok(ProcessGroupPresence::Absent) => TerminationReport {
            supervision: ChildSupervision::SignalDisarmed,
            error: Some(
                "child reported running but its owned process group was absent; numeric signaling permanently disarmed"
                    .into(),
            ),
        },
        Err(error) => TerminationReport {
            supervision: ChildSupervision::SignalDisarmed,
            error: Some(format!(
                "{error}; process-group probe uncertainty permanently disarmed numeric signaling"
            )),
        },
    }
}

fn terminate_owned_process_group_with_leader(
    child: &mut Child,
    process_group: OwnedProcessGroup,
) -> TerminationReport {
    match signal_process_group_if_present(process_group, "-TERM") {
        Ok(true) => {}
        Ok(false) => {
            return TerminationReport {
                supervision: ChildSupervision::SignalDisarmed,
                error: Some(
                    "owned process group disappeared while its leader still reported running; numeric signaling permanently disarmed"
                        .into(),
                ),
            };
        }
        Err(error) => {
            return TerminationReport {
                supervision: ChildSupervision::SignalDisarmed,
                error: Some(format!(
                    "failed to terminate owned process group: {error}; numeric signaling permanently disarmed"
                )),
            };
        }
    }

    let started_at = Instant::now();
    let cleanup_deadline = started_at
        .checked_add(PROCESS_CLEANUP_DEADLINE)
        .unwrap_or(started_at);
    let term_deadline = started_at
        .checked_add(Duration::from_secs(1))
        .map_or(cleanup_deadline, |deadline| deadline.min(cleanup_deadline));
    while Instant::now() < term_deadline {
        // Deliberately do not call wait/try_wait during the grace period. An
        // unreaped leader reserves its numeric PID/PGID, so the escalation
        // below cannot target a group that reused the number.
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
    if let Err(error) = signal_process_group_if_present(process_group, "-KILL") {
        return TerminationReport {
            supervision: ChildSupervision::SignalDisarmed,
            error: Some(format!(
                "failed to escalate owned process-group cleanup: {error}; numeric signaling permanently disarmed"
            )),
        };
    }

    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < cleanup_deadline => {
                thread::sleep(PROCESS_POLL_INTERVAL);
            }
            Ok(None) => {
                return TerminationReport {
                    supervision: ChildSupervision::SignalDisarmed,
                    error: Some(format!(
                        "exact child was not reaped within {PROCESS_CLEANUP_DEADLINE:?}; numeric signaling permanently disarmed"
                    )),
                };
            }
            Err(error) => {
                // TERM and KILL have already been sent. Never retry a numeric
                // signal after child ownership becomes uncertain.
                return TerminationReport {
                    supervision: ChildSupervision::SignalDisarmed,
                    error: Some(format!(
                        "failed to reap exact child after cleanup: {error}; numeric signaling permanently disarmed"
                    )),
                };
            }
        }
    }
    TerminationReport {
        supervision: ChildSupervision::Reaped,
        error: ensure_group_absent_after_leader_exit_until(process_group, cleanup_deadline).err(),
    }
}

fn ensure_group_absent_after_leader_exit(process_group: OwnedProcessGroup) -> Result<(), String> {
    let deadline = Instant::now()
        .checked_add(PROCESS_CLEANUP_DEADLINE)
        .unwrap_or_else(Instant::now);
    ensure_group_absent_after_leader_exit_until(process_group, deadline)
}

fn ensure_group_absent_after_leader_exit_until(
    process_group: OwnedProcessGroup,
    deadline: Instant,
) -> Result<(), String> {
    let verification_window = deadline.saturating_duration_since(Instant::now());
    loop {
        match process_group_presence(process_group)? {
            ProcessGroupPresence::Absent => return Ok(()),
            ProcessGroupPresence::Present if Instant::now() < deadline => {
                thread::sleep(PROCESS_POLL_INTERVAL);
            }
            ProcessGroupPresence::Present => {
                // Once the exact leader has been reaped, its numeric PID/PGID
                // can be reused. Observation is safe, but signaling that number
                // is not. Keep the leak visible instead of risking another job.
                return Err(format!(
                    "process group {} remained through the {verification_window:?} post-exit verification window; no post-reap signal sent",
                    process_group.id
                ));
            }
        }
    }
}

#[cfg(unix)]
fn process_group_presence(
    process_group: OwnedProcessGroup,
) -> Result<ProcessGroupPresence, String> {
    let group = format!("-{}", process_group.id);
    let output = Command::new("/bin/kill")
        .arg("-0")
        .arg("--")
        .arg(&group)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("failed to probe owned process group: {error}"))?;
    if output.status.success() {
        return Ok(ProcessGroupPresence::Present);
    }
    let stderr = std::str::from_utf8(&output.stderr)
        .map_err(|_| "owned process-group probe returned non-UTF-8 stderr".to_owned())?
        .to_ascii_lowercase();
    if stderr.contains("no such process") {
        Ok(ProcessGroupPresence::Absent)
    } else {
        Err(format!(
            "owned process-group probe exited with {} ({} stderr bytes); no signal sent",
            output.status,
            output.stderr.len()
        ))
    }
}

#[cfg(not(unix))]
fn process_group_presence(
    _process_group: OwnedProcessGroup,
) -> Result<ProcessGroupPresence, String> {
    Err("process-group probing is unavailable on this platform".into())
}

#[cfg(unix)]
fn signal_process_group_if_present(
    process_group: OwnedProcessGroup,
    signal: &str,
) -> Result<bool, String> {
    if process_group_presence(process_group)? == ProcessGroupPresence::Absent {
        return Ok(false);
    }

    let group = format!("-{}", process_group.id);
    let status = Command::new("/bin/kill")
        .arg(signal)
        .arg("--")
        .arg(&group)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("failed to execute process-group signal: {error}"))?;
    if status.success() {
        return Ok(true);
    }

    // The group may have exited between the positive probe and the signal.
    // Only classify that race as success after another authoritative probe.
    match process_group_presence(process_group)? {
        ProcessGroupPresence::Absent => Ok(false),
        ProcessGroupPresence::Present => Err(format!(
            "process-group signal {signal} exited with {status} while the owned group remained"
        )),
    }
}

#[cfg(not(unix))]
fn signal_process_group_if_present(
    _process_group: OwnedProcessGroup,
    _signal: &str,
) -> Result<bool, String> {
    Err("process-group signaling is unavailable on this platform".into())
}

#[cfg(test)]
mod helper_contract_tests {
    use super::*;

    fn expectation(kind: ExpectedResponseKind) -> Vec<ResponseExpectation> {
        vec![ResponseExpectation {
            id: serde_json::json!(1),
            kind,
        }]
    }

    fn output(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|line| (*line).to_owned()).collect()
    }

    #[test]
    fn cargo_artifact_message_is_the_fixture_path_authority() {
        let messages = output(&[
            r#"{"reason":"compiler-artifact","target":{"name":"dependency","kind":["lib"]},"executable":null}"#,
            r#"{"reason":"compiler-artifact","target":{"name":"test_server","kind":["example"]},"executable":"/custom-target/aarch64/debug/examples/test_server"}"#,
        ]);
        assert_eq!(
            cargo_example_executable(&messages, "test_server").expect("valid Cargo message stream"),
            Some(PathBuf::from(
                "/custom-target/aarch64/debug/examples/test_server"
            ))
        );
    }

    #[test]
    fn malformed_cargo_message_cannot_be_skipped_before_valid_artifact() {
        let messages = output(&[
            "not-json",
            r#"{"reason":"compiler-artifact","target":{"name":"test_server","kind":["example"]},"executable":"/tmp/test_server"}"#,
        ]);

        assert!(cargo_example_executable(&messages, "test_server").is_err());
        assert!(cargo_example_executable(&output(&["[]"]), "test_server").is_err());
    }

    #[test]
    fn ansi_detector_rejects_every_escape_and_c1_introducer() {
        for candidate in [
            "\u{001b}c",
            "\u{001b}Ppayload",
            "\u{009b}31m",
            "\u{009d}title",
        ] {
            assert!(contains_ansi(candidate), "missed {candidate:?}");
        }
        assert!(!contains_ansi("ordinary [bracketed] text"));
    }

    #[test]
    fn normal_requests_require_an_exact_success_response() {
        let expected = expectation(ExpectedResponseKind::Success);
        assert!(
            validate_jsonrpc_output(
                &output(&[r#"{"jsonrpc":"2.0","id":1,"result":null}"#]),
                &expected,
            )
            .is_ok()
        );
        for invalid in [
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"missing"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":null}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":1}"#,
        ] {
            assert!(
                validate_jsonrpc_output(&output(&[invalid]), &expected).is_err(),
                "normal response unexpectedly accepted: {}",
                jsonrpc_message_metadata(invalid)
            );
        }
    }

    #[test]
    fn blank_stdout_record_between_messages_is_rejected() {
        let expected = expectation(ExpectedResponseKind::Success);
        let valid_response = r#"{"jsonrpc":"2.0","id":1,"result":null}"#;

        // A normal terminal newline is framing consumed by `str::lines`, not
        // an empty record presented to the JSON-RPC validator.
        let (terminal_newline, truncated) =
            captured_lines(format!("{valid_response}\n").as_bytes())
                .expect("fixture output is valid UTF-8");
        assert!(!truncated);
        assert!(validate_jsonrpc_output(&terminal_newline, &expected).is_ok());

        let contaminated = output(&[
            valid_response,
            "   ",
            r#"{"jsonrpc":"2.0","method":"server/notice","params":{}}"#,
        ]);
        assert!(validate_jsonrpc_output(&contaminated, &expected).is_err());
    }

    #[test]
    fn invalid_utf8_stdout_is_rejected_before_json_parsing() {
        let invalid = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\xFF\"}\n";
        let error = captured_jsonrpc_lines(invalid).expect_err("invalid UTF-8 must fail closed");
        assert!(error.contains("not valid UTF-8"));
    }

    #[test]
    fn invalid_utf8_stderr_is_rejected_before_terminal_assertions() {
        let invalid = b"terminal text \xFF\n";
        let error = captured_lines(invalid).expect_err("invalid UTF-8 must fail closed");
        assert!(error.contains("not valid UTF-8"));
    }

    #[test]
    fn jsonrpc_metadata_never_echoes_method_text_or_controls() {
        const CANARY: &str = "METHOD_METADATA_SECRET_CANARY";
        let message = format!(r#"{{"jsonrpc":"2.0","method":"{CANARY}\u001b\n","id":7}}"#);

        let metadata = jsonrpc_message_metadata(&message);

        assert!(!metadata.contains(CANARY));
        assert!(!metadata.contains('\u{1b}'));
        assert!(!metadata.contains('\n'));
        assert!(metadata.contains("method_present=true"));
        assert!(metadata.contains("id=7"));
    }

    #[test]
    fn error_expectations_require_a_well_formed_exact_error() {
        let expected = expectation(ExpectedResponseKind::Error { code: -32601 });
        assert!(
            validate_jsonrpc_output(
                &output(&[r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#]),
                &expected,
            )
            .is_ok()
        );
        for invalid in [
            r#"{"jsonrpc":"2.0","id":1,"error":null}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"wrong"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601.5,"message":"fractional"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":null}}"#,
        ] {
            assert!(
                validate_jsonrpc_output(&output(&[invalid]), &expected).is_err(),
                "error response unexpectedly accepted: {}",
                jsonrpc_message_metadata(invalid)
            );
        }
    }

    #[test]
    fn notification_response_hybrids_are_rejected() {
        for invalid in [
            r#"{"jsonrpc":"2.0","method":"notice","result":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notice","error":{"code":1,"message":"bad"}}"#,
            r#"{"jsonrpc":"2.0","result":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notice","params":false}"#,
        ] {
            assert!(
                validate_jsonrpc_output(&output(&[invalid]), &[]).is_err(),
                "notification hybrid unexpectedly accepted: {}",
                jsonrpc_message_metadata(invalid)
            );
        }
    }

    #[test]
    fn relative_target_dir_uses_the_nested_cargo_working_directory() {
        let manifest = Path::new("/workspace/crates/fastmcp-console");
        let candidates = test_server_binary_candidates(
            manifest,
            Some(std::ffi::OsStr::new("relative-target")),
            Some(std::ffi::OsStr::new("aarch64-unknown-linux-gnu")),
            None,
            "test_server",
        );
        assert_eq!(
            candidates,
            vec![
                manifest
                    .join("relative-target/aarch64-unknown-linux-gnu/debug/examples/test_server"),
                manifest.join("relative-target/debug/examples/test_server"),
            ]
        );
    }

    #[test]
    fn fixture_build_uses_a_distinct_target_lock_for_absolute_and_relative_roots() {
        let manifest = Path::new("/workspace/crates/fastmcp-console");
        assert_eq!(
            e2e_fixture_target_dir(manifest, Some(std::ffi::OsStr::new("/custom-target")),),
            PathBuf::from("/custom-target/fastmcp-console-e2e-fixture")
        );
        assert_eq!(
            e2e_fixture_target_dir(manifest, Some(std::ffi::OsStr::new("relative-target")),),
            manifest.join("relative-target/fastmcp-console-e2e-fixture")
        );
    }

    #[test]
    fn current_test_executable_preserves_the_target_triple_prefix() {
        let candidates = test_server_binary_candidates(
            Path::new("/workspace/crates/fastmcp-console"),
            None,
            None,
            Some(Path::new(
                "/custom-target/aarch64-unknown-linux-gnu/release/deps/e2e-test",
            )),
            "test_server",
        );
        assert_eq!(
            candidates.first(),
            Some(&PathBuf::from(
                "/custom-target/aarch64-unknown-linux-gnu/debug/examples/test_server"
            ))
        );
    }
}

/// JSON-RPC message builders for testing.
pub mod jsonrpc {
    /// Build an initialize request.
    #[must_use]
    pub fn initialize(id: u64) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "e2e-test",
                    "version": "1.0.0"
                }
            }
        })
        .to_string()
    }

    /// Build a tools/list request.
    #[must_use]
    pub fn tools_list(id: u64) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": {}
        })
        .to_string()
    }

    /// Build a tools/call request.
    #[must_use]
    pub fn tools_call(id: u64, name: &str, args: serde_json::Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": args
            }
        })
        .to_string()
    }

    /// Build a ping request.
    #[must_use]
    pub fn ping(id: u64) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "ping"
        })
        .to_string()
    }
}
