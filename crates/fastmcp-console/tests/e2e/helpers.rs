//! Test utilities for E2E tests.
//!
//! Provides infrastructure for spawning server processes and capturing their output.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{OnceLock, mpsc};
use std::thread;
use std::time::Duration;

/// Build the test server binary once before tests run.
/// This avoids cargo lock contention when tests run in parallel.
static TEST_SERVER_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Ensure the test server binary is built and return its path.
fn get_test_server_binary() -> PathBuf {
    TEST_SERVER_PATH
        .get_or_init(|| {
            eprintln!("[E2E] Building test_server binary...");
            let output = Command::new("cargo")
                .args([
                    "build",
                    "--package",
                    "fastmcp-console",
                    "--example",
                    "test_server",
                ])
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .output()
                .expect("Failed to build test_server");

            if !output.status.success() {
                panic!(
                    "Failed to build test_server: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            // Find the binary in target directory
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let target_dir = std::env::var("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| manifest_dir.join("../../target"));
            let binary_path = target_dir.join("debug/examples/test_server");

            if !binary_path.exists() {
                panic!("test_server binary not found at {}", binary_path.display());
            }

            eprintln!("[E2E] Built test_server at {}", binary_path.display());
            binary_path
        })
        .clone()
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
    /// Whether to capture stderr.
    pub capture_stderr: bool,
    /// Whether to capture stdout.
    pub capture_stdout: bool,
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
            ],
            capture_stderr: true,
            capture_stdout: true,
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

    /// Check if stdout contains a string (for JSON-RPC).
    #[must_use]
    pub fn stdout_contains(&self, needle: &str) -> bool {
        self.stdout.iter().any(|line| line.contains(needle))
    }

    /// Check that stdout contains ONLY valid JSON-RPC.
    #[must_use]
    pub fn stdout_is_valid_jsonrpc(&self) -> bool {
        self.stdout.iter().all(|line| {
            if line.trim().is_empty() {
                return true;
            }
            serde_json::from_str::<serde_json::Value>(line).is_ok()
        })
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
            "stdout must not contain ANSI codes! Found in stdout:\n{}",
            combined
        );
    }

    /// Assert stdout is valid JSON-RPC.
    ///
    /// # Panics
    ///
    /// Panics if stdout contains non-JSON lines.
    pub fn assert_stdout_valid_jsonrpc(&self) {
        for (i, line) in self.stdout.iter().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            assert!(
                serde_json::from_str::<serde_json::Value>(line).is_ok(),
                "stdout line {} is not valid JSON:\n{}",
                i + 1,
                line
            );
        }
    }

    /// Print detailed diagnostics for debugging.
    pub fn print_diagnostics(&self) {
        eprintln!("\n=== E2E Test Result ===");
        eprintln!("Exit code: {exit_code}", exit_code = self.exit_code);
        eprintln!("Duration: {:?}", self.duration);
        eprintln!("\n--- STDOUT ({} lines) ---", self.stdout.len());
        for (i, line) in self.stdout.iter().enumerate() {
            eprintln!("{:4}: {}", i + 1, line);
        }
        eprintln!("\n--- STDERR ({} lines) ---", self.stderr.len());
        for (i, line) in self.stderr.iter().enumerate() {
            eprintln!("{:4}: {}", i + 1, line);
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

/// Check if a string contains ANSI escape codes.
fn contains_ansi(s: &str) -> bool {
    s.contains("\x1b[") || s.contains("\x1b]")
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
        self.run_with_messages(&[])
    }

    /// Run a test server with JSON-RPC messages.
    ///
    /// Sends the given messages to stdin and captures output.
    pub fn run_with_messages(&self, messages: &[&str]) -> TestServerResult {
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

        eprintln!("[E2E] Starting server with {} messages", messages.len());
        eprintln!("[E2E] Binary: {}", binary_path.display());
        eprintln!("[E2E] Environment: {:?}", self.config.env_vars);
        eprintln!("[E2E] Clear env: {:?}", self.config.clear_env);

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[E2E] Failed to spawn: {}", e);
                return TestServerResult {
                    stdout: vec![],
                    stderr: vec![format!("Failed to spawn: {}", e)],
                    exit_code: -1,
                    duration: start.elapsed(),
                };
            }
        };

        // Send messages to stdin
        if let Some(mut stdin) = child.stdin.take() {
            for msg in messages {
                eprintln!("[E2E] Sending: {}", msg);
                if let Err(e) = writeln!(stdin, "{}", msg) {
                    eprintln!("[E2E] Write error: {}", e);
                }
            }
            // Close stdin to signal EOF
            drop(stdin);
        }

        // Capture output with timeout
        let result = capture_with_timeout(&mut child, self.config.timeout);

        let duration = start.elapsed();
        eprintln!(
            "[E2E] Server completed in {:?} with exit code {:?}",
            duration, result.exit_code
        );

        result
    }
}

/// Capture stdout and stderr from a child process with timeout.
fn capture_with_timeout(child: &mut Child, timeout: Duration) -> TestServerResult {
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    // Spawn threads to read stdout and stderr
    let (stdout_tx, stdout_rx) = mpsc::channel();
    let (stderr_tx, stderr_rx) = mpsc::channel();

    if let Some(stdout) = stdout_handle {
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
            let _ = stdout_tx.send(lines);
        });
    } else {
        let _ = stdout_tx.send(vec![]);
    }

    if let Some(stderr) = stderr_handle {
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
            let _ = stderr_tx.send(lines);
        });
    } else {
        let _ = stderr_tx.send(vec![]);
    }

    // Wait for process with timeout
    let status = match child.wait() {
        Ok(s) => s.code().unwrap_or(-1),
        Err(e) => {
            eprintln!("[E2E] Wait error: {}", e);
            -1
        }
    };

    // Collect output
    let stdout = stdout_rx.recv_timeout(timeout).unwrap_or_default();
    let stderr = stderr_rx.recv_timeout(timeout).unwrap_or_default();

    TestServerResult {
        stdout,
        stderr,
        exit_code: status,
        duration: timeout,
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
