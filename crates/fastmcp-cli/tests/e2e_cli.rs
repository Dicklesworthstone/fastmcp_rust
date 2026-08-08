//! E2E tests for fastmcp CLI command execution.
//!
//! These tests spawn the actual CLI binary and verify:
//! - Exit codes
//! - stdout/stderr output
//! - Command behavior

#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Child, ExitStatus, Stdio};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::sync::{Arc, Mutex, mpsc};
#[cfg(unix)]
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
const CLI_DEADLINE: Duration = Duration::from_secs(120);
#[cfg(unix)]
const CAPTURE_DRAIN_DEADLINE: Duration = Duration::from_secs(1);
#[cfg(unix)]
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
#[cfg(unix)]
const PROCESS_CLEANUP_DEADLINE: Duration = Duration::from_secs(2);
#[cfg(unix)]
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
#[cfg(unix)]
const PROCESS_TERM_GRACE: Duration = Duration::from_millis(500);
static TEMP_DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[cfg(unix)]
const STATIC_MCP_SERVER_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/static_mcp_server.sh"
);

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_nanos();
        let sequence = TEMP_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_root = std::fs::canonicalize(std::env::temp_dir())
            .expect("resolve the test temporary directory without symlink components");
        let path = temp_root.join(format!(
            "fastmcp-cli-{prefix}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create temp directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("secure temp directory permissions");
        }
        Self { path }
    }
}

impl AsRef<Path> for TestTempDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl std::ops::Deref for TestTempDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

/// Path to the compiled binary (in debug or release mode).
fn get_binary_path() -> String {
    // Use cargo-built binary path
    env!("CARGO_BIN_EXE_fastmcp").to_string()
}

#[cfg(unix)]
#[derive(Debug)]
struct DeadlineExceeded {
    timeout: Duration,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    cleanup_error: Option<String>,
}

#[cfg(unix)]
struct ProcessGroupGuard {
    child: Option<Child>,
    #[cfg(unix)]
    process_group_id: u32,
    owns_process_group: bool,
    armed: bool,
}

#[cfg(unix)]
impl ProcessGroupGuard {
    fn spawn(command: &mut Command) -> Self {
        configure_process_group(command);
        let child = command.spawn().expect("spawn command");
        #[cfg(unix)]
        let process_group_id = child.id();
        Self {
            child: Some(child),
            #[cfg(unix)]
            process_group_id,
            owns_process_group: true,
            armed: true,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("process guard is disarmed")
    }

    fn wait_until(&mut self, timeout: Duration) -> Result<ExitStatus, DeadlineExceeded> {
        let started = Instant::now();
        loop {
            match self.child_is_zombie("failed to inspect child process") {
                Ok(true) => {
                    return Ok(self
                        .kill_and_reap()
                        .unwrap_or_else(|error| {
                            panic!("failed to clean up command descendants after exit: {error}")
                        })
                        .expect("observed zombie child must yield an exit status"));
                }
                Ok(false) => {}
                Err(error) => {
                    self.owns_process_group = false;
                    self.armed = false;
                    panic!("{error}; guard disarmed without signaling");
                }
            }

            if started.elapsed() >= timeout {
                return Err(DeadlineExceeded {
                    timeout,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    cleanup_error: self.kill_and_reap().err(),
                });
            }
            std::thread::sleep(PROCESS_POLL_INTERVAL);
        }
    }

    #[cfg(unix)]
    fn signal_group(&self, signal: &str) -> Result<(), String> {
        let target = format!("-{}", self.process_group_id);
        let status = Command::new("/bin/kill")
            .args([signal, "--", &target])
            .status()
            .map_err(|error| format!("failed to execute /bin/kill: {error}"))?;
        if status.success() || !process_group_has_live_member(self.process_group_id)? {
            return Ok(());
        }
        Err(format!(
            "/bin/kill {signal} -- {target} exited with {status}"
        ))
    }

    fn child_is_zombie(&self, context: &str) -> Result<bool, String> {
        process_is_zombie(self.child.as_ref().expect("process guard is disarmed").id())
            .map_err(|error| format!("{context}: {error}"))
    }

    fn wait_for_cleanup_state(&mut self, deadline: Instant) -> Result<(bool, bool), String> {
        loop {
            let child_exited = self.child_is_zombie("failed to inspect exact child")?;
            let group_live =
                self.owns_process_group && process_group_has_live_member(self.process_group_id)?;
            if (child_exited && !group_live) || Instant::now() >= deadline {
                return Ok((child_exited, group_live));
            }
            std::thread::sleep(PROCESS_POLL_INTERVAL);
        }
    }

    fn kill_and_reap(&mut self) -> Result<Option<ExitStatus>, String> {
        if !self.armed {
            return Ok(None);
        }

        let deadline = Instant::now()
            .checked_add(PROCESS_CLEANUP_DEADLINE)
            .unwrap_or_else(Instant::now);
        let mut errors = Vec::new();
        let mut direct_kill_error = None;
        let mut child_exited = match self.child_is_zombie("failed to inspect exact child") {
            Ok(exited) => exited,
            Err(error) => {
                self.owns_process_group = false;
                self.armed = false;
                return Err(format!("{error}; guard disarmed without signaling"));
            }
        };

        // The leader is deliberately left unreaped until every group signal
        // has completed. A live or zombie unreaped leader pins its numeric
        // PGID, so the fresh membership checks below cannot refer to a reused
        // process group.
        let mut group_live = match process_group_has_live_member(self.process_group_id) {
            Ok(live) => live,
            Err(error) => {
                self.owns_process_group = false;
                self.armed = false;
                return Err(format!(
                    "failed to inspect owned process group; guard disarmed without signaling: {error}"
                ));
            }
        };

        if group_live {
            if let Err(error) = self.signal_group("-TERM") {
                self.owns_process_group = false;
                self.armed = false;
                return Err(format!("{error}; guard disarmed without further signaling"));
            } else {
                let term_deadline = deadline.min(
                    Instant::now()
                        .checked_add(PROCESS_TERM_GRACE)
                        .unwrap_or(deadline),
                );
                match self.wait_for_cleanup_state(term_deadline) {
                    Ok((exited, live)) => {
                        child_exited = exited;
                        group_live = live;
                    }
                    Err(error) => {
                        self.owns_process_group = false;
                        self.armed = false;
                        return Err(format!("{error}; guard disarmed without further signaling"));
                    }
                }
                if group_live {
                    if let Err(error) = self.signal_group("-KILL") {
                        self.owns_process_group = false;
                        self.armed = false;
                        return Err(format!("{error}; guard disarmed without further signaling"));
                    }
                }
            }
        }

        if !child_exited {
            match self.child_is_zombie("failed to inspect exact child before direct kill") {
                Ok(true) => {}
                Ok(false) => {
                    direct_kill_error = self.child_mut().kill().err();
                }
                Err(error) => {
                    self.owns_process_group = false;
                    self.armed = false;
                    return Err(format!("{error}; guard disarmed without direct signaling"));
                }
            }
        }

        match self.wait_for_cleanup_state(deadline) {
            Ok((exited, live)) => {
                child_exited = exited;
                group_live = live;
            }
            Err(error) => {
                self.owns_process_group = false;
                self.armed = false;
                return Err(format!("{error}; guard disarmed without further signaling"));
            }
        }
        if !child_exited {
            if let Some(error) = direct_kill_error {
                errors.push(format!("failed to kill exact child: {error}"));
            }
            errors.push(format!(
                "exact child did not exit within {PROCESS_CLEANUP_DEADLINE:?}"
            ));
        }
        if group_live {
            errors.push(format!(
                "owned process group {} still has live members after {PROCESS_CLEANUP_DEADLINE:?}",
                self.process_group_id
            ));
        }
        let exit_status = match self.child_mut().try_wait() {
            Ok(status) => status,
            Err(error) => {
                errors.push(format!(
                    "failed to reap exact child after all signaling completed: {error}"
                ));
                None
            }
        };
        self.child = None;
        self.owns_process_group = false;
        self.armed = false;

        if errors.is_empty() {
            Ok(exit_status)
        } else {
            Err(errors.join("; "))
        }
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let Err(error) = self.kill_and_reap() {
            eprintln!("fastmcp CLI test harness cleanup failed: {error}");
        }
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    command.process_group(0);
}

#[cfg(target_os = "linux")]
fn proc_process_disappeared(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
        || error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error())
}

#[cfg(target_os = "linux")]
fn process_group_has_live_member(process_group_id: u32) -> Result<bool, String> {
    let processes = std::fs::read_dir("/proc")
        .map_err(|error| format!("failed to enumerate /proc: {error}"))?;
    for entry in processes {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!("failed to enumerate /proc entry: {error}"));
            }
        };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(error) if proc_process_disappeared(&error) => continue,
            Err(error) => {
                return Err(format!("failed to read process {pid} state: {error}"));
            }
        };
        let (state, group) = linux_process_state_and_group(&stat)
            .ok_or_else(|| format!("malformed /proc/{pid}/stat"))?;
        if group == process_group_id && !matches!(state, 'Z' | 'X' | 'x') {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_group_has_live_member(process_group_id: u32) -> Result<bool, String> {
    let output = Command::new("/bin/ps")
        .args(["-ax", "-o", "pgid=", "-o", "stat="])
        .output()
        .map_err(|error| format!("failed to inspect process groups with /bin/ps: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "/bin/ps process-group inspection exited with {}",
            output.status
        ));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|error| format!("/bin/ps emitted non-UTF-8 process-group output: {error}"))?;
    let mut group_live = false;
    for (line_index, line) in stdout.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let group = fields
            .next()
            .ok_or_else(|| format!("/bin/ps line {} is missing a PGID", line_index + 1))?
            .parse::<u32>()
            .map_err(|error| {
                format!(
                    "/bin/ps line {} has an invalid PGID: {error}",
                    line_index + 1
                )
            })?;
        let state = fields
            .next()
            .and_then(|value| value.chars().next())
            .ok_or_else(|| format!("/bin/ps line {} is missing a state", line_index + 1))?;
        if fields.next().is_some() {
            return Err(format!(
                "/bin/ps line {} has unexpected extra fields",
                line_index + 1
            ));
        }
        if group == process_group_id && !matches!(state, 'Z' | 'X') {
            group_live = true;
        }
    }
    Ok(group_live)
}

#[cfg(target_os = "linux")]
fn process_is_zombie(pid: u32) -> Result<bool, String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|error| format!("failed to read process {pid} state: {error}"))?;
    let (state, _) = linux_process_state_and_group(&stat)
        .ok_or_else(|| format!("malformed /proc/{pid}/stat"))?;
    Ok(matches!(state, 'Z' | 'X' | 'x'))
}

#[cfg(target_os = "linux")]
fn linux_process_state_and_group(stat: &str) -> Option<(char, u32)> {
    let (_, fields) = stat.rsplit_once(')')?;
    let mut fields = fields.split_ascii_whitespace();
    let state = fields.next()?.chars().next()?;
    let _parent_pid = fields.next()?;
    let process_group_id = fields.next()?.parse().ok()?;
    Some((state, process_group_id))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_is_zombie(pid: u32) -> Result<bool, String> {
    let output = Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .map_err(|error| format!("failed to inspect process {pid} with /bin/ps: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "/bin/ps inspection for process {pid} exited with {}",
            output.status
        ));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| format!("/bin/ps returned non-UTF-8 state for process {pid}"))?;
    let mut fields = stdout.split_ascii_whitespace();
    let state = fields
        .next()
        .and_then(|value| value.chars().next())
        .ok_or_else(|| format!("process {pid} disappeared before it was reaped"))?;
    if fields.next().is_some() {
        return Err(format!(
            "/bin/ps returned multiple state fields for process {pid}"
        ));
    }
    Ok(matches!(state, 'Z' | 'X'))
}

#[cfg(unix)]
struct PipeCapture {
    completion: mpsc::Receiver<CaptureOutcome>,
    retained: Arc<Mutex<Vec<u8>>>,
}

#[cfg(unix)]
struct CaptureOutcome {
    truncated: bool,
    read_error: Option<String>,
}

#[cfg(unix)]
fn capture_pipe<R>(mut pipe: R) -> PipeCapture
where
    R: Read + Send + 'static,
{
    let (completion, completed) = mpsc::sync_channel(1);
    let retained = Arc::new(Mutex::new(Vec::new()));
    let thread_retained = Arc::clone(&retained);
    drop(std::thread::spawn(move || {
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
        let _ = completion.send(CaptureOutcome {
            truncated,
            read_error,
        });
    }));
    PipeCapture {
        completion: completed,
        retained,
    }
}

#[cfg(unix)]
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
            // Safe Rust cannot cancel a blocked read held open by a detached
            // descendant, but the shared buffer preserves evidence so far.
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

#[cfg(unix)]
fn run_with_deadline(mut command: Command, timeout: Duration) -> Result<Output, DeadlineExceeded> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut process = ProcessGroupGuard::spawn(&mut command);
    let stdout = capture_pipe(
        process
            .child_mut()
            .stdout
            .take()
            .expect("child stdout must be piped"),
    );
    let stderr = capture_pipe(
        process
            .child_mut()
            .stderr
            .take()
            .expect("child stderr must be piped"),
    );

    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let (stdout, stdout_error) = finish_capture(stdout, "stdout", remaining(deadline));
    if let Some(error) = stdout_error {
        let cleanup_error = process.kill_and_reap().err();
        let (stderr, stderr_error) = finish_capture(stderr, "stderr", CAPTURE_DRAIN_DEADLINE);
        return Err(DeadlineExceeded {
            timeout,
            stdout,
            stderr,
            cleanup_error: Some(
                [Some(error), stderr_error, cleanup_error]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
        });
    }

    let (stderr, stderr_error) = finish_capture(stderr, "stderr", remaining(deadline));
    if let Some(error) = stderr_error {
        let cleanup_error = process.kill_and_reap().err();
        return Err(DeadlineExceeded {
            timeout,
            stdout,
            stderr,
            cleanup_error: Some(
                [Some(error), cleanup_error]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
        });
    }

    match process.wait_until(remaining(deadline)) {
        Ok(status) => Ok(Output {
            status,
            stdout,
            stderr,
        }),
        Err(mut expired) => {
            expired.timeout = timeout;
            expired.stdout = stdout;
            expired.stderr = stderr;
            Err(expired)
        }
    }
}

#[cfg(unix)]
fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

#[cfg(unix)]
fn run_command(command: Command) -> Output {
    run_with_deadline(command, CLI_DEADLINE).unwrap_or_else(|expired| {
        panic!(
            "command exceeded the {:?} harness deadline; cleanup error: {:?}; captured stdout={} bytes, stderr={} bytes (content redacted)",
            expired.timeout,
            expired.cleanup_error,
            expired.stdout.len(),
            expired.stderr.len()
        )
    })
}

#[cfg(not(unix))]
fn run_command(mut command: Command) -> Output {
    command.output().expect("run CLI command")
}

/// Helper to run the CLI and capture output.
fn run_cli(args: &[&str]) -> Output {
    let mut command = Command::new(get_binary_path());
    command
        .args(args)
        // Keep E2E output deterministic: no network checks and no "update available" noise.
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .env_remove("CLINE_MCP_SETTINGS_PATH")
        .env_remove("CLINE_DATA_DIR")
        .env_remove("CLINE_DIR");
    run_command(command)
}

#[cfg(unix)]
fn fixture_server_args<'a>(prefix: &[&'a str], after_server: &[&'a str]) -> Vec<&'a str> {
    let mut args = Vec::with_capacity(prefix.len() + after_server.len() + 3);
    args.extend_from_slice(prefix);
    args.push("/bin/sh");
    args.extend_from_slice(after_server);
    args.extend_from_slice(&["--", STATIC_MCP_SERVER_FIXTURE]);
    args
}

struct IsolatedCliEnvironment {
    home: std::path::PathBuf,
    xdg_config: std::path::PathBuf,
    xdg_data: std::path::PathBuf,
    xdg_cache: std::path::PathBuf,
    project: std::path::PathBuf,
    _root: TestTempDir,
}

impl IsolatedCliEnvironment {
    fn new(label: &str) -> Self {
        let root = TestTempDir::new(label);
        let environment = Self {
            home: root.join("home"),
            xdg_config: root.join("xdg-config"),
            xdg_data: root.join("xdg-data"),
            xdg_cache: root.join("xdg-cache"),
            project: root.join("project"),
            _root: root,
        };
        for directory in [
            &environment.home,
            &environment.xdg_config,
            &environment.xdg_data,
            &environment.xdg_cache,
            &environment.project,
        ] {
            std::fs::create_dir_all(directory).expect("create isolated CLI directory");
        }
        environment
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(get_binary_path());
        command
            .args(args)
            .env("FASTMCP_CHECK_FOR_UPDATES", "0")
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg_config)
            .env("XDG_DATA_HOME", &self.xdg_data)
            .env("XDG_CACHE_HOME", &self.xdg_cache)
            .env("APPDATA", self.home.join("AppData/Roaming"))
            .env("LOCALAPPDATA", self.home.join("AppData/Local"))
            .env_remove("CLINE_MCP_SETTINGS_PATH")
            .env_remove("CLINE_DATA_DIR")
            .env_remove("CLINE_DIR")
            .current_dir(&self.project);
        run_command(command)
    }
}

/// Helper to get stdout as string.
fn stdout_str(output: &Output) -> String {
    std::str::from_utf8(&output.stdout)
        .expect("fastmcp CLI stdout must be valid UTF-8")
        .to_owned()
}

/// Helper to get stderr as string.
fn stderr_str(output: &Output) -> String {
    std::str::from_utf8(&output.stderr)
        .expect("fastmcp CLI stderr must be valid UTF-8")
        .to_owned()
}

#[cfg(unix)]
fn inspect_fixture_server(format: &str) -> Output {
    run_cli(&fixture_server_args(&["inspect", "-f", format], &[]))
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
    assert!(
        stdout.contains("MCP 2026-07-28") && stdout.contains("2024-11-05"),
        "help should disclose the unverified target and current protocol version"
    );
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
    assert!(stdout.contains("--cwd"));
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
    assert!(stdout.contains("--idle-timeout"));
    assert!(stdout.contains("--absolute-timeout"));
    assert!(!stdout.contains("  --timeout"));
    assert!(stdout.contains("[default: 30]"));
    assert!(stdout.contains("[default: 120]"));
    assert!(stdout.contains("--verbose"));
    let normalized = stdout.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains("Per-request idle timeout in seconds (1-300)."));
    assert!(normalized.contains("Non-resettable per-request absolute timeout in seconds (1-900)."));
    assert!(normalized.contains("Starts when initialization or a later MCP request is committed."));
    assert!(normalized.contains("The current connectivity probes do not attach progress tokens"));
    assert!(normalized.contains("peer traffic does not reset their idle timers."));
    assert!(normalized.contains("It does not bound the whole CLI or subprocess lifetime."));
    assert!(normalized.contains(
        "This command is currently Unix-only: other platforms fail before spawning because no Job Object equivalent is implemented yet."
    ));
    assert!(normalized
        .contains("On Unix child stdio, the request timers bound silent and partial-frame reads;"));
    assert!(normalized.contains("blocking child-stdin writes cannot be preempted"));
}

#[test]
fn e2e_cli_dev_help() {
    let output = run_cli(&["dev", "--help"]);

    assert!(output.status.success());

    let stdout = stdout_str(&output);
    assert!(stdout.contains("development mode"));
    assert!(stdout.contains("--reload-dir"));
    assert!(stdout.contains("--reload-pattern"));
    assert!(!stdout.contains("--host"));
    assert!(!stdout.contains("--port"));
    assert!(!stdout.contains("--transport"));
}

#[test]
fn e2e_cli_tasks_help() {
    let output = run_cli(&["tasks", "--help"]);

    assert!(output.status.success());

    let stdout = stdout_str(&output);
    assert!(stdout.contains("legacy background-task RPCs"));
    assert!(stdout.contains("quarantined"));
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
    let dir = TestTempDir::new("run-cwd");

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
fn e2e_cli_run_sets_env_vars_and_rejects_invalid_format() {
    let output = run_cli(&["run", "-e", "FOO=bar", "sh", "--", "-c", "echo $FOO"]);

    assert!(output.status.success());
    assert_eq!(stdout_str(&output).trim(), "bar");

    let output = run_cli(&["run", "-e", "NOT_A_PAIR", "sh", "--", "-c", "echo ok"]);
    assert!(!output.status.success());
    assert!(!stdout_str(&output).contains("ok"));
    assert!(
        stderr_str(&output).contains("expected KEY=VALUE"),
        "expected invalid env var error, got: {}",
        stderr_str(&output)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_cli_dev_rejects_invalid_environment_assignment_before_spawn() {
    let output = run_cli(&["dev", "--no-reload", "-e", "NOT_A_PAIR", "/bin/true"]);

    assert!(!output.status.success());
    assert!(stderr_str(&output).contains("expected KEY=VALUE"));
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_cli_dev_rejects_missing_reload_directory() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_nanos();
    let missing = format!("fastmcp-missing-watch-root-{}-{nonce}", std::process::id());
    let output = run_cli(&["dev", "--reload-dir", &missing, "/bin/true"]);

    assert!(!output.status.success());
    assert!(stderr_str(&output).contains("Failed to resolve reload directory"));
}

#[test]
fn e2e_cli_inspect_missing_server_fails() {
    let output = run_cli(&["inspect"]);

    assert!(!output.status.success());
}

#[cfg(unix)]
#[test]
fn e2e_cli_inspect_text_lists_server_capabilities_and_items() {
    let output = inspect_fixture_server("text");
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
    let output = inspect_fixture_server("json");
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
fn e2e_cli_inspect_closed_stdout_exits_nonzero() {
    let mut command = Command::new(get_binary_path());
    command
        .args(fixture_server_args(&["inspect", "-f", "json"], &[]))
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut process = ProcessGroupGuard::spawn(&mut command);
    drop(
        process
            .child_mut()
            .stdout
            .take()
            .expect("inspect stdout pipe"),
    );
    let stderr = capture_pipe(
        process
            .child_mut()
            .stderr
            .take()
            .expect("inspect stderr pipe"),
    );

    let deadline = Instant::now()
        .checked_add(CLI_DEADLINE)
        .unwrap_or_else(Instant::now);
    let (stderr, capture_error) = finish_capture(stderr, "stderr", remaining(deadline));
    if let Some(error) = capture_error {
        let cleanup_error = process.kill_and_reap().err();
        panic!(
            "failed to drain closed-stdout inspect stderr: {error}; cleanup error: {cleanup_error:?}"
        );
    }
    let status = process
        .wait_until(remaining(deadline))
        .unwrap_or_else(|expired| {
            panic!(
                "closed-stdout inspect exceeded the {:?} deadline; cleanup error: {:?}",
                expired.timeout, expired.cleanup_error
            )
        });
    let output = Output {
        status,
        stdout: Vec::new(),
        stderr,
    };
    assert!(!output.status.success());
    assert_eq!(stdout_str(&output), "");
    assert!(
        stderr_str(&output).contains("Failed to write inspect output to stdout"),
        "closed stdout should reach the top-level error path; stderr: {}",
        stderr_str(&output)
    );
}

#[cfg(unix)]
#[test]
fn e2e_cli_inspect_rejects_schema_misleading_mcp_format_alias() {
    let output = run_cli(&["inspect", "-f", "mcp", "echo-server"]);

    assert!(!output.status.success());
    assert!(stderr_str(&output).contains("text, json"));
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_cli_inspect_output_file_writes_payload() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let output_dir = TestTempDir::new("inspect-output");
    let output_path = output_dir.join("inspect-output.json");
    std::fs::write(&output_path, b"{}\n").expect("seed existing inspect output");
    std::fs::set_permissions(&output_path, std::fs::Permissions::from_mode(0o640))
        .expect("set inspect output mode");
    let seeded_metadata = std::fs::metadata(&output_path).expect("inspect seeded output");

    let output = run_cli(&fixture_server_args(
        &[
            "inspect",
            "-f",
            "json",
            "-o",
            output_path
                .to_str()
                .expect("temp output path should be valid utf-8"),
        ],
        &[],
    ));

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
    let first_bytes = std::fs::read(&output_path).expect("read first inspect output");
    let first_metadata = std::fs::metadata(&output_path).expect("inspect first output metadata");
    assert_eq!(first_metadata.permissions().mode() & 0o777, 0o640);
    assert_eq!(first_metadata.uid(), seeded_metadata.uid());
    assert_eq!(first_metadata.gid(), seeded_metadata.gid());

    let second = run_cli(&fixture_server_args(
        &[
            "inspect",
            "-f",
            "json",
            "-o",
            output_path
                .to_str()
                .expect("temp output path should be valid utf-8"),
        ],
        &[],
    ));
    assert!(
        second.status.success(),
        "idempotent inspect with output file should succeed, stderr: {}",
        stderr_str(&second)
    );
    let second_metadata =
        std::fs::metadata(&output_path).expect("inspect idempotent output metadata");
    assert_eq!(
        std::fs::read(&output_path).expect("read idempotent inspect output"),
        first_bytes
    );
    assert_eq!(second_metadata.ino(), first_metadata.ino());
    assert_eq!(second_metadata.permissions().mode() & 0o777, 0o640);
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
fn e2e_cli_tasks_list_is_quarantined_by_the_server() {
    let output = run_cli(&fixture_server_args(&["tasks", "list"], &[]));

    assert!(!output.status.success());
    assert!(stdout_str(&output).is_empty());
    assert!(stderr_str(&output).contains("Method not found"));
}

#[cfg(unix)]
#[test]
fn e2e_cli_tasks_list_json_is_quarantined_by_the_server() {
    let output = run_cli(&fixture_server_args(&["tasks", "list", "--json"], &[]));

    assert!(!output.status.success());
    assert!(stdout_str(&output).is_empty());
    assert!(stderr_str(&output).contains("Method not found"));
}

#[cfg(unix)]
#[test]
fn e2e_cli_tasks_list_with_status_filter_is_quarantined() {
    let output = run_cli(&fixture_server_args(
        &["tasks", "list", "--status", "pending"],
        &[],
    ));

    assert!(!output.status.success());
    assert!(stdout_str(&output).is_empty());
    assert!(stderr_str(&output).contains("Method not found"));
}

#[cfg(unix)]
#[test]
fn e2e_cli_tasks_stats_json_is_quarantined_by_the_server() {
    let output = run_cli(&fixture_server_args(&["tasks", "stats", "--json"], &[]));

    assert!(!output.status.success());
    assert!(stdout_str(&output).is_empty());
    assert!(stderr_str(&output).contains("Method not found"));
}

#[cfg(unix)]
#[test]
fn e2e_cli_tasks_show_is_quarantined_before_task_lookup() {
    let output = run_cli(&fixture_server_args(&["tasks", "show"], &["task-999"]));

    assert!(!output.status.success());
    assert!(
        stderr_str(&output).contains("Method not found"),
        "expected method-not-found quarantine error, stderr: {}",
        stderr_str(&output)
    );
}

#[cfg(unix)]
#[test]
fn e2e_cli_tasks_cancel_is_quarantined_before_task_lookup() {
    let output = run_cli(&fixture_server_args(&["tasks", "cancel"], &["task-999"]));

    assert!(!output.status.success());
    assert!(
        stderr_str(&output).contains("Method not found"),
        "expected method-not-found quarantine error, stderr: {}",
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
fn e2e_cli_dev_removed_network_options_fail() {
    for option in ["--host", "--port", "--transport"] {
        let output = run_cli(&["dev", option, "unused", "."]);
        assert!(
            !output.status.success(),
            "removed option {option} must be rejected"
        );
    }
}

#[test]
fn e2e_cli_test_removed_single_timeout_option_fails() {
    let output = run_cli(&["test", "--timeout", "30", "./server"]);

    assert!(
        !output.status.success(),
        "removed --timeout option must not remain as an alias"
    );
    assert!(
        stderr_str(&output).contains("--timeout"),
        "clap should identify the removed option"
    );
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
    let stdout = stdout_str(&output);
    assert!(stdout.contains("Cline settings"));
    let json_start = stdout.find('{').expect("Cline dry-run JSON object");
    let preview: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("parse Cline dry-run JSON");
    let entry = &preview["mcpServers"]["test-server"];
    assert_eq!(entry["transport"]["type"], "stdio");
    assert_eq!(entry["transport"]["command"], "/bin/server");
    assert!(entry.get("command").is_none());
    assert!(preview.get("cline.mcpServers").is_none());
}

// =============================================================================
// List Command Tests
// =============================================================================

#[test]
fn e2e_cli_list_default() {
    let environment = IsolatedCliEnvironment::new("list-default");
    let output = environment.run(&["list"]);

    assert!(
        output.status.success(),
        "isolated list should succeed, stderr: {}",
        stderr_str(&output)
    );
    assert!(
        stdout_str(&output).contains("No configured servers found."),
        "isolated list should report an empty registry, stdout: {}",
        stdout_str(&output)
    );
}

#[test]
fn e2e_cli_list_json_format() {
    let environment = IsolatedCliEnvironment::new("list-json");
    std::fs::write(
        environment.project.join("mcp.json"),
        r#"{"servers":{"isolated-server":{"command":"fixture-command","args":["--safe"],"env":{"TOKEN":"secret"},"cwd":"/srv/fixture"}}}"#,
    )
    .expect("write isolated project config");

    let output = environment.run(&["list", "-f", "json"]);
    assert!(
        output.status.success(),
        "isolated JSON list should succeed, stderr: {}",
        stderr_str(&output)
    );

    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("list JSON should parse");
    let root = document
        .as_object()
        .expect("list JSON root should be an object");
    assert_eq!(
        root.len(),
        4,
        "list JSON should expose servers plus explicit mutation metadata"
    );
    assert_eq!(
        root.get("redacted").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        root.get("sanitized").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        root.get("truncated").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let servers = root
        .get("servers")
        .and_then(serde_json::Value::as_array)
        .expect("list JSON should contain a servers array");
    assert_eq!(
        servers.len(),
        1,
        "fixture should produce exactly one server"
    );

    let server = servers[0]
        .as_object()
        .expect("each list JSON server should be an object");
    assert!(server.get("name").is_some_and(serde_json::Value::is_string));
    assert!(
        server
            .get("source")
            .is_some_and(serde_json::Value::is_string)
    );
    assert!(
        server
            .get("command")
            .is_some_and(serde_json::Value::is_string)
    );
    assert!(server.get("args").is_some_and(serde_json::Value::is_array));
    assert!(server.get("env").is_some_and(serde_json::Value::is_object));
    assert!(server.get("cwd").is_some_and(serde_json::Value::is_string));
    assert!(
        server
            .get("enabled")
            .is_some_and(serde_json::Value::is_boolean)
    );
    assert_eq!(
        server.get("name").and_then(serde_json::Value::as_str),
        Some("isolated-server")
    );
    assert_eq!(
        server.get("source").and_then(serde_json::Value::as_str),
        Some("Project (mcp.json)")
    );
    assert_eq!(
        server.get("command").and_then(serde_json::Value::as_str),
        Some("fixture-command")
    );
    assert_eq!(server.get("args"), Some(&serde_json::json!(["--<option>"])));
    assert_eq!(
        server
            .get("env")
            .and_then(|environment| environment.get("TOKEN"))
            .and_then(serde_json::Value::as_str),
        Some("<redacted>")
    );
    assert_eq!(
        server.get("enabled").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        server.get("cwd").and_then(serde_json::Value::as_str),
        Some("/srv/fixture")
    );
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
