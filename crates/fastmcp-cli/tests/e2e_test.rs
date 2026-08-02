//! E2E tests for `fastmcp test`.

#![cfg(unix)]

use std::io::Read;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, ExitStatus, Stdio};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

const CLI_DEADLINE: Duration = Duration::from_secs(120);
const CAPTURE_DRAIN_DEADLINE: Duration = Duration::from_secs(1);
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const PROCESS_CLEANUP_DEADLINE: Duration = Duration::from_secs(2);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
const PROCESS_TERM_GRACE: Duration = Duration::from_millis(500);

fn fastmcp_bin() -> String {
    env!("CARGO_BIN_EXE_fastmcp").to_string()
}

fn stdout_str(output: &Output) -> String {
    std::str::from_utf8(&output.stdout)
        .expect("fastmcp test stdout must be valid UTF-8")
        .to_owned()
}

#[derive(Debug)]
struct DeadlineExceeded {
    timeout: Duration,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    cleanup_error: Option<String>,
}

struct ProcessGroupGuard {
    child: Option<Child>,
    process_group_id: u32,
    owns_process_group: bool,
    armed: bool,
}

impl ProcessGroupGuard {
    fn spawn(command: &mut Command) -> Self {
        command.process_group(0);
        let child = command.spawn().expect("spawn command");
        let process_group_id = child.id();
        Self {
            child: Some(child),
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
        // Do not reap the process-group leader before group cleanup. Its live
        // or zombie PID pins the PGID until all TERM/KILL decisions are over.
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
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!("failed to read process {pid} state: {error}"));
            }
        };
        let (state, group) = linux_process_state_and_group(&stat)
            .ok_or_else(|| format!("malformed /proc/{pid}/stat"))?;
        if group == process_group_id && !matches!(state, 'Z' | 'X') {
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
    Ok(matches!(state, 'Z' | 'X'))
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

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let Err(error) = self.kill_and_reap() {
            eprintln!("fastmcp test-command harness cleanup failed: {error}");
        }
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
            // A detached descendant can retain this pipe. Safe Rust has no
            // portable blocked-read cancellation; preserve partial evidence.
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

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn run_cli(args: &[&str]) -> Output {
    let mut command = Command::new(fastmcp_bin());
    command.args(args).env("FASTMCP_CHECK_FOR_UPDATES", "0");
    run_with_deadline(command, CLI_DEADLINE).unwrap_or_else(|expired| {
        panic!(
            "fastmcp exceeded the {:?} harness deadline; cleanup error: {:?}; captured stdout={} bytes, stderr={} bytes (content redacted)",
            expired.timeout,
            expired.cleanup_error,
            expired.stdout.len(),
            expired.stderr.len()
        )
    })
}

#[cfg(unix)]
#[test]
fn e2e_test_json_report_against_echo_server_example() {
    // Use the workspace example server as the subprocess being tested.
    // This exercises:
    // - stdio subprocess spawning
    // - initialization
    // - ping
    // - tools/resources/prompts listing
    let output = run_cli(&[
        "test",
        "--json",
        "--timeout",
        "30",
        "cargo",
        "--",
        "run",
        "--locked",
        "--offline",
        "-q",
        "-p",
        "fastmcp-rust",
        "--example",
        "echo_server",
    ]);

    assert!(output.status.success());

    let out = stdout_str(&output);
    let json: serde_json::Value = serde_json::from_str(&out).expect("parse test json");
    assert_eq!(json.get("success").and_then(|v| v.as_bool()), Some(true));
    let tests = json
        .get("tests")
        .and_then(|v| v.as_array())
        .expect("test results array");
    assert!(
        tests
            .iter()
            .any(|test| test.get("name").and_then(|name| name.as_str()) == Some("ping")),
        "test report must include a real ping request"
    );
    assert!(json.get("total_duration_ms").is_some());
}

#[cfg(unix)]
#[test]
fn e2e_test_timeout_bounds_silent_initialization() {
    assert_initialization_receive_timeout("exec sleep 5", "silent peer");
}

#[cfg(unix)]
#[test]
fn e2e_test_timeout_bounds_partial_initialization_frame() {
    assert_initialization_receive_timeout(
        r#"printf '%s' '{"jsonrpc":"2.0"'; exec sleep 5"#,
        "partial-frame peer",
    );
}

#[cfg(unix)]
fn assert_initialization_receive_timeout(server_script: &str, scenario: &str) {
    let mut cmd = Command::new(fastmcp_bin());
    cmd.args([
        "test",
        "--json",
        "--timeout",
        "1",
        "sh",
        "--",
        "-c",
        server_script,
    ])
    .env("FASTMCP_CHECK_FOR_UPDATES", "0");

    let started = Instant::now();
    let output = run_with_deadline(cmd, Duration::from_secs(10)).unwrap_or_else(|expired| {
        panic!(
            "the harness deadline expired for {scenario} instead of the product timeout; cleanup error: {:?}; captured stdout={} bytes, stderr={} bytes (content redacted)",
            expired.cleanup_error,
            expired.stdout.len(),
            expired.stderr.len()
        )
    });

    assert!(
        !output.status.success(),
        "{scenario} unexpectedly succeeded"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{scenario} was not bounded by the configured receive deadline"
    );
    let stderr = std::str::from_utf8(&output.stderr)
        .expect("timeout diagnostics must be strict UTF-8 terminal text");
    assert!(
        stderr.contains("Request timed out"),
        "{scenario} omitted the product timeout diagnostic: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn e2e_test_timeout_reports_late_ping_response() {
    // Complete initialization, then delay the ping response beyond the product
    // deadline to cover the post-initialization request path separately from
    // the silent and partial-frame initialization cases above.
    const LATE_PING_SERVER: &str = r#"
IFS= read -r initialize || exit 20
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"late-ping-fixture","version":"1.0.0"}}}'
IFS= read -r initialized || exit 21
IFS= read -r ping || exit 22
sleep 2
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{}}'
"#;

    let mut cmd = Command::new(fastmcp_bin());
    cmd.args([
        "test",
        "--json",
        "--timeout",
        "1",
        "sh",
        "--",
        "-c",
        LATE_PING_SERVER,
    ])
    .env("FASTMCP_CHECK_FOR_UPDATES", "0");

    let output = run_with_deadline(cmd, Duration::from_secs(10)).unwrap_or_else(|expired| {
        panic!(
            "the harness deadline expired instead of the product timeout; cleanup error: {:?}; captured stdout={} bytes, stderr={} bytes (content redacted)",
            expired.cleanup_error,
            expired.stdout.len(),
            expired.stderr.len()
        )
    });

    assert!(!output.status.success());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("timeout run should emit a JSON report");
    assert_eq!(
        report.get("success").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let ping = report
        .get("tests")
        .and_then(serde_json::Value::as_array)
        .and_then(|tests| {
            tests
                .iter()
                .find(|test| test.get("name").and_then(serde_json::Value::as_str) == Some("ping"))
        })
        .expect("timeout report should contain the ping result");
    assert_eq!(
        ping.get("success").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert!(
        ping.get("error")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|error| error.contains("Request timed out")),
        "ping result should contain the product timeout diagnostic: {ping}"
    );
    let stderr =
        std::str::from_utf8(&output.stderr).expect("fastmcp test stderr must be valid UTF-8");
    assert!(
        stderr.contains("Some tests failed"),
        "top-level failure diagnostic missing: {stderr}"
    );
}
