//! E2E tests for `fastmcp dev`.
//!
//! These tests spin up `fastmcp dev` against tiny throwaway Cargo projects and
//! executable fixtures, then validate reload and owned-process cleanup behavior.

#![cfg(target_os = "linux")]

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CLI_DEADLINE: Duration = Duration::from_secs(120);
const CAPTURE_DRAIN_DEADLINE: Duration = Duration::from_secs(1);
const HARNESS_ERROR_PREFIX: &str = "fastmcp-harness-error:";
const LIVE_OUTPUT_CHANNEL_CAPACITY: usize = 512;
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const MAX_LIVE_LINE_BYTES: usize = 16 * 1024;
const PROCESS_CLEANUP_DEADLINE: Duration = Duration::from_secs(2);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
const PROCESS_TERM_GRACE: Duration = Duration::from_millis(500);
static TEMP_DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static CARGO_FIXTURE_LOCK: Mutex<()> = Mutex::new(());

fn fastmcp_bin() -> String {
    env!("CARGO_BIN_EXE_fastmcp").to_string()
}

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let sequence = TEMP_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_root = std::fs::canonicalize(std::env::temp_dir())
            .expect("resolve the test temporary directory without symlink components");
        let path = temp_root.join(format!(
            "fastmcp-cli-{prefix}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create temp dir");
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

fn mktemp_dir(prefix: &str) -> TestTempDir {
    TestTempDir::new(prefix)
}

fn cargo_fixture_lock() -> MutexGuard<'static, ()> {
    CARGO_FIXTURE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir");
    }
    std::fs::write(path, content).unwrap();
}

fn init_cargo_project(root: &Path, body: &str) {
    write_file(
        &root.join("Cargo.toml"),
        r#"[package]
name = "fastmcp_dev_test_proj"
version = "0.1.0"
edition = "2021"

[dependencies]

[workspace]
"#,
    );
    write_file(&root.join("src/main.rs"), body);
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = std::fs::metadata(path)
        .expect("read executable metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("set executable permissions");
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

    fn signal_group(&self, signal: &str) -> Result<(), String> {
        let target = format!("-{}", self.process_group_id);
        let status = Command::new("/bin/kill")
            .args([signal, "--", &target])
            .status()
            .map_err(|error| format!("failed to execute /bin/kill: {error}"))?;
        if status.success() {
            return Ok(());
        }
        match linux_process_group_has_live_member(self.process_group_id) {
            Ok(false) => Ok(()),
            Ok(true) => Err(format!(
                "/bin/kill {signal} -- {target} exited with {status}"
            )),
            Err(inspect_error) => Err(format!(
                "/bin/kill {signal} -- {target} exited with {status}; could not verify ESRCH-equivalent group absence: {inspect_error}"
            )),
        }
    }

    fn child_is_zombie(&self, context: &str) -> Result<bool, String> {
        linux_process_is_zombie(self.child.as_ref().expect("process guard is disarmed").id())
            .map_err(|error| format!("{context}: {error}"))
    }

    fn wait_for_cleanup_state(&mut self, deadline: Instant) -> Result<(bool, bool), String> {
        loop {
            let child_exited = self.child_is_zombie("failed to inspect exact child")?;
            let group_live = self.owns_process_group
                && linux_process_group_has_live_member(self.process_group_id)?;
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
        let mut cleanup_errors = Vec::new();
        let mut direct_kill_error = None;
        let mut child_exited = match self.child_is_zombie("failed to inspect exact child") {
            Ok(exited) => exited,
            Err(error) => {
                self.owns_process_group = false;
                self.armed = false;
                return Err(format!("{error}; guard disarmed without signaling"));
            }
        };
        // Keep the original group leader unreaped until group cleanup is
        // complete. Its live/zombie PID pins the PGID against numeric reuse.
        let mut group_live = if self.owns_process_group {
            match linux_process_group_has_live_member(self.process_group_id) {
                Ok(live) => live,
                Err(error) => {
                    self.owns_process_group = false;
                    self.armed = false;
                    return Err(format!(
                        "failed to inspect owned process group; guard disarmed without signaling: {error}"
                    ));
                }
            }
        } else {
            false
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
                cleanup_errors.push(format!("failed to kill exact child: {error}"));
            }
            cleanup_errors.push(format!(
                "exact child did not exit within {PROCESS_CLEANUP_DEADLINE:?}"
            ));
        }
        if group_live {
            cleanup_errors.push(format!(
                "owned process group {} still has live members after {PROCESS_CLEANUP_DEADLINE:?}",
                self.process_group_id
            ));
        }
        let exit_status = match self.child_mut().try_wait() {
            Ok(status) => status,
            Err(error) => {
                cleanup_errors.push(format!(
                    "failed to reap exact child after all signaling completed: {error}"
                ));
                None
            }
        };
        self.child = None;
        self.owns_process_group = false;
        self.armed = false;

        if cleanup_errors.is_empty() {
            Ok(exit_status)
        } else {
            Err(cleanup_errors.join("; "))
        }
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
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let Err(error) = self.kill_and_reap() {
            eprintln!("fastmcp dev-test process cleanup failed: {error}");
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

fn run_cli_to_completion(mut command: Command, context: &str) -> Output {
    command
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .env("CLICOLOR_FORCE", "0")
        .env("FASTMCP_PLAIN", "1");
    run_with_deadline(command, CLI_DEADLINE).unwrap_or_else(|expired| {
        panic!(
            "{context} exceeded the {:?} harness deadline; cleanup error: {:?}; captured stdout={} bytes, stderr={} bytes (content redacted)",
            expired.timeout,
            expired.cleanup_error,
            expired.stdout.len(),
            expired.stderr.len()
        )
    })
}

struct DevProcess {
    process: ProcessGroupGuard,
}

impl DevProcess {
    fn is_running(&mut self) -> bool {
        let child_pid = self.process.child_mut().id();
        match linux_process_is_zombie(child_pid) {
            Ok(true) => {
                let cleanup_error = self.process.kill_and_reap().err();
                assert!(
                    cleanup_error.is_none(),
                    "failed to clean up exited fastmcp dev: {cleanup_error:?}"
                );
                false
            }
            Ok(false) => true,
            Err(error) => {
                self.process.owns_process_group = false;
                self.process.armed = false;
                panic!("failed to inspect fastmcp dev: {error}; guard disarmed without signaling")
            }
        }
    }

    fn shutdown(mut self) {
        let result = self.shutdown_inner();
        assert!(result.is_ok(), "{}", result.unwrap_err());
    }

    fn shutdown_inner(&mut self) -> Result<(), String> {
        if !self.process.armed {
            return Ok(());
        }

        match self
            .process
            .child_is_zombie("failed to inspect fastmcp dev before shutdown")
        {
            Ok(true) => return self.process.kill_and_reap().map(|_| ()),
            Ok(false) => {}
            Err(error) => {
                self.process.owns_process_group = false;
                self.process.armed = false;
                return Err(format!("{error}; guard disarmed without signaling"));
            }
        }

        // Signal the exact child-owned process group while the retained child
        // is known to be running, before any numeric process-group signal.
        if let Err(interrupt_error) = self.process.signal_group("-INT") {
            self.process.owns_process_group = false;
            self.process.armed = false;
            return Err(format!(
                "failed to interrupt fastmcp dev process group: {interrupt_error}; guard disarmed without further signaling"
            ));
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let child_pid = self.process.child_mut().id();
            match linux_process_is_zombie(child_pid) {
                Ok(true) => return self.process.kill_and_reap().map(|_| ()),
                Ok(false) => std::thread::sleep(PROCESS_POLL_INTERVAL),
                Err(error) => {
                    self.process.owns_process_group = false;
                    self.process.armed = false;
                    return Err(format!(
                        "wait for fastmcp dev shutdown: {error}; guard disarmed without signaling"
                    ));
                }
            }
        }

        let cleanup_error = self.process.kill_and_reap().err();
        Err(format!(
            "fastmcp dev did not exit within the shutdown deadline; cleanup error: {cleanup_error:?}"
        ))
    }
}

impl Drop for DevProcess {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown_inner() {
            eprintln!("fastmcp dev-test graceful shutdown failed: {error}");
        }
    }
}

fn proc_process_disappeared(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
        || error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error())
}

fn linux_process_is_zombie(pid: u32) -> Result<bool, String> {
    let (state, _) = read_linux_process_state_and_group(pid)?
        .ok_or_else(|| format!("process {pid} disappeared before it could be reaped"))?;
    Ok(matches!(state, 'Z' | 'X' | 'x'))
}

fn linux_process_group_has_live_member(process_group_id: u32) -> Result<bool, String> {
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
        let Some((state, group)) = read_linux_process_state_and_group(pid)? else {
            continue;
        };
        if group == process_group_id && !matches!(state, 'Z' | 'X' | 'x') {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_linux_process_state_and_group(pid: u32) -> Result<Option<(char, u32)>, String> {
    const MAX_STAT_READ_ATTEMPTS: usize = 3;

    let path = format!("/proc/{pid}/stat");
    for attempt in 0..MAX_STAT_READ_ATTEMPTS {
        match std::fs::read_to_string(&path) {
            Ok(stat) => {
                if let Some(parsed) = linux_process_state_and_group(&stat) {
                    return Ok(Some(parsed));
                }
                if attempt + 1 < MAX_STAT_READ_ATTEMPTS {
                    std::thread::yield_now();
                }
            }
            Err(error) if proc_process_disappeared(&error) => return Ok(None),
            Err(error) => {
                return Err(format!("failed to read process {pid} state: {error}"));
            }
        }
    }
    match std::fs::symlink_metadata(&path) {
        Err(error) if proc_process_disappeared(&error) => Ok(None),
        Err(error) => Err(format!(
            "failed to recheck malformed process {pid} state: {error}"
        )),
        Ok(_) => Err(format!(
            "malformed /proc/{pid}/stat after {MAX_STAT_READ_ATTEMPTS} reads"
        )),
    }
}

fn linux_process_state_and_group(stat: &str) -> Option<(char, u32)> {
    let (_, fields) = stat.rsplit_once(')')?;
    let mut fields = fields.split_ascii_whitespace();
    let state = fields.next()?.chars().next()?;
    let _parent_pid = fields.next()?;
    let process_group_id = fields.next()?.parse().ok()?;
    Some((state, process_group_id))
}

fn bounded_line_contains(line: &[u8], truncated: bool, needle: &str) -> bool {
    if truncated {
        return false;
    }
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    std::str::from_utf8(line).is_ok_and(|line| line.contains(needle))
}

fn forward_bounded_lines<R>(
    pipe: R,
    sender: mpsc::SyncSender<String>,
    stop_after: Option<&str>,
) -> bool
where
    R: Read,
{
    let mut reader = BufReader::new(pipe);
    let mut line = Vec::new();
    let mut truncated = false;
    loop {
        let available = match reader.fill_buf() {
            Ok([]) => {
                if !line.is_empty() || truncated {
                    let matched = stop_after
                        .is_some_and(|needle| bounded_line_contains(&line, truncated, needle));
                    if !send_bounded_line(&sender, &mut line, truncated) {
                        return false;
                    }
                    return matched;
                }
                return false;
            }
            Ok(available) => available,
            Err(error) => {
                let _ = sender.send(format!("{HARNESS_ERROR_PREFIX} output reader: {error}"));
                return false;
            }
        };
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        let content_len = newline.unwrap_or(available.len());
        let retained = (MAX_LIVE_LINE_BYTES - line.len()).min(content_len);
        line.extend_from_slice(&available[..retained]);
        truncated |= retained < content_len;
        reader.consume(consumed);

        if newline.is_some() {
            let matched =
                stop_after.is_some_and(|needle| bounded_line_contains(&line, truncated, needle));
            if !send_bounded_line(&sender, &mut line, truncated) {
                return false;
            }
            if matched {
                return true;
            }
            truncated = false;
        }
    }
}

fn send_bounded_line(
    sender: &mpsc::SyncSender<String>,
    line: &mut Vec<u8>,
    truncated: bool,
) -> bool {
    if truncated {
        line.clear();
        let _ = sender.send(format!(
            "{HARNESS_ERROR_PREFIX} output line exceeded {MAX_LIVE_LINE_BYTES} bytes"
        ));
        return false;
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    let rendered = match std::str::from_utf8(line) {
        Ok(rendered) => rendered,
        Err(_) => {
            line.clear();
            let _ = sender.send(format!(
                "{HARNESS_ERROR_PREFIX} output line was not valid UTF-8"
            ));
            return false;
        }
    };
    if let Some((offset, character)) = rendered
        .char_indices()
        .find(|(_, character)| is_disallowed_terminal_character(*character))
    {
        let codepoint = u32::from(character);
        line.clear();
        let _ = sender.send(format!(
            "{HARNESS_ERROR_PREFIX} output line contained disallowed terminal character U+{codepoint:04X} at byte {offset}"
        ));
        return false;
    }
    let rendered = rendered.to_owned();
    line.clear();
    sender.send(rendered).is_ok()
}

fn is_disallowed_terminal_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn spawn_dev(root: &Path, args: &[&str]) -> (DevProcess, mpsc::Receiver<String>) {
    let (subcommand, subcommand_args) = args
        .split_first()
        .expect("spawn_dev requires the dev subcommand");
    let mut command = Command::new(fastmcp_bin());
    command
        .arg(subcommand)
        .arg("--verbose")
        .args(subcommand_args)
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .env("CLICOLOR_FORCE", "0")
        .env("FASTMCP_PLAIN", "1")
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", root.join("target"))
        .env("CARGO_TERM_COLOR", "never")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut process = ProcessGroupGuard::spawn(&mut command);

    let stdout = process.child_mut().stdout.take().expect("stdout");
    let stderr = process.child_mut().stderr.take().expect("stderr");

    let (tx, rx) = mpsc::sync_channel::<String>(LIVE_OUTPUT_CHANNEL_CAPACITY);
    let tx_out = tx.clone();
    drop(std::thread::spawn(move || {
        let _ = forward_bounded_lines(stdout, tx_out, None);
    }));

    drop(std::thread::spawn(move || {
        let _ = forward_bounded_lines(stderr, tx, None);
    }));

    (DevProcess { process }, rx)
}

fn wait_for_contains(rx: &mpsc::Receiver<String>, needle: &str, timeout: Duration) -> String {
    let deadline = std::time::Instant::now() + timeout;
    let mut tail: VecDeque<String> = VecDeque::with_capacity(50);
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                assert_valid_live_output(&line);
                if tail.len() == 50 {
                    tail.pop_front();
                }
                tail.push_back(line.clone());
                if line.contains(needle) {
                    return line;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let msg = format!(
        "timed out waiting for output containing {needle:?}; {}",
        live_output_tail_metadata(&tail)
    );
    assert!(msg.is_empty(), "{msg}");
    unreachable!("timeout assertion always fails")
}

fn wait_for_all_contains(
    rx: &mpsc::Receiver<String>,
    needles: &[&str],
    timeout: Duration,
) -> Vec<String> {
    let deadline = Instant::now() + timeout;
    let mut matches = vec![None; needles.len()];
    let mut tail: VecDeque<String> = VecDeque::with_capacity(50);
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                assert_valid_live_output(&line);
                if tail.len() == 50 {
                    tail.pop_front();
                }
                tail.push_back(line.clone());
                for (index, needle) in needles.iter().enumerate() {
                    if matches[index].is_none() && line.contains(needle) {
                        matches[index] = Some(line.clone());
                    }
                }
                if matches.iter().all(Option::is_some) {
                    return matches
                        .into_iter()
                        .map(|line| line.expect("all output markers present"))
                        .collect();
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let missing = needles
        .iter()
        .zip(&matches)
        .filter_map(|(needle, line)| line.is_none().then_some(*needle))
        .collect::<Vec<_>>();
    panic!(
        "timed out waiting for output markers {missing:?}; {}",
        live_output_tail_metadata(&tail)
    );
}

fn assert_not_contains_for(
    process: &mut DevProcess,
    rx: &mpsc::Receiver<String>,
    needle: &str,
    duration: Duration,
) {
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                assert_valid_live_output(&line);
                if line.contains(needle) {
                    let msg = format!(
                        "unexpected output containing {needle:?}; line_bytes={}",
                        line.len()
                    );
                    assert!(msg.is_empty(), "{msg}");
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("fastmcp dev output disconnected during negative assertion")
            }
        }
    }
    assert!(
        process.is_running(),
        "fastmcp dev exited during negative assertion"
    );
}

fn assert_valid_live_output(line: &str) {
    assert!(
        !line.starts_with(HARNESS_ERROR_PREFIX),
        "live output capture failed; line_bytes={}",
        line.len()
    );
    assert!(
        !line.chars().any(is_disallowed_terminal_character),
        "live output contained a disallowed terminal character; line_bytes={}",
        line.len()
    );
}

fn live_output_tail_metadata(lines: &VecDeque<String>) -> String {
    let total_bytes = lines
        .iter()
        .fold(0usize, |total, line| total.saturating_add(line.len()));
    let max_line_bytes = lines.iter().map(String::len).max().unwrap_or(0);
    format!(
        "retained_lines={}, retained_bytes={total_bytes}, max_line_bytes={max_line_bytes}",
        lines.len()
    )
}

fn fixture_pid(line: &str) -> u32 {
    line.split_once("dev-test-server-start pid=")
        .and_then(|(_, pid)| pid.parse().ok())
        .unwrap_or_else(|| {
            panic!(
                "fixture output did not contain a valid PID; line_bytes={}",
                line.len()
            )
        })
}

#[test]
fn live_output_capture_rejects_controls_without_echoing_line_content() {
    let secret = "live-output-secret-canary";
    let mut line = format!("prefix\u{001b}[31m{secret}").into_bytes();
    let (sender, receiver) = mpsc::sync_channel(1);

    assert!(!send_bounded_line(&sender, &mut line, false));
    let error = receiver.recv().expect("capture error");
    assert!(error.starts_with(HARNESS_ERROR_PREFIX));
    assert!(error.contains("U+001B"));
    assert!(!error.contains(secret));
    assert!(!error.contains('\u{001b}'));
}

#[test]
fn live_output_tail_metadata_never_echoes_retained_lines() {
    let secret = "retained-output-secret-canary";
    let lines = VecDeque::from([secret.to_string(), "ordinary".to_string()]);
    let metadata = live_output_tail_metadata(&lines);

    assert!(metadata.contains("retained_lines=2"));
    assert!(!metadata.contains(secret));
    assert!(!metadata.contains("ordinary"));
}

fn wait_for_linux_process_exit(pid: u32, timeout: Duration) {
    let path = PathBuf::from(format!("/proc/{pid}"));
    let deadline = Instant::now() + timeout;
    while linux_process_path_exists(&path) && Instant::now() < deadline {
        std::thread::sleep(PROCESS_POLL_INTERVAL);
    }
    assert!(
        !linux_process_path_exists(&path),
        "process {pid} remained alive after shutdown"
    );
}

fn linux_process_path_exists(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => panic!("failed to inspect {}: {error}", path.display()),
    }
}

fn wait_for_process_marker(path: &Path, timeout: Duration) -> (u32, u32) {
    let deadline = Instant::now() + timeout;
    loop {
        match std::fs::read_to_string(path) {
            Ok(marker) if marker.ends_with('\n') => {
                let fields = marker.split_ascii_whitespace().collect::<Vec<_>>();
                assert_eq!(
                    fields.len(),
                    2,
                    "process marker must contain exactly a PID and a process-group ID"
                );
                let pid = fields[0]
                    .parse::<u32>()
                    .expect("process marker PID must be numeric");
                let process_group_id = fields[1]
                    .parse::<u32>()
                    .expect("process marker group ID must be numeric");
                assert!(pid > 0, "process marker PID must be positive");
                assert!(
                    process_group_id > 0,
                    "process marker group ID must be positive"
                );
                return (pid, process_group_id);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("failed to read process marker {}: {error}", path.display()),
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for process marker {}",
            path.display()
        );
        std::thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

fn wait_for_marker_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => return,
            Ok(_) => panic!("marker path is not a file: {}", path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("failed to inspect marker {}: {error}", path.display()),
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for marker {}",
            path.display()
        );
        std::thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

fn assert_live_process_in_group(pid: u32, process_group_id: u32, context: &str) {
    let (state, observed_group_id) = read_linux_process_state_and_group(pid)
        .unwrap_or_else(|error| panic!("{context}: {error}"))
        .unwrap_or_else(|| panic!("{context}: process {pid} disappeared"));
    assert!(
        !matches!(state, 'Z' | 'X' | 'x'),
        "{context}: process {pid} was not live"
    );
    assert_eq!(
        observed_group_id, process_group_id,
        "{context}: process {pid} was not in the recorded managed group"
    );
}

fn wait_for_linux_process_group_exit(process_group_id: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let group_live = linux_process_group_has_live_member(process_group_id)
            .unwrap_or_else(|error| panic!("failed to inspect process group: {error}"));
        if !group_live {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "process group {process_group_id} remained live after shutdown"
        );
        std::thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

fn wait_for_dev_exit(process: &mut DevProcess, timeout: Duration, context: &str) -> ExitStatus {
    process
        .process
        .wait_until(timeout)
        .unwrap_or_else(|expired| {
            panic!(
                "{context} exceeded the {:?} harness deadline; cleanup error: {:?}; captured stdout={} bytes, stderr={} bytes (content redacted)",
                expired.timeout,
                expired.cleanup_error,
                expired.stdout.len(),
                expired.stderr.len()
            )
        })
}

#[test]
fn live_output_capture_rejects_invalid_utf8() {
    let (sender, receiver) = mpsc::sync_channel(1);
    let mut line = vec![b'o', b'k', 0xff];

    assert!(!send_bounded_line(&sender, &mut line, false));
    assert!(line.is_empty(), "rejected output bytes must be discarded");
    assert_eq!(
        receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("invalid UTF-8 must emit a harness diagnostic"),
        format!("{HARNESS_ERROR_PREFIX} output line was not valid UTF-8")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_dev_no_reload_exits_for_cargo_project() {
    let _cargo_fixture_lock = cargo_fixture_lock();
    let root = mktemp_dir("dev-no-reload");
    init_cargo_project(
        &root,
        r#"fn main() {
    // Exits immediately.
    println!("dev-test-exit");
}"#,
    );

    let mut command = Command::new(fastmcp_bin());
    command
        .args(["dev", "--no-reload", root.to_str().unwrap()])
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", root.join("target"))
        .env("CARGO_TERM_COLOR", "never");
    let output = run_cli_to_completion(command, "fastmcp dev --no-reload Cargo fixture");

    assert!(output.status.success());
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_dev_no_reload_propagates_direct_binary_exit_status() {
    let mut command = Command::new(fastmcp_bin());
    command
        .args(["dev", "--no-reload", "/bin/true"])
        .env("FASTMCP_CHECK_FOR_UPDATES", "0");
    let success = run_cli_to_completion(command, "successful direct dev fixture");
    assert!(success.status.success());

    let mut command = Command::new(fastmcp_bin());
    command
        .args(["dev", "--no-reload", "/bin/false"])
        .env("FASTMCP_CHECK_FOR_UPDATES", "0");
    let failure = run_cli_to_completion(command, "failing direct dev fixture");
    assert!(
        !failure.status.success(),
        "a failing development server must make the CLI fail"
    );
    assert_eq!(
        failure.status.code(),
        Some(1),
        "the CLI must preserve the direct child's exit code"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_dev_no_reload_signal_cleans_up_descendant_processes() {
    let root = mktemp_dir("dev-no-reload-signal");
    let server = root.join("server.sh");
    write_file(
        &server,
        "#!/bin/sh\nsleep 60 &\necho dev-test-server-start pid=$!\nwait\n",
    );
    make_executable(&server);

    let (process, rx) = spawn_dev(
        &root,
        &["dev", "--no-reload", server.to_str().expect("server path")],
    );
    let output = wait_for_contains(&rx, "dev-test-server-start", Duration::from_secs(10));
    let descendant_pid = fixture_pid(&output);

    process.shutdown();
    wait_for_linux_process_exit(descendant_pid, Duration::from_secs(10));
}

#[cfg(target_os = "linux")]
#[test]
fn reality_check_regression_e2e_dev_owner_death_stops_managed_group() {
    let root = mktemp_dir("dev-owner-death");
    let server = root.join("server.sh");
    let process_marker = root.join("server-process");
    write_file(
        &server,
        r#"#!/bin/sh
trap '' HUP INT TERM
process_group_id=$(/usr/bin/ps -o pgid= -p "$$") || exit 70
printf '%s %s\n' "$$" "$process_group_id" > "$FASTMCP_DEV_PROCESS_MARKER" || exit 71
while :; do
    sleep 60
done
"#,
    );
    make_executable(&server);

    let process_marker_env = format!("FASTMCP_DEV_PROCESS_MARKER={}", process_marker.display());
    let (mut process, _output) = spawn_dev(
        &root,
        &[
            "dev",
            "--no-reload",
            "--env",
            process_marker_env.as_str(),
            server.to_str().expect("server path"),
        ],
    );
    let (server_pid, managed_group_id) =
        wait_for_process_marker(&process_marker, Duration::from_secs(10));
    assert_ne!(
        managed_group_id, process.process.process_group_id,
        "the managed server must not share the outer CLI process group"
    );
    assert_live_process_in_group(
        server_pid,
        managed_group_id,
        "owner-death fixture before killing the CLI",
    );

    // Kill only the CLI owner, not its outer harness group. Closing the
    // inherited write end of the private control pipe must wake the in-group
    // watchdog and stop the independently managed server group.
    process
        .process
        .child_mut()
        .kill()
        .expect("kill the exact fastmcp dev owner process");
    let status = wait_for_dev_exit(
        &mut process,
        Duration::from_secs(10),
        "SIGKILLed fastmcp dev owner",
    );
    assert!(
        !status.success(),
        "SIGKILLed CLI owner cannot exit successfully"
    );

    wait_for_linux_process_exit(server_pid, Duration::from_secs(10));
    wait_for_linux_process_group_exit(managed_group_id, Duration::from_secs(10));
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_dev_closed_stdout_cleans_up_idle_managed_group() {
    let root = mktemp_dir("dev-closed-stdout");
    let server = root.join("server.sh");
    let process_marker = root.join("server-process");
    let reload_trigger = root
        .canonicalize()
        .expect("canonicalize reload fixture root")
        .join("reload-trigger");
    write_file(
        &server,
        r#"#!/bin/sh
process_group_id=$(/usr/bin/ps -o pgid= -p "$$") || exit 70
printf '%s %s\n' "$$" "$process_group_id" > "$FASTMCP_DEV_PROCESS_MARKER" || exit 71
while :; do
    sleep 60
done
"#,
    );
    make_executable(&server);

    let process_marker_env = format!("FASTMCP_DEV_PROCESS_MARKER={}", process_marker.display());
    let reload_pattern = reload_trigger.to_string_lossy().replace('\\', "/");
    let mut command = Command::new(fastmcp_bin());
    command
        .arg("dev")
        .arg("--clear")
        .arg("--reload-dir")
        .arg(root.as_os_str())
        .arg("--reload-pattern")
        .arg(&reload_pattern)
        .arg("--env")
        .arg(&process_marker_env)
        .arg(&server)
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .env("CLICOLOR_FORCE", "0")
        .env("FASTMCP_PLAIN", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut guarded = ProcessGroupGuard::spawn(&mut command);
    let stdout = guarded
        .child_mut()
        .stdout
        .take()
        .expect("fastmcp dev stdout must be piped");
    let (output_sender, output_receiver) =
        mpsc::sync_channel::<String>(LIVE_OUTPUT_CHANNEL_CAPACITY);
    let (closed_sender, closed_receiver) = mpsc::sync_channel(1);
    drop(std::thread::spawn(move || {
        let matched = forward_bounded_lines(stdout, output_sender, Some("Watching for changes"));
        let _ = closed_sender.send(matched);
    }));
    let mut process = DevProcess { process: guarded };

    let _ = wait_for_contains(
        &output_receiver,
        "Watching for changes",
        Duration::from_secs(10),
    );
    assert!(
        closed_receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("stdout closer must report before its deadline"),
        "fastmcp dev stdout closed before the watcher became ready"
    );
    let (server_pid, managed_group_id) =
        wait_for_process_marker(&process_marker, Duration::from_secs(10));
    assert_ne!(
        managed_group_id, process.process.process_group_id,
        "the managed server must not share the outer CLI process group"
    );
    assert_live_process_in_group(
        server_pid,
        managed_group_id,
        "fixture server after watcher readiness and stdout closure",
    );

    // The stdout reader returned (and therefore closed the pipe) only after it
    // observed watcher readiness. Touching this exact matching path now makes
    // the requested terminal clear fail while the idle child is live.
    write_file(&reload_trigger, "reload\n");

    let status = wait_for_dev_exit(
        &mut process,
        Duration::from_secs(15),
        "fastmcp dev after stdout EPIPE",
    );
    assert!(
        !status.success(),
        "a development-status EPIPE must surface as a command failure"
    );
    wait_for_linux_process_exit(server_pid, Duration::from_secs(10));
    wait_for_linux_process_group_exit(managed_group_id, Duration::from_secs(10));
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_dev_natural_leader_exit_cleans_up_orphaned_descendant() {
    let root = mktemp_dir("dev-natural-leader-exit");
    let server = root.join("server.sh");
    let process_marker = root.join("descendant-process");
    write_file(
        &server,
        r#"#!/bin/sh
sleep 60 </dev/null >/dev/null 2>&1 &
descendant_pid=$!
process_group_id=$(/usr/bin/ps -o pgid= -p "$descendant_pid") || exit 70
printf '%s %s\n' "$descendant_pid" "$process_group_id" > "$FASTMCP_DEV_PROCESS_MARKER" || exit 71
exit 0
"#,
    );
    make_executable(&server);

    let process_marker_env = format!("FASTMCP_DEV_PROCESS_MARKER={}", process_marker.display());
    let mut command = Command::new(fastmcp_bin());
    command
        .arg("dev")
        .arg("--no-reload")
        .arg("--env")
        .arg(&process_marker_env)
        .arg(&server)
        .env("FASTMCP_CHECK_FOR_UPDATES", "0");
    let output = run_cli_to_completion(command, "natural managed-leader exit fixture");

    assert!(
        output.status.success(),
        "a successful direct server must preserve its successful status"
    );
    let (descendant_pid, managed_group_id) =
        wait_for_process_marker(&process_marker, Duration::from_secs(2));
    wait_for_linux_process_exit(descendant_pid, Duration::from_secs(10));
    wait_for_linux_process_group_exit(managed_group_id, Duration::from_secs(10));
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_dev_term_ignoring_descendant_is_killed_by_watchdog_escalation() {
    let root = mktemp_dir("dev-watchdog-kill");
    let server = root.join("server.sh");
    let process_marker = root.join("server-process");
    let survived_term_marker = root.join("server-survived-term");
    write_file(
        &server,
        r#"#!/bin/sh
process_group_id=$(/usr/bin/ps -o pgid= -p "$$") || exit 70
printf '%s %s\n' "$$" "$process_group_id" > "$FASTMCP_DEV_PROCESS_MARKER" || exit 71
term_seen=0
trap '' HUP INT
trap 'term_seen=1' TERM
while :; do
    sleep 60 || :
    if [ "$term_seen" -eq 1 ]; then
        printf 'survived-term\n' > "$FASTMCP_DEV_SURVIVED_TERM_MARKER"
        term_seen=2
    fi
done
"#,
    );
    make_executable(&server);

    let process_marker_env = format!("FASTMCP_DEV_PROCESS_MARKER={}", process_marker.display());
    let survived_term_marker_env = format!(
        "FASTMCP_DEV_SURVIVED_TERM_MARKER={}",
        survived_term_marker.display()
    );
    let (mut process, _output) = spawn_dev(
        &root,
        &[
            "dev",
            "--no-reload",
            "--env",
            process_marker_env.as_str(),
            "--env",
            survived_term_marker_env.as_str(),
            server.to_str().expect("server path"),
        ],
    );
    let (server_pid, managed_group_id) =
        wait_for_process_marker(&process_marker, Duration::from_secs(10));
    assert_ne!(
        managed_group_id, process.process.process_group_id,
        "the managed server must not share the outer CLI process group"
    );
    assert_live_process_in_group(
        server_pid,
        managed_group_id,
        "TERM-ignoring fixture before shutdown",
    );
    assert!(
        process.is_running(),
        "fastmcp dev exited before shutdown was requested"
    );

    // The outer CLI group leader is retained and known live here, so this is
    // the only safe point at which the harness signals its numeric group.
    process
        .process
        .signal_group("-INT")
        .expect("interrupt exact fastmcp dev process group");
    wait_for_marker_file(&survived_term_marker, Duration::from_secs(5));

    let status = wait_for_dev_exit(
        &mut process,
        Duration::from_secs(15),
        "fastmcp dev watchdog escalation",
    );
    assert!(status.success(), "signal-driven dev shutdown must succeed");
    wait_for_linux_process_exit(server_pid, Duration::from_secs(10));
    wait_for_linux_process_group_exit(managed_group_id, Duration::from_secs(10));
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_dev_hot_reload_rebuilds_on_matching_change() {
    let _cargo_fixture_lock = cargo_fixture_lock();
    let root = mktemp_dir("dev-hot-reload");
    init_cargo_project(
        &root,
        r#"use std::time::Duration;

fn main() {
    println!("dev-test-server-start pid={}", std::process::id());
    std::thread::sleep(Duration::from_secs(60));
}"#,
    );

    let (process, rx) = spawn_dev(
        &root,
        &[
            "dev",
            "--debounce",
            "50",
            "--reload-dir",
            "src",
            "--reload-pattern",
            "src/main.rs",
            root.to_str().unwrap(),
        ],
    );

    let initial = wait_for_all_contains(
        &rx,
        &["Watching for changes", "dev-test-server-start"],
        Duration::from_secs(60),
    );
    let first_pid = fixture_pid(&initial[1]);

    // Touch a matching file.
    let main_rs = root.join("src/main.rs");
    let mut content = std::fs::read_to_string(&main_rs).expect("read main.rs");
    content.push_str("\n// change to trigger reload\n");
    write_file(&main_rs, &content);

    let _ = wait_for_contains(&rx, "Change detected, rebuilding", Duration::from_secs(60));
    // After rebuild, `cargo run` should execute again and our test binary should print again.
    let restarted = wait_for_contains(&rx, "dev-test-server-start", Duration::from_secs(60));
    let second_pid = fixture_pid(&restarted);
    assert_ne!(
        first_pid, second_pid,
        "reload reused the old server process"
    );
    wait_for_linux_process_exit(first_pid, Duration::from_secs(10));

    process.shutdown();
    wait_for_linux_process_exit(second_pid, Duration::from_secs(10));
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_dev_reload_patterns_prevent_unrelated_changes_from_rebuilding() {
    let _cargo_fixture_lock = cargo_fixture_lock();
    let root = mktemp_dir("dev-pattern-filter");
    init_cargo_project(
        &root,
        r#"use std::time::Duration;

fn main() {
    println!("dev-test-server-start pid={}", std::process::id());
    std::thread::sleep(Duration::from_secs(60));
}"#,
    );

    let (mut process, rx) = spawn_dev(
        &root,
        &[
            "dev",
            "--debounce",
            "50",
            "--reload-dir",
            "src",
            "--reload-pattern",
            "src/main.rs",
            root.to_str().unwrap(),
        ],
    );

    let initial = wait_for_all_contains(
        &rx,
        &["Watching for changes", "dev-test-server-start"],
        Duration::from_secs(60),
    );
    let server_pid = fixture_pid(&initial[1]);

    // Modify an unrelated file that should not match the pattern.
    let other_rs = root.join("src/ignored.rs");
    write_file(&other_rs, "pub fn ignored() {}\n");

    // Give the watcher some time to observe the change; we should NOT rebuild.
    assert_not_contains_for(
        &mut process,
        &rx,
        "Change detected, rebuilding",
        Duration::from_millis(800),
    );

    process.shutdown();
    wait_for_linux_process_exit(server_pid, Duration::from_secs(10));
}
