//! E2E tests for `fastmcp list`.

#![cfg(unix)]

use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CAPTURE_DRAIN_DEADLINE: Duration = Duration::from_secs(1);
const CLI_DEADLINE: Duration = Duration::from_secs(120);
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const PROCESS_CLEANUP_DEADLINE: Duration = Duration::from_secs(2);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
const PROCESS_TERM_GRACE: Duration = Duration::from_millis(500);
static TEMP_DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
        // Keep CLI fixtures beneath a root-owned sticky ancestor even when a build
        // farm rewrites TMPDIR beneath a shared non-sticky mirror.
        let temp_root = std::fs::canonicalize("/tmp")
            .expect("resolve the sticky test temporary directory without symlinks");
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

fn fastmcp_bin() -> String {
    env!("CARGO_BIN_EXE_fastmcp").to_string()
}

struct ChildGuard {
    child: Option<Child>,
    #[cfg(unix)]
    process_group_id: u32,
    owns_process_group: bool,
    armed: bool,
}

impl ChildGuard {
    fn spawn(command: &mut Command) -> Self {
        configure_process_group(command);
        let child = command.spawn().expect("spawn CLI command");
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
        self.child.as_mut().expect("child guard is disarmed")
    }

    fn wait_until(&mut self, timeout: Duration) -> Result<ExitStatus, String> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        loop {
            match self.child_is_zombie("failed to inspect CLI child") {
                Ok(true) => {
                    return self
                        .terminate()
                        .map_err(|error| {
                            format!("failed to clean up CLI descendants after exit: {error}")
                        })?
                        .ok_or_else(|| "observed zombie CLI child had no exit status".to_owned());
                }
                Ok(false) if Instant::now() < deadline => {
                    std::thread::sleep(PROCESS_POLL_INTERVAL);
                }
                Ok(false) => {
                    let cleanup = self.terminate().err();
                    return Err(format!(
                        "command exceeded its {timeout:?} deadline; cleanup error: {cleanup:?}"
                    ));
                }
                Err(error) => {
                    self.owns_process_group = false;
                    self.armed = false;
                    return Err(format!(
                        "failed to inspect CLI child; guard disarmed: {error}"
                    ));
                }
            }
        }
    }

    #[cfg(unix)]
    fn signal_group(&self, signal: &str) -> Result<(), String> {
        let target = format!("-{}", self.process_group_id);
        let status = Command::new("/bin/kill")
            .args([signal, "--", &target])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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
        process_is_zombie(self.child.as_ref().expect("child guard is disarmed").id())
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

    fn terminate(&mut self) -> Result<Option<ExitStatus>, String> {
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
        // The unreaped live/zombie leader pins the PGID until all group
        // signals and membership checks have completed.
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

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Err(error) = self.terminate() {
            eprintln!("fastmcp list-test harness cleanup failed: {error}");
        }
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

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
        let Some((state, group)) = read_linux_process_state_and_group(pid)? else {
            continue;
        };
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
    let (state, _) = read_linux_process_state_and_group(pid)?
        .ok_or_else(|| format!("process {pid} disappeared before it could be reaped"))?;
    Ok(matches!(state, 'Z' | 'X' | 'x'))
}

#[cfg(target_os = "linux")]
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

fn run_command(mut command: Command) -> Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = ChildGuard::spawn(&mut command);
    let stdout = capture_pipe(child.child_mut().stdout.take().expect("piped stdout"));
    let stderr = capture_pipe(child.child_mut().stderr.take().expect("piped stderr"));
    let deadline = Instant::now()
        .checked_add(CLI_DEADLINE)
        .unwrap_or_else(Instant::now);
    let (stdout, stdout_error) = finish_capture(stdout, "stdout", remaining(deadline));
    if let Some(error) = stdout_error {
        let cleanup = child.terminate().err();
        let (stderr, stderr_error) = finish_capture(stderr, "stderr", CAPTURE_DRAIN_DEADLINE);
        panic!(
            "failed to drain CLI output: {}; cleanup error: {cleanup:?}; captured stdout={} bytes, stderr={} bytes (content redacted)",
            [Some(error), stderr_error]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join("; "),
            stdout.len(),
            stderr.len()
        );
    }

    let (stderr, stderr_error) = finish_capture(stderr, "stderr", remaining(deadline));
    if let Some(error) = stderr_error {
        let cleanup = child.terminate().err();
        panic!(
            "failed to drain CLI output: {error}; cleanup error: {cleanup:?}; captured stdout={} bytes, stderr={} bytes (content redacted)",
            stdout.len(),
            stderr.len()
        );
    }

    let status = child.wait_until(remaining(deadline));
    let status = status.unwrap_or_else(|error| {
        panic!(
            "{error}; captured stdout={} bytes, stderr={} bytes (content redacted)",
            stdout.len(),
            stderr.len()
        )
    });
    Output {
        status,
        stdout,
        stderr,
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn mktemp_dir(prefix: &str) -> TestTempDir {
    TestTempDir::new(prefix)
}

fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir");
    }
    std::fs::write(path, content).unwrap();
}

fn run_cli(home: &Path, cwd: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(fastmcp_bin());
    command
        .args(args)
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("CLINE_MCP_SETTINGS_PATH")
        .env_remove("CLINE_DATA_DIR")
        .env_remove("CLINE_DIR")
        .current_dir(cwd);
    run_command(command)
}

fn stdout_str(output: &Output) -> String {
    std::str::from_utf8(&output.stdout)
        .expect("fastmcp list stdout must be valid UTF-8")
        .to_owned()
}

fn stderr_str(output: &Output) -> String {
    std::str::from_utf8(&output.stderr)
        .expect("fastmcp list stderr must be valid UTF-8")
        .to_owned()
}

#[cfg(target_os = "macos")]
fn claude_cfg(home: &Path) -> PathBuf {
    home.join("Library/Application Support/Claude/claude_desktop_config.json")
}

#[cfg(target_os = "linux")]
fn claude_cfg(home: &Path) -> PathBuf {
    home.join(".config/Claude/claude_desktop_config.json")
}

#[cfg(target_os = "linux")]
fn cursor_cfg(home: &Path) -> PathBuf {
    home.join(".cursor/mcp.json")
}

#[cfg(target_os = "linux")]
fn cline_cfg(home: &Path) -> PathBuf {
    home.join(".cline/data/settings/cline_mcp_settings.json")
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_list_json_enumerates_multiple_sources() {
    let home = mktemp_dir("list-home");
    let proj = mktemp_dir("list-proj");

    write_file(
        &claude_cfg(&home),
        r#"{"mcpServers":{"claude-srv":{"command":"echo","args":["a"]}}}"#,
    );
    write_file(
        &cursor_cfg(&home),
        r#"{"mcpServers":{"cursor-srv":{"command":"echo","args":["b"]}}}"#,
    );
    write_file(
        &cline_cfg(&home),
        r#"{"mcpServers":{"cline-srv":{"transport":{"type":"stdio","command":"echo","args":["c"]}}}}"#,
    );
    write_file(
        &proj.join("mcp.json"),
        r#"{"servers":{"proj-srv":{"command":"echo","args":["d"]}}}"#,
    );

    let output = run_cli(&home, &proj, &["list", "--format", "json"]);
    assert!(output.status.success());

    let out = stdout_str(&output);
    let json: serde_json::Value = serde_json::from_str(&out).expect("parse list json");
    let servers = json
        .get("servers")
        .and_then(|v| v.as_array())
        .expect("servers array");

    let mut names: Vec<String> = servers
        .iter()
        .filter_map(|s| {
            s.get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    names.sort();

    assert!(names.contains(&"claude-srv".to_string()));
    assert!(names.contains(&"cursor-srv".to_string()));
    assert!(names.contains(&"cline-srv".to_string()));
    assert!(names.contains(&"proj-srv".to_string()));
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_list_yaml_output_is_parseable() {
    let home = mktemp_dir("list-yaml-home");
    let proj = mktemp_dir("list-yaml-proj");

    write_file(
        &claude_cfg(&home),
        r#"{"mcpServers":{"claude-srv":{"command":"echo","args":[]}}}"#,
    );

    let output = run_cli(&home, &proj, &["list", "--format", "yaml"]);
    assert!(output.status.success());

    let out = stdout_str(&output);
    let yaml: serde_yaml::Value = serde_yaml::from_str(&out).expect("parse list yaml");
    assert!(yaml.get("servers").is_some());
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_list_custom_config_path_only_uses_that_file() {
    let home = mktemp_dir("list-custom-home");
    let proj = mktemp_dir("list-custom-proj");
    let custom = proj.join("custom.json");

    // Put a server in the standard Claude config, but verify `--config` ignores it.
    write_file(
        &claude_cfg(&home),
        r#"{"mcpServers":{"should-not-appear":{"command":"echo","args":[]}}}"#,
    );
    write_file(
        &custom,
        r#"{"mcpServers":{"custom-srv":{"command":"echo","args":[]}}}"#,
    );

    let output = run_cli(
        &home,
        &proj,
        &[
            "list",
            "--config",
            custom.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert!(output.status.success());

    let out = stdout_str(&output);
    let json: serde_json::Value = serde_json::from_str(&out).expect("parse list json");
    let servers = json
        .get("servers")
        .and_then(|v| v.as_array())
        .expect("servers array");

    let names: Vec<&str> = servers
        .iter()
        .filter_map(|s| s.get("name").and_then(|v| v.as_str()))
        .collect();

    assert!(names.contains(&"custom-srv"));
    assert!(!names.contains(&"should-not-appear"));
}

#[test]
fn e2e_list_remote_config_is_typed_and_never_renders_credentials() {
    const USERINFO_SECRET: &str = "remote-userinfo-secret";
    const PATH_SECRET: &str = "remote-path-secret";
    const QUERY_SECRET: &str = "remote-query-secret";
    const FRAGMENT_SECRET: &str = "remote-fragment-secret";
    const HEADER_SECRET: &str = "remote-header-secret";
    const AUTH_SECRET: &str = "remote-auth-secret";

    let home = mktemp_dir("list-remote-home");
    let proj = mktemp_dir("list-remote-proj");
    let custom = proj.join("remote.json");
    write_file(
        &custom,
        &format!(
            r#"{{"mcpServers":{{"remote":{{"type":"http","url":"https://user:{USERINFO_SECRET}@api.example.test/{PATH_SECRET}?token={QUERY_SECRET}#{FRAGMENT_SECRET}","headers":{{"Authorization":"Bearer {HEADER_SECRET}"}},"auth":{{"token":"{AUTH_SECRET}"}}}},"public-root":{{"type":"sse","url":"https://events.example.test/"}}}}}}"#,
        ),
    );

    for format in ["json", "yaml"] {
        let output = run_cli(
            &home,
            &proj,
            &[
                "list",
                "--config",
                custom.to_str().unwrap(),
                "--format",
                format,
            ],
        );
        assert!(output.status.success(), "remote {format} listing failed");
        let rendered = stdout_str(&output);
        for secret in [
            USERINFO_SECRET,
            PATH_SECRET,
            QUERY_SECRET,
            FRAGMENT_SECRET,
            HEADER_SECRET,
            AUTH_SECRET,
            "Authorization",
        ] {
            assert!(!rendered.contains(secret));
            assert!(!stderr_str(&output).contains(secret));
        }
        assert!(rendered.contains("streamable-http"));
        assert!(rendered.contains("sse"));
        assert!(rendered.contains("https://api.example.test/<redacted-route>"));
        assert!(rendered.contains("https://events.example.test/"));
    }

    let json_output = run_cli(
        &home,
        &proj,
        &[
            "list",
            "--config",
            custom.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    let json: serde_json::Value =
        serde_json::from_str(&stdout_str(&json_output)).expect("parse remote list JSON");
    let servers = json["servers"].as_array().expect("remote server array");
    let remote = servers
        .iter()
        .find(|server| server["name"] == "remote")
        .expect("remote entry");
    assert_eq!(remote["transport"], "streamable-http");
    assert_eq!(
        remote["endpoint"],
        "https://api.example.test/<redacted-route>"
    );
    assert_eq!(remote["credentials_configured"], true);
    assert!(remote.get("command").is_none());
    assert_eq!(json["redacted"], true);

    let root = servers
        .iter()
        .find(|server| server["name"] == "public-root")
        .expect("root endpoint entry");
    assert_eq!(root["transport"], "sse");
    assert_eq!(root["endpoint"], "https://events.example.test/");
    assert_eq!(root["credentials_configured"], false);

    let table_output = run_cli(
        &home,
        &proj,
        &["list", "--config", custom.to_str().unwrap(), "--verbose"],
    );
    assert!(table_output.status.success());
    let table = stdout_str(&table_output);
    assert!(table.contains("Transport"));
    assert!(table.contains("Target"));
    assert!(table.contains("Credentials"));
    assert!(table.contains("configured"));
    for secret in [
        USERINFO_SECRET,
        PATH_SECRET,
        QUERY_SECRET,
        FRAGMENT_SECRET,
        HEADER_SECRET,
        AUTH_SECRET,
        "Authorization",
    ] {
        assert!(!table.contains(secret));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_list_current_nested_cline_remote_config() {
    const HEADER_SECRET: &str = "cline-header-secret";
    const OAUTH_SECRET: &str = "cline-oauth-secret";
    let home = mktemp_dir("list-cline-remote-home");
    let proj = mktemp_dir("list-cline-remote-proj");
    write_file(
        &cline_cfg(&home),
        &format!(
            r#"{{"mcpServers":{{"cline-http":{{"transport":{{"type":"streamableHttp","url":"https://cline.example.test/mcp","headers":{{"X-Api-Key":"{HEADER_SECRET}"}}}},"oauth":{{"accessToken":"{OAUTH_SECRET}"}},"disabled":true}},"cline-sse":{{"transport":{{"type":"sse","url":"https://events.cline.example.test/"}}}}}}}}"#,
        ),
    );

    for format in ["json", "yaml"] {
        let output = run_cli(
            &home,
            &proj,
            &["list", "--target", "cline", "--format", format],
        );
        assert!(output.status.success(), "nested Cline {format} listing");
        let rendered = stdout_str(&output);
        assert!(!rendered.contains(HEADER_SECRET));
        assert!(!rendered.contains(OAUTH_SECRET));
        assert!(!rendered.contains("X-Api-Key"));
        assert!(rendered.contains("streamable-http"));
        assert!(rendered.contains("sse"));
        assert!(rendered.contains("https://cline.example.test/<redacted-route>"));
        assert!(rendered.contains("https://events.cline.example.test/"));

        if format == "json" {
            let json: serde_json::Value =
                serde_json::from_str(&rendered).expect("parse Cline list JSON");
            let servers = json["servers"].as_array().expect("Cline server array");
            let http = servers
                .iter()
                .find(|server| server["name"] == "cline-http")
                .expect("nested Cline HTTP entry");
            assert_eq!(http["transport"], "streamable-http");
            assert_eq!(
                http["endpoint"],
                "https://cline.example.test/<redacted-route>"
            );
            assert_eq!(http["credentials_configured"], true);
            assert_eq!(http["enabled"], false);

            let sse = servers
                .iter()
                .find(|server| server["name"] == "cline-sse")
                .expect("nested Cline SSE entry");
            assert_eq!(sse["transport"], "sse");
            assert_eq!(sse["endpoint"], "https://events.cline.example.test/");
            assert_eq!(sse["credentials_configured"], false);
        }
    }

    let table = run_cli(&home, &proj, &["list", "--target", "cline", "--verbose"]);
    assert!(table.status.success(), "nested Cline table listing");
    let rendered = stdout_str(&table);
    assert!(rendered.contains("streamable-http"));
    assert!(rendered.contains("sse"));
    assert!(rendered.contains("https://cline.example.test/<redacted-route>"));
    assert!(rendered.contains("https://events.cline.example.test/"));
    assert!(!rendered.contains(HEADER_SECRET));
    assert!(!rendered.contains(OAUTH_SECRET));
    assert!(!rendered.contains("X-Api-Key"));
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_list_custom_config_honors_the_explicit_client_target() {
    const SECRET: &str = "CUSTOM_TARGET_SECRET_MUST_NOT_LEAK";
    let home = mktemp_dir("list-custom-target-home");
    let proj = mktemp_dir("list-custom-target-proj");
    let custom = proj.join("nested-cline.json");
    let config = serde_json::json!({
        "mcpServers": {
            "remote": {
                "transport": {
                    "type": "streamableHttp",
                    "url": "https://custom.cline.example.test/",
                    "headers": {"Authorization": format!("Bearer {SECRET}")},
                }
            }
        }
    });
    write_file(&custom, &config.to_string());

    let accepted = run_cli(
        &home,
        &proj,
        &[
            "list",
            "--config",
            custom.to_str().unwrap(),
            "--target",
            "cline",
            "--format",
            "json",
        ],
    );
    assert!(
        accepted.status.success(),
        "the explicit Cline target must select the nested Cline schema"
    );
    let rendered = stdout_str(&accepted);
    assert!(!rendered.contains(SECRET));
    assert!(!stderr_str(&accepted).contains(SECRET));
    let json: serde_json::Value =
        serde_json::from_str(&rendered).expect("parse explicitly targeted custom config");
    assert_eq!(json["servers"][0]["transport"], "streamable-http");
    assert_eq!(
        json["servers"][0]["endpoint"],
        "https://custom.cline.example.test/"
    );
    assert_eq!(json["servers"][0]["credentials_configured"], true);
    assert_eq!(json["redacted"], true);

    let rejected = run_cli(
        &home,
        &proj,
        &[
            "list",
            "--config",
            custom.to_str().unwrap(),
            "--target",
            "cursor",
            "--format",
            "json",
        ],
    );
    assert!(
        !rejected.status.success(),
        "changing only the target must not admit Cline's nested schema as Cursor config"
    );
    assert!(
        rejected.stdout.is_empty(),
        "wrong-target custom parsing must fail atomically"
    );
    let diagnostic = stderr_str(&rejected);
    assert!(diagnostic.contains("schema validation failed"));
    assert!(!diagnostic.contains(SECRET));
    assert!(diagnostic.len() < 16 * 1024);
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_list_cursor_url_only_remote_marks_userinfo_credentials() {
    const USERINFO_SECRET: &str = "cursor-userinfo-only-secret";
    let home = mktemp_dir("list-cursor-remote-home");
    let proj = mktemp_dir("list-cursor-remote-proj");
    write_file(
        &cursor_cfg(&home),
        &format!(
            r#"{{"mcpServers":{{"cursor-remote":{{"url":"https://user:{USERINFO_SECRET}@cursor.example.test/"}}}}}}"#,
        ),
    );

    let output = run_cli(
        &home,
        &proj,
        &["list", "--target", "cursor", "--format", "json"],
    );
    assert!(
        output.status.success(),
        "documented Cursor URL-only listing"
    );
    let rendered = stdout_str(&output);
    assert!(!rendered.contains(USERINFO_SECRET));
    let json: serde_json::Value = serde_json::from_str(&rendered).expect("parse Cursor list JSON");
    assert_eq!(json["servers"][0]["transport"], "streamable-http");
    assert_eq!(
        json["servers"][0]["endpoint"],
        "https://cursor.example.test/<redacted-route>"
    );
    assert_eq!(json["servers"][0]["credentials_configured"], true);
    assert_eq!(json["redacted"], true);
}

#[test]
fn e2e_list_remote_config_rejects_forbidden_dimension_atomically() {
    const SECRET: &str = "REMOTE_E2E_NEGATIVE_SECRET_MUST_NOT_LEAK";
    let home = mktemp_dir("list-remote-negative-home");
    let proj = mktemp_dir("list-remote-negative-proj");
    let custom = proj.join("remote-negative.json");
    let accepted = serde_json::json!({
        "mcpServers": {
            "remote": {
                "type": "sse",
                "url": "https://example.test/sse",
                "headers": {"X-Test": "safe"},
            }
        }
    });
    let mut invalid_scheme = accepted.clone();
    invalid_scheme["mcpServers"]["remote"]["url"] = serde_json::json!("ftp://example.test/sse");
    let mut malformed_url = accepted.clone();
    malformed_url["mcpServers"]["remote"]["url"] = serde_json::json!("https://example.test/%zz");
    let mut non_string_header = accepted.clone();
    non_string_header["mcpServers"]["remote"]["headers"]["X-Test"] = serde_json::json!([SECRET]);
    let mut conflicting_local_field = accepted.clone();
    conflicting_local_field["mcpServers"]["remote"]["command"] = serde_json::json!(SECRET);
    let mut unsupported_transport = accepted.clone();
    unsupported_transport["mcpServers"]["remote"]["type"] = serde_json::json!("ws");
    let mut unknown_field = accepted;
    unknown_field["mcpServers"]["remote"]["credentialTypo"] = serde_json::json!(SECRET);
    let cases = [
        invalid_scheme.to_string(),
        malformed_url.to_string(),
        non_string_header.to_string(),
        conflicting_local_field.to_string(),
        unsupported_transport.to_string(),
        unknown_field.to_string(),
    ];

    for content in cases {
        write_file(&custom, &content);
        let output = run_cli(
            &home,
            &proj,
            &[
                "list",
                "--config",
                custom.to_str().unwrap(),
                "--format",
                "json",
            ],
        );
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "failed list output must be atomic"
        );
        let stderr = stderr_str(&output);
        assert!(stderr.contains("schema validation failed"));
        assert!(!stderr.contains(SECRET));
        assert!(stderr.len() < 16 * 1024);
    }
}

#[test]
fn e2e_list_toml_preserves_cwd_in_structured_and_verbose_output() {
    let home = mktemp_dir("list-toml-cwd-home");
    let proj = mktemp_dir("list-toml-cwd-proj");
    let custom = proj.join("custom.toml");
    write_file(
        &custom,
        "[servers.toml-server]\ncommand = \"echo\"\ncwd = \"/srv/toml-server\"\n",
    );

    let json_output = run_cli(
        &home,
        &proj,
        &[
            "list",
            "--config",
            custom.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert!(json_output.status.success());
    let json: serde_json::Value =
        serde_json::from_str(&stdout_str(&json_output)).expect("parse TOML-backed list JSON");
    assert_eq!(json["servers"][0]["cwd"], "/srv/toml-server");

    let table_output = run_cli(
        &home,
        &proj,
        &["list", "--config", custom.to_str().unwrap(), "--verbose"],
    );
    assert!(table_output.status.success());
    let table = stdout_str(&table_output);
    assert!(table.contains("Working Directory"));
    assert!(table.contains("/srv/toml-server"));
}

#[test]
fn e2e_list_redacts_environment_values_in_structured_and_table_output() {
    const SECRET: &str = "e2e-secret-must-never-be-rendered";
    const ARG_SECRET: &str = "e2e-argument-secret-must-never-be-rendered";
    const CWD_SECRET: &str = "e2e-cwd-secret-must-never-be-rendered";

    let home = mktemp_dir("list-redaction-home");
    let proj = mktemp_dir("list-redaction-proj");
    let custom = proj.join("secrets.json");
    write_file(
        &custom,
        r#"{"mcpServers":{"secret-server":{"command":"echo","args":["--safe","visible","--api-token","e2e-argument-secret-must-never-be-rendered","--client-secret=inline-argument-secret","https://user:url-password@example.test/path"],"env":{"API_TOKEN":"e2e-secret-must-never-be-rendered"},"cwd":"token=e2e-cwd-secret-must-never-be-rendered\n/srv/server"}}}"#,
    );

    let json_output = run_cli(
        &home,
        &proj,
        &[
            "list",
            "--config",
            custom.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert!(
        json_output.status.success(),
        "JSON list failed with status {} (stdout={} bytes, stderr={} bytes; content redacted)",
        json_output.status,
        json_output.stdout.len(),
        json_output.stderr.len()
    );
    let json_stdout = stdout_str(&json_output);
    assert!(!json_stdout.contains(SECRET));
    assert!(!json_stdout.contains(ARG_SECRET));
    assert!(!json_stdout.contains(CWD_SECRET));
    assert!(!json_stdout.contains("inline-argument-secret"));
    assert!(!json_stdout.contains("url-password"));
    assert!(!stderr_str(&json_output).contains(SECRET));
    let json: serde_json::Value = serde_json::from_str(&json_stdout).expect("parse list JSON");
    assert_eq!(json["servers"][0]["env"]["API_TOKEN"], "<redacted>");
    assert_eq!(json["servers"][0]["args"][0], "--<option>");
    assert_eq!(json["servers"][0]["args"][1], "<redacted>");
    assert_eq!(json["servers"][0]["args"][2], "--<option>");
    assert_eq!(json["servers"][0]["args"][3], "<redacted>");
    assert_eq!(json["servers"][0]["args"][4], "--<option>=<redacted>");
    assert_eq!(json["servers"][0]["args"][5], "<redacted>");
    assert_eq!(
        json["servers"][0]["cwd"],
        "token=<redacted>\\x0A/srv/server"
    );
    assert_eq!(json["redacted"], true);
    assert_eq!(json["sanitized"], true);
    assert_eq!(json["truncated"], false);
    assert!(!json_stdout.contains("safe"));
    assert!(!json_stdout.contains("api-token"));
    assert!(!json_stdout.contains("client-secret"));
    assert!(!json_stdout.contains("visible"));

    let yaml_output = run_cli(
        &home,
        &proj,
        &[
            "list",
            "--config",
            custom.to_str().unwrap(),
            "--format",
            "yaml",
        ],
    );
    assert!(
        yaml_output.status.success(),
        "YAML list failed with status {} (stdout={} bytes, stderr={} bytes; content redacted)",
        yaml_output.status,
        yaml_output.stdout.len(),
        yaml_output.stderr.len()
    );
    let yaml_stdout = stdout_str(&yaml_output);
    assert!(!yaml_stdout.contains(SECRET));
    assert!(!yaml_stdout.contains(ARG_SECRET));
    assert!(!yaml_stdout.contains(CWD_SECRET));
    assert!(!yaml_stdout.contains("inline-argument-secret"));
    assert!(!yaml_stdout.contains("url-password"));
    assert!(!stderr_str(&yaml_output).contains(SECRET));
    let yaml: serde_yaml::Value = serde_yaml::from_str(&yaml_stdout).expect("parse list YAML");
    assert_eq!(
        yaml.get("servers")
            .and_then(serde_yaml::Value::as_sequence)
            .and_then(|servers| servers.first())
            .and_then(|server| server.get("env"))
            .and_then(|environment| environment.get("API_TOKEN"))
            .and_then(serde_yaml::Value::as_str),
        Some("<redacted>")
    );
    assert_eq!(
        yaml.get("redacted").and_then(serde_yaml::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        yaml.get("sanitized").and_then(serde_yaml::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        yaml.get("truncated").and_then(serde_yaml::Value::as_bool),
        Some(false)
    );

    let table_output = run_cli(
        &home,
        &proj,
        &["list", "--config", custom.to_str().unwrap(), "--verbose"],
    );
    assert!(
        table_output.status.success(),
        "table list failed with status {} (stdout={} bytes, stderr={} bytes; content redacted)",
        table_output.status,
        table_output.stdout.len(),
        table_output.stderr.len()
    );
    let table_rendering = format!("{}{}", stdout_str(&table_output), stderr_str(&table_output));
    assert!(!table_rendering.contains(SECRET));
    assert!(!table_rendering.contains(ARG_SECRET));
    assert!(!table_rendering.contains(CWD_SECRET));
    assert!(!table_rendering.contains("inline-argument-secret"));
    assert!(!table_rendering.contains("url-password"));
    assert!(!table_rendering.contains("client-secret"));
    assert!(!table_rendering.contains("visible"));
    assert!(table_rendering.contains("API_TOKEN=<redacted>"));
    assert!(table_rendering.contains("--<option> <redacted>"));
    assert!(table_rendering.contains("--<option>=<redacted>"));
    assert!(table_rendering.contains("Working Directory"));
    assert!(table_rendering.contains("token=<redacted>\\x0A/srv/server"));
}

#[test]
fn e2e_list_custom_config_rejects_malformed_server_entry_atomically() {
    let home = mktemp_dir("list-malformed-custom-home");
    let proj = mktemp_dir("list-malformed-custom-proj");
    let custom = proj.join("malformed.json");
    write_file(
        &custom,
        r#"{"mcpServers":{"valid":{"command":"echo"},"broken":{"command":42}}}"#,
    );

    let output = run_cli(
        &home,
        &proj,
        &[
            "list",
            "--config",
            custom.to_str().unwrap(),
            "--format",
            "json",
        ],
    );

    assert!(!output.status.success());
    assert_eq!(stdout_str(&output), "", "failed JSON output must be atomic");
    let stderr = stderr_str(&output);
    assert!(stderr.contains("Invalid MCP server entry \"broken\""));
    assert!(stderr.contains("Custom config"));
    assert!(stderr.contains(custom.to_str().unwrap()));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn e2e_list_explicit_target_rejects_malformed_server_entry() {
    let home = mktemp_dir("list-malformed-target-home");
    let proj = mktemp_dir("list-malformed-target-proj");
    let config_path = claude_cfg(&home);
    write_file(
        &config_path,
        r#"{"mcpServers":{"broken":{"args":["missing-command"]}}}"#,
    );

    let output = run_cli(
        &home,
        &proj,
        &["list", "--target", "claude", "--format", "json"],
    );

    assert!(!output.status.success());
    assert_eq!(stdout_str(&output), "", "failed JSON output must be atomic");
    let stderr = stderr_str(&output);
    assert!(stderr.contains("Invalid MCP server entry \"broken\""));
    assert!(stderr.contains("Claude config"));
    assert!(stderr.contains(config_path.to_str().unwrap()));
}

#[test]
fn e2e_list_custom_config_errors_are_strict_and_metadata_only() {
    const JSON_SECRET: &str = "JSON_SOURCE_CREDENTIAL_MUST_NOT_LEAK";
    const TOML_SECRET: &str = "TOML_SOURCE_CREDENTIAL_MUST_NOT_LEAK";
    const TYPO_SECRET: &str = "UNKNOWN_FIELD_CREDENTIAL_MUST_NOT_LEAK";
    const ENTRY_NAME_SECRET: &str = "UNKNOWN_ENTRY_NAME_CREDENTIAL_MUST_NOT_LEAK";

    let home = mktemp_dir("list-strict-custom-home");
    let proj = mktemp_dir("list-strict-custom-proj");
    let malformed_json = proj.join("malformed-\u{1b}[31m.json");
    write_file(
        &malformed_json,
        &format!(r#"{{"mcpServers":{{"bad":"{JSON_SECRET}""#),
    );

    let output = run_cli(
        &home,
        &proj,
        &[
            "list",
            "--config",
            malformed_json.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert!(!output.status.success());
    assert_eq!(output.stdout, b"");
    let stderr = stderr_str(&output);
    assert!(!stderr.contains(JSON_SECRET));
    assert!(!stderr.contains('\u{1b}'));
    assert!(stderr.contains("category:"));
    assert!(stderr.contains("line:"));
    assert!(stderr.contains("\\x1B"));

    let malformed_toml = proj.join("malformed.toml");
    write_file(
        &malformed_toml,
        &format!("[servers.bad]\ncommand = \"{TOML_SECRET}\n"),
    );
    let output = run_cli(
        &home,
        &proj,
        &[
            "list",
            "--config",
            malformed_toml.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert!(!output.status.success());
    assert_eq!(output.stdout, b"");
    let stderr = stderr_str(&output);
    assert!(!stderr.contains(TOML_SECRET));
    assert!(stderr.contains("category: syntax"));

    let strict_cases = [
        ("scalar.json", "42", "root must be a JSON object"),
        (
            "missing.json",
            r#"{"unrelated":{}}"#,
            "expected MCP server registry is missing",
        ),
        (
            "wrong-registry.json",
            r#"{"mcpServers":[]}"#,
            "MCP server registry must be a JSON object",
        ),
        (
            "typo.json",
            r#"{"mcpServers":{"token=UNKNOWN_ENTRY_NAME_CREDENTIAL_MUST_NOT_LEAK\u001b[31m":{"command":"echo","credential_typo":["UNKNOWN_FIELD_CREDENTIAL_MUST_NOT_LEAK"]}}}"#,
            "schema validation failed",
        ),
    ];
    for (file_name, content, expected) in strict_cases {
        let path = proj.join(file_name);
        write_file(&path, content);
        let output = run_cli(
            &home,
            &proj,
            &[
                "list",
                "--config",
                path.to_str().unwrap(),
                "--format",
                "json",
            ],
        );
        assert!(!output.status.success(), "{file_name} must be rejected");
        assert!(output.stdout.is_empty(), "failure output must be atomic");
        let stderr = stderr_str(&output);
        assert!(
            stderr.contains(expected),
            "unexpected {file_name} diagnostic"
        );
        assert!(!stderr.contains(TYPO_SECRET));
        assert!(!stderr.contains(ENTRY_NAME_SECRET));
        assert!(!stderr.contains('\u{1b}'));
        assert!(stderr.len() < 16 * 1024);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn e2e_list_explicit_client_config_requires_object_registry_and_valid_core_entries() {
    const FIELD_SECRET: &str = "CLIENT_FIELD_CREDENTIAL_MUST_NOT_LEAK";

    let home = mktemp_dir("list-strict-client-home");
    let proj = mktemp_dir("list-strict-client-proj");
    let config_path = claude_cfg(&home);
    let cases = [
        ("[]", "root must be a JSON object"),
        (r#"{"other":{}}"#, "expected MCP server registry is missing"),
        (
            r#"{"mcpServers":"CLIENT_REGISTRY_CREDENTIAL_MUST_NOT_LEAK"}"#,
            "MCP server registry must be a JSON object",
        ),
        (
            r#"{"mcpServers":{"bad":{"command":"echo","args":"CLIENT_FIELD_CREDENTIAL_MUST_NOT_LEAK"}}}"#,
            "schema validation failed",
        ),
        (
            r#"{"mcpServers":{"bad":{"command":"echo","argumentz":["CLIENT_FIELD_CREDENTIAL_MUST_NOT_LEAK"]}}}"#,
            "schema validation failed",
        ),
    ];

    for (content, expected) in cases {
        write_file(&config_path, content);
        let output = run_cli(
            &home,
            &proj,
            &["list", "--target", "claude", "--format", "json"],
        );
        assert!(!output.status.success());
        assert_eq!(output.stdout, b"");
        let stderr = stderr_str(&output);
        assert!(stderr.contains(expected));
        assert!(!stderr.contains(FIELD_SECRET));
        assert!(!stderr.contains("CLIENT_REGISTRY_CREDENTIAL_MUST_NOT_LEAK"));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_list_accepts_client_owned_cline_extension_fields() {
    let home = mktemp_dir("list-cline-extension-home");
    let proj = mktemp_dir("list-cline-extension-proj");
    let config_path = cline_cfg(&home);
    write_file(
        &config_path,
        r#"{"mcpServers":{"extended":{"transport":{"type":"stdio","command":"echo","args":["--mode","test"],"cwd":"/srv/server","env":{"MODE":"test"}},"disabled":true,"autoApprove":["echo"],"timeout":60,"remoteConfigured":false,"oauth":null,"metadata":["e2e",null]}}}"#,
    );

    let output = run_cli(
        &home,
        &proj,
        &["list", "--target", "cline", "--format", "json"],
    );
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_str(&stdout_str(&output)).expect("parse Cline list JSON");
    assert_eq!(json["servers"][0]["name"], "extended");
    assert_eq!(json["servers"][0]["command"], "echo");
    assert_eq!(
        json["servers"][0]["args"],
        serde_json::json!(["--<option>", "<redacted>"])
    );
    assert_eq!(json["servers"][0]["env"]["MODE"], "<redacted>");
    assert_eq!(json["servers"][0]["cwd"], "/srv/server");
    assert_eq!(json["servers"][0]["enabled"], false);
    assert!(json["servers"][0].get("credentials_configured").is_none());

    write_file(
        &config_path,
        r#"{"mcpServers":{"extended":{"transport":{"type":"stdio","command":"echo"},"oauth":null}}}"#,
    );
    let null_oauth_output = run_cli(
        &home,
        &proj,
        &["list", "--target", "cline", "--format", "json"],
    );
    assert!(null_oauth_output.status.success());
    let null_oauth_json: serde_json::Value = serde_json::from_str(&stdout_str(&null_oauth_output))
        .expect("parse null-OAuth Cline list JSON");
    assert!(
        null_oauth_json["servers"][0]
            .get("credentials_configured")
            .is_none()
    );
    assert_eq!(null_oauth_json["redacted"], false);

    const OAUTH_SECRET: &str = "CLINE_STDIO_OAUTH_SECRET_MUST_NOT_LEAK";
    write_file(
        &config_path,
        &format!(
            r#"{{"mcpServers":{{"extended":{{"transport":{{"type":"stdio","command":"echo"}},"oauth":{{"accessToken":"{OAUTH_SECRET}"}}}}}}}}"#
        ),
    );
    let credentialed_output = run_cli(
        &home,
        &proj,
        &["list", "--target", "cline", "--format", "json"],
    );
    assert!(credentialed_output.status.success());
    let credentialed_stdout = stdout_str(&credentialed_output);
    assert!(!credentialed_stdout.contains(OAUTH_SECRET));
    assert!(!stderr_str(&credentialed_output).contains(OAUTH_SECRET));
    let credentialed_json: serde_json::Value =
        serde_json::from_str(&credentialed_stdout).expect("parse credentialed Cline list JSON");
    assert_eq!(
        credentialed_json["servers"][0]["credentials_configured"],
        true
    );
    assert_eq!(credentialed_json["redacted"], true);
}

#[test]
fn e2e_list_project_local_parse_failure_is_a_safe_warning() {
    const SECRET: &str = "PROJECT_CONFIG_CREDENTIAL_MUST_NOT_LEAK";

    let home = mktemp_dir("list-project-warning-home");
    let proj = mktemp_dir("list-project-warning-proj");
    write_file(
        &proj.join("mcp.json"),
        &format!(r#"{{"servers":{{"bad":"{SECRET}""#),
    );

    let output = run_cli(&home, &proj, &["list", "--format", "json"]);
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_str(&stdout_str(&output)).expect("warning must not corrupt JSON output");
    assert!(json["servers"].is_array());
    let stderr = stderr_str(&output);
    assert!(stderr.contains("Warning: failed to load project config"));
    assert!(!stderr.contains(SECRET));
    assert!(!stderr.contains('\u{1b}'));
}
