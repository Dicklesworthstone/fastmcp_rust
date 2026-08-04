//! E2E tests for `fastmcp install`.
//!
//! These tests run the compiled CLI binary and validate that `install`:
//! - Modifies the correct config file per target
//! - Creates a backup when overwriting an existing config
//! - Honors `--dry-run` by not touching the filesystem
//! - Fails cleanly on invalid JSON configs

#![cfg(target_os = "linux")]

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
        use std::os::unix::fs::PermissionsExt as _;

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
        std::fs::create_dir(&path).expect("create temp home");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("secure temp home permissions");
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

fn get_binary_path() -> String {
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
            eprintln!("fastmcp install-test harness cleanup failed: {error}");
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

fn run_cli_with_home(home: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(get_binary_path());
    command
        .args(args)
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .env("HOME", home)
        .env("USERPROFILE", home) // used as fallback for cursor path on non-unix
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("CLINE_MCP_SETTINGS_PATH")
        .env_remove("CLINE_DATA_DIR")
        .env_remove("CLINE_DIR");
    run_command(command)
}

#[cfg(target_os = "linux")]
fn run_cli_with_home_and_umask(home: &Path, umask: &str, args: &[&str]) -> Output {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("umask \"$1\"; shift; exec \"$@\"")
        .arg("fastmcp-umask-wrapper")
        .arg(umask)
        .arg(get_binary_path())
        .args(args)
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("CLINE_MCP_SETTINGS_PATH")
        .env_remove("CLINE_DATA_DIR")
        .env_remove("CLINE_DIR");
    run_command(command)
}

#[cfg(target_os = "linux")]
fn run_cli_with_config_home(home: &Path, config_home: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(get_binary_path());
    command
        .args(args)
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", config_home)
        .env_remove("CLINE_MCP_SETTINGS_PATH")
        .env_remove("CLINE_DATA_DIR")
        .env_remove("CLINE_DIR")
        .current_dir(home);
    run_command(command)
}

#[cfg(target_os = "linux")]
fn run_cli_with_cline_overrides(
    home: &Path,
    settings_path: Option<&Path>,
    data_dir: Option<&Path>,
    cline_dir: Option<&Path>,
    args: &[&str],
) -> Output {
    let mut command = Command::new(get_binary_path());
    command
        .args(args)
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("CLINE_MCP_SETTINGS_PATH")
        .env_remove("CLINE_DATA_DIR")
        .env_remove("CLINE_DIR");
    if let Some(path) = settings_path {
        command.env("CLINE_MCP_SETTINGS_PATH", path);
    }
    if let Some(path) = data_dir {
        command.env("CLINE_DATA_DIR", path);
    }
    if let Some(path) = cline_dir {
        command.env("CLINE_DIR", path);
    }
    run_command(command)
}

fn stdout_str(output: &Output) -> String {
    std::str::from_utf8(&output.stdout)
        .expect("fastmcp install stdout must be valid UTF-8")
        .to_owned()
}

fn stderr_str(output: &Output) -> String {
    std::str::from_utf8(&output.stderr)
        .expect("fastmcp install stderr must be valid UTF-8")
        .to_owned()
}

fn mktemp_home(prefix: &str) -> TestTempDir {
    TestTempDir::new(prefix)
}

fn read_to_string(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => std::panic::panic_any(format!("read {}: {e}", path.display())),
    }
}

fn write_secure_config_fixture(path: &Path, contents: impl AsRef<[u8]>) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(path, contents).expect("write config fixture");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("secure config fixture permissions");
}

fn create_secure_fixture_directory(root: &TestTempDir, directory: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let root_path: &Path = root.as_ref();
    let relative = directory
        .strip_prefix(root_path)
        .expect("fixture directory must remain beneath its test root");
    std::fs::set_permissions(root_path, std::fs::Permissions::from_mode(0o700))
        .expect("secure fixture root permissions");

    let mut current = root_path.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            panic!("fixture directory contains a non-normal path component");
        };
        current.push(name);
        match std::fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = std::fs::symlink_metadata(&current)
                    .expect("inspect existing fixture directory");
                assert!(
                    metadata.is_dir() && !metadata.file_type().is_symlink(),
                    "fixture path component must be a real directory"
                );
            }
            Err(error) => panic!("create fixture directory {}: {error}", current.display()),
        }
        std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o700))
            .expect("secure fixture directory permissions");
    }
}

#[cfg(target_os = "linux")]
fn claude_path(home: &Path) -> PathBuf {
    home.join(".config/Claude/claude_desktop_config.json")
}

#[cfg(target_os = "linux")]
fn claude_path_in_config_home(config_home: &Path) -> PathBuf {
    config_home.join("Claude/claude_desktop_config.json")
}

#[cfg(target_os = "linux")]
fn cursor_path(home: &Path) -> PathBuf {
    home.join(".cursor/mcp.json")
}

#[cfg(target_os = "linux")]
fn cline_path(home: &Path) -> PathBuf {
    home.join(".cline/data/settings/cline_mcp_settings.json")
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_claude_modifies_config_and_creates_backup() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let home = mktemp_home("install-claude");
    let path = claude_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());

    let original = r#"{"mcpServers":{"existing":{"command":"x","args":[]}}}"#;
    write_secure_config_fixture(&path, original);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let original_metadata = std::fs::metadata(&path).unwrap();

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );
    assert!(output.status.success(), "stderr: {}", stderr_str(&output));

    let bak = PathBuf::from(format!("{}.bak", path.display()));
    assert!(bak.exists(), "expected backup file {bak:?} to exist");
    assert_eq!(read_to_string(&bak), original);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let installed_metadata = std::fs::metadata(&path).unwrap();
    let backup_metadata = std::fs::metadata(&bak).unwrap();
    assert_eq!(installed_metadata.uid(), original_metadata.uid());
    assert_eq!(installed_metadata.gid(), original_metadata.gid());
    assert_eq!(backup_metadata.uid(), original_metadata.uid());
    assert_eq!(backup_metadata.gid(), original_metadata.gid());

    let new_content = read_to_string(&path);
    let json: serde_json::Value = serde_json::from_str(&new_content).unwrap();
    let servers = json
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .expect("mcpServers must be an object");
    assert!(servers.contains_key("existing"));
    assert!(servers.contains_key("my-server"));
    assert!(servers["my-server"].get("cwd").is_none());

    let first_install_bytes = std::fs::read(&path).expect("read first installed config");
    let second_output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );
    assert!(
        second_output.status.success(),
        "stderr: {}",
        stderr_str(&second_output)
    );
    assert!(stdout_str(&second_output).contains("no changes or backup were needed"));
    assert_eq!(
        std::fs::read(&path).expect("read idempotent installed config"),
        first_install_bytes
    );
    assert_eq!(read_to_string(&bak), original);
    let second_backup = PathBuf::from(format!("{}.bak.1", path.display()));
    assert!(
        !second_backup.exists(),
        "idempotent install must not create another backup"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_semantic_noop_preserves_noncanonical_bytes_without_backup() {
    let home = mktemp_home("install-semantic-noop");
    let path = claude_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());
    let original =
        br#"{"mcpServers":{"my-server":{"command":"/bin/echo"}},"metadata":{"format":"keep-me"}}"#;
    write_secure_config_fixture(&path, original);

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );

    assert!(output.status.success(), "stderr: {}", stderr_str(&output));
    assert!(stdout_str(&output).contains("no changes or backup were needed"));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let backup = PathBuf::from(format!("{}.bak", path.display()));
    assert!(!backup.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_uses_a_versioned_backup_without_overwriting_the_primary() {
    let home = mktemp_home("install-versioned-backup");
    let path = claude_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());
    let original = br#"{"mcpServers":{"existing":{"command":"x"}}}"#;
    let primary_backup_contents = b"preexisting backup must remain unchanged";
    write_secure_config_fixture(&path, original);
    let primary_backup = PathBuf::from(format!("{}.bak", path.display()));
    write_secure_config_fixture(&primary_backup, primary_backup_contents);

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );

    assert!(output.status.success(), "stderr: {}", stderr_str(&output));
    assert_eq!(
        std::fs::read(&primary_backup).unwrap(),
        primary_backup_contents
    );
    let versioned_backup = PathBuf::from(format!("{}.bak.1", path.display()));
    assert_eq!(std::fs::read(&versioned_backup).unwrap(), original);
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_rejects_multiply_linked_config_without_mutation() {
    let home = mktemp_home("install-hardlink");
    let path = claude_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());
    let original = br#"{"mcpServers":{"existing":{"command":"x"}}}"#;
    write_secure_config_fixture(&path, original);
    let alias = path.with_file_name("linked-config.json");
    std::fs::hard_link(&path, &alias).unwrap();

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );

    assert!(!output.status.success());
    assert!(stderr_str(&output).contains("multiply linked"));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(std::fs::read(&alias).unwrap(), original);
    assert!(!PathBuf::from(format!("{}.bak", path.display())).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_rejects_special_mode_bits_without_mutation() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = mktemp_home("install-special-mode");
    let path = claude_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());
    let original = br#"{"mcpServers":{"existing":{"command":"x"}}}"#;
    write_secure_config_fixture(&path, original);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o4640)).unwrap();

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );

    assert!(!output.status.success());
    assert!(stderr_str(&output).contains("set-user-ID"));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(!PathBuf::from(format!("{}.bak", path.display())).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_rejects_group_writable_config_without_mutation() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = mktemp_home("install-group-writable");
    let path = claude_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());
    let original = br#"{"mcpServers":{"existing":{"command":"x"}}}"#;
    write_secure_config_fixture(&path, original);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );

    assert!(!output.status.success());
    assert!(stderr_str(&output).contains("group-writable"));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(!PathBuf::from(format!("{}.bak", path.display())).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_rejects_unprotected_shared_parent_without_mutation() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = mktemp_home("install-shared-parent");
    let path = claude_path(&home);
    let parent = path.parent().unwrap();
    create_secure_fixture_directory(&home, parent);
    let original = br#"{"mcpServers":{"existing":{"command":"x"}}}"#;
    write_secure_config_fixture(&path, original);
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o777)).unwrap();

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );

    assert!(!output.status.success());
    assert!(stderr_str(&output).contains("writable by another group or user"));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(!PathBuf::from(format!("{}.bak", path.display())).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_read_and_semantic_noop_accept_xattrs_but_replacement_fails_closed() {
    let home = mktemp_home("install-xattr");
    let path = claude_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());
    let original = br#"{"mcpServers":{"my-server":{"command":"/bin/echo"}}}"#;
    write_secure_config_fixture(&path, original);
    if let Err(error) = rustix::fs::setxattr(
        &path,
        "user.fastmcp-test",
        b"preserve-me",
        rustix::fs::XattrFlags::CREATE,
    ) {
        let error = std::io::Error::from(error);
        if error.kind() == std::io::ErrorKind::Unsupported || error.raw_os_error() == Some(95) {
            return;
        }
        panic!("failed to create test xattr: {error}");
    }

    let list_output = run_cli_with_home(&home, &["list", "--target", "claude", "--format", "json"]);
    assert!(
        list_output.status.success(),
        "read-only list stderr: {}",
        stderr_str(&list_output)
    );

    let noop_output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );
    assert!(
        noop_output.status.success(),
        "semantic no-op stderr: {}",
        stderr_str(&noop_output)
    );
    assert!(stdout_str(&noop_output).contains("no changes or backup were needed"));

    let mutation_output = run_cli_with_home(
        &home,
        &["install", "other-server", "/bin/echo", "--target", "claude"],
    );
    assert!(!mutation_output.status.success());
    assert!(stderr_str(&mutation_output).contains("extended attributes"));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(!PathBuf::from(format!("{}.bak", path.display())).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_claude_install_and_list_share_xdg_config_path() {
    let home = mktemp_home("claude-xdg-home");
    let config_home = mktemp_home("claude-xdg-config");
    let expected_path = claude_path_in_config_home(&config_home);
    let legacy_home_path = claude_path(&home);

    let install_output = run_cli_with_config_home(
        &home,
        &config_home,
        &["install", "xdg-server", "/bin/echo", "--target", "claude"],
    );
    assert!(
        install_output.status.success(),
        "install stderr: {}",
        stderr_str(&install_output)
    );
    assert!(expected_path.exists());
    assert!(!legacy_home_path.exists());

    let list_output = run_cli_with_config_home(
        &home,
        &config_home,
        &["list", "--target", "claude", "--format", "json"],
    );
    assert!(
        list_output.status.success(),
        "list stderr: {}",
        stderr_str(&list_output)
    );
    let listed: serde_json::Value =
        serde_json::from_str(&stdout_str(&list_output)).expect("parse list output");
    let servers = listed["servers"].as_array().expect("servers array");
    assert!(
        servers
            .iter()
            .any(|server| server["name"].as_str() == Some("xdg-server"))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_claude_dry_run_does_not_touch_files() {
    let home = mktemp_home("install-claude-dry");
    let path = claude_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());

    let original = r#"{"mcpServers":{"existing":{"command":"x","args":[]}}}"#;
    write_secure_config_fixture(&path, original);

    let output = run_cli_with_home(
        &home,
        &[
            "install",
            "--dry-run",
            "my-server",
            "/bin/echo",
            "--target",
            "claude",
        ],
    );
    assert!(output.status.success(), "stderr: {}", stderr_str(&output));
    assert!(stdout_str(&output).contains("Dry-run: proposed update"));

    let bak = PathBuf::from(format!("{}.bak", path.display()));
    assert!(!bak.exists(), "dry-run must not create a backup");
    assert_eq!(read_to_string(&path), original);
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_cursor_modifies_config_and_creates_backup() {
    let home = mktemp_home("install-cursor");
    let path = cursor_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());

    let original = r#"{"mcpServers":{"existing":{"command":"x","args":[]},"my-server":{"type":"http","url":"https://example.invalid/mcp","headers":{"Authorization":"Bearer stale"},"auth":{"mode":"stale"},"oauth":{"clientId":"stale"},"envFile":".env.local","command":"stale"}}}"#;
    write_secure_config_fixture(&path, original);

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "cursor"],
    );
    assert!(output.status.success(), "stderr: {}", stderr_str(&output));

    let bak = PathBuf::from(format!("{}.bak", path.display()));
    assert!(bak.exists(), "expected backup file {bak:?} to exist");
    assert_eq!(read_to_string(&bak), original);

    let new_content = read_to_string(&path);
    let json: serde_json::Value = serde_json::from_str(&new_content).unwrap();
    let servers = json
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .expect("mcpServers must be an object");
    assert!(servers.contains_key("existing"));
    assert!(servers.contains_key("my-server"));
    let installed = servers["my-server"]
        .as_object()
        .expect("installed Cursor entry must be an object");
    assert_eq!(installed.get("type"), Some(&serde_json::json!("stdio")));
    assert_eq!(
        installed.get("command"),
        Some(&serde_json::json!("/bin/echo"))
    );
    assert_eq!(
        installed.get("envFile"),
        Some(&serde_json::json!(".env.local"))
    );
    for stale in ["url", "headers", "auth", "oauth", "transportType"] {
        assert!(
            !installed.contains_key(stale),
            "stale Cursor field: {stale}"
        );
    }
    assert!(!installed.contains_key("cwd"));
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_cline_clears_transport_ownership_and_preserves_generic_metadata() {
    let home = mktemp_home("install-cline");
    let path = cline_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());

    let original = r#"{"otherSetting":{"keep":true},"mcpServers":{"existing":{"transport":{"type":"stdio","command":"x","args":[]}},"my-server":{"transport":{"type":"stdio","command":"stale-command","args":["stale"],"cwd":"/stale","env":{"STALE":"1"}},"type":"stdio","transportType":"stdio","command":"legacy-command","args":["legacy"],"cwd":"/legacy","env":{"LEGACY":"1"},"url":"https://example.invalid/stale","headers":{"X-Stale":"value"},"auth":{"mode":"stale"},"disabled":false,"autoApprove":["echo"],"timeout":120,"remoteConfigured":true,"oauth":{"clientId":"preserve-me"},"metadata":{"owner":"preserve-me"}}}}"#;
    write_secure_config_fixture(&path, original);

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "cline"],
    );
    assert!(output.status.success(), "stderr: {}", stderr_str(&output));

    let bak = PathBuf::from(format!("{}.bak", path.display()));
    assert!(bak.exists(), "expected backup file {bak:?} to exist");
    assert_eq!(read_to_string(&bak), original);

    let new_content = read_to_string(&path);
    let json: serde_json::Value = serde_json::from_str(&new_content).unwrap();
    assert_eq!(json["otherSetting"]["keep"], true);
    assert!(json.get("cline.mcpServers").is_none());

    let servers = json
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .expect("mcpServers must be an object");
    assert!(servers.contains_key("existing"));
    assert!(servers.contains_key("my-server"));
    let installed = servers["my-server"]
        .as_object()
        .expect("installed Cline entry must be an object");
    assert_eq!(installed["transport"]["type"], "stdio");
    assert_eq!(installed["transport"]["command"], "/bin/echo");
    assert_eq!(installed["transport"]["args"], serde_json::json!([]));
    assert_eq!(installed["autoApprove"], serde_json::json!(["echo"]));
    assert_eq!(installed["timeout"], 120);
    assert_eq!(installed["metadata"]["owner"], "preserve-me");
    assert!(
        installed.get("remoteConfigured").is_none(),
        "a local install must clear the remote-sync ownership marker"
    );
    assert!(
        installed.get("oauth").is_none(),
        "OAuth state belongs to the replaced transport"
    );
    for stale in [
        "type",
        "transportType",
        "command",
        "args",
        "cwd",
        "env",
        "url",
        "headers",
        "auth",
    ] {
        assert!(!installed.contains_key(stale), "stale Cline field: {stale}");
    }

    let list_output = run_cli_with_home(&home, &["list", "--target", "cline", "--format", "json"]);
    assert!(
        list_output.status.success(),
        "stderr: {}",
        stderr_str(&list_output)
    );
    let listed: serde_json::Value = serde_json::from_str(&stdout_str(&list_output)).unwrap();
    let listed_server = listed["servers"]
        .as_array()
        .and_then(|servers| servers.iter().find(|server| server["name"] == "my-server"))
        .expect("updated Cline server must be listable");
    assert_eq!(listed_server["command"], "/bin/echo");

    let before_noop = read_to_string(&path);
    let noop = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "cline"],
    );
    assert!(noop.status.success(), "stderr: {}", stderr_str(&noop));
    assert!(stdout_str(&noop).contains("already configured"));
    assert_eq!(read_to_string(&path), before_noop);
    let second_backup = PathBuf::from(format!("{}.bak.1", path.display()));
    assert!(
        !second_backup.exists(),
        "semantic no-op must not create a backup"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_cline_honors_settings_data_and_cline_directory_precedence() {
    let home = mktemp_home("install-cline-overrides");
    let direct = home.join("direct/settings.json");
    let data_dir = home.join("data-override");
    let cline_dir = home.join("cline-override");
    let data_settings = data_dir.join("settings/cline_mcp_settings.json");
    let cline_settings = cline_dir.join("data/settings/cline_mcp_settings.json");

    let direct_output = run_cli_with_cline_overrides(
        &home,
        Some(&direct),
        Some(&data_dir),
        Some(&cline_dir),
        &["install", "direct", "/bin/echo", "--target", "cline"],
    );
    assert!(
        direct_output.status.success(),
        "stderr: {}",
        stderr_str(&direct_output)
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&read_to_string(&direct)).unwrap()["mcpServers"]
            ["direct"]["transport"]["command"],
        "/bin/echo"
    );
    assert!(!data_settings.exists());
    assert!(!cline_settings.exists());

    let data_output = run_cli_with_cline_overrides(
        &home,
        None,
        Some(&data_dir),
        Some(&cline_dir),
        &["install", "data", "/bin/echo", "--target", "cline"],
    );
    assert!(
        data_output.status.success(),
        "stderr: {}",
        stderr_str(&data_output)
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&read_to_string(&data_settings)).unwrap()["mcpServers"]
            ["data"]["transport"]["type"],
        "stdio"
    );
    assert!(!cline_settings.exists());

    let cline_output = run_cli_with_cline_overrides(
        &home,
        None,
        None,
        Some(&cline_dir),
        &["install", "cline", "/bin/echo", "--target", "cline"],
    );
    assert!(
        cline_output.status.success(),
        "stderr: {}",
        stderr_str(&cline_output)
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&read_to_string(&cline_settings)).unwrap()["mcpServers"]
            ["cline"]["transport"]["type"],
        "stdio"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_missing_config_creates_new_without_backup() {
    let home = mktemp_home("install-missing-config");
    let path = claude_path(&home);
    assert!(!path.exists());

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );
    assert!(output.status.success(), "stderr: {}", stderr_str(&output));

    let bak = PathBuf::from(format!("{}.bak", path.display()));
    assert!(
        !bak.exists(),
        "no backup should be created for a new config"
    );

    let new_content = read_to_string(&path);
    let json: serde_json::Value = serde_json::from_str(&new_content).unwrap();
    let servers = json
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .expect("mcpServers must be an object");
    assert!(servers.contains_key("my-server"));

    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600,
        "new installation configs must begin with secret-safe permissions"
    );
    assert_eq!(
        std::fs::metadata(home.join(".config"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700,
        "new parent directories must be owner-only"
    );
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700,
        "the immediate config parent must be owner-only"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_restores_exact_secure_modes_under_maximally_restrictive_umask() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = mktemp_home("install-restrictive-umask");
    let path = claude_path(&home);
    let output = run_cli_with_home_and_umask(
        &home,
        "0777",
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );

    assert!(output.status.success(), "stderr: {}", stderr_str(&output));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600,
        "the published config must be exactly owner-readable and owner-writable"
    );
    for directory in [home.join(".config"), home.join(".config/Claude")] {
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700,
            "new parent directory {} must be exactly owner-only",
            directory.display()
        );
    }
    let retained_stage_exists = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".fastmcp-stage-")
        });
    assert!(
        !retained_stage_exists,
        "a successful publication must not leave a staging name behind"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_refuses_unsupported_per_server_fields_consistently_with_list() {
    let home = mktemp_home("install-extension-cwd");
    let path = claude_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());
    let original = br#"{
        "mcpServers": {
            "my-server": {
                "command": "/old/server",
                "args": ["--old"],
                "cwd": "/old/cwd",
                "clientExtension": {"transportHint": "keep-me"}
            }
        },
        "clientRootExtension": true
    }"#;
    write_secure_config_fixture(&path, original);

    let output = run_cli_with_home(
        &home,
        &[
            "install",
            "-C",
            "/srv/my-server",
            "my-server",
            "/bin/echo",
            "--target",
            "claude",
        ],
    );

    assert!(!output.status.success());
    assert!(
        stderr_str(&output).contains("unsupported or malformed per-server fields"),
        "stderr: {}",
        stderr_str(&output)
    );
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(!PathBuf::from(format!("{}.bak", path.display())).exists());

    let list = run_cli_with_home(&home, &["list", "--target", "claude", "--format", "json"]);
    assert!(!list.status.success());
    assert!(stderr_str(&list).contains("schema validation failed"));
    assert!(list.stdout.is_empty(), "failed list output must be atomic");
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_rejects_read_only_config_without_mutation() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = mktemp_home("install-read-only");
    let path = claude_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());
    let original = br#"{"mcpServers":{"existing":{"command":"x"}}}"#;
    write_secure_config_fixture(&path, original);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );

    assert!(!output.status.success());
    assert!(stderr_str(&output).contains("read-only"));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(!PathBuf::from(format!("{}.bak", path.display())).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_rejects_symlink_config_without_mutating_target() {
    use std::os::unix::fs::symlink;

    let home = mktemp_home("install-symlink");
    let path = claude_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());
    let target = home.join("real-config.json");
    let original = br#"{"mcpServers":{"existing":{"command":"x"}}}"#;
    write_secure_config_fixture(&target, original);
    symlink(&target, &path).unwrap();

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );

    assert!(!output.status.success());
    assert!(stderr_str(&output).contains("symbolic links are not accepted"));
    assert_eq!(std::fs::read(&target).unwrap(), original);
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!PathBuf::from(format!("{}.bak", path.display())).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_invalid_json_fails_cleanly() {
    const SECRET: &str = "INSTALL_JSON_CREDENTIAL_MUST_NOT_LEAK";

    let home = mktemp_home("install-invalid-json");
    let path = claude_path(&home);
    create_secure_fixture_directory(&home, path.parent().unwrap());

    write_secure_config_fixture(
        &path,
        format!(r#"{{"mcpServers":{{"bad":{{"command":"{SECRET}""#),
    );

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );
    assert!(!output.status.success(), "expected non-zero exit");

    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("config") || stderr.contains("JSON") || stderr.contains("parse"),
        "expected metadata-only parse error (stderr={} bytes; content redacted)",
        stderr.len()
    );
    assert!(!stderr.contains(SECRET));
    assert!(stderr.contains("category:"));
    assert!(stderr.contains("line:"));
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_dry_run_redacts_arguments_and_sanitizes_names_and_paths() {
    const POSITIONAL_SECRET: &str = "DRY_RUN_POSITIONAL_CREDENTIAL_MUST_NOT_LEAK";
    const ATTACHED_SECRET: &str = "DRY_RUN_ATTACHED_CREDENTIAL_MUST_NOT_LEAK";
    const SHORT_SECRET: &str = "DRY_RUN_SHORT_CREDENTIAL_MUST_NOT_LEAK";

    let home = mktemp_home("install-dry-control-\u{1b}[31m");
    let output = run_cli_with_home(
        &home,
        &[
            "install",
            "--dry-run",
            "--target",
            "claude",
            "preview-\u{1b}[32m",
            "/bin/echo",
            "--",
            POSITIONAL_SECRET,
            "--token=DRY_RUN_ATTACHED_CREDENTIAL_MUST_NOT_LEAK",
            "-HDRY_RUN_SHORT_CREDENTIAL_MUST_NOT_LEAK",
        ],
    );
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = stdout_str(&output);
    for secret in [POSITIONAL_SECRET, ATTACHED_SECRET, SHORT_SECRET] {
        assert!(!stdout.contains(secret));
    }
    assert!(!stdout.contains('\u{1b}'));
    assert!(stdout.contains("\\x1B"));
    assert!(stdout.len() < 24 * 1024);

    let json_start = stdout.find('{').expect("dry-run JSON object");
    let preview: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("parse dry-run JSON");
    let server = preview["mcpServers"]
        .as_object()
        .and_then(|servers| servers.values().next())
        .expect("one preview server");
    assert_eq!(
        server["args"],
        serde_json::json!(["<redacted>", "--<option>=<redacted>", "-<option><redacted>"])
    );
    assert!(server.get("cwd").is_none());

    let path = claude_path(&home);
    assert!(!path.exists(), "dry-run must not create a config file");
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_success_sanitizes_and_bounds_name_and_path() {
    let home = mktemp_home("install-success-control-\u{1b}[31m");
    let server_name = format!("name-\u{1b}[32m-{}", "x".repeat(8 * 1024));

    let output = run_cli_with_home(
        &home,
        &["install", &server_name, "/bin/echo", "--target", "claude"],
    );
    assert!(output.status.success());
    let stderr = stderr_str(&output);
    assert!(stderr.contains("owner-only parent directories"));
    assert!(!stderr.contains('\u{1b}'));
    let stdout = stdout_str(&output);
    assert!(!stdout.contains('\u{1b}'));
    assert!(stdout.contains("\\x1B"));
    assert!(stdout.contains("...[truncated]"));
    assert!(stdout.len() < 16 * 1024);

    let config: serde_json::Value =
        serde_json::from_str(&read_to_string(&claude_path(&home))).unwrap();
    assert!(
        config["mcpServers"]
            .as_object()
            .is_some_and(|servers| servers.contains_key(&server_name))
    );
}
