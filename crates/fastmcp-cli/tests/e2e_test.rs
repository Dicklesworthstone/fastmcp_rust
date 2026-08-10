//! E2E tests for `fastmcp test`.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, ExitStatus, Stdio};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

const CLI_DEADLINE: Duration = Duration::from_secs(120);
const CAPTURE_DRAIN_DEADLINE: Duration = Duration::from_secs(1);
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const PROCESS_CLEANUP_DEADLINE: Duration = Duration::from_secs(2);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
const PROCESS_TERM_GRACE: Duration = Duration::from_millis(500);
const FORBIDDEN_CONTACT_WORK_CAP: usize = 16;
const FORBIDDEN_CONTACT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const FORBIDDEN_CONTACT_FINAL_QUIET_INTERVAL: Duration = Duration::from_millis(20);
const FORBIDDEN_CONTACT_FINAL_DRAIN_DEADLINE: Duration = Duration::from_millis(250);
const FORBIDDEN_CONTACT_SHUTDOWN_ACK_DEADLINE: Duration = Duration::from_millis(500);
const LOOPBACK_FIXTURE_DEADLINE: Duration = Duration::from_secs(2);
const LOOPBACK_FIXTURE_ACK_DEADLINE: Duration = Duration::from_millis(2500);
const LOOPBACK_FIXTURE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const STATIC_MCP_SERVER_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/static_mcp_server.sh"
);
const INSPECT_PROTOCOL_WIRE_PREFIX: &str = "FASTMCP_E2E_WIRE ";

const MODERN_INSPECT_FIXTURE: &str = r#"
emit_wire() {
    printf 'FASTMCP_E2E_WIRE %s\n' "$1" >&2
}

is_exact_modern_discovery() {
    printf '%s\n' "$1" | grep -Eq '^\{"jsonrpc":"2\.0","method":"server/discover","params":\{"_meta":\{"io\.modelcontextprotocol/clientCapabilities":\{\},"io\.modelcontextprotocol/clientInfo":\{"name":"[^"]*","version":"[^"]*"\},"io\.modelcontextprotocol/protocolVersion":"2026-07-28"\}\},"id":1\}$' || return 1
}

while IFS= read -r request; do
    emit_wire "$request"
    is_exact_modern_discovery "$request" || exit 1
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"_meta":{"serverInfo":{"name":"modern-inspect-server","version":"1.0.0"}},"ttlMs":0,"cacheScope":"private"}}'
done
"#;

const LEGACY_FALLBACK_INSPECT_FIXTURE: &str = r#"
emit_wire() {
    printf 'FASTMCP_E2E_WIRE %s\n' "$1" >&2
}

require_no_final_metadata() {
    case "$1" in
        *'io.modelcontextprotocol/protocolVersion'*|*'io.modelcontextprotocol/clientCapabilities'*|*'io.modelcontextprotocol/clientInfo'*|*'io.modelcontextprotocol/serverInfo'*|*'io.modelcontextprotocol/subscriptionId'*)
            return 1
            ;;
    esac
}

is_exact_modern_discovery() {
    printf '%s\n' "$1" | grep -Eq '^\{"jsonrpc":"2\.0","method":"server/discover","params":\{"_meta":\{"io\.modelcontextprotocol/clientCapabilities":\{\},"io\.modelcontextprotocol/clientInfo":\{"name":"[^"]*","version":"[^"]*"\},"io\.modelcontextprotocol/protocolVersion":"2026-07-28"\}\},"id":1\}$' || return 1
}

is_exact_legacy_initialize() {
    printf '%s\n' "$1" | grep -Eq '^\{"jsonrpc":"2\.0","method":"initialize","params":\{"protocolVersion":"2024-11-05","capabilities":\{\},"clientInfo":\{"name":"[^"]*","version":"[^"]*"\}\},"id":[0-9]+\}$' || return 1
    require_no_final_metadata "$1"
}

is_exact_legacy_initialized_notification() {
    [ "$1" = '{"jsonrpc":"2.0","method":"notifications/initialized"}' ] || return 1
    require_no_final_metadata "$1"
}

is_exact_legacy_operating_request() {
    printf '%s\n' "$1" | grep -Eq '^\{"jsonrpc":"2\.0","method":"(tools/list|resources/list|resources/templates/list|prompts/list)","params":\{\},"id":[0-9]+\}$' || return 1
    require_no_final_metadata "$1"
}

respond() {
    printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$request_id" "$1"
}

respond_method_not_found() {
    printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Method not found"}}\n' "$request_id"
}

require_request_id() {
    request_id=$(printf '%s\n' "$1" | sed -n 's/.*"id":[[:space:]]*\([0-9][0-9]*\).*/\1/p')
    case "$request_id" in
        '' | *[!0-9]*) return 1 ;;
    esac
}

state=awaiting_initialize
while IFS= read -r request; do
    emit_wire "$request"

    case "$state" in
        awaiting_initialize)
            require_request_id "$request" || exit 1
            case "$request" in
                *'"method":"server/discover"'*)
                    is_exact_modern_discovery "$request" || exit 1
                    respond_method_not_found
                    exit 0
                    ;;
                *'"method":"initialize"'*)
                    is_exact_legacy_initialize "$request" || exit 1
                    respond '{"protocolVersion":"2024-11-05","capabilities":{"tools":{},"resources":{},"prompts":{}},"serverInfo":{"name":"legacy-inspect-server","version":"1.0.0"}}'
                    state=awaiting_initialized_notification
                    ;;
                *) exit 1 ;;
            esac
            ;;
        awaiting_initialized_notification)
            is_exact_legacy_initialized_notification "$request" || exit 1
            state=operating
            ;;
        operating)
            is_exact_legacy_operating_request "$request" || exit 1
            case "$request" in
                *'"method":"tools/list"'*)
                    respond '{"tools":[]}'
                    ;;
                *'"method":"resources/list"'*)
                    respond '{"resources":[]}'
                    ;;
                *'"method":"resources/templates/list"'*)
                    respond '{"resourceTemplates":[]}'
                    ;;
                *'"method":"prompts/list"'*)
                    respond '{"prompts":[]}'
                    ;;
                *) exit 1 ;;
            esac
            ;;
        *) exit 1 ;;
    esac
done
"#;

const LEGACY_PLANTED_INITIALIZE_REQUEST: &str = r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"planted-legacy-client","version":"1.0.0"}},"id":1}"#;
const LEGACY_PLANTED_REPEATED_INITIALIZE_REQUEST: &str = r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"planted-legacy-client","version":"1.0.0"}},"id":2}"#;
const LEGACY_PLANTED_INITIALIZED_NOTIFICATION: &str =
    r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const LEGACY_PLANTED_TOOLS_LIST_REQUEST: &str =
    r#"{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}"#;

const UNAUTHORIZED_DISCOVERY_REJECTION_INSPECT_FIXTURE: &str = r#"
emit_wire() {
    printf 'FASTMCP_E2E_WIRE %s\n' "$1" >&2
}

is_exact_modern_discovery() {
    printf '%s\n' "$1" | grep -Eq '^\{"jsonrpc":"2\.0","method":"server/discover","params":\{"_meta":\{"io\.modelcontextprotocol/clientCapabilities":\{\},"io\.modelcontextprotocol/clientInfo":\{"name":"[^"]*","version":"[^"]*"\},"io\.modelcontextprotocol/protocolVersion":"2026-07-28"\}\},"id":1\}$' || return 1
}

while IFS= read -r request; do
    emit_wire "$request"
    is_exact_modern_discovery "$request" || exit 1
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"final discovery rejected"}}'
    exit 0
done
"#;

fn fastmcp_bin() -> String {
    env!("CARGO_BIN_EXE_fastmcp").to_string()
}

fn stdout_str(output: &Output) -> String {
    std::str::from_utf8(&output.stdout)
        .expect("fastmcp test stdout must be valid UTF-8")
        .to_owned()
}

fn stderr_str(output: &Output) -> String {
    std::str::from_utf8(&output.stderr)
        .expect("fastmcp test stderr must be valid UTF-8")
        .to_owned()
}

fn observed_protocol_wire(output: &Output) -> Vec<serde_json::Value> {
    stderr_str(output)
        .lines()
        .filter_map(|line| line.strip_prefix(INSPECT_PROTOCOL_WIRE_PREFIX))
        .map(|request| {
            serde_json::from_str(request)
                .unwrap_or_else(|error| panic!("fixture must record valid JSON-RPC wire: {error}"))
        })
        .collect()
}

fn request_method(request: &serde_json::Value) -> &str {
    request
        .get("method")
        .and_then(serde_json::Value::as_str)
        .expect("recorded wire message must have a method")
}

fn assert_no_final_metadata(request: &serde_json::Value) {
    let encoded = serde_json::to_string(request).expect("recorded wire must serialize");
    for final_metadata_key in [
        "io.modelcontextprotocol/protocolVersion",
        "io.modelcontextprotocol/clientCapabilities",
        "io.modelcontextprotocol/clientInfo",
        "io.modelcontextprotocol/serverInfo",
        "io.modelcontextprotocol/subscriptionId",
    ] {
        assert!(
            !encoded.contains(final_metadata_key),
            "legacy wire must not carry {final_metadata_key}"
        );
    }
}

fn assert_exact_modern_discovery_request(request: &serde_json::Value) {
    assert_eq!(
        request
            .as_object()
            .expect("modern discovery must be a JSON object")
            .len(),
        4,
        "modern discovery must contain only JSON-RPC envelope fields"
    );
    assert_eq!(request["jsonrpc"], "2.0");
    assert_eq!(request_method(request), "server/discover");
    assert_eq!(request["id"], 1);
    let params = request["params"]
        .as_object()
        .expect("modern discovery must carry object params");
    assert_eq!(
        params.len(),
        1,
        "modern discovery params must contain only _meta"
    );
    let metadata = params["_meta"]
        .as_object()
        .expect("modern discovery must carry request metadata");
    assert_eq!(
        metadata.len(),
        3,
        "modern discovery metadata must contain only final protocol fields"
    );
    assert_eq!(
        metadata["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
    assert!(
        metadata
            .get("io.modelcontextprotocol/clientCapabilities")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|capabilities| capabilities.is_empty()),
        "modern discovery must carry exactly the empty final client capabilities object"
    );
    let client_info = metadata
        .get("io.modelcontextprotocol/clientInfo")
        .and_then(serde_json::Value::as_object)
        .expect("modern discovery must carry final client info object");
    assert_eq!(
        client_info.len(),
        2,
        "modern discovery client info must contain only name and version"
    );
    assert!(
        client_info
            .get("name")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "modern discovery client info name must be a string"
    );
    assert!(
        client_info
            .get("version")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "modern discovery client info version must be a string"
    );
}

fn assert_exact_legacy_initialize_request(request: &serde_json::Value) {
    assert_eq!(
        request
            .as_object()
            .expect("legacy initialize must be a JSON object")
            .len(),
        4,
        "legacy initialize must contain only JSON-RPC envelope fields"
    );
    assert_eq!(request["jsonrpc"], "2.0");
    assert_eq!(request_method(request), "initialize");
    assert!(
        request.get("id").is_some_and(serde_json::Value::is_number),
        "legacy initialize must carry a numeric JSON-RPC request ID"
    );
    let params = request["params"]
        .as_object()
        .expect("legacy initialize must carry params");
    assert_eq!(
        params.len(),
        3,
        "legacy initialize must contain exactly its three legacy fields"
    );
    assert_eq!(
        params
            .get("protocolVersion")
            .and_then(serde_json::Value::as_str),
        Some("2024-11-05"),
        "legacy initialize must carry the exact protocol version string"
    );
    assert!(
        params
            .get("capabilities")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|capabilities| capabilities.is_empty()),
        "legacy initialize must carry exactly the empty legacy capabilities object"
    );
    let client_info = params
        .get("clientInfo")
        .and_then(serde_json::Value::as_object)
        .expect("legacy initialize clientInfo must be an object");
    assert_eq!(
        client_info.len(),
        2,
        "legacy clientInfo must contain only name and version"
    );
    assert!(
        client_info
            .get("name")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "legacy clientInfo.name must be a string"
    );
    assert!(
        client_info
            .get("version")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "legacy clientInfo.version must be a string"
    );
    assert!(
        !params.contains_key("_meta"),
        "legacy initialize must not carry final metadata"
    );
    assert_no_final_metadata(request);
}

fn assert_exact_legacy_initialized_notification_request(request: &serde_json::Value) {
    assert_eq!(
        request
            .as_object()
            .expect("legacy initialized notification must be a JSON object")
            .len(),
        2,
        "legacy initialized notification must contain only JSON-RPC envelope fields"
    );
    assert_eq!(request["jsonrpc"], "2.0");
    assert_eq!(request_method(request), "notifications/initialized");
    assert!(
        request.get("id").is_none(),
        "legacy initialized notification must not have an ID"
    );
    assert!(
        request.get("params").is_none(),
        "legacy initialized notification must not have params"
    );
    assert_no_final_metadata(request);
}

fn assert_exact_legacy_operating_request(request: &serde_json::Value) {
    assert_eq!(
        request
            .as_object()
            .expect("legacy operating request must be a JSON object")
            .len(),
        4,
        "legacy operating request must contain only JSON-RPC envelope fields"
    );
    assert_eq!(request["jsonrpc"], "2.0");
    assert!(
        matches!(
            request_method(request),
            "tools/list" | "resources/list" | "resources/templates/list" | "prompts/list"
        ),
        "legacy inspect must issue only operating list requests after initialization"
    );
    assert!(
        request.get("id").is_some_and(serde_json::Value::is_number),
        "legacy operating request must carry a numeric JSON-RPC request ID"
    );
    assert!(
        request
            .get("params")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|params| params.is_empty()),
        "legacy operating request must carry exactly an empty params object"
    );
    assert_no_final_metadata(request);
}

fn assert_no_legacy_initialize(wire: &[serde_json::Value]) {
    assert!(
        wire.iter()
            .all(|request| request_method(request) != "initialize"),
        "a failed modern negotiation must not send a legacy initialize request"
    );
}

fn assert_modern_negotiation_wire(wire: &[serde_json::Value]) {
    assert_eq!(
        wire.len(),
        1,
        "modern inspect must send exactly one discovery request"
    );
    assert_exact_modern_discovery_request(&wire[0]);
}

fn assert_legacy_lifecycle_wire(wire: &[serde_json::Value]) {
    assert_eq!(
        wire.iter().map(request_method).collect::<Vec<_>>(),
        vec![
            "initialize",
            "notifications/initialized",
            "tools/list",
            "resources/list",
            "resources/templates/list",
            "prompts/list",
        ],
        "legacy inspect must run initialize, notification, then its operating requests exactly once"
    );
    assert_exact_legacy_initialize_request(&wire[0]);
    assert_exact_legacy_initialized_notification_request(&wire[1]);
    for request in &wire[2..] {
        assert_exact_legacy_operating_request(request);
    }
}

fn assert_legacy_negotiation_wire(wire: &[serde_json::Value]) {
    assert_legacy_lifecycle_wire(wire);
}

fn assert_auto_legacy_fallback_wire(wire: &[serde_json::Value]) {
    assert_eq!(
        request_method(
            wire.first()
                .expect("Auto fallback must record a modern discovery request"),
        ),
        "server/discover"
    );
    assert_exact_modern_discovery_request(&wire[0]);
    assert_legacy_lifecycle_wire(&wire[1..]);
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

fn fixture_wait(deadline: Instant, context: &str) -> Duration {
    let wait = deadline.saturating_duration_since(Instant::now());
    assert!(
        !wait.is_zero(),
        "loopback fixture deadline elapsed while {context}"
    );
    wait.min(LOOPBACK_FIXTURE_POLL_INTERVAL)
}

fn accept_h1_fixture_connection(
    listener: &TcpListener,
    deadline: Instant,
    context: &str,
) -> TcpStream {
    listener
        .set_nonblocking(true)
        .expect("make loopback fixture listener nonblocking");
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::park_timeout(fixture_wait(deadline, context));
            }
            Err(error) => panic!("{context}: accept loopback HTTP connection: {error}"),
        }
    }
}

fn read_h1_fixture_chunk(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
    context: &str,
) -> usize {
    loop {
        stream
            .set_read_timeout(Some(fixture_wait(deadline, context)))
            .expect("set loopback fixture read timeout");
        match stream.read(buffer) {
            Ok(read) => return read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => panic!("{context}: read loopback HTTP request: {error}"),
        }
    }
}

fn configure_h1_fixture_write(stream: &TcpStream, deadline: Instant, context: &str) {
    stream
        .set_write_timeout(Some(fixture_wait(deadline, context)))
        .expect("set loopback fixture write timeout");
}

fn read_h1_json_request(stream: &mut TcpStream, deadline: Instant) -> (String, serde_json::Value) {
    let mut wire = Vec::new();
    let mut buffer = [0_u8; 4_096];
    let head_end = loop {
        let read = read_h1_fixture_chunk(stream, &mut buffer, deadline, "read HTTP request head");
        assert!(read > 0, "HTTP client closed before a complete request");
        wire.extend_from_slice(&buffer[..read]);
        if let Some(position) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = std::str::from_utf8(&wire[..head_end])
        .expect("HTTP fixture request head is UTF-8")
        .to_owned();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("HTTP fixture content length is numeric")
            })
        })
        .expect("HTTP fixture request has a content length");
    while wire.len() < head_end + content_length {
        let read = read_h1_fixture_chunk(stream, &mut buffer, deadline, "read HTTP request body");
        assert!(
            read > 0,
            "HTTP client closed before its complete request body"
        );
        wire.extend_from_slice(&buffer[..read]);
    }
    let body = serde_json::from_slice(&wire[head_end..head_end + content_length])
        .expect("HTTP fixture request body is JSON-RPC");
    (head, body)
}

fn write_h1_json_response(stream: &mut TcpStream, deadline: Instant, body: &str) {
    write_h1_json_response_with_status(stream, deadline, 200, body);
}

fn write_h1_json_response_with_status(
    stream: &mut TcpStream,
    deadline: Instant,
    status: u16,
    body: &str,
) {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Test Response",
    };
    configure_h1_fixture_write(stream, deadline, "write HTTP JSON response");
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .expect("write HTTP fixture response head");
    stream
        .write_all(body.as_bytes())
        .expect("write HTTP fixture response body");
    stream.flush().expect("flush HTTP fixture response");
}

#[cfg(feature = "legacy-2024-11-05")]
fn read_h1_request_head(stream: &mut TcpStream, deadline: Instant) -> String {
    let mut wire = Vec::new();
    let mut buffer = [0_u8; 4_096];
    while !wire.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = read_h1_fixture_chunk(stream, &mut buffer, deadline, "read HTTP request head");
        assert!(read > 0, "HTTP client closed before its request head");
        wire.extend_from_slice(&buffer[..read]);
    }
    std::str::from_utf8(&wire)
        .expect("HTTP fixture request head is UTF-8")
        .to_owned()
}

#[cfg(feature = "legacy-2024-11-05")]
fn write_h1_empty_response(stream: &mut TcpStream, deadline: Instant, status: u16) {
    let reason = match status {
        202 => "Accepted",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Test Response",
    };
    configure_h1_fixture_write(stream, deadline, "write empty HTTP response");
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .expect("write empty HTTP fixture response head");
    stream.flush().expect("flush empty HTTP fixture response");
}

#[cfg(feature = "legacy-2024-11-05")]
fn begin_h1_chunked_sse(stream: &mut TcpStream, deadline: Instant) {
    configure_h1_fixture_write(stream, deadline, "write chunked SSE response");
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
        )
        .expect("write chunked legacy SSE response head");
    stream
        .flush()
        .expect("flush chunked legacy SSE response head");
}

#[cfg(feature = "legacy-2024-11-05")]
fn write_h1_chunked_sse_event(stream: &mut TcpStream, deadline: Instant, event: &str) {
    configure_h1_fixture_write(stream, deadline, "write chunked SSE event");
    write!(stream, "{:X}\r\n{event}\r\n", event.len()).expect("write chunked legacy SSE event");
    stream.flush().expect("flush chunked legacy SSE event");
}

#[cfg(feature = "legacy-2024-11-05")]
fn serve_legacy_http_inspect_bundle(
    listener: TcpListener,
    deadline: Instant,
    modern_probe_status: Option<u16>,
    advertised_message_target: String,
) {
    if let Some(status) = modern_probe_status {
        let mut modern =
            accept_h1_fixture_connection(&listener, deadline, "accept modern HTTP probe");
        let (head, request) = read_h1_json_request(&mut modern, deadline);
        assert!(
            head.starts_with("POST /mcp HTTP/1.1\r\n"),
            "Auto must contact the configured modern POST endpoint first"
        );
        assert_eq!(request["id"], 1);
        assert_eq!(request["method"], "server/discover");
        write_h1_empty_response(&mut modern, deadline, status);
    }

    let mut sse = accept_h1_fixture_connection(&listener, deadline, "accept legacy SSE GET");
    let sse_head = read_h1_request_head(&mut sse, deadline);
    assert!(
        sse_head.starts_with("GET /legacy-sse HTTP/1.1\r\n"),
        "the first legacy contact must use the configured SSE endpoint"
    );
    assert!(
        !sse_head.contains("MCP-Protocol-Version:"),
        "the exact legacy SSE GET must not carry final headers"
    );
    begin_h1_chunked_sse(&mut sse, deadline);
    write_h1_chunked_sse_event(
        &mut sse,
        deadline,
        &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
    );

    for (expected_method, response) in [
        (
            "initialize",
            Some(
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"legacy-h1-inspect","version":"1.0.0"}}}"#,
            ),
        ),
        ("notifications/initialized", None),
        (
            "tools/list",
            Some(
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"legacy-h1-tool","description":"legacy H1 catalog","inputSchema":{"type":"object"}}]}}"#,
            ),
        ),
    ] {
        let mut message = accept_h1_fixture_connection(
            &listener,
            deadline,
            "accept configured legacy message POST",
        );
        let (head, request) = read_h1_json_request(&mut message, deadline);
        assert!(
            head.starts_with("POST /legacy-message HTTP/1.1\r\n"),
            "legacy request must retain the configured message POST endpoint"
        );
        assert_eq!(request["method"], expected_method);
        assert!(
            request
                .get("params")
                .and_then(serde_json::Value::as_object)
                .is_none_or(|params| !params.contains_key("_meta")),
            "legacy wire must not carry final metadata"
        );
        write_h1_empty_response(&mut message, deadline, 202);
        if let Some(response) = response {
            write_h1_chunked_sse_event(
                &mut sse,
                deadline,
                &format!("event: message\ndata: {response}\n\n"),
            );
        }
    }
}

struct LoopbackFixture {
    completion: mpsc::Receiver<Result<(), String>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Drop for LoopbackFixture {
    fn drop(&mut self) {
        let Some(worker) = self.worker.take() else {
            return;
        };
        // Fixture I/O has a finite deadline. Even an assertion failure in the
        // owning test must retain and join the worker rather than detach it.
        let _ = self.completion.recv_timeout(LOOPBACK_FIXTURE_ACK_DEADLINE);
        let _ = worker.join();
    }
}

fn spawn_loopback_fixture<F>(context: &'static str, fixture: F) -> LoopbackFixture
where
    F: FnOnce(Instant) + Send + 'static,
{
    spawn_loopback_fixture_with_deadline(context, LOOPBACK_FIXTURE_DEADLINE, fixture)
}

fn spawn_loopback_fixture_with_deadline<F>(
    context: &'static str,
    timeout: Duration,
    fixture: F,
) -> LoopbackFixture
where
    F: FnOnce(Instant) + Send + 'static,
{
    let (completed, completion) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + timeout;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture(deadline)))
            .map_err(|_| format!("{context} panicked"));
        // This acknowledgement is the worker's final action. Once the
        // bounded receipt arrives, joining cannot wait on fixture work.
        let _ = completed.send(result);
    });
    LoopbackFixture {
        completion,
        worker: Some(worker),
    }
}

fn wait_for_loopback_fixture(mut fixture: LoopbackFixture, context: &str) {
    let completion = fixture
        .completion
        .recv_timeout(LOOPBACK_FIXTURE_ACK_DEADLINE)
        .unwrap_or_else(|error| panic!("{context} did not acknowledge completion: {error}"));
    fixture
        .worker
        .take()
        .expect("loopback fixture worker must be retained until joined")
        .join()
        .unwrap_or_else(|_| panic!("{context} worker must join after completion acknowledgement"));
    completion.unwrap_or_else(|error| panic!("{context} failed: {error}"));
}

#[test]
fn loopback_fixture_timeout_acknowledges_before_settled_join() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback timeout fixture");
    let started = Instant::now();
    let mut fixture = spawn_loopback_fixture_with_deadline(
        "loopback timeout fixture",
        Duration::from_millis(30),
        move |deadline| {
            let _ =
                accept_h1_fixture_connection(&listener, deadline, "accept absent loopback client");
        },
    );

    let completion = fixture
        .completion
        .recv_timeout(Duration::from_millis(250))
        .expect("timed-out loopback fixture must acknowledge completion");
    fixture
        .worker
        .take()
        .expect("timed-out loopback fixture worker must be retained until joined")
        .join()
        .expect("timed-out loopback fixture must join after acknowledgement");
    assert!(
        completion.is_err(),
        "absent loopback client must fail the fixture"
    );
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "absent loopback client must fail within the fixture deadline"
    );
}

#[test]
fn loopback_fixture_drop_joins_an_abandoned_bounded_worker() {
    let completed = Arc::new(AtomicBool::new(false));
    let worker_completed = Arc::clone(&completed);
    let fixture = spawn_loopback_fixture_with_deadline(
        "abandoned loopback fixture",
        Duration::from_millis(250),
        move |_| {
            std::thread::park_timeout(Duration::from_millis(40));
            worker_completed.store(true, Ordering::SeqCst);
        },
    );

    drop(fixture);
    assert!(
        completed.load(Ordering::SeqCst),
        "dropping a fixture must join its bounded worker instead of detaching it"
    );
}

#[cfg(feature = "legacy-2024-11-05")]
fn inspect_http_bundle(
    policy: &str,
    modern_url: &str,
    legacy_sse_url: &str,
    legacy_message_url: &str,
) -> Output {
    run_cli(&[
        "inspect",
        "--http-url",
        modern_url,
        "--legacy-sse-url",
        legacy_sse_url,
        "--legacy-message-url",
        legacy_message_url,
        "--protocol-policy",
        policy,
        "--format",
        "json",
    ])
}

struct ForbiddenHttpContactObserver {
    shutdown: Option<mpsc::Sender<()>>,
    completion: Option<mpsc::Receiver<Result<(), String>>>,
    observer: Option<std::thread::JoinHandle<()>>,
}

impl Drop for ForbiddenHttpContactObserver {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(completion) = self.completion.take() {
            let _ = completion.recv_timeout(FORBIDDEN_CONTACT_SHUTDOWN_ACK_DEADLINE);
        }
        if let Some(observer) = self.observer.take() {
            let _ = observer.join();
        }
    }
}

struct ForbiddenContactFinalDrainControl {
    started: mpsc::Sender<()>,
    permit: mpsc::Receiver<()>,
}

fn observer_shutdown_requested(shutdown_requested: &mpsc::Receiver<()>) -> bool {
    matches!(
        shutdown_requested.try_recv(),
        Ok(()) | Err(mpsc::TryRecvError::Disconnected)
    )
}

fn drain_forbidden_http_contacts_after_shutdown(
    listener: &TcpListener,
    contacts: &AtomicUsize,
    context: &str,
    shutdown_requested: &mpsc::Receiver<()>,
) -> Result<(), String> {
    let final_deadline = Instant::now() + FORBIDDEN_CONTACT_FINAL_DRAIN_DEADLINE;
    let mut quiet_deadline = Instant::now() + FORBIDDEN_CONTACT_FINAL_QUIET_INTERVAL;

    loop {
        for _ in 0..FORBIDDEN_CONTACT_WORK_CAP {
            match listener.accept() {
                Ok((_stream, _)) => {
                    contacts.fetch_add(1, Ordering::SeqCst);
                    quiet_deadline = Instant::now() + FORBIDDEN_CONTACT_FINAL_QUIET_INTERVAL;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    return Err(format!(
                        "observe forbidden {context} contact during shutdown: {error}"
                    ));
                }
            }
        }

        let now = Instant::now();
        if now >= quiet_deadline || now >= final_deadline {
            return Ok(());
        }
        let wait = quiet_deadline
            .min(final_deadline)
            .saturating_duration_since(now)
            .min(FORBIDDEN_CONTACT_POLL_INTERVAL);
        match shutdown_requested.recv_timeout(wait) {
            Ok(())
            | Err(mpsc::RecvTimeoutError::Disconnected)
            | Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

fn observe_forbidden_http_contacts(
    listener: TcpListener,
    contacts: Arc<AtomicUsize>,
    context: &'static str,
    shutdown_requested: &mpsc::Receiver<()>,
    final_drain_control: Option<ForbiddenContactFinalDrainControl>,
) -> Result<(), String> {
    'observe: loop {
        if observer_shutdown_requested(shutdown_requested) {
            break;
        }

        for _ in 0..FORBIDDEN_CONTACT_WORK_CAP {
            if observer_shutdown_requested(shutdown_requested) {
                break 'observe;
            }
            match listener.accept() {
                Ok((_stream, _)) => {
                    contacts.fetch_add(1, Ordering::SeqCst);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(format!("observe forbidden {context} contact: {error}")),
            }
        }

        match shutdown_requested.recv_timeout(FORBIDDEN_CONTACT_POLL_INTERVAL) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }

    if let Some(control) = final_drain_control {
        control
            .started
            .send(())
            .map_err(|_| format!("forbidden {context} final drain control was dropped"))?;
        control
            .permit
            .recv_timeout(FORBIDDEN_CONTACT_SHUTDOWN_ACK_DEADLINE)
            .map_err(|error| {
                format!("forbidden {context} final drain was not permitted: {error}")
            })?;
    }
    drain_forbidden_http_contacts_after_shutdown(&listener, &contacts, context, shutdown_requested)
}

fn spawn_forbidden_http_contact_observer(
    listener: TcpListener,
    contacts: Arc<AtomicUsize>,
    context: &'static str,
) -> ForbiddenHttpContactObserver {
    spawn_forbidden_http_contact_observer_with_final_drain_control(
        listener, contacts, context, None,
    )
}

fn spawn_forbidden_http_contact_observer_with_final_drain_control(
    listener: TcpListener,
    contacts: Arc<AtomicUsize>,
    context: &'static str,
    final_drain_control: Option<ForbiddenContactFinalDrainControl>,
) -> ForbiddenHttpContactObserver {
    listener
        .set_nonblocking(true)
        .expect("make forbidden HTTP observer nonblocking");
    let (shutdown, shutdown_requested) = mpsc::channel();
    let (completed, completion) = mpsc::channel();
    let observer = std::thread::spawn(move || {
        let result = observe_forbidden_http_contacts(
            listener,
            contacts,
            context,
            &shutdown_requested,
            final_drain_control,
        );
        // The final drain has completed before this final worker action.
        let _ = completed.send(result);
    });
    ForbiddenHttpContactObserver {
        shutdown: Some(shutdown),
        completion: Some(completion),
        observer: Some(observer),
    }
}

fn stop_forbidden_http_contact_observer(mut observer: ForbiddenHttpContactObserver, context: &str) {
    let shutdown_result = observer
        .shutdown
        .take()
        .expect("forbidden HTTP observer shutdown sender must be retained")
        .send(());
    let completion = observer
        .completion
        .take()
        .expect("forbidden HTTP observer completion receiver must be retained")
        .recv_timeout(FORBIDDEN_CONTACT_SHUTDOWN_ACK_DEADLINE)
        .unwrap_or_else(|error| {
            panic!("forbidden {context} observer did not acknowledge shutdown: {error}")
        });
    observer
        .observer
        .take()
        .expect("forbidden HTTP observer worker must be retained until joined")
        .join()
        .unwrap_or_else(|_| panic!("forbidden {context} observer must complete"));
    shutdown_result.unwrap_or_else(|_| panic!("signal forbidden {context} observer shutdown"));
    completion.unwrap_or_else(|error| panic!("forbidden {context} observer failed: {error}"));
}

#[test]
fn forbidden_contact_observer_caps_continuous_contacts_and_drains_shutdown_queue() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind observer helper fixture");
    let address = listener
        .local_addr()
        .expect("read observer helper fixture address");
    let contacts = Arc::new(AtomicUsize::new(0));
    let (final_drain_started, final_drain_started_at) = mpsc::channel();
    let (permit_final_drain, final_drain_permit) = mpsc::channel();
    let mut observer = spawn_forbidden_http_contact_observer_with_final_drain_control(
        listener,
        Arc::clone(&contacts),
        "observer helper fixture",
        Some(ForbiddenContactFinalDrainControl {
            started: final_drain_started,
            permit: final_drain_permit,
        }),
    );

    let continuous_contact_count = FORBIDDEN_CONTACT_WORK_CAP * 2;
    let continuous_contacts = (0..continuous_contact_count)
        .map(|_| {
            TcpStream::connect_timeout(&address, FORBIDDEN_CONTACT_SHUTDOWN_ACK_DEADLINE)
                .expect("queue continuous observer contact")
        })
        .collect::<Vec<_>>();
    observer
        .shutdown
        .as_ref()
        .expect("observer helper shutdown sender must be retained")
        .send(())
        .expect("signal observer helper shutdown");
    final_drain_started_at
        .recv_timeout(FORBIDDEN_CONTACT_SHUTDOWN_ACK_DEADLINE)
        .expect("observer helper must acknowledge final-drain start");
    let shutdown_continuous_contact_count = FORBIDDEN_CONTACT_WORK_CAP * 2;
    let shutdown_continuous_contacts = (0..shutdown_continuous_contact_count)
        .map(|_| {
            TcpStream::connect_timeout(&address, FORBIDDEN_CONTACT_SHUTDOWN_ACK_DEADLINE)
                .expect("queue continuous observer contact during shutdown")
        })
        .collect::<Vec<_>>();
    let queued_at_shutdown =
        TcpStream::connect_timeout(&address, FORBIDDEN_CONTACT_SHUTDOWN_ACK_DEADLINE)
            .expect("queue observer contact after shutdown acknowledgement");
    permit_final_drain
        .send(())
        .expect("permit observer helper final drain");

    let completion = observer
        .completion
        .take()
        .expect("observer helper completion receiver must be retained")
        .recv_timeout(FORBIDDEN_CONTACT_SHUTDOWN_ACK_DEADLINE)
        .expect("observer helper must acknowledge shutdown completion");
    observer
        .observer
        .take()
        .expect("observer helper worker must be retained until joined")
        .join()
        .expect("observer helper must join after completion acknowledgement");
    completion.expect("observer helper final drain must succeed");
    assert_eq!(
        contacts.load(Ordering::SeqCst),
        continuous_contact_count + shutdown_continuous_contact_count + 1,
        "the capped observer must count continuous contacts and the contact queued at shutdown"
    );
    drop((
        continuous_contacts,
        shutdown_continuous_contacts,
        queued_at_shutdown,
    ));
}

fn inspect_protocol_fixture(policy: &str, format: &str, fixture: &str) -> Output {
    run_cli(&[
        "inspect",
        "--protocol-policy",
        policy,
        "--format",
        format,
        "/bin/sh",
        "--",
        "-c",
        fixture,
    ])
}

fn run_legacy_fixture_with_requests(requests: &[&str]) -> Output {
    let input = format!("{}\n", requests.join("\n"));
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("printf '%s' \"$1\" | /bin/sh -c \"$2\"")
        .arg("legacy-lifecycle-fixture")
        .arg(&input)
        .arg(LEGACY_FALLBACK_INSPECT_FIXTURE);
    run_with_deadline(command, Duration::from_secs(10))
        .expect("legacy lifecycle fixture must exit after its input closes")
}

fn run_modern_fixture_with_request(request: &str) -> Output {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("printf '%s\n' \"$1\" | /bin/sh -c \"$2\"")
        .arg("modern-discovery-fixture")
        .arg(request)
        .arg(MODERN_INSPECT_FIXTURE);
    run_with_deadline(command, Duration::from_secs(10))
        .expect("modern discovery fixture must exit after its input closes")
}

#[cfg(unix)]
#[test]
fn e2e_test_json_report_against_static_protocol_fixture() {
    // Use a deterministic stdio peer as the subprocess being tested.
    // This exercises:
    // - stdio subprocess spawning
    // - initialization
    // - ping
    // - tools/resources/prompts listing
    let output = run_cli(&[
        "test",
        "--json",
        "--idle-timeout",
        "30",
        "--absolute-timeout",
        "120",
        "/bin/sh",
        "--",
        STATIC_MCP_SERVER_FIXTURE,
    ]);

    assert!(output.status.success());

    let out = stdout_str(&output);
    let json: serde_json::Value = serde_json::from_str(&out).expect("parse test json");
    assert_eq!(json.get("success").and_then(|v| v.as_bool()), Some(true));
    let tests = json
        .get("tests")
        .and_then(|v| v.as_array())
        .expect("test results array");
    for (name, expected_details) in [
        ("initialize", "protocol 2024-11-05"),
        ("ping", "server responded"),
        ("list_tools", "4 tools"),
        ("list_resources", "2 resources"),
        ("list_prompts", "2 prompts"),
    ] {
        let result = tests
            .iter()
            .find(|test| test.get("name").and_then(|value| value.as_str()) == Some(name))
            .unwrap_or_else(|| panic!("test report must include {name}"));
        assert_eq!(
            result.get("success").and_then(serde_json::Value::as_bool),
            Some(true),
            "{name} must succeed"
        );
        assert_ne!(
            result.get("skipped").and_then(serde_json::Value::as_bool),
            Some(true),
            "{name} must exercise the peer instead of being skipped"
        );
        assert_eq!(
            result.get("details").and_then(serde_json::Value::as_str),
            Some(expected_details),
            "{name} must report the expected bounded result"
        );
    }
    assert!(json.get("total_duration_ms").is_some());
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn e2e_cli_inspect_protocol_policy_reports_selected_era_and_exact_version() {
    for (case_name, policy, fixture, expected_version, expected_era, assert_wire) in [
        (
            "modern-only",
            "modern-only",
            MODERN_INSPECT_FIXTURE,
            "2026-07-28",
            "modern-2026",
            assert_modern_negotiation_wire as fn(&[serde_json::Value]),
        ),
        (
            "auto-modern",
            "auto",
            MODERN_INSPECT_FIXTURE,
            "2026-07-28",
            "modern-2026",
            assert_modern_negotiation_wire,
        ),
        (
            "legacy-only",
            "legacy-only",
            LEGACY_FALLBACK_INSPECT_FIXTURE,
            "2024-11-05",
            "legacy-2024",
            assert_legacy_negotiation_wire,
        ),
        (
            "auto-legacy-fallback",
            "auto",
            LEGACY_FALLBACK_INSPECT_FIXTURE,
            "2024-11-05",
            "legacy-2024",
            assert_auto_legacy_fallback_wire,
        ),
    ] {
        let text_output = inspect_protocol_fixture(policy, "text", fixture);
        assert!(
            text_output.status.success(),
            "{policy} inspect text should succeed, stderr: {}",
            stderr_str(&text_output)
        );
        let expected_text =
            format!("Protocol: policy={policy} version={expected_version} era={expected_era}");
        let text = stdout_str(&text_output);
        assert_eq!(
            text.lines().find(|line| line.starts_with("Protocol: ")),
            Some(expected_text.as_str()),
            "{case_name} text inspect must emit the selected protocol triad exactly"
        );
        assert_wire(&observed_protocol_wire(&text_output));

        let json_output = inspect_protocol_fixture(policy, "json", fixture);
        assert!(
            json_output.status.success(),
            "{policy} inspect JSON should succeed, stderr: {}",
            stderr_str(&json_output)
        );
        let json: serde_json::Value =
            serde_json::from_str(&stdout_str(&json_output)).expect("inspect output should be JSON");
        assert_eq!(json["protocol"]["policy"], policy);
        assert_eq!(json["protocol"]["version"], expected_version);
        assert_eq!(json["protocol"]["era"], expected_era);
        assert_wire(&observed_protocol_wire(&json_output));
    }
}

#[test]
fn e2e_cli_inspect_http_bundle_modern_only_uses_live_modern_h1_and_negotiated_status_renderer() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind modern HTTP inspect fixture");
    let address = listener
        .local_addr()
        .expect("read modern HTTP inspect fixture address");
    let url = format!("http://{address}/mcp");
    let fixture = spawn_loopback_fixture("modern HTTP inspect fixture", move |deadline| {
        let mut stream = accept_h1_fixture_connection(
            &listener,
            deadline,
            "accept modern HTTP inspect connection",
        );
        let (head, request) = read_h1_json_request(&mut stream, deadline);
        assert!(
            head.starts_with("POST /mcp HTTP/1.1\r\n"),
            "inspect must use the configured modern H1 POST route"
        );
        assert_eq!(request["id"], 1);
        assert_eq!(request["method"], "server/discover");
        assert_eq!(
            request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        write_h1_json_response(
            &mut stream,
            deadline,
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"_meta":{"serverInfo":{"name":"modern-h1-inspect","version":"1.0.0"}},"ttlMs":0,"cacheScope":"private"}}"#,
        );

        let mut stream = accept_h1_fixture_connection(
            &listener,
            deadline,
            "accept modern HTTP tools-list connection",
        );
        let (head, request) = read_h1_json_request(&mut stream, deadline);
        assert!(
            head.starts_with("POST /mcp HTTP/1.1\r\n"),
            "inspect tools/list must retain the configured modern H1 POST route"
        );
        assert_eq!(request["id"], 2);
        assert_eq!(request["method"], "tools/list");
        assert_eq!(
            request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        write_h1_json_response(
            &mut stream,
            deadline,
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[{"name":"h1-tool","description":"modern H1 catalog","inputSchema":{"type":"object"}}],"ttlMs":0,"cacheScope":"private"}}"#,
        );
    });

    let output = run_cli(&[
        "inspect",
        "--http-url",
        &url,
        "--protocol-policy",
        "modern-only",
        "--format",
        "json",
    ]);
    assert!(
        output.status.success(),
        "modern HTTP inspect should succeed, stderr: {}",
        stderr_str(&output)
    );
    wait_for_loopback_fixture(fixture, "modern HTTP inspect fixture");

    let rendered: serde_json::Value =
        serde_json::from_str(&stdout_str(&output)).expect("inspect output is diagnostic JSON");
    assert_eq!(rendered["server"]["name"], "modern-h1-inspect");
    assert_eq!(rendered["protocol"]["policy"], "modern-only");
    assert_eq!(rendered["protocol"]["version"], "2026-07-28");
    assert_eq!(rendered["protocol"]["era"], "modern-2026");
    assert_eq!(rendered["tools"][0]["name"], "h1-tool");
}

#[cfg(not(feature = "legacy-2024-11-05"))]
#[test]
fn e2e_cli_no_default_auto_and_legacy_only_refuse_before_http_contact() {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("bind no-default feature-unavailable observer");
    let address = listener
        .local_addr()
        .expect("read no-default feature-unavailable observer address");
    let url = format!("http://{address}/mcp");
    let contacts = Arc::new(AtomicUsize::new(0));
    let observer = spawn_forbidden_http_contact_observer(
        listener,
        Arc::clone(&contacts),
        "no-default feature-unavailable HTTP",
    );

    for policy in ["auto", "legacy-only"] {
        let output = run_cli(&[
            "inspect",
            "--http-url",
            &url,
            "--protocol-policy",
            policy,
            "--format",
            "json",
        ]);
        assert!(
            !output.status.success(),
            "a no-default-features CLI must refuse {policy} before HTTP contact"
        );
        let stderr = stderr_str(&output);
        assert!(
            stderr.contains("FeatureUnavailable") && stderr.contains("legacy-2024-11-05"),
            "the no-default-features refusal for {policy} must name the compiled-out feature: {stderr}"
        );
    }

    stop_forbidden_http_contact_observer(observer, "no-default feature-unavailable HTTP");
    assert_eq!(
        contacts.load(Ordering::SeqCst),
        0,
        "Auto and LegacyOnly must fail before contacting the configured HTTP endpoint"
    );
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn e2e_cli_inspect_http_bundle_auto_keeps_modern_after_discovery_when_application_post_fails() {
    let modern_listener =
        TcpListener::bind("127.0.0.1:0").expect("bind Auto modern application fixture");
    let modern_address = modern_listener
        .local_addr()
        .expect("read Auto modern application fixture address");
    let legacy_listener =
        TcpListener::bind("127.0.0.1:0").expect("bind forbidden Auto legacy observer");
    let legacy_address = legacy_listener
        .local_addr()
        .expect("read forbidden Auto legacy observer address");
    let modern_url = format!("http://{modern_address}/mcp");
    let legacy_sse_url = format!("http://{legacy_address}/legacy-sse");
    let legacy_message_url = format!("http://{legacy_address}/legacy-message");
    let legacy_contacts = Arc::new(AtomicUsize::new(0));
    let legacy_observer = spawn_forbidden_http_contact_observer(
        legacy_listener,
        Arc::clone(&legacy_contacts),
        "Auto legacy",
    );
    let modern_fixture = spawn_loopback_fixture(
        "Auto modern application fixture",
        move |deadline| {
            let mut discovery = accept_h1_fixture_connection(
                &modern_listener,
                deadline,
                "accept Auto modern discovery POST",
            );
            let (head, request) = read_h1_json_request(&mut discovery, deadline);
            assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert_eq!(request["id"], 1);
            assert_eq!(request["method"], "server/discover");
            assert_eq!(
                request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
                "2026-07-28"
            );
            write_h1_json_response(
                &mut discovery,
                deadline,
                r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"_meta":{"serverInfo":{"name":"auto-modern-h1-inspect","version":"1.0.0"}},"ttlMs":0,"cacheScope":"private"}}"#,
            );

            let mut application = accept_h1_fixture_connection(
                &modern_listener,
                deadline,
                "accept Auto modern tools-list POST",
            );
            let (head, request) = read_h1_json_request(&mut application, deadline);
            assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert_eq!(request["id"], 2);
            assert_eq!(request["method"], "tools/list");
            assert_eq!(
                request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
                "2026-07-28"
            );
            write_h1_empty_response(&mut application, deadline, 500);
        },
    );

    let output = inspect_http_bundle("auto", &modern_url, &legacy_sse_url, &legacy_message_url);
    assert!(
        !output.status.success(),
        "an application POST failure after modern discovery must fail instead of downgrading"
    );
    wait_for_loopback_fixture(modern_fixture, "Auto modern application fixture");
    stop_forbidden_http_contact_observer(legacy_observer, "Auto legacy");
    assert_eq!(
        legacy_contacts.load(Ordering::SeqCst),
        0,
        "a modern-selected Auto connection must not contact either configured legacy endpoint after an application failure"
    );
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn e2e_cli_inspect_http_bundle_auto_uses_authorized_legacy_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind Auto legacy HTTP fixture");
    let address = listener
        .local_addr()
        .expect("read Auto legacy HTTP fixture address");
    let modern_url = format!("http://{address}/mcp");
    let legacy_sse_url = format!("http://{address}/legacy-sse");
    let legacy_message_url = format!("http://{address}/legacy-message");
    let fixture_message_url = legacy_message_url.clone();
    let fixture = spawn_loopback_fixture("Auto legacy HTTP fixture", move |deadline| {
        serve_legacy_http_inspect_bundle(listener, deadline, Some(404), fixture_message_url);
    });

    let output = inspect_http_bundle("auto", &modern_url, &legacy_sse_url, &legacy_message_url);
    assert!(
        output.status.success(),
        "Auto must use the configured legacy bundle after its authorized modern refusal: {}",
        stderr_str(&output)
    );
    wait_for_loopback_fixture(fixture, "Auto legacy HTTP fixture");
    let rendered: serde_json::Value =
        serde_json::from_str(&stdout_str(&output)).expect("Auto inspect output is diagnostic JSON");
    assert_eq!(rendered["server"]["name"], "legacy-h1-inspect");
    assert_eq!(rendered["protocol"]["policy"], "auto");
    assert_eq!(rendered["protocol"]["version"], "2024-11-05");
    assert_eq!(rendered["protocol"]["era"], "legacy-2024");
    assert_eq!(rendered["tools"][0]["name"], "legacy-h1-tool");
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn e2e_cli_inspect_http_bundle_auto_rejects_recognized_discovery_error_without_legacy_contact() {
    let modern_listener =
        TcpListener::bind("127.0.0.1:0").expect("bind recognized-refusal modern fixture");
    let modern_address = modern_listener
        .local_addr()
        .expect("read recognized-refusal modern fixture address");
    let legacy_listener =
        TcpListener::bind("127.0.0.1:0").expect("bind recognized-refusal legacy observer");
    let legacy_address = legacy_listener
        .local_addr()
        .expect("read recognized-refusal legacy observer address");
    let modern_url = format!("http://{modern_address}/mcp");
    let legacy_sse_url = format!("http://{legacy_address}/legacy-sse");
    let legacy_message_url = format!("http://{legacy_address}/legacy-message");
    let legacy_contacts = Arc::new(AtomicUsize::new(0));
    let legacy_observer = spawn_forbidden_http_contact_observer(
        legacy_listener,
        Arc::clone(&legacy_contacts),
        "recognized-refusal legacy",
    );
    let modern_fixture =
        spawn_loopback_fixture("recognized-refusal modern fixture", move |deadline| {
            let mut modern = accept_h1_fixture_connection(
                &modern_listener,
                deadline,
                "accept recognized-refusal modern discovery POST",
            );
            let (head, request) = read_h1_json_request(&mut modern, deadline);
            assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert_eq!(request["id"], 1);
            assert_eq!(request["method"], "server/discover");
            write_h1_json_response_with_status(
                &mut modern,
                deadline,
                404,
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#,
            );
        });

    let output = inspect_http_bundle("auto", &modern_url, &legacy_sse_url, &legacy_message_url);
    assert!(
        !output.status.success(),
        "a recognized discovery error at the same 404 as the fallback-positive case must not downgrade"
    );
    wait_for_loopback_fixture(modern_fixture, "recognized-refusal modern fixture");
    stop_forbidden_http_contact_observer(legacy_observer, "recognized-refusal legacy");
    assert_eq!(
        legacy_contacts.load(Ordering::SeqCst),
        0,
        "a recognized modern discovery error must not contact either configured legacy endpoint"
    );
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn e2e_cli_inspect_http_bundle_legacy_only_skips_modern_contact() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind LegacyOnly HTTP fixture");
    let address = listener
        .local_addr()
        .expect("read LegacyOnly HTTP fixture address");
    let modern_url = format!("http://{address}/mcp");
    let legacy_sse_url = format!("http://{address}/legacy-sse");
    let legacy_message_url = format!("http://{address}/legacy-message");
    let fixture_message_url = legacy_message_url.clone();
    let fixture = spawn_loopback_fixture("LegacyOnly HTTP fixture", move |deadline| {
        serve_legacy_http_inspect_bundle(listener, deadline, None, fixture_message_url);
    });

    let output = inspect_http_bundle(
        "legacy-only",
        &modern_url,
        &legacy_sse_url,
        &legacy_message_url,
    );
    assert!(
        output.status.success(),
        "LegacyOnly must use the configured legacy bundle directly: {}",
        stderr_str(&output)
    );
    wait_for_loopback_fixture(fixture, "LegacyOnly HTTP fixture");
    let rendered: serde_json::Value = serde_json::from_str(&stdout_str(&output))
        .expect("LegacyOnly inspect output is diagnostic JSON");
    assert_eq!(rendered["protocol"]["policy"], "legacy-only");
    assert_eq!(rendered["protocol"]["version"], "2024-11-05");
    assert_eq!(rendered["protocol"]["era"], "legacy-2024");
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn e2e_cli_inspect_http_bundle_rejects_incomplete_auto_without_contact() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind no-probe HTTP fixture");
    let address = listener
        .local_addr()
        .expect("read no-probe HTTP fixture address");
    let url = format!("http://{address}/mcp");
    let legacy_sse_url = format!("http://{address}/legacy-sse");
    let probes = Arc::new(AtomicUsize::new(0));
    let observer = spawn_forbidden_http_contact_observer(
        listener,
        Arc::clone(&probes),
        "HTTP policy rejection",
    );

    let output = run_cli(&[
        "inspect",
        "--http-url",
        &url,
        "--legacy-sse-url",
        &legacy_sse_url,
        "--protocol-policy",
        "auto",
        "--format",
        "json",
    ]);
    assert!(
        !output.status.success(),
        "an incomplete Auto bundle must not infer its missing legacy message endpoint"
    );
    assert!(
        stderr_str(&output).contains("requires a configured legacy message POST target"),
        "the incomplete-bundle rejection must be explicit"
    );
    stop_forbidden_http_contact_observer(observer, "HTTP policy rejection");
    assert_eq!(
        probes.load(Ordering::SeqCst),
        0,
        "incomplete-bundle rejection must occur before any HTTP side effect"
    );
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn e2e_cli_inspect_http_bundle_rejects_mismatched_legacy_message_endpoint() {
    let sse_listener = TcpListener::bind("127.0.0.1:0").expect("bind mismatch SSE fixture");
    let sse_address = sse_listener
        .local_addr()
        .expect("read mismatch SSE fixture address");
    let configured_listener =
        TcpListener::bind("127.0.0.1:0").expect("bind configured message observer");
    let configured_address = configured_listener
        .local_addr()
        .expect("read configured message observer address");
    let advertised_listener =
        TcpListener::bind("127.0.0.1:0").expect("bind advertised message observer");
    let advertised_address = advertised_listener
        .local_addr()
        .expect("read advertised message observer address");
    let configured_contacts = Arc::new(AtomicUsize::new(0));
    let advertised_contacts = Arc::new(AtomicUsize::new(0));
    let configured_observer = spawn_forbidden_http_contact_observer(
        configured_listener,
        Arc::clone(&configured_contacts),
        "configured message",
    );
    let advertised_observer = spawn_forbidden_http_contact_observer(
        advertised_listener,
        Arc::clone(&advertised_contacts),
        "advertised message",
    );
    let fixture = spawn_loopback_fixture("mismatch legacy SSE fixture", move |deadline| {
        let mut sse =
            accept_h1_fixture_connection(&sse_listener, deadline, "accept mismatch legacy SSE GET");
        let head = read_h1_request_head(&mut sse, deadline);
        assert!(head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
        begin_h1_chunked_sse(&mut sse, deadline);
        write_h1_chunked_sse_event(
            &mut sse,
            deadline,
            &format!("event: endpoint\ndata: http://{advertised_address}/legacy-message\n\n"),
        );
    });
    let modern_url = format!("http://{sse_address}/mcp");
    let legacy_sse_url = format!("http://{sse_address}/legacy-sse");
    let configured_message_url = format!("http://{configured_address}/legacy-message");

    let output = inspect_http_bundle(
        "legacy-only",
        &modern_url,
        &legacy_sse_url,
        &configured_message_url,
    );
    assert!(
        !output.status.success(),
        "changing only the SSE-advertised message target must reject the bundle"
    );
    wait_for_loopback_fixture(fixture, "mismatch legacy SSE fixture");
    stop_forbidden_http_contact_observer(configured_observer, "configured message");
    stop_forbidden_http_contact_observer(advertised_observer, "advertised message");
    assert_eq!(
        configured_contacts.load(Ordering::SeqCst),
        0,
        "a mismatched legacy endpoint must not contact the configured message route"
    );
    assert_eq!(
        advertised_contacts.load(Ordering::SeqCst),
        0,
        "a mismatched legacy endpoint must not contact the advertised foreign route"
    );
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn e2e_cli_inspect_http_bundle_auto_rejects_unauthorized_fallback_without_legacy_contact() {
    let modern_listener =
        TcpListener::bind("127.0.0.1:0").expect("bind unauthorized modern fixture");
    let modern_address = modern_listener
        .local_addr()
        .expect("read unauthorized modern fixture address");
    let legacy_listener =
        TcpListener::bind("127.0.0.1:0").expect("bind unauthorized legacy observer");
    let legacy_address = legacy_listener
        .local_addr()
        .expect("read unauthorized legacy observer address");
    let modern_url = format!("http://{modern_address}/mcp");
    let legacy_sse_url = format!("http://{legacy_address}/legacy-sse");
    let legacy_message_url = format!("http://{legacy_address}/legacy-message");
    let legacy_contacts = Arc::new(AtomicUsize::new(0));
    let modern_fixture = spawn_loopback_fixture("unauthorized modern fixture", move |deadline| {
        let mut modern = accept_h1_fixture_connection(
            &modern_listener,
            deadline,
            "accept unauthorized modern probe",
        );
        let (head, request) = read_h1_json_request(&mut modern, deadline);
        assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
        assert_eq!(request["method"], "server/discover");
        write_h1_empty_response(&mut modern, deadline, 500);
    });
    let legacy_observer = spawn_forbidden_http_contact_observer(
        legacy_listener,
        Arc::clone(&legacy_contacts),
        "unauthorized legacy",
    );

    let output = inspect_http_bundle("auto", &modern_url, &legacy_sse_url, &legacy_message_url);
    assert!(
        !output.status.success(),
        "changing only the authorized 404 refusal to an ordinary 500 must not downgrade"
    );
    wait_for_loopback_fixture(modern_fixture, "unauthorized modern fixture");
    stop_forbidden_http_contact_observer(legacy_observer, "unauthorized legacy");
    assert_eq!(
        legacy_contacts.load(Ordering::SeqCst),
        0,
        "an unauthorized modern failure must not contact a legacy endpoint"
    );
}

#[test]
fn e2e_legacy_lifecycle_fixture_planted_negative_rejects_list_before_initialized() {
    let output = run_legacy_fixture_with_requests(&[
        LEGACY_PLANTED_INITIALIZE_REQUEST,
        LEGACY_PLANTED_TOOLS_LIST_REQUEST,
    ]);
    assert!(
        !output.status.success(),
        "legacy fixture must reject an operating list request before notifications/initialized"
    );
    let wire = observed_protocol_wire(&output);
    assert_eq!(
        wire.iter().map(request_method).collect::<Vec<_>>(),
        vec!["initialize", "tools/list"],
        "planted pre-initialization list must be the rejected observed wire"
    );
    assert_exact_legacy_initialize_request(&wire[0]);
    assert_exact_legacy_operating_request(&wire[1]);
}

#[test]
fn e2e_legacy_lifecycle_fixture_planted_negative_rejects_repeated_initialize() {
    let output = run_legacy_fixture_with_requests(&[
        LEGACY_PLANTED_INITIALIZE_REQUEST,
        LEGACY_PLANTED_REPEATED_INITIALIZE_REQUEST,
    ]);
    assert!(
        !output.status.success(),
        "legacy fixture must reject a repeated initialize before notifications/initialized"
    );
    let wire = observed_protocol_wire(&output);
    assert_eq!(
        wire.iter().map(request_method).collect::<Vec<_>>(),
        vec!["initialize", "initialize"],
        "planted repeated initialization must be the rejected observed wire"
    );
    assert_exact_legacy_initialize_request(&wire[0]);
    assert_exact_legacy_initialize_request(&wire[1]);
}

#[test]
fn e2e_legacy_initialized_fixture_planted_negatives_reject_noncanonical_envelopes() {
    for (case_name, malformed_notification) in [
        (
            "extra envelope field",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","extra":true}"#,
        ),
        (
            "unexpected params object",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
        ),
    ] {
        let output = run_legacy_fixture_with_requests(&[
            LEGACY_PLANTED_INITIALIZE_REQUEST,
            malformed_notification,
        ]);
        assert!(
            !output.status.success(),
            "legacy fixture must reject initialized notification with {case_name}"
        );
        let wire = observed_protocol_wire(&output);
        assert_eq!(
            wire.len(),
            2,
            "rejected initialized notification must follow exactly one initialize"
        );
        assert_exact_legacy_initialize_request(&wire[0]);
        let expected: serde_json::Value = serde_json::from_str(malformed_notification)
            .expect("planted notification must be JSON");
        assert_eq!(
            wire[1], expected,
            "fixture must reject the observed initialized notification with {case_name}"
        );
    }
}

#[test]
fn e2e_legacy_operating_fixture_planted_negatives_reject_noncanonical_envelopes() {
    for (case_name, malformed_operating_request) in [
        (
            "extra envelope field",
            r#"{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2,"extra":true}"#,
        ),
        (
            "non-object params",
            r#"{"jsonrpc":"2.0","method":"tools/list","params":null,"id":2}"#,
        ),
    ] {
        let output = run_legacy_fixture_with_requests(&[
            LEGACY_PLANTED_INITIALIZE_REQUEST,
            LEGACY_PLANTED_INITIALIZED_NOTIFICATION,
            malformed_operating_request,
        ]);
        assert!(
            !output.status.success(),
            "legacy fixture must reject operating request with {case_name}"
        );
        let wire = observed_protocol_wire(&output);
        assert_eq!(
            wire.len(),
            3,
            "rejected operating request must follow initialize and initialized notification"
        );
        assert_exact_legacy_initialize_request(&wire[0]);
        assert_exact_legacy_initialized_notification_request(&wire[1]);
        let expected: serde_json::Value = serde_json::from_str(malformed_operating_request)
            .expect("planted operating request must be JSON");
        assert_eq!(
            wire[2], expected,
            "fixture must reject the observed operating request with {case_name}"
        );
    }
}

#[test]
fn e2e_modern_discovery_fixture_planted_negatives_reject_noncanonical_envelopes() {
    for (case_name, malformed_discovery) in [
        (
            "extra envelope field",
            r#"{"jsonrpc":"2.0","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"planted-modern-client","version":"1.0.0"},"io.modelcontextprotocol/protocolVersion":"2026-07-28"}},"id":1,"extra":true}"#,
        ),
        (
            "wrong jsonrpc",
            r#"{"jsonrpc":"1.0","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"planted-modern-client","version":"1.0.0"},"io.modelcontextprotocol/protocolVersion":"2026-07-28"}},"id":1}"#,
        ),
        (
            "missing jsonrpc",
            r#"{"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"planted-modern-client","version":"1.0.0"},"io.modelcontextprotocol/protocolVersion":"2026-07-28"}},"id":1}"#,
        ),
        (
            "wrong method",
            r#"{"jsonrpc":"2.0","method":"server/unknown","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"planted-modern-client","version":"1.0.0"},"io.modelcontextprotocol/protocolVersion":"2026-07-28"}},"id":1}"#,
        ),
        (
            "wrong id",
            r#"{"jsonrpc":"2.0","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"planted-modern-client","version":"1.0.0"},"io.modelcontextprotocol/protocolVersion":"2026-07-28"}},"id":2}"#,
        ),
        (
            "missing id",
            r#"{"jsonrpc":"2.0","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"planted-modern-client","version":"1.0.0"},"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#,
        ),
        (
            "null params",
            r#"{"jsonrpc":"2.0","method":"server/discover","params":null,"id":1}"#,
        ),
        (
            "extra params field",
            r#"{"jsonrpc":"2.0","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"planted-modern-client","version":"1.0.0"},"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"extra":true},"id":1}"#,
        ),
        (
            "null metadata",
            r#"{"jsonrpc":"2.0","method":"server/discover","params":{"_meta":null},"id":1}"#,
        ),
        (
            "non-object client capabilities",
            r#"{"jsonrpc":"2.0","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":null,"io.modelcontextprotocol/clientInfo":{"name":"planted-modern-client","version":"1.0.0"},"io.modelcontextprotocol/protocolVersion":"2026-07-28"}},"id":1}"#,
        ),
        (
            "extra client info field",
            r#"{"jsonrpc":"2.0","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"planted-modern-client","version":"1.0.0","extra":true},"io.modelcontextprotocol/protocolVersion":"2026-07-28"}},"id":1}"#,
        ),
        (
            "extra metadata field",
            r#"{"jsonrpc":"2.0","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"planted-modern-client","version":"1.0.0"},"io.modelcontextprotocol/protocolVersion":"2026-07-28","extra":true}},"id":1}"#,
        ),
    ] {
        let output = run_modern_fixture_with_request(malformed_discovery);
        assert!(
            !output.status.success(),
            "modern fixture must reject discovery with {case_name}"
        );
        let wire = observed_protocol_wire(&output);
        assert_eq!(
            wire.len(),
            1,
            "rejected {case_name} must be the only observed discovery request"
        );
        let expected: serde_json::Value =
            serde_json::from_str(malformed_discovery).expect("planted discovery must be JSON");
        assert_eq!(
            wire[0], expected,
            "fixture must reject the actual discovery request with {case_name}"
        );
    }
}

#[test]
fn e2e_legacy_initialize_fixture_planted_negatives_reject_malformed_shapes() {
    for (case_name, malformed_initialize) in [
        (
            "null protocolVersion",
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":null,"capabilities":{},"clientInfo":{"name":"planted-legacy-client","version":"1.0.0"}},"id":1}"#,
        ),
        (
            "wrong protocolVersion",
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"planted-legacy-client","version":"1.0.0"}},"id":1}"#,
        ),
        (
            "non-object capabilities",
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":[],"clientInfo":{"name":"planted-legacy-client","version":"1.0.0"}},"id":1}"#,
        ),
        (
            "null clientInfo name",
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":null,"version":"1.0.0"}},"id":1}"#,
        ),
        (
            "numeric clientInfo version",
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"planted-legacy-client","version":1}},"id":1}"#,
        ),
        (
            "extra clientInfo field",
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"planted-legacy-client","version":"1.0.0","extra":true}},"id":1}"#,
        ),
        (
            "extra legacy parameter",
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"planted-legacy-client","version":"1.0.0"},"extra":true},"id":1}"#,
        ),
        (
            "final-only metadata",
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"planted-legacy-client","version":"1.0.0"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}},"id":1}"#,
        ),
    ] {
        let output = run_legacy_fixture_with_requests(&[malformed_initialize]);
        assert!(
            !output.status.success(),
            "legacy fixture must reject {case_name}"
        );
        let wire = observed_protocol_wire(&output);
        assert_eq!(
            wire.len(),
            1,
            "rejected {case_name} must be the only observed wire request"
        );
        let expected: serde_json::Value =
            serde_json::from_str(malformed_initialize).expect("planted initialize must be JSON");
        assert_eq!(
            wire[0], expected,
            "fixture must reject the actual malformed {case_name} request"
        );
    }
}

#[test]
fn e2e_cli_inspect_modern_only_planted_negative_never_falls_back_to_legacy() {
    let output = inspect_protocol_fixture("modern-only", "text", LEGACY_FALLBACK_INSPECT_FIXTURE);
    assert!(
        !output.status.success(),
        "ModernOnly must reject a legacy-only peer instead of silently falling back"
    );
    let wire = observed_protocol_wire(&output);
    assert_modern_negotiation_wire(&wire);
    assert_no_legacy_initialize(&wire);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn e2e_cli_inspect_auto_planted_negative_rejects_unauthorized_discovery_failure() {
    let output = inspect_protocol_fixture(
        "auto",
        "json",
        UNAUTHORIZED_DISCOVERY_REJECTION_INSPECT_FIXTURE,
    );
    assert!(
        !output.status.success(),
        "Auto must not fall back on a discovery error outside the authorized legacy class"
    );
    let wire = observed_protocol_wire(&output);
    assert_modern_negotiation_wire(&wire);
    assert_no_legacy_initialize(&wire);
}

#[cfg(target_os = "linux")]
#[test]
fn reality_check_regression_e2e_test_cleans_descendants_before_success() {
    const FORKING_SERVER_WRAPPER: &str = r#"
trap '' HUP
/bin/sh -c 'trap "" HUP; exec </dev/null >/dev/null 2>/dev/null; while :; do /bin/sleep 3600; done' &
stubborn_pid=$!
printf "FASTMCP_TEST_STUBBORN_PID=%s\n" "$stubborn_pid" >&2
# A non-interactive shell may otherwise connect an asynchronous list's stdin
# to /dev/null. Save the inherited MCP request pipe before starting the
# asynchronous list, then close both extra descriptor copies promptly.
exec 3<&0
/bin/sh -c 'exec 3<&-; trap "" HUP; printf "FASTMCP_TEST_DESCENDANT_PID=%s\n" "$$" >&2; exec /bin/sh "$1"' fastmcp-descendant "$1" <&3 &
exec 3<&-
exit 0
"#;

    let output = run_cli(&[
        "test",
        "--json",
        "--idle-timeout",
        "30",
        "--absolute-timeout",
        "120",
        "/bin/sh",
        "--",
        "-c",
        FORKING_SERVER_WRAPPER,
        "fastmcp-forking-server",
        STATIC_MCP_SERVER_FIXTURE,
    ]);
    assert!(
        output.status.success(),
        "the descendant-served protocol probe should succeed: status={}; stdout={}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse descendant cleanup report");
    assert_eq!(report["success"], true);
    let cleanup = report["tests"]
        .as_array()
        .and_then(|tests| tests.iter().find(|test| test["name"] == "cleanup"))
        .expect("successful report must include explicit cleanup verification");
    assert_eq!(cleanup["success"], true);
    assert_eq!(cleanup["details"], "owned subprocess group stopped");

    let stderr = std::str::from_utf8(&output.stderr).expect("peer marker must be UTF-8");
    for (marker, description) in [
        ("FASTMCP_TEST_DESCENDANT_PID=", "protocol descendant"),
        ("FASTMCP_TEST_STUBBORN_PID=", "stubborn descendant"),
    ] {
        let descendant_pid = stderr
            .lines()
            .find_map(|line| line.strip_prefix(marker))
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_else(|| panic!("forked {description} must report its PID"));
        let deadline = Instant::now() + PROCESS_CLEANUP_DEADLINE;
        loop {
            match std::fs::read_to_string(format!("/proc/{descendant_pid}/stat")) {
                Ok(stat) => {
                    let (state, _) = linux_process_state_and_group(&stat)
                        .expect("descendant process state must be parseable");
                    if matches!(state, 'Z' | 'X' | 'x') {
                        break;
                    }
                }
                Err(error) if proc_process_disappeared(&error) => break,
                Err(error) => panic!("failed to inspect descendant process state: {error}"),
            }
            assert!(
                Instant::now() < deadline,
                "fastmcp test reported success while {description} {descendant_pid} remained live"
            );
            std::thread::sleep(PROCESS_POLL_INTERVAL);
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn reality_check_regression_e2e_test_owner_death_stops_anchored_group() {
    const DELAYED_SERVER: &str = r#"
printf "FASTMCP_TEST_OWNER_DEATH_PID=%s\n" "$$" >&2
/bin/sleep 30
exec /bin/sh "$1"
"#;

    let mut command = Command::new(fastmcp_bin());
    command
        .args([
            "test",
            "--json",
            "--idle-timeout",
            "30",
            "--absolute-timeout",
            "120",
            "/bin/sh",
            "--",
            "-c",
            DELAYED_SERVER,
            "fastmcp-owner-death-server",
            STATIC_MCP_SERVER_FIXTURE,
        ])
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut process = ProcessGroupGuard::spawn(&mut command);
    let stderr = process
        .child_mut()
        .stderr
        .take()
        .expect("owner-death stderr");
    let (marker_sender, marker_receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stderr).read_line(&mut line);
        // Sending the completed payload is this worker's final action.
        let _ = marker_sender.send((result, line));
    });
    let (read_result, marker) = marker_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("owner-death fixture did not report its PID: {error}"));
    reader
        .join()
        .expect("stderr marker reader must join after its final acknowledgement");
    read_result.expect("read owner-death PID marker");
    let target_pid = marker
        .trim()
        .strip_prefix("FASTMCP_TEST_OWNER_DEATH_PID=")
        .and_then(|value| value.parse::<u32>().ok())
        .expect("parse owner-death PID marker");

    process
        .child_mut()
        .kill()
        .expect("kill only the fastmcp CLI owner");
    let owner_status = process
        .wait_until(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("reap fastmcp CLI owner: {error:?}"));
    assert!(!owner_status.success(), "killed CLI owner cannot succeed");
    let deadline = Instant::now() + PROCESS_CLEANUP_DEADLINE;
    loop {
        match std::fs::read_to_string(format!("/proc/{target_pid}/stat")) {
            Ok(stat) => {
                let (state, _) = linux_process_state_and_group(&stat)
                    .expect("owner-death process state must be parseable");
                if matches!(state, 'Z' | 'X' | 'x') {
                    break;
                }
            }
            Err(error) if proc_process_disappeared(&error) => break,
            Err(error) => panic!("failed to inspect owner-death target: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "anchor did not stop target {target_pid} after CLI owner death"
        );
        std::thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

#[cfg(feature = "e2e-fixture")]
#[test]
fn e2e_test_json_report_against_compiled_fastmcp_server() {
    let server = env!("CARGO_BIN_EXE_fastmcp_cli_e2e_server");

    let output = run_cli(&[
        "test",
        "--json",
        "--idle-timeout",
        "30",
        "--absolute-timeout",
        "120",
        server,
    ]);
    assert!(output.status.success());

    let report: serde_json::Value =
        serde_json::from_str(&stdout_str(&output)).expect("parse framework test report");
    assert_eq!(report["success"], true);
    let tests = report["tests"]
        .as_array()
        .expect("framework report test array");
    for (name, expected_details) in [
        ("initialize", "protocol 2024-11-05"),
        ("ping", "server responded"),
        ("list_tools", "1 tools"),
        ("list_resources", "1 resources"),
        ("list_prompts", "1 prompts"),
    ] {
        let result = tests
            .iter()
            .find(|test| test["name"] == name)
            .unwrap_or_else(|| panic!("framework report must include {name}"));
        assert_eq!(result["success"], true, "{name} must succeed");
        assert_ne!(
            result["skipped"].as_bool(),
            Some(true),
            "{name} must execute"
        );
        assert_eq!(result["details"], expected_details);
    }
}

#[cfg(feature = "e2e-fixture")]
#[test]
fn reality_check_regression_compiled_stdio_server_exits_when_worker_output_fails() {
    let server = env!("CARGO_BIN_EXE_fastmcp_cli_e2e_server");
    let mut command = Command::new(server);
    command
        .env("FASTMCP_NO_BANNER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut guard = ProcessGroupGuard::spawn(&mut command);
    let mut stdin = guard
        .child_mut()
        .stdin
        .take()
        .expect("compiled fixture stdin");
    let stdout = guard
        .child_mut()
        .stdout
        .take()
        .expect("compiled fixture stdout");
    drop(stdout);

    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}\n")
        .expect("request reaches compiled fixture");
    stdin.flush().expect("request flushes");
    let started = Instant::now();
    let status = guard
        .wait_until(Duration::from_secs(10))
        .unwrap_or_else(|timeout| panic!("compiled fixture did not stop: {timeout:?}"));

    assert!(!status.success());
    assert!(started.elapsed() < Duration::from_secs(10));
    drop(stdin);
}

#[cfg(feature = "e2e-fixture")]
#[test]
fn reality_check_regression_compiled_stdio_server_bounds_unread_output_pipe() {
    let server = env!("CARGO_BIN_EXE_fastmcp_cli_e2e_server");
    let mut command = Command::new(server);
    command
        .env("FASTMCP_NO_BANNER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut guard = ProcessGroupGuard::spawn(&mut command);
    let mut stdin = guard
        .child_mut()
        .stdin
        .take()
        .expect("compiled fixture stdin");
    let _unread_stdout = guard
        .child_mut()
        .stdout
        .take()
        .expect("compiled fixture stdout");

    let initialize = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "pipe-saturation-test", "version": "1.0.0"}
        }
    });
    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {"message": "x".repeat(1024 * 1024)},
            "_meta": {"progressToken": "saturation-progress"}
        }
    });
    for request in [initialize, call] {
        serde_json::to_writer(&mut stdin, &request).expect("encode saturation request");
        stdin.write_all(b"\n").expect("frame saturation request");
    }
    stdin.flush().expect("saturation requests flush");

    let started = Instant::now();
    let status = guard
        .wait_until(Duration::from_secs(10))
        .unwrap_or_else(|timeout| panic!("compiled fixture did not bound stdout: {timeout:?}"));

    assert!(!status.success());
    assert!(started.elapsed() < Duration::from_secs(10));
    drop(stdin);
}

#[cfg(unix)]
#[test]
fn e2e_static_protocol_fixture_ignores_nested_notification_ids() {
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        r#"printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/progress","params":{"id":99}}' '{"jsonrpc":"2.0","method":"ping","id":7}' | /bin/sh "$1""#,
        "fixture-notification-probe",
        STATIC_MCP_SERVER_FIXTURE,
    ]);
    let output = run_with_deadline(command, Duration::from_secs(10))
        .expect("static protocol fixture must exit after its input closes");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let responses = std::str::from_utf8(&output.stdout)
        .expect("fixture output must be UTF-8")
        .lines()
        .collect::<Vec<_>>();
    assert_eq!(
        responses.len(),
        1,
        "notification params.id must not produce a response"
    );
    let response: serde_json::Value =
        serde_json::from_str(responses[0]).expect("fixture response must be valid JSON");
    assert_eq!(response["id"], 7);
    assert_eq!(response["result"], serde_json::json!({}));
}

#[cfg(unix)]
#[test]
fn e2e_test_absolute_timeout_bounds_silent_initialization() {
    assert_initialization_absolute_timeout("exec sleep 5", "silent peer");
}

#[test]
fn e2e_test_json_report_is_emitted_when_connect_fails() {
    let missing_server = format!(
        "/definitely-missing-fastmcp-e2e-server-{}",
        std::process::id()
    );
    let mut cmd = Command::new(fastmcp_bin());
    cmd.args(["test", "--json", &missing_server])
        .env("FASTMCP_CHECK_FOR_UPDATES", "0");

    let output = run_with_deadline(cmd, Duration::from_secs(10))
        .expect("missing executable failure must remain promptly bounded");

    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("JSON mode must report connection failure on stdout");
    assert_eq!(report["server"].as_str(), Some(missing_server.as_str()));
    assert_eq!(report["success"], false);
    let tests = report["tests"]
        .as_array()
        .expect("connection failure report must contain tests");
    assert_eq!(tests.len(), 1);
    assert_eq!(tests[0]["name"], "initialize");
    assert_eq!(tests[0]["success"], false);
    assert!(
        tests[0]["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty())
    );
    assert!(tests[0].get("timeout_source").is_none());
}

#[cfg(unix)]
#[test]
fn e2e_test_absolute_timeout_bounds_partial_initialization_frame() {
    assert_initialization_absolute_timeout(
        r#"printf '%s' '{"jsonrpc":"2.0"'; exec sleep 5"#,
        "partial-frame peer",
    );
}

#[cfg(unix)]
fn assert_initialization_absolute_timeout(server_script: &str, scenario: &str) {
    let mut cmd = Command::new(fastmcp_bin());
    cmd.args([
        "test",
        "--json",
        "--idle-timeout",
        "2",
        "--absolute-timeout",
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
        stderr.contains("Request timed out at the absolute deadline"),
        "{scenario} did not select the intentionally earlier absolute deadline: {stderr}"
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("JSON mode must report initialization timeout on stdout");
    assert_eq!(report["success"], false);
    let tests = report["tests"]
        .as_array()
        .expect("initialization failure report must contain tests");
    assert_eq!(tests.len(), 1);
    assert_eq!(tests[0]["name"], "initialize");
    assert_eq!(tests[0]["success"], false);
    assert_eq!(tests[0]["timeout_source"], "absolute");
    assert!(
        tests[0]["error"]
            .as_str()
            .is_some_and(|error| error.contains("Request timed out at the absolute deadline"))
    );
}

#[cfg(unix)]
#[test]
fn e2e_test_idle_timeout_reports_late_ping_response() {
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
        "--idle-timeout",
        "1",
        "--absolute-timeout",
        "3",
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
            .is_some_and(|error| error.contains("Request timed out at the idle deadline")),
        "ping result should select the intentionally earlier idle deadline: {ping}"
    );
    assert_eq!(
        ping.get("timeout_source")
            .and_then(serde_json::Value::as_str),
        Some("idle")
    );
    let stderr =
        std::str::from_utf8(&output.stderr).expect("fastmcp test stderr must be valid UTF-8");
    assert!(
        stderr.contains("Some tests failed"),
        "top-level failure diagnostic missing: {stderr}"
    );
}
