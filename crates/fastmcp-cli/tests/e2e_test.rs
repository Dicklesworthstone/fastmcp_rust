//! E2E tests for `fastmcp test`.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, ExitStatus, Stdio};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

const CLI_DEADLINE: Duration = Duration::from_secs(120);
const CAPTURE_DRAIN_DEADLINE: Duration = Duration::from_secs(1);
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const PROCESS_CLEANUP_DEADLINE: Duration = Duration::from_secs(2);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
const PROCESS_TERM_GRACE: Duration = Duration::from_millis(500);
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

fn read_h1_json_request(stream: &mut TcpStream) -> (String, serde_json::Value) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set HTTP fixture read timeout");
    let mut wire = Vec::new();
    let mut buffer = [0_u8; 4_096];
    let head_end = loop {
        let read = stream.read(&mut buffer).expect("read HTTP fixture request");
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
        let read = stream
            .read(&mut buffer)
            .expect("read HTTP fixture request body");
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

fn write_h1_json_response(stream: &mut TcpStream, body: &str) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .expect("write HTTP fixture response head");
    stream
        .write_all(body.as_bytes())
        .expect("write HTTP fixture response body");
    stream.flush().expect("flush HTTP fixture response");
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
fn e2e_cli_inspect_http_url_uses_live_modern_h1_and_negotiated_status_renderer() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind modern HTTP inspect fixture");
    let address = listener
        .local_addr()
        .expect("read modern HTTP inspect fixture address");
    let url = format!("http://{address}/mcp");
    let fixture = std::thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("accept modern HTTP inspect connection");
        let (head, request) = read_h1_json_request(&mut stream);
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
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"_meta":{"serverInfo":{"name":"modern-h1-inspect","version":"1.0.0"}},"ttlMs":0,"cacheScope":"private"}}"#,
        );

        let (mut stream, _) = listener
            .accept()
            .expect("accept modern HTTP tools-list connection");
        let (head, request) = read_h1_json_request(&mut stream);
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
    fixture
        .join()
        .expect("modern HTTP inspect fixture must complete");

    let rendered: serde_json::Value =
        serde_json::from_str(&stdout_str(&output)).expect("inspect output is diagnostic JSON");
    assert_eq!(rendered["server"]["name"], "modern-h1-inspect");
    assert_eq!(rendered["protocol"]["policy"], "modern-only");
    assert_eq!(rendered["protocol"]["version"], "2026-07-28");
    assert_eq!(rendered["protocol"]["era"], "modern-2026");
    assert_eq!(rendered["tools"][0]["name"], "h1-tool");
}

#[test]
fn e2e_cli_inspect_http_url_auto_policy_rejects_before_any_h1_probe() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind no-probe HTTP fixture");
    listener
        .set_nonblocking(true)
        .expect("make no-probe HTTP fixture nonblocking");
    let address = listener
        .local_addr()
        .expect("read no-probe HTTP fixture address");
    let url = format!("http://{address}/mcp");
    let probes = Arc::new(AtomicUsize::new(0));
    let observed_probes = Arc::clone(&probes);
    let observer = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((_stream, _)) => {
                    observed_probes.fetch_add(1, Ordering::SeqCst);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("observe HTTP policy rejection connection: {error}"),
            }
        }
    });

    let output = run_cli(&[
        "inspect",
        "--http-url",
        &url,
        "--protocol-policy",
        "auto",
        "--format",
        "json",
    ]);
    assert!(
        !output.status.success(),
        "changing only modern-only to auto must reject the URL target"
    );
    assert!(
        stderr_str(&output).contains("--http-url requires --protocol-policy modern-only"),
        "policy rejection must be explicit"
    );
    observer
        .join()
        .expect("no-probe HTTP observer must complete");
    assert_eq!(
        probes.load(Ordering::SeqCst),
        0,
        "policy rejection must occur before any HTTP probe side effect"
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
        let _ = marker_sender.send((result, line));
    });
    let (read_result, marker) = marker_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("owner-death fixture did not report its PID: {error}"));
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
    reader.join().expect("stderr marker reader");

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
