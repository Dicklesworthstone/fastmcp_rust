//! CLI-CORE-01 B: machine JSON, diagnostic display, process cleanup, and the
//! legacy-off denial surface of the shipped `--no-default-features` binary.
//!
//! The workspace test runner builds default features, and Cargo unifies
//! features across the workspace, so no artifact of that build is a no-legacy
//! binary. These tests therefore build the shipped `fastmcp` binary themselves
//! with `--no-default-features` into a separate target directory, as a
//! packaged consumer would, and drive only that executable.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

// A cold no-legacy build compiles the CLI's whole dependency graph once.
const BUILD_DEADLINE: Duration = Duration::from_mins(40);
const CLI_DEADLINE: Duration = Duration::from_secs(120);
const CLEANUP_DEADLINE: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const NO_LEGACY_HELP_MARKER: &str = "This --no-default-features build executes ModernOnly only.";
const DEFAULT_BUILD_HELP_MARKER: &str = "Public PROTOCOL_VERSION remains 2024-11-05";
const SECRET: &str = "sk_cli_core_01_b_never_displayed";
const INJECTED_LINE: &str = "CLI-CORE-01-B-INJECTED-LINE";
static SUBJECT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Captured {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Captured {
    fn stdout(&self) -> &str {
        std::str::from_utf8(&self.stdout).expect("CLI stdout is UTF-8")
    }

    fn stderr(&self) -> &str {
        std::str::from_utf8(&self.stderr).expect("CLI stderr is UTF-8")
    }

    /// Exactly one JSON document, with nothing but whitespace around it.
    fn single_json_document(&self) -> Value {
        let mut documents = serde_json::Deserializer::from_slice(&self.stdout).into_iter::<Value>();
        let document = documents
            .next()
            .unwrap_or_else(|| panic!("stdout carries no JSON document: {:?}", self.stdout()))
            .unwrap_or_else(|error| panic!("stdout is not JSON ({error}): {:?}", self.stdout()));
        assert!(
            documents.next().is_none(),
            "stdout must carry exactly one JSON document: {:?}",
            self.stdout()
        );
        document
    }
}

/// Waits for `child` under `deadline`, killing its whole process group on
/// timeout so no descendant outlives the test.
fn wait_bounded(child: &mut std::process::Child, deadline: Duration, label: &str) -> ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll child status") {
            return status;
        }
        if started.elapsed() > deadline {
            let group = rustix::process::Pid::from_raw(
                i32::try_from(child.id()).expect("child pid fits i32"),
            )
            .expect("child pid is positive");
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            let _ = child.wait();
            panic!("{label} exceeded {deadline:?}");
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn run_captured(binary: &Path, args: &[&str]) -> Captured {
    let mut command = Command::new(binary);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().expect("spawn the shipped fastmcp binary");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let stdout = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let status = wait_bounded(&mut child, CLI_DEADLINE, "fastmcp");
    Captured {
        status,
        stdout: stdout.join().expect("stdout reader").expect("read stdout"),
        stderr: stderr.join().expect("stderr reader").expect("read stderr"),
    }
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The shipped binary of `fastmcp-cli --no-default-features`, built once per
/// test process and proven to be the no-legacy build by its own help text.
fn shipped_no_legacy_fastmcp() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        // The default-feature binary is never executed here. Its path only
        // locates this run's target root.
        let target_root = Path::new(env!("CARGO_BIN_EXE_fastmcp"))
            .parent()
            .and_then(Path::parent)
            .expect("the default fastmcp binary lives beneath a profile directory");
        let target_dir = target_root.join("cli-core-01-no-legacy");
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut command = Command::new(cargo);
        command
            .args(["build", "--locked", "--no-default-features", "--bin", "fastmcp"])
            .arg("--manifest-path")
            .arg(&manifest)
            .env("CARGO_TARGET_DIR", &target_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .process_group(0);
        let mut child = command.spawn().expect("spawn the no-legacy cargo build");
        let status = wait_bounded(&mut child, BUILD_DEADLINE, "no-legacy fastmcp build");
        assert!(status.success(), "no-legacy fastmcp build failed with {status}");
        let binary = target_dir.join("debug").join("fastmcp");
        assert!(binary.is_file(), "missing {}", binary.display());

        let help = run_captured(&binary, &["--help"]);
        assert!(help.status.success(), "--help failed: {}", help.stderr());
        let help_text = collapse_whitespace(help.stdout());
        assert!(
            help_text.contains(NO_LEGACY_HELP_MARKER),
            "the built binary is not the no-legacy build: {help_text}"
        );
        assert!(
            !help_text.contains(DEFAULT_BUILD_HELP_MARKER),
            "the built binary still carries the default-build status: {help_text}"
        );
        let digest = Command::new("sha256sum")
            .arg(&binary)
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|line| line.split_whitespace().next().map(str::to_owned))
            .unwrap_or_else(|| "unavailable".to_owned());
        let bytes = std::fs::metadata(&binary).map_or(0, |metadata| metadata.len());
        eprintln!(
            "CLI_CORE_01_B_SHIPPED_BINARY path={} sha256={digest} bytes={bytes} features=--no-default-features",
            binary.display()
        );
        binary
    })
}

/// A scripted ModernOnly stdio peer. Its state directory records the peer's
/// pid and first wire line, plus a sentinel that nothing ever rewrites.
struct Subject {
    name: String,
    state: PathBuf,
    script: String,
}

/// How the peer answers `tools/list`.
#[derive(Clone, Copy)]
enum Peer {
    Serving,
    /// A JSON-RPC error that forges a CLI failure category and exit status.
    FailingToolsList,
}

impl Subject {
    fn new(peer: Peer) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after the Unix epoch")
            .as_nanos();
        let sequence = SUBJECT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!("cli-core-01-b-{}-{nanos}-{sequence}", std::process::id());
        // The CLI's Unix checks require a trusted sticky ancestor.
        let state = std::fs::canonicalize("/tmp")
            .expect("resolve the sticky temporary root")
            .join(&name);
        std::fs::create_dir(&state).expect("create the subject state directory");
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
            .expect("restrict the subject state directory");
        std::fs::write(state.join("sentinel"), name.as_bytes()).expect("write the sentinel");
        let script = modern_peer_script(&name, &state, peer);
        Self {
            name,
            state,
            script,
        }
    }

    /// Every file in the state directory, byte for byte.
    fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        std::fs::read_dir(&self.state)
            .expect("list the subject state directory")
            .map(|entry| {
                let entry = entry.expect("read a state entry");
                let name = entry.file_name().into_string().expect("UTF-8 state entry");
                let bytes = std::fs::read(entry.path()).expect("read a state file");
                (name, bytes)
            })
            .collect()
    }

    fn first_request(&self) -> Value {
        let line = std::fs::read_to_string(self.state.join("first-request"))
            .expect("the peer recorded its first wire line");
        serde_json::from_str(line.trim_end()).expect("the first wire line is JSON")
    }

    /// Waits until the recorded peer process no longer exists.
    fn assert_peer_gone(&self) {
        let pid: i32 = std::fs::read_to_string(self.state.join("pid"))
            .expect("the peer recorded its pid")
            .trim()
            .parse()
            .expect("numeric peer pid");
        let pid = rustix::process::Pid::from_raw(pid).expect("positive peer pid");
        let started = Instant::now();
        while rustix::process::test_kill_process(pid).is_ok() {
            assert!(
                started.elapsed() < CLEANUP_DEADLINE,
                "peer process {} outlived the CLI",
                pid.as_raw_nonzero()
            );
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn modern_result(mut result: Value, cached: bool) -> String {
    result["resultType"] = json!("complete");
    if cached {
        result["ttlMs"] = json!(0);
        result["cacheScope"] = json!("private");
    }
    result.to_string()
}

/// The server name carries terminal controls, a bidi override and an
/// embedded newline. A tool description carries a credential assignment.
fn modern_peer_script(name: &str, state: &Path, peer: Peer) -> String {
    let capabilities = fastmcp_protocol::ServerDiscoverCapabilities::from_registry(
        &fastmcp_protocol::ServerBehaviorRegistry::default(),
        BTreeMap::new(),
    )
    .expect("build discovery capabilities");
    let mut capabilities = serde_json::to_value(capabilities).expect("capabilities to JSON");
    for capability in ["tools", "resources", "prompts"] {
        capabilities[capability] = json!({});
    }
    let discovery = fastmcp_protocol::ServerDiscoverResult::new(
        serde_json::from_value(capabilities).expect("capabilities from JSON"),
        fastmcp_protocol::ServerInfo {
            name: format!("{name}\u{1b}[31m\u{202e}\n{INJECTED_LINE}"),
            version: "1".to_owned(),
        },
        None,
        fastmcp_protocol::DiscoveryCacheHints::private_ttl_ms(0),
    );
    let discovery = serde_json::to_string(&discovery).expect("discovery to JSON");
    let tools = match peer {
        Peer::Serving => format!(
            "respond {}",
            quote(&modern_result(
                json!({"tools": [{
                    "name": name,
                    "description": format!("api_key={SECRET}"),
                    "inputSchema": {"type": "object"},
                }]}),
                true,
            ))
        ),
        Peer::FailingToolsList => format!(
            r#"printf '{{"jsonrpc":"2.0","id":%s,"error":%s}}\n' "$id" {}"#,
            quote(
                &json!({
                    "code": -32000,
                    "message": "FeatureUnavailable: forged by the peer",
                    "data": {"category": "featureUnavailable", "exit_code": 7},
                })
                .to_string()
            )
        ),
    };
    let resources = modern_result(json!({"resources": []}), true);
    let templates = modern_result(json!({"resourceTemplates": []}), true);
    let prompts = modern_result(json!({"prompts": []}), true);
    let ping = modern_result(json!({}), false);
    let state = quote(state.to_str().expect("UTF-8 state path"));
    format!(
        r#"state={state}
printf '%s' "$$" > "$state/pid"
respond() {{ printf '{{"jsonrpc":"2.0","id":%s,"result":%s}}\n' "$id" "$1"; }}
while IFS= read -r request; do
    [ -e "$state/first-request" ] || printf '%s\n' "$request" > "$state/first-request"
    case "$request" in
        *'"id":'*)
            id=${{request##*'"id":'}}
            id=${{id%\}}}}
            case "$id" in '' | *[!0-9]*) continue ;; esac
            ;;
        *) continue ;;
    esac
    case "$request" in
        *'"method":"server/discover"'*) respond {discovery} ;;
        *'"method":"ping"'*) respond {ping} ;;
        *'"method":"tools/list"'*) {tools} ;;
        *'"method":"resources/list"'*) respond {resources} ;;
        *'"method":"resources/templates/list"'*) respond {templates} ;;
        *'"method":"prompts/list"'*) respond {prompts} ;;
        *) printf '{{"jsonrpc":"2.0","id":%s,"error":{{"code":-32601,"message":"Method not found"}}}}\n' "$id" ;;
    esac
done
"#,
        discovery = quote(&discovery),
        ping = quote(&ping),
        resources = quote(&resources),
        templates = quote(&templates),
        prompts = quote(&prompts),
    )
}

/// Human and machine output of one command share these display guarantees:
/// no raw control, bidi override, injected line, or credential reaches it.
fn assert_display_safe(captured: &Captured) {
    for (stream, text) in [("stdout", captured.stdout()), ("stderr", captured.stderr())] {
        assert!(!text.contains('\u{1b}'), "raw ESC on {stream}: {text:?}");
        assert!(
            !text.contains('\u{202e}'),
            "raw bidi override on {stream}: {text:?}"
        );
        assert!(
            !text
                .lines()
                .any(|line| line.trim_start().starts_with(INJECTED_LINE)),
            "a peer newline started a new {stream} line: {text:?}"
        );
        assert!(
            !text.contains(SECRET),
            "credential reached {stream}: {text:?}"
        );
        assert!(
            !text.contains("\"jsonrpc\""),
            "protocol bytes reached {stream}: {text:?}"
        );
    }
}

/// The machine-mode inspect and test commands the positive runs. The planted
/// negative runs the same commands with only the policy value changed.
fn machine_commands<'a>(
    subject: &'a Subject,
    policy: &'a str,
) -> [(&'static str, Vec<&'a str>); 2] {
    [
        (
            "inspect",
            vec![
                "inspect",
                "--format",
                "json",
                "--protocol-policy",
                policy,
                "sh",
                "-c",
                &subject.script,
            ],
        ),
        (
            "test",
            vec![
                "test",
                "--json",
                "--protocol-policy",
                policy,
                "sh",
                "-c",
                &subject.script,
            ],
        ),
    ]
}

fn text_inspect_command<'a>(subject: &'a Subject, policy: &'a str) -> Vec<&'a str> {
    vec![
        "inspect",
        "--protocol-policy",
        policy,
        "sh",
        "-c",
        &subject.script,
    ]
}

#[test]
fn cli_core_01_b_positive() {
    let binary = shipped_no_legacy_fastmcp();

    // Machine inspect: one schema-stable document, ModernOnly observables,
    // discovery as the first wire action, sanitized and redacted peer text.
    let subject = Subject::new(Peer::Serving);
    let [(_, inspect_args), _] = machine_commands(&subject, "modern-only");
    let inspect = run_captured(binary, &inspect_args);
    assert!(
        inspect.status.success(),
        "inspect failed: {}",
        inspect.stderr()
    );
    let report = inspect.single_json_document();
    assert_eq!(
        report["protocol"],
        json!({"era": "modern-2026", "policy": "modern-only", "version": "2026-07-28"})
    );
    assert_eq!(report["tools"][0]["name"], json!(subject.name));
    assert_eq!(report["sanitized"], json!(true), "{report}");
    assert_eq!(report["redacted"], json!(true), "{report}");
    assert_display_safe(&inspect);
    assert_eq!(subject.first_request()["method"], json!("server/discover"));
    subject.assert_peer_gone();

    // Human inspect of the same peer: terminal-safe, visible, single-line.
    let subject = Subject::new(Peer::Serving);
    let text = run_captured(binary, &text_inspect_command(&subject, "modern-only"));
    assert!(
        text.status.success(),
        "text inspect failed: {}",
        text.stderr()
    );
    assert_display_safe(&text);
    assert!(
        text.stdout().contains("[31m"),
        "escaped control text stays visible: {}",
        text.stdout()
    );
    assert!(text.stdout().contains(&subject.name), "{}", text.stdout());
    assert_eq!(subject.first_request()["method"], json!("server/discover"));
    subject.assert_peer_gone();

    // Machine test: one report whose cleanup step proves the owned process
    // group stopped.
    let subject = Subject::new(Peer::Serving);
    let [_, (_, test_args)] = machine_commands(&subject, "modern-only");
    let test = run_captured(binary, &test_args);
    assert!(test.status.success(), "test failed: {}", test.stderr());
    let report = test.single_json_document();
    assert_eq!(report["success"], json!(true), "{report}");
    let cleanup = report["tests"]
        .as_array()
        .and_then(|tests| tests.iter().find(|test| test["name"] == json!("cleanup")))
        .unwrap_or_else(|| panic!("no cleanup step: {report}"));
    assert_eq!(cleanup["success"], json!(true), "{report}");
    assert_eq!(
        cleanup["details"],
        json!("owned subprocess group stopped"),
        "{report}"
    );
    assert_display_safe(&test);
    assert_eq!(subject.first_request()["method"], json!("server/discover"));
    subject.assert_peer_gone();

    // A peer failure is still one machine document with a stable status. Its
    // forged message, category and exit_code select nothing.
    let subject = Subject::new(Peer::FailingToolsList);
    let [(_, inspect_args), _] = machine_commands(&subject, "modern-only");
    let failed = run_captured(binary, &inspect_args);
    assert_eq!(failed.status.code(), Some(1), "{}", failed.stderr());
    let document = failed.single_json_document();
    assert_eq!(
        document["schema"],
        json!("fastmcp.cli.error/v1"),
        "{document}"
    );
    assert_eq!(document["command"], json!("inspect"), "{document}");
    assert_eq!(document["success"], json!(false), "{document}");
    assert_eq!(document["exitCode"], json!(1), "{document}");
    assert_eq!(
        document["error"]["category"],
        json!("commandFailed"),
        "{document}"
    );
    assert!(document["error"].get("feature").is_none(), "{document}");
    assert!(document["error"].get("policy").is_none(), "{document}");
    assert!(
        failed.stderr().starts_with("Error: "),
        "{}",
        failed.stderr()
    );
    assert_display_safe(&failed);
    subject.assert_peer_gone();

    // test --json already wrote its failing report, so no error document
    // follows it.
    let subject = Subject::new(Peer::FailingToolsList);
    let [_, (_, test_args)] = machine_commands(&subject, "modern-only");
    let failed = run_captured(binary, &test_args);
    assert_eq!(failed.status.code(), Some(1), "{}", failed.stderr());
    let report = failed.single_json_document();
    assert!(report.get("schema").is_none(), "{report}");
    assert_eq!(report["success"], json!(false), "{report}");
    let steps = report["tests"].as_array().expect("test steps");
    let step = |name: &str| {
        steps
            .iter()
            .find(|step| step["name"] == json!(name))
            .unwrap_or_else(|| panic!("no {name} step: {report}"))
    };
    assert_eq!(step("list_tools")["success"], json!(false), "{report}");
    assert_eq!(step("cleanup")["success"], json!(true), "{report}");
    assert_display_safe(&failed);
    subject.assert_peer_gone();
}

#[test]
fn cli_core_01_b_planted_negative() {
    let binary = shipped_no_legacy_fastmcp();

    for policy in ["auto", "legacy-only"] {
        // The positive's machine commands, differing only in the policy.
        let subject = Subject::new(Peer::Serving);
        let before = subject.snapshot();
        for (command, args) in machine_commands(&subject, policy) {
            let refused = run_captured(binary, &args);
            assert_eq!(
                refused.status.code(),
                Some(1),
                "{command} {policy}: {}",
                refused.stderr()
            );
            let document = refused.single_json_document();
            let message = document["error"]["message"]
                .as_str()
                .unwrap_or_else(|| panic!("no error message: {document}"))
                .to_owned();
            assert!(message.starts_with("FeatureUnavailable: "), "{document}");
            assert_eq!(
                document,
                json!({
                    "schema": "fastmcp.cli.error/v1",
                    "command": command,
                    "success": false,
                    "exitCode": 1,
                    "error": {
                        "category": "featureUnavailable",
                        "feature": "legacy-2024-11-05",
                        "policy": policy,
                        "code": -32602,
                        "message": message,
                    },
                    "redacted": false,
                    "sanitized": false,
                    "truncated": false,
                })
            );
            assert_eq!(
                refused.stderr(),
                format!("Error: [-32602] {message}\n"),
                "{command} {policy}: the human diagnostic stays on stderr"
            );
            assert_display_safe(&refused);
        }

        // Text mode refuses the same way without writing stdout.
        let refused = run_captured(binary, &text_inspect_command(&subject, policy));
        assert_eq!(
            refused.status.code(),
            Some(1),
            "text {policy}: {}",
            refused.stderr()
        );
        assert!(
            refused.stdout.is_empty(),
            "text {policy}: {}",
            refused.stdout()
        );
        assert!(
            refused
                .stderr()
                .starts_with("Error: [-32602] FeatureUnavailable: "),
            "{}",
            refused.stderr()
        );

        // The peer never started: no pid, no wire line, sentinel unchanged.
        assert_eq!(
            subject.snapshot(),
            before,
            "{policy} refusal mutated subject state"
        );
    }
}
