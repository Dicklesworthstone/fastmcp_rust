//! Compile-fail tests for procedural macros using trybuild.
//!
//! These tests verify that macros produce clear compile errors
//! for invalid usage patterns.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

const COMPILE_DEADLINE: Duration = Duration::from_secs(10 * 60);
const PROCESS_CLEANUP_DEADLINE: Duration = Duration::from_secs(2);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(100);
#[cfg(unix)]
const PROCESS_TERM_GRACE: Duration = Duration::from_millis(500);
const TRYBUILD_WORKER_ENV: &str = "FASTMCP_TRYBUILD_BOUNDED_WORKER";

#[test]
fn compile_fail_tests() {
    if std::env::var_os(TRYBUILD_WORKER_ENV).as_deref() == Some(std::ffi::OsStr::new("1")) {
        let tests = trybuild::TestCases::new();
        tests.compile_fail("tests/trybuild/*.rs");
        return;
    }

    // trybuild owns nested Cargo processes internally and exposes no timeout.
    // Run the ordinary suite in an exact, recursively selected copy of this
    // test binary so the parent can bound and clean up the whole process group.
    let mut command = Command::new(std::env::current_exe().expect("resolve current test binary"));
    command
        .args(["--exact", "compile_fail_tests", "--nocapture"])
        .env(TRYBUILD_WORKER_ENV, "1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = run_bounded(command, "trybuild compile-fail worker", COMPILE_DEADLINE)
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(status.success(), "trybuild worker exited with {status}");
}

/// Compile a real downstream package whose only dependency is a renamed
/// `fastmcp-rust` facade. This is intentionally an explicit packaging gate:
/// it launches nested Cargo with an isolated target directory and would make
/// every ordinary workspace test run unnecessarily expensive.
#[test]
#[ignore = "explicit facade-only downstream compile gate"]
fn renamed_facade_only_consumer_compiles_every_macro_family() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let target_dir = cargo_target_dir(manifest_dir);
    let fixture_root = target_dir.join("facade-only-renamed-consumer");
    let fixture_src = fixture_root.join("src");
    fs::create_dir_all(&fixture_src).expect("create facade-only consumer source directory");

    let facade_path = toml_path(manifest_dir);
    fs::write(
        fixture_root.join("Cargo.toml"),
        format!(
            r#"[package]
name = "fastmcp-facade-only-renamed-consumer"
version = "0.0.0"
edition = "2024"
publish = false

[workspace]

[dependencies]
mcp = {{ package = "fastmcp-rust", path = "{facade_path}" }}
"#,
        ),
    )
    .expect("write facade-only consumer manifest");
    fs::write(fixture_src.join("lib.rs"), FACADE_ONLY_CONSUMER)
        .expect("write facade-only consumer source");

    let fixture_manifest = fixture_root.join("Cargo.toml");
    let fixture_target_dir = target_dir.join("facade-only-renamed-consumer-target");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut lock_command = Command::new(&cargo);
    lock_command
        .arg("generate-lockfile")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(&fixture_manifest)
        .env("CARGO_TARGET_DIR", &fixture_target_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let lock_status = run_bounded(
        lock_command,
        "facade-only consumer offline lock generation",
        COMPILE_DEADLINE,
    )
    .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        lock_status.success(),
        "facade-only consumer lock generation failed with {lock_status}"
    );

    let mut check_command = Command::new(cargo);
    check_command
        .arg("check")
        .arg("--locked")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(&fixture_manifest)
        // Nested Cargo must not contend on the outer test invocation's target
        // lock. The fixed sibling directory remains reusable across explicit
        // gate runs without multiplying per-run artifact trees.
        .env("CARGO_TARGET_DIR", &fixture_target_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = run_bounded(
        check_command,
        "facade-only consumer locked offline check",
        COMPILE_DEADLINE,
    )
    .unwrap_or_else(|error| panic!("{error}"));

    assert!(
        status.success(),
        "facade-only consumer failed to compile with status {status}",
    );
}

fn run_bounded(mut command: Command, label: &str, timeout: Duration) -> Result<ExitStatus, String> {
    let mut process = OwnedProcessGroup::spawn(&mut command)
        .map_err(|error| format!("failed to start {label}: {error}"))?;
    process.wait_until(label, timeout)
}

struct OwnedProcessGroup {
    child: Option<Child>,
    #[cfg(unix)]
    process_group_id: u32,
    owns_process_group: bool,
    armed: bool,
}

impl OwnedProcessGroup {
    fn spawn(command: &mut Command) -> std::io::Result<Self> {
        configure_process_group(command);
        let child = command.spawn()?;
        #[cfg(unix)]
        let process_group_id = child.id();
        Ok(Self {
            child: Some(child),
            #[cfg(unix)]
            process_group_id,
            owns_process_group: true,
            armed: true,
        })
    }

    fn wait_until(&mut self, label: &str, timeout: Duration) -> Result<ExitStatus, String> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        loop {
            match self.child_has_exited("failed to inspect bounded child") {
                Ok(true) => {
                    return self
                        .terminate()
                        .map_err(|error| {
                            format!("failed to clean up {label} descendants after exit: {error}")
                        })?
                        .ok_or_else(|| {
                            format!("observed exited {label} child had no exit status")
                        });
                }
                Ok(false) if Instant::now() < deadline => {
                    std::thread::sleep(PROCESS_POLL_INTERVAL);
                }
                Ok(false) => {
                    let cleanup = self.terminate().err();
                    return Err(format!(
                        "{label} exceeded its {timeout:?} deadline; cleanup error: {cleanup:?}"
                    ));
                }
                Err(error) => {
                    // Once wait ownership is uncertain, never send another
                    // numeric PID or process-group signal.
                    self.owns_process_group = false;
                    self.armed = false;
                    return Err(format!(
                        "failed to inspect {label}; guard disarmed without signaling: {error}"
                    ));
                }
            }
        }
    }

    fn child_has_exited(&mut self, context: &str) -> Result<bool, String> {
        #[cfg(unix)]
        {
            return process_is_zombie(
                self.child
                    .as_ref()
                    .expect("owned process guard is armed")
                    .id(),
            )
            .map_err(|error| format!("{context}: {error}"));
        }
        #[cfg(not(unix))]
        {
            match self
                .child
                .as_mut()
                .expect("owned process guard is armed")
                .try_wait()
            {
                Ok(Some(_)) => Ok(true),
                Ok(None) => Ok(false),
                Err(error) => Err(format!("{context}: {error}")),
            }
        }
    }

    fn process_group_has_live_member(&self) -> Result<bool, String> {
        #[cfg(unix)]
        {
            if self.owns_process_group {
                return process_group_has_live_member(self.process_group_id);
            }
        }
        Ok(false)
    }

    fn wait_for_cleanup_state(&mut self, deadline: Instant) -> Result<(bool, bool), String> {
        loop {
            let child_exited = self.child_has_exited("failed to inspect exact child")?;
            let group_live = self.process_group_has_live_member()?;
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
        #[cfg(not(unix))]
        {
            // Without an OS process-group API in std, cleanup can only target
            // the exact child on non-Unix platforms; detached descendants are
            // outside this harness's portable containment boundary.
            let _ = self.owns_process_group;
        }
        let mut child_exited = match self.child_has_exited("failed to inspect exact child") {
            Ok(exited) => exited,
            Err(error) => {
                self.owns_process_group = false;
                self.armed = false;
                return Err(format!("{error}; guard disarmed without signaling"));
            }
        };
        // On Unix, child_has_exited observes zombie state without wait(2).
        // The live/zombie leader therefore pins its PGID until every group
        // signal and membership check is complete. Non-Unix has no group
        // signaling and may use try_wait directly.
        let mut group_live = match self.process_group_has_live_member() {
            Ok(live) => live,
            Err(error) => {
                self.owns_process_group = false;
                self.armed = false;
                return Err(format!(
                    "failed to inspect owned process group; guard disarmed without signaling: {error}"
                ));
            }
        };

        #[cfg(unix)]
        if group_live {
            if let Err(error) = signal_process_group(self.process_group_id, "-TERM") {
                self.owns_process_group = false;
                self.armed = false;
                return Err(format!(
                    "TERM process group: {error}; guard disarmed without further signaling"
                ));
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
                    if let Err(error) = signal_process_group(self.process_group_id, "-KILL") {
                        self.owns_process_group = false;
                        self.armed = false;
                        return Err(format!(
                            "KILL process group: {error}; guard disarmed without further signaling"
                        ));
                    }
                }
            }
        }

        if !child_exited {
            match self.child_has_exited("failed to inspect exact child before direct kill") {
                Ok(true) => {}
                Ok(false) => {
                    direct_kill_error = self
                        .child
                        .as_mut()
                        .expect("owned process guard is armed")
                        .kill()
                        .err();
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
                errors.push(format!("kill exact child: {error}"));
            }
            errors.push(format!(
                "exact child did not exit within {PROCESS_CLEANUP_DEADLINE:?}"
            ));
        }
        if group_live {
            errors.push(format!(
                "owned process group still has live members after {PROCESS_CLEANUP_DEADLINE:?}"
            ));
        }
        let exit_status = match self
            .child
            .as_mut()
            .expect("owned process guard is armed")
            .try_wait()
        {
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

impl Drop for OwnedProcessGroup {
    fn drop(&mut self) {
        if let Err(error) = self.terminate() {
            eprintln!("trybuild harness process cleanup failed: {error}");
        }
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn signal_process_group(process_group: u32, signal: &str) -> Result<(), String> {
    let group = format!("-{process_group}");
    let status = Command::new("/bin/kill")
        .arg(signal)
        .arg("--")
        .arg(group)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("failed to execute /bin/kill: {error}"))?;
    if status.success() || !process_group_has_live_member(process_group)? {
        return Ok(());
    }
    Err(format!("kill exited with status {status}"))
}

#[cfg(target_os = "linux")]
fn process_group_has_live_member(process_group_id: u32) -> Result<bool, String> {
    let processes =
        fs::read_dir("/proc").map_err(|error| format!("failed to enumerate /proc: {error}"))?;
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
        let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
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
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
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

fn cargo_target_dir(manifest_dir: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || {
            manifest_dir
                .parent()
                .and_then(Path::parent)
                .expect("facade crate must be nested beneath the workspace")
                .join("target")
        },
        PathBuf::from,
    )
}

fn toml_path(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

const FACADE_ONLY_CONSUMER: &str = r#"
#![allow(dead_code)]

use mcp::{
    ClientHttpNegotiation, CompleteResult, ConfigLoader, Content, JsonSchema, McpConfig,
    McpResult, FinalRequestMeta, LegacySseHttpClient, ModernHttpClient, ModernHttpExecutor,
    ModernHttpRequest, MrtrExchangeRegistry, PromptHandler, PromptMessage, ProtocolPolicy,
    ResourceHandler, Role, ServerConfig, ToolHandler, legacy_2024, modern, prompt, resource,
    tool,
};

#[derive(JsonSchema)]
struct ToolInput {
    count: u64,
    label: Option<String>,
}

#[tool]
fn facade_tool(count: u64) -> String {
    count.to_string()
}

#[resource(uri = "facade://status")]
fn facade_resource() -> String {
    "ready".to_string()
}

#[prompt]
fn facade_prompt(name: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::text(name),
    }]
}

fn assert_generated_surface() -> McpResult<()> {
    fn tool_handler<T: ToolHandler>(_: T) {}
    fn resource_handler<T: ResourceHandler>(_: T) {}
    fn prompt_handler<T: PromptHandler>(_: T) {}

    tool_handler(FacadeTool);
    resource_handler(FacadeResourceResource);
    prompt_handler(FacadePromptPrompt);
    let _ = ToolInput::json_schema();
    Ok(())
}

fn assert_dual_era_facade_surface() {
    let request = ModernHttpRequest::new(
        "https://mcp.example.test/mcp",
        b"{}".to_vec(),
        modern::PROTOCOL_VERSION,
        modern::SERVER_DISCOVER_METHOD,
        None,
    )
    .expect("facade modern HTTP executor types compile");
    assert!(request.headers().iter().any(|(name, _)| name == "Mcp-Method"));
    let _executor = ModernHttpExecutor::new();

    let mut config = McpConfig::new();
    config.add_server("final", ServerConfig::new("final-mcp"));
    assert_eq!(config.server_names(), vec!["final"]);
    let _: Option<ConfigLoader> = None;
    let _: Option<ClientHttpNegotiation> = None;
    let _: Option<CompleteResult<()>> = None;
    let _: Option<FinalRequestMeta> = None;
    let _: Option<ModernHttpClient> = None;
    let _: Option<MrtrExchangeRegistry> = None;
    let _: Option<LegacySseHttpClient> = None;
    let _: Option<modern::ContentBlock> = None;
    let _: Option<modern::ExtensionDescriptorRegistry> = None;
    let _: Option<modern::ServerDiscoverResult> = None;
    let _: Option<modern::InboundRequestContext> = None;
    let final_meta = modern::FinalRequestMeta::new(modern::ClientCapabilities::default());
    assert_eq!(final_meta.protocol_version, modern::PROTOCOL_VERSION);
    let _: Option<modern::ClientInfo> = None;
    let _: Option<modern::RequestId> = None;
    let _: &str = modern::FINAL_PROTOCOL_VERSION_META_KEY;
    let _: Option<modern::FinalListParams> = None;
    let _: Option<modern::FinalCallToolParams> = None;
    let _: Option<modern::FinalReadResourceParams> = None;
    let _: Option<modern::FinalGetPromptParams> = None;
    let _: Option<modern::FinalSetLogLevelParams> = None;
    let _: Option<modern::FinalEmptyParams> = None;
    let _: Option<modern::FinalListToolsResult> = None;
    let _: Option<modern::FinalCallToolResult> = None;
    let _: Option<modern::FinalListResourcesResult> = None;
    let _: Option<modern::FinalListResourceTemplatesResult> = None;
    let _: Option<modern::FinalReadResourceResult> = None;
    let _: Option<modern::FinalListPromptsResult> = None;
    let _: Option<modern::FinalPromptMessage> = None;
    let _: Option<modern::FinalGetPromptResult> = None;
    let _: Option<modern::FinalEmptyResult> = None;
    let _: Option<modern::FinalCoreRequest> = None;
    let _: Option<modern::FinalCoreResult> = None;
    let _: Option<modern::CoreRequest> = None;
    let _: Option<modern::CoreResult> = None;
    let _: Option<modern::CoreDispatchError> = None;
    let _: Option<modern::ModernHttpClient> = None;
    let _: Option<modern::ModernHttpConnectOutcome> = None;
    let _: Option<modern::ModernHttpClientError> = None;
    let _: Option<modern::ModernHttpSseResponseStream> = None;
    let final_completion = modern::FinalCompletionParams {
        meta: modern::OpenMetadata::default(),
        reference: modern::FinalCompletionReference::Prompt {
            name: "city".to_owned(),
        },
        argument: modern::FinalCompletionArgument {
            name: "prefix".to_owned(),
            value: "bo".to_owned(),
        },
        context: Some(modern::FinalCompletionContext::default()),
    };
    let final_completion_result = modern::FinalCompletionResult {
        completion: modern::CompletionValues {
            values: vec!["boston".to_owned()],
            total: Some(1),
            has_more: Some(false),
        },
    };
    assert_eq!(final_completion.argument.value, "bo");
    assert_eq!(final_completion_result.completion.values[0], "boston");
    let requests = modern::MrtrInputRequests::new([(
        "roots".to_owned(),
        modern::MrtrInputRequest::roots(),
    )])
    .expect("facade final MRTR input request types compile");
    assert_eq!(requests.len(), 1);
    let _registry = modern::MrtrExchangeRegistry::new();
    assert_eq!(modern::DEFAULT_MAX_MRTR_ROUNDS, 8);
    let _: Option<legacy_2024::CallToolParams> = None;
    let _: Option<legacy_2024::Legacy2024Lifecycle> = None;
    let _: Option<legacy_2024::LegacySseHttpClient> = None;
    let _: Option<legacy_2024::LegacySseHttpClientError> = None;
    let legacy_completion = legacy_2024::LegacyCompletionParams {
        reference: legacy_2024::LegacyCompletionReference::Resource {
            uri: "resource://cities".to_owned(),
        },
        argument: legacy_2024::LegacyCompletionArgument {
            name: "prefix".to_owned(),
            value: "bo".to_owned(),
        },
    };
    let legacy_completion_result = legacy_2024::LegacyCompletionResult {
        completion: legacy_2024::CompletionValues {
            values: vec!["boston".to_owned()],
            total: Some(1),
            has_more: Some(false),
        },
    };
    assert_eq!(legacy_completion.argument.value, "bo");
    assert_eq!(legacy_completion_result.completion.values[0], "boston");

    let uri = modern::AbsoluteUri::parse("https://mcp.example.test/final")
        .expect("facade final common types compile");
    assert_eq!(uri.as_str(), "https://mcp.example.test/final");
    assert_eq!(ProtocolPolicy::ModernOnly, modern::ProtocolPolicy::ModernOnly);
}

fn assert_legacy_sse_method_signatures(
    cx: &legacy_2024::Cx,
    plan: legacy_2024::ClientProtocolPlan,
    client: &mut legacy_2024::LegacySseHttpClient,
) {
    let message = legacy_2024::JsonRpcMessage::Request(legacy_2024::JsonRpcRequest::new(
        "initialize",
        None,
        legacy_2024::RequestId::Number(1),
    ));
    let _connect = legacy_2024::LegacySseHttpClient::connect(cx, plan);
    let _send = client.send(cx, &message);
    let _next_message = client.next_message(cx);
}

fn assert_prelude_dual_era_surface() {
    use mcp::prelude::*;

    let _: Option<modern::FinalRequestMeta> = None;
    let _: Option<modern::FinalCallToolParams> = None;
    let _: Option<modern::ClientInfo> = None;
    let _: Option<modern::RequestId> = None;
    let _: Option<modern::CoreRequest> = None;
    let _: Option<modern::ModernHttpClient> = None;
    let _: Option<modern::MrtrExchangeRegistry> = None;
    let _: Option<modern::FinalCompletionParams> = None;
    let _: Option<modern::FinalCompletionResult> = None;
    let _: Option<legacy_2024::CallToolParams> = None;
    let _: Option<legacy_2024::LegacyCompletionParams> = None;
    let _: Option<legacy_2024::LegacyCompletionResult> = None;
    let _: Option<legacy_2024::LegacySseHttpClient> = None;

    fn assert_legacy_sse_method_signatures_from_prelude(
        cx: &legacy_2024::Cx,
        plan: legacy_2024::ClientProtocolPlan,
        client: &mut legacy_2024::LegacySseHttpClient,
    ) {
        let message = legacy_2024::JsonRpcMessage::Request(legacy_2024::JsonRpcRequest::new(
            "initialize",
            None,
            legacy_2024::RequestId::Number(1),
        ));
        let _connect = legacy_2024::LegacySseHttpClient::connect(cx, plan);
        let _send = client.send(cx, &message);
        let _next_message = client.next_message(cx);
    }
}
"#;
