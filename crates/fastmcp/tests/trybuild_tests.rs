//! Downstream compile tests for the facade and procedural macros using trybuild.
//!
//! These tests verify both facade consumers that must compile and macros that
//! produce clear compile errors for invalid usage patterns.

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

/// Facade feature selections that must compile from the manifest itself.
///
/// The default and ModernOnly probes prove that optional symbols do not leak
/// into the curated facade. The remaining entries cover every independently
/// selectable optional surface and each feature composite owned by the facade.
const FACADE_FEATURE_COMPILE_PROBES: &[(&str, &[&str])] = &[
    ("default", &[]),
    ("modern-only", &["--no-default-features"]),
    (
        "legacy",
        &["--no-default-features", "--features", "legacy-2024-11-05"],
    ),
    ("tasks", &["--no-default-features", "--features", "tasks"]),
    ("apps", &["--no-default-features", "--features", "apps"]),
    // Proxy without Tasks must not name the final-task listener re-exports.
    ("proxy", &["--no-default-features", "--features", "proxy"]),
    // The legacy composite also intentionally omits the Tasks-only listeners.
    (
        "proxy-legacy",
        &["--no-default-features", "--features", "proxy-legacy"],
    ),
    (
        "proxy-tasks",
        &["--no-default-features", "--features", "proxy-tasks"],
    ),
    (
        "websocket-experimental",
        &[
            "--no-default-features",
            "--features",
            "websocket-experimental",
        ],
    ),
    (
        "testing",
        &["--no-default-features", "--features", "testing"],
    ),
    (
        "testing-lab",
        &["--no-default-features", "--features", "testing-lab"],
    ),
    ("all-features", &["--all-features"]),
];

struct DownstreamFeatureSymbolProbe {
    name: &'static str,
    features: &'static [&'static str],
    source: &'static str,
    should_compile: bool,
    absent_feature_diagnostic: Option<&'static str>,
}

/// Each enabled profile has a near-identical feature-off negative. These are
/// real downstream crates, so a transitive or namespaced re-export leak is
/// rejected at the public facade boundary rather than merely by this crate's
/// internal feature compilation.
const DOWNSTREAM_FEATURE_SYMBOL_PROBES: &[DownstreamFeatureSymbolProbe] = &[
    DownstreamFeatureSymbolProbe {
        name: "apps-present",
        features: &["apps"],
        source: r#"
use mcp::{
    MCP_APPS_HTML_MIME_TYPE,
    McpAppsClientSettings,
    client::mcp_apps,
    modern::McpAppsUiResource as ModernMcpAppsUiResource,
    providers::McpAppsUiResource,
};

#[mcp::tool(ui(resource_uri = "ui://apps.example.test/weather", visibility = ["model", "app"]))]
fn apps_ui_tool() -> String {
    "weather".to_owned()
}

fn generic_client_host<T, P>(
    client: &mcp::modern::Client,
    transport: T,
    configuration: mcp::modern::McpAppsHostConfiguration,
    policy: P,
) -> Result<mcp::modern::McpAppsHost<T, P>, mcp::modern::McpAppsHostError>
where
    T: mcp::modern::McpAppsBridgeTransport,
    P: mcp::modern::McpAppsHostPolicy,
{
    client.mcp_apps_host(transport, configuration, policy)
}

fn generic_http_host<T, P>(
    client: &mcp::modern::HttpClient,
    transport: T,
    configuration: mcp::modern::McpAppsHostConfiguration,
    policy: P,
) -> Result<mcp::modern::McpAppsHost<T, P>, mcp::modern::McpAppsHostError>
where
    T: mcp::modern::McpAppsBridgeTransport,
    P: mcp::modern::McpAppsHostPolicy,
{
    client.mcp_apps_host(transport, configuration, policy)
}

pub fn probe() {
    let _: Option<McpAppsUiResource> = None;
    let _: Option<ModernMcpAppsUiResource> = None;
    let _: Option<mcp::modern::McpAppsInMemoryHostTransport> = None;
    let _: Option<mcp::modern::McpAppsInMemoryViewTransport> = None;
    let _ = McpAppsClientSettings::new(vec![MCP_APPS_HTML_MIME_TYPE.to_owned()]);
    let _ = mcp_apps::mcp_apps_in_memory_pair(1);
    let _ = <AppsUiTool as mcp::ToolHandler>::final_metadata(&AppsUiTool);
}
"#,
        should_compile: true,
        absent_feature_diagnostic: None,
    },
    DownstreamFeatureSymbolProbe {
        name: "apps-absent-root",
        features: &[],
        source: r#"
use mcp::McpAppsClientSettings;

pub fn probe() {
    let _: Option<McpAppsClientSettings> = None;
}
"#,
        should_compile: false,
        absent_feature_diagnostic: Some("McpAppsClientSettings"),
    },
    DownstreamFeatureSymbolProbe {
        name: "apps-absent-exact-legacy-namespace",
        features: &["apps", "legacy-2024-11-05"],
        source: r#"
use mcp::legacy_2024::McpAppsHost;

pub fn probe() {
    let _: Option<McpAppsHost<(), ()>> = None;
}
"#,
        should_compile: false,
        absent_feature_diagnostic: Some("McpAppsHost"),
    },
    DownstreamFeatureSymbolProbe {
        name: "apps-absent-protocol-namespace",
        features: &[],
        source: r#"
use mcp::protocol::extensions::MCP_APPS_HTML_MIME_TYPE;

pub fn probe() {
    let _: &str = MCP_APPS_HTML_MIME_TYPE;
}
"#,
        should_compile: false,
        absent_feature_diagnostic: Some("MCP_APPS_HTML_MIME_TYPE"),
    },
    DownstreamFeatureSymbolProbe {
        name: "apps-absent-root-extensions-namespace",
        features: &[],
        source: r#"
use mcp::extensions::MCP_APPS_HTML_MIME_TYPE;

pub fn probe() {
    let _: &str = MCP_APPS_HTML_MIME_TYPE;
}
"#,
        should_compile: false,
        absent_feature_diagnostic: Some("MCP_APPS_HTML_MIME_TYPE"),
    },
    DownstreamFeatureSymbolProbe {
        name: "apps-absent-modern-extensions-namespace",
        features: &[],
        source: r#"
use mcp::modern::extensions::MCP_APPS_HTML_MIME_TYPE;

pub fn probe() {
    let _: &str = MCP_APPS_HTML_MIME_TYPE;
}
"#,
        should_compile: false,
        absent_feature_diagnostic: Some("MCP_APPS_HTML_MIME_TYPE"),
    },
    DownstreamFeatureSymbolProbe {
        name: "apps-absent-private-protocol-namespace",
        features: &[],
        source: r#"
use mcp::__private::protocol::McpAppsBridgeError;

pub fn probe() {
    let _: Option<McpAppsBridgeError> = None;
}
"#,
        should_compile: false,
        absent_feature_diagnostic: Some("McpAppsBridgeError"),
    },
    DownstreamFeatureSymbolProbe {
        name: "apps-absent-extension-handler-installation",
        features: &[],
        source: r#"
use mcp::{ExtensionDescriptorRegistry, ExtensionHandlerRegistry};

pub fn probe() {
    let mut registry = ExtensionHandlerRegistry::new(ExtensionDescriptorRegistry::new());
    let _ = registry.install_official_mcp_apps();
}
"#,
        should_compile: false,
        absent_feature_diagnostic: Some("install_official_mcp_apps"),
    },
    DownstreamFeatureSymbolProbe {
        name: "modern-server-construction-present",
        features: &[],
        source: r#"
use mcp::modern::ServerBuilder;

pub fn probe() {
    let _ = ServerBuilder::new("modern-probe", "1.0.0");
}
"#,
        should_compile: true,
        absent_feature_diagnostic: None,
    },
    DownstreamFeatureSymbolProbe {
        name: "server-escape-root",
        features: &[],
        source: r#"
use mcp::ServerBuilder;

pub fn probe() {
    let _ = ServerBuilder::new("escaped", "1.0.0");
}
"#,
        should_compile: false,
        absent_feature_diagnostic: Some("ServerBuilder"),
    },
    DownstreamFeatureSymbolProbe {
        name: "server-escape-server-namespace",
        features: &[],
        source: r#"
use mcp::server::ServerBuilder;

pub fn probe() {
    let _ = ServerBuilder::new("escaped", "1.0.0");
}
"#,
        should_compile: false,
        absent_feature_diagnostic: Some("ServerBuilder"),
    },
    DownstreamFeatureSymbolProbe {
        name: "server-escape-private-namespace",
        features: &[],
        source: r#"
use mcp::__private::server::ServerBuilder;

pub fn probe() {
    let _ = ServerBuilder::new("escaped", "1.0.0");
}
"#,
        should_compile: false,
        absent_feature_diagnostic: Some("ServerBuilder"),
    },
    DownstreamFeatureSymbolProbe {
        name: "tasks-present",
        features: &["tasks"],
        source: r#"
use mcp::{FinalTaskId, FinalTaskRuntime};

pub fn probe() {
    let _: Option<FinalTaskId> = None;
    let _: Option<FinalTaskRuntime> = None;
}
"#,
        should_compile: true,
        absent_feature_diagnostic: None,
    },
    DownstreamFeatureSymbolProbe {
        name: "tasks-absent",
        features: &[],
        source: r#"
use mcp::{FinalTaskId, FinalTaskRuntime};

pub fn probe() {
    let _: Option<FinalTaskId> = None;
    let _: Option<FinalTaskRuntime> = None;
}
"#,
        should_compile: false,
        absent_feature_diagnostic: Some("FinalTaskId"),
    },
    DownstreamFeatureSymbolProbe {
        name: "proxy-present",
        features: &["proxy"],
        source: r#"
use mcp::{ProxyClient, ProxyUpstreamBinding};

pub fn probe() {
    let _: Option<ProxyClient> = None;
    let _: Option<ProxyUpstreamBinding> = None;
}
"#,
        should_compile: true,
        absent_feature_diagnostic: None,
    },
    DownstreamFeatureSymbolProbe {
        name: "proxy-absent",
        features: &[],
        source: r#"
use mcp::{ProxyClient, ProxyUpstreamBinding};

pub fn probe() {
    let _: Option<ProxyClient> = None;
    let _: Option<ProxyUpstreamBinding> = None;
}
"#,
        should_compile: false,
        absent_feature_diagnostic: Some("ProxyClient"),
    },
];

#[test]
fn facade_feature_profile_compile_probes() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = manifest_dir.join("Cargo.toml");
    let target_dir = cargo_target_dir(manifest_dir).join("facade-feature-compile-probes");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

    for (profile, arguments) in FACADE_FEATURE_COMPILE_PROBES {
        let mut command = Command::new(&cargo);
        command
            .arg("check")
            .arg("--locked")
            .arg("--offline")
            .arg("--manifest-path")
            .arg(&manifest)
            .args(*arguments)
            .env("CARGO_TARGET_DIR", &target_dir)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let status = run_bounded(
            command,
            &format!("facade feature compile probe ({profile})"),
            COMPILE_DEADLINE,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            status.success(),
            "facade feature compile probe {profile} failed with {status}",
        );
    }
}

#[test]
fn downstream_feature_symbol_probes() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let facade_path = toml_path(manifest_dir);
    let target_dir = cargo_target_dir(manifest_dir).join("downstream-feature-symbol-probes");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

    for probe in DOWNSTREAM_FEATURE_SYMBOL_PROBES {
        let fixture_root = target_dir.join(probe.name);
        let fixture_src = fixture_root.join("src");
        fs::create_dir_all(&fixture_src)
            .unwrap_or_else(|error| panic!("create {} fixture source: {error}", probe.name));

        let features = probe
            .features
            .iter()
            .map(|feature| format!("\"{feature}\""))
            .collect::<Vec<_>>()
            .join(", ");
        fs::write(
            fixture_root.join("Cargo.toml"),
            format!(
                r#"[package]
name = "fastmcp-downstream-feature-{}"
version = "0.0.0"
edition = "2024"
publish = false

[workspace]

[dependencies]
mcp = {{ package = "fastmcp-rust", path = "{facade_path}", default-features = false, features = [{features}] }}
"#,
                probe.name,
            ),
        )
        .unwrap_or_else(|error| panic!("write {} fixture manifest: {error}", probe.name));
        fs::write(fixture_src.join("lib.rs"), probe.source)
            .unwrap_or_else(|error| panic!("write {} fixture source: {error}", probe.name));

        let fixture_manifest = fixture_root.join("Cargo.toml");
        let fixture_target_dir = target_dir.join(format!("{}-target", probe.name));
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
            &format!("{} downstream feature lock generation", probe.name),
            COMPILE_DEADLINE,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            lock_status.success(),
            "{} downstream feature lock generation failed with {lock_status}",
            probe.name,
        );

        let diagnostic_path = fixture_root.join("check.stderr");
        let mut check_command = Command::new(&cargo);
        check_command
            .arg("check")
            .arg("--locked")
            .arg("--offline")
            .arg("--manifest-path")
            .arg(&fixture_manifest)
            .env("CARGO_TARGET_DIR", &fixture_target_dir)
            .stdout(Stdio::inherit());
        if probe.absent_feature_diagnostic.is_some() {
            let diagnostics = fs::File::create(&diagnostic_path).unwrap_or_else(|error| {
                panic!("create {} diagnostic capture: {error}", probe.name)
            });
            check_command.stderr(Stdio::from(diagnostics));
        } else {
            check_command.stderr(Stdio::inherit());
        }
        let label = format!("{} downstream feature symbol probe", probe.name);
        let status = run_bounded(check_command, &label, COMPILE_DEADLINE)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            status.success(),
            probe.should_compile,
            "{} downstream feature symbol probe expected success={}, got {}",
            probe.name,
            probe.should_compile,
            status,
        );
        if let Some(expected_diagnostic) = probe.absent_feature_diagnostic {
            let diagnostics = fs::read_to_string(&diagnostic_path)
                .unwrap_or_else(|error| panic!("read {} diagnostic capture: {error}", probe.name));
            assert!(
                diagnostics.contains(expected_diagnostic),
                "{} absent-feature probe must fail because `{expected_diagnostic}` is unavailable; diagnostics:\n{diagnostics}",
                probe.name,
            );
        }
    }
}

#[test]
fn compile_fail_tests() {
    if std::env::var_os(TRYBUILD_WORKER_ENV).as_deref() == Some(std::ffi::OsStr::new("1")) {
        let tests = trybuild::TestCases::new();
        tests.compile_fail("tests/trybuild/prompt_*.rs");
        tests.compile_fail("tests/trybuild/resource_*.rs");
        #[cfg(not(feature = "apps"))]
        tests.compile_fail("tests/trybuild/tool_apps_ui_unsupported.rs");
        tests.compile_fail("tests/trybuild/tool_invalid_timeout.rs");
        tests.compile_fail("tests/trybuild/tool_typed_return.rs");
        tests.compile_fail("tests/trybuild/tool_unknown_attr.rs");
        tests.compile_fail("tests/trybuild/tool_zero_timeout.rs");
        #[cfg(feature = "tasks")]
        {
            tests.compile_fail("tests/trybuild/tool_tasks_incompatible_return.rs");
            tests.compile_fail("tests/trybuild/tool_tasks_facade_outcome_required.rs");
            tests.pass("tests/trybuild_pass/tool_tasks_enabled.rs");
        }
        #[cfg(not(feature = "tasks"))]
        tests.compile_fail("tests/trybuild/tasks_disabled/tool_tasks_feature_disabled.rs");
        tests.compile_fail("tests/trybuild/websocket/*.rs");
        #[cfg(all(feature = "apps", feature = "legacy-2024-11-05"))]
        tests.pass("tests/trybuild_pass/facade_dual_era_consumer.rs");
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
/// `fastmcp-rust` facade.
#[test]
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

/// Compile a real downstream package that enables the Tasks macro directly
/// from `fastmcp-derive`, without a `fastmcp-rust` facade dependency.
#[test]
fn direct_derive_tasks_consumer_compiles() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("facade crate must be nested beneath the workspace");
    let target_dir = cargo_target_dir(manifest_dir);
    let fixture_root = target_dir.join("direct-derive-tasks-consumer");
    let fixture_src = fixture_root.join("src");
    fs::create_dir_all(&fixture_src).expect("create direct-derive consumer source directory");

    let derive_path = toml_path(&workspace_root.join("crates/fastmcp-macros"));
    let core_path = toml_path(&workspace_root.join("crates/fastmcp-core"));
    let protocol_path = toml_path(&workspace_root.join("crates/fastmcp-protocol"));
    let server_path = toml_path(&workspace_root.join("crates/fastmcp-server"));
    fs::write(
        fixture_root.join("Cargo.toml"),
        format!(
            r#"[package]
name = "fastmcp-direct-derive-tasks-consumer"
version = "0.0.0"
edition = "2024"
publish = false

[workspace]

[dependencies]
fastmcp-derive = {{ path = "{derive_path}", features = ["tasks"] }}
fastmcp-core = {{ path = "{core_path}" }}
fastmcp-protocol = {{ path = "{protocol_path}", features = ["tasks"] }}
fastmcp-server = {{ path = "{server_path}" }}
serde_json = "=1.0.151"
"#,
        ),
    )
    .expect("write direct-derive consumer manifest");
    fs::write(fixture_src.join("lib.rs"), DIRECT_DERIVE_TASKS_CONSUMER)
        .expect("write direct-derive consumer source");

    let fixture_manifest = fixture_root.join("Cargo.toml");
    let fixture_target_dir = target_dir.join("direct-derive-tasks-consumer-target");
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
        "direct-derive Tasks consumer offline lock generation",
        COMPILE_DEADLINE,
    )
    .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        lock_status.success(),
        "direct-derive Tasks consumer lock generation failed with {lock_status}"
    );

    let mut check_command = Command::new(cargo);
    check_command
        .arg("check")
        .arg("--locked")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(&fixture_manifest)
        .env("CARGO_TARGET_DIR", &fixture_target_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = run_bounded(
        check_command,
        "direct-derive Tasks consumer locked offline check",
        COMPILE_DEADLINE,
    )
    .unwrap_or_else(|error| panic!("{error}"));

    assert!(
        status.success(),
        "direct-derive Tasks consumer failed to compile with status {status}",
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

#[tool]
fn renamed_facade_final_task_tool() -> mcp::FinalToolOutcome {
    unreachable!("the renamed-facade probe compiles a final tool outcome without Tasks opt-in")
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

#[resource(uri = "facade://mrtr-resumable-resource")]
fn facade_mrtr_resumable_resource(
    completed_inputs: Option<&modern::MrtrCompletedInputs>,
) -> modern::FinalMethodOutcome<modern::FinalReadResourceResult> {
    let request_state = if completed_inputs.is_some() {
        "facade-mrtr-resource-resumed"
    } else {
        "facade-mrtr-resource-initial"
    };
    modern::FinalMethodOutcome::InputRequired(
        modern::InputRequiredResult::new(
            None,
            Some(request_state.to_owned()),
            mcp::ResultMeta::default(),
        )
        .expect("request state makes the renamed-facade MRTR resource result valid"),
    )
}

#[prompt]
fn facade_mrtr_resumable_prompt(
    completed_inputs: Option<&modern::MrtrCompletedInputs>,
) -> modern::FinalMethodOutcome<modern::FinalGetPromptResult> {
    let request_state = if completed_inputs.is_some() {
        "facade-mrtr-prompt-resumed"
    } else {
        "facade-mrtr-prompt-initial"
    };
    modern::FinalMethodOutcome::InputRequired(
        modern::InputRequiredResult::new(
            None,
            Some(request_state.to_owned()),
            mcp::ResultMeta::default(),
        )
        .expect("request state makes the renamed-facade MRTR prompt result valid"),
    )
}

fn assert_generated_surface() -> McpResult<()> {
    fn tool_handler<T: ToolHandler>(_: T) {}
    fn resource_handler<T: ResourceHandler>(_: T) {}
    fn prompt_handler<T: PromptHandler>(_: T) {}

    tool_handler(FacadeTool);
    tool_handler(RenamedFacadeFinalTaskTool);
    resource_handler(FacadeResourceResource);
    resource_handler(FacadeMrtrResumableResourceResource);
    prompt_handler(FacadePromptPrompt);
    prompt_handler(FacadeMrtrResumablePromptPrompt);
    let _ = ToolInput::json_schema();
    Ok(())
}

fn assert_renamed_facade_sealed_builders() {
    let _: fn(modern::ServerBuilder) -> McpResult<modern::Server> =
        modern::ServerBuilder::try_build;
    let _: fn(legacy_2024::ServerBuilder) -> McpResult<legacy_2024::Server> =
        legacy_2024::ServerBuilder::try_build;

    let modern_client = modern::client_builder()
        .max_retries(2)
        .retry_delay_ms(5)
        .working_dir(".")
        .env("FACADE_TEST", "1")
        .envs([("FACADE_TEST_TWO", "2")])
        .inherit_env(false)
        .auto_initialize(true)
        .owned_process_group(false);
    assert_eq!(modern_client.protocol_policy(), modern::ModernOnly);

    let modern_server = modern::server_builder("modern-facade", "1.0")
        .without_stats()
        .request_timeout(1)
        .list_page_size(1)
        .mask_error_details(true)
        .strict_input_validation(true)
        .resource_subscriptions()
        .instructions("renamed facade modern server")
        .without_banner()
        .build();
    let _: modern::Server = modern_server;

    let legacy_server = legacy_2024::server_builder("legacy-facade", "1.0")
        .without_stats()
        .request_timeout(1)
        .list_page_size(1)
        .mask_error_details(true)
        .strict_input_validation(true)
        .resource_subscriptions()
        .instructions("renamed facade legacy server")
        .without_banner()
        .build();
    let _: legacy_2024::Server = legacy_server;
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
    let _: Option<modern::InputRequiredResult> = None;
    let _: Option<modern::MrtrCompletedInputs> = None;
    let _: Option<modern::FinalMethodOutcome<modern::FinalReadResourceResult>> = None;
    let _: Option<modern::FinalMethodOutcome<modern::FinalGetPromptResult>> = None;
    let _: Option<LegacySseHttpClient> = None;
    let _: Option<modern::ContentBlock> = None;
    let _: Option<modern::ExtensionDescriptorRegistry> = None;
    let _: Option<modern::ServerDiscoverResult> = None;
    let final_meta = modern::FinalRequestMeta::new(modern::ClientCapabilities::default());
    assert_eq!(final_meta.protocol_version, modern::PROTOCOL_VERSION);
    let _: Option<modern::ClientInfo> = None;
    let _: Option<modern::RequestId> = None;
    let _: &str = modern::FINAL_PROTOCOL_VERSION_META_KEY;
    let _: Option<modern::FinalListParams> = None;
    let _: Option<modern::FinalCallToolParams> = None;
    let _: Option<modern::FinalReadResourceParams> = None;
    let _: Option<modern::FinalGetPromptParams> = None;
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
    let _: Option<modern::HttpClient> = None;
    let _: Option<modern::HttpClientConnectError> = None;
    let _: Option<modern::HttpServer> = None;
    let _: Option<modern::ModernHttpClientError> = None;
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
        completion: modern::FinalCompletionValues {
            values: vec!["boston".to_owned()],
            total: Some(modern::JsonInteger::from(1_i64)),
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
    assert_eq!(modern::client_builder().protocol_policy(), modern::ModernOnly);
}

fn assert_prelude_dual_era_surface() {
    use mcp::prelude::*;

    let _: Option<modern::FinalRequestMeta> = None;
    let _: Option<modern::FinalCallToolParams> = None;
    let _: Option<modern::ClientInfo> = None;
    let _: Option<modern::RequestId> = None;
    let _: Option<modern::HttpClient> = None;
    let _: Option<modern::MrtrExchangeRegistry> = None;
    let _: Option<modern::FinalCompletionParams> = None;
    let _: Option<modern::FinalCompletionResult> = None;
    let _: Option<legacy_2024::CallToolParams> = None;
    let _: Option<legacy_2024::LegacyCompletionParams> = None;
    let _: Option<legacy_2024::LegacyCompletionResult> = None;
}
"#;

const DIRECT_DERIVE_TASKS_CONSUMER: &str = r#"
use fastmcp_derive::tool;
use fastmcp_server::ToolHandler;

#[tool(tasks)]
fn direct_derive_tasks_opt_in() -> fastmcp_server::FinalToolOutcome {
    unreachable!("compile-only direct fastmcp-derive Tasks consumer")
}

fn assert_tool_handler<T: ToolHandler>(_: T) {}

fn direct_derive_tasks_opt_in_declares_tasks() {
    assert_tool_handler(DirectDeriveTasksOptIn);
    assert!(DirectDeriveTasksOptIn.declares_final_tasks());
}
"#;
