//! E2E tests for `fastmcp list`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn fastmcp_bin() -> String {
    env!("CARGO_BIN_EXE_fastmcp").to_string()
}

fn mktemp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!(
        "fastmcp-cli-{prefix}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&p).expect("create temp dir");
    p
}

fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir");
    }
    std::fs::write(path, content).unwrap();
}

fn run_cli(home: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(fastmcp_bin())
        .args(args)
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .current_dir(cwd)
        .output()
        .expect("run fastmcp")
}

fn stdout_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
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
    home.join(".config/Code/User/settings.json")
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
        r#"{"cline.mcpServers":{"cline-srv":{"command":"echo","args":["c"]}}}"#,
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
