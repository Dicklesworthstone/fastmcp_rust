//! E2E tests for `fastmcp install`.
//!
//! These tests run the compiled CLI binary and validate that `install`:
//! - Modifies the correct config file per target
//! - Creates a backup when overwriting an existing config
//! - Honors `--dry-run` by not touching the filesystem
//! - Fails cleanly on invalid JSON configs

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn get_binary_path() -> String {
    env!("CARGO_BIN_EXE_fastmcp").to_string()
}

fn run_cli_with_home(home: &Path, args: &[&str]) -> Output {
    Command::new(get_binary_path())
        .args(args)
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .env("HOME", home)
        .env("USERPROFILE", home) // used as fallback for cursor path on non-unix
        .output()
        .expect("failed to execute CLI binary")
}

fn stdout_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn mktemp_home(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!(
        "fastmcp-cli-{prefix}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&p).expect("create temp home");
    p
}

fn read_to_string(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => std::panic::panic_any(format!("read {}: {e}", path.display())),
    }
}

#[cfg(target_os = "linux")]
fn claude_path(home: &Path) -> PathBuf {
    home.join(".config/Claude/claude_desktop_config.json")
}

#[cfg(target_os = "linux")]
fn cursor_path(home: &Path) -> PathBuf {
    home.join(".cursor/mcp.json")
}

#[cfg(target_os = "linux")]
fn cline_path(home: &Path) -> PathBuf {
    home.join(".config/Code/User/settings.json")
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_claude_modifies_config_and_creates_backup() {
    let home = mktemp_home("install-claude");
    let path = claude_path(&home);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    let original = r#"{"mcpServers":{"existing":{"command":"x","args":[]}}}"#;
    std::fs::write(&path, original).unwrap();

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
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
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_claude_dry_run_does_not_touch_files() {
    let home = mktemp_home("install-claude-dry");
    let path = claude_path(&home);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    let original = r#"{"mcpServers":{"existing":{"command":"x","args":[]}}}"#;
    std::fs::write(&path, original).unwrap();

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
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    let original = r#"{"mcpServers":{"existing":{"command":"x","args":[]}}}"#;
    std::fs::write(&path, original).unwrap();

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
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_cline_modifies_vscode_settings_and_creates_backup() {
    let home = mktemp_home("install-cline");
    let path = cline_path(&home);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    let original =
        r#"{"editor.tabSize": 2, "cline.mcpServers": {"existing": {"command":"x","args":[]}}}"#;
    std::fs::write(&path, original).unwrap();

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
    assert_eq!(json.get("editor.tabSize").and_then(|v| v.as_i64()), Some(2));

    let servers = json
        .get("cline.mcpServers")
        .and_then(|v| v.as_object())
        .expect("cline.mcpServers must be an object");
    assert!(servers.contains_key("existing"));
    assert!(servers.contains_key("my-server"));
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
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_install_invalid_json_fails_cleanly() {
    let home = mktemp_home("install-invalid-json");
    let path = claude_path(&home);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    std::fs::write(&path, "{not valid json").unwrap();

    let output = run_cli_with_home(
        &home,
        &["install", "my-server", "/bin/echo", "--target", "claude"],
    );
    assert!(!output.status.success(), "expected non-zero exit");

    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("config") || stderr.contains("JSON") || stderr.contains("parse"),
        "expected parse error in stderr, got: {stderr}"
    );
}
