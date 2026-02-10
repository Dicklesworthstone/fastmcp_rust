//! E2E tests for `fastmcp dev`.
//!
//! These tests spin up `fastmcp dev` against a tiny throwaway Cargo project and
//! validate hot-reload behavior via file changes.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn init_cargo_project(root: &Path, body: &str) {
    write_file(
        &root.join("Cargo.toml"),
        r#"[package]
name = "fastmcp_dev_test_proj"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    );
    write_file(&root.join("src/main.rs"), body);
}

fn spawn_dev(args: &[&str]) -> (Child, mpsc::Receiver<String>) {
    let mut child = Command::new(fastmcp_bin())
        .args(args)
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .env("CARGO_TERM_COLOR", "never")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fastmcp dev");

    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");

    let (tx, rx) = mpsc::channel::<String>();

    let tx_out = tx.clone();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            let _ = tx_out.send(line);
        }
    });

    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });

    (child, rx)
}

fn wait_for_contains(rx: &mpsc::Receiver<String>, needle: &str, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    let mut tail: VecDeque<String> = VecDeque::with_capacity(50);
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                if tail.len() == 50 {
                    tail.pop_front();
                }
                tail.push_back(line.clone());
                if line.contains(needle) {
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let msg = format!(
        "timed out waiting for output containing {needle:?}. Last output:\n{}",
        tail.into_iter().collect::<Vec<_>>().join("\n")
    );
    assert!(msg.is_empty(), "{msg}");
}

fn assert_not_contains_for(rx: &mpsc::Receiver<String>, needle: &str, duration: Duration) {
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                if line.contains(needle) {
                    let msg = format!("unexpected output containing {needle:?}: {line}");
                    assert!(msg.is_empty(), "{msg}");
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_dev_no_reload_exits_for_cargo_project() {
    let root = mktemp_dir("dev-no-reload");
    init_cargo_project(
        &root,
        r#"fn main() {
    // Exits immediately.
    println!("dev-test-exit");
}"#,
    );

    let output = Command::new(fastmcp_bin())
        .args(["dev", "--no-reload", root.to_str().unwrap()])
        .env("FASTMCP_CHECK_FOR_UPDATES", "0")
        .env("CARGO_TERM_COLOR", "never")
        .output()
        .expect("run fastmcp dev --no-reload");

    assert!(output.status.success());
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_dev_hot_reload_rebuilds_on_matching_change() {
    let root = mktemp_dir("dev-hot-reload");
    init_cargo_project(
        &root,
        r#"use std::time::Duration;

fn main() {
    println!("dev-test-server-start");
    std::thread::sleep(Duration::from_secs(60));
}"#,
    );

    let (mut child, rx) = spawn_dev(&[
        "dev",
        "--debounce",
        "50",
        "--reload-dir",
        "src",
        "--reload-pattern",
        "src/main.rs",
        root.to_str().unwrap(),
    ]);

    wait_for_contains(&rx, "Watching for changes", Duration::from_secs(60));

    // Touch a matching file.
    let main_rs = root.join("src/main.rs");
    let mut content = std::fs::read_to_string(&main_rs).expect("read main.rs");
    content.push_str("\n// change to trigger reload\n");
    write_file(&main_rs, &content);

    wait_for_contains(&rx, "Change detected, rebuilding", Duration::from_secs(60));
    // After rebuild, `cargo run` should execute again and our test binary should print again.
    wait_for_contains(&rx, "dev-test-server-start", Duration::from_secs(60));

    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_dev_reload_patterns_prevent_unrelated_changes_from_rebuilding() {
    let root = mktemp_dir("dev-pattern-filter");
    init_cargo_project(
        &root,
        r#"use std::time::Duration;

fn main() {
    println!("dev-test-server-start");
    std::thread::sleep(Duration::from_secs(60));
}"#,
    );

    let (mut child, rx) = spawn_dev(&[
        "dev",
        "--debounce",
        "50",
        "--reload-dir",
        "src",
        "--reload-pattern",
        "src/main.rs",
        root.to_str().unwrap(),
    ]);

    wait_for_contains(&rx, "Watching for changes", Duration::from_secs(60));

    // Modify an unrelated file that should not match the pattern.
    let other_rs = root.join("src/ignored.rs");
    write_file(&other_rs, "pub fn ignored() {}\n");

    // Give the watcher some time to observe the change; we should NOT rebuild.
    assert_not_contains_for(
        &rx,
        "Change detected, rebuilding",
        Duration::from_millis(800),
    );

    let _ = child.kill();
    let _ = child.wait();
}
