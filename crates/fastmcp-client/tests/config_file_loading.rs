//! End-to-end file selection, byte limits, and fail-closed discovery.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fastmcp_client::mcp_config::{
    ConfigError, ConfigLoader, DEFAULT_MAX_CONFIG_FILE_BYTES, McpConfig,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

// No external test dependency and no recursive cleanup. The fixture only
// removes entries it created with create_new, then its own empty directories.
struct Scratch {
    root: PathBuf,
    files: Vec<PathBuf>,
    directories: Vec<PathBuf>,
}

impl Scratch {
    fn new() -> Self {
        for _ in 0..1_024 {
            let root = std::env::temp_dir().join(format!(
                "fastmcp-config-loader-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
            ));
            let result = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    fs::DirBuilder::new().mode(0o700).create(&root)
                }
                #[cfg(not(unix))]
                {
                    fs::create_dir(&root)
                }
            };
            match result {
                Ok(()) => {
                    return Self {
                        root,
                        files: Vec::new(),
                        directories: Vec::new(),
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create configuration test directory: {error}"),
            }
        }
        panic!("configuration test directory namespace exhausted");
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn write(&mut self, name: &str, content: &[u8]) -> PathBuf {
        let path = self.path(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("new fixture file");
        self.files.push(path.clone());
        file.write_all(content).expect("fixture contents");
        path
    }

    fn directory(&mut self, name: &str) {
        let path = self.path(name);
        fs::create_dir(&path).expect("new fixture subdirectory");
        self.directories.push(path);
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        for file in self.files.iter().rev() {
            let _ = fs::remove_file(file);
        }
        for directory in self.directories.iter().rev() {
            let _ = fs::remove_dir(directory);
        }
        let _ = fs::remove_dir(&self.root);
    }
}

fn assert_server(path: &Path, expected: &str) {
    let config = McpConfig::from_file(path).expect("configuration file");
    assert_eq!(config.get_server("local").unwrap().command, expected);
}

#[test]
fn explicit_file_loader_supports_toml_and_jsonc_without_json_fallback() {
    let mut scratch = Scratch::new();
    let toml = scratch.write("config.toml", b"[mcp_servers.local]\ncommand = \"server\"\n");
    assert_server(&toml, "server");
    let jsonc = br#"{/* comment */"servers":{"local":{"command":"server",},},}"#;
    let explicit = scratch.write("config.jsonc", jsonc);
    assert_server(&explicit, "server");
    let strict = scratch.write("config.json", jsonc);
    assert!(matches!(McpConfig::from_file(strict), Err(ConfigError::ParseError(_))));
}

#[test]
fn vscode_default_path_loads_a_real_registry_with_comments() {
    let mut scratch = Scratch::new();
    scratch.directory(".vscode");
    let path = scratch.write(
        ".vscode/mcp.json",
        br#"{/* comment */"servers":{"local":{"command":"server",},},}"#,
    );
    let config = ConfigLoader::from_path(path).load().unwrap();
    assert_eq!(config.get_server("local").unwrap().command, "server");
}

#[test]
fn exact_file_limit_is_accepted_but_larger_files_are_not_truncated() {
    let mut scratch = Scratch::new();
    let mut bytes = br#"{"mcpServers":{}}"#.to_vec();
    bytes.resize(64, b' ');
    let path = scratch.write("bounded.json", &bytes);
    assert!(McpConfig::from_file_with_limit(&path, 64).is_ok());
    assert!(matches!(
        McpConfig::from_file_with_limit(&path, 63),
        Err(ConfigError::FileTooLarge { limit_bytes: 63 })
    ));
}

#[test]
fn file_limit_counts_utf8_bytes_not_characters() {
    let mut scratch = Scratch::new();
    let text = r#"{"mcpServers":{"local":{"command":"雪"}}}"#;
    let path = scratch.write("utf8.json", text.as_bytes());
    assert!(McpConfig::from_file_with_limit(&path, text.len()).is_ok());
    assert!(matches!(
        McpConfig::from_file_with_limit(&path, text.chars().count()),
        Err(ConfigError::FileTooLarge { .. })
    ));
}

#[test]
fn default_bound_applies_to_discovery_as_well_as_explicit_reads() {
    let mut scratch = Scratch::new();
    let path = scratch.write("large.json", &vec![b' '; DEFAULT_MAX_CONFIG_FILE_BYTES + 1]);
    assert!(matches!(
        McpConfig::from_file(&path),
        Err(ConfigError::FileTooLarge { limit_bytes: DEFAULT_MAX_CONFIG_FILE_BYTES })
    ));
    assert!(matches!(
        ConfigLoader::from_path(path).load(),
        Err(ConfigError::FileTooLarge { .. })
    ));
}

#[test]
fn invalid_limit_is_reported_before_attempting_to_open_a_missing_file() {
    let scratch = Scratch::new();
    assert!(matches!(
        McpConfig::from_file_with_limit(scratch.path("missing.json"), 0),
        Err(ConfigError::InvalidFileByteLimit)
    ));
}

#[test]
fn invalid_utf8_stays_a_read_error() {
    let mut scratch = Scratch::new();
    let path = scratch.write("invalid.json", &[0xff, 0xfe]);
    match McpConfig::from_file(path) {
        Err(ConfigError::ReadError(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }
        other => panic!("expected UTF-8 read refusal, got {other:?}"),
    }
}

#[test]
fn discovery_skips_missing_files_but_not_malformed_files() {
    let mut scratch = Scratch::new();
    let valid = scratch.write("valid.json", br#"{"mcpServers":{"local":{"command":"server"}}}"#);
    let missing_first = ConfigLoader::from_path(scratch.path("missing.json")).with_path(&valid);
    assert_eq!(missing_first.load().unwrap().get_server("local").unwrap().command, "server");
    let invalid = scratch.write("invalid.json", b"{");
    let malformed_first = ConfigLoader::from_path(invalid).with_path(valid);
    assert!(matches!(malformed_first.load(), Err(ConfigError::ParseError(_))));
}

#[test]
fn load_all_keeps_documented_override_order_and_rejects_any_bad_input() {
    let mut scratch = Scratch::new();
    let first = scratch.write("first.json", br#"{"mcpServers":{"local":{"command":"first"}}}"#);
    let last = scratch.write("last.toml", b"[mcp_servers.local]\ncommand = \"last\"\n");
    let loader = ConfigLoader::from_path(first)
        .with_path(scratch.path("missing.json"))
        .with_path(last);
    assert_eq!(loader.load_all().unwrap().get_server("local").unwrap().command, "last");
    let invalid = scratch.write("invalid.json", b"{");
    assert!(matches!(
        loader.with_path(invalid).load_all(),
        Err(ConfigError::ParseError(_))
    ));
}

#[cfg(unix)]
#[test]
fn a_filesystem_error_cannot_silently_select_a_lower_priority_config() {
    let mut scratch = Scratch::new();
    let loop_path = scratch.path("loop.json");
    std::os::unix::fs::symlink(&loop_path, &loop_path).expect("self-referential test symlink");
    scratch.files.push(loop_path.clone());
    let valid = scratch.write("valid.json", br#"{"mcpServers":{"local":{"command":"fallback"}}}"#);
    // Path::exists() reports false for the loop. Discovery must attempt the
    // open and preserve ELOOP instead of skipping to the fallback config.
    assert!(!loop_path.exists());
    let loader = ConfigLoader::from_path(loop_path).with_path(valid);
    assert!(matches!(loader.load(), Err(ConfigError::ReadError(_))));
    assert!(matches!(loader.load_all(), Err(ConfigError::ReadError(_))));
}
