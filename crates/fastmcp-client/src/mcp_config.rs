//! MCP Configuration file support for server registry.
//!
//! This module provides configuration file parsing and client creation from config.
//! It supports the standard MCP configuration format used by Claude Desktop and other clients.
//!
//! # Configuration Format
//!
//! The standard format is JSON with the following structure:
//!
//! ```json
//! {
//!     "mcpServers": {
//!         "server-name": {
//!             "command": "npx",
//!             "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path"],
//!             "env": {
//!                 "API_KEY": "secret"
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use fastmcp::mcp_config::{McpConfig, ConfigLoader};
//!
//! // Load from default location
//! let config = ConfigLoader::default()?.load()?;
//!
//! // Create a client for a specific server
//! let client = config.client("filesystem")?;
//!
//! // Or load from a specific path
//! let config = McpConfig::from_file("/path/to/config.json")?;
//! ```
//!
//! # Default Locations
//!
//! Config files are searched in order:
//! - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
//! - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
//! - Linux: `~/.config/claude/config.json`
//!
//! Project-specific configs can be in `.vscode/mcp.json` or `.mcp/config.json`.

use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use asupersync::Cx;
use fastmcp_core::{McpError, McpResult};
use fastmcp_transport::StdioTransport;
use serde::{Deserialize, Serialize};

use crate::{Client, ClientSession};
use fastmcp_protocol::{ClientCapabilities, ClientInfo};

// ============================================================================
// Configuration Types
// ============================================================================

/// MCP configuration file containing server definitions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpConfig {
    /// Server configurations keyed by name.
    #[serde(default)]
    pub mcp_servers: HashMap<String, ServerConfig>,
}

/// Configuration for a single MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfig {
    /// Command to execute (e.g., "npx", "uvx", "python").
    pub command: String,

    /// Arguments to pass to the command.
    #[serde(default)]
    pub args: Vec<String>,

    /// Environment variables to set.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Working directory for the server process.
    #[serde(default)]
    pub cwd: Option<String>,

    /// Whether the server is disabled.
    #[serde(default)]
    pub disabled: bool,
}

impl ServerConfig {
    /// Creates a new server configuration.
    #[must_use]
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            env: HashMap::new(),
            cwd: None,
            disabled: false,
        }
    }

    /// Adds arguments.
    #[must_use]
    pub fn with_args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Adds an environment variable.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Sets the working directory.
    #[must_use]
    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Sets the disabled flag.
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.disabled = true;
        self
    }
}

// ============================================================================
// Configuration Errors
// ============================================================================

/// Errors that can occur during configuration operations.
#[derive(Debug)]
pub enum ConfigError {
    /// Configuration file not found.
    NotFound(String),
    /// Failed to read configuration file.
    ReadError(std::io::Error),
    /// Failed to parse configuration.
    ParseError(String),
    /// Server not found in configuration.
    ServerNotFound(String),
    /// Server is disabled.
    ServerDisabled(String),
    /// Failed to spawn server process.
    SpawnError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::NotFound(path) => write!(f, "Configuration file not found: {path}"),
            ConfigError::ReadError(e) => write!(f, "Failed to read configuration: {e}"),
            ConfigError::ParseError(e) => write!(f, "Failed to parse configuration: {e}"),
            ConfigError::ServerNotFound(name) => write!(f, "Server not found: {name}"),
            ConfigError::ServerDisabled(name) => write!(f, "Server is disabled: {name}"),
            ConfigError::SpawnError(e) => write!(f, "Failed to spawn server: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::ReadError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ConfigError> for McpError {
    fn from(err: ConfigError) -> Self {
        McpError::internal_error(err.to_string())
    }
}

// ============================================================================
// Configuration Loading
// ============================================================================

impl McpConfig {
    /// Creates an empty configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads configuration from a JSON file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content =
            std::fs::read_to_string(path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ConfigError::NotFound(path.display().to_string())
                } else {
                    ConfigError::ReadError(e)
                }
            })?;

        Self::from_json(&content)
    }

    /// Parses configuration from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(json).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Parses configuration from a TOML string.
    ///
    /// TOML format is an alternative supported by some MCP clients:
    ///
    /// ```toml
    /// [mcp_servers.filesystem]
    /// command = "npx"
    /// args = ["-y", "@modelcontextprotocol/server-filesystem", "/path"]
    ///
    /// [mcp_servers.filesystem.env]
    /// API_KEY = "secret"
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn from_toml(toml: &str) -> Result<Self, ConfigError> {
        toml::from_str(toml).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Serializes configuration to JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Serializes configuration to TOML.
    #[must_use]
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_else(|_| "".to_string())
    }

    /// Adds a server configuration.
    pub fn add_server(&mut self, name: impl Into<String>, config: ServerConfig) {
        self.mcp_servers.insert(name.into(), config);
    }

    /// Gets a server configuration by name.
    #[must_use]
    pub fn get_server(&self, name: &str) -> Option<&ServerConfig> {
        self.mcp_servers.get(name)
    }

    /// Returns all server names.
    #[must_use]
    pub fn server_names(&self) -> Vec<&str> {
        self.mcp_servers.keys().map(String::as_str).collect()
    }

    /// Returns enabled server names.
    #[must_use]
    pub fn enabled_servers(&self) -> Vec<&str> {
        self.mcp_servers
            .iter()
            .filter(|(_, c)| !c.disabled)
            .map(|(n, _)| n.as_str())
            .collect()
    }

    /// Creates a client for a server by name.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is not found, disabled, or fails to start.
    pub fn client(&self, name: &str) -> Result<Client, ConfigError> {
        self.client_with_cx(name, Cx::for_testing())
    }

    /// Creates a client with a provided Cx for cancellation support.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is not found, disabled, or fails to start.
    pub fn client_with_cx(&self, name: &str, cx: Cx) -> Result<Client, ConfigError> {
        let config = self
            .mcp_servers
            .get(name)
            .ok_or_else(|| ConfigError::ServerNotFound(name.to_string()))?;

        if config.disabled {
            return Err(ConfigError::ServerDisabled(name.to_string()));
        }

        spawn_client_from_config(name, config, cx)
    }

    /// Merges another configuration into this one.
    ///
    /// Servers from `other` override servers with the same name.
    pub fn merge(&mut self, other: McpConfig) {
        self.mcp_servers.extend(other.mcp_servers);
    }
}

/// Spawns a client from a server configuration.
fn spawn_client_from_config(name: &str, config: &ServerConfig, cx: Cx) -> Result<Client, ConfigError> {
    // Build the command
    let mut cmd = Command::new(&config.command);
    cmd.args(&config.args);

    // Set environment variables
    for (key, value) in &config.env {
        cmd.env(key, value);
    }

    // Set working directory if specified
    if let Some(ref cwd) = config.cwd {
        cmd.current_dir(cwd);
    }

    // Configure stdio
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());

    // Spawn the process
    let mut child = cmd.spawn().map_err(|e| {
        ConfigError::SpawnError(format!("Failed to spawn {}: {}", config.command, e))
    })?;

    // Get stdin/stdout handles
    let stdin = child.stdin.take().ok_or_else(|| {
        ConfigError::SpawnError(format!("Failed to get stdin for server '{name}'"))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        ConfigError::SpawnError(format!("Failed to get stdout for server '{name}'"))
    })?;

    // Create transport
    let transport = StdioTransport::new(stdout, stdin);

    // Create client info
    let client_info = ClientInfo {
        name: format!("fastmcp-client:{name}"),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    let client_capabilities = ClientCapabilities::default();

    // Create client and initialize
    create_and_initialize_client(child, transport, cx, client_info, client_capabilities)
        .map_err(|e| ConfigError::SpawnError(format!("Initialization failed: {e}")))
}

/// Creates a client and performs initialization handshake.
fn create_and_initialize_client(
    child: Child,
    mut transport: StdioTransport<ChildStdout, ChildStdin>,
    cx: Cx,
    client_info: ClientInfo,
    client_capabilities: ClientCapabilities,
) -> McpResult<Client> {
    use fastmcp_protocol::{
        InitializeParams, InitializeResult, JsonRpcMessage, JsonRpcRequest, PROTOCOL_VERSION,
    };
    use fastmcp_transport::Transport;

    // Send initialize request
    let params = InitializeParams {
        protocol_version: PROTOCOL_VERSION.to_string(),
        capabilities: client_capabilities.clone(),
        client_info: client_info.clone(),
    };

    let params_value = serde_json::to_value(&params)
        .map_err(|e| McpError::internal_error(format!("Failed to serialize params: {e}")))?;

    let request = JsonRpcRequest::new("initialize", Some(params_value), 1);

    transport
        .send(&cx, &JsonRpcMessage::Request(request))
        .map_err(crate::transport_error_to_mcp)?;

    // Receive response
    let response = loop {
        let message = transport.recv(&cx).map_err(crate::transport_error_to_mcp)?;
        if let JsonRpcMessage::Response(resp) = message {
            break resp;
        }
    };

    // Check for error
    if let Some(error) = response.error {
        return Err(McpError::new(
            fastmcp_core::McpErrorCode::from(error.code),
            error.message,
        ));
    }

    // Parse result
    let result_value = response
        .result
        .ok_or_else(|| McpError::internal_error("No result in initialize response"))?;

    let init_result: InitializeResult = serde_json::from_value(result_value)
        .map_err(|e| McpError::internal_error(format!("Failed to parse initialize result: {e}")))?;

    // Send initialized notification
    let notification = JsonRpcRequest {
        jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
        method: "initialized".to_string(),
        params: Some(serde_json::json!({})),
        id: None,
    };

    transport
        .send(&cx, &JsonRpcMessage::Request(notification))
        .map_err(crate::transport_error_to_mcp)?;

    // Create session
    let session = ClientSession::new(
        client_info,
        client_capabilities,
        init_result.server_info,
        init_result.capabilities,
        init_result.protocol_version,
    );

    // Return client
    Ok(Client::from_parts(child, transport, cx, session, 30_000))
}

// ============================================================================
// Configuration Loader
// ============================================================================

/// Loader for finding and loading MCP configurations.
///
/// This handles platform-specific default locations and searching
/// multiple potential config file paths.
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    /// Paths to search for configuration files.
    search_paths: Vec<PathBuf>,
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigLoader {
    /// Creates a new loader with default search paths.
    #[must_use]
    pub fn new() -> Self {
        Self {
            search_paths: default_config_paths(),
        }
    }

    /// Creates a loader with a single specific path.
    #[must_use]
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self {
            search_paths: vec![path.into()],
        }
    }

    /// Adds a search path.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.search_paths.push(path.into());
        self
    }

    /// Prepends a search path (searched first).
    #[must_use]
    pub fn with_priority_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.search_paths.insert(0, path.into());
        self
    }

    /// Loads configuration from the first existing file.
    ///
    /// # Errors
    ///
    /// Returns an error if no configuration file is found or parsing fails.
    pub fn load(&self) -> Result<McpConfig, ConfigError> {
        for path in &self.search_paths {
            if path.exists() {
                return McpConfig::from_file(path);
            }
        }

        Err(ConfigError::NotFound(
            "No MCP configuration file found".to_string(),
        ))
    }

    /// Loads and merges all existing configuration files.
    ///
    /// Later files override earlier ones.
    pub fn load_all(&self) -> McpConfig {
        let mut config = McpConfig::new();

        for path in &self.search_paths {
            if path.exists() {
                if let Ok(loaded) = McpConfig::from_file(path) {
                    config.merge(loaded);
                }
            }
        }

        config
    }

    /// Returns all search paths.
    #[must_use]
    pub fn search_paths(&self) -> &[PathBuf] {
        &self.search_paths
    }

    /// Returns paths that exist.
    #[must_use]
    pub fn existing_paths(&self) -> Vec<&PathBuf> {
        self.search_paths.iter().filter(|p| p.exists()).collect()
    }
}

// ============================================================================
// Default Config Paths
// ============================================================================

/// Returns platform-specific default configuration paths.
#[must_use]
pub fn default_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Project-specific configs (current directory)
    paths.push(PathBuf::from(".mcp/config.json"));
    paths.push(PathBuf::from(".vscode/mcp.json"));

    // User-level configs
    if let Some(home) = dirs::home_dir() {
        #[cfg(target_os = "macos")]
        {
            // Claude Desktop on macOS
            paths.push(home.join("Library/Application Support/Claude/claude_desktop_config.json"));
            // Generic MCP config
            paths.push(home.join(".config/mcp/config.json"));
        }

        #[cfg(target_os = "windows")]
        {
            // Claude Desktop on Windows
            if let Some(appdata) = dirs::data_dir() {
                paths.push(appdata.join("Claude/claude_desktop_config.json"));
            }
            // Generic MCP config
            paths.push(home.join(".mcp/config.json"));
        }

        #[cfg(target_os = "linux")]
        {
            // XDG config directory
            if let Ok(xdg_config) = env::var("XDG_CONFIG_HOME") {
                let xdg_path = PathBuf::from(xdg_config);
                paths.push(xdg_path.join("mcp/config.json"));
                paths.push(xdg_path.join("claude/config.json"));
            } else {
                paths.push(home.join(".config/mcp/config.json"));
                paths.push(home.join(".config/claude/config.json"));
            }
        }
    }

    paths
}

/// Returns the Claude Desktop configuration path for the current platform.
#[must_use]
pub fn claude_desktop_config_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .map(|h| h.join("Library/Application Support/Claude/claude_desktop_config.json"))
    }

    #[cfg(target_os = "windows")]
    {
        dirs::data_dir().map(|d| d.join("Claude/claude_desktop_config.json"))
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg_config) = env::var("XDG_CONFIG_HOME") {
            Some(PathBuf::from(xdg_config).join("claude/config.json"))
        } else {
            dirs::home_dir().map(|h| h.join(".config/claude/config.json"))
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_config() {
        let config = McpConfig::new();
        assert!(config.mcp_servers.is_empty());
        assert!(config.server_names().is_empty());
    }

    #[test]
    fn test_parse_json_config() {
        let json = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": {
                        "DEBUG": "true"
                    }
                },
                "other": {
                    "command": "python",
                    "args": ["-m", "my_server"],
                    "disabled": true
                }
            }
        }"#;

        let config = McpConfig::from_json(json).unwrap();

        assert_eq!(config.mcp_servers.len(), 2);

        let fs = config.get_server("filesystem").unwrap();
        assert_eq!(fs.command, "npx");
        assert_eq!(fs.args.len(), 3);
        assert_eq!(fs.env.get("DEBUG"), Some(&"true".to_string()));
        assert!(!fs.disabled);

        let other = config.get_server("other").unwrap();
        assert!(other.disabled);

        // enabled_servers should only return non-disabled servers
        let enabled = config.enabled_servers();
        assert_eq!(enabled.len(), 1);
        assert!(enabled.contains(&"filesystem"));
    }

    #[test]
    fn test_parse_toml_config() {
        // Note: serde rename_all="camelCase" applies to TOML too
        let toml = r#"
            [mcpServers.filesystem]
            command = "npx"
            args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]

            [mcpServers.filesystem.env]
            DEBUG = "true"
        "#;

        let config = McpConfig::from_toml(toml).unwrap();

        let fs = config.get_server("filesystem").unwrap();
        assert_eq!(fs.command, "npx");
        assert_eq!(fs.args.len(), 3);
        assert_eq!(fs.env.get("DEBUG"), Some(&"true".to_string()));
    }

    #[test]
    fn test_server_config_builder() {
        let config = ServerConfig::new("python")
            .with_args(["-m", "my_server"])
            .with_env("API_KEY", "secret")
            .with_cwd("/opt/server");

        assert_eq!(config.command, "python");
        assert_eq!(config.args, vec!["-m", "my_server"]);
        assert_eq!(config.env.get("API_KEY"), Some(&"secret".to_string()));
        assert_eq!(config.cwd, Some("/opt/server".to_string()));
        assert!(!config.disabled);
    }

    #[test]
    fn test_config_add_and_get_server() {
        let mut config = McpConfig::new();

        config.add_server(
            "test",
            ServerConfig::new("echo").with_args(["hello"]),
        );

        assert_eq!(config.server_names().len(), 1);
        assert!(config.get_server("test").is_some());
        assert!(config.get_server("nonexistent").is_none());
    }

    #[test]
    fn test_config_merge() {
        let mut base = McpConfig::new();
        base.add_server("server1", ServerConfig::new("cmd1"));
        base.add_server("server2", ServerConfig::new("cmd2"));

        let mut overlay = McpConfig::new();
        overlay.add_server("server2", ServerConfig::new("cmd2-override"));
        overlay.add_server("server3", ServerConfig::new("cmd3"));

        base.merge(overlay);

        assert_eq!(base.mcp_servers.len(), 3);
        assert_eq!(base.get_server("server1").unwrap().command, "cmd1");
        assert_eq!(base.get_server("server2").unwrap().command, "cmd2-override");
        assert_eq!(base.get_server("server3").unwrap().command, "cmd3");
    }

    #[test]
    fn test_config_serialization() {
        let mut config = McpConfig::new();
        config.add_server(
            "test",
            ServerConfig::new("npx")
                .with_args(["-y", "server"])
                .with_env("KEY", "value"),
        );

        let json = config.to_json();
        assert!(json.contains("mcpServers"));
        assert!(json.contains("npx"));

        let toml = config.to_toml();
        assert!(toml.contains("mcpServers"));
        assert!(toml.contains("npx"));
    }

    #[test]
    fn test_config_loader() {
        let loader = ConfigLoader::new()
            .with_path("/custom/path/config.json")
            .with_priority_path("/priority/config.json");

        let paths = loader.search_paths();
        assert!(paths.first().unwrap().to_str().unwrap().contains("priority"));
        assert!(paths.last().unwrap().to_str().unwrap().contains("custom"));
    }

    #[test]
    fn test_error_server_not_found() {
        let config = McpConfig::new();
        let result = config.client("nonexistent");
        assert!(matches!(result, Err(ConfigError::ServerNotFound(_))));
    }

    #[test]
    fn test_error_server_disabled() {
        let mut config = McpConfig::new();
        config.add_server("disabled", ServerConfig::new("echo").disabled());

        let result = config.client("disabled");
        assert!(matches!(result, Err(ConfigError::ServerDisabled(_))));
    }

    #[test]
    fn test_default_config_paths_not_empty() {
        let paths = default_config_paths();
        assert!(!paths.is_empty());
    }

    #[test]
    fn test_config_error_display() {
        let errors = vec![
            (ConfigError::NotFound("path".into()), "not found"),
            (ConfigError::ServerNotFound("name".into()), "server not found"),
            (ConfigError::ServerDisabled("name".into()), "disabled"),
            (ConfigError::ParseError("msg".into()), "parse"),
        ];

        for (error, expected) in errors {
            assert!(
                error.to_string().to_lowercase().contains(expected),
                "Expected '{}' to contain '{}'",
                error,
                expected
            );
        }
    }
}
