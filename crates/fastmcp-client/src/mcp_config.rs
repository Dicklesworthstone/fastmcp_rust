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
//!                 "EXAMPLE_ENV": "example-value"
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use fastmcp_rust::{
//!     Cx,
//!     mcp_config::{ConfigError, ConfigLoader, McpConfig},
//! };
//!
//! // Load from default location
//! let config = ConfigLoader::default().load()?;
//!
//! // Create a client for a specific server
//! # fn create_client(config: &McpConfig, cx: &Cx) -> Result<(), ConfigError> {
//! let client = config.client(cx, "filesystem")?;
//! # let _ = client;
//! # Ok(())
//! # }
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
//! - Linux and other non-macOS Unix: `$XDG_CONFIG_HOME/Claude/claude_desktop_config.json`
//!   (falling back to `~/.config/Claude/claude_desktop_config.json`)
//!
//! Project-specific configs can be in `.vscode/mcp.json` or `.mcp/config.json`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use asupersync::Cx;
use fastmcp_core::{CanonicalHttpUrl, McpError, McpResult};
use fastmcp_transport::StdioTransport;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::{
    ChildGuard, Client, ClientProtocolPlan, ClientSession, RequestTimeoutPolicy,
    combine_cleanup_results, combine_operation_with_cleanup, resolve_stdio_command,
    transport_error_to_mcp,
};
use fastmcp_protocol::protocol_policy::{
    HttpEndpointBundle, HttpEndpointBundleError, HttpRouteKind, ProtocolPolicy,
};
use fastmcp_protocol::{ClientCapabilities, ClientInfo};

// ============================================================================
// Configuration Types
// ============================================================================

/// MCP configuration file containing server definitions.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpConfig {
    /// Server configurations keyed by name.
    #[serde(default)]
    pub mcp_servers: HashMap<String, ServerConfig>,
}

impl std::fmt::Debug for McpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let enabled_server_count = self
            .mcp_servers
            .values()
            .filter(|config| !config.disabled)
            .count();
        f.debug_struct("McpConfig")
            .field("server_count", &self.mcp_servers.len())
            .field("enabled_server_count", &enabled_server_count)
            .field(
                "disabled_server_count",
                &self.mcp_servers.len().saturating_sub(enabled_server_count),
            )
            .finish()
    }
}

/// Configuration for a single MCP server.
#[derive(Clone, Serialize, Deserialize)]
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

    /// Optional immutable HTTP route configuration for this server.
    ///
    /// This config is separate from the stdio command surface. It never
    /// derives a route from a peer, discovery response, redirect, or origin.
    #[serde(default)]
    http: Option<HttpEndpointConfig>,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("command_set", &!self.command.is_empty())
            .field("arg_count", &self.args.len())
            .field("env_var_count", &self.env.len())
            .field("cwd_set", &self.cwd.is_some())
            .field("disabled", &self.disabled)
            .field("http_configured", &self.http.is_some())
            .finish()
    }
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
            http: None,
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

    /// Attaches an already validated, immutable HTTP endpoint configuration.
    #[must_use]
    pub fn with_http_endpoint_config(mut self, http: HttpEndpointConfig) -> Self {
        self.http = Some(http);
        self
    }

    /// Returns this server's immutable HTTP endpoint configuration, if any.
    #[must_use]
    pub const fn http_endpoint_config(&self) -> Option<&HttpEndpointConfig> {
        self.http.as_ref()
    }
}

/// Typed refusal while parsing configured HTTP endpoint routes.
///
/// The error deliberately retains route roles rather than raw endpoint text,
/// so configuration diagnostics do not disclose query values or userinfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpEndpointConfigError {
    /// A configured target is not a canonical HTTP(S) URL.
    InvalidTarget {
        /// The configured route whose URL was rejected.
        route: HttpRouteKind,
    },
    /// HTTP endpoint URLs cannot carry credentials in their authority.
    UserinfoNotAllowed {
        /// The configured route whose URL carried userinfo.
        route: HttpRouteKind,
    },
    /// The policy required a modern POST route that was not configured.
    MissingModernPostTarget {
        /// The explicit policy being validated.
        policy: ProtocolPolicy,
    },
    /// The policy required a legacy SSE GET route that was not configured.
    MissingLegacySseTarget {
        /// The explicit policy being validated.
        policy: ProtocolPolicy,
    },
    /// The policy required a legacy message POST route that was not configured.
    MissingLegacyMessagePostTarget {
        /// The explicit policy being validated.
        policy: ProtocolPolicy,
    },
    /// A configured route included an HTTP fragment.
    FragmentNotAllowed {
        /// The configured route whose fragment was rejected.
        route: HttpRouteKind,
    },
    /// Two configured routes collide on the same method and canonical target.
    RouteCollision {
        /// The first colliding configured route.
        first: HttpRouteKind,
        /// The second colliding configured route.
        second: HttpRouteKind,
    },
}

impl std::fmt::Display for HttpEndpointConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTarget { route } => {
                write!(
                    formatter,
                    "configured {route} target is not a valid HTTP(S) URL"
                )
            }
            Self::UserinfoNotAllowed { route } => {
                write!(
                    formatter,
                    "configured {route} target must not contain userinfo"
                )
            }
            Self::MissingModernPostTarget { policy } => write!(
                formatter,
                "{policy:?} requires an explicit modern MCP POST target"
            ),
            Self::MissingLegacySseTarget { policy } => write!(
                formatter,
                "{policy:?} requires an explicit legacy SSE GET target"
            ),
            Self::MissingLegacyMessagePostTarget { policy } => write!(
                formatter,
                "{policy:?} requires an explicit legacy message POST target"
            ),
            Self::FragmentNotAllowed { route } => {
                write!(
                    formatter,
                    "configured {route} target must not contain a fragment"
                )
            }
            Self::RouteCollision { first, second } => {
                write!(formatter, "configured {first} and {second} routes collide")
            }
        }
    }
}

impl std::error::Error for HttpEndpointConfigError {}

impl From<HttpEndpointBundleError> for HttpEndpointConfigError {
    fn from(error: HttpEndpointBundleError) -> Self {
        match error {
            HttpEndpointBundleError::MissingModernPostTarget { policy } => {
                Self::MissingModernPostTarget { policy }
            }
            HttpEndpointBundleError::MissingLegacySseTarget { policy } => {
                Self::MissingLegacySseTarget { policy }
            }
            HttpEndpointBundleError::MissingLegacyMessagePostTarget { policy } => {
                Self::MissingLegacyMessagePostTarget { policy }
            }
            HttpEndpointBundleError::FragmentNotAllowed { route } => {
                Self::FragmentNotAllowed { route }
            }
            HttpEndpointBundleError::RouteCollision { first, second, .. } => {
                Self::RouteCollision { first, second }
            }
        }
    }
}

/// Immutable HTTP endpoint configuration constructed from trusted local input.
///
/// The serialized form is a nested `http` object on a server configuration:
///
/// ```json
/// {
///   "policy": "Auto",
///   "modernPost": "https://mcp.example.test/mcp",
///   "legacySse": "https://mcp.example.test/sse",
///   "legacyMessagePost": "https://mcp.example.test/messages",
///   "credentialPartition": "credential-v1",
///   "securityPartition": "security-v1",
///   "transportProfile": "http-sse-v2",
///   "policyGeneration": 1,
///   "configurationGeneration": 1,
///   "legacyReceiptGeneration": 1
/// }
/// ```
///
/// `policy` is intentionally required. `Auto`, `ModernOnly`, and
/// `LegacyOnly` are distinct immutable selections, not strings that may be
/// changed after a peer response or a failed request.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpEndpointConfig {
    policy: ProtocolPolicy,
    modern_post: Option<CanonicalHttpUrl>,
    legacy_sse: Option<CanonicalHttpUrl>,
    legacy_message_post: Option<CanonicalHttpUrl>,
    credential_partition: String,
    security_partition: String,
    transport_profile: String,
    policy_generation: u64,
    configuration_generation: u64,
    legacy_receipt_generation: u64,
    bundle: HttpEndpointBundle,
}

impl std::fmt::Debug for HttpEndpointConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpEndpointConfig")
            .field("policy", &self.policy)
            .field("modern_post_configured", &self.modern_post.is_some())
            .field("legacy_sse_configured", &self.legacy_sse.is_some())
            .field(
                "legacy_message_post_configured",
                &self.legacy_message_post.is_some(),
            )
            .field("policy_generation", &self.policy_generation)
            .field("configuration_generation", &self.configuration_generation)
            .field("legacy_receipt_generation", &self.legacy_receipt_generation)
            .finish()
    }
}

impl HttpEndpointConfig {
    /// Validates trusted endpoint configuration and freezes its bundle key.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: ProtocolPolicy,
        modern_post: Option<String>,
        legacy_sse: Option<String>,
        legacy_message_post: Option<String>,
        credential_partition: String,
        security_partition: String,
        transport_profile: String,
        policy_generation: u64,
        configuration_generation: u64,
        legacy_receipt_generation: u64,
    ) -> Result<Self, HttpEndpointConfigError> {
        let modern_post = parse_configured_target(modern_post, HttpRouteKind::ModernMcpPost)?;
        let legacy_sse = parse_configured_target(legacy_sse, HttpRouteKind::LegacySseGet)?;
        let legacy_message_post =
            parse_configured_target(legacy_message_post, HttpRouteKind::LegacyMessagePost)?;
        let bundle = HttpEndpointBundle::new(
            policy,
            modern_post.clone(),
            legacy_sse.clone(),
            legacy_message_post.clone(),
            credential_partition.clone(),
            security_partition.clone(),
            transport_profile.clone(),
            policy_generation,
            configuration_generation,
            legacy_receipt_generation,
        )
        .map_err(HttpEndpointConfigError::from)?;

        Ok(Self {
            policy,
            modern_post,
            legacy_sse,
            legacy_message_post,
            credential_partition,
            security_partition,
            transport_profile,
            policy_generation,
            configuration_generation,
            legacy_receipt_generation,
            bundle,
        })
    }

    /// Returns the explicitly configured, immutable protocol policy.
    #[must_use]
    pub const fn policy(&self) -> ProtocolPolicy {
        self.policy
    }

    /// Returns the validated immutable HTTP endpoint bundle.
    #[must_use]
    pub const fn endpoint_bundle(&self) -> &HttpEndpointBundle {
        &self.bundle
    }
}

fn parse_configured_target(
    target: Option<String>,
    route: HttpRouteKind,
) -> Result<Option<CanonicalHttpUrl>, HttpEndpointConfigError> {
    let Some(target) = target else {
        return Ok(None);
    };
    let target = CanonicalHttpUrl::parse(&target)
        .map_err(|_| HttpEndpointConfigError::InvalidTarget { route })?;
    if target.has_userinfo() {
        return Err(HttpEndpointConfigError::UserinfoNotAllowed { route });
    }
    Ok(Some(target))
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HttpEndpointConfigWire {
    policy: ProtocolPolicy,
    #[serde(default)]
    modern_post: Option<String>,
    #[serde(default)]
    legacy_sse: Option<String>,
    #[serde(default)]
    legacy_message_post: Option<String>,
    credential_partition: String,
    security_partition: String,
    transport_profile: String,
    policy_generation: u64,
    configuration_generation: u64,
    legacy_receipt_generation: u64,
}

impl<'de> Deserialize<'de> for HttpEndpointConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = HttpEndpointConfigWire::deserialize(deserializer)?;
        Self::new(
            wire.policy,
            wire.modern_post,
            wire.legacy_sse,
            wire.legacy_message_post,
            wire.credential_partition,
            wire.security_partition,
            wire.transport_profile,
            wire.policy_generation,
            wire.configuration_generation,
            wire.legacy_receipt_generation,
        )
        .map_err(D::Error::custom)
    }
}

impl Serialize for HttpEndpointConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        HttpEndpointConfigWire {
            policy: self.policy,
            modern_post: self
                .modern_post
                .as_ref()
                .map(|target| target.as_str().to_owned()),
            legacy_sse: self
                .legacy_sse
                .as_ref()
                .map(|target| target.as_str().to_owned()),
            legacy_message_post: self
                .legacy_message_post
                .as_ref()
                .map(|target| target.as_str().to_owned()),
            credential_partition: self.credential_partition.clone(),
            security_partition: self.security_partition.clone(),
            transport_profile: self.transport_profile.clone(),
            policy_generation: self.policy_generation,
            configuration_generation: self.configuration_generation,
            legacy_receipt_generation: self.legacy_receipt_generation,
        }
        .serialize(serializer)
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
    /// Server process started, but the MCP client lifecycle failed.
    ClientError(McpError),
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
            ConfigError::ClientError(e) => write!(f, "MCP client lifecycle failed: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::ReadError(e) => Some(e),
            ConfigError::ClientError(e) => Some(e),
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
        let content = std::fs::read_to_string(path).map_err(|e| {
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
        serde_json::from_str(json)
            .map_err(|_| ConfigError::ParseError("Invalid JSON configuration".to_string()))
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
    /// EXAMPLE_ENV = "example-value"
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn from_toml(toml: &str) -> Result<Self, ConfigError> {
        toml::from_str(toml)
            .map_err(|_| ConfigError::ParseError("Invalid TOML configuration".to_string()))
    }

    /// Serializes configuration to JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Serializes configuration to TOML.
    #[must_use]
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_else(|_| String::new())
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

    /// Creates a client for a server by name under the caller's capability
    /// context.
    ///
    /// Initialization and subsequent ordinary requests use
    /// the default [`RequestTimeoutPolicy`]. Use
    /// [`Self::client_with_timeout_policy`] to select different bounds.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is not found, disabled, or fails to start
    /// or initialize.
    ///
    /// The context is mandatory; configuration-based client construction never
    /// creates or re-enters a runtime on behalf of a library caller.
    ///
    /// ```compile_fail
    /// use fastmcp_client::mcp_config::McpConfig;
    ///
    /// let config = McpConfig::new();
    /// let _client = config.client("filesystem");
    /// ```
    pub fn client(&self, cx: &Cx, name: &str) -> Result<Client, ConfigError> {
        self.client_with_timeout_policy(cx, name, RequestTimeoutPolicy::default())
    }

    /// Creates a client using an explicit idle/absolute timeout policy.
    ///
    /// The policy applies to initialization as well as subsequent ordinary
    /// requests. Use this path when the default 30-second idle and 120-second
    /// absolute initialization limits are not appropriate.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is not found, disabled, or fails to
    /// start or initialize.
    pub fn client_with_timeout_policy(
        &self,
        cx: &Cx,
        name: &str,
        timeout_policy: RequestTimeoutPolicy,
    ) -> Result<Client, ConfigError> {
        timeout_policy
            .validate()
            .map_err(ConfigError::ClientError)?;
        let config = self
            .mcp_servers
            .get(name)
            .ok_or_else(|| ConfigError::ServerNotFound(name.to_string()))?;

        if config.disabled {
            return Err(ConfigError::ServerDisabled(name.to_string()));
        }

        spawn_client_from_config(name, config, cx, timeout_policy)
    }

    /// Merges another configuration into this one.
    ///
    /// Servers from `other` override servers with the same name.
    pub fn merge(&mut self, other: McpConfig) {
        self.mcp_servers.extend(other.mcp_servers);
    }
}

/// Spawns a client from a server configuration.
fn spawn_client_from_config(
    name: &str,
    config: &ServerConfig,
    cx: &Cx,
    timeout_policy: RequestTimeoutPolicy,
) -> Result<Client, ConfigError> {
    if cx.checkpoint().is_err() {
        return Err(ConfigError::ClientError(McpError::request_cancelled()));
    }

    // Build the command
    let executable = resolve_stdio_command(&config.command, config.cwd.as_deref().map(Path::new))
        .map_err(ConfigError::ClientError)?;
    let mut cmd = Command::new(executable);
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
    // Configuration expansion may consume the caller's cancellation budget.
    // Re-admit the subprocess immediately before creation so an observed
    // cancellation cannot still produce a child.
    if cx.checkpoint().is_err() {
        return Err(ConfigError::ClientError(McpError::request_cancelled()));
    }
    // Spawn the process
    let child = cmd.spawn().map_err(|error| {
        ConfigError::SpawnError(format!(
            "Configured server process could not be started ({:?})",
            error.kind()
        ))
    })?;
    let mut child_guard = ChildGuard::new(child);

    // Get stdin/stdout handles
    let stdin = child_guard.child_mut().stdin.take().ok_or_else(|| {
        ConfigError::SpawnError(format!("Failed to get stdin for server '{name}'"))
    })?;
    let stdout = child_guard.child_mut().stdout.take().ok_or_else(|| {
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
    create_and_initialize_client(
        child_guard.disarm(),
        transport,
        cx,
        client_info,
        client_capabilities,
        timeout_policy,
    )
    .map_err(ConfigError::ClientError)
}

/// Creates a client and performs initialization handshake.
fn create_and_initialize_client(
    child: Child,
    mut transport: StdioTransport<ChildStdout, ChildStdin>,
    cx: &Cx,
    client_info: ClientInfo,
    client_capabilities: ClientCapabilities,
    timeout_policy: RequestTimeoutPolicy,
) -> McpResult<Client> {
    use fastmcp_transport::Transport;

    let child_guard = ChildGuard::new(child);
    let init_result = match crate::initialize_child_transport(
        &mut transport,
        cx,
        &client_info,
        &client_capabilities,
        timeout_policy,
    ) {
        Ok(result) => result,
        Err(error) => {
            return combine_operation_with_cleanup(Err(error), || {
                combine_cleanup_results(
                    transport.close().map_err(transport_error_to_mcp),
                    child_guard.cleanup(),
                )
            });
        }
    };

    // The child peer controls the selected version, so keep this boundary
    // fallible even though the shared initialization validator already checks it.
    let session = match ClientSession::try_new(
        client_info,
        client_capabilities,
        init_result.server_info,
        init_result.capabilities,
        init_result.protocol_version,
    ) {
        Ok(session) => match session
            .with_legacy_instructions(init_result.instructions)
            .try_with_protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly))
        {
            Ok(session) => session,
            Err(_) => {
                return combine_operation_with_cleanup(
                    Err(McpError::internal_error(
                        "Configured legacy initialization selected an incompatible protocol era",
                    )),
                    || {
                        combine_cleanup_results(
                            transport.close().map_err(transport_error_to_mcp),
                            child_guard.cleanup(),
                        )
                    },
                );
            }
        },
        Err(_) => {
            return combine_operation_with_cleanup(
                Err(McpError::internal_error(
                    "Server selected an unsupported MCP protocol version",
                )),
                || {
                    combine_cleanup_results(
                        transport.close().map_err(transport_error_to_mcp),
                        child_guard.cleanup(),
                    )
                },
            );
        }
    };

    if cx.checkpoint().is_err() {
        return combine_operation_with_cleanup(Err(McpError::request_cancelled()), || {
            combine_cleanup_results(
                transport.close().map_err(transport_error_to_mcp),
                child_guard.cleanup(),
            )
        });
    }

    // Return client
    Ok(Client::from_parts(
        child_guard.disarm(),
        transport,
        cx.clone(),
        session,
        timeout_policy,
    ))
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
    ///
    /// # Errors
    ///
    /// Returns the first read or parse error instead of silently omitting an
    /// existing configuration file from the merged result.
    pub fn load_all(&self) -> Result<McpConfig, ConfigError> {
        let mut config = McpConfig::new();

        for path in &self.search_paths {
            if path.exists() {
                config.merge(McpConfig::from_file(path)?);
            }
        }

        Ok(config)
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

#[derive(Debug, Clone)]
struct ConfigLocations {
    home: Option<PathBuf>,
    #[cfg(all(unix, not(target_os = "macos")))]
    unix_config: Option<PathBuf>,
    #[cfg(target_os = "windows")]
    windows_data: Option<PathBuf>,
}

impl ConfigLocations {
    fn from_environment() -> Self {
        let home = dirs::home_dir();
        #[cfg(all(unix, not(target_os = "macos")))]
        let unix_config = unix_config_home(
            home.as_deref(),
            std::env::var_os("XDG_CONFIG_HOME").as_deref(),
        );

        Self {
            home,
            #[cfg(all(unix, not(target_os = "macos")))]
            unix_config,
            #[cfg(target_os = "windows")]
            windows_data: dirs::data_dir(),
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn unix_config_home(
    home: Option<&Path>,
    xdg_config_home: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    xdg_config_home
        .map(Path::new)
        .filter(|path| !path.as_os_str().is_empty() && path.is_absolute())
        .map(Path::to_path_buf)
        .or_else(|| home.map(|path| path.join(".config")))
}

fn claude_desktop_config_path_from(locations: &ConfigLocations) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        locations
            .home
            .as_ref()
            .map(|home| home.join("Library/Application Support/Claude/claude_desktop_config.json"))
    }

    #[cfg(target_os = "windows")]
    {
        locations
            .windows_data
            .as_ref()
            .map(|data| data.join("Claude/claude_desktop_config.json"))
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        locations
            .unix_config
            .as_ref()
            .map(|config| config.join("Claude/claude_desktop_config.json"))
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", unix)))]
    {
        let _ = locations;
        None
    }
}

fn default_config_paths_from(locations: &ConfigLocations) -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from(".mcp/config.json"),
        PathBuf::from(".vscode/mcp.json"),
    ];

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    if let Some(claude_path) = claude_desktop_config_path_from(locations) {
        paths.push(claude_path);
    }

    #[cfg(target_os = "macos")]
    if let Some(home) = &locations.home {
        paths.push(home.join(".config/mcp/config.json"));
    }

    #[cfg(target_os = "windows")]
    if let Some(home) = &locations.home {
        paths.push(home.join(".mcp/config.json"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    if let Some(config) = &locations.unix_config {
        paths.push(config.join("mcp/config.json"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    if let Some(claude_path) = claude_desktop_config_path_from(locations) {
        paths.push(claude_path);
    }

    paths
}

/// Returns platform-specific default configuration paths.
#[must_use]
pub fn default_config_paths() -> Vec<PathBuf> {
    default_config_paths_from(&ConfigLocations::from_environment())
}

/// Returns the Claude Desktop configuration path for the current platform.
///
/// macOS and Windows use Claude Desktop's native locations. Claude Desktop is
/// not officially distributed for Linux; on non-macOS Unix, FastMCP retains a
/// desktop-compatible config convention beneath the XDG configuration
/// directory so its installer, lister, and configuration loader agree.
#[must_use]
pub fn claude_desktop_config_path() -> Option<PathBuf> {
    claude_desktop_config_path_from(&ConfigLocations::from_environment())
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
        assert_eq!(config.server_names().len(), 0);
    }

    #[test]
    fn explicit_http_policies_parse_to_immutable_endpoint_bundles() {
        let config = McpConfig::from_json(
            r#"{
                "mcpServers": {
                    "modern": {
                        "command": "unused",
                        "http": {
                            "policy": "ModernOnly",
                            "modernPost": "https://modern.example.test/mcp",
                            "credentialPartition": "credential-a",
                            "securityPartition": "security-a",
                            "transportProfile": "http-sse-v2",
                            "policyGeneration": 3,
                            "configurationGeneration": 5,
                            "legacyReceiptGeneration": 7
                        }
                    },
                    "legacy": {
                        "command": "unused",
                        "http": {
                            "policy": "LegacyOnly",
                            "legacySse": "https://legacy.example.test/sse",
                            "legacyMessagePost": "https://legacy.example.test/messages",
                            "credentialPartition": "credential-b",
                            "securityPartition": "security-b",
                            "transportProfile": "http-sse-v2",
                            "policyGeneration": 3,
                            "configurationGeneration": 5,
                            "legacyReceiptGeneration": 7
                        }
                    },
                    "auto": {
                        "command": "unused",
                        "http": {
                            "policy": "Auto",
                            "modernPost": "https://auto.example.test/mcp",
                            "legacySse": "https://auto.example.test/sse",
                            "legacyMessagePost": "https://auto.example.test/messages",
                            "credentialPartition": "credential-c",
                            "securityPartition": "security-c",
                            "transportProfile": "http-sse-v2",
                            "policyGeneration": 3,
                            "configurationGeneration": 5,
                            "legacyReceiptGeneration": 7
                        }
                    }
                }
            }"#,
        )
        .expect("every explicit policy with its required routes is valid");

        let modern = config
            .get_server("modern")
            .and_then(ServerConfig::http_endpoint_config)
            .expect("modern config must retain its immutable bundle");
        let legacy = config
            .get_server("legacy")
            .and_then(ServerConfig::http_endpoint_config)
            .expect("legacy config must retain its immutable bundle");
        let auto = config
            .get_server("auto")
            .and_then(ServerConfig::http_endpoint_config)
            .expect("auto config must retain its immutable bundle");

        assert_eq!(modern.policy(), ProtocolPolicy::ModernOnly);
        assert_eq!(legacy.policy(), ProtocolPolicy::LegacyOnly);
        assert_eq!(auto.policy(), ProtocolPolicy::Auto);

        let original_auto_key = auto.endpoint_bundle().key();
        let serialized = config.to_json();
        let reparsed = McpConfig::from_json(&serialized)
            .expect("canonical endpoint configuration must round-trip");
        let reparsed_auto = reparsed
            .get_server("auto")
            .and_then(ServerConfig::http_endpoint_config)
            .expect("round-tripped auto config must retain its immutable bundle");
        assert_eq!(reparsed_auto.endpoint_bundle().key(), original_auto_key);
    }

    #[test]
    fn auto_endpoint_bundle_rejects_only_a_missing_legacy_message_post() {
        let accepted = HttpEndpointConfig::new(
            ProtocolPolicy::Auto,
            Some("https://auto.example.test/mcp".to_owned()),
            Some("https://auto.example.test/sse".to_owned()),
            Some("https://auto.example.test/messages".to_owned()),
            "credential-c".to_owned(),
            "security-c".to_owned(),
            "http-sse-v2".to_owned(),
            3,
            5,
            7,
        )
        .expect("the accepted auto bundle has every required route");
        let accepted_key = accepted.endpoint_bundle().key();

        // The only changed input is the missing legacy message POST target.
        // The accepted bundle is immutable, so this failed construction cannot
        // mutate its endpoint key or make it share a cache identity.
        let refusal = HttpEndpointConfig::new(
            ProtocolPolicy::Auto,
            Some("https://auto.example.test/mcp".to_owned()),
            Some("https://auto.example.test/sse".to_owned()),
            None,
            "credential-c".to_owned(),
            "security-c".to_owned(),
            "http-sse-v2".to_owned(),
            3,
            5,
            7,
        )
        .expect_err("Auto must reject a missing explicit legacy message POST target");
        assert_eq!(
            refusal,
            HttpEndpointConfigError::MissingLegacyMessagePostTarget {
                policy: ProtocolPolicy::Auto,
            }
        );
        let parse_error = McpConfig::from_json(
            r#"{
                "mcpServers": {
                    "auto": {
                        "command": "unused",
                        "http": {
                            "policy": "Auto",
                            "modernPost": "https://auto.example.test/mcp",
                            "legacySse": "https://auto.example.test/sse",
                            "credentialPartition": "credential-c",
                            "securityPartition": "security-c",
                            "transportProfile": "http-sse-v2",
                            "policyGeneration": 3,
                            "configurationGeneration": 5,
                            "legacyReceiptGeneration": 7
                        }
                    }
                }
            }"#,
        )
        .expect_err("config parsing must run endpoint-bundle validation");
        assert!(matches!(parse_error, ConfigError::ParseError(_)));
        assert_eq!(accepted.endpoint_bundle().key(), accepted_key);
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
            .with_env("EXAMPLE_ENV", "example-value")
            .with_cwd("/opt/server");

        assert_eq!(config.command, "python");
        assert_eq!(config.args, vec!["-m", "my_server"]);
        assert_eq!(
            config.env.get("EXAMPLE_ENV"),
            Some(&"example-value".to_string())
        );
        assert_eq!(config.cwd, Some("/opt/server".to_string()));
        assert!(!config.disabled);
    }

    #[test]
    fn server_config_debug_redacts_environment_and_argument_values() {
        let env_value_canary = "server-config-env-value-canary";
        let argument_canary = "server-config-api-argument-canary";
        let command_canary = "server-config-command-secret-canary";
        let config = ServerConfig::new(command_canary)
            .with_args(["-m", "safe_module", "--api-key", argument_canary])
            .with_env("SERVICE_API_TOKEN", env_value_canary)
            .with_cwd("/private/server/path");

        let debug = format!("{:?}", config);
        assert!(debug.contains("ServerConfig"));
        assert!(debug.contains("command_set: true"));
        assert!(debug.contains("arg_count: 4"));
        assert!(debug.contains("env_var_count: 1"));
        assert!(debug.contains("cwd_set: true"));
        assert!(debug.contains("disabled: false"));
        assert!(!debug.contains(env_value_canary));
        assert!(!debug.contains(argument_canary));
        assert!(!debug.contains(command_canary));
        assert!(!debug.contains("SERVICE_API_TOKEN"));
        assert!(!debug.contains("/private/server/path"));

        let serialized = serde_json::to_value(&config).expect("server config must serialize");
        assert_eq!(serialized["command"], command_canary);
        assert_eq!(serialized["args"][3], argument_canary);
        assert_eq!(serialized["env"]["SERVICE_API_TOKEN"], env_value_canary);
    }

    #[test]
    fn mcp_config_debug_is_a_redacted_aggregate_summary() {
        let env_value_canary = "aggregate-env-value-canary";
        let argument_canary = "aggregate-api-argument-canary";
        let mut config = McpConfig::new();
        config.add_server(
            "enabled-server",
            ServerConfig::new("runner")
                .with_args(["--credential", argument_canary])
                .with_env("API_TOKEN", env_value_canary),
        );
        config.add_server("disabled-server", ServerConfig::new("other").disabled());

        let debug = format!("{:?}", config);
        assert!(debug.contains("McpConfig"));
        assert!(debug.contains("server_count: 2"));
        assert!(debug.contains("enabled_server_count: 1"));
        assert!(debug.contains("disabled_server_count: 1"));
        assert!(!debug.contains(env_value_canary));
        assert!(!debug.contains(argument_canary));
        assert!(!debug.contains("API_TOKEN"));
    }

    #[test]
    fn test_config_add_and_get_server() {
        let mut config = McpConfig::new();

        config.add_server("test", ServerConfig::new("echo").with_args(["hello"]));

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
        assert!(
            paths
                .first()
                .unwrap()
                .to_str()
                .unwrap()
                .contains("priority")
        );
        assert!(paths.last().unwrap().to_str().unwrap().contains("custom"));
    }

    #[test]
    fn test_error_server_not_found() {
        let config = McpConfig::new();
        let result = config.client(&Cx::for_testing(), "nonexistent");
        assert!(matches!(result, Err(ConfigError::ServerNotFound(_))));
    }

    #[test]
    fn test_error_server_disabled() {
        let mut config = McpConfig::new();
        config.add_server("disabled", ServerConfig::new("echo").disabled());

        let result = config.client(&Cx::for_testing(), "disabled");
        assert!(matches!(result, Err(ConfigError::ServerDisabled(_))));
    }

    #[test]
    fn test_default_config_paths_not_empty() {
        let paths = default_config_paths();
        assert_ne!(paths.len(), 0);
    }

    #[test]
    fn default_loader_includes_the_authoritative_claude_desktop_path() {
        let Some(claude_path) = claude_desktop_config_path() else {
            return;
        };

        let loader = ConfigLoader::default();
        assert!(loader.search_paths().contains(&claude_path));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn unix_loader_and_resolver_share_isolated_xdg_path() {
        let home = Path::new("/isolated/home");
        let xdg = std::ffi::OsStr::new("/isolated/xdg");
        let locations = ConfigLocations {
            home: Some(home.to_path_buf()),
            unix_config: unix_config_home(Some(home), Some(xdg)),
        };
        let expected = PathBuf::from("/isolated/xdg/Claude/claude_desktop_config.json");

        assert_eq!(
            claude_desktop_config_path_from(&locations),
            Some(expected.clone())
        );

        let loader = ConfigLoader {
            search_paths: default_config_paths_from(&locations),
        };
        assert!(loader.search_paths().contains(&expected));
        assert!(
            loader
                .search_paths()
                .contains(&PathBuf::from("/isolated/xdg/mcp/config.json"))
        );
        assert!(
            !loader
                .search_paths()
                .contains(&PathBuf::from("/isolated/xdg/claude/config.json"))
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn unix_empty_missing_or_relative_xdg_falls_back_to_isolated_home() {
        let home = Path::new("/isolated/home");
        let expected = home.join(".config");
        let xdg_values = [
            None,
            Some(std::ffi::OsStr::new("")),
            Some(std::ffi::OsStr::new("relative/config")),
        ];

        for xdg in xdg_values {
            assert_eq!(unix_config_home(Some(home), xdg), Some(expected.clone()));
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn unix_absolute_xdg_does_not_require_home() {
        let xdg = std::ffi::OsStr::new("/isolated/xdg");
        assert_eq!(
            unix_config_home(None, Some(xdg)),
            Some(PathBuf::from("/isolated/xdg"))
        );
    }

    #[test]
    fn test_config_error_display() {
        let errors = vec![
            (ConfigError::NotFound("path".into()), "not found"),
            (
                ConfigError::ServerNotFound("name".into()),
                "server not found",
            ),
            (ConfigError::ServerDisabled("name".into()), "disabled"),
            (ConfigError::ParseError("msg".into()), "parse"),
            (
                ConfigError::ClientError(McpError::request_cancelled()),
                "lifecycle",
            ),
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

    #[test]
    fn test_config_error_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no access");
        let config_err = ConfigError::ReadError(io_err);
        assert!(std::error::Error::source(&config_err).is_some());

        let not_found = ConfigError::NotFound("path".into());
        assert!(std::error::Error::source(&not_found).is_none());

        let parse_err = ConfigError::ParseError("bad".into());
        assert!(std::error::Error::source(&parse_err).is_none());

        let client_err = ConfigError::ClientError(McpError::request_cancelled());
        assert!(std::error::Error::source(&client_err).is_some());
    }

    #[test]
    fn active_and_cancelled_contexts_differ_only_at_cancellation_gate() {
        let mut config = McpConfig::new();
        config.add_server("cancelled", ServerConfig::new("definitely-not-a-command"));
        let original_config = config.to_json();

        let active_error = match config.client(&Cx::for_testing(), "cancelled") {
            Ok(_) => panic!("an unresolved command must not create a client"),
            Err(error) => error,
        };
        assert!(matches!(active_error, ConfigError::ClientError(_)));
        assert!(!matches!(
            active_error,
            ConfigError::ClientError(McpError {
                code: fastmcp_core::McpErrorCode::RequestCancelled,
                ..
            })
        ));
        assert_eq!(config.to_json(), original_config);

        let cancelled_cx = Cx::for_testing();
        cancelled_cx.set_cancel_requested(true);

        let error = match config.client(&cancelled_cx, "cancelled") {
            Ok(_) => panic!("cancelled context must be rejected before spawn"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ConfigError::ClientError(McpError {
                code: fastmcp_core::McpErrorCode::RequestCancelled,
                ..
            })
        ));
        assert_eq!(config.to_json(), original_config);
    }

    #[test]
    fn invalid_policy_precedes_config_lookup_and_process_creation() {
        let mut config = McpConfig::new();
        config.add_server("configured", ServerConfig::new("definitely-not-a-command"));
        let invalid_policy = RequestTimeoutPolicy {
            idle_timeout: std::time::Duration::ZERO,
            absolute_timeout: std::time::Duration::from_secs(1),
            reset_idle_on_matching_progress: true,
        };

        let error = match config.client_with_timeout_policy(
            &Cx::for_testing(),
            "missing",
            invalid_policy,
        ) {
            Ok(_) => panic!("invalid timeout policy must fail before configuration lookup"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ConfigError::ClientError(McpError {
                code: fastmcp_core::McpErrorCode::InvalidParams,
                ..
            })
        ));

        let cancelled_cx = Cx::for_testing();
        cancelled_cx.set_cancel_requested(true);
        let error =
            match config.client_with_timeout_policy(&cancelled_cx, "configured", invalid_policy) {
                Ok(_) => panic!("invalid timeout policy must fail before checkpoint and spawn"),
                Err(error) => error,
            };
        assert!(matches!(
            error,
            ConfigError::ClientError(McpError {
                code: fastmcp_core::McpErrorCode::InvalidParams,
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn policy_aware_config_client_applies_policy_to_initialization() {
        let mut config = McpConfig::new();
        config.add_server(
            "silent",
            ServerConfig::new("sh").with_args(["-c", "exec sleep 5"]),
        );
        let policy = RequestTimeoutPolicy::new(
            std::time::Duration::from_millis(50),
            std::time::Duration::from_millis(250),
        )
        .expect("custom initialization policy must validate");
        let started = std::time::Instant::now();

        let error = match config.client_with_timeout_policy(&Cx::for_testing(), "silent", policy) {
            Ok(_) => panic!("silent initialization must honor the custom idle timeout"),
            Err(error) => error,
        };
        let ConfigError::ClientError(error) = error else {
            panic!("initialization timeout must remain a client lifecycle error");
        };

        assert_eq!(error.message, "Request timed out at the idle deadline");
        assert_eq!(
            error.data,
            Some(serde_json::json!({"timeoutSource": "idle"}))
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn config_legacy_initialization_returns_a_legacy_only_session_plan() {
        let initialize_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "configured-legacy", "version": "1.0.0"}
            }
        });
        let response_line = serde_json::to_string(&initialize_response)
            .expect("serialize exact legacy initialization response");
        assert!(
            !response_line.contains('\''),
            "the shell fixture requires a single-quote-free JSON line"
        );
        let script = format!(
            "IFS= read -r _; printf '%s\\n' '{response_line}'; IFS= read -r _; exec sleep 2"
        );
        let mut config = McpConfig::new();
        config.add_server(
            "legacy",
            ServerConfig::new("sh").with_args(["-c", script.as_str()]),
        );

        let mut client = config
            .client(&Cx::for_request(), "legacy")
            .expect("configured stdio client completes exact legacy initialization");

        assert_eq!(client.protocol_policy(), ProtocolPolicy::LegacyOnly);
        assert_eq!(
            client.selected_protocol_era(),
            Some(fastmcp_protocol::protocol_policy::ProtocolEra::Legacy2024)
        );
        client.close().expect("configured legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn config_legacy_initialization_rejects_only_a_modern_peer_version() {
        let initialize_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "serverInfo": {"name": "configured-legacy", "version": "1.0.0"}
            }
        });
        let response_line = serde_json::to_string(&initialize_response)
            .expect("serialize wrong-era initialization response");
        assert!(
            !response_line.contains('\''),
            "the shell fixture requires a single-quote-free JSON line"
        );
        let script = format!("IFS= read -r _; printf '%s\\n' '{response_line}'; exec sleep 2");
        let mut config = McpConfig::new();
        config.add_server(
            "legacy",
            ServerConfig::new("sh").with_args(["-c", script.as_str()]),
        );

        let error = match config.client(&Cx::for_request(), "legacy") {
            Err(error) => error,
            Ok(_) => {
                panic!("changing only the peer era must reject configured legacy initialization")
            }
        };

        assert!(matches!(error, ConfigError::ClientError(_)));
        assert!(
            error
                .to_string()
                .contains("Server selected an unsupported MCP protocol version")
        );
    }

    #[test]
    fn test_config_error_into_mcp_error() {
        let err = ConfigError::ServerNotFound("test-srv".into());
        let mcp_err: McpError = err.into();
        assert_eq!(mcp_err.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(mcp_err.message.contains("test-srv"));
    }

    #[test]
    fn test_server_config_disabled_builder() {
        let config = ServerConfig::new("echo").disabled();
        assert!(config.disabled);
    }

    #[test]
    fn test_config_json_round_trip() {
        let mut config = McpConfig::new();
        config.add_server(
            "srv",
            ServerConfig::new("cmd")
                .with_args(["a1", "a2"])
                .with_env("K", "V")
                .with_cwd("/tmp"),
        );

        let json = config.to_json();
        let restored = McpConfig::from_json(&json).expect("round-trip parse");
        let srv = restored.get_server("srv").expect("server present");
        assert_eq!(srv.command, "cmd");
        assert_eq!(srv.args, vec!["a1", "a2"]);
        assert_eq!(srv.env.get("K"), Some(&"V".to_string()));
        assert_eq!(srv.cwd.as_deref(), Some("/tmp"));
    }

    #[test]
    fn test_config_toml_round_trip() {
        let mut config = McpConfig::new();
        config.add_server(
            "srv",
            ServerConfig::new("python").with_args(["-m", "server"]),
        );

        let toml_str = config.to_toml();
        let restored = McpConfig::from_toml(&toml_str).expect("round-trip parse");
        let srv = restored.get_server("srv").expect("server present");
        assert_eq!(srv.command, "python");
        assert_eq!(srv.args, vec!["-m", "server"]);
    }

    #[test]
    fn test_parse_invalid_json() {
        let canary = "JSON-CONFIG-SECRET-CANARY";
        let error = McpConfig::from_json(&format!(r#"{{"secret":"{canary}",}}"#))
            .expect_err("invalid JSON must fail");
        assert!(matches!(&error, ConfigError::ParseError(_)));
        assert!(!error.to_string().contains(canary));
    }

    #[test]
    fn test_parse_invalid_toml() {
        let canary = "TOML-CONFIG-SECRET-CANARY";
        let error = McpConfig::from_toml(&format!("secret = \"{canary}\"\n[invalid toml = = ="))
            .expect_err("invalid TOML must fail");
        assert!(matches!(&error, ConfigError::ParseError(_)));
        assert!(!error.to_string().contains(canary));
    }

    #[test]
    fn test_from_file_not_found() {
        let result = McpConfig::from_file("/nonexistent/path/to/config.json");
        assert!(matches!(result, Err(ConfigError::NotFound(_))));
    }

    #[test]
    fn test_config_merge_empty() {
        let mut base = McpConfig::new();
        base.add_server("a", ServerConfig::new("cmd_a"));
        base.merge(McpConfig::new());
        assert_eq!(base.mcp_servers.len(), 1);
        assert!(base.get_server("a").is_some());
    }

    #[test]
    fn test_config_loader_from_path() {
        let loader = ConfigLoader::from_path("/specific/path.json");
        assert_eq!(loader.search_paths().len(), 1);
        assert_eq!(
            loader.search_paths()[0],
            PathBuf::from("/specific/path.json")
        );
    }

    #[test]
    fn test_config_loader_load_no_files_exist() {
        let loader =
            ConfigLoader::from_path("/nonexistent/a.json").with_path("/nonexistent/b.json");
        let result = loader.load();
        assert!(matches!(result, Err(ConfigError::NotFound(_))));
    }

    #[test]
    fn test_config_loader_load_all_no_files() {
        let loader = ConfigLoader::from_path("/nonexistent/a.json");
        let config = loader.load_all().expect("missing paths are skipped");
        assert!(config.mcp_servers.is_empty());
    }

    #[test]
    fn config_loader_load_all_surfaces_an_existing_malformed_file() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let error = ConfigLoader::from_path(manifest)
            .load_all()
            .expect_err("an existing non-JSON file must not be silently omitted");

        assert!(matches!(error, ConfigError::ParseError(_)));
    }

    #[test]
    fn test_config_loader_existing_paths_empty() {
        let loader = ConfigLoader::from_path("/nonexistent/file.json");
        assert_eq!(loader.existing_paths().len(), 0);
    }

    #[test]
    fn test_config_loader_default() {
        let loader = ConfigLoader::default();
        assert_ne!(loader.search_paths().len(), 0);
    }

    #[test]
    fn test_enabled_servers_all_disabled() {
        let mut config = McpConfig::new();
        config.add_server("a", ServerConfig::new("cmd").disabled());
        config.add_server("b", ServerConfig::new("cmd").disabled());
        assert_eq!(config.enabled_servers().len(), 0);
    }

    #[test]
    fn test_claude_desktop_config_path_is_some() {
        // On supported/configured platforms, this should return Some when the
        // required platform directory is available.
        let path = claude_desktop_config_path();
        if dirs::home_dir().is_some() || dirs::data_dir().is_some() {
            assert!(path.is_some());
        }
    }

    #[test]
    fn test_server_config_with_multiple_env_vars() {
        let config = ServerConfig::new("cmd")
            .with_env("A", "1")
            .with_env("B", "2")
            .with_env("C", "3");
        assert_eq!(config.env.len(), 3);
        assert_eq!(config.env.get("A"), Some(&"1".to_string()));
        assert_eq!(config.env.get("B"), Some(&"2".to_string()));
        assert_eq!(config.env.get("C"), Some(&"3".to_string()));
    }

    #[test]
    fn test_config_spawn_error_display() {
        let err = ConfigError::SpawnError("process died".into());
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("spawn"));
        assert!(msg.contains("process died"));
    }

    #[test]
    fn test_config_empty_json_object() {
        let config = McpConfig::from_json("{}").expect("parse empty object");
        assert!(config.mcp_servers.is_empty());
    }

    #[test]
    fn test_config_json_with_defaults() {
        let json = r#"{"mcpServers": {"srv": {"command": "echo"}}}"#;
        let config = McpConfig::from_json(json).expect("parse");
        let srv = config.get_server("srv").unwrap();
        assert_eq!(srv.args.len(), 0);
        assert!(srv.env.is_empty());
        assert!(srv.cwd.is_none());
        assert!(!srv.disabled);
    }
}
