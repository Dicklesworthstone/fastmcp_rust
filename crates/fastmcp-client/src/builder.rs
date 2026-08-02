//! Client builder for configuring MCP clients.
//!
//! The builder provides a fluent API for constructing MCP clients with
//! customizable timeout, retry, and subprocess spawn options.
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_rust::ClientBuilder;
//!
//! let client = ClientBuilder::new()
//!     .client_info("my-client", "1.0.0")
//!     .timeout_ms(60_000)
//!     .max_retries(3)
//!     .retry_delay_ms(1000)
//!     .working_dir("/tmp")
//!     .env("DEBUG", "1")
//!     .connect_stdio("uvx", &["my-server"])?;
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::{McpError, McpResult, block_on};
use fastmcp_protocol::{ClientCapabilities, ClientInfo};
use fastmcp_transport::{StdioTransport, Transport};

use crate::{ChildGuard, Client, ClientSession, resolve_stdio_command};

/// Builder for configuring an MCP client.
///
/// Use this to configure timeout, retry, and spawn options before
/// connecting to an MCP server.
#[derive(Clone)]
pub struct ClientBuilder {
    /// Client identification info.
    client_info: ClientInfo,
    /// Request timeout in milliseconds.
    timeout_ms: u64,
    /// Maximum number of connection retries.
    max_retries: u32,
    /// Delay between retries in milliseconds.
    retry_delay_ms: u64,
    /// Working directory for subprocess.
    working_dir: Option<PathBuf>,
    /// Environment variables to set for subprocess.
    env_vars: HashMap<String, String>,
    /// Whether to inherit parent's environment.
    inherit_env: bool,
    /// Client capabilities to advertise.
    capabilities: ClientCapabilities,
    /// Whether to defer initialization until first use.
    auto_initialize: bool,
}

impl std::fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("client_info", &self.client_info)
            .field("timeout_ms", &self.timeout_ms)
            .field("max_retries", &self.max_retries)
            .field("retry_delay_ms", &self.retry_delay_ms)
            .field("working_dir_set", &self.working_dir.is_some())
            .field("env_var_count", &self.env_vars.len())
            .field("inherit_env", &self.inherit_env)
            .field("sampling_capability", &self.capabilities.sampling.is_some())
            .field(
                "elicitation_capability",
                &self.capabilities.elicitation.is_some(),
            )
            .field("roots_capability", &self.capabilities.roots.is_some())
            .field("auto_initialize", &self.auto_initialize)
            .finish()
    }
}

impl ClientBuilder {
    /// Creates a new client builder with default settings.
    ///
    /// Default configuration:
    /// - Client name: "fastmcp-client"
    /// - Timeout: 30 seconds
    /// - Max retries: 0 (no retries)
    /// - Retry delay: 1 second
    /// - Inherit environment: true
    /// - Auto-initialize: false (initialize immediately on connect)
    #[must_use]
    pub fn new() -> Self {
        Self {
            client_info: ClientInfo {
                name: "fastmcp-client".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            timeout_ms: 30_000,
            max_retries: 0,
            retry_delay_ms: 1_000,
            working_dir: None,
            env_vars: HashMap::new(),
            inherit_env: true,
            capabilities: ClientCapabilities::default(),
            auto_initialize: false,
        }
    }

    /// Sets the client name and version.
    ///
    /// This information is sent to the server during initialization.
    #[must_use]
    pub fn client_info(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.client_info = ClientInfo {
            name: name.into(),
            version: version.into(),
        };
        self
    }

    /// Sets the response deadline in milliseconds.
    ///
    /// This is applied to the initialization handshake and subsequent response
    /// receives. On Unix, bounded child-pipe readiness polling makes it a hard
    /// receive deadline even while a server is silent or holds a partial
    /// frame. On non-Unix targets, the standard child pipe has no portable safe
    /// readiness primitive, so the deadline remains frame-boundary-only.
    /// Default is 30,000ms (30 seconds).
    #[must_use]
    pub fn timeout_ms(mut self, timeout: u64) -> Self {
        self.timeout_ms = timeout;
        self
    }

    /// Sets the maximum number of connection retries.
    ///
    /// When connecting to a server fails, the client will retry up to
    /// this many times before returning an error. Default is 0 (no retries).
    #[must_use]
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Sets the delay between connection retries in milliseconds.
    ///
    /// Default is 1,000ms (1 second).
    #[must_use]
    pub fn retry_delay_ms(mut self, delay: u64) -> Self {
        self.retry_delay_ms = delay;
        self
    }

    /// Sets the working directory for the subprocess.
    ///
    /// If not set, the subprocess inherits the current working directory.
    #[must_use]
    pub fn working_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(path.into());
        self
    }

    /// Adds an environment variable for the subprocess.
    ///
    /// Multiple calls to this method accumulate environment variables.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.insert(key.into(), value.into());
        self
    }

    /// Adds multiple environment variables for the subprocess.
    #[must_use]
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (key, value) in vars {
            self.env_vars.insert(key.into(), value.into());
        }
        self
    }

    /// Sets whether to inherit the parent process's environment.
    ///
    /// If true (default), the subprocess starts with the parent's environment
    /// plus any variables added via [`env`](Self::env) or [`envs`](Self::envs).
    ///
    /// If false, the subprocess starts with only the explicitly set variables.
    #[must_use]
    pub fn inherit_env(mut self, inherit: bool) -> Self {
        self.inherit_env = inherit;
        self
    }

    /// Sets the client capabilities advertised during initialization.
    ///
    /// The complete value replaces the default empty capability set.
    #[must_use]
    pub fn capabilities(mut self, capabilities: ClientCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Enables auto-initialization mode.
    ///
    /// When enabled, the client defers the MCP initialization handshake until
    /// the first method call (e.g., `list_tools`, `call_tool`). This allows
    /// the subprocess to start immediately without blocking on initialization.
    ///
    /// Default is `false` (initialize immediately on connect).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let client = ClientBuilder::new()
    ///     .auto_initialize(true)
    ///     .connect_stdio("uvx", &["my-server"])?;
    ///
    /// // Subprocess is running but not yet initialized
    /// // Initialization happens on first use:
    /// let tools = client.list_tools()?; // Initializes here
    /// ```
    #[must_use]
    pub fn auto_initialize(mut self, enabled: bool) -> Self {
        self.auto_initialize = enabled;
        self
    }

    /// Connects to a server via stdio subprocess.
    ///
    /// Spawns the specified command as a subprocess and communicates via
    /// stdin/stdout using JSON-RPC over NDJSON framing.
    ///
    /// # Arguments
    ///
    /// * `command` - The command to run (e.g., "uvx", "npx")
    /// * `args` - Arguments to pass to the command
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The subprocess fails to spawn
    /// - The initialization handshake fails
    /// - All retry attempts are exhausted
    pub fn connect_stdio(self, command: &str, args: &[&str]) -> McpResult<Client> {
        block_on(async {
            let cx = Cx::current().expect("fastmcp runtime should install a current Cx");
            self.connect_stdio_with_cx(command, args, &cx)
        })
    }

    /// Connects to a server via stdio subprocess with a provided Cx.
    ///
    /// Same as [`connect_stdio`](Self::connect_stdio) but allows providing
    /// a custom capability context for cancellation support.
    pub fn connect_stdio_with_cx(self, command: &str, args: &[&str], cx: &Cx) -> McpResult<Client> {
        let mut last_error = None;
        // Compute attempts in u64 to avoid overflow when max_retries == u32::MAX.
        let attempts = u64::from(self.max_retries) + 1;

        for attempt in 0..attempts {
            // Honor cancellation/budget before each attempt.
            if cx.checkpoint().is_err() {
                return Err(McpError::request_cancelled());
            }

            if attempt > 0 {
                // Delay before retry while still observing cancellation.
                // Slice sleeps so cancellation is detected promptly even for long delays.
                let mut remaining_ms = self.retry_delay_ms;
                while remaining_ms > 0 {
                    if cx.checkpoint().is_err() {
                        return Err(McpError::request_cancelled());
                    }

                    let sleep_ms = remaining_ms.min(25);
                    std::thread::sleep(Duration::from_millis(sleep_ms));
                    remaining_ms = remaining_ms.saturating_sub(sleep_ms);
                }
            }

            match self.try_connect(command, args, cx) {
                Ok(client) => return Ok(client),
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        // All attempts failed
        Err(last_error.unwrap_or_else(|| McpError::internal_error("Connection failed")))
    }

    /// Attempts a single connection.
    fn try_connect(&self, command: &str, args: &[&str], cx: &Cx) -> McpResult<Client> {
        // Build the command
        let executable = resolve_stdio_command(command, self.working_dir.as_deref())?;
        let mut cmd = Command::new(executable);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        // Set working directory if specified
        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        // Set environment
        if !self.inherit_env {
            cmd.env_clear();
        }
        for (key, value) in &self.env_vars {
            cmd.env(key, value);
        }
        // Spawn the subprocess
        let child = cmd
            .spawn()
            .map_err(|e| McpError::internal_error(format!("Failed to spawn subprocess: {e}")))?;
        let mut child_guard = ChildGuard::new(child);

        // Get stdin/stdout handles
        let stdin = child_guard
            .child_mut()
            .stdin
            .take()
            .ok_or_else(|| McpError::internal_error("Failed to get subprocess stdin"))?;
        let stdout = child_guard
            .child_mut()
            .stdout
            .take()
            .ok_or_else(|| McpError::internal_error("Failed to get subprocess stdout"))?;

        // Create transport
        let transport = StdioTransport::new(stdout, stdin);
        let child = child_guard.disarm();

        if self.auto_initialize {
            // Create uninitialized client - initialization will happen on first use
            Ok(self.create_uninitialized_client(child, transport, cx))
        } else {
            // Perform initialization immediately
            self.initialize_client(child, transport, cx)
        }
    }

    /// Creates an uninitialized client for auto-initialize mode.
    fn create_uninitialized_client(
        &self,
        child: Child,
        transport: StdioTransport<std::process::ChildStdout, std::process::ChildStdin>,
        cx: &Cx,
    ) -> Client {
        // Create a placeholder session - will be updated on first use
        let session = ClientSession::new(
            self.client_info.clone(),
            self.capabilities.clone(),
            fastmcp_protocol::ServerInfo {
                name: String::new(),
                version: String::new(),
            },
            fastmcp_protocol::ServerCapabilities::default(),
            String::new(),
        );

        Client::from_parts_uninitialized(child, transport, cx.clone(), session, self.timeout_ms)
    }

    /// Performs the initialization handshake and creates the client.
    fn initialize_client(
        &self,
        child: Child,
        mut transport: StdioTransport<std::process::ChildStdout, std::process::ChildStdin>,
        cx: &Cx,
    ) -> McpResult<Client> {
        // Guard ensures child process is killed if initialization fails.
        // Disarmed when client is successfully created.
        let child_guard = ChildGuard::new(child);

        let init_result = match crate::initialize_child_transport(
            &mut transport,
            cx,
            &self.client_info,
            &self.capabilities,
            self.timeout_ms,
        ) {
            Ok(result) => result,
            Err(error) => {
                let _ = transport.close();
                return Err(error);
            }
        };

        // Create session
        let session = ClientSession::new(
            self.client_info.clone(),
            self.capabilities.clone(),
            init_result.server_info,
            init_result.capabilities,
            init_result.protocol_version,
        );

        // Create client - disarm guard since Client now owns the subprocess
        Ok(Client::from_parts(
            child_guard.disarm(),
            transport,
            cx.clone(),
            session,
            self.timeout_ms,
        ))
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_core::McpErrorCode;

    #[test]
    fn test_builder_defaults() {
        let builder = ClientBuilder::new();
        assert_eq!(builder.client_info.name, "fastmcp-client");
        assert_eq!(builder.timeout_ms, 30_000);
        assert_eq!(builder.max_retries, 0);
        assert_eq!(builder.retry_delay_ms, 1_000);
        assert!(builder.inherit_env);
        assert!(builder.working_dir.is_none());
        assert!(builder.env_vars.is_empty());
        assert!(!builder.auto_initialize);
    }

    #[test]
    fn test_builder_fluent_api() {
        let builder = ClientBuilder::new()
            .client_info("test-client", "2.0.0")
            .timeout_ms(60_000)
            .max_retries(3)
            .retry_delay_ms(500)
            .working_dir("/tmp")
            .env("FOO", "bar")
            .env("BAZ", "qux")
            .inherit_env(false);

        assert_eq!(builder.client_info.name, "test-client");
        assert_eq!(builder.client_info.version, "2.0.0");
        assert_eq!(builder.timeout_ms, 60_000);
        assert_eq!(builder.max_retries, 3);
        assert_eq!(builder.retry_delay_ms, 500);
        assert_eq!(builder.working_dir, Some(PathBuf::from("/tmp")));
        assert_eq!(builder.env_vars.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(builder.env_vars.get("BAZ"), Some(&"qux".to_string()));
        assert!(!builder.inherit_env);
    }

    #[test]
    fn test_builder_envs() {
        let vars = [("KEY1", "value1"), ("KEY2", "value2")];
        let builder = ClientBuilder::new().envs(vars);

        assert_eq!(builder.env_vars.get("KEY1"), Some(&"value1".to_string()));
        assert_eq!(builder.env_vars.get("KEY2"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_builder_clone() {
        let builder1 = ClientBuilder::new()
            .client_info("test", "1.0")
            .timeout_ms(5000);

        let builder2 = builder1.clone();

        assert_eq!(builder2.client_info.name, "test");
        assert_eq!(builder2.timeout_ms, 5000);
    }

    #[test]
    fn test_builder_auto_initialize() {
        let builder = ClientBuilder::new().auto_initialize(true);
        assert!(builder.auto_initialize);

        let builder = ClientBuilder::new().auto_initialize(false);
        assert!(!builder.auto_initialize);
    }

    #[test]
    fn test_builder_default_trait() {
        let builder = ClientBuilder::default();
        assert_eq!(builder.client_info.name, "fastmcp-client");
        assert_eq!(builder.timeout_ms, 30_000);
        assert_eq!(builder.max_retries, 0);
        assert!(!builder.auto_initialize);
    }

    #[test]
    fn test_builder_env_override() {
        let builder = ClientBuilder::new()
            .env("KEY", "first")
            .env("KEY", "second");
        assert_eq!(builder.env_vars.get("KEY"), Some(&"second".to_string()));
    }

    #[test]
    fn test_builder_envs_combined_with_env() {
        let builder = ClientBuilder::new()
            .env("A", "1")
            .envs([("B", "2"), ("C", "3")])
            .env("D", "4");
        assert_eq!(builder.env_vars.len(), 4);
        assert_eq!(builder.env_vars.get("A"), Some(&"1".to_string()));
        assert_eq!(builder.env_vars.get("B"), Some(&"2".to_string()));
        assert_eq!(builder.env_vars.get("C"), Some(&"3".to_string()));
        assert_eq!(builder.env_vars.get("D"), Some(&"4".to_string()));
    }

    #[test]
    fn test_connect_stdio_with_cx_respects_cancellation_during_retries() {
        let cx = Cx::for_request();
        cx.set_cancel_requested(true);
        let result = ClientBuilder::new()
            .max_retries(2)
            .retry_delay_ms(100)
            .connect_stdio_with_cx("definitely-not-a-real-command", &[], &cx);

        assert!(
            result.is_err(),
            "cancelled context should abort before retry attempts"
        );
        let err = result.err().expect("error result");
        assert_eq!(err.code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn test_connect_stdio_with_cx_max_retries_does_not_overflow() {
        let cx = Cx::for_request();
        cx.set_cancel_requested(true);

        let result = ClientBuilder::new()
            .max_retries(u32::MAX)
            .retry_delay_ms(1)
            .connect_stdio_with_cx("definitely-not-a-real-command", &[], &cx);

        assert!(
            result.is_err(),
            "cancelled context should return an error, not panic from retry overflow"
        );
        let err = result.err().expect("error result");
        assert_eq!(err.code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn builder_debug_redacts_subprocess_environment_values() {
        let env_value_canary = "builder-env-api-value-canary";
        let builder = ClientBuilder::new()
            .client_info("dbg-test", "0.1")
            .timeout_ms(42_000)
            .working_dir("/private/debug/path")
            .env("SERVICE_API_TOKEN", env_value_canary)
            .inherit_env(false);
        let debug = format!("{:?}", builder);

        assert!(debug.contains("ClientBuilder"));
        assert!(debug.contains("dbg-test"));
        assert!(debug.contains("0.1"));
        assert!(debug.contains("timeout_ms: 42000"));
        assert!(debug.contains("working_dir_set: true"));
        assert!(debug.contains("env_var_count: 1"));
        assert!(debug.contains("inherit_env: false"));
        assert!(!debug.contains(env_value_canary));
        assert!(!debug.contains("SERVICE_API_TOKEN"));
        assert!(!debug.contains("/private/debug/path"));
    }

    #[test]
    fn connect_stdio_nonexistent_command_fails() {
        let result = ClientBuilder::new()
            .max_retries(0)
            .connect_stdio("fastmcp_nonexistent_binary_xyz", &["--version"]);
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn connect_stdio_times_out_during_silent_initialization() {
        let started = std::time::Instant::now();
        let result = ClientBuilder::new()
            .timeout_ms(40)
            .connect_stdio("sh", &["-c", "exec sleep 5"]);

        let Err(error) = result else {
            panic!("silent initialization should time out");
        };
        assert_eq!(error.message, "Request timed out");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn builder_working_dir_last_wins() {
        let builder = ClientBuilder::new()
            .working_dir("/first")
            .working_dir("/second");
        assert_eq!(builder.working_dir, Some(PathBuf::from("/second")));
    }

    // =========================================================================
    // Additional coverage tests (bd-10fu)
    // =========================================================================

    #[cfg(unix)]
    #[test]
    fn child_guard_disarm_returns_child() {
        let mut command = Command::new("true");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().expect("failed to spawn 'true'");
        let guard = ChildGuard::new(child);
        let mut returned = guard.disarm();
        // disarm gives back a valid Child we can wait on
        let status = returned.wait().expect("wait failed");
        assert!(status.success());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_guard_drop_kills_child() {
        let mut command = Command::new("sleep");
        command
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().expect("failed to spawn 'sleep'");
        let pid = child.id();
        {
            let _guard = ChildGuard::new(child);
            // guard dropped here → child is killed and waited
        }
        // Verify the process is no longer running by trying to wait on it
        // via /proc (Linux-specific but sufficient for CI)
        let proc_path = format!("/proc/{}/status", pid);
        assert!(
            !std::path::Path::new(&proc_path).exists(),
            "process should no longer exist after drop"
        );
    }

    #[test]
    fn builder_capabilities_default_is_empty() {
        let builder = ClientBuilder::new();
        assert!(builder.capabilities.sampling.is_none());
        assert!(builder.capabilities.elicitation.is_none());
        assert!(builder.capabilities.roots.is_none());
    }

    #[test]
    fn builder_capabilities_replaces_the_advertised_set() {
        let capabilities = ClientCapabilities {
            sampling: Some(fastmcp_protocol::SamplingCapability {}),
            elicitation: None,
            roots: None,
        };
        let builder = ClientBuilder::new().capabilities(capabilities);

        assert!(builder.capabilities.sampling.is_some());
        assert!(builder.capabilities.elicitation.is_none());
        assert!(builder.capabilities.roots.is_none());
    }

    #[test]
    fn connect_stdio_spawn_failure_error_message() {
        let result = ClientBuilder::new()
            .max_retries(0)
            .connect_stdio("fastmcp_no_such_binary_abc123", &[]);
        match result {
            Err(err) => assert!(
                err.message.contains("spawn"),
                "error should mention spawn failure: {}",
                err.message
            ),
            Ok(_) => panic!("expected spawn to fail"),
        }
    }
}
