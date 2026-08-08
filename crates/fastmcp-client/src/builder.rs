//! Client builder for configuring MCP clients.
//!
//! The builder provides a fluent API for constructing MCP clients with
//! customizable timeout, retry, and subprocess spawn options.
//!
//! # Example
//!
//! ```ignore
//! use std::time::Duration;
//! use fastmcp_rust::{Client, ClientBuilder, McpResult, RequestTimeoutPolicy};
//!
//! fn connect() -> McpResult<Client> {
//!     ClientBuilder::new()
//!         .client_info("my-client", "1.0.0")
//!         .request_timeout_policy(RequestTimeoutPolicy::new(
//!             Duration::from_secs(30),
//!             Duration::from_secs(60),
//!         )?)
//!         .max_retries(3)
//!         .retry_delay_ms(1000)
//!         .working_dir("/tmp")
//!         .env("DEBUG", "1")
//!         .connect_stdio("uvx", &["my-server"])
//! }
//! ```

use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::{McpError, McpResult, block_on};
use fastmcp_protocol::extensions::McpAppsClientSettings;
use fastmcp_protocol::protocol_policy::ProtocolPolicy;
use fastmcp_protocol::{ClientCapabilities, ClientInfo};
use fastmcp_transport::StdioTransport;

use crate::{
    ChildGuard, ChildOwnership, Client, ClientHttpConnection, ClientHttpConnectionError,
    ClientHttpNegotiation, ClientHttpNegotiationError, ClientProtocolPlan, ClientSession,
    HttpClient, HttpClientError, ProcessGroupAnchor, RequestTimeoutPolicy,
    combine_operation_with_cleanup, is_cleanup_unverified, resolve_stdio_command,
};

/// Builder for configuring an MCP client.
///
/// Use this to configure timeout, retry, and spawn options before
/// connecting to an MCP server.
#[derive(Clone)]
pub struct ClientBuilder {
    /// Client identification info.
    client_info: ClientInfo,
    /// Validated ordinary-request idle/absolute timeout policy.
    timeout_policy: RequestTimeoutPolicy,
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
    /// Optional official MCP Apps client settings for final discovery.
    mcp_apps_settings: Option<McpAppsClientSettings>,
    /// Whether to defer initialization until first use.
    auto_initialize: bool,
    /// Whether the subprocess must be isolated in an owned Unix process group.
    owned_process_group: bool,
    protocol_plan: ClientProtocolPlan,
}

impl std::fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("client_info", &self.client_info)
            .field("timeout_policy", &self.timeout_policy)
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
            .field("mcp_apps_configured", &self.mcp_apps_settings.is_some())
            .field("auto_initialize", &self.auto_initialize)
            .field("owned_process_group", &self.owned_process_group)
            .finish()
    }
}

impl ClientBuilder {
    /// Creates a new client builder with default settings.
    ///
    /// Default configuration:
    /// - Client name: "fastmcp-client"
    /// - Request idle timeout: 30 seconds
    /// - Request absolute timeout: 120 seconds
    /// - Matching strictly increasing progress resets idle: enabled
    /// - Max retries: 0 (no retries)
    /// - Retry delay: 1 second
    /// - Inherit environment: true
    /// - Auto-initialize: false (initialize immediately on connect)
    /// - Protocol policy: Auto
    #[must_use]
    pub fn new() -> Self {
        Self {
            client_info: ClientInfo {
                name: "fastmcp-client".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            timeout_policy: RequestTimeoutPolicy::default(),
            max_retries: 0,
            retry_delay_ms: 1_000,
            working_dir: None,
            env_vars: HashMap::new(),
            inherit_env: true,
            capabilities: ClientCapabilities::default(),
            mcp_apps_settings: None,
            auto_initialize: false,
            owned_process_group: false,
            protocol_plan: ClientProtocolPlan::stdio(
                fastmcp_protocol::protocol_policy::ProtocolPolicy::Auto,
            ),
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

    /// Sets the validated idle/absolute policy for ordinary requests.
    ///
    /// Initialization uses the same idle and absolute bounds, but has no
    /// request-owned progress that could reset idle. On Unix, bounded
    /// child-pipe readiness polling enforces both response timers even while a
    /// server is silent or holds a partial frame. On non-Unix targets,
    /// the standard child pipe has no portable safe readiness primitive, so
    /// reads remain frame-boundary-only and synchronous child-stdin response
    /// writes cannot be preempted by these timers. It also has no equivalent
    /// bounded atomic cancellation-control write, so a required cancellation
    /// or timeout control explicitly fails that connection.
    #[must_use]
    pub fn request_timeout_policy(mut self, policy: RequestTimeoutPolicy) -> Self {
        self.timeout_policy = policy;
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

    /// Configures the official MCP Apps MIME types advertised during final discovery.
    ///
    /// Apps can activate only on a final MCP connection when the server also
    /// advertises its exact empty Apps marker. Exact legacy routes neither
    /// advertise nor activate these settings.
    #[must_use]
    pub fn mcp_apps(mut self, settings: McpAppsClientSettings) -> Self {
        self.mcp_apps_settings = Some(settings);
        self
    }

    /// Enables auto-initialization mode.
    ///
    /// When enabled, the client defers the MCP initialization handshake until
    /// the first method call (e.g., `list_tools`, `call_tool`). This allows
    /// the subprocess to start immediately without blocking on initialization.
    ///
    /// `ProtocolPolicy::Auto` is the exception: it completes its disposable
    /// modern probe during connection so a recognized refusal can be followed
    /// only by a fresh exact-legacy subprocess. Fixed modern and legacy plans
    /// retain deferred initialization.
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

    /// Requires ownership of the subprocess's inherited Unix process group.
    ///
    /// When enabled, a `/bin/sh` anchor becomes a dedicated process-group
    /// leader. The requested executable is still spawned directly, as the
    /// anchor's sibling in that group, so its executable, argument vector,
    /// environment, working directory, and protocol descriptors retain normal
    /// [`Command`] semantics. A private close-on-exec control pipe keeps the
    /// anchor alive and asks it to kill its own group on explicit close, drop,
    /// or owner-process death.
    ///
    /// The caller must retain exclusive ownership of the spawned child: a
    /// process-wide `waitpid(-1)` reaper or external signalling can interfere
    /// with bounded reap verification. Descendants that deliberately enter
    /// another process group or session are outside this ownership boundary.
    /// A host-side `fork` that retains the private control descriptor can also
    /// delay owner-death cleanup until that copy closes. This includes a
    /// concurrent setup-time raw fork on Unix targets whose standard library
    /// cannot create the internal socket pair with atomic close-on-exec.
    ///
    /// The mode fails closed during connection on platforms where this crate
    /// has no safe process-group or Job Object equivalent.
    #[must_use]
    pub fn owned_process_group(mut self, enabled: bool) -> Self {
        self.owned_process_group = enabled;
        self
    }

    /// Selects an immutable protocol and endpoint plan before process creation.
    #[must_use]
    pub fn protocol_plan(mut self, protocol_plan: ClientProtocolPlan) -> Self {
        self.protocol_plan = protocol_plan;
        self
    }

    /// Returns the immutable protocol plan that will be validated before connect.
    #[must_use]
    pub const fn selected_protocol_plan(&self) -> &ClientProtocolPlan {
        &self.protocol_plan
    }

    /// Starts a modern-first HTTP negotiation from this immutable builder plan.
    ///
    /// This is a side-effect-free admission boundary. The returned attempt
    /// permits at most one modern probe and binds its cache to the complete
    /// configured endpoint bundle rather than to an HTTP origin.
    pub fn http_negotiation(&self) -> Result<ClientHttpNegotiation, ClientHttpNegotiationError> {
        ClientHttpNegotiation::from_protocol_plan(&self.protocol_plan)
    }

    /// Connects the configured HTTP plan using the current capability context.
    ///
    /// `Auto` selects the admitted final stateless route or exact legacy
    /// SSE route internally; callers receive one ready connection.
    pub fn connect_http(self) -> Result<ClientHttpConnection, ClientHttpConnectionError> {
        block_on(async {
            let cx = Cx::current().expect("fastmcp runtime should install a current Cx");
            self.connect_http_with_cx(&cx).await
        })
    }

    /// Connects the configured HTTP plan with an explicit cancellation context.
    ///
    /// The connection consumes at most one disposable modern probe before
    /// `Auto` may open its exact legacy SSE fallback. It never leaves protocol
    /// classification to the caller.
    pub async fn connect_http_with_cx(
        self,
        cx: &Cx,
    ) -> Result<ClientHttpConnection, ClientHttpConnectionError> {
        ClientHttpConnection::connect_with_mcp_apps(
            cx,
            self.protocol_plan,
            self.client_info,
            self.capabilities,
            self.mcp_apps_settings,
        )
        .await
    }

    /// Connects a ready high-level HTTP client using the current capability context.
    ///
    /// In addition to selecting the immutable HTTP era, this completes the
    /// exact legacy initialization lifecycle when the plan selects SSE.
    pub fn connect_http_client(self) -> Result<HttpClient, HttpClientError> {
        block_on(async {
            let cx = Cx::current().expect("fastmcp runtime should install a current Cx");
            self.connect_http_client_with_cx(&cx).await
        })
    }

    /// Connects a ready high-level HTTP client with an explicit cancellation context.
    ///
    /// Modern clients are ready after `server/discover`; exact legacy clients
    /// are ready only after `initialize` and `notifications/initialized` have
    /// both completed on the admitted legacy routes.
    pub async fn connect_http_client_with_cx(self, cx: &Cx) -> Result<HttpClient, HttpClientError> {
        HttpClient::connect_with_mcp_apps(
            cx,
            self.protocol_plan,
            self.client_info,
            self.capabilities,
            self.mcp_apps_settings,
        )
        .await
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
    /// - The request idle/absolute policy is invalid
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
        // Reject unusable configuration once, before cancellation checks,
        // retries, command resolution, or subprocess creation. In particular,
        // auto-initialize must never return a live client that cannot issue its
        // first protocol request.
        self.timeout_policy.validate()?;
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
                Err(error) if is_cleanup_unverified(&error) => return Err(error),
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
        match self.protocol_plan.policy() {
            ProtocolPolicy::ModernOnly | ProtocolPolicy::LegacyOnly => self
                .try_connect_with_protocol_plan(
                    command,
                    args,
                    cx,
                    self.protocol_plan.clone(),
                    self.auto_initialize,
                ),
            ProtocolPolicy::Auto => self.try_connect_auto(command, args, cx),
        }
    }

    /// Selects an era with a disposable modern child before exposing a client.
    ///
    /// A stdio peer has one opening-frame classification, so the modern probe
    /// can never be reused for exact legacy initialization. Only the
    /// recognized JSON-RPC discovery refusal authorizes a second spawn.
    fn try_connect_auto(&self, command: &str, args: &[&str], cx: &Cx) -> McpResult<Client> {
        let modern_plan = ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly);
        match self.try_connect_with_protocol_plan(command, args, cx, modern_plan, false) {
            Ok(mut client) => {
                client.set_protocol_plan_after_selection(self.protocol_plan.clone());
                Ok(client)
            }
            Err(error) if crate::auto_legacy_fallback_is_authorized(&error) => {
                // The disposable modern child has been cleaned up before its
                // error reaches this branch. Observe cancellation again before
                // creating a fresh legacy child.
                if cx.checkpoint().is_err() {
                    return Err(McpError::request_cancelled());
                }
                let legacy_plan = ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly);
                let mut client =
                    self.try_connect_with_protocol_plan(command, args, cx, legacy_plan, false)?;
                client.set_protocol_plan_after_selection(self.protocol_plan.clone());
                Ok(client)
            }
            Err(error) => Err(error),
        }
    }

    /// Spawns one configured subprocess and applies one fixed protocol era.
    fn try_connect_with_protocol_plan(
        &self,
        command: &str,
        args: &[&str],
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
        defer_initialization: bool,
    ) -> McpResult<Client> {
        // Build the command
        let executable = resolve_stdio_command(command, self.working_dir.as_deref())?;
        let (mut cmd, child_ownership, mut group_anchor) =
            self.prepare_stdio_command(executable, args)?;
        cmd.stdin(Stdio::piped())
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
        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(error) => {
                let operation = Err(McpError::internal_error(format!(
                    "Failed to spawn subprocess: {error}"
                )));
                return combine_operation_with_cleanup(operation, || {
                    group_anchor
                        .as_mut()
                        .map_or(Ok(()), ProcessGroupAnchor::cleanup)
                });
            }
        };
        let mut child_guard = match group_anchor.take() {
            Some(anchor) => ChildGuard::with_process_group(child, anchor),
            None => ChildGuard::with_ownership(child, child_ownership),
        };
        if let Err(error) = child_guard.verify_group_anchor() {
            return combine_operation_with_cleanup(Err(error), || child_guard.cleanup());
        }

        // Get stdin/stdout handles
        let stdin = match child_guard.child_mut().stdin.take() {
            Some(stdin) => stdin,
            None => {
                return combine_operation_with_cleanup(
                    Err(McpError::internal_error("Failed to get subprocess stdin")),
                    || child_guard.cleanup(),
                );
            }
        };
        let stdout = match child_guard.child_mut().stdout.take() {
            Some(stdout) => stdout,
            None => {
                return combine_operation_with_cleanup(
                    Err(McpError::internal_error("Failed to get subprocess stdout")),
                    || child_guard.cleanup(),
                );
            }
        };

        // Create transport
        let transport = StdioTransport::new(stdout, stdin);
        let (child, group_anchor) = child_guard.disarm_all();

        if defer_initialization {
            // Create uninitialized client - initialization will happen on first use
            Ok(self.create_uninitialized_client(
                child,
                child_ownership,
                group_anchor,
                transport,
                cx,
                protocol_plan,
            ))
        } else {
            self.initialize_client(
                child,
                child_ownership,
                group_anchor,
                transport,
                cx,
                protocol_plan,
            )
        }
    }

    fn prepare_stdio_command(
        &self,
        executable: PathBuf,
        args: &[&str],
    ) -> McpResult<(Command, ChildOwnership, Option<ProcessGroupAnchor>)> {
        let mut command = Command::new(executable);
        command.args(args);
        if !self.owned_process_group {
            return Ok((command, ChildOwnership::DirectChild, None));
        }

        #[cfg(unix)]
        {
            let anchor = ProcessGroupAnchor::spawn()?;
            command.process_group(anchor.raw_process_group());
            Ok((command, ChildOwnership::OwnedProcessGroup, Some(anchor)))
        }

        #[cfg(not(unix))]
        {
            let _ = command;
            Err(McpError::internal_error(
                "Owned subprocess groups are unavailable on this platform",
            ))
        }
    }

    /// Creates an uninitialized client for auto-initialize mode.
    fn create_uninitialized_client(
        &self,
        child: Child,
        child_ownership: ChildOwnership,
        group_anchor: Option<ProcessGroupAnchor>,
        transport: StdioTransport<std::process::ChildStdout, std::process::ChildStdin>,
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
    ) -> Client {
        // Create a placeholder session - will be updated on first use
        let session = ClientSession::new_placeholder(
            self.client_info.clone(),
            self.capabilities.clone(),
            fastmcp_protocol::ServerInfo {
                name: String::new(),
                version: String::new(),
            },
            fastmcp_protocol::ServerCapabilities::default(),
        )
        .with_mcp_apps_settings(self.mcp_apps_settings.clone())
        .with_protocol_plan(protocol_plan);

        Client::from_parts_uninitialized_with_ownership(
            child,
            child_ownership,
            group_anchor,
            transport,
            cx.clone(),
            session,
            self.timeout_policy,
        )
    }

    /// Performs the initialization handshake and creates the client.
    fn initialize_client(
        &self,
        child: Child,
        child_ownership: ChildOwnership,
        group_anchor: Option<ProcessGroupAnchor>,
        transport: StdioTransport<std::process::ChildStdout, std::process::ChildStdin>,
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
    ) -> McpResult<Client> {
        let mut client = self.create_uninitialized_client(
            child,
            child_ownership,
            group_anchor,
            transport,
            cx,
            protocol_plan,
        );
        if let Err(error) = client.ensure_initialized() {
            let cleanup = client.close();
            return combine_operation_with_cleanup(Err(error), || cleanup);
        }
        Ok(client)
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

    #[cfg(unix)]
    fn auto_legacy_lifecycle_script(discovery_error_code: i32) -> String {
        format!(
            "IFS= read -r first || exit 1; \\
             case \"$first\" in \\
             *server/discover*) printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{{\"code\":{discovery_error_code},\"message\":\"final discovery unavailable\"}}}}' ;; \\
             *initialize*2024-11-05*) \\
             case \"$first\" in *io.modelcontextprotocol/ui*|*_meta*) exit 1 ;; esac; \\
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{{}},\"serverInfo\":{{\"name\":\"builder-auto-legacy\",\"version\":\"1.0.0\"}}}}}}'; \\
             IFS= read -r lifecycle || exit 1; \\
             case \"$lifecycle\" in *notifications/initialized*) case \"$lifecycle\" in *io.modelcontextprotocol/ui*|*_meta*) exit 1 ;; esac ;; *) exit 1 ;; esac; \\
             IFS= read -r request || exit 1; \\
             case \"$request\" in *ping*) case \"$request\" in *io.modelcontextprotocol/ui*|*_meta*) exit 1 ;; esac; printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{}}}}' ;; *) exit 1 ;; esac ;; \\
             *) exit 1 ;; esac; \\
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_apps_lifecycle_script(server_advertises_apps: bool) -> String {
        let discovery_result = if server_advertises_apps {
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"extensions":{"io.modelcontextprotocol/ui":{}}},"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"builder-modern-apps","version":"1.0.0"}}}}"#
        } else {
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"builder-modern-apps","version":"1.0.0"}}}}"#
        };
        let ping_case = if server_advertises_apps {
            "*ping*io.modelcontextprotocol/ui*)"
        } else {
            "*ping*io.modelcontextprotocol/ui*) exit 1 ;; *ping*)"
        };
        format!(
            "IFS= read -r discover || exit 1; \\
             case \"$discover\" in *server/discover*io.modelcontextprotocol/ui*) printf '%s\\n' '{discovery_result}' ;; *) exit 1 ;; esac; \\
             IFS= read -r ping || exit 1; \\
             case \"$ping\" in {ping_case} printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{}}}}' ;; *) exit 1 ;; esac; \\
             exec sleep 2"
        )
    }

    #[test]
    fn test_builder_defaults() {
        let builder = ClientBuilder::new();
        assert_eq!(builder.client_info.name, "fastmcp-client");
        assert_eq!(builder.timeout_policy, RequestTimeoutPolicy::default());
        assert_eq!(builder.max_retries, 0);
        assert_eq!(builder.retry_delay_ms, 1_000);
        assert!(builder.inherit_env);
        assert!(builder.working_dir.is_none());
        assert!(builder.env_vars.is_empty());
        assert!(!builder.auto_initialize);
        assert!(!builder.owned_process_group);
    }

    #[test]
    fn builder_retains_public_mcp_apps_configuration() {
        let settings = McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
            .expect("valid Apps MIME settings");
        let builder = ClientBuilder::new().mcp_apps(settings.clone());
        assert_eq!(builder.mcp_apps_settings, Some(settings));
    }

    #[test]
    fn test_builder_fluent_api() {
        let builder = ClientBuilder::new()
            .client_info("test-client", "2.0.0")
            .request_timeout_policy(
                RequestTimeoutPolicy::new(Duration::from_secs(20), Duration::from_secs(60))
                    .unwrap()
                    .reset_idle_on_matching_progress(false),
            )
            .max_retries(3)
            .retry_delay_ms(500)
            .working_dir("/tmp")
            .env("FOO", "bar")
            .env("BAZ", "qux")
            .inherit_env(false)
            .owned_process_group(true);

        assert_eq!(builder.client_info.name, "test-client");
        assert_eq!(builder.client_info.version, "2.0.0");
        assert_eq!(
            builder.timeout_policy,
            RequestTimeoutPolicy::new(Duration::from_secs(20), Duration::from_secs(60))
                .unwrap()
                .reset_idle_on_matching_progress(false)
        );
        assert_eq!(builder.max_retries, 3);
        assert_eq!(builder.retry_delay_ms, 500);
        assert_eq!(builder.working_dir, Some(PathBuf::from("/tmp")));
        assert_eq!(builder.env_vars.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(builder.env_vars.get("BAZ"), Some(&"qux".to_string()));
        assert!(!builder.inherit_env);
        assert!(builder.owned_process_group);
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
            .request_timeout_policy(
                RequestTimeoutPolicy::new(Duration::from_secs(4), Duration::from_secs(5)).unwrap(),
            );

        let builder2 = builder1.clone();

        assert_eq!(builder2.client_info.name, "test");
        assert_eq!(
            builder2.timeout_policy,
            RequestTimeoutPolicy::new(Duration::from_secs(4), Duration::from_secs(5)).unwrap()
        );
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
        assert_eq!(builder.timeout_policy, RequestTimeoutPolicy::default());
        assert_eq!(builder.max_retries, 0);
        assert!(!builder.auto_initialize);
        assert!(!builder.owned_process_group);
    }

    #[cfg(unix)]
    #[test]
    fn reality_check_regression_owned_process_group_preserves_spawn_command() {
        let builder = ClientBuilder::new().owned_process_group(true);
        let (command, ownership, mut anchor) = builder
            .prepare_stdio_command(PathBuf::from("echo"), &["--flag"])
            .expect("Unix owned-group command");

        assert_eq!(ownership, ChildOwnership::OwnedProcessGroup);
        assert_eq!(command.get_program(), "echo");
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(arguments, vec!["--flag".to_owned()]);
        anchor
            .as_mut()
            .expect("owned group has an anchor")
            .cleanup()
            .expect("anchor cleanup");
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
    fn invalid_timeout_policy_is_rejected_by_its_constructor() {
        for (idle, absolute) in [
            (Duration::ZERO, Duration::from_millis(1)),
            (
                crate::MAX_CLIENT_IDLE_TIMEOUT + Duration::from_millis(1),
                Duration::from_millis(1),
            ),
            (Duration::from_millis(1), Duration::ZERO),
            (
                Duration::from_millis(1),
                crate::MAX_CLIENT_ABSOLUTE_TIMEOUT + Duration::from_millis(1),
            ),
            (Duration::MAX, Duration::MAX),
        ] {
            let error = RequestTimeoutPolicy::new(idle, absolute)
                .expect_err("invalid timeout policy must be rejected");
            assert_eq!(error.code, McpErrorCode::InvalidParams);
        }
    }

    #[test]
    fn builder_debug_redacts_subprocess_environment_values() {
        let env_value_canary = "builder-env-api-value-canary";
        let builder = ClientBuilder::new()
            .client_info("dbg-test", "0.1")
            .request_timeout_policy(
                RequestTimeoutPolicy::new(Duration::from_secs(21), Duration::from_secs(42))
                    .unwrap()
                    .reset_idle_on_matching_progress(false),
            )
            .working_dir("/private/debug/path")
            .env("SERVICE_API_TOKEN", env_value_canary)
            .inherit_env(false);
        let debug = format!("{:?}", builder);

        assert!(debug.contains("ClientBuilder"));
        assert!(debug.contains("dbg-test"));
        assert!(debug.contains("0.1"));
        assert!(debug.contains("idle_timeout: 21s"));
        assert!(debug.contains("absolute_timeout: 42s"));
        assert!(debug.contains("reset_idle_on_matching_progress: false"));
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
            .request_timeout_policy(
                RequestTimeoutPolicy::new(Duration::from_millis(20), Duration::from_millis(40))
                    .unwrap(),
            )
            .connect_stdio("sh", &["-c", "exec sleep 5"]);

        let Err(error) = result else {
            panic!("silent initialization should time out");
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
    fn public_builder_auto_with_configured_apps_falls_back_without_legacy_metadata_leak() {
        let script = auto_legacy_lifecycle_script(-32601);
        let mut client = ClientBuilder::new()
            .mcp_apps(
                McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
                    .expect("valid Apps MIME settings"),
            )
            .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::Auto))
            .connect_stdio_with_cx("sh", &["-c", script.as_str()], &Cx::for_request())
            .expect("recognized discovery refusal starts a fresh exact legacy client");

        assert_eq!(client.protocol_policy(), ProtocolPolicy::Auto);
        assert_eq!(
            client.selected_protocol_era(),
            Some(fastmcp_protocol::protocol_policy::ProtocolEra::Legacy2024)
        );
        client
            .ping()
            .expect("the public builder returns a usable Auto-selected legacy client");
        client.close().expect("Auto-selected legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn public_builder_auto_with_configured_apps_rejects_only_an_unsupported_final_discovery_error()
    {
        let script = auto_legacy_lifecycle_script(-32022);
        let builder = ClientBuilder::new()
            .mcp_apps(
                McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
                    .expect("valid Apps MIME settings"),
            )
            .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::Auto));
        let state_before_connect = builder.selected_protocol_plan().clone();

        let error = match builder.clone().connect_stdio_with_cx(
            "sh",
            &["-c", script.as_str()],
            &Cx::for_request(),
        ) {
            Ok(_) => panic!("changing only the discovery error must not authorize legacy fallback"),
            Err(error) => error,
        };

        assert!(error.message.contains("final discovery unavailable"));
        assert_eq!(builder.selected_protocol_plan(), &state_before_connect);
    }

    #[cfg(unix)]
    #[test]
    fn public_builder_advertises_configured_apps_after_active_modern_discovery() {
        let script = modern_apps_lifecycle_script(true);
        let mut client = ClientBuilder::new()
            .mcp_apps(
                McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
                    .expect("valid Apps MIME settings"),
            )
            .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
            .connect_stdio_with_cx("sh", &["-c", script.as_str()], &Cx::for_request())
            .expect("active modern discovery initializes the public Apps client");

        assert!(client.mcp_apps_active());
        client
            .ping()
            .expect("active Apps negotiation advertises Apps on the public request path");
        client.close().expect("active Apps client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn public_builder_omits_configured_apps_after_one_field_inactive_modern_discovery() {
        let script = modern_apps_lifecycle_script(false);
        let mut client = ClientBuilder::new()
            .mcp_apps(
                McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
                    .expect("valid Apps MIME settings"),
            )
            .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
            .connect_stdio_with_cx("sh", &["-c", script.as_str()], &Cx::for_request())
            .expect("one missing server Apps declaration initializes modern inactive Apps state");

        assert!(!client.mcp_apps_active());
        client
            .ping()
            .expect("inactive Apps negotiation omits Apps on the public request path");
        client.close().expect("inactive Apps client cleanup");
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
