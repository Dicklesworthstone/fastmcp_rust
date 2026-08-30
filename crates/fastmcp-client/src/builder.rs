//! Client builder for configuring MCP clients.
//!
//! The builder provides a fluent API for constructing MCP clients with
//! customizable timeout, retry, and subprocess spawn options.
//!
//! # Example
//!
//! ```ignore
//! use std::time::Duration;
//! use fastmcp_rust::{Client, ClientBuilder, Cx, McpResult, RequestTimeoutPolicy};
//!
//! async fn connect(cx: &Cx) -> McpResult<Client> {
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
//!         .connect_stdio_with_cx("uvx", &["my-server"], cx)
//!         .await
//! }
//! ```

use std::collections::HashMap;
#[cfg(feature = "websocket-experimental")]
use std::future::Future;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asupersync::Cx;
#[cfg(feature = "websocket-experimental")]
use asupersync::io::{AsyncRead, AsyncWrite};
use fastmcp_core::{
    McpContext, McpError, McpResult, SamplingRequest, SamplingRequestMessage, SamplingRole,
};
use fastmcp_protocol::extensions::{
    ClientExtensionDiscovery, ExtensionDescriptorRegistry, ExtensionSettingsCompatibilityResolver,
    McpAppsClientSettings,
};
use fastmcp_protocol::protocol_policy::ProtocolPolicy;
use fastmcp_protocol::{
    ClientCapabilities, ClientInfo, CreateMessageParams, CreateMessageResult, ListRootsResult,
    Root, RootsCapability, SamplingContent,
};
use fastmcp_transport::StdioTransport;
#[cfg(feature = "websocket-experimental")]
use fastmcp_transport::websocket::AsyncWsClientTransport;

#[cfg(all(test, unix, feature = "legacy-2024-11-05"))]
use crate::ReverseRequestCancellation;
#[cfg(feature = "websocket-experimental")]
use crate::WebSocketClient;
use crate::http_executor::ModernHttpExecutorError;
use crate::{
    AutoStdioFallbackSignal, ChildGuard, ChildOwnership, Client, ClientExtensionRuntime,
    ClientHttpConnection, ClientHttpConnectionError, ClientHttpNegotiation,
    ClientHttpNegotiationError, ClientProtocolPlan, ClientSession, HttpClient, HttpClientError,
    ModernHttpClientError, ProcessGroupAnchor, RequestTimeoutPolicy, ReverseRequestHandlers,
    combine_operation_and_cleanup, combine_operation_with_cleanup, is_cleanup_unverified,
    resolve_stdio_command, validate_protocol_plan_feature,
};

#[cfg(feature = "legacy-2024-11-05")]
const DEFAULT_PROTOCOL_POLICY: ProtocolPolicy = ProtocolPolicy::Auto;
#[cfg(not(feature = "legacy-2024-11-05"))]
const DEFAULT_PROTOCOL_POLICY: ProtocolPolicy = ProtocolPolicy::ModernOnly;

/// The maximum number of connection attempts admitted by the client retry policy.
const MAX_CONNECTION_ATTEMPTS: u32 = 8;
/// The maximum delay before one connection retry.
const MAX_CONNECTION_RETRY_DELAY: Duration = Duration::from_secs(30);
/// The maximum elapsed time for the entire connection retry operation.
const MAX_CONNECTION_RETRY_ELAPSED: Duration = Duration::from_secs(120);
/// The elapsed cap used by the legacy retry-count and millisecond-delay setters.
const DEFAULT_CONNECTION_RETRY_ELAPSED: Duration = Duration::from_secs(120);
/// Bounded timer slice used to observe a caller-owned context while waiting.
const CONNECTION_RETRY_CANCEL_SLICE: Duration = Duration::from_millis(25);

/// One initialized stdio child attempt. `Fallback` is possible only for the
/// disposable modern Auto probe, after its child has been fully cleaned up.
enum StdioConnectionAttempt {
    Connected(Box<Client>),
    Fallback(AutoStdioFallbackSignal),
}

fn legacy_capabilities_for_handlers(
    capabilities: &ClientCapabilities,
    handlers: &ReverseRequestHandlers,
) -> ClientCapabilities {
    let mut legacy_capabilities = capabilities.clone();
    handlers.derive_legacy_capabilities(&mut legacy_capabilities);
    legacy_capabilities
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConnectionRetryPolicy {
    max_attempts: u32,
    retry_delay: Duration,
    total_elapsed: Duration,
}

impl ConnectionRetryPolicy {
    fn new(max_attempts: u32, retry_delay: Duration, total_elapsed: Duration) -> McpResult<Self> {
        if max_attempts == 0 {
            return Err(McpError::invalid_params(
                "Connection retry policy requires at least one attempt",
            ));
        }
        if max_attempts > MAX_CONNECTION_ATTEMPTS {
            return Err(McpError::invalid_params(format!(
                "Connection retry attempts must not exceed {MAX_CONNECTION_ATTEMPTS}",
            )));
        }
        if retry_delay > MAX_CONNECTION_RETRY_DELAY {
            return Err(McpError::invalid_params(format!(
                "Connection retry delay must not exceed {} seconds",
                MAX_CONNECTION_RETRY_DELAY.as_secs(),
            )));
        }
        if total_elapsed.is_zero() || total_elapsed > MAX_CONNECTION_RETRY_ELAPSED {
            return Err(McpError::invalid_params(format!(
                "Connection retry elapsed limit must be between 1ns and {} seconds",
                MAX_CONNECTION_RETRY_ELAPSED.as_secs(),
            )));
        }

        let retry_count = max_attempts.checked_sub(1).ok_or_else(|| {
            McpError::invalid_params("Connection retry attempt count underflowed")
        })?;
        let scheduled_delay = retry_delay.checked_mul(retry_count).ok_or_else(|| {
            McpError::invalid_params("Connection retry delays overflow the duration range")
        })?;
        if scheduled_delay > total_elapsed {
            return Err(McpError::invalid_params(
                "Connection retry delays exceed the total elapsed limit",
            ));
        }

        Ok(Self {
            max_attempts,
            retry_delay,
            total_elapsed,
        })
    }

    fn from_legacy(max_retries: u32, retry_delay_ms: u64) -> McpResult<Self> {
        let max_attempts = max_retries.checked_add(1).ok_or_else(|| {
            McpError::invalid_params("Connection retry count exceeds the attempt range")
        })?;
        Self::new(
            max_attempts,
            Duration::from_millis(retry_delay_ms),
            DEFAULT_CONNECTION_RETRY_ELAPSED,
        )
    }
}

/// Builder for configuring an MCP client.
///
/// Use this to configure timeout, retry, and spawn options before
/// connecting to an MCP server.
#[derive(Clone)]
pub struct ClientBuilder {
    /// Client identification info.
    client_info: ClientInfo,
    /// Modern-only Implementation extras. Exact-2024 initialize stays name/version.
    client_title: Option<String>,
    client_description: Option<String>,
    client_website_url: Option<String>,
    client_icons: Vec<fastmcp_protocol::common_types::RawIcon>,
    /// Validated ordinary-request idle/absolute timeout policy.
    timeout_policy: RequestTimeoutPolicy,
    /// Maximum number of connection retries.
    max_retries: u32,
    /// Delay between retries in milliseconds.
    retry_delay_ms: u64,
    /// Explicit validated retry policy, if one supersedes legacy retry settings.
    retry_policy: Option<ConnectionRetryPolicy>,
    /// Working directory for subprocess.
    working_dir: Option<PathBuf>,
    /// Environment variables to set for subprocess.
    env_vars: HashMap<String, String>,
    /// Whether to inherit parent's environment.
    inherit_env: bool,
    /// Client capabilities to advertise.
    capabilities: ClientCapabilities,
    /// Exact-2024 server-to-client callbacks installed before initialization.
    reverse_request_handlers: ReverseRequestHandlers,
    /// Shared inbound request slot for as_proxy reverse sampling/roots.
    inbound_legacy_reverse: Arc<Mutex<Option<McpContext>>>,
    /// Optional official MCP Apps client settings for final discovery.
    mcp_apps_settings: Option<McpAppsClientSettings>,
    /// Frozen generic final extension descriptors, local settings, and resolver.
    client_extension_runtime: Option<Arc<ClientExtensionRuntime>>,
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
            .field("retry_policy", &self.retry_policy)
            .field("working_dir_set", &self.working_dir.is_some())
            .field("env_var_count", &self.env_vars.len())
            .field("inherit_env", &self.inherit_env)
            .field("sampling_capability", &self.capabilities.sampling.is_some())
            .field(
                "elicitation_capability",
                &self.capabilities.elicitation.is_some(),
            )
            .field("roots_capability", &self.capabilities.roots.is_some())
            .field(
                "reverse_request_handlers_configured",
                &!self.reverse_request_handlers.is_empty(),
            )
            .field("mcp_apps_configured", &self.mcp_apps_settings.is_some())
            .field(
                "client_extension_registry_configured",
                &self.client_extension_runtime.is_some(),
            )
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
    /// - Protocol policy: Auto when exact-2024 support is compiled, otherwise ModernOnly
    #[must_use]
    pub fn new() -> Self {
        Self {
            client_info: ClientInfo {
                name: "fastmcp-client".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            client_title: None,
            client_description: None,
            client_website_url: None,
            client_icons: Vec::new(),
            timeout_policy: RequestTimeoutPolicy::default(),
            max_retries: 0,
            retry_delay_ms: 1_000,
            retry_policy: None,
            working_dir: None,
            env_vars: HashMap::new(),
            inherit_env: true,
            capabilities: ClientCapabilities::default(),
            reverse_request_handlers: ReverseRequestHandlers::new(),
            inbound_legacy_reverse: Arc::new(Mutex::new(None)),
            mcp_apps_settings: None,
            client_extension_runtime: None,
            auto_initialize: false,
            owned_process_group: false,
            protocol_plan: ClientProtocolPlan::stdio(DEFAULT_PROTOCOL_POLICY),
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

    /// Sets the modern discovery/request title. Exact-2024 initialize stays name/version.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.client_title = Some(title.into());
        self
    }

    /// Sets the modern discovery/request description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.client_description = Some(description.into());
        self
    }

    /// Sets the modern discovery/request website URL.
    #[must_use]
    pub fn website_url(mut self, website_url: impl Into<String>) -> Self {
        self.client_website_url = Some(website_url.into());
        self
    }

    /// Sets the modern discovery/request icon set.
    #[must_use]
    pub fn icons(mut self, icons: Vec<fastmcp_protocol::common_types::RawIcon>) -> Self {
        self.client_icons = icons;
        self
    }

    fn modern_client_implementation(&self) -> fastmcp_protocol::common_types::Implementation {
        let mut implementation = self.client_info.to_implementation();
        implementation.title = self.client_title.clone();
        implementation.description = self.client_description.clone();
        if let Some(website_url) = self.client_website_url.as_deref()
            && let Ok(uri) = fastmcp_protocol::common_types::AbsoluteUri::parse(website_url)
        {
            implementation.website_url = Some(uri);
        }
        implementation.icons = self.client_icons.clone();
        implementation
    }

    fn client_implementation_for_session(
        &self,
    ) -> Option<fastmcp_protocol::common_types::Implementation> {
        let implementation = self.modern_client_implementation();
        if implementation.title.is_some()
            || implementation.description.is_some()
            || implementation.website_url.is_some()
            || !implementation.icons.is_empty()
        {
            Some(implementation)
        } else {
            None
        }
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
        self.retry_policy = None;
        self
    }

    /// Sets the delay between connection retries in milliseconds.
    ///
    /// Default is 1,000ms (1 second).
    #[must_use]
    pub fn retry_delay_ms(mut self, delay: u64) -> Self {
        self.retry_delay_ms = delay;
        self.retry_policy = None;
        self
    }

    /// Sets a validated bounded policy for connection retries.
    ///
    /// `max_attempts` includes the initial attempt, so one attempt preserves
    /// the default zero-retry behavior. The policy rejects values above the
    /// connection safety caps and delay schedules that exceed `total_elapsed`.
    pub fn connection_retry_policy(
        mut self,
        max_attempts: u32,
        retry_delay: Duration,
        total_elapsed: Duration,
    ) -> McpResult<Self> {
        self.retry_policy = Some(ConnectionRetryPolicy::new(
            max_attempts,
            retry_delay,
            total_elapsed,
        )?);
        Ok(self)
    }

    fn effective_connection_retry_policy(&self) -> McpResult<ConnectionRetryPolicy> {
        match self.retry_policy {
            Some(policy) => Ok(policy),
            None => ConnectionRetryPolicy::from_legacy(self.max_retries, self.retry_delay_ms),
        }
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

    /// Configures exact MCP 2024-11-05 server-to-client request handlers.
    ///
    /// The builder derives the matching legacy `sampling` and `roots`
    /// capabilities only if negotiation selects the exact legacy initialize
    /// handshake. Auto discovery remains a modern request without these
    /// legacy-only capability claims; a legacy fallback advertises them.
    #[must_use]
    pub fn reverse_request_handlers(mut self, handlers: ReverseRequestHandlers) -> Self {
        self.reverse_request_handlers = handlers;
        self
    }

    /// Advertises exact-2024 sampling+roots and forwards reverse RPCs onto the
    /// inbound request context bound by as_proxy.
    ///
    /// Handlers are installed before initialize so advertised capabilities
    /// match the callable surface. `ProxyClient` binds the inbound ctx for
    /// the duration of each forwarded tools/call.
    #[must_use]
    pub fn forward_inbound_legacy_reverse(mut self) -> Self {
        let inbound = Arc::clone(&self.inbound_legacy_reverse);
        self.capabilities.sampling = Some(fastmcp_protocol::SamplingCapability::default());
        self.capabilities.roots = Some(RootsCapability {
            list_changed: false,
        });
        self.reverse_request_handlers = ReverseRequestHandlers::new()
            .with_sampling_create_message({
                let inbound = Arc::clone(&inbound);
                move |_cx, _cancel, params| {
                    let inbound = Arc::clone(&inbound);
                    Box::pin(async move {
                        let inbound = inbound
                            .lock()
                            .map_err(|_| {
                                McpError::internal_error("Stdio inbound reverse lock poisoned")
                            })?
                            .clone()
                            .ok_or_else(|| {
                                McpError::invalid_request(
                                    "Stdio proxy legacy sampling callback is unavailable",
                                )
                            })?;
                        if !inbound.can_sample() {
                            return Err(McpError::invalid_request(
                                "Sampling not available: client does not support sampling capability",
                            ));
                        }
                        let response = inbound
                            .sample_with_request(stdio_sampling_request_from_params(params)?)
                            .await?;
                        Ok(CreateMessageResult::text(response.text, response.model))
                    })
                }
            })
            .with_roots_list({
                let inbound = Arc::clone(&inbound);
                move |_cx, _cancel, _params| {
                    let inbound = Arc::clone(&inbound);
                    Box::pin(async move {
                        let inbound = inbound
                            .lock()
                            .map_err(|_| {
                                McpError::internal_error("Stdio inbound reverse lock poisoned")
                            })?
                            .clone()
                            .ok_or_else(|| {
                                McpError::invalid_request(
                                    "Stdio proxy legacy roots callback is unavailable",
                                )
                            })?;
                        let roots = inbound.list_roots().await?;
                        Ok(ListRootsResult::new(
                            roots
                                .into_iter()
                                .map(|root| match root.name {
                                    Some(name) => Root::with_name(root.uri, name),
                                    None => Root::new(root.uri),
                                })
                                .collect(),
                        ))
                    })
                }
            });
        self
    }

    /// Configures the official MCP Apps MIME types advertised during final discovery.
    ///
    /// Apps can activate only on a final MCP connection when the server also
    /// advertises its exact empty Apps marker. Exact legacy routes neither
    /// advertise nor activate these settings.
    #[cfg(feature = "apps")]
    #[must_use]
    pub fn mcp_apps(mut self, settings: McpAppsClientSettings) -> Self {
        self.mcp_apps_settings = Some(settings);
        self
    }

    /// Installs a final-only client extension registry and its local discovery settings.
    ///
    /// The builder validates every local settings owner and freezes the
    /// descriptor registry before any connection exists. The resolver factory
    /// is invoked once for every discovery connection or retry, and must
    /// return an independent resolver instance rather than a shared mutable
    /// handle. A resolver itself is intentionally not accepted: `Clone` does
    /// not prove that `Arc<Mutex<_>>`-backed state is isolated. A successful modern
    /// `server/discover` then produces one retained bilateral extension set;
    /// [`Client::request_final_extension`](crate::Client::request_final_extension)
    /// and its HTTP counterpart admit only client-to-server methods from that
    /// set. Exact MCP 2024-11-05 never negotiates or exposes this surface.
    pub fn extension_registry<F, R>(
        mut self,
        descriptors: ExtensionDescriptorRegistry,
        client_discovery: ClientExtensionDiscovery,
        resolver_factory: F,
    ) -> McpResult<Self>
    where
        F: Fn() -> R + Send + Sync + 'static,
        R: ExtensionSettingsCompatibilityResolver + Send + 'static,
    {
        if self.client_extension_runtime.is_some() {
            return Err(McpError::invalid_params(
                "Client extension registry is already configured",
            ));
        }
        self.client_extension_runtime = Some(Arc::new(ClientExtensionRuntime::new(
            descriptors,
            client_discovery,
            resolver_factory,
        )?));
        Ok(self)
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
    /// # use fastmcp_rust::{ClientBuilder, Cx, McpResult};
    /// # async fn connect(cx: &Cx) -> McpResult<()> {
    /// let mut client = ClientBuilder::new()
    ///     .auto_initialize(true)
    ///     .connect_stdio_with_cx("uvx", &["my-server"], cx)
    ///     .await?;
    ///
    /// // Subprocess is running but not yet initialized
    /// // Initialization happens on first use:
    /// let tools = client.list_tools()?; // Initializes here
    /// # let _ = tools;
    /// # Ok(())
    /// # }
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
        self.validate_feature_configuration().map_err(|_| {
            ClientHttpNegotiationError::FeatureConfigurationUnavailable {
                policy: self.protocol_plan.policy(),
            }
        })?;
        ClientHttpNegotiation::from_protocol_plan(&self.protocol_plan)
    }

    /// Connects the configured HTTP plan with an explicit cancellation context.
    ///
    /// The connection consumes at most one disposable modern probe before
    /// `Auto` may open its exact legacy SSE fallback. It never leaves protocol
    /// classification to the caller.
    ///
    /// HTTP connection is deliberately available only through this
    /// caller-owned context. In particular, the client library never creates
    /// or re-enters a runtime to make this asynchronous boundary look
    /// synchronous.
    ///
    /// ```compile_fail
    /// use fastmcp_client::ClientBuilder;
    ///
    /// // Omitting the caller-owned context is not a supported HTTP API.
    /// let _ = ClientBuilder::new().connect_http();
    /// ```
    pub async fn connect_http_with_cx(
        self,
        cx: &Cx,
    ) -> Result<ClientHttpConnection, ClientHttpConnectionError> {
        let builder = self.selected_legacy_builder_with_reverse_handlers();
        builder
            .validate_feature_configuration()
            .map_err(|_| builder.http_feature_configuration_admission_error())?;
        builder
            .validate_reverse_callback_configuration(&builder.protocol_plan)
            .map_err(|_| Self::http_policy_admission_error())?;
        let reverse_request_handlers = builder.reverse_request_handlers.clone();
        let mut client_capabilities = builder.capabilities.clone();
        if reverse_request_handlers.has_modern_handlers() {
            reverse_request_handlers.derive_modern_capabilities(&mut client_capabilities);
        }
        let legacy_capabilities =
            legacy_capabilities_for_handlers(&client_capabilities, &reverse_request_handlers);
        let client_implementation = builder.client_implementation_for_session();
        let mut connection = ClientHttpConnection::connect_with_extensions(
            cx,
            builder.protocol_plan,
            builder.client_info.clone(),
            client_capabilities,
            builder.mcp_apps_settings,
            builder.client_extension_runtime,
        )
        .await?;
        if let Some(implementation) = client_implementation {
            connection.set_client_implementation(implementation);
        }
        match connection.selected_protocol_era() {
            fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026
                if reverse_request_handlers.has_modern_handlers() =>
            {
                connection
                    .set_modern_reverse_request_handlers(reverse_request_handlers)
                    .map_err(|_| Self::http_policy_admission_error())?;
                let _ = legacy_capabilities;
            }
            #[cfg(feature = "legacy-2024-11-05")]
            fastmcp_protocol::protocol_policy::ProtocolEra::Legacy2024 => {
                // This must run even for an empty handler set. A caller may not
                // advertise exact-2024 sampling or roots authority without the
                // matching callable handler merely because Auto selected legacy
                // after its disposable modern probe.
                reverse_request_handlers
                    .validate_legacy_capabilities(&legacy_capabilities)
                    .map_err(|_| Self::http_policy_admission_error())?;
                connection.set_legacy_client_capabilities(legacy_capabilities);
                connection
                    .set_legacy_reverse_request_handlers(reverse_request_handlers)
                    .map_err(|_| Self::http_policy_admission_error())?;
            }
            _ => {
                let _ = (reverse_request_handlers, legacy_capabilities);
            }
        }

        if cx.checkpoint().is_err() {
            #[cfg(feature = "legacy-2024-11-05")]
            if connection.selected_protocol_era()
                == fastmcp_protocol::protocol_policy::ProtocolEra::Legacy2024
            {
                return Err(ClientHttpConnectionError::Legacy(
                    crate::LegacySseHttpClientError::Cancelled,
                ));
            }
            return Err(ClientHttpConnectionError::Modern(
                ModernHttpClientError::Executor(ModernHttpExecutorError::Cancelled),
            ));
        }

        Ok(connection)
    }

    /// Connects a ready high-level HTTP client with an explicit cancellation context.
    ///
    /// Modern clients are ready after `server/discover`; exact legacy clients
    /// are ready only after `initialize` and `notifications/initialized` have
    /// both completed on the admitted legacy routes.
    pub async fn connect_http_client_with_cx(self, cx: &Cx) -> Result<HttpClient, HttpClientError> {
        let builder = self.selected_legacy_builder_with_reverse_handlers();
        builder
            .validate_feature_configuration()
            .map_err(HttpClientError::CoreResult)?;
        builder
            .validate_reverse_callback_configuration(&builder.protocol_plan)
            .map_err(HttpClientError::CoreResult)?;
        let reverse_request_handlers = builder.reverse_request_handlers.clone();
        let mut client_capabilities = builder.capabilities.clone();
        if reverse_request_handlers.has_modern_handlers() {
            reverse_request_handlers.derive_modern_capabilities(&mut client_capabilities);
        }
        let client_implementation = builder.client_implementation_for_session();
        let mut client = HttpClient::connect_with_extensions(
            cx,
            builder.protocol_plan,
            builder.client_info,
            client_capabilities,
            builder.mcp_apps_settings,
            builder.client_extension_runtime,
            reverse_request_handlers,
        )
        .await?;
        if let Some(implementation) = client_implementation {
            client.set_client_implementation(implementation);
        }
        if cx.checkpoint().is_err() {
            return Err(HttpClientError::CoreResult(McpError::request_cancelled()));
        }
        Ok(client)
    }

    /// Connects to a server via a stdio subprocess under the caller's context.
    ///
    /// The caller-owned context is mandatory; the client library never creates
    /// or re-enters a runtime merely to make stdio construction look
    /// context-free.
    ///
    /// ```compile_fail
    /// use fastmcp_client::ClientBuilder;
    ///
    /// let _client = ClientBuilder::new().connect_stdio("server", &[]);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the timeout or retry policy is invalid, the caller
    /// is cancelled, the subprocess fails to spawn, initialization fails, or
    /// all bounded retry attempts are exhausted.
    pub async fn connect_stdio_with_cx(
        self,
        command: &str,
        args: &[&str],
        cx: &Cx,
    ) -> McpResult<Client> {
        // Reject unusable configuration once, before cancellation checks,
        // retries, command resolution, or subprocess creation. In particular,
        // auto-initialize must never return a live client that cannot issue its
        // first protocol request.
        let (retry_policy, retry_deadline) = self.validated_connection_retry_plan()?;
        let mut last_error = None;

        for attempt in 0..retry_policy.max_attempts {
            // Honor cancellation/budget before each attempt.
            if cx.checkpoint().is_err() {
                return Err(McpError::request_cancelled());
            }
            if Instant::now() >= retry_deadline {
                return Err(Self::connection_retry_elapsed_error());
            }

            if attempt > 0 {
                Self::wait_for_connection_retry(cx, retry_policy.retry_delay, retry_deadline)
                    .await?;
            }

            match self.try_connect(command, args, cx, retry_deadline) {
                Ok(mut client) => {
                    if cx.checkpoint().is_err() {
                        let cleanup = client.close();
                        return combine_operation_with_cleanup(
                            Err(McpError::request_cancelled()),
                            || cleanup,
                        );
                    }
                    if Instant::now() >= retry_deadline {
                        let cleanup = client.close();
                        return combine_operation_with_cleanup(
                            Err(Self::connection_retry_elapsed_error()),
                            || cleanup,
                        );
                    }
                    return Ok(client);
                }
                Err(error) if is_cleanup_unverified(&error) => return Err(error),
                Err(e) => {
                    last_error = Some(e);
                    if Instant::now() >= retry_deadline {
                        return Err(Self::connection_retry_elapsed_error());
                    }
                }
            }
        }

        // All attempts failed
        Err(last_error.unwrap_or_else(|| McpError::internal_error("Connection failed")))
    }

    /// Performs the one bounded stdio attempt used by fixed-plan constructors.
    ///
    /// This deliberately does not implement retry waiting. Public configurable
    /// retry users go through [`Self::connect_stdio_with_cx`] so every delay is
    /// awaited under the caller's capability context.
    pub(crate) fn connect_stdio_once_with_cx(
        self,
        command: &str,
        args: &[&str],
        cx: &Cx,
    ) -> McpResult<Client> {
        let (_retry_policy, retry_deadline) = self.validated_connection_retry_plan()?;
        if cx.checkpoint().is_err() {
            return Err(McpError::request_cancelled());
        }
        if Instant::now() >= retry_deadline {
            return Err(Self::connection_retry_elapsed_error());
        }

        match self.try_connect(command, args, cx, retry_deadline) {
            Ok(mut client) => {
                if cx.checkpoint().is_err() {
                    let cleanup = client.close();
                    return combine_operation_with_cleanup(
                        Err(McpError::request_cancelled()),
                        || cleanup,
                    );
                }
                if Instant::now() >= retry_deadline {
                    let cleanup = client.close();
                    return combine_operation_with_cleanup(
                        Err(Self::connection_retry_elapsed_error()),
                        || cleanup,
                    );
                }
                Ok(client)
            }
            Err(error) if is_cleanup_unverified(&error) => Err(error),
            Err(_error) if Instant::now() >= retry_deadline => {
                Err(Self::connection_retry_elapsed_error())
            }
            Err(error) => Err(error),
        }
    }

    /// Negotiates one native caller-context async WebSocket connection.
    ///
    /// The caller establishes the real `ws://` or `wss://` transport with
    /// [`AsyncWsClientTransport`] and passes its owned value here. This method
    /// never blocks, creates a runtime, or accepts synthetic transport halves.
    #[cfg(feature = "websocket-experimental")]
    pub async fn connect_websocket_with_cx<IO>(
        self,
        cx: &Cx,
        transport: AsyncWsClientTransport<IO>,
    ) -> McpResult<WebSocketClient<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.validate_feature_configuration()?;
        self.validate_websocket_configuration()?;
        let client_implementation = self.client_implementation_for_session();
        WebSocketClient::connect_with_builder_configuration_with_cx(
            cx,
            self.protocol_plan,
            self.client_info,
            client_implementation,
            self.capabilities,
            self.reverse_request_handlers,
            self.mcp_apps_settings,
            self.client_extension_runtime,
            transport,
        )
        .await
    }

    /// Negotiates Auto with a caller-owned factory that creates a fresh
    /// upgraded transport for the sole permitted exact-legacy retry.
    #[cfg(feature = "websocket-experimental")]
    pub async fn connect_websocket_auto_with_cx<IO, F, Fut>(
        self,
        cx: &Cx,
        fresh_transport: F,
    ) -> McpResult<WebSocketClient<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnMut(&Cx) -> Fut,
        Fut: Future<Output = McpResult<AsyncWsClientTransport<IO>>>,
    {
        self.validate_feature_configuration()?;
        self.validate_websocket_configuration()?;
        if !matches!(self.protocol_plan.policy(), ProtocolPolicy::Auto) {
            return Err(McpError::invalid_params(
                "connect_websocket_auto_with_cx requires the Auto protocol policy",
            ));
        }
        WebSocketClient::connect_auto_with_builder_configuration_with_cx(
            cx,
            self.client_info,
            self.capabilities,
            self.reverse_request_handlers,
            self.mcp_apps_settings,
            self.client_extension_runtime,
            fresh_transport,
        )
        .await
    }

    #[cfg(feature = "websocket-experimental")]
    fn validate_websocket_configuration(&self) -> McpResult<()> {
        if matches!(self.protocol_plan.policy(), ProtocolPolicy::ModernOnly)
            && !self.reverse_request_handlers.is_empty()
        {
            return Err(McpError::invalid_params(
                "MCP 2026-07-28 does not support exact-2024 reverse request handlers",
            ));
        }
        Ok(())
    }

    fn connection_retry_elapsed_error() -> McpError {
        McpError::internal_error("Connection retry elapsed limit exceeded")
    }

    fn validated_connection_retry_plan(&self) -> McpResult<(ConnectionRetryPolicy, Instant)> {
        self.validate_feature_configuration()?;
        self.timeout_policy.validate()?;
        let retry_policy = self.effective_connection_retry_policy()?;
        let retry_deadline = Instant::now()
            .checked_add(retry_policy.total_elapsed)
            .ok_or_else(|| {
                McpError::invalid_params(
                    "Connection retry elapsed limit exceeds the monotonic clock range",
                )
            })?;
        Ok((retry_policy, retry_deadline))
    }

    async fn wait_for_connection_retry(
        cx: &Cx,
        retry_delay: Duration,
        retry_deadline: Instant,
    ) -> McpResult<()> {
        if cx.checkpoint().is_err() {
            return Err(McpError::request_cancelled());
        }

        let delay_deadline = Instant::now().checked_add(retry_delay).ok_or_else(|| {
            McpError::invalid_params("Connection retry delay exceeds the monotonic clock range")
        })?;
        loop {
            if cx.checkpoint().is_err() {
                return Err(McpError::request_cancelled());
            }

            let now = Instant::now();
            if now >= retry_deadline {
                return Err(Self::connection_retry_elapsed_error());
            }
            if now >= delay_deadline {
                return Ok(());
            }

            let mut sleep_for = delay_deadline
                .saturating_duration_since(now)
                .min(retry_deadline.saturating_duration_since(now))
                .min(CONNECTION_RETRY_CANCEL_SLICE);
            if let Some(remaining_budget) = cx.budget().remaining_time(cx.now()) {
                sleep_for = sleep_for.min(remaining_budget);
            }
            if sleep_for.is_zero() {
                if cx.checkpoint().is_err() {
                    return Err(McpError::request_cancelled());
                }
                return Err(Self::connection_retry_elapsed_error());
            }

            // This caller-owned timer is deliberately sliced so cancellation
            // and deadline checkpoints remain observable during a retry wait.
            asupersync::time::sleep(cx.now(), sleep_for).await;
        }
    }

    /// Attempts a single connection.
    fn try_connect(
        &self,
        command: &str,
        args: &[&str],
        cx: &Cx,
        retry_deadline: Instant,
    ) -> McpResult<Client> {
        match self.protocol_plan.policy() {
            ProtocolPolicy::ModernOnly => match self.try_connect_with_protocol_plan(
                command,
                args,
                cx,
                self.protocol_plan.clone(),
                self.auto_initialize,
                false,
                retry_deadline,
            )? {
                StdioConnectionAttempt::Connected(client) => Ok(*client),
                StdioConnectionAttempt::Fallback(_) => {
                    unreachable!("only an Auto modern probe can return a fallback signal")
                }
            },
            ProtocolPolicy::LegacyOnly => {
                let legacy_builder = self.legacy_builder_with_reverse_handlers();
                match legacy_builder.try_connect_with_protocol_plan(
                    command,
                    args,
                    cx,
                    self.protocol_plan.clone(),
                    self.auto_initialize,
                    false,
                    retry_deadline,
                )? {
                    StdioConnectionAttempt::Connected(client) => Ok(*client),
                    StdioConnectionAttempt::Fallback(_) => {
                        unreachable!("only an Auto modern probe can return a fallback signal")
                    }
                }
            }
            ProtocolPolicy::Auto => self.try_connect_auto(command, args, cx, retry_deadline),
        }
    }

    /// Returns the builder state for an already-selected exact-2024 connection.
    ///
    /// Reverse request handlers are an exact-2024 surface. Their derived
    /// capabilities and handlers must therefore stay out of the disposable
    /// final discovery probe and enter only after Auto has authorized its
    /// fresh legacy connection.
    fn legacy_builder_with_reverse_handlers(&self) -> Self {
        let mut builder = self.clone();
        builder.capabilities = legacy_capabilities_for_handlers(
            &builder.capabilities,
            &builder.reverse_request_handlers,
        );
        builder
    }

    /// Applies callback-derived capabilities only when the immutable plan has
    /// already selected exact MCP 2024-11-05.
    ///
    /// This is intentionally distinct from Auto: a modern discovery probe
    /// must remain free of legacy reverse-request capability claims.
    fn selected_legacy_builder_with_reverse_handlers(&self) -> Self {
        match self.protocol_plan.policy() {
            ProtocolPolicy::LegacyOnly => self.legacy_builder_with_reverse_handlers(),
            ProtocolPolicy::ModernOnly | ProtocolPolicy::Auto => self.clone(),
        }
    }

    /// Selects an era with a disposable modern child before exposing a client.
    ///
    /// A stdio peer has one opening-frame classification, so the modern probe
    /// can never be reused for exact legacy initialization. Only a correlated
    /// JSON-RPC discovery refusal or Unix-observable clean first-probe timeout
    /// authorizes a second spawn.
    fn try_connect_auto(
        &self,
        command: &str,
        args: &[&str],
        cx: &Cx,
        retry_deadline: Instant,
    ) -> McpResult<Client> {
        let modern_plan = ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly);
        // Exact-2024 reverse handlers neither advertise nor execute during a
        // modern probe. Keep that disposable child handler-free so Auto stays
        // modern-first regardless of local legacy callback configuration.
        let mut modern_builder = self.clone();
        modern_builder.reverse_request_handlers = ReverseRequestHandlers::new();
        match modern_builder.try_connect_with_protocol_plan(
            command,
            args,
            cx,
            modern_plan,
            false,
            true,
            retry_deadline,
        ) {
            Ok(StdioConnectionAttempt::Connected(client)) => {
                let mut client = *client;
                client.set_protocol_plan_after_selection(self.protocol_plan.clone());
                Ok(client)
            }
            Ok(StdioConnectionAttempt::Fallback(_signal)) => {
                // The disposable modern child has been cleaned up before its
                // structured signal reaches this branch. Observe cancellation
                // again before creating a fresh legacy child.
                crate::admit_auto_legacy_fallback(cx)?;
                if Instant::now() >= retry_deadline {
                    return Err(Self::connection_retry_elapsed_error());
                }
                let legacy_plan = ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly);
                let legacy_builder = self.legacy_builder_with_reverse_handlers();
                let mut client = match legacy_builder.try_connect_with_protocol_plan(
                    command,
                    args,
                    cx,
                    legacy_plan,
                    false,
                    false,
                    retry_deadline,
                )? {
                    StdioConnectionAttempt::Connected(client) => *client,
                    StdioConnectionAttempt::Fallback(_) => {
                        unreachable!("an exact-2024 connection cannot emit an Auto fallback signal")
                    }
                };
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
        auto_modern_probe: bool,
        retry_deadline: Instant,
    ) -> McpResult<StdioConnectionAttempt> {
        self.validate_feature_configuration()?;
        self.validate_reverse_callback_configuration(&protocol_plan)?;

        // Keep command resolution and optional process-group setup on the
        // admitted side of the caller's cancellation and retry bounds.
        if cx.checkpoint().is_err() {
            return Err(McpError::request_cancelled());
        }
        if Instant::now() >= retry_deadline {
            return Err(Self::connection_retry_elapsed_error());
        }

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
        // Command setup, including an optional Unix process-group anchor, may
        // consume the caller's cancellation or retry budget. Re-admit the MCP
        // subprocess immediately before creation and report anchor cleanup if
        // the attempt has expired in the meantime.
        let admission_error = if cx.checkpoint().is_err() {
            Some(McpError::request_cancelled())
        } else if Instant::now() >= retry_deadline {
            Some(Self::connection_retry_elapsed_error())
        } else {
            None
        };
        if let Some(error) = admission_error {
            return combine_operation_with_cleanup(Err(error), || {
                group_anchor
                    .as_mut()
                    .map_or(Ok(()), ProcessGroupAnchor::cleanup)
            });
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
        let initialization_policy = if defer_initialization {
            None
        } else {
            match self.initialize_timeout_policy_for_retry_deadline(retry_deadline) {
                Ok(policy) => Some(policy),
                Err(error) => {
                    return combine_operation_with_cleanup(Err(error), || child_guard.cleanup());
                }
            }
        };

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
            Ok(StdioConnectionAttempt::Connected(Box::new(
                self.create_uninitialized_client(
                    child,
                    child_ownership,
                    group_anchor,
                    transport,
                    cx,
                    protocol_plan,
                    self.timeout_policy,
                ),
            )))
        } else {
            let timeout_policy =
                initialization_policy.expect("initialized connection has a retry timeout policy");
            if auto_modern_probe {
                self.initialize_auto_modern_probe_client(
                    child,
                    child_ownership,
                    group_anchor,
                    transport,
                    cx,
                    protocol_plan,
                    timeout_policy,
                    retry_deadline,
                )
            } else {
                self.initialize_client(
                    child,
                    child_ownership,
                    group_anchor,
                    transport,
                    cx,
                    protocol_plan,
                    timeout_policy,
                    retry_deadline,
                )
                .map(|client| StdioConnectionAttempt::Connected(Box::new(client)))
            }
        }
    }

    fn validate_reverse_callback_configuration(
        &self,
        protocol_plan: &ClientProtocolPlan,
    ) -> McpResult<()> {
        match protocol_plan.policy() {
            ProtocolPolicy::LegacyOnly => self
                .reverse_request_handlers
                .validate_legacy_capabilities(&self.capabilities),
            ProtocolPolicy::ModernOnly if !self.reverse_request_handlers.is_empty() => {
                Err(McpError::invalid_params(
                    "MCP 2026-07-28 does not support exact-2024 reverse request handlers",
                ))
            }
            ProtocolPolicy::ModernOnly | ProtocolPolicy::Auto => Ok(()),
        }
    }

    /// Refuses a policy or extension that this crate build did not include,
    /// before it can resolve a command, spawn a process, or contact HTTP.
    fn validate_feature_configuration(&self) -> McpResult<()> {
        validate_protocol_plan_feature(&self.protocol_plan)?;

        #[cfg(not(feature = "apps"))]
        if self.mcp_apps_settings.is_some()
            || self
                .client_extension_runtime
                .as_ref()
                .is_some_and(|runtime| runtime.configures_mcp_apps())
        {
            return Err(McpError::invalid_params(
                "FeatureUnavailable: apps is compiled out; MCP Apps configuration requires --features apps",
            ));
        }

        #[cfg(not(feature = "tasks"))]
        if self
            .client_extension_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.configures_extension("io.modelcontextprotocol/tasks"))
        {
            return Err(McpError::invalid_params(
                "FeatureUnavailable: tasks is compiled out; Tasks configuration requires --features tasks",
            ));
        }

        Ok(())
    }

    fn http_feature_configuration_admission_error(&self) -> ClientHttpConnectionError {
        // The existing public HTTP connection error vocabulary has no
        // feature-configuration admission variant. This is fail-closed: no
        // modern probe is sent and no legacy route is opened.
        ClientHttpConnectionError::Modern(ModernHttpClientError::Negotiation(
            ClientHttpNegotiationError::FeatureConfigurationUnavailable {
                policy: self.protocol_plan.policy(),
            },
        ))
    }

    fn http_policy_admission_error() -> ClientHttpConnectionError {
        // Reverse callback admission has its own validation path. Retain the
        // existing refusal shape here; feature configuration uses the typed
        // `FeatureConfigurationUnavailable` outcome above.
        ClientHttpConnectionError::Modern(ModernHttpClientError::Negotiation(
            ClientHttpNegotiationError::ModernProbeForbiddenForLegacyOnly,
        ))
    }

    fn initialize_timeout_policy_for_retry_deadline(
        &self,
        retry_deadline: Instant,
    ) -> McpResult<RequestTimeoutPolicy> {
        let remaining = retry_deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| *remaining >= Duration::from_millis(1))
            .ok_or_else(Self::connection_retry_elapsed_error)?;
        RequestTimeoutPolicy::new(
            self.timeout_policy.idle_timeout().min(remaining),
            self.timeout_policy.absolute_timeout().min(remaining),
        )
        .map(|policy| {
            policy.reset_idle_on_matching_progress(
                self.timeout_policy.resets_idle_on_matching_progress(),
            )
        })
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
        timeout_policy: RequestTimeoutPolicy,
    ) -> Client {
        // Create a placeholder session - will be updated on first use
        let mut session = ClientSession::new_placeholder(
            self.client_info.clone(),
            self.capabilities.clone(),
            fastmcp_protocol::ServerInfo {
                name: String::new(),
                version: String::new(),
            },
            fastmcp_protocol::ServerCapabilities::default(),
        )
        .with_mcp_apps_settings(self.mcp_apps_settings.clone())
        .with_client_extension_runtime(self.client_extension_runtime.clone())
        .with_protocol_plan(protocol_plan);
        if let Some(implementation) = self.client_implementation_for_session() {
            session = session.with_client_implementation(implementation);
        }

        let mut client = Client::from_parts_uninitialized_with_ownership(
            child,
            child_ownership,
            group_anchor,
            transport,
            cx.clone(),
            session,
            timeout_policy,
        );
        client.install_reverse_request_handlers_before_initialization(
            self.reverse_request_handlers.clone(),
        );
        client.attach_inbound_legacy_reverse_slot(Arc::clone(&self.inbound_legacy_reverse));
        client
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
        timeout_policy: RequestTimeoutPolicy,
        retry_deadline: Instant,
    ) -> McpResult<Client> {
        let mut client = self.create_uninitialized_client(
            child,
            child_ownership,
            group_anchor,
            transport,
            cx,
            protocol_plan,
            timeout_policy,
        );
        if let Err(error) = client.ensure_initialized() {
            let cleanup = client.close();
            return combine_operation_with_cleanup(Err(error), || cleanup);
        }
        if Instant::now() >= retry_deadline {
            let cleanup = client.close();
            return combine_operation_with_cleanup(
                Err(Self::connection_retry_elapsed_error()),
                || cleanup,
            );
        }
        Ok(client)
    }

    /// Initializes Auto's disposable modern child and closes it before
    /// surfacing its one authorized fallback signal.
    fn initialize_auto_modern_probe_client(
        &self,
        child: Child,
        child_ownership: ChildOwnership,
        group_anchor: Option<ProcessGroupAnchor>,
        transport: StdioTransport<std::process::ChildStdout, std::process::ChildStdin>,
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
        timeout_policy: RequestTimeoutPolicy,
        retry_deadline: Instant,
    ) -> McpResult<StdioConnectionAttempt> {
        let mut client = self.create_uninitialized_client(
            child,
            child_ownership,
            group_anchor,
            transport,
            cx,
            protocol_plan,
            timeout_policy,
        );
        match client.ensure_initialized_for_auto_modern_probe() {
            Ok(Some(signal)) => {
                // A fallback is valid only once its disposable child is gone.
                // A cleanup failure is terminal and cannot be converted into a
                // second subprocess attempt.
                let cleanup = client.close();
                combine_operation_and_cleanup(Ok(StdioConnectionAttempt::Fallback(signal)), cleanup)
            }
            Ok(None) => {
                if Instant::now() >= retry_deadline {
                    let cleanup = client.close();
                    return combine_operation_with_cleanup(
                        Err(Self::connection_retry_elapsed_error()),
                        || cleanup,
                    );
                }
                Ok(StdioConnectionAttempt::Connected(Box::new(client)))
            }
            Err(error) => {
                let cleanup = client.close();
                combine_operation_with_cleanup(Err(error), || cleanup)
            }
        }
    }
}

fn stdio_sampling_request_from_params(params: CreateMessageParams) -> McpResult<SamplingRequest> {
    let max_tokens = params
        .max_tokens
        .as_i32()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            McpError::invalid_params("Stdio inbound sampling maxTokens must fit a u32 token budget")
        })?;
    let messages = params
        .messages
        .into_iter()
        .map(|message| {
            let text = match message.content {
                SamplingContent::Text { text } => text,
                SamplingContent::Image { .. } => {
                    return Err(McpError::invalid_params(
                        "Stdio inbound sampling cannot forward an image sampling message",
                    ));
                }
            };
            Ok(SamplingRequestMessage {
                role: match message.role {
                    fastmcp_protocol::Role::User => SamplingRole::User,
                    fastmcp_protocol::Role::Assistant => SamplingRole::Assistant,
                },
                text,
            })
        })
        .collect::<McpResult<Vec<_>>>()?;
    let mut request = SamplingRequest::new(messages, max_tokens);
    if let Some(system_prompt) = params.system_prompt {
        request = request.with_system_prompt(system_prompt);
    }
    if let Some(temperature) = params.temperature {
        request = request.with_temperature(temperature);
    }
    if !params.stop_sequences.is_empty() {
        request = request.with_stop_sequences(params.stop_sequences);
    }
    Ok(request)
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_core::{McpErrorCode, block_on};

    #[cfg(all(unix, feature = "legacy-2024-11-05"))]
    fn reverse_callback_test_runtime() -> asupersync::runtime::Runtime {
        asupersync::runtime::RuntimeBuilder::multi_thread()
            .worker_threads(2)
            .build()
            .expect("reverse callback test runtime must build")
    }

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

    #[cfg(unix)]
    struct StdioRetryAttemptLog {
        path: PathBuf,
    }

    #[cfg(unix)]
    impl StdioRetryAttemptLog {
        fn new(label: &str) -> Self {
            static NEXT_LOG_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

            let log_id = NEXT_LOG_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "fastmcp-client-stdio-retry-{label}-{}-{log_id}.log",
                std::process::id()
            ));
            std::fs::write(&path, []).expect("retry attempt log must be created empty");
            Self { path }
        }

        fn lines(&self) -> Vec<String> {
            std::fs::read_to_string(&self.path)
                .expect("retry attempt log must remain readable")
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    #[cfg(unix)]
    impl Drop for StdioRetryAttemptLog {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[cfg(unix)]
    struct PublicStdioRetryProbe {
        error: McpError,
        attempt_events: Vec<String>,
        elapsed: Duration,
    }

    #[cfg(unix)]
    fn run_public_stdio_retry_probe(cancel_during_delay: bool) -> PublicStdioRetryProbe {
        const RETRY_DELAY: Duration = Duration::from_secs(2);
        const FIRST_RESPONSE: [&str; 2] = ["spawn", "response"];

        let attempt_log = StdioRetryAttemptLog::new(if cancel_during_delay {
            "cancelled"
        } else {
            "active"
        });
        let attempt_log_arg = attempt_log
            .path
            .to_str()
            .expect("temporary retry attempt path must be valid UTF-8");
        let script = r#"printf '%s\n' spawn >> "$1";
            IFS= read -r request || exit 91;
            case "$request" in *server/discover*) ;; *) exit 92 ;; esac;
            printf '%s\n' '{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"planned retry probe failure"}}';
            printf '%s\n' response >> "$1";
            exit 73"#;
        let cx = Cx::for_request();
        let canceller = cancel_during_delay.then(|| {
            let cancellation_cx = cx.clone();
            let cancellation_log = attempt_log.path.clone();
            std::thread::spawn(move || {
                let observation_deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let events = std::fs::read_to_string(&cancellation_log).unwrap_or_default();
                    if events.lines().eq(FIRST_RESPONSE) {
                        break;
                    }
                    assert!(
                        Instant::now() < observation_deadline,
                        "the first real child must emit its correlated failure before cancellation"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }

                // The child has emitted its terminal response. Give the public
                // connection path time to enter its much longer retry delay,
                // then cancel that caller-owned wait.
                std::thread::sleep(Duration::from_millis(50));
                cancellation_cx.set_cancel_requested(true);
            })
        });

        let started = Instant::now();
        let result = block_on(
            ClientBuilder::new()
                .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
                .auto_initialize(false)
                .connection_retry_policy(2, RETRY_DELAY, Duration::from_secs(5))
                .expect("two-attempt public retry policy must be valid")
                .connect_stdio_with_cx(
                    "sh",
                    &["-c", script, "fastmcp-stdio-retry-probe", attempt_log_arg],
                    &cx,
                ),
        );
        let elapsed = started.elapsed();
        if let Some(canceller) = canceller {
            canceller
                .join()
                .expect("retry-delay cancellation helper must complete");
        }
        let error = match result {
            Ok(mut client) => {
                client
                    .close()
                    .expect("unexpected retry probe client must still be cleaned up");
                panic!("both retry probe children return a correlated protocol failure")
            }
            Err(error) => error,
        };

        // A wrongly admitted second child may append shortly after the public
        // future resolves. Wait one cancellation slice before freezing the
        // observable so the negative assertion detects that race as well.
        std::thread::sleep(CONNECTION_RETRY_CANCEL_SLICE);
        PublicStdioRetryProbe {
            error,
            attempt_events: attempt_log.lines(),
            elapsed,
        }
    }

    #[test]
    fn test_builder_defaults() {
        let builder = ClientBuilder::new();
        assert_eq!(builder.client_info.name, "fastmcp-client");
        assert_eq!(builder.timeout_policy, RequestTimeoutPolicy::default());
        assert_eq!(builder.max_retries, 0);
        assert_eq!(builder.retry_delay_ms, 1_000);
        assert!(builder.retry_policy.is_none());
        assert!(builder.inherit_env);
        assert!(builder.working_dir.is_none());
        assert!(builder.env_vars.is_empty());
        assert!(!builder.auto_initialize);
        assert!(!builder.owned_process_group);
    }

    #[test]
    fn reverse_handlers_derive_exact_legacy_capabilities_before_connect() {
        let handlers = ReverseRequestHandlers::new()
            .with_sampling_create_message(|_cx, _cancellation, _params| {
                Box::pin(async {
                    Ok(fastmcp_protocol::CreateMessageResult::text(
                        "ok",
                        "test-model",
                    ))
                })
            })
            .with_roots_list(|_cx, _cancellation, _params| {
                Box::pin(async { Ok(fastmcp_protocol::ListRootsResult::new(Vec::new())) })
            });
        let builder = ClientBuilder::new()
            .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly))
            .reverse_request_handlers(handlers);
        let builder = builder.selected_legacy_builder_with_reverse_handlers();

        assert!(builder.capabilities.sampling.is_some());
        assert_eq!(
            builder
                .capabilities
                .roots
                .as_ref()
                .map(|roots| roots.list_changed),
            Some(false)
        );
        builder
            .validate_reverse_callback_configuration(builder.selected_protocol_plan())
            .expect("derived callbacks and advertised legacy capabilities agree");
    }

    #[test]
    fn reverse_handlers_reject_modern_and_require_legacy_capability_parity() {
        let sampling_handler = || {
            ReverseRequestHandlers::new().with_sampling_create_message(
                |_cx, _cancellation, _params| {
                    Box::pin(async {
                        Ok(fastmcp_protocol::CreateMessageResult::text(
                            "ok",
                            "test-model",
                        ))
                    })
                },
            )
        };
        let modern = ClientBuilder::new().reverse_request_handlers(sampling_handler());
        let modern_error = modern
            .validate_reverse_callback_configuration(&ClientProtocolPlan::stdio(
                ProtocolPolicy::ModernOnly,
            ))
            .expect_err("final negotiation cannot expose exact-2024 callbacks");
        assert_eq!(modern_error.code, fastmcp_core::McpErrorCode::InvalidParams);

        let modern_http_handlers = ReverseRequestHandlers::new()
            .with_modern_sampling_create_message(|_cx, _cancellation, _params| {
                Box::pin(async {
                    Err(fastmcp_core::McpError::internal_error(
                        "modern HTTP reverse handlers must be rejected before contact",
                    ))
                })
            });
        assert!(
            modern_http_handlers.has_modern_handlers(),
            "modern sampling is a modern reverse handler"
        );
        assert!(
            modern_http_handlers.is_empty(),
            "modern handlers must not count as exact-2024 handlers"
        );

        let mut capabilities = ClientCapabilities::default();
        capabilities.roots = Some(fastmcp_protocol::RootsCapability { list_changed: true });
        let legacy = ClientBuilder::new()
            .capabilities(capabilities)
            .reverse_request_handlers(ReverseRequestHandlers::new().with_roots_list(
                |_cx, _cancellation, _params| {
                    Box::pin(async { Ok(fastmcp_protocol::ListRootsResult::new(Vec::new())) })
                },
            ));
        legacy
            .validate_reverse_callback_configuration(&ClientProtocolPlan::stdio(
                ProtocolPolicy::LegacyOnly,
            ))
            .expect("roots/listChanged may accompany its callable roots/list handler");

        let missing_handler = ClientBuilder::new().capabilities(ClientCapabilities {
            roots: Some(fastmcp_protocol::RootsCapability {
                list_changed: false,
            }),
            ..ClientCapabilities::default()
        });
        let legacy_error = missing_handler
            .validate_reverse_callback_configuration(&ClientProtocolPlan::stdio(
                ProtocolPolicy::LegacyOnly,
            ))
            .expect_err("an advertised roots capability requires a roots/list handler");
        assert_eq!(legacy_error.code, fastmcp_core::McpErrorCode::InvalidParams);
    }

    #[test]
    fn http_connect_does_not_refuse_modern_reverse_handlers_before_contact() {
        let handlers = ReverseRequestHandlers::new().with_modern_sampling_create_message(
            |_cx, _cancellation, _params| {
                Box::pin(async {
                    Err(McpError::internal_error(
                        "modern HTTP reverse handler is unused when the peer is unreachable",
                    ))
                })
            },
        );
        let plan = ClientProtocolPlan::http(
            ProtocolPolicy::ModernOnly,
            Some(
                fastmcp_core::CanonicalHttpUrl::parse("http://127.0.0.1:1/mcp")
                    .expect("loopback HTTP URL is canonical"),
            ),
            None,
            None,
            "fastmcp-test-http".to_owned(),
            "fastmcp-test-http".to_owned(),
            "modern-http-reverse-contact".to_owned(),
            0,
            0,
            0,
        )
        .expect("modern-only HTTP plan admits a POST target");
        let builder = ClientBuilder::new()
            .protocol_plan(plan)
            .reverse_request_handlers(handlers);
        let error = block_on(builder.connect_http_with_cx(&Cx::for_testing()))
            .err()
            .expect("an unreachable modern POST target still fails at contact");
        assert!(
            !matches!(
                error,
                ClientHttpConnectionError::Modern(
                    ModernHttpClientError::ReverseRequestDispatch(_)
                        | ModernHttpClientError::ReverseResponsePostRejected { .. }
                )
            ),
            "modern reverse handlers must reach the HTTP probe instead of failing closed: {error}"
        );
        assert!(
            matches!(error, ClientHttpConnectionError::Modern(_)),
            "unreachable modern POST remains a modern transport error: {error}"
        );
    }

    #[cfg(unix)]
    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn builder_advertises_callbacks_before_legacy_initialize_and_dispatches_them() {
        let script = "IFS= read -r initialize || exit 1; \
            capabilities_ok=true; \
            case \"$initialize\" in *'\"method\":\"initialize\"'*) ;; *) capabilities_ok=false;; esac; \
            case \"$initialize\" in *'\"sampling\":{}'*) ;; *) capabilities_ok=false;; esac; \
            case \"$initialize\" in *'\"roots\":{}'*) ;; *) capabilities_ok=false;; esac; \
            case \"$initialize\" in *'\"elicitation\"'*) capabilities_ok=false;; *) ;; esac; \
            printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"callback-builder\",\"version\":\"1.0.0\"}}}'; \
            IFS= read -r lifecycle || exit 1; \
            case \"$lifecycle\" in *notifications/initialized*) lifecycle_ok=true;; *) lifecycle_ok=false;; esac; \
            IFS= read -r request || exit 1; \
            printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":41,\"params\":{\"messages\":[],\"maxTokens\":9}}'; \
            IFS= read -r callback || exit 1; \
            callback_ok=true; \
            case \"$callback\" in *'\"id\":41'*) ;; *) callback_ok=false;; esac; \
            case \"$callback\" in *'\"model\":\"builder-model\"'*) ;; *) callback_ok=false;; esac; \
            case \"$callback\" in *'\"error\"'*) callback_ok=false;; *) ;; esac; \
            case \"$request\" in *'\"id\":2'*) request_ok=true;; *) request_ok=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"capabilities\":%s,\"lifecycle\":%s,\"callback\":%s,\"request\":%s}}\\n' \"$capabilities_ok\" \"$lifecycle_ok\" \"$callback_ok\" \"$request_ok\"; exec sleep 2";
        let handlers = ReverseRequestHandlers::new()
            .with_sampling_create_message(|_cx, _cancellation, _params| {
                Box::pin(async {
                    Ok(fastmcp_protocol::CreateMessageResult::text(
                        "configured before initialize",
                        "builder-model",
                    ))
                })
            })
            .with_roots_list(|_cx, _cancellation, _params| {
                Box::pin(async { Ok(fastmcp_protocol::ListRootsResult::new(Vec::new())) })
            });
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread callback test runtime must build");
        runtime.block_on(async move {
            let cx = Cx::current().expect("callback test runtime installs a current context");
            let mut client = ClientBuilder::new()
                .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly))
                .reverse_request_handlers(handlers)
                .connect_stdio_with_cx("sh", &["-c", script], &cx)
                .await
                .expect("legacy callback configuration completes initialize before exposure");

            let result = client
                .request_with_cx(&cx, "test/builder-callback", Some(serde_json::json!({})))
                .await
                .expect("cooperative ingress lets the configured callback respond");
            assert_eq!(
                result.result.as_ref(),
                Some(&serde_json::json!({
                    "capabilities": true,
                    "lifecycle": true,
                    "callback": true,
                    "request": true
                })),
            );
            assert!(result.error.is_none());
            client.close().expect("builder callback client cleanup");
        });
    }

    #[cfg(unix)]
    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn current_thread_receive_cancellation_preserves_connection_and_callback_state() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct CallbackCancellationProbe {
            dropped: std::sync::Arc<AtomicBool>,
        }

        impl Drop for CallbackCancellationProbe {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::SeqCst);
            }
        }

        let script = "IFS= read -r initialize || exit 1; \
            case \"$initialize\" in *'\"method\":\"initialize\"'*) ;; *) exit 1 ;; esac; \
            printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"callback-cancellation-builder\",\"version\":\"1.0.0\"}}}'; \
            IFS= read -r lifecycle || exit 1; \
            case \"$lifecycle\" in *notifications/initialized*) ;; *) exit 1 ;; esac; \
            IFS= read -r request || exit 1; \
            case \"$request\" in *'\"id\":2'*) ;; *) exit 1 ;; esac; \
            printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":41,\"params\":{\"messages\":[],\"maxTokens\":9}}'; \
            IFS= read -r control || exit 1; \
            control_ok=true; \
            case \"$control\" in *'\"method\":\"notifications/cancelled\"'*'\"requestId\":2'*) ;; *) control_ok=false ;; esac; \
            printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"late\":true}}'; \
            printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":41}}'; \
            IFS= read -r next || exit 1; \
            callback_response=false; follow_up_ok=true; \
            case \"$next\" in \
                *'\"method\":\"test/builder-callback-after-cancellation\"'*'\"id\":3'*) ;; \
                *'\"id\":41'*'\"error\"'*|*'\"id\":41'*'\"result\"'*) callback_response=true; IFS= read -r follow_up || exit 1; case \"$follow_up\" in *'\"method\":\"test/builder-callback-after-cancellation\"'*'\"id\":3'*) ;; *) follow_up_ok=false ;; esac ;; \
                *) callback_response=true; IFS= read -r follow_up || exit 1; case \"$follow_up\" in *'\"method\":\"test/builder-callback-after-cancellation\"'*'\"id\":3'*) ;; *) follow_up_ok=false ;; esac ;; \
            esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"control\":%s,\"callbackResponse\":%s,\"followUp\":%s}}\\n' \"$control_ok\" \"$callback_response\" \"$follow_up_ok\"; \
            exec sleep 2";
        let callback_started = std::sync::Arc::new(AtomicBool::new(false));
        let callback_future_dropped = std::sync::Arc::new(AtomicBool::new(false));
        let callback_cx_observed = std::sync::Arc::new(std::sync::Mutex::new(None::<Cx>));
        let callback_token_observed =
            std::sync::Arc::new(std::sync::Mutex::new(None::<ReverseRequestCancellation>));
        let callback_mutated = std::sync::Arc::new(AtomicBool::new(false));
        let handlers = ReverseRequestHandlers::new().with_sampling_create_message({
            let callback_started = std::sync::Arc::clone(&callback_started);
            let callback_future_dropped = std::sync::Arc::clone(&callback_future_dropped);
            let callback_cx_observed = std::sync::Arc::clone(&callback_cx_observed);
            let callback_token_observed = std::sync::Arc::clone(&callback_token_observed);
            let callback_mutated = std::sync::Arc::clone(&callback_mutated);
            move |callback_cx, cancellation, _params| {
                let callback_started = std::sync::Arc::clone(&callback_started);
                let callback_future_dropped = std::sync::Arc::clone(&callback_future_dropped);
                let callback_cx_observed = std::sync::Arc::clone(&callback_cx_observed);
                let callback_token_observed = std::sync::Arc::clone(&callback_token_observed);
                let callback_mutated = std::sync::Arc::clone(&callback_mutated);
                Box::pin(async move {
                    callback_started.store(true, Ordering::SeqCst);
                    *callback_cx_observed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(callback_cx.clone());
                    *callback_token_observed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(cancellation.clone());
                    let cancellation_probe = CallbackCancellationProbe {
                        dropped: std::sync::Arc::clone(&callback_future_dropped),
                    };
                    let (_park_sender, mut park_receiver) =
                        asupersync::channel::oneshot::channel::<()>();
                    let parked = park_receiver.recv(callback_cx).await;
                    if callback_cx.checkpoint().is_err() && cancellation.checkpoint().is_err() {
                        drop(cancellation_probe);
                        return Err(fastmcp_core::McpError::request_cancelled());
                    }
                    assert!(
                        parked.is_ok(),
                        "a live callback park cannot close before cancellation"
                    );
                    callback_mutated.store(true, Ordering::SeqCst);
                    Ok(fastmcp_protocol::CreateMessageResult::text(
                        "must not be sent after cancellation",
                        "cancelled-callback-model",
                    ))
                })
            }
        });
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread callback cancellation runtime must build");
        runtime.block_on(async move {
            let cx = Cx::current().expect("callback test runtime installs a current context");
            let mut client = ClientBuilder::new()
                .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly))
                .reverse_request_handlers(handlers)
                .connect_stdio_with_cx("sh", &["-c", script], &cx)
                .await
                .expect("legacy callback cancellation configuration initializes");

            let operation_cx = Cx::for_request();
            let cancellation_cx = operation_cx.clone();
            let callback_started_for_canceller = std::sync::Arc::clone(&callback_started);
            let canceller = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(1);
                while !callback_started_for_canceller.load(Ordering::SeqCst)
                    && Instant::now() < deadline
                {
                    std::thread::yield_now();
                }
                assert!(
                    callback_started_for_canceller.load(Ordering::SeqCst),
                    "the reverse callback must start before forced operation cancellation"
                );
                std::thread::sleep(Duration::from_millis(2));
                cancellation_cx.set_cancel_requested(true);
            });

            let cancellation = client
                .request_with_cx(
                    &operation_cx,
                    "test/builder-callback-cancellation",
                    Some(serde_json::json!({})),
                )
                .await
                .expect_err(
                    "operation cancellation must settle its request without closing the connection",
                );
            canceller
                .join()
                .expect("forced operation cancellation thread must complete");
            assert_eq!(cancellation.code, McpErrorCode::RequestCancelled);
            assert!(client.is_initialized());

            let response = client
                .request_with_cx(
                    &cx,
                    "test/builder-callback-after-cancellation",
                    Some(serde_json::json!({})),
                )
                .await
                .expect("a later request drives late traffic and proves the connection reusable");
            assert_eq!(
                response.result.as_ref(),
                Some(&serde_json::json!({
                    "control": true,
                    "callbackResponse": false,
                    "followUp": true
                }))
            );
            assert!(response.error.is_none());

            let callback_settlement_deadline =
                Instant::now() + crate::REVERSE_CALLBACK_SHUTDOWN_TIMEOUT;
            while !callback_future_dropped.load(Ordering::SeqCst)
                && Instant::now() < callback_settlement_deadline
            {
                client
                    .drain_completed_reverse_callbacks()
                    .expect("an expected cancelled callback join is not connection-terminal");
                asupersync::runtime::yield_now().await;
            }
            client
                .drain_completed_reverse_callbacks()
                .expect("an expected cancelled callback join is not connection-terminal");
            assert!(callback_started.load(Ordering::SeqCst));
            assert!(callback_future_dropped.load(Ordering::SeqCst));
            assert!(
                callback_cx_observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref()
                    .is_some_and(Cx::is_cancel_requested),
                "task abort must cancel the callback-owned Cx"
            );
            assert!(
                callback_token_observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref()
                    .is_some_and(ReverseRequestCancellation::is_cancel_requested),
                "peer cancellation must cancel the protocol token"
            );
            assert!(!callback_mutated.load(Ordering::SeqCst));
            assert_eq!(client.responses.pending_len(), 0);
            assert_eq!(client.responses.tombstone_len(), 0);
            assert_eq!(client.responses.uncorrelated_diagnostics(), 0);
            assert!(client.responses.terminal_error().is_none());
            client
                .close()
                .expect("cancelled callback is joined by its owning client");
        });
    }

    #[cfg(unix)]
    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn current_thread_receive_deadline_reaps_panicked_reverse_callback() {
        let script = "IFS= read -r initialize || exit 1; \
            printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"callback-panic-builder\",\"version\":\"1.0.0\"}}}'; \
            IFS= read -r lifecycle || exit 1; \
            IFS= read -r request || exit 1; \
            printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":41,\"params\":{\"messages\":[],\"maxTokens\":9}}'; \
            exec sleep 2";
        let handlers = ReverseRequestHandlers::new().with_sampling_create_message(
            |_callback_cx, _cancellation, _params| {
                Box::pin(async {
                    panic!("reverse callback panic canary");
                })
            },
        );
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread callback panic runtime must build");

        runtime.block_on(async move {
            let cx = Cx::current().expect("callback panic runtime installs a current context");
            let mut client = ClientBuilder::new()
                .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly))
                .reverse_request_handlers(handlers)
                .connect_stdio_with_cx("sh", &["-c", script], &cx)
                .await
                .expect("legacy callback panic configuration initializes");

            let error = client
                .request_with_cx(
                    &cx,
                    "test/builder-callback-panic",
                    Some(serde_json::json!({})),
                )
                .await
                .expect_err("the next bounded ingress turn must reap the callback panic");
            assert_eq!(error.code, McpErrorCode::InternalError);
            assert_eq!(error.message, "Client reverse callback task panicked");
            assert!(!client.is_initialized());
            client
                .close()
                .expect("terminal callback panic still settles subprocess ownership");
        });
    }

    #[cfg(unix)]
    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn auto_with_reverse_handlers_keeps_a_modern_selected_connection_handler_free() {
        let script = r#"IFS= read -r discover || exit 1;
            case "$discover" in
                *server/discover*) ;;
                *) exit 1 ;;
            esac;
            case "$discover" in
                *'"sampling"'*|*'"roots"'*) exit 1 ;;
            esac;
            printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"auto-modern-callbacks","version":"1.0.0"}}}}';
            exec sleep 2"#;
        let handlers = ReverseRequestHandlers::new().with_sampling_create_message(
            |_cx, _cancellation, _params| {
                Box::pin(async {
                    Ok(fastmcp_protocol::CreateMessageResult::text(
                        "must stay out of modern discovery",
                        "auto-modern-model",
                    ))
                })
            },
        );

        let mut client = block_on(
            ClientBuilder::new()
                .reverse_request_handlers(handlers)
                .connect_stdio_with_cx("sh", &["-c", script], &Cx::for_request()),
        )
        .expect("Auto probes the final handshake before considering legacy callbacks");

        assert_eq!(client.protocol_policy(), ProtocolPolicy::Auto);
        assert_eq!(
            client.selected_protocol_era(),
            Some(fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026)
        );
        client.close().expect("Auto-modern client cleanup");
    }

    #[cfg(unix)]
    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn auto_with_reverse_handlers_installs_them_only_after_method_not_found_fallback() {
        let script = r#"IFS= read -r first || exit 1;
            case "$first" in
                *server/discover*)
                    printf '%s\n' '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}';
                    exec sleep 2 ;;
                *initialize*2024-11-05*)
                    capabilities_ok=true;
                    case "$first" in *'"sampling":{}'*) ;; *) capabilities_ok=false ;; esac;
                    case "$first" in *'"roots"'*|*'"elicitation"'*) capabilities_ok=false ;; *) ;; esac;
                    printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"auto-legacy-callbacks","version":"1.0.0"}}}';
                    IFS= read -r lifecycle || exit 1;
                    case "$lifecycle" in *notifications/initialized*) lifecycle_ok=true ;; *) lifecycle_ok=false ;; esac;
                    IFS= read -r request || exit 1;
                    printf '%s\n' '{"jsonrpc":"2.0","method":"sampling/createMessage","id":41,"params":{"messages":[],"maxTokens":9}}';
                    IFS= read -r callback || exit 1;
                    callback_ok=true;
                    case "$callback" in *'"id":41'*) ;; *) callback_ok=false ;; esac;
                    case "$callback" in *'"model":"auto-legacy-model"'*) ;; *) callback_ok=false ;; esac;
                    case "$callback" in *'"error"'*) callback_ok=false ;; *) ;; esac;
                    case "$request" in *'"id":2'*) request_ok=true ;; *) request_ok=false ;; esac;
                    printf '{"jsonrpc":"2.0","id":2,"result":{"capabilities":%s,"lifecycle":%s,"callback":%s,"request":%s}}\n' "$capabilities_ok" "$lifecycle_ok" "$callback_ok" "$request_ok";
                    exec sleep 2 ;;
                *) exit 1 ;;
            esac"#;
        let handlers = ReverseRequestHandlers::new().with_sampling_create_message(
            |_cx, _cancellation, _params| {
                Box::pin(async {
                    Ok(fastmcp_protocol::CreateMessageResult::text(
                        "installed after fallback",
                        "auto-legacy-model",
                    ))
                })
            },
        );

        let runtime = reverse_callback_test_runtime();
        let test = runtime.handle().spawn(async move {
            let cx = Cx::current().expect("callback test runtime installs a current context");
            let mut client = ClientBuilder::new()
                .reverse_request_handlers(handlers)
                .connect_stdio_with_cx("sh", &["-c", script], &cx)
                .await
                .expect("MethodNotFound authorizes a fresh legacy client with its callbacks");

            assert_eq!(client.protocol_policy(), ProtocolPolicy::Auto);
            assert_eq!(
                client.selected_protocol_era(),
                Some(fastmcp_protocol::protocol_policy::ProtocolEra::Legacy2024)
            );
            let result: serde_json::Value = client
                .send_request("test/auto-fallback-callback", serde_json::json!({}))
                .expect("the selected legacy client dispatches its configured callback");
            assert_eq!(
                result,
                serde_json::json!({
                    "capabilities": true,
                    "lifecycle": true,
                    "callback": true,
                    "request": true
                })
            );
            client.close().expect("Auto-legacy client cleanup");
        });
        runtime.block_on(test);
    }

    #[cfg(all(unix, not(feature = "legacy-2024-11-05")))]
    #[test]
    fn feature_off_builder_auto_and_legacy_refuse_before_command_resolution() {
        for policy in [ProtocolPolicy::Auto, ProtocolPolicy::LegacyOnly] {
            let error = block_on(
                ClientBuilder::new()
                    .protocol_plan(ClientProtocolPlan::stdio(policy))
                    .connect_stdio_with_cx(
                        "fastmcp-client-builder-feature-off-must-not-spawn",
                        &[],
                        &Cx::for_testing(),
                    ),
            )
            .err()
            .expect("feature-off builder policy must reject before command resolution");
            assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
            assert!(
                error
                    .message
                    .contains("FeatureUnavailable: legacy-2024-11-05 is compiled out"),
                "{policy:?} must fail at feature admission rather than process startup"
            );
        }

        #[cfg(feature = "apps")]
        for policy in [ProtocolPolicy::Auto, ProtocolPolicy::LegacyOnly] {
            let error = block_on(
                ClientBuilder::new()
                    .mcp_apps(
                        McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
                            .expect("valid Apps MIME settings"),
                    )
                    .protocol_plan(ClientProtocolPlan::stdio(policy))
                    .connect_stdio_with_cx(
                        "fastmcp-client-builder-apps-feature-off-must-not-spawn",
                        &[],
                        &Cx::for_testing(),
                    ),
            )
            .err()
            .expect("Apps with an unavailable legacy policy must reject before startup");
            assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
            assert!(
                error
                    .message
                    .contains("FeatureUnavailable: legacy-2024-11-05 is compiled out"),
                "Apps {policy:?} must fail at feature admission rather than process startup"
            );
        }
    }

    #[cfg(not(feature = "legacy-2024-11-05"))]
    #[test]
    fn feature_off_http_admission_reports_the_unavailable_configuration_before_contact() {
        let builder =
            ClientBuilder::new().protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::Auto));

        assert!(matches!(
            builder.http_negotiation(),
            Err(
                ClientHttpNegotiationError::FeatureConfigurationUnavailable {
                    policy: ProtocolPolicy::Auto,
                }
            )
        ));

        let error = block_on(builder.connect_http_with_cx(&Cx::for_testing()))
            .err()
            .expect("feature admission must reject Auto before HTTP contact");
        assert!(matches!(
            error,
            ClientHttpConnectionError::Modern(ModernHttpClientError::Negotiation(
                ClientHttpNegotiationError::FeatureConfigurationUnavailable {
                    policy: ProtocolPolicy::Auto,
                }
            ))
        ));
    }

    #[cfg(feature = "apps")]
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
        let result = block_on(
            ClientBuilder::new()
                .max_retries(2)
                .retry_delay_ms(100)
                .connect_stdio_with_cx("definitely-not-a-real-command", &[], &cx),
        );

        assert!(
            result.is_err(),
            "cancelled context should abort before retry attempts"
        );
        let err = result.err().expect("error result");
        assert_eq!(err.code, McpErrorCode::RequestCancelled);
    }

    #[cfg(unix)]
    #[test]
    fn public_connect_stdio_with_cx_retries_after_failed_first_child() {
        let probe = run_public_stdio_retry_probe(false);

        assert_ne!(
            probe.error.code,
            McpErrorCode::RequestCancelled,
            "an active caller context must not turn a failed retry sequence into cancellation"
        );
        assert_eq!(
            probe.attempt_events,
            ["spawn", "response", "spawn", "response"],
            "the public connection path must create and observe the second real child"
        );
        assert!(
            probe.elapsed >= Duration::from_secs(2),
            "the second child must remain gated by the configured caller-context retry delay"
        );
    }

    #[cfg(unix)]
    #[test]
    fn public_connect_stdio_with_cx_cancellation_during_retry_delay_creates_no_second_child() {
        let probe = run_public_stdio_retry_probe(true);

        assert_eq!(probe.error.code, McpErrorCode::RequestCancelled);
        assert_eq!(
            probe.attempt_events,
            ["spawn", "response"],
            "cancellation after the failed first child must leave the attempt log unchanged"
        );
        assert!(
            probe.elapsed < Duration::from_secs(2),
            "caller cancellation must settle before the retry delay could admit attempt two"
        );
    }

    #[test]
    fn cancelled_direct_attempt_is_refused_before_command_setup() {
        let cx = Cx::for_request();
        cx.set_cancel_requested(true);
        let retry_deadline = Instant::now()
            .checked_add(Duration::from_secs(1))
            .expect("short retry deadline fits the monotonic clock");

        let error = match ClientBuilder::new().try_connect_with_protocol_plan(
            "fastmcp-client-cancelled-direct-attempt-must-not-spawn",
            &[],
            &cx,
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            false,
            false,
            retry_deadline,
        ) {
            Ok(_) => panic!("a cancelled retry attempt must be rejected before process creation"),
            Err(error) => error,
        };

        assert_eq!(error.code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn connection_retry_policy_accepts_hard_boundaries_and_preserves_zero_retries() {
        let policy = ConnectionRetryPolicy::new(
            MAX_CONNECTION_ATTEMPTS,
            Duration::ZERO,
            MAX_CONNECTION_RETRY_ELAPSED,
        )
        .expect("hard retry policy boundaries are valid");
        assert_eq!(policy.max_attempts, MAX_CONNECTION_ATTEMPTS);
        assert_eq!(policy.retry_delay, Duration::ZERO);
        assert_eq!(policy.total_elapsed, MAX_CONNECTION_RETRY_ELAPSED);

        let maximum_delay_policy =
            ConnectionRetryPolicy::new(2, MAX_CONNECTION_RETRY_DELAY, MAX_CONNECTION_RETRY_ELAPSED)
                .expect("maximum per-retry delay fits the maximum elapsed limit");
        assert_eq!(maximum_delay_policy.retry_delay, MAX_CONNECTION_RETRY_DELAY);
        assert_eq!(
            maximum_delay_policy.total_elapsed,
            MAX_CONNECTION_RETRY_ELAPSED
        );

        let default_policy = ClientBuilder::new()
            .effective_connection_retry_policy()
            .expect("default retry policy is valid");
        assert_eq!(default_policy.max_attempts, 1);
        assert_eq!(default_policy.retry_delay, Duration::from_secs(1));
    }

    #[test]
    fn connection_retry_policy_rejects_one_field_attempt_count_above_hard_cap() {
        let error = ClientBuilder::new()
            .connection_retry_policy(
                MAX_CONNECTION_ATTEMPTS + 1,
                Duration::ZERO,
                MAX_CONNECTION_RETRY_ELAPSED,
            )
            .expect_err("only the attempt count differs from the hard-boundary policy");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
    }

    #[test]
    fn connection_retry_wait_awaits_active_caller_context() {
        let cx = Cx::for_request();
        let retry_deadline = Instant::now()
            .checked_add(Duration::from_secs(1))
            .expect("short retry deadline fits the monotonic clock");

        block_on(ClientBuilder::wait_for_connection_retry(
            &cx,
            Duration::from_millis(1),
            retry_deadline,
        ))
        .expect("an active caller context admits its bounded retry wait");

        assert!(
            cx.checkpoint().is_ok(),
            "awaiting a retry timer must not mutate the caller cancellation state"
        );
    }

    #[test]
    fn connection_retry_wait_rejects_pre_cancelled_context() {
        let cx = Cx::for_request();
        cx.set_cancel_requested(true);
        let retry_deadline = Instant::now()
            .checked_add(Duration::from_secs(1))
            .expect("short retry deadline fits the monotonic clock");

        let error = block_on(ClientBuilder::wait_for_connection_retry(
            &cx,
            Duration::from_millis(1),
            retry_deadline,
        ))
        .expect_err("a cancelled context must not begin a retry wait");
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn connect_stdio_with_cx_rejects_legacy_retry_count_above_hard_limit() {
        let cx = Cx::for_request();
        cx.set_cancel_requested(true);

        let result = block_on(
            ClientBuilder::new()
                .max_retries(u32::MAX)
                .retry_delay_ms(1)
                .connect_stdio_with_cx("definitely-not-a-real-command", &[], &cx),
        );

        assert!(
            result.is_err(),
            "invalid retry configuration should return an error without attempting a connection"
        );
        let err = result.err().expect("error result");
        assert_eq!(err.code, McpErrorCode::InvalidParams);
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
        let result = block_on(ClientBuilder::new().max_retries(0).connect_stdio_with_cx(
            "fastmcp_nonexistent_binary_xyz",
            &["--version"],
            &Cx::for_testing(),
        ));
        assert!(result.is_err());
    }

    #[cfg(all(unix, feature = "legacy-2024-11-05"))]
    #[test]
    fn public_builder_auto_clean_first_probe_timeout_reopens_a_fresh_legacy_child() {
        // One invocation can either consume discovery and remain silent, or
        // consume exact-2024 initialization. The successful second branch
        // therefore proves the selected legacy connection is a fresh child.
        let script = r#"IFS= read -r first || exit 1;
            case "$first" in
                *server/discover*) exec sleep 5 ;;
                *initialize*2024-11-05*)
                    printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"auto-timeout-legacy","version":"1.0.0"}}}';
                    IFS= read -r lifecycle || exit 1;
                    case "$lifecycle" in *notifications/initialized*) ;; *) exit 1 ;; esac;
                    IFS= read -r request || exit 1;
                    case "$request" in *ping*) printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{}}' ;; *) exit 1 ;; esac;
                    exec sleep 2 ;;
                *) exit 1 ;;
            esac"#;
        let started = Instant::now();
        let mut client = block_on(
            ClientBuilder::new()
                .request_timeout_policy(
                    RequestTimeoutPolicy::new(Duration::from_secs(1), Duration::from_secs(3))
                        .expect("bounded probe timeout is valid"),
                )
                .connect_stdio_with_cx("sh", &["-c", script], &Cx::for_request()),
        )
        .expect("a clean first-probe timeout authorizes one fresh legacy child");

        assert_eq!(client.protocol_policy(), ProtocolPolicy::Auto);
        assert_eq!(
            client.selected_protocol_era(),
            Some(fastmcp_protocol::protocol_policy::ProtocolEra::Legacy2024)
        );
        client
            .ping()
            .expect("the fresh legacy child accepts its first ordinary request");
        client
            .close()
            .expect("fresh legacy timeout-fallback cleanup");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(all(unix, feature = "legacy-2024-11-05"))]
    #[test]
    fn public_builder_auto_rejects_wrong_id_partial_malformed_ambiguous_and_transport_probes() {
        let legacy_success = concat!(
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"forbidden-legacy\",\"version\":\"1.0.0\"}}}'; ",
            "IFS= read -r lifecycle || exit 1; case \"$lifecycle\" in *notifications/initialized*) ;; *) exit 1 ;; esac; exec sleep 2"
        );
        let cases = [
            (
                "wrong-id",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":-32601,\"message\":\"method not found\"}}'; exec sleep 2",
            ),
            (
                "partial-frame-timeout",
                "printf '%s' '{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601'; exec sleep 10",
            ),
            (
                "malformed-result",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\",\"supportedVersions\":[\"2026-07-28\"],\"capabilities\":{}}}'; exec sleep 2",
            ),
            (
                "ambiguous-envelope",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{},\"error\":{\"code\":-32601,\"message\":\"method not found\"}}'; exec sleep 2",
            ),
            ("transport-closed", "exit 0"),
        ];

        for (name, discovery_branch) in cases {
            let script = format!(
                "IFS= read -r first || exit 1; case \"$first\" in *server/discover*) {discovery_branch} ;; *initialize*2024-11-05*) {legacy_success} ;; *) exit 1 ;; esac"
            );
            let result = block_on(
                ClientBuilder::new()
                    .max_retries(0)
                    .request_timeout_policy(
                        RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(5))
                            .expect("bounded probe timeout is valid"),
                    )
                    .connect_stdio_with_cx("sh", &["-c", script.as_str()], &Cx::for_request()),
            );
            assert!(
                result.is_err(),
                "{name} must remain terminal instead of reaching the legacy-success branch"
            );
        }
    }

    #[cfg(all(unix, feature = "legacy-2024-11-05"))]
    #[test]
    fn public_builder_auto_cancelled_probe_never_opens_legacy_child() {
        let script = r#"IFS= read -r first || exit 1;
            case "$first" in
                *server/discover*) exec sleep 5 ;;
                *initialize*2024-11-05*)
                    printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"forbidden-cancelled-legacy","version":"1.0.0"}}}';
                    exec sleep 2 ;;
                *) exit 1 ;;
            esac"#;
        let cx = Cx::for_request();
        let cancelling_cx = cx.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            cancelling_cx.cancel_fast(asupersync::CancelKind::User);
        });
        let result = block_on(
            ClientBuilder::new()
                .request_timeout_policy(
                    RequestTimeoutPolicy::new(Duration::from_secs(1), Duration::from_secs(1))
                        .expect("bounded cancellation probe timeout is valid"),
                )
                .connect_stdio_with_cx("sh", &["-c", script], &cx),
        );
        canceller
            .join()
            .expect("probe cancellation helper joins after the public connection returns");
        let error = match result {
            Ok(_) => panic!("caller cancellation during the modern probe is terminal"),
            Err(error) => error,
        };
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
    }

    #[cfg(unix)]
    #[test]
    fn connect_stdio_times_out_during_silent_initialization() {
        let started = std::time::Instant::now();
        let result = block_on(
            ClientBuilder::new()
                .request_timeout_policy(
                    RequestTimeoutPolicy::new(Duration::from_millis(20), Duration::from_millis(40))
                        .unwrap(),
                )
                .connect_stdio_with_cx("sh", &["-c", "exec sleep 5"], &Cx::for_testing()),
        );

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
    fn connection_retry_elapsed_cap_terminates_slow_initialization() {
        let started = Instant::now();
        let builder = ClientBuilder::new()
            .request_timeout_policy(
                RequestTimeoutPolicy::new(Duration::from_secs(30), Duration::from_secs(30))
                    .expect("ordinary initialization policy is valid"),
            )
            .connection_retry_policy(1, Duration::ZERO, Duration::from_millis(25))
            .expect("bounded retry policy is valid");

        let error = match block_on(builder.connect_stdio_with_cx(
            "sh",
            &["-c", "exec sleep 5"],
            &Cx::for_testing(),
        )) {
            Ok(mut client) => {
                let _ = client.close();
                panic!("slow initialization must not outlive the retry elapsed cap");
            }
            Err(error) => error,
        };
        assert_eq!(error.message, "Connection retry elapsed limit exceeded");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[cfg(all(feature = "apps", feature = "legacy-2024-11-05"))]
    #[test]
    fn default_builder_auto_with_configured_apps_falls_back_without_legacy_metadata_leak() {
        let script = auto_legacy_lifecycle_script(-32601);
        let mut client = block_on(
            ClientBuilder::new()
                .mcp_apps(
                    McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
                        .expect("valid Apps MIME settings"),
                )
                .connect_stdio_with_cx("sh", &["-c", script.as_str()], &Cx::for_request()),
        )
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
    #[cfg(all(feature = "apps", feature = "legacy-2024-11-05"))]
    #[test]
    fn default_builder_auto_rejects_invalid_params_discovery_without_legacy_fallback() {
        // This differs from the accepted default-Auto fallback fixture only in
        // the discovery error code. If Auto starts a legacy child for -32602,
        // the fixture's initialize branch succeeds and this test incorrectly
        // receives a live legacy client.
        let script = auto_legacy_lifecycle_script(-32602);
        let builder = ClientBuilder::new().mcp_apps(
            McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
                .expect("valid Apps MIME settings"),
        );
        let state_before_connect = builder.selected_protocol_plan().clone();

        let error = match block_on(builder.clone().connect_stdio_with_cx(
            "sh",
            &["-c", script.as_str()],
            &Cx::for_request(),
        )) {
            Ok(_) => panic!("invalid discovery parameters must not authorize legacy fallback"),
            Err(error) => error,
        };

        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(builder.selected_protocol_plan(), &state_before_connect);
    }

    #[cfg(unix)]
    #[cfg(all(feature = "apps", feature = "legacy-2024-11-05"))]
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

        let error = match block_on(builder.clone().connect_stdio_with_cx(
            "sh",
            &["-c", script.as_str()],
            &Cx::for_request(),
        )) {
            Ok(_) => panic!("changing only the discovery error must not authorize legacy fallback"),
            Err(error) => error,
        };

        assert!(error.message.contains("final discovery unavailable"));
        assert_eq!(builder.selected_protocol_plan(), &state_before_connect);
    }

    #[cfg(unix)]
    #[cfg(feature = "apps")]
    #[test]
    fn public_builder_advertises_configured_apps_after_active_modern_discovery() {
        let script = modern_apps_lifecycle_script(true);
        let mut client = block_on(
            ClientBuilder::new()
                .mcp_apps(
                    McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
                        .expect("valid Apps MIME settings"),
                )
                .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
                .connect_stdio_with_cx("sh", &["-c", script.as_str()], &Cx::for_request()),
        )
        .expect("active modern discovery initializes the public Apps client");

        assert!(client.mcp_apps_active());
        client
            .ping()
            .expect("active Apps negotiation advertises Apps on the public request path");
        client.close().expect("active Apps client cleanup");
    }

    #[cfg(unix)]
    #[cfg(feature = "apps")]
    #[test]
    fn public_builder_omits_configured_apps_after_one_field_inactive_modern_discovery() {
        let script = modern_apps_lifecycle_script(false);
        let mut client = block_on(
            ClientBuilder::new()
                .mcp_apps(
                    McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
                        .expect("valid Apps MIME settings"),
                )
                .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
                .connect_stdio_with_cx("sh", &["-c", script.as_str()], &Cx::for_request()),
        )
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
        let result = block_on(ClientBuilder::new().max_retries(0).connect_stdio_with_cx(
            "fastmcp_no_such_binary_abc123",
            &[],
            &Cx::for_testing(),
        ));
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
