//! Server builder for configuring MCP servers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use fastmcp_console::config::{BannerStyle, ConsoleConfig, TrafficVerbosity};
use fastmcp_console::stats::ServerStats;
use fastmcp_core::McpResult;
use fastmcp_protocol::extensions::ExtensionSettingsCompatibilityResolver;
use fastmcp_protocol::protocol_policy::ProtocolPolicy;
use fastmcp_protocol::{
    LoggingCapability, PromptsCapability, ResourceTemplate, ResourcesCapability,
    ServerCapabilities, ServerExtensionDiscovery, ServerInfo, ToolsCapability,
};
use log::{Level, LevelFilter};

use crate::handler::CompletionHandler;
use crate::proxy::{ProxyPromptHandler, ProxyResourceHandler, ProxyToolHandler};
#[cfg(test)]
use crate::tasks::SharedTaskManager;
use crate::{
    AuthProvider, DuplicateBehavior, ExtensionHandlerRegistry, FinalSubscriptionRegistry,
    FinalTaskRuntime, HttpServerConfig, LifespanHooks, LoggingConfig, PromptHandler, ProxyCatalog,
    ProxyClient, ResourceHandler, Router, Server, ServerExtensionConfigurationError,
    ServerExtensionRuntime, ToolHandler,
};

/// Default request timeout in seconds.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Builder for configuring an MCP server.
pub struct ServerBuilder {
    info: ServerInfo,
    capabilities: ServerCapabilities,
    router: Router,
    instructions: Option<String>,
    /// Request timeout in seconds (0 = no timeout).
    request_timeout_secs: u64,
    /// Whether to enable statistics collection.
    stats_enabled: bool,
    /// Whether to mask internal error details in responses.
    mask_error_details: bool,
    /// Logging configuration.
    logging: LoggingConfig,
    /// Console configuration for rich output.
    console_config: ConsoleConfig,
    /// Lifecycle hooks for startup/shutdown.
    lifespan: LifespanHooks,
    /// Optional authentication provider.
    auth_provider: Option<Arc<dyn AuthProvider>>,
    /// Registered middleware.
    middleware: Vec<Box<dyn crate::Middleware>>,
    /// Test-only legacy task manager. Production builds have no task-manager
    /// field or builder edge.
    #[cfg(test)]
    task_manager: Option<SharedTaskManager>,
    /// Behavior when registering duplicate component names.
    on_duplicate: DuplicateBehavior,
    /// Whether to use strict input validation (reject extra properties).
    strict_input_validation: bool,
    /// Per-connection ceiling for concurrent server-to-client requests.
    max_bidirectional_requests_per_connection: usize,
    /// Immutable protocol-era admission policy for live stdio/runtime connections.
    protocol_policy: ProtocolPolicy,
    /// Immutable configuration for the live dual-era HTTP endpoint.
    http_config: HttpServerConfig,
    /// Installed extension handlers and current server discovery settings.
    extension_runtime: Option<ServerExtensionRuntime>,
    /// Application-owned state for the configured final Tasks extension.
    final_task_runtime: Option<FinalTaskRuntime>,
}

impl ServerBuilder {
    /// Creates a new server builder.
    ///
    /// Statistics collection is enabled by default. Use [`without_stats`](Self::without_stats)
    /// to disable it for performance-critical scenarios.
    ///
    /// Console configuration defaults to environment-based settings. Use
    /// [`with_console_config`](Self::with_console_config) for programmatic control.
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        let console_config = ConsoleConfig::from_env();
        let logging = LoggingConfig::from(&console_config);
        Self {
            info: ServerInfo {
                name: name.into(),
                version: version.into(),
            },
            capabilities: ServerCapabilities {
                logging: Some(LoggingCapability::default()),
                ..ServerCapabilities::default()
            },
            router: Router::new(),
            instructions: None,
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
            stats_enabled: true,
            mask_error_details: false, // Disabled by default for development
            logging,
            console_config,
            lifespan: LifespanHooks::default(),
            auth_provider: None,
            middleware: Vec::new(),
            #[cfg(test)]
            task_manager: None,
            on_duplicate: DuplicateBehavior::default(),
            strict_input_validation: false,
            max_bidirectional_requests_per_connection:
                crate::bidirectional::DEFAULT_MAX_IN_FLIGHT_REQUESTS,
            protocol_policy: ProtocolPolicy::Auto,
            http_config: HttpServerConfig::default(),
            extension_runtime: None,
            final_task_runtime: None,
        }
    }

    /// Sets the behavior when registering duplicate component names.
    ///
    /// Controls what happens when a tool, resource, resource template, prompt,
    /// or mounted component is registered with an identifier that already
    /// exists:
    ///
    /// - [`DuplicateBehavior::Error`]: Reject the conflicting registration,
    ///   log the error, and continue constructing the builder
    /// - [`DuplicateBehavior::Warn`]: Log warning, keep original (default)
    /// - [`DuplicateBehavior::Replace`]: Replace with new component
    /// - [`DuplicateBehavior::Ignore`]: Silently keep original
    ///
    /// # Example
    ///
    /// ```ignore
    /// Server::new("demo", "1.0")
    ///     .on_duplicate(DuplicateBehavior::Error)  // Strict mode
    ///     .tool(handler1)
    ///     .tool(handler2)  // Rejected and logged if the name conflicts
    ///     .build();
    /// ```
    #[must_use]
    pub fn on_duplicate(mut self, behavior: DuplicateBehavior) -> Self {
        self.on_duplicate = behavior;
        self
    }

    /// Sets an authentication provider.
    #[must_use]
    pub fn auth_provider<P: AuthProvider + 'static>(mut self, provider: P) -> Self {
        self.auth_provider = Some(Arc::new(provider));
        self
    }

    /// Disables statistics collection.
    ///
    /// Use this for performance-critical scenarios where the overhead
    /// of atomic operations for stats tracking is undesirable.
    /// The overhead is minimal (typically nanoseconds per request),
    /// so this is rarely needed.
    #[must_use]
    pub fn without_stats(mut self) -> Self {
        self.stats_enabled = false;
        self
    }

    /// Sets the request timeout in seconds.
    ///
    /// Set to 0 to omit the server-owned ceiling. Ambient/request and handler
    /// deadlines are still composed into admission checks, cooperative
    /// checkpoints, and late-result rejection; this setting cannot relax them.
    /// A deadline does not preempt blocking synchronous code or imply that
    /// descendant work has been cancelled and drained. Default is 30 seconds.
    #[must_use]
    pub fn request_timeout(mut self, secs: u64) -> Self {
        self.request_timeout_secs = secs;
        self
    }

    /// Sets the maximum number of in-flight server-to-client requests for one
    /// transport connection.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` when `max` is zero or exceeds the hard safety
    /// limit enforced by the bidirectional request tracker.
    pub fn max_bidirectional_requests_per_connection(mut self, max: usize) -> McpResult<Self> {
        crate::bidirectional::PendingRequests::validate_max_in_flight(max)?;
        self.max_bidirectional_requests_per_connection = max;
        Ok(self)
    }

    /// Sets the pagination page size for list methods.
    ///
    /// When set, list methods will return up to `page_size` items and provide an
    /// opaque `nextCursor` for retrieving the next page. When not set (default),
    /// list methods return all items in a single response.
    #[must_use]
    pub fn list_page_size(mut self, page_size: usize) -> Self {
        self.router.set_list_page_size(Some(page_size));
        self
    }

    /// Enables or disables error detail masking.
    ///
    /// When enabled, internal error details are hidden from client responses:
    /// - Stack traces removed
    /// - File paths sanitized
    /// - Internal state not exposed
    /// - Generic "Internal server error" message returned
    ///
    /// Client errors (invalid request, method not found, etc.) are preserved
    /// since they don't contain sensitive internal details.
    ///
    /// Default is `false` (disabled) for development convenience.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let server = Server::new("api", "1.0")
    ///     .mask_error_details(true)  // Always mask in production
    ///     .build();
    /// ```
    #[must_use]
    pub fn mask_error_details(mut self, enabled: bool) -> Self {
        self.mask_error_details = enabled;
        self
    }

    /// Automatically masks error details based on environment.
    ///
    /// Masking is enabled when:
    /// - `FASTMCP_ENV` is set to "production"
    /// - `FASTMCP_MASK_ERRORS` is set to "true" or "1"
    /// - The build is a release build (`cfg!(not(debug_assertions))`)
    ///
    /// Masking is explicitly disabled when:
    /// - `FASTMCP_MASK_ERRORS` is set to "false" or "0"
    ///
    /// # Example
    ///
    /// ```ignore
    /// let server = Server::new("api", "1.0")
    ///     .auto_mask_errors()
    ///     .build();
    /// ```
    #[must_use]
    pub fn auto_mask_errors(mut self) -> Self {
        // Check for explicit override first
        if let Ok(val) = std::env::var("FASTMCP_MASK_ERRORS") {
            match val.to_lowercase().as_str() {
                "true" | "1" | "yes" => {
                    self.mask_error_details = true;
                    return self;
                }
                "false" | "0" | "no" => {
                    self.mask_error_details = false;
                    return self;
                }
                _ => {} // Fall through to other checks
            }
        }

        // Check for production environment
        if let Ok(env) = std::env::var("FASTMCP_ENV") {
            if env.to_lowercase() == "production" {
                self.mask_error_details = true;
                return self;
            }
        }

        // Default: mask in release builds, don't mask in debug builds
        self.mask_error_details = cfg!(not(debug_assertions));
        self
    }

    /// Returns whether error masking is enabled.
    #[must_use]
    pub fn is_error_masking_enabled(&self) -> bool {
        self.mask_error_details
    }

    /// Enables or disables strict input validation.
    ///
    /// When enabled, tool input validation will reject any properties not
    /// explicitly defined in the tool's input schema (enforces `additionalProperties: false`).
    ///
    /// When disabled (default), extra properties are allowed unless the schema
    /// explicitly sets `additionalProperties: false`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let server = Server::new("api", "1.0")
    ///     .strict_input_validation(true)  // Reject unknown properties
    ///     .build();
    /// ```
    #[must_use]
    pub fn strict_input_validation(mut self, enabled: bool) -> Self {
        self.strict_input_validation = enabled;
        self
    }

    /// Returns whether strict input validation is enabled.
    #[must_use]
    pub fn is_strict_input_validation_enabled(&self) -> bool {
        self.strict_input_validation
    }

    /// Selects the immutable MCP protocol-era policy for live stdio and runtime connections.
    ///
    /// The default [`ProtocolPolicy::Auto`] classifies the first accepted opening frame and then
    /// pins that connection to its selected era. `ModernOnly` and `LegacyOnly` reject an opening
    /// frame from the other exact supported era before it can enter request dispatch.
    #[must_use]
    pub fn protocol_policy(mut self, policy: ProtocolPolicy) -> Self {
        self.protocol_policy = policy;
        self
    }

    /// Installs the server's modern-only extension handlers and discovery settings.
    ///
    /// Descriptor registration remains mutable only until [`Self::build`]. The
    /// builder validates the advertised identifiers immediately, then freezes
    /// the handler and descriptor registries together while building the
    /// immutable [`Server`]. Exact MCP 2024-11-05 remains outside this path.
    pub fn extension_registry<R>(
        mut self,
        handlers: ExtensionHandlerRegistry,
        server_discovery: ServerExtensionDiscovery,
        resolver: R,
    ) -> Result<Self, ServerExtensionConfigurationError>
    where
        R: ExtensionSettingsCompatibilityResolver + Send + 'static,
    {
        if self.extension_runtime.is_some() {
            return Err(ServerExtensionConfigurationError::AlreadyInstalled);
        }
        let mut extension_runtime =
            ServerExtensionRuntime::new(handlers, server_discovery, resolver)?;
        if let Some(task_runtime) = self.final_task_runtime.as_ref() {
            extension_runtime.install_final_tasks(task_runtime)?;
        }
        self.extension_runtime = Some(extension_runtime);
        Ok(self)
    }

    /// Installs the official final Tasks extension around application-owned state.
    ///
    /// The supplied runtime owns neither an executor nor a task region. Its
    /// store and notification emitter remain application-owned, while a
    /// caller-owned structured supervisor advances worker state through the
    /// [`FinalTaskRuntime`] retained on the built [`Server`]. This builder
    /// installs the official descriptor, its three client-to-server request
    /// handlers, and its `notifications/tasks` delivery path together.
    pub fn final_tasks(
        mut self,
        task_runtime: FinalTaskRuntime,
    ) -> Result<Self, ServerExtensionConfigurationError> {
        if self.final_task_runtime.is_some() {
            return Err(ServerExtensionConfigurationError::FinalTasksAlreadyInstalled);
        }
        if let Some(extension_runtime) = self.extension_runtime.as_mut() {
            extension_runtime.install_final_tasks(&task_runtime)?;
        }
        self.final_task_runtime = Some(task_runtime);
        Ok(self)
    }

    /// Sets configuration for the live dual-era HTTP endpoint.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use fastmcp_server::HttpServerConfig;
    ///
    /// Server::new("demo", "1.0")
    ///     .http_config(HttpServerConfig::new().mcp_path("/api/mcp").max_connections(128))
    ///     .build();
    /// ```
    #[must_use]
    pub fn http_config(mut self, config: HttpServerConfig) -> Self {
        self.http_config = config;
        self
    }

    /// Builds a live dual-era HTTP endpoint with an exact legacy SSE origin.
    ///
    /// The modern route remains at [`HttpServerConfig::mcp_path`], while the
    /// exact MCP 2024-11-05 SSE route advertises `legacy_origin` plus the
    /// configured legacy message path.
    pub fn build_http_endpoint(
        self,
        legacy_origin: impl Into<String>,
    ) -> Result<crate::ServerHttpEndpoint, fastmcp_transport::http::DualEraHttpEndpointError> {
        self.build().into_http_endpoint(legacy_origin)
    }

    /// Registers a middleware.
    #[must_use]
    pub fn middleware<M: crate::Middleware + 'static>(mut self, middleware: M) -> Self {
        self.middleware.push(Box::new(middleware));
        self
    }

    /// Registers a tool handler.
    ///
    /// Duplicate handling is controlled by [`on_duplicate`](Self::on_duplicate).
    /// If [`DuplicateBehavior::Error`] is set and a duplicate is found,
    /// an error will be logged and the tool will not be registered.
    #[must_use]
    pub fn tool<H: ToolHandler + 'static>(mut self, handler: H) -> Self {
        if let Err(e) = self
            .router
            .add_tool_with_behavior(handler, self.on_duplicate)
        {
            log::error!(
                target: "fastmcp_rust::builder",
                "Failed to register tool; code={:?}",
                e.code
            );
        } else {
            self.capabilities.tools = Some(ToolsCapability::default());
        }
        self
    }

    /// Registers a resource handler.
    ///
    /// Duplicate handling is controlled by [`on_duplicate`](Self::on_duplicate).
    /// If [`DuplicateBehavior::Error`] is set and a duplicate is found,
    /// an error will be logged and the resource will not be registered.
    #[must_use]
    pub fn resource<H: ResourceHandler + 'static>(mut self, handler: H) -> Self {
        if let Err(e) = self
            .router
            .add_resource_with_behavior(handler, self.on_duplicate)
        {
            log::error!(
                target: "fastmcp_rust::builder",
                "Failed to register resource; code={:?}",
                e.code
            );
        } else {
            self.capabilities.resources = Some(ResourcesCapability::default());
        }
        self
    }

    /// Registers a resource template.
    ///
    /// Duplicate handling is controlled by [`on_duplicate`](Self::on_duplicate).
    /// With [`DuplicateBehavior::Error`], a conflicting template is rejected
    /// and logged while builder construction continues.
    #[must_use]
    pub fn resource_template(mut self, template: ResourceTemplate) -> Self {
        if let Err(error) = self
            .router
            .add_resource_template_with_behavior(template, self.on_duplicate)
        {
            log::error!(
                target: "fastmcp_rust::builder",
                "Failed to register resource template; code={:?}",
                error.code
            );
        } else {
            self.capabilities.resources = Some(ResourcesCapability::default());
        }
        self
    }

    /// Registers a prompt handler.
    ///
    /// Duplicate handling is controlled by [`on_duplicate`](Self::on_duplicate).
    /// If [`DuplicateBehavior::Error`] is set and a duplicate is found,
    /// an error will be logged and the prompt will not be registered.
    #[must_use]
    pub fn prompt<H: PromptHandler + 'static>(mut self, handler: H) -> Self {
        if let Err(e) = self
            .router
            .add_prompt_with_behavior(handler, self.on_duplicate)
        {
            log::error!(
                target: "fastmcp_rust::builder",
                "Failed to register prompt; code={:?}",
                e.code
            );
        } else {
            self.capabilities.prompts = Some(PromptsCapability::default());
        }
        self
    }

    /// Registers the server-wide `completion/complete` handler.
    ///
    /// The handler receives disjoint exact-legacy and final request parameter
    /// types. Building with a handler installs the real router dispatch target,
    /// which is the sole condition that enables final discovery's
    /// `capabilities.completions` claim.
    #[must_use]
    pub fn completion_handler<H: CompletionHandler + 'static>(mut self, handler: H) -> Self {
        self.router.add_completion_handler(handler);
        self
    }

    /// Registers proxy handlers for a remote MCP server.
    ///
    /// Use [`ProxyCatalog::from_client`] or [`ProxyClient::catalog`] to fetch
    /// definitions before calling this method.
    #[must_use]
    pub fn proxy(mut self, client: ProxyClient, catalog: ProxyCatalog) -> Self {
        let has_tools = !catalog.tools.is_empty();
        let has_resources = !catalog.resources.is_empty() || !catalog.resource_templates.is_empty();
        let has_prompts = !catalog.prompts.is_empty();

        for tool in catalog.tools {
            if let Err(error) = self.router.add_tool_with_behavior(
                ProxyToolHandler::new(tool, client.clone()),
                self.on_duplicate,
            ) {
                log::error!(
                    target: "fastmcp_rust::builder",
                    "Failed to register proxied tool; code={:?}",
                    error.code
                );
            }
        }

        for resource in catalog.resources {
            if let Err(error) = self.router.add_resource_with_behavior(
                ProxyResourceHandler::new(resource, client.clone()),
                self.on_duplicate,
            ) {
                log::error!(
                    target: "fastmcp_rust::builder",
                    "Failed to register proxied resource; code={:?}",
                    error.code
                );
            }
        }

        for template in catalog.resource_templates {
            if let Err(error) = self.router.add_resource_with_behavior(
                ProxyResourceHandler::from_template(template, client.clone()),
                self.on_duplicate,
            ) {
                log::error!(
                    target: "fastmcp_rust::builder",
                    "Failed to register proxied resource template; code={:?}",
                    error.code
                );
            }
        }

        for prompt in catalog.prompts {
            if let Err(error) = self.router.add_prompt_with_behavior(
                ProxyPromptHandler::new(prompt, client.clone()),
                self.on_duplicate,
            ) {
                log::error!(
                    target: "fastmcp_rust::builder",
                    "Failed to register proxied prompt; code={:?}",
                    error.code
                );
            }
        }

        if has_tools {
            self.capabilities.tools = Some(ToolsCapability::default());
        }
        if has_resources {
            self.capabilities.resources = Some(ResourcesCapability::default());
        }
        if has_prompts {
            self.capabilities.prompts = Some(PromptsCapability::default());
        }

        self
    }

    /// Creates a proxy to an external MCP server with automatic discovery.
    ///
    /// This is a convenience method that combines connection, discovery, and
    /// handler registration. The client should already be initialized (connected
    /// to the server).
    ///
    /// All tools, resources, and prompts from the external server are registered
    /// as proxy handlers with the specified prefix.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use fastmcp_client::Client;
    ///
    /// // Create and initialize client
    /// let mut client = Client::new(transport)?;
    /// client.initialize()?;
    ///
    /// // Create main server with proxy to external
    /// let main = Server::new("main", "1.0")
    ///     .tool(local_tool)
    ///     .as_proxy("ext", client)?    // ext/external_tool, etc.
    ///     .build();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the catalog fetch fails or the configured duplicate
    /// policy rejects a proxied component.
    pub fn as_proxy(
        mut self,
        prefix: &str,
        client: fastmcp_client::Client,
    ) -> Result<Self, fastmcp_core::McpError> {
        // Create proxy client and fetch catalog
        let proxy_client = ProxyClient::from_client(client);
        let catalog = proxy_client.catalog()?;

        // Capture counts before consuming
        let tool_count = catalog.tools.len();
        let resource_count = catalog.resources.len();
        let template_count = catalog.resource_templates.len();
        let prompt_count = catalog.prompts.len();

        let has_tools = tool_count > 0;
        let has_resources = resource_count > 0 || template_count > 0;
        let has_prompts = prompt_count > 0;

        // Register tools with prefix
        for tool in catalog.tools {
            log::debug!(
                target: "fastmcp_rust::proxy",
                "Registering proxied tool with configured prefix"
            );
            self.router.add_tool_with_behavior(
                ProxyToolHandler::with_prefix(tool, prefix, proxy_client.clone()),
                self.on_duplicate,
            )?;
        }

        // Register resources with prefix
        for resource in catalog.resources {
            log::debug!(
                target: "fastmcp_rust::proxy",
                "Registering proxied resource with configured prefix"
            );
            self.router.add_resource_with_behavior(
                ProxyResourceHandler::with_prefix(resource, prefix, proxy_client.clone()),
                self.on_duplicate,
            )?;
        }

        // Register resource templates with prefix
        for template in catalog.resource_templates {
            log::debug!(
                target: "fastmcp_rust::proxy",
                "Registering proxied resource template with configured prefix"
            );
            self.router.add_resource_with_behavior(
                ProxyResourceHandler::from_template_with_prefix(
                    template,
                    prefix,
                    proxy_client.clone(),
                ),
                self.on_duplicate,
            )?;
        }

        // Register prompts with prefix
        for prompt in catalog.prompts {
            log::debug!(
                target: "fastmcp_rust::proxy",
                "Registering proxied prompt with configured prefix"
            );
            self.router.add_prompt_with_behavior(
                ProxyPromptHandler::with_prefix(prompt, prefix, proxy_client.clone()),
                self.on_duplicate,
            )?;
        }

        // Update capabilities
        if has_tools {
            self.capabilities.tools = Some(ToolsCapability::default());
        }
        if has_resources {
            self.capabilities.resources = Some(ResourcesCapability::default());
        }
        if has_prompts {
            self.capabilities.prompts = Some(PromptsCapability::default());
        }

        log::info!(
            target: "fastmcp_rust::proxy",
            "Proxied {} tools, {} resources, {} templates, and {} prompts with a configured prefix",
            tool_count,
            resource_count,
            template_count,
            prompt_count
        );

        Ok(self)
    }

    /// Creates a proxy to an external MCP server without a prefix.
    ///
    /// Similar to [`as_proxy`](Self::as_proxy), but tools/resources/prompts
    /// keep their original names. Use this when proxying a single external
    /// server or when you don't need namespace separation.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let main = Server::new("main", "1.0")
    ///     .as_proxy_raw(client)?  // External tools appear with original names
    ///     .build();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if catalog discovery fails or the configured duplicate
    /// policy rejects any unprefixed proxy component.
    pub fn as_proxy_raw(
        self,
        client: fastmcp_client::Client,
    ) -> Result<Self, fastmcp_core::McpError> {
        self.as_proxy_raw_with_proxy_client(ProxyClient::from_client(client))
    }

    fn as_proxy_raw_with_proxy_client(
        self,
        proxy_client: ProxyClient,
    ) -> Result<Self, fastmcp_core::McpError> {
        let catalog = proxy_client.catalog()?;
        self.register_raw_proxy_catalog(proxy_client, catalog)
    }

    fn register_raw_proxy_catalog(
        mut self,
        proxy_client: ProxyClient,
        catalog: ProxyCatalog,
    ) -> Result<Self, fastmcp_core::McpError> {
        let has_tools = !catalog.tools.is_empty();
        let has_resources = !catalog.resources.is_empty() || !catalog.resource_templates.is_empty();
        let has_prompts = !catalog.prompts.is_empty();

        for tool in catalog.tools {
            self.router.add_tool_with_behavior(
                ProxyToolHandler::new(tool, proxy_client.clone()),
                self.on_duplicate,
            )?;
        }

        for resource in catalog.resources {
            self.router.add_resource_with_behavior(
                ProxyResourceHandler::new(resource, proxy_client.clone()),
                self.on_duplicate,
            )?;
        }

        for template in catalog.resource_templates {
            self.router.add_resource_with_behavior(
                ProxyResourceHandler::from_template(template, proxy_client.clone()),
                self.on_duplicate,
            )?;
        }

        for prompt in catalog.prompts {
            self.router.add_prompt_with_behavior(
                ProxyPromptHandler::new(prompt, proxy_client.clone()),
                self.on_duplicate,
            )?;
        }

        if has_tools {
            self.capabilities.tools = Some(ToolsCapability::default());
        }
        if has_resources {
            self.capabilities.resources = Some(ResourcesCapability::default());
        }
        if has_prompts {
            self.capabilities.prompts = Some(PromptsCapability::default());
        }

        Ok(self)
    }

    // ─────────────────────────────────────────────────
    // Server Composition (Mount)
    // ─────────────────────────────────────────────────

    /// Mounts another server's components into this server with an optional prefix.
    ///
    /// This consumes the source server and moves all its tools, resources, and prompts
    /// into this server. Names/URIs are prefixed with `prefix/` if a prefix is provided.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let db_server = Server::new("db", "1.0")
    ///     .tool(query_tool)
    ///     .tool(insert_tool)
    ///     .build();
    ///
    /// let api_server = Server::new("api", "1.0")
    ///     .tool(endpoint_tool)
    ///     .build();
    ///
    /// let main = Server::new("main", "1.0")
    ///     .mount(db_server, Some("db"))      // db/query, db/insert
    ///     .mount(api_server, Some("api"))    // api/endpoint
    ///     .build();
    /// ```
    ///
    /// # Prefix Rules
    ///
    /// - Prefixes must be alphanumeric plus underscores and hyphens
    /// - Prefixes cannot contain slashes
    /// - With prefix `"db"`, tool `"query"` becomes `"db/query"`
    /// - Without prefix, names are preserved (may cause conflicts)
    ///
    /// Duplicate handling follows [`on_duplicate`](Self::on_duplicate). With
    /// [`DuplicateBehavior::Error`], any conflict rejects the complete mount;
    /// the failure is logged and fluent builder construction continues.
    #[must_use]
    pub fn mount(mut self, server: crate::Server, prefix: Option<&str>) -> Self {
        let has_tools = server.has_tools();
        let has_resources = server.has_resources();
        let has_prompts = server.has_prompts();

        let source_router = server.into_router();
        let result = self
            .router
            .mount_with_behavior(source_router, prefix, self.on_duplicate);

        // Log warnings if any
        for warning in &result.warnings {
            log::warn!(target: "fastmcp_rust::mount", "{}", warning);
        }
        for error in &result.errors {
            log::error!(target: "fastmcp_rust::mount", "{}", error);
        }

        // Update capabilities based on what was mounted
        if has_tools && result.tools > 0 {
            self.capabilities.tools = Some(ToolsCapability::default());
        }
        if has_resources && (result.resources > 0 || result.resource_templates > 0) {
            self.capabilities.resources = Some(ResourcesCapability::default());
        }
        if has_prompts && result.prompts > 0 {
            self.capabilities.prompts = Some(PromptsCapability::default());
        }

        self
    }

    /// Mounts only tools from another server with an optional prefix.
    ///
    /// Similar to [`mount`](Self::mount), but only transfers tools, ignoring
    /// resources and prompts.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let utils_server = Server::new("utils", "1.0")
    ///     .tool(format_tool)
    ///     .tool(parse_tool)
    ///     .resource(config_resource)  // Will NOT be mounted
    ///     .build();
    ///
    /// let main = Server::new("main", "1.0")
    ///     .mount_tools(utils_server, Some("utils"))  // Only tools
    ///     .build();
    /// ```
    ///
    /// Duplicate handling follows [`on_duplicate`](Self::on_duplicate).
    #[must_use]
    pub fn mount_tools(mut self, server: crate::Server, prefix: Option<&str>) -> Self {
        let source_router = server.into_router();
        let result =
            self.router
                .mount_tools_with_behavior(source_router, prefix, self.on_duplicate);

        // Log warnings if any
        for warning in &result.warnings {
            log::warn!(target: "fastmcp_rust::mount", "{}", warning);
        }
        for error in &result.errors {
            log::error!(target: "fastmcp_rust::mount", "{}", error);
        }

        // Update capabilities if tools were mounted
        if result.tools > 0 {
            self.capabilities.tools = Some(ToolsCapability::default());
        }

        self
    }

    /// Mounts only resources from another server with an optional prefix.
    ///
    /// Similar to [`mount`](Self::mount), but only transfers resources,
    /// ignoring tools and prompts.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let data_server = Server::new("data", "1.0")
    ///     .resource(config_resource)
    ///     .resource(schema_resource)
    ///     .tool(query_tool)  // Will NOT be mounted
    ///     .build();
    ///
    /// let main = Server::new("main", "1.0")
    ///     .mount_resources(data_server, Some("data"))  // Only resources
    ///     .build();
    /// ```
    ///
    /// Duplicate handling follows [`on_duplicate`](Self::on_duplicate) for
    /// both static resources and resource templates.
    #[must_use]
    pub fn mount_resources(mut self, server: crate::Server, prefix: Option<&str>) -> Self {
        let source_router = server.into_router();
        let result =
            self.router
                .mount_resources_with_behavior(source_router, prefix, self.on_duplicate);

        // Log warnings if any
        for warning in &result.warnings {
            log::warn!(target: "fastmcp_rust::mount", "{}", warning);
        }
        for error in &result.errors {
            log::error!(target: "fastmcp_rust::mount", "{}", error);
        }

        // Update capabilities if resources were mounted
        if result.resources > 0 || result.resource_templates > 0 {
            self.capabilities.resources = Some(ResourcesCapability::default());
        }

        self
    }

    /// Mounts only prompts from another server with an optional prefix.
    ///
    /// Similar to [`mount`](Self::mount), but only transfers prompts,
    /// ignoring tools and resources.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let templates_server = Server::new("templates", "1.0")
    ///     .prompt(greeting_prompt)
    ///     .prompt(error_prompt)
    ///     .tool(format_tool)  // Will NOT be mounted
    ///     .build();
    ///
    /// let main = Server::new("main", "1.0")
    ///     .mount_prompts(templates_server, Some("tmpl"))  // Only prompts
    ///     .build();
    /// ```
    ///
    /// Duplicate handling follows [`on_duplicate`](Self::on_duplicate).
    #[must_use]
    pub fn mount_prompts(mut self, server: crate::Server, prefix: Option<&str>) -> Self {
        let source_router = server.into_router();
        let result =
            self.router
                .mount_prompts_with_behavior(source_router, prefix, self.on_duplicate);

        // Log warnings if any
        for warning in &result.warnings {
            log::warn!(target: "fastmcp_rust::mount", "{}", warning);
        }
        for error in &result.errors {
            log::error!(target: "fastmcp_rust::mount", "{}", error);
        }

        // Update capabilities if prompts were mounted
        if result.prompts > 0 {
            self.capabilities.prompts = Some(PromptsCapability::default());
        }

        self
    }

    /// Sets custom server instructions.
    #[must_use]
    pub fn instructions(mut self, instructions: impl Into<String>) -> Self {
        self.instructions = Some(instructions.into());
        self
    }

    /// Sets the log level.
    ///
    /// Default is read from `FASTMCP_LOG` environment variable, or `INFO` if not set.
    #[must_use]
    pub fn log_level(mut self, level: Level) -> Self {
        let filter = level.to_level_filter();
        self.logging.level = filter;
        self.console_config.log_level = filter;
        self
    }

    /// Sets the log level from a filter, including [`LevelFilter::Off`].
    #[must_use]
    pub fn log_level_filter(mut self, filter: LevelFilter) -> Self {
        self.logging.level = filter;
        self.console_config.log_level = filter;
        self
    }

    /// Sets whether to show timestamps in logs.
    ///
    /// Default is `true`.
    #[must_use]
    pub fn log_timestamps(mut self, show: bool) -> Self {
        self.logging.timestamps = show;
        self.console_config.log_timestamps = show;
        self
    }

    /// Sets whether to show target/module paths in logs.
    ///
    /// Default is `true`.
    #[must_use]
    pub fn log_targets(mut self, show: bool) -> Self {
        self.logging.targets = show;
        self.console_config.log_targets = show;
        self
    }

    /// Sets whether to show source file and line in logs.
    #[must_use]
    pub fn log_file_line(mut self, show: bool) -> Self {
        self.logging.file_line = show;
        self.console_config.log_file_line = show;
        self
    }

    /// Sets the full logging configuration.
    #[must_use]
    pub fn logging(mut self, config: LoggingConfig) -> Self {
        self.console_config.log_level = config.level;
        self.console_config.log_timestamps = config.timestamps;
        self.console_config.log_targets = config.targets;
        self.console_config.log_file_line = config.file_line;
        self.logging = config;
        self
    }

    // ─────────────────────────────────────────────────
    // Console Configuration
    // ─────────────────────────────────────────────────

    /// Sets the complete console configuration.
    ///
    /// This controls server-owned console output, including the banner,
    /// traffic logging, logger formatting, and rich/plain display mode.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use fastmcp_console::config::{ConsoleConfig, BannerStyle};
    ///
    /// Server::new("demo", "1.0.0")
    ///     .with_console_config(
    ///         ConsoleConfig::new()
    ///             .with_banner(BannerStyle::Compact)
    ///             .plain_mode()
    ///     )
    ///     .build();
    /// ```
    #[must_use]
    pub fn with_console_config(mut self, config: ConsoleConfig) -> Self {
        self.logging = LoggingConfig::from(&config);
        self.console_config = config;
        self
    }

    /// Sets the banner style.
    ///
    /// Controls how the startup banner is displayed.
    /// Default is `BannerStyle::Full`.
    #[must_use]
    pub fn with_banner(mut self, style: BannerStyle) -> Self {
        self.console_config = self.console_config.with_banner(style);
        self
    }

    /// Disables the startup banner.
    #[must_use]
    pub fn without_banner(mut self) -> Self {
        self.console_config = self.console_config.without_banner();
        self
    }

    /// Enables request/response traffic logging.
    ///
    /// Controls the verbosity of traffic logging:
    /// - `None`: No traffic logging (default)
    /// - `Summary`: Method name and timing only
    /// - `Full`: Full request/response bodies
    #[must_use]
    pub fn with_traffic_logging(mut self, verbosity: TrafficVerbosity) -> Self {
        self.console_config = self.console_config.with_traffic(verbosity);
        self
    }

    /// Forces plain text output (no colors/styling).
    ///
    /// Useful for CI environments, logging to files, or when running
    /// as an MCP server where rich output might interfere with the
    /// JSON-RPC protocol.
    #[must_use]
    pub fn plain_mode(mut self) -> Self {
        self.console_config = self.console_config.plain_mode();
        self
    }

    /// Forces color output even in non-TTY environments.
    #[must_use]
    pub fn force_color(mut self) -> Self {
        self.console_config = self.console_config.force_color(true);
        self
    }

    /// Returns a reference to the current console configuration.
    #[must_use]
    pub fn console_config(&self) -> &ConsoleConfig {
        &self.console_config
    }

    // ─────────────────────────────────────────────────
    // Lifecycle Hooks
    // ─────────────────────────────────────────────────

    /// Registers a startup hook that runs before the server starts accepting connections.
    ///
    /// The hook can perform initialization tasks like:
    /// - Opening database connections
    /// - Loading configuration files
    /// - Initializing caches
    ///
    /// If the hook returns an error, the server will not start.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Server::new("demo", "1.0.0")
    ///     .on_startup(|| {
    ///         println!("Server starting up...");
    ///         Ok(())
    ///     })
    ///     .run_stdio();
    /// ```
    #[must_use]
    pub fn on_startup<F, E>(mut self, hook: F) -> Self
    where
        F: FnOnce() -> Result<(), E> + Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        self.lifespan.on_startup = Some(Box::new(move || {
            hook().map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        }));
        self
    }

    /// Registers a shutdown hook that runs when the server is shutting down.
    ///
    /// The hook can perform cleanup tasks like:
    /// - Closing database connections
    /// - Flushing caches
    /// - Saving state
    ///
    /// Shutdown hooks are run on a best-effort basis. If the process is
    /// forcefully terminated, hooks may not run.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Server::new("demo", "1.0.0")
    ///     .on_shutdown(|| {
    ///         println!("Server shutting down...");
    ///     })
    ///     .run_stdio();
    /// ```
    #[must_use]
    pub fn on_shutdown<F>(mut self, hook: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        self.lifespan.on_shutdown = Some(Box::new(hook));
        self
    }

    /// Retains the legacy task manager for unit-test archaeology only.
    /// Production builds expose no task-manager builder edge.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_task_manager(mut self, task_manager: SharedTaskManager) -> Self {
        self.task_manager = Some(task_manager);
        // Fail closed even if future builder composition adds another path
        // that mutates the capability object before this call.
        self.capabilities.tasks = None;
        self
    }

    /// Returns the current request timeout.
    #[cfg(test)]
    fn request_timeout_secs(&self) -> u64 {
        self.request_timeout_secs
    }

    /// Builds the server.
    #[must_use]
    pub fn build(mut self) -> Server {
        // Configure router with strict input validation setting
        self.router
            .set_strict_input_validation(self.strict_input_validation);
        let console = fastmcp_console::console::FastMcpConsole::with_enabled(
            self.console_config.should_use_rich(),
        );
        let final_subscriptions = Arc::new(FinalSubscriptionRegistry::default());
        let final_task_runtime = self.final_task_runtime.clone();
        if let Some(task_runtime) = final_task_runtime.as_ref() {
            let subscriptions = Arc::clone(&final_subscriptions);
            task_runtime.add_notification_emitter(Arc::new(move |notification| {
                if subscriptions.publish_task(notification).is_err() {
                    log::error!(
                        target: "fastmcp_rust::server",
                        "Failed to publish a typed final Task notification"
                    );
                }
            }));
        }
        self.router
            .set_final_task_runtime(final_task_runtime.clone());
        let extension_runtime = match self.extension_runtime {
            Some(mut runtime) => {
                runtime
                    .freeze()
                    .expect("validated server extension descriptors must freeze");
                Some(Arc::new(runtime))
            }
            None => final_task_runtime.map(|task_runtime| {
                let mut runtime = ServerExtensionRuntime::with_final_tasks(&task_runtime)
                    .expect("final Tasks must install into an empty extension registry");
                runtime
                    .freeze()
                    .expect("final Tasks extension descriptors must freeze");
                Arc::new(runtime)
            }),
        };

        Server {
            info: self.info,
            capabilities: self.capabilities,
            router: Arc::new(self.router),
            instructions: self.instructions,
            request_timeout_secs: self.request_timeout_secs,
            stats: if self.stats_enabled {
                Some(ServerStats::new())
            } else {
                None
            },
            mask_error_details: self.mask_error_details,
            logging: self.logging,
            console_config: self.console_config,
            console,
            lifespan: Mutex::new(Some(self.lifespan)),
            auth_provider: self.auth_provider,
            middleware: Arc::new(self.middleware),
            active_requests: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            task_manager: self.task_manager,
            max_bidirectional_requests_per_connection: self
                .max_bidirectional_requests_per_connection,
            protocol_policy: self.protocol_policy,
            http_config: self.http_config,
            extension_runtime,
            final_task_runtime: self.final_task_runtime,
            final_subscriptions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_core::{McpContext, McpResult};
    use fastmcp_protocol::{Content, Prompt, Resource, ResourceContent, Tool};

    // ── Stub handlers ────────────────────────────────────────────────

    struct TestTool;
    impl crate::ToolHandler for TestTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "test_tool".to_string(),
                description: Some("a test tool".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }
        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text("ok")])
        }
    }

    struct TestResource;
    impl crate::ResourceHandler for TestResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "file:///test".to_string(),
                name: "test_res".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }
        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![ResourceContent {
                uri: "file:///test".to_string(),
                mime_type: None,
                text: Some("content".to_string()),
                blob: None,
            }])
        }
    }

    struct TestPrompt;
    impl crate::PromptHandler for TestPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "test_prompt".to_string(),
                description: None,
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }
        }
        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<fastmcp_protocol::PromptMessage>> {
            Ok(vec![])
        }
    }

    struct TestCompletion;

    impl crate::handler::CompletionHandler for TestCompletion {
        fn complete_legacy(
            &self,
            _ctx: &McpContext,
            _params: fastmcp_protocol::LegacyCompletionParams,
        ) -> McpResult<fastmcp_protocol::CompletionValues> {
            Ok(fastmcp_protocol::CompletionValues {
                values: vec!["staging".to_string()],
                total: Some(1),
                has_more: Some(false),
            })
        }

        fn complete_final(
            &self,
            _ctx: &McpContext,
            _params: fastmcp_protocol::FinalCompletionParams,
        ) -> McpResult<fastmcp_protocol::CompletionValues> {
            Ok(fastmcp_protocol::CompletionValues {
                values: vec!["staging".to_string()],
                total: Some(1),
                has_more: Some(false),
            })
        }
    }

    struct CountingCompletion(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    impl crate::handler::CompletionHandler for CountingCompletion {
        fn complete_legacy(
            &self,
            _ctx: &McpContext,
            _params: fastmcp_protocol::LegacyCompletionParams,
        ) -> McpResult<fastmcp_protocol::CompletionValues> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(fastmcp_protocol::CompletionValues {
                values: vec!["staging".to_string()],
                total: Some(1),
                has_more: Some(false),
            })
        }

        fn complete_final(
            &self,
            _ctx: &McpContext,
            _params: fastmcp_protocol::FinalCompletionParams,
        ) -> McpResult<fastmcp_protocol::CompletionValues> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(fastmcp_protocol::CompletionValues {
                values: vec!["staging".to_string()],
                total: Some(1),
                has_more: Some(false),
            })
        }
    }

    struct MarkedTool(&'static str);

    impl crate::ToolHandler for MarkedTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "duplicate_tool".to_string(),
                description: Some(self.0.to_string()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![self.0.to_string()],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text(self.0)])
        }
    }

    struct MarkedResource(&'static str);

    impl crate::ResourceHandler for MarkedResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "duplicate://resource".to_string(),
                name: self.0.to_string(),
                description: Some(self.0.to_string()),
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![self.0.to_string()],
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![])
        }
    }

    struct MarkedPrompt(&'static str);

    impl crate::PromptHandler for MarkedPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "duplicate_prompt".to_string(),
                description: Some(self.0.to_string()),
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![self.0.to_string()],
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<fastmcp_protocol::PromptMessage>> {
            Ok(vec![])
        }
    }

    fn marked_resource_template(marker: &str) -> ResourceTemplate {
        ResourceTemplate {
            uri_template: "duplicate://{item}".to_string(),
            name: marker.to_string(),
            description: Some(marker.to_string()),
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![marker.to_string()],
        }
    }

    fn marked_builder(marker: &'static str) -> ServerBuilder {
        ServerBuilder::new("marked", "1.0")
            .tool(MarkedTool(marker))
            .resource(MarkedResource(marker))
            .resource_template(marked_resource_template(marker))
            .prompt(MarkedPrompt(marker))
    }

    fn assert_marked_server(server: &crate::Server, marker: &str) {
        assert_eq!(server.tools().len(), 1);
        assert_eq!(server.resources().len(), 1);
        assert_eq!(server.resource_templates().len(), 1);
        assert_eq!(server.prompts().len(), 1);
        assert_eq!(server.tools()[0].tags, vec![marker.to_string()]);
        assert_eq!(server.resources()[0].tags, vec![marker.to_string()]);
        assert_eq!(
            server.resource_templates()[0].tags,
            vec![marker.to_string()]
        );
        assert_eq!(server.prompts()[0].tags, vec![marker.to_string()]);
    }

    struct DuplicatePolicyProxyBackend;

    impl crate::proxy::ProxyBackend for DuplicatePolicyProxyBackend {
        fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
            Ok(duplicate_policy_proxy_catalog().tools)
        }

        fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
            Ok(duplicate_policy_proxy_catalog().resources)
        }

        fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
            Ok(duplicate_policy_proxy_catalog().resource_templates)
        }

        fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
            Ok(duplicate_policy_proxy_catalog().prompts)
        }

        fn call_tool(&mut self, _: &str, _: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![])
        }

        fn call_tool_with_progress(
            &mut self,
            _: &str,
            _: serde_json::Value,
            _: crate::proxy::ProgressCallback<'_>,
        ) -> McpResult<Vec<Content>> {
            Ok(vec![])
        }

        fn read_resource(&mut self, _: &str) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![])
        }

        fn get_prompt(
            &mut self,
            _: &str,
            _: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<fastmcp_protocol::PromptMessage>> {
            Ok(vec![])
        }
    }

    fn duplicate_policy_proxy_catalog() -> ProxyCatalog {
        ProxyCatalog {
            tools: vec![Tool {
                name: "test_tool".to_string(),
                description: Some("proxied tool".to_string()),
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }],
            resources: vec![Resource {
                uri: "file:///test".to_string(),
                name: "proxied resource".to_string(),
                description: Some("proxied resource".to_string()),
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }],
            prompts: vec![Prompt {
                name: "test_prompt".to_string(),
                description: Some("proxied prompt".to_string()),
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }],
            ..ProxyCatalog::default()
        }
    }

    // ── Builder defaults ─────────────────────────────────────────────

    #[test]
    fn builder_new_sets_info() {
        let builder = ServerBuilder::new("my-server", "2.0.0");
        let server = builder.build();
        assert_eq!(server.info().name, "my-server");
        assert_eq!(server.info().version, "2.0.0");
    }

    #[test]
    fn builder_default_has_logging_capability() {
        let builder = ServerBuilder::new("srv", "1.0");
        let server = builder.build();
        assert!(server.capabilities().logging.is_some());
    }

    #[test]
    fn builder_default_has_no_tool_resource_prompt_capabilities() {
        let builder = ServerBuilder::new("srv", "1.0");
        let server = builder.build();
        assert!(server.capabilities().tools.is_none());
        assert!(server.capabilities().resources.is_none());
        assert!(server.capabilities().prompts.is_none());
    }

    #[test]
    fn builder_completion_handler_activates_exact_discovery_capability() {
        let server = ServerBuilder::new("srv", "1.0")
            .completion_handler(TestCompletion)
            .build();
        let discovery = server
            .server_discovery()
            .expect("installed completion handler produces discovery");
        let wire = serde_json::to_value(discovery).expect("discovery serializes");

        assert_eq!(wire["capabilities"]["completions"], serde_json::json!({}));
    }

    #[test]
    fn builder_without_completion_handler_omits_discovery_capability() {
        let server = ServerBuilder::new("srv", "1.0").build();
        let discovery = server
            .server_discovery()
            .expect("server without completion handler still discovers");
        let wire = serde_json::to_value(discovery).expect("discovery serializes");

        assert!(
            wire["capabilities"].get("completions").is_none(),
            "absence of the handler must not advertise completion"
        );
    }

    #[test]
    fn builder_completion_handler_rejects_final_metadata_before_handler_state_changes() {
        let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server = ServerBuilder::new("srv", "1.0")
            .completion_handler(CountingCompletion(std::sync::Arc::clone(&invocations)))
            .build();
        let request_ctx = McpContext::new(asupersync::Cx::for_testing(), 93);
        let baseline = fastmcp_protocol::JsonRpcRequest::new(
            "completion/complete",
            Some(serde_json::json!({
                "ref": {"type": "ref/prompt", "name": "deploy"},
                "argument": {"name": "environment", "value": "sta"},
            })),
            93_i64,
        );
        let mut planted = baseline.clone();
        planted
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("completion parameters are an object")
            .insert(
                "_meta".to_string(),
                serde_json::json!({
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                }),
            );

        let baseline_result = server
            .router
            .dispatch_legacy_completion(&request_ctx, &baseline)
            .expect("baseline legacy completion reaches the builder-installed handler");
        assert_eq!(
            invocations.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the accepted request invokes the installed handler once"
        );
        let planted_before = serde_json::to_vec(&planted).expect("planted request serializes");

        let error = server
            .router
            .dispatch_legacy_completion(&request_ctx, &planted)
            .expect_err("the sole final metadata field is refused in the exact legacy route");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
        assert_eq!(
            invocations.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "cross-era rejection occurs before handler-owned state can change"
        );
        assert_eq!(
            serde_json::to_vec(&planted).expect("rejected request serializes"),
            planted_before,
            "the rejected request remains caller-owned and unchanged"
        );
        assert_eq!(
            server
                .router
                .dispatch_legacy_completion(&request_ctx, &baseline)
                .expect("baseline remains dispatchable after the rejection"),
            baseline_result,
            "the rejected one-field variant cannot alter the accepted completion result"
        );
        assert_eq!(
            invocations.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "only accepted requests mutate handler-owned state"
        );
    }

    #[test]
    fn builder_default_stats_enabled() {
        let server = ServerBuilder::new("srv", "1.0").build();
        assert!(server.stats().is_some());
    }

    #[test]
    fn builder_default_request_timeout() {
        let builder = ServerBuilder::new("srv", "1.0");
        assert_eq!(builder.request_timeout_secs(), DEFAULT_REQUEST_TIMEOUT_SECS);
    }

    #[test]
    fn builder_bidirectional_limit_has_exact_validated_boundaries() {
        let default = ServerBuilder::new("srv", "1.0");
        assert_eq!(
            default.max_bidirectional_requests_per_connection,
            crate::bidirectional::DEFAULT_MAX_IN_FLIGHT_REQUESTS
        );

        for valid in [1, crate::bidirectional::HARD_MAX_IN_FLIGHT_REQUESTS] {
            let server = ServerBuilder::new("srv", "1.0")
                .max_bidirectional_requests_per_connection(valid)
                .expect("boundary must be valid")
                .build();
            assert_eq!(server.max_bidirectional_requests_per_connection, valid);
            assert_eq!(
                server.new_pending_requests_for_connection().max_in_flight(),
                valid
            );
        }

        for invalid in [0, crate::bidirectional::HARD_MAX_IN_FLIGHT_REQUESTS + 1] {
            let Err(error) =
                ServerBuilder::new("srv", "1.0").max_bidirectional_requests_per_connection(invalid)
            else {
                panic!("out-of-range limit must fail closed");
            };
            assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
        }
    }

    #[test]
    fn builder_default_error_masking_disabled() {
        let builder = ServerBuilder::new("srv", "1.0");
        assert!(!builder.is_error_masking_enabled());
    }

    #[test]
    fn builder_default_strict_validation_disabled() {
        let builder = ServerBuilder::new("srv", "1.0");
        assert!(!builder.is_strict_input_validation_enabled());
    }

    #[test]
    fn builder_protocol_policy_defaults_to_auto() {
        let server = ServerBuilder::new("srv", "1.0").build();

        assert_eq!(server.protocol_policy(), ProtocolPolicy::Auto);
    }

    // ── Fluent API setters ───────────────────────────────────────────

    #[test]
    fn builder_request_timeout() {
        let builder = ServerBuilder::new("srv", "1.0").request_timeout(60);
        assert_eq!(builder.request_timeout_secs(), 60);
    }

    #[test]
    fn builder_request_timeout_zero_omits_server_ceiling() {
        let builder = ServerBuilder::new("srv", "1.0").request_timeout(0);
        assert_eq!(builder.request_timeout_secs(), 0);
    }

    #[test]
    fn builder_without_stats() {
        let server = ServerBuilder::new("srv", "1.0").without_stats().build();
        assert!(server.stats().is_none());
    }

    #[test]
    fn builder_mask_error_details() {
        let builder = ServerBuilder::new("srv", "1.0").mask_error_details(true);
        assert!(builder.is_error_masking_enabled());
    }

    #[test]
    fn builder_strict_input_validation() {
        let builder = ServerBuilder::new("srv", "1.0").strict_input_validation(true);
        assert!(builder.is_strict_input_validation_enabled());
    }

    #[test]
    fn builder_instructions() {
        let server = ServerBuilder::new("srv", "1.0")
            .instructions("Use this server wisely")
            .build();
        // instructions stored internally - verify build succeeds
        let _ = server;
    }

    #[test]
    fn builder_log_level() {
        let builder = ServerBuilder::new("srv", "1.0").log_level(Level::Debug);
        assert_eq!(builder.logging.level, LevelFilter::Debug);
        assert_eq!(builder.console_config.log_level, LevelFilter::Debug);
    }

    #[test]
    fn builder_log_level_filter() {
        let builder = ServerBuilder::new("srv", "1.0").log_level_filter(LevelFilter::Warn);
        assert_eq!(builder.logging.level, LevelFilter::Warn);
        assert_eq!(builder.console_config.log_level, LevelFilter::Warn);
    }

    #[test]
    fn builder_log_timestamps_and_targets() {
        let builder = ServerBuilder::new("srv", "1.0")
            .log_timestamps(false)
            .log_targets(false)
            .log_file_line(true);
        assert!(!builder.logging.timestamps);
        assert!(!builder.console_config.log_timestamps);
        assert!(!builder.logging.targets);
        assert!(!builder.console_config.log_targets);
        assert!(builder.logging.file_line);
        assert!(builder.console_config.log_file_line);
    }

    // ── Console configuration ────────────────────────────────────────

    #[test]
    fn builder_without_banner() {
        let builder = ServerBuilder::new("srv", "1.0").without_banner();
        let config = builder.console_config();
        assert_eq!(config.banner_style, BannerStyle::None);
    }

    #[test]
    fn builder_with_banner_compact() {
        let builder = ServerBuilder::new("srv", "1.0").with_banner(BannerStyle::Compact);
        let config = builder.console_config();
        assert_eq!(config.banner_style, BannerStyle::Compact);
    }

    #[test]
    fn builder_plain_mode() {
        let builder = ServerBuilder::new("srv", "1.0").plain_mode();
        let _config = builder.console_config();
    }

    // ── Handler registration ─────────────────────────────────────────

    #[test]
    fn builder_tool_enables_capability() {
        let server = ServerBuilder::new("srv", "1.0").tool(TestTool).build();
        assert!(server.capabilities().tools.is_some());
        assert!(server.has_tools());
    }

    #[test]
    fn builder_resource_enables_capability() {
        let server = ServerBuilder::new("srv", "1.0")
            .resource(TestResource)
            .build();
        assert!(server.capabilities().resources.is_some());
        assert!(server.has_resources());
    }

    #[test]
    fn builder_prompt_enables_capability() {
        let server = ServerBuilder::new("srv", "1.0").prompt(TestPrompt).build();
        assert!(server.capabilities().prompts.is_some());
        assert!(server.has_prompts());
    }

    #[test]
    fn builder_all_handlers() {
        let server = ServerBuilder::new("srv", "1.0")
            .tool(TestTool)
            .resource(TestResource)
            .prompt(TestPrompt)
            .build();
        assert!(server.has_tools());
        assert!(server.has_resources());
        assert!(server.has_prompts());
    }

    #[test]
    fn builder_no_handlers_means_no_capabilities() {
        let server = ServerBuilder::new("srv", "1.0").build();
        assert!(!server.has_tools());
        assert!(!server.has_resources());
        assert!(!server.has_prompts());
    }

    // ── Duplicate behavior ───────────────────────────────────────────

    #[test]
    fn builder_on_duplicate_default_is_warn() {
        let _builder = ServerBuilder::new("srv", "1.0");
        // DuplicateBehavior::default() is Warn - builder should use that
    }

    #[test]
    fn builder_on_duplicate_ignore() {
        let server = ServerBuilder::new("srv", "1.0")
            .on_duplicate(DuplicateBehavior::Ignore)
            .tool(TestTool)
            .build();
        assert!(server.has_tools());
    }

    #[test]
    fn builder_on_duplicate_replace() {
        let server = ServerBuilder::new("srv", "1.0")
            .on_duplicate(DuplicateBehavior::Replace)
            .tool(TestTool)
            .build();
        assert!(server.has_tools());
    }

    #[test]
    fn builder_resource_template_honors_duplicate_policy() {
        for behavior in [
            DuplicateBehavior::Warn,
            DuplicateBehavior::Ignore,
            DuplicateBehavior::Error,
        ] {
            let server = ServerBuilder::new("srv", "1.0")
                .on_duplicate(behavior)
                .resource_template(marked_resource_template("original"))
                .resource_template(marked_resource_template("incoming"))
                .build();
            assert_eq!(server.resource_templates().len(), 1);
            assert_eq!(server.resource_templates()[0].name, "original");
        }

        let server = ServerBuilder::new("srv", "1.0")
            .on_duplicate(DuplicateBehavior::Replace)
            .resource_template(marked_resource_template("original"))
            .resource_template(marked_resource_template("incoming"))
            .build();
        assert_eq!(server.resource_templates().len(), 1);
        assert_eq!(server.resource_templates()[0].name, "incoming");
    }

    // ── Lifecycle hooks ──────────────────────────────────────────────

    #[test]
    fn builder_on_startup_builds() {
        let server = ServerBuilder::new("srv", "1.0")
            .on_startup(|| -> Result<(), std::io::Error> { Ok(()) })
            .build();
        let _ = server;
    }

    #[test]
    fn builder_on_shutdown_builds() {
        let server = ServerBuilder::new("srv", "1.0").on_shutdown(|| {}).build();
        let _ = server;
    }

    // ── Console config on built server ───────────────────────────────

    #[test]
    fn built_server_console_config_matches_builder() {
        let server = ServerBuilder::new("srv", "1.0").without_banner().build();
        assert_eq!(server.console_config().banner_style, BannerStyle::None);
    }

    // ── Chaining ─────────────────────────────────────────────────────

    #[test]
    fn builder_chaining_fluent_api() {
        let server = ServerBuilder::new("chain", "3.0")
            .request_timeout(120)
            .mask_error_details(true)
            .strict_input_validation(true)
            .without_banner()
            .plain_mode()
            .tool(TestTool)
            .resource(TestResource)
            .prompt(TestPrompt)
            .on_shutdown(|| {})
            .build();

        assert_eq!(server.info().name, "chain");
        assert_eq!(server.info().version, "3.0");
        assert!(server.has_tools());
        assert!(server.has_resources());
        assert!(server.has_prompts());
    }

    // ── Console configuration extended ─────────────────────────────

    #[test]
    fn builder_with_console_config() {
        let mut config = ConsoleConfig::new().with_banner(BannerStyle::None);
        config.log_level = LevelFilter::Trace;
        config.log_timestamps = false;
        config.log_targets = false;
        config.log_file_line = true;
        let builder = ServerBuilder::new("srv", "1.0").with_console_config(config);
        assert_eq!(builder.console_config().banner_style, BannerStyle::None);
        assert_eq!(builder.logging.level, LevelFilter::Trace);
        assert!(!builder.logging.timestamps);
        assert!(!builder.logging.targets);
        assert!(builder.logging.file_line);
    }

    #[test]
    fn logging_and_console_setters_keep_one_effective_configuration() {
        let console = ConsoleConfig::new().with_log_level_filter(LevelFilter::Off);
        let builder = ServerBuilder::new("srv", "1.0")
            .log_level(Level::Debug)
            .with_console_config(console);
        assert_eq!(builder.logging.level, LevelFilter::Off);
        assert_eq!(builder.console_config.log_level, LevelFilter::Off);

        let builder = builder.log_level_filter(LevelFilter::Warn);
        assert_eq!(builder.logging.level, LevelFilter::Warn);
        assert_eq!(builder.console_config.log_level, LevelFilter::Warn);
    }

    #[test]
    fn builder_with_traffic_logging() {
        let builder = ServerBuilder::new("srv", "1.0").with_traffic_logging(TrafficVerbosity::Full);
        let config = builder.console_config();
        assert_eq!(config.traffic_verbosity, TrafficVerbosity::Full);
    }

    #[test]
    fn builder_force_color() {
        let builder = ServerBuilder::new("srv", "1.0").force_color();
        let _config = builder.console_config();
        // Just verify the chain completes without panic
    }

    // ── Logging config ─────────────────────────────────────────────

    #[test]
    fn builder_logging_full_config() {
        let config = LoggingConfig {
            level: LevelFilter::Trace,
            timestamps: false,
            targets: false,
            file_line: true,
        };
        let _builder = ServerBuilder::new("srv", "1.0").logging(config);
    }

    // ── List page size ─────────────────────────────────────────────

    #[test]
    fn builder_list_page_size() {
        let server = ServerBuilder::new("srv", "1.0")
            .list_page_size(50)
            .tool(TestTool)
            .build();
        assert!(server.has_tools());
    }

    // ── Resource template ──────────────────────────────────────────

    #[test]
    fn builder_resource_template_enables_capability() {
        let template = ResourceTemplate {
            uri_template: "file://{path}".to_string(),
            name: "Template".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let server = ServerBuilder::new("srv", "1.0")
            .resource_template(template)
            .build();
        assert!(server.capabilities().resources.is_some());
    }

    // ── Middleware ──────────────────────────────────────────────────

    struct NoopMiddleware;
    impl crate::Middleware for NoopMiddleware {}

    #[test]
    fn builder_middleware() {
        let server = ServerBuilder::new("srv", "1.0")
            .middleware(NoopMiddleware)
            .build();
        let _ = server;
    }

    #[test]
    fn builder_multiple_middleware() {
        let server = ServerBuilder::new("srv", "1.0")
            .middleware(NoopMiddleware)
            .middleware(NoopMiddleware)
            .build();
        let _ = server;
    }

    // ── Auth provider ──────────────────────────────────────────────

    struct TestAuthProvider;
    impl crate::AuthProvider for TestAuthProvider {
        fn authenticate(
            &self,
            _ctx: &McpContext,
            _request: crate::auth::AuthRequest<'_>,
        ) -> McpResult<fastmcp_core::AuthContext> {
            Ok(fastmcp_core::AuthContext::with_subject("test-user"))
        }
    }

    #[test]
    fn builder_auth_provider() {
        let server = ServerBuilder::new("srv", "1.0")
            .auth_provider(TestAuthProvider)
            .build();
        let _ = server;
    }

    // ── auto_mask_errors ───────────────────────────────────────────

    #[test]
    fn builder_auto_mask_errors() {
        // In debug builds (test mode), auto_mask_errors defaults to false
        let builder = ServerBuilder::new("srv", "1.0").auto_mask_errors();
        // In debug_assertions mode, masking should be disabled
        assert!(!builder.is_error_masking_enabled());
    }

    // ── Duplicate behavior error ───────────────────────────────────

    struct DupTool(&'static str);
    impl crate::ToolHandler for DupTool {
        fn definition(&self) -> Tool {
            Tool {
                name: self.0.to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }
        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text("ok")])
        }
    }

    #[test]
    fn builder_on_duplicate_error_logs_but_continues() {
        // With DuplicateBehavior::Error, duplicate registration logs error
        // but builder doesn't panic
        let server = ServerBuilder::new("srv", "1.0")
            .on_duplicate(DuplicateBehavior::Error)
            .tool(DupTool("dup"))
            .tool(DupTool("dup")) // duplicate - will log error
            .build();
        assert!(server.has_tools());
    }

    // ── Mount ──────────────────────────────────────────────────────

    #[test]
    fn builder_mount_with_prefix() {
        let source = ServerBuilder::new("sub", "1.0")
            .tool(TestTool)
            .resource(TestResource)
            .prompt(TestPrompt)
            .build();

        let main = ServerBuilder::new("main", "1.0")
            .mount(source, Some("sub"))
            .build();

        assert!(main.has_tools());
        assert!(main.has_resources());
        assert!(main.has_prompts());
    }

    #[test]
    fn builder_mount_without_prefix() {
        let source = ServerBuilder::new("sub", "1.0").tool(TestTool).build();

        let main = ServerBuilder::new("main", "1.0")
            .mount(source, None)
            .build();

        assert!(main.has_tools());
    }

    #[test]
    fn builder_mount_tools_only() {
        let source = ServerBuilder::new("sub", "1.0")
            .tool(TestTool)
            .resource(TestResource)
            .prompt(TestPrompt)
            .build();

        let main = ServerBuilder::new("main", "1.0")
            .mount_tools(source, Some("sub"))
            .build();

        assert!(main.has_tools());
        // Resources and prompts should NOT be mounted
        assert!(!main.has_resources());
        assert!(!main.has_prompts());
    }

    #[test]
    fn builder_mount_resources_only() {
        let source = ServerBuilder::new("sub", "1.0")
            .tool(TestTool)
            .resource(TestResource)
            .prompt(TestPrompt)
            .build();

        let main = ServerBuilder::new("main", "1.0")
            .mount_resources(source, Some("data"))
            .build();

        assert!(!main.has_tools());
        assert!(main.has_resources());
        assert!(!main.has_prompts());
    }

    #[test]
    fn builder_mount_prompts_only() {
        let source = ServerBuilder::new("sub", "1.0")
            .tool(TestTool)
            .resource(TestResource)
            .prompt(TestPrompt)
            .build();

        let main = ServerBuilder::new("main", "1.0")
            .mount_prompts(source, Some("tmpl"))
            .build();

        assert!(!main.has_tools());
        assert!(!main.has_resources());
        assert!(main.has_prompts());
    }

    #[test]
    fn builder_mount_empty_server() {
        let source = ServerBuilder::new("empty", "1.0").build();

        let main = ServerBuilder::new("main", "1.0")
            .mount(source, Some("empty"))
            .build();

        assert!(!main.has_tools());
        assert!(!main.has_resources());
        assert!(!main.has_prompts());
    }

    #[test]
    fn builder_full_mount_honors_duplicate_policy_for_all_component_kinds() {
        for behavior in [
            DuplicateBehavior::Warn,
            DuplicateBehavior::Ignore,
            DuplicateBehavior::Replace,
            DuplicateBehavior::Error,
        ] {
            let server = marked_builder("original")
                .on_duplicate(behavior)
                .mount(marked_builder("incoming").build(), None)
                .build();
            assert_marked_server(
                &server,
                if behavior == DuplicateBehavior::Replace {
                    "incoming"
                } else {
                    "original"
                },
            );
        }
    }

    #[test]
    fn builder_partial_mounts_honor_duplicate_policy() {
        for behavior in [
            DuplicateBehavior::Warn,
            DuplicateBehavior::Ignore,
            DuplicateBehavior::Replace,
            DuplicateBehavior::Error,
        ] {
            let replacement_marker = if behavior == DuplicateBehavior::Replace {
                "incoming"
            } else {
                "original"
            };

            let tools = marked_builder("original")
                .on_duplicate(behavior)
                .mount_tools(marked_builder("incoming").build(), None)
                .build();
            assert_eq!(tools.tools()[0].tags, vec![replacement_marker.to_string()]);
            assert_eq!(tools.resources()[0].tags, vec!["original".to_string()]);
            assert_eq!(
                tools.resource_templates()[0].tags,
                vec!["original".to_string()]
            );
            assert_eq!(tools.prompts()[0].tags, vec!["original".to_string()]);

            let resources = marked_builder("original")
                .on_duplicate(behavior)
                .mount_resources(marked_builder("incoming").build(), None)
                .build();
            assert_eq!(resources.tools()[0].tags, vec!["original".to_string()]);
            assert_eq!(
                resources.resources()[0].tags,
                vec![replacement_marker.to_string()]
            );
            assert_eq!(
                resources.resource_templates()[0].tags,
                vec![replacement_marker.to_string()]
            );
            assert_eq!(resources.prompts()[0].tags, vec!["original".to_string()]);

            let prompts = marked_builder("original")
                .on_duplicate(behavior)
                .mount_prompts(marked_builder("incoming").build(), None)
                .build();
            assert_eq!(prompts.tools()[0].tags, vec!["original".to_string()]);
            assert_eq!(prompts.resources()[0].tags, vec!["original".to_string()]);
            assert_eq!(
                prompts.resource_templates()[0].tags,
                vec!["original".to_string()]
            );
            assert_eq!(
                prompts.prompts()[0].tags,
                vec![replacement_marker.to_string()]
            );
        }
    }

    #[test]
    fn builder_full_and_partial_mounts_reject_invalid_prefixes() {
        let full = marked_builder("original")
            .on_duplicate(DuplicateBehavior::Replace)
            .mount(marked_builder("incoming").build(), Some("peer/secret"))
            .build();
        assert_marked_server(&full, "original");

        let tools = marked_builder("original")
            .on_duplicate(DuplicateBehavior::Replace)
            .mount_tools(marked_builder("incoming").build(), Some("peer/secret"))
            .build();
        assert_marked_server(&tools, "original");

        let resources = marked_builder("original")
            .on_duplicate(DuplicateBehavior::Replace)
            .mount_resources(marked_builder("incoming").build(), Some("peer/secret"))
            .build();
        assert_marked_server(&resources, "original");

        let prompts = marked_builder("original")
            .on_duplicate(DuplicateBehavior::Replace)
            .mount_prompts(marked_builder("incoming").build(), Some("peer/secret"))
            .build();
        assert_marked_server(&prompts, "original");
    }

    // ── Proxy registration ─────────────────────────────────────────

    #[test]
    fn builder_proxy_with_catalog() {
        use crate::proxy::{ProxyCatalog, ProxyClient};

        struct DummyBackend;
        impl crate::proxy::ProxyBackend for DummyBackend {
            fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
                Ok(vec![])
            }
            fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
                Ok(vec![])
            }
            fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
                Ok(vec![])
            }
            fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
                Ok(vec![])
            }
            fn call_tool(&mut self, _: &str, _: serde_json::Value) -> McpResult<Vec<Content>> {
                Ok(vec![])
            }
            fn call_tool_with_progress(
                &mut self,
                _: &str,
                _: serde_json::Value,
                _: crate::proxy::ProgressCallback<'_>,
            ) -> McpResult<Vec<Content>> {
                Ok(vec![])
            }
            fn read_resource(&mut self, _: &str) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![])
            }
            fn get_prompt(
                &mut self,
                _: &str,
                _: std::collections::HashMap<String, String>,
            ) -> McpResult<Vec<fastmcp_protocol::PromptMessage>> {
                Ok(vec![])
            }
        }

        let client = ProxyClient::from_backend(DummyBackend);
        let catalog = ProxyCatalog {
            tools: vec![Tool {
                name: "proxy-tool".to_string(),
                description: None,
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }],
            ..ProxyCatalog::default()
        };

        let server = ServerBuilder::new("srv", "1.0")
            .proxy(client, catalog)
            .build();
        assert!(server.has_tools());
    }

    #[test]
    fn builder_proxy_honors_duplicate_policy_for_every_component_kind() {
        for behavior in [
            DuplicateBehavior::Warn,
            DuplicateBehavior::Ignore,
            DuplicateBehavior::Error,
        ] {
            let server = ServerBuilder::new("srv", "1.0")
                .on_duplicate(behavior)
                .tool(TestTool)
                .resource(TestResource)
                .prompt(TestPrompt)
                .proxy(
                    ProxyClient::from_backend(DuplicatePolicyProxyBackend),
                    duplicate_policy_proxy_catalog(),
                )
                .build();
            let router = server.into_router();

            assert_eq!(
                router.tools()[0].description.as_deref(),
                Some("a test tool")
            );
            assert_eq!(router.resources()[0].name, "test_res");
            assert_eq!(router.prompts()[0].description, None);
        }

        let replaced = ServerBuilder::new("srv", "1.0")
            .on_duplicate(DuplicateBehavior::Replace)
            .tool(TestTool)
            .resource(TestResource)
            .prompt(TestPrompt)
            .proxy(
                ProxyClient::from_backend(DuplicatePolicyProxyBackend),
                duplicate_policy_proxy_catalog(),
            )
            .build()
            .into_router();

        assert_eq!(
            replaced.tools()[0].description.as_deref(),
            Some("proxied tool")
        );
        assert_eq!(replaced.resources()[0].name, "proxied resource");
        assert_eq!(
            replaced.prompts()[0].description.as_deref(),
            Some("proxied prompt")
        );
    }

    #[test]
    fn as_proxy_raw_propagates_duplicate_registration_errors() {
        let result = ServerBuilder::new("srv", "1.0")
            .on_duplicate(DuplicateBehavior::Error)
            .tool(TestTool)
            .as_proxy_raw_with_proxy_client(ProxyClient::from_backend(DuplicatePolicyProxyBackend));

        let error = match result {
            Ok(_) => panic!("raw proxy registration unexpectedly accepted a duplicate tool"),
            Err(error) => error,
        };
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidRequest);
        assert!(error.message.starts_with("Tool already exists"));
    }

    // ── DEFAULT_REQUEST_TIMEOUT_SECS constant ──────────────────────

    #[test]
    fn default_request_timeout_constant() {
        assert_eq!(DEFAULT_REQUEST_TIMEOUT_SECS, 30);
    }

    // ── mask_error_details toggling ────────────────────────────────

    #[test]
    fn builder_mask_error_details_toggle() {
        let builder = ServerBuilder::new("srv", "1.0")
            .mask_error_details(true)
            .mask_error_details(false);
        assert!(!builder.is_error_masking_enabled());
    }

    // ── strict_input_validation toggling ────────────────────────────

    #[test]
    fn builder_strict_validation_toggle() {
        let builder = ServerBuilder::new("srv", "1.0")
            .strict_input_validation(true)
            .strict_input_validation(false);
        assert!(!builder.is_strict_input_validation_enabled());
    }

    // ── Task manager ──────────────────────────────────────────────────

    #[test]
    fn builder_with_task_manager_retains_manager_without_advertising_capability() {
        use crate::tasks::TaskManager;
        let tm = TaskManager::new().into_shared();
        let server = ServerBuilder::new("srv", "1.0")
            .with_task_manager(tm)
            .build();
        assert!(server.task_manager().is_some());
        assert!(server.capabilities().tasks.is_none());
    }

    #[test]
    fn builder_with_notifying_task_manager_keeps_capability_quarantined() {
        use crate::tasks::TaskManager;
        let tm = TaskManager::with_list_changed_notifications().into_shared();
        let server = ServerBuilder::new("srv", "1.0")
            .with_task_manager(tm)
            .build();
        assert!(server.task_manager().is_some());
        assert!(server.capabilities().tasks.is_none());
    }

    #[test]
    fn builder_with_non_notifying_task_manager_keeps_capability_quarantined() {
        use crate::tasks::TaskManager;
        let tm = TaskManager::new().into_shared();
        let server = ServerBuilder::new("srv", "1.0")
            .with_task_manager(tm)
            .build();
        assert!(server.task_manager().is_some());
        assert!(server.capabilities().tasks.is_none());
    }

    // ── Duplicate behavior for resources and prompts ─────────────────

    struct DupResource(&'static str);
    impl crate::ResourceHandler for DupResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: format!("file:///{}", self.0),
                name: self.0.to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }
        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![])
        }
    }

    struct DupPrompt(&'static str);
    impl crate::PromptHandler for DupPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: self.0.to_string(),
                description: None,
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }
        }
        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<fastmcp_protocol::PromptMessage>> {
            Ok(vec![])
        }
    }

    #[test]
    fn builder_on_duplicate_error_resource_logs_but_continues() {
        let server = ServerBuilder::new("srv", "1.0")
            .on_duplicate(DuplicateBehavior::Error)
            .resource(DupResource("dup"))
            .resource(DupResource("dup"))
            .build();
        assert!(server.has_resources());
    }

    #[test]
    fn builder_on_duplicate_error_prompt_logs_but_continues() {
        let server = ServerBuilder::new("srv", "1.0")
            .on_duplicate(DuplicateBehavior::Error)
            .prompt(DupPrompt("dup"))
            .prompt(DupPrompt("dup"))
            .build();
        assert!(server.has_prompts());
    }

    // ── Proxy with resources and prompts ─────────────────────────────

    #[test]
    fn builder_proxy_with_resources_and_prompts() {
        use crate::proxy::{ProxyCatalog, ProxyClient};

        struct DummyBackend2;
        impl crate::proxy::ProxyBackend for DummyBackend2 {
            fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
                Ok(vec![])
            }
            fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
                Ok(vec![])
            }
            fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
                Ok(vec![])
            }
            fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
                Ok(vec![])
            }
            fn call_tool(&mut self, _: &str, _: serde_json::Value) -> McpResult<Vec<Content>> {
                Ok(vec![])
            }
            fn call_tool_with_progress(
                &mut self,
                _: &str,
                _: serde_json::Value,
                _: crate::proxy::ProgressCallback<'_>,
            ) -> McpResult<Vec<Content>> {
                Ok(vec![])
            }
            fn read_resource(&mut self, _: &str) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![])
            }
            fn get_prompt(
                &mut self,
                _: &str,
                _: std::collections::HashMap<String, String>,
            ) -> McpResult<Vec<fastmcp_protocol::PromptMessage>> {
                Ok(vec![])
            }
        }

        let client = ProxyClient::from_backend(DummyBackend2);
        let catalog = ProxyCatalog {
            resources: vec![Resource {
                uri: "file:///proxy-res".to_string(),
                name: "proxy-res".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }],
            prompts: vec![Prompt {
                name: "proxy-prompt".to_string(),
                description: None,
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }],
            resource_templates: vec![ResourceTemplate {
                uri_template: "db://{table}".to_string(),
                name: "db".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }],
            ..ProxyCatalog::default()
        };

        let server = ServerBuilder::new("srv", "1.0")
            .proxy(client, catalog)
            .build();
        assert!(server.has_resources());
        assert!(server.has_prompts());
        assert!(!server.has_tools());
    }

    // ── Build propagates strict validation to router ─────────────────

    #[test]
    fn build_propagates_strict_validation_to_router() {
        let server = ServerBuilder::new("srv", "1.0")
            .strict_input_validation(true)
            .build();
        let router = server.into_router();
        assert!(router.strict_input_validation());
    }

    #[test]
    fn build_propagates_strict_validation_false_to_router() {
        let server = ServerBuilder::new("srv", "1.0")
            .strict_input_validation(false)
            .build();
        let router = server.into_router();
        assert!(!router.strict_input_validation());
    }

    // ── log_level_filter with Off ────────────────────────────────────

    #[test]
    fn builder_log_level_filter_off() {
        let builder = ServerBuilder::new("srv", "1.0").log_level_filter(LevelFilter::Off);
        assert_eq!(builder.logging.level, LevelFilter::Off);
        assert_eq!(builder.console_config.log_level, LevelFilter::Off);
    }

    // ── mount does not update capabilities when nothing mounted ──────

    #[test]
    fn builder_mount_no_op_leaves_capabilities_unchanged() {
        let source = ServerBuilder::new("sub", "1.0").build();
        let main = ServerBuilder::new("main", "1.0")
            .mount(source, Some("ns"))
            .build();
        assert!(!main.has_tools());
        assert!(!main.has_resources());
        assert!(!main.has_prompts());
    }
}
