//! Server builder for configuring MCP servers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use fastmcp_console::config::{BannerStyle, ConsoleConfig, TrafficVerbosity};
use fastmcp_console::stats::ServerStats;
use fastmcp_protocol::{
    LoggingCapability, PromptsCapability, ResourceTemplate, ResourcesCapability,
    ServerCapabilities, ServerInfo, TasksCapability, ToolsCapability,
};
use log::{Level, LevelFilter};

use crate::proxy::{ProxyPromptHandler, ProxyResourceHandler, ProxyToolHandler};
use crate::tasks::SharedTaskManager;
use crate::{
    AuthProvider, DuplicateBehavior, LifespanHooks, LoggingConfig, PromptHandler, ProxyCatalog,
    ProxyClient, ResourceHandler, Router, Server, ToolHandler,
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
    /// Optional task manager for background tasks (Docket/SEP-1686).
    task_manager: Option<SharedTaskManager>,
    /// Behavior when registering duplicate component names.
    on_duplicate: DuplicateBehavior,
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
            logging: LoggingConfig::from_env(),
            console_config: ConsoleConfig::from_env(),
            lifespan: LifespanHooks::default(),
            auth_provider: None,
            middleware: Vec::new(),
            task_manager: None,
            on_duplicate: DuplicateBehavior::default(),
        }
    }

    /// Sets the behavior when registering duplicate component names.
    ///
    /// Controls what happens when a tool, resource, or prompt is registered
    /// with a name that already exists:
    ///
    /// - [`DuplicateBehavior::Error`]: Fail with an error
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
    ///     .tool(handler2)  // Fails if name conflicts
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
    /// Set to 0 to disable timeout enforcement.
    /// Default is 30 seconds.
    #[must_use]
    pub fn request_timeout(mut self, secs: u64) -> Self {
        self.request_timeout_secs = secs;
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
            log::error!(target: "fastmcp::builder", "Failed to register tool: {}", e);
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
            log::error!(target: "fastmcp::builder", "Failed to register resource: {}", e);
        } else {
            self.capabilities.resources = Some(ResourcesCapability::default());
        }
        self
    }

    /// Registers a resource template.
    #[must_use]
    pub fn resource_template(mut self, template: ResourceTemplate) -> Self {
        self.router.add_resource_template(template);
        self.capabilities.resources = Some(ResourcesCapability::default());
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
            log::error!(target: "fastmcp::builder", "Failed to register prompt: {}", e);
        } else {
            self.capabilities.prompts = Some(PromptsCapability::default());
        }
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
            self.router
                .add_tool(ProxyToolHandler::new(tool, client.clone()));
        }

        for resource in catalog.resources {
            self.router
                .add_resource(ProxyResourceHandler::new(resource, client.clone()));
        }

        for template in catalog.resource_templates {
            self.router
                .add_resource(ProxyResourceHandler::from_template(
                    template,
                    client.clone(),
                ));
        }

        for prompt in catalog.prompts {
            self.router
                .add_prompt(ProxyPromptHandler::new(prompt, client.clone()));
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
    /// Returns an error if the catalog fetch fails.
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
                target: "fastmcp::proxy",
                "Registering proxied tool: {}/{}", prefix, tool.name
            );
            self.router.add_tool(ProxyToolHandler::with_prefix(
                tool,
                prefix,
                proxy_client.clone(),
            ));
        }

        // Register resources with prefix
        for resource in catalog.resources {
            log::debug!(
                target: "fastmcp::proxy",
                "Registering proxied resource: {}/{}", prefix, resource.uri
            );
            self.router.add_resource(ProxyResourceHandler::with_prefix(
                resource,
                prefix,
                proxy_client.clone(),
            ));
        }

        // Register resource templates with prefix
        for template in catalog.resource_templates {
            log::debug!(
                target: "fastmcp::proxy",
                "Registering proxied template: {}/{}", prefix, template.uri_template
            );
            self.router
                .add_resource(ProxyResourceHandler::from_template_with_prefix(
                    template,
                    prefix,
                    proxy_client.clone(),
                ));
        }

        // Register prompts with prefix
        for prompt in catalog.prompts {
            log::debug!(
                target: "fastmcp::proxy",
                "Registering proxied prompt: {}/{}", prefix, prompt.name
            );
            self.router.add_prompt(ProxyPromptHandler::with_prefix(
                prompt,
                prefix,
                proxy_client.clone(),
            ));
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
            target: "fastmcp::proxy",
            "Proxied {} tools, {} resources, {} templates, {} prompts with prefix '{}'",
            tool_count,
            resource_count,
            template_count,
            prompt_count,
            prefix
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
    pub fn as_proxy_raw(
        self,
        client: fastmcp_client::Client,
    ) -> Result<Self, fastmcp_core::McpError> {
        let proxy_client = ProxyClient::from_client(client);
        let catalog = proxy_client.catalog()?;
        Ok(self.proxy(proxy_client, catalog))
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
    #[must_use]
    pub fn mount(mut self, server: crate::Server, prefix: Option<&str>) -> Self {
        let has_tools = server.has_tools();
        let has_resources = server.has_resources();
        let has_prompts = server.has_prompts();

        let source_router = server.into_router();
        let result = self.router.mount(source_router, prefix);

        // Log warnings if any
        for warning in &result.warnings {
            log::warn!(target: "fastmcp::mount", "{}", warning);
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
    #[must_use]
    pub fn mount_tools(mut self, server: crate::Server, prefix: Option<&str>) -> Self {
        let source_router = server.into_router();
        let result = self.router.mount_tools(source_router, prefix);

        // Log warnings if any
        for warning in &result.warnings {
            log::warn!(target: "fastmcp::mount", "{}", warning);
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
    #[must_use]
    pub fn mount_resources(mut self, server: crate::Server, prefix: Option<&str>) -> Self {
        let source_router = server.into_router();
        let result = self.router.mount_resources(source_router, prefix);

        // Log warnings if any
        for warning in &result.warnings {
            log::warn!(target: "fastmcp::mount", "{}", warning);
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
    #[must_use]
    pub fn mount_prompts(mut self, server: crate::Server, prefix: Option<&str>) -> Self {
        let source_router = server.into_router();
        let result = self.router.mount_prompts(source_router, prefix);

        // Log warnings if any
        for warning in &result.warnings {
            log::warn!(target: "fastmcp::mount", "{}", warning);
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
        self.logging.level = level;
        self
    }

    /// Sets the log level from a filter.
    #[must_use]
    pub fn log_level_filter(mut self, filter: LevelFilter) -> Self {
        self.logging.level = filter.to_level().unwrap_or(Level::Info);
        self
    }

    /// Sets whether to show timestamps in logs.
    ///
    /// Default is `true`.
    #[must_use]
    pub fn log_timestamps(mut self, show: bool) -> Self {
        self.logging.timestamps = show;
        self
    }

    /// Sets whether to show target/module paths in logs.
    ///
    /// Default is `true`.
    #[must_use]
    pub fn log_targets(mut self, show: bool) -> Self {
        self.logging.targets = show;
        self
    }

    /// Sets the full logging configuration.
    #[must_use]
    pub fn logging(mut self, config: LoggingConfig) -> Self {
        self.logging = config;
        self
    }

    // ─────────────────────────────────────────────────
    // Console Configuration
    // ─────────────────────────────────────────────────

    /// Sets the complete console configuration.
    ///
    /// This provides full control over all console output settings including
    /// banner, traffic logging, periodic stats, and error formatting.
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
    /// - `Headers`: Include metadata/headers
    /// - `Full`: Full request/response bodies
    #[must_use]
    pub fn with_traffic_logging(mut self, verbosity: TrafficVerbosity) -> Self {
        self.console_config = self.console_config.with_traffic(verbosity);
        self
    }

    /// Enables periodic statistics display.
    ///
    /// When enabled, statistics will be printed to stderr at the specified
    /// interval. Requires stats collection to be enabled (the default).
    #[must_use]
    pub fn with_periodic_stats(mut self, interval_secs: u64) -> Self {
        self.console_config = self.console_config.with_periodic_stats(interval_secs);
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

    /// Sets a task manager for background tasks (Docket/SEP-1686).
    ///
    /// When a task manager is configured, the server will advertise
    /// task capabilities and handle task-related methods.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use fastmcp_server::TaskManager;
    ///
    /// let task_manager = TaskManager::new();
    /// Server::new("demo", "1.0.0")
    ///     .with_task_manager(task_manager.into_shared())
    ///     .run_stdio();
    /// ```
    #[must_use]
    pub fn with_task_manager(mut self, task_manager: SharedTaskManager) -> Self {
        self.task_manager = Some(task_manager);
        let mut capability = TasksCapability::default();
        if let Some(manager) = &self.task_manager {
            capability.list_changed = manager.has_list_changed_notifications();
        }
        self.capabilities.tasks = Some(capability);
        self
    }

    /// Builds the server.
    #[must_use]
    pub fn build(self) -> Server {
        Server {
            info: self.info,
            capabilities: self.capabilities,
            router: self.router,
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
            lifespan: Mutex::new(Some(self.lifespan)),
            auth_provider: self.auth_provider,
            middleware: Arc::new(self.middleware),
            active_requests: Mutex::new(HashMap::new()),
            task_manager: self.task_manager,
            pending_requests: std::sync::Arc::new(crate::bidirectional::PendingRequests::new()),
        }
    }
}
