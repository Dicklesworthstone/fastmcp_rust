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
    AuthProvider, DuplicateBehavior, HttpServerConfig, LifespanHooks, LoggingConfig, PromptHandler,
    ProxyCatalog, ProxyClient, ResourceHandler, Router, Server, ToolHandler,
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
    /// Whether to use strict input validation (reject extra properties).
    strict_input_validation: bool,
    /// HTTP server configuration (paths, max_connections, CORS).
    http_config: HttpServerConfig,
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
            strict_input_validation: false,
            http_config: HttpServerConfig::default(),
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

    /// Sets the HTTP server configuration (paths, max connections, CORS).
    ///
    /// This configuration is used by [`Server::run_http`](crate::Server::run_http)
    /// and related HTTP methods.
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
            log::error!(target: "fastmcp_rust::builder", "Failed to register tool: {}", e);
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
            log::error!(target: "fastmcp_rust::builder", "Failed to register resource: {}", e);
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
            log::error!(target: "fastmcp_rust::builder", "Failed to register prompt: {}", e);
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
                target: "fastmcp_rust::proxy",
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
                target: "fastmcp_rust::proxy",
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
                target: "fastmcp_rust::proxy",
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
                target: "fastmcp_rust::proxy",
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
            target: "fastmcp_rust::proxy",
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
            log::warn!(target: "fastmcp_rust::mount", "{}", warning);
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
            log::warn!(target: "fastmcp_rust::mount", "{}", warning);
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
            log::warn!(target: "fastmcp_rust::mount", "{}", warning);
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
            log::warn!(target: "fastmcp_rust::mount", "{}", warning);
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
            http_config: self.http_config,
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
    fn builder_default_error_masking_disabled() {
        let builder = ServerBuilder::new("srv", "1.0");
        assert!(!builder.is_error_masking_enabled());
    }

    #[test]
    fn builder_default_strict_validation_disabled() {
        let builder = ServerBuilder::new("srv", "1.0");
        assert!(!builder.is_strict_input_validation_enabled());
    }

    // ── Fluent API setters ───────────────────────────────────────────

    #[test]
    fn builder_request_timeout() {
        let builder = ServerBuilder::new("srv", "1.0").request_timeout(60);
        assert_eq!(builder.request_timeout_secs(), 60);
    }

    #[test]
    fn builder_request_timeout_zero_disables() {
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
        let _builder = ServerBuilder::new("srv", "1.0").log_level(Level::Debug);
    }

    #[test]
    fn builder_log_level_filter() {
        let _builder = ServerBuilder::new("srv", "1.0").log_level_filter(LevelFilter::Warn);
    }

    #[test]
    fn builder_log_timestamps_and_targets() {
        let _builder = ServerBuilder::new("srv", "1.0")
            .log_timestamps(false)
            .log_targets(false);
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
        let config = ConsoleConfig::new().with_banner(BannerStyle::None);
        let builder = ServerBuilder::new("srv", "1.0").with_console_config(config);
        assert_eq!(builder.console_config().banner_style, BannerStyle::None);
    }

    #[test]
    fn builder_with_traffic_logging() {
        let builder = ServerBuilder::new("srv", "1.0").with_traffic_logging(TrafficVerbosity::Full);
        let config = builder.console_config();
        assert_eq!(config.traffic_verbosity, TrafficVerbosity::Full);
    }

    #[test]
    fn builder_with_periodic_stats() {
        let builder = ServerBuilder::new("srv", "1.0").with_periodic_stats(30);
        let config = builder.console_config();
        assert_eq!(config.stats_interval_secs, 30);
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
            level: Level::Trace,
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
    fn builder_with_task_manager_enables_capability() {
        use crate::tasks::TaskManager;
        let tm = TaskManager::new().into_shared();
        let server = ServerBuilder::new("srv", "1.0")
            .with_task_manager(tm)
            .build();
        assert!(server.capabilities().tasks.is_some());
    }

    #[test]
    fn builder_with_task_manager_list_changed_true() {
        use crate::tasks::TaskManager;
        let tm = TaskManager::with_list_changed_notifications().into_shared();
        let server = ServerBuilder::new("srv", "1.0")
            .with_task_manager(tm)
            .build();
        let cap = server.capabilities().tasks.as_ref().unwrap();
        assert!(cap.list_changed);
    }

    #[test]
    fn builder_with_task_manager_list_changed_false() {
        use crate::tasks::TaskManager;
        let tm = TaskManager::new().into_shared();
        let server = ServerBuilder::new("srv", "1.0")
            .with_task_manager(tm)
            .build();
        let cap = server.capabilities().tasks.as_ref().unwrap();
        assert!(!cap.list_changed);
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

    // ── log_level_filter with Off defaults to Info ───────────────────

    #[test]
    fn builder_log_level_filter_off() {
        let _builder = ServerBuilder::new("srv", "1.0").log_level_filter(LevelFilter::Off);
        // LevelFilter::Off.to_level() is None, so logging.level defaults to Info
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
