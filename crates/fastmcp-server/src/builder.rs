//! Server builder for configuring MCP servers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use fastmcp_console::config::{BannerStyle, ConsoleConfig, TrafficVerbosity};
use fastmcp_console::stats::ServerStats;
use fastmcp_protocol::{
    LoggingCapability, PromptsCapability, ResourceTemplate, ResourcesCapability,
    ServerCapabilities, ServerInfo, ToolsCapability,
};
use log::{Level, LevelFilter};

use crate::{
    AuthProvider, LifespanHooks, LoggingConfig, PromptHandler, ResourceHandler, Router, Server,
    ToolHandler,
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
    /// Logging configuration.
    logging: LoggingConfig,
    /// Console configuration for rich output.
    console_config: ConsoleConfig,
    /// Lifecycle hooks for startup/shutdown.
    lifespan: LifespanHooks,
    /// Optional authentication provider.
    auth_provider: Option<Arc<dyn AuthProvider>>,
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
            logging: LoggingConfig::from_env(),
            console_config: ConsoleConfig::from_env(),
            lifespan: LifespanHooks::default(),
            auth_provider: None,
        }
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

    /// Registers a tool handler.
    #[must_use]
    pub fn tool<H: ToolHandler + 'static>(mut self, handler: H) -> Self {
        self.router.add_tool(handler);
        self.capabilities.tools = Some(ToolsCapability::default());
        self
    }

    /// Registers a resource handler.
    #[must_use]
    pub fn resource<H: ResourceHandler + 'static>(mut self, handler: H) -> Self {
        self.router.add_resource(handler);
        self.capabilities.resources = Some(ResourcesCapability::default());
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
    #[must_use]
    pub fn prompt<H: PromptHandler + 'static>(mut self, handler: H) -> Self {
        self.router.add_prompt(handler);
        self.capabilities.prompts = Some(PromptsCapability::default());
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
            logging: self.logging,
            console_config: self.console_config,
            lifespan: Mutex::new(Some(self.lifespan)),
            auth_provider: self.auth_provider,
            active_requests: Mutex::new(HashMap::new()),
        }
    }
}
