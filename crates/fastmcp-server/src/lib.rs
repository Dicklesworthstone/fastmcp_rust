//! MCP server implementation for FastMCP.
//!
//! This crate provides the server-side implementation:
//! - Server builder pattern
//! - Tool, resource, and prompt registration
//! - Request routing and dispatching
//! - Session management
//!
//! # Example
//!
//! ```ignore
//! use fastmcp::prelude::*;
//!
//! #[tool]
//! async fn greet(ctx: &McpContext, name: String) -> String {
//!     format!("Hello, {name}!")
//! }
//!
//! fn main() {
//!     Server::new("my-server", "1.0.0")
//!         .tool(greet)
//!         .run_stdio();
//! }
//! ```

#![forbid(unsafe_code)]
#![allow(dead_code)]

mod auth;
mod builder;
mod handler;
mod router;
mod session;
mod tasks;

#[cfg(test)]
mod tests;

pub use builder::ServerBuilder;
pub use fastmcp_console::config::{BannerStyle, ConsoleConfig, TrafficVerbosity};
pub use fastmcp_console::stats::{ServerStats, StatsSnapshot};
pub use auth::{AllowAllAuthProvider, AuthProvider, AuthRequest};
pub use handler::{
    BoxFuture, ProgressNotificationSender, PromptHandler, ResourceHandler, ToolHandler,
    create_context_with_progress,
};
pub use router::{NotificationSender, Router};
pub use session::Session;
pub use tasks::{SharedTaskManager, TaskManager};

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use asupersync::{Budget, CancelKind, Cx};
use fastmcp_console::logging::RichLoggerBuilder;
use fastmcp_console::{banner::StartupBanner, console};
use fastmcp_core::logging::{debug, error, info, targets};
use fastmcp_core::{AuthContext, McpContext, McpError, McpErrorCode};
use fastmcp_protocol::{
    CallToolParams, CancelledParams, GetPromptParams, InitializeParams, JsonRpcError,
    JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, ListPromptsParams,
    ListResourceTemplatesParams, ListResourcesParams, ListToolsParams, LogLevel, Prompt,
    ReadResourceParams, RequestId, Resource, ResourceTemplate, ServerCapabilities, ServerInfo,
    SetLogLevelParams, SubscribeResourceParams, Tool, UnsubscribeResourceParams,
};
use fastmcp_transport::sse::SseServerTransport;
use fastmcp_transport::websocket::WsTransport;
use fastmcp_transport::{Codec, StdioTransport, Transport, TransportError};
use log::{Level, LevelFilter};

/// Type alias for startup hook function.
pub type StartupHook =
    Box<dyn FnOnce() -> Result<(), Box<dyn std::error::Error + Send + Sync>> + Send>;

/// Type alias for shutdown hook function.
pub type ShutdownHook = Box<dyn FnOnce() + Send>;

/// Lifecycle hooks for server startup and shutdown.
///
/// These hooks allow custom initialization and cleanup logic to run
/// at well-defined points in the server lifecycle:
///
/// - `on_startup`: Called before the server starts accepting connections
/// - `on_shutdown`: Called when the server is shutting down
///
/// # Example
///
/// ```ignore
/// use fastmcp::prelude::*;
///
/// Server::new("demo", "1.0.0")
///     .on_startup(|| {
///         println!("Initializing...");
///         // Initialize database, caches, etc.
///         Ok(())
///     })
///     .on_shutdown(|| {
///         println!("Cleaning up...");
///         // Close connections, flush buffers, etc.
///     })
///     .run_stdio();
/// ```
#[derive(Default)]
pub struct LifespanHooks {
    /// Hook called before the server starts accepting connections.
    pub on_startup: Option<StartupHook>,
    /// Hook called when the server is shutting down.
    pub on_shutdown: Option<ShutdownHook>,
}

impl LifespanHooks {
    /// Creates empty lifecycle hooks.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Logging configuration for the server.
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Minimum log level (default: INFO).
    pub level: Level,
    /// Show timestamps in logs (default: true).
    pub timestamps: bool,
    /// Show module targets in logs (default: true).
    pub targets: bool,
    /// Show file:line in logs (default: false).
    pub file_line: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: Level::Info,
            timestamps: true,
            targets: true,
            file_line: false,
        }
    }
}

impl LoggingConfig {
    /// Create logging config from environment variables.
    ///
    /// Respects:
    /// - `FASTMCP_LOG`: Log level (error, warn, info, debug, trace)
    /// - `FASTMCP_LOG_TIMESTAMPS`: Show timestamps (0/false to disable)
    /// - `FASTMCP_LOG_TARGETS`: Show targets (0/false to disable)
    /// - `FASTMCP_LOG_FILE_LINE`: Show file:line (1/true to enable)
    #[must_use]
    pub fn from_env() -> Self {
        let level = std::env::var("FASTMCP_LOG")
            .ok()
            .and_then(|s| match s.to_lowercase().as_str() {
                "error" => Some(Level::Error),
                "warn" | "warning" => Some(Level::Warn),
                "info" => Some(Level::Info),
                "debug" => Some(Level::Debug),
                "trace" => Some(Level::Trace),
                _ => None,
            })
            .unwrap_or(Level::Info);

        let timestamps = std::env::var("FASTMCP_LOG_TIMESTAMPS")
            .map(|s| !matches!(s.to_lowercase().as_str(), "0" | "false" | "no"))
            .unwrap_or(true);

        let targets = std::env::var("FASTMCP_LOG_TARGETS")
            .map(|s| !matches!(s.to_lowercase().as_str(), "0" | "false" | "no"))
            .unwrap_or(true);

        let file_line = std::env::var("FASTMCP_LOG_FILE_LINE")
            .map(|s| matches!(s.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

        Self {
            level,
            timestamps,
            targets,
            file_line,
        }
    }
}

/// An MCP server instance.
///
/// Servers are built using [`ServerBuilder`] and can run on various
/// transports (stdio, SSE, WebSocket).
pub struct Server {
    info: ServerInfo,
    capabilities: ServerCapabilities,
    router: Router,
    instructions: Option<String>,
    /// Request timeout in seconds (0 = no timeout).
    request_timeout_secs: u64,
    /// Runtime statistics collector (None = disabled).
    stats: Option<ServerStats>,
    /// Logging configuration.
    logging: LoggingConfig,
    /// Console configuration for rich output.
    console_config: ConsoleConfig,
    /// Lifecycle hooks (wrapped in Option so they can be taken once).
    lifespan: Mutex<Option<LifespanHooks>>,
    /// Optional authentication provider.
    auth_provider: Option<Arc<dyn AuthProvider>>,
    /// Active requests by JSON-RPC request ID.
    active_requests: Mutex<HashMap<RequestId, Cx>>,
}

impl Server {
    /// Creates a new server builder.
    #[must_use]
    #[allow(clippy::new_ret_no_self)]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> ServerBuilder {
        ServerBuilder::new(name, version)
    }

    /// Returns the server info.
    #[must_use]
    pub fn info(&self) -> &ServerInfo {
        &self.info
    }

    /// Returns the server capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &ServerCapabilities {
        &self.capabilities
    }

    /// Lists all registered tools.
    #[must_use]
    pub fn tools(&self) -> Vec<Tool> {
        self.router.tools()
    }

    /// Lists all registered resources.
    #[must_use]
    pub fn resources(&self) -> Vec<Resource> {
        self.router.resources()
    }

    /// Lists all registered resource templates.
    #[must_use]
    pub fn resource_templates(&self) -> Vec<ResourceTemplate> {
        self.router.resource_templates()
    }

    /// Lists all registered prompts.
    #[must_use]
    pub fn prompts(&self) -> Vec<Prompt> {
        self.router.prompts()
    }

    /// Returns a point-in-time snapshot of server statistics.
    ///
    /// Returns `None` if statistics collection is disabled.
    #[must_use]
    pub fn stats(&self) -> Option<StatsSnapshot> {
        self.stats.as_ref().map(ServerStats::snapshot)
    }

    /// Returns the raw statistics collector.
    ///
    /// Useful for advanced scenarios where you need direct access.
    /// Returns `None` if statistics collection is disabled.
    #[must_use]
    pub fn stats_collector(&self) -> Option<&ServerStats> {
        self.stats.as_ref()
    }

    /// Renders a stats panel to stderr, if stats are enabled.
    pub fn display_stats(&self) {
        let Some(stats) = self.stats.as_ref() else {
            return;
        };

        let snapshot = stats.snapshot();
        let renderer = fastmcp_console::stats::StatsRenderer::detect();
        renderer.render_panel(&snapshot, console());
    }

    /// Returns the console configuration.
    #[must_use]
    pub fn console_config(&self) -> &ConsoleConfig {
        &self.console_config
    }

    /// Renders the startup banner based on console configuration.
    fn render_startup_banner(&self) {
        let render = || {
            let mut banner = StartupBanner::new(&self.info.name, &self.info.version)
                .tools(self.router.tools_count())
                .resources(self.router.resources_count())
                .prompts(self.router.prompts_count())
                .transport("stdio");

            if let Some(desc) = self.instructions.as_deref().filter(|d| !d.is_empty()) {
                banner = banner.description(desc);
            }

            // Apply banner style from config
            match self.console_config.banner_style {
                BannerStyle::Full => banner.render(console()),
                BannerStyle::Compact | BannerStyle::Minimal => {
                    // Compact/Minimal: render without the large logo
                    banner.no_logo().render(console());
                }
                BannerStyle::None => {} // Already checked show_banner, but be safe
            }
        };

        if let Err(err) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(render)) {
            eprintln!("Warning: banner rendering failed: {err:?}");
        }
    }

    /// Initializes rich logging based on server configuration.
    ///
    /// This should be called early in the startup sequence, before any
    /// log output is generated. If initialization fails (e.g., logger
    /// already set), a warning is printed to stderr.
    fn init_rich_logging(&self) {
        let result = RichLoggerBuilder::new()
            .level(self.logging.level)
            .with_timestamps(self.logging.timestamps)
            .with_targets(self.logging.targets)
            .with_file_line(self.logging.file_line)
            .init();

        if let Err(e) = result {
            // Logger already initialized (likely by user code), not an error
            eprintln!("Note: Rich logging not initialized (logger already set): {e}");
        }
    }

    /// Runs the server on stdio transport.
    ///
    /// This is the primary way to run MCP servers as subprocesses.
    /// Creates a testing Cx and runs the server loop.
    pub fn run_stdio(self) -> ! {
        // Create a Cx for the server (for now, use testing Cx)
        let cx = Cx::for_testing();
        self.run_stdio_with_cx(&cx)
    }

    /// Runs the server on stdio with a provided Cx.
    ///
    /// This allows integration with a real asupersync runtime.
    pub fn run_stdio_with_cx(self, cx: &Cx) -> ! {
        // Initialize rich logging first, before any log output
        self.init_rich_logging();

        let transport = StdioTransport::stdio();
        let shared = SharedTransport::new(transport);

        // Create a notification sender that writes to a separate stdout handle.
        // This allows progress notifications to be sent during handler execution
        // while the main transport is blocked on recv().
        let notification_sender = create_notification_sender();

        self.run_loop(
            cx,
            |cx| shared.recv(cx),
            |cx, message| shared.send(cx, message),
            notification_sender,
        )
    }

    /// Runs the server on a custom transport with a testing Cx.
    ///
    /// This is useful for SSE/WebSocket integrations where the transport is
    /// provided by an external server framework.
    pub fn run_transport<T>(self, transport: T) -> !
    where
        T: Transport + Send + 'static,
    {
        let cx = Cx::for_testing();
        self.run_transport_with_cx(&cx, transport)
    }

    /// Runs the server on a custom transport with a provided Cx.
    ///
    /// This allows integration with a real asupersync runtime.
    pub fn run_transport_with_cx<T>(self, cx: &Cx, transport: T) -> !
    where
        T: Transport + Send + 'static,
    {
        self.init_rich_logging();

        let shared = SharedTransport::new(transport);
        let notification_sender = create_transport_notification_sender(shared.clone());

        self.run_loop(
            cx,
            |cx| shared.recv(cx),
            |cx, message| shared.send(cx, message),
            notification_sender,
        )
    }

    /// Runs the server using SSE transport with a testing Cx.
    ///
    /// This is a convenience wrapper around [`SseServerTransport`].
    pub fn run_sse<W, R>(self, writer: W, request_source: R, endpoint_url: impl Into<String>) -> !
    where
        W: Write + Send + 'static,
        R: Iterator<Item = JsonRpcRequest> + Send + 'static,
    {
        let transport = SseServerTransport::new(writer, request_source, endpoint_url);
        self.run_transport(transport)
    }

    /// Runs the server using SSE transport with a provided Cx.
    pub fn run_sse_with_cx<W, R>(
        self,
        cx: &Cx,
        writer: W,
        request_source: R,
        endpoint_url: impl Into<String>,
    ) -> !
    where
        W: Write + Send + 'static,
        R: Iterator<Item = JsonRpcRequest> + Send + 'static,
    {
        let transport = SseServerTransport::new(writer, request_source, endpoint_url);
        self.run_transport_with_cx(cx, transport)
    }

    /// Runs the server using WebSocket transport with a testing Cx.
    ///
    /// This is a convenience wrapper around [`WsTransport`].
    pub fn run_websocket<R, W>(self, reader: R, writer: W) -> !
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let transport = WsTransport::new(reader, writer);
        self.run_transport(transport)
    }

    /// Runs the server using WebSocket transport with a provided Cx.
    pub fn run_websocket_with_cx<R, W>(self, cx: &Cx, reader: R, writer: W) -> !
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let transport = WsTransport::new(reader, writer);
        self.run_transport_with_cx(cx, transport)
    }

    /// Runs the startup lifecycle hook, if configured.
    ///
    /// Returns `true` if startup succeeded (or no hook was configured),
    /// `false` if the hook returned an error.
    pub(crate) fn run_startup_hook(&self) -> bool {
        let hook = {
            let mut guard = self.lifespan.lock().expect("lifespan lock poisoned");
            guard.as_mut().and_then(|h| h.on_startup.take())
        };

        if let Some(hook) = hook {
            debug!(target: targets::SERVER, "Running startup hook");
            match hook() {
                Ok(()) => {
                    debug!(target: targets::SERVER, "Startup hook completed successfully");
                    true
                }
                Err(e) => {
                    error!(target: targets::SERVER, "Startup hook failed: {}", e);
                    false
                }
            }
        } else {
            true
        }
    }

    /// Runs the shutdown lifecycle hook, if configured.
    pub(crate) fn run_shutdown_hook(&self) {
        let hook = {
            let mut guard = self.lifespan.lock().expect("lifespan lock poisoned");
            guard.as_mut().and_then(|h| h.on_shutdown.take())
        };

        if let Some(hook) = hook {
            debug!(target: targets::SERVER, "Running shutdown hook");
            hook();
            debug!(target: targets::SERVER, "Shutdown hook completed");
        }
    }

    /// Performs graceful shutdown: runs hook, closes stats, exits.
    fn graceful_shutdown(&self, exit_code: i32) -> ! {
        self.run_shutdown_hook();
        if let Some(ref stats) = self.stats {
            stats.connection_closed();
        }
        std::process::exit(exit_code)
    }

    /// Shared server loop for any transport, using closure-based recv/send.
    fn run_loop<R, S>(
        self,
        cx: &Cx,
        mut recv: R,
        mut send: S,
        notification_sender: NotificationSender,
    ) -> !
    where
        R: FnMut(&Cx) -> Result<JsonRpcMessage, TransportError>,
        S: FnMut(&Cx, &JsonRpcMessage) -> Result<(), TransportError>,
    {
        let mut session = Session::new(self.info.clone(), self.capabilities.clone());

        // Track connection opened
        if let Some(ref stats) = self.stats {
            stats.connection_opened();
        }

        // Render startup banner if enabled (respects both config and legacy env var)
        if self.console_config.show_banner && !banner_suppressed() {
            self.render_startup_banner();
        }

        // Run startup hook
        if !self.run_startup_hook() {
            error!(target: targets::SERVER, "Startup hook failed, exiting");
            self.graceful_shutdown(1);
        }

        // Main request loop
        loop {
            // Check for cancellation
            if cx.is_cancel_requested() {
                info!(target: targets::SERVER, "Cancellation requested, shutting down");
                self.graceful_shutdown(0);
            }

            // Receive next message
            let message = match recv(cx) {
                Ok(msg) => msg,
                Err(TransportError::Closed) => {
                    // Clean shutdown - track connection close
                    self.graceful_shutdown(0);
                }
                Err(TransportError::Cancelled) => {
                    info!(target: targets::SERVER, "Transport cancelled");
                    self.graceful_shutdown(0);
                }
                Err(e) => {
                    error!(target: targets::TRANSPORT, "Transport error: {}", e);
                    continue;
                }
            };

            // Handle the message
            let response_opt = match message {
                JsonRpcMessage::Request(request) => {
                    // Track bytes received (approximate from serialized request size)
                    if let Some(ref stats) = self.stats {
                        // Estimate request size by serializing back to JSON
                        // This is approximate but accurate enough for statistics
                        if let Ok(json) = serde_json::to_string(&request) {
                            stats.add_bytes_received(json.len() as u64 + 1); // +1 for newline
                        }
                    }
                    self.handle_request(cx, &mut session, request, &notification_sender)
                }
                JsonRpcMessage::Response(_) => {
                    // Servers don't expect responses
                    continue;
                }
            };

            if let Some(response) = response_opt {
                // Track bytes sent (approximate from serialized response size)
                if let Some(ref stats) = self.stats {
                    if let Ok(json) = serde_json::to_string(&response) {
                        stats.add_bytes_sent(json.len() as u64 + 1); // +1 for newline
                    }
                }

                // Send response
                if let Err(e) = send(cx, &JsonRpcMessage::Response(response)) {
                    error!(target: targets::TRANSPORT, "Failed to send response: {}", e);
                }
            }
        }
    }

    /// Handles a single JSON-RPC request.
    fn handle_request(
        &self,
        cx: &Cx,
        session: &mut Session,
        request: JsonRpcRequest,
        notification_sender: &NotificationSender,
    ) -> Option<JsonRpcResponse> {
        let id = request.id.clone();
        let method = request.method.clone();
        let is_notification = id.is_none();

        // Start timing for stats
        let start_time = Instant::now();

        // Generate internal request ID for tracing
        let request_id = request_id_to_u64(id.as_ref());

        // Create a budget for this request based on timeout configuration
        let budget = self.create_request_budget();

        // Check if budget is already exhausted (should not happen, but be defensive)
        if budget.is_exhausted() {
            // Record failed request due to exhausted budget
            if let Some(ref stats) = self.stats {
                stats.record_request(&method, start_time.elapsed(), false);
            }
            // If it's a notification, we don't send an error response
            let response_id = id.clone()?;
            return Some(JsonRpcResponse::error(
                Some(response_id),
                JsonRpcError {
                    code: McpErrorCode::RequestCancelled.into(),
                    message: "Request budget exhausted".to_string(),
                    data: None,
                },
            ));
        }

        let request_cx = if is_notification {
            cx.clone()
        } else {
            Cx::for_testing_with_budget(budget)
        };

        let _active_guard = id.clone().map(|request_id| {
            ActiveRequestGuard::new(&self.active_requests, request_id, request_cx.clone())
        });

        // Dispatch based on method, passing the budget and notification sender
        let result = self.dispatch_method(
            &request_cx,
            session,
            &method,
            request.params,
            request_id,
            &budget,
            notification_sender,
        );

        // Record statistics
        let latency = start_time.elapsed();
        if let Some(ref stats) = self.stats {
            match &result {
                Ok(_) => stats.record_request(&method, latency, true),
                Err(e) if e.code == fastmcp_core::McpErrorCode::RequestCancelled => {
                    stats.record_cancelled(&method, latency);
                }
                Err(_) => stats.record_request(&method, latency, false),
            }
        }

        // If it's a notification (no ID), we must not reply
        if is_notification {
            if let Err(e) = result {
                fastmcp_core::logging::error!(
                    target: targets::HANDLER,
                    "Notification '{}' failed: {}",
                    method,
                    e
                );
            }
            return None;
        }

        // For success, we need a non-None id (checked above, so unwrap is safe-ish, but let's be correct)
        // We only reach here if id is Some.
        let response_id = id.clone().unwrap();

        match result {
            Ok(value) => Some(JsonRpcResponse::success(response_id, value)),
            Err(e) => Some(JsonRpcResponse::error(
                id,
                JsonRpcError {
                    code: e.code.into(),
                    message: e.message,
                    data: e.data,
                },
            )),
        }
    }

    /// Creates a budget for a new request based on server configuration.
    fn create_request_budget(&self) -> Budget {
        if self.request_timeout_secs == 0 {
            // No timeout - unlimited budget
            Budget::INFINITE
        } else {
            // Create budget with deadline
            Budget::with_deadline_secs(self.request_timeout_secs)
        }
    }

    /// Dispatches a request to the appropriate handler.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn dispatch_method(
        &self,
        cx: &Cx,
        session: &mut Session,
        method: &str,
        params: Option<serde_json::Value>,
        request_id: u64,
        budget: &Budget,
        notification_sender: &NotificationSender,
    ) -> Result<serde_json::Value, McpError> {
        // Check cancellation before dispatch
        if cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }

        // Check budget before dispatch (for poll-based exhaustion)
        if budget.is_exhausted() {
            return Err(McpError::new(
                McpErrorCode::RequestCancelled,
                "Request budget exhausted",
            ));
        }

        // Check initialization state
        // Per MCP spec, client must send initialize first.
        // We allow "ping" for health checks even before initialization.
        if !session.is_initialized() && method != "initialize" && method != "ping" {
            return Err(McpError::invalid_request(
                "Server not initialized. Client must send 'initialize' first.",
            ));
        }

        if self.should_authenticate(method) {
            let auth_request = AuthRequest {
                method,
                params: params.as_ref(),
                request_id,
            };
            self.authenticate_request(cx, request_id, session, auth_request)?;
        }

        match method {
            "initialize" => {
                let params: InitializeParams = parse_params(params)?;
                let result = self.router.handle_initialize(
                    cx,
                    session,
                    params,
                    self.instructions.as_deref(),
                )?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "initialized" => {
                // Notification, no response needed (but we send empty ok)
                Ok(serde_json::Value::Null)
            }
            "notifications/cancelled" => {
                let params: CancelledParams = parse_params(params)?;
                self.handle_cancelled_notification(params);
                Ok(serde_json::Value::Null)
            }
            "logging/setLevel" => {
                let params: SetLogLevelParams = parse_params(params)?;
                self.handle_set_log_level(params);
                Ok(serde_json::Value::Null)
            }
            "tools/list" => {
                let params: ListToolsParams = parse_params_or_default(params)?;
                let result = self.router.handle_tools_list(cx, params)?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "tools/call" => {
                let params: CallToolParams = parse_params(params)?;
                let result = self.router.handle_tools_call(
                    cx,
                    request_id,
                    params,
                    budget,
                    session.state().clone(),
                    Some(notification_sender),
                )?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "resources/list" => {
                let params: ListResourcesParams = parse_params_or_default(params)?;
                let result = self.router.handle_resources_list(cx, params)?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "resources/templates/list" => {
                let params: ListResourceTemplatesParams = parse_params_or_default(params)?;
                let result = self.router.handle_resource_templates_list(cx, params)?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "resources/read" => {
                let params: ReadResourceParams = parse_params(params)?;
                let result = self.router.handle_resources_read(
                    cx,
                    request_id,
                    &params,
                    budget,
                    session.state().clone(),
                    Some(notification_sender),
                )?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "resources/subscribe" => {
                let params: SubscribeResourceParams = parse_params(params)?;
                if !self.router.resource_exists(&params.uri) {
                    return Err(McpError::resource_not_found(&params.uri));
                }
                session.subscribe_resource(params.uri);
                Ok(serde_json::json!({}))
            }
            "resources/unsubscribe" => {
                let params: UnsubscribeResourceParams = parse_params(params)?;
                session.unsubscribe_resource(&params.uri);
                Ok(serde_json::json!({}))
            }
            "prompts/list" => {
                let params: ListPromptsParams = parse_params_or_default(params)?;
                let result = self.router.handle_prompts_list(cx, params)?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "prompts/get" => {
                let params: GetPromptParams = parse_params(params)?;
                let result = self.router.handle_prompts_get(
                    cx,
                    request_id,
                    params,
                    budget,
                    session.state().clone(),
                    Some(notification_sender),
                )?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "ping" => {
                // Simple ping-pong for health checks
                Ok(serde_json::json!({}))
            }
            _ => Err(McpError::method_not_found(method)),
        }
    }

    fn should_authenticate(&self, method: &str) -> bool {
        !matches!(
            method,
            "initialize" | "initialized" | "notifications/cancelled" | "ping"
        )
    }

    fn authenticate_request(
        &self,
        cx: &Cx,
        request_id: u64,
        session: &Session,
        request: AuthRequest<'_>,
    ) -> Result<AuthContext, McpError> {
        let Some(provider) = &self.auth_provider else {
            return Ok(AuthContext::anonymous());
        };

        let ctx = McpContext::with_state(cx.clone(), request_id, session.state().clone());
        let auth = provider.authenticate(&ctx, request)?;
        if !ctx.set_auth(auth.clone()) {
            debug!(
                target: targets::SESSION,
                "Auth context not stored (session state unavailable)"
            );
        }
        Ok(auth)
    }

    fn handle_cancelled_notification(&self, params: CancelledParams) {
        let reason = params.reason.as_deref().unwrap_or("unspecified");
        let await_cleanup = params.await_cleanup.unwrap_or(false);
        info!(
            target: targets::SESSION,
            "Cancellation requested for requestId={} (reason: {}, await_cleanup={})",
            params.request_id,
            reason,
            await_cleanup
        );
        if await_cleanup {
            fastmcp_core::logging::warn!(
                target: targets::SESSION,
                "await_cleanup requested but not supported without per-request regions"
            );
        }
        let cx = {
            let guard = self
                .active_requests
                .lock()
                .expect("active_requests lock poisoned");
            guard.get(&params.request_id).cloned()
        };
        if let Some(cx) = cx {
            cx.cancel_with(CancelKind::User, None);
        } else {
            fastmcp_core::logging::warn!(
                target: targets::SESSION,
                "No active request found for cancellation requestId={}",
                params.request_id
            );
        }
    }

    fn handle_set_log_level(&self, params: SetLogLevelParams) {
        let requested = match params.level {
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Warning => LevelFilter::Warn,
            LogLevel::Error => LevelFilter::Error,
        };

        let configured = self.logging.level.to_level_filter();
        let effective = if requested > configured {
            configured
        } else {
            requested
        };

        log::set_max_level(effective);

        if effective != requested {
            fastmcp_core::logging::warn!(
                target: targets::SESSION,
                "Client requested log level {:?}; clamped to server level {:?}",
                params.level,
                effective
            );
        } else {
            info!(
                target: targets::SESSION,
                "Log level set to {:?}",
                params.level
            );
        }
    }
}

struct ActiveRequestGuard<'a> {
    map: &'a Mutex<HashMap<RequestId, Cx>>,
    id: RequestId,
}

impl<'a> ActiveRequestGuard<'a> {
    fn new(map: &'a Mutex<HashMap<RequestId, Cx>>, id: RequestId, cx: Cx) -> Self {
        let mut guard = map.lock().expect("active_requests lock poisoned");
        if guard.insert(id.clone(), cx).is_some() {
            fastmcp_core::logging::warn!(
                target: targets::SESSION,
                "Active request replaced for requestId={}",
                id
            );
        }
        Self { map, id }
    }
}

impl Drop for ActiveRequestGuard<'_> {
    fn drop(&mut self) {
        let mut guard = self.map.lock().expect("active_requests lock poisoned");
        guard.remove(&self.id);
    }
}

/// Checks if banner should be suppressed via environment variable.
///
/// This is a legacy check. Prefer using `ConsoleConfig` for banner control.
fn banner_suppressed() -> bool {
    std::env::var("FASTMCP_NO_BANNER")
        .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Parses required parameters from JSON.
fn parse_params<T: serde::de::DeserializeOwned>(
    params: Option<serde_json::Value>,
) -> Result<T, McpError> {
    let value = params.ok_or_else(|| McpError::invalid_params("Missing required parameters"))?;
    serde_json::from_value(value).map_err(|e| McpError::invalid_params(e.to_string()))
}

/// Parses optional parameters from JSON, using default if not provided.
fn parse_params_or_default<T: serde::de::DeserializeOwned + Default>(
    params: Option<serde_json::Value>,
) -> Result<T, McpError> {
    match params {
        Some(value) => {
            serde_json::from_value(value).map_err(|e| McpError::invalid_params(e.to_string()))
        }
        None => Ok(T::default()),
    }
}

/// Converts a JSON-RPC RequestId to a u64 for internal tracking.
///
/// If the ID is a number, uses that number. If it's a string or absent,
/// uses 0 as a fallback.
fn request_id_to_u64(id: Option<&RequestId>) -> u64 {
    match id {
        Some(RequestId::Number(n)) => (*n).try_into().unwrap_or(0),
        Some(RequestId::String(_)) | None => 0,
    }
}

struct SharedTransport<T> {
    inner: Arc<Mutex<T>>,
}

impl<T> Clone for SharedTransport<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T: Transport> SharedTransport<T> {
    fn new(transport: T) -> Self {
        Self {
            inner: Arc::new(Mutex::new(transport)),
        }
    }

    fn recv(&self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        let mut guard = self.inner.lock().map_err(|_| transport_lock_error())?;
        guard.recv(cx)
    }

    fn send(&self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        let mut guard = self.inner.lock().map_err(|_| transport_lock_error())?;
        guard.send(cx, message)
    }
}

fn transport_lock_error() -> TransportError {
    TransportError::Io(std::io::Error::other("transport lock poisoned"))
}

fn create_transport_notification_sender<T>(transport: SharedTransport<T>) -> NotificationSender
where
    T: Transport + Send + 'static,
{
    let cx = Cx::for_testing();

    Arc::new(move |request: JsonRpcRequest| {
        let message = JsonRpcMessage::Request(request);
        if let Err(e) = transport.send(&cx, &message) {
            log::error!(
                target: targets::TRANSPORT,
                "Failed to send notification: {}",
                e
            );
        }
    })
}

/// Creates a notification sender that writes JSON-RPC notifications to stdout.
///
/// This creates a separate stdout handle for sending notifications, allowing
/// notifications (like progress updates) to be sent during handler execution
/// independently of the main transport.
///
/// The sender uses NDJSON format (newline-delimited JSON) to match the
/// standard MCP transport format.
fn create_notification_sender() -> NotificationSender {
    use std::sync::Mutex;

    // Create a Mutex-wrapped stdout handle for thread-safe writes.
    // Each notification write is atomic at the stdout level.
    let stdout = Mutex::new(std::io::stdout());
    let codec = Codec::new();

    Arc::new(move |request: JsonRpcRequest| {
        // Encode the notification to JSON
        let bytes = match codec.encode_request(&request) {
            Ok(b) => b,
            Err(e) => {
                log::error!(target: targets::SERVER, "Failed to encode notification: {}", e);
                return;
            }
        };

        // Write to stdout atomically
        if let Ok(mut stdout) = stdout.lock() {
            if let Err(e) = stdout.write_all(&bytes) {
                log::error!(target: targets::TRANSPORT, "Failed to send notification: {}", e);
            }
            if let Err(e) = stdout.flush() {
                log::error!(target: targets::TRANSPORT, "Failed to flush notification: {}", e);
            }
        } else {
            log::warn!(target: targets::SERVER, "Failed to acquire stdout lock for notification");
        }
    })
}
