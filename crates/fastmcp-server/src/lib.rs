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
pub mod bidirectional;
mod builder;
pub mod caching;
pub mod docket;
mod handler;
mod middleware;
pub mod oauth;
pub mod oidc;
pub mod providers;
mod proxy;
pub mod rate_limiting;
mod router;
mod session;
mod tasks;
pub mod transform;

#[cfg(test)]
mod tests;

#[cfg(feature = "jwt")]
pub use auth::JwtTokenVerifier;
pub use auth::{
    AllowAllAuthProvider, AuthProvider, AuthRequest, StaticTokenVerifier, TokenAuthProvider,
    TokenVerifier,
};
pub use builder::ServerBuilder;
pub use fastmcp_console::config::{BannerStyle, ConsoleConfig, TrafficVerbosity};
pub use fastmcp_console::stats::{ServerStats, StatsSnapshot};
pub use handler::{
    BidirectionalSenders, BoxFuture, ProgressNotificationSender, PromptHandler, ResourceHandler,
    ToolHandler, create_context_with_progress, create_context_with_progress_and_senders,
};
pub use middleware::{Middleware, MiddlewareDecision};
pub use proxy::{ProxyBackend, ProxyCatalog, ProxyClient};
pub use router::{MountResult, NotificationSender, Router, RouterResourceReader, RouterToolCaller, TagFilters};
pub use session::Session;
pub use tasks::{SharedTaskManager, TaskManager};

// Re-export bidirectional communication types
pub use bidirectional::{
    PendingRequests, RequestSender, TransportElicitationSender, TransportRootsProvider,
    TransportSamplingSender,
};

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use asupersync::{Budget, CancelKind, Cx, RegionId};
use fastmcp_console::client::RequestResponseRenderer;
use fastmcp_console::logging::RichLoggerBuilder;
use fastmcp_console::{banner::StartupBanner, console};
use fastmcp_core::logging::{debug, error, info, targets};
use fastmcp_core::{AuthContext, McpContext, McpError, McpErrorCode, McpResult};
use fastmcp_protocol::{
    CallToolParams, CancelTaskParams, CancelledParams, GetPromptParams, GetTaskParams,
    InitializeParams, JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse,
    ListPromptsParams, ListResourceTemplatesParams, ListResourcesParams, ListTasksParams,
    ListToolsParams, LogLevel, LogMessageParams, Prompt, ReadResourceParams, RequestId, Resource,
    ResourceTemplate, ServerCapabilities, ServerInfo, SetLogLevelParams, SubmitTaskParams,
    SubscribeResourceParams, Tool, UnsubscribeResourceParams,
};
use fastmcp_transport::sse::SseServerTransport;
use fastmcp_transport::websocket::WsTransport;
use fastmcp_transport::{AsyncStdout, Codec, StdioTransport, Transport, TransportError};
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

/// Behavior when registering a component with a name that already exists.
///
/// This setting controls how the server handles duplicate tool, resource,
/// or prompt names during registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DuplicateBehavior {
    /// Raise an error and fail registration.
    ///
    /// Use this for strict validation in production environments.
    Error,

    /// Log a warning and keep the original component.
    ///
    /// This is the default behavior, providing visibility into duplicates
    /// while maintaining backwards compatibility.
    #[default]
    Warn,

    /// Replace the original component with the new one.
    ///
    /// Use this when you want later registrations to override earlier ones.
    Replace,

    /// Silently keep the original component.
    ///
    /// Use this when duplicates are expected and should be ignored.
    Ignore,
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
    /// Whether to mask internal error details in responses.
    mask_error_details: bool,
    /// Logging configuration.
    logging: LoggingConfig,
    /// Console configuration for rich output.
    console_config: ConsoleConfig,
    /// Lifecycle hooks (wrapped in Option so they can be taken once).
    lifespan: Mutex<Option<LifespanHooks>>,
    /// Optional authentication provider.
    auth_provider: Option<Arc<dyn AuthProvider>>,
    /// Registered middleware.
    middleware: Arc<Vec<Box<dyn crate::Middleware>>>,
    /// Active requests by JSON-RPC request ID.
    active_requests: Mutex<HashMap<RequestId, ActiveRequest>>,
    /// Optional task manager for background tasks (Docket/SEP-1686).
    task_manager: Option<SharedTaskManager>,
    /// Pending server-to-client requests (for bidirectional communication).
    pending_requests: Arc<bidirectional::PendingRequests>,
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

    /// Returns the task manager, if configured.
    ///
    /// Returns `None` if background tasks are not enabled.
    #[must_use]
    pub fn task_manager(&self) -> Option<&SharedTaskManager> {
        self.task_manager.as_ref()
    }

    /// Consumes the server and returns its router.
    ///
    /// This is used for mounting one server's components into another.
    #[must_use]
    pub fn into_router(self) -> Router {
        self.router
    }

    /// Returns the capabilities this server provides.
    ///
    /// This is useful when determining what components a server has
    /// before mounting.
    #[must_use]
    pub fn has_tools(&self) -> bool {
        self.capabilities.tools.is_some()
    }

    /// Returns whether this server has resources.
    #[must_use]
    pub fn has_resources(&self) -> bool {
        self.capabilities.resources.is_some()
    }

    /// Returns whether this server has prompts.
    #[must_use]
    pub fn has_prompts(&self) -> bool {
        self.capabilities.prompts.is_some()
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

        let shared_recv = shared.clone();
        let shared_send = shared.clone();
        self.run_loop(
            cx,
            move |cx| shared_recv.recv(cx),
            move |cx, message| shared_send.send(cx, message),
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

        let shared_recv = shared.clone();
        let shared_send = shared;
        self.run_loop(
            cx,
            move |cx| shared_recv.recv(cx),
            move |cx, message| shared_send.send(cx, message),
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
            let mut guard = self.lifespan.lock().unwrap_or_else(|poisoned| {
                error!(target: targets::SERVER, "lifespan lock poisoned in run_startup_hook, recovering");
                poisoned.into_inner()
            });
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
            let mut guard = self.lifespan.lock().unwrap_or_else(|poisoned| {
                error!(target: targets::SERVER, "lifespan lock poisoned in run_shutdown_hook, recovering");
                poisoned.into_inner()
            });
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
        self.cancel_active_requests(CancelKind::Shutdown, true);
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
        send: S,
        notification_sender: NotificationSender,
    ) -> !
    where
        R: FnMut(&Cx) -> Result<JsonRpcMessage, TransportError>,
        S: FnMut(&Cx, &JsonRpcMessage) -> Result<(), TransportError> + Send + Sync + 'static,
    {
        let mut session = Session::new(self.info.clone(), self.capabilities.clone());

        // Wrap send in Arc<Mutex> for shared access from bidirectional requests
        let send = Arc::new(Mutex::new(send));

        // Create a RequestSender for bidirectional communication
        let request_sender = {
            let send_clone = send.clone();
            let send_fn: bidirectional::TransportSendFn = Arc::new(move |message| {
                let mut guard = send_clone
                    .lock()
                    .map_err(|e| format!("Lock poisoned: {}", e))?;
                // We need a Cx for the send call, but we're sending async so use a basic one
                let cx = Cx::for_testing();
                guard(&cx, message).map_err(|e| format!("Send failed: {}", e))
            });
            bidirectional::RequestSender::new(self.pending_requests.clone(), send_fn)
        };

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

        // Create traffic renderer if enabled
        let traffic_renderer = if self.console_config.show_request_traffic {
            let mut renderer = RequestResponseRenderer::new(self.console_config.resolve_context());
            renderer.truncate_at = self.console_config.truncate_at;
            match self.console_config.traffic_verbosity {
                TrafficVerbosity::None => {} // Should not happen given the if check
                TrafficVerbosity::Summary | TrafficVerbosity::Headers => {
                    renderer.show_params = false;
                    renderer.show_result = false;
                }
                TrafficVerbosity::Full => {
                    renderer.show_params = true;
                    renderer.show_result = true;
                }
            }
            Some(renderer)
        } else {
            None
        };

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

            // Log request traffic
            if let Some(renderer) = &traffic_renderer {
                if let JsonRpcMessage::Request(req) = &message {
                    renderer.render_request(req, console());
                }
            }

            let start_time = Instant::now();

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
                    self.handle_request(
                        cx,
                        &mut session,
                        request,
                        &notification_sender,
                        &request_sender,
                    )
                }
                JsonRpcMessage::Response(response) => {
                    // Route response to pending server-initiated request (bidirectional)
                    if self.pending_requests.route_response(&response) {
                        debug!(target: targets::SERVER, "Routed response to pending request");
                    } else {
                        debug!(target: targets::SERVER, "Received unexpected response: {:?}", response.id);
                    }
                    continue;
                }
            };

            let duration = start_time.elapsed();

            if let Some(response) = response_opt {
                // Log response traffic
                if let Some(renderer) = &traffic_renderer {
                    renderer.render_response(&response, Some(duration), console());
                }

                // Track bytes sent (approximate from serialized response size)
                if let Some(ref stats) = self.stats {
                    if let Ok(json) = serde_json::to_string(&response) {
                        stats.add_bytes_sent(json.len() as u64 + 1); // +1 for newline
                    }
                }

                // Send response
                let send_result = {
                    let mut guard = send.lock().unwrap();
                    guard(cx, &JsonRpcMessage::Response(response))
                };
                if let Err(e) = send_result {
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
        request_sender: &bidirectional::RequestSender,
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
            Cx::for_request_with_budget(budget)
        };

        let _active_guard = id.clone().map(|request_id| {
            ActiveRequestGuard::new(&self.active_requests, request_id, request_cx.clone())
        });

        // Dispatch based on method, passing the budget, notification sender, and request sender
        let result = self.dispatch_method(
            &request_cx,
            session,
            request,
            request_id,
            &budget,
            notification_sender,
            request_sender,
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
            Err(e) => {
                // Log full error before masking if this is an internal error
                if self.mask_error_details && e.is_internal() {
                    fastmcp_core::logging::error!(
                        target: targets::HANDLER,
                        "Request '{}' failed (masked in response): {}",
                        method,
                        e
                    );
                }

                // Apply masking if enabled
                let masked = e.masked(self.mask_error_details);
                Some(JsonRpcResponse::error(
                    id,
                    JsonRpcError {
                        code: masked.code.into(),
                        message: masked.message,
                        data: masked.data,
                    },
                ))
            }
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
        request: JsonRpcRequest,
        request_id: u64,
        budget: &Budget,
        notification_sender: &NotificationSender,
        request_sender: &bidirectional::RequestSender,
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
        if !session.is_initialized() && request.method != "initialize" && request.method != "ping" {
            return Err(McpError::invalid_request(
                "Server not initialized. Client must send 'initialize' first.",
            ));
        }

        if let Some(task_manager) = &self.task_manager {
            task_manager.set_notification_sender(Arc::clone(notification_sender));
        }

        // Middleware: on_request
        // We use a temporary context derived from the request context for middleware
        // so they can access session state but share the request's lifecycle.
        let mw_ctx = McpContext::with_state(cx.clone(), request_id, session.state().clone());
        let mut entered_middleware: Vec<&dyn crate::Middleware> = Vec::new();

        for m in self.middleware.iter() {
            entered_middleware.push(m.as_ref());
            match m.on_request(&mw_ctx, &request) {
                Ok(crate::MiddlewareDecision::Continue) => {}
                Ok(crate::MiddlewareDecision::Respond(v)) => {
                    return self.apply_middleware_response(
                        &entered_middleware,
                        &mw_ctx,
                        &request,
                        v,
                    );
                }
                Err(e) => {
                    let err =
                        self.apply_middleware_error(&entered_middleware, &mw_ctx, &request, e);
                    return Err(err);
                }
            }
        }

        if self.should_authenticate(&request.method) {
            let auth_request = AuthRequest {
                method: &request.method,
                params: request.params.as_ref(),
                request_id,
            };
            self.authenticate_request(cx, request_id, session, auth_request)?;
        }

        let method = &request.method;
        let params = request.params.clone();

        // Create bidirectional senders based on client capabilities
        let bidirectional_senders = self.create_bidirectional_senders(session, request_sender);

        let result = match method.as_str() {
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
                self.handle_set_log_level(session, params);
                Ok(serde_json::Value::Null)
            }
            "tools/list" => {
                let params: ListToolsParams = parse_params_or_default(params)?;
                let result = self.router.handle_tools_list(cx, params, Some(session.state()))?;
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
                    bidirectional_senders.as_ref(),
                )?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "resources/list" => {
                let params: ListResourcesParams = parse_params_or_default(params)?;
                let result = self.router.handle_resources_list(cx, params, Some(session.state()))?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "resources/templates/list" => {
                let params: ListResourceTemplatesParams = parse_params_or_default(params)?;
                let result = self.router.handle_resource_templates_list(cx, params, Some(session.state()))?;
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
                    bidirectional_senders.as_ref(),
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
                let result = self.router.handle_prompts_list(cx, params, Some(session.state()))?;
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
                    bidirectional_senders.as_ref(),
                )?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "ping" => {
                // Simple ping-pong for health checks
                Ok(serde_json::json!({}))
            }
            // Task methods (Docket/SEP-1686)
            "tasks/list" => {
                let params: ListTasksParams = parse_params_or_default(params)?;
                let result =
                    self.router
                        .handle_tasks_list(cx, params, self.task_manager.as_ref())?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "tasks/get" => {
                let params: GetTaskParams = parse_params(params)?;
                let result =
                    self.router
                        .handle_tasks_get(cx, params, self.task_manager.as_ref())?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "tasks/cancel" => {
                let params: CancelTaskParams = parse_params(params)?;
                let result =
                    self.router
                        .handle_tasks_cancel(cx, params, self.task_manager.as_ref())?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            "tasks/submit" => {
                let params: SubmitTaskParams = parse_params(params)?;
                let result =
                    self.router
                        .handle_tasks_submit(cx, params, self.task_manager.as_ref())?;
                Ok(serde_json::to_value(result).map_err(McpError::from)?)
            }
            _ => Err(McpError::method_not_found(method)),
        };

        let final_result = match result {
            Ok(v) => self.apply_middleware_response(&entered_middleware, &mw_ctx, &request, v),
            Err(e) => Err(self.apply_middleware_error(&entered_middleware, &mw_ctx, &request, e)),
        };

        self.maybe_emit_log_notification(session, notification_sender, method, &final_result);

        final_result
    }

    fn apply_middleware_response(
        &self,
        stack: &[&dyn crate::Middleware],
        ctx: &McpContext,
        request: &JsonRpcRequest,
        value: serde_json::Value,
    ) -> Result<serde_json::Value, McpError> {
        let mut response = value;
        for m in stack.iter().rev() {
            match m.on_response(ctx, request, response) {
                Ok(next) => response = next,
                Err(err) => {
                    let mapped = self.apply_middleware_error(stack, ctx, request, err);
                    return Err(mapped);
                }
            }
        }
        Ok(response)
    }

    fn apply_middleware_error(
        &self,
        stack: &[&dyn crate::Middleware],
        ctx: &McpContext,
        request: &JsonRpcRequest,
        error: McpError,
    ) -> McpError {
        let mut err = error;
        for m in stack.iter().rev() {
            err = m.on_error(ctx, request, err);
        }
        err
    }

    /// Creates bidirectional senders based on client capabilities.
    ///
    /// Returns `Some(BidirectionalSenders)` if the client supports any bidirectional
    /// features (sampling, elicitation), or `None` if no features are supported.
    fn create_bidirectional_senders(
        &self,
        session: &Session,
        request_sender: &bidirectional::RequestSender,
    ) -> Option<handler::BidirectionalSenders> {
        let supports_sampling = session.supports_sampling();
        let supports_elicitation = session.supports_elicitation();

        if !supports_sampling && !supports_elicitation {
            return None;
        }

        let mut senders = handler::BidirectionalSenders::new();

        if supports_sampling {
            let sampling_sender: Arc<dyn fastmcp_core::SamplingSender> = Arc::new(
                bidirectional::TransportSamplingSender::new(request_sender.clone()),
            );
            senders = senders.with_sampling(sampling_sender);
        }

        if supports_elicitation {
            let elicitation_sender: Arc<dyn fastmcp_core::ElicitationSender> = Arc::new(
                bidirectional::TransportElicitationSender::new(request_sender.clone()),
            );
            senders = senders.with_elicitation(elicitation_sender);
        }

        Some(senders)
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
        let active = {
            let guard = self.active_requests.lock().unwrap_or_else(|poisoned| {
                error!(target: targets::SERVER, "active_requests lock poisoned, recovering");
                poisoned.into_inner()
            });
            guard
                .get(&params.request_id)
                .map(|entry| (entry.cx.clone(), entry.region_id, entry.completion.clone()))
        };
        if let Some((cx, region_id, completion)) = active {
            cx.cancel_with(CancelKind::User, None);
            if await_cleanup {
                let completed = completion.wait_timeout(AWAIT_CLEANUP_TIMEOUT);
                if !completed {
                    fastmcp_core::logging::warn!(
                        target: targets::SESSION,
                        "await_cleanup timed out for requestId={} (region={:?})",
                        params.request_id,
                        region_id
                    );
                }
            }
        } else {
            fastmcp_core::logging::warn!(
                target: targets::SESSION,
                "No active request found for cancellation requestId={}",
                params.request_id
            );
        }
    }

    fn cancel_active_requests(&self, kind: CancelKind, await_cleanup: bool) {
        let active: Vec<(RequestId, RegionId, Cx, Arc<RequestCompletion>)> = {
            let guard = self.active_requests.lock().unwrap_or_else(|poisoned| {
                error!(target: targets::SERVER, "active_requests lock poisoned in cancel_active_requests, recovering");
                poisoned.into_inner()
            });
            guard
                .iter()
                .map(|(request_id, entry)| {
                    (
                        request_id.clone(),
                        entry.region_id,
                        entry.cx.clone(),
                        entry.completion.clone(),
                    )
                })
                .collect()
        };
        if active.is_empty() {
            return;
        }
        info!(
            target: targets::SESSION,
            "Cancelling {} active request(s) (kind={:?}, await_cleanup={})",
            active.len(),
            kind,
            await_cleanup
        );
        for (_, _, cx, _) in &active {
            cx.cancel_with(kind, None);
        }

        if await_cleanup {
            for (request_id, region_id, _cx, completion) in active {
                let completed = completion.wait_timeout(AWAIT_CLEANUP_TIMEOUT);
                if !completed {
                    fastmcp_core::logging::warn!(
                        target: targets::SESSION,
                        "Shutdown cancel timed out for requestId={} (region={:?})",
                        request_id,
                        region_id
                    );
                }
            }
        }
    }

    fn handle_set_log_level(&self, session: &mut Session, params: SetLogLevelParams) {
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

        let effective_level = match effective {
            LevelFilter::Debug => LogLevel::Debug,
            LevelFilter::Info => LogLevel::Info,
            LevelFilter::Warn => LogLevel::Warning,
            LevelFilter::Error => LogLevel::Error,
            _ => LogLevel::Info,
        };
        session.set_log_level(effective_level);

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

    fn log_level_rank(level: LogLevel) -> u8 {
        match level {
            LogLevel::Debug => 1,
            LogLevel::Info => 2,
            LogLevel::Warning => 3,
            LogLevel::Error => 4,
        }
    }

    fn emit_log_notification(
        &self,
        session: &Session,
        sender: &NotificationSender,
        level: LogLevel,
        message: impl Into<String>,
    ) {
        let Some(min_level) = session.log_level() else {
            return;
        };
        if Self::log_level_rank(level) < Self::log_level_rank(min_level) {
            return;
        }

        let ts = chrono::Utc::now().to_rfc3339();
        let text = format!("{ts} {}", message.into());
        let params = LogMessageParams {
            level,
            logger: Some("fastmcp::server".to_string()),
            data: serde_json::Value::String(text),
        };
        let payload = match serde_json::to_value(params) {
            Ok(value) => value,
            Err(err) => {
                fastmcp_core::logging::warn!(
                    target: targets::SESSION,
                    "Failed to serialize log message notification: {}",
                    err
                );
                return;
            }
        };
        sender(JsonRpcRequest::notification(
            "notifications/message",
            Some(payload),
        ));
    }

    fn maybe_emit_log_notification(
        &self,
        session: &Session,
        sender: &NotificationSender,
        method: &str,
        result: &McpResult<serde_json::Value>,
    ) {
        if method.starts_with("notifications/") || method == "logging/setLevel" {
            return;
        }
        let level = if result.is_ok() {
            LogLevel::Info
        } else {
            LogLevel::Error
        };
        let message = if result.is_ok() {
            format!("Handled {}", method)
        } else {
            format!("Error handling {}", method)
        };
        self.emit_log_notification(session, sender, level, message);
    }
}

const AWAIT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

struct RequestCompletion {
    done: Mutex<bool>,
    cv: Condvar,
}

impl RequestCompletion {
    fn new() -> Self {
        Self {
            done: Mutex::new(false),
            cv: Condvar::new(),
        }
    }

    fn mark_done(&self) {
        let mut done = self
            .done
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !*done {
            *done = true;
            self.cv.notify_all();
        }
    }

    fn wait_timeout(&self, timeout: Duration) -> bool {
        let mut done = self
            .done
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *done {
            return true;
        }
        let start = Instant::now();
        let mut remaining = timeout;
        loop {
            let (guard, result) = self
                .cv
                .wait_timeout(done, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            done = guard;
            if *done {
                return true;
            }
            if result.timed_out() {
                return false;
            }
            let elapsed = start.elapsed();
            remaining = match timeout.checked_sub(elapsed) {
                Some(left) if !left.is_zero() => left,
                _ => return false,
            };
        }
    }

    fn is_done(&self) -> bool {
        let done = self
            .done
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *done
    }
}

struct ActiveRequest {
    cx: Cx,
    region_id: RegionId,
    completion: Arc<RequestCompletion>,
}

impl ActiveRequest {
    fn new(cx: Cx, completion: Arc<RequestCompletion>) -> Self {
        let region_id = cx.region_id();
        Self {
            cx,
            region_id,
            completion,
        }
    }
}

struct ActiveRequestGuard<'a> {
    map: &'a Mutex<HashMap<RequestId, ActiveRequest>>,
    id: RequestId,
    completion: Arc<RequestCompletion>,
}

impl<'a> ActiveRequestGuard<'a> {
    fn new(map: &'a Mutex<HashMap<RequestId, ActiveRequest>>, id: RequestId, cx: Cx) -> Self {
        let completion = Arc::new(RequestCompletion::new());
        let entry = ActiveRequest::new(cx, completion.clone());
        let mut guard = map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.insert(id.clone(), entry).is_some() {
            fastmcp_core::logging::warn!(
                target: targets::SESSION,
                "Active request replaced for requestId={}",
                id
            );
        }
        Self {
            map,
            id,
            completion,
        }
    }
}

impl Drop for ActiveRequestGuard<'_> {
    fn drop(&mut self) {
        {
            let mut guard = self
                .map
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match guard.get(&self.id) {
                Some(entry) if Arc::ptr_eq(&entry.completion, &self.completion) => {
                    guard.remove(&self.id);
                }
                Some(_) => {
                    fastmcp_core::logging::warn!(
                        target: targets::SESSION,
                        "Active request replaced before drop for requestId={}",
                        self.id
                    );
                }
                None => {
                    fastmcp_core::logging::warn!(
                        target: targets::SESSION,
                        "Active request missing on drop for requestId={}",
                        self.id
                    );
                }
            }
        }
        self.completion.mark_done();
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
/// uses a stable hash (string) or 0 (absent) as a fallback.
fn request_id_to_u64(id: Option<&RequestId>) -> u64 {
    match id {
        Some(RequestId::Number(n)) => *n as u64,
        Some(RequestId::String(s)) => stable_hash_request_id(s),
        None => 0,
    }
}

fn stable_hash_request_id(value: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    if hash == 0 { FNV_OFFSET } else { hash }
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

    // Use AsyncStdout so notifications share the global stdout lock used by
    // the transport writer, preventing interleaved NDJSON writes.
    let stdout = Mutex::new(AsyncStdout::new());
    let codec = Codec::new();

    Arc::new(move |request: JsonRpcRequest| {
        let bytes = match codec.encode_request(&request) {
            Ok(b) => b,
            Err(e) => {
                log::error!(target: targets::SERVER, "Failed to encode notification: {}", e);
                return;
            }
        };

        if let Ok(mut stdout) = stdout.lock() {
            if let Err(e) = stdout.write_all_unchecked(&bytes) {
                log::error!(target: targets::TRANSPORT, "Failed to send notification: {}", e);
            }
            if let Err(e) = stdout.flush_unchecked() {
                log::error!(target: targets::TRANSPORT, "Failed to flush notification: {}", e);
            }
        } else {
            log::warn!(target: targets::SERVER, "Failed to acquire stdout lock for notification");
        }
    })
}
