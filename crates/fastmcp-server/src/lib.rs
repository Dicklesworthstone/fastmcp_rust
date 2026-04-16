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
//! use fastmcp_rust::prelude::*;
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
//!
//! # Role in the System
//!
//! `fastmcp-server` is the **execution engine** for MCP servers. It ties
//! together:
//! - Protocol types (`fastmcp-protocol`) for requests and responses
//! - Transports (`fastmcp-transport`) for stdio/SSE/WebSocket I/O
//! - Core context + cancellation (`fastmcp-core`) for budgets and checkpoints
//! - Console output (`fastmcp-console`) for human-friendly stderr rendering
//!
//! The façade crate `fastmcp` re-exports this API, so most users interact with
//! `Server` via `fastmcp_rust::prelude::*`.

#![forbid(unsafe_code)]
#![allow(dead_code)]

// Proc-macros (fastmcp-derive) reference this crate by its external name
// (`fastmcp_server::...`). This alias makes those macros usable inside this crate too
// (including in unit tests).
extern crate self as fastmcp_server;

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
pub use router::{
    MountResult, NotificationSender, Router, RouterResourceReader, RouterToolCaller, TagFilters,
};
pub use session::Session;
pub use tasks::{SharedTaskManager, TaskManager};

// Re-export bidirectional communication types
pub use bidirectional::{
    PendingRequests, RequestSender, TransportElicitationSender, TransportRootsProvider,
    TransportSamplingSender,
};

use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use fastmcp_transport::http::{
    HttpHandlerConfig, HttpMethod, HttpRequest, HttpRequestHandler, HttpResponse, HttpStatus,
    HttpTransport,
};

use asupersync::time::wall_now;
use asupersync::{Budget, CancelKind, Cx, RegionId};
use fastmcp_console::client::RequestResponseRenderer;
use fastmcp_console::logging::RichLoggerBuilder;
use fastmcp_console::{banner::StartupBanner, console};
use fastmcp_core::logging::{debug, error, info, targets};
use fastmcp_core::{AuthContext, McpContext, McpError, McpErrorCode, McpResult, SessionState};
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
/// use fastmcp_rust::prelude::*;
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

/// Configuration for the turnkey HTTP server started by [`Server::run_http`].
///
/// All fields have sensible defaults. Use the builder methods to customise.
///
/// # Example
///
/// ```ignore
/// use fastmcp_server::HttpServerConfig;
///
/// let config = HttpServerConfig::new()
///     .mcp_path("/api/mcp")
///     .health_path("/healthz")
///     .max_connections(128);
/// ```
#[derive(Debug, Clone)]
pub struct HttpServerConfig {
    /// Path where MCP JSON-RPC requests are accepted (default: `"/mcp"`).
    pub mcp_path: String,
    /// Path for the health-check endpoint (default: `"/health"`).
    pub health_path: String,
    /// Maximum number of concurrent connections (default: 64).
    pub max_connections: usize,
    /// Inner HTTP handler configuration (CORS, body size, timeouts).
    pub handler_config: HttpHandlerConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpRequestExecutionMode {
    ConcurrentReadOnly,
    ExclusiveSession,
}

impl HttpRequestExecutionMode {
    fn for_method(method: &str) -> Self {
        match method {
            "resources/read" | "prompts/get" => Self::ConcurrentReadOnly,
            _ => Self::ExclusiveSession,
        }
    }

    fn for_request(router: &Router, request: &JsonRpcRequest) -> Self {
        match request.method.as_str() {
            "tools/call" => request
                .params
                .as_ref()
                .and_then(|params| params.get("name"))
                .and_then(serde_json::Value::as_str)
                .filter(|name| router.tool_is_read_only(name))
                .map_or(Self::ExclusiveSession, |_| Self::ConcurrentReadOnly),
            _ => Self::for_method(&request.method),
        }
    }
}

#[derive(Debug, Clone)]
struct SessionView {
    initialized: bool,
    state: SessionState,
    supports_sampling: bool,
    supports_elicitation: bool,
    log_level: Option<LogLevel>,
}

impl SessionView {
    fn from_session(session: &Session) -> Self {
        Self {
            initialized: session.is_initialized(),
            state: session.state().clone(),
            supports_sampling: session.supports_sampling(),
            supports_elicitation: session.supports_elicitation(),
            log_level: session.log_level(),
        }
    }
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            mcp_path: "/mcp".to_string(),
            health_path: "/health".to_string(),
            max_connections: 64,
            handler_config: HttpHandlerConfig {
                base_path: "/mcp".to_string(),
                ..HttpHandlerConfig::default()
            },
        }
    }
}

impl HttpServerConfig {
    /// Creates a new configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the MCP endpoint path.
    #[must_use]
    pub fn mcp_path(mut self, path: impl Into<String>) -> Self {
        self.mcp_path = path.into();
        self
    }

    /// Sets the health-check endpoint path.
    #[must_use]
    pub fn health_path(mut self, path: impl Into<String>) -> Self {
        self.health_path = path.into();
        self
    }

    /// Sets the maximum number of concurrent connections.
    #[must_use]
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Sets the inner HTTP handler configuration.
    #[must_use]
    pub fn handler_config(mut self, config: HttpHandlerConfig) -> Self {
        self.handler_config = config;
        self
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
    /// HTTP server configuration (paths, max_connections, CORS).
    http_config: HttpServerConfig,
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

    /// Processes a single JSON-RPC request through the full server dispatch
    /// pipeline (initialization checks, middleware, routing, tool/resource/prompt
    /// execution, error masking, and statistics recording).
    ///
    /// This is the public equivalent of the internal `handle_request` method that
    /// the built-in transports (`run_stdio`, `run_http`, etc.) use. It allows
    /// external code to drive the server from a custom transport or embedding
    /// without going through a `Transport` abstraction.
    ///
    /// # Parameters
    ///
    /// - `cx` — The cancellation / budget context for this request.
    /// - `session` — Mutable reference to the session for this connection.
    ///   The caller is responsible for session lifecycle (creation, sharing,
    ///   locking if shared across threads).
    /// - `request` — The incoming JSON-RPC request (or notification).
    /// - `notification_sender` — Callback used to push server-initiated
    ///   notifications (e.g. progress) back to the client.
    /// - `request_sender` — Sender for server-to-client requests
    ///   (sampling, elicitation, roots).
    ///
    /// # Returns
    ///
    /// `Some(JsonRpcResponse)` for normal requests, or `None` for
    /// notifications (JSON-RPC messages without an `id`).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use fastmcp_rust::{
    ///     Server, Session, JsonRpcRequest, NotificationSender,
    ///     bidirectional::RequestSender,
    /// };
    /// use fastmcp_core::Cx;
    ///
    /// let server = Arc::new(
    ///     Server::new("my-server", "1.0.0").build(),
    /// );
    /// let mut session = Session::new();
    /// let cx = Cx::for_request();
    /// let notify: NotificationSender = Arc::new(|_| {});
    /// let req_sender = RequestSender::noop();
    ///
    /// let request: JsonRpcRequest = /* ... */;
    /// let response = server.dispatch_request(
    ///     &cx, &mut session, request, &notify, &req_sender,
    /// );
    /// ```
    pub fn dispatch_request(
        &self,
        cx: &Cx,
        session: &mut Session,
        request: JsonRpcRequest,
        notification_sender: &NotificationSender,
        request_sender: &bidirectional::RequestSender,
    ) -> Option<JsonRpcResponse> {
        self.handle_request(cx, session, request, notification_sender, request_sender)
    }

    /// Processes a single JSON-RPC request with automatic concurrency
    /// classification, allowing read-only requests to execute without holding
    /// the session mutex for the duration of the handler.
    ///
    /// This is the concurrent counterpart of [`dispatch_request`](Self::dispatch_request).
    /// Use it when the session is shared across threads behind an
    /// `Arc<Mutex<Session>>` (e.g. in HTTP or WebSocket transports where
    /// multiple requests may arrive simultaneously).
    ///
    /// Internally, each request is classified into one of two execution modes:
    ///
    /// - **`ConcurrentReadOnly`** (`resources/read`, `prompts/get`, and
    ///   `tools/call` on read-only tools): a lightweight session snapshot
    ///   is taken and the mutex is released immediately, so other
    ///   requests can proceed in parallel.
    /// - **`ExclusiveSession`** (everything else): the mutex is held for the
    ///   full duration of the handler, guaranteeing exclusive access to
    ///   session state.
    ///
    /// Mutex poisoning is recovered from automatically (the poisoned inner
    /// value is used), matching the behaviour of the internal HTTP handler.
    ///
    /// # Parameters
    ///
    /// - `cx` — The cancellation / budget context for this request.
    /// - `session` — Shared, mutex-protected session for this connection.
    /// - `request` — The incoming JSON-RPC request (or notification).
    /// - `notification_sender` — Callback used to push server-initiated
    ///   notifications (e.g. progress) back to the client.
    /// - `request_sender` — Sender for server-to-client requests
    ///   (sampling, elicitation, roots).
    ///
    /// # Returns
    ///
    /// `Some(JsonRpcResponse)` for normal requests, or `None` for
    /// notifications (JSON-RPC messages without an `id`).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::sync::{Arc, Mutex};
    /// use fastmcp_rust::{
    ///     Server, Session, JsonRpcRequest, NotificationSender,
    ///     bidirectional::RequestSender,
    /// };
    /// use fastmcp_core::Cx;
    ///
    /// let server = Arc::new(
    ///     Server::new("my-server", "1.0.0").build(),
    /// );
    /// let session = Arc::new(Mutex::new(Session::new()));
    /// let cx = Cx::for_request();
    /// let notify: NotificationSender = Arc::new(|_| {});
    /// let req_sender = RequestSender::noop();
    ///
    /// let request: JsonRpcRequest = /* ... */;
    /// let response = server.dispatch_request_concurrent(
    ///     &cx, &session, request, &notify, &req_sender,
    /// );
    /// ```
    pub fn dispatch_request_concurrent(
        &self,
        cx: &Cx,
        session: &Arc<Mutex<Session>>,
        request: JsonRpcRequest,
        notification_sender: &NotificationSender,
        request_sender: &bidirectional::RequestSender,
    ) -> Option<JsonRpcResponse> {
        let execution_mode = HttpRequestExecutionMode::for_request(&self.router, &request);

        match execution_mode {
            HttpRequestExecutionMode::ConcurrentReadOnly => {
                let session_view = {
                    let session_guard = match session.lock() {
                        Ok(g) => g,
                        Err(poisoned) => {
                            error!(target: targets::SERVER, "Session lock poisoned, recovering");
                            poisoned.into_inner()
                        }
                    };
                    SessionView::from_session(&session_guard)
                };
                self.handle_request_with_view(
                    cx,
                    &session_view,
                    request,
                    notification_sender,
                    request_sender,
                )
            }
            HttpRequestExecutionMode::ExclusiveSession => {
                let mut session_guard = match session.lock() {
                    Ok(g) => g,
                    Err(poisoned) => {
                        error!(target: targets::SERVER, "Session lock poisoned, recovering");
                        poisoned.into_inner()
                    }
                };
                self.handle_request(
                    cx,
                    &mut session_guard,
                    request,
                    notification_sender,
                    request_sender,
                )
            }
        }
    }

    /// Runs the server on stdio transport.
    ///
    /// This is the primary way to run MCP servers as subprocesses.
    /// Creates a request-scoped Cx and runs the server loop.
    pub fn run_stdio(self) -> ! {
        // Top-level server loop Cx (non-test). Per-request budgets are applied in `handle_request`.
        let cx = Cx::for_request();
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

    /// Runs the server on a custom transport with a request-scoped Cx.
    ///
    /// This is useful for SSE/WebSocket integrations where the transport is
    /// provided by an external server framework.
    pub fn run_transport<T>(self, transport: T) -> !
    where
        T: Transport + Send + 'static,
    {
        // Top-level server loop Cx (non-test). Per-request budgets are applied in `handle_request`.
        let cx = Cx::for_request();
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

    /// Runs the server on a custom transport and returns when the transport closes or the Cx is cancelled.
    ///
    /// Unlike [`run_transport_with_cx`](Self::run_transport_with_cx), this does not call
    /// `std::process::exit` on shutdown. This is useful for tests and embedding where you need
    /// the server loop to be joinable.
    pub fn run_transport_returning_with_cx<T>(self, cx: &Cx, transport: T)
    where
        T: Transport + Send + 'static,
    {
        self.init_rich_logging();

        let shared = SharedTransport::new(transport);
        let notification_sender = create_transport_notification_sender(shared.clone());

        let shared_recv = shared.clone();
        let shared_send = shared;
        self.run_loop_returning(
            cx,
            move |cx| shared_recv.recv(cx),
            move |cx, message| shared_send.send(cx, message),
            notification_sender,
        );
    }

    /// Runs the server on a custom transport and returns when the transport closes.
    ///
    /// This uses a request-scoped [`Cx`], but unlike [`run_transport`](Self::run_transport) it does
    /// not exit the process.
    pub fn run_transport_returning<T>(self, transport: T)
    where
        T: Transport + Send + 'static,
    {
        // Top-level server loop Cx (non-test). Per-request budgets are applied in `handle_request`.
        let cx = Cx::for_request();
        self.run_transport_returning_with_cx(&cx, transport);
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

    // =========================================================================
    // HTTP Server — turnkey Streamable HTTP transport
    // =========================================================================

    /// Runs the server on HTTP transport, listening on the given address.
    ///
    /// This is the HTTP equivalent of [`run_stdio`](Self::run_stdio). It binds a
    /// TCP listener, accepts connections, and dispatches MCP JSON-RPC requests
    /// over HTTP.
    ///
    /// # Routes
    ///
    /// | Method  | Path       | Description                              |
    /// |---------|------------|------------------------------------------|
    /// | POST    | `/mcp`     | MCP JSON-RPC handler                     |
    /// | GET     | `/health`  | Health check (`{"status": "ok"}`)        |
    /// | OPTIONS | `/mcp`     | CORS preflight (via `HttpRequestHandler`) |
    ///
    /// # Example
    ///
    /// ```ignore
    /// Server::new("my-server", "1.0.0")
    ///     .tool(my_tool)
    ///     .build()
    ///     .run_http("0.0.0.0:3000");
    /// ```
    pub fn run_http(self, addr: impl Into<String>) -> ! {
        let cx = Cx::for_request();
        self.run_http_with_cx(&cx, addr)
    }

    /// Runs the server on HTTP with a provided [`Cx`].
    ///
    /// This allows integration with a real asupersync runtime.
    pub fn run_http_with_cx(self, cx: &Cx, addr: impl Into<String>) -> ! {
        self.run_http_accept_loop(cx, addr.into(), false);
        // run_http_accept_loop only returns when `returning` is true.
        unreachable!()
    }

    /// Runs the server on HTTP and returns when the listener closes or the [`Cx`]
    /// is cancelled.
    ///
    /// Unlike [`run_http`](Self::run_http), this does **not** call
    /// `std::process::exit` on shutdown. This is useful for tests and embedding.
    pub fn run_http_returning(self, addr: impl Into<String>) {
        let cx = Cx::for_request();
        self.run_http_returning_with_cx(&cx, addr);
    }

    /// Full control: custom [`Cx`] + returns on shutdown.
    pub fn run_http_returning_with_cx(self, cx: &Cx, addr: impl Into<String>) {
        self.run_http_accept_loop(cx, addr.into(), true);
    }

    /// Core HTTP accept loop shared by all `run_http*` variants.
    ///
    /// When `returning` is `false` the method calls `std::process::exit` on
    /// shutdown (matching the behaviour of the stdio/transport family).
    ///
    /// Each accepted connection is handled in its own thread, enabling
    /// concurrent tool dispatch across HTTP connections. The number of
    /// concurrent connections is bounded by `HttpServerConfig::max_connections`.
    #[allow(clippy::too_many_lines)]
    fn run_http_accept_loop(self, cx: &Cx, addr: String, returning: bool) {
        self.init_rich_logging();

        // Bind the TCP listener.
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                error!(target: targets::TRANSPORT, "Failed to bind HTTP listener on {}: {}", addr, e);
                if returning {
                    return;
                }
                std::process::exit(1);
            }
        };

        // Poll accept in nonblocking mode so cancellation/shutdown can be
        // observed promptly even when no clients are connecting.
        let _ = listener.set_nonblocking(true);

        info!(target: targets::SERVER, "HTTP server listening on {}", addr);

        // Extract http_config paths before wrapping self in Arc.
        let mcp_path = self.http_config.mcp_path.clone();
        let health_path = self.http_config.health_path.clone();
        let max_connections = self.http_config.max_connections;

        // Set up per-server state shared across connections.
        let session = Arc::new(Mutex::new(Session::new(
            self.info.clone(),
            self.capabilities.clone(),
        )));

        // Notification sender — for HTTP we log notifications since there is no
        // persistent outbound channel per connection.
        let notification_sender: NotificationSender = Arc::new(|request: JsonRpcRequest| {
            log::debug!(
                target: targets::SERVER,
                "HTTP notification (not deliverable to client): {}",
                request.method
            );
        });

        // Request sender for bidirectional communication.
        let request_sender = Arc::new({
            let send_fn: bidirectional::TransportSendFn = Arc::new(|_message| {
                // HTTP is request/response — server-to-client requests are not
                // deliverable.  Log and drop.
                Err("HTTP transport does not support server-to-client requests".into())
            });
            bidirectional::RequestSender::new(self.pending_requests.clone(), send_fn)
        });

        // Track connection opened.
        if let Some(ref stats) = self.stats {
            stats.connection_opened();
        }

        // Render startup banner (with HTTP transport name).
        if self.console_config.show_banner && !banner_suppressed() {
            self.render_http_startup_banner(&addr);
        }

        // Run startup hook.
        if !self.run_startup_hook() {
            error!(target: targets::SERVER, "Startup hook failed");
            if returning {
                self.graceful_shutdown_returning();
                return;
            }
            self.graceful_shutdown(1);
        }

        // Build the HTTP request handler with the server's config (or default).
        let http_handler = Arc::new(HttpRequestHandler::new());

        // Traffic renderer.
        let traffic_renderer = Arc::new(if self.console_config.show_request_traffic {
            let mut renderer = RequestResponseRenderer::new(self.console_config.resolve_context());
            renderer.truncate_at = self.console_config.truncate_at;
            match self.console_config.traffic_verbosity {
                TrafficVerbosity::None => {}
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
        });

        // Wrap self in Arc for sharing across connection handler threads.
        let server = Arc::new(self);

        // Active connection counter for max_connections enforcement.
        let active_connections = Arc::new(AtomicUsize::new(0));

        // Accept loop — each connection is handled in its own thread.
        loop {
            if cx.is_cancel_requested() {
                info!(target: targets::SERVER, "Cancellation requested, shutting down HTTP server");
                if returning {
                    server.graceful_shutdown_returning();
                    return;
                }
                server.graceful_shutdown(0);
            }

            let (stream, peer_addr) = match listener.accept() {
                Ok(pair) => pair,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Non-blocking timeout — check cancellation and retry.
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => {
                    error!(target: targets::TRANSPORT, "Failed to accept connection: {}", e);
                    continue;
                }
            };

            // Enforce max_connections.
            let current = active_connections.load(Ordering::Relaxed);
            if current >= max_connections {
                debug!(
                    target: targets::TRANSPORT,
                    "Rejecting connection from {} (max_connections {} reached)",
                    peer_addr,
                    max_connections
                );
                // Write a 503 Service Unavailable and close.
                if let Ok(reader_stream) = stream.try_clone() {
                    let mut http_transport =
                        HttpTransport::new(BufReader::new(reader_stream), BufWriter::new(stream));
                    let _ = http_transport.write_response(
                        &HttpResponse::new(HttpStatus::SERVICE_UNAVAILABLE)
                            .with_json(&serde_json::json!({"error": "too many connections"})),
                    );
                }
                continue;
            }

            debug!(
                target: targets::TRANSPORT,
                "Accepted HTTP connection from {}",
                peer_addr
            );

            // The listener is nonblocking so the accepted socket may inherit
            // that mode on some platforms; force blocking reads for
            // HttpTransport's request/response flow.
            let _ = stream.set_nonblocking(false);

            // Clone shared state for the connection handler thread.
            let server = Arc::clone(&server);
            let session = Arc::clone(&session);
            let notification_sender = Arc::clone(&notification_sender);
            let request_sender = Arc::clone(&request_sender);
            let http_handler = Arc::clone(&http_handler);
            let traffic_renderer = Arc::clone(&traffic_renderer);
            let active_connections = Arc::clone(&active_connections);
            let mcp_path = mcp_path.clone();
            let health_path = health_path.clone();
            let conn_cx = cx.clone();

            // Increment active connection count.
            active_connections.fetch_add(1, Ordering::Relaxed);

            // Spawn a thread to handle this connection concurrently.
            std::thread::spawn(move || {
                // Ensure connection count is decremented when this thread exits.
                struct ConnectionGuard(Arc<AtomicUsize>);
                impl Drop for ConnectionGuard {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                let _guard = ConnectionGuard(active_connections);

                // Read the HTTP request from the connection.
                let reader = BufReader::new(match stream.try_clone() {
                    Ok(s) => s,
                    Err(e) => {
                        error!(target: targets::TRANSPORT, "Failed to clone TCP stream: {}", e);
                        return;
                    }
                });
                let writer = BufWriter::new(stream);
                let mut http_transport: HttpTransport<
                    BufReader<std::net::TcpStream>,
                    BufWriter<std::net::TcpStream>,
                > = HttpTransport::new(reader, writer);

                let http_request = match http_transport.read_request() {
                    Ok(req) => req,
                    Err(e) => {
                        debug!(target: targets::TRANSPORT, "Failed to read HTTP request: {}", e);
                        return;
                    }
                };

                // Route by path and method.
                let response = if http_request.path == health_path
                    && http_request.method == HttpMethod::Get
                {
                    // Health-check endpoint.
                    HttpResponse::ok().with_json(&serde_json::json!({"status": "ok"}))
                } else if http_request.path == mcp_path
                    && http_request.method == HttpMethod::Options
                {
                    // CORS preflight.
                    http_handler.handle_options(&http_request)
                } else if http_request.path == mcp_path && http_request.method == HttpMethod::Post {
                    // MCP JSON-RPC handler.
                    server.handle_http_mcp_request(
                        &conn_cx,
                        &session,
                        &http_handler,
                        &http_request,
                        &notification_sender,
                        &request_sender,
                        &traffic_renderer,
                    )
                } else {
                    // 404 for anything else.
                    HttpResponse::new(HttpStatus::NOT_FOUND)
                        .with_json(&serde_json::json!({"error": "not found"}))
                };

                // Write the response.
                if let Err(e) = http_transport.write_response(&response) {
                    debug!(target: targets::TRANSPORT, "Failed to write HTTP response: {}", e);
                }
            });
        }
    }

    /// Processes a single MCP JSON-RPC request received over HTTP.
    fn handle_http_mcp_request(
        &self,
        cx: &Cx,
        session: &Arc<Mutex<Session>>,
        http_handler: &HttpRequestHandler,
        http_request: &HttpRequest,
        notification_sender: &NotificationSender,
        request_sender: &bidirectional::RequestSender,
        traffic_renderer: &Option<RequestResponseRenderer>,
    ) -> HttpResponse {
        // Parse the JSON-RPC request from the HTTP body.
        let json_rpc = match http_handler.parse_request(http_request) {
            Ok(r) => r,
            Err(e) => {
                debug!(target: targets::TRANSPORT, "Invalid MCP request: {}", e);
                return http_handler
                    .error_response(HttpStatus::BAD_REQUEST, &format!("Invalid request: {e}"));
            }
        };

        // Log request traffic.
        if let Some(renderer) = traffic_renderer {
            renderer.render_request(&json_rpc, console());
        }

        // Track bytes received.
        if let Some(ref stats) = self.stats {
            if let Ok(json) = serde_json::to_string(&json_rpc) {
                stats.add_bytes_received(json.len() as u64 + 1);
            }
        }

        let start_time = Instant::now();

        let execution_mode = HttpRequestExecutionMode::for_request(&self.router, &json_rpc);

        // Dispatch through the server's handler. Concurrent HTTP methods take
        // a lock-free view of session metadata while sharing live session
        // state; request-local auth now lives on McpContext instead of being
        // written into SessionState.
        let response_opt = match execution_mode {
            HttpRequestExecutionMode::ConcurrentReadOnly => {
                let session_view = {
                    let session_guard = match session.lock() {
                        Ok(g) => g,
                        Err(poisoned) => {
                            error!(target: targets::SERVER, "Session lock poisoned, recovering");
                            poisoned.into_inner()
                        }
                    };
                    SessionView::from_session(&session_guard)
                };
                self.handle_request_with_view(
                    cx,
                    &session_view,
                    json_rpc,
                    notification_sender,
                    request_sender,
                )
            }
            HttpRequestExecutionMode::ExclusiveSession => {
                let mut session_guard = match session.lock() {
                    Ok(g) => g,
                    Err(poisoned) => {
                        error!(target: targets::SERVER, "Session lock poisoned, recovering");
                        poisoned.into_inner()
                    }
                };
                self.handle_request(
                    cx,
                    &mut session_guard,
                    json_rpc,
                    notification_sender,
                    request_sender,
                )
            }
        };

        let duration = start_time.elapsed();

        match response_opt {
            Some(json_rpc_response) => {
                // Log response traffic.
                if let Some(renderer) = traffic_renderer {
                    renderer.render_response(&json_rpc_response, Some(duration), console());
                }

                // Track bytes sent.
                if let Some(ref stats) = self.stats {
                    if let Ok(json) = serde_json::to_string(&json_rpc_response) {
                        stats.add_bytes_sent(json.len() as u64 + 1);
                    }
                }

                let origin = http_request.header("origin");
                http_handler.create_response(&json_rpc_response, origin)
            }
            None => {
                // Notification (no response expected) — return 202 Accepted.
                HttpResponse::new(HttpStatus::ACCEPTED)
            }
        }
    }

    /// Renders the HTTP-specific startup banner.
    fn render_http_startup_banner(&self, addr: &str) {
        let render = || {
            let transport_label = format!("http://{addr}");
            let mut banner = StartupBanner::new(&self.info.name, &self.info.version)
                .tools(self.router.tools_count())
                .resources(self.router.resources_count())
                .prompts(self.router.prompts_count())
                .transport(&transport_label);

            if let Some(desc) = self.instructions.as_deref().filter(|d| !d.is_empty()) {
                banner = banner.description(desc);
            }

            match self.console_config.banner_style {
                BannerStyle::Full => banner.render(console()),
                BannerStyle::Compact | BannerStyle::Minimal => {
                    banner.no_logo().render(console());
                }
                BannerStyle::None => {}
            }
        };

        if let Err(err) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(render)) {
            eprintln!("Warning: banner rendering failed: {err:?}");
        }
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

    /// Performs graceful shutdown without exiting the process.
    ///
    /// This is intended for embedding/testing scenarios where the server loop is
    /// running on a thread and the caller wants to `join()` it.
    fn graceful_shutdown_returning(&self) {
        self.cancel_active_requests(CancelKind::Shutdown, true);
        self.run_shutdown_hook();
        if let Some(ref stats) = self.stats {
            stats.connection_closed();
        }
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
            let send_cx = cx.clone();
            let send_fn: bidirectional::TransportSendFn = Arc::new(move |message| {
                let mut guard = send_clone
                    .lock()
                    .map_err(|e| format!("Lock poisoned: {}", e))?;
                guard(&send_cx, message).map_err(|e| format!("Send failed: {}", e))
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
                    let mut guard = match send.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => {
                            error!(
                                target: targets::TRANSPORT,
                                "Send channel lock poisoned; continuing with inner guard"
                            );
                            poisoned.into_inner()
                        }
                    };
                    guard(cx, &JsonRpcMessage::Response(response))
                };
                if let Err(e) = send_result {
                    error!(target: targets::TRANSPORT, "Failed to send response: {}", e);
                }
            }
        }
    }

    /// Shared server loop for embedding/testing, returning on shutdown instead of exiting.
    ///
    /// This is intentionally separate from [`run_loop`](Self::run_loop) because the primary server
    /// entrypoints use `std::process::exit` on shutdown for subprocess use-cases.
    #[allow(clippy::too_many_lines)]
    fn run_loop_returning<R, S>(
        self,
        cx: &Cx,
        mut recv: R,
        send: S,
        notification_sender: NotificationSender,
    ) where
        R: FnMut(&Cx) -> Result<JsonRpcMessage, TransportError>,
        S: FnMut(&Cx, &JsonRpcMessage) -> Result<(), TransportError> + Send + Sync + 'static,
    {
        let mut session = Session::new(self.info.clone(), self.capabilities.clone());

        // Wrap send in Arc<Mutex> for shared access from bidirectional requests
        let send = Arc::new(Mutex::new(send));

        // Create a RequestSender for bidirectional communication
        let request_sender = {
            let send_clone = send.clone();
            let send_cx = cx.clone();
            let send_fn: bidirectional::TransportSendFn = Arc::new(move |message| {
                let mut guard = send_clone
                    .lock()
                    .map_err(|e| format!("Lock poisoned: {}", e))?;
                guard(&send_cx, message).map_err(|e| format!("Send failed: {}", e))
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
            error!(target: targets::SERVER, "Startup hook failed, stopping");
            self.graceful_shutdown_returning();
            return;
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
                info!(target: targets::SERVER, "Cancellation requested, stopping");
                self.graceful_shutdown_returning();
                return;
            }

            // Receive next message
            let message = match recv(cx) {
                Ok(msg) => msg,
                Err(TransportError::Closed) => {
                    self.graceful_shutdown_returning();
                    return;
                }
                Err(TransportError::Cancelled) => {
                    info!(target: targets::SERVER, "Transport cancelled");
                    self.graceful_shutdown_returning();
                    return;
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
                        debug!(
                            target: targets::SERVER,
                            "Received unexpected response: {:?}",
                            response.id
                        );
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
                    let mut guard = match send.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => {
                            error!(
                                target: targets::TRANSPORT,
                                "Send channel lock poisoned; continuing with inner guard"
                            );
                            poisoned.into_inner()
                        }
                    };
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

        let _active_guard = match id.clone() {
            Some(request_id) => {
                match ActiveRequestGuard::try_new(
                    &self.active_requests,
                    request_id.clone(),
                    request_cx.clone(),
                ) {
                    Ok(guard) => Some(guard),
                    Err(duplicate_id) => {
                        if let Some(ref stats) = self.stats {
                            stats.record_request(&method, start_time.elapsed(), false);
                        }
                        let message = format!(
                            "Request id {duplicate_id} is already active; wait for the earlier request to finish before reusing it"
                        );
                        return Some(JsonRpcResponse::error(
                            Some(request_id),
                            JsonRpcError {
                                code: McpErrorCode::InvalidRequest.into(),
                                message,
                                data: None,
                            },
                        ));
                    }
                }
            }
            None => None,
        };

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

        // We only reach here if `is_notification` is false, which implies `id` is present.
        // Use `?` to avoid `unwrap()` and keep the control-flow explicit.
        let response_id = id.clone()?;

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

    fn handle_request_with_view(
        &self,
        cx: &Cx,
        session: &SessionView,
        request: JsonRpcRequest,
        notification_sender: &NotificationSender,
        request_sender: &bidirectional::RequestSender,
    ) -> Option<JsonRpcResponse> {
        let id = request.id.clone();
        let method = request.method.clone();
        let is_notification = id.is_none();

        let start_time = Instant::now();
        let request_id = request_id_to_u64(id.as_ref());
        let budget = self.create_request_budget();

        if budget.is_exhausted() {
            if let Some(ref stats) = self.stats {
                stats.record_request(&method, start_time.elapsed(), false);
            }
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

        let _active_guard = match id.clone() {
            Some(request_id) => {
                match ActiveRequestGuard::try_new(
                    &self.active_requests,
                    request_id.clone(),
                    request_cx.clone(),
                ) {
                    Ok(guard) => Some(guard),
                    Err(duplicate_id) => {
                        if let Some(ref stats) = self.stats {
                            stats.record_request(&method, start_time.elapsed(), false);
                        }
                        let message = format!(
                            "Request id {duplicate_id} is already active; wait for the earlier request to finish before reusing it"
                        );
                        return Some(JsonRpcResponse::error(
                            Some(request_id),
                            JsonRpcError {
                                code: McpErrorCode::InvalidRequest.into(),
                                message,
                                data: None,
                            },
                        ));
                    }
                }
            }
            None => None,
        };

        let result = self.dispatch_read_only_http_method(
            &request_cx,
            session,
            request,
            request_id,
            &budget,
            notification_sender,
            request_sender,
        );

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

        let response_id = id.clone()?;

        match result {
            Ok(value) => Some(JsonRpcResponse::success(response_id, value)),
            Err(e) => {
                if self.mask_error_details && e.is_internal() {
                    fastmcp_core::logging::error!(
                        target: targets::HANDLER,
                        "Request '{}' failed (masked in response): {}",
                        method,
                        e
                    );
                }

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
            // Budget deadlines are absolute (`Time` since runtime epoch). We use `wall_now()`
            // so timeouts work even when running outside a full asupersync scheduler.
            let now = wall_now();
            let timeout_ns = self.request_timeout_secs.saturating_mul(1_000_000_000);
            let deadline = now.saturating_add_nanos(timeout_ns);
            Budget::new().with_deadline(deadline)
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
        // Deadline exhaustion is time-based and must be checked against current time.
        if budget.is_past_deadline(wall_now()) {
            cx.cancel_fast(CancelKind::Deadline);
            return Err(McpError::new(
                McpErrorCode::RequestCancelled,
                "Request timeout exceeded",
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

        let mut mw_ctx = McpContext::with_state(cx.clone(), request_id, session.state().clone());
        let request_auth = if self.should_authenticate(&request.method) {
            let auth_request = AuthRequest {
                method: &request.method,
                params: request.params.as_ref(),
                request_id,
            };
            match self.authenticate_request(cx, request_id, session, auth_request) {
                Ok(auth) => Some(auth),
                Err(err) => {
                    let err = self.apply_global_middleware_error(&mw_ctx, &request, err);
                    let result = Err(err);
                    self.maybe_emit_log_notification(
                        session,
                        notification_sender,
                        &request.method,
                        &result,
                    );
                    return result;
                }
            }
        } else {
            None
        };
        if let Some(auth) = request_auth.clone() {
            mw_ctx = mw_ctx.with_auth(auth);
        }

        // Middleware: on_request
        // We use a temporary context derived from the request context for middleware
        // so they can access session state, request auth, and share the request's lifecycle.
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

        let dispatch_auth = mw_ctx.auth();

        // Everything after middleware entry must flow through `result` so that:
        // - `on_response` runs for successes in reverse middleware order
        // - `on_error` runs for handler/middleware errors in reverse middleware order
        //
        // Without this, `?` would early-return from `dispatch_method` and bypass middleware error
        // rewriting, contradicting the ordering semantics documented in `middleware.rs`.
        let result: Result<serde_json::Value, McpError> = (|| {
            let method = &request.method;
            let params = request.params.clone();

            // Create bidirectional senders based on client capabilities
            let bidirectional_senders = self.create_bidirectional_senders(session, request_sender);

            match method.as_str() {
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
                    let result =
                        self.router
                            .handle_tools_list(cx, params, Some(session.state()))?;
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
                        dispatch_auth.clone(),
                        Some(notification_sender),
                        bidirectional_senders.as_ref(),
                    )?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                "resources/list" => {
                    let params: ListResourcesParams = parse_params_or_default(params)?;
                    let result =
                        self.router
                            .handle_resources_list(cx, params, Some(session.state()))?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                "resources/templates/list" => {
                    let params: ListResourceTemplatesParams = parse_params_or_default(params)?;
                    let result = self.router.handle_resource_templates_list(
                        cx,
                        params,
                        Some(session.state()),
                    )?;
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
                        dispatch_auth.clone(),
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
                    let result =
                        self.router
                            .handle_prompts_list(cx, params, Some(session.state()))?;
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
                        dispatch_auth.clone(),
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
            }
        })();

        let final_result = match result {
            Ok(v) => self.apply_middleware_response(&entered_middleware, &mw_ctx, &request, v),
            Err(e) => Err(self.apply_middleware_error(&entered_middleware, &mw_ctx, &request, e)),
        };

        self.maybe_emit_log_notification(
            session,
            notification_sender,
            &request.method,
            &final_result,
        );

        final_result
    }

    fn dispatch_read_only_http_method(
        &self,
        cx: &Cx,
        session: &SessionView,
        request: JsonRpcRequest,
        request_id: u64,
        budget: &Budget,
        notification_sender: &NotificationSender,
        request_sender: &bidirectional::RequestSender,
    ) -> Result<serde_json::Value, McpError> {
        if cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }

        if budget.is_exhausted() {
            return Err(McpError::new(
                McpErrorCode::RequestCancelled,
                "Request budget exhausted",
            ));
        }

        if budget.is_past_deadline(wall_now()) {
            cx.cancel_fast(CancelKind::Deadline);
            return Err(McpError::new(
                McpErrorCode::RequestCancelled,
                "Request timeout exceeded",
            ));
        }

        if !session.initialized && request.method != "initialize" && request.method != "ping" {
            return Err(McpError::invalid_request(
                "Server not initialized. Client must send 'initialize' first.",
            ));
        }

        if let Some(task_manager) = &self.task_manager {
            task_manager.set_notification_sender(Arc::clone(notification_sender));
        }

        let mut mw_ctx = McpContext::with_state(cx.clone(), request_id, session.state.clone());
        let request_auth = if self.should_authenticate(&request.method) {
            let auth_request = AuthRequest {
                method: &request.method,
                params: request.params.as_ref(),
                request_id,
            };
            match self.authenticate_request_with_state(cx, request_id, &session.state, auth_request)
            {
                Ok(auth) => Some(auth),
                Err(err) => {
                    let err = self.apply_global_middleware_error(&mw_ctx, &request, err);
                    let result = Err(err);
                    self.maybe_emit_log_notification_for_level(
                        session.log_level,
                        notification_sender,
                        &request.method,
                        &result,
                    );
                    return result;
                }
            }
        } else {
            None
        };
        if let Some(auth) = request_auth.clone() {
            mw_ctx = mw_ctx.with_auth(auth);
        }

        let mut entered_middleware: Vec<&dyn crate::Middleware> = Vec::new();

        for m in self.middleware.iter() {
            entered_middleware.push(m.as_ref());
            match m.on_request(&mw_ctx, &request) {
                Ok(crate::MiddlewareDecision::Continue) => {}
                Ok(crate::MiddlewareDecision::Respond(v)) => {
                    let result =
                        self.apply_middleware_response(&entered_middleware, &mw_ctx, &request, v);
                    self.maybe_emit_log_notification_for_level(
                        session.log_level,
                        notification_sender,
                        &request.method,
                        &result,
                    );
                    return result;
                }
                Err(e) => {
                    let err =
                        self.apply_middleware_error(&entered_middleware, &mw_ctx, &request, e);
                    let result = Err(err);
                    self.maybe_emit_log_notification_for_level(
                        session.log_level,
                        notification_sender,
                        &request.method,
                        &result,
                    );
                    return result;
                }
            }
        }

        let dispatch_auth = mw_ctx.auth();

        let result: Result<serde_json::Value, McpError> = (|| {
            let method = &request.method;
            let params = request.params.clone();
            let bidirectional_senders =
                self.create_bidirectional_senders_from_view(session, request_sender);

            match method.as_str() {
                "tools/call" => {
                    let params: CallToolParams = parse_params(params)?;
                    let result = self.router.handle_tools_call(
                        cx,
                        request_id,
                        params,
                        budget,
                        session.state.clone(),
                        dispatch_auth.clone(),
                        Some(notification_sender),
                        bidirectional_senders.as_ref(),
                    )?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                "resources/read" => {
                    let params: ReadResourceParams = parse_params(params)?;
                    let result = self.router.handle_resources_read(
                        cx,
                        request_id,
                        &params,
                        budget,
                        session.state.clone(),
                        dispatch_auth.clone(),
                        Some(notification_sender),
                        bidirectional_senders.as_ref(),
                    )?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                "prompts/get" => {
                    let params: GetPromptParams = parse_params(params)?;
                    let result = self.router.handle_prompts_get(
                        cx,
                        request_id,
                        params,
                        budget,
                        session.state.clone(),
                        dispatch_auth.clone(),
                        Some(notification_sender),
                        bidirectional_senders.as_ref(),
                    )?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                _ => Err(McpError::method_not_found(method)),
            }
        })();

        let final_result = match result {
            Ok(v) => self.apply_middleware_response(&entered_middleware, &mw_ctx, &request, v),
            Err(e) => Err(self.apply_middleware_error(&entered_middleware, &mw_ctx, &request, e)),
        };

        self.maybe_emit_log_notification_for_level(
            session.log_level,
            notification_sender,
            &request.method,
            &final_result,
        );

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

    fn apply_global_middleware_error(
        &self,
        ctx: &McpContext,
        request: &JsonRpcRequest,
        error: McpError,
    ) -> McpError {
        let mut err = error;
        for m in self.middleware.iter().rev() {
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
        self.create_bidirectional_senders_from_capabilities(
            session.supports_sampling(),
            session.supports_elicitation(),
            request_sender,
        )
    }

    fn create_bidirectional_senders_from_view(
        &self,
        session: &SessionView,
        request_sender: &bidirectional::RequestSender,
    ) -> Option<handler::BidirectionalSenders> {
        self.create_bidirectional_senders_from_capabilities(
            session.supports_sampling,
            session.supports_elicitation,
            request_sender,
        )
    }

    fn create_bidirectional_senders_from_capabilities(
        &self,
        supports_sampling: bool,
        supports_elicitation: bool,
        request_sender: &bidirectional::RequestSender,
    ) -> Option<handler::BidirectionalSenders> {
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

    fn authenticate_request_with_state(
        &self,
        cx: &Cx,
        request_id: u64,
        session_state: &SessionState,
        request: AuthRequest<'_>,
    ) -> Result<AuthContext, McpError> {
        let Some(provider) = &self.auth_provider else {
            return Ok(AuthContext::anonymous());
        };

        let ctx = McpContext::with_state(cx.clone(), request_id, session_state.clone());
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

    fn emit_log_notification_for_level(
        &self,
        min_level: Option<LogLevel>,
        sender: &NotificationSender,
        level: LogLevel,
        message: impl Into<String>,
    ) {
        let Some(min_level) = min_level else {
            return;
        };
        if Self::log_level_rank(level) < Self::log_level_rank(min_level) {
            return;
        }

        let ts = chrono::Utc::now().to_rfc3339();
        let text = format!("{ts} {}", message.into());
        let params = LogMessageParams {
            level,
            logger: Some("fastmcp_rust::server".to_string()),
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

    fn emit_log_notification(
        &self,
        session: &Session,
        sender: &NotificationSender,
        level: LogLevel,
        message: impl Into<String>,
    ) {
        self.emit_log_notification_for_level(session.log_level(), sender, level, message);
    }

    fn maybe_emit_log_notification_for_level(
        &self,
        min_level: Option<LogLevel>,
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
        self.emit_log_notification_for_level(min_level, sender, level, message);
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
    fn try_new(
        map: &'a Mutex<HashMap<RequestId, ActiveRequest>>,
        id: RequestId,
        cx: Cx,
    ) -> Result<Self, RequestId> {
        let completion = Arc::new(RequestCompletion::new());
        let entry = ActiveRequest::new(cx, completion.clone());
        let mut guard = map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.contains_key(&id) {
            fastmcp_core::logging::warn!(
                target: targets::SESSION,
                "Duplicate active requestId={} rejected while an earlier request is still running",
                id
            );
            return Err(id);
        }
        guard.insert(id.clone(), entry);
        Ok(Self {
            map,
            id,
            completion,
        })
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
    let cx = Cx::for_request();

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

#[cfg(test)]
mod lib_unit_tests {
    use super::*;
    use fastmcp_derive::tool;
    use fastmcp_protocol::{CallToolResult, Content};
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    #[derive(Debug, Default)]
    struct HttpOverlapMetrics {
        current: AtomicUsize,
        max: AtomicUsize,
    }

    static HTTP_OVERLAP_METRICS: OnceLock<HttpOverlapMetrics> = OnceLock::new();
    static HTTP_OVERLAP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn http_overlap_metrics() -> &'static HttpOverlapMetrics {
        HTTP_OVERLAP_METRICS.get_or_init(HttpOverlapMetrics::default)
    }

    fn http_overlap_lock() -> &'static Mutex<()> {
        HTTP_OVERLAP_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn reset_http_overlap_metrics() {
        let metrics = http_overlap_metrics();
        metrics.current.store(0, Ordering::SeqCst);
        metrics.max.store(0, Ordering::SeqCst);
    }

    fn test_request_sender() -> RequestSender {
        let pending = Arc::new(PendingRequests::new());
        let send_fn: bidirectional::TransportSendFn =
            Arc::new(|message| Err(format!("unexpected outbound message in test: {message:?}")));
        RequestSender::new(pending, send_fn)
    }

    fn http_json_request(method: &str, params: serde_json::Value, id: i64) -> HttpRequest {
        let request = JsonRpcRequest::new(method, Some(params), id);
        HttpRequest::new(HttpMethod::Post, "/mcp")
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_vec(&request).expect("serialize JSON-RPC request"))
    }

    #[tool(
        name = "http_overlap_tool",
        description = "Records concurrent overlap for HTTP tests",
        annotations(read_only)
    )]
    fn http_overlap_tool(_ctx: &McpContext) -> String {
        let metrics = http_overlap_metrics();
        let current = metrics.current.fetch_add(1, Ordering::SeqCst) + 1;
        metrics.max.fetch_max(current, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(100));
        metrics.current.fetch_sub(1, Ordering::SeqCst);
        "overlap-ok".to_string()
    }

    #[tool(
        name = "http_auth_echo_tool_runtime",
        description = "Returns the request-scoped auth subject while recording overlap",
        annotations(read_only)
    )]
    fn http_auth_echo_tool_runtime(ctx: &McpContext) -> String {
        let metrics = http_overlap_metrics();
        let current = metrics.current.fetch_add(1, Ordering::SeqCst) + 1;
        metrics.max.fetch_max(current, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(100));
        metrics.current.fetch_sub(1, Ordering::SeqCst);
        ctx.auth()
            .and_then(|auth| auth.subject)
            .unwrap_or_else(|| "anonymous".to_string())
    }

    #[tool(
        name = "http_stateful_increment_tool",
        description = "Increments a session counter across HTTP requests"
    )]
    fn http_stateful_increment_tool(ctx: &McpContext) -> String {
        let count: i32 = ctx.get_state("http_counter").unwrap_or(0);
        let next = count + 1;
        assert!(ctx.set_state("http_counter", next));
        format!("Counter: {next}")
    }

    #[tool(
        name = "http_current_auth_subject_tool",
        description = "Returns the current request auth subject",
        annotations(read_only)
    )]
    fn http_current_auth_subject_tool(ctx: &McpContext) -> String {
        ctx.auth()
            .and_then(|auth| auth.subject)
            .unwrap_or_else(|| "anonymous".to_string())
    }

    #[tool(
        name = "http_current_auth_subject_exclusive_tool",
        description = "Returns the current request auth subject from the exclusive path"
    )]
    fn http_current_auth_subject_exclusive_tool(ctx: &McpContext) -> String {
        ctx.auth()
            .and_then(|auth| auth.subject)
            .unwrap_or_else(|| "anonymous".to_string())
    }

    #[derive(Debug, Clone)]
    struct CapturingAuthMiddleware {
        seen: Arc<Mutex<Vec<(String, Option<String>)>>>,
    }

    impl Middleware for CapturingAuthMiddleware {
        fn on_request(
            &self,
            ctx: &McpContext,
            request: &JsonRpcRequest,
        ) -> McpResult<MiddlewareDecision> {
            self.seen
                .lock()
                .expect("captured auth middleware mutex should not be poisoned")
                .push((
                    request.method.clone(),
                    ctx.auth().and_then(|auth| auth.subject),
                ));
            Ok(MiddlewareDecision::Continue)
        }
    }

    #[derive(Debug, Clone)]
    struct OverridingAuthMiddleware {
        subject: &'static str,
    }

    impl Middleware for OverridingAuthMiddleware {
        fn on_request(
            &self,
            ctx: &McpContext,
            _request: &JsonRpcRequest,
        ) -> McpResult<MiddlewareDecision> {
            ctx.set_auth(AuthContext::with_subject(self.subject));
            Ok(MiddlewareDecision::Continue)
        }
    }

    #[derive(Debug)]
    struct AlwaysFailAuthProvider;

    impl AuthProvider for AlwaysFailAuthProvider {
        fn authenticate(
            &self,
            _ctx: &McpContext,
            _request: AuthRequest<'_>,
        ) -> McpResult<AuthContext> {
            Err(McpError::invalid_request("auth failed"))
        }
    }

    #[derive(Debug, Clone)]
    struct RewritingErrorMiddleware;

    impl Middleware for RewritingErrorMiddleware {
        fn on_error(
            &self,
            _ctx: &McpContext,
            _request: &JsonRpcRequest,
            error: McpError,
        ) -> McpError {
            McpError::new(error.code, format!("rewritten: {}", error.message))
        }
    }

    // ── parse_params ────────────────────────────────────────────────

    #[test]
    fn parse_params_none_returns_error() {
        let result = parse_params::<serde_json::Value>(None);
        let err = result.unwrap_err();
        assert!(err.message.contains("Missing required parameters"));
    }

    #[test]
    fn parse_params_invalid_json_returns_error() {
        // Pass a string where a struct is expected
        let result = parse_params::<ListToolsParams>(Some(serde_json::json!("not_an_object")));
        assert!(result.is_err());
    }

    #[test]
    fn parse_params_valid_json_succeeds() {
        let result = parse_params::<ReadResourceParams>(Some(serde_json::json!({"uri": "x://y"})));
        let params = result.unwrap();
        assert_eq!(params.uri, "x://y");
    }

    // ── parse_params_or_default ─────────────────────────────────────

    #[test]
    fn parse_params_or_default_none_returns_default() {
        let result = parse_params_or_default::<ListToolsParams>(None);
        let params = result.unwrap();
        assert!(params.cursor.is_none());
    }

    #[test]
    fn parse_params_or_default_invalid_json_returns_error() {
        let result =
            parse_params_or_default::<ListToolsParams>(Some(serde_json::json!("bad_input")));
        assert!(result.is_err());
    }

    #[test]
    fn parse_params_or_default_valid_json_succeeds() {
        let result =
            parse_params_or_default::<ListToolsParams>(Some(serde_json::json!({"cursor": "abc"})));
        let params = result.unwrap();
        assert_eq!(params.cursor.as_deref(), Some("abc"));
    }

    // ── request_id_to_u64 ───────────────────────────────────────────

    #[test]
    fn request_id_to_u64_number() {
        let id = RequestId::Number(42);
        assert_eq!(request_id_to_u64(Some(&id)), 42);
    }

    #[test]
    fn request_id_to_u64_string() {
        let id = RequestId::String("req-123".to_string());
        let result = request_id_to_u64(Some(&id));
        assert_ne!(result, 0);
    }

    #[test]
    fn request_id_to_u64_none() {
        assert_eq!(request_id_to_u64(None), 0);
    }

    // ── stable_hash_request_id ──────────────────────────────────────

    #[test]
    fn stable_hash_is_deterministic() {
        let h1 = stable_hash_request_id("test");
        let h2 = stable_hash_request_id("test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn stable_hash_never_returns_zero() {
        // Empty string and various inputs should never produce 0
        assert_ne!(stable_hash_request_id(""), 0);
        assert_ne!(stable_hash_request_id("a"), 0);
    }

    #[test]
    fn stable_hash_different_inputs_differ() {
        let h1 = stable_hash_request_id("alpha");
        let h2 = stable_hash_request_id("beta");
        assert_ne!(h1, h2);
    }

    // ── RequestCompletion ───────────────────────────────────────────

    #[test]
    fn request_completion_new_is_not_done() {
        let rc = RequestCompletion::new();
        assert!(!rc.is_done());
    }

    #[test]
    fn request_completion_mark_done_sets_done() {
        let rc = RequestCompletion::new();
        rc.mark_done();
        assert!(rc.is_done());
    }

    #[test]
    fn request_completion_mark_done_idempotent() {
        let rc = RequestCompletion::new();
        rc.mark_done();
        rc.mark_done(); // should not panic
        assert!(rc.is_done());
    }

    #[test]
    fn request_completion_wait_timeout_returns_true_if_done() {
        let rc = RequestCompletion::new();
        rc.mark_done();
        assert!(rc.wait_timeout(Duration::from_millis(10)));
    }

    #[test]
    fn request_completion_wait_timeout_returns_false_if_not_done() {
        let rc = RequestCompletion::new();
        assert!(!rc.wait_timeout(Duration::from_millis(10)));
    }

    // ── DuplicateBehavior ───────────────────────────────────────────

    #[test]
    fn duplicate_behavior_default_is_warn() {
        assert_eq!(DuplicateBehavior::default(), DuplicateBehavior::Warn);
    }

    #[test]
    fn duplicate_behavior_debug_and_clone() {
        let b = DuplicateBehavior::Error;
        let debug = format!("{:?}", b);
        assert!(debug.contains("Error"));
        let cloned = b;
        assert_eq!(cloned, DuplicateBehavior::Error);
    }

    #[test]
    fn duplicate_behavior_all_variants_are_distinct() {
        assert_ne!(DuplicateBehavior::Error, DuplicateBehavior::Warn);
        assert_ne!(DuplicateBehavior::Warn, DuplicateBehavior::Replace);
        assert_ne!(DuplicateBehavior::Replace, DuplicateBehavior::Ignore);
    }

    // ── LoggingConfig ───────────────────────────────────────────────

    #[test]
    fn logging_config_default_values() {
        let config = LoggingConfig::default();
        assert_eq!(config.level, Level::Info);
        assert!(config.timestamps);
        assert!(config.targets);
        assert!(!config.file_line);
    }

    // ── LifespanHooks ───────────────────────────────────────────────

    #[test]
    fn lifespan_hooks_new_has_no_hooks() {
        let hooks = LifespanHooks::new();
        assert!(hooks.on_startup.is_none());
        assert!(hooks.on_shutdown.is_none());
    }

    // ── log_level_rank ──────────────────────────────────────────────

    #[test]
    fn log_level_rank_ordering() {
        assert!(Server::log_level_rank(LogLevel::Debug) < Server::log_level_rank(LogLevel::Info));
        assert!(Server::log_level_rank(LogLevel::Info) < Server::log_level_rank(LogLevel::Warning));
        assert!(
            Server::log_level_rank(LogLevel::Warning) < Server::log_level_rank(LogLevel::Error)
        );
    }

    // ── ActiveRequestGuard ──────────────────────────────────────────

    #[test]
    fn active_request_guard_removes_on_drop() {
        let map = Mutex::new(HashMap::new());
        let cx = Cx::for_testing();
        let id = RequestId::Number(1);
        {
            let _guard = ActiveRequestGuard::try_new(&map, id.clone(), cx).expect("insert guard");
            assert_eq!(map.lock().unwrap().len(), 1);
        }
        // After drop, the entry should be removed
        assert_eq!(map.lock().unwrap().len(), 0);
    }

    #[test]
    fn active_request_guard_rejects_duplicate_request_id() {
        let map = Mutex::new(HashMap::new());
        let first = ActiveRequestGuard::try_new(&map, RequestId::Number(7), Cx::for_testing())
            .expect("first request should register");
        let duplicate = ActiveRequestGuard::try_new(&map, RequestId::Number(7), Cx::for_testing());
        assert!(
            duplicate.is_err(),
            "duplicate active request id must be rejected"
        );
        drop(first);
        assert!(map.lock().unwrap().is_empty());
    }

    // =========================================================================
    // Additional coverage tests (bd-cd79)
    // =========================================================================

    #[test]
    fn logging_config_debug_and_clone() {
        let config = LoggingConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("LoggingConfig"));
        assert!(debug.contains("Info"));

        let cloned = config.clone();
        assert_eq!(cloned.level, Level::Info);
        assert_eq!(cloned.timestamps, config.timestamps);
    }

    #[test]
    fn transport_lock_error_is_io() {
        let err = transport_lock_error();
        match err {
            TransportError::Io(io) => {
                assert!(io.to_string().contains("poisoned"));
            }
            other => panic!("expected Io variant, got: {other:?}"),
        }
    }

    #[test]
    fn lifespan_hooks_default_matches_new() {
        let default_hooks = LifespanHooks::default();
        let new_hooks = LifespanHooks::new();
        assert!(default_hooks.on_startup.is_none());
        assert!(default_hooks.on_shutdown.is_none());
        assert!(new_hooks.on_startup.is_none());
        assert!(new_hooks.on_shutdown.is_none());
    }

    #[test]
    fn request_completion_wait_resolves_on_concurrent_done() {
        use std::sync::Arc;
        use std::thread;

        let rc = Arc::new(RequestCompletion::new());
        let rc_clone = rc.clone();

        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            rc_clone.mark_done();
        });

        // Should resolve within the timeout because the other thread marks done
        assert!(rc.wait_timeout(Duration::from_secs(2)));
        handle.join().unwrap();
    }

    #[test]
    fn active_request_stores_region_id() {
        let cx = Cx::for_testing();
        let expected_region = cx.region_id();
        let completion = Arc::new(RequestCompletion::new());
        let ar = ActiveRequest::new(cx, completion);
        assert_eq!(ar.region_id, expected_region);
    }

    #[test]
    fn http_request_execution_mode_classifies_methods() {
        let mut router = Router::new();
        router.add_tool(HttpOverlapTool);
        router.add_tool(HttpStatefulIncrementTool);

        assert_eq!(
            HttpRequestExecutionMode::for_request(
                &router,
                &JsonRpcRequest::new(
                    "tools/call",
                    Some(serde_json::json!({
                        "name": "http_overlap_tool",
                        "arguments": {}
                    })),
                    1,
                ),
            ),
            HttpRequestExecutionMode::ConcurrentReadOnly
        );
        assert_eq!(
            HttpRequestExecutionMode::for_request(
                &router,
                &JsonRpcRequest::new(
                    "tools/call",
                    Some(serde_json::json!({
                        "name": "http_stateful_increment_tool",
                        "arguments": {}
                    })),
                    2,
                ),
            ),
            HttpRequestExecutionMode::ExclusiveSession
        );
        assert_eq!(
            HttpRequestExecutionMode::for_request(
                &router,
                &JsonRpcRequest::new("resources/read", None, 3),
            ),
            HttpRequestExecutionMode::ConcurrentReadOnly
        );
        assert_eq!(
            HttpRequestExecutionMode::for_request(
                &router,
                &JsonRpcRequest::new("prompts/get", None, 4)
            ),
            HttpRequestExecutionMode::ConcurrentReadOnly
        );

        assert_eq!(
            HttpRequestExecutionMode::for_request(
                &router,
                &JsonRpcRequest::new("initialize", None, 5)
            ),
            HttpRequestExecutionMode::ExclusiveSession
        );
        assert_eq!(
            HttpRequestExecutionMode::for_request(
                &router,
                &JsonRpcRequest::new("logging/setLevel", None, 6),
            ),
            HttpRequestExecutionMode::ExclusiveSession
        );
        assert_eq!(
            HttpRequestExecutionMode::for_request(
                &router,
                &JsonRpcRequest::new("resources/subscribe", None, 7),
            ),
            HttpRequestExecutionMode::ExclusiveSession
        );
    }

    #[test]
    fn http_read_only_requests_can_overlap_without_session_mutex_serialization() {
        let _guard = http_overlap_lock()
            .lock()
            .expect("http overlap test lock poisoned");
        reset_http_overlap_metrics();

        let server = Arc::new(
            Server::new("http-test-server", "1.0.0")
                .tool(HttpOverlapTool)
                .build(),
        );
        let session = Arc::new(Mutex::new(Session::new(
            server.info.clone(),
            server.capabilities.clone(),
        )));
        session.lock().expect("session lock poisoned").initialize(
            fastmcp_protocol::ClientInfo {
                name: "http-test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            fastmcp_protocol::ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let http_handler = Arc::new(HttpRequestHandler::new());
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let start = Arc::new(std::sync::Barrier::new(3));

        let run_request = |id| {
            let server = Arc::clone(&server);
            let session = Arc::clone(&session);
            let http_handler = Arc::clone(&http_handler);
            let notification_sender = Arc::clone(&notification_sender);
            let request_sender = request_sender.clone();
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                let cx = Cx::for_testing();
                let request = http_json_request(
                    "tools/call",
                    serde_json::json!({
                        "name": "http_overlap_tool",
                        "arguments": {}
                    }),
                    id,
                );
                let traffic_renderer: Option<RequestResponseRenderer> = None;
                let response = server.handle_http_mcp_request(
                    &cx,
                    &session,
                    &http_handler,
                    &request,
                    &notification_sender,
                    &request_sender,
                    &traffic_renderer,
                );
                assert_eq!(response.status, HttpStatus::OK);
                let json: JsonRpcResponse =
                    serde_json::from_slice(&response.body).expect("parse HTTP JSON-RPC response");
                assert!(
                    json.error.is_none(),
                    "unexpected error response: {:?}",
                    json.error
                );
            })
        };

        let first = run_request(1);
        let second = run_request(2);
        start.wait();

        first.join().expect("first HTTP request thread panicked");
        second.join().expect("second HTTP request thread panicked");

        let overlap = http_overlap_metrics().max.load(Ordering::SeqCst);
        assert!(
            overlap >= 2,
            "expected concurrent HTTP tools/call overlap, observed max overlap {overlap}"
        );
    }

    #[test]
    fn http_read_only_requests_keep_request_auth_isolated() {
        #[derive(Debug)]
        struct EchoAuthProvider;

        impl AuthProvider for EchoAuthProvider {
            fn authenticate(
                &self,
                _ctx: &McpContext,
                request: AuthRequest<'_>,
            ) -> McpResult<AuthContext> {
                let access = request
                    .access_token()
                    .ok_or_else(|| McpError::invalid_request("missing auth token"))?;
                Ok(AuthContext {
                    subject: Some(access.token.clone()),
                    token: Some(access),
                    ..AuthContext::default()
                })
            }
        }

        let guard = http_overlap_lock()
            .lock()
            .expect("http overlap test lock poisoned");
        reset_http_overlap_metrics();

        let server = Arc::new(
            Server::new("http-auth-test-server", "1.0.0")
                .auth_provider(EchoAuthProvider)
                .tool(HttpAuthEchoToolRuntime)
                .build(),
        );
        let session = Arc::new(Mutex::new(Session::new(
            server.info.clone(),
            server.capabilities.clone(),
        )));
        session.lock().expect("session lock poisoned").initialize(
            fastmcp_protocol::ClientInfo {
                name: "http-auth-test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            fastmcp_protocol::ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let http_handler = Arc::new(HttpRequestHandler::new());
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let start = Arc::new(std::sync::Barrier::new(3));

        let run_request = |id, token: &'static str| {
            let server = Arc::clone(&server);
            let session = Arc::clone(&session);
            let http_handler = Arc::clone(&http_handler);
            let notification_sender = Arc::clone(&notification_sender);
            let request_sender = request_sender.clone();
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                let cx = Cx::for_testing();
                let request = http_json_request(
                    "tools/call",
                    serde_json::json!({
                        "name": "http_auth_echo_tool_runtime",
                        "arguments": {},
                        "auth": format!("Bearer {token}")
                    }),
                    id,
                );
                let traffic_renderer: Option<RequestResponseRenderer> = None;
                let response = server.handle_http_mcp_request(
                    &cx,
                    &session,
                    &http_handler,
                    &request,
                    &notification_sender,
                    &request_sender,
                    &traffic_renderer,
                );
                assert_eq!(response.status, HttpStatus::OK);
                let json: JsonRpcResponse =
                    serde_json::from_slice(&response.body).expect("parse HTTP JSON-RPC response");
                let result = json.result.expect("authenticated request should succeed");
                let tool_result: CallToolResult =
                    serde_json::from_value(result).expect("parse tool result payload");
                assert!(
                    !tool_result.is_error,
                    "auth echo tool unexpectedly returned an error payload"
                );
                match tool_result.content.as_slice() {
                    [Content::Text { text }] => text.clone(),
                    other => panic!("expected single text tool result, got {other:?}"),
                }
            })
        };

        let first = run_request(1, "alpha");
        let second = run_request(2, "beta");
        start.wait();

        let first_result = first.join();
        let second_result = second.join();
        let overlap = http_overlap_metrics().max.load(Ordering::SeqCst);
        drop(guard);

        let first_subject = first_result.expect("first auth request thread panicked");
        let second_subject = second_result.expect("second auth request thread panicked");

        assert_eq!(first_subject, "alpha");
        assert_eq!(second_subject, "beta");
        assert!(
            overlap >= 2,
            "expected authenticated requests to overlap, observed max overlap {overlap}"
        );
    }

    #[test]
    fn http_stateful_tool_calls_preserve_session_state_updates() {
        let server = Arc::new(
            Server::new("http-state-test-server", "1.0.0")
                .tool(HttpStatefulIncrementTool)
                .build(),
        );
        let session = Arc::new(Mutex::new(Session::new(
            server.info.clone(),
            server.capabilities.clone(),
        )));
        session.lock().expect("session lock poisoned").initialize(
            fastmcp_protocol::ClientInfo {
                name: "http-state-test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            fastmcp_protocol::ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let http_handler = Arc::new(HttpRequestHandler::new());
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();

        let run_request = |id| {
            let cx = Cx::for_testing();
            let request = http_json_request(
                "tools/call",
                serde_json::json!({
                    "name": "http_stateful_increment_tool",
                    "arguments": {}
                }),
                id,
            );
            let traffic_renderer: Option<RequestResponseRenderer> = None;
            let response = server.handle_http_mcp_request(
                &cx,
                &session,
                &http_handler,
                &request,
                &notification_sender,
                &request_sender,
                &traffic_renderer,
            );
            assert_eq!(response.status, HttpStatus::OK);
            let json: JsonRpcResponse =
                serde_json::from_slice(&response.body).expect("parse HTTP JSON-RPC response");
            let result = json.result.expect("stateful request should succeed");
            let tool_result: CallToolResult =
                serde_json::from_value(result).expect("parse tool result payload");
            assert!(!tool_result.is_error, "stateful tool unexpectedly errored");
            match tool_result.content.as_slice() {
                [Content::Text { text }] => text.clone(),
                other => panic!("expected single text tool result, got {other:?}"),
            }
        };

        assert_eq!(run_request(1), "Counter: 1");
        assert_eq!(run_request(2), "Counter: 2");
    }

    #[test]
    fn http_exclusive_requests_expose_request_auth_to_middleware() {
        #[derive(Debug)]
        struct EchoAuthProvider;

        impl AuthProvider for EchoAuthProvider {
            fn authenticate(
                &self,
                _ctx: &McpContext,
                request: AuthRequest<'_>,
            ) -> McpResult<AuthContext> {
                let access = request
                    .access_token()
                    .ok_or_else(|| McpError::invalid_request("missing auth token"))?;
                Ok(AuthContext {
                    subject: Some(access.token.clone()),
                    token: Some(access),
                    ..AuthContext::default()
                })
            }
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let middleware = CapturingAuthMiddleware {
            seen: Arc::clone(&seen),
        };
        let server = Server::new("http-middleware-auth-test-server", "1.0.0")
            .auth_provider(EchoAuthProvider)
            .middleware(middleware)
            .build();
        let session = Arc::new(Mutex::new(Session::new(
            server.info.clone(),
            server.capabilities.clone(),
        )));
        session.lock().expect("session lock poisoned").initialize(
            fastmcp_protocol::ClientInfo {
                name: "http-middleware-client".to_string(),
                version: "1.0.0".to_string(),
            },
            fastmcp_protocol::ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let http_handler = Arc::new(HttpRequestHandler::new());
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let request = http_json_request(
            "tools/list",
            serde_json::json!({
                "auth": "Bearer alpha"
            }),
            1,
        );
        let traffic_renderer: Option<RequestResponseRenderer> = None;
        let response = server.handle_http_mcp_request(
            &Cx::for_testing(),
            &session,
            &http_handler,
            &request,
            &notification_sender,
            &request_sender,
            &traffic_renderer,
        );
        assert_eq!(response.status, HttpStatus::OK);

        let observed = seen
            .lock()
            .expect("captured auth middleware mutex should not be poisoned")
            .clone();
        assert_eq!(
            observed,
            vec![("tools/list".to_string(), Some("alpha".to_string()))]
        );
    }

    #[test]
    fn http_read_only_requests_expose_request_auth_to_middleware() {
        #[derive(Debug)]
        struct EchoAuthProvider;

        impl AuthProvider for EchoAuthProvider {
            fn authenticate(
                &self,
                _ctx: &McpContext,
                request: AuthRequest<'_>,
            ) -> McpResult<AuthContext> {
                let access = request
                    .access_token()
                    .ok_or_else(|| McpError::invalid_request("missing auth token"))?;
                Ok(AuthContext {
                    subject: Some(access.token.clone()),
                    token: Some(access),
                    ..AuthContext::default()
                })
            }
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let middleware = CapturingAuthMiddleware {
            seen: Arc::clone(&seen),
        };
        let server = Server::new("http-read-only-middleware-auth-test-server", "1.0.0")
            .auth_provider(EchoAuthProvider)
            .middleware(middleware)
            .tool(HttpCurrentAuthSubjectTool)
            .build();
        let session = Arc::new(Mutex::new(Session::new(
            server.info.clone(),
            server.capabilities.clone(),
        )));
        session.lock().expect("session lock poisoned").initialize(
            fastmcp_protocol::ClientInfo {
                name: "http-read-only-middleware-client".to_string(),
                version: "1.0.0".to_string(),
            },
            fastmcp_protocol::ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let http_handler = Arc::new(HttpRequestHandler::new());
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let request = http_json_request(
            "tools/call",
            serde_json::json!({
                "name": "http_current_auth_subject_tool",
                "arguments": {},
                "auth": "Bearer beta"
            }),
            1,
        );
        let traffic_renderer: Option<RequestResponseRenderer> = None;
        let response = server.handle_http_mcp_request(
            &Cx::for_testing(),
            &session,
            &http_handler,
            &request,
            &notification_sender,
            &request_sender,
            &traffic_renderer,
        );
        assert_eq!(response.status, HttpStatus::OK);

        let json: JsonRpcResponse =
            serde_json::from_slice(&response.body).expect("parse HTTP JSON-RPC response");
        let result = json.result.expect("read-only auth request should succeed");
        let tool_result: CallToolResult =
            serde_json::from_value(result).expect("parse tool result payload");
        match tool_result.content.as_slice() {
            [Content::Text { text }] => assert_eq!(text, "beta"),
            other => panic!("expected single text tool result, got {other:?}"),
        }

        let observed = seen
            .lock()
            .expect("captured auth middleware mutex should not be poisoned")
            .clone();
        assert_eq!(
            observed,
            vec![("tools/call".to_string(), Some("beta".to_string()))]
        );
    }

    #[test]
    fn http_exclusive_middleware_auth_mutation_reaches_handler_dispatch() {
        let server = Server::new("http-exclusive-auth-override-test-server", "1.0.0")
            .middleware(OverridingAuthMiddleware {
                subject: "exclusive-override",
            })
            .tool(HttpCurrentAuthSubjectExclusiveTool)
            .build();
        let session = Arc::new(Mutex::new(Session::new(
            server.info.clone(),
            server.capabilities.clone(),
        )));
        session.lock().expect("session lock poisoned").initialize(
            fastmcp_protocol::ClientInfo {
                name: "http-exclusive-auth-override-client".to_string(),
                version: "1.0.0".to_string(),
            },
            fastmcp_protocol::ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let http_handler = Arc::new(HttpRequestHandler::new());
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let request = http_json_request(
            "tools/call",
            serde_json::json!({
                "name": "http_current_auth_subject_exclusive_tool",
                "arguments": {}
            }),
            1,
        );
        let traffic_renderer: Option<RequestResponseRenderer> = None;
        let response = server.handle_http_mcp_request(
            &Cx::for_testing(),
            &session,
            &http_handler,
            &request,
            &notification_sender,
            &request_sender,
            &traffic_renderer,
        );
        assert_eq!(response.status, HttpStatus::OK);

        let json: JsonRpcResponse =
            serde_json::from_slice(&response.body).expect("parse HTTP JSON-RPC response");
        let result = json
            .result
            .expect("exclusive auth override request should succeed");
        let tool_result: CallToolResult =
            serde_json::from_value(result).expect("parse tool result payload");
        match tool_result.content.as_slice() {
            [Content::Text { text }] => assert_eq!(text, "exclusive-override"),
            other => panic!("expected single text tool result, got {other:?}"),
        }
    }

    #[test]
    fn http_read_only_middleware_auth_mutation_reaches_handler_dispatch() {
        let server = Server::new("http-read-only-auth-override-test-server", "1.0.0")
            .middleware(OverridingAuthMiddleware {
                subject: "read-only-override",
            })
            .tool(HttpCurrentAuthSubjectTool)
            .build();
        let session = Arc::new(Mutex::new(Session::new(
            server.info.clone(),
            server.capabilities.clone(),
        )));
        session.lock().expect("session lock poisoned").initialize(
            fastmcp_protocol::ClientInfo {
                name: "http-read-only-auth-override-client".to_string(),
                version: "1.0.0".to_string(),
            },
            fastmcp_protocol::ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let http_handler = Arc::new(HttpRequestHandler::new());
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let request = http_json_request(
            "tools/call",
            serde_json::json!({
                "name": "http_current_auth_subject_tool",
                "arguments": {}
            }),
            1,
        );
        let traffic_renderer: Option<RequestResponseRenderer> = None;
        let response = server.handle_http_mcp_request(
            &Cx::for_testing(),
            &session,
            &http_handler,
            &request,
            &notification_sender,
            &request_sender,
            &traffic_renderer,
        );
        assert_eq!(response.status, HttpStatus::OK);

        let json: JsonRpcResponse =
            serde_json::from_slice(&response.body).expect("parse HTTP JSON-RPC response");
        let result = json
            .result
            .expect("read-only auth override request should succeed");
        let tool_result: CallToolResult =
            serde_json::from_value(result).expect("parse tool result payload");
        match tool_result.content.as_slice() {
            [Content::Text { text }] => assert_eq!(text, "read-only-override"),
            other => panic!("expected single text tool result, got {other:?}"),
        }
    }

    #[test]
    fn http_exclusive_auth_failures_flow_through_middleware_error_rewriting() {
        let server = Server::new("http-exclusive-auth-error-test-server", "1.0.0")
            .auth_provider(AlwaysFailAuthProvider)
            .middleware(RewritingErrorMiddleware)
            .build();
        let session = Arc::new(Mutex::new(Session::new(
            server.info.clone(),
            server.capabilities.clone(),
        )));
        session.lock().expect("session lock poisoned").initialize(
            fastmcp_protocol::ClientInfo {
                name: "http-exclusive-auth-error-client".to_string(),
                version: "1.0.0".to_string(),
            },
            fastmcp_protocol::ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let http_handler = Arc::new(HttpRequestHandler::new());
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let request = http_json_request(
            "tools/list",
            serde_json::json!({
                "auth": "Bearer nope"
            }),
            1,
        );
        let traffic_renderer: Option<RequestResponseRenderer> = None;
        let response = server.handle_http_mcp_request(
            &Cx::for_testing(),
            &session,
            &http_handler,
            &request,
            &notification_sender,
            &request_sender,
            &traffic_renderer,
        );
        assert_eq!(response.status, HttpStatus::OK);

        let json: JsonRpcResponse =
            serde_json::from_slice(&response.body).expect("parse HTTP JSON-RPC response");
        let error = json
            .error
            .expect("auth failure should return JSON-RPC error");
        assert_eq!(error.message, "rewritten: auth failed");
    }

    #[test]
    fn http_read_only_auth_failures_flow_through_middleware_error_rewriting() {
        let server = Server::new("http-read-only-auth-error-test-server", "1.0.0")
            .auth_provider(AlwaysFailAuthProvider)
            .middleware(RewritingErrorMiddleware)
            .tool(HttpCurrentAuthSubjectTool)
            .build();
        let session = Arc::new(Mutex::new(Session::new(
            server.info.clone(),
            server.capabilities.clone(),
        )));
        session.lock().expect("session lock poisoned").initialize(
            fastmcp_protocol::ClientInfo {
                name: "http-read-only-auth-error-client".to_string(),
                version: "1.0.0".to_string(),
            },
            fastmcp_protocol::ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let http_handler = Arc::new(HttpRequestHandler::new());
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let request = http_json_request(
            "tools/call",
            serde_json::json!({
                "name": "http_current_auth_subject_tool",
                "arguments": {},
                "auth": "Bearer nope"
            }),
            1,
        );
        let traffic_renderer: Option<RequestResponseRenderer> = None;
        let response = server.handle_http_mcp_request(
            &Cx::for_testing(),
            &session,
            &http_handler,
            &request,
            &notification_sender,
            &request_sender,
            &traffic_renderer,
        );
        assert_eq!(response.status, HttpStatus::OK);

        let json: JsonRpcResponse =
            serde_json::from_slice(&response.body).expect("parse HTTP JSON-RPC response");
        let error = json
            .error
            .expect("auth failure should return JSON-RPC error");
        assert_eq!(error.message, "rewritten: auth failed");
    }

    #[test]
    fn router_tools_call_injects_explicit_request_auth() {
        let server = Server::new("router-auth-test-server", "1.0.0")
            .tool(HttpCurrentAuthSubjectTool)
            .build();
        let result = server
            .router
            .handle_tools_call(
                &Cx::for_testing(),
                41,
                CallToolParams {
                    name: "http_current_auth_subject_tool".to_string(),
                    arguments: Some(serde_json::json!({})),
                    meta: None,
                },
                &Budget::INFINITE,
                SessionState::new(),
                Some(AuthContext::with_subject("alpha")),
                None,
                None,
            )
            .expect("tool call should succeed");

        match result.content.as_slice() {
            [Content::Text { text }] => assert_eq!(text, "alpha"),
            other => panic!("expected single text tool result, got {other:?}"),
        }
    }

    #[test]
    fn http_returning_server_honors_cancellation_without_needing_accept_wakeup() {
        let port_probe =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port probe");
        let addr = port_probe
            .local_addr()
            .expect("discover ephemeral port probe address");
        drop(port_probe);

        let cx = Cx::for_testing();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let server_thread = thread::spawn({
            let server = Server::new("http-cancel-test", "1.0.0").build();
            let cx = cx.clone();
            let addr = addr.to_string();
            move || {
                server.run_http_returning_with_cx(&cx, addr);
                let _ = done_tx.send(());
            }
        });

        std::thread::sleep(Duration::from_millis(50));
        cx.cancel_with(CancelKind::User, None);

        let returned_before_wakeup = done_rx.recv_timeout(Duration::from_millis(300)).is_ok();
        if !returned_before_wakeup {
            let _ = std::net::TcpStream::connect(addr);
            let _ = done_rx.recv_timeout(Duration::from_secs(1));
        }

        server_thread
            .join()
            .expect("HTTP returning server thread should not panic");

        // The "no extra accept-wakeup needed" guarantee is a Unix
        // accept()/epoll behavior; on Windows the IOCP-backed listener
        // doesn't unblock from a non-I/O signal, so a fallback connect
        // is the documented path there.  As long as the server *does*
        // shut down within the fallback window (verified by
        // `server_thread.join()` returning above), the cancellation
        // contract is honored on Windows too.  No matching `#[cfg(windows)]`
        // arm is needed: `returned_before_wakeup` is already consumed by
        // the `if !returned_before_wakeup` branch above on every platform.
        #[cfg(not(windows))]
        assert!(
            returned_before_wakeup,
            "run_http_returning_with_cx should stop promptly after cancellation without requiring an extra connection to wake accept()"
        );
    }
}
