//! MCP server implementation for FastMCP.
//!
//! This crate provides the server-side implementation:
//! - Server builder pattern
//! - Tool, resource, and prompt registration
//! - Request routing and dispatching
//! - Session management
//!
//! MCP 2026-07-28 support is under implementation and remains unverified. The
//! public protocol constant is still `2024-11-05`; server source presence is
//! not aggregate conformance or release evidence.
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_rust::prelude::*;
//!
//! #[tool]
//! async fn greet(ctx: &McpContext, name: String) -> McpResult<String> {
//!     ctx.checkpoint()?;
//!     Ok(format!("Hello, {name}!"))
//! }
//!
//! fn main() {
//!     Server::new("my-server", "1.0.0")
//!         .tool(Greet)
//!         .build()
//!         .run_stdio();
//! }
//! ```
//!
//! # Role in the System
//!
//! `fastmcp-server` is the **execution engine** for MCP servers. It ties
//! together:
//! - Protocol types (`fastmcp-protocol`) for requests and responses
//! - Transports (`fastmcp-transport`) for stdio/SSE/WebSocket/HTTP/memory I/O
//! - Core context + cancellation (`fastmcp-core`) for budgets and checkpoints
//! - Console output (`fastmcp-console`) for human-friendly stderr rendering
//!
//! The façade package `fastmcp-rust` re-exports this API, so most users
//! interact with `Server` via `fastmcp_rust::prelude::*`.
//!
//! # Extension panic-containment boundary
//!
//! Unwinding extension callback panics (including handler, auth, middleware,
//! and lifecycle callbacks) are caught at their framework boundaries.
//! Request-path failures are mapped to a fixed payload-free peer error. FastMCP
//! also installs a redacting panic hook for local diagnostics, but Rust's hook
//! is process-global and replaceable: an embedding application that installs
//! another hook afterward controls subsequent panic diagnostics. Such
//! replacement does not change the fixed peer error, but FastMCP cannot promise
//! payload-free local diagnostics after its hook has been replaced.

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
// FND-01: Docket/Redis is not part of the FND-01 production surface. Source bytes
// remain on disk (no-deletion) and are package-excluded; do not re-export.
mod handler;
mod middleware;
pub mod oauth;
pub mod oidc;
pub mod providers;
mod proxy;
pub mod rate_limiting;
mod router;
mod session;
#[cfg(test)]
mod tasks;
pub mod transform;

#[cfg(test)]
mod tests;

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
pub use router::{MountResult, NotificationSender, Router, TagFilters};
use router::{RouterResourceReader, RouterToolCaller};
pub use session::Session;
use session::{
    InitializationSnapshot, MAX_RESOURCE_SUBSCRIPTION_BYTES_PER_SESSION, SessionPrincipalBinding,
    SubscriptionAdmission, SubscriptionAdmissionError, SubscriptionRemoval,
    SubscriptionRemovalError,
};
#[cfg(test)]
pub(crate) use tasks::{SharedTaskManager, TaskManager};

// Re-export bidirectional communication types
pub use bidirectional::{
    PendingRequests, RequestSender, TransportElicitationSender, TransportRootsProvider,
    TransportSamplingSender,
};

use std::any::Any;
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Once};
use std::time::{Duration, Instant};

use fastmcp_transport::http::{
    HttpHandlerConfig, HttpMethod, HttpRequest, HttpRequestHandler, HttpResponse, HttpStatus,
    HttpTransport,
};

use asupersync::{Budget, CancelKind, Cx, RegionId, channel::mpsc as asupersync_mpsc};
use fastmcp_console::banner::StartupBanner;
use fastmcp_console::client::RequestResponseRenderer;
use fastmcp_console::console::FastMcpConsole;
use fastmcp_console::logging::RichLoggerBuilder;
#[cfg(test)]
use fastmcp_core::AuthContext;
use fastmcp_core::logging::{debug, error, info, targets};
use fastmcp_core::{
    McpContext, McpContextLeaseGuard, McpError, McpErrorCode, McpRequestCancellation, McpResult,
    SessionState, Sha256Digest, block_on, sha256_bounded,
};
use fastmcp_protocol::{
    CallToolParams, CancelledParams, GetPromptParams, InitializeParams, JsonRpcError,
    JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, ListPromptsParams,
    ListResourceTemplatesParams, ListResourcesParams, ListToolsParams, LogLevel, LogMessageParams,
    Prompt, ReadResourceParams, RequestId, Resource, ResourceTemplate, ServerCapabilities,
    ServerInfo, SetLogLevelParams, SubscribeResourceParams, Tool, UnsubscribeResourceParams,
};

const REDACTED_EXTENSION_PANIC_INCIDENT: &[u8] =
    b"fastmcp extension callback panicked; panic payload redacted\n";
const UNQUALIFIED_HTTP_DIAGNOSTIC: &[u8] = b"fastmcp turnkey HTTP is unavailable: the sessionful legacy listener is quarantined until stateless per-request dispatch and request-owned cancellation are qualified\n";
/// Server-local error code for a bounded resource-subscription admission
/// failure. MCP does not currently assign a standard `ResourceExhausted` code.
const RESOURCE_EXHAUSTED_ERROR_CODE: i32 = -32006;
const RESOURCE_SUBSCRIPTION_CAPACITY_MESSAGE: &str = "Resource subscription capacity exhausted";
const MAX_DISPATCH_QUEUE_DEPTH: usize = 64;
const MAX_DISPATCH_QUEUE_BYTES: usize = 16 * 1024 * 1024;
const DISPATCH_QUEUE_CAPACITY_MESSAGE: &str = "Server request queue capacity exhausted";
static INSTALL_EXTENSION_PANIC_HOOK: Once = Once::new();
#[cfg(test)]
static REDACTED_EXTENSION_PANIC_COUNT: AtomicUsize = AtomicUsize::new(0);

fn lock_http_session(session: &Mutex<Session>) -> std::sync::MutexGuard<'_, Session> {
    #[cfg(test)]
    if lib_unit_tests::record_http_session_lock_attempt(std::ptr::from_ref(session).addr()) {
        match session.try_lock() {
            Ok(guard) => return guard,
            Err(std::sync::TryLockError::WouldBlock) => {
                lib_unit_tests::record_http_session_lock_contention(
                    std::ptr::from_ref(session).addr(),
                );
            }
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                error!(target: targets::SERVER, "Session lock poisoned, recovering");
                return poisoned.into_inner();
            }
        }
    }

    match session.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            error!(target: targets::SERVER, "Session lock poisoned, recovering");
            poisoned.into_inner()
        }
    }
}

#[derive(Default)]
struct DispatchRequestByteCounter {
    bytes: usize,
}

impl Write for DispatchRequestByteCounter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let prospective = self
            .bytes
            .checked_add(buffer.len())
            .ok_or_else(|| std::io::Error::other(DISPATCH_QUEUE_CAPACITY_MESSAGE))?;
        if prospective > MAX_DISPATCH_QUEUE_BYTES {
            return Err(std::io::Error::other(DISPATCH_QUEUE_CAPACITY_MESSAGE));
        }
        self.bytes = prospective;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn measure_dispatch_request(request: &JsonRpcRequest) -> Option<usize> {
    let mut counter = DispatchRequestByteCounter::default();
    serde_json::to_writer(&mut counter, request)
        .ok()
        .map(|()| counter.bytes)
}

fn is_quarantined_task_rpc(method: &str) -> bool {
    matches!(
        method,
        "tasks/list" | "tasks/get" | "tasks/cancel" | "tasks/submit"
    )
}

fn is_notification_only_method(method: &str) -> bool {
    method.starts_with("notifications/")
}

fn is_request_only_method(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "ping"
            | "logging/setLevel"
            | "tools/list"
            | "tools/call"
            | "resources/list"
            | "resources/templates/list"
            | "resources/read"
            | "resources/subscribe"
            | "resources/unsubscribe"
            | "prompts/list"
            | "prompts/get"
            | "tasks/list"
            | "tasks/get"
            | "tasks/cancel"
            | "tasks/submit"
    )
}

fn is_session_mutation(method: &str) -> bool {
    matches!(
        method,
        "initialize" | "logging/setLevel" | "resources/subscribe" | "resources/unsubscribe"
    )
}

enum SessionMutationRollback {
    RemoveResourceSubscription(String),
    RestoreResourceSubscription(String),
    RestoreInitialization(InitializationSnapshot),
    RestoreLogLevel(Option<LogLevel>),
}

impl SessionMutationRollback {
    fn apply(self, session: &mut Session) {
        match self {
            Self::RemoveResourceSubscription(uri) => {
                session.rollback_resource_subscription(&uri);
            }
            Self::RestoreResourceSubscription(uri) => {
                session.restore_resource_subscription(uri);
            }
            Self::RestoreInitialization(snapshot) => {
                session.restore_initialization(snapshot);
            }
            Self::RestoreLogLevel(level) => {
                session.restore_log_level(level);
            }
        }
    }
}

#[derive(Default)]
struct DispatchQueueState {
    inner: Mutex<DispatchQueueStateInner>,
}

#[derive(Default)]
struct DispatchQueueStateInner {
    /// Request IDs retain this reservation from admission until the response
    /// attempt completes. Keeping it across the queued-to-active transition
    /// closes both admission TOCTOU and post-commit ABA races with ID reuse.
    reserved: HashSet<RequestId>,
    /// Reserved requests that a worker has begun dispatching.
    dispatching: HashSet<RequestId>,
    cancelled: HashSet<RequestId>,
    queued_bytes: usize,
    stopping: bool,
}

struct QueuedDispatchRequest {
    request: JsonRpcRequest,
    serialized_bytes: usize,
}

impl DispatchQueueState {
    fn admit(&self, id: &RequestId) -> bool {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !inner.stopping && inner.reserved.insert(id.clone())
    }

    fn discard(&self, id: &RequestId) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.reserved.remove(id);
        inner.dispatching.remove(id);
        inner.cancelled.remove(id);
    }

    fn reserve_queued_bytes(&self, serialized_bytes: usize) -> bool {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.stopping {
            return false;
        }
        let Some(prospective) = inner.queued_bytes.checked_add(serialized_bytes) else {
            return false;
        };
        if prospective > MAX_DISPATCH_QUEUE_BYTES {
            return false;
        }
        inner.queued_bytes = prospective;
        true
    }

    fn release_queued_bytes(&self, serialized_bytes: usize) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.queued_bytes = inner.queued_bytes.saturating_sub(serialized_bytes);
    }

    fn cancel_if_queued(&self, id: &RequestId) -> bool {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !inner.reserved.contains(id) || inner.dispatching.contains(id) {
            return false;
        }
        inner.cancelled.insert(id.clone());
        true
    }

    fn begin_dispatch(&self, id: &RequestId) -> bool {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(inner.reserved.contains(id));
        inner.dispatching.insert(id.clone());
        inner.cancelled.remove(id) || inner.stopping
    }

    fn is_stopping(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stopping
    }

    fn stop(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.stopping = true;
        let queued = inner
            .reserved
            .difference(&inner.dispatching)
            .cloned()
            .collect::<Vec<_>>();
        inner.cancelled.extend(queued);
    }
}

/// Marks an unexpected dispatch-worker exit before the worker stack unwinds.
///
/// The latch is disarmed only after a stop requested by the receive pump. A
/// returned send failure, disconnected worker queue, or panic therefore closes
/// admission and makes the pump report failure. Its drop path contains queue
/// wake-up failures so a worker panic cannot turn into a double-panic abort.
struct DispatchWorkerFailureLatch {
    failed: Arc<AtomicBool>,
    queue: Arc<DispatchQueueState>,
    cx: Cx,
    armed: bool,
}

impl DispatchWorkerFailureLatch {
    fn new(failed: Arc<AtomicBool>, queue: Arc<DispatchQueueState>, cx: Cx) -> Self {
        Self {
            failed,
            queue,
            cx,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DispatchWorkerFailureLatch {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.failed.store(true, Ordering::Release);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.queue.stop()));
        self.cx.set_cancel_requested(true);
    }
}

thread_local! {
    static REDACT_EXTENSION_PANIC: Cell<bool> = const { Cell::new(false) };
}

struct ExtensionPanicRedactionGuard {
    previous: bool,
}

impl ExtensionPanicRedactionGuard {
    fn enter() -> Self {
        let previous = REDACT_EXTENSION_PANIC.with(|redact| redact.replace(true));
        Self { previous }
    }
}

impl Drop for ExtensionPanicRedactionGuard {
    fn drop(&mut self) {
        REDACT_EXTENSION_PANIC.with(|redact| redact.set(self.previous));
    }
}

/// Installs FastMCP's payload-redacting diagnostic hook once.
///
/// Rust exposes one process-global, replaceable panic hook. An embedding
/// application can call `std::panic::set_hook` after this function returns and
/// replace FastMCP's hook; FastMCP cannot prevent or reliably detect that. The
/// fixed peer-facing error produced after `catch_unwind` remains payload-free,
/// but payload-free process diagnostics require the application to preserve or
/// correctly chain the installed hook.
fn install_extension_panic_hook() {
    INSTALL_EXTENSION_PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            let redact = REDACT_EXTENSION_PANIC.try_with(Cell::get).unwrap_or(false);
            if redact {
                // This branch deliberately cannot observe `panic_info`. Keep
                // the local diagnostic constant-sized and payload-free.
                #[cfg(test)]
                REDACTED_EXTENSION_PANIC_COUNT.fetch_add(1, Ordering::Relaxed);
                let _ = std::io::stderr().write_all(REDACTED_EXTENSION_PANIC_INCIDENT);
            } else {
                previous(panic_info);
            }
        }));
    });
}

pub(crate) fn catch_extension_unwind<R>(
    callback: impl FnOnce() -> R,
) -> Result<R, Box<dyn Any + Send>> {
    install_extension_panic_hook();
    let _redaction = ExtensionPanicRedactionGuard::enter();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(callback))
}

fn extension_panic_error(extension_class: &'static str) -> McpError {
    static NEXT_EXTENSION_INCIDENT_ID: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(1);
    let incident_id = NEXT_EXTENSION_INCIDENT_ID.fetch_add(1, Ordering::Relaxed);
    error!(
        target: targets::SERVER,
        "extension callback terminated unexpectedly; incident_id={incident_id}; class={extension_class}; detail=panic_payload_redacted"
    );
    McpError::internal_error("Internal server error")
}

fn resource_subscription_capacity_error() -> McpError {
    McpError::new(
        McpErrorCode::Custom(RESOURCE_EXHAUSTED_ERROR_CODE),
        RESOURCE_SUBSCRIPTION_CAPACITY_MESSAGE,
    )
}

fn mask_peer_error(error: McpError, mask_error_details: bool) -> McpError {
    // This one server-owned custom error has a fixed, reviewed, payload-free
    // public contract. Preserve it while continuing to mask arbitrary custom
    // extension errors, including attempts to reuse the same numeric code with
    // a different message or data.
    if error.code == McpErrorCode::Custom(RESOURCE_EXHAUSTED_ERROR_CODE)
        && error.message == RESOURCE_SUBSCRIPTION_CAPACITY_MESSAGE
        && error.data.is_none()
    {
        error
    } else {
        error.masked(mask_error_details)
    }
}
use fastmcp_transport::sse::SseServerTransport;
use fastmcp_transport::websocket::WsTransport;
use fastmcp_transport::{AsyncStdout, Codec, StdioTransport, Transport, TransportError};
use log::{Level, LevelFilter};

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReceiveErrorDisposition {
    Retry,
    ReplyWithParseError,
    ReplyWithInvalidRequest(Option<RequestId>),
    Terminate,
}

fn classify_receive_error(error: &TransportError) -> ReceiveErrorDisposition {
    match error {
        // A timeout does not consume or corrupt a message boundary.
        TransportError::Timeout => ReceiveErrorDisposition::Retry,
        // JSON decoding begins only after a transport has isolated one
        // complete message. Reply with the fixed uncorrelated JSON-RPC error,
        // then admit the next complete message.
        TransportError::Codec(fastmcp_transport::CodecError::Json(_)) => {
            ReceiveErrorDisposition::ReplyWithParseError
        }
        TransportError::Codec(fastmcp_transport::CodecError::InvalidMessage {
            kind: fastmcp_transport::InvalidMessageKind::Request,
            request_id,
            ..
        }) => ReceiveErrorDisposition::ReplyWithInvalidRequest(request_id.clone()),
        TransportError::Codec(fastmcp_transport::CodecError::InvalidMessage {
            kind: fastmcp_transport::InvalidMessageKind::Response,
            ..
        }) => ReceiveErrorDisposition::Terminate,
        // A bounded line reader can detect an oversized frame before it has
        // consumed the delimiter. The byte stream may still point inside the
        // rejected frame, so retrying would reinterpret its suffix.
        TransportError::Codec(fastmcp_transport::CodecError::MessageTooLarge(_)) => {
            ReceiveErrorDisposition::Terminate
        }
        // I/O errors include HTTP/WebSocket framing and protocol violations.
        // Continuing on the same byte stream could reinterpret attacker-owned
        // suffix bytes after the parser has lost synchronization.
        TransportError::Io(_) | TransportError::Closed | TransportError::Cancelled => {
            ReceiveErrorDisposition::Terminate
        }
    }
}

fn send_uncorrelated_parse_error<S>(send: &Arc<Mutex<S>>, cx: &Cx) -> Result<(), TransportError>
where
    S: FnMut(&Cx, &JsonRpcMessage) -> Result<(), TransportError>,
{
    send_jsonrpc_error(send, cx, None, McpErrorCode::ParseError, "Parse error")
}

fn send_invalid_request<S>(
    send: &Arc<Mutex<S>>,
    cx: &Cx,
    request_id: Option<RequestId>,
) -> Result<(), TransportError>
where
    S: FnMut(&Cx, &JsonRpcMessage) -> Result<(), TransportError>,
{
    send_jsonrpc_error(
        send,
        cx,
        request_id,
        McpErrorCode::InvalidRequest,
        "Invalid Request",
    )
}

fn send_jsonrpc_error<S>(
    send: &Arc<Mutex<S>>,
    cx: &Cx,
    request_id: Option<RequestId>,
    code: McpErrorCode,
    message: &'static str,
) -> Result<(), TransportError>
where
    S: FnMut(&Cx, &JsonRpcMessage) -> Result<(), TransportError>,
{
    let response = JsonRpcResponse::error(
        request_id,
        JsonRpcError {
            code: code.into(),
            message: message.to_string(),
            data: None,
        },
    );
    let mut guard = send
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard(cx, &JsonRpcMessage::Response(response))
}

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
    /// Maximum enabled log verbosity (default: INFO).
    ///
    /// Set this to [`LevelFilter::Off`] to disable server-managed logging.
    pub level: LevelFilter,
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
            level: LevelFilter::Info,
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
    /// - `FASTMCP_LOG`: Log filter (`off`, `error`, `warn`, `info`, `debug`, or `trace`)
    /// - `FASTMCP_LOG_TIMESTAMPS`: Show timestamps (0/false to disable)
    /// - `FASTMCP_LOG_TARGETS`: Show targets (0/false to disable)
    /// - `FASTMCP_LOG_FILE_LINE`: Show file:line (1/true to enable)
    #[must_use]
    pub fn from_env() -> Self {
        Self::from(&ConsoleConfig::from_env())
    }
}

impl From<&ConsoleConfig> for LoggingConfig {
    fn from(config: &ConsoleConfig) -> Self {
        Self {
            level: config.log_level,
            timestamps: config.log_timestamps,
            targets: config.log_targets,
            file_line: config.log_file_line,
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

/// Configuration reserved for the qualified HTTP server path.
///
/// The public [`Server::run_http`] entry point currently fails closed before
/// binding; these values do not activate the quarantined legacy listener.
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
    /// Path for the health-check endpoint (default: `"/health"`).
    pub health_path: String,
    /// Maximum number of concurrent connections (default: 64).
    pub max_connections: usize,
    /// Inner HTTP handler configuration (endpoint path, CORS, and body size).
    pub handler_config: HttpHandlerConfig,
}

// Legacy snapshot dispatch support retained privately while the public shared
// session entry point is fully serialized. A snapshot is an isolated copy;
// mutations made through a handler context cannot write into the live session.
#[derive(Debug, Clone)]
struct SessionView {
    id: u64,
    initialized: bool,
    state: SessionState,
    supports_sampling: bool,
    supports_elicitation: bool,
    log_level: Option<LogLevel>,
    principal_binding: SessionPrincipalBinding,
}

impl SessionView {
    fn from_session(session: &Session) -> Self {
        Self {
            id: session.id(),
            initialized: session.is_initialized(),
            state: session.state().snapshot(),
            supports_sampling: session.supports_sampling(),
            supports_elicitation: session.supports_elicitation(),
            log_level: session.log_level(),
            principal_binding: session.principal_binding(),
        }
    }
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
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
        self.handler_config.base_path = path.into();
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
    router: Arc<Router>,
    instructions: Option<String>,
    /// Server-owned request ceiling in seconds (0 = no additional ceiling).
    request_timeout_secs: u64,
    /// Runtime statistics collector (None = disabled).
    stats: Option<ServerStats>,
    /// Whether to mask internal error details in responses.
    mask_error_details: bool,
    /// Logging configuration.
    logging: LoggingConfig,
    /// Console configuration for rich output.
    console_config: ConsoleConfig,
    /// Server-owned console resolved from `console_config`.
    console: FastMcpConsole,
    /// Lifecycle hooks (wrapped in Option so they can be taken once).
    lifespan: Mutex<Option<LifespanHooks>>,
    /// Optional authentication provider.
    auth_provider: Option<Arc<dyn AuthProvider>>,
    /// Registered middleware.
    middleware: Arc<Vec<Box<dyn crate::Middleware>>>,
    /// Active requests by connection/session identity and JSON-RPC request ID.
    active_requests: Mutex<HashMap<ActiveRequestKey, ActiveRequest>>,
    /// Test-only legacy task manager retained while the task subsystem is
    /// rebuilt. It is absent from production library builds.
    #[cfg(test)]
    task_manager: Option<SharedTaskManager>,
    /// Per-connection ceiling for pending server-to-client requests.
    max_bidirectional_requests_per_connection: usize,
    /// Reserved HTTP configuration; public `run_http*` paths currently reject.
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

    fn new_pending_requests_for_connection(&self) -> Arc<bidirectional::PendingRequests> {
        Arc::new(
            bidirectional::PendingRequests::with_max_in_flight(
                self.max_bidirectional_requests_per_connection,
            )
            .expect("ServerBuilder validates the bidirectional request limit"),
        )
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

    /// Returns the test-only legacy task manager, if configured.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn task_manager(&self) -> Option<&SharedTaskManager> {
        self.task_manager.as_ref()
    }

    /// Consumes the server and returns its router.
    ///
    /// This is used for mounting one server's components into another.
    ///
    #[must_use]
    pub fn into_router(self) -> Router {
        Arc::into_inner(self.router)
            .expect("the server is the sole strong owner of its router outside dispatch")
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
        let renderer =
            fastmcp_console::stats::StatsRenderer::new(self.console_config.resolve_context());
        renderer.render_panel(&snapshot, &self.console);
    }

    fn configured_traffic_renderer(&self) -> Option<RequestResponseRenderer> {
        let show_bodies = match self.console_config.traffic_verbosity {
            TrafficVerbosity::None => return None,
            TrafficVerbosity::Summary => false,
            TrafficVerbosity::Full => true,
        };
        let mut renderer = RequestResponseRenderer::new(self.console_config.resolve_context());
        renderer.truncate_at = self.console_config.truncate_at;
        renderer.max_json_depth = self.console_config.max_json_depth;
        renderer.show_params = show_bodies;
        renderer.show_result = show_bodies;
        Some(renderer)
    }

    /// Returns the console configuration.
    #[must_use]
    pub fn console_config(&self) -> &ConsoleConfig {
        &self.console_config
    }

    /// Renders the startup banner based on console configuration.
    fn render_startup_banner(&self, transport: &str) {
        let render = || {
            let mut banner = StartupBanner::new(&self.info.name, &self.info.version)
                .tools(self.router.tools_count())
                .resources(self.router.resources_count())
                .prompts(self.router.prompts_count())
                .transport(transport)
                .show_capabilities(self.console_config.show_capabilities);

            if let Some(desc) = self.instructions.as_deref().filter(|d| !d.is_empty()) {
                banner = banner.description(desc);
            }

            // Apply banner style from config
            match self.console_config.banner_style {
                BannerStyle::Full => banner.render(&self.console),
                BannerStyle::Compact => {
                    banner.no_logo().render(&self.console);
                }
                BannerStyle::Minimal => banner.minimal().render(&self.console),
                BannerStyle::None => {} // Already checked show_banner, but be safe
            }
        };

        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(render)).is_err() {
            self.console
                .print_plain("Warning: startup banner rendering failed");
        }
    }

    /// Initializes rich logging based on server configuration.
    ///
    /// This should be called early in the startup sequence, before any
    /// log output is generated. If initialization fails (e.g., logger
    /// already set), a warning is printed to stderr.
    fn init_rich_logging(&self) {
        let result = RichLoggerBuilder::new()
            .level_filter(self.logging.level)
            .with_timestamps(self.logging.timestamps)
            .with_targets(self.logging.targets)
            .with_file_line(self.logging.file_line)
            .with_max_width(Some(self.console_config.truncate_at))
            .with_context(self.console_config.resolve_context())
            .init();

        if result.is_err() {
            // Logger already initialized (likely by user code), not an error
            self.console
                .print_plain("Note: Rich logging not initialized (logger already set)");
        }
    }

    /// Processes a single JSON-RPC request through the full server dispatch
    /// pipeline (initialization checks, middleware, routing, tool/resource/prompt
    /// execution, error masking, and statistics recording).
    ///
    /// This is the public equivalent of the internal `handle_request` method that
    /// the stdio and custom transport paths use. It allows
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

    /// Processes a single JSON-RPC request against a shared session.
    ///
    /// This is the concurrent counterpart of [`dispatch_request`](Self::dispatch_request).
    /// Use it when the session is shared across threads behind an
    /// `Arc<Mutex<Session>>` (e.g. in HTTP or WebSocket transports where
    /// multiple requests may arrive simultaneously).
    ///
    /// The mutex is held for the full handler duration. MCP tool annotations
    /// are advisory hints, and every handler context can mutate session state
    /// or perform nested calls, so treating a hint as an execution-safety
    /// boundary would permit lost updates.
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
        let mut session_guard = match session.lock() {
            Ok(guard) => guard,
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

    /// Runs the server on stdio transport.
    ///
    /// This is the primary way to run MCP servers as subprocesses. The current
    /// receive pump and serialized dispatch worker run under one ambient server
    /// context; independently owned per-request child contexts remain an
    /// unverified runtime prerequisite.
    pub fn run_stdio(self) -> ! {
        block_on(async move {
            let cx = Cx::current().expect("fastmcp runtime should install a current Cx");
            self.run_stdio_with_cx(&cx)
        })
    }

    /// Runs the server on stdio with a provided Cx.
    ///
    /// This allows integration with a real asupersync runtime.
    pub fn run_stdio_with_cx(self, cx: &Cx) -> ! {
        // Initialize rich logging first, before any log output
        self.init_rich_logging();

        let mut transport = StdioTransport::stdio();
        let mut stdout = AsyncStdout::new();
        let codec = Codec::new();

        // Create a notification sender that writes to a separate stdout handle.
        // This allows progress notifications to be sent during handler execution
        // while the main transport is blocked on recv().
        let notification_sender = create_notification_sender();

        self.run_loop(
            cx,
            move |cx| transport.recv(cx),
            move |cx, message| {
                if cx.is_cancel_requested() {
                    return Err(TransportError::Cancelled);
                }
                let bytes = match message {
                    JsonRpcMessage::Request(request) => codec.encode_request(request)?,
                    JsonRpcMessage::Response(response) => codec.encode_response(response)?,
                };
                stdout.write_all_unchecked(&bytes)?;
                stdout.flush_unchecked()?;
                Ok(())
            },
            notification_sender,
            "stdio",
        )
    }

    /// Runs the server on a custom transport under one ambient server context.
    ///
    /// This is useful for SSE/WebSocket integrations where the transport is
    /// provided by an external server framework.
    pub fn run_transport<T>(self, transport: T) -> !
    where
        T: Transport + Send + 'static,
    {
        block_on(async move {
            let cx = Cx::current().expect("fastmcp runtime should install a current Cx");
            self.run_transport_with_cx(&cx, transport)
        })
    }

    /// Runs the server on a custom transport with a provided Cx.
    ///
    /// This allows integration with a real asupersync runtime.
    pub fn run_transport_with_cx<T>(self, cx: &Cx, transport: T) -> !
    where
        T: Transport + Send + 'static,
    {
        self.run_transport_with_label(cx, transport, "custom")
    }

    fn run_transport_with_label<T>(self, cx: &Cx, transport: T, label: &'static str) -> !
    where
        T: Transport + Send + 'static,
    {
        self.init_rich_logging();

        let shared = SharedTransport::new(transport);
        let notification_sender = create_transport_notification_sender(shared.clone(), cx.clone());

        let shared_recv = shared.clone();
        let shared_send = shared;
        self.run_loop_legacy(
            cx,
            move |cx| shared_recv.recv(cx),
            move |cx, message| shared_send.send(cx, message),
            notification_sender,
            label,
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
        let notification_sender = create_transport_notification_sender(shared.clone(), cx.clone());

        let shared_recv = shared.clone();
        let shared_send = shared;
        self.run_loop_returning_legacy(
            cx,
            move |cx| shared_recv.recv(cx),
            move |cx, message| shared_send.send(cx, message),
            notification_sender,
            "custom",
        );
    }

    /// Runs the server on a custom transport and returns when the transport closes.
    ///
    /// This uses one ambient server [`Cx`], but unlike
    /// [`run_transport`](Self::run_transport) it does not exit the process.
    /// Independently owned per-request child contexts are not yet provided by
    /// this legacy loop.
    pub fn run_transport_returning<T>(self, transport: T)
    where
        T: Transport + Send + 'static,
    {
        block_on(async move {
            let cx = Cx::current().expect("fastmcp runtime should install a current Cx");
            self.run_transport_returning_with_cx(&cx, transport);
        });
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
        block_on(async move {
            let cx = Cx::current().expect("fastmcp runtime should install a current Cx");
            self.run_transport_with_label(&cx, transport, "sse")
        })
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
        self.run_transport_with_label(cx, transport, "sse")
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
        block_on(async move {
            let cx = Cx::current().expect("fastmcp runtime should install a current Cx");
            self.run_transport_with_label(&cx, transport, "websocket")
        })
    }

    /// Runs the server using WebSocket transport with a provided Cx.
    pub fn run_websocket_with_cx<R, W>(self, cx: &Cx, reader: R, writer: W) -> !
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let transport = WsTransport::new(reader, writer);
        self.run_transport_with_label(cx, transport, "websocket")
    }

    // =========================================================================
    // HTTP Server — fail-closed until stateless Streamable HTTP qualification
    // =========================================================================

    /// Rejects use of the not-yet-qualified turnkey HTTP transport.
    ///
    /// The previous listener shared one mutable legacy [`Session`] across all
    /// accepted clients. That violates both client isolation and the stateless
    /// MCP 2026-07-28 HTTP model. Until stateless per-request ingress and an
    /// independently owned request execution context land, this method logs a
    /// fixed diagnostic and exits with status 1 without binding a socket.
    pub fn run_http(self, addr: impl Into<String>) -> ! {
        self.reject_unqualified_http(addr.into(), false);
        unreachable!("non-returning HTTP rejection must terminate the process")
    }

    /// Rejects use of the turnkey HTTP transport with a provided [`Cx`].
    pub fn run_http_with_cx(self, _cx: &Cx, addr: impl Into<String>) -> ! {
        self.reject_unqualified_http(addr.into(), false);
        unreachable!("non-returning HTTP rejection must terminate the process")
    }

    /// Reports the not-yet-qualified HTTP transport and returns without binding.
    ///
    /// Unlike [`run_http`](Self::run_http), this does **not** terminate the
    /// process. It remains useful for embedding code that needs a fail-closed
    /// probe while the stateless HTTP implementation is under construction.
    pub fn run_http_returning(self, addr: impl Into<String>) {
        self.reject_unqualified_http(addr.into(), true);
    }

    /// Fail-closed probe with a custom [`Cx`]; no socket is bound.
    pub fn run_http_returning_with_cx(self, _cx: &Cx, addr: impl Into<String>) {
        self.reject_unqualified_http(addr.into(), true);
    }

    fn configured_http_request_handler(&self) -> HttpRequestHandler {
        HttpRequestHandler::with_config(self.http_config.handler_config.clone())
    }

    /// Fails closed until the stateless MCP 2026-07-28 HTTP path is qualified.
    fn reject_unqualified_http(self, _addr: String, returning: bool) {
        // Rejection must not initialize or replace the embedding process's
        // logger. The fixed direct diagnostic cannot be hidden by a logger
        // filter and contains no caller- or peer-controlled bytes.
        let _ = std::io::stderr().write_all(UNQUALIFIED_HTTP_DIAGNOSTIC);
        if returning {
            return;
        }
        std::process::exit(1);
    }

    /// Unwired legacy HTTP accept loop retained for extraction into LEG-02.
    ///
    /// This sessionful code is deliberately unreachable from every public
    /// `run_http*` entry point. If the 2025-11-25 adapter is implemented, it
    /// must move behind that feature's protocol-policy gate and replace the
    /// shared session with the bounded, owner-bound legacy registry specified
    /// by LEG-02.
    ///
    /// Each accepted connection is handled in its own bounded thread, but the
    /// shared legacy session serializes handler dispatch. This code is retained
    /// only as source material for the future isolated legacy adapter.
    #[allow(clippy::too_many_lines)]
    fn run_unwired_legacy_http_accept_loop(self, cx: &Cx, addr: String, returning: bool) {
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
        let mcp_path = self.http_config.handler_config.base_path.clone();
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

        // Preserve the request policy configured on this server. Constructing a
        // default handler here would silently discard CORS, body-size, and
        // base-path policy supplied through `HttpServerConfig`.
        let http_handler = Arc::new(self.configured_http_request_handler());

        // Traffic renderer.
        let traffic_renderer = Arc::new(self.configured_traffic_renderer());

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
                let request_sender = bidirectional::RequestSender::new(
                    server.new_pending_requests_for_connection(),
                    Arc::new(|_message| {
                        Err("HTTP transport does not support server-to-client requests".into())
                    }),
                );

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
                let status = match &e {
                    fastmcp_transport::http::HttpError::InvalidPath(_) => HttpStatus::NOT_FOUND,
                    fastmcp_transport::http::HttpError::OriginNotAllowed(_) => {
                        HttpStatus::FORBIDDEN
                    }
                    _ => HttpStatus::BAD_REQUEST,
                };
                return http_handler.error_response(status, &format!("Invalid request: {e}"));
            }
        };

        // Log request traffic.
        if let Some(renderer) = traffic_renderer {
            renderer.render_request(&json_rpc, &self.console);
        }

        // Track bytes received.
        if let Some(ref stats) = self.stats {
            if let Ok(json) = serde_json::to_string(&json_rpc) {
                stats.add_bytes_received(json.len() as u64 + 1);
            }
        }

        let start_time = Instant::now();

        // Advisory annotations cannot prove that a handler is free of session
        // mutations or nested calls. Serialize the full request until a
        // framework-enforced read-only context exists.
        let response_opt = {
            let mut session_guard = lock_http_session(session);
            self.handle_request_with_transport_authorization(
                cx,
                &mut session_guard,
                json_rpc,
                http_request.authorization(),
                notification_sender,
                request_sender,
            )
        };

        let duration = start_time.elapsed();

        match response_opt {
            Some(json_rpc_response) => {
                // Log response traffic.
                if let Some(renderer) = traffic_renderer {
                    renderer.render_response(&json_rpc_response, Some(duration), &self.console);
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
                .transport(&transport_label)
                .show_capabilities(self.console_config.show_capabilities);

            if let Some(desc) = self.instructions.as_deref().filter(|d| !d.is_empty()) {
                banner = banner.description(desc);
            }

            match self.console_config.banner_style {
                BannerStyle::Full => banner.render(&self.console),
                BannerStyle::Compact => {
                    banner.no_logo().render(&self.console);
                }
                BannerStyle::Minimal => banner.minimal().render(&self.console),
                BannerStyle::None => {}
            }
        };

        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(render)).is_err() {
            self.console
                .print_plain("Warning: startup banner rendering failed");
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
            match catch_extension_unwind(hook) {
                Ok(Ok(())) => {
                    debug!(target: targets::SERVER, "Startup hook completed successfully");
                    true
                }
                Ok(Err(e)) => {
                    error!(target: targets::SERVER, "Startup hook failed: {}", e);
                    false
                }
                Err(_payload) => {
                    let _ = extension_panic_error("startup_hook");
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
            if catch_extension_unwind(hook).is_err() {
                let _ = extension_panic_error("shutdown_hook");
            } else {
                debug!(target: targets::SERVER, "Shutdown hook completed");
            }
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

    /// Runs a continuous receive pump while one bounded worker serializes
    /// request dispatch against the connection session.
    fn run_loop<R, S>(
        self,
        cx: &Cx,
        recv: R,
        send: S,
        notification_sender: NotificationSender,
        transport_label: &'static str,
    ) -> !
    where
        R: FnMut(&Cx) -> Result<JsonRpcMessage, TransportError>,
        S: FnMut(&Cx, &JsonRpcMessage) -> Result<(), TransportError> + Send + Sync + 'static,
    {
        let exit_code = self.run_loop_pump(cx, recv, send, notification_sender, transport_label);
        std::process::exit(exit_code)
    }

    /// Returning counterpart of [`Self::run_loop`].
    fn run_loop_returning<R, S>(
        self,
        cx: &Cx,
        recv: R,
        send: S,
        notification_sender: NotificationSender,
        transport_label: &'static str,
    ) where
        R: FnMut(&Cx) -> Result<JsonRpcMessage, TransportError>,
        S: FnMut(&Cx, &JsonRpcMessage) -> Result<(), TransportError> + Send + Sync + 'static,
    {
        let _ = self.run_loop_pump(cx, recv, send, notification_sender, transport_label);
    }

    #[allow(clippy::too_many_lines)]
    fn run_loop_pump<R, S>(
        self,
        cx: &Cx,
        mut recv: R,
        send: S,
        notification_sender: NotificationSender,
        transport_label: &'static str,
    ) -> i32
    where
        R: FnMut(&Cx) -> Result<JsonRpcMessage, TransportError>,
        S: FnMut(&Cx, &JsonRpcMessage) -> Result<(), TransportError> + Send + Sync + 'static,
    {
        if let Some(ref stats) = self.stats {
            stats.connection_opened();
        }
        if self.console_config.show_banner && !banner_suppressed() {
            self.render_startup_banner(transport_label);
        }
        if !self.run_startup_hook() {
            error!(target: targets::SERVER, "Startup hook failed, stopping");
            self.graceful_shutdown_returning();
            return 1;
        }

        let traffic_renderer = self.configured_traffic_renderer();

        let server = Arc::new(self);
        let session = Session::new(server.info.clone(), server.capabilities.clone());
        let session_id = session.id();
        let session_principal = session.principal_binding();
        let send = Arc::new(Mutex::new(send));
        let queue_state = Arc::new(DispatchQueueState::default());
        let worker_failed = Arc::new(AtomicBool::new(false));
        let pending_requests = server.new_pending_requests_for_connection();
        let (dispatch_sender, mut dispatch_receiver) =
            asupersync_mpsc::channel::<QueuedDispatchRequest>(MAX_DISPATCH_QUEUE_DEPTH);

        let request_sender = {
            let send = Arc::clone(&send);
            let send_cx = cx.clone();
            let send_fn: bidirectional::TransportSendFn = Arc::new(move |message| {
                let mut guard = send
                    .lock()
                    .map_err(|_| "transport send lock unavailable".to_string())?;
                guard(&send_cx, message).map_err(|_| "transport send failed".to_string())
            });
            bidirectional::RequestSender::new(Arc::clone(&pending_requests), send_fn)
        };

        let worker_server = Arc::clone(&server);
        let worker_send = Arc::clone(&send);
        let worker_queue_state = Arc::clone(&queue_state);
        let worker_failed_flag = Arc::clone(&worker_failed);
        let worker_cx = cx.clone();
        let worker_notification_sender = Arc::clone(&notification_sender);
        let worker_renderer = traffic_renderer.clone();
        let worker = std::thread::spawn(move || {
            let mut failure_latch = DispatchWorkerFailureLatch::new(
                Arc::clone(&worker_failed_flag),
                Arc::clone(&worker_queue_state),
                worker_cx.clone(),
            );
            let mut returned_failure = false;
            let mut session = session;
            loop {
                if worker_queue_state.is_stopping() {
                    break;
                }
                let queued_request = match dispatch_receiver.try_recv() {
                    Ok(request) => request,
                    Err(asupersync_mpsc::RecvError::Empty) => {
                        if worker_queue_state.is_stopping() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(
                        asupersync_mpsc::RecvError::Disconnected
                        | asupersync_mpsc::RecvError::Cancelled,
                    ) => break,
                };
                worker_queue_state.release_queued_bytes(queued_request.serialized_bytes);
                let request = queued_request.request;

                if worker_queue_state.is_stopping() {
                    if let Some(id) = request.id.as_ref() {
                        worker_queue_state.discard(id);
                    }
                    break;
                }

                let start_time = Instant::now();
                if let Some(renderer) = &worker_renderer {
                    renderer.render_request(&request, &self.console);
                }

                let request_id = request.id.clone();
                let handled = worker_server.handle_request_from_dispatch_queue(
                    &worker_cx,
                    &mut session,
                    request,
                    &worker_notification_sender,
                    &request_sender,
                    &worker_queue_state,
                );
                let duration = start_time.elapsed();
                let Some(handled) = handled else {
                    if let Some(id) = request_id.as_ref() {
                        worker_queue_state.discard(id);
                    }
                    continue;
                };

                // Acquire exclusive output ownership before closing the
                // cancellation race. This is the strongest reservation the
                // current synchronous writer surface can provide; the later
                // write/flush can still fail and therefore remains fallible.
                let mut send_guard = worker_send
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let send_result = handled.send_with(&mut session, |response| {
                    send_guard(&worker_cx, &JsonRpcMessage::Response(response.clone()))
                });
                drop(send_guard);
                if let Ok(response) = &send_result {
                    if let Some(renderer) = &worker_renderer {
                        renderer.render_response(response, Some(duration), &self.console);
                    }
                    if let Some(ref stats) = worker_server.stats
                        && let Ok(json) = serde_json::to_string(response)
                    {
                        stats.add_bytes_sent(json.len() as u64 + 1);
                    }
                }
                if let Some(id) = request_id.as_ref() {
                    worker_queue_state.discard(id);
                }
                if send_result.is_err() {
                    returned_failure = true;
                    break;
                }
            }
            if !returned_failure && worker_queue_state.is_stopping() {
                failure_latch.disarm();
            }
        });

        let mut exit_code = 0;
        loop {
            if worker_failed.load(Ordering::Acquire) {
                exit_code = 1;
                break;
            }
            if cx.is_cancel_requested() {
                break;
            }

            let message = match recv(cx) {
                Ok(message) => message,
                Err(TransportError::Closed | TransportError::Cancelled) => break,
                Err(error) => match classify_receive_error(&error) {
                    ReceiveErrorDisposition::Retry => continue,
                    ReceiveErrorDisposition::ReplyWithParseError => {
                        if send_uncorrelated_parse_error(&send, cx).is_err() {
                            exit_code = 1;
                            break;
                        }
                        continue;
                    }
                    ReceiveErrorDisposition::ReplyWithInvalidRequest(request_id) => {
                        if send_invalid_request(&send, cx, request_id).is_err() {
                            exit_code = 1;
                            break;
                        }
                        continue;
                    }
                    ReceiveErrorDisposition::Terminate => {
                        exit_code = 1;
                        break;
                    }
                },
            };

            // Account at the receive boundary so queued, rejected, cancelled,
            // and bidirectional-response frames are not omitted from traffic
            // totals merely because they never reach a dispatch worker.
            if let Some(ref stats) = server.stats
                && let Ok(json) = serde_json::to_string(&message)
            {
                stats.add_bytes_received(json.len() as u64 + 1);
            }

            match message {
                JsonRpcMessage::Response(response) => {
                    if response.validate().is_err() {
                        exit_code = 1;
                        break;
                    }
                    if !pending_requests.route_response(&response) {
                        debug!(target: targets::SERVER, "Received unmatched JSON-RPC response");
                    }
                }
                JsonRpcMessage::Request(mut request)
                    if request.id.is_none() && request.method == "notifications/cancelled" =>
                {
                    if request.validate().is_err() {
                        if send_invalid_request(&send, cx, request.id).is_err() {
                            exit_code = 1;
                            break;
                        }
                        continue;
                    }
                    match server.authenticate_cancelled_control_notification(
                        cx,
                        &session_principal,
                        &mut request,
                    ) {
                        Ok(params) => {
                            if !queue_state.cancel_if_queued(&params.request_id) {
                                server.handle_cancelled_notification(session_id, params);
                                let interrupted = pending_requests.cancel_cancelled();
                                if interrupted > 0 {
                                    debug!(
                                        target: targets::SESSION,
                                        "Interrupted {interrupted} pending server-to-client request(s) owned by the cancelled request"
                                    );
                                }
                            }
                        }
                        Err(error) => {
                            error!(
                                target: targets::SERVER,
                                "Rejected cancellation notification before mutation; code={:?}",
                                error.code
                            )
                        }
                    }
                }
                JsonRpcMessage::Request(request) => {
                    if request.validate().is_err() {
                        if send_invalid_request(&send, cx, request.id).is_err() {
                            exit_code = 1;
                            break;
                        }
                        continue;
                    }
                    let request_id = request.id.clone();
                    if let Some(id) = request_id.as_ref()
                        && (server.request_id_is_active(session_id, id) || !queue_state.admit(id))
                    {
                        let duplicate = JsonRpcResponse::error(
                            Some(id.clone()),
                            JsonRpcError {
                                code: McpErrorCode::InvalidRequest.into(),
                                message: "Request id is already active".to_string(),
                                data: None,
                            },
                        );
                        if send
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)(
                            cx,
                            &JsonRpcMessage::Response(duplicate),
                        )
                        .is_err()
                        {
                            exit_code = 1;
                            break;
                        }
                        continue;
                    }

                    let serialized_bytes = measure_dispatch_request(&request);
                    if serialized_bytes.is_none_or(|bytes| !queue_state.reserve_queued_bytes(bytes))
                    {
                        if let Some(id) = request.id {
                            queue_state.discard(&id);
                            let overloaded = JsonRpcResponse::error(
                                Some(id),
                                JsonRpcError {
                                    code: RESOURCE_EXHAUSTED_ERROR_CODE,
                                    message: DISPATCH_QUEUE_CAPACITY_MESSAGE.to_string(),
                                    data: None,
                                },
                            );
                            if send
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)(
                                cx,
                                &JsonRpcMessage::Response(overloaded),
                            )
                            .is_err()
                            {
                                exit_code = 1;
                                break;
                            }
                        }
                        continue;
                    }
                    let serialized_bytes = serialized_bytes
                        .expect("a dispatch byte reservation requires a measured request");

                    match dispatch_sender.try_send(QueuedDispatchRequest {
                        request,
                        serialized_bytes,
                    }) {
                        Ok(()) => {}
                        Err(asupersync_mpsc::SendError::Full(request)) => {
                            queue_state.release_queued_bytes(request.serialized_bytes);
                            if let Some(id) = request.request.id {
                                queue_state.discard(&id);
                                let overloaded = JsonRpcResponse::error(
                                    Some(id),
                                    JsonRpcError {
                                        code: RESOURCE_EXHAUSTED_ERROR_CODE,
                                        message: DISPATCH_QUEUE_CAPACITY_MESSAGE.to_string(),
                                        data: None,
                                    },
                                );
                                if send
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)(
                                    cx,
                                    &JsonRpcMessage::Response(overloaded),
                                )
                                .is_err()
                                {
                                    exit_code = 1;
                                    break;
                                }
                            }
                        }
                        Err(
                            asupersync_mpsc::SendError::Disconnected(request)
                            | asupersync_mpsc::SendError::Cancelled(request),
                        ) => {
                            queue_state.release_queued_bytes(request.serialized_bytes);
                            if let Some(id) = request.request.id {
                                queue_state.discard(&id);
                            }
                            exit_code = 1;
                            break;
                        }
                    }
                }
            }
        }

        queue_state.stop();
        drop(dispatch_sender);
        server.cancel_active_requests(CancelKind::Shutdown, false);
        pending_requests.cancel_all();
        if worker.join().is_err() {
            exit_code = 1;
        }
        if worker_failed.load(Ordering::Acquire) {
            exit_code = 1;
        }
        server.run_shutdown_hook();
        if let Some(ref stats) = server.stats {
            stats.connection_closed();
        }
        exit_code
    }

    /// Legacy synchronous loop retained privately for differential tests.
    fn run_loop_legacy<R, S>(
        self,
        cx: &Cx,
        mut recv: R,
        send: S,
        notification_sender: NotificationSender,
        transport_label: &'static str,
    ) -> !
    where
        R: FnMut(&Cx) -> Result<JsonRpcMessage, TransportError>,
        S: FnMut(&Cx, &JsonRpcMessage) -> Result<(), TransportError> + Send + Sync + 'static,
    {
        let mut session = Session::new(self.info.clone(), self.capabilities.clone());

        // Wrap send in Arc<Mutex> for shared access from bidirectional requests
        let send = Arc::new(Mutex::new(send));
        let pending_requests = self.new_pending_requests_for_connection();

        // Create a RequestSender for bidirectional communication
        let request_sender = bidirectional::RequestSender::new(
            Arc::clone(&pending_requests),
            Arc::new(|_| Err("bidirectional requests require a split transport".to_string())),
        );

        // Track connection opened
        if let Some(ref stats) = self.stats {
            stats.connection_opened();
        }

        // Render startup banner if enabled (respects both config and legacy env var)
        if self.console_config.show_banner && !banner_suppressed() {
            self.render_startup_banner(transport_label);
        }

        // Run startup hook
        if !self.run_startup_hook() {
            error!(target: targets::SERVER, "Startup hook failed, exiting");
            self.graceful_shutdown(1);
        }

        // Create traffic renderer if enabled
        let traffic_renderer = self.configured_traffic_renderer();

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
                Err(error) => match classify_receive_error(&error) {
                    ReceiveErrorDisposition::Retry => {
                        debug!(target: targets::TRANSPORT, "Transport receive timed out; retrying");
                        continue;
                    }
                    ReceiveErrorDisposition::ReplyWithParseError => {
                        error!(target: targets::TRANSPORT, "Rejected malformed transport message");
                        if send_uncorrelated_parse_error(&send, cx).is_err() {
                            error!(target: targets::TRANSPORT, "Failed to send parse-error response; terminating transport");
                            self.graceful_shutdown(1);
                        }
                        continue;
                    }
                    ReceiveErrorDisposition::ReplyWithInvalidRequest(request_id) => {
                        error!(target: targets::TRANSPORT, "Rejected invalid JSON-RPC request");
                        if send_invalid_request(&send, cx, request_id).is_err() {
                            error!(target: targets::TRANSPORT, "Failed to send invalid-request response; terminating transport");
                            self.graceful_shutdown(1);
                        }
                        continue;
                    }
                    ReceiveErrorDisposition::Terminate => {
                        error!(target: targets::TRANSPORT, "Fatal transport receive failure; terminating transport");
                        self.graceful_shutdown(1);
                    }
                },
            };

            // Log request traffic
            if let Some(renderer) = &traffic_renderer {
                if let JsonRpcMessage::Request(req) = &message {
                    renderer.render_request(req, &self.console);
                }
            }

            let start_time = Instant::now();

            // Handle the message
            let response_opt = match message {
                JsonRpcMessage::Request(request) => {
                    if request.validate().is_err() {
                        if send_invalid_request(&send, cx, request.id).is_err() {
                            self.graceful_shutdown(1);
                        }
                        continue;
                    }
                    // Track bytes received (approximate from serialized request size)
                    if let Some(ref stats) = self.stats {
                        // Estimate request size by serializing back to JSON
                        // This is approximate but accurate enough for statistics
                        if let Ok(json) = serde_json::to_string(&request) {
                            stats.add_bytes_received(json.len() as u64 + 1); // +1 for newline
                        }
                    }
                    self.handle_request_internal(
                        cx,
                        &mut session,
                        request,
                        &notification_sender,
                        &request_sender,
                        None,
                        None,
                    )
                }
                JsonRpcMessage::Response(response) => {
                    if response.validate().is_err() {
                        self.graceful_shutdown(1);
                    }
                    // Route response to pending server-initiated request (bidirectional)
                    if pending_requests.route_response(&response) {
                        debug!(target: targets::SERVER, "Routed response to pending request");
                    } else {
                        let request_key = response.id.as_ref().map(request_id_log_key);
                        debug!(
                            target: targets::SERVER,
                            "Received unexpected response (id_present={}, request_key={:016x})",
                            response.id.is_some(),
                            request_key.unwrap_or_default()
                        );
                    }
                    continue;
                }
            };

            let duration = start_time.elapsed();

            if let Some(response) = response_opt {
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
                let send_result = response.send_with(&mut session, |response| {
                    guard(cx, &JsonRpcMessage::Response(response.clone()))
                });
                drop(guard);
                if let Ok(response) = &send_result {
                    if let Some(renderer) = &traffic_renderer {
                        renderer.render_response(response, Some(duration), &self.console);
                    }
                    if let Some(ref stats) = self.stats
                        && let Ok(json) = serde_json::to_string(response)
                    {
                        stats.add_bytes_sent(json.len() as u64 + 1);
                    }
                }
                if send_result.is_err() {
                    error!(target: targets::TRANSPORT, "Failed to send response; terminating transport");
                    self.graceful_shutdown(1);
                }
            }
        }
    }

    /// Shared server loop for embedding/testing, returning on shutdown instead of exiting.
    ///
    /// This is intentionally separate from [`run_loop`](Self::run_loop) because the primary server
    /// entrypoints use `std::process::exit` on shutdown for subprocess use-cases.
    #[allow(clippy::too_many_lines)]
    fn run_loop_returning_legacy<R, S>(
        self,
        cx: &Cx,
        mut recv: R,
        send: S,
        notification_sender: NotificationSender,
        transport_label: &'static str,
    ) where
        R: FnMut(&Cx) -> Result<JsonRpcMessage, TransportError>,
        S: FnMut(&Cx, &JsonRpcMessage) -> Result<(), TransportError> + Send + Sync + 'static,
    {
        let mut session = Session::new(self.info.clone(), self.capabilities.clone());

        // Wrap send in Arc<Mutex> for shared access from bidirectional requests
        let send = Arc::new(Mutex::new(send));
        let pending_requests = self.new_pending_requests_for_connection();

        // Create a RequestSender for bidirectional communication
        let request_sender = bidirectional::RequestSender::new(
            Arc::clone(&pending_requests),
            Arc::new(|_| Err("bidirectional requests require a split transport".to_string())),
        );

        // Track connection opened
        if let Some(ref stats) = self.stats {
            stats.connection_opened();
        }

        // Render startup banner if enabled (respects both config and legacy env var)
        if self.console_config.show_banner && !banner_suppressed() {
            self.render_startup_banner(transport_label);
        }

        // Run startup hook
        if !self.run_startup_hook() {
            error!(target: targets::SERVER, "Startup hook failed, stopping");
            self.graceful_shutdown_returning();
            return;
        }

        // Create traffic renderer if enabled
        let traffic_renderer = self.configured_traffic_renderer();

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
                Err(error) => match classify_receive_error(&error) {
                    ReceiveErrorDisposition::Retry => {
                        debug!(target: targets::TRANSPORT, "Transport receive timed out; retrying");
                        continue;
                    }
                    ReceiveErrorDisposition::ReplyWithParseError => {
                        error!(target: targets::TRANSPORT, "Rejected malformed transport message");
                        if send_uncorrelated_parse_error(&send, cx).is_err() {
                            error!(target: targets::TRANSPORT, "Failed to send parse-error response; terminating transport");
                            self.graceful_shutdown_returning();
                            return;
                        }
                        continue;
                    }
                    ReceiveErrorDisposition::ReplyWithInvalidRequest(request_id) => {
                        error!(target: targets::TRANSPORT, "Rejected invalid JSON-RPC request");
                        if send_invalid_request(&send, cx, request_id).is_err() {
                            error!(target: targets::TRANSPORT, "Failed to send invalid-request response; terminating transport");
                            self.graceful_shutdown_returning();
                            return;
                        }
                        continue;
                    }
                    ReceiveErrorDisposition::Terminate => {
                        error!(target: targets::TRANSPORT, "Fatal transport receive failure; terminating transport");
                        self.graceful_shutdown_returning();
                        return;
                    }
                },
            };

            // Log request traffic
            if let Some(renderer) = &traffic_renderer {
                if let JsonRpcMessage::Request(req) = &message {
                    renderer.render_request(req, &self.console);
                }
            }

            let start_time = Instant::now();

            // Handle the message
            let response_opt = match message {
                JsonRpcMessage::Request(request) => {
                    if request.validate().is_err() {
                        if send_invalid_request(&send, cx, request.id).is_err() {
                            self.graceful_shutdown_returning();
                            return;
                        }
                        continue;
                    }
                    // Track bytes received (approximate from serialized request size)
                    if let Some(ref stats) = self.stats {
                        // Estimate request size by serializing back to JSON
                        // This is approximate but accurate enough for statistics
                        if let Ok(json) = serde_json::to_string(&request) {
                            stats.add_bytes_received(json.len() as u64 + 1); // +1 for newline
                        }
                    }
                    self.handle_request_internal(
                        cx,
                        &mut session,
                        request,
                        &notification_sender,
                        &request_sender,
                        None,
                        None,
                    )
                }
                JsonRpcMessage::Response(response) => {
                    if response.validate().is_err() {
                        self.graceful_shutdown_returning();
                        return;
                    }
                    // Route response to pending server-initiated request (bidirectional)
                    if pending_requests.route_response(&response) {
                        debug!(target: targets::SERVER, "Routed response to pending request");
                    } else {
                        let request_key = response.id.as_ref().map(request_id_log_key);
                        debug!(
                            target: targets::SERVER,
                            "Received unexpected response (id_present={}, request_key={:016x})",
                            response.id.is_some(),
                            request_key.unwrap_or_default()
                        );
                    }
                    continue;
                }
            };

            let duration = start_time.elapsed();

            if let Some(response) = response_opt {
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
                let send_result = response.send_with(&mut session, |response| {
                    guard(cx, &JsonRpcMessage::Response(response.clone()))
                });
                drop(guard);
                if let Ok(response) = &send_result {
                    if let Some(renderer) = &traffic_renderer {
                        renderer.render_response(response, Some(duration), &self.console);
                    }
                    if let Some(ref stats) = self.stats
                        && let Ok(json) = serde_json::to_string(response)
                    {
                        stats.add_bytes_sent(json.len() as u64 + 1);
                    }
                }
                if send_result.is_err() {
                    error!(target: targets::TRANSPORT, "Failed to send response; terminating transport");
                    self.graceful_shutdown_returning();
                    return;
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
        self.handle_request_internal(
            cx,
            session,
            request,
            notification_sender,
            request_sender,
            None,
            None,
        )
        .map(|handled| handled.finalize_for_return(session))
    }

    /// Handles a request with transport-private authorization metadata.
    fn handle_request_with_transport_authorization(
        &self,
        cx: &Cx,
        session: &mut Session,
        request: JsonRpcRequest,
        transport_authorization: Option<&str>,
        notification_sender: &NotificationSender,
        request_sender: &bidirectional::RequestSender,
    ) -> Option<JsonRpcResponse> {
        self.handle_request_internal(
            cx,
            session,
            request,
            notification_sender,
            request_sender,
            None,
            transport_authorization,
        )
        .map(|handled| handled.finalize_for_return(session))
    }

    fn handle_request_from_dispatch_queue<'a>(
        &'a self,
        cx: &Cx,
        session: &mut Session,
        request: JsonRpcRequest,
        notification_sender: &NotificationSender,
        request_sender: &bidirectional::RequestSender,
        queue_state: &DispatchQueueState,
    ) -> Option<HandledRequest<'a>> {
        self.handle_request_internal(
            cx,
            session,
            request,
            notification_sender,
            request_sender,
            Some(queue_state),
            None,
        )
    }

    fn handle_request_internal<'a>(
        &'a self,
        cx: &Cx,
        session: &mut Session,
        request: JsonRpcRequest,
        notification_sender: &NotificationSender,
        request_sender: &bidirectional::RequestSender,
        dispatch_queue: Option<&DispatchQueueState>,
        transport_authorization: Option<&str>,
    ) -> Option<HandledRequest<'a>> {
        let id = request.id.clone();
        let method = request.method.clone();
        let is_notification = id.is_none();

        // Start timing for stats
        let start_time = Instant::now();

        if !is_notification && is_notification_only_method(&method) {
            let deferred_stats = DeferredRequestStats::new(
                self.stats.as_ref(),
                &method,
                start_time,
                DeferredRequestOutcome::Failure,
            );
            return Some(
                HandledRequest::untracked(JsonRpcResponse::error(
                    id,
                    JsonRpcError {
                        code: McpErrorCode::InvalidRequest.into(),
                        message: "MCP notification method must not carry a request id".to_string(),
                        data: None,
                    },
                ))
                .with_deferred_stats(deferred_stats),
            );
        }

        if is_notification && is_request_only_method(&method) {
            if let Some(ref stats) = self.stats {
                stats.record_request(&method, start_time.elapsed(), false);
            }
            error!(
                target: targets::SERVER,
                "Rejected request-only MCP method sent without an id; method_key={:016x}",
                stable_hash_request_id(&method)
            );
            return None;
        }

        // Generate internal request ID for tracing
        let request_id = request_id_to_u64(id.as_ref());

        // Create a budget for this request based on timeout configuration
        let budget = self.create_request_budget(cx);

        // Reject an already-cancelled or exhausted request before it acquires
        // request tracking or enters authentication/middleware.
        if let Some(error) = Self::request_budget_error(cx, budget) {
            // If it's a notification, we don't send an error response
            let outcome = if error.code == McpErrorCode::RequestCancelled {
                DeferredRequestOutcome::Cancelled
            } else {
                DeferredRequestOutcome::Failure
            };
            let Some(response_id) = id.clone() else {
                if let Some(stats) =
                    DeferredRequestStats::new(self.stats.as_ref(), &method, start_time, outcome)
                {
                    stats.record();
                }
                return None;
            };
            let deferred_stats =
                DeferredRequestStats::new(self.stats.as_ref(), &method, start_time, outcome);
            return Some(
                HandledRequest::untracked(JsonRpcResponse::error(
                    Some(response_id),
                    JsonRpcError {
                        code: error.code.into(),
                        message: error.message,
                        data: error.data,
                    },
                ))
                .with_deferred_stats(deferred_stats),
            );
        }

        let request_cx = cx.clone();

        let active_guard = match id.clone() {
            Some(request_id) => {
                match ActiveRequestGuard::try_new(
                    &self.active_requests,
                    session.id(),
                    request_id.clone(),
                    request_cx.clone(),
                ) {
                    Ok(guard) => Some(guard),
                    Err(_duplicate_id) => {
                        let message = "Request id is already active; wait for the earlier request to finish before reusing it".to_string();
                        let deferred_stats = DeferredRequestStats::new(
                            self.stats.as_ref(),
                            &method,
                            start_time,
                            DeferredRequestOutcome::Failure,
                        );
                        return Some(
                            HandledRequest::untracked(JsonRpcResponse::error(
                                Some(request_id),
                                JsonRpcError {
                                    code: McpErrorCode::InvalidRequest.into(),
                                    message,
                                    data: None,
                                },
                            ))
                            .with_deferred_stats(deferred_stats),
                        );
                    }
                }
            }
            None => None,
        };
        let request_cancellation = active_guard.as_ref().map_or_else(
            McpRequestCancellation::new,
            ActiveRequestGuard::cancellation,
        );
        if let (Some(queue), Some(request_id)) = (dispatch_queue, id.as_ref())
            && queue.begin_dispatch(request_id)
        {
            let _ = request_cancellation.cancel();
        }

        // Dispatch based on method, passing the budget, notification sender, and request sender
        let mut session_mutation_rollback = None;
        let mut result = self.dispatch_method(
            &request_cx,
            session,
            request,
            request_id,
            &request_cancellation,
            &budget,
            notification_sender,
            request_sender,
            &mut session_mutation_rollback,
            transport_authorization,
        );
        result = Self::enforce_post_dispatch_liveness(
            &request_cancellation,
            &request_cx,
            budget,
            result,
        );
        if result.is_err()
            && let Some(rollback) = session_mutation_rollback.take()
        {
            rollback.apply(session);
        }

        let stats_outcome = match &result {
            Ok(_) => DeferredRequestOutcome::Success,
            Err(e) if e.code == McpErrorCode::RequestCancelled => DeferredRequestOutcome::Cancelled,
            Err(_) => DeferredRequestOutcome::Failure,
        };

        // If it's a notification (no ID), we must not reply
        if is_notification {
            if let Err(e) = result {
                fastmcp_core::logging::error!(
                    target: targets::HANDLER,
                    "Notification method={} failed with code={:?}",
                    safe_peer_log_key(&method),
                    e.code
                );
            }
            if let Some(stats) =
                DeferredRequestStats::new(self.stats.as_ref(), &method, start_time, stats_outcome)
            {
                stats.record();
            }
            return None;
        }

        // We only reach here if `is_notification` is false, which implies `id` is present.
        // Use `?` to avoid `unwrap()` and keep the control-flow explicit.
        let response_id = id.clone()?;

        let response = match result {
            Ok(value) => JsonRpcResponse::success(response_id, value),
            Err(e) => {
                // Log full error before masking if this is an internal error
                if self.mask_error_details && e.is_internal() {
                    fastmcp_core::logging::error!(
                        target: targets::HANDLER,
                        "Request method={} failed with masked internal code={:?}",
                        safe_peer_log_key(&method),
                        e.code
                    );
                }

                // Apply masking if enabled
                let masked = mask_peer_error(e, self.mask_error_details);
                JsonRpcResponse::error(
                    id,
                    JsonRpcError {
                        code: masked.code.into(),
                        message: masked.message,
                        data: masked.data,
                    },
                )
            }
        };

        let deferred_stats =
            DeferredRequestStats::new(self.stats.as_ref(), &method, start_time, stats_outcome);
        Some(
            HandledRequest::tracked(
                response,
                request_cancellation,
                active_guard,
                session_mutation_rollback,
                request_cx,
                budget,
            )
            .with_deferred_stats(deferred_stats),
        )
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
        if !is_notification && is_notification_only_method(&method) {
            if let Some(ref stats) = self.stats {
                stats.record_request(&method, start_time.elapsed(), false);
            }
            return Some(JsonRpcResponse::error(
                id,
                JsonRpcError {
                    code: McpErrorCode::InvalidRequest.into(),
                    message: "MCP notification method must not carry a request id".to_string(),
                    data: None,
                },
            ));
        }
        if is_notification && is_request_only_method(&method) {
            if let Some(ref stats) = self.stats {
                stats.record_request(&method, start_time.elapsed(), false);
            }
            return None;
        }
        let request_id = request_id_to_u64(id.as_ref());
        let budget = self.create_request_budget(cx);

        if let Some(error) = Self::request_budget_error(cx, budget) {
            if let Some(ref stats) = self.stats {
                stats.record_request(&method, start_time.elapsed(), false);
            }
            let response_id = id.clone()?;
            return Some(JsonRpcResponse::error(
                Some(response_id),
                JsonRpcError {
                    code: error.code.into(),
                    message: error.message,
                    data: error.data,
                },
            ));
        }

        let request_cx = cx.clone();

        let active_guard = match id.clone() {
            Some(request_id) => {
                match ActiveRequestGuard::try_new(
                    &self.active_requests,
                    session.id,
                    request_id.clone(),
                    request_cx.clone(),
                ) {
                    Ok(guard) => Some(guard),
                    Err(_duplicate_id) => {
                        if let Some(ref stats) = self.stats {
                            stats.record_request(&method, start_time.elapsed(), false);
                        }
                        let message = "Request id is already active; wait for the earlier request to finish before reusing it".to_string();
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
        let request_cancellation = active_guard.as_ref().map_or_else(
            McpRequestCancellation::new,
            ActiveRequestGuard::cancellation,
        );

        let mut result = self.dispatch_read_only_http_method(
            &request_cx,
            session,
            request,
            request_id,
            &request_cancellation,
            &budget,
            notification_sender,
            request_sender,
        );
        result = Self::enforce_post_dispatch_liveness(
            &request_cancellation,
            &request_cx,
            budget,
            result,
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
                    "Notification method={} failed with code={:?}",
                    safe_peer_log_key(&method),
                    e.code
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
                        "Request method={} failed with masked internal code={:?}",
                        safe_peer_log_key(&method),
                        e.code
                    );
                }

                let masked = mask_peer_error(e, self.mask_error_details);
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
    fn create_request_budget(&self, cx: &Cx) -> Budget {
        if self.request_timeout_secs == 0 {
            // No timeout - unlimited budget
            Budget::INFINITE
        } else {
            // Keep the ceiling in the caller context's clock domain so router
            // admission and post-completion checks compare like with like.
            // The legacy synchronous handler dispatcher uses a private runtime
            // for its timeout future and therefore does not itself drive a
            // foreign virtual clock.
            let now = cx.now();
            let timeout_ns = self.request_timeout_secs.saturating_mul(1_000_000_000);
            let deadline = now.saturating_add_nanos(timeout_ns);
            Budget::new().with_deadline(deadline)
        }
    }

    fn request_budget_error(cx: &Cx, budget: Budget) -> Option<McpError> {
        if cx.is_cancel_requested() {
            return Some(McpError::request_cancelled());
        }
        let effective_budget = cx.budget().meet(budget);
        if effective_budget.is_past_deadline(cx.now()) {
            return Some(McpError::new(
                McpErrorCode::RequestCancelled,
                "Request timeout exceeded",
            ));
        }
        None
    }

    fn enforce_request_budget(cx: &Cx, budget: Budget) -> McpResult<()> {
        match Self::request_budget_error(cx, budget) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn enforce_post_dispatch_liveness(
        request_cancellation: &McpRequestCancellation,
        cx: &Cx,
        budget: Budget,
        mut result: McpResult<serde_json::Value>,
    ) -> McpResult<serde_json::Value> {
        if request_cancellation.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }
        if let Some(error) = Self::request_budget_error(cx, budget) {
            result = Err(error);
        }
        result
    }

    fn request_context_error(ctx: &McpContext) -> Option<McpError> {
        if ctx.ensure_live().is_err() {
            return Some(McpError::request_cancelled());
        }
        None
    }

    fn enforce_request_context(ctx: &McpContext) -> McpResult<()> {
        match Self::request_context_error(ctx) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Builds the single shared authority object for one request.
    ///
    /// Authentication, middleware, top-level handlers, and any nested
    /// tool/resource dispatch all derive from this context so request-local
    /// budget accounting remains shared and the committed authenticated
    /// principal cannot be replaced between layers.
    fn request_context(
        &self,
        cx: &Cx,
        request_id: u64,
        state: SessionState,
        request_cancellation: McpRequestCancellation,
        budget: Budget,
    ) -> McpResult<(McpContext, McpContextLeaseGuard)> {
        let tool_caller = Arc::new(RouterToolCaller::request_scoped(
            Arc::downgrade(&self.router),
            state.clone(),
        ));
        let resource_reader = Arc::new(RouterResourceReader::request_scoped(
            Arc::downgrade(&self.router),
            state.clone(),
        ));

        McpContext::with_state(cx.clone(), request_id, state)
            .with_request_cancellation(request_cancellation)
            .with_budget_ceiling(budget)
            .with_tool_caller(tool_caller)
            .with_resource_reader(resource_reader)
            .begin_request_scope()
            .ok_or_else(|| McpError::internal_error("request scope could not be established"))
    }

    /// Dispatches a request to the appropriate handler.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn dispatch_method(
        &self,
        cx: &Cx,
        session: &mut Session,
        mut request: JsonRpcRequest,
        request_id: u64,
        request_cancellation: &McpRequestCancellation,
        budget: &Budget,
        notification_sender: &NotificationSender,
        request_sender: &bidirectional::RequestSender,
        session_mutation_rollback: &mut Option<SessionMutationRollback>,
        transport_authorization: Option<&str>,
    ) -> Result<serde_json::Value, McpError> {
        let (mw_ctx, _request_lease_guard) = self.request_context(
            cx,
            request_id,
            session.state().clone(),
            request_cancellation.clone(),
            *budget,
        )?;
        if let Err(error) = Self::enforce_request_context(&mw_ctx) {
            let result =
                Self::enforce_post_dispatch_liveness(request_cancellation, cx, *budget, Err(error));
            self.maybe_emit_log_notification(
                session,
                notification_sender,
                &request.method,
                &result,
            );
            return result;
        }

        // Reject before authentication or extension middleware can claim the
        // method. Quarantine must be invariant under server configuration.
        if is_quarantined_task_rpc(&request.method) {
            let result = Self::enforce_post_dispatch_liveness(
                request_cancellation,
                cx,
                *budget,
                Err(McpError::method_not_found(&request.method)),
            );
            self.maybe_emit_log_notification(
                session,
                notification_sender,
                &request.method,
                &result,
            );
            return result;
        }

        // Check initialization state
        if !session.is_initialized() && request.method != "initialize" && request.method != "ping" {
            let result = Self::enforce_post_dispatch_liveness(
                request_cancellation,
                cx,
                *budget,
                Err(McpError::invalid_request(
                    "Server not initialized. Client must send 'initialize' first.",
                )),
            );
            self.maybe_emit_log_notification(
                session,
                notification_sender,
                &request.method,
                &result,
            );
            return result;
        }

        let auth_result = {
            let auth_request = AuthRequest {
                method: &request.method,
                params: request.params.as_ref(),
                transport_authorization,
                request_id,
            };
            self.authenticate_request(&mw_ctx, auth_request)
                .and_then(|fingerprint| {
                    if session.principal_binding().bind_or_verify(fingerprint) {
                        Self::enforce_request_context(&mw_ctx)
                    } else {
                        Err(McpError::new(
                            McpErrorCode::ResourceForbidden,
                            "Authenticated principal does not own this session",
                        ))
                    }
                })
        };
        auth::strip_recognized_access_credentials(&mut request.params);
        if let Err(err) = auth_result {
            let err = Self::request_context_error(&mw_ctx).unwrap_or(err);
            let err =
                self.finalize_global_middleware_error(request_cancellation, &mw_ctx, &request, err);
            let result = Err(err);
            self.maybe_emit_log_notification(
                session,
                notification_sender,
                &request.method,
                &result,
            );
            return result;
        }

        // Middleware: on_request
        // We use a temporary context derived from the request context for middleware
        // so they can access session state, request auth, and share the request's lifecycle.
        let mut entered_middleware: Vec<&dyn crate::Middleware> = Vec::new();

        for m in self.middleware.iter() {
            if let Some(error) = Self::request_context_error(&mw_ctx) {
                let result = self.finalize_middleware_result(
                    request_cancellation,
                    &entered_middleware,
                    &mw_ctx,
                    &request,
                    Err(error),
                );
                self.maybe_emit_log_notification(
                    session,
                    notification_sender,
                    &request.method,
                    &result,
                );
                return result;
            }
            entered_middleware.push(m.as_ref());
            let decision = match catch_extension_unwind(|| m.on_request(&mw_ctx, &request)) {
                Ok(decision) => decision,
                Err(_payload) => Err(extension_panic_error("middleware_on_request")),
            };
            if let Some(error) = Self::request_context_error(&mw_ctx) {
                let result = self.finalize_middleware_result(
                    request_cancellation,
                    &entered_middleware,
                    &mw_ctx,
                    &request,
                    Err(error),
                );
                self.maybe_emit_log_notification(
                    session,
                    notification_sender,
                    &request.method,
                    &result,
                );
                return result;
            }
            match decision {
                Ok(crate::MiddlewareDecision::Continue) => {}
                Ok(crate::MiddlewareDecision::Respond(v)) => {
                    let short_circuit_result = if is_session_mutation(&request.method) {
                        Err(McpError::internal_error(
                            "Middleware cannot short-circuit session mutations",
                        ))
                    } else {
                        Ok(v)
                    };
                    let result = self.finalize_middleware_result(
                        request_cancellation,
                        &entered_middleware,
                        &mw_ctx,
                        &request,
                        short_circuit_result,
                    );
                    self.maybe_emit_log_notification(
                        session,
                        notification_sender,
                        &request.method,
                        &result,
                    );
                    return result;
                }
                Err(e) => {
                    let result = self.finalize_middleware_result(
                        request_cancellation,
                        &entered_middleware,
                        &mw_ctx,
                        &request,
                        Err(e),
                    );
                    self.maybe_emit_log_notification(
                        session,
                        notification_sender,
                        &request.method,
                        &result,
                    );
                    return result;
                }
            }
        }

        // Everything after middleware entry must flow through `result` so that:
        // - `on_response` runs for successes in reverse middleware order
        // - `on_error` runs for handler/middleware errors in reverse middleware order
        //
        // Without this, `?` would early-return from `dispatch_method` and bypass middleware error
        // rewriting, contradicting the ordering semantics documented in `middleware.rs`.
        let result: Result<serde_json::Value, McpError> = (|| {
            Self::enforce_request_context(&mw_ctx)?;
            let method = &request.method;
            let params = request.params.clone();

            // Create bidirectional senders based on client capabilities
            let bidirectional_senders =
                self.create_bidirectional_senders(session, request_sender, request_cancellation);

            match method.as_str() {
                "initialize" => {
                    let params: InitializeParams = parse_params(params)?;
                    *session_mutation_rollback =
                        Some(SessionMutationRollback::RestoreInitialization(
                            session.initialization_snapshot(),
                        ));
                    let result = self.router.handle_initialize(
                        &mw_ctx,
                        session,
                        params,
                        self.instructions.as_deref(),
                    )?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                "notifications/initialized" => {
                    // Notification, no response needed (but we send empty ok)
                    Ok(serde_json::Value::Null)
                }
                "notifications/cancelled" => {
                    let params: CancelledParams = parse_params(params)?;
                    self.handle_cancelled_notification(session.id(), params);
                    Ok(serde_json::Value::Null)
                }
                "logging/setLevel" => {
                    let params: SetLogLevelParams = parse_params(params)?;
                    *session_mutation_rollback = Some(SessionMutationRollback::RestoreLogLevel(
                        session.log_level(),
                    ));
                    self.handle_set_log_level(session, params);
                    Ok(serde_json::Value::Null)
                }
                "tools/list" => {
                    let params: ListToolsParams = parse_params_or_default(params)?;
                    let result =
                        self.router
                            .handle_tools_list(&mw_ctx, params, Some(session.state()))?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                "tools/call" => {
                    let params: CallToolParams = parse_params(params)?;
                    let result = self.router.handle_tools_call(
                        &mw_ctx,
                        params,
                        session.state().clone(),
                        Some(notification_sender),
                        bidirectional_senders.as_ref(),
                    )?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                "resources/list" => {
                    let params: ListResourcesParams = parse_params_or_default(params)?;
                    let result = self.router.handle_resources_list(
                        &mw_ctx,
                        params,
                        Some(session.state()),
                    )?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                "resources/templates/list" => {
                    let params: ListResourceTemplatesParams = parse_params_or_default(params)?;
                    let result = self.router.handle_resource_templates_list(
                        &mw_ctx,
                        params,
                        Some(session.state()),
                    )?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                "resources/read" => {
                    let params: ReadResourceParams = parse_params(params)?;
                    let result = self.router.handle_resources_read(
                        &mw_ctx,
                        &params,
                        session.state().clone(),
                        Some(notification_sender),
                        bidirectional_senders.as_ref(),
                    )?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                "resources/subscribe" => {
                    let params: SubscribeResourceParams = parse_params(params)?;
                    let uri = params.uri;
                    // Enforce the individual retention bound before router
                    // lookup/template matching can hash or scan an impossible
                    // peer-controlled URI.
                    if uri.len() > MAX_RESOURCE_SUBSCRIPTION_BYTES_PER_SESSION {
                        return Err(resource_subscription_capacity_error());
                    }
                    if !self.router.resource_exists(&uri) {
                        return Err(McpError::resource_not_found(&uri));
                    }
                    match session.subscribe_resource(&mw_ctx, uri.clone()) {
                        Ok(SubscriptionAdmission::Accepted) => {
                            *session_mutation_rollback =
                                Some(SessionMutationRollback::RemoveResourceSubscription(uri));
                            Ok(serde_json::json!({}))
                        }
                        Ok(SubscriptionAdmission::Duplicate) => Ok(serde_json::json!({})),
                        Err(SubscriptionAdmissionError::CapacityExceeded) => {
                            Err(resource_subscription_capacity_error())
                        }
                        Err(SubscriptionAdmissionError::RequestNotLive) => {
                            Err(McpError::request_cancelled())
                        }
                    }
                }
                "resources/unsubscribe" => {
                    let params: UnsubscribeResourceParams = parse_params(params)?;
                    let uri = params.uri;
                    match session.unsubscribe_resource(&mw_ctx, &uri) {
                        Ok(SubscriptionRemoval::Removed) => {
                            *session_mutation_rollback =
                                Some(SessionMutationRollback::RestoreResourceSubscription(uri));
                            Ok(serde_json::json!({}))
                        }
                        Ok(SubscriptionRemoval::NotSubscribed) => Ok(serde_json::json!({})),
                        Err(SubscriptionRemovalError::RequestNotLive) => {
                            Err(McpError::request_cancelled())
                        }
                    }
                }
                "prompts/list" => {
                    let params: ListPromptsParams = parse_params_or_default(params)?;
                    let result =
                        self.router
                            .handle_prompts_list(&mw_ctx, params, Some(session.state()))?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                "prompts/get" => {
                    let params: GetPromptParams = parse_params(params)?;
                    let result = self.router.handle_prompts_get(
                        &mw_ctx,
                        params,
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
                _ => Err(McpError::method_not_found(method)),
            }
        })();

        let final_result = self.finalize_middleware_result(
            request_cancellation,
            &entered_middleware,
            &mw_ctx,
            &request,
            result,
        );

        if final_result.is_err()
            && let Some(rollback) = session_mutation_rollback.take()
        {
            rollback.apply(session);
        }

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
        mut request: JsonRpcRequest,
        request_id: u64,
        request_cancellation: &McpRequestCancellation,
        budget: &Budget,
        notification_sender: &NotificationSender,
        request_sender: &bidirectional::RequestSender,
    ) -> Result<serde_json::Value, McpError> {
        let (mw_ctx, _request_lease_guard) = self.request_context(
            cx,
            request_id,
            session.state.clone(),
            request_cancellation.clone(),
            *budget,
        )?;
        if let Err(error) = Self::enforce_request_context(&mw_ctx) {
            let result =
                Self::enforce_post_dispatch_liveness(request_cancellation, cx, *budget, Err(error));
            self.maybe_emit_log_notification_for_level(
                session.log_level,
                notification_sender,
                &request.method,
                &result,
            );
            return result;
        }

        // Preserve the same fail-closed invariant if this private legacy
        // snapshot path is ever invoked directly.
        if is_quarantined_task_rpc(&request.method) {
            let result = Self::enforce_post_dispatch_liveness(
                request_cancellation,
                cx,
                *budget,
                Err(McpError::method_not_found(&request.method)),
            );
            self.maybe_emit_log_notification_for_level(
                session.log_level,
                notification_sender,
                &request.method,
                &result,
            );
            return result;
        }

        if !session.initialized && request.method != "initialize" && request.method != "ping" {
            let result = Self::enforce_post_dispatch_liveness(
                request_cancellation,
                cx,
                *budget,
                Err(McpError::invalid_request(
                    "Server not initialized. Client must send 'initialize' first.",
                )),
            );
            self.maybe_emit_log_notification_for_level(
                session.log_level,
                notification_sender,
                &request.method,
                &result,
            );
            return result;
        }

        let auth_result = {
            let auth_request = AuthRequest {
                method: &request.method,
                params: request.params.as_ref(),
                transport_authorization: None,
                request_id,
            };
            self.authenticate_request(&mw_ctx, auth_request)
                .and_then(|fingerprint| {
                    if session.principal_binding.bind_or_verify(fingerprint) {
                        Self::enforce_request_context(&mw_ctx)
                    } else {
                        Err(McpError::new(
                            McpErrorCode::ResourceForbidden,
                            "Authenticated principal does not own this session",
                        ))
                    }
                })
        };
        auth::strip_recognized_access_credentials(&mut request.params);
        if let Err(err) = auth_result {
            let err = Self::request_context_error(&mw_ctx).unwrap_or(err);
            let err =
                self.finalize_global_middleware_error(request_cancellation, &mw_ctx, &request, err);
            let result = Err(err);
            self.maybe_emit_log_notification_for_level(
                session.log_level,
                notification_sender,
                &request.method,
                &result,
            );
            return result;
        }

        let mut entered_middleware: Vec<&dyn crate::Middleware> = Vec::new();

        for m in self.middleware.iter() {
            if let Some(error) = Self::request_context_error(&mw_ctx) {
                let result = self.finalize_middleware_result(
                    request_cancellation,
                    &entered_middleware,
                    &mw_ctx,
                    &request,
                    Err(error),
                );
                self.maybe_emit_log_notification_for_level(
                    session.log_level,
                    notification_sender,
                    &request.method,
                    &result,
                );
                return result;
            }
            entered_middleware.push(m.as_ref());
            let decision = match catch_extension_unwind(|| m.on_request(&mw_ctx, &request)) {
                Ok(decision) => decision,
                Err(_payload) => Err(extension_panic_error("middleware_on_request")),
            };
            if let Some(error) = Self::request_context_error(&mw_ctx) {
                let result = self.finalize_middleware_result(
                    request_cancellation,
                    &entered_middleware,
                    &mw_ctx,
                    &request,
                    Err(error),
                );
                self.maybe_emit_log_notification_for_level(
                    session.log_level,
                    notification_sender,
                    &request.method,
                    &result,
                );
                return result;
            }
            match decision {
                Ok(crate::MiddlewareDecision::Continue) => {}
                Ok(crate::MiddlewareDecision::Respond(v)) => {
                    let short_circuit_result = if is_session_mutation(&request.method) {
                        Err(McpError::internal_error(
                            "Middleware cannot short-circuit session mutations",
                        ))
                    } else {
                        Ok(v)
                    };
                    let result = self.finalize_middleware_result(
                        request_cancellation,
                        &entered_middleware,
                        &mw_ctx,
                        &request,
                        short_circuit_result,
                    );
                    self.maybe_emit_log_notification_for_level(
                        session.log_level,
                        notification_sender,
                        &request.method,
                        &result,
                    );
                    return result;
                }
                Err(e) => {
                    let result = self.finalize_middleware_result(
                        request_cancellation,
                        &entered_middleware,
                        &mw_ctx,
                        &request,
                        Err(e),
                    );
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

        let result: Result<serde_json::Value, McpError> = (|| {
            Self::enforce_request_context(&mw_ctx)?;
            let method = &request.method;
            let params = request.params.clone();
            let bidirectional_senders = self.create_bidirectional_senders_from_view(
                session,
                request_sender,
                request_cancellation,
            );

            match method.as_str() {
                "tools/call" => {
                    let params: CallToolParams = parse_params(params)?;
                    let result = self.router.handle_tools_call(
                        &mw_ctx,
                        params,
                        session.state.clone(),
                        Some(notification_sender),
                        bidirectional_senders.as_ref(),
                    )?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                "resources/read" => {
                    let params: ReadResourceParams = parse_params(params)?;
                    let result = self.router.handle_resources_read(
                        &mw_ctx,
                        &params,
                        session.state.clone(),
                        Some(notification_sender),
                        bidirectional_senders.as_ref(),
                    )?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                "prompts/get" => {
                    let params: GetPromptParams = parse_params(params)?;
                    let result = self.router.handle_prompts_get(
                        &mw_ctx,
                        params,
                        session.state.clone(),
                        Some(notification_sender),
                        bidirectional_senders.as_ref(),
                    )?;
                    Ok(serde_json::to_value(result).map_err(McpError::from)?)
                }
                _ => Err(McpError::method_not_found(method)),
            }
        })();

        let final_result = self.finalize_middleware_result(
            request_cancellation,
            &entered_middleware,
            &mw_ctx,
            &request,
            result,
        );

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
        if let Some(error) = Self::request_context_error(ctx) {
            return Err(error);
        }
        let mut response = value;
        for m in stack.iter().rev() {
            let invocation = catch_extension_unwind(|| m.on_response(ctx, request, response));
            match invocation {
                Ok(Ok(next)) => {
                    response = next;
                    if let Some(error) = Self::request_context_error(ctx) {
                        return Err(error);
                    }
                }
                Ok(Err(err)) => return Err(err),
                Err(_payload) => {
                    return Err(extension_panic_error("middleware_on_response"));
                }
            }
        }
        Ok(response)
    }

    fn finalize_middleware_result(
        &self,
        request_cancellation: &McpRequestCancellation,
        stack: &[&dyn crate::Middleware],
        ctx: &McpContext,
        request: &JsonRpcRequest,
        result: McpResult<serde_json::Value>,
    ) -> McpResult<serde_json::Value> {
        let initial = Self::request_context_error(ctx).map_or(result, Err);
        let mut terminal_cancellation = initial
            .as_ref()
            .is_err_and(|error| error.code == McpErrorCode::RequestCancelled);
        let (result, error_hooks_applied) = match initial {
            Ok(value) => match self.apply_middleware_response(stack, ctx, request, value) {
                Ok(value) => (Ok(value), false),
                Err(error) => {
                    terminal_cancellation |= error.code == McpErrorCode::RequestCancelled;
                    (
                        Err(self.apply_middleware_error(stack, ctx, request, error)),
                        true,
                    )
                }
            },
            Err(error) => (
                Err(self.apply_middleware_error(stack, ctx, request, error)),
                true,
            ),
        };

        // Response/error middleware is part of request dispatch. Cancellation
        // remains eligible throughout those callbacks and until the caller's
        // actual response-commit boundary. Error hooks may observe and clean
        // up a cancellation, but may not rewrite its terminal wire class.
        let cancellation_observed = terminal_cancellation
            || Self::request_context_error(ctx).is_some()
            || request_cancellation.is_cancel_requested();
        if cancellation_observed {
            if !error_hooks_applied {
                let _ =
                    self.apply_middleware_error(stack, ctx, request, McpError::request_cancelled());
            }
            return Err(McpError::request_cancelled());
        }

        result
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
            err = match catch_extension_unwind(|| m.on_error(ctx, request, err)) {
                Ok(next) => next,
                // A panicking error hook must not prevent earlier middleware
                // from running their reverse-order cleanup. Replace the
                // in-flight error with the fixed peer-safe failure and keep
                // unwinding the entered middleware stack.
                Err(_payload) => extension_panic_error("middleware_on_error"),
            };
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
            err = match catch_extension_unwind(|| m.on_error(ctx, request, err)) {
                Ok(next) => next,
                // Auth and other pre-entry failures use the full registered
                // stack. Preserve reverse cleanup even if one hook panics.
                Err(_payload) => extension_panic_error("middleware_on_error"),
            };
        }
        err
    }

    fn finalize_global_middleware_error(
        &self,
        request_cancellation: &McpRequestCancellation,
        ctx: &McpContext,
        request: &JsonRpcRequest,
        error: McpError,
    ) -> McpError {
        let terminal_cancellation = error.code == McpErrorCode::RequestCancelled;
        let mapped = self.apply_global_middleware_error(ctx, request, error);
        if terminal_cancellation
            || Self::request_context_error(ctx).is_some()
            || request_cancellation.is_cancel_requested()
        {
            return McpError::request_cancelled();
        }
        mapped
    }

    /// Creates bidirectional senders based on client capabilities.
    ///
    /// Returns `Some(BidirectionalSenders)` if the client supports any bidirectional
    /// features (sampling, elicitation), or `None` if no features are supported.
    fn create_bidirectional_senders(
        &self,
        session: &Session,
        request_sender: &bidirectional::RequestSender,
        request_cancellation: &McpRequestCancellation,
    ) -> Option<handler::BidirectionalSenders> {
        self.create_bidirectional_senders_from_capabilities(
            session.supports_sampling(),
            session.supports_elicitation(),
            request_sender,
            request_cancellation,
        )
    }

    fn create_bidirectional_senders_from_view(
        &self,
        session: &SessionView,
        request_sender: &bidirectional::RequestSender,
        request_cancellation: &McpRequestCancellation,
    ) -> Option<handler::BidirectionalSenders> {
        self.create_bidirectional_senders_from_capabilities(
            session.supports_sampling,
            session.supports_elicitation,
            request_sender,
            request_cancellation,
        )
    }

    fn create_bidirectional_senders_from_capabilities(
        &self,
        supports_sampling: bool,
        supports_elicitation: bool,
        request_sender: &bidirectional::RequestSender,
        request_cancellation: &McpRequestCancellation,
    ) -> Option<handler::BidirectionalSenders> {
        if !supports_sampling && !supports_elicitation {
            return None;
        }

        let mut senders = handler::BidirectionalSenders::new();
        let request_sender = request_sender.for_request(request_cancellation.clone());

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

    fn authenticate_request(
        &self,
        ctx: &McpContext,
        request: AuthRequest<'_>,
    ) -> Result<Sha256Digest, McpError> {
        if !request.credential_sources_are_admissible() {
            return Err(McpError::new(
                McpErrorCode::ResourceForbidden,
                "Authentication failed",
            ));
        }
        let credential_present = request.has_any_credential_source();
        let Some(provider) = &self.auth_provider else {
            if credential_present {
                return Err(McpError::new(
                    McpErrorCode::ResourceForbidden,
                    "Authentication failed",
                ));
            }
            Self::enforce_request_context(ctx)?;
            if !ctx.commit_anonymous_auth() {
                return Err(Self::request_context_error(ctx).unwrap_or_else(|| {
                    McpError::internal_error("authentication admission was already committed")
                }));
            }
            return auth::principal_fingerprint(None);
        };
        let auth = {
            let staged_ctx = ctx.clone().with_isolated_auth();
            let result = catch_extension_unwind(|| provider.authenticate(&staged_ctx, request))
                .map_err(|_payload| extension_panic_error("auth_provider"))?;
            result.map_err(|provider_error| {
                debug!(
                    target: targets::SERVER,
                    "Authentication provider denied request; code={:?}",
                    provider_error.code
                );
                McpError::new(McpErrorCode::ResourceForbidden, "Authentication failed")
            })?
        };
        if credential_present && auth.subject.as_deref().is_none_or(str::is_empty) {
            error!(
                target: targets::SERVER,
                "Authentication provider admitted a credential without a stable subject"
            );
            return Err(McpError::new(
                McpErrorCode::ResourceForbidden,
                "Authentication failed",
            ));
        }
        let fingerprint = auth::principal_fingerprint(Some(&auth)).map_err(|provider_error| {
            debug!(
                target: targets::SERVER,
                "Authentication provider returned inadmissible facts; code={:?}",
                provider_error.code
            );
            McpError::new(McpErrorCode::ResourceForbidden, "Authentication failed")
        })?;
        Self::enforce_request_context(ctx)?;
        if !ctx.set_auth(auth) {
            if let Some(error) = Self::request_context_error(ctx) {
                return Err(error);
            }
            return Err(McpError::internal_error(
                "authentication context was already committed",
            ));
        }
        Ok(fingerprint)
    }

    /// Authenticates and parses an out-of-band cancellation before any queue,
    /// active-request, or bidirectional waiter state is mutated.
    fn authenticate_cancelled_control_notification(
        &self,
        cx: &Cx,
        principal_binding: &SessionPrincipalBinding,
        request: &mut JsonRpcRequest,
    ) -> McpResult<CancelledParams> {
        let budget = self.create_request_budget(cx);
        Self::enforce_request_budget(cx, budget)?;
        let (request_ctx, _request_lease_guard) =
            McpContext::new(cx.clone(), request_id_to_u64(request.id.as_ref()))
                .with_budget_ceiling(budget)
                .begin_request_scope()
                .ok_or_else(|| {
                    McpError::internal_error("request scope could not be established")
                })?;
        let auth_request = AuthRequest {
            method: &request.method,
            params: request.params.as_ref(),
            transport_authorization: None,
            request_id: request_id_to_u64(request.id.as_ref()),
        };
        let fingerprint = self.authenticate_request(&request_ctx, auth_request)?;
        auth::strip_recognized_access_credentials(&mut request.params);
        let params = parse_params::<CancelledParams>(request.params.take())?;
        if !principal_binding.verify_existing(fingerprint) {
            return Err(McpError::new(
                McpErrorCode::ResourceForbidden,
                "Authenticated principal does not own an admitted session",
            ));
        }
        Self::enforce_request_context(&request_ctx)?;
        Ok(params)
    }

    fn request_id_is_active(&self, session_id: u64, request_id: &RequestId) -> bool {
        self.active_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&ActiveRequestKey::new(session_id, request_id.clone()))
    }

    fn handle_cancelled_notification(&self, session_id: u64, params: CancelledParams) {
        let reason = params.reason.as_deref().unwrap_or("unspecified");
        let await_cleanup = params.await_cleanup.unwrap_or(false);
        info!(
            target: targets::SESSION,
            "Cancellation requested for request_key={:016x} (reason_present={}, reason_bytes={}, await_cleanup={})",
            request_id_log_key(&params.request_id),
            params.reason.is_some(),
            reason.len(),
            await_cleanup
        );
        let active = {
            let guard = self.active_requests.lock().unwrap_or_else(|poisoned| {
                error!(target: targets::SERVER, "active_requests lock poisoned, recovering");
                poisoned.into_inner()
            });
            guard
                .get(&ActiveRequestKey::new(
                    session_id,
                    params.request_id.clone(),
                ))
                .map(|entry| {
                    (
                        entry.cancellation.clone(),
                        entry.region_id,
                        entry.completion.clone(),
                    )
                })
        };
        if let Some((cancellation, region_id, completion)) = active {
            let accepted = cancellation.cancel();
            if await_cleanup && accepted {
                // The dispatch worker already serializes the session, so later
                // requests cannot overtake this request's cleanup. Never block
                // the sole receive pump here: it must remain free to route a
                // server-to-client response that the cancelling handler may be
                // awaiting before it can unwind.
                debug!(
                    target: targets::SESSION,
                    "await_cleanup accepted without blocking receive pump for request_key={:016x} (ambient_region={:?}, already_complete={})",
                    request_id_log_key(&params.request_id),
                    region_id,
                    completion.is_done()
                );
            } else if cancellation.is_finalizing() {
                debug!(
                    target: targets::SESSION,
                    "Cancellation arrived after response finalization began for request_key={:016x}",
                    request_id_log_key(&params.request_id)
                );
            } else if !accepted {
                debug!(
                    target: targets::SESSION,
                    "Cancellation was already pending for request_key={:016x} (await_cleanup={}, already_complete={})",
                    request_id_log_key(&params.request_id),
                    await_cleanup,
                    completion.is_done()
                );
            }
        } else {
            fastmcp_core::logging::warn!(
                target: targets::SESSION,
                "No active request found for cancellation request_key={:016x}",
                request_id_log_key(&params.request_id)
            );
        }
    }

    fn cancel_active_requests(&self, kind: CancelKind, await_cleanup: bool) {
        let active: Vec<(
            ActiveRequestKey,
            RegionId,
            Cx,
            McpRequestCancellation,
            Arc<RequestCompletion>,
        )> = {
            let guard = self.active_requests.lock().unwrap_or_else(|poisoned| {
                error!(target: targets::SERVER, "active_requests lock poisoned in cancel_active_requests, recovering");
                poisoned.into_inner()
            });
            guard
                .iter()
                .map(|(key, entry)| {
                    (
                        key.clone(),
                        entry.region_id,
                        entry.cx.clone(),
                        entry.cancellation.clone(),
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
        for (_, _, cx, cancellation, _) in &active {
            cancellation.cancel();
            cx.cancel_with(kind, None);
        }

        if await_cleanup {
            for (key, region_id, _cx, _cancellation, completion) in active {
                let completed = completion.wait_timeout(AWAIT_CLEANUP_TIMEOUT);
                if !completed {
                    fastmcp_core::logging::warn!(
                        target: targets::SESSION,
                        "Shutdown cancel timed out for session={} request_key={:016x} (ambient_region={:?})",
                        key.session_id,
                        request_id_log_key(&key.request_id),
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

        let configured = self.logging.level;
        let effective = if requested > configured {
            configured
        } else {
            requested
        };

        if effective == LevelFilter::Off {
            session.restore_log_level(None);
            fastmcp_core::logging::warn!(
                target: targets::SESSION,
                "Client requested log level {:?}; server logging is disabled",
                params.level
            );
            return;
        }

        let effective_level = match effective {
            LevelFilter::Debug => LogLevel::Debug,
            LevelFilter::Info => LogLevel::Info,
            LevelFilter::Warn => LogLevel::Warning,
            LevelFilter::Error => LogLevel::Error,
            // A client cannot request Trace through MCP; defensively clamp a
            // future/internal Trace value to the most verbose protocol level.
            LevelFilter::Trace => LogLevel::Debug,
            // Handled by the early return above.
            LevelFilter::Off => LogLevel::Error,
        };
        session.set_log_level(effective_level);

        if effective != requested {
            fastmcp_core::logging::warn!(
                target: targets::SESSION,
                "Client requested log level {:?}; provisional session level clamped to server level {:?}",
                params.level,
                effective
            );
        } else {
            info!(
                target: targets::SESSION,
                "Provisional session log level set to {:?}",
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
        let notification = JsonRpcRequest::notification("notifications/message", Some(payload));
        if catch_extension_unwind(|| sender(notification)).is_err() {
            // Notification delivery is an application-supplied extension
            // boundary. A broken callback must not unwind across dispatch and
            // discard the already-computed JSON-RPC response. Keep both this
            // diagnostic and the panic hook payload-free.
            let _ = extension_panic_error("log_notification_sender");
        }
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
        let method_key = safe_peer_log_key(method);
        let message = if result.is_ok() {
            format!("Handled method={method_key}")
        } else {
            format!("Error handling method={method_key}")
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
        let method_key = safe_peer_log_key(method);
        let message = if result.is_ok() {
            format!("Handled method={method_key}")
        } else {
            format!("Error handling method={method_key}")
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
    cancellation: McpRequestCancellation,
    region_id: RegionId,
    completion: Arc<RequestCompletion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ActiveRequestKey {
    session_id: u64,
    request_id: RequestId,
}

impl ActiveRequestKey {
    fn new(session_id: u64, request_id: RequestId) -> Self {
        Self {
            session_id,
            request_id,
        }
    }
}

impl ActiveRequest {
    fn new(cx: Cx, completion: Arc<RequestCompletion>) -> Self {
        let region_id = cx.region_id();
        Self {
            cx,
            cancellation: McpRequestCancellation::new(),
            region_id,
            completion,
        }
    }
}

struct ActiveRequestGuard<'a> {
    map: &'a Mutex<HashMap<ActiveRequestKey, ActiveRequest>>,
    key: ActiveRequestKey,
    cancellation: McpRequestCancellation,
    completion: Arc<RequestCompletion>,
}

impl<'a> ActiveRequestGuard<'a> {
    fn try_new(
        map: &'a Mutex<HashMap<ActiveRequestKey, ActiveRequest>>,
        session_id: u64,
        id: RequestId,
        cx: Cx,
    ) -> Result<Self, RequestId> {
        let completion = Arc::new(RequestCompletion::new());
        let entry = ActiveRequest::new(cx, completion.clone());
        let cancellation = entry.cancellation.clone();
        let mut guard = map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = ActiveRequestKey::new(session_id, id.clone());
        if guard.contains_key(&key) {
            fastmcp_core::logging::warn!(
                target: targets::SESSION,
                "Duplicate active request_key={:016x} rejected while an earlier request is still running",
                request_id_log_key(&id)
            );
            return Err(id);
        }
        guard.insert(key.clone(), entry);
        Ok(Self {
            map,
            key,
            cancellation,
            completion,
        })
    }

    fn cancellation(&self) -> McpRequestCancellation {
        self.cancellation.clone()
    }
}

impl Drop for ActiveRequestGuard<'_> {
    fn drop(&mut self) {
        {
            let mut guard = self
                .map
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match guard.get(&self.key) {
                Some(entry) if Arc::ptr_eq(&entry.completion, &self.completion) => {
                    guard.remove(&self.key);
                }
                Some(_) => {
                    fastmcp_core::logging::warn!(
                        target: targets::SESSION,
                        "Active request replaced before drop for session={} request_key={:016x}",
                        self.key.session_id,
                        request_id_log_key(&self.key.request_id)
                    );
                }
                None => {
                    fastmcp_core::logging::warn!(
                        target: targets::SESSION,
                        "Active request missing on drop for session={} request_key={:016x}",
                        self.key.session_id,
                        request_id_log_key(&self.key.request_id)
                    );
                }
            }
        }
        self.completion.mark_done();
    }
}

/// Keeps request cancellation ownership and reversible session mutations alive
/// until a direct caller accepts the response or the transport path has
/// acquired exclusive output ownership for one response attempt.
///
/// Exclusive ownership prevents another frame from overtaking the response,
/// but synchronous `Write`/`flush` remain fallible and cannot provide an atomic
/// wire-commit primitive. A failed attempt therefore still rolls back reversible
/// session mutations and is never counted as a sent response.
struct HandledRequest<'a> {
    response: JsonRpcResponse,
    cancellation: Option<McpRequestCancellation>,
    _active_guard: Option<ActiveRequestGuard<'a>>,
    session_mutation_rollback: Option<SessionMutationRollback>,
    deferred_stats: Option<DeferredRequestStats>,
    commit_liveness: Option<CommitLiveness>,
}

struct CommitLiveness {
    cx: Cx,
    budget: Budget,
}

#[derive(Clone, Copy)]
enum DeferredRequestOutcome {
    Success,
    Failure,
    Cancelled,
}

struct DeferredRequestStats {
    collector: ServerStats,
    method: String,
    started_at: Instant,
    outcome: DeferredRequestOutcome,
}

impl DeferredRequestStats {
    fn new(
        collector: Option<&ServerStats>,
        method: &str,
        started_at: Instant,
        outcome: DeferredRequestOutcome,
    ) -> Option<Self> {
        collector.map(|collector| Self {
            collector: collector.clone(),
            method: method.to_string(),
            started_at,
            outcome,
        })
    }

    fn record(self) {
        let latency = self.started_at.elapsed();
        match self.outcome {
            DeferredRequestOutcome::Success => {
                self.collector.record_request(&self.method, latency, true);
            }
            DeferredRequestOutcome::Failure => {
                self.collector.record_request(&self.method, latency, false);
            }
            DeferredRequestOutcome::Cancelled => {
                self.collector.record_cancelled(&self.method, latency);
            }
        }
    }
}

impl<'a> HandledRequest<'a> {
    fn untracked(response: JsonRpcResponse) -> Self {
        Self {
            response,
            cancellation: None,
            _active_guard: None,
            session_mutation_rollback: None,
            deferred_stats: None,
            commit_liveness: None,
        }
    }

    fn tracked(
        response: JsonRpcResponse,
        cancellation: McpRequestCancellation,
        active_guard: Option<ActiveRequestGuard<'a>>,
        session_mutation_rollback: Option<SessionMutationRollback>,
        commit_cx: Cx,
        commit_budget: Budget,
    ) -> Self {
        Self {
            response,
            cancellation: Some(cancellation),
            _active_guard: active_guard,
            session_mutation_rollback,
            deferred_stats: None,
            commit_liveness: Some(CommitLiveness {
                cx: commit_cx,
                budget: commit_budget,
            }),
        }
    }

    fn with_deferred_stats(mut self, deferred_stats: Option<DeferredRequestStats>) -> Self {
        self.deferred_stats = deferred_stats;
        self
    }

    fn commit_liveness_error(&self) -> Option<McpError> {
        self.commit_liveness
            .as_ref()
            .and_then(|liveness| Server::request_budget_error(&liveness.cx, liveness.budget))
    }

    fn replace_with_terminal_error(&mut self, session: &mut Session, error: McpError) {
        if let Some(rollback) = self.session_mutation_rollback.take() {
            rollback.apply(session);
        }
        if let Some(stats) = self.deferred_stats.as_mut() {
            stats.outcome = DeferredRequestOutcome::Cancelled;
        }
        self.response = JsonRpcResponse::error(
            self.response.id.clone(),
            JsonRpcError {
                code: error.code.into(),
                message: error.message,
                data: error.data,
            },
        );
    }

    fn resolve_commit_race(&mut self, session: &mut Session) {
        if let Some(error) = self.commit_liveness_error() {
            if let Some(cancellation) = &self.cancellation {
                let _ = cancellation.cancel();
            }
            self.replace_with_terminal_error(session, error);
            return;
        }

        let cancellation_won = self
            .cancellation
            .as_ref()
            .is_some_and(|cancellation| !cancellation.begin_finalization());
        if cancellation_won {
            self.replace_with_terminal_error(session, McpError::request_cancelled());
            return;
        }

        // The token CAS is the explicit-cancellation linearization point. A
        // second ambient/deadline check closes the interval between the first
        // liveness snapshot and that CAS. Cancellation after this snapshot
        // loses to response finalization.
        if let Some(error) = self.commit_liveness_error() {
            self.replace_with_terminal_error(session, error);
        }
    }

    fn finalize_for_return(mut self, session: &mut Session) -> JsonRpcResponse {
        self.resolve_commit_race(session);
        self.session_mutation_rollback.take();
        if let Some(stats) = self.deferred_stats.take() {
            stats.record();
        }
        self.response
    }

    fn send_with<F>(
        mut self,
        session: &mut Session,
        send: F,
    ) -> Result<JsonRpcResponse, TransportError>
    where
        F: FnOnce(&JsonRpcResponse) -> Result<(), TransportError>,
    {
        // Callers must acquire exclusive output ownership before entering this
        // method. Finalization then linearizes against cancellation immediately
        // before the single fallible write/flush attempt.
        self.resolve_commit_race(session);
        match send(&self.response) {
            Ok(()) => {
                self.session_mutation_rollback.take();
                if let Some(stats) = self.deferred_stats.take() {
                    stats.record();
                }
                Ok(self.response)
            }
            Err(error) => {
                if let Some(rollback) = self.session_mutation_rollback.take() {
                    rollback.apply(session);
                }
                Err(error)
            }
        }
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

fn request_id_log_key(id: &RequestId) -> u64 {
    request_id_to_u64(Some(id))
}

const PEER_LOG_KEY_INPUT_BYTES: usize = 4 * 1024;
const PEER_LOG_KEY_PREFIX_BYTES: usize = 8;

#[derive(Clone, Copy)]
struct SafePeerLogKey {
    byte_len: usize,
    hashed_bytes: usize,
    digest_prefix: [u8; PEER_LOG_KEY_PREFIX_BYTES],
}

impl std::fmt::Display for SafePeerLogKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bytes={},sha256_prefix=", self.byte_len)?;
        for byte in self.digest_prefix {
            write!(f, "{byte:02x}")?;
        }
        if self.hashed_bytes < self.byte_len {
            write!(f, ",hashed_prefix_bytes={}", self.hashed_bytes)?;
        }
        Ok(())
    }
}

fn safe_peer_log_key(value: &str) -> SafePeerLogKey {
    let bytes = value.as_bytes();
    let hashed_bytes = bytes.len().min(PEER_LOG_KEY_INPUT_BYTES);
    let mut digest_prefix = [0_u8; PEER_LOG_KEY_PREFIX_BYTES];
    if let Ok(digest) = sha256_bounded(&bytes[..hashed_bytes], PEER_LOG_KEY_INPUT_BYTES) {
        digest_prefix.copy_from_slice(&digest.as_bytes()[..PEER_LOG_KEY_PREFIX_BYTES]);
    }
    SafePeerLogKey {
        byte_len: bytes.len(),
        hashed_bytes,
        digest_prefix,
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
        let mut guard = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(transport_lock_error()),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "transport receive owns the unsplit I/O handle",
                )));
            }
        };
        guard.send(cx, message)
    }
}

fn transport_lock_error() -> TransportError {
    TransportError::Io(std::io::Error::other("transport lock poisoned"))
}

fn create_transport_notification_sender<T>(
    transport: SharedTransport<T>,
    cx: Cx,
) -> NotificationSender
where
    T: Transport + Send + 'static,
{
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Condvar, OnceLock};
    use std::thread;
    use std::time::Duration;

    #[derive(Debug, Default)]
    struct HttpOverlapMetrics {
        current: AtomicUsize,
        max: AtomicUsize,
    }

    static HTTP_OVERLAP_METRICS: OnceLock<HttpOverlapMetrics> = OnceLock::new();
    static HTTP_OVERLAP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static HTTP_OVERLAP_CONTROL: OnceLock<HttpOverlapControl> = OnceLock::new();

    #[derive(Debug, Default)]
    struct HttpOverlapControlState {
        enabled: bool,
        target_session: Option<usize>,
        lock_attempts: usize,
        lock_contentions: usize,
        entries: usize,
        permits: usize,
    }

    #[derive(Debug, Default)]
    struct HttpOverlapControl {
        state: Mutex<HttpOverlapControlState>,
        changed: Condvar,
    }

    impl HttpOverlapControl {
        fn begin(&self, target_session: usize) -> HttpOverlapControlGuard<'_> {
            let mut state = self.state.lock().expect("HTTP overlap control poisoned");
            state.enabled = true;
            state.target_session = Some(target_session);
            state.lock_attempts = 0;
            state.lock_contentions = 0;
            state.entries = 0;
            state.permits = 0;
            HttpOverlapControlGuard { control: self }
        }

        fn record_lock_attempt(&self, session: usize) -> bool {
            let mut state = self.state.lock().expect("HTTP overlap control poisoned");
            if !state.enabled || state.target_session != Some(session) {
                return false;
            }
            state.lock_attempts += 1;
            self.changed.notify_all();
            true
        }

        fn record_lock_contention(&self, session: usize) {
            let mut state = self.state.lock().expect("HTTP overlap control poisoned");
            if state.enabled && state.target_session == Some(session) {
                state.lock_contentions += 1;
                self.changed.notify_all();
            }
        }

        fn enter_and_wait(&self) {
            let mut state = self.state.lock().expect("HTTP overlap control poisoned");
            if !state.enabled {
                return;
            }
            state.entries += 1;
            self.changed.notify_all();
            while state.enabled && state.permits == 0 {
                state = self
                    .changed
                    .wait(state)
                    .expect("HTTP overlap control poisoned while waiting");
            }
            state.permits = state.permits.saturating_sub(1);
        }

        fn wait_for_entries(&self, target: usize, timeout: Duration) -> bool {
            let state = self.state.lock().expect("HTTP overlap control poisoned");
            let (state, _) = self
                .changed
                .wait_timeout_while(state, timeout, |state| state.entries < target)
                .expect("HTTP overlap control poisoned while observing entries");
            state.entries >= target
        }

        fn wait_for_lock_attempts(&self, target: usize, timeout: Duration) -> bool {
            let state = self.state.lock().expect("HTTP overlap control poisoned");
            let (state, _) = self
                .changed
                .wait_timeout_while(state, timeout, |state| state.lock_attempts < target)
                .expect("HTTP overlap control poisoned while observing lock attempts");
            state.lock_attempts >= target
        }

        fn wait_for_lock_contentions(&self, target: usize, timeout: Duration) -> bool {
            let state = self.state.lock().expect("HTTP overlap control poisoned");
            let (state, _) = self
                .changed
                .wait_timeout_while(state, timeout, |state| state.lock_contentions < target)
                .expect("HTTP overlap control poisoned while observing lock contention");
            state.lock_contentions >= target
        }

        fn release_one(&self) {
            let mut state = self.state.lock().expect("HTTP overlap control poisoned");
            state.permits = state.permits.saturating_add(1);
            self.changed.notify_all();
        }

        fn disable(&self) {
            let mut state = self.state.lock().expect("HTTP overlap control poisoned");
            state.enabled = false;
            state.target_session = None;
            state.permits = 0;
            self.changed.notify_all();
        }
    }

    struct HttpOverlapControlGuard<'a> {
        control: &'a HttpOverlapControl,
    }

    impl Drop for HttpOverlapControlGuard<'_> {
        fn drop(&mut self) {
            self.control.disable();
        }
    }

    type HttpOverlapWorker = thread::JoinHandle<Result<(), String>>;
    type HttpOverlapWorkerResult = thread::Result<Result<(), String>>;

    struct HttpOverlapWorkers<'a> {
        control: &'a HttpOverlapControl,
        handles: Vec<HttpOverlapWorker>,
    }

    impl<'a> HttpOverlapWorkers<'a> {
        fn new(control: &'a HttpOverlapControl) -> Self {
            Self {
                control,
                handles: Vec::new(),
            }
        }

        fn push(&mut self, handle: HttpOverlapWorker) {
            self.handles.push(handle);
        }

        fn join_all(mut self) -> Vec<HttpOverlapWorkerResult> {
            self.control.disable();
            self.handles
                .drain(..)
                .map(thread::JoinHandle::join)
                .collect()
        }
    }

    impl Drop for HttpOverlapWorkers<'_> {
        fn drop(&mut self) {
            self.control.disable();
            for handle in self.handles.drain(..) {
                let _ = handle.join();
            }
        }
    }

    fn http_overlap_metrics() -> &'static HttpOverlapMetrics {
        HTTP_OVERLAP_METRICS.get_or_init(HttpOverlapMetrics::default)
    }

    fn http_overlap_lock() -> &'static Mutex<()> {
        HTTP_OVERLAP_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn http_overlap_control() -> &'static HttpOverlapControl {
        HTTP_OVERLAP_CONTROL.get_or_init(HttpOverlapControl::default)
    }

    pub(super) fn record_http_session_lock_attempt(session: usize) -> bool {
        http_overlap_control().record_lock_attempt(session)
    }

    pub(super) fn record_http_session_lock_contention(session: usize) {
        http_overlap_control().record_lock_contention(session);
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

    fn fixed_test_subject_for_credential(token: &str) -> McpResult<&'static str> {
        match token {
            "alpha" => Ok("principal-alpha"),
            "beta" => Ok("principal-beta"),
            _ => Err(McpError::invalid_request("unrecognized auth token")),
        }
    }

    fn initialized_test_session(server: &Server) -> Session {
        let mut session = Session::new(server.info.clone(), server.capabilities.clone());
        session.initialize(
            fastmcp_protocol::ClientInfo {
                name: "panic-containment-test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            fastmcp_protocol::ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );
        session
    }

    fn initialize_test_request(
        id: i64,
        client_name: &str,
        capabilities: fastmcp_protocol::ClientCapabilities,
    ) -> JsonRpcRequest {
        JsonRpcRequest::new(
            "initialize",
            Some(
                serde_json::to_value(InitializeParams {
                    protocol_version: "2024-11-05".to_string(),
                    capabilities,
                    client_info: fastmcp_protocol::ClientInfo {
                        name: client_name.to_string(),
                        version: "1.0.0".to_string(),
                    },
                })
                .expect("serialize initialize request"),
            ),
            id,
        )
    }

    #[test]
    fn resource_exhausted_masking_preserves_only_the_fixed_server_contract() {
        let fixed = mask_peer_error(resource_subscription_capacity_error(), true);
        assert_eq!(
            fixed.code,
            McpErrorCode::Custom(RESOURCE_EXHAUSTED_ERROR_CODE)
        );
        assert_eq!(fixed.message, RESOURCE_SUBSCRIPTION_CAPACITY_MESSAGE);
        assert!(fixed.data.is_none());

        let forged = mask_peer_error(
            McpError::with_data(
                McpErrorCode::Custom(RESOURCE_EXHAUSTED_ERROR_CODE),
                "credential-canary-must-be-masked",
                serde_json::json!({"token": "secret-canary"}),
            ),
            true,
        );
        assert_eq!(forged.message, "Internal server error");
        assert!(forged.data.is_none());
    }

    fn dispatch_test_request(
        server: &Server,
        session: &mut Session,
        method: &str,
    ) -> JsonRpcResponse {
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        server
            .dispatch_request(
                &Cx::for_testing(),
                session,
                JsonRpcRequest::new(method, Some(serde_json::json!({})), 1_i64),
                &notification_sender,
                &request_sender,
            )
            .expect("test request should produce a JSON-RPC response")
    }

    #[test]
    fn http_server_uses_its_configured_request_handler_policy() {
        let handler_config = HttpHandlerConfig {
            base_path: "/private/mcp".to_string(),
            allow_cors: false,
            cors_origins: vec!["https://trusted.example".to_string()],
            max_body_size: 321,
        };
        let server = Server::new("http-policy-test", "1.0.0")
            .http_config(
                HttpServerConfig::new()
                    .mcp_path("/private/mcp")
                    .handler_config(handler_config),
            )
            .build();

        let handler = server.configured_http_request_handler();
        let actual = handler.config();
        assert_eq!(actual.base_path, "/private/mcp");
        assert!(!actual.allow_cors);
        assert_eq!(
            actual.cors_origins,
            vec!["https://trusted.example".to_string()]
        );
        assert_eq!(actual.max_body_size, 321);

        let options = HttpRequest::new(HttpMethod::Options, "/private/mcp")
            .with_header("origin", "https://trusted.example");
        assert_eq!(
            handler.handle_options(&options).status,
            HttpStatus::METHOD_NOT_ALLOWED
        );

        let oversized = HttpRequest::new(HttpMethod::Post, "/private/mcp")
            .with_header("content-type", "application/json")
            .with_body(vec![b'x'; 322]);
        assert!(matches!(
            handler.parse_request(&oversized),
            Err(fastmcp_transport::http::HttpError::BodyTooLarge {
                size: 322,
                max: 321
            })
        ));
    }

    #[test]
    fn http_server_mcp_path_updates_the_authoritative_handler_path() {
        let config = HttpServerConfig::new().mcp_path("/single-source");
        assert_eq!(config.handler_config.base_path, "/single-source");

        let server = Server::new("http-path-test", "1.0.0")
            .http_config(config)
            .build();
        let handler = server.configured_http_request_handler();
        assert_eq!(handler.config().base_path, "/single-source");
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
        http_overlap_control().enter_and_wait();
        metrics.current.fetch_sub(1, Ordering::SeqCst);
        "overlap-ok".to_string()
    }

    #[tool(
        name = "http_auth_echo_tool_runtime",
        description = "Returns the request-scoped auth subject while recording overlap",
        annotations(read_only)
    )]
    fn http_auth_echo_tool_runtime(ctx: &McpContext) -> String {
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
            if ctx.set_auth(AuthContext::with_subject(self.subject)) {
                return Err(McpError::internal_error(
                    "middleware replaced a committed authenticated principal",
                ));
            }
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

    #[derive(Debug, Clone)]
    struct ResponseCancellationRewriter;

    impl Middleware for ResponseCancellationRewriter {
        fn on_response(
            &self,
            _ctx: &McpContext,
            _request: &JsonRpcRequest,
            _response: serde_json::Value,
        ) -> McpResult<serde_json::Value> {
            Err(McpError::request_cancelled())
        }

        fn on_error(
            &self,
            _ctx: &McpContext,
            _request: &JsonRpcRequest,
            _error: McpError,
        ) -> McpError {
            McpError::internal_error("hostile cancellation rewrite")
        }
    }

    #[derive(Debug, Clone)]
    struct RejectResponseMiddleware;

    impl Middleware for RejectResponseMiddleware {
        fn on_response(
            &self,
            _ctx: &McpContext,
            _request: &JsonRpcRequest,
            _response: serde_json::Value,
        ) -> McpResult<serde_json::Value> {
            Err(McpError::internal_error(
                "response middleware rejected provisional session mutation",
            ))
        }
    }

    const EXTENSION_PANIC_CANARY: &str =
        "EXTENSION_PANIC_CANARY Bearer peer-secret\n\u{001b}[31mpayload\u{001b}[0m";

    #[derive(Debug)]
    struct PanickingAuthProvider;

    impl AuthProvider for PanickingAuthProvider {
        fn authenticate(
            &self,
            _ctx: &McpContext,
            _request: AuthRequest<'_>,
        ) -> McpResult<AuthContext> {
            panic!("{EXTENSION_PANIC_CANARY}")
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum PanickingMiddlewareHook {
        Request,
        Response,
        Error,
    }

    type MiddlewareEvent = (&'static str, &'static str);

    #[derive(Debug, Clone)]
    struct RecordingPanicMiddleware {
        name: &'static str,
        panic_at: Option<PanickingMiddlewareHook>,
        events: Arc<Mutex<Vec<MiddlewareEvent>>>,
    }

    impl RecordingPanicMiddleware {
        fn new(
            name: &'static str,
            panic_at: Option<PanickingMiddlewareHook>,
            events: &Arc<Mutex<Vec<MiddlewareEvent>>>,
        ) -> Self {
            Self {
                name,
                panic_at,
                events: Arc::clone(events),
            }
        }

        fn record(&self, hook: &'static str) {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((self.name, hook));
        }

        fn should_panic(&self, hook: PanickingMiddlewareHook) -> bool {
            self.panic_at == Some(hook)
        }
    }

    impl Middleware for RecordingPanicMiddleware {
        fn on_request(
            &self,
            _ctx: &McpContext,
            _request: &JsonRpcRequest,
        ) -> McpResult<MiddlewareDecision> {
            self.record("request");
            if self.should_panic(PanickingMiddlewareHook::Request) {
                panic!("{EXTENSION_PANIC_CANARY}");
            }
            Ok(MiddlewareDecision::Continue)
        }

        fn on_response(
            &self,
            _ctx: &McpContext,
            _request: &JsonRpcRequest,
            response: serde_json::Value,
        ) -> McpResult<serde_json::Value> {
            self.record("response");
            if self.should_panic(PanickingMiddlewareHook::Response) {
                panic!("{EXTENSION_PANIC_CANARY}");
            }
            Ok(response)
        }

        fn on_error(
            &self,
            _ctx: &McpContext,
            _request: &JsonRpcRequest,
            error: McpError,
        ) -> McpError {
            self.record("error");
            if self.should_panic(PanickingMiddlewareHook::Error) {
                panic!("{EXTENSION_PANIC_CANARY}");
            }
            error
        }
    }

    fn recorded_middleware_events(
        events: &Arc<Mutex<Vec<MiddlewareEvent>>>,
    ) -> Vec<MiddlewareEvent> {
        events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn assert_peer_extension_error_is_sanitized(response: &JsonRpcResponse) {
        let error = response
            .error
            .as_ref()
            .expect("extension panic must produce a JSON-RPC error");
        assert_eq!(error.message, "Internal server error");
        assert_eq!(error.data, None);

        let wire = serde_json::to_string(response).expect("JSON-RPC response should serialize");
        for forbidden in [
            "EXTENSION_PANIC_CANARY",
            "Bearer",
            "peer-secret",
            "payload",
            "\\u001b",
        ] {
            assert!(
                !wire.contains(forbidden),
                "peer response exposed panic payload fragment {forbidden:?}: {wire}"
            );
        }
    }

    // ── parse_params ────────────────────────────────────────────────

    #[test]
    fn configured_task_manager_does_not_advertise_or_enable_task_rpc_methods() {
        let server = Server::new("quarantined-task-rpc-test", "1.0.0")
            .with_task_manager(TaskManager::new().into_shared())
            .build();
        assert!(server.task_manager().is_some());
        assert!(server.capabilities().tasks.is_none());

        let mut session = initialized_test_session(&server);
        for method in ["tasks/list", "tasks/get", "tasks/cancel", "tasks/submit"] {
            let response = dispatch_test_request(&server, &mut session, method);
            let error = response
                .error
                .as_ref()
                .unwrap_or_else(|| panic!("{method} must fail closed"));
            assert_eq!(error.code, i32::from(McpErrorCode::MethodNotFound));
            assert!(response.result.is_none());
        }
    }

    #[test]
    fn notification_only_methods_reject_ids_and_bare_initialized_is_unknown() {
        let server = Server::new("notification-envelope-test", "1.0.0").build();
        let mut session = initialized_test_session(&server);

        for method in ["notifications/initialized", "notifications/cancelled"] {
            let response = dispatch_test_request(&server, &mut session, method);
            let error = response
                .error
                .unwrap_or_else(|| panic!("{method} with an id must be rejected"));
            assert_eq!(error.code, i32::from(McpErrorCode::InvalidRequest));
            assert!(response.result.is_none());
        }

        let response = dispatch_test_request(&server, &mut session, "initialized");
        let error = response
            .error
            .expect("the legacy bare initialized spelling must not be routed");
        assert_eq!(error.code, i32::from(McpErrorCode::MethodNotFound));
    }

    #[test]
    fn log_level_is_session_local_and_does_not_mutate_process_filter() {
        let server = Server::new("session-log-level-test", "1.0.0")
            .log_level(Level::Debug)
            .build();
        let mut first = initialized_test_session(&server);
        let mut second = initialized_test_session(&server);
        let process_level = log::max_level();
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();

        for (session, id, level) in [
            (&mut first, 1_i64, LogLevel::Debug),
            (&mut second, 2_i64, LogLevel::Error),
        ] {
            let request = JsonRpcRequest::new(
                "logging/setLevel",
                Some(
                    serde_json::to_value(SetLogLevelParams { level })
                        .expect("serialize log-level request"),
                ),
                id,
            );
            let response = server
                .dispatch_request(
                    &Cx::for_testing(),
                    session,
                    request,
                    &notification_sender,
                    &request_sender,
                )
                .expect("setLevel request must have a response");
            assert!(
                response.error.is_none(),
                "unexpected response: {response:?}"
            );
        }

        assert_eq!(first.log_level(), Some(LogLevel::Debug));
        assert_eq!(second.log_level(), Some(LogLevel::Error));
        assert_eq!(log::max_level(), process_level);
    }

    #[test]
    fn disabled_server_logging_does_not_enable_session_notifications() {
        let server = Server::new("disabled-session-log-level-test", "1.0.0")
            .log_level_filter(LevelFilter::Off)
            .build();
        let mut session = initialized_test_session(&server);
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let request = JsonRpcRequest::new(
            "logging/setLevel",
            Some(
                serde_json::to_value(SetLogLevelParams {
                    level: LogLevel::Debug,
                })
                .expect("serialize log-level request"),
            ),
            3_i64,
        );

        let response = server
            .dispatch_request(
                &Cx::for_testing(),
                &mut session,
                request,
                &notification_sender,
                &request_sender,
            )
            .expect("setLevel request must have a response");

        assert!(
            response.error.is_none(),
            "unexpected response: {response:?}"
        );
        assert_eq!(session.log_level(), None);
    }

    #[test]
    fn panicking_log_sender_cannot_discard_response_or_leak_active_request() {
        let server = Server::new("log-sender-panic-test", "1.0.0")
            .log_level(Level::Debug)
            .build();
        let mut session = initialized_test_session(&server);
        session.set_log_level(LogLevel::Debug);
        let sender: NotificationSender =
            Arc::new(|_| panic!("LOG-SENDER-PANIC-CANARY Bearer secret\r\nforged-line"));
        let request_sender = test_request_sender();

        let response = server
            .dispatch_request(
                &Cx::for_testing(),
                &mut session,
                JsonRpcRequest::new("ping", Some(serde_json::json!({})), 77_i64),
                &sender,
                &request_sender,
            )
            .expect("ping must retain its response despite sender panic");

        assert!(
            response.error.is_none(),
            "unexpected response: {response:?}"
        );
        assert!(
            server
                .active_requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );

        let failing_server = Server::new("auth-failure-log-sender-panic-test", "1.0.0")
            .log_level(Level::Debug)
            .auth_provider(AlwaysFailAuthProvider)
            .build();
        let mut failing_session = initialized_test_session(&failing_server);
        failing_session.set_log_level(LogLevel::Debug);
        let response = failing_server
            .dispatch_request(
                &Cx::for_testing(),
                &mut failing_session,
                JsonRpcRequest::new("tools/list", Some(serde_json::json!({})), 78_i64),
                &sender,
                &request_sender,
            )
            .expect("auth failure must retain its response despite sender panic");
        assert!(response.error.is_some());
        assert!(
            failing_server
                .active_requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
    }

    #[test]
    fn credential_is_visible_only_to_auth_then_stripped_before_middleware() {
        #[derive(Debug, Clone)]
        struct CaptureRawAuth {
            seen: Arc<Mutex<Option<serde_json::Value>>>,
        }

        impl AuthProvider for CaptureRawAuth {
            fn authenticate(
                &self,
                _ctx: &McpContext,
                request: AuthRequest<'_>,
            ) -> McpResult<AuthContext> {
                assert!(request.access_token().is_some());
                *self
                    .seen
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = request.params.cloned();
                Ok(AuthContext::with_subject("fixed-test-principal"))
            }
        }

        #[derive(Debug, Clone)]
        struct CaptureSanitizedParams {
            seen: Arc<Mutex<Option<serde_json::Value>>>,
        }

        impl Middleware for CaptureSanitizedParams {
            fn on_request(
                &self,
                _ctx: &McpContext,
                request: &JsonRpcRequest,
            ) -> McpResult<MiddlewareDecision> {
                *self
                    .seen
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = request.params.clone();
                Ok(MiddlewareDecision::Continue)
            }
        }

        let raw = Arc::new(Mutex::new(None));
        let sanitized = Arc::new(Mutex::new(None));
        let server = Server::new("credential-custody-test", "1.0.0")
            .auth_provider(CaptureRawAuth {
                seen: Arc::clone(&raw),
            })
            .middleware(CaptureSanitizedParams {
                seen: Arc::clone(&sanitized),
            })
            .build();
        let mut session = initialized_test_session(&server);
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let request = JsonRpcRequest::new(
            "tools/list",
            Some(serde_json::json!({
                "authorization": "Bearer top-level-secret",
                "_meta": {
                    "accessToken": "Bearer metadata-secret",
                    "trace": "preserved-metadata"
                },
                "headers": {
                    "Authorization": "Bearer header-secret",
                    "x-preserved": "yes"
                },
                "arguments": {
                    "token": "domain-value",
                    "nested": {"authorization": "domain-authorization"}
                }
            })),
            91_i64,
        );

        let response = server
            .dispatch_request(
                &Cx::for_testing(),
                &mut session,
                request,
                &notification_sender,
                &request_sender,
            )
            .expect("authenticated tools/list must respond");
        assert!(
            response.error.is_none(),
            "unexpected response: {response:?}"
        );

        let raw = raw
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .expect("auth provider must receive raw params");
        assert_eq!(raw["authorization"], "Bearer top-level-secret");

        let sanitized = sanitized
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .expect("middleware must receive sanitized params");
        assert!(sanitized.get("authorization").is_none());
        assert!(sanitized["_meta"].get("accessToken").is_none());
        assert_eq!(sanitized["_meta"]["trace"], "preserved-metadata");
        assert!(sanitized["headers"].get("Authorization").is_none());
        assert_eq!(sanitized["headers"]["x-preserved"], "yes");
        assert_eq!(sanitized["arguments"]["token"], "domain-value");
        assert_eq!(
            sanitized["arguments"]["nested"]["authorization"],
            "domain-authorization"
        );
    }

    #[test]
    fn auth_provider_covers_initialize_ping_and_control_notifications() {
        #[derive(Debug, Clone)]
        struct RecordingAuthProvider {
            methods: Arc<Mutex<Vec<String>>>,
        }

        impl AuthProvider for RecordingAuthProvider {
            fn authenticate(
                &self,
                _ctx: &McpContext,
                request: AuthRequest<'_>,
            ) -> McpResult<AuthContext> {
                self.methods
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(request.method.to_string());
                Ok(AuthContext::with_subject("connection-owner"))
            }
        }

        let methods = Arc::new(Mutex::new(Vec::new()));
        let server = Server::new("auth-all-methods-test", "1.0.0")
            .auth_provider(RecordingAuthProvider {
                methods: Arc::clone(&methods),
            })
            .build();
        let mut session = Session::new(server.info.clone(), server.capabilities.clone());
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();

        let initialize = server
            .dispatch_request(
                &Cx::for_testing(),
                &mut session,
                initialize_test_request(
                    101,
                    "authenticated-client",
                    fastmcp_protocol::ClientCapabilities::default(),
                ),
                &notification_sender,
                &request_sender,
            )
            .expect("initialize request must respond");
        assert!(initialize.error.is_none());

        assert!(
            server
                .dispatch_request(
                    &Cx::for_testing(),
                    &mut session,
                    JsonRpcRequest::notification("notifications/initialized", None),
                    &notification_sender,
                    &request_sender,
                )
                .is_none()
        );

        let ping = server
            .dispatch_request(
                &Cx::for_testing(),
                &mut session,
                JsonRpcRequest::new("ping", Some(serde_json::json!({})), 102_i64),
                &notification_sender,
                &request_sender,
            )
            .expect("ping request must respond");
        assert!(ping.error.is_none());

        assert!(
            server
                .dispatch_request(
                    &Cx::for_testing(),
                    &mut session,
                    JsonRpcRequest::notification(
                        "notifications/cancelled",
                        Some(
                            serde_json::to_value(CancelledParams {
                                request_id: RequestId::Number(999),
                                reason: None,
                                await_cleanup: None,
                            })
                            .expect("serialize cancellation"),
                        ),
                    ),
                    &notification_sender,
                    &request_sender,
                )
                .is_none()
        );

        assert_eq!(
            *methods
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec![
                "initialize",
                "notifications/initialized",
                "ping",
                "notifications/cancelled",
            ]
        );
    }

    #[test]
    fn malformed_or_ambiguous_credentials_never_reach_the_provider() {
        #[derive(Debug, Clone)]
        struct CountingAuthProvider {
            calls: Arc<AtomicUsize>,
        }

        impl AuthProvider for CountingAuthProvider {
            fn authenticate(
                &self,
                _ctx: &McpContext,
                _request: AuthRequest<'_>,
            ) -> McpResult<AuthContext> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(AuthContext::with_subject("must-not-run"))
            }
        }

        #[derive(Debug, Clone)]
        struct CapturingAdmissionError {
            seen: Arc<Mutex<Vec<(Option<serde_json::Value>, McpError)>>>,
        }

        impl Middleware for CapturingAdmissionError {
            fn on_error(
                &self,
                _ctx: &McpContext,
                request: &JsonRpcRequest,
                error: McpError,
            ) -> McpError {
                self.seen
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((request.params.clone(), error.clone()));
                error
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let server = Server::new("credential-admission-test", "1.0.0")
            .auth_provider(CountingAuthProvider {
                calls: Arc::clone(&calls),
            })
            .middleware(CapturingAdmissionError {
                seen: Arc::clone(&seen),
            })
            .build();
        let mut session = initialized_test_session(&server);
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let cases = [
            (
                Some("Bearer native"),
                serde_json::json!({
                    "authorization": "Bearer in-band",
                    "cursor": "preserved"
                }),
            ),
            (
                None,
                serde_json::json!({
                    "authorization": "Bearer first",
                    "_meta": {"accessToken": "Bearer second"},
                    "cursor": "preserved"
                }),
            ),
            (Some("Bearer"), serde_json::json!({"cursor": "preserved"})),
        ];

        for (index, (native, params)) in cases.into_iter().enumerate() {
            let response = server
                .handle_request_with_transport_authorization(
                    &Cx::for_testing(),
                    &mut session,
                    JsonRpcRequest::new(
                        "tools/list",
                        Some(params),
                        i64::try_from(index + 1).expect("bounded test request ID"),
                    ),
                    native,
                    &notification_sender,
                    &request_sender,
                )
                .expect("request must receive an authentication error");
            let error = response.error.expect("authentication must fail");
            assert_eq!(error.code, i32::from(McpErrorCode::ResourceForbidden));
            assert_eq!(error.message, "Authentication failed");
            assert!(error.data.is_none());
        }

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let seen = seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(seen.len(), 3);
        for (params, error) in seen.iter() {
            assert_eq!(error.message, "Authentication failed");
            assert!(error.data.is_none());
            let params = params.as_ref().expect("non-credential params remain");
            assert_eq!(params["cursor"], "preserved");
            let wire = serde_json::to_string(params).expect("serialize sanitized params");
            assert!(!wire.contains("Bearer"));
            assert!(!wire.contains("first"));
            assert!(!wire.contains("second"));
            assert!(!wire.contains("native"));
        }
    }

    #[test]
    fn cancellation_control_cannot_claim_an_unbound_session_principal() {
        let server = Server::new("cancel-control-owner-test", "1.0.0").build();
        let session = Session::new(server.info.clone(), server.capabilities.clone());
        let binding = session.principal_binding();
        let mut cancellation = JsonRpcRequest::notification(
            "notifications/cancelled",
            Some(
                serde_json::to_value(CancelledParams {
                    request_id: RequestId::Number(17),
                    reason: None,
                    await_cleanup: None,
                })
                .expect("serialize cancellation"),
            ),
        );

        let error = server
            .authenticate_cancelled_control_notification(
                &Cx::for_testing(),
                &binding,
                &mut cancellation,
            )
            .expect_err("a control frame must not establish session ownership");
        assert_eq!(error.code, McpErrorCode::ResourceForbidden);

        let admitted_anonymous = auth::principal_fingerprint(None).expect("bounded fingerprint");
        assert!(binding.bind_or_verify(admitted_anonymous));
        let mut cancellation = JsonRpcRequest::notification(
            "notifications/cancelled",
            Some(
                serde_json::to_value(CancelledParams {
                    request_id: RequestId::Number(17),
                    reason: None,
                    await_cleanup: None,
                })
                .expect("serialize cancellation"),
            ),
        );
        assert!(
            server
                .authenticate_cancelled_control_notification(
                    &Cx::for_testing(),
                    &binding,
                    &mut cancellation,
                )
                .is_ok()
        );
    }

    #[test]
    fn failed_initialize_auth_does_not_initialize_session() {
        let server = Server::new("initialize-auth-failure-test", "1.0.0")
            .auth_provider(AlwaysFailAuthProvider)
            .build();
        let mut session = Session::new(server.info.clone(), server.capabilities.clone());
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();

        let response = server
            .dispatch_request(
                &Cx::for_testing(),
                &mut session,
                initialize_test_request(
                    103,
                    "unauthenticated-client",
                    fastmcp_protocol::ClientCapabilities::default(),
                ),
                &notification_sender,
                &request_sender,
            )
            .expect("initialize auth failure must respond");

        assert!(response.error.is_some());
        assert!(!session.is_initialized());
    }

    // Extension panic-containment regressions.
    #[test]
    fn auth_provider_panic_is_counted_sanitized_and_runs_global_reverse_cleanup() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = Server::new("auth-panic-containment-test", "1.0.0")
            .auth_provider(PanickingAuthProvider)
            .middleware(RecordingPanicMiddleware::new("first", None, &events))
            .middleware(RecordingPanicMiddleware::new("second", None, &events))
            .middleware(RecordingPanicMiddleware::new("third", None, &events))
            .build();
        let mut session = initialized_test_session(&server);
        let panic_count_before = REDACTED_EXTENSION_PANIC_COUNT.load(Ordering::Relaxed);

        let response = dispatch_test_request(&server, &mut session, "tools/list");

        let panic_count_after = REDACTED_EXTENSION_PANIC_COUNT.load(Ordering::Relaxed);
        assert!(
            panic_count_after > panic_count_before,
            "the installed redaction hook must count the contained auth-provider panic"
        );
        assert_peer_extension_error_is_sanitized(&response);
        assert_eq!(
            recorded_middleware_events(&events),
            vec![("third", "error"), ("second", "error"), ("first", "error"),]
        );
    }

    #[test]
    fn middleware_on_request_panic_runs_entered_stack_reverse_cleanup() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = Server::new("middleware-request-panic-test", "1.0.0")
            .middleware(RecordingPanicMiddleware::new("first", None, &events))
            .middleware(RecordingPanicMiddleware::new(
                "second",
                Some(PanickingMiddlewareHook::Request),
                &events,
            ))
            .middleware(RecordingPanicMiddleware::new("third", None, &events))
            .build();
        let mut session = initialized_test_session(&server);

        let response = dispatch_test_request(&server, &mut session, "ping");

        assert_peer_extension_error_is_sanitized(&response);
        assert_eq!(
            recorded_middleware_events(&events),
            vec![
                ("first", "request"),
                ("second", "request"),
                ("second", "error"),
                ("first", "error"),
            ]
        );
    }

    #[test]
    fn middleware_on_response_panic_runs_full_entered_stack_reverse_cleanup() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = Server::new("middleware-response-panic-test", "1.0.0")
            .middleware(RecordingPanicMiddleware::new("first", None, &events))
            .middleware(RecordingPanicMiddleware::new(
                "second",
                Some(PanickingMiddlewareHook::Response),
                &events,
            ))
            .middleware(RecordingPanicMiddleware::new("third", None, &events))
            .build();
        let mut session = initialized_test_session(&server);

        let response = dispatch_test_request(&server, &mut session, "ping");

        assert_peer_extension_error_is_sanitized(&response);
        assert_eq!(
            recorded_middleware_events(&events),
            vec![
                ("first", "request"),
                ("second", "request"),
                ("third", "request"),
                ("third", "response"),
                ("second", "response"),
                ("third", "error"),
                ("second", "error"),
                ("first", "error"),
            ]
        );
    }

    #[test]
    fn middleware_response_cancellation_cannot_be_rewritten_by_error_hook() {
        let server = Server::new("middleware-response-cancellation-test", "1.0.0")
            .middleware(ResponseCancellationRewriter)
            .build();
        let mut session = initialized_test_session(&server);

        let response = dispatch_test_request(&server, &mut session, "ping");

        let error = response
            .error
            .expect("response-stage cancellation must remain an error");
        assert_eq!(error.code, i32::from(McpErrorCode::RequestCancelled));
        assert_eq!(error.message, "Request cancelled");
        assert!(!error.message.contains("hostile"));
    }

    #[test]
    fn middleware_on_error_panic_does_not_skip_remaining_reverse_cleanup() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = Server::new("middleware-error-panic-test", "1.0.0")
            .middleware(RecordingPanicMiddleware::new("first", None, &events))
            .middleware(RecordingPanicMiddleware::new(
                "second",
                Some(PanickingMiddlewareHook::Error),
                &events,
            ))
            .middleware(RecordingPanicMiddleware::new("third", None, &events))
            .build();
        let mut session = initialized_test_session(&server);

        let response = dispatch_test_request(&server, &mut session, "unknown/test-method");

        assert_peer_extension_error_is_sanitized(&response);
        assert_eq!(
            recorded_middleware_events(&events),
            vec![
                ("first", "request"),
                ("second", "request"),
                ("third", "request"),
                ("third", "error"),
                ("second", "error"),
                ("first", "error"),
            ]
        );
    }

    // Parameter parsing regressions.
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

    #[test]
    fn dispatch_queue_reservation_spans_dispatch_until_response_completion() {
        let queue = DispatchQueueState::default();
        let request_id = RequestId::String("linearized-request".to_string());

        assert!(queue.admit(&request_id));
        assert!(!queue.begin_dispatch(&request_id));
        assert!(
            !queue.admit(&request_id),
            "an active request must retain its queue reservation"
        );
        assert!(
            !queue.cancel_if_queued(&request_id),
            "active cancellation must route through ActiveRequestGuard"
        );

        queue.discard(&request_id);
        assert!(
            queue.admit(&request_id),
            "the id may be reused only after response completion releases it"
        );
    }

    #[test]
    fn dispatch_queue_stop_rejects_admission_and_cancels_queued_start() {
        let queue = DispatchQueueState::default();
        let queued = RequestId::Number(7);
        assert!(queue.admit(&queued));

        queue.stop();

        assert!(queue.is_stopping());
        assert!(queue.begin_dispatch(&queued));
        assert!(!queue.admit(&RequestId::Number(8)));
    }

    #[test]
    fn dispatch_queue_enforces_and_releases_aggregate_byte_budget() {
        let queue = DispatchQueueState::default();

        assert!(queue.reserve_queued_bytes(MAX_DISPATCH_QUEUE_BYTES));
        assert!(!queue.reserve_queued_bytes(1));
        queue.release_queued_bytes(MAX_DISPATCH_QUEUE_BYTES / 2);
        assert!(queue.reserve_queued_bytes(MAX_DISPATCH_QUEUE_BYTES / 2));
        assert!(!queue.reserve_queued_bytes(usize::MAX));

        queue.release_queued_bytes(MAX_DISPATCH_QUEUE_BYTES);
        queue.stop();
        assert!(!queue.reserve_queued_bytes(1));
    }

    #[test]
    fn dispatch_request_measurement_matches_wire_serialization() {
        let request = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"payload": "bounded"})),
            7_i64,
        );
        assert_eq!(
            measure_dispatch_request(&request),
            Some(serde_json::to_vec(&request).unwrap().len())
        );
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
        assert_eq!(config.level, LevelFilter::Info);
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
            let _guard =
                ActiveRequestGuard::try_new(&map, 11, id.clone(), cx).expect("insert guard");
            assert_eq!(map.lock().unwrap().len(), 1);
        }
        // After drop, the entry should be removed
        assert_eq!(map.lock().unwrap().len(), 0);
    }

    #[test]
    fn active_request_guard_rejects_duplicate_request_id() {
        let map = Mutex::new(HashMap::new());
        let first = ActiveRequestGuard::try_new(&map, 11, RequestId::Number(7), Cx::for_testing())
            .expect("first request should register");
        let duplicate =
            ActiveRequestGuard::try_new(&map, 11, RequestId::Number(7), Cx::for_testing());
        assert!(
            duplicate.is_err(),
            "duplicate active request id must be rejected"
        );
        drop(first);
        assert!(map.lock().unwrap().is_empty());
    }

    #[test]
    fn active_request_guard_allows_same_request_id_in_distinct_sessions() {
        let map = Mutex::new(HashMap::new());
        let first = ActiveRequestGuard::try_new(&map, 11, RequestId::Number(7), Cx::for_testing())
            .expect("first session should register");
        let second = ActiveRequestGuard::try_new(&map, 12, RequestId::Number(7), Cx::for_testing())
            .expect("second session may reuse the same wire request id");
        assert_eq!(map.lock().unwrap().len(), 2);
        drop((first, second));
        assert!(map.lock().unwrap().is_empty());
    }

    #[test]
    fn cancellation_notification_is_bound_to_originating_session() {
        let server = Server::new("cancel-owner-test", "1.0.0").build();
        let first_cx = Cx::for_testing();
        let second_cx = Cx::for_testing();
        let request_id = RequestId::Number(7);
        let first = ActiveRequestGuard::try_new(
            &server.active_requests,
            11,
            request_id.clone(),
            first_cx.clone(),
        )
        .expect("first session should register");
        let second = ActiveRequestGuard::try_new(
            &server.active_requests,
            12,
            request_id.clone(),
            second_cx.clone(),
        )
        .expect("second session should register");
        let first_cancellation = first.cancellation();
        let second_cancellation = second.cancellation();

        server.handle_cancelled_notification(
            11,
            CancelledParams {
                request_id,
                reason: Some("owner requested cancellation".to_string()),
                await_cleanup: Some(false),
            },
        );

        assert!(first_cancellation.is_cancel_requested());
        assert!(!second_cancellation.is_cancel_requested());
        assert!(!first_cx.is_cancel_requested());
        assert!(!second_cx.is_cancel_requested());
        drop((first, second));
    }

    #[test]
    fn await_cleanup_does_not_block_the_receive_path() {
        let server = Server::new("nonblocking-await-cleanup-test", "1.0.0").build();
        let request_id = RequestId::Number(41);
        let guard = ActiveRequestGuard::try_new(
            &server.active_requests,
            11,
            request_id.clone(),
            Cx::for_testing(),
        )
        .expect("request should register");
        let cancellation = guard.cancellation();
        let start = Instant::now();

        server.handle_cancelled_notification(
            11,
            CancelledParams {
                request_id,
                reason: None,
                await_cleanup: Some(true),
            },
        );

        assert!(cancellation.is_cancel_requested());
        assert!(!guard.completion.is_done());
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "the receive path must not wait for request cleanup"
        );
    }

    #[test]
    fn duplicate_cancellation_is_not_misclassified_as_finalization() {
        let server = Server::new("duplicate-cancellation-state-test", "1.0.0").build();
        let request_id = RequestId::Number(42);
        let guard = ActiveRequestGuard::try_new(
            &server.active_requests,
            11,
            request_id.clone(),
            Cx::for_testing(),
        )
        .expect("request should register");
        let cancellation = guard.cancellation();

        for await_cleanup in [false, true] {
            server.handle_cancelled_notification(
                11,
                CancelledParams {
                    request_id: request_id.clone(),
                    reason: None,
                    await_cleanup: Some(await_cleanup),
                },
            );
        }

        assert!(cancellation.is_cancel_requested());
        assert!(!cancellation.is_finalizing());
        assert!(!guard.completion.is_done());
    }

    #[test]
    fn request_local_cancellation_dominates_a_late_success_without_cancelling_ambient_cx() {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        cancellation.cancel();

        let result = Server::enforce_post_dispatch_liveness(
            &cancellation,
            &cx,
            Budget::INFINITE,
            Ok(serde_json::json!({"late": "success"})),
        )
        .expect_err("late request cancellation must dominate a successful handler result");

        assert_eq!(result.code, McpErrorCode::RequestCancelled);
        assert!(!cx.is_cancel_requested());
    }

    #[test]
    fn post_dispatch_success_remains_cancellable_until_response_commit() {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let result = Server::enforce_post_dispatch_liveness(
            &cancellation,
            &cx,
            Budget::INFINITE,
            Ok(serde_json::json!({"committed": true})),
        )
        .expect("active request should preserve its successful result");

        assert_eq!(result, serde_json::json!({"committed": true}));
        assert!(!cancellation.is_finalizing());
        assert!(cancellation.cancel());
        assert!(cancellation.is_cancel_requested());
        assert!(!cx.is_cancel_requested());
    }

    #[test]
    fn initialize_response_middleware_failure_restores_exact_prior_state() {
        let server = Server::new("initialize-middleware-rollback-test", "1.0.0")
            .middleware(RejectResponseMiddleware)
            .build();
        let mut session = Session::new(server.info.clone(), server.capabilities.clone());
        session.initialize(
            fastmcp_protocol::ClientInfo {
                name: "original-client".to_string(),
                version: "0.9.0".to_string(),
            },
            fastmcp_protocol::ClientCapabilities {
                sampling: Some(fastmcp_protocol::SamplingCapability {}),
                elicitation: None,
                roots: None,
            },
            "original-protocol".to_string(),
        );
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let response = server
            .dispatch_request(
                &Cx::for_testing(),
                &mut session,
                initialize_test_request(
                    81,
                    "replacement-client",
                    fastmcp_protocol::ClientCapabilities {
                        sampling: None,
                        elicitation: Some(fastmcp_protocol::ElicitationCapability::form()),
                        roots: None,
                    },
                ),
                &notification_sender,
                &test_request_sender(),
            )
            .expect("initialize middleware failure must produce a response");

        assert!(response.error.is_some());
        assert!(session.is_initialized());
        assert_eq!(
            session.client_info().map(|info| info.name.as_str()),
            Some("original-client")
        );
        assert_eq!(session.protocol_version(), Some("original-protocol"));
        assert!(session.supports_sampling());
        assert!(!session.supports_elicitation());
    }

    #[test]
    fn late_initialize_cancellation_restores_uninitialized_state() {
        let server = Server::new("initialize-cancellation-rollback-test", "1.0.0").build();
        let mut session = Session::new(server.info.clone(), server.capabilities.clone());
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let handled = server
            .handle_request_internal(
                &Cx::for_testing(),
                &mut session,
                initialize_test_request(
                    82,
                    "cancelled-client",
                    fastmcp_protocol::ClientCapabilities::default(),
                ),
                &notification_sender,
                &request_sender,
                None,
                None,
            )
            .expect("initialize must produce a provisional response");
        let cancellation = handled
            .cancellation
            .as_ref()
            .expect("initialize request must remain cancellable")
            .clone();

        assert!(session.is_initialized());
        assert!(cancellation.cancel());
        let response = handled.finalize_for_return(&mut session);

        assert_eq!(
            response.error.as_ref().map(|error| error.code),
            Some(i32::from(McpErrorCode::RequestCancelled))
        );
        assert!(!session.is_initialized());
        assert!(session.client_info().is_none());
        assert!(session.client_capabilities().is_none());
        assert!(session.protocol_version().is_none());
    }

    #[test]
    fn initialize_encode_failure_restores_exact_prior_state() {
        let server = Server::new("initialize-encode-rollback-test", "1.0.0").build();
        let mut session = initialized_test_session(&server);
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let handled = server
            .handle_request_internal(
                &Cx::for_testing(),
                &mut session,
                initialize_test_request(
                    83,
                    "unsent-replacement-client",
                    fastmcp_protocol::ClientCapabilities::default(),
                ),
                &notification_sender,
                &request_sender,
                None,
                None,
            )
            .expect("initialize must produce a provisional response");

        assert_eq!(
            session.client_info().map(|info| info.name.as_str()),
            Some("unsent-replacement-client")
        );
        let json_error = serde_json::from_str::<serde_json::Value>("{")
            .expect_err("malformed JSON must create a codec error");
        let error = handled
            .send_with(&mut session, |_response| {
                Err(TransportError::Codec(fastmcp_transport::CodecError::Json(
                    json_error,
                )))
            })
            .expect_err("encode failure must propagate");

        assert!(matches!(error, TransportError::Codec(_)));
        assert_eq!(
            session.client_info().map(|info| info.name.as_str()),
            Some("panic-containment-test-client")
        );
        assert_eq!(session.protocol_version(), Some("2024-11-05"));
    }

    #[test]
    fn log_level_write_failure_restores_previous_level() {
        let server = Server::new("log-level-write-rollback-test", "1.0.0")
            .log_level(Level::Debug)
            .build();
        let mut session = initialized_test_session(&server);
        session.set_log_level(LogLevel::Warning);
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let request = JsonRpcRequest::new(
            "logging/setLevel",
            Some(
                serde_json::to_value(SetLogLevelParams {
                    level: LogLevel::Debug,
                })
                .expect("serialize logging/setLevel request"),
            ),
            84_i64,
        );
        let handled = server
            .handle_request_internal(
                &Cx::for_testing(),
                &mut session,
                request,
                &notification_sender,
                &request_sender,
                None,
                None,
            )
            .expect("logging/setLevel must produce a provisional response");

        assert_eq!(session.log_level(), Some(LogLevel::Debug));
        let error = handled
            .send_with(&mut session, |_response| {
                Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "test logging response write failure",
                )))
            })
            .expect_err("write failure must propagate");

        assert!(matches!(error, TransportError::Io(_)));
        assert_eq!(session.log_level(), Some(LogLevel::Warning));
    }

    #[test]
    fn handled_response_retains_active_request_until_commit_and_late_cancellation_wins() {
        let server = Server::new("commit-race-test", "1.0.0").build();
        let mut session = initialized_test_session(&server);
        let request_id = RequestId::String("commit-race".to_string());
        let request_cx = Cx::for_testing();
        let guard = ActiveRequestGuard::try_new(
            &server.active_requests,
            session.id(),
            request_id.clone(),
            request_cx.clone(),
        )
        .expect("register active request");
        let cancellation = guard.cancellation();
        let handled = HandledRequest::tracked(
            JsonRpcResponse::success(request_id.clone(), serde_json::json!({"ok": true})),
            cancellation.clone(),
            Some(guard),
            None,
            request_cx,
            Budget::INFINITE,
        )
        .with_deferred_stats(DeferredRequestStats::new(
            server.stats.as_ref(),
            "tools/call",
            Instant::now(),
            DeferredRequestOutcome::Success,
        ));

        assert!(server.request_id_is_active(session.id(), &request_id));
        assert!(cancellation.cancel());
        let response = handled.finalize_for_return(&mut session);

        assert_eq!(response.id, Some(request_id.clone()));
        assert_eq!(
            response.error.as_ref().map(|error| error.code),
            Some(i32::from(McpErrorCode::RequestCancelled))
        );
        assert!(!server.request_id_is_active(session.id(), &request_id));
        let stats = server.stats().expect("stats enabled by default");
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.successful_requests, 0);
        assert_eq!(stats.cancelled_requests, 1);
    }

    #[test]
    fn ambient_cancellation_before_commit_rolls_back_and_replaces_success() {
        let mut session = Session::new(
            ServerInfo {
                name: "ambient-commit-test".to_string(),
                version: "1.0.0".to_string(),
            },
            ServerCapabilities::default(),
        );
        session.set_log_level(LogLevel::Debug);
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let handled = HandledRequest::tracked(
            JsonRpcResponse::success(RequestId::Number(91), serde_json::json!({"ok": true})),
            cancellation.clone(),
            None,
            Some(SessionMutationRollback::RestoreLogLevel(Some(
                LogLevel::Warning,
            ))),
            cx.clone(),
            Budget::INFINITE,
        );

        cx.set_cancel_requested(true);
        let response = handled.finalize_for_return(&mut session);

        assert_eq!(
            response.error.as_ref().map(|error| error.code),
            Some(i32::from(McpErrorCode::RequestCancelled))
        );
        assert_eq!(session.log_level(), Some(LogLevel::Warning));
        assert!(cancellation.is_cancel_requested());
    }

    #[test]
    fn deadline_expiring_while_response_is_pending_prevents_commit() {
        let mut session = Session::new(
            ServerInfo {
                name: "deadline-commit-test".to_string(),
                version: "1.0.0".to_string(),
            },
            ServerCapabilities::default(),
        );
        let cx = Cx::for_testing();
        // Keep the precondition well away from scheduler jitter. The previous
        // one-millisecond window could expire while the test thread was
        // descheduled before the assertion below.
        let budget = Budget::new().with_deadline(cx.now().saturating_add_nanos(1_000_000_000));
        assert!(Server::request_budget_error(&cx, budget).is_none());
        let handled = HandledRequest::tracked(
            JsonRpcResponse::success(RequestId::Number(92), serde_json::json!({"ok": true})),
            McpRequestCancellation::new(),
            None,
            None,
            cx,
            budget,
        );

        std::thread::sleep(Duration::from_millis(1_100));
        let response = handled.finalize_for_return(&mut session);

        assert_eq!(
            response.error.as_ref().map(|error| error.code),
            Some(i32::from(McpErrorCode::RequestCancelled))
        );
        assert_eq!(
            response.error.as_ref().map(|error| error.message.as_str()),
            Some("Request timeout exceeded")
        );
    }

    #[test]
    fn failed_response_write_rolls_back_reversible_session_mutation() {
        let server = Server::new("commit-rollback-test", "1.0.0").build();
        let mut session = initialized_test_session(&server);
        let uri = "test://response-write-rollback".to_string();
        session.restore_resource_subscription(uri.clone());
        let handled = HandledRequest::tracked(
            JsonRpcResponse::success(RequestId::Number(9), serde_json::json!({})),
            McpRequestCancellation::new(),
            None,
            Some(SessionMutationRollback::RemoveResourceSubscription(
                uri.clone(),
            )),
            Cx::for_testing(),
            Budget::INFINITE,
        )
        .with_deferred_stats(DeferredRequestStats::new(
            server.stats.as_ref(),
            "resources/subscribe",
            Instant::now(),
            DeferredRequestOutcome::Success,
        ));

        let error = handled
            .send_with(&mut session, |_response| {
                Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "test write failure",
                )))
            })
            .expect_err("failed response write must propagate");

        assert!(matches!(error, TransportError::Io(_)));
        assert!(!session.is_resource_subscribed(&uri));
        assert_eq!(
            server
                .stats()
                .expect("stats enabled by default")
                .total_requests,
            0,
            "a response that never reached the transport must not be counted as sent"
        );
    }

    #[test]
    fn expired_ambient_deadline_is_enforced_before_and_after_dispatch() {
        let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(asupersync::Time::ZERO));

        let admission = Server::request_budget_error(&cx, Budget::INFINITE)
            .expect("expired ambient deadline must fail pre-admission");
        assert_eq!(admission.code, McpErrorCode::RequestCancelled);

        let result = Server::enforce_post_dispatch_liveness(
            &McpRequestCancellation::new(),
            &cx,
            Budget::INFINITE,
            Ok(serde_json::json!({"late": "success"})),
        )
        .expect_err("expired ambient deadline must dominate a late success");
        assert_eq!(result.code, McpErrorCode::RequestCancelled);
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
        assert_eq!(cloned.level, LevelFilter::Info);
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
    fn dispatch_worker_send_failure_returns_failure_status() {
        let emitted = Arc::new(AtomicBool::new(false));
        let emitted_for_receive = Arc::clone(&emitted);
        let cx = Cx::for_testing();
        let exit_code = Server::new("worker-send-failure-test", "1.0.0")
            .build()
            .run_loop_pump(
                &cx,
                move |receive_cx| {
                    if !emitted_for_receive.swap(true, Ordering::AcqRel) {
                        return Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
                            "ping", None, 701_i64,
                        )));
                    }
                    if receive_cx.is_cancel_requested() {
                        Err(TransportError::Cancelled)
                    } else {
                        std::thread::yield_now();
                        Err(TransportError::Timeout)
                    }
                },
                |_send_cx, _message| {
                    Err(TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "test response send failure",
                    )))
                },
                Arc::new(|_| {}),
                "test",
            );

        assert_eq!(exit_code, 1);
    }

    #[test]
    fn dispatch_worker_panic_trips_failure_latch_and_returns_failure_status() {
        let emitted = Arc::new(AtomicBool::new(false));
        let emitted_for_receive = Arc::clone(&emitted);
        let cx = Cx::for_testing();
        let exit_code = Server::new("worker-panic-latch-test", "1.0.0")
            .build()
            .run_loop_pump(
                &cx,
                move |receive_cx| {
                    if !emitted_for_receive.swap(true, Ordering::AcqRel) {
                        return Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
                            "ping", None, 702_i64,
                        )));
                    }
                    if receive_cx.is_cancel_requested() {
                        Err(TransportError::Cancelled)
                    } else {
                        std::thread::yield_now();
                        Err(TransportError::Timeout)
                    }
                },
                |_send_cx, _message| -> Result<(), TransportError> {
                    panic!("dispatch worker send callback panic")
                },
                Arc::new(|_| {}),
                "test",
            );

        assert_eq!(exit_code, 1);
    }

    #[test]
    fn returning_loop_replies_to_bounded_codec_error_then_reads_next_frame() {
        use std::collections::VecDeque;
        use std::sync::atomic::AtomicUsize;

        let steps = Arc::new(Mutex::new(VecDeque::from([
            Err(TransportError::Codec(fastmcp_transport::CodecError::Json(
                serde_json::from_str::<serde_json::Value>("{")
                    .expect_err("fixture must be invalid JSON"),
            ))),
            Err(TransportError::Closed),
        ])));
        let receive_calls = Arc::new(AtomicUsize::new(0));
        let sent = Arc::new(Mutex::new(Vec::<JsonRpcMessage>::new()));
        let receive_steps = Arc::clone(&steps);
        let receive_count = Arc::clone(&receive_calls);
        let sent_messages = Arc::clone(&sent);

        Server::new("recoverable-codec-error-test", "1.0.0")
            .build()
            .run_loop_returning(
                &Cx::for_testing(),
                move |_| {
                    receive_count.fetch_add(1, Ordering::Relaxed);
                    receive_steps
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .pop_front()
                        .unwrap_or(Err(TransportError::Closed))
                },
                move |_, message| {
                    sent_messages
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(message.clone());
                    Ok(())
                },
                Arc::new(|_| {}),
                "test",
            );

        assert_eq!(receive_calls.load(Ordering::Relaxed), 2);
        let sent = sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let [JsonRpcMessage::Response(response)] = sent.as_slice() else {
            panic!("expected one uncorrelated parse-error response");
        };
        assert!(response.id.is_none());
        assert_eq!(
            response.error.as_ref().map(|error| error.code),
            Some(-32700)
        );
        let wire = serde_json::to_value(response).expect("parse error response must serialize");
        assert!(wire.get("id").is_none());
    }

    #[test]
    fn returning_loop_correlates_invalid_request_only_when_codec_proves_unique_id() {
        use std::collections::VecDeque;

        let invalid = fastmcp_transport::Codec::new()
            .decode_complete_message(br#"{"jsonrpc":"2.1","method":"tools/list","id":"safe-id"}"#)
            .expect_err("wrong JSON-RPC version must be invalid");
        let steps = Arc::new(Mutex::new(VecDeque::from([
            Err(TransportError::Codec(invalid)),
            Err(TransportError::Closed),
        ])));
        let sent = Arc::new(Mutex::new(Vec::<JsonRpcMessage>::new()));
        let receive_steps = Arc::clone(&steps);
        let sent_messages = Arc::clone(&sent);

        Server::new("correlated-invalid-request-test", "1.0.0")
            .build()
            .run_loop_returning(
                &Cx::for_testing(),
                move |_| {
                    receive_steps
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .pop_front()
                        .unwrap_or(Err(TransportError::Closed))
                },
                move |_, message| {
                    sent_messages
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(message.clone());
                    Ok(())
                },
                Arc::new(|_| {}),
                "test",
            );

        let sent = sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let [JsonRpcMessage::Response(response)] = sent.as_slice() else {
            panic!("expected one invalid-request response");
        };
        assert_eq!(response.id, Some(RequestId::String("safe-id".to_string())));
        assert_eq!(
            response.error.as_ref().map(|error| error.code),
            Some(i32::from(McpErrorCode::InvalidRequest))
        );
    }

    #[test]
    fn returning_loop_terminates_after_fatal_framing_error_without_logging_payload() {
        use std::sync::atomic::AtomicUsize;

        let receive_calls = Arc::new(AtomicUsize::new(0));
        let receive_count = Arc::clone(&receive_calls);
        let sent = Arc::new(AtomicUsize::new(0));
        let sent_count = Arc::clone(&sent);

        Server::new("fatal-framing-error-test", "1.0.0")
            .build()
            .run_loop_returning(
                &Cx::for_testing(),
                move |_| {
                    receive_count.fetch_add(1, Ordering::Relaxed);
                    Err(TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "SECRET_FRAMING_CANARY\r\nforged-log-line",
                    )))
                },
                move |_, _| {
                    sent_count.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                },
                Arc::new(|_| {}),
                "test",
            );

        assert_eq!(receive_calls.load(Ordering::Relaxed), 1);
        assert_eq!(sent.load(Ordering::Relaxed), 0);
        assert_eq!(
            classify_receive_error(&TransportError::Timeout),
            ReceiveErrorDisposition::Retry
        );
        assert_eq!(
            classify_receive_error(&TransportError::Codec(
                fastmcp_transport::CodecError::MessageTooLarge(42)
            )),
            ReceiveErrorDisposition::Terminate
        );
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
    fn http_advisory_read_only_tools_remain_session_serialized() {
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
        let control = http_overlap_control();
        let _control_guard = control.begin(Arc::as_ptr(&session).addr());

        let http_handler = Arc::new(HttpRequestHandler::new());
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();

        let run_request = |id| {
            let server = Arc::clone(&server);
            let session = Arc::clone(&session);
            let http_handler = Arc::clone(&http_handler);
            let notification_sender = Arc::clone(&notification_sender);
            let request_sender = request_sender.clone();
            thread::spawn(move || -> Result<(), String> {
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
                if response.status != HttpStatus::OK {
                    return Err(format!(
                        "unexpected HTTP status from overlap request: {:?}",
                        response.status
                    ));
                }
                let json: JsonRpcResponse = serde_json::from_slice(&response.body)
                    .map_err(|error| format!("failed to parse HTTP JSON-RPC response: {error}"))?;
                if let Some(error) = json.error {
                    return Err(format!("unexpected JSON-RPC error response: {error:?}"));
                }
                Ok(())
            })
        };

        let mut workers = HttpOverlapWorkers::new(control);
        workers.push(run_request(1));
        let first_entered = control.wait_for_entries(1, Duration::from_secs(2));

        workers.push(run_request(2));
        let both_reached_session_lock = control.wait_for_lock_attempts(2, Duration::from_secs(2));
        let second_observed_contention =
            control.wait_for_lock_contentions(1, Duration::from_secs(2));

        control.release_one();
        let second_entered_after_release = control.wait_for_entries(2, Duration::from_secs(2));
        control.release_one();
        // Always unblock the instrumentation and join both workers before any
        // assertion can panic. This keeps a failing test from leaking request
        // threads into later tests that share the process-global probe.
        let mut results = workers.join_all().into_iter();
        let first_result = results.next().expect("first HTTP worker result missing");
        let second_result = results.next().expect("second HTTP worker result missing");

        assert!(
            first_entered,
            "the first HTTP handler did not enter within the test deadline"
        );
        assert!(
            both_reached_session_lock,
            "both HTTP requests must reach the target session-lock boundary"
        );
        assert!(
            second_observed_contention,
            "the second HTTP request did not observe the held session lock"
        );
        assert!(
            second_entered_after_release,
            "the second HTTP handler did not enter after the first released the session"
        );
        first_result
            .expect("first HTTP request thread panicked")
            .expect("first HTTP request failed");
        second_result
            .expect("second HTTP request thread panicked")
            .expect("second HTTP request failed");

        let overlap = http_overlap_metrics().max.load(Ordering::SeqCst);
        assert_eq!(
            overlap, 1,
            "advisory read-only metadata must not bypass session serialization"
        );
    }

    #[test]
    fn native_http_auth_binds_session_and_rejects_cross_principal_reuse() {
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
                let subject = fixed_test_subject_for_credential(&access.token)?;
                Ok(AuthContext::with_subject(subject))
            }
        }

        let server = Server::new("http-auth-test-server", "1.0.0")
            .auth_provider(EchoAuthProvider)
            .tool(HttpAuthEchoToolRuntime)
            .build();
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

        let http_handler = HttpRequestHandler::new();
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();

        let run_request = |id, token: &str| {
            let request = http_json_request(
                "tools/call",
                serde_json::json!({
                    "name": "http_auth_echo_tool_runtime",
                    "arguments": {}
                }),
                id,
            )
            .with_header("Authorization", format!("Bearer {token}"));
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
            serde_json::from_slice::<JsonRpcResponse>(&response.body)
                .expect("parse HTTP JSON-RPC response")
        };

        for id in [1, 2] {
            let response = run_request(id, "alpha");
            let result = response.result.expect("bound principal should succeed");
            let tool_result: CallToolResult =
                serde_json::from_value(result).expect("parse tool result payload");
            assert!(matches!(
                tool_result.content.as_slice(),
                [Content::Text { text }] if text == "principal-alpha"
            ));
        }

        let rejected = run_request(3, "beta");
        let error = rejected
            .error
            .expect("a different principal must not reuse session state");
        assert_eq!(error.code, i32::from(McpErrorCode::ResourceForbidden));
        assert!(rejected.result.is_none());
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
                let subject = fixed_test_subject_for_credential(&access.token)?;
                Ok(AuthContext::with_subject(subject))
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
            vec![(
                "tools/list".to_string(),
                Some("principal-alpha".to_string())
            )]
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
                let subject = fixed_test_subject_for_credential(&access.token)?;
                Ok(AuthContext::with_subject(subject))
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
            [Content::Text { text }] => assert_eq!(text, "principal-beta"),
            other => panic!("expected single text tool result, got {other:?}"),
        }

        let observed = seen
            .lock()
            .expect("captured auth middleware mutex should not be poisoned")
            .clone();
        assert_eq!(
            observed,
            vec![("tools/call".to_string(), Some("principal-beta".to_string()))]
        );
    }

    #[test]
    fn http_exclusive_middleware_cannot_replace_committed_request_auth() {
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
            .expect("exclusive request should succeed with committed anonymous auth");
        let tool_result: CallToolResult =
            serde_json::from_value(result).expect("parse tool result payload");
        match tool_result.content.as_slice() {
            [Content::Text { text }] => assert_eq!(text, "anonymous"),
            other => panic!("expected single text tool result, got {other:?}"),
        }
    }

    #[test]
    fn http_read_only_middleware_cannot_replace_committed_request_auth() {
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
            .expect("read-only request should succeed with committed anonymous auth");
        let tool_result: CallToolResult =
            serde_json::from_value(result).expect("parse tool result payload");
        match tool_result.content.as_slice() {
            [Content::Text { text }] => assert_eq!(text, "anonymous"),
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
        assert_eq!(error.message, "rewritten: Authentication failed");
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
        assert_eq!(error.message, "rewritten: Authentication failed");
    }

    #[test]
    fn auth_provider_error_payload_is_sanitized_before_middleware_and_wire() {
        const CANARY: &str = "AUTH-PROVIDER-RAW-CREDENTIAL-CANARY";

        #[derive(Debug)]
        struct LeakingAuthProvider;

        impl AuthProvider for LeakingAuthProvider {
            fn authenticate(
                &self,
                _ctx: &McpContext,
                _request: AuthRequest<'_>,
            ) -> McpResult<AuthContext> {
                Err(McpError::with_data(
                    McpErrorCode::ResourceForbidden,
                    format!("denied bearer {CANARY}"),
                    serde_json::json!({"raw_token": CANARY}),
                ))
            }
        }

        #[derive(Debug, Clone)]
        struct CapturingErrorMiddleware {
            seen: Arc<Mutex<Vec<McpError>>>,
        }

        impl Middleware for CapturingErrorMiddleware {
            fn on_error(
                &self,
                _ctx: &McpContext,
                _request: &JsonRpcRequest,
                error: McpError,
            ) -> McpError {
                self.seen
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(error.clone());
                error
            }
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let server = Server::new("auth-error-sanitization-test", "1.0.0")
            .auth_provider(LeakingAuthProvider)
            .middleware(CapturingErrorMiddleware {
                seen: Arc::clone(&seen),
            })
            .build();
        let session = Arc::new(Mutex::new(Session::new(
            server.info.clone(),
            server.capabilities.clone(),
        )));
        session.lock().expect("session lock poisoned").initialize(
            fastmcp_protocol::ClientInfo {
                name: "auth-error-sanitization-client".to_string(),
                version: "1.0.0".to_string(),
            },
            fastmcp_protocol::ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let http_handler = HttpRequestHandler::new();
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let response = server.handle_http_mcp_request(
            &Cx::for_testing(),
            &session,
            &http_handler,
            &http_json_request(
                "tools/list",
                serde_json::json!({"authorization": "Bearer peer-token"}),
                1,
            ),
            &notification_sender,
            &request_sender,
            &None,
        );
        let wire = String::from_utf8(response.body).expect("UTF-8 JSON-RPC response");
        assert!(!wire.contains(CANARY));
        let response: JsonRpcResponse = serde_json::from_str(&wire).expect("JSON-RPC response");
        let error = response.error.expect("authentication must fail");
        assert_eq!(error.message, "Authentication failed");
        assert!(error.data.is_none());

        let seen = seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].message, "Authentication failed");
        assert!(seen[0].data.is_none());
        assert!(!format!("{:?}", seen[0]).contains(CANARY));
    }

    #[test]
    fn router_tools_call_injects_explicit_request_auth() {
        let server = Server::new("router-auth-test-server", "1.0.0")
            .tool(HttpCurrentAuthSubjectTool)
            .build();
        let state = SessionState::new();
        let request_ctx = McpContext::with_state(Cx::for_testing(), 41, state.clone())
            .with_auth(AuthContext::with_subject("alpha"));
        let result = server
            .router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "http_current_auth_subject_tool".to_string(),
                    arguments: Some(serde_json::json!({})),
                    meta: None,
                },
                state,
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
    fn request_cost_accounting_flows_through_auth_middleware_and_handler() {
        type Observation = (&'static str, Option<u64>);

        #[derive(Debug, Clone)]
        struct ChargingAuth {
            seen: Arc<Mutex<Vec<Observation>>>,
        }

        impl AuthProvider for ChargingAuth {
            fn authenticate(
                &self,
                ctx: &McpContext,
                _request: AuthRequest<'_>,
            ) -> McpResult<AuthContext> {
                ctx.consume_cost(1)?;
                self.seen
                    .lock()
                    .expect("cost observation mutex poisoned")
                    .push(("auth", ctx.budget().cost_quota));
                Ok(AuthContext::anonymous())
            }
        }

        #[derive(Debug, Clone)]
        struct ChargingMiddleware {
            seen: Arc<Mutex<Vec<Observation>>>,
        }

        impl Middleware for ChargingMiddleware {
            fn on_request(
                &self,
                ctx: &McpContext,
                _request: &JsonRpcRequest,
            ) -> McpResult<MiddlewareDecision> {
                ctx.consume_cost(1)?;
                self.seen
                    .lock()
                    .expect("cost observation mutex poisoned")
                    .push(("middleware", ctx.budget().cost_quota));
                Ok(MiddlewareDecision::Continue)
            }
        }

        #[derive(Debug, Clone)]
        struct ChargingTool {
            seen: Arc<Mutex<Vec<Observation>>>,
        }

        impl ToolHandler for ChargingTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "charging_tool".to_string(),
                    description: Some("Charges the shared request cost budget".to_string()),
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: Vec::new(),
                    annotations: None,
                }
            }

            fn call(&self, ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
                ctx.consume_cost(1)?;
                self.seen
                    .lock()
                    .expect("cost observation mutex poisoned")
                    .push(("handler", ctx.budget().cost_quota));
                Ok(vec![Content::text("charged")])
            }
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let server = Server::new("request-cost-accounting-test", "1.0.0")
            .auth_provider(ChargingAuth {
                seen: Arc::clone(&seen),
            })
            .middleware(ChargingMiddleware {
                seen: Arc::clone(&seen),
            })
            .tool(ChargingTool {
                seen: Arc::clone(&seen),
            })
            .build();
        let mut session = initialized_test_session(&server);
        let cx = Cx::for_testing_with_budget(Budget::new().with_cost_quota(3));
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let request = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "name": "charging_tool",
                "arguments": {}
            })),
            1,
        );

        let response = server
            .dispatch_request(
                &cx,
                &mut session,
                request,
                &notification_sender,
                &request_sender,
            )
            .expect("request should produce a response");
        assert!(
            response.error.is_none(),
            "unexpected response: {response:?}"
        );
        assert_eq!(
            *seen.lock().expect("cost observation mutex poisoned"),
            vec![
                ("auth", Some(2)),
                ("middleware", Some(1)),
                ("handler", Some(0)),
            ]
        );
        assert_eq!(
            cx.budget().cost_quota,
            Some(3),
            "request accounting must not mutate the caller-owned ambient Cx"
        );

        let rejected_seen = Arc::new(Mutex::new(Vec::new()));
        let rejected_server = Server::new("request-cost-overrun-test", "1.0.0")
            .auth_provider(ChargingAuth {
                seen: Arc::clone(&rejected_seen),
            })
            .middleware(ChargingMiddleware {
                seen: Arc::clone(&rejected_seen),
            })
            .tool(ChargingTool {
                seen: Arc::clone(&rejected_seen),
            })
            .build();
        let mut rejected_session = initialized_test_session(&rejected_server);
        let rejected_cx = Cx::for_testing_with_budget(Budget::new().with_cost_quota(2));
        let rejected_response = rejected_server
            .dispatch_request(
                &rejected_cx,
                &mut rejected_session,
                JsonRpcRequest::new(
                    "tools/call",
                    Some(serde_json::json!({
                        "name": "charging_tool",
                        "arguments": {}
                    })),
                    2,
                ),
                &notification_sender,
                &request_sender,
            )
            .expect("over-budget tool request should produce a response");
        assert!(rejected_response.result.is_none());
        assert_eq!(
            rejected_response
                .error
                .as_ref()
                .expect("budget refusal must be a JSON-RPC cancellation error")
                .code,
            i32::from(McpErrorCode::RequestCancelled)
        );
        assert_eq!(
            *rejected_seen
                .lock()
                .expect("cost observation mutex poisoned"),
            vec![("auth", Some(1)), ("middleware", Some(0))],
            "the N+1 handler debit must fail before handler effects"
        );
    }

    #[test]
    fn failed_authentication_cannot_publish_a_tentative_identity() {
        #[derive(Debug, Clone, Copy)]
        struct MutatingFailAuth;

        impl AuthProvider for MutatingFailAuth {
            fn authenticate(
                &self,
                ctx: &McpContext,
                _request: AuthRequest<'_>,
            ) -> McpResult<AuthContext> {
                ctx.set_auth(AuthContext::with_subject("tentative-secret-identity"));
                Err(McpError::invalid_request("authentication rejected"))
            }
        }

        #[derive(Debug, Clone)]
        struct CaptureAuthOnError {
            seen: Arc<Mutex<Vec<Option<String>>>>,
        }

        impl Middleware for CaptureAuthOnError {
            fn on_error(
                &self,
                ctx: &McpContext,
                _request: &JsonRpcRequest,
                error: McpError,
            ) -> McpError {
                self.seen
                    .lock()
                    .expect("auth error observation mutex poisoned")
                    .push(ctx.auth().and_then(|auth| auth.subject));
                error
            }
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let server = Server::new("transactional-auth-test", "1.0.0")
            .auth_provider(MutatingFailAuth)
            .middleware(CaptureAuthOnError {
                seen: Arc::clone(&seen),
            })
            .build();
        let mut session = initialized_test_session(&server);
        let response = dispatch_test_request(&server, &mut session, "tools/list");

        assert!(response.error.is_some());
        assert_eq!(
            *seen.lock().expect("auth error observation mutex poisoned"),
            vec![None],
            "failed provider identity must remain isolated from error middleware"
        );
    }

    #[test]
    fn zero_cost_quota_allows_a_zero_cost_request() {
        let server = Server::new("zero-cost-request-test", "1.0.0")
            .tool(HttpCurrentAuthSubjectTool)
            .build();
        let mut session = initialized_test_session(&server);
        let cx = Cx::for_testing_with_budget(Budget::new().with_cost_quota(0));
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let response = server
            .dispatch_request(
                &cx,
                &mut session,
                JsonRpcRequest::new(
                    "tools/call",
                    Some(serde_json::json!({
                        "name": "http_current_auth_subject_tool",
                        "arguments": {}
                    })),
                    1,
                ),
                &notification_sender,
                &request_sender,
            )
            .expect("zero-cost request should produce a response");

        assert!(
            response.error.is_none(),
            "unexpected response: {response:?}"
        );
        assert!(response.result.is_some());
    }

    #[test]
    fn production_dispatch_wires_router_backed_nested_tool_calls() {
        #[derive(Debug, Clone, Copy)]
        struct InnerTool;

        impl ToolHandler for InnerTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "inner_tool".to_string(),
                    description: Some("Nested dispatch target".to_string()),
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: Vec::new(),
                    annotations: None,
                }
            }

            fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
                Ok(vec![Content::text("inner-result")])
            }
        }

        #[derive(Debug, Clone, Copy)]
        struct OuterTool;

        impl ToolHandler for OuterTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "outer_tool".to_string(),
                    description: Some("Calls another registered tool".to_string()),
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: Vec::new(),
                    annotations: None,
                }
            }

            fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
                Err(McpError::internal_error(
                    "outer_tool requires async dispatch",
                ))
            }

            fn call_async<'a>(
                &'a self,
                ctx: &'a McpContext,
                _args: serde_json::Value,
            ) -> BoxFuture<'a, fastmcp_core::McpOutcome<Vec<Content>>> {
                Box::pin(async move {
                    match ctx.call_tool("inner_tool", serde_json::json!({})).await {
                        Ok(result) => {
                            let text = result.first_text().unwrap_or("missing nested text");
                            asupersync::Outcome::Ok(vec![Content::text(text)])
                        }
                        Err(error) => asupersync::Outcome::Err(error),
                    }
                })
            }
        }

        let server = Server::new("nested-production-dispatch-test", "1.0.0")
            .tool(InnerTool)
            .tool(OuterTool)
            .build();
        let mut session = initialized_test_session(&server);
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let response = server
            .dispatch_request(
                &Cx::for_testing(),
                &mut session,
                JsonRpcRequest::new(
                    "tools/call",
                    Some(serde_json::json!({
                        "name": "outer_tool",
                        "arguments": {}
                    })),
                    1_i64,
                ),
                &notification_sender,
                &request_sender,
            )
            .expect("nested tool request should produce a response");
        let result: CallToolResult = serde_json::from_value(
            response
                .result
                .expect("top-level tool should complete through nested router dispatch"),
        )
        .expect("decode nested tool result");

        match result.content.as_slice() {
            [Content::Text { text }] => assert_eq!(text, "inner-result"),
            other => panic!("expected nested tool text result, got {other:?}"),
        }
    }

    #[test]
    fn escaped_request_context_is_revoked_and_does_not_retain_server_router() {
        #[derive(Clone)]
        struct CaptureContextTool {
            captured: Arc<Mutex<Option<McpContext>>>,
        }

        impl ToolHandler for CaptureContextTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "capture_context".to_string(),
                    description: Some(
                        "Captures a request context for revocation testing".to_string(),
                    ),
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: Vec::new(),
                    annotations: None,
                }
            }

            fn call(&self, ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
                *self
                    .captured
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ctx.clone());
                Ok(vec![Content::text("captured")])
            }
        }

        let captured = Arc::new(Mutex::new(None));
        let server = Server::new("request-lease-test", "1.0.0")
            .tool(CaptureContextTool {
                captured: Arc::clone(&captured),
            })
            .build();
        let mut session = initialized_test_session(&server);
        let notification_sender: NotificationSender = Arc::new(|_| {});
        let request_sender = test_request_sender();
        let response = server
            .dispatch_request(
                &Cx::for_testing(),
                &mut session,
                JsonRpcRequest::new(
                    "tools/call",
                    Some(serde_json::json!({
                        "name": "capture_context",
                        "arguments": {}
                    })),
                    1_i64,
                ),
                &notification_sender,
                &request_sender,
            )
            .expect("capture request should produce a response");
        assert!(
            response.error.is_none(),
            "unexpected response: {response:?}"
        );

        let escaped = captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("handler should capture its context");
        let error = block_on(escaped.call_tool("capture_context", serde_json::json!({})))
            .expect_err("nested authority must close when dispatch returns");
        assert_eq!(error.code, McpErrorCode::RequestCancelled);

        let router = server.into_router();
        assert!(
            router
                .tools()
                .iter()
                .any(|tool| tool.name == "capture_context")
        );
    }

    #[test]
    fn http_returning_server_fails_closed_without_runtime_or_lifecycle_hooks() {
        let startup_called = Arc::new(AtomicBool::new(false));
        let shutdown_called = Arc::new(AtomicBool::new(false));
        let startup_observer = Arc::clone(&startup_called);
        let shutdown_observer = Arc::clone(&shutdown_called);

        Server::new("http-fail-closed-test", "1.0.0")
            .on_startup(move || {
                startup_observer.store(true, Ordering::SeqCst);
                Ok::<(), std::io::Error>(())
            })
            .on_shutdown(move || shutdown_observer.store(true, Ordering::SeqCst))
            .build()
            .run_http_returning("not-a-bindable-socket-address");

        assert!(!startup_called.load(Ordering::SeqCst));
        assert!(!shutdown_called.load(Ordering::SeqCst));

        Server::new("http-fail-closed-cx-test", "1.0.0")
            .build()
            .run_http_returning_with_cx(&Cx::for_testing(), "also-not-a-socket-address");
    }

    #[test]
    fn http_nonreturning_rejection_child() {
        match std::env::var("FASTMCP_HTTP_REJECTION_CHILD_MODE").as_deref() {
            Ok("plain") => Server::new("http-reject-child", "1.0.0")
                .build()
                .run_http("not-a-socket-address"),
            Ok("with-cx") => Server::new("http-reject-cx-child", "1.0.0")
                .build()
                .run_http_with_cx(&Cx::for_testing(), "not-a-socket-address"),
            _ => {}
        }
    }

    #[test]
    fn http_nonreturning_entry_points_exit_one_with_fixed_diagnostic() {
        let current_test_binary =
            std::env::current_exe().expect("resolve current server test binary");

        for mode in ["plain", "with-cx"] {
            let mut child = std::process::Command::new(&current_test_binary)
                .args([
                    "--exact",
                    "lib_unit_tests::http_nonreturning_rejection_child",
                    "--nocapture",
                ])
                .env("FASTMCP_HTTP_REJECTION_CHILD_MODE", mode)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn isolated HTTP rejection child");
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if child
                    .try_wait()
                    .expect("poll isolated HTTP rejection child")
                    .is_some()
                {
                    break;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("HTTP rejection child for mode {mode:?} did not exit within 5 seconds");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let output = child
                .wait_with_output()
                .expect("collect isolated HTTP rejection child output");

            assert_eq!(
                output.status.code(),
                Some(1),
                "HTTP rejection child for mode {mode:?} did not exit 1: {output:?}"
            );
            assert!(
                output
                    .stderr
                    .windows(UNQUALIFIED_HTTP_DIAGNOSTIC.len())
                    .any(|window| window == UNQUALIFIED_HTTP_DIAGNOSTIC),
                "HTTP rejection child for mode {mode:?} omitted fixed diagnostic: {output:?}"
            );
        }
    }
}
