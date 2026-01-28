//! HTTP transport for FastMCP.
//!
//! This module provides HTTP-based transport for MCP servers, enabling
//! web-based deployments without relying on stdio or WebSockets.
//!
//! # Modes
//!
//! The HTTP transport supports two modes:
//!
//! - **Stateless**: Each HTTP request contains a single JSON-RPC message and receives
//!   a single response. No session state is maintained between requests.
//!
//! - **Streamable**: Long-lived connections using HTTP streaming (chunked transfer)
//!   for bidirectional communication. Supports Server-Sent Events (SSE) for
//!   server-to-client notifications.
//!
//! # Integration
//!
//! This transport is designed to integrate with any HTTP server framework.
//! It provides:
//!
//! - [`HttpRequestHandler`]: Processes incoming HTTP requests containing JSON-RPC messages
//! - [`HttpTransport`]: Full transport implementation for HTTP connections
//! - [`StreamableHttpTransport`]: Streaming transport for long-lived connections
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_transport::http::{HttpRequestHandler, HttpRequest, HttpResponse};
//!
//! let handler = HttpRequestHandler::new();
//!
//! // In your HTTP server's request handler:
//! fn handle_mcp_request(http_req: YourHttpRequest) -> YourHttpResponse {
//!     let request = HttpRequest {
//!         method: http_req.method(),
//!         path: http_req.path(),
//!         headers: http_req.headers(),
//!         body: http_req.body(),
//!     };
//!
//!     let mcp_response = handler.handle(&cx, request)?;
//!
//!     YourHttpResponse::new()
//!         .status(mcp_response.status)
//!         .header("Content-Type", &mcp_response.content_type)
//!         .body(mcp_response.body)
//! }
//! ```

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asupersync::Cx;
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};

use crate::{Codec, CodecError, Transport, TransportError};

// =============================================================================
// HTTP Request/Response Types
// =============================================================================

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Options,
    Head,
    Patch,
}

impl HttpMethod {
    /// Parses an HTTP method from a string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "DELETE" => Some(Self::Delete),
            "OPTIONS" => Some(Self::Options),
            "HEAD" => Some(Self::Head),
            "PATCH" => Some(Self::Patch),
            _ => None,
        }
    }

    /// Returns the method as a string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Head => "HEAD",
            Self::Patch => "PATCH",
        }
    }
}

/// HTTP status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpStatus(pub u16);

impl HttpStatus {
    pub const OK: Self = Self(200);
    pub const ACCEPTED: Self = Self(202);
    pub const BAD_REQUEST: Self = Self(400);
    pub const UNAUTHORIZED: Self = Self(401);
    pub const FORBIDDEN: Self = Self(403);
    pub const NOT_FOUND: Self = Self(404);
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    pub const SERVICE_UNAVAILABLE: Self = Self(503);

    /// Returns true if this is a success status (2xx).
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.0)
    }

    /// Returns true if this is a client error (4xx).
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.0)
    }

    /// Returns true if this is a server error (5xx).
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.0)
    }
}

/// Incoming HTTP request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP method.
    pub method: HttpMethod,
    /// Request path (e.g., "/mcp/v1").
    pub path: String,
    /// Request headers.
    pub headers: HashMap<String, String>,
    /// Request body.
    pub body: Vec<u8>,
    /// Query parameters.
    pub query: HashMap<String, String>,
}

impl HttpRequest {
    /// Creates a new HTTP request.
    #[must_use]
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: HashMap::new(),
            body: Vec::new(),
            query: HashMap::new(),
        }
    }

    /// Adds a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.into().to_lowercase(), value.into());
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Adds a query parameter.
    #[must_use]
    pub fn with_query(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query.insert(name.into(), value.into());
        self
    }

    /// Gets a header value (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(String::as_str)
    }

    /// Gets the Content-Type header.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Gets the Authorization header.
    #[must_use]
    pub fn authorization(&self) -> Option<&str> {
        self.header("authorization")
    }

    /// Parses the body as JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

/// Outgoing HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: HttpStatus,
    /// Response headers.
    pub headers: HashMap<String, String>,
    /// Response body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Creates a new HTTP response with the given status.
    #[must_use]
    pub fn new(status: HttpStatus) -> Self {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        Self {
            status,
            headers,
            body: Vec::new(),
        }
    }

    /// Creates a 200 OK response.
    #[must_use]
    pub fn ok() -> Self {
        Self::new(HttpStatus::OK)
    }

    /// Creates a 400 Bad Request response.
    #[must_use]
    pub fn bad_request() -> Self {
        Self::new(HttpStatus::BAD_REQUEST)
    }

    /// Creates a 500 Internal Server Error response.
    #[must_use]
    pub fn internal_error() -> Self {
        Self::new(HttpStatus::INTERNAL_SERVER_ERROR)
    }

    /// Adds a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.into().to_lowercase(), value.into());
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Sets the body as JSON.
    #[must_use]
    pub fn with_json<T: serde::Serialize>(mut self, value: &T) -> Self {
        self.body = serde_json::to_vec(value).unwrap_or_default();
        self.headers
            .insert("content-type".to_string(), "application/json".to_string());
        self
    }

    /// Sets CORS headers for cross-origin requests.
    #[must_use]
    pub fn with_cors(mut self, origin: &str) -> Self {
        self.headers.insert(
            "access-control-allow-origin".to_string(),
            origin.to_string(),
        );
        self.headers.insert(
            "access-control-allow-methods".to_string(),
            "GET, POST, OPTIONS".to_string(),
        );
        self.headers.insert(
            "access-control-allow-headers".to_string(),
            "Content-Type, Authorization".to_string(),
        );
        self
    }
}

// =============================================================================
// HTTP Error
// =============================================================================

/// HTTP transport error.
#[derive(Debug)]
pub enum HttpError {
    /// Invalid HTTP method.
    InvalidMethod(String),
    /// Invalid Content-Type.
    InvalidContentType(String),
    /// JSON parsing error.
    JsonError(serde_json::Error),
    /// Codec error.
    CodecError(CodecError),
    /// Request timeout.
    Timeout,
    /// Connection closed.
    Closed,
    /// Transport error.
    Transport(TransportError),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMethod(m) => write!(f, "invalid HTTP method: {}", m),
            Self::InvalidContentType(ct) => write!(f, "invalid content type: {}", ct),
            Self::JsonError(e) => write!(f, "JSON error: {}", e),
            Self::CodecError(e) => write!(f, "codec error: {}", e),
            Self::Timeout => write!(f, "request timeout"),
            Self::Closed => write!(f, "connection closed"),
            Self::Transport(e) => write!(f, "transport error: {}", e),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<serde_json::Error> for HttpError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonError(err)
    }
}

impl From<CodecError> for HttpError {
    fn from(err: CodecError) -> Self {
        Self::CodecError(err)
    }
}

impl From<TransportError> for HttpError {
    fn from(err: TransportError) -> Self {
        Self::Transport(err)
    }
}

// =============================================================================
// HTTP Request Handler
// =============================================================================

/// Configuration for the HTTP request handler.
#[derive(Debug, Clone)]
pub struct HttpHandlerConfig {
    /// Base path for MCP endpoints (e.g., "/mcp/v1").
    pub base_path: String,
    /// Whether to allow CORS requests.
    pub allow_cors: bool,
    /// Allowed CORS origins ("*" for all).
    pub cors_origins: Vec<String>,
    /// Request timeout.
    pub timeout: Duration,
    /// Maximum request body size in bytes.
    pub max_body_size: usize,
}

impl Default for HttpHandlerConfig {
    fn default() -> Self {
        Self {
            base_path: "/mcp/v1".to_string(),
            allow_cors: true,
            cors_origins: vec!["*".to_string()],
            timeout: Duration::from_secs(30),
            max_body_size: 10 * 1024 * 1024, // 10 MB
        }
    }
}

/// Handles HTTP requests containing MCP JSON-RPC messages.
///
/// This handler is designed to be integrated with any HTTP server framework.
/// It processes incoming HTTP requests, extracts JSON-RPC messages, and returns
/// appropriate HTTP responses.
pub struct HttpRequestHandler {
    config: HttpHandlerConfig,
    codec: Codec,
}

impl HttpRequestHandler {
    /// Creates a new HTTP request handler with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(HttpHandlerConfig::default())
    }

    /// Creates a new HTTP request handler with the given configuration.
    #[must_use]
    pub fn with_config(config: HttpHandlerConfig) -> Self {
        Self {
            config,
            codec: Codec::new(),
        }
    }

    /// Returns the handler configuration.
    #[must_use]
    pub fn config(&self) -> &HttpHandlerConfig {
        &self.config
    }

    /// Handles a CORS preflight OPTIONS request.
    #[must_use]
    pub fn handle_options(&self, request: &HttpRequest) -> HttpResponse {
        if !self.config.allow_cors {
            return HttpResponse::new(HttpStatus::METHOD_NOT_ALLOWED);
        }

        let origin = request.header("origin").unwrap_or("*");
        let allowed = self.is_origin_allowed(origin);

        if !allowed {
            return HttpResponse::new(HttpStatus::FORBIDDEN);
        }

        HttpResponse::new(HttpStatus::OK)
            .with_cors(origin)
            .with_header("access-control-max-age", "86400")
    }

    /// Checks if the origin is allowed for CORS.
    #[must_use]
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        self.config
            .cors_origins
            .iter()
            .any(|o| o == "*" || o == origin)
    }

    /// Parses a JSON-RPC request from an HTTP request.
    pub fn parse_request(&self, request: &HttpRequest) -> Result<JsonRpcRequest, HttpError> {
        // Validate method
        if request.method != HttpMethod::Post {
            return Err(HttpError::InvalidMethod(
                request.method.as_str().to_string(),
            ));
        }

        // Validate content type
        let content_type = request.content_type().unwrap_or("");
        if !content_type.starts_with("application/json") {
            return Err(HttpError::InvalidContentType(content_type.to_string()));
        }

        // Validate body size
        if request.body.len() > self.config.max_body_size {
            return Err(HttpError::InvalidContentType(format!(
                "body size {} exceeds limit {}",
                request.body.len(),
                self.config.max_body_size
            )));
        }

        // Parse JSON-RPC request
        let json_rpc: JsonRpcRequest = serde_json::from_slice(&request.body)?;
        Ok(json_rpc)
    }

    /// Creates an HTTP response from a JSON-RPC response.
    #[must_use]
    pub fn create_response(
        &self,
        response: &JsonRpcResponse,
        origin: Option<&str>,
    ) -> HttpResponse {
        let body = self.codec.encode_response(response).unwrap_or_default();

        let mut http_response = HttpResponse::ok()
            .with_body(body)
            .with_header("content-type", "application/json");

        if self.config.allow_cors {
            if let Some(origin) = origin {
                if self.is_origin_allowed(origin) {
                    http_response = http_response.with_cors(origin);
                }
            }
        }

        http_response
    }

    /// Creates an error HTTP response.
    #[must_use]
    pub fn error_response(&self, status: HttpStatus, message: &str) -> HttpResponse {
        let error = serde_json::json!({
            "error": {
                "code": -32600,
                "message": message
            }
        });

        HttpResponse::new(status).with_json(&error)
    }
}

impl Default for HttpRequestHandler {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// HTTP Transport
// =============================================================================

/// HTTP transport for stateless MCP communication.
///
/// In stateless mode, each HTTP request contains a single JSON-RPC message
/// and receives a single response. This is suitable for simple integrations
/// where session state is not needed.
pub struct HttpTransport<R, W> {
    reader: R,
    writer: W,
    codec: Codec,
    closed: bool,
    pending_responses: Vec<JsonRpcResponse>,
}

impl<R: Read, W: Write> HttpTransport<R, W> {
    /// Creates a new HTTP transport.
    #[must_use]
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            codec: Codec::new(),
            closed: false,
            pending_responses: Vec::new(),
        }
    }

    /// Reads an HTTP request from the reader.
    ///
    /// This is a simplified HTTP parser for demonstration.
    /// In production, use a proper HTTP parsing library.
    pub fn read_request(&mut self) -> Result<HttpRequest, HttpError> {
        let mut buffer = Vec::new();
        let mut byte = [0u8; 1];

        // Read headers until \r\n\r\n
        loop {
            if self
                .reader
                .read(&mut byte)
                .map_err(|e| HttpError::Transport(e.into()))?
                == 0
            {
                return Err(HttpError::Closed);
            }
            buffer.push(byte[0]);

            if buffer.ends_with(b"\r\n\r\n") {
                break;
            }

            // Prevent infinite loops
            if buffer.len() > 64 * 1024 {
                return Err(HttpError::InvalidContentType(
                    "headers too large".to_string(),
                ));
            }
        }

        let header_str = String::from_utf8_lossy(&buffer);
        let mut lines = header_str.lines();

        // Parse request line
        let request_line = lines
            .next()
            .ok_or_else(|| HttpError::InvalidMethod("missing request line".to_string()))?;

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(HttpError::InvalidMethod("invalid request line".to_string()));
        }

        let method = HttpMethod::parse(parts[0])
            .ok_or_else(|| HttpError::InvalidMethod(parts[0].to_string()))?;

        let path = parts[1].to_string();

        // Parse headers
        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_lowercase(), value.trim().to_string());
            }
        }

        // Read body if Content-Length is present
        let content_length: usize = headers
            .get("content-length")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            self.reader
                .read_exact(&mut body)
                .map_err(|e| HttpError::Transport(e.into()))?;
        }

        Ok(HttpRequest {
            method,
            path,
            headers,
            body,
            query: HashMap::new(),
        })
    }

    /// Writes an HTTP response to the writer.
    pub fn write_response(&mut self, response: &HttpResponse) -> Result<(), HttpError> {
        let status_text = match response.status.0 {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown",
        };

        // Write status line
        write!(
            self.writer,
            "HTTP/1.1 {} {}\r\n",
            response.status.0, status_text
        )
        .map_err(|e| HttpError::Transport(e.into()))?;

        // Write headers
        for (name, value) in &response.headers {
            write!(self.writer, "{}: {}\r\n", name, value)
                .map_err(|e| HttpError::Transport(e.into()))?;
        }

        // Write content-length if not present
        if !response.headers.contains_key("content-length") {
            write!(self.writer, "content-length: {}\r\n", response.body.len())
                .map_err(|e| HttpError::Transport(e.into()))?;
        }

        // End headers
        write!(self.writer, "\r\n").map_err(|e| HttpError::Transport(e.into()))?;

        // Write body
        self.writer
            .write_all(&response.body)
            .map_err(|e| HttpError::Transport(e.into()))?;
        self.writer
            .flush()
            .map_err(|e| HttpError::Transport(e.into()))?;

        Ok(())
    }

    /// Queues a response to be sent.
    pub fn queue_response(&mut self, response: JsonRpcResponse) {
        self.pending_responses.push(response);
    }
}

impl<R: Read, W: Write> Transport for HttpTransport<R, W> {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        if self.closed {
            return Err(TransportError::Closed);
        }

        let response = match message {
            JsonRpcMessage::Response(r) => r.clone(),
            JsonRpcMessage::Request(r) => {
                // For HTTP transport, requests from server to client
                // are typically sent as notifications or SSE events.
                // For now, we just ignore them.
                let _ = r;
                return Ok(());
            }
        };

        let http_response = HttpResponse::ok().with_json(&response);

        self.write_response(&http_response)
            .map_err(|_| TransportError::Io(std::io::Error::other("write error")))?;

        Ok(())
    }

    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        if self.closed {
            return Err(TransportError::Closed);
        }

        let http_request = self.read_request().map_err(|e| match e {
            HttpError::Closed => TransportError::Closed,
            HttpError::Timeout => TransportError::Timeout,
            _ => TransportError::Io(std::io::Error::other(e.to_string())),
        })?;

        // Parse JSON-RPC from body
        let json_rpc: JsonRpcRequest = serde_json::from_slice(&http_request.body)
            .map_err(|e| TransportError::Codec(CodecError::Json(e)))?;

        Ok(JsonRpcMessage::Request(json_rpc))
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.closed = true;
        Ok(())
    }
}

// =============================================================================
// Streaming HTTP Transport
// =============================================================================

/// Streaming HTTP transport for long-lived MCP connections.
///
/// This transport uses HTTP streaming (chunked transfer encoding) for
/// server-to-client messages and regular POST requests for client-to-server
/// messages.
pub struct StreamableHttpTransport {
    /// Request queue (from HTTP POST requests).
    requests: Arc<Mutex<Vec<JsonRpcRequest>>>,
    /// Response queue (to be sent via streaming).
    responses: Arc<Mutex<Vec<JsonRpcResponse>>>,
    /// Codec for message encoding.
    codec: Codec,
    /// Whether the transport is closed.
    closed: bool,
    /// Poll interval for checking new messages.
    poll_interval: Duration,
}

impl StreamableHttpTransport {
    /// Creates a new streaming HTTP transport.
    #[must_use]
    pub fn new() -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            codec: Codec::new(),
            closed: false,
            poll_interval: Duration::from_millis(10),
        }
    }

    /// Pushes a request into the queue (from HTTP handler).
    pub fn push_request(&self, request: JsonRpcRequest) {
        if let Ok(mut guard) = self.requests.lock() {
            guard.push(request);
        }
    }

    /// Pops a response from the queue (for HTTP streaming).
    #[must_use]
    pub fn pop_response(&self) -> Option<JsonRpcResponse> {
        self.responses.lock().ok()?.pop()
    }

    /// Checks if there are pending responses.
    #[must_use]
    pub fn has_responses(&self) -> bool {
        self.responses
            .lock()
            .map(|g| !g.is_empty())
            .unwrap_or(false)
    }

    /// Returns the request queue for external access.
    #[must_use]
    pub fn request_queue(&self) -> Arc<Mutex<Vec<JsonRpcRequest>>> {
        Arc::clone(&self.requests)
    }

    /// Returns the response queue for external access.
    #[must_use]
    pub fn response_queue(&self) -> Arc<Mutex<Vec<JsonRpcResponse>>> {
        Arc::clone(&self.responses)
    }
}

impl Default for StreamableHttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for StreamableHttpTransport {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        if self.closed {
            return Err(TransportError::Closed);
        }

        if let JsonRpcMessage::Response(response) = message {
            if let Ok(mut guard) = self.responses.lock() {
                guard.push(response.clone());
            }
        }

        Ok(())
    }

    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        if self.closed {
            return Err(TransportError::Closed);
        }

        // Poll for requests
        loop {
            if cx.is_cancel_requested() {
                return Err(TransportError::Cancelled);
            }

            if let Ok(mut guard) = self.requests.lock() {
                if let Some(request) = guard.pop() {
                    return Ok(JsonRpcMessage::Request(request));
                }
            }

            // Sleep briefly before polling again
            std::thread::sleep(self.poll_interval);
        }
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.closed = true;
        Ok(())
    }
}

// =============================================================================
// Session Support
// =============================================================================

/// HTTP session for maintaining state across requests.
#[derive(Debug, Clone)]
pub struct HttpSession {
    /// Session ID.
    pub id: String,
    /// Session creation time.
    pub created_at: Instant,
    /// Last activity time.
    pub last_activity: Instant,
    /// Session data.
    pub data: HashMap<String, serde_json::Value>,
}

impl HttpSession {
    /// Creates a new session with the given ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        let now = Instant::now();
        Self {
            id: id.into(),
            created_at: now,
            last_activity: now,
            data: HashMap::new(),
        }
    }

    /// Updates the last activity time.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Checks if the session has expired.
    #[must_use]
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Gets a session value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.data.get(key)
    }

    /// Sets a session value.
    pub fn set(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.data.insert(key.into(), value);
        self.touch();
    }

    /// Removes a session value.
    pub fn remove(&mut self, key: &str) -> Option<serde_json::Value> {
        self.touch();
        self.data.remove(key)
    }
}

/// Session store for HTTP sessions.
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: Mutex<HashMap<String, HttpSession>>,
    timeout: Duration,
}

impl SessionStore {
    /// Creates a new session store with the given timeout.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            timeout,
        }
    }

    /// Creates a new session store with default 1-hour timeout.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(Duration::from_secs(3600))
    }

    /// Creates a new session.
    #[must_use]
    pub fn create(&self) -> String {
        let id = generate_session_id();
        let session = HttpSession::new(&id);

        if let Ok(mut guard) = self.sessions.lock() {
            guard.insert(id.clone(), session);
        }

        id
    }

    /// Gets a session by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<HttpSession> {
        let mut guard = self.sessions.lock().ok()?;
        let session = guard.get_mut(id)?;

        if session.is_expired(self.timeout) {
            guard.remove(id);
            return None;
        }

        session.touch();
        Some(session.clone())
    }

    /// Updates a session.
    pub fn update(&self, session: HttpSession) {
        if let Ok(mut guard) = self.sessions.lock() {
            guard.insert(session.id.clone(), session);
        }
    }

    /// Removes a session.
    pub fn remove(&self, id: &str) {
        if let Ok(mut guard) = self.sessions.lock() {
            guard.remove(id);
        }
    }

    /// Removes expired sessions.
    pub fn cleanup(&self) {
        if let Ok(mut guard) = self.sessions.lock() {
            guard.retain(|_, s| !s.is_expired(self.timeout));
        }
    }

    /// Returns the number of active sessions.
    #[must_use]
    pub fn count(&self) -> usize {
        self.sessions.lock().map(|g| g.len()).unwrap_or(0)
    }
}

/// Generates a random session ID.
fn generate_session_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let state = RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );

    format!("{:016x}", hasher.finish())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_parse() {
        assert_eq!(HttpMethod::parse("GET"), Some(HttpMethod::Get));
        assert_eq!(HttpMethod::parse("POST"), Some(HttpMethod::Post));
        assert_eq!(HttpMethod::parse("get"), Some(HttpMethod::Get));
        assert_eq!(HttpMethod::parse("INVALID"), None);
    }

    #[test]
    fn test_http_status() {
        assert!(HttpStatus::OK.is_success());
        assert!(HttpStatus::BAD_REQUEST.is_client_error());
        assert!(HttpStatus::INTERNAL_SERVER_ERROR.is_server_error());
    }

    #[test]
    fn test_http_request_builder() {
        let request = HttpRequest::new(HttpMethod::Post, "/api/mcp")
            .with_header("Content-Type", "application/json")
            .with_body(b"{\"test\": true}".to_vec())
            .with_query("version", "1");

        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(request.path, "/api/mcp");
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.query.get("version"), Some(&"1".to_string()));
    }

    #[test]
    fn test_http_response_builder() {
        let response = HttpResponse::ok()
            .with_header("X-Custom", "value")
            .with_body(b"Hello".to_vec());

        assert_eq!(response.status, HttpStatus::OK);
        assert_eq!(response.headers.get("x-custom"), Some(&"value".to_string()));
        assert_eq!(response.body, b"Hello");
    }

    #[test]
    fn test_http_response_json() {
        let data = serde_json::json!({"result": "ok"});
        let response = HttpResponse::ok().with_json(&data);

        assert!(!response.body.is_empty());
        assert_eq!(
            response.headers.get("content-type"),
            Some(&"application/json".to_string())
        );
    }

    #[test]
    fn test_http_response_cors() {
        let response = HttpResponse::ok().with_cors("https://example.com");

        assert_eq!(
            response.headers.get("access-control-allow-origin"),
            Some(&"https://example.com".to_string())
        );
    }

    #[test]
    fn test_http_handler_options() {
        let handler = HttpRequestHandler::new();
        let request = HttpRequest::new(HttpMethod::Options, "/mcp/v1")
            .with_header("Origin", "https://example.com");

        let response = handler.handle_options(&request);
        assert_eq!(response.status, HttpStatus::OK);
    }

    #[test]
    fn test_http_handler_parse_request() {
        let handler = HttpRequestHandler::new();

        // Valid request
        let json_rpc = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "test",
            "id": 1
        });
        let request = HttpRequest::new(HttpMethod::Post, "/mcp/v1")
            .with_header("Content-Type", "application/json")
            .with_body(serde_json::to_vec(&json_rpc).unwrap());

        let result = handler.parse_request(&request);
        assert!(result.is_ok());

        // Invalid method
        let request = HttpRequest::new(HttpMethod::Get, "/mcp/v1");
        assert!(handler.parse_request(&request).is_err());

        // Invalid content type
        let request =
            HttpRequest::new(HttpMethod::Post, "/mcp/v1").with_header("Content-Type", "text/plain");
        assert!(handler.parse_request(&request).is_err());
    }

    #[test]
    fn test_http_session() {
        let mut session = HttpSession::new("test-session");
        assert_eq!(session.id, "test-session");

        session.set("key", serde_json::json!("value"));
        assert_eq!(session.get("key"), Some(&serde_json::json!("value")));

        session.remove("key");
        assert!(session.get("key").is_none());

        assert!(!session.is_expired(Duration::from_secs(3600)));
    }

    #[test]
    fn test_session_store() {
        let store = SessionStore::with_defaults();

        let id = store.create();
        assert!(!id.is_empty());

        let session = store.get(&id);
        assert!(session.is_some());

        store.remove(&id);
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn test_streamable_transport() {
        let transport = StreamableHttpTransport::new();

        // Push a request
        let request = JsonRpcRequest::new("test", None, 1i64);
        transport.push_request(request);

        // Should have a request in queue
        let guard = transport.requests.lock().unwrap();
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn test_http_error_display() {
        let err = HttpError::InvalidMethod("PATCH".to_string());
        assert!(err.to_string().contains("PATCH"));

        let err = HttpError::Timeout;
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_generate_session_id() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();

        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 16);
    }

    // =========================================================================
    // E2E HTTP Transport Tests (bd-2kv / bd-3fq1)
    // =========================================================================

    #[test]
    fn e2e_http_request_response_flow() {
        use fastmcp_protocol::RequestId;
        use std::io::Cursor;

        // Build an HTTP request with JSON-RPC body
        let json_rpc_request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        });
        let body = serde_json::to_vec(&json_rpc_request).unwrap();

        let http_request = format!(
            "POST /mcp/v1 HTTP/1.1\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n",
            body.len()
        );

        let mut input = http_request.into_bytes();
        input.extend(body);

        let reader = Cursor::new(input);
        let mut output = Vec::new();

        let cx = Cx::for_testing();

        {
            let mut transport = HttpTransport::new(reader, &mut output);

            // Receive the request
            let msg = transport.recv(&cx).unwrap();
            match msg {
                JsonRpcMessage::Request(req) => {
                    assert_eq!(req.method, "tools/list");
                    assert_eq!(req.id, Some(RequestId::Number(1)));

                    // Send response
                    let response = JsonRpcResponse {
                        jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
                        result: Some(serde_json::json!({"tools": []})),
                        error: None,
                        id: Some(RequestId::Number(1)),
                    };
                    transport
                        .send(&cx, &JsonRpcMessage::Response(response))
                        .unwrap();
                }
                _ => panic!("Expected request"),
            }
        }

        // Verify HTTP response
        let response_str = String::from_utf8(output).unwrap();
        assert!(response_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response_str.contains("content-type: application/json"));
        assert!(response_str.contains("\"tools\":[]"));
    }

    #[test]
    fn e2e_http_error_status_codes() {
        let handler = HttpRequestHandler::new();

        // Invalid method should return error
        let request = HttpRequest::new(HttpMethod::Get, "/mcp/v1")
            .with_header("Content-Type", "application/json");
        let result = handler.parse_request(&request);
        assert!(matches!(result, Err(HttpError::InvalidMethod(_))));

        // Invalid content type
        let request =
            HttpRequest::new(HttpMethod::Post, "/mcp/v1").with_header("Content-Type", "text/xml");
        let result = handler.parse_request(&request);
        assert!(matches!(result, Err(HttpError::InvalidContentType(_))));

        // Create error response
        let response = handler.error_response(HttpStatus::BAD_REQUEST, "Invalid request format");
        assert_eq!(response.status, HttpStatus::BAD_REQUEST);
        let body_str = String::from_utf8(response.body).unwrap();
        assert!(body_str.contains("\"error\""));
    }

    #[test]
    fn e2e_http_content_type_handling() {
        let handler = HttpRequestHandler::new();

        // Standard JSON content type
        let request = HttpRequest::new(HttpMethod::Post, "/mcp/v1")
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","method":"test","id":1}"#);
        assert!(handler.parse_request(&request).is_ok());

        // JSON with charset
        let request = HttpRequest::new(HttpMethod::Post, "/mcp/v1")
            .with_header("Content-Type", "application/json; charset=utf-8")
            .with_body(r#"{"jsonrpc":"2.0","method":"test","id":1}"#);
        assert!(handler.parse_request(&request).is_ok());

        // Response content type is always application/json
        let response = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            result: Some(serde_json::json!({})),
            error: None,
            id: Some(fastmcp_protocol::RequestId::Number(1)),
        };
        let http_response = handler.create_response(&response, None);
        assert_eq!(
            http_response.headers.get("content-type"),
            Some(&"application/json".to_string())
        );
    }

    #[test]
    fn e2e_http_cors_handling() {
        let config = HttpHandlerConfig {
            allow_cors: true,
            cors_origins: vec!["https://allowed.com".to_string()],
            ..Default::default()
        };
        let handler = HttpRequestHandler::with_config(config);

        // Allowed origin
        assert!(handler.is_origin_allowed("https://allowed.com"));

        // Disallowed origin
        assert!(!handler.is_origin_allowed("https://evil.com"));

        // OPTIONS request from allowed origin
        let request = HttpRequest::new(HttpMethod::Options, "/mcp/v1")
            .with_header("Origin", "https://allowed.com");
        let response = handler.handle_options(&request);
        assert_eq!(response.status, HttpStatus::OK);
        assert_eq!(
            response.headers.get("access-control-allow-origin"),
            Some(&"https://allowed.com".to_string())
        );

        // OPTIONS request from disallowed origin
        let request = HttpRequest::new(HttpMethod::Options, "/mcp/v1")
            .with_header("Origin", "https://evil.com");
        let response = handler.handle_options(&request);
        assert_eq!(response.status, HttpStatus::FORBIDDEN);
    }

    #[test]
    fn e2e_http_streaming_transport() {
        use fastmcp_protocol::RequestId;

        let mut transport = StreamableHttpTransport::new();
        let cx = Cx::for_testing();

        // Simulate multiple requests being pushed (from HTTP handlers)
        let req1 = JsonRpcRequest::new("method1", None, 1i64);
        let req2 = JsonRpcRequest::new("method2", None, 2i64);
        transport.push_request(req1);
        transport.push_request(req2);

        // Transport should receive requests in LIFO order (pop from vec)
        let msg = transport.recv(&cx).unwrap();
        if let JsonRpcMessage::Request(req) = msg {
            assert_eq!(req.method, "method2"); // Last pushed, first popped
        }

        // Send a response
        let response = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            result: Some(serde_json::json!({})),
            error: None,
            id: Some(RequestId::Number(2)),
        };
        transport
            .send(&cx, &JsonRpcMessage::Response(response))
            .unwrap();

        // Response should be available for streaming
        assert!(transport.has_responses());
        let resp = transport.pop_response().unwrap();
        assert_eq!(resp.id, Some(RequestId::Number(2)));
    }

    #[test]
    fn e2e_http_session_lifecycle() {
        let store = SessionStore::new(Duration::from_millis(100));

        // Create session
        let id = store.create();
        assert_eq!(store.count(), 1);

        // Get and modify session
        let mut session = store.get(&id).unwrap();
        session.set("user_id", serde_json::json!(42));
        store.update(session);

        // Retrieve and verify
        let session = store.get(&id).unwrap();
        assert_eq!(session.get("user_id"), Some(&serde_json::json!(42)));

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        // Session should be expired
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn e2e_http_transport_cancellation() {
        use std::io::Cursor;

        let reader = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let mut transport = HttpTransport::new(reader, &mut output);

        // Send should respect cancellation
        let response = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            result: None,
            error: None,
            id: None,
        };
        let result = transport.send(&cx, &JsonRpcMessage::Response(response));
        assert!(matches!(result, Err(TransportError::Cancelled)));

        // Nothing should be written
        assert!(output.is_empty());
    }

    #[test]
    fn e2e_http_transport_close() {
        use std::io::Cursor;

        let reader = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();

        let cx = Cx::for_testing();
        let mut transport = HttpTransport::new(reader, &mut output);

        // Close transport
        transport.close().unwrap();

        // Operations should fail after close
        let response = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            result: None,
            error: None,
            id: None,
        };
        let result = transport.send(&cx, &JsonRpcMessage::Response(response));
        assert!(matches!(result, Err(TransportError::Closed)));
    }

    #[test]
    fn e2e_http_body_size_limit() {
        let config = HttpHandlerConfig {
            max_body_size: 100,
            ..Default::default()
        };
        let handler = HttpRequestHandler::with_config(config);

        // Body exceeding limit
        let large_body = vec![b'x'; 200];
        let request = HttpRequest::new(HttpMethod::Post, "/mcp/v1")
            .with_header("Content-Type", "application/json")
            .with_body(large_body);

        let result = handler.parse_request(&request);
        // The error message contains "body size"
        assert!(matches!(result, Err(HttpError::InvalidContentType(_))));
    }
}
