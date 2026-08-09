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

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{
    Arc, Mutex, TryLockError,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use asupersync::{Cx, channel::mpsc};
use fastmcp_core::{McpRequestCancellation, draw_security_identifier};
use fastmcp_protocol::protocol_version::{
    FinalHttpRequestMetadata, RequestAdmissionError, RequestVersionMetadata,
    admit_final_http_request,
};
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId};

use crate::sse::{
    ModernSseDecoder, ModernSseEndOfStream, ModernSseLimits, ModernSseParseError,
    ModernSsePushError, SseEvent,
};
use crate::{Codec, CodecError, Transport, TransportError};

/// Result of consuming one finite modern HTTP SSE response body.
///
/// The collector binds every terminal JSON-RPC response to one outgoing
/// request ID. Server notifications are passed to the supplied callback in
/// wire order before the terminal response is returned at EOF.
#[derive(Debug)]
pub struct ModernHttpSseCollector {
    request_id: RequestId,
    decoder: Option<ModernSseDecoder>,
    codec: Codec,
    terminal: Option<JsonRpcResponse>,
}

/// Errors while collecting one request-scoped modern HTTP SSE response body.
#[derive(Debug)]
pub enum ModernHttpSseCollectorError {
    /// The request ID cannot be used as a JSON-RPC correlation key.
    InvalidRequestId,
    /// Caller cancellation stopped collection before a terminal response.
    Cancelled,
    /// Bounded SSE framing refused the response body.
    Sse(ModernSseParseError),
    /// A completed SSE payload was not one valid bounded JSON-RPC message.
    Codec(CodecError),
    /// The transport context expired while consuming the response body.
    Transport(TransportError),
    /// Notification delivery returned an application transport error.
    NotificationDelivery(TransportError),
    /// A server-to-client request carried an ID and is therefore not a notification.
    NonNotificationRequest {
        /// The request ID unexpectedly carried by the server message.
        request_id: RequestId,
    },
    /// A terminal response belongs to a request other than this SSE body.
    TerminalResponseIdMismatch {
        /// The outgoing request ID bound to this body.
        expected: RequestId,
        /// The response ID observed on the body, including absent IDs.
        actual: Option<RequestId>,
    },
    /// A second terminal response arrived after the body's first terminal response.
    DuplicateTerminalResponse {
        /// The request ID bound to this body.
        request_id: RequestId,
    },
    /// A notification arrived after this finite response had terminated.
    NotificationAfterTerminal {
        /// The request ID bound to this body.
        request_id: RequestId,
    },
    /// The HTTP body ended before a correlated terminal response.
    EndOfStream {
        /// Exact incomplete SSE framing discarded at EOF.
        framing: ModernSseEndOfStream,
    },
    /// The response body was already finished or refused.
    Closed,
}

impl std::fmt::Display for ModernHttpSseCollectorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequestId => {
                formatter.write_str("modern HTTP SSE collector has invalid request ID")
            }
            Self::Cancelled => formatter.write_str("modern HTTP SSE collection was cancelled"),
            Self::Sse(error) => error.fmt(formatter),
            Self::Codec(error) => error.fmt(formatter),
            Self::Transport(error) => error.fmt(formatter),
            Self::NotificationDelivery(error) => error.fmt(formatter),
            Self::NonNotificationRequest { request_id } => write!(
                formatter,
                "modern HTTP SSE server request {request_id:?} is not a notification"
            ),
            Self::TerminalResponseIdMismatch { expected, actual } => write!(
                formatter,
                "modern HTTP SSE response ID {actual:?} does not match request {expected:?}"
            ),
            Self::DuplicateTerminalResponse { request_id } => write!(
                formatter,
                "modern HTTP SSE body for request {request_id:?} emitted a duplicate terminal response"
            ),
            Self::NotificationAfterTerminal { request_id } => write!(
                formatter,
                "modern HTTP SSE body for request {request_id:?} emitted a notification after its terminal response"
            ),
            Self::EndOfStream { .. } => formatter
                .write_str("modern HTTP SSE body ended before its correlated terminal response"),
            Self::Closed => formatter.write_str("modern HTTP SSE collector is closed"),
        }
    }
}

impl std::error::Error for ModernHttpSseCollectorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sse(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::NotificationDelivery(error) => Some(error),
            Self::InvalidRequestId
            | Self::Cancelled
            | Self::NonNotificationRequest { .. }
            | Self::TerminalResponseIdMismatch { .. }
            | Self::DuplicateTerminalResponse { .. }
            | Self::NotificationAfterTerminal { .. }
            | Self::EndOfStream { .. }
            | Self::Closed => None,
        }
    }
}

impl ModernHttpSseCollector {
    /// Creates a bounded collector for exactly one outgoing request.
    ///
    /// The decoder uses WHATWG SSE framing in replacement mode and the
    /// existing strict transport codec for each completed JSON-RPC payload.
    pub fn new(
        request_id: RequestId,
        limits: ModernSseLimits,
    ) -> Result<Self, ModernHttpSseCollectorError> {
        if request_id.validate().is_err() {
            return Err(ModernHttpSseCollectorError::InvalidRequestId);
        }
        let mut codec = Codec::new();
        codec.set_max_message_size(limits.max_event_bytes());
        Ok(Self {
            request_id,
            decoder: Some(ModernSseDecoder::new(limits)),
            codec,
            terminal: None,
        })
    }

    /// Incrementally consumes an HTTP response-body chunk.
    ///
    /// Each server notification is delivered immediately in wire order. A
    /// response is retained only if its ID exactly matches this collector's
    /// request ID. Continue feeding chunks through EOF so duplicate terminals
    /// cannot be hidden after an otherwise valid first response.
    pub fn push(
        &mut self,
        cx: &Cx,
        chunk: &[u8],
        mut deliver_notification: impl FnMut(JsonRpcRequest) -> Result<(), TransportError>,
    ) -> Result<(), ModernHttpSseCollectorError> {
        if let Err(error) = Self::checkpoint(cx) {
            return Err(self.refuse(error));
        }

        let request_id = self.request_id.clone();
        let result = {
            let decoder = self
                .decoder
                .as_mut()
                .ok_or(ModernHttpSseCollectorError::Closed)?;
            let codec = &mut self.codec;
            let terminal = &mut self.terminal;
            decoder.push_with(chunk, |event| {
                Self::checkpoint(cx)?;
                let message = codec
                    .decode_complete_message(event.as_bytes())
                    .map_err(ModernHttpSseCollectorError::Codec)?;
                match message {
                    JsonRpcMessage::Request(notification) => {
                        if terminal.is_some() {
                            return Err(ModernHttpSseCollectorError::NotificationAfterTerminal {
                                request_id: request_id.clone(),
                            });
                        }
                        if let Some(request_id) = notification.id.clone() {
                            return Err(ModernHttpSseCollectorError::NonNotificationRequest {
                                request_id,
                            });
                        }
                        deliver_notification(notification)
                            .map_err(ModernHttpSseCollectorError::NotificationDelivery)
                    }
                    JsonRpcMessage::Response(response) => {
                        if terminal.is_some() {
                            return Err(ModernHttpSseCollectorError::DuplicateTerminalResponse {
                                request_id: request_id.clone(),
                            });
                        }
                        if response.id.as_ref() != Some(&request_id) {
                            return Err(ModernHttpSseCollectorError::TerminalResponseIdMismatch {
                                expected: request_id.clone(),
                                actual: response.id,
                            });
                        }
                        *terminal = Some(response);
                        Ok(())
                    }
                }
            })
        };
        match result {
            Ok(()) => {}
            Err(ModernSsePushError::Parse(error)) => {
                return Err(self.refuse(ModernHttpSseCollectorError::Sse(error)));
            }
            Err(ModernSsePushError::Consumer(error)) => return Err(self.refuse(error)),
        }

        if let Err(error) = Self::checkpoint(cx) {
            return Err(self.refuse(error));
        }
        Ok(())
    }

    /// Ends the finite HTTP body and returns its one correlated terminal response.
    ///
    /// EOF without a terminal response is an error even if the SSE framing was
    /// otherwise clean. An unfinished final SSE event is reported in the EOF
    /// error instead of being synthesized into a JSON-RPC message.
    pub fn finish(&mut self, cx: &Cx) -> Result<JsonRpcResponse, ModernHttpSseCollectorError> {
        if let Err(error) = Self::checkpoint(cx) {
            return Err(self.refuse(error));
        }
        let decoder = self
            .decoder
            .take()
            .ok_or(ModernHttpSseCollectorError::Closed)?;
        let framing = decoder.finish().map_err(ModernHttpSseCollectorError::Sse)?;
        if framing.discarded_pending_event || framing.discarded_partial_line {
            self.terminal = None;
            return Err(ModernHttpSseCollectorError::EndOfStream { framing });
        }
        self.terminal
            .take()
            .ok_or(ModernHttpSseCollectorError::EndOfStream { framing })
    }

    fn checkpoint(cx: &Cx) -> Result<(), ModernHttpSseCollectorError> {
        match http_checkpoint(cx) {
            Ok(()) => Ok(()),
            Err(TransportError::Cancelled) => Err(ModernHttpSseCollectorError::Cancelled),
            Err(error) => Err(ModernHttpSseCollectorError::Transport(error)),
        }
    }

    fn refuse(&mut self, error: ModernHttpSseCollectorError) -> ModernHttpSseCollectorError {
        self.decoder = None;
        self.terminal = None;
        error
    }
}

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
    pub const NOT_ACCEPTABLE: Self = Self(406);
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
#[derive(Clone)]
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

impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path_bytes", &self.path.len())
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .field("query_parameter_count", &self.query.len())
            .finish()
    }
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
        self.headers.iter().find_map(|(header_name, value)| {
            header_name
                .eq_ignore_ascii_case(name)
                .then_some(value.as_str())
        })
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

/// Concrete HTTP POST sink for the exact MCP 2024-11-05 SSE endpoint event.
///
/// This narrow adapter opens one plain-HTTP connection to the URI advertised
/// by the legacy SSE stream and writes one JSON-RPC message POST. It never
/// derives a `/sse` or `/messages` route and never adds modern session headers.
/// TLS, credential, redirect, and origin policy are intentionally owned by the
/// corresponding security and adapter layers rather than this transport slice.
#[derive(Debug, Default)]
pub struct LegacySseHttpPostSink;

impl LegacySseHttpPostSink {
    /// Creates a concrete legacy SSE message-POST sink.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl crate::sse::LegacySsePostSink for LegacySseHttpPostSink {
    fn post(
        &mut self,
        cx: &Cx,
        post: crate::sse::LegacySseMessagePost,
    ) -> Result<(), TransportError> {
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }
        let (authority, target) = legacy_sse_http_post_target(post.endpoint())?;
        let mut stream = TcpStream::connect(authority).map_err(TransportError::Io)?;
        let request = format!(
            "POST {target} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            post.body().len(),
        );
        stream
            .write_all(request.as_bytes())
            .map_err(TransportError::Io)?;
        stream.write_all(post.body()).map_err(TransportError::Io)?;
        stream.flush().map_err(TransportError::Io)?;
        stream.shutdown(Shutdown::Write).map_err(TransportError::Io)
    }
}

fn legacy_sse_http_post_target(endpoint: &str) -> Result<(&str, &str), TransportError> {
    let authority_and_target = endpoint.strip_prefix("http://").ok_or_else(|| {
        TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "legacy SSE advertised endpoint must be an absolute HTTP URI",
        ))
    })?;
    if authority_and_target
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0'))
    {
        return Err(TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "legacy SSE advertised endpoint contains an invalid control byte",
        )));
    }
    let (authority, target) = authority_and_target
        .split_once('/')
        .map_or((authority_and_target, "/"), |(authority, _target)| {
            (authority, &authority_and_target[authority.len()..])
        });
    if authority.is_empty() {
        return Err(TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "legacy SSE advertised endpoint omits its authority",
        )));
    }
    Ok((authority, target))
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

const JSON_ENCODING_ERROR_BODY: &[u8] =
    br#"{"error":{"code":-32603,"message":"Failed to encode JSON response"}}"#;

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
    ///
    /// Serialization failures are converted into a deterministic 500 response
    /// with a nonempty JSON error body. Use [`Self::try_with_json`] when the
    /// caller needs the typed serialization error instead.
    #[must_use]
    pub fn with_json<T: serde::Serialize>(mut self, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => self.body = body,
            Err(_) => {
                self.status = HttpStatus::INTERNAL_SERVER_ERROR;
                self.body = JSON_ENCODING_ERROR_BODY.to_vec();
            }
        }
        self.headers
            .insert("content-type".to_string(), "application/json".to_string());
        self
    }

    /// Tries to set the body as JSON, preserving serialization failure as a
    /// typed [`HttpError`].
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::JsonError`] when `value` cannot be serialized.
    pub fn try_with_json<T: serde::Serialize>(mut self, value: &T) -> Result<Self, HttpError> {
        self.body = serde_json::to_vec(value)?;
        self.headers
            .insert("content-type".to_string(), "application/json".to_string());
        Ok(self)
    }

    /// Sets CORS headers for cross-origin requests.
    #[must_use]
    pub fn with_cors(mut self, origin: &str) -> Self {
        if !is_valid_http_header_value(origin) {
            return self;
        }
        self.headers.insert(
            "access-control-allow-origin".to_string(),
            origin.to_string(),
        );
        self.headers.insert(
            "access-control-allow-methods".to_string(),
            "POST, OPTIONS".to_string(),
        );
        self.headers.insert(
            "access-control-allow-headers".to_string(),
            "Content-Type, Authorization".to_string(),
        );
        self.headers.insert(
            "vary".to_string(),
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers".to_string(),
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
    /// Invalid HTTP request line.
    InvalidRequestLine(String),
    /// Invalid HTTP header syntax or framing.
    InvalidHeader(String),
    /// Invalid Content-Type.
    InvalidContentType(String),
    /// The request accepts neither modern JSON nor request-scoped SSE.
    NotAcceptable,
    /// The final MCP header/body admission boundary rejected the request.
    ProtocolAdmission(RequestAdmissionError),
    /// Request path does not match the configured MCP endpoint.
    InvalidPath(String),
    /// Request Origin is not admitted by the configured policy.
    OriginNotAllowed(String),
    /// HTTP headers exceeded the maximum allowed size.
    HeadersTooLarge { size: usize, max: usize },
    /// HTTP body exceeded the maximum allowed size.
    BodyTooLarge { size: usize, max: usize },
    /// Unsupported Transfer-Encoding.
    UnsupportedTransferEncoding(String),
    /// Unsupported request Content-Encoding.
    UnsupportedContentEncoding(String),
    /// JSON encoding or decoding error.
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
            Self::InvalidMethod(_) => write!(f, "invalid HTTP method"),
            Self::InvalidRequestLine(_) => write!(f, "invalid HTTP request line"),
            Self::InvalidHeader(_) => write!(f, "invalid HTTP header"),
            Self::InvalidContentType(_) => write!(f, "invalid content type"),
            Self::NotAcceptable => {
                write!(f, "no supported MCP response representation is acceptable")
            }
            Self::ProtocolAdmission(_) => write!(f, "final MCP request admission rejected"),
            Self::InvalidPath(_) => write!(f, "invalid MCP endpoint path"),
            Self::OriginNotAllowed(_) => write!(f, "origin is not allowed"),
            Self::HeadersTooLarge { size, max } => {
                write!(f, "headers too large: {size} > {max} bytes")
            }
            Self::BodyTooLarge { size, max } => write!(f, "body too large: {size} > {max} bytes"),
            Self::UnsupportedTransferEncoding(_) => write!(f, "unsupported transfer encoding"),
            Self::UnsupportedContentEncoding(_) => write!(f, "unsupported content encoding"),
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

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_valid_http_header_value(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte == b'\t' || byte >= b' ' && byte != 0x7f)
}

/// Validates requests assembled through the public `HttpRequest` fields.
///
/// The wire parser normalizes names while parsing, but framework integrations
/// commonly construct `HttpRequest` directly. HTTP field names remain
/// case-insensitive on that path, and two differently-cased map keys must not
/// be allowed to smuggle conflicting security-sensitive values.
fn validate_http_request_headers(request: &HttpRequest) -> Result<(), HttpError> {
    let mut normalized_names = HashSet::with_capacity(request.headers.len());
    for (name, value) in &request.headers {
        if !is_http_token(name) {
            return Err(HttpError::InvalidHeader(format!(
                "invalid request header name: {name}"
            )));
        }
        if !is_valid_http_header_value(value) {
            return Err(HttpError::InvalidHeader(format!(
                "invalid value for request header {name}"
            )));
        }

        let normalized_name = name.to_ascii_lowercase();
        if !normalized_names.insert(normalized_name.clone()) {
            return Err(HttpError::InvalidHeader(format!(
                "duplicate request header: {normalized_name}"
            )));
        }
    }
    Ok(())
}

fn validate_mcp_request_metadata(request: &HttpRequest) -> Result<(), HttpError> {
    if request.method != HttpMethod::Post {
        return Err(HttpError::InvalidMethod(
            request.method.as_str().to_string(),
        ));
    }

    let content_type = request.content_type().unwrap_or("");
    if !is_modern_json_content_type(content_type) {
        return Err(HttpError::InvalidContentType(content_type.to_string()));
    }
    if let Some(coding) = request.header("content-encoding")
        && !is_identity_content_coding(coding)
    {
        return Err(HttpError::UnsupportedContentEncoding(coding.to_string()));
    }
    Ok(())
}

/// Accepts exactly `application/json`, optionally with one single
/// `charset=utf-8` parameter, ASCII-case-insensitively. A different charset
/// or any other parameter must be refused before body admission rather than
/// silently decoded as UTF-8 anyway.
fn is_modern_json_content_type(value: &str) -> bool {
    let mut parts = value.split(';');
    let essence = parts.next().unwrap_or("").trim();
    if !essence.eq_ignore_ascii_case("application/json") {
        return false;
    }
    let Some(parameter) = parts.next() else {
        return true;
    };
    if parts.next().is_some() {
        return false;
    }
    let Some((name, charset)) = parameter.trim().split_once('=') else {
        return false;
    };
    name.trim().eq_ignore_ascii_case("charset") && charset.trim().eq_ignore_ascii_case("utf-8")
}

/// Maximum ignored empty RFC 9110 list elements in one request
/// `Content-Encoding` value; framing noise stays finite.
const MAX_IGNORED_REQUEST_CONTENT_ENCODING_EMPTY_ELEMENTS: usize = 16;

/// A present request `Content-Encoding` must reduce to exactly one semantic
/// `identity` token. Any compressed or unknown coding is a transport failure
/// with no JSON-RPC dispatch; without this check a coded body would reach
/// JSON admission and fail there with a misleading diagnostic.
fn is_identity_content_coding(value: &str) -> bool {
    let mut ignored_empty_elements = 0_usize;
    let mut semantic_codings = 0_usize;
    for element in value.split(',') {
        let element = element.trim_matches([' ', '\t']);
        if element.is_empty() {
            ignored_empty_elements += 1;
            if ignored_empty_elements > MAX_IGNORED_REQUEST_CONTENT_ENCODING_EMPTY_ELEMENTS {
                return false;
            }
            continue;
        }
        if !element.eq_ignore_ascii_case("identity") {
            return false;
        }
        semantic_codings += 1;
        if semantic_codings > 1 {
            return false;
        }
    }
    semantic_codings == 1
}

fn is_origin_allowed(config: &HttpHandlerConfig, origin: &str) -> bool {
    config.allow_cors
        && !origin.is_empty()
        && config.cors_origins.iter().any(|allowed| allowed == origin)
}

fn validate_mcp_request_policy(
    request: &HttpRequest,
    config: &HttpHandlerConfig,
) -> Result<(), HttpError> {
    validate_http_request_headers(request)?;
    if request.path != config.base_path {
        return Err(HttpError::InvalidPath(request.path.clone()));
    }
    if let Some(origin) = request.header("origin") {
        if !is_origin_allowed(config, origin) {
            return Err(HttpError::OriginNotAllowed(origin.to_string()));
        }
    }
    validate_mcp_request_metadata(request)?;
    if request.body.len() > config.max_body_size {
        return Err(HttpError::BodyTooLarge {
            size: request.body.len(),
            max: config.max_body_size,
        });
    }
    Ok(())
}

fn body_protocol_version(request: &JsonRpcRequest) -> Option<&str> {
    request
        .params
        .as_ref()?
        .as_object()?
        .get("_meta")?
        .as_object()?
        .get("io.modelcontextprotocol/protocolVersion")?
        .as_str()
}

fn body_mcp_name(request: &JsonRpcRequest) -> Option<&str> {
    let parameter_name = match request.method.as_str() {
        "tools/call" | "prompts/get" => "name",
        "resources/read" => "uri",
        _ => return None,
    };
    request
        .params
        .as_ref()?
        .as_object()?
        .get(parameter_name)?
        .as_str()
}

fn response_representation(request: &HttpRequest) -> Result<HttpResponseRepresentation, HttpError> {
    let Some(accept) = request.header("accept") else {
        return Ok(HttpResponseRepresentation::Json);
    };

    if accepts_media_type(accept, "application", "json") {
        Ok(HttpResponseRepresentation::Json)
    } else if accepts_media_type(accept, "text", "event-stream") {
        Ok(HttpResponseRepresentation::Sse)
    } else {
        Err(HttpError::NotAcceptable)
    }
}

fn accepts_media_type(value: &str, expected_type: &str, expected_subtype: &str) -> bool {
    value.split(',').any(|entry| {
        let mut parameters = entry.split(';');
        let media_type = parameters.next().unwrap_or("").trim();
        let Some((type_part, subtype_part)) = media_type.split_once('/') else {
            return false;
        };
        let quality_is_zero = parameters.any(|parameter| {
            parameter
                .trim()
                .strip_prefix("q=")
                .or_else(|| parameter.trim().strip_prefix("Q="))
                .is_some_and(|quality| matches!(quality, "0" | "0.0" | "0.00" | "0.000"))
        });
        !quality_is_zero
            && (type_part.eq_ignore_ascii_case(expected_type) || type_part == "*")
            && (subtype_part.eq_ignore_ascii_case(expected_subtype) || subtype_part == "*")
    })
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
    /// Exact allowed CORS origins.
    ///
    /// Wildcards are deliberately unsupported because MCP requests can carry
    /// credentials. Each cross-origin deployment must name every trusted
    /// origin explicitly.
    pub cors_origins: Vec<String>,
    /// Maximum request body size in bytes.
    pub max_body_size: usize,
}

/// The response representation selected independently for one admitted request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpResponseRepresentation {
    /// A finite `application/json` response body.
    Json,
    /// A finite `text/event-stream` response body bound to this request only.
    Sse,
}

/// A modern HTTP request admitted before authentication or application dispatch.
///
/// The response representation is immutable and request-local. In particular,
/// admitting this value does not create an SSE response body; callers must
/// explicitly bind one only after downstream dispatch is ready to own its
/// cancellation guard.
#[derive(Debug, Clone)]
pub struct ModernHttpRequestAdmission {
    request: JsonRpcRequest,
    response_representation: HttpResponseRepresentation,
}

impl ModernHttpRequestAdmission {
    /// Returns the bounded, strictly decoded JSON-RPC request for downstream dispatch.
    #[must_use]
    pub const fn request(&self) -> &JsonRpcRequest {
        &self.request
    }

    /// Returns this request's immutable response representation.
    #[must_use]
    pub const fn response_representation(&self) -> HttpResponseRepresentation {
        self.response_representation
    }

    /// Binds the selected SSE response body to this request's JSON-RPC ID.
    ///
    /// Calling this for a JSON-selected request or a notification is rejected
    /// before response-stream state is allocated. Dropping the returned body
    /// cancels its paired request guard and releases the registry entry.
    pub fn bind_sse_response_body(
        &self,
        responses: &StreamableHttpResponseStream,
    ) -> Result<StreamableHttpRequestResponseStream, TransportError> {
        if self.response_representation != HttpResponseRepresentation::Sse {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the admitted HTTP request selected a JSON response",
            )));
        }
        let request_id = self.request.id.clone().ok_or_else(|| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a JSON-RPC notification cannot own an SSE response body",
            ))
        })?;
        responses.for_request(request_id)
    }
}

impl Default for HttpHandlerConfig {
    fn default() -> Self {
        Self {
            base_path: "/mcp/v1".to_string(),
            allow_cors: false,
            cors_origins: Vec::new(),
            max_body_size: 10 * 1024 * 1024, // 10 MB
        }
    }
}

/// Handles HTTP requests containing MCP JSON-RPC messages.
///
/// This handler is designed to be integrated with any HTTP server framework.
/// It processes incoming HTTP requests, extracts JSON-RPC messages, and returns
/// appropriate HTTP responses.
///
/// [`HttpRequest`] already owns its body. Integrations must also enforce a
/// streaming body limit before constructing that value; this handler's size
/// check prevents parsing but cannot undo allocation performed upstream.
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
        let mut codec = Codec::new();
        codec.set_max_message_size(config.max_body_size);
        Self { config, codec }
    }

    /// Returns the handler configuration.
    #[must_use]
    pub fn config(&self) -> &HttpHandlerConfig {
        &self.config
    }

    /// Handles a CORS preflight OPTIONS request.
    #[must_use]
    pub fn handle_options(&self, request: &HttpRequest) -> HttpResponse {
        if validate_http_request_headers(request).is_err() {
            return HttpResponse::new(HttpStatus::BAD_REQUEST);
        }
        if request.path != self.config.base_path {
            return HttpResponse::new(HttpStatus::NOT_FOUND);
        }
        if request.method != HttpMethod::Options {
            return HttpResponse::new(HttpStatus::METHOD_NOT_ALLOWED);
        }
        if !self.config.allow_cors {
            return HttpResponse::new(HttpStatus::METHOD_NOT_ALLOWED);
        }

        let Some(origin) = request.header("origin") else {
            return HttpResponse::new(HttpStatus::FORBIDDEN);
        };
        if request.header("access-control-request-method") != Some("POST") {
            return HttpResponse::new(HttpStatus::FORBIDDEN);
        }
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
        is_origin_allowed(&self.config, origin)
    }

    /// Parses a JSON-RPC request from an HTTP request.
    pub fn parse_request(&self, request: &HttpRequest) -> Result<JsonRpcRequest, HttpError> {
        validate_mcp_request_policy(request, &self.config)?;

        // HTTP framing already supplies one complete body. Route it through
        // the shared strict JSON admission boundary before typed decoding.
        Ok(self.codec.decode_complete_request(&request.body)?)
    }

    /// Admits one final MCP 2026-07-28 request before authentication or dispatch.
    ///
    /// This applies the fixed endpoint/method/media/bounds boundary, strict
    /// raw JSON-RPC object decoding (including batch rejection), PRT-03's
    /// header/body mirrors, and request-local response selection. It does not
    /// allocate a response body, authenticate, resolve a method, or mutate
    /// application state.
    pub fn admit_modern_request(
        &self,
        request: &HttpRequest,
    ) -> Result<ModernHttpRequestAdmission, HttpError> {
        validate_mcp_request_policy(request, &self.config)?;
        let json_rpc = self.codec.decode_complete_request(&request.body)?;
        admit_final_http_request(FinalHttpRequestMetadata {
            version: RequestVersionMetadata {
                header_version: request.header("MCP-Protocol-Version"),
                body_version: body_protocol_version(&json_rpc),
            },
            header_method: request.header("Mcp-Method"),
            body_method: Some(&json_rpc.method),
            header_name: request.header("Mcp-Name"),
            body_name: body_mcp_name(&json_rpc),
        })
        .map_err(HttpError::ProtocolAdmission)?;
        let response_representation = response_representation(request)?;

        Ok(ModernHttpRequestAdmission {
            request: json_rpc,
            response_representation,
        })
    }

    /// Creates an HTTP response from a JSON-RPC response.
    ///
    /// Encoding failures are converted into a deterministic 500 response with
    /// a nonempty JSON error body. Use [`Self::try_create_response`] when the
    /// caller needs the typed codec error instead.
    #[must_use]
    pub fn create_response(
        &self,
        response: &JsonRpcResponse,
        origin: Option<&str>,
    ) -> HttpResponse {
        self.create_response_from_encoding(self.codec.encode_response(response), origin)
    }

    /// Tries to create an HTTP response from a JSON-RPC response.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::CodecError`] when the JSON-RPC response cannot be
    /// encoded.
    pub fn try_create_response(
        &self,
        response: &JsonRpcResponse,
        origin: Option<&str>,
    ) -> Result<HttpResponse, HttpError> {
        self.try_create_response_from_encoding(self.codec.encode_response(response), origin)
    }

    fn create_response_from_encoding(
        &self,
        encoded: Result<Vec<u8>, CodecError>,
        origin: Option<&str>,
    ) -> HttpResponse {
        match self.try_create_response_from_encoding(encoded, origin) {
            Ok(response) => response,
            Err(_) => self.with_allowed_origin(
                HttpResponse::internal_error().with_body(JSON_ENCODING_ERROR_BODY),
                origin,
            ),
        }
    }

    fn try_create_response_from_encoding(
        &self,
        encoded: Result<Vec<u8>, CodecError>,
        origin: Option<&str>,
    ) -> Result<HttpResponse, HttpError> {
        let body = encoded?;

        let http_response = HttpResponse::ok()
            .with_body(body)
            .with_header("content-type", "application/json");

        Ok(self.with_allowed_origin(http_response, origin))
    }

    fn with_allowed_origin(
        &self,
        mut http_response: HttpResponse,
        origin: Option<&str>,
    ) -> HttpResponse {
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
///
/// Context-aware receive checks cancellation/budget state before and after
/// every completed incremental read and again after parse/decode. The generic
/// `R: Read` boundary cannot preempt an underlying synchronous read that is
/// already blocked; callers requiring bounded cancellation while a peer is
/// silent must supply a readiness-aware or asynchronous host boundary.
pub struct HttpTransport<R, W> {
    reader: R,
    writer: W,
    codec: Codec,
    config: HttpHandlerConfig,
    closed: bool,
    /// Exact admitted Origin for the request awaiting its response.
    response_origin: Option<String>,
    /// Whether one admitted HTTP request is still awaiting its sole response.
    response_pending: bool,
}

fn read_retry_interrupted<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    cx: Option<&Cx>,
) -> Result<usize, HttpError> {
    loop {
        if let Some(cx) = cx {
            // Check again immediately before each potentially blocking read,
            // including reads separated by parsing or buffer growth.
            http_checkpoint(cx).map_err(HttpError::Transport)?;
        }
        match reader.read(buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                if let Some(cx) = cx {
                    http_checkpoint(cx).map_err(HttpError::Transport)?;
                }
            }
            Ok(read) => {
                if let Some(cx) = cx {
                    // Incremental parsing can span many successful reads. A
                    // single entry checkpoint is insufficient for a slow peer:
                    // recheck after every completed read before another read
                    // may block or newly consumed bytes can be admitted.
                    http_checkpoint(cx).map_err(HttpError::Transport)?;
                }
                return Ok(read);
            }
            Err(error) => return Err(HttpError::Transport(error.into())),
        }
    }
}

fn read_exact_retry_interrupted<R: Read>(
    reader: &mut R,
    mut buffer: &mut [u8],
    cx: Option<&Cx>,
) -> Result<(), HttpError> {
    while !buffer.is_empty() {
        let read = read_retry_interrupted(reader, buffer, cx)?;
        if read == 0 {
            return Err(HttpError::Transport(
                std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into(),
            ));
        }
        let (_, remaining) = buffer.split_at_mut(read);
        buffer = remaining;
    }
    Ok(())
}

impl<R: Read, W: Write> HttpTransport<R, W> {
    /// Creates a new HTTP transport.
    #[must_use]
    pub fn new(reader: R, writer: W) -> Self {
        Self::with_config(reader, writer, HttpHandlerConfig::default())
    }

    /// Creates an HTTP transport with an explicit endpoint and Origin policy.
    #[must_use]
    pub fn with_config(reader: R, writer: W, config: HttpHandlerConfig) -> Self {
        let mut codec = Codec::new();
        codec.set_max_message_size(config.max_body_size);
        Self {
            reader,
            writer,
            codec,
            config,
            closed: false,
            response_origin: None,
            response_pending: false,
        }
    }

    /// Returns the transport's HTTP admission policy.
    #[must_use]
    pub fn config(&self) -> &HttpHandlerConfig {
        &self.config
    }

    /// Reads an HTTP request from the reader.
    ///
    /// Any error is terminal for this transport. The incremental parser may
    /// already have consumed a request line, headers, chunk metadata, or a body
    /// prefix, so the unread suffix can never be admitted as a new request.
    pub fn read_request(&mut self) -> Result<HttpRequest, HttpError> {
        self.read_request_with_context(None)
    }

    fn read_request_with_context(&mut self, cx: Option<&Cx>) -> Result<HttpRequest, HttpError> {
        if self.closed {
            return Err(HttpError::Closed);
        }

        let result = self.read_request_inner(cx);
        if result.is_err() {
            self.closed = true;
            self.response_pending = false;
            self.response_origin = None;
        }
        result
    }

    fn read_request_inner(&mut self, cx: Option<&Cx>) -> Result<HttpRequest, HttpError> {
        const MAX_HEADERS_SIZE: usize = 64 * 1024;
        let max_body_size = self.config.max_body_size;

        let mut buffer = Vec::new();
        let mut byte = [0u8; 1];

        // Read headers until \r\n\r\n
        loop {
            if read_retry_interrupted(&mut self.reader, &mut byte, cx)? == 0 {
                return Err(HttpError::Closed);
            }
            buffer.push(byte[0]);

            if buffer.len() > MAX_HEADERS_SIZE {
                return Err(HttpError::HeadersTooLarge {
                    size: buffer.len(),
                    max: MAX_HEADERS_SIZE,
                });
            }
            if buffer.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        let header_str = std::str::from_utf8(&buffer)
            .map_err(|_| HttpError::InvalidHeader("headers are not valid UTF-8".to_string()))?;
        let header_block = header_str.strip_suffix("\r\n\r\n").ok_or_else(|| {
            HttpError::InvalidHeader("headers are not terminated by CRLF CRLF".to_string())
        })?;
        let mut lines = header_block.split("\r\n");

        // Parse request line
        let request_line = lines
            .next()
            .ok_or_else(|| HttpError::InvalidRequestLine("missing request line".to_string()))?;
        let mut request_parts = request_line.split(' ');
        let method_token = request_parts.next().unwrap_or("");
        let full_path = request_parts.next().unwrap_or("");
        let version = request_parts.next().unwrap_or("");
        if method_token.is_empty()
            || full_path.is_empty()
            || !full_path.bytes().all(|byte| byte.is_ascii_graphic())
            || version != "HTTP/1.1"
            || request_parts.next().is_some()
        {
            return Err(HttpError::InvalidRequestLine(request_line.to_string()));
        }

        let method = HttpMethod::parse(method_token)
            .filter(|method| method.as_str() == method_token)
            .ok_or_else(|| HttpError::InvalidMethod(method_token.to_string()))?;

        let (path, query_str) = full_path
            .split_once('?')
            .map_or((full_path.to_string(), None), |(p, q)| {
                (p.to_string(), Some(q))
            });

        let mut query = HashMap::new();
        if let Some(qs) = query_str {
            for pair in qs.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                query.insert(k.to_string(), v.to_string());
            }
        }

        // Parse headers
        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                return Err(HttpError::InvalidHeader(
                    "unexpected empty header line".to_string(),
                ));
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                return Err(HttpError::InvalidHeader(
                    "obsolete folded header line".to_string(),
                ));
            }
            let (name, raw_value) = line.split_once(':').ok_or_else(|| {
                HttpError::InvalidHeader("header is missing ':' separator".to_string())
            })?;
            if !is_http_token(name) {
                return Err(HttpError::InvalidHeader(format!(
                    "invalid header name: {name}"
                )));
            }
            let value = raw_value.trim_matches([' ', '\t']);
            if !is_valid_http_header_value(value) {
                return Err(HttpError::InvalidHeader(format!(
                    "invalid value for header {name}"
                )));
            }
            let normalized_name = name.to_ascii_lowercase();
            if headers
                .insert(normalized_name.clone(), value.to_string())
                .is_some()
            {
                return Err(HttpError::InvalidHeader(format!(
                    "duplicate header: {normalized_name}"
                )));
            }
        }

        if headers.contains_key("content-length") && headers.contains_key("transfer-encoding") {
            return Err(HttpError::InvalidHeader(
                "content-length and transfer-encoding cannot be combined".to_string(),
            ));
        }

        // Read body.
        //
        // We support Content-Length or Transfer-Encoding: chunked. This is sufficient for MCP's
        // JSON-RPC-over-HTTP payloads and avoids pulling in a full HTTP server stack here.
        let mut body = Vec::new();

        if let Some(te) = headers.get("transfer-encoding") {
            if te.trim().eq_ignore_ascii_case("chunked") {
                // Chunked transfer encoding
                loop {
                    // Read chunk size line (hex), terminated by CRLF.
                    let mut line = Vec::new();
                    loop {
                        if read_retry_interrupted(&mut self.reader, &mut byte, cx)? == 0 {
                            return Err(HttpError::Closed);
                        }
                        line.push(byte[0]);
                        if line.len() > 1024 {
                            return Err(HttpError::InvalidHeader(
                                "invalid chunk size line".to_string(),
                            ));
                        }
                        if line.ends_with(b"\r\n") {
                            break;
                        }
                    }

                    let line_str = std::str::from_utf8(&line).map_err(|_| {
                        HttpError::InvalidHeader("chunk size is not valid UTF-8".to_string())
                    })?;
                    let size_str = line_str.strip_suffix("\r\n").ok_or_else(|| {
                        HttpError::InvalidHeader(
                            "chunk size line is not CRLF terminated".to_string(),
                        )
                    })?;
                    if size_str.contains(';') {
                        return Err(HttpError::InvalidHeader(
                            "chunk extensions are not supported".to_string(),
                        ));
                    }
                    let size = usize::from_str_radix(size_str, 16)
                        .map_err(|_| HttpError::InvalidHeader("invalid chunk size".to_string()))?;

                    if size == 0 {
                        // Consume the empty line that terminates a chunked body.
                        // Trailer fields are deliberately unsupported below.
                        let mut trailer = Vec::new();
                        loop {
                            if read_retry_interrupted(&mut self.reader, &mut byte, cx)? == 0 {
                                return Err(HttpError::Closed);
                            }
                            trailer.push(byte[0]);
                            if trailer.len() > MAX_HEADERS_SIZE {
                                return Err(HttpError::HeadersTooLarge {
                                    size: trailer.len(),
                                    max: MAX_HEADERS_SIZE,
                                });
                            }
                            if trailer.ends_with(b"\r\n") {
                                break;
                            }
                        }
                        if trailer != b"\r\n" {
                            return Err(HttpError::InvalidHeader(
                                "HTTP trailer fields are not supported".to_string(),
                            ));
                        }
                        break;
                    }

                    // Reject the declared aggregate length before allocating
                    // the chunk. Allocating `size` first would let an
                    // attacker trigger an OOM with only a large hexadecimal
                    // chunk header on the wire.
                    let body_start = body.len();
                    let projected_body_size = body_start.saturating_add(size);
                    if projected_body_size > max_body_size {
                        return Err(HttpError::BodyTooLarge {
                            size: projected_body_size,
                            max: max_body_size,
                        });
                    }
                    body.resize(projected_body_size, 0);
                    read_exact_retry_interrupted(&mut self.reader, &mut body[body_start..], cx)?;

                    // Consume trailing CRLF after the chunk.
                    let mut crlf = [0u8; 2];
                    read_exact_retry_interrupted(&mut self.reader, &mut crlf, cx)?;
                    if &crlf != b"\r\n" {
                        return Err(HttpError::InvalidHeader(
                            "invalid chunk terminator".to_string(),
                        ));
                    }
                }
            } else {
                return Err(HttpError::UnsupportedTransferEncoding(te.clone()));
            }
        } else {
            // Content-Length (if present)
            let content_length = match headers.get("content-length") {
                Some(value) => {
                    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(HttpError::InvalidHeader(
                            "invalid content-length".to_string(),
                        ));
                    }
                    value.parse::<usize>().map_err(|_| {
                        HttpError::InvalidHeader("content-length is out of range".to_string())
                    })?
                }
                None => 0,
            };

            if content_length > max_body_size {
                return Err(HttpError::BodyTooLarge {
                    size: content_length,
                    max: max_body_size,
                });
            }

            body.resize(content_length, 0);
            if content_length > 0 {
                read_exact_retry_interrupted(&mut self.reader, &mut body, cx)?;
            }
        }

        if let Some(cx) = cx {
            // Parsing and allocation follow the final read. Recheck once more
            // before exposing the fully consumed request to the transport.
            http_checkpoint(cx).map_err(HttpError::Transport)?;
        }

        Ok(HttpRequest {
            method,
            path,
            headers,
            body,
            query,
        })
    }

    /// Writes an HTTP response to the writer.
    pub fn write_response(&mut self, response: &HttpResponse) -> Result<(), HttpError> {
        // Validate the complete header set before emitting the status line so
        // a rejected field cannot leave a partial response on the wire.
        let mut normalized_names = HashSet::new();
        let mut has_content_length = false;
        for (name, value) in &response.headers {
            if !is_http_token(name) {
                return Err(HttpError::InvalidHeader(format!(
                    "invalid response header name: {name}"
                )));
            }
            if !is_valid_http_header_value(value) {
                return Err(HttpError::InvalidHeader(format!(
                    "invalid value for response header {name}"
                )));
            }
            let normalized_name = name.to_ascii_lowercase();
            if !normalized_names.insert(normalized_name.clone()) {
                return Err(HttpError::InvalidHeader(format!(
                    "duplicate response header: {normalized_name}"
                )));
            }
            if normalized_name == "transfer-encoding" {
                return Err(HttpError::InvalidHeader(
                    "HttpTransport does not encode transfer-encoding responses".to_string(),
                ));
            }
            if normalized_name == "content-length" {
                let length = value.parse::<usize>().map_err(|_| {
                    HttpError::InvalidHeader("invalid response content-length".to_string())
                })?;
                if length != response.body.len() {
                    return Err(HttpError::InvalidHeader(
                        "response content-length does not match body".to_string(),
                    ));
                }
                has_content_length = true;
            }
        }

        let status_text = match response.status.0 {
            200 => "OK",
            202 => "Accepted",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
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
        if !has_content_length {
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
}

impl<R: Read, W: Write> Transport for HttpTransport<R, W> {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        http_checkpoint(cx)?;

        let response = match message {
            JsonRpcMessage::Response(r) => r.clone(),
            JsonRpcMessage::Request(r) => {
                // For HTTP transport, requests from server to client
                // are typically sent as notifications or SSE events.
                // This transport is request/response only and cannot deliver server-to-client
                // requests. Returning Ok() would silently drop messages and can deadlock
                // bidirectional protocols, so we fail explicitly.
                let _ = r;
                return Err(TransportError::Io(std::io::Error::other(
                    "HttpTransport cannot send server-to-client requests",
                )));
            }
        };

        if !self.response_pending {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no admitted HTTP request is awaiting a response",
            )));
        }

        let encoded = self.codec.encode_response(&response)?;
        let mut http_response = HttpResponse::ok()
            .with_body(encoded)
            .with_header("content-type", "application/json");
        if let Some(origin) = self.response_origin.as_deref() {
            http_response = http_response.with_cors(origin);
        }

        if self.write_response(&http_response).is_err() {
            // A partially written HTTP response cannot be retried safely on
            // the same byte stream.
            self.closed = true;
            return Err(TransportError::Io(std::io::Error::other("write error")));
        }
        self.response_pending = false;
        self.response_origin = None;

        Ok(())
    }

    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        http_checkpoint(cx)?;
        if self.response_pending {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "previous HTTP request is still awaiting a response",
            )));
        }

        let http_request = match self.read_request_with_context(Some(cx)) {
            Ok(request) => request,
            Err(error) => {
                // The incremental HTTP parser may already have consumed a
                // request-line, headers, chunk metadata, or body prefix. It is
                // never safe to treat the remaining suffix as a new request.
                self.closed = true;
                self.response_pending = false;
                self.response_origin = None;
                return Err(match error {
                    HttpError::Closed => TransportError::Closed,
                    HttpError::Timeout => TransportError::Timeout,
                    HttpError::Transport(error) => error,
                    _ => TransportError::Io(std::io::Error::other(error.to_string())),
                });
            }
        };
        validate_mcp_request_policy(&http_request, &self.config).map_err(|error| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.to_string(),
            ))
        })?;
        self.response_origin = http_request.header("origin").map(ToOwned::to_owned);
        self.response_pending = true;

        // Parse JSON-RPC from the complete HTTP body through the same bounded
        // admission policy used by every other transport.
        let json_rpc = self.codec.decode_complete_request(&http_request.body)?;

        if let Err(error) = http_checkpoint(cx) {
            // The complete HTTP exchange has already left the byte stream. A
            // failed post-decode checkpoint is terminal rather than authority
            // to retry and silently skip that request.
            self.closed = true;
            self.response_pending = false;
            self.response_origin = None;
            return Err(error);
        }

        if json_rpc.is_notification() {
            // Streamable HTTP acknowledges notification POSTs at the HTTP
            // layer; JSON-RPC itself does not produce a response. Completing
            // that exchange here prevents the one-outstanding-request guard
            // from permanently blocking the next request.
            let mut accepted = HttpResponse::new(HttpStatus::ACCEPTED);
            if let Some(origin) = self.response_origin.as_deref() {
                accepted = accepted.with_cors(origin);
            }
            if self.write_response(&accepted).is_err() {
                self.closed = true;
                return Err(TransportError::Io(std::io::Error::other("write error")));
            }
            self.response_pending = false;
            self.response_origin = None;
        }

        Ok(JsonRpcMessage::Request(json_rpc))
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.closed = true;
        self.response_pending = false;
        self.response_origin = None;
        Ok(())
    }
}

// =============================================================================
// Streaming HTTP Transport
// =============================================================================

const DEFAULT_STREAMABLE_QUEUE_CAPACITY: usize = 64;
const MAX_STREAMABLE_QUEUE_CAPACITY: usize = 1_024;
const MAX_STREAMABLE_QUEUED_BYTES_PER_DIRECTION: usize = 16 * 1024 * 1024;

struct QueuedRequest {
    message: JsonRpcRequest,
    serialized_bytes: usize,
}

/// One JSON-RPC message emitted through a request-owned modern SSE body.
///
/// A body may carry any number of server-to-client notifications and exactly
/// one terminal response. Notifications retain the request body that owns
/// their delivery, so independent modern requests cannot observe, consume, or
/// cancel one another's outbound messages.
#[derive(Debug, Clone)]
pub enum StreamableHttpRequestResponseMessage {
    /// A server-to-client JSON-RPC notification sent before the terminal response.
    Notification(JsonRpcRequest),
    /// The single terminal JSON-RPC response for the owning request.
    Response(JsonRpcResponse),
}

struct QueuedResponse {
    request_id: Option<RequestId>,
    message: StreamableHttpRequestResponseMessage,
    serialized_bytes: usize,
}

struct StreamableResponseMailbox {
    queue: VecDeque<QueuedResponse>,
    retained_bytes: usize,
}

struct StreamableAdmissionGuard<'a> {
    active: &'a AtomicUsize,
}

impl Drop for StreamableAdmissionGuard<'_> {
    fn drop(&mut self) {
        let previous = self.active.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0, "streamable admission count underflow");
    }
}

fn begin_streamable_admission<'a>(
    open: &AtomicBool,
    active: &'a AtomicUsize,
) -> Result<StreamableAdmissionGuard<'a>, TransportError> {
    // These two atomics form one admission gate. Sequential consistency is
    // intentional: with only acquire/release ordering, close could observe the
    // old active count while an entrant observed the old open flag (the
    // store-buffering outcome), allowing an admission to outlive close.
    active.fetch_add(1, Ordering::SeqCst);
    if !open.load(Ordering::SeqCst) {
        let previous = active.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0, "streamable admission count underflow");
        return Err(TransportError::Closed);
    }
    Ok(StreamableAdmissionGuard { active })
}

fn close_streamable_admissions(open: &AtomicBool, active: &AtomicUsize) {
    open.store(false, Ordering::SeqCst);
    while active.load(Ordering::SeqCst) != 0 {
        std::thread::yield_now();
    }
}

impl StreamableResponseMailbox {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            retained_bytes: 0,
        }
    }
}

/// Cloneable, accounting-aware ingress for streamable HTTP requests.
///
/// This handle is intended for HTTP request-handler threads while the owning
/// [`StreamableHttpTransport`] is blocked in [`Transport::recv`]. Every clone
/// shares the transport's count and serialized-byte limits; the raw channel is
/// deliberately not exposed because sending through it would bypass those
/// admission checks.
pub struct StreamableHttpRequestIngress {
    codec: Codec,
    sender: mpsc::Sender<QueuedRequest>,
    retained_bytes: Arc<AtomicUsize>,
    max_queued_bytes: usize,
    endpoint_count: Arc<AtomicUsize>,
    admissions_open: Arc<AtomicBool>,
    active_admissions: Arc<AtomicUsize>,
}

impl Clone for StreamableHttpRequestIngress {
    fn clone(&self) -> Self {
        self.endpoint_count.fetch_add(1, Ordering::Relaxed);
        let mut codec = Codec::new();
        codec.set_max_message_size(self.codec.max_message_size());
        Self {
            codec,
            sender: self.sender.clone(),
            retained_bytes: Arc::clone(&self.retained_bytes),
            max_queued_bytes: self.max_queued_bytes,
            endpoint_count: Arc::clone(&self.endpoint_count),
            admissions_open: Arc::clone(&self.admissions_open),
            active_admissions: Arc::clone(&self.active_admissions),
        }
    }
}

impl Drop for StreamableHttpRequestIngress {
    fn drop(&mut self) {
        let previous = self.endpoint_count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "request-ingress endpoint count underflow");
        if previous == 1 {
            close_streamable_admissions(&self.admissions_open, &self.active_admissions);
        }
    }
}

impl StreamableHttpRequestIngress {
    /// Admits one request to the transport's bounded request queue.
    ///
    /// # Errors
    ///
    /// Returns `WouldBlock` when either the count or serialized-byte budget is
    /// full, and returns [`TransportError::Closed`] after transport shutdown.
    pub fn push_request(&self, cx: &Cx, request: JsonRpcRequest) -> Result<(), TransportError> {
        enqueue_streamable_request(
            &self.codec,
            &self.sender,
            &self.retained_bytes,
            self.max_queued_bytes,
            &self.admissions_open,
            &self.active_admissions,
            cx,
            request,
        )
    }

    /// Returns the hard request-count capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.sender.capacity()
    }

    /// Closes the shared request-admission endpoint.
    ///
    /// Dropping the final ingress handle has the same effect. Closing one clone
    /// is intentionally ingress-wide; all clones stop admitting requests while
    /// an independent response stream may still drain prior work. This is a
    /// synchronization barrier: it waits for bounded admissions that already
    /// entered the gate to commit or abort.
    pub fn close(&self) {
        close_streamable_admissions(&self.admissions_open, &self.active_admissions);
    }

    /// Returns whether request admission or the owning receiver has closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        !self.admissions_open.load(Ordering::Acquire) || self.sender.is_closed()
    }
}

/// Cloneable, accounting-aware consumer for streamable HTTP outbound messages.
///
/// Every receive operation names its expected JSON-RPC request ID. Clones can
/// therefore wait for different unowned responses without consuming one
/// another's messages. Request-owned SSE bodies use their dedicated consumer
/// instead, which preserves notification and terminal-response ordering.
/// Dequeues release the corresponding count and serialized-byte reservations
/// exactly once.
pub struct StreamableHttpResponseStream {
    codec: Codec,
    mailbox: Arc<Mutex<StreamableResponseMailbox>>,
    request_states: Arc<Mutex<HashMap<RequestId, Arc<StreamableHttpRequestCancellationState>>>>,
    pending_count: Arc<AtomicUsize>,
    endpoint_count: Arc<AtomicUsize>,
    active_admissions: Arc<AtomicUsize>,
    capacity: usize,
    max_queued_bytes: usize,
    owner_open: Arc<AtomicBool>,
    admissions_open: Arc<AtomicBool>,
    poll_interval: Duration,
    #[cfg(test)]
    empty_polls: Arc<AtomicUsize>,
    #[cfg(test)]
    entered_empty_waits: Arc<AtomicUsize>,
}

impl Clone for StreamableHttpResponseStream {
    fn clone(&self) -> Self {
        self.endpoint_count.fetch_add(1, Ordering::Relaxed);
        Self {
            codec: response_stream_codec(&self.codec),
            mailbox: Arc::clone(&self.mailbox),
            request_states: Arc::clone(&self.request_states),
            pending_count: Arc::clone(&self.pending_count),
            endpoint_count: Arc::clone(&self.endpoint_count),
            active_admissions: Arc::clone(&self.active_admissions),
            capacity: self.capacity,
            max_queued_bytes: self.max_queued_bytes,
            owner_open: Arc::clone(&self.owner_open),
            admissions_open: Arc::clone(&self.admissions_open),
            poll_interval: self.poll_interval,
            #[cfg(test)]
            empty_polls: Arc::clone(&self.empty_polls),
            #[cfg(test)]
            entered_empty_waits: Arc::clone(&self.entered_empty_waits),
        }
    }
}

/// Builds the encoding-only codec held by an external response stream.
///
/// `Codec` deliberately does not implement `Clone`: its decode buffer is
/// mutable per direction. Response streams only encode, so they retain the
/// originating transport's exact message-size admission limit while starting
/// with an independent, empty decode buffer.
fn response_stream_codec(codec: &Codec) -> Codec {
    let mut response_codec = Codec::new();
    response_codec.set_max_message_size(codec.max_message_size());
    response_codec
}

impl Drop for StreamableHttpResponseStream {
    fn drop(&mut self) {
        let previous = self.endpoint_count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "response-stream endpoint count underflow");
        if previous == 1 {
            self.terminate();
        }
    }
}

impl StreamableHttpResponseStream {
    /// Pops an unowned response for `request_id` without blocking.
    ///
    /// A null-ID JSON-RPC error can be selected with `None`. If another clone
    /// currently owns the mailbox lock, this returns `WouldBlock` rather than
    /// blocking the calling thread. A live request-owned SSE body must consume
    /// its own messages through [`StreamableHttpRequestResponseStream`].
    pub fn pop_response(
        &self,
        request_id: Option<&RequestId>,
    ) -> Result<Option<JsonRpcResponse>, TransportError> {
        if let Some(request_id) = request_id {
            if self.request_is_live(request_id)? {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "request-owned Streamable HTTP messages must use their bound SSE response body",
                )));
            }
        }
        let queued = self.pop_matching(|queued| {
            matches!(
                &queued.message,
                StreamableHttpRequestResponseMessage::Response(response)
                    if response.id.as_ref() == request_id
            )
        })?;
        Ok(queued.map(|queued| match queued.message {
            StreamableHttpRequestResponseMessage::Response(response) => response,
            StreamableHttpRequestResponseMessage::Notification(_) => {
                unreachable!("the response matcher cannot dequeue a notification")
            }
        }))
    }

    fn pop_matching(
        &self,
        matches: impl Fn(&QueuedResponse) -> bool,
    ) -> Result<Option<QueuedResponse>, TransportError> {
        if let Some(message) =
            try_pop_streamable_message(&self.mailbox, &self.pending_count, &matches)?
        {
            return Ok(Some(message));
        }
        if !self.admissions_open.load(Ordering::Acquire)
            && self.active_admissions.load(Ordering::SeqCst) == 0
        {
            // An admitted producer can commit between the first empty mailbox
            // check and dropping its admission guard. Once the gate is closed
            // and the active count reaches zero, recheck under the mailbox
            // lock before declaring terminal closure.
            match try_pop_streamable_message(&self.mailbox, &self.pending_count, &matches)? {
                Some(message) => Ok(Some(message)),
                None => Err(TransportError::Closed),
            }
        } else {
            Ok(None)
        }
    }

    /// Waits for the response matching `request_id` while observing the full
    /// context checkpoint contract, including masking and budget exhaustion.
    pub fn recv_response(
        &self,
        cx: &Cx,
        request_id: Option<&RequestId>,
    ) -> Result<JsonRpcResponse, TransportError> {
        #[cfg(test)]
        let mut entered_empty_wait = false;
        loop {
            http_checkpoint(cx)?;
            match self.pop_response(request_id) {
                Ok(Some(response)) => return Ok(response),
                Ok(None) => {}
                Err(error) if is_would_block(&error) => {}
                Err(error) => return Err(error),
            }
            #[cfg(test)]
            {
                self.empty_polls.fetch_add(1, Ordering::Release);
                if !entered_empty_wait {
                    self.entered_empty_waits.fetch_add(1, Ordering::Release);
                    entered_empty_wait = true;
                }
            }
            std::thread::sleep(self.poll_interval);
        }
    }

    fn pop_request_message(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<StreamableHttpRequestResponseMessage>, TransportError> {
        Ok(self
            .pop_matching(|queued| queued.request_id.as_ref() == Some(request_id))?
            .map(|queued| queued.message))
    }

    fn pop_request_response(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<JsonRpcResponse>, TransportError> {
        if let Some(response) =
            try_pop_streamable_request_response(&self.mailbox, &self.pending_count, request_id)?
        {
            return Ok(Some(response));
        }
        if !self.admissions_open.load(Ordering::Acquire)
            && self.active_admissions.load(Ordering::SeqCst) == 0
        {
            match try_pop_streamable_request_response(
                &self.mailbox,
                &self.pending_count,
                request_id,
            )? {
                Some(response) => Ok(Some(response)),
                None => Err(TransportError::Closed),
            }
        } else {
            Ok(None)
        }
    }

    fn request_is_live(&self, request_id: &RequestId) -> Result<bool, TransportError> {
        let request_states = match self.request_states.try_lock() {
            Ok(request_states) => request_states,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(streamable_queue_full_error(
                    "streamable HTTP request-response registry is busy",
                ));
            }
        };
        Ok(request_states.contains_key(request_id))
    }

    fn request_response_guard_is_active(
        &self,
        cancellation: &StreamableHttpRequestCancellation,
    ) -> Result<bool, TransportError> {
        let request_states = match self.request_states.try_lock() {
            Ok(request_states) => request_states,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(streamable_queue_full_error(
                    "streamable HTTP request-response registry is busy",
                ));
            }
        };
        Ok(request_states
            .get(cancellation.request_id())
            .is_some_and(|state| Arc::ptr_eq(state, &cancellation.state)))
    }

    fn enqueue_request_message(
        &self,
        cx: &Cx,
        cancellation: &StreamableHttpRequestCancellation,
        message: StreamableHttpRequestResponseMessage,
    ) -> Result<(), TransportError> {
        if !self.owner_open.load(Ordering::Acquire) || !self.admissions_open.load(Ordering::Acquire)
        {
            return Err(TransportError::Closed);
        }
        cancellation.checkpoint(cx)?;
        let _admission =
            begin_streamable_admission(&self.admissions_open, &self.active_admissions)?;
        let serialized_bytes = match &message {
            StreamableHttpRequestResponseMessage::Notification(notification) => {
                self.codec.encode_request(notification)?.len()
            }
            StreamableHttpRequestResponseMessage::Response(response) => {
                self.codec.encode_response(response)?.len()
            }
        };
        cancellation.checkpoint(cx)?;
        let mut mailbox = match self.mailbox.try_lock() {
            Ok(mailbox) => mailbox,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(streamable_queue_full_error(
                    "streamable response mailbox is busy",
                ));
            }
        };
        if !self.owner_open.load(Ordering::Acquire) || !self.admissions_open.load(Ordering::Acquire)
        {
            return Err(TransportError::Closed);
        }
        cancellation.checkpoint(cx)?;
        if mailbox.queue.len() >= self.capacity {
            return Err(streamable_queue_full_error(
                "streamable response queue is full",
            ));
        }
        let prospective = mailbox
            .retained_bytes
            .checked_add(serialized_bytes)
            .filter(|bytes| *bytes <= self.max_queued_bytes)
            .ok_or_else(|| {
                streamable_queue_full_error("streamable response byte budget is full")
            })?;
        mailbox.queue.push_back(QueuedResponse {
            request_id: Some(cancellation.request_id().clone()),
            message,
            serialized_bytes,
        });
        mailbox.retained_bytes = prospective;
        self.pending_count.fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn send_response_for_request(
        &self,
        cx: &Cx,
        cancellation: &StreamableHttpRequestCancellation,
        response: JsonRpcResponse,
    ) -> Result<(), TransportError> {
        if response.id.as_ref() != Some(cancellation.request_id()) {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "streamable HTTP response ID does not match its request response body",
            )));
        }
        cancellation.checkpoint(cx)?;
        if !self.request_response_guard_is_active(cancellation)? {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "streamable HTTP response guard does not belong to this live transport request",
            )));
        }
        cancellation.with_message_commit(cx, true, || {
            self.enqueue_request_message(
                cx,
                cancellation,
                StreamableHttpRequestResponseMessage::Response(response),
            )
        })
    }

    fn send_notification_for_request(
        &self,
        cx: &Cx,
        cancellation: &StreamableHttpRequestCancellation,
        notification: JsonRpcRequest,
    ) -> Result<(), TransportError> {
        if !notification.is_notification() {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "streamable HTTP request-owned messages must be JSON-RPC notifications",
            )));
        }
        cancellation.checkpoint(cx)?;
        if !self.request_response_guard_is_active(cancellation)? {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "streamable HTTP notification guard does not belong to this live transport request",
            )));
        }
        cancellation.with_message_commit(cx, false, || {
            self.enqueue_request_message(
                cx,
                cancellation,
                StreamableHttpRequestResponseMessage::Notification(notification),
            )
        })
    }

    fn discard_request_messages(&self, request_id: &RequestId) {
        let mut mailbox = self
            .mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut discarded_count = 0;
        let mut discarded_bytes = 0;
        mailbox.queue.retain(|queued| {
            if queued.request_id.as_ref() == Some(request_id) {
                discarded_count += 1;
                discarded_bytes += queued.serialized_bytes;
                false
            } else {
                true
            }
        });
        if discarded_count != 0 {
            debug_assert!(mailbox.retained_bytes >= discarded_bytes);
            mailbox.retained_bytes = mailbox.retained_bytes.saturating_sub(discarded_bytes);
            let previous = self
                .pending_count
                .fetch_sub(discarded_count, Ordering::AcqRel);
            debug_assert!(
                previous >= discarded_count,
                "response pending-count underflow while cancelling a request body"
            );
        }
    }

    /// Returns whether at least one outbound message is awaiting consumption.
    #[must_use]
    pub fn has_responses(&self) -> bool {
        self.pending_count.load(Ordering::Acquire) > 0
    }

    /// Returns the number of outbound messages awaiting consumption.
    #[must_use]
    pub fn pending_responses(&self) -> usize {
        self.pending_count.load(Ordering::Acquire)
    }

    /// Returns the number of request-owned response bodies that remain live.
    ///
    /// This count excludes queued messages: a body remains live while it can
    /// still accept notifications and its one terminal response, or be
    /// cancelled by its HTTP response teardown.
    pub fn live_request_bodies(&self) -> Result<usize, TransportError> {
        let request_states = match self.request_states.try_lock() {
            Ok(request_states) => request_states,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(streamable_queue_full_error(
                    "streamable HTTP request-response registry is busy",
                ));
            }
        };
        Ok(request_states.len())
    }

    /// Returns the hard response-count capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Closes the shared response-admission endpoint.
    ///
    /// Already-admitted outbound messages remain available to their matching
    /// consumers. Closing any clone seals production for every clone. Dropping
    /// the final response-stream handle additionally discards responses that
    /// can no longer have a consumer. This is a synchronization barrier for
    /// bounded response admissions already inside the gate.
    pub fn close(&self) {
        close_streamable_admissions(&self.admissions_open, &self.active_admissions);
    }

    fn terminate(&self) {
        close_streamable_admissions(&self.admissions_open, &self.active_admissions);

        let request_states = {
            let mut request_states = self
                .request_states
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *request_states)
        };
        for state in request_states.into_values() {
            StreamableHttpRequestCancellation { state }.cancel();
        }

        let mut mailbox = self
            .mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mailbox.queue.clear();
        mailbox.retained_bytes = 0;
        self.pending_count.store(0, Ordering::Release);
    }

    /// Returns whether the owner or shared response producer has closed.
    ///
    /// Matching responses admitted before closure remain drainable.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        !self.owner_open.load(Ordering::Acquire) || !self.admissions_open.load(Ordering::Acquire)
    }

    /// Binds an SSE response consumer to one request's outbound messages.
    ///
    /// The returned stream carries the request ID internally, so an HTTP
    /// response body cannot accidentally consume another in-flight request's
    /// notifications or terminal response. Dropping it requests cancellation
    /// through the paired guard; request handlers retain that guard and
    /// checkpoint it before committing further work or writes.
    #[must_use]
    pub fn for_request(
        &self,
        request_id: RequestId,
    ) -> Result<StreamableHttpRequestResponseStream, TransportError> {
        // Registering a request body is itself a response-side admission. It
        // must share the close barrier with response commits: otherwise a
        // listener shutdown could leave a newly registered body waiting on a
        // stream that can no longer produce its terminal response.
        let _admission =
            begin_streamable_admission(&self.admissions_open, &self.active_admissions)?;
        if !self.owner_open.load(Ordering::Acquire) {
            return Err(TransportError::Closed);
        }

        let state = Arc::new(StreamableHttpRequestCancellationState {
            request_id: request_id.clone(),
            cancelled: AtomicBool::new(false),
            terminal_committed: AtomicBool::new(false),
            response_commit_gate: Mutex::new(()),
            request_cancellation: McpRequestCancellation::new(),
        });
        let mut request_states = match self.request_states.try_lock() {
            Ok(request_states) => request_states,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(streamable_queue_full_error(
                    "streamable HTTP request-response registry is busy",
                ));
            }
        };
        if request_states.contains_key(&request_id) {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "streamable HTTP request already has a live response body",
            )));
        }
        let mailbox = match self.mailbox.try_lock() {
            Ok(mailbox) => mailbox,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(streamable_queue_full_error(
                    "streamable HTTP response mailbox is busy",
                ));
            }
        };
        if mailbox
            .queue
            .iter()
            .any(|queued| queued.request_id.as_ref() == Some(&request_id))
        {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "streamable HTTP response is already queued for this request ID",
            )));
        }
        drop(mailbox);
        request_states.insert(request_id.clone(), Arc::clone(&state));
        Ok(StreamableHttpRequestResponseStream {
            responses: self.clone(),
            request_id,
            request_states: Arc::clone(&self.request_states),
            cancellation: StreamableHttpRequestCancellation { state },
            finished: AtomicBool::new(false),
        })
    }
}

/// Request-owned cancellation guard paired with a response stream.
///
/// A handler keeps a clone of this guard while it performs request work. A
/// peer disconnect drops the response body, which marks the guard cancelled;
/// the handler then observes [`TransportError::Cancelled`] at its next
/// explicit checkpoint before it can commit another response-side effect.
#[derive(Clone, Debug)]
pub struct StreamableHttpRequestCancellation {
    state: Arc<StreamableHttpRequestCancellationState>,
}

#[derive(Debug)]
struct StreamableHttpRequestCancellationState {
    request_id: RequestId,
    cancelled: AtomicBool,
    terminal_committed: AtomicBool,
    response_commit_gate: Mutex<()>,
    request_cancellation: McpRequestCancellation,
}

impl StreamableHttpRequestCancellation {
    fn cancel(&self) {
        let _commit_gate = self
            .state
            .response_commit_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.state.cancelled.store(true, Ordering::Release);
        self.state.request_cancellation.cancel();
    }

    fn with_message_commit<T>(
        &self,
        cx: &Cx,
        terminal: bool,
        commit: impl FnOnce() -> Result<T, TransportError>,
    ) -> Result<T, TransportError> {
        self.checkpoint(cx)?;
        if self.is_terminal_committed() {
            return Err(TransportError::Closed);
        }
        let _commit_gate = match self.state.response_commit_gate.try_lock() {
            Ok(commit_gate) => commit_gate,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(streamable_queue_full_error(
                    "streamable request response commit is busy",
                ));
            }
        };
        self.checkpoint(cx)?;
        if self.is_terminal_committed() {
            return Err(TransportError::Closed);
        }
        let committed = commit()?;
        if terminal {
            self.state.terminal_committed.store(true, Ordering::Release);
        }
        Ok(committed)
    }

    /// Returns whether the request response body has been dropped or finished.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    /// Returns whether a terminal response has already been committed.
    #[must_use]
    pub fn is_terminal_committed(&self) -> bool {
        self.state.terminal_committed.load(Ordering::Acquire)
    }

    /// Returns the only JSON-RPC response ID this request guard may commit.
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.state.request_id
    }

    /// Returns the server request-cancellation domain paired with this HTTP
    /// response body. Dropping the body cancels this domain before it can
    /// admit a later handler effect.
    #[must_use]
    pub fn request_cancellation(&self) -> McpRequestCancellation {
        self.state.request_cancellation.clone()
    }

    /// Observes caller cancellation and the request response body's lifetime.
    ///
    /// Callers must checkpoint again after any independently cancellable work
    /// and immediately before committing a response-side effect.
    pub fn checkpoint(&self, cx: &Cx) -> Result<(), TransportError> {
        http_checkpoint(cx)?;
        if self.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        Ok(())
    }
}

/// Per-request consumer for one Streamable HTTP response body.
///
/// This abstraction owns the response's correlation ID and its cancellation
/// guard. It intentionally has no `Clone` implementation: one dropped HTTP
/// response body has one cancellation decision for its request, while handlers
/// can clone only the accompanying [`StreamableHttpRequestCancellation`] guard.
pub struct StreamableHttpRequestResponseStream {
    responses: StreamableHttpResponseStream,
    request_id: RequestId,
    request_states: Arc<Mutex<HashMap<RequestId, Arc<StreamableHttpRequestCancellationState>>>>,
    cancellation: StreamableHttpRequestCancellation,
    finished: AtomicBool,
}

/// Cloneable producer for one request-owned Streamable HTTP response body.
///
/// Producers can emit ordered notifications and the one terminal response
/// without owning the body itself. Once the body is dropped, the paired
/// cancellation state rejects every later producer effect.
#[derive(Clone)]
pub struct StreamableHttpRequestResponseSender {
    responses: StreamableHttpResponseStream,
    cancellation: StreamableHttpRequestCancellation,
}

impl Drop for StreamableHttpRequestResponseStream {
    fn drop(&mut self) {
        self.finish();
    }
}

impl StreamableHttpRequestResponseStream {
    fn finish(&self) {
        if !self.finished.swap(true, Ordering::AcqRel) {
            self.cancellation.cancel();
            let mut request_states = self
                .request_states
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if request_states
                .get(&self.request_id)
                .is_some_and(|state| Arc::ptr_eq(state, &self.cancellation.state))
            {
                request_states.remove(&self.request_id);
            }
            drop(request_states);
            self.responses.discard_request_messages(&self.request_id);
        }
    }

    /// Returns a cancellation guard for the request handler that owns this
    /// response body.
    #[must_use]
    pub fn cancellation(&self) -> StreamableHttpRequestCancellation {
        self.cancellation.clone()
    }

    /// Returns a producer for this exact request body.
    ///
    /// The producer preserves the body's ordering and request ownership while
    /// allowing request work to run independently from socket streaming.
    #[must_use]
    pub fn sender(&self) -> StreamableHttpRequestResponseSender {
        StreamableHttpRequestResponseSender {
            responses: self.responses.clone(),
            cancellation: self.cancellation(),
        }
    }

    /// Returns the request ID bound to this response body.
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns whether this response body has reached its terminal state.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    /// Pops the next notification or terminal response for this request body
    /// without blocking.
    ///
    /// Messages are emitted in commit order for this exact request. Receiving
    /// the terminal response finishes the body; subsequent calls fail closed.
    pub fn pop_message(
        &self,
    ) -> Result<Option<StreamableHttpRequestResponseMessage>, TransportError> {
        if self.is_finished() {
            return Err(TransportError::Closed);
        }
        if self.cancellation.is_cancelled() {
            return Err(TransportError::Cancelled);
        }

        let message = self.responses.pop_request_message(&self.request_id)?;
        if matches!(
            message,
            Some(StreamableHttpRequestResponseMessage::Response(_))
        ) {
            self.finish();
        }
        Ok(message)
    }

    /// Waits for the next notification or terminal response while observing
    /// both caller cancellation and this response body's lifetime.
    pub fn recv_message(
        &self,
        cx: &Cx,
    ) -> Result<StreamableHttpRequestResponseMessage, TransportError> {
        loop {
            self.cancellation.checkpoint(cx)?;
            match self.pop_message() {
                Ok(Some(message)) => return Ok(message),
                Ok(None) => {}
                Err(error) if is_would_block(&error) => {}
                Err(error) => return Err(error),
            }
            std::thread::sleep(self.responses.poll_interval);
        }
    }

    /// Pops the bound request's final response without blocking.
    ///
    /// A pending notification must be consumed through [`Self::pop_message`]
    /// before this compatibility method can receive the terminal response.
    /// A completed response is terminal for this body. Subsequent calls fail
    /// closed rather than allowing a second final response for the request.
    pub fn pop_response(&self) -> Result<Option<JsonRpcResponse>, TransportError> {
        if self.is_finished() {
            return Err(TransportError::Closed);
        }
        if self.cancellation.is_cancelled() {
            return Err(TransportError::Cancelled);
        }

        let response = self.responses.pop_request_response(&self.request_id)?;
        if response.is_some() {
            self.finish();
        }
        Ok(response)
    }

    /// Waits for the bound request's final response while observing both the
    /// caller context and response-body cancellation.
    pub fn recv_response(&self, cx: &Cx) -> Result<JsonRpcResponse, TransportError> {
        loop {
            self.cancellation.checkpoint(cx)?;
            match self.pop_response() {
                Ok(Some(response)) => return Ok(response),
                Ok(None) => {}
                Err(error) if is_would_block(&error) => {}
                Err(error) => return Err(error),
            }
            std::thread::sleep(self.responses.poll_interval);
        }
    }
}

impl StreamableHttpRequestResponseSender {
    /// Returns the request cancellation domain paired with this producer.
    #[must_use]
    pub fn request_cancellation(&self) -> McpRequestCancellation {
        self.cancellation.request_cancellation()
    }

    /// Commits one notification before this body's terminal response.
    pub fn send_notification(
        &self,
        cx: &Cx,
        notification: JsonRpcRequest,
    ) -> Result<(), TransportError> {
        self.responses
            .send_notification_for_request(cx, &self.cancellation, notification)
    }

    /// Commits this body's one terminal response.
    pub fn send_response(&self, cx: &Cx, response: JsonRpcResponse) -> Result<(), TransportError> {
        self.responses
            .send_response_for_request(cx, &self.cancellation, response)
    }
}

fn try_pop_streamable_message(
    mailbox: &Mutex<StreamableResponseMailbox>,
    pending_count: &AtomicUsize,
    matches: impl Fn(&QueuedResponse) -> bool,
) -> Result<Option<QueuedResponse>, TransportError> {
    let mut mailbox = match mailbox.try_lock() {
        Ok(mailbox) => mailbox,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => {
            return Err(streamable_queue_full_error(
                "streamable response mailbox is busy",
            ));
        }
    };
    let Some(position) = mailbox.queue.iter().position(matches) else {
        return Ok(None);
    };
    let response = mailbox
        .queue
        .remove(position)
        .expect("response position was obtained from the same mailbox");
    debug_assert!(mailbox.retained_bytes >= response.serialized_bytes);
    mailbox.retained_bytes = mailbox
        .retained_bytes
        .saturating_sub(response.serialized_bytes);
    let previous = pending_count.fetch_sub(1, Ordering::AcqRel);
    debug_assert!(previous > 0, "response pending-count underflow");
    Ok(Some(response))
}

fn try_pop_streamable_response(
    mailbox: &Mutex<StreamableResponseMailbox>,
    pending_count: &AtomicUsize,
    matches: impl Fn(&JsonRpcResponse) -> bool,
) -> Result<Option<JsonRpcResponse>, TransportError> {
    let queued = try_pop_streamable_message(mailbox, pending_count, |queued| {
        matches!(
            &queued.message,
            StreamableHttpRequestResponseMessage::Response(response) if matches(response)
        )
    })?;
    Ok(queued.map(|queued| match queued.message {
        StreamableHttpRequestResponseMessage::Response(response) => response,
        StreamableHttpRequestResponseMessage::Notification(_) => {
            unreachable!("the response matcher cannot dequeue a notification")
        }
    }))
}

fn try_pop_streamable_request_response(
    mailbox: &Mutex<StreamableResponseMailbox>,
    pending_count: &AtomicUsize,
    request_id: &RequestId,
) -> Result<Option<JsonRpcResponse>, TransportError> {
    let mut mailbox = match mailbox.try_lock() {
        Ok(mailbox) => mailbox,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => {
            return Err(streamable_queue_full_error(
                "streamable response mailbox is busy",
            ));
        }
    };
    let Some(position) = mailbox
        .queue
        .iter()
        .position(|queued| queued.request_id.as_ref() == Some(request_id))
    else {
        return Ok(None);
    };
    if matches!(
        &mailbox.queue[position].message,
        StreamableHttpRequestResponseMessage::Notification(_)
    ) {
        return Err(TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a request-owned notification must be consumed before its terminal response",
        )));
    }
    let queued = mailbox
        .queue
        .remove(position)
        .expect("response position was obtained from the same mailbox");
    debug_assert!(mailbox.retained_bytes >= queued.serialized_bytes);
    mailbox.retained_bytes = mailbox
        .retained_bytes
        .saturating_sub(queued.serialized_bytes);
    let previous = pending_count.fetch_sub(1, Ordering::AcqRel);
    debug_assert!(previous > 0, "response pending-count underflow");
    match queued.message {
        StreamableHttpRequestResponseMessage::Response(response) => Ok(Some(response)),
        StreamableHttpRequestResponseMessage::Notification(_) => {
            unreachable!("notification messages return before they are removed")
        }
    }
}

fn release_streamable_bytes(retained_bytes: &AtomicUsize, serialized_bytes: usize) {
    let _ = retained_bytes.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(current.saturating_sub(serialized_bytes))
    });
}

fn http_checkpoint(cx: &Cx) -> Result<(), TransportError> {
    cx.checkpoint().map_err(|error| {
        use asupersync::{CancelKind, error::ErrorKind};

        match cx.cancel_reason().map(|reason| reason.kind) {
            Some(CancelKind::Deadline | CancelKind::Timeout) => TransportError::Timeout,
            Some(_) => TransportError::Cancelled,
            None => match error.kind() {
                ErrorKind::DeadlineExceeded | ErrorKind::CancelTimeout => TransportError::Timeout,
                ErrorKind::Cancelled
                | ErrorKind::PollQuotaExhausted
                | ErrorKind::CostQuotaExhausted => TransportError::Cancelled,
                _ => TransportError::Cancelled,
            },
        }
    })
}

fn is_would_block(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::Io(error) if error.kind() == std::io::ErrorKind::WouldBlock
    )
}

fn streamable_queue_full_error(message: &'static str) -> TransportError {
    TransportError::Io(std::io::Error::new(std::io::ErrorKind::WouldBlock, message))
}

fn map_streamable_send_error<T>(
    error: mpsc::SendError<T>,
    full_message: &'static str,
) -> TransportError {
    match error {
        mpsc::SendError::Disconnected(_) => TransportError::Closed,
        mpsc::SendError::Cancelled(_) => TransportError::Cancelled,
        mpsc::SendError::Full(_) => TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            full_message,
        )),
    }
}

fn reserve_streamable_bytes(
    retained_bytes: &AtomicUsize,
    max_queued_bytes: usize,
    serialized_bytes: usize,
    admissions_open: &AtomicBool,
    cx: &Cx,
    full_message: &'static str,
) -> Result<(), TransportError> {
    let mut current = retained_bytes.load(Ordering::Acquire);
    loop {
        if !admissions_open.load(Ordering::Acquire) {
            return Err(TransportError::Closed);
        }
        let prospective = current
            .checked_add(serialized_bytes)
            .filter(|bytes| *bytes <= max_queued_bytes)
            .ok_or_else(|| streamable_queue_full_error(full_message))?;
        match retained_bytes.compare_exchange_weak(
            current,
            prospective,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(observed) => {
                current = observed;
                http_checkpoint(cx)?;
            }
        }
    }
}

fn enqueue_streamable_request(
    codec: &Codec,
    sender: &mpsc::Sender<QueuedRequest>,
    retained_bytes: &AtomicUsize,
    max_queued_bytes: usize,
    admissions_open: &AtomicBool,
    active_admissions: &AtomicUsize,
    cx: &Cx,
    request: JsonRpcRequest,
) -> Result<(), TransportError> {
    if !admissions_open.load(Ordering::Acquire) {
        return Err(TransportError::Closed);
    }
    http_checkpoint(cx)?;
    let _admission = begin_streamable_admission(admissions_open, active_admissions)?;

    let serialized_bytes = codec.encode_request(&request)?.len();
    // Encoding is bounded but can still be substantial. Re-check after that
    // CPU work so a deadline or cancellation raised during encoding wins
    // before the request acquires queue reservations.
    http_checkpoint(cx)?;
    reserve_streamable_bytes(
        retained_bytes,
        max_queued_bytes,
        serialized_bytes,
        admissions_open,
        cx,
        "streamable request byte budget is full",
    )?;
    if let Err(error) = sender.try_send(QueuedRequest {
        message: request,
        serialized_bytes,
    }) {
        release_streamable_bytes(retained_bytes, serialized_bytes);
        let disconnected = matches!(&error, mpsc::SendError::Disconnected(_));
        let error = map_streamable_send_error(error, "streamable request queue is full");
        if disconnected {
            admissions_open.store(false, Ordering::Release);
        }
        return Err(error);
    }
    Ok(())
}

/// Streaming HTTP transport for long-lived MCP connections.
///
/// This transport uses HTTP streaming (chunked transfer encoding) for
/// server-to-client messages and regular POST requests for client-to-server
/// messages.
pub struct StreamableHttpTransport {
    /// Shared typed-message validation and serialized-size boundary.
    codec: Codec,
    /// Bounded request channel (from HTTP POST requests).
    request_sender: Option<mpsc::Sender<QueuedRequest>>,
    request_receiver: mpsc::Receiver<QueuedRequest>,
    request_retained_bytes: Arc<AtomicUsize>,
    request_endpoint_count: Arc<AtomicUsize>,
    request_admissions_open: Arc<AtomicBool>,
    request_active_admissions: Arc<AtomicUsize>,
    /// Bounded, correlation-aware response mailbox.
    response_mailbox: Arc<Mutex<StreamableResponseMailbox>>,
    /// Live request-owned response bodies keyed by their JSON-RPC request ID.
    request_response_states:
        Arc<Mutex<HashMap<RequestId, Arc<StreamableHttpRequestCancellationState>>>>,
    response_pending_count: Arc<AtomicUsize>,
    response_endpoint_count: Arc<AtomicUsize>,
    response_active_admissions: Arc<AtomicUsize>,
    response_admissions_open: Arc<AtomicBool>,
    response_externalized: bool,
    capacity: usize,
    max_queued_bytes_per_direction: usize,
    /// Whether the transport owner remains open.
    owner_open: Arc<AtomicBool>,
    /// Poll interval for checking new messages.
    poll_interval: Duration,
    #[cfg(test)]
    request_empty_polls: Arc<AtomicUsize>,
    #[cfg(test)]
    response_empty_polls: Arc<AtomicUsize>,
    #[cfg(test)]
    response_entered_empty_waits: Arc<AtomicUsize>,
}

impl StreamableHttpTransport {
    /// Creates a new streaming HTTP transport.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_STREAMABLE_QUEUE_CAPACITY)
            .expect("the built-in streamable HTTP queue capacity must be valid")
    }

    /// Creates a streaming HTTP transport with bounded queues in both directions.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error when `capacity` is zero or exceeds the
    /// hard queue-count limit.
    pub fn with_capacity(capacity: usize) -> Result<Self, TransportError> {
        Self::with_queue_limits(capacity, MAX_STREAMABLE_QUEUED_BYTES_PER_DIRECTION)
    }

    fn with_queue_limits(
        capacity: usize,
        max_queued_bytes_per_direction: usize,
    ) -> Result<Self, TransportError> {
        if capacity == 0 || capacity > MAX_STREAMABLE_QUEUE_CAPACITY {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "streamable HTTP queue capacity is outside the supported range",
            )));
        }
        if max_queued_bytes_per_direction == 0
            || max_queued_bytes_per_direction > MAX_STREAMABLE_QUEUED_BYTES_PER_DIRECTION
        {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "streamable HTTP queue byte limit is outside the supported range",
            )));
        }

        let (request_sender, request_receiver) = mpsc::channel(capacity);
        Ok(Self {
            codec: Codec::new(),
            request_sender: Some(request_sender),
            request_receiver,
            request_retained_bytes: Arc::new(AtomicUsize::new(0)),
            request_endpoint_count: Arc::new(AtomicUsize::new(0)),
            request_admissions_open: Arc::new(AtomicBool::new(true)),
            request_active_admissions: Arc::new(AtomicUsize::new(0)),
            response_mailbox: Arc::new(Mutex::new(StreamableResponseMailbox::new())),
            request_response_states: Arc::new(Mutex::new(HashMap::new())),
            response_pending_count: Arc::new(AtomicUsize::new(0)),
            response_endpoint_count: Arc::new(AtomicUsize::new(0)),
            response_active_admissions: Arc::new(AtomicUsize::new(0)),
            response_admissions_open: Arc::new(AtomicBool::new(true)),
            response_externalized: false,
            capacity,
            max_queued_bytes_per_direction,
            owner_open: Arc::new(AtomicBool::new(true)),
            poll_interval: Duration::from_millis(10),
            #[cfg(test)]
            request_empty_polls: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            response_empty_polls: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            response_entered_empty_waits: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Returns a cloneable request-ingress handle for HTTP handler threads.
    ///
    /// The handle captures the transport's current message-size limit and
    /// shares its queue count, byte accounting, and close state. Each admission
    /// observes cancellation through the supplied [`Cx`].
    ///
    /// # Errors
    ///
    /// Returns `AlreadyExists` after the request endpoint has already been
    /// externalized, or [`TransportError::Closed`] after owner shutdown.
    pub fn request_ingress(&mut self) -> Result<StreamableHttpRequestIngress, TransportError> {
        if !self.owner_open.load(Ordering::Acquire) {
            return Err(TransportError::Closed);
        }
        let sender = self.request_sender.take().ok_or_else(|| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "streamable HTTP request ingress has already been externalized",
            ))
        })?;
        self.request_endpoint_count.store(1, Ordering::Release);
        let mut codec = Codec::new();
        codec.set_max_message_size(self.codec.max_message_size());
        Ok(StreamableHttpRequestIngress {
            codec,
            sender,
            retained_bytes: Arc::clone(&self.request_retained_bytes),
            max_queued_bytes: self.max_queued_bytes_per_direction,
            endpoint_count: Arc::clone(&self.request_endpoint_count),
            admissions_open: Arc::clone(&self.request_admissions_open),
            active_admissions: Arc::clone(&self.request_active_admissions),
        })
    }

    /// Returns a cloneable response consumer for HTTP streaming threads.
    ///
    /// Multiple clones may wait for different request IDs without consuming
    /// one another's responses.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyExists` after the response endpoint has already been
    /// externalized, or [`TransportError::Closed`] after owner shutdown.
    pub fn response_stream(&mut self) -> Result<StreamableHttpResponseStream, TransportError> {
        if !self.owner_open.load(Ordering::Acquire) {
            return Err(TransportError::Closed);
        }
        if self.response_externalized {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "streamable HTTP response stream has already been externalized",
            )));
        }
        self.response_externalized = true;
        self.response_endpoint_count.store(1, Ordering::Release);
        Ok(StreamableHttpResponseStream {
            codec: response_stream_codec(&self.codec),
            mailbox: Arc::clone(&self.response_mailbox),
            request_states: Arc::clone(&self.request_response_states),
            pending_count: Arc::clone(&self.response_pending_count),
            endpoint_count: Arc::clone(&self.response_endpoint_count),
            active_admissions: Arc::clone(&self.response_active_admissions),
            capacity: self.capacity(),
            max_queued_bytes: self.max_queued_bytes_per_direction,
            owner_open: Arc::clone(&self.owner_open),
            admissions_open: Arc::clone(&self.response_admissions_open),
            poll_interval: self.poll_interval,
            #[cfg(test)]
            empty_polls: Arc::clone(&self.response_empty_polls),
            #[cfg(test)]
            entered_empty_waits: Arc::clone(&self.response_entered_empty_waits),
        })
    }

    /// Returns the external producer/consumer handles used around a running
    /// transport.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyExists` unless both endpoints remain owner-held, or
    /// [`TransportError::Closed`] after owner shutdown.
    pub fn split_handles(
        &mut self,
    ) -> Result<(StreamableHttpRequestIngress, StreamableHttpResponseStream), TransportError> {
        if self.request_sender.is_none() || self.response_externalized {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "streamable HTTP endpoints have already been externalized",
            )));
        }
        let ingress = self.request_ingress()?;
        let response_stream = self.response_stream()?;
        Ok((ingress, response_stream))
    }

    /// Pushes a request into the bounded queue (from an HTTP handler).
    ///
    /// The operation rejects overload with `WouldBlock`; it never grows the
    /// queue beyond the configured capacity.
    pub fn push_request(&self, cx: &Cx, request: JsonRpcRequest) -> Result<(), TransportError> {
        let sender = self.request_sender.as_ref().ok_or(TransportError::Closed)?;
        enqueue_streamable_request(
            &self.codec,
            sender,
            &self.request_retained_bytes,
            self.max_queued_bytes_per_direction,
            &self.request_admissions_open,
            &self.request_active_admissions,
            cx,
            request,
        )
    }

    /// Pops a response from the queue (for HTTP streaming).
    pub fn pop_response(&self) -> Result<Option<JsonRpcResponse>, TransportError> {
        if self.response_externalized {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the response consumer has been externalized",
            )));
        }
        if let Some(response) = try_pop_streamable_response(
            &self.response_mailbox,
            &self.response_pending_count,
            |_| true,
        )? {
            return Ok(Some(response));
        }
        if !self.response_admissions_open.load(Ordering::Acquire)
            && self.response_active_admissions.load(Ordering::SeqCst) == 0
        {
            // Stabilize the empty observation against a producer that
            // committed immediately before dropping the final admission.
            match try_pop_streamable_response(
                &self.response_mailbox,
                &self.response_pending_count,
                |_| true,
            )? {
                Some(response) => Ok(Some(response)),
                None => Err(TransportError::Closed),
            }
        } else {
            Ok(None)
        }
    }

    /// Checks if there are pending responses.
    #[must_use]
    pub fn has_responses(&self) -> bool {
        self.response_pending_count.load(Ordering::Acquire) > 0
    }

    /// Returns the number of admitted requests awaiting dispatch.
    #[must_use]
    pub fn pending_requests(&self) -> usize {
        self.request_receiver.len()
    }

    /// Returns the number of admitted responses awaiting streaming.
    #[must_use]
    pub fn pending_responses(&self) -> usize {
        self.response_pending_count.load(Ordering::Acquire)
    }

    /// Returns the hard queue capacity used in each direction.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn request_response_guard_is_active(
        &self,
        cancellation: &StreamableHttpRequestCancellation,
    ) -> Result<bool, TransportError> {
        let request_states = match self.request_response_states.try_lock() {
            Ok(request_states) => request_states,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(streamable_queue_full_error(
                    "streamable HTTP request-response registry is busy",
                ));
            }
        };
        Ok(request_states
            .get(cancellation.request_id())
            .is_some_and(|state| Arc::ptr_eq(state, &cancellation.state)))
    }

    fn response_is_bound_to_live_request(
        &self,
        response: &JsonRpcResponse,
    ) -> Result<bool, TransportError> {
        let Some(request_id) = response.id.as_ref() else {
            return Ok(false);
        };
        let request_states = match self.request_response_states.try_lock() {
            Ok(request_states) => request_states,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(streamable_queue_full_error(
                    "streamable HTTP request-response registry is busy",
                ));
            }
        };
        Ok(request_states.contains_key(request_id))
    }

    /// Commits a final response for one live request response body.
    ///
    /// The guard binds the response ID to its request and closes the request's
    /// response-commit gate before a dropped body returns. This prevents a
    /// disconnected request from committing a late response while retaining
    /// the transport's existing count and byte backpressure limits.
    pub fn send_response_for_request(
        &mut self,
        cx: &Cx,
        cancellation: &StreamableHttpRequestCancellation,
        response: JsonRpcResponse,
    ) -> Result<(), TransportError> {
        if response.id.as_ref() != Some(cancellation.request_id()) {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "streamable HTTP response ID does not match its request response body",
            )));
        }
        cancellation.checkpoint(cx)?;
        if !self.request_response_guard_is_active(cancellation)? {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "streamable HTTP response guard does not belong to this live transport request",
            )));
        }
        cancellation.with_message_commit(cx, true, || {
            self.enqueue_message(
                cx,
                Some(cancellation.request_id().clone()),
                StreamableHttpRequestResponseMessage::Response(response),
                Some(cancellation),
            )
        })
    }

    /// Commits one server-to-client notification for one live modern SSE body.
    ///
    /// The request cancellation guard identifies the only body that can emit
    /// this notification. The shared bounded outbound queue provides
    /// backpressure, while the request-local commit gate keeps notifications
    /// ordered before the body's one terminal response.
    pub fn send_notification_for_request(
        &mut self,
        cx: &Cx,
        cancellation: &StreamableHttpRequestCancellation,
        notification: JsonRpcRequest,
    ) -> Result<(), TransportError> {
        if !notification.is_notification() {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "streamable HTTP request-owned messages must be JSON-RPC notifications",
            )));
        }
        cancellation.checkpoint(cx)?;
        if !self.request_response_guard_is_active(cancellation)? {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "streamable HTTP notification guard does not belong to this live transport request",
            )));
        }
        cancellation.with_message_commit(cx, false, || {
            self.enqueue_message(
                cx,
                Some(cancellation.request_id().clone()),
                StreamableHttpRequestResponseMessage::Notification(notification),
                Some(cancellation),
            )
        })
    }

    fn enqueue_message(
        &mut self,
        cx: &Cx,
        request_id: Option<RequestId>,
        message: StreamableHttpRequestResponseMessage,
        request_cancellation: Option<&StreamableHttpRequestCancellation>,
    ) -> Result<(), TransportError> {
        if !self.owner_open.load(Ordering::Acquire)
            || !self.response_admissions_open.load(Ordering::Acquire)
        {
            return Err(TransportError::Closed);
        }
        http_checkpoint(cx)?;
        if let Some(cancellation) = request_cancellation {
            cancellation.checkpoint(cx)?;
        }
        // Validate before retaining a clone in the bounded queue. The codec
        // bounds each message's serialized size, while the retained-byte
        // counter bounds the aggregate queue footprint.
        let _admission = begin_streamable_admission(
            &self.response_admissions_open,
            &self.response_active_admissions,
        )?;
        let serialized_bytes = match &message {
            StreamableHttpRequestResponseMessage::Notification(notification) => {
                self.codec.encode_request(notification)?.len()
            }
            StreamableHttpRequestResponseMessage::Response(response) => {
                self.codec.encode_response(response)?.len()
            }
        };
        // Do not commit a response after cancellation or a deadline that
        // became observable during bounded serialization.
        http_checkpoint(cx)?;
        if let Some(cancellation) = request_cancellation {
            cancellation.checkpoint(cx)?;
        }
        let mut mailbox = match self.response_mailbox.try_lock() {
            Ok(mailbox) => mailbox,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(streamable_queue_full_error(
                    "streamable response mailbox is busy",
                ));
            }
        };
        if !self.owner_open.load(Ordering::Acquire)
            || !self.response_admissions_open.load(Ordering::Acquire)
        {
            return Err(TransportError::Closed);
        }
        if let Some(cancellation) = request_cancellation {
            cancellation.checkpoint(cx)?;
        }
        if mailbox.queue.len() >= self.capacity {
            return Err(streamable_queue_full_error(
                "streamable response queue is full",
            ));
        }
        let prospective = mailbox
            .retained_bytes
            .checked_add(serialized_bytes)
            .filter(|bytes| *bytes <= self.max_queued_bytes_per_direction)
            .ok_or_else(|| {
                streamable_queue_full_error("streamable response byte budget is full")
            })?;
        mailbox.queue.push_back(QueuedResponse {
            request_id,
            message,
            serialized_bytes,
        });
        mailbox.retained_bytes = prospective;
        self.response_pending_count.fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn release_request_bytes(&self, serialized_bytes: usize) {
        release_streamable_bytes(&self.request_retained_bytes, serialized_bytes);
    }

    fn close_queues(&mut self) {
        self.owner_open.store(false, Ordering::Release);
        close_streamable_admissions(
            &self.request_admissions_open,
            &self.request_active_admissions,
        );
        close_streamable_admissions(
            &self.response_admissions_open,
            &self.response_active_admissions,
        );
        self.request_sender.take();
        self.request_receiver.close();
        while let Ok(request) = self.request_receiver.try_recv() {
            self.release_request_bytes(request.serialized_bytes);
        }
        // Outbound responses are deliberately retained. `Transport::close`
        // first settles bounded in-flight admissions and seals production;
        // extant response-stream handles can then drain the bounded mailbox.
    }
}

impl Drop for StreamableHttpTransport {
    fn drop(&mut self) {
        self.close_queues();
    }
}

impl Default for StreamableHttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for StreamableHttpTransport {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        if !self.owner_open.load(Ordering::Acquire)
            || !self.response_admissions_open.load(Ordering::Acquire)
        {
            return Err(TransportError::Closed);
        }
        http_checkpoint(cx)?;

        match message {
            JsonRpcMessage::Response(response) => {
                if self.response_is_bound_to_live_request(response)? {
                    return Err(TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "request-bound Streamable HTTP responses must use send_response_for_request",
                    )));
                }
                self.enqueue_message(
                    cx,
                    response.id.clone(),
                    StreamableHttpRequestResponseMessage::Response(response.clone()),
                    None,
                )?;
            }
            JsonRpcMessage::Request(_) => {
                // A server-to-client notification needs a request-owned modern
                // SSE body. The generic transport trait has no such owner, so
                // fail closed rather than routing it to another active stream.
                return Err(TransportError::Io(std::io::Error::other(
                    "StreamableHttpTransport requires a request-owned guard for server-to-client notifications",
                )));
            }
        }

        Ok(())
    }

    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        // Poll for requests
        loop {
            if !self.owner_open.load(Ordering::Acquire) {
                return Err(TransportError::Closed);
            }
            http_checkpoint(cx)?;

            match self.request_receiver.try_recv() {
                Ok(request) => {
                    self.release_request_bytes(request.serialized_bytes);
                    return Ok(JsonRpcMessage::Request(request.message));
                }
                Err(mpsc::RecvError::Empty) => {}
                Err(mpsc::RecvError::Disconnected) => {
                    self.request_admissions_open.store(false, Ordering::Release);
                    return Err(TransportError::Closed);
                }
                Err(mpsc::RecvError::Cancelled) => return Err(TransportError::Cancelled),
            }

            if !self.request_admissions_open.load(Ordering::Acquire)
                && self.request_active_admissions.load(Ordering::SeqCst) == 0
            {
                // A producer admitted before closure can enqueue between the
                // first empty observation and dropping its admission guard.
                // With the gate closed and no active producers, one final
                // receive makes the terminal decision stable.
                return match self.request_receiver.try_recv() {
                    Ok(request) => {
                        self.release_request_bytes(request.serialized_bytes);
                        Ok(JsonRpcMessage::Request(request.message))
                    }
                    Err(mpsc::RecvError::Empty | mpsc::RecvError::Disconnected) => {
                        Err(TransportError::Closed)
                    }
                    Err(mpsc::RecvError::Cancelled) => Err(TransportError::Cancelled),
                };
            }

            #[cfg(test)]
            self.request_empty_polls.fetch_add(1, Ordering::Release);

            // Sleep briefly before polling again
            std::thread::sleep(self.poll_interval);
        }
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.close_queues();
        Ok(())
    }
}

// =============================================================================
// Dual-era HTTP/SSE endpoint composition
// =============================================================================

/// Configuration for one endpoint that serves modern Streamable HTTP and
/// exact MCP 2024-11-05 SSE clients side by side.
#[derive(Debug, Clone)]
pub struct DualEraHttpEndpointConfig {
    /// GET route for the legacy SSE event stream.
    pub legacy_sse_path: String,
    /// POST route advertised to the legacy SSE client by its first event.
    pub legacy_message_path: String,
    /// Plain-HTTP origin used to construct the opaque legacy POST URI.
    pub legacy_origin: String,
    /// Maximum legacy POST requests retained before application dispatch.
    pub legacy_request_capacity: usize,
}

impl DualEraHttpEndpointConfig {
    /// Creates a configuration with bounded defaults for the two legacy routes.
    #[must_use]
    pub fn new(
        legacy_sse_path: impl Into<String>,
        legacy_message_path: impl Into<String>,
        legacy_origin: impl Into<String>,
    ) -> Self {
        Self {
            legacy_sse_path: legacy_sse_path.into(),
            legacy_message_path: legacy_message_path.into(),
            legacy_origin: legacy_origin.into(),
            legacy_request_capacity: DEFAULT_STREAMABLE_QUEUE_CAPACITY,
        }
    }
}

/// Failure while constructing or operating a [`DualEraHttpEndpoint`].
#[derive(Debug)]
pub enum DualEraHttpEndpointError {
    /// The endpoint configuration does not provide disjoint, valid routes.
    InvalidConfiguration(String),
    /// Modern HTTP admission failed.
    Http(HttpError),
    /// A bounded transport operation failed.
    Transport(TransportError),
    /// The session identifier could not be generated.
    Session(HttpSessionError),
    /// The session has been closed and can no longer admit work.
    Closed,
}

impl std::fmt::Display for DualEraHttpEndpointError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(
                    formatter,
                    "invalid dual-era HTTP endpoint configuration: {message}"
                )
            }
            Self::Http(error) => write!(formatter, "modern HTTP admission failed: {error}"),
            Self::Transport(error) => write!(formatter, "HTTP transport failed: {error}"),
            Self::Session(error) => write!(formatter, "HTTP session setup failed: {error}"),
            Self::Closed => formatter.write_str("dual-era HTTP session is closed"),
        }
    }
}

impl std::error::Error for DualEraHttpEndpointError {}

impl From<HttpError> for DualEraHttpEndpointError {
    fn from(error: HttpError) -> Self {
        Self::Http(error)
    }
}

impl From<TransportError> for DualEraHttpEndpointError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<CodecError> for DualEraHttpEndpointError {
    fn from(error: CodecError) -> Self {
        Self::Transport(TransportError::Codec(error))
    }
}

impl From<HttpSessionError> for DualEraHttpEndpointError {
    fn from(error: HttpSessionError) -> Self {
        Self::Session(error)
    }
}

/// A public endpoint composition for modern Streamable HTTP and legacy SSE.
///
/// The modern route is owned by the supplied [`HttpRequestHandler`]. The two
/// legacy routes remain explicit and disjoint: one GET opens the SSE stream,
/// while the exact POST URI advertised in its first event is the only ingress
/// for legacy client requests.
pub struct DualEraHttpEndpoint {
    handler: Arc<HttpRequestHandler>,
    config: DualEraHttpEndpointConfig,
}

impl DualEraHttpEndpoint {
    /// Validates a dual-era endpoint configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when any route is malformed or overlaps another route,
    /// when the legacy origin cannot be used by [`LegacySseHttpPostSink`], or
    /// when the configured legacy request queue bound is invalid.
    pub fn new(
        handler: HttpRequestHandler,
        config: DualEraHttpEndpointConfig,
    ) -> Result<Self, DualEraHttpEndpointError> {
        validate_dual_era_path("legacy SSE route", &config.legacy_sse_path)?;
        validate_dual_era_path("legacy message route", &config.legacy_message_path)?;
        validate_legacy_http_origin(&config.legacy_origin)?;
        if config.legacy_request_capacity == 0
            || config.legacy_request_capacity > MAX_STREAMABLE_QUEUE_CAPACITY
        {
            return Err(DualEraHttpEndpointError::InvalidConfiguration(
                "legacy request capacity is outside the supported range".to_string(),
            ));
        }
        let modern_path = &handler.config().base_path;
        if config.legacy_sse_path == config.legacy_message_path
            || config.legacy_sse_path == *modern_path
            || config.legacy_message_path == *modern_path
        {
            return Err(DualEraHttpEndpointError::InvalidConfiguration(
                "modern, legacy SSE, and legacy POST routes must be distinct".to_string(),
            ));
        }
        Ok(Self {
            handler: Arc::new(handler),
            config,
        })
    }

    /// Opens one independently bounded endpoint session.
    ///
    /// The session owns its modern request/response transport, legacy request
    /// queue, and one live legacy SSE stream. Dropping or closing it clears all
    /// three deterministically.
    pub fn open_session(&self) -> Result<DualEraHttpSession, DualEraHttpEndpointError> {
        let session_id = generate_session_id()?;
        let mut transport =
            StreamableHttpTransport::with_capacity(self.config.legacy_request_capacity)?;
        let (modern_ingress, modern_responses) = transport.split_handles()?;
        let mut legacy_codec = Codec::new();
        legacy_codec.set_max_message_size(self.handler.config().max_body_size);
        let legacy_message_endpoint = format!(
            "{}{}?session_id={session_id}",
            self.config.legacy_origin, self.config.legacy_message_path
        );

        Ok(DualEraHttpSession {
            handler: Arc::clone(&self.handler),
            legacy_sse_path: self.config.legacy_sse_path.clone(),
            legacy_message_path: self.config.legacy_message_path.clone(),
            session_id: session_id.clone(),
            legacy_message_endpoint,
            legacy_request_capacity: self.config.legacy_request_capacity,
            legacy_requests: VecDeque::new(),
            legacy_codec,
            legacy_live_sender: None,
            legacy_live_active: Arc::new(AtomicBool::new(false)),
            legacy_live_pending: Arc::new(AtomicUsize::new(0)),
            modern_transport: transport,
            modern_ingress,
            modern_responses,
            closed: false,
        })
    }
}

fn validate_dual_era_path(label: &str, path: &str) -> Result<(), DualEraHttpEndpointError> {
    if !path.starts_with('/')
        || path.len() == 1
        || path
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0' | b'?' | b'#'))
    {
        return Err(DualEraHttpEndpointError::InvalidConfiguration(format!(
            "{label} must be a non-root absolute path without query, fragment, or control bytes"
        )));
    }
    Ok(())
}

fn validate_legacy_http_origin(origin: &str) -> Result<(), DualEraHttpEndpointError> {
    let Some(authority) = origin.strip_prefix("http://") else {
        return Err(DualEraHttpEndpointError::InvalidConfiguration(
            "legacy origin must use the plain HTTP scheme supported by the legacy POST sink"
                .to_string(),
        ));
    };
    if authority.is_empty()
        || authority.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || matches!(byte, b'/' | b'?' | b'#' | b'\\' | b'\r' | b'\n' | b'\0')
        })
    {
        return Err(DualEraHttpEndpointError::InvalidConfiguration(
            "legacy origin must contain exactly one nonempty HTTP authority".to_string(),
        ));
    }
    Ok(())
}

fn sse_http_response(body: Vec<u8>) -> HttpResponse {
    HttpResponse::new(HttpStatus::OK)
        .with_header("content-type", "text/event-stream")
        .with_header("cache-control", "no-cache")
        .with_header("connection", "keep-alive")
        .with_header("x-accel-buffering", "no")
        .with_body(body)
}

fn method_rejection(allowed: &str) -> HttpResponse {
    HttpResponse::new(HttpStatus::METHOD_NOT_ALLOWED).with_header("allow", allowed)
}

fn legacy_post_has_modern_binding_headers(request: &HttpRequest) -> bool {
    [
        "mcp-protocol-version",
        "mcp-method",
        "mcp-name",
        "mcp-session-id",
    ]
    .iter()
    .any(|name| request.header(name).is_some())
}

/// The externally renderable result of one [`DualEraHttpSession`] request.
pub enum DualEraHttpEndpointResponse {
    /// A complete HTTP response, including legacy POST responses.
    Immediate(HttpResponse),
    /// A modern JSON response that becomes available after application dispatch.
    ModernJson(DualEraHttpJsonResponse),
    /// A modern request-scoped SSE response body.
    ModernSse(DualEraHttpSseResponse),
    /// A live legacy SSE stream that begins with its endpoint.
    LegacySse(DualEraHttpLegacySseResponse),
}

/// One admitted modern JSON response awaiting its matching JSON-RPC response.
pub struct DualEraHttpJsonResponse {
    handler: Arc<HttpRequestHandler>,
    responses: StreamableHttpResponseStream,
    request_id: RequestId,
    origin: Option<String>,
}

impl DualEraHttpJsonResponse {
    /// Tries to render the one response bound to this modern request.
    ///
    /// `Ok(None)` means application dispatch has not yet committed its final
    /// response. The returned HTTP value has the normal JSON response headers.
    pub fn try_response(&self) -> Result<Option<HttpResponse>, DualEraHttpEndpointError> {
        let Some(response) = self.responses.pop_response(Some(&self.request_id))? else {
            return Ok(None);
        };
        Ok(Some(
            self.handler
                .try_create_response(&response, self.origin.as_deref())?,
        ))
    }
}

/// One finite modern SSE response body bound to its exact JSON-RPC request.
pub struct DualEraHttpSseResponse {
    response: HttpResponse,
    body: StreamableHttpRequestResponseStream,
    codec: Codec,
}

impl DualEraHttpSseResponse {
    /// Returns the HTTP status and headers to send before the finite SSE body.
    #[must_use]
    pub fn response(&self) -> &HttpResponse {
        &self.response
    }

    /// Returns the request-owned cancellation guard for application dispatch.
    #[must_use]
    pub fn cancellation(&self) -> StreamableHttpRequestCancellation {
        self.body.cancellation()
    }

    /// Returns a producer for notifications and the terminal response of this
    /// exact request-owned SSE body.
    #[must_use]
    pub fn sender(&self) -> StreamableHttpRequestResponseSender {
        self.body.sender()
    }

    /// Returns whether this body has emitted its terminal response.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.body.is_finished()
    }

    /// Tries to frame the next notification or terminal response as an SSE
    /// `message` event without blocking the caller's runtime worker.
    pub fn pop_event(&self) -> Result<Option<SseEvent>, DualEraHttpEndpointError> {
        let Some(message) = self.body.pop_message()? else {
            return Ok(None);
        };
        Self::frame_message(&self.codec, message).map(Some)
    }

    /// Receives and frames the next notification or terminal response as an
    /// SSE `message` event.
    ///
    /// Modern notifications and the final response are ordered within this
    /// request body. These events deliberately have no resumable ID because
    /// this request-scoped body is not resumable.
    pub fn recv_event(&self, cx: &Cx) -> Result<SseEvent, DualEraHttpEndpointError> {
        Self::frame_message(&self.codec, self.body.recv_message(cx)?)
    }

    fn frame_message(
        codec: &Codec,
        message: StreamableHttpRequestResponseMessage,
    ) -> Result<SseEvent, DualEraHttpEndpointError> {
        let mut encoded = match message {
            StreamableHttpRequestResponseMessage::Notification(notification) => {
                codec.encode_request(&notification)?
            }
            StreamableHttpRequestResponseMessage::Response(response) => {
                codec.encode_response(&response)?
            }
        };
        if encoded.pop() != Some(b'\n') {
            return Err(DualEraHttpEndpointError::Transport(TransportError::Io(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "JSON-RPC codec omitted its NDJSON delimiter",
                ),
            )));
        }
        let data = String::from_utf8(encoded).map_err(|error| {
            DualEraHttpEndpointError::Transport(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error,
            )))
        })?;
        Ok(SseEvent::message(data))
    }
}

struct LegacySseLiveMessage {
    data: String,
}

/// One live legacy SSE response body for an exact MCP 2024-11-05 session.
///
/// The stream starts with its endpoint event. Subsequent server messages arrive
/// only through the session that admitted this stream. Waiting for them checks
/// the caller context between bounded nonblocking channel polls.
pub struct DualEraHttpLegacySseResponse {
    response: HttpResponse,
    initial_events: VecDeque<SseEvent>,
    receiver: mpsc::Receiver<LegacySseLiveMessage>,
    active: Arc<AtomicBool>,
    pending: Arc<AtomicUsize>,
    poll_interval: Duration,
}

impl DualEraHttpLegacySseResponse {
    /// Returns the HTTP status and headers to send before the live SSE body.
    #[must_use]
    pub fn response(&self) -> &HttpResponse {
        &self.response
    }

    /// Receives the next endpoint or live legacy SSE event.
    ///
    /// Once the session or this response body closes, the method returns
    /// [`TransportError::Closed`].
    /// Non-blocking variant of [`Self::recv_event`]: returns `Ok(None)` when
    /// no event is ready, so async pumps can poll between yields without
    /// parking a blocking thread per live stream.
    pub fn try_recv_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<SseEvent>, DualEraHttpEndpointError> {
        http_checkpoint(cx)?;
        if !self.active.load(Ordering::Acquire) {
            return Err(DualEraHttpEndpointError::Transport(TransportError::Closed));
        }
        if let Some(event) = self.initial_events.pop_front() {
            return Ok(Some(event));
        }
        match self.receiver.try_recv() {
            Ok(message) => {
                let previous = self.pending.fetch_sub(1, Ordering::AcqRel);
                debug_assert!(previous > 0, "legacy SSE live-event count underflow");
                Ok(Some(SseEvent::message(message.data)))
            }
            Err(mpsc::RecvError::Empty) => Ok(None),
            Err(mpsc::RecvError::Disconnected) => {
                Err(DualEraHttpEndpointError::Transport(TransportError::Closed))
            }
            Err(mpsc::RecvError::Cancelled) => Err(DualEraHttpEndpointError::Transport(
                TransportError::Cancelled,
            )),
        }
    }

    pub fn recv_event(&mut self, cx: &Cx) -> Result<SseEvent, DualEraHttpEndpointError> {
        http_checkpoint(cx)?;
        if !self.active.load(Ordering::Acquire) {
            return Err(DualEraHttpEndpointError::Transport(TransportError::Closed));
        }
        if let Some(event) = self.initial_events.pop_front() {
            return Ok(event);
        }

        loop {
            http_checkpoint(cx)?;
            if !self.active.load(Ordering::Acquire) {
                return Err(DualEraHttpEndpointError::Transport(TransportError::Closed));
            }
            match self.receiver.try_recv() {
                Ok(message) => {
                    let previous = self.pending.fetch_sub(1, Ordering::AcqRel);
                    debug_assert!(previous > 0, "legacy SSE live-event count underflow");
                    return Ok(SseEvent::message(message.data));
                }
                Err(mpsc::RecvError::Empty) => {
                    // This poll loop runs on a blocking thread; without a
                    // pause it spins one core at 100% between events.
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(mpsc::RecvError::Disconnected) => {
                    return Err(DualEraHttpEndpointError::Transport(TransportError::Closed));
                }
                Err(mpsc::RecvError::Cancelled) => {
                    return Err(DualEraHttpEndpointError::Transport(
                        TransportError::Cancelled,
                    ));
                }
            }
            std::thread::sleep(self.poll_interval);
        }
    }
}

impl Drop for DualEraHttpLegacySseResponse {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        self.pending.store(0, Ordering::Release);
    }
}

/// A session combining modern Streamable HTTP with exact legacy SSE/POST flow.
pub struct DualEraHttpSession {
    handler: Arc<HttpRequestHandler>,
    legacy_sse_path: String,
    legacy_message_path: String,
    session_id: String,
    legacy_message_endpoint: String,
    legacy_request_capacity: usize,
    legacy_requests: VecDeque<JsonRpcRequest>,
    legacy_codec: Codec,
    legacy_live_sender: Option<mpsc::Sender<LegacySseLiveMessage>>,
    legacy_live_active: Arc<AtomicBool>,
    legacy_live_pending: Arc<AtomicUsize>,
    modern_transport: StreamableHttpTransport,
    modern_ingress: StreamableHttpRequestIngress,
    modern_responses: StreamableHttpResponseStream,
    closed: bool,
}

impl DualEraHttpSession {
    /// Returns the opaque session value required by the advertised legacy POST URI.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the exact legacy POST URI advertised in the first SSE event.
    #[must_use]
    pub fn legacy_message_endpoint(&self) -> &str {
        &self.legacy_message_endpoint
    }

    /// Returns whether this session has stopped admitting work.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Handles one request against exactly one modern or legacy route.
    ///
    /// Modern requests are admitted through the existing final HTTP boundary.
    /// Legacy GET returns a fresh live stream beginning with its endpoint;
    /// legacy POST accepts only the URI advertised for this exact session.
    pub fn handle(
        &mut self,
        cx: &Cx,
        request: HttpRequest,
    ) -> Result<DualEraHttpEndpointResponse, DualEraHttpEndpointError> {
        if self.closed {
            return Err(DualEraHttpEndpointError::Closed);
        }
        http_checkpoint(cx)?;

        if request.path == self.handler.config().base_path {
            return self.handle_modern(cx, request);
        }
        if request.path == self.legacy_sse_path {
            return self.handle_legacy_sse(request);
        }
        if request.path == self.legacy_message_path {
            return self.handle_legacy_post(request);
        }
        Ok(DualEraHttpEndpointResponse::Immediate(HttpResponse::new(
            HttpStatus::NOT_FOUND,
        )))
    }

    fn handle_modern(
        &mut self,
        cx: &Cx,
        request: HttpRequest,
    ) -> Result<DualEraHttpEndpointResponse, DualEraHttpEndpointError> {
        let origin = request.header("origin").map(str::to_owned);
        let admission = self.handler.admit_modern_request(&request)?;
        let json_rpc = admission.request().clone();

        match admission.response_representation() {
            HttpResponseRepresentation::Json => {
                self.modern_ingress.push_request(cx, json_rpc.clone())?;
                let Some(request_id) = json_rpc.id else {
                    return Ok(DualEraHttpEndpointResponse::Immediate(HttpResponse::new(
                        HttpStatus::ACCEPTED,
                    )));
                };
                Ok(DualEraHttpEndpointResponse::ModernJson(
                    DualEraHttpJsonResponse {
                        handler: Arc::clone(&self.handler),
                        responses: self.modern_responses.clone(),
                        request_id,
                        origin,
                    },
                ))
            }
            HttpResponseRepresentation::Sse => {
                let body = admission.bind_sse_response_body(&self.modern_responses)?;
                self.modern_ingress.push_request(cx, json_rpc)?;
                Ok(DualEraHttpEndpointResponse::ModernSse(
                    DualEraHttpSseResponse {
                        response: sse_http_response(Vec::new()),
                        body,
                        codec: Codec::new(),
                    },
                ))
            }
        }
    }

    fn handle_legacy_sse(
        &mut self,
        request: HttpRequest,
    ) -> Result<DualEraHttpEndpointResponse, DualEraHttpEndpointError> {
        validate_http_request_headers(&request)?;
        if request.method != HttpMethod::Get {
            return Ok(DualEraHttpEndpointResponse::Immediate(method_rejection(
                "GET",
            )));
        }

        // Exact MCP 2024-11-05 reconnects establish a fresh SSE endpoint
        // lifecycle. `Last-Event-ID` is intentionally ignored: it neither
        // replays messages nor selects or mutates session state.
        let mut initial_events = VecDeque::new();
        initial_events.push_back(SseEvent::endpoint(&self.legacy_message_endpoint));
        if self
            .legacy_live_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(DualEraHttpEndpointResponse::Immediate(HttpResponse::new(
                HttpStatus::SERVICE_UNAVAILABLE,
            )));
        }
        self.legacy_live_pending.store(0, Ordering::Release);
        let (sender, receiver) = mpsc::channel(self.legacy_request_capacity);
        self.legacy_live_sender = Some(sender);
        Ok(DualEraHttpEndpointResponse::LegacySse(
            DualEraHttpLegacySseResponse {
                response: sse_http_response(Vec::new()),
                initial_events,
                receiver,
                active: Arc::clone(&self.legacy_live_active),
                pending: Arc::clone(&self.legacy_live_pending),
                poll_interval: Duration::from_millis(10),
            },
        ))
    }

    fn handle_legacy_post(
        &mut self,
        request: HttpRequest,
    ) -> Result<DualEraHttpEndpointResponse, DualEraHttpEndpointError> {
        validate_http_request_headers(&request)?;
        if request.method != HttpMethod::Post {
            return Ok(DualEraHttpEndpointResponse::Immediate(method_rejection(
                "POST",
            )));
        }
        if request.query.len() != 1
            || request.query.get("session_id").map(String::as_str) != Some(self.session_id())
        {
            return Ok(DualEraHttpEndpointResponse::Immediate(HttpResponse::new(
                HttpStatus::NOT_FOUND,
            )));
        }
        let content_type = request.content_type().unwrap_or("");
        if !content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
            || legacy_post_has_modern_binding_headers(&request)
        {
            return Ok(DualEraHttpEndpointResponse::Immediate(
                HttpResponse::bad_request(),
            ));
        }
        if request.body.len() > self.handler.config().max_body_size {
            return Err(DualEraHttpEndpointError::Http(HttpError::BodyTooLarge {
                size: request.body.len(),
                max: self.handler.config().max_body_size,
            }));
        }
        if self.legacy_requests.len() >= self.legacy_request_capacity {
            return Ok(DualEraHttpEndpointResponse::Immediate(HttpResponse::new(
                HttpStatus::SERVICE_UNAVAILABLE,
            )));
        }

        let request = self.legacy_codec.decode_complete_request(&request.body)?;
        self.legacy_requests.push_back(request);
        Ok(DualEraHttpEndpointResponse::Immediate(HttpResponse::new(
            HttpStatus::ACCEPTED,
        )))
    }

    /// Receives one modern request after final HTTP admission.
    pub fn recv_modern_request(
        &mut self,
        cx: &Cx,
    ) -> Result<JsonRpcRequest, DualEraHttpEndpointError> {
        if self.closed {
            return Err(DualEraHttpEndpointError::Closed);
        }
        match self.modern_transport.recv(cx)? {
            JsonRpcMessage::Request(request) => Ok(request),
            JsonRpcMessage::Response(_) => Err(DualEraHttpEndpointError::Transport(
                TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "modern request ingress yielded a JSON-RPC response",
                )),
            )),
        }
    }

    /// Removes the next legacy client POST request in FIFO order.
    #[must_use]
    pub fn take_legacy_request(&mut self) -> Option<JsonRpcRequest> {
        (!self.closed)
            .then(|| self.legacy_requests.pop_front())
            .flatten()
    }

    /// Sends one finite JSON response for a modern JSON-selected request.
    pub fn send_modern_json_response(
        &mut self,
        cx: &Cx,
        response: JsonRpcResponse,
    ) -> Result<(), DualEraHttpEndpointError> {
        if self.closed {
            return Err(DualEraHttpEndpointError::Closed);
        }
        self.modern_transport
            .send(cx, &JsonRpcMessage::Response(response))?;
        Ok(())
    }

    /// Sends one response for the exact modern SSE request owned by `cancellation`.
    pub fn send_modern_sse_response(
        &mut self,
        cx: &Cx,
        cancellation: &StreamableHttpRequestCancellation,
        response: JsonRpcResponse,
    ) -> Result<(), DualEraHttpEndpointError> {
        if self.closed {
            return Err(DualEraHttpEndpointError::Closed);
        }
        self.modern_transport
            .send_response_for_request(cx, cancellation, response)?;
        Ok(())
    }

    /// Sends one request-owned notification through a modern SSE response body.
    ///
    /// The cancellation guard prevents a notification from being routed to a
    /// different in-flight request or committed after its HTTP body closes.
    pub fn send_modern_sse_notification(
        &mut self,
        cx: &Cx,
        cancellation: &StreamableHttpRequestCancellation,
        notification: JsonRpcRequest,
    ) -> Result<(), DualEraHttpEndpointError> {
        if self.closed {
            return Err(DualEraHttpEndpointError::Closed);
        }
        self.modern_transport
            .send_notification_for_request(cx, cancellation, notification)?;
        Ok(())
    }

    /// Publishes one legacy server-to-client message to the live SSE stream.
    ///
    /// Exact MCP 2024-11-05 does not retain legacy SSE events or assign event
    /// IDs. If no legacy stream is live, the message is not persisted for a
    /// later GET.
    pub fn publish_legacy_message(
        &self,
        message: &JsonRpcMessage,
    ) -> Result<(), DualEraHttpEndpointError> {
        if self.closed {
            return Err(DualEraHttpEndpointError::Closed);
        }
        let mut encoded = match message {
            JsonRpcMessage::Request(request) => self.legacy_codec.encode_request(request)?,
            JsonRpcMessage::Response(response) => self.legacy_codec.encode_response(response)?,
        };
        if encoded.pop() != Some(b'\n') {
            return Err(DualEraHttpEndpointError::Transport(TransportError::Io(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "JSON-RPC codec omitted its NDJSON delimiter",
                ),
            )));
        }
        let data = String::from_utf8(encoded).map_err(|error| {
            DualEraHttpEndpointError::Transport(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error,
            )))
        })?;
        let reserves_live_delivery = self.reserve_legacy_live_delivery()?;
        if reserves_live_delivery {
            let Some(sender) = self.legacy_live_sender.as_ref() else {
                self.release_legacy_live_delivery();
                return Ok(());
            };
            if let Err(error) = sender.try_send(LegacySseLiveMessage { data }) {
                self.release_legacy_live_delivery();
                if matches!(&error, mpsc::SendError::Disconnected(_)) {
                    self.legacy_live_active.store(false, Ordering::Release);
                    return Ok(());
                } else {
                    return Err(DualEraHttpEndpointError::Transport(
                        map_streamable_send_error(error, "legacy SSE live queue is full"),
                    ));
                }
            }
        }
        Ok(())
    }

    fn reserve_legacy_live_delivery(&self) -> Result<bool, DualEraHttpEndpointError> {
        if !self.legacy_live_active.load(Ordering::Acquire) {
            return Ok(false);
        }

        let mut pending = self.legacy_live_pending.load(Ordering::Acquire);
        loop {
            if !self.legacy_live_active.load(Ordering::Acquire) {
                return Ok(false);
            }
            if pending >= self.legacy_request_capacity {
                return Err(DualEraHttpEndpointError::Transport(
                    streamable_queue_full_error("legacy SSE live queue is full"),
                ));
            }
            match self.legacy_live_pending.compare_exchange_weak(
                pending,
                pending + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(true),
                Err(observed) => pending = observed,
            }
        }
    }

    fn release_legacy_live_delivery(&self) {
        let _ =
            self.legacy_live_pending
                .try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                    pending.checked_sub(1)
                });
    }

    /// Closes the session, cancels all live modern response bodies, and clears
    /// queued modern work plus legacy request and live-stream state.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.modern_ingress.close();
        self.modern_responses.terminate();
        let _ = self.modern_transport.close();
        self.legacy_live_active.store(false, Ordering::Release);
        self.legacy_live_pending.store(0, Ordering::Release);
        self.legacy_live_sender = None;
        self.legacy_requests.clear();
    }
}

impl Drop for DualEraHttpSession {
    fn drop(&mut self) {
        self.close();
    }
}

// =============================================================================
// Session Support
// =============================================================================

const MAX_HTTP_SESSIONS: usize = 1_024;
const MAX_HTTP_SESSION_ID_BYTES: usize = 128;
const MAX_HTTP_SESSION_ENTRIES: usize = 64;
const MAX_HTTP_SESSION_KEY_BYTES: usize = 256;
const MAX_HTTP_SESSION_VALUE_BYTES: usize = 256 * 1024;
const MAX_HTTP_SESSION_RETAINED_BYTES: usize = 1024 * 1024;

/// Bounded HTTP session admission failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpSessionError {
    InvalidSessionId,
    InvalidCapacity,
    KeyTooLarge,
    ValueTooLarge,
    CapacityExceeded,
    SessionNotFound,
    RandomnessUnavailable,
}

impl std::fmt::Display for HttpSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidSessionId => "invalid HTTP session identifier",
            Self::InvalidCapacity => "HTTP session capacity is outside the supported range",
            Self::KeyTooLarge => "HTTP session key exceeds byte limit",
            Self::ValueTooLarge => "HTTP session value exceeds byte limit",
            Self::CapacityExceeded => "HTTP session capacity exhausted",
            Self::SessionNotFound => "HTTP session not found",
            Self::RandomnessUnavailable => "HTTP session identifier generation failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for HttpSessionError {}

#[derive(Debug, Clone)]
struct HttpSessionEntry {
    value: serde_json::Value,
    retained_bytes: usize,
}

struct SessionValueByteCounter {
    bytes: usize,
    limit: usize,
}

impl Write for SessionValueByteCounter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let Some(next) = self.bytes.checked_add(buffer.len()) else {
            return Err(std::io::Error::other("session value byte limit exceeded"));
        };
        if next > self.limit {
            return Err(std::io::Error::other("session value byte limit exceeded"));
        }
        self.bytes = next;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn measure_session_value(value: &serde_json::Value) -> Result<usize, HttpSessionError> {
    let mut counter = SessionValueByteCounter {
        bytes: 0,
        limit: MAX_HTTP_SESSION_VALUE_BYTES,
    };
    serde_json::to_writer(&mut counter, value).map_err(|_| HttpSessionError::ValueTooLarge)?;
    Ok(counter.bytes)
}

/// HTTP session for maintaining state across requests.
#[derive(Debug, Clone)]
pub struct HttpSession {
    /// Session ID.
    id: String,
    /// Session creation time.
    created_at: Instant,
    /// Last activity time.
    last_activity: Instant,
    /// Session data.
    data: HashMap<String, HttpSessionEntry>,
    retained_bytes: usize,
}

impl HttpSession {
    /// Creates a new session with the given ID.
    pub fn new(id: impl Into<String>) -> Result<Self, HttpSessionError> {
        let id = id.into();
        if id.is_empty()
            || id.len() > MAX_HTTP_SESSION_ID_BYTES
            || !id.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(HttpSessionError::InvalidSessionId);
        }
        let now = Instant::now();
        Ok(Self {
            id,
            created_at: now,
            last_activity: now,
            data: HashMap::new(),
            retained_bytes: 0,
        })
    }

    /// Returns this session's immutable identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns when the session was created.
    #[must_use]
    pub fn created_at(&self) -> Instant {
        self.created_at
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
        self.data.get(key).map(|entry| &entry.value)
    }

    /// Sets a session value.
    pub fn set(
        &mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Result<(), HttpSessionError> {
        let key = key.into();
        if key.is_empty() || key.len() > MAX_HTTP_SESSION_KEY_BYTES {
            return Err(HttpSessionError::KeyTooLarge);
        }
        if !self.data.contains_key(&key) && self.data.len() >= MAX_HTTP_SESSION_ENTRIES {
            return Err(HttpSessionError::CapacityExceeded);
        }
        let value_bytes = measure_session_value(&value)?;
        let retained_bytes = key
            .len()
            .checked_add(value_bytes)
            .ok_or(HttpSessionError::CapacityExceeded)?;
        let prior_bytes = self.data.get(&key).map_or(0, |entry| entry.retained_bytes);
        let prospective = self
            .retained_bytes
            .checked_sub(prior_bytes)
            .and_then(|bytes| bytes.checked_add(retained_bytes))
            .ok_or(HttpSessionError::CapacityExceeded)?;
        if prospective > MAX_HTTP_SESSION_RETAINED_BYTES {
            return Err(HttpSessionError::CapacityExceeded);
        }
        self.data.insert(
            key,
            HttpSessionEntry {
                value,
                retained_bytes,
            },
        );
        self.retained_bytes = prospective;
        self.touch();
        Ok(())
    }

    /// Removes a session value.
    pub fn remove(&mut self, key: &str) -> Option<serde_json::Value> {
        self.touch();
        self.data.remove(key).map(|entry| {
            self.retained_bytes = self.retained_bytes.saturating_sub(entry.retained_bytes);
            entry.value
        })
    }
}

/// Session store for HTTP sessions.
#[derive(Debug)]
pub struct SessionStore {
    sessions: Mutex<HashMap<String, HttpSession>>,
    timeout: Duration,
    max_sessions: usize,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl SessionStore {
    /// Creates a new session store with the given timeout.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self::with_capacity(timeout, MAX_HTTP_SESSIONS)
            .expect("the built-in HTTP session capacity must be valid")
    }

    /// Creates a session store with a hard global session limit.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSessionError::InvalidCapacity`] when `max_sessions` is
    /// zero or exceeds the hard global session limit.
    pub fn with_capacity(timeout: Duration, max_sessions: usize) -> Result<Self, HttpSessionError> {
        if max_sessions == 0 || max_sessions > MAX_HTTP_SESSIONS {
            return Err(HttpSessionError::InvalidCapacity);
        }
        Ok(Self {
            sessions: Mutex::new(HashMap::new()),
            timeout,
            max_sessions,
        })
    }

    /// Creates a new session store with default 1-hour timeout.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(Duration::from_secs(3600))
    }

    /// Creates a new session.
    pub fn create(&self) -> Result<String, HttpSessionError> {
        let id = generate_session_id()?;
        let session = HttpSession::new(&id)?;
        let mut guard = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.retain(|_, existing| !existing.is_expired(self.timeout));
        if guard.len() >= self.max_sessions {
            return Err(HttpSessionError::CapacityExceeded);
        }
        if guard.contains_key(&id) {
            return Err(HttpSessionError::CapacityExceeded);
        }
        guard.insert(id.clone(), session);
        Ok(id)
    }

    /// Gets a session by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<HttpSession> {
        let mut guard = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let session = guard.get_mut(id)?;

        if session.is_expired(self.timeout) {
            guard.remove(id);
            return None;
        }

        session.touch();
        Some(session.clone())
    }

    /// Updates a session.
    pub fn update(&self, session: HttpSession) -> Result<(), HttpSessionError> {
        let mut guard = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.retain(|_, existing| !existing.is_expired(self.timeout));
        if !guard.contains_key(&session.id) {
            return Err(HttpSessionError::SessionNotFound);
        }
        guard.insert(session.id.clone(), session);
        Ok(())
    }

    /// Removes a session.
    pub fn remove(&self, id: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id);
    }

    /// Removes expired sessions.
    pub fn cleanup(&self) {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|_, session| !session.is_expired(self.timeout));
    }

    /// Returns the number of active sessions.
    #[must_use]
    pub fn count(&self) -> usize {
        let mut guard = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.retain(|_, session| !session.is_expired(self.timeout));
        guard.len()
    }
}

/// Generates a fresh 256-bit session ID from the process-wide OS randomness
/// boundary and encodes it as fixed-width lowercase hexadecimal.
fn generate_session_id() -> Result<String, HttpSessionError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let identifier =
        draw_security_identifier().map_err(|_| HttpSessionError::RandomnessUnavailable)?;
    let mut encoded = String::with_capacity(identifier.as_bytes().len() * 2);
    for byte in identifier.as_bytes() {
        encoded.push(char::from(HEX[usize::from(*byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    Ok(encoded)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct InterruptEveryOtherRead {
        inner: Cursor<Vec<u8>>,
        interrupt_next: bool,
        interruptions: Arc<AtomicUsize>,
        cancel_on_interrupt: Option<Cx>,
    }

    impl Read for InterruptEveryOtherRead {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.interrupt_next {
                self.interrupt_next = false;
                self.interruptions.fetch_add(1, Ordering::AcqRel);
                if let Some(cx) = self.cancel_on_interrupt.as_ref() {
                    cx.set_cancel_requested(true);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "deterministic transient read interruption",
                ));
            }
            self.interrupt_next = true;
            self.inner.read(buffer)
        }
    }

    struct CancelAfterSuccessfulRead {
        inner: Cursor<Vec<u8>>,
        cx: Cx,
        reads: Arc<AtomicUsize>,
    }

    impl Read for CancelAfterSuccessfulRead {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let read = self.inner.read(buffer)?;
            if read > 0 && self.reads.fetch_add(1, Ordering::AcqRel) == 0 {
                self.cx.set_cancel_requested(true);
            }
            Ok(read)
        }
    }

    #[derive(Debug)]
    struct FailingSerialize;

    impl serde::Serialize for FailingSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(<S::Error as serde::ser::Error>::custom(
                "intentional HTTP response encoding failure",
            ))
        }
    }

    fn wait_for_counter(counter: &AtomicUsize, expected: usize) -> bool {
        let deadline = Instant::now() + Duration::from_secs(1);
        while counter.load(Ordering::Acquire) < expected {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::yield_now();
        }
        true
    }

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
    fn directly_constructed_request_headers_are_case_insensitive_at_admission() {
        let config = HttpHandlerConfig {
            allow_cors: true,
            cors_origins: vec!["https://trusted.example".to_string()],
            ..HttpHandlerConfig::default()
        };
        let handler = HttpRequestHandler::with_config(config);
        let mut request = HttpRequest::new(HttpMethod::Post, "/mcp/v1")
            .with_body(r#"{"jsonrpc":"2.0","method":"test","id":1}"#);
        request
            .headers
            .insert("Content-Type".to_string(), "application/json".to_string());
        request
            .headers
            .insert("Origin".to_string(), "https://trusted.example".to_string());

        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.header("ORIGIN"), Some("https://trusted.example"));
        assert!(handler.parse_request(&request).is_ok());

        request
            .headers
            .insert("Origin".to_string(), "https://denied.example".to_string());
        assert!(matches!(
            handler.parse_request(&request),
            Err(HttpError::OriginNotAllowed(origin)) if origin == "https://denied.example"
        ));
    }

    #[test]
    fn directly_constructed_case_insensitive_duplicate_headers_are_rejected() {
        let config = HttpHandlerConfig {
            allow_cors: true,
            cors_origins: vec!["https://trusted.example".to_string()],
            ..HttpHandlerConfig::default()
        };
        let handler = HttpRequestHandler::with_config(config);
        let mut request = HttpRequest::new(HttpMethod::Post, "/mcp/v1")
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","method":"test","id":1}"#);
        request
            .headers
            .insert("Origin".to_string(), "https://trusted.example".to_string());
        request
            .headers
            .insert("origin".to_string(), "https://denied.example".to_string());

        assert!(matches!(
            handler.parse_request(&request),
            Err(HttpError::InvalidHeader(message)) if message.contains("duplicate")
        ));

        request.method = HttpMethod::Options;
        request.headers.insert(
            "Access-Control-Request-Method".to_string(),
            "POST".to_string(),
        );
        assert_eq!(
            handler.handle_options(&request).status,
            HttpStatus::BAD_REQUEST
        );
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
    fn http_response_json_encoding_failure_is_typed_and_fails_closed() {
        let error = HttpResponse::ok()
            .try_with_json(&FailingSerialize)
            .expect_err("fallible JSON response builder must preserve serializer failure");
        assert!(matches!(error, HttpError::JsonError(_)));

        let response = HttpResponse::ok()
            .with_header("x-response-policy", "preserved")
            .with_json(&FailingSerialize);
        assert_eq!(response.status, HttpStatus::INTERNAL_SERVER_ERROR);
        assert_eq!(response.body, JSON_ENCODING_ERROR_BODY);
        assert!(!response.body.is_empty());
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            response
                .headers
                .get("x-response-policy")
                .map(String::as_str),
            Some("preserved")
        );
    }

    #[test]
    fn test_http_response_cors() {
        let response = HttpResponse::ok().with_cors("https://example.com");

        assert_eq!(
            response.headers.get("access-control-allow-origin"),
            Some(&"https://example.com".to_string())
        );
        assert_eq!(
            response.headers.get("access-control-allow-methods"),
            Some(&"POST, OPTIONS".to_string())
        );
        assert_eq!(
            response.headers.get("vary").map(String::as_str),
            Some("Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
        );

        let rejected = HttpResponse::ok().with_cors("https://example.com\r\nx-injected: yes");
        assert!(!rejected.headers.contains_key("access-control-allow-origin"));
        assert!(!rejected.headers.contains_key("vary"));
    }

    #[test]
    fn default_http_handler_rejects_cross_origin_preflight() {
        let handler = HttpRequestHandler::new();
        let request = HttpRequest::new(HttpMethod::Options, "/mcp/v1")
            .with_header("Origin", "https://example.com")
            .with_header("Access-Control-Request-Method", "POST");

        let response = handler.handle_options(&request);
        assert_eq!(response.status, HttpStatus::METHOD_NOT_ALLOWED);
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

        let request = HttpRequest::new(HttpMethod::Post, "/wrong")
            .with_header("Content-Type", "application/json")
            .with_body(serde_json::to_vec(&json_rpc).unwrap());
        assert!(matches!(
            handler.parse_request(&request),
            Err(HttpError::InvalidPath(path)) if path == "/wrong"
        ));
    }

    #[test]
    fn http_handler_response_encoding_failure_is_typed_and_returns_500() {
        let config = HttpHandlerConfig {
            allow_cors: true,
            cors_origins: vec!["https://allowed.example".to_string()],
            ..HttpHandlerConfig::default()
        };
        let handler = HttpRequestHandler::with_config(config);

        let typed_error = serde_json::to_vec(&FailingSerialize)
            .expect_err("fixture serializer must fail response encoding");
        let typed_result = handler.try_create_response_from_encoding(
            Err(CodecError::from(typed_error)),
            Some("https://allowed.example"),
        );
        assert!(matches!(typed_result, Err(HttpError::CodecError(_))));

        let fallback_error = serde_json::to_vec(&FailingSerialize)
            .expect_err("fixture serializer must fail response encoding");
        let response = handler.create_response_from_encoding(
            Err(CodecError::from(fallback_error)),
            Some("https://allowed.example"),
        );
        assert_eq!(response.status, HttpStatus::INTERNAL_SERVER_ERROR);
        assert_eq!(response.body, JSON_ENCODING_ERROR_BODY);
        assert!(!response.body.is_empty());
        assert_eq!(
            response
                .headers
                .get("access-control-allow-origin")
                .map(String::as_str),
            Some("https://allowed.example")
        );
    }

    #[test]
    fn test_http_session() {
        let mut session = HttpSession::new("test-session").unwrap();
        assert_eq!(session.id(), "test-session");

        session.set("key", serde_json::json!("value")).unwrap();
        assert_eq!(session.get("key"), Some(&serde_json::json!("value")));

        session.remove("key");
        assert!(session.get("key").is_none());

        assert!(!session.is_expired(Duration::from_secs(3600)));
    }

    #[test]
    fn http_session_id_requires_visible_ascii() {
        for invalid in ["", "contains space", "line\nbreak", "nul\0byte", "é"] {
            assert_eq!(
                HttpSession::new(invalid).unwrap_err(),
                HttpSessionError::InvalidSessionId
            );
        }
        assert!(HttpSession::new("!visible-session~").is_ok());
    }

    #[test]
    fn http_session_state_is_hard_bounded() {
        let mut session = HttpSession::new("bounded-session").unwrap();
        for index in 0..MAX_HTTP_SESSION_ENTRIES {
            session
                .set(format!("key-{index}"), serde_json::json!(index))
                .expect("entry at or below the count limit");
        }
        assert_eq!(
            session.set("one-too-many", serde_json::json!(true)),
            Err(HttpSessionError::CapacityExceeded)
        );
        session
            .set("key-0", serde_json::json!("replacement"))
            .expect("replacement does not consume another entry");

        let oversized = "x".repeat(MAX_HTTP_SESSION_VALUE_BYTES);
        assert_eq!(
            session.set("key-0", serde_json::Value::String(oversized)),
            Err(HttpSessionError::ValueTooLarge)
        );
        assert!(matches!(
            HttpSession::new("x".repeat(MAX_HTTP_SESSION_ID_BYTES + 1)),
            Err(HttpSessionError::InvalidSessionId)
        ));
    }

    #[test]
    fn test_session_store() {
        let store = SessionStore::with_defaults();

        let id = store.create().unwrap();
        assert!(!id.is_empty());

        let session = store.get(&id);
        assert!(session.is_some());

        store.remove(&id);
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn session_store_rejects_above_global_capacity() {
        let store = SessionStore::with_capacity(Duration::from_secs(3600), 1)
            .expect("capacity one is valid");
        let first = store.create().expect("first session admitted");
        assert_eq!(store.count(), 1);
        assert_eq!(store.create(), Err(HttpSessionError::CapacityExceeded));
        store.remove(&first);
        assert!(store.create().is_ok());
    }

    #[test]
    fn session_store_rejects_invalid_capacity_without_panicking() {
        assert!(matches!(
            SessionStore::with_capacity(Duration::from_secs(3600), 0),
            Err(HttpSessionError::InvalidCapacity)
        ));
        assert!(matches!(
            SessionStore::with_capacity(Duration::from_secs(3600), MAX_HTTP_SESSIONS + 1),
            Err(HttpSessionError::InvalidCapacity)
        ));
    }

    #[test]
    fn test_streamable_transport() {
        let transport = StreamableHttpTransport::new();
        let cx = Cx::for_testing();

        // Push a request
        let request = JsonRpcRequest::new("test", None, 1i64);
        transport.push_request(&cx, request).unwrap();

        // Should have a request in queue
        assert_eq!(transport.pending_requests(), 1);
    }

    #[test]
    fn test_http_error_display() {
        let err = HttpError::InvalidMethod("PATCH".to_string());
        assert_eq!(err.to_string(), "invalid HTTP method");

        let err = HttpError::Timeout;
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_generate_session_id() {
        let id1 = generate_session_id().unwrap();
        let id2 = generate_session_id().unwrap();

        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 64);
        assert!(id1.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(id1.bytes().all(|byte| !byte.is_ascii_uppercase()));
    }

    #[test]
    fn test_http_transport_read_request_chunked_body_and_query() {
        use std::io::Cursor;

        let body = br#"{"jsonrpc":"2.0","method":"test","id":1}"#;
        let body1 = &body[..10];
        let body2 = &body[10..];

        let raw = format!(
            "POST /mcp/v1?foo=bar&x=y HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Type: application/json\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
{:x}\r\n\
{}\r\n\
{:x}\r\n\
{}\r\n\
0\r\n\
\r\n",
            body1.len(),
            std::str::from_utf8(body1).unwrap(),
            body2.len(),
            std::str::from_utf8(body2).unwrap(),
        );

        let reader = Cursor::new(raw.into_bytes());
        let mut output = Vec::new();
        let mut transport = HttpTransport::new(reader, &mut output);

        let req = transport.read_request().unwrap();
        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(req.path, "/mcp/v1");
        assert_eq!(req.query.get("foo"), Some(&"bar".to_string()));
        assert_eq!(req.query.get("x"), Some(&"y".to_string()));
        assert_eq!(req.body, body);
    }

    #[test]
    fn chunked_request_rejects_non_empty_trailer_fields_and_latches_closed() {
        let raw = b"POST /mcp/v1 HTTP/1.1\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
0\r\n\
X-Checksum: abc123\r\n\
\r\n";
        let mut transport = HttpTransport::new(Cursor::new(raw.to_vec()), Vec::new());

        let error = transport.read_request().unwrap_err();

        assert!(matches!(
            error,
            HttpError::InvalidHeader(detail)
                if detail == "HTTP trailer fields are not supported"
        ));
        assert!(transport.closed);
        assert!(matches!(
            transport.recv(&Cx::for_testing()),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn chunked_request_bounds_oversized_trailer_before_line_termination() {
        const HEADER_LIMIT: usize = 64 * 1024;
        const PREFIX: &[u8] = b"X-Trailer: ";

        let mut raw = b"POST /mcp/v1 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
        raw.extend_from_slice(PREFIX);
        raw.extend(vec![b'a'; HEADER_LIMIT + 1 - PREFIX.len()]);

        let mut transport = HttpTransport::new(Cursor::new(raw), Vec::new());
        let error = transport.read_request().unwrap_err();

        assert!(matches!(
            error,
            HttpError::HeadersTooLarge {
                size,
                max: HEADER_LIMIT
            } if size == HEADER_LIMIT + 1
        ));
        assert!(transport.closed);
    }

    #[test]
    fn chunked_request_rejects_oversized_declaration_before_body_read() {
        let declared_size = 10 * 1024 * 1024 + 1;
        let raw = format!(
            "POST /mcp/v1 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{declared_size:x}\r\n"
        );
        let mut transport = HttpTransport::new(Cursor::new(raw.into_bytes()), Vec::new());

        let error = transport.read_request().unwrap_err();

        let HttpError::BodyTooLarge { size, max } = error else {
            panic!("expected body-too-large error");
        };
        assert_eq!(size, declared_size);
        assert_eq!(max, 10 * 1024 * 1024);
    }

    #[test]
    fn chunked_request_rejects_unimplemented_transfer_coding_chain() {
        let raw = b"POST /mcp/v1 HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        let mut transport = HttpTransport::new(Cursor::new(raw.to_vec()), Vec::new());

        let error = transport.read_request().unwrap_err();

        assert!(matches!(
            error,
            HttpError::UnsupportedTransferEncoding(value) if value == "gzip, chunked"
        ));
    }

    #[test]
    fn http_request_head_is_strict_utf8_and_http_11_three_token_syntax() {
        let malformed_heads = [
            b"POST /mcp/v1 HTTP/1.0\r\n\r\n".to_vec(),
            b"POST /mcp/v1 HTTP/1.1 extra\r\n\r\n".to_vec(),
            b"POST  /mcp/v1 HTTP/1.1\r\n\r\n".to_vec(),
        ];
        for raw in malformed_heads {
            let mut transport = HttpTransport::new(Cursor::new(raw), Vec::new());
            assert!(matches!(
                transport.read_request(),
                Err(HttpError::InvalidRequestLine(_))
            ));
        }

        let mut invalid_utf8 = b"POST /mcp/v1 HTTP/1.1\r\nX-Test: ".to_vec();
        invalid_utf8.push(0xff);
        invalid_utf8.extend_from_slice(b"\r\n\r\n");
        let mut transport = HttpTransport::new(Cursor::new(invalid_utf8), Vec::new());
        assert!(matches!(
            transport.read_request(),
            Err(HttpError::InvalidHeader(_))
        ));
    }

    #[test]
    fn http_request_rejects_malformed_folded_duplicate_and_ambiguous_headers() {
        let malformed = [
            "POST /mcp/v1 HTTP/1.1\r\nContent-Length: nope\r\n\r\n",
            "POST /mcp/v1 HTTP/1.1\r\nHost: one\r\nhost: two\r\n\r\n",
            "POST /mcp/v1 HTTP/1.1\r\nX-Test: one\r\n two\r\n\r\n",
            "POST /mcp/v1 HTTP/1.1\r\nBad Name: value\r\n\r\n",
            "POST /mcp/v1 HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        ];

        for raw in malformed {
            let mut transport =
                HttpTransport::new(Cursor::new(raw.as_bytes().to_vec()), Vec::new());
            assert!(matches!(
                transport.read_request(),
                Err(HttpError::InvalidHeader(_))
            ));
        }
    }

    #[test]
    fn http_response_rejects_header_injection_before_writing() {
        for (name, value) in [
            ("x-test", "safe\r\nx-injected: yes"),
            ("x-test\ninvalid", "safe"),
        ] {
            let response = HttpResponse::ok().with_header(name, value);
            let mut transport = HttpTransport::new(Cursor::new(Vec::<u8>::new()), Vec::new());

            let error = transport.write_response(&response).unwrap_err();

            assert!(matches!(error, HttpError::InvalidHeader(_)));
            assert!(transport.writer.is_empty());
        }

        let mut response = HttpResponse::ok();
        response
            .headers
            .insert("X-Duplicate".to_string(), "one".to_string());
        response
            .headers
            .insert("x-duplicate".to_string(), "two".to_string());
        let mut transport = HttpTransport::new(Cursor::new(Vec::<u8>::new()), Vec::new());
        assert!(matches!(
            transport.write_response(&response),
            Err(HttpError::InvalidHeader(_))
        ));
        assert!(transport.writer.is_empty());
    }

    #[test]
    fn http_response_writes_reason_phrases_for_every_declared_status() {
        for (status, expected_line) in [
            (HttpStatus::OK, "HTTP/1.1 200 OK\r\n"),
            (HttpStatus::ACCEPTED, "HTTP/1.1 202 Accepted\r\n"),
            (HttpStatus::BAD_REQUEST, "HTTP/1.1 400 Bad Request\r\n"),
            (HttpStatus::UNAUTHORIZED, "HTTP/1.1 401 Unauthorized\r\n"),
            (HttpStatus::FORBIDDEN, "HTTP/1.1 403 Forbidden\r\n"),
            (HttpStatus::NOT_FOUND, "HTTP/1.1 404 Not Found\r\n"),
            (
                HttpStatus::METHOD_NOT_ALLOWED,
                "HTTP/1.1 405 Method Not Allowed\r\n",
            ),
            (
                HttpStatus::INTERNAL_SERVER_ERROR,
                "HTTP/1.1 500 Internal Server Error\r\n",
            ),
            (
                HttpStatus::SERVICE_UNAVAILABLE,
                "HTTP/1.1 503 Service Unavailable\r\n",
            ),
        ] {
            let mut transport = HttpTransport::new(Cursor::new(Vec::<u8>::new()), Vec::new());
            transport
                .write_response(&HttpResponse::new(status))
                .expect("declared status must serialize");

            assert!(transport.writer.starts_with(expected_line.as_bytes()));
        }
    }

    #[test]
    fn http_transport_recv_requires_post_and_json_media_type() {
        let body = br#"{"jsonrpc":"2.0","method":"test","id":1}"#;
        for (method, content_type) in [
            ("GET", "application/json"),
            ("POST", "application/jsonevil"),
            ("POST", "text/plain"),
        ] {
            let head = format!(
                "{method} /mcp/v1 HTTP/1.1\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let mut raw = head.into_bytes();
            raw.extend_from_slice(body);
            let mut transport = HttpTransport::new(Cursor::new(raw), Vec::new());

            let error = transport.recv(&Cx::for_testing()).unwrap_err();

            assert!(matches!(
                error,
                TransportError::Io(ref source)
                    if source.kind() == std::io::ErrorKind::InvalidData
            ));
        }
    }

    #[test]
    fn http_transport_enforces_exact_origin_policy_without_reflecting_input() {
        let body = br#"{"jsonrpc":"2.0","method":"test","id":1}"#;
        let request = |origin: &str| {
            let head = format!(
                "POST /mcp/v1 HTTP/1.1\r\nContent-Type: application/json\r\nOrigin: {origin}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let mut raw = head.into_bytes();
            raw.extend_from_slice(body);
            raw
        };
        let config = HttpHandlerConfig {
            allow_cors: true,
            cors_origins: vec!["https://trusted.example".to_string()],
            ..HttpHandlerConfig::default()
        };

        let mut allowed = HttpTransport::with_config(
            Cursor::new(request("https://trusted.example")),
            Vec::new(),
            config.clone(),
        );
        assert!(allowed.recv(&Cx::for_testing()).is_ok());

        let secret_origin = "https://secret-canary.invalid";
        let mut denied =
            HttpTransport::with_config(Cursor::new(request(secret_origin)), Vec::new(), config);
        let error = denied.recv(&Cx::for_testing()).unwrap_err();
        assert!(matches!(
            error,
            TransportError::Io(ref source)
                if source.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(!error.to_string().contains(secret_origin));

        let wildcard = HttpHandlerConfig {
            allow_cors: true,
            cors_origins: vec!["*".to_string()],
            ..HttpHandlerConfig::default()
        };
        let mut wildcard_transport = HttpTransport::with_config(
            Cursor::new(request("https://untrusted.example")),
            Vec::new(),
            wildcard,
        );
        assert!(wildcard_transport.recv(&Cx::for_testing()).is_err());
    }

    #[test]
    fn http_transport_config_bounds_body_before_allocation() {
        let config = HttpHandlerConfig {
            max_body_size: 8,
            ..HttpHandlerConfig::default()
        };
        let raw =
            b"POST /mcp/v1 HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\n";
        let mut transport =
            HttpTransport::with_config(Cursor::new(raw.to_vec()), Vec::new(), config);

        assert!(matches!(
            transport.read_request(),
            Err(HttpError::BodyTooLarge { size: 9, max: 8 })
        ));
    }

    #[test]
    fn reality_check_regression_http_retries_interrupted_header_and_body_reads() {
        let body = br#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
        let head = format!(
            "POST /mcp/v1 HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut wire = head.into_bytes();
        wire.extend_from_slice(body);
        let interruptions = Arc::new(AtomicUsize::new(0));
        let reader = InterruptEveryOtherRead {
            inner: Cursor::new(wire),
            interrupt_next: true,
            interruptions: Arc::clone(&interruptions),
            cancel_on_interrupt: None,
        };
        let mut transport = HttpTransport::new(reader, Vec::new());

        let message = transport
            .recv(&Cx::for_testing())
            .expect("transient interruptions must not terminate HTTP framing");

        assert!(matches!(
            message,
            JsonRpcMessage::Request(ref request) if request.method == "tools/list"
        ));
        assert!(interruptions.load(Ordering::Acquire) > body.len());
        assert!(!transport.closed);
        assert!(transport.response_pending);
    }

    #[test]
    fn reality_check_regression_http_checks_context_between_interrupted_read_retries() {
        let cx = Cx::for_testing();
        let reader = InterruptEveryOtherRead {
            inner: Cursor::new(b"POST /mcp/v1 HTTP/1.1\r\nContent-Length: 0\r\n\r\n".to_vec()),
            interrupt_next: false,
            interruptions: Arc::new(AtomicUsize::new(0)),
            cancel_on_interrupt: Some(cx.clone()),
        };
        let mut transport = HttpTransport::new(reader, Vec::new());

        assert!(matches!(
            transport.recv(&cx),
            Err(TransportError::Cancelled)
        ));
        assert!(transport.closed);
        assert!(!transport.response_pending);
    }

    #[test]
    fn reality_check_regression_http_checks_context_after_successful_incremental_read() {
        let cx = Cx::for_testing();
        let reads = Arc::new(AtomicUsize::new(0));
        let reader = CancelAfterSuccessfulRead {
            inner: Cursor::new(
                b"POST /mcp/v1 HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n"
                    .to_vec(),
            ),
            cx: cx.clone(),
            reads: Arc::clone(&reads),
        };
        let mut transport = HttpTransport::new(reader, Vec::new());

        assert!(matches!(
            transport.recv(&cx),
            Err(TransportError::Cancelled)
        ));
        assert_eq!(reads.load(Ordering::Acquire), 1);
        assert!(transport.closed);
        assert!(!transport.response_pending);
    }

    #[test]
    fn reality_check_regression_http_recv_uses_full_checkpoint_and_preserves_masking() {
        let body = br#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
        let head = format!(
            "POST /mcp/v1 HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut wire = head.into_bytes();
        wire.extend_from_slice(body);
        let mut transport = HttpTransport::new(Cursor::new(wire), Vec::new());

        let deadline_cx = Cx::for_testing_with_budget(
            asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
        );
        assert!(matches!(
            transport.recv(&deadline_cx),
            Err(TransportError::Timeout)
        ));

        let poll_cx = Cx::for_testing_with_budget(asupersync::Budget::new().with_poll_quota(0));
        assert!(matches!(
            transport.recv(&poll_cx),
            Err(TransportError::Cancelled)
        ));

        let cost_cx = Cx::for_testing_with_budget(asupersync::Budget::new().with_cost_quota(0));
        assert!(matches!(
            transport.recv(&cost_cx),
            Err(TransportError::Cancelled)
        ));
        assert!(!transport.closed);
        assert!(!transport.response_pending);

        let cancelled_cx = Cx::for_testing();
        cancelled_cx.set_cancel_requested(true);
        let message = cancelled_cx
            .masked(|| transport.recv(&cancelled_cx))
            .expect("masking defers explicit cancellation at HTTP receive admission");
        assert!(matches!(
            message,
            JsonRpcMessage::Request(ref request) if request.method == "tools/list"
        ));
        assert!(transport.response_pending);
    }

    #[test]
    fn reality_check_regression_http_send_uses_full_checkpoint_without_losing_response_ownership() {
        let body = br#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
        let head = format!(
            "POST /mcp/v1 HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut wire = head.into_bytes();
        wire.extend_from_slice(body);
        let mut transport = HttpTransport::new(Cursor::new(wire), Vec::new());
        transport
            .recv(&Cx::for_testing())
            .expect("establish one pending HTTP response");
        let response = JsonRpcMessage::Response(JsonRpcResponse::success(
            RequestId::Number(1),
            serde_json::Value::Null,
        ));

        let deadline_cx = Cx::for_testing_with_budget(
            asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
        );
        assert!(matches!(
            transport.send(&deadline_cx, &response),
            Err(TransportError::Timeout)
        ));
        let poll_cx = Cx::for_testing_with_budget(asupersync::Budget::new().with_poll_quota(0));
        assert!(matches!(
            transport.send(&poll_cx, &response),
            Err(TransportError::Cancelled)
        ));
        let cost_cx = Cx::for_testing_with_budget(asupersync::Budget::new().with_cost_quota(0));
        assert!(matches!(
            transport.send(&cost_cx, &response),
            Err(TransportError::Cancelled)
        ));
        assert!(transport.response_pending);
        assert!(transport.writer.is_empty());

        let masked_deadline_cx = Cx::for_testing_with_budget(
            asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
        );
        masked_deadline_cx.masked(|| {
            transport
                .send(&masked_deadline_cx, &response)
                .expect("masking defers deadline enforcement at HTTP send admission");
        });
        assert!(!transport.response_pending);
        assert!(transport.writer.starts_with(b"HTTP/1.1 200 OK\r\n"));
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
            assert!(
                matches!(msg, JsonRpcMessage::Request(_)),
                "Expected request"
            );
            let JsonRpcMessage::Request(req) = msg else {
                return;
            };

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

        // Verify HTTP response
        let response_str = String::from_utf8(output).unwrap();
        assert!(response_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response_str.contains("content-type: application/json"));
        assert!(response_str.contains("\"tools\":[]"));
    }

    #[test]
    fn http_transport_response_emits_json_and_exact_admitted_origin_headers() {
        let body = br#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
        let origin = "https://trusted.example";
        let head = format!(
            "POST /mcp/v1 HTTP/1.1\r\nContent-Type: application/json\r\nOrigin: {origin}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut input = head.into_bytes();
        input.extend_from_slice(body);
        let config = HttpHandlerConfig {
            allow_cors: true,
            cors_origins: vec![origin.to_string()],
            ..HttpHandlerConfig::default()
        };
        let mut output = Vec::new();

        {
            let mut transport = HttpTransport::with_config(Cursor::new(input), &mut output, config);
            transport.recv(&Cx::for_testing()).unwrap();
            transport
                .send(
                    &Cx::for_testing(),
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        fastmcp_protocol::RequestId::Number(1),
                        serde_json::json!({"tools": []}),
                    )),
                )
                .unwrap();
        }

        let response = String::from_utf8(output).unwrap();
        assert!(response.contains("content-type: application/json\r\n"));
        assert!(response.contains(&format!("access-control-allow-origin: {origin}\r\n")));
        assert!(response.contains(
            "vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers\r\n"
        ));
    }

    #[test]
    fn http_transport_does_not_overwrite_origin_while_a_response_is_pending() {
        let first_origin = "https://first.example";
        let second_origin = "https://second.example";
        let request = |origin: &str, id: i64| {
            let body = format!(r#"{{"jsonrpc":"2.0","method":"tools/list","id":{id}}}"#);
            let head = format!(
                "POST /mcp/v1 HTTP/1.1\r\nContent-Type: application/json\r\nOrigin: {origin}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let mut framed = head.into_bytes();
            framed.extend_from_slice(body.as_bytes());
            framed
        };
        let mut input = request(first_origin, 1);
        input.extend(request(second_origin, 2));
        let config = HttpHandlerConfig {
            allow_cors: true,
            cors_origins: vec![first_origin.to_string(), second_origin.to_string()],
            ..HttpHandlerConfig::default()
        };
        let mut output = Vec::new();

        {
            let cx = Cx::for_testing();
            let mut transport = HttpTransport::with_config(Cursor::new(input), &mut output, config);
            transport.recv(&cx).expect("first request is admitted");

            let pending = transport
                .recv(&cx)
                .expect_err("a second request cannot overwrite pending response ownership");
            assert!(matches!(
                pending,
                TransportError::Io(ref error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
            ));

            transport
                .send(
                    &cx,
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        fastmcp_protocol::RequestId::Number(1),
                        serde_json::json!({"sequence": 1}),
                    )),
                )
                .expect("first response is written");
            transport.recv(&cx).expect("second request remains unread");
            transport
                .send(
                    &cx,
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        fastmcp_protocol::RequestId::Number(2),
                        serde_json::json!({"sequence": 2}),
                    )),
                )
                .expect("second response is written");
        }

        let wire = String::from_utf8(output).unwrap();
        let responses: Vec<_> = wire
            .split("HTTP/1.1 ")
            .filter(|response| !response.is_empty())
            .collect();
        assert_eq!(responses.len(), 2);
        assert!(responses[0].contains(first_origin));
        assert!(!responses[0].contains(second_origin));
        assert!(responses[0].contains(r#""sequence":1"#));
        assert!(responses[1].contains(second_origin));
        assert!(!responses[1].contains(first_origin));
        assert!(responses[1].contains(r#""sequence":2"#));
    }

    #[test]
    fn http_transport_acknowledges_notification_and_releases_origin_slot() {
        let origin = "https://trusted.example";
        let body = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let head = format!(
            "POST /mcp/v1 HTTP/1.1\r\nContent-Type: application/json\r\nOrigin: {origin}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut input = head.into_bytes();
        input.extend_from_slice(body);
        let config = HttpHandlerConfig {
            allow_cors: true,
            cors_origins: vec![origin.to_string()],
            ..HttpHandlerConfig::default()
        };
        let mut output = Vec::new();

        {
            let mut transport = HttpTransport::with_config(Cursor::new(input), &mut output, config);
            let message = transport.recv(&Cx::for_testing()).unwrap();
            assert!(
                matches!(message, JsonRpcMessage::Request(ref request) if request.is_notification())
            );
            assert!(!transport.response_pending);
            assert!(transport.response_origin.is_none());
        }

        let wire = String::from_utf8(output).unwrap();
        assert!(wire.starts_with("HTTP/1.1 202 Accepted\r\n"));
        assert!(wire.contains(&format!("access-control-allow-origin: {origin}\r\n")));
        assert!(wire.ends_with("\r\n\r\n"));
    }

    #[test]
    fn http_framing_or_eof_failure_latches_terminal_and_closed_wins_over_cancellation() {
        let body_prefix = br#"{"jsonrpc":"2.0""#;
        let head = format!(
            "POST /mcp/v1 HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body_prefix.len() + 10
        );
        let mut input = head.into_bytes();
        input.extend_from_slice(body_prefix);
        let mut transport = HttpTransport::new(Cursor::new(input), Vec::new());
        let cx = Cx::for_testing();

        assert!(matches!(transport.recv(&cx), Err(TransportError::Io(_))));
        assert!(transport.closed);
        assert!(!transport.response_pending);
        assert!(transport.response_origin.is_none());

        cx.set_cancel_requested(true);
        assert!(matches!(transport.recv(&cx), Err(TransportError::Closed)));
        assert!(matches!(
            transport.send(
                &cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    fastmcp_protocol::RequestId::Number(1),
                    serde_json::Value::Null,
                )),
            ),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn complete_http_body_codec_error_keeps_response_slot_for_jsonrpc_error() {
        let body = b"{not-json";
        let head = format!(
            "POST /mcp/v1 HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut input = head.into_bytes();
        input.extend_from_slice(body);
        let mut transport = HttpTransport::new(Cursor::new(input), Vec::new());
        let cx = Cx::for_testing();

        assert!(matches!(
            transport.recv(&cx),
            Err(TransportError::Codec(CodecError::Json(_)))
        ));
        assert!(!transport.closed);
        assert!(transport.response_pending);

        let response = JsonRpcResponse::error(
            None,
            fastmcp_protocol::JsonRpcError {
                code: -32700,
                message: "Parse error".to_string(),
                data: None,
            },
        );
        transport
            .send(&cx, &JsonRpcMessage::Response(response))
            .unwrap();
        assert!(!transport.closed);
        assert!(!transport.response_pending);
        assert!(transport.writer.starts_with(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn http_handler_rejects_escaped_duplicate_object_member() {
        let handler = HttpRequestHandler::new();
        let request = HttpRequest::new(HttpMethod::Post, "/mcp/v1")
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","method":"first","m\u0065thod":"second","id":1}"#);

        let error = handler.parse_request(&request).unwrap_err();

        assert!(matches!(
            error,
            HttpError::CodecError(CodecError::InvalidMessage {
                kind: crate::InvalidMessageKind::Request,
                ..
            })
        ));
        assert!(error.to_string().contains("duplicate JSON object member"));
    }

    #[test]
    fn http_transport_rejects_escaped_duplicate_object_member() {
        let body = br#"{"jsonrpc":"2.0","method":"first","m\u0065thod":"second","id":1}"#;
        let request_head = format!(
            "POST /mcp/v1 HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut input = request_head.into_bytes();
        input.extend_from_slice(body);
        let reader = Cursor::new(input);
        let writer = Vec::new();
        let mut transport = HttpTransport::new(reader, writer);

        let error = transport.recv(&Cx::for_testing()).unwrap_err();

        assert!(matches!(
            error,
            TransportError::Codec(CodecError::InvalidMessage {
                kind: crate::InvalidMessageKind::Request,
                ..
            })
        ));
        assert!(error.to_string().contains("duplicate JSON object member"));
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
    fn modern_json_content_type_admits_only_a_utf8_charset_parameter() {
        assert!(is_modern_json_content_type("application/json"));
        assert!(is_modern_json_content_type("Application/JSON"));
        assert!(is_modern_json_content_type(
            "application/json; charset=utf-8"
        ));
        assert!(is_modern_json_content_type(
            "application/json; charset=UTF-8"
        ));

        // The changed variable in each rejection is one parameter detail.
        assert!(!is_modern_json_content_type(
            "application/json; charset=utf-16"
        ));
        assert!(!is_modern_json_content_type(
            "application/json; charset=utf-8; boundary=x"
        ));
        assert!(!is_modern_json_content_type("application/json; nonsense"));
        assert!(!is_modern_json_content_type("text/json"));
        assert!(!is_modern_json_content_type(""));
    }

    #[test]
    fn request_content_coding_admits_only_singleton_identity() {
        assert!(is_identity_content_coding("identity"));
        assert!(is_identity_content_coding("Identity"));
        assert!(is_identity_content_coding(", identity"));

        assert!(!is_identity_content_coding("gzip"));
        assert!(!is_identity_content_coding("identity, identity"));
        assert!(!is_identity_content_coding(""));
        assert!(!is_identity_content_coding(",,,"));
    }

    #[test]
    fn coded_request_bodies_are_refused_before_json_admission() {
        let handler = HttpRequestHandler::new();

        // The identical request without the coding header parses; the sole
        // changed variable is the compressed content coding, which must be
        // a typed transport refusal rather than a JSON diagnostic.
        let admitted = HttpRequest::new(HttpMethod::Post, "/mcp/v1")
            .with_header("Content-Type", "application/json")
            .with_body(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec());
        assert!(handler.parse_request(&admitted).is_ok());

        let coded = HttpRequest::new(HttpMethod::Post, "/mcp/v1")
            .with_header("Content-Type", "application/json")
            .with_header("Content-Encoding", "gzip")
            .with_body(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec());
        let result = handler.parse_request(&coded);
        assert!(matches!(
            result,
            Err(HttpError::UnsupportedContentEncoding(value)) if value == "gzip"
        ));
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
            .with_header("Origin", "https://allowed.com")
            .with_header("Access-Control-Request-Method", "POST");
        let response = handler.handle_options(&request);
        assert_eq!(response.status, HttpStatus::OK);
        assert_eq!(
            response.headers.get("access-control-allow-origin"),
            Some(&"https://allowed.com".to_string())
        );

        // OPTIONS request from disallowed origin
        let request = HttpRequest::new(HttpMethod::Options, "/mcp/v1")
            .with_header("Origin", "https://evil.com")
            .with_header("Access-Control-Request-Method", "POST");
        let response = handler.handle_options(&request);
        assert_eq!(response.status, HttpStatus::FORBIDDEN);

        let wrong_preflight_method = HttpRequest::new(HttpMethod::Options, "/mcp/v1")
            .with_header("Origin", "https://allowed.com")
            .with_header("Access-Control-Request-Method", "GET");
        assert_eq!(
            handler.handle_options(&wrong_preflight_method).status,
            HttpStatus::FORBIDDEN
        );

        let post = HttpRequest::new(HttpMethod::Post, "/mcp/v1")
            .with_header("Content-Type", "application/json")
            .with_header("Origin", "https://evil.com")
            .with_body(r#"{"jsonrpc":"2.0","method":"test","id":1}"#);
        assert!(matches!(
            handler.parse_request(&post),
            Err(HttpError::OriginNotAllowed(origin)) if origin == "https://evil.com"
        ));

        let missing_origin = HttpRequest::new(HttpMethod::Options, "/mcp/v1");
        assert_eq!(
            handler.handle_options(&missing_origin).status,
            HttpStatus::FORBIDDEN
        );

        let wrong_path = HttpRequest::new(HttpMethod::Options, "/wrong")
            .with_header("Origin", "https://allowed.com")
            .with_header("Access-Control-Request-Method", "POST");
        assert_eq!(
            handler.handle_options(&wrong_path).status,
            HttpStatus::NOT_FOUND
        );

        let wildcard_handler = HttpRequestHandler::with_config(HttpHandlerConfig {
            allow_cors: true,
            cors_origins: vec!["*".to_string()],
            ..HttpHandlerConfig::default()
        });
        assert!(!wildcard_handler.is_origin_allowed("https://allowed.com"));
    }

    #[test]
    fn e2e_http_streaming_transport() {
        use fastmcp_protocol::RequestId;

        let mut transport = StreamableHttpTransport::new();
        let cx = Cx::for_testing();

        // Simulate multiple requests being pushed (from HTTP handlers)
        let req1 = JsonRpcRequest::new("method1", None, 1i64);
        let req2 = JsonRpcRequest::new("method2", None, 2i64);
        transport.push_request(&cx, req1).unwrap();
        transport.push_request(&cx, req2).unwrap();

        // Transport should receive requests in FIFO order.
        let msg = transport.recv(&cx).unwrap();
        if let JsonRpcMessage::Request(req) = msg {
            assert_eq!(req.method, "method1");
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
        let resp = transport.pop_response().unwrap().unwrap();
        assert_eq!(resp.id, Some(RequestId::Number(2)));
    }

    #[test]
    fn streamable_http_request_response_body_routes_only_its_bound_final_response() {
        let mut transport = StreamableHttpTransport::new();
        let response_stream = transport
            .response_stream()
            .expect("response stream can be externalized once");
        let request_id = RequestId::Number(701);
        let request_response = response_stream
            .for_request(request_id.clone())
            .expect("each request receives one response body");
        assert!(matches!(
            response_stream.for_request(request_id.clone()),
            Err(TransportError::Io(ref error)) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        let other_request_id = RequestId::Number(703);
        let other_request_response = response_stream
            .for_request(other_request_id.clone())
            .expect("independent requests receive independent response bodies");
        let request_cancellation = request_response.cancellation();
        let other_cancellation = other_request_response.cancellation();
        let cx = Cx::for_testing();

        request_cancellation
            .checkpoint(&cx)
            .expect("a live response body admits request work");
        transport
            .send_response_for_request(
                &cx,
                &other_cancellation,
                JsonRpcResponse::success(
                    other_request_id.clone(),
                    serde_json::json!({"response": "other"}),
                ),
            )
            .expect("an independent request response remains queued for its own body");
        transport
            .send_response_for_request(
                &cx,
                &request_cancellation,
                JsonRpcResponse::success(
                    request_id.clone(),
                    serde_json::json!({"response": "bound"}),
                ),
            )
            .expect("a live request response body accepts its final response");

        let response = request_response
            .recv_response(&cx)
            .expect("the request response body receives only its bound response");
        assert_eq!(response.id, Some(request_id));
        assert!(request_response.is_finished());
        assert!(request_cancellation.is_cancelled());
        assert_eq!(response_stream.pending_responses(), 1);
        assert!(matches!(
            request_response.pop_response(),
            Err(TransportError::Closed)
        ));
        let other_response = other_request_response
            .recv_response(&cx)
            .expect("the second body receives the response retained for its request ID");
        assert_eq!(other_response.id, Some(other_request_id));
        assert_eq!(response_stream.pending_responses(), 0);
    }

    #[test]
    fn streamable_http_request_owned_notifications_are_ordered_bounded_and_terminal() {
        let mut transport =
            StreamableHttpTransport::with_capacity(2).expect("capacity two is valid");
        let response_stream = transport
            .response_stream()
            .expect("response stream can be externalized once");
        let request_id = RequestId::Number(704);
        let request_body = response_stream
            .for_request(request_id.clone())
            .expect("the request receives one response body");
        let cancellation = request_body.cancellation();
        let cx = Cx::for_testing();

        transport
            .send_notification_for_request(
                &cx,
                &cancellation,
                JsonRpcRequest::notification(
                    "notifications/progress",
                    Some(serde_json::json!({"progress": 1})),
                ),
            )
            .expect("the first notification is admitted");
        transport
            .send_notification_for_request(
                &cx,
                &cancellation,
                JsonRpcRequest::notification(
                    "notifications/progress",
                    Some(serde_json::json!({"progress": 2})),
                ),
            )
            .expect("the second notification is admitted");
        assert_eq!(response_stream.pending_responses(), 2);
        assert!(matches!(
            transport.send_notification_for_request(
                &cx,
                &cancellation,
                JsonRpcRequest::notification("notifications/progress", None),
            ),
            Err(TransportError::Io(ref error)) if error.kind() == std::io::ErrorKind::WouldBlock
        ));

        assert!(matches!(
            request_body
                .recv_message(&cx)
                .expect("the first queued message is readable"),
            StreamableHttpRequestResponseMessage::Notification(notification)
                if notification.method == "notifications/progress"
                    && notification.params == Some(serde_json::json!({"progress": 1}))
        ));
        assert!(!request_body.is_finished());
        transport
            .send_response_for_request(
                &cx,
                &cancellation,
                JsonRpcResponse::success(request_id.clone(), serde_json::json!({"complete": true})),
            )
            .expect("draining one notification makes room for the terminal response");
        assert!(cancellation.is_terminal_committed());

        assert!(matches!(
            request_body
                .recv_message(&cx)
                .expect("the second notification remains ahead of the terminal response"),
            StreamableHttpRequestResponseMessage::Notification(notification)
                if notification.params == Some(serde_json::json!({"progress": 2}))
        ));
        assert!(matches!(
            request_body
                .recv_message(&cx)
                .expect("the final message is the terminal response"),
            StreamableHttpRequestResponseMessage::Response(response)
                if response.id == Some(request_id)
        ));
        assert!(request_body.is_finished());
        assert_eq!(response_stream.pending_responses(), 0);
    }

    #[test]
    fn streamable_http_notification_rejects_a_foreign_request_owner_without_mutation() {
        let mut transport = StreamableHttpTransport::new();
        let response_stream = transport
            .response_stream()
            .expect("response stream can be externalized once");
        let request_id = RequestId::Number(705);
        let request_body = response_stream
            .for_request(request_id.clone())
            .expect("the local request body is registered");
        let local_cancellation = request_body.cancellation();

        let mut foreign_transport = StreamableHttpTransport::new();
        let foreign_stream = foreign_transport
            .response_stream()
            .expect("the foreign response stream can be externalized once");
        let foreign_body = foreign_stream
            .for_request(request_id)
            .expect("the foreign request has the same ID but a distinct owner");
        let foreign_cancellation = foreign_body.cancellation();
        let cx = Cx::for_testing();
        let pending_before = response_stream.pending_responses();
        let retained_before = transport
            .response_mailbox
            .lock()
            .expect("response mailbox is available")
            .retained_bytes;

        // Planted forbidden dimension: only the guard belongs to a different
        // transport; the JSON-RPC ID and notification are otherwise valid.
        assert!(matches!(
            transport.send_notification_for_request(
                &cx,
                &foreign_cancellation,
                JsonRpcRequest::notification("notifications/progress", None),
            ),
            Err(TransportError::Io(ref error)) if error.kind() == std::io::ErrorKind::InvalidInput
        ));
        assert_eq!(response_stream.pending_responses(), pending_before);
        assert_eq!(
            transport
                .response_mailbox
                .lock()
                .expect("response mailbox is available")
                .retained_bytes,
            retained_before,
            "a foreign owner must not mutate the local response stream"
        );
        assert!(
            request_body
                .pop_message()
                .expect("the local body remains readable")
                .is_none()
        );
        local_cancellation
            .checkpoint(&cx)
            .expect("the local body remains live after a foreign-owner rejection");
    }

    #[test]
    fn streamable_http_rejects_sse_binding_over_an_unowned_queued_response() {
        let mut transport = StreamableHttpTransport::new();
        let response_stream = transport
            .response_stream()
            .expect("response stream can be externalized once");
        let request_id = RequestId::Number(707);
        let cx = Cx::for_testing();
        transport
            .send(
                &cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    request_id.clone(),
                    serde_json::json!({"unowned": true}),
                )),
            )
            .expect("an unowned response is queued before SSE binding");
        let pending_before = response_stream.pending_responses();
        let retained_before = transport
            .response_mailbox
            .lock()
            .expect("response mailbox is available")
            .retained_bytes;

        // Planted forbidden dimension: only a generic response for this ID
        // was queued before the otherwise valid SSE body registration.
        assert!(matches!(
            response_stream.for_request(request_id.clone()),
            Err(TransportError::Io(ref error)) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(response_stream.pending_responses(), pending_before);
        assert_eq!(
            transport
                .response_mailbox
                .lock()
                .expect("response mailbox is available")
                .retained_bytes,
            retained_before,
            "rejected SSE binding must preserve the generic response byte reservation"
        );
        assert_eq!(
            response_stream
                .pop_response(Some(&request_id))
                .expect("the generic response remains independently consumable")
                .expect("the generic response remains queued")
                .id,
            Some(request_id)
        );
        assert_eq!(response_stream.pending_responses(), 0);
    }

    #[test]
    fn streamable_http_notification_rejects_a_closed_request_body_without_mutation() {
        let mut transport = StreamableHttpTransport::new();
        let response_stream = transport
            .response_stream()
            .expect("response stream can be externalized once");
        let request_body = response_stream
            .for_request(RequestId::Number(706))
            .expect("the request body is registered");
        let cancellation = request_body.cancellation();
        let cx = Cx::for_testing();
        transport
            .send_notification_for_request(
                &cx,
                &cancellation,
                JsonRpcRequest::notification("notifications/progress", None),
            )
            .expect("the live request body accepts its notification");
        assert_eq!(response_stream.pending_responses(), 1);
        assert!(
            transport
                .response_mailbox
                .lock()
                .expect("response mailbox is available")
                .retained_bytes
                > 0
        );

        // Planted forbidden dimension: only the request body is dropped before
        // the otherwise identical notification commit.
        drop(request_body);

        assert_eq!(
            response_stream.pending_responses(),
            0,
            "closing a request body releases its queued notifications"
        );
        assert_eq!(
            transport
                .response_mailbox
                .lock()
                .expect("response mailbox is available")
                .retained_bytes,
            0,
            "closing a request body releases its notification byte reservation"
        );

        assert!(matches!(
            transport.send_notification_for_request(
                &cx,
                &cancellation,
                JsonRpcRequest::notification("notifications/progress", None),
            ),
            Err(TransportError::Cancelled)
        ));
        assert_eq!(response_stream.pending_responses(), 0);
        assert_eq!(
            transport
                .response_mailbox
                .lock()
                .expect("response mailbox is available")
                .retained_bytes,
            0,
            "a closed request body must not retain a notification"
        );
        assert!(!response_stream.is_closed());
    }

    #[test]
    fn streamable_http_request_response_body_disconnect_cancels_before_commit() {
        let mut transport = StreamableHttpTransport::new();
        let response_stream = transport
            .response_stream()
            .expect("response stream can be externalized once");
        let request_response = response_stream
            .for_request(RequestId::Number(702))
            .expect("the response body is registered before dispatch");
        let request_cancellation = request_response.cancellation();
        let cx = Cx::for_testing();
        let pending_before = response_stream.pending_responses();

        // Planted forbidden dimension: the otherwise live request response
        // body is dropped, modeling peer disconnect before handler commit.
        drop(request_response);

        assert!(request_cancellation.is_cancelled());
        assert!(matches!(
            request_cancellation.checkpoint(&cx),
            Err(TransportError::Cancelled)
        ));
        assert_eq!(
            response_stream.pending_responses(),
            pending_before,
            "disconnect cancellation must not enqueue or consume another request's response"
        );
        assert!(
            !response_stream.is_closed(),
            "one request-body disconnect must not close independent response bodies"
        );
    }

    #[test]
    fn streamable_http_request_response_body_enforces_backpressure_and_terminal_commit() {
        let mut transport =
            StreamableHttpTransport::with_capacity(1).expect("capacity one is valid");
        let response_stream = transport
            .response_stream()
            .expect("response stream can be externalized once");
        let first_id = RequestId::Number(801);
        let first_body = response_stream
            .for_request(first_id.clone())
            .expect("the first response body is registered");
        let first_cancellation = first_body.cancellation();
        let second_id = RequestId::Number(802);
        let second_body = response_stream
            .for_request(second_id.clone())
            .expect("the second response body is registered");
        let second_cancellation = second_body.cancellation();
        let cx = Cx::for_testing();

        transport
            .send_response_for_request(
                &cx,
                &first_cancellation,
                JsonRpcResponse::success(first_id.clone(), serde_json::json!({"sequence": 1})),
            )
            .expect("the first bounded response is admitted");
        assert!(first_cancellation.is_terminal_committed());
        assert!(matches!(
            transport.send(
                &cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    first_id.clone(),
                    serde_json::json!({"raw_bypass": true}),
                )),
            ),
            Err(TransportError::Io(ref error)) if error.kind() == std::io::ErrorKind::InvalidInput
        ));
        let retained_before_backpressure = transport
            .response_mailbox
            .lock()
            .expect("response mailbox is available")
            .retained_bytes;
        assert!(matches!(
            transport.send_response_for_request(
                &cx,
                &second_cancellation,
                JsonRpcResponse::success(second_id.clone(), serde_json::json!({"sequence": 2})),
            ),
            Err(TransportError::Io(ref error)) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert_eq!(response_stream.pending_responses(), 1);
        assert_eq!(
            transport
                .response_mailbox
                .lock()
                .expect("response mailbox is available")
                .retained_bytes,
            retained_before_backpressure,
            "a slow consumer must not grow the bounded response mailbox"
        );

        assert_eq!(
            first_body
                .recv_response(&cx)
                .expect("the first body drains its final response")
                .id,
            Some(first_id.clone())
        );
        assert!(first_body.is_finished());
        assert!(first_cancellation.is_cancelled());
        assert!(matches!(
            transport.send_response_for_request(
                &cx,
                &first_cancellation,
                JsonRpcResponse::success(first_id, serde_json::json!({"late": true})),
            ),
            Err(TransportError::Cancelled)
        ));
        assert_eq!(response_stream.pending_responses(), 0);

        transport
            .send_response_for_request(
                &cx,
                &second_cancellation,
                JsonRpcResponse::success(second_id.clone(), serde_json::json!({"sequence": 2})),
            )
            .expect("draining the first body releases exactly one response slot");
        assert_eq!(
            second_body
                .recv_response(&cx)
                .expect("the second body receives the response admitted after backpressure")
                .id,
            Some(second_id)
        );
        assert_eq!(response_stream.pending_responses(), 0);
    }

    #[test]
    fn streamable_http_request_response_body_rejects_commit_after_disconnect() {
        let mut transport = StreamableHttpTransport::new();
        let response_stream = transport
            .response_stream()
            .expect("response stream can be externalized once");
        let request_id = RequestId::Number(803);
        let request_body = response_stream
            .for_request(request_id.clone())
            .expect("the response body is registered before dispatch");
        let request_cancellation = request_body.cancellation();
        let cx = Cx::for_testing();
        let pending_before = response_stream.pending_responses();
        let retained_before = transport
            .response_mailbox
            .lock()
            .expect("response mailbox is available")
            .retained_bytes;

        // Planted forbidden dimension: only the request body is dropped before
        // the handler attempts its otherwise identical response commit.
        drop(request_body);

        assert!(matches!(
            transport.send_response_for_request(
                &cx,
                &request_cancellation,
                JsonRpcResponse::success(request_id, serde_json::json!({"late": true})),
            ),
            Err(TransportError::Cancelled)
        ));
        assert_eq!(response_stream.pending_responses(), pending_before);
        assert_eq!(
            transport
                .response_mailbox
                .lock()
                .expect("response mailbox is available")
                .retained_bytes,
            retained_before,
            "a cancelled request must leave queued-response accounting unchanged"
        );
        assert!(!response_stream.is_closed());
    }

    #[test]
    fn streamable_http_response_body_admission_closes_with_the_shared_stream() {
        let mut transport = StreamableHttpTransport::new();
        let response_stream = transport
            .response_stream()
            .expect("response stream can be externalized once");

        let live_body = response_stream
            .for_request(RequestId::Number(804))
            .expect("an open response stream admits a request-owned body");
        assert_eq!(
            response_stream
                .live_request_bodies()
                .expect("live body registry is observable"),
            1
        );
        drop(live_body);
        assert_eq!(
            response_stream
                .live_request_bodies()
                .expect("dropped body releases the registry entry"),
            0
        );

        response_stream.close();

        // Planted forbidden dimension: only the shared response stream has
        // closed. Registration must fail before it allocates a request body.
        assert!(matches!(
            response_stream.for_request(RequestId::Number(805)),
            Err(TransportError::Closed)
        ));
        assert_eq!(
            response_stream
                .live_request_bodies()
                .expect("closed admission leaves the registry unchanged"),
            0
        );
    }

    #[test]
    fn streamable_http_request_ingress_feeds_transport_owned_by_recv_thread() {
        let mut transport =
            StreamableHttpTransport::with_capacity(1).expect("capacity one is valid");
        let empty_polls = Arc::clone(&transport.request_empty_polls);
        let ingress = transport
            .request_ingress()
            .expect("request ingress can be externalized once");
        let receive_cx = Cx::for_testing();
        let cancel_cx = receive_cx.clone();
        let (result_sender, result_receiver) = std::sync::mpsc::channel();

        let worker = std::thread::spawn(move || {
            let mut transport = transport;
            let result = transport.recv(&receive_cx);
            result_sender
                .send(result)
                .expect("test result receiver remains available");
        });

        if !wait_for_counter(&empty_polls, 1) {
            cancel_cx.set_cancel_requested(true);
            worker.join().expect("receive thread cancels cleanly");
            panic!("transport did not enter its empty receive wait");
        }
        ingress
            .push_request(
                &Cx::for_testing(),
                JsonRpcRequest::new("concurrent/ingress", None, 17_i64),
            )
            .expect("independent ingress can feed the owned transport");

        let received = match result_receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(result) => result.expect("transport receives the concurrent request"),
            Err(error) => {
                cancel_cx.set_cancel_requested(true);
                let _ = worker.join();
                panic!("transport did not receive concurrent ingress: {error}");
            }
        };
        worker.join().expect("receive thread completes");

        let JsonRpcMessage::Request(request) = received else {
            panic!("expected request");
        };
        assert_eq!(request.method, "concurrent/ingress");
    }

    #[test]
    fn streamable_http_response_stream_consumes_while_transport_is_owned_elsewhere() {
        use fastmcp_protocol::RequestId;

        let mut transport =
            StreamableHttpTransport::with_capacity(1).expect("capacity one is valid");
        let response_stream = transport
            .response_stream()
            .expect("response stream can be externalized once");
        let entered_empty_waits = Arc::clone(&response_stream.entered_empty_waits);
        let receive_cx = Cx::for_testing();
        let cancel_cx = receive_cx.clone();
        let (result_sender, result_receiver) = std::sync::mpsc::channel();
        let request_id = RequestId::Number(23);
        let worker_request_id = request_id.clone();

        let worker = std::thread::spawn(move || {
            let result = response_stream.recv_response(&receive_cx, Some(&worker_request_id));
            result_sender
                .send(result)
                .expect("test result receiver remains available");
        });

        if !wait_for_counter(&entered_empty_waits, 1) {
            cancel_cx.set_cancel_requested(true);
            worker.join().expect("response thread cancels cleanly");
            panic!("response consumer did not enter its empty wait");
        }
        transport
            .send(
                &Cx::for_testing(),
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    request_id,
                    serde_json::json!({"concurrent": true}),
                )),
            )
            .expect("transport can produce for an independent response consumer");

        let response = match result_receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(result) => result.expect("response stream receives the concurrent response"),
            Err(error) => {
                cancel_cx.set_cancel_requested(true);
                let _ = worker.join();
                panic!("response stream did not receive transport output: {error}");
            }
        };
        worker.join().expect("response thread completes");
        assert_eq!(response.id, Some(RequestId::Number(23)));
        assert_eq!(transport.pending_responses(), 0);
    }

    #[test]
    fn streamable_http_correlates_two_concurrent_consumers_exactly_once() {
        let mut transport =
            StreamableHttpTransport::with_capacity(2).expect("capacity two is valid");
        let first_stream = transport
            .response_stream()
            .expect("response stream can be externalized once");
        let second_stream = first_stream.clone();
        let entered_empty_waits = Arc::clone(&first_stream.entered_empty_waits);
        let (result_sender, result_receiver) = std::sync::mpsc::channel();
        let first_cx = Cx::for_testing();
        let first_cancel_cx = first_cx.clone();
        let second_cx = Cx::for_testing();
        let second_cancel_cx = second_cx.clone();

        let first_sender = result_sender.clone();
        let first_worker = std::thread::spawn(move || {
            let id = RequestId::Number(101);
            first_sender
                .send((id.clone(), first_stream.recv_response(&first_cx, Some(&id))))
                .expect("test result receiver remains available");
        });
        let second_worker = std::thread::spawn(move || {
            let id = RequestId::Number(202);
            result_sender
                .send((
                    id.clone(),
                    second_stream.recv_response(&second_cx, Some(&id)),
                ))
                .expect("test result receiver remains available");
        });

        if !wait_for_counter(&entered_empty_waits, 2) {
            first_cancel_cx.set_cancel_requested(true);
            second_cancel_cx.set_cancel_requested(true);
            first_worker.join().expect("first consumer cancels cleanly");
            second_worker
                .join()
                .expect("second consumer cancels cleanly");
            panic!("both correlated consumers did not enter empty waits");
        }
        for (id, marker) in [(RequestId::Number(202), 2), (RequestId::Number(101), 1)] {
            transport
                .send(
                    &Cx::for_testing(),
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        id,
                        serde_json::json!({"consumer": marker}),
                    )),
                )
                .expect("each correlated response is admitted");
        }

        let received = (0..2)
            .map(|_| result_receiver.recv_timeout(Duration::from_secs(1)))
            .collect::<Result<Vec<_>, _>>();
        if received.is_err() {
            first_cancel_cx.set_cancel_requested(true);
            second_cancel_cx.set_cancel_requested(true);
        }
        first_worker.join().expect("first consumer completes");
        second_worker.join().expect("second consumer completes");

        let mut observed = HashSet::new();
        for (expected_id, result) in received.expect("both consumers complete") {
            let response = result.expect("correlated receive succeeds");
            assert_eq!(response.id.as_ref(), Some(&expected_id));
            assert!(
                observed.insert(expected_id),
                "response delivered more than once"
            );
        }
        assert_eq!(observed.len(), 2);
        assert_eq!(transport.pending_responses(), 0);
    }

    #[test]
    fn streamable_http_unmatched_pop_retains_response_and_byte_reservation() {
        let mut transport = StreamableHttpTransport::new();
        let response_stream = transport
            .response_stream()
            .expect("response stream can be externalized once");
        let expected_id = RequestId::Number(303);
        transport
            .send(
                &Cx::for_testing(),
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    expected_id.clone(),
                    serde_json::json!({"retained": true}),
                )),
            )
            .expect("response is admitted");
        let retained_before = transport
            .response_mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retained_bytes;
        assert!(retained_before > 0);

        assert!(
            response_stream
                .pop_response(Some(&RequestId::Number(404)))
                .expect("unmatched pop is not terminal")
                .is_none()
        );
        assert_eq!(transport.pending_responses(), 1);
        assert_eq!(
            transport
                .response_mailbox
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retained_bytes,
            retained_before
        );

        let response = response_stream
            .pop_response(Some(&expected_id))
            .expect("matching pop succeeds")
            .expect("matching response is still retained");
        assert_eq!(response.id, Some(expected_id));
        assert_eq!(transport.pending_responses(), 0);
        assert_eq!(
            transport
                .response_mailbox
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retained_bytes,
            0
        );
    }

    #[test]
    fn e2e_http_streaming_response_queue_is_fifo() {
        use fastmcp_protocol::RequestId;

        let mut transport = StreamableHttpTransport::new();
        let cx = Cx::for_testing();

        let first = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            result: Some(serde_json::json!({"seq": 1})),
            error: None,
            id: Some(RequestId::Number(1)),
        };
        let second = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            result: Some(serde_json::json!({"seq": 2})),
            error: None,
            id: Some(RequestId::Number(2)),
        };

        transport
            .send(&cx, &JsonRpcMessage::Response(first))
            .unwrap();
        transport
            .send(&cx, &JsonRpcMessage::Response(second))
            .unwrap();

        let first_out = transport
            .pop_response()
            .expect("response channel remains open")
            .expect("first response");
        let second_out = transport
            .pop_response()
            .expect("response channel remains open")
            .expect("second response");
        assert_eq!(first_out.id, Some(RequestId::Number(1)));
        assert_eq!(second_out.id, Some(RequestId::Number(2)));
    }

    #[test]
    fn e2e_http_streaming_rejects_server_to_client_requests() {
        let mut transport = StreamableHttpTransport::new();
        let cx = Cx::for_testing();
        let request = JsonRpcRequest::notification("notifications/message", None);

        let err = transport
            .send(&cx, &JsonRpcMessage::Request(request))
            .expect_err("streamable transport must reject server-to-client requests");

        assert!(matches!(err, TransportError::Io(_)));
    }

    #[test]
    fn e2e_http_streaming_response_queue_is_hard_bounded() {
        use fastmcp_protocol::RequestId;

        let mut transport =
            StreamableHttpTransport::with_capacity(1).expect("capacity one is valid");
        let cx = Cx::for_testing();
        let first = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            result: Some(serde_json::json!({"ok": true})),
            error: None,
            id: Some(RequestId::Number(1)),
        };
        let second = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            result: Some(serde_json::json!({"ok": true})),
            error: None,
            id: Some(RequestId::Number(2)),
        };

        transport
            .send(&cx, &JsonRpcMessage::Response(first))
            .unwrap();

        let err = transport
            .send(&cx, &JsonRpcMessage::Response(second))
            .expect_err("a second queued response must exceed capacity one");
        assert!(matches!(
            err,
            TransportError::Io(ref error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert_eq!(transport.pending_responses(), 1);
    }

    #[test]
    fn e2e_http_streaming_request_queue_is_hard_bounded_and_fifo() {
        let mut transport =
            StreamableHttpTransport::with_capacity(1).expect("capacity one is valid");
        let cx = Cx::for_testing();
        transport
            .push_request(&cx, JsonRpcRequest::new("first", None, 1i64))
            .unwrap();
        let error = transport
            .push_request(&cx, JsonRpcRequest::new("rejected", None, 2i64))
            .expect_err("a second queued request must exceed capacity one");
        assert!(matches!(
            error,
            TransportError::Io(ref error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));

        let JsonRpcMessage::Request(request) = transport.recv(&cx).unwrap() else {
            panic!("expected request");
        };
        assert_eq!(request.method, "first");
        assert_eq!(transport.pending_requests(), 0);
    }

    #[test]
    fn streamable_http_rejects_invalid_or_oversized_typed_messages_before_queueing() {
        let cx = Cx::for_testing();
        let mut transport =
            StreamableHttpTransport::with_capacity(2).expect("capacity two is valid");
        transport.codec.set_max_message_size(64);

        let oversized = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"payload": "x".repeat(128)})),
            1_i64,
        );
        assert!(matches!(
            transport.push_request(&cx, oversized),
            Err(TransportError::Codec(CodecError::MessageTooLarge(_)))
        ));
        assert_eq!(transport.pending_requests(), 0);

        let invalid_response = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            result: None,
            error: None,
            id: Some(fastmcp_protocol::RequestId::Number(1)),
        };
        assert!(matches!(
            transport.send(&cx, &JsonRpcMessage::Response(invalid_response)),
            Err(TransportError::Codec(CodecError::Json(_)))
        ));
        assert_eq!(transport.pending_responses(), 0);
    }

    #[test]
    fn streamable_http_enforces_aggregate_byte_budgets_in_both_directions() {
        const TEST_BYTE_BUDGET: usize = 512;

        let cx = Cx::for_testing();
        let mut transport = StreamableHttpTransport::with_queue_limits(4, TEST_BYTE_BUDGET)
            .expect("test limits are valid");
        let (request_ingress, response_stream) = transport
            .split_handles()
            .expect("endpoints can be externalized once");
        let request = JsonRpcRequest::new(
            "budget/request",
            Some(serde_json::json!({"payload": "x".repeat(320)})),
            1_i64,
        );
        let request_bytes = transport
            .codec
            .encode_request(&request)
            .expect("request is encodable")
            .len();
        assert!(request_bytes <= TEST_BYTE_BUDGET);
        assert!(request_bytes * 2 > TEST_BYTE_BUDGET);

        request_ingress.push_request(&cx, request.clone()).unwrap();
        let request_error = request_ingress
            .push_request(&cx, request.clone())
            .expect_err("aggregate request bytes must be bounded");
        assert!(matches!(
            request_error,
            TransportError::Io(ref error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert!(matches!(
            transport.recv(&cx).unwrap(),
            JsonRpcMessage::Request(_)
        ));
        request_ingress
            .push_request(&cx, request)
            .expect("dequeue releases the request byte budget");

        let response = JsonRpcResponse::success(
            fastmcp_protocol::RequestId::Number(1),
            serde_json::json!({"payload": "x".repeat(320)}),
        );
        let response_bytes = transport
            .codec
            .encode_response(&response)
            .expect("response is encodable")
            .len();
        assert!(response_bytes <= TEST_BYTE_BUDGET);
        assert!(response_bytes * 2 > TEST_BYTE_BUDGET);

        transport
            .send(&cx, &JsonRpcMessage::Response(response.clone()))
            .unwrap();
        let response_error = transport
            .send(&cx, &JsonRpcMessage::Response(response.clone()))
            .expect_err("aggregate response bytes must be bounded");
        assert!(matches!(
            response_error,
            TransportError::Io(ref error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        response_stream
            .pop_response(Some(&fastmcp_protocol::RequestId::Number(1)))
            .expect("response queue remains open")
            .expect("one response was queued");
        transport
            .send(&cx, &JsonRpcMessage::Response(response))
            .expect("dequeue releases the response byte budget");
    }

    #[test]
    fn e2e_http_streaming_rejects_zero_capacity() {
        assert!(matches!(
            StreamableHttpTransport::with_capacity(0),
            Err(TransportError::Io(ref error))
                if error.kind() == std::io::ErrorKind::InvalidInput
        ));
        assert!(matches!(
            StreamableHttpTransport::with_capacity(MAX_STREAMABLE_QUEUE_CAPACITY + 1),
            Err(TransportError::Io(ref error))
                if error.kind() == std::io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn streamable_http_close_is_terminal_for_public_queue_operations() {
        let cx = Cx::for_testing();
        let mut transport =
            StreamableHttpTransport::with_capacity(1).expect("capacity one is valid");
        let (request_ingress, response_stream) = transport
            .split_handles()
            .expect("endpoints can be externalized once");
        let response_id = fastmcp_protocol::RequestId::Number(1);
        transport
            .send(
                &cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    response_id.clone(),
                    serde_json::Value::Null,
                )),
            )
            .unwrap();
        request_ingress
            .push_request(&cx, JsonRpcRequest::new("queued", None, 1_i64))
            .unwrap();
        assert!(transport.has_responses());
        assert_eq!(transport.pending_requests(), 1);
        assert_eq!(transport.pending_responses(), 1);

        transport.close().unwrap();

        assert!(transport.has_responses());
        assert_eq!(transport.pending_requests(), 0);
        assert_eq!(transport.pending_responses(), 1);
        assert!(request_ingress.is_closed());
        assert!(response_stream.is_closed());
        cx.set_cancel_requested(true);
        assert!(matches!(
            transport.push_request(&cx, JsonRpcRequest::new("after-close", None, 2_i64)),
            Err(TransportError::Closed)
        ));
        assert!(matches!(
            request_ingress
                .push_request(&cx, JsonRpcRequest::new("after-close-handle", None, 3_i64)),
            Err(TransportError::Closed)
        ));
        let drained = response_stream
            .pop_response(Some(&response_id))
            .expect("already-admitted response remains drainable")
            .expect("queued response is retained across graceful close");
        assert_eq!(drained.id, Some(response_id.clone()));
        assert_eq!(transport.pending_responses(), 0);
        assert!(matches!(
            response_stream.pop_response(Some(&response_id)),
            Err(TransportError::Closed)
        ));
        assert!(matches!(
            transport.send(
                &cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    fastmcp_protocol::RequestId::Number(2),
                    serde_json::Value::Null,
                )),
            ),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn streamable_http_owner_drop_closes_external_handles() {
        let (request_ingress, response_stream) = {
            let mut transport = StreamableHttpTransport::new();
            transport
                .split_handles()
                .expect("endpoints can be externalized once")
        };

        assert!(request_ingress.is_closed());
        assert!(response_stream.is_closed());
        assert!(matches!(
            request_ingress.push_request(
                &Cx::for_testing(),
                JsonRpcRequest::new("after-owner-drop", None, 1_i64)
            ),
            Err(TransportError::Closed)
        ));
        assert!(matches!(
            response_stream.pop_response(Some(&fastmcp_protocol::RequestId::Number(1))),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn streamable_http_owner_drop_preserves_admitted_response_for_external_drain() {
        let response_id = fastmcp_protocol::RequestId::Number(77);
        let response_stream = {
            let mut transport = StreamableHttpTransport::new();
            let response_stream = transport
                .response_stream()
                .expect("response stream can be externalized once");
            transport
                .send(
                    &Cx::for_testing(),
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        response_id.clone(),
                        serde_json::json!({"drain": true}),
                    )),
                )
                .expect("response is admitted before owner drop");
            response_stream
        };

        let response = response_stream
            .pop_response(Some(&response_id))
            .expect("owner drop still permits an admitted response to drain")
            .expect("the admitted response remains present");
        assert_eq!(response.id, Some(response_id.clone()));
        assert!(matches!(
            response_stream.pop_response(Some(&response_id)),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn streamable_http_externalizes_each_endpoint_exactly_once() {
        let mut request_transport = StreamableHttpTransport::new();
        let request_ingress = request_transport
            .request_ingress()
            .expect("request ingress can be externalized once");
        assert!(request_transport.request_sender.is_none());
        assert!(matches!(
            request_transport.request_ingress(),
            Err(TransportError::Io(ref error))
                if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        drop(request_ingress);
        assert!(matches!(
            request_transport.recv(&Cx::for_testing()),
            Err(TransportError::Closed)
        ));

        let mut response_transport = StreamableHttpTransport::new();
        let response_stream = response_transport
            .response_stream()
            .expect("response stream can be externalized once");
        assert!(matches!(
            response_transport.response_stream(),
            Err(TransportError::Io(ref error))
                if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert!(matches!(
            response_transport.pop_response(),
            Err(TransportError::Io(ref error))
                if error.kind() == std::io::ErrorKind::InvalidInput
        ));
        response_transport
            .send(
                &Cx::for_testing(),
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    fastmcp_protocol::RequestId::Number(1),
                    serde_json::Value::Null,
                )),
            )
            .expect("response is admitted while the external consumer lives");
        assert_eq!(response_transport.pending_responses(), 1);
        drop(response_stream);
        assert_eq!(response_transport.pending_responses(), 0);
        assert_eq!(
            response_transport
                .response_mailbox
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retained_bytes,
            0
        );
        assert!(matches!(
            response_transport.send(
                &Cx::for_testing(),
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    fastmcp_protocol::RequestId::Number(2),
                    serde_json::Value::Null,
                )),
            ),
            Err(TransportError::Closed)
        ));
        assert_eq!(response_transport.pending_responses(), 0);
    }

    #[test]
    fn streamable_http_response_pop_and_admission_are_nonblocking_under_contention() {
        let mut transport = StreamableHttpTransport::new();
        let response_stream = transport
            .response_stream()
            .expect("response stream can be externalized once");
        let mailbox = Arc::clone(&transport.response_mailbox);
        let mailbox_guard = mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        assert!(matches!(
            response_stream.pop_response(Some(&fastmcp_protocol::RequestId::Number(1))),
            Err(TransportError::Io(ref error))
                if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert!(matches!(
            transport.send(
                &Cx::for_testing(),
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    fastmcp_protocol::RequestId::Number(1),
                    serde_json::Value::Null,
                )),
            ),
            Err(TransportError::Io(ref error))
                if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert_eq!(transport.pending_responses(), 0);
        drop(mailbox_guard);
    }

    #[test]
    fn streamable_http_observes_deadline_budget_and_masked_checkpoint_semantics() {
        let mut transport =
            StreamableHttpTransport::with_capacity(2).expect("capacity two is valid");
        let deadline_cx = Cx::for_testing_with_budget(
            asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
        );
        assert!(matches!(
            transport.push_request(&deadline_cx, JsonRpcRequest::new("expired", None, 1_i64),),
            Err(TransportError::Timeout)
        ));
        assert_eq!(transport.pending_requests(), 0);

        let exhausted_cx =
            Cx::for_testing_with_budget(asupersync::Budget::new().with_poll_quota(0));
        assert!(matches!(
            transport.push_request(
                &exhausted_cx,
                JsonRpcRequest::new("budget-exhausted", None, 2_i64),
            ),
            Err(TransportError::Cancelled)
        ));

        let masked_deadline_cx = Cx::for_testing_with_budget(
            asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
        );
        masked_deadline_cx.masked(|| {
            transport
                .push_request(
                    &masked_deadline_cx,
                    JsonRpcRequest::new("masked", None, 3_i64),
                )
                .expect("masking defers deadline enforcement at the checkpoint");
        });
        assert!(matches!(
            transport.recv(&Cx::for_testing()),
            Ok(JsonRpcMessage::Request(ref request)) if request.method == "masked"
        ));
        assert!(matches!(
            transport.push_request(
                &masked_deadline_cx,
                JsonRpcRequest::new("after-mask", None, 4_i64),
            ),
            Err(TransportError::Timeout)
        ));

        let mut response_transport = StreamableHttpTransport::new();
        let response_stream = response_transport
            .response_stream()
            .expect("response stream can be externalized once");
        let response_id = fastmcp_protocol::RequestId::Number(5);
        response_transport
            .send(
                &Cx::for_testing(),
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    response_id.clone(),
                    serde_json::Value::Null,
                )),
            )
            .expect("response is admitted");
        let cancelled_cx = Cx::for_testing();
        cancelled_cx.set_cancel_requested(true);
        let masked_response = cancelled_cx
            .masked(|| response_stream.recv_response(&cancelled_cx, Some(&response_id)));
        assert_eq!(
            masked_response.expect("masking defers cancellation").id,
            Some(response_id)
        );

        let mut empty_transport = StreamableHttpTransport::new();
        let empty_stream = empty_transport
            .response_stream()
            .expect("response stream can be externalized once");
        let expired_wait_cx = Cx::for_testing_with_budget(
            asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
        );
        assert!(matches!(
            empty_stream.recv_response(
                &expired_wait_cx,
                Some(&fastmcp_protocol::RequestId::Number(6)),
            ),
            Err(TransportError::Timeout)
        ));
    }

    #[test]
    fn streamable_http_transport_send_and_recv_use_checkpoint_not_raw_cancel_flag() {
        let mut send_transport = StreamableHttpTransport::new();
        let deadline_cx = Cx::for_testing_with_budget(
            asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
        );
        assert!(matches!(
            send_transport.send(
                &deadline_cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    fastmcp_protocol::RequestId::Number(1),
                    serde_json::Value::Null,
                )),
            ),
            Err(TransportError::Timeout)
        ));
        assert_eq!(send_transport.pending_responses(), 0);

        let masked_cx = Cx::for_testing();
        masked_cx.set_cancel_requested(true);
        masked_cx.masked(|| {
            send_transport
                .send(
                    &masked_cx,
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        fastmcp_protocol::RequestId::Number(2),
                        serde_json::Value::Null,
                    )),
                )
                .expect("masking defers cancellation during send admission");
        });
        assert_eq!(
            send_transport
                .pop_response()
                .expect("direct response consumer remains open")
                .expect("masked send admitted one response")
                .id,
            Some(fastmcp_protocol::RequestId::Number(2))
        );

        let mut receive_transport = StreamableHttpTransport::new();
        let expired_receive_cx = Cx::for_testing_with_budget(
            asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
        );
        assert!(matches!(
            receive_transport.recv(&expired_receive_cx),
            Err(TransportError::Timeout)
        ));
    }

    #[test]
    fn streamable_http_recv_drains_admission_that_finishes_during_ingress_close() {
        let mut transport =
            StreamableHttpTransport::with_capacity(1).expect("capacity one is valid");
        let empty_polls = Arc::clone(&transport.request_empty_polls);
        let ingress = transport
            .request_ingress()
            .expect("request ingress can be externalized once");
        let request = JsonRpcRequest::new("close/drain", None, 909_i64);
        let serialized_bytes = ingress
            .codec
            .encode_request(&request)
            .expect("test request is encodable")
            .len();
        let sender = ingress.sender.clone();
        let retained_bytes = Arc::clone(&ingress.retained_bytes);
        let retained_bytes_observer = Arc::clone(&ingress.retained_bytes);
        let admissions_open = Arc::clone(&ingress.admissions_open);
        let active_admissions = Arc::clone(&ingress.active_admissions);
        let active_admissions_observer = Arc::clone(&ingress.active_admissions);
        let max_queued_bytes = ingress.max_queued_bytes;
        let (admitted_sender, admitted_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();

        let producer = std::thread::spawn(move || {
            let admission = begin_streamable_admission(&admissions_open, &active_admissions)
                .expect("producer enters before close");
            reserve_streamable_bytes(
                &retained_bytes,
                max_queued_bytes,
                serialized_bytes,
                &admissions_open,
                &Cx::for_testing(),
                "test request byte budget is full",
            )
            .expect("producer reserves bytes before close");
            admitted_sender
                .send(())
                .expect("test admission receiver remains available");
            release_receiver
                .recv()
                .expect("test releases the admitted producer");
            assert!(
                sender
                    .try_send(QueuedRequest {
                        message: request,
                        serialized_bytes,
                    })
                    .is_ok(),
                "the pre-close admission commits to the bounded queue"
            );
            drop(admission);
        });
        admitted_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("producer reaches the admitted pre-commit state");

        let close_open = Arc::clone(&ingress.admissions_open);
        let closer = std::thread::spawn(move || ingress.close());
        let close_deadline = Instant::now() + Duration::from_secs(1);
        while close_open.load(Ordering::SeqCst) {
            if Instant::now() >= close_deadline {
                release_sender
                    .send(())
                    .expect("release producer during test cleanup");
                producer.join().expect("producer cleanup succeeds");
                closer.join().expect("closer cleanup succeeds");
                panic!("ingress close did not seal the admission gate");
            }
            std::thread::yield_now();
        }

        let (result_sender, result_receiver) = std::sync::mpsc::channel();
        let receive_cx = Cx::for_testing();
        let cancel_receive_cx = receive_cx.clone();
        let receiver = std::thread::spawn(move || {
            result_sender
                .send(transport.recv(&receive_cx))
                .expect("test result receiver remains available");
        });
        if !wait_for_counter(&empty_polls, 1) {
            release_sender
                .send(())
                .expect("release producer during test cleanup");
            producer.join().expect("producer cleanup succeeds");
            closer.join().expect("closer cleanup succeeds");
            cancel_receive_cx.set_cancel_requested(true);
            receiver.join().expect("receiver cleanup succeeds");
            panic!("receiver reported closure instead of waiting for the active admission");
        }

        release_sender
            .send(())
            .expect("release the admitted producer");
        producer.join().expect("producer completes");
        closer.join().expect("ingress close completes");
        let received = match result_receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(result) => result.expect("pre-close admission remains receivable"),
            Err(error) => {
                cancel_receive_cx.set_cancel_requested(true);
                receiver.join().expect("receiver cleanup succeeds");
                panic!("receiver did not drain the admitted request: {error}");
            }
        };
        receiver.join().expect("receiver completes");
        assert!(matches!(
            received,
            JsonRpcMessage::Request(ref request) if request.method == "close/drain"
        ));
        assert_eq!(retained_bytes_observer.load(Ordering::Acquire), 0);
        assert_eq!(active_admissions_observer.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn streamable_http_request_close_race_preserves_accounting() {
        for sequence in 0..32_i64 {
            let mut transport =
                StreamableHttpTransport::with_capacity(1).expect("capacity one is valid");
            let ingress = transport
                .request_ingress()
                .expect("request ingress can be externalized once");
            let worker_ingress = ingress.clone();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let worker_barrier = Arc::clone(&barrier);
            let worker = std::thread::spawn(move || {
                worker_barrier.wait();
                worker_ingress.push_request(
                    &Cx::for_testing(),
                    JsonRpcRequest::new("race", None, sequence),
                )
            });

            barrier.wait();
            ingress.close();
            match worker.join().expect("request producer completes") {
                Ok(()) => assert!(matches!(
                    transport.recv(&Cx::for_testing()),
                    Ok(JsonRpcMessage::Request(_))
                )),
                Err(TransportError::Closed) => {
                    assert_eq!(transport.pending_requests(), 0);
                }
                Err(error) => panic!("unexpected request race result: {error}"),
            }
            assert_eq!(transport.pending_requests(), 0);
            assert_eq!(transport.request_retained_bytes.load(Ordering::Acquire), 0);
            assert_eq!(
                transport.request_active_admissions.load(Ordering::Acquire),
                0
            );
        }
    }

    #[test]
    fn streamable_http_response_close_race_preserves_accounting_and_drain() {
        for sequence in 0..32_i64 {
            let mut transport =
                StreamableHttpTransport::with_capacity(1).expect("capacity one is valid");
            let response_stream = transport
                .response_stream()
                .expect("response stream can be externalized once");
            let response_id = fastmcp_protocol::RequestId::Number(sequence);
            let worker_id = response_id.clone();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let worker_barrier = Arc::clone(&barrier);
            let worker = std::thread::spawn(move || {
                worker_barrier.wait();
                let result = transport.send(
                    &Cx::for_testing(),
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        worker_id,
                        serde_json::Value::Null,
                    )),
                );
                (transport, result)
            });

            barrier.wait();
            response_stream.close();
            let (transport, result) = worker.join().expect("response producer completes");
            match result {
                Ok(()) => {
                    let drained = response_stream
                        .pop_response(Some(&response_id))
                        .expect("pre-close admission remains drainable")
                        .expect("successful admission has exactly one response");
                    assert_eq!(drained.id, Some(response_id.clone()));
                }
                Err(TransportError::Closed) => {
                    assert_eq!(transport.pending_responses(), 0);
                }
                Err(error) => panic!("unexpected response race result: {error}"),
            }
            assert_eq!(transport.pending_responses(), 0);
            assert_eq!(
                transport
                    .response_mailbox
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .retained_bytes,
                0
            );
            assert_eq!(
                transport.response_active_admissions.load(Ordering::Acquire),
                0
            );
            assert!(matches!(
                response_stream.pop_response(Some(&response_id)),
                Err(TransportError::Closed)
            ));
        }
    }

    #[test]
    fn e2e_http_session_lifecycle() {
        let store = SessionStore::new(Duration::from_millis(100));

        // Create session
        let id = store.create().unwrap();
        assert_eq!(store.count(), 1);

        // Get and modify session
        let mut session = store.get(&id).unwrap();
        session.set("user_id", serde_json::json!(42)).unwrap();
        store.update(session).unwrap();

        // Retrieve and verify
        let session = store.get(&id).unwrap();
        assert_eq!(session.get("user_id"), Some(&serde_json::json!(42)));

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        // Session should be expired
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn http_session_count_excludes_expired_sessions_without_prior_lookup() {
        let timeout = Duration::from_secs(60);
        let store = SessionStore::new(timeout);
        let id = store.create().unwrap();
        assert_eq!(store.count(), 1);

        store
            .sessions
            .lock()
            .unwrap()
            .get_mut(&id)
            .unwrap()
            .last_activity = Instant::now() - timeout - Duration::from_secs(1);

        assert_eq!(store.count(), 0);
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
        assert!(matches!(result, Err(HttpError::BodyTooLarge { .. })));
    }

    #[test]
    fn handler_body_limit_configures_the_strict_codec_boundary() {
        let configured_limit = 12 * 1024 * 1024;
        let handler = HttpRequestHandler::with_config(HttpHandlerConfig {
            max_body_size: configured_limit,
            ..Default::default()
        });

        assert_eq!(handler.codec.max_message_size(), configured_limit);
    }

    #[test]
    fn http_method_as_str_round_trips() {
        let methods = [
            HttpMethod::Get,
            HttpMethod::Post,
            HttpMethod::Put,
            HttpMethod::Delete,
            HttpMethod::Options,
            HttpMethod::Head,
            HttpMethod::Patch,
        ];
        for m in methods {
            let s = m.as_str();
            let parsed = HttpMethod::parse(s).unwrap();
            assert_eq!(parsed, m);
        }
    }

    #[test]
    fn http_status_boundary_cases() {
        assert!(HttpStatus(299).is_success());
        assert!(!HttpStatus(300).is_success());
        assert!(HttpStatus(499).is_client_error());
        assert!(!HttpStatus(500).is_client_error());
        assert!(HttpStatus(599).is_server_error());
        assert!(!HttpStatus(600).is_server_error());
    }

    #[test]
    fn http_request_content_type_and_authorization() {
        let req = HttpRequest::new(HttpMethod::Get, "/")
            .with_header("Content-Type", "text/plain")
            .with_header("Authorization", "Bearer token123");
        assert_eq!(req.content_type(), Some("text/plain"));
        assert_eq!(req.authorization(), Some("Bearer token123"));
    }

    #[test]
    fn http_request_debug_redacts_headers_body_path_and_query_values() {
        let canary = "HTTP-REQUEST-SECRET-CANARY";
        let req = HttpRequest::new(HttpMethod::Post, format!("/mcp/{canary}"))
            .with_header("Authorization", format!("Bearer {canary}"))
            .with_body(format!("{{\"secret\":\"{canary}\"}}"))
            .with_query("token", canary);

        let debug = format!("{req:?}");
        assert!(debug.contains("HttpRequest"));
        assert!(debug.contains("header_count: 1"));
        assert!(!debug.contains(canary));
        assert!(!debug.contains("Authorization"));
        assert!(!debug.contains("token"));
    }

    #[test]
    fn http_request_json_parse() {
        let body = serde_json::json!({"key": "value"});
        let req =
            HttpRequest::new(HttpMethod::Post, "/").with_body(serde_json::to_vec(&body).unwrap());
        let parsed: serde_json::Value = req.json().unwrap();
        assert_eq!(parsed["key"], "value");
    }

    #[test]
    fn http_response_convenience_constructors() {
        let bad = HttpResponse::bad_request();
        assert_eq!(bad.status, HttpStatus::BAD_REQUEST);
        let err = HttpResponse::internal_error();
        assert_eq!(err.status, HttpStatus::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn http_handler_config_defaults() {
        let config = HttpHandlerConfig::default();
        assert_eq!(config.base_path, "/mcp/v1");
        assert!(!config.allow_cors);
        assert!(config.cors_origins.is_empty());
        assert_eq!(config.max_body_size, 10 * 1024 * 1024);
    }

    #[test]
    fn http_handler_config_accessor() {
        let handler = HttpRequestHandler::new();
        assert_eq!(handler.config().base_path, "/mcp/v1");
    }

    #[test]
    fn http_error_display_all_variants() {
        let cases: Vec<(HttpError, &str)> = vec![
            (HttpError::InvalidMethod("X".into()), "invalid HTTP method"),
            (
                HttpError::InvalidRequestLine("bad".into()),
                "invalid HTTP request line",
            ),
            (
                HttpError::InvalidHeader("bad".into()),
                "invalid HTTP header",
            ),
            (
                HttpError::InvalidContentType("text/xml".into()),
                "invalid content type",
            ),
            (
                HttpError::InvalidPath("/wrong".into()),
                "invalid MCP endpoint path",
            ),
            (
                HttpError::OriginNotAllowed("https://denied.example".into()),
                "origin is not allowed",
            ),
            (
                HttpError::HeadersTooLarge { size: 100, max: 50 },
                "headers too large: 100 > 50",
            ),
            (
                HttpError::BodyTooLarge {
                    size: 200,
                    max: 100,
                },
                "body too large: 200 > 100",
            ),
            (
                HttpError::UnsupportedTransferEncoding("gzip".into()),
                "unsupported transfer encoding",
            ),
            (HttpError::Timeout, "request timeout"),
            (HttpError::Closed, "connection closed"),
        ];
        for (err, expected) in cases {
            assert!(
                err.to_string().contains(expected),
                "expected '{}' in '{}'",
                expected,
                err
            );
        }
    }

    #[test]
    fn http_error_from_codec_error() {
        let codec_err = CodecError::MessageTooLarge(999);
        let http_err: HttpError = codec_err.into();
        assert!(matches!(http_err, HttpError::CodecError(_)));
        assert!(http_err.to_string().contains("codec error"));
    }

    #[test]
    fn http_error_from_transport_error() {
        let transport_err = TransportError::Closed;
        let http_err: HttpError = transport_err.into();
        assert!(matches!(http_err, HttpError::Transport(_)));
        assert!(http_err.to_string().contains("transport error"));
    }

    #[test]
    fn http_transport_send_rejects_request_messages() {
        use std::io::Cursor;

        let reader = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        let cx = Cx::for_testing();
        let mut transport = HttpTransport::new(reader, &mut output);

        let request = JsonRpcRequest::new("test", None, 1i64);
        let result = transport.send(&cx, &JsonRpcMessage::Request(request));
        assert!(result.is_err());
    }

    #[test]
    fn session_store_cleanup_removes_expired() {
        let store = SessionStore::new(Duration::from_millis(50));
        let _id1 = store.create().unwrap();
        let _id2 = store.create().unwrap();
        assert_eq!(store.count(), 2);

        std::thread::sleep(Duration::from_millis(100));
        store.cleanup();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn handle_options_cors_disabled() {
        let config = HttpHandlerConfig {
            allow_cors: false,
            ..Default::default()
        };
        let handler = HttpRequestHandler::with_config(config);
        let request = HttpRequest::new(HttpMethod::Options, "/mcp/v1");
        let response = handler.handle_options(&request);
        assert_eq!(response.status, HttpStatus::METHOD_NOT_ALLOWED);
    }

    fn dual_era_modern_sse_request(id: i64) -> HttpRequest {
        let request = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "name": "weather",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28"
                }
            })),
            id,
        );
        HttpRequest::new(HttpMethod::Post, "/mcp")
            .with_header("content-type", "application/json")
            .with_header("accept", "text/event-stream")
            .with_header("MCP-Protocol-Version", "2026-07-28")
            .with_header("Mcp-Method", "tools/call")
            .with_header("Mcp-Name", "weather")
            .with_body(serde_json::to_vec(&request).expect("modern request serializes"))
    }

    fn dual_era_endpoint() -> DualEraHttpEndpoint {
        let handler = HttpRequestHandler::with_config(HttpHandlerConfig {
            base_path: "/mcp".to_string(),
            ..HttpHandlerConfig::default()
        });
        let config =
            DualEraHttpEndpointConfig::new("/legacy/sse", "/legacy/messages", "http://legacy.test");
        DualEraHttpEndpoint::new(handler, config).expect("dual-era endpoint configuration is valid")
    }

    #[test]
    fn dual_era_modern_h1_sse_delivers_every_request_owned_event_before_terminal() {
        let endpoint = dual_era_endpoint();
        let mut session = endpoint.open_session().expect("endpoint opens a session");
        let cx = Cx::for_testing();
        let codec = Codec::new();

        let response = session
            .handle(&cx, dual_era_modern_sse_request(171))
            .expect("a real modern H1 SSE request is admitted");
        let DualEraHttpEndpointResponse::ModernSse(response) = response else {
            panic!("Accept: text/event-stream creates a request-owned modern SSE body");
        };
        assert_eq!(
            session
                .recv_modern_request(&cx)
                .expect("admitted H1 request reaches the modern dispatch side")
                .method,
            "tools/call"
        );

        let sender = response.sender();
        sender
            .send_notification(
                &cx,
                JsonRpcRequest::notification(
                    "notifications/progress",
                    Some(serde_json::json!({"progress": 1})),
                ),
            )
            .expect("the first request-owned notification is admitted");
        sender
            .send_notification(
                &cx,
                JsonRpcRequest::notification(
                    "notifications/progress",
                    Some(serde_json::json!({"progress": 2})),
                ),
            )
            .expect("the second request-owned notification is admitted");
        sender
            .send_response(
                &cx,
                JsonRpcResponse::success(RequestId::Number(171), serde_json::json!({"ok": true})),
            )
            .expect("the terminal response is admitted after both notifications");

        let first = response
            .pop_event()
            .expect("the first event frames")
            .expect("the first event is queued");
        let second = response
            .pop_event()
            .expect("the second event frames")
            .expect("the second event is queued");
        let terminal = response
            .pop_event()
            .expect("the terminal event frames")
            .expect("the terminal event is queued");
        assert!(matches!(
            codec
                .decode_complete_message(first.data.as_bytes())
                .expect("first SSE event remains JSON-RPC"),
            JsonRpcMessage::Request(notification)
                if notification.method == "notifications/progress"
                    && notification.params == Some(serde_json::json!({"progress": 1}))
        ));
        assert!(matches!(
            codec
                .decode_complete_message(second.data.as_bytes())
                .expect("second SSE event remains JSON-RPC"),
            JsonRpcMessage::Request(notification)
                if notification.method == "notifications/progress"
                    && notification.params == Some(serde_json::json!({"progress": 2}))
        ));
        assert!(matches!(
            codec
                .decode_complete_message(terminal.data.as_bytes())
                .expect("terminal SSE event remains JSON-RPC"),
            JsonRpcMessage::Response(message) if message.id == Some(RequestId::Number(171))
        ));
        assert!(response.is_finished());
    }

    #[test]
    fn dual_era_modern_h1_sse_disconnect_cancels_and_rejects_the_later_effect() {
        let endpoint = dual_era_endpoint();
        let mut session = endpoint.open_session().expect("endpoint opens a session");
        let cx = Cx::for_testing();

        let response = session
            .handle(&cx, dual_era_modern_sse_request(172))
            .expect("the otherwise identical modern H1 SSE request is admitted");
        let DualEraHttpEndpointResponse::ModernSse(response) = response else {
            panic!("Accept: text/event-stream creates a request-owned modern SSE body");
        };
        assert_eq!(
            session
                .recv_modern_request(&cx)
                .expect("admitted H1 request reaches the modern dispatch side")
                .method,
            "tools/call"
        );

        let sender = response.sender();
        sender
            .send_notification(
                &cx,
                JsonRpcRequest::notification(
                    "notifications/progress",
                    Some(serde_json::json!({"progress": 1})),
                ),
            )
            .expect("the first request-owned notification is admitted");

        // Planted forbidden dimension: the peer body closes before the
        // otherwise identical second notification and terminal response.
        drop(response);

        assert!(sender.request_cancellation().is_cancel_requested());
        assert!(matches!(
            sender.send_notification(
                &cx,
                JsonRpcRequest::notification(
                    "notifications/progress",
                    Some(serde_json::json!({"progress": 2})),
                ),
            ),
            Err(TransportError::Cancelled)
        ));
        assert!(matches!(
            sender.send_response(
                &cx,
                JsonRpcResponse::success(RequestId::Number(172), serde_json::json!({"ok": true})),
            ),
            Err(TransportError::Cancelled)
        ));
    }

    #[test]
    fn dual_era_endpoint_composes_fresh_legacy_sse_with_modern_request_bodies() {
        let endpoint = dual_era_endpoint();
        let mut session = endpoint.open_session().expect("endpoint opens a session");
        let cx = Cx::for_testing();
        let codec = Codec::new();

        session
            .publish_legacy_message(&JsonRpcMessage::Response(JsonRpcResponse::success(
                RequestId::Number(41),
                serde_json::json!({"phase": "before-stream"}),
            )))
            .expect("a message without a live stream is not retained");

        let legacy_get = session
            .handle(&cx, HttpRequest::new(HttpMethod::Get, "/legacy/sse"))
            .expect("legacy GET is admitted");
        let DualEraHttpEndpointResponse::LegacySse(mut legacy_get) = legacy_get else {
            panic!("legacy GET returns a live SSE response body");
        };
        assert_eq!(legacy_get.response().status, HttpStatus::OK);
        assert_eq!(
            legacy_get.response().headers.get("content-type"),
            Some(&"text/event-stream".to_string())
        );
        assert_eq!(
            legacy_get.response().headers.get("cache-control"),
            Some(&"no-cache".to_string())
        );
        assert_eq!(
            legacy_get.response().headers.get("connection"),
            Some(&"keep-alive".to_string())
        );
        assert_eq!(
            legacy_get.response().headers.get("x-accel-buffering"),
            Some(&"no".to_string())
        );

        let endpoint_event = legacy_get
            .recv_event(&cx)
            .expect("fresh legacy endpoint event is available");
        assert_eq!(endpoint_event.data, session.legacy_message_endpoint());
        assert!(endpoint_event.id.is_none());

        session
            .publish_legacy_message(&JsonRpcMessage::Response(JsonRpcResponse::success(
                RequestId::Number(42),
                serde_json::json!({"phase": "live"}),
            )))
            .expect("a message is delivered to the live legacy stream");
        let live_event = legacy_get
            .recv_event(&cx)
            .expect("the live legacy event is available");
        assert!(live_event.id.is_none());
        assert!(matches!(
            codec
                .decode_complete_message(live_event.data.as_bytes())
                .expect("live legacy data remains JSON-RPC"),
            JsonRpcMessage::Response(response) if response.id == Some(RequestId::Number(42))
        ));

        drop(legacy_get);

        let legacy_request =
            JsonRpcRequest::new("ping", Some(serde_json::json!({"value": 1})), 77_i64);
        let legacy_post = HttpRequest::new(HttpMethod::Post, "/legacy/messages")
            .with_header("content-type", "application/json")
            .with_query("session_id", session.session_id())
            .with_body(
                codec
                    .encode_request(&legacy_request)
                    .expect("legacy request serializes"),
            );
        let legacy_post = session
            .handle(&cx, legacy_post)
            .expect("advertised legacy POST is admitted");
        let DualEraHttpEndpointResponse::Immediate(legacy_post) = legacy_post else {
            panic!("legacy POST has a complete HTTP acceptance response");
        };
        assert_eq!(legacy_post.status, HttpStatus::ACCEPTED);
        assert_eq!(
            session
                .take_legacy_request()
                .expect("legacy POST reaches only the legacy request queue")
                .method,
            "ping"
        );

        let modern_sse = session
            .handle(&cx, dual_era_modern_sse_request(91))
            .expect("modern request with matching directional headers is admitted");
        let DualEraHttpEndpointResponse::ModernSse(modern_sse) = modern_sse else {
            panic!("modern Accept selection creates a request-scoped SSE response body");
        };
        assert_eq!(
            modern_sse.response().headers.get("content-type"),
            Some(&"text/event-stream".to_string())
        );
        assert_eq!(
            modern_sse.response().headers.get("x-accel-buffering"),
            Some(&"no".to_string())
        );
        assert_eq!(
            session
                .recv_modern_request(&cx)
                .expect("only the modern route reaches the modern transport")
                .method,
            "tools/call"
        );
        let cancellation = modern_sse.cancellation();
        session
            .send_modern_sse_notification(
                &cx,
                &cancellation,
                JsonRpcRequest::notification(
                    "notifications/progress",
                    Some(serde_json::json!({"progress": 50})),
                ),
            )
            .expect("the request-owned modern notification is committed before the response");
        session
            .send_modern_sse_response(
                &cx,
                &cancellation,
                JsonRpcResponse::success(RequestId::Number(91), serde_json::json!({"ok": true})),
            )
            .expect("the bound modern SSE response is committed through its guard");
        let notification_event = modern_sse
            .recv_event(&cx)
            .expect("the request-owned notification renders as the first modern SSE event");
        assert!(notification_event.id.is_none());
        assert!(matches!(
            codec
                .decode_complete_message(notification_event.data.as_bytes())
                .expect("modern SSE notification data remains JSON-RPC"),
            JsonRpcMessage::Request(notification)
                if notification.is_notification()
                    && notification.method == "notifications/progress"
                    && notification.params == Some(serde_json::json!({"progress": 50}))
        ));
        let modern_event = modern_sse
            .recv_event(&cx)
            .expect("the bound modern response renders as an SSE event");
        assert!(modern_event.id.is_none());
        assert!(matches!(
            codec
                .decode_complete_message(modern_event.data.as_bytes())
                .expect("modern SSE data remains JSON-RPC"),
            JsonRpcMessage::Response(response) if response.id == Some(RequestId::Number(91))
        ));

        let mut modern_json_request = dual_era_modern_sse_request(93);
        modern_json_request
            .headers
            .insert("accept".to_string(), "application/json".to_string());
        let modern_json = session
            .handle(&cx, modern_json_request)
            .expect("modern JSON request with matching directional headers is admitted");
        let DualEraHttpEndpointResponse::ModernJson(modern_json) = modern_json else {
            panic!("modern JSON Accept selection creates a finite JSON response handle");
        };
        assert_eq!(
            session
                .recv_modern_request(&cx)
                .expect("modern JSON request reaches the modern transport")
                .method,
            "tools/call"
        );
        session
            .send_modern_json_response(
                &cx,
                JsonRpcResponse::success(RequestId::Number(93), serde_json::json!({"ok": true})),
            )
            .expect("modern JSON response is committed");
        let modern_json = modern_json
            .try_response()
            .expect("modern JSON response rendering succeeds")
            .expect("the matching modern JSON response is available");
        assert_eq!(modern_json.status, HttpStatus::OK);
        assert_eq!(
            modern_json.headers.get("content-type"),
            Some(&"application/json".to_string())
        );
        assert!(matches!(
            codec
                .decode_complete_message(&modern_json.body)
                .expect("modern JSON body remains JSON-RPC"),
            JsonRpcMessage::Response(response) if response.id == Some(RequestId::Number(93))
        ));

        let abandoned = session
            .handle(&cx, dual_era_modern_sse_request(92))
            .expect("second modern SSE request is admitted before cleanup");
        let DualEraHttpEndpointResponse::ModernSse(abandoned) = abandoned else {
            panic!("second modern request has its own response body");
        };
        let abandoned_cancellation = abandoned.cancellation();
        session.close();
        assert!(session.is_closed());
        assert!(abandoned_cancellation.is_cancelled());
        assert!(session.take_legacy_request().is_none());
    }

    #[test]
    fn dual_era_endpoint_ignores_last_event_id_and_starts_a_fresh_legacy_stream() {
        let cx = Cx::for_testing();
        let codec = Codec::new();

        let fresh_reconnect = |last_event_id: Option<&str>| {
            let endpoint = dual_era_endpoint();
            let mut session = endpoint.open_session().expect("endpoint opens a session");

            let first_get = session
                .handle(&cx, HttpRequest::new(HttpMethod::Get, "/legacy/sse"))
                .expect("baseline legacy GET is admitted");
            let DualEraHttpEndpointResponse::LegacySse(mut first_get) = first_get else {
                panic!("baseline legacy GET creates a live SSE response body");
            };
            let first_endpoint = first_get
                .recv_event(&cx)
                .expect("baseline stream begins with its endpoint event");
            assert_eq!(first_endpoint.data, session.legacy_message_endpoint());
            assert!(first_endpoint.id.is_none());

            session
                .publish_legacy_message(&JsonRpcMessage::Response(JsonRpcResponse::success(
                    RequestId::Number(81),
                    serde_json::json!({"phase": "closed-stream"}),
                )))
                .expect("the baseline stream accepts one live message");
            drop(first_get);

            let session_id_before = session.session_id().to_owned();
            let endpoint_before = session.legacy_message_endpoint().to_owned();
            let legacy_request_count_before = session.legacy_requests.len();
            let pending_before = session.legacy_live_pending.load(Ordering::Acquire);
            assert_eq!(pending_before, 0);

            let reconnect = match last_event_id {
                Some(last_event_id) => HttpRequest::new(HttpMethod::Get, "/legacy/sse")
                    .with_header("last-event-id", last_event_id),
                None => HttpRequest::new(HttpMethod::Get, "/legacy/sse"),
            };
            let resumed_get = session
                .handle(&cx, reconnect)
                .expect("the primed reconnect opens a fresh legacy GET");
            let DualEraHttpEndpointResponse::LegacySse(mut resumed_get) = resumed_get else {
                panic!("the primed reconnect creates a fresh live SSE response body");
            };
            assert_eq!(session.session_id(), session_id_before);
            assert_eq!(session.legacy_message_endpoint(), endpoint_before);
            assert_eq!(session.legacy_requests.len(), legacy_request_count_before);
            assert_eq!(
                session.legacy_live_pending.load(Ordering::Acquire),
                pending_before
            );

            let fresh_endpoint = resumed_get
                .recv_event(&cx)
                .expect("fresh stream begins with its endpoint instead of a replay");
            assert_eq!(fresh_endpoint.data, endpoint_before);
            assert!(fresh_endpoint.id.is_none());

            session
                .publish_legacy_message(&JsonRpcMessage::Response(JsonRpcResponse::success(
                    RequestId::Number(82),
                    serde_json::json!({"phase": "fresh-stream"}),
                )))
                .expect("the fresh stream accepts a new live message");
            let fresh_event = resumed_get
                .recv_event(&cx)
                .expect("only the new live message arrives after the endpoint event");
            assert!(fresh_event.id.is_none());
            let JsonRpcMessage::Response(response) = codec
                .decode_complete_message(fresh_event.data.as_bytes())
                .expect("fresh legacy data remains JSON-RPC")
            else {
                panic!("fresh legacy event must be the new response");
            };
            assert_eq!(response.id, Some(RequestId::Number(82)));

            (fresh_endpoint.id, fresh_event.id, response.result)
        };

        let control = fresh_reconnect(None);
        let with_last_event_id = fresh_reconnect(Some("legacy-cursor-that-cannot-replay"));
        assert_eq!(
            with_last_event_id, control,
            "Last-Event-ID must produce the same fresh-only stream as the equivalently primed control"
        );
    }

    #[test]
    fn dual_era_endpoint_streams_legacy_response_after_advertised_post() {
        let endpoint = dual_era_endpoint();
        let mut session = endpoint.open_session().expect("endpoint opens a session");
        let cx = Cx::for_testing();
        let codec = Codec::new();

        let legacy_sse = session
            .handle(&cx, HttpRequest::new(HttpMethod::Get, "/legacy/sse"))
            .expect("legacy SSE GET is admitted");
        let DualEraHttpEndpointResponse::LegacySse(mut legacy_sse) = legacy_sse else {
            panic!("legacy GET creates its live SSE response body");
        };
        assert_eq!(legacy_sse.response().status, HttpStatus::OK);
        assert_eq!(
            legacy_sse
                .recv_event(&cx)
                .expect("the advertised legacy POST endpoint is first")
                .data,
            session.legacy_message_endpoint()
        );

        let request = JsonRpcRequest::new("ping", Some(serde_json::json!({"value": 7})), 71_i64);
        let post = HttpRequest::new(HttpMethod::Post, "/legacy/messages")
            .with_header("content-type", "application/json")
            .with_query("session_id", session.session_id())
            .with_body(
                codec
                    .encode_request(&request)
                    .expect("legacy request serializes"),
            );
        let post = session
            .handle(&cx, post)
            .expect("the advertised legacy POST is admitted");
        let DualEraHttpEndpointResponse::Immediate(post) = post else {
            panic!("legacy POST returns its HTTP acceptance response");
        };
        assert_eq!(post.status, HttpStatus::ACCEPTED);
        assert_eq!(
            session
                .take_legacy_request()
                .expect("the POST reached legacy application dispatch")
                .id,
            Some(RequestId::Number(71))
        );

        session
            .publish_legacy_message(&JsonRpcMessage::Response(JsonRpcResponse::success(
                RequestId::Number(71),
                serde_json::json!({"pong": true}),
            )))
            .expect("the dispatch response is sent to the live stream");
        let response_event = legacy_sse
            .recv_event(&cx)
            .expect("the open legacy stream receives the response after POST");
        assert!(response_event.id.is_none());
        assert!(matches!(
            codec
                .decode_complete_message(response_event.data.as_bytes())
                .expect("live legacy response stays JSON-RPC"),
            JsonRpcMessage::Response(response) if response.id == Some(RequestId::Number(71))
        ));
    }

    #[test]
    fn dual_era_endpoint_recovers_live_capacity_after_queue_rejection() {
        let handler = HttpRequestHandler::with_config(HttpHandlerConfig {
            base_path: "/mcp".to_string(),
            ..HttpHandlerConfig::default()
        });
        let mut config =
            DualEraHttpEndpointConfig::new("/legacy/sse", "/legacy/messages", "http://legacy.test");
        config.legacy_request_capacity = 1;
        let endpoint = DualEraHttpEndpoint::new(handler, config)
            .expect("capacity-one live stream configuration is valid");
        let mut session = endpoint.open_session().expect("endpoint opens a session");
        let cx = Cx::for_testing();
        let legacy_sse = session
            .handle(&cx, HttpRequest::new(HttpMethod::Get, "/legacy/sse"))
            .expect("legacy SSE GET is admitted");
        let DualEraHttpEndpointResponse::LegacySse(mut legacy_sse) = legacy_sse else {
            panic!("legacy GET creates a live SSE response body");
        };
        let _endpoint = legacy_sse
            .recv_event(&cx)
            .expect("endpoint event is available before live messages");

        session
            .publish_legacy_message(&JsonRpcMessage::Response(JsonRpcResponse::success(
                RequestId::Number(85),
                serde_json::json!({"queued": true}),
            )))
            .expect("the first live message fills the capacity-one queue");
        let rejected = session
            .publish_legacy_message(&JsonRpcMessage::Response(JsonRpcResponse::success(
                RequestId::Number(86),
                serde_json::json!({"queued": false}),
            )))
            .expect_err("the second live message is rejected before enqueue");
        assert!(matches!(
            &rejected,
            DualEraHttpEndpointError::Transport(TransportError::Io(error))
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && error.to_string().contains("legacy SSE live queue is full")
        ));

        let first_event = legacy_sse
            .recv_event(&cx)
            .expect("the first queued message reaches the live stream");
        assert!(first_event.id.is_none());

        session
            .publish_legacy_message(&JsonRpcMessage::Response(JsonRpcResponse::success(
                RequestId::Number(86),
                serde_json::json!({"queued": false}),
            )))
            .expect("consuming the first message releases live capacity");
        let recovered_event = legacy_sse
            .recv_event(&cx)
            .expect("the retried message reaches the live stream");
        assert!(recovered_event.id.is_none());
    }

    #[test]
    fn dual_era_endpoint_rejects_only_wrong_session_legacy_post_without_mutation() {
        let endpoint = dual_era_endpoint();
        let mut session = endpoint.open_session().expect("endpoint opens a session");
        let cx = Cx::for_testing();
        let codec = Codec::new();
        let request = JsonRpcRequest::new("ping", Some(serde_json::json!({"value": 9})), 73_i64);
        let accepted = HttpRequest::new(HttpMethod::Post, "/legacy/messages")
            .with_header("content-type", "application/json")
            .with_query("session_id", session.session_id())
            .with_body(
                codec
                    .encode_request(&request)
                    .expect("legacy request serializes"),
            );
        let mut wrong_session = accepted.clone();
        wrong_session
            .query
            .insert("session_id".to_string(), "other-session".to_string());
        assert_eq!(wrong_session.method, accepted.method);
        assert_eq!(wrong_session.path, accepted.path);
        assert_eq!(wrong_session.headers, accepted.headers);
        assert_eq!(wrong_session.body, accepted.body);
        assert_eq!(wrong_session.query.len(), accepted.query.len());
        assert_ne!(wrong_session.query, accepted.query);

        let rejected = session
            .handle(&cx, wrong_session)
            .expect("wrong-session legacy POST becomes an HTTP rejection");
        let DualEraHttpEndpointResponse::Immediate(rejected) = rejected else {
            panic!("wrong-session POST cannot create a streaming response");
        };
        assert_eq!(rejected.status, HttpStatus::NOT_FOUND);
        assert!(session.take_legacy_request().is_none());

        let accepted = session
            .handle(&cx, accepted)
            .expect("the otherwise identical correct-session POST is admitted");
        let DualEraHttpEndpointResponse::Immediate(accepted) = accepted else {
            panic!("correct-session POST has an immediate acceptance response");
        };
        assert_eq!(accepted.status, HttpStatus::ACCEPTED);
        assert_eq!(
            session
                .take_legacy_request()
                .expect("wrong-session rejection left the queue empty")
                .id,
            Some(RequestId::Number(73))
        );
    }

    #[test]
    fn dual_era_endpoint_rejects_only_the_wrong_legacy_sse_method_without_mutation() {
        let endpoint = dual_era_endpoint();
        let mut session = endpoint.open_session().expect("endpoint opens a session");
        let cx = Cx::for_testing();
        let allowed = HttpRequest::new(HttpMethod::Get, "/legacy/sse");
        let mut rejected = allowed.clone();
        rejected.method = HttpMethod::Post;

        let allowed = session
            .handle(&cx, allowed)
            .expect("the baseline legacy SSE GET is admitted");
        let DualEraHttpEndpointResponse::LegacySse(allowed) = allowed else {
            panic!("baseline legacy SSE route returns a live response body");
        };
        assert_eq!(allowed.response().status, HttpStatus::OK);

        let rejected = session
            .handle(&cx, rejected)
            .expect("method rejection is an HTTP response rather than a queue mutation");
        let DualEraHttpEndpointResponse::Immediate(rejected) = rejected else {
            panic!("rejected legacy SSE method returns an immediate response");
        };
        assert_eq!(rejected.status, HttpStatus::METHOD_NOT_ALLOWED);
        assert_eq!(rejected.headers.get("allow"), Some(&"GET".to_string()));
        assert!(session.take_legacy_request().is_none());
    }

    #[test]
    fn modern_http_sse_collector_incrementally_delivers_notifications_then_terminal() {
        let request_id = RequestId::Number(4_201);
        let notification = JsonRpcRequest::notification(
            "notifications/progress",
            Some(serde_json::json!({"progress": 50})),
        );
        let response = JsonRpcResponse::success(
            request_id.clone(),
            serde_json::json!({"result": "complete"}),
        );
        let notification_json = serde_json::to_string(&notification).expect("notification encodes");
        let notification_bytes = notification_json.as_bytes().to_vec();
        let response_json = serde_json::to_string(&response).expect("response encodes");
        let body = format!(
            "event: ignored\r\ndata: {notification_json}\r\n\r\ndata: {response_json}\r\n\r\n"
        );
        let split = body.len() / 2;
        let limits = ModernSseLimits::new(4_096, 4_096, 8).expect("nonzero SSE limits");
        let mut collector =
            ModernHttpSseCollector::new(request_id.clone(), limits).expect("valid request ID");
        let cx = Cx::for_testing();
        let mut notifications = Vec::new();

        collector
            .push(&cx, &body.as_bytes()[..split], |notification| {
                notifications.push(
                    serde_json::to_vec(&notification).expect("delivered notification encodes"),
                );
                Ok(())
            })
            .expect("a partial HTTP chunk does not synthesize an SSE event");
        collector
            .push(&cx, &body.as_bytes()[split..], |notification| {
                notifications.push(
                    serde_json::to_vec(&notification).expect("delivered notification encodes"),
                );
                Ok(())
            })
            .expect("the remaining chunk admits its notification and terminal response");

        assert_eq!(notifications, vec![notification_bytes]);
        assert_eq!(
            collector
                .finish(&cx)
                .expect("EOF returns the one correlated terminal response"),
            response
        );
    }

    #[test]
    fn modern_http_sse_collector_finish_returns_one_complete_terminal_response() {
        let request_id = RequestId::Number(4_208);
        let response = JsonRpcResponse::success(request_id.clone(), serde_json::json!(true));
        let response_json = serde_json::to_string(&response).expect("response encodes");
        let limits = ModernSseLimits::new(4_096, 4_096, 8).expect("nonzero SSE limits");
        let mut collector =
            ModernHttpSseCollector::new(request_id, limits).expect("valid request ID");
        let cx = Cx::for_testing();

        collector
            .push(&cx, format!("data: {response_json}\n\n").as_bytes(), |_| {
                Ok(())
            })
            .expect("complete terminal event is admitted before EOF");
        assert_eq!(
            collector
                .finish(&cx)
                .expect("uncancelled EOF releases the terminal response"),
            response
        );
        assert_collector_is_closed(&mut collector, &cx);
    }

    #[test]
    fn modern_http_sse_collector_finish_cancellation_cannot_be_reused() {
        let request_id = RequestId::Number(4_209);
        let response = JsonRpcResponse::success(request_id.clone(), serde_json::json!(true));
        let response_json = serde_json::to_string(&response).expect("response encodes");
        let limits = ModernSseLimits::new(4_096, 4_096, 8).expect("nonzero SSE limits");
        let mut collector =
            ModernHttpSseCollector::new(request_id, limits).expect("valid request ID");
        let fresh_cx = Cx::for_testing();
        let cancelled_cx = Cx::for_testing();

        collector
            .push(
                &fresh_cx,
                format!("data: {response_json}\n\n").as_bytes(),
                |_| Ok(()),
            )
            .expect("terminal response is retained before cancelled EOF");
        cancelled_cx.set_cancel_requested(true);
        assert!(matches!(
            collector.finish(&cancelled_cx),
            Err(ModernHttpSseCollectorError::Cancelled)
        ));
        assert_collector_is_closed(&mut collector, &fresh_cx);
    }

    #[test]
    fn modern_http_sse_collector_rejects_only_mismatched_terminal_id() {
        let request_id = RequestId::Number(4_202);
        let response = JsonRpcResponse::success(
            RequestId::Number(4_203),
            serde_json::json!({"result": "complete"}),
        );
        let response_json = serde_json::to_string(&response).expect("response encodes");
        let body = format!("data: {response_json}\n\n");
        let limits = ModernSseLimits::new(4_096, 4_096, 8).expect("nonzero SSE limits");
        let mut collector =
            ModernHttpSseCollector::new(request_id.clone(), limits).expect("valid request ID");
        let cx = Cx::for_testing();

        assert!(matches!(
            collector.push(&cx, body.as_bytes(), |_| Ok(())),
            Err(ModernHttpSseCollectorError::TerminalResponseIdMismatch {
                expected,
                actual: Some(RequestId::Number(4_203)),
            }) if expected == request_id
        ));
        assert_collector_is_closed(&mut collector, &cx);
    }

    #[test]
    fn modern_http_sse_collector_rejects_only_trailing_incomplete_bytes_after_terminal() {
        let request_id = RequestId::Number(4_204);
        let response = JsonRpcResponse::success(request_id.clone(), serde_json::json!(true));
        let response_json = serde_json::to_string(&response).expect("response encodes");
        let complete_body = format!("data: {response_json}\n\n");
        let body = format!("{complete_body}data: {{");
        let limits = ModernSseLimits::new(4_096, 4_096, 8).expect("nonzero SSE limits");
        let mut collector =
            ModernHttpSseCollector::new(request_id, limits).expect("valid request ID");
        let cx = Cx::for_testing();

        collector
            .push(&cx, body.as_bytes(), |_| Ok(()))
            .expect("the terminal is complete before the trailing partial SSE line");
        assert!(matches!(
            collector.finish(&cx),
            Err(ModernHttpSseCollectorError::EndOfStream {
                framing: ModernSseEndOfStream {
                    discarded_pending_event: false,
                    discarded_partial_line: true,
                },
            })
        ));
        assert_collector_is_closed(&mut collector, &cx);
    }

    #[test]
    fn modern_http_sse_collector_poisoned_by_codec_error_cannot_release_prior_terminal() {
        let request_id = RequestId::Number(4_205);
        let response = JsonRpcResponse::success(request_id.clone(), serde_json::json!(true));
        let response_json = serde_json::to_string(&response).expect("response encodes");
        let body = format!("data: {response_json}\n\ndata: not-json\n\n");
        let limits = ModernSseLimits::new(4_096, 4_096, 8).expect("nonzero SSE limits");
        let mut collector =
            ModernHttpSseCollector::new(request_id, limits).expect("valid request ID");
        let cx = Cx::for_testing();

        assert!(matches!(
            collector.push(&cx, body.as_bytes(), |_| Ok(())),
            Err(ModernHttpSseCollectorError::Codec(_))
        ));
        assert_collector_is_closed(&mut collector, &cx);
    }

    #[test]
    fn modern_http_sse_collector_poisoned_by_sse_framing_error_stays_closed() {
        let limits = ModernSseLimits::new(8, 4_096, 8).expect("nonzero SSE limits");
        let mut collector = ModernHttpSseCollector::new(RequestId::Number(4_206), limits)
            .expect("valid request ID");
        let cx = Cx::for_testing();

        assert!(matches!(
            collector.push(&cx, b"data: too-long\n", |_| Ok(())),
            Err(ModernHttpSseCollectorError::Sse(
                ModernSseParseError::LineTooLong { .. }
            ))
        ));
        assert_collector_is_closed(&mut collector, &cx);
    }

    #[test]
    fn modern_http_sse_collector_poisoned_by_notification_delivery_error_stays_closed() {
        let notification = JsonRpcRequest::notification(
            "notifications/progress",
            Some(serde_json::json!({"progress": 50})),
        );
        let notification_json = serde_json::to_string(&notification).expect("notification encodes");
        let limits = ModernSseLimits::new(4_096, 4_096, 8).expect("nonzero SSE limits");
        let mut collector = ModernHttpSseCollector::new(RequestId::Number(4_206), limits)
            .expect("valid request ID");
        let cx = Cx::for_testing();

        assert!(matches!(
            collector.push(
                &cx,
                format!("data: {notification_json}\n\n").as_bytes(),
                |_| { Err(TransportError::Closed) }
            ),
            Err(ModernHttpSseCollectorError::NotificationDelivery(
                TransportError::Closed
            ))
        ));
        assert_collector_is_closed(&mut collector, &cx);
    }

    #[test]
    fn modern_http_sse_collector_poisoned_by_mid_chunk_cancellation_stays_closed() {
        let request_id = RequestId::Number(4_207);
        let notification = JsonRpcRequest::notification("notifications/progress", None);
        let response = JsonRpcResponse::success(request_id.clone(), serde_json::json!(true));
        let notification_json = serde_json::to_string(&notification).expect("notification encodes");
        let response_json = serde_json::to_string(&response).expect("response encodes");
        let body = format!("data: {notification_json}\n\ndata: {response_json}\n\n");
        let limits = ModernSseLimits::new(4_096, 4_096, 8).expect("nonzero SSE limits");
        let mut collector =
            ModernHttpSseCollector::new(request_id, limits).expect("valid request ID");
        let cancelled_cx = Cx::for_testing();
        let fresh_cx = Cx::for_testing();

        assert!(matches!(
            collector.push(&cancelled_cx, body.as_bytes(), |_| {
                cancelled_cx.set_cancel_requested(true);
                Ok(())
            }),
            Err(ModernHttpSseCollectorError::Cancelled)
        ));
        assert_collector_is_closed(&mut collector, &fresh_cx);
    }

    fn assert_collector_is_closed(collector: &mut ModernHttpSseCollector, cx: &Cx) {
        assert!(matches!(
            collector.push(cx, b"", |_| Ok(())),
            Err(ModernHttpSseCollectorError::Closed)
        ));
        assert!(matches!(
            collector.finish(cx),
            Err(ModernHttpSseCollectorError::Closed)
        ));
    }
}
