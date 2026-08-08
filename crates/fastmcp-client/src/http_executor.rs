//! Native modern HTTP request and response-stream execution.
//!
//! This module owns modern MCP POST execution, disposable first-probe
//! negotiation, and the public response stream surface. It neither retries an
//! MCP request nor follows redirects.

use std::collections::VecDeque;
use std::fmt;
use std::future::poll_fn;
use std::pin::Pin;

use asupersync::Cx;
use asupersync::bytes::Buf;
use asupersync::http::Body;
use asupersync::http::h1::http_client::ClientIo;
use asupersync::http::h1::{
    ClientError, ClientStreamingResponse, HttpClient, Method, RedirectPolicy, RetryPolicy,
};
use fastmcp_protocol::methods::{
    Final2026Direction, Final2026EnvelopeKind, PROMPTS_GET, RESOURCES_READ, TOOLS_CALL,
    final_2026_07_28_method,
};
use fastmcp_protocol::protocol_policy::{
    HttpModernProbe, HttpProbeBody, MODERN_PROTOCOL_VERSION, ProtocolEra, ProtocolPolicy,
};
use fastmcp_protocol::{
    ClientCapabilities, ClientInfo, FinalRequestMeta, JsonRpcMessage, JsonRpcRequest, RequestId,
    SERVER_DISCOVER, ServerDiscoverResult, decode_strict_jsonrpc_message,
};

use crate::sse::{BoundedSseParser, SseEndOfStream, SseLimits, SseParseError};
use crate::{
    ClientHttpNegotiation, ClientHttpNegotiationDecision, ClientHttpNegotiationError,
    ClientProtocolPlan,
};

/// Exact request headers required for a modern MCP JSON-RPC POST.
pub const MODERN_MCP_ACCEPT: &str = "application/json, text/event-stream";
pub const MODERN_MCP_ACCEPT_ENCODING: &str = "identity";
pub const MODERN_MCP_CONTENT_TYPE: &str = "application/json";

/// Maximum response bytes retained while classifying a disposable modern probe.
pub const MAX_MODERN_HTTP_PROBE_BODY_BYTES: usize = 64 * 1024;

/// Maximum retained bytes in one legacy SSE event, including its field names.
const MAX_LEGACY_SSE_EVENT_BYTES: usize = 64 * 1024;

/// Maximum bytes in one legacy SSE line before the connection is refused.
const MAX_LEGACY_SSE_LINE_BYTES: usize = 16 * 1024;

/// Maximum ignored legacy SSE comment lines between dispatched events.
const MAX_LEGACY_SSE_KEEPALIVE_LINES: usize = 64;

/// Maximum JSON-RPC bytes accepted from one legacy `message` SSE event.
const MAX_LEGACY_SSE_MESSAGE_BYTES: usize = 64 * 1024;

/// LIMIT-01's default cap for ignored RFC 9110 list elements in one
/// `Content-Encoding` field value.
///
/// Empty elements are framing noise, never semantic content codings. Keeping
/// the count finite prevents a response header from consuming unbounded work
/// before this executor exposes any body bytes.
const MAX_IGNORED_RESPONSE_CONTENT_ENCODING_EMPTY_ELEMENTS: usize = 16;

/// A single modern MCP JSON-RPC POST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModernHttpRequest {
    target: String,
    body: Vec<u8>,
    protocol_version: String,
    method: String,
    name: Option<String>,
}

impl ModernHttpRequest {
    /// Constructs the immutable wire inputs for one modern POST.
    pub fn new(
        target: impl Into<String>,
        body: Vec<u8>,
        protocol_version: impl Into<String>,
        method: impl Into<String>,
        name: Option<String>,
    ) -> Result<Self, ModernHttpExecutorError> {
        let target = target.into();
        let protocol_version = protocol_version.into();
        let method = method.into();
        if target.is_empty() || protocol_version.is_empty() || method.is_empty() {
            return Err(ModernHttpExecutorError::InvalidRequestMetadata);
        }
        if [target.as_str(), protocol_version.as_str(), method.as_str()]
            .into_iter()
            .chain(name.as_deref())
            .any(contains_header_control)
        {
            return Err(ModernHttpExecutorError::InvalidRequestMetadata);
        }
        Ok(Self {
            target,
            body,
            protocol_version,
            method,
            name,
        })
    }

    /// Returns the configured absolute target supplied by the caller.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the JSON-RPC request bytes exactly as they will be POSTed.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Builds the fixed, uncoded MCP request headers.
    ///
    /// `Accept-Encoding` explicitly requests the canonical identity coding;
    /// the request itself deliberately omits `Content-Encoding` because its
    /// JSON-RPC body is not encoded.
    #[must_use]
    pub fn headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![
            (
                "Content-Type".to_owned(),
                MODERN_MCP_CONTENT_TYPE.to_owned(),
            ),
            ("Accept".to_owned(), MODERN_MCP_ACCEPT.to_owned()),
            (
                "Accept-Encoding".to_owned(),
                MODERN_MCP_ACCEPT_ENCODING.to_owned(),
            ),
            (
                "MCP-Protocol-Version".to_owned(),
                self.protocol_version.clone(),
            ),
            ("Mcp-Method".to_owned(), self.method.clone()),
        ];
        if let Some(name) = &self.name {
            headers.push(("Mcp-Name".to_owned(), name.clone()));
        }
        headers
    }
}

/// The admitted body form for a modern response stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModernHttpResponseKind {
    /// A successful immediate JSON response.
    Json,
    /// A successful request-scoped SSE response stream.
    Sse,
    /// A non-success response whose body remains opaque to this transport layer.
    HttpFailure,
}

/// Response metadata fixed before any response-body bytes are consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModernHttpResponseMetadata {
    status: u16,
    kind: ModernHttpResponseKind,
}

impl ModernHttpResponseMetadata {
    /// Returns the received HTTP status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the body decoding lane selected from the response head.
    #[must_use]
    pub const fn kind(&self) -> ModernHttpResponseKind {
        self.kind
    }
}

/// A live native response stream, owned by one modern POST.
#[derive(Debug)]
pub struct ModernHttpResponseStream {
    metadata: ModernHttpResponseMetadata,
    response: ClientStreamingResponse<ClientIo>,
}

impl ModernHttpResponseStream {
    /// Returns metadata admitted before exposing the body stream.
    #[must_use]
    pub const fn metadata(&self) -> &ModernHttpResponseMetadata {
        &self.metadata
    }

    /// Consumes this wrapper and returns the native cancel-aware response stream.
    #[must_use]
    pub fn into_native(self) -> ClientStreamingResponse<ClientIo> {
        self.response
    }

    /// Converts a validated modern SSE response into a bounded event stream.
    ///
    /// The parser is the crate's shipped WHATWG event-stream implementation;
    /// it retains neither reconnect nor event-ID state. Callers receive data
    /// payloads in wire order and remain responsible for JSON-RPC admission.
    /// Passing explicit limits keeps response-stream memory bounded without
    /// assigning ambient parser ceilings to the HTTP executor.
    pub fn into_sse_stream(
        self,
        limits: SseLimits,
    ) -> Result<ModernHttpSseResponseStream, ModernHttpExecutorError> {
        if !matches!(self.metadata.kind, ModernHttpResponseKind::Sse) {
            return Err(ModernHttpExecutorError::ExpectedSseResponse {
                actual: self.metadata.kind,
            });
        }
        Ok(ModernHttpSseResponseStream {
            response: Some(self.response),
            parser: Some(BoundedSseParser::new(limits)),
            pending_events: VecDeque::new(),
            end_of_stream: None,
        })
    }

    /// Reads a finite response body into memory under an explicit caller bound.
    ///
    /// This consumes the stream. It is appropriate for the disposable modern
    /// connection probe and ordinary JSON responses; callers expecting an SSE
    /// stream should retain [`Self::into_native`] instead.
    pub async fn read_to_end(
        self,
        cx: &Cx,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, ModernHttpExecutorError> {
        let mut response = self.response;
        let mut bytes = Vec::new();

        loop {
            if cx.checkpoint().is_err() {
                return Err(ModernHttpExecutorError::Cancelled);
            }
            let Some(frame) =
                poll_fn(|task_cx| Pin::new(&mut response.body).poll_frame(task_cx)).await
            else {
                break;
            };
            if cx.checkpoint().is_err() {
                return Err(ModernHttpExecutorError::Cancelled);
            }
            let Some(mut data) = frame
                .map_err(|_| ModernHttpExecutorError::ResponseBodyReadFailed)?
                .into_data()
            else {
                continue;
            };

            while data.has_remaining() {
                let chunk = data.chunk();
                if chunk.len() > maximum_bytes.saturating_sub(bytes.len()) {
                    return Err(ModernHttpExecutorError::ResponseBodyTooLarge { maximum_bytes });
                }
                bytes.extend_from_slice(chunk);
                data.advance(chunk.len());
            }
        }

        Ok(bytes)
    }
}

/// A live bounded parser over one modern HTTP SSE response body.
///
/// This owns both the native response body and the parser, so a parser
/// refusal immediately drops the response body instead of allowing callers
/// to continue using a malformed stream.
#[derive(Debug)]
pub struct ModernHttpSseResponseStream {
    response: Option<ClientStreamingResponse<ClientIo>>,
    parser: Option<BoundedSseParser>,
    pending_events: VecDeque<String>,
    end_of_stream: Option<SseEndOfStream>,
}

impl ModernHttpSseResponseStream {
    /// Returns the next completed SSE `data` payload, or `None` at EOF.
    ///
    /// The returned payload is not JSON-RPC-admitted. Its caller must decode
    /// it through the protocol's strict response/notification admission path.
    pub async fn next_event(&mut self, cx: &Cx) -> Result<Option<String>, ModernHttpExecutorError> {
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(Some(event));
        }
        if self.end_of_stream.is_some() {
            return Ok(None);
        }

        loop {
            if cx.checkpoint().is_err() {
                return Err(ModernHttpExecutorError::Cancelled);
            }
            let response = self
                .response
                .as_mut()
                .ok_or(ModernHttpExecutorError::SseStreamClosed)?;
            let Some(frame) =
                poll_fn(|task_cx| Pin::new(&mut response.body).poll_frame(task_cx)).await
            else {
                let parser = self
                    .parser
                    .take()
                    .ok_or(ModernHttpExecutorError::SseStreamClosed)?;
                let end_of_stream = parser.finish().map_err(ModernHttpExecutorError::SseParse)?;
                self.response = None;
                self.end_of_stream = Some(end_of_stream);
                return Ok(None);
            };
            if cx.checkpoint().is_err() {
                return Err(ModernHttpExecutorError::Cancelled);
            }
            let Some(mut data) = frame
                .map_err(|_| ModernHttpExecutorError::ResponseBodyReadFailed)?
                .into_data()
            else {
                continue;
            };

            while data.has_remaining() {
                let chunk = data.chunk();
                let parser = self
                    .parser
                    .as_mut()
                    .ok_or(ModernHttpExecutorError::SseStreamClosed)?;
                match parser.push(chunk) {
                    Ok(events) => self.pending_events.extend(events),
                    Err(error) => {
                        self.response = None;
                        self.parser = None;
                        self.pending_events.clear();
                        return Err(ModernHttpExecutorError::SseParse(error));
                    }
                }
                data.advance(chunk.len());
            }
            if let Some(event) = self.pending_events.pop_front() {
                return Ok(Some(event));
            }
        }
    }

    /// Returns the parser's EOF report once [`Self::next_event`] observed EOF.
    #[must_use]
    pub const fn end_of_stream(&self) -> Option<SseEndOfStream> {
        self.end_of_stream
    }
}

/// Errors raised before or while executing one modern POST.
#[derive(Debug)]
pub enum ModernHttpExecutorError {
    /// Request metadata cannot safely become an HTTP header value.
    InvalidRequestMetadata,
    /// Caller cancellation was observed before dispatching the POST.
    Cancelled,
    /// The native HTTP client could not complete the single exchange.
    Transport(ClientError),
    /// A redirect is terminal for MCP and was not followed.
    Redirect { status: u16 },
    /// A response has no usable singleton content encoding.
    UnsupportedContentEncoding,
    /// A response repeated a header whose cardinality is fixed for MCP.
    DuplicateResponseHeader { name: &'static str },
    /// A successful response did not select JSON or SSE exactly.
    UnsupportedSuccessContentType,
    /// An API requiring a modern SSE response received another admitted kind.
    ExpectedSseResponse {
        /// The body lane selected from the response head.
        actual: ModernHttpResponseKind,
    },
    /// A response body exceeded the caller's explicit retained-byte limit.
    ResponseBodyTooLarge {
        /// Maximum bytes that could be retained before the stream was dropped.
        maximum_bytes: usize,
    },
    /// The native response body could not be decoded while being consumed.
    ResponseBodyReadFailed,
    /// The bounded SSE parser refused a response body.
    SseParse(SseParseError),
    /// The SSE stream was already consumed, closed, or refused.
    SseStreamClosed,
}

impl fmt::Display for ModernHttpExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestMetadata => {
                formatter.write_str("invalid modern MCP request metadata")
            }
            Self::Cancelled => formatter.write_str("modern MCP request was cancelled"),
            Self::Transport(error) => write!(formatter, "native HTTP exchange failed: {error}"),
            Self::Redirect { status } => {
                write!(
                    formatter,
                    "modern MCP request received forbidden redirect status {status}"
                )
            }
            Self::UnsupportedContentEncoding => {
                formatter.write_str("modern MCP response has unsupported content encoding")
            }
            Self::DuplicateResponseHeader { name } => {
                write!(formatter, "modern MCP response repeats {name}")
            }
            Self::UnsupportedSuccessContentType => {
                formatter.write_str("modern MCP success response has unsupported content type")
            }
            Self::ExpectedSseResponse { actual } => {
                write!(
                    formatter,
                    "modern MCP operation requires an SSE response, received {actual:?}"
                )
            }
            Self::ResponseBodyTooLarge { maximum_bytes } => {
                write!(
                    formatter,
                    "modern MCP response body exceeds the {maximum_bytes}-byte limit"
                )
            }
            Self::ResponseBodyReadFailed => {
                formatter.write_str("modern MCP response body could not be read")
            }
            Self::SseParse(error) => error.fmt(formatter),
            Self::SseStreamClosed => {
                formatter.write_str("modern MCP SSE response stream is closed")
            }
        }
    }
}

impl std::error::Error for ModernHttpExecutorError {}

/// Executes modern MCP HTTP POSTs through explicit native HTTP primitives.
#[derive(Clone)]
pub struct ModernHttpExecutor {
    client: HttpClient,
}

impl Default for ModernHttpExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ModernHttpExecutor {
    /// Creates an HTTP client that cannot redirect or replay MCP requests.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: native_http_client(),
        }
    }

    /// Sends exactly one POST and returns its still-live response stream.
    pub async fn execute(
        &self,
        cx: &Cx,
        request: &ModernHttpRequest,
    ) -> Result<ModernHttpResponseStream, ModernHttpExecutorError> {
        if cx.checkpoint().is_err() {
            return Err(ModernHttpExecutorError::Cancelled);
        }
        let response = self
            .client
            .request_streaming(
                cx,
                Method::Post,
                request.target(),
                request.headers(),
                request.body().to_vec(),
            )
            .await
            .map_err(map_transport_error)?;
        if cx.checkpoint().is_err() {
            return Err(ModernHttpExecutorError::Cancelled);
        }
        let metadata = validate_response_head(response.head.status, &response.head.headers)?;
        Ok(ModernHttpResponseStream { metadata, response })
    }
}

fn native_http_client() -> HttpClient {
    HttpClient::builder()
        .redirect_policy(RedirectPolicy::None)
        .retry_policy(RetryPolicy::None)
        .no_cookie_store()
        .no_proxy()
        .build()
}

/// A configured native modern HTTP client after one successful modern probe.
///
/// The executor retained here is deliberately created only after the probe has
/// been consumed and classified. Probe connection/body state is therefore not
/// reusable by ordinary requests.
#[derive(Clone)]
pub struct ModernHttpClient {
    protocol_plan: ClientProtocolPlan,
    modern_post_target: String,
    client_info: ClientInfo,
    client_capabilities: ClientCapabilities,
    server_discovery: ServerDiscoverResult,
    executor: ModernHttpExecutor,
}

/// The result of a policy-bound modern HTTP connection attempt.
pub enum ModernHttpConnectOutcome {
    /// The probe selected MCP 2026-07-28 and a modern request client is ready.
    Modern(ModernHttpClient),
    /// A recognized disposable modern refusal opened the exact configured
    /// MCP 2024-11-05 SSE GET endpoint and pinned its advertised POST route.
    LegacySse(LegacySseHttpClient),
}

impl ModernHttpConnectOutcome {
    /// Returns the selected era after this connection attempt, if any.
    ///
    /// Legacy is selected only after its first SSE `endpoint` event has been
    /// validated against the immutable configured POST target.
    #[must_use]
    pub const fn selected_era(&self) -> Option<ProtocolEra> {
        match self {
            Self::Modern(_) => Some(ProtocolEra::Modern2026),
            Self::LegacySse(_) => Some(ProtocolEra::Legacy2024),
        }
    }

    /// Returns the ready modern client when the probe selected the modern era.
    #[must_use]
    pub fn into_modern(self) -> Option<ModernHttpClient> {
        match self {
            Self::Modern(client) => Some(client),
            Self::LegacySse(_) => None,
        }
    }

    /// Returns the ready legacy SSE client when the configured legacy route
    /// was opened after a recognized auto refusal or under `LegacyOnly`.
    #[must_use]
    pub fn into_legacy_sse(self) -> Option<LegacySseHttpClient> {
        match self {
            Self::Modern(_) => None,
            Self::LegacySse(client) => Some(client),
        }
    }
}

/// Errors raised while connecting or issuing a policy-bound modern HTTP request.
#[derive(Debug)]
pub enum ModernHttpClientError {
    /// The supplied plan has no configured modern HTTP POST target.
    MissingModernPostTarget,
    /// A normal modern request requires object parameters so final metadata can
    /// be bound without changing the method-specific parameter shape.
    RequestParametersMustBeObject,
    /// `tools/call`, `prompts/get`, and `resources/read` omitted their required
    /// value for the final `Mcp-Name` header mirror.
    MissingRequestName { method: String },
    /// The caller selected no active final client-to-server method.
    UnsupportedFinalMethod { method: String },
    /// The caller selected a final method that only the server may send.
    ServerInitiatedFinalMethod { method: String },
    /// The caller omitted the request ID required by the selected final method.
    MissingRequestId { method: String },
    /// The caller supplied an ID for a final notification method.
    NotificationHasRequestId { method: String },
    /// JSON-RPC or final metadata serialization failed before a native POST.
    RequestEncodingFailed,
    /// The native executor rejected or failed the HTTP exchange.
    Executor(ModernHttpExecutorError),
    /// The immutable-plan classifier rejected the disposable probe.
    Negotiation(ClientHttpNegotiationError),
    /// The peer returned a recognized JSON-RPC error to `server/discover`.
    DiscoveryRejected,
    /// The recognized response was not the exact typed discovery reply.
    InvalidDiscoveryResponse,
    /// The configured native legacy SSE connection could not be opened or
    /// safely used after policy selected its exact endpoint bundle.
    LegacySse(LegacySseHttpClientError),
}

impl fmt::Display for ModernHttpClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingModernPostTarget => {
                formatter.write_str("the protocol plan has no modern MCP POST target")
            }
            Self::RequestParametersMustBeObject => {
                formatter.write_str("modern MCP request parameters must be an object")
            }
            Self::MissingRequestName { method } => {
                write!(
                    formatter,
                    "modern MCP {method} request is missing its header name value"
                )
            }
            Self::UnsupportedFinalMethod { method } => {
                write!(formatter, "{method} is not an active final MCP method")
            }
            Self::ServerInitiatedFinalMethod { method } => {
                write!(formatter, "{method} is a server-initiated final MCP method")
            }
            Self::MissingRequestId { method } => {
                write!(formatter, "modern MCP request {method} requires an ID")
            }
            Self::NotificationHasRequestId { method } => {
                write!(
                    formatter,
                    "modern MCP notification {method} must not have an ID"
                )
            }
            Self::RequestEncodingFailed => {
                formatter.write_str("modern MCP request encoding failed")
            }
            Self::Executor(error) => error.fmt(formatter),
            Self::Negotiation(error) => error.fmt(formatter),
            Self::DiscoveryRejected => formatter.write_str("server/discover was rejected"),
            Self::InvalidDiscoveryResponse => {
                formatter.write_str("server/discover returned an invalid final response")
            }
            Self::LegacySse(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ModernHttpClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Executor(error) => Some(error),
            Self::Negotiation(error) => Some(error),
            Self::LegacySse(error) => Some(error),
            Self::MissingModernPostTarget
            | Self::RequestParametersMustBeObject
            | Self::MissingRequestName { .. }
            | Self::UnsupportedFinalMethod { .. }
            | Self::ServerInitiatedFinalMethod { .. }
            | Self::MissingRequestId { .. }
            | Self::NotificationHasRequestId { .. }
            | Self::RequestEncodingFailed
            | Self::DiscoveryRejected
            | Self::InvalidDiscoveryResponse => None,
        }
    }
}

impl ModernHttpClient {
    /// Connects using one immutable HTTP protocol plan and a disposable modern
    /// `server/discover` probe.
    ///
    /// `ModernOnly` always retains the modern result. `LegacyOnly` opens only
    /// the configured legacy SSE route. `Auto` opens legacy only for the
    /// negotiation layer's recognized 400/404/405 empty-or-unrecognized
    /// refusal shapes; transport, body, and malformed-response failures never
    /// authorize a downgrade.
    pub async fn connect(
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
    ) -> Result<ModernHttpConnectOutcome, ModernHttpClientError> {
        if cx.checkpoint().is_err() {
            return Err(ModernHttpClientError::Executor(
                ModernHttpExecutorError::Cancelled,
            ));
        }
        if matches!(protocol_plan.policy(), ProtocolPolicy::LegacyOnly) {
            return LegacySseHttpClient::connect(cx, protocol_plan)
                .await
                .map(ModernHttpConnectOutcome::LegacySse)
                .map_err(ModernHttpClientError::LegacySse);
        }

        let modern_post_target = protocol_plan
            .modern_post_target()
            .ok_or(ModernHttpClientError::MissingModernPostTarget)?
            .to_owned();
        let mut negotiation = ClientHttpNegotiation::from_protocol_plan(&protocol_plan)
            .map_err(ModernHttpClientError::Negotiation)?;
        let probe_request = build_modern_request(
            &modern_post_target,
            &client_info,
            &client_capabilities,
            SERVER_DISCOVER,
            serde_json::json!({}),
            Some(RequestId::Number(1)),
        )?;

        let probe_response = ModernHttpExecutor::new()
            .execute(cx, &probe_request)
            .await
            .map_err(ModernHttpClientError::Executor)?;
        let probe_status = probe_response.metadata().status();
        let probe_body = probe_response
            .read_to_end(cx, MAX_MODERN_HTTP_PROBE_BODY_BYTES)
            .await
            .map_err(ModernHttpClientError::Executor)?;
        let probe = HttpModernProbe {
            status: probe_status,
            body: classify_modern_probe_body(&probe_body),
        };

        match negotiation
            .observe_modern_probe(probe)
            .map_err(ModernHttpClientError::Negotiation)?
        {
            ClientHttpNegotiationDecision::ModernSelected => {
                let server_discovery = decode_modern_discovery_response(&probe_body)?;
                Ok(ModernHttpConnectOutcome::Modern(Self {
                    protocol_plan,
                    modern_post_target,
                    client_info,
                    client_capabilities,
                    server_discovery,
                    executor: ModernHttpExecutor::new(),
                }))
            }
            ClientHttpNegotiationDecision::LegacySseFallbackAuthorized => {
                LegacySseHttpClient::connect(cx, protocol_plan)
                    .await
                    .map(ModernHttpConnectOutcome::LegacySse)
                    .map_err(ModernHttpClientError::LegacySse)
            }
        }
    }

    /// Returns the immutable policy and endpoint plan selected before connect.
    #[must_use]
    pub const fn protocol_plan(&self) -> &ClientProtocolPlan {
        &self.protocol_plan
    }

    /// Returns the configured immutable modern POST target.
    #[must_use]
    pub fn modern_post_target(&self) -> &str {
        &self.modern_post_target
    }

    /// Returns the exact typed discovery result that selected modern HTTP.
    #[must_use]
    pub const fn server_discovery(&self) -> &ServerDiscoverResult {
        &self.server_discovery
    }

    /// Issues one modern JSON-RPC request through the native HTTP executor.
    ///
    /// The runtime overwrites the final metadata keys in `_meta` from its
    /// immutable client identity and capability values, then mirrors the exact
    /// protocol version, method, and conditional name in the HTTP request
    /// headers. The response body stays live for the caller to stream or drain.
    pub async fn request(
        &self,
        cx: &Cx,
        method: impl AsRef<str>,
        parameters: serde_json::Value,
        request_id: Option<RequestId>,
    ) -> Result<ModernHttpResponseStream, ModernHttpClientError> {
        let request = build_modern_request(
            &self.modern_post_target,
            &self.client_info,
            &self.client_capabilities,
            method.as_ref(),
            parameters,
            request_id,
        )?;
        self.executor
            .execute(cx, &request)
            .await
            .map_err(ModernHttpClientError::Executor)
    }
}

/// A live MCP 2024-11-05 SSE connection with its advertised POST target
/// pinned to the immutable legacy endpoint bundle.
pub struct LegacySseHttpClient {
    protocol_plan: ClientProtocolPlan,
    configured_message_post_target: String,
    advertised_message_post_target: String,
    post_client: HttpClient,
    stream: LegacySseResponseStream,
}

impl LegacySseHttpClient {
    /// Opens the configured SSE GET endpoint and admits its first `endpoint`
    /// event only when it exactly matches the immutable configured POST route.
    pub async fn connect(
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
    ) -> Result<Self, LegacySseHttpClientError> {
        if cx.checkpoint().is_err() {
            return Err(LegacySseHttpClientError::Cancelled);
        }
        let sse_target = protocol_plan
            .legacy_sse_target()
            .ok_or(LegacySseHttpClientError::MissingSseTarget)?
            .to_owned();
        let configured_message_post_target = protocol_plan
            .legacy_message_post_target()
            .ok_or(LegacySseHttpClientError::MissingMessagePostTarget)?
            .to_owned();

        let response = native_http_client()
            .request_streaming(
                cx,
                Method::Get,
                &sse_target,
                vec![
                    ("Accept".to_owned(), "text/event-stream".to_owned()),
                    (
                        "Accept-Encoding".to_owned(),
                        MODERN_MCP_ACCEPT_ENCODING.to_owned(),
                    ),
                ],
                Vec::new(),
            )
            .await
            .map_err(map_transport_error)
            .map_err(LegacySseHttpClientError::Executor)?;
        validate_legacy_sse_response_head(response.head.status, &response.head.headers)?;

        let mut stream = LegacySseResponseStream::new(response);
        let advertised_message_post_target = match stream.next_event(cx).await? {
            Some(LegacySseEvent::Endpoint(target)) if !target.is_empty() => target,
            Some(LegacySseEvent::Endpoint(_)) => {
                return Err(LegacySseHttpClientError::EmptyAdvertisedMessagePostTarget);
            }
            Some(LegacySseEvent::Message(_)) => {
                return Err(LegacySseHttpClientError::FirstEventWasNotEndpoint);
            }
            None => return Err(LegacySseHttpClientError::SseEndedBeforeEndpoint),
        };
        if advertised_message_post_target != configured_message_post_target {
            return Err(
                LegacySseHttpClientError::AdvertisedMessagePostTargetMismatch {
                    configured: configured_message_post_target,
                    advertised: advertised_message_post_target,
                },
            );
        }

        Ok(Self {
            protocol_plan,
            configured_message_post_target,
            advertised_message_post_target,
            post_client: native_http_client(),
            stream,
        })
    }

    /// Returns the immutable policy and endpoint plan used to open this client.
    #[must_use]
    pub const fn protocol_plan(&self) -> &ClientProtocolPlan {
        &self.protocol_plan
    }

    /// Returns the exact configured legacy message POST target.
    #[must_use]
    pub fn configured_message_post_target(&self) -> &str {
        &self.configured_message_post_target
    }

    /// Returns the validated endpoint advertised by the first SSE event.
    #[must_use]
    pub fn advertised_message_post_target(&self) -> &str {
        &self.advertised_message_post_target
    }

    /// Sends one legacy JSON-RPC envelope to the validated advertised POST URL.
    ///
    /// The legacy request intentionally carries no final-MCP metadata headers.
    pub async fn send(
        &self,
        cx: &Cx,
        message: &JsonRpcMessage,
    ) -> Result<(), LegacySseHttpClientError> {
        if cx.checkpoint().is_err() {
            return Err(LegacySseHttpClientError::Cancelled);
        }
        let mut body = serde_json::to_vec(message)
            .map_err(|_| LegacySseHttpClientError::MessageEncodingFailed)?;
        body.push(b'\n');
        let mut response = self
            .post_client
            .request_streaming(
                cx,
                Method::Post,
                &self.advertised_message_post_target,
                vec![
                    (
                        "Content-Type".to_owned(),
                        MODERN_MCP_CONTENT_TYPE.to_owned(),
                    ),
                    ("Accept".to_owned(), "application/json".to_owned()),
                    (
                        "Accept-Encoding".to_owned(),
                        MODERN_MCP_ACCEPT_ENCODING.to_owned(),
                    ),
                ],
                body,
            )
            .await
            .map_err(map_transport_error)
            .map_err(LegacySseHttpClientError::Executor)?;
        if cx.checkpoint().is_err() {
            return Err(LegacySseHttpClientError::Cancelled);
        }
        validate_content_encoding(&response.head.headers)
            .map_err(LegacySseHttpClientError::Executor)?;
        if (300..400).contains(&response.head.status) {
            return Err(LegacySseHttpClientError::MessagePostRedirect {
                status: response.head.status,
            });
        }
        if !(200..300).contains(&response.head.status) {
            return Err(LegacySseHttpClientError::MessagePostRejected {
                status: response.head.status,
            });
        }
        drain_native_response(cx, &mut response, MAX_LEGACY_SSE_MESSAGE_BYTES)
            .await
            .map_err(LegacySseHttpClientError::Executor)?;
        Ok(())
    }

    /// Waits for the next legacy SSE `message` JSON-RPC envelope.
    ///
    /// A repeated `endpoint` event is refused instead of allowing it to change
    /// the POST destination after connection establishment.
    pub async fn next_message(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<JsonRpcMessage>, LegacySseHttpClientError> {
        loop {
            match self.stream.next_event(cx).await? {
                Some(LegacySseEvent::Message(payload)) => {
                    return decode_strict_jsonrpc_message(
                        payload.as_bytes(),
                        MAX_LEGACY_SSE_MESSAGE_BYTES,
                    )
                    .map(Some)
                    .map_err(|_| LegacySseHttpClientError::MessageDecodeFailed);
                }
                Some(LegacySseEvent::Endpoint(_)) => {
                    return Err(LegacySseHttpClientError::UnexpectedEndpointEvent);
                }
                None => return Ok(None),
            }
        }
    }
}

/// Errors emitted by the exact legacy SSE GET plus advertised POST client.
#[derive(Debug)]
pub enum LegacySseHttpClientError {
    /// The immutable plan omitted its legacy SSE GET target.
    MissingSseTarget,
    /// The immutable plan omitted its legacy message POST target.
    MissingMessagePostTarget,
    /// The caller's context was cancelled.
    Cancelled,
    /// Native HTTP setup, framing, or body consumption failed.
    Executor(ModernHttpExecutorError),
    /// The SSE GET endpoint returned a redirect, which must not be followed.
    SseGetRedirect { status: u16 },
    /// The SSE GET endpoint did not return a 2xx response.
    SseGetRejected { status: u16 },
    /// A successful SSE GET did not declare the required content type.
    UnsupportedSseContentType,
    /// The stream ended before it advertised a POST endpoint.
    SseEndedBeforeEndpoint,
    /// The first dispatched legacy SSE event was not `endpoint`.
    FirstEventWasNotEndpoint,
    /// The first `endpoint` event had an empty data value.
    EmptyAdvertisedMessagePostTarget,
    /// The advertised POST route differed from the configured immutable one.
    AdvertisedMessagePostTargetMismatch {
        configured: String,
        advertised: String,
    },
    /// A later endpoint event attempted to alter an established destination.
    UnexpectedEndpointEvent,
    /// An SSE line exceeded the bounded legacy parser limit.
    SseLineTooLong,
    /// An SSE event exceeded the bounded legacy parser limit.
    SseEventTooLarge,
    /// An SSE field line was not valid UTF-8.
    SseInvalidUtf8,
    /// Too many ignored comments were received before an event boundary.
    TooManySseKeepalives,
    /// A JSON-RPC envelope could not be serialized for a legacy POST.
    MessageEncodingFailed,
    /// The legacy POST endpoint returned a redirect, which must not be followed.
    MessagePostRedirect { status: u16 },
    /// The legacy POST endpoint did not acknowledge the JSON-RPC envelope.
    MessagePostRejected { status: u16 },
    /// A legacy SSE `message` event was not a strict JSON-RPC envelope.
    MessageDecodeFailed,
}

impl fmt::Display for LegacySseHttpClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSseTarget => formatter.write_str("the plan has no legacy SSE GET target"),
            Self::MissingMessagePostTarget => {
                formatter.write_str("the plan has no legacy message POST target")
            }
            Self::Cancelled => formatter.write_str("legacy SSE HTTP operation was cancelled"),
            Self::Executor(error) => error.fmt(formatter),
            Self::SseGetRedirect { status } => {
                write!(
                    formatter,
                    "legacy SSE GET received forbidden redirect status {status}"
                )
            }
            Self::SseGetRejected { status } => {
                write!(
                    formatter,
                    "legacy SSE GET was rejected with status {status}"
                )
            }
            Self::UnsupportedSseContentType => {
                formatter.write_str("legacy SSE GET did not return text/event-stream")
            }
            Self::SseEndedBeforeEndpoint => {
                formatter.write_str("legacy SSE ended before its endpoint event")
            }
            Self::FirstEventWasNotEndpoint => {
                formatter.write_str("the first legacy SSE event was not endpoint")
            }
            Self::EmptyAdvertisedMessagePostTarget => {
                formatter.write_str("legacy SSE advertised an empty message POST target")
            }
            Self::AdvertisedMessagePostTargetMismatch {
                configured,
                advertised,
            } => write!(
                formatter,
                "legacy SSE advertised POST target {advertised:?} differs from configured target {configured:?}"
            ),
            Self::UnexpectedEndpointEvent => {
                formatter.write_str("legacy SSE attempted to replace its established POST target")
            }
            Self::SseLineTooLong => formatter.write_str("legacy SSE line exceeds its byte limit"),
            Self::SseEventTooLarge => {
                formatter.write_str("legacy SSE event exceeds its byte limit")
            }
            Self::SseInvalidUtf8 => formatter.write_str("legacy SSE field line is not UTF-8"),
            Self::TooManySseKeepalives => {
                formatter.write_str("legacy SSE exceeded its ignored keepalive limit")
            }
            Self::MessageEncodingFailed => formatter.write_str("legacy JSON-RPC encoding failed"),
            Self::MessagePostRedirect { status } => {
                write!(
                    formatter,
                    "legacy message POST received forbidden redirect status {status}"
                )
            }
            Self::MessagePostRejected { status } => {
                write!(
                    formatter,
                    "legacy message POST was rejected with status {status}"
                )
            }
            Self::MessageDecodeFailed => formatter.write_str("legacy SSE message was not JSON-RPC"),
        }
    }
}

impl std::error::Error for LegacySseHttpClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Executor(error) => Some(error),
            Self::MissingSseTarget
            | Self::MissingMessagePostTarget
            | Self::Cancelled
            | Self::SseGetRedirect { .. }
            | Self::SseGetRejected { .. }
            | Self::UnsupportedSseContentType
            | Self::SseEndedBeforeEndpoint
            | Self::FirstEventWasNotEndpoint
            | Self::EmptyAdvertisedMessagePostTarget
            | Self::AdvertisedMessagePostTargetMismatch { .. }
            | Self::UnexpectedEndpointEvent
            | Self::SseLineTooLong
            | Self::SseEventTooLarge
            | Self::SseInvalidUtf8
            | Self::TooManySseKeepalives
            | Self::MessageEncodingFailed
            | Self::MessagePostRedirect { .. }
            | Self::MessagePostRejected { .. }
            | Self::MessageDecodeFailed => None,
        }
    }
}

#[derive(Debug)]
enum LegacySseEvent {
    Endpoint(String),
    Message(String),
}

struct LegacySseResponseStream {
    response: Option<ClientStreamingResponse<ClientIo>>,
    parser: LegacySseParser,
    pending_events: VecDeque<LegacySseEvent>,
}

impl LegacySseResponseStream {
    fn new(response: ClientStreamingResponse<ClientIo>) -> Self {
        Self {
            response: Some(response),
            parser: LegacySseParser::default(),
            pending_events: VecDeque::new(),
        }
    }

    async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<LegacySseEvent>, LegacySseHttpClientError> {
        loop {
            if cx.checkpoint().is_err() {
                return Err(LegacySseHttpClientError::Cancelled);
            }
            if let Some(event) = self.pending_events.pop_front() {
                return Ok(Some(event));
            }
            let Some(response) = self.response.as_mut() else {
                return Ok(None);
            };
            let Some(frame) =
                poll_fn(|task_cx| Pin::new(&mut response.body).poll_frame(task_cx)).await
            else {
                self.response = None;
                self.parser.finish();
                return Ok(None);
            };
            let Some(mut data) = frame
                .map_err(|_| ModernHttpExecutorError::ResponseBodyReadFailed)
                .map_err(LegacySseHttpClientError::Executor)?
                .into_data()
            else {
                continue;
            };
            while data.has_remaining() {
                let chunk = data.chunk();
                self.pending_events.extend(self.parser.push(chunk)?);
                data.advance(chunk.len());
            }
        }
    }
}

#[derive(Default)]
struct LegacySseParser {
    line: Vec<u8>,
    pending_cr: bool,
    event_type: Option<LegacySseEventType>,
    data: String,
    has_data: bool,
    event_bytes: usize,
    ignored_keepalives: usize,
}

#[derive(Clone, Copy)]
enum LegacySseEventType {
    Endpoint,
    Message,
    Ignore,
}

impl LegacySseParser {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<LegacySseEvent>, LegacySseHttpClientError> {
        let mut events = Vec::new();
        for &byte in bytes {
            if self.pending_cr {
                self.pending_cr = false;
                if byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\r' => {
                    self.finish_line(&mut events)?;
                    self.pending_cr = true;
                }
                b'\n' => self.finish_line(&mut events)?,
                _ => {
                    if self.line.len() >= MAX_LEGACY_SSE_LINE_BYTES {
                        return Err(LegacySseHttpClientError::SseLineTooLong);
                    }
                    self.line.push(byte);
                }
            }
        }
        Ok(events)
    }

    fn finish(&mut self) {
        self.line.clear();
        self.reset_event();
    }

    fn finish_line(
        &mut self,
        events: &mut Vec<LegacySseEvent>,
    ) -> Result<(), LegacySseHttpClientError> {
        let line = std::str::from_utf8(&self.line)
            .map_err(|_| LegacySseHttpClientError::SseInvalidUtf8)?;
        if line.is_empty() {
            self.ignored_keepalives = 0;
            if self.has_data {
                let event_type = self.event_type.unwrap_or(LegacySseEventType::Message);
                let mut data = std::mem::take(&mut self.data);
                data.pop();
                self.has_data = false;
                self.event_type = None;
                self.event_bytes = 0;
                match event_type {
                    LegacySseEventType::Endpoint => events.push(LegacySseEvent::Endpoint(data)),
                    LegacySseEventType::Message => events.push(LegacySseEvent::Message(data)),
                    LegacySseEventType::Ignore => {}
                }
            } else {
                self.reset_event();
            }
            self.line.clear();
            return Ok(());
        }
        if line.starts_with(':') {
            self.ignored_keepalives = self.ignored_keepalives.saturating_add(1);
            if self.ignored_keepalives > MAX_LEGACY_SSE_KEEPALIVE_LINES {
                return Err(LegacySseHttpClientError::TooManySseKeepalives);
            }
            self.line.clear();
            return Ok(());
        }
        self.ignored_keepalives = 0;
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        self.event_bytes = self
            .event_bytes
            .saturating_add(line.len().saturating_add(1));
        if self.event_bytes > MAX_LEGACY_SSE_EVENT_BYTES {
            return Err(LegacySseHttpClientError::SseEventTooLarge);
        }
        match field {
            "event" => {
                self.event_type = Some(match value {
                    "endpoint" => LegacySseEventType::Endpoint,
                    "message" => LegacySseEventType::Message,
                    _ => LegacySseEventType::Ignore,
                });
            }
            "data" => {
                if self
                    .data
                    .len()
                    .saturating_add(value.len())
                    .saturating_add(1)
                    > MAX_LEGACY_SSE_MESSAGE_BYTES
                {
                    return Err(LegacySseHttpClientError::SseEventTooLarge);
                }
                self.data.push_str(value);
                self.data.push('\n');
                self.has_data = true;
            }
            _ => {}
        }
        self.line.clear();
        Ok(())
    }

    fn reset_event(&mut self) {
        self.event_type = None;
        self.data.clear();
        self.has_data = false;
        self.event_bytes = 0;
    }
}

fn validate_legacy_sse_response_head(
    status: u16,
    headers: &[(String, String)],
) -> Result<(), LegacySseHttpClientError> {
    validate_content_encoding(headers).map_err(LegacySseHttpClientError::Executor)?;
    if (300..400).contains(&status) {
        return Err(LegacySseHttpClientError::SseGetRedirect { status });
    }
    if !(200..300).contains(&status) {
        return Err(LegacySseHttpClientError::SseGetRejected { status });
    }
    let content_type = single_header(headers, "content-type", "Content-Type")
        .map_err(LegacySseHttpClientError::Executor)?
        .map(normalize_success_content_type)
        .transpose()
        .map_err(LegacySseHttpClientError::Executor)?;
    match content_type {
        Some(content_type) if content_type.eq_ignore_ascii_case("text/event-stream") => Ok(()),
        None | Some(_) => Err(LegacySseHttpClientError::UnsupportedSseContentType),
    }
}

async fn drain_native_response(
    cx: &Cx,
    response: &mut ClientStreamingResponse<ClientIo>,
    maximum_bytes: usize,
) -> Result<(), ModernHttpExecutorError> {
    let mut consumed = 0_usize;
    loop {
        if cx.checkpoint().is_err() {
            return Err(ModernHttpExecutorError::Cancelled);
        }
        let Some(frame) = poll_fn(|task_cx| Pin::new(&mut response.body).poll_frame(task_cx)).await
        else {
            return Ok(());
        };
        let Some(mut data) = frame
            .map_err(|_| ModernHttpExecutorError::ResponseBodyReadFailed)?
            .into_data()
        else {
            continue;
        };
        while data.has_remaining() {
            let chunk = data.chunk();
            if chunk.len() > maximum_bytes.saturating_sub(consumed) {
                return Err(ModernHttpExecutorError::ResponseBodyTooLarge { maximum_bytes });
            }
            consumed = consumed.saturating_add(chunk.len());
            data.advance(chunk.len());
        }
    }
}

fn build_modern_request(
    target: &str,
    client_info: &ClientInfo,
    client_capabilities: &ClientCapabilities,
    method: &str,
    parameters: serde_json::Value,
    request_id: Option<RequestId>,
) -> Result<ModernHttpRequest, ModernHttpClientError> {
    validate_final_method(method, request_id.is_some())?;
    let mut parameters = parameters
        .as_object()
        .cloned()
        .ok_or(ModernHttpClientError::RequestParametersMustBeObject)?;
    let name = request_name_header_value(method, &parameters)?;
    let mut metadata = parameters
        .remove("_meta")
        .map(|metadata| {
            metadata
                .as_object()
                .cloned()
                .ok_or(ModernHttpClientError::RequestParametersMustBeObject)
        })
        .transpose()?
        .unwrap_or_default();
    let mut final_request_meta = FinalRequestMeta::new(client_capabilities.clone());
    final_request_meta.client_info = Some(client_info.clone());
    let final_metadata = serde_json::to_value(final_request_meta)
        .map_err(|_| ModernHttpClientError::RequestEncodingFailed)?;
    let final_metadata = final_metadata
        .as_object()
        .ok_or(ModernHttpClientError::RequestEncodingFailed)?;
    metadata.extend(final_metadata.clone());
    parameters.insert("_meta".to_owned(), serde_json::Value::Object(metadata));

    let request = match request_id {
        Some(request_id) => JsonRpcRequest::new(
            method,
            Some(serde_json::Value::Object(parameters)),
            request_id,
        ),
        None => JsonRpcRequest::notification(method, Some(serde_json::Value::Object(parameters))),
    };
    let body =
        serde_json::to_vec(&request).map_err(|_| ModernHttpClientError::RequestEncodingFailed)?;
    ModernHttpRequest::new(target, body, MODERN_PROTOCOL_VERSION, method, name)
        .map_err(ModernHttpClientError::Executor)
}

fn request_name_header_value(
    method: &str,
    parameters: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<String>, ModernHttpClientError> {
    let Some(field) = (match method {
        TOOLS_CALL | PROMPTS_GET => Some("name"),
        RESOURCES_READ => Some("uri"),
        _ => None,
    }) else {
        return Ok(None);
    };
    parameters
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .map(Some)
        .ok_or_else(|| ModernHttpClientError::MissingRequestName {
            method: method.to_owned(),
        })
}

fn validate_final_method(method: &str, has_request_id: bool) -> Result<(), ModernHttpClientError> {
    let final_method = final_2026_07_28_method(method).ok_or_else(|| {
        ModernHttpClientError::UnsupportedFinalMethod {
            method: method.to_owned(),
        }
    })?;
    if !matches!(
        final_method.direction,
        Final2026Direction::ClientToServer | Final2026Direction::Bidirectional
    ) {
        return Err(ModernHttpClientError::ServerInitiatedFinalMethod {
            method: method.to_owned(),
        });
    }
    match (final_method.envelope, has_request_id) {
        (Final2026EnvelopeKind::Request, false) => Err(ModernHttpClientError::MissingRequestId {
            method: method.to_owned(),
        }),
        (Final2026EnvelopeKind::Notification, true) => {
            Err(ModernHttpClientError::NotificationHasRequestId {
                method: method.to_owned(),
            })
        }
        _ => Ok(()),
    }
}

fn classify_modern_probe_body(body: &[u8]) -> HttpProbeBody {
    if body.is_empty() {
        return HttpProbeBody::Empty;
    }
    match decode_strict_jsonrpc_message(body, MAX_MODERN_HTTP_PROBE_BODY_BYTES) {
        Ok(JsonRpcMessage::Response(_)) => HttpProbeBody::RecognizedModernJsonRpc,
        Ok(JsonRpcMessage::Request(_)) | Err(_) => HttpProbeBody::Unrecognized,
    }
}

fn decode_modern_discovery_response(
    body: &[u8],
) -> Result<ServerDiscoverResult, ModernHttpClientError> {
    let message = decode_strict_jsonrpc_message(body, MAX_MODERN_HTTP_PROBE_BODY_BYTES)
        .map_err(|_| ModernHttpClientError::InvalidDiscoveryResponse)?;
    let JsonRpcMessage::Response(response) = message else {
        return Err(ModernHttpClientError::InvalidDiscoveryResponse);
    };
    if response.id != Some(RequestId::Number(1)) {
        return Err(ModernHttpClientError::InvalidDiscoveryResponse);
    }
    if response.error.is_some() {
        return Err(ModernHttpClientError::DiscoveryRejected);
    }
    let result = response
        .result
        .ok_or(ModernHttpClientError::InvalidDiscoveryResponse)?;
    serde_json::from_value(result).map_err(|_| ModernHttpClientError::InvalidDiscoveryResponse)
}

fn map_transport_error(error: ClientError) -> ModernHttpExecutorError {
    if error.is_cancelled() {
        ModernHttpExecutorError::Cancelled
    } else {
        ModernHttpExecutorError::Transport(error)
    }
}

/// Validates response encoding and selects the only allowed body lane.
pub fn validate_response_head(
    status: u16,
    headers: &[(String, String)],
) -> Result<ModernHttpResponseMetadata, ModernHttpExecutorError> {
    validate_content_encoding(headers)?;
    if (300..400).contains(&status) {
        return Err(ModernHttpExecutorError::Redirect { status });
    }
    let kind = if (200..300).contains(&status) {
        let content_type = single_header(headers, "content-type", "Content-Type")?
            .map(normalize_success_content_type)
            .transpose()?;
        match content_type {
            Some(content_type) if content_type.eq_ignore_ascii_case("application/json") => {
                ModernHttpResponseKind::Json
            }
            Some(content_type) if content_type.eq_ignore_ascii_case("text/event-stream") => {
                ModernHttpResponseKind::Sse
            }
            None | Some(_) => return Err(ModernHttpExecutorError::UnsupportedSuccessContentType),
        }
    } else {
        ModernHttpResponseKind::HttpFailure
    };
    Ok(ModernHttpResponseMetadata { status, kind })
}

fn validate_content_encoding(headers: &[(String, String)]) -> Result<(), ModernHttpExecutorError> {
    let Some(value) = single_header(headers, "content-encoding", "Content-Encoding")? else {
        return Ok(());
    };

    let mut ignored_empty_elements = 0_usize;
    let mut semantic_codings = 0_usize;
    for element in value.split(',') {
        let element = trim_http_ows(element);
        if element.is_empty() {
            ignored_empty_elements = ignored_empty_elements.saturating_add(1);
            if ignored_empty_elements > MAX_IGNORED_RESPONSE_CONTENT_ENCODING_EMPTY_ELEMENTS {
                return Err(ModernHttpExecutorError::UnsupportedContentEncoding);
            }
            continue;
        }
        if !element.eq_ignore_ascii_case(MODERN_MCP_ACCEPT_ENCODING) {
            return Err(ModernHttpExecutorError::UnsupportedContentEncoding);
        }
        semantic_codings = semantic_codings.saturating_add(1);
        if semantic_codings > 1 {
            return Err(ModernHttpExecutorError::UnsupportedContentEncoding);
        }
    }

    if semantic_codings == 1 {
        Ok(())
    } else {
        Err(ModernHttpExecutorError::UnsupportedContentEncoding)
    }
}

fn single_header<'a>(
    headers: &'a [(String, String)],
    wanted_name: &str,
    display_name: &'static str,
) -> Result<Option<&'a str>, ModernHttpExecutorError> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(wanted_name))
        .map(|(_, value)| value.as_str());
    let first = values.next();
    if first.is_some() && values.next().is_some() {
        return Err(ModernHttpExecutorError::DuplicateResponseHeader { name: display_name });
    }
    Ok(first)
}

fn normalize_success_content_type(value: &str) -> Result<&str, ModernHttpExecutorError> {
    let mut parts = value.split(';');
    let essence = parts.next().map(trim_http_ows).unwrap_or_default();
    let Some(parameters) = parts.next() else {
        return Ok(essence);
    };
    if parts.next().is_some() {
        return Err(ModernHttpExecutorError::UnsupportedSuccessContentType);
    }
    let Some((name, charset)) = trim_http_ows(parameters).split_once('=') else {
        return Err(ModernHttpExecutorError::UnsupportedSuccessContentType);
    };
    if !trim_http_ows(name).eq_ignore_ascii_case("charset")
        || !trim_http_ows(charset).eq_ignore_ascii_case("utf-8")
    {
        return Err(ModernHttpExecutorError::UnsupportedSuccessContentType);
    }
    Ok(essence)
}

fn trim_http_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

fn contains_header_control(value: &str) -> bool {
    value
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0'))
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_IGNORED_RESPONSE_CONTENT_ENCODING_EMPTY_ELEMENTS, ModernHttpClientError,
        ModernHttpExecutorError, ModernHttpResponseKind, decode_modern_discovery_response,
        validate_response_head,
    };

    #[test]
    fn bounded_empty_content_encoding_elements_preserve_the_identity_stream_lane() {
        let encoding = format!(
            "{}Identity",
            ",".repeat(MAX_IGNORED_RESPONSE_CONTENT_ENCODING_EMPTY_ELEMENTS)
        );
        let response = validate_response_head(
            200,
            &[
                ("Content-Type".to_owned(), "text/event-stream".to_owned()),
                ("Content-Encoding".to_owned(), encoding),
            ],
        )
        .expect("one semantic identity token admits the SSE stream");

        assert_eq!(response.kind(), ModernHttpResponseKind::Sse);
    }

    #[test]
    fn one_extra_empty_content_encoding_element_rejects_without_admitting_a_body_lane() {
        let accepted_encoding = format!(
            "{}identity",
            ",".repeat(MAX_IGNORED_RESPONSE_CONTENT_ENCODING_EMPTY_ELEMENTS)
        );
        let accepted_headers = vec![
            ("Content-Type".to_owned(), "text/event-stream".to_owned()),
            ("Content-Encoding".to_owned(), accepted_encoding),
        ];
        assert!(validate_response_head(200, &accepted_headers).is_ok());

        // The sole changed field is one additional empty RFC 9110 list
        // element. This pure admission function owns no mutable body state,
        // so the rejection cannot expose or mutate a response stream.
        let rejected_encoding = format!(
            "{}identity",
            ",".repeat(MAX_IGNORED_RESPONSE_CONTENT_ENCODING_EMPTY_ELEMENTS + 1)
        );
        let rejected_headers = vec![
            ("Content-Type".to_owned(), "text/event-stream".to_owned()),
            ("Content-Encoding".to_owned(), rejected_encoding),
        ];
        assert!(matches!(
            validate_response_head(200, &rejected_headers),
            Err(ModernHttpExecutorError::UnsupportedContentEncoding)
        ));
    }

    #[test]
    fn modern_connect_requires_the_exact_typed_discovery_result() {
        let exact = br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#;
        let admitted = decode_modern_discovery_response(exact)
            .expect("the exact final discovery result must be retained");
        assert_eq!(admitted.supported_versions(), ["2026-07-28"]);

        let planted = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        assert!(matches!(
            decode_modern_discovery_response(planted),
            Err(ModernHttpClientError::InvalidDiscoveryResponse)
        ));
    }
}
