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
    Final2026Direction, Final2026EnvelopeKind, PROMPTS_GET, RESOURCES_READ, SUBSCRIPTIONS_LISTEN,
    TOOLS_CALL, final_2026_07_28_method,
};
use fastmcp_protocol::protocol_policy::{
    HttpModernProbe, HttpProbeBody, MODERN_PROTOCOL_VERSION, ProtocolEra, ProtocolPolicy,
};
use fastmcp_protocol::{
    ClientCapabilities, ClientInfo, CompleteResult, CoreDispatchError, CoreRequest, CoreResult,
    FINAL_SUBSCRIPTION_ID_META_KEY, FinalCoreResult, FinalNotificationError, FinalRequestMeta,
    FinalSubscriptionsAcknowledgedNotificationParams, FinalSubscriptionsListenResult,
    JsonRpcAdmissionError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId,
    SERVER_DISCOVER, ServerDiscoverResult, ServerNotification, SubscriptionFilter,
    decode_strict_jsonrpc_message,
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

    /// Consumes a final `subscriptions/listen` SSE response until its exact
    /// complete terminal result.
    ///
    /// Every dispatched SSE `data` payload must be one strictly admitted
    /// JSON-RPC message. The listener binds both acknowledgement and terminal
    /// result IDs to `request_id`, retains typed notifications in wire order,
    /// and refuses EOF or cancellation in place of a complete result.
    pub async fn collect_final_subscriptions_listen(
        self,
        cx: &Cx,
        request_id: RequestId,
        requested: SubscriptionFilter,
        limits: SseLimits,
    ) -> Result<ModernHttpSubscriptionListenCollector, ModernHttpSubscriptionListenError> {
        if request_id.validate().is_err() {
            return Err(ModernHttpSubscriptionListenError::InvalidRequestId);
        }
        let core_request = final_subscriptions_listen_core_request(&requested)?;
        let maximum_jsonrpc_bytes = limits.max_event_bytes();
        let mut stream = self
            .into_sse_stream(limits)
            .map_err(ModernHttpSubscriptionListenError::Executor)?;
        let mut accepted_filter = None;
        let mut notifications = Vec::new();

        loop {
            let event = match stream.next_event(cx).await {
                Ok(Some(event)) => event,
                Ok(None) => {
                    return Err(ModernHttpSubscriptionListenError::EndOfStream {
                        framing: stream.end_of_stream(),
                    });
                }
                Err(ModernHttpExecutorError::Cancelled) => {
                    return Err(ModernHttpSubscriptionListenError::Cancelled {
                        request_id: request_id.clone(),
                    });
                }
                Err(error) => return Err(ModernHttpSubscriptionListenError::Executor(error)),
            };
            let message = decode_strict_jsonrpc_message(event.as_bytes(), maximum_jsonrpc_bytes)
                .map_err(ModernHttpSubscriptionListenError::JsonRpcAdmission)?;

            match message {
                JsonRpcMessage::Response(response) => {
                    return collect_final_subscriptions_terminal(
                        &core_request,
                        response,
                        request_id,
                        accepted_filter,
                        notifications,
                    );
                }
                JsonRpcMessage::Request(request) => {
                    let notification = ServerNotification::decode(&request)
                        .map_err(ModernHttpSubscriptionListenError::NotificationAdmission)?;
                    match notification {
                        ServerNotification::SubscriptionsAcknowledged(acknowledgement) => {
                            if accepted_filter.is_some() {
                                return Err(
                                    ModernHttpSubscriptionListenError::DuplicateAcknowledgement,
                                );
                            }
                            validate_http_subscription_acknowledgement(
                                &request_id,
                                &requested,
                                &acknowledgement,
                            )?;
                            accepted_filter = Some(acknowledgement.notifications);
                        }
                        ServerNotification::Cancelled(cancellation) => {
                            if cancellation.request_id != request_id {
                                return Err(
                                    ModernHttpSubscriptionListenError::CancellationIdMismatch {
                                        expected: request_id,
                                        actual: cancellation.request_id,
                                    },
                                );
                            }
                            return Err(ModernHttpSubscriptionListenError::Cancelled {
                                request_id,
                            });
                        }
                        notification @ (ServerNotification::ResourcesListChanged(_)
                        | ServerNotification::ToolsListChanged(_)
                        | ServerNotification::PromptsListChanged(_)
                        | ServerNotification::ResourceUpdated(_)) => {
                            let Some(accepted_filter) = accepted_filter.as_ref() else {
                                return Err(
                                    ModernHttpSubscriptionListenError::EventBeforeAcknowledgement,
                                );
                            };
                            validate_http_subscription_notification_filter(
                                &notification,
                                accepted_filter,
                            )?;
                            notifications.push(notification);
                        }
                        notification @ (ServerNotification::Progress(_)
                        | ServerNotification::Message(_)) => notifications.push(notification),
                    }
                }
            }
        }
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

/// The terminal record collected from one final HTTP `subscriptions/listen`
/// response stream.
///
/// The acknowledgement is retained separately because it establishes the
/// accepted subscription filter. `notifications` preserves the wire order of
/// every typed notification belonging to this request after that
/// acknowledgement. The acknowledgement itself and a terminal cancellation
/// are control frames, not ordinary subscription events.
#[derive(Debug, Clone)]
pub struct ModernHttpSubscriptionListenCollector {
    /// The JSON-RPC request ID that owns this response stream.
    pub subscription_id: RequestId,
    /// The exact subset of requested notification categories accepted by the server.
    pub accepted_filter: SubscriptionFilter,
    /// Request-owned typed notifications in received wire order.
    pub notifications: Vec<ServerNotification>,
    /// The final complete result terminating the subscription stream.
    pub terminal: CompleteResult<FinalSubscriptionsListenResult>,
}

/// Errors raised while consuming one final HTTP `subscriptions/listen` SSE
/// response stream.
#[derive(Debug)]
pub enum ModernHttpSubscriptionListenError {
    /// The supplied request ID is not a valid JSON-RPC correlation key.
    InvalidRequestId,
    /// Constructing or issuing the final `subscriptions/listen` request failed.
    Request(ModernHttpClientError),
    /// The response did not use the required SSE body lane or could not be read.
    Executor(ModernHttpExecutorError),
    /// An SSE event was not one strictly admitted JSON-RPC object.
    JsonRpcAdmission(JsonRpcAdmissionError),
    /// A server request was not one typed final server notification.
    NotificationAdmission(FinalNotificationError),
    /// The server emitted a response for a request other than this listener.
    ResponseIdMismatch {
        /// The immutable ID assigned to the outgoing listen request.
        expected: RequestId,
        /// The response ID observed on the SSE stream.
        actual: Option<RequestId>,
    },
    /// The server terminated the listener with a JSON-RPC error.
    RemoteError {
        /// The remote JSON-RPC error code.
        code: i32,
        /// The remote JSON-RPC error message.
        message: String,
    },
    /// The exact final `subscriptions/listen` terminal result was invalid.
    TerminalResult(CoreDispatchError),
    /// The selected core result was not a final subscriptions/listen result.
    UnexpectedTerminalResult,
    /// The terminal subscription ID did not bind to the outgoing request.
    TerminalIdMismatch {
        /// The immutable ID assigned to the outgoing listen request.
        expected: RequestId,
        /// The subscription ID decoded from the terminal result metadata.
        actual: RequestId,
    },
    /// The stream ended successfully before its required acknowledgement.
    TerminalBeforeAcknowledgement,
    /// The stream delivered a duplicate subscription acknowledgement.
    DuplicateAcknowledgement,
    /// An acknowledgement omitted its required subscription ID metadata.
    AcknowledgementMissingId,
    /// An acknowledgement subscription ID could not be decoded as JSON-RPC ID.
    AcknowledgementInvalidId,
    /// An acknowledgement was bound to a different listener.
    AcknowledgementIdMismatch {
        /// The immutable ID assigned to the outgoing listen request.
        expected: RequestId,
        /// The subscription ID decoded from acknowledgement metadata.
        actual: RequestId,
    },
    /// An acknowledgement accepted a category that the caller did not request.
    AcknowledgementFilterNotRequested { category: &'static str },
    /// An acknowledgement accepted an invalid resource-update URI set.
    AcknowledgementResourceFilterNotRequested,
    /// An acknowledgement accepted an unrequested extension filter.
    AcknowledgementExtensionFilterNotRequested,
    /// A subscription event arrived before acknowledgement established its filter.
    EventBeforeAcknowledgement,
    /// A subscription event was outside the accepted filter.
    EventOutsideAcceptedFilter,
    /// A final cancellation targeted another request instead of this listener.
    CancellationIdMismatch {
        /// The immutable ID assigned to the outgoing listen request.
        expected: RequestId,
        /// The request ID carried by the cancellation notification.
        actual: RequestId,
    },
    /// The server cancelled this request-owned listener.
    Cancelled { request_id: RequestId },
    /// The SSE stream reached EOF without a complete terminal result.
    EndOfStream {
        /// The parser's exact report of discarded framing at EOF.
        framing: Option<SseEndOfStream>,
    },
}

impl fmt::Display for ModernHttpSubscriptionListenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestId => {
                formatter.write_str("subscriptions/listen requires a valid JSON-RPC request ID")
            }
            Self::Request(error) => error.fmt(formatter),
            Self::Executor(error) => error.fmt(formatter),
            Self::JsonRpcAdmission(error) => write!(
                formatter,
                "subscriptions/listen SSE event failed strict JSON-RPC admission: {error}"
            ),
            Self::NotificationAdmission(error) => write!(
                formatter,
                "subscriptions/listen SSE event was not a valid final server notification: {error}"
            ),
            Self::ResponseIdMismatch { expected, actual } => write!(
                formatter,
                "subscriptions/listen response ID {actual:?} did not match request {expected:?}"
            ),
            Self::RemoteError { code, message } => {
                write!(formatter, "subscriptions/listen failed with JSON-RPC {code}: {message}")
            }
            Self::TerminalResult(error) => write!(
                formatter,
                "invalid subscriptions/listen terminal result: {error}"
            ),
            Self::UnexpectedTerminalResult => {
                formatter.write_str("subscriptions/listen received a non-listen terminal result")
            }
            Self::TerminalIdMismatch { expected, actual } => write!(
                formatter,
                "subscriptions/listen terminal ID {actual:?} did not match request {expected:?}"
            ),
            Self::TerminalBeforeAcknowledgement => {
                formatter.write_str("subscriptions/listen terminated before acknowledgement")
            }
            Self::DuplicateAcknowledgement => {
                formatter.write_str("subscriptions/listen received a duplicate acknowledgement")
            }
            Self::AcknowledgementMissingId => {
                formatter.write_str("subscriptions/listen acknowledgement is missing its subscription ID")
            }
            Self::AcknowledgementInvalidId => formatter
                .write_str("subscriptions/listen acknowledgement has an invalid subscription ID"),
            Self::AcknowledgementIdMismatch { expected, actual } => write!(
                formatter,
                "subscriptions/listen acknowledgement ID {actual:?} did not match request {expected:?}"
            ),
            Self::AcknowledgementFilterNotRequested { category } => write!(
                formatter,
                "subscriptions/listen acknowledgement accepted unrequested {category} notifications"
            ),
            Self::AcknowledgementResourceFilterNotRequested => formatter.write_str(
                "subscriptions/listen acknowledgement accepted unrequested resource update notifications",
            ),
            Self::AcknowledgementExtensionFilterNotRequested => formatter.write_str(
                "subscriptions/listen acknowledgement accepted an unrequested extension filter",
            ),
            Self::EventBeforeAcknowledgement => formatter
                .write_str("subscriptions/listen received a subscription event before acknowledgement"),
            Self::EventOutsideAcceptedFilter => formatter
                .write_str("subscriptions/listen received an event outside its accepted filter"),
            Self::CancellationIdMismatch { expected, actual } => write!(
                formatter,
                "subscriptions/listen cancellation ID {actual:?} did not match request {expected:?}"
            ),
            Self::Cancelled { request_id } => write!(
                formatter,
                "subscriptions/listen request {request_id:?} was cancelled by the server"
            ),
            Self::EndOfStream { .. } => formatter.write_str(
                "subscriptions/listen SSE reached EOF before terminal complete result",
            ),
        }
    }
}

impl std::error::Error for ModernHttpSubscriptionListenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::Executor(error) => Some(error),
            Self::JsonRpcAdmission(error) => Some(error),
            Self::NotificationAdmission(error) => Some(error),
            Self::TerminalResult(error) => Some(error),
            Self::InvalidRequestId
            | Self::ResponseIdMismatch { .. }
            | Self::RemoteError { .. }
            | Self::UnexpectedTerminalResult
            | Self::TerminalIdMismatch { .. }
            | Self::TerminalBeforeAcknowledgement
            | Self::DuplicateAcknowledgement
            | Self::AcknowledgementMissingId
            | Self::AcknowledgementInvalidId
            | Self::AcknowledgementIdMismatch { .. }
            | Self::AcknowledgementFilterNotRequested { .. }
            | Self::AcknowledgementResourceFilterNotRequested
            | Self::AcknowledgementExtensionFilterNotRequested
            | Self::EventBeforeAcknowledgement
            | Self::EventOutsideAcceptedFilter
            | Self::CancellationIdMismatch { .. }
            | Self::Cancelled { .. }
            | Self::EndOfStream { .. } => None,
        }
    }
}

fn final_subscriptions_listen_core_request(
    requested: &SubscriptionFilter,
) -> Result<CoreRequest, ModernHttpSubscriptionListenError> {
    let parameters = serde_json::json!({
        "_meta": FinalRequestMeta::new(ClientCapabilities::default()),
        "notifications": requested,
    });
    CoreRequest::decode(
        ProtocolEra::Modern2026,
        SUBSCRIPTIONS_LISTEN,
        Some(&parameters),
    )
    .map_err(ModernHttpSubscriptionListenError::TerminalResult)
}

fn collect_final_subscriptions_terminal(
    core_request: &CoreRequest,
    response: JsonRpcResponse,
    expected_id: RequestId,
    accepted_filter: Option<SubscriptionFilter>,
    notifications: Vec<ServerNotification>,
) -> Result<ModernHttpSubscriptionListenCollector, ModernHttpSubscriptionListenError> {
    if response.id.as_ref() != Some(&expected_id) {
        return Err(ModernHttpSubscriptionListenError::ResponseIdMismatch {
            expected: expected_id,
            actual: response.id,
        });
    }
    if let Some(error) = response.error.as_ref() {
        return Err(ModernHttpSubscriptionListenError::RemoteError {
            code: error.code,
            message: error.message.clone(),
        });
    }
    let result = core_request
        .decode_response(&response)
        .map_err(ModernHttpSubscriptionListenError::TerminalResult)?;
    let CoreResult::Final(FinalCoreResult::SubscriptionsListen {
        result: terminal,
        subscription_id,
        ..
    }) = result
    else {
        return Err(ModernHttpSubscriptionListenError::UnexpectedTerminalResult);
    };
    if subscription_id != expected_id {
        return Err(ModernHttpSubscriptionListenError::TerminalIdMismatch {
            expected: expected_id,
            actual: subscription_id,
        });
    }
    let Some(accepted_filter) = accepted_filter else {
        return Err(ModernHttpSubscriptionListenError::TerminalBeforeAcknowledgement);
    };
    Ok(ModernHttpSubscriptionListenCollector {
        subscription_id,
        accepted_filter,
        notifications,
        terminal,
    })
}

fn validate_http_subscription_acknowledgement(
    expected_id: &RequestId,
    requested: &SubscriptionFilter,
    acknowledgement: &FinalSubscriptionsAcknowledgedNotificationParams,
) -> Result<(), ModernHttpSubscriptionListenError> {
    let subscription_id = acknowledgement
        .meta
        .as_ref()
        .and_then(|metadata| metadata.get(FINAL_SUBSCRIPTION_ID_META_KEY))
        .ok_or(ModernHttpSubscriptionListenError::AcknowledgementMissingId)
        .and_then(|value| {
            serde_json::from_value::<RequestId>(value.clone())
                .map_err(|_| ModernHttpSubscriptionListenError::AcknowledgementInvalidId)
        })?;
    if &subscription_id != expected_id {
        return Err(
            ModernHttpSubscriptionListenError::AcknowledgementIdMismatch {
                expected: expected_id.clone(),
                actual: subscription_id,
            },
        );
    }
    validate_http_subscription_acknowledgement_filter(requested, &acknowledgement.notifications)
}

fn validate_http_subscription_acknowledgement_filter(
    requested: &SubscriptionFilter,
    acknowledged: &SubscriptionFilter,
) -> Result<(), ModernHttpSubscriptionListenError> {
    for (category, requested, acknowledged) in [
        (
            "prompts/list_changed",
            requested.prompts_list_changed,
            acknowledged.prompts_list_changed,
        ),
        (
            "resources/list_changed",
            requested.resources_list_changed,
            acknowledged.resources_list_changed,
        ),
        (
            "tools/list_changed",
            requested.tools_list_changed,
            acknowledged.tools_list_changed,
        ),
    ] {
        match acknowledged {
            None => {}
            Some(true) if requested == Some(true) => {}
            Some(_) => {
                return Err(
                    ModernHttpSubscriptionListenError::AcknowledgementFilterNotRequested {
                        category,
                    },
                );
            }
        }
    }

    if let Some(acknowledged_uris) = &acknowledged.resource_subscriptions {
        let Some(requested_uris) = &requested.resource_subscriptions else {
            return Err(
                ModernHttpSubscriptionListenError::AcknowledgementResourceFilterNotRequested,
            );
        };
        for (index, uri) in acknowledged_uris.iter().enumerate() {
            if !requested_uris
                .iter()
                .any(|requested_uri| requested_uri == uri)
                || acknowledged_uris[..index]
                    .iter()
                    .any(|previous_uri| previous_uri == uri)
            {
                return Err(
                    ModernHttpSubscriptionListenError::AcknowledgementResourceFilterNotRequested,
                );
            }
        }
    }

    if acknowledged.additional.iter().any(|(name, value)| {
        requested
            .additional
            .get(name)
            .is_none_or(|requested_value| requested_value != value)
    }) {
        return Err(ModernHttpSubscriptionListenError::AcknowledgementExtensionFilterNotRequested);
    }

    Ok(())
}

fn validate_http_subscription_notification_filter(
    notification: &ServerNotification,
    accepted_filter: &SubscriptionFilter,
) -> Result<(), ModernHttpSubscriptionListenError> {
    let accepted = match notification {
        ServerNotification::ResourcesListChanged(_) => {
            accepted_filter.resources_list_changed == Some(true)
        }
        ServerNotification::ToolsListChanged(_) => accepted_filter.tools_list_changed == Some(true),
        ServerNotification::PromptsListChanged(_) => {
            accepted_filter.prompts_list_changed == Some(true)
        }
        ServerNotification::ResourceUpdated(update) => accepted_filter
            .resource_subscriptions
            .as_ref()
            .is_some_and(|uris| uris.iter().any(|uri| uri == update.uri.as_str())),
        ServerNotification::Cancelled(_)
        | ServerNotification::Progress(_)
        | ServerNotification::Message(_)
        | ServerNotification::SubscriptionsAcknowledged(_) => false,
    };
    if accepted {
        Ok(())
    } else {
        Err(ModernHttpSubscriptionListenError::EventOutsideAcceptedFilter)
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

/// A connected client HTTP transport selected by its immutable protocol plan.
///
/// Auto performs the modern probe and, only for an authorized refusal, opens
/// the exact configured legacy SSE route. Callers use one connection and
/// request method; they do not classify the probe result themselves.
pub enum ClientHttpConnection {
    /// Stateless MCP 2026-07-28 POST transport.
    Modern(ModernHttpClient),
    /// Exact MCP 2024-11-05 SSE plus message POST transport.
    LegacySse(LegacySseHttpClient),
}

/// One response returned through `ClientHttpConnection::request`.
pub enum ClientHttpResponse {
    /// The still-live HTTP response from a stateless modern POST.
    Modern(ModernHttpResponseStream),
    /// One strict JSON-RPC response received over the exact legacy SSE stream.
    Legacy(JsonRpcMessage),
}

/// Errors raised by the unified client HTTP connection and request surface.
#[derive(Debug)]
pub enum ClientHttpConnectionError {
    /// Connection selection, modern request construction, or modern execution failed.
    Modern(ModernHttpClientError),
    /// Exact legacy SSE setup, message POST, or stream decoding failed.
    Legacy(LegacySseHttpClientError),
    /// The exact legacy SSE stream ended before the correlated response arrived.
    LegacyResponseStreamEnded { request_id: RequestId },
    /// The exact legacy stream emitted an envelope other than the correlated response.
    LegacyUnexpectedMessage { request_id: RequestId },
    /// The exact legacy stream emitted a response for a different request.
    LegacyResponseIdMismatch {
        expected: RequestId,
        actual: Option<RequestId>,
    },
    /// Final `subscriptions/listen` requires the modern HTTP transport.
    SubscriptionsListenRequiresModern,
    /// A modern subscription response stream failed typed admission or collection.
    SubscriptionsListen(ModernHttpSubscriptionListenError),
}

impl fmt::Display for ClientHttpConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Modern(error) => error.fmt(formatter),
            Self::Legacy(error) => error.fmt(formatter),
            Self::LegacyResponseStreamEnded { request_id } => {
                write!(
                    formatter,
                    "legacy SSE ended before response {request_id:?} arrived"
                )
            }
            Self::LegacyUnexpectedMessage { request_id } => {
                write!(
                    formatter,
                    "legacy SSE emitted a non-response while waiting for {request_id:?}"
                )
            }
            Self::LegacyResponseIdMismatch { expected, actual } => {
                write!(
                    formatter,
                    "legacy SSE response ID {actual:?} did not match request {expected:?}"
                )
            }
            Self::SubscriptionsListenRequiresModern => {
                formatter.write_str("subscriptions/listen requires the modern HTTP transport")
            }
            Self::SubscriptionsListen(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ClientHttpConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Modern(error) => Some(error),
            Self::Legacy(error) => Some(error),
            Self::LegacyResponseStreamEnded { .. }
            | Self::LegacyUnexpectedMessage { .. }
            | Self::LegacyResponseIdMismatch { .. }
            | Self::SubscriptionsListenRequiresModern => None,
            Self::SubscriptionsListen(error) => Some(error),
        }
    }
}

impl ClientHttpConnection {
    /// Connects using the selected policy without exposing a probe-outcome
    /// classification step to the caller.
    pub async fn connect(
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
    ) -> Result<Self, ClientHttpConnectionError> {
        match ModernHttpClient::connect(cx, protocol_plan, client_info, client_capabilities)
            .await
            .map_err(ClientHttpConnectionError::Modern)?
        {
            ModernHttpConnectOutcome::Modern(client) => Ok(Self::Modern(client)),
            ModernHttpConnectOutcome::LegacySse(client) => Ok(Self::LegacySse(client)),
        }
    }

    /// Returns the era admitted by this completed connection.
    #[must_use]
    pub const fn selected_protocol_era(&self) -> ProtocolEra {
        match self {
            Self::Modern(_) => ProtocolEra::Modern2026,
            Self::LegacySse(_) => ProtocolEra::Legacy2024,
        }
    }

    /// Returns the immutable policy and endpoint bundle used for this connection.
    #[must_use]
    pub const fn protocol_plan(&self) -> &ClientProtocolPlan {
        match self {
            Self::Modern(client) => client.protocol_plan(),
            Self::LegacySse(client) => client.protocol_plan(),
        }
    }

    /// Sends one active client request through the selected transport.
    ///
    /// Modern requests execute as one stateless final POST. Exact legacy
    /// requests are posted to the pinned endpoint and then require the next
    /// SSE envelope to be the response with this exact request ID.
    pub async fn request(
        &mut self,
        cx: &Cx,
        method: impl AsRef<str>,
        parameters: serde_json::Value,
        request_id: RequestId,
    ) -> Result<ClientHttpResponse, ClientHttpConnectionError> {
        let method = method.as_ref();
        match self {
            Self::Modern(client) => client
                .request(cx, method, parameters, Some(request_id))
                .await
                .map(ClientHttpResponse::Modern)
                .map_err(ClientHttpConnectionError::Modern),
            Self::LegacySse(client) => {
                let request = JsonRpcRequest::new(method, Some(parameters), request_id.clone());
                client
                    .send(cx, &JsonRpcMessage::Request(request))
                    .await
                    .map_err(ClientHttpConnectionError::Legacy)?;
                let message = client
                    .next_message(cx)
                    .await
                    .map_err(ClientHttpConnectionError::Legacy)?;
                let message = message.ok_or_else(|| {
                    ClientHttpConnectionError::LegacyResponseStreamEnded {
                        request_id: request_id.clone(),
                    }
                })?;
                let JsonRpcMessage::Response(response) = &message else {
                    return Err(ClientHttpConnectionError::LegacyUnexpectedMessage { request_id });
                };
                if response.id.as_ref() != Some(&request_id) {
                    return Err(ClientHttpConnectionError::LegacyResponseIdMismatch {
                        expected: request_id,
                        actual: response.id.clone(),
                    });
                }
                Ok(ClientHttpResponse::Legacy(message))
            }
        }
    }

    /// Opens and consumes one typed final `subscriptions/listen` HTTP stream.
    ///
    /// This operation is unavailable once the immutable connection plan has
    /// selected exact MCP 2024-11-05. Modern streams require one explicit SSE
    /// parser bound so the caller, rather than ambient transport state, fixes
    /// response framing limits.
    pub async fn listen_subscriptions_typed(
        &self,
        cx: &Cx,
        request_id: RequestId,
        notifications: SubscriptionFilter,
        limits: SseLimits,
    ) -> Result<ModernHttpSubscriptionListenCollector, ClientHttpConnectionError> {
        match self {
            Self::Modern(client) => client
                .listen_subscriptions_typed(cx, request_id, notifications, limits)
                .await
                .map_err(ClientHttpConnectionError::SubscriptionsListen),
            Self::LegacySse(_) => Err(ClientHttpConnectionError::SubscriptionsListenRequiresModern),
        }
    }

    /// Sends one client notification through the selected transport.
    ///
    /// Exact legacy notifications are posted to the pinned message endpoint
    /// without an ID. Modern notifications retain their stateless final POST
    /// contract and consume their finite HTTP acknowledgement before returning.
    pub async fn notify(
        &mut self,
        cx: &Cx,
        method: impl AsRef<str>,
        parameters: Option<serde_json::Value>,
    ) -> Result<(), ClientHttpConnectionError> {
        let method = method.as_ref();
        match self {
            Self::Modern(client) => {
                let response = client
                    .request(
                        cx,
                        method,
                        parameters.unwrap_or_else(|| serde_json::json!({})),
                        None,
                    )
                    .await
                    .map_err(ClientHttpConnectionError::Modern)?;
                response
                    .read_to_end(cx, MAX_MODERN_HTTP_PROBE_BODY_BYTES)
                    .await
                    .map_err(|error| {
                        ClientHttpConnectionError::Modern(ModernHttpClientError::Executor(error))
                    })?;
                Ok(())
            }
            Self::LegacySse(client) => client
                .send(
                    cx,
                    &JsonRpcMessage::Request(JsonRpcRequest::notification(method, parameters)),
                )
                .await
                .map_err(ClientHttpConnectionError::Legacy),
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

    /// Opens and consumes one typed final `subscriptions/listen` HTTP stream.
    ///
    /// The request is emitted with the same immutable final metadata as every
    /// other modern HTTP request. The returned collector contains the exact
    /// acknowledgement filter, ordered typed notifications, and complete
    /// terminal result only after every stream frame passes strict admission.
    pub async fn listen_subscriptions_typed(
        &self,
        cx: &Cx,
        request_id: RequestId,
        notifications: SubscriptionFilter,
        limits: SseLimits,
    ) -> Result<ModernHttpSubscriptionListenCollector, ModernHttpSubscriptionListenError> {
        if request_id.validate().is_err() {
            return Err(ModernHttpSubscriptionListenError::InvalidRequestId);
        }
        let response = self
            .request(
                cx,
                SUBSCRIPTIONS_LISTEN,
                serde_json::json!({ "notifications": notifications.clone() }),
                Some(request_id.clone()),
            )
            .await
            .map_err(ModernHttpSubscriptionListenError::Request)?;
        response
            .collect_final_subscriptions_listen(cx, request_id, notifications, limits)
            .await
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
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use asupersync::Cx;
    use asupersync::runtime::RuntimeBuilder;
    use fastmcp_protocol::{RequestId, ServerNotification, SubscriptionFilter};

    use super::{
        ClientHttpConnectionError, ClientHttpResponse, LegacySseHttpClientError,
        MAX_IGNORED_RESPONSE_CONTENT_ENCODING_EMPTY_ELEMENTS, ModernHttpClientError,
        ModernHttpExecutorError, ModernHttpResponseKind, ModernHttpSubscriptionListenError,
        decode_modern_discovery_response, validate_response_head,
    };
    use crate::sse::SseLimits;
    use crate::{CanonicalHttpUrl, ClientBuilder, ClientProtocolPlan, ProtocolEra, ProtocolPolicy};

    #[derive(Debug)]
    struct CapturedHttpRequest {
        head: String,
        body: Vec<u8>,
    }

    fn runtime_block_on<F: std::future::Future>(future: F) -> F::Output {
        RuntimeBuilder::current_thread()
            .build()
            .expect("native HTTP test runtime must build")
            .block_on(future)
    }

    fn plan(
        modern_target: &str,
        legacy_sse_target: &str,
        legacy_message_target: &str,
        policy: ProtocolPolicy,
    ) -> ClientProtocolPlan {
        let modern_target =
            CanonicalHttpUrl::parse(modern_target).expect("local modern target must be canonical");
        let legacy_sse = CanonicalHttpUrl::parse(legacy_sse_target)
            .expect("local legacy SSE target must be canonical");
        let legacy_message = CanonicalHttpUrl::parse(legacy_message_target)
            .expect("local legacy message target must be canonical");
        ClientProtocolPlan::http(
            policy,
            (!matches!(policy, ProtocolPolicy::LegacyOnly)).then_some(modern_target),
            (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_sse),
            (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_message),
            "client-http-public-test".to_owned(),
            "client-http-public-test".to_owned(),
            "native-h1-client-test".to_owned(),
            1,
            1,
            0,
        )
        .expect("complete local HTTP plan must be accepted")
    }

    fn read_request(stream: &mut TcpStream) -> CapturedHttpRequest {
        let mut wire = Vec::new();
        let mut buffer = [0_u8; 4096];
        let head_end = loop {
            let read = stream.read(&mut buffer).expect("read native HTTP request");
            assert!(read > 0, "client closed before a complete request arrived");
            wire.extend_from_slice(&buffer[..read]);
            if let Some(position) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let head = std::str::from_utf8(&wire[..head_end])
            .expect("request head must be UTF-8")
            .to_owned();
        let content_length = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .map(|value| {
                value
                    .parse::<usize>()
                    .expect("Content-Length must be numeric")
            })
            .unwrap_or(0);
        while wire.len() < head_end.saturating_add(content_length) {
            let read = stream
                .read(&mut buffer)
                .expect("read native HTTP request body");
            assert!(read > 0, "client closed before its advertised body arrived");
            wire.extend_from_slice(&buffer[..read]);
        }
        CapturedHttpRequest {
            head,
            body: wire[head_end..head_end + content_length].to_vec(),
        }
    }

    fn write_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
        let reason = match status {
            200 => "OK",
            202 => "Accepted",
            404 => "Not Found",
            _ => "Test Response",
        };
        write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("write native HTTP response head");
        stream
            .write_all(body)
            .expect("write native HTTP response body");
        stream.flush().expect("flush native HTTP response");
    }

    fn begin_chunked_sse(stream: &mut TcpStream) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
        )
        .expect("write chunked legacy SSE response head");
        stream
            .flush()
            .expect("flush chunked legacy SSE response head");
    }

    fn write_chunked_sse_event(stream: &mut TcpStream, event: &str) {
        write!(stream, "{:X}\r\n{event}\r\n", event.len()).expect("write chunked legacy SSE event");
        stream.flush().expect("flush chunked legacy SSE event");
    }

    fn finish_chunked_sse(stream: &mut TcpStream) {
        stream
            .write_all(b"0\r\n\r\n")
            .expect("finish chunked legacy SSE response");
        stream
            .flush()
            .expect("flush finished chunked legacy SSE response");
    }

    fn modern_discovery_body() -> &'static [u8] {
        br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#
    }

    fn subscriptions_listen_sse_events(acknowledgement_id: i64) -> [String; 4] {
        [
            format!(
                "data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/subscriptions/acknowledged\",\"params\":{{\"_meta\":{{\"io.modelcontextprotocol/subscriptionId\":{acknowledgement_id}}},\"notifications\":{{\"toolsListChanged\":true,\"promptsListChanged\":true}}}}}}\n\n"
            ),
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n".to_owned(),
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/prompts/list_changed\"}\n\n".to_owned(),
            "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"resultType\":\"complete\",\"_meta\":{\"io.modelcontextprotocol/subscriptionId\":2}}}\n\n".to_owned(),
        ]
    }

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

    #[test]
    fn public_http_connection_auto_selects_modern_and_issues_a_stateless_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local modern listener");
        let address = listener.local_addr().expect("read local modern address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern probe");
            let probe_request = read_request(&mut probe);
            assert!(probe_request.head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert!(
                probe_request
                    .head
                    .contains("MCP-Protocol-Version: 2026-07-28\r\n")
            );
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("modern probe must be JSON-RPC")["method"],
                "server/discover"
            );
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            let (mut stream, _) = listener.accept().expect("accept modern request");
            let request = read_request(&mut stream);
            assert!(request.head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert!(
                request
                    .head
                    .contains("MCP-Protocol-Version: 2026-07-28\r\n")
            );
            let body = serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("modern request must be JSON-RPC");
            assert_eq!(body["method"], "ping");
            assert_eq!(
                body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
                "2026-07-28"
            );
            write_response(
                &mut stream,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete"}}"#,
            );
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(
            ClientBuilder::new()
                .client_info("public-http-client", "1.0.0")
                .protocol_plan(plan(
                    &modern_target,
                    "http://127.0.0.1:9/legacy-sse",
                    "http://127.0.0.1:9/legacy-message",
                    ProtocolPolicy::Auto,
                ))
                .connect_http_with_cx(&cx),
        )
        .expect("recognized modern discovery selects the public HTTP connection");
        assert_eq!(connection.selected_protocol_era(), ProtocolEra::Modern2026);

        let response = runtime_block_on(connection.request(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(2),
        ))
        .expect("the public HTTP request path retains the selected modern transport");
        let ClientHttpResponse::Modern(response) = response else {
            panic!("Auto modern selection must not open the legacy stream");
        };
        let body = runtime_block_on(response.read_to_end(&cx, 4_096))
            .expect("modern JSON response remains readable");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)
                .expect("modern response is JSON-RPC")["result"]["resultType"],
            "complete"
        );
        server.join().expect("local modern server must join");
    }

    #[test]
    fn public_http_modern_subscriptions_listen_collects_ordered_typed_notifications() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind local final subscriptions/listen listener");
        let address = listener
            .local_addr()
            .expect("read local final subscriptions/listen address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("modern probe must be JSON-RPC")["method"],
                "server/discover"
            );
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            let (mut stream, _) = listener
                .accept()
                .expect("accept final subscriptions/listen request");
            let request = read_request(&mut stream);
            assert!(request.head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert!(
                request
                    .head
                    .contains("Mcp-Method: subscriptions/listen\r\n")
            );
            let body = serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("subscriptions/listen request must be JSON-RPC");
            assert_eq!(body["id"], 2);
            assert_eq!(body["method"], "subscriptions/listen");
            assert_eq!(
                body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
                "2026-07-28"
            );
            assert_eq!(body["params"]["notifications"]["toolsListChanged"], true);
            assert_eq!(body["params"]["notifications"]["promptsListChanged"], true);

            begin_chunked_sse(&mut stream);
            for event in subscriptions_listen_sse_events(2) {
                write_chunked_sse_event(&mut stream, &event);
            }
            finish_chunked_sse(&mut stream);
        });

        let cx = Cx::for_request();
        let connection = runtime_block_on(
            ClientBuilder::new()
                .client_info("public-http-client", "1.0.0")
                .protocol_plan(plan(
                    &modern_target,
                    "http://127.0.0.1:9/legacy-sse",
                    "http://127.0.0.1:9/legacy-message",
                    ProtocolPolicy::ModernOnly,
                ))
                .connect_http_with_cx(&cx),
        )
        .expect("modern discovery selects final HTTP subscriptions/listen");
        let collector = runtime_block_on(connection.listen_subscriptions_typed(
            &cx,
            RequestId::Number(2),
            SubscriptionFilter {
                tools_list_changed: Some(true),
                prompts_list_changed: Some(true),
                ..SubscriptionFilter::default()
            },
            SseLimits::new(1_024, 8_192, 16).expect("explicit SSE bounds are nonzero"),
        ))
        .expect("typed final HTTP listener admits acknowledgement, ordered events, and terminal");

        assert_eq!(collector.subscription_id, RequestId::Number(2));
        assert_eq!(collector.accepted_filter.tools_list_changed, Some(true));
        assert_eq!(collector.accepted_filter.prompts_list_changed, Some(true));
        assert!(matches!(
            collector.notifications.as_slice(),
            [
                ServerNotification::ToolsListChanged(None),
                ServerNotification::PromptsListChanged(None)
            ]
        ));
        assert!(matches!(
            collector.terminal.payload,
            fastmcp_protocol::FinalSubscriptionsListenResult {}
        ));
        server
            .join()
            .expect("final subscriptions/listen server must join");
    }

    #[test]
    fn public_http_modern_subscriptions_listen_rejects_one_field_acknowledgement_id_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind local malformed final subscriptions/listen listener");
        let address = listener
            .local_addr()
            .expect("read local malformed final subscriptions/listen address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("modern probe must be JSON-RPC")["method"],
                "server/discover"
            );
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            let (mut stream, _) = listener
                .accept()
                .expect("accept final subscriptions/listen request");
            let request = read_request(&mut stream);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&request.body)
                    .expect("subscriptions/listen request must be JSON-RPC")["method"],
                "subscriptions/listen"
            );
            begin_chunked_sse(&mut stream);
            // This differs from the admitted stream only in the acknowledgement ID.
            for event in subscriptions_listen_sse_events(3) {
                write_chunked_sse_event(&mut stream, &event);
            }
            finish_chunked_sse(&mut stream);
        });

        let cx = Cx::for_request();
        let connection = runtime_block_on(
            ClientBuilder::new()
                .client_info("public-http-client", "1.0.0")
                .protocol_plan(plan(
                    &modern_target,
                    "http://127.0.0.1:9/legacy-sse",
                    "http://127.0.0.1:9/legacy-message",
                    ProtocolPolicy::ModernOnly,
                ))
                .connect_http_with_cx(&cx),
        )
        .expect("modern discovery selects final HTTP subscriptions/listen");
        let error = runtime_block_on(connection.listen_subscriptions_typed(
            &cx,
            RequestId::Number(2),
            SubscriptionFilter {
                tools_list_changed: Some(true),
                prompts_list_changed: Some(true),
                ..SubscriptionFilter::default()
            },
            SseLimits::new(1_024, 8_192, 16).expect("explicit SSE bounds are nonzero"),
        ))
        .expect_err("only the acknowledgement subscription ID differs from the admitted stream");
        assert!(matches!(
            error,
            ClientHttpConnectionError::SubscriptionsListen(
                ModernHttpSubscriptionListenError::AcknowledgementIdMismatch {
                    expected: RequestId::Number(2),
                    actual: RequestId::Number(3),
                }
            )
        ));
        server
            .join()
            .expect("malformed final subscriptions/listen server must join");
    }

    #[test]
    fn public_http_connection_legacy_only_posts_and_reads_exact_sse_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local legacy listener");
        let address = listener.local_addr().expect("read local legacy address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let server = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept legacy SSE GET");
            let sse_request = read_request(&mut sse);
            assert!(sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            let sse_body = format!(
                "event: endpoint\ndata: {advertised_message_target}\n\nevent: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{}}}}\n\n"
            );
            write_response(&mut sse, 200, "text/event-stream", sse_body.as_bytes());

            let (mut message_post, _) = listener.accept().expect("accept legacy message POST");
            let message_request = read_request(&mut message_post);
            assert!(
                message_request
                    .head
                    .starts_with("POST /legacy-message HTTP/1.1\r\n")
            );
            assert!(
                !message_request
                    .head
                    .contains("MCP-Protocol-Version: 2026-07-28\r\n")
            );
            let message = serde_json::from_slice::<serde_json::Value>(&message_request.body)
                .expect("legacy message POST must contain JSON-RPC");
            assert_eq!(message["method"], "ping");
            assert!(message["params"].get("_meta").is_none());
            write_response(&mut message_post, 202, "application/json", b"");
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(
            ClientBuilder::new()
                .protocol_plan(plan(
                    "http://127.0.0.1:9/mcp",
                    &sse_target,
                    &message_target,
                    ProtocolPolicy::LegacyOnly,
                ))
                .connect_http_with_cx(&cx),
        )
        .expect("legacy-only opens the exact configured SSE route");
        assert_eq!(connection.selected_protocol_era(), ProtocolEra::Legacy2024);

        let response = runtime_block_on(connection.request(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(2),
        ))
        .expect("legacy request posts then waits for its exact SSE response");
        let ClientHttpResponse::Legacy(message) = response else {
            panic!("legacy-only must not issue a final stateless POST");
        };
        let fastmcp_protocol::JsonRpcMessage::Response(response) = message else {
            panic!("legacy SSE must return a JSON-RPC response");
        };
        assert_eq!(response.id, Some(RequestId::Number(2)));
        server.join().expect("local legacy server must join");
    }

    #[test]
    fn public_http_connection_auto_falls_back_to_fresh_exact_legacy_lifecycle() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local Auto fallback listener");
        let address = listener
            .local_addr()
            .expect("read local Auto fallback address");
        let modern_target = format!("http://{address}/mcp");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept disposable modern probe");
            let probe_request = read_request(&mut probe);
            assert!(probe_request.head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert!(
                probe_request
                    .head
                    .contains("MCP-Protocol-Version: 2026-07-28\r\n")
            );
            write_response(&mut probe, 404, "text/plain", b"");

            let (mut sse, _) = listener.accept().expect("accept fresh legacy SSE GET");
            let sse_request = read_request(&mut sse);
            assert!(sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            assert!(
                !sse_request.head.contains("MCP-Protocol-Version:"),
                "the fresh exact legacy SSE GET must not retain final headers"
            );
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            let (mut initialize_post, _) = listener
                .accept()
                .expect("accept exact legacy initialize POST");
            let initialize_request = read_request(&mut initialize_post);
            assert!(
                initialize_request
                    .head
                    .starts_with("POST /legacy-message HTTP/1.1\r\n")
            );
            assert!(
                !initialize_request
                    .head
                    .contains("MCP-Protocol-Version: 2026-07-28\r\n")
            );
            let initialize = serde_json::from_slice::<serde_json::Value>(&initialize_request.body)
                .expect("legacy initialize POST must be JSON-RPC");
            assert_eq!(initialize["id"], 2);
            assert_eq!(initialize["method"], "initialize");
            assert_eq!(initialize["params"]["protocolVersion"], "2024-11-05");
            assert!(initialize["params"].get("_meta").is_none());
            write_response(&mut initialize_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-server\",\"version\":\"1.0.0\"}}}\n\n",
            );
            finish_chunked_sse(&mut sse);

            let (mut initialized_post, _) = listener
                .accept()
                .expect("accept exact legacy initialized notification");
            let initialized_request = read_request(&mut initialized_post);
            let initialized =
                serde_json::from_slice::<serde_json::Value>(&initialized_request.body)
                    .expect("legacy initialized notification must be JSON-RPC");
            assert_eq!(initialized["method"], "notifications/initialized");
            assert!(initialized.get("id").is_none());
            assert!(initialized.get("params").is_none());
            assert!(
                !initialized_request
                    .head
                    .contains("MCP-Protocol-Version: 2026-07-28\r\n")
            );
            write_response(&mut initialized_post, 202, "application/json", b"");
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(
            ClientBuilder::new()
                .client_info("public-http-client", "1.0.0")
                .protocol_plan(plan(
                    &modern_target,
                    &sse_target,
                    &message_target,
                    ProtocolPolicy::Auto,
                ))
                .connect_http_with_cx(&cx),
        )
        .expect("the recognized modern refusal opens the exact fresh legacy transport");
        assert_eq!(connection.selected_protocol_era(), ProtocolEra::Legacy2024);

        let response = runtime_block_on(connection.request(
            &cx,
            "initialize",
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "public-http-client", "version": "1.0.0" },
            }),
            RequestId::Number(2),
        ))
        .expect(
            "Auto fallback posts exact legacy initialize then awaits its correlated SSE response",
        );
        let ClientHttpResponse::Legacy(message) = response else {
            panic!("recognized modern refusal must keep the public connection on legacy SSE");
        };
        let fastmcp_protocol::JsonRpcMessage::Response(response) = message else {
            panic!("the buffered exact legacy lifecycle reply must be JSON-RPC");
        };
        assert_eq!(response.id, Some(RequestId::Number(2)));

        runtime_block_on(connection.notify(&cx, "notifications/initialized", None))
            .expect("the public fallback path sends the exact id-free lifecycle notification");
        server.join().expect("Auto fallback server must join");
    }

    #[test]
    fn public_http_connection_auto_rejects_only_a_contradictory_legacy_endpoint() {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind local contradictory peer listener");
        let address = listener
            .local_addr()
            .expect("read local contradictory peer address");
        let modern_target = format!("http://{address}/mcp");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let contradictory_target = format!("http://{address}/other-message");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept disposable modern probe");
            let probe_request = read_request(&mut probe);
            assert!(probe_request.head.starts_with("POST /mcp HTTP/1.1\r\n"));
            write_response(&mut probe, 404, "text/plain", b"");

            let (mut sse, _) = listener.accept().expect("accept authorized legacy SSE GET");
            let sse_request = read_request(&mut sse);
            assert!(sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            let sse_body = format!("event: endpoint\ndata: {contradictory_target}\n\n");
            write_response(&mut sse, 200, "text/event-stream", sse_body.as_bytes());
        });

        let cx = Cx::for_request();
        let error = runtime_block_on(
            ClientBuilder::new()
                .protocol_plan(plan(
                    &modern_target,
                    &sse_target,
                    &message_target,
                    ProtocolPolicy::Auto,
                ))
                .connect_http_with_cx(&cx),
        )
        .err()
        .expect("only the advertised POST target differs from the configured legacy plan");
        assert!(matches!(
            error,
            ClientHttpConnectionError::Modern(ModernHttpClientError::LegacySse(
                LegacySseHttpClientError::AdvertisedMessagePostTargetMismatch { .. }
            ))
        ));
        server.join().expect("contradictory peer server must join");
    }
}
