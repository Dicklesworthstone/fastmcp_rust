//! Native modern HTTP request and response-stream execution.
//!
//! This module owns modern MCP POST execution, disposable first-probe
//! negotiation, and the public response stream surface. It neither retries an
//! MCP request nor follows redirects.

use std::collections::{BTreeMap, VecDeque};
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
use fastmcp_protocol::extensions::{
    McpAppsClientSettings, OFFICIAL_MCP_APPS_EXTENSION_ID, OFFICIAL_TASKS_RESULT_DISCRIMINATOR,
};
use fastmcp_protocol::methods::{
    Final2026Direction, Final2026EnvelopeKind, PROMPTS_GET, RESOURCES_READ, SUBSCRIPTIONS_LISTEN,
    TOOLS_CALL, final_2026_07_28_method,
};
use fastmcp_protocol::protocol_policy::{
    HttpModernProbe, HttpProbeBody, MODERN_PROTOCOL_VERSION, ProtocolEra, ProtocolPolicy,
};
use fastmcp_protocol::tasks_extension::{
    TASK_STATUS_NOTIFICATION, TASK_SUBSCRIPTION_IDS_KEY,
    TaskStatusNotification as FinalTaskStatusNotification,
};
use fastmcp_protocol::{
    ClientCapabilities, ClientInfo, CompleteResult, CoreDispatchError, CoreRequest, CoreResult,
    FINAL_SUBSCRIPTION_ID_META_KEY, FinalCoreResult, FinalNotificationError, FinalRequestMeta,
    FinalSubscriptionsAcknowledgedNotificationParams, FinalSubscriptionsListenResult,
    JsonRpcAdmissionError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId,
    SERVER_DISCOVER, ServerDiscoverResult, ServerNotification, SubscriptionFilter,
    decode_strict_jsonrpc_message, task_subscription_ids,
};

use crate::session::resolve_mcp_apps_activation;
use crate::sse::{BoundedSseParser, SseEndOfStream, SseLimits, SseParseError};
use crate::{
    ClientHttpNegotiation, ClientHttpNegotiationDecision, ClientHttpNegotiationError,
    ClientProtocolPlan, FinalToolCallOutcome, admit_final_tasks_discovery_surface,
    admit_final_tasks_result_discriminator,
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

/// Maximum server notifications retained while one legacy request waits for
/// its correlated terminal response.
const MAX_QUEUED_LEGACY_NOTIFICATIONS: usize = 64;

/// Final-only metadata keys that exact 2024-11-05 public requests must reject
/// before opening their legacy message POST.
const FINAL_ONLY_LEGACY_REQUEST_METADATA_KEYS: [&str; 5] = [
    "io.modelcontextprotocol/protocolVersion",
    "io.modelcontextprotocol/clientCapabilities",
    "io.modelcontextprotocol/clientInfo",
    "io.modelcontextprotocol/serverInfo",
    "io.modelcontextprotocol/subscriptionId",
];

/// LIMIT-01's default cap for ignored RFC 9110 list elements in one
/// `Content-Encoding` field value.
///
/// Empty elements are framing noise, never semantic content codings. Keeping
/// the count finite prevents a response header from consuming unbounded work
/// before this executor exposes any body bytes.
const MAX_IGNORED_RESPONSE_CONTENT_ENCODING_EMPTY_ELEMENTS: usize = 16;

/// A single modern MCP JSON-RPC POST.
#[derive(Clone, PartialEq, Eq)]
pub struct ModernHttpRequest {
    target: String,
    body: Vec<u8>,
    protocol_version: String,
    method: String,
    name: Option<String>,
    authorization: Option<String>,
}

impl fmt::Debug for ModernHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModernHttpRequest")
            .field("target", &self.target)
            .field("protocol_version", &self.protocol_version)
            .field("method", &self.method)
            .field("name", &self.name)
            .field("body_bytes", &self.body.len())
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
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
            authorization: None,
        })
    }

    /// Attaches the bound bearer credential's `Authorization` header when —
    /// and only when — `target` is canonically identical to the credential's
    /// bound HTTPS resource. Any other target leaves the request
    /// credential-free rather than downgrading or redirecting the token.
    #[must_use]
    pub fn with_authorization(
        mut self,
        credential: &crate::http_auth::BoundBearerCredential,
        target: &fastmcp_core::CanonicalHttpUrl,
    ) -> Self {
        self.authorization = credential.authorization_for_target(target);
        self
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
        if let Some(authorization) = &self.authorization {
            headers.push(("Authorization".to_owned(), authorization.clone()));
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
    /// A content-type-free `202 Accepted` notification acknowledgement whose
    /// body must be checked by the notification caller before it is accepted.
    EmptyAcknowledgement,
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
        let mut task_notifications = Vec::new();

        loop {
            let event = match stream.next_event(cx).await {
                Ok(Some(event)) => event,
                Ok(None) => {
                    return Err(ModernHttpSubscriptionListenError::EndOfStream {
                        framing: stream.end_of_stream(),
                    });
                }
                Err(ModernHttpExecutorError::Cancelled) => {
                    return Err(ModernHttpSubscriptionListenError::CallerCancelled {
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
                        task_notifications,
                    );
                }
                JsonRpcMessage::Request(request) => {
                    if request.id.is_none() && request.method == TASK_STATUS_NOTIFICATION {
                        let Some(accepted_filter) = accepted_filter.as_ref() else {
                            return Err(
                                ModernHttpSubscriptionListenError::EventBeforeAcknowledgement,
                            );
                        };
                        let accepted_task_ids = task_subscription_ids(accepted_filter)
                            .ok()
                            .flatten()
                            .ok_or(ModernHttpSubscriptionListenError::EventOutsideAcceptedFilter)?;
                        let notification: FinalTaskStatusNotification =
                            serde_json::from_slice(event.as_bytes()).map_err(|_| {
                                ModernHttpSubscriptionListenError::TaskNotificationAdmission
                            })?;
                        let subscription_id = notification
                            .params
                            .meta
                            .as_ref()
                            .and_then(|metadata| metadata.get(FINAL_SUBSCRIPTION_ID_META_KEY))
                            .and_then(|value| {
                                serde_json::from_value::<RequestId>(value.clone()).ok()
                            });
                        if subscription_id.as_ref() != Some(&request_id) {
                            return Err(
                                ModernHttpSubscriptionListenError::TaskEventSubscriptionIdMismatch,
                            );
                        }
                        if !accepted_task_ids
                            .iter()
                            .any(|task_id| task_id == &notification.params.task.base().task_id)
                        {
                            return Err(
                                ModernHttpSubscriptionListenError::TaskEventOutsideAcceptedFilter,
                            );
                        }
                        task_notifications.push(notification);
                        continue;
                    }
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
    /// Request-owned typed Tasks events admitted by the exact acknowledged IDs.
    pub task_notifications: Vec<FinalTaskStatusNotification>,
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
    /// The retained discovery response did not bilaterally admit Tasks.
    TasksNegotiation,
    /// The response did not use the required SSE body lane or could not be read.
    Executor(ModernHttpExecutorError),
    /// An SSE event was not one strictly admitted JSON-RPC object.
    JsonRpcAdmission(JsonRpcAdmissionError),
    /// A server request was not one typed final server notification.
    NotificationAdmission(FinalNotificationError),
    /// A `notifications/tasks` event did not match the exact Tasks wire type.
    TaskNotificationAdmission,
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
    /// A Tasks event carried a subscription ID other than this listener's ID.
    TaskEventSubscriptionIdMismatch,
    /// A Tasks event named a task outside the acknowledged exact-ID set.
    TaskEventOutsideAcceptedFilter,
    /// A final cancellation targeted another request instead of this listener.
    CancellationIdMismatch {
        /// The immutable ID assigned to the outgoing listen request.
        expected: RequestId,
        /// The request ID carried by the cancellation notification.
        actual: RequestId,
    },
    /// The caller cancelled this request-owned listener context.
    CallerCancelled { request_id: RequestId },
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
            Self::TasksNegotiation => formatter.write_str(
                "subscriptions/listen Tasks filter was not bilaterally negotiated",
            ),
            Self::Executor(error) => error.fmt(formatter),
            Self::JsonRpcAdmission(error) => write!(
                formatter,
                "subscriptions/listen SSE event failed strict JSON-RPC admission: {error}"
            ),
            Self::NotificationAdmission(error) => write!(
                formatter,
                "subscriptions/listen SSE event was not a valid final server notification: {error}"
            ),
            Self::TaskNotificationAdmission => formatter.write_str(
                "subscriptions/listen SSE event was not a valid Tasks notification",
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
            Self::TaskEventSubscriptionIdMismatch => formatter.write_str(
                "subscriptions/listen Tasks event named a different subscription",
            ),
            Self::TaskEventOutsideAcceptedFilter => formatter.write_str(
                "subscriptions/listen Tasks event was outside its accepted taskIds filter",
            ),
            Self::CancellationIdMismatch { expected, actual } => write!(
                formatter,
                "subscriptions/listen cancellation ID {actual:?} did not match request {expected:?}"
            ),
            Self::CallerCancelled { request_id } => write!(
                formatter,
                "subscriptions/listen request {request_id:?} was cancelled by the caller"
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
            | Self::TasksNegotiation
            | Self::TaskNotificationAdmission
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
            | Self::TaskEventSubscriptionIdMismatch
            | Self::TaskEventOutsideAcceptedFilter
            | Self::CancellationIdMismatch { .. }
            | Self::CallerCancelled { .. }
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
    task_notifications: Vec<FinalTaskStatusNotification>,
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
        task_notifications,
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

    let requested_task_ids = task_subscription_ids(requested).map_err(|_| {
        ModernHttpSubscriptionListenError::AcknowledgementExtensionFilterNotRequested
    })?;
    let acknowledged_task_ids = task_subscription_ids(acknowledged).map_err(|_| {
        ModernHttpSubscriptionListenError::AcknowledgementExtensionFilterNotRequested
    })?;
    match (requested_task_ids.as_ref(), acknowledged_task_ids.as_ref()) {
        (None, Some(_)) => {
            return Err(
                ModernHttpSubscriptionListenError::AcknowledgementExtensionFilterNotRequested,
            );
        }
        (Some(requested), Some(acknowledged)) => {
            for (index, task_id) in acknowledged.iter().enumerate() {
                if !requested.iter().any(|requested| requested == task_id)
                    || acknowledged[..index]
                        .iter()
                        .any(|previous| previous == task_id)
                {
                    return Err(
                        ModernHttpSubscriptionListenError::AcknowledgementExtensionFilterNotRequested,
                    );
                }
            }
        }
        (Some(_), None) | (None, None) => {}
    }

    if acknowledged.additional.iter().any(|(name, value)| {
        name != TASK_SUBSCRIPTION_IDS_KEY
            && requested
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
    mcp_apps_settings: Option<McpAppsClientSettings>,
    mcp_apps_active: bool,
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
    /// A public legacy request attempted to carry final-only metadata.
    LegacyFinalMetadata { member: &'static str },
    /// Too many interleaved legacy notifications accumulated before a response.
    LegacyNotificationQueueFull,
    /// A convenience request expected a finite JSON response but received a
    /// different admitted modern body lane.
    ExpectedJsonResponse { actual: ModernHttpResponseKind },
    /// A convenience request body was not one strictly admitted JSON-RPC
    /// response envelope.
    ResponseAdmission(JsonRpcAdmissionError),
    /// A convenience request received a JSON-RPC request rather than its
    /// correlated response.
    UnexpectedResponseMessage { request_id: RequestId },
    /// A modern convenience response did not retain the caller's request ID.
    ResponseIdMismatch {
        expected: RequestId,
        actual: Option<RequestId>,
    },
    /// A modern notification acknowledgement did not use the required 202
    /// status, so it cannot be treated as an accepted notification.
    ModernNotificationUnexpectedStatus { status: u16 },
    /// A modern notification acknowledgement carried a body rather than the
    /// empty acknowledgement required by the stateless notification surface.
    ModernNotificationUnexpectedBody,
    /// Final `subscriptions/listen` requires the modern HTTP transport.
    SubscriptionsListenRequiresModern,
    /// A modern subscription response stream failed typed admission or collection.
    SubscriptionsListen(ModernHttpSubscriptionListenError),
    /// Final Tasks-backed `tools/call` requires the modern HTTP transport.
    FinalToolCallRequiresModern,
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
            Self::LegacyFinalMetadata { member } => write!(
                formatter,
                "exact legacy request cannot carry final-only metadata member {member}"
            ),
            Self::LegacyNotificationQueueFull => formatter.write_str(
                "legacy request received too many interleaved notifications before its response",
            ),
            Self::ExpectedJsonResponse { actual } => write!(
                formatter,
                "HTTP request expected a JSON response but received {actual:?}"
            ),
            Self::ResponseAdmission(error) => {
                write!(
                    formatter,
                    "HTTP request response failed JSON-RPC admission: {error}"
                )
            }
            Self::UnexpectedResponseMessage { request_id } => write!(
                formatter,
                "HTTP request received a JSON-RPC request while waiting for response {request_id:?}"
            ),
            Self::ResponseIdMismatch { expected, actual } => write!(
                formatter,
                "HTTP response ID {actual:?} did not match request {expected:?}"
            ),
            Self::ModernNotificationUnexpectedStatus { status } => write!(
                formatter,
                "modern HTTP notification acknowledgement used unexpected status {status}"
            ),
            Self::ModernNotificationUnexpectedBody => formatter
                .write_str("modern HTTP notification acknowledgement must have an empty body"),
            Self::SubscriptionsListenRequiresModern => {
                formatter.write_str("subscriptions/listen requires the modern HTTP transport")
            }
            Self::SubscriptionsListen(error) => error.fmt(formatter),
            Self::FinalToolCallRequiresModern => formatter
                .write_str("final Tasks-backed tools/call requires the modern HTTP transport"),
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
            | Self::LegacyFinalMetadata { .. }
            | Self::LegacyNotificationQueueFull
            | Self::ExpectedJsonResponse { .. }
            | Self::UnexpectedResponseMessage { .. }
            | Self::ResponseIdMismatch { .. }
            | Self::ModernNotificationUnexpectedStatus { .. }
            | Self::ModernNotificationUnexpectedBody
            | Self::SubscriptionsListenRequiresModern
            | Self::FinalToolCallRequiresModern => None,
            Self::ResponseAdmission(error) => Some(error),
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
        Self::connect_with_mcp_apps(cx, protocol_plan, client_info, client_capabilities, None).await
    }

    pub(crate) async fn connect_with_mcp_apps(
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        mcp_apps_settings: Option<McpAppsClientSettings>,
    ) -> Result<Self, ClientHttpConnectionError> {
        match ModernHttpClient::connect_with_mcp_apps(
            cx,
            protocol_plan,
            client_info,
            client_capabilities,
            mcp_apps_settings,
        )
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

    /// Returns the exact discovery result that selected the modern era.
    ///
    /// Exact legacy HTTP sessions use `initialize` rather than
    /// `server/discover`, so they deliberately have no counterpart here.
    #[must_use]
    pub fn server_discovery(&self) -> Option<&ServerDiscoverResult> {
        match self {
            Self::Modern(client) => Some(client.server_discovery()),
            Self::LegacySse(_) => None,
        }
    }

    /// Returns whether final discovery activated the official MCP Apps extension.
    #[must_use]
    pub fn mcp_apps_active(&self) -> bool {
        match self {
            Self::Modern(client) => client.mcp_apps_active(),
            Self::LegacySse(_) => false,
        }
    }

    /// Pops the oldest server notification interleaved before a legacy request response.
    ///
    /// Modern stateless HTTP bodies do not share this legacy SSE queue.
    #[must_use]
    pub fn take_legacy_notification(&mut self) -> Option<JsonRpcRequest> {
        match self {
            Self::Modern(_) => None,
            Self::LegacySse(client) => client.take_notification(),
        }
    }

    /// Sends one active client request through the selected transport.
    ///
    /// Modern requests execute as one stateless final POST. Exact legacy
    /// requests are posted to the pinned endpoint, queue interleaved server
    /// notifications, and await the response with this exact request ID.
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
                reject_final_only_legacy_request_metadata(&parameters)?;
                let request = JsonRpcRequest::new(method, Some(parameters), request_id.clone());
                client
                    .send(cx, &JsonRpcMessage::Request(request))
                    .await
                    .map_err(ClientHttpConnectionError::Legacy)?;
                loop {
                    let message = client
                        .next_message(cx)
                        .await
                        .map_err(ClientHttpConnectionError::Legacy)?;
                    let message = message.ok_or_else(|| {
                        ClientHttpConnectionError::LegacyResponseStreamEnded {
                            request_id: request_id.clone(),
                        }
                    })?;
                    match message {
                        JsonRpcMessage::Request(notification) if notification.is_notification() => {
                            client.queue_notification(notification).map_err(|_| {
                                ClientHttpConnectionError::LegacyNotificationQueueFull
                            })?;
                        }
                        JsonRpcMessage::Request(_) => {
                            return Err(ClientHttpConnectionError::LegacyUnexpectedMessage {
                                request_id,
                            });
                        }
                        JsonRpcMessage::Response(response) => {
                            if response.id.as_ref() != Some(&request_id) {
                                return Err(ClientHttpConnectionError::LegacyResponseIdMismatch {
                                    expected: request_id,
                                    actual: response.id,
                                });
                            }
                            return Ok(ClientHttpResponse::Legacy(JsonRpcMessage::Response(
                                response,
                            )));
                        }
                    }
                }
            }
        }
    }

    /// Sends one request and returns its complete, strictly admitted JSON-RPC
    /// response.
    ///
    /// This is the ordinary high-level request surface for callers that do
    /// not need to retain a modern streaming response. It binds the response
    /// ID to `request_id` in both eras. Modern request-scoped SSE remains
    /// available through [`Self::request`].
    pub async fn request_json(
        &mut self,
        cx: &Cx,
        method: impl AsRef<str>,
        parameters: serde_json::Value,
        request_id: RequestId,
        maximum_response_bytes: usize,
    ) -> Result<JsonRpcResponse, ClientHttpConnectionError> {
        let response = self
            .request(cx, method, parameters, request_id.clone())
            .await?;
        match response {
            ClientHttpResponse::Legacy(JsonRpcMessage::Response(response)) => Ok(response),
            ClientHttpResponse::Legacy(JsonRpcMessage::Request(_)) => {
                Err(ClientHttpConnectionError::UnexpectedResponseMessage { request_id })
            }
            ClientHttpResponse::Modern(response) => {
                let kind = response.metadata().kind();
                if !matches!(kind, ModernHttpResponseKind::Json) {
                    return Err(ClientHttpConnectionError::ExpectedJsonResponse { actual: kind });
                }
                let body = response
                    .read_to_end(cx, maximum_response_bytes)
                    .await
                    .map_err(|error| {
                        ClientHttpConnectionError::Modern(ModernHttpClientError::Executor(error))
                    })?;
                let message = decode_strict_jsonrpc_message(&body, maximum_response_bytes)
                    .map_err(ClientHttpConnectionError::ResponseAdmission)?;
                let JsonRpcMessage::Response(response) = message else {
                    return Err(ClientHttpConnectionError::UnexpectedResponseMessage {
                        request_id,
                    });
                };
                if response.id.as_ref() != Some(&request_id) {
                    return Err(ClientHttpConnectionError::ResponseIdMismatch {
                        expected: request_id,
                        actual: response.id,
                    });
                }
                Ok(response)
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

    /// Calls one tool without projecting away the final result algebra.
    ///
    /// An exact legacy-selected connection rejects this operation before any
    /// request is sent. A modern connection requires bilateral discovery of
    /// the official Tasks result discriminator and returns the exact complete,
    /// task, or input-required branch.
    pub async fn call_tool_final_outcome(
        &self,
        cx: &Cx,
        request_id: RequestId,
        name: &str,
        arguments: serde_json::Value,
        maximum_response_bytes: usize,
    ) -> Result<FinalToolCallOutcome, ClientHttpConnectionError> {
        match self {
            Self::Modern(client) => client
                .call_tool_final_outcome(cx, request_id, name, arguments, maximum_response_bytes)
                .await
                .map_err(ClientHttpConnectionError::Modern),
            Self::LegacySse(_) => Err(ClientHttpConnectionError::FinalToolCallRequiresModern),
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
                if response.metadata().status() != 202 {
                    return Err(
                        ClientHttpConnectionError::ModernNotificationUnexpectedStatus {
                            status: response.metadata().status(),
                        },
                    );
                }
                let body = response
                    .read_to_end(cx, MAX_MODERN_HTTP_PROBE_BODY_BYTES)
                    .await
                    .map_err(|error| {
                        ClientHttpConnectionError::Modern(ModernHttpClientError::Executor(error))
                    })?;
                if !body.is_empty() {
                    return Err(ClientHttpConnectionError::ModernNotificationUnexpectedBody);
                }
                Ok(())
            }
            Self::LegacySse(client) => {
                if let Some(parameters) = parameters.as_ref() {
                    reject_final_only_legacy_request_metadata(parameters)?;
                }
                client
                    .send(
                        cx,
                        &JsonRpcMessage::Request(JsonRpcRequest::notification(method, parameters)),
                    )
                    .await
                    .map_err(ClientHttpConnectionError::Legacy)
            }
        }
    }
}

fn reject_final_only_legacy_request_metadata(
    parameters: &serde_json::Value,
) -> Result<(), ClientHttpConnectionError> {
    let Some(metadata) = parameters
        .as_object()
        .and_then(|parameters| parameters.get("_meta"))
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };
    let Some(member) = FINAL_ONLY_LEGACY_REQUEST_METADATA_KEYS
        .iter()
        .copied()
        .find(|member| metadata.contains_key(*member))
    else {
        return Ok(());
    };
    Err(ClientHttpConnectionError::LegacyFinalMetadata { member })
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
    /// The typed final discovery reply did not advertise the final version
    /// selected for this modern HTTP connection.
    DiscoveryDoesNotAdvertiseModernProtocol,
    /// The configured native legacy SSE connection could not be opened or
    /// safely used after policy selected its exact endpoint bundle.
    LegacySse(LegacySseHttpClientError),
    /// The supplied request ID is not a valid JSON-RPC correlation key.
    InvalidRequestId,
    /// The retained discovery response did not admit the official Tasks
    /// result discriminator with exact bilateral empty settings.
    TasksNegotiation,
    /// The finite response body was not one strictly admitted JSON-RPC message.
    InvalidJsonRpcResponse(JsonRpcAdmissionError),
    /// The server returned a response for a different request.
    ResponseIdMismatch {
        /// The immutable outgoing request ID.
        expected: RequestId,
        /// The response ID observed on the wire.
        actual: Option<RequestId>,
    },
    /// The server returned a JSON-RPC error for the tool call.
    RemoteError { code: i32, message: String },
    /// The response contradicted the final typed core result contract.
    TypedResult(CoreDispatchError),
    /// The decoded response was not one final `tools/call` result branch.
    UnexpectedToolCallResult,
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
            Self::DiscoveryDoesNotAdvertiseModernProtocol => {
                formatter.write_str("server/discover did not advertise MCP 2026-07-28")
            }
            Self::LegacySse(error) => error.fmt(formatter),
            Self::InvalidRequestId => {
                formatter.write_str("final HTTP tools/call requires a valid JSON-RPC request ID")
            }
            Self::TasksNegotiation => formatter
                .write_str("final HTTP tools/call Tasks result was not bilaterally negotiated"),
            Self::InvalidJsonRpcResponse(error) => {
                write!(
                    formatter,
                    "final HTTP tools/call response failed JSON-RPC admission: {error}"
                )
            }
            Self::ResponseIdMismatch { expected, actual } => write!(
                formatter,
                "final HTTP tools/call response ID {actual:?} did not match request {expected:?}"
            ),
            Self::RemoteError { code, message } => {
                write!(
                    formatter,
                    "final HTTP tools/call failed with JSON-RPC {code}: {message}"
                )
            }
            Self::TypedResult(error) => {
                write!(formatter, "invalid final HTTP tools/call result: {error}")
            }
            Self::UnexpectedToolCallResult => {
                formatter.write_str("final HTTP tools/call decoded to an unrelated core result")
            }
        }
    }
}

impl std::error::Error for ModernHttpClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Executor(error) => Some(error),
            Self::Negotiation(error) => Some(error),
            Self::LegacySse(error) => Some(error),
            Self::InvalidJsonRpcResponse(error) => Some(error),
            Self::TypedResult(error) => Some(error),
            Self::MissingModernPostTarget
            | Self::RequestParametersMustBeObject
            | Self::MissingRequestName { .. }
            | Self::UnsupportedFinalMethod { .. }
            | Self::ServerInitiatedFinalMethod { .. }
            | Self::MissingRequestId { .. }
            | Self::NotificationHasRequestId { .. }
            | Self::RequestEncodingFailed
            | Self::DiscoveryRejected
            | Self::InvalidDiscoveryResponse
            | Self::DiscoveryDoesNotAdvertiseModernProtocol
            | Self::InvalidRequestId
            | Self::TasksNegotiation
            | Self::ResponseIdMismatch { .. }
            | Self::RemoteError { .. }
            | Self::UnexpectedToolCallResult => None,
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
        Self::connect_with_mcp_apps(cx, protocol_plan, client_info, client_capabilities, None).await
    }

    pub(crate) async fn connect_with_mcp_apps(
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        mcp_apps_settings: Option<McpAppsClientSettings>,
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
        let client_extensions = mcp_apps_client_extensions(mcp_apps_settings.as_ref());
        let probe_request = build_modern_request_with_extensions(
            &modern_post_target,
            &client_info,
            &client_capabilities,
            SERVER_DISCOVER,
            serde_json::json!({}),
            Some(RequestId::Number(1)),
            client_extensions.as_ref(),
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
                let mcp_apps_active =
                    resolve_mcp_apps_activation(mcp_apps_settings.as_ref(), &server_discovery);
                Ok(ModernHttpConnectOutcome::Modern(Self {
                    protocol_plan,
                    modern_post_target,
                    client_info,
                    client_capabilities,
                    mcp_apps_settings,
                    mcp_apps_active,
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

    /// Returns whether final discovery activated the official MCP Apps extension.
    #[must_use]
    pub const fn mcp_apps_active(&self) -> bool {
        self.mcp_apps_active
    }

    fn active_mcp_apps_settings(&self) -> Option<&McpAppsClientSettings> {
        self.mcp_apps_active
            .then_some(self.mcp_apps_settings.as_ref())
            .flatten()
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
        let client_extensions = merge_client_extensions(self.active_mcp_apps_settings(), None);
        let request = build_modern_request_with_extensions(
            &self.modern_post_target,
            &self.client_info,
            &self.client_capabilities,
            method.as_ref(),
            parameters,
            request_id,
            client_extensions.as_ref(),
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
        let tasks_requested = task_subscription_ids(&notifications)
            .map_err(|_| ModernHttpSubscriptionListenError::TasksNegotiation)?
            .is_some();
        let client_extensions = if tasks_requested {
            admit_final_tasks_discovery_surface(
                &self.server_discovery,
                TASK_STATUS_NOTIFICATION,
                fastmcp_protocol::ExtensionDirection::ServerToClient,
            )
            .map_err(|_| ModernHttpSubscriptionListenError::TasksNegotiation)?;
            Some(BTreeMap::from([(
                fastmcp_protocol::TASKS_EXTENSION.to_owned(),
                serde_json::json!({}),
            )]))
        } else {
            None
        };
        let client_extensions =
            merge_client_extensions(self.active_mcp_apps_settings(), client_extensions.as_ref());
        let request = build_modern_request_with_extensions(
            &self.modern_post_target,
            &self.client_info,
            &self.client_capabilities,
            SUBSCRIPTIONS_LISTEN,
            serde_json::json!({ "notifications": notifications.clone() }),
            Some(request_id.clone()),
            client_extensions.as_ref(),
        )
        .map_err(ModernHttpSubscriptionListenError::Request)?;
        let response = self
            .executor
            .execute(cx, &request)
            .await
            .map_err(ModernHttpSubscriptionListenError::Executor)?;
        response
            .collect_final_subscriptions_listen(cx, request_id, notifications, limits)
            .await
    }

    /// Calls one final tool through native HTTP and retains its exact result branch.
    pub async fn call_tool_final_outcome(
        &self,
        cx: &Cx,
        request_id: RequestId,
        name: &str,
        arguments: serde_json::Value,
        maximum_response_bytes: usize,
    ) -> Result<FinalToolCallOutcome, ModernHttpClientError> {
        if request_id.validate().is_err() {
            return Err(ModernHttpClientError::InvalidRequestId);
        }
        admit_final_tasks_result_discriminator(
            &self.server_discovery,
            OFFICIAL_TASKS_RESULT_DISCRIMINATOR,
        )
        .map_err(|_| ModernHttpClientError::TasksNegotiation)?;

        let parameters = serde_json::json!({
            "_meta": FinalRequestMeta::new(self.client_capabilities.clone()),
            "name": name,
            "arguments": arguments,
        });
        let core_request =
            CoreRequest::decode(ProtocolEra::Modern2026, TOOLS_CALL, Some(&parameters))
                .map_err(ModernHttpClientError::TypedResult)?;
        let task_extensions = BTreeMap::from([(
            fastmcp_protocol::TASKS_EXTENSION.to_owned(),
            serde_json::json!({}),
        )]);
        let client_extensions =
            merge_client_extensions(self.active_mcp_apps_settings(), Some(&task_extensions));
        let request = build_modern_request_with_extensions(
            &self.modern_post_target,
            &self.client_info,
            &self.client_capabilities,
            TOOLS_CALL,
            parameters,
            Some(request_id.clone()),
            client_extensions.as_ref(),
        )?;
        let response = self
            .executor
            .execute(cx, &request)
            .await
            .map_err(ModernHttpClientError::Executor)?;
        let body = response
            .read_to_end(cx, maximum_response_bytes)
            .await
            .map_err(ModernHttpClientError::Executor)?;
        let message = decode_strict_jsonrpc_message(&body, maximum_response_bytes)
            .map_err(ModernHttpClientError::InvalidJsonRpcResponse)?;
        let JsonRpcMessage::Response(response) = message else {
            return Err(ModernHttpClientError::UnexpectedToolCallResult);
        };
        if response.id.as_ref() != Some(&request_id) {
            return Err(ModernHttpClientError::ResponseIdMismatch {
                expected: request_id,
                actual: response.id,
            });
        }
        if let Some(error) = response.error.as_ref() {
            return Err(ModernHttpClientError::RemoteError {
                code: error.code,
                message: error.message.clone(),
            });
        }
        match core_request
            .decode_response(&response)
            .map_err(ModernHttpClientError::TypedResult)?
        {
            CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) => {
                Ok(FinalToolCallOutcome::Complete(result))
            }
            CoreResult::Final(FinalCoreResult::ToolsCallTask { result }) => {
                Ok(FinalToolCallOutcome::Task(result))
            }
            CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { result, .. }) => {
                Ok(FinalToolCallOutcome::InputRequired(result))
            }
            _ => Err(ModernHttpClientError::UnexpectedToolCallResult),
        }
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
    notifications: VecDeque<JsonRpcRequest>,
}

/// Admits an advertised legacy message endpoint against the configured one.
///
/// The exact 2024-11-05 HTTP+SSE lane advertises its message endpoint with a
/// server-generated session query (for example `?session_id=…`) that no
/// client can preconfigure. Admission therefore accepts byte equality, or an
/// advertised target that extends a query-free configured target with only a
/// query component. Scheme, authority, and path can never change, so the
/// admitted resource, era, authorization, and cache partition stay pinned to
/// the immutable configured bundle; a configured target that already carries
/// a query still requires byte equality.
fn advertised_legacy_target_is_admissible(configured: &str, advertised: &str) -> bool {
    if advertised == configured {
        return true;
    }
    match advertised.split_once('?') {
        Some((base, _session_query)) => base == configured && !configured.contains('?'),
        None => false,
    }
}

#[cfg(test)]
mod legacy_target_admission_tests {
    use super::advertised_legacy_target_is_admissible;

    #[test]
    fn byte_equal_targets_are_admitted() {
        assert!(advertised_legacy_target_is_admissible(
            "http://127.0.0.1:9/messages",
            "http://127.0.0.1:9/messages",
        ));
        assert!(advertised_legacy_target_is_admissible(
            "http://127.0.0.1:9/messages?session=one",
            "http://127.0.0.1:9/messages?session=one",
        ));
    }

    #[test]
    fn a_session_query_may_extend_a_query_free_configured_target() {
        assert!(advertised_legacy_target_is_admissible(
            "http://127.0.0.1:9/messages",
            "http://127.0.0.1:9/messages?session_id=abc123",
        ));
    }

    #[test]
    fn resource_divergence_remains_a_mismatch() {
        // Changed path.
        assert!(!advertised_legacy_target_is_admissible(
            "http://127.0.0.1:9/messages",
            "http://127.0.0.1:9/other?session_id=abc",
        ));
        // Changed authority.
        assert!(!advertised_legacy_target_is_admissible(
            "http://127.0.0.1:9/messages",
            "http://evil.example/messages?session_id=abc",
        ));
        // Changed scheme.
        assert!(!advertised_legacy_target_is_admissible(
            "https://127.0.0.1:9/messages",
            "http://127.0.0.1:9/messages?session_id=abc",
        ));
        // A configured query is immutable: a different query is a mismatch.
        assert!(!advertised_legacy_target_is_admissible(
            "http://127.0.0.1:9/messages?session=one",
            "http://127.0.0.1:9/messages?session=two",
        ));
        // Dropping a configured query is a mismatch.
        assert!(!advertised_legacy_target_is_admissible(
            "http://127.0.0.1:9/messages?session=one",
            "http://127.0.0.1:9/messages",
        ));
    }
}

impl LegacySseHttpClient {
    /// Opens the configured SSE GET endpoint and admits its first `endpoint`
    /// event only when it names the immutable configured POST resource: the
    /// advertised target must equal the configured one exactly, or differ
    /// from a query-free configured target solely by an appended query
    /// component (the exact 2024-11-05 lane advertises a session-scoped
    /// message endpoint). Any scheme, authority, or path divergence remains
    /// a hard mismatch.
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
        if !advertised_legacy_target_is_admissible(
            &configured_message_post_target,
            &advertised_message_post_target,
        ) {
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
            notifications: VecDeque::new(),
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

    /// Pops the oldest notification received while an owning request awaited
    /// its correlated response.
    #[must_use]
    pub fn take_notification(&mut self) -> Option<JsonRpcRequest> {
        self.notifications.pop_front()
    }

    fn queue_notification(&mut self, notification: JsonRpcRequest) -> Result<(), ()> {
        if self.notifications.len() >= MAX_QUEUED_LEGACY_NOTIFICATIONS {
            return Err(());
        }
        self.notifications.push_back(notification);
        Ok(())
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
    build_modern_request_with_extensions(
        target,
        client_info,
        client_capabilities,
        method,
        parameters,
        request_id,
        None,
    )
}

fn mcp_apps_client_extensions(
    settings: Option<&McpAppsClientSettings>,
) -> Option<BTreeMap<String, serde_json::Value>> {
    settings.map(|settings| {
        BTreeMap::from([(
            OFFICIAL_MCP_APPS_EXTENSION_ID.to_owned(),
            settings.to_extension_settings().into_value(),
        )])
    })
}

fn merge_client_extensions(
    mcp_apps_settings: Option<&McpAppsClientSettings>,
    per_call_extensions: Option<&BTreeMap<String, serde_json::Value>>,
) -> Option<BTreeMap<String, serde_json::Value>> {
    let mut merged = mcp_apps_client_extensions(mcp_apps_settings).unwrap_or_default();
    if let Some(per_call_extensions) = per_call_extensions {
        for (extension_id, settings) in per_call_extensions {
            merged
                .entry(extension_id.clone())
                .or_insert_with(|| settings.clone());
        }
    }
    (!merged.is_empty()).then_some(merged)
}

fn build_modern_request_with_extensions(
    target: &str,
    client_info: &ClientInfo,
    client_capabilities: &ClientCapabilities,
    method: &str,
    parameters: serde_json::Value,
    request_id: Option<RequestId>,
    client_extensions: Option<&BTreeMap<String, serde_json::Value>>,
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
    let mut final_metadata = serde_json::to_value(final_request_meta)
        .map_err(|_| ModernHttpClientError::RequestEncodingFailed)?;
    if let Some(client_extensions) = client_extensions {
        let capabilities = final_metadata
            .as_object_mut()
            .and_then(|metadata| metadata.get_mut("io.modelcontextprotocol/clientCapabilities"))
            .and_then(serde_json::Value::as_object_mut)
            .ok_or(ModernHttpClientError::RequestEncodingFailed)?;
        capabilities.insert(
            "extensions".to_owned(),
            serde_json::Value::Object(client_extensions.clone().into_iter().collect()),
        );
    }
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
    let discovery: ServerDiscoverResult = serde_json::from_value(result)
        .map_err(|_| ModernHttpClientError::InvalidDiscoveryResponse)?;
    if !discovery
        .supported_versions()
        .iter()
        .any(|version| version == MODERN_PROTOCOL_VERSION)
    {
        return Err(ModernHttpClientError::DiscoveryDoesNotAdvertiseModernProtocol);
    }
    Ok(discovery)
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
            None if status == 202 => ModernHttpResponseKind::EmptyAcknowledgement,
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
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::{Duration, Instant};

    use asupersync::Cx;
    use asupersync::runtime::RuntimeBuilder;
    use fastmcp_protocol::extensions::{McpAppsClientSettings, OFFICIAL_MCP_APPS_EXTENSION_ID};
    use fastmcp_protocol::{
        ClientCapabilities, ClientInfo, RequestId, ServerNotification, SubscriptionFilter,
    };

    use super::{
        ClientHttpConnection, ClientHttpConnectionError, LegacySseHttpClientError,
        MAX_IGNORED_RESPONSE_CONTENT_ENCODING_EMPTY_ELEMENTS, ModernHttpClientError,
        ModernHttpExecutorError, ModernHttpResponseKind, ModernHttpSubscriptionListenCollector,
        ModernHttpSubscriptionListenError, decode_modern_discovery_response,
        merge_client_extensions, validate_response_head,
    };
    use crate::sse::SseLimits;
    use crate::{
        CanonicalHttpUrl, ClientBuilder, ClientProtocolPlan, FinalToolCallOutcome, ProtocolEra,
        ProtocolPolicy,
    };

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

    #[test]
    fn modern_http_merges_configured_apps_and_per_call_tasks_extensions() {
        let apps = McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
            .expect("valid Apps MIME settings");
        let tasks = BTreeMap::from([(
            fastmcp_protocol::TASKS_EXTENSION.to_owned(),
            serde_json::json!({}),
        )]);

        let merged = merge_client_extensions(Some(&apps), Some(&tasks))
            .expect("Apps and Tasks produce one extension map");
        assert_eq!(merged.len(), 2);
        assert_eq!(
            merged.get(fastmcp_protocol::extensions::OFFICIAL_MCP_APPS_EXTENSION_ID),
            Some(&serde_json::json!({
                "mimeTypes": ["text/html;profile=mcp-app"]
            }))
        );
        assert_eq!(
            merged.get(fastmcp_protocol::TASKS_EXTENSION),
            Some(&serde_json::json!({}))
        );
    }

    #[test]
    fn modern_http_configured_apps_settings_win_over_a_one_field_per_call_collision() {
        let apps = McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
            .expect("valid Apps MIME settings");
        let conflicting_apps = BTreeMap::from([(
            OFFICIAL_MCP_APPS_EXTENSION_ID.to_owned(),
            serde_json::json!({"mimeTypes": ["text/plain"]}),
        )]);

        let merged = merge_client_extensions(Some(&apps), Some(&conflicting_apps))
            .expect("configured Apps settings produce one extension map");
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged.get(OFFICIAL_MCP_APPS_EXTENSION_ID),
            Some(&serde_json::json!({
                "mimeTypes": ["text/html;profile=mcp-app"]
            }))
        );
    }

    fn assert_public_http_apps_advertisement_after_discovery(apps_active: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local Apps listener");
        let address = listener.local_addr().expect("read local Apps address");
        let modern_target = format!("http://{address}/mcp");
        let discovery_body = if apps_active {
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\",\"supportedVersions\":[\"2026-07-28\"],\"capabilities\":{\"extensions\":{\"io.modelcontextprotocol/ui\":{}}},\"ttlMs\":0,\"cacheScope\":\"private\"}}"
        } else {
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\",\"supportedVersions\":[\"2026-07-28\"],\"capabilities\":{},\"ttlMs\":0,\"cacheScope\":\"private\"}}"
        }
        .to_owned();
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept Apps discovery request");
            let probe_request = read_request(&mut probe);
            let probe_message = serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                .expect("Apps discovery request must be JSON-RPC");
            assert_eq!(probe_message["method"], "server/discover");
            assert_eq!(
                probe_message["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
                    [OFFICIAL_MCP_APPS_EXTENSION_ID],
                serde_json::json!({"mimeTypes": ["text/html;profile=mcp-app"]})
            );
            write_response(
                &mut probe,
                200,
                "application/json",
                discovery_body.as_bytes(),
            );

            let (mut list_stream, _) = listener.accept().expect("accept Apps tools/list request");
            let list_request = read_request(&mut list_stream);
            let list = serde_json::from_slice::<serde_json::Value>(&list_request.body)
                .expect("Apps tools/list request must be JSON-RPC");
            assert_eq!(list["id"], 2);
            assert_eq!(list["method"], "tools/list");
            let advertised_apps =
                list["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
                    .get(OFFICIAL_MCP_APPS_EXTENSION_ID);
            if apps_active {
                assert_eq!(
                    advertised_apps,
                    Some(&serde_json::json!({
                        "mimeTypes": ["text/html;profile=mcp-app"]
                    }))
                );
            } else {
                assert!(
                    advertised_apps.is_none(),
                    "inactive Apps negotiation must not advertise an extension on ordinary requests"
                );
            }
            write_response(
                &mut list_stream,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
            );
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(
            ClientBuilder::new()
                .mcp_apps(
                    McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
                        .expect("valid Apps MIME settings"),
                )
                .protocol_plan(plan(
                    &modern_target,
                    "http://127.0.0.1:9/legacy-sse",
                    "http://127.0.0.1:9/legacy-message",
                    ProtocolPolicy::ModernOnly,
                ))
                .connect_http_with_cx(&cx),
        )
        .expect("public client completes final discovery");
        assert_eq!(connection.mcp_apps_active(), apps_active);
        let response = runtime_block_on(connection.request_json(
            &cx,
            "tools/list",
            serde_json::json!({}),
            RequestId::Number(2),
            4_096,
        ))
        .expect("public client sends the negotiated Apps request");
        assert_eq!(response.id, Some(RequestId::Number(2)));
        server.join().expect("Apps negotiation server must join");
    }

    #[test]
    fn public_http_connection_advertises_configured_apps_after_active_discovery() {
        assert_public_http_apps_advertisement_after_discovery(true);
    }

    #[test]
    fn public_http_connection_omits_configured_apps_after_one_field_inactive_discovery() {
        assert_public_http_apps_advertisement_after_discovery(false);
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

    fn write_response_without_content_type(stream: &mut TcpStream, status: u16, body: &[u8]) {
        let reason = match status {
            200 => "OK",
            202 => "Accepted",
            404 => "Not Found",
            _ => "Test Response",
        };
        write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("write content-type-free native HTTP response head");
        stream
            .write_all(body)
            .expect("write content-type-free native HTTP response body");
        stream
            .flush()
            .expect("flush content-type-free native HTTP response");
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
        br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#
    }

    fn modern_tasks_discovery_body() -> Vec<u8> {
        let capabilities = fastmcp_protocol::ServerDiscoverCapabilities::from_registry(
            &fastmcp_protocol::ServerBehaviorRegistry::default(),
            BTreeMap::from([(
                fastmcp_protocol::TASKS_EXTENSION.to_owned(),
                serde_json::json!({}),
            )]),
        )
        .expect("typed Tasks discovery capabilities");
        let result = fastmcp_protocol::ServerDiscoverResult::new(
            capabilities,
            fastmcp_protocol::ServerInfo {
                name: "tasks-http-server".to_owned(),
                version: "1.0.0".to_owned(),
            },
            None,
            fastmcp_protocol::DiscoveryCacheHints::private_ttl_ms(0),
        );
        let mut response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": result,
        });
        response["result"]["supportedVersions"] = serde_json::json!(["2026-07-28"]);
        serde_json::to_vec(&response).expect("typed Tasks discovery response")
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

    fn run_public_http_tasks_subscription(
        notification_task_id: &str,
    ) -> Result<ModernHttpSubscriptionListenCollector, ClientHttpConnectionError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind local Tasks subscriptions/listen listener");
        let address = listener
            .local_addr()
            .expect("read local Tasks subscriptions/listen address");
        let modern_target = format!("http://{address}/mcp");
        let notification_task_id = notification_task_id.to_owned();
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept Tasks modern probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("Tasks modern probe must be JSON-RPC")["method"],
                "server/discover"
            );
            write_response(
                &mut probe,
                200,
                "application/json",
                &modern_tasks_discovery_body(),
            );

            let (mut stream, _) = listener
                .accept()
                .expect("accept Tasks subscriptions/listen request");
            let request = read_request(&mut stream);
            let body = serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("Tasks subscriptions/listen request must be JSON-RPC");
            assert_eq!(body["method"], "subscriptions/listen");
            assert_eq!(body["params"]["notifications"]["taskIds"][0], "task-73");
            assert_eq!(
                body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
                    ["io.modelcontextprotocol/tasks"],
                serde_json::json!({})
            );

            begin_chunked_sse(&mut stream);
            for event in [
                "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/subscriptions/acknowledged\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/subscriptionId\":2},\"notifications\":{\"toolsListChanged\":true,\"taskIds\":[\"task-73\"]}}}\n\n".to_owned(),
                format!(
                    "data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tasks\",\"params\":{{\"_meta\":{{\"io.modelcontextprotocol/subscriptionId\":2}},\"taskId\":\"{notification_task_id}\",\"status\":\"working\",\"createdAt\":\"2026-07-28T12:00:00.000Z\",\"lastUpdatedAt\":\"2026-07-28T12:00:00.000Z\",\"ttlMs\":null}}}}\n\n"
                ),
                "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"resultType\":\"complete\",\"_meta\":{\"io.modelcontextprotocol/subscriptionId\":2}}}\n\n".to_owned(),
            ] {
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
        .expect("Tasks discovery selects final HTTP subscriptions/listen");
        let mut filter = SubscriptionFilter {
            tools_list_changed: Some(true),
            ..SubscriptionFilter::default()
        };
        fastmcp_protocol::set_task_subscription_ids(
            &mut filter,
            vec![fastmcp_protocol::FinalTaskId::parse("task-73").expect("bounded HTTP task id")],
        )
        .expect("compose Tasks beside the HTTP core filter");
        let result = runtime_block_on(connection.listen_subscriptions_typed(
            &cx,
            RequestId::Number(2),
            filter,
            SseLimits::new(2_048, 16_384, 16).expect("explicit SSE bounds are nonzero"),
        ));
        server.join().expect("Tasks HTTP server must join");
        result
    }

    fn run_public_http_tasks_tool_outcome(
        result_type: &str,
    ) -> Result<FinalToolCallOutcome, ClientHttpConnectionError> {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind local Tasks tools/call listener");
        let address = listener
            .local_addr()
            .expect("read local Tasks tools/call address");
        let modern_target = format!("http://{address}/mcp");
        let result_type = result_type.to_owned();
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept Tasks modern probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("Tasks modern probe must be JSON-RPC")["method"],
                "server/discover"
            );
            write_response(
                &mut probe,
                200,
                "application/json",
                &modern_tasks_discovery_body(),
            );

            let (mut stream, _) = listener.accept().expect("accept Tasks tools/call request");
            let request = read_request(&mut stream);
            assert!(request.head.contains("Mcp-Method: tools/call\r\n"));
            assert!(request.head.contains("Mcp-Name: durable-tool\r\n"));
            let body = serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("Tasks tools/call request must be JSON-RPC");
            assert_eq!(body["id"], 2);
            assert_eq!(body["method"], "tools/call");
            assert_eq!(body["params"]["name"], "durable-tool");
            assert_eq!(body["params"]["arguments"]["work"], 73);
            assert_eq!(
                body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
                    ["io.modelcontextprotocol/tasks"],
                serde_json::json!({})
            );
            let response = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"resultType\":\"{result_type}\",\"taskId\":\"task-73\",\"status\":\"working\",\"createdAt\":\"2026-07-28T12:00:00.000Z\",\"lastUpdatedAt\":\"2026-07-28T12:00:00.000Z\",\"ttlMs\":null}}}}"
            );
            write_response(&mut stream, 200, "application/json", response.as_bytes());
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
        .expect("Tasks discovery selects final HTTP tools/call");
        let result = runtime_block_on(connection.call_tool_final_outcome(
            &cx,
            RequestId::Number(2),
            "durable-tool",
            serde_json::json!({"work": 73}),
            4_096,
        ));
        assert_eq!(connection.selected_protocol_era(), ProtocolEra::Modern2026);
        server.join().expect("Tasks HTTP tool server must join");
        result
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
        let exact = br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#;
        let admitted = decode_modern_discovery_response(exact)
            .expect("the exact final discovery result must be retained");
        assert_eq!(admitted.supported_versions(), ["2026-07-28"]);

        let planted = br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#;
        assert!(matches!(
            decode_modern_discovery_response(planted),
            Err(ModernHttpClientError::InvalidDiscoveryResponse)
        ));
    }

    #[test]
    fn public_http_connection_auto_selects_modern_and_accepts_a_content_type_free_empty_notification_acknowledgement()
     {
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
            assert_eq!(body["method"], "tools/list");
            assert_eq!(
                body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
                "2026-07-28"
            );
            write_response(
                &mut stream,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
            );

            let (mut notification, _) = listener.accept().expect("accept modern notification");
            let notification_request = read_request(&mut notification);
            assert!(
                notification_request
                    .head
                    .starts_with("POST /mcp HTTP/1.1\r\n")
            );
            let body = serde_json::from_slice::<serde_json::Value>(&notification_request.body)
                .expect("modern notification must be JSON-RPC");
            assert_eq!(body["method"], "notifications/cancelled");
            assert!(body.get("id").is_none());
            assert_eq!(body["params"]["requestId"], 2);
            write_response_without_content_type(&mut notification, 202, b"");
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

        let response = runtime_block_on(connection.request_json(
            &cx,
            "tools/list",
            serde_json::json!({}),
            RequestId::Number(2),
            4_096,
        ))
        .expect("the public HTTP request path retains the selected modern transport");
        assert_eq!(
            response
                .result
                .as_ref()
                .expect("modern response has result")["resultType"],
            "complete",
        );
        runtime_block_on(connection.notify(
            &cx,
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": 2})),
        ))
        .expect("a modern notification receives its exact empty 202 acknowledgement");
        server.join().expect("local modern server must join");
    }

    #[test]
    fn public_http_connection_notify_rejects_only_one_nonempty_byte_in_a_content_type_free_202_acknowledgement()
     {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind notification listener");
        let address = listener
            .local_addr()
            .expect("read notification listener address");
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

            let (mut notification, _) = listener.accept().expect("accept modern notification");
            let notification_request = read_request(&mut notification);
            let body = serde_json::from_slice::<serde_json::Value>(&notification_request.body)
                .expect("modern notification must be JSON-RPC");
            assert_eq!(body["method"], "notifications/cancelled");
            assert!(body.get("id").is_none());
            // The response differs from the accepted neighbour only by this
            // single body byte.
            write_response_without_content_type(&mut notification, 202, b"x");
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(
            ClientBuilder::new()
                .protocol_plan(plan(
                    &modern_target,
                    "http://127.0.0.1:9/legacy-sse",
                    "http://127.0.0.1:9/legacy-message",
                    ProtocolPolicy::ModernOnly,
                ))
                .connect_http_with_cx(&cx),
        )
        .expect("modern discovery selects the stateless connection");
        let error = runtime_block_on(connection.notify(
            &cx,
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": 2})),
        ))
        .expect_err("one nonempty acknowledgement byte must remain rejected");
        assert!(matches!(
            error,
            ClientHttpConnectionError::ModernNotificationUnexpectedBody
        ));
        server.join().expect("notification test server must join");
    }

    #[test]
    fn public_http_connection_request_json_rejects_only_a_modern_response_id_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind modern mismatch listener");
        let address = listener.local_addr().expect("read modern mismatch address");
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

            let (mut stream, _) = listener.accept().expect("accept modern request");
            let request = read_request(&mut stream);
            let body = serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("modern request must be JSON-RPC");
            assert_eq!(body["id"], 2);
            assert_eq!(body["method"], "tools/list");
            // Only the response ID differs from the admitted positive request.
            write_response(
                &mut stream,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
            );
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(
            ClientBuilder::new()
                .protocol_plan(plan(
                    &modern_target,
                    "http://127.0.0.1:9/legacy-sse",
                    "http://127.0.0.1:9/legacy-message",
                    ProtocolPolicy::ModernOnly,
                ))
                .connect_http_with_cx(&cx),
        )
        .expect("modern discovery selects the exact stateless connection");
        let error = runtime_block_on(connection.request_json(
            &cx,
            "tools/list",
            serde_json::json!({}),
            RequestId::Number(2),
            4_096,
        ))
        .expect_err("only the response ID differs from the admitted modern request");
        assert!(matches!(
            error,
            ClientHttpConnectionError::ResponseIdMismatch {
                expected: RequestId::Number(2),
                actual: Some(RequestId::Number(3)),
            }
        ));
        server.join().expect("modern mismatch server must join");
    }

    #[test]
    fn public_http_connection_auto_rejects_one_field_modern_version_mismatch_without_downgrade() {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind local contradictory modern listener");
        let address = listener
            .local_addr()
            .expect("read local contradictory modern address");
        let modern_target = format!("http://{address}/mcp");
        let legacy_sse_target = format!("http://{address}/legacy-sse");
        let legacy_message_target = format!("http://{address}/legacy-message");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("modern probe must be JSON-RPC")["method"],
                "server/discover"
            );
            // Only supportedVersions differs from the modern-positive reply:
            // a final discovery response cannot select modern while omitting
            // the final protocol version requested by this connection.
            write_response(
                &mut probe,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2024-11-05"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#,
            );

            listener
                .set_nonblocking(true)
                .expect("observe an unintended downgrade without blocking");
            let deadline = Instant::now() + Duration::from_millis(100);
            loop {
                match listener.accept() {
                    Ok(_) => panic!(
                        "a contradictory modern discovery reply must not open the legacy SSE route"
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("observe unintended legacy connection: {error}"),
                }
            }
        });

        let cx = Cx::for_request();
        let connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                &modern_target,
                &legacy_sse_target,
                &legacy_message_target,
                ProtocolPolicy::Auto,
            ),
            ClientInfo {
                name: "public-http-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ));
        let Err(error) = connection else {
            panic!("contradictory discovery must fail rather than select either era");
        };
        assert!(matches!(
            error,
            ClientHttpConnectionError::Modern(
                ModernHttpClientError::DiscoveryDoesNotAdvertiseModernProtocol
            )
        ));
        server
            .join()
            .expect("contradictory modern server must join");
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
    fn public_http_tasks_subscription_collects_acknowledged_exact_task_id() {
        let collector = run_public_http_tasks_subscription("task-73")
            .expect("HTTP Tasks event must remain typed and request-owned");
        assert_eq!(collector.accepted_filter.tools_list_changed, Some(true));
        assert!(collector.notifications.is_empty());
        assert_eq!(collector.task_notifications.len(), 1);
        assert_eq!(
            collector.task_notifications[0]
                .params
                .task
                .base()
                .task_id
                .as_str(),
            "task-73"
        );
    }

    #[test]
    fn public_http_tasks_subscription_rejects_one_field_unacknowledged_task_id() {
        let error = run_public_http_tasks_subscription("task-74")
            .expect_err("one changed taskId must fail the HTTP stream closed");
        assert!(matches!(
            error,
            ClientHttpConnectionError::SubscriptionsListen(
                ModernHttpSubscriptionListenError::TaskEventOutsideAcceptedFilter
            )
        ));
    }

    #[test]
    fn public_http_tasks_tool_outcome_retains_exact_created_task() {
        let outcome = run_public_http_tasks_tool_outcome("task")
            .expect("HTTP tools/call must retain the negotiated Tasks branch");
        let FinalToolCallOutcome::Task(result) = outcome else {
            panic!("Tasks-backed HTTP tools/call must not project into complete content");
        };
        assert_eq!(result.task.base().task_id.as_str(), "task-73");
    }

    #[test]
    fn public_http_tasks_tool_outcome_rejects_one_field_result_type_change() {
        // The response differs from the admitted positive only in resultType.
        let error = run_public_http_tasks_tool_outcome("complete")
            .expect_err("one changed discriminator must fail typed HTTP result admission");
        assert!(matches!(
            error,
            ClientHttpConnectionError::Modern(ModernHttpClientError::TypedResult(_))
        ));
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

            let (mut notification_post, _) =
                listener.accept().expect("accept legacy notification POST");
            let notification_request = read_request(&mut notification_post);
            let notification =
                serde_json::from_slice::<serde_json::Value>(&notification_request.body)
                    .expect("legacy notification POST must contain JSON-RPC");
            assert_eq!(notification["method"], "notifications/cancelled");
            assert!(notification.get("id").is_none());
            assert_eq!(notification["params"]["requestId"], 2);
            write_response(&mut notification_post, 202, "application/json", b"");
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

        let response = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(2),
            4_096,
        ))
        .expect("legacy request posts then waits for its exact SSE response");
        assert_eq!(response.id, Some(RequestId::Number(2)));
        runtime_block_on(connection.notify(
            &cx,
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": 2})),
        ))
        .expect("a legacy notification posts without an ID to the exact endpoint");
        server.join().expect("local legacy server must join");
    }

    #[test]
    fn public_http_connection_request_json_rejects_only_a_legacy_response_id_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind legacy mismatch listener");
        let address = listener.local_addr().expect("read legacy mismatch address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let server = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept legacy SSE GET");
            let sse_request = read_request(&mut sse);
            assert!(sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            let sse_body = format!(
                "event: endpoint\ndata: {advertised_message_target}\n\nevent: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{}}}}\n\n"
            );
            write_response(&mut sse, 200, "text/event-stream", sse_body.as_bytes());

            let (mut message_post, _) = listener.accept().expect("accept legacy message POST");
            let message_request = read_request(&mut message_post);
            let message = serde_json::from_slice::<serde_json::Value>(&message_request.body)
                .expect("legacy message POST must contain JSON-RPC");
            assert_eq!(message["id"], 2);
            assert_eq!(message["method"], "ping");
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
        let error = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(2),
            4_096,
        ))
        .expect_err("only the response ID differs from the admitted legacy request");
        assert!(matches!(
            error,
            ClientHttpConnectionError::LegacyResponseIdMismatch {
                expected: RequestId::Number(2),
                actual: Some(RequestId::Number(3)),
            }
        ));
        server.join().expect("legacy mismatch server must join");
    }

    #[test]
    fn public_http_client_auto_falls_back_to_ready_exact_legacy_lifecycle() {
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
            assert_eq!(initialize["id"], 1);
            assert_eq!(initialize["method"], "initialize");
            assert_eq!(initialize["params"]["protocolVersion"], "2024-11-05");
            assert!(initialize["params"].get("_meta").is_none());
            write_response(&mut initialize_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-server\",\"version\":\"1.0.0\"}}}\n\n",
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
        let client = runtime_block_on(
            ClientBuilder::new()
                .client_info("public-http-client", "1.0.0")
                .protocol_plan(plan(
                    &modern_target,
                    &sse_target,
                    &message_target,
                    ProtocolPolicy::Auto,
                ))
                .connect_http_client_with_cx(&cx),
        )
        .expect("the public client completes the exact fresh legacy lifecycle");
        assert_eq!(client.selected_protocol_era(), ProtocolEra::Legacy2024);
        assert_eq!(client.server_info().name, "legacy-server");
        assert!(client.legacy_server_capabilities().is_some());
        assert!(client.server_discovery().is_none());
        server.join().expect("Auto fallback server must join");
    }

    #[test]
    fn public_http_client_legacy_only_completes_exact_legacy_lifecycle() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local legacy listener");
        let address = listener
            .local_addr()
            .expect("read local legacy listener address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let server = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept exact legacy SSE GET");
            let sse_request = read_request(&mut sse);
            assert!(sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            assert!(
                !sse_request.head.contains("MCP-Protocol-Version:"),
                "exact legacy SSE GET must not carry final headers"
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
            let initialize = serde_json::from_slice::<serde_json::Value>(&initialize_request.body)
                .expect("legacy initialize POST must be JSON-RPC");
            assert_eq!(initialize["id"], 1);
            assert_eq!(initialize["method"], "initialize");
            assert_eq!(initialize["params"]["protocolVersion"], "2024-11-05");
            assert!(initialize["params"].get("_meta").is_none());
            write_response(&mut initialize_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-only-server\",\"version\":\"1.0.0\"}}}\n\n",
            );

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
            write_response(&mut initialized_post, 202, "application/json", b"");

            let (mut ping_post, _) = listener
                .accept()
                .expect("accept exact legacy post-lifecycle ping POST");
            let ping_request = read_request(&mut ping_post);
            assert!(
                ping_request
                    .head
                    .starts_with("POST /legacy-message HTTP/1.1\r\n")
            );
            assert!(
                !ping_request
                    .head
                    .contains("MCP-Protocol-Version: 2026-07-28\r\n"),
                "exact legacy request must not carry final headers"
            );
            let ping = serde_json::from_slice::<serde_json::Value>(&ping_request.body)
                .expect("legacy post-lifecycle ping must be JSON-RPC");
            assert_eq!(ping["id"], 2);
            assert_eq!(ping["method"], "ping");
            assert!(ping["params"].get("_meta").is_none());
            write_response(&mut ping_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n",
            );
            finish_chunked_sse(&mut sse);
        });

        let cx = Cx::for_request();
        let mut client = runtime_block_on(
            ClientBuilder::new()
                .client_info("public-http-client", "1.0.0")
                .mcp_apps(
                    McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
                        .expect("valid Apps MIME settings"),
                )
                .protocol_plan(plan(
                    "http://127.0.0.1:9/mcp",
                    &sse_target,
                    &message_target,
                    ProtocolPolicy::LegacyOnly,
                ))
                .connect_http_client_with_cx(&cx),
        )
        .expect("legacy-only public client completes the exact lifecycle");
        assert_eq!(client.selected_protocol_era(), ProtocolEra::Legacy2024);
        assert_eq!(client.server_info().name, "legacy-only-server");
        assert!(client.legacy_server_capabilities().is_some());
        assert!(client.server_discovery().is_none());
        assert!(!client.mcp_apps_active());
        let response = runtime_block_on(client.connection_mut().request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(2),
            4_096,
        ))
        .expect("configured Apps must not leak into a post-lifecycle legacy request");
        assert_eq!(response.id, Some(RequestId::Number(2)));
        server.join().expect("legacy-only server must join");
    }

    #[test]
    fn public_http_client_rejects_only_a_legacy_initialize_version_mismatch() {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind local legacy-version listener");
        let address = listener
            .local_addr()
            .expect("read local legacy-version address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let server = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept legacy SSE GET");
            let sse_request = read_request(&mut sse);
            assert!(sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            let (mut initialize_post, _) = listener
                .accept()
                .expect("accept exact legacy initialize POST");
            let initialize_request = read_request(&mut initialize_post);
            let initialize = serde_json::from_slice::<serde_json::Value>(&initialize_request.body)
                .expect("legacy initialize POST must be JSON-RPC");
            assert_eq!(initialize["id"], 1);
            assert_eq!(initialize["method"], "initialize");
            write_response(&mut initialize_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-server\",\"version\":\"1.0.0\"}}}\n\n",
            );
            finish_chunked_sse(&mut sse);
        });

        let cx = Cx::for_request();
        let error = runtime_block_on(
            ClientBuilder::new()
                .protocol_plan(plan(
                    "http://127.0.0.1:9/mcp",
                    &sse_target,
                    &message_target,
                    ProtocolPolicy::LegacyOnly,
                ))
                .connect_http_client_with_cx(&cx),
        )
        .err()
        .expect("only the selected legacy initialize version is incompatible");
        assert!(matches!(
            error,
            crate::HttpClientError::LegacyInitializationUnsupportedProtocolVersion { actual }
                if actual == "2026-07-28"
        ));
        server.join().expect("legacy-version server must join");
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

    #[test]
    fn public_legacy_request_queues_interleaved_notification_until_its_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local legacy listener");
        let address = listener
            .local_addr()
            .expect("read local legacy listener address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let server = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept exact legacy SSE GET");
            let sse_request = read_request(&mut sse);
            assert!(sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            let (mut request_post, _) = listener.accept().expect("accept exact legacy POST");
            let request = read_request(&mut request_post);
            let request = serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("legacy POST remains JSON-RPC");
            assert_eq!(request["id"], 41);
            assert_eq!(request["method"], "ping");
            assert!(request["params"].get("_meta").is_none());
            write_response(&mut request_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n",
            );
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":41,\"result\":{\"ok\":true}}\n\n",
            );
            finish_chunked_sse(&mut sse);
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
        .expect("public connection opens the exact legacy lane");
        let response = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(41),
            4_096,
        ))
        .expect("interleaved notification does not replace the correlated response");
        assert_eq!(response.id, Some(RequestId::Number(41)));
        let notification = connection
            .take_legacy_notification()
            .expect("interleaved legacy notification is retained for the caller");
        assert!(notification.is_notification());
        assert_eq!(notification.method, "notifications/progress");
        assert!(connection.take_legacy_notification().is_none());
        server.join().expect("legacy request server must join");
    }

    #[test]
    fn public_legacy_request_rejects_only_final_metadata_without_sending_or_mutating() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local legacy listener");
        let address = listener
            .local_addr()
            .expect("read local legacy listener address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let server = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept exact legacy SSE GET");
            let sse_request = read_request(&mut sse);
            assert!(sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            assert!(
                !sse_request.head.contains("MCP-Protocol-Version:"),
                "exact legacy SSE GET must not carry final headers"
            );
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            // The negative request must not create a POST. The first and only
            // POST is the otherwise identical request after rejection.
            let (mut request_post, _) = listener.accept().expect("accept unchanged legacy POST");
            let request = read_request(&mut request_post);
            let request = serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("recovered legacy POST remains JSON-RPC");
            assert_eq!(request["id"], 42);
            assert_eq!(request["method"], "ping");
            assert!(request["params"].get("_meta").is_none());
            write_response(&mut request_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{\"ok\":true}}\n\n",
            );
            finish_chunked_sse(&mut sse);
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
        .expect("public connection opens the exact legacy lane");
        let rejected = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({
                "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
            }),
            RequestId::Number(42),
            4_096,
        ));
        assert!(matches!(
            rejected,
            Err(ClientHttpConnectionError::LegacyFinalMetadata {
                member: "io.modelcontextprotocol/protocolVersion"
            })
        ));

        let response = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(42),
            4_096,
        ))
        .expect("changing only final metadata leaves the legacy connection usable");
        assert_eq!(response.id, Some(RequestId::Number(42)));
        server.join().expect("legacy negative server must join");
    }

    #[test]
    fn public_legacy_notification_rejects_only_final_metadata_without_sending_or_mutating() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local legacy listener");
        let address = listener
            .local_addr()
            .expect("read local legacy listener address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let server = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept exact legacy SSE GET");
            let sse_request = read_request(&mut sse);
            assert!(sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            // The rejected notification must not create a POST. The first and
            // only POST is the otherwise identical notification after it.
            let (mut notification_post, _) = listener
                .accept()
                .expect("accept unchanged legacy notification POST");
            let notification = read_request(&mut notification_post);
            let notification = serde_json::from_slice::<serde_json::Value>(&notification.body)
                .expect("recovered legacy notification remains JSON-RPC");
            assert_eq!(notification["method"], "notifications/cancelled");
            assert!(notification.get("id").is_none());
            assert_eq!(notification["params"]["requestId"], 42);
            assert!(notification["params"].get("_meta").is_none());
            write_response(&mut notification_post, 202, "application/json", b"");
            finish_chunked_sse(&mut sse);
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
        .expect("public connection opens the exact legacy lane");
        let rejected = runtime_block_on(connection.notify(
            &cx,
            "notifications/cancelled",
            Some(serde_json::json!({
                "requestId": 42,
                "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
            })),
        ));
        assert!(matches!(
            rejected,
            Err(ClientHttpConnectionError::LegacyFinalMetadata {
                member: "io.modelcontextprotocol/protocolVersion"
            })
        ));

        runtime_block_on(connection.notify(
            &cx,
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": 42})),
        ))
        .expect("changing only final metadata leaves the legacy connection usable");
        server.join().expect("legacy notification server must join");
    }
}
