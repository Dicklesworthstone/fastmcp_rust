//! Native modern HTTP request and response-stream execution.
//!
//! This module owns modern MCP POST execution, disposable first-probe
//! negotiation, and the public response stream surface. It neither retries an
//! MCP request nor follows redirects.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use asupersync::Cx;
use asupersync::bytes::Buf;
use asupersync::channel::oneshot;
use asupersync::http::h1::http_client::ClientIo;
use asupersync::http::h1::{
    ClientError, ClientStreamingResponse, HttpClient, Method, RedirectPolicy, RetryPolicy,
};
use asupersync::http::{Body, Frame};
#[cfg(feature = "tasks")]
use fastmcp_protocol::extensions::ExtensionDirection;
#[cfg(feature = "tasks")]
use fastmcp_protocol::extensions::OFFICIAL_TASKS_RESULT_DISCRIMINATOR;
use fastmcp_protocol::extensions::{McpAppsClientSettings, OFFICIAL_MCP_APPS_EXTENSION_ID};
use fastmcp_protocol::methods::{
    Final2026Direction, Final2026EnvelopeKind, Final2026Peer, NOTIFICATIONS_PROGRESS, PING,
    PROMPTS_GET, RESOURCES_READ, SUBSCRIPTIONS_LISTEN, TOOLS_CALL, final_2026_07_28_method,
};
use fastmcp_protocol::protocol_policy::{
    HttpModernProbe, HttpProbeBody, MODERN_PROTOCOL_VERSION, ProtocolEra, ProtocolPolicy,
};
#[cfg(feature = "tasks")]
use fastmcp_protocol::task_subscription_ids;
#[cfg(feature = "tasks")]
use fastmcp_protocol::tasks_extension::{
    CancelTaskParams as FinalCancelTaskParams, CancelTaskResult as FinalCancelTaskResult,
    GetTaskParams as FinalGetTaskParams, GetTaskResult as FinalGetTaskResult, TASK_CANCEL,
    TASK_GET, TASK_STATUS_NOTIFICATION, TASK_SUBSCRIPTION_IDS_KEY, TASK_UPDATE, Task as FinalTask,
    TaskId as FinalTaskId, TaskInputLedger, TaskInputResponses as FinalTaskInputResponses,
    TaskMethodRequest, TaskRequestMeta, TaskStatusNotification as FinalTaskStatusNotification,
    UpdateTaskParams as FinalUpdateTaskParams, UpdateTaskResult as FinalUpdateTaskResult,
};
use fastmcp_protocol::{
    CancellationSender, CancellationWireMessage, ClientCapabilities, ClientInfo, CompleteResult,
    CoreDispatchError, CoreRequest, CoreResult, CorrelationKey, ElicitRequestParams, ElicitResult,
    FINAL_SUBSCRIPTION_ID_META_KEY, FinalCoreResult, FinalCreateMessageParams,
    FinalCreateMessageResult, FinalEmbeddedRootsListParams, FinalEmbeddedRootsListResult,
    FinalNotificationError, FinalProgressNotificationParams, FinalRequestMeta,
    FinalSubscriptionsAcknowledgedNotificationParams, FinalSubscriptionsListenResult,
    InputRequiredResult, JsonInteger, JsonRpcAdmissionError, JsonRpcMessage, JsonRpcRequest,
    JsonRpcResponse, RequestId, SERVER_DISCOVER, ServerDiscoverResult, ServerNotification,
    SubscriptionFilter, decode_strict_jsonrpc_message, decode_strict_jsonrpc_response,
};

#[cfg(feature = "tasks")]
use crate::FinalToolCallOutcome;
use crate::execution::{MrtrDriver, MrtrDriverLimits};
use crate::session::{ClientExtensionRuntime, mcp_apps_activation_receipt};
use crate::sse::{BoundedSseParser, SseEndOfStream, SseLimits, SseParseError, SsePushError};
use crate::{
    ClientHttpNegotiation, ClientHttpNegotiationDecision, ClientHttpNegotiationError,
    ClientProtocolPlan, MAX_MRTR_CONTINUATION_ROUNDS, MAX_MRTR_INPUT_RESPONSES,
    MAX_MRTR_TOTAL_INPUT_RESPONSES, MrtrInputResponses, ReverseCallbackState,
    ReverseRequestCancellation, ReverseRequestHandlers, validate_protocol_plan_feature,
};
#[cfg(feature = "tasks")]
use crate::{admit_final_tasks_discovery_surface, admit_final_tasks_result_discriminator};
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};

/// Exact request headers required for a modern MCP JSON-RPC POST.
pub const MODERN_MCP_ACCEPT: &str = "application/json, text/event-stream";
pub const MODERN_MCP_ACCEPT_ENCODING: &str = "identity";
pub const MODERN_MCP_CONTENT_TYPE: &str = "application/json";

fn is_modern_http_final_server_notification(request: &JsonRpcRequest) -> bool {
    request.id.is_none()
        && final_2026_07_28_method(&request.method)
            .is_some_and(|method| method.admits_notification_from(Final2026Peer::Server))
}

enum ModernHttpRequestScopedNotification {
    Server(ServerNotification),
    Progress(FinalProgressNotificationParams),
    Ignored,
}

fn classify_modern_http_request_scoped_notification(
    request: &JsonRpcRequest,
    frame: &[u8],
) -> Result<ModernHttpRequestScopedNotification, FinalNotificationError> {
    if !is_modern_http_final_server_notification(request) {
        return Ok(ModernHttpRequestScopedNotification::Ignored);
    }
    if request.method == "notifications/cancelled" {
        return Ok(ModernHttpRequestScopedNotification::Ignored);
    }
    let raw_params = raw_final_notification_params(request, frame)?;
    let notification = match raw_params.as_deref() {
        Some(raw_params) => ServerNotification::decode_with_raw_params(request, raw_params),
        None => ServerNotification::decode(request),
    }?;
    Ok(match notification {
        ServerNotification::Progress(progress) => {
            ModernHttpRequestScopedNotification::Progress(progress)
        }
        notification => ModernHttpRequestScopedNotification::Server(notification),
    })
}

fn raw_final_notification_params(
    request: &JsonRpcRequest,
    frame: &[u8],
) -> Result<Option<String>, FinalNotificationError> {
    if request.method != NOTIFICATIONS_PROGRESS {
        return Ok(None);
    }

    #[derive(serde::Deserialize)]
    struct RawNotificationEnvelope {
        #[serde(default)]
        params: Option<Box<serde_json::value::RawValue>>,
    }

    serde_json::from_slice::<RawNotificationEnvelope>(frame)
        .map_err(|_| FinalNotificationError::InvalidParams {
            method: NOTIFICATIONS_PROGRESS,
        })?
        .params
        .map(|params| params.get().to_owned())
        .ok_or(FinalNotificationError::InvalidParams {
            method: NOTIFICATIONS_PROGRESS,
        })
        .map(Some)
}

/// Maximum response bytes retained while classifying a disposable modern probe.
pub const MAX_MODERN_HTTP_PROBE_BODY_BYTES: usize = 64 * 1024;

/// Maximum completed SSE payloads retained from one native HTTP body frame
/// before a caller receives the next event.
///
/// This is independent of the per-event [`SseLimits`] bound: one valid body
/// frame can contain many individually valid events.
pub const MAX_PENDING_MODERN_HTTP_SSE_EVENTS: usize = 128;

/// Maximum interleaved notifications and reverse requests accepted while one
/// modern HTTP request waits for its correlated terminal response on SSE.
const MAX_MODERN_HTTP_INTERLEAVED_CONTROL_FRAMES: usize = 64;

/// Maximum UTF-8 encoded bytes retained by pending modern HTTP SSE payloads
/// from one or more native body frames before a caller receives the next
/// event.
pub const MAX_PENDING_MODERN_HTTP_SSE_EVENT_BYTES: usize = 64 * 1024;

/// Maximum retained bytes in one legacy SSE event, including its field names.
const MAX_LEGACY_SSE_EVENT_BYTES: usize = 64 * 1024;

/// Maximum bytes in one legacy SSE line before the connection is refused.
const MAX_LEGACY_SSE_LINE_BYTES: usize = 16 * 1024;

/// Maximum ignored legacy SSE comment lines between dispatched events.
const MAX_LEGACY_SSE_KEEPALIVE_LINES: usize = 64;

/// Maximum JSON-RPC bytes accepted from one legacy `message` SSE event.
const MAX_LEGACY_SSE_MESSAGE_BYTES: usize = 64 * 1024;

/// Maximum complete legacy SSE events retained after one native body frame.
///
/// The exact legacy lane shares one long-lived response body. Individual event
/// limits alone do not bound the allocation caused by a native body frame
/// containing many otherwise-valid events.
const MAX_PENDING_LEGACY_SSE_EVENTS: usize = 128;

/// Maximum UTF-8 bytes retained by complete legacy SSE events waiting for the
/// next caller read.
const MAX_PENDING_LEGACY_SSE_EVENT_BYTES: usize = 64 * 1024;

/// Maximum interleaved notifications and reverse requests accepted while one
/// legacy request waits for its correlated terminal response.
const MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES: usize = 64;

/// Maximum server notifications retained while one legacy request waits for
/// its correlated terminal response.
const MAX_QUEUED_LEGACY_NOTIFICATIONS: usize = MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES;

/// Maximum terminal response IDs retained after server-authorized cancellation.
///
/// A legacy SSE peer can deliver the cancelled request's terminal response only
/// after the caller has already received `notifications/cancelled`. Retaining a
/// bounded tombstone lets the next request discard that late terminal frame
/// without misaligning the shared SSE stream.
const MAX_QUEUED_LEGACY_CANCELLED_RESPONSE_IDS: usize = 64;

/// Maximum locally owned legacy response waiters. The persistent reader never
/// permits an unbounded server stream to create local correlation state.
const MAX_PERSISTENT_LEGACY_RESPONSE_WAITERS: usize = 64;

/// Maximum live exact-2024 server-to-client callbacks owned by one persistent
/// legacy SSE connection. This bounds both retained cancellation state and
/// spawned callback tasks while leaving the shared SSE reader free to accept a
/// matching cancellation notification.
const MAX_PERSISTENT_LEGACY_REVERSE_CALLBACKS: usize = 16;

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
    include_method_header: bool,
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
            .field("include_method_header", &self.include_method_header)
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
            include_method_header: true,
        })
    }

    /// POSTs one JSON-RPC response answering a server-initiated reverse request.
    ///
    /// Reverse-response POSTs omit `Mcp-Method` because they are not client
    /// requests. The body is the exact JSON-RPC response envelope.
    pub fn for_jsonrpc_response(
        target: impl Into<String>,
        protocol_version: impl Into<String>,
        body: Vec<u8>,
    ) -> Result<Self, ModernHttpExecutorError> {
        let target = target.into();
        let protocol_version = protocol_version.into();
        if target.is_empty() || protocol_version.is_empty() {
            return Err(ModernHttpExecutorError::InvalidRequestMetadata);
        }
        if [target.as_str(), protocol_version.as_str()]
            .into_iter()
            .any(contains_header_control)
        {
            return Err(ModernHttpExecutorError::InvalidRequestMetadata);
        }
        Ok(Self {
            target,
            body,
            protocol_version,
            method: String::new(),
            name: None,
            authorization: None,
            include_method_header: false,
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
        ];
        if self.include_method_header {
            headers.push(("Mcp-Method".to_owned(), self.method.clone()));
        }
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
            pending_event_bytes: 0,
            end_of_stream: None,
        })
    }

    /// Converts this response into a typed, request-owned final core listener.
    ///
    /// The listener accepts only final server notifications and the one
    /// response correlated to `request_id`. Progress is decoded from the raw
    /// SSE event so its JSON-number lexemes remain intact.
    pub fn into_final_core_listener(
        self,
        request_id: RequestId,
        core_request: CoreRequest,
        limits: SseLimits,
    ) -> Result<ModernHttpFinalCoreListener, ModernHttpFinalCoreListenError> {
        if request_id.validate().is_err() {
            return Err(ModernHttpFinalCoreListenError::InvalidRequestId);
        }
        if !matches!(core_request, CoreRequest::Final(_)) {
            return Err(ModernHttpFinalCoreListenError::NonFinalCoreRequest);
        }
        let maximum_jsonrpc_bytes = limits.max_event_bytes();
        let stream = self
            .into_sse_stream(limits)
            .map_err(ModernHttpFinalCoreListenError::Executor)?;
        Ok(ModernHttpFinalCoreListener {
            stream,
            core_request,
            request_id,
            maximum_jsonrpc_bytes,
            tasks_result_negotiated: false,
            terminal_received: false,
        })
    }

    /// Converts this response into the Tasks-authorized final `tools/call`
    /// listener used only after bilateral Tasks discovery admission.
    #[cfg(feature = "tasks")]
    fn into_final_tasks_tool_call_listener(
        self,
        request_id: RequestId,
        core_request: CoreRequest,
        limits: SseLimits,
    ) -> Result<ModernHttpFinalCoreListener, ModernHttpFinalCoreListenError> {
        let mut listener = self.into_final_core_listener(request_id, core_request, limits)?;
        listener.tasks_result_negotiated = true;
        Ok(listener)
    }

    /// Converts this response into a live final `subscriptions/listen` listener.
    ///
    /// Every dispatched SSE `data` payload must be one strictly admitted
    /// JSON-RPC message. The listener binds both acknowledgement and terminal
    /// result IDs to `request_id`, and refuses EOF or cancellation in place of
    /// a complete result.
    pub fn into_final_subscriptions_listener(
        self,
        request_id: RequestId,
        requested: SubscriptionFilter,
        limits: SseLimits,
    ) -> Result<ModernHttpSubscriptionListener, ModernHttpSubscriptionListenError> {
        if request_id.validate().is_err() {
            return Err(ModernHttpSubscriptionListenError::InvalidRequestId);
        }
        let core_request = final_subscriptions_listen_core_request(&requested)?;
        let maximum_jsonrpc_bytes = limits.max_event_bytes();
        let stream = self
            .into_sse_stream(limits)
            .map_err(ModernHttpSubscriptionListenError::Executor)?;
        Ok(ModernHttpSubscriptionListener {
            stream,
            core_request,
            request_id,
            requested,
            accepted_filter: None,
            maximum_jsonrpc_bytes,
            terminal_received: false,
        })
    }

    /// Consumes a final `subscriptions/listen` SSE response until its exact
    /// complete terminal result.
    ///
    /// This is the terminal-collector convenience wrapper over
    /// [`Self::into_final_subscriptions_listener`]. Callers that need each
    /// accepted event as it arrives should retain the returned listener instead.
    pub async fn collect_final_subscriptions_listen(
        self,
        cx: &Cx,
        request_id: RequestId,
        requested: SubscriptionFilter,
        limits: SseLimits,
    ) -> Result<ModernHttpSubscriptionListenCollector, ModernHttpSubscriptionListenError> {
        self.into_final_subscriptions_listener(request_id, requested, limits)?
            .collect(cx)
            .await
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
        let cancellation = McpRequestCancellation::new();
        self.read_to_end_with_cancellation(cx, &cancellation, maximum_bytes)
            .await
    }

    /// Reads a finite response body while observing one request-local
    /// cancellation domain as well as the ambient context.
    ///
    /// Cancellation wins while the native body is pending: dropping the
    /// response stream then closes the request-owned body instead of waiting
    /// for a peer frame or cancelling sibling HTTP requests.
    pub async fn read_to_end_with_cancellation(
        self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, ModernHttpExecutorError> {
        let mut response = self.response;
        let mut bytes = Vec::new();
        let mut cancelled = std::pin::pin!(cancellation.cancelled());

        loop {
            if cx.checkpoint().is_err() || cancellation.is_cancel_requested() {
                return Err(ModernHttpExecutorError::Cancelled);
            }
            let frame = poll_fn(|task_cx| {
                if cancelled.as_mut().poll(task_cx).is_ready() {
                    return Poll::Ready(Err(()));
                }
                match Pin::new(&mut response.body).poll_frame(task_cx) {
                    Poll::Ready(frame) => Poll::Ready(Ok(frame)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            let frame = frame.map_err(|()| ModernHttpExecutorError::Cancelled)?;
            let frame = reject_body_frame_after_cancellation(cx, frame)?;
            let Some(frame) = frame else {
                break;
            };
            let Some(mut data) = frame
                .map_err(|_| ModernHttpExecutorError::ResponseBodyReadFailed)?
                .into_data()
            else {
                continue;
            };

            while data.has_remaining() {
                if cancellation.is_cancel_requested() {
                    return Err(ModernHttpExecutorError::Cancelled);
                }
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

/// One accepted record from a live final HTTP `subscriptions/listen` response.
#[derive(Debug, Clone)]
pub enum ModernHttpSubscriptionListenEvent {
    /// The server acknowledged an exact subset of the requested filter.
    Acknowledged {
        /// The exact filter accepted for the rest of this stream.
        accepted_filter: SubscriptionFilter,
    },
    /// An acknowledged catalog or resource change notification.
    Notification(ServerNotification),
    /// An acknowledged official Tasks status notification.
    #[cfg(feature = "tasks")]
    TaskNotification(FinalTaskStatusNotification),
    /// The complete result terminating this subscription stream.
    Terminal {
        /// The subscription ID encoded in the correlated terminal result.
        subscription_id: RequestId,
        /// The terminal complete result.
        result: CompleteResult<FinalSubscriptionsListenResult>,
    },
}

/// A live, request-owned final HTTP `subscriptions/listen` response stream.
#[derive(Debug)]
pub struct ModernHttpSubscriptionListener {
    stream: ModernHttpSseResponseStream,
    core_request: CoreRequest,
    request_id: RequestId,
    requested: SubscriptionFilter,
    accepted_filter: Option<SubscriptionFilter>,
    maximum_jsonrpc_bytes: usize,
    terminal_received: bool,
}

impl ModernHttpSubscriptionListener {
    /// Returns the JSON-RPC request ID that owns this listener.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the acknowledged filter once the first stream record is admitted.
    #[must_use]
    pub const fn accepted_filter(&self) -> Option<&SubscriptionFilter> {
        self.accepted_filter.as_ref()
    }

    /// Reads and validates one record from this live listener.
    ///
    /// `None` is returned only after the terminal record was already yielded.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ModernHttpSubscriptionListenEvent>, ModernHttpSubscriptionListenError> {
        let result = self.next_event_inner(cx).await;
        if result.is_err()
            || matches!(
                &result,
                Ok(Some(ModernHttpSubscriptionListenEvent::Terminal { .. }))
            )
        {
            self.stream.close();
        }
        result
    }

    async fn next_event_inner(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ModernHttpSubscriptionListenEvent>, ModernHttpSubscriptionListenError> {
        if self.terminal_received {
            return Ok(None);
        }

        let event = match self.stream.next_event(cx).await {
            Ok(Some(event)) => event,
            Ok(None) => {
                return Err(ModernHttpSubscriptionListenError::EndOfStream {
                    framing: self.stream.end_of_stream(),
                });
            }
            Err(ModernHttpExecutorError::Cancelled) => {
                return Err(ModernHttpSubscriptionListenError::CallerCancelled {
                    request_id: self.request_id.clone(),
                });
            }
            Err(error) => return Err(ModernHttpSubscriptionListenError::Executor(error)),
        };
        let message = decode_strict_jsonrpc_message(event.as_bytes(), self.maximum_jsonrpc_bytes)
            .map_err(ModernHttpSubscriptionListenError::JsonRpcAdmission)?;

        match message {
            JsonRpcMessage::Response(response) => {
                let admission =
                    decode_strict_jsonrpc_response(event.as_bytes(), self.maximum_jsonrpc_bytes)
                        .map_err(ModernHttpSubscriptionListenError::JsonRpcAdmission)?;
                if admission.response() != &response {
                    return Err(ModernHttpSubscriptionListenError::JsonRpcAdmission(
                        JsonRpcAdmissionError::InvalidEnvelope,
                    ));
                }
                let (_, raw_result) = admission.into_parts();
                let (subscription_id, result) = decode_final_subscriptions_terminal(
                    &self.core_request,
                    response,
                    raw_result.as_deref(),
                    self.request_id.clone(),
                )?;
                if self.accepted_filter.is_none() {
                    return Err(ModernHttpSubscriptionListenError::TerminalBeforeAcknowledgement);
                }
                self.terminal_received = true;
                Ok(Some(ModernHttpSubscriptionListenEvent::Terminal {
                    subscription_id,
                    result,
                }))
            }
            JsonRpcMessage::Request(request) => {
                #[cfg(feature = "tasks")]
                if request.id.is_none() && request.method == TASK_STATUS_NOTIFICATION {
                    let Some(accepted_filter) = self.accepted_filter.as_ref() else {
                        return Err(ModernHttpSubscriptionListenError::EventBeforeAcknowledgement);
                    };
                    let accepted_task_ids =
                        task_subscription_ids(accepted_filter)
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
                        .and_then(|value| serde_json::from_value::<RequestId>(value.clone()).ok());
                    if !subscription_id.as_ref().is_some_and(|subscription_id| {
                        subscription_id.correlates_with(&self.request_id)
                    }) {
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
                    return Ok(Some(ModernHttpSubscriptionListenEvent::TaskNotification(
                        notification,
                    )));
                }
                #[cfg(not(feature = "tasks"))]
                if request.id.is_none() && request.method == "notifications/tasks" {
                    return Err(ModernHttpSubscriptionListenError::EventOutsideAcceptedFilter);
                }
                let raw_params = raw_final_notification_params(&request, event.as_bytes())
                    .map_err(ModernHttpSubscriptionListenError::NotificationAdmission)?;
                let notification = match raw_params.as_deref() {
                    Some(raw_params) => {
                        ServerNotification::decode_with_raw_params(&request, raw_params)
                    }
                    None => ServerNotification::decode(&request),
                }
                .map_err(ModernHttpSubscriptionListenError::NotificationAdmission)?;
                match notification {
                    ServerNotification::SubscriptionsAcknowledged(acknowledgement) => {
                        if self.accepted_filter.is_some() {
                            return Err(
                                ModernHttpSubscriptionListenError::DuplicateAcknowledgement,
                            );
                        }
                        validate_http_subscription_acknowledgement(
                            &self.request_id,
                            &self.requested,
                            &acknowledgement,
                        )?;
                        let accepted_filter = acknowledgement.notifications;
                        self.accepted_filter = Some(accepted_filter.clone());
                        Ok(Some(ModernHttpSubscriptionListenEvent::Acknowledged {
                            accepted_filter,
                        }))
                    }
                    ServerNotification::Cancelled(_) => {
                        Err(ModernHttpSubscriptionListenError::ServerCancellationOnHttp)
                    }
                    notification @ (ServerNotification::ResourcesListChanged(_)
                    | ServerNotification::ToolsListChanged(_)
                    | ServerNotification::PromptsListChanged(_)
                    | ServerNotification::ResourceUpdated(_)) => {
                        let Some(accepted_filter) = self.accepted_filter.as_ref() else {
                            return Err(
                                ModernHttpSubscriptionListenError::EventBeforeAcknowledgement,
                            );
                        };
                        validate_http_subscription_notification_filter(
                            &notification,
                            accepted_filter,
                        )?;
                        Ok(Some(ModernHttpSubscriptionListenEvent::Notification(
                            notification,
                        )))
                    }
                    ServerNotification::Progress(_) | ServerNotification::Message(_) => {
                        // `subscriptions/listen` admits only the categories
                        // explicitly established by its first acknowledgement.
                        // Progress and log notifications belong to the
                        // request-scoped response stream of the request that
                        // opted into them; they are never subscription events.
                        if self.accepted_filter.is_none() {
                            Err(ModernHttpSubscriptionListenError::EventBeforeAcknowledgement)
                        } else {
                            Err(ModernHttpSubscriptionListenError::EventOutsideAcceptedFilter)
                        }
                    }
                }
            }
        }
    }

    /// Collects this live listener into the terminal compatibility record.
    pub async fn collect(
        mut self,
        cx: &Cx,
    ) -> Result<ModernHttpSubscriptionListenCollector, ModernHttpSubscriptionListenError> {
        let mut notifications = Vec::new();
        #[cfg(feature = "tasks")]
        let mut task_notifications = Vec::new();

        loop {
            let Some(event) = self.next_event(cx).await? else {
                return Err(ModernHttpSubscriptionListenError::EndOfStream {
                    framing: self.stream.end_of_stream(),
                });
            };
            match event {
                ModernHttpSubscriptionListenEvent::Acknowledged { .. } => {}
                ModernHttpSubscriptionListenEvent::Notification(notification) => {
                    notifications.push(notification);
                }
                #[cfg(feature = "tasks")]
                ModernHttpSubscriptionListenEvent::TaskNotification(notification) => {
                    task_notifications.push(notification);
                }
                ModernHttpSubscriptionListenEvent::Terminal {
                    subscription_id,
                    result: terminal,
                } => {
                    let accepted_filter = self
                        .accepted_filter
                        .clone()
                        .ok_or(ModernHttpSubscriptionListenError::TerminalBeforeAcknowledgement)?;
                    return Ok(ModernHttpSubscriptionListenCollector {
                        subscription_id,
                        accepted_filter,
                        notifications,
                        #[cfg(feature = "tasks")]
                        task_notifications,
                        terminal,
                    });
                }
            }
        }
    }
}

/// Maximum exact final progress notifications retained by one ordinary modern
/// HTTP request-owned collector.
pub const MAX_QUEUED_FINAL_HTTP_PROGRESS_NOTIFICATIONS: usize = 64;

/// One accepted record from an ordinary final core HTTP response stream.
#[derive(Debug, Clone)]
pub enum ModernHttpFinalCoreEvent {
    /// An exact progress notification retained without `f64` conversion.
    Progress(FinalProgressNotificationParams),
    /// Another exact final server notification admitted by its declared direction.
    Notification(ServerNotification),
    /// The one final core result correlated to the request that opened this stream.
    Terminal(FinalCoreResult),
}

/// The terminal record collected from one ordinary final core HTTP response stream.
#[derive(Debug, Clone)]
pub struct ModernHttpFinalCoreCollector {
    /// The JSON-RPC request identity that owns the response stream.
    pub request_id: RequestId,
    /// Exact final progress notifications in received order.
    pub progress_notifications: Vec<FinalProgressNotificationParams>,
    /// The final core result correlated to `request_id`.
    pub terminal: FinalCoreResult,
}

/// A live, request-owned final core HTTP response stream.
///
/// This listener is intentionally final-only. It never projects a notification
/// through the legacy progress callback or invokes a legacy reverse-request
/// handler.
#[derive(Debug)]
pub struct ModernHttpFinalCoreListener {
    stream: ModernHttpSseResponseStream,
    core_request: CoreRequest,
    request_id: RequestId,
    maximum_jsonrpc_bytes: usize,
    tasks_result_negotiated: bool,
    terminal_received: bool,
}

impl ModernHttpFinalCoreListener {
    /// Returns the JSON-RPC request ID that owns this listener.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn fail<T>(
        &mut self,
        error: ModernHttpFinalCoreListenError,
    ) -> Result<T, ModernHttpFinalCoreListenError> {
        self.stream.close();
        Err(error)
    }

    /// Reads and validates one request-owned server notification or terminal result.
    ///
    /// The listener closes its owned response body if `cx` is cancelled. A
    /// server cancellation notification is invalid on modern HTTP because body
    /// closure is the sole cancellation mechanism for this response stream.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ModernHttpFinalCoreEvent>, ModernHttpFinalCoreListenError> {
        if self.terminal_received {
            return Ok(None);
        }

        let event = match self.stream.next_event(cx).await {
            Ok(Some(event)) => event,
            Ok(None) => {
                return self.fail(ModernHttpFinalCoreListenError::EndOfStream {
                    framing: self.stream.end_of_stream(),
                });
            }
            Err(ModernHttpExecutorError::Cancelled) => {
                return self.fail(ModernHttpFinalCoreListenError::CallerCancelled {
                    request_id: self.request_id.clone(),
                });
            }
            Err(error) => return self.fail(ModernHttpFinalCoreListenError::Executor(error)),
        };
        let message =
            match decode_strict_jsonrpc_message(event.as_bytes(), self.maximum_jsonrpc_bytes) {
                Ok(message) => message,
                Err(error) => {
                    return self.fail(ModernHttpFinalCoreListenError::JsonRpcAdmission(error));
                }
            };

        match message {
            JsonRpcMessage::Response(response) => {
                let admission = match decode_strict_jsonrpc_response(
                    event.as_bytes(),
                    self.maximum_jsonrpc_bytes,
                ) {
                    Ok(admission) => admission,
                    Err(error) => {
                        return self.fail(ModernHttpFinalCoreListenError::JsonRpcAdmission(error));
                    }
                };
                if admission.response() != &response {
                    return self.fail(ModernHttpFinalCoreListenError::JsonRpcAdmission(
                        JsonRpcAdmissionError::InvalidEnvelope,
                    ));
                }
                let (_, raw_result) = admission.into_parts();
                let terminal = match decode_final_core_terminal(
                    &self.core_request,
                    response,
                    raw_result.as_deref(),
                    self.request_id.clone(),
                    self.tasks_result_negotiated,
                ) {
                    Ok(terminal) => terminal,
                    Err(error) => return self.fail(error),
                };
                self.terminal_received = true;
                self.stream.close();
                Ok(Some(ModernHttpFinalCoreEvent::Terminal(terminal)))
            }
            JsonRpcMessage::Request(request) => {
                let raw_params = match raw_final_notification_params(&request, event.as_bytes()) {
                    Ok(raw_params) => raw_params,
                    Err(error) => {
                        return self
                            .fail(ModernHttpFinalCoreListenError::NotificationAdmission(error));
                    }
                };
                let notification = match raw_params.as_deref() {
                    Some(raw_params) => {
                        ServerNotification::decode_with_raw_params(&request, raw_params)
                    }
                    None => ServerNotification::decode(&request),
                };
                let notification = match notification {
                    Ok(notification) => notification,
                    Err(error) => {
                        return self
                            .fail(ModernHttpFinalCoreListenError::NotificationAdmission(error));
                    }
                };

                match notification {
                    ServerNotification::Progress(progress) => {
                        Ok(Some(ModernHttpFinalCoreEvent::Progress(progress)))
                    }
                    ServerNotification::Cancelled(_) => {
                        self.fail(ModernHttpFinalCoreListenError::ServerCancellationOnHttp)
                    }
                    notification => Ok(Some(ModernHttpFinalCoreEvent::Notification(notification))),
                }
            }
        }
    }

    /// Collects exact progress notifications until the one terminal core result.
    pub async fn collect(
        mut self,
        cx: &Cx,
    ) -> Result<ModernHttpFinalCoreCollector, ModernHttpFinalCoreListenError> {
        let mut progress_notifications = Vec::new();
        loop {
            let Some(event) = self.next_event(cx).await? else {
                return self.fail(ModernHttpFinalCoreListenError::EndOfStream {
                    framing: self.stream.end_of_stream(),
                });
            };
            match event {
                ModernHttpFinalCoreEvent::Progress(progress) => {
                    if progress_notifications.len() >= MAX_QUEUED_FINAL_HTTP_PROGRESS_NOTIFICATIONS
                    {
                        return self.fail(ModernHttpFinalCoreListenError::ProgressQueueFull);
                    }
                    progress_notifications.push(progress);
                }
                ModernHttpFinalCoreEvent::Notification(_) => {}
                ModernHttpFinalCoreEvent::Terminal(terminal) => {
                    return Ok(ModernHttpFinalCoreCollector {
                        request_id: self.request_id.clone(),
                        progress_notifications,
                        terminal,
                    });
                }
            }
        }
    }
}

/// Errors raised while consuming an ordinary final core HTTP SSE response stream.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "this public typed error preserves direct protocol error ownership and source chaining; boxing one branch would degrade the caller-facing error API"
)]
pub enum ModernHttpFinalCoreListenError {
    /// The supplied request ID is not a valid JSON-RPC correlation key.
    InvalidRequestId,
    /// A non-final core request cannot own this final-only listener.
    NonFinalCoreRequest,
    /// Constructing or issuing the final core request failed.
    Request(ModernHttpClientError),
    /// The response did not use the required SSE body lane or could not be read.
    Executor(ModernHttpExecutorError),
    /// An SSE event was not one strictly admitted JSON-RPC object.
    JsonRpcAdmission(JsonRpcAdmissionError),
    /// A server request was not one exact final server notification.
    NotificationAdmission(FinalNotificationError),
    /// The server emitted a terminal response for another request.
    ResponseIdMismatch {
        /// The immutable outgoing request ID.
        expected: RequestId,
        /// The response ID observed on the stream.
        actual: Option<RequestId>,
    },
    /// The server terminated the request with a JSON-RPC error.
    RemoteError {
        /// Server-provided JSON-RPC code.
        code: JsonInteger,
        /// Server-provided JSON-RPC message.
        message: String,
    },
    /// The terminal result contradicted the selected final core method.
    TerminalResult(CoreDispatchError),
    /// A generic core listener received a Tasks-only `tools/call` result.
    TasksResultRequiresNegotiatedListener,
    /// The decoded terminal branch was not final.
    UnexpectedTerminalResult,
    /// The bounded progress queue is full.
    ProgressQueueFull,
    /// A server cancellation notification is invalid on a modern HTTP response stream.
    ServerCancellationOnHttp,
    /// The caller cancelled this request-owned listener context.
    CallerCancelled { request_id: RequestId },
    /// The SSE stream reached EOF before a terminal response.
    EndOfStream { framing: Option<SseEndOfStream> },
}

impl fmt::Display for ModernHttpFinalCoreListenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestId => {
                formatter.write_str("final core HTTP listener requires a valid JSON-RPC request ID")
            }
            Self::NonFinalCoreRequest => {
                formatter.write_str("final core HTTP listener requires a final core request")
            }
            Self::Request(error) => error.fmt(formatter),
            Self::Executor(error) => error.fmt(formatter),
            Self::JsonRpcAdmission(error) => write!(
                formatter,
                "final core SSE event failed strict JSON-RPC admission: {error}"
            ),
            Self::NotificationAdmission(error) => write!(
                formatter,
                "final core SSE event was not a valid final server notification: {error}"
            ),
            Self::ResponseIdMismatch { expected, actual } => write!(
                formatter,
                "final core response ID {actual:?} did not match request {expected:?}"
            ),
            Self::RemoteError { code, message } => write!(
                formatter,
                "final core request failed with JSON-RPC {code}: {message}"
            ),
            Self::TerminalResult(error) => {
                write!(formatter, "invalid final core terminal result: {error}")
            }
            Self::TasksResultRequiresNegotiatedListener => formatter
                .write_str("final core listener received a Tasks result without Tasks negotiation"),
            Self::UnexpectedTerminalResult => {
                formatter.write_str("final core listener decoded a non-final terminal result")
            }
            Self::ProgressQueueFull => {
                formatter.write_str("final core progress queue capacity exceeded")
            }
            Self::ServerCancellationOnHttp => formatter.write_str(
                "final core HTTP response received an invalid server cancellation notification",
            ),
            Self::CallerCancelled { request_id } => write!(
                formatter,
                "final core request {request_id:?} was cancelled by the caller"
            ),
            Self::EndOfStream { .. } => {
                formatter.write_str("final core SSE reached EOF before terminal response")
            }
        }
    }
}

impl std::error::Error for ModernHttpFinalCoreListenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::Executor(error) => Some(error),
            Self::JsonRpcAdmission(error) => Some(error),
            Self::NotificationAdmission(error) => Some(error),
            Self::TerminalResult(error) => Some(error),
            Self::InvalidRequestId
            | Self::NonFinalCoreRequest
            | Self::ResponseIdMismatch { .. }
            | Self::RemoteError { .. }
            | Self::TasksResultRequiresNegotiatedListener
            | Self::UnexpectedTerminalResult
            | Self::ProgressQueueFull
            | Self::ServerCancellationOnHttp
            | Self::CallerCancelled { .. }
            | Self::EndOfStream { .. } => None,
        }
    }
}

fn decode_final_core_terminal(
    core_request: &CoreRequest,
    response: JsonRpcResponse,
    result_source: Option<&str>,
    expected_id: RequestId,
    tasks_result_negotiated: bool,
) -> Result<FinalCoreResult, ModernHttpFinalCoreListenError> {
    #[cfg(not(feature = "tasks"))]
    let _ = tasks_result_negotiated;
    if !response
        .id
        .as_ref()
        .is_some_and(|response_id| response_id.correlates_with(&expected_id))
    {
        return Err(ModernHttpFinalCoreListenError::ResponseIdMismatch {
            expected: expected_id,
            actual: response.id,
        });
    }
    if let Some(error) = response.error.as_ref() {
        return Err(ModernHttpFinalCoreListenError::RemoteError {
            code: error.code.clone(),
            message: error.message.clone(),
        });
    }
    let result_source = result_source.ok_or_else(|| {
        ModernHttpFinalCoreListenError::TerminalResult(CoreDispatchError::InvalidResult {
            era: core_request.era(),
            method: core_request.method(),
        })
    })?;
    let CoreResult::Final(result) = core_request
        .decode_response_result(&response, result_source)
        .map_err(ModernHttpFinalCoreListenError::TerminalResult)?
    else {
        return Err(ModernHttpFinalCoreListenError::UnexpectedTerminalResult);
    };
    #[cfg(feature = "tasks")]
    if matches!(result, FinalCoreResult::ToolsCallTask { .. }) && !tasks_result_negotiated {
        return Err(ModernHttpFinalCoreListenError::TasksResultRequiresNegotiatedListener);
    }
    Ok(result)
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
    pending_event_bytes: usize,
    end_of_stream: Option<SseEndOfStream>,
}

impl ModernHttpSseResponseStream {
    /// Releases the owned response body and parser immediately.
    ///
    /// A request-owned listener uses this for cancellation, terminal delivery,
    /// and every refused wire record so a caller cannot resume a malformed
    /// stream.
    fn close(&mut self) {
        self.response = None;
        self.parser = None;
        self.pending_events.clear();
        self.pending_event_bytes = 0;
    }

    /// Retains one completed SSE payload after checking the aggregate budget.
    ///
    /// This is intentionally called by the parser's per-dispatch callback,
    /// rather than after it has materialized every event from a native body
    /// frame. A chunk packed with valid events therefore stops at the first
    /// overflowing event and never allocates its unneeded tail payloads.
    fn retain_pending_event(&mut self, event: String) -> Result<(), ModernHttpExecutorError> {
        let event_count = self
            .pending_events
            .len()
            .checked_add(1)
            .filter(|count| *count <= MAX_PENDING_MODERN_HTTP_SSE_EVENTS)
            .ok_or(ModernHttpExecutorError::PendingSseEventCountExceeded {
                maximum_events: MAX_PENDING_MODERN_HTTP_SSE_EVENTS,
            })?;
        let event_bytes = self
            .pending_event_bytes
            .checked_add(event.len())
            .filter(|bytes| *bytes <= MAX_PENDING_MODERN_HTTP_SSE_EVENT_BYTES)
            .ok_or(ModernHttpExecutorError::PendingSseEventBytesExceeded {
                maximum_bytes: MAX_PENDING_MODERN_HTTP_SSE_EVENT_BYTES,
            })?;
        debug_assert!(event_count <= MAX_PENDING_MODERN_HTTP_SSE_EVENTS);
        self.pending_events.push_back(event);
        self.pending_event_bytes = event_bytes;
        Ok(())
    }

    /// Feeds one already-bounded native body frame through the SSE parser.
    ///
    /// Keeping parser dispatch and aggregate pending-event admission in one
    /// helper makes the frame-level count/byte contract independent of how a
    /// particular HTTP decoder segments a chunked transfer on the network.
    fn push_body_frame(&mut self, chunk: &[u8]) -> Result<(), ModernHttpExecutorError> {
        let mut parser = self
            .parser
            .take()
            .ok_or(ModernHttpExecutorError::SseStreamClosed)?;
        match parser.push_with(chunk, |event| self.retain_pending_event(event)) {
            Ok(()) => {
                self.parser = Some(parser);
                Ok(())
            }
            Err(SsePushError::Parse(error)) => {
                self.close();
                Err(ModernHttpExecutorError::SseParse(error))
            }
            Err(SsePushError::Consumer(error)) => {
                self.close();
                Err(error)
            }
        }
    }

    /// Returns the next completed SSE `data` payload, or `None` at EOF.
    ///
    /// The returned payload is not JSON-RPC-admitted. Its caller must decode
    /// it through the protocol's strict response/notification admission path.
    pub async fn next_event(&mut self, cx: &Cx) -> Result<Option<String>, ModernHttpExecutorError> {
        if cx.checkpoint().is_err() {
            self.close();
            return Err(ModernHttpExecutorError::Cancelled);
        }
        if let Some(event) = self.pending_events.pop_front() {
            self.pending_event_bytes = self.pending_event_bytes.saturating_sub(event.len());
            return Ok(Some(event));
        }
        if self.end_of_stream.is_some() {
            return Ok(None);
        }
        let (_cancellation_guard, mut cancellation_signal) = oneshot::channel::<()>();

        loop {
            if cx.checkpoint().is_err() {
                self.close();
                return Err(ModernHttpExecutorError::Cancelled);
            }
            let frame = {
                let response = self
                    .response
                    .as_mut()
                    .ok_or(ModernHttpExecutorError::SseStreamClosed)?;
                let mut cancellation = std::pin::pin!(cancellation_signal.recv(cx));
                poll_fn(|task_cx| {
                    if cancellation.as_mut().poll(task_cx).is_ready() {
                        return Poll::Ready(Err(()));
                    }
                    match Pin::new(&mut response.body).poll_frame(task_cx) {
                        Poll::Ready(frame) => Poll::Ready(Ok(frame)),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await
            };
            let frame = match frame {
                Ok(frame) => frame,
                Err(()) => {
                    self.close();
                    return Err(ModernHttpExecutorError::Cancelled);
                }
            };
            let frame = match reject_body_frame_after_cancellation(cx, frame) {
                Ok(frame) => frame,
                Err(ModernHttpExecutorError::Cancelled) => {
                    self.close();
                    return Err(ModernHttpExecutorError::Cancelled);
                }
                Err(error) => return Err(error),
            };
            let Some(frame) = frame else {
                let parser = self
                    .parser
                    .take()
                    .ok_or(ModernHttpExecutorError::SseStreamClosed)?;
                let end_of_stream = parser.finish().map_err(ModernHttpExecutorError::SseParse)?;
                self.response = None;
                self.end_of_stream = Some(end_of_stream);
                return Ok(None);
            };
            let frame = match frame {
                Ok(frame) => frame,
                Err(_) => {
                    self.close();
                    return Err(ModernHttpExecutorError::ResponseBodyReadFailed);
                }
            };
            let Some(mut data) = frame.into_data() else {
                continue;
            };

            while data.has_remaining() {
                let chunk = data.chunk();
                self.push_body_frame(chunk)?;
                data.advance(chunk.len());
            }
            if let Some(event) = self.pending_events.pop_front() {
                self.pending_event_bytes = self.pending_event_bytes.saturating_sub(event.len());
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
    #[cfg(feature = "tasks")]
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
        code: JsonInteger,
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
    /// The caller cancelled this request-owned listener context.
    CallerCancelled { request_id: RequestId },
    /// Server cancellation notifications are invalid on a modern HTTP SSE
    /// response stream; response-body closure is the only cancellation signal.
    ServerCancellationOnHttp,
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
            Self::CallerCancelled { request_id } => write!(
                formatter,
                "subscriptions/listen request {request_id:?} was cancelled by the caller"
            ),
            Self::ServerCancellationOnHttp => formatter.write_str(
                "subscriptions/listen received an invalid server cancellation notification over HTTP",
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
            | Self::CallerCancelled { .. }
            | Self::ServerCancellationOnHttp
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

fn decode_final_subscriptions_terminal(
    core_request: &CoreRequest,
    response: JsonRpcResponse,
    result_source: Option<&str>,
    expected_id: RequestId,
) -> Result<
    (RequestId, CompleteResult<FinalSubscriptionsListenResult>),
    ModernHttpSubscriptionListenError,
> {
    if !response
        .id
        .as_ref()
        .is_some_and(|response_id| response_id.correlates_with(&expected_id))
    {
        return Err(ModernHttpSubscriptionListenError::ResponseIdMismatch {
            expected: expected_id,
            actual: response.id,
        });
    }
    if let Some(error) = response.error.as_ref() {
        return Err(ModernHttpSubscriptionListenError::RemoteError {
            code: error.code.clone(),
            message: error.message.clone(),
        });
    }
    let result_source = result_source.ok_or_else(|| {
        ModernHttpSubscriptionListenError::TerminalResult(CoreDispatchError::InvalidResult {
            era: core_request.era(),
            method: core_request.method(),
        })
    })?;
    // The protocol decoder correctly rejects a response whose result metadata
    // names a different subscription, but that generic rejection would erase
    // the HTTP listener's more useful expected/actual diagnostic. Inspect only
    // this already-correlated terminal member first; malformed or absent
    // metadata still falls through to the authoritative protocol decoder.
    if let Some(subscription_id) = serde_json::from_str::<serde_json::Value>(result_source)
        .ok()
        .and_then(|result| result.get("_meta").cloned())
        .and_then(|metadata| metadata.get(FINAL_SUBSCRIPTION_ID_META_KEY).cloned())
        .and_then(|subscription_id| serde_json::from_value::<RequestId>(subscription_id).ok())
        && !subscription_id.correlates_with(&expected_id)
    {
        return Err(ModernHttpSubscriptionListenError::TerminalIdMismatch {
            expected: expected_id,
            actual: subscription_id,
        });
    }
    let result = core_request
        .decode_response_result(&response, result_source)
        .map_err(ModernHttpSubscriptionListenError::TerminalResult)?;
    let CoreResult::Final(FinalCoreResult::SubscriptionsListen {
        result: terminal,
        subscription_id,
        ..
    }) = result
    else {
        return Err(ModernHttpSubscriptionListenError::UnexpectedTerminalResult);
    };
    if !subscription_id.correlates_with(&expected_id) {
        return Err(ModernHttpSubscriptionListenError::TerminalIdMismatch {
            expected: expected_id,
            actual: subscription_id,
        });
    }
    Ok((subscription_id, terminal))
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
    if !subscription_id.correlates_with(expected_id) {
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

    #[cfg(feature = "tasks")]
    {
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
            (Some(_) | None, None) => {}
        }

        if acknowledged.additional.iter().any(|(name, value)| {
            name != TASK_SUBSCRIPTION_IDS_KEY
                && requested
                    .additional
                    .get(name)
                    .is_none_or(|requested_value| requested_value != value)
        }) {
            return Err(
                ModernHttpSubscriptionListenError::AcknowledgementExtensionFilterNotRequested,
            );
        }
    }

    #[cfg(not(feature = "tasks"))]
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
    /// Modern stateless HTTP forbids server-issued session state.
    ForbiddenResponseSessionHeader,
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
    /// One native HTTP body frame would exceed the bounded pending SSE event count.
    PendingSseEventCountExceeded {
        /// Maximum retained completed SSE payloads.
        maximum_events: usize,
    },
    /// One native HTTP body frame would exceed the bounded pending SSE payload bytes.
    PendingSseEventBytesExceeded {
        /// Maximum retained UTF-8 encoded SSE payload bytes.
        maximum_bytes: usize,
    },
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
            Self::ForbiddenResponseSessionHeader => {
                formatter.write_str("modern stateless HTTP response included MCP-Session-Id")
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
            Self::PendingSseEventCountExceeded { maximum_events } => write!(
                formatter,
                "modern MCP SSE response exceeds the {maximum_events}-event pending limit"
            ),
            Self::PendingSseEventBytesExceeded { maximum_bytes } => write!(
                formatter,
                "modern MCP SSE response exceeds the {maximum_bytes}-byte pending limit"
            ),
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
        self.execute_with_optional_cancellation(cx, None, request)
            .await
    }

    /// Sends one POST while allowing an owning request to abandon the native
    /// exchange before the peer has produced response headers.
    ///
    /// Returning on cancellation drops the still-pending native request
    /// future. That closes only this exchange; it does not cancel the ambient
    /// connection context or unrelated HTTP requests.
    pub(crate) async fn execute_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: &ModernHttpRequest,
    ) -> Result<ModernHttpResponseStream, ModernHttpExecutorError> {
        self.execute_with_optional_cancellation(cx, Some(cancellation), request)
            .await
    }

    async fn execute_with_optional_cancellation(
        &self,
        cx: &Cx,
        cancellation: Option<&McpRequestCancellation>,
        request: &ModernHttpRequest,
    ) -> Result<ModernHttpResponseStream, ModernHttpExecutorError> {
        if cx.checkpoint().is_err()
            || cancellation.is_some_and(McpRequestCancellation::is_cancel_requested)
        {
            return Err(ModernHttpExecutorError::Cancelled);
        }
        let mut exchange = Box::pin(self.client.request_streaming(
            cx,
            Method::Post,
            request.target(),
            request.headers(),
            request.body().to_vec(),
        ));
        let response = match cancellation {
            Some(cancellation) => {
                let mut cancelled = std::pin::pin!(cancellation.cancelled());
                poll_fn(|task_cx| {
                    if cancelled.as_mut().poll(task_cx).is_ready() {
                        return Poll::Ready(Err(()));
                    }
                    match exchange.as_mut().poll(task_cx) {
                        Poll::Ready(response) => Poll::Ready(Ok(response)),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await
                .map_err(|()| ModernHttpExecutorError::Cancelled)?
                .map_err(map_transport_error)?
            }
            None => exchange.await.map_err(map_transport_error)?,
        };
        if cx.checkpoint().is_err()
            || cancellation.is_some_and(McpRequestCancellation::is_cancel_requested)
        {
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
    client_implementation: Option<fastmcp_protocol::common_types::Implementation>,
    client_capabilities: ClientCapabilities,
    mcp_apps_settings: Option<McpAppsClientSettings>,
    client_extension_runtime: Option<Arc<ClientExtensionRuntime>>,
    /// Discovery is committed before this client is constructed and must not
    /// change for the lifetime of any cloned request handle. Keeping it behind
    /// `Arc`, rather than a mutable lock, makes the final-era binding a type
    /// property instead of a convention.
    discovery_state: Arc<ModernHttpDiscoveryState>,
    executor: ModernHttpExecutor,
    reverse_request_handlers: ReverseRequestHandlers,
}

#[derive(Clone)]
struct ModernHttpDiscoveryState {
    mcp_apps_activation_receipt: Option<fastmcp_protocol::extensions::McpAppsActivationReceipt>,
    server_discovery: ServerDiscoverResult,
    negotiated_extensions: Option<fastmcp_protocol::extensions::NegotiatedExtensionSet>,
}

/// The result of a policy-bound modern HTTP connection attempt.
#[allow(
    clippy::large_enum_variant,
    reason = "this public one-shot connection outcome deliberately returns direct ownership of the selected client; boxing the modern client would add allocation and distort its caller-facing pattern-matching API"
)]
pub enum ModernHttpConnectOutcome {
    /// The probe selected MCP 2026-07-28 and a modern request client is ready.
    Modern(ModernHttpClient),
    /// A recognized disposable modern refusal opened the exact configured
    /// MCP 2024-11-05 SSE GET endpoint and pinned its advertised POST route.
    #[cfg(feature = "legacy-2024-11-05")]
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
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => Some(ProtocolEra::Legacy2024),
        }
    }

    /// Returns the ready modern client when the probe selected the modern era.
    #[must_use]
    pub fn into_modern(self) -> Option<ModernHttpClient> {
        match self {
            Self::Modern(client) => Some(client),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => None,
        }
    }

    /// Returns the ready legacy SSE client when the configured legacy route
    /// was opened after a recognized auto refusal or under `LegacyOnly`.
    #[cfg(feature = "legacy-2024-11-05")]
    #[must_use]
    pub fn into_legacy_sse(self) -> Option<LegacySseHttpClient> {
        match self {
            Self::Modern(_) => None,
            Self::LegacySse(client) => Some(client),
        }
    }
}

/// Errors raised by an ordinary modern HTTP multi-round model-request tool
/// retry (MRTR) operation.
///
/// These operations deliberately use only ordinary final core requests. They
/// neither request nor accept the official Tasks result discriminator.
#[derive(Debug)]
pub enum ModernHttpMrtrError {
    /// The shared cancellation, deadline, continuation, or input bound refused
    /// the operation before another request could be committed.
    Driver(McpError),
    /// Constructing or issuing an ordinary modern core request failed.
    Request(ModernHttpClientError),
    /// A request-scoped SSE response failed final-core admission or collection.
    Listener(ModernHttpFinalCoreListenError),
    /// A JSON response failed strict JSON-RPC admission.
    JsonRpcAdmission(JsonRpcAdmissionError),
    /// A JSON response did not retain the request ID for its MRTR round.
    ResponseIdMismatch {
        /// The immutable ID assigned to the outgoing round.
        expected: RequestId,
        /// The response ID observed on the wire.
        actual: Option<RequestId>,
    },
    /// A JSON-RPC request frame appeared where this round requires a response.
    UnexpectedResponseMessage,
    /// A peer terminated the round with a JSON-RPC error.
    RemoteError { code: JsonInteger, message: String },
    /// A successful JSON response did not retain its result source.
    MissingResult,
    /// The ordinary method-specific result contradicted the selected core contract.
    TypedResult(CoreDispatchError),
    /// The ordinary request unexpectedly decoded to a non-final core result.
    UnexpectedCoreResult,
    /// A continuation supplied an invalid JSON-RPC request ID.
    InvalidRequestId { request_id: RequestId },
    /// A continuation attempted to reuse an ID from an earlier round.
    ReusedRequestId { request_id: RequestId },
    /// An ordinary MRTR request received a body lane that cannot contain one
    /// terminal final core result.
    UnexpectedResponseKind { actual: ModernHttpResponseKind },
    /// A `tools/call` response selected the Tasks-only result branch even
    /// though this operation did not negotiate Tasks.
    TasksResultRequiresNegotiatedOperation,
}

impl fmt::Display for ModernHttpMrtrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Driver(error) => error.fmt(formatter),
            Self::Request(error) => error.fmt(formatter),
            Self::Listener(error) => error.fmt(formatter),
            Self::JsonRpcAdmission(error) => {
                write!(
                    formatter,
                    "ordinary HTTP MRTR response failed JSON-RPC admission: {error}"
                )
            }
            Self::ResponseIdMismatch { expected, actual } => write!(
                formatter,
                "ordinary HTTP MRTR response ID {actual:?} did not match request {expected:?}"
            ),
            Self::UnexpectedResponseMessage => formatter
                .write_str("ordinary HTTP MRTR received a JSON-RPC request, not a response"),
            Self::RemoteError { code, message } => write!(
                formatter,
                "ordinary HTTP MRTR failed with JSON-RPC {code}: {message}"
            ),
            Self::MissingResult => {
                formatter.write_str("ordinary HTTP MRTR response omitted its result")
            }
            Self::TypedResult(error) => {
                write!(formatter, "ordinary HTTP MRTR result is invalid: {error}")
            }
            Self::UnexpectedCoreResult => {
                formatter.write_str("ordinary HTTP MRTR decoded to a non-final core result")
            }
            Self::InvalidRequestId { request_id } => write!(
                formatter,
                "ordinary HTTP MRTR requires a valid request ID, received {request_id:?}"
            ),
            Self::ReusedRequestId { request_id } => write!(
                formatter,
                "ordinary HTTP MRTR continuation reused request ID {request_id:?}"
            ),
            Self::UnexpectedResponseKind { actual } => write!(
                formatter,
                "ordinary HTTP MRTR requires JSON or SSE, received {actual:?}"
            ),
            Self::TasksResultRequiresNegotiatedOperation => formatter.write_str(
                "ordinary HTTP MRTR received a Tasks-only result without Tasks negotiation",
            ),
        }
    }
}

impl std::error::Error for ModernHttpMrtrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Driver(error) => Some(error),
            Self::Request(error) => Some(error),
            Self::Listener(error) => Some(error),
            Self::JsonRpcAdmission(error) => Some(error),
            Self::TypedResult(error) => Some(error),
            Self::InvalidRequestId { .. }
            | Self::ReusedRequestId { .. }
            | Self::UnexpectedResponseKind { .. }
            | Self::ResponseIdMismatch { .. }
            | Self::UnexpectedResponseMessage
            | Self::RemoteError { .. }
            | Self::MissingResult
            | Self::UnexpectedCoreResult
            | Self::TasksResultRequiresNegotiatedOperation => None,
        }
    }
}

/// Exact MCP 2024-11-05 connection state retained by [`ClientHttpConnection`].
///
/// Its fields are deliberately private so a legacy connection cannot expose
/// crate-internal extension-admission state as part of the public API.
#[cfg(feature = "legacy-2024-11-05")]
pub struct LegacySseConnection {
    client: LegacySseHttpClient,
    negotiated_protocol_version: Option<String>,
    client_capabilities: ClientCapabilities,
    reverse_request_handlers: ReverseRequestHandlers,
    cancelled_response_ids: VecDeque<RequestId>,
    persistent_receiver: Option<LegacySsePersistentReceiver>,
    client_extension_runtime: Option<Arc<ClientExtensionRuntime>>,
}

#[cfg(not(feature = "legacy-2024-11-05"))]
struct LegacySseConnection {
    client: LegacySseHttpClient,
    negotiated_protocol_version: Option<String>,
    client_capabilities: ClientCapabilities,
    reverse_request_handlers: ReverseRequestHandlers,
    cancelled_response_ids: VecDeque<RequestId>,
    persistent_receiver: Option<LegacySsePersistentReceiver>,
    client_extension_runtime: Option<Arc<ClientExtensionRuntime>>,
}

/// A connected client HTTP transport selected by its immutable protocol plan.
///
/// Auto performs the modern probe and, only for an authorized refusal, opens
/// the exact configured legacy SSE route. Callers use one connection and
/// request method; they do not classify the probe result themselves.
#[allow(
    clippy::large_enum_variant,
    reason = "this public dual-era connection deliberately retains each selected transport inline; boxing only the larger era would distort direct transport access and pattern matching throughout the client API"
)]
pub enum ClientHttpConnection {
    /// Stateless MCP 2026-07-28 POST transport.
    Modern(ModernHttpClient),
    /// Exact MCP 2024-11-05 SSE plus message POST transport.
    #[cfg(feature = "legacy-2024-11-05")]
    LegacySse(LegacySseConnection),
}

/// One response returned through `ClientHttpConnection::request`.
#[allow(
    clippy::large_enum_variant,
    reason = "this public dual-era response deliberately returns each typed transport payload directly; boxing the modern stream would add an avoidable allocation and alter the established public match surface"
)]
pub enum ClientHttpResponse {
    /// The still-live HTTP response from a stateless modern POST.
    Modern(ModernHttpResponseStream),
    /// One strict JSON-RPC response received over the exact legacy SSE stream.
    #[cfg(feature = "legacy-2024-11-05")]
    Legacy(JsonRpcMessage),
}

/// The already-proven request construction lane used by the shared bounded
/// JSON response collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModernRequestAdmission<'a> {
    Core(&'a str),
    FinalExtension(&'a str),
}

/// Immutable evidence that one exact-2024 request POST was acknowledged.
///
/// A [`LegacyHttpRequest`] exists only after this receipt has been created.
/// In particular, its cancellation operation can never emit a
/// `notifications/cancelled` frame for a request whose POST was not accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(feature = "legacy-2024-11-05")]
pub struct LegacyHttpRequestCommit {
    request_id: RequestId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(not(feature = "legacy-2024-11-05"))]
struct LegacyHttpRequestCommit {
    request_id: RequestId,
}

impl LegacyHttpRequestCommit {
    /// Returns the exact JSON-RPC ID whose POST acknowledgement was observed.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }
}

/// One committed exact-2024 HTTP request with exclusive ownership of its
/// response waiter.
///
/// The handle borrows neither [`ClientHttpConnection`] nor the SSE ingress
/// reader. It may therefore be awaited or cancelled while sibling request
/// handles remain live. Dropping an unfinished handle retains a bounded
/// tombstone so the connection-owned reader drains its late terminal frame.
#[cfg(feature = "legacy-2024-11-05")]
pub struct LegacyHttpRequest {
    commit: LegacyHttpRequestCommit,
    key: CorrelationKey,
    receiver: oneshot::Receiver<LegacyPersistentResponse>,
    state: Arc<std::sync::Mutex<LegacySsePersistentState>>,
    outbound: LegacySseHttpOutbound,
    terminal: bool,
}

#[cfg(not(feature = "legacy-2024-11-05"))]
struct LegacyHttpRequest {
    commit: LegacyHttpRequestCommit,
    key: CorrelationKey,
    receiver: oneshot::Receiver<LegacyPersistentResponse>,
    state: Arc<std::sync::Mutex<LegacySsePersistentState>>,
    outbound: LegacySseHttpOutbound,
    terminal: bool,
}

impl LegacyHttpRequest {
    /// Returns the confirmed POST-commit receipt.
    #[must_use]
    pub const fn commit_receipt(&self) -> &LegacyHttpRequestCommit {
        &self.commit
    }

    /// Awaits this handle's correlated terminal response without borrowing the
    /// owning connection or its independent SSE ingress reader.
    pub async fn wait(&mut self, cx: &Cx) -> Result<JsonRpcMessage, ClientHttpConnectionError> {
        match self.receiver.recv(cx).await {
            Ok(LegacyPersistentResponse::Response(response)) => {
                self.terminal = true;
                Ok(JsonRpcMessage::Response(response))
            }
            Ok(LegacyPersistentResponse::Cancelled) => {
                self.terminal = true;
                Err(ClientHttpConnectionError::LegacyRequestCancelled {
                    request_id: self.commit.request_id.clone(),
                })
            }
            Err(_) => {
                self.retire()?;
                Err(ClientHttpConnectionError::LegacyPersistentReceiverStopped)
            }
        }
    }

    /// Emits one exact-2024 cancellation notification after the request's
    /// POST commit and retires this waiter for late-response draining.
    pub async fn cancel(
        &mut self,
        cx: &Cx,
        reason: Option<String>,
    ) -> Result<(), ClientHttpConnectionError> {
        if self.terminal {
            return Err(ClientHttpConnectionError::LegacyRequestCancelled {
                request_id: self.commit.request_id.clone(),
            });
        }
        if !cancellation_control_is_authorized(self.retire()?) {
            return Err(ClientHttpConnectionError::LegacyRequestNoLongerPending {
                request_id: self.commit.request_id.clone(),
            });
        }
        let params = serde_json::to_value(fastmcp_protocol::CancelledParams {
            request_id: self.commit.request_id.clone(),
            reason,
        })
        .map_err(|_| {
            ClientHttpConnectionError::Legacy(LegacySseHttpClientError::MessageEncodingFailed)
        })?;
        self.outbound
            .send(
                cx,
                &JsonRpcMessage::Request(JsonRpcRequest::notification(
                    fastmcp_protocol::methods::NOTIFICATIONS_CANCELLED,
                    Some(params),
                )),
            )
            .await
            .map_err(|error| ClientHttpConnectionError::Legacy(error.error))
    }

    fn retire(&mut self) -> Result<LegacyPersistentWaiterRetirement, ClientHttpConnectionError> {
        if self.terminal {
            return Ok(LegacyPersistentWaiterRetirement::AlreadyTerminal);
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let retirement = retire_abandoned_persistent_waiter(
            &mut state,
            &self.key,
            self.commit.request_id.clone(),
        )?;
        self.terminal = true;
        Ok(retirement)
    }
}

impl Drop for LegacyHttpRequest {
    fn drop(&mut self) {
        let _ = self.retire();
    }
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
    /// The exact legacy server cancelled the request currently awaiting its
    /// correlated response.
    LegacyRequestCancelled { request_id: RequestId },
    /// A terminal SSE response won the request's cancellation election before
    /// the caller could retire its live waiter. No cancellation control POST
    /// was emitted.
    LegacyRequestNoLongerPending { request_id: RequestId },
    /// Too many late terminal response IDs remain after cancelled legacy
    /// requests, so accepting another cancellation would lose stream alignment.
    LegacyCancelledResponseQueueFull,
    /// The caller attempted to reuse an ID whose cancelled legacy terminal
    /// response has not yet been drained from the shared SSE stream.
    LegacyCancelledRequestStillDraining { request_id: RequestId },
    /// A public legacy request attempted to carry final-only metadata.
    LegacyFinalMetadata { member: &'static str },
    /// A raw legacy request attempted to bypass a configured final extension
    /// descriptor instead of using the negotiated extension request surface.
    RegisteredExtensionMethodRequiresAdmission { method: String },
    /// The frozen client registry or retained discovery result did not admit
    /// a requested final extension method.
    FinalExtensionAdmission(McpError),
    /// Too many interleaved legacy notifications accumulated before a response.
    LegacyNotificationQueueFull,
    /// Too many interleaved legacy notifications or reverse requests arrived
    /// before the correlated response.
    LegacyInterleavedControlFrameLimitExceeded { limit: usize },
    /// The ready legacy SSE reader was unavailable before it could be owned by
    /// its structured receive task.
    LegacyPersistentReceiverUnavailable,
    /// Exact-2024 callback handlers and client capabilities did not describe
    /// the same callable server-to-client surface before SSE ingress started.
    LegacyCallbackConfiguration(McpError),
    /// The ready legacy SSE reader has stopped, so it cannot accept another
    /// locally owned request.
    LegacyPersistentReceiverStopped,
    /// Too many ready-client legacy requests are awaiting their SSE responses.
    LegacyPersistentResponseQueueFull,
    /// The request-scoped legacy HTTP control surface is unavailable on a
    /// modern stateless connection.
    LegacyRequestOperationRequiresLegacy,
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
    /// Modern HTTP cancellation is selected by closing the request-owned
    /// response body, never by posting a second JSON-RPC notification.
    ModernCancellationRequiresResponseClose,
    /// MCP 2026-07-28 does not permit client notification POSTs over HTTP.
    ModernClientNotificationPostUnsupported { method: String },
    /// Final `subscriptions/listen` requires the modern HTTP transport.
    SubscriptionsListenRequiresModern,
    /// A modern subscription response stream failed typed admission or collection.
    SubscriptionsListen(ModernHttpSubscriptionListenError),
    /// An ordinary modern final core response stream failed typed admission or collection.
    FinalCoreListen(ModernHttpFinalCoreListenError),
    /// Ordinary final core response streams require the modern HTTP transport.
    FinalCoreListenRequiresModern,
    /// An ordinary modern HTTP MRTR operation failed.
    Mrtr(ModernHttpMrtrError),
    /// Ordinary modern HTTP MRTR requires the modern HTTP transport.
    MrtrRequiresModern,
    /// Final Tasks-backed `tools/call` requires the modern HTTP transport.
    FinalToolCallRequiresModern,
    /// Official final Tasks lifecycle methods require the modern HTTP transport.
    FinalTasksRequiresModern { method: &'static str },
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
            Self::LegacyRequestCancelled { request_id } => {
                write!(
                    formatter,
                    "legacy SSE server cancellation matched active request {request_id:?}"
                )
            }
            Self::LegacyRequestNoLongerPending { request_id } => write!(
                formatter,
                "legacy request {request_id:?} completed before local cancellation won its election"
            ),
            Self::LegacyCancelledResponseQueueFull => formatter.write_str(
                "legacy SSE retained too many cancelled response IDs before their terminal frames arrived",
            ),
            Self::LegacyCancelledRequestStillDraining { request_id } => write!(
                formatter,
                "legacy request ID {request_id:?} cannot be reused before its cancelled terminal response is drained",
            ),
            Self::LegacyFinalMetadata { member } => write!(
                formatter,
                "exact legacy request cannot carry final-only metadata member {member}"
            ),
            Self::RegisteredExtensionMethodRequiresAdmission { method } => write!(
                formatter,
                "registered final extension method {method} requires the admitted extension request surface"
            ),
            Self::FinalExtensionAdmission(error) => error.fmt(formatter),
            Self::LegacyNotificationQueueFull => formatter.write_str(
                "legacy request received too many interleaved notifications before its response",
            ),
            Self::LegacyInterleavedControlFrameLimitExceeded { limit } => write!(
                formatter,
                "legacy request received more than {limit} interleaved notifications or reverse requests before its response",
            ),
            Self::LegacyPersistentReceiverUnavailable => formatter
                .write_str("ready legacy SSE receiver is unavailable"),
            Self::LegacyCallbackConfiguration(error) => error.fmt(formatter),
            Self::LegacyPersistentReceiverStopped => formatter
                .write_str("ready legacy SSE receiver has stopped"),
            Self::LegacyPersistentResponseQueueFull => formatter
                .write_str("ready legacy SSE response queue is full"),
            Self::LegacyRequestOperationRequiresLegacy => formatter
                .write_str("request-scoped legacy HTTP operations require the legacy SSE transport"),
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
            Self::ModernCancellationRequiresResponseClose => formatter.write_str(
                "modern HTTP cancellation requires closing the request-owned response body",
            ),
            Self::ModernClientNotificationPostUnsupported { method } => write!(
                formatter,
                "modern HTTP does not permit a client notification POST for {method}"
            ),
            Self::SubscriptionsListenRequiresModern => {
                formatter.write_str("subscriptions/listen requires the modern HTTP transport")
            }
            Self::SubscriptionsListen(error) => error.fmt(formatter),
            Self::FinalCoreListen(error) => error.fmt(formatter),
            Self::FinalCoreListenRequiresModern => {
                formatter.write_str("final core response streams require the modern HTTP transport")
            }
            Self::Mrtr(error) => error.fmt(formatter),
            Self::MrtrRequiresModern => {
                formatter.write_str("ordinary HTTP MRTR requires the modern HTTP transport")
            }
            Self::FinalToolCallRequiresModern => formatter
                .write_str("final Tasks-backed tools/call requires the modern HTTP transport"),
            Self::FinalTasksRequiresModern { method } => {
                write!(formatter, "final {method} requires the modern HTTP transport")
            }
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
            | Self::LegacyRequestCancelled { .. }
            | Self::LegacyRequestNoLongerPending { .. }
            | Self::LegacyCancelledResponseQueueFull
            | Self::LegacyCancelledRequestStillDraining { .. }
            | Self::LegacyFinalMetadata { .. }
            | Self::RegisteredExtensionMethodRequiresAdmission { .. }
            | Self::LegacyNotificationQueueFull
            | Self::LegacyInterleavedControlFrameLimitExceeded { .. }
            | Self::LegacyPersistentReceiverUnavailable
            | Self::LegacyPersistentReceiverStopped
            | Self::LegacyPersistentResponseQueueFull
            | Self::LegacyRequestOperationRequiresLegacy
            | Self::ExpectedJsonResponse { .. }
            | Self::UnexpectedResponseMessage { .. }
            | Self::ResponseIdMismatch { .. }
            | Self::ModernNotificationUnexpectedStatus { .. }
            | Self::ModernNotificationUnexpectedBody
            | Self::ModernCancellationRequiresResponseClose
            | Self::ModernClientNotificationPostUnsupported { .. }
            | Self::SubscriptionsListenRequiresModern
            | Self::FinalCoreListenRequiresModern
            | Self::MrtrRequiresModern
            | Self::FinalToolCallRequiresModern
            | Self::FinalTasksRequiresModern { .. } => None,
            Self::LegacyCallbackConfiguration(error) => Some(error),
            Self::FinalExtensionAdmission(error) => Some(error),
            Self::ResponseAdmission(error) => Some(error),
            Self::SubscriptionsListen(error) => Some(error),
            Self::FinalCoreListen(error) => Some(error),
            Self::Mrtr(error) => Some(error),
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
        validate_protocol_plan_feature(&protocol_plan)
            .map_err(ModernHttpClientError::FeatureUnavailable)
            .map_err(ClientHttpConnectionError::Modern)?;
        Self::connect_with_mcp_apps(cx, protocol_plan, client_info, client_capabilities, None).await
    }

    pub(crate) async fn connect_with_mcp_apps(
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        mcp_apps_settings: Option<McpAppsClientSettings>,
    ) -> Result<Self, ClientHttpConnectionError> {
        Self::connect_with_extensions(
            cx,
            protocol_plan,
            client_info,
            client_capabilities,
            mcp_apps_settings,
            None,
        )
        .await
    }

    pub(crate) async fn connect_with_extensions(
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        mcp_apps_settings: Option<McpAppsClientSettings>,
        client_extension_runtime: Option<Arc<ClientExtensionRuntime>>,
    ) -> Result<Self, ClientHttpConnectionError> {
        #[cfg(feature = "legacy-2024-11-05")]
        let legacy_client_capabilities = client_capabilities.clone();
        #[cfg(feature = "legacy-2024-11-05")]
        let legacy_client_extension_runtime = client_extension_runtime.clone();
        match ModernHttpClient::connect_with_extensions(
            cx,
            protocol_plan,
            client_info,
            client_capabilities,
            mcp_apps_settings,
            client_extension_runtime,
        )
        .await
        .map_err(ClientHttpConnectionError::Modern)?
        {
            ModernHttpConnectOutcome::Modern(client) => Ok(Self::Modern(client)),
            #[cfg(feature = "legacy-2024-11-05")]
            ModernHttpConnectOutcome::LegacySse(client) => {
                Ok(Self::LegacySse(LegacySseConnection {
                    client,
                    negotiated_protocol_version: None,
                    client_capabilities: legacy_client_capabilities,
                    reverse_request_handlers: ReverseRequestHandlers::new(),
                    cancelled_response_ids: VecDeque::new(),
                    persistent_receiver: None,
                    client_extension_runtime: legacy_client_extension_runtime,
                }))
            }
        }
    }

    /// Returns the era admitted by this completed connection.
    #[must_use]
    pub const fn selected_protocol_era(&self) -> ProtocolEra {
        match self {
            Self::Modern(_) => ProtocolEra::Modern2026,
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => ProtocolEra::Legacy2024,
        }
    }

    /// Returns the exact protocol version validated for this connection.
    ///
    /// Modern selection validates its version during discovery. Exact legacy
    /// selection returns `None` until the high-level client has validated the
    /// `initialize` response and retained its wire value.
    #[must_use]
    pub fn protocol_version(&self) -> Option<&str> {
        match self {
            Self::Modern(_) => Some(MODERN_PROTOCOL_VERSION),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(LegacySseConnection {
                negotiated_protocol_version,
                ..
            }) => negotiated_protocol_version.as_deref(),
        }
    }

    /// Records the exact legacy version after its `initialize` response has
    /// been validated by the high-level lifecycle.
    #[cfg(feature = "legacy-2024-11-05")]
    pub(crate) fn record_legacy_negotiated_protocol_version(&mut self, version: String) {
        let Self::LegacySse(LegacySseConnection {
            negotiated_protocol_version,
            ..
        }) = self
        else {
            unreachable!("only a legacy initialization can record a legacy protocol version");
        };
        debug_assert!(
            negotiated_protocol_version.is_none(),
            "legacy protocol version is immutable after initialization"
        );
        *negotiated_protocol_version = Some(version);
    }

    /// Returns the immutable policy and endpoint bundle used for this connection.
    #[must_use]
    pub const fn protocol_plan(&self) -> &ClientProtocolPlan {
        match self {
            Self::Modern(client) => client.protocol_plan(),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(LegacySseConnection { client, .. }) => client.protocol_plan(),
        }
    }

    /// Returns the exact discovery result that selected the modern era.
    ///
    /// Exact legacy HTTP sessions use `initialize` rather than
    /// `server/discover`, so they deliberately have no counterpart here.
    #[must_use]
    pub fn server_discovery(&self) -> Option<ServerDiscoverResult> {
        match self {
            Self::Modern(client) => Some(client.server_discovery()),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => None,
        }
    }

    /// Retains modern Implementation extras on the modern HTTP connection.
    pub fn set_client_implementation(
        &mut self,
        implementation: fastmcp_protocol::common_types::Implementation,
    ) {
        if let Self::Modern(client) = self {
            client.set_client_implementation(implementation);
        }
    }

    /// Returns whether final discovery activated the official MCP Apps extension.
    #[cfg(feature = "apps")]
    #[must_use]
    pub fn mcp_apps_active(&self) -> bool {
        match self {
            Self::Modern(client) => client.mcp_apps_active(),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => false,
        }
    }

    /// Returns the retained generic extension set for a modern connection.
    #[must_use]
    pub fn negotiated_extensions(
        &self,
    ) -> Option<fastmcp_protocol::extensions::NegotiatedExtensionSet> {
        match self {
            Self::Modern(client) => client.negotiated_extensions(),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => None,
        }
    }

    pub(crate) fn admit_final_extension_method(
        &self,
        extension_id: &fastmcp_protocol::ExtensionId,
        method: &str,
    ) -> McpResult<()> {
        match self {
            Self::Modern(client) => client.admit_final_extension_method(extension_id, method),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => Err(McpError::invalid_params(
                "Final client extensions are unavailable in exact MCP 2024-11-05",
            )),
        }
    }

    #[cfg(feature = "apps")]
    pub(crate) fn mcp_apps_activation_receipt(
        &self,
    ) -> Option<fastmcp_protocol::extensions::McpAppsActivationReceipt> {
        match self {
            Self::Modern(client) => client.mcp_apps_activation_receipt(),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => None,
        }
    }

    /// Pops the oldest server notification interleaved before a legacy request response.
    ///
    /// Modern stateless HTTP bodies do not share this legacy SSE queue.
    #[must_use]
    #[cfg(feature = "legacy-2024-11-05")]
    pub fn take_legacy_notification(&mut self) -> Option<JsonRpcRequest> {
        match self {
            Self::Modern(_) => None,
            Self::LegacySse(LegacySseConnection {
                client,
                persistent_receiver,
                ..
            }) => persistent_receiver
                .as_ref()
                .and_then(LegacySsePersistentReceiver::take_notification)
                .or_else(|| client.take_notification()),
        }
    }

    /// Replaces the retained exact-2024 capability set before initialization.
    ///
    /// Auto negotiation intentionally discovers with the caller's ordinary
    /// capabilities. Callback-derived capabilities belong only to the legacy
    /// initialize envelope selected after that discovery decision.
    #[cfg(feature = "legacy-2024-11-05")]
    pub(crate) fn set_legacy_client_capabilities(&mut self, capabilities: ClientCapabilities) {
        let Self::LegacySse(LegacySseConnection {
            client_capabilities,
            ..
        }) = self
        else {
            return;
        };
        *client_capabilities = capabilities;
    }

    /// Starts the exact-2024 reader owned by a ready high-level HTTP client.
    ///
    /// Initialization remains request-owned so its response cannot race this
    /// receiver. Once ready, one structured child exclusively drains the SSE
    /// stream, retains bounded notifications, and services eligible reverse
    /// requests even while no ordinary client request is pending.
    #[cfg(feature = "legacy-2024-11-05")]
    pub(crate) fn start_legacy_receive_pump(
        &mut self,
        cx: &Cx,
    ) -> Result<(), ClientHttpConnectionError> {
        let Self::LegacySse(LegacySseConnection {
            client,
            client_capabilities,
            reverse_request_handlers,
            persistent_receiver,
            ..
        }) = self
        else {
            return Ok(());
        };
        if persistent_receiver.is_some() {
            return Ok(());
        }
        let reader = client
            .take_reader()
            .ok_or(ClientHttpConnectionError::LegacyPersistentReceiverUnavailable)?;
        let outbound = client.outbound();
        *persistent_receiver = Some(LegacySsePersistentReceiver::start(
            cx,
            reader,
            outbound,
            client_capabilities.clone(),
            reverse_request_handlers.clone(),
        )?);
        Ok(())
    }

    /// Starts one exact-2024 request-scoped HTTP operation.
    ///
    /// The returned handle owns the registered response waiter and its
    /// confirmed POST-commit receipt. Once returned, the caller may await or
    /// cancel it without holding `&mut self`; the connection-owned SSE reader
    /// continues to route cancellations, reverse requests, sibling progress,
    /// and late terminal responses independently.
    #[cfg(feature = "legacy-2024-11-05")]
    pub async fn start_legacy_request(
        &mut self,
        cx: &Cx,
        method: impl AsRef<str>,
        parameters: serde_json::Value,
        request_id: RequestId,
    ) -> Result<LegacyHttpRequest, ClientHttpConnectionError> {
        let method = method.as_ref();
        if !matches!(self, Self::LegacySse(_)) {
            return Err(ClientHttpConnectionError::LegacyRequestOperationRequiresLegacy);
        }
        self.start_legacy_receive_pump(cx)?;
        let Self::LegacySse(LegacySseConnection {
            client_extension_runtime,
            persistent_receiver,
            ..
        }) = self
        else {
            unreachable!("legacy transport was checked before starting its receiver");
        };
        if client_extension_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.owns_method(method))
        {
            return Err(
                ClientHttpConnectionError::RegisteredExtensionMethodRequiresAdmission {
                    method: method.to_owned(),
                },
            );
        }
        reject_final_only_legacy_request_metadata(&parameters)?;
        persistent_receiver
            .as_ref()
            .expect("legacy receive pump installs its persistent receiver")
            .start_request(cx, method, parameters, request_id)
            .await
    }

    /// Configures exact MCP 2024-11-05 reverse-request handlers on this raw
    /// HTTP connection.
    ///
    /// The supplied handlers must exactly match the client capabilities that
    /// were retained for the legacy `initialize` request. Configure this before
    /// issuing that request: a ready [`crate::HttpClient`] has already completed
    /// initialization and therefore cannot safely change this callable surface.
    #[cfg(feature = "legacy-2024-11-05")]
    pub fn set_legacy_reverse_request_handlers(
        &mut self,
        handlers: ReverseRequestHandlers,
    ) -> fastmcp_core::McpResult<()> {
        let Self::LegacySse(LegacySseConnection {
            client_capabilities,
            reverse_request_handlers,
            ..
        }) = self
        else {
            return Err(fastmcp_core::McpError::invalid_params(
                "exact MCP 2024-11-05 reverse request handlers require the legacy HTTP transport",
            ));
        };
        handlers.validate_legacy_capabilities(client_capabilities)?;
        *reverse_request_handlers = handlers;
        Ok(())
    }

    /// Installs modern reverse-request handlers on a selected modern HTTP client.
    pub fn set_modern_reverse_request_handlers(
        &mut self,
        handlers: ReverseRequestHandlers,
    ) -> fastmcp_core::McpResult<()> {
        let Self::Modern(client) = self else {
            return Err(fastmcp_core::McpError::invalid_params(
                "modern reverse request handlers require the modern HTTP transport",
            ));
        };
        client.reverse_request_handlers = handlers;
        Ok(())
    }

    /// Returns the installed modern reverse handlers when this connection is
    /// the MCP 2026-07-28 HTTP transport.
    pub(crate) fn modern_reverse_request_handlers(&self) -> Option<&ReverseRequestHandlers> {
        match self {
            Self::Modern(client) => Some(&client.reverse_request_handlers),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => None,
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
        self.request_with_optional_cancellation(cx, None, method, parameters, request_id)
            .await
    }

    async fn request_with_optional_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: Option<&McpRequestCancellation>,
        method: impl AsRef<str>,
        parameters: serde_json::Value,
        request_id: RequestId,
    ) -> Result<ClientHttpResponse, ClientHttpConnectionError> {
        let method = method.as_ref();
        match self {
            Self::Modern(client) => match cancellation {
                Some(cancellation) => client
                    .request_with_cancellation(
                        cx,
                        cancellation,
                        method,
                        parameters,
                        Some(request_id),
                    )
                    .await
                    .map(ClientHttpResponse::Modern)
                    .map_err(ClientHttpConnectionError::Modern),
                None => client
                    .request(cx, method, parameters, Some(request_id))
                    .await
                    .map(ClientHttpResponse::Modern)
                    .map_err(ClientHttpConnectionError::Modern),
            },
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(LegacySseConnection {
                client,
                client_capabilities,
                reverse_request_handlers,
                cancelled_response_ids,
                persistent_receiver,
                client_extension_runtime,
                ..
            }) => {
                if client_extension_runtime
                    .as_ref()
                    .is_some_and(|runtime| runtime.owns_method(method))
                {
                    return Err(
                        ClientHttpConnectionError::RegisteredExtensionMethodRequiresAdmission {
                            method: method.to_owned(),
                        },
                    );
                }
                reject_final_only_legacy_request_metadata(&parameters)?;
                if let Some(receiver) = persistent_receiver.as_ref() {
                    return receiver
                        .request(cx, method, parameters, request_id)
                        .await
                        .map(ClientHttpResponse::Legacy);
                }
                if cancelled_response_ids
                    .iter()
                    .any(|cancelled_id| cancelled_id.correlates_with(&request_id))
                {
                    return Err(
                        ClientHttpConnectionError::LegacyCancelledRequestStillDraining {
                            request_id,
                        },
                    );
                }
                let request = JsonRpcRequest::new(method, Some(parameters), request_id.clone());
                if let Err(error) = client
                    .outbound()
                    .send(cx, &JsonRpcMessage::Request(request))
                    .await
                {
                    let LegacySseOutboundSendError {
                        error,
                        request_may_have_reached_peer,
                    } = error;
                    if request_may_have_reached_peer {
                        if cancelled_response_ids.len() >= MAX_QUEUED_LEGACY_CANCELLED_RESPONSE_IDS
                        {
                            return Err(
                                ClientHttpConnectionError::LegacyCancelledResponseQueueFull,
                            );
                        }
                        cancelled_response_ids.push_back(request_id);
                    }
                    return Err(ClientHttpConnectionError::Legacy(error));
                }
                let mut interleaved_control_frames = 0_usize;
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
                            admit_legacy_interleaved_control_frame(
                                &mut interleaved_control_frames,
                            )?;
                            if matching_legacy_request_cancellation(&notification, &request_id) {
                                if cancelled_response_ids.len()
                                    >= MAX_QUEUED_LEGACY_CANCELLED_RESPONSE_IDS
                                {
                                    return Err(
                                        ClientHttpConnectionError::LegacyCancelledResponseQueueFull,
                                    );
                                }
                                cancelled_response_ids.push_back(request_id.clone());
                                return Err(ClientHttpConnectionError::LegacyRequestCancelled {
                                    request_id,
                                });
                            }
                            client.queue_notification(notification).map_err(|()| {
                                ClientHttpConnectionError::LegacyNotificationQueueFull
                            })?;
                        }
                        JsonRpcMessage::Request(server_request) => {
                            admit_legacy_interleaved_control_frame(
                                &mut interleaved_control_frames,
                            )?;
                            let response = legacy_http_server_request_response(
                                cx,
                                client_capabilities,
                                reverse_request_handlers,
                                &server_request,
                            )
                            .ok_or_else(|| {
                                ClientHttpConnectionError::LegacyUnexpectedMessage {
                                    request_id: request_id.clone(),
                                }
                            })?;
                            client
                                .send(cx, &response)
                                .await
                                .map_err(ClientHttpConnectionError::Legacy)?;
                        }
                        JsonRpcMessage::Response(response) => {
                            if response.id.as_ref().is_some_and(|response_id| {
                                cancelled_response_ids
                                    .iter()
                                    .any(|cancelled_id| cancelled_id.correlates_with(response_id))
                            }) {
                                let response_id = response
                                    .id
                                    .as_ref()
                                    .expect("response ID was checked before removing tombstone");
                                let position = cancelled_response_ids
                                    .iter()
                                    .position(|cancelled_id| {
                                        cancelled_id.correlates_with(response_id)
                                    })
                                    .expect("checked tombstone remains present until removal");
                                cancelled_response_ids.remove(position);
                                continue;
                            }
                            if !response
                                .id
                                .as_ref()
                                .is_some_and(|response_id| response_id.correlates_with(&request_id))
                            {
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
        self.request_json_with_result_source(
            cx,
            method,
            parameters,
            request_id,
            maximum_response_bytes,
        )
        .await
        .map(|(response, _)| response)
    }

    /// Sends one request and returns its strictly admitted response together
    /// with the lossless JSON source of its `result` member.
    ///
    /// A modern JSON response returns `Some(source)` when it has a result. The
    /// source is retained without re-serialization, preserving its member
    /// order and JSON-number lexemes. The response and source originate from
    /// the same admitted body, and the response ID is correlated to
    /// `request_id` before either is returned. Exact legacy SSE responses
    /// retain their established typed behavior and therefore return `None`.
    /// Use [`Self::request_json`] when the source sidecar is not needed.
    pub async fn request_json_with_result_source(
        &mut self,
        cx: &Cx,
        method: impl AsRef<str>,
        parameters: serde_json::Value,
        request_id: RequestId,
        maximum_response_bytes: usize,
    ) -> Result<(JsonRpcResponse, Option<String>), ClientHttpConnectionError> {
        self.request_json_with_result_source_at(
            cx,
            method,
            parameters,
            request_id,
            maximum_response_bytes,
        )
        .await
        .map(|(response, result_source, _, _, _)| (response, result_source))
    }

    /// Sends one request and retains the monotonic receipt instant captured
    /// immediately after strict transport response decoding completes.
    ///
    /// The receipt is intentionally captured before response-envelope routing
    /// and ID correlation. It is crate-visible only so bounded final-cache TTL
    /// accounting can start at ingress without changing the public raw-source
    /// API.
    pub(crate) async fn request_json_with_result_source_at(
        &mut self,
        cx: &Cx,
        method: impl AsRef<str>,
        parameters: serde_json::Value,
        request_id: RequestId,
        maximum_response_bytes: usize,
    ) -> Result<
        (
            JsonRpcResponse,
            Option<String>,
            Instant,
            Vec<ServerNotification>,
            Vec<FinalProgressNotificationParams>,
        ),
        ClientHttpConnectionError,
    > {
        self.request_json_with_result_source_at_inner(
            cx,
            None,
            ModernRequestAdmission::Core(method.as_ref()),
            parameters,
            request_id,
            maximum_response_bytes,
        )
        .await
    }

    /// Sends one generic final extension request through the exact method
    /// descriptor admitted by both the frozen client registry and retained
    /// `server/discover` result.
    ///
    /// Admission, request-ID validation, metadata construction, peer contact,
    /// and correlated response decoding remain one indivisible path. Ordinary
    /// raw requests cannot select this core-method bypass.
    pub(crate) async fn request_final_extension_json_with_result_source_at(
        &mut self,
        cx: &Cx,
        extension_id: &fastmcp_protocol::ExtensionId,
        method: &str,
        parameters: serde_json::Value,
        request_id: RequestId,
        maximum_response_bytes: usize,
    ) -> Result<
        (
            JsonRpcResponse,
            Option<String>,
            Instant,
            Vec<ServerNotification>,
            Vec<FinalProgressNotificationParams>,
        ),
        ClientHttpConnectionError,
    > {
        self.admit_final_extension_method(extension_id, method)
            .map_err(ClientHttpConnectionError::FinalExtensionAdmission)?;
        self.request_json_with_result_source_at_inner(
            cx,
            None,
            ModernRequestAdmission::FinalExtension(method),
            parameters,
            request_id,
            maximum_response_bytes,
        )
        .await
    }

    /// Request-local variant of [`Self::request_json_with_result_source_at`].
    ///
    /// The HTTP exchange and its disposable JSON body are owned by this
    /// cancellation domain, including the wait for response headers.
    pub(crate) async fn request_json_with_result_source_at_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: impl AsRef<str>,
        parameters: serde_json::Value,
        request_id: RequestId,
        maximum_response_bytes: usize,
    ) -> Result<
        (
            JsonRpcResponse,
            Option<String>,
            Instant,
            Vec<ServerNotification>,
            Vec<FinalProgressNotificationParams>,
        ),
        ClientHttpConnectionError,
    > {
        if cancellation.is_cancel_requested() {
            return Err(ClientHttpConnectionError::Modern(
                ModernHttpClientError::Executor(ModernHttpExecutorError::Cancelled),
            ));
        }
        self.request_json_with_result_source_at_inner(
            cx,
            Some(cancellation),
            ModernRequestAdmission::Core(method.as_ref()),
            parameters,
            request_id,
            maximum_response_bytes,
        )
        .await
    }

    async fn request_json_with_result_source_at_inner(
        &mut self,
        cx: &Cx,
        cancellation: Option<&McpRequestCancellation>,
        admission: ModernRequestAdmission<'_>,
        parameters: serde_json::Value,
        request_id: RequestId,
        maximum_response_bytes: usize,
    ) -> Result<
        (
            JsonRpcResponse,
            Option<String>,
            Instant,
            Vec<ServerNotification>,
            Vec<FinalProgressNotificationParams>,
        ),
        ClientHttpConnectionError,
    > {
        let response = match admission {
            ModernRequestAdmission::Core(method) => {
                self.request_with_optional_cancellation(
                    cx,
                    cancellation,
                    method,
                    parameters,
                    request_id.clone(),
                )
                .await?
            }
            ModernRequestAdmission::FinalExtension(method) => {
                let client = match self {
                    Self::Modern(client) => client,
                    #[cfg(feature = "legacy-2024-11-05")]
                    Self::LegacySse(_) => {
                        return Err(ClientHttpConnectionError::FinalExtensionAdmission(
                            McpError::invalid_params(
                                "Final extensions are unavailable in exact MCP 2024-11-05",
                            ),
                        ));
                    }
                };
                debug_assert!(
                    cancellation.is_none(),
                    "the final extension surface has no request-local cancellation entry"
                );
                client
                    .execute_admitted_final_extension_request(
                        cx,
                        method,
                        parameters,
                        request_id.clone(),
                    )
                    .await
                    .map(ClientHttpResponse::Modern)
                    .map_err(ClientHttpConnectionError::Modern)?
            }
        };
        match response {
            #[cfg(feature = "legacy-2024-11-05")]
            ClientHttpResponse::Legacy(JsonRpcMessage::Response(response)) => {
                Ok((response, None, Instant::now(), Vec::new(), Vec::new()))
            }
            #[cfg(feature = "legacy-2024-11-05")]
            ClientHttpResponse::Legacy(JsonRpcMessage::Request(_)) => {
                Err(ClientHttpConnectionError::UnexpectedResponseMessage { request_id })
            }
            ClientHttpResponse::Modern(response) => {
                let kind = response.metadata().kind();
                match kind {
                    ModernHttpResponseKind::Json => {
                        let body = match cancellation {
                            Some(cancellation) => {
                                response
                                    .read_to_end_with_cancellation(
                                        cx,
                                        cancellation,
                                        maximum_response_bytes,
                                    )
                                    .await
                            }
                            None => response.read_to_end(cx, maximum_response_bytes).await,
                        }
                        .map_err(|error| {
                            ClientHttpConnectionError::Modern(ModernHttpClientError::Executor(
                                error,
                            ))
                        })?;
                        admit_modern_json_response_body(&body, &request_id, maximum_response_bytes)
                            .map(|(response, result_source, receipt)| {
                                (response, result_source, receipt, Vec::new(), Vec::new())
                            })
                    }
                    ModernHttpResponseKind::Sse => {
                        self.drain_modern_sse_json_response(
                            cx,
                            cancellation,
                            response,
                            request_id,
                            maximum_response_bytes,
                        )
                        .await
                    }
                    actual => Err(ClientHttpConnectionError::ExpectedJsonResponse { actual }),
                }
            }
        }
    }

    async fn drain_modern_sse_json_response(
        &mut self,
        cx: &Cx,
        cancellation: Option<&McpRequestCancellation>,
        response: ModernHttpResponseStream,
        request_id: RequestId,
        maximum_response_bytes: usize,
    ) -> Result<
        (
            JsonRpcResponse,
            Option<String>,
            Instant,
            Vec<ServerNotification>,
            Vec<FinalProgressNotificationParams>,
        ),
        ClientHttpConnectionError,
    > {
        let Self::Modern(client) = self else {
            return Err(ClientHttpConnectionError::ExpectedJsonResponse {
                actual: ModernHttpResponseKind::Sse,
            });
        };
        let limits = SseLimits::new(
            maximum_response_bytes.max(1_024),
            maximum_response_bytes.max(4_096),
            32,
        )
        .ok_or(ClientHttpConnectionError::ExpectedJsonResponse {
            actual: ModernHttpResponseKind::Sse,
        })?;
        let mut stream = response.into_sse_stream(limits).map_err(|error| {
            ClientHttpConnectionError::Modern(ModernHttpClientError::Executor(error))
        })?;
        let mut interleaved_control_frames = 0_usize;
        let mut server_notifications = Vec::new();
        let mut progress_notifications = Vec::new();
        loop {
            if cx.checkpoint().is_err()
                || cancellation.is_some_and(McpRequestCancellation::is_cancel_requested)
            {
                return Err(ClientHttpConnectionError::Modern(
                    ModernHttpClientError::Executor(ModernHttpExecutorError::Cancelled),
                ));
            }
            let event = match stream.next_event(cx).await {
                Ok(Some(event)) => event,
                Ok(None) => {
                    return Err(ClientHttpConnectionError::UnexpectedResponseMessage {
                        request_id,
                    });
                }
                Err(error) => {
                    return Err(ClientHttpConnectionError::Modern(
                        ModernHttpClientError::Executor(error),
                    ));
                }
            };
            let message = decode_strict_jsonrpc_message(event.as_bytes(), maximum_response_bytes)
                .map_err(ClientHttpConnectionError::ResponseAdmission)?;
            match message {
                JsonRpcMessage::Response(response) => {
                    if !response
                        .id
                        .as_ref()
                        .is_some_and(|response_id| response_id.correlates_with(&request_id))
                    {
                        return Err(ClientHttpConnectionError::ResponseIdMismatch {
                            expected: request_id,
                            actual: response.id,
                        });
                    }
                    return admit_modern_json_response_body(
                        event.as_bytes(),
                        &request_id,
                        maximum_response_bytes,
                    )
                    .map(|(response, result_source, receipt)| {
                        (
                            response,
                            result_source,
                            receipt,
                            server_notifications,
                            progress_notifications,
                        )
                    });
                }
                JsonRpcMessage::Request(request) if request.is_notification() => {
                    interleaved_control_frames = interleaved_control_frames.checked_add(1).ok_or(
                        ClientHttpConnectionError::LegacyInterleavedControlFrameLimitExceeded {
                            limit: MAX_MODERN_HTTP_INTERLEAVED_CONTROL_FRAMES,
                        },
                    )?;
                    if interleaved_control_frames > MAX_MODERN_HTTP_INTERLEAVED_CONTROL_FRAMES {
                        return Err(
                            ClientHttpConnectionError::LegacyInterleavedControlFrameLimitExceeded {
                                limit: MAX_MODERN_HTTP_INTERLEAVED_CONTROL_FRAMES,
                            },
                        );
                    }
                    match classify_modern_http_request_scoped_notification(
                        &request,
                        event.as_bytes(),
                    )
                    .map_err(|_| {
                        ClientHttpConnectionError::UnexpectedResponseMessage {
                            request_id: request_id.clone(),
                        }
                    })? {
                        ModernHttpRequestScopedNotification::Server(notification) => {
                            server_notifications.push(notification);
                        }
                        ModernHttpRequestScopedNotification::Progress(progress) => {
                            progress_notifications.push(progress);
                        }
                        ModernHttpRequestScopedNotification::Ignored => {}
                    }
                }
                JsonRpcMessage::Request(server_request) => {
                    interleaved_control_frames = interleaved_control_frames.checked_add(1).ok_or(
                        ClientHttpConnectionError::LegacyInterleavedControlFrameLimitExceeded {
                            limit: MAX_MODERN_HTTP_INTERLEAVED_CONTROL_FRAMES,
                        },
                    )?;
                    if interleaved_control_frames > MAX_MODERN_HTTP_INTERLEAVED_CONTROL_FRAMES {
                        return Err(
                            ClientHttpConnectionError::LegacyInterleavedControlFrameLimitExceeded {
                                limit: MAX_MODERN_HTTP_INTERLEAVED_CONTROL_FRAMES,
                            },
                        );
                    }
                    let Some(reverse_response) = modern_http_server_request_response(
                        cx,
                        &client.reverse_request_handlers,
                        &server_request,
                    ) else {
                        return Err(ClientHttpConnectionError::UnexpectedResponseMessage {
                            request_id,
                        });
                    };
                    let JsonRpcMessage::Response(reverse_response) = reverse_response else {
                        return Err(ClientHttpConnectionError::UnexpectedResponseMessage {
                            request_id,
                        });
                    };
                    client
                        .post_jsonrpc_response(cx, &reverse_response)
                        .await
                        .map_err(ClientHttpConnectionError::Modern)?;
                }
            }
        }
    }

    /// Opens one live final `subscriptions/listen` HTTP stream.
    ///
    /// This operation is unavailable once the immutable connection plan has
    /// selected exact MCP 2024-11-05. Modern streams require one explicit SSE
    /// parser bound so the caller, rather than ambient transport state, fixes
    /// response framing limits.
    pub async fn open_subscriptions_listener(
        &self,
        cx: &Cx,
        request_id: RequestId,
        notifications: SubscriptionFilter,
        limits: SseLimits,
    ) -> Result<ModernHttpSubscriptionListener, ClientHttpConnectionError> {
        match self {
            Self::Modern(client) => client
                .open_subscriptions_listener(cx, request_id, notifications, limits)
                .await
                .map_err(ClientHttpConnectionError::SubscriptionsListen),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => Err(ClientHttpConnectionError::SubscriptionsListenRequiresModern),
        }
    }

    /// Opens one live final `subscriptions/listen` HTTP stream.
    pub async fn listen_subscriptions_typed(
        &self,
        cx: &Cx,
        request_id: RequestId,
        notifications: SubscriptionFilter,
        limits: SseLimits,
    ) -> Result<ModernHttpSubscriptionListenCollector, ClientHttpConnectionError> {
        self.open_subscriptions_listener(cx, request_id, notifications, limits)
            .await?
            .collect(cx)
            .await
            .map_err(ClientHttpConnectionError::SubscriptionsListen)
    }

    /// Opens one live typed final core response stream.
    ///
    /// This is the ordinary request counterpart to
    /// [`Self::open_subscriptions_listener`]. Its collector retains bounded
    /// exact final progress notifications, while live iteration forwards each
    /// notification once and accepts only the terminal response correlated to
    /// `request_id`.
    pub async fn open_final_core_listener(
        &self,
        cx: &Cx,
        method: impl AsRef<str>,
        parameters: serde_json::Value,
        request_id: RequestId,
        limits: SseLimits,
    ) -> Result<ModernHttpFinalCoreListener, ClientHttpConnectionError> {
        match self {
            Self::Modern(client) => client
                .open_final_core_listener(cx, method, parameters, request_id, limits)
                .await
                .map_err(ClientHttpConnectionError::FinalCoreListen),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => Err(ClientHttpConnectionError::FinalCoreListenRequiresModern),
        }
    }

    /// Opens one live typed final `tools/call` response stream.
    pub async fn open_final_tool_call_listener(
        &self,
        cx: &Cx,
        request_id: RequestId,
        name: &str,
        arguments: serde_json::Value,
        limits: SseLimits,
    ) -> Result<ModernHttpFinalCoreListener, ClientHttpConnectionError> {
        self.open_final_core_listener(
            cx,
            TOOLS_CALL,
            serde_json::json!({ "name": name, "arguments": arguments }),
            request_id,
            limits,
        )
        .await
    }

    /// Calls one tool through ordinary modern HTTP and follows bounded MRTR
    /// continuations without negotiating Tasks.
    pub async fn call_tool_with_mrtr_retry<F, I>(
        &self,
        cx: &Cx,
        initial_request_id: RequestId,
        deadline: Instant,
        name: &str,
        arguments: serde_json::Value,
        sse_limits: SseLimits,
        maximum_response_bytes: usize,
        next_request_id: I,
        respond: F,
    ) -> Result<CoreResult, ClientHttpConnectionError>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
        I: FnMut() -> McpResult<RequestId>,
    {
        match self {
            Self::Modern(client) => client
                .call_tool_with_mrtr_retry(
                    cx,
                    initial_request_id,
                    deadline,
                    name,
                    arguments,
                    sse_limits,
                    maximum_response_bytes,
                    next_request_id,
                    respond,
                )
                .await
                .map_err(ClientHttpConnectionError::Mrtr),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => Err(ClientHttpConnectionError::MrtrRequiresModern),
        }
    }

    /// Reads one resource through ordinary modern HTTP and follows bounded
    /// MRTR continuations without negotiating Tasks.
    pub async fn read_resource_with_mrtr_retry<F, I>(
        &self,
        cx: &Cx,
        initial_request_id: RequestId,
        deadline: Instant,
        uri: &str,
        sse_limits: SseLimits,
        maximum_response_bytes: usize,
        next_request_id: I,
        respond: F,
    ) -> Result<CoreResult, ClientHttpConnectionError>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
        I: FnMut() -> McpResult<RequestId>,
    {
        match self {
            Self::Modern(client) => client
                .read_resource_with_mrtr_retry(
                    cx,
                    initial_request_id,
                    deadline,
                    uri,
                    sse_limits,
                    maximum_response_bytes,
                    next_request_id,
                    respond,
                )
                .await
                .map_err(ClientHttpConnectionError::Mrtr),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => Err(ClientHttpConnectionError::MrtrRequiresModern),
        }
    }

    /// Gets one prompt through ordinary modern HTTP and follows bounded MRTR
    /// continuations without negotiating Tasks.
    pub async fn get_prompt_with_mrtr_retry<F, I>(
        &self,
        cx: &Cx,
        initial_request_id: RequestId,
        deadline: Instant,
        name: &str,
        arguments: std::collections::HashMap<String, String>,
        sse_limits: SseLimits,
        maximum_response_bytes: usize,
        next_request_id: I,
        respond: F,
    ) -> Result<CoreResult, ClientHttpConnectionError>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
        I: FnMut() -> McpResult<RequestId>,
    {
        match self {
            Self::Modern(client) => client
                .get_prompt_with_mrtr_retry(
                    cx,
                    initial_request_id,
                    deadline,
                    name,
                    arguments,
                    sse_limits,
                    maximum_response_bytes,
                    next_request_id,
                    respond,
                )
                .await
                .map_err(ClientHttpConnectionError::Mrtr),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => Err(ClientHttpConnectionError::MrtrRequiresModern),
        }
    }

    /// Opens one live typed final `tools/call` response stream after bilateral
    /// Tasks result-discriminator admission.
    #[cfg(feature = "tasks")]
    pub async fn open_final_tasks_tool_call_listener(
        &self,
        cx: &Cx,
        request_id: RequestId,
        name: &str,
        arguments: serde_json::Value,
        limits: SseLimits,
    ) -> Result<ModernHttpFinalCoreListener, ClientHttpConnectionError> {
        self.open_final_tasks_tool_call_listener_with_progress_marker(
            cx, request_id, name, arguments, None, limits,
        )
        .await
    }

    /// Opens a typed final `tools/call` stream while retaining the caller's
    /// progress token in the upstream request metadata.
    #[cfg(feature = "tasks")]
    pub async fn open_final_tasks_tool_call_listener_with_progress_marker(
        &self,
        cx: &Cx,
        request_id: RequestId,
        name: &str,
        arguments: serde_json::Value,
        progress_marker: Option<&fastmcp_protocol::ProgressMarker>,
        limits: SseLimits,
    ) -> Result<ModernHttpFinalCoreListener, ClientHttpConnectionError> {
        match self {
            Self::Modern(client) => client
                .open_final_tasks_tool_call_listener_with_progress_marker(
                    cx,
                    request_id,
                    name,
                    arguments,
                    progress_marker,
                    limits,
                )
                .await
                .map_err(ClientHttpConnectionError::FinalCoreListen),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => Err(ClientHttpConnectionError::FinalCoreListenRequiresModern),
        }
    }

    /// Reads one task through the official final Tasks extension.
    ///
    /// An exact MCP 2024-11-05 connection rejects this before opening its
    /// legacy message endpoint. A modern connection performs version and
    /// bilateral extension admission before its native POST.
    #[cfg(feature = "tasks")]
    pub async fn get_task_final(
        &self,
        cx: &Cx,
        request_id: RequestId,
        task_id: FinalTaskId,
        maximum_response_bytes: usize,
    ) -> Result<FinalGetTaskResult, ClientHttpConnectionError> {
        match self {
            Self::Modern(client) => client
                .get_task_final(cx, request_id, task_id, maximum_response_bytes)
                .await
                .map_err(ClientHttpConnectionError::Modern),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => {
                Err(ClientHttpConnectionError::FinalTasksRequiresModern { method: TASK_GET })
            }
        }
    }

    /// Supplies responses for one final input-required task through the
    /// official Tasks extension.
    ///
    /// An exact MCP 2024-11-05 connection rejects this before opening its
    /// legacy message endpoint. A modern connection validates the retained
    /// task input ledger before its native POST.
    #[cfg(feature = "tasks")]
    pub async fn update_task_final(
        &self,
        cx: &Cx,
        request_id: RequestId,
        task: &FinalTask,
        input_responses: FinalTaskInputResponses,
        maximum_response_bytes: usize,
    ) -> Result<FinalUpdateTaskResult, ClientHttpConnectionError> {
        match self {
            Self::Modern(client) => client
                .update_task_final(
                    cx,
                    request_id,
                    task,
                    input_responses,
                    maximum_response_bytes,
                )
                .await
                .map_err(ClientHttpConnectionError::Modern),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => Err(ClientHttpConnectionError::FinalTasksRequiresModern {
                method: TASK_UPDATE,
            }),
        }
    }

    /// Requests cancellation through the official final Tasks extension.
    ///
    /// An exact MCP 2024-11-05 connection rejects this before opening its
    /// legacy message endpoint.
    #[cfg(feature = "tasks")]
    pub async fn cancel_task_final(
        &self,
        cx: &Cx,
        request_id: RequestId,
        task_id: FinalTaskId,
        maximum_response_bytes: usize,
    ) -> Result<FinalCancelTaskResult, ClientHttpConnectionError> {
        match self {
            Self::Modern(client) => client
                .cancel_task_final(cx, request_id, task_id, maximum_response_bytes)
                .await
                .map_err(ClientHttpConnectionError::Modern),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => Err(ClientHttpConnectionError::FinalTasksRequiresModern {
                method: TASK_CANCEL,
            }),
        }
    }

    /// Calls one tool without projecting away the final result algebra.
    ///
    /// An exact legacy-selected connection rejects this operation before any
    /// request is sent. A modern connection requires bilateral discovery of
    /// the official Tasks result discriminator and returns the exact complete,
    /// task, or input-required branch.
    #[cfg(feature = "tasks")]
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
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(_) => Err(ClientHttpConnectionError::FinalToolCallRequiresModern),
        }
    }

    /// Sends one client notification through the selected transport.
    ///
    /// Exact legacy notifications are posted to the pinned message endpoint
    /// without an ID. MCP 2026-07-28 rejects every client notification over
    /// HTTP before a POST can be opened; client cancellation closes the owned
    /// response body instead.
    pub async fn notify(
        &mut self,
        cx: &Cx,
        method: impl AsRef<str>,
        parameters: Option<serde_json::Value>,
    ) -> Result<(), ClientHttpConnectionError> {
        let method = method.as_ref();
        match self {
            Self::Modern(client) => {
                if method == "notifications/cancelled" {
                    return Err(ClientHttpConnectionError::ModernCancellationRequiresResponseClose);
                }
                let _ = client;
                let _ = cx;
                let _ = parameters;
                Err(
                    ClientHttpConnectionError::ModernClientNotificationPostUnsupported {
                        method: method.to_owned(),
                    },
                )
            }
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(LegacySseConnection { client, .. }) => {
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

/// Admits one server control frame interleaved before a legacy request's
/// correlated response. Counting both notifications and reverse requests
/// prevents an upstream from bypassing the request-owned stream bound by
/// alternating frame kinds.
fn admit_legacy_interleaved_control_frame(
    count: &mut usize,
) -> Result<(), ClientHttpConnectionError> {
    if *count >= MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES {
        return Err(
            ClientHttpConnectionError::LegacyInterleavedControlFrameLimitExceeded {
                limit: MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES,
            },
        );
    }
    *count += 1;
    Ok(())
}

/// Returns whether this exact legacy server cancellation is valid and owns the
/// application request currently awaiting an SSE response.
fn matching_legacy_request_cancellation(
    notification: &JsonRpcRequest,
    active_request_id: &RequestId,
) -> bool {
    let Ok(CancellationWireMessage::Legacy2024 { params, .. }) = CancellationWireMessage::decode(
        ProtocolEra::Legacy2024,
        CancellationSender::Server,
        notification,
    ) else {
        return false;
    };
    params.request_id.correlates_with(active_request_id)
}

fn legacy_cancelled_request_id(notification: &JsonRpcRequest) -> Option<RequestId> {
    let Ok(CancellationWireMessage::Legacy2024 { params, .. }) = CancellationWireMessage::decode(
        ProtocolEra::Legacy2024,
        CancellationSender::Server,
        notification,
    ) else {
        return None;
    };
    Some(params.request_id)
}

/// Produces the exact legacy response to one server-initiated request received
/// while a client HTTP request owns the shared SSE reader.
///
/// The configured callback must match the capability retained for legacy
/// initialization. Sampling and roots are never serviced merely because a
/// handler exists; elicitation remains unavailable in exact MCP 2024-11-05.
fn legacy_http_server_request_response(
    cx: &Cx,
    client_capabilities: &ClientCapabilities,
    handlers: &ReverseRequestHandlers,
    request: &JsonRpcRequest,
) -> Option<JsonRpcMessage> {
    let request_id = request.id.clone()?;
    if request.method.starts_with("notifications/") {
        return crate::invalid_notification_request_response(request);
    }
    if request.method == "ping" {
        return Some(JsonRpcMessage::Response(JsonRpcResponse::success(
            request_id,
            serde_json::json!({}),
        )));
    }

    match request.method.as_str() {
        "sampling/createMessage" if client_capabilities.sampling.is_some() => {
            let Some(handler) = handlers.sampling_create_message.as_ref() else {
                return crate::method_not_found_response(request);
            };
            let result = crate::decode_reverse_request_params(request).and_then(|params| {
                crate::invoke_locked_reverse_request_handler(
                    cx,
                    handler,
                    ReverseRequestCancellation::new(),
                    params,
                )
            });
            Some(crate::reverse_request_response(request_id, result))
        }
        "roots/list" if client_capabilities.roots.is_some() => {
            let Some(handler) = handlers.roots_list.as_ref() else {
                return crate::method_not_found_response(request);
            };
            let result = crate::decode_reverse_request_params(request).and_then(|params| {
                crate::invoke_locked_reverse_request_handler(
                    cx,
                    handler,
                    ReverseRequestCancellation::new(),
                    params,
                )
            });
            Some(crate::reverse_request_response(request_id, result))
        }
        // Exact 2024-11-05 never admitted elicitation. In particular, do not
        // infer it from a newer capability accidentally supplied to this raw
        // HTTP connector.
        "elicitation/create" => crate::method_not_found_response(request),
        _ => crate::method_not_found_response(request),
    }
}

fn admit_modern_json_response_body(
    body: &[u8],
    request_id: &RequestId,
    maximum_response_bytes: usize,
) -> Result<(JsonRpcResponse, Option<String>, Instant), ClientHttpConnectionError> {
    let message = decode_strict_jsonrpc_message(body, maximum_response_bytes)
        .map_err(ClientHttpConnectionError::ResponseAdmission)?;
    let JsonRpcMessage::Response(response) = message else {
        return Err(ClientHttpConnectionError::UnexpectedResponseMessage {
            request_id: request_id.clone(),
        });
    };
    let admission = decode_strict_jsonrpc_response(body, maximum_response_bytes)
        .map_err(ClientHttpConnectionError::ResponseAdmission)?;
    let receipt = Instant::now();
    if admission.response() != &response {
        return Err(ClientHttpConnectionError::ResponseAdmission(
            JsonRpcAdmissionError::InvalidEnvelope,
        ));
    }
    if !response
        .id
        .as_ref()
        .is_some_and(|response_id| response_id.correlates_with(request_id))
    {
        return Err(ClientHttpConnectionError::ResponseIdMismatch {
            expected: request_id.clone(),
            actual: response.id,
        });
    }
    let (_, result_source) = admission.into_parts();
    Ok((response, result_source, receipt))
}

/// Answers one modern server-initiated request received on a request-owned SSE
/// body by invoking the matching typed reverse handler.
fn modern_http_server_request_response(
    cx: &Cx,
    handlers: &ReverseRequestHandlers,
    request: &JsonRpcRequest,
) -> Option<JsonRpcMessage> {
    let request_id = request.id.clone()?;
    if request.method.starts_with("notifications/") {
        return crate::invalid_notification_request_response(request);
    }
    if request.method == "ping" {
        return Some(JsonRpcMessage::Response(JsonRpcResponse::success(
            request_id,
            serde_json::json!({}),
        )));
    }
    match request.method.as_str() {
        "sampling/createMessage" => {
            let Some(handler) = handlers.modern_sampling_create_message.as_ref() else {
                return crate::method_not_found_response(request);
            };
            let result = crate::decode_reverse_request_params::<FinalCreateMessageParams>(request)
                .and_then(|params| {
                    crate::invoke_locked_reverse_request_handler(
                        cx,
                        handler,
                        ReverseRequestCancellation::new(),
                        params,
                    )
                });
            Some(crate::reverse_request_response::<FinalCreateMessageResult>(
                request_id, result,
            ))
        }
        "roots/list" => {
            let Some(handler) = handlers.modern_roots_list.as_ref() else {
                return crate::method_not_found_response(request);
            };
            let result =
                crate::decode_reverse_request_params::<FinalEmbeddedRootsListParams>(request)
                    .and_then(|params| {
                        crate::invoke_locked_reverse_request_handler(
                            cx,
                            handler,
                            ReverseRequestCancellation::new(),
                            params,
                        )
                    });
            Some(crate::reverse_request_response::<
                FinalEmbeddedRootsListResult,
            >(request_id, result))
        }
        "elicitation/create" => {
            let Some(handler) = handlers.modern_elicitation_create.as_ref() else {
                return crate::method_not_found_response(request);
            };
            let result = crate::decode_reverse_request_params::<ElicitRequestParams>(request)
                .and_then(|params| {
                    crate::invoke_locked_reverse_request_handler(
                        cx,
                        handler,
                        ReverseRequestCancellation::new(),
                        params,
                    )
                });
            Some(crate::reverse_request_response::<ElicitResult>(
                request_id, result,
            ))
        }
        _ => crate::method_not_found_response(request),
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
    /// A public constructor selected a protocol policy compiled out of this client.
    FeatureUnavailable(McpError),
    /// A modern reverse request could not be dispatched or encoded.
    ReverseRequestDispatch(McpError),
    /// The reverse-response POST was not accepted by the peer.
    ReverseResponsePostRejected {
        /// HTTP status observed on the reverse-response POST.
        status: u16,
    },
    /// The supplied plan has no configured modern HTTP POST target.
    MissingModernPostTarget,
    /// A normal modern request requires object parameters so final metadata can
    /// be bound without changing the method-specific parameter shape.
    RequestParametersMustBeObject,
    /// A method that requires an `Mcp-Name` header mirror omitted its body
    /// value. This includes core routing values and final Tasks `taskId`s.
    MissingRequestName { method: String },
    /// The caller selected no active final client-to-server method.
    UnsupportedFinalMethod { method: String },
    /// The caller selected a final method that only the server may send.
    ServerInitiatedFinalMethod { method: String },
    /// The caller omitted the request ID required by the selected final method.
    MissingRequestId { method: String },
    /// The caller supplied an ID for a final notification method.
    NotificationHasRequestId { method: String },
    /// MCP 2026-07-28 does not permit client notification POSTs over HTTP.
    ClientNotificationPostUnsupported { method: String },
    /// JSON-RPC or final metadata serialization failed before a native POST.
    RequestEncodingFailed,
    /// The native executor rejected or failed the HTTP exchange.
    Executor(ModernHttpExecutorError),
    /// The immutable-plan classifier rejected the disposable probe.
    Negotiation(ClientHttpNegotiationError),
    /// The peer returned a recognized JSON-RPC error to `server/discover`.
    ///
    /// The code remains a [`JsonInteger`] because JSON-RPC permits integers
    /// beyond the local `i32` compatibility domain.
    DiscoveryRejected {
        /// Exact peer JSON-RPC error code.
        code: JsonInteger,
        /// Peer-provided diagnostic message.
        message: String,
        /// Optional peer JSON-RPC error data.
        data: Option<serde_json::Value>,
    },
    /// The recognized response was not the exact typed discovery reply.
    InvalidDiscoveryResponse,
    /// The typed final discovery reply did not advertise the final version
    /// selected for this modern HTTP connection.
    DiscoveryDoesNotAdvertiseModernProtocol,
    /// The builder-owned generic extension registry could not negotiate the
    /// retained final discovery settings.
    ClientExtensionNegotiation { message: String },
    /// The configured native legacy SSE connection could not be opened or
    /// safely used after policy selected its exact endpoint bundle.
    #[cfg(feature = "legacy-2024-11-05")]
    LegacySse(LegacySseHttpClientError),
    /// The supplied request ID is not a valid JSON-RPC correlation key.
    InvalidRequestId,
    /// The retained discovery response did not admit the official Tasks
    /// result discriminator with exact bilateral empty settings.
    TasksNegotiation,
    /// The retained final discovery response did not bilaterally admit this
    /// official Tasks lifecycle method with exact empty settings.
    TasksMethodNegotiation { method: &'static str },
    /// The caller supplied an invalid JSON-RPC correlation key for an official
    /// final Tasks lifecycle request.
    InvalidTasksRequestId { method: &'static str },
    /// Constructing or validating the exact official Tasks request failed
    /// before any native HTTP exchange began.
    TasksRequestEncoding { method: &'static str },
    /// `tasks/update` requires an `input_required` task returned by this peer.
    TasksUpdateRequiresInputRequired,
    /// `tasks/update` responses did not match the retained task input ledger.
    TasksUpdateInputMismatch,
    /// A final Tasks response body was not one strictly admitted JSON-RPC
    /// response envelope.
    InvalidTasksJsonRpcResponse {
        /// Exact official Tasks method that received the malformed response.
        method: &'static str,
        /// The strict admission failure.
        error: JsonRpcAdmissionError,
    },
    /// A final Tasks response did not retain the outgoing request ID.
    TasksResponseIdMismatch {
        /// Exact official Tasks method that received the contradictory response.
        method: &'static str,
        /// The immutable outgoing request ID.
        expected: RequestId,
        /// The response ID observed on the wire.
        actual: Option<RequestId>,
    },
    /// The server returned a JSON-RPC error to an official Tasks lifecycle request.
    TasksRemoteError {
        /// Exact official Tasks method that received the error.
        method: &'static str,
        /// Server-provided JSON-RPC code.
        code: JsonInteger,
        /// Server-provided JSON-RPC message.
        message: String,
    },
    /// A successful official Tasks lifecycle response did not contain a
    /// lossless result payload.
    TasksResultMissing { method: &'static str },
    /// A successful official Tasks lifecycle response did not match its exact
    /// typed result envelope.
    TasksResultDecode { method: &'static str },
    /// `tasks/get` returned a task ID other than the one requested.
    #[cfg(feature = "tasks")]
    TasksGetIdMismatch {
        /// Task ID retained from the outgoing request.
        expected: FinalTaskId,
        /// Task ID decoded from the peer result.
        actual: FinalTaskId,
    },
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
    RemoteError { code: JsonInteger, message: String },
    /// The response contradicted the final typed core result contract.
    TypedResult(CoreDispatchError),
    /// The decoded response was not one final `tools/call` result branch.
    UnexpectedToolCallResult,
}

impl fmt::Display for ModernHttpClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FeatureUnavailable(error) => error.fmt(formatter),
            Self::ReverseRequestDispatch(error) => error.fmt(formatter),
            Self::ReverseResponsePostRejected { status } => write!(
                formatter,
                "modern HTTP reverse-response POST was rejected with status {status}"
            ),
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
            Self::ClientNotificationPostUnsupported { method } => write!(
                formatter,
                "modern HTTP does not permit a client notification POST for {method}"
            ),
            Self::RequestEncodingFailed => {
                formatter.write_str("modern MCP request encoding failed")
            }
            Self::Executor(error) => error.fmt(formatter),
            Self::Negotiation(error) => error.fmt(formatter),
            Self::DiscoveryRejected { code, message, .. } => {
                write!(
                    formatter,
                    "server/discover failed with JSON-RPC {code}: {message}"
                )
            }
            Self::InvalidDiscoveryResponse => {
                formatter.write_str("server/discover returned an invalid final response")
            }
            Self::DiscoveryDoesNotAdvertiseModernProtocol => {
                formatter.write_str("server/discover did not advertise MCP 2026-07-28")
            }
            Self::ClientExtensionNegotiation { message } => {
                write!(
                    formatter,
                    "final client extension negotiation failed: {message}"
                )
            }
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(error) => error.fmt(formatter),
            Self::InvalidRequestId => {
                formatter.write_str("final HTTP tools/call requires a valid JSON-RPC request ID")
            }
            Self::TasksNegotiation => formatter
                .write_str("final HTTP tools/call Tasks result was not bilaterally negotiated"),
            Self::TasksMethodNegotiation { method } => write!(
                formatter,
                "final HTTP {method} was not bilaterally admitted by the official Tasks extension"
            ),
            Self::InvalidTasksRequestId { method } => {
                write!(
                    formatter,
                    "final HTTP {method} requires a valid JSON-RPC request ID"
                )
            }
            Self::TasksRequestEncoding { method } => {
                write!(formatter, "final HTTP {method} request encoding failed")
            }
            Self::TasksUpdateRequiresInputRequired => {
                formatter.write_str("tasks/update requires an input_required final task")
            }
            Self::TasksUpdateInputMismatch => formatter.write_str(
                "tasks/update inputResponses do not match the retained task input requests",
            ),
            Self::InvalidTasksJsonRpcResponse { method, error } => write!(
                formatter,
                "final HTTP {method} response failed JSON-RPC admission: {error}"
            ),
            Self::TasksResponseIdMismatch {
                method,
                expected,
                actual,
            } => write!(
                formatter,
                "final HTTP {method} response ID {actual:?} did not match request {expected:?}"
            ),
            Self::TasksRemoteError {
                method,
                code,
                message,
            } => write!(
                formatter,
                "final HTTP {method} failed with JSON-RPC {code}: {message}"
            ),
            Self::TasksResultMissing { method } => {
                write!(formatter, "final HTTP {method} response omitted its result")
            }
            Self::TasksResultDecode { method } => {
                write!(formatter, "final HTTP {method} result is invalid")
            }
            #[cfg(feature = "tasks")]
            Self::TasksGetIdMismatch { expected, actual } => write!(
                formatter,
                "final HTTP tasks/get returned task ID {actual:?}, expected {expected:?}"
            ),
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
            Self::FeatureUnavailable(error) => Some(error),
            Self::ReverseRequestDispatch(error) => Some(error),
            Self::Executor(error) => Some(error),
            Self::Negotiation(error) => Some(error),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::LegacySse(error) => Some(error),
            Self::InvalidTasksJsonRpcResponse { error, .. } => Some(error),
            Self::InvalidJsonRpcResponse(error) => Some(error),
            Self::TypedResult(error) => Some(error),
            Self::MissingModernPostTarget
            | Self::ReverseResponsePostRejected { .. }
            | Self::RequestParametersMustBeObject
            | Self::MissingRequestName { .. }
            | Self::UnsupportedFinalMethod { .. }
            | Self::ServerInitiatedFinalMethod { .. }
            | Self::MissingRequestId { .. }
            | Self::NotificationHasRequestId { .. }
            | Self::ClientNotificationPostUnsupported { .. }
            | Self::RequestEncodingFailed
            | Self::DiscoveryRejected { .. }
            | Self::InvalidDiscoveryResponse
            | Self::DiscoveryDoesNotAdvertiseModernProtocol
            | Self::ClientExtensionNegotiation { .. }
            | Self::InvalidRequestId
            | Self::TasksNegotiation
            | Self::TasksMethodNegotiation { .. }
            | Self::InvalidTasksRequestId { .. }
            | Self::TasksRequestEncoding { .. }
            | Self::TasksUpdateRequiresInputRequired
            | Self::TasksUpdateInputMismatch
            | Self::TasksResponseIdMismatch { .. }
            | Self::TasksRemoteError { .. }
            | Self::TasksResultMissing { .. }
            | Self::TasksResultDecode { .. }
            | Self::ResponseIdMismatch { .. }
            | Self::RemoteError { .. }
            | Self::UnexpectedToolCallResult => None,
            #[cfg(feature = "tasks")]
            Self::TasksGetIdMismatch { .. } => None,
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
        validate_protocol_plan_feature(&protocol_plan)
            .map_err(ModernHttpClientError::FeatureUnavailable)?;
        Self::connect_with_mcp_apps(cx, protocol_plan, client_info, client_capabilities, None).await
    }

    pub(crate) async fn connect_with_mcp_apps(
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        mcp_apps_settings: Option<McpAppsClientSettings>,
    ) -> Result<ModernHttpConnectOutcome, ModernHttpClientError> {
        Self::connect_with_extensions(
            cx,
            protocol_plan,
            client_info,
            client_capabilities,
            mcp_apps_settings,
            None,
        )
        .await
    }

    pub(crate) async fn connect_with_extensions(
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        mcp_apps_settings: Option<McpAppsClientSettings>,
        client_extension_runtime: Option<Arc<ClientExtensionRuntime>>,
    ) -> Result<ModernHttpConnectOutcome, ModernHttpClientError> {
        validate_protocol_plan_feature(&protocol_plan)
            .map_err(ModernHttpClientError::FeatureUnavailable)?;
        if cx.checkpoint().is_err() {
            return Err(ModernHttpClientError::Executor(
                ModernHttpExecutorError::Cancelled,
            ));
        }
        if matches!(protocol_plan.policy(), ProtocolPolicy::LegacyOnly) {
            #[cfg(feature = "legacy-2024-11-05")]
            return LegacySseHttpClient::connect(cx, protocol_plan)
                .await
                .map(ModernHttpConnectOutcome::LegacySse)
                .map_err(ModernHttpClientError::LegacySse);
            #[cfg(not(feature = "legacy-2024-11-05"))]
            return Err(ModernHttpClientError::FeatureUnavailable(
                McpError::invalid_params(
                    "MCP 2024-11-05 HTTP requires the legacy-2024-11-05 feature",
                ),
            ));
        }

        let modern_post_target = protocol_plan
            .modern_post_target()
            .ok_or(ModernHttpClientError::MissingModernPostTarget)?
            .to_owned();
        let mut negotiation = ClientHttpNegotiation::from_protocol_plan(&protocol_plan)
            .map_err(ModernHttpClientError::Negotiation)?;
        let configured_extensions = client_extension_runtime
            .as_ref()
            .map(|runtime| runtime.client_wire_extensions());
        let generic_apps_configured = client_extension_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.configures_mcp_apps());
        let client_extensions = merge_client_extensions(
            (!generic_apps_configured)
                .then_some(mcp_apps_settings.as_ref())
                .flatten(),
            configured_extensions.as_ref(),
        );
        let probe_request = build_modern_request_with_extensions(
            &modern_post_target,
            &client_info.to_implementation(),
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
        let probe_body_kind = classify_modern_probe_body(&probe_body);
        // A JSON-RPC-shaped response is not enough to establish the modern
        // era: its `server/discover` final-result algebra must be admitted
        // before the negotiation classifier records modern selection.
        let admitted_discovery = matches!(probe_body_kind, HttpProbeBody::RecognizedModernJsonRpc)
            .then(|| decode_modern_discovery_response(&probe_body))
            .transpose()?;
        let probe = HttpModernProbe {
            status: probe_status,
            body: probe_body_kind,
        };

        match negotiation
            .observe_modern_probe(probe)
            .map_err(ModernHttpClientError::Negotiation)?
        {
            ClientHttpNegotiationDecision::ModernSelected => {
                let server_discovery =
                    admitted_discovery.ok_or(ModernHttpClientError::InvalidDiscoveryResponse)?;
                let negotiated_extensions = client_extension_runtime
                    .as_ref()
                    .map(|runtime| runtime.negotiate(&server_discovery))
                    .transpose()
                    .map_err(|error| ModernHttpClientError::ClientExtensionNegotiation {
                        message: error.to_string(),
                    })?;
                let mcp_apps_activation_receipt = match client_extension_runtime.as_ref() {
                    Some(runtime) if runtime.configures_mcp_apps() => negotiated_extensions
                        .as_ref()
                        .and_then(|negotiated| runtime.mcp_apps_activation_receipt(negotiated)),
                    _ => mcp_apps_activation_receipt(mcp_apps_settings.as_ref(), &server_discovery),
                };
                Ok(ModernHttpConnectOutcome::Modern(Self {
                    protocol_plan,
                    modern_post_target,
                    client_info,
                    client_implementation: None,
                    client_capabilities,
                    mcp_apps_settings,
                    client_extension_runtime,
                    discovery_state: Arc::new(ModernHttpDiscoveryState {
                        mcp_apps_activation_receipt,
                        server_discovery,
                        negotiated_extensions,
                    }),
                    executor: ModernHttpExecutor::new(),
                    reverse_request_handlers: ReverseRequestHandlers::new(),
                }))
            }
            #[cfg(feature = "legacy-2024-11-05")]
            ClientHttpNegotiationDecision::LegacySseFallbackAuthorized => {
                LegacySseHttpClient::connect(cx, protocol_plan)
                    .await
                    .map(ModernHttpConnectOutcome::LegacySse)
                    .map_err(ModernHttpClientError::LegacySse)
            }
            #[cfg(not(feature = "legacy-2024-11-05"))]
            ClientHttpNegotiationDecision::LegacySseFallbackAuthorized => Err(
                ModernHttpClientError::FeatureUnavailable(McpError::invalid_params(
                    "MCP 2024-11-05 HTTP requires the legacy-2024-11-05 feature",
                )),
            ),
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

    async fn post_jsonrpc_response(
        &self,
        cx: &Cx,
        response: &JsonRpcResponse,
    ) -> Result<(), ModernHttpClientError> {
        let body = serde_json::to_vec(response).map_err(|_| {
            ModernHttpClientError::ReverseRequestDispatch(McpError::internal_error(
                "modern reverse response could not serialize",
            ))
        })?;
        let request = ModernHttpRequest::for_jsonrpc_response(
            &self.modern_post_target,
            MODERN_PROTOCOL_VERSION,
            body,
        )
        .map_err(ModernHttpClientError::Executor)?;
        let response = self
            .executor
            .execute(cx, &request)
            .await
            .map_err(ModernHttpClientError::Executor)?;
        let status = response.metadata().status();
        let _ = response
            .read_to_end(cx, 4_096)
            .await
            .map_err(ModernHttpClientError::Executor)?;
        if status != 202 && status != 200 {
            return Err(ModernHttpClientError::ReverseResponsePostRejected { status });
        }
        Ok(())
    }

    /// Returns the exact typed discovery result that selected modern HTTP.
    #[must_use]
    pub fn server_discovery(&self) -> ServerDiscoverResult {
        self.discovery_state.server_discovery.clone()
    }

    /// Retains modern Implementation extras for later request `_meta` stamps.
    pub fn set_client_implementation(
        &mut self,
        implementation: fastmcp_protocol::common_types::Implementation,
    ) {
        self.client_implementation = Some(implementation);
    }

    fn stamped_client_identity(&self) -> fastmcp_protocol::common_types::Implementation {
        self.client_implementation
            .clone()
            .unwrap_or_else(|| self.client_info.to_implementation())
    }

    /// Returns whether final discovery activated the official MCP Apps extension.
    #[cfg(feature = "apps")]
    #[must_use]
    pub fn mcp_apps_active(&self) -> bool {
        self.discovery_state.mcp_apps_activation_receipt.is_some()
    }

    /// Returns the sole Apps receipt derived by this connection's retained
    /// final discovery negotiation.
    #[cfg(feature = "apps")]
    #[must_use]
    pub fn mcp_apps_activation_receipt(
        &self,
    ) -> Option<fastmcp_protocol::extensions::McpAppsActivationReceipt> {
        self.discovery_state.mcp_apps_activation_receipt.clone()
    }

    /// Returns the frozen generic extension set retained from final discovery.
    #[must_use]
    pub fn negotiated_extensions(
        &self,
    ) -> Option<fastmcp_protocol::extensions::NegotiatedExtensionSet> {
        self.discovery_state.negotiated_extensions.clone()
    }

    fn admit_final_extension_method(
        &self,
        extension_id: &fastmcp_protocol::ExtensionId,
        method: &str,
    ) -> McpResult<()> {
        let runtime = self.client_extension_runtime.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "No builder-owned final client extension registry is configured",
            )
        })?;
        let negotiated = self
            .discovery_state
            .negotiated_extensions
            .clone()
            .ok_or_else(|| {
                McpError::invalid_params(
                    "Final client extension settings were not negotiated by server/discover",
                )
            })?;
        runtime.admit_method(&negotiated, extension_id, method)
    }

    fn configured_client_extensions(
        &self,
        additional_client_extensions: Option<&BTreeMap<String, serde_json::Value>>,
    ) -> Option<BTreeMap<String, serde_json::Value>> {
        let mut extensions = self
            .client_extension_runtime
            .as_ref()
            .map_or_else(BTreeMap::new, |runtime| runtime.client_wire_extensions());
        if let Some(additional_client_extensions) = additional_client_extensions {
            for (extension_id, settings) in additional_client_extensions {
                extensions
                    .entry(extension_id.clone())
                    .or_insert_with(|| settings.clone());
            }
        }
        (!extensions.is_empty()).then_some(extensions)
    }

    fn build_post_discovery_request(
        &self,
        _cx: &Cx,
        method: &str,
        parameters: serde_json::Value,
        request_id: Option<RequestId>,
        additional_client_extensions: Option<&BTreeMap<String, serde_json::Value>>,
    ) -> Result<ModernHttpRequest, ModernHttpClientError> {
        let mcp_apps_active = self.discovery_state.mcp_apps_activation_receipt.is_some();
        let generic_apps_configured = self
            .client_extension_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.configures_mcp_apps());
        let client_extension_settings =
            self.configured_client_extensions(additional_client_extensions);
        let client_extensions = merge_client_extensions(
            (mcp_apps_active && !generic_apps_configured)
                .then_some(self.mcp_apps_settings.as_ref())
                .flatten(),
            client_extension_settings.as_ref(),
        );
        let request = build_modern_request_with_extensions(
            &self.modern_post_target,
            &self.stamped_client_identity(),
            &self.client_capabilities,
            method,
            parameters,
            request_id,
            client_extensions.as_ref(),
        )?;
        Ok(request)
    }

    async fn execute_post_discovery_request(
        &self,
        cx: &Cx,
        request: &ModernHttpRequest,
    ) -> Result<ModernHttpResponseStream, ModernHttpClientError> {
        self.executor
            .execute(cx, request)
            .await
            .map_err(ModernHttpClientError::Executor)
    }

    async fn execute_post_discovery_request_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: &ModernHttpRequest,
    ) -> Result<ModernHttpResponseStream, ModernHttpClientError> {
        self.executor
            .execute_with_cancellation(cx, cancellation, request)
            .await
            .map_err(ModernHttpClientError::Executor)
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
        let method = method.as_ref();
        validate_final_method(method, request_id.is_some())?;
        if request_id.is_none() {
            return Err(ModernHttpClientError::ClientNotificationPostUnsupported {
                method: method.to_owned(),
            });
        }
        let request =
            self.build_post_discovery_request(cx, method, parameters, request_id, None)?;
        self.execute_post_discovery_request(cx, &request).await
    }

    /// Executes a final extension request only after the connection-level
    /// registry/discovery admission has succeeded in the same call path.
    ///
    /// This is deliberately private and distinct from [`Self::request`]: it
    /// bypasses only the core method table, not request-ID, cancellation,
    /// metadata, or native HTTP admission.
    async fn execute_admitted_final_extension_request(
        &self,
        cx: &Cx,
        method: &str,
        parameters: serde_json::Value,
        request_id: RequestId,
    ) -> Result<ModernHttpResponseStream, ModernHttpClientError> {
        if cx.checkpoint().is_err() {
            return Err(ModernHttpClientError::Executor(
                ModernHttpExecutorError::Cancelled,
            ));
        }
        if request_id.validate().is_err() {
            return Err(ModernHttpClientError::InvalidRequestId);
        }
        let generic_apps_configured = self
            .client_extension_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.configures_mcp_apps());
        let client_extension_settings = self.configured_client_extensions(None);
        let client_extensions = merge_client_extensions(
            (self.discovery_state.mcp_apps_activation_receipt.is_some()
                && !generic_apps_configured)
                .then_some(self.mcp_apps_settings.as_ref())
                .flatten(),
            client_extension_settings.as_ref(),
        );
        let request = build_modern_request_after_method_validation(
            &self.modern_post_target,
            &self.stamped_client_identity(),
            &self.client_capabilities,
            method,
            parameters,
            Some(request_id),
            client_extensions.as_ref(),
        )?;
        self.execute_post_discovery_request(cx, &request).await
    }

    async fn request_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: serde_json::Value,
        request_id: Option<RequestId>,
    ) -> Result<ModernHttpResponseStream, ModernHttpClientError> {
        if cancellation.is_cancel_requested() {
            return Err(ModernHttpClientError::Executor(
                ModernHttpExecutorError::Cancelled,
            ));
        }
        validate_final_method(method, request_id.is_some())?;
        if request_id.is_none() {
            return Err(ModernHttpClientError::ClientNotificationPostUnsupported {
                method: method.to_owned(),
            });
        }
        let request =
            self.build_post_discovery_request(cx, method, parameters, request_id, None)?;
        self.execute_post_discovery_request_with_cancellation(cx, cancellation, &request)
            .await
    }

    /// Calls one tool through ordinary modern HTTP and follows bounded MRTR
    /// continuations without negotiating Tasks.
    ///
    /// `next_request_id` is called only after a peer `input_required` result
    /// has passed the shared continuation and input bounds. Every returned ID
    /// is validated and must differ from every earlier round before it can be
    /// sent. The operation uses the one supplied absolute `deadline` for its
    /// initial request and every continuation.
    pub async fn call_tool_with_mrtr_retry<F, I>(
        &self,
        cx: &Cx,
        initial_request_id: RequestId,
        deadline: Instant,
        name: &str,
        arguments: serde_json::Value,
        sse_limits: SseLimits,
        maximum_response_bytes: usize,
        next_request_id: I,
        respond: F,
    ) -> Result<CoreResult, ModernHttpMrtrError>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
        I: FnMut() -> McpResult<RequestId>,
    {
        self.drive_mrtr_retry(
            cx,
            initial_request_id,
            deadline,
            TOOLS_CALL,
            serde_json::json!({ "name": name, "arguments": arguments }),
            sse_limits,
            maximum_response_bytes,
            next_request_id,
            respond,
        )
        .await
    }

    /// Reads one resource through ordinary modern HTTP and follows bounded
    /// MRTR continuations without negotiating Tasks.
    pub async fn read_resource_with_mrtr_retry<F, I>(
        &self,
        cx: &Cx,
        initial_request_id: RequestId,
        deadline: Instant,
        uri: &str,
        sse_limits: SseLimits,
        maximum_response_bytes: usize,
        next_request_id: I,
        respond: F,
    ) -> Result<CoreResult, ModernHttpMrtrError>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
        I: FnMut() -> McpResult<RequestId>,
    {
        self.drive_mrtr_retry(
            cx,
            initial_request_id,
            deadline,
            RESOURCES_READ,
            serde_json::json!({ "uri": uri }),
            sse_limits,
            maximum_response_bytes,
            next_request_id,
            respond,
        )
        .await
    }

    /// Gets one prompt through ordinary modern HTTP and follows bounded MRTR
    /// continuations without negotiating Tasks.
    pub async fn get_prompt_with_mrtr_retry<F, I>(
        &self,
        cx: &Cx,
        initial_request_id: RequestId,
        deadline: Instant,
        name: &str,
        arguments: std::collections::HashMap<String, String>,
        sse_limits: SseLimits,
        maximum_response_bytes: usize,
        next_request_id: I,
        respond: F,
    ) -> Result<CoreResult, ModernHttpMrtrError>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
        I: FnMut() -> McpResult<RequestId>,
    {
        let mut parameters = serde_json::json!({ "name": name });
        if !arguments.is_empty() {
            let parameters = parameters.as_object_mut().ok_or_else(|| {
                ModernHttpMrtrError::Driver(McpError::internal_error(
                    "MRTR prompt parameters must remain an object",
                ))
            })?;
            parameters.insert(
                "arguments".to_owned(),
                serde_json::to_value(arguments).map_err(|error| {
                    ModernHttpMrtrError::Driver(McpError::internal_error(format!(
                        "MRTR prompt arguments could not serialize: {error}"
                    )))
                })?,
            );
        }
        self.drive_mrtr_retry(
            cx,
            initial_request_id,
            deadline,
            PROMPTS_GET,
            parameters,
            sse_limits,
            maximum_response_bytes,
            next_request_id,
            respond,
        )
        .await
    }

    async fn drive_mrtr_retry<F, I>(
        &self,
        cx: &Cx,
        initial_request_id: RequestId,
        deadline: Instant,
        method: &'static str,
        original_parameters: serde_json::Value,
        sse_limits: SseLimits,
        maximum_response_bytes: usize,
        mut next_request_id: I,
        mut respond: F,
    ) -> Result<CoreResult, ModernHttpMrtrError>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
        I: FnMut() -> McpResult<RequestId>,
    {
        validate_mrtr_request_id(&initial_request_id)?;
        let limits =
            MrtrDriverLimits::new(MAX_MRTR_CONTINUATION_ROUNDS, MAX_MRTR_TOTAL_INPUT_RESPONSES)
                .map_err(ModernHttpMrtrError::Driver)?;
        let mut driver =
            MrtrDriver::new(cx, deadline, limits).map_err(ModernHttpMrtrError::Driver)?;
        let mut used_request_ids = vec![initial_request_id.clone()];
        let mut request_id = initial_request_id;
        let mut parameters = original_parameters.clone();

        loop {
            driver
                .before_request()
                .map_err(ModernHttpMrtrError::Driver)?;
            let result = await_mrtr_until(
                cx,
                driver.deadline(),
                self.execute_mrtr_round(
                    cx,
                    method,
                    parameters,
                    request_id.clone(),
                    sse_limits,
                    maximum_response_bytes,
                ),
            )
            .await?;
            // A response body can finish after the operation deadline. Do
            // not turn that late terminal into success or let it trigger a
            // caller callback for another continuation.
            driver
                .before_request()
                .map_err(ModernHttpMrtrError::Driver)?;
            let Some(input_required) = mrtr_input_required_for_method(method, &result) else {
                return Ok(result);
            };

            // This occurs before either user callback or ID allocation, so a
            // fifth continuation cannot create an effect or a sixth POST.
            driver
                .begin_continuation()
                .map_err(ModernHttpMrtrError::Driver)?;
            let input_responses = respond(input_required).map_err(ModernHttpMrtrError::Driver)?;
            let input_response_count = input_responses.len();
            let retry_parameters =
                mrtr_retry_parameters(original_parameters.clone(), input_required, input_responses)
                    .map_err(ModernHttpMrtrError::Driver)?;
            driver
                .admit_input_responses(input_response_count)
                .map_err(ModernHttpMrtrError::Driver)?;

            let next_id = next_request_id().map_err(ModernHttpMrtrError::Driver)?;
            validate_mrtr_request_id(&next_id)?;
            if used_request_ids
                .iter()
                .any(|used_id| used_id.correlates_with(&next_id))
            {
                return Err(ModernHttpMrtrError::ReusedRequestId {
                    request_id: next_id,
                });
            }
            used_request_ids.push(next_id.clone());
            request_id = next_id;
            parameters = retry_parameters;
        }
    }

    async fn execute_mrtr_round(
        &self,
        cx: &Cx,
        method: &'static str,
        parameters: serde_json::Value,
        request_id: RequestId,
        sse_limits: SseLimits,
        maximum_response_bytes: usize,
    ) -> Result<CoreResult, ModernHttpMrtrError> {
        let request = self
            .build_post_discovery_request(cx, method, parameters, Some(request_id.clone()), None)
            .map_err(ModernHttpMrtrError::Request)?;
        let wire_request: JsonRpcRequest = serde_json::from_slice(&request.body).map_err(|_| {
            ModernHttpMrtrError::Request(ModernHttpClientError::RequestEncodingFailed)
        })?;
        let core_request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            method,
            wire_request.params.as_ref(),
        )
        .map_err(|error| ModernHttpMrtrError::Request(ModernHttpClientError::TypedResult(error)))?;
        let response = self
            .execute_post_discovery_request(cx, &request)
            .await
            .map_err(ModernHttpMrtrError::Request)?;

        let result = match response.metadata().kind() {
            ModernHttpResponseKind::Json => {
                let body = response
                    .read_to_end(cx, maximum_response_bytes)
                    .await
                    .map_err(|error| {
                        ModernHttpMrtrError::Request(ModernHttpClientError::Executor(error))
                    })?;
                decode_mrtr_json_response(
                    &core_request,
                    &request_id,
                    &body,
                    maximum_response_bytes,
                )?
            }
            ModernHttpResponseKind::Sse => {
                response
                    .into_final_core_listener(request_id, core_request, sse_limits)
                    .map_err(ModernHttpMrtrError::Listener)?
                    .collect(cx)
                    .await
                    .map_err(ModernHttpMrtrError::Listener)?
                    .terminal
            }
            actual => return Err(ModernHttpMrtrError::UnexpectedResponseKind { actual }),
        };
        #[cfg(feature = "tasks")]
        if matches!(&result, FinalCoreResult::ToolsCallTask { .. }) {
            return Err(ModernHttpMrtrError::TasksResultRequiresNegotiatedOperation);
        }
        Ok(CoreResult::Final(result))
    }

    /// Opens one typed final core response stream for an ordinary core request.
    ///
    /// The request is constructed through the same immutable metadata and
    /// extension path as [`Self::request`]. Its collector retains exact server
    /// progress notifications from the request-owned SSE body without
    /// projecting them through a legacy `f64` callback; live iteration does
    /// not retain a hidden duplicate queue. Although its request retains the
    /// standard JSON-or-SSE `Accept` contract, this SSE-only API rejects a
    /// server response on the JSON body lane.
    pub async fn open_final_core_listener(
        &self,
        cx: &Cx,
        method: impl AsRef<str>,
        parameters: serde_json::Value,
        request_id: RequestId,
        limits: SseLimits,
    ) -> Result<ModernHttpFinalCoreListener, ModernHttpFinalCoreListenError> {
        if request_id.validate().is_err() {
            return Err(ModernHttpFinalCoreListenError::InvalidRequestId);
        }
        let method = method.as_ref();
        let request = self
            .build_post_discovery_request(cx, method, parameters, Some(request_id.clone()), None)
            .map_err(ModernHttpFinalCoreListenError::Request)?;
        let wire_request: JsonRpcRequest = serde_json::from_slice(&request.body).map_err(|_| {
            ModernHttpFinalCoreListenError::Request(ModernHttpClientError::RequestEncodingFailed)
        })?;
        let core_request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            method,
            wire_request.params.as_ref(),
        )
        .map_err(ModernHttpFinalCoreListenError::TerminalResult)?;
        let response = self
            .execute_post_discovery_request(cx, &request)
            .await
            .map_err(ModernHttpFinalCoreListenError::Request)?;
        response.into_final_core_listener(request_id, core_request, limits)
    }

    /// Opens one typed final `tools/call` response stream.
    pub async fn open_final_tool_call_listener(
        &self,
        cx: &Cx,
        request_id: RequestId,
        name: &str,
        arguments: serde_json::Value,
        limits: SseLimits,
    ) -> Result<ModernHttpFinalCoreListener, ModernHttpFinalCoreListenError> {
        self.open_final_core_listener(
            cx,
            TOOLS_CALL,
            serde_json::json!({ "name": name, "arguments": arguments }),
            request_id,
            limits,
        )
        .await
    }

    /// Opens one typed final `tools/call` response stream after exact bilateral
    /// Tasks result-discriminator admission.
    #[cfg(feature = "tasks")]
    pub async fn open_final_tasks_tool_call_listener(
        &self,
        cx: &Cx,
        request_id: RequestId,
        name: &str,
        arguments: serde_json::Value,
        limits: SseLimits,
    ) -> Result<ModernHttpFinalCoreListener, ModernHttpFinalCoreListenError> {
        self.open_final_tasks_tool_call_listener_with_progress_marker(
            cx, request_id, name, arguments, None, limits,
        )
        .await
    }

    /// Opens a typed final Tasks `tools/call` response stream with an optional
    /// exact progress marker supplied by the caller.
    #[cfg(feature = "tasks")]
    pub async fn open_final_tasks_tool_call_listener_with_progress_marker(
        &self,
        cx: &Cx,
        request_id: RequestId,
        name: &str,
        arguments: serde_json::Value,
        progress_marker: Option<&fastmcp_protocol::ProgressMarker>,
        limits: SseLimits,
    ) -> Result<ModernHttpFinalCoreListener, ModernHttpFinalCoreListenError> {
        if request_id.validate().is_err() {
            return Err(ModernHttpFinalCoreListenError::InvalidRequestId);
        }
        let discovery = self.server_discovery();
        admit_final_tasks_result_discriminator(&discovery, OFFICIAL_TASKS_RESULT_DISCRIMINATOR)
            .map_err(|_| {
                ModernHttpFinalCoreListenError::Request(ModernHttpClientError::TasksNegotiation)
            })?;

        let task_extensions = BTreeMap::from([(
            fastmcp_protocol::TASKS_EXTENSION.to_owned(),
            serde_json::json!({}),
        )]);
        let mut parameters = serde_json::json!({ "name": name, "arguments": arguments });
        if let Some(marker) = progress_marker {
            parameters["_meta"] = serde_json::json!({ "progressToken": marker });
        }
        let request = self
            .build_post_discovery_request(
                cx,
                TOOLS_CALL,
                parameters,
                Some(request_id.clone()),
                Some(&task_extensions),
            )
            .map_err(ModernHttpFinalCoreListenError::Request)?;
        let wire_request: JsonRpcRequest = serde_json::from_slice(&request.body).map_err(|_| {
            ModernHttpFinalCoreListenError::Request(ModernHttpClientError::RequestEncodingFailed)
        })?;
        let core_request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            TOOLS_CALL,
            wire_request.params.as_ref(),
        )
        .map_err(ModernHttpFinalCoreListenError::TerminalResult)?;
        let response = self
            .execute_post_discovery_request(cx, &request)
            .await
            .map_err(ModernHttpFinalCoreListenError::Request)?;
        response.into_final_tasks_tool_call_listener(request_id, core_request, limits)
    }

    /// Opens and consumes one typed final `subscriptions/listen` HTTP stream.
    ///
    /// The request is emitted with the same immutable final metadata as every
    /// other modern HTTP request. Each later listener event has passed strict
    /// admission and acknowledgement-filter validation.
    pub async fn open_subscriptions_listener(
        &self,
        cx: &Cx,
        request_id: RequestId,
        notifications: SubscriptionFilter,
        limits: SseLimits,
    ) -> Result<ModernHttpSubscriptionListener, ModernHttpSubscriptionListenError> {
        if request_id.validate().is_err() {
            return Err(ModernHttpSubscriptionListenError::InvalidRequestId);
        }
        #[cfg(feature = "tasks")]
        let tasks_requested = task_subscription_ids(&notifications)
            .map_err(|_| ModernHttpSubscriptionListenError::TasksNegotiation)?
            .is_some();
        #[cfg(feature = "tasks")]
        let client_extensions = if tasks_requested {
            let discovery = self.server_discovery();
            admit_final_tasks_discovery_surface(
                &discovery,
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
        #[cfg(not(feature = "tasks"))]
        let client_extensions: Option<BTreeMap<String, serde_json::Value>> = None;
        let request = self
            .build_post_discovery_request(
                cx,
                SUBSCRIPTIONS_LISTEN,
                serde_json::json!({ "notifications": notifications.clone() }),
                Some(request_id.clone()),
                client_extensions.as_ref(),
            )
            .map_err(ModernHttpSubscriptionListenError::Request)?;
        let response = self
            .execute_post_discovery_request(cx, &request)
            .await
            .map_err(ModernHttpSubscriptionListenError::Request)?;
        response.into_final_subscriptions_listener(request_id, notifications, limits)
    }

    /// Opens and consumes one typed final `subscriptions/listen` HTTP stream.
    pub async fn listen_subscriptions_typed(
        &self,
        cx: &Cx,
        request_id: RequestId,
        notifications: SubscriptionFilter,
        limits: SseLimits,
    ) -> Result<ModernHttpSubscriptionListenCollector, ModernHttpSubscriptionListenError> {
        self.open_subscriptions_listener(cx, request_id, notifications, limits)
            .await?
            .collect(cx)
            .await
    }

    /// Calls one final tool through native HTTP and retains its exact result branch.
    #[cfg(feature = "tasks")]
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
        let discovery = self.server_discovery();
        admit_final_tasks_result_discriminator(&discovery, OFFICIAL_TASKS_RESULT_DISCRIMINATOR)
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
        let request = self.build_post_discovery_request(
            cx,
            TOOLS_CALL,
            parameters,
            Some(request_id.clone()),
            Some(&task_extensions),
        )?;
        let response = self.execute_post_discovery_request(cx, &request).await?;
        let body = response
            .read_to_end(cx, maximum_response_bytes)
            .await
            .map_err(ModernHttpClientError::Executor)?;
        let message = decode_strict_jsonrpc_message(&body, maximum_response_bytes)
            .map_err(ModernHttpClientError::InvalidJsonRpcResponse)?;
        let JsonRpcMessage::Response(response) = message else {
            return Err(ModernHttpClientError::UnexpectedToolCallResult);
        };
        let admission = decode_strict_jsonrpc_response(&body, maximum_response_bytes)
            .map_err(ModernHttpClientError::InvalidJsonRpcResponse)?;
        if admission.response() != &response {
            return Err(ModernHttpClientError::InvalidJsonRpcResponse(
                JsonRpcAdmissionError::InvalidEnvelope,
            ));
        }
        let (_, result_source) = admission.into_parts();
        if !response
            .id
            .as_ref()
            .is_some_and(|response_id| response_id.correlates_with(&request_id))
        {
            return Err(ModernHttpClientError::ResponseIdMismatch {
                expected: request_id,
                actual: response.id,
            });
        }
        if let Some(error) = response.error.as_ref() {
            return Err(ModernHttpClientError::RemoteError {
                code: error.code.clone(),
                message: error.message.clone(),
            });
        }
        let result_source = result_source
            .as_deref()
            .ok_or(ModernHttpClientError::UnexpectedToolCallResult)?;
        match core_request
            .decode_response_result(&response, result_source)
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

    /// Reads one task through the negotiated official Tasks extension.
    ///
    /// This rejects before a native POST when the retained discovery response
    /// did not select MCP 2026-07-28 or did not bilaterally admit
    /// `tasks/get` with exact empty extension settings.
    #[cfg(feature = "tasks")]
    pub async fn get_task_final(
        &self,
        cx: &Cx,
        request_id: RequestId,
        task_id: FinalTaskId,
        maximum_response_bytes: usize,
    ) -> Result<FinalGetTaskResult, ModernHttpClientError> {
        let (request_meta, client_extensions) = self.prepare_final_tasks_method(TASK_GET)?;
        let wire = TaskMethodRequest::new(
            request_id.clone(),
            TASK_GET,
            FinalGetTaskParams {
                request: request_meta,
                task_id: task_id.clone(),
            },
        );
        let wire = TaskMethodRequest::decode(
            serde_json::to_value(wire)
                .map_err(|_| ModernHttpClientError::TasksRequestEncoding { method: TASK_GET })?,
        )
        .map_err(|_| ModernHttpClientError::TasksRequestEncoding { method: TASK_GET })?;
        let parameters = serde_json::to_value(wire.params)
            .map_err(|_| ModernHttpClientError::TasksRequestEncoding { method: TASK_GET })?;
        let result: FinalGetTaskResult = self
            .send_final_tasks_request(
                cx,
                TASK_GET,
                request_id,
                parameters,
                &client_extensions,
                maximum_response_bytes,
            )
            .await?;
        let actual = result.task.base().task_id.clone();
        if actual != task_id {
            return Err(ModernHttpClientError::TasksGetIdMismatch {
                expected: task_id,
                actual,
            });
        }
        Ok(result)
    }

    /// Supplies responses for the exact input requests retained by one final
    /// `input_required` task through the official Tasks extension.
    ///
    /// The request is rejected before a native POST unless the task is an
    /// admitted input-required task and `inputResponses` exactly matches its
    /// retained input ledger.
    #[cfg(feature = "tasks")]
    pub async fn update_task_final(
        &self,
        cx: &Cx,
        request_id: RequestId,
        task: &FinalTask,
        input_responses: FinalTaskInputResponses,
        maximum_response_bytes: usize,
    ) -> Result<FinalUpdateTaskResult, ModernHttpClientError> {
        let (request_meta, client_extensions) = self.prepare_final_tasks_method(TASK_UPDATE)?;
        let FinalTask::InputRequired {
            base,
            input_requests,
        } = task
        else {
            return Err(ModernHttpClientError::TasksUpdateRequiresInputRequired);
        };
        let ledger = TaskInputLedger::from_requests(input_requests)
            .map_err(|_| ModernHttpClientError::TasksUpdateInputMismatch)?;
        ledger
            .validate_responses(&input_responses)
            .map_err(|_| ModernHttpClientError::TasksUpdateInputMismatch)?;

        let wire = TaskMethodRequest::new(
            request_id.clone(),
            TASK_UPDATE,
            FinalUpdateTaskParams {
                request: request_meta,
                task_id: base.task_id.clone(),
                input_responses,
            },
        );
        let wire = TaskMethodRequest::decode_update(
            serde_json::to_value(wire).map_err(|_| {
                ModernHttpClientError::TasksRequestEncoding {
                    method: TASK_UPDATE,
                }
            })?,
            &ledger,
        )
        .map_err(|_| ModernHttpClientError::TasksRequestEncoding {
            method: TASK_UPDATE,
        })?;
        let parameters = serde_json::to_value(wire.params).map_err(|_| {
            ModernHttpClientError::TasksRequestEncoding {
                method: TASK_UPDATE,
            }
        })?;
        self.send_final_tasks_request(
            cx,
            TASK_UPDATE,
            request_id,
            parameters,
            &client_extensions,
            maximum_response_bytes,
        )
        .await
    }

    /// Requests cancellation through the negotiated official Tasks extension.
    ///
    /// The response preserves the exact empty final `complete` acknowledgement
    /// rather than projecting a task snapshot.
    #[cfg(feature = "tasks")]
    pub async fn cancel_task_final(
        &self,
        cx: &Cx,
        request_id: RequestId,
        task_id: FinalTaskId,
        maximum_response_bytes: usize,
    ) -> Result<FinalCancelTaskResult, ModernHttpClientError> {
        let (request_meta, client_extensions) = self.prepare_final_tasks_method(TASK_CANCEL)?;
        let wire = TaskMethodRequest::new(
            request_id.clone(),
            TASK_CANCEL,
            FinalCancelTaskParams {
                request: request_meta,
                task_id,
            },
        );
        let wire = TaskMethodRequest::decode_cancel(serde_json::to_value(wire).map_err(|_| {
            ModernHttpClientError::TasksRequestEncoding {
                method: TASK_CANCEL,
            }
        })?)
        .map_err(|_| ModernHttpClientError::TasksRequestEncoding {
            method: TASK_CANCEL,
        })?;
        let parameters = serde_json::to_value(wire.params).map_err(|_| {
            ModernHttpClientError::TasksRequestEncoding {
                method: TASK_CANCEL,
            }
        })?;
        self.send_final_tasks_request(
            cx,
            TASK_CANCEL,
            request_id,
            parameters,
            &client_extensions,
            maximum_response_bytes,
        )
        .await
    }

    /// Proves the selected final version and exact bilateral Tasks admission
    /// before constructing an extension request. The returned metadata and
    /// extension map are then shared by the typed wire validator and native
    /// HTTP request constructor.
    #[cfg(feature = "tasks")]
    fn prepare_final_tasks_method(
        &self,
        method: &'static str,
    ) -> Result<(TaskRequestMeta, BTreeMap<String, serde_json::Value>), ModernHttpClientError> {
        let discovery = self.server_discovery();
        if !discovery
            .supported_versions()
            .iter()
            .any(|version| version == MODERN_PROTOCOL_VERSION)
        {
            return Err(ModernHttpClientError::DiscoveryDoesNotAdvertiseModernProtocol);
        }
        admit_final_tasks_discovery_surface(&discovery, method, ExtensionDirection::ClientToServer)
            .map_err(|_| ModernHttpClientError::TasksMethodNegotiation { method })?;

        let tasks_extension = BTreeMap::from([(
            fastmcp_protocol::TASKS_EXTENSION.to_owned(),
            serde_json::json!({}),
        )]);
        let client_extensions = tasks_extension;
        let mut final_metadata = FinalRequestMeta::new(self.client_capabilities.clone());
        final_metadata.client_info = Some(
            self.client_implementation
                .clone()
                .unwrap_or_else(|| self.client_info.to_implementation()),
        );
        let mut metadata = serde_json::to_value(final_metadata)
            .map_err(|_| ModernHttpClientError::TasksRequestEncoding { method })?;
        let capabilities = metadata
            .as_object_mut()
            .and_then(|metadata| {
                metadata.get_mut(fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY)
            })
            .and_then(serde_json::Value::as_object_mut)
            .ok_or(ModernHttpClientError::TasksRequestEncoding { method })?;
        capabilities.insert(
            "extensions".to_owned(),
            serde_json::Value::Object(client_extensions.clone().into_iter().collect()),
        );
        let meta = serde_json::from_value(metadata)
            .map_err(|_| ModernHttpClientError::TasksRequestEncoding { method })?;
        Ok((TaskRequestMeta { meta }, client_extensions))
    }

    #[cfg(feature = "tasks")]
    async fn send_final_tasks_request<R>(
        &self,
        cx: &Cx,
        method: &'static str,
        request_id: RequestId,
        parameters: serde_json::Value,
        client_extensions: &BTreeMap<String, serde_json::Value>,
        maximum_response_bytes: usize,
    ) -> Result<R, ModernHttpClientError>
    where
        R: serde::de::DeserializeOwned,
    {
        if request_id.validate().is_err() {
            return Err(ModernHttpClientError::InvalidTasksRequestId { method });
        }
        // Discovery fixes the extension authority for the connected client;
        // every Tasks POST is otherwise independent and stateless.
        let discovery = self.discovery_state.clone();
        if !discovery
            .server_discovery
            .supported_versions()
            .iter()
            .any(|version| version == MODERN_PROTOCOL_VERSION)
        {
            return Err(ModernHttpClientError::DiscoveryDoesNotAdvertiseModernProtocol);
        }
        admit_final_tasks_discovery_surface(
            &discovery.server_discovery,
            method,
            ExtensionDirection::ClientToServer,
        )
        .map_err(|_| ModernHttpClientError::TasksMethodNegotiation { method })?;
        let generic_apps_configured = self
            .client_extension_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.configures_mcp_apps());
        let configured_extensions = self.configured_client_extensions(Some(client_extensions));
        let client_extensions = merge_client_extensions(
            (discovery.mcp_apps_activation_receipt.is_some() && !generic_apps_configured)
                .then_some(self.mcp_apps_settings.as_ref())
                .flatten(),
            configured_extensions.as_ref(),
        )
        .ok_or(ModernHttpClientError::TasksRequestEncoding { method })?;
        let request = build_modern_tasks_request(
            &self.modern_post_target,
            &self.stamped_client_identity(),
            &self.client_capabilities,
            method,
            parameters,
            request_id.clone(),
            &client_extensions,
        )?;
        let response = self.execute_post_discovery_request(cx, &request).await?;
        let body = response
            .read_to_end(cx, maximum_response_bytes)
            .await
            .map_err(ModernHttpClientError::Executor)?;
        let message =
            decode_strict_jsonrpc_message(&body, maximum_response_bytes).map_err(|error| {
                ModernHttpClientError::InvalidTasksJsonRpcResponse { method, error }
            })?;
        let JsonRpcMessage::Response(response) = message else {
            return Err(ModernHttpClientError::InvalidTasksJsonRpcResponse {
                method,
                error: JsonRpcAdmissionError::InvalidEnvelope,
            });
        };
        let admission =
            decode_strict_jsonrpc_response(&body, maximum_response_bytes).map_err(|error| {
                ModernHttpClientError::InvalidTasksJsonRpcResponse { method, error }
            })?;
        if admission.response() != &response {
            return Err(ModernHttpClientError::InvalidTasksJsonRpcResponse {
                method,
                error: JsonRpcAdmissionError::InvalidEnvelope,
            });
        }
        if !response
            .id
            .as_ref()
            .is_some_and(|response_id| response_id.correlates_with(&request_id))
        {
            return Err(ModernHttpClientError::TasksResponseIdMismatch {
                method,
                expected: request_id,
                actual: response.id,
            });
        }
        if let Some(error) = response.error.as_ref() {
            return Err(ModernHttpClientError::TasksRemoteError {
                method,
                code: error.code.clone(),
                message: error.message.clone(),
            });
        }
        let (_, result_source) = admission.into_parts();
        let result_source = result_source
            .as_deref()
            .ok_or(ModernHttpClientError::TasksResultMissing { method })?;
        serde_json::from_str(result_source)
            .map_err(|_| ModernHttpClientError::TasksResultDecode { method })
    }
}

/// A live MCP 2024-11-05 SSE connection with its advertised POST target
/// pinned to the immutable legacy endpoint bundle.
#[cfg(feature = "legacy-2024-11-05")]
pub struct LegacySseHttpClient {
    protocol_plan: ClientProtocolPlan,
    configured_message_post_target: String,
    advertised_message_post_target: String,
    post_client: HttpClient,
    stream: Option<LegacySseResponseStream>,
    notifications: VecDeque<JsonRpcRequest>,
}

/// Internal exact-2024 connection state retained only so feature-off public
/// constructors can reject legacy policy before any peer contact.
#[cfg(not(feature = "legacy-2024-11-05"))]
pub(crate) struct LegacySseHttpClient {
    protocol_plan: ClientProtocolPlan,
    configured_message_post_target: String,
    advertised_message_post_target: String,
    post_client: HttpClient,
    stream: Option<LegacySseResponseStream>,
    notifications: VecDeque<JsonRpcRequest>,
}

/// Cloneable POST half of an admitted exact-2024 SSE connection.
#[derive(Clone)]
struct LegacySseHttpOutbound {
    advertised_message_post_target: String,
    post_client: HttpClient,
}

/// One failed exact-2024 message POST together with whether the peer might
/// already own the corresponding request and therefore emit its SSE response.
struct LegacySseOutboundSendError {
    error: LegacySseHttpClientError,
    request_may_have_reached_peer: bool,
}

impl LegacySseOutboundSendError {
    const fn not_submitted(error: LegacySseHttpClientError) -> Self {
        Self {
            error,
            request_may_have_reached_peer: false,
        }
    }

    const fn submitted(error: LegacySseHttpClientError) -> Self {
        Self {
            error,
            request_may_have_reached_peer: true,
        }
    }
}

/// One locally registered terminal response waiter.
struct LegacyPersistentResponseWaiter {
    sender: oneshot::Sender<LegacyPersistentResponse>,
}

enum LegacyPersistentResponse {
    Response(JsonRpcResponse),
    Cancelled,
}

/// Result of the state-locked request-retirement election.
///
/// Only `Cancelled` means this caller removed a live pending waiter and
/// installed the tombstone that authorizes an outbound cancellation control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LegacyPersistentWaiterRetirement {
    Cancelled,
    ReaderWon,
    AlreadyTerminal,
}

/// A cancellation control frame is valid only after this handle's state-locked
/// retirement removed the still-live waiter and installed its tombstone.
const fn cancellation_control_is_authorized(retirement: LegacyPersistentWaiterRetirement) -> bool {
    matches!(retirement, LegacyPersistentWaiterRetirement::Cancelled)
}

/// Small shared state touched only at message-routing and caller-admission
/// boundaries. The reader owns all I/O; callers cannot poll or consume its
/// SSE stream directly.
struct LegacySsePersistentState {
    pending: HashMap<CorrelationKey, LegacyPersistentResponseWaiter>,
    cancelled_response_ids: VecDeque<RequestId>,
    notifications: VecDeque<JsonRpcRequest>,
    stopped: bool,
}

impl LegacySsePersistentState {
    fn stop(&mut self) {
        self.stopped = true;
        self.pending.clear();
        self.cancelled_response_ids.clear();
        self.notifications.clear();
    }
}

/// Retires a caller that stopped waiting while preserving ownership of its
/// possible late SSE terminal response. The reader consumes that tombstone
/// instead of treating the late response as foreign and stopping itself.
fn retire_abandoned_persistent_waiter(
    state: &mut LegacySsePersistentState,
    key: &CorrelationKey,
    request_id: RequestId,
) -> Result<LegacyPersistentWaiterRetirement, ClientHttpConnectionError> {
    if state.pending.remove(key).is_none() {
        return Ok(LegacyPersistentWaiterRetirement::ReaderWon);
    }
    if state.cancelled_response_ids.len() >= MAX_QUEUED_LEGACY_CANCELLED_RESPONSE_IDS {
        state.stop();
        return Err(ClientHttpConnectionError::LegacyCancelledResponseQueueFull);
    }
    state.cancelled_response_ids.push_back(request_id);
    Ok(LegacyPersistentWaiterRetirement::Cancelled)
}

/// Connection-owned dispatch for server-to-client exact-2024 callbacks.
///
/// The persistent SSE reader owns ingress, while callback tasks own their
/// async user future and response POST. The shared callback state
/// is the cancellation and response-election boundary: a matching
/// `notifications/cancelled` can be read while a handler runs, and only a
/// callback that claims its still-open entry may begin a response POST.
struct LegacySseReverseCallbackDispatcher {
    state: Arc<ReverseCallbackState>,
    tasks: Arc<std::sync::Mutex<Vec<(Option<RequestId>, asupersync::runtime::TaskHandle<()>)>>>,
}

impl LegacySseReverseCallbackDispatcher {
    fn new() -> Self {
        Self {
            state: Arc::new(ReverseCallbackState::default()),
            tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn dispatch<P, R>(
        &self,
        cx: &Cx,
        request_id: RequestId,
        params: P,
        handler: Arc<
            dyn for<'callback> Fn(
                    &'callback Cx,
                    ReverseRequestCancellation,
                    P,
                ) -> crate::ReverseRequestFuture<'callback, R>
                + Send
                + Sync,
        >,
        outbound: LegacySseHttpOutbound,
        persistent_state: Arc<std::sync::Mutex<LegacySsePersistentState>>,
    ) -> McpResult<()>
    where
        P: Send + 'static,
        R: serde::Serialize + Send + 'static,
    {
        self.reap_finished_tasks()?;
        let mut tasks = self.tasks.lock().map_err(|_| {
            McpError::internal_error("Legacy reverse callback task registry failed")
        })?;
        if tasks.len() >= MAX_PERSISTENT_LEGACY_REVERSE_CALLBACKS {
            return Err(McpError::internal_error(
                "Legacy reverse callback capacity exceeded",
            ));
        }

        let cancellation = self.state.admit(&request_id)?;
        let callback_state = Arc::clone(&self.state);
        let response_id = request_id.clone();
        let callback_id = request_id.clone();
        let invoke_cancellation = cancellation.clone();
        let task = match cx.spawn(move |callback_cx| async move {
            // This task is connection-owned. It deliberately performs no OS
            // thread handoff: the callback receives the task Cx and can await
            // only cancel-aware operations supplied by that owner.
            let result = match invoke_cancellation.checkpoint() {
                Ok(()) => handler(&callback_cx, invoke_cancellation, params).await,
                Err(error) => Err(error),
            };
            let response = crate::reverse_request_response(response_id, result);
            if callback_state.claim_response_if_open(&callback_id, &cancellation) {
                if outbound.send(&callback_cx, &response).await.is_err() {
                    callback_state.cancel_all();
                    persistent_state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .stop();
                }
            }
            callback_state.complete(&callback_id);
        }) {
            Ok(task) => task,
            Err(_) => {
                self.state.complete(&request_id);
                return Err(McpError::internal_error(
                    "Legacy reverse callback dispatcher is unavailable",
                ));
            }
        };
        tasks.push((Some(request_id), task));
        Ok(())
    }

    /// Queues a protocol response onto a bounded connection-owned task. The
    /// ingress reader never awaits an HTTP POST, so it remains able to admit a
    /// matching cancellation while an outbound peer is slow or wedged.
    fn send_immediate(
        &self,
        cx: &Cx,
        outbound: LegacySseHttpOutbound,
        persistent_state: Arc<std::sync::Mutex<LegacySsePersistentState>>,
        response: JsonRpcMessage,
    ) -> McpResult<()> {
        self.reap_finished_tasks()?;
        let mut tasks = self.tasks.lock().map_err(|_| {
            McpError::internal_error("Legacy reverse callback task registry failed")
        })?;
        if tasks.len() >= MAX_PERSISTENT_LEGACY_REVERSE_CALLBACKS {
            return Err(McpError::internal_error(
                "Legacy reverse callback capacity exceeded",
            ));
        }
        let task = cx
            .spawn(move |response_cx| async move {
                if outbound.send(&response_cx, &response).await.is_err() {
                    persistent_state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .stop();
                }
            })
            .map_err(|_| {
                McpError::internal_error("Legacy reverse response dispatcher is unavailable")
            })?;
        tasks.push((None, task));
        Ok(())
    }

    fn cancel(&self, request_id: &RequestId) -> bool {
        let cancelled = self.state.cancel(request_id);
        if cancelled {
            let tasks = self
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (task_id, task) in tasks.iter() {
                if task_id
                    .as_ref()
                    .is_some_and(|task_id| task_id.correlates_with(request_id))
                {
                    task.abort();
                }
            }
        }
        let _ = self.reap_finished_tasks();
        cancelled
    }

    /// Nonblockingly joins every finished callback before its handle can be
    /// dropped. A completed panic makes the connection fail closed rather
    /// than silently disappearing during a later admission pass.
    fn reap_finished_tasks(&self) -> McpResult<usize> {
        let mut tasks = self.tasks.lock().map_err(|_| {
            McpError::internal_error("Legacy reverse callback task registry failed")
        })?;
        let mut active = Vec::with_capacity(tasks.len());
        let mut panicked = false;
        for (request_id, mut task) in std::mem::take(&mut *tasks) {
            match task.try_join() {
                Ok(None) => active.push((request_id, task)),
                Ok(Some(())) => {}
                Err(_) => panicked = true,
            }
        }
        let active_count = active.len();
        *tasks = active;
        if panicked {
            let error = McpError::internal_error("Legacy reverse callback task panicked");
            self.state.fail_connection(error.clone());
            return Err(error);
        }
        Ok(active_count)
    }

    /// Cancels every callback. The caller-owned asupersync region remains the
    /// task owner; these handles are observers and need not outlive this
    /// connection merely to keep the tasks structurally owned.
    fn close(&self) {
        self.state.cancel_all();
        let tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (_, task) in tasks.iter() {
            task.abort();
        }
    }
}

enum LegacySseReverseRequestDispatch {
    Immediate(JsonRpcMessage),
    CallbackAdmitted,
}

/// Admits one exact-2024 reverse request from the persistent SSE reader.
///
/// This is deliberately separate from the raw request/response helper: the
/// ready high-level connection must not run a user callback on its sole SSE
/// receive task, because that task is the only path by which cancellation can
/// reach the callback registry.
fn legacy_sse_reverse_request_dispatch(
    cx: &Cx,
    client_capabilities: &ClientCapabilities,
    handlers: &ReverseRequestHandlers,
    callbacks: &LegacySseReverseCallbackDispatcher,
    outbound: LegacySseHttpOutbound,
    persistent_state: Arc<std::sync::Mutex<LegacySsePersistentState>>,
    request: &JsonRpcRequest,
) -> Option<LegacySseReverseRequestDispatch> {
    let request_id = request.id.clone()?;
    if request.method.starts_with("notifications/") {
        return crate::invalid_notification_request_response(request)
            .map(LegacySseReverseRequestDispatch::Immediate);
    }
    if request.method == "ping" {
        return Some(LegacySseReverseRequestDispatch::Immediate(
            JsonRpcMessage::Response(JsonRpcResponse::success(request_id, serde_json::json!({}))),
        ));
    }

    match request.method.as_str() {
        "sampling/createMessage" if client_capabilities.sampling.is_some() => {
            let dispatch = match handlers.sampling_create_message.as_ref() {
                Some(handler) => match crate::decode_reverse_request_params(request) {
                    Ok(params) => callbacks.dispatch(
                        cx,
                        request_id.clone(),
                        params,
                        Arc::clone(handler),
                        outbound,
                        persistent_state,
                    ),
                    Err(error) => Err(error),
                },
                None => Err(McpError::method_not_found("sampling/createMessage")),
            };
            Some(dispatch.map_or_else(
                |error| {
                    LegacySseReverseRequestDispatch::Immediate(crate::reverse_request_response::<
                        crate::CreateMessageResult,
                    >(
                        request_id, Err(error)
                    ))
                },
                |()| LegacySseReverseRequestDispatch::CallbackAdmitted,
            ))
        }
        "roots/list" if client_capabilities.roots.is_some() => {
            let dispatch = match handlers.roots_list.as_ref() {
                Some(handler) => match crate::decode_reverse_request_params(request) {
                    Ok(params) => callbacks.dispatch(
                        cx,
                        request_id.clone(),
                        params,
                        Arc::clone(handler),
                        outbound,
                        persistent_state,
                    ),
                    Err(error) => Err(error),
                },
                None => Err(McpError::method_not_found("roots/list")),
            };
            Some(dispatch.map_or_else(
                |error| {
                    LegacySseReverseRequestDispatch::Immediate(crate::reverse_request_response::<
                        crate::ListRootsResult,
                    >(
                        request_id, Err(error)
                    ))
                },
                |()| LegacySseReverseRequestDispatch::CallbackAdmitted,
            ))
        }
        // Exact 2024-11-05 never admitted elicitation, including over a
        // ready high-level HTTP/SSE client connection.
        "elicitation/create" => crate::method_not_found_response(request)
            .map(LegacySseReverseRequestDispatch::Immediate),
        _ => crate::method_not_found_response(request)
            .map(LegacySseReverseRequestDispatch::Immediate),
    }
}

/// Structured ready-client ownership of the exact-2024 SSE receive side.
/// Opaque structured owner of an exact-2024 persistent SSE receive task.
///
/// This type is public only because it is retained inside a public
/// [`ClientHttpConnection`] variant. Its state and lifecycle operations remain
/// private to the connection so callers cannot detach or replace the reader.
#[doc(hidden)]
#[cfg(feature = "legacy-2024-11-05")]
pub struct LegacySsePersistentReceiver {
    state: Arc<std::sync::Mutex<LegacySsePersistentState>>,
    task: asupersync::runtime::TaskHandle<()>,
    outbound: LegacySseHttpOutbound,
    reverse_callbacks: LegacySseReverseCallbackDispatcher,
}

#[cfg(not(feature = "legacy-2024-11-05"))]
struct LegacySsePersistentReceiver {
    state: Arc<std::sync::Mutex<LegacySsePersistentState>>,
    task: asupersync::runtime::TaskHandle<()>,
    outbound: LegacySseHttpOutbound,
    reverse_callbacks: LegacySseReverseCallbackDispatcher,
}

impl LegacySsePersistentReceiver {
    fn start(
        cx: &Cx,
        mut reader: LegacySseResponseStream,
        outbound: LegacySseHttpOutbound,
        client_capabilities: ClientCapabilities,
        reverse_request_handlers: ReverseRequestHandlers,
    ) -> Result<Self, ClientHttpConnectionError> {
        reverse_request_handlers
            .validate_legacy_capabilities(&client_capabilities)
            .map_err(ClientHttpConnectionError::LegacyCallbackConfiguration)?;
        let state = Arc::new(std::sync::Mutex::new(LegacySsePersistentState {
            pending: HashMap::new(),
            cancelled_response_ids: VecDeque::new(),
            notifications: VecDeque::new(),
            stopped: false,
        }));
        let task_state = Arc::clone(&state);
        let task_outbound = outbound.clone();
        let reverse_callbacks = LegacySseReverseCallbackDispatcher::new();
        let task_reverse_callbacks = LegacySseReverseCallbackDispatcher {
            state: Arc::clone(&reverse_callbacks.state),
            tasks: Arc::clone(&reverse_callbacks.tasks),
        };
        // API callers may pass a request-scoped cancellation token while the
        // surrounding runtime has the spawn gateway. Prefer that ambient
        // runtime context for the region-owned reader, retaining the caller's
        // context only when it is itself spawn-capable.
        let task_cx = Cx::current().unwrap_or_else(|| cx.clone());
        let task = task_cx
            .spawn(move |child_cx| async move {
                loop {
                    if child_cx.checkpoint().is_err() {
                        break;
                    }
                    if task_reverse_callbacks.reap_finished_tasks().is_err() {
                        break;
                    }
                    if task_state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .stopped
                    {
                        break;
                    }
                    let message = match next_legacy_sse_message(&mut reader, &child_cx).await {
                        Ok(Some(message)) => message,
                        Ok(None) | Err(_) => break,
                    };
                    match message {
                        JsonRpcMessage::Request(notification) if notification.is_notification() => {
                            let mut state = task_state
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            if let Some(request_id) = legacy_cancelled_request_id(&notification) {
                                if task_reverse_callbacks.cancel(&request_id) {
                                    continue;
                                }
                                let key = request_id.correlation_key().ok();
                                if let Some(key) = key
                                    && let Some(waiter) = state.pending.remove(&key)
                                {
                                    if state.cancelled_response_ids.len()
                                        < MAX_QUEUED_LEGACY_CANCELLED_RESPONSE_IDS
                                    {
                                        state.cancelled_response_ids.push_back(request_id);
                                        let _ = waiter
                                            .sender
                                            .send(&child_cx, LegacyPersistentResponse::Cancelled);
                                        continue;
                                    }
                                    state.stop();
                                    break;
                                }
                            }
                            if state.notifications.len() >= MAX_QUEUED_LEGACY_NOTIFICATIONS {
                                state.stop();
                                break;
                            }
                            state.notifications.push_back(notification);
                        }
                        JsonRpcMessage::Request(server_request) => {
                            let Some(dispatch) = legacy_sse_reverse_request_dispatch(
                                &child_cx,
                                &client_capabilities,
                                &reverse_request_handlers,
                                &task_reverse_callbacks,
                                task_outbound.clone(),
                                Arc::clone(&task_state),
                                &server_request,
                            ) else {
                                let mut state = task_state
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                state.stop();
                                break;
                            };
                            if let LegacySseReverseRequestDispatch::Immediate(response) = dispatch
                                && task_reverse_callbacks
                                    .send_immediate(
                                        &child_cx,
                                        task_outbound.clone(),
                                        Arc::clone(&task_state),
                                        response,
                                    )
                                    .is_err()
                            {
                                task_reverse_callbacks.close();
                                break;
                            }
                        }
                        JsonRpcMessage::Response(response) => {
                            let Some(response_id) = response.id.clone() else {
                                let mut state = task_state
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                state.stop();
                                break;
                            };
                            let Ok(key) = response_id.correlation_key() else {
                                let mut state = task_state
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                state.stop();
                                break;
                            };
                            let waiter = {
                                let mut state = task_state
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                if let Some(position) = state
                                    .cancelled_response_ids
                                    .iter()
                                    .position(|cancelled| cancelled.correlates_with(&response_id))
                                {
                                    state.cancelled_response_ids.remove(position);
                                    continue;
                                }
                                let waiter = state.pending.remove(&key);
                                if waiter.is_none() {
                                    state.stop();
                                }
                                waiter
                            };
                            let Some(waiter) = waiter else {
                                break;
                            };
                            let _ = waiter
                                .sender
                                .send(&child_cx, LegacyPersistentResponse::Response(response));
                        }
                    }
                }
                task_state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .stop();
                task_reverse_callbacks.close();
            })
            .map_err(|_| ClientHttpConnectionError::LegacyPersistentReceiverUnavailable)?;
        Ok(Self {
            state,
            task,
            outbound,
            reverse_callbacks,
        })
    }

    fn take_notification(&self) -> Option<JsonRpcRequest> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .notifications
            .pop_front()
    }

    async fn start_request(
        &self,
        cx: &Cx,
        method: &str,
        parameters: serde_json::Value,
        request_id: RequestId,
    ) -> Result<LegacyHttpRequest, ClientHttpConnectionError> {
        let key = request_id
            .correlation_key()
            .map_err(|_| ClientHttpConnectionError::LegacyPersistentReceiverStopped)?;
        let (sender, receiver) = oneshot::channel();
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.stopped {
                return Err(ClientHttpConnectionError::LegacyPersistentReceiverStopped);
            }
            if state.pending.len() >= MAX_PERSISTENT_LEGACY_RESPONSE_WAITERS {
                return Err(ClientHttpConnectionError::LegacyPersistentResponseQueueFull);
            }
            if state
                .cancelled_response_ids
                .iter()
                .any(|cancelled_id| cancelled_id.correlates_with(&request_id))
            {
                return Err(
                    ClientHttpConnectionError::LegacyCancelledRequestStillDraining { request_id },
                );
            }
            if state.pending.contains_key(&key) {
                return Err(ClientHttpConnectionError::LegacyPersistentResponseQueueFull);
            }
            state
                .pending
                .insert(key.clone(), LegacyPersistentResponseWaiter { sender });
        }
        let request = JsonRpcRequest::new(method, Some(parameters), request_id.clone());
        if let Err(error) = self
            .outbound
            .send(cx, &JsonRpcMessage::Request(request))
            .await
        {
            let LegacySseOutboundSendError {
                error,
                request_may_have_reached_peer,
            } = error;
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if request_may_have_reached_peer {
                retire_abandoned_persistent_waiter(&mut state, &key, request_id)?;
            } else {
                state.pending.remove(&key);
            }
            return Err(ClientHttpConnectionError::Legacy(error));
        }
        Ok(LegacyHttpRequest {
            commit: LegacyHttpRequestCommit { request_id },
            key,
            receiver,
            state: Arc::clone(&self.state),
            outbound: self.outbound.clone(),
            terminal: false,
        })
    }

    async fn request(
        &self,
        cx: &Cx,
        method: &str,
        parameters: serde_json::Value,
        request_id: RequestId,
    ) -> Result<JsonRpcMessage, ClientHttpConnectionError> {
        let mut request = self
            .start_request(cx, method, parameters, request_id)
            .await?;
        request.wait(cx).await
    }
}

impl Drop for LegacySsePersistentReceiver {
    fn drop(&mut self) {
        self.reverse_callbacks.close();
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stop();
        self.task.abort();
    }
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
    /// Opens the configured exact-2024 SSE GET endpoint and admits its first
    /// `endpoint` event only when it names the immutable configured POST
    /// resource.
    #[cfg(feature = "legacy-2024-11-05")]
    pub async fn connect(
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
    ) -> Result<Self, LegacySseHttpClientError> {
        Self::connect_inner(cx, protocol_plan).await
    }

    /// Opens the configured SSE GET endpoint and admits its first `endpoint`
    /// event only when it names the immutable configured POST resource: the
    /// advertised target must equal the configured one exactly, or differ
    /// from a query-free configured target solely by an appended query
    /// component (the exact 2024-11-05 lane advertises a session-scoped
    /// message endpoint). Any scheme, authority, or path divergence remains
    /// a hard mismatch.
    #[cfg(feature = "legacy-2024-11-05")]
    async fn connect_inner(
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
            stream: Some(stream),
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

    fn outbound(&self) -> LegacySseHttpOutbound {
        LegacySseHttpOutbound {
            advertised_message_post_target: self.advertised_message_post_target.clone(),
            post_client: self.post_client.clone(),
        }
    }

    fn take_reader(&mut self) -> Option<LegacySseResponseStream> {
        self.stream.take()
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
        self.outbound()
            .send(cx, message)
            .await
            .map_err(|error| error.error)
    }

    /// Waits for the next legacy SSE `message` JSON-RPC envelope.
    ///
    /// A repeated `endpoint` event is refused instead of allowing it to change
    /// the POST destination after connection establishment.
    pub async fn next_message(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<JsonRpcMessage>, LegacySseHttpClientError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or(LegacySseHttpClientError::ReceiverOwnedByReadyClient)?;
        next_legacy_sse_message(stream, cx).await
    }
}

impl LegacySseHttpOutbound {
    async fn send(
        &self,
        cx: &Cx,
        message: &JsonRpcMessage,
    ) -> Result<(), LegacySseOutboundSendError> {
        if cx.checkpoint().is_err() {
            return Err(LegacySseOutboundSendError::not_submitted(
                LegacySseHttpClientError::Cancelled,
            ));
        }
        let mut body = serde_json::to_vec(message).map_err(|_| {
            LegacySseOutboundSendError::not_submitted(
                LegacySseHttpClientError::MessageEncodingFailed,
            )
        })?;
        body.push(b'\n');
        let mut exchange = Box::pin(self.post_client.request_streaming(
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
        ));
        // The native HTTP exchange checks `cx` before and after its response
        // head operation, but a quiet peer leaves that future parked on I/O.
        // Bind a second pending future to the explicit caller context so its
        // cancellation waker can win while the response head is still absent.
        // Dropping `exchange` then closes this request-owned connection; the
        // conservative submitted classification below retains the response
        // tombstone in case the peer already accepted the POST.
        let (_cancellation_guard, mut cancellation_signal) = oneshot::channel::<()>();
        let mut cancellation = std::pin::pin!(cancellation_signal.recv(cx));
        let mut response = poll_fn(|task_cx| {
            if cancellation.as_mut().poll(task_cx).is_ready() {
                return Poll::Ready(Err(LegacySseHttpClientError::Cancelled));
            }
            match exchange.as_mut().poll(task_cx) {
                Poll::Ready(response) => Poll::Ready(response.map_err(|error| {
                    LegacySseHttpClientError::Executor(map_transport_error(error))
                })),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
        .map_err(LegacySseOutboundSendError::submitted)?;
        if cx.checkpoint().is_err() {
            return Err(LegacySseOutboundSendError::submitted(
                LegacySseHttpClientError::Cancelled,
            ));
        }
        validate_content_encoding(&response.head.headers)
            .map_err(LegacySseHttpClientError::Executor)
            .map_err(LegacySseOutboundSendError::submitted)?;
        if (300..400).contains(&response.head.status) {
            return Err(LegacySseOutboundSendError::submitted(
                LegacySseHttpClientError::MessagePostRedirect {
                    status: response.head.status,
                },
            ));
        }
        if !(200..300).contains(&response.head.status) {
            return Err(LegacySseOutboundSendError::submitted(
                LegacySseHttpClientError::MessagePostRejected {
                    status: response.head.status,
                },
            ));
        }
        drain_native_response(cx, &mut response, MAX_LEGACY_SSE_MESSAGE_BYTES)
            .await
            .map_err(LegacySseHttpClientError::Executor)
            .map_err(LegacySseOutboundSendError::submitted)
    }
}

async fn next_legacy_sse_message(
    stream: &mut LegacySseResponseStream,
    cx: &Cx,
) -> Result<Option<JsonRpcMessage>, LegacySseHttpClientError> {
    match stream.next_event(cx).await? {
        Some(LegacySseEvent::Message(payload)) => {
            decode_strict_jsonrpc_message(payload.as_bytes(), MAX_LEGACY_SSE_MESSAGE_BYTES)
                .map(Some)
                .map_err(|_| LegacySseHttpClientError::MessageDecodeFailed)
        }
        Some(LegacySseEvent::Endpoint(_)) => Err(LegacySseHttpClientError::UnexpectedEndpointEvent),
        None => Ok(None),
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
    /// A ready high-level client owns this connection's SSE reader.
    ReceiverOwnedByReadyClient,
    /// One native body frame completed too many legacy events before the
    /// caller could receive the next one.
    PendingSseEventCountExceeded { maximum_events: usize },
    /// Complete legacy events waiting for delivery exceeded their byte bound.
    PendingSseEventBytesExceeded { maximum_bytes: usize },
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
            Self::ReceiverOwnedByReadyClient => {
                formatter.write_str("legacy SSE reader is owned by the ready HTTP client")
            }
            Self::PendingSseEventCountExceeded { maximum_events } => write!(
                formatter,
                "legacy SSE retained more than {maximum_events} complete events before delivery"
            ),
            Self::PendingSseEventBytesExceeded { maximum_bytes } => write!(
                formatter,
                "legacy SSE retained more than {maximum_bytes} event bytes before delivery"
            ),
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
            | Self::MessageDecodeFailed
            | Self::ReceiverOwnedByReadyClient
            | Self::PendingSseEventCountExceeded { .. }
            | Self::PendingSseEventBytesExceeded { .. } => None,
        }
    }
}

#[derive(Debug)]
enum LegacySseEvent {
    Endpoint(String),
    Message(String),
}

impl LegacySseEvent {
    fn len(&self) -> usize {
        match self {
            Self::Endpoint(value) | Self::Message(value) => value.len(),
        }
    }
}

struct LegacySseResponseStream {
    response: Option<ClientStreamingResponse<ClientIo>>,
    parser: LegacySseParser,
    pending_events: VecDeque<LegacySseEvent>,
    pending_event_bytes: usize,
}

impl LegacySseResponseStream {
    fn new(response: ClientStreamingResponse<ClientIo>) -> Self {
        Self {
            response: Some(response),
            parser: LegacySseParser::default(),
            pending_events: VecDeque::new(),
            pending_event_bytes: 0,
        }
    }

    fn close_for_cancellation(&mut self) {
        self.response = None;
        self.parser.finish();
        self.pending_events.clear();
        self.pending_event_bytes = 0;
    }

    /// Retains one completed legacy SSE event after aggregate admission.
    ///
    /// The parser calls this at each blank-line dispatch rather than first
    /// collecting every event from a native body frame. The pending count and
    /// byte limits are therefore an admission boundary, not a post-allocation
    /// check.
    fn retain_pending_event(
        &mut self,
        event: LegacySseEvent,
    ) -> Result<(), LegacySseHttpClientError> {
        let event_count = self
            .pending_events
            .len()
            .checked_add(1)
            .filter(|count| *count <= MAX_PENDING_LEGACY_SSE_EVENTS)
            .ok_or(LegacySseHttpClientError::PendingSseEventCountExceeded {
                maximum_events: MAX_PENDING_LEGACY_SSE_EVENTS,
            });
        if let Err(error) = event_count {
            self.close_for_cancellation();
            return Err(error);
        }

        let event_bytes = self
            .pending_event_bytes
            .checked_add(event.len())
            .filter(|bytes| *bytes <= MAX_PENDING_LEGACY_SSE_EVENT_BYTES)
            .ok_or(LegacySseHttpClientError::PendingSseEventBytesExceeded {
                maximum_bytes: MAX_PENDING_LEGACY_SSE_EVENT_BYTES,
            });
        let event_bytes = match event_bytes {
            Ok(event_bytes) => event_bytes,
            Err(error) => {
                self.close_for_cancellation();
                return Err(error);
            }
        };

        self.pending_events.push_back(event);
        self.pending_event_bytes = event_bytes;
        Ok(())
    }

    async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<LegacySseEvent>, LegacySseHttpClientError> {
        loop {
            if cx.checkpoint().is_err() {
                self.close_for_cancellation();
                return Err(LegacySseHttpClientError::Cancelled);
            }
            if let Some(event) = self.pending_events.pop_front() {
                self.pending_event_bytes = self.pending_event_bytes.saturating_sub(event.len());
                return Ok(Some(event));
            }
            let Some(response) = self.response.as_mut() else {
                return Ok(None);
            };
            let (_cancellation_guard, mut cancellation_signal) = oneshot::channel::<()>();
            let mut cancellation = std::pin::pin!(cancellation_signal.recv(cx));
            let frame = poll_fn(|task_cx| {
                if cancellation.as_mut().poll(task_cx).is_ready() {
                    return Poll::Ready(Err(()));
                }
                match Pin::new(&mut response.body).poll_frame(task_cx) {
                    Poll::Ready(frame) => Poll::Ready(Ok(frame)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            let frame = match frame {
                Ok(frame) => frame,
                Err(()) => {
                    self.close_for_cancellation();
                    return Err(LegacySseHttpClientError::Cancelled);
                }
            };
            let frame = match reject_body_frame_after_cancellation(cx, frame) {
                Ok(frame) => frame,
                Err(ModernHttpExecutorError::Cancelled) => {
                    self.close_for_cancellation();
                    return Err(LegacySseHttpClientError::Cancelled);
                }
                Err(error) => return Err(LegacySseHttpClientError::Executor(error)),
            };
            let Some(frame) = frame else {
                self.response = None;
                self.parser.finish();
                return Ok(None);
            };
            let frame = match frame {
                Ok(frame) => frame,
                Err(_) => {
                    self.close_for_cancellation();
                    return Err(LegacySseHttpClientError::Executor(
                        ModernHttpExecutorError::ResponseBodyReadFailed,
                    ));
                }
            };
            let Some(mut data) = frame.into_data() else {
                continue;
            };
            while data.has_remaining() {
                let chunk = data.chunk();
                let mut parser = std::mem::take(&mut self.parser);
                match parser.push_with(chunk, |event| self.retain_pending_event(event)) {
                    Ok(()) => self.parser = parser,
                    Err(error) => {
                        self.close_for_cancellation();
                        return Err(error);
                    }
                }
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
    /// Parses one native body chunk and admits each completed event before
    /// parsing the next. The caller owns the aggregate pending-event budget;
    /// this parser owns only one partial event at a time.
    fn push_with(
        &mut self,
        bytes: &[u8],
        mut accept: impl FnMut(LegacySseEvent) -> Result<(), LegacySseHttpClientError>,
    ) -> Result<(), LegacySseHttpClientError> {
        for &byte in bytes {
            if self.pending_cr {
                self.pending_cr = false;
                if byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\r' => {
                    self.finish_line_with(&mut accept)?;
                    self.pending_cr = true;
                }
                b'\n' => self.finish_line_with(&mut accept)?,
                _ => {
                    if self.line.len() >= MAX_LEGACY_SSE_LINE_BYTES {
                        return Err(LegacySseHttpClientError::SseLineTooLong);
                    }
                    self.line.push(byte);
                }
            }
        }
        Ok(())
    }

    fn finish(&mut self) {
        self.line.clear();
        self.reset_event();
    }

    fn finish_line_with(
        &mut self,
        accept: &mut impl FnMut(LegacySseEvent) -> Result<(), LegacySseHttpClientError>,
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
                    LegacySseEventType::Endpoint => accept(LegacySseEvent::Endpoint(data))?,
                    LegacySseEventType::Message => accept(LegacySseEvent::Message(data))?,
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

/// Applies the cancellation boundary after the body poll has selected a ready
/// frame or EOF. The body and cancellation signal can become ready in the same
/// poll, so the pre-poll cancellation select alone cannot safely admit either
/// outcome to a caller.
fn reject_body_frame_after_cancellation<T, E>(
    cx: &Cx,
    frame: Option<Result<Frame<T>, E>>,
) -> Result<Option<Result<Frame<T>, E>>, ModernHttpExecutorError> {
    cx.checkpoint()
        .map_err(|_| ModernHttpExecutorError::Cancelled)?;
    Ok(frame)
}

async fn drain_native_response(
    cx: &Cx,
    response: &mut ClientStreamingResponse<ClientIo>,
    maximum_bytes: usize,
) -> Result<(), ModernHttpExecutorError> {
    let mut consumed = 0_usize;
    let (_cancellation_guard, mut cancellation_signal) = oneshot::channel::<()>();
    loop {
        if cx.checkpoint().is_err() {
            return Err(ModernHttpExecutorError::Cancelled);
        }
        let mut cancellation = std::pin::pin!(cancellation_signal.recv(cx));
        let frame = poll_fn(|task_cx| {
            if cancellation.as_mut().poll(task_cx).is_ready() {
                return Poll::Ready(Err(()));
            }
            match Pin::new(&mut response.body).poll_frame(task_cx) {
                Poll::Ready(frame) => Poll::Ready(Ok(frame)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
        .map_err(|()| ModernHttpExecutorError::Cancelled)?;
        let frame = reject_body_frame_after_cancellation(cx, frame)?;
        let Some(frame) = frame else {
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
        &client_info.to_implementation(),
        client_capabilities,
        method,
        parameters,
        request_id,
        None,
    )
}

fn validate_mrtr_request_id(request_id: &RequestId) -> Result<(), ModernHttpMrtrError> {
    if request_id.validate().is_err() {
        return Err(ModernHttpMrtrError::InvalidRequestId {
            request_id: request_id.clone(),
        });
    }
    Ok(())
}

async fn await_mrtr_until<T>(
    cx: &Cx,
    deadline: Instant,
    future: impl Future<Output = Result<T, ModernHttpMrtrError>>,
) -> Result<T, ModernHttpMrtrError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| {
            ModernHttpMrtrError::Driver(McpError::internal_error(
                "MRTR operation absolute deadline elapsed",
            ))
        })?;
    if remaining.is_zero() {
        return Err(ModernHttpMrtrError::Driver(McpError::internal_error(
            "MRTR operation absolute deadline elapsed",
        )));
    }
    asupersync::time::timeout(cx.now(), remaining, future)
        .await
        .map_err(|_| {
            ModernHttpMrtrError::Driver(McpError::internal_error(
                "MRTR operation absolute deadline elapsed",
            ))
        })?
}

fn mrtr_retry_parameters(
    mut parameters: serde_json::Value,
    input_required: &InputRequiredResult,
    input_responses: MrtrInputResponses,
) -> McpResult<serde_json::Value> {
    if input_responses.len() > MAX_MRTR_INPUT_RESPONSES {
        return Err(McpError::invalid_params(format!(
            "MRTR inputResponses must not exceed {MAX_MRTR_INPUT_RESPONSES} entries",
        )));
    }

    let input_requests = input_required.input_requests();
    if input_requests.is_none() && !input_responses.is_empty() {
        return Err(McpError::invalid_params(
            "MRTR inputResponses require peer inputRequests",
        ));
    }
    if let Some(input_requests) = input_requests {
        for key in input_responses.keys() {
            if !input_requests
                .members()
                .iter()
                .any(|request| request.name == *key)
            {
                return Err(McpError::invalid_params(
                    "MRTR inputResponses contain a key not requested by the peer",
                ));
            }
        }
        for request in input_requests.members() {
            if !input_responses.contains_key(&request.name) {
                return Err(McpError::invalid_params(
                    "MRTR inputResponses must include every key requested by the peer",
                ));
            }
        }
    }
    if input_responses.is_empty() && input_required.request_state().is_none() {
        return Err(McpError::invalid_params(
            "MRTR retry requires inputResponses or requestState",
        ));
    }

    let parameters = parameters
        .as_object_mut()
        .ok_or_else(|| McpError::internal_error("MRTR retry parameters must remain an object"))?;
    if !input_responses.is_empty() {
        parameters.insert(
            "inputResponses".to_owned(),
            serde_json::to_value(input_responses).map_err(|error| {
                McpError::internal_error(format!(
                    "MRTR inputResponses could not serialize: {error}"
                ))
            })?,
        );
    }
    if let Some(request_state) = input_required.request_state() {
        parameters.insert(
            "requestState".to_owned(),
            serde_json::Value::String(request_state.to_owned()),
        );
    }
    Ok(serde_json::Value::Object(parameters.clone()))
}

fn mrtr_input_required_for_method<'a>(
    method: &str,
    result: &'a CoreResult,
) -> Option<&'a InputRequiredResult> {
    match (method, result) {
        (TOOLS_CALL, CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { result, .. }))
        | (
            RESOURCES_READ,
            CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { result, .. }),
        )
        | (
            PROMPTS_GET,
            CoreResult::Final(FinalCoreResult::PromptsGetInputRequired { result, .. }),
        ) => Some(result),
        _ => None,
    }
}

fn decode_mrtr_json_response(
    core_request: &CoreRequest,
    request_id: &RequestId,
    body: &[u8],
    maximum_response_bytes: usize,
) -> Result<FinalCoreResult, ModernHttpMrtrError> {
    let message = decode_strict_jsonrpc_message(body, maximum_response_bytes)
        .map_err(ModernHttpMrtrError::JsonRpcAdmission)?;
    let JsonRpcMessage::Response(response) = message else {
        return Err(ModernHttpMrtrError::UnexpectedResponseMessage);
    };
    let admission = decode_strict_jsonrpc_response(body, maximum_response_bytes)
        .map_err(ModernHttpMrtrError::JsonRpcAdmission)?;
    if admission.response() != &response {
        return Err(ModernHttpMrtrError::JsonRpcAdmission(
            JsonRpcAdmissionError::InvalidEnvelope,
        ));
    }
    if !response
        .id
        .as_ref()
        .is_some_and(|response_id| response_id.correlates_with(request_id))
    {
        return Err(ModernHttpMrtrError::ResponseIdMismatch {
            expected: request_id.clone(),
            actual: response.id,
        });
    }
    if let Some(error) = response.error.as_ref() {
        return Err(ModernHttpMrtrError::RemoteError {
            code: error.code.clone(),
            message: error.message.clone(),
        });
    }
    let (_, result_source) = admission.into_parts();
    let result_source = result_source
        .as_deref()
        .ok_or(ModernHttpMrtrError::MissingResult)?;
    let CoreResult::Final(result) = core_request
        .decode_response_result(&response, result_source)
        .map_err(ModernHttpMrtrError::TypedResult)?
    else {
        return Err(ModernHttpMrtrError::UnexpectedCoreResult);
    };
    Ok(result)
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
    client_info: &fastmcp_protocol::common_types::Implementation,
    client_capabilities: &ClientCapabilities,
    method: &str,
    parameters: serde_json::Value,
    request_id: Option<RequestId>,
    client_extensions: Option<&BTreeMap<String, serde_json::Value>>,
) -> Result<ModernHttpRequest, ModernHttpClientError> {
    validate_final_method(method, request_id.is_some())?;
    build_modern_request_after_method_validation(
        target,
        client_info,
        client_capabilities,
        method,
        parameters,
        request_id,
        client_extensions,
    )
}

/// Builds an official Tasks extension request after its typed wire envelope
/// and bilateral discovery admission have already been proven by the caller.
///
/// This deliberately remains separate from the generic final-method builder:
/// extension methods are not part of the core method registry and must never
/// become reachable through the ungated raw request surface.
#[cfg(feature = "tasks")]
fn build_modern_tasks_request(
    target: &str,
    client_info: &fastmcp_protocol::common_types::Implementation,
    client_capabilities: &ClientCapabilities,
    method: &'static str,
    parameters: serde_json::Value,
    request_id: RequestId,
    client_extensions: &BTreeMap<String, serde_json::Value>,
) -> Result<ModernHttpRequest, ModernHttpClientError> {
    if !matches!(method, TASK_GET | TASK_UPDATE | TASK_CANCEL) {
        return Err(ModernHttpClientError::TasksRequestEncoding { method });
    }
    if request_id.validate().is_err() {
        return Err(ModernHttpClientError::InvalidTasksRequestId { method });
    }
    build_modern_request_after_method_validation(
        target,
        client_info,
        client_capabilities,
        method,
        parameters,
        Some(request_id),
        Some(client_extensions),
    )
}

/// Adds final HTTP metadata after the caller has validated that the method is
/// reachable through its own core or extension-specific admission path.
fn build_modern_request_after_method_validation(
    target: &str,
    client_info: &fastmcp_protocol::common_types::Implementation,
    client_capabilities: &ClientCapabilities,
    method: &str,
    parameters: serde_json::Value,
    request_id: Option<RequestId>,
    client_extensions: Option<&BTreeMap<String, serde_json::Value>>,
) -> Result<ModernHttpRequest, ModernHttpClientError> {
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
    let field = match method {
        TOOLS_CALL | PROMPTS_GET => Some("name"),
        RESOURCES_READ => Some("uri"),
        _ => None,
    };
    #[cfg(feature = "tasks")]
    let field = field
        .or_else(|| matches!(method, TASK_GET | TASK_UPDATE | TASK_CANCEL).then_some("taskId"));
    let Some(field) = field else {
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
    // Connection health-check. Not a member of the official 2026 client-request
    // union; the server still answers `{}` on the stateless HTTP surface.
    if method == PING {
        return if has_request_id {
            Ok(())
        } else {
            Err(ModernHttpClientError::MissingRequestId {
                method: method.to_owned(),
            })
        };
    }
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
    let admission = decode_strict_jsonrpc_response(body, MAX_MODERN_HTTP_PROBE_BODY_BYTES)
        .map_err(|_| ModernHttpClientError::InvalidDiscoveryResponse)?;
    if admission.response() != &response {
        return Err(ModernHttpClientError::InvalidDiscoveryResponse);
    }
    if !response
        .id
        .as_ref()
        .is_some_and(|response_id| response_id.correlates_with(&RequestId::Number(1)))
    {
        return Err(ModernHttpClientError::InvalidDiscoveryResponse);
    }
    if let Some(error) = response.error {
        return Err(ModernHttpClientError::DiscoveryRejected {
            code: error.code,
            message: error.message,
            data: error.data,
        });
    }
    let result_source = admission
        .raw_result()
        .ok_or(ModernHttpClientError::InvalidDiscoveryResponse)?;
    let discovery: ServerDiscoverResult = serde_json::from_str(result_source)
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
    if headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("mcp-session-id"))
    {
        return Err(ModernHttpExecutorError::ForbiddenResponseSessionHeader);
    }
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
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::fmt::Write as _;
    use std::future::Future as _;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::task::{Context, Poll, Wake, Waker};
    use std::thread;
    use std::time::{Duration, Instant};

    use asupersync::bytes::Bytes;
    use asupersync::channel::oneshot;
    use asupersync::http::Frame;
    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use asupersync::{CancelKind, Cx};
    #[cfg(feature = "legacy-2024-11-05")]
    use fastmcp_core::McpError;
    #[cfg(feature = "apps")]
    use fastmcp_protocol::extensions::{
        ClientExtensionDiscovery, ExtensionDescriptorRegistry, McpAppsClientSettings,
        OFFICIAL_MCP_APPS_EXTENSION_ID, official_mcp_apps_negotiation_resolver,
        register_official_mcp_apps_extension,
    };
    use fastmcp_protocol::methods::{
        PROMPTS_GET, RESOURCES_READ, SERVER_DISCOVER, SUBSCRIPTIONS_LISTEN, TOOLS_CALL,
    };
    #[cfg(feature = "legacy-2024-11-05")]
    use fastmcp_protocol::protocol_policy::LEGACY_PROTOCOL_VERSION;
    use fastmcp_protocol::protocol_policy::{MODERN_PROTOCOL_VERSION, ProtocolEra};
    use fastmcp_protocol::{
        ClientCapabilities, ClientInfo, CoreResult, FinalCoreResult, JsonRpcRequest, RequestId,
        ServerNotification, SubscriptionFilter,
    };

    #[cfg(feature = "apps")]
    use super::merge_client_extensions;
    use super::{
        ClientHttpConnection, ClientHttpConnectionError, LegacyPersistentResponse,
        LegacyPersistentResponseWaiter, LegacyPersistentWaiterRetirement, LegacySsePersistentState,
        MAX_IGNORED_RESPONSE_CONTENT_ENCODING_EMPTY_ELEMENTS, MAX_MRTR_CONTINUATION_ROUNDS,
        MAX_PENDING_MODERN_HTTP_SSE_EVENT_BYTES, MAX_PENDING_MODERN_HTTP_SSE_EVENTS,
        MAX_QUEUED_FINAL_HTTP_PROGRESS_NOTIFICATIONS, MAX_QUEUED_LEGACY_CANCELLED_RESPONSE_IDS,
        ModernHttpClient, ModernHttpClientError, ModernHttpExecutorError, ModernHttpFinalCoreEvent,
        ModernHttpFinalCoreListenError, ModernHttpMrtrError, ModernHttpResponseKind,
        ModernHttpSubscriptionListenCollector, ModernHttpSubscriptionListenError,
        cancellation_control_is_authorized, decode_modern_discovery_response,
        reject_body_frame_after_cancellation, retire_abandoned_persistent_waiter,
        validate_response_head,
    };
    #[cfg(feature = "legacy-2024-11-05")]
    use super::{
        LegacySseConnection, LegacySseHttpClientError, MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES,
        MAX_PENDING_LEGACY_SSE_EVENT_BYTES, MAX_PENDING_LEGACY_SSE_EVENTS,
    };
    #[cfg(feature = "tasks")]
    use crate::FinalToolCallOutcome;
    #[cfg(feature = "apps")]
    use crate::session::ClientExtensionRuntime;
    use crate::sse::SseLimits;
    use crate::{
        CanonicalHttpUrl, ClientBuilder, ClientProtocolPlan, ProtocolPolicy, ReverseRequestHandlers,
    };

    #[derive(Debug)]
    struct CapturedHttpRequest {
        head: String,
        body: Vec<u8>,
    }

    #[derive(Debug, Default)]
    struct CountingWake(AtomicUsize);

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    const LEGACY_TEST_PEER_BOUND: Duration = Duration::from_secs(2);
    const LEGACY_TEST_PEER_POLL_INTERVAL: Duration = Duration::from_millis(1);

    fn persistent_state_with_waiter(
        request_id: RequestId,
        cancelled_response_ids: VecDeque<RequestId>,
    ) -> (LegacySsePersistentState, fastmcp_protocol::CorrelationKey) {
        let key = request_id
            .correlation_key()
            .expect("test request ID has a correlation key");
        let (sender, _receiver) = oneshot::channel::<LegacyPersistentResponse>();
        let mut pending = HashMap::new();
        pending.insert(key.clone(), LegacyPersistentResponseWaiter { sender });
        (
            LegacySsePersistentState {
                pending,
                cancelled_response_ids,
                notifications: VecDeque::new(),
                stopped: false,
            },
            key,
        )
    }

    #[test]
    fn abandoned_persistent_waiter_retains_one_late_response_tombstone() {
        let request_id = RequestId::Number(41);
        let (mut state, key) = persistent_state_with_waiter(request_id.clone(), VecDeque::new());

        let retirement = retire_abandoned_persistent_waiter(&mut state, &key, request_id.clone())
            .expect("one cancelled caller retains its exact late-response tombstone");

        assert_eq!(retirement, LegacyPersistentWaiterRetirement::Cancelled);
        assert!(cancellation_control_is_authorized(retirement));
        assert!(state.pending.is_empty());
        assert_eq!(state.cancelled_response_ids, VecDeque::from([request_id]));
        assert!(!state.stopped);
    }

    #[test]
    fn reader_wins_request_retirement_emits_no_cancellation_control() {
        let request_id = RequestId::Number(42);
        let (mut state, key) = persistent_state_with_waiter(request_id.clone(), VecDeque::new());

        // Force the reader-wins state: it has removed the waiter to deliver a
        // terminal response, but the handle has not yet observed its oneshot.
        let _terminal_waiter = state.pending.remove(&key);
        let retirement = retire_abandoned_persistent_waiter(&mut state, &key, request_id)
            .expect("reader-won retirement is not a queue failure");

        assert_eq!(retirement, LegacyPersistentWaiterRetirement::ReaderWon);
        assert!(state.cancelled_response_ids.is_empty());
        assert!(
            !cancellation_control_is_authorized(retirement),
            "a reader-won terminal response must authorize zero cancellation control POSTs"
        );
    }

    #[test]
    fn one_extra_abandoned_persistent_waiter_stops_before_losing_response_alignment() {
        let request_id = RequestId::Number(41);
        let cancelled_response_ids = (0..MAX_QUEUED_LEGACY_CANCELLED_RESPONSE_IDS)
            .map(|id| RequestId::Number(id as i64))
            .collect();
        let (mut state, key) =
            persistent_state_with_waiter(request_id.clone(), cancelled_response_ids);

        assert!(matches!(
            retire_abandoned_persistent_waiter(&mut state, &key, request_id),
            Err(ClientHttpConnectionError::LegacyCancelledResponseQueueFull)
        ));
        assert!(state.stopped);
        assert!(state.pending.is_empty());
    }

    #[test]
    fn persistent_receiver_shutdown_releases_waiters_and_retained_ingress() {
        let request_id = RequestId::Number(43);
        let key = request_id
            .correlation_key()
            .expect("test request ID has a correlation key");
        let (sender, mut receiver) = oneshot::channel::<LegacyPersistentResponse>();
        let mut pending = HashMap::new();
        pending.insert(key, LegacyPersistentResponseWaiter { sender });
        let mut state = LegacySsePersistentState {
            pending,
            cancelled_response_ids: VecDeque::from([RequestId::Number(42)]),
            notifications: VecDeque::from([JsonRpcRequest::notification(
                "notifications/message",
                None,
            )]),
            stopped: false,
        };

        state.stop();

        assert!(state.stopped);
        assert!(state.pending.is_empty());
        assert!(state.cancelled_response_ids.is_empty());
        assert!(state.notifications.is_empty());
        assert!(runtime_block_on(receiver.recv(&Cx::for_request())).is_err());
    }

    thread_local! {
        /// Keeps response bodies and connection-owned receive tasks under the
        /// same live runtime across the sequential `block_on` calls made by
        /// one HTTP test. Rebuilding the runtime per call destroys the owner
        /// of a returned stream or spawned legacy receive pump before the
        /// test can drive that value again.
        static HTTP_TEST_RUNTIME: Runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("native HTTP test runtime must build");
    }

    fn runtime_block_on<F: std::future::Future>(future: F) -> F::Output {
        HTTP_TEST_RUNTIME.with(|runtime| runtime.block_on(future))
    }

    /// Accepts one local peer connection without allowing a pre-connect
    /// client failure to strand the peer thread. The caller's deadline bounds
    /// every accept in the scripted wire exchange, while the stop signal
    /// closes the no-connection path before its owner joins the thread.
    fn accept_legacy_test_peer(
        listener: &TcpListener,
        stop: &mpsc::Receiver<()>,
        deadline: Instant,
    ) -> Result<Option<TcpStream>, String> {
        loop {
            match stop.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => return Ok(None),
                Err(mpsc::TryRecvError::Empty) => {}
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_read_timeout(Some(LEGACY_TEST_PEER_BOUND))
                        .map_err(|error| format!("set legacy peer read timeout: {error}"))?;
                    stream
                        .set_write_timeout(Some(LEGACY_TEST_PEER_BOUND))
                        .map_err(|error| format!("set legacy peer write timeout: {error}"))?;
                    return Ok(Some(stream));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    thread::sleep(LEGACY_TEST_PEER_POLL_INTERVAL);
                }
                Err(error) => return Err(format!("accept legacy test peer: {error}")),
            }
        }
    }

    fn signal_legacy_test_peer_stop(stop: &mpsc::SyncSender<()>) {
        match stop.try_send(()) {
            Ok(()) | Err(mpsc::TrySendError::Full(()) | mpsc::TrySendError::Disconnected(())) => {}
        }
    }

    #[cfg(all(feature = "apps", feature = "tasks"))]
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

    #[cfg(feature = "apps")]
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

    #[cfg(feature = "apps")]
    fn generic_mcp_apps_runtime(mime_type: &str) -> Arc<ClientExtensionRuntime> {
        let mut registry = ExtensionDescriptorRegistry::new();
        let apps_id = register_official_mcp_apps_extension(&mut registry)
            .expect("official Apps descriptor registers before the generic builder freeze");
        let settings = McpAppsClientSettings::new(vec![mime_type.to_owned()])
            .expect("generic Apps test MIME is valid");
        Arc::new(
            ClientExtensionRuntime::new(
                registry,
                ClientExtensionDiscovery {
                    extensions: BTreeMap::from([(apps_id, settings.to_extension_settings())]),
                },
                official_mcp_apps_negotiation_resolver,
            )
            .expect("generic Apps runtime freezes one authoritative descriptor registry"),
        )
    }

    #[cfg(feature = "apps")]
    fn assert_generic_mcp_apps_precedes_compatibility_settings(
        generic_mime_type: &str,
        compatibility_mime_type: &str,
        expected_active: bool,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind generic Apps listener");
        let address = listener
            .local_addr()
            .expect("read generic Apps listener address");
        let modern_target = format!("http://{address}/mcp");
        let expected_generic_settings = serde_json::json!({
            "mimeTypes": [generic_mime_type]
        });
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept generic Apps discovery");
            let probe = read_request(&mut stream);
            let probe_document = serde_json::from_slice::<serde_json::Value>(&probe.body)
                .expect("generic Apps discovery is JSON-RPC");
            assert_eq!(probe_document["method"], SERVER_DISCOVER);
            assert_eq!(
                probe_document["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
                    [OFFICIAL_MCP_APPS_EXTENSION_ID],
                expected_generic_settings,
                "the frozen generic registry, not dedicated Apps compatibility settings, owns discovery"
            );
            write_response(
                &mut stream,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"extensions":{"io.modelcontextprotocol/ui":{}}},"ttlMs":0,"cacheScope":"private"}}"#,
            );
        });

        let cx = Cx::for_request();
        let connection = runtime_block_on(ClientHttpConnection::connect_with_extensions(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "generic-apps-precedence-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
            Some(
                McpAppsClientSettings::new(vec![compatibility_mime_type.to_owned()])
                    .expect("compatibility Apps test MIME is valid"),
            ),
            Some(generic_mcp_apps_runtime(generic_mime_type)),
        ))
        .expect("generic Apps discovery selects the modern connection");
        assert_eq!(
            connection.mcp_apps_active(),
            expected_active,
            "only the generic Apps setting differs across this precedence pair"
        );
        server.join().expect("generic Apps precedence server joins");
    }

    #[cfg(feature = "apps")]
    #[test]
    fn generic_mcp_apps_registry_precedes_dedicated_compatibility_settings() {
        assert_generic_mcp_apps_precedes_compatibility_settings(
            "text/html;profile=mcp-app",
            "text/html",
            true,
        );
        assert_generic_mcp_apps_precedes_compatibility_settings(
            "text/html",
            "text/html;profile=mcp-app",
            false,
        );
    }

    #[cfg(feature = "apps")]
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
                br#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private","zeta":{"second":2,"first":1},"alpha":1.20e+4}}"#,
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
        let (response, result_source) =
            runtime_block_on(connection.request_json_with_result_source(
                &cx,
                "tools/list",
                serde_json::json!({}),
                RequestId::Number(2),
                4_096,
            ))
            .expect("public client sends the negotiated Apps request");
        assert_eq!(response.id, Some(RequestId::Number(2)));
        assert_eq!(
            result_source.as_deref(),
            Some(
                r#"{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private","zeta":{"second":2,"first":1},"alpha":1.20e+4}"#
            ),
            "the public source-bearing HTTP API retains result member order and number lexemes",
        );
        server.join().expect("Apps negotiation server must join");
    }

    #[cfg(feature = "apps")]
    #[test]
    fn public_http_connection_request_json_with_result_source_is_lossless() {
        assert_public_http_apps_advertisement_after_discovery(true);
    }

    #[cfg(feature = "apps")]
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

    #[cfg(not(feature = "legacy-2024-11-05"))]
    #[test]
    fn feature_off_public_http_constructors_refuse_legacy_before_peer_contact() {
        // `LegacySseHttpClient` is crate-private and its `connect` constructor
        // is compiled out without the legacy feature. These are the remaining
        // public HTTP connection entry points available to a downstream
        // no-feature user.
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind a peer that feature-off constructors must not contact");
        let address = listener
            .local_addr()
            .expect("read feature-off no-contact listener address");
        let legacy_sse = format!("http://{address}/legacy-sse");
        let legacy_message = format!("http://{address}/legacy-message");
        let protocol_plan = plan(
            "http://127.0.0.1:9/unused-modern",
            &legacy_sse,
            &legacy_message,
            ProtocolPolicy::LegacyOnly,
        );
        let client_info = ClientInfo {
            name: "feature-off-direct-http".to_owned(),
            version: "1.0.0".to_owned(),
        };
        let cx = Cx::for_testing();

        let connection_error = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            protocol_plan.clone(),
            client_info.clone(),
            ClientCapabilities::default(),
        ))
        .err()
        .expect("direct policy-bound HTTP connection must reject before contact");
        assert!(matches!(
            connection_error,
            ClientHttpConnectionError::Modern(ModernHttpClientError::FeatureUnavailable(_))
        ));

        let modern_error = runtime_block_on(ModernHttpClient::connect(
            &cx,
            protocol_plan.clone(),
            client_info.clone(),
            ClientCapabilities::default(),
        ))
        .err()
        .expect("direct modern HTTP constructor must reject before contact");
        assert!(matches!(
            modern_error,
            ModernHttpClientError::FeatureUnavailable(_)
        ));

        let client_error = runtime_block_on(crate::HttpClient::connect(
            &cx,
            protocol_plan,
            client_info,
            ClientCapabilities::default(),
        ))
        .err()
        .expect("direct high-level HTTP constructor must reject before contact");
        assert!(matches!(
            client_error,
            crate::HttpClientError::CoreResult(_)
        ));

        listener
            .set_nonblocking(true)
            .expect("configure feature-off no-contact listener");
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
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

    fn final_progress_payload(message_bytes: usize) -> String {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"progressToken\":2,\"progress\":1,\"message\":\"{}\"}}}}",
            "x".repeat(message_bytes)
        )
    }

    fn one_frame_sse_body(payloads: &[String]) -> String {
        let mut body = String::new();
        for payload in payloads {
            write!(&mut body, "data: {payload}\n\n")
                .expect("writing an SSE frame into a String cannot fail");
        }
        body
    }

    fn legacy_sse_body_with_messages(message_target: &str, message_count: usize) -> String {
        let mut body = format!("event: endpoint\ndata: {message_target}\n\n");
        for index in 0..message_count {
            write!(
                &mut body,
                "event: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":{index},\"result\":{{}}}}\n\n"
            )
            .expect("writing a legacy SSE frame into a String cannot fail");
        }
        body
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

    #[cfg(feature = "tasks")]
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

    fn subscriptions_listen_sse_events(acknowledgement_id: &str) -> [String; 4] {
        [
            format!(
                "data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/subscriptions/acknowledged\",\"params\":{{\"_meta\":{{\"io.modelcontextprotocol/subscriptionId\":{acknowledgement_id}}},\"notifications\":{{\"toolsListChanged\":true,\"promptsListChanged\":true}}}}}}\n\n"
            ),
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n".to_owned(),
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/prompts/list_changed\"}\n\n".to_owned(),
            "data: {\"jsonrpc\":\"2.0\",\"id\":2e0,\"result\":{\"resultType\":\"complete\",\"_meta\":{\"io.modelcontextprotocol/subscriptionId\":2.0}}}\n\n".to_owned(),
        ]
    }

    fn run_public_http_subscriptions_listen_terminal(
        terminal_response_id: &str,
        terminal_subscription_id: &str,
    ) -> Result<ModernHttpSubscriptionListenCollector, ClientHttpConnectionError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind subscriptions/listen termination listener");
        let address = listener
            .local_addr()
            .expect("read subscriptions/listen termination address");
        let modern_target = format!("http://{address}/mcp");
        let terminal_response_id = terminal_response_id.to_owned();
        let terminal_subscription_id = terminal_subscription_id.to_owned();
        let server = thread::spawn(move || {
            let (mut discovery, _) = listener.accept().expect("accept termination discovery");
            let discovery_request = read_request(&mut discovery);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&discovery_request.body)
                    .expect("termination discovery is JSON-RPC")["method"],
                SERVER_DISCOVER
            );
            assert!(!discovery_request.head.contains("MCP-Session-Id:"));
            write_response(
                &mut discovery,
                200,
                "application/json",
                modern_discovery_body(),
            );

            let (mut stream, _) = listener
                .accept()
                .expect("accept subscriptions/listen termination request");
            let request = read_request(&mut stream);
            assert!(!request.head.contains("MCP-Session-Id:"));
            let request = serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("termination request is JSON-RPC");
            assert_eq!(request["id"], 2);
            assert_eq!(request["method"], SUBSCRIPTIONS_LISTEN);

            begin_chunked_sse(&mut stream);
            let events = subscriptions_listen_sse_events("2e0");
            write_chunked_sse_event(&mut stream, &events[0]);
            write_chunked_sse_event(
                &mut stream,
                &format!(
                    "data: {{\"jsonrpc\":\"2.0\",\"id\":{terminal_response_id},\"result\":{{\"resultType\":\"complete\",\"_meta\":{{\"io.modelcontextprotocol/subscriptionId\":{terminal_subscription_id}}}}}}}\n\n"
                ),
            );
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
        .expect("modern discovery selects subscriptions/listen");
        let result = runtime_block_on(connection.listen_subscriptions_typed(
            &cx,
            RequestId::Number(2),
            SubscriptionFilter {
                tools_list_changed: Some(true),
                prompts_list_changed: Some(true),
                ..SubscriptionFilter::default()
            },
            SseLimits::new(1_024, 8_192, 16).expect("explicit SSE bounds are nonzero"),
        ));
        server
            .join()
            .expect("subscriptions/listen termination server joins");
        result
    }

    #[cfg(feature = "tasks")]
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

    #[cfg(feature = "tasks")]
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
        assert_eq!(connection.protocol_version(), Some(MODERN_PROTOCOL_VERSION));
        server.join().expect("Tasks HTTP tool server must join");
        result
    }

    #[cfg(feature = "tasks")]
    fn assert_public_http_tasks_lifecycle_request(
        request: CapturedHttpRequest,
        method: &str,
        request_id: i64,
    ) -> serde_json::Value {
        assert!(request.head.contains(&format!("Mcp-Method: {method}\r\n")));
        assert!(
            request
                .head
                .contains("MCP-Protocol-Version: 2026-07-28\r\n")
        );
        let body = serde_json::from_slice::<serde_json::Value>(&request.body)
            .expect("Tasks lifecycle request must be JSON-RPC");
        assert_eq!(body["id"], request_id);
        assert_eq!(body["method"], method);
        let task_id = body["params"]["taskId"]
            .as_str()
            .expect("Tasks lifecycle request carries a taskId");
        assert!(
            request.head.contains(&format!("Mcp-Name: {task_id}\r\n")),
            "Tasks lifecycle request must mirror taskId through Mcp-Name",
        );
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
            serde_json::json!({"io.modelcontextprotocol/tasks": {}})
        );
        body
    }

    #[cfg(feature = "tasks")]
    fn run_public_http_tasks_lifecycle() -> Result<
        (
            fastmcp_protocol::tasks_extension::GetTaskResult,
            fastmcp_protocol::tasks_extension::UpdateTaskResult,
            fastmcp_protocol::tasks_extension::CancelTaskResult,
        ),
        ClientHttpConnectionError,
    > {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind local Tasks lifecycle HTTP listener");
        let address = listener
            .local_addr()
            .expect("read local Tasks lifecycle HTTP address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept Tasks lifecycle probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("Tasks lifecycle probe must be JSON-RPC")["method"],
                "server/discover"
            );
            write_response(
                &mut probe,
                200,
                "application/json",
                &modern_tasks_discovery_body(),
            );

            let (mut get, _) = listener.accept().expect("accept tasks/get request");
            let get_request =
                assert_public_http_tasks_lifecycle_request(read_request(&mut get), "tasks/get", 2);
            assert_eq!(get_request["params"]["taskId"], "task-73");
            write_response(
                &mut get,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","taskId":"task-73","status":"input_required","createdAt":"2026-07-28T12:00:00.000Z","lastUpdatedAt":"2026-07-28T12:00:00.000Z","ttlMs":null,"inputRequests":{}}}"#,
            );

            let (mut update, _) = listener.accept().expect("accept tasks/update request");
            let update_request = assert_public_http_tasks_lifecycle_request(
                read_request(&mut update),
                "tasks/update",
                3,
            );
            assert_eq!(update_request["params"]["taskId"], "task-73");
            assert_eq!(
                update_request["params"]["inputResponses"],
                serde_json::json!({})
            );
            write_response(
                &mut update,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete"}}"#,
            );

            let (mut cancel, _) = listener.accept().expect("accept tasks/cancel request");
            let cancel_request = assert_public_http_tasks_lifecycle_request(
                read_request(&mut cancel),
                "tasks/cancel",
                4,
            );
            assert_eq!(cancel_request["params"]["taskId"], "task-73");
            write_response(
                &mut cancel,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete"}}"#,
            );
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
        .expect("Tasks discovery selects final HTTP lifecycle methods");
        let task_id =
            fastmcp_protocol::FinalTaskId::parse("task-73").expect("bounded Tasks lifecycle ID");
        let result = (|| {
            let get = runtime_block_on(connection.get_task_final(
                &cx,
                RequestId::Number(2),
                task_id.clone(),
                4_096,
            ))?;
            let update = runtime_block_on(connection.update_task_final(
                &cx,
                RequestId::Number(3),
                &get.task,
                BTreeMap::new(),
                4_096,
            ))?;
            let cancel = runtime_block_on(connection.cancel_task_final(
                &cx,
                RequestId::Number(4),
                task_id,
                4_096,
            ))?;
            Ok((get, update, cancel))
        })();
        assert_eq!(connection.selected_protocol_era(), ProtocolEra::Modern2026);
        assert_eq!(connection.protocol_version(), Some(MODERN_PROTOCOL_VERSION));
        server
            .join()
            .expect("Tasks lifecycle HTTP server must join");
        result
    }

    /// Executes two independent final `tasks/get` POSTs after discovery.
    ///
    /// The first response varies only by its returned task ID. The second is
    /// always valid, proving that the first finite response body was consumed
    /// and cannot be mistaken for a later request-owned result.
    #[cfg(feature = "tasks")]
    fn run_public_http_tasks_get_id_pair(
        first_response_task_id: &str,
    ) -> (
        Result<fastmcp_protocol::tasks_extension::GetTaskResult, ClientHttpConnectionError>,
        fastmcp_protocol::tasks_extension::GetTaskResult,
    ) {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind local Tasks ID-pair HTTP listener");
        let address = listener
            .local_addr()
            .expect("read local Tasks ID-pair HTTP address");
        let modern_target = format!("http://{address}/mcp");
        let first_response_task_id = first_response_task_id.to_owned();
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept Tasks ID-pair probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("Tasks ID-pair probe must be JSON-RPC")["method"],
                "server/discover"
            );
            write_response(
                &mut probe,
                200,
                "application/json",
                &modern_tasks_discovery_body(),
            );

            let (mut first, _) = listener
                .accept()
                .expect("accept first independent tasks/get request");
            let first_request = assert_public_http_tasks_lifecycle_request(
                read_request(&mut first),
                "tasks/get",
                2,
            );
            assert_eq!(first_request["params"]["taskId"], "task-73");
            let first_response = format!(
                r#"{{"jsonrpc":"2.0","id":2,"result":{{"resultType":"complete","taskId":"{first_response_task_id}","status":"working","createdAt":"2026-07-28T12:00:00.000Z","lastUpdatedAt":"2026-07-28T12:00:00.000Z","ttlMs":null}}}}"#
            );
            write_response(
                &mut first,
                200,
                "application/json",
                first_response.as_bytes(),
            );

            let (mut second, _) = listener
                .accept()
                .expect("accept fresh tasks/get after the first body is consumed");
            let second_request = assert_public_http_tasks_lifecycle_request(
                read_request(&mut second),
                "tasks/get",
                3,
            );
            assert_eq!(second_request["params"]["taskId"], "task-73");
            write_response(
                &mut second,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","taskId":"task-73","status":"working","createdAt":"2026-07-28T12:00:01.000Z","lastUpdatedAt":"2026-07-28T12:00:01.000Z","ttlMs":null}}"#,
            );
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
        .expect("Tasks discovery selects final HTTP tasks/get");
        let task_id =
            fastmcp_protocol::FinalTaskId::parse("task-73").expect("bounded Tasks task ID");
        let first = runtime_block_on(connection.get_task_final(
            &cx,
            RequestId::Number(2),
            task_id.clone(),
            4_096,
        ));
        let second =
            runtime_block_on(connection.get_task_final(&cx, RequestId::Number(3), task_id, 4_096))
                .expect("fresh tasks/get must not observe the first response body");
        server.join().expect("Tasks ID-pair HTTP server must join");
        (first, second)
    }

    #[cfg(feature = "tasks")]
    #[test]
    fn public_http_tasks_get_exact_id_retains_its_own_response_body() {
        let (first, second) = run_public_http_tasks_get_id_pair("task-73");
        assert_eq!(
            first
                .expect("the matching first tasks/get response is admitted")
                .task
                .base()
                .task_id
                .as_str(),
            "task-73"
        );
        assert_eq!(second.task.base().task_id.as_str(), "task-73");
        assert_eq!(
            second.task.base().last_updated_at.as_str(),
            "2026-07-28T12:00:01.000Z"
        );
    }

    #[cfg(feature = "tasks")]
    #[test]
    fn public_http_tasks_get_rejects_one_field_foreign_id_then_reuses_fresh_body() {
        let (first, second) = run_public_http_tasks_get_id_pair("task-74");
        assert!(matches!(
            first,
            Err(ClientHttpConnectionError::Modern(
                ModernHttpClientError::TasksGetIdMismatch { expected, actual }
            )) if expected.as_str() == "task-73" && actual.as_str() == "task-74"
        ));
        assert_eq!(second.task.base().task_id.as_str(), "task-73");
        assert_eq!(
            second.task.base().last_updated_at.as_str(),
            "2026-07-28T12:00:01.000Z",
            "the valid second response is fresh rather than leaked from the rejected body"
        );
    }

    #[test]
    fn final_core_listener_live_progress_is_exact_and_terminal_closes_body() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind final core listener peer");
        let address = listener
            .local_addr()
            .expect("read final core listener peer address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern discovery probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("modern discovery probe is JSON-RPC")["method"],
                "server/discover"
            );
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            let (mut stream, _) = listener.accept().expect("accept final core tool stream");
            let request = read_request(&mut stream);
            assert!(
                request
                    .head
                    .contains("Accept: application/json, text/event-stream\r\n"),
                "the final-core listener must retain the standard modern response admission"
            );
            let request = serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("final core tool stream request is JSON-RPC");
            assert_eq!(request["id"], 2);
            assert_eq!(request["method"], "tools/call");
            begin_chunked_sse(&mut stream);
            for _ in 0..=MAX_QUEUED_FINAL_HTTP_PROGRESS_NOTIFICATIONS {
                write_chunked_sse_event(
                    &mut stream,
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":2,\"progress\":1e400,\"total\":1e401,\"message\":\"exact\"}}\n\n",
                );
            }
            write_chunked_sse_event(
                &mut stream,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"resultType\":\"complete\",\"content\":[{\"type\":\"text\",\"text\":\"done\"}],\"isError\":false}}\n\n",
            );
            finish_chunked_sse(&mut stream);
        });

        let cx = Cx::for_request();
        let connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "final-core-listener-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("modern discovery selects the public final core listener");
        let mut listener = runtime_block_on(connection.open_final_tool_call_listener(
            &cx,
            RequestId::Number(2),
            "echo",
            serde_json::json!({}),
            SseLimits::new(4_096, 65_536, 8).expect("bounded SSE limits"),
        ))
        .expect("open final core listener");
        for index in 0..=MAX_QUEUED_FINAL_HTTP_PROGRESS_NOTIFICATIONS {
            let progress = runtime_block_on(listener.next_event(&cx))
                .expect("admit exact final progress")
                .expect("progress event before terminal");
            if index == 0 {
                assert!(matches!(
                    progress,
                    ModernHttpFinalCoreEvent::Progress(progress)
                        if progress.progress.as_str() == "1e400"
                            && progress.total.as_ref().is_some_and(|total| total.as_str() == "1e401")
                            && progress.message.as_deref() == Some("exact")
                ));
            } else {
                assert!(matches!(progress, ModernHttpFinalCoreEvent::Progress(_)));
            }
        }
        let terminal = runtime_block_on(listener.next_event(&cx))
            .expect("admit correlated terminal")
            .expect("terminal event after progress");
        assert!(matches!(
            terminal,
            ModernHttpFinalCoreEvent::Terminal(fastmcp_protocol::FinalCoreResult::ToolsCall { .. })
        ));
        assert!(
            listener.stream.response.is_none(),
            "terminal must release the body"
        );
        assert!(
            listener.stream.parser.is_none(),
            "terminal must release the parser"
        );
        assert!(
            runtime_block_on(listener.next_event(&cx))
                .expect("terminal listener cannot resume")
                .is_none()
        );
        server.join().expect("final core listener peer joins");
    }

    fn read_one_frame_final_progress(
        payloads: Vec<String>,
        limits: SseLimits,
    ) -> (
        Result<Option<ModernHttpFinalCoreEvent>, ModernHttpFinalCoreListenError>,
        bool,
        bool,
        usize,
        usize,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind one-frame SSE peer");
        let address = listener
            .local_addr()
            .expect("read one-frame SSE peer address");
        let modern_target = format!("http://{address}/mcp");
        let body = one_frame_sse_body(&payloads);
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept one-frame discovery probe");
            let _ = read_request(&mut probe);
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            let (mut stream, _) = listener.accept().expect("accept one-frame tool request");
            let _ = read_request(&mut stream);
            begin_chunked_sse(&mut stream);
            finish_chunked_sse(&mut stream);
        });

        let cx = Cx::for_request();
        let connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "one-frame-pending-events-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("one-frame discovery selects modern HTTP");
        let mut listener = runtime_block_on(connection.open_final_tool_call_listener(
            &cx,
            RequestId::Number(2),
            "echo",
            serde_json::json!({}),
            limits,
        ))
        .expect("open one-frame final core listener");
        // A chunked-transfer chunk is not guaranteed to remain one native
        // response-body frame: the HTTP decoder may segment it according to
        // its own read buffer. Feed the exact parser frame through the same
        // production helper so this boundary test deterministically exercises
        // the aggregate pending-event contract rather than TCP segmentation.
        let result = match listener.stream.push_body_frame(body.as_bytes()) {
            Ok(()) => runtime_block_on(listener.next_event(&cx)),
            Err(error) => Err(ModernHttpFinalCoreListenError::Executor(error)),
        };
        let snapshot = (
            listener.stream.response.is_some(),
            listener.stream.parser.is_some(),
            listener.stream.pending_events.len(),
            listener.stream.pending_event_bytes,
        );
        drop(listener);
        server.join().expect("one-frame SSE peer joins");
        (result, snapshot.0, snapshot.1, snapshot.2, snapshot.3)
    }

    #[test]
    fn one_frame_pending_sse_events_admit_the_count_limit() {
        let payload = final_progress_payload(0);
        let (result, body_open, parser_open, pending_count, pending_bytes) =
            read_one_frame_final_progress(
                vec![payload.clone(); MAX_PENDING_MODERN_HTTP_SSE_EVENTS],
                SseLimits::new(4_096, 65_536, 8).expect("bounded SSE limits"),
            );

        assert!(matches!(
            result,
            Ok(Some(ModernHttpFinalCoreEvent::Progress(_)))
        ));
        assert!(
            body_open,
            "the admitted stream remains request-owned and live"
        );
        assert!(parser_open, "the admitted stream retains its parser");
        assert_eq!(
            pending_count,
            MAX_PENDING_MODERN_HTTP_SSE_EVENTS - 1,
            "one dispatched event leaves the remaining one-frame payloads bounded"
        );
        assert_eq!(pending_bytes, payload.len() * pending_count);
    }

    #[test]
    fn one_frame_pending_sse_events_reject_one_extra_and_release_body() {
        let (result, body_open, parser_open, pending_count, pending_bytes) =
            read_one_frame_final_progress(
                vec![final_progress_payload(0); MAX_PENDING_MODERN_HTTP_SSE_EVENTS + 1],
                SseLimits::new(4_096, 65_536, 8).expect("bounded SSE limits"),
            );

        assert!(matches!(
            result,
            Err(ModernHttpFinalCoreListenError::Executor(
                ModernHttpExecutorError::PendingSseEventCountExceeded {
                    maximum_events: MAX_PENDING_MODERN_HTTP_SSE_EVENTS,
                }
            ))
        ));
        assert!(!body_open, "count overflow must release the response body");
        assert!(!parser_open, "count overflow must release the parser");
        assert_eq!(pending_count, 0);
        assert_eq!(pending_bytes, 0);
    }

    #[test]
    fn one_frame_pending_sse_bytes_admit_the_byte_limit() {
        let empty_payload = final_progress_payload(0);
        let accepted_message_bytes = MAX_PENDING_MODERN_HTTP_SSE_EVENT_BYTES
            .checked_sub(empty_payload.len())
            .expect("explicit pending byte limit exceeds the progress envelope");
        let accepted_payload = final_progress_payload(accepted_message_bytes);
        let (result, body_open, parser_open, pending_count, pending_bytes) =
            read_one_frame_final_progress(
                vec![accepted_payload.clone()],
                SseLimits::new(accepted_payload.len() + 32, accepted_payload.len() + 32, 8)
                    .expect("SSE limits admit the exact pending payload"),
            );

        assert!(matches!(
            result,
            Ok(Some(ModernHttpFinalCoreEvent::Progress(_)))
        ));
        assert!(body_open, "the exact byte limit remains admitted");
        assert!(parser_open, "the exact byte limit retains the parser");
        assert_eq!(pending_count, 0, "the delivered event is not retained");
        assert_eq!(pending_bytes, 0, "the delivered event is not retained");
    }

    #[test]
    fn one_frame_pending_sse_bytes_reject_one_extra_and_release_body() {
        let empty_payload = final_progress_payload(0);
        let accepted_message_bytes = MAX_PENDING_MODERN_HTTP_SSE_EVENT_BYTES
            .checked_sub(empty_payload.len())
            .expect("explicit pending byte limit exceeds the progress envelope");
        let rejected_payload = final_progress_payload(accepted_message_bytes + 1);
        assert_eq!(
            final_progress_payload(accepted_message_bytes).len(),
            MAX_PENDING_MODERN_HTTP_SSE_EVENT_BYTES
        );
        let (result, body_open, parser_open, pending_count, pending_bytes) =
            read_one_frame_final_progress(
                vec![rejected_payload.clone()],
                SseLimits::new(rejected_payload.len() + 32, rejected_payload.len() + 32, 8)
                    .expect("SSE limits admit the one oversized pending payload"),
            );

        assert!(matches!(
            result,
            Err(ModernHttpFinalCoreListenError::Executor(
                ModernHttpExecutorError::PendingSseEventBytesExceeded {
                    maximum_bytes: MAX_PENDING_MODERN_HTTP_SSE_EVENT_BYTES,
                }
            ))
        ));
        assert!(!body_open, "byte overflow must release the response body");
        assert!(!parser_open, "byte overflow must release the parser");
        assert_eq!(pending_count, 0);
        assert_eq!(pending_bytes, 0);
    }

    #[test]
    fn final_core_listener_rejects_one_terminal_id_change_and_closes_body() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind final core ID peer");
        let address = listener
            .local_addr()
            .expect("read final core ID peer address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern discovery probe");
            let _ = read_request(&mut probe);
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            let (mut stream, _) = listener.accept().expect("accept final core tool stream");
            let request = read_request(&mut stream);
            assert!(
                request
                    .head
                    .contains("Accept: application/json, text/event-stream\r\n"),
                "the final-core listener must retain the standard modern response admission"
            );
            begin_chunked_sse(&mut stream);
            // This differs from the admitted terminal above only in its JSON-RPC ID.
            write_chunked_sse_event(
                &mut stream,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resultType\":\"complete\",\"content\":[{\"type\":\"text\",\"text\":\"done\"}],\"isError\":false}}\n\n",
            );
            finish_chunked_sse(&mut stream);
        });

        let cx = Cx::for_request();
        let connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "final-core-ID-listener-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("modern discovery selects the final core listener");
        let mut listener = runtime_block_on(connection.open_final_core_listener(
            &cx,
            TOOLS_CALL,
            serde_json::json!({"name": "echo", "arguments": {}}),
            RequestId::Number(2),
            SseLimits::new(4_096, 65_536, 8).expect("bounded SSE limits"),
        ))
        .expect("open final core listener");
        let error = runtime_block_on(listener.next_event(&cx))
            .expect_err("one terminal ID change must fail closed");
        assert!(matches!(
            error,
            ModernHttpFinalCoreListenError::ResponseIdMismatch {
                expected: RequestId::Number(2),
                actual: Some(RequestId::Number(3)),
            }
        ));
        assert!(
            listener.stream.response.is_none(),
            "ID refusal must release the body"
        );
        assert!(
            listener.stream.parser.is_none(),
            "ID refusal must release the parser"
        );
        server.join().expect("final core ID peer joins");
    }

    #[test]
    fn final_core_listener_rejects_json_response_after_standard_accept() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind final core JSON peer");
        let address = listener
            .local_addr()
            .expect("read final core JSON peer address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern discovery probe");
            let _ = read_request(&mut probe);
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            let (mut stream, _) = listener.accept().expect("accept final core JSON request");
            let request = read_request(&mut stream);
            assert!(
                request
                    .head
                    .contains("Accept: application/json, text/event-stream\r\n"),
                "the final-core listener must retain the standard modern response admission"
            );
            write_response(
                &mut stream,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"done"}],"isError":false}}"#,
            );
        });

        let cx = Cx::for_request();
        let connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "final-core-JSON-listener-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("modern discovery selects the final core listener");
        let error = runtime_block_on(connection.open_final_tool_call_listener(
            &cx,
            RequestId::Number(2),
            "echo",
            serde_json::json!({}),
            SseLimits::new(4_096, 65_536, 8).expect("bounded SSE limits"),
        ))
        .expect_err("the SSE-only final-core listener must reject a JSON response body");
        assert!(matches!(
            error,
            ClientHttpConnectionError::FinalCoreListen(ModernHttpFinalCoreListenError::Executor(
                ModernHttpExecutorError::ExpectedSseResponse {
                    actual: ModernHttpResponseKind::Json,
                }
            ))
        ));
        server.join().expect("final core JSON peer joins");
    }

    #[test]
    fn final_core_listener_rejects_server_cancellation_and_closes_body() {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind final core cancellation listener");
        let address = listener
            .local_addr()
            .expect("read final core cancellation address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern discovery probe");
            let _ = read_request(&mut probe);
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            let (mut stream, _) = listener.accept().expect("accept final core tool stream");
            let request = read_request(&mut stream);
            assert!(
                request
                    .head
                    .contains("Accept: application/json, text/event-stream\r\n"),
                "the final-core listener must retain the standard modern response admission"
            );
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&request.body)
                    .expect("final core tool stream request is JSON-RPC")["method"],
                "tools/call"
            );
            begin_chunked_sse(&mut stream);
            write_chunked_sse_event(
                &mut stream,
                "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":2}}\n\n",
            );
            finish_chunked_sse(&mut stream);
        });

        let cx = Cx::for_request();
        let connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "final-core-cancellation-listener-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("modern discovery selects the final core listener");
        let mut listener = runtime_block_on(connection.open_final_tool_call_listener(
            &cx,
            RequestId::Number(2),
            "echo",
            serde_json::json!({}),
            SseLimits::new(4_096, 65_536, 8).expect("bounded SSE limits"),
        ))
        .expect("open final core listener");
        let error = runtime_block_on(listener.next_event(&cx))
            .expect_err("server cancellation must be refused on final HTTP SSE");
        assert!(matches!(
            error,
            ModernHttpFinalCoreListenError::ServerCancellationOnHttp
        ));
        assert!(
            listener.stream.response.is_none(),
            "server cancellation refusal must release the body"
        );
        assert!(
            listener.stream.parser.is_none(),
            "server cancellation refusal must release the parser"
        );
        server.join().expect("final core cancellation peer joins");
    }

    #[test]
    #[cfg(feature = "tasks")]
    fn generic_final_core_listener_rejects_tasks_tool_result_and_closes_body() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind generic Tasks peer");
        let address = listener
            .local_addr()
            .expect("read generic Tasks peer address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept Tasks discovery probe");
            let _ = read_request(&mut probe);
            write_response(
                &mut probe,
                200,
                "application/json",
                &modern_tasks_discovery_body(),
            );

            let (mut stream, _) = listener.accept().expect("accept generic tool stream");
            let request = read_request(&mut stream);
            let request = serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("generic tool stream request is JSON-RPC");
            assert!(request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
                ["extensions"]
                .get(fastmcp_protocol::TASKS_EXTENSION)
                .is_none());
            begin_chunked_sse(&mut stream);
            write_chunked_sse_event(
                &mut stream,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"resultType\":\"task\",\"taskId\":\"task-73\",\"status\":\"working\",\"createdAt\":\"2026-07-28T12:00:00.000Z\",\"lastUpdatedAt\":\"2026-07-28T12:00:00.000Z\",\"ttlMs\":null}}\n\n",
            );
            finish_chunked_sse(&mut stream);
        });

        let cx = Cx::for_request();
        let connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "generic-final-core-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("Tasks-capable discovery selects modern HTTP");
        let mut listener = runtime_block_on(connection.open_final_tool_call_listener(
            &cx,
            RequestId::Number(2),
            "durable-tool",
            serde_json::json!({}),
            SseLimits::new(4_096, 65_536, 8).expect("bounded SSE limits"),
        ))
        .expect("generic listener opens without a Tasks request");
        assert!(matches!(
            runtime_block_on(listener.next_event(&cx)),
            Err(ModernHttpFinalCoreListenError::TasksResultRequiresNegotiatedListener)
        ));
        assert!(
            listener.stream.response.is_none(),
            "Tasks refusal must release the body"
        );
        assert!(
            listener.stream.parser.is_none(),
            "Tasks refusal must release the parser"
        );
        server.join().expect("generic Tasks peer joins");
    }

    #[test]
    #[cfg(feature = "tasks")]
    fn negotiated_tasks_tool_listener_admits_tasks_tool_result() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind negotiated Tasks peer");
        let address = listener
            .local_addr()
            .expect("read negotiated Tasks peer address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept Tasks discovery probe");
            let _ = read_request(&mut probe);
            write_response(
                &mut probe,
                200,
                "application/json",
                &modern_tasks_discovery_body(),
            );

            let (mut stream, _) = listener.accept().expect("accept Tasks tool stream");
            let request = read_request(&mut stream);
            let request = serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("Tasks tool stream request is JSON-RPC");
            assert_eq!(
                request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
                    [fastmcp_protocol::TASKS_EXTENSION],
                serde_json::json!({})
            );
            begin_chunked_sse(&mut stream);
            write_chunked_sse_event(
                &mut stream,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"resultType\":\"task\",\"taskId\":\"task-73\",\"status\":\"working\",\"createdAt\":\"2026-07-28T12:00:00.000Z\",\"lastUpdatedAt\":\"2026-07-28T12:00:00.000Z\",\"ttlMs\":null}}\n\n",
            );
            finish_chunked_sse(&mut stream);
        });

        let cx = Cx::for_request();
        let connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "negotiated-final-core-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("Tasks-capable discovery selects modern HTTP");
        let mut listener = runtime_block_on(connection.open_final_tasks_tool_call_listener(
            &cx,
            RequestId::Number(2),
            "durable-tool",
            serde_json::json!({}),
            SseLimits::new(4_096, 65_536, 8).expect("bounded SSE limits"),
        ))
        .expect("Tasks-negotiated listener opens");
        assert!(matches!(
            runtime_block_on(listener.next_event(&cx)),
            Ok(Some(ModernHttpFinalCoreEvent::Terminal(
                fastmcp_protocol::FinalCoreResult::ToolsCallTask { .. }
            )))
        ));
        assert!(
            listener.stream.response.is_none(),
            "terminal must release the body"
        );
        assert!(
            listener.stream.parser.is_none(),
            "terminal must release the parser"
        );
        server.join().expect("negotiated Tasks peer joins");
    }

    #[test]
    fn final_core_collector_rejects_one_extra_progress_before_terminal() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind final core overflow peer");
        let address = listener
            .local_addr()
            .expect("read final core overflow peer address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern discovery probe");
            let _ = read_request(&mut probe);
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            let (mut stream, _) = listener.accept().expect("accept final core tool stream");
            let _ = read_request(&mut stream);
            begin_chunked_sse(&mut stream);
            for _ in 0..=MAX_QUEUED_FINAL_HTTP_PROGRESS_NOTIFICATIONS {
                write_chunked_sse_event(
                    &mut stream,
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":2,\"progress\":1e400,\"total\":1e401,\"message\":\"exact\"}}\n\n",
                );
            }
            write_chunked_sse_event(
                &mut stream,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"resultType\":\"complete\",\"content\":[{\"type\":\"text\",\"text\":\"done\"}],\"isError\":false}}\n\n",
            );
            finish_chunked_sse(&mut stream);
        });

        let cx = Cx::for_request();
        let client = runtime_block_on(ModernHttpClient::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "final-core-overflow-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("modern discovery selects the final core listener")
        .into_modern()
        .expect("modern-only connection cannot select legacy");
        let error = runtime_block_on(async {
            client
                .open_final_tool_call_listener(
                    &cx,
                    RequestId::Number(2),
                    "echo",
                    serde_json::json!({}),
                    SseLimits::new(4_096, 65_536, 128).expect("bounded SSE limits"),
                )
                .await?
                .collect(&cx)
                .await
        })
        .expect_err("one extra exact progress notification must fail closed");
        assert!(matches!(
            error,
            ModernHttpFinalCoreListenError::ProgressQueueFull
        ));
        server.join().expect("final core overflow peer joins");
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
    fn modern_connect_applies_only_the_absent_result_type_compatibility_rule() {
        let exact = br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#;
        let admitted = decode_modern_discovery_response(exact)
            .expect("the exact final discovery result must be retained");
        assert_eq!(admitted.supported_versions(), ["2026-07-28"]);
        assert!(admitted.peer_diagnostic().is_none());

        let absent = br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#;
        let compatibility = decode_modern_discovery_response(absent)
            .expect("an otherwise-valid missing discriminator establishes the modern era");
        assert_eq!(compatibility.result_type(), "complete");
        assert_eq!(
            compatibility.peer_diagnostic(),
            Some(fastmcp_protocol::ResultPeerDiagnostic::ModernMissingResultType)
        );

        for planted in [
            br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"task","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"com.example/deferred-discovery","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":null,"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":{"complete":true},"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private","requestState":"resume-1"}}"#.as_slice(),
        ] {
            assert!(matches!(
                decode_modern_discovery_response(planted),
                Err(ModernHttpClientError::InvalidDiscoveryResponse)
            ));
        }
    }

    #[test]
    fn public_http_auto_commits_missing_result_type_discovery_before_final_traffic() {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind missing-resultType modern listener");
        let address = listener
            .local_addr()
            .expect("read missing-resultType modern address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut discovery, _) = listener.accept().expect("accept modern discovery");
            let discovery_request = read_request(&mut discovery);
            assert!(discovery_request.head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert!(
                discovery_request
                    .head
                    .contains("MCP-Protocol-Version: 2026-07-28\r\n")
            );
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&discovery_request.body)
                    .expect("discovery is JSON-RPC")["method"],
                SERVER_DISCOVER
            );
            write_response(
                &mut discovery,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#,
            );

            let (mut request, _) = listener.accept().expect("accept final request");
            let final_request = read_request(&mut request);
            assert!(final_request.head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert!(
                final_request
                    .head
                    .contains("MCP-Protocol-Version: 2026-07-28\r\n"),
                "the traffic after discovery remains on the committed final era"
            );
            let final_body = serde_json::from_slice::<serde_json::Value>(&final_request.body)
                .expect("final request is JSON-RPC");
            assert_eq!(final_body["id"], 2);
            assert_eq!(final_body["method"], "tools/list");
            write_response(
                &mut request,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
            );
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(
            ClientBuilder::new()
                .protocol_plan(plan(
                    &modern_target,
                    "http://127.0.0.1:9/legacy-sse",
                    "http://127.0.0.1:9/legacy-message",
                    ProtocolPolicy::Auto,
                ))
                .connect_http_with_cx(&cx),
        )
        .expect("an otherwise-valid missing resultType discovery selects final HTTP");
        assert_eq!(connection.selected_protocol_era(), ProtocolEra::Modern2026);
        assert_eq!(
            connection
                .server_discovery()
                .expect("the committed final era retains discovery")
                .peer_diagnostic(),
            Some(fastmcp_protocol::ResultPeerDiagnostic::ModernMissingResultType)
        );

        let response = runtime_block_on(connection.request_json(
            &cx,
            "tools/list",
            serde_json::json!({}),
            RequestId::Number(2),
            4_096,
        ))
        .expect("the committed final connection accepts subsequent final traffic");
        assert_eq!(response.id, Some(RequestId::Number(2)));
        server
            .join()
            .expect("missing-resultType modern server must join");
    }

    #[test]
    fn modern_http_answers_sampling_reverse_request_on_sse_and_completes_tools_list() {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind modern HTTP reverse-sampling listener");
        let address = listener
            .local_addr()
            .expect("read modern HTTP reverse-sampling address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut discovery, _) = listener.accept().expect("accept modern discovery");
            let discovery_request = read_request(&mut discovery);
            assert!(discovery_request.head.starts_with("POST /mcp HTTP/1.1\r\n"));
            write_response(
                &mut discovery,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"modern-http-reverse","version":"1.0"}}}}"#,
            );

            let (mut listed, _) = listener.accept().expect("accept modern tools/list");
            let list_request = read_request(&mut listed);
            assert!(list_request.head.starts_with("POST /mcp HTTP/1.1\r\n"));
            let list_body = serde_json::from_slice::<serde_json::Value>(&list_request.body)
                .expect("tools/list is JSON-RPC");
            assert_eq!(list_body["method"], "tools/list");
            begin_chunked_sse(&mut listed);
            write_chunked_sse_event(
                &mut listed,
                "data: {\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"sampling/createMessage\",\"params\":{\"_meta\":{},\"messages\":[{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":\"hello\"}}],\"maxTokens\":8}}\n\n",
            );

            let (mut reverse, _) = listener
                .accept()
                .expect("accept modern reverse-response POST");
            let reverse_request = read_request(&mut reverse);
            assert!(reverse_request.head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert!(
                !reverse_request.head.contains("Mcp-Method:"),
                "reverse-response POST must omit Mcp-Method: {}",
                reverse_request.head
            );
            let reverse_body = serde_json::from_slice::<serde_json::Value>(&reverse_request.body)
                .expect("reverse response is JSON-RPC");
            assert_eq!(reverse_body["id"], 99);
            assert_eq!(
                reverse_body["result"]["model"],
                serde_json::json!("modern-http-model")
            );
            write_response(&mut reverse, 202, "application/json", b"");

            write_chunked_sse_event(
                &mut listed,
                "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"resultType\":\"complete\",\"tools\":[],\"ttlMs\":0,\"cacheScope\":\"private\"}}\n\n",
            );
            finish_chunked_sse(&mut listed);
        });

        let handlers = ReverseRequestHandlers::new().with_modern_sampling_create_message(
            |_cx, _cancellation, params| {
                Box::pin(async move {
                    assert_eq!(params.max_tokens.to_string(), "8");
                    Ok(fastmcp_protocol::FinalCreateMessageResult {
                        content: fastmcp_protocol::FinalSamplingMessageContent::Block(
                            fastmcp_protocol::common_types::SamplingContentBlock::Text {
                                text: "sampled".to_owned(),
                                annotations: None,
                                meta: None,
                                additional: std::collections::BTreeMap::new(),
                            },
                        ),
                        model: "modern-http-model".to_owned(),
                        role: fastmcp_protocol::Role::Assistant,
                        stop_reason: None,
                        meta: None,
                    })
                })
            },
        );
        let cx = Cx::for_request();
        let mut connection = runtime_block_on(
            ClientBuilder::new()
                .protocol_plan(plan(
                    &modern_target,
                    "http://127.0.0.1:9/legacy-sse",
                    "http://127.0.0.1:9/legacy-message",
                    ProtocolPolicy::ModernOnly,
                ))
                .reverse_request_handlers(handlers)
                .connect_http_with_cx(&cx),
        )
        .expect("modern HTTP connects with reverse sampling handlers");
        let response = runtime_block_on(connection.request_json(
            &cx,
            "tools/list",
            serde_json::json!({}),
            RequestId::Number(2),
            4_096,
        ))
        .expect("tools/list completes after modern HTTP sampling is answered");
        assert_eq!(response.id, Some(RequestId::Number(2)));
        server
            .join()
            .expect("modern HTTP reverse-sampling server must join");
    }

    #[test]
    fn modern_discovery_response_correlates_numeric_aliases_and_rejects_foreign_ids() {
        let numeric_alias = br#"{"jsonrpc":"2.0","id":1e0,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#;
        assert!(decode_modern_discovery_response(numeric_alias).is_ok());

        // This body differs only in its response ID, which must not be admitted
        // as the `server/discover` probe response for ID 1.
        let foreign_id = br#"{"jsonrpc":"2.0","id":2e0,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#;
        assert!(matches!(
            decode_modern_discovery_response(foreign_id),
            Err(ModernHttpClientError::InvalidDiscoveryResponse)
        ));
    }

    #[test]
    fn modern_discovery_retains_an_arbitrary_width_jsonrpc_error_diagnostic() {
        let error = decode_modern_discovery_response(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-999999999999999999999999999999999999999999999,"message":"unavailable","data":{"retry":false}}}"#,
        )
        .expect_err("a discovery JSON-RPC error must remain an error");

        let ModernHttpClientError::DiscoveryRejected {
            code,
            message,
            data,
        } = error
        else {
            panic!("discovery error remains typed");
        };
        assert_eq!(
            code.as_str(),
            "-999999999999999999999999999999999999999999999"
        );
        assert_eq!(message, "unavailable");
        assert_eq!(data, Some(serde_json::json!({"retry": false})));
    }

    #[test]
    fn modern_discovery_retains_a_normal_jsonrpc_error_diagnostic_unchanged() {
        let error = decode_modern_discovery_response(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params","data":["name"]}}"#,
        )
        .expect_err("a normal discovery JSON-RPC error must remain an error");

        assert!(matches!(
            error,
            ModernHttpClientError::DiscoveryRejected {
                code,
                message,
                data: Some(serde_json::Value::Array(data)),
            } if code.as_str() == "-32602" && message == "invalid params" && data == vec![serde_json::json!("name")]
        ));
    }

    #[test]
    fn public_http_connection_rejects_modern_progress_notification_without_peer_contact() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local modern listener");
        let address = listener.local_addr().expect("read local modern address");
        let modern_target = format!("http://{address}/mcp");
        let (verify_sender, verify_receiver) = mpsc::channel();
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
            verify_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("client reports the local progress refusal");
            listener
                .set_nonblocking(true)
                .expect("configure listener for no-POST assertion");
            match listener.accept() {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Ok(_) => panic!("modern progress must not open a notification POST"),
                Err(error) => panic!("unexpected listener error: {error}"),
            }
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(
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
        .expect("recognized modern discovery selects the public HTTP connection");
        assert_eq!(connection.selected_protocol_era(), ProtocolEra::Modern2026);

        let error = runtime_block_on(connection.notify(
            &cx,
            "notifications/progress",
            Some(serde_json::json!({"progressToken": 2, "progress": 0.5})),
        ))
        .expect_err("final HTTP refuses a client progress POST before peer contact");
        assert!(matches!(
            error,
            ClientHttpConnectionError::ModernClientNotificationPostUnsupported { ref method }
                if method == "notifications/progress"
        ));
        verify_sender
            .send(())
            .expect("release the peer no-POST assertion");
        server.join().expect("local modern server must join");
    }

    #[test]
    fn modern_http_client_rejects_server_notification_before_transport_contact() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind notification listener");
        let address = listener
            .local_addr()
            .expect("read notification listener address");
        let modern_target = format!("http://{address}/mcp");
        let (verify_sender, verify_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("modern probe must be JSON-RPC")["method"],
                "server/discover"
            );
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            let (mut request, _) = listener.accept().expect("accept positive modern request");
            let request_wire = read_request(&mut request);
            let request_body = serde_json::from_slice::<serde_json::Value>(&request_wire.body)
                .expect("positive modern request must be JSON-RPC");
            assert_eq!(request_body["id"], 2);
            assert_eq!(request_body["method"], "tools/list");
            write_response(
                &mut request,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#,
            );

            verify_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("client reports the direct local progress refusal");
            listener
                .set_nonblocking(true)
                .expect("configure listener for no-POST assertion");
            match listener.accept() {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Ok(_) => panic!("direct modern progress request must not open a notification POST"),
                Err(error) => panic!("unexpected listener error: {error}"),
            }
        });

        let cx = Cx::for_request();
        let client = runtime_block_on(ModernHttpClient::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "public-http-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("modern discovery selects a direct modern client")
        .into_modern()
        .expect("modern-only discovery cannot yield legacy");
        let positive = runtime_block_on(client.request(
            &cx,
            "tools/list",
            serde_json::json!({}),
            Some(RequestId::Number(2)),
        ))
        .expect("an active final client request opens exactly one modern POST");
        assert_eq!(positive.metadata().kind(), ModernHttpResponseKind::Json);
        drop(positive);
        let error = runtime_block_on(client.request(
            &cx,
            "notifications/progress",
            serde_json::json!({}),
            Some(RequestId::Number(2)),
        ))
        .expect_err("server-only final notifications fail before a modern POST can open");
        assert!(matches!(
            error,
            ModernHttpClientError::ServerInitiatedFinalMethod { ref method }
                if method == "notifications/progress"
        ));
        verify_sender
            .send(())
            .expect("release the peer no-POST assertion");
        server.join().expect("notification test server must join");
    }

    #[test]
    fn modern_http_cancellation_rejects_notification_post_without_contacting_the_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind modern listener");
        let address = listener.local_addr().expect("read modern listener address");
        let modern_target = format!("http://{address}/mcp");
        let (verify_sender, verify_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("modern probe must be JSON-RPC")["method"],
                "server/discover"
            );
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            verify_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("client reports the local cancellation refusal");
            listener
                .set_nonblocking(true)
                .expect("configure local listener for a no-POST assertion");
            match listener.accept() {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Ok(_) => panic!("modern cancellation must not open a notification POST"),
                Err(error) => panic!("unexpected listener error: {error}"),
            }
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
        .expect_err("modern cancellation is response-body closure, not a notification POST");
        assert!(matches!(
            error,
            ClientHttpConnectionError::ModernCancellationRequiresResponseClose
        ));
        verify_sender
            .send(())
            .expect("release the peer no-POST assertion");
        server.join().expect("modern peer must join");
    }

    #[test]
    fn modern_http_sse_cancellation_drops_the_owned_response_body_immediately() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind modern SSE listener");
        let address = listener.local_addr().expect("read modern SSE address");
        let modern_target = format!("http://{address}/mcp");
        let (ready_sender, ready_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("modern probe must be JSON-RPC")["method"],
                "server/discover"
            );
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            let (mut stream, _) = listener.accept().expect("accept modern SSE request");
            let request = read_request(&mut stream);
            assert!(
                request
                    .head
                    .contains("Accept: application/json, text/event-stream\r\n"),
                "the final-core listener must retain the standard modern response admission"
            );
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&request.body)
                    .expect("modern request must be JSON-RPC")["method"],
                "tools/call"
            );
            begin_chunked_sse(&mut stream);
            ready_sender
                .send(())
                .expect("tell client the response body is live");
            release_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("wait until the caller cancels the owned stream");
        });

        let cx = Cx::for_request();
        let client = runtime_block_on(ModernHttpClient::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "public-http-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("modern discovery selects a direct modern client")
        .into_modern()
        .expect("modern-only discovery cannot yield legacy");
        let mut listener = runtime_block_on(client.open_final_tool_call_listener(
            &cx,
            RequestId::Number(2),
            "echo",
            serde_json::json!({}),
            SseLimits::new(1_024, 8_192, 4).expect("nonzero SSE bounds"),
        ))
        .expect("open the request-owned final-core SSE response");
        ready_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("server exposed the live response body");

        let wake_counter = Arc::new(CountingWake::default());
        let waker = Waker::from(Arc::clone(&wake_counter));
        let mut task_context = Context::from_waker(&waker);
        {
            let mut next_event = std::pin::pin!(listener.next_event(&cx));
            assert!(matches!(
                next_event.as_mut().poll(&mut task_context),
                Poll::Pending
            ));

            cx.cancel_with(
                CancelKind::User,
                Some("cancel the owned modern SSE response"),
            );
            assert!(
                wake_counter.0.load(Ordering::SeqCst) > 0,
                "Cx cancellation must wake the already-pending quiet response body"
            );
            assert!(matches!(
                next_event.as_mut().poll(&mut task_context),
                Poll::Ready(Err(ModernHttpFinalCoreListenError::CallerCancelled {
                    request_id: RequestId::Number(2),
                }))
            ));
        }
        assert!(listener.stream.response.is_none());
        assert!(listener.stream.parser.is_none());
        assert!(listener.stream.pending_events.is_empty());

        release_sender
            .send(())
            .expect("release the response-owning peer");
        server.join().expect("modern SSE server must join");
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn legacy_quiet_sse_cancellation_drops_the_owned_response_body_immediately() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind legacy SSE listener");
        let address = listener.local_addr().expect("read legacy SSE address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let (ready_sender, ready_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept exact legacy SSE GET");
            let request = read_request(&mut stream);
            assert!(request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            assert!(
                !request.head.contains("MCP-Protocol-Version:"),
                "exact legacy SSE GET must not carry final headers"
            );
            begin_chunked_sse(&mut stream);
            write_chunked_sse_event(
                &mut stream,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );
            ready_sender
                .send(())
                .expect("tell client the exact legacy body is quiet and live");
            release_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("wait until the caller cancels the quiet legacy stream");
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
        .expect("exact legacy connection opens its configured SSE lane");
        ready_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("server exposed the live exact legacy response body");

        let ClientHttpConnection::LegacySse(LegacySseConnection { client, .. }) = &mut connection
        else {
            panic!("LegacyOnly must retain the exact legacy SSE lane");
        };
        let wake_counter = Arc::new(CountingWake::default());
        let waker = Waker::from(Arc::clone(&wake_counter));
        let mut task_context = Context::from_waker(&waker);
        {
            let mut next_message = std::pin::pin!(client.next_message(&cx));
            assert!(matches!(
                next_message.as_mut().poll(&mut task_context),
                Poll::Pending
            ));

            cx.cancel_with(
                CancelKind::User,
                Some("cancel the owned exact legacy SSE response"),
            );
            assert!(
                wake_counter.0.load(Ordering::SeqCst) > 0,
                "Cx cancellation must wake the already-pending quiet legacy response body"
            );
            assert!(matches!(
                next_message.as_mut().poll(&mut task_context),
                Poll::Ready(Err(LegacySseHttpClientError::Cancelled))
            ));
        }
        let stream = client
            .stream
            .as_ref()
            .expect("raw legacy client retains its reader");
        assert!(stream.response.is_none());
        assert!(stream.pending_events.is_empty());

        release_sender
            .send(())
            .expect("release the response-owning exact legacy peer");
        server.join().expect("legacy SSE server must join");
    }

    #[test]
    fn ready_body_frame_is_rejected_when_cancellation_wins_after_poll() {
        let cx = Cx::for_request();
        let ready_frame = Some(Ok::<_, ()>(Frame::data(Bytes::copy_from_slice(b"ready"))));
        cx.cancel_with(
            CancelKind::User,
            Some("cancel immediately after a ready native body frame"),
        );

        assert!(matches!(
            reject_body_frame_after_cancellation(&cx, ready_frame),
            Err(ModernHttpExecutorError::Cancelled)
        ));
    }

    #[test]
    fn ready_body_eof_is_rejected_when_cancellation_wins_after_poll() {
        let cx = Cx::for_request();
        let ready_eof = None::<Result<Frame<Bytes>, ()>>;
        cx.cancel_with(
            CancelKind::User,
            Some("cancel immediately after a ready native body EOF"),
        );

        assert!(matches!(
            reject_body_frame_after_cancellation(&cx, ready_eof),
            Err(ModernHttpExecutorError::Cancelled)
        ));
    }

    #[test]
    fn public_http_connection_request_json_with_result_source_rejects_a_stale_response_id() {
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
            // This carries the discovery request's stale ID instead of the
            // just-sent tools/list ID; the result source must not escape that
            // failed correlation check.
            write_response(
                &mut stream,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
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
        let error = runtime_block_on(connection.request_json_with_result_source(
            &cx,
            "tools/list",
            serde_json::json!({}),
            RequestId::Number(2),
            4_096,
        ))
        .expect_err("a stale response ID cannot return a result source for this request");
        assert!(matches!(
            error,
            ClientHttpConnectionError::ResponseIdMismatch {
                expected: RequestId::Number(2),
                actual: Some(RequestId::Number(1)),
            }
        ));
        server.join().expect("modern mismatch server must join");
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn public_http_auto_does_not_fall_back_after_a_recognized_discovery_refusal() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind recognized-refusal listener");
        let address = listener
            .local_addr()
            .expect("read recognized-refusal address");
        let modern_target = format!("http://{address}/mcp");
        let legacy_sse_target = format!("http://{address}/legacy-sse");
        let legacy_message_target = format!("http://{address}/legacy-message");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept disposable modern probe");
            let probe_request = read_request(&mut probe);
            assert!(probe_request.head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("probe is JSON-RPC")["method"],
                SERVER_DISCOVER
            );
            // This differs from the positive legacy-fallback probe only in
            // the returned body. A correlated JSON-RPC refusal is protocol
            // evidence for the final lane, never authorization to contact
            // the legacy endpoints.
            write_response(
                &mut probe,
                404,
                "text/plain",
                br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"server/discover unavailable"}}"#,
            );

            listener
                .set_nonblocking(true)
                .expect("configure listener for no-fallback assertion");
            let deadline = Instant::now() + Duration::from_millis(100);
            loop {
                match listener.accept() {
                    Ok(_) => panic!(
                        "a recognized modern discovery refusal must not contact legacy SSE or POST"
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("observe unintended legacy contact: {error}"),
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
            panic!("a recognized discovery refusal cannot select legacy");
        };
        assert!(matches!(
            error,
            ClientHttpConnectionError::Modern(ModernHttpClientError::DiscoveryRejected {
                code,
                message,
                data: None,
            }) if code.as_str() == "-32601" && message == "server/discover unavailable"
        ));
        server.join().expect("recognized-refusal server must join");
    }

    #[cfg(feature = "legacy-2024-11-05")]
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
            for event in subscriptions_listen_sse_events("2e0") {
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

        assert!(
            collector
                .subscription_id
                .correlates_with(&RequestId::Number(2)),
            "mathematically equal integer spellings retain one subscription owner"
        );
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
    fn public_http_modern_subscriptions_listen_requires_acknowledgement_as_first_frame() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind final subscriptions/listen first-frame listener");
        let address = listener
            .local_addr()
            .expect("read final subscriptions/listen first-frame address");
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
            // This differs from a valid subscription stream only in its first
            // dispatched JSON-RPC notification: the required acknowledgement
            // has been replaced with an otherwise valid progress frame.
            write_chunked_sse_event(
                &mut stream,
                "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":2,\"progress\":0.5}}\n\n",
            );
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
            SubscriptionFilter::default(),
            SseLimits::new(1_024, 8_192, 16).expect("explicit SSE bounds are nonzero"),
        ))
        .expect_err("a subscription stream must begin with its acknowledgement");
        assert!(matches!(
            error,
            ClientHttpConnectionError::SubscriptionsListen(
                ModernHttpSubscriptionListenError::EventBeforeAcknowledgement
            )
        ));
        server
            .join()
            .expect("first-frame subscription server must join");
    }

    #[test]
    fn public_http_modern_subscriptions_listen_rejects_server_cancellation_frames() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind final subscriptions/listen cancellation listener");
        let address = listener
            .local_addr()
            .expect("read final subscriptions/listen cancellation address");
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
            write_chunked_sse_event(
                &mut stream,
                "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":2}}\n\n",
            );
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
        let mut subscription = runtime_block_on(connection.open_subscriptions_listener(
            &cx,
            RequestId::Number(2),
            SubscriptionFilter::default(),
            SseLimits::new(1_024, 8_192, 16).expect("explicit SSE bounds are nonzero"),
        ))
        .expect("open the request-owned subscription response stream");
        let error = runtime_block_on(subscription.next_event(&cx))
            .expect_err("server cancellation notifications are invalid on final HTTP SSE");
        assert!(matches!(
            error,
            ModernHttpSubscriptionListenError::ServerCancellationOnHttp
        ));
        assert!(
            subscription.stream.response.is_none(),
            "the refused subscription frame must release its request-owned HTTP body"
        );
        assert!(
            subscription.stream.parser.is_none(),
            "the refused subscription frame must release its bounded SSE parser"
        );
        server
            .join()
            .expect("final subscriptions/listen cancellation server must join");
    }

    #[test]
    fn public_http_modern_subscriptions_listen_rejects_wrong_terminal_response_id() {
        let error = run_public_http_subscriptions_listen_terminal("3", "2")
            .expect_err("a foreign terminal response ID must not yield a terminal");
        assert!(matches!(
            error,
            ClientHttpConnectionError::SubscriptionsListen(
                ModernHttpSubscriptionListenError::ResponseIdMismatch {
                    expected: RequestId::Number(2),
                    actual: Some(RequestId::Number(3)),
                }
            )
        ));
    }

    #[test]
    fn public_http_modern_subscriptions_listen_rejects_wrong_terminal_subscription_id() {
        let error = run_public_http_subscriptions_listen_terminal("2", "3")
            .expect_err("a foreign terminal subscription ID must not yield a terminal");
        assert!(matches!(
            error,
            ClientHttpConnectionError::SubscriptionsListen(
                ModernHttpSubscriptionListenError::TerminalIdMismatch {
                    expected: RequestId::Number(2),
                    actual: RequestId::Number(3),
                }
            )
        ));
    }

    #[test]
    #[cfg(feature = "tasks")]
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
    #[cfg(feature = "tasks")]
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
    #[cfg(feature = "tasks")]
    fn public_http_tasks_tool_outcome_retains_exact_created_task() {
        let outcome = run_public_http_tasks_tool_outcome("task")
            .expect("HTTP tools/call must retain the negotiated Tasks branch");
        let FinalToolCallOutcome::Task(result) = outcome else {
            panic!("Tasks-backed HTTP tools/call must not project into complete content");
        };
        assert_eq!(result.task.base().task_id.as_str(), "task-73");
    }

    #[test]
    #[cfg(feature = "tasks")]
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
    #[cfg(feature = "tasks")]
    fn public_http_tasks_lifecycle_emits_typed_exact_extension_wires() {
        let (get, update, cancel) = run_public_http_tasks_lifecycle()
            .expect("typed HTTP Tasks lifecycle must retain all three final responses");
        assert_eq!(get.task.base().task_id.as_str(), "task-73");
        assert!(matches!(
            get.task,
            fastmcp_protocol::tasks_extension::Task::InputRequired { .. }
        ));
        assert!(update.meta.is_none());
        assert!(update.additional.is_empty());
        assert!(cancel.meta.is_none());
        assert!(cancel.additional.is_empty());
    }

    #[test]
    #[cfg(feature = "tasks")]
    fn public_http_tasks_get_rejects_absent_capability_without_post() {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind local absent-Tasks HTTP listener");
        let address = listener
            .local_addr()
            .expect("read local absent-Tasks HTTP address");
        let modern_target = format!("http://{address}/mcp");
        let (stop_tx, stop_rx) = mpsc::sync_channel(1);
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept absent-Tasks probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("absent-Tasks probe must be JSON-RPC")["method"],
                "server/discover"
            );
            write_response(&mut probe, 200, "application/json", modern_discovery_body());
            listener
                .set_nonblocking(true)
                .expect("make absent-Tasks listener nonblocking");
            assert!(
                accept_legacy_test_peer(
                    &listener,
                    &stop_rx,
                    Instant::now() + LEGACY_TEST_PEER_BOUND,
                )
                .expect("observe absent-Tasks request path")
                .is_none(),
                "unadvertised Tasks method must not open a native POST"
            );
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
        .expect("modern discovery without Tasks still selects final HTTP");
        let error = runtime_block_on(connection.get_task_final(
            &cx,
            RequestId::Number(2),
            fastmcp_protocol::FinalTaskId::parse("task-73").expect("bounded task ID"),
            4_096,
        ))
        .expect_err("unadvertised Tasks method must be rejected locally");
        assert!(matches!(
            error,
            ClientHttpConnectionError::Modern(ModernHttpClientError::TasksMethodNegotiation {
                method: fastmcp_protocol::TASK_GET
            })
        ));
        signal_legacy_test_peer_stop(&stop_tx);
        server
            .join()
            .expect("absent-Tasks HTTP listener must observe no POST");
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    #[cfg(feature = "tasks")]
    fn public_http_tasks_lifecycle_rejects_legacy_before_message_post() {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind local legacy Tasks-negative listener");
        let address = listener
            .local_addr()
            .expect("read local legacy Tasks-negative address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let (stop_tx, stop_rx) = mpsc::sync_channel(1);
        let server = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept exact legacy SSE GET");
            let sse_request = read_request(&mut sse);
            assert!(sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );
            listener
                .set_nonblocking(true)
                .expect("make legacy Tasks-negative listener nonblocking");
            assert!(
                accept_legacy_test_peer(
                    &listener,
                    &stop_rx,
                    Instant::now() + LEGACY_TEST_PEER_BOUND,
                )
                .expect("observe legacy Tasks-negative request path")
                .is_none(),
                "final Tasks lifecycle must not open the legacy message endpoint"
            );
            finish_chunked_sse(&mut sse);
        });

        let cx = Cx::for_request();
        let connection = runtime_block_on(
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
        let error = runtime_block_on(connection.cancel_task_final(
            &cx,
            RequestId::Number(2),
            fastmcp_protocol::FinalTaskId::parse("task-73").expect("bounded task ID"),
            4_096,
        ))
        .expect_err("final Tasks lifecycle must be rejected before legacy POST");
        assert!(matches!(
            error,
            ClientHttpConnectionError::FinalTasksRequiresModern {
                method: fastmcp_protocol::TASK_CANCEL
            }
        ));
        signal_legacy_test_peer_stop(&stop_tx);
        server
            .join()
            .expect("legacy Tasks-negative listener must observe no POST");
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
            for event in subscriptions_listen_sse_events("3") {
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

    #[cfg(feature = "legacy-2024-11-05")]
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
                "event: endpoint\ndata: {advertised_message_target}\n\nevent: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":2e0,\"result\":{{}}}}\n\n"
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
        let mut connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                "http://127.0.0.1:9/mcp",
                &sse_target,
                &message_target,
                ProtocolPolicy::LegacyOnly,
            ),
            ClientInfo {
                name: "public-legacy-http-connection".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("legacy-only opens the exact configured SSE route");
        assert_eq!(connection.selected_protocol_era(), ProtocolEra::Legacy2024);
        assert_eq!(
            connection.protocol_version(),
            None,
            "a raw legacy connection has not yet validated an initialize wire version"
        );

        let response = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(2),
            4_096,
        ))
        .expect("legacy request posts then waits for its exact SSE response");
        assert!(
            response
                .id
                .as_ref()
                .is_some_and(|response_id| response_id.correlates_with(&RequestId::Number(2)))
        );
        runtime_block_on(connection.notify(
            &cx,
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": 2})),
        ))
        .expect("a legacy notification posts without an ID to the exact endpoint");
        server.join().expect("local legacy server must join");
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn legacy_connection_rejects_one_final_metadata_member_without_contact_or_mutation() {
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

            // The negative carries only a final-only metadata member. It must
            // not post or advance the connection: this is the one accepted
            // request, using the same ID after the rejection.
            let (mut message_post, _) = listener
                .accept()
                .expect("accept unchanged exact legacy message POST");
            let message_request = read_request(&mut message_post);
            assert!(
                message_request
                    .head
                    .starts_with("POST /legacy-message HTTP/1.1\r\n")
            );
            let message = serde_json::from_slice::<serde_json::Value>(&message_request.body)
                .expect("unchanged legacy message POST must contain JSON-RPC");
            assert_eq!(message["id"], 2);
            assert_eq!(message["method"], "ping");
            assert!(
                message["params"].get("_meta").is_none(),
                "rejected final metadata must never reach the legacy endpoint"
            );
            write_response(&mut message_post, 202, "application/json", b"");
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                "http://127.0.0.1:9/mcp",
                &sse_target,
                &message_target,
                ProtocolPolicy::LegacyOnly,
            ),
            ClientInfo {
                name: "public-legacy-http-connection".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("legacy-only opens the exact configured SSE route");
        assert_eq!(connection.selected_protocol_era(), ProtocolEra::Legacy2024);
        assert_eq!(connection.protocol_version(), None);

        let rejected = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({
                "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
            }),
            RequestId::Number(2),
            4_096,
        ));
        assert!(matches!(
            rejected,
            Err(ClientHttpConnectionError::LegacyFinalMetadata {
                member: "io.modelcontextprotocol/protocolVersion"
            })
        ));
        assert_eq!(connection.selected_protocol_era(), ProtocolEra::Legacy2024);
        assert_eq!(
            connection.protocol_version(),
            None,
            "rejected final metadata cannot record a legacy initialization version"
        );

        let response = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(2),
            4_096,
        ))
        .expect("changing only final metadata leaves the raw legacy connection usable");
        assert_eq!(response.id, Some(RequestId::Number(2)));
        server.join().expect("local legacy server must join");
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn public_legacy_sse_connection_retains_the_exact_pending_event_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind bounded legacy listener");
        let address = listener
            .local_addr()
            .expect("read bounded legacy listener address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let server = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept bounded legacy SSE GET");
            let request = read_request(&mut sse);
            assert!(request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            let body = legacy_sse_body_with_messages(
                &advertised_message_target,
                MAX_PENDING_LEGACY_SSE_EVENTS - 1,
            );
            write_response(&mut sse, 200, "text/event-stream", body.as_bytes());
        });

        let cx = Cx::for_request();
        let connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                "http://127.0.0.1:9/mcp",
                &sse_target,
                &message_target,
                ProtocolPolicy::LegacyOnly,
            ),
            ClientInfo {
                name: "bounded-legacy-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("the exact legacy pending-event limit must remain usable");
        let ClientHttpConnection::LegacySse(LegacySseConnection { client, .. }) = connection else {
            panic!("LegacyOnly must retain the exact legacy SSE lane");
        };
        let stream = client.stream.expect("legacy reader remains available");
        assert_eq!(
            stream.pending_events.len(),
            MAX_PENDING_LEGACY_SSE_EVENTS - 1,
            "the endpoint is delivered while exactly the bounded message backlog remains"
        );
        assert!(
            stream.pending_event_bytes <= MAX_PENDING_LEGACY_SSE_EVENT_BYTES,
            "the admitted message backlog remains byte-bounded"
        );
        server.join().expect("bounded legacy server must join");
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn public_legacy_sse_connection_rejects_one_extra_pending_event() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind overflowing legacy listener");
        let address = listener
            .local_addr()
            .expect("read overflowing legacy listener address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let server = thread::spawn(move || {
            let (mut sse, _) = listener
                .accept()
                .expect("accept overflowing legacy SSE GET");
            let request = read_request(&mut sse);
            assert!(request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            let body = legacy_sse_body_with_messages(
                &advertised_message_target,
                MAX_PENDING_LEGACY_SSE_EVENTS,
            );
            write_response(&mut sse, 200, "text/event-stream", body.as_bytes());
        });

        let cx = Cx::for_request();
        let error = match runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                "http://127.0.0.1:9/mcp",
                &sse_target,
                &message_target,
                ProtocolPolicy::LegacyOnly,
            ),
            ClientInfo {
                name: "overflowing-legacy-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        )) {
            Err(error) => error,
            Ok(_) => panic!("one extra legacy event must refuse the long-lived SSE body"),
        };
        assert!(matches!(
            error,
            ClientHttpConnectionError::Modern(ModernHttpClientError::LegacySse(
                LegacySseHttpClientError::PendingSseEventCountExceeded {
                    maximum_events: MAX_PENDING_LEGACY_SSE_EVENTS,
                }
            ))
        ));
        server.join().expect("overflowing legacy server must join");
    }

    #[cfg(feature = "legacy-2024-11-05")]
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

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn public_http_auto_modern_discovery_omits_exact_legacy_callback_capabilities() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Auto modern listener");
        let address = listener.local_addr().expect("read Auto modern address");
        let modern_target = format!("http://{address}/mcp");
        let callback_calls = Arc::new(AtomicUsize::new(0));
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept Auto modern discovery");
            let request =
                serde_json::from_slice::<serde_json::Value>(&read_request(&mut probe).body)
                    .expect("Auto modern discovery is JSON-RPC");
            assert_eq!(request["method"], SERVER_DISCOVER);
            let capabilities =
                &request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"];
            assert!(capabilities.get("sampling").is_none());
            assert!(capabilities.get("roots").is_none());
            write_response(
                &mut probe,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"modern","version":"1"}}}}"#,
            );
        });

        let sampling_calls = Arc::clone(&callback_calls);
        let cx = Cx::for_request();
        let client = runtime_block_on(
            ClientBuilder::new()
                .protocol_plan(plan(
                    &modern_target,
                    "http://127.0.0.1:9/legacy-sse",
                    "http://127.0.0.1:9/legacy-message",
                    ProtocolPolicy::Auto,
                ))
                .reverse_request_handlers(
                    ReverseRequestHandlers::new().with_sampling_create_message(
                        move |_cx, _cancellation, _params| {
                            sampling_calls.fetch_add(1, Ordering::SeqCst);
                            Box::pin(async {
                                Ok(crate::CreateMessageResult::text("unexpected", "unexpected"))
                            })
                        },
                    ),
                )
                .connect_http_client_with_cx(&cx),
        )
        .expect("Auto retains modern discovery without legacy callback metadata");
        assert_eq!(client.selected_protocol_era(), ProtocolEra::Modern2026);
        assert_eq!(callback_calls.load(Ordering::SeqCst), 0);
        server.join().expect("Auto modern server joins");
    }

    #[cfg(feature = "legacy-2024-11-05")]
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
            assert!(
                !sse_request.head.contains("MCP-Session-Id:"),
                "Auto fallback must not leak a modern discovery session onto legacy SSE"
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
            assert!(
                !initialize_request.head.contains("MCP-Session-Id:"),
                "Auto fallback must not leak a modern discovery session onto legacy POST"
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
        assert_eq!(
            client.connection().protocol_version(),
            Some(LEGACY_PROTOCOL_VERSION),
            "the public client retains the exact validated legacy initialize wire version"
        );
        assert_eq!(client.server_info().name, "legacy-server");
        assert!(client.legacy_server_capabilities().is_some());
        assert!(client.server_discovery().is_none());
        server.join().expect("Auto fallback server must join");
    }

    #[cfg(all(feature = "apps", feature = "legacy-2024-11-05"))]
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
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n",
            );

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
        assert_eq!(
            client.connection().protocol_version(),
            Some(LEGACY_PROTOCOL_VERSION),
            "the public client retains the exact validated legacy initialize wire version"
        );
        assert_eq!(client.server_info().name, "legacy-only-server");
        assert!(client.legacy_server_capabilities().is_some());
        assert!(client.server_discovery().is_none());
        assert!(!client.mcp_apps_active());
        std::thread::sleep(Duration::from_millis(20));
        let notification = client
            .take_legacy_notification()
            .expect("ready legacy client drains notifications before a client request");
        assert_eq!(notification.method, "notifications/progress");
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

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn public_http_client_rejects_a_wrong_legacy_initialize_wire_version() {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind local legacy-version listener");
        let address = listener
            .local_addr()
            .expect("read local legacy-version address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let (stop_tx, stop_rx) = mpsc::sync_channel::<()>(1);
        let server = thread::spawn(move || -> Result<bool, String> {
            listener
                .set_nonblocking(true)
                .map_err(|error| format!("make legacy-version listener nonblocking: {error}"))?;
            let deadline = Instant::now() + LEGACY_TEST_PEER_BOUND;
            let Some(mut sse) = accept_legacy_test_peer(&listener, &stop_rx, deadline)? else {
                return Ok(false);
            };
            let sse_request = read_request(&mut sse);
            assert!(sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            let Some(mut initialize_post) = accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
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
            Ok(true)
        });

        let cx = Cx::for_request();
        let connection_result = runtime_block_on(
            ClientBuilder::new()
                .protocol_plan(plan(
                    "http://127.0.0.1:9/mcp",
                    &sse_target,
                    &message_target,
                    ProtocolPolicy::LegacyOnly,
                ))
                .connect_http_client_with_cx(&cx),
        );
        signal_legacy_test_peer_stop(&stop_tx);
        let served = server
            .join()
            .expect("legacy-version server thread must join")
            .expect("legacy-version server must settle without an accept-loop failure");
        let error = connection_result
            .err()
            .expect("only the selected legacy initialize version is incompatible");
        assert!(
            served,
            "the wrong-version wire peer must receive its two requests"
        );
        assert!(matches!(
            error,
            crate::HttpClientError::LegacyInitializationUnsupportedProtocolVersion { actual }
                if actual == "2026-07-28"
        ));
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn wrong_version_peer_settles_after_a_planted_pre_connect_client_cancellation() {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind local pre-connect settlement listener");
        let address = listener
            .local_addr()
            .expect("read local pre-connect settlement address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let (stop_tx, stop_rx) = mpsc::sync_channel::<()>(1);
        let server = thread::spawn(move || -> Result<bool, String> {
            listener
                .set_nonblocking(true)
                .map_err(|error| format!("make pre-connect listener nonblocking: {error}"))?;
            let deadline = Instant::now() + LEGACY_TEST_PEER_BOUND;
            Ok(accept_legacy_test_peer(&listener, &stop_rx, deadline)?.is_some())
        });

        let cx = Cx::for_request();
        cx.cancel_with(
            CancelKind::User,
            Some("plant a client failure before the legacy SSE connect"),
        );
        let connection_result = runtime_block_on(
            ClientBuilder::new()
                .protocol_plan(plan(
                    "http://127.0.0.1:9/mcp",
                    &sse_target,
                    &message_target,
                    ProtocolPolicy::LegacyOnly,
                ))
                .connect_http_client_with_cx(&cx),
        );
        signal_legacy_test_peer_stop(&stop_tx);
        let accepted = server
            .join()
            .expect("pre-connect server thread must join")
            .expect("pre-connect server must settle without an accept-loop failure");

        assert!(
            connection_result.is_err(),
            "the planted cancelled context fails before the legacy peer can connect"
        );
        assert!(
            !accepted,
            "the stopped peer must not accept a connection after the pre-connect failure"
        );
    }

    #[cfg(feature = "legacy-2024-11-05")]
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

    #[cfg(feature = "legacy-2024-11-05")]
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

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn legacy_http_request_admits_exact_combined_control_bound_and_keeps_correlation() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind legacy control listener");
        let address = listener
            .local_addr()
            .expect("read legacy control listener address");
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

            let (mut first_post, _) = listener.accept().expect("accept bounded legacy POST");
            let first =
                serde_json::from_slice::<serde_json::Value>(&read_request(&mut first_post).body)
                    .expect("bounded legacy POST remains JSON-RPC");
            assert_eq!(first["id"], 41);
            write_response(&mut first_post, 202, "application/json", b"");

            for _ in 0..(MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES / 2) {
                write_chunked_sse_event(
                    &mut sse,
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n",
                );
            }
            for index in 0..(MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES / 2) {
                let reverse_id = 1_000_i64 + index as i64;
                write_chunked_sse_event(
                    &mut sse,
                    &format!(
                        "event: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":{reverse_id},\"method\":\"ping\",\"params\":{{}}}}\n\n"
                    ),
                );
                let (mut reverse_reply_post, _) = listener
                    .accept()
                    .expect("accept bounded reverse-request reply");
                let reverse_reply = serde_json::from_slice::<serde_json::Value>(
                    &read_request(&mut reverse_reply_post).body,
                )
                .expect("bounded reverse reply remains JSON-RPC");
                assert_eq!(reverse_reply["id"], reverse_id);
                assert_eq!(reverse_reply["result"], serde_json::json!({}));
                write_response(&mut reverse_reply_post, 202, "application/json", b"");
            }
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":41,\"result\":{\"bounded\":true}}\n\n",
            );

            let (mut follow_up_post, _) = listener
                .accept()
                .expect("accept post-boundary follow-up request");
            let follow_up = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut follow_up_post).body,
            )
            .expect("post-boundary follow-up remains JSON-RPC");
            assert_eq!(follow_up["id"], 42);
            write_response(&mut follow_up_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{\"followUp\":true}}\n\n",
            );
            finish_chunked_sse(&mut sse);
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                "http://127.0.0.1:9/mcp",
                &sse_target,
                &message_target,
                ProtocolPolicy::LegacyOnly,
            ),
            ClientInfo {
                name: "legacy-control-boundary-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("legacy control-boundary connection opens");
        let bounded = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(41),
            4_096,
        ))
        .expect("the exact combined legacy control-frame bound remains admitted");
        assert_eq!(bounded.id, Some(RequestId::Number(41)));

        let mut notifications = 0;
        while connection.take_legacy_notification().is_some() {
            notifications += 1;
        }
        assert_eq!(
            notifications,
            MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES / 2,
            "the admitted notification half remains available after reverse-call processing"
        );

        let follow_up = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(42),
            4_096,
        ))
        .expect("the exact boundary leaves the shared legacy stream correlated for a follow-up");
        assert_eq!(follow_up.id, Some(RequestId::Number(42)));
        server.join().expect("legacy control-boundary server joins");
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn legacy_http_request_rejects_n_plus_one_combined_control_frame_without_extra_reply() {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind legacy control-limit listener");
        let address = listener
            .local_addr()
            .expect("read legacy control-limit listener address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let (limit_observed_tx, limit_observed_rx) = mpsc::sync_channel(1);
        let server = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept exact legacy SSE GET");
            let sse_request = read_request(&mut sse);
            assert!(sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            let (mut first_post, _) = listener.accept().expect("accept limited legacy POST");
            let first =
                serde_json::from_slice::<serde_json::Value>(&read_request(&mut first_post).body)
                    .expect("limited legacy POST remains JSON-RPC");
            assert_eq!(first["id"], 91);
            write_response(&mut first_post, 202, "application/json", b"");

            for _ in 0..(MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES / 2) {
                write_chunked_sse_event(
                    &mut sse,
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n",
                );
            }
            for index in 0..(MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES / 2) {
                let reverse_id = 2_000_i64 + index as i64;
                write_chunked_sse_event(
                    &mut sse,
                    &format!(
                        "event: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":{reverse_id},\"method\":\"ping\",\"params\":{{}}}}\n\n"
                    ),
                );
                let (mut reverse_reply_post, _) = listener
                    .accept()
                    .expect("accept pre-limit reverse-request reply");
                let reverse_reply = serde_json::from_slice::<serde_json::Value>(
                    &read_request(&mut reverse_reply_post).body,
                )
                .expect("pre-limit reverse reply remains JSON-RPC");
                assert_eq!(reverse_reply["id"], reverse_id);
                assert_eq!(reverse_reply["result"], serde_json::json!({}));
                write_response(&mut reverse_reply_post, 202, "application/json", b"");
            }

            let rejected_reverse_id =
                2_000_i64 + (MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES / 2) as i64;
            write_chunked_sse_event(
                &mut sse,
                &format!(
                    "event: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":{rejected_reverse_id},\"method\":\"ping\",\"params\":{{}}}}\n\n"
                ),
            );
            limit_observed_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("client must reject the N+1 control frame before any reply is posted");

            listener
                .set_nonblocking(true)
                .expect("make control-limit listener nonblocking");
            let no_reply_deadline = Instant::now() + Duration::from_millis(100);
            while Instant::now() < no_reply_deadline {
                match listener.accept() {
                    Ok((mut unexpected, _)) => {
                        let unexpected = read_request(&mut unexpected);
                        panic!(
                            "N+1 reverse request must not receive a reply POST: {}",
                            String::from_utf8_lossy(&unexpected.body)
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(LEGACY_TEST_PEER_POLL_INTERVAL);
                    }
                    Err(error) => panic!("accept unexpected N+1 reply: {error}"),
                }
            }
            finish_chunked_sse(&mut sse);
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                "http://127.0.0.1:9/mcp",
                &sse_target,
                &message_target,
                ProtocolPolicy::LegacyOnly,
            ),
            ClientInfo {
                name: "legacy-control-limit-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("legacy control-limit connection opens");
        let error = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(91),
            4_096,
        ))
        .expect_err("one combined control frame past the exact bound must be refused");
        assert!(matches!(
            error,
            ClientHttpConnectionError::LegacyInterleavedControlFrameLimitExceeded {
                limit: MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES
            }
        ));

        let mut notifications = 0;
        while connection.take_legacy_notification().is_some() {
            notifications += 1;
        }
        assert_eq!(
            notifications,
            MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES / 2,
            "the rejected reverse request must not mutate the already admitted notification state"
        );
        limit_observed_tx
            .send(())
            .expect("allow the peer to verify no N+1 reverse reply was posted");
        server.join().expect("legacy control-limit server joins");
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn legacy_http_request_services_authorized_reverse_calls_and_rejects_elicitation() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind legacy reverse listener");
        let address = listener
            .local_addr()
            .expect("read legacy reverse listener address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let (stop_tx, stop_rx) = mpsc::sync_channel::<()>(1);
        let server = thread::spawn(move || -> Result<bool, String> {
            listener
                .set_nonblocking(true)
                .map_err(|error| format!("make legacy reverse listener nonblocking: {error}"))?;
            let deadline = Instant::now() + LEGACY_TEST_PEER_BOUND;
            let Some(mut sse) = accept_legacy_test_peer(&listener, &stop_rx, deadline)? else {
                return Ok(false);
            };
            let sse_request = read_request(&mut sse);
            assert!(sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            let Some(mut application_post) =
                accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let application = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut application_post).body,
            )
            .map_err(|error| format!("decode application request: {error}"))?;
            assert_eq!(application["id"], 71);
            assert_eq!(application["method"], "ping");
            write_response(&mut application_post, 202, "application/json", b"");

            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":81,\"params\":{\"messages\":[],\"maxTokens\":9}}\n\n",
            );
            let Some(mut sampling_post) = accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let sampling =
                serde_json::from_slice::<serde_json::Value>(&read_request(&mut sampling_post).body)
                    .map_err(|error| format!("decode sampling reply: {error}"))?;
            assert_eq!(sampling["id"], 81);
            assert_eq!(sampling["result"]["model"], "legacy-http-handler");
            write_response(&mut sampling_post, 202, "application/json", b"");

            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"roots/list\",\"id\":82,\"params\":{}}\n\n",
            );
            let Some(mut roots_post) = accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let roots =
                serde_json::from_slice::<serde_json::Value>(&read_request(&mut roots_post).body)
                    .map_err(|error| format!("decode roots reply: {error}"))?;
            assert_eq!(roots["id"], 82);
            assert_eq!(roots["result"]["roots"][0]["uri"], "file:///workspace");
            write_response(&mut roots_post, 202, "application/json", b"");

            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"elicitation/create\",\"id\":83,\"params\":{}}\n\n",
            );
            let Some(mut elicitation_post) =
                accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let elicitation = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut elicitation_post).body,
            )
            .map_err(|error| format!("decode elicitation rejection: {error}"))?;
            assert_eq!(elicitation["id"], 83);
            assert_eq!(elicitation["error"]["code"], -32601);
            write_response(&mut elicitation_post, 202, "application/json", b"");

            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":71,\"result\":{\"first\":true}}\n\n",
            );
            let Some(mut follow_up_post) = accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let follow_up = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut follow_up_post).body,
            )
            .map_err(|error| format!("decode follow-up request: {error}"))?;
            assert_eq!(follow_up["id"], 72);
            assert_eq!(follow_up["method"], "ping");
            write_response(&mut follow_up_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":72,\"result\":{\"followUp\":true}}\n\n",
            );
            finish_chunked_sse(&mut sse);
            Ok(true)
        });

        let capabilities = ClientCapabilities {
            sampling: Some(fastmcp_protocol::SamplingCapability {}),
            roots: Some(fastmcp_protocol::RootsCapability {
                list_changed: false,
            }),
            ..ClientCapabilities::default()
        };
        let handlers = ReverseRequestHandlers::new()
            .with_sampling_create_message(|_cx, _cancellation, _params| {
                Box::pin(async {
                    Ok(crate::CreateMessageResult::text(
                        "handled over legacy HTTP",
                        "legacy-http-handler",
                    ))
                })
            })
            .with_roots_list(|_cx, _cancellation, _params| {
                Box::pin(async {
                    Ok(crate::ListRootsResult::new(vec![
                        fastmcp_protocol::Root::new("file:///workspace"),
                    ]))
                })
            });
        let cx = Cx::for_request();
        let mut connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                "http://127.0.0.1:9/mcp",
                &sse_target,
                &message_target,
                ProtocolPolicy::LegacyOnly,
            ),
            ClientInfo {
                name: "legacy-http-reverse-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            capabilities,
        ))
        .expect("bounded legacy SSE connection opens");
        connection
            .set_legacy_reverse_request_handlers(handlers)
            .expect("handlers and retained legacy capabilities match");

        let first = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(71),
            4_096,
        ));
        let follow_up = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(72),
            4_096,
        ));
        signal_legacy_test_peer_stop(&stop_tx);
        let served = server
            .join()
            .expect("legacy reverse server must join")
            .expect("legacy reverse server exchange must remain bounded");

        assert!(
            served,
            "bounded legacy reverse peer must serve the exchange"
        );
        assert_eq!(
            first
                .expect("correlated application response follows reverse replies")
                .id,
            Some(RequestId::Number(71))
        );
        assert_eq!(
            follow_up
                .expect("follow-up remains aligned after reverse request replies")
                .id,
            Some(RequestId::Number(72))
        );
    }

    #[cfg(feature = "legacy-2024-11-05")]
    fn assert_public_high_level_http_initialize_reverse_callbacks(
        policy: ProtocolPolicy,
        configure_handlers: bool,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind high-level legacy reverse callback listener");
        let address = listener
            .local_addr()
            .expect("read high-level legacy reverse callback address");
        let modern_target = format!("http://{address}/mcp");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let (stop_tx, stop_rx) = mpsc::sync_channel::<()>(1);
        let server = thread::spawn(move || -> Result<bool, String> {
            listener.set_nonblocking(true).map_err(|error| {
                format!("make high-level legacy reverse callback listener nonblocking: {error}")
            })?;
            let deadline = Instant::now() + LEGACY_TEST_PEER_BOUND;

            if policy == ProtocolPolicy::Auto {
                let Some(mut probe) = accept_legacy_test_peer(&listener, &stop_rx, deadline)?
                else {
                    return Ok(false);
                };
                let discovery =
                    serde_json::from_slice::<serde_json::Value>(&read_request(&mut probe).body)
                        .map_err(|error| format!("decode disposable modern discovery: {error}"))?;
                if discovery["method"] != "server/discover" {
                    return Err(
                        "Auto did not issue its disposable modern discovery request".to_owned()
                    );
                }
                write_response(&mut probe, 404, "text/plain", b"");
            }

            let Some(mut sse) = accept_legacy_test_peer(&listener, &stop_rx, deadline)? else {
                return Ok(false);
            };
            let sse_request = read_request(&mut sse);
            if !sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n") {
                return Err("legacy lifecycle did not open the configured SSE route".to_owned());
            }
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            let Some(mut initialize_post) = accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let initialize = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut initialize_post).body,
            )
            .map_err(|error| format!("decode legacy initialize request: {error}"))?;
            if initialize["method"] != "initialize" || initialize["id"] != 1 {
                return Err(
                    "high-level HTTP client did not begin exact legacy initialize".to_owned(),
                );
            }
            if configure_handlers
                != (initialize["params"]["capabilities"]
                    .get("sampling")
                    .is_some()
                    && initialize["params"]["capabilities"].get("roots").is_some())
            {
                return Err(
                    "initialize callback capabilities did not match configured handlers".to_owned(),
                );
            }
            write_response(&mut initialize_post, 202, "application/json", b"");

            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":81,\"params\":{\"messages\":[],\"maxTokens\":9}}\n\n",
            );
            let Some(mut sampling_post) = accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let sampling =
                serde_json::from_slice::<serde_json::Value>(&read_request(&mut sampling_post).body)
                    .map_err(|error| format!("decode sampling callback reply: {error}"))?;
            if sampling["id"] != 81 {
                return Err("sampling reply lost its server request ID".to_owned());
            }
            if configure_handlers {
                if sampling["result"]["model"] != "high-level-http-handler" {
                    return Err(
                        "configured sampling handler was not active during initialize".to_owned(),
                    );
                }
            } else if sampling["error"]["code"] != -32601 {
                return Err("missing sampling handler did not retain MethodNotFound".to_owned());
            }
            write_response(&mut sampling_post, 202, "application/json", b"");

            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"roots/list\",\"id\":82,\"params\":{}}\n\n",
            );
            let Some(mut roots_post) = accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let roots =
                serde_json::from_slice::<serde_json::Value>(&read_request(&mut roots_post).body)
                    .map_err(|error| format!("decode roots callback reply: {error}"))?;
            if roots["id"] != 82 {
                return Err("roots reply lost its server request ID".to_owned());
            }
            if configure_handlers {
                if roots["result"]["roots"][0]["uri"] != "file:///workspace" {
                    return Err(
                        "configured roots handler was not active during initialize".to_owned()
                    );
                }
            } else if roots["error"]["code"] != -32601 {
                return Err("missing roots handler did not retain MethodNotFound".to_owned());
            }
            write_response(&mut roots_post, 202, "application/json", b"");

            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"high-level-reverse\",\"version\":\"1.0.0\"}}}\n\n",
            );
            let Some(mut initialized_post) =
                accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let initialized = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut initialized_post).body,
            )
            .map_err(|error| format!("decode initialized notification: {error}"))?;
            if initialized["method"] != "notifications/initialized" {
                return Err(
                    "high-level HTTP client did not complete the legacy lifecycle".to_owned(),
                );
            }
            write_response(&mut initialized_post, 202, "application/json", b"");

            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":84,\"params\":{\"messages\":[],\"maxTokens\":9}}\n\n",
            );
            let Some(mut ready_sampling_post) =
                accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let ready_sampling = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut ready_sampling_post).body,
            )
            .map_err(|error| format!("decode ready sampling reply: {error}"))?;
            if ready_sampling["id"] != 84 {
                return Err("ready sampling reply lost its server request ID".to_owned());
            }
            if configure_handlers {
                if ready_sampling["result"]["model"] != "high-level-http-handler" {
                    return Err("ready SSE receiver did not dispatch sampling callback".to_owned());
                }
            } else if ready_sampling["error"]["code"] != -32601 {
                return Err("ready SSE receiver did not retain MethodNotFound".to_owned());
            }
            write_response(&mut ready_sampling_post, 202, "application/json", b"");
            finish_chunked_sse(&mut sse);
            Ok(true)
        });

        let cx = Cx::for_request();
        let builder = ClientBuilder::new().protocol_plan(plan(
            &modern_target,
            &sse_target,
            &message_target,
            policy,
        ));
        let builder = if configure_handlers {
            builder.reverse_request_handlers(
                ReverseRequestHandlers::new()
                    .with_sampling_create_message(|_cx, _cancellation, _params| {
                        Box::pin(async {
                            Ok(crate::CreateMessageResult::text(
                                "handled during high-level HTTP initialize",
                                "high-level-http-handler",
                            ))
                        })
                    })
                    .with_roots_list(|_cx, _cancellation, _params| {
                        Box::pin(async {
                            Ok(crate::ListRootsResult::new(vec![
                                fastmcp_protocol::Root::new("file:///workspace"),
                            ]))
                        })
                    }),
            )
        } else {
            builder
        };
        let client = runtime_block_on(builder.connect_http_client_with_cx(&cx))
            .expect("public high-level HTTP client completes the exact legacy lifecycle");
        assert_eq!(client.selected_protocol_era(), ProtocolEra::Legacy2024);
        let served = server
            .join()
            .expect("high-level reverse callback server must join")
            .expect("high-level reverse callback exchange must remain bounded");
        drop(client);
        signal_legacy_test_peer_stop(&stop_tx);
        assert!(
            served,
            "high-level legacy peer must receive the configured callback behavior"
        );
    }

    /// Exercises the ready high-level exact-2024 SSE receive path. The two
    /// callers differ only in the request ID carried by the server's
    /// cancellation notification: `84` owns the reverse request; `85` does
    /// not. The matching case must fence the callback POST, while the
    /// one-variable non-match must still receive the normal callback result.
    #[cfg(feature = "legacy-2024-11-05")]
    fn assert_public_high_level_http_reverse_callback_cancellation(cancellation_id: i64) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind high-level legacy reverse cancellation listener");
        let address = listener
            .local_addr()
            .expect("read high-level legacy reverse cancellation address");
        let modern_target = format!("http://{address}/mcp");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let (stop_tx, stop_rx) = mpsc::sync_channel::<()>(1);
        let (callback_started_tx, callback_started_rx) = mpsc::sync_channel::<()>(1);
        let server = thread::spawn(move || -> Result<bool, String> {
            listener.set_nonblocking(true).map_err(|error| {
                format!("make high-level legacy reverse cancellation listener nonblocking: {error}")
            })?;
            let deadline = Instant::now() + LEGACY_TEST_PEER_BOUND;

            let Some(mut sse) = accept_legacy_test_peer(&listener, &stop_rx, deadline)? else {
                return Ok(false);
            };
            let sse_request = read_request(&mut sse);
            if !sse_request.head.starts_with("GET /legacy-sse HTTP/1.1\r\n") {
                return Err("reverse cancellation lifecycle did not open the SSE route".to_owned());
            }
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            let Some(mut initialize_post) = accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let initialize = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut initialize_post).body,
            )
            .map_err(|error| format!("decode reverse cancellation initialize: {error}"))?;
            if initialize["method"] != "initialize"
                || initialize["params"]["capabilities"]
                    .get("sampling")
                    .is_none()
            {
                return Err("reverse cancellation client did not advertise sampling".to_owned());
            }
            write_response(&mut initialize_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"high-level-reverse-cancellation\",\"version\":\"1.0.0\"}}}\n\n",
            );

            let Some(mut initialized_post) =
                accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let initialized = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut initialized_post).body,
            )
            .map_err(|error| format!("decode reverse cancellation initialized: {error}"))?;
            if initialized["method"] != "notifications/initialized" {
                return Err(
                    "reverse cancellation lifecycle missed initialized notification".to_owned(),
                );
            }
            write_response(&mut initialized_post, 202, "application/json", b"");

            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":84,\"params\":{\"messages\":[],\"maxTokens\":9}}\n\n",
            );
            callback_started_rx
                .recv_timeout(LEGACY_TEST_PEER_BOUND)
                .map_err(|error| {
                    format!("reverse callback did not start before cancellation: {error}")
                })?;
            write_chunked_sse_event(
                &mut sse,
                &format!(
                    "event: message\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{{\"requestId\":{cancellation_id}}}}}\n\n"
                ),
            );

            if cancellation_id == 84 {
                let unexpected = accept_legacy_test_peer(
                    &listener,
                    &stop_rx,
                    Instant::now() + Duration::from_millis(250),
                )?;
                if unexpected.is_some() {
                    return Err("matching callback cancellation still posted a response".to_owned());
                }
            } else {
                let Some(mut callback_post) =
                    accept_legacy_test_peer(&listener, &stop_rx, deadline)?
                else {
                    return Ok(false);
                };
                let callback = serde_json::from_slice::<serde_json::Value>(
                    &read_request(&mut callback_post).body,
                )
                .map_err(|error| format!("decode non-matching callback response: {error}"))?;
                if callback["id"] != 84 || callback["result"]["model"] != "cancellation-fence" {
                    return Err(
                        "non-matching cancellation suppressed the callback response".to_owned()
                    );
                }
                write_response(&mut callback_post, 202, "application/json", b"");
            }
            finish_chunked_sse(&mut sse);
            Ok(true)
        });

        let invoked = Arc::new(AtomicUsize::new(0));
        let observed_cancellation = Arc::new(AtomicUsize::new(0));
        let handlers = ReverseRequestHandlers::new().with_sampling_create_message({
            let invoked = Arc::clone(&invoked);
            let observed_cancellation = Arc::clone(&observed_cancellation);
            move |callback_cx, cancellation, _params| {
                let invoked = Arc::clone(&invoked);
                let observed_cancellation = Arc::clone(&observed_cancellation);
                let callback_started_tx = callback_started_tx.clone();
                Box::pin(async move {
                    invoked.fetch_add(1, Ordering::SeqCst);
                    let _ = callback_started_tx.try_send(());
                    let deadline = Instant::now() + Duration::from_millis(200);
                    while Instant::now() < deadline {
                        if cancellation.is_cancel_requested() {
                            observed_cancellation.fetch_add(1, Ordering::SeqCst);
                            return Err(McpError::request_cancelled());
                        }
                        asupersync::time::sleep(callback_cx.now(), Duration::from_millis(1)).await;
                    }
                    if cancellation.is_cancel_requested() {
                        observed_cancellation.fetch_add(1, Ordering::SeqCst);
                        return Err(McpError::request_cancelled());
                    }
                    Ok(crate::CreateMessageResult::text(
                        "reverse callback completed",
                        "cancellation-fence",
                    ))
                })
            }
        });
        let cx = Cx::for_request();
        let client = runtime_block_on(
            ClientBuilder::new()
                .protocol_plan(plan(
                    &modern_target,
                    &sse_target,
                    &message_target,
                    ProtocolPolicy::LegacyOnly,
                ))
                .reverse_request_handlers(handlers)
                .connect_http_client_with_cx(&cx),
        )
        .expect("public high-level HTTP client completes reverse cancellation lifecycle");
        assert_eq!(client.selected_protocol_era(), ProtocolEra::Legacy2024);
        let served = server
            .join()
            .expect("high-level reverse cancellation server must join")
            .expect("high-level reverse cancellation exchange must remain bounded");
        drop(client);
        signal_legacy_test_peer_stop(&stop_tx);
        assert!(
            served,
            "high-level legacy peer must observe exact reverse cancellation behavior"
        );
        assert_eq!(
            invoked.load(Ordering::SeqCst),
            1,
            "the live callback must start before the server sends cancellation"
        );
        assert_eq!(
            observed_cancellation.load(Ordering::SeqCst),
            usize::from(cancellation_id == 84),
            "only the matching cancellation may reach the live callback"
        );
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn public_high_level_http_installs_legacy_reverse_callbacks_before_initialize() {
        assert_public_high_level_http_initialize_reverse_callbacks(
            ProtocolPolicy::LegacyOnly,
            true,
        );
        assert_public_high_level_http_initialize_reverse_callbacks(ProtocolPolicy::Auto, true);
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn public_high_level_http_without_handlers_rejects_reverse_calls_during_initialize() {
        assert_public_high_level_http_initialize_reverse_callbacks(
            ProtocolPolicy::LegacyOnly,
            false,
        );
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn public_high_level_http_matching_reverse_callback_cancellation_fences_response_post() {
        assert_public_high_level_http_reverse_callback_cancellation(84);
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn public_high_level_http_nonmatching_reverse_callback_cancellation_preserves_response_post() {
        assert_public_high_level_http_reverse_callback_cancellation(85);
    }

    #[test]
    fn public_high_level_modern_http_rejects_legacy_reverse_handlers_before_connecting() {
        let invoked = Arc::new(AtomicUsize::new(0));
        let handlers = ReverseRequestHandlers::new().with_sampling_create_message({
            let invoked = Arc::clone(&invoked);
            move |_cx, _cancellation, _params| {
                invoked.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(crate::CreateMessageResult::text("unexpected", "unexpected")) })
            }
        });
        let cx = Cx::for_request();
        let Err(error) = runtime_block_on(
            ClientBuilder::new()
                .protocol_plan(plan(
                    "http://127.0.0.1:9/mcp",
                    "http://127.0.0.1:9/legacy-sse",
                    "http://127.0.0.1:9/legacy-message",
                    ProtocolPolicy::ModernOnly,
                ))
                .reverse_request_handlers(handlers)
                .connect_http_client_with_cx(&cx),
        ) else {
            panic!("ModernOnly HTTP must reject exact-2024 callback configuration");
        };
        assert!(matches!(
            error,
            crate::HttpClientError::CoreResult(error)
                if error.code == fastmcp_core::McpErrorCode::InvalidParams
        ));
        assert_eq!(
            invoked.load(Ordering::SeqCst),
            0,
            "a refused modern connection must not invoke a legacy callback"
        );
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn legacy_http_matching_cancellation_discards_late_response_before_follow_up() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind legacy cancellation listener");
        let address = listener
            .local_addr()
            .expect("read legacy cancellation listener address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let (stop_tx, stop_rx) = mpsc::sync_channel::<()>(1);
        let server = thread::spawn(move || -> Result<bool, String> {
            listener.set_nonblocking(true).map_err(|error| {
                format!("make legacy cancellation listener nonblocking: {error}")
            })?;
            let deadline = Instant::now() + LEGACY_TEST_PEER_BOUND;
            let Some(mut sse) = accept_legacy_test_peer(&listener, &stop_rx, deadline)? else {
                return Ok(false);
            };
            let _ = read_request(&mut sse);
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            let Some(mut cancelled_post) = accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let cancelled = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut cancelled_post).body,
            )
            .map_err(|error| format!("decode cancelled application request: {error}"))?;
            assert_eq!(cancelled["id"], 91);
            write_response(&mut cancelled_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":91}}\n\n",
            );

            let Some(mut follow_up_post) = accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let follow_up = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut follow_up_post).body,
            )
            .map_err(|error| format!("decode cancellation follow-up request: {error}"))?;
            assert_eq!(follow_up["id"], 92);
            write_response(&mut follow_up_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":91,\"result\":{\"late\":true}}\n\n",
            );
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":92,\"result\":{\"followUp\":true}}\n\n",
            );
            finish_chunked_sse(&mut sse);
            Ok(true)
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                "http://127.0.0.1:9/mcp",
                &sse_target,
                &message_target,
                ProtocolPolicy::LegacyOnly,
            ),
            ClientInfo {
                name: "legacy-http-cancellation-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("bounded legacy cancellation connection opens");
        let cancelled = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(91),
            4_096,
        ));
        let follow_up = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(92),
            4_096,
        ));
        signal_legacy_test_peer_stop(&stop_tx);
        let served = server
            .join()
            .expect("legacy cancellation server must join")
            .expect("legacy cancellation server exchange must remain bounded");

        assert!(
            served,
            "bounded legacy cancellation peer must serve the exchange"
        );
        assert!(matches!(
            cancelled,
            Err(ClientHttpConnectionError::LegacyRequestCancelled {
                request_id: RequestId::Number(91)
            })
        ));
        assert_eq!(
            follow_up
                .expect("late cancelled response is discarded before follow-up")
                .id,
            Some(RequestId::Number(92))
        );
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn ready_legacy_tombstone_refuses_reused_id_and_routes_distinct_follow_up() {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind ready legacy tombstone listener");
        let address = listener
            .local_addr()
            .expect("read ready legacy tombstone listener address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let (same_id_checked_tx, same_id_checked_rx) = mpsc::sync_channel::<()>(1);
        let (follow_up_ready_tx, follow_up_ready_rx) = mpsc::sync_channel::<()>(1);
        let server = thread::spawn(move || {
            let deadline = Instant::now() + LEGACY_TEST_PEER_BOUND;
            let (mut sse, _) = listener
                .accept()
                .expect("accept ready legacy tombstone SSE connection");
            listener
                .set_nonblocking(true)
                .expect("configure ready legacy tombstone listener");
            let _ = read_request(&mut sse);
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            let mut cancelled_post = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "timed out waiting for ready legacy cancellation POST"
                        );
                        thread::sleep(LEGACY_TEST_PEER_POLL_INTERVAL);
                    }
                    Err(error) => panic!("accept ready legacy cancellation POST: {error}"),
                }
            };
            let cancelled = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut cancelled_post).body,
            )
            .expect("decode ready legacy cancellation request");
            assert_eq!(cancelled["id"], 91);
            write_response(&mut cancelled_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":91}}\n\n",
            );

            same_id_checked_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("the tombstoned-ID rejection must be observed before probing POSTs");
            let no_replay_deadline = Instant::now() + Duration::from_millis(100);
            while Instant::now() < no_replay_deadline {
                match listener.accept() {
                    Ok(_) => panic!("a tombstoned legacy request ID must not POST again"),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(LEGACY_TEST_PEER_POLL_INTERVAL);
                    }
                    Err(error) => panic!("unexpected tombstoned-ID accept error: {error}"),
                }
            }

            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":91,\"result\":{\"late\":true}}\n\n",
            );
            follow_up_ready_tx
                .send(())
                .expect("allow distinct follow-up after stale frame is queued");
            let mut follow_up_post = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "timed out waiting for distinct ready legacy follow-up"
                        );
                        thread::sleep(LEGACY_TEST_PEER_POLL_INTERVAL);
                    }
                    Err(error) => panic!("accept distinct ready legacy follow-up: {error}"),
                }
            };
            let follow_up = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut follow_up_post).body,
            )
            .expect("decode distinct ready legacy follow-up");
            assert_eq!(follow_up["id"], 92);
            write_response(&mut follow_up_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":92,\"result\":{\"followUp\":true}}\n\n",
            );
            finish_chunked_sse(&mut sse);
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(async {
            let mut connection = ClientHttpConnection::connect(
                &cx,
                plan(
                    "http://127.0.0.1:9/mcp",
                    &sse_target,
                    &message_target,
                    ProtocolPolicy::LegacyOnly,
                ),
                ClientInfo {
                    name: "ready-legacy-tombstone-client".to_owned(),
                    version: "1.0.0".to_owned(),
                },
                ClientCapabilities::default(),
            )
            .await?;
            connection.start_legacy_receive_pump(&cx)?;
            Ok::<_, ClientHttpConnectionError>(connection)
        })
        .expect("ready legacy tombstone connection opens");
        let cancelled = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(91),
            4_096,
        ));
        assert!(matches!(
            cancelled,
            Err(ClientHttpConnectionError::LegacyRequestCancelled {
                request_id: RequestId::Number(91)
            })
        ));

        let reused = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(91),
            4_096,
        ));
        assert!(matches!(
            reused,
            Err(
                ClientHttpConnectionError::LegacyCancelledRequestStillDraining {
                    request_id: RequestId::Number(91)
                }
            )
        ));
        same_id_checked_tx
            .send(())
            .expect("allow server to prove the rejected ID never posted");
        follow_up_ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("server discards the old terminal frame before follow-up");

        let follow_up = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(92),
            4_096,
        ));
        assert_eq!(
            follow_up
                .expect("distinct ID remains usable after the stale terminal frame")
                .id,
            Some(RequestId::Number(92))
        );
        server.join().expect("ready legacy tombstone peer joins");
    }

    #[cfg(feature = "legacy-2024-11-05")]
    fn assert_legacy_cancelled_post_tombstones_late_response_before_follow_up(
        use_ready_receive_pump: bool,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind ready legacy accepted-POST cancellation listener");
        let address = listener
            .local_addr()
            .expect("read ready legacy accepted-POST cancellation listener address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let (post_accepted_tx, post_accepted_rx) = mpsc::sync_channel::<()>(1);
        let (release_late_tx, release_late_rx) = mpsc::sync_channel::<()>(1);
        let (follow_up_ready_tx, follow_up_ready_rx) = mpsc::sync_channel::<()>(1);
        let server = thread::spawn(move || {
            let deadline = Instant::now() + LEGACY_TEST_PEER_BOUND;
            let (mut sse, _) = listener
                .accept()
                .expect("accept ready legacy accepted-POST SSE connection");
            listener
                .set_nonblocking(true)
                .expect("configure ready legacy accepted-POST listener");
            let _ = read_request(&mut sse);
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            let mut cancelled_post = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "timed out waiting for accepted legacy POST"
                        );
                        thread::sleep(LEGACY_TEST_PEER_POLL_INTERVAL);
                    }
                    Err(error) => panic!("accept ready legacy accepted POST: {error}"),
                }
            };
            let cancelled = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut cancelled_post).body,
            )
            .expect("decode accepted legacy POST");
            assert_eq!(cancelled["id"], 91);
            post_accepted_tx
                .send(())
                .expect("allow caller cancellation after peer accepts the POST");
            release_late_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("wait until cancelled caller has installed its tombstone");
            drop(cancelled_post);
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":91,\"result\":{\"late\":true}}\n\n",
            );
            follow_up_ready_tx
                .send(())
                .expect("allow follow-up after the late terminal frame");

            let mut follow_up_post = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "timed out waiting for accepted-POST follow-up"
                        );
                        thread::sleep(LEGACY_TEST_PEER_POLL_INTERVAL);
                    }
                    Err(error) => panic!("accept accepted-POST follow-up: {error}"),
                }
            };
            let follow_up = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut follow_up_post).body,
            )
            .expect("decode accepted-POST follow-up");
            assert_eq!(follow_up["id"], 92);
            write_response(&mut follow_up_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":92,\"result\":{\"followUp\":true}}\n\n",
            );
            finish_chunked_sse(&mut sse);
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(async {
            let mut connection = ClientHttpConnection::connect(
                &cx,
                plan(
                    "http://127.0.0.1:9/mcp",
                    &sse_target,
                    &message_target,
                    ProtocolPolicy::LegacyOnly,
                ),
                ClientInfo {
                    name: "ready-legacy-accepted-post-client".to_owned(),
                    version: "1.0.0".to_owned(),
                },
                ClientCapabilities::default(),
            )
            .await?;
            if use_ready_receive_pump {
                connection.start_legacy_receive_pump(&cx)?;
            }
            Ok::<_, ClientHttpConnectionError>(connection)
        })
        .expect("ready legacy accepted-POST connection opens");
        let cancelled_cx = Cx::for_request();
        let cancellation_controller = {
            let cancelled_cx = cancelled_cx.clone();
            thread::spawn(move || {
                post_accepted_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("server must observe the POST before cancellation");
                cancelled_cx.cancel_with(
                    CancelKind::User,
                    Some("cancel accepted legacy POST before its HTTP acknowledgement"),
                );
            })
        };
        let cancelled = runtime_block_on(connection.request_json(
            &cancelled_cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(91),
            4_096,
        ));
        cancellation_controller
            .join()
            .expect("accepted-POST cancellation controller joins");
        assert!(matches!(
            cancelled,
            Err(ClientHttpConnectionError::Legacy(
                LegacySseHttpClientError::Cancelled
                    | LegacySseHttpClientError::Executor(ModernHttpExecutorError::Cancelled)
            ))
        ));
        release_late_tx
            .send(())
            .expect("release the late accepted-POST terminal response");
        follow_up_ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("late accepted-POST terminal frame is queued");

        let follow_up = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(92),
            4_096,
        ));
        assert_eq!(
            follow_up
                .expect("late accepted-POST response is tombstoned before follow-up")
                .id,
            Some(RequestId::Number(92))
        );
        server
            .join()
            .expect("ready legacy accepted-POST cancellation peer joins");
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn legacy_cancelled_post_tombstones_late_response_before_follow_up() {
        assert_legacy_cancelled_post_tombstones_late_response_before_follow_up(false);
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn ready_legacy_cancelled_post_tombstones_late_response_before_follow_up() {
        assert_legacy_cancelled_post_tombstones_late_response_before_follow_up(true);
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn legacy_http_foreign_cancellation_is_retained_without_cancelling_active_request() {
        // This differs from the admitted cancellation case only in the
        // notification requestId: 102 names no active request.
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind legacy foreign-cancel listener");
        let address = listener
            .local_addr()
            .expect("read legacy foreign-cancel listener address");
        let sse_target = format!("http://{address}/legacy-sse");
        let message_target = format!("http://{address}/legacy-message");
        let advertised_message_target = message_target.clone();
        let (stop_tx, stop_rx) = mpsc::sync_channel::<()>(1);
        let server = thread::spawn(move || -> Result<bool, String> {
            listener.set_nonblocking(true).map_err(|error| {
                format!("make legacy foreign-cancel listener nonblocking: {error}")
            })?;
            let deadline = Instant::now() + LEGACY_TEST_PEER_BOUND;
            let Some(mut sse) = accept_legacy_test_peer(&listener, &stop_rx, deadline)? else {
                return Ok(false);
            };
            let _ = read_request(&mut sse);
            begin_chunked_sse(&mut sse);
            write_chunked_sse_event(
                &mut sse,
                &format!("event: endpoint\ndata: {advertised_message_target}\n\n"),
            );

            let Some(mut application_post) =
                accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let application = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut application_post).body,
            )
            .map_err(|error| format!("decode foreign-cancel application request: {error}"))?;
            assert_eq!(application["id"], 101);
            write_response(&mut application_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":102}}\n\n",
            );
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":101,\"result\":{\"active\":true}}\n\n",
            );

            let Some(mut follow_up_post) = accept_legacy_test_peer(&listener, &stop_rx, deadline)?
            else {
                return Ok(false);
            };
            let follow_up = serde_json::from_slice::<serde_json::Value>(
                &read_request(&mut follow_up_post).body,
            )
            .map_err(|error| format!("decode foreign-cancel follow-up request: {error}"))?;
            assert_eq!(follow_up["id"], 103);
            write_response(&mut follow_up_post, 202, "application/json", b"");
            write_chunked_sse_event(
                &mut sse,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":103,\"result\":{\"followUp\":true}}\n\n",
            );
            finish_chunked_sse(&mut sse);
            Ok(true)
        });

        let cx = Cx::for_request();
        let mut connection = runtime_block_on(ClientHttpConnection::connect(
            &cx,
            plan(
                "http://127.0.0.1:9/mcp",
                &sse_target,
                &message_target,
                ProtocolPolicy::LegacyOnly,
            ),
            ClientInfo {
                name: "legacy-http-foreign-cancel-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("bounded legacy foreign-cancel connection opens");
        let active = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(101),
            4_096,
        ));
        let follow_up = runtime_block_on(connection.request_json(
            &cx,
            "ping",
            serde_json::json!({}),
            RequestId::Number(103),
            4_096,
        ));
        signal_legacy_test_peer_stop(&stop_tx);
        let served = server
            .join()
            .expect("legacy foreign-cancel server must join")
            .expect("legacy foreign-cancel server exchange must remain bounded");

        assert!(
            served,
            "bounded legacy foreign-cancel peer must serve the exchange"
        );
        assert_eq!(
            active
                .expect("foreign cancellation must not cancel active request")
                .id,
            Some(RequestId::Number(101))
        );
        let notification = connection
            .take_legacy_notification()
            .expect("foreign cancellation is retained as an ordinary notification");
        assert_eq!(notification.method, "notifications/cancelled");
        assert_eq!(
            notification.params.expect("foreign cancellation params")["requestId"],
            102
        );
        assert_eq!(
            follow_up
                .expect("foreign cancellation does not disturb follow-up alignment")
                .id,
            Some(RequestId::Number(103))
        );
    }

    #[cfg(feature = "legacy-2024-11-05")]
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

    #[cfg(feature = "legacy-2024-11-05")]
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

    #[cfg(feature = "apps")]
    #[test]
    fn modern_http_client_is_stateless_for_json_and_sse_posts() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stateless HTTP listener");
        let address = listener.local_addr().expect("read stateless HTTP address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut discovery_stream, _) = listener.accept().expect("accept stateless discovery");
            let discovery = read_request(&mut discovery_stream);
            assert!(!discovery.head.contains("MCP-Session-Id:"));
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&discovery.body)
                    .expect("stateless discovery is JSON-RPC")["method"],
                SERVER_DISCOVER
            );
            write_response(
                &mut discovery_stream,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"extensions":{"io.modelcontextprotocol/ui":{}}},"serverInfo":{"name":"stateless","version":"1"},"ttlMs":0,"cacheScope":"private"}}"#,
            );

            let (mut json_stream, _) = listener.accept().expect("accept stateless JSON POST");
            let json = read_request(&mut json_stream);
            assert!(!json.head.contains("MCP-Session-Id:"));
            let json = serde_json::from_slice::<serde_json::Value>(&json.body)
                .expect("stateless JSON request is JSON-RPC");
            assert_eq!(json["id"], 2);
            assert_eq!(json["method"], "tools/list");
            assert!(
                json["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
                    .get(OFFICIAL_MCP_APPS_EXTENSION_ID)
                    .is_some()
            );
            write_response(
                &mut json_stream,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
            );

            let (mut sse_stream, _) = listener.accept().expect("accept stateless SSE POST");
            let sse = read_request(&mut sse_stream);
            assert!(!sse.head.contains("MCP-Session-Id:"));
            let sse = serde_json::from_slice::<serde_json::Value>(&sse.body)
                .expect("stateless SSE request is JSON-RPC");
            assert_eq!(sse["id"], 3);
            assert_eq!(sse["method"], TOOLS_CALL);
            write_response(
                &mut sse_stream,
                200,
                "text/event-stream",
                br#"event: message
data: {"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","content":[{"type":"text","text":"done"}],"isError":false}}

"#,
            );
        });

        let cx = Cx::for_request();
        let apps = McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
            .expect("valid Apps client settings");
        let client = runtime_block_on(ModernHttpClient::connect_with_mcp_apps(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "stateless-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
            Some(apps),
        ))
        .expect("stateless discovery selects modern HTTP")
        .into_modern()
        .expect("ModernOnly cannot select legacy HTTP");
        let json = runtime_block_on(client.request(
            &cx,
            "tools/list",
            serde_json::json!({}),
            Some(RequestId::Number(2)),
        ))
        .expect("stateless JSON POST succeeds");
        runtime_block_on(json.read_to_end(&cx, 4_096)).expect("drain stateless JSON response");

        let mut listener = runtime_block_on(client.open_final_tool_call_listener(
            &cx,
            RequestId::Number(3),
            "echo",
            serde_json::json!({}),
            SseLimits::new(1_024, 4_096, 4).expect("bounded stateless SSE limits"),
        ))
        .expect("stateless SSE POST opens");
        assert!(matches!(
            runtime_block_on(listener.next_event(&cx)),
            Ok(Some(ModernHttpFinalCoreEvent::Terminal(
                FinalCoreResult::ToolsCall { .. }
            )))
        ));
        server.join().expect("stateless HTTP server joins");
    }

    #[test]
    fn modern_http_client_rejects_mcp_session_id_response_header() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind session-header listener");
        let address = listener.local_addr().expect("read session-header address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut discovery, _) = listener.accept().expect("accept session-header discovery");
            let discovery_request = read_request(&mut discovery);
            assert!(!discovery_request.head.contains("MCP-Session-Id:"));
            let body = modern_discovery_body();
            write!(
                discovery,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMCP-Session-Id: forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("write session-header response head");
            discovery
                .write_all(body)
                .expect("write session-header response body");
            discovery.flush().expect("flush session-header response");
        });

        let cx = Cx::for_request();
        let result = runtime_block_on(ModernHttpClient::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "session-header-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ));
        assert!(matches!(
            result,
            Err(ModernHttpClientError::Executor(
                ModernHttpExecutorError::ForbiddenResponseSessionHeader
            ))
        ));
        server.join().expect("session-header server joins");
    }

    #[test]
    fn ordinary_modern_http_mrtr_retries_tool_resource_and_prompt_state_only_without_tasks() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ordinary MRTR listener");
        let address = listener.local_addr().expect("read ordinary MRTR address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept ordinary MRTR probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("ordinary MRTR probe is JSON-RPC")["method"],
                "server/discover"
            );
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            for (method, request_id, state, terminal) in [
                (TOOLS_CALL, 2, None, false),
                (TOOLS_CALL, 3, Some("tool-state"), true),
                (RESOURCES_READ, 4, None, false),
                (RESOURCES_READ, 5, Some("resource-state"), true),
                (PROMPTS_GET, 6, None, false),
                (PROMPTS_GET, 7, Some("prompt-state"), true),
            ] {
                let (mut stream, _) = listener.accept().expect("accept ordinary MRTR round");
                let request = read_request(&mut stream);
                assert!(request.head.contains(&format!("Mcp-Method: {method}\r\n")));
                assert!(
                    !request.head.contains("MCP-Session-Id:"),
                    "every ordinary MRTR round must remain stateless"
                );
                let body = serde_json::from_slice::<serde_json::Value>(&request.body)
                    .expect("ordinary MRTR request is JSON-RPC");
                assert_eq!(body["id"], request_id);
                assert_eq!(body["method"], method);
                assert_eq!(
                    body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
                    MODERN_PROTOCOL_VERSION
                );
                assert!(
                    body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
                        .get("extensions")
                        .is_none(),
                    "ordinary MRTR must not negotiate Tasks"
                );
                match state {
                    Some(state) => {
                        assert_eq!(body["params"]["requestState"], state);
                        assert!(body["params"].get("inputResponses").is_none());
                    }
                    None => {
                        assert!(body["params"].get("requestState").is_none());
                        assert!(body["params"].get("inputResponses").is_none());
                    }
                }

                let response = if terminal {
                    match method {
                        TOOLS_CALL => format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":{request_id},\"result\":{{\"resultType\":\"complete\",\"content\":[{{\"type\":\"text\",\"text\":\"done\"}}]}}}}"
                        ),
                        RESOURCES_READ => format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":{request_id},\"result\":{{\"resultType\":\"complete\",\"contents\":[],\"ttlMs\":0,\"cacheScope\":\"private\"}}}}"
                        ),
                        PROMPTS_GET => format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":{request_id},\"result\":{{\"resultType\":\"complete\",\"messages\":[]}}}}"
                        ),
                        _ => unreachable!("the test covers only MRTR core methods"),
                    }
                } else {
                    let state = match method {
                        TOOLS_CALL => "tool-state",
                        RESOURCES_READ => "resource-state",
                        PROMPTS_GET => "prompt-state",
                        _ => unreachable!("the test covers only MRTR core methods"),
                    };
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":{request_id},\"result\":{{\"resultType\":\"input_required\",\"requestState\":\"{state}\"}}}}"
                    )
                };
                write_response(&mut stream, 200, "application/json", response.as_bytes());
            }
        });

        let cx = Cx::for_request();
        let client = runtime_block_on(ModernHttpClient::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "ordinary-mrtr-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("modern discovery selects ordinary HTTP MRTR")
        .into_modern()
        .expect("ModernOnly cannot select legacy HTTP");
        let sse_limits = SseLimits::new(1_024, 8_192, 8).expect("bounded SSE limits");

        let mut next_tool_id = [RequestId::Number(3)].into_iter();
        let tool = runtime_block_on(client.call_tool_with_mrtr_retry(
            &cx,
            RequestId::Number(2),
            Instant::now() + Duration::from_secs(2),
            "ordinary-tool",
            serde_json::json!({"input": "state-only"}),
            sse_limits,
            4_096,
            || {
                Ok(next_tool_id
                    .next()
                    .expect("exactly one tool continuation ID"))
            },
            |input_required| {
                assert_eq!(input_required.request_state(), Some("tool-state"));
                Ok(BTreeMap::new())
            },
        ))
        .expect("ordinary HTTP tool MRTR completes without Tasks");
        assert!(matches!(
            tool,
            CoreResult::Final(FinalCoreResult::ToolsCall { .. })
        ));

        let mut next_resource_id = [RequestId::Number(5)].into_iter();
        let resource = runtime_block_on(client.read_resource_with_mrtr_retry(
            &cx,
            RequestId::Number(4),
            Instant::now() + Duration::from_secs(2),
            "file:///ordinary-mrtr.txt",
            sse_limits,
            4_096,
            || {
                Ok(next_resource_id
                    .next()
                    .expect("exactly one resource continuation ID"))
            },
            |input_required| {
                assert_eq!(input_required.request_state(), Some("resource-state"));
                Ok(BTreeMap::new())
            },
        ))
        .expect("ordinary HTTP resource MRTR completes without Tasks");
        assert!(matches!(
            resource,
            CoreResult::Final(FinalCoreResult::ResourcesRead { .. })
        ));

        let mut next_prompt_id = [RequestId::Number(7)].into_iter();
        let prompt = runtime_block_on(client.get_prompt_with_mrtr_retry(
            &cx,
            RequestId::Number(6),
            Instant::now() + Duration::from_secs(2),
            "ordinary-prompt",
            HashMap::new(),
            sse_limits,
            4_096,
            || {
                Ok(next_prompt_id
                    .next()
                    .expect("exactly one prompt continuation ID"))
            },
            |input_required| {
                assert_eq!(input_required.request_state(), Some("prompt-state"));
                Ok(BTreeMap::new())
            },
        ))
        .expect("ordinary HTTP prompt MRTR completes without Tasks");
        assert!(matches!(
            prompt,
            CoreResult::Final(FinalCoreResult::PromptsGet { .. })
        ));
        server.join().expect("ordinary MRTR peer joins");
    }

    #[test]
    fn ordinary_modern_http_mrtr_round_bound_changes_only_the_fifth_terminal_and_never_posts_again()
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind MRTR bound listener");
        let address = listener.local_addr().expect("read MRTR bound address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept MRTR bound probe");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("MRTR bound probe is JSON-RPC")["method"],
                "server/discover"
            );
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            // This matches a four-round positive exchange except that the
            // fifth terminal is one extra input_required result.
            for request_id in 2..=(MAX_MRTR_CONTINUATION_ROUNDS as i64 + 2) {
                let (mut stream, _) = listener.accept().expect("accept bounded MRTR round");
                let request = read_request(&mut stream);
                let body = serde_json::from_slice::<serde_json::Value>(&request.body)
                    .expect("bounded MRTR request is JSON-RPC");
                assert_eq!(body["id"], request_id);
                assert_eq!(body["method"], TOOLS_CALL);
                assert!(
                    body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
                        .get("extensions")
                        .is_none(),
                    "ordinary MRTR must not negotiate Tasks"
                );
                let state = format!("round-{request_id}");
                let response = format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{request_id},\"result\":{{\"resultType\":\"input_required\",\"requestState\":\"{state}\"}}}}"
                );
                write_response(&mut stream, 200, "application/json", response.as_bytes());
            }

            listener
                .set_nonblocking(true)
                .expect("configure no-contact assertion");
            let no_contact_deadline = Instant::now() + Duration::from_millis(200);
            while Instant::now() < no_contact_deadline {
                match listener.accept() {
                    Ok(_) => panic!("MRTR round bound must reject before a sixth POST"),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("unexpected no-contact accept error: {error}"),
                }
            }
        });

        let cx = Cx::for_request();
        let client = runtime_block_on(ModernHttpClient::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "ordinary-mrtr-bound-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("modern discovery selects ordinary HTTP MRTR")
        .into_modern()
        .expect("ModernOnly cannot select legacy HTTP");
        let mut next_id = 3_i64;
        let mut callback_count = 0_usize;
        let error = runtime_block_on(client.call_tool_with_mrtr_retry(
            &cx,
            RequestId::Number(2),
            Instant::now() + Duration::from_secs(2),
            "bound-tool",
            serde_json::json!({}),
            SseLimits::new(1_024, 8_192, 8).expect("bounded SSE limits"),
            4_096,
            || {
                let request_id = RequestId::Number(next_id);
                next_id += 1;
                Ok(request_id)
            },
            |_| {
                callback_count += 1;
                Ok(BTreeMap::new())
            },
        ))
        .expect_err("the one extra input_required result exceeds the local round bound");
        assert!(matches!(
            error,
            super::ModernHttpMrtrError::Driver(ref error)
                if error.message == "MRTR continuation-round limit exceeded"
        ));
        assert_eq!(callback_count, MAX_MRTR_CONTINUATION_ROUNDS);
        assert_eq!(next_id, MAX_MRTR_CONTINUATION_ROUNDS as i64 + 3);
        server.join().expect("MRTR no-contact peer joins");
    }

    fn assert_public_http_mrtr_requires_every_input_key(complete_retry: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind two-input MRTR listener");
        let address = listener
            .local_addr()
            .expect("read two-input MRTR listener address");
        let modern_target = format!("http://{address}/mcp");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept two-input discovery");
            let probe_request = read_request(&mut probe);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&probe_request.body)
                    .expect("two-input discovery is JSON-RPC")["method"],
                "server/discover"
            );
            write_response(&mut probe, 200, "application/json", modern_discovery_body());

            let (mut initial, _) = listener.accept().expect("accept two-input initial request");
            let initial_request = read_request(&mut initial);
            let initial_request =
                serde_json::from_slice::<serde_json::Value>(&initial_request.body)
                    .expect("two-input initial request is JSON-RPC");
            assert_eq!(initial_request["id"], 2);
            assert_eq!(initial_request["method"], TOOLS_CALL);
            write_response(
                &mut initial,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"},"sampling":{"method":"sampling/createMessage"}},"requestState":"retry-two"}}"#,
            );

            if complete_retry {
                let (mut retry, _) = listener.accept().expect("accept complete-input retry");
                let retry_request = read_request(&mut retry);
                let retry_request =
                    serde_json::from_slice::<serde_json::Value>(&retry_request.body)
                        .expect("complete-input retry is JSON-RPC");
                assert_eq!(retry_request["id"], 3);
                assert_eq!(retry_request["method"], TOOLS_CALL);
                assert_eq!(
                    retry_request["params"]["inputResponses"],
                    serde_json::json!({
                        "roots": {"roots": []},
                        "sampling": {"messages": []},
                    })
                );
                assert_eq!(retry_request["params"]["requestState"], "retry-two");
                write_response(
                    &mut retry,
                    200,
                    "application/json",
                    br#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","content":[],"isError":false}}"#,
                );
            } else {
                listener
                    .set_nonblocking(true)
                    .expect("configure partial-map no-contact assertion");
                let no_contact_deadline = Instant::now() + Duration::from_millis(200);
                while Instant::now() < no_contact_deadline {
                    match listener.accept() {
                        Ok(_) => panic!(
                            "a partial MRTR map must reject before a second public HTTP POST"
                        ),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => {
                            panic!("unexpected partial-map no-contact error: {error}");
                        }
                    }
                }
            }
        });

        let cx = Cx::for_request();
        let client = runtime_block_on(ModernHttpClient::connect(
            &cx,
            plan(
                &modern_target,
                "http://127.0.0.1:9/legacy-sse",
                "http://127.0.0.1:9/legacy-message",
                ProtocolPolicy::ModernOnly,
            ),
            ClientInfo {
                name: "two-input-mrtr-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("modern discovery selects two-input MRTR")
        .into_modern()
        .expect("ModernOnly cannot select legacy HTTP");
        let mut next_request_id = 3_i64;
        let mut callback_count = 0_usize;
        let result = runtime_block_on(client.call_tool_with_mrtr_retry(
            &cx,
            RequestId::Number(2),
            Instant::now() + Duration::from_secs(2),
            "two-input-tool",
            serde_json::json!({}),
            SseLimits::new(1_024, 8_192, 8).expect("bounded SSE limits"),
            4_096,
            || {
                let request_id = RequestId::Number(next_request_id);
                next_request_id += 1;
                Ok(request_id)
            },
            |_| {
                callback_count += 1;
                let mut responses =
                    BTreeMap::from([("roots".to_owned(), serde_json::json!({"roots": []}))]);
                if complete_retry {
                    responses.insert("sampling".to_owned(), serde_json::json!({"messages": []}));
                }
                Ok(responses)
            },
        ));

        if complete_retry {
            assert!(matches!(
                result,
                Ok(CoreResult::Final(FinalCoreResult::ToolsCall { .. }))
            ));
            assert_eq!(next_request_id, 4);
        } else {
            assert!(matches!(
                result,
                Err(ModernHttpMrtrError::Driver(ref error))
                    if error.message == "MRTR inputResponses must include every key requested by the peer"
            ));
            assert_eq!(
                next_request_id, 3,
                "a partial map must not allocate a continuation request ID"
            );
        }
        assert_eq!(callback_count, 1);
        server.join().expect("two-input MRTR peer joins");
    }

    #[test]
    fn public_http_mrtr_retries_after_every_requested_input_key_is_supplied() {
        assert_public_http_mrtr_requires_every_input_key(true);
    }

    #[test]
    fn public_http_mrtr_partial_input_map_has_no_next_post_or_id_mutation() {
        assert_public_http_mrtr_requires_every_input_key(false);
    }

    #[test]
    fn public_http_ping_is_admitted_without_entering_the_final_request_union() {
        super::validate_final_method(fastmcp_protocol::methods::PING, true)
            .expect("ping is a connection health-check");
        super::validate_final_method(fastmcp_protocol::methods::PING, false)
            .expect_err("ping still requires a request id");
        let refused = super::validate_final_method("logging/setLevel", true)
            .expect_err("the removed final setLevel RPC stays refused");
        assert!(matches!(
            refused,
            super::ModernHttpClientError::UnsupportedFinalMethod { method }
                if method == "logging/setLevel"
        ));
        assert!(
            fastmcp_protocol::methods::final_2026_07_28_method("ping").is_none(),
            "ping must remain outside the official 2026 client-request union"
        );
    }
}
