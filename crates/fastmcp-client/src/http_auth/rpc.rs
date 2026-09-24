//! Typed, bounded core calls over a [`ManagedOAuthSession`].
//!
//! Connects AUTH-03/04/07's discovery/login/renewal path to CLT-01's core
//! request/result vocabulary. Each call owns one POST, one correlation ID and
//! one response body. Notifications are delivered incrementally, never hidden
//! by a terminal collector. All wire admission uses fastmcp-protocol codecs.
//!
//! This explicit modern-only core-call API does not negotiate extensions,
//! cache results, or automatically retry an input-required result. Reviewed
//! schema-derived parameter headers are an explicit opt-in in [`tool_headers`].
//! Use the returned typed `input_required` branch for host continuation policy.
//! It does not replace the existing Auto/legacy or extension-aware clients.
//! For bounded authenticated subscription streams, see [`subscription`].

use std::fmt;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::common_types::ExactNonNegativeJsonNumber;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    CoreRequest, CoreResult, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION,
    JsonInteger, JsonRpcMessage, ProgressMarker, RequestId, ServerNotification,
    decode_strict_jsonrpc_message, decode_strict_jsonrpc_response,
};
use serde::Deserialize;

use super::managed::{
    ManagedOAuthResponse, ManagedOAuthSession, ManagedOAuthSseStream, OAuthSessionError,
};
use crate::http_executor::{ModernHttpRequest, ModernHttpResponseKind};
use crate::sse::SseLimits;

/// Bounded catalog traversal and explicitly enabled credential-local page caching.
pub mod catalog;
/// Explicit host-driven, bounded input-required continuation operations.
pub mod interaction;
/// Bounded resource reads and explicitly enabled credential-local result caching.
pub mod resource;
/// Request-owned, bounded core subscription streams over managed OAuth.
pub mod subscription;
/// Explicit parameter-header disclosure with ordinary managed call ownership.
pub mod tool_headers;

/// Independent request, frame, cumulative payload, notification and time bounds.
/// Native HTTP/SSE bounds continue to apply and may be tighter than these limits.
#[derive(Clone, Copy, Debug)]
pub struct ManagedCoreLimits {
    request_bytes: usize,
    frame_bytes: usize,
    total_bytes: usize,
    notifications: usize,
    timeout: Duration,
}

impl Default for ManagedCoreLimits {
    fn default() -> Self {
        Self {
            request_bytes: 8 * 1024 * 1024,
            frame_bytes: 8 * 1024 * 1024,
            total_bytes: 32 * 1024 * 1024,
            notifications: 64,
            timeout: Duration::from_secs(120),
        }
    }
}

impl ManagedCoreLimits {
    pub(crate) fn request_bytes(self) -> usize { self.request_bytes }
    pub(crate) fn frame_bytes(self) -> usize { self.frame_bytes }
    pub(crate) fn total_bytes(self) -> usize { self.total_bytes }
    pub(crate) fn timeout(self) -> Duration { self.timeout }

    /// A notification limit of zero intentionally requires a terminal-only
    /// response. The deadline includes credential acquisition, HTTP headers,
    /// all body reads, and time spent by the caller between successive reads.
    pub fn new(
        request_bytes: usize,
        frame_bytes: usize,
        total_bytes: usize,
        notifications: usize,
        timeout: Duration,
    ) -> Result<Self, ManagedCoreError> {
        if !(1..=8 * 1024 * 1024).contains(&request_bytes)
            || !(1..=8 * 1024 * 1024).contains(&frame_bytes)
            || !(frame_bytes..=128 * 1024 * 1024).contains(&total_bytes)
            || notifications > 1024
            || timeout.is_zero()
            || timeout > Duration::from_mins(15)
        {
            return Err(ManagedCoreError::InvalidLimits);
        }
        Ok(Self { request_bytes, frame_bytes, total_bytes, notifications, timeout })
    }
}

/// No peer-provided error message, data, malformed frame or request payload is
/// retained in diagnostics. A valid remote error exposes only its numeric code.
#[derive(Debug)]
pub enum ManagedCoreError {
    InvalidLimits,
    InvalidRequest,
    UnsupportedRequest,
    UnsupportedResult,
    RequestTooLarge,
    InvalidResponse,
    ResponseIdMismatch,
    InvalidResult,
    UnexpectedNotification,
    InvalidProgress,
    NotificationLimit,
    ResponseByteLimit,
    MissingTerminal,
    Closed,
    Cancelled,
    TimedOut,
    RuntimeUnavailable,
    HttpStatus { status: u16 },
    Remote { code: JsonInteger },
    Session(OAuthSessionError),
}

impl fmt::Display for ManagedCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Remote { code } => write!(f, "managed core request failed with JSON-RPC {code}"),
            Self::HttpStatus { status } => write!(f, "managed core request rejected with HTTP {status}"),
            Self::Session(error) => error.fmt(f),
            other => f.write_str(match other {
                Self::InvalidLimits => "invalid managed core call limits",
                Self::InvalidRequest => "invalid typed core request",
                Self::UnsupportedRequest => "request requires a different protocol or extension client",
                Self::UnsupportedResult => "result requires extension negotiation absent from this core call",
                Self::RequestTooLarge => "typed core request exceeds the encoded-byte limit",
                Self::InvalidResponse => "core response failed strict JSON-RPC admission",
                Self::ResponseIdMismatch => "core response does not match the owning request ID",
                Self::InvalidResult => "core result does not match its request's protocol contract",
                Self::UnexpectedNotification => "unexpected control or reverse request in a core response",
                Self::InvalidProgress => "core response progress is uncorrelated or not increasing",
                Self::NotificationLimit => "core response notification limit exceeded",
                Self::ResponseByteLimit => "core response payload-byte limit exceeded",
                Self::MissingTerminal => "core response ended without its terminal result",
                Self::Closed => "managed core call is closed",
                Self::Cancelled => "managed core call cancelled",
                Self::TimedOut => "managed core call absolute deadline exceeded",
                Self::RuntimeUnavailable => "managed core calls require the caller's timer",
                Self::Remote { .. } | Self::HttpStatus { .. } | Self::Session(_) => unreachable!(),
            }),
        }
    }
}

impl std::error::Error for ManagedCoreError {}

impl From<OAuthSessionError> for ManagedCoreError {
    fn from(error: OAuthSessionError) -> Self { Self::Session(error) }
}

/// A notification is delivered before any later result/error. Results retain
/// their complete/input-required distinction and lossless protocol payloads.
/// Neither results nor input-required outcomes trigger another POST.
pub enum ManagedCoreEvent {
    Notification(Box<ServerNotification>),
    Result(Box<CoreResult>),
}

impl ManagedOAuthSession {
    /// Sends one already-typed core request to this session's exact resource.
    /// The protocol encoder, bounds and method/profile checks run before token
    /// renewal or network contact. Metadata is caller-authored and validated,
    /// not silently replaced. In particular it must contain final version and
    /// client capabilities. Nonempty extension advertisements are rejected:
    /// this API has not performed bilateral extension negotiation.
    pub async fn request_core(
        &self,
        cx: &Cx,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedCoreLimits,
    ) -> Result<ManagedCoreCall, ManagedCoreError> {
        self.request_core_with_cancellation(
            cx, &McpRequestCancellation::new(), request, request_id, limits,
        ).await
    }

    /// Like [`Self::request_core`], with a request-local cancellation domain
    /// retained through every response read. Cancellation never sends a modern
    /// HTTP cancellation notification and never cancels sibling calls.
    pub async fn request_core_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedCoreLimits,
    ) -> Result<ManagedCoreCall, ManagedCoreError> {
        let deadline = call_deadline(cx, cancellation, limits.timeout)?;
        let (wire, decoder) = prepare(self.resource().as_str(), request, request_id, limits)?;
        let response = bounded_wait(cx, cancellation, deadline, async {
            self.execute_with_cancellation(cx, cancellation, &wire).await.map_err(ManagedCoreError::from)
        }).await?;
        ManagedCoreCall::from_response(response, decoder, cancellation.clone(), deadline)
    }
}

/// One incremental core call. Drop/close owns response cleanup. A polled read
/// that is dropped also retires the call; partial JSON/SSE state is not reusable.
/// Access-token expiry and session closure remain enforced by the managed body.
/// Native idle/absolute response policies are retained, not relaxed by this API.
pub struct ManagedCoreCall {
    body: Option<CoreBody>,
    decoder: CoreDecoder,
    cancellation: McpRequestCancellation,
    deadline: Time,
    generation: u64,
    finished: bool,
}

enum CoreBody {
    Json(ManagedOAuthResponse),
    Sse(ManagedOAuthSseStream),
}

impl ManagedCoreCall {
    fn from_response(
        response: ManagedOAuthResponse,
        decoder: CoreDecoder,
        cancellation: McpRequestCancellation,
        deadline: Time,
    ) -> Result<Self, ManagedCoreError> {
        if response.metadata().status() != 200 {
            return Err(ManagedCoreError::HttpStatus { status: response.metadata().status() });
        }
        let generation = response.credential_generation();
        let body = match response.metadata().kind() {
            ModernHttpResponseKind::Json => CoreBody::Json(response),
            ModernHttpResponseKind::Sse => {
                // Include framing overhead while bounding the decoded RPC
                // payload separately in CoreDecoder. The native pending-frame
                // budget remains a separate, potentially tighter ceiling.
                let frame = decoder.limits.frame_bytes;
                let limits = SseLimits::new(frame + 16, frame + 64, 64)
                    .ok_or(ManagedCoreError::InvalidLimits)?;
                CoreBody::Sse(response.into_sse_stream(limits)?)
            }
            _ => return Err(ManagedCoreError::InvalidResponse),
        };
        Ok(Self {
            body: Some(body), decoder, cancellation, deadline, generation, finished: false,
        })
    }

    pub fn request_id(&self) -> &RequestId { &self.decoder.request_id }

    /// Session-local credential generation, not a cross-session cache identity.
    pub fn credential_generation(&self) -> u64 { self.generation }

    pub fn close(&mut self) { self.body = None; }

    /// Returns `None` only after delivering the single typed result. EOF before
    /// that result, a foreign ID, malformed ingress and remote errors fail the
    /// call. Already-delivered notifications remain with the caller on failure.
    /// An SSE result is withheld until clean body EOF: duplicate terminals,
    /// trailing notifications, read failures, cancellation and deadline expiry
    /// cannot turn a partial response into a published or cacheable success.
    pub async fn next_event(&mut self, cx: &Cx) -> Result<Option<ManagedCoreEvent>, ManagedCoreError> {
        if self.finished { return Ok(None); }
        let body = self.body.take().ok_or(ManagedCoreError::Closed)?;
        check_call(cx, &self.cancellation, self.deadline)?;
        let (frame, remaining) = match body {
            CoreBody::Json(response) => {
                let frame = bounded_wait(cx, &self.cancellation, self.deadline, async {
                    response.read_to_end(cx, self.decoder.limits.frame_bytes)
                        .await.map_err(ManagedCoreError::from)
                }).await?;
                (frame, None)
            }
            CoreBody::Sse(mut stream) => {
                let payload = bounded_wait(cx, &self.cancellation, self.deadline, async {
                    stream.next_event(cx).await.map_err(ManagedCoreError::from)
                }).await?.ok_or(ManagedCoreError::MissingTerminal)?;
                (payload.into_bytes(), Some(CoreBody::Sse(stream)))
            }
        };
        let event = self.decoder.admit(&frame, remaining.is_some())?;
        check_call(cx, &self.cancellation, self.deadline)?;
        match &event {
            ManagedCoreEvent::Result(_) => {
                if let Some(CoreBody::Sse(mut stream)) = remaining {
                    finish_finite_sse(cx, &self.cancellation, self.deadline, async {
                        stream.next_event(cx).await.map_err(ManagedCoreError::from)
                    }).await?;
                }
                check_call(cx, &self.cancellation, self.deadline)?;
                self.finished = true;
            }
            ManagedCoreEvent::Notification(_) => self.body = remaining,
        }
        Ok(Some(event))
    }
}

// A terminal JSON-RPC result does not prove that its finite HTTP body has
// ended. Keep the stream owned by the awaiting call until EOF, refusing the
// first trailing data event without retaining its potentially sensitive text.
// Native SSE framing/body bounds still apply, and the original call deadline
// also bounds comment-only tails or peers that never close the response.
// Dropping this wait drops the read future and its caller-owned stream; it
// never detaches work or cancels the parent/sibling request domain.
pub(crate) async fn finish_finite_sse(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    deadline: Time,
    next: impl Future<Output = Result<Option<String>, ManagedCoreError>>,
) -> Result<(), ManagedCoreError> {
    bounded_wait(cx, cancellation, deadline, async {
        match next.await? {
            None => Ok(()),
            Some(_) => Err(ManagedCoreError::InvalidResponse),
        }
    }).await
}

pub(crate) struct CoreDecoder {
    request: CoreRequest,
    request_id: RequestId,
    progress_marker: Option<ProgressMarker>,
    last_progress: Option<ExactNonNegativeJsonNumber>,
    limits: ManagedCoreLimits,
    bytes: usize,
    notifications: usize,
}

fn prepare(
    target: &str,
    request: CoreRequest,
    request_id: RequestId,
    limits: ManagedCoreLimits,
) -> Result<(ModernHttpRequest, CoreDecoder), ManagedCoreError> {
    if request.era() != ProtocolEra::Modern2026 || !matches!(request.method(),
        "server/discover" | "tools/list" | "tools/call" | "resources/list"
        | "resources/templates/list" | "resources/read" | "prompts/list"
        | "prompts/get" | "completion/complete"
    ) {
        return Err(ManagedCoreError::UnsupportedRequest);
    }
    request_id.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
    let params = request.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    let metadata = params.get("_meta").and_then(serde_json::Value::as_object)
        .ok_or(ManagedCoreError::InvalidRequest)?;
    if let Some(extensions) = metadata.get(FINAL_CLIENT_CAPABILITIES_META_KEY)
        .and_then(|capabilities| capabilities.get("extensions"))
        && !extensions.as_object().is_some_and(serde_json::Map::is_empty)
    {
        return Err(ManagedCoreError::UnsupportedRequest);
    }
    let name = if matches!(request.method(), "tools/call" | "prompts/get") {
        params.get("name").and_then(serde_json::Value::as_str).map(str::to_owned)
    } else { None };
    let envelope = serde_json::json!({
        "jsonrpc": "2.0", "id": request_id, "method": request.method(), "params": params,
    });
    let mut encoded = BoundedWriter { bytes: Vec::new(), maximum: limits.request_bytes };
    serde_json::to_writer(&mut encoded, &envelope).map_err(|_| ManagedCoreError::RequestTooLarge)?;
    let wire = ModernHttpRequest::new(target, encoded.bytes, FINAL_PROTOCOL_VERSION, request.method(), name)
        .map_err(|_| ManagedCoreError::InvalidRequest)?;
    Ok((wire, CoreDecoder::for_request(request, request_id, limits)?))
}

impl CoreDecoder {
    // Profile negotiation belongs to the authenticated dispatch owner. This
    // constructor shares only the core method/result/notification contract;
    // an auth extension stamp never activates Tasks or any other result family.
    pub(crate) fn for_request(
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedCoreLimits,
    ) -> Result<Self, ManagedCoreError> {
        if request.era() != ProtocolEra::Modern2026 || !matches!(request.method(),
            "server/discover" | "tools/list" | "tools/call" | "resources/list"
            | "resources/templates/list" | "resources/read" | "prompts/list"
            | "prompts/get" | "completion/complete"
        ) {
            return Err(ManagedCoreError::UnsupportedRequest);
        }
        request_id.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
        let params = request.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?
            .ok_or(ManagedCoreError::InvalidRequest)?;
        let metadata = params.get("_meta").and_then(serde_json::Value::as_object)
            .ok_or(ManagedCoreError::InvalidRequest)?;
        let progress_marker = metadata.get("progressToken").map(|value| {
            serde_json::from_value(value.clone()).map_err(|_| ManagedCoreError::InvalidRequest)
        }).transpose()?;
        Ok(Self {
            request, request_id, progress_marker, last_progress: None, limits,
            bytes: 0, notifications: 0,
        })
    }

    pub(crate) fn usage(&self) -> (usize, usize) {
        (self.bytes, self.notifications)
    }

    // Only a fresh round decoder can inherit an interaction's cumulative work.
    // A previously active decoder must never have its counters rewound.
    pub(crate) fn resume_usage(&mut self, bytes: usize, notifications: usize) -> Result<(), ManagedCoreError> {
        if self.bytes != 0 || self.notifications != 0 {
            return Err(ManagedCoreError::InvalidResponse);
        }
        if bytes >= self.limits.total_bytes {
            return Err(ManagedCoreError::ResponseByteLimit);
        }
        if notifications > self.limits.notifications {
            return Err(ManagedCoreError::NotificationLimit);
        }
        self.bytes = bytes;
        self.notifications = notifications;
        Ok(())
    }

    pub(crate) fn admit(&mut self, frame: &[u8], allow_notification: bool) -> Result<ManagedCoreEvent, ManagedCoreError> {
        if frame.len() > self.limits.frame_bytes
            || frame.len() > self.limits.total_bytes.saturating_sub(self.bytes)
        {
            return Err(ManagedCoreError::ResponseByteLimit);
        }
        let message = decode_strict_jsonrpc_message(frame, self.limits.frame_bytes)
            .map_err(|_| ManagedCoreError::InvalidResponse)?;
        let event = match message {
            JsonRpcMessage::Response(response) => {
                if !response.id.as_ref().is_some_and(|id| id.correlates_with(&self.request_id)) {
                    return Err(ManagedCoreError::ResponseIdMismatch);
                }
                if let Some(error) = response.error {
                    return Err(ManagedCoreError::Remote { code: error.code });
                }
                // Compile-time Tasks support in the shared codec is not this
                // call's authority to accept a Task. Check the core discriminator
                // boundary after strict envelope admission and before decoding
                // any extension result, identically in every feature profile.
                if response.result.as_ref().and_then(|result| result.get("resultType"))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|kind| !matches!(kind, "complete" | "input_required"))
                {
                    return Err(ManagedCoreError::UnsupportedResult);
                }
                let admission = decode_strict_jsonrpc_response(frame, self.limits.frame_bytes)
                    .map_err(|_| ManagedCoreError::InvalidResponse)?;
                let (response, source) = admission.into_parts();
                let source = source.ok_or(ManagedCoreError::InvalidResult)?;
                let result = self.request.decode_response_result(&response, &source)
                    .map_err(|_| ManagedCoreError::InvalidResult)?;
                ManagedCoreEvent::Result(Box::new(result))
            }
            JsonRpcMessage::Request(request) => {
                if !allow_notification || request.id.is_some() {
                    return Err(ManagedCoreError::UnexpectedNotification);
                }
                if self.notifications >= self.limits.notifications {
                    return Err(ManagedCoreError::NotificationLimit);
                }
                #[derive(Deserialize)]
                struct RawNotification {
                    params: Option<Box<serde_json::value::RawValue>>,
                }
                let raw: RawNotification = serde_json::from_slice(frame)
                    .map_err(|_| ManagedCoreError::InvalidResponse)?;
                let notification = match raw.params {
                    Some(params) => ServerNotification::decode_with_raw_params(&request, params.get()),
                    None => ServerNotification::decode(&request),
                }.map_err(|_| ManagedCoreError::UnexpectedNotification)?;
                match &notification {
                    ServerNotification::Cancelled(_) | ServerNotification::SubscriptionsAcknowledged(_) => {
                        return Err(ManagedCoreError::UnexpectedNotification);
                    }
                    ServerNotification::Progress(progress) => {
                        if self.progress_marker.as_ref() != Some(&progress.progress_token)
                            || self.last_progress.as_ref().is_some_and(|previous| progress.progress.cmp(previous).is_le())
                        {
                            return Err(ManagedCoreError::InvalidProgress);
                        }
                        self.last_progress = Some(progress.progress.clone());
                    }
                    _ => {},
                }
                self.notifications += 1;
                ManagedCoreEvent::Notification(Box::new(notification))
            }
        };
        self.bytes += frame.len();
        Ok(event)
    }
}

struct BoundedWriter { bytes: Vec<u8>, maximum: usize }

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("core request byte limit"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn call_deadline(cx: &Cx, cancellation: &McpRequestCancellation, timeout: Duration) -> Result<Time, ManagedCoreError> {
    if cancellation.is_cancel_requested() || cx.checkpoint().is_err() { return Err(ManagedCoreError::Cancelled); }
    if cx.timer_driver().is_none() { return Err(ManagedCoreError::RuntimeUnavailable); }
    let nanos = u64::try_from(timeout.as_nanos()).map_err(|_| ManagedCoreError::InvalidLimits)?;
    let end = cx.now().as_nanos().checked_add(nanos).ok_or(ManagedCoreError::InvalidLimits)?;
    let deadline = cx.budget().deadline.map_or(Time::from_nanos(end), |parent| parent.min(Time::from_nanos(end)));
    check_call(cx, cancellation, deadline)?;
    Ok(deadline)
}

fn check_call(cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time) -> Result<(), ManagedCoreError> {
    if cancellation.is_cancel_requested() || cx.checkpoint().is_err() { return Err(ManagedCoreError::Cancelled); }
    if cx.now() >= deadline { return Err(ManagedCoreError::TimedOut); }
    Ok(())
}

async fn bounded_wait<T>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    deadline: Time,
    future: impl Future<Output = Result<T, ManagedCoreError>>,
) -> Result<T, ManagedCoreError> {
    if cx.timer_driver().is_none() { return Err(ManagedCoreError::RuntimeUnavailable); }
    let deadline = cx.budget().deadline.map_or(deadline, |parent| parent.min(deadline));
    let mut sleep = std::pin::pin!(Sleep::new(deadline));
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut ambient = std::pin::pin!(receiver.recv(cx));
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        check_call(cx, cancellation, deadline)?;
        let _caller = Cx::set_current(Some(cx.clone()));
        if cancelled.as_mut().poll(task).is_ready() || ambient.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(ManagedCoreError::Cancelled));
        }
        if sleep.as_mut().poll(task).is_ready() { return Poll::Ready(Err(ManagedCoreError::TimedOut)); }
        let value = future.as_mut().poll(task);
        check_call(cx, cancellation, deadline)?;
        value
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::json;

    fn request(method: &str, mut params: serde_json::Value) -> CoreRequest {
        params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
    }

    fn decoder(method: &str, params: serde_json::Value) -> CoreDecoder {
        prepare("https://mcp.example/mcp", request(method, params), RequestId::Number(7), ManagedCoreLimits::default()).unwrap().1
    }

    fn frame(result: &str) -> Vec<u8> {
        format!(r#"{{"jsonrpc":"2.0","id":7,"result":{result}}}"#).into_bytes()
    }

    #[test]
    fn preparation_preserves_typed_params_id_and_routing_name() {
        let core = request("tools/call", json!({"name":"echo","arguments":{"text":"hello"}}));
        let (wire, _) = prepare("https://mcp.example/mcp", core, RequestId::Number(7), ManagedCoreLimits::default()).unwrap();
        let body: serde_json::Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(body["id"], 7);
        assert_eq!(body["method"], "tools/call");
        assert_eq!(body["params"]["arguments"]["text"], "hello");
        assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], FINAL_PROTOCOL_VERSION);
        let headers = wire.headers();
        assert!(headers.iter().any(|(name, value)| name.eq_ignore_ascii_case("mcp-name") && value == "echo"));
        assert!(!headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("authorization")));
        let tiny = ManagedCoreLimits::new(10, 1024, 1024, 1, Duration::from_secs(1)).unwrap();
        assert!(matches!(prepare("https://mcp.example/mcp", request("tools/list", json!({})), RequestId::Number(7), tiny), Err(ManagedCoreError::RequestTooLarge)));
    }

    #[test]
    fn json_and_sse_share_method_owned_lossless_result_admission() {
        let raw = r#"{"resultType":"complete","tools":[],"ttlMs":100,"cacheScope":"private","x-exact":{"z":900719925474099312345,"a":1.20e+4}}"#;
        for sse in [false, true] {
            let mut decoder = decoder("tools/list", json!({}));
            let ManagedCoreEvent::Result(result) = decoder.admit(&frame(raw), sse).unwrap() else { panic!("terminal expected") };
            let encoded = result.encode().unwrap();
            assert!(encoded.contains("900719925474099312345"));
            assert!(encoded.contains("1.20e+4"));
            assert!(encoded.find("\"z\"").unwrap() < encoded.find("\"a\"").unwrap());
        }
        let mut decoder = decoder("tools/list", json!({}));
        assert!(matches!(decoder.admit(&frame(r#"{"resultType":"complete","contents":[],"ttlMs":100,"cacheScope":"private"}"#), false), Err(ManagedCoreError::InvalidResult)));
    }

    #[test]
    fn input_required_is_a_typed_terminal_not_an_automatic_retry() {
        let mut decoder = decoder("resources/read", json!({"uri":"file:///sample"}));
        let response = frame(r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"opaque-state"}"#);
        let ManagedCoreEvent::Result(result) = decoder.admit(&response, false).unwrap() else { panic!("terminal expected") };
        assert!(matches!(*result, CoreResult::Final(fastmcp_protocol::FinalCoreResult::ResourcesReadInputRequired { .. })));
    }

    #[test]
    fn response_ids_duplicate_fields_and_batch_arrays_are_not_admitted() {
        for invalid in [
            r#"{"jsonrpc":"2.0","id":8,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
            r#"{"jsonrpc":"2.0","id":"7","result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
            r#"{"jsonrpc":"2.0","id":7,"id":7,"result":{}}"#,
            r#"[{"jsonrpc":"2.0","id":7,"result":{}}]"#,
        ] {
            let mut decoder = decoder("tools/list", json!({}));
            assert!(decoder.admit(invalid.as_bytes(), false).is_err());
            assert_eq!(decoder.bytes, 0);
            assert_eq!(decoder.notifications, 0);
        }
    }

    #[test]
    fn notifications_are_incremental_and_limits_leave_invalid_state_unchanged() {
        let notification = br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        let mut state = decoder("tools/list", json!({}));
        state.limits.notifications = 1;
        assert!(matches!(state.admit(notification, true), Ok(ManagedCoreEvent::Notification(_))));
        let before = state.bytes;
        assert!(matches!(state.admit(notification, true), Err(ManagedCoreError::NotificationLimit)));
        assert_eq!(state.bytes, before);
        assert_eq!(state.notifications, 1);
        assert!(matches!(state.admit(&frame(r#"{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}"#), true), Ok(ManagedCoreEvent::Result(_))));
        let mut json_decoder = decoder("tools/list", json!({}));
        assert!(matches!(json_decoder.admit(notification, false), Err(ManagedCoreError::UnexpectedNotification)));
    }

    #[test]
    fn foreign_or_nonincreasing_progress_cannot_advance_the_call() {
        let mut decoder = decoder("tools/call", json!({"name":"echo"}));
        decoder.progress_marker = Some(ProgressMarker::String("owned".to_owned()));
        let progress = |token: &str, value: u64| serde_json::to_vec(&json!({
            "jsonrpc":"2.0", "method":"notifications/progress",
            "params":{"progressToken":token,"progress":value}
        })).unwrap();
        assert!(decoder.admit(&progress("owned", 2), true).is_ok());
        let before = decoder.bytes;
        for (token, value) in [("foreign", 3), ("owned", 2), ("owned", 1)] {
            assert!(matches!(decoder.admit(&progress(token, value), true), Err(ManagedCoreError::InvalidProgress)));
            assert_eq!(decoder.bytes, before);
            assert_eq!(decoder.notifications, 1);
        }
        assert!(decoder.admit(&progress("owned", 3), true).is_ok());
    }

    #[test]
    fn remote_error_diagnostics_never_retain_peer_message_or_data() {
        let mut decoder = decoder("tools/list", json!({}));
        let response = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32603,"message":"secret-canary","data":{"secret":"also-secret"}}}"#;
        let error = decoder.admit(response, false).err().unwrap();
        assert!(matches!(&error, ManagedCoreError::Remote { .. }));
        assert!(!format!("{error:?} {error}").contains("secret"));
    }

    #[test]
    fn total_payload_limit_is_not_reset_by_each_notification() {
        let notification = br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        let mut decoder = decoder("tools/list", json!({}));
        decoder.limits.total_bytes = notification.len();
        assert!(decoder.admit(notification, true).is_ok());
        assert!(matches!(decoder.admit(&frame(r#"{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}"#), true), Err(ManagedCoreError::ResponseByteLimit)));
        assert_eq!(decoder.notifications, 1);
    }

    #[test]
    fn compiled_extension_codecs_do_not_authorize_core_call_task_results() {
        let task = r#"{"resultType":"task","taskId":"opaque","status":"working","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":1000}"#;
        #[cfg(feature = "tasks")]
        assert!(matches!(request("tools/call", json!({"name":"echo"})).decode_result(task),
            Ok(CoreResult::Final(fastmcp_protocol::FinalCoreResult::ToolsCallTask { .. }))));
        for sse in [false, true] {
            let mut decoder = decoder("tools/call", json!({"name":"echo"}));
            assert!(matches!(decoder.admit(&frame(task), sse), Err(ManagedCoreError::UnsupportedResult)));
            assert_eq!(decoder.bytes, 0);
            assert_eq!(decoder.notifications, 0);
            assert!(matches!(decoder.admit(&frame(r#"{"resultType":"complete","content":[]}"#), sse), Ok(ManagedCoreEvent::Result(_))));
        }
    }

    #[test]
    fn progress_identity_is_retained_from_the_actual_encoded_request() {
        let mut params = request("tools/call", json!({"name":"echo"})).encode_params().unwrap().unwrap();
        params["_meta"]["progressToken"] = json!("owned");
        let core = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap();
        let (wire, decoder) = prepare("https://mcp.example/mcp", core, RequestId::Number(7), ManagedCoreLimits::default()).unwrap();
        assert_eq!(decoder.progress_marker, Some(ProgressMarker::String("owned".to_owned())));
        let body: serde_json::Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(body["params"]["_meta"]["progressToken"], "owned");
    }

    #[test]
    fn same_poll_cancellation_withholds_a_ready_value_without_cancelling_parent() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let cancellation = McpRequestCancellation::new();
            let deadline = call_deadline(&cx, &cancellation, Duration::from_secs(1)).unwrap();
            let result = bounded_wait(&cx, &cancellation, deadline, async {
                cancellation.cancel();
                Ok(7_u8)
            }).await;
            assert!(matches!(result, Err(ManagedCoreError::Cancelled)));
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn dropping_a_polled_wait_drops_its_owned_future_without_parent_cancellation() {
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        struct OwnedPending(Arc<AtomicBool>);
        impl Future for OwnedPending {
            type Output = Result<(), ManagedCoreError>;
            fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Self::Output> { Poll::Pending }
        }
        impl Drop for OwnedPending {
            fn drop(&mut self) { self.0.store(true, Ordering::Release); }
        }
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let cancellation = McpRequestCancellation::new();
            let dropped = Arc::new(AtomicBool::new(false));
            let deadline = call_deadline(&cx, &cancellation, Duration::from_secs(1)).unwrap();
            let mut waiting = Box::pin(bounded_wait(&cx, &cancellation, deadline, OwnedPending(Arc::clone(&dropped))));
            poll_fn(|task| { assert!(waiting.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            drop(waiting);
            assert!(dropped.load(Ordering::Acquire));
            assert!(!cancellation.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn finite_sse_requires_eof_and_rejects_all_trailing_data_without_disclosure() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let cancellation = McpRequestCancellation::new();
            let deadline = call_deadline(&cx, &cancellation, Duration::from_secs(1)).unwrap();
            assert!(finish_finite_sse(&cx, &cancellation, deadline, async { Ok(None) }).await.is_ok());
            for trailing in [
                r#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
                r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#,
                r#"{"jsonrpc":"2.0","id":8,"error":{"code":-32603,"message":"secret-canary"}}"#,
                "malformed-secret-canary",
                "",
            ] {
                let error = finish_finite_sse(&cx, &cancellation, deadline, async {
                    Ok(Some(trailing.to_owned()))
                }).await.unwrap_err();
                assert!(matches!(error, ManagedCoreError::InvalidResponse));
                assert!(!format!("{error:?} {error}").contains("secret-canary"));
            }
            assert!(!cancellation.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn finite_sse_retains_tail_read_errors_and_same_poll_cancellation() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let cancellation = McpRequestCancellation::new();
            let deadline = call_deadline(&cx, &cancellation, Duration::from_secs(1)).unwrap();
            let failed = finish_finite_sse(&cx, &cancellation, deadline, async {
                Err(ManagedCoreError::ResponseByteLimit)
            }).await;
            assert!(matches!(failed, Err(ManagedCoreError::ResponseByteLimit)));
            let cancelled = finish_finite_sse(&cx, &cancellation, deadline, async {
                cancellation.cancel();
                Ok(None)
            }).await;
            assert!(matches!(cancelled, Err(ManagedCoreError::Cancelled)));
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn finite_sse_pending_eof_uses_the_original_absolute_deadline() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let cancellation = McpRequestCancellation::new();
            let deadline = call_deadline(&cx, &cancellation, Duration::from_millis(20)).unwrap();
            let result = finish_finite_sse(&cx, &cancellation, deadline, std::future::pending()).await;
            assert!(matches!(result, Err(ManagedCoreError::TimedOut)));
            assert!(!cancellation.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn dropping_finite_sse_eof_wait_releases_its_owned_read() {
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        struct OwnedRead(Arc<AtomicBool>);
        impl Future for OwnedRead {
            type Output = Result<Option<String>, ManagedCoreError>;
            fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Self::Output> { Poll::Pending }
        }
        impl Drop for OwnedRead {
            fn drop(&mut self) { self.0.store(true, Ordering::Release); }
        }
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let cancellation = McpRequestCancellation::new();
            let dropped = Arc::new(AtomicBool::new(false));
            let deadline = call_deadline(&cx, &cancellation, Duration::from_secs(1)).unwrap();
            let mut waiting = Box::pin(finish_finite_sse(&cx, &cancellation, deadline, OwnedRead(Arc::clone(&dropped))));
            poll_fn(|task| { assert!(waiting.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            drop(waiting);
            assert!(dropped.load(Ordering::Acquire));
            assert!(!cancellation.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
        });
    }

}
