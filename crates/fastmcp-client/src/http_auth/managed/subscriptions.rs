//! Authenticated core catalog/resource subscriptions over one owned HTTP POST.
//!
//! SUB-03 consumes the existing native subscription validator: there is no
//! second acknowledgement, filter, JSON-RPC or terminal-result parser here.
//! The managed owner adds token expiry, session closure, caller cancellation
//! and finite whole-listen bounds around that same production validator.
//!
//! This modern-only API does not negotiate Tasks/other extension filters,
//! reconnect, replay missed events, or extend a stream after token renewal.
//! After any gap, callers must explicitly open a fresh subscription and
//! reconcile their catalogs/resources; a successful new acknowledgement does
//! not prove that events from the gap were delivered.

use std::fmt;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    CompleteResult, CoreRequest, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION,
    FinalSubscriptionsListenResult, JsonInteger, RequestId, ServerNotification, SubscriptionFilter,
};

use super::{ManagedOAuthResponse, ManagedOAuthSession, OAuthSessionError, deadline_after};
use crate::http_executor::{
    ModernHttpRequest, ModernHttpResponseKind, ModernHttpSubscriptionListenError,
    ModernHttpSubscriptionListenEvent, ModernHttpSubscriptionListener,
};
use crate::sse::SseLimits;

/// Finite admission and lifetime bounds for one core subscription.
/// Native HTTP idle/absolute deadlines and pending-event budgets still apply
/// and may be tighter. No event queue grows with the lifetime of the stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedSubscriptionLimits {
    request_bytes: usize,
    frame_bytes: usize,
    records: usize,
    timeout: Duration,
}

impl Default for ManagedSubscriptionLimits {
    fn default() -> Self {
        Self {
            request_bytes: 64 * 1024,
            frame_bytes: 64 * 1024,
            records: 1024,
            timeout: Duration::from_secs(900),
        }
    }
}

impl ManagedSubscriptionLimits {
    /// `records` includes the acknowledgement and terminal result, not just
    /// change notifications. Reaching the limit without a terminal is failure,
    /// never successful EOF. `frame_bytes` bounds the native SSE line/event
    /// representation including framing overhead as well as its JSON payload.
    /// Time spent acquiring credentials or between event reads is included.
    pub fn new(
        request_bytes: usize,
        frame_bytes: usize,
        records: usize,
        timeout: Duration,
    ) -> Result<Self, ManagedSubscriptionError> {
        if !(1..=64 * 1024).contains(&request_bytes)
            || !(1..=64 * 1024).contains(&frame_bytes)
            || !(2..=4096).contains(&records)
            || timeout.is_zero()
            || timeout > Duration::from_secs(3600)
        {
            return Err(ManagedSubscriptionError::InvalidLimits);
        }
        Ok(Self { request_bytes, frame_bytes, records, timeout })
    }
}

/// Failures contain no peer error message, subscription ID, filter, or body.
/// The protocol decoder's detailed peer diagnostics are deliberately not
/// retained by this authenticated convenience API.
#[derive(Debug)]
pub enum ManagedSubscriptionError {
    InvalidLimits,
    InvalidRequest,
    UnsupportedExtension,
    RequestTooLarge,
    InvalidResponse,
    MissingTerminal,
    RecordLimit,
    Closed,
    Remote { code: JsonInteger },
    Session(OAuthSessionError),
}

impl fmt::Display for ManagedSubscriptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid managed subscription limits"),
            Self::InvalidRequest => f.write_str("invalid final core subscription request"),
            Self::UnsupportedExtension => f.write_str("managed core subscription cannot negotiate extension filters"),
            Self::RequestTooLarge => f.write_str("managed subscription request exceeds its byte limit"),
            Self::InvalidResponse => f.write_str("managed subscription response failed admission"),
            Self::MissingTerminal => f.write_str("managed subscription ended without a complete terminal result"),
            Self::RecordLimit => f.write_str("managed subscription record limit exceeded"),
            Self::Closed => f.write_str("managed subscription is closed"),
            Self::Remote { code } => write!(f, "managed subscription failed with JSON-RPC {code}"),
            Self::Session(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ManagedSubscriptionError {}

impl From<OAuthSessionError> for ManagedSubscriptionError {
    fn from(error: OAuthSessionError) -> Self { Self::Session(error) }
}

/// Incrementally delivered records. The existing native decoder enforces the
/// first acknowledgement, its requested-filter subset, subsequent event
/// categories/resource URIs, and the correlated terminal's subscription ID.
pub enum ManagedSubscriptionEvent {
    Acknowledged { accepted_filter: SubscriptionFilter },
    Notification(Box<ServerNotification>),
    Terminal {
        subscription_id: RequestId,
        result: Box<CompleteResult<FinalSubscriptionsListenResult>>,
    },
}

impl ManagedOAuthSession {
    /// Starts one explicitly selected modern core `subscriptions/listen` POST.
    /// The caller supplies a typed request with final per-request metadata.
    /// Request/profile/size checks finish before any renewal or network contact.
    /// This does not add a legacy session or perform implicit discovery.
    pub async fn subscribe_core(
        &self,
        cx: &Cx,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedSubscriptionLimits,
    ) -> Result<ManagedSubscription, ManagedSubscriptionError> {
        self.subscribe_core_with_cancellation(
            cx, &McpRequestCancellation::new(), request, request_id, limits,
        ).await
    }

    /// Retains one request-local cancellation domain through the entire listen.
    /// Cancellation closes only this POST; it never sends a cancellation
    /// notification, cancels the ambient Cx, or resubmits the request.
    pub async fn subscribe_core_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedSubscriptionLimits,
    ) -> Result<ManagedSubscription, ManagedSubscriptionError> {
        self.check(cx, cancellation)?;
        let deadline = deadline_after(cx, limits.timeout)?;
        let (wire, requested) = prepare(self.resource().as_str(), request, &request_id, limits)?;
        let response = self.await_active(cx, cancellation, deadline, None, async {
            self.execute_with_cancellation(cx, cancellation, &wire).await
        }).await?;
        ManagedSubscription::from_response(response, request_id, requested, limits, deadline)
    }
}

/// One authenticated, incremental core subscription. Renewal of the shared
/// login never extends this owner's original credential lifetime. The stream
/// is not Clone, and its raw transport cannot be extracted without the guards.
/// Drop/close releases the socket; an unpolled retained owner is released on
/// its next poll or drop, not by an unowned background task.
pub struct ManagedSubscription {
    listener: Option<ModernHttpSubscriptionListener>,
    session: ManagedOAuthSession,
    cancellation: McpRequestCancellation,
    request_id: RequestId,
    accepted_filter: Option<SubscriptionFilter>,
    expires_at: Instant,
    generation: u64,
    deadline: Time,
    limits: ManagedSubscriptionLimits,
    records: usize,
    finished: bool,
}

impl ManagedSubscription {
    fn from_response(
        response: ManagedOAuthResponse,
        request_id: RequestId,
        requested: SubscriptionFilter,
        limits: ManagedSubscriptionLimits,
        deadline: Time,
    ) -> Result<Self, ManagedSubscriptionError> {
        if response.metadata().status() != 200 || response.metadata().kind() != ModernHttpResponseKind::Sse {
            return Err(ManagedSubscriptionError::InvalidResponse);
        }
        let ManagedOAuthResponse { response, session, cancellation, expires_at, generation } = response;
        let framing = SseLimits::new(limits.frame_bytes, limits.frame_bytes, 64)
            .ok_or(ManagedSubscriptionError::InvalidLimits)?;
        let listener = response.into_final_subscriptions_listener(request_id.clone(), requested, framing)
            .map_err(admission_error)?;
        Ok(Self {
            listener: Some(listener), session, cancellation, request_id,
            accepted_filter: None, expires_at, generation, deadline, limits,
            records: 0, finished: false,
        })
    }

    pub fn request_id(&self) -> &RequestId { &self.request_id }

    /// Session-local generation, not a cross-session identity or replay cursor.
    pub fn credential_generation(&self) -> u64 { self.generation }

    pub fn accepted_filter(&self) -> Option<&SubscriptionFilter> { self.accepted_filter.as_ref() }

    /// Immediately releases this owned response without closing sibling calls.
    pub fn close(&mut self) { self.listener = None; }

    /// `None` is possible only after a complete terminal was already delivered.
    /// A polled read owns the socket until it yields a validated record. If the
    /// read is abandoned, its parser/socket are dropped and cannot be reused.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ManagedSubscriptionEvent>, ManagedSubscriptionError> {
        if self.finished { return Ok(None); }
        let mut listener = self.listener.take().ok_or(ManagedSubscriptionError::Closed)?;
        self.session.check(cx, &self.cancellation)?;
        if self.records >= self.limits.records {
            return Err(ManagedSubscriptionError::RecordLimit);
        }
        let record = self.session.await_active(
            cx, &self.cancellation, self.deadline, Some(self.expires_at), async {
                // Keep protocol failures distinct without exposing their raw
                // peer diagnostics through OAuthSessionError.
                Ok(listener.next_event(cx).await)
            },
        ).await?.map_err(admission_error)?.ok_or(ManagedSubscriptionError::MissingTerminal)?;
        let record = match record {
            ModernHttpSubscriptionListenEvent::Acknowledged { accepted_filter } => {
                ManagedSubscriptionEvent::Acknowledged { accepted_filter }
            }
            ModernHttpSubscriptionListenEvent::Notification(notification) => {
                ManagedSubscriptionEvent::Notification(Box::new(notification))
            }
            ModernHttpSubscriptionListenEvent::Terminal { subscription_id, result } => {
                ManagedSubscriptionEvent::Terminal { subscription_id, result: Box::new(result) }
            }
            #[cfg(feature = "tasks")]
            ModernHttpSubscriptionListenEvent::TaskNotification(_) => {
                return Err(ManagedSubscriptionError::UnsupportedExtension);
            }
        };
        self.session.check(cx, &self.cancellation)?;
        if Instant::now() >= self.expires_at {
            return Err(OAuthSessionError::LoginRequired.into());
        }
        if cx.now() >= self.deadline {
            return Err(OAuthSessionError::TimedOut.into());
        }
        // Publication follows the final lifetime checks. A decoded ACK that
        // loses to cancellation/expiry must not become caller-visible state.
        if let ManagedSubscriptionEvent::Acknowledged { accepted_filter } = &record {
            self.accepted_filter = Some(accepted_filter.clone());
        }
        self.records += 1;
        if matches!(record, ManagedSubscriptionEvent::Terminal { .. }) {
            self.finished = true;
        } else {
            self.listener = Some(listener);
        }
        Ok(Some(record))
    }
}

fn admission_error(error: ModernHttpSubscriptionListenError) -> ManagedSubscriptionError {
    match error {
        ModernHttpSubscriptionListenError::RemoteError { code, .. } => ManagedSubscriptionError::Remote { code },
        ModernHttpSubscriptionListenError::EndOfStream { .. } => ManagedSubscriptionError::MissingTerminal,
        ModernHttpSubscriptionListenError::CallerCancelled { .. } => OAuthSessionError::Cancelled.into(),
        ModernHttpSubscriptionListenError::Executor(error) => OAuthSessionError::Http(error).into(),
        _ => ManagedSubscriptionError::InvalidResponse,
    }
}

fn prepare(
    target: &str,
    request: CoreRequest,
    request_id: &RequestId,
    limits: ManagedSubscriptionLimits,
) -> Result<(ModernHttpRequest, SubscriptionFilter), ManagedSubscriptionError> {
    if request.era() != ProtocolEra::Modern2026 || request.method() != "subscriptions/listen" {
        return Err(ManagedSubscriptionError::InvalidRequest);
    }
    request_id.validate().map_err(|_| ManagedSubscriptionError::InvalidRequest)?;
    let params = request.encode_params().map_err(|_| ManagedSubscriptionError::InvalidRequest)?
        .ok_or(ManagedSubscriptionError::InvalidRequest)?;
    let metadata = params.get("_meta").and_then(serde_json::Value::as_object)
        .ok_or(ManagedSubscriptionError::InvalidRequest)?;
    if let Some(extensions) = metadata.get(FINAL_CLIENT_CAPABILITIES_META_KEY)
        .and_then(|capabilities| capabilities.get("extensions"))
        && !extensions.as_object().is_some_and(serde_json::Map::is_empty)
    {
        return Err(ManagedSubscriptionError::UnsupportedExtension);
    }
    let filter: SubscriptionFilter = serde_json::from_value(
        params.get("notifications").cloned().ok_or(ManagedSubscriptionError::InvalidRequest)?,
    ).map_err(|_| ManagedSubscriptionError::InvalidRequest)?;
    if !filter.additional.is_empty() {
        return Err(ManagedSubscriptionError::UnsupportedExtension);
    }
    let envelope = serde_json::json!({
        "jsonrpc": "2.0", "id": request_id, "method": "subscriptions/listen", "params": params,
    });
    let mut writer = BoundedRequest { bytes: Vec::new(), maximum: limits.request_bytes };
    serde_json::to_writer(&mut writer, &envelope).map_err(|_| ManagedSubscriptionError::RequestTooLarge)?;
    let wire = ModernHttpRequest::new(
        target, writer.bytes, FINAL_PROTOCOL_VERSION, "subscriptions/listen", None,
    ).map_err(|_| ManagedSubscriptionError::InvalidRequest)?;
    Ok((wire, filter))
}

struct BoundedRequest { bytes: Vec<u8>, maximum: usize }

impl Write for BoundedRequest {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("managed subscription request limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::json;

    fn request(notifications: serde_json::Value, extensions: serde_json::Value) -> CoreRequest {
        let mut meta = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        meta[FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"] = extensions;
        CoreRequest::decode(ProtocolEra::Modern2026, "subscriptions/listen", Some(&json!({
            "_meta": meta, "notifications": notifications,
        }))).unwrap()
    }

    #[test]
    fn prepared_subscription_preserves_correlation_metadata_and_core_filter() {
        let request = request(json!({"toolsListChanged": true}), json!({}));
        let (wire, filter) = prepare("https://mcp.example/mcp", request, &RequestId::Number(0), ManagedSubscriptionLimits::default()).unwrap();
        assert_eq!(filter.tools_list_changed, Some(true));
        assert!(filter.additional.is_empty());
        let value: serde_json::Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(value["id"], 0);
        assert_eq!(value["method"], "subscriptions/listen");
        assert_eq!(value["params"]["notifications"]["toolsListChanged"], true);
        assert!(wire.headers().iter().any(|(name, value)| name == "Mcp-Method" && value == "subscriptions/listen"));
        assert!(!wire.headers().iter().any(|(name, _)| name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("last-event-id")));
    }

    #[test]
    fn core_subscription_rejects_unnegotiated_extensions_before_dispatch() {
        for (filter, extensions) in [
            (json!({"toolsListChanged": true, "taskIds": ["private-task"]}), json!({})),
            (json!({"toolsListChanged": true}), json!({"io.modelcontextprotocol/tasks": {}})),
            (json!({"tools/list_changed": true}), json!({})),
        ] {
            assert!(matches!(prepare("https://mcp.example/mcp", request(filter, extensions), &RequestId::Number(1), ManagedSubscriptionLimits::default()), Err(ManagedSubscriptionError::UnsupportedExtension)));
        }
    }

    #[test]
    fn filter_presence_is_preserved_without_inventing_subscription_authority() {
        for filter in [json!({}), json!({"toolsListChanged": false}), json!({"resourceSubscriptions": []})] {
            let (wire, _) = prepare("https://mcp.example/mcp", request(filter.clone(), json!({})), &RequestId::Number(1), ManagedSubscriptionLimits::default()).unwrap();
            let value: serde_json::Value = serde_json::from_slice(wire.body()).unwrap();
            assert_eq!(value["params"]["notifications"], filter);
        }
    }

    #[test]
    fn subscription_request_limit_refuses_without_partial_output() {
        let mut limits = ManagedSubscriptionLimits::default();
        limits.request_bytes = 1;
        assert!(matches!(prepare("https://mcp.example/mcp", request(json!({}), json!({})), &RequestId::Number(1), limits), Err(ManagedSubscriptionError::RequestTooLarge)));
        let mut writer = BoundedRequest { bytes: b"ok".to_vec(), maximum: 2 };
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(writer.bytes, b"ok");
    }

    #[test]
    fn subscription_limits_and_errors_do_not_hide_unbounded_work_or_peer_text() {
        let second = Duration::from_secs(1);
        assert!(ManagedSubscriptionLimits::new(1024, 1024, 2, second).is_ok());
        for (request, frame, records, timeout) in [
            (0, 1024, 2, second), (1024, 0, 2, second),
            (1024, 1024, 1, second), (1024, 1024, 4097, second),
            (1024, 1024, 2, Duration::ZERO), (1024, 1024, 2, Duration::from_secs(3601)),
        ] {
            assert!(ManagedSubscriptionLimits::new(request, frame, records, timeout).is_err());
        }
        let error = admission_error(ModernHttpSubscriptionListenError::RemoteError {
            code: JsonInteger::from(-32603_i64), message: "peer-secret-canary".to_owned(),
        });
        assert!(!format!("{error:?} {error}").contains("peer-secret-canary"));
    }
}
