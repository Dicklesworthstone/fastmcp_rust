//! Request-owned core subscription streams over managed OAuth.
//!
//! A listen owns one authenticated POST and its response body. The first
//! notification must acknowledge a subset of the requested core filter; later
//! notifications must belong to that subscription and that accepted subset.
//! No reconnect, token-renewal replay, extension activation, or resource fetch
//! is triggered by an event. Callers explicitly decide how to recover from a
//! closed stream and how to refresh their application state.

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    CoreRequest, CoreResult, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION,
    FINAL_SUBSCRIPTION_ID_META_KEY, FinalCoreRequest, FinalCoreResult,
    FinalSubscriptionsListenParams, JsonRpcMessage, RequestId, ServerNotification,
    SubscriptionFilter, decode_strict_jsonrpc_message, decode_strict_jsonrpc_response,
};
use serde::Deserialize;
use serde_json::Value;

use super::{
    BoundedWriter, ManagedCoreError, ManagedCoreEvent, ManagedCoreLimits, bounded_wait,
    call_deadline, check_call, finish_finite_sse,
};
use crate::http_auth::managed::{ManagedOAuthSession, ManagedOAuthSseStream};
use crate::http_executor::{ModernHttpRequest, ModernHttpResponseKind};
use crate::sse::SseLimits;

/// Maximum exact resource selectors retained by one managed core subscription.
pub const MAX_MANAGED_SUBSCRIPTION_RESOURCES: usize = 256;
/// Maximum UTF-8 bytes in one resource selector. Selectors are never normalized.
pub const MAX_MANAGED_SUBSCRIPTION_RESOURCE_BYTES: usize = 16 * 1024;

impl ManagedOAuthSession {
    /// Opens a core `subscriptions/listen` stream at this session's exact HTTPS
    /// resource. The caller supplies the request ID, final metadata, explicit
    /// filter, and absolute work bounds. Unsupported extension filters and
    /// extension advertisements fail before credential renewal or network I/O.
    ///
    /// The notification limit includes the acknowledgement. The timeout covers
    /// credential acquisition, all reads, and caller time between reads; events
    /// and keepalives never reset it. There is no automatic reconnection.
    pub async fn listen_core(
        &self,
        cx: &Cx,
        params: FinalSubscriptionsListenParams,
        request_id: RequestId,
        limits: ManagedCoreLimits,
    ) -> Result<ManagedSubscription, ManagedCoreError> {
        self.listen_core_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            params,
            request_id,
            limits,
        )
        .await
    }

    /// Opens a listen with a retained request-local cancellation domain.
    /// Cancelling or dropping this stream releases its HTTP body without
    /// cancelling the session, its parent context, or a sibling request.
    pub async fn listen_core_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: FinalSubscriptionsListenParams,
        request_id: RequestId,
        limits: ManagedCoreLimits,
    ) -> Result<ManagedSubscription, ManagedCoreError> {
        let deadline = call_deadline(cx, cancellation, limits.timeout)?;
        let (wire, decoder) = prepare(self.resource().as_str(), params, request_id, limits)?;
        let response = bounded_wait(cx, cancellation, deadline, async {
            self.execute_with_cancellation(cx, cancellation, &wire)
                .await
                .map_err(ManagedCoreError::from)
        })
        .await?;
        if response.metadata().status() != 200 {
            return Err(ManagedCoreError::HttpStatus {
                status: response.metadata().status(),
            });
        }
        // A successful listen is an incremental SSE response, never a JSON
        // collector pretending that a terminal-only response opened a stream.
        if !matches!(response.metadata().kind(), ModernHttpResponseKind::Sse) {
            return Err(ManagedCoreError::InvalidResponse);
        }
        let generation = response.credential_generation();
        let sse_limits = SseLimits::with_data_lines(
            limits.frame_bytes + 16,
            limits.frame_bytes + 64,
            64,
            4096,
        )
        .ok_or(ManagedCoreError::InvalidLimits)?;
        let body = response.into_sse_stream(sse_limits)?;
        check_call(cx, cancellation, deadline)?;
        Ok(ManagedSubscription {
            body: Some(body),
            decoder,
            cancellation: cancellation.clone(),
            deadline,
            generation,
            finished: false,
        })
    }
}

/// One bounded, incremental subscription. Notifications retain their typed
/// protocol payload, including acknowledgement metadata and unknown members.
/// A graceful complete result is published only after clean HTTP body EOF.
/// EOF without that result, malformed input, or a foreign ID fails the stream.
///
/// A dropped, already-polled `next_event` future retires the stream: partial
/// framing state cannot be reused. Drop/close is local; no modern HTTP
/// cancellation notification, reconnect, or detached task is created.
pub struct ManagedSubscription {
    body: Option<ManagedOAuthSseStream>,
    decoder: SubscriptionDecoder,
    cancellation: McpRequestCancellation,
    deadline: Time,
    generation: u64,
    finished: bool,
}

impl ManagedSubscription {
    pub fn request_id(&self) -> &RequestId {
        &self.decoder.request_id
    }

    /// Session-local credential generation, not a cross-session cache key.
    pub fn credential_generation(&self) -> u64 {
        self.generation
    }

    /// The server's admitted filter, available only after acknowledgement.
    pub fn accepted_filter(&self) -> Option<&SubscriptionFilter> {
        self.decoder.accepted.as_ref()
    }

    /// Releases this response body without closing its managed OAuth session.
    pub fn close(&mut self) {
        self.body = None;
    }

    /// Delivers the acknowledgement first, then only matching core changes.
    /// The final result is followed by `None`; other premature termination is
    /// an error. A refusal releases the body and cannot advance stream state.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ManagedCoreEvent>, ManagedCoreError> {
        if self.finished {
            return Ok(None);
        }
        let mut body = self.body.take().ok_or(ManagedCoreError::Closed)?;
        check_call(cx, &self.cancellation, self.deadline)?;
        let frame = bounded_wait(cx, &self.cancellation, self.deadline, async {
            body.next_event(cx).await.map_err(ManagedCoreError::from)
        })
        .await?
        .ok_or(ManagedCoreError::MissingTerminal)?;
        let event = self.decoder.admit(frame.as_bytes())?;
        check_call(cx, &self.cancellation, self.deadline)?;
        match &event {
            ManagedCoreEvent::Result(_) => {
                finish_finite_sse(cx, &self.cancellation, self.deadline, async {
                    body.next_event(cx).await.map_err(ManagedCoreError::from)
                })
                .await?;
                check_call(cx, &self.cancellation, self.deadline)?;
                self.finished = true;
            }
            ManagedCoreEvent::Notification(_) => self.body = Some(body),
        }
        Ok(Some(event))
    }
}

fn prepare(
    target: &str,
    params: FinalSubscriptionsListenParams,
    request_id: RequestId,
    limits: ManagedCoreLimits,
) -> Result<(ModernHttpRequest, SubscriptionDecoder), ManagedCoreError> {
    if limits.notifications == 0 {
        return Err(ManagedCoreError::InvalidLimits);
    }
    validate_filter(&params.notifications)?;
    request_id.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
    let requested = params.notifications.clone();
    let request = CoreRequest::Final(FinalCoreRequest::SubscriptionsListen(params));
    let params = request.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    let metadata = params.get("_meta").and_then(Value::as_object)
        .ok_or(ManagedCoreError::InvalidRequest)?;
    if let Some(extensions) = metadata.get(FINAL_CLIENT_CAPABILITIES_META_KEY)
        .and_then(|capabilities| capabilities.get("extensions"))
        && !extensions.as_object().is_some_and(serde_json::Map::is_empty)
    {
        return Err(ManagedCoreError::UnsupportedRequest);
    }
    let envelope = serde_json::json!({
        "jsonrpc": "2.0", "id": request_id, "method": "subscriptions/listen", "params": params,
    });
    let mut encoded = BoundedWriter { bytes: Vec::new(), maximum: limits.request_bytes };
    serde_json::to_writer(&mut encoded, &envelope)
        .map_err(|_| ManagedCoreError::RequestTooLarge)?;
    let wire = ModernHttpRequest::new(
        target, encoded.bytes, FINAL_PROTOCOL_VERSION, "subscriptions/listen", None,
    )
    .map_err(|_| ManagedCoreError::InvalidRequest)?;
    Ok((wire, SubscriptionDecoder {
        request,
        request_id,
        requested,
        accepted: None,
        limits,
        bytes: 0,
        notifications: 0,
        terminal: false,
    }))
}

fn validate_filter(filter: &SubscriptionFilter) -> Result<(), ManagedCoreError> {
    // The schema remains open; this explicitly core-only client has no
    // negotiated authority to act on unknown/extension notification selectors.
    if !filter.additional.is_empty() {
        return Err(ManagedCoreError::UnsupportedRequest);
    }
    if let Some(resources) = &filter.resource_subscriptions {
        if resources.len() > MAX_MANAGED_SUBSCRIPTION_RESOURCES {
            return Err(ManagedCoreError::InvalidRequest);
        }
        let mut unique = std::collections::BTreeSet::new();
        for uri in resources {
            if uri.len() > MAX_MANAGED_SUBSCRIPTION_RESOURCE_BYTES || !unique.insert(uri) {
                return Err(ManagedCoreError::InvalidRequest);
            }
        }
    }
    Ok(())
}

fn is_subset(accepted: &SubscriptionFilter, requested: &SubscriptionFilter) -> bool {
    validate_filter(accepted).is_ok()
        && (accepted.tools_list_changed != Some(true) || requested.tools_list_changed == Some(true))
        && (accepted.resources_list_changed != Some(true) || requested.resources_list_changed == Some(true))
        && (accepted.prompts_list_changed != Some(true) || requested.prompts_list_changed == Some(true))
        && accepted.resource_subscriptions.as_ref().is_none_or(|accepted| {
            accepted.iter().all(|uri| requested.resource_subscriptions.as_ref()
                .is_some_and(|requested| requested.contains(uri)))
        })
}

struct SubscriptionDecoder {
    request: CoreRequest,
    request_id: RequestId,
    requested: SubscriptionFilter,
    accepted: Option<SubscriptionFilter>,
    limits: ManagedCoreLimits,
    bytes: usize,
    notifications: usize,
    terminal: bool,
}

impl SubscriptionDecoder {
    fn admit(&mut self, frame: &[u8]) -> Result<ManagedCoreEvent, ManagedCoreError> {
        if self.terminal {
            return Err(ManagedCoreError::InvalidResponse);
        }
        if frame.len() > self.limits.frame_bytes
            || frame.len() > self.limits.total_bytes.saturating_sub(self.bytes)
        {
            return Err(ManagedCoreError::ResponseByteLimit);
        }
        let message = decode_strict_jsonrpc_message(frame, self.limits.frame_bytes)
            .map_err(|_| ManagedCoreError::InvalidResponse)?;
        let mut accepted = None;
        let event = match message {
            JsonRpcMessage::Response(response) => {
                if !response.id.as_ref().is_some_and(|id| id.correlates_with(&self.request_id)) {
                    return Err(ManagedCoreError::ResponseIdMismatch);
                }
                if let Some(error) = response.error {
                    return Err(ManagedCoreError::Remote { code: error.code });
                }
                if self.accepted.is_none() {
                    return Err(ManagedCoreError::UnexpectedNotification);
                }
                let (response, source) = decode_strict_jsonrpc_response(frame, self.limits.frame_bytes)
                    .map_err(|_| ManagedCoreError::InvalidResponse)?.into_parts();
                let source = source.ok_or(ManagedCoreError::InvalidResult)?;
                let result = self.request.decode_response_result(&response, &source)
                    .map_err(|_| ManagedCoreError::InvalidResult)?;
                if !matches!(&result, CoreResult::Final(FinalCoreResult::SubscriptionsListen { .. })) {
                    return Err(ManagedCoreError::InvalidResult);
                }
                ManagedCoreEvent::Result(Box::new(result))
            }
            JsonRpcMessage::Request(request) => {
                if request.id.is_some() {
                    return Err(ManagedCoreError::UnexpectedNotification);
                }
                if self.notifications >= self.limits.notifications {
                    return Err(ManagedCoreError::NotificationLimit);
                }
                let subscription_id = request.params.as_ref()
                    .and_then(|params| params.get("_meta"))
                    .and_then(|meta| meta.get(FINAL_SUBSCRIPTION_ID_META_KEY))
                    .and_then(|id| serde_json::from_value::<RequestId>(id.clone()).ok())
                    .ok_or(ManagedCoreError::ResponseIdMismatch)?;
                if !subscription_id.correlates_with(&self.request_id) {
                    return Err(ManagedCoreError::ResponseIdMismatch);
                }
                #[derive(Deserialize)]
                struct RawNotification {
                    params: Box<serde_json::value::RawValue>,
                }
                let raw: RawNotification = serde_json::from_slice(frame)
                    .map_err(|_| ManagedCoreError::InvalidResponse)?;
                let notification = ServerNotification::decode_with_raw_params(&request, raw.params.get())
                    .map_err(|_| ManagedCoreError::UnexpectedNotification)?;
                if let ServerNotification::SubscriptionsAcknowledged(acknowledgement) = &notification {
                    if self.accepted.is_some() || !is_subset(&acknowledgement.notifications, &self.requested) {
                        return Err(ManagedCoreError::UnexpectedNotification);
                    }
                    accepted = Some(acknowledgement.notifications.clone());
                } else {
                    let filter = self.accepted.as_ref().ok_or(ManagedCoreError::UnexpectedNotification)?;
                    let selected = match request.method.as_str() {
                        "notifications/tools/list_changed" => filter.tools_list_changed == Some(true),
                        "notifications/resources/list_changed" => filter.resources_list_changed == Some(true),
                        "notifications/prompts/list_changed" => filter.prompts_list_changed == Some(true),
                        "notifications/resources/updated" => request.params.as_ref()
                            .and_then(|params| params.get("uri")).and_then(Value::as_str)
                            .is_some_and(|uri| filter.resource_subscriptions.as_ref()
                                .is_some_and(|resources| resources.iter().any(|resource| resource == uri))),
                        _ => false,
                    };
                    if !selected {
                        return Err(ManagedCoreError::UnexpectedNotification);
                    }
                }
                ManagedCoreEvent::Notification(Box::new(notification))
            }
        };
        // Commit acknowledgement and accounting together, only after every
        // structural, correlation, filter and work-budget check succeeded.
        if let Some(accepted) = accepted {
            self.accepted = Some(accepted);
        }
        match &event {
            ManagedCoreEvent::Notification(_) => self.notifications += 1,
            ManagedCoreEvent::Result(_) => self.terminal = true,
        }
        self.bytes += frame.len();
        Ok(event)
    }
}

#[cfg(test)]
mod tests;
