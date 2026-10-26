//! Exact server cancellation admission for native authenticated subscriptions.
//! The response owner releases the stream after its first valid terminal.

use fastmcp_protocol::{
    FINAL_SUBSCRIPTION_ID_META_KEY, JsonRpcMessage, RequestId, ServerNotification,
    decode_strict_jsonrpc_message,
};
use serde::Deserialize;
use serde_json::Value;

use super::{DpopStreamError, ManagedCoreError};

/// Subscription cancellation requires both params.requestId and the exact
/// subscription marker to identify this listen. A Task ID or a general request
/// cancellation without subscription metadata cannot terminate its stream.
/// The shared protocol notification codec owns payload/metadata validation.
pub(super) fn admit_cancelled(
    frame: &[u8],
    id: &RequestId,
    maximum: usize,
) -> Result<(), DpopStreamError> {
    let message = decode_strict_jsonrpc_message(frame, maximum)
        .map_err(|_| ManagedCoreError::InvalidResponse)?;
    let JsonRpcMessage::Request(request) = message else {
        return Err(ManagedCoreError::UnexpectedNotification.into());
    };
    if request.id.is_some() || request.method != "notifications/cancelled" {
        return Err(ManagedCoreError::UnexpectedNotification.into());
    }
    #[derive(Deserialize)]
    struct RawNotification {
        params: Box<serde_json::value::RawValue>,
    }
    let raw: RawNotification = serde_json::from_slice(frame)
        .map_err(|_| ManagedCoreError::InvalidResponse)?;
    // Discard the typed payload immediately: reason/unknown fields are not
    // diagnostic authority and must never escape through the terminal error.
    ServerNotification::decode_with_raw_params(&request, raw.params.get())
        .map_err(|_| ManagedCoreError::UnexpectedNotification)?;
    let params = request.params.as_ref().ok_or(ManagedCoreError::InvalidResponse)?;
    let target = params.get("requestId")
        .and_then(|value| serde_json::from_value::<RequestId>(value.clone()).ok())
        .ok_or(ManagedCoreError::ResponseIdMismatch)?;
    if !target.correlates_with(id) {
        return Err(ManagedCoreError::ResponseIdMismatch.into());
    }
    check_subscription_marker(params, id)
}

fn check_subscription_marker(value: &Value, id: &RequestId) -> Result<(), DpopStreamError> {
    let marker = value.get("_meta")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get(FINAL_SUBSCRIPTION_ID_META_KEY))
        .and_then(|marker| serde_json::from_value::<RequestId>(marker.clone()).ok())
        .ok_or(ManagedCoreError::ResponseIdMismatch)?;
    if !marker.correlates_with(id) {
        return Err(ManagedCoreError::ResponseIdMismatch.into());
    }
    Ok(())
}
