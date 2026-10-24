//! First-terminal-wins admission for native authenticated subscriptions.
//!
//! The final cancellation and subscription specifications describe different
//! peer teardown signals. Accept their two orderings without turning a late
//! signal into another application outcome. This is not ordinary RPC replay
//! tolerance: nonterminal traffic, foreign IDs and malformed envelopes fail.

use fastmcp_protocol::{
    FINAL_SUBSCRIPTION_ID_META_KEY, JsonRpcMessage, RequestId, ServerNotification,
    decode_strict_jsonrpc_message, decode_strict_jsonrpc_response,
};
use serde::Deserialize;
use serde_json::Value;

use super::{DpopStreamError, ManagedCoreError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Signal {
    Complete,
    Cancelled,
}

/// Retains only the winning signal and whether its counterpart was consumed.
/// Neither peer reasons nor late result/error payloads are retained.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct SubscriptionEnd {
    first: Option<Signal>,
    paired: bool,
}

impl SubscriptionEnd {
    pub(super) fn complete(&mut self) {
        self.first = Some(Signal::Complete);
    }

    pub(super) fn cancel(&mut self) {
        self.first = Some(Signal::Cancelled);
    }

    /// Called only after a complete, admitted terminal by the stream reader.
    /// At most one complementary signal is tolerated. This never replaces the
    /// first result and cannot deliver a notification or extend an idle timer.
    /// The owner supplies the remaining cumulative frame/payload allowance and
    /// charges successful admission. A rejected tail leaves this state intact.
    pub(super) fn admit_tail(
        &mut self,
        frame: &[u8],
        id: &RequestId,
        maximum: usize,
    ) -> Result<(), DpopStreamError> {
        if self.paired {
            return Err(ManagedCoreError::InvalidResponse.into());
        }
        match self.first {
            Some(Signal::Complete) => admit_cancelled(frame, id, maximum)?,
            Some(Signal::Cancelled) => {
                // Once cancellation wins, a later response is not an
                // actionable result or error. Admit only its strict envelope
                // and exact identity; never decode it as a successor operation.
                let (response, _) = decode_strict_jsonrpc_response(frame, maximum)
                    .map_err(|_| ManagedCoreError::InvalidResponse)?.into_parts();
                if !response.id.as_ref().is_some_and(|other| other.correlates_with(id)) {
                    return Err(ManagedCoreError::ResponseIdMismatch.into());
                }
                if let Some(result) = &response.result {
                    check_subscription_marker(result, id)?;
                }
            }
            None => return Err(ManagedCoreError::InvalidResponse.into()),
        }
        self.paired = true;
        Ok(())
    }
}

/// A cancellation is correlated by params.requestId, NOT by a Task ID or the
/// optional subscription marker. Standard cancellation need not have _meta;
/// when a subscription marker is present it must independently agree.
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
    if let Some(metadata) = value.get("_meta") {
        let metadata = metadata.as_object().ok_or(ManagedCoreError::InvalidResponse)?;
        if let Some(marker) = metadata.get(FINAL_SUBSCRIPTION_ID_META_KEY) {
            let marker: RequestId = serde_json::from_value(marker.clone())
                .map_err(|_| ManagedCoreError::ResponseIdMismatch)?;
            if !marker.correlates_with(id) {
                return Err(ManagedCoreError::ResponseIdMismatch.into());
            }
        }
    }
    Ok(())
}
