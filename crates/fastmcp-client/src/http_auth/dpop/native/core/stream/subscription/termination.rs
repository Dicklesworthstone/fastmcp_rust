//! Adds peer teardown to the shared core filter decoder without changing the
//! ordinary RPC decoder or negotiating extension authority.

use fastmcp_protocol::{
    CoreResult, JsonRpcMessage, RequestId, ServerNotification, decode_strict_jsonrpc_message,
};

use super::super::{DpopStreamError, ManagedCoreError, ManagedCoreLimits, StreamDecoder, StreamEvent};
use super::super::subscription_end::{SubscriptionEnd, admit_cancelled};
use crate::http_auth::rpc::ManagedCoreEvent;
use crate::http_auth::rpc::subscription::SubscriptionDecoder;

type Terminal = Result<CoreResult, DpopStreamError>;

pub(super) struct TerminalDecoder {
    inner: SubscriptionDecoder,
    id: RequestId,
    limits: ManagedCoreLimits,
    acknowledged: bool,
    terminal: bool,
    control_bytes: usize,
    end: SubscriptionEnd,
}

impl TerminalDecoder {
    pub(super) fn new(inner: SubscriptionDecoder, id: RequestId, limits: ManagedCoreLimits) -> Self {
        Self {
            inner, id, limits, acknowledged: false, terminal: false,
            control_bytes: 0, end: SubscriptionEnd::default(),
        }
    }

    fn maximum(&self, frame: &[u8]) -> Result<usize, DpopStreamError> {
        let maximum = self.limits.frame_bytes().min(
            self.limits.total_bytes().saturating_sub(self.usage().0),
        );
        if frame.len() > maximum {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        Ok(maximum)
    }
}

impl StreamDecoder for TerminalDecoder {
    type Terminal = Terminal;

    fn admit(&mut self, frame: &[u8], allow_notification: bool)
        -> Result<StreamEvent<Terminal>, DpopStreamError>
    {
        if self.terminal { return Err(ManagedCoreError::InvalidResponse.into()); }
        let maximum = self.maximum(frame)?;
        if !allow_notification { return Err(self.inner.json_error(frame).into()); }
        let message = decode_strict_jsonrpc_message(frame, maximum)
            .map_err(|_| ManagedCoreError::InvalidResponse)?;
        if let JsonRpcMessage::Request(request) = &message
            && request.method == "notifications/cancelled"
        {
            if !self.acknowledged { return Err(ManagedCoreError::UnexpectedNotification.into()); }
            admit_cancelled(frame, &self.id, maximum)?;
            self.control_bytes += frame.len();
            self.terminal = true;
            self.end.cancel();
            return Ok(StreamEvent::Result(Err(DpopStreamError::SubscriptionCancelled)));
        }
        // All ACK subset, URI, metadata, category, exact result and notification
        // quota decisions still belong to the existing shared core codec.
        match self.inner.admit(frame)? {
            ManagedCoreEvent::Notification(notification) => {
                if matches!(&*notification, ServerNotification::SubscriptionsAcknowledged(_)) {
                    self.acknowledged = true;
                }
                Ok(StreamEvent::Notification(notification))
            }
            ManagedCoreEvent::Result(result) => {
                self.terminal = true;
                self.end.complete();
                Ok(StreamEvent::Result(Ok(*result)))
            }
        }
    }

    fn admit_terminal_tail(&mut self, frame: &[u8]) -> Result<(), DpopStreamError> {
        if !self.terminal { return Err(ManagedCoreError::InvalidResponse.into()); }
        let maximum = self.maximum(frame)?;
        self.end.admit_tail(frame, &self.id, maximum)?;
        self.control_bytes += frame.len();
        Ok(())
    }

    fn usage(&self) -> (usize, usize) {
        let (bytes, notifications) = self.inner.usage();
        // Every addition was admitted against the same finite total cap.
        (bytes + self.control_bytes, notifications)
    }
}
