//! Multi-round tools after an explicitly approved, pre-dispatch header repair.
//!
//! One unread initial response is transferred to the existing MRTR owner. The
//! same owner handles notifications, full/partial input, state-only rounds and
//! host-driven resolution. No response is replayed, no second state machine is
//! introduced, and no resolver is invoked by the repair itself.
//!
//! These are core transport APIs, not schema-bound tool clients. They preserve
//! the transport's null-omission rule and do not add full input/output schema
//! validation. The host must approve the definition and every requested effect.
//! A header-rejection contract never supplies continuation-journal authority.

use std::fmt;
use std::sync::Arc;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::http_headers::ParameterHeaderBinding;
use fastmcp_protocol::{CoreRequest, FinalTool, RequestId};

use super::{
    ManagedCatalogError, ManagedOAuthSession, RejectedToolHeaders,
    ReviewedToolHeaders, ToolHeaderRepairContract, ToolHeaderRepairError,
    ToolHeaderRepairLimits, ToolHeaderRepairOutcome,
};
use crate::http_auth::rpc::interaction::{
    ManagedInteraction, ManagedInteractionError, ManagedInteractionLimits,
};

/// One configuration fixed before the first POST. The repair's core bounds are
/// also the interaction's bounds: a refresh never starts a new response budget
/// or timeout. Round/input limits count only actual continuations, not catalog
/// pages or the single pre-dispatch-rejected attempt.
#[derive(Clone, Copy, Debug)]
pub struct ToolHeaderInteractionLimits {
    repair: ToolHeaderRepairLimits,
    maximum_continuations: usize,
    maximum_input_responses: usize,
}

impl Default for ToolHeaderInteractionLimits {
    fn default() -> Self {
        Self { repair: ToolHeaderRepairLimits::default(),
            maximum_continuations: 8, maximum_input_responses: 256 }
    }
}

impl ToolHeaderInteractionLimits {
    /// Retains the repair's transport policy and validates the existing MRTR
    /// hard bounds before any credential acquisition or initial request.
    pub fn new(
        repair: ToolHeaderRepairLimits,
        maximum_continuations: usize,
        maximum_input_responses: usize,
    ) -> Result<Self, ManagedInteractionError> {
        ManagedInteractionLimits::new(repair.core, maximum_continuations, maximum_input_responses)?;
        Ok(Self { repair, maximum_continuations, maximum_input_responses })
    }
}

/// Existing sanitized boundaries are retained; no request or peer payloads are
/// copied into errors. A repair error cannot be mistaken for a pending input.
#[derive(Debug)]
pub enum ToolHeaderInteractionError {
    Repair(ToolHeaderRepairError),
    Interaction(ManagedInteractionError),
}
impl fmt::Display for ToolHeaderInteractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Repair(error) => fmt::Display::fmt(error, f),
            Self::Interaction(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ToolHeaderInteractionError {}
impl From<ToolHeaderRepairError> for ToolHeaderInteractionError {
    fn from(error: ToolHeaderRepairError) -> Self { Self::Repair(error) }
}
impl From<ManagedInteractionError> for ToolHeaderInteractionError {
    fn from(error: ManagedInteractionError) -> Self { Self::Interaction(error) }
}

/// Success owns the unread response inside an ordinary interaction. Rejection
/// carries a single-use repair decision, never a synthetic input-required event.
#[must_use = "drive the interaction or explicitly decide whether to repair the rejection"]
pub enum ToolHeaderInteractionOutcome {
    Interaction(Box<ManagedInteraction>),
    Rejected(Box<RejectedToolHeaderInteraction>),
}

/// Non-Clone ownership of the same original request, rejection, cancellation
/// domain, lifetime and limits. Dropping it sends no catalog or tool request.
/// No external core call can be injected or rebound to a different session.
pub struct RejectedToolHeaderInteraction {
    rejected: RejectedToolHeaders,
    limits: ToolHeaderInteractionLimits,
}
impl fmt::Debug for RejectedToolHeaderInteraction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RejectedToolHeaderInteraction").finish_non_exhaustive()
    }
}

impl ManagedOAuthSession {
    /// Opens a core tool interaction with one explicit initial-header repair
    /// opportunity. Complete responses, notifications and input challenges all
    /// use the normal interaction API after this initial ownership transfer.
    /// No network failure qualifies for header repair and no input is resolved
    /// automatically. Use the explicit cancellation variant to abort host pauses.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_tool_interaction_with_header_repair(
        &self, cx: &Cx, request: CoreRequest, request_id: RequestId,
        reviewed: Arc<ReviewedToolHeaders>, endpoint: ToolHeaderRepairContract,
        limits: ToolHeaderInteractionLimits,
    ) -> Result<ToolHeaderInteractionOutcome, ToolHeaderInteractionError> {
        Box::pin(self.start_tool_interaction_with_header_repair_and_cancellation(
            cx, &McpRequestCancellation::new(), request, request_id, reviewed, endpoint, limits,
        )).await
    }

    /// Retains request-local cancellation across rejection, host approval,
    /// refresh, successful response and every continuation. Shared OAuth state
    /// and siblings are not deliberately cancelled by this operation.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_tool_interaction_with_header_repair_and_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        request: CoreRequest, request_id: RequestId, reviewed: Arc<ReviewedToolHeaders>,
        endpoint: ToolHeaderRepairContract, limits: ToolHeaderInteractionLimits,
    ) -> Result<ToolHeaderInteractionOutcome, ToolHeaderInteractionError> {
        let outcome = Box::pin(self.request_tool_with_header_repair_and_cancellation(
            cx, cancellation, request, request_id, &reviewed, endpoint, limits.repair,
        )).await?;
        Ok(match outcome {
            ToolHeaderRepairOutcome::Call(call) => ToolHeaderInteractionOutcome::Interaction(Box::new(
                ManagedInteraction::from_initial_header_call(cx, self.clone(), call, reviewed,
                    limits.maximum_continuations, limits.maximum_input_responses)?,
            )),
            ToolHeaderRepairOutcome::Rejected(rejected) => ToolHeaderInteractionOutcome::Rejected(Box::new(
                RejectedToolHeaderInteraction { rejected, limits },
            )),
        })
    }
}

impl RejectedToolHeaderInteraction {
    /// Explicitly refreshes and retries once, then hands the unread response to
    /// the normal interaction. The refreshed plan is retained for all future
    /// continuations. The rejected request, every catalog ID and the retry ID
    /// remain reserved, including for later explicitly configured journal reads.
    ///
    /// This consumes repair permission. A second rejection or uncertain retry
    /// cannot create another repair owner. No host resolver runs here; call
    /// `next_event`, `resume`, `resume_partial`, `drive` or `drive_partial` on the
    /// returned interaction. Its deadline and conservative catalog-byte charge
    /// are inherited rather than reset. Correctable input errors retain their
    /// challenge exactly as on an interaction opened without repair.
    pub async fn refresh_and_start<I, A, R>(
        self, cx: &Cx, next_id: I, approve: A, review: R,
    ) -> Result<ManagedInteraction, ToolHeaderInteractionError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        A: FnOnce(&FinalTool) -> bool,
        R: FnMut(&ParameterHeaderBinding) -> bool,
    {
        Ok(Box::pin(self.rejected.refresh_and_start_interaction(cx,
            self.limits.maximum_continuations, self.limits.maximum_input_responses,
            next_id, approve, review,
        )).await?)
    }
}

#[cfg(test)]
mod tests;
