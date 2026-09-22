//! Schema-bound, explicitly resumed tool interactions.
//!
//! Reuses the core interaction's immutable original request, answer correlation,
//! fresh-ID ledger, requestState custody, cumulative limits and one-attempt
//! dispatch. Only the host can resume an input-required operation. A complete
//! result must satisfy the same output contract admitted before its first POST.

use std::fmt;
use std::sync::Arc;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreRequest, FinalInputResponses, InputRequiredResult, RequestId};

use super::{ManagedToolClient, ManagedToolError, ToolContract, check_tool_call};
use crate::http_auth::rpc::{ManagedCoreError, interaction::{
    ManagedInteraction, ManagedInteractionError, ManagedInteractionEvent,
    ManagedInteractionLimits,
}};

/// Errors retain the core interaction's correctable-input distinctions without
/// retaining the challenge, submitted answer, schema, or tool output.
#[derive(Debug)]
pub enum ManagedToolInteractionError {
    Tool(ManagedToolError),
    Interaction(ManagedInteractionError),
}

impl fmt::Display for ManagedToolInteractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tool(error) => fmt::Display::fmt(error, f),
            Self::Interaction(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for ManagedToolInteractionError {}

impl From<ManagedToolError> for ManagedToolInteractionError {
    fn from(error: ManagedToolError) -> Self { Self::Tool(error) }
}

impl From<ManagedInteractionError> for ManagedToolInteractionError {
    fn from(error: ManagedInteractionError) -> Self { Self::Interaction(error) }
}

impl ManagedToolClient {
    /// Starts a schema-checked tool operation whose input-required results are
    /// answered explicitly through `resume` or `resume_partial`. Arguments are
    /// validated before credential renewal or network I/O. The original schema,
    /// tool identity, arguments and login cannot change between rounds.
    pub async fn start_interaction(
        &self,
        cx: &Cx,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedInteractionLimits,
    ) -> Result<ManagedToolInteraction, ManagedToolInteractionError> {
        self.start_interaction_with_cancellation(
            cx, &McpRequestCancellation::new(), request, request_id, limits,
        ).await
    }

    /// Retains the request-local cancellation domain while reading, awaiting
    /// host input, validating output and opening explicit continuations.
    pub async fn start_interaction_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedInteractionLimits,
    ) -> Result<ManagedToolInteraction, ManagedToolInteractionError> {
        check_tool_call(cx, cancellation, &self.contract)?;
        self.contract.validate_request(&request)?;
        check_tool_call(cx, cancellation, &self.contract)?;
        let operation = self.session.start_core_interaction_with_cancellation(
            cx, cancellation, request, request_id, limits,
        ).await?;
        check_tool_call(cx, cancellation, &self.contract)?;
        Ok(ManagedToolInteraction {
            operation: Some(operation), contract: self.contract.clone(),
            cancellation: cancellation.clone(), finished: false,
        })
    }
}

/// One schema-bound interaction. A dropped, polled read/resume future retires
/// the operation rather than making a possibly dispatched attempt reusable.
/// A locally rejected answer retains the current challenge for correction.
///
/// Contract invalidation prevents later entry/publication but cannot recall an
/// already-admitted dispatch or wake an idle socket. Use the request's retained
/// cancellation handle to interrupt waiting work. No resolver, replay, external
/// action, detached worker, or new lifetime budget is introduced here.
pub struct ManagedToolInteraction {
    operation: Option<ManagedInteraction>,
    contract: Arc<ToolContract>,
    cancellation: McpRequestCancellation,
    finished: bool,
}

impl fmt::Debug for ManagedToolInteraction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedToolInteraction")
            .field("awaiting_input", &self.pending_input().is_some())
            .field("finished", &self.finished)
            .field("closed", &self.operation.is_none())
            .finish_non_exhaustive()
    }
}

impl ManagedToolInteraction {
    /// Borrows the current challenge without authorizing any requested action.
    /// A cancelled or invalidated operation exposes no pending host work.
    pub fn pending_input(&self) -> Option<&InputRequiredResult> {
        if self.contract.check().is_err() || self.cancellation.is_cancel_requested() {
            return None;
        }
        self.operation.as_ref().and_then(ManagedInteraction::pending_input)
    }

    pub fn close(&mut self) { self.operation = None; }

    /// Delivers notifications and challenges unchanged. Complete results are
    /// checked against the retained output schema before publication. Reading
    /// while input is pending returns `InputPending`, preserving the challenge.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ManagedInteractionEvent>, ManagedToolInteractionError> {
        if self.finished { return Ok(None); }
        let mut operation = self.take_checked(cx)?;
        let next = operation.next_event(cx).await;
        check_tool_call(cx, &self.cancellation, &self.contract)?;
        let event = match next {
            Ok(Some(event)) => event,
            Ok(None) => return Err(ManagedToolError::Core(ManagedCoreError::MissingTerminal).into()),
            Err(error) => {
                // Core read admission leaves a challenge only for a local
                // InputPending refusal. Transport/decoder failures retire it.
                if matches!(&error, ManagedInteractionError::InputPending)
                    && operation.pending_input().is_some()
                {
                    self.operation = Some(operation);
                }
                return Err(error.into());
            }
        };
        let complete = admit_event(&self.contract, &event)?;
        check_tool_call(cx, &self.cancellation, &self.contract)?;
        if complete {
            self.finished = true;
        } else {
            self.operation = Some(operation);
        }
        Ok(Some(event))
    }

    /// Answers every requested input, or explicitly resumes state-only work.
    /// The core owner copies only the current challenge's exact requestState.
    /// Incorrect answers/IDs retain that challenge; dispatched work is never
    /// retried after a missing response, failed send or abandoned future.
    pub async fn resume(
        &mut self,
        cx: &Cx,
        request_id: RequestId,
        responses: Option<FinalInputResponses>,
    ) -> Result<(), ManagedToolInteractionError> {
        self.resume_selected(cx, request_id, responses, false).await
    }

    /// Submits a nonempty subset using the core interaction's partial-answer
    /// policy. A proper subset requires nonempty server-owned continuation state.
    pub async fn resume_partial(
        &mut self,
        cx: &Cx,
        request_id: RequestId,
        responses: FinalInputResponses,
    ) -> Result<(), ManagedToolInteractionError> {
        self.resume_selected(cx, request_id, Some(responses), true).await
    }

    async fn resume_selected(
        &mut self,
        cx: &Cx,
        request_id: RequestId,
        responses: Option<FinalInputResponses>,
        partial: bool,
    ) -> Result<(), ManagedToolInteractionError> {
        let mut operation = self.take_checked(cx)?;
        if operation.pending_input().is_none() {
            self.operation = Some(operation);
            return Err(ManagedInteractionError::NotAwaitingInput.into());
        }
        let outcome = if partial {
            // Only resume_partial supplies this mode, always with a map.
            let responses = responses.ok_or(ManagedInteractionError::InvalidInputResponses)?;
            operation.resume_partial(cx, request_id, responses).await
        } else {
            operation.resume(cx, request_id, responses).await
        };
        check_tool_call(cx, &self.cancellation, &self.contract)?;
        // Before dispatch, the core owner retains a challenge on local refusal.
        // After dispatch, failures erase it. Never infer retry permission from
        // an error code alone or restore an abandoned async attempt.
        if outcome.is_ok() || operation.pending_input().is_some() {
            self.operation = Some(operation);
        }
        outcome.map_err(ManagedToolInteractionError::from)
    }

    fn take_checked(&mut self, cx: &Cx) -> Result<ManagedInteraction, ManagedToolInteractionError> {
        let operation = self.operation.take().ok_or(ManagedToolError::Closed)?;
        check_tool_call(cx, &self.cancellation, &self.contract)?;
        Ok(operation)
    }
}

fn admit_event(contract: &ToolContract, event: &ManagedInteractionEvent) -> Result<bool, ManagedToolError> {
    contract.check()?;
    match event {
        ManagedInteractionEvent::Complete(result) => {
            contract.validate_result(result)?;
            Ok(true)
        }
        ManagedInteractionEvent::Notification(_) | ManagedInteractionEvent::InputRequired(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests;
