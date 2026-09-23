//! Explicit recovery of one continuation reply from a configured replay journal.
//!
//! Nothing in a transport error, tool annotation, or peer advertisement grants
//! replay authority. The host must already know that this exact HTTPS endpoint
//! protects every continuation attempt with a one-use registry and reply journal.
//! Initial calls and ordinary `resume` retain their non-replay behavior.

use std::fmt;

use asupersync::Cx;
use asupersync::http::h1::{ClientError, HttpError};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::{CoreRequest, FinalInputResponses, InputRequiredResult, RequestId};

use super::{
    InputSelection, ManagedCoreCall, ManagedCoreError, ManagedCoreEvent,
    ManagedInteraction, ManagedInteractionError, ManagedInteractionEvent, Step,
    admit_challenge, admit_fresh_id, bounded_wait, continuation_request_selected,
    input_required, prepare,
};
use crate::http_auth::managed::OAuthSessionError;
use crate::http_executor::{ModernHttpExecutorError, ModernHttpResponseKind};

pub(crate) const MAX_RECOVERIES: usize = 4;
// At most 64 continuation rounds, each with its first POST and four recovery
// POSTs, plus the initial operation. The ordinary interaction keeps this same
// history after a successful hand-back, so IDs never become reusable.
const MAX_REQUEST_IDS: usize = 1 + 64 * (1 + MAX_RECOVERIES);

/// Trusted deployment configuration, NOT a server-discovered capability.
///
/// Construct only for an endpoint whose owner guarantees that every matching
/// continuation passes through the same replay journal and one-use continuation
/// registry. The journal must bind exact request parameters and current caller
/// authority, retain uncertain attempts without re-executing them, and return a
/// captured JSON reply or refuse recovery. The native server's
/// `ContinuationReplayMiddleware` supplies that contract when correctly placed
/// around native MRTR dispatch. Successor recovery additionally requires its
/// successor-enabled mode. Initial calls are never covered.
///
/// This value cannot establish that a remote deployment actually obeys those
/// rules. Misconfiguration can repeat remote effects. No wire flag or idempotent
/// annotation is accepted as a substitute. This is neither durable recovery nor
/// an exactly-once guarantee; a lost/expired journal may refuse every recovery.
#[derive(Clone)]
pub struct ContinuationReplayContract {
    resource: CanonicalHttpUrl,
    maximum_recoveries: usize,
}
impl ContinuationReplayContract {
    pub fn for_configured_endpoint(resource: CanonicalHttpUrl, maximum_recoveries: usize)
        -> Result<Self, ContinuationRecoveryError>
    {
        if !resource.as_str().starts_with("https://") || !(1..=MAX_RECOVERIES).contains(&maximum_recoveries) {
            return Err(ContinuationRecoveryError::InvalidContract);
        }
        Ok(Self { resource, maximum_recoveries })
    }

    pub(crate) fn admit_endpoint(&self, resource: &CanonicalHttpUrl) -> Result<usize, ContinuationRecoveryError> {
        if resource.as_str() != self.resource.as_str() {
            return Err(ContinuationRecoveryError::EndpointMismatch);
        }
        Ok(self.maximum_recoveries)
    }
}
impl fmt::Debug for ContinuationReplayContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContinuationReplayContract")
            .field("maximum_recoveries", &self.maximum_recoveries).finish_non_exhaustive()
    }
}

/// Local refusals and interrupted-I/O diagnostics retain no answers or state.
/// Other failures keep the existing managed interaction's error boundary.
#[derive(Debug)]
pub enum ContinuationRecoveryError {
    Interrupted,
    InvalidContract,
    EndpointMismatch,
    StateRequired,
    WrongPhase,
    RecoveryLimit,
    JsonReplyRequired,
    Interaction(ManagedInteractionError),
}
impl fmt::Display for ContinuationRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interrupted => f.write_str("continuation reply interrupted; recovery requires an explicit host decision"),
            Self::InvalidContract => f.write_str("invalid configured continuation replay contract"),
            Self::EndpointMismatch => f.write_str("continuation replay contract names another endpoint"),
            Self::StateRequired => f.write_str("reply recovery requires nonempty server continuation state"),
            Self::WrongPhase => f.write_str("continuation recovery operation is not in the required phase"),
            Self::RecoveryLimit => f.write_str("continuation reply recovery budget exhausted"),
            Self::JsonReplyRequired => f.write_str("continuation reply recovery requires a finite JSON response"),
            Self::Interaction(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for ContinuationRecoveryError {}
impl From<ManagedInteractionError> for ContinuationRecoveryError {
    fn from(error: ManagedInteractionError) -> Self { Self::Interaction(error) }
}
impl From<ManagedCoreError> for ContinuationRecoveryError {
    fn from(error: ManagedCoreError) -> Self { Self::Interaction(error.into()) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { Prepared, Reading, Recoverable, Delivered, Closed }

/// Exclusive custody of one answered continuation and its reply recovery.
///
/// No host resolver is retained or invoked. Answers, parameters and opaque state
/// are immutable after preparation. Each `send`/`recover` sends at most one POST;
/// a failure never schedules another. Recovery changes only the JSON-RPC ID.
/// Normal session renewal and authentication still run before every POST.
///
/// The original interaction deadline includes all pauses and recoveries. Each
/// attempted response reserves a full frame against its remaining byte budget;
/// a clean result refunds unused reservation, but truncated/abandoned reads do
/// not. This deliberately charges an unknown body conservatively. The entire
/// ID history and original continuation/input counters survive hand-back.
///
/// Dropping a polled send/read retires its socket and leaves this owner eligible
/// only for explicit recovery under the configured contract. Dropping this
/// owner discards all answers and closes local observation, not sibling calls
/// or remote work. Cancellation/deadline/authentication/protocol failures are
/// terminal, not recoverable. Retained answers are ordinary owned Rust values,
/// not a heap-wide zeroization or restart-persistence facility.
#[must_use = "send once, observe the reply, and explicitly decide any recovery"]
pub struct RecoverableManagedContinuation {
    interaction: ManagedInteraction,
    request: Option<CoreRequest>,
    call: Option<Box<ManagedCoreCall>>,
    phase: Phase,
    maximum_recoveries: usize,
    attempts: usize,
    answer_count: usize,
}
impl fmt::Debug for RecoverableManagedContinuation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoverableManagedContinuation")
            .field("phase", &self.phase).field("attempts", &self.attempts).finish_non_exhaustive()
    }
}

impl ManagedInteraction {
    /// Transfers the current admitted challenge into explicit reply-recovery
    /// custody. This consumes the interaction and sends nothing. Local refusal
    /// drops this consumed owner; use ordinary `resume` for correctable input.
    /// Nonempty answers may be a proper subset, using the normal partial-answer
    /// validator. State-only and present-empty distinctions are unchanged.
    ///
    /// Only this interaction's original request and pending challenge can be
    /// used: callers cannot inject a replacement target, metadata or state.
    pub fn prepare_recoverable_continuation(
        mut self, cx: &Cx, responses: Option<FinalInputResponses>, contract: ContinuationReplayContract,
    ) -> Result<RecoverableManagedContinuation, ContinuationRecoveryError> {
        self.check(cx)?;
        let maximum_recoveries = contract.admit_endpoint(self.session.resource())?;
        let input = self.pending_input().ok_or(ManagedInteractionError::NotAwaitingInput)?;
        admit_challenge(&self.original, input, self.limits, self.continuations, self.input_responses)?;
        admit_answer_bytes(responses.as_ref(), self.limits.core.request_bytes)?;
        let answer_count = responses.as_ref().map_or(0, FinalInputResponses::len);
        let request = recovery_request(&self.original, input, responses)?;
        // Check the complete retained request before handing out the owner.
        // This ID is used only for encoding admission, never dispatch/history.
        let _ = prepare(self.session.resource().as_str(), request.clone(), RequestId::Number(0), self.limits.core)?;
        self.step = None;
        Ok(RecoverableManagedContinuation {
            interaction: self, request: Some(request), call: None, phase: Phase::Prepared,
            maximum_recoveries, attempts: 0, answer_count,
        })
    }
}

impl RecoverableManagedContinuation {
    pub fn attempts(&self) -> usize { self.attempts }
    pub fn is_recovery_pending(&self) -> bool { self.phase == Phase::Recoverable }

    /// Executes the first continuation attempt. There is no automatic retry.
    pub async fn send(&mut self, cx: &Cx, request_id: RequestId) -> Result<(), ContinuationRecoveryError> {
        self.attempt(cx, request_id, false).await
    }

    /// Explicitly requests the same reply using a fresh correlation ID. Only an
    /// interrupted send/read can enter this phase. No answer/metadata/state
    /// replacement is accepted. A remote JSON-RPC error ends recovery.
    pub async fn recover(&mut self, cx: &Cx, request_id: RequestId) -> Result<(), ContinuationRecoveryError> {
        self.attempt(cx, request_id, true).await
    }

    pub fn close(&mut self) {
        self.call = None;
        self.request = None;
        self.interaction.close();
        self.phase = Phase::Closed;
    }

    /// Delivers one complete or successor input-required result. Recovery is
    /// finite-JSON-only: notification/SSE streams cannot be replayed by this API.
    /// On success the captured answers are released before publishing the event.
    pub async fn next_event(&mut self, cx: &Cx) -> Result<ManagedInteractionEvent, ContinuationRecoveryError> {
        self.check(cx)?;
        if self.phase != Phase::Reading { return Err(ContinuationRecoveryError::WrongPhase); }
        let mut call = self.call.take().ok_or(ContinuationRecoveryError::WrongPhase)?;
        // Abandonment preserves only the conservative reservation and request,
        // never a partially consumed parser or a reusable network response.
        self.phase = Phase::Recoverable;
        let outcome = call.next_event(cx).await;
        self.check(cx)?;
        let result = match outcome {
            Ok(Some(ManagedCoreEvent::Result(result))) => result,
            Ok(_) => { self.close(); return Err(ContinuationRecoveryError::JsonReplyRequired); }
            Err(error) => return Err(self.failed(error)),
        };
        // The decoder accounts the actual successful frame plus earlier work.
        self.interaction.response_bytes = call.decoder.bytes;
        self.interaction.notifications = call.decoder.notifications;
        let event = if let Some(input) = input_required(&result) {
            if self.interaction.response_bytes >= self.interaction.limits.core.total_bytes {
                self.close();
                return Err(ManagedCoreError::ResponseByteLimit.into());
            }
            if let Err(error) = admit_challenge(&self.interaction.original, input, self.interaction.limits,
                self.interaction.continuations, self.interaction.input_responses)
            {
                self.close();
                return Err(error.into());
            }
            let input = Box::new(input.clone());
            self.interaction.step = Some(Step::Awaiting(input.clone()));
            ManagedInteractionEvent::InputRequired(input)
        } else {
            self.interaction.step = Some(Step::Complete);
            ManagedInteractionEvent::Complete(result)
        };
        self.check(cx)?;
        self.request = None;
        self.phase = Phase::Delivered;
        Ok(event)
    }

    /// Returns the same original interaction after a validated reply has been
    /// delivered. Its new challenge can be resolved normally or transferred to
    /// another recoverable continuation. Never returns the old answered input.
    pub fn into_interaction(self) -> Result<ManagedInteraction, ContinuationRecoveryError> {
        if self.phase != Phase::Delivered { return Err(ContinuationRecoveryError::WrongPhase); }
        Ok(self.interaction)
    }

    async fn attempt(&mut self, cx: &Cx, request_id: RequestId, recovery: bool)
        -> Result<(), ContinuationRecoveryError>
    {
        self.check(cx)?;
        let expected = if recovery { Phase::Recoverable } else { Phase::Prepared };
        if self.phase != expected {
            return Err(ContinuationRecoveryError::WrongPhase);
        }
        if recovery && self.attempts > self.maximum_recoveries {
            return Err(ContinuationRecoveryError::RecoveryLimit);
        }
        if self.interaction.used_ids.len() >= MAX_REQUEST_IDS {
            return Err(ContinuationRecoveryError::RecoveryLimit);
        }
        admit_fresh_id(&self.interaction.used_ids, &request_id)?;
        let core = self.interaction.limits.core;
        let reserved = reserve_frame(self.interaction.response_bytes, core.frame_bytes, core.total_bytes)?;
        let request = self.request.as_ref().ok_or(ContinuationRecoveryError::WrongPhase)?.clone();
        let (wire, mut decoder) = prepare(self.interaction.session.resource().as_str(), request, request_id.clone(), core)?;
        decoder.bytes = self.interaction.response_bytes;
        decoder.notifications = self.interaction.notifications;
        self.check(cx)?;
        // Election precedes suspension, including authorization acquisition.
        // Recoveries consume attempts/bytes/IDs but never count the same host
        // answers as new inputs or advance the logical continuation round.
        if !recovery {
            self.interaction.continuations += 1;
            self.interaction.input_responses += self.answer_count;
        }
        self.interaction.response_bytes = reserved;
        self.interaction.used_ids.push(request_id);
        self.attempts += 1;
        self.phase = Phase::Recoverable;
        let response = bounded_wait(cx, &self.interaction.cancellation, self.interaction.deadline, async {
            self.interaction.session.execute_with_cancellation(cx, &self.interaction.cancellation, &wire)
                .await.map_err(ManagedCoreError::from)
        }).await;
        self.check(cx)?;
        let response = match response { Ok(response) => response, Err(error) => return Err(self.failed(error)) };
        if response.metadata().kind() != ModernHttpResponseKind::Json {
            self.close();
            return Err(ContinuationRecoveryError::JsonReplyRequired);
        }
        let call = ManagedCoreCall::from_response(response, decoder,
            self.interaction.cancellation.clone(), self.interaction.deadline);
        match call {
            Ok(call) => {
                self.interaction.generation = call.credential_generation();
                self.call = Some(Box::new(call));
                self.phase = Phase::Reading;
                Ok(())
            }
            Err(error) => Err(self.failed(error)),
        }
    }

    fn check(&mut self, cx: &Cx) -> Result<(), ContinuationRecoveryError> {
        if let Err(error) = self.interaction.check(cx) {
            self.close();
            return Err(error.into());
        }
        Ok(())
    }
    fn failed(&mut self, error: ManagedCoreError) -> ContinuationRecoveryError {
        if recoverable_transport_failure(&error) { return ContinuationRecoveryError::Interrupted; }
        self.close();
        error.into()
    }
}

pub(crate) fn recovery_request(original: &CoreRequest, input: &InputRequiredResult, responses: Option<FinalInputResponses>)
    -> Result<CoreRequest, ContinuationRecoveryError>
{
    if input.request_state().is_none_or(str::is_empty) { return Err(ContinuationRecoveryError::StateRequired); }
    let selection = if responses.as_ref().is_some_and(|answers| !answers.is_empty()) {
        InputSelection::Partial
    } else { InputSelection::Complete };
    Ok(continuation_request_selected(original, input, responses, selection)?)
}
pub(crate) fn reserve_frame(used: usize, frame: usize, total: usize) -> Result<usize, ManagedCoreError> {
    used.checked_add(frame).filter(|reserved| *reserved <= total).ok_or(ManagedCoreError::ResponseByteLimit)
}
pub(crate) fn admit_answer_bytes(responses: Option<&FinalInputResponses>, maximum: usize) -> Result<(), ManagedCoreError> {
    if let Some(responses) = responses {
        let mut encoded = super::super::BoundedWriter { bytes: Vec::new(), maximum };
        serde_json::to_writer(&mut encoded, responses).map_err(|_| ManagedCoreError::RequestTooLarge)?;
    }
    Ok(())
}
fn recoverable_transport_failure(error: &ManagedCoreError) -> bool {
    matches!(error, ManagedCoreError::MissingTerminal)
        || matches!(error, ManagedCoreError::Session(OAuthSessionError::Http(error))
            if recovery_http_interruption(error))
}
pub(crate) fn recovery_http_interruption(error: &ModernHttpExecutorError) -> bool {
    matches!(error, ModernHttpExecutorError::ResponseBodyReadFailed
        | ModernHttpExecutorError::Transport(ClientError::Io(_) | ClientError::HttpError(HttpError::Io(_)))
        | ModernHttpExecutorError::DispatchUncertain(ClientError::Io(_) | ClientError::HttpError(HttpError::Io(_))))
}

#[cfg(test)]
mod tests;
