//! Explicit recovery of a machine-authenticated continuation's finite reply.
//!
//! This composes the existing machine request encoder, discovery admission and
//! core decoder with the configured server replay contract. A failed discovery
//! never authorizes replay. After operation dispatch can begin, interrupted I/O
//! permits only an explicit recovery decision, using the SAME access token.

use std::fmt;
use std::future::Future;

use asupersync::{Cx, Time};
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreRequest, FinalInputResponses, RequestId};
use fastmcp_protocol::protocol_policy::ProtocolEra;

use super::{
    ClientCredentialsCoreError, ClientCredentialsInteraction, ClientCredentialsInteractionError,
    ManagedCoreError, ManagedCoreEvent, ManagedInteractionError, ManagedInteractionEvent,
    Step, admit_challenge, admit_pair, input_required, preflight,
};
use super::super::super::{
    ClientCredentialsError, ClientCredentialsSnapshot, MAX_TOKEN_BYTES,
    active, admit_resource, authorize, check_token, prepare,
};
use crate::http_auth::rpc::{CoreDecoder, ManagedCoreLimits};
use crate::http_auth::rpc::interaction::recovery::{
    ContinuationRecoveryError, ContinuationReplayContract, MAX_RECOVERIES,
    admit_answer_bytes, recovery_http_interruption, recovery_request, reserve_frame,
};
use crate::http_executor::{ModernHttpExecutor, ModernHttpExecutorError, ModernHttpRequest,
    ModernHttpResponseKind, ModernHttpResponseStream};

// Each round owns both discovery and operation IDs, including failed attempts.
const MAX_REQUEST_IDS: usize = 2 + 64 * (1 + MAX_RECOVERIES) * 2;

/// Fixed recovery diagnostics. No raw native HTTP, issuer or response text is
/// retained. Discovery/authentication failure is terminal even when its cause
/// is I/O; only the operation's interrupted reply is eligible for recovery.
#[derive(Debug)]
pub enum MachineContinuationRecoveryError {
    Recovery(ContinuationRecoveryError),
    Interaction(ClientCredentialsInteractionError),
    Transport,
    Redirect { status: u16 },
}
impl fmt::Display for MachineContinuationRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recovery(error) => error.fmt(f),
            Self::Interaction(error) => error.fmt(f),
            Self::Transport => f.write_str("machine continuation exchange failed"),
            Self::Redirect { status } => write!(f, "machine continuation refused HTTP redirect {status}"),
        }
    }
}
impl std::error::Error for MachineContinuationRecoveryError {}
impl From<ContinuationRecoveryError> for MachineContinuationRecoveryError {
    fn from(error: ContinuationRecoveryError) -> Self { Self::Recovery(error) }
}
impl From<ClientCredentialsInteractionError> for MachineContinuationRecoveryError {
    fn from(error: ClientCredentialsInteractionError) -> Self { Self::Interaction(error) }
}
impl From<ClientCredentialsCoreError> for MachineContinuationRecoveryError {
    fn from(error: ClientCredentialsCoreError) -> Self { Self::Interaction(error.into()) }
}
impl From<ClientCredentialsError> for MachineContinuationRecoveryError {
    fn from(error: ClientCredentialsError) -> Self { Self::Interaction(error.into()) }
}
impl From<ManagedCoreError> for MachineContinuationRecoveryError {
    fn from(error: ManagedCoreError) -> Self { Self::Interaction(error.into()) }
}
impl From<ManagedInteractionError> for MachineContinuationRecoveryError {
    fn from(error: ManagedInteractionError) -> Self { Self::Interaction(error.into()) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { Prepared, Reading, Recoverable, Delivered, Closed }

/// One answered continuation, one original machine owner, and bounded explicit
/// recovery. Normal interactions still never replay failed requests.
///
/// Preparation sends nothing. The first send acquires a credential using the
/// ordinary Basic/private-key-JWT policy, then pins that snapshot until this
/// continuation delivers its reply. Every attempt requires fresh discovery
/// with the same token as its operation. Concurrent renewal cannot replace it;
/// expiry/revocation ends recovery rather than silently acquiring another token.
/// A successfully returned interaction resumes ordinary renewal for later rounds.
///
/// The host must configure the SAME trusted endpoint contract required by the
/// managed recovery API. This type cannot prove the remote journal is installed.
/// It never invokes an input resolver or changes answers, arguments, metadata or
/// requestState. A contract misconfiguration can repeat remote effects.
///
/// First-send/recovery IDs share the interaction's bounded history. Each attempt
/// reserves a full operation-response frame; only clean JSON delivery refunds
/// unused bytes. Discovery has its existing separate finite document limit and
/// the finite attempt count. The original deadline includes all caller pauses.
/// Dropping a polled grant/discovery future closes recovery; dropping an operation
/// send/read permits only explicit recovery. No sockets/parsers survive a dropped
/// read. Drop discards ordinary owned answers, not a durable or zeroizing store.
#[must_use = "send once, observe the reply, then explicitly decide any recovery"]
pub struct RecoverableMachineContinuation {
    interaction: ClientCredentialsInteraction,
    request: Option<CoreRequest>,
    snapshot: Option<ClientCredentialsSnapshot>,
    response: Option<ModernHttpResponseStream>,
    decoder: Option<CoreDecoder>,
    phase: Phase,
    maximum_recoveries: usize,
    attempts: usize,
    answer_count: usize,
}
impl fmt::Debug for RecoverableMachineContinuation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoverableMachineContinuation")
            .field("phase", &self.phase).field("attempts", &self.attempts).finish_non_exhaustive()
    }
}

impl ClientCredentialsInteraction {
    /// Moves only this interaction's currently admitted challenge into recovery
    /// custody. Answers are bounded and checked before a retained copy can be
    /// made. Proper subsets use the shared partial-answer validator. A state-only
    /// challenge requires absent answers; present-empty remains distinct.
    ///
    /// Local refusal consumes/drops this interaction; ordinary `resume` remains
    /// the correctable-input API. Initial requests cannot enter recovery.
    pub fn prepare_recoverable_continuation(
        mut self, cx: &Cx, responses: Option<FinalInputResponses>, contract: ContinuationReplayContract,
    ) -> Result<RecoverableMachineContinuation, MachineContinuationRecoveryError> {
        self.check(cx)?;
        let maximum_recoveries = contract.admit_endpoint(self.client.resource())?;
        let input = self.pending_input().ok_or(ManagedInteractionError::NotAwaitingInput)?;
        admit_challenge(&self.original, input, self.limits, self.continuations, self.input_responses)?;
        admit_answer_bytes(responses.as_ref(), self.limits.core().request_bytes())?;
        let answer_count = responses.as_ref().map_or(0, FinalInputResponses::len);
        let request = recovery_request(&self.original, input, responses)?;
        // These IDs measure admission only; they are never dispatched or retained.
        preflight(self.client.resource(), &request, &RequestId::Number(0), &RequestId::Number(1), self.limits.core())?;
        self.step = None;
        Ok(RecoverableMachineContinuation {
            interaction: self, request: Some(request), snapshot: None, response: None, decoder: None,
            phase: Phase::Prepared, maximum_recoveries, attempts: 0, answer_count,
        })
    }
}

impl RecoverableMachineContinuation {
    pub fn attempts(&self) -> usize { self.attempts }
    pub fn is_recovery_pending(&self) -> bool { self.phase == Phase::Recoverable }

    /// First attempt: acquire once, discover once, send at most one operation.
    pub async fn send(&mut self, cx: &Cx, discovery_id: RequestId, request_id: RequestId)
        -> Result<(), MachineContinuationRecoveryError>
    { self.attempt(cx, discovery_id, request_id, false).await }

    /// Recover under the original credential after an interrupted operation
    /// send/read. Both IDs must be fresh across discovery and operation history.
    /// This never resubmits a failed discovery or implicitly re-enters the host.
    pub async fn recover(&mut self, cx: &Cx, discovery_id: RequestId, request_id: RequestId)
        -> Result<(), MachineContinuationRecoveryError>
    { self.attempt(cx, discovery_id, request_id, true).await }

    pub fn close(&mut self) {
        self.response = None;
        self.decoder = None;
        self.snapshot = None;
        self.request = None;
        self.interaction.close();
        self.phase = Phase::Closed;
    }

    /// Delivers one method-validated complete result or successor challenge.
    /// The original response must be finite JSON, not an SSE event history.
    pub async fn next_event(&mut self, cx: &Cx)
        -> Result<ManagedInteractionEvent, MachineContinuationRecoveryError>
    {
        self.check(cx)?;
        if self.phase != Phase::Reading { return Err(ContinuationRecoveryError::WrongPhase.into()); }
        let response = self.response.take().ok_or(ContinuationRecoveryError::WrongPhase)?;
        let mut decoder = self.decoder.take().ok_or(ContinuationRecoveryError::WrongPhase)?;
        let snapshot = self.snapshot.as_ref().ok_or(ContinuationRecoveryError::WrongPhase)?;
        self.phase = Phase::Recoverable;
        let read = guarded(cx, self.interaction.deadline, &self.interaction.client.inner.closed,
            &self.interaction.cancellation, snapshot, async {
                response.read_to_end_with_cancellation(cx, &self.interaction.cancellation,
                    self.interaction.limits.core().frame_bytes()).await.map_err(operation_http_error)
            }).await;
        self.check(cx)?;
        let bytes = match read { Ok(bytes) => bytes, Err(error) => return Err(self.failed(error)) };
        let admitted = decoder.admit(&bytes, false).map_err(MachineContinuationRecoveryError::from);
        let result = match admitted {
            Ok(ManagedCoreEvent::Result(result)) => result,
            Ok(_) => { self.close(); return Err(ContinuationRecoveryError::JsonReplyRequired.into()); }
            Err(error) => return Err(self.failed(error)),
        };
        self.check(cx)?;
        (self.interaction.response_bytes, self.interaction.notifications) = decoder.usage();
        let event = if let Some(input) = input_required(&result) {
            if self.interaction.response_bytes >= self.interaction.limits.core().total_bytes() {
                self.close(); return Err(ManagedCoreError::ResponseByteLimit.into());
            }
            if let Err(error) = admit_challenge(&self.interaction.original, input, self.interaction.limits,
                self.interaction.continuations, self.interaction.input_responses)
            { self.close(); return Err(error.into()); }
            let input = Box::new(input.clone());
            self.interaction.step = Some(Step::Awaiting(input.clone()));
            ManagedInteractionEvent::InputRequired(input)
        } else {
            self.interaction.step = Some(Step::Complete);
            ManagedInteractionEvent::Complete(result)
        };
        self.check(cx)?;
        self.snapshot = None;
        self.request = None;
        self.phase = Phase::Delivered;
        Ok(event)
    }

    /// Return the same interaction after delivery, carrying its complete ID and
    /// work history. Later rounds can use normal resume or prepare new custody.
    pub fn into_interaction(self) -> Result<ClientCredentialsInteraction, MachineContinuationRecoveryError> {
        if self.phase != Phase::Delivered { return Err(ContinuationRecoveryError::WrongPhase.into()); }
        Ok(self.interaction)
    }

    async fn attempt(&mut self, cx: &Cx, discovery_id: RequestId, request_id: RequestId, recovery: bool)
        -> Result<(), MachineContinuationRecoveryError>
    {
        self.check(cx)?;
        let expected = if recovery { Phase::Recoverable } else { Phase::Prepared };
        if self.phase != expected { return Err(ContinuationRecoveryError::WrongPhase.into()); }
        if (recovery && self.attempts > self.maximum_recoveries)
            || self.interaction.used_ids.len() > MAX_REQUEST_IDS - 2
        { return Err(ContinuationRecoveryError::RecoveryLimit.into()); }
        admit_pair(&self.interaction.used_ids, &discovery_id, &request_id)?;
        let limits = self.interaction.limits.core();
        let reserved = reserve_frame(self.interaction.response_bytes, limits.frame_bytes(), limits.total_bytes())?;
        let request = self.request.as_ref().ok_or(ContinuationRecoveryError::WrongPhase)?;
        let prepared = prepared(self.interaction.client.resource(), request, &discovery_id, &request_id, limits)?;
        let mut decoder = CoreDecoder::for_request(prepared.request, request_id.clone(), limits)?;
        decoder.resume_usage(self.interaction.response_bytes, self.interaction.notifications)?;
        self.check(cx)?;
        if !recovery {
            self.interaction.continuations += 1;
            self.interaction.input_responses += self.answer_count;
        }
        self.interaction.response_bytes = reserved;
        self.interaction.used_ids.extend([discovery_id.clone(), request_id]);
        self.attempts += 1;
        // Neither an abandoned grant nor a failed/abandoned discovery may elect
        // operation replay. Only the operation dispatch boundary changes this.
        self.phase = Phase::Closed;
        let client = self.interaction.client.clone();
        let cancellation = self.interaction.cancellation.clone();
        let end = self.interaction.deadline;
        if self.snapshot.is_none() {
            let acquired = active(cx, end, &client.inner.closed, &cancellation, None,
                client.credential_with_cancellation(cx, &cancellation)).await;
            match acquired {
                Ok(snapshot) => self.snapshot = Some(snapshot),
                Err(error) => { self.close(); return Err(error.into()); }
            }
        }
        let snapshot = self.snapshot.as_ref().ok_or(ContinuationRecoveryError::WrongPhase)?;
        let discovery = discover(cx, end, &client.inner.closed, &cancellation, snapshot,
            &discovery_id, prepared.discovery, prepared.discovery_wire, limits.frame_bytes()).await;
        if let Err(error) = discovery { self.close(); return Err(error); }
        self.check(cx)?;
        let snapshot = self.snapshot.as_ref().ok_or(ContinuationRecoveryError::WrongPhase)?;
        let wire = match authorize(snapshot, prepared.wire) {
            Ok(wire) => wire,
            Err(error) => { self.close(); return Err(error.into()); }
        };
        self.phase = Phase::Recoverable;
        let response = guarded(cx, end, &client.inner.closed, &cancellation, snapshot, async {
            ModernHttpExecutor::new().execute_with_cancellation(cx, &cancellation, &wire)
                .await.map_err(operation_http_error)
        }).await;
        self.check(cx)?;
        let response = match response { Ok(response) => response, Err(error) => return Err(self.failed(error)) };
        if response.metadata().status() != 200 {
            let status = response.metadata().status();
            self.close(); return Err(ManagedCoreError::HttpStatus { status }.into());
        }
        if response.metadata().kind() != ModernHttpResponseKind::Json {
            self.close(); return Err(ContinuationRecoveryError::JsonReplyRequired.into());
        }
        self.interaction.generation = self.snapshot.as_ref().ok_or(ContinuationRecoveryError::WrongPhase)?.generation();
        self.response = Some(response);
        self.decoder = Some(decoder);
        self.phase = Phase::Reading;
        Ok(())
    }

    fn check(&mut self, cx: &Cx) -> Result<(), MachineContinuationRecoveryError> {
        if let Err(error) = self.interaction.check(cx) { self.close(); return Err(error.into()); }
        if let Some(snapshot) = &self.snapshot {
            if let Err(error) = check_token(snapshot.credential(), snapshot.expires_at()) {
                self.close(); return Err(error.into());
            }
        }
        Ok(())
    }
    fn failed(&mut self, error: MachineContinuationRecoveryError) -> MachineContinuationRecoveryError {
        if !matches!(error, MachineContinuationRecoveryError::Recovery(ContinuationRecoveryError::Interrupted)) {
            self.close();
        }
        error
    }
}

struct Prepared { wire: ModernHttpRequest, request: CoreRequest, discovery_wire: ModernHttpRequest, discovery: CoreRequest }
fn prepared(resource: &fastmcp_core::CanonicalHttpUrl, request: &CoreRequest,
    discovery_id: &RequestId, request_id: &RequestId, limits: ManagedCoreLimits,
) -> Result<Prepared, MachineContinuationRecoveryError> {
    preflight(resource, request, discovery_id, request_id, limits)?;
    let (wire, request) = prepare(resource, request, request_id)?;
    let params = request.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    let discovery = CoreRequest::decode(ProtocolEra::Modern2026, "server/discover",
        Some(&serde_json::json!({"_meta":params["_meta"]}))).map_err(|_| ManagedCoreError::InvalidRequest)?;
    let (discovery_wire, discovery) = prepare(resource, &discovery, discovery_id)?;
    Ok(Prepared { wire, request, discovery_wire, discovery })
}

#[allow(clippy::too_many_arguments)]
async fn discover(cx: &Cx, end: Time, owner: &McpRequestCancellation, cancellation: &McpRequestCancellation,
    snapshot: &ClientCredentialsSnapshot, id: &RequestId, request: CoreRequest, wire: ModernHttpRequest, frame_bytes: usize,
) -> Result<(), MachineContinuationRecoveryError> {
    guarded(cx, end, owner, cancellation, snapshot, async {
        let wire = authorize(snapshot, wire)?;
        let response = ModernHttpExecutor::new().execute_with_cancellation(cx, cancellation, &wire)
            .await.map_err(terminal_http_error)?;
        if response.metadata().status() != 200 || response.metadata().kind() != ModernHttpResponseKind::Json {
            return Err(ClientCredentialsError::Negotiation.into());
        }
        let bytes = response.read_to_end_with_cancellation(cx, cancellation, MAX_TOKEN_BYTES.min(frame_bytes))
            .await.map_err(terminal_http_error)?;
        admit_resource(&request, id, &bytes)?;
        Ok(())
    }).await
}
async fn guarded<T>(cx: &Cx, end: Time, owner: &McpRequestCancellation, cancellation: &McpRequestCancellation,
    snapshot: &ClientCredentialsSnapshot, future: impl Future<Output = Result<T, MachineContinuationRecoveryError>>,
) -> Result<T, MachineContinuationRecoveryError> {
    active(cx, end, owner, cancellation, Some(snapshot), async { Ok(future.await) }).await?
}
fn terminal_http_error(error: ModernHttpExecutorError) -> MachineContinuationRecoveryError {
    match error {
        ModernHttpExecutorError::Redirect { status } => MachineContinuationRecoveryError::Redirect { status },
        _ => MachineContinuationRecoveryError::Transport,
    }
}
fn operation_http_error(error: ModernHttpExecutorError) -> MachineContinuationRecoveryError {
    if recovery_http_interruption(&error) { ContinuationRecoveryError::Interrupted.into() }
    else { terminal_http_error(error) }
}

#[cfg(test)]
mod tests;
