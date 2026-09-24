//! Caller-owned machine tool submission with explicit, bounded core input.
//!
//! An owner exists before acquisition or dispatch. Once a tool POST may have
//! started, interruption is DeliveryUnknown, never permission to repeat it.
//! Continuations echo only the current admitted challenge under the opening
//! credential. No automatic resolver, renewal, polling or mutation retry runs.

/// Initial checkpoint persistence after explicit core-input continuations.
pub mod persisted;

use std::fmt;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreRequest, FinalCoreResult, FinalInputResponses, InputRequiredResult, RequestId};
use serde_json::{Value, json};

use super::{
    BoundedBody, ClientCredentialsError, ClientCredentialsSnapshot, ClientCredentialsTaskCall,
    ClientCredentialsTasksClient, ClientCredentialsTasksError, Decoder, ManagedTaskEvent,
    ManagedTaskRequest, ManagedTasksError, ModernHttpExecutor, ModernHttpExecutorError,
    ModernHttpRequest, ModernHttpResponseKind, Prepared, active, admit_composition,
    authorize, discovery_deadline, encode, prepare, require_success,
};
use super::super::{OAuthDiscoveryError, check_context, check_token};
use crate::http_auth::rpc::ManagedCoreLimits;
use crate::http_auth::rpc::interaction::{
    InputSelection, ManagedInteractionError, ManagedInteractionLimits, admit_challenge,
    admit_fresh_id, continuation_request_selected, validate_initial,
};
pub use crate::http_auth::managed::tasks::interaction::ManagedTaskInteractionEvent as ClientCredentialsTaskSubmissionEvent;
pub use crate::http_auth::managed::tasks::interaction::submission::TaskSubmissionState;

// At most 130 retained IDs (two for each of 65 rounds). Bound the complete
// encoded identity before cloning it; JSON escaping cannot evade the ceiling.
// This is the protocol's own string-id bound: `RequestId::validate` refuses
// anything longer first, so a larger local ceiling could never be reached.
const MAX_ID_WIRE_BYTES: usize = fastmcp_protocol::MAX_JSONRPC_STRING_ID_ENCODED_BYTES;

/// Cumulative authority for one initial call and all explicit continuations.
/// The client's timeout is ONE deadline, including acquisition and host pauses.
/// Its request/frame/stream bounds still apply independently to every round.
#[derive(Clone, Copy, Debug)]
pub struct ClientCredentialsTaskSubmissionPolicy {
    input: ManagedInteractionLimits,
    maximum_records: usize,
}
impl Default for ClientCredentialsTaskSubmissionPolicy {
    fn default() -> Self {
        Self { input: ManagedInteractionLimits::default(), maximum_records: 256 }
    }
}
impl ClientCredentialsTaskSubmissionPolicy {
    /// Zero continuations accepts only immediate ordinary or Task results.
    /// State-only rounds may use a zero input-response budget. No count resets
    /// when discovery is repeated, a host pauses, or a new response is opened.
    pub fn new(maximum_continuations: usize, maximum_input_responses: usize, maximum_records: usize)
        -> Result<Self, ClientCredentialsTaskSubmissionCause>
    {
        if !(1..=1024).contains(&maximum_records) {
            return Err(ClientCredentialsTaskSubmissionCause::InvalidPolicy);
        }
        let input = ManagedInteractionLimits::new(ManagedCoreLimits::default(),
            maximum_continuations, maximum_input_responses)?;
        Ok(Self { input, maximum_records })
    }
}

/// Fixed diagnostics; raw peer errors, arguments, opaque state and answers are
/// not formatted or retained by the submission's errors.
#[derive(Debug)]
pub enum ClientCredentialsTaskSubmissionCause {
    InvalidPolicy,
    RecordLimit,
    Input(ManagedInteractionError),
    Task(ClientCredentialsTasksError),
}
impl fmt::Display for ClientCredentialsTaskSubmissionCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => f.write_str("invalid machine Task submission policy"),
            Self::RecordLimit => f.write_str("machine Task submission record budget exhausted"),
            Self::Input(error) => error.fmt(f),
            Self::Task(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for ClientCredentialsTaskSubmissionCause {}
impl From<ManagedInteractionError> for ClientCredentialsTaskSubmissionCause {
    fn from(error: ManagedInteractionError) -> Self { Self::Input(error) }
}
impl From<ClientCredentialsTasksError> for ClientCredentialsTaskSubmissionCause {
    fn from(error: ClientCredentialsTasksError) -> Self { Self::Task(error) }
}
impl From<ManagedTasksError> for ClientCredentialsTaskSubmissionCause {
    fn from(error: ManagedTasksError) -> Self { Self::Task(error.into()) }
}
impl From<ClientCredentialsError> for ClientCredentialsTaskSubmissionCause {
    fn from(error: ClientCredentialsError) -> Self { Self::Task(error.into()) }
}

pub enum ClientCredentialsTaskSubmissionError {
    InvalidState,
    InputPending,
    NotDispatched(Box<ClientCredentialsTaskSubmissionCause>),
    /// The tool executor was entered; this is not proof that bytes were sent,
    /// that no Task exists, or that a completed effect was rolled back.
    TaskCreationDeliveryUnknown(Box<ClientCredentialsTaskSubmissionCause>),
}
impl ClientCredentialsTaskSubmissionError {
    pub fn cause(&self) -> Option<&ClientCredentialsTaskSubmissionCause> {
        match self {
            Self::NotDispatched(cause) | Self::TaskCreationDeliveryUnknown(cause) => Some(cause),
            Self::InvalidState | Self::InputPending => None,
        }
    }
}
impl fmt::Display for ClientCredentialsTaskSubmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidState => "machine Task submission is not in the required phase",
            Self::InputPending => "machine Task submission requires explicit host input",
            Self::NotDispatched(_) => "machine tool attempt stopped before dispatch",
            Self::TaskCreationDeliveryUnknown(_) =>
                "machine Task creation delivery is unknown; do not repeat the tool attempt",
        })
    }
}
impl fmt::Debug for ClientCredentialsTaskSubmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(self, f) }
}
impl std::error::Error for ClientCredentialsTaskSubmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause().map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}
fn not_dispatched(error: impl Into<ClientCredentialsTaskSubmissionCause>) -> ClientCredentialsTaskSubmissionError {
    ClientCredentialsTaskSubmissionError::NotDispatched(Box::new(error.into()))
}

struct Round {
    ids: (RequestId, RequestId),
    operation: Prepared,
    discovery: CoreRequest,
    discovery_wire: ModernHttpRequest,
}
struct Progress {
    original: CoreRequest,
    pending: Option<Box<InputRequiredResult>>,
    used_ids: Vec<RequestId>,
    continuations: usize,
    responses: usize,
    records: usize,
    policy: ClientCredentialsTaskSubmissionPolicy,
}
impl Progress {
    fn remaining_records(&self) -> usize { self.policy.maximum_records.saturating_sub(self.records) }

    fn admit(&mut self, event: ManagedTaskEvent) -> Result<ClientCredentialsTaskSubmissionEvent, ClientCredentialsTaskSubmissionCause> {
        if self.remaining_records() == 0 { return Err(ClientCredentialsTaskSubmissionCause::RecordLimit); }
        self.records += 1;
        match event {
            ManagedTaskEvent::Notification(notification) => Ok(ClientCredentialsTaskSubmissionEvent::Notification(notification)),
            ManagedTaskEvent::ToolResult(result) => match result.as_ref() {
                FinalCoreResult::ToolsCallInputRequired { result: input, .. } => {
                    let input: &InputRequiredResult = input;
                    if self.remaining_records() == 0 { return Err(ClientCredentialsTaskSubmissionCause::RecordLimit); }
                    admit_challenge(&self.original, input, self.policy.input, self.continuations, self.responses)?;
                    let input = Box::new(input.clone());
                    self.pending = Some(input.clone());
                    Ok(ClientCredentialsTaskSubmissionEvent::InputRequired(input))
                }
                FinalCoreResult::ToolsCall { .. } | FinalCoreResult::ToolsCallTask { .. } =>
                    Ok(ClientCredentialsTaskSubmissionEvent::Result(result)),
                _ => Err(ManagedTasksError::InvalidResponse.into()),
            },
            _ => Err(ManagedTasksError::InvalidResponse.into()),
        }
    }

    fn prepare_resume(&self, client: &ClientCredentialsTasksClient, ids: (RequestId, RequestId),
        responses: Option<FinalInputResponses>, selection: InputSelection,
    ) -> Result<(Round, usize), ClientCredentialsTaskSubmissionCause> {
        let input = self.pending.as_ref().ok_or(ManagedInteractionError::NotAwaitingInput)?;
        if self.remaining_records() == 0 { return Err(ClientCredentialsTaskSubmissionCause::RecordLimit); }
        admit_pair(&ids)?;
        admit_fresh_id(&self.used_ids, &ids.0)?;
        admit_fresh_id(&self.used_ids, &ids.1)?;
        admit_challenge(&self.original, input, self.policy.input, self.continuations, self.responses)?;
        let count = responses.as_ref().map_or(0, FinalInputResponses::len);
        // The shared validator preserves absent/empty distinctions and requires
        // nonempty server state for a proper subset. No old answers accumulate.
        let next = continuation_request_selected(&self.original, input, responses, selection)?;
        let params = next.encode_params().map_err(|_| ManagedTasksError::InvalidRequest)?
            .ok_or(ManagedTasksError::InvalidRequest)?;
        let name = params.get("name").and_then(Value::as_str).ok_or(ManagedTasksError::InvalidRequest)?.to_owned();
        let progress = params["_meta"].get("progressToken").map(|value|
            serde_json::from_value(value.clone()).map_err(|_| ManagedTasksError::InvalidRequest)).transpose()?;
        let wire = encode(client.client.resource().as_str(), "tools/call", &ids.1, params, Some(name), client.limits.request_bytes)?;
        let operation = Prepared { wire, decoder: Decoder::Tool(Box::new(next)), progress };
        Ok((prepare_round(client, ids, operation)?, count))
    }

    fn commit_resume(&mut self, ids: &(RequestId, RequestId), count: usize) {
        self.pending = None;
        self.used_ids.extend([ids.0.clone(), ids.1.clone()]);
        self.continuations += 1;
        self.responses += count;
    }
}

/// Non-Clone custody from local preparation until an ordinary or actual Task
/// result is delivered. InputRequired remains an explicitly resumable challenge.
/// Request IDs are correlation only, not application idempotency keys.
///
/// A polled send/resume consumes its attempt before suspension. A polled read
/// takes its socket before suspension and marks delivery unknown. Abandonment
/// can never restore send permission. Unpolled futures have no effects. close
/// releases arguments, answers and sockets without cancelling a remote Task.
///
/// One original deadline and opening credential cover every round and host
/// pause. Fresh discovery precedes EVERY tool POST, but never renews credentials.
/// This owner does not persist a Task ID or claim restart/exactly-once execution;
/// after a Task result, explicitly use the checkpoint and Task-watch APIs.
#[must_use = "retain submission custody through the final result or uncertain delivery"]
pub struct ClientCredentialsTaskSubmission {
    client: ClientCredentialsTasksClient,
    prepared: Option<Round>,
    progress: Option<Progress>,
    credential: Option<ClientCredentialsSnapshot>,
    call: Option<ClientCredentialsTaskCall>,
    cancellation: McpRequestCancellation,
    deadline: Option<Time>,
    request_id: RequestId,
    state: TaskSubmissionState,
}
impl fmt::Debug for ClientCredentialsTaskSubmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCredentialsTaskSubmission").field("state", &self.state).finish_non_exhaustive()
    }
}
impl ClientCredentialsTasksClient {
    /// Prepare both bounded wire documents locally, before credential or network
    /// effects. No Task preference, continuation or idempotency token is injected.
    /// Original tool arguments and the composed capability metadata are preserved.
    pub fn prepare_tool_submission(&self, discovery_id: RequestId, request_id: RequestId,
        name: String, arguments: Option<Value>, policy: ClientCredentialsTaskSubmissionPolicy,
    ) -> Result<ClientCredentialsTaskSubmission, ClientCredentialsTaskSubmissionError> {
        let ids = (discovery_id, request_id);
        admit_pair(&ids).map_err(not_dispatched)?;
        let operation = prepare(self.client.resource().as_str(), &self.metadata, &ids.1,
            ManagedTaskRequest::CallTool { name, arguments }, self.limits).map_err(not_dispatched)?;
        let Decoder::Tool(original) = &operation.decoder else { return Err(not_dispatched(ManagedTasksError::InvalidRequest)); };
        validate_initial(original).map_err(not_dispatched)?;
        let progress = Progress { original: (**original).clone(), pending: None,
            used_ids: vec![ids.0.clone(), ids.1.clone()], continuations: 0, responses: 0, records: 0, policy };
        let request_id = ids.1.clone();
        let round = prepare_round(self, ids, operation).map_err(not_dispatched)?;
        Ok(ClientCredentialsTaskSubmission {
            client: self.clone(), prepared: Some(round), progress: Some(progress), credential: None,
            call: None, cancellation: McpRequestCancellation::new(), deadline: None,
            request_id, state: TaskSubmissionState::Prepared,
        })
    }
}
impl ClientCredentialsTaskSubmission {
    pub fn state(&self) -> TaskSubmissionState { self.state }
    pub fn request_id(&self) -> &RequestId { &self.request_id }
    pub fn pending_input(&self) -> Option<&InputRequiredResult> {
        if self.state != TaskSubmissionState::AwaitingInput { return None; }
        self.progress.as_ref().and_then(|progress| progress.pending.as_deref())
    }
    pub fn close(&mut self) {
        self.prepared = None;
        self.progress = None;
        self.credential = None;
        self.call = None;
        self.state = closed_state(self.state);
    }
    pub async fn send(&mut self, cx: &Cx) -> Result<(), ClientCredentialsTaskSubmissionError> {
        self.send_with_cancellation(cx, &McpRequestCancellation::new()).await
    }
    pub async fn send_with_cancellation(&mut self, cx: &Cx, cancellation: &McpRequestCancellation)
        -> Result<(), ClientCredentialsTaskSubmissionError> {
        if self.state != TaskSubmissionState::Prepared { return Err(self.phase_error()); }
        let round = self.prepared.take().ok_or(ClientCredentialsTaskSubmissionError::InvalidState)?;
        self.state = TaskSubmissionState::NotDispatched;
        self.cancellation = cancellation.clone();
        let result = async {
            let deadline = discovery_deadline(cx, self.client.limits.timeout.min(self.client.client.inner.timeout))
                .map_err(ClientCredentialsError::from)?;
            self.deadline = Some(deadline);
            let credential = active(cx, deadline, &self.client.client.inner.closed, cancellation, None, async {
                self.client.client.credential_with_cancellation(cx, cancellation).await
            }).await?;
            let remaining = self.progress.as_ref().ok_or(ManagedTasksError::Closed)?.remaining_records();
            let call = dispatch(&mut self.state, cx, &self.client, cancellation, deadline, &credential, round, remaining).await?;
            Ok::<_, ClientCredentialsTaskSubmissionCause>((call, credential))
        }.await;
        self.accept_dispatch(result)
    }

    pub async fn next_event(&mut self, cx: &Cx)
        -> Result<Option<ClientCredentialsTaskSubmissionEvent>, ClientCredentialsTaskSubmissionError> {
        if self.state == TaskSubmissionState::Resolved { return Ok(None); }
        if self.state == TaskSubmissionState::AwaitingInput {
            if let Err(error) = self.check(cx) { self.close(); return Err(not_dispatched(error)); }
            return Err(ClientCredentialsTaskSubmissionError::InputPending);
        }
        if self.state != TaskSubmissionState::AwaitingResponse { return Err(self.phase_error()); }
        let mut call = self.call.take().ok_or(ClientCredentialsTaskSubmissionError::InvalidState)?;
        self.state = TaskSubmissionState::DeliveryUnknown;
        let admitted: Result<_, ClientCredentialsTaskSubmissionCause> = match call.next_event(cx).await {
            Ok(Some(event)) => self.progress.as_mut().ok_or_else(|| ClientCredentialsTaskSubmissionCause::from(ManagedTasksError::Closed))
                .and_then(|progress| progress.admit(event)),
            Ok(None) => Err(ManagedTasksError::MissingTerminal.into()),
            Err(error) => Err(error.into()),
        };
        // Capability/continuation admission can itself do bounded CPU work.
        // Recheck the original authority before publishing its outcome.
        let admitted = admitted.and_then(|event| { self.check(cx)?; Ok(event) });
        match admitted {
            Ok(event) => {
                match &event {
                    ClientCredentialsTaskSubmissionEvent::Notification(_) => {
                        self.call = Some(call);
                        self.state = TaskSubmissionState::AwaitingResponse;
                    }
                    ClientCredentialsTaskSubmissionEvent::InputRequired(_) => self.state = TaskSubmissionState::AwaitingInput,
                    ClientCredentialsTaskSubmissionEvent::Result(_) => {
                        self.state = TaskSubmissionState::Resolved;
                        self.progress = None;
                        self.credential = None;
                    }
                }
                Ok(Some(event))
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    /// Submit complete correlated answers (or None for a state-only challenge).
    /// Invalid local answers/IDs leave the challenge correctable. Once a valid
    /// continuation is consumed, discovery failure still cannot restore it.
    pub async fn resume(&mut self, cx: &Cx, discovery_id: RequestId, request_id: RequestId,
        responses: Option<FinalInputResponses>,
    ) -> Result<(), ClientCredentialsTaskSubmissionError> {
        self.resume_selected(cx, (discovery_id, request_id), responses, InputSelection::Complete).await
    }
    /// Proper subsets require nonempty server-owned state. Never synthesizes a
    /// declined answer, merges previous answers, or trims opaque continuation data.
    pub async fn resume_partial(&mut self, cx: &Cx, discovery_id: RequestId, request_id: RequestId,
        responses: FinalInputResponses,
    ) -> Result<(), ClientCredentialsTaskSubmissionError> {
        self.resume_selected(cx, (discovery_id, request_id), Some(responses), InputSelection::Partial).await
    }
    async fn resume_selected(&mut self, cx: &Cx, ids: (RequestId, RequestId),
        responses: Option<FinalInputResponses>, selection: InputSelection,
    ) -> Result<(), ClientCredentialsTaskSubmissionError> {
        if self.state != TaskSubmissionState::AwaitingInput { return Err(self.phase_error()); }
        if let Err(error) = self.check(cx) { self.close(); return Err(not_dispatched(error)); }
        let progress = self.progress.as_mut().ok_or(ClientCredentialsTaskSubmissionError::InvalidState)?;
        let (round, count) = progress.prepare_resume(&self.client, ids, responses, selection).map_err(not_dispatched)?;
        progress.commit_resume(&round.ids, count);
        let remaining = progress.remaining_records();
        self.request_id = round.ids.1.clone();
        self.state = TaskSubmissionState::NotDispatched;
        let credential = self.credential.take().ok_or(ClientCredentialsTaskSubmissionError::InvalidState)?;
        let deadline = self.deadline.ok_or(ClientCredentialsTaskSubmissionError::InvalidState)?;
        let result = dispatch(&mut self.state, cx, &self.client, &self.cancellation,
            deadline, &credential, round, remaining).await.map(|call| (call, credential));
        self.accept_dispatch(result)
    }

    fn check(&self, cx: &Cx) -> Result<(), ClientCredentialsTaskSubmissionCause> {
        let credential = self.credential.as_ref().ok_or(ManagedTasksError::Closed)?;
        let deadline = self.deadline.ok_or(ManagedTasksError::Closed)?;
        check_live(cx, &self.client, &self.cancellation, deadline, credential)?;
        Ok(())
    }
    fn accept_dispatch(&mut self, result: Result<(ClientCredentialsTaskCall, ClientCredentialsSnapshot), ClientCredentialsTaskSubmissionCause>)
        -> Result<(), ClientCredentialsTaskSubmissionError> {
        match result {
            Ok((call, credential)) => {
                self.call = Some(call); self.credential = Some(credential);
                self.state = TaskSubmissionState::AwaitingResponse;
                Ok(())
            }
            Err(error) => Err(self.fail(error)),
        }
    }
    fn fail(&mut self, error: ClientCredentialsTaskSubmissionCause) -> ClientCredentialsTaskSubmissionError {
        let unknown = matches!(self.state, TaskSubmissionState::DeliveryUnknown | TaskSubmissionState::AwaitingResponse);
        self.close();
        if unknown { ClientCredentialsTaskSubmissionError::TaskCreationDeliveryUnknown(Box::new(error)) }
        else { not_dispatched(error) }
    }
    fn phase_error(&self) -> ClientCredentialsTaskSubmissionError {
        match self.state {
            TaskSubmissionState::DeliveryUnknown => ClientCredentialsTaskSubmissionError::TaskCreationDeliveryUnknown(
                Box::new(ManagedTasksError::Closed.into())),
            TaskSubmissionState::AwaitingInput => ClientCredentialsTaskSubmissionError::InputPending,
            _ => ClientCredentialsTaskSubmissionError::InvalidState,
        }
    }
}
fn closed_state(state: TaskSubmissionState) -> TaskSubmissionState {
    match state {
        TaskSubmissionState::Prepared => TaskSubmissionState::NotDispatched,
        TaskSubmissionState::AwaitingResponse => TaskSubmissionState::DeliveryUnknown,
        TaskSubmissionState::AwaitingInput => TaskSubmissionState::Closed,
        other => other,
    }
}
fn admit_pair(ids: &(RequestId, RequestId)) -> Result<(), ClientCredentialsTaskSubmissionCause> {
    for id in [&ids.0, &ids.1] {
        id.validate().map_err(|_| ManagedTasksError::InvalidRequest)?;
        let mut bytes = BoundedBody { bytes: Vec::new(), maximum: MAX_ID_WIRE_BYTES };
        serde_json::to_writer(&mut bytes, id).map_err(|_| ManagedTasksError::RequestTooLarge)?;
    }
    if ids.0.correlates_with(&ids.1) { return Err(ManagedTasksError::InvalidRequest.into()); }
    Ok(())
}
fn prepare_round(client: &ClientCredentialsTasksClient, ids: (RequestId, RequestId), operation: Prepared)
    -> Result<Round, ClientCredentialsTaskSubmissionCause> {
    let discovery = CoreRequest::decode(fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026,
        "server/discover", Some(&json!({"_meta":client.metadata}))).map_err(|_| ManagedTasksError::InvalidRequest)?;
    let params = discovery.encode_params().map_err(|_| ManagedTasksError::InvalidRequest)?.ok_or(ManagedTasksError::InvalidRequest)?;
    let discovery_wire = encode(client.client.resource().as_str(), "server/discover", &ids.0, params, None, client.limits.request_bytes)?;
    Ok(Round { ids, operation, discovery, discovery_wire })
}
fn check_live(cx: &Cx, client: &ClientCredentialsTasksClient, cancellation: &McpRequestCancellation,
    deadline: Time, credential: &ClientCredentialsSnapshot,
) -> Result<(), ClientCredentialsError> {
    if client.client.inner.closed.is_cancel_requested() { return Err(ClientCredentialsError::Closed); }
    if cancellation.is_cancel_requested() { return Err(OAuthDiscoveryError::Cancelled.into()); }
    check_context(cx, cx.budget().deadline.map_or(deadline, |parent| parent.min(deadline))).map_err(ClientCredentialsError::from)?;
    check_token(&credential.bearer, credential.expires_at)
}
fn transport_error(error: ModernHttpExecutorError) -> ClientCredentialsError {
    match error { ModernHttpExecutorError::Redirect { status } => ClientCredentialsError::Redirect { status },
        _ => ClientCredentialsError::Transport }
}
#[allow(clippy::too_many_arguments)]
async fn dispatch(state: &mut TaskSubmissionState, cx: &Cx, client: &ClientCredentialsTasksClient,
    cancellation: &McpRequestCancellation, deadline: Time, credential: &ClientCredentialsSnapshot,
    round: Round, remaining_records: usize,
) -> Result<ClientCredentialsTaskCall, ClientCredentialsTaskSubmissionCause> {
    if remaining_records == 0 { return Err(ClientCredentialsTaskSubmissionCause::RecordLimit); }
    active(cx, deadline, &client.client.inner.closed, cancellation, Some(credential), async {
        Ok(async {
            let executor = ModernHttpExecutor::new();
            let wire = authorize(credential, round.discovery_wire)?;
            let response = executor.execute_with_cancellation(cx, cancellation, &wire).await.map_err(transport_error)?;
            check_live(cx, client, cancellation, deadline, credential)?;
            require_success(&response)?;
            if response.metadata().kind() != ModernHttpResponseKind::Json { return Err(ManagedTasksError::Negotiation.into()); }
            let bytes = response.read_to_end_with_cancellation(cx, cancellation, client.limits.frame_bytes).await
                .map_err(|_| ClientCredentialsError::UnexpectedResponse)?;
            admit_composition(&round.discovery, &round.ids.0, &bytes, &round.operation.decoder, client.limits.frame_bytes)?;
            check_live(cx, client, cancellation, deadline, credential)?;
            let wire = authorize(credential, round.operation.wire)?;
            // This marker must be INSIDE the lifetime guard and immediately
            // before executor entry, not before discovery or after awaiting HTTP.
            *state = TaskSubmissionState::DeliveryUnknown;
            let response = executor.execute_with_cancellation(cx, cancellation, &wire).await.map_err(transport_error)?;
            check_live(cx, client, cancellation, deadline, credential)?;
            require_success(&response)?;
            let mut limits = client.limits;
            limits.records = limits.records.min(remaining_records);
            let pinned = ClientCredentialsSnapshot { bearer: credential.bearer.clone(), scopes: credential.scopes.clone(),
                expires_at: credential.expires_at, generation: credential.generation };
            Ok(ClientCredentialsTaskCall::new(response, round.operation.decoder, round.operation.progress,
                pinned, client.client.inner.closed.clone(), cancellation.clone(), round.ids.1, deadline, limits)?)
        }.await)
    }).await?
}

#[cfg(test)]
mod tests;
