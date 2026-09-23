//! Explicit, bounded multi-round core operations over managed OAuth.
//!
//! A server's `input_required` result suspends one operation. The host decides
//! whether to answer it and calls `resume` with a fresh request ID. Only the
//! current challenge's correlated answers and opaque state enter that next
//! POST; the original method, target, arguments and metadata are immutable.
//! No transport error, missing response or dropped future is a retry signal.
//!
//! This implements the caller-driven MRTR-01 path for tools/call,
//! resources/read and prompts/get. The optional `drive` method uses explicit
//! host callbacks; it never supplies its own model, roots or browser handler.
//! Tasks negotiation and server requestState signature verification remain
//! separate host/server responsibilities.

use std::fmt;
use std::future::Future;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::exact_json_to_serde;
use fastmcp_protocol::{
    CoreRequest, CoreResult, FinalCoreRequest, FinalCoreResult,
    FinalEmbeddedElicitationParams, FinalEmbeddedInputRequest, FinalInputResponses,
    InputRequiredResult, RequestId, ServerNotification, FINAL_CLIENT_CAPABILITIES_META_KEY,
};

use super::{
    ManagedCoreCall, ManagedCoreError, ManagedCoreEvent, ManagedCoreLimits,
    ManagedOAuthSession, bounded_wait, call_deadline, check_call, prepare,
};

/// Explicit reply recovery for independently configured continuation journals.
pub mod recovery;

const MAX_INPUTS_PER_ROUND: usize = 128;

/// Limits for the whole interaction, not a fresh budget for each retry.
/// `core.total_bytes`, `core.notifications` and `core.timeout` are shared by
/// every round. `core.request_bytes` and `core.frame_bytes` apply per request
/// and frame. Ordinary resumption attempts at most `max_continuations + 1`
/// POSTs; explicit journal recovery additionally has its own bounded attempts.
#[derive(Clone, Copy, Debug)]
pub struct ManagedInteractionLimits {
    core: ManagedCoreLimits,
    max_continuations: usize,
    max_input_responses: usize,
}

impl Default for ManagedInteractionLimits {
    fn default() -> Self {
        Self {
            core: ManagedCoreLimits::default(),
            max_continuations: 8,
            max_input_responses: 256,
        }
    }
}

impl ManagedInteractionLimits {
    pub(crate) fn core(self) -> ManagedCoreLimits { self.core }

    /// Zero continuations explicitly requires completion on the first POST.
    /// A zero input budget still permits bounded, explicitly resumed state-only
    /// rounds. Hard ceilings bound the retained ID ledger and input work.
    pub fn new(
        core: ManagedCoreLimits,
        max_continuations: usize,
        max_input_responses: usize,
    ) -> Result<Self, ManagedInteractionError> {
        if max_continuations > 64 || max_input_responses > 1024 {
            return Err(ManagedInteractionError::InvalidLimits);
        }
        Ok(Self { core, max_continuations, max_input_responses })
    }
}

/// Sanitized errors: no challenge, opaque state, answer, or original arguments
/// are retained by the interaction error or its diagnostic formatting.
#[derive(Debug)]
pub enum ManagedInteractionError {
    InvalidLimits,
    InvalidInitialRequest,
    NotAwaitingInput,
    InputPending,
    InvalidInputResponses,
    /// A proper subset needs server-owned state to retain the accepted answers.
    PartialStateRequired,
    CapabilityNotAdvertised,
    ContinuationLimit,
    InputLimit,
    RepeatedRequestId,
    /// The host declined further resolver or notification processing.
    AbortedByHost,
    Closed,
    Core(ManagedCoreError),
}

impl fmt::Display for ManagedInteractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid managed interaction limits",
            Self::InvalidInitialRequest => "interaction requires an initial final tool, resource or prompt request",
            Self::NotAwaitingInput => "interaction is not awaiting input",
            Self::InputPending => "interaction requires explicit host input before another response read",
            Self::InvalidInputResponses => "answers do not match the current input-required result",
            Self::PartialStateRequired => "partial answers require a nonempty server continuation state",
            Self::CapabilityNotAdvertised => "input-required result requests an unadvertised client capability",
            Self::ContinuationLimit => "interaction continuation limit exceeded",
            Self::InputLimit => "interaction input-response limit exceeded",
            Self::RepeatedRequestId => "interaction continuation requires a fresh request ID",
            Self::AbortedByHost => "managed interaction aborted by its host",
            Self::Closed => "managed interaction is closed",
            Self::Core(error) => return fmt::Display::fmt(error, f),
        })
    }
}

impl std::error::Error for ManagedInteractionError {}

impl From<ManagedCoreError> for ManagedInteractionError {
    fn from(error: ManagedCoreError) -> Self { Self::Core(error) }
}

/// Notifications remain incremental across all rounds. An input-required
/// event is a copy for the host: modifying that copy cannot alter the pending
/// challenge or the opaque state the operation will echo.
pub enum ManagedInteractionEvent {
    Notification(Box<ServerNotification>),
    InputRequired(Box<InputRequiredResult>),
    Complete(Box<CoreResult>),
}

/// A host-selected answer to one admitted challenge. No requestState, target,
/// method, original arguments or replacement capabilities can be supplied.
/// Deliberately not Debug/Clone: response payloads may contain private input.
pub struct ManagedInputReply {
    /// Fresh ID for the single continuation POST.
    pub request_id: RequestId,
    /// Exact correlated replies, or absence for a state-only continuation.
    pub input_responses: Option<FinalInputResponses>,
}

enum Step {
    Reading(Box<ManagedCoreCall>),
    Awaiting(Box<InputRequiredResult>),
    Complete,
}

/// One non-Clone, host-driven operation. It retains only the original request,
/// current response/challenge and a bounded ID ledger, not prior answers.
///
/// Local answer/ID/size rejection leaves the pending challenge available for
/// correction. Once resume can dispatch, any failure or abandonment closes
/// the operation instead of permitting a second send with that same state.
/// Server side effects already committed cannot be undone by local closure.
pub struct ManagedInteraction {
    session: ManagedOAuthSession,
    original: CoreRequest,
    step: Option<Step>,
    cancellation: McpRequestCancellation,
    deadline: Time,
    limits: ManagedInteractionLimits,
    used_ids: Vec<RequestId>,
    continuations: usize,
    input_responses: usize,
    response_bytes: usize,
    notifications: usize,
    generation: u64,
}

impl fmt::Debug for ManagedInteraction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedInteraction")
            .field("continuations", &self.continuations)
            .field("awaiting_input", &matches!(self.step, Some(Step::Awaiting(_))))
            .field("closed", &self.step.is_none())
            .finish_non_exhaustive()
    }
}

impl ManagedOAuthSession {
    /// Opens an explicitly selected modern multi-round core operation.
    /// All input-related effects remain under host control through `resume`.
    /// Existing `request_core` retains its one-POST behavior unchanged.
    pub async fn start_core_interaction(
        &self,
        cx: &Cx,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedInteractionLimits,
    ) -> Result<ManagedInteraction, ManagedInteractionError> {
        self.start_core_interaction_with_cancellation(
            cx, &McpRequestCancellation::new(), request, request_id, limits,
        ).await
    }

    /// Retains the supplied request-local cancellation domain across every
    /// round, including pauses while the host obtains input. No cancellation
    /// notification, automatic reconnect or grant retry is introduced.
    pub async fn start_core_interaction_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedInteractionLimits,
    ) -> Result<ManagedInteraction, ManagedInteractionError> {
        let deadline = call_deadline(cx, cancellation, limits.core.timeout)?;
        validate_initial(&request)?;
        let (wire, decoder) = prepare(
            self.resource().as_str(), request.clone(), request_id.clone(), limits.core,
        )?;
        let response = bounded_wait(cx, cancellation, deadline, async {
            self.execute_with_cancellation(cx, cancellation, &wire).await.map_err(ManagedCoreError::from)
        }).await?;
        let call = ManagedCoreCall::from_response(response, decoder, cancellation.clone(), deadline)?;
        let generation = call.credential_generation();
        Ok(ManagedInteraction {
            session: self.clone(), original: request, step: Some(Step::Reading(Box::new(call))),
            cancellation: cancellation.clone(), deadline, limits, used_ids: vec![request_id],
            continuations: 0, input_responses: 0, response_bytes: 0, notifications: 0, generation,
        })
    }
}

impl ManagedInteraction {
    /// Borrows the current admitted challenge; this is not authorization to
    /// perform any requested action. The host must apply its own consent and
    /// disclosure policy. It cannot replace this challenge or requestState.
    pub fn pending_input(&self) -> Option<&InputRequiredResult> {
        match &self.step {
            Some(Step::Awaiting(input)) => Some(input),
            _ => None,
        }
    }

    pub fn continuation_count(&self) -> usize { self.continuations }

    /// Credential generation of the most recently opened response, local to
    /// this login. It is neither an execution ID nor a cross-session cache key.
    pub fn credential_generation(&self) -> u64 { self.generation }

    /// Releases the current response or challenge without cancelling siblings.
    pub fn close(&mut self) { self.step = None; }

    /// Runs this operation through explicitly supplied host callbacks.
    ///
    /// `resolve` receives each admitted input-required result once and returns
    /// a fresh ID plus typed answers. The framework supplies no default resolver
    /// and opens no URL, model session or filesystem root itself. `notify`
    /// receives notifications as they arrive, before any later failure. It is
    /// synchronous and must return promptly without blocking the async runtime.
    ///
    /// The resolver future is bounded by this operation's original deadline,
    /// caller budget and cancellation domain. It must be cancellation-correct
    /// when dropped. The host remains responsible for its own external effects;
    /// completing a model/user action cannot be undone if the subsequent POST
    /// fails. Session closure prevents network continuation, but cancelling a
    /// host-owned resolver requires this operation's cancellation handle or its
    /// caller Cx, rather than relying on OAuth session closure alone.
    ///
    /// Consuming ownership makes callback failure, invalid answers and dropped
    /// driver futures terminal: neither the callback nor the POST is retried.
    /// A manually observed pending challenge can be handed to `drive`; a
    /// previously delivered final result is never delivered a second time.
    pub async fn drive<R, F, N>(
        self,
        cx: &Cx,
        resolve: R,
        notify: N,
    ) -> Result<Box<CoreResult>, ManagedInteractionError>
    where
        R: FnMut(Box<InputRequiredResult>) -> F,
        F: Future<Output = Result<ManagedInputReply, ManagedInteractionError>>,
        N: FnMut(Box<ServerNotification>) -> Result<(), ManagedInteractionError>,
    {
        self.drive_selected(cx, resolve, notify, InputSelection::Complete).await
    }

    /// Drives an operation whose host may answer only some inputs per round.
    /// Each callback authorizes only the returned answers; omitted inputs are
    /// neither resolved nor given synthetic cancellation/error responses.
    /// State-only and present-empty challenges retain the `drive` contract.
    /// Nonempty proper subsets require server-issued continuation state.
    /// All callback, continuation, byte and lifetime bounds span the full run.
    pub async fn drive_partial<R, F, N>(
        self,
        cx: &Cx,
        resolve: R,
        notify: N,
    ) -> Result<Box<CoreResult>, ManagedInteractionError>
    where
        R: FnMut(Box<InputRequiredResult>) -> F,
        F: Future<Output = Result<ManagedInputReply, ManagedInteractionError>>,
        N: FnMut(Box<ServerNotification>) -> Result<(), ManagedInteractionError>,
    {
        self.drive_selected(cx, resolve, notify, InputSelection::Partial).await
    }

    async fn drive_selected<R, F, N>(
        mut self,
        cx: &Cx,
        mut resolve: R,
        mut notify: N,
        selection: InputSelection,
    ) -> Result<Box<CoreResult>, ManagedInteractionError>
    where
        R: FnMut(Box<InputRequiredResult>) -> F,
        F: Future<Output = Result<ManagedInputReply, ManagedInteractionError>>,
        N: FnMut(Box<ServerNotification>) -> Result<(), ManagedInteractionError>,
    {
        loop {
            self.check(cx)?;
            let event = match self.pending_input() {
                Some(input) => ManagedInteractionEvent::InputRequired(Box::new(input.clone())),
                None => self.next_event(cx).await?.ok_or(ManagedInteractionError::Closed)?,
            };
            self.check(cx)?;
            match event {
                ManagedInteractionEvent::Notification(notification) => {
                    notify(notification)?;
                    self.check(cx)?;
                }
                ManagedInteractionEvent::InputRequired(input) => {
                    // Invocation itself occurs inside the guarded future, so a
                    // pre-existing cancellation cannot run the resolver once.
                    let reply = bounded_wait(cx, &self.cancellation, self.deadline, async {
                        Ok(resolve(input).await)
                    }).await??;
                    self.check(cx)?;
                    // Absence/empty presence keep their strict meaning. Only
                    // a nonempty response map can opt into partial progress.
                    let selected = if reply.input_responses.as_ref().is_some_and(|answers| !answers.is_empty()) {
                        selection
                    } else { InputSelection::Complete };
                    self.resume_selected(cx, reply.request_id, reply.input_responses, selected).await?;
                }
                ManagedInteractionEvent::Complete(result) => return Ok(result),
            }
        }
    }

    /// Delivers the next notification, input challenge or complete result.
    /// A challenge is emitted once. Further reads return `InputPending` until
    /// the host explicitly resumes, rather than reporting a false successful EOF.
    /// Dropping a polled read releases its response and leaves the operation closed.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ManagedInteractionEvent>, ManagedInteractionError> {
        if matches!(self.step, Some(Step::Complete)) { return Ok(None); }
        self.check(cx)?;
        let mut call = match self.step.take() {
            Some(Step::Reading(call)) => call,
            Some(step @ Step::Awaiting(_)) => {
                self.step = Some(step);
                return Err(ManagedInteractionError::InputPending);
            }
            Some(Step::Complete) => return Ok(None),
            None => return Err(ManagedInteractionError::Closed),
        };
        let event = call.next_event(cx).await?.ok_or(ManagedCoreError::MissingTerminal)?;
        self.response_bytes = call.decoder.bytes;
        self.notifications = call.decoder.notifications;
        self.check(cx)?;
        match event {
            ManagedCoreEvent::Notification(notification) => {
                self.step = Some(Step::Reading(call));
                Ok(Some(ManagedInteractionEvent::Notification(notification)))
            }
            ManagedCoreEvent::Result(result) => {
                if let Some(input) = input_required(&result) {
                    // No possible next result fits a fully exhausted budget.
                    // Refuse before exposing a new host-input work item.
                    if self.response_bytes >= self.limits.core.total_bytes {
                        return Err(ManagedCoreError::ResponseByteLimit.into());
                    }
                    admit_challenge(
                        &self.original, input, self.limits,
                        self.continuations, self.input_responses,
                    )?;
                    self.check(cx)?;
                    let input = Box::new(input.clone());
                    self.step = Some(Step::Awaiting(input.clone()));
                    Ok(Some(ManagedInteractionEvent::InputRequired(input)))
                } else {
                    self.step = Some(Step::Complete);
                    Ok(Some(ManagedInteractionEvent::Complete(result)))
                }
            }
        }
    }

    /// Answers the current challenge with one explicitly authorized POST.
    ///
    /// Every requested key must be present exactly once with the response kind
    /// selected by the protocol descriptor. Absent `inputRequests` requires
    /// `None`; a present empty map requires `Some(empty)`. Responses from prior
    /// rounds are never merged. requestState, including a present empty string,
    /// is copied verbatim from the current result, not supplied by the host.
    ///
    /// A new request ID must differ under JSON-RPC correlation semantics from
    /// every ID previously attempted by this operation. Identity, metadata,
    /// arguments and resource cannot be replaced through this API.
    pub async fn resume(
        &mut self,
        cx: &Cx,
        request_id: RequestId,
        responses: Option<FinalInputResponses>,
    ) -> Result<(), ManagedInteractionError> {
        self.resume_selected(cx, request_id, responses, InputSelection::Complete).await
    }

    /// Submits a nonempty subset of the current challenge's answers. Unselected
    /// inputs are not fabricated, executed, or retained as local answers. The
    /// next response determines the remaining challenge and its successor state.
    /// A proper subset requires a nonempty server-issued requestState; without
    /// it the server has supplied no continuation custody for omitted answers.
    /// Supplying all answers remains valid, including for a stateless challenge.
    ///
    /// This uses the same bounded, one-attempt dispatch as `resume`. Local
    /// validation failures preserve the original challenge. A lost response or
    /// an abandoned send never authorizes another attempt with the old state.
    pub async fn resume_partial(
        &mut self,
        cx: &Cx,
        request_id: RequestId,
        responses: FinalInputResponses,
    ) -> Result<(), ManagedInteractionError> {
        self.resume_selected(cx, request_id, Some(responses), InputSelection::Partial).await
    }

    async fn resume_selected(
        &mut self,
        cx: &Cx,
        request_id: RequestId,
        responses: Option<FinalInputResponses>,
        selection: InputSelection,
    ) -> Result<(), ManagedInteractionError> {
        self.check(cx)?;
        let Some(Step::Awaiting(input)) = &self.step else {
            return Err(if self.step.is_none() {
                ManagedInteractionError::Closed
            } else {
                ManagedInteractionError::NotAwaitingInput
            });
        };
        admit_fresh_id(&self.used_ids, &request_id)?;
        // All fallible local validation happens before consuming the challenge.
        let count = responses.as_ref().map_or(0, FinalInputResponses::len);
        let next = continuation_request_selected(&self.original, input, responses, selection)?;
        let (wire, mut decoder) = prepare(
            self.session.resource().as_str(), next, request_id.clone(), self.limits.core,
        )?;
        decoder.bytes = self.response_bytes;
        decoder.notifications = self.notifications;
        self.check(cx)?;
        // Commit local ownership before the first await. A lost response, a
        // cancelled send, or a dropped future cannot resurrect this attempt.
        self.step = None;
        self.used_ids.push(request_id);
        self.continuations += 1;
        self.input_responses += count;
        let response = bounded_wait(cx, &self.cancellation, self.deadline, async {
            self.session.execute_with_cancellation(cx, &self.cancellation, &wire)
                .await.map_err(ManagedCoreError::from)
        }).await?;
        let call = ManagedCoreCall::from_response(
            response, decoder, self.cancellation.clone(), self.deadline,
        )?;
        self.generation = call.credential_generation();
        self.step = Some(Step::Reading(Box::new(call)));
        Ok(())
    }

    fn check(&mut self, cx: &Cx) -> Result<(), ManagedInteractionError> {
        let deadline = cx.budget().deadline.map_or(self.deadline, |caller| caller.min(self.deadline));
        if let Err(error) = check_call(cx, &self.cancellation, deadline) {
            self.close();
            return Err(error.into());
        }
        Ok(())
    }
}

pub(crate) fn validate_initial(request: &CoreRequest) -> Result<(), ManagedInteractionError> {
    let initial = match request {
        CoreRequest::Final(FinalCoreRequest::ToolsCall(params)) => {
            params.input_responses.is_none() && params.request_state.is_none()
        }
        CoreRequest::Final(FinalCoreRequest::ResourcesRead(params)) => {
            params.input_responses.is_none() && params.request_state.is_none()
        }
        CoreRequest::Final(FinalCoreRequest::PromptsGet(params)) => {
            params.input_responses.is_none() && params.request_state.is_none()
        }
        _ => false,
    };
    if initial { Ok(()) } else { Err(ManagedInteractionError::InvalidInitialRequest) }
}

pub(crate) fn input_required(result: &CoreResult) -> Option<&InputRequiredResult> {
    match result {
        CoreResult::Final(
            FinalCoreResult::ToolsCallInputRequired { result, .. }
            | FinalCoreResult::ResourcesReadInputRequired { result, .. }
            | FinalCoreResult::PromptsGetInputRequired { result, .. },
        ) => Some(result),
        _ => None,
    }
}

pub(crate) fn admit_fresh_id(previous: &[RequestId], next: &RequestId) -> Result<(), ManagedInteractionError> {
    next.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
    if previous.iter().any(|id| id.correlates_with(next)) {
        return Err(ManagedInteractionError::RepeatedRequestId);
    }
    Ok(())
}

/// Checks embedded parameter and sampling-control wire shapes before derived
/// struct/enum decoders can accept sequence/tagged representations or erase
/// explicit nulls. This borrowed check does not grant any client capability.
pub(crate) fn validate_embedded_input_shape(
    value: &serde_json::Value,
) -> Result<(), ManagedInteractionError> {
    if let Some(params) = value.get("params") {
        if !params.is_object() {
            return Err(ManagedCoreError::InvalidResult.into());
        }
        if value.get("method").and_then(serde_json::Value::as_str) == Some("sampling/createMessage") {
            // Derived Rust structs also accept sequences. Wire tool controls
            // and tool descriptors must retain their required object shape.
            if let Some(tools) = params.get("tools") {
                if !tools.as_array().is_some_and(|tools| tools.iter().all(serde_json::Value::is_object)) {
                    return Err(ManagedCoreError::InvalidResult.into());
                }
            }
            if let Some(choice) = params.get("toolChoice") {
                if !choice.is_object()
                    || choice.get("mode").is_some_and(|mode| !mode.is_string())
                {
                    return Err(ManagedCoreError::InvalidResult.into());
                }
            }
            if params.get("includeContext").is_some_and(|context| !context.is_string()) {
                return Err(ManagedCoreError::InvalidResult.into());
            }
        }
    }
    Ok(())
}

/// Admits one received descriptor before optional-field deserialization can
/// erase invalid presence. Only declared object capabilities grant authority;
/// unknown children do not stand in for the required leaf.
///
/// Context is advisory. This admission preserves its received value for
/// host-driven operations; automatic resolvers must normalize an unsupported
/// context request and expose that decision before performing host effects.
pub(crate) fn admit_embedded_input(
    capabilities: &serde_json::Value,
    value: serde_json::Value,
) -> Result<FinalEmbeddedInputRequest, ManagedInteractionError> {
    validate_embedded_input_shape(&value)?;
    let descriptor: FinalEmbeddedInputRequest = serde_json::from_value(value)
        .map_err(|_| ManagedCoreError::InvalidResult)?;
    let advertised = match &descriptor {
        FinalEmbeddedInputRequest::Roots(_) => {
            capabilities.get("roots").is_some_and(serde_json::Value::is_object)
        }
        FinalEmbeddedInputRequest::Sampling(params) => {
            let sampling = &capabilities["sampling"];
            sampling.is_object()
                && ((params.tools.is_none() && params.tool_choice.is_none())
                    || sampling.get("tools").is_some_and(serde_json::Value::is_object))
        }
        FinalEmbeddedInputRequest::Elicitation(FinalEmbeddedElicitationParams::Form(_)) => {
            capabilities.get("elicitation").and_then(serde_json::Value::as_object)
                .is_some_and(|elicitation| elicitation.is_empty()
                    || elicitation.get("form").is_some_and(serde_json::Value::is_object))
        }
        FinalEmbeddedInputRequest::Elicitation(FinalEmbeddedElicitationParams::Url(_)) => {
            capabilities["elicitation"].get("url").is_some_and(serde_json::Value::is_object)
        }
    };
    if !advertised {
        return Err(ManagedInteractionError::CapabilityNotAdvertised);
    }
    Ok(descriptor)
}

/// Normalizes only a caller-owned effective descriptor. Task ledgers retain
/// their original wire values. The caller exposes the returned diagnostic
/// after whole-batch admission and before invoking any host input effects.
#[cfg(feature = "tasks")]
pub(crate) fn normalize_embedded_input_context(
    capabilities: &serde_json::Value,
    request: &mut FinalEmbeddedInputRequest,
) -> bool {
    if capabilities["sampling"]["context"].is_object() {
        return false;
    }
    let FinalEmbeddedInputRequest::Sampling(params) = request else { return false };
    if params.include_context.is_some_and(|context| context != fastmcp_protocol::IncludeContext::None) {
        params.include_context = None;
        true
    } else {
        false
    }
}

pub(crate) fn admit_challenge(
    original: &CoreRequest,
    input: &InputRequiredResult,
    limits: ManagedInteractionLimits,
    continuations: usize,
    input_responses: usize,
) -> Result<(), ManagedInteractionError> {
    if continuations >= limits.max_continuations {
        return Err(ManagedInteractionError::ContinuationLimit);
    }
    let Some(requests) = input.input_requests() else { return Ok(()) };
    let count = requests.members().len();
    if count > MAX_INPUTS_PER_ROUND || count > limits.max_input_responses.saturating_sub(input_responses) {
        return Err(ManagedInteractionError::InputLimit);
    }
    let params = original.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    let capabilities = &params["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY];
    for member in requests.members() {
        let value = exact_json_to_serde(&member.value).map_err(|_| ManagedCoreError::InvalidResult)?;
        admit_embedded_input(capabilities, value)?;
    }
    Ok(())
}

pub(crate) fn continuation_request(
    original: &CoreRequest,
    input: &InputRequiredResult,
    responses: Option<FinalInputResponses>,
) -> Result<CoreRequest, ManagedInteractionError> {
    continuation_request_selected(original, input, responses, InputSelection::Complete)
}

#[derive(Clone, Copy)]
pub(crate) enum InputSelection { Complete, Partial }

/// Validate only correlation/shape, never invoke a resolver or manufacture
/// answers for omitted inputs. The interaction already admitted capabilities
/// and the entire challenge before making it available to the host.
pub(crate) fn validate_partial_responses(
    input: &InputRequiredResult,
    responses: &FinalInputResponses,
) -> Result<(), ManagedInteractionError> {
    let requests = input.input_requests().ok_or(ManagedInteractionError::InvalidInputResponses)?;
    if responses.is_empty() || responses.len() > requests.members().len()
        || requests.members().len() > MAX_INPUTS_PER_ROUND
    {
        return Err(ManagedInteractionError::InvalidInputResponses);
    }
    for (key, response) in responses.entries() {
        let request = requests.get(key).ok_or(ManagedInteractionError::InvalidInputResponses)?;
        let request = exact_json_to_serde(request).map_err(|_| ManagedInteractionError::InvalidInputResponses)?;
        let descriptor: FinalEmbeddedInputRequest = serde_json::from_value(request)
            .map_err(|_| ManagedInteractionError::InvalidInputResponses)?;
        if !response.matches_kind(descriptor.response_kind()) {
            return Err(ManagedInteractionError::InvalidInputResponses);
        }
    }
    if responses.len() < requests.members().len()
        && input.request_state().is_none_or(str::is_empty)
    {
        return Err(ManagedInteractionError::PartialStateRequired);
    }
    Ok(())
}

pub(crate) fn continuation_request_selected(
    original: &CoreRequest,
    input: &InputRequiredResult,
    responses: Option<FinalInputResponses>,
    selection: InputSelection,
) -> Result<CoreRequest, ManagedInteractionError> {
    if matches!(selection, InputSelection::Partial) {
        validate_partial_responses(input, responses.as_ref().ok_or(ManagedInteractionError::InvalidInputResponses)?)?;
    } else {
        match (input.input_requests(), responses.as_ref()) {
            (None, None) => {},
            (Some(_), Some(responses)) => responses.validate_against_input_required(input)
                .map_err(|_| ManagedInteractionError::InvalidInputResponses)?,
            _ => return Err(ManagedInteractionError::InvalidInputResponses),
        }
    }
    let mut next = original.clone();
    let state = input.request_state().map(str::to_owned);
    match &mut next {
        CoreRequest::Final(FinalCoreRequest::ToolsCall(params)) => {
            params.input_responses = responses;
            params.request_state = state;
        }
        CoreRequest::Final(FinalCoreRequest::ResourcesRead(params)) => {
            params.input_responses = responses;
            params.request_state = state;
        }
        CoreRequest::Final(FinalCoreRequest::PromptsGet(params)) => {
            params.input_responses = responses;
            params.request_state = state;
        }
        _ => return Err(ManagedInteractionError::InvalidInitialRequest),
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::{Value, json};

    fn request(method: &str, mut params: Value, capabilities: Value) -> CoreRequest {
        let mut metadata = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        metadata[FINAL_CLIENT_CAPABILITIES_META_KEY] = capabilities;
        metadata["com.example/identity"] = json!("unchanged");
        params["_meta"] = metadata;
        CoreRequest::decode(fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026, method, Some(&params)).unwrap()
    }

    fn input(request: &CoreRequest, source: &str) -> InputRequiredResult {
        let result = request.decode_result(source).unwrap();
        input_required(&result).unwrap().clone()
    }

    fn answers(value: Value) -> FinalInputResponses { serde_json::from_value(value).unwrap() }

    #[test]
    fn continuation_changes_only_current_answers_and_exact_opaque_state() {
        for (method, params) in [
            ("tools/call", json!({"name":"echo","arguments":{"payload":"original"}})),
            ("resources/read", json!({"uri":"file:///opaque/%2Fresource"})),
            ("prompts/get", json!({"name":"prompt","arguments":{"subject":"original"}})),
        ] {
            let original = request(method, params, json!({"roots":{}}));
            validate_initial(&original).unwrap();
            let before = original.encode_params().unwrap().unwrap();
            let challenge = input(&original, r#"{"resultType":"input_required","inputRequests":{"roots-a":{"method":"roots/list"}},"requestState":"  opaque+/%\u0000  "}"#);
            let supplied = answers(json!({"roots-a":{"roots":[]}}));
            let next = continuation_request(&original, &challenge, Some(supplied)).unwrap();
            let mut after = next.encode_params().unwrap().unwrap();
            assert_eq!(after["requestState"], "  opaque+/%\0  ");
            assert_eq!(after["inputResponses"], json!({"roots-a":{"roots":[]}}));
            after.as_object_mut().unwrap().remove("requestState");
            after.as_object_mut().unwrap().remove("inputResponses");
            assert_eq!(after, before);
            assert_eq!(original.encode_params().unwrap().unwrap(), before);
        }
    }

    #[test]
    fn continuation_preserves_absent_empty_and_state_only_distinctions() {
        let original = request("tools/call", json!({"name":"echo"}), json!({}));
        let state_only = input(&original, r#"{"resultType":"input_required","requestState":""}"#);
        let next = continuation_request(&original, &state_only, None).unwrap().encode_params().unwrap().unwrap();
        assert_eq!(next["requestState"], "");
        assert!(next.get("inputResponses").is_none());
        assert!(next.get("arguments").is_none());
        assert!(matches!(continuation_request(&original, &state_only, Some(answers(json!({})))), Err(ManagedInteractionError::InvalidInputResponses)));
        let empty_inputs = input(&original, r#"{"resultType":"input_required","inputRequests":{}}"#);
        assert!(matches!(continuation_request(&original, &empty_inputs, None), Err(ManagedInteractionError::InvalidInputResponses)));
        let next = continuation_request(&original, &empty_inputs, Some(answers(json!({})))).unwrap().encode_params().unwrap().unwrap();
        assert_eq!(next["inputResponses"], json!({}));
        assert!(next.get("requestState").is_none());
    }

    #[test]
    fn every_key_and_response_kind_must_match_the_current_challenge() {
        let original = request("resources/read", json!({"uri":"file:///input"}), json!({"roots":{}}));
        let challenge = input(&original, r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"sealed"}"#);
        let before = original.encode_params().unwrap();
        for invalid in [json!({}), json!({"other":{"roots":[]}}), json!({"roots":{"action":"decline"}}), json!({"roots":{"roots":[]},"extra":{"roots":[]}})] {
            assert!(matches!(continuation_request(&original, &challenge, Some(answers(invalid))), Err(ManagedInteractionError::InvalidInputResponses)));
            assert_eq!(original.encode_params().unwrap(), before);
        }
        assert!(continuation_request(&original, &challenge, Some(answers(json!({"roots":{"roots":[]}})))).is_ok());
    }

    #[test]
    fn next_round_does_not_accumulate_old_answers_or_old_request_state() {
        let original = request("tools/call", json!({"name":"echo"}), json!({"roots":{}}));
        let first = input(&original, r#"{"resultType":"input_required","inputRequests":{"first":{"method":"roots/list"}},"requestState":"old"}"#);
        let first_retry = continuation_request(&original, &first, Some(answers(json!({"first":{"roots":[]}})))).unwrap();
        let second = input(&first_retry, r#"{"resultType":"input_required","inputRequests":{"second":{"method":"roots/list"}}}"#);
        let next = continuation_request(&original, &second, Some(answers(json!({"second":{"roots":[]}})))).unwrap().encode_params().unwrap().unwrap();
        assert!(next.get("requestState").is_none());
        assert_eq!(next["inputResponses"], json!({"second":{"roots":[]}}));
        assert!(matches!(continuation_request(&original, &second, Some(answers(json!({"first":{"roots":[]}})))), Err(ManagedInteractionError::InvalidInputResponses)));
    }

    #[test]
    fn capability_and_round_budgets_are_checked_before_exposing_input() {
        let original = request("tools/call", json!({"name":"echo"}), json!({"roots":{}}));
        let challenge = input(&original, r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}}}"#);
        let limits = ManagedInteractionLimits::new(ManagedCoreLimits::default(), 1, 1).unwrap();
        assert!(admit_challenge(&original, &challenge, limits, 0, 0).is_ok());
        let unadvertised = request("tools/call", json!({"name":"echo"}), json!({}));
        assert!(matches!(admit_challenge(&unadvertised, &challenge, limits, 0, 0), Err(ManagedInteractionError::CapabilityNotAdvertised)));
        assert!(matches!(admit_challenge(&original, &challenge, limits, 1, 0), Err(ManagedInteractionError::ContinuationLimit)));
        assert!(matches!(admit_challenge(&original, &challenge, limits, 0, 1), Err(ManagedInteractionError::InputLimit)));
        let state_only = input(&original, r#"{"resultType":"input_required","requestState":"state"}"#);
        assert!(admit_challenge(&original, &state_only, limits, 0, 1).is_ok());
        assert!(matches!(admit_challenge(&original, &state_only, limits, 1, 1), Err(ManagedInteractionError::ContinuationLimit)));
    }

    #[test]
    fn embedded_capabilities_require_the_exact_hard_leaf() {
        let roots = json!({"method":"roots/list"});
        let sampling = json!({"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}});
        let tools = json!({"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16,"tools":[]}});
        let choice = json!({"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16,"toolChoice":{"mode":"auto"}}});
        let form = json!({"method":"elicitation/create","params":{"mode":"form","message":"details","requestedSchema":{"type":"object","properties":{}}}});
        let url = json!({"method":"elicitation/create","params":{"mode":"url","message":"continue","url":"https://example.test/consent"}});
        for (descriptor, granted, denied) in [
            (roots, json!({"roots":{}}), json!({"extensions":{"roots":{}}})),
            (sampling, json!({"sampling":{}}), json!({"sampling":null})),
            (tools, json!({"sampling":{"tools":{}}}), json!({"sampling":{"context":{}}})),
            (choice, json!({"sampling":{"tools":{}}}), json!({"sampling":{}})),
            (form.clone(), json!({"elicitation":{}}), json!({"elicitation":{"unknown":{}}})),
            (form, json!({"elicitation":{"form":{}}}), json!({"elicitation":{"url":{}}})),
            (url, json!({"elicitation":{"url":{}}}), json!({"elicitation":{}})),
        ] {
            assert!(admit_embedded_input(&granted, descriptor.clone()).is_ok());
            assert!(matches!(admit_embedded_input(&denied, descriptor),
                Err(ManagedInteractionError::CapabilityNotAdvertised)));
        }
        let choice = json!({"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16,"toolChoice":{"mode":"auto"}}});
        for grant in [Value::Null, json!(true), json!([]), json!("tools")] {
            assert!(matches!(admit_embedded_input(&json!({"sampling":{"tools":grant}}), choice.clone()),
                Err(ManagedInteractionError::CapabilityNotAdvertised)));
        }
    }

    #[test]
    fn advisory_context_does_not_change_the_retained_descriptor() {
        let descriptor = json!({"method":"sampling/createMessage","params":{
            "messages":[],"maxTokens":16,"includeContext":"allServers"
        }});
        for capabilities in [json!({"sampling":{}}), json!({"sampling":{"context":{}}})] {
            let admitted = admit_embedded_input(&capabilities, descriptor.clone()).unwrap();
            assert_eq!(serde_json::to_value(admitted).unwrap(), descriptor);
        }
        assert!(matches!(admit_embedded_input(&json!({}), descriptor),
            Err(ManagedInteractionError::CapabilityNotAdvertised)));
    }

    #[test]
    fn embedded_admission_rejects_shape_and_null_before_optional_conversion() {
        let capabilities = json!({"roots":{},"sampling":{"tools":{},"context":{}}});
        for params in [Value::Null, json!([]), json!(["sequence"]), json!(true), json!(1)] {
            for method in ["roots/list", "sampling/createMessage"] {
                assert!(matches!(admit_embedded_input(&capabilities, json!({"method":method,"params":params.clone()})),
                    Err(ManagedInteractionError::Core(ManagedCoreError::InvalidResult))));
            }
        }
        for field in ["tools", "toolChoice", "includeContext"] {
            let mut descriptor = json!({"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}});
            descriptor["params"][field] = Value::Null;
            assert!(matches!(admit_embedded_input(&capabilities, descriptor),
                Err(ManagedInteractionError::Core(ManagedCoreError::InvalidResult))));
        }
        assert!(admit_embedded_input(&capabilities, json!({"method":"roots/list"})).is_ok());
        assert!(admit_embedded_input(&capabilities, json!({"method":"roots/list","params":{}})).is_ok());
        assert!(admit_embedded_input(&capabilities, json!({"method":"sampling/createMessage","params":{
            "messages":[],"maxTokens":16,"tools":[],"toolChoice":{"mode":"auto"},"includeContext":"none"
        }})).is_ok());
    }

    #[test]
    fn embedded_sampling_controls_require_their_wire_shapes() {
        let capabilities = json!({"sampling":{"tools":{}}});
        for choice in [json!({}), json!({"mode":"auto"})] {
            let descriptor = json!({"method":"sampling/createMessage","params":{
                "messages":[],"maxTokens":16,"toolChoice":choice
            }});
            assert!(admit_embedded_input(&capabilities, descriptor).is_ok());
        }
        for choice in [json!([]), json!(["auto"]), json!({"mode":null}), json!({"mode":{"auto":null}})] {
            let descriptor = json!({"method":"sampling/createMessage","params":{
                "messages":[],"maxTokens":16,"toolChoice":choice
            }});
            assert!(matches!(admit_embedded_input(&capabilities, descriptor),
                Err(ManagedInteractionError::Core(ManagedCoreError::InvalidResult))));
        }
        for tools in [json!([]), json!([{"name":"tool","inputSchema":{"type":"object"}}])] {
            let descriptor = json!({"method":"sampling/createMessage","params":{
                "messages":[],"maxTokens":16,"tools":tools
            }});
            assert!(admit_embedded_input(&capabilities, descriptor).is_ok());
        }
        for tools in [
            json!({"name":"tool","inputSchema":{"type":"object"}}),
            json!([["tool",null,null,null,{"type":"object"}]]),
            json!([null]),
            json!([true]),
        ] {
            let descriptor = json!({"method":"sampling/createMessage","params":{
                "messages":[],"maxTokens":16,"tools":tools
            }});
            assert!(matches!(admit_embedded_input(&capabilities, descriptor),
                Err(ManagedInteractionError::Core(ManagedCoreError::InvalidResult))));
        }
        for context in [json!("allServers"), json!("thisServer"), json!("none")] {
            let descriptor = json!({"method":"sampling/createMessage","params":{
                "messages":[],"maxTokens":16,"includeContext":context
            }});
            assert!(admit_embedded_input(&capabilities, descriptor).is_ok());
        }
        for context in [json!({"allServers":null}), json!({"none":null}), json!([])] {
            let descriptor = json!({"method":"sampling/createMessage","params":{
                "messages":[],"maxTokens":16,"includeContext":context
            }});
            assert!(matches!(admit_embedded_input(&capabilities, descriptor),
                Err(ManagedInteractionError::Core(ManagedCoreError::InvalidResult))));
        }
    }

    #[test]
    fn mixed_admission_checks_late_missing_capabilities_without_changing_state() {
        let original = request("tools/call", json!({"name":"echo"}), json!({"roots":{},"sampling":{}}));
        let challenge = input(&original, r#"{"resultType":"input_required","inputRequests":{"first":{"method":"roots/list"},"last":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16,"toolChoice":{"mode":"auto"}}}},"requestState":"same-state"}"#);
        let before = format!("{challenge:?}");
        let limits = ManagedInteractionLimits::new(ManagedCoreLimits::default(), 1, 2).unwrap();
        assert!(matches!(admit_challenge(&original, &challenge, limits, 0, 0),
            Err(ManagedInteractionError::CapabilityNotAdvertised)));
        assert_eq!(format!("{challenge:?}"), before);
        assert_eq!(challenge.request_state(), Some("same-state"));
        let capable = request("tools/call", json!({"name":"echo"}), json!({"roots":{},"sampling":{"tools":{}}}));
        assert!(admit_challenge(&capable, &challenge, limits, 0, 0).is_ok());
        assert_eq!(format!("{challenge:?}"), before);
    }

    #[test]
    fn correlation_aliases_cannot_reuse_an_earlier_round_id() {
        let used = vec![RequestId::Number(1), RequestId::String("second".to_owned())];
        for id in ["1", "1.0", "1e0", "\"second\""] {
            assert!(matches!(admit_fresh_id(&used, &serde_json::from_str(id).unwrap()), Err(ManagedInteractionError::RepeatedRequestId)));
        }
        assert!(admit_fresh_id(&used, &RequestId::String("1".to_owned())).is_ok());
        assert!(admit_fresh_id(&used, &RequestId::Number(2)).is_ok());
    }

    #[test]
    fn starting_from_unowned_retry_state_is_refused() {
        for params in [json!({"name":"echo","requestState":"injected"}), json!({"name":"echo","inputResponses":{}})] {
            assert!(matches!(validate_initial(&request("tools/call", params, json!({}))), Err(ManagedInteractionError::InvalidInitialRequest)));
        }
        assert!(matches!(validate_initial(&request("tools/list", json!({}), json!({}))), Err(ManagedInteractionError::InvalidInitialRequest)));
        assert!(ManagedInteractionLimits::new(ManagedCoreLimits::default(), 65, 1).is_err());
        assert!(ManagedInteractionLimits::new(ManagedCoreLimits::default(), 1, 1025).is_err());
    }

    fn two_inputs(original: &CoreRequest, state: Option<&str>) -> InputRequiredResult {
        let mut value = json!({"resultType":"input_required", "inputRequests":{
            "one":{"method":"roots/list"}, "two":{"method":"roots/list"}
        }});
        if let Some(state) = state { value["requestState"] = json!(state); }
        input(original, &value.to_string())
    }

    #[test]
    fn partial_answers_advance_all_three_methods_without_rewriting_original_fields() {
        for (method, params) in [
            ("tools/call", json!({"name":"echo","arguments":{"x":1}})),
            ("resources/read", json!({"uri":"file:///unchanged/%2F"})),
            ("prompts/get", json!({"name":"prompt","arguments":{"subject":"same"}})),
        ] {
            let original = request(method, params, json!({"roots":{}}));
            let before = original.encode_params().unwrap().unwrap();
            let challenge = two_inputs(&original, Some("  opaque\0  "));
            let supplied = answers(json!({"two":{"roots":[]}}));
            assert!(continuation_request(&original, &challenge, Some(supplied.clone())).is_err(),
                "the existing exhaustive API must not silently become partial");
            let next = continuation_request_selected(&original, &challenge, Some(supplied), InputSelection::Partial).unwrap();
            let mut encoded = next.encode_params().unwrap().unwrap();
            assert_eq!(encoded["inputResponses"], json!({"two":{"roots":[]}}));
            assert_eq!(encoded["requestState"], "  opaque\0  ");
            encoded.as_object_mut().unwrap().remove("inputResponses");
            encoded.as_object_mut().unwrap().remove("requestState");
            assert_eq!(encoded, before);
            assert_eq!(original.encode_params().unwrap().unwrap(), before);
            assert_eq!(challenge.input_requests().unwrap().members().len(), 2);
        }
    }

    #[test]
    fn proper_subsets_require_state_but_complete_answers_do_not() {
        let original = request("tools/call", json!({"name":"echo"}), json!({"roots":{}}));
        for state in [None, Some("")] {
            let challenge = two_inputs(&original, state);
            assert!(matches!(validate_partial_responses(&challenge, &answers(json!({"one":{"roots":[]}}))),
                Err(ManagedInteractionError::PartialStateRequired)));
            assert!(validate_partial_responses(&challenge, &answers(json!({"one":{"roots":[]},"two":{"roots":[]}}))).is_ok());
        }
        // Opaque whitespace is not a missing handle and must not be trimmed.
        assert!(validate_partial_responses(&two_inputs(&original, Some(" ")), &answers(json!({"one":{"roots":[]}}))).is_ok());
    }

    #[test]
    fn partial_admission_rejects_empty_foreign_and_wrong_kind_answers() {
        let original = request("tools/call", json!({"name":"echo"}), json!({"roots":{}}));
        let challenge = two_inputs(&original, Some("state"));
        for wire in [json!({}), json!({"other":{"roots":[]}}), json!({"one":{"action":"decline"}}),
            json!({"one":{"roots":[]},"two":{"roots":[]},"other":{"roots":[]}})]
        {
            assert!(matches!(validate_partial_responses(&challenge, &answers(wire)),
                Err(ManagedInteractionError::InvalidInputResponses)));
            assert_eq!(challenge.request_state(), Some("state"));
            assert_eq!(challenge.input_requests().unwrap().members().len(), 2);
        }
        assert!(validate_partial_responses(&challenge, &answers(json!({"one":{"roots":[]}}))).is_ok());
    }

    #[test]
    fn partial_resume_never_synthesizes_state_only_or_empty_map_responses() {
        let original = request("tools/call", json!({"name":"echo"}), json!({}));
        for source in [r#"{"resultType":"input_required","requestState":"state"}"#,
            r#"{"resultType":"input_required","inputRequests":{},"requestState":"state"}"#]
        {
            let challenge = input(&original, source);
            assert!(validate_partial_responses(&challenge, &answers(json!({}))).is_err());
            assert!(validate_partial_responses(&challenge, &answers(json!({"one":{"roots":[]}}))).is_err());
        }
    }

    #[test]
    fn partial_round_uses_successor_state_and_does_not_resend_accepted_answers() {
        let original = request("tools/call", json!({"name":"echo"}), json!({"roots":{}}));
        let first = two_inputs(&original, Some("first-state"));
        let _ = continuation_request_selected(&original, &first,
            Some(answers(json!({"one":{"roots":[]}}))), InputSelection::Partial).unwrap();
        let second = input(&original, r#"{"resultType":"input_required","inputRequests":{"two":{"method":"roots/list"}},"requestState":"second-state"}"#);
        assert!(validate_partial_responses(&second, &answers(json!({"one":{"roots":[]}}))).is_err());
        let next = continuation_request_selected(&original, &second,
            Some(answers(json!({"two":{"roots":[]}}))), InputSelection::Partial).unwrap().encode_params().unwrap().unwrap();
        assert_eq!(next["requestState"], "second-state");
        assert_eq!(next["inputResponses"], json!({"two":{"roots":[]}}));
        let limits = ManagedInteractionLimits::new(ManagedCoreLimits::default(), 2, 2).unwrap();
        assert!(admit_challenge(&original, &second, limits, 1, 1).is_ok());
        assert!(matches!(admit_challenge(&original, &second, limits, 2, 1), Err(ManagedInteractionError::ContinuationLimit)));
        assert!(matches!(admit_challenge(&original, &second, limits, 1, 2), Err(ManagedInteractionError::InputLimit)));
    }

    #[test]
    fn partial_answer_wire_order_is_preserved_and_duplicate_keys_are_refused() {
        let original = request("tools/call", json!({"name":"echo"}), json!({"roots":{}}));
        let challenge = input(&original, r#"{"resultType":"input_required","inputRequests":{"a":{"method":"roots/list"},"m":{"method":"roots/list"},"z":{"method":"roots/list"}},"requestState":"state"}"#);
        let responses: FinalInputResponses = serde_json::from_str(r#"{"z":{"roots":[]},"a":{"roots":[]}}"#).unwrap();
        validate_partial_responses(&challenge, &responses).unwrap();
        assert_eq!(responses.entries().iter().map(|(name,_)| name.as_str()).collect::<Vec<_>>(), ["z","a"]);
        assert_eq!(serde_json::to_string(&responses).unwrap(), r#"{"z":{"roots":[]},"a":{"roots":[]}}"#);
        assert!(serde_json::from_str::<FinalInputResponses>(r#"{"z":{"roots":[]},"z":{"roots":[]}}"#).is_err());
    }
}
