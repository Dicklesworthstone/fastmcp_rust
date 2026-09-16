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
use fastmcp_protocol::result::exact_json_to_serde;
use fastmcp_protocol::{
    CoreRequest, CoreResult, FinalCoreRequest, FinalCoreResult,
    FinalEmbeddedElicitationParams, FinalEmbeddedInputRequest, FinalInputResponses,
    InputRequiredResult, RequestId, ServerNotification, FINAL_CLIENT_CAPABILITIES_META_KEY,
};

use super::{
    ManagedCoreCall, ManagedCoreError, ManagedCoreEvent, ManagedCoreLimits,
    ManagedOAuthSession, bounded_wait, call_deadline, check_call, prepare,
};

const MAX_INPUTS_PER_ROUND: usize = 128;

/// Limits for the whole interaction, not a fresh budget for each retry.
/// `core.total_bytes`, `core.notifications` and `core.timeout` are shared by
/// every round. `core.request_bytes` and `core.frame_bytes` apply per request
/// and frame. At most `max_continuations + 1` POSTs can ever be attempted.
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
        mut self,
        cx: &Cx,
        mut resolve: R,
        mut notify: N,
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
                    self.resume(cx, reply.request_id, reply.input_responses).await?;
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
        let next = continuation_request(&self.original, input, responses)?;
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

fn validate_initial(request: &CoreRequest) -> Result<(), ManagedInteractionError> {
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

fn input_required(result: &CoreResult) -> Option<&InputRequiredResult> {
    match result {
        CoreResult::Final(
            FinalCoreResult::ToolsCallInputRequired { result, .. }
            | FinalCoreResult::ResourcesReadInputRequired { result, .. }
            | FinalCoreResult::PromptsGetInputRequired { result, .. },
        ) => Some(result),
        _ => None,
    }
}

fn admit_fresh_id(previous: &[RequestId], next: &RequestId) -> Result<(), ManagedInteractionError> {
    next.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
    if previous.iter().any(|id| id.correlates_with(next)) {
        return Err(ManagedInteractionError::RepeatedRequestId);
    }
    Ok(())
}

fn admit_challenge(
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
        let descriptor: FinalEmbeddedInputRequest = serde_json::from_value(value.clone())
            .map_err(|_| ManagedCoreError::InvalidResult)?;
        let advertised = match descriptor {
            FinalEmbeddedInputRequest::Roots(_) => capabilities.get("roots").is_some_and(serde_json::Value::is_object),
            FinalEmbeddedInputRequest::Sampling(_) => {
                let sampling = &capabilities["sampling"];
                sampling.is_object()
                    && (value["params"].get("tools").is_none() || sampling.get("tools").is_some_and(serde_json::Value::is_object))
                    && (value["params"].get("includeContext").is_none_or(|context| context == "none")
                        || sampling.get("context").is_some_and(serde_json::Value::is_object))
            }
            FinalEmbeddedInputRequest::Elicitation(FinalEmbeddedElicitationParams::Form(_)) => {
                capabilities["elicitation"].get("form").is_some_and(serde_json::Value::is_object)
            }
            FinalEmbeddedInputRequest::Elicitation(FinalEmbeddedElicitationParams::Url(_)) => {
                capabilities["elicitation"].get("url").is_some_and(serde_json::Value::is_object)
            }
        };
        if !advertised { return Err(ManagedInteractionError::CapabilityNotAdvertised); }
    }
    Ok(())
}

fn continuation_request(
    original: &CoreRequest,
    input: &InputRequiredResult,
    responses: Option<FinalInputResponses>,
) -> Result<CoreRequest, ManagedInteractionError> {
    match (input.input_requests(), responses.as_ref()) {
        (None, None) => {},
        (Some(_), Some(responses)) => responses.validate_against_input_required(input)
            .map_err(|_| ManagedInteractionError::InvalidInputResponses)?,
        _ => return Err(ManagedInteractionError::InvalidInputResponses),
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
}
