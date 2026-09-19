//! Typed, host-authorized resolution of mixed final MRTR input batches.
//!
//! Roots, form/URL elicitation and sampling share one preflight, approval and
//! deadline. Sampling retains the existing tool-loop and whole-batch budgets.
//! This module neither sends a continuation nor treats a failed effect as a
//! retry signal. The original interaction still owns requestState and ID history.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::common_types::AbsoluteUri;
use fastmcp_protocol::{
    AdmittedSchema, CoreRequest, ElicitContentValue, FinalEmbeddedElicitationParams,
    FinalEmbeddedElicitationResult, FinalEmbeddedFormElicitationParams,
    FinalEmbeddedInputRequest, FinalEmbeddedInputResponse, FinalEmbeddedRootsListParams,
    FinalEmbeddedRootsListResult, FinalEmbeddedUrlElicitationParams, FinalInputResponses,
    InputRequiredResult, RequestId, admit_final_schema, exact_json_to_serde,
};

use super::{BatchHost, SamplingInputError, SamplingInputLimits};
use super::super::{
    SamplingHost, SamplingRunError, SamplingToolLoop, check, cooperate, deadline,
    encoded_size, run_sampling_tool_loop, within,
};
use crate::http_auth::rpc::ManagedCoreLimits;
use crate::http_auth::rpc::interaction::{
    ManagedInputReply, ManagedInteractionError, ManagedInteractionLimits,
    admit_challenge, validate_initial, validate_partial_responses,
};

/// No host error carries user input, model output, URLs or provider diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreInputHostError { Denied, Failed }

/// A borrowing, caller-owned host operation. No worker or runtime is created.
pub type CoreInputHostFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, CoreInputHostError>> + Send + 'a>>;

/// One immutable, preflighted descriptor, in its received map order.
/// The key is a correlation identity, not authority to access a resource.
pub struct CoreInputRequest {
    key: String,
    descriptor: FinalEmbeddedInputRequest,
    form_schema: Option<AdmittedSchema>,
}
impl CoreInputRequest {
    pub fn key(&self) -> &str { &self.key }
    pub fn descriptor(&self) -> &FinalEmbeddedInputRequest { &self.descriptor }
}

/// The host supplies all disclosure, UI, model and tool authority. Approval is
/// for the complete selected batch and happens before its first input effect.
/// Each effect must still recheck revocable host authority at its own boundary.
///
/// Form decline/cancel and URL accept/decline/cancel are ordinary typed replies,
/// not host failures. URL acceptance means the host obtained navigation consent;
/// it does not assert that the external workflow completed. The framework never
/// opens that URL, invents roots, supplies default form values, or selects a model.
/// Futures must cooperate with cancellation and may not hide blocking work or
/// detached children. Host-owned allocations before return are outside the
/// framework's retained-reply bounds.
pub trait CoreInputHost: SamplingHost {
    fn approve_inputs<'a>(
        &'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        requests: &'a [CoreInputRequest],
    ) -> CoreInputHostFuture<'a, ()>;

    fn roots<'a>(
        &'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedRootsListParams,
    ) -> CoreInputHostFuture<'a, FinalEmbeddedRootsListResult>;

    fn form<'a>(
        &'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedFormElicitationParams,
    ) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>;

    fn url<'a>(
        &'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedUrlElicitationParams,
    ) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>;
}

/// `sampling.inputs/input_bytes/reply_bytes` bound the entire mixed batch;
/// model/tool counters apply cumulatively to all sampling siblings. Roots and
/// submitted form fields are additionally bounded across all input responses.
#[derive(Clone, Copy, Debug)]
pub struct CoreInputLimits {
    sampling: SamplingInputLimits,
    roots: usize,
    form_fields: usize,
}
impl Default for CoreInputLimits {
    fn default() -> Self {
        Self { sampling: SamplingInputLimits::default(), roots: 256, form_fields: 256 }
    }
}
impl CoreInputLimits {
    pub fn new(sampling: SamplingInputLimits, roots: usize, form_fields: usize)
        -> Result<Self, CoreInputError>
    {
        if roots > 4096 || form_fields > 4096 { return Err(CoreInputError::InvalidLimits); }
        Ok(Self { sampling, roots, form_fields })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreInputStage { Approval, Roots, Form, Url }

/// Fixed diagnostics; failed batches return no accumulated answers. A failure
/// after a host effect cannot undo it and never authorizes automatic replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreInputError {
    InvalidLimits,
    InvalidRequest,
    InvalidInput,
    InvalidSelection,
    PartialStateRequired,
    CapabilityNotAdvertised,
    InputLimit,
    InputByteLimit,
    ReplyByteLimit,
    RootLimit,
    FormFieldLimit,
    InvalidResponse,
    InvalidFormContent,
    Host { stage: CoreInputStage, reason: CoreInputHostError },
    Sampling(SamplingInputError),
}
impl fmt::Display for CoreInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "core input resolution: {self:?}")
    }
}
impl std::error::Error for CoreInputError {}
impl From<SamplingRunError> for CoreInputError {
    fn from(error: SamplingRunError) -> Self { Self::Sampling(error.into()) }
}

/// Resolve one complete mixed challenge into the existing typed reply map.
///
/// All descriptors, advertised capabilities, sampling histories/tool schemas,
/// and form schemas are admitted before even the approval callback. Responses
/// retain exact keys and received order. Absence and a present-empty input map
/// remain distinct and invoke no host. Accepted form data is schema-validated;
/// declined/dismissed forms have no content. Roots must be structural file URIs.
///
/// Supply the interaction's original CoreRequest and a fresh request ID. This
/// helper does not own correlation history or requestState: the returned reply
/// must still pass `resume` on that SAME interaction. For machine OAuth, supply
/// its separate fresh discovery ID to the machine interaction's resume method.
/// Nothing is dispatched here. Host answers are ordinary owned Rust values;
/// this interface makes no heap-wide zeroization or durable-recovery claim.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_core_inputs<H: CoreInputHost + ?Sized>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    original: &CoreRequest,
    input: InputRequiredResult,
    request_id: RequestId,
    limits: CoreInputLimits,
    host: &mut H,
) -> Result<ManagedInputReply, CoreInputError> {
    resolve_selection(cx, cancellation, original, input, request_id, limits, None, host).await
}

/// Resolve only an explicitly selected nonempty set of input keys. Every
/// descriptor is still admitted before approval, but approval and callbacks
/// receive only the selection, in SERVER map order rather than caller order.
/// Omitted inputs perform no host work and consume no model/tool budget.
///
/// A proper subset requires a nonempty server requestState. Resume the SAME
/// interaction with `resume_partial`; do not assemble or alter continuation
/// state yourself. An all-key selection is also accepted without requestState.
/// Empty, duplicated, or unknown selections fail before host callbacks.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_selected_core_inputs<H: CoreInputHost + ?Sized>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    original: &CoreRequest,
    input: InputRequiredResult,
    request_id: RequestId,
    limits: CoreInputLimits,
    keys: &[&str],
    host: &mut H,
) -> Result<ManagedInputReply, CoreInputError> {
    resolve_selection(cx, cancellation, original, input, request_id, limits, Some(keys), host).await
}

#[allow(clippy::too_many_arguments)]
async fn resolve_selection<H: CoreInputHost + ?Sized>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    original: &CoreRequest,
    input: InputRequiredResult,
    request_id: RequestId,
    limits: CoreInputLimits,
    keys: Option<&[&str]>,
    host: &mut H,
) -> Result<ManagedInputReply, CoreInputError> {
    request_id.validate().map_err(|_| CoreInputError::InvalidRequest)?;
    validate_initial(original).map_err(|_| CoreInputError::InvalidRequest)?;
    let end = deadline(cx, cancellation, limits.sampling.run.timeout)?;
    if let Some(keys) = keys {
        let map = input.input_requests().ok_or(CoreInputError::InvalidSelection)?;
        if keys.is_empty() || keys.len() > limits.sampling.inputs || keys.len() > map.members().len() {
            return Err(CoreInputError::InvalidSelection);
        }
        for (index, key) in keys.iter().enumerate() {
            if keys[..index].contains(key) || map.get(key).is_none() {
                return Err(CoreInputError::InvalidSelection);
            }
        }
        if keys.len() < map.members().len() && input.request_state().is_none_or(str::is_empty) {
            return Err(CoreInputError::PartialStateRequired);
        }
    }
    let admission = ManagedInteractionLimits::new(ManagedCoreLimits::default(), 1, limits.sampling.inputs)
        .map_err(|_| CoreInputError::InvalidLimits)?;
    admit_challenge(original, &input, admission, 0, 0).map_err(|error| match error {
        ManagedInteractionError::CapabilityNotAdvertised => CoreInputError::CapabilityNotAdvertised,
        ManagedInteractionError::InputLimit => CoreInputError::InputLimit,
        _ => CoreInputError::InvalidInput,
    })?;
    let Some(map) = input.input_requests() else {
        check(cx, cancellation, end)?;
        return Ok(ManagedInputReply { request_id, input_responses: None });
    };
    let mut requests = Vec::with_capacity(map.members().len());
    let mut input_bytes = 2;
    let mut minimum_reply_bytes = 2;
    let mut sampling_count = 0;
    for (index, member) in map.members().iter().enumerate() {
        check(cx, cancellation, end)?;
        let value = exact_json_to_serde(&member.value).map_err(|_| CoreInputError::InvalidInput)?;
        let key_bytes = encoded_size(&member.name, limits.sampling.input_bytes)
            .map_err(|_| CoreInputError::InputByteLimit)?;
        let value_bytes = encoded_size(&value, limits.sampling.input_bytes)
            .map_err(|_| CoreInputError::InputByteLimit)?;
        input_bytes = member_bytes(input_bytes, key_bytes, value_bytes, index != 0, limits.sampling.input_bytes)
            .ok_or(CoreInputError::InputByteLimit)?;
        let selected = keys.is_none_or(|keys| keys.contains(&member.name.as_str()));
        // Every response needs at least an object. Refuse an impossible map
        // before asking a host to perform effects whose answers cannot fit.
        if selected {
            minimum_reply_bytes = member_bytes(minimum_reply_bytes, key_bytes, 2, !requests.is_empty(), limits.sampling.reply_bytes)
                .ok_or(CoreInputError::ReplyByteLimit)?;
        }
        let descriptor: FinalEmbeddedInputRequest = serde_json::from_value(value)
            .map_err(|_| CoreInputError::InvalidInput)?;
        let form_schema = match &descriptor {
            FinalEmbeddedInputRequest::Sampling(request) => {
                sampling_count += usize::from(selected);
                SamplingToolLoop::new(request.clone(), limits.sampling.run.conversation)
                    .map_err(SamplingRunError::from)?;
                None
            }
            FinalEmbeddedInputRequest::Elicitation(FinalEmbeddedElicitationParams::Form(request)) => {
                Some(admit_final_schema(request.requested_schema.schema().clone())
                    .map_err(|_| CoreInputError::InvalidInput)?)
            }
            _ => None,
        };
        if selected {
            requests.push(CoreInputRequest { key: member.name.clone(), descriptor, form_schema });
        }
    }
    if sampling_count > limits.sampling.model_rounds {
        return Err(CoreInputError::Sampling(SamplingInputError::ModelRoundLimit));
    }
    check(cx, cancellation, end)?;
    let mut budgeted = BatchHost {
        host, models: limits.sampling.model_rounds, tools: limits.sampling.tool_calls,
        result_bytes: limits.sampling.run.tool_result_bytes, refusal: None,
    };
    // Nest the typed result so the existing guard retains its cancellation and
    // deadline precedence without disguising input-specific errors as sampling.
    let entries = within(cx, cancellation, end, async {
        Ok(async {
            if !requests.is_empty() {
                budgeted.host.approve_inputs(cx, cancellation, &requests).await
                    .map_err(|reason| CoreInputError::Host { stage: CoreInputStage::Approval, reason })?;
            }
            let mut entries = Vec::with_capacity(requests.len());
            let mut reply_bytes = 2;
            let mut roots = 0;
            let mut fields = 0;
            for request in &requests {
                cooperate(cx, cancellation, end).await?;
                let response = match &request.descriptor {
                    FinalEmbeddedInputRequest::Sampling(params) => {
                        let result = run_sampling_tool_loop(cx, cancellation, params.clone(), limits.sampling.run, &mut budgeted).await;
                        let result = result.map_err(|error| {
                            if matches!(error, SamplingRunError::Cancelled | SamplingRunError::TimedOut) {
                                CoreInputError::from(error)
                            } else if let Some(refusal) = budgeted.refusal {
                                CoreInputError::Sampling(refusal)
                            } else { CoreInputError::from(error) }
                        })?;
                        FinalEmbeddedInputResponse::Sampling(result.response)
                    }
                    FinalEmbeddedInputRequest::Roots(params) => {
                        let result = budgeted.host.roots(cx, cancellation, params).await
                            .map_err(|reason| CoreInputError::Host { stage: CoreInputStage::Roots, reason })?;
                        roots = add_count(roots, result.roots.len(), limits.roots).ok_or(CoreInputError::RootLimit)?;
                        FinalEmbeddedInputResponse::Roots(result)
                    }
                    FinalEmbeddedInputRequest::Elicitation(FinalEmbeddedElicitationParams::Form(params)) => {
                        let result = budgeted.host.form(cx, cancellation, params).await
                            .map_err(|reason| CoreInputError::Host { stage: CoreInputStage::Form, reason })?;
                        fields = add_count(fields, result.content.as_ref().map_or(0, std::collections::BTreeMap::len), limits.form_fields)
                            .ok_or(CoreInputError::FormFieldLimit)?;
                        FinalEmbeddedInputResponse::Elicitation(result)
                    }
                    FinalEmbeddedInputRequest::Elicitation(FinalEmbeddedElicitationParams::Url(params)) => {
                        FinalEmbeddedInputResponse::Elicitation(budgeted.host.url(cx, cancellation, params).await
                            .map_err(|reason| CoreInputError::Host { stage: CoreInputStage::Url, reason })?)
                    }
                };
                check(cx, cancellation, end)?;
                let key_bytes = encoded_size(&request.key, limits.sampling.reply_bytes)
                    .map_err(|_| CoreInputError::ReplyByteLimit)?;
                let value_bytes = encoded_size(&response, limits.sampling.reply_bytes - reply_bytes)
                    .map_err(|_| CoreInputError::ReplyByteLimit)?;
                reply_bytes = member_bytes(reply_bytes, key_bytes, value_bytes, !entries.is_empty(), limits.sampling.reply_bytes)
                    .ok_or(CoreInputError::ReplyByteLimit)?;
                validate_response(request, &response)?;
                check(cx, cancellation, end)?;
                entries.push((request.key.clone(), response));
            }
            Ok::<_, CoreInputError>(entries)
        }.await)
    }).await??;
    let responses = FinalInputResponses::try_from_entries(entries).map_err(|_| CoreInputError::InvalidResponse)?;
    if keys.is_some() {
        validate_partial_responses(&input, &responses).map_err(|_| CoreInputError::InvalidResponse)?;
    } else {
        responses.validate_against_input_required(&input).map_err(|_| CoreInputError::InvalidResponse)?;
    }
    check(cx, cancellation, end)?;
    Ok(ManagedInputReply { request_id, input_responses: Some(responses) })
}

fn add_count(current: usize, added: usize, limit: usize) -> Option<usize> {
    current.checked_add(added).filter(|total| *total <= limit)
}
fn member_bytes(current: usize, key: usize, value: usize, comma: bool, limit: usize) -> Option<usize> {
    current.checked_add(key)?.checked_add(value)?.checked_add(1 + usize::from(comma))
        .filter(|total| *total <= limit)
}
fn validate_response(request: &CoreInputRequest, response: &FinalEmbeddedInputResponse) -> Result<(), CoreInputError> {
    if !response.matches_kind(request.descriptor.response_kind()) { return Err(CoreInputError::InvalidResponse); }
    if let FinalEmbeddedInputResponse::Roots(result) = response {
        for root in &result.roots {
            let uri = AbsoluteUri::parse(root.uri.clone()).map_err(|_| CoreInputError::InvalidResponse)?;
            if !uri.has_scheme("file") { return Err(CoreInputError::InvalidResponse); }
        }
    }
    if let (Some(schema), FinalEmbeddedInputResponse::Elicitation(result)) = (&request.form_schema, response) {
        if let Some(content) = &result.content {
            // serde_json encodes a nonfinite f64 as null. Do not silently turn
            // a locally authored invalid number into a different user's answer.
            if content.values().any(|value| matches!(value, ElicitContentValue::Float(number) if !number.is_finite())) {
                return Err(CoreInputError::InvalidFormContent);
            }
            let value = serde_json::to_value(content).map_err(|_| CoreInputError::InvalidFormContent)?;
            schema.validate(&value).map_err(|_| CoreInputError::InvalidFormContent)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
