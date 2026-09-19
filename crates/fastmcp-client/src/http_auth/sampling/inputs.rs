//! Resolve sampling-only MRTR challenges into exact, ordered response maps.
//!
//! Every descriptor and initial sampling conversation is admitted before the
//! first host callback. Mixed roots/elicitation batches are refused in full;
//! this helper never silently ignores a sibling or invents an answer for it.
//! The host still owns model disclosure, tool consent and capability admission.
//!
//! This produces the existing ManagedInputReply for explicit interaction
//! resumption. It does not send a POST, change the original request, copy or
//! replace requestState, or decide that a previous attempt may safely be retried.
//! ManagedInteraction::resume owns those checks and the exact opaque state.

/// Host-authorized mixed roots, elicitation and sampling input resolution.
pub mod mixed;

use std::fmt;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    FinalCreateMessageResult, FinalEmbeddedCreateMessageParams, FinalEmbeddedInputRequest,
    FinalEmbeddedInputResponse, FinalInputResponses, InputRequiredResult, RequestId,
    exact_json_to_serde,
};

use super::{
    SamplingContentBlock, SamplingHost, SamplingHostError, SamplingHostFuture,
    SamplingRunError, SamplingRunLimits, SamplingToolLoop, check, deadline,
    encoded_size, run_sampling_tool_loop, within,
};
use crate::http_auth::rpc::interaction::ManagedInputReply;

const MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;

/// Whole-challenge limits. Each individual conversation also retains `run`'s
/// own limits. Model calls, newly executed tools and encoded tool-result bytes
/// are additionally charged across all siblings, never reset per input key.
#[derive(Clone, Copy, Debug)]
pub struct SamplingInputLimits {
    run: SamplingRunLimits,
    inputs: usize,
    model_rounds: usize,
    tool_calls: usize,
    input_bytes: usize,
    reply_bytes: usize,
}

impl SamplingInputLimits {
    pub fn new(
        run: SamplingRunLimits,
        inputs: usize,
        model_rounds: usize,
        tool_calls: usize,
        input_bytes: usize,
        reply_bytes: usize,
    ) -> Result<Self, SamplingInputError> {
        if inputs > 128 || model_rounds > 1024 || tool_calls > 4096
            || !(2..=MAX_BATCH_BYTES).contains(&input_bytes)
            || !(2..=MAX_BATCH_BYTES).contains(&reply_bytes)
        {
            return Err(SamplingInputError::InvalidLimits);
        }
        Ok(Self { run, inputs, model_rounds, tool_calls, input_bytes, reply_bytes })
    }
}

impl Default for SamplingInputLimits {
    fn default() -> Self {
        Self {
            run: SamplingRunLimits::default(), inputs: 8, model_rounds: 64,
            tool_calls: 256, input_bytes: 4 * 1024 * 1024, reply_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Fixed diagnostics never retain a server-assigned key, requestState, model
/// request, result, schema, or host/provider error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SamplingInputError {
    InvalidLimits,
    InvalidRequestId,
    InvalidInput,
    UnsupportedInput,
    InputLimit,
    InputByteLimit,
    ReplyByteLimit,
    ModelRoundLimit,
    ToolCallLimit,
    ToolResultByteLimit,
    Run(SamplingRunError),
}

impl fmt::Display for SamplingInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sampling input resolution: {self:?}")
    }
}
impl std::error::Error for SamplingInputError {}
impl From<SamplingRunError> for SamplingInputError {
    fn from(error: SamplingRunError) -> Self { Self::Run(error) }
}

/// Resolves all sampling descriptors in one consumed input-required result.
///
/// Server-assigned response keys and their order are retained exactly. Absent
/// inputRequests produces absent inputResponses; a present empty map produces
/// a present empty map. Neither case invokes the model or tool host. Every
/// result is checked against the original descriptor map before being returned.
///
/// The host supplies a fresh outer request ID. Its correlation history and
/// original requestState remain with ManagedInteraction::resume, which must
/// still admit the returned reply. This function does not gain network authority
/// from accepting that ID. Host effects already performed cannot be undone if
/// a later sibling fails, so failures return no partial reply and never retry.
///
/// `run.timeout` covers the entire challenge, including every sibling's model
/// rounds. Dropping the future retires all pending host work and retained replies.
pub async fn resolve_sampling_inputs<H: SamplingHost + ?Sized>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    input: InputRequiredResult,
    request_id: RequestId,
    limits: SamplingInputLimits,
    host: &mut H,
) -> Result<ManagedInputReply, SamplingInputError> {
    request_id.validate().map_err(|_| SamplingInputError::InvalidRequestId)?;
    let end = deadline(cx, cancellation, limits.run.timeout)?;
    let Some(map) = input.input_requests() else {
        check(cx, cancellation, end)?;
        return Ok(ManagedInputReply { request_id, input_responses: None });
    };
    if map.members().len() > limits.inputs { return Err(SamplingInputError::InputLimit); }
    // At least one model call is necessary for every nonempty conversation.
    if map.members().len() > limits.model_rounds { return Err(SamplingInputError::ModelRoundLimit); }
    let mut requests = Vec::with_capacity(map.members().len());
    let mut input_bytes = 2_usize; // Braces, including the present-empty case.
    for (index, member) in map.members().iter().enumerate() {
        check(cx, cancellation, end)?;
        // ExactJsonObject is the protocol's bounded, duplicate-aware input
        // boundary. Conversion of one descriptor is therefore independently
        // bounded even before this smaller aggregate policy is enforced.
        let value = exact_json_to_serde(&member.value).map_err(|_| SamplingInputError::InvalidInput)?;
        let key_bytes = encoded_size(&member.name, limits.input_bytes - input_bytes)
            .map_err(|_| SamplingInputError::InputByteLimit)?;
        let value_bytes = encoded_size(&value, limits.input_bytes - input_bytes)
            .map_err(|_| SamplingInputError::InputByteLimit)?;
        input_bytes = input_bytes.checked_add(key_bytes).and_then(|n| n.checked_add(value_bytes))
            .and_then(|n| n.checked_add(1 + usize::from(index != 0)))
            .filter(|n| *n <= limits.input_bytes).ok_or(SamplingInputError::InputByteLimit)?;
        let descriptor: FinalEmbeddedInputRequest = serde_json::from_value(value)
            .map_err(|_| SamplingInputError::InvalidInput)?;
        let FinalEmbeddedInputRequest::Sampling(request) = descriptor else {
            return Err(SamplingInputError::UnsupportedInput);
        };
        // Fully validate later siblings now, not after an earlier model/tool
        // effect. The executing runner performs the same admission independently.
        SamplingToolLoop::new(request.clone(), limits.run.conversation)
            .map_err(SamplingRunError::from)?;
        requests.push((member.name.clone(), request));
    }
    check(cx, cancellation, end)?;
    let mut budgeted = BatchHost {
        host, models: limits.model_rounds, tools: limits.tool_calls,
        result_bytes: limits.run.tool_result_bytes, refusal: None,
    };
    // An outer guarded wait caps all nested runs at the original deadline.
    // The inner runner's per-conversation deadline can never extend this one.
    let outcome = within(cx, cancellation, end, async {
        let mut entries = Vec::with_capacity(requests.len());
        let mut reply_bytes = 2_usize;
        for (index, (key, request)) in requests.into_iter().enumerate() {
            let run = run_sampling_tool_loop(cx, cancellation, request, limits.run, &mut budgeted).await?;
            let key_bytes = encoded_size(&key, limits.reply_bytes - reply_bytes)?;
            let value_bytes = encoded_size(&run.response, limits.reply_bytes - reply_bytes)?;
            let Some(total) = reply_bytes.checked_add(key_bytes).and_then(|n| n.checked_add(value_bytes))
                .and_then(|n| n.checked_add(1 + usize::from(index != 0)))
                .filter(|n| *n <= limits.reply_bytes) else {
                return Err(SamplingRunError::ToolResultByteLimit);
            };
            reply_bytes = total;
            entries.push((key, FinalEmbeddedInputResponse::Sampling(run.response)));
        }
        Ok(entries)
    }).await;
    let entries = match outcome {
        Ok(entries) => entries,
        Err(error) => {
            // Host-budget refusals do not masquerade as provider failures. A
            // simultaneous timeout/cancellation still takes precedence.
            if matches!(error, SamplingRunError::Cancelled | SamplingRunError::TimedOut) {
                return Err(error.into());
            }
            if let Some(refusal) = budgeted.refusal { return Err(refusal); }
            if error == SamplingRunError::ToolResultByteLimit {
                return Err(SamplingInputError::ReplyByteLimit);
            }
            return Err(error.into());
        }
    };
    let responses = FinalInputResponses::try_from_entries(entries)
        .map_err(|_| SamplingInputError::InvalidInput)?;
    responses.validate_against_input_required(&input).map_err(|_| SamplingInputError::InvalidInput)?;
    check(cx, cancellation, end)?;
    Ok(ManagedInputReply { request_id, input_responses: Some(responses) })
}

struct BatchHost<'a, H: ?Sized> {
    host: &'a mut H,
    models: usize,
    tools: usize,
    result_bytes: usize,
    refusal: Option<SamplingInputError>,
}

impl<H: SamplingHost + ?Sized> SamplingHost for BatchHost<'_, H> {
    fn sample<'a>(
        &'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedCreateMessageParams,
    ) -> SamplingHostFuture<'a, FinalCreateMessageResult> {
        if self.models == 0 {
            self.refusal = Some(SamplingInputError::ModelRoundLimit);
            return Box::pin(std::future::ready(Err(SamplingHostError::Failed)));
        }
        self.models -= 1;
        self.host.sample(cx, cancellation, request)
    }

    fn approve_tools<'a>(
        &'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        calls: &'a [SamplingContentBlock],
    ) -> SamplingHostFuture<'a, ()> {
        // A tool batch must fit in full and leave a model round to consume its
        // results before even the host approval callback can run.
        let refusal = if self.models == 0 { Some(SamplingInputError::ModelRoundLimit) }
            else if calls.len() > self.tools { Some(SamplingInputError::ToolCallLimit) }
            else { None };
        if let Some(refusal) = refusal {
            self.refusal = Some(refusal);
            return Box::pin(std::future::ready(Err(SamplingHostError::Failed)));
        }
        self.host.approve_tools(cx, cancellation, calls)
    }

    fn execute_tool<'a>(
        &'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        call: &'a SamplingContentBlock,
    ) -> SamplingHostFuture<'a, SamplingContentBlock> {
        if self.tools == 0 {
            self.refusal = Some(SamplingInputError::ToolCallLimit);
            return Box::pin(std::future::ready(Err(SamplingHostError::Failed)));
        }
        self.tools -= 1;
        Box::pin(async move {
            let result = self.host.execute_tool(cx, cancellation, call).await?;
            match encoded_size(&result, self.result_bytes) {
                Ok(bytes) => self.result_bytes -= bytes,
                Err(SamplingRunError::ToolResultByteLimit) => {
                    self.refusal = Some(SamplingInputError::ToolResultByteLimit);
                    return Err(SamplingHostError::Failed);
                }
                Err(_) => return Err(SamplingHostError::Failed),
            }
            Ok(result)
        })
    }
}
