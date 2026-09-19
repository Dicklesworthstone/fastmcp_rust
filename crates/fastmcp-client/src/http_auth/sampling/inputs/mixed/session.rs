//! One host-input budget across a complete multi-round interaction.
//!
//! The one-challenge helpers remain useful on their own, but calling them with
//! fresh limits for every successor does not enforce a whole-operation cost.
//! This owner keeps the original request, deadline and counters across rounds.
//! It never posts a continuation or interprets a lost reply as retry authority.

use std::fmt;

use asupersync::{Cx, Time};
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    CoreRequest, FinalCreateMessageResult, FinalEmbeddedCreateMessageParams,
    FinalEmbeddedElicitationResult, FinalEmbeddedFormElicitationParams,
    FinalEmbeddedRootsListParams, FinalEmbeddedRootsListResult,
    FinalEmbeddedUrlElicitationParams, InputRequiredResult, RequestId,
};
use fastmcp_protocol::common_types::SamplingContentBlock;

use super::{
    CoreInputError, CoreInputHost, CoreInputHostError, CoreInputHostFuture,
    CoreInputLimits, CoreInputRequest, ManagedInputReply, SamplingInputError,
    SamplingRunError, check, deadline, encoded_size, exact_json_to_serde,
    member_bytes, resolve_selection, validate_initial, within,
};
use crate::http_auth::sampling::{SamplingHost, SamplingHostError, SamplingHostFuture};

/// Non-secret cumulative usage. Input selections and model/tool invocations
/// are charged before entering the host, including a subsequently denied call.
/// Byte/root/field counts describe admitted values, not allocations hidden
/// inside the application host or rejected oversized host values.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoreInputUsage {
    pub resolutions: usize,
    pub selected_inputs: usize,
    pub model_rounds: usize,
    pub tool_calls: usize,
    pub input_bytes: usize,
    pub reply_bytes: usize,
    pub tool_result_bytes: usize,
    pub roots: usize,
    pub form_fields: usize,
}

/// No error retains the original request, input keys, answers or host text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreInputSessionError {
    InvalidLimits,
    Closed,
    ResolutionLimit,
    RepeatedRequestId,
    Input(CoreInputError),
}
impl fmt::Display for CoreInputSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid core input session limits"),
            Self::Closed => f.write_str("core input session is closed"),
            Self::ResolutionLimit => f.write_str("core input session resolution limit exceeded"),
            Self::RepeatedRequestId => f.write_str("core input session requires a fresh request ID"),
            Self::Input(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for CoreInputSessionError {}
impl From<CoreInputError> for CoreInputSessionError {
    fn from(error: CoreInputError) -> Self { Self::Input(error) }
}
impl From<SamplingRunError> for CoreInputSessionError {
    fn from(error: SamplingRunError) -> Self { Self::Input(error.into()) }
}

/// Non-Clone host-input custody for one immutable original request.
///
/// `limits` now apply across ALL resolutions, including selected inputs, model
/// calls, tool calls/results, descriptor/reply bytes, roots and form fields.
/// The conversation sublimits still apply to each individual sampling loop.
/// All descriptors of an observed challenge count toward input bytes, even
/// omitted siblings; only selected inputs consume the selected-input budget.
/// The original timeout includes pauses between calls, not just host execution.
///
/// Every failed or abandoned polled resolution permanently closes this owner.
/// It cannot re-enter a host to reconstruct answers lost after an earlier effect.
/// Successful answers are not retained or automatically resubmitted. Keep this
/// owner paired with one interaction: it does not replace the interaction's
/// request-ID ledger, original credentials, or server continuation authority.
pub struct CoreInputSession {
    original: CoreRequest,
    cancellation: McpRequestCancellation,
    deadline: Time,
    limits: CoreInputLimits,
    maximum_resolutions: usize,
    used_ids: Vec<RequestId>,
    usage: CoreInputUsage,
    closed: bool,
}
impl fmt::Debug for CoreInputSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreInputSession").field("usage", &self.usage)
            .field("closed", &self.closed).finish_non_exhaustive()
    }
}
impl CoreInputSession {
    /// Binds policy without invoking any host or network operation. At most 64
    /// resolutions can be admitted; zero selects no input-resolution authority.
    pub fn new(
        cx: &Cx, cancellation: &McpRequestCancellation, original: CoreRequest,
        limits: CoreInputLimits, maximum_resolutions: usize,
    ) -> Result<Self, CoreInputSessionError> {
        if maximum_resolutions > 64 { return Err(CoreInputSessionError::InvalidLimits); }
        validate_initial(&original).map_err(|_| CoreInputError::InvalidRequest)?;
        let end = deadline(cx, cancellation, limits.sampling.run.timeout)?;
        let end = cx.budget().deadline.map_or(end, |caller| caller.min(end));
        Ok(Self {
            original, cancellation: cancellation.clone(), deadline: end, limits,
            maximum_resolutions, used_ids: Vec::new(), usage: CoreInputUsage::default(), closed: false,
        })
    }

    pub fn usage(&self) -> CoreInputUsage { self.usage }
    pub fn is_closed(&self) -> bool { self.closed }
    /// Local closure does not cancel a sibling, revoke credentials, or change
    /// server state. Drop this owner to release its retained original request.
    pub fn close(&mut self) { self.closed = true; }

    pub async fn resolve<H: CoreInputHost + ?Sized>(
        &mut self, cx: &Cx, input: InputRequiredResult, request_id: RequestId, host: &mut H,
    ) -> Result<ManagedInputReply, CoreInputSessionError> {
        self.resolve_inner(cx, input, request_id, None, host).await
    }

    /// Selects inputs using the same preflight, ordering and nonempty-state
    /// requirements as `resolve_selected_core_inputs`. Omitted callbacks are
    /// never invoked, and their model/tool budgets are not charged.
    pub async fn resolve_selected<H: CoreInputHost + ?Sized>(
        &mut self, cx: &Cx, input: InputRequiredResult, request_id: RequestId,
        keys: &[&str], host: &mut H,
    ) -> Result<ManagedInputReply, CoreInputSessionError> {
        self.resolve_inner(cx, input, request_id, Some(keys), host).await
    }

    async fn resolve_inner<H: CoreInputHost + ?Sized>(
        &mut self, cx: &Cx, input: InputRequiredResult, request_id: RequestId,
        keys: Option<&[&str]>, host: &mut H,
    ) -> Result<ManagedInputReply, CoreInputSessionError> {
        if self.closed { return Err(CoreInputSessionError::Closed); }
        // Election precedes every possible callback/suspension. Errors and
        // abandonment cannot restore a host effect's replay authority.
        self.closed = true;
        check(cx, &self.cancellation, self.deadline)?;
        request_id.validate().map_err(|_| CoreInputError::InvalidRequest)?;
        if self.used_ids.iter().any(|id| id.correlates_with(&request_id)) {
            return Err(CoreInputSessionError::RepeatedRequestId);
        }
        if self.usage.resolutions >= self.maximum_resolutions {
            return Err(CoreInputSessionError::ResolutionLimit);
        }
        let mut remaining = self.limits;
        remaining.sampling.model_rounds -= self.usage.model_rounds;
        remaining.sampling.tool_calls -= self.usage.tool_calls;
        remaining.sampling.input_bytes -= self.usage.input_bytes;
        remaining.sampling.reply_bytes -= self.usage.reply_bytes;
        remaining.sampling.run.tool_result_bytes -= self.usage.tool_result_bytes;
        remaining.roots -= self.usage.roots;
        remaining.form_fields -= self.usage.form_fields;
        // The existing policy constructor admits at least two bytes per map.
        // Remaining session capacity may be smaller, so guard empty maps too.
        if input.input_requests().is_some() {
            if remaining.sampling.input_bytes < 2 { return Err(CoreInputError::InputByteLimit.into()); }
            if remaining.sampling.reply_bytes < 2 { return Err(CoreInputError::ReplyByteLimit.into()); }
        }
        let input_bytes = input_size(&input, remaining.sampling.input_bytes)?;
        let selected = keys.map_or_else(|| input.input_requests().map_or(0, |map| map.members().len()), <[&str]>::len);
        if selected > self.limits.sampling.inputs - self.usage.selected_inputs {
            return Err(CoreInputError::InputLimit.into());
        }
        self.usage.resolutions += 1;
        self.usage.input_bytes += input_bytes;
        self.used_ids.push(request_id.clone());
        let mut budgeted = SessionHost { host, usage: &mut self.usage, limits: self.limits, refusal: None };
        let reply = within(cx, &self.cancellation, self.deadline, async {
            Ok(resolve_selection(cx, &self.cancellation, &self.original, input,
                request_id, remaining, keys, &mut budgeted).await)
        }).await?;
        let reply = match reply {
            Ok(reply) => reply,
            Err(error) => {
                if matches!(error, CoreInputError::Sampling(SamplingInputError::Run(
                    SamplingRunError::Cancelled | SamplingRunError::TimedOut))) {
                    return Err(error.into());
                }
                return Err(budgeted.refusal.unwrap_or(error).into());
            }
        };
        let bytes = match &reply.input_responses {
            Some(responses) => encoded_size(responses, remaining.sampling.reply_bytes)
                .map_err(|_| CoreInputError::ReplyByteLimit)?,
            None => 0,
        };
        check(cx, &self.cancellation, self.deadline)?;
        self.usage.reply_bytes += bytes;
        self.closed = false;
        Ok(reply)
    }
}

fn input_size(input: &InputRequiredResult, maximum: usize) -> Result<usize, CoreInputError> {
    let Some(map) = input.input_requests() else { return Ok(0); };
    let mut total = 2;
    for (index, member) in map.members().iter().enumerate() {
        let value = exact_json_to_serde(&member.value).map_err(|_| CoreInputError::InvalidInput)?;
        let key = encoded_size(&member.name, maximum).map_err(|_| CoreInputError::InputByteLimit)?;
        let value = encoded_size(&value, maximum).map_err(|_| CoreInputError::InputByteLimit)?;
        total = member_bytes(total, key, value, index != 0, maximum).ok_or(CoreInputError::InputByteLimit)?;
    }
    Ok(total)
}

struct SessionHost<'a, H: ?Sized> {
    host: &'a mut H,
    usage: &'a mut CoreInputUsage,
    limits: CoreInputLimits,
    refusal: Option<CoreInputError>,
}
impl<H: CoreInputHost + ?Sized> SamplingHost for SessionHost<'_, H> {
    fn sample<'a>(&'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedCreateMessageParams) -> SamplingHostFuture<'a, FinalCreateMessageResult>
    {
        if self.usage.model_rounds >= self.limits.sampling.model_rounds {
            self.refusal = Some(CoreInputError::Sampling(SamplingInputError::ModelRoundLimit));
            return Box::pin(std::future::ready(Err(SamplingHostError::Failed)));
        }
        self.usage.model_rounds += 1;
        self.host.sample(cx, cancellation, request)
    }
    fn approve_tools<'a>(&'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        calls: &'a [SamplingContentBlock]) -> SamplingHostFuture<'a, ()>
    {
        let refusal = if self.usage.model_rounds >= self.limits.sampling.model_rounds {
            Some(SamplingInputError::ModelRoundLimit)
        } else if calls.len() > self.limits.sampling.tool_calls - self.usage.tool_calls {
            Some(SamplingInputError::ToolCallLimit)
        } else if self.usage.tool_result_bytes >= self.limits.sampling.run.tool_result_bytes {
            Some(SamplingInputError::ToolResultByteLimit)
        } else { None };
        if let Some(refusal) = refusal {
            self.refusal = Some(CoreInputError::Sampling(refusal));
            return Box::pin(std::future::ready(Err(SamplingHostError::Failed)));
        }
        self.host.approve_tools(cx, cancellation, calls)
    }
    fn execute_tool<'a>(&'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        call: &'a SamplingContentBlock) -> SamplingHostFuture<'a, SamplingContentBlock>
    {
        if self.usage.tool_calls >= self.limits.sampling.tool_calls {
            self.refusal = Some(CoreInputError::Sampling(SamplingInputError::ToolCallLimit));
            return Box::pin(std::future::ready(Err(SamplingHostError::Failed)));
        }
        self.usage.tool_calls += 1;
        Box::pin(async move {
            let result = self.host.execute_tool(cx, cancellation, call).await?;
            let maximum = self.limits.sampling.run.tool_result_bytes - self.usage.tool_result_bytes;
            let bytes = encoded_size(&result, maximum).map_err(|_| {
                self.refusal = Some(CoreInputError::Sampling(SamplingInputError::ToolResultByteLimit));
                SamplingHostError::Failed
            })?;
            self.usage.tool_result_bytes += bytes;
            Ok(result)
        })
    }
}
impl<H: CoreInputHost + ?Sized> CoreInputHost for SessionHost<'_, H> {
    fn approve_inputs<'a>(&'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        requests: &'a [CoreInputRequest]) -> CoreInputHostFuture<'a, ()>
    {
        if requests.len() > self.limits.sampling.inputs - self.usage.selected_inputs {
            self.refusal = Some(CoreInputError::InputLimit);
            return Box::pin(std::future::ready(Err(CoreInputHostError::Failed)));
        }
        self.usage.selected_inputs += requests.len();
        self.host.approve_inputs(cx, cancellation, requests)
    }
    fn roots<'a>(&'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedRootsListParams) -> CoreInputHostFuture<'a, FinalEmbeddedRootsListResult>
    {
        Box::pin(async move {
            let result = self.host.roots(cx, cancellation, request).await?;
            if result.roots.len() > self.limits.roots - self.usage.roots {
                self.refusal = Some(CoreInputError::RootLimit);
                return Err(CoreInputHostError::Failed);
            }
            self.usage.roots += result.roots.len();
            Ok(result)
        })
    }
    fn form<'a>(&'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedFormElicitationParams) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>
    {
        Box::pin(async move {
            let result = self.host.form(cx, cancellation, request).await?;
            let fields = result.content.as_ref().map_or(0, std::collections::BTreeMap::len);
            if fields > self.limits.form_fields - self.usage.form_fields {
                self.refusal = Some(CoreInputError::FormFieldLimit);
                return Err(CoreInputHostError::Failed);
            }
            self.usage.form_fields += fields;
            Ok(result)
        })
    }
    fn url<'a>(&'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedUrlElicitationParams) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>
    { self.host.url(cx, cancellation, request) }
}

#[cfg(test)]
mod tests;
