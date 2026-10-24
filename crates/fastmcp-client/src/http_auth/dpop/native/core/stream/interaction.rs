//! Complete host-input conversations over JSON or incremental SSE and DPoP.
//!
//! The shared stream reader owns every socket and every notification. The
//! shared input session owns host approval, roots, forms, sampling and their
//! cumulative limits. Only the library retains and echoes opaque requestState.

use std::fmt;
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    CoreRequest, FinalInputResponses, InputRequiredResult, RequestId, ServerNotification,
};

use super::{
    CompletedStream, CoreDecoder, DpopCoreError, DpopCredential, DpopHttpClient, DpopHttpError,
    DpopStreamError, DpopStreamLimits, Idle, Lifetime, ManagedCoreError, ModernHttpRequest,
    PreparedStream, SseLimits, WaitBounds, check_live, prepare, with_caller, within,
};
use crate::http_auth::dpop::native::core::interaction::host::{DpopHostError, DpopHostResult};
use crate::http_auth::rpc::interaction::{
    ManagedInputReply, ManagedInteractionError, ManagedInteractionLimits, admit_challenge,
    admit_fresh_id, continuation_request, input_required, validate_initial,
};
use crate::http_auth::sampling::inputs::mixed::{CoreInputHost, CoreInputLimits};
use crate::http_auth::sampling::inputs::mixed::session::{CoreInputSession, CoreInputSessionError};
use crate::http_executor::parameter_headers::{ReviewedToolHeaders, ToolHeaderDispatchError};

/// One frozen policy for network rounds and typed host-input execution.
/// The interaction's core byte and notification limits span every round.
/// Encoded outgoing requests count against that same cumulative byte limit.
#[derive(Clone, Copy, Debug)]
pub struct DpopStreamHostLimits {
    interaction: ManagedInteractionLimits,
    inputs: CoreInputLimits,
    resolutions: usize,
    stream: DpopStreamLimits,
}

impl Default for DpopStreamHostLimits {
    fn default() -> Self {
        Self {
            interaction: ManagedInteractionLimits::default(),
            inputs: CoreInputLimits::default(),
            resolutions: 8,
            stream: DpopStreamLimits::default(),
        }
    }
}

impl DpopStreamHostLimits {
    /// Idle bounds each network round, starting before its preparation. Time
    /// obtaining host input consumes the original absolute and input deadlines,
    /// not a fresh per-round absolute allowance. Zero resolutions allows only
    /// an immediately complete result. No policy supplies default host consent.
    pub fn new(
        interaction: ManagedInteractionLimits,
        inputs: CoreInputLimits,
        resolutions: usize,
        idle: Duration,
    ) -> Result<Self, DpopStreamHostError> {
        if resolutions > 64 {
            return Err(CoreInputSessionError::InvalidLimits.into());
        }
        Ok(Self {
            interaction,
            inputs,
            resolutions,
            stream: DpopStreamLimits::new(interaction.core(), idle)?,
        })
    }

    pub fn with_sse_limits(mut self, limits: SseLimits) -> Result<Self, DpopStreamHostError> {
        self.stream = self.stream.with_sse_limits(limits)?;
        Ok(self)
    }

    pub fn with_progress_idle_reset(mut self, enabled: bool) -> Self {
        self.stream = self.stream.with_progress_idle_reset(enabled);
        self
    }
}

/// Fixed diagnostic categories never retain a token, host answer, requestState
/// or peer error message. An observer error is terminal, not replay permission.
#[derive(Debug)]
pub enum DpopStreamHostError {
    Stream(DpopStreamError),
    Host(DpopHostError),
    Headers(ToolHeaderDispatchError),
}

impl fmt::Display for DpopStreamHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream(error) => fmt::Display::fmt(error, f),
            Self::Host(error) => fmt::Display::fmt(error, f),
            Self::Headers(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for DpopStreamHostError {}

impl From<DpopStreamError> for DpopStreamHostError {
    fn from(error: DpopStreamError) -> Self {
        Self::Stream(error)
    }
}

impl From<DpopCoreError> for DpopStreamHostError {
    fn from(error: DpopCoreError) -> Self {
        Self::Stream(error.into())
    }
}

impl From<DpopHttpError> for DpopStreamHostError {
    fn from(error: DpopHttpError) -> Self {
        Self::Stream(error.into())
    }
}

impl From<ManagedCoreError> for DpopStreamHostError {
    fn from(error: ManagedCoreError) -> Self {
        Self::Stream(error.into())
    }
}

impl From<ManagedInteractionError> for DpopStreamHostError {
    fn from(error: ManagedInteractionError) -> Self {
        Self::Host(error.into())
    }
}

impl From<CoreInputSessionError> for DpopStreamHostError {
    fn from(error: CoreInputSessionError) -> Self {
        Self::Host(error.into())
    }
}

impl From<ToolHeaderDispatchError> for DpopStreamHostError {
    fn from(error: ToolHeaderDispatchError) -> Self {
        Self::Headers(error)
    }
}

impl DpopHttpClient {
    /// Execute tools/call, resources/read or prompts/get through JSON/SSE
    /// input-required rounds with an explicitly supplied typed input host.
    /// Notifications reach the observer before a later terminal result exists.
    /// A result or challenge is actionable only after clean HTTP EOF; truncated
    /// tails, duplicate terminals and observer failure cannot trigger host work.
    ///
    /// Every round uses the original request, resource, DPoP credential, caller
    /// and absolute deadline. A fresh proof and correlation ID do not authorize
    /// a retry: HTTP errors, nonce challenges, cancellation and dropped futures
    /// are terminal. There is no login, refresh, redirect, Tasks negotiation,
    /// partial answer dispatch, implicit host capability or background task.
    ///
    /// Request bytes, admitted JSON payload bytes and notification counts are
    /// cumulative. Native wire and SSE parser ceilings remain independently
    /// enforced per exchange. Valid progress can reset only that exchange's
    /// idle timer. Host waits remain inside the original credential/session
    /// lifetime and input deadline. Use distinct ID prefixes for concurrent
    /// logical exchanges. Neither correlation IDs nor prefixes are idempotency
    /// keys. Already committed host effects and delivered observations cannot
    /// be recalled after a later failure. Ordinary calls do not emit parameter
    /// headers; use the explicit reviewed-header variant to enable disclosure.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_core_with_streaming_input_host<H, N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        request: CoreRequest,
        id_prefix: String,
        limits: DpopStreamHostLimits,
        host: &mut H,
        observer: N,
    ) -> Result<DpopHostResult, DpopStreamHostError>
    where
        H: CoreInputHost + ?Sized,
        N: FnMut(&ServerNotification) -> bool,
    {
        self.execute_streaming_input_host_configured(
            cx, cancellation, credential, request, id_prefix, &limits, None, host, observer,
        ).await
    }

    /// Execute a tool conversation with one immutable, explicitly reviewed
    /// parameter-header plan. The review remains bound to the complete HTTPS
    /// resource and exact tool. Every POST projects only the original tool
    /// arguments from its actual wire body, never host input or requestState.
    ///
    /// Header admission runs before proof signing and network I/O on both the
    /// initial request and every continuation. A binding or projection failure
    /// stops the whole operation; it never falls back to an unreviewed request.
    /// This does not authorize invocation, refresh a stale schema, or permit
    /// replay. The application owns review freshness and non-sensitive exposure
    /// policy. All ordinary stream, input, cancellation and deadline bounds apply.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_core_with_streaming_input_host_and_headers<H, N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        request: CoreRequest,
        id_prefix: String,
        limits: DpopStreamHostLimits,
        reviewed: &ReviewedToolHeaders,
        host: &mut H,
        observer: N,
    ) -> Result<DpopHostResult, DpopStreamHostError>
    where
        H: CoreInputHost + ?Sized,
        N: FnMut(&ServerNotification) -> bool,
    {
        self.execute_streaming_input_host_configured(
            cx, cancellation, credential, request, id_prefix, &limits, Some(reviewed), host, observer,
        ).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_streaming_input_host_configured<H, N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        request: CoreRequest,
        id_prefix: String,
        // By reference: the struct is 280 bytes, past the
        // `large_types_passed_by_value` threshold, and this function only
        // reads its fields. It is `Copy`, so every `limits.field` use below
        // works unchanged through the reference.
        limits: &DpopStreamHostLimits,
        reviewed: Option<&ReviewedToolHeaders>,
        host: &mut H,
        mut observer: N,
    ) -> Result<DpopHostResult, DpopStreamHostError>
    where
        H: CoreInputHost + ?Sized,
        N: FnMut(&ServerNotification) -> bool,
    {
        let first_id = request_id(&id_prefix, 0)?;
        let timeout = self.policy.timeout.min(limits.interaction.core().timeout());
        let mut bounds = WaitBounds::new(cx, timeout, credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let mut inputs = CoreInputSession::new(
            cx, cancellation, request.clone(), limits.inputs, limits.resolutions,
        )?;
        if inputs.deadline() < bounds.deadline {
            bounds.deadline = inputs.deadline();
            bounds.terminal = DpopHttpError::TimedOut;
        }
        let mut conversation = Conversation::new(request, first_id, limits.interaction)?;
        loop {
            let idle = Idle::new(cx.now(), limits.stream.idle);
            let lifetime = Lifetime { cx, cancellation, session: &self.session, credential, bounds };
            with_caller(cx, || lifetime.check(&idle))?;
            let (wire, decoder) = conversation.prepare(
                self.resource().as_str(), self.policy.max_body_bytes, reviewed,
            )?;
            let completed = self.execute_prepared_core_stream(
                cx, cancellation, credential,
                PreparedStream { wire, decoder, limits: limits.stream, bounds, idle },
                &mut observer,
            ).await?;
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let input = match conversation.accept(completed)? {
                Step::Complete(result) => {
                    check_live(cx, cancellation, &self.session, credential, bounds)?;
                    return Ok(DpopHostResult {
                        result: *result, usage: inputs.usage(), continuations: conversation.continuations,
                    });
                }
                Step::Input(input) => input,
            };
            let next_id = request_id(&id_prefix, conversation.continuations + 1)?;
            admit_fresh_id(&conversation.used_ids, &next_id)?;
            // Only the trusted input engine receives the opaque wire challenge.
            // The application's host sees preflighted descriptors, never state.
            let reply = within(cx, cancellation, &self.session, credential, bounds, async {
                Ok(inputs.resolve(cx, input.as_ref().clone(), next_id, host).await)
            }).await??;
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            conversation.resume(&input, reply)?;
        }
    }
}

fn request_id(prefix: &str, ordinal: usize) -> Result<RequestId, DpopStreamHostError> {
    if prefix.is_empty() || prefix.len() > 128 || prefix.chars().any(char::is_control) {
        return Err(DpopStreamHostError::Host(DpopHostError::InvalidIdPrefix));
    }
    let id = RequestId::String(format!("{prefix}:{ordinal}"));
    id.validate().map_err(|_| DpopStreamHostError::Host(DpopHostError::InvalidIdPrefix))?;
    Ok(id)
}

// Private linear state: never exported, cached, serialized or reused after a
// failed exchange. Protocol admission and reply composition remain shared with
// the ordinary managed interaction rather than reimplemented for DPoP/SSE.
struct Conversation {
    original: CoreRequest,
    current: CoreRequest,
    request_id: RequestId,
    used_ids: Vec<RequestId>,
    limits: ManagedInteractionLimits,
    usage: (usize, usize),
    continuations: usize,
    input_responses: usize,
}

enum Step {
    Complete(Box<fastmcp_protocol::CoreResult>),
    Input(Box<InputRequiredResult>),
}

impl Conversation {
    fn new(
        original: CoreRequest,
        request_id: RequestId,
        limits: ManagedInteractionLimits,
    ) -> Result<Self, DpopStreamHostError> {
        validate_initial(&original)?;
        Ok(Self {
            current: original.clone(), original,
            used_ids: vec![request_id.clone()], request_id,
            limits, usage: (0, 0), continuations: 0, input_responses: 0,
        })
    }

    fn prepare(
        &self,
        target: &str,
        transport_limit: usize,
        reviewed: Option<&ReviewedToolHeaders>,
    ) -> Result<(ModernHttpRequest, CoreDecoder), DpopStreamHostError> {
        let (wire, mut decoder) = prepare(
            target, self.current.clone(), self.request_id.clone(), self.limits.core(), transport_limit,
        )?;
        let wire = match reviewed {
            Some(reviewed) => wire.with_reviewed_tool_headers(reviewed)?,
            None => wire,
        };
        let bytes = self.usage.0.checked_add(wire.body().len())
            .ok_or(ManagedCoreError::RequestTooLarge)?;
        // Reserve the exact outgoing bytes in the shared decoder before I/O.
        // Its existing admission now refuses a cumulative excess BEFORE a
        // notification callback, not retrospectively after a terminal result.
        decoder.resume_usage(bytes, self.usage.1)?;
        Ok((wire, decoder))
    }

    fn accept(&mut self, completed: CompletedStream) -> Result<Step, DpopStreamHostError> {
        if completed.usage.0 < self.usage.0 || completed.usage.1 < self.usage.1 {
            return Err(ManagedCoreError::InvalidResponse.into());
        }
        let Some(input) = input_required(&completed.result) else {
            self.usage = completed.usage;
            return Ok(Step::Complete(Box::new(completed.result)));
        };
        if completed.usage.0 >= self.limits.core().total_bytes() {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        admit_challenge(
            &self.original, input, self.limits, self.continuations, self.input_responses,
        )?;
        self.usage = completed.usage;
        Ok(Step::Input(Box::new(input.clone())))
    }

    fn resume(
        &mut self,
        input: &InputRequiredResult,
        reply: ManagedInputReply,
    ) -> Result<(), DpopStreamHostError> {
        admit_fresh_id(&self.used_ids, &reply.request_id)?;
        let count = reply.input_responses.as_ref().map_or(0, FinalInputResponses::len);
        let current = continuation_request(&self.original, input, reply.input_responses)?;
        self.current = current;
        self.request_id = reply.request_id.clone();
        self.used_ids.push(reply.request_id);
        self.continuations += 1;
        self.input_responses += count;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
