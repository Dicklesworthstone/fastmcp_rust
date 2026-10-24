//! Typed host-input execution over one DPoP credential and one budget owner.
//!
//! The common input engine owns approval, form-result validation, roots and
//! sampling/tool-loop policy. Its counters survive every network round; the
//! DPoP owner additionally bounds every host wait by token/session revocation.

use std::fmt;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreRequest, CoreResult, InputRequiredResult, RequestId};

use super::{
    DpopCredential, DpopHttpClient, DpopHttpError, DpopInteractionError, ManagedInputReply,
    ManagedInteractionError, ManagedInteractionLimits, Rounds, WaitBounds, admit_fresh_id,
    check_live, within,
};
use crate::http_auth::dpop::DpopSession;
use crate::http_auth::sampling::inputs::mixed::{CoreInputHost, CoreInputLimits};
use crate::http_auth::sampling::inputs::mixed::session::{
    CoreInputSession, CoreInputSessionError, CoreInputUsage,
};

/// Network and host limits are frozen before the first POST. Input limits
/// apply cumulatively, not once per challenge. The host-input timeout includes
/// all intervening network waits; the DPoP deadline bounds the complete run.
#[derive(Clone, Copy, Debug)]
pub struct DpopHostLimits {
    interaction: ManagedInteractionLimits,
    inputs: CoreInputLimits,
    resolutions: usize,
}

impl Default for DpopHostLimits {
    fn default() -> Self {
        Self {
            interaction: ManagedInteractionLimits::default(),
            inputs: CoreInputLimits::default(),
            resolutions: 8,
        }
    }
}

impl DpopHostLimits {
    /// Zero resolutions permits only an immediately complete server response.
    pub fn new(
        interaction: ManagedInteractionLimits,
        inputs: CoreInputLimits,
        resolutions: usize,
    ) -> Result<Self, CoreInputSessionError> {
        if resolutions > 64 {
            return Err(CoreInputSessionError::InvalidLimits);
        }
        Ok(Self {
            interaction,
            inputs,
            resolutions,
        })
    }
}

/// Only a complete result escapes, along with non-secret cumulative usage.
/// Input-required results and server continuation state remain driver-owned.
pub struct DpopHostResult {
    pub result: CoreResult,
    pub usage: CoreInputUsage,
    pub continuations: usize,
}

/// Fixed diagnostic categories; no server state, host answer or token is kept.
#[derive(Debug)]
pub enum DpopHostError {
    InvalidIdPrefix,
    Interaction(DpopInteractionError),
    Input(CoreInputSessionError),
}

impl fmt::Display for DpopHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdPrefix => f.write_str("invalid DPoP host request ID prefix"),
            Self::Interaction(error) => fmt::Display::fmt(error, f),
            Self::Input(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for DpopHostError {}

impl From<DpopInteractionError> for DpopHostError {
    fn from(error: DpopInteractionError) -> Self {
        Self::Interaction(error)
    }
}

impl From<DpopHttpError> for DpopHostError {
    fn from(error: DpopHttpError) -> Self {
        Self::Interaction(error.into())
    }
}

impl From<ManagedInteractionError> for DpopHostError {
    fn from(error: ManagedInteractionError) -> Self {
        Self::Interaction(error.into())
    }
}

impl From<CoreInputSessionError> for DpopHostError {
    fn from(error: CoreInputSessionError) -> Self {
        Self::Input(error)
    }
}

impl DpopHttpClient {
    /// Execute a tool, resource or prompt request through an explicit typed
    /// host. No default model, filesystem roots, browser or consent is supplied.
    /// The common input engine validates the entire challenge before approval,
    /// validates accepted form contents and returns a complete kind-bound map.
    /// Failed, denied or abandoned host work never produces a partial POST.
    ///
    /// Use distinct prefixes for simultaneous logical exchanges. Generated IDs
    /// are correlation identities, not retry or idempotency authority. State-
    /// only and present-empty challenges retain exact wire presence and invoke
    /// no host callbacks. Every continuation still consumes the round budget.
    ///
    /// The original DPoP credential is retained throughout. There is no login,
    /// refresh, redirect, failed-call retry, partial selection or SSE support.
    /// Host-created futures must be cancellation-correct; already committed
    /// host/server effects cannot be rolled back by dropping this future.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_core_with_input_host<H: CoreInputHost + ?Sized>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        request: CoreRequest,
        id_prefix: String,
        limits: DpopHostLimits,
        host: &mut H,
    ) -> Result<DpopHostResult, DpopHostError> {
        let first_id = request_id(&id_prefix, 0)?;
        let timeout = self.policy.timeout.min(limits.interaction.core().timeout());
        let bounds = WaitBounds::new(cx, timeout, credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let mut inputs = CoreInputSession::new(
            cx,
            cancellation,
            request.clone(),
            limits.inputs,
            limits.resolutions,
        )?;
        let bounds = host_bounds(bounds, &inputs);
        let (mut rounds, mut wire, mut decoder) = Rounds::new(
            self.resource().as_str(),
            request,
            first_id,
            limits.interaction,
            self.policy.max_body_bytes,
        )?;
        loop {
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let response = self
                .post_resource_with_bounds(cx, cancellation, credential, &wire, bounds)
                .await?;
            let outcome = rounds.decode(&mut decoder, response);
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let result = outcome?;
            let Some(input) = rounds.accept(&decoder, &result)? else {
                check_live(cx, cancellation, &self.session, credential, bounds)?;
                return Ok(DpopHostResult {
                    result,
                    usage: inputs.usage(),
                    continuations: rounds.continuations,
                });
            };
            drop(result);
            let next_id = request_id(&id_prefix, rounds.continuations + 1)?;
            admit_fresh_id(&rounds.used_ids, &next_id)?;
            let reply = resolve_host(
                cx,
                cancellation,
                &self.session,
                credential,
                bounds,
                &mut inputs,
                &input,
                next_id,
                host,
            )
            .await?;
            (wire, decoder) = rounds.resume(&input, reply)?;
        }
    }
}

// Freeze the intersection before request encoding. It also governs waits
// that never invoke a resolver and the final reply after the last host effect.
// Equal deadlines retain the existing credential-expiry classification.
fn host_bounds(mut bounds: WaitBounds, inputs: &CoreInputSession) -> WaitBounds {
    if inputs.deadline() < bounds.deadline {
        bounds.deadline = inputs.deadline();
        bounds.terminal = DpopHttpError::TimedOut;
    }
    bounds
}

fn request_id(prefix: &str, ordinal: usize) -> Result<RequestId, DpopHostError> {
    if prefix.is_empty() || prefix.len() > 128 || prefix.chars().any(char::is_control) {
        return Err(DpopHostError::InvalidIdPrefix);
    }
    let id = RequestId::String(format!("{prefix}:{ordinal}"));
    id.validate().map_err(|_| DpopHostError::InvalidIdPrefix)?;
    Ok(id)
}

// Raw state is passed only to the trusted library input engine. Its host
// surface exposes CoreInputRequest descriptors, never InputRequiredResult.
// The outer native guard adds credential/session revocation to the common
// host engine's own caller, cancellation, deadline and accumulated quotas.
#[allow(clippy::too_many_arguments)]
async fn resolve_host<H: CoreInputHost + ?Sized>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    session: &DpopSession,
    credential: &DpopCredential,
    bounds: WaitBounds,
    inputs: &mut CoreInputSession,
    input: &InputRequiredResult,
    request_id: RequestId,
    host: &mut H,
) -> Result<ManagedInputReply, DpopHostError> {
    Ok(within(cx, cancellation, session, credential, bounds, async {
        Ok(inputs.resolve(cx, input.clone(), request_id, host).await)
    })
    .await??)
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::{Duration, Instant};

    use asupersync::Budget;
    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_protocol::common_types::SamplingContentBlock;
    use fastmcp_protocol::dpop::DpopKey;
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use fastmcp_protocol::sampling::SamplingToolLoopLimits;
    use fastmcp_protocol::{
        ClientCapabilities, FinalCreateMessageResult, FinalEmbeddedCreateMessageParams,
        FinalEmbeddedElicitationResult, FinalEmbeddedFormElicitationParams,
        FinalEmbeddedRootsListParams, FinalEmbeddedRootsListResult,
        FinalEmbeddedUrlElicitationParams, FinalRequestMeta,
    };
    use serde_json::json;

    use super::*;
    #[cfg(feature = "native-tls-roots")]
    use crate::http_auth::dpop::native::core::DpopCoreError;
    use crate::http_auth::rpc::interaction::input_required;
    use crate::http_auth::sampling::{
        SamplingHost, SamplingHostError, SamplingHostFuture, SamplingRunLimits,
    };
    use crate::http_auth::sampling::inputs::SamplingInputLimits;
    use crate::http_auth::sampling::inputs::mixed::{
        CoreInputError, CoreInputHostError, CoreInputHostFuture, CoreInputRequest,
    };

    const MIXED: &str = r#"{"resultType":"input_required","requestState":" private-state ","inputRequests":{
        "r":{"method":"roots/list"},
        "f":{"method":"elicitation/create","params":{"mode":"form","message":"Quantity?","requestedSchema":{"type":"object","properties":{"quantity":{"type":"integer","minimum":1,"maximum":5}},"required":["quantity"],"additionalProperties":false}}}
    }}"#;

    fn input_limits(timeout: Duration) -> CoreInputLimits {
        let run = SamplingRunLimits::new(SamplingToolLoopLimits::default(), timeout, 8192).unwrap();
        let sampling = SamplingInputLimits::new(run, 8, 16, 32, 8192, 8192).unwrap();
        CoreInputLimits::new(sampling, 16, 16).unwrap()
    }

    fn original() -> CoreRequest {
        let mut meta =
            serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        meta[fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY] =
            json!({"roots":{},"elicitation":{"form":{}}});
        CoreRequest::decode(
            ProtocolEra::Modern2026,
            "tools/call",
            Some(&json!({"name":"echo","arguments":{"fixed":42},"_meta":meta})),
        )
        .unwrap()
    }

    fn input(source: &str) -> InputRequiredResult {
        input_required(&original().decode_result(source).unwrap())
            .unwrap()
            .clone()
    }

    fn runtime() -> (Runtime, Cx, TimerDriverHandle, Arc<VirtualClock>) {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        (runtime, cx, timer, clock)
    }

    fn session() -> (DpopSession, DpopCredential) {
        let endpoint = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
        let session = DpopSession::new(
            DpopKey::generate().unwrap(),
            endpoint.clone(),
            CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap(),
        )
        .unwrap();
        let credential = session
            .admit_token_response(
                &endpoint,
                200,
                br#"{"access_token":"host-token","token_type":"DPoP","expires_in":60}"#,
                Instant::now(),
                Duration::from_secs(60),
            )
            .unwrap();
        (session, credential)
    }

    #[derive(Default)]
    struct Host {
        calls: Vec<&'static str>,
        invalid_form: bool,
        deny: bool,
        hang: bool,
        drops: Arc<AtomicUsize>,
    }

    struct PendingDrop(Arc<AtomicUsize>);

    impl Drop for PendingDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl SamplingHost for Host {
        fn sample<'a>(
            &'a mut self,
            _: &'a Cx,
            _: &'a McpRequestCancellation,
            _: &'a FinalEmbeddedCreateMessageParams,
        ) -> SamplingHostFuture<'a, FinalCreateMessageResult> {
            self.calls.push("sample");
            Box::pin(async { Err(SamplingHostError::Denied) })
        }

        fn approve_tools<'a>(
            &'a mut self,
            _: &'a Cx,
            _: &'a McpRequestCancellation,
            _: &'a [SamplingContentBlock],
        ) -> SamplingHostFuture<'a, ()> {
            self.calls.push("tools");
            Box::pin(async { Err(SamplingHostError::Denied) })
        }

        fn execute_tool<'a>(
            &'a mut self,
            _: &'a Cx,
            _: &'a McpRequestCancellation,
            _: &'a SamplingContentBlock,
        ) -> SamplingHostFuture<'a, SamplingContentBlock> {
            self.calls.push("execute");
            Box::pin(async { Err(SamplingHostError::Denied) })
        }
    }

    impl CoreInputHost for Host {
        fn approve_inputs<'a>(
            &'a mut self,
            _: &'a Cx,
            _: &'a McpRequestCancellation,
            requests: &'a [CoreInputRequest],
        ) -> CoreInputHostFuture<'a, ()> {
            self.calls.push("approve");
            assert!(!requests.is_empty());
            let denied = self.deny;
            Box::pin(async move {
                if denied {
                    Err(CoreInputHostError::Denied)
                } else {
                    Ok(())
                }
            })
        }

        fn roots<'a>(
            &'a mut self,
            _: &'a Cx,
            _: &'a McpRequestCancellation,
            _: &'a FinalEmbeddedRootsListParams,
        ) -> CoreInputHostFuture<'a, FinalEmbeddedRootsListResult> {
            self.calls.push("roots");
            let hang = self.hang;
            let drops = Arc::clone(&self.drops);
            Box::pin(async move {
                if hang {
                    let _drop = PendingDrop(drops);
                    std::future::pending::<()>().await;
                }
                Ok(serde_json::from_value(json!({"roots":[{"uri":"file:///approved"}]})).unwrap())
            })
        }

        fn form<'a>(
            &'a mut self,
            _: &'a Cx,
            _: &'a McpRequestCancellation,
            _: &'a FinalEmbeddedFormElicitationParams,
        ) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult> {
            self.calls.push("form");
            let quantity = if self.invalid_form { 9 } else { 3 };
            Box::pin(async move {
                Ok(serde_json::from_value(json!({
                    "action":"accept","content":{"quantity":quantity}
                }))
                .unwrap())
            })
        }

        fn url<'a>(
            &'a mut self,
            _: &'a Cx,
            _: &'a McpRequestCancellation,
            _: &'a FinalEmbeddedUrlElicitationParams,
        ) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult> {
            self.calls.push("url");
            Box::pin(async { Err(CoreInputHostError::Denied) })
        }
    }

    // Finite helpers may yield cooperatively between input effects. A bounded
    // number of manual polls drives only in-memory, immediately ready hosts.
    fn ready<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        for _ in 0..32 {
            if let Poll::Ready(value) = future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                return value;
            }
        }
        panic!("immediately ready host resolution did not settle");
    }

    #[test]
    fn typed_host_replies_use_common_form_validation_and_complete_maps() {
        for invalid in [false, true] {
            let (runtime, cx, timer, _) = runtime();
            let (session, credential) = session();
            let cancel = McpRequestCancellation::new();
            let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
            let mut inputs = CoreInputSession::new(
                &cx, &cancel, original(), CoreInputLimits::default(), 4,
            )
            .unwrap();
            let mut host = Host { invalid_form: invalid, ..Host::default() };
            let challenge = input(MIXED);
            let outcome = ready(resolve_host(
                &cx, &cancel, &session, &credential, bounds, &mut inputs,
                &challenge, RequestId::Number(1), &mut host,
            ));
            if invalid {
                assert!(matches!(outcome, Err(DpopHostError::Input(
                    CoreInputSessionError::Input(CoreInputError::InvalidFormContent)
                ))));
                assert!(inputs.is_closed());
            } else {
                let reply = outcome.unwrap();
                reply.input_responses.unwrap().validate_against_input_required(&challenge).unwrap();
                assert_eq!(inputs.usage().resolutions, 1);
                assert_eq!(inputs.usage().selected_inputs, 2);
                assert_eq!(inputs.usage().roots, 1);
                assert_eq!(inputs.usage().form_fields, 1);
            }
            assert_eq!(host.calls, ["approve", "roots", "form"]);
            assert_eq!(timer.pending_count(), 0);
            drop(cx);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn resolution_quota_survives_successful_rounds_and_refuses_before_more_host_work() {
        let (runtime, cx, timer, _) = runtime();
        let (session, credential) = session();
        let cancel = McpRequestCancellation::new();
        let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
        let mut inputs = CoreInputSession::new(
            &cx, &cancel, original(), CoreInputLimits::default(), 1,
        )
        .unwrap();
        let mut host = Host::default();
        let challenge = input(MIXED);
        assert!(ready(resolve_host(
            &cx, &cancel, &session, &credential, bounds, &mut inputs,
            &challenge, RequestId::Number(1), &mut host,
        )).is_ok());
        let before = host.calls.clone();
        assert!(matches!(ready(resolve_host(
            &cx, &cancel, &session, &credential, bounds, &mut inputs,
            &challenge, RequestId::Number(2), &mut host,
        )), Err(DpopHostError::Input(CoreInputSessionError::ResolutionLimit))));
        assert_eq!(host.calls, before);
        assert_eq!(inputs.usage().resolutions, 1);
        assert_eq!(timer.pending_count(), 0);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn empty_and_state_only_rounds_need_no_host_and_preserve_reply_presence() {
        let (runtime, cx, timer, _) = runtime();
        let (session, credential) = session();
        let cancel = McpRequestCancellation::new();
        let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
        let mut inputs = CoreInputSession::new(
            &cx, &cancel, original(), CoreInputLimits::default(), 4,
        )
        .unwrap();
        let mut host = Host::default();
        for (ordinal, source, present) in [
            (1, r#"{"resultType":"input_required","requestState":"opaque"}"#, false),
            (2, r#"{"resultType":"input_required","inputRequests":{}}"#, true),
        ] {
            let reply = ready(resolve_host(
                &cx, &cancel, &session, &credential, bounds, &mut inputs,
                &input(source), RequestId::Number(ordinal), &mut host,
            ))
            .unwrap();
            assert_eq!(reply.input_responses.is_some(), present);
            assert!(reply.input_responses.as_ref().is_none_or(|map| map.is_empty()));
        }
        assert!(host.calls.is_empty());
        assert_eq!(inputs.usage().resolutions, 2);
        assert_eq!(timer.pending_count(), 0);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn host_deadline_is_frozen_and_never_extends_an_earlier_native_limit() {
        use asupersync::types::Time;
        use crate::http_auth::dpop::DpopClientError;

        let (runtime, cx, _, clock) = runtime();
        let cancel = McpRequestCancellation::new();
        let inputs = CoreInputSession::new(
            &cx,
            &cancel,
            original(),
            input_limits(Duration::from_secs(2)),
            4,
        )
        .unwrap();
        let end = inputs.deadline();
        assert_eq!(end, Time::from_nanos(2_000_000_000));
        // Preparation consumes time rather than granting another two seconds.
        clock.advance(1_000_000_000);
        for (deadline, terminal) in [
            (Time::from_nanos(1_500_000_000), DpopHttpError::TimedOut),
            (
                Time::from_nanos(1_500_000_000),
                DpopClientError::CredentialUnavailable.into(),
            ),
            (end, DpopClientError::CredentialUnavailable.into()),
            (Time::from_nanos(10_000_000_000), DpopHttpError::TimedOut),
        ] {
            let selected = host_bounds(WaitBounds { deadline, terminal }, &inputs);
            assert_eq!(selected.deadline, deadline.min(end));
            assert_eq!(selected.terminal, terminal);
            assert_eq!(inputs.usage(), CoreInputUsage::default());
        }
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn host_deadline_wakes_quiet_non_host_work_and_retires_its_future() {
        let (runtime, cx, timer, clock) = runtime();
        let (session, credential) = session();
        let cancel = McpRequestCancellation::new();
        let inputs = CoreInputSession::new(
            &cx,
            &cancel,
            original(),
            input_limits(Duration::from_secs(2)),
            4,
        )
        .unwrap();
        let native = WaitBounds::new(&cx, Duration::from_secs(20), &credential).unwrap();
        let bounds = host_bounds(native, &inputs);
        let drops = Arc::new(AtomicUsize::new(0));
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut task = Context::from_waker(&waker);
        let owned = PendingDrop(Arc::clone(&drops));
        let mut waiting = Box::pin(within(
            &cx,
            &cancel,
            &session,
            &credential,
            bounds,
            async move {
                let _owned = owned;
                std::future::pending::<Result<(), DpopHttpError>>().await
            },
        ));
        assert!(waiting.as_mut().poll(&mut task).is_pending());
        clock.advance(bounds.deadline.as_nanos() - 1);
        assert_eq!(timer.process_timers(), 0);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        clock.advance(1);
        assert!(timer.process_timers() > 0);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert_eq!(
            waiting.as_mut().poll(&mut task),
            Poll::Ready(Err(DpopHttpError::TimedOut))
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(inputs.usage(), CoreInputUsage::default());
        assert!(!credential.is_revoked());
        assert!(!cancel.is_cancel_requested());
        drop(waiting);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn completed_host_round_does_not_restart_the_final_response_deadline() {
        for expired in [false, true] {
            let (runtime, cx, timer, clock) = runtime();
            let (session, credential) = session();
            let cancel = McpRequestCancellation::new();
            let mut inputs = CoreInputSession::new(
                &cx,
                &cancel,
                original(),
                input_limits(Duration::from_secs(2)),
                4,
            )
            .unwrap();
            let native = WaitBounds::new(&cx, Duration::from_secs(20), &credential).unwrap();
            let bounds = host_bounds(native, &inputs);
            let mut host = Host::default();
            let challenge = input(MIXED);
            assert!(
                ready(resolve_host(
                    &cx,
                    &cancel,
                    &session,
                    &credential,
                    bounds,
                    &mut inputs,
                    &challenge,
                    RequestId::Number(1),
                    &mut host,
                ))
                .is_ok()
            );
            assert_eq!(host_bounds(native, &inputs).deadline, bounds.deadline);
            let mut operation = Box::pin(within(
                &cx,
                &cancel,
                &session,
                &credential,
                bounds,
                async {
                    clock.advance(bounds.deadline.as_nanos() - u64::from(!expired));
                    Ok(42)
                },
            ));
            let result = operation.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            assert_eq!(
                result,
                if expired {
                    Poll::Ready(Err(DpopHttpError::TimedOut))
                } else {
                    Poll::Ready(Ok(42))
                }
            );
            assert_eq!(inputs.usage().resolutions, 1);
            assert_eq!(timer.pending_count(), 0);
            assert!(!credential.is_revoked());
            drop(operation);
            drop(cx);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn token_owner_and_deadline_wake_a_quiet_typed_host_without_partial_replies() {
        for cause in 0..3 {
            let (runtime, cx, timer, clock) = runtime();
            let (session, credential) = session();
            let cancel = McpRequestCancellation::new();
            let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
            let mut inputs = CoreInputSession::new(
                &cx, &cancel, original(), CoreInputLimits::default(), 4,
            )
            .unwrap();
            let drops = Arc::new(AtomicUsize::new(0));
            let mut host = Host { hang: true, drops: Arc::clone(&drops), ..Host::default() };
            let challenge = input(MIXED);
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut task = Context::from_waker(&waker);
            let mut waiting = Box::pin(resolve_host(
                &cx, &cancel, &session, &credential, bounds, &mut inputs,
                &challenge, RequestId::Number(1), &mut host,
            ));
            for _ in 0..8 {
                assert!(waiting.as_mut().poll(&mut task).is_pending());
            }
            let before = wakes.0.load(Ordering::SeqCst);
            match cause {
                0 => credential.revoke(),
                1 => session.revoke(),
                _ => {
                    clock.advance(bounds.deadline.as_nanos());
                    assert!(timer.process_timers() > 0);
                }
            }
            assert!(wakes.0.load(Ordering::SeqCst) > before);
            assert!(matches!(waiting.as_mut().poll(&mut task), Poll::Ready(Err(_))));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            drop(waiting);
            assert_eq!(host.calls, ["approve", "roots"]);
            assert!(inputs.is_closed());
            assert_eq!(timer.pending_count(), 0);
            drop(cx);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn abandoned_typed_host_retires_pending_work_without_revoking_the_login() {
        let (runtime, cx, timer, _) = runtime();
        let (session, credential) = session();
        let cancel = McpRequestCancellation::new();
        let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
        let mut inputs = CoreInputSession::new(
            &cx, &cancel, original(), CoreInputLimits::default(), 4,
        )
        .unwrap();
        let mut host = Host { hang: true, ..Host::default() };
        let drops = Arc::clone(&host.drops);
        let challenge = input(MIXED);
        let mut waiting = Box::pin(resolve_host(
            &cx, &cancel, &session, &credential, bounds, &mut inputs,
            &challenge, RequestId::Number(1), &mut host,
        ));
        for _ in 0..8 {
            assert!(waiting.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        drop(waiting);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(inputs.is_closed());
        assert_eq!(timer.pending_count(), 0);
        assert!(!credential.is_revoked());
        assert!(!cancel.is_cancel_requested());
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn correlation_prefix_and_resolution_limits_are_admitted_before_execution() {
        for prefix in ["", "bad\n", &"x".repeat(129)] {
            assert!(matches!(request_id(prefix, 0), Err(DpopHostError::InvalidIdPrefix)));
        }
        let ids: Vec<_> = (0..65).map(|n| request_id("host", n).unwrap()).collect();
        for (index, id) in ids.iter().enumerate() {
            assert!(ids[..index].iter().all(|previous| !id.correlates_with(previous)));
        }
        assert!(DpopHostLimits::new(
            ManagedInteractionLimits::default(), CoreInputLimits::default(), 64,
        ).is_ok());
        assert!(DpopHostLimits::new(
            ManagedInteractionLimits::default(), CoreInputLimits::default(), 65,
        ).is_err());
    }

    #[cfg(feature = "native-tls-roots")]
    mod tls {
        use std::future::poll_fn;

        use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
        use asupersync::net::TcpListener;
        use asupersync::runtime::reactor::create_reactor;
        use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder};
        use serde_json::Value;

        use super::*;
        use crate::http_auth::dpop::native::DpopHttpPolicy;

        // Existing public TEST ONLY OAuth identity; never deployment credentials.
        // Inlined, not included: `*.pem` is transfer-excluded, so including it
        // makes this target unbuildable on a remote worker and a target that
        // fails to build can report `0 passed` instead of failing. Same bytes
        // and same remedy as LEAF and KEY below.
        const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
        const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
        const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

        async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
            let mut left = pin!(left);
            let mut right = pin!(right);
            let (mut first, mut second) = (None, None);
            poll_fn(|task| {
                if first.is_none() {
                    if let Poll::Ready(value) = left.as_mut().poll(task) {
                        first = Some(value);
                    }
                }
                if second.is_none() {
                    if let Poll::Ready(value) = right.as_mut().poll(task) {
                        second = Some(value);
                    }
                }
                if first.is_some() && second.is_some() {
                    Poll::Ready((first.take().unwrap(), second.take().unwrap()))
                } else {
                    Poll::Pending
                }
            })
            .await
        }

        async fn read_request<IO: AsyncRead + Unpin>(io: &mut IO) -> (String, Value) {
            let mut wire = Vec::new();
            let mut buffer = [0; 2048];
            let end = loop {
                let count = io.read(&mut buffer).await.unwrap();
                assert!(count > 0 && wire.len() + count <= 32 * 1024);
                wire.extend_from_slice(&buffer[..count]);
                if let Some(index) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let head = std::str::from_utf8(&wire[..end]).unwrap().to_owned();
            let length = head.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            }).unwrap();
            assert!(end + length <= 32 * 1024);
            while wire.len() < end + length {
                let count = io.read(&mut buffer).await.unwrap();
                assert!(count > 0 && wire.len() + count <= 32 * 1024);
                wire.extend_from_slice(&buffer[..count]);
            }
            assert_eq!(wire.len(), end + length);
            (head, serde_json::from_slice(&wire[end..]).unwrap())
        }

        #[derive(Clone, Copy)]
        enum Case {
            Complete,
            CompleteWithoutInput,
            QuietResponseHead,
            QuietResponseBody,
            InvalidForm,
            ResolutionLimit,
            HostDenies,
        }

        #[test]
        fn public_dpop_host_execution_preserves_state_and_stops_before_partial_or_excess_posts() {
            for case in [
                Case::Complete,
                Case::CompleteWithoutInput,
                Case::QuietResponseHead,
                Case::QuietResponseBody,
                Case::InvalidForm,
                Case::ResolutionLimit,
                Case::HostDenies,
            ] {
                RuntimeBuilder::current_thread()
                    .with_reactor(create_reactor().unwrap())
                    .build()
                    .unwrap()
                    .block_on(async {
                        let cx = Cx::current().unwrap();
                        let deadline = cx.now().saturating_add_nanos(20_000_000_000);
                        asupersync::time::timeout_at(deadline, async {
                            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                            let address = listener.local_addr().unwrap();
                            let endpoint = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
                            let resource = CanonicalHttpUrl::parse(&format!("https://{address}/mcp")).unwrap();
                            let session = DpopSession::new(DpopKey::generate().unwrap(), endpoint.clone(), resource).unwrap();
                            let credential = session.admit_token_response(
                                &endpoint, 200,
                                br#"{"access_token":"host-token","token_type":"DPoP","expires_in":60}"#,
                                Instant::now(), Duration::from_secs(60),
                            ).unwrap();
                            let root = Certificate::from_pem(ROOT).unwrap().remove(0);
                            let policy = DpopHttpPolicy::default().with_resource_root_der(root.as_der().to_vec()).unwrap();
                            let mut client = DpopHttpClient::new(session, policy).unwrap();
                            let tls = TlsAcceptorBuilder::new(
                                CertificateChain::from_pem(LEAF).unwrap(),
                                PrivateKey::from_pem(KEY).unwrap(),
                            ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
                            let expected = original().encode_params().unwrap().unwrap();
                            let posts = match case {
                                Case::Complete => 3,
                                Case::ResolutionLimit => 2,
                                _ => 1,
                            };
                            let server = async {
                                let mut proofs = Vec::new();
                                for ordinal in 0..posts {
                                    let (socket, _) = listener.accept().await.unwrap();
                                    let mut socket = tls.accept(socket).await.unwrap();
                                    let (head, mut body) = read_request(&mut socket).await;
                                    assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
                                    assert_eq!(body["id"], format!("input-host:{ordinal}"));
                                    assert_eq!(body["method"], "tools/call");
                                    if ordinal != 0 {
                                        assert_eq!(body["params"]["requestState"], " private-state ");
                                        assert_eq!(body["params"]["inputResponses"], json!({
                                            "r":{"roots":[{"uri":"file:///approved"}]},
                                            "f":{"action":"accept","content":{"quantity":3}}
                                        }));
                                        body["params"].as_object_mut().unwrap().remove("requestState");
                                        body["params"].as_object_mut().unwrap().remove("inputResponses");
                                    }
                                    assert_eq!(body["params"], expected);
                                    let headers: Vec<_> = head.lines().filter_map(|line| line.split_once(':'))
                                        .map(|(key, value)| (key.to_ascii_lowercase(), value.trim())).collect();
                                    assert_eq!(headers.iter().filter(|(key, _)| key == "authorization").count(), 1);
                                    assert!(headers.iter().any(|(key, value)| key == "authorization" && *value == "DPoP host-token"));
                                    let proof = headers.iter().find(|(key, _)| key == "dpop").unwrap().1.to_owned();
                                    assert!(!proofs.contains(&proof));
                                    proofs.push(proof);
                                    if matches!(case, Case::QuietResponseHead | Case::QuietResponseBody) {
                                        if matches!(case, Case::QuietResponseBody) {
                                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n{").await.unwrap();
                                        }
                                        // A silent peer cannot wait until the much later
                                        // native timeout. The host deadline must close I/O.
                                        let mut byte = [0];
                                        assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0));
                                        break;
                                    }
                                    let result = if ordinal == 2 || matches!(case, Case::CompleteWithoutInput) {
                                        r#"{"resultType":"complete","content":[{"type":"text","text":"done"}]}"#
                                    } else {
                                        MIXED
                                    };
                                    // Keep the descriptor's wire order; do not round-trip
                                    // through a sorted serde_json map in the fixture.
                                    let body = format!(r#"{{"jsonrpc":"2.0","id":"input-host:{ordinal}","result":{result}}}"#);
                                    let wire = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nDPoP-Nonce: next-nonce\r\nConnection: close\r\n\r\n{body}", body.len());
                                    socket.write_all(wire.as_bytes()).await.unwrap();
                                    socket.shutdown().await.unwrap();
                                }
                                proofs.len()
                            };
                            let cancel = McpRequestCancellation::new();
                            let input_policy = if matches!(case, Case::QuietResponseHead | Case::QuietResponseBody | Case::CompleteWithoutInput) {
                                input_limits(Duration::from_secs(3))
                            } else {
                                CoreInputLimits::default()
                            };
                            let limits = DpopHostLimits::new(
                                ManagedInteractionLimits::default(), input_policy,
                                if matches!(case, Case::ResolutionLimit) { 1 } else { 4 },
                            ).unwrap();
                            let mut host = Host {
                                invalid_form: matches!(case, Case::InvalidForm),
                                deny: matches!(case, Case::HostDenies),
                                ..Host::default()
                            };
                            let application = client.execute_core_with_input_host(
                                &cx, &cancel, &credential, original(), "input-host".to_owned(), limits, &mut host,
                            );
                            let (received, outcome) = pair(server, application).await;
                            assert_eq!(received, posts);
                            match case {
                                Case::CompleteWithoutInput => {
                                    assert!(outcome.unwrap().result.encode().unwrap().contains("done"));
                                    assert!(host.calls.is_empty());
                                }
                                Case::QuietResponseHead | Case::QuietResponseBody => {
                                    assert!(matches!(outcome, Err(DpopHostError::Interaction(
                                        DpopInteractionError::Core(DpopCoreError::Transport(
                                            DpopHttpError::TimedOut
                                        ))
                                    ))));
                                    assert!(host.calls.is_empty());
                                }
                                Case::Complete => {
                                    let outcome = outcome.unwrap();
                                    assert!(outcome.result.encode().unwrap().contains("done"));
                                    assert_eq!(outcome.continuations, 2);
                                    assert_eq!(outcome.usage.resolutions, 2);
                                    assert_eq!(outcome.usage.selected_inputs, 4);
                                    assert_eq!(outcome.usage.roots, 2);
                                    assert_eq!(outcome.usage.form_fields, 2);
                                    assert_eq!(host.calls, ["approve", "roots", "form", "approve", "roots", "form"]);
                                }
                                Case::InvalidForm => assert!(matches!(outcome, Err(DpopHostError::Input(
                                    CoreInputSessionError::Input(CoreInputError::InvalidFormContent)
                                )))),
                                Case::ResolutionLimit => {
                                    assert!(matches!(outcome, Err(DpopHostError::Input(CoreInputSessionError::ResolutionLimit))));
                                    assert_eq!(host.calls, ["approve", "roots", "form"]);
                                }
                                Case::HostDenies => {
                                    assert!(matches!(outcome, Err(DpopHostError::Input(CoreInputSessionError::Input(
                                        CoreInputError::Host { reason: CoreInputHostError::Denied, .. }
                                    )))));
                                    assert_eq!(host.calls, ["approve"]);
                                }
                            }
                            assert!(!credential.is_revoked());
                            assert!(!cancel.is_cancel_requested());
                            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
                        }).await.expect("DPoP host execution must settle without hidden retries");
                    });
            }
        }
    }
}
