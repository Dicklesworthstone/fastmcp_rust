//! Host-driven multi-round core requests over one DPoP credential.
//!
//! Every continuation is explicitly authorized by the supplied resolver. The
//! original request, resource, credential, caller context and absolute deadline
//! remain fixed across all rounds, including time spent obtaining host input.
//! A failed or abandoned exchange is terminal, never an automatic retry.

/// Complete DPoP execution with the common typed, cumulatively budgeted host.
pub mod host;

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    CoreRequest, CoreResult, FinalEmbeddedInputRequest, FinalInputResponses, InputRequiredResult,
    RequestId, exact_json_to_serde,
};

use super::super::within;
use super::{
    CoreDecoder, DpopCoreError, DpopCredential, DpopHttpClient, DpopHttpError, DpopHttpResponse,
    ManagedCoreError, ModernHttpRequest, WaitBounds, check_live, decode_response, prepare,
};
use crate::http_auth::rpc::interaction::{
    ManagedInteractionError, admit_challenge, admit_fresh_id, continuation_request, input_required,
    validate_initial,
};

pub use crate::http_auth::rpc::interaction::{ManagedInputReply, ManagedInteractionLimits};

/// Only the admitted input descriptors made available to a host resolver.
///
/// The server's opaque requestState, result metadata and unknown result fields
/// are deliberately not retained. They remain private to the exchange driver.
/// This value has no serialization, dereference or conversion back to a wire
/// result. Debug reports only presence and count, never input keys or values.
///
/// ```compile_fail
/// use fastmcp_client::http_auth::dpop::native::core::interaction::DpopInputChallenge;
/// fn inspect(input: &DpopInputChallenge) {
///     let _ = input.request_state();
/// }
/// ```
///
/// ```compile_fail
/// use fastmcp_client::http_auth::dpop::native::core::interaction::DpopInputChallenge;
/// fn serialize(input: &DpopInputChallenge) {
///     let _ = serde_json::to_string(input);
/// }
/// ```
pub struct DpopInputChallenge {
    requests: Option<BTreeMap<String, FinalEmbeddedInputRequest>>,
}

impl DpopInputChallenge {
    /// Absence requires an absent reply map; a present empty map requires a
    /// present empty reply map. A nonempty map must be answered completely,
    /// with one correctly typed response for every key. No partial automatic
    /// continuation is dispatched after failure, refusal or cancellation.
    pub fn input_requests(&self) -> Option<&BTreeMap<String, FinalEmbeddedInputRequest>> {
        self.requests.as_ref()
    }

    // Called only after Rounds::accept has admitted the entire challenge.
    // Copy descriptors, not the result: stripping a few known fields from a
    // cloned result could still leak opaque state through future additions.
    fn from_input(input: &InputRequiredResult) -> Result<Self, ManagedCoreError> {
        let requests = input
            .input_requests()
            .map(|requests| {
                let mut projected = BTreeMap::new();
                for member in requests.members() {
                    let value = exact_json_to_serde(&member.value)
                        .map_err(|_| ManagedCoreError::InvalidResult)?;
                    let descriptor = serde_json::from_value(value)
                        .map_err(|_| ManagedCoreError::InvalidResult)?;
                    if projected.insert(member.name.clone(), descriptor).is_some() {
                        return Err(ManagedCoreError::InvalidResult);
                    }
                }
                Ok(projected)
            })
            .transpose()?;
        Ok(Self { requests })
    }
}

impl fmt::Debug for DpopInputChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopInputChallenge")
            .field("inputs_present", &self.requests.is_some())
            .field(
                "input_count",
                &self.requests.as_ref().map_or(0, BTreeMap::len),
            )
            .finish_non_exhaustive()
    }
}

/// Sanitized failures. No request state, host answer, token or peer diagnostic
/// is retained. A resolver declines using `ManagedInteractionError::AbortedByHost`.
#[derive(Debug)]
pub enum DpopInteractionError {
    Core(DpopCoreError),
    Input(ManagedInteractionError),
}

impl fmt::Display for DpopInteractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => fmt::Display::fmt(error, f),
            Self::Input(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for DpopInteractionError {}

impl From<DpopCoreError> for DpopInteractionError {
    fn from(error: DpopCoreError) -> Self {
        Self::Core(error)
    }
}

impl From<DpopHttpError> for DpopInteractionError {
    fn from(error: DpopHttpError) -> Self {
        Self::Core(DpopCoreError::Transport(error))
    }
}

impl From<ManagedCoreError> for DpopInteractionError {
    fn from(error: ManagedCoreError) -> Self {
        Self::Core(DpopCoreError::Protocol(error))
    }
}

impl From<ManagedInteractionError> for DpopInteractionError {
    fn from(error: ManagedInteractionError) -> Self {
        Self::Input(error)
    }
}

impl DpopHttpClient {
    /// Drive an initial tools/call, resources/read or prompts/get through
    /// explicitly supplied host input. The resolver receives only descriptors
    /// from an entirely admitted challenge, never its opaque requestState or
    /// result metadata. It returns only a fresh ID and correlated answers and
    /// cannot replace the method, arguments, metadata or state echoed on wire.
    ///
    /// Both invocation and polling of the resolver are guarded by caller,
    /// operation, session-owner and token revocation, and the original deadline.
    /// The resolver must be cancel-correct when dropped. The framework invokes
    /// no model, browser, tool or filesystem operation on the host's behalf.
    ///
    /// Limits span the entire conversation. In this driver, core.total_bytes
    /// caps the SUM of encoded request and admitted response body bytes; it is
    /// not reset on a new ID. The native response-buffer cap remains a separate
    /// ceiling. No refresh, redirect, failed-call replay, extension negotiation
    /// or SSE support is added. The ordinary
    /// request_core method still returns input_required after one POST.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_core_interaction<R, F>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedInteractionLimits,
        mut resolve: R,
    ) -> Result<CoreResult, DpopInteractionError>
    where
        R: FnMut(DpopInputChallenge) -> F,
        F: Future<Output = Result<ManagedInputReply, ManagedInteractionError>>,
    {
        let timeout = self.policy.timeout.min(limits.core().timeout());
        let bounds = WaitBounds::new(cx, timeout, credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let (mut state, mut wire, mut decoder) = Rounds::new(
            self.resource().as_str(),
            request,
            request_id,
            limits,
            self.policy.max_body_bytes,
        )?;
        loop {
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let response = self
                .post_resource_with_bounds(cx, cancellation, credential, &wire, bounds)
                .await?;
            let outcome = state.decode(&mut decoder, response);
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let result = outcome?;
            let Some(input) = state.accept(&decoder, &result)? else {
                check_live(cx, cancellation, &self.session, credential, bounds)?;
                return Ok(result);
            };
            // Retain the private wire challenge, not a host-authored state.
            // The host receives descriptors only. Prior results and answers
            // do not accumulate across rounds.
            drop(result);
            let reply = resolve_input(
                cx,
                cancellation,
                &self.session,
                credential,
                bounds,
                &input,
                &mut resolve,
            )
            .await?;
            (wire, decoder) = state.resume(&input, reply)?;
        }
    }
}

// Keep callback invocation inside the guarded future. Creating that future
// must not run user code before cancellation and deadline admission.
#[allow(clippy::too_many_arguments)]
async fn resolve_input<R, F>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    session: &crate::http_auth::dpop::DpopSession,
    credential: &DpopCredential,
    bounds: WaitBounds,
    input: &InputRequiredResult,
    resolve: &mut R,
) -> Result<ManagedInputReply, DpopInteractionError>
where
    R: FnMut(DpopInputChallenge) -> F,
    F: Future<Output = Result<ManagedInputReply, ManagedInteractionError>>,
{
    check_live(cx, cancellation, session, credential, bounds)?;
    let projected = DpopInputChallenge::from_input(input)?;
    Ok(
        within(cx, cancellation, session, credential, bounds, async {
            Ok(resolve(projected).await)
        })
        .await??,
    )
}

// Only the currently owned conversation can construct a next request. These
// counters and IDs are not public resumable state or a retry/recovery journal.
struct Rounds {
    target: String,
    original: CoreRequest,
    limits: ManagedInteractionLimits,
    transport_limit: usize,
    used_ids: Vec<RequestId>,
    continuations: usize,
    input_responses: usize,
    request_bytes: usize,
    response_bytes: usize,
}

impl Rounds {
    fn new(
        target: &str,
        original: CoreRequest,
        request_id: RequestId,
        limits: ManagedInteractionLimits,
        transport_limit: usize,
    ) -> Result<(Self, ModernHttpRequest, CoreDecoder), DpopInteractionError> {
        validate_initial(&original)?;
        let mut state = Self {
            target: target.to_owned(),
            original,
            limits,
            transport_limit,
            used_ids: vec![request_id.clone()],
            continuations: 0,
            input_responses: 0,
            request_bytes: 0,
            response_bytes: 0,
        };
        let (wire, decoder) = state.prepare(state.original.clone(), request_id)?;
        state.request_bytes = wire.body().len();
        Ok((state, wire, decoder))
    }

    fn prepare(
        &self,
        request: CoreRequest,
        request_id: RequestId,
    ) -> Result<(ModernHttpRequest, CoreDecoder), DpopInteractionError> {
        let remaining = self.remaining_bytes();
        // No valid response can fit once the outgoing request exhausts the
        // conversation budget. Refuse before retaining or dispatching it.
        if remaining <= 1 {
            return Err(ManagedCoreError::RequestTooLarge.into());
        }
        let (wire, mut decoder) = prepare(
            &self.target,
            request,
            request_id,
            self.limits.core(),
            self.transport_limit.min(remaining - 1),
        )?;
        decoder.resume_usage(self.response_bytes, 0)?;
        Ok((wire, decoder))
    }

    fn remaining_bytes(&self) -> usize {
        self.limits
            .core()
            .total_bytes()
            .saturating_sub(self.request_bytes)
            .saturating_sub(self.response_bytes)
    }

    fn decode(
        &self,
        decoder: &mut CoreDecoder,
        response: DpopHttpResponse,
    ) -> Result<CoreResult, DpopInteractionError> {
        if response.body().len() > self.remaining_bytes() {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        Ok(decode_response(decoder, response)?)
    }

    fn accept(
        &mut self,
        decoder: &CoreDecoder,
        result: &CoreResult,
    ) -> Result<Option<Box<InputRequiredResult>>, DpopInteractionError> {
        let response_bytes = decoder.usage().0;
        if self.request_bytes > self.limits.core().total_bytes()
            || response_bytes < self.response_bytes
            || response_bytes
                > self
                    .limits
                    .core()
                    .total_bytes()
                    .saturating_sub(self.request_bytes)
        {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        let Some(input) = input_required(result) else {
            self.response_bytes = response_bytes;
            return Ok(None);
        };
        // Refuse impossible further work before asking the host to spend time
        // or disclose data. Every descriptor must pass capability admission.
        if response_bytes == self.limits.core().total_bytes() - self.request_bytes {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        admit_challenge(
            &self.original,
            input,
            self.limits,
            self.continuations,
            self.input_responses,
        )?;
        self.response_bytes = response_bytes;
        Ok(Some(Box::new(input.clone())))
    }

    fn resume(
        &mut self,
        input: &InputRequiredResult,
        reply: ManagedInputReply,
    ) -> Result<(ModernHttpRequest, CoreDecoder), DpopInteractionError> {
        admit_fresh_id(&self.used_ids, &reply.request_id)?;
        let count = reply
            .input_responses
            .as_ref()
            .map_or(0, FinalInputResponses::len);
        let request = continuation_request(&self.original, input, reply.input_responses)?;
        let prepared = self.prepare(request, reply.request_id.clone())?;
        // All local checks precede ownership commit. The caller owns a single
        // future; failure or abandonment after this point cannot replay it.
        self.request_bytes += prepared.0.body().len();
        self.used_ids.push(reply.request_id);
        self.continuations += 1;
        self.input_responses += count;
        Ok(prepared)
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::{Duration, Instant};

    use asupersync::Budget;
    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_protocol::dpop::DpopKey;
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::{Value, json};

    use super::*;
    use crate::http_auth::dpop::DpopSession;
    use crate::http_auth::dpop::native::DpopHttpResponse;
    use crate::http_auth::rpc::ManagedCoreLimits;

    const TARGET: &str = "https://mcp.example/mcp?tenant=one";
    const INPUT: &str = r#"{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}},"requestState":" opaque+/% "}"#;

    fn request(method: &str, mut params: Value, capabilities: Value) -> CoreRequest {
        params["_meta"] =
            serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        params["_meta"][fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY] = capabilities;
        params["_meta"]["com.example/identity"] = json!("fixed");
        CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
    }

    fn initial(limits: ManagedInteractionLimits) -> (Rounds, ModernHttpRequest, CoreDecoder) {
        Rounds::new(
            TARGET,
            request("tools/call", json!({"name":"echo"}), json!({"roots":{}})),
            RequestId::Number(7),
            limits,
            8 * 1024 * 1024,
        )
        .unwrap()
    }

    fn response(id: i64, result: &str) -> DpopHttpResponse {
        DpopHttpResponse {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#).into_bytes(),
        }
    }

    fn challenge(state: &mut Rounds, decoder: &mut CoreDecoder) -> Box<InputRequiredResult> {
        let result = state.decode(decoder, response(7, INPUT)).unwrap();
        state.accept(decoder, &result).unwrap().unwrap()
    }

    fn reply(id: i64, answers: Option<Value>) -> ManagedInputReply {
        ManagedInputReply {
            request_id: RequestId::Number(id),
            input_responses: answers.map(|answers| serde_json::from_value(answers).unwrap()),
        }
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
        let token_endpoint = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
        let session = DpopSession::new(
            DpopKey::generate().unwrap(),
            token_endpoint.clone(),
            CanonicalHttpUrl::parse(TARGET).unwrap(),
        )
        .unwrap();
        let credential = session
            .admit_token_response(
                &token_endpoint,
                200,
                br#"{"access_token":"private-token","token_type":"DPoP","expires_in":60}"#,
                Instant::now(),
                Duration::from_secs(60),
            )
            .unwrap();
        (session, credential)
    }

    #[test]
    fn every_continuation_preserves_original_identity_and_only_current_answers() {
        for (method, params) in [
            (
                "tools/call",
                json!({"name":"echo","arguments":{"text":"original"}}),
            ),
            ("resources/read", json!({"uri":"file:///original"})),
            (
                "prompts/get",
                json!({"name":"greet","arguments":{"name":"original"}}),
            ),
        ] {
            let original = request(method, params, json!({"roots":{}}));
            let before = original.encode_params().unwrap().unwrap();
            let (mut state, _, mut decoder) = Rounds::new(
                TARGET,
                original,
                RequestId::Number(7),
                ManagedInteractionLimits::default(),
                8192,
            )
            .unwrap();
            let input = challenge(&mut state, &mut decoder);
            let (wire, mut decoder) = state
                .resume(&input, reply(8, Some(json!({"r":{"roots":[]}}))))
                .unwrap();
            let mut payload: Value = serde_json::from_slice(wire.body()).unwrap();
            assert_eq!(wire.target(), TARGET);
            assert_eq!(payload["method"], method);
            assert_eq!(payload["id"], 8);
            assert_eq!(payload["params"]["requestState"], " opaque+/% ");
            assert_eq!(
                payload["params"]["inputResponses"],
                json!({"r":{"roots":[]}})
            );
            payload["params"]
                .as_object_mut()
                .unwrap()
                .remove("requestState");
            payload["params"]
                .as_object_mut()
                .unwrap()
                .remove("inputResponses");
            assert_eq!(payload["params"], before);

            let next = r#"{"resultType":"input_required","inputRequests":{"s":{"method":"roots/list"}},"requestState":"successor"}"#;
            let result = decode_response(&mut decoder, response(8, next)).unwrap();
            let input = state.accept(&decoder, &result).unwrap().unwrap();
            let (wire, _) = state
                .resume(&input, reply(9, Some(json!({"s":{"roots":[]}}))))
                .unwrap();
            let payload: Value = serde_json::from_slice(wire.body()).unwrap();
            assert_eq!(payload["params"]["requestState"], "successor");
            assert_eq!(
                payload["params"]["inputResponses"],
                json!({"s":{"roots":[]}})
            );
            assert_eq!(state.original.encode_params().unwrap().unwrap(), before);
            assert_eq!(state.used_ids.len(), 3);
            assert_eq!(state.continuations, 2);
            assert_eq!(state.input_responses, 2);
        }
    }

    #[test]
    fn invalid_answers_and_reused_ids_do_not_commit_a_continuation() {
        let (mut state, _, mut decoder) = initial(ManagedInteractionLimits::default());
        let input = challenge(&mut state, &mut decoder);
        for invalid in [
            reply(7, Some(json!({"r":{"roots":[]}}))),
            reply(8, None),
            reply(8, Some(json!({}))),
            reply(8, Some(json!({"foreign":{"roots":[]}}))),
            reply(8, Some(json!({"r":{"action":"decline"}}))),
            reply(8, Some(json!({"r":{"roots":[]},"extra":{"roots":[]}}))),
        ] {
            assert!(state.resume(&input, invalid).is_err());
            assert_eq!(state.used_ids, vec![RequestId::Number(7)]);
            assert_eq!(state.continuations, 0);
            assert_eq!(state.input_responses, 0);
        }
        assert!(
            state
                .resume(&input, reply(8, Some(json!({"r":{"roots":[]}}))))
                .is_ok()
        );
        assert!(matches!(
            state.resume(&input, reply(8, Some(json!({"r":{"roots":[]}})))),
            Err(DpopInteractionError::Input(
                ManagedInteractionError::RepeatedRequestId
            ))
        ));
    }

    #[test]
    fn resolver_projection_excludes_state_metadata_and_unknown_result_fields() {
        let (mut state, _, mut decoder) = initial(ManagedInteractionLimits::default());
        let source = r#"{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}},"requestState":"private-state-canary","_meta":{"private":"private-meta-canary"},"x-secret":"private-unknown-canary"}"#;
        let result = state.decode(&mut decoder, response(7, source)).unwrap();
        let input = state.accept(&decoder, &result).unwrap().unwrap();
        let projected = DpopInputChallenge::from_input(&input).unwrap();
        let requests = projected.input_requests().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(matches!(
            requests.get("r"),
            Some(FinalEmbeddedInputRequest::Roots(_))
        ));
        let debug = format!("{projected:?}");
        for secret in [
            "private-state-canary",
            "private-meta-canary",
            "private-unknown-canary",
        ] {
            assert!(!debug.contains(secret));
        }
        // Projection does not destroy or rewrite the state needed on wire.
        let (wire, _) = state
            .resume(&input, reply(8, Some(json!({"r":{"roots":[]}}))))
            .unwrap();
        let body: Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(body["params"]["requestState"], "private-state-canary");
        assert!(body["params"].get("x-secret").is_none());
        assert!(body["params"]["_meta"].get("private").is_none());
    }

    #[test]
    fn resolver_projection_keeps_absence_distinct_from_present_empty_inputs() {
        for (source, present) in [
            (
                r#"{"resultType":"input_required","requestState":"private"}"#,
                false,
            ),
            (
                r#"{"resultType":"input_required","inputRequests":{},"requestState":"private"}"#,
                true,
            ),
        ] {
            let (mut state, _, mut decoder) = initial(ManagedInteractionLimits::default());
            let result = state.decode(&mut decoder, response(7, source)).unwrap();
            let input = state.accept(&decoder, &result).unwrap().unwrap();
            let projected = DpopInputChallenge::from_input(&input).unwrap();
            assert_eq!(projected.input_requests().is_some(), present);
            assert!(projected.input_requests().is_none_or(BTreeMap::is_empty));
            assert!(!format!("{projected:?}").contains("private"));
        }
    }

    #[test]
    fn resolver_cannot_replace_the_exact_unicode_continuation_state() {
        let (runtime, cx, _, _) = runtime();
        let (session, credential) = session();
        let cancellation = McpRequestCancellation::new();
        let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
        let (mut state, _, mut decoder) = initial(ManagedInteractionLimits::default());
        let source = r#"{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}},"requestState":"  \u2603+/%\u0000  "}"#;
        let result = state.decode(&mut decoder, response(7, source)).unwrap();
        let input = state.accept(&decoder, &result).unwrap().unwrap();
        let mut resolve = |projected: DpopInputChallenge| {
            assert_eq!(projected.input_requests().unwrap().len(), 1);
            std::future::ready(Ok(reply(8, Some(json!({"r":{"roots":[]}})))))
        };
        let mut waiting = Box::pin(resolve_input(
            &cx,
            &cancellation,
            &session,
            &credential,
            bounds,
            &input,
            &mut resolve,
        ));
        let Poll::Ready(Ok(answer)) = waiting
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("ready resolver did not produce an answer");
        };
        drop(waiting);
        let (wire, _) = state.resume(&input, answer).unwrap();
        let body: Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(body["params"]["requestState"], "  \u{2603}+/%\0  ");
        assert_eq!(body["id"], 8);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn incomplete_multi_input_answers_do_not_create_a_continuation() {
        let (mut state, _, mut decoder) = initial(ManagedInteractionLimits::default());
        let source = r#"{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"},"s":{"method":"roots/list"}},"requestState":"sealed"}"#;
        let result = state.decode(&mut decoder, response(7, source)).unwrap();
        let input = state.accept(&decoder, &result).unwrap().unwrap();
        let before = (state.request_bytes, state.response_bytes);
        assert!(matches!(
            state.resume(&input, reply(8, Some(json!({"r":{"roots":[]}})))),
            Err(DpopInteractionError::Input(
                ManagedInteractionError::InvalidInputResponses
            ))
        ));
        assert_eq!((state.request_bytes, state.response_bytes), before);
        assert_eq!(state.used_ids, vec![RequestId::Number(7)]);
        assert_eq!(state.input_responses, 0);
        let answers = json!({"r":{"roots":[]},"s":{"roots":[]}});
        let (wire, _) = state
            .resume(&input, reply(8, Some(answers.clone())))
            .unwrap();
        let body: Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(body["params"]["inputResponses"], answers);
        assert_eq!(state.input_responses, 2);
        assert_eq!(state.request_bytes, before.0 + wire.body().len());
    }

    #[test]
    fn complete_exchange_obeys_the_exact_combined_request_and_response_byte_limit() {
        const COMPLETE: &str = r#"{"resultType":"complete","content":[]}"#;
        let first_size = response(7, INPUT).body().len();
        let final_size = response(8, COMPLETE).body().len();
        let (mut reference, first_wire, mut decoder) = initial(ManagedInteractionLimits::default());
        let input = challenge(&mut reference, &mut decoder);
        let (second_wire, _) = reference
            .resume(&input, reply(8, Some(json!({"r":{"roots":[]}}))))
            .unwrap();
        let request_bytes = first_wire.body().len() + second_wire.body().len();
        let total = request_bytes + first_size + final_size;
        for exact in [false, true] {
            let maximum = total - usize::from(!exact);
            let core = ManagedCoreLimits::new(
                8192,
                first_size.max(final_size),
                maximum,
                0,
                Duration::from_secs(10),
            )
            .unwrap();
            let limits = ManagedInteractionLimits::new(core, 8, 128).unwrap();
            let (mut state, _, mut decoder) = initial(limits);
            let input = challenge(&mut state, &mut decoder);
            let (_, mut decoder) = state
                .resume(&input, reply(8, Some(json!({"r":{"roots":[]}}))))
                .unwrap();
            assert_eq!(state.request_bytes, request_bytes);
            let result = state.decode(&mut decoder, response(8, COMPLETE));
            if exact {
                assert!(state.accept(&decoder, &result.unwrap()).unwrap().is_none());
                assert_eq!(state.remaining_bytes(), 0);
                assert_eq!(state.response_bytes, first_size + final_size);
            } else {
                assert!(matches!(
                    result,
                    Err(DpopInteractionError::Core(DpopCoreError::Protocol(
                        ManagedCoreError::ResponseByteLimit
                    )))
                ));
                assert_eq!(decoder.usage().0, first_size);
                assert_eq!(state.response_bytes, first_size);
            }
        }
    }

    #[test]
    fn request_budget_refusal_preserves_ids_counters_and_pending_answers() {
        let (mut reference, first_wire, mut decoder) = initial(ManagedInteractionLimits::default());
        let input = challenge(&mut reference, &mut decoder);
        let (second_wire, _) = reference
            .resume(&input, reply(8, Some(json!({"r":{"roots":[]}}))))
            .unwrap();
        let response_size = response(7, INPUT).body().len();
        let maximum = first_wire.body().len() + response_size + second_wire.body().len();
        let core = ManagedCoreLimits::new(8192, response_size, maximum, 0, Duration::from_secs(10))
            .unwrap();
        let limits = ManagedInteractionLimits::new(core, 8, 128).unwrap();
        let (mut state, _, mut decoder) = initial(limits);
        let input = challenge(&mut state, &mut decoder);
        let before = (state.request_bytes, state.response_bytes);
        // An outgoing request that leaves no possible response is refused
        // before an ID or a continuation is committed and before any POST.
        assert!(matches!(
            state.resume(&input, reply(8, Some(json!({"r":{"roots":[]}})))),
            Err(DpopInteractionError::Core(DpopCoreError::Protocol(
                ManagedCoreError::RequestTooLarge
            )))
        ));
        assert_eq!((state.request_bytes, state.response_bytes), before);
        assert_eq!(state.used_ids, vec![RequestId::Number(7)]);
        assert_eq!(state.continuations, 0);
        assert_eq!(state.input_responses, 0);
        assert_eq!(input.request_state(), Some(" opaque+/% "));
    }

    #[test]
    fn state_only_and_empty_input_presence_retain_different_wire_meanings() {
        for (source, answers) in [
            (r#"{"resultType":"input_required","requestState":""}"#, None),
            (
                r#"{"resultType":"input_required","inputRequests":{}}"#,
                Some(json!({})),
            ),
        ] {
            let (mut state, _, mut decoder) = initial(ManagedInteractionLimits::default());
            let result = decode_response(&mut decoder, response(7, source)).unwrap();
            let input = state.accept(&decoder, &result).unwrap().unwrap();
            let opposite = if answers.is_some() {
                None
            } else {
                Some(json!({}))
            };
            assert!(state.resume(&input, reply(8, opposite)).is_err());
            let (wire, _) = state.resume(&input, reply(8, answers.clone())).unwrap();
            let payload: Value = serde_json::from_slice(wire.body()).unwrap();
            assert_eq!(payload["params"].get("inputResponses"), answers.as_ref());
            assert_eq!(
                payload["params"].get("requestState").is_some(),
                answers.is_none()
            );
        }
    }

    #[test]
    fn an_unadvertised_member_refuses_the_whole_challenge() {
        let (mut state, _, mut decoder) = initial(ManagedInteractionLimits::default());
        let mixed = r#"{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"},"s":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":1}}}}"#;
        let result = decode_response(&mut decoder, response(7, mixed)).unwrap();
        assert!(matches!(
            state.accept(&decoder, &result),
            Err(DpopInteractionError::Input(
                ManagedInteractionError::CapabilityNotAdvertised
            ))
        ));
        assert_eq!(state.continuations, 0);
        assert_eq!(state.input_responses, 0);
    }

    #[test]
    fn continuation_and_input_limits_refuse_further_host_work() {
        for (max_rounds, max_inputs, expected_round_limit) in [(0, 4, true), (4, 0, false)] {
            let limits =
                ManagedInteractionLimits::new(ManagedCoreLimits::default(), max_rounds, max_inputs)
                    .unwrap();
            let (mut state, _, mut decoder) = initial(limits);
            let result = decode_response(&mut decoder, response(7, INPUT)).unwrap();
            let error = state.accept(&decoder, &result).err().unwrap();
            if expected_round_limit {
                assert!(matches!(
                    error,
                    DpopInteractionError::Input(ManagedInteractionError::ContinuationLimit)
                ));
            } else {
                assert!(matches!(
                    error,
                    DpopInteractionError::Input(ManagedInteractionError::InputLimit)
                ));
            }
            let (mut state, _, mut decoder) = initial(limits);
            let complete = decode_response(
                &mut decoder,
                response(7, r#"{"resultType":"complete","content":[]}"#),
            )
            .unwrap();
            assert!(state.accept(&decoder, &complete).unwrap().is_none());
        }
    }

    #[test]
    fn response_bytes_are_cumulative_and_exhaustion_precedes_host_resolution() {
        let first_size = response(7, INPUT).body.len();
        let (_, first_wire, _) = initial(ManagedInteractionLimits::default());
        let first_request_size = first_wire.body().len();
        let core = ManagedCoreLimits::new(
            8192,
            first_size,
            first_request_size + first_size,
            0,
            Duration::from_secs(10),
        )
        .unwrap();
        let limits = ManagedInteractionLimits::new(core, 8, 128).unwrap();
        let (mut state, _, mut decoder) = initial(limits);
        let result = decode_response(&mut decoder, response(7, INPUT)).unwrap();
        assert!(matches!(
            state.accept(&decoder, &result),
            Err(DpopInteractionError::Core(DpopCoreError::Protocol(
                ManagedCoreError::ResponseByteLimit
            )))
        ));

        let (mut reference, _, mut reference_decoder) =
            initial(ManagedInteractionLimits::default());
        let input = challenge(&mut reference, &mut reference_decoder);
        let (second_wire, _) = reference
            .resume(&input, reply(8, Some(json!({"r":{"roots":[]}}))))
            .unwrap();
        let core = ManagedCoreLimits::new(
            8192,
            first_size,
            first_request_size + second_wire.body().len() + first_size * 2 - 1,
            0,
            Duration::from_secs(10),
        )
        .unwrap();
        let limits = ManagedInteractionLimits::new(core, 8, 128).unwrap();
        let (mut state, _, mut decoder) = initial(limits);
        let input = challenge(&mut state, &mut decoder);
        let (_, mut decoder) = state
            .resume(&input, reply(8, Some(json!({"r":{"roots":[]}}))))
            .unwrap();
        assert_eq!(decoder.usage().0, first_size);
        assert!(matches!(
            state.decode(&mut decoder, response(8, INPUT)),
            Err(DpopInteractionError::Core(DpopCoreError::Protocol(
                ManagedCoreError::ResponseByteLimit
            )))
        ));
        assert_eq!(decoder.usage().0, first_size);
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PendingReply(Arc<AtomicUsize>);

    impl Future for PendingReply {
        type Output = Result<ManagedInputReply, ManagedInteractionError>;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingReply {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn pending_resolver_wakes_and_drops_for_all_owner_domains_and_the_deadline() {
        for cause in 0..5 {
            let (runtime, cx, timer, clock) = runtime();
            let (session, credential) = session();
            let cancellation = McpRequestCancellation::new();
            let (mut state, _, mut decoder) = initial(ManagedInteractionLimits::default());
            let input = challenge(&mut state, &mut decoder);
            let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
            let invocations = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let mut resolve = |_: DpopInputChallenge| {
                invocations.fetch_add(1, Ordering::SeqCst);
                PendingReply(Arc::clone(&drops))
            };
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = Context::from_waker(&waker);
            let mut waiting = Box::pin(resolve_input(
                &cx,
                &cancellation,
                &session,
                &credential,
                bounds,
                &input,
                &mut resolve,
            ));
            assert!(waiting.as_mut().poll(&mut task).is_pending());
            assert_eq!(invocations.load(Ordering::SeqCst), 1);
            match cause {
                0 => cx.set_cancel_requested(true),
                1 => {
                    cancellation.cancel();
                }
                2 => session.revoke(),
                3 => credential.revoke(),
                _ => {
                    clock.advance(bounds.deadline.as_nanos());
                    assert!(timer.process_timers() > 0);
                }
            }
            assert!(counter.0.load(Ordering::SeqCst) > 0);
            assert!(matches!(
                waiting.as_mut().poll(&mut task),
                Poll::Ready(Err(_))
            ));
            assert_eq!(invocations.load(Ordering::SeqCst), 1);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(state.continuations, 0);
            drop(waiting);
            assert_eq!(timer.pending_count(), 0);
            assert_eq!(Arc::strong_count(&counter), 2);
            drop(cx);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn pre_cancelled_resolution_never_invokes_the_callback() {
        let cx = Cx::for_testing();
        let (session, credential) = session();
        let cancellation = McpRequestCancellation::new();
        cancellation.cancel();
        let (mut state, _, mut decoder) = initial(ManagedInteractionLimits::default());
        let input = challenge(&mut state, &mut decoder);
        let bounds = WaitBounds {
            deadline: asupersync::types::Time::from_nanos(u64::MAX),
            terminal: DpopHttpError::TimedOut,
        };
        let mut resolve = |_: DpopInputChallenge| -> std::future::Ready<
            Result<ManagedInputReply, ManagedInteractionError>,
        > { panic!("cancelled operation invoked its resolver") };
        let mut waiting = Box::pin(resolve_input(
            &cx,
            &cancellation,
            &session,
            &credential,
            bounds,
            &input,
            &mut resolve,
        ));
        assert!(matches!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(DpopInteractionError::Core(DpopCoreError::Transport(
                DpopHttpError::Cancelled
            ))))
        ));
    }

    #[test]
    fn dropping_the_driver_wait_releases_the_resolver_without_revoking_siblings() {
        let (runtime, cx, timer, _) = runtime();
        let (session, credential) = session();
        let cancellation = McpRequestCancellation::new();
        let (mut state, _, mut decoder) = initial(ManagedInteractionLimits::default());
        let input = challenge(&mut state, &mut decoder);
        let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut resolve = |_: DpopInputChallenge| PendingReply(Arc::clone(&drops));
        let mut waiting = Box::pin(resolve_input(
            &cx,
            &cancellation,
            &session,
            &credential,
            bounds,
            &input,
            &mut resolve,
        ));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(waiting);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(timer.pending_count(), 0);
        assert!(!cancellation.is_cancel_requested());
        assert!(!credential.is_revoked());
        assert!(cx.checkpoint().is_ok());
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn a_ready_reply_cannot_escape_mid_poll_token_revocation() {
        let (runtime, cx, timer, _) = runtime();
        let (session, credential) = session();
        let cancellation = McpRequestCancellation::new();
        let (mut state, _, mut decoder) = initial(ManagedInteractionLimits::default());
        let input = challenge(&mut state, &mut decoder);
        let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
        let mut resolve = |_: DpopInputChallenge| {
            credential.revoke();
            std::future::ready(Ok(reply(8, Some(json!({"r":{"roots":[]}})))))
        };
        let mut waiting = Box::pin(resolve_input(
            &cx,
            &cancellation,
            &session,
            &credential,
            bounds,
            &input,
            &mut resolve,
        ));
        assert!(matches!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(DpopInteractionError::Core(DpopCoreError::Transport(
                DpopHttpError::Authorization(
                    crate::http_auth::dpop::DpopClientError::CredentialUnavailable
                )
            ))))
        ));
        assert_eq!(state.continuations, 0);
        drop(waiting);
        assert_eq!(timer.pending_count(), 0);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}

#[cfg(all(test, feature = "native-tls-roots"))]
mod tls_tests {
    use std::future::poll_fn;
    use std::pin::pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};

    use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use asupersync::net::TcpListener;
    use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
    use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder};
    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_protocol::dpop::{DpopKey, DpopNonce};
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::{Value, json};

    use super::*;
    use crate::http_auth::dpop::DpopSession;
    use crate::http_auth::dpop::native::DpopHttpPolicy;

    // Public TEST ONLY identity shared with the existing native OAuth fixtures.
    // Inlined, not included: `*.pem` is transfer-excluded, so including it
    // makes this target unbuildable on a remote worker and a target that fails
    // to build can report `0 passed` instead of failing. Same bytes and same
    // remedy as LEAF and KEY below.
    const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
    const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
    const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

    async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
        let mut left = pin!(left);
        let mut right = pin!(right);
        let mut l = None;
        let mut r = None;
        poll_fn(|task| {
            if l.is_none() {
                if let Poll::Ready(value) = left.as_mut().poll(task) {
                    l = Some(value);
                }
            }
            if r.is_none() {
                if let Poll::Ready(value) = right.as_mut().poll(task) {
                    r = Some(value);
                }
            }
            if l.is_some() && r.is_some() {
                Poll::Ready((l.take().unwrap(), r.take().unwrap()))
            } else {
                Poll::Pending
            }
        })
        .await
    }

    async fn read_request<IO: AsyncRead + Unpin>(io: &mut IO) -> (String, Value) {
        let mut wire = Vec::new();
        let mut buffer = [0_u8; 2048];
        let end = loop {
            let count = io.read(&mut buffer).await.unwrap();
            assert!(count > 0 && wire.len() + count <= 32 * 1024);
            wire.extend_from_slice(&buffer[..count]);
            if let Some(index) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let head = std::str::from_utf8(&wire[..end]).unwrap().to_owned();
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        assert!(end + length <= 32 * 1024);
        while wire.len() < end + length {
            let count = io.read(&mut buffer).await.unwrap();
            assert!(count > 0 && wire.len() + count <= 32 * 1024);
            wire.extend_from_slice(&buffer[..count]);
        }
        assert_eq!(wire.len(), end + length);
        (head, serde_json::from_slice(&wire[end..]).unwrap())
    }

    #[derive(Clone, Copy, Debug)]
    enum Case {
        Complete,
        CompleteMultiInput,
        PartialReply,
        Unadvertised,
        ForeignResponseId,
        HostDeclines,
    }

    #[test]
    fn native_tls_interaction_preserves_identity_and_never_retries_failed_rounds() {
        for case in [
            Case::Complete,
            Case::CompleteMultiInput,
            Case::PartialReply,
            Case::Unadvertised,
            Case::ForeignResponseId,
            Case::HostDeclines,
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
                        let target = CanonicalHttpUrl::parse(&format!("https://{address}/mcp?tenant=one")).unwrap();
                        let token_endpoint = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
                        let session = DpopSession::new(DpopKey::generate().unwrap(), token_endpoint.clone(), target.clone()).unwrap();
                        let credential = session.admit_token_response(
                            &token_endpoint, 200,
                            br#"{"access_token":"interaction-token","token_type":"DPoP","expires_in":60}"#,
                            Instant::now(), Duration::from_secs(60),
                        ).unwrap();
                        let root = Certificate::from_pem(ROOT).unwrap().remove(0);
                        let policy = DpopHttpPolicy::default().with_resource_root_der(root.as_der().to_vec()).unwrap();
                        let mut client = DpopHttpClient::new(session, policy).unwrap();
                        let mut params = json!({"name":"echo","arguments":{"text":"original"}});
                        params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
                        params["_meta"][fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY] = if matches!(case, Case::Unadvertised) {
                            json!({})
                        } else {
                            json!({"roots":{}})
                        };
                        let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap();
                        let expected = request.encode_params().unwrap().unwrap();
                        let acceptor = TlsAcceptorBuilder::new(
                            CertificateChain::from_pem(LEAF).unwrap(),
                            PrivateKey::from_pem(KEY).unwrap(),
                        ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
                        let multi_input = matches!(case, Case::CompleteMultiInput | Case::PartialReply);
                        let complete_answers = if matches!(case, Case::CompleteMultiInput) {
                            json!({"r":{"roots":[]},"s":{"roots":[]}})
                        } else {
                            json!({"r":{"roots":[]}})
                        };
                        let count = if matches!(case, Case::Complete | Case::CompleteMultiInput | Case::ForeignResponseId) { 2 } else { 1 };
                        let server = async {
                            let mut proofs = Vec::new();
                            for round in 0..count {
                                let (socket, _) = listener.accept().await.unwrap();
                                let mut socket = acceptor.accept(socket).await.unwrap();
                                let (head, mut body) = read_request(&mut socket).await;
                                assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
                                assert_eq!(body["id"], 7 + round);
                                assert_eq!(body["method"], "tools/call");
                                if round == 1 {
                                    assert_eq!(body["params"]["requestState"], " opaque+/% ");
                                    assert_eq!(body["params"]["inputResponses"], complete_answers);
                                    body["params"].as_object_mut().unwrap().remove("requestState");
                                    body["params"].as_object_mut().unwrap().remove("inputResponses");
                                }
                                assert_eq!(body["params"], expected);
                                let headers: Vec<_> = head.lines().filter_map(|line| line.split_once(':'))
                                    .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned())).collect();
                                assert_eq!(headers.iter().filter(|(name, _)| name == "authorization").count(), 1);
                                assert!(headers.iter().any(|(name, value)| name == "authorization" && value == "DPoP interaction-token"));
                                assert!(headers.iter().any(|(name, value)| name == "mcp-name" && value == "echo"));
                                let proof = headers.iter().find(|(name, _)| name == "dpop").unwrap().1.clone();
                                assert!(!proofs.contains(&proof));
                                proofs.push(proof);
                                let response = if round == 0 {
                                    let inputs = if multi_input {
                                        json!({"r":{"method":"roots/list"},"s":{"method":"roots/list"}})
                                    } else {
                                        json!({"r":{"method":"roots/list"}})
                                    };
                                    json!({"jsonrpc":"2.0","id":7,"result":{
                                        "resultType":"input_required","inputRequests":inputs,
                                        "requestState":" opaque+/% "
                                    }})
                                } else {
                                    json!({"jsonrpc":"2.0","id":if matches!(case, Case::ForeignResponseId) { 9 } else { 8 },
                                        "result":{"resultType":"complete","content":[{"type":"text","text":"done"}]}})
                                }.to_string();
                                let wire = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nDPoP-Nonce: next-nonce\r\nConnection: close\r\n\r\n{response}", response.len());
                                socket.write_all(wire.as_bytes()).await.unwrap();
                                socket.shutdown().await.unwrap();
                            }
                            proofs.len()
                        };
                        let calls = AtomicUsize::new(0);
                        let cancellation = McpRequestCancellation::new();
                        let application = client.drive_core_interaction(
                            &cx, &cancellation, &credential, request, RequestId::Number(7),
                            ManagedInteractionLimits::default(),
                            |input| {
                                calls.fetch_add(1, Ordering::SeqCst);
                                let requests = input.input_requests().unwrap();
                                assert_eq!(requests.len(), if multi_input { 2 } else { 1 });
                                assert!(matches!(requests.get("r"), Some(FinalEmbeddedInputRequest::Roots(_))));
                                assert!(!format!("{input:?}").contains("opaque"));
                                std::future::ready(if matches!(case, Case::HostDeclines) {
                                    Err(ManagedInteractionError::AbortedByHost)
                                } else {
                                    Ok(ManagedInputReply {
                                        request_id: RequestId::Number(8),
                                        input_responses: Some(serde_json::from_value(complete_answers.clone()).unwrap()),
                                    })
                                })
                            },
                        );
                        let (requests, outcome) = pair(server, application).await;
                        assert_eq!(requests, count);
                        match case {
                            Case::Complete | Case::CompleteMultiInput => assert!(outcome.unwrap().encode().unwrap().contains("done")),
                            Case::PartialReply => assert!(matches!(outcome, Err(DpopInteractionError::Input(ManagedInteractionError::InvalidInputResponses)))),
                            Case::Unadvertised => assert!(matches!(outcome, Err(DpopInteractionError::Input(ManagedInteractionError::CapabilityNotAdvertised)))),
                            Case::ForeignResponseId => assert!(matches!(outcome, Err(DpopInteractionError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseIdMismatch))))),
                            Case::HostDeclines => assert!(matches!(outcome, Err(DpopInteractionError::Input(ManagedInteractionError::AbortedByHost)))),
                        }
                        assert_eq!(calls.load(Ordering::SeqCst), usize::from(!matches!(case, Case::Unadvertised)));
                        assert!(!credential.is_revoked());
                        assert_eq!(client.session.resource_nonce, Some(DpopNonce::new("next-nonce").unwrap()));
                        assert!(client.session.token_nonce.is_none());
                        assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
                    }).await.expect("DPoP interaction must settle without an implicit extra request");
                });
        }
    }
}
