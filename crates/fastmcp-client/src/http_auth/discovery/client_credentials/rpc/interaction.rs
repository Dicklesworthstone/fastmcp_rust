//! Host-controlled multi-round core operations for machine OAuth clients.
//!
//! Reuses the interactive client's challenge/capability/answer validators, but
//! routes every round through the machine client's fresh same-token discovery.
//! A host explicitly supplies a fresh discovery ID, operation ID and correlated
//! answers. It cannot replace the target, method, original arguments, metadata
//! or opaque requestState. No transport failure is an automatic retry signal.

use std::fmt;
use std::future::Future;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreRequest, CoreResult, FinalInputResponses, InputRequiredResult, RequestId, ServerNotification};

use super::{ClientCredentialsCoreCall, ClientCredentialsCoreError, ManagedCoreEvent, preflight};
use super::super::{ClientCredentialsClient, ClientCredentialsError, active, check_context, discovery_deadline};
use crate::http_auth::rpc::ManagedCoreError;
use crate::http_auth::rpc::interaction::{
    ManagedInteractionError, admit_challenge, admit_fresh_id, continuation_request,
    input_required, validate_initial, InputSelection, continuation_request_selected,
};

pub use crate::http_auth::rpc::interaction::{ManagedInteractionEvent, ManagedInteractionLimits};

/// Sanitized call or interaction-policy failure. No answer, opaque state,
/// original argument, malformed peer frame or credential is retained.
#[derive(Debug)]
pub enum ClientCredentialsInteractionError {
    Core(ClientCredentialsCoreError),
    Interaction(ManagedInteractionError),
}

impl fmt::Display for ClientCredentialsInteractionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => fmt::Display::fmt(error, formatter),
            Self::Interaction(error) => fmt::Display::fmt(error, formatter),
        }
    }
}
impl std::error::Error for ClientCredentialsInteractionError {}
impl From<ClientCredentialsCoreError> for ClientCredentialsInteractionError {
    fn from(error: ClientCredentialsCoreError) -> Self { Self::Core(error) }
}
impl From<ClientCredentialsError> for ClientCredentialsInteractionError {
    fn from(error: ClientCredentialsError) -> Self { Self::Core(error.into()) }
}
impl From<ManagedCoreError> for ClientCredentialsInteractionError {
    fn from(error: ManagedCoreError) -> Self { Self::Core(error.into()) }
}
impl From<ManagedInteractionError> for ClientCredentialsInteractionError {
    fn from(error: ManagedInteractionError) -> Self { Self::Interaction(error) }
}

/// Answers to the current challenge. Both IDs must be fresh across the entire
/// interaction, including IDs used by earlier discovery requests. This type
/// deliberately has no Debug or Clone implementation: answers can be private.
pub struct ClientCredentialsInputReply {
    pub discovery_id: RequestId,
    pub request_id: RequestId,
    pub input_responses: Option<FinalInputResponses>,
}

enum Step {
    Reading(Box<ClientCredentialsCoreCall>),
    Awaiting(Box<InputRequiredResult>),
    Complete,
}

/// An immutable machine identity and original request, one current response or
/// challenge, and bounded cumulative work. It retains a machine client clone so
/// dropping another clone cannot accidentally abandon the credential owner.
/// Explicit client close remains effective across all clones.
///
/// Each round has one discovery POST and one operation POST; the supplied
/// continuation limit bounds rounds, not all HTTP traffic. Credential grants
/// remain bounded by the machine client's existing acquisition policy. Total
/// response bytes and notification counts span operation responses in every
/// round; discovery retains its existing separate document bound.
///
/// A local answer/ID/size refusal leaves the pending challenge correctable.
/// Once resume reaches dispatch, any error or dropped future retires the
/// interaction. Neither a failed operation nor a host callback is replayed.
pub struct ClientCredentialsInteraction {
    client: ClientCredentialsClient,
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

impl fmt::Debug for ClientCredentialsInteraction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ClientCredentialsInteraction")
            .field("continuations", &self.continuations)
            .field("awaiting_input", &matches!(self.step, Some(Step::Awaiting(_))))
            .field("closed", &self.step.is_none())
            .finish_non_exhaustive()
    }
}

impl ClientCredentialsClient {
    /// Begins an explicitly selected tools/call, resources/read or prompts/get
    /// interaction. One deadline includes all rounds and time spent waiting for
    /// host input. This never starts a model, opens a URL, or discovers roots.
    pub async fn start_core_interaction(
        &self,
        cx: &Cx,
        request: CoreRequest,
        discovery_id: RequestId,
        request_id: RequestId,
        limits: ManagedInteractionLimits,
    ) -> Result<ClientCredentialsInteraction, ClientCredentialsInteractionError> {
        self.start_core_interaction_with_cancellation(
            cx, &McpRequestCancellation::new(), request, discovery_id, request_id, limits,
        ).await
    }

    pub async fn start_core_interaction_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        discovery_id: RequestId,
        request_id: RequestId,
        limits: ManagedInteractionLimits,
    ) -> Result<ClientCredentialsInteraction, ClientCredentialsInteractionError> {
        let core = limits.core();
        let deadline = discovery_deadline(cx, core.timeout().min(self.inner.timeout))
            .map_err(ClientCredentialsError::from)?;
        validate_initial(&request)?;
        admit_pair(&[], &discovery_id, &request_id)?;
        preflight(self.resource(), &request, &discovery_id, &request_id, core)?;
        let mut call = active(cx, deadline, &self.inner.closed, cancellation, None, async {
            Ok(self.request_core_with_cancellation(
                cx, cancellation, request.clone(), discovery_id.clone(), request_id.clone(), core,
            ).await)
        }).await??;
        call.deadline = call.deadline.min(deadline);
        let generation = call.credential_generation();
        Ok(ClientCredentialsInteraction {
            client: self.clone(), original: request, step: Some(Step::Reading(Box::new(call))),
            cancellation: cancellation.clone(), deadline, limits,
            used_ids: vec![discovery_id, request_id], continuations: 0, input_responses: 0,
            response_bytes: 0, notifications: 0, generation,
        })
    }
}

fn admit_pair(
    used: &[RequestId],
    discovery_id: &RequestId,
    request_id: &RequestId,
) -> Result<(), ManagedInteractionError> {
    admit_fresh_id(used, discovery_id)?;
    admit_fresh_id(used, request_id)?;
    if discovery_id.correlates_with(request_id) {
        return Err(ManagedInteractionError::RepeatedRequestId);
    }
    Ok(())
}

impl ClientCredentialsInteraction {
    /// Reading this challenge is not consent to disclose data or perform any
    /// requested action. The host owns its input and disclosure policy.
    pub fn pending_input(&self) -> Option<&InputRequiredResult> {
        match &self.step {
            Some(Step::Awaiting(input)) => Some(input),
            _ => None,
        }
    }

    pub fn continuation_count(&self) -> usize { self.continuations }
    pub fn credential_generation(&self) -> u64 { self.generation }
    pub fn close(&mut self) { self.step = None; }

    /// Delivers one notification, challenge or final result. Awaiting input is
    /// not EOF; calling again before resume returns InputPending. Only an
    /// already-delivered complete result yields subsequent Ok(None).
    pub async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ManagedInteractionEvent>, ClientCredentialsInteractionError> {
        self.check(cx)?;
        let step = self.step.take().ok_or(ManagedInteractionError::Closed)?;
        let mut call = match step {
            Step::Reading(call) => call,
            Step::Awaiting(input) => {
                self.step = Some(Step::Awaiting(input));
                return Err(ManagedInteractionError::InputPending.into());
            }
            Step::Complete => {
                self.step = Some(Step::Complete);
                return Ok(None);
            }
        };
        let event = call.next_event(cx).await?.ok_or(ManagedCoreError::MissingTerminal)?;
        (self.response_bytes, self.notifications) = call.decoder.usage();
        self.check(cx)?;
        match event {
            ManagedCoreEvent::Notification(notification) => {
                self.step = Some(Step::Reading(call));
                Ok(Some(ManagedInteractionEvent::Notification(notification)))
            }
            ManagedCoreEvent::Result(result) => {
                if let Some(input) = input_required(&result) {
                    if self.response_bytes >= self.limits.core().total_bytes() {
                        return Err(ManagedCoreError::ResponseByteLimit.into());
                    }
                    admit_challenge(&self.original, input, self.limits,
                        self.continuations, self.input_responses)?;
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

    /// Echoes only the current challenge's exact opaque state and validated
    /// answers in one explicitly authorized continuation. Missing and empty
    /// input maps remain distinct; old answers never accumulate across rounds.
    /// Local validation completes before consuming the pending challenge.
    pub async fn resume(
        &mut self,
        cx: &Cx,
        discovery_id: RequestId,
        request_id: RequestId,
        responses: Option<FinalInputResponses>,
    ) -> Result<(), ClientCredentialsInteractionError> {
        self.resume_selected(cx, discovery_id, request_id, responses, InputSelection::Complete).await
    }

    /// Submits only the nonempty set of answers explicitly selected by the
    /// host. A proper subset requires nonempty server-issued requestState.
    /// The next server result, not a local merge, defines the next challenge.
    /// All original metadata, arguments, capability and cumulative work bounds
    /// remain in force. Both IDs must be fresh across discovery and operation
    /// requests from every prior round. Local refusal preserves this challenge;
    /// once discovery starts, failure or abandonment cannot authorize a retry.
    pub async fn resume_partial(
        &mut self,
        cx: &Cx,
        discovery_id: RequestId,
        request_id: RequestId,
        responses: FinalInputResponses,
    ) -> Result<(), ClientCredentialsInteractionError> {
        self.resume_selected(cx, discovery_id, request_id, Some(responses), InputSelection::Partial).await
    }

    async fn resume_selected(
        &mut self,
        cx: &Cx,
        discovery_id: RequestId,
        request_id: RequestId,
        responses: Option<FinalInputResponses>,
        selection: InputSelection,
    ) -> Result<(), ClientCredentialsInteractionError> {
        self.check(cx)?;
        let Some(Step::Awaiting(input)) = &self.step else {
            return Err(if self.step.is_none() {
                ManagedInteractionError::Closed
            } else {
                ManagedInteractionError::NotAwaitingInput
            }.into());
        };
        admit_pair(&self.used_ids, &discovery_id, &request_id)?;
        let count = responses.as_ref().map_or(0, FinalInputResponses::len);
        let next = match selection {
            InputSelection::Complete => continuation_request(&self.original, input, responses)?,
            InputSelection::Partial => continuation_request_selected(&self.original, input, responses, selection)?,
        };
        preflight(self.client.resource(), &next, &discovery_id, &request_id, self.limits.core())?;
        self.check(cx)?;
        // Commit ownership before suspension. A failed discovery also consumes
        // this attempt; it cannot authorize replay of the same opaque state.
        self.step = None;
        self.used_ids.push(discovery_id.clone());
        self.used_ids.push(request_id.clone());
        self.continuations += 1;
        self.input_responses += count;
        let mut call = active(
            cx, self.deadline, &self.client.inner.closed, &self.cancellation, None,
            async {
                Ok(self.client.request_core_with_cancellation(
                    cx, &self.cancellation, next, discovery_id, request_id, self.limits.core(),
                ).await)
            },
        ).await??;
        call.deadline = call.deadline.min(self.deadline);
        call.decoder.resume_usage(self.response_bytes, self.notifications)?;
        self.generation = call.credential_generation();
        self.step = Some(Step::Reading(Box::new(call)));
        Ok(())
    }

    /// Runs explicitly supplied host callbacks under the original interaction
    /// deadline, owner closure and request cancellation. Consuming self means a
    /// failed or abandoned driver cannot repeat a callback or continuation.
    /// notify is synchronous and must not block the caller's async runtime.
    pub async fn drive<R, F, N>(
        self,
        cx: &Cx,
        resolve: R,
        notify: N,
    ) -> Result<Box<CoreResult>, ClientCredentialsInteractionError>
    where
        R: FnMut(Box<InputRequiredResult>) -> F,
        F: Future<Output = Result<ClientCredentialsInputReply, ClientCredentialsInteractionError>>,
        N: FnMut(Box<ServerNotification>) -> Result<(), ClientCredentialsInteractionError>,
    {
        self.drive_selected(cx, resolve, notify, InputSelection::Complete).await
    }

    /// Like `drive`, but a nonempty host reply may answer a subset of the
    /// current inputs. Omitted inputs are never executed or given fabricated
    /// replies. Absent/present-empty input maps retain the exhaustive contract;
    /// a proper subset requires server-owned continuation state. This does not
    /// replay callbacks or extend the original deadline and response budgets.
    pub async fn drive_partial<R, F, N>(
        self,
        cx: &Cx,
        resolve: R,
        notify: N,
    ) -> Result<Box<CoreResult>, ClientCredentialsInteractionError>
    where
        R: FnMut(Box<InputRequiredResult>) -> F,
        F: Future<Output = Result<ClientCredentialsInputReply, ClientCredentialsInteractionError>>,
        N: FnMut(Box<ServerNotification>) -> Result<(), ClientCredentialsInteractionError>,
    {
        self.drive_selected(cx, resolve, notify, InputSelection::Partial).await
    }

    async fn drive_selected<R, F, N>(
        mut self,
        cx: &Cx,
        mut resolve: R,
        mut notify: N,
        selection: InputSelection,
    ) -> Result<Box<CoreResult>, ClientCredentialsInteractionError>
    where
        R: FnMut(Box<InputRequiredResult>) -> F,
        F: Future<Output = Result<ClientCredentialsInputReply, ClientCredentialsInteractionError>>,
        N: FnMut(Box<ServerNotification>) -> Result<(), ClientCredentialsInteractionError>,
    {
        loop {
            self.check(cx)?;
            if let Some(input) = self.pending_input().cloned() {
                let reply = active(
                    cx, self.deadline, &self.client.inner.closed, &self.cancellation, None,
                    async { Ok(resolve(Box::new(input)).await) },
                ).await??;
                let selected = if reply.input_responses.as_ref().is_some_and(|answers| !answers.is_empty()) {
                    selection
                } else { InputSelection::Complete };
                self.resume_selected(cx, reply.discovery_id, reply.request_id, reply.input_responses, selected).await?;
                continue;
            }
            match self.next_event(cx).await? {
                Some(ManagedInteractionEvent::Notification(notification)) => notify(notification)?,
                Some(ManagedInteractionEvent::InputRequired(_)) => {},
                Some(ManagedInteractionEvent::Complete(result)) => return Ok(result),
                None => return Err(ManagedInteractionError::Closed.into()),
            }
        }
    }

    fn check(&mut self, cx: &Cx) -> Result<(), ClientCredentialsInteractionError> {
        let deadline = cx.budget().deadline.map_or(self.deadline, |caller| caller.min(self.deadline));
        let result = if self.client.inner.closed.is_cancel_requested() {
            Err(ClientCredentialsError::Closed)
        } else if self.cancellation.is_cancel_requested() {
            Err(super::super::super::OAuthDiscoveryError::Cancelled.into())
        } else {
            check_context(cx, deadline).map_err(ClientCredentialsError::from)
                .and_then(|()| self.client.inner.authentication.check())
        };
        if let Err(error) = result {
            self.close();
            return Err(error.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::{Value, json};

    fn original(method: &str, mut params: Value, capabilities: Value) -> CoreRequest {
        let mut metadata = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        metadata[fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY] = capabilities;
        metadata["com.example/identity"] = json!("immutable-machine-owner");
        params["_meta"] = metadata;
        CoreRequest::decode(fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026,
            method, Some(&params)).unwrap()
    }

    fn challenge(request: &CoreRequest, raw: &str) -> InputRequiredResult {
        input_required(&request.decode_result(raw).unwrap()).unwrap().clone()
    }

    #[test]
    fn machine_continuation_ids_are_fresh_across_both_discovery_and_operation() {
        let used = [RequestId::Number(1), RequestId::Number(2)];
        assert!(admit_pair(&used, &RequestId::Number(3), &RequestId::Number(4)).is_ok());
        for (discovery, operation) in [(1, 4), (2, 4), (3, 1), (3, 2), (3, 3)] {
            assert!(matches!(admit_pair(&used, &RequestId::Number(discovery), &RequestId::Number(operation)),
                Err(ManagedInteractionError::RepeatedRequestId)));
        }
        assert!(admit_pair(&used, &RequestId::String("1".to_owned()), &RequestId::String("2".to_owned())).is_ok());
    }

    #[test]
    fn machine_continuation_keeps_original_fields_and_only_the_current_answers() {
        for (method, params) in [
            ("tools/call", json!({"name":"echo","arguments":{"payload":"original"}})),
            ("resources/read", json!({"uri":"file:///opaque/%2Fresource"})),
            ("prompts/get", json!({"name":"prompt","arguments":{"subject":"original"}})),
        ] {
            let original = original(method, params, json!({"roots":{}}));
            validate_initial(&original).unwrap();
            let before = original.encode_params().unwrap().unwrap();
            let first = challenge(&original,
                r#"{"resultType":"input_required","inputRequests":{"first":{"method":"roots/list"}},"requestState":"  opaque+/%\u0000  "}"#);
            admit_challenge(&original, &first, ManagedInteractionLimits::default(), 0, 0).unwrap();
            let answers = serde_json::from_value(json!({"first":{"roots":[]}})).unwrap();
            let next = continuation_request(&original, &first, Some(answers)).unwrap();
            let mut after = next.encode_params().unwrap().unwrap();
            assert_eq!(after["requestState"], "  opaque+/%\0  ");
            after.as_object_mut().unwrap().remove("inputResponses");
            after.as_object_mut().unwrap().remove("requestState");
            assert_eq!(after, before);
            let second = challenge(&next,
                r#"{"resultType":"input_required","inputRequests":{"second":{"method":"roots/list"}}}"#);
            let answers = serde_json::from_value(json!({"second":{"roots":[]}})).unwrap();
            let next = continuation_request(&original, &second, Some(answers)).unwrap().encode_params().unwrap().unwrap();
            assert!(next.get("requestState").is_none());
            assert_eq!(next["inputResponses"], json!({"second":{"roots":[]}}));
            assert_eq!(original.encode_params().unwrap().unwrap(), before);
        }
    }

    #[test]
    fn machine_challenges_require_advertised_capabilities_and_remaining_work() {
        let allowed = original("tools/call", json!({"name":"echo"}), json!({"roots":{}}));
        let denied = original("tools/call", json!({"name":"echo"}), json!({}));
        let input = challenge(&allowed, r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}}}"#);
        assert!(admit_challenge(&allowed, &input, ManagedInteractionLimits::default(), 0, 0).is_ok());
        assert!(matches!(admit_challenge(&denied, &input, ManagedInteractionLimits::default(), 0, 0),
            Err(ManagedInteractionError::CapabilityNotAdvertised)));
        let no_rounds = ManagedInteractionLimits::new(super::super::ManagedCoreLimits::default(), 0, 1).unwrap();
        assert!(matches!(admit_challenge(&allowed, &input, no_rounds, 0, 0),
            Err(ManagedInteractionError::ContinuationLimit)));
        let one_input = ManagedInteractionLimits::new(super::super::ManagedCoreLimits::default(), 2, 1).unwrap();
        assert!(matches!(admit_challenge(&allowed, &input, one_input, 1, 1),
            Err(ManagedInteractionError::InputLimit)));
    }

    #[test]
    fn machine_answers_preserve_absent_empty_and_kind_distinctions() {
        let original = original("resources/read", json!({"uri":"file:///input"}), json!({"roots":{}}));
        let input = challenge(&original, r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}}}"#);
        for wrong in [json!({}), json!({"other":{"roots":[]}}), json!({"roots":{"action":"decline"}}),
            json!({"roots":{"roots":[]},"extra":{"roots":[]}})]
        {
            let answers = serde_json::from_value(wrong).unwrap();
            assert!(matches!(continuation_request(&original, &input, Some(answers)),
                Err(ManagedInteractionError::InvalidInputResponses)));
        }
        let empty = challenge(&original, r#"{"resultType":"input_required","inputRequests":{}}"#);
        assert!(continuation_request(&original, &empty, None).is_err());
        assert!(continuation_request(&original, &empty, Some(serde_json::from_value(json!({})).unwrap())).is_ok());
        let state = challenge(&original, r#"{"resultType":"input_required","requestState":""}"#);
        assert!(continuation_request(&original, &state, None).is_ok());
        assert!(continuation_request(&original, &state, Some(serde_json::from_value(json!({})).unwrap())).is_err());
    }

    fn runtime() -> asupersync::runtime::Runtime {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .blocking_threads(0, 2)
            .build().unwrap()
    }

    // A revoked cached token forces a real acquisition refusal before network
    // contact. This tests ownership/attempt retirement, not an issuer exchange.
    fn awaiting(cx: &Cx) -> ClientCredentialsInteraction {
        use std::sync::{Arc, atomic::AtomicUsize};
        use std::time::{Duration, Instant};
        use crate::http_auth::discovery::client_credentials as machine;

        let resource = fastmcp_core::CanonicalHttpUrl::parse("https://machine.example/mcp").unwrap();
        let closed = McpRequestCancellation::new();
        let expires_at = Instant::now() + Duration::from_secs(60);
        let bearer = crate::http_auth::BoundBearerCredential::bind_with_expiry(
            resource.clone(), "revoked-local-test-token", expires_at,
        ).unwrap().for_owner(&closed).unwrap();
        bearer.revoke();
        let client = ClientCredentialsClient {
            inner: Arc::new(machine::ClientInner {
                resource,
                token_endpoint: fastmcp_core::CanonicalHttpUrl::parse("https://issuer.example/token").unwrap(),
                client_id: "machine-test-client".to_owned(), scopes: vec![],
                authentication: machine::MachineAuthentication::Basic(Arc::new(machine::ClientSecret("test-only".to_owned()))),
                issuer_roots: vec![], timeout: Duration::from_secs(5),
                maximum_lifetime: Duration::from_secs(60), leeway: Duration::from_secs(1),
                closed, pending: AtomicUsize::new(0),
                state: Arc::new(asupersync::sync::Mutex::new(machine::TokenState {
                    current: Some(machine::ServiceToken { bearer, scopes: vec![], expires_at, renew_after: expires_at }),
                    generation: 1,
                })),
            }),
        };
        let original = original("tools/call", json!({"name":"echo"}), json!({}));
        let input = challenge(&original, r#"{"resultType":"input_required","requestState":"current-state"}"#);
        ClientCredentialsInteraction {
            client, original, step: Some(Step::Awaiting(Box::new(input))),
            cancellation: McpRequestCancellation::new(),
            deadline: discovery_deadline(cx, Duration::from_secs(5)).unwrap(),
            limits: ManagedInteractionLimits::default(),
            used_ids: vec![RequestId::Number(1), RequestId::Number(2)],
            continuations: 0, input_responses: 0, response_bytes: 0, notifications: 0, generation: 1,
        }
    }

    #[test]
    fn machine_local_resume_refusals_keep_the_pending_challenge_correctable() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let mut operation = awaiting(&cx);
            assert!(matches!(operation.next_event(&cx).await,
                Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::InputPending))));
            let wrong = Some(serde_json::from_value(json!({})).unwrap());
            assert!(matches!(operation.resume(&cx, RequestId::Number(3), RequestId::Number(4), wrong).await,
                Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::InvalidInputResponses))));
            assert!(matches!(operation.resume(&cx, RequestId::Number(1), RequestId::Number(4), None).await,
                Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::RepeatedRequestId))));
            assert_eq!(operation.pending_input().unwrap().request_state(), Some("current-state"));
            assert_eq!(operation.continuation_count(), 0);
            assert_eq!(operation.used_ids.len(), 2);
        });
    }

    #[test]
    fn machine_started_resume_failure_cannot_reuse_its_challenge_or_ids() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let mut operation = awaiting(&cx);
            assert!(matches!(operation.resume(&cx, RequestId::Number(3), RequestId::Number(4), None).await,
                Err(ClientCredentialsInteractionError::Core(ClientCredentialsCoreError::Authentication(ClientCredentialsError::Expired)))));
            assert!(operation.pending_input().is_none());
            assert_eq!(operation.continuation_count(), 1);
            assert_eq!(operation.used_ids.len(), 4);
            assert!(matches!(operation.resume(&cx, RequestId::Number(5), RequestId::Number(6), None).await,
                Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::Closed))));
            assert_eq!(operation.continuation_count(), 1);
        });
    }

    #[test]
    fn machine_cancellation_and_owner_close_retire_waiting_input_without_an_attempt() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            for close_owner in [false, true] {
                let mut operation = awaiting(&cx);
                if close_owner { operation.client.close(); }
                else { operation.cancellation.cancel(); }
                assert!(operation.resume(&cx, RequestId::Number(3), RequestId::Number(4), None).await.is_err());
                assert!(operation.pending_input().is_none());
                assert_eq!(operation.continuation_count(), 0);
                assert_eq!(operation.used_ids.len(), 2);
            }
        });
    }

    #[test]
    fn machine_driver_drops_a_pending_host_resolver_when_its_owner_closes() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let operation = awaiting(&cx);
            let closer = operation.client.clone();
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&calls);
            let result = operation.drive(&cx, move |_| {
                observed.fetch_add(1, Ordering::Relaxed);
                let closer = closer.clone();
                async move {
                    closer.close();
                    std::future::pending::<Result<ClientCredentialsInputReply, ClientCredentialsInteractionError>>().await
                }
            }, |_| Ok(())).await;
            assert!(matches!(result,
                Err(ClientCredentialsInteractionError::Core(ClientCredentialsCoreError::Authentication(ClientCredentialsError::Closed)))));
            assert_eq!(calls.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn machine_continuation_budget_carries_bytes_and_notifications_between_rounds() {
        use crate::http_auth::rpc::{CoreDecoder, ManagedCoreLimits};
        use std::time::Duration;

        let limits = ManagedCoreLimits::new(4096, 1024, 2048, 1, Duration::from_secs(1)).unwrap();
        let request = original("tools/call", json!({"name":"echo"}), json!({}));
        let mut first = CoreDecoder::for_request(request.clone(), RequestId::Number(2), limits).unwrap();
        let notification = br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        first.admit(notification, true).unwrap();
        let mut second = CoreDecoder::for_request(request.clone(), RequestId::Number(4), limits).unwrap();
        let (bytes, notifications) = first.usage();
        second.resume_usage(bytes, notifications).unwrap();
        assert!(matches!(second.admit(notification, true), Err(ManagedCoreError::NotificationLimit)));
        assert_eq!(second.usage(), first.usage());
        let terminal = br#"{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete","content":[]}}"#;
        assert!(matches!(second.admit(terminal, true), Ok(ManagedCoreEvent::Result(_))));
        assert_eq!(second.usage(), (bytes + terminal.len(), notifications));
        let observed = second.usage();
        assert!(matches!(second.resume_usage(0, 0), Err(ManagedCoreError::InvalidResponse)));
        assert_eq!(second.usage(), observed);
        let mut full = CoreDecoder::for_request(request, RequestId::Number(6), limits).unwrap();
        assert!(matches!(full.resume_usage(2048, 0), Err(ManagedCoreError::ResponseByteLimit)));
        assert!(matches!(full.resume_usage(0, 2), Err(ManagedCoreError::NotificationLimit)));
        assert_eq!(full.usage(), (0, 0));
    }

    fn awaiting_partial(cx: &Cx, state: Option<&str>) -> ClientCredentialsInteraction {
        let mut operation = awaiting(cx);
        operation.original = original("tools/call", json!({"name":"echo"}), json!({"roots":{}}));
        let mut result = json!({"resultType":"input_required","inputRequests":{
            "one":{"method":"roots/list"},"two":{"method":"roots/list"}
        }});
        if let Some(state) = state { result["requestState"] = json!(state); }
        operation.step = Some(Step::Awaiting(Box::new(challenge(&operation.original, &result.to_string()))));
        operation
    }

    fn answer(key: &str) -> FinalInputResponses {
        serde_json::from_value(json!({key:{"roots":[]}})).unwrap()
    }

    #[test]
    fn machine_partial_refusals_preserve_challenge_ids_and_all_work_counters() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let mut operation = awaiting_partial(&cx, Some("state"));
            let original = operation.original.encode_params().unwrap();
            for invalid in [FinalInputResponses::default(), answer("foreign"),
                serde_json::from_value(json!({"one":{"action":"decline"}})).unwrap()]
            {
                assert!(matches!(operation.resume_partial(&cx, RequestId::Number(3), RequestId::Number(4), invalid).await,
                    Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::InvalidInputResponses))));
            }
            assert!(matches!(operation.resume(&cx, RequestId::Number(3), RequestId::Number(4), Some(answer("one"))).await,
                Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::InvalidInputResponses))));
            assert_eq!(operation.pending_input().unwrap().input_requests().unwrap().members().len(), 2);
            assert_eq!(operation.pending_input().unwrap().request_state(), Some("state"));
            assert_eq!(operation.original.encode_params().unwrap(), original);
            assert_eq!(operation.used_ids, [RequestId::Number(1), RequestId::Number(2)]);
            assert_eq!((operation.continuations, operation.input_responses, operation.response_bytes, operation.notifications), (0,0,0,0));
        });
    }

    #[test]
    fn machine_partial_admission_uses_both_id_namespaces_before_credential_work() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let mut operation = awaiting_partial(&cx, Some("state"));
            for (discovery, request) in [(1,4), (2,4), (3,1), (3,2), (3,3)] {
                assert!(matches!(operation.resume_partial(&cx, RequestId::Number(discovery), RequestId::Number(request), answer("one")).await,
                    Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::RepeatedRequestId))));
            }
            assert_eq!(operation.continuation_count(), 0);
            assert_eq!(operation.used_ids.len(), 2);
            assert!(operation.pending_input().is_some());
        });
    }

    #[test]
    fn machine_partial_dispatch_failure_consumes_only_the_selected_answers_once() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let mut operation = awaiting_partial(&cx, Some("state"));
            // The existing fixture's revoked token refuses acquisition. The
            // partial response must reach this boundary, not full-map validation.
            assert!(matches!(operation.resume_partial(&cx, RequestId::Number(3), RequestId::Number(4), answer("one")).await,
                Err(ClientCredentialsInteractionError::Core(ClientCredentialsCoreError::Authentication(ClientCredentialsError::Expired)))));
            assert!(operation.pending_input().is_none());
            assert_eq!((operation.continuations, operation.input_responses, operation.used_ids.len()), (1,1,4));
            assert!(matches!(operation.resume_partial(&cx, RequestId::Number(5), RequestId::Number(6), answer("one")).await,
                Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::Closed))));
            assert_eq!((operation.continuations, operation.input_responses, operation.used_ids.len()), (1,1,4));
        });
    }

    #[test]
    fn machine_partial_state_refusal_does_not_consume_the_full_answer_control() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            for state in [None, Some("")] {
                let mut operation = awaiting_partial(&cx, state);
                assert!(matches!(operation.resume_partial(&cx, RequestId::Number(3), RequestId::Number(4), answer("one")).await,
                    Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::PartialStateRequired))));
                assert_eq!(operation.continuation_count(), 0);
                let all = serde_json::from_value(json!({"one":{"roots":[]},"two":{"roots":[]}})).unwrap();
                assert!(matches!(operation.resume_partial(&cx, RequestId::Number(3), RequestId::Number(4), all).await,
                    Err(ClientCredentialsInteractionError::Core(ClientCredentialsCoreError::Authentication(ClientCredentialsError::Expired)))));
                assert_eq!((operation.continuations, operation.input_responses), (1,2));
            }
        });
    }

    #[test]
    fn machine_partial_owner_close_prevents_callbacks_and_attempts() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let operation = awaiting_partial(&cx, Some("state"));
            operation.client.close();
            let calls = std::cell::Cell::new(0);
            let outcome = operation.drive_partial(&cx, |_| {
                calls.set(calls.get() + 1);
                std::future::ready(Ok(ClientCredentialsInputReply {
                    discovery_id: RequestId::Number(3), request_id: RequestId::Number(4),
                    input_responses: Some(answer("one")),
                }))
            }, |_| Ok(())).await;
            assert!(matches!(outcome,
                Err(ClientCredentialsInteractionError::Core(ClientCredentialsCoreError::Authentication(ClientCredentialsError::Closed)))));
            assert_eq!(calls.get(), 0);
        });
    }

    #[test]
    fn machine_partial_driver_cancellation_discards_ready_host_answers() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let operation = awaiting_partial(&cx, Some("state"));
            let cancel = operation.cancellation.clone();
            let calls = std::cell::Cell::new(0);
            let outcome = operation.drive_partial(&cx, |_| {
                calls.set(calls.get() + 1);
                cancel.cancel();
                std::future::ready(Ok(ClientCredentialsInputReply {
                    discovery_id: RequestId::Number(3), request_id: RequestId::Number(4),
                    input_responses: Some(answer("one")),
                }))
            }, |_| Ok(())).await;
            assert!(matches!(outcome, Err(ClientCredentialsInteractionError::Core(
                ClientCredentialsCoreError::Authentication(ClientCredentialsError::Discovery(
                    super::super::super::super::OAuthDiscoveryError::Cancelled))))));
            assert_eq!(calls.get(), 1);
        });
    }
}
