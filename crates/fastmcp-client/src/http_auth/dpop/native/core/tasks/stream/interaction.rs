//! Task-capable tool conversations over DPoP, JSON/SSE and explicit host input.
//!
//! This joins existing Tasks negotiation, method-owned reply decoding, the
//! common stream reader and the shared typed input session. A Task ends this
//! conversation; it is not implicitly polled, updated or cancelled.

use std::fmt;
use std::sync::Arc;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    CoreRequest, FinalCoreResult, FinalRequestMeta, InputRequiredResult, RequestId,
    ServerNotification,
};
use serde_json::{Value, json};

use super::{
    DpopCredential, DpopHttpClient, DpopStreamError, DpopStreamLimits, DpopTaskOperation,
    Idle, ManagedCoreError, ManagedTaskEvent, Prepared, PreparedStream, Reply,
    TaskStreamDecoder, WaitBounds, check_live, progress_marker,
};
use super::super::{CoreDecoder, DpopHttpError, DpopTasksError, ManagedTaskRequest, wire};
use crate::http_auth::dpop::native::within;
use crate::http_auth::rpc::interaction::{
    ManagedInputReply, ManagedInteractionError, ManagedInteractionLimits, admit_challenge,
    admit_fresh_id, continuation_request, validate_initial,
};
use crate::http_auth::sampling::inputs::mixed::{CoreInputHost, CoreInputLimits};
use crate::http_auth::sampling::inputs::mixed::session::{
    CoreInputSession, CoreInputSessionError, CoreInputUsage,
};
use crate::http_executor::parameter_headers::ReviewedToolHeaders;

/// Whole-conversation limits. Core total bytes count both encoded request
/// bodies, each discovery reply and all operation payloads across ALL rounds.
/// Notifications and host work are also cumulative; per-frame, per-request,
/// native raw-body and SSE syntax ceilings remain independently enforced.
#[derive(Clone, Copy, Debug)]
pub struct DpopTaskHostLimits {
    stream: DpopStreamLimits,
    interaction: ManagedInteractionLimits,
    inputs: CoreInputLimits,
    resolutions: usize,
}

impl Default for DpopTaskHostLimits {
    fn default() -> Self {
        Self {
            stream: DpopStreamLimits::default(),
            interaction: ManagedInteractionLimits::default(),
            inputs: CoreInputLimits::default(),
            resolutions: 8,
        }
    }
}

impl DpopTaskHostLimits {
    /// Zero continuations accepts only an immediate complete or Task result.
    /// State-only rounds still consume a continuation, but invoke no host.
    pub fn new(
        stream: DpopStreamLimits,
        inputs: CoreInputLimits,
        maximum_continuations: usize,
        maximum_input_responses: usize,
    ) -> Result<Self, DpopTaskHostError> {
        let interaction = ManagedInteractionLimits::new(
            stream.core, maximum_continuations, maximum_input_responses,
        )?;
        Ok(Self { stream, interaction, inputs, resolutions: maximum_continuations })
    }
}

/// Only an admitted tool completion or Task creation escapes the driver.
/// A completed tool's isError flag is preserved, not promoted into success.
/// Usage describes host work, not authorization or an exactly-once receipt.
pub struct DpopTaskHostResult {
    pub result: Box<FinalCoreResult>,
    pub usage: CoreInputUsage,
    pub continuations: usize,
}

/// No diagnostic retains peer state, arguments, answers, tokens or host text.
#[derive(Debug)]
pub enum DpopTaskHostError {
    InvalidIdPrefix,
    Stream(DpopStreamError),
    Interaction(ManagedInteractionError),
    Input(CoreInputSessionError),
}

impl fmt::Display for DpopTaskHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdPrefix => f.write_str("invalid DPoP Task conversation ID prefix"),
            Self::Stream(error) => error.fmt(f),
            Self::Interaction(error) => error.fmt(f),
            Self::Input(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for DpopTaskHostError {}
impl From<DpopStreamError> for DpopTaskHostError {
    fn from(error: DpopStreamError) -> Self { Self::Stream(error) }
}
impl From<DpopTasksError> for DpopTaskHostError {
    fn from(error: DpopTasksError) -> Self { Self::Stream(error.into()) }
}
impl From<DpopHttpError> for DpopTaskHostError {
    fn from(error: DpopHttpError) -> Self { Self::Stream(error.into()) }
}
impl From<ManagedCoreError> for DpopTaskHostError {
    fn from(error: ManagedCoreError) -> Self { Self::Stream(error.into()) }
}
impl From<ManagedInteractionError> for DpopTaskHostError {
    fn from(error: ManagedInteractionError) -> Self { Self::Interaction(error) }
}
impl From<CoreInputSessionError> for DpopTaskHostError {
    fn from(error: CoreInputSessionError) -> Self { Self::Input(error) }
}

impl DpopHttpClient {
    /// Execute a Task-capable tool call through typed host-input rounds.
    ///
    /// The initial operation must be CallTool. Its optional reviewed headers
    /// apply to the original tool arguments on every round, never to host
    /// answers or requestState. Other operations are refused before I/O.
    /// Capabilities are caller-authored; selecting this API supplies neither
    /// roots, a model, a browser nor consent. The existing input engine admits
    /// a whole challenge before approval and validates the host's typed replies.
    /// Only that trusted engine receives opaque server continuation state.
    ///
    /// Each round performs fresh JSON Tasks discovery before its tool POST.
    /// Tool replies may be JSON or incremental SSE. A challenge/result is not
    /// actionable until clean HTTP EOF; invalid tails and observer refusal
    /// cannot trigger host effects or a successor POST. The original request,
    /// exact resource and DPoP credential remain pinned across all rounds.
    ///
    /// One absolute native/core/caller/credential deadline starts before local
    /// preparation. The input session additionally fixes its deadline before
    /// the first network operation. Idle starts before each round's preparation
    /// and discovery; only admitted progress may reset it. Host waits remain
    /// bounded by original expiry, revocation, cancellation and both deadlines.
    ///
    /// Use a distinct 1..=128 byte ASCII alphanumeric/dot/dash/underscore prefix
    /// for concurrent conversations. Generated discovery/tool IDs must also be
    /// distinct from the initial pair. They are not retry or idempotency keys.
    /// No HTTP error, challenge nonce, lost reply or host failure permits replay.
    /// No refresh, recovery journal, partial-answer POST, Task polling, detached
    /// work or implicit remote cancellation is installed. Dropping this future
    /// disposes its current socket/host future; prior effects cannot be undone.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_task_with_input_host<H, N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        operation: DpopTaskOperation,
        id_prefix: &str,
        limits: &DpopTaskHostLimits,
        host: &mut H,
        mut observer: N,
    ) -> Result<DpopTaskHostResult, DpopTaskHostError>
    where
        H: CoreInputHost + ?Sized,
        N: FnMut(&ServerNotification) -> bool,
    {
        let mut bounds = WaitBounds::new(
            cx, self.policy.timeout.min(limits.stream.core.timeout()), credential,
        )?;
        let mut idle = Idle::new(cx.now(), limits.stream.idle);
        check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
        validate_prefix(id_prefix)?;
        if !matches!(&operation.request, ManagedTaskRequest::CallTool { .. }) {
            return Err(ManagedInteractionError::InvalidInitialRequest.into());
        }
        let ids = (operation.discovery_id.clone(), operation.operation_id.clone());
        let reviewed = operation.reviewed_headers.clone();
        let mut prepared = Box::new(Prepared::new(
            self.resource().as_str(), metadata, operation, limits.stream.core,
            self.policy.max_body_bytes,
        )?);
        let mut conversation = Conversation::new(&prepared, ids, reviewed, limits.interaction)?;
        let mut inputs = CoreInputSession::new(
            cx, cancellation, conversation.original.clone(), limits.inputs, limits.resolutions,
        )?;
        if inputs.deadline() < bounds.deadline {
            bounds.deadline = inputs.deadline();
            bounds.terminal = DpopHttpError::TimedOut;
        }
        loop {
            check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
            let charged = conversation.reserve_round(&mut prepared)?;
            let progress = progress_marker(&prepared.operation_wire, limits.stream.core.request_bytes())?;
            let response = self.post_resource_with_bounds(
                cx, cancellation, credential, &prepared.discovery_wire, idle.bounds(bounds),
            ).await?;
            check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
            let bytes = charged.checked_add(response.body().len())
                .ok_or(ManagedCoreError::ResponseByteLimit)?;
            let admitted = (*prepared).admit(response);
            check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
            let (wire, mut decoder) = TaskStreamDecoder::from_admitted(
                admitted?, limits.stream.core, bytes, progress,
            )?;
            // The fresh per-method decoder inherits cumulative quotas, not the
            // previous round's progress value or terminal flag.
            decoder.notifications = conversation.usage.1;
            let completed = Box::pin(self.execute_prepared_core_stream(
                cx, cancellation, credential,
                PreparedStream { wire, decoder, limits: limits.stream, bounds, idle },
                &mut observer,
            )).await?;
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let input = match conversation.accept(completed.result, completed.usage)? {
                Step::Complete(result) => return Ok(DpopTaskHostResult {
                    result, usage: inputs.usage(), continuations: conversation.continuations,
                }),
                Step::Input(input) => input,
            };
            let ids = conversation.next_ids(id_prefix)?;
            let reply = within(cx, cancellation, &self.session, credential, bounds, async {
                Ok(inputs.resolve(cx, (*input).clone(), ids.1.clone(), host).await)
            }).await??;
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            conversation.resume(&input, ids, reply)?;
            // A new idle allowance is per network round, never a new absolute
            // lifetime. Local serialization and discovery spend it too.
            idle = Idle::new(cx.now(), limits.stream.idle);
            prepared = Box::new(conversation.prepare(
                self.resource().as_str(), self.policy.max_body_bytes,
            )?);
        }
    }
}

fn validate_prefix(prefix: &str) -> Result<(), DpopTaskHostError> {
    if prefix.is_empty() || prefix.len() > 128
        || !prefix.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(DpopTaskHostError::InvalidIdPrefix);
    }
    Ok(())
}

// Private linear state, not a public replay token or an alternate wire schema.
// Initial admission stays in Prepared::new; every successor is derived only
// from that admitted original and the shared continuation validator.
struct Conversation {
    original: CoreRequest,
    current: CoreRequest,
    ids: (RequestId, RequestId),
    used_ids: Vec<RequestId>,
    reviewed: Option<Arc<ReviewedToolHeaders>>,
    limits: ManagedInteractionLimits,
    usage: (usize, usize),
    continuations: usize,
    input_responses: usize,
}

enum Step {
    Complete(Box<FinalCoreResult>),
    Input(Box<InputRequiredResult>),
}

impl Conversation {
    fn new(
        prepared: &Prepared,
        ids: (RequestId, RequestId),
        reviewed: Option<Arc<ReviewedToolHeaders>>,
        limits: ManagedInteractionLimits,
    ) -> Result<Self, DpopTaskHostError> {
        let Reply::Tool(original) = &prepared.reply else {
            return Err(ManagedInteractionError::InvalidInitialRequest.into());
        };
        validate_initial(original)?;
        Ok(Self {
            original: (**original).clone(), current: (**original).clone(),
            used_ids: vec![ids.0.clone(), ids.1.clone()], ids, reviewed, limits,
            usage: (0, 0), continuations: 0, input_responses: 0,
        })
    }

    fn reserve_round(&self, prepared: &mut Prepared) -> Result<usize, DpopTaskHostError> {
        let bytes = self.usage.0
            .checked_add(prepared.discovery_wire.body().len())
            .and_then(|bytes| bytes.checked_add(prepared.operation_wire.body().len()))
            .ok_or(ManagedCoreError::ResponseByteLimit)?;
        // Before even discovery can spend authority. The discovery decoder's
        // remaining limit subsequently becomes the operation decoder's limit.
        prepared.discovery_decoder.resume_usage(bytes, self.usage.1)?;
        Ok(bytes)
    }

    fn accept(
        &mut self,
        event: ManagedTaskEvent,
        usage: (usize, usize),
    ) -> Result<Step, DpopTaskHostError> {
        if usage.0 < self.usage.0 || usage.1 < self.usage.1
            || usage.0 > self.limits.core().total_bytes()
            || usage.1 > self.limits.core().notifications()
        {
            return Err(ManagedCoreError::InvalidResponse.into());
        }
        let ManagedTaskEvent::ToolResult(result) = event else {
            return Err(ManagedCoreError::InvalidResult.into());
        };
        let step = match result.as_ref() {
            FinalCoreResult::ToolsCall { .. } | FinalCoreResult::ToolsCallTask { .. } => {
                Step::Complete(result)
            }
            FinalCoreResult::ToolsCallInputRequired { result: input, .. } => {
                if usage.0 >= self.limits.core().total_bytes() {
                    return Err(ManagedCoreError::ResponseByteLimit.into());
                }
                admit_challenge(&self.original, input, self.limits,
                    self.continuations, self.input_responses)?;
                let input: &InputRequiredResult = input;
                Step::Input(Box::new(input.clone()))
            }
            _ => return Err(ManagedCoreError::InvalidResult.into()),
        };
        self.usage = usage;
        Ok(step)
    }

    fn next_ids(&self, prefix: &str) -> Result<(RequestId, RequestId), DpopTaskHostError> {
        validate_prefix(prefix)?;
        let ordinal = self.continuations + 1;
        let discovery = RequestId::String(format!("{prefix}:{ordinal}:discover"));
        let tool = RequestId::String(format!("{prefix}:{ordinal}:tool"));
        admit_fresh_id(&self.used_ids, &discovery)?;
        admit_fresh_id(&self.used_ids, &tool)?;
        Ok((discovery, tool))
    }

    fn resume(
        &mut self,
        input: &InputRequiredResult,
        ids: (RequestId, RequestId),
        reply: ManagedInputReply,
    ) -> Result<(), DpopTaskHostError> {
        admit_challenge(&self.original, input, self.limits,
            self.continuations, self.input_responses)?;
        admit_fresh_id(&self.used_ids, &ids.0)?;
        admit_fresh_id(&self.used_ids, &ids.1)?;
        if ids.0.correlates_with(&ids.1) || !ids.1.correlates_with(&reply.request_id) {
            return Err(ManagedInteractionError::RepeatedRequestId.into());
        }
        let count = reply.input_responses.as_ref().map_or(0, |answers| answers.len());
        let next = continuation_request(&self.original, input, reply.input_responses)?;
        self.current = next;
        self.used_ids.extend([ids.0.clone(), ids.1.clone()]);
        self.ids = ids;
        self.continuations += 1;
        self.input_responses += count;
        Ok(())
    }

    fn prepare(&self, target: &str, native_maximum: usize) -> Result<Prepared, DpopTaskHostError> {
        let limits = self.limits.core();
        let maximum = limits.request_bytes().min(native_maximum);
        let params = self.current.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?
            .ok_or(ManagedCoreError::InvalidRequest)?;
        let name = params.get("name").and_then(Value::as_str)
            .ok_or(ManagedCoreError::InvalidRequest)?.to_owned();
        // Only original metadata enters discovery. No argument, host reply or
        // opaque continuation state can leak through the negotiation request.
        let discovery_params = json!({"_meta":params["_meta"]});
        let discovery = CoreRequest::decode(
            ProtocolEra::Modern2026, "server/discover", Some(&discovery_params),
        ).map_err(|_| ManagedCoreError::InvalidRequest)?;
        let discovery_wire = wire(target, "server/discover", &self.ids.0,
            discovery_params, None, maximum)?;
        let discovery_decoder = CoreDecoder::for_request(discovery, self.ids.0.clone(), limits)?;
        let operation_wire = wire(target, "tools/call", &self.ids.1, params, Some(name), maximum)?;
        let operation_wire = match &self.reviewed {
            Some(reviewed) => operation_wire.with_reviewed_tool_headers(reviewed)
                .map_err(DpopTasksError::from)?,
            None => operation_wire,
        };
        Ok(Prepared {
            discovery_wire, discovery_decoder, operation_wire,
            operation_id: self.ids.1.clone(), reply: Reply::Tool(Box::new(self.current.clone())), limits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_protocol::{ClientCapabilities, CoreResult, FinalInputResponses};
    use crate::http_auth::rpc::ManagedCoreLimits;
    use std::time::Duration;

    const TARGET: &str = "https://mcp.example/mcp?tenant=one";
    const INPUT: &str = r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"  state+/%\u0000  "}"#;

    fn setup(continuations: usize, responses: usize) -> Conversation {
        let mut metadata = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        metadata["io.modelcontextprotocol/clientCapabilities"] = json!({"roots":{}});
        metadata["progressToken"] = json!("owned");
        let limits = ManagedInteractionLimits::new(ManagedCoreLimits::default(), continuations, responses).unwrap();
        let reviewed = Arc::new(ReviewedToolHeaders::new(CanonicalHttpUrl::parse(TARGET).unwrap(),
            "echo", json!({"type":"object","properties":{
                "region":{"type":"string","x-mcp-header":"Region"},
                "private":{"type":"string","writeOnly":true}
            }}), |_| true).unwrap());
        let ids = (RequestId::Number(1), RequestId::Number(2));
        let operation = DpopTaskOperation::new(ids.0.clone(), ids.1.clone(), ManagedTaskRequest::CallTool {
            name: "echo".to_owned(), arguments: Some(json!({"region":"eu","private":"body-only"})),
        }).unwrap().with_reviewed_tool_headers(Arc::clone(&reviewed)).unwrap();
        let prepared = Prepared::new(TARGET, serde_json::from_value(metadata).unwrap(), operation,
            limits.core(), 8192).unwrap();
        Conversation::new(&prepared, ids, Some(reviewed), limits).unwrap()
    }

    fn result(state: &Conversation, source: &str) -> ManagedTaskEvent {
        let CoreResult::Final(result) = state.current.decode_result(source).unwrap() else { panic!("modern result"); };
        ManagedTaskEvent::ToolResult(Box::new(result))
    }

    fn challenge(state: &mut Conversation, source: &str) -> Box<InputRequiredResult> {
        let event = result(state, source);
        let Step::Input(input) = state.accept(event, (state.usage.0 + 1, state.usage.1)).unwrap()
        else { panic!("input challenge"); };
        input
    }

    fn reply(id: &RequestId, value: Value) -> ManagedInputReply {
        ManagedInputReply { request_id: id.clone(),
            input_responses: Some(serde_json::from_value::<FinalInputResponses>(value).unwrap()) }
    }

    #[test]
    fn task_continuation_preserves_original_metadata_arguments_headers_and_exact_state() {
        let mut state = setup(4, 4);
        let original = state.original.encode_params().unwrap().unwrap();
        let input = challenge(&mut state, INPUT);
        let ids = state.next_ids("run").unwrap();
        state.resume(&input, ids.clone(), reply(&ids.1, json!({"roots":{"roots":[]}}))).unwrap();
        let prepared = state.prepare(TARGET, 8192).unwrap();
        let body: Value = serde_json::from_slice(prepared.operation_wire.body()).unwrap();
        assert_eq!(body["params"]["arguments"], original["arguments"]);
        assert_eq!(body["params"]["_meta"], original["_meta"]);
        assert_eq!(body["params"]["requestState"], "  state+/%\0  ");
        assert_eq!(body["params"]["inputResponses"], json!({"roots":{"roots":[]}}));
        assert_eq!(body["id"], json!(ids.1));
        let discovery: Value = serde_json::from_slice(prepared.discovery_wire.body()).unwrap();
        assert_eq!(discovery["params"], json!({"_meta":original["_meta"]}));
        assert!(!prepared.discovery_wire.headers().iter().any(|(name, _)| name.starts_with("Mcp-Param-")));
        assert!(prepared.operation_wire.headers().contains(&("Mcp-Param-Region".to_owned(), "eu".to_owned())));
        assert!(!prepared.operation_wire.headers().iter().any(|(_, value)| value.contains("body-only")));
        assert_eq!(prepared.operation_wire.target(), TARGET);
        assert_eq!(state.original.encode_params().unwrap().unwrap(), original);
        assert_eq!((state.continuations, state.input_responses), (1, 1));
        assert!(state.prepare("https://other.example/mcp", 8192).is_err());
    }

    #[test]
    fn successive_task_challenges_replace_prior_answers_and_state_without_replay() {
        let mut state = setup(3, 3);
        let first = challenge(&mut state, INPUT);
        let ids = state.next_ids("run").unwrap();
        state.resume(&first, ids.clone(), reply(&ids.1, json!({"roots":{"roots":[]}}))).unwrap();
        let second = challenge(&mut state,
            r#"{"resultType":"input_required","inputRequests":{},"requestState":"next"}"#);
        let next = state.next_ids("run").unwrap();
        assert_ne!(ids, next);
        state.resume(&second, next.clone(), reply(&next.1, json!({}))).unwrap();
        let params = state.current.encode_params().unwrap().unwrap();
        assert_eq!(params["inputResponses"], json!({}));
        assert_eq!(params["requestState"], "next");
        let third = challenge(&mut state, r#"{"resultType":"input_required","requestState":""}"#);
        let ids = state.next_ids("run").unwrap();
        state.resume(&third, ids.clone(), ManagedInputReply { request_id: ids.1, input_responses: None }).unwrap();
        let params = state.current.encode_params().unwrap().unwrap();
        assert!(params.get("inputResponses").is_none());
        assert_eq!(params["requestState"], "");
        assert_eq!((state.continuations, state.input_responses, state.used_ids.len()), (3, 1, 8));
    }

    #[test]
    fn invalid_task_replies_and_reused_id_pairs_leave_conversation_unchanged() {
        let mut state = setup(2, 2);
        let input = challenge(&mut state, INPUT);
        let before = state.current.encode_params().unwrap();
        let ids = state.next_ids("run").unwrap();
        for answers in [json!({}), json!({"foreign":{"roots":[]}})] {
            assert!(state.resume(&input, ids.clone(), reply(&ids.1, answers)).is_err());
            assert_eq!(state.current.encode_params().unwrap(), before);
            assert_eq!((state.continuations, state.input_responses, state.used_ids.len()), (0, 0, 2));
        }
        let alias: RequestId = serde_json::from_str("1e0").unwrap();
        assert!(state.resume(&input, (alias, ids.1.clone()), reply(&ids.1, json!({"roots":{"roots":[]}}))).is_err());
        assert!(state.resume(&input, ids.clone(), reply(&RequestId::Number(99), json!({"roots":{"roots":[]}}))).is_err());
        state.used_ids.push(RequestId::String("run:1:discover".to_owned()));
        assert!(matches!(state.next_ids("run"), Err(DpopTaskHostError::Interaction(ManagedInteractionError::RepeatedRequestId))));
        assert_eq!(state.current.encode_params().unwrap(), before);
    }

    #[test]
    fn task_host_limits_reject_challenges_before_host_work_but_preserve_terminal_families() {
        for (continuations, responses) in [(0, 2), (2, 0)] {
            let mut state = setup(continuations, responses);
            let event = result(&state, INPUT);
            assert!(state.accept(event, (1, 0)).is_err());
            assert_eq!(state.usage, (0, 0));
        }
        for source in [
            r#"{"resultType":"complete","content":[],"isError":true}"#,
            r#"{"resultType":"task","taskId":"task-one","status":"working","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":60000}"#,
        ] {
            let mut state = setup(0, 0);
            let event = result(&state, source);
            let Step::Complete(result) = state.accept(event, (1, 0)).unwrap() else { panic!("terminal"); };
            assert!(matches!(*result, FinalCoreResult::ToolsCall { .. } | FinalCoreResult::ToolsCallTask { .. }));
            assert_eq!(state.continuations, 0);
        }
        let mut state = setup(2, 2);
        let bad = result(&state, r#"{"resultType":"input_required","inputRequests":{"sample":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}}},"requestState":"private-canary"}"#);
        let error = state.accept(bad, (1, 0)).err().unwrap();
        assert!(matches!(&error, DpopTaskHostError::Interaction(ManagedInteractionError::CapabilityNotAdvertised)));
        assert!(!format!("{error:?} {error}").contains("private-canary"));
        assert_eq!(state.usage, (0, 0));
    }

    #[test]
    fn task_round_reserves_both_requests_and_prior_work_before_discovery() {
        let mut state = setup(2, 2);
        state.usage = (137, 2);
        let mut prepared = state.prepare(TARGET, 8192).unwrap();
        let expected = 137 + prepared.discovery_wire.body().len() + prepared.operation_wire.body().len();
        assert_eq!(state.reserve_round(&mut prepared).unwrap(), expected);
        assert_eq!(prepared.discovery_decoder.usage(), (expected, 2));
        // A fresh decoder is mandatory; accounting cannot reset a used owner.
        assert!(state.reserve_round(&mut prepared).is_err());
        let core = ManagedCoreLimits::new(8192, 1, expected, 2, Duration::from_secs(60)).unwrap();
        state.limits = ManagedInteractionLimits::new(core, 2, 2).unwrap();
        let mut prepared = state.prepare(TARGET, 8192).unwrap();
        assert!(state.reserve_round(&mut prepared).is_err());
        assert_eq!(prepared.discovery_decoder.usage(), (0, 0));
        state.usage = (usize::MAX, 2);
        assert!(state.reserve_round(&mut prepared).is_err());
        assert_eq!(prepared.discovery_decoder.usage(), (0, 0));
    }
}
