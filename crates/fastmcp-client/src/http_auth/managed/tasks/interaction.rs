//! Task-capable, credential-bound multi-round tool operations.
//!
//! A tool can request host input before it completes or creates a Task. This
//! owner joins the existing Tasks discovery/dispatch path to the shared MRTR
//! continuation validator. It never restarts tools/call after a lost response,
//! resolves an input implicitly, or turns a Task into a completed tool result.
//! Use the existing Task driver after explicitly receiving a Task result.
//!
//! The opening access credential is pinned across all rounds. Refresh cannot
//! move an opaque continuation into a different authorization context. Expiry
//! ends this operation instead of silently logging in again or replaying it.

use std::fmt;
use std::future::Future;
use std::time::Instant;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    CoreRequest, FinalCoreResult, FinalInputResponses, InputRequiredResult,
    RequestId, ServerNotification,
};
use serde_json::Value;

use super::{
    ManagedTaskCall, ManagedTaskEvent, ManagedTaskRequest, ManagedTaskRequestIds,
    ManagedTasksClient, ManagedTasksError, ManagedTasksLimits, OAuthCredentialSnapshot,
    OAuthSessionError, PreparedTask, PreparedTaskRound, TaskDecoder, deadline_after,
    encode_request, prepare,
};
use crate::http_auth::rpc::ManagedCoreLimits;
use crate::http_auth::rpc::interaction::{
    InputSelection, ManagedInteractionError, ManagedInteractionLimits,
    admit_challenge, admit_fresh_id, continuation_request_selected, validate_initial,
};

/// Whole-operation bounds, in addition to the Tasks client's per-frame and
/// per-request limits. The Tasks client's timeout is one deadline for the entire interaction,
/// including discovery, credential acquisition, reads and host input pauses.
/// Records count notifications and tool results across every round; discovery
/// has one independently frame-bounded response per round. At most
/// `maximum_continuations + 1` discovery/tool POST pairs can be attempted.
#[derive(Clone, Copy, Debug)]
pub struct ManagedTaskInteractionPolicy {
    input: ManagedInteractionLimits,
    maximum_records: usize,
}

impl Default for ManagedTaskInteractionPolicy {
    fn default() -> Self {
        Self { input: ManagedInteractionLimits::default(), maximum_records: 256 }
    }
}

impl ManagedTaskInteractionPolicy {
    /// Zero continuations permits only an immediately completed or Task result.
    /// Zero input responses still permits explicitly authorized state-only
    /// rounds. There is no automatic retry allowance hidden in these bounds.
    pub fn new(
        maximum_continuations: usize,
        maximum_input_responses: usize,
        maximum_records: usize,
    ) -> Result<Self, ManagedTaskInteractionError> {
        if !(1..=1024).contains(&maximum_records) {
            return Err(ManagedTaskInteractionError::InvalidPolicy);
        }
        let input = ManagedInteractionLimits::new(
            ManagedCoreLimits::default(), maximum_continuations, maximum_input_responses,
        )?;
        Ok(Self { input, maximum_records })
    }
}

/// Diagnostics retain neither arguments, answers, continuation state, task IDs
/// nor credentials. The existing protocol and transport errors remain typed.
#[derive(Debug)]
pub enum ManagedTaskInteractionError {
    InvalidPolicy,
    RecordLimit,
    InputPending,
    NotAwaitingInput,
    Closed,
    Task(ManagedTasksError),
    Interaction(ManagedInteractionError),
}

impl fmt::Display for ManagedTaskInteractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => f.write_str("invalid managed Task interaction policy"),
            Self::RecordLimit => f.write_str("Task interaction cumulative record limit exceeded"),
            Self::InputPending => f.write_str("Task interaction requires explicit host input"),
            Self::NotAwaitingInput => f.write_str("Task interaction is not awaiting input"),
            Self::Closed => f.write_str("managed Task interaction is closed"),
            Self::Task(error) => fmt::Display::fmt(error, f),
            Self::Interaction(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ManagedTaskInteractionError {}
impl From<ManagedTasksError> for ManagedTaskInteractionError {
    fn from(error: ManagedTasksError) -> Self { Self::Task(error) }
}
impl From<OAuthSessionError> for ManagedTaskInteractionError {
    fn from(error: OAuthSessionError) -> Self { Self::Task(error.into()) }
}
impl From<ManagedInteractionError> for ManagedTaskInteractionError {
    fn from(error: ManagedInteractionError) -> Self { Self::Interaction(error) }
}

/// A tool result retains its complete/Task distinction. InputRequired is not
/// successful EOF and cannot cause another POST without an explicit resume.
pub enum ManagedTaskInteractionEvent {
    Notification(Box<ServerNotification>),
    InputRequired(Box<InputRequiredResult>),
    Result(Box<FinalCoreResult>),
}

/// The host, not the protocol peer, selects whether input should be submitted.
/// Replies cannot replace the original call or supply their own requestState.
pub enum ManagedTaskInputAction {
    Respond {
        ids: ManagedTaskRequestIds,
        input_responses: Option<FinalInputResponses>,
    },
    RespondPartial {
        ids: ManagedTaskRequestIds,
        input_responses: FinalInputResponses,
    },
    /// Return ownership with the exact challenge still pending, without a POST.
    Pause,
}

/// A paused operation remains explicitly resumable. A result may be an
/// ordinary tool completion (including isError) or an actual Task creation.
/// Neither is automatically retried, polled, or converted into success.
pub enum ManagedTaskDriveOutcome {
    Paused(Box<ManagedTaskInteraction>),
    Result(Box<FinalCoreResult>),
}

struct ToolProgress {
    original: CoreRequest,
    pending: Option<Box<InputRequiredResult>>,
    used_ids: Vec<RequestId>,
    continuations: usize,
    input_responses: usize,
    records: usize,
    finished: bool,
    policy: ManagedTaskInteractionPolicy,
}

impl ToolProgress {
    fn new(original: CoreRequest, ids: &ManagedTaskRequestIds, policy: ManagedTaskInteractionPolicy) -> Result<Self, ManagedTaskInteractionError> {
        validate_initial(&original)?;
        Ok(Self {
            original, pending: None,
            used_ids: vec![ids.discovery.clone(), ids.operation.clone()],
            continuations: 0, input_responses: 0, records: 0, finished: false, policy,
        })
    }

    fn remaining_records(&self) -> usize {
        self.policy.maximum_records.saturating_sub(self.records)
    }

    // The caller has consumed response custody before invoking this method.
    // A validation error can never leave an input challenge resumable.
    fn admit_result(&mut self, result: Box<FinalCoreResult>) -> Result<ManagedTaskInteractionEvent, ManagedTaskInteractionError> {
        if self.remaining_records() == 0 { return Err(ManagedTaskInteractionError::RecordLimit); }
        self.records += 1;
        match result.as_ref() {
            FinalCoreResult::ToolsCallInputRequired { result: input, .. } => {
                let input: &InputRequiredResult = input;
                if self.remaining_records() == 0 { return Err(ManagedTaskInteractionError::RecordLimit); }
                admit_challenge(&self.original, input, self.policy.input, self.continuations, self.input_responses)?;
                let input = Box::new(input.clone());
                self.pending = Some(input.clone());
                Ok(ManagedTaskInteractionEvent::InputRequired(input))
            }
            FinalCoreResult::ToolsCall { .. } | FinalCoreResult::ToolsCallTask { .. } => {
                self.finished = true;
                Ok(ManagedTaskInteractionEvent::Result(result))
            }
            _ => Err(ManagedTasksError::InvalidResponse.into()),
        }
    }

    // Pure local admission. A wrong key/type, reused ID, or oversized encoded
    // answer cannot consume the challenge or acquire a new credential.
    fn prepare_resume(
        &self, target: &str, ids: &ManagedTaskRequestIds,
        responses: Option<FinalInputResponses>, selection: InputSelection,
        limits: ManagedTasksLimits,
    ) -> Result<(PreparedTask, usize), ManagedTaskInteractionError> {
        let input = self.pending.as_ref().ok_or(ManagedTaskInteractionError::NotAwaitingInput)?;
        if self.remaining_records() == 0 { return Err(ManagedTaskInteractionError::RecordLimit); }
        admit_challenge(&self.original, input, self.policy.input, self.continuations, self.input_responses)?;
        admit_fresh_id(&self.used_ids, &ids.discovery)?;
        admit_fresh_id(&self.used_ids, &ids.operation)?;
        // ManagedTaskRequestIds also excludes aliases within the pair.
        let _ = ManagedTaskRequestIds::new(ids.discovery.clone(), ids.operation.clone())?;
        let count = responses.as_ref().map_or(0, FinalInputResponses::len);
        let next = continuation_request_selected(&self.original, input, responses, selection)?;
        let parameters = next.encode_params().map_err(|_| ManagedTasksError::InvalidRequest)?
            .ok_or(ManagedTasksError::InvalidRequest)?;
        let name = parameters.get("name").and_then(Value::as_str)
            .ok_or(ManagedTasksError::InvalidRequest)?.to_owned();
        let progress = parameters["_meta"].get("progressToken").map(|value|
            serde_json::from_value(value.clone()).map_err(|_| ManagedTasksError::InvalidRequest)
        ).transpose()?;
        let wire = encode_request(target, "tools/call", &ids.operation, parameters, Some(name), limits.request_bytes)?;
        Ok((PreparedTask { wire, decoder: TaskDecoder::Tool(Box::new(next)), progress }, count))
    }

    fn commit_resume(&mut self, ids: &ManagedTaskRequestIds, count: usize) {
        self.pending = None;
        self.used_ids.extend([ids.discovery.clone(), ids.operation.clone()]);
        self.continuations += 1;
        self.input_responses += count;
    }
}

/// Non-Clone ownership of the original tool operation, its current response or
/// pending challenge, and its opening credential. No previous answers are kept.
/// Abandoning a polled read/resume closes the operation. Local validation errors
/// during resume preserve the challenge, so the host can correct its answers.
/// There is no implicit server cancellation or exactly-once/restart guarantee.
pub struct ManagedTaskInteraction {
    client: ManagedTasksClient,
    credential: Option<OAuthCredentialSnapshot>,
    call: Option<Box<ManagedTaskCall>>,
    progress: ToolProgress,
    cancellation: McpRequestCancellation,
    deadline: Time,
}

impl fmt::Debug for ManagedTaskInteraction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedTaskInteraction")
            .field("continuations", &self.progress.continuations)
            .field("awaiting_input", &self.progress.pending.is_some())
            .field("finished", &self.progress.finished)
            .finish_non_exhaustive()
    }
}

impl ManagedTasksClient {
    /// Starts a task-capable tool call that can be explicitly resumed through
    /// core input-required rounds. The original arguments and metadata remain
    /// immutable. Each round re-discovers Tasks with the exact opening token.
    pub async fn start_tool_interaction(
        &self, cx: &Cx, ids: ManagedTaskRequestIds, name: String,
        arguments: Option<Value>, policy: ManagedTaskInteractionPolicy,
    ) -> Result<ManagedTaskInteraction, ManagedTaskInteractionError> {
        self.start_tool_interaction_with_cancellation(cx, &McpRequestCancellation::new(), ids, name, arguments, policy).await
    }

    /// Retains one request-local cancellation domain and one absolute timeout
    /// across all rounds. A task returned at the end is not automatically polled
    /// or cancelled; its ongoing lifecycle belongs to the existing Task APIs.
    pub async fn start_tool_interaction_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        ids: ManagedTaskRequestIds, name: String, arguments: Option<Value>,
        policy: ManagedTaskInteractionPolicy,
    ) -> Result<ManagedTaskInteraction, ManagedTaskInteractionError> {
        self.session.check(cx, cancellation)?;
        let deadline = deadline_after(cx, self.limits.timeout)?;
        let prepared = prepare(self.session.resource().as_str(), &self.metadata, &ids.operation,
            ManagedTaskRequest::CallTool { name, arguments }, self.limits)?;
        let TaskDecoder::Tool(original) = &prepared.decoder else { return Err(ManagedTasksError::InvalidRequest.into()) };
        let progress = ToolProgress::new((**original).clone(), &ids, policy)?;
        let round = self.prepare_round(ids, prepared)?;
        let credential = self.session.await_active(cx, cancellation, deadline, None, async {
            self.session.credential_with_cancellation(cx, cancellation).await
        }).await?;
        let call = self.execute_round(cx, cancellation, round, &credential, deadline, policy.maximum_records).await?;
        check_live(cx, self, cancellation, deadline, &credential)?;
        Ok(ManagedTaskInteraction {
            client: self.clone(), credential: Some(credential), call: Some(Box::new(call)),
            progress, cancellation: cancellation.clone(), deadline,
        })
    }
}

impl ManagedTaskInteraction {
    pub fn pending_input(&self) -> Option<&InputRequiredResult> { self.progress.pending.as_deref() }
    pub fn continuation_count(&self) -> usize { self.progress.continuations }
    pub fn is_finished(&self) -> bool { self.progress.finished }

    /// Drops the current response, challenge and credential without sending a
    /// cancellation notification or cancelling another operation's token.
    pub fn close(&mut self) {
        self.call = None;
        self.credential = None;
        self.progress.pending = None;
    }

    /// Drives input-required rounds with explicitly supplied host callbacks.
    /// No built-in roots, model, tool executor, browser, or consent policy is
    /// installed. The resolver receives each current challenge once; returning
    /// Pause hands this owner back without consuming state or request IDs.
    /// Notifications remain incremental rather than being buffered to the end.
    ///
    /// The opening credential's expiry, original operation deadline, session
    /// closure and both cancellation domains bound pending host work as well
    /// as network work. A callback must cooperate with cancellation by dropping
    /// its own child work; synchronous non-yielding work cannot be preempted.
    /// A callback error, invalid reply or abandoned driver is terminal locally,
    /// not permission to repeat an external host action or tool POST.
    pub async fn drive<R, F, N>(
        mut self, cx: &Cx, mut resolve: R, mut notify: N,
    ) -> Result<ManagedTaskDriveOutcome, ManagedTaskInteractionError>
    where
        R: FnMut(Box<InputRequiredResult>) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskInteractionError>>,
        N: FnMut(Box<ServerNotification>) -> Result<(), ManagedTaskInteractionError>,
    {
        loop {
            self.check(cx)?;
            let event = match self.pending_input() {
                Some(input) => ManagedTaskInteractionEvent::InputRequired(Box::new(input.clone())),
                None => self.next_event(cx).await?.ok_or(ManagedTaskInteractionError::Closed)?,
            };
            match event {
                ManagedTaskInteractionEvent::Notification(notification) => {
                    self.check(cx)?;
                    notify(notification)?;
                    self.check(cx)?;
                }
                ManagedTaskInteractionEvent::InputRequired(input) => {
                    self.check(cx)?;
                    let expiry = self.credential.as_ref().ok_or(ManagedTaskInteractionError::Closed)?.expires_at();
                    // Invoke the host inside the guard, never before its first
                    // cancellation/deadline check. Session closure also wakes
                    // an idle resolver, without touching the caller's Cx.
                    let action = self.client.session.await_active(
                        cx, &self.cancellation, self.deadline, Some(expiry), async {
                            Ok(resolve(input).await)
                        },
                    ).await??;
                    self.check(cx)?;
                    match action {
                        ManagedTaskInputAction::Pause => return Ok(ManagedTaskDriveOutcome::Paused(Box::new(self))),
                        ManagedTaskInputAction::Respond { ids, input_responses } => {
                            self.resume(cx, ids, input_responses).await?;
                        }
                        ManagedTaskInputAction::RespondPartial { ids, input_responses } => {
                            self.resume_partial(cx, ids, input_responses).await?;
                        }
                    }
                }
                ManagedTaskInteractionEvent::Result(result) => return Ok(ManagedTaskDriveOutcome::Result(result)),
            }
        }
    }

    pub async fn next_event(&mut self, cx: &Cx) -> Result<Option<ManagedTaskInteractionEvent>, ManagedTaskInteractionError> {
        if self.progress.finished { return Ok(None); }
        self.check(cx)?;
        if self.progress.pending.is_some() { return Err(ManagedTaskInteractionError::InputPending); }
        if self.progress.remaining_records() == 0 {
            self.close();
            return Err(ManagedTaskInteractionError::RecordLimit);
        }
        let mut call = self.call.take().ok_or(ManagedTaskInteractionError::Closed)?;
        // The read future, not the reusable owner, now owns the credential too.
        let credential = self.credential.take().ok_or(ManagedTaskInteractionError::Closed)?;
        let event = call.next_event(cx).await?.ok_or(ManagedTasksError::MissingTerminal)?;
        check_live(cx, &self.client, &self.cancellation, self.deadline, &credential)?;
        let event = match event {
            ManagedTaskEvent::Notification(notification) => {
                self.progress.records += 1;
                self.call = Some(call);
                ManagedTaskInteractionEvent::Notification(notification)
            }
            ManagedTaskEvent::ToolResult(result) => self.progress.admit_result(result)?,
            _ => return Err(ManagedTasksError::InvalidResponse.into()),
        };
        if !self.progress.finished { self.credential = Some(credential); }
        Ok(Some(event))
    }

    /// Submit exactly the current challenge's answers, with fresh discovery and
    /// operation IDs. State-only and absent/empty input-map distinctions are
    /// retained. The caller cannot replace requestState, metadata or arguments.
    pub async fn resume(
        &mut self, cx: &Cx, ids: ManagedTaskRequestIds,
        responses: Option<FinalInputResponses>,
    ) -> Result<(), ManagedTaskInteractionError> {
        self.resume_selected(cx, ids, responses, InputSelection::Complete).await
    }

    /// Submit a nonempty subset of answers. A proper subset requires nonempty
    /// server continuation state; omitted inputs receive no synthetic answer.
    pub async fn resume_partial(
        &mut self, cx: &Cx, ids: ManagedTaskRequestIds, responses: FinalInputResponses,
    ) -> Result<(), ManagedTaskInteractionError> {
        self.resume_selected(cx, ids, Some(responses), InputSelection::Partial).await
    }

    fn take_resume(
        &mut self, cx: &Cx, ids: ManagedTaskRequestIds,
        responses: Option<FinalInputResponses>, selection: InputSelection,
    ) -> Result<(PreparedTaskRound, OAuthCredentialSnapshot), ManagedTaskInteractionError> {
        self.check(cx)?;
        let (prepared, count) = self.progress.prepare_resume(
            self.client.session.resource().as_str(), &ids, responses, selection, self.client.limits,
        )?;
        let round = self.client.prepare_round(ids.clone(), prepared)?;
        self.check(cx)?;
        let credential = self.credential.take().ok_or(ManagedTaskInteractionError::Closed)?;
        self.progress.commit_resume(&ids, count);
        // No await precedes this ownership transfer. Failure after this point
        // is an uncertain attempt, never permission to reuse the old challenge.
        Ok((round, credential))
    }

    async fn resume_selected(
        &mut self, cx: &Cx, ids: ManagedTaskRequestIds,
        responses: Option<FinalInputResponses>, selection: InputSelection,
    ) -> Result<(), ManagedTaskInteractionError> {
        let (round, credential) = self.take_resume(cx, ids, responses, selection)?;
        let call = self.client.execute_round(cx, &self.cancellation, round, &credential,
            self.deadline, self.progress.remaining_records()).await?;
        check_live(cx, &self.client, &self.cancellation, self.deadline, &credential)?;
        self.call = Some(Box::new(call));
        self.credential = Some(credential);
        Ok(())
    }

    fn check(&mut self, cx: &Cx) -> Result<(), ManagedTaskInteractionError> {
        let result = match self.credential.as_ref() {
            Some(credential) => check_live(cx, &self.client, &self.cancellation, self.deadline, credential),
            None => Err(ManagedTaskInteractionError::Closed),
        };
        if result.is_err() { self.close(); }
        result
    }
}

fn check_live(
    cx: &Cx, client: &ManagedTasksClient, cancellation: &McpRequestCancellation,
    deadline: Time, credential: &OAuthCredentialSnapshot,
) -> Result<(), ManagedTaskInteractionError> {
    client.session.check(cx, cancellation)?;
    let deadline = cx.budget().deadline.map_or(deadline, |caller| caller.min(deadline));
    if cx.now() >= deadline { return Err(OAuthSessionError::TimedOut.into()); }
    if Instant::now() >= credential.expires_at() || credential.credential().is_revoked() {
        return Err(OAuthSessionError::LoginRequired.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use super::super::TASKS_EXTENSION;
    use serde_json::json;

    fn ids(first: i64, second: i64) -> ManagedTaskRequestIds {
        ManagedTaskRequestIds::new(RequestId::Number(first), RequestId::Number(second)).unwrap()
    }

    fn progress(capabilities: Value, policy: ManagedTaskInteractionPolicy) -> ToolProgress {
        let mut metadata = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        metadata[fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY] = capabilities;
        metadata["com.example/original"] = json!("retained");
        let prepared = prepare("https://mcp.example/mcp", &metadata, &RequestId::Number(2),
            ManagedTaskRequest::CallTool { name: "work".to_owned(), arguments: Some(json!({"source":"original"})) },
            ManagedTasksLimits::default()).unwrap();
        let TaskDecoder::Tool(original) = prepared.decoder else { panic!("tool decoder") };
        ToolProgress::new(*original, &ids(1, 2), policy).unwrap()
    }

    fn receive(state: &mut ToolProgress, result: &str) -> Result<ManagedTaskInteractionEvent, ManagedTaskInteractionError> {
        let bytes = format!(r#"{{"jsonrpc":"2.0","id":2,"result":{result}}}"#);
        let decoder = TaskDecoder::Tool(Box::new(state.original.clone()));
        let ManagedTaskEvent::ToolResult(result) = super::super::decode_result(
            &decoder, bytes.as_bytes(), &RequestId::Number(2), 65536,
        ).unwrap() else { panic!("tool result") };
        state.admit_result(result)
    }

    fn answers(value: Value) -> FinalInputResponses { serde_json::from_value(value).unwrap() }

    #[test]
    fn task_capable_continuation_preserves_original_and_can_finish_as_a_task() {
        let mut state = progress(json!({"roots":{}}), ManagedTaskInteractionPolicy::default());
        let before = state.original.encode_params().unwrap().unwrap();
        assert!(matches!(receive(&mut state, r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"  opaque+/%\u0000  "}"#).unwrap(),
            ManagedTaskInteractionEvent::InputRequired(_)));
        let (next, count) = state.prepare_resume("https://mcp.example/mcp", &ids(3, 4),
            Some(answers(json!({"roots":{"roots":[]}}))), InputSelection::Complete,
            ManagedTasksLimits::default()).unwrap();
        let wire: Value = serde_json::from_slice(next.wire.body()).unwrap();
        assert_eq!(wire["method"], "tools/call");
        assert_eq!(wire["id"], 4);
        assert_eq!(wire["params"]["requestState"], "  opaque+/%\0  ");
        assert_eq!(wire["params"]["inputResponses"], json!({"roots":{"roots":[]}}));
        let mut after = wire["params"].clone();
        after.as_object_mut().unwrap().remove("inputResponses");
        after.as_object_mut().unwrap().remove("requestState");
        assert_eq!(after, before);
        assert_eq!(state.original.encode_params().unwrap().unwrap(), before);
        assert_eq!(after["_meta"][fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
            json!({TASKS_EXTENSION:{}}));
        state.commit_resume(&ids(3, 4), count);
        assert!(state.pending.is_none());
        let event = receive(&mut state, r#"{"resultType":"task","taskId":"task-one","status":"working","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":60000}"#).unwrap();
        assert!(matches!(event, ManagedTaskInteractionEvent::Result(result) if matches!(*result, FinalCoreResult::ToolsCallTask { .. })));
        assert!(state.finished);
        assert_eq!(state.continuations, 1);
        assert_eq!(state.records, 2);
    }

    #[test]
    fn invalid_answers_and_numeric_aliases_preserve_the_pending_challenge() {
        let mut state = progress(json!({"roots":{}}), ManagedTaskInteractionPolicy::default());
        receive(&mut state, r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"sealed"}"#).unwrap();
        for supplied in [json!({}), json!({"unknown":{"roots":[]}}), json!({"roots":{"action":"decline"}})] {
            assert!(state.prepare_resume("https://mcp.example/mcp", &ids(3, 4), Some(answers(supplied)),
                InputSelection::Complete, ManagedTasksLimits::default()).is_err());
            assert_eq!(state.pending.as_ref().unwrap().request_state(), Some("sealed"));
            assert_eq!((state.continuations, state.input_responses, state.used_ids.len()), (0, 0, 2));
        }
        for pair in [ids(1, 4), ids(3, 2), ManagedTaskRequestIds::new(
            serde_json::from_str("2e0").unwrap(), RequestId::Number(4),
        ).unwrap()] {
            assert!(matches!(state.prepare_resume("https://mcp.example/mcp", &pair,
                Some(answers(json!({"roots":{"roots":[]}}))), InputSelection::Complete, ManagedTasksLimits::default()),
                Err(ManagedTaskInteractionError::Interaction(ManagedInteractionError::RepeatedRequestId))));
        }
        assert!(state.pending.is_some());
    }

    #[test]
    fn partial_answers_require_state_and_never_accumulate_old_answers() {
        let mut state = progress(json!({"roots":{}}), ManagedTaskInteractionPolicy::default());
        receive(&mut state, r#"{"resultType":"input_required","inputRequests":{"a":{"method":"roots/list"},"b":{"method":"roots/list"}},"requestState":"state-one"}"#).unwrap();
        let (_, count) = state.prepare_resume("https://mcp.example/mcp", &ids(3, 4),
            Some(answers(json!({"a":{"roots":[]}}))), InputSelection::Partial, ManagedTasksLimits::default()).unwrap();
        state.commit_resume(&ids(3, 4), count);
        receive(&mut state, r#"{"resultType":"input_required","inputRequests":{"b":{"method":"roots/list"}}}"#).unwrap();
        let (next, _) = state.prepare_resume("https://mcp.example/mcp", &ids(5, 6),
            Some(answers(json!({"b":{"roots":[]}}))), InputSelection::Complete, ManagedTasksLimits::default()).unwrap();
        let wire: Value = serde_json::from_slice(next.wire.body()).unwrap();
        assert_eq!(wire["params"]["inputResponses"], json!({"b":{"roots":[]}}));
        assert!(wire["params"].get("requestState").is_none());

        let mut stateless = progress(json!({"roots":{}}), ManagedTaskInteractionPolicy::default());
        receive(&mut stateless, r#"{"resultType":"input_required","inputRequests":{"a":{"method":"roots/list"},"b":{"method":"roots/list"}}}"#).unwrap();
        assert!(matches!(stateless.prepare_resume("https://mcp.example/mcp", &ids(3, 4),
            Some(answers(json!({"a":{"roots":[]}}))), InputSelection::Partial, ManagedTasksLimits::default()),
            Err(ManagedTaskInteractionError::Interaction(ManagedInteractionError::PartialStateRequired))));
        assert!(stateless.pending.is_some());
    }

    #[test]
    fn challenge_limits_precede_host_work_but_immediate_completion_needs_no_resolver() {
        let mut no_capability = progress(json!({}), ManagedTaskInteractionPolicy::default());
        assert!(matches!(receive(&mut no_capability, r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}}}"#),
            Err(ManagedTaskInteractionError::Interaction(ManagedInteractionError::CapabilityNotAdvertised))));
        assert!(no_capability.pending.is_none());
        let policy = ManagedTaskInteractionPolicy::new(0, 0, 1).unwrap();
        let mut complete = progress(json!({}), policy);
        assert!(matches!(receive(&mut complete, r#"{"resultType":"complete","content":[],"isError":true}"#).unwrap(),
            ManagedTaskInteractionEvent::Result(_)));
        assert!(complete.finished);
        let mut cannot_continue = progress(json!({}), policy);
        assert!(receive(&mut cannot_continue, r#"{"resultType":"input_required","requestState":"state"}"#).is_err());
        assert!(cannot_continue.pending.is_none());
    }

    #[test]
    fn records_and_input_work_do_not_reset_on_each_continuation() {
        let policy = ManagedTaskInteractionPolicy::new(8, 1, 3).unwrap();
        let mut state = progress(json!({"roots":{}}), policy);
        receive(&mut state, r#"{"resultType":"input_required","inputRequests":{"a":{"method":"roots/list"}}}"#).unwrap();
        let (_, count) = state.prepare_resume("https://mcp.example/mcp", &ids(3, 4),
            Some(answers(json!({"a":{"roots":[]}}))), InputSelection::Complete, ManagedTasksLimits::default()).unwrap();
        state.commit_resume(&ids(3, 4), count);
        assert!(matches!(receive(&mut state, r#"{"resultType":"input_required","inputRequests":{"b":{"method":"roots/list"}}}"#),
            Err(ManagedTaskInteractionError::Interaction(ManagedInteractionError::InputLimit))));
        assert_eq!(state.input_responses, 1);
        assert_eq!(state.records, 2);
        assert!(state.pending.is_none());
    }

    #[test]
    fn absent_and_present_empty_answers_remain_distinct_with_tasks_negotiated() {
        for (source, supplied, present) in [
            (r#"{"resultType":"input_required","requestState":""}"#, None, false),
            (r#"{"resultType":"input_required","inputRequests":{}}"#, Some(answers(json!({}))), true),
        ] {
            let mut state = progress(json!({}), ManagedTaskInteractionPolicy::default());
            receive(&mut state, source).unwrap();
            let (next, count) = state.prepare_resume("https://mcp.example/mcp", &ids(3, 4), supplied,
                InputSelection::Complete, ManagedTasksLimits::default()).unwrap();
            let wire: Value = serde_json::from_slice(next.wire.body()).unwrap();
            assert_eq!(wire["params"].get("inputResponses").is_some(), present);
            assert_eq!(count, 0);
        }
    }

    fn pending_interaction() -> (ManagedTaskInteraction, crate::http_auth::BoundBearerCredential) {
        use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize}};
        use asupersync::sync::Mutex;
        use crate::http_auth::{BoundBearerCredential, CanonicalHttpUrl};
        use crate::http_auth::managed::{OAuthSessionPolicy, SessionInner};
        use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration};

        let url = |value| CanonicalHttpUrl::parse(value).unwrap();
        let resource = url("https://mcp.example/mcp");
        let config = OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url("https://issuer.example/token"), resource.clone(), "native-client", vec![],
        ).unwrap();
        let session = super::super::ManagedOAuthSession {
            inner: Arc::new(SessionInner {
                client: OAuthClient::new(config), resource: resource.clone(),
                policy: OAuthSessionPolicy::default(), state: Arc::new(Mutex::new(None)),
                closed: McpRequestCancellation::new(), logout_handoff: AtomicBool::new(false),
                pending: AtomicUsize::new(0),
            }),
        };
        let expiry = Instant::now() + std::time::Duration::from_secs(60);
        let bearer = BoundBearerCredential::bind_with_expiry(resource, "opening-secret", expiry).unwrap();
        let credential = OAuthCredentialSnapshot::new(&bearer, &[], 1, expiry, &session.inner.closed).unwrap();
        let mut progress = progress(json!({"roots":{}}), ManagedTaskInteractionPolicy::default());
        receive(&mut progress, r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"sealed-original"}"#).unwrap();
        let metadata = progress.original.encode_params().unwrap().unwrap()["_meta"].clone();
        (ManagedTaskInteraction {
            client: ManagedTasksClient { session, metadata, limits: ManagedTasksLimits::default() },
            credential: Some(credential), call: None, progress,
            cancellation: McpRequestCancellation::new(), deadline: Time::from_nanos(u64::MAX),
        }, bearer)
    }

    #[test]
    fn resume_transfers_custody_once_and_keeps_continuations_out_of_discovery() {
        let cx = Cx::for_testing();
        let (mut operation, bearer) = pending_interaction();
        let rejected = operation.take_resume(&cx, ids(3, 4), Some(answers(json!({}))), InputSelection::Complete);
        assert!(rejected.is_err());
        assert!(operation.pending_input().is_some());
        assert!(operation.credential.is_some());
        let (round, credential) = operation.take_resume(&cx, ids(3, 4),
            Some(answers(json!({"roots":{"roots":[]}}))), InputSelection::Complete).unwrap();
        assert!(operation.pending_input().is_none());
        assert!(operation.credential.is_none());
        assert_eq!(operation.continuation_count(), 1);
        let discovery: Value = serde_json::from_slice(round.discover_wire.body()).unwrap();
        let continuation: Value = serde_json::from_slice(round.prepared.wire.body()).unwrap();
        assert_eq!(discovery["method"], "server/discover");
        assert!(discovery["params"].get("requestState").is_none());
        assert!(discovery["params"].get("inputResponses").is_none());
        assert_eq!(continuation["params"]["requestState"], "sealed-original");
        for wire in [&round.discover_wire, &round.prepared.wire] {
            let authenticated = credential.authorize_request(wire).unwrap();
            assert!(authenticated.headers().iter().any(|(name, value)|
                name.eq_ignore_ascii_case("authorization") && value == "Bearer opening-secret"));
        }
        // Abandon the exact attempt before receiving a response. There is no
        // retained credential or pending challenge with which to send it again.
        drop((round, credential));
        assert!(matches!(operation.take_resume(&cx, ids(5, 6),
            Some(answers(json!({"roots":{"roots":[]}}))), InputSelection::Complete),
            Err(ManagedTaskInteractionError::Closed)));
        assert!(!bearer.is_revoked());
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn oversized_continuation_is_correctable_without_consuming_ids_or_state() {
        let cx = Cx::for_testing();
        let (mut operation, _) = pending_interaction();
        operation.client.limits = ManagedTasksLimits::new(1024, 4096, 16, std::time::Duration::from_secs(60)).unwrap();
        let uri = format!("file:///{}", "x".repeat(2048));
        assert!(matches!(operation.take_resume(&cx, ids(3, 4),
            Some(answers(json!({"roots":{"roots":[{"uri":uri}]}}))), InputSelection::Complete),
            Err(ManagedTaskInteractionError::Task(ManagedTasksError::RequestTooLarge))));
        assert!(operation.pending_input().is_some());
        assert_eq!(operation.continuation_count(), 0);
        assert_eq!(operation.progress.used_ids.len(), 2);
        assert!(operation.take_resume(&cx, ids(3, 4),
            Some(answers(json!({"roots":{"roots":[]}}))), InputSelection::Complete).is_ok());
    }

    #[test]
    fn revoked_opening_credential_closes_pending_input_instead_of_renewing() {
        let cx = Cx::for_testing();
        let (mut operation, bearer) = pending_interaction();
        let (sibling, independent) = pending_interaction();
        bearer.revoke();
        assert!(matches!(operation.take_resume(&cx, ids(3, 4),
            Some(answers(json!({"roots":{"roots":[]}}))), InputSelection::Complete),
            Err(ManagedTaskInteractionError::Task(ManagedTasksError::Session(OAuthSessionError::LoginRequired)))));
        assert!(operation.pending_input().is_none());
        assert!(operation.credential.is_none());
        assert_eq!(operation.continuation_count(), 0);
        assert!(!operation.client.session.inner.closed.is_cancel_requested());
        assert!(!independent.is_revoked());
        assert!(sibling.pending_input().is_some());
    }

    #[test]
    fn pending_input_is_not_eof_and_cancellation_closes_only_its_owner() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};
        let cx = Cx::for_testing();
        let (mut operation, bearer) = pending_interaction();
        let mut task = Context::from_waker(Waker::noop());
        {
            let mut read = Box::pin(operation.next_event(&cx));
            assert!(matches!(read.as_mut().poll(&mut task),
                Poll::Ready(Err(ManagedTaskInteractionError::InputPending))));
        }
        assert!(operation.pending_input().is_some());
        operation.cancellation.cancel();
        {
            let mut read = Box::pin(operation.next_event(&cx));
            assert!(matches!(read.as_mut().poll(&mut task),
                Poll::Ready(Err(ManagedTaskInteractionError::Task(ManagedTasksError::Session(OAuthSessionError::Cancelled))))));
        }
        assert!(operation.pending_input().is_none());
        assert!(!bearer.is_revoked());
        assert!(!operation.client.session.inner.closed.is_cancel_requested());
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn host_driver_can_pause_without_spending_continuation_state_or_ids() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        use std::cell::Cell;
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let (operation, bearer) = pending_interaction();
            let calls = Cell::new(0);
            let outcome = operation.drive(&cx, |input| {
                calls.set(calls.get() + 1);
                assert_eq!(input.request_state(), Some("sealed-original"));
                std::future::ready(Ok(ManagedTaskInputAction::Pause))
            }, |_| panic!("no notification was received")).await.unwrap();
            let ManagedTaskDriveOutcome::Paused(mut operation) = outcome else { panic!("host pause") };
            assert_eq!(calls.get(), 1);
            assert_eq!(operation.continuation_count(), 0);
            assert_eq!(operation.progress.used_ids.len(), 2);
            assert_eq!(operation.pending_input().unwrap().request_state(), Some("sealed-original"));
            assert!(operation.take_resume(&cx, ids(3, 4),
                Some(answers(json!({"roots":{"roots":[]}}))), InputSelection::Complete).is_ok());
            assert!(!bearer.is_revoked());
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn host_driver_does_not_retry_resolver_failure_or_invalid_answers() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        use std::cell::Cell;
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            for invalid in [false, true] {
                let (operation, bearer) = pending_interaction();
                let calls = Cell::new(0);
                let result = operation.drive(&cx, |_| {
                    calls.set(calls.get() + 1);
                    std::future::ready(if invalid {
                        Ok(ManagedTaskInputAction::Respond { ids: ids(3, 4), input_responses: Some(answers(json!({}))) })
                    } else { Err(ManagedInteractionError::AbortedByHost.into()) })
                }, |_| Ok(())).await;
                assert!(matches!(result, Err(ManagedTaskInteractionError::Interaction(_))));
                assert_eq!(calls.get(), 1);
                assert!(!bearer.is_revoked());
                assert!(cx.checkpoint().is_ok());
            }
        });
    }

    struct PendingResolver(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl Future for PendingResolver {
        type Output = Result<ManagedTaskInputAction, ManagedTaskInteractionError>;
        fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
            std::task::Poll::Pending
        }
    }
    impl Drop for PendingResolver {
        fn drop(&mut self) { self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
    }

    #[test]
    fn closing_session_wakes_and_drops_an_idle_host_resolver() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        use std::task::{Context, Poll, Wake, Waker};
        struct Count(AtomicUsize);
        impl Wake for Count {
            fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
            fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let (operation, _) = pending_interaction();
            let session_close = operation.client.session.inner.closed.clone();
            let cancellation = operation.cancellation.clone();
            let dropped = Arc::new(AtomicUsize::new(0));
            let counter = Arc::new(Count(AtomicUsize::new(0)));
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = Context::from_waker(&waker);
            let mut driver = Box::pin(operation.drive(&cx, |_| PendingResolver(Arc::clone(&dropped)), |_| Ok(())));
            assert!(driver.as_mut().poll(&mut task).is_pending());
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            let before = counter.0.load(Ordering::SeqCst);
            session_close.cancel();
            assert!(counter.0.load(Ordering::SeqCst) > before, "must wake without a resolver event");
            assert!(matches!(driver.as_mut().poll(&mut task),
                Poll::Ready(Err(ManagedTaskInteractionError::Task(ManagedTasksError::Session(OAuthSessionError::Closed))))));
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert!(!cancellation.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn abandoning_driver_drops_host_work_without_revoking_sibling_credentials() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        use std::task::{Context, Waker};
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let (operation, bearer) = pending_interaction();
            let session = operation.client.session.clone();
            let dropped = Arc::new(AtomicUsize::new(0));
            let mut driver = Box::pin(operation.drive(&cx, |_| PendingResolver(Arc::clone(&dropped)), |_| Ok(())));
            let mut task = Context::from_waker(Waker::noop());
            assert!(driver.as_mut().poll(&mut task).is_pending());
            drop(driver);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert!(!session.inner.closed.is_cancel_requested());
            assert!(!bearer.is_revoked());
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn pre_cancelled_driver_never_invokes_host_code() {
        use std::cell::Cell;
        use std::task::{Context, Poll, Waker};
        let cx = Cx::for_testing();
        let (operation, bearer) = pending_interaction();
        operation.cancellation.cancel();
        let calls = Cell::new(0);
        let mut driver = Box::pin(operation.drive(&cx, |_| {
            calls.set(calls.get() + 1);
            std::future::ready(Ok(ManagedTaskInputAction::Pause))
        }, |_| Ok(())));
        let mut task = Context::from_waker(Waker::noop());
        assert!(matches!(driver.as_mut().poll(&mut task),
            Poll::Ready(Err(ManagedTaskInteractionError::Task(ManagedTasksError::Session(OAuthSessionError::Cancelled))))));
        assert_eq!(calls.get(), 0);
        assert!(!bearer.is_revoked());
    }
}
