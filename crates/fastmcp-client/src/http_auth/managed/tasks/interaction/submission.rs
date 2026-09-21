//! Owned submission of a Task-capable tool call, including uncertain delivery.
//!
//! Prepare the owner before polling any network future. Discovery failures are
//! distinct from failures after the tool operation reaches its executor. Once
//! delivery is uncertain, neither send nor resume can repeat that attempt.
//! An application must reconcile through its own declared idempotency contract;
//! a request ID is not an idempotency key and a missing Task ID is never guessed.
//!
//! This is volatile custody, not durable Task resume or exactly-once execution.
//! The existing interaction/Tasks codecs still authorize every result and input.

use std::fmt;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreResult, FinalCoreResult, FinalInputResponses, InputRequiredResult, RequestId};
use serde_json::Value;

use super::{
    InputSelection, ManagedTaskCall, ManagedTaskInteraction,
    ManagedTaskInteractionError, ManagedTaskInteractionEvent, ManagedTaskInteractionPolicy,
    ManagedTaskRequest, ManagedTaskRequestIds, ManagedTasksClient, ManagedTasksError,
    ManagedTasksLimits, OAuthCredentialSnapshot, PreparedTaskRound, TaskDecoder,
    ToolProgress, check_live, deadline_after, prepare,
};
use super::super::{admit_discovery, require_json, response_source};

/// Local evidence about this submission, not proof of remote commit or rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskSubmissionState {
    /// Locally validated, with no credential acquisition or network effects.
    Prepared,
    /// The current attempt stopped during local admission/discovery. Its owned
    /// attempt was consumed; sending it again requires a separate host decision.
    NotDispatched,
    /// The admitted tool POST has a response that still needs full validation.
    AwaitingResponse,
    /// A validated input-required reply is pending explicit host input.
    AwaitingInput,
    /// The tool executor was entered, but no complete result was delivered.
    /// This is deliberately conservative: it does not prove bytes were sent.
    DeliveryUnknown,
    /// A fully admitted complete or Task result was handed to the caller.
    Resolved,
    /// A pending input challenge was explicitly abandoned, not completed.
    Closed,
}

/// Errors retain a typed cause but never invent a Task ID or retry permission.
/// Debug/Display intentionally omit the cause; callers can inspect it explicitly.
pub enum ManagedTaskSubmissionError {
    InvalidState,
    InputPending,
    NotDispatched(Box<ManagedTaskInteractionError>),
    /// A Task or other tool effect may already exist. Do not repeat the creating
    /// call or continuation automatically, including after timeout/cancellation.
    TaskCreationDeliveryUnknown(Box<ManagedTaskInteractionError>),
}

impl ManagedTaskSubmissionError {
    pub fn cause(&self) -> Option<&ManagedTaskInteractionError> {
        match self {
            Self::NotDispatched(cause) | Self::TaskCreationDeliveryUnknown(cause) => Some(cause),
            Self::InvalidState | Self::InputPending => None,
        }
    }
}

impl fmt::Display for ManagedTaskSubmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidState => "Task submission is not in the required phase",
            Self::InputPending => "Task submission requires explicit host input",
            Self::NotDispatched(_) => "Task-capable tool attempt stopped before operation dispatch",
            Self::TaskCreationDeliveryUnknown(_) =>
                "Task creation delivery is unknown; reconcile manually and do not repeat the tool attempt",
        })
    }
}
impl fmt::Debug for ManagedTaskSubmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(self, f) }
}
impl std::error::Error for ManagedTaskSubmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause().map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

/// Non-Clone ownership exists BEFORE the first send. An abandoned polled send
/// records whether it reached tool dispatch; an abandoned polled read records
/// unknown delivery. Neither can be resumed by calling send a second time.
/// Unpolled futures do not consume the prepared attempt or pending response.
///
/// Notifications are incremental. Complete, input-required and actual Task
/// results retain their protocol distinction; a Task result does not become
/// a successful tool completion. Input is answered only through explicit resume.
/// Local argument/answer validation and fresh discovery precede every tool POST.
/// The initial send starts one deadline shared with every read/continuation.
/// The opening credential, request-local cancellation and all interaction
/// counters remain pinned until the owner resolves or is closed/dropped.
#[must_use = "send once, observe the result, and inspect uncertainty before discarding custody"]
pub struct ManagedTaskSubmission {
    client: ManagedTasksClient,
    prepared: Option<(PreparedTaskRound, ToolProgress)>,
    interaction: Option<ManagedTaskInteraction>,
    request_id: RequestId,
    state: TaskSubmissionState,
}

impl fmt::Debug for ManagedTaskSubmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedTaskSubmission").field("state", &self.state).finish_non_exhaustive()
    }
}

impl ManagedTasksClient {
    /// Performs only bounded local preparation. No token is acquired, no
    /// discovery or tool POST is sent, and no Task preference is injected into
    /// the original tool arguments. Application idempotency data stays exactly
    /// where the application put it; this API synthesizes no idempotency key.
    pub fn prepare_tool_submission(
        &self,
        ids: ManagedTaskRequestIds,
        name: String,
        arguments: Option<Value>,
        policy: ManagedTaskInteractionPolicy,
    ) -> Result<ManagedTaskSubmission, ManagedTaskSubmissionError> {
        let pending = (|| {
            let prepared = prepare(self.session.resource().as_str(), &self.metadata, &ids.operation,
                ManagedTaskRequest::CallTool { name, arguments }, self.limits)?;
            let TaskDecoder::Tool(original) = &prepared.decoder else {
                return Err(ManagedTasksError::InvalidRequest.into());
            };
            let progress = ToolProgress::new((**original).clone(), &ids, policy)?;
            let request_id = ids.operation.clone();
            let round = self.prepare_round(ids, prepared)?;
            Ok::<_, ManagedTaskInteractionError>((round, progress, request_id))
        })().map_err(|error| ManagedTaskSubmissionError::NotDispatched(Box::new(error)))?;
        Ok(ManagedTaskSubmission {
            client: self.clone(), prepared: Some((pending.0, pending.1)), interaction: None,
            request_id: pending.2, state: TaskSubmissionState::Prepared,
        })
    }
}

impl ManagedTaskSubmission {
    pub fn state(&self) -> TaskSubmissionState { self.state }

    /// Correlation identity of the latest admitted attempt, never a Task ID or
    /// a cross-process idempotency token. Local rejected answers leave it intact.
    pub fn request_id(&self) -> &RequestId { &self.request_id }

    pub fn pending_input(&self) -> Option<&InputRequiredResult> {
        self.interaction.as_ref().and_then(ManagedTaskInteraction::pending_input)
    }

    /// Drops local sockets, arguments, input state and credential custody. It
    /// sends no remote cancellation. Unknown delivery remains unknown, and an
    /// abandoned input challenge must not be reported as successful EOF.
    pub fn close(&mut self) {
        self.prepared = None;
        self.interaction = None;
        self.state = closed_state(self.state);
    }

    pub async fn send(&mut self, cx: &Cx) -> Result<(), ManagedTaskSubmissionError> {
        self.send_with_cancellation(cx, &McpRequestCancellation::new()).await
    }

    /// The cancellation domain is retained across all subsequent reads and
    /// continuations. Cancellation before dispatch is not remote cancellation;
    /// cancellation after possible dispatch cannot prove absence of a Task.
    pub async fn send_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
    ) -> Result<(), ManagedTaskSubmissionError> {
        if self.state != TaskSubmissionState::Prepared { return Err(self.phase_error()); }
        let (round, progress) = self.prepared.take().ok_or(ManagedTaskSubmissionError::InvalidState)?;
        // Commit local attempt consumption before any possible suspension.
        self.state = TaskSubmissionState::NotDispatched;
        let result = async {
            self.client.session.check(cx, cancellation)?;
            let deadline = deadline_after(cx, self.client.limits.timeout)?;
            let credential = self.client.session.await_active(cx, cancellation, deadline, None, async {
                self.client.session.credential_with_cancellation(cx, cancellation).await
            }).await?;
            let call = dispatch_tracked(&mut self.state, cx, &self.client, cancellation,
                round, &credential, deadline, progress.remaining_records()).await?;
            check_live(cx, &self.client, cancellation, deadline, &credential)?;
            Ok::<_, ManagedTaskInteractionError>(ManagedTaskInteraction {
                client: self.client.clone(), credential: Some(credential), call: Some(Box::new(call)),
                progress, cancellation: cancellation.clone(), deadline,
            })
        }.await;
        match result {
            Ok(interaction) => {
                self.interaction = Some(interaction);
                self.state = TaskSubmissionState::AwaitingResponse;
                Ok(())
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    /// Delivers one incremental event through the existing strict interaction
    /// decoder. Every failure after dispatch is conservatively uncertain, even
    /// a protocol, HTTP or peer error: none establishes remote rollback.
    /// A partially read SSE result cannot resolve this owner's uncertainty.
    pub async fn next_event(
        &mut self, cx: &Cx,
    ) -> Result<Option<ManagedTaskInteractionEvent>, ManagedTaskSubmissionError> {
        match self.state {
            TaskSubmissionState::Resolved => return Ok(None),
            TaskSubmissionState::AwaitingInput => {
                let interaction = self.interaction.as_mut().ok_or(ManagedTaskSubmissionError::InvalidState)?;
                if let Err(error) = interaction.check(cx) {
                    self.close();
                    return Err(ManagedTaskSubmissionError::NotDispatched(Box::new(error)));
                }
                return Err(ManagedTaskSubmissionError::InputPending);
            }
            TaskSubmissionState::AwaitingResponse => {},
            _ => return Err(self.phase_error()),
        }
        let mut interaction = self.interaction.take().ok_or_else(|| self.phase_error())?;
        // A dropped POLLED read loses parser custody and cannot become a retry.
        self.state = TaskSubmissionState::DeliveryUnknown;
        match interaction.next_event(cx).await {
            Ok(Some(event)) => {
                self.state = match &event {
                    ManagedTaskInteractionEvent::Notification(_) => TaskSubmissionState::AwaitingResponse,
                    ManagedTaskInteractionEvent::InputRequired(_) => TaskSubmissionState::AwaitingInput,
                    ManagedTaskInteractionEvent::Result(_) => TaskSubmissionState::Resolved,
                };
                if self.state != TaskSubmissionState::Resolved { self.interaction = Some(interaction); }
                Ok(Some(event))
            }
            Ok(None) => Err(self.fail(ManagedTasksError::MissingTerminal.into())),
            Err(error) => Err(self.fail(error)),
        }
    }

    pub async fn resume(
        &mut self, cx: &Cx, ids: ManagedTaskRequestIds, responses: Option<FinalInputResponses>,
    ) -> Result<(), ManagedTaskSubmissionError> {
        self.resume_selected(cx, ids, responses, InputSelection::Complete).await
    }

    /// Partial answers obey the existing nonempty-state and input-key rules.
    /// A locally invalid answer remains correctable; a possibly dispatched
    /// continuation never returns the consumed challenge as retry authority.
    pub async fn resume_partial(
        &mut self, cx: &Cx, ids: ManagedTaskRequestIds, responses: FinalInputResponses,
    ) -> Result<(), ManagedTaskSubmissionError> {
        self.resume_selected(cx, ids, Some(responses), InputSelection::Partial).await
    }

    async fn resume_selected(
        &mut self, cx: &Cx, ids: ManagedTaskRequestIds,
        responses: Option<FinalInputResponses>, selection: InputSelection,
    ) -> Result<(), ManagedTaskSubmissionError> {
        if self.state != TaskSubmissionState::AwaitingInput { return Err(self.phase_error()); }
        let request_id = ids.operation.clone();
        let interaction = self.interaction.as_mut().ok_or(ManagedTaskSubmissionError::InvalidState)?;
        let (round, credential) = match interaction.take_resume(cx, ids, responses, selection) {
            Ok(prepared) => prepared,
            Err(error) => {
                // Local validation preserves the challenge; lifetime failures
                // close it in the shared validator. Neither dispatched a retry.
                if interaction.pending_input().is_none() || interaction.credential.is_none() {
                    self.close();
                }
                return Err(ManagedTaskSubmissionError::NotDispatched(Box::new(error)));
            }
        };
        let mut interaction = self.interaction.take().ok_or(ManagedTaskSubmissionError::InvalidState)?;
        self.request_id = request_id;
        self.state = TaskSubmissionState::NotDispatched;
        let result = dispatch_tracked(&mut self.state, cx, &self.client, &interaction.cancellation,
            round, &credential, interaction.deadline, interaction.progress.remaining_records()).await;
        let result = result.and_then(|call| {
            check_live(cx, &self.client, &interaction.cancellation, interaction.deadline, &credential)?;
            Ok(call)
        });
        match result {
            Ok(call) => {
                interaction.call = Some(Box::new(call));
                interaction.credential = Some(credential);
                self.interaction = Some(interaction);
                self.state = TaskSubmissionState::AwaitingResponse;
                Ok(())
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    fn phase_error(&self) -> ManagedTaskSubmissionError {
        if self.state == TaskSubmissionState::DeliveryUnknown {
            ManagedTaskSubmissionError::TaskCreationDeliveryUnknown(Box::new(ManagedTaskInteractionError::Closed))
        } else {
            ManagedTaskSubmissionError::InvalidState
        }
    }

    fn fail(&mut self, error: ManagedTaskInteractionError) -> ManagedTaskSubmissionError {
        self.close();
        if self.state == TaskSubmissionState::DeliveryUnknown {
            ManagedTaskSubmissionError::TaskCreationDeliveryUnknown(Box::new(error))
        } else {
            ManagedTaskSubmissionError::NotDispatched(Box::new(error))
        }
    }
}

fn closed_state(state: TaskSubmissionState) -> TaskSubmissionState {
    match state {
        TaskSubmissionState::AwaitingResponse | TaskSubmissionState::DeliveryUnknown => TaskSubmissionState::DeliveryUnknown,
        TaskSubmissionState::AwaitingInput | TaskSubmissionState::Closed => TaskSubmissionState::Closed,
        TaskSubmissionState::Prepared | TaskSubmissionState::NotDispatched => TaskSubmissionState::NotDispatched,
        TaskSubmissionState::Resolved => TaskSubmissionState::Resolved,
    }
}

// The only additional dispatch decision is the local uncertainty checkpoint.
// All wire preparation, live resource discovery, surface admission, auth and
// HTTP response ownership reuse the existing production validators/executor.
// The checkpoint is conservative at executor handoff, not a socket-byte receipt:
// a connect failure after this point can still be reported as unknown delivery.
#[allow(clippy::too_many_arguments)]
async fn dispatch_tracked(
    state: &mut TaskSubmissionState, cx: &Cx, client: &ManagedTasksClient,
    cancellation: &McpRequestCancellation, round: PreparedTaskRound,
    credential: &OAuthCredentialSnapshot, deadline: Time, records: usize,
) -> Result<ManagedTaskCall, ManagedTaskInteractionError> {
    if records == 0 { return Err(ManagedTasksError::RecordLimit.into()); }
    let PreparedTaskRound { ids, prepared, discovery, discover_wire } = round;
    let response = client.execute_bound(cx, cancellation, deadline, credential, &discover_wire).await?;
    require_json(&response)?;
    let bytes = client.session.await_active(cx, cancellation, deadline, Some(credential.expires_at), async {
        response.read_to_end(cx, client.limits.frame_bytes).await
    }).await?;
    let (envelope, source) = response_source(&bytes, &ids.discovery, client.limits.frame_bytes)?;
    let CoreResult::Final(FinalCoreResult::Discover(discovered)) = discovery.decode_response_result(&envelope, &source)
        .map_err(|_| ManagedTasksError::InvalidResponse)? else { return Err(ManagedTasksError::InvalidResponse.into()); };
    admit_discovery(&discovered, &prepared.decoder)?;
    check_live(cx, client, cancellation, deadline, credential)?;
    // From this line onward, disappearance of the future is retained by the
    // caller-owned state even though no Rust Result can be delivered on Drop.
    *state = TaskSubmissionState::DeliveryUnknown;
    let response = client.execute_bound(cx, cancellation, deadline, credential, &prepared.wire).await?;
    let limits = ManagedTasksLimits { records: records.min(client.limits.records), ..client.limits };
    Ok(ManagedTaskCall::from_response(response, prepared, ids.operation, limits, deadline)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize}};
    use std::task::{Context, Poll, Waker};
    use asupersync::sync::Mutex;
    use crate::http_auth::CanonicalHttpUrl;
    use crate::http_auth::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy, SessionInner};
    use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration};
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::json;

    fn client() -> ManagedTasksClient {
        let url = |text| CanonicalHttpUrl::parse(text).unwrap();
        let resource = url("https://mcp.example/mcp");
        let configuration = OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url("https://issuer.example/token"), resource.clone(), "native-client", vec![],
        ).unwrap();
        let session = ManagedOAuthSession { inner: Arc::new(SessionInner {
            client: OAuthClient::new(configuration), resource, policy: OAuthSessionPolicy::default(),
            state: Arc::new(Mutex::new(None)), closed: McpRequestCancellation::new(),
            logout_handoff: AtomicBool::new(false), pending: AtomicUsize::new(0),
        }) };
        ManagedTasksClient::new(session, FinalRequestMeta::new(ClientCapabilities::default()), ManagedTasksLimits::default()).unwrap()
    }

    fn submission() -> ManagedTaskSubmission {
        client().prepare_tool_submission(ManagedTaskRequestIds::new(RequestId::Number(1), RequestId::Number(2)).unwrap(),
            "work".to_owned(), Some(json!({"applicationKey":"host-chosen","secret":"not-for-diagnostics"})),
            ManagedTaskInteractionPolicy::default()).unwrap()
    }

    #[test]
    fn preparation_preserves_arguments_and_has_no_login_or_task_state() {
        let owner = submission();
        assert_eq!(owner.state(), TaskSubmissionState::Prepared);
        assert!(owner.interaction.is_none());
        let (round, progress) = owner.prepared.as_ref().unwrap();
        let wire: Value = serde_json::from_slice(round.prepared.wire.body()).unwrap();
        assert_eq!(wire["params"]["arguments"], json!({"applicationKey":"host-chosen","secret":"not-for-diagnostics"}));
        assert!(wire["params"].get("task").is_none());
        assert_eq!(progress.continuations, 0);
        assert_eq!(progress.used_ids.len(), 2);
        assert!(!format!("{owner:?}").contains("not-for-diagnostics"));
    }

    #[test]
    fn unpolled_send_does_not_consume_local_custody() {
        let cx = Cx::for_testing();
        let mut owner = submission();
        drop(Box::pin(owner.send(&cx)));
        assert_eq!(owner.state(), TaskSubmissionState::Prepared);
        assert!(owner.prepared.is_some());
        assert_eq!(owner.request_id(), &RequestId::Number(2));
    }

    #[test]
    fn pre_cancelled_send_is_not_dispatched_and_cannot_be_repeated() {
        use std::future::Future;
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        cancellation.cancel();
        let mut owner = submission();
        let mut context = Context::from_waker(Waker::noop());
        {
            let mut send = Box::pin(owner.send_with_cancellation(&cx, &cancellation));
            assert!(matches!(send.as_mut().poll(&mut context), Poll::Ready(Err(ManagedTaskSubmissionError::NotDispatched(cause)))
                if matches!(*cause, ManagedTaskInteractionError::Task(ManagedTasksError::Session(OAuthSessionError::Cancelled)))));
        }
        assert_eq!(owner.state(), TaskSubmissionState::NotDispatched);
        assert!(owner.prepared.is_none());
        let mut send = Box::pin(owner.send(&cx));
        assert!(matches!(send.as_mut().poll(&mut context), Poll::Ready(Err(ManagedTaskSubmissionError::InvalidState))));
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn close_preserves_uncertainty_and_never_completes_pending_input() {
        for (before, after) in [
            (TaskSubmissionState::Prepared, TaskSubmissionState::NotDispatched),
            (TaskSubmissionState::NotDispatched, TaskSubmissionState::NotDispatched),
            (TaskSubmissionState::AwaitingResponse, TaskSubmissionState::DeliveryUnknown),
            (TaskSubmissionState::DeliveryUnknown, TaskSubmissionState::DeliveryUnknown),
            (TaskSubmissionState::AwaitingInput, TaskSubmissionState::Closed),
            (TaskSubmissionState::Resolved, TaskSubmissionState::Resolved),
            (TaskSubmissionState::Closed, TaskSubmissionState::Closed),
        ] {
            assert_eq!(closed_state(before), after);
            assert_eq!(closed_state(after), after);
        }
    }

    #[test]
    fn same_failure_is_classified_by_dispatch_evidence_not_error_spelling() {
        let mut before = submission();
        before.state = TaskSubmissionState::NotDispatched;
        let mut after = submission();
        after.state = TaskSubmissionState::DeliveryUnknown;
        assert!(matches!(before.fail(ManagedTasksError::MissingTerminal.into()), ManagedTaskSubmissionError::NotDispatched(_)));
        assert!(matches!(after.fail(ManagedTasksError::MissingTerminal.into()), ManagedTaskSubmissionError::TaskCreationDeliveryUnknown(_)));
        assert!(matches!(after.phase_error(), ManagedTaskSubmissionError::TaskCreationDeliveryUnknown(_)));
        assert!(before.prepared.is_none() && after.prepared.is_none());
    }
}
