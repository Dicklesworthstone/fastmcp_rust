//! Explicit core input followed by insert-only persistence of the actual Task.
//!
//! The existing submission alone prepares, authorizes and dispatches every round.
//! A core input challenge is neither a Task nor a persistence event. Only an
//! admitted nonterminal Task triggers the shared initial-checkpoint writer.

use std::fmt;
use std::future::Future;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{FinalInputResponses, InputRequiredResult, RequestId, ServerNotification};

use super::{ClientCredentialsSnapshot, ClientCredentialsTaskSubmission,
    ClientCredentialsTaskSubmissionError, ClientCredentialsTaskSubmissionEvent, TaskSubmissionState};
use super::super::creation::persist_pending;
pub use super::super::creation::{ClientCredentialsTaskPersistenceWarning,
    PendingClientCredentialsTaskResult, PersistedClientCredentialsTaskResult,
    TaskResumeBinding, TaskResumeCapturePolicy, TaskResumeError, TaskResumeInsert};

/// Before result admission, preserve the underlying submission's exact delivery
/// classification. After admission, storage failures accompany the real result
/// as ClientCredentialsTaskPersistenceWarning, never as a creation error.
#[derive(Debug)]
pub enum CheckpointedTaskSubmissionError {
    Resume(TaskResumeError),
    Submission(ClientCredentialsTaskSubmissionError),
    Closed,
}
impl fmt::Display for CheckpointedTaskSubmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resume(error) => error.fmt(f),
            Self::Submission(error) => error.fmt(f),
            Self::Closed => f.write_str("checkpointed machine submission is closed; do not replay"),
        }
    }
}
impl std::error::Error for CheckpointedTaskSubmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resume(error) => Some(error), Self::Submission(error) => Some(error),
            Self::Closed => None,
        }
    }
}
impl From<TaskResumeError> for CheckpointedTaskSubmissionError {
    fn from(error: TaskResumeError) -> Self { Self::Resume(error) }
}
impl From<ClientCredentialsTaskSubmissionError> for CheckpointedTaskSubmissionError {
    fn from(error: ClientCredentialsTaskSubmissionError) -> Self { Self::Submission(error) }
}

/// InputRequired must be answered explicitly through resume or resume_partial.
/// Result is the intact final protocol union plus independent checkpoint evidence.
pub enum CheckpointedTaskSubmissionEvent<E> {
    Notification(Box<ServerNotification>),
    InputRequired(Box<InputRequiredResult>),
    Result(Box<PersistedClientCredentialsTaskResult<E>>),
}

impl ClientCredentialsTaskSubmission {
    /// Attach initial checkpoint custody BEFORE sending this prepared submission.
    /// The host independently binds current to this machine registration; saved
    /// data never selects a client, resource, credential or continuation.
    ///
    /// Complete/partial/state-only continuations keep this submission's original
    /// authority, metadata, identities and cumulative limits. Nothing invokes an
    /// input resolver automatically. Wrong local answers remain correctable.
    ///
    /// persist must conditionally INSERT the controls and acknowledge only after
    /// durable completion. Use TaskResumeInsert::apply in the host's owned,
    /// joined blocking lane; the library installs no store, key or worker.
    /// The original credential and deadline also cover persistence, not a newly
    /// acquired token or a fresh timeout after the final continuation.
    ///
    /// No record is saved for a core input challenge, ordinary result, unknown
    /// delivery or already-terminal Task. Failure to save a known Task returns
    /// that real result with a warning. This is not a durable continuation log,
    /// process-crash result inbox, automatic restart or exactly-once execution.
    pub fn with_initial_checkpoint<P, F, E>(
        self, current: TaskResumeBinding, capture: TaskResumeCapturePolicy, persist: P,
    ) -> Result<CheckpointedClientCredentialsTaskSubmission<P>, CheckpointedTaskSubmissionError>
    where P: FnMut(TaskResumeInsert) -> F, F: Future<Output = Result<(), E>>,
    {
        if self.state() != TaskSubmissionState::Prepared {
            return Err(self.phase_error().into());
        }
        if current.resource().as_str() != self.client.client.resource().as_str() {
            return Err(TaskResumeError::Unavailable.into());
        }
        Ok(CheckpointedClientCredentialsTaskSubmission {
            submission: self, current, capture, persist, pending: None, closed: false, finished: false,
        })
    }
}

/// Caller-owned multi-round submission and its single initial checkpoint attempt.
/// Dropping a polled response/save retires observation without losing a known
/// result or its write disposition. Pending input and storage are deliberately
/// different states; neither failure can recreate the original tool request.
#[must_use = "retain submission custody through input, result and checkpoint disposition"]
pub struct CheckpointedClientCredentialsTaskSubmission<P> {
    submission: ClientCredentialsTaskSubmission,
    current: TaskResumeBinding,
    capture: TaskResumeCapturePolicy,
    persist: P,
    pending: Option<PendingClientCredentialsTaskResult>,
    closed: bool,
    finished: bool,
}
impl<P> fmt::Debug for CheckpointedClientCredentialsTaskSubmission<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckpointedClientCredentialsTaskSubmission")
            .field("submission_state", &self.submission.state())
            .field("pending_result", &self.pending.is_some())
            .field("closed", &self.closed).field("finished", &self.finished).finish_non_exhaustive()
    }
}
impl<P> CheckpointedClientCredentialsTaskSubmission<P> {
    /// Resolved is remote result evidence, not acknowledgement of a saved record.
    pub fn submission_state(&self) -> TaskSubmissionState { self.submission.state() }
    pub fn request_id(&self) -> &RequestId { self.submission.request_id() }
    pub fn pending_input(&self) -> Option<&InputRequiredResult> { self.submission.pending_input() }
    pub fn pending(&self) -> Option<&PendingClientCredentialsTaskResult> { self.pending.as_ref() }
    pub fn is_finished(&self) -> bool { self.finished }
    pub fn close(&mut self) { self.closed = true; self.submission.close(); }
    /// Export retained result/write evidence without granting another save or POST.
    pub fn take_pending(&mut self) -> Option<PendingClientCredentialsTaskResult> {
        self.close(); self.pending.take()
    }

    pub async fn send(&mut self, cx: &Cx) -> Result<(), CheckpointedTaskSubmissionError> {
        self.send_with_cancellation(cx, &McpRequestCancellation::new()).await
    }
    pub async fn send_with_cancellation(&mut self, cx: &Cx, cancellation: &McpRequestCancellation)
        -> Result<(), CheckpointedTaskSubmissionError>
    {
        self.require_open()?;
        // Underlying custody consumes the attempt before suspension, including
        // on drop. A second send cannot replace its original cancellation/deadline.
        Ok(self.submission.send_with_cancellation(cx, cancellation).await?)
    }
    pub async fn resume(&mut self, cx: &Cx, discovery_id: RequestId, request_id: RequestId,
        responses: Option<FinalInputResponses>,
    ) -> Result<(), CheckpointedTaskSubmissionError> {
        self.require_open()?;
        Ok(self.submission.resume(cx, discovery_id, request_id, responses).await?)
    }
    pub async fn resume_partial(&mut self, cx: &Cx, discovery_id: RequestId, request_id: RequestId,
        responses: FinalInputResponses,
    ) -> Result<(), CheckpointedTaskSubmissionError> {
        self.require_open()?;
        Ok(self.submission.resume_partial(cx, discovery_id, request_id, responses).await?)
    }

    pub async fn next_event<F, E>(&mut self, cx: &Cx)
        -> Result<Option<CheckpointedTaskSubmissionEvent<E>>, CheckpointedTaskSubmissionError>
    where P: FnMut(TaskResumeInsert) -> F, F: Future<Output = Result<(), E>>,
    {
        if self.finished { return Ok(None); }
        self.require_open()?;
        if self.submission.state() != TaskSubmissionState::AwaitingResponse {
            // Preserve InputPending, unknown-delivery and phase errors. Asking
            // for another event cannot consume a still-correctable challenge.
            let _ = self.submission.next_event(cx).await?;
            return Err(CheckpointedTaskSubmissionError::Closed);
        }
        self.closed = true;
        // Copy the actual opening authority before next_event releases it at a
        // terminal response. This is not a second credential lookup. Its shared
        // revocation token, exact expiry and original deadline bound the save.
        let original = self.submission.credential.as_ref()
            .ok_or(ClientCredentialsTaskSubmissionError::InvalidState)?;
        let credential = ClientCredentialsSnapshot {
            bearer: original.bearer.clone(), scopes: original.scopes.clone(),
            expires_at: original.expires_at, generation: original.generation,
        };
        let deadline = self.submission.deadline.ok_or(ClientCredentialsTaskSubmissionError::InvalidState)?;
        let owner = self.submission.client.client.inner.closed.clone();
        let cancellation = self.submission.cancellation.clone();
        let event = self.submission.next_event(cx).await?
            .ok_or(ClientCredentialsTaskSubmissionError::InvalidState)?;
        match event {
            ClientCredentialsTaskSubmissionEvent::Notification(notification) => {
                self.closed = false;
                Ok(Some(CheckpointedTaskSubmissionEvent::Notification(notification)))
            }
            ClientCredentialsTaskSubmissionEvent::InputRequired(input) => {
                self.closed = false;
                Ok(Some(CheckpointedTaskSubmissionEvent::InputRequired(input)))
            }
            ClientCredentialsTaskSubmissionEvent::Result(result) => {
                // No fallible work or suspension between admission and custody.
                self.pending = Some(PendingClientCredentialsTaskResult::new(result));
                let pending = self.pending.as_mut().expect("admitted result retained above");
                let warning = match pending.capture(cx, &self.current, self.capture) {
                    Ok(true) => persist_pending(pending, cx, &self.current, &mut self.persist,
                        deadline, &owner, &cancellation, &credential).await,
                    Ok(false) => None,
                    Err(error) => Some(ClientCredentialsTaskPersistenceWarning::Record(error)),
                };
                let pending = self.pending.take().expect("exclusive owner retains result through save");
                self.finished = true;
                Ok(Some(CheckpointedTaskSubmissionEvent::Result(Box::new(
                    PersistedClientCredentialsTaskResult::new(pending, warning),
                ))))
            }
        }
    }

    fn require_open(&self) -> Result<(), CheckpointedTaskSubmissionError> {
        if self.closed || self.finished { return Err(CheckpointedTaskSubmissionError::Closed); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};
    use fastmcp_core::{CanonicalHttpUrl, partition::{DurableOwnerKey, PartitionDescriptor}};
    use fastmcp_protocol::{ClientCapabilities, CoreResult, FinalRequestMeta};
    use serde_json::json;
    use crate::http_auth::BoundBearerCredential;
    use crate::http_auth::discovery::client_credentials::{
        ClientCredentialsClient, ClientInner, ClientSecret, MachineAuthentication, TokenState,
    };
    use super::super::{ClientCredentialsTaskSubmissionPolicy, ClientCredentialsTaskSubmissionCause};
    use super::super::super::{ClientCredentialsTasksClient, ClientCredentialsTasksLimits, ManagedTaskEvent};

    fn submission() -> ClientCredentialsTaskSubmission {
        let client = ClientCredentialsClient { inner: Arc::new(ClientInner {
            resource: CanonicalHttpUrl::parse("https://machine.example/mcp").unwrap(),
            token_endpoint: CanonicalHttpUrl::parse("https://issuer.example/token").unwrap(),
            client_id: "checkpoint-fixture".to_owned(), scopes: vec![],
            authentication: MachineAuthentication::Basic(Arc::new(ClientSecret("fixture-secret".to_owned()))),
            issuer_roots: vec![], timeout: Duration::from_secs(5), maximum_lifetime: Duration::from_secs(600),
            leeway: Duration::from_secs(30), closed: McpRequestCancellation::new(), pending: AtomicUsize::new(0),
            state: Arc::new(asupersync::sync::Mutex::new(TokenState::default())),
        }) };
        let caps: ClientCapabilities = serde_json::from_value(json!({"roots":{}})).unwrap();
        let client = ClientCredentialsTasksClient::new(client, FinalRequestMeta::new(caps), ClientCredentialsTasksLimits::default()).unwrap();
        client.prepare_tool_submission(RequestId::Number(1), RequestId::Number(2), "compute".to_owned(),
            Some(json!({"PRIVATE-ARGUMENT":1})), ClientCredentialsTaskSubmissionPolicy::new(2, 2, 4).unwrap()).unwrap()
    }
    fn binding(resource: &str) -> TaskResumeBinding {
        let facts = PartitionDescriptor::from_verified_facts("fixture", 1, "https://issuer.example",
            resource, "tenant", "subject", "client", 1, 1, &[b"bound-resource".as_slice()]).unwrap();
        TaskResumeBinding::from_verified_owner(CanonicalHttpUrl::parse(resource).unwrap(), "checkpointed-machine",
            &DurableOwnerKey::derive(&facts, 1).unwrap(), [1; 32], [2; 32], [3; 32]).unwrap()
    }
    fn capture() -> TaskResumeCapturePolicy { TaskResumeCapturePolicy::new(Duration::from_secs(60)).unwrap() }
    type Save = fn(TaskResumeInsert) -> std::future::Ready<Result<(), ()>>;
    fn save(_: TaskResumeInsert) -> std::future::Ready<Result<(), ()>> { std::future::ready(Ok(())) }
    fn wrapped() -> CheckpointedClientCredentialsTaskSubmission<Save> {
        submission().with_initial_checkpoint(binding("https://machine.example/mcp"), capture(), save as Save).unwrap()
    }
    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("local admission must not start I/O"),
        }
    }
    fn awaiting_input(cx: &Cx) -> CheckpointedClientCredentialsTaskSubmission<Save> {
        let mut owner = wrapped();
        let submission = &mut owner.submission;
        let progress = submission.progress.as_mut().unwrap();
        let wire = json!({"resultType":"input_required","requestState":"  PRIVATE-STATE\u{0}  ",
            "inputRequests":{"one":{"method":"roots/list"},"two":{"method":"roots/list"}}});
        let CoreResult::Final(result) = progress.original.decode_result(&wire.to_string()).unwrap() else { unreachable!() };
        assert!(matches!(progress.admit(ManagedTaskEvent::ToolResult(Box::new(result))).unwrap(),
            ClientCredentialsTaskSubmissionEvent::InputRequired(_)));
        let expires_at = Instant::now() + Duration::from_secs(60);
        let bearer = BoundBearerCredential::bind_with_expiry(submission.client.client.resource().clone(),
            "fixture-token", expires_at).unwrap().for_owner(&submission.client.client.inner.closed).unwrap();
        submission.credential = Some(ClientCredentialsSnapshot { bearer, scopes: vec![], expires_at, generation: 7 });
        submission.deadline = Some(cx.now().saturating_add_nanos(5_000_000_000));
        submission.state = TaskSubmissionState::AwaitingInput;
        owner
    }

    #[test]
    fn checkpoint_attachment_is_local_and_preserves_the_exact_prepared_round() {
        let original = submission();
        let bytes = original.prepared.as_ref().unwrap().operation.wire.body().to_vec();
        let calls = Cell::new(0);
        let owner = original.with_initial_checkpoint(binding("https://machine.example/mcp"), capture(), |_| {
            calls.set(calls.get() + 1); std::future::ready(Ok::<_, ()>(()))
        }).unwrap();
        assert_eq!(owner.submission.prepared.as_ref().unwrap().operation.wire.body(), bytes);
        assert_eq!(owner.submission.progress.as_ref().unwrap().policy.maximum_records, 4);
        assert_eq!(owner.submission_state(), TaskSubmissionState::Prepared);
        assert!(owner.submission.credential.is_none() && owner.submission.deadline.is_none());
        assert!(owner.pending().is_none() && owner.pending_input().is_none());
        assert!(!format!("{owner:?}").contains("PRIVATE"));
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn checkpoint_attachment_rejects_foreign_resource_and_every_started_phase() {
        for resource in ["https://other.example/mcp", "https://machine.example/other", "https://machine.example/mcp?other"] {
            let original = submission();
            let client = original.client.clone();
            assert!(matches!(original.with_initial_checkpoint(binding(resource), capture(), save as Save),
                Err(CheckpointedTaskSubmissionError::Resume(TaskResumeError::Unavailable))));
            assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
        }
        for state in [TaskSubmissionState::NotDispatched, TaskSubmissionState::AwaitingResponse,
            TaskSubmissionState::AwaitingInput, TaskSubmissionState::DeliveryUnknown,
            TaskSubmissionState::Resolved, TaskSubmissionState::Closed] {
            let mut original = submission(); original.state = state;
            assert!(matches!(original.with_initial_checkpoint(binding("https://machine.example/mcp"), capture(), save as Save),
                Err(CheckpointedTaskSubmissionError::Submission(_))));
        }
    }

    #[test]
    fn cancelled_send_and_unpolled_futures_never_grant_a_second_attempt() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap()).build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let mut owner = wrapped();
                let cancellation = McpRequestCancellation::new(); cancellation.cancel();
                drop(owner.send_with_cancellation(&cx, &cancellation));
                drop(owner.next_event(&cx));
                assert_eq!(owner.submission_state(), TaskSubmissionState::Prepared);
                assert!(matches!(owner.next_event(&cx).await,
                    Err(CheckpointedTaskSubmissionError::Submission(ClientCredentialsTaskSubmissionError::InvalidState))));
                assert!(matches!(owner.send_with_cancellation(&cx, &cancellation).await,
                    Err(CheckpointedTaskSubmissionError::Submission(ClientCredentialsTaskSubmissionError::NotDispatched(_)))));
                let deadline = owner.submission.deadline;
                assert!(owner.send(&cx).await.is_err());
                assert_eq!(owner.submission.deadline, deadline);
                assert!(owner.submission.cancellation.is_cancel_requested());
                assert_eq!(owner.submission_state(), TaskSubmissionState::NotDispatched);
                assert!(owner.pending().is_none());
                assert!(owner.submission.client.client.inner.state.try_lock_owned().unwrap().current.is_none());
                assert!(cx.checkpoint().is_ok());
            });
    }

    #[test]
    fn input_pending_and_invalid_answers_preserve_the_same_challenge_and_budgets() {
        let cx = Cx::for_testing();
        let mut owner = awaiting_input(&cx);
        let before = owner.submission.progress.as_ref().unwrap().original.encode_params().unwrap();
        let ids = owner.submission.progress.as_ref().unwrap().used_ids.clone();
        let deadline = owner.submission.deadline;
        assert!(matches!(ready(owner.next_event(&cx)),
            Err(CheckpointedTaskSubmissionError::Submission(ClientCredentialsTaskSubmissionError::InputPending))));
        for value in [json!({}), json!({"other":{"roots":[]}}), json!({"one":{"action":"decline"}})] {
            let responses = serde_json::from_value(value).unwrap();
            assert!(matches!(ready(owner.resume_partial(&cx, RequestId::Number(3), RequestId::Number(4), responses)),
                Err(CheckpointedTaskSubmissionError::Submission(ClientCredentialsTaskSubmissionError::NotDispatched(_)))));
            let progress = owner.submission.progress.as_ref().unwrap();
            assert_eq!((progress.continuations, progress.responses, progress.records), (0, 0, 1));
            assert_eq!(progress.used_ids, ids);
            assert_eq!(progress.original.encode_params().unwrap(), before);
            assert_eq!(owner.pending_input().unwrap().request_state(), Some("  PRIVATE-STATE\u{0}  "));
            assert_eq!(owner.submission_state(), TaskSubmissionState::AwaitingInput);
            assert_eq!(owner.submission.deadline, deadline);
            assert!(owner.pending().is_none());
        }
        let responses = serde_json::from_value(json!({"one":{"roots":[]},"two":{"roots":[]}})).unwrap();
        let error = ready(owner.resume(&cx, RequestId::Number(3), RequestId::Number(2), Some(responses))).unwrap_err();
        assert!(matches!(error, CheckpointedTaskSubmissionError::Submission(ClientCredentialsTaskSubmissionError::NotDispatched(cause))
            if matches!(*cause, ClientCredentialsTaskSubmissionCause::Input(_))));
        assert_eq!(owner.submission_state(), TaskSubmissionState::AwaitingInput);
    }

    #[test]
    fn input_expiry_and_close_do_not_clear_uncertain_delivery_or_create_a_checkpoint() {
        let cx = Cx::for_testing();
        let mut owner = awaiting_input(&cx);
        owner.submission.credential.as_mut().unwrap().expires_at = Instant::now();
        let error = ready(owner.resume(&cx, RequestId::Number(3), RequestId::Number(4), None)).unwrap_err();
        assert!(matches!(error, CheckpointedTaskSubmissionError::Submission(ClientCredentialsTaskSubmissionError::NotDispatched(_))));
        assert_eq!(owner.submission_state(), TaskSubmissionState::Closed);
        assert!(owner.pending_input().is_none() && owner.pending().is_none());
        let mut owner = wrapped();
        owner.submission.state = TaskSubmissionState::DeliveryUnknown;
        owner.close();
        assert_eq!(owner.submission_state(), TaskSubmissionState::DeliveryUnknown);
        assert!(ready(owner.send(&cx)).is_err());
        assert!(owner.take_pending().is_none());
    }
}
