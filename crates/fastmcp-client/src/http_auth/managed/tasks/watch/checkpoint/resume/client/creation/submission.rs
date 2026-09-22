//! Persist a newly created Task before publishing its normal submission result.
//!
//! The existing submission owns discovery, tool dispatch, continuations and
//! unknown delivery. This owner adds exactly one conditional persistence step
//! AFTER an actual Task result has been fully admitted. A failed save returns
//! the real result with a warning, never a creation error or a replay permit.
//! Dropping a polled save leaves that result and its write disposition here.

use std::fmt;
use std::future::Future;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    FinalCoreResult, FinalInputResponses, InputRequiredResult, RequestId, ServerNotification,
};
use fastmcp_protocol::tasks_extension::Task;
use serde_json::Value;

use crate::http_auth::managed::{OAuthSessionError, deadline_after};
use crate::http_auth::managed::tasks::{ManagedTaskRequestIds, ManagedTasksClient};
use crate::http_auth::managed::tasks::interaction::{
    ManagedTaskInteractionEvent, ManagedTaskInteractionPolicy,
};
use crate::http_auth::managed::tasks::interaction::submission::{
    ManagedTaskSubmission, ManagedTaskSubmissionError, TaskSubmissionState,
};
use super::{TaskResumeCapturePolicy, TaskResumeInsert};
use super::super::lifecycle::TaskResumePersistenceState;
use super::super::super::{TaskResumeBinding, TaskResumeError, TaskResumeRecord};

/// The Task result is known; only its local resume persistence failed or was
/// interrupted. This warning NEVER means that the creating call should repeat.
/// An error from the host is retained but not formatted automatically.
pub enum ResumePersistenceWarning<E> {
    Record(TaskResumeError),
    Session(OAuthSessionError),
    Persistence(E),
}
impl<E> fmt::Debug for ResumePersistenceWarning<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record(error) => f.debug_tuple("Record").field(error).finish(),
            Self::Session(error) => f.debug_tuple("Session").field(error).finish(),
            Self::Persistence(_) => f.write_str("Persistence(<host error>)"),
        }
    }
}
impl<E> fmt::Display for ResumePersistenceWarning<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Task result is available but resume persistence needs attention; do not repeat creation")
    }
}
impl<E: std::error::Error + 'static> std::error::Error for ResumePersistenceWarning<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Record(error) => Some(error),
            Self::Session(error) => Some(error),
            Self::Persistence(error) => Some(error),
        }
    }
}

/// Retained BEFORE a persistence callback can run or suspend. No Clone or
/// serialization is supplied for the application result. After abandonment,
/// export the record or reconcile storage explicitly; never repeat tools/call.
pub struct PendingTaskSubmissionResult {
    result: Box<FinalCoreResult>,
    insert: Option<TaskResumeInsert>,
    persistence: TaskResumePersistenceState,
}
impl PendingTaskSubmissionResult {
    pub fn result(&self) -> &FinalCoreResult { &self.result }
    pub fn record(&self) -> Option<&TaskResumeRecord> { self.insert.as_ref().map(TaskResumeInsert::record) }
    pub fn persistence(&self) -> TaskResumePersistenceState { self.persistence }
    pub fn into_parts(self) -> (Box<FinalCoreResult>, Option<TaskResumeRecord>, TaskResumePersistenceState) {
        (self.result, self.insert.map(|insert| insert.record), self.persistence)
    }

    fn capture(
        &mut self, cx: &Cx, current: &TaskResumeBinding, policy: TaskResumeCapturePolicy,
    ) -> Result<bool, TaskResumeError> {
        let FinalCoreResult::ToolsCallTask { result, .. } = &*self.result else {
            return Ok(false);
        };
        if matches!(&result.task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
            // Already-delivered terminal state needs no restart lookup hint.
            // Its application result is still returned intact to the caller.
            return Ok(false);
        }
        self.insert = Some(TaskResumeInsert::capture(cx, current, &result.task, policy)?);
        Ok(true)
    }
}
impl fmt::Debug for PendingTaskSubmissionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingTaskSubmissionResult")
            .field("persistence", &self.persistence).finish_non_exhaustive()
    }
}

/// The complete protocol result plus its separate, payload-free persistence
/// receipt. A warning is delivered WITH the real result, not in place of it.
/// Acknowledged means the host reported durable success; it is not exactly-once
/// execution or evidence that a particular key provider has been qualified.
pub struct PersistedTaskResult<E> {
    pending: PendingTaskSubmissionResult,
    warning: Option<ResumePersistenceWarning<E>>,
}
impl<E> PersistedTaskResult<E> {
    pub fn result(&self) -> &FinalCoreResult { self.pending.result() }
    pub fn record(&self) -> Option<&TaskResumeRecord> { self.pending.record() }
    pub fn persistence(&self) -> TaskResumePersistenceState { self.pending.persistence() }
    pub fn warning(&self) -> Option<&ResumePersistenceWarning<E>> { self.warning.as_ref() }
    pub fn into_parts(self) -> (PendingTaskSubmissionResult, Option<ResumePersistenceWarning<E>>) {
        (self.pending, self.warning)
    }
}
impl<E> fmt::Debug for PersistedTaskResult<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistedTaskResult")
            .field("persistence", &self.pending.persistence)
            .field("has_warning", &self.warning.is_some()).finish_non_exhaustive()
    }
}

/// Notifications and core input challenges remain incremental. Only an actual
/// nonterminal Task result triggers persistence. No Task preference is sent.
pub enum PersistedTaskSubmissionEvent<E> {
    Notification(Box<ServerNotification>),
    InputRequired(Box<InputRequiredResult>),
    Result(Box<PersistedTaskResult<E>>),
}

#[derive(Debug)]
pub enum PersistedTaskSubmissionError {
    Resume(TaskResumeError),
    Submission(ManagedTaskSubmissionError),
    Closed,
}
impl fmt::Display for PersistedTaskSubmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resume(error) => error.fmt(f),
            Self::Submission(error) => error.fmt(f),
            Self::Closed => f.write_str("persisted Task submission is closed"),
        }
    }
}
impl std::error::Error for PersistedTaskSubmissionError {}
impl From<TaskResumeError> for PersistedTaskSubmissionError {
    fn from(error: TaskResumeError) -> Self { Self::Resume(error) }
}
impl From<ManagedTaskSubmissionError> for PersistedTaskSubmissionError {
    fn from(error: ManagedTaskSubmissionError) -> Self { Self::Submission(error) }
}

impl ManagedTasksClient {
    /// Locally prepares a Task-capable tool submission with initial persistence.
    /// Current binding and capture policy precede token renewal/network effects.
    /// The host must associate that verified binding with THIS login; saved
    /// bytes never choose an account or endpoint.
    ///
    /// `persist` must conditionally insert the supplied controls and acknowledge
    /// only durable success. On Linux use TaskResumeInsert::apply in a joined,
    /// caller-owned blocking lane. No store, key, runtime or worker is installed.
    /// Application idempotency arguments and the ordinary result union stay
    /// untouched. Core input is handled by explicit resume/resume_partial.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_tool_submission_persisted<P, F, E>(
        &self,
        ids: ManagedTaskRequestIds,
        name: String,
        arguments: Option<Value>,
        policy: ManagedTaskInteractionPolicy,
        current: TaskResumeBinding,
        capture: TaskResumeCapturePolicy,
        persist: P,
    ) -> Result<PersistedTaskSubmission<P>, PersistedTaskSubmissionError>
    where
        P: FnMut(TaskResumeInsert) -> F,
        F: Future<Output = Result<(), E>>,
    {
        admit_resource(self.session.resource().as_str(), &current)?;
        let submission = self.prepare_tool_submission(ids, name, arguments, policy)?;
        Ok(PersistedTaskSubmission {
            client: self.clone(), submission, current, capture, persist,
            cancellation: McpRequestCancellation::new(), deadline: None,
            pending: None, closed: false, finished: false,
        })
    }
}

/// Adds initial storage custody to the existing non-retrying submission owner.
/// The original submission still owns wire validation, credential pinning and
/// continuation counters. This owner never recreates a call after storage error.
///
/// The original send deadline, request cancellation, session closure and record
/// retention bound persistence too. AFTER a fully admitted result, those local
/// failures become warnings accompanying that result, not unknown creation.
/// Closing/dropping before result admission still leaves the submission's usual
/// unknown-delivery disposition. Dropping while persisting retains pending().
/// Result extraction on a failed/closed owner does not resume or retry anything.
#[must_use = "retain the owner through result and persistence disposition"]
pub struct PersistedTaskSubmission<P> {
    client: ManagedTasksClient,
    submission: ManagedTaskSubmission,
    current: TaskResumeBinding,
    capture: TaskResumeCapturePolicy,
    persist: P,
    cancellation: McpRequestCancellation,
    deadline: Option<Time>,
    pending: Option<PendingTaskSubmissionResult>,
    closed: bool,
    finished: bool,
}
impl<P> fmt::Debug for PersistedTaskSubmission<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistedTaskSubmission")
            .field("submission_state", &self.submission.state())
            .field("pending_result", &self.pending.is_some())
            .field("finished", &self.finished).finish_non_exhaustive()
    }
}

impl<P> PersistedTaskSubmission<P> {
    /// Remote submission disposition; Resolved alone does NOT acknowledge a save.
    pub fn submission_state(&self) -> TaskSubmissionState { self.submission.state() }
    pub fn request_id(&self) -> &RequestId { self.submission.request_id() }
    pub fn pending_input(&self) -> Option<&InputRequiredResult> { self.submission.pending_input() }
    pub fn pending(&self) -> Option<&PendingTaskSubmissionResult> { self.pending.as_ref() }
    pub fn take_pending(&mut self) -> Option<PendingTaskSubmissionResult> { self.pending.take() }
    pub fn is_finished(&self) -> bool { self.finished }

    /// Never removes a record or cancels a remote Task. A retained known result
    /// and an unconfirmed write remain inspectable after explicit local close.
    pub fn close(&mut self) {
        self.submission.close();
        self.closed = true;
    }

    pub async fn send(&mut self, cx: &Cx) -> Result<(), PersistedTaskSubmissionError> {
        self.send_with_cancellation(cx, &McpRequestCancellation::new()).await
    }

    pub async fn send_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
    ) -> Result<(), PersistedTaskSubmissionError> {
        self.require_open()?;
        // A rejected second send must not reset the saved original deadline or
        // the cancellation domain selected by the first actual attempt.
        if self.submission.state() != TaskSubmissionState::Prepared {
            return Ok(self.submission.send_with_cancellation(cx, cancellation).await?);
        }
        self.deadline = Some(deadline_after(cx, self.client.limits.timeout)
            .map_err(|error| ManagedTaskSubmissionError::NotDispatched(Box::new(error.into())))?);
        self.cancellation = cancellation.clone();
        Ok(self.submission.send_with_cancellation(cx, cancellation).await?)
    }

    pub async fn resume(
        &mut self, cx: &Cx, ids: ManagedTaskRequestIds, responses: Option<FinalInputResponses>,
    ) -> Result<(), PersistedTaskSubmissionError> {
        self.require_open()?;
        Ok(self.submission.resume(cx, ids, responses).await?)
    }

    pub async fn resume_partial(
        &mut self, cx: &Cx, ids: ManagedTaskRequestIds, responses: FinalInputResponses,
    ) -> Result<(), PersistedTaskSubmissionError> {
        self.require_open()?;
        Ok(self.submission.resume_partial(cx, ids, responses).await?)
    }

    /// A normal nonterminal Task result waits for the one persistence attempt.
    /// Failure returns Result with ResumePersistenceWarning AND the actual Task.
    /// No save occurs for a notification, core input-required reply, ordinary
    /// tool completion, unknown Task creation or already-terminal Task result.
    pub async fn next_event<F, E>(
        &mut self, cx: &Cx,
    ) -> Result<Option<PersistedTaskSubmissionEvent<E>>, PersistedTaskSubmissionError>
    where
        P: FnMut(TaskResumeInsert) -> F,
        F: Future<Output = Result<(), E>>,
    {
        if self.finished { return Ok(None); }
        self.require_open()?;
        if self.submission.state() != TaskSubmissionState::AwaitingResponse {
            // Preserve the existing typed unknown-delivery/input-pending errors
            // and the correctable challenge. This path cannot deliver a result.
            let _ = self.submission.next_event(cx).await?;
            return Err(PersistedTaskSubmissionError::Closed);
        }
        // Retire this read/write opportunity before suspension. If the future
        // is abandoned, neither the read nor the save can be started again.
        self.closed = true;
        let event = self.submission.next_event(cx).await?
            .ok_or(PersistedTaskSubmissionError::Closed)?;
        match event {
            ManagedTaskInteractionEvent::Notification(notification) => {
                self.closed = false;
                Ok(Some(PersistedTaskSubmissionEvent::Notification(notification)))
            }
            ManagedTaskInteractionEvent::InputRequired(input) => {
                self.closed = false;
                Ok(Some(PersistedTaskSubmissionEvent::InputRequired(input)))
            }
            ManagedTaskInteractionEvent::Result(result) => {
                // No await or fallible operation precedes retaining the REAL
                // validated result. From here on, failures cannot erase its ID.
                self.pending = Some(PendingTaskSubmissionResult {
                    result, insert: None, persistence: TaskResumePersistenceState::NotAttempted,
                });
                let captured = self.pending.as_mut().expect("result retained above")
                    .capture(cx, &self.current, self.capture);
                let warning = match captured {
                    Ok(true) => self.persist_created(cx).await,
                    Ok(false) => None,
                    Err(error) => Some(ResumePersistenceWarning::Record(error)),
                };
                let pending = self.pending.take().expect("exclusive owner retains result through save");
                self.finished = true;
                Ok(Some(PersistedTaskSubmissionEvent::Result(Box::new(PersistedTaskResult { pending, warning }))))
            }
        }
    }

    async fn persist_created<F, E>(&mut self, cx: &Cx) -> Option<ResumePersistenceWarning<E>>
    where
        P: FnMut(TaskResumeInsert) -> F,
        F: Future<Output = Result<(), E>>,
    {
        let pending = self.pending.as_mut().expect("only called after result capture");
        let insert = pending.insert.as_ref().expect("only called with captured controls").clone();
        let retention_deadline = match insert.retention_deadline(cx, &self.current) {
            Ok(deadline) => deadline,
            Err(error) => return Some(ResumePersistenceWarning::Record(error)),
        };
        let deadline = retention_deadline.min(self.deadline.expect("a sent submission has a deadline"));
        let state = &mut pending.persistence;
        let persist = &mut self.persist;
        let session = self.client.session.clone();
        let cancellation = self.cancellation.clone();
        let result = Box::pin(session.await_active(cx, &cancellation, deadline, None, async {
            Ok(persist_insert(state, persist, insert.clone()).await)
        })).await;
        match result {
            Err(error) => return Some(ResumePersistenceWarning::Session(error)),
            Ok(Err(error)) => return Some(ResumePersistenceWarning::Persistence(error)),
            Ok(Ok(())) => {},
        }
        if let Err(error) = session.check(cx, &cancellation) {
            return Some(ResumePersistenceWarning::Session(error));
        }
        if cx.now() >= deadline {
            return Some(ResumePersistenceWarning::Session(OAuthSessionError::TimedOut));
        }
        insert.record().admit(cx, &self.current).err().map(ResumePersistenceWarning::Record)
    }

    fn require_open(&self) -> Result<(), PersistedTaskSubmissionError> {
        if self.closed || self.finished { return Err(PersistedTaskSubmissionError::Closed); }
        Ok(())
    }
}

fn admit_resource(resource: &str, current: &TaskResumeBinding) -> Result<(), TaskResumeError> {
    if current.resource().as_str() != resource { return Err(TaskResumeError::Unavailable); }
    Ok(())
}

async fn persist_insert<P, F, E>(
    state: &mut TaskResumePersistenceState, persist: &mut P, insert: TaskResumeInsert,
) -> Result<(), E>
where
    P: FnMut(TaskResumeInsert) -> F,
    F: Future<Output = Result<(), E>>,
{
    // Before invoking the host, including a synchronous panic/side effect.
    *state = TaskResumePersistenceState::Unconfirmed;
    let result = persist(insert).await;
    // Preserve observed success even if the enclosing lifetime guard withholds
    // publication after a ready callback closes the session or exceeds time.
    if result.is_ok() { *state = TaskResumePersistenceState::Acknowledged; }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;
    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::json;
    use crate::http_auth::managed::tasks::{ManagedTaskEvent, ManagedTaskRequest, ManagedTasksLimits, decode_result, prepare};

    fn binding() -> TaskResumeBinding {
        let descriptor = PartitionDescriptor::from_verified_facts(
            "fixture", 1, "issuer", "https://mcp.example/mcp", "tenant", "subject", "client", 1, 1, &[b"fixture"],
        ).unwrap();
        let owner = DurableOwnerKey::derive(&descriptor, 1).unwrap();
        TaskResumeBinding::from_verified_owner(CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap(),
            "creation", &owner, [1; 32], [2; 32], [3; 32]).unwrap()
    }
    fn policy() -> TaskResumeCapturePolicy { TaskResumeCapturePolicy::new(Duration::from_secs(60)).unwrap() }
    fn pending(result: Value) -> PendingTaskSubmissionResult {
        let metadata = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        let prepared = prepare("https://mcp.example/mcp", &metadata, &RequestId::Number(2),
            ManagedTaskRequest::CallTool { name: "work".to_owned(), arguments: None }, ManagedTasksLimits::default()).unwrap();
        let bytes = json!({"jsonrpc":"2.0","id":2,"result":result}).to_string();
        let ManagedTaskEvent::ToolResult(result) = decode_result(&prepared.decoder, bytes.as_bytes(),
            &RequestId::Number(2), 65536).unwrap() else { panic!("tool result required") };
        PendingTaskSubmissionResult { result, insert: None, persistence: TaskResumePersistenceState::NotAttempted }
    }
    fn created() -> Value {
        json!({"resultType":"task", "taskId":"  exact / ID  ", "status":"working",
            "createdAt":"2000-01-01T00:00:00Z", "lastUpdatedAt":"2000-01-01T00:00:01Z",
            "ttlMs":null, "statusMessage":"PRIVATE-STATUS"})
    }
    fn insert() -> TaskResumeInsert {
        let mut pending = pending(created());
        assert!(pending.capture(&Cx::for_testing(), &binding(), policy()).unwrap());
        pending.insert.take().unwrap()
    }
    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test operation must be ready"),
        }
    }

    #[test]
    fn persistence_resource_is_checked_before_submission_preparation() {
        let binding = binding();
        assert!(admit_resource("https://mcp.example/mcp", &binding).is_ok());
        for resource in ["https://other.example/mcp", "https://mcp.example/other", "https://mcp.example/mcp?tenant=other"] {
            assert_eq!(admit_resource(resource, &binding), Err(TaskResumeError::Unavailable));
        }
        assert!(admit_resource("https://mcp.example/mcp", &binding).is_ok());
    }

    #[test]
    fn actual_task_identity_survives_control_capture_without_application_payload() {
        let mut value = pending(created());
        assert!(value.capture(&Cx::for_testing(), &binding(), policy()).unwrap());
        let record = value.record().unwrap();
        assert_eq!(record.task_id().as_str(), "  exact / ID  ");
        let bytes = record.encode().unwrap();
        assert!(!bytes.windows(7).any(|window| window == b"PRIVATE"));
        assert!(matches!(value.result(), FinalCoreResult::ToolsCallTask { result, .. }
            if result.task.base().status_message.as_deref() == Some("PRIVATE-STATUS")));
        assert_eq!(value.persistence(), TaskResumePersistenceState::NotAttempted);
    }

    #[test]
    fn ordinary_and_already_terminal_results_do_not_create_resume_records() {
        let mut terminal = created();
        terminal["status"] = json!("cancelled");
        for result in [json!({"resultType":"complete", "content":[], "isError":true}), terminal] {
            let mut pending = pending(result);
            assert!(!pending.capture(&Cx::for_testing(), &binding(), policy()).unwrap());
            assert!(pending.record().is_none());
        }
    }

    #[test]
    fn failed_record_capture_does_not_erase_the_validated_task_result() {
        let mut task = created();
        task["ttlMs"] = json!(1);
        task["lastUpdatedAt"] = task["createdAt"].clone();
        let mut pending = pending(task);
        assert!(pending.capture(&Cx::for_testing(), &binding(), policy()).is_err());
        assert!(pending.record().is_none());
        assert!(matches!(pending.result(), FinalCoreResult::ToolsCallTask { .. }));
    }

    #[test]
    fn save_success_and_failure_keep_distinct_persistence_dispositions() {
        for success in [true, false] {
            let calls = Cell::new(0);
            let mut state = TaskResumePersistenceState::NotAttempted;
            let mut save = |command: TaskResumeInsert| {
                calls.set(calls.get() + 1);
                assert_eq!(command.record().task_id().as_str(), "  exact / ID  ");
                std::future::ready(if success { Ok(()) } else { Err("host failure") })
            };
            assert_eq!(ready(persist_insert(&mut state, &mut save, insert())).is_ok(), success);
            assert_eq!(calls.get(), 1);
            assert_eq!(state, if success { TaskResumePersistenceState::Acknowledged } else { TaskResumePersistenceState::Unconfirmed });
        }
    }

    #[test]
    fn abandoned_save_retains_unconfirmed_state_and_drops_the_owned_future() {
        struct Pending<'a>(&'a Cell<bool>);
        impl Future for Pending<'_> {
            type Output = Result<(), ()>;
            fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> { Poll::Pending }
        }
        impl Drop for Pending<'_> { fn drop(&mut self) { self.0.set(true); } }
        let dropped = Cell::new(false);
        let mut state = TaskResumePersistenceState::NotAttempted;
        let mut save = |_| Pending(&dropped);
        let mut saving = Box::pin(persist_insert(&mut state, &mut save, insert()));
        assert!(saving.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        drop(saving);
        assert!(dropped.get());
        assert_eq!(state, TaskResumePersistenceState::Unconfirmed);
    }

    #[test]
    fn pending_result_extraction_preserves_the_task_and_original_record() {
        let mut value = pending(created());
        value.capture(&Cx::for_testing(), &binding(), policy()).unwrap();
        let encoded = value.record().unwrap().encode().unwrap();
        value.persistence = TaskResumePersistenceState::Unconfirmed;
        let (task, record, state) = value.into_parts();
        assert!(matches!(*task, FinalCoreResult::ToolsCallTask { .. }));
        assert_eq!(record.unwrap().encode().unwrap(), encoded);
        assert_eq!(state, TaskResumePersistenceState::Unconfirmed);
    }

    #[test]
    fn persistence_diagnostics_do_not_format_host_secrets() {
        let warning = ResumePersistenceWarning::Persistence("PRIVATE-PATH-AND-KEY");
        assert!(!format!("{warning:?} {warning}").contains("PRIVATE"));
        let value = pending(created());
        assert!(!format!("{value:?}").contains("exact / ID"));
        assert!(!format!("{:?}", insert()).contains("exact / ID"));
    }
}
