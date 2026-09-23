//! Caller-owned machine tool submission with initial Task checkpoint custody.
//!
//! A creating call and its local checkpoint are not one transaction. Preserve
//! the fully admitted result BEFORE capture or persistence, and return it with
//! a separate warning if saving fails. Lost creating replies remain uncertain;
//! neither failure is permission to repeat tools/call. No call is retried here.

use std::fmt;
use std::future::Future;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{FinalCoreResult, RequestId, ServerNotification};
use fastmcp_protocol::tasks_extension::Task;
use serde_json::Value;

use super::{
    ClientCredentialsError, ClientCredentialsSnapshot, ClientCredentialsTaskCall,
    ClientCredentialsTasksClient, ClientCredentialsTasksError, ManagedTaskEvent,
    ManagedTaskRequest, ManagedTasksError, PreparedRound, active, discovery_deadline,
};
pub use crate::http_auth::managed::tasks::watch::checkpoint::resume::{
    TaskResumeBinding, TaskResumeError, TaskResumeRecord,
};
pub use crate::http_auth::managed::tasks::watch::checkpoint::resume::client::{
    creation::{TaskResumeCapturePolicy, TaskResumeInsert},
    lifecycle::TaskResumePersistenceState,
};

/// What has been observed about the creating request, not checkpoint durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCredentialsTaskCreationState {
    /// Local preflight only; send has not entered the acquisition/request round.
    Prepared,
    /// The round started, but no response head was returned. It may have sent
    /// the tool request. Even failed discovery is conservatively included.
    Unconfirmed,
    /// The response head arrived, but no complete final result was admitted.
    /// A closed/abandoned owner cannot resume this response or repeat the call.
    AwaitingResponse,
    /// A complete tool result was admitted. This includes ordinary and core
    /// input-required results; it does not imply that a Task was created/saved.
    Resolved,
}

#[derive(Debug)]
pub enum ClientCredentialsTaskCreationError {
    Task(ClientCredentialsTasksError),
    Resume(TaskResumeError),
    NotSent,
    AlreadyAttempted,
    Closed,
}
impl fmt::Display for ClientCredentialsTaskCreationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Task(error) => error.fmt(f),
            Self::Resume(error) => error.fmt(f),
            Self::NotSent => f.write_str("machine Task submission has not been sent"),
            Self::AlreadyAttempted => f.write_str("machine Task submission was already attempted; do not replay"),
            Self::Closed => f.write_str("machine Task submission is closed"),
        }
    }
}
impl std::error::Error for ClientCredentialsTaskCreationError {}
impl From<ClientCredentialsTasksError> for ClientCredentialsTaskCreationError {
    fn from(error: ClientCredentialsTasksError) -> Self { Self::Task(error) }
}
impl From<ClientCredentialsError> for ClientCredentialsTaskCreationError {
    fn from(error: ClientCredentialsError) -> Self { Self::Task(error.into()) }
}
impl From<ManagedTasksError> for ClientCredentialsTaskCreationError {
    fn from(error: ManagedTasksError) -> Self { Self::Task(error.into()) }
}
impl From<TaskResumeError> for ClientCredentialsTaskCreationError {
    fn from(error: TaskResumeError) -> Self { Self::Resume(error) }
}

/// A known result accompanies this warning. No warning variant means unknown
/// creation or authorizes another tool request. Host errors are not formatted.
pub enum ClientCredentialsTaskPersistenceWarning<E> {
    Record(TaskResumeError),
    Authentication(ClientCredentialsError),
    Persistence(E),
}
impl<E> fmt::Debug for ClientCredentialsTaskPersistenceWarning<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record(error) => f.debug_tuple("Record").field(error).finish(),
            Self::Authentication(error) => f.debug_tuple("Authentication").field(error).finish(),
            Self::Persistence(_) => f.write_str("Persistence(<host error>)"),
        }
    }
}
impl<E> fmt::Display for ClientCredentialsTaskPersistenceWarning<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("machine Task result is available but checkpoint persistence needs attention; do not repeat creation")
    }
}
impl<E: std::error::Error + 'static> std::error::Error for ClientCredentialsTaskPersistenceWarning<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Record(error) => Some(error), Self::Authentication(error) => Some(error),
            Self::Persistence(error) => Some(error),
        }
    }
}

/// Application-result custody is separate from payload-free checkpoint controls.
/// This value remains on the owner when a polled persistence future is dropped.
/// Its last published state is evidence, not a fresh storage probe/retry permit.
pub struct PendingClientCredentialsTaskResult {
    result: Box<FinalCoreResult>,
    insert: Option<TaskResumeInsert>,
    persistence: TaskResumePersistenceState,
}
impl PendingClientCredentialsTaskResult {
    pub(super) fn new(result: Box<FinalCoreResult>) -> Self {
        Self { result, insert: None, persistence: TaskResumePersistenceState::NotAttempted }
    }
    pub fn result(&self) -> &FinalCoreResult { &self.result }
    pub fn record(&self) -> Option<&TaskResumeRecord> { self.insert.as_ref().map(TaskResumeInsert::record) }
    pub fn persistence(&self) -> TaskResumePersistenceState { self.persistence }
    pub fn into_parts(self) -> (Box<FinalCoreResult>, Option<TaskResumeInsert>, TaskResumePersistenceState) {
        (self.result, self.insert, self.persistence)
    }

    pub(super) fn capture(&mut self, cx: &Cx, current: &TaskResumeBinding, policy: TaskResumeCapturePolicy)
        -> Result<bool, TaskResumeError>
    {
        let FinalCoreResult::ToolsCallTask { result, .. } = &*self.result else { return Ok(false); };
        if matches!(&result.task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
            return Ok(false);
        }
        self.insert = Some(TaskResumeInsert::capture(cx, current, &result.task, policy)?);
        Ok(true)
    }
}
impl fmt::Debug for PendingClientCredentialsTaskResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingClientCredentialsTaskResult")
            .field("persistence", &self.persistence).finish_non_exhaustive()
    }
}

/// A storage failure is delivered WITH the actual validated protocol result.
/// Ordinary results, core input-required results, and already-terminal Tasks
/// have no checkpoint. They are never coerced into a newly created live Task.
pub struct PersistedClientCredentialsTaskResult<E> {
    pending: PendingClientCredentialsTaskResult,
    warning: Option<ClientCredentialsTaskPersistenceWarning<E>>,
}
impl<E> PersistedClientCredentialsTaskResult<E> {
    pub(super) fn new(pending: PendingClientCredentialsTaskResult, warning: Option<ClientCredentialsTaskPersistenceWarning<E>>) -> Self {
        Self { pending, warning }
    }
    pub fn result(&self) -> &FinalCoreResult { self.pending.result() }
    pub fn record(&self) -> Option<&TaskResumeRecord> { self.pending.record() }
    pub fn persistence(&self) -> TaskResumePersistenceState { self.pending.persistence() }
    pub fn warning(&self) -> Option<&ClientCredentialsTaskPersistenceWarning<E>> { self.warning.as_ref() }
    pub fn into_parts(self) -> (PendingClientCredentialsTaskResult, Option<ClientCredentialsTaskPersistenceWarning<E>>) {
        (self.pending, self.warning)
    }
}
impl<E> fmt::Debug for PersistedClientCredentialsTaskResult<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistedClientCredentialsTaskResult")
            .field("persistence", &self.persistence()).field("has_warning", &self.warning.is_some())
            .finish_non_exhaustive()
    }
}

pub enum PersistedClientCredentialsTaskSubmissionEvent<E> {
    Notification(Box<ServerNotification>),
    Result(Box<PersistedClientCredentialsTaskResult<E>>),
}

impl ClientCredentialsTasksClient {
    /// Prepare one eligible tool call without a grant, network or storage effect.
    /// Validate the entire discovery/operation round, not just the arguments.
    /// The host independently binds current to THIS registration and resource;
    /// records never select an identity, and no Task preference is sent.
    ///
    /// persist must perform an INSERT ONLY and acknowledge durable completion.
    /// TaskResumeInsert::apply supplies that operation for the existing Linux
    /// protected store. Run blocking work in a caller-owned joined lane; no key,
    /// store, worker, runtime or plaintext fallback is installed by this method.
    ///
    /// The result union stays intact. A core input_required reply is returned as
    /// such and is NOT automatically resumed. This owner sends one tools/call;
    /// it does not implement continuation execution or a mutation-recovery log.
    /// For explicit core-input continuations followed by checkpoint capture,
    /// prepare_tool_submission(...).with_initial_checkpoint(...) retains the
    /// existing continuation engine and its cumulative limits through saving.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_tool_submission_persisted<P, F, E>(
        &self, discovery_id: RequestId, request_id: RequestId, name: String,
        arguments: Option<Value>, current: TaskResumeBinding, capture: TaskResumeCapturePolicy,
        persist: P,
    ) -> Result<PersistedClientCredentialsTaskSubmission<P>, ClientCredentialsTaskCreationError>
    where P: FnMut(TaskResumeInsert) -> F, F: Future<Output = Result<(), E>>,
    {
        if current.resource().as_str() != self.client.resource().as_str() {
            return Err(TaskResumeError::Unavailable.into());
        }
        let round = self.prepare_round(discovery_id, request_id.clone(), ManagedTaskRequest::CallTool { name, arguments })?;
        Ok(PersistedClientCredentialsTaskSubmission {
            client: self.clone(), current, capture, persist, request_id, round: Some(round),
            call: None, pending: None, state: ClientCredentialsTaskCreationState::Prepared,
            closed: false, finished: false,
        })
    }
}

/// Exactly one creating exchange and, only for an admitted nonterminal Task,
/// one initial checkpoint insertion. send starts the deadline; notifications,
/// caller pauses and persistence consume that same budget. The opening token
/// remains pinned through saving; failure cannot silently renew its authority.
///
/// Dropping a polled send/read/save permanently closes that operation. During
/// a save, the already-admitted result stays in pending(). No unknown delivery,
/// close, cancellation or storage error installs a retry or remote cancellation.
#[must_use = "retain known Task results and inspect their persistence disposition"]
pub struct PersistedClientCredentialsTaskSubmission<P> {
    client: ClientCredentialsTasksClient,
    current: TaskResumeBinding,
    capture: TaskResumeCapturePolicy,
    persist: P,
    request_id: RequestId,
    round: Option<PreparedRound>,
    call: Option<ClientCredentialsTaskCall>,
    pending: Option<PendingClientCredentialsTaskResult>,
    state: ClientCredentialsTaskCreationState,
    closed: bool,
    finished: bool,
}
impl<P> fmt::Debug for PersistedClientCredentialsTaskSubmission<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistedClientCredentialsTaskSubmission")
            .field("state", &self.state).field("closed", &self.closed)
            .field("has_pending_result", &self.pending.is_some()).finish_non_exhaustive()
    }
}
impl<P> PersistedClientCredentialsTaskSubmission<P> {
    pub fn submission_state(&self) -> ClientCredentialsTaskCreationState { self.state }
    pub fn request_id(&self) -> &RequestId { &self.request_id }
    pub fn pending(&self) -> Option<&PendingClientCredentialsTaskResult> { self.pending.as_ref() }
    pub fn is_finished(&self) -> bool { self.finished }
    pub fn is_closed(&self) -> bool { self.closed }
    pub fn close(&mut self) {
        self.closed = true;
        self.round = None;
        self.call = None;
    }
    /// End observation before handing out retained result/write custody. This
    /// does not reset the submission or resolve an uncertain storage outcome.
    pub fn take_pending(&mut self) -> Option<PendingClientCredentialsTaskResult> {
        self.close(); self.pending.take()
    }

    pub async fn send(&mut self, cx: &Cx) -> Result<(), ClientCredentialsTaskCreationError> {
        self.send_with_cancellation(cx, &McpRequestCancellation::new()).await
    }

    pub async fn send_with_cancellation(&mut self, cx: &Cx, cancellation: &McpRequestCancellation)
        -> Result<(), ClientCredentialsTaskCreationError>
    {
        if self.state != ClientCredentialsTaskCreationState::Prepared {
            return Err(ClientCredentialsTaskCreationError::AlreadyAttempted);
        }
        if self.closed { return Err(ClientCredentialsTaskCreationError::Closed); }
        self.closed = true;
        let round = self.round.take().ok_or(ClientCredentialsTaskCreationError::Closed)?;
        let deadline = discovery_deadline(cx, self.client.limits.timeout.min(self.client.client.inner.timeout))
            .map_err(ClientCredentialsError::from)?;
        self.state = ClientCredentialsTaskCreationState::Unconfirmed;
        let call = self.client.execute_round(cx, cancellation, round, deadline).await?;
        self.call = Some(call);
        self.state = ClientCredentialsTaskCreationState::AwaitingResponse;
        self.closed = false;
        Ok(())
    }

    /// Keep notifications incremental. A nonterminal Task waits for its single
    /// insert attempt; failures after result admission are warnings, not Err.
    /// A lost/invalid creating reply is still an Err with no invented Task ID.
    pub async fn next_event<F, E>(&mut self, cx: &Cx)
        -> Result<Option<PersistedClientCredentialsTaskSubmissionEvent<E>>, ClientCredentialsTaskCreationError>
    where P: FnMut(TaskResumeInsert) -> F, F: Future<Output = Result<(), E>>,
    {
        if self.finished { return Ok(None); }
        if self.closed { return Err(ClientCredentialsTaskCreationError::Closed); }
        if self.state == ClientCredentialsTaskCreationState::Prepared {
            return Err(ClientCredentialsTaskCreationError::NotSent);
        }
        self.closed = true;
        let mut call = self.call.take().ok_or(ClientCredentialsTaskCreationError::Closed)?;
        let event = call.next_event(cx).await?.ok_or(ManagedTasksError::MissingTerminal)?;
        match event {
            ManagedTaskEvent::Notification(notification) => {
                self.call = Some(call);
                self.closed = false;
                Ok(Some(PersistedClientCredentialsTaskSubmissionEvent::Notification(notification)))
            }
            ManagedTaskEvent::ToolResult(result) => {
                // No fallible step or suspension between admission and custody.
                self.state = ClientCredentialsTaskCreationState::Resolved;
                self.pending = Some(PendingClientCredentialsTaskResult::new(result));
                let captured = self.pending.as_mut().expect("result retained above")
                    .capture(cx, &self.current, self.capture);
                let warning = match captured {
                    Ok(true) => self.persist_created(cx, &call).await,
                    Ok(false) => None,
                    Err(error) => Some(ClientCredentialsTaskPersistenceWarning::Record(error)),
                };
                let pending = self.pending.take().expect("exclusive owner retains admitted result");
                self.finished = true;
                Ok(Some(PersistedClientCredentialsTaskSubmissionEvent::Result(Box::new(
                    PersistedClientCredentialsTaskResult::new(pending, warning),
                ))))
            }
            _ => Err(ManagedTasksError::InvalidResponse.into()),
        }
    }

    async fn persist_created<F, E>(&mut self, cx: &Cx, call: &ClientCredentialsTaskCall)
        -> Option<ClientCredentialsTaskPersistenceWarning<E>>
    where P: FnMut(TaskResumeInsert) -> F, F: Future<Output = Result<(), E>>,
    {
        let pending = self.pending.as_mut().expect("admitted result precedes saving");
        persist_pending(pending, cx, &self.current, &mut self.persist,
            call.deadline, &call.owner, &call.cancellation, &call.snapshot).await
    }
}

// Shared by one-shot creation and explicit core-input submissions. Neither
// caller may reacquire authority or replace the original deadline at this point.
// The admitted result stays in its owner's pending slot throughout the save.
#[allow(clippy::too_many_arguments)]
pub(super) async fn persist_pending<P, F, E>(
    pending: &mut PendingClientCredentialsTaskResult, cx: &Cx,
    current: &TaskResumeBinding, persist: &mut P, deadline: Time,
    owner: &McpRequestCancellation, cancellation: &McpRequestCancellation,
    credential: &ClientCredentialsSnapshot,
) -> Option<ClientCredentialsTaskPersistenceWarning<E>>
where P: FnMut(TaskResumeInsert) -> F, F: Future<Output = Result<(), E>>,
{
    let insert = pending.insert.as_ref().expect("capture precedes persistence").clone();
    let deadline = match insert.retention_deadline(cx, current) {
        Ok(retention) => retention.min(deadline),
        Err(error) => return Some(ClientCredentialsTaskPersistenceWarning::Record(error)),
    };
    let state = &mut pending.persistence;
    let saved = active(cx, deadline, owner, cancellation, Some(credential), async {
        Ok(persist_insert(state, persist, insert.clone()).await)
    }).await;
    match saved {
        Err(error) => return Some(ClientCredentialsTaskPersistenceWarning::Authentication(error)),
        Ok(Err(error)) => return Some(ClientCredentialsTaskPersistenceWarning::Persistence(error)),
        Ok(Ok(())) => {},
    }
    // Local expiry cannot erase the real Task or an already-admitted save.
    insert.record().admit(cx, current).err().map(ClientCredentialsTaskPersistenceWarning::Record)
}

async fn persist_insert<P, F, E>(state: &mut TaskResumePersistenceState, persist: &mut P, insert: TaskResumeInsert)
    -> Result<(), E>
where P: FnMut(TaskResumeInsert) -> F, F: Future<Output = Result<(), E>>,
{
    *state = TaskResumePersistenceState::Unconfirmed;
    let result = persist(insert).await;
    if result.is_ok() { *state = TaskResumePersistenceState::Acknowledged; }
    result
}

#[cfg(test)]
mod tests;
