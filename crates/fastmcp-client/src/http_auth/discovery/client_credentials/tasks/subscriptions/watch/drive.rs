//! Explicit host input resolution while a machine Task is watched.
//!
//! Notifications drive observation. An acknowledged local input update is
//! followed by one immediate reconciliation get: a partial answer need not
//! change Task status or cause a notification. No failed POST is ever retried.
//! The owned driver exposes explicit cancellation and retains update receipts
//! after errors, cancellation, close or abandonment of a polled drive future.
//! Opt-in bounded observation recovery retains input history and the original
//! credential. It never retries an update whose acknowledgement was not read.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::{McpRequestCancellation, sha256_bounded};
use fastmcp_protocol::tasks_extension::{Task, TaskId, TaskInputLedger, TaskInputRequests, TaskInputResponses};
use fastmcp_protocol::{FinalEmbeddedElicitationParams, FinalEmbeddedInputRequest, RequestId, FINAL_CLIENT_CAPABILITIES_META_KEY};

use super::{
    BoundedBody, ClientCredentialsError, ClientCredentialsSnapshot, ClientCredentialsTaskWatch,
    ClientCredentialsTaskWatchError, ClientCredentialsTaskWatchPolicy,
    ClientCredentialsTasksClient, ClientCredentialsTasksError,
    ManagedTaskEvent, ManagedTaskRequest, ManagedTasksError, WatchState, active, check_watch,
    copy_binding, discovery_deadline, prepare_pinned, request_pinned,
};
use super::cancellation::{
    CancellableClientCredentialsTaskWatchError, ClientCredentialsTaskCancelHandle,
};
use super::recovery::{
    ClientCredentialsTaskRecoveryError, ClientCredentialsTaskRecoveryPolicy, RecoveryState,
};
pub use crate::http_auth::discovery::client_credentials::tasks::driver::{
    ClientCredentialsTaskWaitError, ManagedTaskInputAction, ManagedTaskRunOutcome,
};
pub use crate::http_auth::managed::tasks::watch::drive::TaskInputUpdateState;

/// Explicit input authority in addition to the watch's finite lifetime and
/// snapshot/record budgets. Zero updates selects observation only. Input bytes
/// bound each serialized descriptor map and the retained key/digest history;
/// the lifetime key count separately bounds collection overhead.
#[derive(Clone, Copy, Debug)]
pub struct ClientCredentialsTaskWatchDrivePolicy {
    watch: ClientCredentialsTaskWatchPolicy,
    maximum_updates: usize,
    maximum_input_keys: usize,
    maximum_input_bytes: usize,
    recovery: Option<ClientCredentialsTaskRecoveryPolicy>,
}
impl Default for ClientCredentialsTaskWatchDrivePolicy {
    fn default() -> Self {
        Self { watch: ClientCredentialsTaskWatchPolicy::default(), maximum_updates: 32,
            maximum_input_keys: 256, maximum_input_bytes: 1024 * 1024, recovery: None }
    }
}
impl ClientCredentialsTaskWatchDrivePolicy {
    pub fn new(
        watch: ClientCredentialsTaskWatchPolicy, maximum_updates: usize,
        maximum_input_keys: usize, maximum_input_bytes: usize,
    ) -> Result<Self, ClientCredentialsTaskWatchDriveError> {
        if maximum_updates > 128 || maximum_input_keys > 4096
            || !(1..=4 * 1024 * 1024).contains(&maximum_input_bytes)
        { return Err(ClientCredentialsTaskWaitError::InvalidPolicy.into()); }
        Ok(Self { watch, maximum_updates, maximum_input_keys, maximum_input_bytes, recovery: None })
    }

    /// Recover ended observation streams, including a reconciliation read after
    /// an admitted update ACK. Retain the same input history, update receipts,
    /// request identity sequence, snapshot budget and absolute deadline.
    ///
    /// The listen record budget is divided across the initial connection and
    /// every allowed reconnect, with at least two records per connection.
    /// Unlike observation-only recovery, input execution NEVER renews its
    /// credential. Expiry, revocation, failed mutations, malformed responses,
    /// HTTP refusals and ambiguous transport errors remain terminal.
    pub fn with_recovery(
        mut self,
        recovery: ClientCredentialsTaskRecoveryPolicy,
    ) -> Result<Self, ClientCredentialsTaskWatchDriveError> {
        self.recovery = Some(recovery);
        self.connection_policy()?;
        Ok(self)
    }

    fn connection_policy(self) -> Result<ClientCredentialsTaskWatchPolicy, ClientCredentialsTaskWatchDriveError> {
        match self.recovery {
            Some(recovery) => Ok(recovery.connection_policy(self.watch)?),
            None => Ok(self.watch),
        }
    }
}

/// Diagnostics retain no raw responses, host error text, credentials or input
/// answers. An acknowledged cancellation is not a terminal or rollback receipt.
#[derive(Debug)]
pub enum ClientCredentialsTaskWatchDriveError {
    Watch(ClientCredentialsTaskWatchError),
    Input(ClientCredentialsTaskWaitError),
    Recovery(ClientCredentialsTaskRecoveryError),
    CancellationRequested,
}
impl fmt::Display for ClientCredentialsTaskWatchDriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Watch(error) => error.fmt(f),
            Self::Input(error) => error.fmt(f),
            Self::Recovery(error) => error.fmt(f),
            Self::CancellationRequested => f.write_str("machine Task cancellation acknowledged; input driver stopped"),
        }
    }
}
impl std::error::Error for ClientCredentialsTaskWatchDriveError {}
impl From<ClientCredentialsTaskWatchError> for ClientCredentialsTaskWatchDriveError {
    fn from(error: ClientCredentialsTaskWatchError) -> Self { Self::Watch(error) }
}
impl From<ClientCredentialsTaskWaitError> for ClientCredentialsTaskWatchDriveError {
    fn from(error: ClientCredentialsTaskWaitError) -> Self { Self::Input(error) }
}
impl From<ClientCredentialsTasksError> for ClientCredentialsTaskWatchDriveError {
    fn from(error: ClientCredentialsTasksError) -> Self { Self::Watch(error.into()) }
}
impl From<ClientCredentialsError> for ClientCredentialsTaskWatchDriveError {
    fn from(error: ClientCredentialsError) -> Self { Self::Watch(error.into()) }
}
impl From<ManagedTasksError> for ClientCredentialsTaskWatchDriveError {
    fn from(error: ManagedTasksError) -> Self { Self::Watch(error.into()) }
}
impl From<ClientCredentialsTaskRecoveryError> for ClientCredentialsTaskWatchDriveError {
    fn from(error: ClientCredentialsTaskRecoveryError) -> Self {
        match error {
            ClientCredentialsTaskRecoveryError::Watch(error) => Self::Watch(error),
            error => Self::Recovery(error),
        }
    }
}
impl From<CancellableClientCredentialsTaskWatchError> for ClientCredentialsTaskWatchDriveError {
    fn from(error: CancellableClientCredentialsTaskWatchError) -> Self {
        match error {
            CancellableClientCredentialsTaskWatchError::CancellationRequested => Self::CancellationRequested,
            CancellableClientCredentialsTaskWatchError::Closed => ClientCredentialsTaskWatchError::Closed.into(),
            CancellableClientCredentialsTaskWatchError::Watch(error) => error.into(),
        }
    }
}

#[derive(Default)]
struct UpdateProgress {
    state: TaskInputUpdateState,
    acknowledged: usize,
    request_id: Option<RequestId>,
}
impl UpdateProgress {
    fn begin(&mut self, id: RequestId, maximum: usize) -> Result<(), ClientCredentialsTaskWaitError> {
        if self.state == TaskInputUpdateState::Unconfirmed {
            return Err(ClientCredentialsTaskWaitError::UnexpectedResponse);
        }
        if self.acknowledged >= maximum { return Err(ClientCredentialsTaskWaitError::UpdateLimit); }
        self.request_id = Some(id);
        self.state = TaskInputUpdateState::Unconfirmed;
        Ok(())
    }
    fn acknowledge(&mut self) -> Result<(), ClientCredentialsTaskWaitError> {
        if self.state != TaskInputUpdateState::Unconfirmed {
            return Err(ClientCredentialsTaskWaitError::UnexpectedResponse);
        }
        // The admitted drive policy bounds this counter to at most 128.
        self.acknowledged += 1;
        self.state = TaskInputUpdateState::Acknowledged;
        Ok(())
    }
}

impl ClientCredentialsTasksClient {
    /// Observes an existing Task and resolves input only through the supplied
    /// host callback. A resolver may return a nonempty subset of the unresolved
    /// keys, or return control to the caller without an update. Advertised
    /// roots/sampling/elicitation capabilities gate every resolver invocation.
    /// No implicit model, browser, filesystem access or Task creation occurs.
    ///
    /// This convenience runs the same owned driver as `watch_task_inputs`.
    /// Use that constructor to retain update disposition and obtain an explicit
    /// remote-cancel handle. Without using the handle no remote cancel is sent.
    /// Successfully acknowledged keys are never answered twice in this run.
    /// Reusing any observed key with a changed descriptor is rejected. The
    /// in-memory ledger is not permission to replay after a lost update reply.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task_watching<R, F, O>(
        &self, cx: &Cx, task_id: TaskId, id_prefix: String,
        policy: ClientCredentialsTaskWatchDrivePolicy, resolve: R, observe: O,
    ) -> Result<ManagedTaskRunOutcome, ClientCredentialsTaskWatchDriveError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ClientCredentialsTaskWatchDriveError>>,
        O: FnMut(&Task) -> Result<(), ClientCredentialsTaskWatchDriveError>,
    {
        self.drive_task_watching_with_cancellation(cx, &McpRequestCancellation::new(),
            task_id, id_prefix, policy, resolve, observe).await
    }

    /// Local cancellation drops pending resolver/network work without cancelling
    /// the remote Task or sibling calls. Errors after an update may follow a
    /// remote effect; they are not permission to retry it. Synchronous callbacks
    /// must return promptly and cooperate with the host.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task_watching_with_cancellation<R, F, O>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, task_id: TaskId,
        id_prefix: String, policy: ClientCredentialsTaskWatchDrivePolicy, resolve: R, observe: O,
    ) -> Result<ManagedTaskRunOutcome, ClientCredentialsTaskWatchDriveError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ClientCredentialsTaskWatchDriveError>>,
        O: FnMut(&Task) -> Result<(), ClientCredentialsTaskWatchDriveError>,
    {
        let mut driver = self.watch_task_inputs_with_cancellation(
            cx, cancellation, task_id, id_prefix, policy,
        ).await?;
        Box::pin(driver.drive(cx, resolve, observe)).await
    }

    /// Admit one Task's input driver before reading a snapshot or invoking host
    /// code. Its cancel handle can interrupt a pending resolver, get or update
    /// response. Admission, caller pauses and execution share one finite
    /// deadline and the exact credential that acknowledged the subscription.
    /// Reconnection is opt-in through the drive policy; credential renewal,
    /// Task creation and mutation replay are never implicit.
    pub async fn watch_task_inputs(
        &self, cx: &Cx, task_id: TaskId, id_prefix: String,
        policy: ClientCredentialsTaskWatchDrivePolicy,
    ) -> Result<ClientCredentialsTaskWatchDriver, ClientCredentialsTaskWatchDriveError> {
        self.watch_task_inputs_with_cancellation(cx, &McpRequestCancellation::new(),
            task_id, id_prefix, policy).await
    }

    /// Retain the caller's cancellation domain without taking authority to
    /// cancel it. Validate selection, identifiers and cancel encoding before
    /// acquisition or network work. Expired input authority is never renewed.
    pub async fn watch_task_inputs_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, task_id: TaskId,
        id_prefix: String, policy: ClientCredentialsTaskWatchDrivePolicy,
    ) -> Result<ClientCredentialsTaskWatchDriver, ClientCredentialsTaskWatchDriveError> {
        let connection_policy = policy.connection_policy()?;
        let _ = WatchState::new(vec![task_id.clone()], policy.watch.maximum_snapshots)?;
        let deadline = discovery_deadline(cx, policy.watch.timeout).map_err(ClientCredentialsError::from)?;
        let mut remote_cancel = ClientCredentialsTaskCancelHandle::for_observation(
            self, task_id.clone(), &id_prefix, cancellation, deadline,
        )?;
        let owner = &self.client.inner.closed;
        let mut watch = Box::pin(active(cx, deadline, owner, cancellation, None, async {
            Ok(self.watch_tasks_with_cancellation(cx, cancellation,
                vec![task_id], id_prefix, connection_policy).await)
        })).await??;
        watch.deadline = watch.deadline.min(deadline);
        check_watch(cx, watch.deadline, owner, cancellation, &watch.binding)?;
        let binding = copy_binding(&watch.binding);
        remote_cancel.pin_binding(copy_binding(&binding), watch.deadline)?;
        let recovery = policy.recovery.map(|policy| RecoveryState::new(&watch, connection_policy, policy));
        Ok(ClientCredentialsTaskWatchDriver {
            client: self.clone(), cancellation: cancellation.clone(), deadline: watch.deadline,
            policy, binding: Some(binding), watch: Some(watch), remote_cancel,
            progress: UpdateProgress::default(), recovery,
        })
    }
}

/// One-shot, caller-owned input execution with inspectable mutation evidence.
///
/// A polled drive takes transport custody before suspension. Dropping it closes
/// observation and future cancellation admission, including during host input
/// or an update reply. Unpolled futures have no effect. ReturnToCaller ends this
/// run; it does not restore an old challenge as retry authority. Close and drop
/// never automatically cancel the remote Task or the shared machine client.
///
/// CancellationRequested means a cancel ACK was validated, not that an update
/// rolled back or a Task is terminal. Inspect update_state after interruption:
/// the last update can be Unconfirmed even when cancellation is Acknowledged.
/// This is process-local evidence, not durable mutation recovery.
#[must_use = "retain the input driver to control cancellation and inspect update disposition"]
pub struct ClientCredentialsTaskWatchDriver {
    client: ClientCredentialsTasksClient,
    cancellation: McpRequestCancellation,
    deadline: Time,
    policy: ClientCredentialsTaskWatchDrivePolicy,
    binding: Option<ClientCredentialsSnapshot>,
    watch: Option<ClientCredentialsTaskWatch>,
    remote_cancel: ClientCredentialsTaskCancelHandle,
    progress: UpdateProgress,
    recovery: Option<RecoveryState>,
}
impl ClientCredentialsTaskWatchDriver {
    pub fn cancel_handle(&self) -> ClientCredentialsTaskCancelHandle { self.remote_cancel.clone() }
    pub fn update_state(&self) -> TaskInputUpdateState { self.progress.state }
    pub fn acknowledged_updates(&self) -> usize { self.progress.acknowledged }
    /// Includes failed replacement admissions and remains available after
    /// cancellation, close or abandonment. An unpolled drive spends nothing.
    pub fn reconnection_attempts(&self) -> usize {
        self.recovery.as_ref().map_or(0, RecoveryState::reconnection_attempts)
    }
    /// Correlation only, never an idempotency key or remote rollback evidence.
    pub fn last_update_request_id(&self) -> Option<&RequestId> { self.progress.request_id.as_ref() }
    pub fn close(&mut self) {
        self.remote_cancel.close_observation();
        self.watch = None;
        self.binding = None;
    }

    /// Run once. A validated remote cancel ACK wakes owned pending work; a
    /// failed attempt does not. Checks surround host callbacks and precede
    /// mutations. Completed synchronous host side effects cannot be recalled.
    pub async fn drive<R, F, O>(
        &mut self, cx: &Cx, mut resolve: R, mut observe: O,
    ) -> Result<ManagedTaskRunOutcome, ClientCredentialsTaskWatchDriveError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ClientCredentialsTaskWatchDriveError>>,
        O: FnMut(&Task) -> Result<(), ClientCredentialsTaskWatchDriveError>,
    {
        if self.remote_cancel.cancellation_requested() {
            self.close();
            return Err(ClientCredentialsTaskWatchDriveError::CancellationRequested);
        }
        let mut watch = self.watch.take().ok_or(ClientCredentialsTaskWatchError::Closed)?;
        let remote = self.remote_cancel.clone();
        // Always armed: completion, handoff, error and abandonment all end this
        // one-shot owner. UpdateProgress stays on self for later inspection.
        let _lease = remote.read_lease();
        let binding = self.binding.take().ok_or(ClientCredentialsTaskWatchError::Closed)?;
        let client = self.client.clone();
        let cancellation = self.cancellation.clone();
        let deadline = self.deadline;
        let running = Box::pin(active(cx, deadline, &client.client.inner.closed,
            &cancellation, Some(&binding), async {
                Ok(self.drive_active(cx, &mut watch, &binding, &mut resolve, &mut observe).await)
            }));
        remote.until_acknowledged(running).await??
    }

    fn check(&self, cx: &Cx, binding: &ClientCredentialsSnapshot) -> Result<(), ClientCredentialsTaskWatchDriveError> {
        if self.remote_cancel.cancellation_requested() {
            return Err(ClientCredentialsTaskWatchDriveError::CancellationRequested);
        }
        check_watch(cx, self.deadline, &self.client.client.inner.closed, &self.cancellation, binding)?;
        Ok(())
    }

    async fn drive_active<R, F, O>(
        &mut self, cx: &Cx, watch: &mut ClientCredentialsTaskWatch, binding: &ClientCredentialsSnapshot,
        resolve: &mut R, observe: &mut O,
    ) -> Result<ManagedTaskRunOutcome, ClientCredentialsTaskWatchDriveError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ClientCredentialsTaskWatchDriveError>>,
        O: FnMut(&Task) -> Result<(), ClientCredentialsTaskWatchDriveError>,
    {
        let client = self.client.clone();
        let cancellation = self.cancellation.clone();
        let deadline = self.deadline;
        let policy = self.policy;
        let task_id = watch.state.task_ids[0].clone();
        let mut ledger = InputHistory::default();
        let mut reconciled = None;
        loop {
            self.check(cx, binding)?;
            let task = match reconciled.take() {
                Some(task) => task,
                None => {
                    let snapshot = match self.recovery.as_mut() {
                        Some(recovery) => Box::pin(recovery.next_snapshot(cx, watch, Some(binding))).await?,
                        None => watch.next_snapshot(cx).await?,
                    };
                    snapshot.ok_or(ClientCredentialsTaskWatchError::UnexpectedEvent)?.task
                }
            };
            self.check(cx, binding)?;
            observe(&task)?;
            self.check(cx, binding)?;
            if matches!(&*task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
                self.remote_cancel.select_terminal()?;
                return Ok(ManagedTaskRunOutcome::Terminal(task));
            }
            let Task::InputRequired { input_requests, .. } = &*task else { continue; };
            if policy.maximum_updates == 0 { return Ok(ManagedTaskRunOutcome::InputRequired(task)); }
            let pending = ledger.unanswered(input_requests, policy)?;
            if pending.requests.is_empty() { continue; }
            if self.progress.acknowledged >= policy.maximum_updates { return Err(ClientCredentialsTaskWaitError::UpdateLimit.into()); }
            admit_capabilities(&client.metadata, &pending.requests)?;
            self.check(cx, binding)?;
            let resolution = resolve(pending.requests.clone());
            self.check(cx, binding)?;
            let action = resolution.await?;
            self.check(cx, binding)?;
            let ManagedTaskInputAction::Respond(responses) = action else {
                return Ok(ManagedTaskRunOutcome::InputRequired(task));
            };
            let next_ledger = ledger.with_answers(&pending, &responses)?;
            let mut encoded = BoundedBody { bytes: Vec::new(), maximum: client.limits.request_bytes };
            serde_json::to_writer(&mut encoded, &responses).map_err(|_| ManagedTasksError::RequestTooLarge)?;
            drop(encoded);
            // Reserve BOTH request pairs and the reconciliation slot before
            // mutation. Preflight complete documents before recording an attempt,
            // not just their responses. The underlying request path encodes again
            // without widening authority, IDs or byte bounds.
            watch.state.reserve_snapshot()?;
            let update_ids = watch.ids.next_pair()?;
            let get_ids = watch.ids.next_pair()?;
            let _ = prepare_pinned(&client, &get_ids, ManagedTaskRequest::Get(task_id.clone()))?;
            let _ = prepare_pinned(&client, &update_ids,
                ManagedTaskRequest::Update { task: task.clone(), input_responses: responses.clone() })?;
            self.check(cx, binding)?;
            self.progress.begin(update_ids.1.clone(), policy.maximum_updates)?;
            let mut call = request_pinned(&client, cx, &cancellation, binding, deadline, update_ids,
                ManagedTaskRequest::Update { task, input_responses: responses }).await?;
            if !matches!(call.next_event(cx).await?, Some(ManagedTaskEvent::Updated(_))) {
                return Err(ClientCredentialsTaskWatchError::UnexpectedEvent.into());
            }
            // No suspension separates decoder admission and its receipt. A
            // failed get or concurrent cancel must not erase an admitted update.
            self.progress.acknowledge()?;
            ledger = next_ledger;
            drop(call);
            self.check(cx, binding)?;
            // A partial answer need not change status or cause a notification.
            // Only observation AFTER this admitted ACK can recover. The update
            // itself and its response read above never enter the recovery loop.
            let observed = async {
                let mut call = request_pinned(&client, cx, &cancellation, binding, deadline, get_ids,
                    ManagedTaskRequest::Get(task_id.clone())).await?;
                let Some(ManagedTaskEvent::Snapshot(snapshot)) = call.next_event(cx).await? else {
                    return Err(ClientCredentialsTaskWatchError::UnexpectedEvent);
                };
                Ok::<_, ClientCredentialsTaskWatchError>(snapshot.task)
            }.await;
            self.check(cx, binding)?;
            match observed {
                Ok(task) => {
                    watch.finished = watch.state.record_snapshot(&task)?;
                    if let Some(recovery) = self.recovery.as_mut() { recovery.record_snapshot(watch, &task)?; }
                    if watch.finished { watch.close(); }
                    reconciled = Some(Box::new(task));
                }
                Err(error) => match self.recovery.as_mut() {
                    Some(recovery) => {
                        Box::pin(recovery.reconnect_after(cx, watch, Some(binding), error)).await?;
                    }
                    None => return Err(error.into()),
                },
            }
        }
    }
}
impl Drop for ClientCredentialsTaskWatchDriver {
    fn drop(&mut self) { self.remote_cancel.close_observation(); }
}
impl fmt::Debug for ClientCredentialsTaskWatchDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCredentialsTaskWatchDriver")
            .field("update_state", &self.progress.state)
            .field("acknowledged_updates", &self.progress.acknowledged)
            .field("reconnection_attempts", &self.reconnection_attempts())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
struct InputHistory { entries: BTreeMap<String, ([u8; 32], bool)>, bytes: usize }
struct PendingInputs { requests: TaskInputRequests, fingerprints: BTreeMap<String, [u8; 32]> }
impl InputHistory {
    fn unanswered(&mut self, requests: &TaskInputRequests, policy: ClientCredentialsTaskWatchDrivePolicy)
        -> Result<PendingInputs, ClientCredentialsTaskWaitError>
    {
        // Bound the complete descriptor set before copying it into a host
        // handoff. History retains only identities/digests, never raw answers.
        let mut writer = BoundedBody { bytes: Vec::new(), maximum: policy.maximum_input_bytes };
        serde_json::to_writer(&mut writer, requests).map_err(|_| ClientCredentialsTaskWaitError::StateByteLimit)?;
        drop(writer);
        let mut pending = PendingInputs { requests: TaskInputRequests::new(), fingerprints: BTreeMap::new() };
        let mut next = self.clone();
        for (key, request) in requests {
            let mut writer = BoundedBody { bytes: Vec::new(), maximum: policy.maximum_input_bytes };
            serde_json::to_writer(&mut writer, request).map_err(|_| ClientCredentialsTaskWaitError::StateByteLimit)?;
            let fingerprint = sha256_bounded(&writer.bytes, policy.maximum_input_bytes)
                .map_err(|_| ClientCredentialsTaskWaitError::StateByteLimit)?.into_bytes();
            match next.entries.get(key) {
                Some((previous, answered)) => {
                    if previous != &fingerprint { return Err(ClientCredentialsTaskWaitError::InputKeyReused); }
                    if *answered { continue; }
                }
                None => {
                    if next.entries.len() >= policy.maximum_input_keys { return Err(ClientCredentialsTaskWaitError::InputLimit); }
                    next.bytes = next.bytes.checked_add(key.len()).and_then(|n| n.checked_add(32))
                        .filter(|n| *n <= policy.maximum_input_bytes).ok_or(ClientCredentialsTaskWaitError::StateByteLimit)?;
                    next.entries.insert(key.clone(), (fingerprint, false));
                }
            }
            pending.requests.insert(key.clone(), request.clone());
            pending.fingerprints.insert(key.clone(), fingerprint);
        }
        // Observation reserves identity, not successful delivery. In particular
        // a server cannot change an as-yet-unanswered key after a partial update.
        *self = next;
        Ok(pending)
    }
    fn with_answers(&self, pending: &PendingInputs, responses: &TaskInputResponses)
        -> Result<Self, ClientCredentialsTaskWaitError>
    {
        if responses.is_empty() || responses.keys().any(|key| !pending.requests.contains_key(key)) {
            return Err(ClientCredentialsTaskWaitError::InvalidInputResponse);
        }
        TaskInputLedger::from_requests(&pending.requests).and_then(|ledger| ledger.validate_responses(responses))
            .map_err(|_| ClientCredentialsTaskWaitError::InvalidInputResponse)?;
        let mut next = self.clone();
        for key in responses.keys() {
            let fingerprint = pending.fingerprints.get(key).ok_or(ClientCredentialsTaskWaitError::InvalidInputResponse)?;
            let (observed, answered) = next.entries.get_mut(key).ok_or(ClientCredentialsTaskWaitError::InvalidInputResponse)?;
            if *answered || *observed != *fingerprint { return Err(ClientCredentialsTaskWaitError::InputKeyReused); }
            *answered = true;
        }
        Ok(next)
    }
}

fn admit_capabilities(metadata: &serde_json::Value, requests: &TaskInputRequests)
    -> Result<(), ClientCredentialsTaskWaitError>
{
    let capabilities = &metadata[FINAL_CLIENT_CAPABILITIES_META_KEY];
    for request in requests.values() {
        let advertised = match request {
            FinalEmbeddedInputRequest::Roots(_) => capabilities.get("roots").is_some_and(serde_json::Value::is_object),
            FinalEmbeddedInputRequest::Sampling(_) => {
                let wire = serde_json::to_value(request).map_err(|_| ClientCredentialsTaskWaitError::UnexpectedResponse)?;
                let sampling = &capabilities["sampling"];
                sampling.is_object()
                    && (wire["params"].get("tools").is_none() || sampling.get("tools").is_some_and(serde_json::Value::is_object))
                    && (wire["params"].get("includeContext").is_none_or(|context| context == "none")
                        || sampling.get("context").is_some_and(serde_json::Value::is_object))
            }
            FinalEmbeddedInputRequest::Elicitation(FinalEmbeddedElicitationParams::Form(_)) =>
                capabilities["elicitation"].get("form").is_some_and(serde_json::Value::is_object),
            FinalEmbeddedInputRequest::Elicitation(FinalEmbeddedElicitationParams::Url(_)) =>
                capabilities["elicitation"].get("url").is_some_and(serde_json::Value::is_object),
        };
        if !advertised { return Err(ClientCredentialsTaskWaitError::CapabilityNotAdvertised); }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
