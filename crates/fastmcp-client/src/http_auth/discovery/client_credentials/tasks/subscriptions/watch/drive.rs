//! Explicit host input resolution while a machine Task is watched.
//!
//! Notifications drive observation. An acknowledged local input update is
//! followed by one immediate reconciliation get: a partial answer need not
//! change Task status or cause a notification. No failed POST is ever retried.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;

use asupersync::Cx;
use fastmcp_core::{McpRequestCancellation, sha256_bounded};
use fastmcp_protocol::tasks_extension::{Task, TaskId, TaskInputLedger, TaskInputRequests, TaskInputResponses};
use fastmcp_protocol::{FinalEmbeddedElicitationParams, FinalEmbeddedInputRequest, FINAL_CLIENT_CAPABILITIES_META_KEY};

use super::{
    BoundedBody, ClientCredentialsError, ClientCredentialsTaskWatchError,
    ClientCredentialsTaskWatchPolicy, ClientCredentialsTasksClient, ClientCredentialsTasksError,
    ManagedTaskEvent, ManagedTaskRequest, ManagedTasksError, active, check_watch,
    copy_binding, prepare_pinned, request_pinned,
};
pub use crate::http_auth::discovery::client_credentials::tasks::driver::{
    ClientCredentialsTaskWaitError, ManagedTaskInputAction, ManagedTaskRunOutcome,
};

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
}
impl Default for ClientCredentialsTaskWatchDrivePolicy {
    fn default() -> Self {
        Self { watch: ClientCredentialsTaskWatchPolicy::default(), maximum_updates: 32,
            maximum_input_keys: 256, maximum_input_bytes: 1024 * 1024 }
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
        Ok(Self { watch, maximum_updates, maximum_input_keys, maximum_input_bytes })
    }
}

/// Closed diagnostics from observation or input admission. Neither variant
/// retains raw responses, host error text, credentials or input answers.
#[derive(Debug)]
pub enum ClientCredentialsTaskWatchDriveError {
    Watch(ClientCredentialsTaskWatchError),
    Input(ClientCredentialsTaskWaitError),
}
impl fmt::Display for ClientCredentialsTaskWatchDriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::Watch(error) => error.fmt(f), Self::Input(error) => error.fmt(f) }
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

impl ClientCredentialsTasksClient {
    /// Observes an existing Task and resolves input only through the supplied
    /// host callback. A resolver may return a nonempty subset of the unresolved
    /// keys, or return control to the caller without an update. Advertised
    /// roots/sampling/elicitation capabilities gate every resolver invocation.
    /// No implicit model, browser, filesystem access or Task creation occurs.
    ///
    /// Successfully acknowledged keys are never answered twice in this run.
    /// Reusing any observed key with a changed descriptor is rejected. This in-memory
    /// ledger does not survive restart: another run must reconcile remote state
    /// and must not replay an update whose response was lost.
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

    /// One original subscription credential and deadline own ACK, gets, host
    /// callbacks and updates. Cancellation drops pending resolver/network work
    /// without cancelling the remote Task or sibling calls. Errors after an
    /// update may follow a remote effect; they are not permission to retry it.
    /// Synchronous callbacks must return promptly and cooperate with the host.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task_watching_with_cancellation<R, F, O>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, task_id: TaskId,
        id_prefix: String, policy: ClientCredentialsTaskWatchDrivePolicy, mut resolve: R, mut observe: O,
    ) -> Result<ManagedTaskRunOutcome, ClientCredentialsTaskWatchDriveError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ClientCredentialsTaskWatchDriveError>>,
        O: FnMut(&Task) -> Result<(), ClientCredentialsTaskWatchDriveError>,
    {
        let mut watch = self.watch_tasks_with_cancellation(cx, cancellation,
            vec![task_id.clone()], id_prefix, policy.watch).await?;
        let binding = copy_binding(&watch.binding);
        let deadline = watch.deadline;
        let owner = &self.client.inner.closed;
        active(cx, deadline, owner, cancellation, Some(&binding), async {
            Ok(async {
                let mut ledger = InputHistory::default();
                let mut updates = 0;
                let mut reconciled = None;
                loop {
                    let task = match reconciled.take() {
                        Some(task) => task,
                        None => watch.next_snapshot(cx).await?
                            .ok_or(ClientCredentialsTaskWatchError::UnexpectedEvent)?.task,
                    };
                    check_watch(cx, deadline, owner, cancellation, &binding)?;
                    observe(&task)?;
                    check_watch(cx, deadline, owner, cancellation, &binding)?;
                    if matches!(&*task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
                        return Ok(ManagedTaskRunOutcome::Terminal(task));
                    }
                    let Task::InputRequired { input_requests, .. } = &*task else { continue; };
                    if policy.maximum_updates == 0 { return Ok(ManagedTaskRunOutcome::InputRequired(task)); }
                    let pending = ledger.unanswered(input_requests, policy)?;
                    if pending.requests.is_empty() { continue; }
                    if updates >= policy.maximum_updates { return Err(ClientCredentialsTaskWaitError::UpdateLimit.into()); }
                    admit_capabilities(&self.metadata, &pending.requests)?;
                    check_watch(cx, deadline, owner, cancellation, &binding)?;
                    let resolution = resolve(pending.requests.clone());
                    check_watch(cx, deadline, owner, cancellation, &binding)?;
                    let action = resolution.await?;
                    check_watch(cx, deadline, owner, cancellation, &binding)?;
                    let ManagedTaskInputAction::Respond(responses) = action else {
                        return Ok(ManagedTaskRunOutcome::InputRequired(task));
                    };
                    // Prepare the complete replacement ledger and reserve BOTH
                    // request pairs and the reconciliation slot before mutation.
                    // ACK never precedes a fallible local budget reservation.
                    let next_ledger = ledger.with_answers(&pending, &responses)?;
                    let mut encoded = BoundedBody { bytes: Vec::new(), maximum: self.limits.request_bytes };
                    serde_json::to_writer(&mut encoded, &responses).map_err(|_| ManagedTasksError::RequestTooLarge)?;
                    drop(encoded);
                    watch.state.reserve_snapshot()?;
                    let update_ids = watch.ids.next_pair()?;
                    let get_ids = watch.ids.next_pair()?;
                    // Admit the follow-up get before any input mutation as well.
                    let _ = prepare_pinned(self, &get_ids, ManagedTaskRequest::Get(task_id.clone()))?;
                    check_watch(cx, deadline, owner, cancellation, &binding)?;
                    let mut call = request_pinned(self, cx, cancellation, &binding, deadline, update_ids,
                        ManagedTaskRequest::Update { task, input_responses: responses }).await?;
                    if !matches!(call.next_event(cx).await?, Some(ManagedTaskEvent::Updated(_))) {
                        return Err(ClientCredentialsTaskWatchError::UnexpectedEvent.into());
                    }
                    drop(call);
                    ledger = next_ledger;
                    updates += 1;
                    check_watch(cx, deadline, owner, cancellation, &binding)?;
                    // A partial answer can leave status=input_required, with no
                    // status notification. Reconcile this successful local write
                    // immediately instead of stranding the other unresolved keys.
                    let mut call = request_pinned(self, cx, cancellation, &binding, deadline, get_ids,
                        ManagedTaskRequest::Get(task_id.clone())).await?;
                    let Some(ManagedTaskEvent::Snapshot(snapshot)) = call.next_event(cx).await? else {
                        return Err(ClientCredentialsTaskWatchError::UnexpectedEvent.into());
                    };
                    drop(call);
                    check_watch(cx, deadline, owner, cancellation, &binding)?;
                    watch.finished = watch.state.record_snapshot(&snapshot.task)?;
                    if watch.finished { watch.close(); }
                    reconciled = Some(Box::new(snapshot.task));
                }
            }.await)
        }).await?
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
