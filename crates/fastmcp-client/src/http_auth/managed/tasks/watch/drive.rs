//! Host-approved input resolution over a managed OAuth Task watch.
//!
//! Notifications trigger fresh snapshots. Each acknowledged local update also
//! triggers one reconciliation get, since a partial answer need not emit a
//! notification. No timer polling, mutation retry or background worker is used.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::time::Instant;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::{McpRequestCancellation, sha256_bounded};
use fastmcp_protocol::tasks_extension::{Task, TaskId, TaskInputLedger, TaskInputRequests, TaskInputResponses};
use fastmcp_protocol::{FinalEmbeddedElicitationParams, FinalEmbeddedInputRequest, FINAL_CLIENT_CAPABILITIES_META_KEY};

use super::{ManagedTaskWatchError, ManagedTaskWatchPolicy, ManagedTasksClient};
use super::super::{
    BoundedWriter, ManagedTaskEvent, ManagedTaskRequest, ManagedTasksError,
    OAuthCredentialSnapshot, OAuthSessionError, deadline_after, prepare,
};
pub use super::super::driver::{ManagedTaskDriverError, ManagedTaskInputAction, ManagedTaskRunOutcome};

/// Finite input authority in addition to the watch's lifetime, snapshot and
/// record limits. Zero updates is observation only. The byte bound covers the
/// complete encoded descriptor map and retained key/fingerprint history; the
/// lifetime key bound separately limits collection overhead.
#[derive(Clone, Copy, Debug)]
pub struct ManagedTaskWatchDrivePolicy {
    watch: ManagedTaskWatchPolicy,
    maximum_updates: usize,
    maximum_input_keys: usize,
    maximum_input_bytes: usize,
}

impl Default for ManagedTaskWatchDrivePolicy {
    fn default() -> Self {
        Self { watch: ManagedTaskWatchPolicy::default(), maximum_updates: 32,
            maximum_input_keys: 256, maximum_input_bytes: 1024 * 1024 }
    }
}

impl ManagedTaskWatchDrivePolicy {
    pub fn new(
        watch: ManagedTaskWatchPolicy, maximum_updates: usize,
        maximum_input_keys: usize, maximum_input_bytes: usize,
    ) -> Result<Self, ManagedTaskWatchDriveError> {
        if maximum_updates > 128 || maximum_input_keys > 4096
            || !(1..=4 * 1024 * 1024).contains(&maximum_input_bytes)
        { return Err(ManagedTaskDriverError::InvalidPolicy.into()); }
        Ok(Self { watch, maximum_updates, maximum_input_keys, maximum_input_bytes })
    }
}

/// Diagnostics retain no task IDs, input answers, credentials or peer bodies.
#[derive(Debug)]
pub enum ManagedTaskWatchDriveError {
    Watch(ManagedTaskWatchError),
    Input(ManagedTaskDriverError),
    /// A concurrent renewal changed the credential during listen admission.
    /// No host callback or input update has run; start a new operation explicitly.
    CredentialChanged,
}

impl fmt::Display for ManagedTaskWatchDriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Watch(error) => error.fmt(f),
            Self::Input(error) => error.fmt(f),
            Self::CredentialChanged => f.write_str("Task watch credential changed during admission"),
        }
    }
}
impl std::error::Error for ManagedTaskWatchDriveError {}
impl From<ManagedTaskWatchError> for ManagedTaskWatchDriveError {
    fn from(error: ManagedTaskWatchError) -> Self { Self::Watch(error) }
}
impl From<ManagedTaskDriverError> for ManagedTaskWatchDriveError {
    fn from(error: ManagedTaskDriverError) -> Self { Self::Input(error) }
}
impl From<ManagedTasksError> for ManagedTaskWatchDriveError {
    fn from(error: ManagedTasksError) -> Self { Self::Watch(error.into()) }
}
impl From<OAuthSessionError> for ManagedTaskWatchDriveError {
    fn from(error: OAuthSessionError) -> Self { Self::Watch(error.into()) }
}

impl ManagedTasksClient {
    /// Observes one existing Task and resolves input only through the supplied
    /// host callback. Responses may cover a nonempty subset of unresolved keys;
    /// `ReturnToCaller` pauses without an update. Advertised roots, sampling and
    /// elicitation capabilities gate every resolver invocation.
    ///
    /// One identity sequence covers listen, all gets and every update. A local
    /// update is reconciled immediately even without a notification. Answered
    /// keys are not answered again, and changing any previously observed input
    /// descriptor is rejected, including an as-yet-unanswered key.
    ///
    /// This operation never creates/cancels a remote Task, reconnects or retries
    /// a failed POST. Its ledger is process-local; restarting is not authority
    /// to replay an update whose acknowledgement was lost.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task_watching<R, F, O>(
        &self, cx: &Cx, task_id: TaskId, id_prefix: String,
        policy: ManagedTaskWatchDrivePolicy, resolve: R, observe: O,
    ) -> Result<ManagedTaskRunOutcome, ManagedTaskWatchDriveError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskWatchDriveError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskWatchDriveError>,
    {
        self.drive_task_watching_with_cancellation(cx, &McpRequestCancellation::new(),
            task_id, id_prefix, policy, resolve, observe).await
    }

    /// Pins the original subscription credential through snapshots, callbacks,
    /// discovery and updates. Renewal cannot extend this run or change its
    /// authorization. The deadline includes initial credential acquisition and
    /// listen admission. Cancelling/dropping it releases owned work without
    /// cancelling the ambient Cx, a sibling call or the remote Task.
    /// Synchronous host callbacks must return promptly and cooperate.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task_watching_with_cancellation<R, F, O>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, task_id: TaskId,
        id_prefix: String, policy: ManagedTaskWatchDrivePolicy, mut resolve: R, mut observe: O,
    ) -> Result<ManagedTaskRunOutcome, ManagedTaskWatchDriveError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskWatchDriveError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskWatchDriveError>,
    {
        self.session.check(cx, cancellation)?;
        // Validate the selection and identity before acquiring/renewing a token.
        let _ = super::WatchState::new(vec![task_id.clone()], policy.watch.maximum_snapshots)?;
        let _ = super::WatchIds::new(id_prefix.clone())?;
        let deadline = deadline_after(cx, policy.watch.timeout)?;
        let credential = self.session.await_active(cx, cancellation, deadline, None, async {
            self.session.credential_with_cancellation(cx, cancellation).await
        }).await?;
        self.session.await_active(cx, cancellation, deadline, Some(credential.expires_at), async {
            Ok(async {
                let mut watch = Box::pin(self.watch_tasks_with_cancellation(cx, cancellation,
                    vec![task_id.clone()], id_prefix, policy.watch)).await?;
                let generation = watch.subscription.as_ref()
                    .ok_or(ManagedTaskWatchError::Closed)?.credential_generation();
                if generation != credential.generation {
                    return Err(ManagedTaskWatchDriveError::CredentialChanged);
                }
                watch.deadline = watch.deadline.min(deadline);
                let mut ledger = InputHistory::default();
                let mut updates = 0;
                let mut reconciled = None;
                loop {
                    let task = match reconciled.take() {
                        Some(task) => task,
                        None => Box::pin(watch.next_snapshot_with_credential(cx, Some(&credential))).await?
                            .ok_or(ManagedTaskWatchError::UnexpectedEvent)?.task,
                    };
                    check_drive(self, cx, cancellation, deadline, &credential)?;
                    observe(&task)?;
                    check_drive(self, cx, cancellation, deadline, &credential)?;
                    if matches!(&*task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
                        return Ok(ManagedTaskRunOutcome::Terminal(task));
                    }
                    let Task::InputRequired { input_requests, .. } = &*task else { continue; };
                    if policy.maximum_updates == 0 { return Ok(ManagedTaskRunOutcome::InputRequired(task)); }
                    let pending = ledger.unanswered(input_requests, policy)?;
                    if pending.requests.is_empty() { continue; }
                    if updates >= policy.maximum_updates { return Err(ManagedTaskDriverError::UpdateLimit.into()); }
                    admit_capabilities(&self.metadata, &pending.requests)?;
                    check_drive(self, cx, cancellation, deadline, &credential)?;
                    let resolution = resolve(pending.requests.clone());
                    check_drive(self, cx, cancellation, deadline, &credential)?;
                    let action = resolution.await?;
                    check_drive(self, cx, cancellation, deadline, &credential)?;
                    let ManagedTaskInputAction::Respond(responses) = action else {
                        return Ok(ManagedTaskRunOutcome::InputRequired(task));
                    };
                    // All local reservations and BOTH complete request encodings
                    // precede the mutation. A partial answer must not consume the
                    // last slot and leave its required reconciliation impossible.
                    let next_ledger = ledger.with_answers(&pending, &responses)?;
                    watch.state.reserve_snapshot()?;
                    let update_ids = watch.ids.next_pair()?;
                    let get_ids = watch.ids.next_pair()?;
                    let update = prepare(self.session.resource().as_str(), &self.metadata,
                        &update_ids.operation, ManagedTaskRequest::Update { task, input_responses: responses }, self.limits)?;
                    let update_round = self.prepare_round(update_ids, update)?;
                    let get = prepare(self.session.resource().as_str(), &self.metadata,
                        &get_ids.operation, ManagedTaskRequest::Get(task_id.clone()), self.limits)?;
                    let get_round = self.prepare_round(get_ids, get)?;
                    check_drive(self, cx, cancellation, deadline, &credential)?;
                    let call_deadline = deadline.min(deadline_after(cx, self.limits.timeout)?);
                    let mut call = self.execute_round(cx, cancellation, update_round,
                        &credential, call_deadline, self.limits.records).await?;
                    if !matches!(call.next_event(cx).await?, Some(ManagedTaskEvent::Updated(_))) {
                        return Err(ManagedTaskWatchError::UnexpectedEvent.into());
                    }
                    drop(call);
                    ledger = next_ledger;
                    updates += 1;
                    check_drive(self, cx, cancellation, deadline, &credential)?;
                    let call_deadline = deadline.min(deadline_after(cx, self.limits.timeout)?);
                    let mut call = self.execute_round(cx, cancellation, get_round,
                        &credential, call_deadline, self.limits.records).await?;
                    let Some(ManagedTaskEvent::Snapshot(snapshot)) = call.next_event(cx).await? else {
                        return Err(ManagedTaskWatchError::UnexpectedEvent.into());
                    };
                    drop(call);
                    check_drive(self, cx, cancellation, deadline, &credential)?;
                    watch.finished = watch.state.record_snapshot(&snapshot.task)?;
                    if watch.finished { watch.close(); }
                    reconciled = Some(Box::new(snapshot.task));
                }
            }.await)
        }).await?
    }
}

fn check_drive(
    client: &ManagedTasksClient, cx: &Cx, cancellation: &McpRequestCancellation,
    deadline: Time, credential: &OAuthCredentialSnapshot,
) -> Result<(), ManagedTaskWatchDriveError> {
    client.session.check(cx, cancellation)?;
    if Instant::now() >= credential.expires_at { return Err(OAuthSessionError::LoginRequired.into()); }
    let deadline = cx.budget().deadline.map_or(deadline, |parent| parent.min(deadline));
    if cx.now() >= deadline { return Err(OAuthSessionError::TimedOut.into()); }
    Ok(())
}

#[derive(Clone, Default)]
struct InputHistory { entries: BTreeMap<String, ([u8; 32], bool)>, bytes: usize }
struct PendingInputs { requests: TaskInputRequests, fingerprints: BTreeMap<String, [u8; 32]> }

impl InputHistory {
    fn unanswered(&mut self, requests: &TaskInputRequests, policy: ManagedTaskWatchDrivePolicy)
        -> Result<PendingInputs, ManagedTaskDriverError>
    {
        let mut writer = BoundedWriter { bytes: Vec::new(), maximum: policy.maximum_input_bytes };
        serde_json::to_writer(&mut writer, requests).map_err(|_| ManagedTaskDriverError::StateByteLimit)?;
        drop(writer);
        let mut pending = PendingInputs { requests: TaskInputRequests::new(), fingerprints: BTreeMap::new() };
        let mut next = self.clone();
        for (key, request) in requests {
            let mut writer = BoundedWriter { bytes: Vec::new(), maximum: policy.maximum_input_bytes };
            serde_json::to_writer(&mut writer, request).map_err(|_| ManagedTaskDriverError::StateByteLimit)?;
            let fingerprint = sha256_bounded(&writer.bytes, policy.maximum_input_bytes)
                .map_err(|_| ManagedTaskDriverError::StateByteLimit)?.into_bytes();
            match next.entries.get(key) {
                Some((previous, answered)) => {
                    if previous != &fingerprint { return Err(ManagedTaskDriverError::InputKeyReused); }
                    if *answered { continue; }
                }
                None => {
                    if next.entries.len() >= policy.maximum_input_keys { return Err(ManagedTaskDriverError::InputLimit); }
                    next.bytes = next.bytes.checked_add(key.len()).and_then(|n| n.checked_add(32))
                        .filter(|n| *n <= policy.maximum_input_bytes).ok_or(ManagedTaskDriverError::StateByteLimit)?;
                    next.entries.insert(key.clone(), (fingerprint, false));
                }
            }
            pending.requests.insert(key.clone(), request.clone());
            pending.fingerprints.insert(key.clone(), fingerprint);
        }
        *self = next;
        Ok(pending)
    }

    fn with_answers(&self, pending: &PendingInputs, responses: &TaskInputResponses)
        -> Result<Self, ManagedTaskDriverError>
    {
        if responses.is_empty() || responses.keys().any(|key| !pending.requests.contains_key(key)) {
            return Err(ManagedTaskDriverError::InvalidInputResponse);
        }
        TaskInputLedger::from_requests(&pending.requests).and_then(|ledger| ledger.validate_responses(responses))
            .map_err(|_| ManagedTaskDriverError::InvalidInputResponse)?;
        let mut next = self.clone();
        for key in responses.keys() {
            let fingerprint = pending.fingerprints.get(key).ok_or(ManagedTaskDriverError::InvalidInputResponse)?;
            let (observed, answered) = next.entries.get_mut(key).ok_or(ManagedTaskDriverError::InvalidInputResponse)?;
            if *answered || *observed != *fingerprint { return Err(ManagedTaskDriverError::InputKeyReused); }
            *answered = true;
        }
        Ok(next)
    }
}

fn admit_capabilities(metadata: &serde_json::Value, requests: &TaskInputRequests)
    -> Result<(), ManagedTaskDriverError>
{
    let capabilities = &metadata[FINAL_CLIENT_CAPABILITIES_META_KEY];
    for request in requests.values() {
        let advertised = match request {
            FinalEmbeddedInputRequest::Roots(_) => capabilities.get("roots").is_some_and(serde_json::Value::is_object),
            FinalEmbeddedInputRequest::Sampling(_) => {
                let wire = serde_json::to_value(request).map_err(|_| ManagedTaskDriverError::UnexpectedResponse)?;
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
        if !advertised { return Err(ManagedTaskDriverError::CapabilityNotAdvertised); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inputs() -> TaskInputRequests {
        serde_json::from_value(json!({"one":{"method":"roots/list"},"two":{"method":"roots/list"}})).unwrap()
    }
    fn answers(key: &str) -> TaskInputResponses {
        serde_json::from_value(json!({key:{"roots":[]}})).unwrap()
    }

    #[test]
    fn partial_answers_preserve_unanswered_keys_and_do_not_replay_acknowledged_keys() {
        let policy = ManagedTaskWatchDrivePolicy::default();
        let mut history = InputHistory::default();
        let pending = history.unanswered(&inputs(), policy).unwrap();
        let committed = history.with_answers(&pending, &answers("one")).unwrap();
        assert!(!history.entries["one"].1, "preparation is not acknowledgement");
        history = committed;
        let remaining = history.unanswered(&inputs(), policy).unwrap();
        assert_eq!(remaining.requests.keys().map(String::as_str).collect::<Vec<_>>(), ["two"]);
        history = history.with_answers(&remaining, &answers("two")).unwrap();
        assert!(history.unanswered(&inputs(), policy).unwrap().requests.is_empty());
    }

    #[test]
    fn changed_unanswered_descriptor_is_rejected_atomically() {
        let policy = ManagedTaskWatchDrivePolicy::default();
        let mut history = InputHistory::default();
        history.unanswered(&inputs(), policy).unwrap();
        let before = history.entries.clone();
        let bytes = history.bytes;
        let changed = serde_json::from_value(json!({
            "new":{"method":"roots/list"},
            "two":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":1}}
        })).unwrap();
        assert!(matches!(history.unanswered(&changed, policy), Err(ManagedTaskDriverError::InputKeyReused)));
        assert_eq!(history.entries, before);
        assert_eq!(history.bytes, bytes);
    }

    #[test]
    fn input_history_keeps_lifetime_limits_when_keys_disappear() {
        let mut policy = ManagedTaskWatchDrivePolicy::default();
        policy.maximum_input_keys = 2;
        let mut history = InputHistory::default();
        history.unanswered(&inputs(), policy).unwrap();
        history.unanswered(&TaskInputRequests::new(), policy).unwrap();
        let new = serde_json::from_value(json!({"three":{"method":"roots/list"}})).unwrap();
        assert!(matches!(history.unanswered(&new, policy), Err(ManagedTaskDriverError::InputLimit)));
        assert_eq!(history.entries.len(), 2);
    }

    #[test]
    fn response_preparation_rejects_empty_foreign_and_wrong_kind_answers() {
        let mut history = InputHistory::default();
        let pending = history.unanswered(&inputs(), ManagedTaskWatchDrivePolicy::default()).unwrap();
        for value in [json!({}), json!({"foreign":{"roots":[]}}), json!({"one":{"action":"decline"}})] {
            let response = serde_json::from_value(value).unwrap();
            assert!(matches!(history.with_answers(&pending, &response), Err(ManagedTaskDriverError::InvalidInputResponse)));
            assert!(history.entries.values().all(|(_, answered)| !answered));
        }
    }

    #[test]
    fn descriptor_budget_covers_the_whole_host_handoff() {
        let mut policy = ManagedTaskWatchDrivePolicy::default();
        policy.maximum_input_bytes = serde_json::to_vec(&inputs()).unwrap().len() - 1;
        let mut history = InputHistory::default();
        assert!(matches!(history.unanswered(&inputs(), policy), Err(ManagedTaskDriverError::StateByteLimit)));
        assert!(history.entries.is_empty());
        assert_eq!(history.bytes, 0);
    }

    #[test]
    fn watch_drive_policy_has_finite_authority_and_observation_only_mode() {
        let watch = ManagedTaskWatchPolicy::default();
        assert!(ManagedTaskWatchDrivePolicy::new(watch, 0, 0, 1).is_ok());
        for (updates, keys, bytes) in [(129, 1, 1), (1, 4097, 1), (1, 1, 0), (1, 1, 4 * 1024 * 1024 + 1)] {
            assert!(ManagedTaskWatchDrivePolicy::new(watch, updates, keys, bytes).is_err());
        }
    }

    #[test]
    fn capabilities_gate_host_input_before_resolution() {
        let absent = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{}});
        let roots = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"roots":{}}});
        assert!(matches!(admit_capabilities(&absent, &inputs()), Err(ManagedTaskDriverError::CapabilityNotAdvertised)));
        assert!(admit_capabilities(&roots, &inputs()).is_ok());
    }
}
