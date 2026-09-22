//! Bounded, opt-in Task polling and input resolution over managed OAuth.
//!
//! TASK-03: follows an existing opaque task ID using the same client/resource
//! binding as its ordinary Task operations. Each get/update retains fresh
//! credential-bound Tasks discovery. This driver creates no task, background
//! worker, runtime, reconnect loop or persistent state. A failed POST is never
//! retried. Host callbacks must be cooperative; synchronous work cannot be
//! preempted. Local cancellation stops observation, not remote execution.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::future::Future;
use std::time::Duration;

use asupersync::Cx;
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_core::{McpRequestCancellation, Sha256Digest, sha256_bounded};
use fastmcp_protocol::{CorrelationKey, FINAL_CLIENT_CAPABILITIES_META_KEY};
use fastmcp_protocol::tasks_extension::{Task, TaskId, TaskInputLedger, TaskInputRequests, TaskInputResponses};

use crate::http_auth::rpc::interaction::{
    ManagedInteractionError, admit_embedded_input, normalize_embedded_input_context,
};

use super::{
    BoundedWriter, ManagedTaskEvent, ManagedTaskRequest, ManagedTaskRequestIds,
    ManagedTasksClient, ManagedTasksError, OAuthSessionError, deadline_after, prepare,
};

/// One finite budget for the entire poll/resolve/update lifecycle, including
/// credential renewal, discovery, network reads, host input and poll delays.
#[derive(Clone, Copy, Debug)]
pub struct ManagedTaskDriverPolicy {
    minimum_poll_interval: Duration,
    timeout: Duration,
    maximum_polls: usize,
    maximum_updates: usize,
    maximum_input_keys: usize,
    maximum_state_bytes: usize,
}

impl Default for ManagedTaskDriverPolicy {
    fn default() -> Self {
        Self {
            minimum_poll_interval: Duration::from_secs(1),
            timeout: Duration::from_mins(15),
            maximum_polls: 512,
            maximum_updates: 32,
            maximum_input_keys: 256,
            maximum_state_bytes: 1024 * 1024,
        }
    }
}

impl ManagedTaskDriverPolicy {
    /// Polling never runs faster than either this nonzero local floor or the
    /// latest peer `pollIntervalMs`. A huge peer interval is not shortened to
    /// fit the run: the overall deadline expires instead of an early new POST.
    /// Zero updates provides an explicit observation-only budget; the input
    /// key budget is unused in that mode. State bytes bound encoded request
    /// identities and retained input-key fingerprints, not allocator overhead.
    /// Counts bound that overhead too.
    pub fn new(
        minimum_poll_interval: Duration,
        timeout: Duration,
        maximum_polls: usize,
        maximum_updates: usize,
        maximum_input_keys: usize,
        maximum_state_bytes: usize,
    ) -> Result<Self, ManagedTaskDriverError> {
        if minimum_poll_interval.is_zero()
            || minimum_poll_interval > Duration::from_secs(60)
            || timeout.is_zero() || timeout > Duration::from_hours(24)
            || !(1..=4096).contains(&maximum_polls)
            || maximum_updates > 128 || maximum_input_keys > 4096
            || !(1..=4 * 1024 * 1024).contains(&maximum_state_bytes)
        {
            return Err(ManagedTaskDriverError::InvalidPolicy);
        }
        Ok(Self { minimum_poll_interval, timeout, maximum_polls, maximum_updates,
            maximum_input_keys, maximum_state_bytes })
    }
}

/// Host-selected response to previously unanswered Task input requests.
/// Respond may contain a nonempty strict subset; unlike the low-level wire
/// API, this automatic driver rejects unknown/already-answered keys and empty
/// updates so an input loop cannot issue effectless POSTs indefinitely.
pub enum ManagedTaskInputAction {
    Respond(TaskInputResponses),
    /// Return the exact current Task without submitting an input update.
    ReturnToCaller,
}

/// A terminal task is not necessarily successful: inspect its Completed,
/// Failed or Cancelled variant. InputRequired is an explicit host pause, not
/// a terminal task or an implicit promise of successful remote execution.
pub enum ManagedTaskRunOutcome {
    Terminal(Box<Task>),
    InputRequired(Box<Task>),
}

/// No host text, input keys, answers, task IDs or remote error bodies are kept
/// in driver diagnostics. Returning an error never reports remote cancellation.
#[derive(Debug)]
pub enum ManagedTaskDriverError {
    InvalidPolicy,
    PollLimit,
    UpdateLimit,
    InputLimit,
    StateByteLimit,
    InvalidRequestIds,
    RepeatedRequestId,
    InvalidInputResponse,
    InputKeyReused,
    CapabilityNotAdvertised,
    UnexpectedResponse,
    AbortedByHost,
    Task(ManagedTasksError),
}

impl fmt::Display for ManagedTaskDriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::Task(error) = self { return fmt::Display::fmt(error, f); }
        f.write_str(match self {
            Self::InvalidPolicy => "invalid managed Task driver policy",
            Self::PollLimit => "managed Task poll budget exhausted",
            Self::UpdateLimit => "managed Task input-update budget exhausted",
            Self::InputLimit => "managed Task input-key budget exhausted",
            Self::StateByteLimit => "managed Task retained-state byte budget exhausted",
            Self::InvalidRequestIds => "invalid managed Task driver request identities",
            Self::RepeatedRequestId => "managed Task driver request identity already used",
            Self::InvalidInputResponse => "host answers do not match unresolved Task input",
            Self::InputKeyReused => "Task reused an answered input key with a different descriptor",
            Self::CapabilityNotAdvertised => "Task input requires an unadvertised client capability",
            Self::UnexpectedResponse => "managed Task driver received an unexpected result",
            Self::AbortedByHost => "managed Task driver stopped by its host",
            Self::Task(_) => unreachable!(),
        })
    }
}

impl std::error::Error for ManagedTaskDriverError {}
impl From<ManagedTasksError> for ManagedTaskDriverError {
    fn from(error: ManagedTasksError) -> Self { Self::Task(error) }
}

impl ManagedTasksClient {
    /// Follows one task to its terminal snapshot or an explicit host input pause.
    /// The first get is immediate. Later gets honor the last admitted polling
    /// hint; no background work continues after this consuming future is dropped.
    ///
    /// `next_ids` supplies a distinct discovery/operation pair before each POST
    /// pair. Every ID remains reserved for this whole run, including numeric
    /// aliases. The resolver sees only input keys not successfully acknowledged
    /// earlier in this run. An unchanged stale input snapshot therefore cannot
    /// cause duplicate resolver work or a duplicate update. Reusing an answered
    /// key with a different serialized descriptor fails rather than approving
    /// new input. Descriptor fingerprints are representation-sensitive.
    ///
    /// Observers run once per admitted snapshot, including unchanged snapshots.
    /// Roots, sampling, sampling tools/toolChoice and form/URL elicitation require
    /// the corresponding capability in this client's immutable metadata.
    /// The resolver receives copies with unadvertised context hints omitted;
    /// retained descriptors keep their original representation.
    /// Neither observer nor resolver errors are retried. After an uncertain
    /// update, the driver returns an error and performs no further get/update.
    /// Starting another driver is an explicit new operation with no exactly-once
    /// or restart guarantee; callers must reconcile remote state first.
    pub async fn drive_task<I, R, F, O>(
        &self,
        cx: &Cx,
        task_id: TaskId,
        policy: ManagedTaskDriverPolicy,
        next_ids: I,
        resolve: R,
        observe: O,
    ) -> Result<ManagedTaskRunOutcome, ManagedTaskDriverError>
    where
        I: FnMut() -> Result<ManagedTaskRequestIds, ManagedTaskDriverError>,
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        self.drive_task_with_cancellation(cx, &McpRequestCancellation::new(), task_id,
            policy, next_ids, resolve, observe).await
    }

    /// One request-local cancellation domain covers poll sleeps, credential
    /// acquisition, both POSTs, body reads and pending resolver futures. Session
    /// closure also wakes these waits, without cancelling the caller's context.
    /// Neither operation sends `tasks/cancel`; remote cancellation is explicit.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task_with_cancellation<I, R, F, O>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: TaskId,
        policy: ManagedTaskDriverPolicy,
        mut next_ids: I,
        mut resolve: R,
        mut observe: O,
    ) -> Result<ManagedTaskRunOutcome, ManagedTaskDriverError>
    where
        I: FnMut() -> Result<ManagedTaskRequestIds, ManagedTaskDriverError>,
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        self.session.check(cx, cancellation).map_err(ManagedTasksError::from)?;
        let deadline = deadline_after(cx, policy.timeout).map_err(ManagedTasksError::from)?;
        // The outer guard includes host callbacks and sleeps as well as I/O.
        // Explicit inner checks also stop a ready host callback that overruns
        // its deadline before this composite future next returns Poll::Pending.
        self.session.await_active(cx, cancellation, deadline, None, async {
            Ok(async {
                let mut state = DriverState::default();
                let mut polls = 0;
                let mut updates = 0;
                let mut due = cx.now();
                loop {
                    if polls >= policy.maximum_polls { return Err(ManagedTaskDriverError::PollLimit); }
                    if cx.now() < due { Sleep::new(due).await; }
                    self.check_driver(cx, cancellation, deadline)?;
                    let ids = next_ids()?;
                    self.check_driver(cx, cancellation, deadline)?;
                    state.reserve_ids(&ids, policy.maximum_state_bytes)?;
                    polls += 1;
                    self.check_driver(cx, cancellation, deadline)?;
                    let mut call = self.request_with_cancellation(cx, cancellation, ids,
                        ManagedTaskRequest::Get(task_id.clone())).await?;
                    let Some(ManagedTaskEvent::Snapshot(snapshot)) = call.next_event(cx).await? else {
                        return Err(ManagedTaskDriverError::UnexpectedResponse);
                    };
                    drop(call);
                    let task = snapshot.task;
                    // Keep the peer's relative polling hint anchored to receipt,
                    // not to the later completion of a potentially slow resolver.
                    due = next_poll_time(cx.now(), &task, policy.minimum_poll_interval)?;
                    self.check_driver(cx, cancellation, deadline)?;
                    observe(&task)?;
                    self.check_driver(cx, cancellation, deadline)?;
                    if matches!(task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
                        return Ok(ManagedTaskRunOutcome::Terminal(Box::new(task)));
                    }
                    let Task::InputRequired { input_requests, .. } = &task else { continue };
                    // Observation-only mode cannot invoke input handlers, even
                    // when the configured input-key budget is zero.
                    if policy.maximum_updates == 0 {
                        return Ok(ManagedTaskRunOutcome::InputRequired(Box::new(task)));
                    }
                    let (pending, fingerprints) = state.unanswered(input_requests, policy)?;
                    if pending.is_empty() { continue; }
                    if updates >= policy.maximum_updates { return Err(ManagedTaskDriverError::UpdateLimit); }
                    let callback_inputs = admit_capabilities(&self.metadata, &pending)?;
                    self.check_driver(cx, cancellation, deadline)?;
                    let resolution = resolve(callback_inputs);
                    self.check_driver(cx, cancellation, deadline)?;
                    let action = resolution.await?;
                    self.check_driver(cx, cancellation, deadline)?;
                    let ManagedTaskInputAction::Respond(responses) = action else {
                        return Ok(ManagedTaskRunOutcome::InputRequired(Box::new(task)));
                    };
                    validate_answers(&pending, &responses)?;
                    let answered: Vec<_> = responses.keys().cloned().collect();
                    let update = ManagedTaskRequest::Update { task: Box::new(task), input_responses: responses };
                    // Validate the actual encoded update before asking the host
                    // for IDs or allowing a renewal/discovery effect.
                    let provisional = fastmcp_protocol::RequestId::Number(0);
                    let _ = prepare(self.session.resource().as_str(), &self.metadata, &provisional,
                        update_for_validation(&update)?, self.limits)?;
                    self.check_driver(cx, cancellation, deadline)?;
                    let ids = next_ids()?;
                    self.check_driver(cx, cancellation, deadline)?;
                    state.reserve_ids(&ids, policy.maximum_state_bytes)?;
                    // Include the newly reserved IDs before verifying that an
                    // acknowledged update can fit our retained input ledger.
                    state.answer_bytes(&answered, &fingerprints, policy.maximum_state_bytes)?;
                    updates += 1;
                    self.check_driver(cx, cancellation, deadline)?;
                    let mut call = self.request_with_cancellation(cx, cancellation, ids, update).await?;
                    if !matches!(call.next_event(cx).await?, Some(ManagedTaskEvent::Updated(_))) {
                        return Err(ManagedTaskDriverError::UnexpectedResponse);
                    }
                    self.check_driver(cx, cancellation, deadline)?;
                    // Only an admitted update acknowledgement advances local
                    // input state. Any error/drop before it exits this run.
                    state.record_answers(&answered, &fingerprints, policy.maximum_state_bytes)?;
                }
            }.await)
        }).await.map_err(ManagedTasksError::from)?
    }

    fn check_driver(&self, cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time) -> Result<(), ManagedTaskDriverError> {
        self.session.check(cx, cancellation).map_err(ManagedTasksError::from)?;
        let deadline = cx.budget().deadline.map_or(deadline, |parent| parent.min(deadline));
        if cx.now() >= deadline {
            return Err(ManagedTasksError::from(OAuthSessionError::TimedOut).into());
        }
        Ok(())
    }
}

fn update_for_validation(request: &ManagedTaskRequest) -> Result<ManagedTaskRequest, ManagedTaskDriverError> {
    match request {
        ManagedTaskRequest::Update { task, input_responses } => Ok(ManagedTaskRequest::Update {
            task: task.clone(), input_responses: input_responses.clone(),
        }),
        _ => Err(ManagedTaskDriverError::UnexpectedResponse),
    }
}

fn next_poll_time(now: Time, task: &Task, minimum: Duration) -> Result<Time, ManagedTaskDriverError> {
    let peer = task.base().poll_interval_ms.as_ref().map(|hint| hint.try_as_millis())
        .transpose().map_err(|_| ManagedTaskDriverError::UnexpectedResponse)?
        .map(Duration::from_millis).unwrap_or(minimum);
    let nanos = u64::try_from(peer.max(minimum).as_nanos()).unwrap_or(u64::MAX);
    Ok(now.saturating_add_nanos(nanos))
}

#[derive(Default)]
struct DriverState {
    ids: HashSet<CorrelationKey>,
    answered: BTreeMap<String, Sha256Digest>,
    retained_bytes: usize,
}

impl DriverState {
    fn reserve_ids(&mut self, ids: &ManagedTaskRequestIds, maximum: usize) -> Result<(), ManagedTaskDriverError> {
        let mut writer = BoundedWriter { bytes: Vec::new(), maximum: 8192 };
        serde_json::to_writer(&mut writer, &(&ids.discovery, &ids.operation))
            .map_err(|_| ManagedTaskDriverError::InvalidRequestIds)?;
        let one = ids.discovery.correlation_key().map_err(|_| ManagedTaskDriverError::InvalidRequestIds)?;
        let two = ids.operation.correlation_key().map_err(|_| ManagedTaskDriverError::InvalidRequestIds)?;
        if one == two || self.ids.contains(&one) || self.ids.contains(&two) {
            return Err(ManagedTaskDriverError::RepeatedRequestId);
        }
        let bytes = self.retained_bytes.checked_add(writer.bytes.len()).ok_or(ManagedTaskDriverError::StateByteLimit)?;
        if bytes > maximum { return Err(ManagedTaskDriverError::StateByteLimit); }
        self.ids.insert(one);
        self.ids.insert(two);
        self.retained_bytes = bytes;
        Ok(())
    }

    fn unanswered(
        &self, requests: &TaskInputRequests, policy: ManagedTaskDriverPolicy,
    ) -> Result<(TaskInputRequests, BTreeMap<String, Sha256Digest>), ManagedTaskDriverError> {
        let mut pending = TaskInputRequests::new();
        let mut fingerprints = BTreeMap::new();
        let mut bytes = self.retained_bytes;
        for (key, request) in requests {
            let mut writer = BoundedWriter { bytes: Vec::new(), maximum: policy.maximum_state_bytes };
            serde_json::to_writer(&mut writer, request).map_err(|_| ManagedTaskDriverError::StateByteLimit)?;
            let digest = sha256_bounded(&writer.bytes, policy.maximum_state_bytes)
                .map_err(|_| ManagedTaskDriverError::StateByteLimit)?;
            if let Some(previous) = self.answered.get(key) {
                if previous != &digest { return Err(ManagedTaskDriverError::InputKeyReused); }
                continue;
            }
            if self.answered.len() + pending.len() >= policy.maximum_input_keys {
                return Err(ManagedTaskDriverError::InputLimit);
            }
            bytes = bytes.checked_add(key.len()).and_then(|n| n.checked_add(32))
                .ok_or(ManagedTaskDriverError::StateByteLimit)?;
            if bytes > policy.maximum_state_bytes { return Err(ManagedTaskDriverError::StateByteLimit); }
            pending.insert(key.clone(), request.clone());
            fingerprints.insert(key.clone(), digest);
        }
        Ok((pending, fingerprints))
    }

    fn answer_bytes(&self, keys: &[String], fingerprints: &BTreeMap<String, Sha256Digest>, maximum: usize) -> Result<usize, ManagedTaskDriverError> {
        let mut bytes = self.retained_bytes;
        for key in keys {
            if self.answered.contains_key(key) || !fingerprints.contains_key(key) {
                return Err(ManagedTaskDriverError::InvalidInputResponse);
            }
            bytes = bytes.checked_add(key.len()).and_then(|n| n.checked_add(32))
                .ok_or(ManagedTaskDriverError::StateByteLimit)?;
        }
        if bytes > maximum { return Err(ManagedTaskDriverError::StateByteLimit); }
        Ok(bytes)
    }

    fn record_answers(&mut self, keys: &[String], fingerprints: &BTreeMap<String, Sha256Digest>, maximum: usize) -> Result<(), ManagedTaskDriverError> {
        let bytes = self.answer_bytes(keys, fingerprints, maximum)?;
        for key in keys { self.answered.insert(key.clone(), fingerprints[key].clone()); }
        self.retained_bytes = bytes;
        Ok(())
    }
}

fn validate_answers(requests: &TaskInputRequests, responses: &TaskInputResponses) -> Result<(), ManagedTaskDriverError> {
    if responses.is_empty() || responses.keys().any(|key| !requests.contains_key(key)) {
        return Err(ManagedTaskDriverError::InvalidInputResponse);
    }
    TaskInputLedger::from_requests(requests).and_then(|ledger| ledger.validate_responses(responses))
        .map_err(|_| ManagedTaskDriverError::InvalidInputResponse)
}

fn admit_capabilities(metadata: &serde_json::Value, requests: &TaskInputRequests) -> Result<TaskInputRequests, ManagedTaskDriverError> {
    let capabilities = &metadata[FINAL_CLIENT_CAPABILITIES_META_KEY];
    for request in requests.values() {
        let wire = serde_json::to_value(request).map_err(|_| ManagedTaskDriverError::UnexpectedResponse)?;
        admit_embedded_input(capabilities, wire).map_err(|error| match error {
            ManagedInteractionError::CapabilityNotAdvertised => ManagedTaskDriverError::CapabilityNotAdvertised,
            _ => ManagedTaskDriverError::UnexpectedResponse,
        })?;
    }
    let mut callback_inputs = requests.clone();
    let mut context_ignored = false;
    for request in callback_inputs.values_mut() {
        context_ignored |= normalize_embedded_input_context(capabilities, request);
    }
    if context_ignored {
        log::warn!("ignoring unadvertised sampling context hint in Task input");
    }
    Ok(callback_inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::RequestId;
    use serde_json::json;

    fn inputs() -> TaskInputRequests {
        serde_json::from_value(json!({"one":{"method":"roots/list"},"two":{"method":"roots/list"}})).unwrap()
    }
    fn ids(one: i64, two: i64) -> ManagedTaskRequestIds {
        ManagedTaskRequestIds::new(RequestId::Number(one), RequestId::Number(two)).unwrap()
    }
    fn task(interval: Option<u64>) -> Task {
        let mut value = json!({"taskId":"opaque-task","status":"working","createdAt":"2026-09-17T00:00:00Z","lastUpdatedAt":"2026-09-17T00:00:00Z","ttlMs":null});
        if let Some(interval) = interval { value["pollIntervalMs"] = json!(interval); }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn poll_hint_never_shortens_the_local_floor_or_wraps_a_large_interval() {
        let now = Time::from_nanos(1000);
        for (hint, expected) in [(None, 100_000_000), (Some(1), 100_000_000), (Some(300), 300_000_000)] {
            assert_eq!(next_poll_time(now, &task(hint), Duration::from_millis(100)).unwrap(), now.saturating_add_nanos(expected));
        }
        assert_eq!(next_poll_time(now, &task(Some(u64::MAX)), Duration::from_millis(1)).unwrap(), Time::from_nanos(u64::MAX));
    }

    #[test]
    fn both_ids_are_reserved_atomically_and_numeric_aliases_cannot_recur() {
        let mut state = DriverState::default();
        state.reserve_ids(&ids(1, 2), 4096).unwrap();
        let before = state.retained_bytes;
        assert!(matches!(state.reserve_ids(&ids(3, 2), 4096), Err(ManagedTaskDriverError::RepeatedRequestId)));
        assert_eq!(state.retained_bytes, before);
        state.reserve_ids(&ids(3, 4), 4096).unwrap();
        let alias = ManagedTaskRequestIds::new(serde_json::from_str("2e0").unwrap(), RequestId::Number(5)).unwrap();
        assert!(matches!(state.reserve_ids(&alias, 4096), Err(ManagedTaskDriverError::RepeatedRequestId)));
        let distinct = ManagedTaskRequestIds::new(RequestId::String("2".to_owned()), RequestId::Number(5)).unwrap();
        state.reserve_ids(&distinct, 4096).unwrap();
    }

    #[test]
    fn partial_answers_remove_only_acknowledged_keys_from_future_resolver_work() {
        let mut state = DriverState::default();
        let policy = ManagedTaskDriverPolicy::default();
        let (pending, fingerprints) = state.unanswered(&inputs(), policy).unwrap();
        let reply: TaskInputResponses = serde_json::from_value(json!({"one":{"roots":[]}})).unwrap();
        validate_answers(&pending, &reply).unwrap();
        state.record_answers(&["one".to_owned()], &fingerprints, policy.maximum_state_bytes).unwrap();
        let (pending, fingerprints) = state.unanswered(&inputs(), policy).unwrap();
        assert_eq!(pending.keys().map(String::as_str).collect::<Vec<_>>(), ["two"]);
        state.record_answers(&["two".to_owned()], &fingerprints, policy.maximum_state_bytes).unwrap();
        assert!(state.unanswered(&inputs(), policy).unwrap().0.is_empty());
    }

    #[test]
    fn reusing_answered_key_with_changed_descriptor_fails_without_mutation() {
        let mut state = DriverState::default();
        let policy = ManagedTaskDriverPolicy::default();
        let (_, fingerprints) = state.unanswered(&inputs(), policy).unwrap();
        state.record_answers(&["one".to_owned()], &fingerprints, policy.maximum_state_bytes).unwrap();
        let before = state.retained_bytes;
        let changed = serde_json::from_value(json!({"one":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}}})).unwrap();
        assert!(matches!(state.unanswered(&changed, policy), Err(ManagedTaskDriverError::InputKeyReused)));
        assert_eq!(state.retained_bytes, before);
        assert_eq!(state.answered.len(), 1);
    }

    #[test]
    fn automatic_updates_reject_empty_foreign_or_wrong_kind_answers() {
        for value in [json!({}), json!({"other":{"roots":[]}}), json!({"one":{"action":"decline"}})] {
            let replies: TaskInputResponses = serde_json::from_value(value).unwrap();
            assert!(matches!(validate_answers(&inputs(), &replies), Err(ManagedTaskDriverError::InvalidInputResponse)));
        }
    }

    #[test]
    fn budgets_reject_before_retained_state_changes() {
        let mut state = DriverState::default();
        assert!(matches!(state.reserve_ids(&ids(1, 2), 1), Err(ManagedTaskDriverError::StateByteLimit)));
        assert!(state.ids.is_empty());
        let mut policy = ManagedTaskDriverPolicy::default();
        policy.maximum_input_keys = 1;
        assert!(matches!(state.unanswered(&inputs(), policy), Err(ManagedTaskDriverError::InputLimit)));
        assert!(state.answered.is_empty());
        let (_, prints) = state.unanswered(&inputs(), ManagedTaskDriverPolicy::default()).unwrap();
        assert!(matches!(state.record_answers(&["one".to_owned()], &prints, 1), Err(ManagedTaskDriverError::StateByteLimit)));
        assert!(state.answered.is_empty());
    }

    #[test]
    fn policy_has_no_unbounded_poll_or_zero_delay_mode() {
        let second = Duration::from_secs(1);
        assert!(ManagedTaskDriverPolicy::new(second, second, 1, 0, 0, 1).is_ok());
        for (delay, timeout, polls, updates, inputs, bytes) in [
            (Duration::ZERO, second, 1, 1, 1, 1024),
            (second, Duration::ZERO, 1, 1, 1, 1024),
            (second, second, 0, 1, 1, 1024),
            (second, second, 4097, 1, 1, 1024),
            (second, second, 1, 129, 1, 1024),
            (second, second, 1, 1, 4097, 1024),
            (second, second, 1, 1, 1, 0),
        ] { assert!(ManagedTaskDriverPolicy::new(delay, timeout, polls, updates, inputs, bytes).is_err()); }
    }

    #[test]
    fn input_capabilities_are_admitted_before_automatic_resolution() {
        let absent = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{}});
        let roots = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"roots":{}}});
        assert!(matches!(admit_capabilities(&absent, &inputs()), Err(ManagedTaskDriverError::CapabilityNotAdvertised)));
        assert!(admit_capabilities(&roots, &inputs()).is_ok());
        let sampling = serde_json::from_value(json!({"sample":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":1,"includeContext":"allServers"}}})).unwrap();
        let before = serde_json::to_value(&sampling).unwrap();
        let plain = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"sampling":{}}});
        let context = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"sampling":{"context":{}}}});
        assert!(matches!(admit_capabilities(&absent, &sampling), Err(ManagedTaskDriverError::CapabilityNotAdvertised)));
        assert!(admit_capabilities(&plain, &sampling).is_ok());
        assert!(admit_capabilities(&context, &sampling).is_ok());
        assert_eq!(serde_json::to_value(&sampling).unwrap(), before);
    }

    #[test]
    fn sampling_tools_and_tool_choice_require_the_tools_capability() {
        for (field, value) in [("tools", json!([])), ("toolChoice", json!({}))] {
            let mut params = json!({"messages":[],"maxTokens":1,"includeContext":"allServers"});
            params[field] = value;
            let requests = serde_json::from_value(json!({"sample":{"method":"sampling/createMessage","params":params}})).unwrap();
            let before = serde_json::to_value(&requests).unwrap();
            for sampling in [json!({}), json!({"context":{}}), json!({"tools":null}), json!({"tools":[]})] {
                let metadata = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"sampling":sampling}});
                assert!(matches!(admit_capabilities(&metadata, &requests), Err(ManagedTaskDriverError::CapabilityNotAdvertised)));
            }
            let metadata = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"sampling":{"tools":{}}}});
            let callback = serde_json::to_value(admit_capabilities(&metadata, &requests).unwrap()).unwrap();
            assert!(callback["sample"]["params"].get("includeContext").is_none());
            assert_eq!(serde_json::to_value(&requests).unwrap(), before);
        }
    }

    #[test]
    fn literal_empty_elicitation_grants_forms_but_unknown_children_do_not() {
        let requests = serde_json::from_value(json!({"form":{"method":"elicitation/create","params":{
            "mode":"form","message":"Approve","requestedSchema":{"type":"object","properties":{}}
        }}})).unwrap();
        let before = serde_json::to_value(&requests).unwrap();
        for elicitation in [json!({}), json!({"form":{}})] {
            let metadata = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"elicitation":elicitation}});
            assert!(admit_capabilities(&metadata, &requests).is_ok());
        }
        for elicitation in [json!({"future":{}}), json!({"url":{}}), json!({"form":null}), json!({"form":[]})] {
            let metadata = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"elicitation":elicitation}});
            assert!(matches!(admit_capabilities(&metadata, &requests), Err(ManagedTaskDriverError::CapabilityNotAdvertised)));
        }
        assert_eq!(serde_json::to_value(&requests).unwrap(), before);
    }

    #[test]
    fn context_normalization_changes_only_ungranted_resolver_copies() {
        let plain = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"roots":{},"sampling":{}}});
        let granted = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"roots":{},"sampling":{"context":{}}}});
        for context in [None, Some("none"), Some("thisServer"), Some("allServers")] {
            let mut params = json!({"messages":[],"maxTokens":1});
            if let Some(context) = context { params["includeContext"] = json!(context); }
            let requests = serde_json::from_value(json!({
                "roots":{"method":"roots/list"},
                "sample":{"method":"sampling/createMessage","params":params}
            })).unwrap();
            let before = serde_json::to_value(&requests).unwrap();
            let callback = serde_json::to_value(admit_capabilities(&plain, &requests).unwrap()).unwrap();
            if context.is_some_and(|context| context != "none") {
                assert!(callback["sample"]["params"].get("includeContext").is_none());
                assert_eq!(callback["roots"], before["roots"]);
            } else {
                assert_eq!(callback, before);
            }
            assert_eq!(serde_json::to_value(admit_capabilities(&granted, &requests).unwrap()).unwrap(), before);
            assert_eq!(serde_json::to_value(&requests).unwrap(), before);
        }
    }

    #[test]
    fn update_identity_bytes_cannot_displace_acknowledged_input_custody() {
        let mut state = DriverState::default();
        let policy = ManagedTaskDriverPolicy::default();
        let (_, fingerprints) = state.unanswered(&inputs(), policy).unwrap();
        let exact = "one".len() + 32;
        assert!(state.answer_bytes(&["one".to_owned()], &fingerprints, exact).is_ok());
        state.reserve_ids(&ids(3, 4), exact).unwrap();
        assert!(matches!(state.answer_bytes(&["one".to_owned()], &fingerprints, exact), Err(ManagedTaskDriverError::StateByteLimit)));
        assert!(state.answered.is_empty());
    }
}
