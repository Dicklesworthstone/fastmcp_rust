//! Bounded lifecycle observation and host input for machine-authenticated Tasks.
//!
//! Polls the existing Tasks client, retaining fresh same-token discovery before
//! every get/update. Input resolution is opt-in; observation never answers input.
//! No task is created or automatically cancelled here. Failed POSTs are not retried.
//! Dropping the future stops local observation; it does not undo remote work.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::future::Future;
use std::time::Duration;

use asupersync::Cx;
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_core::{McpRequestCancellation, Sha256Digest, sha256_bounded};
use fastmcp_protocol::tasks_extension::{Task, TaskId, TaskInputLedger, TaskInputRequests, TaskInputResponses};
use fastmcp_protocol::{CorrelationKey, FinalEmbeddedElicitationParams, FinalEmbeddedInputRequest,
    RequestId, FINAL_CLIENT_CAPABILITIES_META_KEY};

pub use crate::http_auth::managed::tasks::driver::{ManagedTaskInputAction, ManagedTaskRunOutcome};
use super::{BoundedBody, ClientCredentialsTasksClient, ClientCredentialsTasksError,
    ManagedTaskEvent, ManagedTaskRequest, ManagedTasksError, prepare};
use super::super::{ClientCredentialsError, OAuthDiscoveryError, active, check_context,
    discovery_deadline};

/// One budget for all polls, grants, discovery, reads, callbacks and sleeps.
#[derive(Clone, Copy, Debug)]
pub struct ClientCredentialsTaskWaitPolicy {
    minimum_poll_interval: Duration,
    timeout: Duration,
    maximum_polls: usize,
    maximum_state_bytes: usize,
}

/// Explicit input-resolution authority in addition to the whole-run wait budget.
/// Zero updates selects observation only, and never invokes the resolver.
#[derive(Clone, Copy, Debug)]
pub struct ClientCredentialsTaskDrivePolicy {
    wait: ClientCredentialsTaskWaitPolicy,
    maximum_updates: usize,
    maximum_input_keys: usize,
}

impl Default for ClientCredentialsTaskDrivePolicy {
    fn default() -> Self {
        Self { wait: ClientCredentialsTaskWaitPolicy::default(), maximum_updates: 32,
            maximum_input_keys: 256 }
    }
}

impl ClientCredentialsTaskDrivePolicy {
    /// Input keys and descriptor fingerprints share the wait policy's byte
    /// budget with request identities. No answers or raw descriptors are retained
    /// after a successful update. Counts bound collection overhead separately.
    pub fn new(wait: ClientCredentialsTaskWaitPolicy, maximum_updates: usize, maximum_input_keys: usize)
        -> Result<Self, ClientCredentialsTaskWaitError>
    {
        if maximum_updates > 128 || maximum_input_keys > 4096 {
            return Err(ClientCredentialsTaskWaitError::InvalidPolicy);
        }
        Ok(Self { wait, maximum_updates, maximum_input_keys })
    }
}

impl Default for ClientCredentialsTaskWaitPolicy {
    fn default() -> Self {
        Self {
            minimum_poll_interval: Duration::from_secs(1),
            timeout: Duration::from_secs(900),
            maximum_polls: 512,
            maximum_state_bytes: 1024 * 1024,
        }
    }
}

impl ClientCredentialsTaskWaitPolicy {
    /// The larger of the local floor and the peer hint controls each next get.
    /// A large peer hint is never shortened to squeeze in another poll before
    /// the deadline. State bytes bound serialized IDs; the poll count separately
    /// bounds collection overhead. Both request IDs remain reserved for the run.
    pub fn new(
        minimum_poll_interval: Duration,
        timeout: Duration,
        maximum_polls: usize,
        maximum_state_bytes: usize,
    ) -> Result<Self, ClientCredentialsTaskWaitError> {
        if minimum_poll_interval.is_zero()
            || minimum_poll_interval > Duration::from_secs(60)
            || timeout.is_zero()
            || timeout > Duration::from_secs(86_400)
            || !(1..=4096).contains(&maximum_polls)
            || !(1..=4 * 1024 * 1024).contains(&maximum_state_bytes)
        {
            return Err(ClientCredentialsTaskWaitError::InvalidPolicy);
        }
        Ok(Self { minimum_poll_interval, timeout, maximum_polls, maximum_state_bytes })
    }
}

/// Sanitized failures. No task ID, callback text, token, or peer body is retained.
#[derive(Debug)]
pub enum ClientCredentialsTaskWaitError {
    InvalidPolicy,
    PollLimit,
    UpdateLimit,
    InputLimit,
    InvalidInputResponse,
    InputKeyReused,
    CapabilityNotAdvertised,
    InvalidRequestIds,
    RepeatedRequestId,
    StateByteLimit,
    UnexpectedResponse,
    AbortedByHost,
    Task(ClientCredentialsTasksError),
}

impl fmt::Display for ClientCredentialsTaskWaitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => f.write_str("invalid machine Task wait policy"),
            Self::PollLimit => f.write_str("machine Task poll budget exhausted"),
            Self::UpdateLimit => f.write_str("machine Task input-update budget exhausted"),
            Self::InputLimit => f.write_str("machine Task input-key budget exhausted"),
            Self::InvalidInputResponse => f.write_str("host answers do not match unresolved Task input"),
            Self::InputKeyReused => f.write_str("Task reused an answered key with a different descriptor"),
            Self::CapabilityNotAdvertised => f.write_str("Task input requires an unadvertised client capability"),
            Self::InvalidRequestIds => f.write_str("invalid machine Task request identities"),
            Self::RepeatedRequestId => f.write_str("machine Task request identity already used"),
            Self::StateByteLimit => f.write_str("machine Task retained-state budget exhausted"),
            Self::UnexpectedResponse => f.write_str("machine Task wait received an unexpected response"),
            Self::AbortedByHost => f.write_str("machine Task wait stopped by its host"),
            Self::Task(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for ClientCredentialsTaskWaitError {}
impl From<ClientCredentialsTasksError> for ClientCredentialsTaskWaitError {
    fn from(error: ClientCredentialsTasksError) -> Self { Self::Task(error) }
}
impl From<ClientCredentialsError> for ClientCredentialsTaskWaitError {
    fn from(error: ClientCredentialsError) -> Self { Self::Task(error.into()) }
}
impl From<ManagedTasksError> for ClientCredentialsTaskWaitError {
    fn from(error: ManagedTasksError) -> Self { Self::Task(error.into()) }
}

impl ClientCredentialsTasksClient {
    /// Observes an existing Task until a terminal snapshot or input-required.
    ///
    /// The first get is immediate. `next_ids` returns distinct discovery and
    /// operation IDs before each poll. Numeric aliases count as the same ID;
    /// string and numeric IDs remain distinct. No identity is reused during the
    /// run. A failed get, discovery, grant, or callback ends the run, not a retry.
    ///
    /// `observe` sees each admitted snapshot once, including unchanged ones.
    /// Input-required returns to the host without answering it. Completed,
    /// Failed and Cancelled retain their different protocol meanings in the
    /// terminal outcome. Starting another wait is an explicit new observation,
    /// not an exactly-once, replay, persistence, or remote-cancellation guarantee.
    pub async fn wait_task<I, O>(
        &self,
        cx: &Cx,
        task_id: TaskId,
        policy: ClientCredentialsTaskWaitPolicy,
        next_ids: I,
        observe: O,
    ) -> Result<ManagedTaskRunOutcome, ClientCredentialsTaskWaitError>
    where
        I: FnMut() -> Result<(RequestId, RequestId), ClientCredentialsTaskWaitError>,
        O: FnMut(&Task) -> Result<(), ClientCredentialsTaskWaitError>,
    {
        self.wait_task_with_cancellation(cx, &McpRequestCancellation::new(), task_id,
            policy, next_ids, observe).await
    }

    /// Cancellation and machine-owner closure wake pending sleeps and reads.
    /// Neither cancels the caller's Cx, a sibling call, or the remote Task.
    /// Grants may renew between polls, but discovery and get always use one
    /// snapshot, and expiry during an individual call still retires that call.
    /// Synchronous host callbacks must cooperate; they cannot be preempted, but
    /// a callback returning after cancellation/deadline cannot trigger a POST.
    #[allow(clippy::too_many_arguments)]
    pub async fn wait_task_with_cancellation<I, O>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: TaskId,
        policy: ClientCredentialsTaskWaitPolicy,
        next_ids: I,
        observe: O,
    ) -> Result<ManagedTaskRunOutcome, ClientCredentialsTaskWaitError>
    where
        I: FnMut() -> Result<(RequestId, RequestId), ClientCredentialsTaskWaitError>,
        O: FnMut(&Task) -> Result<(), ClientCredentialsTaskWaitError>,
    {
        self.drive_task_with_cancellation(cx, cancellation, task_id,
            ClientCredentialsTaskDrivePolicy { wait: policy, maximum_updates: 0, maximum_input_keys: 0 },
            next_ids, |_| std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller)), observe).await
    }

    /// Follows a Task and explicitly resolves input through the host callback.
    /// The resolver receives only keys not successfully answered earlier in this
    /// run. A response may be a nonempty subset; unknown keys, wrong response
    /// kinds, and reused keys with changed descriptors fail before a POST.
    /// The immutable advertised roots/sampling/elicitation capabilities gate
    /// resolver invocation. There is no automatic model, browser, or roots access.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task<I, R, F, O>(
        &self, cx: &Cx, task_id: TaskId, policy: ClientCredentialsTaskDrivePolicy,
        next_ids: I, resolve: R, observe: O,
    ) -> Result<ManagedTaskRunOutcome, ClientCredentialsTaskWaitError>
    where
        I: FnMut() -> Result<(RequestId, RequestId), ClientCredentialsTaskWaitError>,
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ClientCredentialsTaskWaitError>>,
        O: FnMut(&Task) -> Result<(), ClientCredentialsTaskWaitError>,
    {
        self.drive_task_with_cancellation(cx, &McpRequestCancellation::new(), task_id,
            policy, next_ids, resolve, observe).await
    }

    /// One deadline/cancellation domain includes all polls, resolver futures and
    /// updates. Only an admitted update acknowledgement advances the answered-key
    /// ledger. An uncertain update returns an error and issues no further POST.
    /// An unchanged stale snapshot cannot cause duplicate resolver work or repeat
    /// an acknowledged answer. This ledger is local to the run; restarting is
    /// an explicit new operation and requires reconciling remote state first.
    /// Descriptor fingerprints are representation-sensitive, not semantic hashes.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task_with_cancellation<I, R, F, O>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, task_id: TaskId,
        policy: ClientCredentialsTaskDrivePolicy, mut next_ids: I, mut resolve: R, mut observe: O,
    ) -> Result<ManagedTaskRunOutcome, ClientCredentialsTaskWaitError>
    where
        I: FnMut() -> Result<(RequestId, RequestId), ClientCredentialsTaskWaitError>,
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ClientCredentialsTaskWaitError>>,
        O: FnMut(&Task) -> Result<(), ClientCredentialsTaskWaitError>,
    {
        let deadline = discovery_deadline(cx, policy.wait.timeout)
            .map_err(ClientCredentialsError::from)?;
        let owner = &self.client.inner.closed;
        check_wait(cx, deadline, owner, cancellation)?;
        active(cx, deadline, owner, cancellation, None, async {
            Ok(async {
                let mut state = PollState::default();
                let mut due = cx.now();
                let mut updates = 0;
                loop {
                    check_wait(cx, deadline, owner, cancellation)?;
                    if state.polls >= policy.wait.maximum_polls {
                        return Err(ClientCredentialsTaskWaitError::PollLimit);
                    }
                    if cx.now() < due { Sleep::new(due).await; }
                    check_wait(cx, deadline, owner, cancellation)?;
                    let (discovery, operation) = next_ids()?;
                    check_wait(cx, deadline, owner, cancellation)?;
                    state.reserve(&discovery, &operation, policy.wait)?;
                    check_wait(cx, deadline, owner, cancellation)?;
                    let mut call = self.request_with_cancellation(cx, cancellation,
                        discovery, operation, ManagedTaskRequest::Get(task_id.clone())).await?;
                    let Some(ManagedTaskEvent::Snapshot(snapshot)) = call.next_event(cx).await? else {
                        return Err(ClientCredentialsTaskWaitError::UnexpectedResponse);
                    };
                    drop(call);
                    let received_at = cx.now();
                    check_wait(cx, deadline, owner, cancellation)?;
                    observe(&snapshot.task)?;
                    check_wait(cx, deadline, owner, cancellation)?;
                    let task = match next_step(snapshot.task, received_at, policy.wait.minimum_poll_interval)? {
                        PollStep::WaitUntil(next) => { due = next; continue; }
                        PollStep::Return(ManagedTaskRunOutcome::Terminal(task)) => {
                            return Ok(ManagedTaskRunOutcome::Terminal(task));
                        }
                        PollStep::Return(ManagedTaskRunOutcome::InputRequired(task)) => {
                            if policy.maximum_updates == 0 {
                                return Ok(ManagedTaskRunOutcome::InputRequired(task));
                            }
                            // Anchor the peer hint to snapshot receipt, not to
                            // completion of a possibly slow host resolver.
                            due = next_poll_time(&task, received_at, policy.wait.minimum_poll_interval)?;
                            task
                        }
                    };
                    let Task::InputRequired { input_requests, .. } = &*task else {
                        return Err(ClientCredentialsTaskWaitError::UnexpectedResponse);
                    };
                    let (pending, fingerprints) = state.unanswered(input_requests, policy)?;
                    if pending.is_empty() { continue; }
                    if updates >= policy.maximum_updates { return Err(ClientCredentialsTaskWaitError::UpdateLimit); }
                    admit_capabilities(&self.metadata, &pending)?;
                    check_wait(cx, deadline, owner, cancellation)?;
                    let resolution = resolve(pending.clone());
                    check_wait(cx, deadline, owner, cancellation)?;
                    let action = resolution.await?;
                    check_wait(cx, deadline, owner, cancellation)?;
                    let ManagedTaskInputAction::Respond(responses) = action else {
                        return Ok(ManagedTaskRunOutcome::InputRequired(task));
                    };
                    validate_answers(&pending, &responses)?;
                    let answered: Vec<_> = responses.keys().cloned().collect();
                    // Bound serialization before cloning host-authored answers
                    // into the protocol preflight and before any grant/discovery.
                    let mut encoded = BoundedBody { bytes: Vec::new(), maximum: self.limits.request_bytes };
                    serde_json::to_writer(&mut encoded, &responses)
                        .map_err(|_| ManagedTasksError::RequestTooLarge)?;
                    drop(encoded);
                    let _ = prepare(self.client.resource().as_str(), &self.metadata, &RequestId::Number(0),
                        ManagedTaskRequest::Update { task: task.clone(), input_responses: responses.clone() }, self.limits)?;
                    check_wait(cx, deadline, owner, cancellation)?;
                    let (discovery, operation) = next_ids()?;
                    check_wait(cx, deadline, owner, cancellation)?;
                    let after_answers = state.answer_bytes(&answered, &fingerprints, policy.wait.maximum_state_bytes)?;
                    let answer_bytes = after_answers - state.retained_bytes;
                    // Reserve room for both IDs AND the acknowledged ledger
                    // before the mutating POST; budget failure cannot follow ACK.
                    state.reserve_ids(&discovery, &operation,
                        policy.wait.maximum_state_bytes.saturating_sub(answer_bytes))?;
                    updates += 1;
                    check_wait(cx, deadline, owner, cancellation)?;
                    let mut call = self.request_with_cancellation(cx, cancellation, discovery, operation,
                        ManagedTaskRequest::Update { task, input_responses: responses }).await?;
                    if !matches!(call.next_event(cx).await?, Some(ManagedTaskEvent::Updated(_))) {
                        return Err(ClientCredentialsTaskWaitError::UnexpectedResponse);
                    }
                    check_wait(cx, deadline, owner, cancellation)?;
                    state.record_answers(&answered, &fingerprints, policy.wait.maximum_state_bytes)?;
                }
            }.await)
        }).await.map_err(ClientCredentialsTaskWaitError::from)?
    }
}

fn check_wait(
    cx: &Cx,
    deadline: Time,
    owner: &McpRequestCancellation,
    cancellation: &McpRequestCancellation,
) -> Result<(), ClientCredentialsTaskWaitError> {
    if owner.is_cancel_requested() { return Err(ClientCredentialsError::Closed.into()); }
    if cancellation.is_cancel_requested() {
        return Err(ClientCredentialsError::from(OAuthDiscoveryError::Cancelled).into());
    }
    check_context(cx, deadline).map_err(ClientCredentialsError::from)?;
    Ok(())
}

#[derive(Default)]
struct PollState {
    ids: HashSet<CorrelationKey>,
    retained_bytes: usize,
    polls: usize,
    answered: BTreeMap<String, Sha256Digest>,
}

impl PollState {
    fn reserve(
        &mut self,
        discovery: &RequestId,
        operation: &RequestId,
        policy: ClientCredentialsTaskWaitPolicy,
    ) -> Result<(), ClientCredentialsTaskWaitError> {
        if self.polls >= policy.maximum_polls { return Err(ClientCredentialsTaskWaitError::PollLimit); }
        self.reserve_ids(discovery, operation, policy.maximum_state_bytes)?;
        self.polls += 1;
        Ok(())
    }

    fn reserve_ids(&mut self, discovery: &RequestId, operation: &RequestId, maximum: usize)
        -> Result<(), ClientCredentialsTaskWaitError>
    {
        discovery.validate().map_err(|_| ClientCredentialsTaskWaitError::InvalidRequestIds)?;
        operation.validate().map_err(|_| ClientCredentialsTaskWaitError::InvalidRequestIds)?;
        let one = discovery.correlation_key().map_err(|_| ClientCredentialsTaskWaitError::InvalidRequestIds)?;
        let two = operation.correlation_key().map_err(|_| ClientCredentialsTaskWaitError::InvalidRequestIds)?;
        if one == two || self.ids.contains(&one) || self.ids.contains(&two) {
            return Err(ClientCredentialsTaskWaitError::RepeatedRequestId);
        }
        let mut encoded = BoundedBody { bytes: Vec::new(), maximum: 8192 };
        serde_json::to_writer(&mut encoded, &(discovery, operation))
            .map_err(|_| ClientCredentialsTaskWaitError::InvalidRequestIds)?;
        let bytes = self.retained_bytes.checked_add(encoded.bytes.len())
            .filter(|bytes| *bytes <= maximum)
            .ok_or(ClientCredentialsTaskWaitError::StateByteLimit)?;
        self.ids.try_reserve(2).map_err(|_| ClientCredentialsTaskWaitError::StateByteLimit)?;
        self.ids.insert(one);
        self.ids.insert(two);
        self.retained_bytes = bytes;
        Ok(())
    }

    fn unanswered(&self, requests: &TaskInputRequests, policy: ClientCredentialsTaskDrivePolicy)
        -> Result<(TaskInputRequests, BTreeMap<String, Sha256Digest>), ClientCredentialsTaskWaitError>
    {
        let mut pending = TaskInputRequests::new();
        let mut fingerprints = BTreeMap::new();
        let mut bytes = self.retained_bytes;
        for (key, request) in requests {
            let mut encoded = BoundedBody { bytes: Vec::new(), maximum: policy.wait.maximum_state_bytes };
            serde_json::to_writer(&mut encoded, request).map_err(|_| ClientCredentialsTaskWaitError::StateByteLimit)?;
            let fingerprint = sha256_bounded(&encoded.bytes, policy.wait.maximum_state_bytes)
                .map_err(|_| ClientCredentialsTaskWaitError::StateByteLimit)?;
            if let Some(previous) = self.answered.get(key) {
                if previous != &fingerprint { return Err(ClientCredentialsTaskWaitError::InputKeyReused); }
                continue;
            }
            if self.answered.len() + pending.len() >= policy.maximum_input_keys {
                return Err(ClientCredentialsTaskWaitError::InputLimit);
            }
            bytes = bytes.checked_add(key.len()).and_then(|bytes| bytes.checked_add(32))
                .filter(|bytes| *bytes <= policy.wait.maximum_state_bytes)
                .ok_or(ClientCredentialsTaskWaitError::StateByteLimit)?;
            pending.insert(key.clone(), request.clone());
            fingerprints.insert(key.clone(), fingerprint);
        }
        Ok((pending, fingerprints))
    }

    fn answer_bytes(&self, keys: &[String], fingerprints: &BTreeMap<String, Sha256Digest>, maximum: usize)
        -> Result<usize, ClientCredentialsTaskWaitError>
    {
        let mut bytes = self.retained_bytes;
        for key in keys {
            if self.answered.contains_key(key) || !fingerprints.contains_key(key) {
                return Err(ClientCredentialsTaskWaitError::InvalidInputResponse);
            }
            bytes = bytes.checked_add(key.len()).and_then(|bytes| bytes.checked_add(32))
                .filter(|bytes| *bytes <= maximum)
                .ok_or(ClientCredentialsTaskWaitError::StateByteLimit)?;
        }
        Ok(bytes)
    }

    fn record_answers(&mut self, keys: &[String], fingerprints: &BTreeMap<String, Sha256Digest>, maximum: usize)
        -> Result<(), ClientCredentialsTaskWaitError>
    {
        let bytes = self.answer_bytes(keys, fingerprints, maximum)?;
        for key in keys { self.answered.insert(key.clone(), fingerprints[key].clone()); }
        self.retained_bytes = bytes;
        Ok(())
    }
}

enum PollStep {
    WaitUntil(Time),
    Return(ManagedTaskRunOutcome),
}

fn next_step(task: Task, received_at: Time, minimum: Duration)
    -> Result<PollStep, ClientCredentialsTaskWaitError>
{
    if matches!(&task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
        return Ok(PollStep::Return(ManagedTaskRunOutcome::Terminal(Box::new(task))));
    }
    if matches!(&task, Task::InputRequired { .. }) {
        return Ok(PollStep::Return(ManagedTaskRunOutcome::InputRequired(Box::new(task))));
    }
    Ok(PollStep::WaitUntil(next_poll_time(&task, received_at, minimum)?))
}

fn next_poll_time(task: &Task, received_at: Time, minimum: Duration)
    -> Result<Time, ClientCredentialsTaskWaitError>
{
    let peer = task.base().poll_interval_ms.as_ref().map(|hint| hint.try_as_millis())
        .transpose().map_err(|_| ClientCredentialsTaskWaitError::UnexpectedResponse)?
        .map(Duration::from_millis).unwrap_or(minimum);
    let nanos = u64::try_from(peer.max(minimum).as_nanos()).unwrap_or(u64::MAX);
    Ok(received_at.saturating_add_nanos(nanos))
}

fn validate_answers(requests: &TaskInputRequests, responses: &TaskInputResponses)
    -> Result<(), ClientCredentialsTaskWaitError>
{
    if responses.is_empty() || responses.keys().any(|key| !requests.contains_key(key)) {
        return Err(ClientCredentialsTaskWaitError::InvalidInputResponse);
    }
    TaskInputLedger::from_requests(requests).and_then(|ledger| ledger.validate_responses(responses))
        .map_err(|_| ClientCredentialsTaskWaitError::InvalidInputResponse)
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
mod tests {
    use super::*;
    use serde_json::json;

    fn task(status: &str, hint: Option<u64>) -> Task {
        let mut value = json!({"taskId":"owned-task", "status":status,
            "createdAt":"2026-09-17T00:00:00Z", "lastUpdatedAt":"2026-09-17T00:00:00Z", "ttlMs":null});
        if let Some(hint) = hint { value["pollIntervalMs"] = json!(hint); }
        match status {
            "input_required" => value["inputRequests"] = json!({"roots":{"method":"roots/list"}}),
            "completed" => value["result"] = json!({"content":[]}),
            "failed" => value["error"] = json!({"code":-32603,"message":"remote failure"}),
            _ => {},
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn policy_bounds_wait_time_poll_count_and_retained_id_state() {
        assert!(ClientCredentialsTaskWaitPolicy::new(Duration::from_millis(1), Duration::from_secs(1), 1, 1).is_ok());
        for (floor, timeout, polls, bytes) in [
            (Duration::ZERO, Duration::from_secs(1), 1, 1),
            (Duration::from_secs(1), Duration::ZERO, 1, 1),
            (Duration::from_secs(1), Duration::from_secs(1), 0, 1),
            (Duration::from_secs(1), Duration::from_secs(1), 4097, 1),
            (Duration::from_secs(1), Duration::from_secs(1), 1, 0),
            (Duration::from_secs(1), Duration::from_secs(86_401), 1, 1),
        ] {
            assert!(ClientCredentialsTaskWaitPolicy::new(floor, timeout, polls, bytes).is_err());
        }
    }

    #[test]
    fn peer_poll_hints_never_shorten_the_floor_or_overflow_time() {
        let now = Time::from_nanos(1000);
        for (hint, nanos) in [(None, 100_000_000), (Some(1), 100_000_000), (Some(300), 300_000_000), (Some(u64::MAX), u64::MAX)] {
            let PollStep::WaitUntil(due) = next_step(task("working", hint), now, Duration::from_millis(100)).unwrap() else { panic!("working task must wait") };
            assert_eq!(due, now.saturating_add_nanos(nanos));
        }
    }

    #[test]
    fn input_required_and_terminal_snapshots_return_without_another_poll() {
        let now = Time::from_nanos(1000);
        assert!(matches!(next_step(task("input_required", Some(u64::MAX)), now, Duration::from_secs(1)).unwrap(),
            PollStep::Return(ManagedTaskRunOutcome::InputRequired(_))));
        for status in ["completed", "failed"] {
            let PollStep::Return(ManagedTaskRunOutcome::Terminal(result)) =
                next_step(task(status, Some(u64::MAX)), now, Duration::from_secs(1)).unwrap()
                else { panic!("terminal must not schedule another get") };
            assert_eq!(serde_json::to_value(result).unwrap()["status"], status);
        }
    }

    #[test]
    fn id_reservation_is_atomic_and_rejects_numeric_aliases_not_strings() {
        let mut state = PollState::default();
        let policy = ClientCredentialsTaskWaitPolicy::default();
        state.reserve(&RequestId::Number(1), &RequestId::Number(2), policy).unwrap();
        let before = state.retained_bytes;
        assert!(matches!(state.reserve(&RequestId::Number(3), &RequestId::Number(2), policy), Err(ClientCredentialsTaskWaitError::RepeatedRequestId)));
        assert_eq!(state.retained_bytes, before);
        assert_eq!(state.polls, 1);
        state.reserve(&RequestId::Number(3), &RequestId::Number(4), policy).unwrap();
        let alias: RequestId = serde_json::from_str("2e0").unwrap();
        assert!(matches!(state.reserve(&alias, &RequestId::Number(5), policy), Err(ClientCredentialsTaskWaitError::RepeatedRequestId)));
        state.reserve(&RequestId::String("2".to_owned()), &RequestId::Number(5), policy).unwrap();
        assert!(matches!(state.reserve(&RequestId::Number(6), &RequestId::Number(6), policy), Err(ClientCredentialsTaskWaitError::RepeatedRequestId)));
    }

    #[test]
    fn exhausted_poll_or_byte_budgets_do_not_consume_new_ids() {
        let mut state = PollState::default();
        let mut policy = ClientCredentialsTaskWaitPolicy::default();
        policy.maximum_state_bytes = 1;
        assert!(matches!(state.reserve(&RequestId::Number(1), &RequestId::Number(2), policy), Err(ClientCredentialsTaskWaitError::StateByteLimit)));
        assert_eq!(state.polls, 0);
        assert!(state.ids.is_empty());
        policy.maximum_state_bytes = 4096;
        policy.maximum_polls = 1;
        state.reserve(&RequestId::Number(1), &RequestId::Number(2), policy).unwrap();
        assert!(matches!(state.reserve(&RequestId::Number(3), &RequestId::Number(4), policy), Err(ClientCredentialsTaskWaitError::PollLimit)));
        assert_eq!(state.ids.len(), 2);
    }

    fn inputs() -> TaskInputRequests {
        serde_json::from_value(json!({"one":{"method":"roots/list"}, "two":{"method":"roots/list"}})).unwrap()
    }

    #[test]
    fn partial_answers_advance_only_after_ack_and_stale_snapshots_cannot_repeat_them() {
        let mut state = PollState::default();
        let policy = ClientCredentialsTaskDrivePolicy::default();
        let (pending, fingerprints) = state.unanswered(&inputs(), policy).unwrap();
        let reply: TaskInputResponses = serde_json::from_value(json!({"one":{"roots":[]}})).unwrap();
        validate_answers(&pending, &reply).unwrap();
        state.answer_bytes(&["one".to_owned()], &fingerprints, policy.wait.maximum_state_bytes).unwrap();
        assert_eq!(state.unanswered(&inputs(), policy).unwrap().0.len(), 2,
            "preflight alone must not acknowledge any input");
        state.record_answers(&["one".to_owned()], &fingerprints, policy.wait.maximum_state_bytes).unwrap();
        let (remaining, fingerprints) = state.unanswered(&inputs(), policy).unwrap();
        assert_eq!(remaining.keys().map(String::as_str).collect::<Vec<_>>(), ["two"]);
        assert!(validate_answers(&remaining, &reply).is_err());
        state.record_answers(&["two".to_owned()], &fingerprints, policy.wait.maximum_state_bytes).unwrap();
        assert!(state.unanswered(&inputs(), policy).unwrap().0.is_empty());
    }

    #[test]
    fn changed_answered_descriptors_are_rejected_without_mutating_the_ledger() {
        let mut state = PollState::default();
        let policy = ClientCredentialsTaskDrivePolicy::default();
        let (_, fingerprints) = state.unanswered(&inputs(), policy).unwrap();
        state.record_answers(&["one".to_owned()], &fingerprints, policy.wait.maximum_state_bytes).unwrap();
        let before = state.retained_bytes;
        let changed = serde_json::from_value(json!({"one":{"method":"sampling/createMessage",
            "params":{"messages":[],"maxTokens":16}}})).unwrap();
        assert!(matches!(state.unanswered(&changed, policy), Err(ClientCredentialsTaskWaitError::InputKeyReused)));
        assert_eq!(state.retained_bytes, before);
        assert_eq!(state.answered.len(), 1);
    }

    #[test]
    fn empty_foreign_and_wrong_kind_input_answers_do_not_pass_preflight() {
        for wire in [json!({}), json!({"other":{"roots":[]}}), json!({"one":{"action":"decline"}})] {
            let responses: TaskInputResponses = serde_json::from_value(wire).unwrap();
            assert!(matches!(validate_answers(&inputs(), &responses), Err(ClientCredentialsTaskWaitError::InvalidInputResponse)));
        }
        let responses: TaskInputResponses = serde_json::from_value(json!({"one":{"roots":[]}})).unwrap();
        assert!(validate_answers(&inputs(), &responses).is_ok());
    }

    #[test]
    fn update_ids_share_reservations_but_do_not_consume_poll_slots() {
        let mut state = PollState::default();
        let policy = ClientCredentialsTaskDrivePolicy::default();
        state.reserve(&RequestId::Number(1), &RequestId::Number(2), policy.wait).unwrap();
        let (_, fingerprints) = state.unanswered(&inputs(), policy).unwrap();
        let keys = vec!["one".to_owned()];
        let after = state.answer_bytes(&keys, &fingerprints, policy.wait.maximum_state_bytes).unwrap();
        let answer_bytes = after - state.retained_bytes;
        state.reserve_ids(&RequestId::Number(3), &RequestId::Number(4),
            policy.wait.maximum_state_bytes - answer_bytes).unwrap();
        state.record_answers(&keys, &fingerprints, policy.wait.maximum_state_bytes).unwrap();
        assert_eq!(state.polls, 1);
        assert!(matches!(state.reserve(&RequestId::Number(5), &RequestId::Number(4), policy.wait),
            Err(ClientCredentialsTaskWaitError::RepeatedRequestId)));
        state.reserve(&RequestId::Number(5), &RequestId::Number(6), policy.wait).unwrap();
        assert_eq!(state.polls, 2);
    }

    #[test]
    fn input_key_and_combined_byte_bounds_refuse_before_ledger_changes() {
        let mut state = PollState::default();
        let mut policy = ClientCredentialsTaskDrivePolicy::default();
        policy.maximum_input_keys = 1;
        assert!(matches!(state.unanswered(&inputs(), policy), Err(ClientCredentialsTaskWaitError::InputLimit)));
        assert!(state.answered.is_empty());
        policy.maximum_input_keys = 2;
        let (_, fingerprints) = state.unanswered(&inputs(), policy).unwrap();
        let keys = vec!["one".to_owned()];
        let answer_bytes = state.answer_bytes(&keys, &fingerprints, 4096).unwrap();
        assert!(matches!(state.reserve_ids(&RequestId::Number(1), &RequestId::Number(2), 1),
            Err(ClientCredentialsTaskWaitError::StateByteLimit)));
        assert!(state.ids.is_empty());
        state.reserve_ids(&RequestId::Number(1), &RequestId::Number(2), 4096).unwrap();
        let before = state.retained_bytes;
        assert!(matches!(state.record_answers(&keys, &fingerprints, before + answer_bytes - 1),
            Err(ClientCredentialsTaskWaitError::StateByteLimit)));
        assert!(state.answered.is_empty());
        assert_eq!(state.retained_bytes, before);
        state.record_answers(&keys, &fingerprints, before + answer_bytes).unwrap();
    }

    #[test]
    fn input_resolution_requires_the_advertised_capability_not_just_tasks() {
        let absent = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"extensions":{}}});
        assert!(matches!(admit_capabilities(&absent, &inputs()), Err(ClientCredentialsTaskWaitError::CapabilityNotAdvertised)));
        let roots = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"roots":{}}});
        assert!(admit_capabilities(&roots, &inputs()).is_ok());
        let sampling: TaskInputRequests = serde_json::from_value(json!({"sample":{"method":"sampling/createMessage",
            "params":{"messages":[],"maxTokens":16,"includeContext":"allServers"}}})).unwrap();
        let ordinary = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"sampling":{}}});
        assert!(matches!(admit_capabilities(&ordinary, &sampling), Err(ClientCredentialsTaskWaitError::CapabilityNotAdvertised)));
        let context = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"sampling":{"context":{}}}});
        assert!(admit_capabilities(&context, &sampling).is_ok());
    }

    #[test]
    fn local_cancellation_and_owner_closure_leave_sibling_domains_untouched() {
        let cx = Cx::for_testing();
        let owner = McpRequestCancellation::new();
        let cancelled = McpRequestCancellation::new();
        let sibling = McpRequestCancellation::new();
        cancelled.cancel();
        assert!(matches!(check_wait(&cx, Time::from_nanos(u64::MAX), &owner, &cancelled),
            Err(ClientCredentialsTaskWaitError::Task(ClientCredentialsTasksError::Authentication(
                ClientCredentialsError::Discovery(OAuthDiscoveryError::Cancelled))))));
        assert!(!owner.is_cancel_requested());
        assert!(!sibling.is_cancel_requested());
        owner.cancel();
        assert!(matches!(check_wait(&cx, Time::from_nanos(u64::MAX), &owner, &sibling),
            Err(ClientCredentialsTaskWaitError::Task(ClientCredentialsTasksError::Authentication(ClientCredentialsError::Closed)))));
        assert!(!sibling.is_cancel_requested());
        assert!(cx.checkpoint().is_ok());
    }
}
