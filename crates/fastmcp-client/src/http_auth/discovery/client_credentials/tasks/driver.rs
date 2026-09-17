//! Bounded lifecycle observation for machine-authenticated Tasks.
//!
//! Polls the existing Tasks client, retaining fresh same-token discovery before
//! every get. No task is created, automatically cancelled, or resumed here.
//! Dropping the future stops local observation; it does not undo remote work.

use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use asupersync::Cx;
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::tasks_extension::{Task, TaskId};
use fastmcp_protocol::{CorrelationKey, RequestId};

pub use crate::http_auth::managed::tasks::driver::ManagedTaskRunOutcome;
use super::{BoundedBody, ClientCredentialsTasksClient, ClientCredentialsTasksError,
    ManagedTaskEvent, ManagedTaskRequest};
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
        mut next_ids: I,
        mut observe: O,
    ) -> Result<ManagedTaskRunOutcome, ClientCredentialsTaskWaitError>
    where
        I: FnMut() -> Result<(RequestId, RequestId), ClientCredentialsTaskWaitError>,
        O: FnMut(&Task) -> Result<(), ClientCredentialsTaskWaitError>,
    {
        let deadline = discovery_deadline(cx, policy.timeout)
            .map_err(ClientCredentialsError::from)?;
        let owner = &self.client.inner.closed;
        check_wait(cx, deadline, owner, cancellation)?;
        active(cx, deadline, owner, cancellation, None, async {
            Ok(async {
                let mut state = PollState::default();
                let mut due = cx.now();
                loop {
                    check_wait(cx, deadline, owner, cancellation)?;
                    if state.polls >= policy.maximum_polls {
                        return Err(ClientCredentialsTaskWaitError::PollLimit);
                    }
                    if cx.now() < due { Sleep::new(due).await; }
                    check_wait(cx, deadline, owner, cancellation)?;
                    let (discovery, operation) = next_ids()?;
                    check_wait(cx, deadline, owner, cancellation)?;
                    state.reserve(&discovery, &operation, policy)?;
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
                    match next_step(snapshot.task, received_at, policy.minimum_poll_interval)? {
                        PollStep::WaitUntil(next) => due = next,
                        PollStep::Return(outcome) => return Ok(outcome),
                    }
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
}

impl PollState {
    fn reserve(
        &mut self,
        discovery: &RequestId,
        operation: &RequestId,
        policy: ClientCredentialsTaskWaitPolicy,
    ) -> Result<(), ClientCredentialsTaskWaitError> {
        if self.polls >= policy.maximum_polls { return Err(ClientCredentialsTaskWaitError::PollLimit); }
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
            .filter(|bytes| *bytes <= policy.maximum_state_bytes)
            .ok_or(ClientCredentialsTaskWaitError::StateByteLimit)?;
        self.ids.try_reserve(2).map_err(|_| ClientCredentialsTaskWaitError::StateByteLimit)?;
        self.ids.insert(one);
        self.ids.insert(two);
        self.retained_bytes = bytes;
        self.polls += 1;
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
    let peer = task.base().poll_interval_ms.as_ref().map(|hint| hint.try_as_millis())
        .transpose().map_err(|_| ClientCredentialsTaskWaitError::UnexpectedResponse)?
        .map(Duration::from_millis).unwrap_or(minimum);
    let nanos = u64::try_from(peer.max(minimum).as_nanos()).unwrap_or(u64::MAX);
    Ok(PollStep::WaitUntil(received_at.saturating_add_nanos(nanos)))
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
            "completed" => value["result"] = json!({"resultType":"complete","content":[]}),
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
}
