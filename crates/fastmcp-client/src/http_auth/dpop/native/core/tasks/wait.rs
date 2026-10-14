//! Caller-driven, observation-only waiting for a DPoP-protected Task.
//!
//! Every poll is a freshly negotiated discovery/get pair. No creating call,
//! input answer or remote cancellation is ever replayed by this owner.

use std::fmt;
use std::time::Duration;

use asupersync::Time;
use asupersync::time::Sleep;

use super::{
    Cx, DpopCredential, DpopHttpClient, DpopHttpError, DpopTaskOperation, DpopTasksError,
    FinalRequestMeta, GetTaskResult, ManagedCoreError, ManagedCoreLimits, ManagedTaskEvent,
    ManagedTaskRequest, McpRequestCancellation, RequestId, Task, TaskId, WaitBounds, check_live,
};
use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::within;

/// Finite scheduling bounds for one explicit observation run.
/// The response-byte and absolute-time bounds come from `ManagedCoreLimits`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpopTaskWaitPolicy {
    maximum_polls: usize,
    minimum_poll_interval: Duration,
}

impl Default for DpopTaskWaitPolicy {
    fn default() -> Self {
        Self {
            maximum_polls: 64,
            minimum_poll_interval: Duration::from_millis(500),
        }
    }
}

impl DpopTaskWaitPolicy {
    /// Admit 1..=1024 get operations and a nonzero local interval of at most
    /// one minute. A peer's `pollIntervalMs` may lengthen, never shorten it.
    /// The first discovery/get starts immediately; subsequent pairs wait.
    pub fn new(
        maximum_polls: usize,
        minimum_poll_interval: Duration,
    ) -> Result<Self, DpopTaskWaitError> {
        if !(1..=1024).contains(&maximum_polls)
            || minimum_poll_interval.is_zero()
            || minimum_poll_interval > Duration::from_mins(1)
        {
            return Err(DpopTaskWaitError::InvalidPolicy);
        }
        Ok(Self {
            maximum_polls,
            minimum_poll_interval,
        })
    }
}

/// A complete admitted snapshot, not proof of continuing access or a reusable
/// continuation. Failed and cancelled Tasks remain their exact typed states.
/// Input-required is a handoff to the host, not permission to answer inputs.
/// Debug deliberately omits task identifiers, results, errors and input data.
pub enum DpopTaskWaitOutcome {
    Terminal(Box<GetTaskResult>),
    InputRequired(Box<GetTaskResult>),
}

impl fmt::Debug for DpopTaskWaitOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Terminal(_) => "DpopTaskWaitOutcome::Terminal(..)",
            Self::InputRequired(_) => "DpopTaskWaitOutcome::InputRequired(..)",
        })
    }
}

/// Refusals never retain a task ID, prefix, credential or peer diagnostic.
#[derive(Debug)]
pub enum DpopTaskWaitError {
    InvalidPolicy,
    InvalidIdPrefix,
    PollLimit,
    InvalidPollInterval,
    UnexpectedResponse,
    Task(DpopTasksError),
}

impl fmt::Display for DpopTaskWaitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid DPoP Task wait policy",
            Self::InvalidIdPrefix => "invalid DPoP Task wait identity prefix",
            Self::PollLimit => "DPoP Task observation poll limit reached",
            Self::InvalidPollInterval => "Task polling interval cannot be represented",
            Self::UnexpectedResponse => "Task observation requires an admitted get snapshot",
            Self::Task(error) => return error.fmt(f),
        })
    }
}

impl std::error::Error for DpopTaskWaitError {}
impl From<DpopTasksError> for DpopTaskWaitError {
    fn from(error: DpopTasksError) -> Self {
        Self::Task(error)
    }
}
impl From<DpopHttpError> for DpopTaskWaitError {
    fn from(error: DpopHttpError) -> Self {
        Self::Task(error.into())
    }
}
impl From<ManagedCoreError> for DpopTaskWaitError {
    fn from(error: ManagedCoreError) -> Self {
        Self::Task(error.into())
    }
}

// No snapshot history or reusable cursor is retained. Unique IDs are derived
// from one bounded, caller-selected namespace and a bounded monotonic counter.
struct PollState {
    prefix: String,
    started: usize,
    remaining_bytes: usize,
    policy: DpopTaskWaitPolicy,
    limits: ManagedCoreLimits,
}

impl PollState {
    fn new(
        prefix: &str,
        policy: DpopTaskWaitPolicy,
        limits: ManagedCoreLimits,
    ) -> Result<Self, DpopTaskWaitError> {
        if prefix.is_empty()
            || prefix.len() > 128
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        {
            return Err(DpopTaskWaitError::InvalidIdPrefix);
        }
        Ok(Self {
            prefix: prefix.to_owned(),
            started: 0,
            remaining_bytes: limits.total_bytes(),
            policy,
            limits,
        })
    }

    fn check_available(&self) -> Result<(), DpopTaskWaitError> {
        if self.started >= self.policy.maximum_polls {
            return Err(DpopTaskWaitError::PollLimit);
        }
        if self.remaining_bytes == 0 {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        Ok(())
    }

    fn begin(
        &mut self,
        id: &TaskId,
    ) -> Result<(DpopTaskOperation, ManagedCoreLimits), DpopTaskWaitError> {
        self.check_available()?;
        // Narrow both frame and total bounds before discovery. Successful
        // discovery then reserves only the remainder for the get response.
        let limits = ManagedCoreLimits::new(
            self.limits.request_bytes(),
            self.limits.frame_bytes().min(self.remaining_bytes),
            self.remaining_bytes,
            0,
            self.limits.timeout(),
        )?;
        let operation = DpopTaskOperation::new(
            RequestId::String(format!("{}.{}.discover", self.prefix, self.started)),
            RequestId::String(format!("{}.{}.get", self.prefix, self.started)),
            ManagedTaskRequest::Get(id.clone()),
        )
        .map_err(DpopTasksError::from)?;
        self.started += 1;
        Ok((operation, limits))
    }

    fn record(&mut self, bytes: usize) -> Result<(), DpopTaskWaitError> {
        let remaining = self
            .remaining_bytes
            .checked_sub(bytes)
            .ok_or(ManagedCoreError::ResponseByteLimit)?;
        self.remaining_bytes = remaining;
        Ok(())
    }
}

fn next_poll_time(
    now: Time,
    task: &Task,
    minimum: Duration,
) -> Result<Time, DpopTaskWaitError> {
    let peer = task
        .base()
        .poll_interval_ms
        .as_ref()
        .map(|hint| hint.try_as_millis())
        .transpose()
        .map_err(|_| DpopTaskWaitError::InvalidPollInterval)?
        .map(Duration::from_millis)
        .unwrap_or(minimum);
    let nanos = u64::try_from(peer.max(minimum).as_nanos()).unwrap_or(u64::MAX);
    Ok(now.saturating_add_nanos(nanos))
}

async fn pause(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    session: &DpopSession,
    credential: &DpopCredential,
    bounds: WaitBounds,
    due: Time,
) -> Result<(), DpopHttpError> {
    // The same guard used for HTTPS also owns the silent interval. It retires
    // timer and revocation registrations on drop and intersects the host's
    // effect ceiling at every poll; an unrelated ambient clock is never used.
    within(cx, cancellation, session, credential, bounds, async {
        if cx.now() < due {
            Sleep::new(due).await;
        }
        Ok(())
    })
    .await
}

impl DpopHttpClient {
    /// Observe a Task until it completes, fails, is cancelled, or needs input.
    ///
    /// Every poll performs fresh authenticated discovery and then `tasks/get`
    /// against this client's exact resource, using the SAME original credential.
    /// One deadline, bounded by the native/core timeout and caller/token expiry,
    /// spans preparation, discovery, every get, decoding and all poll intervals.
    /// No token renewal, challenge retry, mutation or input callback is performed.
    ///
    /// `limits.total_bytes` is cumulative across ALL discovery and get response
    /// bodies, including JSON-RPC envelopes. Per-frame/request and native body
    /// limits still apply. Each successful pair charges its actual received
    /// lengths; changing IDs never replenishes byte or time budgets. Intermediate
    /// snapshots are discarded. Errors do not return a stale or partial success.
    ///
    /// The first poll is immediate. After a working snapshot, the next pair
    /// waits at least the policy interval or the peer's longer `pollIntervalMs`,
    /// measured from receipt/admission of that snapshot on the caller's clock.
    /// A long hint never shortens the original deadline or authorizes busy polling.
    /// An input-required snapshot returns immediately for explicit host handling.
    /// Remote failure is returned as a terminal Task, not a local transport error.
    ///
    /// Select a unique `id_prefix` for each logical operation in this endpoint's
    /// namespace (1..=128 ASCII letters, digits, underscore, dot or dash). It is
    /// not an idempotency key. This is a native JSON-response observation helper,
    /// not a subscription, durable resume owner or proof of authorization to act
    /// on the returned snapshot. Dropping the future stops local observation.
    #[allow(clippy::too_many_arguments)]
    pub async fn wait_task(
        &mut self,
        cx: &Cx,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        task_id: TaskId,
        id_prefix: &str,
        policy: DpopTaskWaitPolicy,
        limits: ManagedCoreLimits,
    ) -> Result<DpopTaskWaitOutcome, DpopTaskWaitError> {
        self.wait_task_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            credential,
            metadata,
            task_id,
            id_prefix,
            policy,
            limits,
        )
        .await
    }

    /// Request-local cancellation also wakes a silent poll interval. It does
    /// not send `tasks/cancel`, revoke the login, or cancel sibling requests.
    /// A get already committed remotely cannot be recalled by dropping its owner.
    #[allow(clippy::too_many_arguments)]
    pub async fn wait_task_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        task_id: TaskId,
        id_prefix: &str,
        policy: DpopTaskWaitPolicy,
        limits: ManagedCoreLimits,
    ) -> Result<DpopTaskWaitOutcome, DpopTaskWaitError> {
        let bounds = WaitBounds::new(cx, self.policy.timeout.min(limits.timeout()), credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let mut state = PollState::new(id_prefix, policy, limits)?;
        let mut due = cx.now();
        loop {
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            state.check_available()?;
            pause(cx, cancellation, &self.session, credential, bounds, due).await?;
            let (operation, round_limits) = state.begin(&task_id)?;
            let (event, bytes) = self
                .request_task_with_bounds(
                    cx,
                    cancellation,
                    credential,
                    metadata.clone(),
                    operation,
                    round_limits,
                    bounds,
                )
                .await?;
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            state.record(bytes)?;
            let ManagedTaskEvent::Snapshot(snapshot) = event else {
                return Err(DpopTaskWaitError::UnexpectedResponse);
            };
            // This is an observation API. It never interprets remote failure
            // as retry authority or input-required as permission to mutate.
            match &snapshot.task {
                Task::Working(_) => {
                    due = next_poll_time(cx.now(), &snapshot.task, policy.minimum_poll_interval)?;
                }
                Task::InputRequired { .. } => {
                    check_live(cx, cancellation, &self.session, credential, bounds)?;
                    return Ok(DpopTaskWaitOutcome::InputRequired(snapshot));
                }
                Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_) => {
                    check_live(cx, cancellation, &self.session, credential, bounds)?;
                    return Ok(DpopTaskWaitOutcome::Terminal(snapshot));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
