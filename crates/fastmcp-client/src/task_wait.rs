//! Caller-owned, bounded observation of an existing final Task.
//!
//! Waiting only reads Tasks. Explicit stdio input submission and reconciliation
//! use the same caller-owned request machinery; neither replays uncertain work.
//! Remote cancellation, reconnects and persistence remain application actions.

use std::future::Future;
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};

#[cfg(unix)]
use crate::{
    AsyncSubprocessCancellationPolicy, Client, FinalTaskInputLedger, FinalTaskInputResponses,
    FinalTaskInputResume, FinalTaskMethodRequest, FinalTaskRequestMeta, FinalUpdateTaskParams,
    FinalUpdateTaskResult, JsonRpcRequest, ProtocolEra,
};
use crate::http_auth::managed::tasks::watch::checkpoint::resume::timestamp_nanos;
use crate::{FinalTask, FinalTaskHandle, FinalTaskId, HttpClient, HttpClientError};

/// Explicit finite limits for one observation of an already-created Task.
///
/// The fallback applies only when the latest snapshot omits `pollIntervalMs`.
/// A present server suggestion is never shortened to this fallback or to its
/// five-minute configuration ceiling. Per-response transport limits still apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalTaskWaitPolicy {
    timeout: Duration,
    maximum_polls: usize,
    fallback_poll_interval: Duration,
}

impl Default for FinalTaskWaitPolicy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300),
            maximum_polls: 128,
            fallback_poll_interval: Duration::from_secs(1),
        }
    }
}

impl FinalTaskWaitPolicy {
    /// Allows at most 24 hours, 4,096 polls and a five-minute local fallback.
    /// All three limits must be positive. The deadline is fixed when the wait
    /// starts and can only be tightened by the caller's `Cx` deadline or the
    /// Task's finite retention deadline.
    pub fn new(
        timeout: Duration,
        maximum_polls: usize,
        fallback_poll_interval: Duration,
    ) -> McpResult<Self> {
        if timeout.is_zero()
            || timeout > Duration::from_secs(24 * 60 * 60)
            || !(1..=4096).contains(&maximum_polls)
            || fallback_poll_interval.is_zero()
            || fallback_poll_interval > Duration::from_secs(300)
        {
            return Err(McpError::invalid_params("Invalid final Task wait policy"));
        }
        Ok(Self {
            timeout,
            maximum_polls,
            fallback_poll_interval,
        })
    }
}

/// Why one bounded wait returned. The exact latest snapshot, including a
/// completed result or outstanding input descriptors, stays on the handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalTaskWaitOutcome {
    /// The authoritative Task completed. Inspect `handle.task()` for its result.
    Completed,
    /// The authoritative Task failed. Its error remains on the handle.
    Failed,
    /// The authoritative Task reached terminal `cancelled`.
    Cancelled,
    /// The Task requires input. No Host callback or `tasks/update` was invoked.
    InputRequired,
    /// The original local wait budget or caller deadline expired.
    DeadlineElapsed,
    /// The Task's finite `createdAt + ttlMs` retention deadline expired locally.
    /// This does not cancel remote work or erase the last admitted snapshot.
    TaskExpired,
    /// The configured number of authoritative reads was exhausted.
    PollLimitReached,
    /// Local observation was cancelled. This says nothing about remote work.
    ObservationCancelled,
    /// The caller supplied no timer driver, so bounded waiting could not start.
    TimerUnavailable,
}

impl FinalTaskHandle {
    /// Polls until a terminal Task, an input-required pause, or a local bound.
    ///
    /// Every get uses this client's negotiated connection and request-ID
    /// allocator. Use the same client that attached the handle. This method
    /// creates no background task, does not retry a failed request, and never
    /// sends `tasks/update` or `tasks/cancel`. Local cancellation drops only the
    /// in-flight read and keeps the last fully admitted snapshot available.
    ///
    /// Finite `ttlMs` is measured from `createdAt`, not the latest response or
    /// `lastUpdatedAt`. Its remaining lifetime uses the host's wall clock once
    /// at admission and is also anchored to monotonic clocks for this wait.
    /// Later wall-clock advances may shorten it; rollback cannot extend the
    /// admitted wait. This is local expiry observation, not proof of server
    /// deletion or a replacement for server-side authorization and retention.
    /// A null TTL leaves the explicit local wait bounds in force.
    ///
    /// A retained terminal snapshot is data already delivered and returns
    /// immediately, even after retention expires. A retained input-required
    /// snapshot returns immediately only while its retention is live. After
    /// `resume_input` acknowledges an update, explicitly `poll` to reconcile
    /// the state before waiting again. A new invocation is an explicitly new
    /// local budget; it does not claim crash-resume or cross-wait clock custody.
    pub async fn wait(
        &mut self,
        cx: &Cx,
        client: &mut HttpClient,
        cancellation: &McpRequestCancellation,
        policy: FinalTaskWaitPolicy,
    ) -> Result<FinalTaskWaitOutcome, HttpClientError> {
        wait_for_task(self, cx, client, cancellation, policy).await
    }

    /// The same bounded observation over the caller-owned Unix stdio client.
    ///
    /// Reads use the existing yielding stdio request owner. Cancelling,
    /// expiring or dropping the wait retires only that owner; deferred request
    /// cancellation is flushed when the client next drives ingress or closes.
    /// No remote Task cancellation or automatic input effect is performed.
    #[cfg(unix)]
    pub async fn wait_with_stdio(
        &mut self,
        cx: &Cx,
        client: &mut Client,
        cancellation: &McpRequestCancellation,
        policy: FinalTaskWaitPolicy,
    ) -> McpResult<FinalTaskWaitOutcome> {
        wait_for_task(self, cx, client, cancellation, policy).await
    }

    /// Reconciles this handle through one yielding Unix stdio `tasks/get`.
    ///
    /// Use this after an acknowledged input update, which deliberately does
    /// not invent a new Task state. Identity, creation instant and TTL must
    /// still match before the retained snapshot is replaced. A refused read,
    /// cancellation or abandonment leaves the last snapshot unchanged. Use
    /// the same client that attached this handle; the server authorizes reads.
    #[cfg(unix)]
    pub async fn poll_with_stdio(
        &mut self,
        cx: &Cx,
        client: &mut Client,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<&FinalTask> {
        checkpoint_stdio_input(cx, cancellation)?;
        let result = client
            .get_task_final_with_cx(cx, cancellation, self.task_id().clone())
            .await?;
        admit_identity(self.task(), &result.task)?;
        checkpoint_stdio_input(cx, cancellation)?;
        self.task = result.task;
        Ok(&self.task)
    }
}

#[cfg(unix)]
impl Client {
    /// Reads and attaches an existing final Task using the yielding Unix
    /// transport. The handle can then use `wait_with_stdio`; attachment never
    /// repeats a creating call and does not persist the Task ID.
    pub async fn attach_final_task_with_cx(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> McpResult<FinalTaskHandle> {
        self.get_task_final_with_cx(cx, cancellation, task_id)
            .await
            .map(|result| FinalTaskHandle::new(result.task))
    }

    /// Submits explicit Task input responses without blocking the runtime on
    /// the Unix subprocess response wait.
    ///
    /// Phase, response kinds and locally observed finite retention are checked
    /// before initialization or wire effects. The current server still owns
    /// authorization and stale-state admission. No input callback runs here.
    /// This uses the existing typed update codec, negotiated extension, shared
    /// request-ID allocator and request-local cancellation owner.
    ///
    /// The result acknowledges the update; it is not a new Task snapshot.
    /// Cancellation or dropping the future cannot undo an update already sent.
    /// An uncertain update is NEVER automatically replayed. Reconcile using a
    /// fresh `tasks/get` before deciding whether to submit more input. Pipe
    /// writes retain their synchronous commit bound; response waits yield.
    pub async fn update_task_final_with_cx(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task: &FinalTask,
        input_responses: FinalTaskInputResponses,
    ) -> McpResult<FinalUpdateTaskResult> {
        checkpoint_stdio_input(cx, cancellation)?;
        let FinalTask::InputRequired { base, input_requests } = task else {
            return Err(McpError::invalid_request(
                "tasks/update requires an input_required task snapshot",
            ));
        };
        let ledger = FinalTaskInputLedger::from_requests(input_requests)
            .map_err(|_| McpError::invalid_params("Task snapshot has invalid input requests"))?;
        ledger.validate_responses(&input_responses).map_err(|_| {
            McpError::invalid_params(
                "Task input responses do not match the outstanding input request types",
            )
        })?;
        admit_input_retention(task)?;
        self.ensure_initialized_with_cx(cx, cancellation).await?;
        if self.session.protocol_era != Some(ProtocolEra::Modern2026) {
            return Err(McpError::invalid_request(
                "tasks/update is not available on the sealed 2024 adapter",
            ));
        }
        self.admit_final_tasks_method_surface("tasks/update")?;
        checkpoint_stdio_input(cx, cancellation)?;
        // Initialization may have awaited the peer. Do not spend an ID or send
        // a mutation based on retention that expired during that handshake.
        admit_input_retention(task)?;
        let id = self.next_request_id()?;
        let params = FinalUpdateTaskParams {
            request: FinalTaskRequestMeta { meta: self.final_request_meta() },
            task_id: base.task_id.clone(),
            input_responses,
        };
        let value = serde_json::to_value(FinalTaskMethodRequest::new(
            id.clone(), "tasks/update", params,
        ))
        .map_err(|_| McpError::internal_error("Failed to encode final tasks/update request"))?;
        let request = FinalTaskMethodRequest::decode_update(value, &ledger)
            .map_err(|_| McpError::invalid_params("Invalid final tasks/update request"))?;
        let params = serde_json::to_value(request.params)
            .map_err(|_| McpError::internal_error("Failed to encode final tasks/update params"))?;
        let response = self.send_request_response_with_cx(
            cx,
            cancellation,
            JsonRpcRequest::new("tasks/update", Some(params), id),
            self.request_timeout_policy,
            AsyncSubprocessCancellationPolicy::RequestOnly,
            None,
            None,
        ).await?;
        self.decode_final_tasks_response(&response, "tasks/update")
    }
}

#[cfg(unix)]
impl FinalTaskInputResume<'_> {
    /// Flushes this explicit input batch through the yielding Unix stdio path.
    ///
    /// As with HTTP `flush`, consuming the guard does not mutate the handle's
    /// retained snapshot. On success, use `poll_with_stdio` to observe the next
    /// state, then `wait_with_stdio` if it is still working. An error may follow
    /// a committed write: reconcile rather than blindly replaying the batch.
    pub async fn flush_with_stdio(
        self,
        cx: &Cx,
        client: &mut Client,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<FinalUpdateTaskResult> {
        client.update_task_final_with_cx(
            cx, cancellation, &self.handle.task, self.responses,
        ).await
    }
}

#[cfg(unix)]
fn checkpoint_stdio_input(cx: &Cx, cancellation: &McpRequestCancellation) -> McpResult<()> {
    if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
        return Err(McpError::request_cancelled());
    }
    Ok(())
}

#[cfg(unix)]
fn admit_input_retention(task: &FinalTask) -> McpResult<()> {
    if retention_deadline(task)?.is_some_and(|expires| wall_now_nanos() >= expires) {
        return Err(McpError::invalid_request("Final Task input snapshot has expired"));
    }
    Ok(())
}

trait TaskWaitTransport {
    type Error: From<McpError>;

    async fn read_task(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> Result<FinalTask, Self::Error>;
}

impl TaskWaitTransport for HttpClient {
    type Error = HttpClientError;

    async fn read_task(
        &mut self,
        cx: &Cx,
        _cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> Result<FinalTask, Self::Error> {
        self.get_final_task_snapshot(cx, task_id).await
    }
}

#[cfg(unix)]
impl TaskWaitTransport for Client {
    type Error = McpError;

    async fn read_task(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> McpResult<FinalTask> {
        self.get_task_final_with_cx(cx, cancellation, task_id)
            .await
            .map(|result| result.task)
    }
}

fn ready_outcome(task: &FinalTask) -> Option<FinalTaskWaitOutcome> {
    Some(match task {
        FinalTask::Working(_) => return None,
        FinalTask::InputRequired { .. } => FinalTaskWaitOutcome::InputRequired,
        FinalTask::Completed { .. } => FinalTaskWaitOutcome::Completed,
        FinalTask::Failed { .. } => FinalTaskWaitOutcome::Failed,
        FinalTask::Cancelled(_) => FinalTaskWaitOutcome::Cancelled,
    })
}

fn next_delay(task: &FinalTask, policy: FinalTaskWaitPolicy) -> McpResult<Duration> {
    task.base()
        .poll_interval_ms
        .as_ref()
        .map_or(Ok(policy.fallback_poll_interval), |interval| {
            interval
                .try_as_millis()
                .map(Duration::from_millis)
                .map_err(|_| McpError::invalid_request("Invalid final Task polling interval"))
        })
}

fn admit_identity(previous: &FinalTask, next: &FinalTask) -> McpResult<()> {
    let invalid = || McpError::invalid_request("Final Task identity changed during observation");
    if previous.base().task_id != next.base().task_id
        || previous.base().ttl_ms != next.base().ttl_ms
        || timestamp_nanos(&previous.base().created_at).map_err(|_| invalid())?
            != timestamp_nanos(&next.base().created_at).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    Ok(())
}

fn wall_now_nanos() -> i128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_nanos() as i128,
        Err(before_epoch) => -(before_epoch.duration().as_nanos() as i128),
    }
}

fn retention_deadline(task: &FinalTask) -> McpResult<Option<i128>> {
    let Some(ttl) = &task.base().ttl_ms else {
        return Ok(None);
    };
    let invalid = || McpError::invalid_request("Invalid final Task retention deadline");
    let millis = ttl.try_as_millis().map_err(|_| invalid())?;
    let created = timestamp_nanos(&task.base().created_at).map_err(|_| invalid())?;
    // u64 milliseconds fit i128 nanoseconds; do not narrow an otherwise valid
    // long-lived Task through a u64 nanosecond clock before meeting local limits.
    created
        .checked_add(i128::from(millis) * 1_000_000)
        .map(Some)
        .ok_or_else(invalid)
}

struct WaitBudget {
    wall_deadline: Instant,
    runtime_deadline: Time,
    retention_deadline: Option<i128>,
    deadline_outcome: FinalTaskWaitOutcome,
}

impl WaitBudget {
    fn new(cx: &Cx, timeout: Duration, task: &FinalTask) -> McpResult<Self> {
        Self::at_wall_time(cx, timeout, task, wall_now_nanos())
    }

    fn at_wall_time(cx: &Cx, timeout: Duration, task: &FinalTask, wall_now: i128) -> McpResult<Self> {
        let now = cx.now();
        let local_deadline =
            now.saturating_add_nanos(u64::try_from(timeout.as_nanos()).map_err(|_| {
                McpError::invalid_params("Final Task wait deadline is out of range")
            })?);
        let local_deadline = cx
            .budget()
            .deadline
            .map_or(local_deadline, |caller| caller.min(local_deadline));
        let mut remaining = timeout.min(Duration::from_nanos(local_deadline.duration_since(now)));
        let retention_deadline = retention_deadline(task)?;
        let mut deadline_outcome = FinalTaskWaitOutcome::DeadlineElapsed;
        if let Some(expires) = retention_deadline {
            let nanos = expires.saturating_sub(wall_now).max(0);
            if nanos <= remaining.as_nanos() as i128 {
                // Only narrow after meeting the at-most-24-hour local ceiling.
                remaining = Duration::from_nanos(u64::try_from(nanos).map_err(|_| {
                    McpError::invalid_request("Invalid final Task retention deadline")
                })?);
                deadline_outcome = FinalTaskWaitOutcome::TaskExpired;
            }
        }
        let runtime_deadline = now.saturating_add_nanos(
            u64::try_from(remaining.as_nanos())
                .map_err(|_| McpError::invalid_params("Final Task wait deadline is out of range"))?,
        );
        let wall_deadline = Instant::now()
            .checked_add(remaining)
            .ok_or_else(|| McpError::invalid_params("Final Task wait deadline is out of range"))?;
        Ok(Self {
            wall_deadline,
            runtime_deadline,
            retention_deadline,
            deadline_outcome,
        })
    }

    fn stop(&self, cx: &Cx, cancellation: &McpRequestCancellation) -> Option<FinalTaskWaitOutcome> {
        self.stop_at_wall_time(cx, cancellation, wall_now_nanos())
    }

    fn stop_at_wall_time(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        wall_now: i128,
    ) -> Option<FinalTaskWaitOutcome> {
        if cancellation.is_cancel_requested() {
            Some(FinalTaskWaitOutcome::ObservationCancelled)
        } else if self.retention_deadline.is_some_and(|expires| wall_now >= expires) {
            Some(FinalTaskWaitOutcome::TaskExpired)
        } else if cx.now() >= self.runtime_deadline || Instant::now() >= self.wall_deadline {
            Some(self.deadline_outcome)
        } else if cx.checkpoint().is_err() {
            Some(FinalTaskWaitOutcome::ObservationCancelled)
        } else {
            None
        }
    }

    fn remaining(&self, cx: &Cx) -> Duration {
        let remaining = self.wall_deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_nanos(
                self.runtime_deadline.duration_since(cx.now()),
            ));
        self.retention_deadline.map_or(remaining, |expires| {
            let nanos = expires.saturating_sub(wall_now_nanos()).max(0);
            remaining.min(Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX)))
        })
    }

    async fn guard<T>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        operation: impl Future<Output = T>,
    ) -> Result<T, FinalTaskWaitOutcome> {
        let mut operation = std::pin::pin!(operation);
        let mut cancelled = std::pin::pin!(cancellation.cancelled());
        let checkpoint_slice = Duration::from_millis(20);
        let mut wake = Box::pin(asupersync::time::sleep(
            cx.now(),
            self.remaining(cx).min(checkpoint_slice),
        ));
        std::future::poll_fn(|task_cx| {
            let _current = Cx::set_current(Some(cx.clone()));
            if let Some(reason) = self.stop(cx, cancellation) {
                return Poll::Ready(Err(reason));
            }
            if cancelled.as_mut().poll(task_cx).is_ready() {
                return Poll::Ready(Err(FinalTaskWaitOutcome::ObservationCancelled));
            }
            let result = operation.as_mut().poll(task_cx);
            // A completing read cannot publish a result after its caller was
            // cancelled, retention expired, or the original budget elapsed.
            if let Some(reason) = self.stop(cx, cancellation) {
                return Poll::Ready(Err(reason));
            }
            if result.is_pending() && wake.as_mut().poll(task_cx).is_ready() {
                wake.set(asupersync::time::sleep(
                    cx.now(),
                    self.remaining(cx).min(checkpoint_slice),
                ));
                task_cx.waker().wake_by_ref();
            }
            result.map(Ok)
        })
        .await
    }
}

async fn wait_for_task<T: TaskWaitTransport>(
    handle: &mut FinalTaskHandle,
    cx: &Cx,
    client: &mut T,
    cancellation: &McpRequestCancellation,
    policy: FinalTaskWaitPolicy,
) -> Result<FinalTaskWaitOutcome, T::Error> {
    // Already delivered terminal data is not remote work to observe. Preserve
    // the existing immediate-return behavior without silently erasing results.
    if let Some(outcome) = ready_outcome(handle.task())
        && outcome != FinalTaskWaitOutcome::InputRequired
    {
        return Ok(outcome);
    }
    let budget = WaitBudget::new(cx, policy.timeout, handle.task())?;
    if let Some(outcome) = budget.stop(cx, cancellation) {
        return Ok(outcome);
    }
    if let Some(outcome) = ready_outcome(handle.task()) {
        return Ok(outcome);
    }
    if cx.timer_driver().is_none() {
        return Ok(FinalTaskWaitOutcome::TimerUnavailable);
    }
    for _ in 0..policy.maximum_polls {
        let delay = next_delay(handle.task(), policy)?;
        // A peer minimum beyond the remaining budget/retention has no legal
        // next poll. Never shorten it to squeeze a read in before expiry.
        if delay >= budget.remaining(cx) {
            return match budget
                .guard(cx, cancellation, std::future::pending::<()>())
                .await
            {
                Err(outcome) => Ok(outcome),
                Ok(()) => unreachable!("a pending future cannot finish"),
            };
        }
        if let Err(outcome) = budget
            .guard(cx, cancellation, asupersync::time::sleep(cx.now(), delay))
            .await
        {
            return Ok(outcome);
        }
        if let Some(outcome) = budget.stop(cx, cancellation) {
            return Ok(outcome);
        }
        let task = match budget
            .guard(
                cx,
                cancellation,
                client.read_task(cx, cancellation, handle.task_id().clone()),
            )
            .await
        {
            Ok(result) => result?,
            Err(outcome) => return Ok(outcome),
        };
        admit_identity(handle.task(), &task)?;
        if let Some(outcome) = budget.stop(cx, cancellation) {
            return Ok(outcome);
        }
        handle.task = task;
        if let Some(outcome) = ready_outcome(handle.task()) {
            return Ok(outcome);
        }
    }
    Ok(FinalTaskWaitOutcome::PollLimitReached)
}

#[cfg(all(test, unix))]
#[path = "task_wait_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "task_wait_stdio_tests.rs"]
mod stdio_tests;

#[cfg(test)]
#[path = "task_wait_retention_tests.rs"]
mod retention_tests;

#[cfg(all(test, unix))]
#[path = "task_input_stdio_tests.rs"]
mod input_stdio_tests;
