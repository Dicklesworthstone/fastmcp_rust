//! Caller-owned, bounded observation of an existing final Task.
//!
//! This path only reads Tasks. Input effects, remote cancellation, reconnects,
//! persistence and creating-call retries remain explicit application actions.

use std::future::Future;
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};

#[cfg(unix)]
use crate::Client;
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
    /// starts and can only be tightened by the caller's `Cx` deadline.
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
    /// A retained terminal/input-required snapshot returns immediately without
    /// network activity. After `resume_input` acknowledges an update, explicitly
    /// `poll` to reconcile the state before waiting again. A new invocation is
    /// an explicitly new local budget; it does not claim crash-resume support.
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

struct WaitBudget {
    wall_deadline: Instant,
    runtime_deadline: Time,
}

impl WaitBudget {
    fn new(cx: &Cx, timeout: Duration) -> McpResult<Self> {
        let now = cx.now();
        let runtime_deadline =
            now.saturating_add_nanos(u64::try_from(timeout.as_nanos()).map_err(|_| {
                McpError::invalid_params("Final Task wait deadline is out of range")
            })?);
        let runtime_deadline = cx
            .budget()
            .deadline
            .map_or(runtime_deadline, |caller| caller.min(runtime_deadline));
        let remaining = timeout.min(Duration::from_nanos(runtime_deadline.duration_since(now)));
        let wall_deadline = Instant::now()
            .checked_add(remaining)
            .ok_or_else(|| McpError::invalid_params("Final Task wait deadline is out of range"))?;
        Ok(Self {
            wall_deadline,
            runtime_deadline,
        })
    }

    fn stop(&self, cx: &Cx, cancellation: &McpRequestCancellation) -> Option<FinalTaskWaitOutcome> {
        if cancellation.is_cancel_requested() {
            Some(FinalTaskWaitOutcome::ObservationCancelled)
        } else if cx.now() >= self.runtime_deadline || Instant::now() >= self.wall_deadline {
            Some(FinalTaskWaitOutcome::DeadlineElapsed)
        } else if cx.checkpoint().is_err() {
            Some(FinalTaskWaitOutcome::ObservationCancelled)
        } else {
            None
        }
    }

    fn remaining(&self, cx: &Cx) -> Duration {
        self.wall_deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_nanos(
                self.runtime_deadline.duration_since(cx.now()),
            ))
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
            // cancelled or the original absolute budget expired in that poll.
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
    if let Some(outcome) = ready_outcome(handle.task()) {
        return Ok(outcome);
    }
    let budget = WaitBudget::new(cx, policy.timeout)?;
    if let Some(outcome) = budget.stop(cx, cancellation) {
        return Ok(outcome);
    }
    if cx.timer_driver().is_none() {
        return Ok(FinalTaskWaitOutcome::TimerUnavailable);
    }
    for _ in 0..policy.maximum_polls {
        let delay = next_delay(handle.task(), policy)?;
        // A peer minimum beyond the remaining budget has no legal next poll.
        // Wait exclusively for cancellation/deadline rather than shortening
        // the delay: clock rounding must not turn that shortening into a read.
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
