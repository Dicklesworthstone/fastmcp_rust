//! Event-driven Task observation with post-acknowledgement reconciliation.
//!
//! The listen remains open while authenticated snapshots are fetched. Status
//! notifications are only hints: neither their order nor their embedded Task
//! can roll back a newer snapshot or manufacture a successful Task outcome.

/// Bounded, observation-only checkpoints for explicit host-owned restart.
pub mod checkpoint;
/// Event-driven input resolution using the shared acknowledged-input ledger.
pub mod input;

use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::time::Duration;

use asupersync::Time;
use asupersync::bytes::Buf;
use asupersync::http::body::Body;
use asupersync::http::h1::Method;
use asupersync::time::Sleep;
use fastmcp_protocol::tasks_extension::{GetTaskResult, Task, TaskInputRequests};

use super::*;
use input::{InputDecision, InputDriver, ManagedTaskDriverError, ManagedTaskInputAction, NoInput};
use super::super::{
    BYTES_PER_TURN, FRAMES_PER_TURN, Reader, cooperate,
};
use crate::http_auth::dpop::native::{
    DpopHttpError, check_live, resource_headers, within,
};
use crate::http_auth::dpop::native::core::tasks::{
    DpopTaskOperation, ManagedTaskEvent, ManagedTaskRequest,
};
use crate::http_auth::dpop::native::core::tasks::wait::DpopTaskWaitOutcome;
use crate::http_executor::{MODERN_MCP_ACCEPT, validate_response_head};

/// Limits the initial snapshot and all event-triggered reconciliations.
/// No interval is needed: a quiet acknowledged subscription is never polled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpopTaskPollingFallback {
    maximum_polls: usize,
    minimum_poll_interval: Duration,
}

impl DpopTaskPollingFallback {
    /// Admit 1..=1024 additional gets after a clean subscription ending.
    /// The local interval is nonzero and at most one minute; a longer peer
    /// pollIntervalMs always wins.
    pub fn new(
        maximum_polls: usize,
        minimum_poll_interval: Duration,
    ) -> Result<Self, DpopTaskWatchError> {
        if !(1..=1024).contains(&maximum_polls)
            || minimum_poll_interval.is_zero()
            || minimum_poll_interval > Duration::from_mins(1)
        {
            return Err(DpopTaskWatchError::InvalidPolicy);
        }
        Ok(Self { maximum_polls, minimum_poll_interval })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpopTaskWatchPolicy {
    maximum_snapshots: usize,
    fallback: Option<DpopTaskPollingFallback>,
}

impl Default for DpopTaskWatchPolicy {
    fn default() -> Self {
        Self { maximum_snapshots: 64, fallback: None }
    }
}

impl DpopTaskWatchPolicy {
    /// Admit 1..=1024 snapshots, including the initial and final reconciliation.
    /// A single snapshot is useful for a Task which is already non-Working.
    /// Polling fallback is disabled unless explicitly selected.
    pub fn new(maximum_snapshots: usize) -> Result<Self, DpopTaskWatchError> {
        if !(1..=1024).contains(&maximum_snapshots) {
            return Err(DpopTaskWatchError::InvalidPolicy);
        }
        Ok(Self { maximum_snapshots, fallback: None })
    }

    /// Opt into bounded observation-only polling if an acknowledged subscription
    /// ends cleanly while the authoritative Task remains Working. This never
    /// restores Task-input update authority after teardown.
    pub fn with_polling_fallback(
        mut self,
        maximum_polls: usize,
        minimum_poll_interval: Duration,
    ) -> Result<Self, DpopTaskWatchError> {
        self.fallback = Some(DpopTaskPollingFallback::new(
            maximum_polls, minimum_poll_interval,
        )?);
        Ok(self)
    }
}

/// Failures carry no Task ID, resource, credential or peer diagnostic text.
#[derive(Debug)]
pub enum DpopTaskWatchError {
    InvalidPolicy,
    InvalidIdPrefix,
    SnapshotLimit,
    TaskNotAcknowledged,
    SubscriptionEndedWhileWorking,
    FallbackLimit,
    InvalidPollInterval,
    UnexpectedResponse,
    Stream(DpopStreamError),
    /// Capability, host-input, or acknowledged-ledger refusal.
    Driver(ManagedTaskDriverError),
}

impl fmt::Display for DpopTaskWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid DPoP Task watch policy",
            Self::InvalidIdPrefix => "invalid DPoP Task watch identity prefix",
            Self::SnapshotLimit => "DPoP Task watch snapshot limit reached",
            Self::TaskNotAcknowledged => "DPoP Task watch selection was not acknowledged",
            Self::SubscriptionEndedWhileWorking => "DPoP Task subscription ended while work remains",
            Self::FallbackLimit => "DPoP Task polling fallback limit reached",
            Self::InvalidPollInterval => "DPoP Task polling interval cannot be represented",
            Self::UnexpectedResponse => "DPoP Task watch requires a get snapshot",
            Self::Stream(error) => return error.fmt(f),
            Self::Driver(error) => return error.fmt(f),
        })
    }
}

impl std::error::Error for DpopTaskWatchError {}

impl From<DpopStreamError> for DpopTaskWatchError {
    fn from(error: DpopStreamError) -> Self { Self::Stream(error) }
}

impl From<DpopHttpError> for DpopTaskWatchError {
    fn from(error: DpopHttpError) -> Self { Self::Stream(error.into()) }
}

impl From<ManagedCoreError> for DpopTaskWatchError {
    fn from(error: ManagedCoreError) -> Self { Self::Stream(error.into()) }
}

impl From<ManagedTasksError> for DpopTaskWatchError {
    fn from(error: ManagedTasksError) -> Self {
        Self::Stream(DpopTasksError::Task(error).into())
    }
}

struct WatchState {
    prefix: String,
    policy: DpopTaskWatchPolicy,
    snapshots: usize,
    fallback_polls: usize,
    fallback_due: Option<Time>,
    usage: (usize, usize),
    limits: DpopStreamLimits,
}

impl WatchState {
    fn new(prefix: &str, policy: DpopTaskWatchPolicy, limits: DpopStreamLimits)
        -> Result<Self, DpopTaskWatchError>
    {
        if prefix.is_empty() || prefix.len() > 128
            || !prefix.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        {
            return Err(DpopTaskWatchError::InvalidIdPrefix);
        }
        Ok(Self {
            prefix: prefix.to_owned(),
            policy,
            snapshots: 0,
            fallback_polls: 0,
            fallback_due: None,
            usage: (0, 0),
            limits,
        })
    }

    fn require_snapshot(&self) -> Result<(), DpopTaskWatchError> {
        if self.snapshots >= self.policy.maximum_snapshots {
            return Err(DpopTaskWatchError::SnapshotLimit);
        }
        Ok(())
    }

    fn remaining_limits(&self) -> Result<DpopStreamLimits, DpopTaskWatchError> {
        let core = self.limits.core;
        let bytes = core.total_bytes().checked_sub(self.usage.0)
            .filter(|bytes| *bytes > 0).ok_or(ManagedCoreError::ResponseByteLimit)?;
        let notifications = core.notifications().checked_sub(self.usage.1)
            .ok_or(ManagedCoreError::NotificationLimit)?;
        let mut limits = self.limits;
        limits.core = ManagedCoreLimits::new(
            core.request_bytes(), core.frame_bytes().min(bytes), bytes,
            notifications, core.timeout(),
        )?;
        Ok(limits)
    }

    fn charge(&mut self, delta: (usize, usize)) -> Result<(), DpopTaskWatchError> {
        let bytes = self.usage.0.checked_add(delta.0)
            .filter(|bytes| *bytes <= self.limits.core.total_bytes())
            .ok_or(ManagedCoreError::ResponseByteLimit)?;
        let notifications = self.usage.1.checked_add(delta.1)
            .filter(|count| *count <= self.limits.core.notifications())
            .ok_or(ManagedCoreError::NotificationLimit)?;
        // A rejected admission cannot partially spend the other allowance.
        self.usage = (bytes, notifications);
        Ok(())
    }

    fn snapshot_request(&mut self, task: &TaskId)
        -> Result<(DpopTaskOperation, DpopStreamLimits), DpopTaskWatchError>
    {
        self.require_snapshot()?;
        let limits = self.remaining_limits()?;
        let operation = DpopTaskOperation::new(
            RequestId::String(format!("{}.{}.discover", self.prefix, self.snapshots)),
            RequestId::String(format!("{}.{}.get", self.prefix, self.snapshots)),
            ManagedTaskRequest::Get(task.clone()),
        )?;
        self.snapshots += 1;
        Ok((operation, limits))
    }

    fn note_snapshot(&mut self, now: Time, task: &Task) -> Result<(), DpopTaskWatchError> {
        let Some(fallback) = self.policy.fallback else {
            self.fallback_due = None;
            return Ok(());
        };
        if !matches!(task, Task::Working(_)) {
            self.fallback_due = None;
            return Ok(());
        }
        let peer = task.base().poll_interval_ms.as_ref()
            .map(|hint| hint.try_as_millis())
            .transpose()
            .map_err(|_| DpopTaskWatchError::InvalidPollInterval)?
            .map(Duration::from_millis)
            .unwrap_or(fallback.minimum_poll_interval);
        let nanos = u64::try_from(peer.max(fallback.minimum_poll_interval).as_nanos())
            .unwrap_or(u64::MAX);
        self.fallback_due = Some(now.saturating_add_nanos(nanos));
        Ok(())
    }

    fn begin_fallback_poll(&mut self) -> Result<Option<Time>, DpopTaskWatchError> {
        let Some(fallback) = self.policy.fallback else { return Ok(None); };
        if self.fallback_polls >= fallback.maximum_polls {
            return Err(DpopTaskWatchError::FallbackLimit);
        }
        self.require_snapshot()?;
        let due = self.fallback_due.ok_or(DpopTaskWatchError::UnexpectedResponse)?;
        self.fallback_polls += 1;
        Ok(Some(due))
    }

    fn selection(&self, metadata: FinalRequestMeta, task: &TaskId)
        -> Result<DpopTaskSubscription, DpopTaskWatchError>
    {
        Ok(DpopTaskSubscription::new(
            RequestId::String(format!("{}.listen.discover", self.prefix)),
            RequestId::String(format!("{}.listen", self.prefix)),
            metadata, vec![task.clone()],
        )?)
    }

    fn require_acknowledged(decoder: &TaskSubscriptionDecoder, task: &TaskId)
        -> Result<(), DpopTaskWatchError>
    {
        if !decoder.accepted.as_ref().is_some_and(|ids| ids.contains(task)) {
            return Err(DpopTaskWatchError::TaskNotAcknowledged);
        }
        Ok(())
    }
}

fn outcome(snapshot: GetTaskResult) -> Option<DpopTaskWaitOutcome> {
    match &snapshot.task {
        Task::Working(_) => None,
        Task::InputRequired { .. } => Some(DpopTaskWaitOutcome::InputRequired(Box::new(snapshot))),
        Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_) => {
            Some(DpopTaskWaitOutcome::Terminal(Box::new(snapshot)))
        }
    }
}

impl DpopHttpClient {
    #[allow(clippy::too_many_arguments)]
    async fn watch_snapshot<R, F, O>(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
        credential: &DpopCredential, metadata: &FinalRequestMeta, task: &TaskId,
        state: &mut WatchState, bounds: WaitBounds,
        input: &mut Option<InputDriver<R, O>>, may_update: bool,
    ) -> Result<Option<DpopTaskWaitOutcome>, DpopTaskWatchError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        loop {
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let (operation, limits) = state.snapshot_request(task)?;
            let completed = self.request_task_stream_with_bounds(
                cx, cancellation, credential, metadata.clone(), operation, limits, bounds, &mut |_| true,
            ).await?;
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            state.charge(completed.usage)?;
            let ManagedTaskEvent::Snapshot(snapshot) = completed.result else {
                return Err(DpopTaskWatchError::UnexpectedResponse);
            };
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            state.note_snapshot(cx.now(), &snapshot.task)?;
            let Some(input) = input.as_mut() else { return Ok(outcome(*snapshot)); };
            let life = Lifetime { cx, cancellation, session: &self.session, credential, bounds };
            let decision = input.on_snapshot(&life, state, &snapshot.task, may_update).await?;
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            match decision {
                InputDecision::Return => return Ok(outcome(*snapshot)),
                InputDecision::Wait => return Ok(None),
                InputDecision::Update(responses) => {
                    let (operation, limits) = input.update_request(state, snapshot.task, responses)?;
                    let completed = self.request_task_stream_with_bounds(
                        cx, cancellation, credential, metadata.clone(), operation, limits,
                        bounds, &mut |_| true,
                    ).await?;
                    check_live(cx, cancellation, &self.session, credential, bounds)?;
                    state.charge(completed.usage)?;
                    if !matches!(completed.result, ManagedTaskEvent::Updated(_)) {
                        return Err(DpopTaskWatchError::UnexpectedResponse);
                    }
                    // The decoder has admitted both the ACK and clean EOF. No
                    // failed/provisional update can advance custody or be replayed.
                    input.acknowledged()?;
                    // Reconcile now even if the server coalesced its status
                    // notification. The original limits and deadline stay fixed.
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn poll_after_subscription<R, F, O>(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
        credential: &DpopCredential, metadata: &FinalRequestMeta, task: &TaskId,
        state: &mut WatchState, bounds: WaitBounds,
        input: &mut Option<InputDriver<R, O>>,
    ) -> Result<DpopTaskWaitOutcome, DpopTaskWatchError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        loop {
            let Some(due) = state.begin_fallback_poll()? else {
                return Err(DpopTaskWatchError::SubscriptionEndedWhileWorking);
            };
            within(cx, cancellation, &self.session, credential, bounds, async {
                if cx.now() < due { Sleep::new(due).await; }
                Ok(())
            }).await?;
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            if let Some(result) = self.watch_snapshot(
                cx, cancellation, credential, metadata, task, state, bounds, input, false,
            ).await? {
                return Ok(result);
            }
        }
    }

    /// Observe an existing Task without periodic polling or implicit mutation.
    ///
    /// The first authenticated get is immediate. If Working, one Tasks listen
    /// is opened and MUST acknowledge the exact requested Task. A second get is
    /// performed AFTER acknowledgement while that listen remains open, closing
    /// the get/subscribe race even when completion emits no event to this listen.
    /// Later admitted status events trigger fresh gets; their embedded snapshots
    /// are not used to overwrite newer state. Coalesced events may share a get.
    /// A quiet live subscription causes no periodic gets or reconnects.
    ///
    /// The returned complete GetTaskResult is preserved, including metadata.
    /// Input-required is an explicit host handoff; failed/cancelled remote Tasks
    /// are terminal snapshots, not successful executions. A clean subscription
    /// terminal, whether completion or peer cancellation, requires a final get;
    /// a still-Working Task is an error unless an explicit bounded polling
    /// fallback was configured. Fallback waits for the greater of its local
    /// floor and the latest admitted pollIntervalMs, and remains observation-only:
    /// input-required is returned rather than updated. Subscription cancellation
    /// never means Task cancellation. Missing acknowledgement, early EOF, invalid frames
    /// and exhausted bounds fail without a final get. A non-Working
    /// authoritative get stops the local listen without claiming that the
    /// subscription itself completed or validating an unread tail.
    ///
    /// All discovery, get and listen payloads/notifications share the original
    /// limits. ACK counts as a notification. Native raw-body caps apply per
    /// response. The same credential and absolute native/core/caller/token
    /// deadline cover the complete watch. Subscription idle time also bounds
    /// reconciliation; statuses, comments and gets never reset it. Get responses
    /// may be finite JSON or SSE and require clean EOF before publication.
    ///
    /// One live listen and at most one snapshot request are driven together.
    /// The native streaming response owns its socket independently of the
    /// client's bounded discovery pool, so reconciliation reuses this client's
    /// exact transport, trust policy and original DPoP session. No second client,
    /// runtime, detached task, token renewal, tool call, update, remote cancel,
    /// retry, redirect, proxy, cookie state or bearer downgrade is introduced.
    /// Dropping/cancelling this future retires the listen and any in-flight
    /// request without revoking the shared login or discarding reusable idle
    /// discovery connections. Already committed remote effects cannot be recalled.
    ///
    /// Use a fresh 1..=128 ASCII alphanumeric/underscore/dot/dash id_prefix for
    /// each explicit run. Generated IDs are not idempotency or restart tokens.
    #[allow(clippy::too_many_arguments)]
    pub async fn watch_task_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
        credential: &DpopCredential, metadata: FinalRequestMeta, task: TaskId,
        id_prefix: &str, policy: DpopTaskWatchPolicy, limits: DpopStreamLimits,
    ) -> Result<DpopTaskWaitOutcome, DpopTaskWatchError> {
        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            return Err(DpopHttpError::Cancelled.into());
        }
        let bounds = WaitBounds::new(cx, self.policy.timeout.min(limits.core.timeout()), credential)?;
        self.watch_task_using(
            cx, cancellation, credential, metadata, task, id_prefix,
            policy, limits, bounds, (0, 0), None::<NoInput>,
        ).await
    }

    // Observation and input driving share the same live response owner. Only
    // the explicit input entrypoint installs callbacks; checkpoints remain
    // observation-only and never retain input answers or an update capability.
    #[allow(clippy::too_many_arguments)]
    async fn watch_task_using<R, F, O>(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
        credential: &DpopCredential, metadata: FinalRequestMeta, task: TaskId,
        id_prefix: &str, policy: DpopTaskWatchPolicy, limits: DpopStreamLimits,
        bounds: WaitBounds, prior_usage: (usize, usize), mut input: Option<InputDriver<R, O>>,
    ) -> Result<DpopTaskWaitOutcome, DpopTaskWatchError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let mut state = WatchState::new(id_prefix, policy, limits)?;
        // Only the private creating-call adapter supplies nonzero usage. A
        // creation-to-watch handoff cannot replenish either response quota.
        state.charge(prior_usage)?;
        if let Some(result) = self.watch_snapshot(
            cx, cancellation, credential, &metadata, &task, &mut state, bounds, &mut input, true,
        ).await? {
            return Ok(result);
        }
        // Refuse impossible reconciliation before opening a live connection.
        state.require_snapshot()?;
        let remaining = state.remaining_limits()?;
        if remaining.core.notifications() == 0 {
            return Err(ManagedCoreError::NotificationLimit.into());
        }
        let idle = Idle::new(cx.now(), limits.idle);
        let selection = state.selection(metadata.clone(), &task)?;
        let prepared = with_caller(cx, || Prepared::new(
            self.resource().as_str(), selection,
            remaining.core, self.policy.max_body_bytes,
        ))?;
        let response = self.post_resource_with_bounds(
            cx, cancellation, credential, &prepared.discovery_wire, idle.bounds(bounds),
        ).await?;
        check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
        let (wire, mut decoder) = with_caller(cx, || prepared.admit(response))?;
        state.charge(decoder.usage())?;
        // From this point the decoder holds cumulative watch-wide usage. Later
        // gets update these counters rather than obtaining a new listen budget.
        decoder.limits = limits.core;
        decoder.bytes = state.usage.0;
        decoder.notifications = state.usage.1;

        let response = within(cx, cancellation, &self.session, credential, idle.bounds(bounds), async {
            let mut headers = resource_headers(&self.session, credential, &wire, &self.policy)?;
            for (name, value) in &mut headers {
                if name.eq_ignore_ascii_case("Accept") { *value = MODERN_MCP_ACCEPT.to_owned(); }
            }
            check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
            self.transport.request_streaming(
                cx, Method::Post, self.session.resource.as_str(), headers, wire.body().to_vec(),
            ).await.map_err(|_| DpopHttpError::TransportFailed)
        }).await?;
        let kind = with_caller(cx, || -> Result<_, DpopTaskWatchError> {
            check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
            Ok(validate_response_head(response.head.status, &response.head.headers)
                .map_err(|_| DpopHttpError::InvalidResponseHeaders)?.kind())
        })?;
        let source = self.session.resource.clone();
        self.session.observe_resource_nonce(&source, &response.head.headers)
            .map_err(DpopHttpError::from)?;
        check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
        if response.head.status != 200 {
            return Err(ManagedCoreError::HttpStatus { status: response.head.status }.into());
        }
        let mut body = response.body;
        let mut reader = Reader::<_, DpopTaskSubscriptionEvent>::new(
            kind, decoder, limits, self.policy.max_body_bytes,
        )?;
        let mut idle = idle;
        let mut bytes_left = BYTES_PER_TURN;
        let mut frames_left = FRAMES_PER_TURN;
        loop {
            let lifetime = Lifetime { cx, cancellation, session: &self.session, credential, bounds };
            if bytes_left == 0 || frames_left == 0 {
                cooperate(&lifetime, &idle).await?;
                bytes_left = BYTES_PER_TURN;
                frames_left = FRAMES_PER_TURN;
            }
            let frame = within(cx, cancellation, &self.session, credential, idle.bounds(bounds), async {
                poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await
                    .transpose().map_err(|_| DpopHttpError::TransportFailed)
            }).await?;
            let Some(frame) = frame else {
                // Only a clean admitted terminal permits final reconciliation.
                // Peer cancellation ends this listen, not its selected Task.
                let completed = with_caller(cx, || reader.finish(&lifetime, &idle))?;
                match completed.result {
                    Ok(_) | Err(DpopStreamError::SubscriptionCancelled) => {}
                    Err(error) => return Err(error.into()),
                }
                state.usage = completed.usage;
                if let Some(result) = self.watch_snapshot(
                    cx, cancellation, credential, &metadata, &task, &mut state, bounds,
                    &mut input, false,
                ).await? {
                    return Ok(result);
                }
                return self.poll_after_subscription(
                    cx, cancellation, credential, &metadata, &task, &mut state, bounds,
                    &mut input,
                ).await;
            };
            frames_left -= 1;
            let Some(mut data) = frame.into_data() else { continue };
            while data.has_remaining() {
                let lifetime = Lifetime { cx, cancellation, session: &self.session, credential, bounds };
                if bytes_left == 0 {
                    cooperate(&lifetime, &idle).await?;
                    bytes_left = BYTES_PER_TURN;
                    frames_left = FRAMES_PER_TURN;
                }
                let bytes = data.chunk();
                let consumed = bytes.len().min(bytes_left);
                if consumed == 0 { return Err(DpopHttpError::TransportFailed.into()); }
                let mut reconcile = false;
                with_caller(cx, || reader.push(
                    &bytes[..consumed], &lifetime, &mut idle,
                    &mut |_| { reconcile = true; true },
                ))?;
                data.advance(consumed);
                bytes_left -= consumed;
                if reconcile {
                    WatchState::require_acknowledged(&reader.decoder, &task)?;
                }
                if reconcile && reader.terminal.is_none() {
                    state.usage = reader.decoder.usage();
                    // No immutable session borrow crosses this mutable get.
                    // The listen owns its response body, not a pool slot or a
                    // transport borrow; the same client can drive the get.
                    if let Some(result) = self.watch_snapshot(
                        cx, cancellation, credential, &metadata, &task, &mut state, idle.bounds(bounds),
                        &mut input, true,
                    ).await? {
                        return Ok(result);
                    }
                    reader.decoder.bytes = state.usage.0;
                    reader.decoder.notifications = state.usage.1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
