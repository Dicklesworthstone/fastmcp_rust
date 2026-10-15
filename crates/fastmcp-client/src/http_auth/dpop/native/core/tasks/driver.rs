//! Bounded polling and explicit host input for DPoP-protected Tasks.
//!
//! This composes the existing negotiated Task POSTs and the shared Task input
//! ledger. The existing-Task entrypoints do not create Tasks; `start` adds an
//! explicit creating call under the same lifecycle. Neither refreshes credentials,
//! retries failed POSTs, or runs after its caller-owned future is dropped.

/// Start one tool call and drive its Task without resetting execution bounds.
pub mod start;

use std::fmt;
use std::future::Future;

use asupersync::Cx;
use asupersync::time::Sleep;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::tasks_extension::{Task, TaskId, TaskInputRequests};
use fastmcp_protocol::{FinalRequestMeta, RequestId, ServerNotification};

use super::{
    Admitted, DpopCredential, DpopHttpClient, DpopHttpError, DpopHttpResponse,
    DpopTaskOperation, DpopTasksError, ManagedCoreError, ManagedCoreLimits,
    ManagedTaskEvent, ManagedTaskRequest, ManagedTasksError, Prepared, WaitBounds,
    check_live,
};
use super::super::super::within;
use super::super::stream::{DpopStreamError, DpopStreamLimits, Idle, PreparedStream};
use super::stream::{TaskStreamDecoder, progress_marker};
use crate::http_auth::caller::with_caller;
use crate::http_auth::managed::tasks::ManagedTaskRequestIds;
use crate::http_auth::managed::tasks::driver::{
    DriverState, admit_capabilities, next_poll_time, validate_answers,
};
pub use crate::http_auth::managed::tasks::driver::{
    ManagedTaskDriverError, ManagedTaskDriverPolicy, ManagedTaskInputAction,
    ManagedTaskRunOutcome,
};

/// Sanitized failures; no Task ID, input, proof, token or peer text is retained.
#[derive(Debug)]
pub enum DpopTaskDriverError {
    InvalidIdPrefix,
    IdentityExhausted,
    Driver(ManagedTaskDriverError),
    Task(DpopTasksError),
    /// A streaming-specific limit or notification observer stopped the run.
    Stream(DpopStreamError),
}

impl fmt::Display for DpopTaskDriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdPrefix => f.write_str("invalid DPoP Task driver identity prefix"),
            Self::IdentityExhausted => f.write_str("DPoP Task driver identities exhausted"),
            Self::Driver(error) => error.fmt(f),
            Self::Task(error) => error.fmt(f),
            Self::Stream(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DpopTaskDriverError {}
impl From<ManagedTaskDriverError> for DpopTaskDriverError {
    fn from(error: ManagedTaskDriverError) -> Self { Self::Driver(error) }
}
impl From<DpopTasksError> for DpopTaskDriverError {
    fn from(error: DpopTasksError) -> Self { Self::Task(error) }
}
impl From<ManagedTasksError> for DpopTaskDriverError {
    fn from(error: ManagedTasksError) -> Self { Self::Task(error.into()) }
}
impl From<ManagedCoreError> for DpopTaskDriverError {
    fn from(error: ManagedCoreError) -> Self { Self::Task(error.into()) }
}
impl From<DpopHttpError> for DpopTaskDriverError {
    fn from(error: DpopHttpError) -> Self { Self::Task(error.into()) }
}

impl From<DpopStreamError> for DpopTaskDriverError {
    fn from(error: DpopStreamError) -> Self {
        match error {
            // Keep transport/protocol diagnostics consistent across modes.
            DpopStreamError::Core(error) => Self::Task(error.into()),
            DpopStreamError::Task(error) => Self::Task(error),
            error => Self::Stream(error),
        }
    }
}

#[derive(Clone, Copy)]
enum ReplyMode {
    Json,
    Stream(DpopStreamLimits),
}

// Only the driver owns this state. An ACK advances the shared input ledger;
// allocating an ID or sending an update never means that an answer was accepted.
struct Run {
    state: DriverState,
    policy: ManagedTaskDriverPolicy,
    prefix: String,
    sequence: usize,
    polls: usize,
    updates: usize,
    remaining_bytes: usize,
    notifications: usize,
}

impl Run {
    fn new(
        prefix: &str,
        policy: ManagedTaskDriverPolicy,
        limits: ManagedCoreLimits,
    ) -> Result<Self, DpopTaskDriverError> {
        if prefix.is_empty()
            || prefix.len() > 128
            || !prefix.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        {
            return Err(DpopTaskDriverError::InvalidIdPrefix);
        }
        Ok(Self {
            state: DriverState::default(),
            policy,
            prefix: prefix.to_owned(),
            sequence: 0,
            polls: 0,
            updates: 0,
            remaining_bytes: limits.total_bytes(),
            notifications: 0,
        })
    }

    fn prepare(
        &mut self,
        target: &str,
        metadata: FinalRequestMeta,
        request: ManagedTaskRequest,
        limits: ManagedCoreLimits,
        native_maximum: usize,
    ) -> Result<Prepared, DpopTaskDriverError> {
        let update = match &request {
            ManagedTaskRequest::Get(_) => {
                if self.polls >= self.policy.maximum_polls {
                    return Err(ManagedTaskDriverError::PollLimit.into());
                }
                false
            }
            ManagedTaskRequest::Update { .. } => {
                if self.updates >= self.policy.maximum_updates {
                    return Err(ManagedTaskDriverError::UpdateLimit.into());
                }
                true
            }
            // The lifecycle driver never creates or remotely cancels a Task.
            _ => return Err(ManagedTaskDriverError::UnexpectedResponse.into()),
        };
        if self.remaining_bytes == 0 {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        let next = self.sequence.checked_add(1)
            .ok_or(DpopTaskDriverError::IdentityExhausted)?;
        let discovery = RequestId::String(format!("{}.{}.discover", self.prefix, self.sequence));
        let operation = RequestId::String(format!("{}.{}.task", self.prefix, self.sequence));
        let ids = ManagedTaskRequestIds::new(discovery.clone(), operation.clone())?;
        let operation = DpopTaskOperation::new(discovery, operation, request)?;
        let prepared = Prepared::new(target, metadata, operation, limits, native_maximum)?;
        // ID custody and answer custody share the existing bounded ledger.
        // Reserve only after both actual wire requests have passed admission.
        self.state.reserve_ids(&ids, self.policy.maximum_state_bytes)?;
        self.sequence = next;
        if update { self.updates += 1; } else { self.polls += 1; }
        Ok(prepared)
    }

    fn charge(&mut self, bytes: usize) -> Result<(), DpopTaskDriverError> {
        self.remaining_bytes = self.remaining_bytes.checked_sub(bytes)
            .ok_or(ManagedCoreError::ResponseByteLimit)?;
        Ok(())
    }

    fn admit(
        &mut self,
        prepared: Prepared,
        response: DpopHttpResponse,
    ) -> Result<Admitted, DpopTaskDriverError> {
        let bytes = response.body().len();
        let mut admitted = prepared.admit(response)?;
        self.charge(bytes)?;
        if self.remaining_bytes == 0 {
            // Even successful discovery cannot authorize a POST whose response
            // has no remaining budget. Do not spend mutation authority here.
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        admitted.maximum = admitted.maximum.min(self.remaining_bytes);
        Ok(admitted)
    }

    // Stream decoders inherit ALL prior payloads, including the discovery
    // already charged by admit. A fresh parser is not a fresh run budget.
    fn stream_usage(&self, limits: ManagedCoreLimits) -> Result<(usize, usize), DpopTaskDriverError> {
        let bytes = limits.total_bytes().checked_sub(self.remaining_bytes)
            .ok_or(ManagedCoreError::ResponseByteLimit)?;
        Ok((bytes, self.notifications))
    }

    fn complete_stream(
        &mut self,
        usage: (usize, usize),
        limits: ManagedCoreLimits,
    ) -> Result<(), DpopTaskDriverError> {
        let (before, notifications) = self.stream_usage(limits)?;
        if usage.0 < before || usage.0 > limits.total_bytes() {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        if usage.1 < notifications || usage.1 > limits.notifications() {
            return Err(ManagedCoreError::NotificationLimit.into());
        }
        // This is cumulative usage, not a delta: discovery must not be charged
        // twice. Commit both counters only after every quota check succeeds.
        self.remaining_bytes = limits.total_bytes() - usage.0;
        self.notifications = usage.1;
        Ok(())
    }

    fn finish(
        &mut self,
        admitted: Admitted,
        response: DpopHttpResponse,
    ) -> Result<ManagedTaskEvent, DpopTaskDriverError> {
        let bytes = response.body().len();
        let result = admitted.finish(response)?;
        self.charge(bytes)?;
        Ok(result)
    }
}

impl DpopHttpClient {
    /// Follows an existing Task until terminal state or an explicit input pause.
    ///
    /// The first get is immediate. Later gets wait at least the configured
    /// floor and the latest admitted peer polling hint, anchored to snapshot
    /// receipt rather than host-callback completion. Every get/update performs
    /// fresh authenticated Tasks discovery with the SAME original credential.
    /// No Task is created and no `tasks/cancel` is sent by this operation.
    ///
    /// The shared driver policy bounds polls, updates, input keys and retained
    /// state. `limits.total_bytes` bounds ALL discovery/get/update response bodies
    /// across the run; request/frame caps still apply individually. One deadline
    /// is fixed before preparation: the earliest driver, core, native, caller
    /// or original-token deadline wins. No page, sleep or host answer resets it.
    ///
    /// `id_prefix` must contain 1..=128 ASCII alphanumeric, dot, underscore or
    /// dash bytes. Use a distinct prefix for each run in the endpoint's request
    /// namespace. Generated IDs are unique within this run, not idempotency keys
    /// or a cross-process uniqueness guarantee.
    ///
    /// The observer sees every admitted snapshot. The resolver sees only input
    /// keys not acknowledged earlier in this run, after the shared capability
    /// gate and sampling-context normalization. An unchanged stale snapshot
    /// cannot repeat host work or an acknowledged update. A changed descriptor
    /// for an answered key fails closed. Empty, foreign and already-answered
    /// replies are refused. Only a decoded update ACK advances answer custody.
    /// Zero allowed updates returns input-required without invoking a resolver.
    ///
    /// Get/update replies may be JSON or finite request-scoped SSE. Valid
    /// notifications are admitted and discarded incrementally; they still
    /// consume the run-wide byte and notification budgets. Snapshots and
    /// update acknowledgements remain provisional until clean HTTP EOF.
    /// Use [`Self::drive_task_with_events`] to observe notifications or set
    /// parser/idle bounds, and [`Self::drive_task_json_with_cancellation`]
    /// to retain the original JSON-only Accept and error contract.
    ///
    /// Caller-driven execution: no refresh, retry, subscription,
    /// worker or persistent resume state. A failed or uncertain update stops
    /// the run without replay. Callbacks must cooperate; synchronous work and
    /// committed remote effects cannot be preempted or undone. Starting a new
    /// run is an explicit reconciliation decision, not an exactly-once promise.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task<R, F, O>(
        &mut self,
        cx: &Cx,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        task_id: TaskId,
        id_prefix: &str,
        policy: ManagedTaskDriverPolicy,
        limits: ManagedCoreLimits,
        resolve: R,
        observe: O,
    ) -> Result<ManagedTaskRunOutcome, DpopTaskDriverError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        self.drive_task_with_cancellation(
            cx, &McpRequestCancellation::new(), credential, metadata, task_id,
            id_prefix, policy, limits, resolve, observe,
        ).await
    }

    /// Local cancellation covers network waits, poll delays and pending host
    /// resolution. It does not revoke the session or cancel sibling requests.
    /// Dropping this future releases all current socket/timer/input ownership;
    /// no partially driven run remains usable and no remote cancellation follows.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task_with_cancellation<R, F, O>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        task_id: TaskId,
        id_prefix: &str,
        policy: ManagedTaskDriverPolicy,
        limits: ManagedCoreLimits,
        resolve: R,
        observe: O,
    ) -> Result<ManagedTaskRunOutcome, DpopTaskDriverError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        // Reuse the explicit stream path's decoder, quotas and cancellation
        // guard rather than maintaining a second default execution path.
        self.drive_task_with_events(
            cx, cancellation, credential, metadata, task_id, id_prefix, policy,
            DpopStreamLimits::new(limits, limits.timeout())?, resolve, observe,
            |_| true,
        ).await
    }

    /// Explicit JSON-only compatibility mode for an existing Task lifecycle.
    ///
    /// Sends `Accept: application/json` for discovery and get/update, retaining
    /// the original JSON-only response admission and typed HTTP errors. Prefer
    /// [`Self::drive_task_with_cancellation`] for peers which may stream replies.
    /// All modes share the same polling, host-input ledger, original credential,
    /// cancellation, absolute deadline and no-replay/no-remote-cancel rules.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task_json_with_cancellation<R, F, O>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        task_id: TaskId,
        id_prefix: &str,
        policy: ManagedTaskDriverPolicy,
        limits: ManagedCoreLimits,
        resolve: R,
        observe: O,
    ) -> Result<ManagedTaskRunOutcome, DpopTaskDriverError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        self.drive_task_inner(
            cx, cancellation, credential, metadata, task_id, id_prefix, policy,
            limits, ReplyMode::Json, resolve, observe, |_| true,
        ).await
    }

    /// Follow one existing Task with incremental operation notifications and
    /// JSON-or-SSE get/update replies. [`Self::drive_task`] uses this same entry
    /// point with notifications discarded and default parser bounds.
    ///
    /// Poll timing, capability-gated host input, identity reservation and the
    /// acknowledged-input ledger are the SAME driver as the JSON path. Every
    /// round performs fresh JSON discovery under the SAME original credential.
    /// No task creation, remote cancellation, retry, refresh or worker is added.
    ///
    /// Core payload bytes include all discoveries and every notification/result
    /// across the entire run. The notification count is also run-wide: neither
    /// polling nor an update resets either quota. Parser and native raw-body
    /// limits apply per response. Each network pair starts a new idle timer;
    /// valid progress may reset only that timer. The absolute driver/core/native/
    /// caller/token deadline is fixed before preparation and also covers sleeps,
    /// host callbacks and their pending futures. No later round extends it.
    ///
    /// notify sees validated notifications immediately and returns true to
    /// continue, or false to stop. It must be nonblocking and apply the host's
    /// disclosure policy. observe sees only fully admitted Task snapshots. A
    /// provisional update ACK never advances the input ledger: clean HTTP EOF
    /// is required first. Invalid tails, observer refusal/panic, cancellation,
    /// revocation and abandonment stop the run without replay or remote cancel.
    /// Previously delivered notifications and committed effects cannot be undone.
    /// Use request_task_with_events when driving a single operation manually.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task_with_events<R, F, O, N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        task_id: TaskId,
        id_prefix: &str,
        policy: ManagedTaskDriverPolicy,
        limits: DpopStreamLimits,
        resolve: R,
        observe: O,
        notify: N,
    ) -> Result<ManagedTaskRunOutcome, DpopTaskDriverError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
        N: FnMut(&ServerNotification) -> bool,
    {
        self.drive_task_inner(
            cx, cancellation, credential, metadata, task_id, id_prefix, policy,
            limits.core, ReplyMode::Stream(limits), resolve, observe, notify,
        ).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn drive_task_inner<R, F, O, N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        task_id: TaskId,
        id_prefix: &str,
        policy: ManagedTaskDriverPolicy,
        limits: ManagedCoreLimits,
        mode: ReplyMode,
        resolve: R,
        observe: O,
        notify: N,
    ) -> Result<ManagedTaskRunOutcome, DpopTaskDriverError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
        N: FnMut(&ServerNotification) -> bool,
    {
        // Cancellation needs no runtime, timer, credential admission or host
        // effect. Both JSON and SSE enter here before WaitBounds checks the
        // runtime, so a cancelled driver cannot be misreported as unavailable.
        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            return Err(DpopHttpError::Cancelled.into());
        }
        let timeout = policy.timeout.min(limits.timeout()).min(self.policy.timeout);
        let bounds = WaitBounds::new(cx, timeout, credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let run = Run::new(id_prefix, policy, limits)?;
        self.drive_task_run(
            cx, cancellation, credential, metadata, task_id, run, bounds,
            limits, mode, None, resolve, observe, notify,
        ).await
    }

    // Both existing-Task and creating-tool entrypoints use this lifecycle.
    // A creation snapshot is already admitted and charged; consuming it must
    // not issue a redundant get, reset quotas, or lose the original deadline.
    #[allow(clippy::too_many_arguments)]
    async fn drive_task_run<R, F, O, N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        task_id: TaskId,
        mut run: Run,
        bounds: WaitBounds,
        limits: ManagedCoreLimits,
        mode: ReplyMode,
        mut initial: Option<Task>,
        mut resolve: R,
        mut observe: O,
        mut notify: N,
    ) -> Result<ManagedTaskRunOutcome, DpopTaskDriverError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
        N: FnMut(&ServerNotification) -> bool,
    {
        let policy = run.policy;
        let input_metadata = serde_json::to_value(&metadata)
            .map_err(|_| ManagedTasksError::InvalidRequest)?;
        let mut due = cx.now();
        loop {
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let task = if let Some(task) = initial.take() {
                task
            } else {
                if run.polls >= policy.maximum_polls {
                    return Err(ManagedTaskDriverError::PollLimit.into());
                }
                if run.remaining_bytes == 0 {
                    return Err(ManagedCoreError::ResponseByteLimit.into());
                }
                if cx.now() < due {
                    within(cx, cancellation, &self.session, credential, bounds, async {
                        Sleep::new(due).await;
                        Ok(())
                    }).await?;
                }
                check_live(cx, cancellation, &self.session, credential, bounds)?;
                let prepared = run.prepare(self.resource().as_str(), metadata.clone(),
                    ManagedTaskRequest::Get(task_id.clone()), limits, self.policy.max_body_bytes)?;
                let event = self.drive_task_selected_pair(cx, cancellation, credential, bounds,
                    &mut run, prepared, mode, &mut notify).await?;
                let ManagedTaskEvent::Snapshot(snapshot) = event else {
                    return Err(ManagedTaskDriverError::UnexpectedResponse.into());
                };
                snapshot.task
            };
            let received = cx.now();
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let observed = with_caller(cx, || observe(&task));
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            observed?;
            if matches!(task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
                return Ok(ManagedTaskRunOutcome::Terminal(Box::new(task)));
            }
            if policy.maximum_updates == 0 && matches!(task, Task::InputRequired { .. }) {
                return Ok(ManagedTaskRunOutcome::InputRequired(Box::new(task)));
            }
            due = next_poll_time(received, &task, policy.minimum_poll_interval)?;
            let Task::InputRequired { input_requests, .. } = &task else { continue; };
            let (pending, fingerprints) = run.state.unanswered(input_requests, policy)?;
            if pending.is_empty() { continue; }
            if run.updates >= policy.maximum_updates {
                return Err(ManagedTaskDriverError::UpdateLimit.into());
            }
            let callback_inputs = admit_capabilities(&input_metadata, &pending)?;
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let resolution = with_caller(cx, || resolve(callback_inputs));
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let action = within(cx, cancellation, &self.session, credential, bounds,
                async { Ok(resolution.await) }).await?;
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let ManagedTaskInputAction::Respond(responses) = action? else {
                return Ok(ManagedTaskRunOutcome::InputRequired(Box::new(task)));
            };
            validate_answers(&pending, &responses)?;
            let answered: Vec<_> = responses.keys().cloned().collect();
            let prepared = run.prepare(self.resource().as_str(), metadata.clone(),
                ManagedTaskRequest::Update { task: Box::new(task), input_responses: responses },
                limits, self.policy.max_body_bytes)?;
            // Include the update's new ID reservation before checking whether
            // its ACK can fit. Do not post an answer that cannot be remembered.
            run.state.answer_bytes(&answered, &fingerprints, policy.maximum_state_bytes)?;
            let event = self.drive_task_selected_pair(cx, cancellation, credential, bounds,
                &mut run, prepared, mode, &mut notify).await?;
            if !matches!(event, ManagedTaskEvent::Updated(_)) {
                return Err(ManagedTaskDriverError::UnexpectedResponse.into());
            }
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            run.state.record_answers(&answered, &fingerprints, policy.maximum_state_bytes)?;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn drive_task_selected_pair<N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        bounds: WaitBounds,
        run: &mut Run,
        prepared: Prepared,
        mode: ReplyMode,
        notify: &mut N,
    ) -> Result<ManagedTaskEvent, DpopTaskDriverError>
    where
        N: FnMut(&ServerNotification) -> bool,
    {
        let ReplyMode::Stream(limits) = mode else {
            return self.drive_task_pair(cx, cancellation, credential, bounds, run, prepared).await;
        };
        let idle = Idle::new(cx.now(), limits.idle);
        let pair_bounds = idle.bounds(bounds);
        check_live(cx, cancellation, &self.session, credential, pair_bounds)?;
        // Validate the actual operation's progress identity BEFORE discovery or
        // signing. It is independent of generated correlation IDs and carries
        // no authority to acknowledge host input.
        let progress = progress_marker(&prepared.operation_wire, limits.core.request_bytes())?;
        check_live(cx, cancellation, &self.session, credential, pair_bounds)?;
        let response = self.post_resource_with_bounds(cx, cancellation, credential,
            &prepared.discovery_wire, pair_bounds).await?;
        check_live(cx, cancellation, &self.session, credential, pair_bounds)?;
        let admitted = run.admit(prepared, response)?;
        check_live(cx, cancellation, &self.session, credential, pair_bounds)?;
        let (wire, decoder) = TaskStreamDecoder::with_usage(
            admitted, limits.core, run.stream_usage(limits.core)?, progress,
        )?;
        // The shared native reader alone decides EOF, proof/nonce handling,
        // observer context, framing and cooperative ready-body yielding. The
        // same absolute bounds enter every round; no public request wrapper
        // may manufacture a new timeout or discard cumulative accounting here.
        let completed = self.execute_prepared_core_stream(
            cx, cancellation, credential,
            PreparedStream { wire, decoder, limits, bounds, idle }, notify,
        ).await?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        run.complete_stream(completed.usage, limits.core)?;
        Ok(completed.result)
    }

    async fn drive_task_pair(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        bounds: WaitBounds,
        run: &mut Run,
        prepared: Prepared,
    ) -> Result<ManagedTaskEvent, DpopTaskDriverError> {
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let response = self.post_resource_with_bounds(cx, cancellation, credential,
            &prepared.discovery_wire, bounds).await?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let admitted = run.admit(prepared, response);
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let admitted = admitted?;
        let response = self.post_resource_with_bounds(cx, cancellation, credential,
            &admitted.wire, bounds).await?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let event = run.finish(admitted, response);
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        event
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod cancellation_preflight_tests {
    use super::*;
    use crate::http_auth::dpop::DpopSession;
    use crate::http_auth::dpop::native::DpopHttpPolicy;
    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_protocol::ClientCapabilities;
    use fastmcp_protocol::dpop::DpopKey;
    use std::future::Ready;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};

    fn client() -> (DpopHttpClient, DpopCredential) {
        let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
        let resource = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
        let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(), resource)
            .unwrap();
        let credential = session.admit_token_response(
            &issuer, 200,
            br#"{"access_token":"preflight-token","token_type":"DPoP","expires_in":60}"#,
            Instant::now(), Duration::from_secs(60),
        ).unwrap();
        (DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap(), credential)
    }

    fn no_input(_: TaskInputRequests) -> Ready<Result<ManagedTaskInputAction, ManagedTaskDriverError>> {
        panic!("preflight refusal must not invoke an input resolver")
    }

    fn first_poll(
        client: &mut DpopHttpClient,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        streamed: bool,
        prefix: &str,
    ) -> DpopHttpError {
        let metadata = FinalRequestMeta::new(ClientCapabilities::default());
        let task_id = TaskId::parse("task-one").unwrap();
        let policy = ManagedTaskDriverPolicy::default();
        let mut drive: Pin<Box<dyn Future<Output = Result<ManagedTaskRunOutcome, DpopTaskDriverError>> + '_>> =
            if streamed {
                Box::pin(client.drive_task_with_events(
                    cx, cancellation, credential, metadata, task_id, prefix, policy,
                    DpopStreamLimits::default(), no_input,
                    |_| panic!("preflight refusal must not invoke a snapshot observer"),
                    |_| panic!("preflight refusal must not invoke a notification observer"),
                ))
            } else {
                Box::pin(client.drive_task_with_cancellation(
                    cx, cancellation, credential, metadata, task_id, prefix, policy,
                    ManagedCoreLimits::default(), no_input,
                    |_| panic!("preflight refusal must not invoke a snapshot observer"),
                ))
            };
        match drive.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Err(DpopTaskDriverError::Task(DpopTasksError::Core(
                super::super::DpopCoreError::Transport(error),
            )))) => error,
            _ => panic!("the first poll must return the exact local transport disposition"),
        }
    }

    #[test]
    fn both_reply_modes_refuse_precancelled_work_without_requiring_a_runtime() {
        for streamed in [false, true] {
            for cancel_cx in [false, true] {
                for prefix in ["valid", ""] {
                    let cx = Cx::for_testing();
                    assert!(cx.timer_driver().is_none());
                    let cancellation = McpRequestCancellation::new();
                    if cancel_cx { cx.set_cancel_requested(true); } else { cancellation.cancel(); }
                    let (mut client, credential) = client();
                    assert_eq!(
                        first_poll(&mut client, &cx, &cancellation, &credential, streamed, prefix),
                        DpopHttpError::Cancelled,
                    );
                    assert_eq!(cx.checkpoint().is_err(), cancel_cx);
                    assert!(!client.revocation_handle().is_revoked());

                    // A cancelled call neither revokes its credential nor grants
                    // missing runtime authority to a subsequent explicit call.
                    let fresh_cx = Cx::for_testing();
                    assert_eq!(
                        first_poll(&mut client, &fresh_cx, &McpRequestCancellation::new(),
                            &credential, streamed, "fresh"),
                        DpopHttpError::RuntimeUnavailable,
                    );
                }
            }
        }
    }

    #[test]
    fn cancelled_drivers_preserve_cancellation_precedence_over_credential_refusal() {
        for streamed in [false, true] {
            let cx = Cx::for_testing();
            let cancellation = McpRequestCancellation::new();
            cancellation.cancel();
            let (mut client, credential) = client();
            credential.revoke();
            assert_eq!(
                first_poll(&mut client, &cx, &cancellation, &credential, streamed, "valid"),
                DpopHttpError::Cancelled,
            );
            assert!(cx.checkpoint().is_ok());
            assert!(!client.revocation_handle().is_revoked());
        }
    }
}
