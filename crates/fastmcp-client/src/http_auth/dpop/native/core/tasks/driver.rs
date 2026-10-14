//! Bounded polling and explicit host input for DPoP-protected Tasks.
//!
//! This composes the existing negotiated Task POSTs and the shared Task input
//! ledger. It does not create Tasks, refresh credentials, retry failed POSTs,
//! or continue running after its caller-owned future is dropped.

use std::fmt;
use std::future::Future;

use asupersync::Cx;
use asupersync::time::Sleep;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::tasks_extension::{Task, TaskId, TaskInputRequests};
use fastmcp_protocol::{FinalRequestMeta, RequestId};

use super::{
    Admitted, DpopCredential, DpopHttpClient, DpopHttpError, DpopHttpResponse,
    DpopTaskOperation, DpopTasksError, ManagedCoreError, ManagedCoreLimits,
    ManagedTaskEvent, ManagedTaskRequest, ManagedTasksError, Prepared, WaitBounds,
    check_live,
};
use super::super::super::within;
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
}

impl fmt::Display for DpopTaskDriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdPrefix => f.write_str("invalid DPoP Task driver identity prefix"),
            Self::IdentityExhausted => f.write_str("DPoP Task driver identities exhausted"),
            Self::Driver(error) => error.fmt(f),
            Self::Task(error) => error.fmt(f),
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
    /// JSON-only, caller-driven execution: no refresh, retry, subscription,
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
        mut resolve: R,
        mut observe: O,
    ) -> Result<ManagedTaskRunOutcome, DpopTaskDriverError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        let timeout = policy.timeout.min(limits.timeout()).min(self.policy.timeout);
        let bounds = WaitBounds::new(cx, timeout, credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let mut run = Run::new(id_prefix, policy, limits)?;
        let input_metadata = serde_json::to_value(&metadata)
            .map_err(|_| ManagedTasksError::InvalidRequest)?;
        let mut due = cx.now();
        loop {
            check_live(cx, cancellation, &self.session, credential, bounds)?;
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
            let event = self.drive_task_pair(cx, cancellation, credential, bounds,
                &mut run, prepared).await?;
            let ManagedTaskEvent::Snapshot(snapshot) = event else {
                return Err(ManagedTaskDriverError::UnexpectedResponse.into());
            };
            let task = snapshot.task;
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
            let event = self.drive_task_pair(cx, cancellation, credential, bounds,
                &mut run, prepared).await?;
            if !matches!(event, ManagedTaskEvent::Updated(_)) {
                return Err(ManagedTaskDriverError::UnexpectedResponse.into());
            }
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            run.state.record_answers(&answered, &fingerprints, policy.maximum_state_bytes)?;
        }
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
