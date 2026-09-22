//! Host-approved input resolution over a managed OAuth Task watch.
//!
//! Notifications trigger fresh snapshots. Each acknowledged local update also
//! triggers one reconciliation get, since a partial answer need not emit a
//! notification. Optional observation recovery retains the input ledger across
//! reconnects and interrupted reconciliation reads. Mutations are never retried;
//! no timer polling or background worker is used. The owned driver exposes the
//! shared remote-cancel handle and retains update disposition after interruption.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::{McpRequestCancellation, sha256_bounded};
use fastmcp_protocol::tasks_extension::{Task, TaskId, TaskInputLedger, TaskInputRequests, TaskInputResponses};
use fastmcp_protocol::{FinalEmbeddedElicitationParams, FinalEmbeddedInputRequest, RequestId, FINAL_CLIENT_CAPABILITIES_META_KEY};

use super::{ManagedTaskWatch, ManagedTaskWatchError, ManagedTaskWatchPolicy, ManagedTasksClient};
use super::cancellation::{CancellableTaskWatchError, ManagedTaskCancelHandle};
use super::recovery::{ManagedTaskRecoveryError, ManagedTaskRecoveryPolicy, RecoveryState};
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
    recovery: Option<ManagedTaskRecoveryPolicy>,
}

impl Default for ManagedTaskWatchDrivePolicy {
    fn default() -> Self {
        Self { watch: ManagedTaskWatchPolicy::default(), maximum_updates: 32,
            maximum_input_keys: 256, maximum_input_bytes: 1024 * 1024, recovery: None }
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
        Ok(Self { watch, maximum_updates, maximum_input_keys, maximum_input_bytes, recovery: None })
    }

    /// Opts into bounded observation recovery while retaining this run's input
    /// history, update count, request IDs and original deadline. Reconnection
    /// uses the same implementation as observation-only recovering watches.
    /// The watch record budget is partitioned across the initial connection and
    /// every permitted reconnect; each needs at least two records.
    ///
    /// A failed update is NEVER recovered or replayed. Only a lost observation
    /// or the failed get AFTER an admitted update acknowledgement can recover.
    /// The original credential remains pinned: expiry or a changed credential
    /// during reconnect stops the run before more host input can be resolved.
    pub fn with_recovery(
        mut self,
        recovery: ManagedTaskRecoveryPolicy,
    ) -> Result<Self, ManagedTaskWatchDriveError> {
        self.recovery = Some(recovery);
        self.connection_policy()?;
        Ok(self)
    }

    fn connection_policy(self) -> Result<ManagedTaskWatchPolicy, ManagedTaskWatchDriveError> {
        match self.recovery {
            Some(recovery) => Ok(recovery.connection_policy(self.watch)?),
            None => Ok(self.watch),
        }
    }
}

/// Diagnostics retain no task IDs, input answers, credentials or peer bodies.
#[derive(Debug)]
pub enum ManagedTaskWatchDriveError {
    Watch(ManagedTaskWatchError),
    Input(ManagedTaskDriverError),
    Recovery(ManagedTaskRecoveryError),
    /// A validated remote cancellation ACK stopped this driver. This is not a
    /// terminal Task or proof that an in-flight input update did not commit.
    CancellationRequested,
    /// A concurrent renewal changed the credential during listen admission.
    /// No subsequent host callback or input update has run under that credential.
    CredentialChanged,
}

impl fmt::Display for ManagedTaskWatchDriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Watch(error) => error.fmt(f),
            Self::Input(error) => error.fmt(f),
            Self::Recovery(error) => error.fmt(f),
            Self::CancellationRequested => f.write_str("Task cancellation acknowledged; input driver stopped"),
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
impl From<ManagedTaskRecoveryError> for ManagedTaskWatchDriveError {
    fn from(error: ManagedTaskRecoveryError) -> Self {
        match error {
            ManagedTaskRecoveryError::Watch(error) => Self::Watch(error),
            ManagedTaskRecoveryError::CredentialChanged => Self::CredentialChanged,
            error => Self::Recovery(error),
        }
    }
}
impl From<CancellableTaskWatchError> for ManagedTaskWatchDriveError {
    fn from(error: CancellableTaskWatchError) -> Self {
        match error {
            CancellableTaskWatchError::CancellationRequested => Self::CancellationRequested,
            CancellableTaskWatchError::Closed => ManagedTaskWatchError::Closed.into(),
            CancellableTaskWatchError::Watch(error) => error.into(),
            CancellableTaskWatchError::Recovery(error) => error.into(),
            CancellableTaskWatchError::Session(error) => error.into(),
        }
    }
}

/// Local evidence about the most recent input update, not remote Task status.
/// Cancellation, close and future abandonment never clear this disposition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TaskInputUpdateState {
    #[default]
    NotAttempted,
    /// The update round started, but its acknowledgement has not been admitted.
    /// Even a failed discovery is conservatively included. Do not replay it.
    Unconfirmed,
    /// A complete typed update acknowledgement was admitted. Reconciliation or
    /// result delivery can still fail afterwards without erasing this receipt.
    Acknowledged,
}

#[derive(Default)]
struct UpdateProgress {
    state: TaskInputUpdateState,
    acknowledged: usize,
    request_id: Option<RequestId>,
}
impl UpdateProgress {
    fn begin(&mut self, id: RequestId, maximum: usize) -> Result<(), ManagedTaskDriverError> {
        if self.state == TaskInputUpdateState::Unconfirmed {
            return Err(ManagedTaskDriverError::UnexpectedResponse);
        }
        if self.acknowledged >= maximum { return Err(ManagedTaskDriverError::UpdateLimit); }
        self.request_id = Some(id);
        self.state = TaskInputUpdateState::Unconfirmed;
        Ok(())
    }

    fn acknowledge(&mut self) -> Result<(), ManagedTaskDriverError> {
        if self.state != TaskInputUpdateState::Unconfirmed {
            return Err(ManagedTaskDriverError::UnexpectedResponse);
        }
        // begin is bounded by the validated policy (at most 128 updates).
        self.acknowledged += 1;
        self.state = TaskInputUpdateState::Acknowledged;
        Ok(())
    }
}

impl ManagedTasksClient {
    /// Observes one existing Task and resolves input only through the supplied
    /// host callback. Responses may cover a nonempty subset of unresolved keys;
    /// `ReturnToCaller` pauses without an update. Advertised roots, sampling and
    /// elicitation capabilities gate every resolver invocation.
    ///
    /// This convenience uses the same owned driver as `watch_task_inputs`.
    /// Use that constructor to retain update disposition or obtain a separate
    /// remote-cancel handle while host input is pending. Without using that
    /// handle, this operation never issues a remote cancellation.
    /// One identity sequence covers all reads and updates. Acknowledged keys
    /// are not answered again during recovery; changed descriptors are refused.
    /// No creating call or failed mutation is retried. The ledger is volatile:
    /// restarting is not permission to replay an update with a lost reply.
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

    /// Local cancellation releases owned work without cancelling the ambient
    /// Cx, siblings or the remote Task. Synchronous callbacks must cooperate.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task_watching_with_cancellation<R, F, O>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, task_id: TaskId,
        id_prefix: String, policy: ManagedTaskWatchDrivePolicy, resolve: R, observe: O,
    ) -> Result<ManagedTaskRunOutcome, ManagedTaskWatchDriveError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskWatchDriveError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskWatchDriveError>,
    {
        let mut driver = self.watch_task_inputs_with_cancellation(
            cx, cancellation, task_id, id_prefix, policy,
        ).await?;
        Box::pin(driver.drive(cx, resolve, observe)).await
    }

    /// Admit a single Task's input driver without reading a snapshot, invoking
    /// host code, or updating the Task. The returned owner exposes cancel_handle
    /// before drive is polled, so remote cancellation can interrupt a pending
    /// resolver, read, update reply or recovery backoff.
    ///
    /// The complete selection must be acknowledged first. All input work AND
    /// remote cancellation use the opening credential, never an implicitly
    /// renewed input authority. Initial admission, caller pauses and all later
    /// work share one finite deadline. The driver creates no runtime or worker.
    pub async fn watch_task_inputs(
        &self, cx: &Cx, task_id: TaskId, id_prefix: String,
        policy: ManagedTaskWatchDrivePolicy,
    ) -> Result<ManagedTaskWatchDriver, ManagedTaskWatchDriveError> {
        self.watch_task_inputs_with_cancellation(
            cx, &McpRequestCancellation::new(), task_id, id_prefix, policy,
        ).await
    }

    /// Retains the supplied request-local cancellation domain without taking
    /// permission to cancel that shared token. Invalid IDs, policy, and cancel
    /// encodings are refused before credential acquisition or network effects.
    pub async fn watch_task_inputs_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, task_id: TaskId,
        id_prefix: String, policy: ManagedTaskWatchDrivePolicy,
    ) -> Result<ManagedTaskWatchDriver, ManagedTaskWatchDriveError> {
        self.session.check(cx, cancellation)?;
        let _ = super::WatchState::new(vec![task_id.clone()], policy.watch.maximum_snapshots)?;
        let _ = super::WatchIds::new(id_prefix.clone())?;
        let connection_policy = policy.connection_policy()?;
        let deadline = deadline_after(cx, policy.watch.timeout)?;
        let mut remote_cancel = ManagedTaskCancelHandle::for_observation(
            self, task_id.clone(), &id_prefix, cancellation, deadline,
        )?;
        let credential = Arc::new(self.session.await_active(cx, cancellation, deadline, None, async {
            self.session.credential_with_cancellation(cx, cancellation).await
        }).await?);
        remote_cancel.pin_credential(Arc::clone(&credential))?;
        let mut watch = Box::pin(self.session.await_active(
            cx, cancellation, deadline, Some(credential.expires_at), async {
                Ok(self.watch_tasks_with_cancellation(
                    cx, cancellation, vec![task_id], id_prefix, connection_policy,
                ).await)
            },
        )).await??;
        let generation = watch.subscription.as_ref()
            .ok_or(ManagedTaskWatchError::Closed)?.credential_generation();
        if generation != credential.generation { return Err(ManagedTaskWatchDriveError::CredentialChanged); }
        check_drive(self, cx, cancellation, deadline, &credential)?;
        watch.deadline = watch.deadline.min(deadline);
        Ok(ManagedTaskWatchDriver {
            client: self.clone(), cancellation: cancellation.clone(), deadline, policy,
            credential: Some(credential), watch: Some(watch), remote_cancel,
            progress: UpdateProgress::default(),
        })
    }
}

/// Owned, one-shot input execution over the existing authenticated Task watch.
///
/// drive transfers its socket and credential before suspension. Dropping a
/// POLLED drive closes observation and future cancel admission permanently,
/// including while a resolver or update is pending. Unpolled futures do nothing.
/// ReturnToCaller also ends this run; it does not restore an old input challenge
/// as retry authority. No implicit remote cancellation occurs on drop/close.
///
/// A successful remote cancellation produces CancellationRequested, not a
/// fabricated terminal. Inspect update_state afterwards: an interrupted update
/// may have committed. The actual last acknowledgement and correlation ID stay
/// available on this owner after any return, error, close or abandoned future.
/// This evidence is process-local, not a durable mutation-recovery journal.
#[must_use = "retain the input driver to control cancellation and inspect update disposition"]
pub struct ManagedTaskWatchDriver {
    client: ManagedTasksClient,
    cancellation: McpRequestCancellation,
    deadline: Time,
    policy: ManagedTaskWatchDrivePolicy,
    credential: Option<Arc<OAuthCredentialSnapshot>>,
    watch: Option<ManagedTaskWatch>,
    remote_cancel: ManagedTaskCancelHandle,
    progress: UpdateProgress,
}

impl ManagedTaskWatchDriver {
    /// All clones share the existing controller's one-attempt reservation.
    pub fn cancel_handle(&self) -> ManagedTaskCancelHandle { self.remote_cancel.clone() }
    pub fn update_state(&self) -> TaskInputUpdateState { self.progress.state }
    pub fn acknowledged_updates(&self) -> usize { self.progress.acknowledged }
    /// Correlation only, never an idempotency key or proof of remote rollback.
    pub fn last_update_request_id(&self) -> Option<&RequestId> { self.progress.request_id.as_ref() }

    pub fn close(&mut self) {
        self.remote_cancel.close_observation();
        self.watch = None;
        self.credential = None;
    }

    /// Run once through current snapshots and explicit host input. A validated
    /// cancel ACK wakes pending work; a failed cancel attempt does not. All host
    /// callbacks and update effects are checked against the same stop decision.
    /// A terminal is elected only after validation and the observer callback.
    /// Synchronous callbacks must return promptly; completed host side effects
    /// cannot be recalled by a racing cancellation.
    pub async fn drive<R, F, O>(
        &mut self, cx: &Cx, mut resolve: R, mut observe: O,
    ) -> Result<ManagedTaskRunOutcome, ManagedTaskWatchDriveError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskWatchDriveError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskWatchDriveError>,
    {
        if self.remote_cancel.cancellation_requested() {
            self.close();
            return Err(ManagedTaskWatchDriveError::CancellationRequested);
        }
        let mut watch = self.watch.take().ok_or(ManagedTaskWatchError::Closed)?;
        let remote = self.remote_cancel.clone();
        // This lease is intentionally never disarmed: drive is one-shot on
        // success, error, panic or abandonment, not just on a remote cancel.
        let _lease = remote.read_lease();
        let credential = self.credential.take().ok_or(ManagedTaskWatchError::Closed)?;
        let client = self.client.clone();
        let cancellation = self.cancellation.clone();
        let deadline = self.deadline;
        let running = Box::pin(client.session.await_active(
            cx, &cancellation, deadline, Some(credential.expires_at), async {
                Ok(self.drive_active(cx, &mut watch, &credential, &mut resolve, &mut observe).await)
            },
        ));
        remote.until_acknowledged(running).await??
    }

    fn check(&self, cx: &Cx, credential: &OAuthCredentialSnapshot) -> Result<(), ManagedTaskWatchDriveError> {
        if self.remote_cancel.cancellation_requested() { return Err(ManagedTaskWatchDriveError::CancellationRequested); }
        check_drive(&self.client, cx, &self.cancellation, self.deadline, credential)
    }

    async fn drive_active<R, F, O>(
        &mut self, cx: &Cx, watch: &mut ManagedTaskWatch, credential: &OAuthCredentialSnapshot,
        resolve: &mut R, observe: &mut O,
    ) -> Result<ManagedTaskRunOutcome, ManagedTaskWatchDriveError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskWatchDriveError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskWatchDriveError>,
    {
        let client = self.client.clone();
        let cancellation = self.cancellation.clone();
        let deadline = self.deadline;
        let policy = self.policy;
        let mut recovery = policy.recovery.map(|recovery|
            RecoveryState::new(watch, policy.connection_policy().expect("policy admitted before opening"), recovery));
        let mut ledger = InputHistory::default();
        let mut reconciled = None;
        loop {
            self.check(cx, credential)?;
            let task = match reconciled.take() {
                Some(task) => task,
                None => {
                    let snapshot = match recovery.as_mut() {
                        Some(recovery) => Box::pin(recovery.next_snapshot(cx, watch, Some(credential))).await?,
                        None => Box::pin(watch.next_snapshot_with_credential(cx, Some(credential))).await?,
                    };
                    snapshot.ok_or(ManagedTaskWatchError::UnexpectedEvent)?.task
                }
            };
            self.check(cx, credential)?;
            observe(&task)?;
            self.check(cx, credential)?;
            if matches!(&*task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
                self.remote_cancel.select_terminal()?;
                return Ok(ManagedTaskRunOutcome::Terminal(task));
            }
            let Task::InputRequired { input_requests, .. } = &*task else { continue; };
            if policy.maximum_updates == 0 { return Ok(ManagedTaskRunOutcome::InputRequired(task)); }
            let pending = ledger.unanswered(input_requests, policy)?;
            if pending.requests.is_empty() { continue; }
            if self.progress.acknowledged >= policy.maximum_updates { return Err(ManagedTaskDriverError::UpdateLimit.into()); }
            admit_capabilities(&client.metadata, &pending.requests)?;
            self.check(cx, credential)?;
            let resolution = resolve(pending.requests.clone());
            self.check(cx, credential)?;
            let action = resolution.await?;
            self.check(cx, credential)?;
            let ManagedTaskInputAction::Respond(responses) = action else {
                return Ok(ManagedTaskRunOutcome::InputRequired(task));
            };
            // Reserve capacity and encode BOTH requests before dispatching the
            // update, so its mandatory reconciliation always has a local slot.
            let next_ledger = ledger.with_answers(&pending, &responses)?;
            watch.state.reserve_snapshot()?;
            let update_ids = watch.ids.next_pair()?;
            let get_ids = watch.ids.next_pair()?;
            let update = prepare(client.session.resource().as_str(), &client.metadata,
                &update_ids.operation, ManagedTaskRequest::Update { task, input_responses: responses }, client.limits)?;
            let update_id = update_ids.operation.clone();
            let update_round = client.prepare_round(update_ids, update)?;
            let task_id = watch.state.task_ids[0].clone();
            let get = prepare(client.session.resource().as_str(), &client.metadata,
                &get_ids.operation, ManagedTaskRequest::Get(task_id), client.limits)?;
            let get_round = client.prepare_round(get_ids, get)?;
            self.check(cx, credential)?;
            let call_deadline = deadline.min(deadline_after(cx, client.limits.timeout)?);
            // Retain uncertainty before the first await of a mutation round.
            // Observation recovery deliberately cannot retry anything here.
            self.progress.begin(update_id, policy.maximum_updates)?;
            let mut call = client.execute_round(cx, &cancellation, update_round,
                credential, call_deadline, client.limits.records).await?;
            if !matches!(call.next_event(cx).await?, Some(ManagedTaskEvent::Updated(_))) {
                return Err(ManagedTaskWatchError::UnexpectedEvent.into());
            }
            self.progress.acknowledge()?;
            ledger = next_ledger;
            drop(call);
            self.check(cx, credential)?;
            let observed = async {
                let call_deadline = deadline.min(deadline_after(cx, client.limits.timeout)?);
                let mut call = client.execute_round(cx, &cancellation, get_round,
                    credential, call_deadline, client.limits.records).await?;
                let Some(ManagedTaskEvent::Snapshot(snapshot)) = call.next_event(cx).await? else {
                    return Err(ManagedTaskWatchError::UnexpectedEvent);
                };
                Ok::<_, ManagedTaskWatchError>(snapshot.task)
            }.await;
            self.check(cx, credential)?;
            match observed {
                Ok(task) => {
                    watch.finished = watch.state.record_snapshot(&task)?;
                    if let Some(recovery) = recovery.as_mut() { recovery.record_snapshot(watch, &task)?; }
                    if watch.finished { watch.close(); }
                    reconciled = Some(Box::new(task));
                }
                Err(error) => match recovery.as_mut() {
                    Some(recovery) => {
                        // Only observation after an admitted ACK can recover;
                        // input history, update receipt and all budgets survive.
                        Box::pin(recovery.reconnect_after(cx, watch, Some(credential), error)).await?;
                    }
                    None => return Err(error.into()),
                },
            }
        }
    }
}
impl Drop for ManagedTaskWatchDriver {
    fn drop(&mut self) { self.remote_cancel.close_observation(); }
}
impl fmt::Debug for ManagedTaskWatchDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedTaskWatchDriver")
            .field("update_state", &self.progress.state)
            .field("acknowledged_updates", &self.progress.acknowledged)
            .finish_non_exhaustive()
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

    #[test]
    fn combined_recovery_policy_preserves_input_limits_and_rejects_underfunded_streams() {
        let ordinary = ManagedTaskWatchDrivePolicy::default();
        assert!(ordinary.recovery.is_none());
        assert_eq!(ordinary.connection_policy().unwrap(), ordinary.watch);
        let recovering = ordinary.with_recovery(ManagedTaskRecoveryPolicy::default()).unwrap();
        assert_eq!(recovering.maximum_updates, ordinary.maximum_updates);
        assert_eq!(recovering.maximum_input_keys, ordinary.maximum_input_keys);
        assert_eq!(recovering.maximum_input_bytes, ordinary.maximum_input_bytes);
        assert_eq!(recovering.watch, ordinary.watch);
        assert_eq!(recovering.connection_policy().unwrap(),
            ManagedTaskRecoveryPolicy::default().connection_policy(ordinary.watch).unwrap());
        let watch = ManagedTaskWatchPolicy::new(std::time::Duration::from_secs(60), 8, 9).unwrap();
        let underfunded = ManagedTaskWatchDrivePolicy::new(watch, 2, 2, 1024).unwrap();
        assert!(matches!(underfunded.with_recovery(ManagedTaskRecoveryPolicy::default()),
            Err(ManagedTaskWatchDriveError::Recovery(ManagedTaskRecoveryError::InvalidPolicy))));
    }

    #[test]
    fn recovery_preserves_typed_watch_and_credential_failures() {
        assert!(matches!(ManagedTaskWatchDriveError::from(ManagedTaskRecoveryError::CredentialChanged),
            ManagedTaskWatchDriveError::CredentialChanged));
        assert!(matches!(ManagedTaskWatchDriveError::from(ManagedTaskRecoveryError::Watch(ManagedTaskWatchError::SnapshotLimit)),
            ManagedTaskWatchDriveError::Watch(ManagedTaskWatchError::SnapshotLimit)));
        assert!(matches!(ManagedTaskWatchDriveError::from(ManagedTaskRecoveryError::RecoveryLimit),
            ManagedTaskWatchDriveError::Recovery(ManagedTaskRecoveryError::RecoveryLimit)));
    }

    #[test]
    fn pending_update_cannot_be_replaced_by_another_attempt_or_false_ack() {
        let mut progress = UpdateProgress::default();
        assert!(progress.acknowledge().is_err());
        assert_eq!(progress.state, TaskInputUpdateState::NotAttempted);
        progress.begin(RequestId::Number(7), 2).unwrap();
        assert!(progress.begin(RequestId::Number(9), 2).is_err());
        assert_eq!(progress.request_id, Some(RequestId::Number(7)));
        assert_eq!(progress.state, TaskInputUpdateState::Unconfirmed);
        assert_eq!(progress.acknowledged, 0);
        progress.acknowledge().unwrap();
        assert!(progress.acknowledge().is_err());
        assert_eq!(progress.state, TaskInputUpdateState::Acknowledged);
        assert_eq!(progress.acknowledged, 1);
    }

    #[test]
    fn next_input_update_retains_previous_count_and_cannot_reset_the_limit() {
        let mut progress = UpdateProgress::default();
        assert!(progress.begin(RequestId::Number(1), 0).is_err());
        assert!(progress.request_id.is_none());
        progress.begin(RequestId::Number(1), 2).unwrap();
        progress.acknowledge().unwrap();
        progress.begin(RequestId::Number(3), 2).unwrap();
        assert_eq!(progress.acknowledged, 1);
        assert_eq!(progress.state, TaskInputUpdateState::Unconfirmed);
        progress.acknowledge().unwrap();
        assert!(matches!(progress.begin(RequestId::Number(5), 2), Err(ManagedTaskDriverError::UpdateLimit)));
        assert_eq!(progress.acknowledged, 2);
        assert_eq!(progress.state, TaskInputUpdateState::Acknowledged);
        assert_eq!(progress.request_id, Some(RequestId::Number(3)));
    }

    #[test]
    fn remote_cancel_is_distinct_from_local_cancellation_and_preserves_typed_errors() {
        assert!(matches!(ManagedTaskWatchDriveError::from(CancellableTaskWatchError::CancellationRequested),
            ManagedTaskWatchDriveError::CancellationRequested));
        assert!(matches!(ManagedTaskWatchDriveError::from(CancellableTaskWatchError::Closed),
            ManagedTaskWatchDriveError::Watch(ManagedTaskWatchError::Closed)));
        assert!(matches!(ManagedTaskWatchDriveError::from(CancellableTaskWatchError::Session(OAuthSessionError::Cancelled)),
            ManagedTaskWatchDriveError::Watch(ManagedTaskWatchError::Session(OAuthSessionError::Cancelled))));
        assert!(matches!(ManagedTaskWatchDriveError::from(CancellableTaskWatchError::Recovery(ManagedTaskRecoveryError::CredentialChanged)),
            ManagedTaskWatchDriveError::CredentialChanged));
    }
}
