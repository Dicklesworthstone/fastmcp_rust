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
use fastmcp_protocol::tasks_extension::{
    Task, TaskId, TaskInputLedger, TaskInputRequests, TaskInputResponses,
};
use fastmcp_protocol::{CorrelationKey, FINAL_CLIENT_CAPABILITIES_META_KEY, ServerNotification};

use crate::http_auth::rpc::interaction::{
    ManagedInteractionError, admit_embedded_input, normalize_embedded_input_context,
};

use super::{
    BoundedWriter, ManagedTaskCall, ManagedTaskEvent, ManagedTaskRequest, ManagedTaskRequestIds,
    ManagedTasksClient, ManagedTasksError, OAuthSessionError, deadline_after, prepare,
};

/// One finite budget for the entire poll/resolve/update lifecycle, including
/// credential renewal, discovery, network reads, host input and poll delays.
#[derive(Clone, Copy, Debug)]
pub struct ManagedTaskDriverPolicy {
    pub(crate) minimum_poll_interval: Duration,
    pub(crate) timeout: Duration,
    pub(crate) maximum_polls: usize,
    pub(crate) maximum_updates: usize,
    pub(crate) maximum_input_keys: usize,
    pub(crate) maximum_state_bytes: usize,
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
            || timeout.is_zero()
            || timeout > Duration::from_hours(24)
            || !(1..=4096).contains(&maximum_polls)
            || maximum_updates > 128
            || maximum_input_keys > 4096
            || !(1..=4 * 1024 * 1024).contains(&maximum_state_bytes)
        {
            return Err(ManagedTaskDriverError::InvalidPolicy);
        }
        Ok(Self {
            minimum_poll_interval,
            timeout,
            maximum_polls,
            maximum_updates,
            maximum_input_keys,
            maximum_state_bytes,
        })
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
        if let Self::Task(error) = self {
            return fmt::Display::fmt(error, f);
        }
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
            Self::CapabilityNotAdvertised => {
                "Task input requires an unadvertised client capability"
            }
            Self::UnexpectedResponse => "managed Task driver received an unexpected result",
            Self::AbortedByHost => "managed Task driver stopped by its host",
            Self::Task(_) => unreachable!(),
        })
    }
}

impl std::error::Error for ManagedTaskDriverError {}
impl From<ManagedTasksError> for ManagedTaskDriverError {
    fn from(error: ManagedTasksError) -> Self {
        Self::Task(error)
    }
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
        self.drive_task_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            task_id,
            policy,
            next_ids,
            resolve,
            observe,
        )
        .await
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
        self.drive_task_with_events(
            cx, cancellation, task_id, policy, next_ids, resolve, observe, |_| true,
        )
        .await
    }

    /// Follows one existing Task while delivering admitted get/update
    /// notifications before the method's terminal response has arrived.
    ///
    /// `notify` returns true to continue or false to stop locally. It must be
    /// brief, nonblocking, and apply the host's disclosure policy to peer data.
    /// Notifications are not snapshots or update acknowledgements: `observe`
    /// and the input ledger advance only after the existing decoder has checked
    /// the correlated method result and clean response EOF. Already delivered
    /// notifications and committed remote updates cannot be recalled.
    ///
    /// This is the same polling/input state machine as [`Self::drive_task`].
    /// JSON replies still work; SSE uses the existing managed response owner,
    /// not a second parser or a notification history buffer. Per-response
    /// byte/record limits remain in force, and the policy bounds the total
    /// number of get/update pairs. No callback resets either limit or the
    /// original driver deadline. Notifications, snapshot observers, and input
    /// resolvers retain the original response credential's expiry and revocation
    /// even if another caller renews login. Resolver construction and its future
    /// are guarded separately: revocation during construction cannot start the
    /// returned future. Pending host work is woken when that credential is revoked.
    ///
    /// Failure, callback refusal, cancellation or abandonment stops this run
    /// without replay, reconnect, automatic remote cancellation, or a worker.
    /// Normal managed credential acquisition between explicit Task operations
    /// remains unchanged. An input-required snapshot is not permission to
    /// invoke unadvertised capabilities or repeat an acknowledged answer.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task_with_events<I, R, F, O, N>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: TaskId,
        policy: ManagedTaskDriverPolicy,
        mut next_ids: I,
        mut resolve: R,
        mut observe: O,
        mut notify: N,
    ) -> Result<ManagedTaskRunOutcome, ManagedTaskDriverError>
    where
        I: FnMut() -> Result<ManagedTaskRequestIds, ManagedTaskDriverError>,
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
        N: FnMut(&ServerNotification) -> bool,
    {
        self.session
            .check(cx, cancellation)
            .map_err(ManagedTasksError::from)?;
        let deadline = deadline_after(cx, policy.timeout).map_err(ManagedTasksError::from)?;
        // The outer guard includes host callbacks and sleeps as well as I/O.
        // Explicit inner checks also stop a ready host callback that overruns
        // its deadline before this composite future next returns Poll::Pending.
        self.session
            .await_active(cx, cancellation, deadline, None, async {
                Ok(async {
                    let mut state = DriverState::default();
                    let mut polls = 0;
                    let mut updates = 0;
                    let mut due = cx.now();
                    loop {
                        if polls >= policy.maximum_polls {
                            return Err(ManagedTaskDriverError::PollLimit);
                        }
                        if cx.now() < due {
                            Sleep::new(due).await;
                        }
                        self.check_driver(cx, cancellation, deadline)?;
                        let ids = next_ids()?;
                        self.check_driver(cx, cancellation, deadline)?;
                        state.reserve_ids(&ids, policy.maximum_state_bytes)?;
                        polls += 1;
                        self.check_driver(cx, cancellation, deadline)?;
                        let mut call = self
                            .request_with_cancellation(
                                cx,
                                cancellation,
                                ids,
                                ManagedTaskRequest::Get(task_id.clone()),
                            )
                            .await?;
                        let Some(ManagedTaskEvent::Snapshot(snapshot)) =
                            self.next_driver_terminal(
                                cx, cancellation, deadline, &mut call, &mut notify,
                            )
                            .await?
                        else {
                            return Err(ManagedTaskDriverError::UnexpectedResponse);
                        };
                        let callback_lifetime = DriverCallbackLifetime::new(&call, deadline);
                        drop(call);
                        let task = snapshot.task;
                        // Keep the peer's relative polling hint anchored to receipt,
                        // not to the later completion of a potentially slow resolver.
                        due = next_poll_time(cx.now(), &task, policy.minimum_poll_interval)?;
                        self.check_driver(cx, cancellation, deadline)?;
                        callback_lifetime.run(cx, || {
                            std::future::ready(observe(&task))
                        })
                        .await?;
                        self.check_driver(cx, cancellation, deadline)?;
                        if matches!(
                            task,
                            Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)
                        ) {
                            return Ok(ManagedTaskRunOutcome::Terminal(Box::new(task)));
                        }
                        let Task::InputRequired { input_requests, .. } = &task else {
                            continue;
                        };
                        // Observation-only mode cannot invoke input handlers, even
                        // when the configured input-key budget is zero.
                        if policy.maximum_updates == 0 {
                            return Ok(ManagedTaskRunOutcome::InputRequired(Box::new(task)));
                        }
                        let (pending, fingerprints) = state.unanswered(input_requests, policy)?;
                        if pending.is_empty() {
                            continue;
                        }
                        if updates >= policy.maximum_updates {
                            return Err(ManagedTaskDriverError::UpdateLimit);
                        }
                        let callback_inputs = admit_capabilities(&self.metadata, &pending)?;
                        self.check_driver(cx, cancellation, deadline)?;
                        let action = callback_lifetime.run(cx, || {
                            resolve(callback_inputs)
                        })
                        .await?;
                        self.check_driver(cx, cancellation, deadline)?;
                        let ManagedTaskInputAction::Respond(responses) = action else {
                            return Ok(ManagedTaskRunOutcome::InputRequired(Box::new(task)));
                        };
                        validate_answers(&pending, &responses)?;
                        let answered: Vec<_> = responses.keys().cloned().collect();
                        let update = ManagedTaskRequest::Update {
                            task: Box::new(task),
                            input_responses: responses,
                        };
                        // Validate the actual encoded update before asking the host
                        // for IDs or allowing a renewal/discovery effect.
                        let provisional = fastmcp_protocol::RequestId::Number(0);
                        let _ = prepare(
                            self.session.resource().as_str(),
                            &self.metadata,
                            &provisional,
                            update_for_validation(&update)?,
                            self.limits,
                        )?;
                        self.check_driver(cx, cancellation, deadline)?;
                        let ids = callback_lifetime.run(cx, || {
                            std::future::ready(next_ids())
                        })
                        .await?;
                        self.check_driver(cx, cancellation, deadline)?;
                        state.reserve_ids(&ids, policy.maximum_state_bytes)?;
                        // Include the newly reserved IDs before verifying that an
                        // acknowledged update can fit our retained input ledger.
                        state.answer_bytes(&answered, &fingerprints, policy.maximum_state_bytes)?;
                        updates += 1;
                        self.check_driver(cx, cancellation, deadline)?;
                        // Host work retained only the completed response's
                        // lifetime, never its body or bearer text. The unchanged
                        // managed acquisition policy owns this explicit update.
                        let mut call = self
                            .request_with_cancellation(cx, cancellation, ids, update)
                            .await?;
                        if !matches!(
                            self.next_driver_terminal(
                                cx, cancellation, deadline, &mut call, &mut notify,
                            )
                            .await?,
                            Some(ManagedTaskEvent::Updated(_))
                        ) {
                            return Err(ManagedTaskDriverError::UnexpectedResponse);
                        }
                        self.check_driver(cx, cancellation, deadline)?;
                        // Only an admitted update acknowledgement advances local
                        // input state. Any error/drop before it exits this run.
                        state.record_answers(
                            &answered,
                            &fingerprints,
                            policy.maximum_state_bytes,
                        )?;
                    }
                }
                .await)
            })
            .await
            .map_err(ManagedTasksError::from)?
    }

    // Both get and update consume this same decoder-owned event stream. A
    // notification cannot accidentally satisfy the mutation ACK branch, and
    // no rejected/abandoned read can leave a reusable body in the driver.
    async fn next_driver_terminal<N>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Time,
        call: &mut ManagedTaskCall,
        notify: &mut N,
    ) -> Result<Option<ManagedTaskEvent>, ManagedTaskDriverError>
    where
        N: FnMut(&ServerNotification) -> bool,
    {
        loop {
            self.check_driver(cx, cancellation, deadline)?;
            let event = call.next_event(cx).await?;
            self.check_driver(cx, cancellation, deadline)?;
            match event {
                Some(ManagedTaskEvent::Notification(notification)) => {
                    DriverCallbackLifetime::new(call, deadline)
                        .notify(cx, &notification, notify)
                        .await?;
                }
                terminal => return Ok(terminal),
            }
        }
    }

    fn check_driver(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Time,
    ) -> Result<(), ManagedTaskDriverError> {
        self.session
            .check(cx, cancellation)
            .map_err(ManagedTasksError::from)?;
        let deadline = cx
            .budget()
            .deadline
            .map_or(deadline, |parent| parent.min(deadline));
        if cx.now() >= deadline {
            return Err(ManagedTasksError::from(OAuthSessionError::TimedOut).into());
        }
        Ok(())
    }
}

// Guard construction separately from polling the returned host future. Wrapping
// `construct().await` as one future would allow a constructor that revokes its
// credential to start host work before the outer guard observes revocation.
// Both guards retain the same response authority; neither acquires credentials,
// changes a deadline, or transfers host work to a detached task.
// Do not borrow a response/parser across host awaits. An owned response needs
// Send, not Sync; sharing &ManagedTaskCall here would strengthen the public
// driver's future bounds. This snapshot retains only the existing guard's
// session/stop signals and original clocks, never a bearer or socket.
struct DriverCallbackLifetime {
    session: super::ManagedOAuthSession,
    cancellation: McpRequestCancellation,
    revocation: McpRequestCancellation,
    expires_at: std::time::Instant,
    deadline: Time,
}

impl DriverCallbackLifetime {
    fn new(call: &ManagedTaskCall, deadline: Time) -> Self {
        Self {
            session: call.session.clone(),
            cancellation: call.cancellation.clone(),
            revocation: call.revocation.clone(),
            expires_at: call.expires_at,
            deadline: deadline.min(call.deadline),
        }
    }

    async fn run<T, C, F>(&self, cx: &Cx, construct: C) -> Result<T, ManagedTaskDriverError>
    where
        C: FnOnce() -> F,
        F: Future<Output = Result<T, ManagedTaskDriverError>>,
    {
        let future = self.session
            .await_credential(
                cx,
                &self.cancellation,
                self.deadline,
                self.expires_at,
                &self.revocation,
                async { Ok(construct()) },
            )
            .await
            .map_err(ManagedTasksError::from)?;
        self.session
            .await_credential(
                cx,
                &self.cancellation,
                self.deadline,
                self.expires_at,
                &self.revocation,
                async { Ok(future.await) },
            )
            .await
            .map_err(ManagedTasksError::from)?
    }

    // Several buffered notifications may be ready in one poll. Use the SAME
    // guard as observers and resolvers, including for a refusing callback.
    async fn notify<N>(
        &self,
        cx: &Cx,
        notification: &ServerNotification,
        notify: &mut N,
    ) -> Result<(), ManagedTaskDriverError>
    where
        N: FnMut(&ServerNotification) -> bool,
    {
        self.run(cx, || {
            std::future::ready(if notify(notification) {
                Ok(())
            } else {
                Err(ManagedTaskDriverError::AbortedByHost)
            })
        })
        .await
    }
}

fn update_for_validation(
    request: &ManagedTaskRequest,
) -> Result<ManagedTaskRequest, ManagedTaskDriverError> {
    match request {
        ManagedTaskRequest::Update {
            task,
            input_responses,
        } => Ok(ManagedTaskRequest::Update {
            task: task.clone(),
            input_responses: input_responses.clone(),
        }),
        _ => Err(ManagedTaskDriverError::UnexpectedResponse),
    }
}

pub(crate) fn next_poll_time(
    now: Time,
    task: &Task,
    minimum: Duration,
) -> Result<Time, ManagedTaskDriverError> {
    let peer = task
        .base()
        .poll_interval_ms
        .as_ref()
        .map(|hint| hint.try_as_millis())
        .transpose()
        .map_err(|_| ManagedTaskDriverError::UnexpectedResponse)?
        .map(Duration::from_millis)
        .unwrap_or(minimum);
    let nanos = u64::try_from(peer.max(minimum).as_nanos()).unwrap_or(u64::MAX);
    Ok(now.saturating_add_nanos(nanos))
}

#[derive(Default)]
pub(crate) struct DriverState {
    ids: HashSet<CorrelationKey>,
    answered: BTreeMap<String, Sha256Digest>,
    retained_bytes: usize,
}

impl DriverState {
    pub(crate) fn reserve_ids(
        &mut self,
        ids: &ManagedTaskRequestIds,
        maximum: usize,
    ) -> Result<(), ManagedTaskDriverError> {
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            maximum: 8192,
        };
        serde_json::to_writer(&mut writer, &(&ids.discovery, &ids.operation))
            .map_err(|_| ManagedTaskDriverError::InvalidRequestIds)?;
        let one = ids
            .discovery
            .correlation_key()
            .map_err(|_| ManagedTaskDriverError::InvalidRequestIds)?;
        let two = ids
            .operation
            .correlation_key()
            .map_err(|_| ManagedTaskDriverError::InvalidRequestIds)?;
        if one == two || self.ids.contains(&one) || self.ids.contains(&two) {
            return Err(ManagedTaskDriverError::RepeatedRequestId);
        }
        let bytes = self
            .retained_bytes
            .checked_add(writer.bytes.len())
            .ok_or(ManagedTaskDriverError::StateByteLimit)?;
        if bytes > maximum {
            return Err(ManagedTaskDriverError::StateByteLimit);
        }
        self.ids.insert(one);
        self.ids.insert(two);
        self.retained_bytes = bytes;
        Ok(())
    }

    pub(crate) fn unanswered(
        &self,
        requests: &TaskInputRequests,
        policy: ManagedTaskDriverPolicy,
    ) -> Result<(TaskInputRequests, BTreeMap<String, Sha256Digest>), ManagedTaskDriverError> {
        let mut pending = TaskInputRequests::new();
        let mut fingerprints = BTreeMap::new();
        let mut bytes = self.retained_bytes;
        for (key, request) in requests {
            let mut writer = BoundedWriter {
                bytes: Vec::new(),
                maximum: policy.maximum_state_bytes,
            };
            serde_json::to_writer(&mut writer, request)
                .map_err(|_| ManagedTaskDriverError::StateByteLimit)?;
            let digest = sha256_bounded(&writer.bytes, policy.maximum_state_bytes)
                .map_err(|_| ManagedTaskDriverError::StateByteLimit)?;
            if let Some(previous) = self.answered.get(key) {
                if previous != &digest {
                    return Err(ManagedTaskDriverError::InputKeyReused);
                }
                continue;
            }
            if self.answered.len() + pending.len() >= policy.maximum_input_keys {
                return Err(ManagedTaskDriverError::InputLimit);
            }
            bytes = bytes
                .checked_add(key.len())
                .and_then(|n| n.checked_add(32))
                .ok_or(ManagedTaskDriverError::StateByteLimit)?;
            if bytes > policy.maximum_state_bytes {
                return Err(ManagedTaskDriverError::StateByteLimit);
            }
            pending.insert(key.clone(), request.clone());
            fingerprints.insert(key.clone(), digest);
        }
        Ok((pending, fingerprints))
    }

    pub(crate) fn answer_bytes(
        &self,
        keys: &[String],
        fingerprints: &BTreeMap<String, Sha256Digest>,
        maximum: usize,
    ) -> Result<usize, ManagedTaskDriverError> {
        let mut bytes = self.retained_bytes;
        for key in keys {
            if self.answered.contains_key(key) || !fingerprints.contains_key(key) {
                return Err(ManagedTaskDriverError::InvalidInputResponse);
            }
            bytes = bytes
                .checked_add(key.len())
                .and_then(|n| n.checked_add(32))
                .ok_or(ManagedTaskDriverError::StateByteLimit)?;
        }
        if bytes > maximum {
            return Err(ManagedTaskDriverError::StateByteLimit);
        }
        Ok(bytes)
    }

    pub(crate) fn record_answers(
        &mut self,
        keys: &[String],
        fingerprints: &BTreeMap<String, Sha256Digest>,
        maximum: usize,
    ) -> Result<(), ManagedTaskDriverError> {
        let bytes = self.answer_bytes(keys, fingerprints, maximum)?;
        for key in keys {
            self.answered.insert(key.clone(), fingerprints[key].clone());
        }
        self.retained_bytes = bytes;
        Ok(())
    }
}

pub(crate) fn validate_answers(
    requests: &TaskInputRequests,
    responses: &TaskInputResponses,
) -> Result<(), ManagedTaskDriverError> {
    if responses.is_empty() || responses.keys().any(|key| !requests.contains_key(key)) {
        return Err(ManagedTaskDriverError::InvalidInputResponse);
    }
    TaskInputLedger::from_requests(requests)
        .and_then(|ledger| ledger.validate_responses(responses))
        .map_err(|_| ManagedTaskDriverError::InvalidInputResponse)
}

pub(crate) fn admit_capabilities(
    metadata: &serde_json::Value,
    requests: &TaskInputRequests,
) -> Result<TaskInputRequests, ManagedTaskDriverError> {
    let capabilities = &metadata[FINAL_CLIENT_CAPABILITIES_META_KEY];
    for request in requests.values() {
        let wire = serde_json::to_value(request)
            .map_err(|_| ManagedTaskDriverError::UnexpectedResponse)?;
        admit_embedded_input(capabilities, wire).map_err(|error| match error {
            ManagedInteractionError::CapabilityNotAdvertised => {
                ManagedTaskDriverError::CapabilityNotAdvertised
            }
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
        serde_json::from_value(json!({"one":{"method":"roots/list"},"two":{"method":"roots/list"}}))
            .unwrap()
    }
    fn ids(one: i64, two: i64) -> ManagedTaskRequestIds {
        ManagedTaskRequestIds::new(RequestId::Number(one), RequestId::Number(two)).unwrap()
    }
    fn task(interval: Option<u64>) -> Task {
        let mut value = json!({"taskId":"opaque-task","status":"working","createdAt":"2026-09-17T00:00:00Z","lastUpdatedAt":"2026-09-17T00:00:00Z","ttlMs":null});
        if let Some(interval) = interval {
            value["pollIntervalMs"] = json!(interval);
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn poll_hint_never_shortens_the_local_floor_or_wraps_a_large_interval() {
        let now = Time::from_nanos(1000);
        for (hint, expected) in [
            (None, 100_000_000),
            (Some(1), 100_000_000),
            (Some(300), 300_000_000),
        ] {
            assert_eq!(
                next_poll_time(now, &task(hint), Duration::from_millis(100)).unwrap(),
                now.saturating_add_nanos(expected)
            );
        }
        assert_eq!(
            next_poll_time(now, &task(Some(u64::MAX)), Duration::from_millis(1)).unwrap(),
            Time::from_nanos(u64::MAX)
        );
    }

    #[test]
    fn both_ids_are_reserved_atomically_and_numeric_aliases_cannot_recur() {
        let mut state = DriverState::default();
        state.reserve_ids(&ids(1, 2), 4096).unwrap();
        let before = state.retained_bytes;
        assert!(matches!(
            state.reserve_ids(&ids(3, 2), 4096),
            Err(ManagedTaskDriverError::RepeatedRequestId)
        ));
        assert_eq!(state.retained_bytes, before);
        state.reserve_ids(&ids(3, 4), 4096).unwrap();
        let alias =
            ManagedTaskRequestIds::new(serde_json::from_str("2e0").unwrap(), RequestId::Number(5))
                .unwrap();
        assert!(matches!(
            state.reserve_ids(&alias, 4096),
            Err(ManagedTaskDriverError::RepeatedRequestId)
        ));
        let distinct =
            ManagedTaskRequestIds::new(RequestId::String("2".to_owned()), RequestId::Number(5))
                .unwrap();
        state.reserve_ids(&distinct, 4096).unwrap();
    }

    #[test]
    fn partial_answers_remove_only_acknowledged_keys_from_future_resolver_work() {
        let mut state = DriverState::default();
        let policy = ManagedTaskDriverPolicy::default();
        let (pending, fingerprints) = state.unanswered(&inputs(), policy).unwrap();
        let reply: TaskInputResponses =
            serde_json::from_value(json!({"one":{"roots":[]}})).unwrap();
        validate_answers(&pending, &reply).unwrap();
        state
            .record_answers(
                &["one".to_owned()],
                &fingerprints,
                policy.maximum_state_bytes,
            )
            .unwrap();
        let (pending, fingerprints) = state.unanswered(&inputs(), policy).unwrap();
        assert_eq!(
            pending.keys().map(String::as_str).collect::<Vec<_>>(),
            ["two"]
        );
        state
            .record_answers(
                &["two".to_owned()],
                &fingerprints,
                policy.maximum_state_bytes,
            )
            .unwrap();
        assert!(state.unanswered(&inputs(), policy).unwrap().0.is_empty());
    }

    #[test]
    fn reusing_answered_key_with_changed_descriptor_fails_without_mutation() {
        let mut state = DriverState::default();
        let policy = ManagedTaskDriverPolicy::default();
        let (_, fingerprints) = state.unanswered(&inputs(), policy).unwrap();
        state
            .record_answers(
                &["one".to_owned()],
                &fingerprints,
                policy.maximum_state_bytes,
            )
            .unwrap();
        let before = state.retained_bytes;
        let changed = serde_json::from_value(json!({"one":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}}})).unwrap();
        assert!(matches!(
            state.unanswered(&changed, policy),
            Err(ManagedTaskDriverError::InputKeyReused)
        ));
        assert_eq!(state.retained_bytes, before);
        assert_eq!(state.answered.len(), 1);
    }

    #[test]
    fn automatic_updates_reject_empty_foreign_or_wrong_kind_answers() {
        for value in [
            json!({}),
            json!({"other":{"roots":[]}}),
            json!({"one":{"action":"decline"}}),
        ] {
            let replies: TaskInputResponses = serde_json::from_value(value).unwrap();
            assert!(matches!(
                validate_answers(&inputs(), &replies),
                Err(ManagedTaskDriverError::InvalidInputResponse)
            ));
        }
    }

    #[test]
    fn budgets_reject_before_retained_state_changes() {
        let mut state = DriverState::default();
        assert!(matches!(
            state.reserve_ids(&ids(1, 2), 1),
            Err(ManagedTaskDriverError::StateByteLimit)
        ));
        assert!(state.ids.is_empty());
        let mut policy = ManagedTaskDriverPolicy::default();
        policy.maximum_input_keys = 1;
        assert!(matches!(
            state.unanswered(&inputs(), policy),
            Err(ManagedTaskDriverError::InputLimit)
        ));
        assert!(state.answered.is_empty());
        let (_, prints) = state
            .unanswered(&inputs(), ManagedTaskDriverPolicy::default())
            .unwrap();
        assert!(matches!(
            state.record_answers(&["one".to_owned()], &prints, 1),
            Err(ManagedTaskDriverError::StateByteLimit)
        ));
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
        ] {
            assert!(
                ManagedTaskDriverPolicy::new(delay, timeout, polls, updates, inputs, bytes)
                    .is_err()
            );
        }
    }

    #[test]
    fn input_capabilities_are_admitted_before_automatic_resolution() {
        let absent = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{}});
        let roots = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"roots":{}}});
        assert!(matches!(
            admit_capabilities(&absent, &inputs()),
            Err(ManagedTaskDriverError::CapabilityNotAdvertised)
        ));
        assert!(admit_capabilities(&roots, &inputs()).is_ok());
        let sampling = serde_json::from_value(json!({"sample":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":1,"includeContext":"allServers"}}})).unwrap();
        let before = serde_json::to_value(&sampling).unwrap();
        let plain = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"sampling":{}}});
        let context = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"sampling":{"context":{}}}});
        assert!(matches!(
            admit_capabilities(&absent, &sampling),
            Err(ManagedTaskDriverError::CapabilityNotAdvertised)
        ));
        assert!(admit_capabilities(&plain, &sampling).is_ok());
        assert!(admit_capabilities(&context, &sampling).is_ok());
        assert_eq!(serde_json::to_value(&sampling).unwrap(), before);
    }

    #[test]
    fn sampling_tools_and_tool_choice_require_the_tools_capability() {
        for (field, value) in [("tools", json!([])), ("toolChoice", json!({}))] {
            let mut params = json!({"messages":[],"maxTokens":1,"includeContext":"allServers"});
            params[field] = value;
            let requests = serde_json::from_value(
                json!({"sample":{"method":"sampling/createMessage","params":params}}),
            )
            .unwrap();
            let before = serde_json::to_value(&requests).unwrap();
            for sampling in [
                json!({}),
                json!({"context":{}}),
                json!({"tools":null}),
                json!({"tools":[]}),
            ] {
                let metadata = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"sampling":sampling}});
                assert!(matches!(
                    admit_capabilities(&metadata, &requests),
                    Err(ManagedTaskDriverError::CapabilityNotAdvertised)
                ));
            }
            let metadata = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"sampling":{"tools":{}}}});
            let callback =
                serde_json::to_value(admit_capabilities(&metadata, &requests).unwrap()).unwrap();
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
        for elicitation in [
            json!({"future":{}}),
            json!({"url":{}}),
            json!({"form":null}),
            json!({"form":[]}),
        ] {
            let metadata = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"elicitation":elicitation}});
            assert!(matches!(
                admit_capabilities(&metadata, &requests),
                Err(ManagedTaskDriverError::CapabilityNotAdvertised)
            ));
        }
        assert_eq!(serde_json::to_value(&requests).unwrap(), before);
    }

    #[test]
    fn context_normalization_changes_only_ungranted_resolver_copies() {
        let plain = json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"roots":{},"sampling":{}}});
        let granted =
            json!({FINAL_CLIENT_CAPABILITIES_META_KEY:{"roots":{},"sampling":{"context":{}}}});
        for context in [None, Some("none"), Some("thisServer"), Some("allServers")] {
            let mut params = json!({"messages":[],"maxTokens":1});
            if let Some(context) = context {
                params["includeContext"] = json!(context);
            }
            let requests = serde_json::from_value(json!({
                "roots":{"method":"roots/list"},
                "sample":{"method":"sampling/createMessage","params":params}
            }))
            .unwrap();
            let before = serde_json::to_value(&requests).unwrap();
            let callback =
                serde_json::to_value(admit_capabilities(&plain, &requests).unwrap()).unwrap();
            if context.is_some_and(|context| context != "none") {
                assert!(callback["sample"]["params"].get("includeContext").is_none());
                assert_eq!(callback["roots"], before["roots"]);
            } else {
                assert_eq!(callback, before);
            }
            assert_eq!(
                serde_json::to_value(admit_capabilities(&granted, &requests).unwrap()).unwrap(),
                before
            );
            assert_eq!(serde_json::to_value(&requests).unwrap(), before);
        }
    }

    #[test]
    fn update_identity_bytes_cannot_displace_acknowledged_input_custody() {
        let mut state = DriverState::default();
        let policy = ManagedTaskDriverPolicy::default();
        let (_, fingerprints) = state.unanswered(&inputs(), policy).unwrap();
        let exact = "one".len() + 32;
        assert!(
            state
                .answer_bytes(&["one".to_owned()], &fingerprints, exact)
                .is_ok()
        );
        state.reserve_ids(&ids(3, 4), exact).unwrap();
        assert!(matches!(
            state.answer_bytes(&["one".to_owned()], &fingerprints, exact),
            Err(ManagedTaskDriverError::StateByteLimit)
        ));
        assert!(state.answered.is_empty());
    }

    // A real session lifetime with no grant/network. The callback guard must
    // use the response's original credential signal, not acquire a new token.
    fn notification_call() -> ManagedTaskCall {
        use crate::http_auth::managed::{ManagedOAuthSession, OAuthSessionPolicy, SessionInner};
        use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration};
        use fastmcp_core::CanonicalHttpUrl;
        use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize}};
        use std::time::Instant;

        let url = |text| CanonicalHttpUrl::parse(text).unwrap();
        let resource = url("https://mcp.example/mcp");
        let config = OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url("https://issuer.example/token"), resource.clone(), "native-client", vec![],
        ).unwrap();
        let session = ManagedOAuthSession {
            inner: Arc::new(SessionInner {
                client: OAuthClient::new(config), resource,
                policy: OAuthSessionPolicy::default(),
                state: Arc::new(asupersync::sync::Mutex::new(None)),
                closed: McpRequestCancellation::new(), logout_handoff: AtomicBool::new(false),
                pending: AtomicUsize::new(0),
            }),
        };
        ManagedTaskCall {
            body: None,
            decoder: super::super::TaskDecoder::Get(TaskId::parse("task-one").unwrap()),
            session,
            cancellation: McpRequestCancellation::new(), request_id: RequestId::Number(2),
            progress: None, last_progress: None, deadline: Time::from_nanos(u64::MAX),
            expires_at: Instant::now() + Duration::from_secs(60), generation: 1,
            revocation: McpRequestCancellation::new(), limits: super::super::ManagedTasksLimits::default(),
            records: 0, finished: false,
        }
    }

    fn notification() -> ServerNotification {
        let wire = fastmcp_protocol::JsonRpcRequest::notification(
            "notifications/tools/list_changed", None,
        );
        ServerNotification::decode(&wire).unwrap()
    }

    #[test]
    fn driver_notification_lifetime_checks_precede_and_follow_every_callback() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        use std::time::Instant;
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let note = notification();
                for preflight in [false, true] {
                    for action in 0..6 {
                        let mut call = notification_call();
                        let stop = |call: &mut ManagedTaskCall| match action {
                            0 => { call.cancellation.cancel(); }
                            1 => call.session.close(),
                            2 => { call.revocation.cancel(); }
                            3 => call.expires_at = Instant::now(),
                            4 => call.deadline = Time::ZERO,
                            _ => {}
                        };
                        if preflight { stop(&mut call); }
                        let mut calls = 0;
                        let cancelled = call.cancellation.clone();
                        let revoked = call.revocation.clone();
                        let session = call.session.clone();
                        let result = DriverCallbackLifetime::new(&call, Time::from_nanos(u64::MAX)).notify(
                            &cx, &note,
                            &mut |_| {
                                calls += 1;
                                if !preflight {
                                    match action {
                                        0 => { cancelled.cancel(); }
                                        1 => session.close(),
                                        2 => { revoked.cancel(); }
                                        _ => {}
                                    }
                                }
                                // Refusal cannot mask cancellation/revocation.
                                false
                            },
                        ).await;
                        match action {
                            0 => assert!(matches!(result, Err(ManagedTaskDriverError::Task(
                                ManagedTasksError::Session(OAuthSessionError::Cancelled))))),
                            1 => assert!(matches!(result, Err(ManagedTaskDriverError::Task(
                                ManagedTasksError::Session(OAuthSessionError::Closed))))),
                            2 => assert!(matches!(result, Err(ManagedTaskDriverError::Task(
                                ManagedTasksError::Session(OAuthSessionError::LoginRequired))))),
                            3 if preflight => assert!(matches!(result, Err(ManagedTaskDriverError::Task(
                                ManagedTasksError::Session(OAuthSessionError::LoginRequired))))),
                            4 if preflight => assert!(matches!(result, Err(ManagedTaskDriverError::Task(
                                ManagedTasksError::Session(OAuthSessionError::TimedOut))))),
                            _ => assert!(matches!(result, Err(ManagedTaskDriverError::AbortedByHost))),
                        }
                        assert_eq!(calls, usize::from(!preflight || action == 5));
                        if action <= 2 {
                            let again = DriverCallbackLifetime::new(&call, Time::from_nanos(u64::MAX)).notify(
                                &cx, &note,
                                &mut |_| { panic!("a second buffered notification escaped refusal") },
                            ).await;
                            assert!(again.is_err());
                        }
                        assert!(cx.checkpoint().is_ok());
                    }
                }
                let call = notification_call();
                let mut calls = 0;
                DriverCallbackLifetime::new(&call, Time::from_nanos(u64::MAX)).notify(&cx, &note,
                    &mut |_| { calls += 1; true }).await.unwrap();
                assert_eq!(calls, 1);
                assert!(!call.cancellation.is_cancel_requested());
                assert!(!call.session.inner.closed.is_cancel_requested());
            });
    }

    // Count construction, polling and destruction independently: a rejected
    // result alone cannot show that a revoked callback did not start host work.
    struct TrackedHostFuture {
        polls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        drops: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        pending: bool,
    }

    impl Future for TrackedHostFuture {
        type Output = Result<(), ManagedTaskDriverError>;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.pending {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(Ok(()))
            }
        }
    }

    impl Drop for TrackedHostFuture {
        fn drop(&mut self) {
            self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn host_constructor_stops_before_polling_but_live_resolution_completes() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                for stop in 0..4 {
                    let call = notification_call();
                    let polls = Arc::new(AtomicUsize::new(0));
                    let drops = Arc::new(AtomicUsize::new(0));
                    let mut constructors = 0;
                    let result = DriverCallbackLifetime::new(&call, call.deadline).run(&cx, || {
                        constructors += 1;
                        match stop {
                            0 => { call.cancellation.cancel(); }
                            1 => call.session.close(),
                            2 => { call.revocation.cancel(); }
                            _ => {}
                        }
                        TrackedHostFuture {
                            polls: Arc::clone(&polls), drops: Arc::clone(&drops), pending: false,
                        }
                    }).await;
                    match stop {
                        0 => assert!(matches!(result, Err(ManagedTaskDriverError::Task(
                            ManagedTasksError::Session(OAuthSessionError::Cancelled))))),
                        1 => assert!(matches!(result, Err(ManagedTaskDriverError::Task(
                            ManagedTasksError::Session(OAuthSessionError::Closed))))),
                        2 => assert!(matches!(result, Err(ManagedTaskDriverError::Task(
                            ManagedTasksError::Session(OAuthSessionError::LoginRequired))))),
                        _ => assert!(result.is_ok()),
                    }
                    assert_eq!(constructors, 1);
                    assert_eq!(polls.load(Ordering::SeqCst), usize::from(stop == 3));
                    assert_eq!(drops.load(Ordering::SeqCst), 1);
                    if stop < 3 {
                        let refused = DriverCallbackLifetime::new(&call, call.deadline).run(&cx, || {
                            constructors += 1;
                            std::future::ready(Ok(()))
                        }).await;
                        assert!(refused.is_err());
                        assert_eq!(constructors, 1);
                    }
                    assert!(cx.checkpoint().is_ok());
                }
            });
    }

    #[test]
    fn pending_host_resolution_wakes_on_authority_loss_and_releases_owned_work() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        use std::task::{Context, Poll, Wake, Waker};

        struct Wakes(AtomicUsize);
        impl Wake for Wakes {
            fn wake(self: Arc<Self>) { self.wake_by_ref(); }
            fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                for stop in 0..4 {
                    let call = notification_call();
                    let polls = Arc::new(AtomicUsize::new(0));
                    let drops = Arc::new(AtomicUsize::new(0));
                    let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
                    let waker = Waker::from(Arc::clone(&wakes));
                    let mut task = Context::from_waker(&waker);
                    let lifetime = DriverCallbackLifetime::new(&call, call.deadline);
                    let mut resolution = Box::pin(lifetime.run(&cx, || {
                        TrackedHostFuture {
                            polls: Arc::clone(&polls), drops: Arc::clone(&drops), pending: true,
                        }
                    }));
                    assert!(resolution.as_mut().poll(&mut task).is_pending());
                    assert_eq!(polls.load(Ordering::SeqCst), 1);
                    assert_eq!(drops.load(Ordering::SeqCst), 0);
                    let before = wakes.0.load(Ordering::SeqCst);
                    match stop {
                        0 => { call.cancellation.cancel(); }
                        1 => call.session.close(),
                        2 => { call.revocation.cancel(); }
                        _ => {}
                    }
                    if stop < 3 {
                        assert!(wakes.0.load(Ordering::SeqCst) > before,
                            "a silent resolver must be woken without advancing time");
                        let result = resolution.as_mut().poll(&mut task);
                        match stop {
                            0 => assert!(matches!(result, Poll::Ready(Err(ManagedTaskDriverError::Task(
                                ManagedTasksError::Session(OAuthSessionError::Cancelled)))))),
                            1 => assert!(matches!(result, Poll::Ready(Err(ManagedTaskDriverError::Task(
                                ManagedTasksError::Session(OAuthSessionError::Closed)))))),
                            _ => assert!(matches!(result, Poll::Ready(Err(ManagedTaskDriverError::Task(
                                ManagedTasksError::Session(OAuthSessionError::LoginRequired)))))),
                        }
                    }
                    drop(resolution);
                    assert_eq!(polls.load(Ordering::SeqCst), 1,
                        "lost authority must not poll pending host work again");
                    assert_eq!(drops.load(Ordering::SeqCst), 1);
                    let before = wakes.0.load(Ordering::SeqCst);
                    call.cancellation.cancel();
                    call.revocation.cancel();
                    call.session.close();
                    assert_eq!(wakes.0.load(Ordering::SeqCst), before,
                        "completed/abandoned host work must release its stop registrations");
                    assert!(cx.checkpoint().is_ok());
                }
            });
    }

    #[test]
    fn ready_host_results_are_dropped_when_their_poll_revokes_authority() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        use std::task::Poll;

        struct Answer(Arc<AtomicUsize>);
        impl Drop for Answer {
            fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                for revoke in [false, true] {
                    let call = notification_call();
                    let drops = Arc::new(AtomicUsize::new(0));
                    let polls = std::cell::Cell::new(0);
                    let count = &polls;
                    let revocation = call.revocation.clone();
                    let answer_drops = Arc::clone(&drops);
                    let result = DriverCallbackLifetime::new(&call, call.deadline).run(&cx, move || {
                        std::future::poll_fn(move |_| {
                            count.set(count.get() + 1);
                            if revoke { revocation.cancel(); }
                            Poll::Ready(Ok(Answer(Arc::clone(&answer_drops))))
                        })
                    }).await;
                    assert_eq!(polls.get(), 1);
                    if revoke {
                        assert!(matches!(result, Err(ManagedTaskDriverError::Task(
                            ManagedTasksError::Session(OAuthSessionError::LoginRequired)))));
                        assert_eq!(drops.load(Ordering::SeqCst), 1);
                    } else {
                        assert!(result.is_ok());
                        assert_eq!(drops.load(Ordering::SeqCst), 0);
                        drop(result);
                        assert_eq!(drops.load(Ordering::SeqCst), 1);
                    }
                    assert!(cx.checkpoint().is_ok());
                    assert!(!call.session.inner.closed.is_cancel_requested());
                }
            });
    }

    #[test]
    fn callback_lifetime_preserves_send_for_send_host_futures() {
        fn assert_send<F: Future + Send>(_: F) {}

        let cx = Cx::for_testing();
        let call = notification_call();
        let lifetime = DriverCallbackLifetime::new(&call, call.deadline);
        // The future owns no shared reference to the response or parser.
        // This is a compile-time contract, not a runtime execution claim.
        assert_send(lifetime.run(&cx, || std::future::ready(Ok(()))));
    }

    #[test]
    fn precancelled_event_driver_cannot_allocate_ids_or_start_host_work() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
        use std::task::{Context, Poll, Waker};

        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let client = ManagedTasksClient::new(notification_call().session,
                    FinalRequestMeta::new(ClientCapabilities::default()),
                    super::super::ManagedTasksLimits::default()).unwrap();
                let cancellation = McpRequestCancellation::new();
                cancellation.cancel();
                let mut waiting = Box::pin(client.drive_task_with_events(
                    &cx, &cancellation, TaskId::parse("task-one").unwrap(),
                    ManagedTaskDriverPolicy::default(),
                    || panic!("cancelled driver asked for identities"),
                    |_| {
                        panic!("cancelled driver resolved input");
                        #[allow(unreachable_code)]
                        std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller))
                    },
                    |_| panic!("cancelled driver observed a snapshot"),
                    |_| panic!("cancelled driver observed a notification"),
                ));
                assert!(matches!(waiting.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Err(ManagedTaskDriverError::Task(
                        ManagedTasksError::Session(OAuthSessionError::Cancelled))))));
                drop(waiting);
                assert!(cx.checkpoint().is_ok());
                assert!(!client.session.inner.closed.is_cancel_requested());
            });
    }
}
