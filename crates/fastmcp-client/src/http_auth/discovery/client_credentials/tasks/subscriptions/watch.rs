//! Notification-driven observation of machine-authenticated Tasks.
//!
//! Acknowledged coverage precedes the first get. Notifications trigger fresh
//! authenticated snapshots; their embedded Task is never published as current
//! state. The opening credential owns every discovery/get for this watch, even
//! if another caller renews the machine client's token. Expiry ends observation.
//! There is no polling, reconnect, task creation or remote cancellation here.

/// Host-authorized input resolution driven by Task notifications.
pub mod drive;

use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::tasks_extension::{Task, TaskId, task_subscription_ids};
use fastmcp_protocol::{CoreRequest, RequestId, SubscriptionFilter};
use serde_json::json;

use super::{ClientCredentialsSubscriptionLimits, ClientCredentialsTaskSubscription};
use super::super::{
    BoundedBody, ClientCredentialsTaskCall, ClientCredentialsTasksClient,
    ClientCredentialsTasksError, ManagedTaskEvent, ManagedTaskRequest, ManagedTasksError,
    Prepared, admit_composition, encode, prepare, require_success,
};
use super::super::super::{
    ClientCredentialsError, ClientCredentialsSnapshot, OAuthDiscoveryError, active,
    authorize, check_context, check_token, discovery_deadline,
};
use crate::http_executor::{
    ModernHttpExecutor, ModernHttpExecutorError, ModernHttpRequest, ModernHttpResponseKind,
    ModernHttpSubscriptionListenEvent,
};

pub use crate::http_auth::managed::tasks::watch::{ManagedTaskSnapshot, ManagedTaskSnapshotCause};

const MAX_WATCH_TASKS: usize = 128;
const MAX_SELECTION_BYTES: usize = 64 * 1024;

/// Whole-watch bounds. Subscription/native/token deadlines may end the watch
/// earlier; caller pauses count against the same original absolute deadline.
#[derive(Clone, Copy, Debug)]
pub struct ClientCredentialsTaskWatchPolicy {
    timeout: Duration,
    maximum_snapshots: usize,
    maximum_records: usize,
}
impl Default for ClientCredentialsTaskWatchPolicy {
    fn default() -> Self {
        Self { timeout: Duration::from_mins(15), maximum_snapshots: 1024, maximum_records: 2048 }
    }
}
impl ClientCredentialsTaskWatchPolicy {
    pub fn new(timeout: Duration, maximum_snapshots: usize, maximum_records: usize)
        -> Result<Self, ClientCredentialsTaskWatchError>
    {
        if timeout.is_zero() || timeout > Duration::from_secs(3600)
            || !(1..=4096).contains(&maximum_snapshots)
            || !(2..=4096).contains(&maximum_records)
        { return Err(ClientCredentialsTaskWatchError::InvalidPolicy); }
        Ok(Self { timeout, maximum_snapshots, maximum_records })
    }
}

/// Diagnostics retain no selection, credential, input answers or peer text.
#[derive(Debug)]
pub enum ClientCredentialsTaskWatchError {
    InvalidPolicy,
    InvalidSelection,
    InvalidIdPrefix,
    IdentityExhausted,
    IncompleteAcknowledgement,
    SnapshotLimit,
    UnexpectedEvent,
    Interrupted,
    Closed,
    Task(ClientCredentialsTasksError),
}
impl fmt::Display for ClientCredentialsTaskWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => f.write_str("invalid machine Task watch policy"),
            Self::InvalidSelection => f.write_str("invalid machine Task watch selection"),
            Self::InvalidIdPrefix => f.write_str("invalid machine Task watch identity prefix"),
            Self::IdentityExhausted => f.write_str("machine Task watch identities exhausted"),
            Self::IncompleteAcknowledgement => f.write_str("machine Task watch did not acknowledge the complete selection"),
            Self::SnapshotLimit => f.write_str("machine Task watch snapshot budget exhausted"),
            Self::UnexpectedEvent => f.write_str("unexpected machine Task watch event"),
            Self::Interrupted => f.write_str("machine Task subscription ended before all tasks were terminal"),
            Self::Closed => f.write_str("machine Task watch is closed"),
            Self::Task(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ClientCredentialsTaskWatchError {}
impl From<ClientCredentialsTasksError> for ClientCredentialsTaskWatchError {
    fn from(error: ClientCredentialsTasksError) -> Self { Self::Task(error) }
}
impl From<ClientCredentialsError> for ClientCredentialsTaskWatchError {
    fn from(error: ClientCredentialsError) -> Self { Self::Task(error.into()) }
}
impl From<ManagedTasksError> for ClientCredentialsTaskWatchError {
    fn from(error: ManagedTasksError) -> Self { Self::Task(error.into()) }
}

impl ClientCredentialsTasksClient {
    /// Watches 1..=128 distinct existing Tasks without periodic polling.
    /// Opening requires acknowledgement of the entire selection. Initial
    /// snapshots follow selection order; later snapshots follow observed Task
    /// notifications. Input-required is delivered for explicit host handling.
    ///
    /// Select a different prefix for concurrent watches on the endpoint. It is
    /// bounded to 128 ASCII letters/digits/underscore/dash/dot bytes. This watch
    /// never reuses an ID, and IDs are not idempotency or remote replay keys.
    pub async fn watch_tasks(
        &self, cx: &Cx, task_ids: Vec<TaskId>, id_prefix: String,
        policy: ClientCredentialsTaskWatchPolicy,
    ) -> Result<ClientCredentialsTaskWatch, ClientCredentialsTaskWatchError> {
        self.watch_tasks_with_cancellation(cx, &McpRequestCancellation::new(), task_ids, id_prefix, policy).await
    }

    /// Cancellation spans acquisition, ACK, all gets and idle waits. Dropping
    /// or closing a watch affects only local observation, not the remote Tasks
    /// or sibling calls. Failed POSTs and interrupted streams are never retried.
    pub async fn watch_tasks_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, task_ids: Vec<TaskId>,
        id_prefix: String, policy: ClientCredentialsTaskWatchPolicy,
    ) -> Result<ClientCredentialsTaskWatch, ClientCredentialsTaskWatchError> {
        let state = WatchState::new(task_ids, policy.maximum_snapshots)?;
        let mut ids = WatchIds::new(id_prefix)?;
        let (discovery_id, request_id) = ids.next_pair()?;
        let filter = state.filter()?;
        let limits = ClientCredentialsSubscriptionLimits::new(
            self.limits.request_bytes.min(MAX_SELECTION_BYTES),
            self.limits.frame_bytes.min(MAX_SELECTION_BYTES), policy.maximum_records, policy.timeout,
        )?;
        let deadline = discovery_deadline(cx, policy.timeout).map_err(ClientCredentialsError::from)?;
        let owner = &self.client.inner.closed;
        active(cx, deadline, owner, cancellation, None, async {
            Ok(async {
                let mut subscription = self.subscribe_with_cancellation(
                    cx, cancellation, discovery_id, request_id, filter, limits,
                ).await?;
                let Some(ModernHttpSubscriptionListenEvent::Acknowledged { accepted_filter }) =
                    subscription.next_event(cx).await?
                else { return Err(ClientCredentialsTaskWatchError::UnexpectedEvent); };
                state.admit_acknowledgement(&accepted_filter)?;
                // Copy the SAME private snapshot, without reacquisition or a
                // refresh window between ACK and the first protected get.
                let binding = copy_binding(&subscription.snapshot);
                let deadline = deadline.min(subscription.deadline);
                check_watch(cx, deadline, owner, cancellation, &binding)?;
                Ok(ClientCredentialsTaskWatch {
                    client: self.clone(), cancellation: cancellation.clone(), binding,
                    subscription: Some(subscription), state, ids, deadline, finished: false,
                })
            }.await)
        }).await?
    }
}

/// Caller-owned non-Clone stream. Successful EOF means a terminal snapshot was
/// delivered for every selected Task, not that the subscription disconnected.
/// Completed, Failed and Cancelled remain distinct outcomes inside each Task.
///
/// Only one read runs at a time. Notifications arriving during a get or caller
/// pause are consumed on later reads; this is not a server snapshot-isolation
/// or durable event-history guarantee. The original credential bounds all of
/// these pauses. A polled read abandoned halfway closes observation permanently.
pub struct ClientCredentialsTaskWatch {
    client: ClientCredentialsTasksClient,
    cancellation: McpRequestCancellation,
    binding: ClientCredentialsSnapshot,
    subscription: Option<ClientCredentialsTaskSubscription>,
    state: WatchState,
    ids: WatchIds,
    deadline: Time,
    finished: bool,
}
impl ClientCredentialsTaskWatch {
    pub fn remaining_tasks(&self) -> usize { self.state.terminal.iter().filter(|done| !**done).count() }
    pub fn credential_generation(&self) -> u64 { self.binding.generation() }

    /// Releases the listen socket without cancelling a shared domain or Task.
    pub fn close(&mut self) { self.subscription = None; }

    /// Returns an authenticated snapshot, not the notification's possibly old
    /// payload. Late notifications for already-terminal Tasks do not cause
    /// another get or terminal delivery. Any error makes further reads fail
    /// closed; no abandoned partial parser can be resumed.
    pub async fn next_snapshot(&mut self, cx: &Cx)
        -> Result<Option<ManagedTaskSnapshot>, ClientCredentialsTaskWatchError>
    {
        if self.finished { return Ok(None); }
        let mut subscription = self.subscription.take().ok_or(ClientCredentialsTaskWatchError::Closed)?;
        let owner = &self.client.client.inner.closed;
        let snapshot = active(cx, self.deadline, owner, &self.cancellation, Some(&self.binding), async {
            Ok(async {
                let (task_id, cause) = match self.state.initial.pop_front() {
                    Some(index) => (self.state.task_ids[index].clone(), ManagedTaskSnapshotCause::Initial),
                    None => loop {
                        match subscription.next_event(cx).await? {
                            Some(ModernHttpSubscriptionListenEvent::TaskNotification(notification)) => {
                                let id = &notification.params.task.base().task_id;
                                if self.state.needs_snapshot(id)? {
                                    break (id.clone(), ManagedTaskSnapshotCause::ChangeNotification);
                                }
                            }
                            Some(ModernHttpSubscriptionListenEvent::Notification(_)) => {},
                            Some(ModernHttpSubscriptionListenEvent::Terminal { .. }) | None => {
                                return Err(ClientCredentialsTaskWatchError::Interrupted);
                            }
                            Some(ModernHttpSubscriptionListenEvent::Acknowledged { .. }) => {
                                return Err(ClientCredentialsTaskWatchError::UnexpectedEvent);
                            }
                        }
                    },
                };
                self.state.reserve_snapshot()?;
                let ids = self.ids.next_pair()?;
                let mut call = request_pinned(&self.client, cx, &self.cancellation, &self.binding,
                    self.deadline, ids, ManagedTaskRequest::Get(task_id)).await?;
                let Some(ManagedTaskEvent::Snapshot(result)) = call.next_event(cx).await? else {
                    return Err(ClientCredentialsTaskWatchError::UnexpectedEvent);
                };
                Ok(ManagedTaskSnapshot { task: Box::new(result.task), cause })
            }.await)
        }).await??;
        check_watch(cx, self.deadline, owner, &self.cancellation, &self.binding)?;
        self.finished = self.state.record_snapshot(&snapshot.task)?;
        if !self.finished { self.subscription = Some(subscription); }
        Ok(Some(snapshot))
    }
}

// This private composition reuses the ordinary Tasks preparation, discovery
// admission and incremental result decoder. Unlike standalone requests, a watch
// must NOT acquire a replacement credential before a get or explicit update.
// It accepts only those two commands, never creation or remote cancellation.
fn prepare_pinned(
    client: &ClientCredentialsTasksClient, ids: &(RequestId, RequestId), request: ManagedTaskRequest,
) -> Result<(Prepared, CoreRequest, ModernHttpRequest), ClientCredentialsTaskWatchError> {
    if !matches!(&request, ManagedTaskRequest::Get(_) | ManagedTaskRequest::Update { .. }) {
        return Err(ManagedTasksError::InvalidRequest.into());
    }
    ids.0.validate().map_err(|_| ManagedTasksError::InvalidRequest)?;
    ids.1.validate().map_err(|_| ManagedTasksError::InvalidRequest)?;
    if ids.0.correlates_with(&ids.1) { return Err(ManagedTasksError::InvalidRequest.into()); }
    let prepared = prepare(client.client.resource().as_str(), &client.metadata, &ids.1, request, client.limits)?;
    let discovery = CoreRequest::decode(fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026,
        "server/discover", Some(&json!({"_meta":client.metadata})))
        .map_err(|_| ManagedTasksError::InvalidRequest)?;
    let params = discovery.encode_params().map_err(|_| ManagedTasksError::InvalidRequest)?
        .ok_or(ManagedTasksError::InvalidRequest)?;
    let wire = encode(client.client.resource().as_str(), "server/discover", &ids.0,
        params, None, client.limits.request_bytes)?;
    Ok((prepared, discovery, wire))
}

#[allow(clippy::too_many_arguments)]
async fn request_pinned(
    client: &ClientCredentialsTasksClient, cx: &Cx, cancellation: &McpRequestCancellation,
    binding: &ClientCredentialsSnapshot, deadline: Time, ids: (RequestId, RequestId),
    request: ManagedTaskRequest,
) -> Result<ClientCredentialsTaskCall, ClientCredentialsTaskWatchError> {
    let (prepared, discovery, discovery_wire) = prepare_pinned(client, &ids, request)?;
    let deadline = deadline.min(discovery_deadline(cx, client.limits.timeout.min(client.client.inner.timeout))
        .map_err(ClientCredentialsError::from)?);
    let owner = &client.client.inner.closed;
    active(cx, deadline, owner, cancellation, Some(binding), async {
        Ok(async {
            let executor = ModernHttpExecutor::new();
            let wire = authorize(binding, discovery_wire)?;
            let response = executor.execute_with_cancellation(cx, cancellation, &wire).await.map_err(transport_error)?;
            check_watch(cx, deadline, owner, cancellation, binding)?;
            require_success(&response)?;
            if response.metadata().kind() != ModernHttpResponseKind::Json {
                return Err(ManagedTasksError::Negotiation.into());
            }
            let bytes = response.read_to_end_with_cancellation(cx, cancellation, client.limits.frame_bytes).await
                .map_err(|_| ClientCredentialsError::UnexpectedResponse)?;
            admit_composition(&discovery, &ids.0, &bytes, &prepared.decoder, client.limits.frame_bytes)?;
            check_watch(cx, deadline, owner, cancellation, binding)?;
            let wire = authorize(binding, prepared.wire)?;
            let response = executor.execute_with_cancellation(cx, cancellation, &wire).await.map_err(transport_error)?;
            check_watch(cx, deadline, owner, cancellation, binding)?;
            require_success(&response)?;
            Ok(ClientCredentialsTaskCall::new(response, prepared.decoder, prepared.progress,
                copy_binding(binding), owner.clone(), cancellation.clone(), ids.1, deadline, client.limits)?)
        }.await)
    }).await?
}
fn transport_error(error: ModernHttpExecutorError) -> ClientCredentialsError {
    match error {
        ModernHttpExecutorError::Redirect { status } => ClientCredentialsError::Redirect { status },
        _ => ClientCredentialsError::Transport,
    }
}
fn copy_binding(binding: &ClientCredentialsSnapshot) -> ClientCredentialsSnapshot {
    ClientCredentialsSnapshot {
        bearer: binding.bearer.clone(), scopes: binding.scopes.clone(),
        expires_at: binding.expires_at, generation: binding.generation,
    }
}
fn check_watch(
    cx: &Cx, deadline: Time, owner: &McpRequestCancellation,
    cancellation: &McpRequestCancellation, binding: &ClientCredentialsSnapshot,
) -> Result<(), ClientCredentialsTaskWatchError> {
    if owner.is_cancel_requested() { return Err(ClientCredentialsError::Closed.into()); }
    if cancellation.is_cancel_requested() { return Err(ClientCredentialsError::from(OAuthDiscoveryError::Cancelled).into()); }
    let deadline = cx.budget().deadline.map_or(deadline, |caller| caller.min(deadline));
    check_context(cx, deadline).map_err(ClientCredentialsError::from)?;
    check_token(&binding.bearer, binding.expires_at)?;
    Ok(())
}

struct WatchIds { prefix: String, next: u64 }
impl WatchIds {
    fn new(prefix: String) -> Result<Self, ClientCredentialsTaskWatchError> {
        if prefix.is_empty() || prefix.len() > 128
            || !prefix.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        { return Err(ClientCredentialsTaskWatchError::InvalidIdPrefix); }
        Ok(Self { prefix, next: 0 })
    }
    fn next_pair(&mut self) -> Result<(RequestId, RequestId), ClientCredentialsTaskWatchError> {
        let following = self.next.checked_add(2).ok_or(ClientCredentialsTaskWatchError::IdentityExhausted)?;
        let pair = (RequestId::String(format!("{}:{}", self.prefix, self.next)),
            RequestId::String(format!("{}:{}", self.prefix, self.next + 1)));
        self.next = following;
        Ok(pair)
    }
}
struct WatchState {
    task_ids: Vec<TaskId>, initial: VecDeque<usize>, terminal: Vec<bool>,
    snapshots: usize, maximum_snapshots: usize,
}
impl WatchState {
    fn new(task_ids: Vec<TaskId>, maximum_snapshots: usize) -> Result<Self, ClientCredentialsTaskWatchError> {
        if task_ids.is_empty() || task_ids.len() > MAX_WATCH_TASKS || task_ids.len() > maximum_snapshots {
            return Err(ClientCredentialsTaskWatchError::InvalidSelection);
        }
        for (index, id) in task_ids.iter().enumerate() {
            if task_ids[..index].contains(id) { return Err(ClientCredentialsTaskWatchError::InvalidSelection); }
        }
        let mut writer = BoundedBody { bytes: Vec::new(), maximum: MAX_SELECTION_BYTES };
        serde_json::to_writer(&mut writer, &task_ids).map_err(|_| ClientCredentialsTaskWatchError::InvalidSelection)?;
        Ok(Self { initial: (0..task_ids.len()).collect(), terminal: vec![false; task_ids.len()],
            task_ids, snapshots: 0, maximum_snapshots })
    }
    fn filter(&self) -> Result<SubscriptionFilter, ClientCredentialsTaskWatchError> {
        serde_json::from_value(json!({"taskIds":self.task_ids}))
            .map_err(|_| ClientCredentialsTaskWatchError::InvalidSelection)
    }
    fn admit_acknowledgement(&self, filter: &SubscriptionFilter) -> Result<(), ClientCredentialsTaskWatchError> {
        let accepted = task_subscription_ids(filter).map_err(|_| ClientCredentialsTaskWatchError::IncompleteAcknowledgement)?
            .ok_or(ClientCredentialsTaskWatchError::IncompleteAcknowledgement)?;
        if accepted.len() != self.task_ids.len() || self.task_ids.iter().any(|id| !accepted.contains(id)) {
            return Err(ClientCredentialsTaskWatchError::IncompleteAcknowledgement);
        }
        Ok(())
    }
    fn needs_snapshot(&self, task_id: &TaskId) -> Result<bool, ClientCredentialsTaskWatchError> {
        let index = self.task_ids.iter().position(|id| id == task_id)
            .ok_or(ClientCredentialsTaskWatchError::UnexpectedEvent)?;
        Ok(!self.terminal[index])
    }
    fn reserve_snapshot(&mut self) -> Result<(), ClientCredentialsTaskWatchError> {
        if self.snapshots >= self.maximum_snapshots { return Err(ClientCredentialsTaskWatchError::SnapshotLimit); }
        self.snapshots += 1;
        Ok(())
    }
    fn record_snapshot(&mut self, task: &Task) -> Result<bool, ClientCredentialsTaskWatchError> {
        let index = self.task_ids.iter().position(|id| id == &task.base().task_id)
            .ok_or(ClientCredentialsTaskWatchError::UnexpectedEvent)?;
        if self.terminal[index] { return Err(ClientCredentialsTaskWatchError::UnexpectedEvent); }
        self.terminal[index] = matches!(task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_));
        Ok(self.terminal.iter().all(|done| *done))
    }
}

#[cfg(test)]
mod tests;
