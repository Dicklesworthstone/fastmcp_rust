//! Incremental subscription ownership on the existing Memory ingress driver.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, Weak};

use fastmcp_protocol::{
    CompleteResult, CorrelationKey, FinalSubscriptionsListenResult, ServerNotification,
    SubscriptionFilter,
};

use super::*;
use crate::execution::ExecutionTerminalReason;
use crate::{
    ResourceSubscriptionRelations, SubscriptionListenRequest, SubscriptionTimeoutPolicy,
    validate_subscription_acknowledgement_filter, validate_subscription_notification_filter,
};

const SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";
const MAX_SUBSCRIPTIONS: usize = 64;
const MAX_QUEUED_EVENTS: usize = 64;
const MAX_QUEUED_EVENT_BYTES: usize = 256 * 1024;

/// One independently owned, bounded Memory subscription.
///
/// The handle retains partial ingress when its event future is dropped. Dropping
/// the handle itself cancels only this listen request and queues its cancellation
/// control for the next drive. No background task or second reader is created.
#[derive(Debug)]
pub struct MemorySubscriptionExecution {
    owner: Arc<()>,
    request_id: RequestId,
    state: Arc<Mutex<SubscriptionState>>,
}

impl MemorySubscriptionExecution {
    /// The exact listen request ID published to the peer.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// The exact accepted filter, once its acknowledgement has been admitted.
    /// Inactive `false` and empty categories remain visible in this snapshot.
    #[must_use]
    pub fn accepted_filter(&self) -> Option<SubscriptionFilter> {
        lock(&self.state).accepted.clone()
    }

    /// The successful complete result after its terminal event has been read.
    ///
    /// A valid peer cancellation also yields `Terminal`, but leaves this `None`:
    /// cancellation is never represented as a fabricated successful completion.
    /// Local cancellation, expiry, and protocol failure return an error instead.
    #[must_use]
    pub fn terminal_result(&self) -> Option<CompleteResult<FinalSubscriptionsListenResult>> {
        lock(&self.state).terminal_result.clone()
    }
}

/// One admitted event owned by an exact Memory listen request.
#[derive(Debug)]
pub enum MemorySubscriptionEvent {
    /// The peer's accepted subset and the requested categories it did not accept.
    Acknowledged {
        /// Exact acknowledged filter, without broadening local authority.
        accepted: SubscriptionFilter,
        /// Requested active categories or identities omitted by the peer.
        unsupported: SubscriptionFilter,
    },
    /// A catalog or resource event admitted by this listener's accepted filter.
    Notification(Box<ServerNotification>),
    /// An exact-source Tasks snapshot for an explicitly accepted Task ID.
    #[cfg(feature = "tasks")]
    Task(Box<crate::FinalTaskStatusNotification>),
    /// The peer completed or cancelled this listener. This is yielded once;
    /// inspect [`MemorySubscriptionExecution::terminal_result`] to distinguish
    /// successful completion from cancellation-only termination.
    Terminal,
}

#[derive(Debug)]
struct SubscriptionState {
    inner: RequestExecution<ExternalMemoryTransport>,
    request: CoreRequest,
    requested: SubscriptionFilter,
    accepted: Option<SubscriptionFilter>,
    resource_relations: ResourceSubscriptionRelations,
    events: VecDeque<(usize, MemorySubscriptionEvent)>,
    event_bytes: usize,
    terminal_result: Option<CompleteResult<FinalSubscriptionsListenResult>>,
    finished: bool,
}

fn lock(state: &Mutex<SubscriptionState>) -> MutexGuard<'_, SubscriptionState> {
    state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

enum SubscriptionPoll {
    Pending,
    Event(MemorySubscriptionEvent),
    Finished,
}

impl SubscriptionState {
    fn queue(&mut self, event: MemorySubscriptionEvent, source_bytes: usize) -> McpResult<()> {
        let bytes = self.event_bytes.checked_add(source_bytes).ok_or_else(|| {
            McpError::invalid_request("Memory subscription event byte bound exceeded")
        })?;
        if self.events.len() >= MAX_QUEUED_EVENTS || bytes > MAX_QUEUED_EVENT_BYTES {
            return Err(McpError::invalid_request(
                "Memory subscription event queue is full",
            ));
        }
        self.event_bytes = bytes;
        self.events.push_back((source_bytes, event));
        Ok(())
    }

    fn take_event(&mut self, executor: &MemoryExecutor) -> McpResult<SubscriptionPoll> {
        if self.finished {
            return Ok(SubscriptionPoll::Finished);
        }
        let peer_cancelled = self.inner.terminal_reason()
            == Some(ExecutionTerminalReason::PeerSubscriptionTeardown);
        if !self.inner.is_pending_subscription()
            && self.inner.terminal_reason().is_none()
        {
            self.events.clear();
            self.event_bytes = 0;
            self.finished = true;
            return Err(executor.try_take_response(&mut self.inner).err().unwrap_or_else(|| {
                McpError::invalid_request("Memory subscription terminal receipt is unavailable")
            }));
        }
        if let Some(error) = self.inner.terminal_error()
            && !peer_cancelled
        {
            self.events.clear();
            self.event_bytes = 0;
            self.finished = true;
            let _ = executor.try_take_response(&mut self.inner);
            return Err(error);
        }
        if let Some((bytes, event)) = self.events.pop_front() {
            self.event_bytes -= bytes;
            return Ok(SubscriptionPoll::Event(event));
        }
        if peer_cancelled {
            // Consume the selected executor failure exactly once, retaining the
            // distinction between peer teardown and every local failure cause.
            let _ = executor.try_take_response(&mut self.inner);
            self.finished = true;
            return Ok(SubscriptionPoll::Event(MemorySubscriptionEvent::Terminal));
        }
        let response = match executor.try_take_response_with_raw_result(&mut self.inner) {
            Ok(response) => response,
            Err(error) => {
                self.finished = true;
                return Err(error);
            }
        };
        let Some((response, source)) = response else {
            return Ok(SubscriptionPoll::Pending);
        };
        self.finished = true;
        let (result, _) = decode_response(&self.request, response, source.as_deref(), false)?;
        let CoreResult::Final(FinalCoreResult::SubscriptionsListen {
            result,
            subscription_id,
            ..
        }) = result
        else {
            return Err(McpError::invalid_request(
                "Memory subscription returned another method's result",
            ));
        };
        if !subscription_id.correlates_with(self.inner.request_id()) {
            return Err(McpError::invalid_request(
                "Memory subscription terminal ID does not match its listener",
            ));
        }
        if self.accepted.is_none() {
            return Err(McpError::invalid_request(
                "Memory subscription completed before acknowledgement",
            ));
        }
        self.terminal_result = Some(result);
        Ok(SubscriptionPoll::Event(MemorySubscriptionEvent::Terminal))
    }
}

/// Weak registrations let handle Drop remain the sole lifetime owner. The map
/// never allocates request IDs, retains dropped owners, or drives any I/O.
#[derive(Debug, Default)]
pub(super) struct MemorySubscriptionRegistry {
    owners: HashMap<CorrelationKey, Weak<Mutex<SubscriptionState>>>,
    catalog_generations: [u64; 3],
}

impl MemorySubscriptionRegistry {
    /// Observes catalog changes without consuming any listener's event queue.
    pub(super) fn catalog_generation(&self, method: &str) -> u64 {
        match method {
            "tools/list" => self.catalog_generations[0],
            "resources/list" | "resources/templates/list" => self.catalog_generations[1],
            "prompts/list" => self.catalog_generations[2],
            _ => 0,
        }
    }

    /// Called only on the ordinary ingress path after subscription routing has
    /// declined the frame. A valid unsolicited catalog event invalidates an
    /// ongoing traversal while remaining available in the executor's queue.
    pub(super) fn observe_unowned_catalog_frame(&mut self, frame: &ReceivedTransportFrame) {
        let JsonRpcMessage::Request(request) = frame.message() else {
            return;
        };
        if request.id.is_some()
            || !matches!(
                request.method.as_str(),
                "notifications/tools/list_changed"
                    | "notifications/resources/list_changed"
                    | "notifications/prompts/list_changed"
            )
            || request
                .params
                .as_ref()
                .and_then(|params| params.get("_meta"))
                .and_then(|meta| meta.get(SUBSCRIPTION_ID))
                .is_some()
        {
            return;
        }
        if let Ok(
            ServerNotification::ToolsListChanged(_)
            | ServerNotification::ResourcesListChanged(_)
            | ServerNotification::PromptsListChanged(_),
        ) = ServerNotification::decode(request)
        {
            self.record_catalog_change(&request.method);
        }
    }

    fn record_catalog_change(&mut self, notification_method: &str) {
        let generation = match notification_method {
            "notifications/tools/list_changed" => &mut self.catalog_generations[0],
            "notifications/resources/list_changed" => &mut self.catalog_generations[1],
            "notifications/prompts/list_changed" => &mut self.catalog_generations[2],
            _ => return,
        };
        // A bounded traversal cannot receive 2^64 events. Wrapping preserves
        // the next change at MAX instead of permanently saturating the signal.
        *generation = generation.wrapping_add(1);
    }

    fn ensure_capacity(&mut self) -> McpResult<()> {
        self.owners.retain(|_, owner| {
            owner.upgrade().is_some_and(|owner| {
                let state = lock(&owner);
                !state.finished && state.inner.is_pending_subscription()
            })
        });
        if self.owners.len() >= MAX_SUBSCRIPTIONS {
            return Err(McpError::invalid_params(
                "Memory client subscription owner bound exceeded",
            ));
        }
        Ok(())
    }

    /// Routes only an exact owner named by this already-admitted wire frame.
    /// Unknown/retired subscription traffic is discarded at arrival and cannot
    /// acquire ownership if the request allocator reaches that ID in the future.
    pub(super) fn route(
        &mut self,
        executor: &MemoryExecutor,
        cx: &Cx,
        frame: &ReceivedTransportFrame,
    ) -> McpResult<bool> {
        let JsonRpcMessage::Request(request) = frame.message() else {
            return Ok(false);
        };
        if request.id.is_some() {
            return Ok(false);
        }
        let method = request.method.as_str();
        if !matches!(
            method,
            "notifications/subscriptions/acknowledged"
                | "notifications/tools/list_changed"
                | "notifications/resources/list_changed"
                | "notifications/prompts/list_changed"
                | "notifications/resources/updated"
                | "notifications/tasks"
                | "notifications/cancelled"
        ) {
            // Ordinary progress/log traffic never refreshes subscription idle.
            return Ok(false);
        }
        let metadata_id = request
            .params
            .as_ref()
            .and_then(|params| params.get("_meta"))
            .and_then(|meta| meta.get(SUBSCRIPTION_ID));
        let request_id = metadata_id
            .and_then(|value| serde_json::from_value::<RequestId>(value.clone()).ok());
        let owner = request_id
            .as_ref()
            .and_then(|id| id.correlation_key().ok())
            .and_then(|key| self.owners.get(&key))
            .and_then(Weak::upgrade);
        let Some(owner) = owner else {
            if method == "notifications/cancelled" && metadata_id.is_none() {
                // A requestId cannot stand in for the required subscription
                // metadata. Refuse this exact known owner without touching any
                // sibling named by malformed or contradictory peer metadata.
                let owner = request
                    .params
                    .as_ref()
                    .and_then(|params| params.get("requestId"))
                    .and_then(|value| serde_json::from_value::<RequestId>(value.clone()).ok())
                    .and_then(|id| id.correlation_key().ok())
                    .and_then(|key| self.owners.get(&key))
                    .and_then(Weak::upgrade);
                if let Some(owner) = owner {
                    let mut state = lock(&owner);
                    if !state.finished && state.inner.is_pending_subscription() {
                        executor.fail_subscription(
                            cx,
                            &mut state.inner,
                            McpError::invalid_request(
                                "Memory peer subscription cancellation omitted its subscription ID",
                            ),
                        )?;
                    }
                    return Ok(true);
                }
            }
            return Ok(metadata_id.is_some()
                || method == "notifications/subscriptions/acknowledged"
                || method == "notifications/tasks");
        };
        let mut state = lock(&owner);
        if state.finished || !state.inner.is_pending_subscription() {
            return Ok(true);
        }
        let result = admit_notification(&mut state, executor, cx, frame);
        if let Err(error) = result {
            executor.fail_subscription(cx, &mut state.inner, error)?;
        } else {
            self.record_catalog_change(method);
        }
        Ok(true)
    }
}

fn admit_notification(
    state: &mut SubscriptionState,
    executor: &MemoryExecutor,
    cx: &Cx,
    frame: &ReceivedTransportFrame,
) -> McpResult<()> {
    let JsonRpcMessage::Request(request) = frame.message() else {
        unreachable!("subscription router only admits notifications");
    };
    if request.method == "notifications/tasks" {
        #[cfg(feature = "tasks")]
        {
            let accepted = state.accepted.as_ref().ok_or_else(|| {
                McpError::invalid_request("Memory Task event preceded subscription acknowledgement")
            })?;
            let notification: crate::FinalTaskStatusNotification =
                serde_json::from_slice(frame.source()).map_err(|_| {
                    McpError::invalid_request("Memory subscription received an invalid Task event")
                })?;
            let accepted_ids = fastmcp_protocol::task_subscription_ids(accepted)
                .map_err(|_| McpError::invalid_request("Invalid accepted Memory Tasks filter"))?;
            if accepted_ids.as_ref().is_none_or(|ids| {
                !ids.iter().any(|id| id == &notification.params.task.base().task_id)
            }) {
                return Err(McpError::invalid_request(
                    "Memory subscription received an unaccepted Task ID",
                ));
            }
            state.queue(
                MemorySubscriptionEvent::Task(Box::new(notification)),
                frame.source().len(),
            )?;
            executor.record_subscription_activity(&state.inner)?;
            return Ok(());
        }
        #[cfg(not(feature = "tasks"))]
        return Err(McpError::invalid_request(
            "Memory Tasks subscription events require the Tasks feature",
        ));
    }
    let notification = ServerNotification::decode(request).map_err(|_| {
        McpError::invalid_request("Memory subscription received an invalid server notification")
    })?;
    match notification {
        ServerNotification::SubscriptionsAcknowledged(acknowledgement) => {
            if state.accepted.is_some() {
                return Err(McpError::invalid_request(
                    "Memory subscription received a duplicate acknowledgement",
                ));
            }
            // Core false/empty filters are semantically inactive. Preserve the
            // exact peer filter for callers while sharing the existing subset
            // validator for every category that can actually admit an event.
            validate_subscription_acknowledgement_filter(
                &active_filter(&state.requested),
                &active_filter(&acknowledgement.notifications),
            )?;
            let accepted = acknowledgement.notifications;
            let unsupported = unsupported_filter(&state.requested, &accepted)?;
            state.queue(
                MemorySubscriptionEvent::Acknowledged {
                    accepted: accepted.clone(),
                    unsupported,
                },
                frame.source().len(),
            )?;
            state.accepted = Some(accepted);
            executor.record_subscription_activity(&state.inner)?;
        }
        ServerNotification::Cancelled(cancellation) => {
            if state.accepted.is_none() {
                return Err(McpError::invalid_request(
                    "Memory subscription cancellation preceded acknowledgement",
                ));
            }
            if !cancellation.request_id.correlates_with(state.inner.request_id()) {
                return Err(McpError::invalid_request(
                    "Memory subscription cancellation request ID does not match its owner",
                ));
            }
            executor.accept_subscription_teardown(cx, &mut state.inner)?;
        }
        notification => {
            let accepted = state.accepted.as_ref().ok_or_else(|| {
                McpError::invalid_request("Memory event preceded subscription acknowledgement")
            })?;
            validate_subscription_notification_filter(
                &notification,
                accepted,
                &state.resource_relations,
            )?;
            state.queue(
                MemorySubscriptionEvent::Notification(Box::new(notification)),
                frame.source().len(),
            )?;
            executor.record_subscription_activity(&state.inner)?;
        }
    }
    Ok(())
}

fn active_filter(filter: &SubscriptionFilter) -> SubscriptionFilter {
    let mut filter = filter.clone();
    for enabled in [
        &mut filter.prompts_list_changed,
        &mut filter.resources_list_changed,
        &mut filter.tools_list_changed,
    ] {
        if *enabled == Some(false) {
            *enabled = None;
        }
    }
    if filter.resource_subscriptions.as_ref().is_some_and(Vec::is_empty) {
        filter.resource_subscriptions = None;
    }
    #[cfg(feature = "tasks")]
    if filter
        .additional
        .get(fastmcp_protocol::TASK_SUBSCRIPTION_IDS_KEY)
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        filter.additional.remove(fastmcp_protocol::TASK_SUBSCRIPTION_IDS_KEY);
    }
    filter
}

fn unsupported_filter(
    requested: &SubscriptionFilter,
    accepted: &SubscriptionFilter,
) -> McpResult<SubscriptionFilter> {
    let missing = |requested, accepted| {
        (requested == Some(true) && accepted != Some(true)).then_some(true)
    };
    let mut unsupported = SubscriptionFilter {
        prompts_list_changed: missing(requested.prompts_list_changed, accepted.prompts_list_changed),
        resources_list_changed: missing(
            requested.resources_list_changed,
            accepted.resources_list_changed,
        ),
        tools_list_changed: missing(requested.tools_list_changed, accepted.tools_list_changed),
        ..SubscriptionFilter::default()
    };
    if let Some(requested_uris) = &requested.resource_subscriptions {
        let missing: Vec<_> = requested_uris
            .iter()
            .filter(|uri| {
                accepted.resource_subscriptions.as_ref().is_none_or(|accepted| !accepted.contains(uri))
            })
            .cloned()
            .collect();
        if !missing.is_empty() {
            unsupported.resource_subscriptions = Some(missing);
        }
    }
    for (key, value) in &requested.additional {
        #[cfg(feature = "tasks")]
        if key == fastmcp_protocol::TASK_SUBSCRIPTION_IDS_KEY {
            let requested_ids = fastmcp_protocol::task_subscription_ids(requested)
                .map_err(|_| McpError::invalid_params("Invalid requested Memory Tasks filter"))?
                .unwrap_or_default();
            let accepted_ids = fastmcp_protocol::task_subscription_ids(accepted)
                .map_err(|_| McpError::invalid_request("Invalid accepted Memory Tasks filter"))?
                .unwrap_or_default();
            let missing: Vec<_> = requested_ids
                .into_iter()
                .filter(|id| !accepted_ids.contains(id))
                .collect();
            if !missing.is_empty() {
                fastmcp_protocol::set_task_subscription_ids(&mut unsupported, missing)
                    .map_err(|_| McpError::invalid_request("Invalid unsupported Memory Tasks filter"))?;
            }
            continue;
        }
        if accepted.additional.get(key) != Some(value) {
            unsupported.additional.insert(key.clone(), value.clone());
        }
    }
    Ok(unsupported)
}

impl MemoryClient {
    /// Opens one bounded listener with independent idle and absolute deadlines.
    ///
    /// Subscription lifetime is separate from ordinary request timeouts. Up to
    /// 64 listeners share the existing reader, each retaining at most 64 events
    /// and 256 KiB of event source. A listener exceeding either queue bound is
    /// cancelled individually; other listeners and requests continue normally.
    pub async fn subscribe(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        notifications: impl Into<SubscriptionListenRequest>,
    ) -> McpResult<MemorySubscriptionExecution> {
        self.subscribe_with_timeout_policy(
            cx,
            cancellation,
            notifications,
            SubscriptionTimeoutPolicy::default(),
        )
        .await
    }

    /// Opens a listener with explicit bounded, post-publication lifetimes.
    ///
    /// Only accepted acknowledgements and filter-admitted events refresh idle.
    /// Absolute lifetime, the originating caller, and its cancellation token
    /// remain authoritative when another request drives this connection.
    pub async fn subscribe_with_timeout_policy(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        notifications: impl Into<SubscriptionListenRequest>,
        timeout_policy: SubscriptionTimeoutPolicy,
    ) -> McpResult<MemorySubscriptionExecution> {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        timeout_policy.validate()?;
        let (requested, resource_relations) = notifications.into().into_parts()?;
        let advertise_tasks = requested.additional.contains_key("taskIds");
        #[cfg(not(feature = "tasks"))]
        if advertise_tasks {
            return Err(McpError::invalid_params(
                "Memory Tasks subscription filters require the Tasks feature",
            ));
        }
        #[cfg(feature = "tasks")]
        if advertise_tasks {
            fastmcp_protocol::task_subscription_ids(&requested)
                .map_err(|_| McpError::invalid_params("Invalid Memory Tasks subscription filter"))?;
            if !self.tasks_active() {
                return Err(McpError::invalid_params(
                    "Memory Tasks subscription filters require explicit negotiated Tasks",
                ));
            }
        }
        self.executor.poll_timeouts_at(cx, Instant::now())?;
        self.subscriptions.ensure_capacity()?;
        let parameters = self.parameters_with_tasks(
            serde_json::json!({ "notifications": requested }),
            advertise_tasks,
        )?;
        let request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            "subscriptions/listen",
            Some(&parameters),
        )
        .map_err(|_| McpError::invalid_params("Invalid Memory subscription request"))?;
        let next_id = self.next_id.checked_add(1)
            .ok_or_else(|| McpError::internal_error("Memory request IDs exhausted"))?;
        let wire = JsonRpcRequest::new("subscriptions/listen", Some(parameters), self.next_id);
        fastmcp_transport::Codec::new()
            .encode_request(&wire)
            .map_err(transport_error_from_codec)?;
        let deadline = Instant::now() + SEND_ADMISSION_TIMEOUT;
        loop {
            self.flush_controls(cx, cancellation, deadline).await?;
            let permit = reserve_capacity(
                &mut self.sender,
                &mut self.receiver,
                &self.executor,
                &mut self.subscriptions,
                cx,
                cancellation,
                deadline,
            ).await?;
            if let Some(inner) = self.executor.execute_external_subscription(
                cx,
                cancellation,
                wire.clone(),
                timeout_policy,
                |message| permit.send(message),
            )? {
                let request_id = inner.request_id().clone();
                let key = request_id.correlation_key().expect("executor admitted the request ID");
                let state = Arc::new(Mutex::new(SubscriptionState {
                    inner,
                    request,
                    requested,
                    accepted: None,
                    resource_relations,
                    events: VecDeque::new(),
                    event_bytes: 0,
                    terminal_result: None,
                    finished: false,
                }));
                self.subscriptions.owners.insert(key, Arc::downgrade(&state));
                self.next_id = next_id;
                return Ok(MemorySubscriptionExecution {
                    owner: Arc::clone(&self.owner),
                    request_id,
                    state,
                });
            }
        }
    }

    /// Drives the shared connection until this listener has one admitted event.
    ///
    /// Dropping this future preserves the handle and all partially admitted
    /// events. Local cancellation or timeout yields one error, peer completion
    /// or cancellation yields one `Terminal`, and later reads return `None`.
    pub async fn next_subscription_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        execution: &mut MemorySubscriptionExecution,
    ) -> McpResult<Option<MemorySubscriptionEvent>> {
        self.ensure_subscription_owner(execution)?;
        loop {
            let maintenance = self.executor.poll_timeouts_at(cx, Instant::now());
            match lock(&execution.state).take_event(&self.executor)? {
                SubscriptionPoll::Event(event) => return Ok(Some(event)),
                SubscriptionPoll::Finished => return Ok(None),
                SubscriptionPoll::Pending => {}
            }
            maintenance?;
            if checkpoint(cx, cancellation).is_err() {
                self.executor.cancel(cx, &mut lock(&execution.state).inner)?;
                continue;
            }
            self.ensure_open()?;
            if let Err(error) = self.drive_once(cx, cancellation).await {
                if lock(&execution.state).inner.terminal_reason().is_some() {
                    continue;
                }
                if error.code == McpErrorCode::RequestCancelled {
                    self.executor.cancel(cx, &mut lock(&execution.state).inner)?;
                    continue;
                }
                return Err(error);
            }
        }
    }

    /// Elects local cancellation without awaiting channel or event capacity.
    /// Its id-only cancellation control is committed by the next shared drive.
    pub fn cancel_subscription(
        &mut self,
        cx: &Cx,
        execution: &mut MemorySubscriptionExecution,
    ) -> McpResult<()> {
        self.ensure_subscription_owner(execution)?;
        let mut state = lock(&execution.state);
        if !state.finished {
            self.executor.cancel(cx, &mut state.inner)?;
        }
        Ok(())
    }

    fn ensure_subscription_owner(&self, execution: &MemorySubscriptionExecution) -> McpResult<()> {
        if !Arc::ptr_eq(&self.owner, &execution.owner) {
            return Err(McpError::invalid_params(
                "Memory subscription belongs to a different client",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use asupersync::runtime::RuntimeBuilder;
    use fastmcp_transport::memory::create_memory_transport_pair_with_capacity;
    use serde_json::json;

    use super::*;

    fn run<F: Future<Output = ()>>(test: impl FnOnce(Cx) -> F) {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(8), test(cx))
                .await
                .expect("Memory subscriptions must progress on the caller runtime");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    fn info() -> ClientInfo {
        ClientInfo { name: "memory-subscriptions".into(), version: "1".into() }
    }

    fn response(id: i64, result: Value) -> JsonRpcMessage {
        JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), result))
    }

    fn notification(method: &str, id: i64, mut params: Value) -> JsonRpcMessage {
        params.as_object_mut().unwrap().insert(
            "_meta".into(),
            json!({"io.modelcontextprotocol/subscriptionId": id}),
        );
        JsonRpcMessage::Request(JsonRpcRequest::notification(method, Some(params)))
    }

    fn acknowledgement(id: i64, filter: Value) -> JsonRpcMessage {
        notification("notifications/subscriptions/acknowledged", id, json!({"notifications": filter}))
    }

    fn tools_filter() -> SubscriptionFilter {
        SubscriptionFilter { tools_list_changed: Some(true), ..SubscriptionFilter::default() }
    }

    async fn receive(cx: &Cx, peer: &mut MemoryTransport, method: &str) -> JsonRpcRequest {
        let JsonRpcMessage::Request(request) = peer.recv_async(cx).await.unwrap() else {
            panic!("expected a Memory client request");
        };
        assert_eq!(request.method, method);
        request
    }

    async fn connected(cx: &Cx) -> (MemoryClient, MemoryTransport) {
        let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
        peer.send_async(cx, &response(1, json!({
            "resultType": "complete", "supportedVersions": ["2026-07-28"],
            "capabilities": {}, "ttlMs": 0, "cacheScope": "private",
        }))).await.unwrap();
        let client = MemoryClient::builder(info()).connect(cx, transport).await.unwrap();
        receive(cx, &mut peer, "server/discover").await;
        (client, peer)
    }

    async fn open(
        cx: &Cx,
        client: &mut MemoryClient,
        peer: &mut MemoryTransport,
        cancellation: &McpRequestCancellation,
    ) -> MemorySubscriptionExecution {
        let owner = client.subscribe(cx, cancellation, tools_filter()).await.unwrap();
        let request = receive(cx, peer, "subscriptions/listen").await;
        assert_eq!(request.id.as_ref(), Some(owner.request_id()));
        owner
    }

    async fn ordinary_survives(cx: &Cx, client: &mut MemoryClient, peer: &mut MemoryTransport) {
        let token = McpRequestCancellation::new();
        let mut request = client.execute_core(cx, &token, "tools/list", json!({})).await.unwrap();
        let wire = receive(cx, peer, "tools/list").await;
        peer.send_async(cx, &JsonRpcMessage::Response(JsonRpcResponse::success(
            wire.id.unwrap(),
            json!({"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"}),
        ))).await.unwrap();
        assert!(matches!(
            client.next_event(cx, &token, &mut request).await.unwrap(),
            Some(MemoryRequestEvent::Result(result))
                if matches!(*result, CoreResult::Final(FinalCoreResult::ToolsList { .. })),
        ));
    }

    #[test]
    fn memory_subscription_partial_ack_retains_inactive_filters_and_exact_completion() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let token = McpRequestCancellation::new();
            let requested = SubscriptionFilter {
                tools_list_changed: Some(true), prompts_list_changed: Some(true),
                ..SubscriptionFilter::default()
            };
            let mut owner = client.subscribe(&cx, &token, requested).await.unwrap();
            receive(&cx, &mut peer, "subscriptions/listen").await;
            peer.send_async(&cx, &acknowledgement(2, json!({
                "toolsListChanged": true, "promptsListChanged": false,
                "resourcesListChanged": false, "resourceSubscriptions": [],
            }))).await.unwrap();
            let Some(MemorySubscriptionEvent::Acknowledged { accepted, unsupported }) =
                client.next_subscription_event(&cx, &token, &mut owner).await.unwrap()
            else { panic!("first subscription event is an acknowledgement"); };
            assert_eq!(accepted.prompts_list_changed, Some(false));
            assert_eq!(accepted.resources_list_changed, Some(false));
            assert_eq!(accepted.resource_subscriptions, Some(Vec::new()));
            assert_eq!(unsupported.prompts_list_changed, Some(true));
            assert_eq!(unsupported.tools_list_changed, None);
            peer.send_async(&cx, &response(2, json!({
                "resultType": "complete", "receipt": "retained",
                "_meta": {"io.modelcontextprotocol/subscriptionId": 2},
            }))).await.unwrap();
            assert!(matches!(client.next_subscription_event(&cx, &token, &mut owner).await.unwrap(),
                Some(MemorySubscriptionEvent::Terminal)));
            assert!(owner.terminal_result().is_some());
            assert!(client.next_subscription_event(&cx, &token, &mut owner).await.unwrap().is_none());
            ordinary_survives(&cx, &mut client, &mut peer).await;
        });
    }

    #[test]
    fn memory_subscription_dropped_event_future_preserves_other_owners_ingress() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let token = McpRequestCancellation::new();
            let mut first = open(&cx, &mut client, &mut peer, &token).await;
            let mut second = open(&cx, &mut client, &mut peer, &token).await;
            peer.send_async(&cx, &acknowledgement(3, json!({"toolsListChanged":true}))).await.unwrap();
            {
                let mut waiting = pin!(client.next_subscription_event(&cx, &token, &mut first));
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
            }
            assert_eq!(second.accepted_filter().unwrap().tools_list_changed, Some(true));
            assert!(matches!(client.next_subscription_event(&cx, &token, &mut second).await.unwrap(),
                Some(MemorySubscriptionEvent::Acknowledged { .. })));
            peer.send_async(&cx, &acknowledgement(2, json!({"toolsListChanged":true}))).await.unwrap();
            assert!(matches!(client.next_subscription_event(&cx, &token, &mut first).await.unwrap(),
                Some(MemorySubscriptionEvent::Acknowledged { .. })));
            assert!(!client.executor.has_external_controls(&cx).unwrap());
            ordinary_survives(&cx, &mut client, &mut peer).await;
        });
    }

    #[test]
    fn memory_subscription_protocol_refusals_retire_only_the_named_owner() {
        run(|cx| async move {
            for invalid in ["widened_ack", "duplicate_ack", "event_before_ack", "wrong_cancel", "missing_cancel_id"] {
                let (mut client, mut peer) = connected(&cx).await;
                let token = McpRequestCancellation::new();
                let mut rejected = open(&cx, &mut client, &mut peer, &token).await;
                let mut sibling = open(&cx, &mut client, &mut peer, &token).await;
                for owner in [&mut rejected, &mut sibling] {
                    if invalid == "event_before_ack" && owner.request_id() == &RequestId::Number(2) {
                        continue;
                    }
                    if invalid == "widened_ack" && owner.request_id() == &RequestId::Number(2) {
                        continue;
                    }
                    let id = if owner.request_id() == &RequestId::Number(2) { 2 } else { 3 };
                    peer.send_async(&cx, &acknowledgement(id, json!({"toolsListChanged":true}))).await.unwrap();
                    client.next_subscription_event(&cx, &token, owner).await.unwrap();
                }
                let bad = match invalid {
                    "widened_ack" => acknowledgement(2, json!({"promptsListChanged":true})),
                    "duplicate_ack" => acknowledgement(2, json!({"toolsListChanged":true})),
                    "event_before_ack" => notification("notifications/tools/list_changed", 2, json!({})),
                    "wrong_cancel" => notification("notifications/cancelled", 2, json!({"requestId":3})),
                    _ => JsonRpcMessage::Request(JsonRpcRequest::notification(
                        "notifications/cancelled", Some(json!({"requestId":2})),
                    )),
                };
                peer.send_async(&cx, &bad).await.unwrap();
                assert_eq!(client.next_subscription_event(&cx, &token, &mut rejected).await.unwrap_err().code,
                    McpErrorCode::InvalidRequest, "{invalid}");
                client.drive_once(&cx, &token).await.unwrap();
                let cancelled = receive(&cx, &mut peer, "notifications/cancelled").await;
                assert_eq!(cancelled.params.as_ref().unwrap()["requestId"], 2);
                assert!(cancelled.params.as_ref().unwrap().get("_meta").is_none());
                peer.send_async(&cx, &notification("notifications/tools/list_changed", 3, json!({}))).await.unwrap();
                assert!(matches!(client.next_subscription_event(&cx, &token, &mut sibling).await.unwrap(),
                    Some(MemorySubscriptionEvent::Notification(_))));
                ordinary_survives(&cx, &mut client, &mut peer).await;
            }
        });
    }

    #[test]
    fn memory_subscription_peer_teardown_has_no_fabricated_complete_result() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let token = McpRequestCancellation::new();
            let mut owner = open(&cx, &mut client, &mut peer, &token).await;
            peer.send_async(&cx, &acknowledgement(2, json!({"toolsListChanged":true}))).await.unwrap();
            client.next_subscription_event(&cx, &token, &mut owner).await.unwrap();
            peer.send_async(&cx, &notification("notifications/cancelled", 2, json!({"requestId":2}))).await.unwrap();
            assert!(matches!(client.next_subscription_event(&cx, &token, &mut owner).await.unwrap(),
                Some(MemorySubscriptionEvent::Terminal)));
            assert!(owner.terminal_result().is_none());
            assert!(!client.executor.has_external_controls(&cx).unwrap());
            peer.send_async(&cx, &response(2, json!({
                "resultType":"complete", "_meta":{"io.modelcontextprotocol/subscriptionId":2},
            }))).await.unwrap();
            client.drive_once(&cx, &token).await.unwrap();
            assert!(client.next_subscription_event(&cx, &token, &mut owner).await.unwrap().is_none());
            assert!(owner.terminal_result().is_none());
            ordinary_survives(&cx, &mut client, &mut peer).await;
        });
    }

    #[test]
    fn memory_subscription_queue_bounds_do_not_block_unrelated_requests() {
        run(|cx| async move {
            for oversized_event in [false, true] {
                let (mut client, mut peer) = connected(&cx).await;
                let token = McpRequestCancellation::new();
                let mut owner = open(&cx, &mut client, &mut peer, &token).await;
                peer.send_async(&cx, &acknowledgement(2, json!({"toolsListChanged":true}))).await.unwrap();
                client.next_subscription_event(&cx, &token, &mut owner).await.unwrap();
                let count = if oversized_event { 1 } else { MAX_QUEUED_EVENTS + 1 };
                for _ in 0..count {
                    let params = if oversized_event { json!({"padding": "x".repeat(MAX_QUEUED_EVENT_BYTES)}) } else { json!({}) };
                    peer.send_async(&cx, &notification("notifications/tools/list_changed", 2, params)).await.unwrap();
                    client.drive_once(&cx, &token).await.unwrap();
                }
                assert_eq!(client.next_subscription_event(&cx, &token, &mut owner).await.unwrap_err().code,
                    McpErrorCode::InvalidRequest);
                client.drive_once(&cx, &token).await.unwrap();
                receive(&cx, &mut peer, "notifications/cancelled").await;
                ordinary_survives(&cx, &mut client, &mut peer).await;
            }
        });
    }

    #[test]
    fn memory_subscription_owner_limit_releases_dropped_handles() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let token = McpRequestCancellation::new();
            let mut owners = Vec::new();
            for _ in 0..MAX_SUBSCRIPTIONS {
                owners.push(open(&cx, &mut client, &mut peer, &token).await);
            }
            let next_id = client.next_id;
            assert_eq!(client.subscribe(&cx, &token, tools_filter()).await.unwrap_err().code,
                McpErrorCode::InvalidParams);
            assert_eq!(client.next_id, next_id);
            drop(owners.remove(0));
            client.drive_once(&cx, &token).await.unwrap();
            let cancelled = receive(&cx, &mut peer, "notifications/cancelled").await;
            assert_eq!(cancelled.params.unwrap()["requestId"], 2);
            let replacement = open(&cx, &mut client, &mut peer, &token).await;
            assert_eq!(replacement.request_id(), &RequestId::Number(next_id));
            ordinary_survives(&cx, &mut client, &mut peer).await;
        });
    }

    #[test]
    fn memory_subscription_idle_absolute_and_origin_cancellation_beat_buffered_events() {
        run(|cx| async move {
            for cause in ["idle", "absolute", "origin"] {
                let (mut client, mut peer) = connected(&cx).await;
                let origin = McpRequestCancellation::new();
                let live = McpRequestCancellation::new();
                let policy = SubscriptionTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(6)).unwrap();
                let mut owner = client.subscribe_with_timeout_policy(&cx, &origin, tools_filter(), policy).await.unwrap();
                receive(&cx, &mut peer, "subscriptions/listen").await;
                peer.send_async(&cx, &acknowledgement(2, json!({"toolsListChanged":true}))).await.unwrap();
                client.drive_once(&cx, &live).await.unwrap();
                let record = client.executor.pending_records().into_iter().find(|record| record.request_id == RequestId::Number(2)).unwrap();
                match cause {
                    "idle" => client.executor.poll_timeouts_at(&cx, record.idle_deadline).unwrap(),
                    "absolute" => client.executor.poll_timeouts_at(&cx, record.absolute_deadline).unwrap(),
                    _ => origin.cancel(),
                }
                let error = client.next_subscription_event(&cx, &live, &mut owner).await.unwrap_err();
                assert_eq!(error.code, McpErrorCode::RequestCancelled);
                if cause != "origin" {
                    assert_eq!(error.data.as_ref().unwrap()["timeoutSource"], cause);
                }
                assert!(owner.terminal_result().is_none());
                client.drive_once(&cx, &live).await.unwrap();
                receive(&cx, &mut peer, "notifications/cancelled").await;
                ordinary_survives(&cx, &mut client, &mut peer).await;
            }
        });
    }

    #[test]
    fn memory_subscription_unnegotiated_tasks_filter_has_no_publication_or_id_cost() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let token = McpRequestCancellation::new();
            let filter = serde_json::from_value::<SubscriptionFilter>(json!({"taskIds":["task-a"]})).unwrap();
            assert_eq!(client.subscribe(&cx, &token, filter).await.unwrap_err().code, McpErrorCode::InvalidParams);
            assert_eq!(client.next_id, 2);
            assert!(client.executor.pending_records().is_empty());
            ordinary_survives(&cx, &mut client, &mut peer).await;
        });
    }

    #[cfg(feature = "tasks")]
    #[test]
    fn memory_subscription_task_events_keep_exact_result_source_and_accepted_ids() {
        run(|cx| async move {
            let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
            peer.send_async(&cx, &response(1, json!({
                "resultType":"complete", "supportedVersions":["2026-07-28"],
                "capabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}},
                "ttlMs":0, "cacheScope":"private",
            }))).await.unwrap();
            let mut client = MemoryClient::builder(info()).with_tasks().connect(&cx, transport).await.unwrap();
            receive(&cx, &mut peer, "server/discover").await;
            let token = McpRequestCancellation::new();
            let filter = serde_json::from_value::<SubscriptionFilter>(json!({"taskIds":["task-a","task-b"]})).unwrap();
            let mut owner = client.subscribe(&cx, &token, filter).await.unwrap();
            let request = receive(&cx, &mut peer, "subscriptions/listen").await;
            assert_eq!(request.params.unwrap()["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]["io.modelcontextprotocol/tasks"], json!({}));
            peer.send_async(&cx, &acknowledgement(2, json!({"taskIds":["task-a"]}))).await.unwrap();
            let Some(MemorySubscriptionEvent::Acknowledged { unsupported, .. }) = client.next_subscription_event(&cx, &token, &mut owner).await.unwrap() else {
                panic!("expected Tasks acknowledgement");
            };
            assert_eq!(unsupported.additional["taskIds"], json!(["task-b"]));
            let source = br#"{"jsonrpc":"2.0","method":"notifications/tasks","params":{"taskId":"task-a","status":"completed","createdAt":"2026-07-28T12:00:00.000Z","lastUpdatedAt":"2026-07-28T12:00:01.000Z","ttlMs":60000,"result":{"content":[],"precise":7.30e-2,"huge":18446744073709551617},"_meta":{"io.modelcontextprotocol/subscriptionId":2}}}"#;
            admit_frame(&client.executor, &mut client.subscriptions, &cx, ReceivedTransportFrame::admit(source.to_vec()).unwrap()).unwrap();
            let Some(MemorySubscriptionEvent::Task(notification)) = client.next_subscription_event(&cx, &token, &mut owner).await.unwrap() else {
                panic!("expected exact-source Task notification");
            };
            let retained = serde_json::to_string(&notification).unwrap();
            assert!(retained.contains("7.30e-2"));
            assert!(retained.contains("18446744073709551617"));
            let mut foreign = serde_json::from_slice::<Value>(source).unwrap();
            foreign["params"]["taskId"] = json!("task-b");
            let frame = ReceivedTransportFrame::admit(serde_json::to_vec(&foreign).unwrap()).unwrap();
            admit_frame(&client.executor, &mut client.subscriptions, &cx, frame).unwrap();
            assert_eq!(client.next_subscription_event(&cx, &token, &mut owner).await.unwrap_err().code, McpErrorCode::InvalidRequest);
            client.drive_once(&cx, &token).await.unwrap();
            receive(&cx, &mut peer, "notifications/cancelled").await;
            ordinary_survives(&cx, &mut client, &mut peer).await;
        });
    }
}
