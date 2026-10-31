//! Caller-owned, bounded observation of an existing final Task.
//!
//! Waiting only reads Tasks. Explicit input submission and reconciliation
//! use the same caller-owned request machinery; neither replays uncertain work.
//! Remote cancellation, reconnects and persistence remain application actions.

use std::future::Future;
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
#[cfg(feature = "websocket-experimental")]
use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::types::Time;
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};

#[cfg(any(unix, feature = "websocket-experimental"))]
use crate::FinalUpdateTaskResult;
#[cfg(feature = "websocket-experimental")]
use crate::WebSocketClient;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::timestamp_nanos;
#[cfg(unix)]
use crate::{Client, SubscriptionTimeoutPolicy};
use crate::{
    FinalTask, FinalTaskHandle, FinalTaskId, FinalTaskInputResponses, HttpClient, HttpClientError,
    TaskInputLedger,
};
#[cfg(any(unix, feature = "websocket-experimental"))]
use crate::{
    FinalTaskWatchEvent, RequestId, StdioTaskSubscriptionEvent, SubscriptionFilter,
    task_subscription_ids,
};

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
    /// Later wall-clock advances may shorten it; rollback cannot extend an
    /// unchanged retention deadline. Fresh authoritative snapshots may change
    /// `ttlMs`; their checked expiry replaces the previous retention bound
    /// without restarting the caller's original timeout. This is local expiry
    /// observation, not proof of server deletion or a replacement for
    /// server-side authorization and retention.
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

    /// The same bounded observation over the caller-owned WebSocket client.
    ///
    /// The existing request owner retires an abandoned response wait without
    /// cancelling the remote Task or unrelated subscriptions. An interrupted
    /// partial frame write makes the connection unusable rather than replaying
    /// the request. This method never reconnects or submits input implicitly.
    #[cfg(feature = "websocket-experimental")]
    pub async fn wait_with_websocket<IO>(
        &mut self,
        cx: &Cx,
        client: &mut WebSocketClient<IO>,
        cancellation: &McpRequestCancellation,
        policy: FinalTaskWaitPolicy,
    ) -> McpResult<FinalTaskWaitOutcome>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        wait_for_task(self, cx, client, cancellation, policy).await
    }

    /// Reconciles this handle through one yielding Unix stdio `tasks/get`.
    ///
    /// Use this after an acknowledged input update, which deliberately does
    /// not invent a new Task state. Identity and creation instant must still
    /// match; an authoritative TTL change replaces the retention bound. A
    /// refused read, cancellation or abandonment leaves the last snapshot unchanged. Use
    /// the same client that attached this handle; the server authorizes reads.
    #[cfg(unix)]
    pub async fn poll_with_stdio(
        &mut self,
        cx: &Cx,
        client: &mut Client,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<&FinalTask> {
        if self.is_terminal() {
            return Ok(&self.task);
        }
        checkpoint_task_operation(cx, cancellation)?;
        let result = client
            .get_task_final_with_cx(cx, cancellation, self.task_id().clone())
            .await?;
        admit_identity(self.task(), &result.task)?;
        checkpoint_task_operation(cx, cancellation)?;
        self.task = result.task;
        Ok(&self.task)
    }

    /// Reconciles this handle through one cancellation-aware WebSocket read.
    ///
    /// Task identity and creation instant must match before the retained
    /// snapshot changes. Authoritative TTL changes remain admissible. A
    /// terminal snapshot returns without I/O.
    /// Cancelling or dropping an in-flight read preserves the last snapshot
    /// and follows the same request custody as [`Self::wait_with_websocket`].
    #[cfg(feature = "websocket-experimental")]
    pub async fn poll_with_websocket<IO>(
        &mut self,
        cx: &Cx,
        client: &mut WebSocketClient<IO>,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<&FinalTask>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if self.is_terminal() {
            return Ok(&self.task);
        }
        let result = guard_websocket_task_operation(
            cx,
            cancellation,
            client.get_task_final(cx, self.task_id().clone()),
        )
        .await?;
        admit_identity(self.task(), &result.task)?;
        checkpoint_task_operation(cx, cancellation)?;
        self.task = result.task;
        Ok(&self.task)
    }

    /// Submits explicit input responses through the yielding Unix stdio path.
    ///
    /// Phase, response kinds and locally observed finite retention are checked
    /// before initialization or wire effects. The server remains the authority
    /// for authorization and stale-state admission. This method invokes no
    /// input callbacks and does not retry an uncertain update.
    ///
    /// As with [`Self::resume_input`], a successful acknowledgement does not
    /// replace the retained Task snapshot. Call [`Self::poll_with_stdio`] to
    /// reconcile the next state, then [`Self::wait_with_stdio`] if it remains
    /// working. Cancellation or dropping the future cannot undo an update
    /// already sent; reconcile before explicitly submitting another response.
    #[cfg(unix)]
    pub async fn resume_input_with_stdio(
        &mut self,
        cx: &Cx,
        client: &mut Client,
        cancellation: &McpRequestCancellation,
        input_responses: FinalTaskInputResponses,
    ) -> McpResult<FinalUpdateTaskResult> {
        client
            .update_task_final_with_cx(cx, cancellation, &self.task, input_responses)
            .await
    }

    /// Submits one explicit input batch over the negotiated WebSocket client.
    ///
    /// Phase, response kinds, cancellation and finite retention are admitted
    /// before allocating a request ID or sending input. An acknowledgement
    /// leaves the retained snapshot unchanged; explicitly call
    /// [`Self::poll_with_websocket`] before waiting for the next state.
    /// Cancellation or dropping this future cannot undo a committed update.
    /// No uncertain update is replayed: reconcile before deciding to resubmit.
    #[cfg(feature = "websocket-experimental")]
    pub async fn resume_input_with_websocket<IO>(
        &mut self,
        cx: &Cx,
        client: &mut WebSocketClient<IO>,
        cancellation: &McpRequestCancellation,
        input_responses: FinalTaskInputResponses,
    ) -> McpResult<FinalUpdateTaskResult>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        checkpoint_task_operation(cx, cancellation)?;
        admit_task_input(&self.task, &input_responses)?;
        // Retiring a previous dropped read may await a bounded control write.
        // Recheck retention before the new update can allocate its ID. The
        // exclusive client borrow then leaves no other request to settle.
        guard_websocket_task_operation(
            cx,
            cancellation,
            client.settle_abandoned_websocket_request(),
        )
        .await?;
        admit_input_retention(&self.task)?;
        guard_websocket_task_operation(
            cx,
            cancellation,
            client.update_task_final(cx, &self.task, input_responses),
        )
        .await
    }

    /// Watches this Task through the existing Unix stdio subscription owner.
    ///
    /// The watch has the default subscription absolute lifetime, tightened by
    /// the caller deadline and current Task retention. Notifications and one
    /// authoritative read per ambiguous snapshot share the sole stdio ingress
    /// driver. No polling loop, input callback, reconnect or remote Task
    /// cancellation is started. Dropping the watch retires only its listen
    /// request; its deferred control is flushed on the next client operation.
    #[cfg(unix)]
    pub async fn watch_with_stdio<'client, 'handle>(
        &'handle mut self,
        cx: &Cx,
        client: &'client mut Client,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<FinalTaskStreamWatch<'client, 'handle, Client>> {
        open_task_stream_watch(self, cx, client, cancellation).await
    }

    /// Watches this Task through the existing WebSocket subscription owner.
    ///
    /// The client's subscription timeout policy bounds the entire watch;
    /// caller cancellation/deadline and finite Task retention can stop it
    /// sooner. Dropping the watch marks only its exact listen owner for
    /// cancellation before the next client operation. It never starts a
    /// background task or sends `tasks/cancel`.
    #[cfg(feature = "websocket-experimental")]
    pub async fn watch_with_websocket<'client, 'handle, IO>(
        &'handle mut self,
        cx: &Cx,
        client: &'client mut WebSocketClient<IO>,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<FinalTaskStreamWatch<'client, 'handle, WebSocketClient<IO>>>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        open_task_stream_watch(self, cx, client, cancellation).await
    }
}

/// A caller-driven Task watch on a retained stdio or WebSocket connection.
///
/// This watcher borrows the existing client and handle, so it cannot introduce
/// a competing ingress reader or a second request-ID allocator. It yields the
/// acknowledgement, updated Task and reconciled Task variants of
/// [`FinalTaskWatchEvent`]. The underlying transport validates a normal listen
/// completion and then returns `None`; it does not invent the HTTP response
/// payload required by that event enum's `Terminal` variant.
///
/// [`Self::stop_reason`] distinguishes a terminal Task or local observation
/// bound from normal stream exhaustion. Dropping just a `next_event` future
/// preserves partial ingress; dropping during reconciliation exhausts this
/// watch because its ambiguous notification cannot be silently forgotten.
/// Dropping the watcher retires its exact subscription without cancelling the
/// remote Task, a catalog listener, or an unrelated request.
#[cfg(any(unix, feature = "websocket-experimental"))]
pub struct FinalTaskStreamWatch<'client, 'handle, T> {
    handle: &'handle mut FinalTaskHandle,
    client: &'client mut T,
    request_id: Option<RequestId>,
    budget: Option<WaitBudget>,
    observing: bool,
    stop_reason: Option<FinalTaskWaitOutcome>,
    abandon: fn(&mut T, &RequestId),
}

#[cfg(any(unix, feature = "websocket-experimental"))]
impl<T> FinalTaskStreamWatch<'_, '_, T> {
    /// Returns the latest fully admitted Task, including its exact result.
    #[must_use]
    pub fn task(&self) -> &FinalTask {
        self.handle.task()
    }

    /// Returns the terminal Task or local bound that exhausted this watch.
    ///
    /// `None` means the watch remains live, the peer ended its subscription,
    /// accepted an empty Task filter, or an operation failed/was abandoned.
    /// Local cancellation stops observation only; it is never evidence that
    /// the durable Task reached terminal `cancelled`.
    #[must_use]
    pub const fn stop_reason(&self) -> Option<FinalTaskWaitOutcome> {
        self.stop_reason
    }
}

#[cfg(any(unix, feature = "websocket-experimental"))]
impl<T> Drop for FinalTaskStreamWatch<'_, '_, T> {
    fn drop(&mut self) {
        if let Some(request_id) = self.request_id.take() {
            (self.abandon)(self.client, &request_id);
        }
    }
}

#[cfg(unix)]
impl FinalTaskStreamWatch<'_, '_, Client> {
    /// Receives one acknowledged, changed or authoritatively reconciled Task.
    ///
    /// Exact repeats are skipped. Equal/regressed conflicting timestamps
    /// cause at most one `tasks/get` in this call. A terminal Task is yielded
    /// once, then the listener is retired and later calls return `None`.
    /// Cancellation, deadline and retention expiry return `None` with a typed
    /// [`Self::stop_reason`], preserving the last admitted snapshot.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<Option<FinalTaskWatchEvent>> {
        next_task_stream_event(self, cx, cancellation).await
    }
}

#[cfg(feature = "websocket-experimental")]
impl<IO> FinalTaskStreamWatch<'_, '_, WebSocketClient<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Receives one Task event under the original watch lifetime.
    ///
    /// Exact repeats are skipped and ambiguous timestamps cause one bounded
    /// authoritative read. A terminal Task is yielded once; normal stream
    /// termination or a typed local [`Self::stop_reason`] returns `None`.
    /// No remote cancellation or implicit input effect is performed.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<Option<FinalTaskWatchEvent>> {
        next_task_stream_event(self, cx, cancellation).await
    }
}

#[cfg(any(unix, feature = "websocket-experimental"))]
trait TaskWatchTransport: TaskWaitTransport<Error = McpError> {
    fn watch_timeout(&self) -> Duration;
    fn live_watch_id(&self) -> Option<RequestId>;
    async fn open_watch(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        filter: SubscriptionFilter,
    ) -> McpResult<()>;
    async fn next_watch_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<StdioTaskSubscriptionEvent>;
    async fn cancel_watch(&mut self, request_id: &RequestId) -> McpResult<()>;
    fn abandon_watch(&mut self, request_id: &RequestId);
}

#[cfg(unix)]
impl TaskWatchTransport for Client {
    fn watch_timeout(&self) -> Duration {
        SubscriptionTimeoutPolicy::default().absolute_timeout()
    }

    fn live_watch_id(&self) -> Option<RequestId> {
        self.live_task_subscription
            .as_ref()
            .map(|subscription| subscription.execution.request_id().clone())
    }

    async fn open_watch(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        filter: SubscriptionFilter,
    ) -> McpResult<()> {
        self.open_final_task_subscription_listener_with_cx(cx, cancellation, filter)
            .await
    }

    async fn next_watch_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<StdioTaskSubscriptionEvent> {
        self.next_final_task_subscription_event_with_cx(cx, cancellation)
            .await
    }

    async fn cancel_watch(&mut self, request_id: &RequestId) -> McpResult<()> {
        if self
            .live_watch_id()
            .is_some_and(|owned| owned.correlates_with(request_id))
        {
            self.cancel_live_final_task_subscription(&self.cx.clone())?;
        }
        Ok(())
    }

    fn abandon_watch(&mut self, request_id: &RequestId) {
        if self
            .live_watch_id()
            .is_some_and(|owned| owned.correlates_with(request_id))
        {
            // RequestExecution::drop installs the exact tombstone and queues
            // its cancellation for the sole connection driver. No I/O here.
            self.live_task_subscription = None;
        }
    }
}

#[cfg(feature = "websocket-experimental")]
impl<IO> TaskWatchTransport for WebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn watch_timeout(&self) -> Duration {
        self.subscription_timeout_policy.absolute_timeout()
    }

    fn live_watch_id(&self) -> Option<RequestId> {
        self.live_task_subscription
            .as_ref()
            .filter(|subscription| !subscription.abandoned)
            .map(|subscription| subscription.request_id.clone())
    }

    async fn open_watch(
        &mut self,
        cx: &Cx,
        _cancellation: &McpRequestCancellation,
        filter: SubscriptionFilter,
    ) -> McpResult<()> {
        self.open_final_task_subscription_listener(cx, filter).await
    }

    async fn next_watch_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<StdioTaskSubscriptionEvent> {
        self.next_final_task_subscription_event(cx, cancellation)
            .await
    }

    async fn cancel_watch(&mut self, request_id: &RequestId) -> McpResult<()> {
        if self
            .live_task_subscription
            .as_ref()
            .is_some_and(|subscription| subscription.request_id.correlates_with(request_id))
        {
            self.cancel_live_task_subscription().await?;
        }
        Ok(())
    }

    fn abandon_watch(&mut self, request_id: &RequestId) {
        if let Some(subscription) = self.live_task_subscription.as_mut()
            && subscription.request_id.correlates_with(request_id)
        {
            // The next connection operation owns the bounded cancellation
            // write. Keep its exact slot rather than creating a new queue.
            subscription.abandoned = true;
        }
    }
}

#[cfg(any(unix, feature = "websocket-experimental"))]
async fn open_task_stream_watch<'client, 'handle, T: TaskWatchTransport>(
    handle: &'handle mut FinalTaskHandle,
    cx: &Cx,
    client: &'client mut T,
    cancellation: &McpRequestCancellation,
) -> McpResult<FinalTaskStreamWatch<'client, 'handle, T>> {
    let terminal = handle.is_terminal();
    let mut watch = FinalTaskStreamWatch {
        stop_reason: terminal.then(|| ready_outcome(handle.task())).flatten(),
        handle,
        client,
        request_id: None,
        budget: None,
        observing: false,
        abandon: T::abandon_watch,
    };
    if terminal {
        return Ok(watch);
    }
    let budget = WaitBudget::new(cx, watch.client.watch_timeout(), watch.handle.task())?;
    if let Some(reason) = budget.stop(cx, cancellation) {
        watch.stop_reason = Some(reason);
        return Ok(watch);
    }
    if cx.timer_driver().is_none() {
        watch.stop_reason = Some(FinalTaskWaitOutcome::TimerUnavailable);
        return Ok(watch);
    }
    if watch.client.live_watch_id().is_some() {
        return Err(McpError::invalid_request(
            "A final Tasks subscription is already active on this client",
        ));
    }
    let mut filter = SubscriptionFilter::default();
    fastmcp_protocol::set_task_subscription_ids(&mut filter, vec![watch.handle.task_id().clone()])
        .map_err(|_| McpError::internal_error("Final Task watch filter could not be composed"))?;
    let opened = budget
        .guard(
            cx,
            cancellation,
            watch.client.open_watch(cx, cancellation, filter),
        )
        .await;
    // The guard can select cancellation immediately after open committed.
    // Capture the new owner before inspecting that result so it cannot leak.
    watch.request_id = watch.client.live_watch_id();
    match opened {
        Ok(result) => result?,
        Err(reason) => {
            watch.stop_reason = Some(reason);
            stop_task_stream_watch(&mut watch).await?;
            return Ok(watch);
        }
    }
    if watch.request_id.is_none() {
        return Err(McpError::internal_error(
            "Final Task watch lost its listen owner",
        ));
    }
    watch.budget = Some(budget);
    watch.observing = true;
    Ok(watch)
}

#[cfg(any(unix, feature = "websocket-experimental"))]
async fn stop_task_stream_watch<T: TaskWatchTransport>(
    watch: &mut FinalTaskStreamWatch<'_, '_, T>,
) -> McpResult<()> {
    if let Some(request_id) = watch.request_id.as_ref() {
        watch.client.cancel_watch(request_id).await?;
        watch.request_id = None;
    }
    Ok(())
}

#[cfg(any(unix, feature = "websocket-experimental"))]
async fn next_task_stream_event<T: TaskWatchTransport>(
    watch: &mut FinalTaskStreamWatch<'_, '_, T>,
    cx: &Cx,
    cancellation: &McpRequestCancellation,
) -> McpResult<Option<FinalTaskWatchEvent>> {
    let result = next_task_stream_event_inner(watch, cx, cancellation).await;
    if result.is_err() {
        watch.observing = false;
    }
    if !watch.observing {
        stop_task_stream_watch(watch).await?;
    }
    result
}

#[cfg(any(unix, feature = "websocket-experimental"))]
async fn next_task_stream_event_inner<T: TaskWatchTransport>(
    watch: &mut FinalTaskStreamWatch<'_, '_, T>,
    cx: &Cx,
    cancellation: &McpRequestCancellation,
) -> McpResult<Option<FinalTaskWatchEvent>> {
    if !watch.observing {
        return Ok(None);
    }
    loop {
        let budget = watch.budget.as_ref().expect("a live watch has a budget");
        let event = match budget
            .guard(
                cx,
                cancellation,
                watch.client.next_watch_event(cx, cancellation),
            )
            .await
        {
            Ok(result) => result?,
            Err(reason) => {
                watch.stop_reason = Some(reason);
                watch.observing = false;
                return Ok(None);
            }
        };
        match event {
            StdioTaskSubscriptionEvent::Acknowledged(accepted_filter) => {
                let accepted = task_subscription_ids(&accepted_filter)
                    .map_err(|_| {
                        McpError::invalid_request("Invalid final Task watch acknowledgement")
                    })?
                    .unwrap_or_default();
                if accepted.iter().any(|id| id != watch.handle.task_id()) {
                    return Err(McpError::invalid_request(
                        "Final Task watch acknowledgement widened the requested Task filter",
                    ));
                }
                // An empty accepted subset is valid and requests no events.
                if accepted.is_empty() {
                    watch.observing = false;
                }
                return Ok(Some(FinalTaskWatchEvent::Acknowledged { accepted_filter }));
            }
            StdioTaskSubscriptionEvent::Notification(notification) => {
                admit_identity(watch.handle.task(), &notification.params.task)?;
                if watch
                    .handle
                    .snapshot_is_identical(&notification.params.task)
                    .map_err(task_watch_comparison_error)?
                {
                    asupersync::runtime::yield_now().await;
                    continue;
                }
                let reconcile = watch
                    .handle
                    .notification_needs_reconciliation(&notification.params.task)
                    .map_err(task_watch_comparison_error)?;
                let task = if reconcile {
                    // A dropped read must not resume after silently forgetting
                    // this conflict. The watch retains cleanup ownership.
                    watch.observing = false;
                    match budget
                        .guard(
                            cx,
                            cancellation,
                            watch.client.read_task(
                                cx,
                                cancellation,
                                watch.handle.task_id().clone(),
                            ),
                        )
                        .await
                    {
                        Ok(result) => result?,
                        Err(reason) => {
                            watch.stop_reason = Some(reason);
                            return Ok(None);
                        }
                    }
                } else {
                    notification.params.task.clone()
                };
                admit_identity(watch.handle.task(), &task)?;
                let budget = watch.budget.as_mut().expect("a live watch has a budget");
                budget.refresh_retention(cx, &task)?;
                if let Some(reason) = budget.stop(cx, cancellation) {
                    watch.stop_reason = Some(reason);
                    watch.observing = false;
                    return Ok(None);
                }
                watch.handle.task = task;
                watch.observing = !watch.handle.is_terminal();
                if !watch.observing {
                    watch.stop_reason = ready_outcome(watch.handle.task());
                }
                return Ok(Some(if reconcile {
                    FinalTaskWatchEvent::TaskReconciled {
                        observed: Box::new(notification),
                        authoritative: watch.handle.task().clone(),
                    }
                } else {
                    FinalTaskWatchEvent::TaskUpdated(notification)
                }));
            }
            StdioTaskSubscriptionEvent::Terminal => {
                watch.observing = false;
                watch.request_id = None;
                return Ok(None);
            }
        }
    }
}

#[cfg(any(unix, feature = "websocket-experimental"))]
fn task_watch_comparison_error(error: HttpClientError) -> McpError {
    match error {
        HttpClientError::CoreResult(error) => error,
        _ => McpError::internal_error("Final Task snapshot comparison failed"),
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

#[cfg(feature = "websocket-experimental")]
impl<IO> WebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Attaches an existing Task through one negotiated, cancellable read.
    ///
    /// Attachment does not create, replay, persist or automatically resume any
    /// work. Keep using this client for the returned handle's WebSocket methods.
    pub async fn attach_final_task(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> McpResult<FinalTaskHandle> {
        guard_websocket_task_operation(cx, cancellation, self.get_task_final(cx, task_id))
            .await
            .map(|result| FinalTaskHandle::new(result.task))
    }
}

/// Cancellation also guards a pending frame send or response read. Dropping
/// the typed RPC future delegates its exact request to the transport's existing
/// Drop owner; no separate receive loop, retry or connection owner is created.
#[cfg(feature = "websocket-experimental")]
async fn guard_websocket_task_operation<T>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    operation: impl Future<Output = McpResult<T>>,
) -> McpResult<T> {
    let mut operation = std::pin::pin!(operation);
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    // A backpressured send may have no I/O wake before the caller's deadline
    // or independent Cx cancellation. Request-token wakes alone cannot make
    // those checkpoints observable, and response timers start only after send.
    let checkpoint_slice = Duration::from_millis(20);
    let checkpoint_delay = || {
        cx.budget().deadline.map_or(checkpoint_slice, |deadline| {
            checkpoint_slice.min(Duration::from_nanos(deadline.duration_since(cx.now())))
        })
    };
    let mut wake = cx
        .timer_driver()
        .map(|_| Box::pin(asupersync::time::sleep(cx.now(), checkpoint_delay())));
    std::future::poll_fn(|task_cx| {
        let _current = Cx::set_current(Some(cx.clone()));
        if let Err(error) = checkpoint_task_operation(cx, cancellation) {
            return Poll::Ready(Err(error));
        }
        if cancelled.as_mut().poll(task_cx).is_ready() {
            return Poll::Ready(Err(McpError::request_cancelled()));
        }
        let result = operation.as_mut().poll(task_cx);
        if let Err(error) = checkpoint_task_operation(cx, cancellation) {
            return Poll::Ready(Err(error));
        }
        if result.is_pending()
            && let Some(wake) = wake.as_mut()
            && wake.as_mut().poll(task_cx).is_ready()
        {
            wake.set(asupersync::time::sleep(cx.now(), checkpoint_delay()));
            task_cx.waker().wake_by_ref();
        }
        result
    })
    .await
}

pub(super) fn admit_task_input(
    task: &FinalTask,
    input_responses: &FinalTaskInputResponses,
) -> McpResult<()> {
    let FinalTask::InputRequired { input_requests, .. } = task else {
        return Err(McpError::invalid_params(
            "tasks/update requires an input_required final task",
        ));
    };
    let ledger = TaskInputLedger::from_requests(input_requests)
        .map_err(|_| McpError::invalid_params("Task snapshot has invalid input requests"))?;
    ledger.validate_responses(input_responses).map_err(|_| {
        McpError::invalid_params(
            "Task input responses do not match the outstanding input request types",
        )
    })?;
    admit_input_retention(task)
}

#[cfg(any(unix, feature = "websocket-experimental"))]
fn checkpoint_task_operation(cx: &Cx, cancellation: &McpRequestCancellation) -> McpResult<()> {
    if cancellation.is_cancel_requested()
        || cx
            .budget()
            .deadline
            .is_some_and(|deadline| cx.now() >= deadline)
        || cx.checkpoint().is_err()
    {
        return Err(McpError::request_cancelled());
    }
    Ok(())
}

pub(super) fn admit_input_retention(task: &FinalTask) -> McpResult<()> {
    input_retention_remaining(task).map(|_| ())
}

/// Remaining lifetime of the exact supplied input snapshot, without narrowing
/// an otherwise valid long TTL through a nanosecond-sized runtime clock.
/// Callers meet this value with their own finite operation budget before
/// scheduling a timer, and recheck retention before committing input effects.
pub(super) fn input_retention_remaining(task: &FinalTask) -> McpResult<Option<Duration>> {
    let Some(expires) = retention_deadline(task)? else {
        return Ok(None);
    };
    let remaining = expires
        .checked_sub(wall_now_nanos())
        .ok_or_else(|| McpError::invalid_request("Invalid final Task retention deadline"))?;
    if remaining <= 0 {
        return Err(McpError::invalid_request(
            "Final Task input snapshot has expired",
        ));
    }
    let seconds = u64::try_from(remaining / 1_000_000_000)
        .map_err(|_| McpError::invalid_request("Invalid final Task retention deadline"))?;
    let nanos = u32::try_from(remaining % 1_000_000_000)
        .map_err(|_| McpError::invalid_request("Invalid final Task retention deadline"))?;
    Ok(Some(Duration::new(seconds, nanos)))
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

#[cfg(feature = "websocket-experimental")]
impl<IO> TaskWaitTransport for WebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Error = McpError;

    async fn read_task(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> McpResult<FinalTask> {
        guard_websocket_task_operation(cx, cancellation, self.get_task_final(cx, task_id))
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

pub(super) fn admit_identity(previous: &FinalTask, next: &FinalTask) -> McpResult<()> {
    let invalid = || McpError::invalid_request("Final Task identity changed during observation");
    if previous.base().task_id != next.base().task_id
        || timestamp_nanos(&previous.base().created_at).map_err(|_| invalid())?
            != timestamp_nanos(&next.base().created_at).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    // Retention is mutable Task state, not part of its identity. A fresh
    // authoritative snapshot may extend, shorten or remove the TTL; still
    // validate its complete checked expiry before replacing retained state.
    retention_deadline(next).map(|_| ())
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
    local_wall_deadline: Instant,
    local_runtime_deadline: Time,
    wall_deadline: Instant,
    runtime_deadline: Time,
    retention_deadline: Option<i128>,
    deadline_outcome: FinalTaskWaitOutcome,
}

impl WaitBudget {
    fn new(cx: &Cx, timeout: Duration, task: &FinalTask) -> McpResult<Self> {
        Self::at_wall_time(cx, timeout, task, wall_now_nanos())
    }

    fn at_wall_time(
        cx: &Cx,
        timeout: Duration,
        task: &FinalTask,
        wall_now: i128,
    ) -> McpResult<Self> {
        let now = cx.now();
        let local_deadline =
            now.saturating_add_nanos(u64::try_from(timeout.as_nanos()).map_err(|_| {
                McpError::invalid_params("Final Task wait deadline is out of range")
            })?);
        let local_deadline = cx
            .budget()
            .deadline
            .map_or(local_deadline, |caller| caller.min(local_deadline));
        let remaining = timeout.min(Duration::from_nanos(local_deadline.duration_since(now)));
        let wall_deadline = Instant::now()
            .checked_add(remaining)
            .ok_or_else(|| McpError::invalid_params("Final Task wait deadline is out of range"))?;
        let mut budget = Self {
            local_wall_deadline: wall_deadline,
            local_runtime_deadline: local_deadline,
            wall_deadline,
            runtime_deadline: local_deadline,
            retention_deadline: None,
            deadline_outcome: FinalTaskWaitOutcome::DeadlineElapsed,
        };
        budget.refresh_retention_at_wall_time(cx, task, wall_now)?;
        Ok(budget)
    }

    fn refresh_retention(&mut self, cx: &Cx, task: &FinalTask) -> McpResult<()> {
        self.refresh_retention_at_wall_time(cx, task, wall_now_nanos())
    }

    fn refresh_retention_at_wall_time(
        &mut self,
        cx: &Cx,
        task: &FinalTask,
        wall_now: i128,
    ) -> McpResult<()> {
        let retention_deadline = retention_deadline(task)?;
        if retention_deadline == self.retention_deadline {
            // Repeated snapshots must not re-anchor the same expiry after a
            // wall-clock rollback or reset either original local deadline.
            return Ok(());
        }
        let now = cx.now();
        let monotonic_now = Instant::now();
        let local_remaining = self
            .local_wall_deadline
            .saturating_duration_since(monotonic_now)
            .min(Duration::from_nanos(
                self.local_runtime_deadline.duration_since(now),
            ));
        let mut runtime_deadline = self.local_runtime_deadline;
        let mut wall_deadline = self.local_wall_deadline;
        let mut deadline_outcome = FinalTaskWaitOutcome::DeadlineElapsed;
        if let Some(expires) = retention_deadline {
            let nanos = expires.saturating_sub(wall_now).max(0);
            if nanos <= local_remaining.as_nanos() as i128 {
                // Only narrow after meeting the at-most-24-hour local ceiling.
                let nanos = u64::try_from(nanos).map_err(|_| {
                    McpError::invalid_request("Invalid final Task retention deadline")
                })?;
                runtime_deadline = now.saturating_add_nanos(nanos);
                wall_deadline = monotonic_now
                    .checked_add(Duration::from_nanos(nanos))
                    .ok_or_else(|| {
                        McpError::invalid_request("Invalid final Task retention deadline")
                    })?;
                deadline_outcome = FinalTaskWaitOutcome::TaskExpired;
            }
        }
        self.retention_deadline = retention_deadline;
        self.runtime_deadline = runtime_deadline;
        self.wall_deadline = wall_deadline;
        self.deadline_outcome = deadline_outcome;
        Ok(())
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
        } else if self
            .retention_deadline
            .is_some_and(|expires| wall_now >= expires)
        {
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
        let remaining = self
            .wall_deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_nanos(
                self.runtime_deadline.duration_since(cx.now()),
            ));
        self.retention_deadline.map_or(remaining, |expires| {
            let nanos = expires.saturating_sub(wall_now_nanos()).max(0);
            remaining.min(Duration::from_nanos(
                u64::try_from(nanos).unwrap_or(u64::MAX),
            ))
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
    let mut budget = WaitBudget::new(cx, policy.timeout, handle.task())?;
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
        budget.refresh_retention(cx, &task)?;
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

#[cfg(all(test, any(unix, feature = "websocket-experimental")))]
#[path = "task_watch_tests.rs"]
mod watch_tests;
