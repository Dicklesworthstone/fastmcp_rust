//! Caller-owned, bounded observation of an existing final Task.
//!
//! Waiting only reads Tasks. Explicit input submission, reconciliation and
//! opt-in automatic driving share caller-owned request and callback machinery.
//! Reusable drivers retain input custody and never replay uncertain work.
//! Remote cancellation, reconnects and persistence remain application actions.

use std::future::Future;
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
#[cfg(feature = "websocket-experimental")]
use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::types::Time;
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};

#[cfg(feature = "websocket-experimental")]
use crate::WebSocketClient;
use crate::http_auth::caller::with_caller;
use crate::http_auth::managed::client::{
    HttpTaskInputTransport, TaskInputTransport, resolve_snapshot_with_transport,
};
use crate::http_auth::managed::tasks::driver::{
    DriverState, ManagedTaskDriverError, ManagedTaskDriverPolicy,
};
use crate::http_auth::managed::tasks::watch::checkpoint::resume::timestamp_nanos;
#[cfg(unix)]
use crate::Client;
use crate::{
    FinalTask, FinalTaskHandle, FinalTaskId, FinalTaskInputResponses, FinalUpdateTaskResult,
    FinalTaskWatchEvent, HttpClient, HttpClientError, MemoryClient, MemorySubscriptionEvent,
    MemorySubscriptionExecution, RequestId, StdioTaskSubscriptionEvent, SubscriptionFilter,
    SubscriptionTimeoutPolicy, TaskInputLedger, task_subscription_ids,
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
            || timeout > Duration::from_hours(24)
            || !(1..=4096).contains(&maximum_polls)
            || fallback_poll_interval.is_zero()
            || fallback_poll_interval > Duration::from_mins(5)
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
    /// The caller's effective context supplied no usable timer driver.
    TimerUnavailable,
}

/// Bounds an opt-in automatic Task workflow and its retained input ledger.
///
/// The wait policy covers each complete invocation, including callbacks,
/// updates, reconciliation and poll delays. Update limits apply per invocation;
/// input-key and fingerprint-byte limits apply for the driver's entire life.
/// Fingerprints are never evicted. Payload bytes bound the encoded descriptors
/// plus keyed answers in each callback batch, not allocator overhead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalTaskDrivePolicy {
    wait: FinalTaskWaitPolicy,
    maximum_updates: usize,
    maximum_input_keys: usize,
    maximum_state_bytes: usize,
    maximum_payload_bytes: usize,
    maximum_notifications: usize,
}

impl Default for FinalTaskDrivePolicy {
    fn default() -> Self {
        Self {
            wait: FinalTaskWaitPolicy::default(),
            maximum_updates: 32,
            maximum_input_keys: 256,
            maximum_state_bytes: 1024 * 1024,
            maximum_payload_bytes: 8 * 1024 * 1024,
            maximum_notifications: 4096,
        }
    }
}

impl FinalTaskDrivePolicy {
    /// Allows 0..=128 updates per invocation, 1..=4,096 lifetime input keys,
    /// 1..=4 MiB of ledger bytes and 1..=8 MiB of payload per input batch.
    /// Zero updates makes the driver stop at input-required without callbacks.
    pub fn new(
        wait: FinalTaskWaitPolicy,
        maximum_updates: usize,
        maximum_input_keys: usize,
        maximum_state_bytes: usize,
        maximum_payload_bytes: usize,
    ) -> McpResult<Self> {
        if maximum_updates > 128
            || !(1..=4096).contains(&maximum_input_keys)
            || !(1..=4 * 1024 * 1024).contains(&maximum_state_bytes)
            || !(1..=8 * 1024 * 1024).contains(&maximum_payload_bytes)
        {
            return Err(McpError::invalid_params("Invalid final Task drive policy"));
        }
        Ok(Self {
            wait,
            maximum_updates,
            maximum_input_keys,
            maximum_state_bytes,
            maximum_payload_bytes,
            maximum_notifications: 4096,
        })
    }

    /// Bounds admitted Task notifications in one subscription-assisted drive.
    ///
    /// The default is 4,096; 1..=65,536 are accepted. Repeated snapshots also
    /// consume this budget, so a peer cannot keep a drive busy indefinitely by
    /// repeating already answered input. Exhaustion returns a request error
    /// and closes only this invocation's listener. Poll-only driving does not
    /// consume this budget.
    pub fn with_maximum_notifications(mut self, maximum: usize) -> McpResult<Self> {
        if !(1..=65_536).contains(&maximum) {
            return Err(McpError::invalid_params(
                "Invalid final Task notification budget",
            ));
        }
        self.maximum_notifications = maximum;
        Ok(self)
    }

    fn ledger_policy(self) -> ManagedTaskDriverPolicy {
        ManagedTaskDriverPolicy {
            minimum_poll_interval: self.wait.fallback_poll_interval,
            timeout: self.wait.timeout,
            maximum_polls: self.wait.maximum_polls,
            maximum_updates: self.maximum_updates,
            maximum_input_keys: self.maximum_input_keys,
            maximum_state_bytes: self.maximum_state_bytes,
        }
    }
}

/// A reusable, caller-owned automatic workflow for one existing final Task.
///
/// Create it with [`FinalTaskHandle::into_driver`], then use the same client
/// that attached the handle. Driving explicitly authorizes that client's
/// installed roots, sampling and elicitation callbacks, followed by updates
/// and authoritative reads until completion or a local bound. No worker,
/// runtime, reconnect, Task creation or remote cancellation is implicit.
///
/// This owner is deliberately not `Clone`. Acknowledged input fingerprints
/// survive repeated snapshots and subsequent drive calls; the same key cannot
/// trigger another callback, and a changed descriptor for that key is an
/// error. The finite lifetime ledger is never silently reset or evicted.
/// Descriptor fingerprints preserve their serialized representation.
///
/// If a callback or update is interrupted, fails, or loses its acknowledgement,
/// the owner retains an interruption latch. Further automatic driving refuses
/// before another effect rather than guessing whether the Host or peer acted.
/// Inspect [`Self::input_resolution_interrupted`] and explicitly hand off to
/// manual reconciliation with [`Self::into_handle`]. This is in-process
/// custody, not persistence or a crash-recovery/exactly-once guarantee.
pub struct FinalTaskDriver {
    handle: FinalTaskHandle,
    policy: FinalTaskDrivePolicy,
    inputs: DriverState,
    input_resolution_interrupted: bool,
    // A listen gap, changed freshness hint or acknowledged update must not
    // authorize another callback before an authoritative read, even if this
    // invocation is dropped and the next invocation uses polling instead.
    reconcile_before_input: bool,
}

impl FinalTaskDriver {
    /// The last fully admitted authoritative snapshot, including exact terminal
    /// result data. An update acknowledgement alone never changes this snapshot.
    #[must_use]
    pub const fn task(&self) -> &FinalTask {
        self.handle.task()
    }

    #[must_use]
    pub fn task_id(&self) -> &FinalTaskId {
        self.handle.task_id()
    }

    /// True means automatic input custody was interrupted and cannot be retried
    /// safely. A read-only cancellation between input batches does not set it.
    #[must_use]
    pub const fn input_resolution_interrupted(&self) -> bool {
        self.input_resolution_interrupted
    }

    /// Explicitly hands the retained Task back to manual control. This consumes
    /// the automatic owner and discards its input fingerprints and interruption
    /// latch. Creating another driver is a new disclosure decision: reconcile
    /// uncertain Host and peer effects first; a new owner cannot deduplicate
    /// the old owner's input keys.
    #[must_use]
    pub fn into_handle(self) -> FinalTaskHandle {
        self.handle
    }

    /// Drives over the native HTTP client's existing connection and allocator.
    /// The original invocation deadline covers callbacks, update ACKs and all
    /// subsequent reads. A new invocation starts a new local observation budget
    /// while preserving this owner's input ledger and interruption latch.
    /// Update/key/byte exhaustion and changed descriptors return sanitized
    /// request errors; local wait bounds return [`FinalTaskWaitOutcome`].
    pub async fn drive(
        &mut self,
        cx: &Cx,
        client: &mut HttpClient,
        cancellation: &McpRequestCancellation,
    ) -> Result<FinalTaskWaitOutcome, HttpClientError> {
        drive_task(
            self,
            cx,
            &mut HttpTaskInputTransport::native(client),
            cancellation,
        )
        .await
    }

    /// Drives through the existing stdio dispatcher and installed callbacks.
    /// It creates no competing reader or callback task.
    #[cfg(unix)]
    pub async fn drive_with_stdio(
        &mut self,
        cx: &Cx,
        client: &mut Client,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<FinalTaskWaitOutcome> {
        drive_task(self, cx, client, cancellation).await
    }

    /// Drives through the existing Memory dispatcher and installed callbacks.
    /// Unrelated in-flight requests retain their own dispatcher custody.
    pub async fn drive_with_memory(
        &mut self,
        cx: &Cx,
        client: &mut MemoryClient,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<FinalTaskWaitOutcome> {
        drive_task(self, cx, client, cancellation).await
    }

    /// Drives with a native HTTP Task subscription and bounded reconciliation.
    ///
    /// Notifications can deliver input or completion before the next poll.
    /// Authoritative reads still cover the attach/listen acknowledgement gap,
    /// each input update, ambiguous timestamps and silent streams. Every read
    /// respects the latest `pollIntervalMs`, or the configured fallback when
    /// absent. Reads, callbacks and stream waits share the original invocation
    /// deadline, retention bound, poll limit and lifetime input ledger.
    ///
    /// An empty accepted filter or a normal subscription completion/cancellation
    /// retires this listener and continues with bounded polling. It never opens
    /// a replacement subscription or repeats an uncertain update. Malformed or
    /// interrupted streams return their transport error; use the retained
    /// snapshot and interruption latch to decide an explicit next action.
    pub async fn drive_watching(
        &mut self,
        cx: &Cx,
        client: &mut HttpClient,
        cancellation: &McpRequestCancellation,
        limits: crate::sse::SseLimits,
    ) -> Result<FinalTaskWaitOutcome, HttpClientError> {
        drive_task_watching(
            self,
            cx,
            &mut HttpTaskInputTransport::native(client),
            cancellation,
            limits,
        )
        .await
    }

    /// Drives with an independently owned Memory Task subscription.
    ///
    /// This has the same bounded fallback and input-custody rules as
    /// [`Self::drive_watching`]. The existing Memory dispatcher owns all ingress;
    /// ordinary requests and other listeners keep their independent custody.
    /// Dropping or cancelling this future retires only its own listener and
    /// any input operation currently owned by this driver.
    pub async fn drive_watching_with_memory(
        &mut self,
        cx: &Cx,
        client: &mut MemoryClient,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<FinalTaskWaitOutcome> {
        drive_task_watching(self, cx, client, cancellation, ()).await
    }

    /// Drives with the existing Unix stdio Task subscription and input handlers.
    ///
    /// Notifications and authoritative reads share the sole connection reader.
    /// A polling deadline preserves partial ingress before the read is issued;
    /// no competing receive loop or background task is created. The original
    /// invocation bounds, input ledger and fallback rules are the same as
    /// [`Self::drive_watching`]. An already-active Task listener is left intact
    /// and causes this operation to fail before opening another one.
    ///
    /// During ordinary observation, cancellation or drop retires only this
    /// operation's listener and any currently owned input operation. Catalog
    /// listeners and other requests remain live; deferred cancellation is
    /// flushed by the next client turn. Transport failures retain their normal
    /// connection-failure semantics.
    #[cfg(unix)]
    pub async fn drive_watching_with_stdio(
        &mut self,
        cx: &Cx,
        client: &mut Client,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<FinalTaskWaitOutcome> {
        Box::pin(drive_task_watching(self, cx, client, cancellation, ())).await
    }

    /// Drives with the negotiated WebSocket Task subscription and input handlers.
    ///
    /// Partial frames remain on the existing connection when a due poll takes
    /// over from a stream wait. Notifications can deliver input and completion
    /// before that poll, under the same reconciliation, input-custody and
    /// bounded fallback policy as [`Self::drive_watching`]. This does not open
    /// another Task listener when one is already live, reconnect, or cancel the
    /// remote Task. Clean observation cancellation and drop retire the exact
    /// listen owner. An uncertain interrupted write still follows the existing
    /// connection-failure rules because its frame cannot safely be replayed.
    #[cfg(feature = "websocket-experimental")]
    pub async fn drive_watching_with_websocket<IO>(
        &mut self,
        cx: &Cx,
        client: &mut WebSocketClient<IO>,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<FinalTaskWaitOutcome>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Box::pin(drive_task_watching(self, cx, client, cancellation, ())).await
    }

    /// Drives through the negotiated WebSocket dispatcher and callbacks.
    #[cfg(feature = "websocket-experimental")]
    pub async fn drive_with_websocket<IO>(
        &mut self,
        cx: &Cx,
        client: &mut WebSocketClient<IO>,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<FinalTaskWaitOutcome>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        drive_task(self, cx, client, cancellation).await
    }
}

impl FinalTaskHandle {
    /// Transfers this handle into a reusable automatic input workflow.
    /// Existing `wait`, `poll` and manual input methods remain observation or
    /// explicit submission operations; only driving this new owner invokes
    /// installed Host callbacks automatically.
    #[must_use]
    pub fn into_driver(self, policy: FinalTaskDrivePolicy) -> FinalTaskDriver {
        FinalTaskDriver {
            handle: self,
            policy,
            inputs: DriverState::default(),
            input_resolution_interrupted: false,
            reconcile_before_input: false,
        }
    }

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

    /// Observes this Task through the caller-owned in-process client.
    ///
    /// The same finite wait, poll-count, peer minimum-interval, and retention
    /// bounds apply as for [`Self::wait`]. The existing Memory request owner
    /// handles each read, including channel backpressure and sibling responses.
    /// Cancelling or dropping observation retires only the in-flight read; it
    /// neither cancels the remote Task nor repeats an uncertain request.
    /// Use the client that attached this handle. No runtime is constructed.
    pub async fn wait_with_memory(
        &mut self,
        cx: &Cx,
        client: &mut MemoryClient,
        cancellation: &McpRequestCancellation,
        policy: FinalTaskWaitPolicy,
    ) -> McpResult<FinalTaskWaitOutcome> {
        wait_for_task(self, cx, client, cancellation, policy).await
    }

    /// Reconciles this handle through one negotiated Memory `tasks/get`.
    ///
    /// The exact Task ID and creation instant must match before replacing the
    /// retained snapshot. A failed, cancelled, or abandoned read leaves it
    /// unchanged. Already delivered terminal results return without I/O.
    /// Call this explicitly after an acknowledged input update to learn the
    /// resulting state before waiting again.
    pub async fn poll_with_memory(
        &mut self,
        cx: &Cx,
        client: &mut MemoryClient,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<&FinalTask> {
        if self.is_terminal() {
            return Ok(&self.task);
        }
        checkpoint_task_operation(cx, cancellation)?;
        let result = client
            .get_task_final(cx, cancellation, self.task_id().clone())
            .await?;
        admit_identity(self.task(), &result.task)?;
        checkpoint_task_operation(cx, cancellation)?;
        self.task = result.task;
        Ok(&self.task)
    }

    /// Supplies one explicit input batch through the in-process client.
    ///
    /// The retained phase, input descriptors, and finite retention are admitted
    /// before publication. The empty acknowledgement leaves this handle's
    /// snapshot unchanged; use [`Self::poll_with_memory`] to reconcile it.
    /// No input callback or retry runs implicitly. Cancellation or abandonment
    /// cannot undo an update already sent, so reconcile before resubmission.
    pub async fn resume_input_with_memory(
        &mut self,
        cx: &Cx,
        client: &mut MemoryClient,
        cancellation: &McpRequestCancellation,
        input_responses: FinalTaskInputResponses,
    ) -> McpResult<FinalUpdateTaskResult> {
        client
            .update_task_final(cx, cancellation, &self.task, input_responses)
            .await
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
        let caller = with_caller(cx, || Cx::current().expect("Task operation caller is installed"));
        let cx = &caller;
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
        let caller = with_caller(cx, || Cx::current().expect("Task operation caller is installed"));
        let cx = &caller;
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

    /// Watches this Task through an independently owned Memory subscription.
    ///
    /// The existing connection driver admits acknowledgements and exact Task
    /// snapshots while retaining unrelated request and subscription events.
    /// Equal or regressed conflicting snapshots cause one authoritative read;
    /// neither polling nor input callbacks run otherwise. The default listen
    /// lifetime is tightened by the caller deadline and live Task retention.
    ///
    /// Dropping an event wait preserves its subscription. Dropping the watch
    /// retires only its listen request and defers the id-only cancellation
    /// control to the next client operation. Remote Tasks are never cancelled
    /// implicitly, and no runtime or competing ingress reader is constructed.
    pub async fn watch_with_memory<'client, 'handle>(
        &'handle mut self,
        cx: &Cx,
        client: &'client mut MemoryClient,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<
        FinalTaskStreamWatch<'client, 'handle, MemoryClient, MemorySubscriptionExecution>,
    > {
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

/// A caller-driven Task watch on a retained Memory, stdio or WebSocket connection.
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
/// The opening caller retains ownership of the watch's clock, cancellation,
/// deadline and effect ceiling. A later event waiter may further restrict
/// effects or stop observation, but cannot replace that original authority.
pub struct FinalTaskStreamWatch<'client, 'handle, T, O = RequestId> {
    handle: &'handle mut FinalTaskHandle,
    client: &'client mut T,
    owner: Option<O>,
    caller: Option<TaskWatchCaller>,
    budget: Option<WaitBudget>,
    observing: bool,
    stop_reason: Option<FinalTaskWaitOutcome>,
    abandon: fn(&mut T, O),
}

struct TaskWatchCaller {
    cx: Cx,
    cancellation: McpRequestCancellation,
}

impl<T, O> FinalTaskStreamWatch<'_, '_, T, O> {
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

impl<T, O> Drop for FinalTaskStreamWatch<'_, '_, T, O> {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            (self.abandon)(self.client, owner);
        }
    }
}

impl FinalTaskStreamWatch<'_, '_, MemoryClient, MemorySubscriptionExecution> {
    /// Receives one acknowledged, changed or authoritatively reconciled Task.
    ///
    /// Exact repeats are skipped. A conflicting freshness hint causes one
    /// bounded read through the same Memory client. Cancellation, deadline or
    /// retention expiry preserves the latest admitted snapshot and returns
    /// `None` with a typed [`Self::stop_reason`]. A terminal Task is yielded
    /// once before its independent listener is retired.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<Option<FinalTaskWatchEvent>> {
        next_task_stream_event(self, cx, cancellation).await
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
        Box::pin(next_task_stream_event(self, cx, cancellation)).await
    }
}

trait TaskWatchTransport: TaskWaitTransport<Error = McpError> {
    type Owner;

    fn watch_timeout(&self) -> Duration;
    fn live_watch_id(&self) -> Option<RequestId>;
    async fn open_watch(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        filter: SubscriptionFilter,
        owner: &mut Option<Self::Owner>,
    ) -> McpResult<()>;
    async fn next_watch_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        owner: &mut Self::Owner,
    ) -> McpResult<StdioTaskSubscriptionEvent>;
    async fn cancel_watch(&mut self, cx: &Cx, owner: &mut Self::Owner) -> McpResult<()>;
    fn abandon_watch(&mut self, owner: Self::Owner);
}

impl TaskWatchTransport for MemoryClient {
    type Owner = MemorySubscriptionExecution;

    fn watch_timeout(&self) -> Duration {
        SubscriptionTimeoutPolicy::default().absolute_timeout()
    }

    fn live_watch_id(&self) -> Option<RequestId> {
        // Memory subscriptions are owned independently by their handles; an
        // unrelated live listener never reserves a singleton Tasks slot.
        None
    }

    async fn open_watch(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        filter: SubscriptionFilter,
        owner: &mut Option<Self::Owner>,
    ) -> McpResult<()> {
        *owner = Some(self.subscribe(cx, cancellation, filter).await?);
        Ok(())
    }

    async fn next_watch_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        owner: &mut Self::Owner,
    ) -> McpResult<StdioTaskSubscriptionEvent> {
        match self.next_subscription_event(cx, cancellation, owner).await? {
            Some(MemorySubscriptionEvent::Acknowledged { accepted, .. }) => {
                Ok(StdioTaskSubscriptionEvent::Acknowledged(accepted))
            }
            Some(MemorySubscriptionEvent::Task(notification)) => {
                Ok(StdioTaskSubscriptionEvent::Notification(*notification))
            }
            Some(MemorySubscriptionEvent::Terminal) | None => {
                Ok(StdioTaskSubscriptionEvent::Terminal)
            }
            Some(MemorySubscriptionEvent::Notification(_)) => Err(McpError::invalid_request(
                "Final Task watch received an unrequested core notification",
            )),
        }
    }

    fn cancel_watch(
        &mut self,
        cx: &Cx,
        owner: &mut Self::Owner,
    ) -> impl std::future::Future<Output = McpResult<()>> {
        std::future::ready(self.cancel_subscription(cx, owner))
    }

    fn abandon_watch(&mut self, owner: Self::Owner) {
        drop(owner);
    }
}

#[cfg(unix)]
impl TaskWatchTransport for Client {
    type Owner = RequestId;

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
        owner: &mut Option<Self::Owner>,
    ) -> McpResult<()> {
        let result = self
            .open_final_task_subscription_listener_with_cx(cx, cancellation, filter)
            .await;
        *owner = self.live_watch_id();
        result
    }

    async fn next_watch_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        _owner: &mut Self::Owner,
    ) -> McpResult<StdioTaskSubscriptionEvent> {
        self.next_final_task_subscription_event_with_cx(cx, cancellation)
            .await
    }

    fn cancel_watch(
        &mut self,
        _cx: &Cx,
        request_id: &mut Self::Owner,
    ) -> impl std::future::Future<Output = McpResult<()>> {
        let result = if self
            .live_watch_id()
            .is_some_and(|owned| owned.correlates_with(request_id))
        {
            self.cancel_live_final_task_subscription(&self.cx.clone())
        } else {
            Ok(())
        };
        std::future::ready(result)
    }

    fn abandon_watch(&mut self, request_id: Self::Owner) {
        if self
            .live_watch_id()
            .is_some_and(|owned| owned.correlates_with(&request_id))
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
    type Owner = RequestId;

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
        owner: &mut Option<Self::Owner>,
    ) -> McpResult<()> {
        let result = self.open_final_task_subscription_listener(cx, filter).await;
        *owner = self.live_watch_id();
        result
    }

    async fn next_watch_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        _owner: &mut Self::Owner,
    ) -> McpResult<StdioTaskSubscriptionEvent> {
        self.next_final_task_subscription_event(cx, cancellation)
            .await
    }

    async fn cancel_watch(&mut self, _cx: &Cx, request_id: &mut Self::Owner) -> McpResult<()> {
        if self
            .live_task_subscription
            .as_ref()
            .is_some_and(|subscription| subscription.request_id.correlates_with(request_id))
        {
            self.cancel_live_task_subscription().await?;
        }
        Ok(())
    }

    fn abandon_watch(&mut self, request_id: Self::Owner) {
        if let Some(subscription) = self.live_task_subscription.as_mut()
            && subscription.request_id.correlates_with(&request_id)
        {
            // The next connection operation owns the bounded cancellation
            // write. Keep its exact slot rather than creating a new queue.
            subscription.abandoned = true;
        }
    }
}

async fn open_task_stream_watch<'client, 'handle, T: TaskWatchTransport>(
    handle: &'handle mut FinalTaskHandle,
    cx: &Cx,
    client: &'client mut T,
    cancellation: &McpRequestCancellation,
) -> McpResult<FinalTaskStreamWatch<'client, 'handle, T, T::Owner>> {
    let terminal = handle.is_terminal();
    let mut watch = FinalTaskStreamWatch {
        stop_reason: terminal.then(|| ready_outcome(handle.task())).flatten(),
        handle,
        client,
        owner: None,
        caller: None,
        budget: None,
        observing: false,
        abandon: T::abandon_watch,
    };
    if terminal {
        return Ok(watch);
    }
    let caller = with_caller(cx, || Cx::current().expect("Task watch caller is installed"));
    let cx = &caller;
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
            watch
                .client
                .open_watch(cx, cancellation, filter, &mut watch.owner),
        )
        .await;
    // Each adapter stores its exact owner before the open future returns.
    // The guard can then select cancellation immediately after publication
    // without losing ownership of the newly committed listen request.
    match opened {
        Ok(result) => result?,
        Err(reason) => {
            watch.stop_reason = Some(reason);
            stop_task_stream_watch(&mut watch, cx).await?;
            return Ok(watch);
        }
    }
    if watch.owner.is_none() {
        return Err(McpError::internal_error(
            "Final Task watch lost its listen owner",
        ));
    }
    watch.budget = Some(budget);
    watch.caller = Some(TaskWatchCaller {
        cx: caller,
        cancellation: cancellation.clone(),
    });
    watch.observing = true;
    Ok(watch)
}

async fn stop_task_stream_watch<T: TaskWatchTransport>(
    watch: &mut FinalTaskStreamWatch<'_, '_, T, T::Owner>,
    cx: &Cx,
) -> McpResult<()> {
    if let Some(owner) = watch.owner.as_mut() {
        watch.client.cancel_watch(cx, owner).await?;
        watch.owner = None;
    }
    Ok(())
}

async fn next_task_stream_event<T: TaskWatchTransport>(
    watch: &mut FinalTaskStreamWatch<'_, '_, T, T::Owner>,
    cx: &Cx,
    cancellation: &McpRequestCancellation,
) -> McpResult<Option<FinalTaskWatchEvent>> {
    if !watch.observing {
        if watch.owner.is_some() {
            let caller = watch
                .caller
                .as_ref()
                .map_or_else(|| cx.clone(), |origin| origin.cx.clone());
            stop_task_stream_watch(watch, &caller).await?;
        }
        return Ok(None);
    }
    let waiter = with_caller(cx, || {
        Cx::current().expect("Task watch waiter is installed")
    });
    let origin = watch.caller.as_ref().expect("a live watch has a caller");
    // The deadline in WaitBudget belongs to this clock domain. Capture only
    // the waiter's effect ceiling; neither its identity nor its timer may
    // replace the opening caller during ingress or reconciliation.
    let caller = with_caller(&waiter, || {
        with_caller(&origin.cx, || {
            Cx::current().expect("Task watch caller is installed")
        })
    });
    let origin_cancellation = origin.cancellation.clone();
    let result = guard_task_watch_waiter(
        &waiter,
        cancellation,
        next_task_stream_event_inner(watch, &caller, &origin_cancellation, &waiter, cancellation),
    )
    .await;
    let result = match result {
        Ok(result) => result,
        Err(reason) => {
            watch.stop_reason = Some(reason);
            watch.observing = false;
            Ok(None)
        }
    };
    if result.is_err() {
        watch.observing = false;
    }
    if !watch.observing {
        stop_task_stream_watch(watch, &caller).await?;
    }
    result
}

/// A waiter has its own cancellation and clock domain. Its checkpoints may
/// shorten observation, while the inner watch keeps the opening caller's
/// absolute lifetime and timer driver. A waiter timer is polled only under
/// that waiter's context; no absolute timestamp crosses between runtimes.
async fn guard_task_watch_waiter<T>(
    waiter: &Cx,
    cancellation: &McpRequestCancellation,
    operation: impl Future<Output = T>,
) -> Result<T, FinalTaskWaitOutcome> {
    let delay = || {
        let checkpoint_slice = Duration::from_millis(20);
        waiter
            .budget()
            .deadline
            .map_or(checkpoint_slice, |deadline| {
                checkpoint_slice.min(Duration::from_nanos(deadline.duration_since(waiter.now())))
            })
    };
    let mut operation = std::pin::pin!(operation);
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    let mut wake = Box::pin(asupersync::time::sleep(waiter.now(), delay()));
    std::future::poll_fn(|task_cx| {
        with_caller(waiter, || {
            if let Some(reason) = task_watch_waiter_stop(waiter, cancellation) {
                return Poll::Ready(Err(reason));
            }
            if cancelled.as_mut().poll(task_cx).is_ready() {
                return Poll::Ready(Err(FinalTaskWaitOutcome::ObservationCancelled));
            }
            if Cx::current()
                .expect("Task watch waiter is installed")
                .timer_driver()
                .is_none()
            {
                return Poll::Ready(Err(FinalTaskWaitOutcome::TimerUnavailable));
            }
            if let Poll::Ready(result) = operation.as_mut().poll(task_cx) {
                // The inner operation checks the waiter before committing a
                // snapshot. Once committed, its event must remain observable
                // even if the waiter is cancelled during that same poll.
                return Poll::Ready(Ok(result));
            }
            if let Some(reason) = task_watch_waiter_stop(waiter, cancellation) {
                return Poll::Ready(Err(reason));
            }
            if wake.as_mut().poll(task_cx).is_ready() {
                wake.set(asupersync::time::sleep(waiter.now(), delay()));
                task_cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
    })
    .await
}

fn task_watch_waiter_stop(
    waiter: &Cx,
    cancellation: &McpRequestCancellation,
) -> Option<FinalTaskWaitOutcome> {
    if cancellation.is_cancel_requested() {
        Some(FinalTaskWaitOutcome::ObservationCancelled)
    } else if waiter
        .budget()
        .deadline
        .is_some_and(|deadline| waiter.now() >= deadline)
    {
        Some(FinalTaskWaitOutcome::DeadlineElapsed)
    } else if waiter.checkpoint().is_err() {
        Some(FinalTaskWaitOutcome::ObservationCancelled)
    } else {
        None
    }
}

async fn next_task_stream_event_inner<T: TaskWatchTransport>(
    watch: &mut FinalTaskStreamWatch<'_, '_, T, T::Owner>,
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    waiter: &Cx,
    waiter_cancellation: &McpRequestCancellation,
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
                watch.client.next_watch_event(
                    cx,
                    cancellation,
                    watch.owner.as_mut().expect("a live watch has an owner"),
                ),
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
        if let Some(reason) = task_watch_waiter_stop(waiter, waiter_cancellation) {
            watch.stop_reason = Some(reason);
            watch.observing = false;
            return Ok(None);
        }
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
                if let Some(reason) = task_watch_waiter_stop(waiter, waiter_cancellation) {
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
                watch.owner = None;
                return Ok(None);
            }
        }
    }
}

fn task_watch_comparison_error(error: HttpClientError) -> McpError {
    match error {
        HttpClientError::CoreResult(error) => error,
        _ => McpError::internal_error("Final Task snapshot comparison failed"),
    }
}

impl MemoryClient {
    /// Attaches an existing Task through one negotiated in-process read.
    ///
    /// The returned handle can poll, wait, and submit explicit input using this
    /// same client. Attachment never repeats a creating call, starts background
    /// observation, or claims persistence across a process restart.
    pub async fn attach_final_task(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> McpResult<FinalTaskHandle> {
        self.get_task_final(cx, cancellation, task_id)
            .await
            .map(|result| FinalTaskHandle::new(result.task))
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
        let caller = with_caller(cx, || Cx::current().expect("Task operation caller is installed"));
        let cx = &caller;
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
    let caller = with_caller(cx, || Cx::current().expect("Task operation caller is installed"));
    let cx = &caller;
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
        with_caller(cx, || {
            if let Err(error) = checkpoint_task_operation(cx, cancellation) {
                return Poll::Ready(Err(error));
            }
            if cancelled.as_mut().poll(task_cx).is_ready() {
                return Poll::Ready(Err(McpError::request_cancelled()));
            }
            if !Cx::current()
                .expect("Task operation caller is installed")
                .capabilities()
                .time
            {
                return Poll::Ready(Err(McpError::internal_error(
                    "Final Task operation wait requires caller time capability",
                )));
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
    // `validate_responses` is a SHAPE check and documents that it ignores
    // unknown keys on purpose: a partial update may acknowledge a subset of
    // outstanding requests, and the server owns which keys stay live. That
    // tolerance is correct whenever at least one key matches, and it must be
    // preserved -- it has twenty call sites and pinned verdict tests.
    //
    // A NON-EMPTY map naming no outstanding key at all is the different case
    // it leaves open. Such a map can satisfy nothing, so admitting it spends a
    // round trip for a server-side `Ignored`, and the caller believed it was
    // answering something. `update_task_final` documents that phase and
    // response kinds are checked "before allocating an ID or publishing
    // bytes", so the refusal belongs here, in the client's local pre-flight,
    // rather than in the shared shape check or at the server.
    //
    // AN EMPTY MAP STAYS ADMITTED, and the distinction is load-bearing rather
    // than incidental. It is pinned by
    // managed_task_input_admission_preserves_partial_and_unknown_key_semantics
    // (http_auth/managed/client/tasks/tests.rs), which fixes three cases: `{}`
    // is admitted, a map mixing
    // one outstanding key with one unknown key is admitted, and a map naming
    // an outstanding key with the WRONG response kind is refused. An empty
    // map asserts nothing about any key, so it is a no-op acknowledgement;
    // only a non-empty map that answers nothing is a caller error. An earlier
    // revision of this guard omitted the emptiness test and broke that pinned
    // case, which is why the condition is spelled out here.
    if !input_responses.is_empty()
        && !input_responses
            .keys()
            .any(|key| input_requests.contains_key(key))
    {
        return Err(McpError::invalid_params(
            "Task input responses name no outstanding input request",
        ));
    }
    admit_input_retention(task)
}

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

impl TaskWaitTransport for MemoryClient {
    type Error = McpError;

    async fn read_task(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> McpResult<FinalTask> {
        self.get_task_final(cx, cancellation, task_id)
            .await
            .map(|result| result.task)
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
        let caller = with_caller(cx, || Cx::current().expect("Task wait caller is installed"));
        let cx = &caller;
        let mut operation = std::pin::pin!(operation);
        let mut cancelled = std::pin::pin!(cancellation.cancelled());
        let checkpoint_slice = Duration::from_millis(20);
        let mut wake = Box::pin(asupersync::time::sleep(
            cx.now(),
            self.remaining(cx).min(checkpoint_slice),
        ));
        std::future::poll_fn(|task_cx| {
            with_caller(cx, || {
                if let Some(reason) = self.stop(cx, cancellation) {
                    return Poll::Ready(Err(reason));
                }
                if cancelled.as_mut().poll(task_cx).is_ready() {
                    return Poll::Ready(Err(FinalTaskWaitOutcome::ObservationCancelled));
                }
                // The operation may itself be a Sleep. Refuse before polling
                // it when the effective caller cannot authorize its timer.
                if Cx::current()
                    .expect("Task wait caller is installed")
                    .timer_driver()
                    .is_none()
                {
                    return Poll::Ready(Err(FinalTaskWaitOutcome::TimerUnavailable));
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
        })
        .await
    }
}

fn drive_ledger_error(error: ManagedTaskDriverError) -> McpError {
    McpError::invalid_request(match error {
        ManagedTaskDriverError::InputLimit => "Final Task lifetime input-key budget exhausted",
        ManagedTaskDriverError::StateByteLimit => {
            "Final Task lifetime input-fingerprint byte budget exhausted"
        }
        ManagedTaskDriverError::InputKeyReused => {
            "Final Task reused an answered input key with a different descriptor"
        }
        _ => "Invalid final Task input fingerprint ledger",
    })
}

async fn resolve_driver_inputs<T: TaskInputTransport>(
    driver: &mut FinalTaskDriver,
    cx: &Cx,
    client: &mut T,
    cancellation: &McpRequestCancellation,
    budget: &WaitBudget,
    updates: &mut usize,
) -> Result<Option<FinalTaskWaitOutcome>, T::Error> {
    let FinalTask::InputRequired { input_requests, .. } = driver.task() else {
        return Ok(ready_outcome(driver.task()));
    };
    let policy = driver.policy;
    if policy.maximum_updates == 0 {
        return Ok(Some(FinalTaskWaitOutcome::InputRequired));
    }
    if driver.reconcile_before_input {
        return Ok(None);
    }
    let (unanswered, fingerprints) = driver
        .inputs
        .unanswered(input_requests, policy.ledger_policy())
        .map_err(drive_ledger_error)?;
    if unanswered.is_empty() {
        return Ok(None);
    }
    if *updates >= policy.maximum_updates {
        return Err(McpError::invalid_request("Final Task input-update budget exhausted").into());
    }
    let keys: Vec<_> = unanswered.keys().cloned().collect();
    // Reserve all ledger capacity before Host effects. No other borrower can
    // change this owner before the acknowledgement is recorded.
    driver
        .inputs
        .answer_bytes(&keys, &fingerprints, policy.maximum_state_bytes)
        .map_err(drive_ledger_error)?;
    let mut snapshot = driver.task().clone();
    let FinalTask::InputRequired { input_requests, .. } = &mut snapshot else {
        unreachable!("the current snapshot requires input");
    };
    *input_requests = unanswered;
    let interrupted = &mut driver.input_resolution_interrupted;
    let resolution = resolve_snapshot_with_transport(
        cx,
        cancellation,
        client,
        &snapshot,
        policy
            .maximum_input_keys
            .min(fastmcp_protocol::tasks_extension::MAX_TASK_INPUT_MAP_ENTRIES),
        policy.maximum_payload_bytes,
        || *interrupted = true,
    );
    match budget.guard(cx, cancellation, resolution).await {
        Ok(result) => {
            result?;
        }
        Err(outcome) => return Ok(Some(outcome)),
    }
    // This synchronous handoff is the only place that clears the latch.
    // Dropping either future before it runs retains uncertainty, including
    // a response lost after update dispatch. An ACK is never a new snapshot.
    driver
        .inputs
        .record_answers(&keys, &fingerprints, policy.maximum_state_bytes)
        .map_err(drive_ledger_error)?;
    driver.input_resolution_interrupted = false;
    driver.reconcile_before_input = true;
    *updates += 1;
    Ok(None)
}

/// Only transports whose event future retains partial ingress on its listener
/// may implement this trait. A poll timer may drop that future while retaining
/// the listener, then issue an authoritative read on the same client. The Unix
/// stdio slice reader and WebSocket receive half retain their partial frames
/// across that handoff; both continue using their sole connection dispatcher.
trait TaskDriveWatchTransport: TaskInputTransport {
    type Listener;
    type Options;

    async fn open_drive_watch(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        filter: SubscriptionFilter,
        options: Self::Options,
        listener: &mut Option<Self::Listener>,
    ) -> Result<(), Self::Error>;

    async fn next_drive_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        listener: &mut Self::Listener,
    ) -> Result<StdioTaskSubscriptionEvent, Self::Error>;

    fn abandon_drive_watch(&mut self, listener: Self::Listener);
}

impl TaskDriveWatchTransport for MemoryClient {
    type Listener = MemorySubscriptionExecution;
    type Options = ();

    async fn open_drive_watch(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        filter: SubscriptionFilter,
        (): (),
        listener: &mut Option<Self::Listener>,
    ) -> McpResult<()> {
        *listener = Some(self.subscribe(cx, cancellation, filter).await?);
        Ok(())
    }

    async fn next_drive_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        listener: &mut Self::Listener,
    ) -> McpResult<StdioTaskSubscriptionEvent> {
        TaskWatchTransport::next_watch_event(self, cx, cancellation, listener).await
    }

    fn abandon_drive_watch(&mut self, listener: Self::Listener) {
        drop(listener);
    }
}

#[cfg(unix)]
impl TaskDriveWatchTransport for Client {
    type Listener = RequestId;
    type Options = ();

    async fn open_drive_watch(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        filter: SubscriptionFilter,
        (): (),
        listener: &mut Option<Self::Listener>,
    ) -> McpResult<()> {
        if TaskWatchTransport::live_watch_id(self).is_some() {
            return Err(McpError::invalid_request(
                "A final Tasks stdio subscription is already active on this client",
            ));
        }
        TaskWatchTransport::open_watch(self, cx, cancellation, filter, listener).await
    }

    async fn next_drive_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        listener: &mut Self::Listener,
    ) -> McpResult<StdioTaskSubscriptionEvent> {
        TaskWatchTransport::next_watch_event(self, cx, cancellation, listener).await
    }

    fn abandon_drive_watch(&mut self, listener: Self::Listener) {
        TaskWatchTransport::abandon_watch(self, listener);
    }
}

#[cfg(feature = "websocket-experimental")]
impl<IO> TaskDriveWatchTransport for WebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Listener = RequestId;
    type Options = ();

    async fn open_drive_watch(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        filter: SubscriptionFilter,
        (): (),
        listener: &mut Option<Self::Listener>,
    ) -> McpResult<()> {
        if TaskWatchTransport::live_watch_id(self).is_some() {
            return Err(McpError::invalid_request(
                "A final Tasks WebSocket subscription is already active on this client",
            ));
        }
        TaskWatchTransport::open_watch(self, cx, cancellation, filter, listener).await
    }

    async fn next_drive_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        listener: &mut Self::Listener,
    ) -> McpResult<StdioTaskSubscriptionEvent> {
        TaskWatchTransport::next_watch_event(self, cx, cancellation, listener).await
    }

    fn abandon_drive_watch(&mut self, listener: Self::Listener) {
        TaskWatchTransport::abandon_watch(self, listener);
    }
}

impl TaskDriveWatchTransport for HttpTaskInputTransport<'_> {
    type Listener = crate::ModernHttpSubscriptionListener;
    type Options = crate::sse::SseLimits;

    async fn open_drive_watch(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        filter: SubscriptionFilter,
        limits: Self::Options,
        listener: &mut Option<Self::Listener>,
    ) -> Result<(), HttpClientError> {
        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            return Err(McpError::request_cancelled().into());
        }
        *listener = Some(self.client_mut()
            .open_final_task_watch_listener(cx, filter, limits)
            .await?);
        Ok(())
    }

    async fn next_drive_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        listener: &mut Self::Listener,
    ) -> Result<StdioTaskSubscriptionEvent, HttpClientError> {
        use crate::ModernHttpSubscriptionListenEvent as Event;

        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            return Err(McpError::request_cancelled().into());
        }
        let event = listener.next_event(cx).await.map_err(|error| {
            HttpClientError::Connection(crate::ClientHttpConnectionError::SubscriptionsListen(error))
        })?;
        match event {
            Some(Event::Acknowledged { accepted_filter }) => {
                Ok(StdioTaskSubscriptionEvent::Acknowledged(accepted_filter))
            }
            Some(Event::TaskNotification(notification)) => {
                Ok(StdioTaskSubscriptionEvent::Notification(notification))
            }
            Some(Event::Terminal { .. } | Event::Cancelled { .. }) | None => {
                Ok(StdioTaskSubscriptionEvent::Terminal)
            }
            Some(Event::Notification(_)) => Err(McpError::invalid_request(
                "Final Task watch received an unrequested core notification",
            )
            .into()),
        }
    }

    fn abandon_drive_watch(&mut self, mut listener: Self::Listener) {
        listener.cancel();
    }
}

struct TaskDriveWatch<'client, T: TaskDriveWatchTransport> {
    client: &'client mut T,
    listener: Option<T::Listener>,
}

impl<T: TaskDriveWatchTransport> TaskDriveWatch<'_, T> {
    fn retire(&mut self) {
        if let Some(listener) = self.listener.take() {
            self.client.abandon_drive_watch(listener);
        }
    }
}

impl<T: TaskDriveWatchTransport> Drop for TaskDriveWatch<'_, T> {
    fn drop(&mut self) {
        self.retire();
    }
}

/// Keep the complete peer suggestion without narrowing a large millisecond
/// value through the runtime's u64 nanosecond clock. Each actual timer is met
/// with the already bounded invocation budget before it is constructed.
struct TaskPollSchedule {
    wall_started: Instant,
    runtime_started: Time,
    delay: Duration,
}

impl TaskPollSchedule {
    fn new(cx: &Cx, task: &FinalTask, policy: FinalTaskWaitPolicy) -> McpResult<Self> {
        Ok(Self {
            wall_started: Instant::now(),
            runtime_started: cx.now(),
            delay: next_delay(task, policy)?,
        })
    }

    fn remaining(&self, cx: &Cx) -> Duration {
        let elapsed = self.wall_started.elapsed().max(Duration::from_nanos(
            cx.now().duration_since(self.runtime_started),
        ));
        self.delay.saturating_sub(elapsed)
    }
}

async fn next_drive_watch_step<T: TaskDriveWatchTransport>(
    watch: &mut TaskDriveWatch<'_, T>,
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    schedule: &TaskPollSchedule,
    budget: &WaitBudget,
) -> Result<Option<StdioTaskSubscriptionEvent>, T::Error> {
    let delay = schedule.remaining(cx).min(budget.remaining(cx));
    let mut timer = std::pin::pin!(asupersync::time::sleep(cx.now(), delay));
    let Some(listener) = watch.listener.as_mut() else {
        timer.await;
        return Ok(None);
    };
    let mut event = std::pin::pin!(watch.client.next_drive_event(cx, cancellation, listener));
    std::future::poll_fn(|task_cx| {
        // A stream of immediately ready duplicates cannot starve a due read.
        if timer.as_mut().poll(task_cx).is_ready() {
            return Poll::Ready(Ok(None));
        }
        event.as_mut().poll(task_cx).map(|result| result.map(Some))
    })
    .await
}

async fn drive_task_watching<T: TaskDriveWatchTransport>(
    driver: &mut FinalTaskDriver,
    cx: &Cx,
    client: &mut T,
    cancellation: &McpRequestCancellation,
    options: T::Options,
) -> Result<FinalTaskWaitOutcome, T::Error> {
    if let Some(outcome) = ready_outcome(driver.task())
        && outcome != FinalTaskWaitOutcome::InputRequired
    {
        return Ok(outcome);
    }
    let caller = with_caller(cx, || Cx::current().expect("Task drive caller is installed"));
    let cx = &caller;
    let policy = driver.policy;
    let mut budget = WaitBudget::new(cx, policy.wait.timeout, driver.task())?;
    if let Some(outcome) = budget.stop(cx, cancellation) {
        return Ok(outcome);
    }
    if driver.input_resolution_interrupted {
        return Err(McpError::invalid_request(
            "Final Task input resolution was interrupted; manual reconciliation is required",
        )
        .into());
    }
    if cx.timer_driver().is_none() {
        return Ok(FinalTaskWaitOutcome::TimerUnavailable);
    }

    let mut schedule = TaskPollSchedule::new(cx, driver.task(), policy.wait)?;
    let mut filter = SubscriptionFilter::default();
    fastmcp_protocol::set_task_subscription_ids(&mut filter, vec![driver.task_id().clone()])
        .map_err(|_| McpError::internal_error("Final Task watch filter could not be composed"))?;
    // This fact survives future drop and a later switch to poll-only driving.
    driver.reconcile_before_input = true;
    let mut watch = TaskDriveWatch { client, listener: None };
    match budget
        .guard(
            cx,
            cancellation,
            watch.client.open_drive_watch(
                cx, cancellation, filter, options, &mut watch.listener,
            ),
        )
        .await
    {
        Ok(result) => result?,
        Err(outcome) => return Ok(outcome),
    }
    // Publish the exact owner inside the guarded open future. A cancellation
    // selected immediately after a completed open must still let this guard
    // retire the newly installed singleton listener, rather than orphaning it.
    if watch.listener.is_none() {
        return Err(McpError::internal_error("Final Task drive lost its listen owner").into());
    }

    let mut polls = 0;
    let mut updates = 0;
    let mut notifications = 0;
    loop {
        if let Some(outcome) = budget.stop(cx, cancellation) {
            return Ok(outcome);
        }
        let previous_updates = updates;
        if let Some(outcome) = resolve_driver_inputs(
            driver, cx, watch.client, cancellation, &budget, &mut updates,
        )
        .await?
        {
            return Ok(outcome);
        }
        if updates != previous_updates {
            schedule = TaskPollSchedule::new(cx, driver.task(), policy.wait)?;
        }
        let event = match budget
            .guard(
                cx,
                cancellation,
                next_drive_watch_step(&mut watch, cx, cancellation, &schedule, &budget),
            )
            .await
        {
            Ok(result) => result?,
            Err(outcome) => return Ok(outcome),
        };
        match event {
            None => {
                if polls >= policy.wait.maximum_polls {
                    return Ok(FinalTaskWaitOutcome::PollLimitReached);
                }
                let task = match budget
                    .guard(
                        cx,
                        cancellation,
                        watch.client.read(cx, cancellation, driver.task_id().clone()),
                    )
                    .await
                {
                    Ok(result) => result?,
                    Err(outcome) => return Ok(outcome),
                };
                polls += 1;
                admit_identity(driver.task(), &task)?;
                budget.refresh_retention(cx, &task)?;
                if let Some(outcome) = budget.stop(cx, cancellation) {
                    return Ok(outcome);
                }
                driver.handle.task = task;
                driver.reconcile_before_input = false;
                schedule = TaskPollSchedule::new(cx, driver.task(), policy.wait)?;
            }
            Some(StdioTaskSubscriptionEvent::Acknowledged(accepted_filter)) => {
                let accepted = task_subscription_ids(&accepted_filter)
                    .map_err(|_| McpError::invalid_request("Invalid final Task watch acknowledgement"))?
                    .unwrap_or_default();
                if accepted.iter().any(|id| id != driver.task_id()) {
                    return Err(McpError::invalid_request(
                        "Final Task watch acknowledgement widened the requested Task filter",
                    )
                    .into());
                }
                // Even if a silent listener allowed an earlier read, reconcile
                // the gap ending at this acknowledgement before new callbacks.
                driver.reconcile_before_input = true;
                if accepted.is_empty() {
                    watch.retire();
                }
            }
            Some(StdioTaskSubscriptionEvent::Notification(notification)) => {
                if notifications >= policy.maximum_notifications {
                    return Err(McpError::invalid_request(
                        "Final Task subscription notification budget exhausted",
                    )
                    .into());
                }
                notifications += 1;
                let task = notification.params.task;
                admit_identity(driver.task(), &task)?;
                if driver.handle.snapshot_is_identical(&task).map_err(task_watch_comparison_error)? {
                    asupersync::runtime::yield_now().await;
                    continue;
                }
                if driver.handle.notification_needs_reconciliation(&task)
                    .map_err(task_watch_comparison_error)?
                {
                    driver.reconcile_before_input = true;
                    continue;
                }
                budget.refresh_retention(cx, &task)?;
                if let Some(outcome) = budget.stop(cx, cancellation) {
                    return Ok(outcome);
                }
                driver.handle.task = task;
                schedule = TaskPollSchedule::new(cx, driver.task(), policy.wait)?;
            }
            Some(StdioTaskSubscriptionEvent::Terminal) => {
                // Ending a subscription says nothing about the remote Task.
                // Retire once and continue under the same finite read budget.
                watch.retire();
                driver.reconcile_before_input = true;
            }
        }
    }
}

async fn drive_task<T: TaskInputTransport>(
    driver: &mut FinalTaskDriver,
    cx: &Cx,
    client: &mut T,
    cancellation: &McpRequestCancellation,
) -> Result<FinalTaskWaitOutcome, T::Error> {
    // Already delivered results remain inspectable even after local expiry.
    if let Some(outcome) = ready_outcome(driver.task())
        && outcome != FinalTaskWaitOutcome::InputRequired
    {
        return Ok(outcome);
    }
    let caller = with_caller(cx, || Cx::current().expect("Task drive caller is installed"));
    let cx = &caller;
    let policy = driver.policy;
    let mut budget = WaitBudget::new(cx, policy.wait.timeout, driver.task())?;
    if let Some(outcome) = budget.stop(cx, cancellation) {
        return Ok(outcome);
    }
    if driver.input_resolution_interrupted {
        return Err(McpError::invalid_request(
            "Final Task input resolution was interrupted; manual reconciliation is required",
        )
        .into());
    }
    if cx.timer_driver().is_none() {
        return Ok(FinalTaskWaitOutcome::TimerUnavailable);
    }

    let mut polls = 0;
    let mut updates = 0;
    loop {
        if let Some(outcome) = budget.stop(cx, cancellation) {
            return Ok(outcome);
        }
        if let Some(outcome) =
            resolve_driver_inputs(driver, cx, client, cancellation, &budget, &mut updates).await?
        {
            return Ok(outcome);
        }
        if polls >= policy.wait.maximum_polls {
            return Ok(FinalTaskWaitOutcome::PollLimitReached);
        }
        // Includes stale, already-acknowledged input snapshots: no busy loop,
        // duplicate callbacks, effectless updates, or shortened peer minimum.
        let delay = next_delay(driver.task(), policy.wait)?;
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
        let task = match budget
            .guard(
                cx,
                cancellation,
                client.read(cx, cancellation, driver.task_id().clone()),
            )
            .await
        {
            Ok(result) => result?,
            Err(outcome) => return Ok(outcome),
        };
        polls += 1;
        admit_identity(driver.task(), &task)?;
        if let Some(outcome) = budget.stop(cx, cancellation) {
            return Ok(outcome);
        }
        budget.refresh_retention(cx, &task)?;
        if let Some(outcome) = budget.stop(cx, cancellation) {
            return Ok(outcome);
        }
        driver.handle.task = task;
        driver.reconcile_before_input = false;
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
    // Retain the first poll's effect ceiling across delays and later reads.
    let caller = with_caller(cx, || Cx::current().expect("Task wait caller is installed"));
    let cx = &caller;
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

#[cfg(test)]
#[path = "task_watch_memory_tests.rs"]
mod memory_watch_tests;
