//! Connection dispatch driven entirely by the embedding's async task.
//!
//! The connection polls ingress independently of egress and request work. No
//! receive thread, blocking-pool pump, or nested runtime participates. Explicit
//! blocking handlers still require the caller's admitted blocking facility.

mod region;

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, Weak};
use std::task::Poll;

use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::sync::Notify;
use asupersync::time::Sleep;
use fastmcp_transport::memory::{MemoryRecvHalf, MemorySendHalf, MemoryTransport};
use fastmcp_transport::{
    AsyncStdioRecvHalf, AsyncStdioSendHalf, AsyncStdioTransport, ReceivedTransportFrame,
};

// This module is split out of lib.rs and shares its private items. The set
// it uses differs per feature profile, so an explicit list computed for one
// profile would break the others.
#[allow(
    clippy::wildcard_imports,
    reason = "split-out part of lib.rs; its parent-item set is feature-dependent"
)]
use super::*;

const DOCUMENT_BYTES: usize = 10 * 1024 * 1024;
const SUBSCRIPTION_LIFETIME: Duration = Duration::from_hours(1);
#[cfg(feature = "tasks")]
const TASK_SERVICE_HEALTH_INTERVAL: Duration = Duration::from_millis(100);

type RequestWork = Pin<Box<dyn Future<Output = McpResult<()>> + Send>>;
type ReadWork<R> =
    Pin<Box<dyn Future<Output = (R, Result<ReceivedTransportFrame, TransportError>)> + Send>>;
type WriteWork<W> = Pin<Box<dyn Future<Output = (W, Result<(), TransportError>, usize)> + Send>>;

/// Internal framing seam shared by native stdio, memory and WebSocket connections.
/// The read future remains owned until it completes or the connection stops.
trait ConnectionReader: Send + 'static {
    fn receive(
        &mut self,
        cx: &Cx,
    ) -> impl Future<Output = Result<ReceivedTransportFrame, TransportError>> + Send;
}

/// A dropped partial send must latch `is_closed`; cancellation before its
/// first byte may leave this independently owned writer usable.
trait ConnectionWriter: Send + 'static {
    fn send(
        &mut self,
        cx: &Cx,
        message: &JsonRpcMessage,
    ) -> impl Future<Output = Result<(), TransportError>> + Send;
    fn close(&mut self, cx: &Cx) -> impl Future<Output = Result<(), TransportError>> + Send;
    fn is_closed(&self) -> bool;
}

impl<R: AsyncRead + Unpin + Send + 'static> ConnectionReader for AsyncStdioRecvHalf<R> {
    async fn receive(&mut self, cx: &Cx) -> Result<ReceivedTransportFrame, TransportError> {
        self.recv_server_with_source_async(cx).await
    }
}

impl<W: AsyncWrite + Unpin + Send + 'static> ConnectionWriter for AsyncStdioSendHalf<W> {
    async fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        self.send_async(cx, message).await
    }
    async fn close(&mut self, cx: &Cx) -> Result<(), TransportError> {
        self.close_async(cx).await
    }
    fn is_closed(&self) -> bool {
        Self::is_closed(self)
    }
}

impl ConnectionReader for MemoryRecvHalf {
    async fn receive(&mut self, cx: &Cx) -> Result<ReceivedTransportFrame, TransportError> {
        // Keep the committed source, including raw parameter lexemes. A typed
        // receive followed by reserialization would bypass source accounting.
        self.recv_with_source_async(cx).await
    }
}

impl ConnectionWriter for MemorySendHalf {
    async fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        // A full bounded channel yields while ingress continues routing
        // cancellation. Publication is atomic; abandoning a pending send
        // neither publishes a partial frame nor poisons the next reservation.
        self.send_async(cx, message).await
    }
    // `TransportSendHalf::close` is genuinely synchronous (lib.rs:285), so this
    // impl has nothing to await, and the two clippy lints that notice that are
    // in direct conflict: as an `async fn` it draws `unused_async`, and in this
    // block form it draws `manual_async_fn`. One of them has to be allowed.
    // Allowing `manual_async_fn` is the one that works -- an item-level
    // `#[allow(clippy::unused_async)]` does NOT suppress the other direction on
    // a trait impl method (measured: clippy still reported it at this site with
    // the attribute directly above).
    //
    // Both forms are lazy, which is the property that actually matters here.
    // What is NOT acceptable is `std::future::ready(..)`, which the RPITIT
    // trait signature would also accept: that evaluates the close when the
    // future is CONSTRUCTED, so building one and dropping it without awaiting
    // would already have released the sender. Every other effect on this
    // transport is drop-safe by design and this one stays that way.
    #[allow(clippy::manual_async_fn)]
    fn close(&mut self, cx: &Cx) -> impl Future<Output = Result<(), TransportError>> + Send {
        async move {
            // Memory close only releases the sender; no blocking I/O.
            fastmcp_transport::TransportSendHalf::close(self, cx)
        }
    }
    fn is_closed(&self) -> bool {
        Self::is_closed(self)
    }
}

#[cfg(feature = "websocket")]
impl<IO: AsyncRead + AsyncWrite + Unpin + Send + 'static> ConnectionReader
    for fastmcp_transport::websocket::AsyncWsServerRecvHalf<IO>
{
    async fn receive(&mut self, cx: &Cx) -> Result<ReceivedTransportFrame, TransportError> {
        self.recv_with_source(cx).await
    }
}

#[cfg(feature = "websocket")]
impl<IO: AsyncRead + AsyncWrite + Unpin + Send + 'static> ConnectionWriter
    for fastmcp_transport::websocket::AsyncWsServerSendHalf<IO>
{
    async fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        Self::send(self, cx, message).await
    }
    async fn close(&mut self, cx: &Cx) -> Result<(), TransportError> {
        Self::close(self, cx).await
    }
    fn is_closed(&self) -> bool {
        Self::is_closed(self)
    }
}

struct ConnectionBinding {
    transport: InboundRequestTransport,
    authorization: TransportAuthorization,
    auth_custody: Option<AuthDispatchCustody>,
    auth_generation: Option<u64>,
}

impl ConnectionBinding {
    fn stdio() -> Self {
        Self {
            transport: InboundRequestTransport::Stdio,
            authorization: TransportAuthorization::default(),
            auth_custody: None,
            auth_generation: None,
        }
    }
}

/// The wire cancellation election is separate from the dispatcher's
/// finalization election. A completed handler can still have an uncommitted
/// result queued behind backpressure; peer cancellation must suppress it.
struct OutputOwner {
    reservation: ModernDispatchReservation,
    log_level: Option<LoggingLevel>,
    subscription_terminal: Option<Arc<FinalSubscriptionTerminalDelivery>>,
    #[cfg(feature = "legacy-2024-11-05")]
    legacy: Option<Mutex<LegacyOutputState>>,
}

impl OutputOwner {
    fn subscription_drain_delivery(
        &self,
        message: &JsonRpcMessage,
    ) -> Option<&FinalSubscriptionTerminalDelivery> {
        let delivery = self.subscription_terminal.as_deref()?;
        let JsonRpcMessage::Request(notification) = message else {
            return None;
        };
        if notification.method == "notifications/cancelled" {
            return self.subscription_cancellation_delivery(message);
        }
        if notification.id.is_some() {
            return None;
        }
        let subscription_id = notification
            .params
            .as_ref()?
            .get("_meta")?
            .get(FINAL_SUBSCRIPTION_ID_META_KEY)
            .cloned()
            .and_then(|id| serde_json::from_value::<RequestId>(id).ok())?;
        self.reservation
            .request_id
            .as_ref()
            .is_some_and(|expected| expected.correlates_with(&subscription_id))
            .then_some(delivery)
    }

    fn subscription_cancellation_delivery(
        &self,
        message: &JsonRpcMessage,
    ) -> Option<&FinalSubscriptionTerminalDelivery> {
        let delivery = self.subscription_terminal.as_deref()?;
        let JsonRpcMessage::Request(notification) = message else {
            return None;
        };
        if !final_subscription_terminal_notification(notification) {
            return None;
        }
        let request_id = notification
            .params
            .as_ref()?
            .get("requestId")
            .cloned()
            .and_then(|id| serde_json::from_value::<RequestId>(id).ok())?;
        self.reservation
            .request_id
            .as_ref()
            .is_some_and(|expected| expected.correlates_with(&request_id))
            .then_some(delivery)
    }

    fn cancelled(&self) -> bool {
        #[cfg(feature = "legacy-2024-11-05")]
        if self.legacy.is_some() {
            // Local deadline cancellation still needs its terminal error on
            // the wire. Only peer cancellation or connection stop withdraws
            // legacy output before that final wire election.
            return self.reservation.cancellation.is_peer_cancel_requested()
                || self.reservation.queue.is_stopping();
        }
        self.reservation.cancellation.is_cancel_requested()
    }

    fn suppresses_message(&self, message: &JsonRpcMessage) -> bool {
        if self.subscription_terminal.as_ref().is_some_and(|delivery| delivery.is_settled()) {
            return true;
        }
        if let Some(delivery) = self.subscription_drain_delivery(message)
            && delivery.completion_state.load(Ordering::Acquire) == FINAL_TERMINAL_DRAINED
        {
            // Server shutdown withdraws ordinary output but must retain the
            // elected control and its already-queued acknowledgement/events
            // in FIFO order. A peer winner, failed delivery or post-terminal
            // frame never gains that authority.
            return self.reservation.cancellation.is_peer_cancel_requested()
                || delivery.state.load(Ordering::Acquire) != FINAL_TERMINAL_ENQUEUED;
        }
        if self.cancelled() {
            return true;
        }
        #[cfg(feature = "legacy-2024-11-05")]
        if self.legacy.is_some() && !matches!(message, JsonRpcMessage::Response(_)) {
            // A local timeout may still publish its terminal response, but
            // logs and reverse requests must stop with the owning request.
            return self.reservation.cancellation.is_cancel_requested();
        }
        #[cfg(not(feature = "legacy-2024-11-05"))]
        let _ = message;
        false
    }

    #[cfg(feature = "legacy-2024-11-05")]
    fn legacy_budget(&self) -> Option<Budget> {
        self.legacy.as_ref().and_then(|legacy| {
            legacy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .budget
        })
    }

    #[cfg(feature = "legacy-2024-11-05")]
    fn legacy_timed_out(&self, cx: &Cx) -> bool {
        self.legacy_budget()
            .is_some_and(|budget| cx.budget().meet(budget).is_past_deadline(cx.now()))
    }
}

#[cfg(feature = "legacy-2024-11-05")]
#[derive(Default)]
struct LegacyOutputState {
    budget: Option<Budget>,
    // Keep dispatcher registration alive through actual terminal output
    // commitment, rather than only through handler completion.
    active: Option<LiveLegacy2024ActiveRequest>,
}

struct OutputFrame {
    message: JsonRpcMessage,
    owner: Option<Arc<OutputOwner>>,
    bytes: usize,
    subscription_control: bool,
}

impl OutputFrame {
    fn terminal_delivery(&self) -> Option<&FinalSubscriptionTerminalDelivery> {
        self.subscription_control.then_some(())?;
        self.owner.as_ref()?.subscription_cancellation_delivery(&self.message)
    }

    fn drain_delivery(&self) -> Option<&FinalSubscriptionTerminalDelivery> {
        if matches!(&self.message, JsonRpcMessage::Request(notification)
            if notification.method == "notifications/cancelled")
            && !self.subscription_control
        {
            return None;
        }
        self.owner.as_ref()?.subscription_drain_delivery(&self.message)
    }

    fn suppressed(&self) -> bool {
        self.owner.as_ref().is_some_and(|owner| {
            owner.suppresses_message(&self.message)
                || (!self.subscription_control
                    && owner.subscription_cancellation_delivery(&self.message)
                        .is_some_and(|delivery| {
                            delivery.completion_state.load(Ordering::Acquire) == FINAL_TERMINAL_DRAINED
                        }))
        })
    }
}

impl Drop for OutputFrame {
    fn drop(&mut self) {
        // Discard, queue stop and an abandoned writer all relinquish the
        // exact queued control. A successful flush already marked it drained;
        // generic cancellation-shaped frames carry no settlement authority.
        if let Some(delivery) = self.terminal_delivery() {
            delivery.mark_failed();
        }
    }
}

/// Count encoded bytes without allocating another maximum-sized payload.
/// The retained charge includes the NDJSON newline.
fn output_frame_bytes(message: &JsonRpcMessage) -> Option<usize> {
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|size| *size <= DOCUMENT_BYTES)
                .ok_or_else(|| io::Error::other("async stdio output exceeds frame bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Counter(0);
    serde_json::to_writer(&mut count, message).ok()?;
    count.0.checked_add(1)
}

#[derive(Default)]
struct OutputState {
    frames: VecDeque<OutputFrame>,
    /// Includes the frame currently owned by the writer.
    retained_frames: usize,
    retained_bytes: usize,
    candidates: HashMap<u64, Weak<OutputOwner>>,
    failure: Option<&'static str>,
    stopped: bool,
    subscription_drain_deadline: Option<asupersync::Time>,
}

#[derive(Default)]
struct OutputQueue {
    state: Mutex<OutputState>,
    changed: Notify,
}

impl OutputQueue {
    fn begin_subscription_drain(&self, deadline: asupersync::Time) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.subscription_drain_deadline = Some(
            state.subscription_drain_deadline.map_or(deadline, |old| old.min(deadline)),
        );
    }

    fn write_deadline(&self, frame_deadline: asupersync::Time) -> asupersync::Time {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
            .subscription_drain_deadline.map_or(frame_deadline, |drain| drain.min(frame_deadline))
    }

    fn has_subscription_drain(&self) -> bool {
        let candidates = {
            let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            state.candidates.values().cloned().collect::<Vec<_>>()
        };
        candidates.iter().filter_map(Weak::upgrade).any(|owner| {
            owner.subscription_terminal.as_ref().is_some_and(|delivery| {
                delivery.state.load(Ordering::Acquire) == FINAL_TERMINAL_ENQUEUED
                    && delivery.completion_state.load(Ordering::Acquire) == FINAL_TERMINAL_DRAINED
            })
        })
    }

    fn register(&self, owner: &Arc<OutputOwner>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .candidates
            .retain(|_, candidate| candidate.strong_count() != 0);
        state
            .candidates
            .insert(owner.reservation.cancellation_id, Arc::downgrade(owner));
    }

    fn enqueue(&self, message: JsonRpcMessage, owner: Option<Arc<OutputOwner>>) -> bool {
        self.enqueue_frame(message, owner, false)
    }

    fn enqueue_subscription_control(&self, message: JsonRpcMessage, owner: Arc<OutputOwner>) -> bool {
        if owner.subscription_cancellation_delivery(&message).is_none_or(|delivery| {
            delivery.state.load(Ordering::Acquire) != FINAL_TERMINAL_ENQUEUED
                || delivery.completion_state.load(Ordering::Acquire) != FINAL_TERMINAL_DRAINED
        }) {
            return false;
        }
        self.enqueue_frame(message, Some(owner), true)
    }

    fn enqueue_frame(
        &self,
        message: JsonRpcMessage,
        owner: Option<Arc<OutputOwner>>,
        subscription_control: bool,
    ) -> bool {
        if owner
            .as_ref()
            .is_some_and(|owner| owner.suppresses_message(&message))
        {
            return false;
        }
        let measured = output_frame_bytes(&message);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Cancellation can win while serialization is running or this
        // producer is waiting for the queue lock. Recheck inside the same
        // critical section as insertion: a completed cancellation sweep must
        // never be followed by this producer retaining another dead frame.
        if state.stopped
            || state.failure.is_some()
            || owner
                .as_ref()
                .is_some_and(|owner| owner.suppresses_message(&message))
        {
            return false;
        }
        if !Self::log_has_owner(&state, &message, owner.as_ref()) {
            return false;
        }
        let admitted = if let Some(bytes) = measured
            && state.retained_frames < MAX_DISPATCH_QUEUE_DEPTH
            && bytes <= MAX_DISPATCH_QUEUE_BYTES.saturating_sub(state.retained_bytes)
        {
            state.retained_frames += 1;
            state.retained_bytes += bytes;
            state.frames.push_back(OutputFrame {
                message,
                owner,
                bytes,
                subscription_control,
            });
            true
        } else {
            state.failure = Some("output_capacity");
            false
        };
        drop(state);
        self.changed.notify_waiters();
        admitted
    }

    fn log_has_owner(
        state: &OutputState,
        message: &JsonRpcMessage,
        owner: Option<&Arc<OutputOwner>>,
    ) -> bool {
        let JsonRpcMessage::Request(notification) = message else {
            return true;
        };
        if notification.method != "notifications/message" {
            return true;
        }
        #[cfg(feature = "legacy-2024-11-05")]
        if owner.is_some_and(|owner| owner.legacy.is_some()) {
            // The legacy session already applied its negotiated log floor,
            // and this callback captured the originating request explicitly.
            return true;
        }
        // Identifier-free logs have no safe adjacency-based owner. Check both
        // enqueue and writer admission against the compatible live candidates.
        let level = notification
            .params
            .as_ref()
            .and_then(|params| params.get("level"))
            .and_then(|level| serde_json::from_value::<LoggingLevel>(level.clone()).ok());
        let Some((level, origin)) = level.zip(owner) else {
            return false;
        };
        let mut compatible =
            state
                .candidates
                .values()
                .filter_map(Weak::upgrade)
                .filter(|candidate| {
                    !candidate.cancelled()
                        && candidate.log_level.is_some_and(|minimum| {
                            Server::final_log_level_rank(level)
                                >= Server::final_log_level_rank(minimum)
                        })
                });
        compatible
            .next()
            .is_some_and(|candidate| Arc::ptr_eq(&candidate, origin))
            && compatible.next().is_none()
    }

    fn admits_write(&self, frame: &OutputFrame) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !state.stopped
            && state.failure.is_none()
            && !frame.suppressed()
            && Self::log_has_owner(&state, &frame.message, frame.owner.as_ref())
    }

    #[cfg(feature = "legacy-2024-11-05")]
    fn accepts_output(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !state.stopped && state.failure.is_none()
    }

    /// Called after the writer's request deadline wins and the caller has
    /// rejected a partially written frame.
    #[cfg(feature = "legacy-2024-11-05")]
    fn replace_expired_legacy_response(
        &self,
        frame: &mut OutputFrame,
    ) -> Result<bool, TransportError> {
        let Some(owner) = frame.owner.as_ref().filter(|owner| owner.legacy.is_some()) else {
            return Ok(false);
        };
        // An earlier peer cancellation keeps its original cause and must
        // never become an eligible timeout response.
        owner.reservation.cancellation.cancel();
        if owner.cancelled() {
            return Ok(false);
        }
        let JsonRpcMessage::Response(response) = &frame.message else {
            return Ok(false);
        };
        let replacement = JsonRpcMessage::Response(JsonRpcResponse::error(
            response.id.clone(),
            JsonRpcError {
                code: McpErrorCode::RequestCancelled.into(),
                message: "Request timeout exceeded".to_owned(),
                data: None,
            },
        ));
        let measured = output_frame_bytes(&replacement);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.stopped || state.failure.is_some() || owner.cancelled() {
            return Ok(false);
        }
        let retained_without_frame = state.retained_bytes.saturating_sub(frame.bytes);
        let Some(bytes) = measured.filter(|bytes| {
            *bytes <= MAX_DISPATCH_QUEUE_BYTES.saturating_sub(retained_without_frame)
        }) else {
            state.failure = Some("output_capacity");
            drop(state);
            self.changed.notify_waiters();
            return Err(TransportError::Io(io::Error::other(
                "async stdio timeout response exceeds output capacity",
            )));
        };
        state.retained_bytes = retained_without_frame + bytes;
        drop(state);
        frame.message = replacement;
        frame.bytes = bytes;
        self.changed.notify_waiters();
        Ok(true)
    }

    fn pop(&self) -> Option<OutputFrame> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .frames
            .pop_front()
    }

    fn finish(&self, bytes: usize) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retained_frames = state.retained_frames.saturating_sub(1);
        state.retained_bytes = state.retained_bytes.saturating_sub(bytes);
    }

    /// Release uncommitted frames whose request cancellation has won, even
    /// when a different request has the output writer parked on backpressure.
    /// The frame already owned by the writer is deliberately not here: that
    /// writer alone decides whether suppression is safe or partial output
    /// requires terminating the connection.
    fn discard_cancelled(&self) -> usize {
        self.discard_frames(|frame| {
            frame.suppressed()
        })
    }

    fn retain_subscription_drain(&self) {
        self.discard_frames(|frame| {
            frame.drain_delivery().is_none() || frame.suppressed()
        });
    }

    fn discard_frames(&self, discard: impl Fn(&OutputFrame) -> bool) -> usize {
        let discarded = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut discarded = Vec::new();
            // Rotate the original queue once. Live frames retain their FIFO
            // order and existing allocation; no payload is cloned. The only
            // additional storage is a bounded list of frames being retired.
            for _ in 0..state.frames.len() {
                let frame = state.frames.pop_front().expect("counted queued frame");
                if discard(&frame) {
                    state.retained_frames = state.retained_frames.saturating_sub(1);
                    state.retained_bytes = state.retained_bytes.saturating_sub(frame.bytes);
                    discarded.push(frame);
                } else {
                    state.frames.push_back(frame);
                }
            }
            discarded
        };
        let count = discarded.len();
        // A frame may own the last request reservation. Its destructor can
        // acquire the admission mutex, so it must run AFTER the queue unlocks.
        drop(discarded);
        if count != 0 {
            self.changed.notify_waiters();
        }
        count
    }

    fn has_frames(&self) -> bool {
        !self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .frames
            .is_empty()
    }

    fn failure(&self) -> Option<&'static str> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .failure
    }

    fn stop(&self) {
        let frames = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.stopped = true;
            std::mem::take(&mut state.frames)
        };
        // Dropping reservations can acquire the admission mutex. Never do so
        // inside the output queue's bounded critical section.
        drop(frames);
        self.changed.notify_waiters();
    }
}

struct ConnectionLifetime {
    server: Arc<Server>,
    connection: ModernConnection,
    admission: Arc<DispatchQueueState>,
    output: Arc<OutputQueue>,
    binding: ConnectionBinding,
}

impl Drop for ConnectionLifetime {
    fn drop(&mut self) {
        self.admission.stop();
        self.connection.disconnect();
        self.output.stop();
        if let Some(stats) = &self.server.stats {
            stats.connection_closed();
        }
    }
}

fn receive<R: ConnectionReader>(mut reader: R, cx: Cx) -> ReadWork<R> {
    Box::pin(async move {
        let result = reader.receive(&cx).await;
        (reader, result)
    })
}

enum WriteAttempt {
    Complete(Result<(), TransportError>),
    #[cfg(feature = "legacy-2024-11-05")]
    RequestDeadline,
}

async fn send_frame<W: ConnectionWriter>(
    writer: &mut W,
    cx: &Cx,
    frame: &OutputFrame,
    output: &OutputQueue,
    mut timeout: Pin<&mut Sleep>,
    write_deadline: asupersync::Time,
    #[cfg(feature = "legacy-2024-11-05")] observe_legacy_deadline: bool,
) -> WriteAttempt {
    let mut sending = pin!(writer.send(cx, &frame.message));
    let cancellation = frame
        .owner
        .as_ref()
        .map(|owner| owner.reservation.cancellation());
    let mut cancelled = cancellation
        .as_ref()
        .map(|cancel| Box::pin(cancel.cancelled()));
    #[cfg(feature = "legacy-2024-11-05")]
    let mut request_deadline = observe_legacy_deadline
        .then(|| {
            frame
                .owner
                .as_ref()
                .and_then(|owner| owner.legacy_budget())
                .and_then(|budget| cx.budget().meet(budget).deadline)
        })
        .flatten()
        .map(|deadline| Box::pin(Sleep::new(deadline)));
    poll_fn(|task| {
        let terminal_control = frame.drain_delivery().is_some_and(|delivery| {
                delivery.state.load(Ordering::Acquire) == FINAL_TERMINAL_ENQUEUED
                    && delivery.completion_state.load(Ordering::Acquire) == FINAL_TERMINAL_DRAINED
        });
        if frame.suppressed() {
            if let Some(delivery) = frame.terminal_delivery() {
                delivery.mark_failed();
            }
            return Poll::Ready(WriteAttempt::Complete(Ok(())));
        }
        if cancelled
            .as_mut()
            .is_some_and(|cancelled| cancelled.as_mut().poll(task).is_ready())
        {
            // A local legacy timeout does not suppress its error response.
            // Consume this wake once instead of rearming an already-ready
            // cancellation future on every subsequent writer poll.
            cancelled = None;
            if frame.suppressed() {
                if let Some(delivery) = frame.terminal_delivery() {
                    delivery.mark_failed();
                }
                return Poll::Ready(WriteAttempt::Complete(Ok(())));
            }
        }
        #[cfg(feature = "legacy-2024-11-05")]
        if observe_legacy_deadline
            && (frame
                .owner
                .as_ref()
                .is_some_and(|owner| owner.legacy_timed_out(cx))
                || request_deadline
                    .as_mut()
                    .is_some_and(|deadline| deadline.as_mut().poll(task).is_ready()))
        {
            return Poll::Ready(WriteAttempt::RequestDeadline);
        }
        // Keep this absolute timeout across a timeout-response replacement;
        // starting another send must never extend the connection's drain.
        let timed_out = if terminal_control {
            cx.masked(|| timeout.as_mut().poll(task)).is_ready()
        } else {
            timeout.as_mut().poll(task).is_ready()
        };
        if timed_out || cx.now() >= output.write_deadline(write_deadline) {
            return Poll::Ready(WriteAttempt::Complete(Err(TransportError::Timeout)));
        }
        if terminal_control {
            // Retain the caller's absolute ceiling even while masking its
            // cancellation for this elected, bounded terminal write only.
            if cx.budget().deadline.is_some_and(|deadline| cx.now() >= deadline) {
                return Poll::Ready(WriteAttempt::Complete(Err(TransportError::Timeout)));
            }
            let sent = cx.masked(|| sending.as_mut().poll(task));
            if sent.is_ready() {
                if cx.now() >= output.write_deadline(write_deadline)
                    || cx.budget().deadline.is_some_and(|deadline| cx.now() >= deadline)
                {
                    return Poll::Ready(WriteAttempt::Complete(Err(TransportError::Timeout)));
                }
                if frame.suppressed() {
                    return Poll::Ready(WriteAttempt::Complete(Err(TransportError::Cancelled)));
                }
            }
            sent.map(WriteAttempt::Complete)
        } else {
            sending.as_mut().poll(task).map(WriteAttempt::Complete)
        }
    })
    .await
}

fn write<W: ConnectionWriter>(
    mut writer: W,
    cx: Cx,
    frame: OutputFrame,
    output: Arc<OutputQueue>,
) -> WriteWork<W> {
    Box::pin(async move {
        #[cfg(feature = "legacy-2024-11-05")]
        let mut frame = frame;
        if !output.admits_write(&frame) {
            if let Some(delivery) = frame.terminal_delivery() {
                delivery.mark_failed();
            }
            return (writer, Ok(()), frame.bytes);
        }
        let write_deadline = cx.now().saturating_add_nanos(
            u64::try_from(STDIO_OUTPUT_COMMIT_TIMEOUT.as_nanos()).unwrap_or(u64::MAX),
        );
        let mut timeout = pin!(Sleep::new(write_deadline));
        let attempt = send_frame(
            &mut writer,
            &cx,
            &frame,
            &output,
            timeout.as_mut(),
            write_deadline,
            #[cfg(feature = "legacy-2024-11-05")]
            true,
        )
        .await;
        let result = match attempt {
            WriteAttempt::Complete(result) => result,
            #[cfg(feature = "legacy-2024-11-05")]
            WriteAttempt::RequestDeadline => {
                // The pending send was dropped before examining the writer.
                // A partial write is terminal; a zero-byte response wait can
                // safely replace its result under the same commit bound.
                if writer.is_closed() {
                    Err(TransportError::Closed)
                } else {
                    match output.replace_expired_legacy_response(&mut frame) {
                        Ok(keep_response) => {
                            output.discard_cancelled();
                            if keep_response {
                                match send_frame(&mut writer, &cx, &frame, &output, timeout.as_mut(), write_deadline, false)
                                    .await
                                {
                                    WriteAttempt::Complete(result) => result,
                                    // Never re-arm the expired request timer
                                    // while draining its terminal error.
                                    WriteAttempt::RequestDeadline => Err(TransportError::Timeout),
                                }
                            } else {
                                Ok(())
                            }
                        }
                        Err(error) => Err(error),
                    }
                }
            }
        };
        // Dropping a cancelled send after a partial write poisons the shared
        // transport. Never interpret that case as a harmless suppressed frame.
        let result = if result.is_ok() && writer.is_closed() {
            Err(TransportError::Closed)
        } else {
            result
        };
        if let Some(owner) = &frame.owner {
            if result.is_err() {
                if let Some(delivery) = &owner.subscription_terminal {
                    delivery.mark_failed();
                }
            } else if let Some(delivery) = frame.terminal_delivery() {
                // Queue admission is not delivery: only a fully flushed
                // control settles the shutdown receipt.
                delivery.mark_drained();
            }
        }
        if result.is_ok() && matches!(frame.message, JsonRpcMessage::Response(_)) {
            if let Some(owner) = &frame.owner {
                let _ = owner.reservation.cancellation.begin_finalization();
            }
        }
        (writer, result, frame.bytes)
    })
}

fn error_response(id: Option<RequestId>, code: i32, message: &'static str) -> JsonRpcMessage {
    JsonRpcMessage::Response(JsonRpcResponse::error(
        id,
        JsonRpcError {
            code: code.into(),
            message: message.to_owned(),
            data: None,
        },
    ))
}

fn prepare_request(
    lifetime: &ConnectionLifetime,
    cx: &Cx,
    frame: ReceivedTransportFrame,
) -> McpResult<Option<RequestWork>> {
    // `ReceivedTransportFrame::admit`, its only constructor, already applied
    // the shared raw-document admission and decoded this frame once, keeping
    // the exact `params` source. Decoding it again repeats both passes.
    let raw_params = frame.raw_params().map(str::to_owned);
    let JsonRpcMessage::Request(mut request) = frame.into_message() else {
        return Err(server_run_error(
            "receive",
            "direction",
            "Modern connection received a client response",
        ));
    };
    if request.validate().is_err() {
        lifetime
            .output
            .enqueue(error_response(request.id, -32600, "Invalid Request"), None);
        return Ok(None);
    }
    // Version admission applies to requests. Client notifications carry a
    // `NotificationMetaObject` with no protocol version (the official
    // `notifications/cancelled` example has no `_meta` at all), so they must
    // reach their handlers below instead of being dropped here.
    if request.id.is_some() && modern_protocol_version(&request) != Some(MODERN_PROTOCOL_VERSION) {
        if let Some(response) = modern_request_version_refusal(&request) {
            lifetime
                .output
                .enqueue(JsonRpcMessage::Response(response), None);
        }
        return Ok(None);
    }
    if admit_final_client_notification_ingress(&request).is_err() {
        return Ok(None);
    }
    let inbound = InboundRequestContext::with_modern_connection_and_transport_authorization(
        cx.clone(),
        request_id_to_u64(request.id.as_ref()),
        lifetime.binding.transport,
        &lifetime.connection,
        lifetime.binding.authorization.clone(),
    );
    if request.id.is_none() && request.method == "notifications/cancelled" {
        #[cfg(feature = "websocket")]
        if let Some(AuthDispatchCustody::WebSocket(custody)) = &lifetime.binding.auth_custody {
            sanitize_websocket_decoded_request(custody, &mut request);
        }
        if let Ok(cancellation) = lifetime.server.authenticate_modern_cancelled_control(
            &inbound,
            &mut request,
            lifetime.binding.auth_custody.as_ref(),
            lifetime.binding.auth_generation,
        ) {
            lifetime
                .admission
                .cancel_reserved(Server::cancellation_wire_request_id(&cancellation));
            // Authentication and the request's cancellation election precede
            // reclamation. Do not wait for a blocked writer to discover these
            // dead frames or let them consume a later live request's capacity.
            lifetime.output.discard_cancelled();
        }
        return Ok(None);
    }
    let mut reservation = match lifetime
        .admission
        .admit_modern_request(&request, Arc::new(AtomicBool::new(false)))
    {
        Ok(reservation) => reservation,
        Err(error) => {
            if let Some(id) = request.id {
                lifetime.output.enqueue(
                    JsonRpcMessage::Response(JsonRpcResponse::error(Some(id), error)),
                    None,
                );
            }
            return Ok(None);
        }
    };
    // The exact parameter sidecar can be much larger than its typed value
    // (for example, whitespace or long number lexemes). It is additional
    // retained ownership, so charge it before authentication or child creation.
    let raw_bytes = raw_params.as_ref().map_or(0, String::len);
    if !lifetime.admission.reserve_queued_bytes(raw_bytes) {
        if let Some(id) = request.id {
            lifetime.output.enqueue(
                error_response(
                    Some(id),
                    RESOURCE_EXHAUSTED_ERROR_CODE,
                    DISPATCH_QUEUE_CAPACITY_MESSAGE,
                ),
                None,
            );
        }
        return Ok(None);
    }
    reservation.serialized_bytes += raw_bytes;
    let owner = Arc::new(OutputOwner {
        log_level: lifetime.server.final_request_log_level(&request),
        subscription_terminal: (request.method == SUBSCRIPTIONS_LISTEN)
            .then(|| Arc::new(FinalSubscriptionTerminalDelivery::default())),
        reservation,
        #[cfg(feature = "legacy-2024-11-05")]
        legacy: None,
    });
    // Authentication binds connection ownership before the next inbound
    // cancellation may be admitted, even if this child has not been polled.
    #[cfg(feature = "websocket")]
    if let Some(AuthDispatchCustody::WebSocket(custody)) = &lifetime.binding.auth_custody {
        // The reservation stores only size/identity. Strip before retaining
        // the request in child work, immediately before the matching custody
        // fence consumes any mixed-source refusal. Capacity/invalid-envelope
        // rejection therefore cannot leave an unconsumed registry entry.
        sanitize_websocket_decoded_request(custody, &mut request);
    }
    let receipt = match lifetime.server.admit_modern_pump_authentication(
        &inbound,
        &request,
        lifetime.binding.auth_custody.as_ref(),
        lifetime.binding.auth_generation,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            if let Some(id) = request.id {
                lifetime.output.enqueue(
                    JsonRpcMessage::Response(JsonRpcResponse::error(
                        Some(id),
                        JsonRpcError {
                            code: error.code.into(),
                            message: error.message,
                            data: error.data,
                        },
                    )),
                    Some(owner),
                );
            }
            return Ok(None);
        }
    };
    lifetime.output.register(&owner);
    let server = Arc::clone(&lifetime.server);
    let output = Arc::clone(&lifetime.output);
    let caller = cx.clone();
    let work: RequestWork = Box::pin(async move {
        if owner.cancelled() {
            return Ok(());
        }
        let region = region::open(
            &caller,
            server.create_owned_modern_request_budget(&caller, &request.method),
        )?
        .await?;
        let request_cx = region.cx().clone();
        let inbound = inbound.with_cx(request_cx.clone());
        let dispatch_cancellation = McpRequestCancellation::new();
        let notification_output = Arc::clone(&output);
        let notification_owner = Arc::clone(&owner);
        let notification_cancellation = dispatch_cancellation.clone();
        let notifications: NotificationSender = Arc::new(move |notification| {
            let message = JsonRpcMessage::Request(notification);
            let scoped = notification_owner.subscription_drain_delivery(&message).is_some();
            let terminal = notification_owner.subscription_cancellation_delivery(&message)
                .is_some_and(|delivery| delivery.state.load(Ordering::Acquire) == FINAL_TERMINAL_ENQUEUED);
            let queued = if terminal {
                notification_output.enqueue_subscription_control(message, Arc::clone(&notification_owner))
            } else {
                notification_output.enqueue(message, Some(Arc::clone(&notification_owner)))
            };
            if !queued && (scoped || notification_output.failure().is_some()) {
                if let Some(delivery) = &notification_owner.subscription_terminal {
                    delivery.mark_failed();
                    notification_cancellation.cancel();
                }
            }
        });
        let response_id = request.id.clone();
        let mut interrupted = false;
        let response = {
            let mut cancelled = pin!(owner.reservation.cancellation.cancelled());
            let mut deadline = request_cx
                .budget()
                .deadline
                .map(|deadline| Box::pin(Sleep::new(deadline)));
            let mut dispatch = Box::pin(Arc::clone(&server).dispatch_with_protocol_policy_owned(
                ProtocolPolicy::ModernOnly,
                &inbound,
                request,
                raw_params.map(Arc::<str>::from),
                Some(receipt),
                None,
                None,
                dispatch_cancellation.clone(),
                owner.subscription_terminal.clone(),
                notifications,
            ));
            let admitted = owner
                .reservation
                .queue
                .begin_modern_dispatch(owner.reservation.request_id.as_ref())
                == ModernDispatchStart::Ready;
            poll_fn(|task| {
                let _caller = Cx::set_current(Some(request_cx.clone()));
                if !admitted || owner.cancelled() || caller.checkpoint().is_err() {
                    dispatch_cancellation.cancel();
                    interrupted = true;
                    return Poll::Ready(None);
                }
                if cancelled.as_mut().poll(task).is_ready() {
                    dispatch_cancellation.cancel();
                    interrupted = true;
                    return Poll::Ready(None);
                }
                if deadline
                    .as_mut()
                    .is_some_and(|deadline| deadline.as_mut().poll(task).is_ready())
                {
                    dispatch_cancellation.cancel();
                    interrupted = true;
                    return Poll::Ready(response_id.clone().map(|id| {
                        JsonRpcResponse::error(
                            Some(id),
                            JsonRpcError {
                                code: McpErrorCode::RequestCancelled.into(),
                                message: "Request timeout exceeded".to_owned(),
                                data: None,
                            },
                        )
                    }));
                }
                dispatch.as_mut().poll(task)
            })
            .await
        };
        if interrupted || owner.cancelled() || caller.checkpoint().is_err() {
            region
                .cancel(asupersync::CancelReason::new(asupersync::CancelKind::User))
                .map_err(|_| {
                    server_run_error(
                        "dispatch",
                        "region_cancel",
                        "Request region cancellation failed",
                    )
                })?;
        }
        region.close().await.map_err(|_| {
            server_run_error("dispatch", "region_close", "Request region did not close")
        })?;
        if let Some(response) = response {
            output.enqueue(JsonRpcMessage::Response(response), Some(owner));
        }
        Ok(())
    });
    Ok(Some(work))
}

/// The exact-2024 adapter serializes lifecycle and application mutations, but
/// ingress remains independently pollable to deliver reverse responses and
/// cancellation while its current handler is suspended.
#[cfg(feature = "legacy-2024-11-05")]
struct LegacyIngress {
    sender: Option<asupersync_mpsc::Sender<LegacyQueuedRequest>>,
    pending: Arc<PendingRequests>,
    principal: SessionPrincipalBinding,
}

#[cfg(feature = "legacy-2024-11-05")]
struct LegacyQueuedRequest {
    request: JsonRpcRequest,
    invocation: LegacyInvocation,
}

#[cfg(feature = "legacy-2024-11-05")]
#[derive(Clone)]
struct LegacyInvocation {
    owner: Arc<OutputOwner>,
    // Share the retained sanitized document across the worker and adapter
    // callback; cloning it again would bypass admission byte accounting.
    authentication: Arc<AuthAdmissionReceipt>,
}

/// Validate the exact wire surface before authentication can bind a peer or
/// the adapter can change lifecycle state. Notification refusals stay silent.
#[cfg(feature = "legacy-2024-11-05")]
fn admit_legacy_envelope(output: &OutputQueue, request: &JsonRpcRequest) -> bool {
    if request
        .params
        .as_ref()
        .and_then(|params| params.get("_meta"))
        .is_some_and(|metadata| !metadata.is_object())
    {
        if let Some(id) = &request.id {
            output.enqueue(
                error_response(
                    Some(id.clone()),
                    if request.method == "initialize" {
                        -32600
                    } else {
                        -32602
                    },
                    "Exact-2024 metadata must be an object",
                ),
                None,
            );
        }
        return false;
    }
    let wire = serde_json::to_value(request)
        .expect("a validated JSON-RPC request must serialize for legacy admission");
    let Err(error) = fastmcp_protocol::methods::decode_legacy_2024_11_05_envelope_classified(wire)
    else {
        return true;
    };
    use fastmcp_protocol::methods::Legacy2024EnvelopeError;
    let (code, message) = match error {
        Legacy2024EnvelopeError::Envelope(_) => (-32600, "Invalid exact-2024 envelope"),
        Legacy2024EnvelopeError::Method(_) => {
            (-32601, "Method is not part of exact MCP 2024-11-05")
        }
        Legacy2024EnvelopeError::MethodParams(_) => (-32602, "Invalid exact-2024 parameters"),
    };
    if let Some(id) = &request.id {
        output.enqueue(error_response(Some(id.clone()), code, message), None);
    }
    false
}

#[cfg(feature = "legacy-2024-11-05")]
impl LegacyIngress {
    fn install(lifetime: &ConnectionLifetime, cx: &Cx) -> McpResult<(Self, RequestWork)> {
        let server = Arc::clone(&lifetime.server);
        let session = Session::new(server.info.clone(), server.capabilities.clone());
        let session_id = session.id();
        let principal = session.principal_binding();
        let binding = runtime_legacy_binding(session_id);
        let pending = Arc::new(PendingRequests::with_max_in_flight_for_exact_legacy(
            server.max_bidirectional_requests_per_connection,
        )?);
        let runtime = LiveLegacy2024ConnectionRuntime::new(
            SessionState::new(),
            Arc::new(|_| {}),
            None,
            server.logging.level,
        );
        let invocation = Arc::new(Mutex::new(None));
        let region_failure = Arc::new(Mutex::new(None));
        let handler = NativeLegacyHandler {
            server: Arc::clone(&server),
            cx: cx.clone(),
            session_id,
            principal: principal.clone(),
            runtime: runtime.clone(),
            pending: Arc::clone(&pending),
            output: Arc::clone(&lifetime.output),
            invocation: Arc::clone(&invocation),
            region_failure: Arc::clone(&region_failure),
        };
        let mut adapter = server
            .install_legacy_2024_adapter(binding, handler)
            .map_err(|_| McpError::internal_error("Native legacy adapter installation failed"))?;
        let (sender, mut receiver) =
            asupersync_mpsc::channel::<LegacyQueuedRequest>(MAX_DISPATCH_QUEUE_DEPTH);
        let caller = cx.clone();
        let admission = Arc::clone(&lifetime.admission);
        let output = Arc::clone(&lifetime.output);
        let work: RequestWork = Box::pin(async move {
            while !admission.is_stopping() {
                let queued = match receiver.recv(&caller).await {
                    Ok(queued) => queued,
                    Err(asupersync_mpsc::RecvError::Empty) => continue,
                    Err(
                        asupersync_mpsc::RecvError::Disconnected
                        | asupersync_mpsc::RecvError::Cancelled,
                    ) => break,
                };
                let LegacyQueuedRequest {
                    request,
                    invocation: current,
                } = queued;
                if current.owner.cancelled()
                    || admission.begin_modern_dispatch(request.id.as_ref())
                        != ModernDispatchStart::Ready
                {
                    continue;
                }
                let budget = current
                    .owner
                    .legacy
                    .as_ref()
                    .expect("legacy output owner")
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .budget
                    .expect("legacy admission budget");
                // Queue residence consumes the original admission budget,
                // including for adapter-owned lifecycle and logging methods.
                if let Some(error) = Server::request_budget_error(&caller, budget) {
                    current.owner.reservation.cancellation.cancel();
                    if let Some(id) = request.id {
                        output.enqueue(
                            JsonRpcMessage::Response(JsonRpcResponse::error(
                                Some(id),
                                JsonRpcError {
                                    code: error.code.into(),
                                    message: error.message,
                                    data: error.data,
                                },
                            )),
                            Some(current.owner),
                        );
                    }
                    continue;
                }
                *invocation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(current.clone());
                let response = legacy_adapter_response_async(&mut adapter, binding, &request).await;
                invocation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                let failure = region_failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(failure) = failure {
                    let _ = adapter.close(binding);
                    return Err(failure);
                }
                sync_live_legacy_runtime_from_adapter(&runtime, &adapter);
                match response {
                    Ok(Some(response)) => {
                        output.enqueue(JsonRpcMessage::Response(response), Some(current.owner));
                    }
                    Ok(None) => {}
                    // An invalid notification has no response. The exact
                    // adapter preserves its lifecycle for the next frame.
                    Err(error) if (-32602..=-32600).any(|code| error.code() == &code.into()) => {}
                    Err(_) => {
                        let _ = adapter.close(binding);
                        return Err(server_run_error(
                            "dispatch",
                            "legacy_adapter",
                            "Native legacy adapter dispatch failed",
                        ));
                    }
                }
            }
            adapter.close(binding).map_err(|_| {
                server_run_error(
                    "shutdown",
                    "legacy_adapter",
                    "Native legacy adapter did not close",
                )
            })?;
            Ok(())
        });
        Ok((
            Self {
                sender: Some(sender),
                pending,
                principal,
            },
            work,
        ))
    }

    fn authenticate(
        &self,
        server: &Server,
        cx: &Cx,
        budget: Budget,
        request: &mut JsonRpcRequest,
    ) -> McpResult<AuthAdmissionReceipt> {
        Server::enforce_request_budget(cx, budget)?;
        let (request_ctx, _request_lease_guard) =
            McpContext::new(cx.clone(), request_id_to_u64(request.id.as_ref()))
                .with_budget_ceiling(budget)
                .begin_request_scope()
                .ok_or_else(|| {
                    McpError::internal_error("request scope could not be established")
                })?;
        let (fingerprint, authenticated) = server.authenticate_request_without_commit(
            &request_ctx,
            AuthRequest {
                method: &request.method,
                params: request.params.as_ref(),
                transport_authorization: None,
                request_id: request_id_to_u64(request.id.as_ref()),
            },
        )?;
        Server::enforce_request_context(&request_ctx)?;
        bind_connection_principal(&self.principal, fingerprint)?;
        auth::strip_recognized_access_credentials(&mut request.params);
        Ok(AuthAdmissionReceipt {
            method: request.method.clone(),
            request_id: request.id.clone(),
            sanitized_params: request.params.clone(),
            fingerprint,
            authenticated,
        })
    }

    fn admit(
        &self,
        lifetime: &ConnectionLifetime,
        cx: &Cx,
        frame: ReceivedTransportFrame,
    ) -> McpResult<()> {
        let mut request = match frame.into_message() {
            JsonRpcMessage::Response(response) => {
                return match self.pending.route_response_with_disposition(&response) {
                    bidirectional::PendingResponseDisposition::Unmatched => Err(server_run_error(
                        "receive",
                        "legacy_response",
                        "Native legacy connection received an unowned response",
                    )),
                    bidirectional::PendingResponseDisposition::Delivered
                    | bidirectional::PendingResponseDisposition::Rejected
                    | bidirectional::PendingResponseDisposition::RetiredGeneric => Ok(()),
                };
            }
            JsonRpcMessage::Request(request) => request,
        };
        if request.validate().is_err() {
            if let Some(id) = request.id {
                lifetime
                    .output
                    .enqueue(error_response(Some(id), -32600, "Invalid Request"), None);
            }
            return Ok(());
        }
        if !admit_legacy_envelope(&lifetime.output, &request) {
            return Ok(());
        }
        if request.id.is_none() && request.method == "notifications/cancelled" {
            if let Ok(cancellation) = lifetime.server.authenticate_cancelled_control_notification(
                cx,
                &self.principal,
                ProtocolEra::Legacy2024,
                &mut request,
                None,
            ) {
                if lifetime
                    .admission
                    .cancel_reserved(Server::cancellation_wire_request_id(&cancellation))
                    == DispatchCancellationDisposition::Accepted
                {
                    self.pending.cancel_cancelled();
                    lifetime.output.discard_cancelled();
                }
            }
            return Ok(());
        }
        // Reuse the bounded ID/count/byte reservation, including initialize's
        // protection from peer cancellation, without invoking modern dispatch.
        let mut reservation = match lifetime
            .admission
            .admit_modern_request(&request, Arc::new(AtomicBool::new(false)))
        {
            Ok(reservation) => reservation,
            Err(error) => {
                if let Some(id) = request.id {
                    lifetime.output.enqueue(
                        JsonRpcMessage::Response(JsonRpcResponse::error(Some(id), error)),
                        None,
                    );
                }
                return Ok(());
            }
        };
        // Authentication retains one sanitized parameter document beside the
        // queued request. All later clones share that receipt through Arc.
        let receipt_bytes = reservation.serialized_bytes;
        if !lifetime.admission.reserve_queued_bytes(receipt_bytes) {
            if let Some(id) = request.id {
                lifetime.output.enqueue(
                    error_response(
                        Some(id),
                        RESOURCE_EXHAUSTED_ERROR_CODE,
                        DISPATCH_QUEUE_CAPACITY_MESSAGE,
                    ),
                    None,
                );
            }
            return Ok(());
        }
        reservation.serialized_bytes += receipt_bytes;
        let budget = lifetime.server.create_request_budget(cx);
        let owner = Arc::new(OutputOwner {
            reservation,
            log_level: None,
            subscription_terminal: None,
            legacy: Some(Mutex::new(LegacyOutputState {
                budget: Some(budget),
                active: None,
            })),
        });
        let authentication = match self.authenticate(&lifetime.server, cx, budget, &mut request) {
            Ok(receipt) => receipt,
            Err(error) => {
                if let Some(id) = request.id {
                    let error = mask_peer_error(error, lifetime.server.mask_error_details);
                    lifetime.output.enqueue(
                        JsonRpcMessage::Response(JsonRpcResponse::error(
                            Some(id),
                            JsonRpcError {
                                code: error.code.into(),
                                message: error.message,
                                data: error.data,
                            },
                        )),
                        Some(owner),
                    );
                }
                return Ok(());
            }
        };
        let sender = self.sender.as_ref().ok_or_else(|| {
            server_run_error("receive", "legacy_closed", "Native legacy input is closed")
        })?;
        sender
            .try_send(LegacyQueuedRequest {
                request,
                invocation: LegacyInvocation {
                    owner,
                    authentication: Arc::new(authentication),
                },
            })
            .map_err(|_| {
                server_run_error(
                    "receive",
                    "legacy_capacity",
                    "Native legacy dispatch queue could not accept an admitted frame",
                )
            })
    }

    fn finish_input(&mut self) {
        // Dropping the only producer lets FIFO notifications and already
        // admitted calls drain, then terminates the otherwise waiting worker.
        self.sender.take();
        self.pending.cancel_all();
    }
}

#[cfg(feature = "legacy-2024-11-05")]
impl Drop for LegacyIngress {
    fn drop(&mut self) {
        self.finish_input();
    }
}

#[cfg(feature = "legacy-2024-11-05")]
struct NativeLegacyHandler {
    server: Arc<Server>,
    cx: Cx,
    session_id: u64,
    principal: SessionPrincipalBinding,
    runtime: LiveLegacy2024ConnectionRuntime,
    pending: Arc<PendingRequests>,
    output: Arc<OutputQueue>,
    invocation: Arc<Mutex<Option<LegacyInvocation>>>,
    region_failure: Arc<Mutex<Option<McpError>>>,
}

#[cfg(feature = "legacy-2024-11-05")]
impl NativeLegacyHandler {
    fn fail_region(&self, kind: &'static str, message: &'static str) -> Legacy2024HandlerError {
        *self
            .region_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(server_run_error("dispatch", kind, message));
        Legacy2024HandlerError::new(message)
    }
}

#[cfg(feature = "legacy-2024-11-05")]
impl Legacy2024Handler for NativeLegacyHandler {
    fn handle_legacy_2024(
        &mut self,
        _method: &'static str,
        _params: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, Legacy2024HandlerError> {
        Err(live_legacy_sync_dispatch_refused())
    }

    fn handle_legacy_2024_with_request_id_async<'a>(
        &'a mut self,
        request_id: &'a serde_json::Value,
        method: &'static str,
        params: Option<&'a serde_json::Value>,
    ) -> BoxFuture<'a, Result<serde_json::Value, Legacy2024HandlerError>> {
        Box::pin(async move {
            let current = self
                .invocation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .ok_or_else(|| {
                    Legacy2024HandlerError::new("Native legacy request admission is absent")
                })?;
            let request_id =
                serde_json::from_value::<RequestId>(request_id.clone()).map_err(|_| {
                    Legacy2024HandlerError::new("legacy adapter supplied an invalid request ID")
                })?;
            let request = JsonRpcRequest::new(method, params.cloned(), request_id);
            let budget = current
                .owner
                .legacy
                .as_ref()
                .expect("legacy output owner")
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .budget
                .expect("legacy admission budget");
            // The admission task retains a pending mint even if the owning
            // connection is dropped; raw open_child_region lacks that custody.
            let region = region::open(&self.cx, budget)
                .map_err(|_| {
                    self.fail_region("region_open", "Legacy request region admission failed")
                })?
                .await
                .map_err(|_| {
                    self.fail_region("region_open", "Legacy request region could not be opened")
                })?;
            let request_cx = region.cx().clone();
            let mut runtime = self.runtime.clone();
            runtime.notification_sender = {
                let output = Arc::clone(&self.output);
                let owner = Arc::clone(&current.owner);
                Arc::new(move |notification| {
                    output.enqueue(
                        JsonRpcMessage::Request(notification),
                        Some(Arc::clone(&owner)),
                    );
                })
            };
            runtime.request_sender = Some(RequestSender::new(Arc::clone(&self.pending), {
                let output = Arc::clone(&self.output);
                let owner = Arc::clone(&current.owner);
                Arc::new(move |message| {
                    // A dropped in-flight reverse request must still cancel
                    // its peer waiter when its parent was cancelled. Admit
                    // only this trusted, era-checked control without an owner;
                    // application requests/logs/results keep ordinary custody.
                    let cleanup = matches!(message, JsonRpcMessage::Request(notification)
                        if CancellationWireMessage::decode(
                            ProtocolEra::Legacy2024,
                            CancellationSender::Server,
                            notification,
                        ).is_ok());
                    if (!cleanup && owner.suppresses_message(message)) || !output.accepts_output() {
                        return Err("Native legacy output is closed".to_owned());
                    }
                    if output.enqueue(
                        message.clone(),
                        if cleanup {
                            None
                        } else {
                            Some(Arc::clone(&owner))
                        },
                    ) {
                        Ok(())
                    } else {
                        Err("Native legacy output is closed".to_owned())
                    }
                })
            }));
            let cancellation = current.owner.reservation.cancellation();
            let mut interrupted = false;
            let dispatch = {
                let mut cancelled = pin!(cancellation.cancelled());
                let mut deadline = budget
                    .deadline
                    .map(|deadline| Box::pin(Sleep::new(deadline)));
                let mut dispatch = pin!(self.server.dispatch_legacy_2024(
                    &request_cx,
                    self.session_id,
                    &self.principal,
                    Some(&runtime),
                    Some(cancellation.clone()),
                    &request,
                    Some(current.authentication.as_ref()),
                    None,
                ));
                poll_fn(|task| {
                    let _caller = Cx::set_current(Some(request_cx.clone()));
                    if self.cx.checkpoint().is_err()
                        || cancellation.is_cancel_requested()
                        || cancelled.as_mut().poll(task).is_ready()
                    {
                        cancellation.cancel();
                        interrupted = true;
                        return Poll::Ready(Err(McpError::request_cancelled()));
                    }
                    if deadline
                        .as_mut()
                        .is_some_and(|deadline| deadline.as_mut().poll(task).is_ready())
                    {
                        cancellation.cancel();
                        interrupted = true;
                        return Poll::Ready(Err(McpError::new(
                            McpErrorCode::RequestCancelled,
                            "Request timeout exceeded",
                        )));
                    }
                    dispatch.as_mut().poll(task)
                })
                .await
            };
            // The dispatch future and its reverse-request guards were dropped
            // above. Quiesce its child before handing any result to the adapter.
            if cancellation.is_cancel_requested() {
                self.output.discard_cancelled();
            }
            if interrupted || cancellation.is_cancel_requested() || self.cx.checkpoint().is_err() {
                if region
                    .cancel(asupersync::CancelReason::new(asupersync::CancelKind::User))
                    .is_err()
                {
                    self.fail_region("region_cancel", "Legacy request region cancellation failed");
                }
            }
            region.close().await.map_err(|_| {
                self.fail_region("region_close", "Legacy request region did not close")
            })?;
            let LiveLegacy2024Dispatch {
                result,
                active_request,
            } = dispatch.map_err(|error| {
                legacy_handler_error_from_mcp(error, self.server.mask_error_details)
            })?;
            current
                .owner
                .legacy
                .as_ref()
                .expect("legacy output owner")
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .active = Some(active_request);
            result.map_err(|error| {
                legacy_handler_error_from_mcp(error, self.server.mask_error_details)
            })
        })
    }
}

enum ConnectionAdmission {
    Continue(Option<RequestWork>),
    #[cfg(feature = "legacy-2024-11-05")]
    Close,
}

#[cfg(feature = "legacy-2024-11-05")]
enum NativeProtocol {
    Modern,
    Opening(StdioEraClassifier),
    Legacy(LegacyIngress),
}

#[cfg(feature = "legacy-2024-11-05")]
impl NativeProtocol {
    fn new(policy: ProtocolPolicy) -> Self {
        if policy == ProtocolPolicy::ModernOnly {
            Self::Modern
        } else {
            Self::Opening(StdioEraClassifier::new(policy))
        }
    }

    fn needs_opening(&self) -> bool {
        matches!(self, Self::Opening(_))
    }

    fn finish_input(&mut self) {
        if let Self::Legacy(legacy) = self {
            legacy.finish_input();
        }
    }

    fn has_modern_marker(request: &JsonRpcRequest) -> bool {
        request
            .params
            .as_ref()
            .and_then(|params| params.get("_meta"))
            .and_then(serde_json::Value::as_object)
            .is_some_and(|metadata| {
                metadata
                    .keys()
                    .any(|key| key.starts_with("io.modelcontextprotocol/"))
            })
    }

    fn has_valid_modern_metadata(request: &JsonRpcRequest) -> bool {
        let Some(metadata) = request
            .params
            .as_ref()
            .and_then(|params| params.get("_meta"))
        else {
            return false;
        };
        if serde_json::from_value::<fastmcp_protocol::FinalRequestMeta>(metadata.clone()).is_err() {
            return false;
        }
        // FinalRequestMeta retains additional fields without validating their
        // reserved values. Apply the common metadata admission as well, so a
        // malformed log level, key, or trace field cannot select an era and
        // keep a connection open after a terminal opening error. Version support
        // remains a separate check after this structural admission.
        let Ok(metadata) = serde_json::from_value::<OpenMetadata>(metadata.clone()) else {
            return false;
        };
        fastmcp_protocol::common_types::TraceContext::try_from_metadata(&metadata).is_ok()
    }

    fn refuse_opening(
        lifetime: &ConnectionLifetime,
        request: &JsonRpcRequest,
        malformed_metadata: bool,
    ) {
        if malformed_metadata {
            if let Some(id) = &request.id {
                lifetime.output.enqueue(
                    error_response(
                        Some(id.clone()),
                        -32602,
                        "Opening request requires complete valid modern metadata",
                    ),
                    None,
                );
            }
        } else if let Some(response) =
            era_admission_refusal(lifetime.server.protocol_policy, request)
        {
            lifetime
                .output
                .enqueue(JsonRpcMessage::Response(response), None);
        }
    }

    fn prepare(
        &mut self,
        lifetime: &ConnectionLifetime,
        cx: &Cx,
        frame: ReceivedTransportFrame,
    ) -> McpResult<ConnectionAdmission> {
        if let Self::Opening(classifier) = self {
            let JsonRpcMessage::Request(request) = frame.message() else {
                return Ok(ConnectionAdmission::Close);
            };
            if request.id.is_none() {
                return Ok(ConnectionAdmission::Close);
            }
            if request.validate().is_err() {
                lifetime.output.enqueue(
                    error_response(request.id.clone(), -32600, "Invalid Request"),
                    None,
                );
                return Ok(ConnectionAdmission::Close);
            }
            let modern_marker = Self::has_modern_marker(request);
            let legacy_initialize = request.method == "initialize" && !modern_marker;
            if lifetime.server.protocol_policy == ProtocolPolicy::LegacyOnly && !legacy_initialize {
                Self::refuse_opening(lifetime, request, false);
                return Ok(ConnectionAdmission::Close);
            }
            if request.method == "initialize" && modern_marker {
                Self::refuse_opening(lifetime, request, false);
                return Ok(ConnectionAdmission::Close);
            }
            if legacy_initialize {
                // The shared classifier identifies an initialize envelope;
                // native Auto additionally requires a complete exact opening
                // before installing its adapter or binding authentication.
                if !admit_legacy_envelope(&lifetime.output, request) {
                    return Ok(ConnectionAdmission::Close);
                }
                if request
                    .params
                    .as_ref()
                    .and_then(|params| params.get("protocolVersion"))
                    .and_then(serde_json::Value::as_str)
                    != Some(LEGACY_PROTOCOL_VERSION)
                {
                    Self::refuse_opening(lifetime, request, false);
                    return Ok(ConnectionAdmission::Close);
                }
            } else if !modern_marker || !Self::has_valid_modern_metadata(request) {
                Self::refuse_opening(lifetime, request, modern_marker);
                return Ok(ConnectionAdmission::Close);
            }
            let era = match classify_initial_stdio_envelope(classifier, frame.message()) {
                Ok(era) => era,
                Err(decision) if opening_rejection_selected_modern(&decision) => {
                    ProtocolEra::Modern2026
                }
                Err(_) => {
                    Self::refuse_opening(lifetime, request, false);
                    return Ok(ConnectionAdmission::Close);
                }
            };
            match era {
                ProtocolEra::Modern2026 => *self = Self::Modern,
                ProtocolEra::Legacy2024 => {
                    let (legacy, work) = LegacyIngress::install(lifetime, cx)?;
                    legacy.admit(lifetime, cx, frame)?;
                    *self = Self::Legacy(legacy);
                    return Ok(ConnectionAdmission::Continue(Some(work)));
                }
            }
        }
        match self {
            Self::Modern => prepare_request(lifetime, cx, frame).map(ConnectionAdmission::Continue),
            Self::Legacy(legacy) => {
                if let JsonRpcMessage::Request(request) = frame.message()
                    && Self::has_modern_marker(request)
                {
                    Self::refuse_opening(lifetime, request, false);
                    return Ok(ConnectionAdmission::Close);
                }
                legacy.admit(lifetime, cx, frame)?;
                Ok(ConnectionAdmission::Continue(None))
            }
            Self::Opening(_) => unreachable!("opening selected a protocol above"),
        }
    }
}

enum Event<R, W> {
    Read(R, Result<ReceivedTransportFrame, TransportError>),
    Written(W, Result<(), TransportError>, usize),
    Completed(usize, McpResult<()>),
    Output,
    #[cfg(feature = "tasks")]
    TaskServiceCheck,
    Stop(Option<McpError>),
    DrainExpired,
}

struct NativeSubscriptionShutdown {
    receipt: FinalSubscriptionTerminationReceipt,
    deadline: asupersync::Time,
    admission_stopped: bool,
}

/// Rotate the first eligible work lane after every selected event. Merely
/// alternating ingress-first and ingress-last leaves requests ahead of egress
/// in both orders: a replenished set of ready handlers can then starve the
/// writer until an otherwise writable connection exhausts its output queue.
#[derive(Clone, Copy, Default)]
enum ConnectionLane {
    #[default]
    Ingress,
    Requests,
    Egress,
}

impl ConnectionLane {
    const fn next(self) -> Self {
        match self {
            Self::Ingress => Self::Requests,
            Self::Requests => Self::Egress,
            Self::Egress => Self::Ingress,
        }
    }
}

#[derive(Default)]
struct ConnectionSchedule {
    next_lane: ConnectionLane,
    next_request: usize,
}

impl ConnectionSchedule {
    /// Select one ready event without polling a completed future twice.
    /// A pending lane never prevents another lane from progressing. When all
    /// lanes are pending, every owned future is polled to register its waker.
    /// Connection stop, deadline, and service-health checks run before this
    /// selector; fairness must never postpone those control-plane decisions.
    fn poll<R, W>(
        &mut self,
        task: &mut std::task::Context<'_>,
        reading: &mut Option<ReadWork<R>>,
        writing: &mut Option<WriteWork<W>>,
        requests: &mut [RequestWork],
        stopping: bool,
    ) -> Poll<Event<R, W>> {
        let mut lane = self.next_lane;
        for _ in 0..3 {
            let event = match lane {
                ConnectionLane::Ingress if !stopping => {
                    reading
                        .as_mut()
                        .and_then(|reading| match reading.as_mut().poll(task) {
                            Poll::Ready((reader, result)) => Some(Event::Read(reader, result)),
                            Poll::Pending => None,
                        })
                }
                ConnectionLane::Requests => self.poll_request(task, requests),
                ConnectionLane::Egress => {
                    writing
                        .as_mut()
                        .and_then(|writing| match writing.as_mut().poll(task) {
                            Poll::Ready((writer, result, bytes)) => {
                                Some(Event::Written(writer, result, bytes))
                            }
                            Poll::Pending => None,
                        })
                }
                ConnectionLane::Ingress => None,
            };
            if let Some(event) = event {
                self.next_lane = lane.next();
                return Poll::Ready(event);
            }
            lane = lane.next();
        }
        Poll::Pending
    }

    fn poll_request<R, W>(
        &mut self,
        task: &mut std::task::Context<'_>,
        requests: &mut [RequestWork],
    ) -> Option<Event<R, W>> {
        if requests.is_empty() {
            self.next_request = 0;
            return None;
        }
        // swap_remove and subsequent admission can change the length between
        // selections. Normalize before indexing, including after tail removal.
        let start = self.next_request % requests.len();
        for offset in 0..requests.len() {
            let index = (start + offset) % requests.len();
            if let Poll::Ready(result) = requests[index].as_mut().poll(task) {
                // Advance past the selected index even when swap_remove moves
                // another ready future into it. Restarting at that same index
                // would starve pending siblings under completion/admission churn.
                self.next_request = (index + 1) % requests.len();
                return Some(Event::Completed(index, result));
            }
        }
        None
    }
}

#[cfg(test)]
mod schedule_tests {
    use super::{ConnectionSchedule, Event, ReadWork, RequestWork, WriteWork};
    use fastmcp_transport::TransportError;
    use std::future::{Future, poll_fn};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};

    fn read_ready() -> ReadWork<()> {
        Box::pin(async { ((), Err(TransportError::Closed)) })
    }

    fn write_ready() -> WriteWork<()> {
        Box::pin(async { ((), Ok(()), 7) })
    }

    fn request_ready() -> RequestWork {
        Box::pin(async { Ok(()) })
    }

    fn selected(event: Poll<Event<(), ()>>) -> (usize, Option<usize>) {
        match event {
            Poll::Ready(Event::Read((), Err(TransportError::Closed))) => (0, None),
            Poll::Ready(Event::Completed(index, Ok(()))) => (1, Some(index)),
            Poll::Ready(Event::Written((), Ok(()), 7)) => (2, None),
            _ => panic!("expected exactly one ready work event"),
        }
    }

    fn replenish(
        lane: usize,
        request_index: Option<usize>,
        reading: &mut Option<ReadWork<()>>,
        writing: &mut Option<WriteWork<()>>,
        requests: &mut Vec<RequestWork>,
    ) {
        match lane {
            0 => *reading = Some(read_ready()),
            1 => {
                drop(requests.swap_remove(request_index.unwrap()));
                requests.push(request_ready());
            }
            2 => *writing = Some(write_ready()),
            _ => unreachable!(),
        }
    }

    #[test]
    fn continuously_ready_ingress_and_requests_cannot_starve_egress() {
        let mut schedule = ConnectionSchedule::default();
        let mut reading = Some(read_ready());
        let mut writing = Some(write_ready());
        let mut requests = vec![request_ready()];
        let mut task = Context::from_waker(Waker::noop());
        let mut counts = [0; 3];
        for turn in 0..3_000 {
            let (lane, index) = selected(schedule.poll(
                &mut task,
                &mut reading,
                &mut writing,
                &mut requests,
                false,
            ));
            // The original ingress-first/ingress-last alternation selected
            // only ingress and requests. It never reached a writable egress.
            assert_eq!(lane, turn % 3);
            counts[lane] += 1;
            replenish(lane, index, &mut reading, &mut writing, &mut requests);
        }
        assert_eq!(counts, [1_000; 3]);
    }

    #[test]
    fn each_pending_lane_yields_to_both_other_ready_lanes() {
        for blocked in 0..3 {
            let mut schedule = ConnectionSchedule::default();
            let mut reading = Some(read_ready());
            let mut writing = Some(write_ready());
            let mut requests = vec![request_ready()];
            match blocked {
                0 => reading = Some(Box::pin(std::future::pending())),
                1 => requests[0] = Box::pin(std::future::pending()),
                2 => writing = Some(Box::pin(std::future::pending())),
                _ => unreachable!(),
            }
            let mut task = Context::from_waker(Waker::noop());
            let mut counts = [0; 3];
            for _ in 0..600 {
                let (lane, index) = selected(schedule.poll(
                    &mut task,
                    &mut reading,
                    &mut writing,
                    &mut requests,
                    false,
                ));
                assert_ne!(lane, blocked);
                counts[lane] += 1;
                replenish(lane, index, &mut reading, &mut writing, &mut requests);
            }
            for (lane, count) in counts.into_iter().enumerate() {
                assert_eq!(count, if lane == blocked { 0 } else { 300 });
            }
        }
    }

    #[test]
    fn ready_request_churn_does_not_starve_a_pending_sibling() {
        let mut schedule = ConnectionSchedule::default();
        let mut reading: Option<ReadWork<()>> = None;
        let mut writing: Option<WriteWork<()>> = None;
        let mut requests = (0..31).map(|_| request_ready()).collect::<Vec<_>>();
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&polls);
        requests.push(Box::pin(poll_fn(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        })));
        let mut task = Context::from_waker(Waker::noop());
        for _ in 0..8 {
            let before = polls.load(Ordering::SeqCst);
            // Completion removes a slot with swap_remove and admission puts
            // another ready request at the tail, exactly as the serving loop.
            for _ in 0..64 {
                let (lane, index) = selected(schedule.poll(
                    &mut task,
                    &mut reading,
                    &mut writing,
                    &mut requests,
                    false,
                ));
                assert_eq!(lane, 1);
                replenish(lane, index, &mut reading, &mut writing, &mut requests);
            }
            assert!(polls.load(Ordering::SeqCst) > before);
        }
    }

    #[test]
    fn request_cursor_survives_shrink_empty_and_readmission() {
        let mut schedule = ConnectionSchedule::default();
        let mut reading: Option<ReadWork<()>> = None;
        let mut writing: Option<WriteWork<()>> = None;
        let mut requests = (0..9).map(|_| request_ready()).collect::<Vec<_>>();
        let mut task = Context::from_waker(Waker::noop());
        while !requests.is_empty() {
            let (lane, index) = selected(schedule.poll(
                &mut task,
                &mut reading,
                &mut writing,
                &mut requests,
                false,
            ));
            assert_eq!(lane, 1);
            drop(requests.swap_remove(index.unwrap()));
        }
        assert!(
            schedule
                .poll(&mut task, &mut reading, &mut writing, &mut requests, false)
                .is_pending()
        );
        requests.push(request_ready());
        let (lane, index) =
            selected(schedule.poll(&mut task, &mut reading, &mut writing, &mut requests, false));
        assert_eq!((lane, index), (1, Some(0)));
    }

    #[test]
    fn stopping_suppresses_ingress_but_keeps_request_cleanup_runnable() {
        let mut schedule = ConnectionSchedule::default();
        let mut reading: Option<ReadWork<()>> = Some(Box::pin(poll_fn(|_| {
            panic!("stopping must not poll the inbound transport")
        })));
        let mut writing: Option<WriteWork<()>> = None;
        let mut requests = vec![request_ready()];
        let mut task = Context::from_waker(Waker::noop());
        assert_eq!(
            selected(schedule.poll(&mut task, &mut reading, &mut writing, &mut requests, true,)),
            (1, Some(0)),
        );
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    type WakerSlot = Arc<Mutex<Option<Waker>>>;

    fn pending_with_waker<T: 'static>(slot: &WakerSlot) -> Pin<Box<dyn Future<Output = T> + Send>> {
        let slot = Arc::clone(slot);
        Box::pin(poll_fn(move |task| {
            *slot.lock().unwrap() = Some(task.waker().clone());
            Poll::Pending
        }))
    }

    #[test]
    fn all_pending_lanes_register_and_replace_the_current_task_waker() {
        let mut schedule = ConnectionSchedule::default();
        let slots: [WakerSlot; 4] = std::array::from_fn(|_| Arc::new(Mutex::new(None)));
        let mut reading: Option<ReadWork<()>> = Some(pending_with_waker(&slots[0]));
        let mut writing: Option<WriteWork<()>> = Some(pending_with_waker(&slots[1]));
        let mut requests: Vec<RequestWork> =
            vec![pending_with_waker(&slots[2]), pending_with_waker(&slots[3])];
        let old = Arc::new(WakeCount::default());
        let current = Arc::new(WakeCount::default());
        for counter in [&old, &current] {
            let waker = Waker::from(Arc::clone(counter));
            assert!(
                schedule
                    .poll(
                        &mut Context::from_waker(&waker),
                        &mut reading,
                        &mut writing,
                        &mut requests,
                        false,
                    )
                    .is_pending()
            );
            assert!(slots.iter().all(|slot| slot.lock().unwrap().is_some()));
        }
        for slot in &slots {
            let waker = slot.lock().unwrap().take().unwrap();
            waker.wake();
        }
        assert_eq!(old.0.load(Ordering::SeqCst), 0);
        assert_eq!(current.0.load(Ordering::SeqCst), 4);
    }
}

impl Server {
    /// A listen retains connection work and has its own finite lifetime. The
    /// ordinary handler timeout must not silently turn a subscription into a
    /// thirty-second request. The ambient caller's tighter ceiling still wins.
    pub(super) fn create_owned_modern_request_budget(&self, cx: &Cx, method: &str) -> Budget {
        if method == SUBSCRIPTIONS_LISTEN {
            cx.budget().meet(
                Budget::new().with_deadline(
                    cx.now().saturating_add_nanos(
                        SUBSCRIPTION_LIFETIME
                            .as_secs()
                            .saturating_mul(1_000_000_000),
                    ),
                ),
            )
        } else {
            self.create_request_budget(cx)
        }
    }

    /// Serves an NDJSON connection on caller-owned asynchronous I/O.
    ///
    /// Ingress, bounded concurrent requests, subscriptions, and backpressured
    /// egress all progress on the caller's asupersync runtime. Every application
    /// dispatch owns a child region; this function creates no runtime, thread, or
    /// blocking-pool job. Use native nonblocking pipe/socket handles: supplying
    /// an adapter that blocks in `poll_read` or `poll_write` does not make that
    /// adapter asynchronous. Own-process/child-process handle construction is
    /// the embedding's responsibility.
    ///
    /// [`ProtocolPolicy::ModernOnly`] fixes the final era before input. With
    /// `legacy-2024-11-05`, the ordinary [`ProtocolPolicy::Auto`] builder selects
    /// the era from one complete opening request, and [`ProtocolPolicy::LegacyOnly`]
    /// accepts only exact MCP 2024-11-05 initialization. Invalid or ambiguous
    /// opening traffic closes the connection after any role-correct refusal;
    /// the selected era never changes. A well-formed unsupported modern version
    /// selects modern and retains the ordinary per-request version refusal.
    /// Exact-2024 lifecycle and application calls run in bounded FIFO order;
    /// ingress continues delivering reverse replies and peer cancellation while
    /// a legacy handler is suspended. The no-legacy profile requires ModernOnly.
    /// Per-request authentication, raw-parameter admission, middleware, Tasks,
    /// MRTR, and subscription dispatch use the same server implementation as
    /// the other modern entrypoints.
    /// Subscriptions have a one-hour absolute lifetime, bounded further by the
    /// caller's context, independent of the ordinary handler timeout. Client
    /// subscription idle and reconnection policy remains client-owned.
    ///
    /// Peer cancellation suppresses every queued frame for its request. Cancelling
    /// an already partially written frame terminates the connection; a frame
    /// whose flush has completed is committed. Each write has a finite commit
    /// deadline and output retention shares the dispatch count/byte ceilings.
    /// Saturation is a connection failure, never silent loss of a final frame.
    ///
    /// Input EOF permits a five-second response drain, including subscription
    /// cancellation controls. Local cancellation preserves only the elected
    /// subscription controls and their queued event prefixes, under the same
    /// finite drain bound and the original caller deadline. At that bound or
    /// on failure, remaining request regions are cancelled and closed before
    /// the shutdown hook runs. A configured Task supervisor is ready before
    /// ingress starts and is settled before that hook runs, including after transport failure
    /// or caller cancellation. Non-cooperative spawned children remain owned
    /// and awaited; this API never detaches them merely to report a timeout.
    /// Dropping this future closes I/O and transfers region cleanup to the
    /// caller runtime's structured close machinery; it does not run a premature
    /// shutdown hook.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported policy, missing caller timer,
    /// startup failure, protocol-direction failure, output saturation,
    /// transport failure, or an exceeded graceful drain deadline.
    pub async fn serve_stdio_io<R, W>(self, cx: &Cx, reader: R, writer: W) -> McpResult<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        #[cfg(not(feature = "legacy-2024-11-05"))]
        if self.protocol_policy != ProtocolPolicy::ModernOnly {
            return Err(server_run_error(
                "startup",
                "protocol_policy",
                "Async stdio legacy policies require the legacy-2024-11-05 feature",
            ));
        }
        cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
        if cx.timer_driver().is_none() {
            return Err(server_run_error(
                "startup",
                "timer",
                "Async stdio requires the caller's timer driver",
            ));
        }
        #[cfg(feature = "console")]
        self.init_rich_logging();
        let server = Arc::new(self);
        if !server.run_startup_hook() {
            return Err(server_run_error(
                "startup",
                "hook",
                "Server startup hook failed",
            ));
        }
        #[cfg(feature = "tasks")]
        let hosted_tasks = match server.task_service_host.as_ref() {
            // Recovery can invoke application work immediately, so it must
            // follow successful application startup and precede ingress.
            Some(host) => match host.start_ready(cx).await {
                Ok(hosted) => Some(hosted),
                Err(failure) => {
                    // start_ready settles a failed child before returning.
                    server.run_shutdown_hook();
                    return Err(failure);
                }
            },
            None => None,
        };
        let (reader, writer) = AsyncStdioTransport::from_io(reader, writer).into_split();
        let (result, request_regions_quiescent) = Self::serve_modern_connection(
            Arc::clone(&server),
            cx,
            reader,
            writer,
            ConnectionBinding::stdio(),
            #[cfg(feature = "tasks")]
            hosted_tasks.as_ref(),
        )
        .await;
        #[cfg(feature = "tasks")]
        let result = match hosted_tasks {
            Some(hosted_tasks) => {
                // Settlement retains ownership through actual child exit,
                // including when it reports a deadline or supervisor error.
                result.and(hosted_tasks.settle(cx).await)
            }
            None => result,
        };
        if request_regions_quiescent {
            server.run_shutdown_hook();
        }
        result
    }

    /// Serves one bounded in-process connection on the caller's async runtime.
    ///
    /// Unlike a synchronous transport loop, a pending memory receive or a full
    /// response queue never blocks the executor. Independent request regions,
    /// wire cancellation, subscriptions, authentication, raw-source admission,
    /// and output bounds use the same native dispatcher as [`Self::serve_stdio_io`].
    /// The inbound transport remains `Memory`; this does not impersonate stdio
    /// or skip authentication because the peer happens to be in-process.
    ///
    /// Select [`ProtocolPolicy::ModernOnly`] before building. The caller must
    /// supply an asupersync runtime context with a timer driver. No reactor,
    /// helper thread, or blocking pool is needed for asynchronous handlers.
    /// A pending output send has the native finite commit deadline. Successful
    /// channel publication is final and is never retroactively cancelled.
    ///
    /// Dropping or closing the peer's send half starts a five-second response
    /// drain, so the peer may continue receiving accepted results. Keeping its
    /// receive half alive until EOF avoids turning that drain into a delivery
    /// failure. Caller cancellation stops ingress and cancels request regions.
    /// Startup precedes a configured Task supervisor; that service and request
    /// regions settle before shutdown. Dropping this future leaves structured
    /// region cleanup to the caller runtime rather than invoking shutdown early.
    ///
    /// # Errors
    ///
    /// Returns policy, missing-timer, startup, protocol-direction, transport,
    /// output-capacity, task-service, or graceful-drain failures to the caller.
    pub async fn serve_memory(self, cx: &Cx, transport: MemoryTransport) -> McpResult<()> {
        if self.protocol_policy != ProtocolPolicy::ModernOnly {
            return Err(server_run_error(
                "startup",
                "protocol_policy",
                "Async memory serving requires ModernOnly policy",
            ));
        }
        cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
        if cx.timer_driver().is_none() {
            return Err(server_run_error(
                "startup",
                "timer",
                "Async memory serving requires the caller's timer driver",
            ));
        }
        #[cfg(feature = "console")]
        self.init_rich_logging();
        let server = Arc::new(self);
        if !server.run_startup_hook() {
            return Err(server_run_error(
                "startup",
                "hook",
                "Server startup hook failed",
            ));
        }
        #[cfg(feature = "tasks")]
        let hosted_tasks = match server.task_service_host.as_ref() {
            Some(host) => match host.start_ready(cx).await {
                Ok(hosted) => Some(hosted),
                Err(failure) => {
                    server.run_shutdown_hook();
                    return Err(failure);
                }
            },
            None => None,
        };
        let (reader, writer) = transport.into_split();
        let (result, request_regions_quiescent) = Self::serve_modern_connection(
            Arc::clone(&server),
            cx,
            reader,
            writer,
            ConnectionBinding {
                transport: InboundRequestTransport::Memory,
                authorization: TransportAuthorization::default(),
                auth_custody: None,
                auth_generation: None,
            },
            #[cfg(feature = "tasks")]
            hosted_tasks.as_ref(),
        )
        .await;
        #[cfg(feature = "tasks")]
        let result = match hosted_tasks {
            Some(hosted_tasks) => result.and(hosted_tasks.settle(cx).await),
            None => result,
        };
        if request_regions_quiescent {
            server.run_shutdown_hook();
        }
        result
    }

    /// The listener owns startup, the shared Task service, and shutdown.
    /// Each upgraded modern connection owns only its native I/O, requests,
    /// and output; closing it cannot terminate a sibling's subscriptions.
    #[cfg(feature = "websocket")]
    pub(super) async fn serve_modern_websocket<IO>(
        self: Arc<Self>,
        cx: &Cx,
        transport: fastmcp_transport::websocket::AsyncWsServerTransport<IO>,
        authorization: TransportAuthorization,
        auth_custody: Arc<WebSocketAuthCustody>,
        connection_generation: u64,
    ) -> McpResult<()>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
        if cx.timer_driver().is_none() {
            return Err(server_run_error(
                "startup",
                "timer",
                "Native WebSocket serving requires the caller's timer driver",
            ));
        }
        let (reader, writer) = transport.into_split();
        Self::serve_modern_connection(
            self,
            cx,
            reader,
            writer,
            ConnectionBinding {
                transport: InboundRequestTransport::WebSocket,
                authorization,
                auth_custody: Some(AuthDispatchCustody::WebSocket(auth_custody)),
                auth_generation: Some(connection_generation),
            },
            #[cfg(feature = "tasks")]
            None,
        )
        .await
        .0
    }

    async fn serve_modern_connection<R: ConnectionReader, W: ConnectionWriter>(
        server: Arc<Self>,
        cx: &Cx,
        reader: R,
        writer: W,
        binding: ConnectionBinding,
        #[cfg(feature = "tasks")] hosted_tasks: Option<&tasks::HostedTaskService>,
    ) -> (McpResult<()>, bool) {
        #[cfg(feature = "tasks")]
        let mut task_service_check = hosted_tasks.as_ref().map(|_| {
            Box::pin(asupersync::time::sleep(
                cx.now(),
                TASK_SERVICE_HEALTH_INTERVAL,
            ))
        });
        if let Some(stats) = &server.stats {
            stats.connection_opened();
        }
        let lifetime = ConnectionLifetime {
            server: Arc::clone(&server),
            connection: ModernConnection::new(),
            admission: Arc::new(DispatchQueueState::default()),
            output: Arc::new(OutputQueue::default()),
            binding,
        };
        #[cfg(feature = "legacy-2024-11-05")]
        let mut protocol = NativeProtocol::new(
            if matches!(lifetime.binding.transport, InboundRequestTransport::Stdio) {
                server.protocol_policy
            } else {
                // Memory and WebSocket retain their existing ModernOnly binding.
                ProtocolPolicy::ModernOnly
            },
        );
        let mut reading = Some(receive(reader, cx.clone()));
        // A terminal opening refusal must retain the receive half until its
        // response drains: dropping native stdio's reader closes the shared
        // transport terminal and would otherwise suppress the queued error.
        let mut dormant_reader: Option<R> = None;
        // A pending receive owns the live read half. Keep it without polling
        // during local shutdown: dropping it would also close the writer
        // before the elected subscription controls can flush.
        let mut suspended_read: Option<ReadWork<R>> = None;
        let mut available_writer = Some(writer);
        let mut writing: Option<WriteWork<W>> = None;
        let mut requests: Vec<RequestWork> = Vec::new();
        let mut drain: Option<Pin<Box<Sleep>>> = None;
        let mut stopping = false;
        let mut subscription_shutdown: Option<NativeSubscriptionShutdown> = None;
        let mut error = None;
        let mut request_regions_quiescent = true;
        let mut schedule = ConnectionSchedule::default();
        loop {
            if let Some(shutdown) = &mut subscription_shutdown
                && shutdown.receipt.elections_settled()
            {
                if !shutdown.admission_stopped {
                    // The won callbacks must publish their outcome before
                    // generic request cancellation can retire their leases.
                    lifetime.admission.stop();
                    shutdown.admission_stopped = true;
                }
                lifetime.output.retain_subscription_drain();
            }
            if !stopping
                && subscription_shutdown.as_ref().is_none_or(|shutdown| shutdown.admission_stopped)
                && writing.is_none()
                && lifetime.output.has_frames()
            {
                if let Some(frame) = lifetime.output.pop() {
                    writing = Some(write(
                        available_writer.take().expect("one owned async writer"),
                        cx.clone(),
                        frame,
                        Arc::clone(&lifetime.output),
                    ));
                }
            }
            if reading.is_none()
                && requests.is_empty()
                && writing.is_none()
                && !lifetime.output.has_frames()
                && (stopping || lifetime.output.failure().is_none())
                && (stopping || subscription_shutdown.is_none())
            {
                break;
            }
            let mut changed = pin!(lifetime.output.changed.notified());
            let event = poll_fn(|task| {
                let _caller = Cx::set_current(Some(cx.clone()));
                let _ = changed.as_mut().poll(task);
                if !stopping {
                    if let Some(kind) = lifetime.output.failure() {
                        return Poll::Ready(Event::Stop(Some(server_run_error(
                            "send",
                            kind,
                            "Native connection output capacity exhausted",
                        ))));
                    }
                    if subscription_shutdown.is_none() && cx.checkpoint().is_err() {
                        return Poll::Ready(Event::Stop(None));
                    }
                    #[cfg(feature = "tasks")]
                    if subscription_shutdown.is_none()
                        && let Some(hosted_tasks) = hosted_tasks.as_ref()
                    {
                        if let Err(failure) = hosted_tasks.check_running() {
                            return Poll::Ready(Event::Stop(Some(failure)));
                        }
                        // A failed service must stop a silent connection as
                        // well as one actively supplying request frames.
                        if task_service_check
                            .as_mut()
                            .is_some_and(|check| check.as_mut().poll(task).is_ready())
                        {
                            return Poll::Ready(Event::TaskServiceCheck);
                        }
                    }
                    let drain_expired = if let Some(shutdown) = &subscription_shutdown {
                        cx.now() >= shutdown.deadline
                            || drain.as_mut().is_some_and(|drain| {
                                cx.masked(|| drain.as_mut().poll(task)).is_ready()
                            })
                    } else {
                        drain.as_mut().is_some_and(|drain| drain.as_mut().poll(task).is_ready())
                    };
                    if drain_expired {
                        return Poll::Ready(Event::DrainExpired);
                    }
                    if let Some(shutdown) = &subscription_shutdown {
                        if !shutdown.admission_stopped {
                            // A callback on another thread may still own the
                            // exact election. Yield, bounded by the same drain
                            // deadline, without polling request cancellation
                            // or discarding its queued acknowledgement.
                            return Poll::Ready(Event::Output);
                        }
                        if writing.is_none()
                            && !lifetime.output.has_frames()
                            && shutdown.receipt.is_settled()
                        {
                            return Poll::Ready(Event::Stop(None));
                        }
                    }
                }
                if let Poll::Ready(event) =
                    schedule.poll(task, &mut reading, &mut writing, &mut requests, stopping)
                {
                    return Poll::Ready(event);
                }
                if !stopping && writing.is_none() && lifetime.output.has_frames() {
                    return Poll::Ready(Event::Output);
                }
                Poll::Pending
            })
            .await;
            let mut stop = false;
            match event {
                Event::Read(reader, result) => {
                    reading = None;
                    match result {
                        Ok(frame) => {
                            #[cfg(feature = "legacy-2024-11-05")]
                            let admission = protocol.prepare(&lifetime, cx, frame);
                            #[cfg(not(feature = "legacy-2024-11-05"))]
                            let admission = prepare_request(&lifetime, cx, frame)
                                .map(ConnectionAdmission::Continue);
                            match admission {
                                Ok(ConnectionAdmission::Continue(work)) => {
                                    if let Some(work) = work {
                                        requests.push(work);
                                    }
                                    reading = Some(receive(reader, cx.clone()));
                                }
                                #[cfg(feature = "legacy-2024-11-05")]
                                Ok(ConnectionAdmission::Close) => {
                                    dormant_reader = Some(reader);
                                    error.get_or_insert(server_run_error(
                                        "receive",
                                        "protocol_era",
                                        "Native connection rejected protocol-era traffic",
                                    ));
                                    lifetime.admission.stop();
                                    protocol.finish_input();
                                    lifetime.output.discard_cancelled();
                                    drain = Some(Box::pin(asupersync::time::sleep(
                                        cx.now(),
                                        DISPATCH_WORKER_SHUTDOWN_TIMEOUT,
                                    )));
                                }
                                Err(failure) => {
                                    error.get_or_insert(failure);
                                    stop = true;
                                }
                            }
                        }
                        Err(TransportError::Closed) => {
                            if matches!(
                                lifetime.binding.transport,
                                InboundRequestTransport::Stdio | InboundRequestTransport::Memory
                            ) {
                                // Both are owned single connections with independent
                                // receive/send halves. Input EOF must not discard
                                // responses the peer is still waiting to receive.
                                #[cfg(feature = "legacy-2024-11-05")]
                                let modern = {
                                    protocol.finish_input();
                                    matches!(protocol, NativeProtocol::Modern)
                                };
                                #[cfg(not(feature = "legacy-2024-11-05"))]
                                let modern = true;
                                if modern {
                                    let _ = server.terminate_subscription_streams_for_shutdown();
                                    lifetime.admission.cancel_uncorrelated_modern_children();
                                }
                                drain = Some(Box::pin(asupersync::time::sleep(
                                    cx.now(),
                                    DISPATCH_WORKER_SHUTDOWN_TIMEOUT,
                                )));
                            } else {
                                // WebSocket Close has already closed output;
                                // cancelling this connection's reservations
                                // must preserve other live peer connections.
                                stop = true;
                            }
                        }
                        Err(TransportError::Cancelled) => {
                            dormant_reader = Some(reader);
                            stop = true;
                        }
                        Err(failure) => {
                            #[cfg(feature = "legacy-2024-11-05")]
                            let terminal_opening = protocol.needs_opening();
                            #[cfg(not(feature = "legacy-2024-11-05"))]
                            let terminal_opening = false;
                            match classify_receive_error(&failure) {
                                ReceiveErrorDisposition::ReplyWithParseError => {
                                    lifetime
                                        .output
                                        .enqueue(error_response(None, -32700, "Parse error"), None);
                                    if terminal_opening {
                                        dormant_reader = Some(reader);
                                    } else {
                                        reading = Some(receive(reader, cx.clone()));
                                    }
                                }
                                ReceiveErrorDisposition::ReplyWithInvalidRequest(id) => {
                                    lifetime.output.enqueue(
                                        error_response(id, -32600, "Invalid Request"),
                                        None,
                                    );
                                    if terminal_opening {
                                        dormant_reader = Some(reader);
                                    } else {
                                        reading = Some(receive(reader, cx.clone()));
                                    }
                                }
                                ReceiveErrorDisposition::Terminate => {
                                    error.get_or_insert(transport_run_error("receive", &failure));
                                    stop = true;
                                }
                            }
                            if terminal_opening && !stop {
                                error.get_or_insert(server_run_error(
                                    "receive",
                                    "protocol_opening",
                                    "Native connection opening frame was malformed",
                                ));
                                drain = Some(Box::pin(asupersync::time::sleep(
                                    cx.now(),
                                    DISPATCH_WORKER_SHUTDOWN_TIMEOUT,
                                )));
                            }
                        }
                    }
                }
                Event::Written(writer, result, bytes) => {
                    writing = None;
                    available_writer = Some(writer);
                    lifetime.output.finish(bytes);
                    if let Err(failure) = result {
                        error.get_or_insert(transport_run_error("send", &failure));
                        stop = true;
                    }
                }
                Event::Completed(index, result) => {
                    drop(requests.swap_remove(index));
                    if let Err(failure) = result {
                        // These failures are region-open/cancel/close failures.
                        // An unavailable runtime cannot provide a quiescence
                        // receipt; do not run application shutdown over work
                        // whose closure was merely requested by Drop.
                        request_regions_quiescent = false;
                        error.get_or_insert(failure);
                        stop = true;
                    }
                }
                Event::Output => {}
                #[cfg(feature = "tasks")]
                Event::TaskServiceCheck => {
                    task_service_check = Some(Box::pin(asupersync::time::sleep(
                        cx.now(),
                        TASK_SERVICE_HEALTH_INTERVAL,
                    )));
                }
                Event::Stop(failure) => {
                    if let Some(failure) = failure {
                        error.get_or_insert(failure);
                    }
                    stop = true;
                }
                Event::DrainExpired => {
                    error.get_or_insert(server_run_error(
                        "shutdown",
                        "drain_timeout",
                        "Native connection response drain exceeded its deadline",
                    ));
                    stop = true;
                }
            }
            if stop && !stopping {
                #[cfg(feature = "legacy-2024-11-05")]
                let modern = matches!(protocol, NativeProtocol::Modern);
                #[cfg(not(feature = "legacy-2024-11-05"))]
                let modern = true;
                if subscription_shutdown.is_none()
                    && error.is_none()
                    && modern
                    && matches!(lifetime.binding.transport, InboundRequestTransport::Stdio)
                    && cx.checkpoint().is_err()
                {
                    let maximum = cx.now().saturating_add_nanos(
                        u64::try_from(DISPATCH_WORKER_SHUTDOWN_TIMEOUT.as_nanos())
                            .unwrap_or(u64::MAX),
                    );
                    let deadline = cx.budget().deadline.map_or(maximum, |original| original.min(maximum));
                    let receipt = server.final_subscriptions.terminate_with_receipt();
                    if receipt.terminated != 0 || lifetime.output.has_subscription_drain() {
                        lifetime.output.begin_subscription_drain(deadline);
                        suspended_read = reading.take();
                        drain = Some(Box::pin(Sleep::new(deadline)));
                        subscription_shutdown = Some(NativeSubscriptionShutdown {
                            receipt,
                            deadline,
                            admission_stopped: false,
                        });
                        asupersync::runtime::yield_now().await;
                        continue;
                    }
                }
                if let Some(shutdown) = &subscription_shutdown {
                    shutdown.receipt.fail_pending();
                }
                stopping = true;
                lifetime.admission.stop();
                #[cfg(feature = "legacy-2024-11-05")]
                protocol.finish_input();
                lifetime.connection.disconnect();
                lifetime.output.stop();
                reading = None;
                writing = None;
                available_writer = None;
                drop(suspended_read.take());
                drop(dormant_reader.take());
                drain = None;
            }
            // A peer continuously supplying complete frames must not monopolize
            // the embedding's cooperative executor, even when every poll is ready.
            asupersync::runtime::yield_now().await;
        }
        if let Some(mut writer) = available_writer {
            let mut closing = pin!(asupersync::time::timeout(
                cx.now(),
                STDIO_OUTPUT_COMMIT_TIMEOUT,
                writer.close(cx),
            ));
            let close = poll_fn(|task| {
                let _caller = Cx::set_current(Some(cx.clone()));
                closing.as_mut().poll(task)
            })
            .await;
            match close {
                Ok(Ok(())) => {}
                Ok(Err(failure)) => {
                    error.get_or_insert(transport_run_error("close", &failure));
                }
                Err(_) => {
                    error.get_or_insert(transport_run_error("close", &TransportError::Timeout));
                }
            }
        }
        drop(dormant_reader);
        drop(lifetime);
        (error.map_or(Ok(()), Err), request_regions_quiescent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lib_unit_tests::RunnableClock;
    use asupersync::io::ReadBuf;
    use asupersync::net::{TcpListener, TcpStream};
    use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
    use fastmcp_protocol::{Content, Tool};
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Waker};

    mod output_cancellation {
        use super::*;
        use std::task::Wake;

        fn owner(admission: &Arc<DispatchQueueState>, id: i64) -> Arc<OutputOwner> {
            let JsonRpcMessage::Request(request) = discover(id) else {
                unreachable!()
            };
            Arc::new(OutputOwner {
                reservation: admission
                    .admit_modern_request(&request, Arc::new(AtomicBool::new(false)))
                    .expect("one bounded request reservation"),
                log_level: None,
                subscription_terminal: None,
                #[cfg(feature = "legacy-2024-11-05")]
                legacy: None,
            })
        }

        fn response(id: i64) -> JsonRpcMessage {
            JsonRpcMessage::Response(JsonRpcResponse::success(
                RequestId::Number(id),
                serde_json::json!({"resultType": "complete"}),
            ))
        }

        fn progress(value: usize) -> JsonRpcMessage {
            JsonRpcMessage::Request(JsonRpcRequest::notification(
                "notifications/progress",
                Some(serde_json::json!({"progressToken": 7, "progress": value})),
            ))
        }

        fn retained(queue: &OutputQueue) -> (usize, usize, usize) {
            let state = queue.state.lock().unwrap();
            (
                state.frames.len(),
                state.retained_frames,
                state.retained_bytes,
            )
        }

        #[test]
        fn cancellation_reclaims_capacity_behind_an_unrelated_blocked_write() {
            for cancelled in [false, true] {
                let admission = Arc::new(DispatchQueueState::default());
                let pending = owner(&admission, 7);
                let queue = OutputQueue::default();
                queue.enqueue(response(1), None);
                let writing = queue.pop().unwrap();
                for value in 0..MAX_DISPATCH_QUEUE_DEPTH - 1 {
                    queue.enqueue(progress(value), Some(Arc::clone(&pending)));
                }
                assert!(queue.failure().is_none());
                assert_eq!(retained(&queue).1, MAX_DISPATCH_QUEUE_DEPTH);
                if cancelled {
                    pending.reservation.cancellation.cancel();
                }
                let reclaimed = queue.discard_cancelled();
                if cancelled {
                    assert_eq!(reclaimed, MAX_DISPATCH_QUEUE_DEPTH - 1);
                    assert_eq!(retained(&queue), (0, 1, writing.bytes));
                } else {
                    assert_eq!(reclaimed, 0);
                }
                // Only the cancellation bit differs. No peer drain, output
                // completion, or increased limit creates capacity here.
                queue.enqueue(response(9), None);
                assert_eq!(queue.failure().is_none(), cancelled);
                if cancelled {
                    let next = queue.pop().unwrap();
                    assert!(matches!(next.message, JsonRpcMessage::Response(ref result)
                        if result.id == Some(RequestId::Number(9))));
                    queue.finish(next.bytes);
                    assert_eq!(retained(&queue), (0, 1, writing.bytes));
                } else {
                    assert_eq!(queue.failure(), Some("output_capacity"));
                }
                queue.finish(writing.bytes);
            }
        }

        #[test]
        fn reclamation_preserves_live_and_ownerless_fifo_and_exact_byte_charges() {
            let admission = Arc::new(DispatchQueueState::default());
            let cancelled = owner(&admission, 1);
            let live = owner(&admission, 3);
            let queue = OutputQueue::default();
            queue.enqueue(progress(1), Some(Arc::clone(&cancelled)));
            queue.enqueue(response(2), None);
            queue.enqueue(response(3), Some(Arc::clone(&live)));
            queue.enqueue(progress(4), Some(Arc::clone(&cancelled)));
            queue.enqueue(response(5), None);
            let expected_bytes = {
                let state = queue.state.lock().unwrap();
                state
                    .frames
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| matches!(*index, 1 | 2 | 4))
                    .map(|(_, frame)| frame.bytes)
                    .sum::<usize>()
            };
            cancelled.reservation.cancellation.cancel();
            assert_eq!(queue.discard_cancelled(), 2);
            assert_eq!(retained(&queue), (3, 3, expected_bytes));
            assert!(!live.cancelled());
            for id in [2, 3, 5] {
                let frame = queue.pop().unwrap();
                assert!(matches!(frame.message, JsonRpcMessage::Response(ref result)
                    if result.id == Some(RequestId::Number(id))));
                queue.finish(frame.bytes);
            }
            assert_eq!(retained(&queue), (0, 0, 0));
            assert_eq!(queue.discard_cancelled(), 0);
        }

        #[test]
        fn reclamation_does_not_release_or_reclassify_the_in_flight_frame() {
            let admission = Arc::new(DispatchQueueState::default());
            let pending = owner(&admission, 7);
            let queue = OutputQueue::default();
            queue.enqueue(progress(1), Some(Arc::clone(&pending)));
            queue.enqueue(progress(2), Some(Arc::clone(&pending)));
            let writing = queue.pop().unwrap();
            pending.reservation.cancellation.cancel();
            assert_eq!(queue.discard_cancelled(), 1);
            assert_eq!(retained(&queue), (0, 1, writing.bytes));
            assert!(writing.owner.as_ref().unwrap().cancelled());
            // The existing writer still owns cancellation/partial-write
            // handling and must perform its one final capacity release.
            queue.finish(writing.bytes);
            assert_eq!(retained(&queue), (0, 0, 0));
            assert_eq!(queue.discard_cancelled(), 0);
        }

        #[derive(Default)]
        struct Wakes(AtomicUsize);

        impl Wake for Wakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        #[test]
        fn reclamation_drops_the_last_reservation_and_wakes_the_queue_observer() {
            let admission = Arc::new(DispatchQueueState::default());
            let pending = owner(&admission, 7);
            let weak = Arc::downgrade(&pending);
            let queue = OutputQueue::default();
            queue.enqueue(progress(1), Some(Arc::clone(&pending)));
            pending.reservation.cancellation.cancel();
            drop(pending);
            assert!(weak.upgrade().is_some());
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut task = Context::from_waker(&waker);
            let mut changed = pin!(queue.changed.notified());
            assert!(changed.as_mut().poll(&mut task).is_pending());
            assert_eq!(queue.discard_cancelled(), 1);
            assert!(weak.upgrade().is_none(), "queued ownership was retained");
            assert_eq!(retained(&queue), (0, 0, 0));
            assert!(wakes.0.load(Ordering::SeqCst) > 0);
            assert!(changed.as_mut().poll(&mut task).is_ready());
            // Retirement really releases admission, not merely its displayed
            // byte count. The same ID can now acquire a fresh reservation.
            let replacement = owner(&admission, 7);
            assert!(!replacement.cancelled());
        }

        #[test]
        fn reclamation_cannot_revive_a_terminal_output_failure() {
            let admission = Arc::new(DispatchQueueState::default());
            let pending = owner(&admission, 7);
            let queue = OutputQueue::default();
            for value in 0..=MAX_DISPATCH_QUEUE_DEPTH {
                queue.enqueue(progress(value), Some(Arc::clone(&pending)));
            }
            assert_eq!(queue.failure(), Some("output_capacity"));
            pending.reservation.cancellation.cancel();
            assert_eq!(queue.discard_cancelled(), MAX_DISPATCH_QUEUE_DEPTH);
            assert_eq!(retained(&queue), (0, 0, 0));
            queue.enqueue(response(9), None);
            assert_eq!(queue.failure(), Some("output_capacity"));
            assert_eq!(retained(&queue), (0, 0, 0));
        }

        fn admitted(message: &JsonRpcMessage) -> ReceivedTransportFrame {
            ReceivedTransportFrame::admit(serde_json::to_vec(message).unwrap().into_boxed_slice())
                .unwrap()
        }

        #[test]
        fn cancellation_ingress_reclaims_only_the_matching_request_and_preserves_siblings() {
            let cx = Cx::for_testing();
            let lifetime = ConnectionLifetime {
                server: Arc::new(
                    Server::new("output-cancel", "1")
                        .protocol_policy(ProtocolPolicy::ModernOnly)
                        .unwrap()
                        .build(),
                ),
                connection: ModernConnection::new(),
                admission: Arc::new(DispatchQueueState::default()),
                output: Arc::new(OutputQueue::default()),
                binding: ConnectionBinding::stdio(),
            };
            // Authentication and reservation take place before any handler
            // poll. Keep both real request futures owned while routing controls.
            let first = prepare_request(&lifetime, &cx, admitted(&discover(41)))
                .unwrap()
                .unwrap();
            let second = prepare_request(&lifetime, &cx, admitted(&discover(42)))
                .unwrap()
                .unwrap();
            let find_owner = |id: i64| {
                lifetime
                    .output
                    .state
                    .lock()
                    .unwrap()
                    .candidates
                    .values()
                    .filter_map(Weak::upgrade)
                    .find(|owner| {
                        owner.reservation.request_id.as_ref() == Some(&RequestId::Number(id))
                    })
                    .expect("admitted request has an output owner")
            };
            let first_owner = find_owner(41);
            let second_owner = find_owner(42);
            lifetime
                .output
                .enqueue(response(41), Some(Arc::clone(&first_owner)));
            lifetime
                .output
                .enqueue(response(42), Some(Arc::clone(&second_owner)));
            assert_eq!(retained(&lifetime.output).0, 2);
            assert!(
                prepare_request(&lifetime, &cx, admitted(&cancel(999)))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(retained(&lifetime.output).0, 2);
            assert!(!first_owner.cancelled() && !second_owner.cancelled());
            assert!(
                prepare_request(&lifetime, &cx, admitted(&cancel(41)))
                    .unwrap()
                    .is_none()
            );
            assert!(first_owner.cancelled());
            assert!(!second_owner.cancelled());
            assert_eq!(retained(&lifetime.output).0, 1);
            let survivor = lifetime.output.pop().unwrap();
            assert!(
                matches!(survivor.message, JsonRpcMessage::Response(ref result)
                if result.id == Some(RequestId::Number(42)))
            );
            lifetime.output.finish(survivor.bytes);
            assert_eq!(retained(&lifetime.output), (0, 0, 0));
            drop((first, second));
        }
    }

    #[derive(Default)]
    struct Gate {
        released: AtomicBool,
        entered: AtomicUsize,
        dropped: AtomicUsize,
        changed: Notify,
    }

    impl Gate {
        fn release(&self) {
            self.released.store(true, Ordering::Release);
            self.changed.notify_waiters();
        }
    }

    struct ProbeTool(Arc<Gate>);

    impl ToolHandler for ProbeTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "async_probe".to_owned(),
                description: None,
                input_schema: serde_json::json!({"type":"object","properties":{"hold":{"type":"boolean"}},"required":["hold"],"additionalProperties":false}),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }
        fn execution_mode(&self) -> ToolExecutionMode {
            ToolExecutionMode::Async
        }
        fn call(&self, _: &McpContext, _: serde_json::Value) -> McpResult<Vec<Content>> {
            panic!("async stdio must call the declared asynchronous hook")
        }
        fn call_async<'a>(
            &'a self,
            _: &'a McpContext,
            arguments: serde_json::Value,
        ) -> BoxFuture<'a, fastmcp_core::McpOutcome<Vec<Content>>> {
            Box::pin(async move {
                struct Dropped<'a>(&'a AtomicUsize);
                impl Drop for Dropped<'_> {
                    fn drop(&mut self) {
                        self.0.fetch_add(1, Ordering::AcqRel);
                    }
                }
                let _dropped = Dropped(&self.0.dropped);
                self.0.entered.fetch_add(1, Ordering::AcqRel);
                if arguments["hold"] == true {
                    self.0
                        .changed
                        .wait_until(|| self.0.released.load(Ordering::Acquire))
                        .await;
                }
                asupersync::Outcome::Ok(vec![Content::text("executed")])
            })
        }

        fn call_final_outcome_async<'a>(
            &'a self,
            ctx: &'a McpContext,
            arguments: serde_json::Value,
        ) -> BoxFuture<'a, fastmcp_core::McpOutcome<crate::FinalToolOutcome>> {
            Box::pin(async move {
                match self.call_async(ctx, arguments).await {
                    asupersync::Outcome::Ok(content) => {
                        match crate::handler::promote_legacy_tool_content(content) {
                            Ok(result) => {
                                asupersync::Outcome::Ok(crate::FinalToolOutcome::Complete(result))
                            }
                            Err(error) => asupersync::Outcome::Err(error),
                        }
                    }
                    asupersync::Outcome::Err(error) => asupersync::Outcome::Err(error),
                    asupersync::Outcome::Cancelled(reason) => {
                        asupersync::Outcome::Cancelled(reason)
                    }
                    asupersync::Outcome::Panicked(panic) => asupersync::Outcome::Panicked(panic),
                }
            })
        }
    }

    fn request(id: i64, method: &str, mut params: serde_json::Value) -> JsonRpcMessage {
        params["_meta"] = serde_json::json!({
            fastmcp_protocol::FINAL_PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_VERSION,
            fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY: {},
        });
        JsonRpcMessage::Request(JsonRpcRequest::new(method, Some(params), id))
    }

    fn discover(id: i64) -> JsonRpcMessage {
        request(id, "server/discover", serde_json::json!({}))
    }
    fn call(id: i64, hold: bool) -> JsonRpcMessage {
        request(
            id,
            "tools/call",
            serde_json::json!({"name":"async_probe", "arguments":{"hold":hold}}),
        )
    }
    /// A `tools/call` frame whose exact `params` source is `raw_bytes` long,
    /// padded with insignificant whitespace so its typed value stays small.
    fn padded_call(id: i64, hold: bool, raw_bytes: usize) -> Vec<u8> {
        let JsonRpcMessage::Request(request) = call(id, hold) else {
            unreachable!()
        };
        let params = serde_json::to_string(request.params.as_ref().unwrap()).unwrap();
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{{}{}}}}}\n",
            " ".repeat(raw_bytes - params.len()),
            &params[1..params.len() - 1]
        )
        .into_bytes()
    }
    fn cancel(id: i64) -> JsonRpcMessage {
        JsonRpcMessage::Request(JsonRpcRequest::notification(
            "notifications/cancelled",
            Some(serde_json::json!({
                "requestId": id, "_meta": {fastmcp_protocol::FINAL_PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_VERSION},
            })),
        ))
    }
    fn encoded(message: &JsonRpcMessage) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(message).unwrap();
        bytes.push(b'\n');
        bytes
    }
    fn server(gate: &Arc<Gate>) -> Server {
        Server::new("async-stdio", "1.0")
            .protocol_policy(ProtocolPolicy::ModernOnly)
            .expect("modern-only policy is available")
            .tool(ProbeTool(Arc::clone(gate)))
            .build()
    }
    fn run<F, Fut>(test: F)
    where
        F: FnOnce(Cx) -> Fut,
        Fut: Future<Output = ()>,
    {
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .blocking_threads(0, 16)
            .build()
            .unwrap();
        runtime.block_on(async { test(Cx::current().unwrap()).await });
    }

    #[cfg(feature = "websocket")]
    mod native_websocket_tests {
        use super::*;
        use fastmcp_transport::websocket::AsyncWsClientTransport;

        type Peer = AsyncWsClientTransport<TcpStream>;
        type Serving = asupersync::runtime::TaskHandle<McpResult<WebSocketServerShutdown>>;

        fn run_native<F, Fut>(test: F)
        where
            F: FnOnce(Cx) -> Fut,
            Fut: Future<Output = ()>,
        {
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(create_reactor().unwrap())
                .blocking_threads(0, 0)
                .build()
                .unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                assert!(cx.blocking_pool_handle().is_none());
                // The old inline blocking bridge prevents even the runtime's
                // timer from being polled. This test-only watchdog cancels
                // its context so that regression fails rather than hanging.
                let watchdog_cx = cx.clone();
                let (finished, completion) = std::sync::mpsc::sync_channel::<()>(1);
                let watchdog = std::thread::spawn(move || {
                    if matches!(
                        completion.recv_timeout(Duration::from_secs(10)),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    ) {
                        watchdog_cx.cancel_with(
                            CancelKind::Deadline,
                            Some("native WebSocket test made no runtime progress"),
                        );
                        true
                    } else {
                        false
                    }
                });
                let result =
                    asupersync::time::timeout(cx.now(), Duration::from_secs(8), test(cx.clone()))
                        .await;
                let _ = finished.send(());
                assert!(
                    !watchdog.join().unwrap(),
                    "native bridge blocked its runtime"
                );
                result.expect("native WebSocket operation exceeded its bound");
            });
        }

        async fn connect(cx: &Cx, service: Server) -> (Peer, Serving, SocketAddr) {
            let bound = service.bind_websocket(cx, "127.0.0.1:0").await.unwrap();
            let address = bound.local_addr().unwrap();
            let serving = cx
                .spawn(move |serve_cx| async move { bound.serve(&serve_cx).await })
                .unwrap();
            let peer = Peer::connect(cx, &format!("ws://{address}/mcp"))
                .await
                .unwrap();
            (peer, serving, address)
        }

        async fn response(cx: &Cx, peer: &mut Peer, id: i64, forbidden: &[i64]) -> JsonRpcResponse {
            loop {
                let message = peer.recv(cx).await.unwrap();
                if let JsonRpcMessage::Response(response) = message {
                    assert!(
                        !forbidden.iter().any(|id| response.id == Some((*id).into())),
                        "cancelled request emitted a late result: {response:?}"
                    );
                    if response.id == Some(id.into()) {
                        return response;
                    }
                    panic!("unexpected response while awaiting {id}: {response:?}");
                }
            }
        }

        async fn acknowledge(cx: &Cx, peer: &mut Peer, id: i64) {
            peer.send(
                cx,
                &request(
                    id,
                    SUBSCRIPTIONS_LISTEN,
                    serde_json::json!({"notifications":{"toolsListChanged":true}}),
                ),
            )
            .await
            .unwrap();
            let JsonRpcMessage::Request(acknowledgement) = peer.recv(cx).await.unwrap() else {
                panic!("listen must acknowledge before any terminal response");
            };
            assert_eq!(
                acknowledgement.method,
                fastmcp_protocol::methods::NOTIFICATIONS_SUBSCRIPTIONS_ACKNOWLEDGED,
            );
            assert_eq!(
                acknowledgement.params.unwrap()["_meta"]["io.modelcontextprotocol/subscriptionId"],
                serde_json::json!(id),
            );
        }

        async fn stop(cx: &Cx, mut peer: Peer, mut serving: Serving) {
            peer.close(cx).await.unwrap();
            drop(peer);
            serving.abort();
            assert!(matches!(
                serving.join(cx).await.unwrap().unwrap(),
                WebSocketServerShutdown::Quiescent
            ));
        }

        #[test]
        fn native_websocket_server_multiplexes_without_blocking_pool() {
            run_native(|cx| async move {
                let gate = Arc::new(Gate::default());
                let (mut peer, serving, _) = connect(&cx, server(&gate)).await;
                peer.send(&cx, &discover(100)).await.unwrap();
                assert!(response(&cx, &mut peer, 100, &[]).await.error.is_none());
                peer.send(&cx, &call(101, true)).await.unwrap();
                until(&cx, || gate.entered.load(Ordering::Acquire) == 1).await;
                peer.send(&cx, &call(102, false)).await.unwrap();
                assert!(response(&cx, &mut peer, 102, &[]).await.error.is_none());
                assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
                gate.release();
                assert!(response(&cx, &mut peer, 101, &[]).await.error.is_none());
                stop(&cx, peer, serving).await;
                assert_eq!(gate.dropped.load(Ordering::Acquire), 2);
                assert!(cx.checkpoint().is_ok());
            });
        }

        #[test]
        fn native_websocket_server_cancellation_isolates_pending_call_and_listener() {
            run_native(|cx| async move {
                let gate = Arc::new(Gate::default());
                let (mut peer, serving, _) = connect(&cx, server(&gate)).await;
                peer.send(&cx, &call(201, true)).await.unwrap();
                until(&cx, || gate.entered.load(Ordering::Acquire) == 1).await;
                acknowledge(&cx, &mut peer, 202).await;
                peer.send(&cx, &cancel(201)).await.unwrap();
                until(&cx, || gate.dropped.load(Ordering::Acquire) == 1).await;
                peer.send(&cx, &call(203, false)).await.unwrap();
                assert!(
                    response(&cx, &mut peer, 203, &[201, 202])
                        .await
                        .error
                        .is_none()
                );
                peer.send(&cx, &cancel(202)).await.unwrap();
                peer.send(&cx, &discover(204)).await.unwrap();
                assert!(
                    response(&cx, &mut peer, 204, &[201, 202])
                        .await
                        .error
                        .is_none()
                );
                stop(&cx, peer, serving).await;
                assert_eq!(gate.dropped.load(Ordering::Acquire), 2);
                assert!(cx.checkpoint().is_ok());
            });
        }

        #[test]
        fn native_websocket_server_wrong_id_cancellation_preserves_pending_call() {
            run_native(|cx| async move {
                let gate = Arc::new(Gate::default());
                let (mut peer, serving, _) = connect(&cx, server(&gate)).await;
                peer.send(&cx, &call(201, true)).await.unwrap();
                until(&cx, || gate.entered.load(Ordering::Acquire) == 1).await;
                acknowledge(&cx, &mut peer, 202).await;
                // This case changes only the cancellation target above.
                peer.send(&cx, &cancel(999)).await.unwrap();
                peer.send(&cx, &call(203, false)).await.unwrap();
                assert!(
                    response(&cx, &mut peer, 203, &[201, 202])
                        .await
                        .error
                        .is_none()
                );
                assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
                gate.release();
                assert!(response(&cx, &mut peer, 201, &[202]).await.error.is_none());
                peer.send(&cx, &cancel(202)).await.unwrap();
                peer.send(&cx, &discover(204)).await.unwrap();
                assert!(response(&cx, &mut peer, 204, &[202]).await.error.is_none());
                stop(&cx, peer, serving).await;
                assert_eq!(gate.dropped.load(Ordering::Acquire), 2);
            });
        }

        #[test]
        fn native_websocket_server_rejects_cross_era_frame_before_dispatch() {
            run_native(|cx| async move {
                let gate = Arc::new(Gate::default());
                let (mut peer, serving, _) = connect(&cx, server(&gate)).await;
                peer.send(&cx, &discover(400)).await.unwrap();
                assert!(response(&cx, &mut peer, 400, &[]).await.error.is_none());
                let legacy = JsonRpcMessage::Request(JsonRpcRequest::new(
                    "initialize",
                    Some(serde_json::json!({
                        "protocolVersion":"2024-11-05", "capabilities":{},
                        "clientInfo":{"name":"cross-era-peer","version":"1"}
                    })),
                    401_i64,
                ));
                peer.send(&cx, &legacy).await.unwrap();
                assert!(response(&cx, &mut peer, 401, &[]).await.error.is_some());
                assert_eq!(gate.entered.load(Ordering::Acquire), 0);
                peer.send(&cx, &call(402, false)).await.unwrap();
                assert!(response(&cx, &mut peer, 402, &[]).await.error.is_none());
                assert_eq!(gate.entered.load(Ordering::Acquire), 1);
                stop(&cx, peer, serving).await;
            });
        }

        #[test]
        fn native_websocket_server_upgrade_custody_rejects_mixed_credentials() {
            run_native(|cx| async move {
                let gate = Arc::new(Gate::default());
                let (mut peer, serving, _) = connect(&cx, server(&gate)).await;
                let JsonRpcMessage::Request(mut mixed) = call(501, false) else {
                    unreachable!()
                };
                mixed.params.as_mut().unwrap()["_meta"]["token"] =
                    serde_json::json!("must-not-reach-application");
                peer.send(&cx, &JsonRpcMessage::Request(mixed))
                    .await
                    .unwrap();
                let refused = response(&cx, &mut peer, 501, &[]).await;
                assert_eq!(
                    refused.error.unwrap().code.as_i32(),
                    Some(i32::from(McpErrorCode::ResourceForbidden)),
                );
                assert_eq!(gate.entered.load(Ordering::Acquire), 0);
                // The same request ID without a second credential admits.
                peer.send(&cx, &call(501, false)).await.unwrap();
                assert!(response(&cx, &mut peer, 501, &[]).await.error.is_none());
                assert_eq!(gate.entered.load(Ordering::Acquire), 1);
                stop(&cx, peer, serving).await;
            });
        }

        #[test]
        fn native_websocket_server_peer_close_preserves_other_connection_subscription() {
            run_native(|cx| async move {
                let gate = Arc::new(Gate::default());
                let service = server(&gate);
                let subscriptions = Arc::clone(&service.final_subscriptions);
                let (mut first, serving, address) = connect(&cx, service).await;
                let mut second = Peer::connect(&cx, &format!("ws://{address}/mcp"))
                    .await
                    .unwrap();
                acknowledge(&cx, &mut first, 601).await;
                acknowledge(&cx, &mut second, 602).await;
                first.close(&cx).await.unwrap();
                drop(first);
                // Wait until the closed connection has retired its own lease.
                until(&cx, || {
                    subscriptions.inner.lock().unwrap().entries.len() == 1
                })
                .await;
                assert_eq!(
                    subscriptions
                        .publish(ServerNotification::ToolsListChanged(None))
                        .unwrap(),
                    1,
                );
                let JsonRpcMessage::Request(notification) = second.recv(&cx).await.unwrap() else {
                    panic!("another peer's close must not complete this listen");
                };
                assert_eq!(notification.method, "notifications/tools/list_changed");
                second.send(&cx, &call(603, false)).await.unwrap();
                assert!(
                    response(&cx, &mut second, 603, &[602])
                        .await
                        .error
                        .is_none()
                );
                second.send(&cx, &cancel(602)).await.unwrap();
                stop(&cx, second, serving).await;
            });
        }
    }

    /// Names the awaiting call site on expiry; every test shares this helper.
    #[track_caller]
    fn until<'a>(cx: &'a Cx, predicate: impl Fn() -> bool + 'a) -> impl Future<Output = ()> + 'a {
        within_budget(cx, std::panic::Location::caller(), predicate, String::new)
    }

    /// Like [`until`], and on expiry also reports what the probe observed.
    #[track_caller]
    fn until_io<'a>(
        cx: &'a Cx,
        io: &'a IoProbe,
        predicate: impl Fn() -> bool + 'a,
    ) -> impl Future<Output = ()> + 'a {
        within_budget(cx, std::panic::Location::caller(), predicate, move || {
            io.observed()
        })
    }

    async fn within_budget(
        cx: &Cx,
        site: &std::panic::Location<'_>,
        predicate: impl Fn() -> bool,
        observed: impl FnOnce() -> String,
    ) {
        if let Some(waited) = budget_expiry(cx, predicate).await {
            panic!(
                "public async stdio observation at {site} must arrive within its test budget: {waited}; {}",
                observed()
            );
        }
    }

    /// Polls `predicate` until it holds or three seconds of runnable time
    /// pass, as the shared [`RunnableClock`] measures it: host load stretches
    /// the budget, and a server that makes no progress still expires it. On
    /// expiry, returns how long it waited.
    async fn budget_expiry(cx: &Cx, predicate: impl Fn() -> bool) -> Option<String> {
        let clock = RunnableClock::start();
        let started = clock.mark();
        while !predicate() {
            if clock.expired(started, Duration::from_secs(3)) {
                return Some(clock.describe(started));
            }
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
        }
        None
    }

    #[derive(Default)]
    struct IoState {
        inbound: VecDeque<u8>,
        eof: bool,
        outbound: Vec<u8>,
        allowance: usize,
        read_waker: Option<Waker>,
        write_waker: Option<Waker>,
        reads: usize,
        writes: usize,
        reader_dropped: bool,
        writer_dropped: bool,
    }
    #[derive(Default)]
    struct IoProbe(Mutex<IoState>);
    impl IoProbe {
        fn feed(&self, bytes: &[u8]) {
            let wake = {
                let mut state = self.0.lock().unwrap();
                state.inbound.extend(bytes);
                state.read_waker.take()
            };
            if let Some(waker) = wake {
                waker.wake();
            }
        }
        fn eof(&self) {
            let wake = {
                let mut state = self.0.lock().unwrap();
                state.eof = true;
                state.read_waker.take()
            };
            if let Some(waker) = wake {
                waker.wake();
            }
        }
        fn allow(&self, bytes: usize) {
            let wake = {
                let mut state = self.0.lock().unwrap();
                state.allowance = bytes;
                state.write_waker.take()
            };
            if let Some(waker) = wake {
                waker.wake();
            }
        }
        /// Decodes every complete output frame the way a client transport
        /// does. The derived untagged `JsonRpcMessage` decoder cannot read a
        /// request's raw `params`, so it would drop every parameterized
        /// notification; an undecodable complete frame fails loudly instead.
        fn messages(&self) -> Vec<JsonRpcMessage> {
            self.0
                .lock()
                .unwrap()
                .outbound
                .split_inclusive(|byte| *byte == b'\n')
                .filter_map(|line| line.strip_suffix(b"\n"))
                .filter(|line| !line.is_empty())
                .map(|line| {
                    ReceivedTransportFrame::admit(line.to_vec())
                        .map(ReceivedTransportFrame::into_message)
                        .unwrap_or_else(|error| {
                            panic!(
                                "async stdio wrote an undecodable frame {:?}: {error}",
                                String::from_utf8_lossy(line)
                            )
                        })
                })
                .collect()
        }
        /// What the server did with this probe so far.
        fn observed(&self) -> String {
            let state = self.0.lock().unwrap();
            let frames: Vec<String> = state
                .outbound
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| String::from_utf8_lossy(&line[..line.len().min(240)]).into_owned())
                .collect();
            format!(
                "{} inbound bytes unread (eof {}), {} reads, {} writes, reader dropped {}, writer dropped {}, outbound {frames:?}",
                state.inbound.len(),
                state.eof,
                state.reads,
                state.writes,
                state.reader_dropped,
                state.writer_dropped,
            )
        }
        fn response(&self, id: i64) -> Option<JsonRpcResponse> {
            self.messages()
                .into_iter()
                .find_map(|message| match message {
                    JsonRpcMessage::Response(response)
                        if response.id == Some(RequestId::Number(id)) =>
                    {
                        Some(response)
                    }
                    _ => None,
                })
        }
    }
    struct ProbeReader(Arc<IoProbe>);
    impl AsyncRead for ProbeReader {
        fn poll_read(
            self: Pin<&mut Self>,
            task: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut state = self.0.0.lock().unwrap();
            state.reads += 1;
            if state.inbound.is_empty() && !state.eof {
                state.read_waker = Some(task.waker().clone());
                return Poll::Pending;
            }
            let (front, _) = state.inbound.as_slices();
            let count = output.remaining().min(front.len());
            output.put_slice(&front[..count]);
            state.inbound.drain(..count);
            Poll::Ready(Ok(()))
        }
    }
    impl Drop for ProbeReader {
        fn drop(&mut self) {
            self.0.0.lock().unwrap().reader_dropped = true;
        }
    }
    struct ProbeWriter(Arc<IoProbe>);
    impl AsyncWrite for ProbeWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            task: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.0.0.lock().unwrap();
            state.writes += 1;
            if state.allowance == 0 {
                state.write_waker = Some(task.waker().clone());
                return Poll::Pending;
            }
            let count = state.allowance.min(bytes.len());
            state.allowance -= count;
            state.outbound.extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl Drop for ProbeWriter {
        fn drop(&mut self) {
            self.0.0.lock().unwrap().writer_dropped = true;
        }
    }

    #[test]
    fn async_stdio_server_native_tcp_multiplexes_without_blocking_pool() {
        run(|cx| async move {
            let gate = Arc::new(Gate::default());
            let service = server(&gate);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    let (socket, _) = listener.accept().await.unwrap();
                    let (input, output) = socket.into_split();
                    service.serve_stdio_io(&server_cx, input, output).await
                })
                .unwrap();
            let socket = TcpStream::connect(address).await.unwrap();
            let (input, output) = socket.into_split();
            let (mut input, mut output) = AsyncStdioTransport::from_io(input, output).into_split();
            output.send_async(&cx, &discover(1)).await.unwrap();
            assert!(
                matches!(input.recv_async(&cx).await.unwrap(), JsonRpcMessage::Response(response) if response.id == Some(RequestId::Number(1)) && response.error.is_none())
            );
            output.send_async(&cx, &call(2, true)).await.unwrap();
            until(&cx, || gate.entered.load(Ordering::Acquire) == 1).await;
            output.send_async(&cx, &call(3, false)).await.unwrap();
            let response =
                asupersync::time::timeout(cx.now(), Duration::from_secs(3), input.recv_async(&cx))
                    .await
                    .unwrap()
                    .unwrap();
            assert!(
                matches!(response, JsonRpcMessage::Response(response) if response.id == Some(RequestId::Number(3)) && response.error.is_none())
            );
            assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
            gate.release();
            assert!(
                matches!(input.recv_async(&cx).await.unwrap(), JsonRpcMessage::Response(response) if response.id == Some(RequestId::Number(2)) && response.error.is_none())
            );
            output.close_async(&cx).await.unwrap();
            serving.join(&cx).await.unwrap().unwrap();
            assert_eq!(gate.dropped.load(Ordering::Acquire), 2);
        });
    }

    #[test]
    fn async_stdio_server_cancels_pending_request_and_preserves_sibling() {
        run(|cx| async move {
            let gate = Arc::new(Gate::default());
            let io = Arc::new(IoProbe::default());
            io.allow(usize::MAX);
            let service = server(&gate);
            let stream = Arc::clone(&io);
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    service
                        .serve_stdio_io(
                            &server_cx,
                            ProbeReader(Arc::clone(&stream)),
                            ProbeWriter(stream),
                        )
                        .await
                })
                .unwrap();
            io.feed(&encoded(&call(10, true)));
            until(&cx, || gate.entered.load(Ordering::Acquire) == 1).await;
            io.feed(&encoded(&cancel(10)));
            io.feed(&encoded(&call(11, false)));
            until(&cx, || io.response(11).is_some()).await;
            assert!(io.response(11).unwrap().error.is_none());
            assert!(io.response(10).is_none());
            until(&cx, || gate.dropped.load(Ordering::Acquire) == 2).await;
            assert_eq!(gate.dropped.load(Ordering::Acquire), 2);
            io.eof();
            serving.join(&cx).await.unwrap().unwrap();
            assert!(io.0.lock().unwrap().writer_dropped);
        });
    }

    #[test]
    fn async_stdio_server_backpressure_cancellation_suppresses_queued_final_result() {
        run(|cx| async move {
            let gate = Arc::new(Gate::default());
            let io = Arc::new(IoProbe::default());
            let service = server(&gate);
            let stream = Arc::clone(&io);
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    service
                        .serve_stdio_io(
                            &server_cx,
                            ProbeReader(Arc::clone(&stream)),
                            ProbeWriter(stream),
                        )
                        .await
                })
                .unwrap();
            io.feed(&encoded(&discover(20)));
            until(&cx, || io.0.lock().unwrap().writes > 0).await;
            io.feed(&encoded(&call(21, false)));
            until(&cx, || gate.dropped.load(Ordering::Acquire) == 1).await;
            // The handler already returned. Its dispatch finalization must not
            // defeat wire cancellation while the result is still queued.
            io.feed(&encoded(&cancel(21)));
            io.feed(&encoded(&call(22, false)));
            until(&cx, || gate.dropped.load(Ordering::Acquire) == 2).await;
            io.allow(usize::MAX);
            until(&cx, || io.response(22).is_some()).await;
            assert!(io.response(20).unwrap().error.is_none());
            assert!(io.response(21).is_none());
            assert!(io.response(22).unwrap().error.is_none());
            io.eof();
            serving.join(&cx).await.unwrap().unwrap();
        });
    }

    #[test]
    fn async_stdio_server_cancellation_after_partial_output_terminates_connection() {
        run(|cx| async move {
            let gate = Arc::new(Gate::default());
            let io = Arc::new(IoProbe::default());
            io.allow(1);
            let service = server(&gate);
            let stream = Arc::clone(&io);
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    service
                        .serve_stdio_io(
                            &server_cx,
                            ProbeReader(Arc::clone(&stream)),
                            ProbeWriter(stream),
                        )
                        .await
                })
                .unwrap();
            io.feed(&encoded(&call(30, false)));
            until(&cx, || io.0.lock().unwrap().outbound.len() == 1).await;
            io.feed(&encoded(&cancel(30)));
            let result = serving.join(&cx).await.unwrap();
            assert!(result.is_err());
            let state = io.0.lock().unwrap();
            assert_eq!(state.outbound.len(), 1);
            assert!(state.writer_dropped && state.reader_dropped);
        });
    }

    #[test]
    fn async_stdio_server_parse_error_and_invalid_request_preserve_next_frame() {
        run(|cx| async move {
            let gate = Arc::new(Gate::default());
            let io = Arc::new(IoProbe::default());
            io.allow(usize::MAX);
            io.feed(b"{bad\n{\"jsonrpc\":\"2.0\",\"method\":false,\"id\":40}\n");
            io.feed(&encoded(&call(41, false)));
            io.eof();
            server(&gate)
                .serve_stdio_io(
                    &cx,
                    ProbeReader(Arc::clone(&io)),
                    ProbeWriter(Arc::clone(&io)),
                )
                .await
                .unwrap();
            let messages = io.messages();
            assert_eq!(messages.len(), 3);
            assert!(
                matches!(&messages[0], JsonRpcMessage::Response(response) if response.id.is_none() && response.error.as_ref().unwrap().code.as_i32() == Some(-32700))
            );
            assert_eq!(
                io.response(40).unwrap().error.unwrap().code.as_i32(),
                Some(-32600)
            );
            assert!(io.response(41).unwrap().error.is_none());
            assert_eq!(gate.entered.load(Ordering::Acquire), 1);
            let bytes = io.0.lock().unwrap().outbound.clone();
            assert!(!String::from_utf8(bytes).unwrap().contains("\"id\":null"));
        });
    }

    #[test]
    fn async_stdio_server_subscription_ack_and_cancel_share_connection_with_calls() {
        run(|cx| async move {
            let gate = Arc::new(Gate::default());
            let io = Arc::new(IoProbe::default());
            io.allow(usize::MAX);
            let service = server(&gate);
            let stream = Arc::clone(&io);
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    service
                        .serve_stdio_io(
                            &server_cx,
                            ProbeReader(Arc::clone(&stream)),
                            ProbeWriter(stream),
                        )
                        .await
                })
                .unwrap();
            io.feed(&encoded(&request(
                50,
                SUBSCRIPTIONS_LISTEN,
                serde_json::json!({"notifications":{"toolsListChanged":true}}),
            )));
            until_io(&cx, &io, || io.messages().iter().any(|message| matches!(message, JsonRpcMessage::Request(request) if request.method == fastmcp_protocol::methods::NOTIFICATIONS_SUBSCRIPTIONS_ACKNOWLEDGED))).await;
            io.feed(&encoded(&call(51, false)));
            until(&cx, || io.response(51).is_some()).await;
            io.feed(&encoded(&cancel(50)));
            io.feed(&encoded(&discover(52)));
            until(&cx, || io.response(52).is_some()).await;
            io.eof();
            serving.join(&cx).await.unwrap().unwrap();
            assert!(io.response(50).is_none());
            assert!(io.response(51).unwrap().error.is_none());
        });
    }

    mod subscription_shutdown_tests {
        use super::*;
        use asupersync::time::{TimerDriverHandle, VirtualClock};

        fn owner() -> Arc<OutputOwner> {
            let admission = Arc::new(DispatchQueueState::default());
            let JsonRpcMessage::Request(request) = request(
                50, SUBSCRIPTIONS_LISTEN, serde_json::json!({"notifications":{}}),
            ) else { unreachable!() };
            Arc::new(OutputOwner {
                reservation: admission.admit_modern_request(
                    &request, Arc::new(AtomicBool::new(false)),
                ).unwrap(),
                log_level: None,
                subscription_terminal: Some(Arc::new(FinalSubscriptionTerminalDelivery::default())),
                #[cfg(feature = "legacy-2024-11-05")]
                legacy: None,
            })
        }

        fn control() -> JsonRpcMessage {
            JsonRpcMessage::Request(subscription_cancellation_notification(&RequestId::Number(50)).unwrap())
        }

        #[test]
        fn only_the_elected_queued_control_can_settle_or_fail_its_receipt() {
            for withdrawal in 0..3 {
                let owner = owner();
                let delivery = owner.subscription_terminal.as_ref().unwrap();
                let output = OutputQueue::default();
                assert!(output.enqueue(control(), Some(Arc::clone(&owner))));
                assert!(delivery.mark_cancellation_enqueued());
                assert!(output.enqueue_subscription_control(control(), Arc::clone(&owner)));
                let generic = output.pop().unwrap();
                assert!(generic.terminal_delivery().is_none());
                assert!(!output.admits_write(&generic));
                output.finish(generic.bytes);
                drop(generic);
                assert_eq!(delivery.state.load(Ordering::Acquire), FINAL_TERMINAL_ENQUEUED);
                assert!(!delivery.is_settled());
                match withdrawal {
                    0 => output.stop(),
                    1 => {
                        owner.reservation.cancellation.cancel_by_peer();
                        assert_eq!(output.discard_cancelled(), 1);
                    }
                    _ => {
                        let elected = output.pop().unwrap();
                        assert!(elected.terminal_delivery().is_some());
                        output.finish(elected.bytes);
                        drop(elected);
                    }
                }
                assert_eq!(delivery.state.load(Ordering::Acquire), FINAL_TERMINAL_FAILED);
                assert!(delivery.is_settled());
                assert!(!delivery.is_drained());
            }
        }

        #[derive(Clone, Copy, Debug)]
        enum GuardCase { Live, CallerDeadline, DrainDeadline, PeerCancellation, ReceiptFailure }

        struct ReadyWriter {
            clock: Arc<VirtualClock>,
            case: GuardCase,
            owner: Arc<OutputOwner>,
            sends: usize,
        }

        impl ConnectionWriter for ReadyWriter {
            async fn send(&mut self, cx: &Cx, _: &JsonRpcMessage) -> Result<(), TransportError> {
                assert!(cx.checkpoint().is_ok(), "the elected write poll has bounded cancellation masking");
                self.sends += 1;
                match self.case {
                    GuardCase::Live => {}
                    GuardCase::CallerDeadline => { self.clock.advance(10); }
                    GuardCase::DrainDeadline => { self.clock.advance(5); }
                    GuardCase::PeerCancellation => { self.owner.reservation.cancellation.cancel_by_peer(); }
                    GuardCase::ReceiptFailure => self.owner.subscription_terminal.as_ref().unwrap().mark_failed(),
                }
                Ok(())
            }
            async fn close(&mut self, _: &Cx) -> Result<(), TransportError> { Ok(()) }
            fn is_closed(&self) -> bool { false }
        }

        #[test]
        fn ready_terminal_write_rechecks_original_and_whole_drain_authority_after_poll() {
            for case in [GuardCase::Live, GuardCase::CallerDeadline, GuardCase::DrainDeadline,
                GuardCase::PeerCancellation, GuardCase::ReceiptFailure]
            {
                let clock = Arc::new(VirtualClock::new());
                let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
                let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 0)
                    .with_timer_driver(timer.clone()).build().unwrap();
                let cx = runtime.request_cx_with_budget(
                    Budget::new().with_deadline(asupersync::Time::from_nanos(10)),
                );
                let owner = owner();
                let delivery = Arc::clone(owner.subscription_terminal.as_ref().unwrap());
                assert!(delivery.mark_cancellation_enqueued());
                if !matches!(case, GuardCase::PeerCancellation) {
                    owner.reservation.cancellation.cancel();
                }
                let output = Arc::new(OutputQueue::default());
                output.begin_subscription_drain(asupersync::Time::from_nanos(
                    if matches!(case, GuardCase::DrainDeadline) { 5 } else { 100 },
                ));
                assert!(output.enqueue_subscription_control(control(), Arc::clone(&owner)));
                cx.set_cancel_requested(true);
                let mut writing = write(
                    ReadyWriter { clock: Arc::clone(&clock), case, owner, sends: 0 },
                    cx.clone(), output.pop().unwrap(), Arc::clone(&output),
                );
                let caller = Cx::set_current(Some(cx.clone()));
                let Poll::Ready((writer, result, bytes)) = writing.as_mut().poll(
                    &mut Context::from_waker(Waker::noop()),
                ) else { panic!("the ready writer must settle in one poll: {case:?}") };
                output.finish(bytes);
                assert_eq!(writer.sends, 1);
                assert_eq!(result.is_ok(), matches!(case, GuardCase::Live), "{case:?}");
                assert_eq!(delivery.state.load(Ordering::Acquire),
                    if matches!(case, GuardCase::Live) { FINAL_TERMINAL_DRAINED } else { FINAL_TERMINAL_FAILED });
                assert!(cx.is_cancel_requested(), "masking never clears the caller cancellation");
                drop(writing);
                drop(caller);
                drop(cx);
                assert_eq!(timer.pending_count(), 0);
                assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
            }
        }

        #[test]
        fn local_shutdown_retains_a_partial_acknowledgement_and_control_until_flush() {
            for partial_acknowledgement in [false, true] {
                run(|cx| async move {
                    asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
                        let gate = Arc::new(Gate::default());
                        let io = Arc::new(IoProbe::default());
                        io.allow(if partial_acknowledgement { 1 } else { usize::MAX });
                        let service = server(&gate);
                        let registry = Arc::clone(&service.final_subscriptions);
                        let stream = Arc::clone(&io);
                        let (context_tx, context_rx) = std::sync::mpsc::sync_channel(1);
                        let mut serving = cx.spawn(move |server_cx| async move {
                            context_tx.send(server_cx.clone()).unwrap();
                            service.serve_stdio_io(&server_cx,
                                ProbeReader(Arc::clone(&stream)), ProbeWriter(stream)).await
                        }).unwrap();
                        io.feed(&encoded(&request(50, SUBSCRIPTIONS_LISTEN,
                            serde_json::json!({"notifications":{}}))));
                        until(&cx, || if partial_acknowledgement {
                            io.0.lock().unwrap().outbound.len() == 1
                        } else {
                            io.messages().len() == 1
                        }).await;
                        let before = io.0.lock().unwrap().outbound.len();
                        if !partial_acknowledgement { io.allow(1); }
                        context_rx.try_recv().unwrap().cancel_with(
                            CancelKind::User, Some("subscription shutdown drain regression"),
                        );
                        until(&cx, || registry.is_terminating()
                            && (partial_acknowledgement || io.0.lock().unwrap().outbound.len() == before + 1)).await;
                        {
                            let state = io.0.lock().unwrap();
                            assert!(!state.reader_dropped && !state.writer_dropped,
                                "the partial frame still owns both native halves");
                        }
                        io.allow(usize::MAX);
                        serving.join(&cx).await.unwrap().unwrap();
                        let messages = io.messages();
                        assert_eq!(messages.len(), 2, "only acknowledgement and cancellation may be written");
                        assert!(matches!(&messages[0], JsonRpcMessage::Request(request)
                            if request.method == "notifications/subscriptions/acknowledged"));
                        let JsonRpcMessage::Request(control) = &messages[1] else {
                            panic!("shutdown must emit a cancellation notification");
                        };
                        assert!(control.id.is_none());
                        assert_eq!(control.method, "notifications/cancelled");
                        let params = control.params.as_ref().unwrap();
                        assert_eq!(params["requestId"], 50);
                        assert_eq!(params["_meta"][FINAL_SUBSCRIPTION_ID_META_KEY], 50);
                        let state = io.0.lock().unwrap();
                        assert!(state.outbound.ends_with(b"\n"));
                        assert!(state.reader_dropped && state.writer_dropped);
                        assert!(cx.checkpoint().is_ok());
                    }).await.expect("partial subscription frames must drain within the owned shutdown bound");
                });
            }
        }

        #[test]
        fn an_ordinary_partial_frame_cannot_be_relabelled_as_subscription_drain() {
            for subscribed in [false, true] {
                run(|cx| async move {
                    asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
                        let gate = Arc::new(Gate::default());
                        let io = Arc::new(IoProbe::default());
                        io.allow(usize::MAX);
                        let service = server(&gate);
                        let stream = Arc::clone(&io);
                        let (context_tx, context_rx) = std::sync::mpsc::sync_channel(1);
                        let mut serving = cx.spawn(move |server_cx| async move {
                            context_tx.send(server_cx.clone()).unwrap();
                            service.serve_stdio_io(&server_cx,
                                ProbeReader(Arc::clone(&stream)), ProbeWriter(stream)).await
                        }).unwrap();
                        if subscribed {
                            io.feed(&encoded(&request(50, SUBSCRIPTIONS_LISTEN,
                                serde_json::json!({"notifications":{}}))));
                            until(&cx, || io.messages().len() == 1).await;
                        }
                        let before = io.0.lock().unwrap().outbound.len();
                        io.allow(1);
                        io.feed(&encoded(&call(51, false)));
                        until(&cx, || io.0.lock().unwrap().outbound.len() == before + 1).await;
                        context_rx.try_recv().unwrap().cancel_with(
                            CancelKind::User, Some("ordinary partial output shutdown regression"),
                        );
                        let result = serving.join(&cx).await.unwrap();
                        assert_eq!(result.is_err(), subscribed,
                            "ordinary-only shutdown stays unchanged; a required control behind a poisoned frame fails");
                        let state = io.0.lock().unwrap();
                        assert_eq!(state.outbound.len(), before + 1);
                        assert!(state.reader_dropped && state.writer_dropped);
                        assert!(cx.checkpoint().is_ok());
                    }).await.expect("a cancelled partial ordinary frame must stop without further output");
                });
            }
        }
    }

    #[test]
    fn async_stdio_server_retains_exact_parameter_bytes_within_shared_admission_bound() {
        run(|cx| async move {
            let gate = Arc::new(Gate::default());
            let io = Arc::new(IoProbe::default());
            io.allow(usize::MAX);
            let service = server(&gate);
            let stream = Arc::clone(&io);
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    service
                        .serve_stdio_io(
                            &server_cx,
                            ProbeReader(Arc::clone(&stream)),
                            ProbeWriter(stream),
                        )
                        .await
                })
                .unwrap();
            // Each exact source sits at the per-document bound, so two fit the
            // shared admission bound and the third is refused only because
            // its retained raw bytes are charged; its typed value is tiny.
            for id in [60, 61, 62] {
                io.feed(&padded_call(
                    id,
                    true,
                    fastmcp_protocol::MAX_RESULT_ENCODED_BYTES,
                ));
            }
            until_io(&cx, &io, || io.response(62).is_some()).await;
            assert_eq!(
                io.response(62).unwrap().error.unwrap().code.as_i32(),
                Some(RESOURCE_EXHAUSTED_ERROR_CODE)
            );
            assert_eq!(gate.entered.load(Ordering::Acquire), 2);
            gate.release();
            until(&cx, || {
                io.response(60).is_some() && io.response(61).is_some()
            })
            .await;
            io.feed(&encoded(&call(63, false)));
            until(&cx, || io.response(63).is_some()).await;
            assert!(io.response(63).unwrap().error.is_none());
            assert_eq!(gate.entered.load(Ordering::Acquire), 3);
            io.eof();
            serving.join(&cx).await.unwrap().unwrap();
        });
    }

    /// The test above with its three calls never fed: the server has nothing
    /// to make progress on, so the same wait must still expire its budget.
    #[test]
    fn async_stdio_test_budget_expires_when_the_server_makes_no_progress() {
        run(|cx| async move {
            let gate = Arc::new(Gate::default());
            let io = Arc::new(IoProbe::default());
            io.allow(usize::MAX);
            let service = server(&gate);
            let stream = Arc::clone(&io);
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    service
                        .serve_stdio_io(
                            &server_cx,
                            ProbeReader(Arc::clone(&stream)),
                            ProbeWriter(stream),
                        )
                        .await
                })
                .unwrap();
            let waited = budget_expiry(&cx, || io.response(62).is_some())
                .await
                .expect("no response arrives when no call was fed");
            assert!(waited.contains("runnable"), "{waited}");
            assert!(io.response(62).is_none(), "{}", io.observed());
            assert_eq!(gate.entered.load(Ordering::Acquire), 0);
            io.eof();
            serving.join(&cx).await.unwrap().unwrap();
        });
    }

    #[test]
    fn async_stdio_server_refuses_raw_parameters_beyond_the_document_bound() {
        run(|cx| async move {
            let gate = Arc::new(Gate::default());
            let io = Arc::new(IoProbe::default());
            io.allow(usize::MAX);
            let service = server(&gate);
            let stream = Arc::clone(&io);
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    service
                        .serve_stdio_io(
                            &server_cx,
                            ProbeReader(Arc::clone(&stream)),
                            ProbeWriter(stream),
                        )
                        .await
                })
                .unwrap();
            // Differs from the admitted call below only by one byte of
            // insignificant whitespace past the per-document bound.
            io.feed(&padded_call(
                70,
                false,
                fastmcp_protocol::MAX_RESULT_ENCODED_BYTES + 1,
            ));
            until_io(&cx, &io, || io.response(70).is_some()).await;
            assert_eq!(
                io.response(70).unwrap().error.unwrap().code.as_i32(),
                Some(-32602)
            );
            assert_eq!(gate.entered.load(Ordering::Acquire), 0);
            io.feed(&padded_call(
                71,
                false,
                fastmcp_protocol::MAX_RESULT_ENCODED_BYTES,
            ));
            until_io(&cx, &io, || io.response(71).is_some()).await;
            assert!(io.response(71).unwrap().error.is_none());
            assert_eq!(gate.entered.load(Ordering::Acquire), 1);
            io.eof();
            serving.join(&cx).await.unwrap().unwrap();
        });
    }

    #[test]
    fn async_stdio_server_admits_each_frame_once_and_still_refuses_bom_and_duplicates() {
        run(|cx| async move {
            let gate = Arc::new(Gate::default());
            let io = Arc::new(IoProbe::default());
            io.allow(usize::MAX);
            let service = server(&gate);
            let stream = Arc::clone(&io);
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    service
                        .serve_stdio_io(
                            &server_cx,
                            ProbeReader(Arc::clone(&stream)),
                            ProbeWriter(stream),
                        )
                        .await
                })
                .unwrap();
            let named = |id: &str| {
                let JsonRpcMessage::Request(mut request) = call(0, false) else {
                    unreachable!()
                };
                request.id = Some(RequestId::String(id.to_owned()));
                encoded(&JsonRpcMessage::Request(request))
            };
            let responses_to = |id: &RequestId| -> Vec<JsonRpcResponse> {
                io.messages()
                    .into_iter()
                    .filter_map(|message| match message {
                        JsonRpcMessage::Response(response) if response.id.as_ref() == Some(id) => {
                            Some(response)
                        }
                        _ => None,
                    })
                    .collect()
            };
            // Only the transport admits each frame now. Its shared raw
            // admission must still refuse a byte-order mark (U+FEFF) that
            // differs from the admitted U+FEFB only in its last byte.
            io.feed(&named("a\u{feff}"));
            io.feed(&named("a\u{fefb}"));
            let admitted = RequestId::String("a\u{fefb}".to_owned());
            until_io(&cx, &io, || !responses_to(&admitted).is_empty()).await;
            assert!(io.messages().iter().any(|message| matches!(
                message,
                JsonRpcMessage::Response(response)
                    if response.id.is_none()
                        && response.error.as_ref().unwrap().code.as_i32() == Some(-32700)
            )));
            assert!(responses_to(&admitted)[0].error.is_none());
            // A duplicated params member is the only change from the call
            // that follows it under the same id.
            let admitted_bytes = encoded(&call(81, false));
            let duplicated = String::from_utf8(admitted_bytes.clone()).unwrap().replacen(
                "\"name\":\"async_probe\"",
                "\"name\":\"async_probe\",\"name\":\"async_probe\"",
                1,
            );
            io.feed(duplicated.as_bytes());
            io.feed(&admitted_bytes);
            let id = RequestId::Number(81);
            until_io(&cx, &io, || responses_to(&id).len() == 2).await;
            let [refused, answered]: [JsonRpcResponse; 2] = responses_to(&id).try_into().unwrap();
            assert_eq!(refused.error.unwrap().code.as_i32(), Some(-32600));
            assert!(answered.error.is_none());
            assert_eq!(gate.entered.load(Ordering::Acquire), 2);
            io.eof();
            serving.join(&cx).await.unwrap().unwrap();
        });
    }

    #[test]
    fn async_stdio_probe_decodes_parameterized_frames_and_fails_on_undecodable_ones() {
        // The acknowledgement exactly as the async stdio server writes it.
        let acknowledgement = br#"{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":50},"notifications":{"toolsListChanged":true}}}"#;
        let probe = |frame: &[u8]| {
            let io = IoProbe::default();
            let mut state = io.0.lock().unwrap();
            state.outbound.extend_from_slice(frame);
            state.outbound.push(b'\n');
            drop(state);
            io
        };
        assert!(matches!(
            probe(&acknowledgement[..]).messages().as_slice(),
            [JsonRpcMessage::Request(request)]
                if request.method == fastmcp_protocol::methods::NOTIFICATIONS_SUBSCRIPTIONS_ACKNOWLEDGED
        ));
        // The same complete frame without its closing brace must fail the
        // observation rather than read as an absent acknowledgement.
        let truncated = probe(&acknowledgement[..acknowledgement.len() - 1]);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| truncated.messages()))
                .is_err()
        );
    }

    #[test]
    fn async_stdio_server_output_saturation_is_terminal_without_handler_effect() {
        run(|cx| async move {
            let gate = Arc::new(Gate::default());
            let io = Arc::new(IoProbe::default());
            io.feed(&b"invalid\n".repeat(MAX_DISPATCH_QUEUE_DEPTH + 1));
            let result = server(&gate)
                .serve_stdio_io(
                    &cx,
                    ProbeReader(Arc::clone(&io)),
                    ProbeWriter(Arc::clone(&io)),
                )
                .await;
            assert!(result.is_err());
            assert_eq!(gate.entered.load(Ordering::Acquire), 0);
            let state = io.0.lock().unwrap();
            assert!(state.outbound.is_empty());
            assert!(state.reader_dropped && state.writer_dropped);
        });
    }

    #[test]
    fn async_stdio_server_cancelled_silent_receive_closes_owned_io() {
        run(|cx| async move {
            let gate = Arc::new(Gate::default());
            let io = Arc::new(IoProbe::default());
            let service = server(&gate);
            let stream = Arc::clone(&io);
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    service
                        .serve_stdio_io(
                            &server_cx,
                            ProbeReader(Arc::clone(&stream)),
                            ProbeWriter(stream),
                        )
                        .await
                })
                .unwrap();
            until(&cx, || io.0.lock().unwrap().reads > 0).await;
            serving.abort();
            serving.join(&cx).await.unwrap().unwrap();
            let state = io.0.lock().unwrap();
            assert!(state.reader_dropped && state.writer_dropped);
        });
    }

    #[cfg(feature = "tasks")]
    mod hosted_tasks {
        use super::*;
        use crate::tasks::{
            ApplicationTaskSupervisor, FinalTaskRuntime, FinalTaskRuntimeConfig,
            FinalTaskSupervisorFuture, FinalTaskSupervisorHandoff, FinalTaskWorkDescriptor,
            InMemoryFinalTaskStore,
        };
        use fastmcp_protocol::{FinalTaskCallToolResult, FinalTaskId, Task, TaskInputRequests};

        #[derive(Default)]
        struct TaskProbe {
            initialized: AtomicBool,
            fail: AtomicBool,
            panic_on_failure: AtomicBool,
            changed: Notify,
            tool_calls: AtomicUsize,
            initial: AtomicUsize,
            resumed: AtomicUsize,
            active: AtomicUsize,
        }

        struct TaskTool(Arc<TaskProbe>);

        impl ToolHandler for TaskTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "async_task_probe".to_owned(),
                    description: None,
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {"subject": {"type": "string"}, "hold": {"type": "boolean"}},
                        "required": ["subject", "hold"],
                        "additionalProperties": false,
                    }),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: Vec::new(),
                    annotations: None,
                }
            }

            fn execution_mode(&self) -> ToolExecutionMode {
                ToolExecutionMode::Async
            }

            fn declares_final_tasks(&self) -> bool {
                true
            }

            fn call(&self, _: &McpContext, _: serde_json::Value) -> McpResult<Vec<Content>> {
                panic!("modern Tasks must use the final outcome hook")
            }

            fn call_final_outcome(
                &self,
                _: &McpContext,
                arguments: serde_json::Value,
            ) -> McpResult<crate::FinalToolOutcome> {
                self.0.tool_calls.fetch_add(1, Ordering::AcqRel);
                Ok(crate::FinalToolOutcome::CreateTask {
                    work_descriptor: FinalTaskWorkDescriptor::new(arguments)?,
                    status_message: Some("queued by async stdio".to_owned()),
                })
            }
        }

        struct TaskSupervisor(Arc<TaskProbe>);

        impl ApplicationTaskSupervisor for TaskSupervisor {
            fn resume<'a>(
                &'a self,
                _: &'a Cx,
                handoff: FinalTaskSupervisorHandoff,
            ) -> FinalTaskSupervisorFuture<'a> {
                Box::pin(async move {
                    assert!(
                        self.0.initialized.load(Ordering::Acquire),
                        "application startup must precede supervised Task work"
                    );
                    struct Active<'a>(&'a AtomicUsize);
                    impl Drop for Active<'_> {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::AcqRel);
                        }
                    }
                    self.0.active.fetch_add(1, Ordering::AcqRel);
                    let _active = Active(&self.0.active);
                    match handoff {
                        FinalTaskSupervisorHandoff::Initial(initial) => {
                            self.0.initial.fetch_add(1, Ordering::AcqRel);
                            if initial.work_descriptor().as_value()["hold"] == true {
                                self.0
                                    .changed
                                    .wait_until(|| self.0.fail.load(Ordering::Acquire))
                                    .await;
                                assert!(
                                    !self.0.panic_on_failure.load(Ordering::Acquire),
                                    "planted supervised Task panic"
                                );
                                return Err(McpError::internal_error(
                                    "planted supervised Task failure",
                                ));
                            }
                            let requests: TaskInputRequests = serde_json::from_value(
                                serde_json::json!({"roots": {"method": "roots/list"}}),
                            )
                            .expect("valid roots input descriptor");
                            initial.require_input(requests, Some("awaiting roots".to_owned()))?;
                        }
                        FinalTaskSupervisorHandoff::Resumed(accepted) => {
                            let inputs = serde_json::to_value(accepted.input_responses())
                                .expect("accepted input serializes");
                            let result: FinalTaskCallToolResult = serde_json::from_value(
                                serde_json::json!({
                                    "content": [
                                        {"type": "text", "text": accepted.work_descriptor().as_value()["subject"]},
                                        {"type": "text", "text": inputs["roots"]["roots"][0]["uri"]},
                                    ],
                                    "isError": false,
                                }),
                            )
                            .expect("work and accepted roots produce a final tool result");
                            accepted
                                .complete_task(result, Some("resumed and completed".to_owned()))?;
                            self.0.resumed.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                    Ok(())
                })
            }
        }

        fn task_request(id: i64, method: &str, params: serde_json::Value) -> JsonRpcMessage {
            let JsonRpcMessage::Request(mut request) = request(id, method, params) else {
                unreachable!()
            };
            request.params.as_mut().unwrap()["_meta"]
                [fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY] = serde_json::json!({
                "roots": {},
                "extensions": {fastmcp_protocol::TASKS_EXTENSION: {}},
            });
            JsonRpcMessage::Request(request)
        }

        fn task_call(id: i64, hold: bool) -> JsonRpcMessage {
            task_request(
                id,
                "tools/call",
                serde_json::json!({
                    "name": "async_task_probe",
                    "arguments": {"subject": "stdio durable work", "hold": hold},
                }),
            )
        }

        struct TaskServer {
            server: Server,
            runtime: FinalTaskRuntime,
            store: Arc<InMemoryFinalTaskStore>,
            shutdown: Arc<AtomicBool>,
        }

        fn task_server(probe: &Arc<TaskProbe>, supervised: bool) -> TaskServer {
            let store = Arc::new(InMemoryFinalTaskStore::default());
            let runtime = FinalTaskRuntime::new(
                store.clone(),
                FinalTaskRuntimeConfig::new(60_000, Some(1_000)).unwrap(),
                Arc::new(|_| {}),
            );
            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_flag = Arc::clone(&shutdown);
            let shutdown_runtime = runtime.clone();
            let shutdown_probe = Arc::clone(probe);
            let startup_runtime = runtime.clone();
            let startup_probe = Arc::clone(probe);
            let builder = Server::new("hosted-stdio-tasks", "1.0")
                .protocol_policy(ProtocolPolicy::ModernOnly)
                .unwrap()
                .tool(TaskTool(Arc::clone(probe)))
                .final_tasks(runtime.clone())
                .unwrap()
                .on_startup(move || {
                    assert!(
                        !startup_runtime.is_task_service_ready(),
                        "Task recovery must not start before application initialization"
                    );
                    startup_probe.initialized.store(true, Ordering::Release);
                    Ok::<(), io::Error>(())
                })
                .on_shutdown(move || {
                    assert!(!shutdown_runtime.is_task_service_ready());
                    assert_eq!(shutdown_probe.active.load(Ordering::Acquire), 0);
                    shutdown_flag.store(true, Ordering::Release);
                });
            let builder = if supervised {
                builder.task_supervisor(Arc::new(TaskSupervisor(Arc::clone(probe))))
            } else {
                builder
            };
            TaskServer {
                server: builder.build(),
                runtime,
                store,
                shutdown,
            }
        }

        fn serve_tasks(
            cx: &Cx,
            server: Server,
            io: &Arc<IoProbe>,
        ) -> asupersync::runtime::TaskHandle<McpResult<()>> {
            let stream = Arc::clone(io);
            cx.spawn(move |serve_cx| async move {
                server
                    .serve_stdio_io(
                        &serve_cx,
                        ProbeReader(Arc::clone(&stream)),
                        ProbeWriter(stream),
                    )
                    .await
            })
            .expect("serve child is admitted")
        }

        #[test]
        fn async_stdio_hosted_tasks_create_resume_and_settle() {
            run(|cx| async move {
                let probe = Arc::new(TaskProbe::default());
                let TaskServer {
                    server,
                    runtime,
                    store,
                    shutdown,
                } = task_server(&probe, true);
                assert!(!runtime.is_task_service_ready());
                let io = Arc::new(IoProbe::default());
                io.allow(usize::MAX);
                // The first call is already waiting when serve begins. Its
                // acceptance proves readiness precedes request ingress.
                io.feed(&encoded(&task_call(201, false)));
                let mut serving = serve_tasks(&cx, server, &io);
                until_io(&cx, &io, || io.response(201).is_some()).await;
                let created = io.response(201).unwrap();
                assert!(created.error.is_none(), "{created:?}");
                let created = created.result.unwrap();
                assert_eq!(created["resultType"], "task");
                let task_id = FinalTaskId::parse(created["taskId"].as_str().unwrap()).unwrap();
                assert_eq!(store.task_count(), 1);
                until(&cx, || {
                    matches!(
                        runtime.get_task(&task_id).unwrap().task,
                        Task::InputRequired { .. }
                    )
                })
                .await;
                io.feed(&encoded(&task_request(
                    202,
                    "tasks/get",
                    serde_json::json!({"taskId": task_id.as_str()}),
                )));
                until_io(&cx, &io, || io.response(202).is_some()).await;
                let waiting = io.response(202).unwrap().result.unwrap();
                assert_eq!(waiting["taskId"], task_id.as_str());
                assert_eq!(waiting["status"], "input_required");
                assert_eq!(waiting["inputRequests"]["roots"]["method"], "roots/list");

                io.feed(&encoded(&task_request(
                    203,
                    "tasks/update",
                    serde_json::json!({
                        "taskId": task_id.as_str(),
                        "inputResponses": {"roots": {"roots": [{"uri": "file:///stdio-input"}]}},
                    }),
                )));
                until_io(&cx, &io, || io.response(203).is_some()).await;
                assert_eq!(
                    io.response(203).unwrap().result,
                    Some(serde_json::json!({"resultType": "complete"})),
                );
                until(&cx, || probe.resumed.load(Ordering::Acquire) == 1).await;
                io.feed(&encoded(&task_request(
                    204,
                    "tasks/get",
                    serde_json::json!({"taskId": task_id.as_str()}),
                )));
                until_io(&cx, &io, || io.response(204).is_some()).await;
                let completed = io.response(204).unwrap().result.unwrap();
                assert_eq!(completed["taskId"], task_id.as_str());
                assert_eq!(completed["status"], "completed");
                assert_eq!(
                    completed["result"]["content"][0]["text"],
                    "stdio durable work"
                );
                assert_eq!(
                    completed["result"]["content"][1]["text"],
                    "file:///stdio-input"
                );
                assert_eq!(probe.tool_calls.load(Ordering::Acquire), 1);
                assert_eq!(probe.initial.load(Ordering::Acquire), 1);
                assert!(runtime.is_task_service_ready());
                io.eof();
                serving.join(&cx).await.unwrap().unwrap();
                assert!(!runtime.is_task_service_ready());
                assert_eq!(probe.active.load(Ordering::Acquire), 0);
                assert!(shutdown.load(Ordering::Acquire));
                assert_eq!(
                    store.task_count(),
                    1,
                    "settlement retains accepted task state"
                );
            });
        }

        #[test]
        fn async_stdio_tasks_without_supervisor_refuse_creation_without_store_mutation() {
            run(|cx| async move {
                let probe = Arc::new(TaskProbe::default());
                let TaskServer {
                    server,
                    runtime,
                    store,
                    shutdown,
                } = task_server(&probe, false);
                let io = Arc::new(IoProbe::default());
                io.allow(usize::MAX);
                // Same server, runtime and request as the positive test;
                // only the builder's supervisor registration is absent.
                io.feed(&encoded(&task_call(201, false)));
                let mut serving = serve_tasks(&cx, server, &io);
                until_io(&cx, &io, || io.response(201).is_some()).await;
                let refused = io.response(201).unwrap();
                assert!(refused.result.is_none());
                let error = refused.error.unwrap();
                assert_eq!(error.code.as_i32(), Some(-32602));
                assert_eq!(
                    error.message,
                    "Final task creation requires an installed ready task service"
                );
                assert_eq!(probe.tool_calls.load(Ordering::Acquire), 1);
                assert_eq!(probe.initial.load(Ordering::Acquire), 0);
                assert_eq!(probe.resumed.load(Ordering::Acquire), 0);
                assert_eq!(store.task_count(), 0);
                assert_eq!(store.retained_payload_bytes(), 0);
                assert!(!runtime.is_task_service_ready());
                io.eof();
                serving.join(&cx).await.unwrap().unwrap();
                assert!(shutdown.load(Ordering::Acquire));
            });
        }

        #[test]
        fn async_stdio_hosted_tasks_settle_on_transport_failure_and_cancellation() {
            run(|cx| async move {
                for cancel_serve in [false, true] {
                    let probe = Arc::new(TaskProbe::default());
                    let TaskServer {
                        server,
                        runtime,
                        store,
                        shutdown,
                    } = task_server(&probe, true);
                    let io = Arc::new(IoProbe::default());
                    io.allow(usize::MAX);
                    io.feed(&encoded(&task_call(201, true)));
                    let mut serving = serve_tasks(&cx, server, &io);
                    until_io(&cx, &io, || io.response(201).is_some()).await;
                    assert!(io.response(201).unwrap().error.is_none());
                    until(&cx, || probe.active.load(Ordering::Acquire) == 1).await;
                    assert!(runtime.is_task_service_ready());
                    if cancel_serve {
                        serving.abort();
                    } else {
                        // A client response violates the server-only receive
                        // direction and terminates this same active service.
                        io.feed(b"{\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n");
                    }
                    let outcome = asupersync::time::timeout(
                        cx.now(),
                        Duration::from_secs(6),
                        serving.join(&cx),
                    )
                    .await
                    .expect("serve settles its Task service within its bound")
                    .expect("serve child joins");
                    assert_eq!(outcome.is_ok(), cancel_serve, "{outcome:?}");
                    assert!(!runtime.is_task_service_ready());
                    assert_eq!(probe.active.load(Ordering::Acquire), 0);
                    assert_eq!(store.task_count(), 1);
                    assert!(shutdown.load(Ordering::Acquire));
                    let state = io.0.lock().unwrap();
                    assert!(state.reader_dropped && state.writer_dropped);
                }
            });
        }

        #[test]
        fn async_stdio_hosted_task_service_failure_stops_silent_ingress() {
            run(|cx| async move {
                for panic_on_failure in [false, true] {
                    let probe = Arc::new(TaskProbe::default());
                    probe
                        .panic_on_failure
                        .store(panic_on_failure, Ordering::Release);
                    let TaskServer {
                        server,
                        runtime,
                        store,
                        shutdown,
                    } = task_server(&probe, true);
                    let io = Arc::new(IoProbe::default());
                    io.allow(usize::MAX);
                    io.feed(&encoded(&task_call(201, true)));
                    let mut serving = serve_tasks(&cx, server, &io);
                    until_io(&cx, &io, || io.response(201).is_some()).await;
                    assert!(io.response(201).unwrap().error.is_none());
                    until(&cx, || probe.active.load(Ordering::Acquire) == 1).await;
                    assert!(runtime.is_task_service_ready());
                    // The peer supplies no EOF or further traffic. Either a
                    // returned failure or a panic must stop this same service.
                    probe.fail.store(true, Ordering::Release);
                    probe.changed.notify_waiters();
                    let outcome = asupersync::time::timeout(
                        cx.now(),
                        Duration::from_secs(3),
                        serving.join(&cx),
                    )
                    .await
                    .expect("service failure must wake silent ingress")
                    .expect("serve child joins");
                    assert!(
                        outcome.is_err(),
                        "supervisor failure must reach the embedding (panic={panic_on_failure})"
                    );
                    assert!(!runtime.is_task_service_ready());
                    assert_eq!(probe.active.load(Ordering::Acquire), 0);
                    assert_eq!(store.task_count(), 1);
                    assert!(shutdown.load(Ordering::Acquire));
                    let state = io.0.lock().unwrap();
                    assert!(!state.eof);
                    assert!(state.reader_dropped && state.writer_dropped);
                }
            });
        }

        #[test]
        fn async_stdio_hosted_tasks_do_not_start_on_startup_failure() {
            run(|cx| async move {
                let probe = Arc::new(TaskProbe::default());
                let runtime = FinalTaskRuntime::in_memory(
                    FinalTaskRuntimeConfig::new(60_000, Some(1_000)).unwrap(),
                    Arc::new(|_| {}),
                );
                let startup_idle = Arc::new(AtomicBool::new(false));
                let startup_flag = Arc::clone(&startup_idle);
                let startup_runtime = runtime.clone();
                let server = Server::new("hosted-stdio-startup-failure", "1.0")
                    .protocol_policy(ProtocolPolicy::ModernOnly)
                    .unwrap()
                    .final_tasks(runtime.clone())
                    .unwrap()
                    .task_supervisor(Arc::new(TaskSupervisor(Arc::clone(&probe))))
                    .on_startup(move || {
                        startup_flag
                            .store(!startup_runtime.is_task_service_ready(), Ordering::Release);
                        Err(io::Error::other("planted startup failure"))
                    })
                    .build();
                let io = Arc::new(IoProbe::default());
                io.feed(&encoded(&task_call(201, false)));
                let error = server
                    .serve_stdio_io(
                        &cx,
                        ProbeReader(Arc::clone(&io)),
                        ProbeWriter(Arc::clone(&io)),
                    )
                    .await
                    .expect_err("startup hook rejects this serve");
                assert_eq!(error.message, "Server startup hook failed");
                assert!(startup_idle.load(Ordering::Acquire));
                assert!(!runtime.is_task_service_ready());
                assert!(!probe.initialized.load(Ordering::Acquire));
                assert_eq!(probe.tool_calls.load(Ordering::Acquire), 0);
                assert_eq!(probe.initial.load(Ordering::Acquire), 0);
                assert_eq!(probe.active.load(Ordering::Acquire), 0);
                let state = io.0.lock().unwrap();
                assert_eq!(state.reads, 0);
                assert_eq!(state.writes, 0);
                assert!(state.reader_dropped && state.writer_dropped);
            });
        }
    }

    #[cfg(feature = "legacy-2024-11-05")]
    mod dual_era {
        use super::*;

        type Serving = asupersync::runtime::TaskHandle<McpResult<()>>;

        fn run_native<F, Fut>(test: F)
        where
            F: FnOnce(Cx) -> Fut,
            Fut: Future<Output = ()>,
        {
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(create_reactor().unwrap())
                .blocking_threads(0, 0)
                .build()
                .unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                assert!(cx.blocking_pool_handle().is_none());
                // A blocking bridge also blocks the runtime timer. This
                // test-only watchdog turns that regression into a failure.
                let watchdog_cx = cx.clone();
                let (finished, completion) = std::sync::mpsc::sync_channel::<()>(1);
                let watchdog = std::thread::spawn(move || {
                    if matches!(
                        completion.recv_timeout(Duration::from_secs(15)),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    ) {
                        watchdog_cx.cancel_with(
                            CancelKind::Deadline,
                            Some("dual-era stdio test made no runtime progress"),
                        );
                        true
                    } else {
                        false
                    }
                });
                let result =
                    asupersync::time::timeout(cx.now(), Duration::from_secs(12), test(cx.clone()))
                        .await;
                let _ = finished.send(());
                assert!(
                    !watchdog.join().unwrap(),
                    "stdio blocked its embedding runtime"
                );
                result.expect("native dual-era stdio operation exceeded its bound");
            });
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }

        fn configured(policy: ProtocolPolicy, gate: &Arc<Gate>) -> ServerBuilder {
            Server::new("native-dual-era-stdio", "1.0")
                .protocol_policy(policy)
                .unwrap()
                .logging(LoggingConfig {
                    level: LevelFilter::Info,
                    ..LoggingConfig::default()
                })
                .tool(ProbeTool(Arc::clone(gate)))
        }

        fn start(cx: &Cx, service: Server, io: &Arc<IoProbe>) -> Serving {
            let stream = Arc::clone(io);
            cx.spawn(move |server_cx| async move {
                service
                    .serve_stdio_io(
                        &server_cx,
                        ProbeReader(Arc::clone(&stream)),
                        ProbeWriter(stream),
                    )
                    .await
            })
            .unwrap()
        }

        fn legacy_request(id: i64, method: &str, params: serde_json::Value) -> JsonRpcMessage {
            JsonRpcMessage::Request(JsonRpcRequest::new(method, Some(params), id))
        }

        fn initialize(id: i64) -> JsonRpcMessage {
            legacy_request(
                id,
                "initialize",
                serde_json::json!({
                    "protocolVersion": LEGACY_PROTOCOL_VERSION,
                    "capabilities": {"roots": {}},
                    "clientInfo": {"name": "native-test-peer", "version": "1.0"},
                }),
            )
        }

        fn initialized() -> JsonRpcMessage {
            JsonRpcMessage::Request(JsonRpcRequest::notification(
                "notifications/initialized",
                None,
            ))
        }

        fn legacy_call(id: i64, hold: bool) -> JsonRpcMessage {
            legacy_request(
                id,
                "tools/call",
                serde_json::json!({"name": "async_probe", "arguments": {"hold": hold}}),
            )
        }

        fn legacy_cancel(id: i64) -> JsonRpcMessage {
            JsonRpcMessage::Request(JsonRpcRequest::notification(
                "notifications/cancelled",
                Some(serde_json::json!({"requestId": id, "reason": "peer cancelled"})),
            ))
        }

        async fn handshake(cx: &Cx, io: &IoProbe) {
            io.feed(&encoded(&initialize(1)));
            io.feed(&encoded(&initialized()));
            until_io(cx, io, || io.response(1).is_some()).await;
            let response = io.response(1).unwrap();
            assert!(response.error.is_none(), "{response:?}");
            assert_eq!(
                response.result.unwrap()["protocolVersion"],
                LEGACY_PROTOCOL_VERSION
            );
        }

        async fn stop(cx: &Cx, io: &IoProbe, mut serving: Serving) {
            io.eof();
            serving.join(cx).await.unwrap().unwrap();
            let state = io.0.lock().unwrap();
            assert!(state.reader_dropped && state.writer_dropped);
        }

        fn assert_error(io: &IoProbe, id: i64, expected: i32) {
            let response = io.response(id).unwrap();
            assert!(response.result.is_none(), "{response:?}");
            assert_eq!(response.error.unwrap().code.as_i32(), Some(expected));
        }

        fn assert_legacy_result(io: &IoProbe, id: i64, text: &str) {
            let response = io.response(id).unwrap();
            assert!(response.error.is_none(), "{response:?}");
            let result = response.result.unwrap();
            assert_eq!(result["content"][0]["text"], text);
            assert!(result.get("resultType").is_none(), "{result}");
        }

        fn closed(io: &IoProbe) -> bool {
            let state = io.0.lock().unwrap();
            state.reader_dropped && state.writer_dropped
        }

        #[test]
        fn auto_modern_discover_and_tool_use_no_blocking_pool() {
            run_native(|cx| async move {
                let gate = Arc::new(Gate::default());
                let io = Arc::new(IoProbe::default());
                io.allow(usize::MAX);
                let serving = start(&cx, configured(ProtocolPolicy::Auto, &gate).build(), &io);
                io.feed(&encoded(&discover(10)));
                until_io(&cx, &io, || io.response(10).is_some()).await;
                assert!(io.response(10).unwrap().error.is_none());
                io.feed(&encoded(&call(11, false)));
                until_io(&cx, &io, || io.response(11).is_some()).await;
                let response = io.response(11).unwrap();
                assert!(response.error.is_none());
                assert_eq!(response.result.unwrap()["resultType"], "complete");
                assert_eq!(gate.entered.load(Ordering::Acquire), 1);
                assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
                stop(&cx, &io, serving).await;
            });
        }

        #[test]
        fn prebuffered_legacy_lifecycle_drains_ordered_results_after_eof() {
            run_native(|cx| async move {
                for policy in [ProtocolPolicy::Auto, ProtocolPolicy::LegacyOnly] {
                    let gate = Arc::new(Gate::default());
                    let io = Arc::new(IoProbe::default());
                    io.allow(usize::MAX);
                    for message in [initialize(20), initialized(), legacy_call(21, false)] {
                        io.feed(&encoded(&message));
                    }
                    io.eof();
                    let mut serving = start(&cx, configured(policy, &gate).build(), &io);
                    serving.join(&cx).await.unwrap().unwrap();
                    let messages = io.messages();
                    let [
                        JsonRpcMessage::Response(first),
                        JsonRpcMessage::Response(second),
                    ] = messages.as_slice()
                    else {
                        panic!(
                            "legacy lifecycle must emit exactly two ordered results: {messages:?}"
                        );
                    };
                    assert_eq!(first.id, Some(RequestId::Number(20)));
                    assert!(first.error.is_none());
                    assert_eq!(
                        first.result.as_ref().unwrap()["protocolVersion"],
                        LEGACY_PROTOCOL_VERSION
                    );
                    assert_eq!(second.id, Some(RequestId::Number(21)));
                    assert_legacy_result(&io, 21, "executed");
                    assert_eq!(gate.entered.load(Ordering::Acquire), 1);
                    assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
                    assert!(closed(&io));
                }
            });
        }

        struct BadOpening {
            name: &'static str,
            bytes: Vec<u8>,
            error: Option<(Option<i64>, i32)>,
        }

        fn bad_openings(policy: ProtocolPolicy) -> Vec<BadOpening> {
            let JsonRpcMessage::Request(mut mixed) = initialize(30) else {
                unreachable!()
            };
            mixed.params.as_mut().unwrap()["_meta"] = serde_json::json!({
                fastmcp_protocol::FINAL_PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_VERSION,
                fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY: {},
            });
            let JsonRpcMessage::Request(mut wrong_version) = initialize(31) else {
                unreachable!()
            };
            wrong_version.params.as_mut().unwrap()["protocolVersion"] =
                serde_json::json!("2025-03-26");
            let JsonRpcMessage::Request(mut malformed_meta) = initialize(32) else {
                unreachable!()
            };
            malformed_meta.params.as_mut().unwrap()["_meta"] = serde_json::json!([]);
            let JsonRpcMessage::Request(mut missing_capabilities) = discover(33) else {
                unreachable!()
            };
            missing_capabilities.params.as_mut().unwrap()["_meta"] = serde_json::json!({
                fastmcp_protocol::FINAL_PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_VERSION,
            });
            let JsonRpcMessage::Request(mut invalid_log_level) = discover(36) else {
                unreachable!()
            };
            invalid_log_level.params.as_mut().unwrap()["_meta"]["io.modelcontextprotocol/logLevel"] =
                serde_json::json!(true);
            let modern_error = if policy == ProtocolPolicy::LegacyOnly {
                -32601
            } else {
                -32600
            };
            let mut cases = vec![
                BadOpening {
                    name: "malformed JSON",
                    bytes: b"{\n".to_vec(),
                    error: Some((None, -32700)),
                },
                BadOpening {
                    name: "mixed initialize",
                    bytes: encoded(&JsonRpcMessage::Request(mixed)),
                    error: Some((Some(30), modern_error)),
                },
                BadOpening {
                    name: "notification opener",
                    bytes: encoded(&initialized()),
                    error: None,
                },
                BadOpening {
                    name: "response opener",
                    bytes: encoded(&JsonRpcMessage::Response(JsonRpcResponse::success(
                        RequestId::Number(-30),
                        serde_json::json!({}),
                    ))),
                    error: None,
                },
                BadOpening {
                    name: "wrong legacy version",
                    bytes: encoded(&JsonRpcMessage::Request(wrong_version)),
                    error: Some((Some(31), -32600)),
                },
                BadOpening {
                    name: "non-object metadata",
                    bytes: encoded(&JsonRpcMessage::Request(malformed_meta)),
                    error: Some((Some(32), -32600)),
                },
                BadOpening {
                    name: "incomplete modern metadata",
                    bytes: encoded(&JsonRpcMessage::Request(missing_capabilities)),
                    error: Some((
                        Some(33),
                        if policy == ProtocolPolicy::LegacyOnly {
                            -32601
                        } else {
                            -32602
                        },
                    )),
                },
                BadOpening {
                    name: "unmarked tool opener",
                    bytes: encoded(&legacy_call(34, false)),
                    error: Some((Some(34), -32600)),
                },
                BadOpening {
                    name: "invalid modern logging metadata",
                    bytes: encoded(&JsonRpcMessage::Request(invalid_log_level)),
                    error: Some((
                        Some(36),
                        if policy == ProtocolPolicy::LegacyOnly {
                            -32601
                        } else {
                            -32602
                        },
                    )),
                },
            ];
            if policy == ProtocolPolicy::LegacyOnly {
                cases.push(BadOpening {
                    name: "modern discovery under LegacyOnly",
                    bytes: encoded(&discover(35)),
                    error: Some((Some(35), -32601)),
                });
            }
            cases
        }

        async fn reject_bad_openings(cx: &Cx, policy: ProtocolPolicy) {
            for case in bad_openings(policy) {
                let gate = Arc::new(Gate::default());
                let io = Arc::new(IoProbe::default());
                io.feed(&case.bytes);
                // Both valid eras are already buffered behind the bad opener.
                // Neither may restart classification or reach an application.
                for message in [
                    initialize(40),
                    initialized(),
                    legacy_call(41, false),
                    discover(42),
                    call(43, false),
                ] {
                    io.feed(&encoded(&message));
                }
                let mut serving = start(cx, configured(policy, &gate).build(), &io);
                if case.error.is_some() {
                    until_io(cx, &io, || io.0.lock().unwrap().writes > 0).await;
                    let state = io.0.lock().unwrap();
                    assert!(state.outbound.is_empty(), "{}", case.name);
                    assert!(
                        !state.reader_dropped,
                        "{}: reader must survive until the legal error flushes",
                        case.name
                    );
                    assert!(!state.writer_dropped, "{}", case.name);
                    drop(state);
                    io.allow(usize::MAX);
                }
                until_io(cx, &io, || closed(&io)).await;
                assert!(serving.join(cx).await.unwrap().is_err(), "{}", case.name);
                let messages = io.messages();
                match case.error {
                    Some((id, code)) => {
                        let [JsonRpcMessage::Response(response)] = messages.as_slice() else {
                            panic!("{} must emit one legal refusal: {messages:?}", case.name);
                        };
                        assert_eq!(response.id, id.map(RequestId::Number), "{}", case.name);
                        assert!(response.result.is_none(), "{}", case.name);
                        assert_eq!(
                            response.error.as_ref().unwrap().code.as_i32(),
                            Some(code),
                            "{}",
                            case.name
                        );
                    }
                    None => assert!(
                        messages.is_empty(),
                        "{} must close silently: {messages:?}",
                        case.name
                    ),
                }
                assert_eq!(gate.entered.load(Ordering::Acquire), 0, "{}", case.name);
                assert_eq!(gate.dropped.load(Ordering::Acquire), 0, "{}", case.name);
            }
        }

        #[test]
        fn auto_bad_openers_flush_one_legal_error_without_reclassification() {
            run_native(|cx| async move { reject_bad_openings(&cx, ProtocolPolicy::Auto).await });
        }

        #[test]
        fn legacy_only_bad_openers_flush_one_legal_error_without_reclassification() {
            run_native(
                |cx| async move { reject_bad_openings(&cx, ProtocolPolicy::LegacyOnly).await },
            );
        }

        #[test]
        fn unsupported_modern_opening_selects_modern_and_accepts_corrected_version() {
            run_native(|cx| async move {
                let gate = Arc::new(Gate::default());
                let io = Arc::new(IoProbe::default());
                io.allow(usize::MAX);
                let serving = start(&cx, configured(ProtocolPolicy::Auto, &gate).build(), &io);
                let JsonRpcMessage::Request(mut unsupported) = discover(50) else {
                    unreachable!()
                };
                unsupported.params.as_mut().unwrap()["_meta"]
                    [fastmcp_protocol::FINAL_PROTOCOL_VERSION_META_KEY] =
                    serde_json::json!("2099-01-01");
                io.feed(&encoded(&JsonRpcMessage::Request(unsupported)));
                until_io(&cx, &io, || io.response(50).is_some()).await;
                assert_error(&io, 50, -32022);
                assert_eq!(gate.entered.load(Ordering::Acquire), 0);
                io.feed(&encoded(&initialize(51)));
                until_io(&cx, &io, || io.response(51).is_some()).await;
                assert_error(&io, 51, -32601);
                io.feed(&encoded(&call(52, false)));
                until_io(&cx, &io, || io.response(52).is_some()).await;
                let response = io.response(52).unwrap();
                assert!(response.error.is_none());
                assert_eq!(response.result.unwrap()["resultType"], "complete");
                assert_eq!(gate.entered.load(Ordering::Acquire), 1);
                stop(&cx, &io, serving).await;
            });
        }

        #[test]
        fn selected_modern_refuses_legacy_initialize_and_unmarked_tool_then_recovers() {
            run_native(|cx| async move {
                let gate = Arc::new(Gate::default());
                let io = Arc::new(IoProbe::default());
                io.allow(usize::MAX);
                let serving = start(&cx, configured(ProtocolPolicy::Auto, &gate).build(), &io);
                io.feed(&encoded(&discover(60)));
                until_io(&cx, &io, || io.response(60).is_some()).await;
                assert!(io.response(60).unwrap().error.is_none());
                io.feed(&encoded(&initialize(61)));
                io.feed(&encoded(&legacy_call(62, false)));
                until_io(&cx, &io, || {
                    io.response(61).is_some() && io.response(62).is_some()
                })
                .await;
                assert_error(&io, 61, -32601);
                assert_error(&io, 62, -32602);
                assert_eq!(gate.entered.load(Ordering::Acquire), 0);
                io.feed(&encoded(&call(63, false)));
                until_io(&cx, &io, || io.response(63).is_some()).await;
                assert!(io.response(63).unwrap().error.is_none());
                assert_eq!(gate.entered.load(Ordering::Acquire), 1);
                stop(&cx, &io, serving).await;
            });
        }

        #[test]
        fn selected_legacy_rejects_modern_metadata_before_and_after_initialized() {
            run_native(|cx| async move {
                for policy in [ProtocolPolicy::Auto, ProtocolPolicy::LegacyOnly] {
                    for ready in [false, true] {
                        let gate = Arc::new(Gate::default());
                        let io = Arc::new(IoProbe::default());
                        io.allow(usize::MAX);
                        let mut serving = start(&cx, configured(policy, &gate).build(), &io);
                        io.feed(&encoded(&initialize(1)));
                        until_io(&cx, &io, || io.response(1).is_some()).await;
                        assert!(io.response(1).unwrap().error.is_none());
                        if ready {
                            io.feed(&encoded(&initialized()));
                            io.feed(&encoded(&legacy_request(69, "ping", serde_json::json!({}))));
                            until_io(&cx, &io, || io.response(69).is_some()).await;
                            assert!(io.response(69).unwrap().error.is_none());
                        }
                        io.feed(&encoded(&call(70, false)));
                        io.feed(&encoded(&legacy_call(71, false)));
                        until_io(&cx, &io, || closed(&io)).await;
                        assert!(serving.join(&cx).await.unwrap().is_err());
                        assert_error(
                            &io,
                            70,
                            if policy == ProtocolPolicy::LegacyOnly {
                                -32601
                            } else {
                                -32600
                            },
                        );
                        assert!(io.response(71).is_none());
                        assert_eq!(io.messages().len(), if ready { 3 } else { 2 });
                        assert_eq!(gate.entered.load(Ordering::Acquire), 0);
                    }
                }
            });
        }

        struct HandlerLifetime<'a>(&'a Gate);

        impl<'a> HandlerLifetime<'a> {
            fn enter(gate: &'a Gate) -> Self {
                gate.entered.fetch_add(1, Ordering::AcqRel);
                Self(gate)
            }
        }

        impl Drop for HandlerLifetime<'_> {
            fn drop(&mut self) {
                self.0.dropped.fetch_add(1, Ordering::AcqRel);
            }
        }

        struct RootsTool(Arc<Gate>);

        impl ToolHandler for RootsTool {
            fn definition(&self) -> Tool {
                let mut definition = ProbeTool(Arc::clone(&self.0)).definition();
                definition.name = "native_roots".to_owned();
                definition.input_schema =
                    serde_json::json!({"type": "object", "additionalProperties": false});
                definition
            }

            fn execution_mode(&self) -> ToolExecutionMode {
                ToolExecutionMode::Async
            }

            fn call(&self, _: &McpContext, _: serde_json::Value) -> McpResult<Vec<Content>> {
                panic!("native legacy roots must invoke the asynchronous handler")
            }

            fn call_async<'a>(
                &'a self,
                ctx: &'a McpContext,
                _: serde_json::Value,
            ) -> BoxFuture<'a, fastmcp_core::McpOutcome<Vec<Content>>> {
                Box::pin(async move {
                    let _lifetime = HandlerLifetime::enter(&self.0);
                    assert!(ctx.can_list_roots());
                    match ctx.list_roots().await {
                        Ok(roots) => asupersync::Outcome::Ok(vec![Content::text(
                            roots
                                .into_iter()
                                .map(|root| root.uri)
                                .collect::<Vec<_>>()
                                .join(","),
                        )]),
                        Err(error) => asupersync::Outcome::Err(error),
                    }
                })
            }
        }

        struct LogTool(Arc<Gate>);

        impl ToolHandler for LogTool {
            fn definition(&self) -> Tool {
                let mut definition = ProbeTool(Arc::clone(&self.0)).definition();
                definition.name = "native_logs".to_owned();
                definition
            }

            fn execution_mode(&self) -> ToolExecutionMode {
                ToolExecutionMode::Async
            }

            fn call(&self, _: &McpContext, _: serde_json::Value) -> McpResult<Vec<Content>> {
                panic!("native legacy logging must invoke the asynchronous handler")
            }

            fn call_async<'a>(
                &'a self,
                ctx: &'a McpContext,
                arguments: serde_json::Value,
            ) -> BoxFuture<'a, fastmcp_core::McpOutcome<Vec<Content>>> {
                Box::pin(async move {
                    let _lifetime = HandlerLifetime::enter(&self.0);
                    if arguments["hold"] == true {
                        self.0
                            .changed
                            .wait_until(|| self.0.released.load(Ordering::Acquire))
                            .await;
                    }
                    ctx.info("native legacy info");
                    ctx.error("native legacy error");
                    asupersync::Outcome::Ok(vec![Content::text("logged")])
                })
            }
        }

        fn roots_call(id: i64) -> JsonRpcMessage {
            legacy_request(
                id,
                "tools/call",
                serde_json::json!({"name": "native_roots", "arguments": {}}),
            )
        }

        fn log_call(id: i64, hold: bool) -> JsonRpcMessage {
            legacy_request(
                id,
                "tools/call",
                serde_json::json!({"name": "native_logs", "arguments": {"hold": hold}}),
            )
        }

        fn requests(io: &IoProbe, method: &str) -> Vec<JsonRpcRequest> {
            io.messages()
                .into_iter()
                .filter_map(|message| match message {
                    JsonRpcMessage::Request(request) if request.method == method => Some(request),
                    _ => None,
                })
                .collect()
        }

        fn log_payloads(io: &IoProbe) -> Vec<serde_json::Value> {
            requests(io, "notifications/message")
                .into_iter()
                .map(|request| {
                    assert!(request.id.is_none());
                    let params = request.params.unwrap();
                    assert!(
                        params.get("_meta").is_none(),
                        "legacy logs must not acquire final metadata"
                    );
                    params
                })
                .collect()
        }

        async fn set_log_floor(cx: &Cx, io: &IoProbe, level: &str) {
            io.feed(&encoded(&legacy_request(
                2,
                "logging/setLevel",
                serde_json::json!({"level": level}),
            )));
            until_io(cx, io, || io.response(2).is_some()).await;
            assert!(io.response(2).unwrap().error.is_none());
        }

        fn ingress_fence(id: i64) -> JsonRpcMessage {
            // Rejected by ingress, independently of the adapter's currently
            // awaiting handler; its reply proves every preceding frame was read.
            legacy_request(id, "native-test/unknown", serde_json::json!({}))
        }

        #[test]
        fn legacy_reverse_roots_rejects_final_reply_then_accepts_corrected_same_id() {
            run_native(|cx| async move {
                for policy in [ProtocolPolicy::Auto, ProtocolPolicy::LegacyOnly] {
                    let gate = Arc::new(Gate::default());
                    let roots = Arc::new(Gate::default());
                    let io = Arc::new(IoProbe::default());
                    io.allow(usize::MAX);
                    let service = configured(policy, &gate)
                        .tool(RootsTool(Arc::clone(&roots)))
                        .build();
                    let serving = start(&cx, service, &io);
                    handshake(&cx, &io).await;
                    io.feed(&encoded(&roots_call(80)));
                    until_io(&cx, &io, || !requests(&io, "roots/list").is_empty()).await;
                    let reverse = requests(&io, "roots/list").pop().unwrap();
                    let Some(RequestId::Number(reverse_id)) = reverse.id else {
                        panic!("legacy reverse roots requires a server-owned numeric ID");
                    };
                    assert!(reverse_id < 0);
                    assert!(
                        reverse
                            .params
                            .as_ref()
                            .is_none_or(|params| params.get("_meta").is_none())
                    );
                    io.feed(&encoded(&JsonRpcMessage::Response(JsonRpcResponse::success(
                        RequestId::Number(reverse_id),
                        serde_json::json!({"roots": [{"uri": "file:///native/rejected"}], "resultType": "complete"}),
                    ))));
                    io.feed(&encoded(&ingress_fence(81)));
                    until_io(&cx, &io, || io.response(81).is_some()).await;
                    assert_error(&io, 81, -32601);
                    assert!(io.response(80).is_none());
                    assert_eq!(roots.entered.load(Ordering::Acquire), 1);
                    assert_eq!(roots.dropped.load(Ordering::Acquire), 0);
                    io.feed(&encoded(&JsonRpcMessage::Response(JsonRpcResponse::success(
                        RequestId::Number(reverse_id),
                        serde_json::json!({"roots": [{"uri": "file:///native/corrected", "name": "Corrected root"}]}),
                    ))));
                    until_io(&cx, &io, || io.response(80).is_some()).await;
                    assert_legacy_result(&io, 80, "file:///native/corrected");
                    assert_eq!(requests(&io, "roots/list").len(), 1);
                    assert!(requests(&io, "notifications/cancelled").is_empty());
                    assert_eq!(roots.dropped.load(Ordering::Acquire), 1);
                    stop(&cx, &io, serving).await;
                }
            });
        }

        #[test]
        fn legacy_peer_cancel_drops_held_handler_and_preserves_sibling() {
            run_native(|cx| async move {
                for policy in [ProtocolPolicy::Auto, ProtocolPolicy::LegacyOnly] {
                    let gate = Arc::new(Gate::default());
                    let io = Arc::new(IoProbe::default());
                    io.allow(usize::MAX);
                    let serving = start(&cx, configured(policy, &gate).build(), &io);
                    handshake(&cx, &io).await;
                    io.feed(&encoded(&legacy_call(90, true)));
                    until_io(&cx, &io, || gate.entered.load(Ordering::Acquire) == 1).await;
                    io.feed(&encoded(&legacy_cancel(90)));
                    io.feed(&encoded(&legacy_call(91, false)));
                    until_io(&cx, &io, || io.response(91).is_some()).await;
                    assert_legacy_result(&io, 91, "executed");
                    assert!(io.response(90).is_none());
                    assert_eq!(gate.dropped.load(Ordering::Acquire), 2);
                    gate.release();
                    stop(&cx, &io, serving).await;
                    assert!(
                        io.response(90).is_none(),
                        "cancelled handler emitted a late result"
                    );
                }
            });
        }

        #[test]
        fn legacy_logging_floor_retains_explicit_owner_with_two_admitted_requests() {
            run_native(|cx| async move {
                for policy in [ProtocolPolicy::Auto, ProtocolPolicy::LegacyOnly] {
                    for floor in ["info", "error"] {
                        let gate = Arc::new(Gate::default());
                        let logs = Arc::new(Gate::default());
                        let io = Arc::new(IoProbe::default());
                        io.allow(usize::MAX);
                        let service = configured(policy, &gate)
                            .tool(LogTool(Arc::clone(&logs)))
                            .build();
                        let serving = start(&cx, service, &io);
                        handshake(&cx, &io).await;
                        set_log_floor(&cx, &io, floor).await;
                        io.feed(&encoded(&log_call(100, true)));
                        until_io(&cx, &io, || logs.entered.load(Ordering::Acquire) == 1).await;
                        io.feed(&encoded(&legacy_call(101, false)));
                        io.feed(&encoded(&ingress_fence(102)));
                        until_io(&cx, &io, || io.response(102).is_some()).await;
                        assert_error(&io, 102, -32601);
                        assert_eq!(gate.entered.load(Ordering::Acquire), 0);
                        assert!(log_payloads(&io).is_empty());
                        // The second request has an admitted owner but cannot
                        // execute until the first handler returns. Requiring
                        // one unique modern log candidate would lose these logs.
                        logs.release();
                        until_io(&cx, &io, || {
                            io.response(100).is_some() && io.response(101).is_some()
                        })
                        .await;
                        assert_legacy_result(&io, 100, "logged");
                        assert_legacy_result(&io, 101, "executed");
                        let payloads = log_payloads(&io);
                        let observed: Vec<_> = payloads
                            .iter()
                            .filter_map(|params| {
                                let data = params["data"].as_str().unwrap();
                                matches!(data, "native legacy info" | "native legacy error")
                                    .then(|| (params["level"].as_str().unwrap(), data))
                            })
                            .collect();
                        if floor == "info" {
                            assert_eq!(
                                observed,
                                [
                                    ("info", "native legacy info"),
                                    ("error", "native legacy error")
                                ]
                            );
                        } else {
                            assert_eq!(observed, [("error", "native legacy error")]);
                        }
                        assert_eq!(logs.dropped.load(Ordering::Acquire), 1);
                        assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
                        stop(&cx, &io, serving).await;
                    }
                }
            });
        }

        #[test]
        fn legacy_backpressure_peer_cancel_suppresses_queued_logs_and_result() {
            run_native(|cx| async move {
                for policy in [ProtocolPolicy::Auto, ProtocolPolicy::LegacyOnly] {
                    let gate = Arc::new(Gate::default());
                    let logs = Arc::new(Gate::default());
                    let io = Arc::new(IoProbe::default());
                    io.allow(usize::MAX);
                    let service = configured(policy, &gate)
                        .tool(LogTool(Arc::clone(&logs)))
                        .build();
                    let serving = start(&cx, service, &io);
                    handshake(&cx, &io).await;
                    set_log_floor(&cx, &io, "error").await;
                    let writes = io.0.lock().unwrap().writes;
                    io.allow(0);
                    io.feed(&encoded(&legacy_request(
                        110,
                        "ping",
                        serde_json::json!({}),
                    )));
                    until_io(&cx, &io, || io.0.lock().unwrap().writes > writes).await;
                    io.feed(&encoded(&log_call(111, false)));
                    until_io(&cx, &io, || logs.dropped.load(Ordering::Acquire) == 1).await;
                    io.feed(&encoded(&legacy_cancel(111)));
                    io.feed(&encoded(&legacy_call(112, false)));
                    until_io(&cx, &io, || gate.dropped.load(Ordering::Acquire) == 1).await;
                    io.allow(usize::MAX);
                    until_io(&cx, &io, || io.response(112).is_some()).await;
                    assert!(io.response(110).unwrap().error.is_none());
                    assert!(io.response(111).is_none());
                    assert!(log_payloads(&io).is_empty());
                    assert_legacy_result(&io, 112, "executed");
                    stop(&cx, &io, serving).await;
                    assert!(io.response(111).is_none());
                }
            });
        }

        #[test]
        fn legacy_service_abort_drops_pending_handler_and_both_owned_io_halves() {
            run_native(|cx| async move {
                for policy in [ProtocolPolicy::Auto, ProtocolPolicy::LegacyOnly] {
                    let gate = Arc::new(Gate::default());
                    let io = Arc::new(IoProbe::default());
                    io.allow(usize::MAX);
                    let mut serving = start(&cx, configured(policy, &gate).build(), &io);
                    handshake(&cx, &io).await;
                    io.feed(&encoded(&legacy_call(120, true)));
                    until_io(&cx, &io, || gate.entered.load(Ordering::Acquire) == 1).await;
                    serving.abort();
                    serving.join(&cx).await.unwrap().unwrap();
                    assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
                    let state = io.0.lock().unwrap();
                    assert!(!state.eof, "service abort must not depend on peer EOF");
                    assert!(state.reader_dropped && state.writer_dropped);
                    drop(state);
                    assert!(io.response(120).is_none());
                }
            });
        }

        #[test]
        fn legacy_parent_cancel_cleans_reverse_request_once_and_retires_late_reply() {
            run_native(|cx| async move {
                for policy in [ProtocolPolicy::Auto, ProtocolPolicy::LegacyOnly] {
                    let gate = Arc::new(Gate::default());
                    let roots = Arc::new(Gate::default());
                    let io = Arc::new(IoProbe::default());
                    io.allow(usize::MAX);
                    let service = configured(policy, &gate)
                        .tool(RootsTool(Arc::clone(&roots)))
                        .build();
                    let serving = start(&cx, service, &io);
                    handshake(&cx, &io).await;
                    io.feed(&encoded(&roots_call(130)));
                    until_io(&cx, &io, || !requests(&io, "roots/list").is_empty()).await;
                    let reverse = requests(&io, "roots/list").pop().unwrap();
                    let Some(RequestId::Number(reverse_id)) = reverse.id else {
                        panic!("reverse request must have a numeric ID");
                    };
                    assert!(reverse_id < 0);
                    io.feed(&encoded(&legacy_cancel(130)));
                    io.feed(&encoded(&legacy_call(131, false)));
                    until_io(&cx, &io, || io.response(131).is_some()).await;
                    assert_legacy_result(&io, 131, "executed");
                    assert_eq!(roots.dropped.load(Ordering::Acquire), 1);
                    let cleanup = requests(&io, "notifications/cancelled");
                    assert_eq!(cleanup.len(), 1);
                    assert!(cleanup[0].id.is_none());
                    assert_eq!(cleanup[0].params.as_ref().unwrap()["requestId"], reverse_id);
                    assert!(cleanup[0].params.as_ref().unwrap().get("_meta").is_none());
                    io.feed(&encoded(&JsonRpcMessage::Response(
                        JsonRpcResponse::success(
                            RequestId::Number(reverse_id),
                            serde_json::json!({"roots": [{"uri": "file:///native/late"}]}),
                        ),
                    )));
                    io.feed(&encoded(&legacy_cancel(130)));
                    io.feed(&encoded(&legacy_call(132, false)));
                    until_io(&cx, &io, || io.response(132).is_some()).await;
                    assert_legacy_result(&io, 132, "executed");
                    assert!(io.response(130).is_none());
                    assert_eq!(requests(&io, "notifications/cancelled").len(), 1);
                    assert_eq!(requests(&io, "roots/list").len(), 1);
                    assert_eq!(gate.entered.load(Ordering::Acquire), 2);
                    stop(&cx, &io, serving).await;
                    assert!(io.response(130).is_none());
                }
            });
        }

        #[test]
        fn legacy_deadline_replaces_zero_byte_pending_result_and_suppresses_queued_logs() {
            run_native(|cx| async move {
                for policy in [ProtocolPolicy::Auto, ProtocolPolicy::LegacyOnly] {
                    let gate = Arc::new(Gate::default());
                    let logs = Arc::new(Gate::default());
                    let io = Arc::new(IoProbe::default());
                    io.allow(usize::MAX);
                    let service = configured(policy, &gate)
                        .request_timeout(1)
                        .tool(LogTool(Arc::clone(&logs)))
                        .build();
                    let serving = start(&cx, service, &io);
                    handshake(&cx, &io).await;
                    // A successful tool also generates a server info log.
                    // The error floor keeps the first blocked frame a result,
                    // while the second handler still queues its explicit error log.
                    set_log_floor(&cx, &io, "error").await;
                    let (committed_bytes, writes) = {
                        let state = io.0.lock().unwrap();
                        (state.outbound.len(), state.writes)
                    };
                    io.allow(0);
                    io.feed(&encoded(&legacy_call(140, false)));
                    until_io(&cx, &io, || {
                        gate.dropped.load(Ordering::Acquire) == 1
                            && io.0.lock().unwrap().writes > writes
                    })
                    .await;
                    // The first completed result owns the pending write; the
                    // second completed request queues logs and its own result.
                    io.feed(&encoded(&log_call(141, false)));
                    until_io(&cx, &io, || logs.dropped.load(Ordering::Acquire) == 1).await;
                    asupersync::time::sleep(cx.now(), Duration::from_millis(20)).await;
                    let blocked_writes = io.0.lock().unwrap().writes;
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1150)).await;
                    // No input or output capacity changed. A new send attempt
                    // therefore proves the request deadline interrupted the
                    // zero-byte write while it was still pending.
                    until_io(&cx, &io, || io.0.lock().unwrap().writes > blocked_writes).await;
                    assert_eq!(io.0.lock().unwrap().outbound.len(), committed_bytes);
                    assert!(!closed(&io));
                    io.allow(usize::MAX);
                    until_io(&cx, &io, || {
                        io.response(140).is_some() && io.response(141).is_some()
                    })
                    .await;
                    for id in [140, 141] {
                        let response = io.response(id).unwrap();
                        assert!(response.result.is_none());
                        let error = response.error.unwrap();
                        assert_eq!(
                            error.code.as_i32(),
                            Some(i32::from(McpErrorCode::RequestCancelled))
                        );
                        assert_eq!(error.message, "Request timeout exceeded");
                    }
                    assert!(log_payloads(&io).is_empty());
                    io.feed(&encoded(&legacy_call(142, false)));
                    until_io(&cx, &io, || io.response(142).is_some()).await;
                    assert_legacy_result(&io, 142, "executed");
                    assert_eq!(gate.entered.load(Ordering::Acquire), 2);
                    stop(&cx, &io, serving).await;
                }
            });
        }

        #[test]
        fn legacy_deadline_after_three_result_bytes_closes_without_replacement() {
            run_native(|cx| async move {
                for policy in [ProtocolPolicy::Auto, ProtocolPolicy::LegacyOnly] {
                    let gate = Arc::new(Gate::default());
                    let io = Arc::new(IoProbe::default());
                    io.allow(usize::MAX);
                    let service = configured(policy, &gate).request_timeout(1).build();
                    let mut serving = start(&cx, service, &io);
                    handshake(&cx, &io).await;
                    let committed_bytes = io.0.lock().unwrap().outbound.len();
                    io.allow(3);
                    io.feed(&encoded(&legacy_call(150, false)));
                    until_io(&cx, &io, || {
                        io.0.lock().unwrap().outbound.len() == committed_bytes + 3
                    })
                    .await;
                    assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
                    // No more input and no writer wake: the request deadline
                    // itself must interrupt this incomplete JSON-RPC frame.
                    until_io(&cx, &io, || closed(&io)).await;
                    assert!(serving.join(&cx).await.unwrap().is_err());
                    io.allow(usize::MAX);
                    let state = io.0.lock().unwrap();
                    assert!(!state.eof);
                    assert_eq!(state.outbound.len(), committed_bytes + 3);
                    assert!(!state.outbound[committed_bytes..].contains(&b'\n'));
                    assert!(state.reader_dropped && state.writer_dropped);
                    drop(state);
                    assert!(io.response(150).is_none());
                }
            });
        }
    }

    mod native_memory_tests {
        use super::*;
        use fastmcp_transport::memory::create_memory_transport_pair_with_capacity;

        type Serving = asupersync::runtime::TaskHandle<McpResult<()>>;

        fn run_native<F, Fut>(test: F)
        where
            F: FnOnce(Cx) -> Fut,
            Fut: Future<Output = ()>,
        {
            let runtime = RuntimeBuilder::current_thread()
                .blocking_threads(0, 0)
                .build()
                .unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                assert!(cx.blocking_pool_handle().is_none());
                asupersync::time::timeout(cx.now(), Duration::from_secs(8), test(cx.clone()))
                    .await
                    .expect("native memory serving must make bounded runtime progress");
            });
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }

        fn connect(cx: &Cx, service: Server) -> (MemoryTransport, Serving) {
            let (peer, transport) = create_memory_transport_pair_with_capacity(1);
            let serving = cx
                .spawn(
                    move |serve_cx| async move { service.serve_memory(&serve_cx, transport).await },
                )
                .unwrap();
            (peer, serving)
        }

        async fn response(cx: &Cx, peer: &mut MemoryTransport, id: i64) -> JsonRpcResponse {
            let JsonRpcMessage::Response(response) = peer.recv_async(cx).await.unwrap() else {
                panic!("expected the response to {id}");
            };
            assert_eq!(response.id, Some(RequestId::Number(id)));
            response
        }

        async fn stop(cx: &Cx, peer: MemoryTransport, mut serving: Serving) {
            let (mut input, output) = peer.into_split();
            drop(output);
            assert!(matches!(
                input.recv_async(cx).await,
                Err(TransportError::Closed)
            ));
            serving.join(cx).await.unwrap().unwrap();
        }

        #[test]
        fn memory_server_multiplexes_pending_and_ready_calls_without_blocking_pool() {
            run_native(|cx| async move {
                let gate = Arc::new(Gate::default());
                let (mut peer, serving) = connect(&cx, server(&gate));
                peer.send_async(&cx, &discover(1)).await.unwrap();
                assert!(response(&cx, &mut peer, 1).await.error.is_none());
                peer.send_async(&cx, &call(2, true)).await.unwrap();
                until(&cx, || gate.entered.load(Ordering::Acquire) == 1).await;
                peer.send_async(&cx, &call(3, false)).await.unwrap();
                assert!(response(&cx, &mut peer, 3).await.error.is_none());
                assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
                gate.release();
                assert!(response(&cx, &mut peer, 2).await.error.is_none());
                stop(&cx, peer, serving).await;
                assert_eq!(gate.dropped.load(Ordering::Acquire), 2);
                assert!(cx.checkpoint().is_ok());
            });
        }

        #[test]
        fn memory_server_routes_cancellation_while_a_handler_is_pending() {
            run_native(|cx| async move {
                let gate = Arc::new(Gate::default());
                let (mut peer, serving) = connect(&cx, server(&gate));
                peer.send_async(&cx, &call(10, true)).await.unwrap();
                until(&cx, || gate.entered.load(Ordering::Acquire) == 1).await;
                peer.send_async(&cx, &cancel(10)).await.unwrap();
                until(&cx, || gate.dropped.load(Ordering::Acquire) == 1).await;
                peer.send_async(&cx, &call(11, false)).await.unwrap();
                // A late response for 10 fails this exact-id assertion.
                assert!(response(&cx, &mut peer, 11).await.error.is_none());
                stop(&cx, peer, serving).await;
                assert_eq!(gate.dropped.load(Ordering::Acquire), 2);
            });
        }

        #[test]
        fn memory_server_input_half_close_drains_accepted_responses() {
            run_native(|cx| async move {
                let gate = Arc::new(Gate::default());
                let (peer, mut serving) = connect(&cx, server(&gate));
                let (mut input, mut output) = peer.into_split();
                output.send_async(&cx, &call(20, true)).await.unwrap();
                until(&cx, || gate.entered.load(Ordering::Acquire) == 1).await;
                // The result does not exist when input EOF arrives. The old
                // non-stdio EOF branch would cancel it instead of draining.
                drop(output);
                gate.release();
                let JsonRpcMessage::Response(result) = input.recv_async(&cx).await.unwrap() else {
                    panic!("half-close discarded an accepted request");
                };
                assert_eq!(result.id, Some(RequestId::Number(20)));
                assert!(result.error.is_none());
                assert!(matches!(
                    input.recv_async(&cx).await,
                    Err(TransportError::Closed)
                ));
                serving.join(&cx).await.unwrap().unwrap();
                assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
            });
        }

        #[test]
        fn memory_server_subscriptions_and_calls_share_the_native_connection() {
            run_native(|cx| async move {
                let gate = Arc::new(Gate::default());
                let service = server(&gate);
                let subscriptions = Arc::clone(&service.final_subscriptions);
                let (mut peer, serving) = connect(&cx, service);
                peer.send_async(
                    &cx,
                    &request(
                        30,
                        SUBSCRIPTIONS_LISTEN,
                        serde_json::json!({
                            "notifications": {"toolsListChanged": true}
                        }),
                    ),
                )
                .await
                .unwrap();
                let JsonRpcMessage::Request(ack) = peer.recv_async(&cx).await.unwrap() else {
                    panic!("subscription acknowledgement must precede completion");
                };
                assert_eq!(
                    ack.method,
                    fastmcp_protocol::methods::NOTIFICATIONS_SUBSCRIPTIONS_ACKNOWLEDGED
                );
                assert_eq!(
                    ack.params.unwrap()["_meta"]["io.modelcontextprotocol/subscriptionId"],
                    30
                );
                assert_eq!(
                    subscriptions
                        .publish(ServerNotification::ToolsListChanged(None))
                        .unwrap(),
                    1
                );
                let JsonRpcMessage::Request(event) = peer.recv_async(&cx).await.unwrap() else {
                    panic!("expected the live subscription event");
                };
                assert_eq!(event.method, "notifications/tools/list_changed");
                peer.send_async(&cx, &call(31, false)).await.unwrap();
                assert!(response(&cx, &mut peer, 31).await.error.is_none());
                peer.send_async(&cx, &cancel(30)).await.unwrap();
                peer.send_async(&cx, &discover(32)).await.unwrap();
                assert!(response(&cx, &mut peer, 32).await.error.is_none());
                stop(&cx, peer, serving).await;
                assert!(subscriptions.inner.lock().unwrap().entries.is_empty());
            });
        }

        #[test]
        fn memory_connection_writer_backpressure_does_not_block_ingress_or_leak_capacity() {
            run_native(|cx| async move {
                let (peer, transport) = create_memory_transport_pair_with_capacity(1);
                let (mut peer_input, mut peer_output) = peer.into_split();
                let (mut input, mut output) = transport.into_split();
                ConnectionWriter::send(&mut output, &cx, &discover(40))
                    .await
                    .unwrap();
                let second = discover(41);
                {
                    let mut sending = pin!(ConnectionWriter::send(&mut output, &cx, &second));
                    assert!(
                        sending
                            .as_mut()
                            .poll(&mut Context::from_waker(Waker::noop()))
                            .is_pending()
                    );
                    peer_output.send_async(&cx, &cancel(41)).await.unwrap();
                    let frame = ConnectionReader::receive(&mut input, &cx).await.unwrap();
                    assert!(
                        matches!(frame.into_message(), JsonRpcMessage::Request(request) if request.method == "notifications/cancelled")
                    );
                    // Abandon the uncommitted frame while capacity is exhausted.
                }
                let first = peer_input.recv_async(&cx).await.unwrap();
                assert_eq!(
                    serde_json::to_value(first).unwrap(),
                    serde_json::to_value(discover(40)).unwrap()
                );
                ConnectionWriter::send(&mut output, &cx, &discover(42))
                    .await
                    .unwrap();
                let next = peer_input.recv_async(&cx).await.unwrap();
                assert_eq!(
                    serde_json::to_value(next).unwrap(),
                    serde_json::to_value(discover(42)).unwrap()
                );
                ConnectionWriter::close(&mut output, &cx).await.unwrap();
                assert!(matches!(
                    peer_input.recv_async(&cx).await,
                    Err(TransportError::Closed)
                ));
            });
        }

        #[test]
        fn memory_server_rejects_driverless_context_before_startup_or_dispatch() {
            let gate = Arc::new(Gate::default());
            let started = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&started);
            let service = Server::new("memory-driverless", "1")
                .protocol_policy(ProtocolPolicy::ModernOnly)
                .unwrap()
                .tool(ProbeTool(Arc::clone(&gate)))
                .on_startup(move || {
                    flag.store(true, Ordering::Release);
                    Ok::<(), io::Error>(())
                })
                .build();
            let (_peer, transport) = create_memory_transport_pair_with_capacity(1);
            let cx = Cx::for_testing();
            let mut serving = pin!(service.serve_memory(&cx, transport));
            let Poll::Ready(Err(error)) = serving
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("driverless serving must fail before parking");
            };
            assert!(error.message.contains("timer driver"));
            assert!(!started.load(Ordering::Acquire));
            assert_eq!(gate.entered.load(Ordering::Acquire), 0);
        }
    }
}
