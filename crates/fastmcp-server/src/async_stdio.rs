//! Modern stdio framing driven entirely by the embedding's async task.
//!
//! The connection polls ingress independently of egress and request work. No
//! receive thread, blocking-pool pump, or nested runtime participates. Explicit
//! blocking handlers still require the caller's admitted blocking facility.

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, Weak};
use std::task::Poll;

use asupersync::cx::ChildRegionSpec;
use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::sync::Notify;
use asupersync::time::Sleep;
use fastmcp_transport::{
    AsyncStdioRecvHalf, AsyncStdioSendHalf, AsyncStdioTransport, ReceivedTransportFrame,
};

use super::*;

const DOCUMENT_BYTES: usize = 10 * 1024 * 1024;
const SUBSCRIPTION_LIFETIME: Duration = Duration::from_secs(60 * 60);

type RequestWork = Pin<Box<dyn Future<Output = McpResult<()>> + Send>>;
type ReadWork<R> = Pin<
    Box<
        dyn Future<
                Output = (
                    AsyncStdioRecvHalf<R>,
                    Result<ReceivedTransportFrame, TransportError>,
                ),
            > + Send,
    >,
>;
type WriteWork<W> = Pin<
    Box<dyn Future<Output = (AsyncStdioSendHalf<W>, Result<(), TransportError>, usize)> + Send>,
>;

/// The wire cancellation election is separate from the dispatcher's
/// finalization election. A completed handler can still have an uncommitted
/// result queued behind backpressure; peer cancellation must suppress it.
struct OutputOwner {
    reservation: ModernDispatchReservation,
    log_level: Option<LoggingLevel>,
}

impl OutputOwner {
    fn cancelled(&self) -> bool {
        self.reservation.cancellation.is_cancel_requested()
    }
}

struct OutputFrame {
    message: JsonRpcMessage,
    owner: Option<Arc<OutputOwner>>,
    bytes: usize,
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
}

#[derive(Default)]
struct OutputQueue {
    state: Mutex<OutputState>,
    changed: Notify,
}

impl OutputQueue {
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

    fn enqueue(&self, message: JsonRpcMessage, owner: Option<Arc<OutputOwner>>) {
        if owner.as_ref().is_some_and(|owner| owner.cancelled()) {
            return;
        }
        // Count before queue mutation, without allocating encoded copies of
        // a potentially maximum-sized response or notification.
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
        let measured = serde_json::to_writer(&mut count, &message).is_ok();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.stopped || state.failure.is_some() {
            return;
        }
        if !Self::log_has_owner(&state, &message, owner.as_ref()) {
            return;
        }
        let bytes = count.0.saturating_add(1);
        if !measured
            || state.retained_frames >= MAX_DISPATCH_QUEUE_DEPTH
            || bytes > MAX_DISPATCH_QUEUE_BYTES.saturating_sub(state.retained_bytes)
        {
            state.failure = Some("output_capacity");
        } else {
            state.retained_frames += 1;
            state.retained_bytes += bytes;
            state.frames.push_back(OutputFrame {
                message,
                owner,
                bytes,
            });
        }
        drop(state);
        self.changed.notify_waiters();
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
        Self::log_has_owner(&state, &frame.message, frame.owner.as_ref())
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

fn receive<R: AsyncRead + Unpin + Send + 'static>(
    mut reader: AsyncStdioRecvHalf<R>,
    cx: Cx,
) -> ReadWork<R> {
    Box::pin(async move {
        let result = reader.recv_server_with_source_async(&cx).await;
        (reader, result)
    })
}

fn write<W: AsyncWrite + Unpin + Send + 'static>(
    mut writer: AsyncStdioSendHalf<W>,
    cx: Cx,
    frame: OutputFrame,
    output: Arc<OutputQueue>,
) -> WriteWork<W> {
    Box::pin(async move {
        if !output.admits_write(&frame) {
            return (writer, Ok(()), frame.bytes);
        }
        let result = {
            let mut sending = pin!(writer.send_async(&cx, &frame.message));
            let mut timeout = pin!(asupersync::time::sleep(
                cx.now(),
                STDIO_OUTPUT_COMMIT_TIMEOUT
            ));
            let cancellation = frame
                .owner
                .as_ref()
                .map(|owner| owner.reservation.cancellation());
            let mut cancelled = cancellation
                .as_ref()
                .map(|cancel| Box::pin(cancel.cancelled()));
            poll_fn(|task| {
                if frame.owner.as_ref().is_some_and(|owner| owner.cancelled()) {
                    return Poll::Ready(Ok(()));
                }
                if cancelled
                    .as_mut()
                    .is_some_and(|cancelled| cancelled.as_mut().poll(task).is_ready())
                {
                    return Poll::Ready(Ok(()));
                }
                if let Poll::Ready(result) = sending.as_mut().poll(task) {
                    return Poll::Ready(result);
                }
                if timeout.as_mut().poll(task).is_ready() {
                    return Poll::Ready(Err(TransportError::Timeout));
                }
                Poll::Pending
            })
            .await
        };
        // Dropping a cancelled send after a partial write poisons the shared
        // transport. Never interpret that case as a harmless suppressed frame.
        let result = if result.is_ok() && writer.is_closed() {
            Err(TransportError::Closed)
        } else {
            result
        };
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
    let JsonRpcMessage::Request(_) = frame.message() else {
        return Err(server_run_error(
            "receive",
            "direction",
            "Modern stdio received a client response",
        ));
    };
    let (request, raw_params) =
        match JsonRpcRequest::decode_strict_with_raw_params(frame.source(), DOCUMENT_BYTES) {
            Ok(request) => request,
            Err(_) => {
                let id = match frame.message() {
                    JsonRpcMessage::Request(request) => request.id.clone(),
                    _ => None,
                };
                lifetime
                    .output
                    .enqueue(error_response(id, -32600, "Invalid Request"), None);
                return Ok(None);
            }
        };
    if request.method != "initialize"
        && modern_protocol_version(&request) != Some(MODERN_PROTOCOL_VERSION)
    {
        if let Some(id) = request.id.clone() {
            let response = match modern_protocol_version(&request) {
                Some(version) => JsonRpcMessage::Response(JsonRpcResponse::error(
                    Some(id),
                    JsonRpcError {
                        code: fastmcp_protocol::UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE.into(),
                        message: "Unsupported MCP protocol version".to_owned(),
                        data: Some(
                            serde_json::json!({"supported": [MODERN_PROTOCOL_VERSION], "requested": version}),
                        ),
                    },
                )),
                None => error_response(
                    Some(id),
                    -32600,
                    "Modern stdio requires protocol version metadata",
                ),
            };
            lifetime.output.enqueue(response, None);
        }
        return Ok(None);
    }
    if admit_final_client_notification_ingress(&request).is_err() {
        return Ok(None);
    }
    let inbound = InboundRequestContext::with_modern_connection_and_transport_authorization(
        cx.clone(),
        request_id_to_u64(request.id.as_ref()),
        InboundRequestTransport::Stdio,
        &lifetime.connection,
        TransportAuthorization::default(),
    );
    if request.id.is_none() && request.method == "notifications/cancelled" {
        let mut request = request;
        if let Ok(cancellation) = lifetime.server.authenticate_modern_cancelled_control(
            &inbound,
            &mut request,
            None,
            None,
        ) {
            lifetime
                .admission
                .cancel_reserved(Server::cancellation_wire_request_id(&cancellation));
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
        reservation,
    });
    // Authentication binds connection ownership before the next inbound
    // cancellation may be admitted, even if this child has not been polled.
    let receipt = match lifetime
        .server
        .admit_modern_pump_authentication(&inbound, &request, None, None)
    {
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
        let region =
            caller
                .open_child_region(ChildRegionSpec::inherit().with_budget(
                    server.create_owned_modern_request_budget(&caller, &request.method),
                ))
                .await
                .map_err(|_| {
                    server_run_error(
                        "dispatch",
                        "region_open",
                        "Request region could not be opened",
                    )
                })?;
        let request_cx = region.cx().clone();
        let inbound = inbound.with_cx(request_cx.clone());
        let dispatch_cancellation = McpRequestCancellation::new();
        let notification_output = Arc::clone(&output);
        let notification_owner = Arc::clone(&owner);
        let notifications: NotificationSender = Arc::new(move |notification| {
            notification_output.enqueue(
                JsonRpcMessage::Request(notification),
                Some(Arc::clone(&notification_owner)),
            );
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
                None,
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

enum Event<R, W> {
    Read(
        AsyncStdioRecvHalf<R>,
        Result<ReceivedTransportFrame, TransportError>,
    ),
    Written(AsyncStdioSendHalf<W>, Result<(), TransportError>, usize),
    Completed(usize, McpResult<()>),
    Output,
    Stop(Option<McpError>),
    DrainExpired,
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

    /// Serves a ModernOnly NDJSON connection on caller-owned asynchronous I/O.
    ///
    /// Ingress, bounded concurrent requests, subscriptions, and backpressured
    /// egress all progress on the caller's asupersync runtime. Every request
    /// owns a child region; this function creates no runtime, thread, or
    /// blocking-pool job. Use native nonblocking pipe/socket handles: supplying
    /// an adapter that blocks in `poll_read` or `poll_write` does not make that
    /// adapter asynchronous. Own-process/child-process handle construction is
    /// the embedding's responsibility.
    ///
    /// The builder must select [`ProtocolPolicy::ModernOnly`]. This binding is
    /// fixed before input and does not perform a legacy probe or fallback.
    /// Per-request authentication, raw-parameter admission, middleware, Tasks,
    /// MRTR, and subscription dispatch use the same server implementation as
    /// the other modern entrypoints.
    /// Subscriptions have a one-hour absolute lifetime, bounded further by the
    /// caller's context, independent of the ordinary handler timeout. Client
    /// subscription idle and reconnection policy remains client-owned.
    ///
    /// Cancellation suppresses every queued frame for its request. Cancelling
    /// an already partially written frame terminates the connection; a frame
    /// whose flush has completed is committed. Each write has a finite commit
    /// deadline and output retention shares the dispatch count/byte ceilings.
    /// Saturation is a connection failure, never silent loss of a final frame.
    ///
    /// Input EOF permits a five-second response drain, including graceful
    /// subscription completion. At that bound, cancellation, or failure, all
    /// remaining request regions are cancelled and closed before the shutdown
    /// hook runs. Non-cooperative spawned children remain owned and awaited;
    /// this API never detaches them merely to report a timeout. Dropping this
    /// future closes I/O and transfers region cleanup to the caller runtime's
    /// structured close machinery; it does not run a premature shutdown hook.
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
        if self.protocol_policy != ProtocolPolicy::ModernOnly {
            return Err(server_run_error(
                "startup",
                "protocol_policy",
                "Async stdio requires ModernOnly policy",
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
        self.init_rich_logging();
        let server = Arc::new(self);
        if !server.run_startup_hook() {
            return Err(server_run_error(
                "startup",
                "hook",
                "Server startup hook failed",
            ));
        }
        if let Some(stats) = &server.stats {
            stats.connection_opened();
        }
        let lifetime = ConnectionLifetime {
            server: Arc::clone(&server),
            connection: ModernConnection::new(),
            admission: Arc::new(DispatchQueueState::default()),
            output: Arc::new(OutputQueue::default()),
        };
        let (reader, writer) = AsyncStdioTransport::from_io(reader, writer).into_split();
        let mut reading = Some(receive(reader, cx.clone()));
        let mut available_writer = Some(writer);
        let mut writing: Option<WriteWork<W>> = None;
        let mut requests: Vec<RequestWork> = Vec::new();
        let mut drain: Option<Pin<Box<Sleep>>> = None;
        let mut stopping = false;
        let mut error = None;
        let mut request_regions_quiescent = true;
        let mut ingress_first = true;
        loop {
            if !stopping && writing.is_none() && lifetime.output.has_frames() {
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
                            "Async stdio output capacity exhausted",
                        ))));
                    }
                    if cx.checkpoint().is_err() {
                        return Poll::Ready(Event::Stop(None));
                    }
                    if drain
                        .as_mut()
                        .is_some_and(|drain| drain.as_mut().poll(task).is_ready())
                    {
                        return Poll::Ready(Event::DrainExpired);
                    }
                    if ingress_first
                        && let Some(reading) = reading.as_mut()
                        && let Poll::Ready((reader, result)) = reading.as_mut().poll(task)
                    {
                        return Poll::Ready(Event::Read(reader, result));
                    }
                }
                for (index, request) in requests.iter_mut().enumerate() {
                    if let Poll::Ready(result) = request.as_mut().poll(task) {
                        return Poll::Ready(Event::Completed(index, result));
                    }
                }
                if let Some(writing) = writing.as_mut()
                    && let Poll::Ready((writer, result, bytes)) = writing.as_mut().poll(task)
                {
                    return Poll::Ready(Event::Written(writer, result, bytes));
                }
                if !stopping
                    && !ingress_first
                    && let Some(reading) = reading.as_mut()
                    && let Poll::Ready((reader, result)) = reading.as_mut().poll(task)
                {
                    return Poll::Ready(Event::Read(reader, result));
                }
                if !stopping && writing.is_none() && lifetime.output.has_frames() {
                    return Poll::Ready(Event::Output);
                }
                Poll::Pending
            })
            .await;
            ingress_first = !ingress_first;
            let mut stop = false;
            match event {
                Event::Read(reader, result) => {
                    reading = None;
                    match result {
                        Ok(frame) => match prepare_request(&lifetime, cx, frame) {
                            Ok(work) => {
                                if let Some(work) = work {
                                    requests.push(work);
                                }
                                reading = Some(receive(reader, cx.clone()));
                            }
                            Err(failure) => {
                                error.get_or_insert(failure);
                                stop = true;
                            }
                        },
                        Err(TransportError::Closed) => {
                            let _ = server.terminate_subscription_streams_for_shutdown();
                            lifetime.admission.cancel_uncorrelated_modern_children();
                            drain = Some(Box::pin(asupersync::time::sleep(
                                cx.now(),
                                DISPATCH_WORKER_SHUTDOWN_TIMEOUT,
                            )));
                        }
                        Err(TransportError::Cancelled) => stop = true,
                        Err(failure) => match classify_receive_error(&failure) {
                            ReceiveErrorDisposition::ReplyWithParseError => {
                                lifetime
                                    .output
                                    .enqueue(error_response(None, -32700, "Parse error"), None);
                                reading = Some(receive(reader, cx.clone()));
                            }
                            ReceiveErrorDisposition::ReplyWithInvalidRequest(id) => {
                                lifetime
                                    .output
                                    .enqueue(error_response(id, -32600, "Invalid Request"), None);
                                reading = Some(receive(reader, cx.clone()));
                            }
                            ReceiveErrorDisposition::Terminate => {
                                error.get_or_insert(transport_run_error("receive", &failure));
                                stop = true;
                            }
                        },
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
                        "Async stdio response drain exceeded its deadline",
                    ));
                    stop = true;
                }
            }
            if stop && !stopping {
                stopping = true;
                lifetime.admission.stop();
                lifetime.connection.disconnect();
                lifetime.output.stop();
                reading = None;
                writing = None;
                available_writer = None;
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
                writer.close_async(cx),
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
        if request_regions_quiescent {
            server.run_shutdown_hook();
        }
        drop(lifetime);
        error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::io::ReadBuf;
    use asupersync::net::{TcpListener, TcpStream};
    use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
    use fastmcp_protocol::{Content, Tool};
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Waker};

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
            .expect("ModernOnly is available in every build")
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
    async fn until(cx: &Cx, predicate: impl Fn() -> bool) {
        asupersync::time::timeout(cx.now(), Duration::from_secs(3), async {
            while !predicate() {
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("public async stdio observation must arrive within its test budget");
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
        fn messages(&self) -> Vec<JsonRpcMessage> {
            self.0
                .lock()
                .unwrap()
                .outbound
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .filter_map(|line| serde_json::from_slice(line).ok())
                .collect()
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
            let count = output.remaining().min(state.inbound.len());
            for _ in 0..count {
                output.put_slice(&[state.inbound.pop_front().unwrap()]);
            }
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
            until(&cx, || io.messages().iter().any(|message| matches!(message, JsonRpcMessage::Request(request) if request.method == fastmcp_protocol::methods::NOTIFICATIONS_SUBSCRIPTIONS_ACKNOWLEDGED))).await;
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
            for id in [60, 61, 62] {
                let JsonRpcMessage::Request(request) = call(id, true) else {
                    unreachable!()
                };
                let params = serde_json::to_string(request.params.as_ref().unwrap()).unwrap();
                let padded = format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{{}{}}}}}\n",
                    " ".repeat(6 * 1024 * 1024),
                    &params[1..params.len() - 1]
                );
                io.feed(padded.as_bytes());
            }
            until(&cx, || io.response(62).is_some()).await;
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
}
