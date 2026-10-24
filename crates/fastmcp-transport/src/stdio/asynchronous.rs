//! Awaitable NDJSON framing over caller-owned nonblocking I/O.
//!
//! The read buffer belongs to the endpoint, so dropping a pending receive cannot
//! discard a frame prefix. Egress instead has a terminal commit guard: abandoning
//! a partially written frame drops the writer and wakes the other half. A later
//! send must never append a fresh JSON document to that abandoned prefix.

use std::future::{Future, poll_fn};
use std::io;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::sync::Notify;
use asupersync::time::Sleep;
use fastmcp_protocol::JsonRpcMessage;

use super::{AsyncStdioTransport, stdio_checkpoint};
use crate::{
    Codec, CodecError, MAX_CLIENT_TRANSPORT_SOURCE_BYTES, ReceivedTransportFrame, TransportError,
};

const READ_CHUNK_SIZE: usize = 4096;
const READ_TURN_CHUNKS: usize = 16;

/// `Interrupted` results that one `await_io` retries before the operation
/// completes. `Pending` does not transfer bytes or complete a flush/shutdown,
/// so it cannot reset this budget. Each new completed-operation boundary
/// starts a fresh wait with a fresh retry budget.
///
/// `Interrupted` is this layer's single representation for *every* cooperative
/// stop (see `async_io::io_checkpoint`), so it conflates two conditions that
/// need opposite handling. A real `EINTR` consumes nothing and is resolved by
/// the next syscall, which is why the retry exists. But a source whose *own*
/// `Cx` is cancelled or past its deadline reports the same kind on every poll
/// for as long as this caller's context stays live, and retrying that is a
/// busy spin: each turn self-wakes immediately, and a native pipe additionally
/// tears down and rebuilds its reactor registration every turn.
///
/// A run this long is therefore not transient. Stopping is also the
/// fail-closed direction, because `receive` and the send paths pass anything
/// that is neither `Cancelled` nor `Timeout` to `fail_read` / the commit
/// guard, which latches the endpoint closed instead of letting a caller retry
/// into the same spin. The bound is deliberately far above any plausible
/// signal burst and far below the point where a spin would cost real time.
const INTERRUPTED_RETRY_LIMIT: u32 = 64;

#[derive(Default)]
pub(super) struct ReadState {
    buffer: Vec<u8>,
    scanned: usize,
    eof: bool,
}

#[derive(Default)]
pub(super) struct Terminal {
    closed: AtomicBool,
    changed: Notify,
}

impl Terminal {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}

fn native_io_error(cx: &Cx, error: io::Error) -> TransportError {
    if error.kind() == io::ErrorKind::Interrupted {
        if let Err(cancelled) = stdio_checkpoint(cx) {
            return cancelled;
        }
    }
    TransportError::Io(error)
}

// Selecting the caller's drivers must not widen the host's effect authority.
// Capture this before set_current replaces the active context. Only effects
// intersect: cancellation, deadlines and driver identity remain caller-owned.
fn ambient_capability_ceiling() -> CapMask {
    let Some(active) = Cx::current() else {
        return CapMask::all();
    };
    let capabilities = active.capabilities();
    let mut ceiling = CapMask::all();
    for (allowed, without_effect) in [
        (
            capabilities.spawn,
            CapSet::<false, true, true, true, true>::MASK,
        ),
        (
            capabilities.time,
            CapSet::<true, false, true, true, true>::MASK,
        ),
        (
            capabilities.entropy,
            CapSet::<true, true, false, true, true>::MASK,
        ),
        (
            capabilities.io,
            CapSet::<true, true, true, false, true>::MASK,
        ),
        (
            capabilities.remote,
            CapSet::<true, true, true, true, false>::MASK,
        ),
    ] {
        if !allowed {
            ceiling = ceiling.intersect(without_effect);
        }
    }
    ceiling
}

/// Poll under the exact caller context, including its cancellation registration
/// and timer driver. A silent peer does not need to generate an I/O wakeup for
/// cancellation, a deadline, or the opposite half's terminal state to win.
async fn await_io<T>(
    cx: &Cx,
    terminal: &Terminal,
    closing: bool,
    mut operation: impl FnMut(&mut Context<'_>) -> Poll<io::Result<T>>,
) -> Result<T, TransportError> {
    stdio_checkpoint(cx)?;
    let deadline = cx.budget().deadline;
    if deadline.is_some() && cx.timer_driver().is_none() {
        return Err(TransportError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "async stdio deadlines require the caller's timer driver",
        )));
    }
    let mut timeout = deadline.map(|deadline| Box::pin(Sleep::new(deadline)));
    // Keep the sender alive: this channel observes only the receiver's public
    // Cx cancellation registration and never carries an application value.
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = pin!(receiver.recv(cx));
    let mut stopped = pin!(terminal.changed.notified());
    let mut interrupted = 0_u32;
    poll_fn(|task| {
        if !closing && terminal.is_closed() {
            return Poll::Ready(Err(TransportError::Closed));
        }
        // Re-evaluate on every poll: a pending operation may resume under a
        // narrower host scope. Both guards unwind before returning Pending.
        let ceiling = ambient_capability_ceiling();
        let _caller = Cx::set_current(Some(cx.clone()));
        let _restriction = Cx::push_restriction(ceiling);
        if let Err(error) = stdio_checkpoint(cx) {
            return Poll::Ready(Err(error));
        }
        if !closing {
            let _ = stopped.as_mut().poll(task);
            // Register before the second check to close the sibling-close race.
            if terminal.is_closed() {
                return Poll::Ready(Err(TransportError::Closed));
            }
        }
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(stdio_checkpoint(cx)
                .err()
                .unwrap_or(TransportError::Cancelled)));
        }
        if timeout
            .as_mut()
            .is_some_and(|timeout| timeout.as_mut().poll(task).is_ready())
        {
            if let Err(error) = stdio_checkpoint(cx) {
                return Poll::Ready(Err(error));
            }
            // An active mask defers deadline cancellation too. The context
            // observer remains registered and will observe it after unmasking.
            timeout = None;
        }
        // Success is the I/O commitment. Do not turn accepted bytes into a
        // cancellation error by adding a post-poll checkpoint.
        match operation(task) {
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
                if let Err(error) = stdio_checkpoint(cx) {
                    return Poll::Ready(Err(error));
                }
                interrupted += 1;
                if interrupted > INTERRUPTED_RETRY_LIMIT {
                    // The serving caller is still live, but this source has
                    // exceeded the bounded retry policy without completing I/O.
                    return Poll::Ready(Err(TransportError::Io(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!(
                            "async stdio source exceeded {INTERRUPTED_RETRY_LIMIT} \
                             cooperative-stop retries without completing I/O while \
                             this caller's context stayed live; bind the source to the same \
                             Cx that serves it (last reason: {error})"
                        ),
                    ))));
                }
                // A transient OS interruption consumes no bytes. Retry in a
                // later turn, with another checkpoint, instead of losing a
                // retained prefix or spinning inside this executor poll.
                task.waker().wake_by_ref();
                Poll::Pending
            }
            result => {
                // Pending is not progress, even if the source self-woke. Only
                // completing this wait starts a fresh budget for the next I/O.
                result.map(|result| result.map_err(|error| native_io_error(cx, error)))
            }
        }
    })
    .await
}

fn fail_read<R>(reader: &mut Option<R>, state: &mut ReadState, terminal: &Terminal) {
    terminal.close();
    reader.take();
    state.buffer = Vec::new();
    state.scanned = 0;
}

async fn receive<R: AsyncRead + Unpin>(
    cx: &Cx,
    reader: &mut Option<R>,
    state: &mut ReadState,
    codec: &Codec,
    terminal: &Terminal,
    server_ingress: bool,
) -> Result<ReceivedTransportFrame, TransportError> {
    let mut chunks = 0;
    loop {
        if terminal.is_closed() || reader.is_none() {
            reader.take();
            state.buffer = Vec::new();
            state.scanned = 0;
            return Err(TransportError::Closed);
        }
        // No dequeue or buffer mutation on cancellation: a live next receive
        // resumes the exact prefix, including a fully buffered unread frame.
        stdio_checkpoint(cx)?;
        let newline = state.buffer[state.scanned..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| state.scanned + offset);
        if newline.is_some() || state.eof {
            let consumed = newline.map_or(state.buffer.len(), |position| position + 1);
            let mut length = newline.unwrap_or(state.buffer.len());
            if length > 0 && state.buffer[length - 1] == b'\r' {
                length -= 1;
            }
            if length > codec.max_message_size() {
                fail_read(reader, state, terminal);
                return Err(TransportError::Codec(CodecError::MessageTooLarge(length)));
            }
            if length == 0 && state.eof && newline.is_none() {
                reader.take();
                return Err(TransportError::Closed);
            }
            let mut source = std::mem::take(&mut state.buffer);
            state.buffer = source.split_off(consumed);
            state.scanned = 0;
            source.truncate(length);
            if source.iter().all(u8::is_ascii_whitespace) {
                chunks += 1;
            } else {
                match ReceivedTransportFrame::admit(source) {
                    Ok(frame) => return Ok(frame),
                    Err(error) => {
                        // A server may answer a bounded, isolated request-like
                        // line without losing framing. Client ingress has no
                        // trusted response owner and remains terminal.
                        let recoverable_request = server_ingress
                            && matches!(
                                &error,
                                TransportError::Codec(
                                    CodecError::Json(_)
                                        | CodecError::InvalidMessage {
                                            kind: crate::InvalidMessageKind::Request,
                                            ..
                                        }
                                )
                            );
                        if !recoverable_request {
                            fail_read(reader, state, terminal);
                        }
                        return Err(error);
                    }
                }
            }
        } else {
            state.scanned = state.buffer.len();
            // Retain at most one maximum-size document and its CRLF delimiter.
            // An oversized peer is rejected without draining its suffix.
            let wire_limit = codec.max_message_size().saturating_add(2);
            let remaining = wire_limit.saturating_sub(state.buffer.len());
            if remaining == 0 {
                let size = state.buffer.len();
                fail_read(reader, state, terminal);
                return Err(TransportError::Codec(CodecError::MessageTooLarge(size)));
            }
            let mut bytes = [0_u8; READ_CHUNK_SIZE];
            let limit = remaining.min(bytes.len());
            let result = await_io(cx, terminal, false, |task| {
                let Some(reader) = reader.as_mut() else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "async stdio reader closed",
                    )));
                };
                let mut output = ReadBuf::new(&mut bytes[..limit]);
                Pin::new(reader)
                    .poll_read(task, &mut output)
                    .map(|result| result.map(|()| output.filled().len()))
            })
            .await;
            match result {
                Ok(0) => state.eof = true,
                Ok(count) => {
                    let required = state.buffer.len() + count;
                    if required > state.buffer.capacity() {
                        let capacity = state
                            .buffer
                            .capacity()
                            .max(READ_CHUNK_SIZE)
                            .saturating_mul(2)
                            .max(required)
                            .min(wire_limit);
                        state.buffer.reserve_exact(capacity - state.buffer.len());
                    }
                    state.buffer.extend_from_slice(&bytes[..count]);
                }
                Err(error @ (TransportError::Cancelled | TransportError::Timeout)) => {
                    return Err(error);
                }
                Err(error) => {
                    fail_read(reader, state, terminal);
                    return Err(error);
                }
            }
            chunks += 1;
        }
        if chunks >= READ_TURN_CHUNKS {
            // Even an always-readable peer sending empty lines or a large
            // frame must yield so unrelated caller-owned tasks can run.
            asupersync::runtime::yield_now().await;
            chunks = 0;
        }
    }
}

struct WriteCommit<'a, W> {
    writer: &'a mut Option<W>,
    terminal: &'a Terminal,
    started: bool,
    complete: bool,
}

impl<W> WriteCommit<'_, W> {
    fn fail(&mut self) {
        self.terminal.close();
        self.writer.take();
    }
}

impl<W> Drop for WriteCommit<'_, W> {
    fn drop(&mut self) {
        if self.started && !self.complete {
            self.fail();
        }
    }
}

async fn send<W: AsyncWrite + Unpin>(
    cx: &Cx,
    writer: &mut Option<W>,
    codec: &Codec,
    terminal: &Terminal,
    message: &JsonRpcMessage,
) -> Result<(), TransportError> {
    if terminal.is_closed() || writer.is_none() {
        writer.take();
        return Err(TransportError::Closed);
    }
    stdio_checkpoint(cx)?;
    let bytes = match message {
        JsonRpcMessage::Request(request) => codec.encode_request(request)?,
        JsonRpcMessage::Response(response) => codec.encode_response(response)?,
    };
    let mut commit = WriteCommit {
        writer,
        terminal,
        started: false,
        complete: false,
    };
    let mut offset = 0;
    while offset < bytes.len() {
        let result = await_io(cx, terminal, false, |task| {
            let Some(writer) = commit.writer.as_mut() else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "async stdio writer closed",
                )));
            };
            Pin::new(writer).poll_write(task, &bytes[offset..])
        })
        .await;
        match result {
            Ok(0) => {
                commit.fail();
                return Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "async stdio write returned zero",
                )));
            }
            Ok(count) if count <= bytes.len() - offset => {
                // Record acceptance before the next await can be dropped.
                commit.started = true;
                offset += count;
            }
            Ok(_) => {
                commit.fail();
                return Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "async stdio writer overreported accepted bytes",
                )));
            }
            Err(error @ (TransportError::Cancelled | TransportError::Timeout)) => {
                return Err(error);
            }
            Err(error) => {
                commit.fail();
                return Err(error);
            }
        }
        // Bound continuously-ready short writes per executor turn as well.
        if offset < bytes.len() {
            asupersync::runtime::yield_now().await;
        }
    }
    let result = await_io(cx, terminal, false, |task| {
        let Some(writer) = commit.writer.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "async stdio writer closed",
            )));
        };
        Pin::new(writer).poll_flush(task)
    })
    .await;
    if result.is_ok() {
        commit.complete = true;
    }
    result
}

async fn close_writer<W: AsyncWrite + Unpin>(
    cx: &Cx,
    writer: &mut Option<W>,
    terminal: &Terminal,
) -> Result<(), TransportError> {
    if writer.is_none() || terminal.is_closed() {
        writer.take();
        return Ok(());
    }
    stdio_checkpoint(cx)?;
    terminal.close();
    // Once close is elected, a cancelled/dropped shutdown releases the owned
    // handle instead of leaving a pending writer behind a terminal endpoint.
    let mut commit = WriteCommit {
        writer,
        terminal,
        started: true,
        complete: false,
    };
    let result = await_io(cx, terminal, true, |task| {
        let Some(writer) = commit.writer.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        Pin::new(writer).poll_shutdown(task)
    })
    .await;
    commit.writer.take();
    commit.complete = true;
    result
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncStdioTransport<R, W> {
    /// Owns nonblocking asupersync I/O handles and uses awaitable NDJSON framing.
    ///
    /// Use independently owned native pipe or socket halves. The caller owns
    /// the runtime and passes its `Cx` to every operation; no runtime or thread
    /// is created here. An adapter whose `poll_read`/`poll_write` blocks is not
    /// made nonblocking by this constructor.
    #[must_use]
    pub fn from_io(reader: R, writer: W) -> Self {
        Self {
            reader: Some(reader),
            writer: Some(writer),
            codec: Codec::new(),
            closed: false,
            asynchronous: ReadState::default(),
            terminal: Arc::new(Terminal::default()),
        }
    }

    /// Selects a bounded document size before exposing the transport.
    ///
    /// The bound excludes LF/CRLF framing and cannot exceed the shared client
    /// source-retention ceiling. Buffered input is rechecked on the next receive.
    pub fn with_max_message_size(mut self, size: usize) -> Result<Self, TransportError> {
        if size == 0 || size > MAX_CLIENT_TRANSPORT_SOURCE_BYTES {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "async stdio message size is outside the supported bounds",
            )));
        }
        self.codec.set_max_message_size(size);
        Ok(self)
    }

    /// Receives one admitted message while retaining unread prefixes on cancel.
    pub async fn recv_async(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        self.recv_with_source_async(cx)
            .await
            .map(ReceivedTransportFrame::into_message)
    }

    /// Receives a typed message with its exact peer-authored JSON source.
    ///
    /// LF and CRLF framing, bounded blank lines, and a final complete document
    /// at EOF are accepted. Malformed/oversized input closes both split paths.
    /// A cancelled or dropped receive retains its prefix for a later live caller.
    pub async fn recv_with_source_async(
        &mut self,
        cx: &Cx,
    ) -> Result<ReceivedTransportFrame, TransportError> {
        receive(
            cx,
            &mut self.reader,
            &mut self.asynchronous,
            &self.codec,
            &self.terminal,
            false,
        )
        .await
    }

    /// Writes and flushes exactly one complete NDJSON frame.
    ///
    /// Cancellation or dropping this future before any accepted bytes leaves
    /// the transport reusable. After the first accepted byte, cancellation,
    /// error, or drop closes the writer and both transport paths. Successful
    /// flush is never retroactively changed to cancellation. Use `into_split`
    /// when ingress must continue while outbound backpressure is pending.
    pub async fn send_async(
        &mut self,
        cx: &Cx,
        message: &JsonRpcMessage,
    ) -> Result<(), TransportError> {
        send(cx, &mut self.writer, &self.codec, &self.terminal, message).await
    }

    /// Shuts down owned egress under the caller's budget and releases ingress.
    /// A pre-cancelled caller leaves an open transport unchanged and retryable.
    pub async fn close_async(&mut self, cx: &Cx) -> Result<(), TransportError> {
        if !self.terminal.is_closed() {
            stdio_checkpoint(cx)?;
        }
        let result = close_writer(cx, &mut self.writer, &self.terminal).await;
        if self.terminal.is_closed() {
            self.reader.take();
            self.asynchronous.buffer = Vec::new();
        }
        result
    }

    /// Separates one bounded reader from an independently awaitable writer.
    #[must_use]
    pub fn into_split(self) -> (AsyncStdioRecvHalf<R>, AsyncStdioSendHalf<W>) {
        let mut send_codec = Codec::new();
        send_codec.set_max_message_size(self.codec.max_message_size());
        (
            AsyncStdioRecvHalf {
                reader: self.reader,
                state: self.asynchronous,
                codec: self.codec,
                terminal: Arc::clone(&self.terminal),
            },
            AsyncStdioSendHalf {
                writer: self.writer,
                codec: send_codec,
                terminal: self.terminal,
            },
        )
    }

    /// Reports a framing/write failure, explicit close, or exhausted ingress.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.terminal.is_closed() || self.reader.is_none() || self.writer.is_none()
    }
}

/// One source-preserving asynchronous NDJSON reader, independent of egress.
///
/// Dropping this endpoint closes the connection and wakes pending egress,
/// unless all input has already been drained through a clean EOF. Dropping
/// only a receive future instead retains this endpoint and its frame prefix.
pub struct AsyncStdioRecvHalf<R> {
    reader: Option<R>,
    state: ReadState,
    codec: Codec,
    terminal: Arc<Terminal>,
}

impl<R> Drop for AsyncStdioRecvHalf<R> {
    fn drop(&mut self) {
        // Preserve the clean-EOF half-close: an already-owned response may
        // still need to drain. Abandoning live ingress (including a retained
        // frame prefix) must not leave its sibling asleep on backpressure.
        if !self.state.eof || !self.state.buffer.is_empty() {
            self.terminal.close();
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncStdioRecvHalf<R> {
    /// Receives without blocking the executor or acquiring the writer.
    pub async fn recv_async(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        self.recv_with_source_async(cx)
            .await
            .map(ReceivedTransportFrame::into_message)
    }

    /// Retains exact JSON bytes and incomplete input across dropped operations.
    pub async fn recv_with_source_async(
        &mut self,
        cx: &Cx,
    ) -> Result<ReceivedTransportFrame, TransportError> {
        receive(
            cx,
            &mut self.reader,
            &mut self.state,
            &self.codec,
            &self.terminal,
            false,
        )
        .await
    }

    /// Receives one client line at a server's already-selected protocol binding.
    ///
    /// An isolated syntax error or invalid request retains the following line
    /// so the server can send its bounded parse/invalid-request response.
    /// Oversized, response-like invalid, and I/O failures remain terminal.
    /// Client consumers must use [`Self::recv_with_source_async`], whose shared
    /// response-channel failures always terminate instead of guessing an owner.
    pub async fn recv_server_with_source_async(
        &mut self,
        cx: &Cx,
    ) -> Result<ReceivedTransportFrame, TransportError> {
        receive(
            cx,
            &mut self.reader,
            &mut self.state,
            &self.codec,
            &self.terminal,
            true,
        )
        .await
    }

    /// Explicitly closes the connection and wakes pending egress.
    /// Clean input EOF alone permits the sender to finish already-owned work.
    pub fn close(&mut self, cx: &Cx) -> Result<(), TransportError> {
        if !self.is_closed() {
            stdio_checkpoint(cx)?;
        }
        fail_read(&mut self.reader, &mut self.state, &self.terminal);
        Ok(())
    }

    /// Reports whether ingress or the shared connection is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.reader.is_none() || self.terminal.is_closed()
    }
}

/// One asynchronous NDJSON writer with a terminal partial-frame commit guard.
///
/// Dropping this endpoint closes the connection and wakes pending ingress,
/// even when no send or asynchronous close operation is in progress.
pub struct AsyncStdioSendHalf<W> {
    writer: Option<W>,
    codec: Codec,
    terminal: Arc<Terminal>,
}

impl<W> Drop for AsyncStdioSendHalf<W> {
    fn drop(&mut self) {
        // Closing the underlying handle alone cannot wake a reader parked on
        // a different descriptor (or a caller-supplied in-memory reader).
        self.terminal.close();
    }
}

impl<W: AsyncWrite + Unpin> AsyncStdioSendHalf<W> {
    /// Writes independently while the peer's requests and responses are read.
    pub async fn send_async(
        &mut self,
        cx: &Cx,
        message: &JsonRpcMessage,
    ) -> Result<(), TransportError> {
        send(cx, &mut self.writer, &self.codec, &self.terminal, message).await
    }

    /// Closes the connection and interrupts a silent pending receive.
    pub async fn close_async(&mut self, cx: &Cx) -> Result<(), TransportError> {
        close_writer(cx, &mut self.writer, &self.terminal).await
    }

    /// Reports whether egress or the shared connection is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.writer.is_none() || self.terminal.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Wake, Waker};

    use asupersync::net::{TcpListener, TcpStream};
    use asupersync::runtime::RuntimeBuilder;
    use fastmcp_protocol::{JsonRpcRequest, JsonRpcResponse, RequestId};

    /// Counts frame delimiters in a small captured test buffer.
    #[expect(
        clippy::naive_bytecount,
        reason = "a test counts a few delimiters; no bytecount dependency"
    )]
    fn newline_count(bytes: &[u8]) -> usize {
        bytes.iter().filter(|byte| **byte == b'\n').count()
    }

    struct ReadStarted<R> {
        reader: R,
        started: Arc<AtomicBool>,
    }

    impl<R: AsyncRead + Unpin> AsyncRead for ReadStarted<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            task: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.started.store(true, Ordering::SeqCst);
            Pin::new(&mut this.reader).poll_read(task, output)
        }
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn poll<T>(future: Pin<&mut impl Future<Output = T>>, waker: &Waker) -> Poll<T> {
        future.poll(&mut Context::from_waker(waker))
    }

    fn ready<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        for _ in 0..128 {
            if let Poll::Ready(value) = poll(future.as_mut(), Waker::noop()) {
                return value;
            }
        }
        panic!("bounded in-memory operation must complete");
    }

    fn request(id: i64) -> JsonRpcMessage {
        JsonRpcMessage::Request(JsonRpcRequest::new("test/async-stdio", None, id))
    }

    #[derive(Default)]
    struct Feed {
        bytes: Mutex<VecDeque<u8>>,
        waker: Mutex<Option<Waker>>,
        polls: AtomicUsize,
        eof: AtomicBool,
    }

    impl Feed {
        fn push(&self, bytes: &[u8]) {
            self.bytes.lock().unwrap().extend(bytes);
            if let Some(waker) = self.waker.lock().unwrap().take() {
                waker.wake();
            }
        }
    }

    struct FeedReader(Arc<Feed>);

    impl AsyncRead for FeedReader {
        fn poll_read(
            self: Pin<&mut Self>,
            task: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.0.polls.fetch_add(1, Ordering::SeqCst);
            let mut bytes = self.0.bytes.lock().unwrap();
            if bytes.is_empty() && !self.0.eof.load(Ordering::SeqCst) {
                *self.0.waker.lock().unwrap() = Some(task.waker().clone());
                return Poll::Pending;
            }
            while output.remaining() > 0 {
                let Some(byte) = bytes.pop_front() else {
                    break;
                };
                output.put_slice(&[byte]);
            }
            Poll::Ready(Ok(()))
        }
    }

    struct Output {
        bytes: Mutex<Vec<u8>>,
        allowance: AtomicUsize,
        flush_ready: AtomicBool,
        dropped: AtomicBool,
        cancel_on_flush: Option<Cx>,
    }

    impl Output {
        fn new(allowance: usize) -> Arc<Self> {
            Arc::new(Self {
                bytes: Mutex::new(Vec::new()),
                allowance: AtomicUsize::new(allowance),
                flush_ready: AtomicBool::new(true),
                dropped: AtomicBool::new(false),
                cancel_on_flush: None,
            })
        }
    }

    struct TestWriter(Arc<Output>);

    impl Drop for TestWriter {
        fn drop(&mut self) {
            self.0.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl AsyncWrite for TestWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _task: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut committed = self.0.bytes.lock().unwrap();
            let count = self
                .0
                .allowance
                .load(Ordering::SeqCst)
                .saturating_sub(committed.len())
                .min(bytes.len());
            if count == 0 {
                return Poll::Pending;
            }
            committed.extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<io::Result<()>> {
            if !self.0.flush_ready.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            if let Some(cx) = &self.0.cancel_on_flush {
                cx.set_cancel_requested(true);
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(task)
        }
    }

    #[test]
    fn async_stdio_dropped_send_half_wakes_silent_ingress() {
        let feed = Arc::new(Feed::default());
        let output = Output::new(usize::MAX);
        let (mut reader, writer) = AsyncStdioTransport::from_io(
            FeedReader(Arc::clone(&feed)),
            TestWriter(Arc::clone(&output)),
        )
        .into_split();
        let cx = Cx::for_testing();
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        {
            let mut receiving = pin!(reader.recv_async(&cx));
            assert!(poll(receiving.as_mut(), &waker).is_pending());
            let before = count.0.load(Ordering::SeqCst);
            drop(writer);
            assert!(output.dropped.load(Ordering::SeqCst));
            assert!(count.0.load(Ordering::SeqCst) > before);
            assert!(matches!(
                poll(receiving.as_mut(), &waker),
                Poll::Ready(Err(TransportError::Closed))
            ));
        }
        assert!(reader.is_closed());
        assert_eq!(Arc::strong_count(&feed), 1, "ingress handle is released");
    }

    #[test]
    fn async_stdio_dropped_recv_half_wakes_uncommitted_and_partial_sends() {
        for allowance in [0, 5] {
            let output = Output::new(allowance);
            let (reader, mut writer) = AsyncStdioTransport::from_io(
                FeedReader(Arc::new(Feed::default())),
                TestWriter(Arc::clone(&output)),
            )
            .into_split();
            let cx = Cx::for_testing();
            let count = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&count));
            let message = request(81);
            {
                let mut sending = pin!(writer.send_async(&cx, &message));
                assert!(poll(sending.as_mut(), &waker).is_pending());
                // Complete a possible short-write yield, then park on I/O.
                assert!(poll(sending.as_mut(), &waker).is_pending());
                let before = count.0.load(Ordering::SeqCst);
                drop(reader);
                assert!(count.0.load(Ordering::SeqCst) > before);
                assert!(matches!(
                    poll(sending.as_mut(), &waker),
                    Poll::Ready(Err(TransportError::Closed))
                ));
            }
            assert!(writer.is_closed());
            assert!(output.dropped.load(Ordering::SeqCst));
            assert_eq!(output.bytes.lock().unwrap().len(), allowance);
            output.allowance.store(usize::MAX, Ordering::SeqCst);
            assert!(matches!(
                ready(writer.send_async(&cx, &request(82))),
                Err(TransportError::Closed)
            ));
            assert_eq!(output.bytes.lock().unwrap().len(), allowance);
        }
    }

    #[test]
    fn async_stdio_dropped_recv_half_discards_retained_prefix_and_closes_egress() {
        let feed = Arc::new(Feed::default());
        feed.push(b"{\"jsonrpc\":\"2.0\"");
        let (mut reader, mut writer) =
            AsyncStdioTransport::from_io(FeedReader(Arc::clone(&feed)), Vec::<u8>::new())
                .into_split();
        let cx = Cx::for_testing();
        {
            let mut receiving = pin!(reader.recv_async(&cx));
            assert!(poll(receiving.as_mut(), Waker::noop()).is_pending());
        }
        assert!(
            !writer.is_closed(),
            "dropping only the operation is retryable"
        );
        assert!(!reader.state.buffer.is_empty());
        drop(reader);
        assert!(writer.is_closed());
        assert_eq!(Arc::strong_count(&feed), 1);
        assert!(matches!(
            ready(writer.send_async(&cx, &request(83))),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn async_stdio_dropped_recv_half_after_final_eof_keeps_egress_drainable() {
        let source = br#"{"jsonrpc":"2.0","method":"test/eof","id":84}"#;
        // Returning a final unterminated document already observes clean EOF;
        // a caller need not perform one extra receive before dropping ingress.
        for receive_closed in [false, true] {
            let output = Output::new(usize::MAX);
            let (mut reader, mut writer) =
                AsyncStdioTransport::from_io(source.as_slice(), TestWriter(Arc::clone(&output)))
                    .into_split();
            let cx = Cx::for_testing();
            assert_eq!(
                ready(reader.recv_with_source_async(&cx)).unwrap().source(),
                source
            );
            if receive_closed {
                assert!(matches!(
                    ready(reader.recv_async(&cx)),
                    Err(TransportError::Closed)
                ));
            }
            drop(reader);
            assert!(!writer.is_closed());
            ready(writer.send_async(&cx, &request(85))).unwrap();
            assert_eq!(newline_count(&output.bytes.lock().unwrap()), 1);
            assert!(!output.dropped.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn async_stdio_preserves_source_crlf_coalesced_frames_and_final_eof() {
        let source = br#"{"jsonrpc":"2.0","id":1,"result":{"n":7e1,"z":-0.000e+2}}"#;
        let second = br#"{"jsonrpc":"2.0","method":"test/second","id":"two"}"#;
        let bytes = [b"\r\n".as_slice(), source, b"\r\n", second].concat();
        let transport = AsyncStdioTransport::from_io(bytes.as_slice(), Vec::<u8>::new());
        let (mut reader, mut writer) = transport.into_split();
        let cx = Cx::for_testing();
        assert_eq!(
            ready(reader.recv_with_source_async(&cx)).unwrap().source(),
            source
        );
        assert_eq!(
            ready(reader.recv_with_source_async(&cx)).unwrap().source(),
            second
        );
        assert!(matches!(
            ready(reader.recv_async(&cx)),
            Err(TransportError::Closed)
        ));
        // A clean inbound EOF permits the response writer to finish its work.
        ready(writer.send_async(&cx, &request(3))).unwrap();
        assert!(!writer.is_closed());
    }

    #[test]
    fn async_stdio_cancelled_idle_receive_wakes_and_retains_partial_input() {
        let feed = Arc::new(Feed::default());
        let source = br#"{"jsonrpc":"2.0","method":"test/resume","id":4}"#;
        feed.push(&source[..19]);
        let mut transport =
            AsyncStdioTransport::from_io(FeedReader(Arc::clone(&feed)), Vec::<u8>::new());
        let cancelled = Cx::for_testing();
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        {
            let mut receive = pin!(transport.recv_async(&cancelled));
            assert!(poll(receive.as_mut(), &waker).is_pending());
            let before = count.0.load(Ordering::SeqCst);
            cancelled.set_cancel_requested(true);
            assert!(
                count.0.load(Ordering::SeqCst) > before,
                "cancellation wakes without peer I/O"
            );
            assert!(matches!(
                poll(receive.as_mut(), &waker),
                Poll::Ready(Err(TransportError::Cancelled))
            ));
        }
        assert!(!transport.is_closed());
        feed.push(&[&source[19..], b"\n"].concat());
        assert_eq!(
            ready(transport.recv_with_source_async(&Cx::for_testing()))
                .unwrap()
                .source(),
            source
        );
    }

    #[test]
    fn async_stdio_dropped_receive_resumes_prefix_without_publishing_partial_frame() {
        let feed = Arc::new(Feed::default());
        let source = br#"{"jsonrpc":"2.0","method":"test/resume","id":4}"#;
        feed.push(&source[..19]);
        let mut transport =
            AsyncStdioTransport::from_io(FeedReader(Arc::clone(&feed)), Vec::<u8>::new());
        let cx = Cx::for_testing();
        {
            let mut receive = pin!(transport.recv_async(&cx));
            assert!(poll(receive.as_mut(), Waker::noop()).is_pending());
        }
        feed.push(&[&source[19..], b"\n"].concat());
        assert_eq!(
            ready(transport.recv_with_source_async(&cx))
                .unwrap()
                .source(),
            source
        );
    }

    #[test]
    fn async_stdio_frame_bound_accepts_exact_size_and_closes_on_one_extra_byte() {
        let source = br#"{"jsonrpc":"2.0","method":"test/bound","id":5}"#;
        let cx = Cx::for_testing();
        let outgoing = JsonRpcMessage::Request(JsonRpcRequest::new("test/bound", None, 6_i64));
        for extra in [false, true] {
            let wire = if extra {
                [source.as_slice(), b" \r\n"].concat()
            } else {
                [source.as_slice(), b"\r\n"].concat()
            };
            let transport = AsyncStdioTransport::from_io(wire.as_slice(), Vec::<u8>::new())
                .with_max_message_size(source.len())
                .unwrap();
            let (mut reader, mut writer) = transport.into_split();
            let result = ready(reader.recv_with_source_async(&cx));
            if extra {
                assert!(matches!(
                    result,
                    Err(TransportError::Codec(CodecError::MessageTooLarge(_)))
                ));
                assert!(matches!(
                    ready(writer.send_async(&cx, &outgoing)),
                    Err(TransportError::Closed)
                ));
            } else {
                assert_eq!(result.unwrap().source(), source);
                ready(writer.send_async(&cx, &outgoing)).unwrap();
            }
        }
    }

    #[test]
    fn async_stdio_malformed_frame_wakes_backpressured_writer_without_output() {
        let wire = b"{\"jsonrpc\":\"2.0\",\"method\":\"test\",\"id\":1,\"id\":2}\n";
        let output = Output::new(0);
        let (mut reader, mut writer) =
            AsyncStdioTransport::from_io(wire.as_slice(), TestWriter(Arc::clone(&output)))
                .into_split();
        let cx = Cx::for_testing();
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let message = request(7);
        {
            let mut sending = pin!(writer.send_async(&cx, &message));
            assert!(poll(sending.as_mut(), &waker).is_pending());
            assert!(matches!(
                ready(reader.recv_async(&cx)),
                Err(TransportError::Codec(_))
            ));
            assert!(count.0.load(Ordering::SeqCst) > 0);
            assert!(matches!(
                poll(sending.as_mut(), &waker),
                Poll::Ready(Err(TransportError::Closed))
            ));
        }
        assert!(output.bytes.lock().unwrap().is_empty());
        assert!(output.dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn async_stdio_server_request_error_retains_next_line_but_client_error_is_terminal() {
        let wire = b"{bad\n{\"jsonrpc\":\"2.0\",\"method\":\"test/next\",\"id\":91}\n";
        let cx = Cx::for_testing();
        for server_ingress in [true, false] {
            let (mut reader, mut writer) =
                AsyncStdioTransport::from_io(wire.as_slice(), Vec::<u8>::new()).into_split();
            let error = if server_ingress {
                ready(reader.recv_server_with_source_async(&cx)).unwrap_err()
            } else {
                ready(reader.recv_with_source_async(&cx)).unwrap_err()
            };
            assert!(matches!(error, TransportError::Codec(CodecError::Json(_))));
            if server_ingress {
                ready(writer.send_async(
                    &cx,
                    &JsonRpcMessage::Response(JsonRpcResponse::error(
                        None,
                        fastmcp_protocol::JsonRpcError {
                            code: (-32700).into(),
                            message: "Parse error".to_owned(),
                            data: None,
                        },
                    )),
                ))
                .unwrap();
                assert!(
                    matches!(ready(reader.recv_server_with_source_async(&cx)).unwrap().message(), JsonRpcMessage::Request(request) if request.id == Some(91_i64.into()))
                );
            } else {
                assert!(reader.is_closed());
                assert!(matches!(
                    ready(writer.send_async(&cx, &request(92))),
                    Err(TransportError::Closed)
                ));
            }
        }
    }

    #[test]
    fn async_stdio_server_invalid_response_remains_terminal() {
        let wire = b"{\"jsonrpc\":\"2.0\",\"id\":91,\"result\":{},\"error\":{\"code\":-32603,\"message\":\"bad\"}}\n";
        let cx = Cx::for_testing();
        let (mut reader, mut writer) =
            AsyncStdioTransport::from_io(wire.as_slice(), Vec::<u8>::new()).into_split();
        assert!(matches!(
            ready(reader.recv_server_with_source_async(&cx)),
            Err(TransportError::Codec(CodecError::InvalidMessage {
                kind: crate::InvalidMessageKind::Response,
                ..
            }))
        ));
        assert!(reader.is_closed());
        assert!(matches!(
            ready(writer.send_async(&cx, &request(92))),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn async_stdio_dropped_send_before_commit_keeps_writer_reusable() {
        let output = Output::new(0);
        let mut transport = AsyncStdioTransport::from_io(&b""[..], TestWriter(Arc::clone(&output)));
        let cx = Cx::for_testing();
        let message = request(8);
        {
            let mut sending = pin!(transport.send_async(&cx, &message));
            assert!(poll(sending.as_mut(), Waker::noop()).is_pending());
        }
        assert!(!transport.is_closed());
        assert!(output.bytes.lock().unwrap().is_empty());
        output.allowance.store(usize::MAX, Ordering::SeqCst);
        ready(transport.send_async(&cx, &request(9))).unwrap();
        let bytes = output.bytes.lock().unwrap();
        assert_eq!(newline_count(&bytes), 1);
        assert!(std::str::from_utf8(&bytes).unwrap().contains("\"id\":9"));
    }

    #[test]
    fn async_stdio_partial_send_drop_closes_writer_and_wakes_silent_ingress() {
        let output = Output::new(5);
        let feed = Arc::new(Feed::default());
        let (mut reader, mut writer) =
            AsyncStdioTransport::from_io(FeedReader(feed), TestWriter(Arc::clone(&output)))
                .into_split();
        let cx = Cx::for_testing();
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut receiving = pin!(reader.recv_async(&cx));
        assert!(poll(receiving.as_mut(), &waker).is_pending());
        let message = request(10);
        {
            let mut sending = pin!(writer.send_async(&cx, &message));
            assert!(poll(sending.as_mut(), Waker::noop()).is_pending());
            assert_eq!(output.bytes.lock().unwrap().len(), 5);
        }
        assert!(writer.is_closed());
        assert!(output.dropped.load(Ordering::SeqCst));
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            poll(receiving.as_mut(), &waker),
            Poll::Ready(Err(TransportError::Closed))
        ));
        assert!(matches!(
            ready(writer.send_async(&cx, &request(11))),
            Err(TransportError::Closed)
        ));
        assert_eq!(output.bytes.lock().unwrap().len(), 5);
    }

    #[test]
    fn async_stdio_cancel_before_and_after_first_byte_has_distinct_commit_outcomes() {
        for allowance in [0, 5] {
            let output = Output::new(allowance);
            let mut transport =
                AsyncStdioTransport::from_io(&b""[..], TestWriter(Arc::clone(&output)));
            let cancelled = Cx::for_testing();
            let message = request(12);
            {
                let mut sending = pin!(transport.send_async(&cancelled, &message));
                assert!(poll(sending.as_mut(), Waker::noop()).is_pending());
                // Finish the cooperative yield and park on the same blocked
                // writer before changing only the caller cancellation state.
                assert!(poll(sending.as_mut(), Waker::noop()).is_pending());
                cancelled.set_cancel_requested(true);
                assert!(matches!(
                    poll(sending.as_mut(), Waker::noop()),
                    Poll::Ready(Err(TransportError::Cancelled))
                ));
            }
            assert_eq!(transport.is_closed(), allowance != 0);
            assert_eq!(output.dropped.load(Ordering::SeqCst), allowance != 0);
            assert_eq!(output.bytes.lock().unwrap().len(), allowance);
        }
    }

    #[test]
    fn async_stdio_unfinished_flush_drop_is_terminal_after_whole_frame_acceptance() {
        let output = Output::new(usize::MAX);
        output.flush_ready.store(false, Ordering::SeqCst);
        let mut transport = AsyncStdioTransport::from_io(&b""[..], TestWriter(Arc::clone(&output)));
        let cx = Cx::for_testing();
        let message = request(13);
        {
            let mut sending = pin!(transport.send_async(&cx, &message));
            assert!(poll(sending.as_mut(), Waker::noop()).is_pending());
        }
        assert!(transport.is_closed());
        assert!(output.dropped.load(Ordering::SeqCst));
        assert_eq!(output.bytes.lock().unwrap().last(), Some(&b'\n'));
    }

    #[test]
    fn async_stdio_successful_flush_wins_over_simultaneous_cancellation() {
        let cx = Cx::for_testing();
        let mut output = Output::new(usize::MAX);
        Arc::get_mut(&mut output).unwrap().cancel_on_flush = Some(cx.clone());
        let mut transport = AsyncStdioTransport::from_io(&b""[..], TestWriter(Arc::clone(&output)));
        ready(transport.send_async(&cx, &request(14))).unwrap();
        assert!(cx.is_cancel_requested());
        assert!(!transport.is_closed());
        assert_eq!(newline_count(&output.bytes.lock().unwrap()), 1);
    }

    #[test]
    fn async_stdio_masked_cancel_preserves_pending_read_then_unmask_refuses() {
        let feed = Arc::new(Feed::default());
        let mut transport =
            AsyncStdioTransport::from_io(FeedReader(Arc::clone(&feed)), Vec::<u8>::new());
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        {
            let mut receiving = pin!(transport.recv_async(&cx));
            cx.masked(|| assert!(poll(receiving.as_mut(), Waker::noop()).is_pending()));
            assert!(matches!(
                poll(receiving.as_mut(), Waker::noop()),
                Poll::Ready(Err(TransportError::Cancelled))
            ));
        }
        assert!(!transport.is_closed());
        feed.push(b"{\"jsonrpc\":\"2.0\",\"method\":\"test/mask\",\"id\":15}\n");
        ready(transport.recv_async(&Cx::for_testing())).unwrap();
    }

    #[test]
    fn async_stdio_cancelled_close_preserves_handles_then_live_close_wakes_reader() {
        let output = Output::new(usize::MAX);
        let feed = Arc::new(Feed::default());
        let (mut reader, mut writer) =
            AsyncStdioTransport::from_io(FeedReader(feed), TestWriter(Arc::clone(&output)))
                .into_split();
        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        assert!(matches!(
            ready(writer.close_async(&cancelled)),
            Err(TransportError::Cancelled)
        ));
        assert!(!writer.is_closed());
        assert!(!output.dropped.load(Ordering::SeqCst));
        let cx = Cx::for_testing();
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut receiving = pin!(reader.recv_async(&cx));
        assert!(poll(receiving.as_mut(), &waker).is_pending());
        ready(writer.close_async(&cx)).unwrap();
        assert!(output.dropped.load(Ordering::SeqCst));
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            poll(receiving.as_mut(), &waker),
            Poll::Ready(Err(TransportError::Closed))
        ));
    }

    #[test]
    fn async_stdio_native_tcp_split_serves_interleaved_messages_on_caller_runtime() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().expect("application runtime supplies Cx");
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut peer = cx.spawn(move |peer_cx| async move {
                let (socket, _) = listener.accept().await.unwrap();
                let (input, output) = socket.into_split();
                let (mut reader, mut writer) = AsyncStdioTransport::from_io(input, output).into_split();
                for id in [21, 22] {
                    assert!(matches!(reader.recv_async(&peer_cx).await.unwrap(), JsonRpcMessage::Request(request) if request.id == Some(RequestId::Number(id))));
                }
                for id in [22, 21] {
                    writer.send_async(&peer_cx, &JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), serde_json::json!({"echo":id})))).await.unwrap();
                }
                writer.close_async(&peer_cx).await.unwrap();
            }).unwrap();
            let socket = TcpStream::connect(address).await.unwrap();
            let (input, output) = socket.into_split();
            let (mut reader, mut writer) = AsyncStdioTransport::from_io(input, output).into_split();
            // The reader is parked independently before either outbound request.
            let mut receive = cx.spawn(move |read_cx| async move {
                let mut ids = Vec::new();
                for _ in 0..2 {
                    match reader.recv_async(&read_cx).await.unwrap() {
                        JsonRpcMessage::Response(response) => ids.push(response.id),
                        JsonRpcMessage::Request(_) => panic!("expected a peer response"),
                    }
                }
                ids
            }).unwrap();
            asupersync::runtime::yield_now().await;
            writer.send_async(&cx, &request(21)).await.unwrap();
            writer.send_async(&cx, &request(22)).await.unwrap();
            assert_eq!(receive.join(&cx).await.unwrap(), vec![Some(RequestId::Number(22)), Some(RequestId::Number(21))]);
            peer.join(&cx).await.unwrap();
        });
    }

    #[test]
    fn async_stdio_native_tcp_silent_receive_cancellation_preserves_sibling_egress() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut accepting = cx.spawn(move |_peer_cx| async move { listener.accept().await.unwrap().0 }).unwrap();
            let local = TcpStream::connect(address).await.unwrap();
            let remote = accepting.join(&cx).await.unwrap();
            let (remote_input, remote_output) = remote.into_split();
            let mut peer = AsyncStdioTransport::from_io(remote_input, remote_output);
            let (input, output) = local.into_split();
            let started = Arc::new(AtomicBool::new(false));
            let (mut reader, mut writer) = AsyncStdioTransport::from_io(
                ReadStarted { reader: input, started: Arc::clone(&started) }, output,
            ).into_split();
            let mut receiving = cx.spawn(move |read_cx| async move {
                let result = reader.recv_async(&read_cx).await;
                (reader, result)
            }).unwrap();
            for _ in 0..128 {
                if started.load(Ordering::SeqCst) { break; }
                asupersync::runtime::yield_now().await;
            }
            assert!(started.load(Ordering::SeqCst), "native read must actually be parked");
            assert!(!receiving.is_finished(), "silent peer supplies no frame");
            receiving.abort();
            let (mut reader, result) = receiving.join(&cx).await.unwrap();
            assert!(matches!(result, Err(TransportError::Cancelled)));
            assert!(!reader.is_closed());
            writer.send_async(&cx, &request(31)).await.unwrap();
            assert!(matches!(peer.recv_async(&cx).await.unwrap(), JsonRpcMessage::Request(request) if request.id == Some(RequestId::Number(31))));
            peer.send_async(&cx, &request(32)).await.unwrap();
            assert!(matches!(reader.recv_async(&cx).await.unwrap(), JsonRpcMessage::Request(request) if request.id == Some(RequestId::Number(32))));
            writer.close_async(&cx).await.unwrap();
        });
    }

    #[test]
    fn async_stdio_caller_deadline_wakes_silent_read_without_discarding_prefix() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let live = runtime.request_cx_with_budget(asupersync::Budget::new());
        let feed = Arc::new(Feed::default());
        let source = br#"{"jsonrpc":"2.0","method":"test/deadline","id":33}"#;
        feed.push(&source[..20]);
        let mut transport =
            AsyncStdioTransport::from_io(FeedReader(Arc::clone(&feed)), Vec::<u8>::new());
        runtime.block_on(async {
            let deadline = live.now().saturating_add_nanos(100_000_000);
            let limited =
                runtime.request_cx_with_budget(asupersync::Budget::new().with_deadline(deadline));
            assert!(matches!(
                transport.recv_async(&limited).await,
                Err(TransportError::Timeout)
            ));
            assert!(
                feed.polls.load(Ordering::SeqCst) > 0,
                "deadline must expire after ingress actually starts"
            );
            assert!(!transport.is_closed());
            feed.push(&[&source[20..], b"\n"].concat());
            assert_eq!(
                transport
                    .recv_with_source_async(&live)
                    .await
                    .unwrap()
                    .source(),
                source
            );
        });
    }

    /// Reports a cooperative stop for a bounded or unbounded number of polls.
    ///
    /// `remaining: None` never stops interrupting, which is the shape of a
    /// source whose own `Cx` is cancelled or past its deadline while the
    /// context serving the transport stays live (#84).
    struct Interrupting {
        remaining: Mutex<Option<u32>>,
        polls: AtomicUsize,
        rest: Mutex<VecDeque<u8>>,
    }

    struct InterruptingReader(Arc<Interrupting>);

    impl AsyncRead for InterruptingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _task: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.0.polls.fetch_add(1, Ordering::SeqCst);
            {
                let mut remaining = self.0.remaining.lock().unwrap();
                match remaining.as_mut() {
                    Some(0) => {}
                    Some(count) => {
                        *count -= 1;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "test source cooperative stop",
                        )));
                    }
                    None => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "test source cooperative stop",
                        )));
                    }
                }
            }
            let mut bytes = self.0.rest.lock().unwrap();
            while output.remaining() > 0 {
                let Some(byte) = bytes.pop_front() else {
                    break;
                };
                output.put_slice(&[byte]);
            }
            Poll::Ready(Ok(()))
        }
    }

    fn interrupting(
        remaining: Option<u32>,
        rest: &[u8],
    ) -> (
        Arc<Interrupting>,
        AsyncStdioTransport<InterruptingReader, Vec<u8>>,
    ) {
        let inner = Arc::new(Interrupting {
            remaining: Mutex::new(remaining),
            polls: AtomicUsize::new(0),
            rest: Mutex::new(rest.iter().copied().collect()),
        });
        let transport =
            AsyncStdioTransport::from_io(InterruptingReader(Arc::clone(&inner)), Vec::<u8>::new());
        (inner, transport)
    }

    /// Drives one receive to completion, failing instead of spinning forever.
    ///
    /// The ceiling is far above `INTERRUPTED_RETRY_LIMIT`, so a regression that
    /// restored the unbounded retry fails this assertion rather than hanging
    /// the whole test binary.
    fn drive_receive<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        transport: &mut AsyncStdioTransport<R, W>,
        cx: &Cx,
        waker: &Waker,
    ) -> Result<ReceivedTransportFrame, TransportError> {
        let mut receive = pin!(transport.recv_with_source_async(cx));
        for _ in 0..4096 {
            if let Poll::Ready(result) = poll(receive.as_mut(), waker) {
                return result;
            }
        }
        panic!("a bounded cooperative stop must settle, not spin");
    }

    #[test]
    fn async_stdio_retries_a_bounded_cooperative_stop_and_still_delivers_the_frame() {
        let source = br#"{"jsonrpc":"2.0","method":"test/async-stdio","id":7}"#;
        let wire = [&source[..], b"\n"].concat();
        // Exactly at the bound: the last retry is still allowed.
        let (inner, mut transport) = interrupting(Some(INTERRUPTED_RETRY_LIMIT), &wire);
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let frame = drive_receive(&mut transport, &Cx::for_testing(), &waker)
            .expect("a bounded cooperative stop is retried, not fatal");
        assert_eq!(frame.source(), source);
        assert_eq!(
            inner.polls.load(Ordering::SeqCst),
            usize::try_from(INTERRUPTED_RETRY_LIMIT).unwrap() + 1,
            "each interruption is retried once and the next poll delivers"
        );
        assert!(!transport.is_closed());
    }

    #[test]
    fn async_stdio_stops_an_endless_cooperative_stop_instead_of_spinning() {
        // Differs from the positive case in exactly one dimension: the source
        // never stops reporting its cooperative stop.
        let (inner, mut transport) = interrupting(None, b"");
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let error = drive_receive(&mut transport, &Cx::for_testing(), &waker)
            .expect_err("an endless cooperative stop is fatal");
        let TransportError::Io(error) = error else {
            panic!("expected a terminal I/O diagnostic, got {error:?}");
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(
            error.to_string().contains("bind the source to the same"),
            "the diagnostic must name the cause: {error}"
        );
        assert_eq!(
            inner.polls.load(Ordering::SeqCst),
            usize::try_from(INTERRUPTED_RETRY_LIMIT).unwrap() + 1,
            "the guard stops at its bound rather than retrying without end"
        );
        // Not `TransportError::Cancelled`: `await_io` checkpoints the serving
        // context on every poll, so reaching the I/O diagnostic proves that
        // context stayed live and only the source was stopping.
        assert!(
            transport.is_closed(),
            "the endpoint latches closed so a retry cannot re-enter the spin"
        );
    }

    fn effects(cx: &Cx) -> [bool; 5] {
        let capabilities = cx.capabilities();
        [
            capabilities.spawn,
            capabilities.time,
            capabilities.entropy,
            capabilities.io,
            capabilities.remote,
        ]
    }

    type Observations = Arc<Mutex<Vec<(&'static str, [bool; 5])>>>;

    struct ObserveIo<T> {
        inner: T,
        observations: Observations,
    }

    impl<T> ObserveIo<T> {
        fn record(&self, operation: &'static str) {
            let active = Cx::current().expect("I/O must run inside its explicit caller");
            self.observations
                .lock()
                .unwrap()
                .push((operation, effects(&active)));
        }
    }

    impl<R: AsyncRead + Unpin> AsyncRead for ObserveIo<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            task: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.record("read");
            Pin::new(&mut this.inner).poll_read(task, output)
        }
    }

    impl<W: AsyncWrite + Unpin> AsyncWrite for ObserveIo<W> {
        fn poll_write(
            self: Pin<&mut Self>,
            task: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.record("write");
            Pin::new(&mut this.inner).poll_write(task, bytes)
        }

        fn poll_flush(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.record("flush");
            Pin::new(&mut this.inner).poll_flush(task)
        }

        fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.record("shutdown");
            Pin::new(&mut this.inner).poll_shutdown(task)
        }
    }

    #[test]
    fn async_stdio_preserves_all_ambient_and_held_effect_restrictions() {
        let masks = [
            CapMask::all(),
            CapSet::<false, true, true, true, true>::MASK,
            CapSet::<true, false, true, true, true>::MASK,
            CapSet::<true, true, false, true, true>::MASK,
            CapSet::<true, true, true, false, true>::MASK,
            CapSet::<true, true, true, true, false>::MASK,
            CapMask::none(),
        ];
        for held_mask in [
            CapMask::all(),
            CapSet::<true, true, false, true, true>::MASK,
        ] {
            for mask in masks {
                let owner = Cx::for_testing();
                let held = {
                    let _owner = Cx::set_current(Some(owner.clone()));
                    let _restriction = Cx::push_restriction(held_mask);
                    Cx::current().unwrap()
                };
                let foreign = Cx::for_testing();
                let _foreign = Cx::set_current(Some(foreign.clone()));
                let _restriction = Cx::push_restriction(mask);
                let ambient_effects = effects(&Cx::current().unwrap());
                let held_effects = effects(&held);
                let expected = std::array::from_fn(|i| ambient_effects[i] && held_effects[i]);
                let observations: Observations = Arc::new(Mutex::new(Vec::new()));
                let source = br#"{"jsonrpc":"2.0","method":"test/authority","id":93}"#;
                let wire = [source.as_slice(), b"\n"].concat();
                let output = Output::new(usize::MAX);
                let mut transport = AsyncStdioTransport::from_io(
                    ObserveIo {
                        inner: wire.as_slice(),
                        observations: Arc::clone(&observations),
                    },
                    ObserveIo {
                        inner: TestWriter(Arc::clone(&output)),
                        observations: Arc::clone(&observations),
                    },
                );
                // These adapters only copy memory. Removing an effect must not
                // blanket-refuse pure I/O adapters instead of narrowing them.
                assert_eq!(
                    ready(transport.recv_with_source_async(&held))
                        .unwrap()
                        .source(),
                    source
                );
                ready(transport.send_async(&held, &request(94))).unwrap();
                ready(transport.close_async(&held)).unwrap();
                assert_eq!(
                    *observations.lock().unwrap(),
                    vec![
                        ("read", expected),
                        ("write", expected),
                        ("flush", expected),
                        ("shutdown", expected),
                    ]
                );
                assert_eq!(newline_count(&output.bytes.lock().unwrap()), 1);
                assert_eq!(effects(&Cx::current().unwrap()), ambient_effects);
                Cx::current().unwrap().set_cancel_requested(true);
                assert!(foreign.is_cancel_requested());
                assert!(!owner.is_cancel_requested());
            }
        }
    }

    #[test]
    fn async_stdio_rechecks_ambient_authority_after_a_pending_read() {
        for initially_allowed in [false, true] {
            let cx = Cx::for_testing();
            let _ambient = Cx::set_current(Some(Cx::for_testing()));
            let feed = Arc::new(Feed::default());
            let observations: Observations = Arc::new(Mutex::new(Vec::new()));
            let mut transport = AsyncStdioTransport::from_io(
                ObserveIo {
                    inner: FeedReader(Arc::clone(&feed)),
                    observations: Arc::clone(&observations),
                },
                Vec::<u8>::new(),
            );
            let source = br#"{"jsonrpc":"2.0","method":"test/authority","id":95}"#;
            let mut receiving = pin!(transport.recv_with_source_async(&cx));
            for (turn, allowed) in [initially_allowed, !initially_allowed]
                .into_iter()
                .enumerate()
            {
                let mask = if allowed {
                    CapMask::all()
                } else {
                    CapSet::<true, true, true, false, true>::MASK
                };
                {
                    let _restriction = Cx::push_restriction(mask);
                    if turn == 0 {
                        assert!(poll(receiving.as_mut(), Waker::noop()).is_pending());
                    } else {
                        let Poll::Ready(result) = poll(receiving.as_mut(), Waker::noop()) else {
                            panic!("the complete in-memory frame must be delivered");
                        };
                        assert_eq!(result.unwrap().source(), source);
                    }
                    assert_eq!(Cx::current().unwrap().capabilities().io, allowed);
                }
                assert_eq!(effects(&Cx::current().unwrap()), [true; 5]);
                if turn == 0 {
                    feed.push(&[source.as_slice(), b"\n"].concat());
                }
            }
            assert_eq!(
                *observations.lock().unwrap(),
                vec![
                    ("read", [true, true, true, initially_allowed, true]),
                    ("read", [true, true, true, !initially_allowed, true]),
                ]
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn async_stdio_native_send_refuses_ambient_io_denial_before_publishing_bytes() {
        for denied in [false, true] {
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                .blocking_threads(0, 0)
                .build()
                .unwrap();
            let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let (mut peer, writer) = crate::async_io::create_native_pipe(&cx).unwrap();
            let mut transport = AsyncStdioTransport::from_io(&b""[..], writer);
            let request = JsonRpcRequest::new("test/authority", None, 96_i64);
            let expected = Codec::new().encode_request(&request).unwrap();
            let message = JsonRpcMessage::Request(request);
            {
                let foreign = Cx::for_testing();
                // An unrelated ambient cancellation is not the operation's
                // cancellation domain, even when its effect ceiling applies.
                foreign.set_cancel_requested(true);
                let _foreign = Cx::set_current(Some(foreign));
                let mask = if denied {
                    CapSet::<true, true, true, false, true>::MASK
                } else {
                    CapMask::all()
                };
                let _restriction = Cx::push_restriction(mask);
                let result = ready(transport.send_async(&cx, &message));
                if denied {
                    assert!(matches!(
                        result,
                        Err(TransportError::Io(error))
                            if error.kind() == io::ErrorKind::PermissionDenied
                    ));
                    assert!(transport.is_closed());
                } else {
                    result.unwrap();
                }
                assert_eq!(Cx::current().unwrap().capabilities().io, !denied);
                assert!(Cx::current().unwrap().is_cancel_requested());
                assert!(!cx.is_cancel_requested());
            }
            ready(transport.close_async(&cx)).unwrap();
            let mut bytes = [0_u8; 256];
            let mut output = ReadBuf::new(&mut bytes);
            assert!(matches!(
                Pin::new(&mut peer).poll_read(&mut Context::from_waker(Waker::noop()), &mut output),
                Poll::Ready(Ok(()))
            ));
            if denied {
                assert!(
                    output.filled().is_empty(),
                    "denied send published pipe bytes"
                );
            } else {
                assert_eq!(output.filled(), expected.as_slice());
            }
            assert_eq!(cx.io_driver_handle().unwrap().waker_count(), 0);
            drop((transport, peer, cx));
            assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(1)));
        }
    }

    struct YieldBetweenReads<R> {
        inner: R,
        pending: bool,
        turns: Arc<AtomicUsize>,
    }

    impl<R: AsyncRead + Unpin> AsyncRead for YieldBetweenReads<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            task: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.turns.fetch_add(1, Ordering::SeqCst);
            if this.pending {
                this.pending = false;
                task.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.pending = true;
            Pin::new(&mut this.inner).poll_read(task, output)
        }
    }

    #[test]
    fn async_stdio_pending_between_interruptions_does_not_reset_the_retry_budget() {
        let source = br#"{"jsonrpc":"2.0","method":"test/async-stdio","id":97}"#;
        let wire = [source.as_slice(), b"\n"].concat();
        for bounded in [true, false] {
            let inner = Arc::new(Interrupting {
                remaining: Mutex::new(bounded.then_some(INTERRUPTED_RETRY_LIMIT)),
                polls: AtomicUsize::new(0),
                rest: Mutex::new(wire.iter().copied().collect()),
            });
            let turns = Arc::new(AtomicUsize::new(0));
            let mut transport = AsyncStdioTransport::from_io(
                YieldBetweenReads {
                    inner: InterruptingReader(Arc::clone(&inner)),
                    pending: true,
                    turns: Arc::clone(&turns),
                },
                Vec::<u8>::new(),
            );
            let result = drive_receive(&mut transport, &Cx::for_testing(), Waker::noop());
            if bounded {
                assert_eq!(result.unwrap().source(), source);
                assert!(!transport.is_closed());
                assert!(inner.rest.lock().unwrap().is_empty());
            } else {
                assert!(matches!(
                    result,
                    Err(TransportError::Io(error))
                        if error.kind() == io::ErrorKind::ConnectionAborted
                ));
                assert!(transport.is_closed());
                assert_eq!(
                    *inner.rest.lock().unwrap(),
                    wire.iter().copied().collect::<VecDeque<_>>()
                );
            }
            let attempts = usize::try_from(INTERRUPTED_RETRY_LIMIT).unwrap() + 1;
            assert_eq!(inner.polls.load(Ordering::SeqCst), attempts);
            assert_eq!(turns.load(Ordering::SeqCst), attempts * 2);
        }
    }
}
