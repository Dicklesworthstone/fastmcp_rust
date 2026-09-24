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
    poll_fn(|task| {
        if !closing && terminal.is_closed() {
            return Poll::Ready(Err(TransportError::Closed));
        }
        let _caller = Cx::set_current(Some(cx.clone()));
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
                // A transient OS interruption consumes no bytes. Retry in a
                // later turn, with another checkpoint, instead of losing a
                // retained prefix or spinning inside this executor poll.
                task.waker().wake_by_ref();
                Poll::Pending
            }
            result => result.map(|result| result.map_err(|error| native_io_error(cx, error))),
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
                        // A shared byte-stream decode failure has no trusted
                        // request owner. It cannot be skipped to serve a sibling.
                        fail_read(reader, state, terminal);
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
pub struct AsyncStdioRecvHalf<R> {
    reader: Option<R>,
    state: ReadState,
    codec: Codec,
    terminal: Arc<Terminal>,
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
pub struct AsyncStdioSendHalf<W> {
    writer: Option<W>,
    codec: Codec,
    terminal: Arc<Terminal>,
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
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
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
        assert_eq!(
            output
                .bytes
                .lock()
                .unwrap()
                .iter()
                .filter(|byte| **byte == b'\n')
                .count(),
            1
        );
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
}
