//! Standard I/O transport for MCP.
//!
//! This is the primary transport for MCP servers running as subprocess.
//! Uses newline-delimited JSON (NDJSON) framing.
//!
//! # Cancellation checks
//!
//! Transport methods receive an asupersync capability context and use its full
//! checkpoint contract around their I/O paths. Checkpoints observe cancellation,
//! masking, and budget exhaustion. Generic [`Transport::recv`] and writes retain
//! the blocking `Read`/`Write` contract; on Unix, child-pipe callers can use
//! [`StdioTransport::recv_until`] to poll readiness and bound silent or
//! partial-frame reads. EOF is reported as transport closure.
//!
//! # Async I/O Integration
//!
//! This module provides two transport implementations:
//!
//! - [`StdioTransport`]: Generic transport for any `Read`/`Write` types (for testing)
//! - [`AsyncStdioTransport`]: Production transport using async I/O wrappers
//!
//! An oversized NDJSON line is a terminal framing error. The bounded reader
//! does not drain an attacker-controlled remainder after reporting the error;
//! callers must close the transport rather than call `recv` again.
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_transport::{AsyncStdioTransport, Transport};
//! use asupersync::Cx;
//!
//! fn main() {
//!     let mut transport = AsyncStdioTransport::new();
//!     let cx = Cx::for_testing();
//!
//!     loop {
//!         match transport.recv(&cx) {
//!             Ok(msg) => handle_message(msg),
//!             Err(TransportError::Closed) => break,
//!             Err(TransportError::Cancelled) => break,
//!             Err(e) => eprintln!("Error: {}", e),
//!         }
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::time::Duration;
use std::time::Instant;

use asupersync::Cx;
use fastmcp_protocol::{CorrelationKey, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};
#[cfg(unix)]
use rustix::event::{PollFd, PollFlags, Timespec, poll};
#[cfg(unix)]
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

use crate::async_io::{AsyncLineReader, AsyncStdout, BoundedLineReadError};
use crate::{
    Codec, CodecError, SendPermit, Transport, TransportError, TransportRecvHalf, TransportSendHalf,
    TwoPhaseTransport,
};

#[cfg(unix)]
const STDIO_READINESS_POLL_SLICE: Duration = Duration::from_millis(10);
/// POSIX guarantees atomic pipe writes of at least 512 bytes.
#[cfg(unix)]
const STDIO_ATOMIC_CONTROL_FRAME_MAX: usize = 512;

fn stdio_checkpoint(cx: &Cx) -> Result<(), TransportError> {
    cx.checkpoint().map_err(|error| {
        use asupersync::{CancelKind, error::ErrorKind};

        match cx.cancel_reason().map(|reason| reason.kind) {
            Some(CancelKind::Deadline | CancelKind::Timeout) => TransportError::Timeout,
            Some(_) => TransportError::Cancelled,
            None => match error.kind() {
                ErrorKind::DeadlineExceeded | ErrorKind::CancelTimeout => TransportError::Timeout,
                ErrorKind::Cancelled
                | ErrorKind::PollQuotaExhausted
                | ErrorKind::CostQuotaExhausted => TransportError::Cancelled,
                _ => TransportError::Cancelled,
            },
        }
    })
}

/// Stdio transport implementation.
///
/// Reads from stdin and writes to stdout using NDJSON framing.
/// Receives an asupersync context for cancellation and budget checks.
///
/// # Wire Format
///
/// Messages are newline-delimited JSON:
/// - Each message is serialized as a single line of JSON
/// - Lines are terminated by `\n`; CRLF input is also accepted
/// - Empty lines are ignored
/// - UTF-8 encoding is required
pub struct StdioTransport<R, W> {
    reader: BufReader<R>,
    writer: Option<W>,
    codec: Codec,
    line_buffer: Vec<u8>,
    closed: bool,
}

impl<R: Read, W: Write> StdioTransport<R, W> {
    /// Creates a new stdio transport with custom reader/writer.
    ///
    /// This is useful for testing with mock I/O.
    #[must_use]
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer: Some(writer),
            codec: Codec::new(),
            line_buffer: Vec::with_capacity(4096),
            closed: false,
        }
    }

    /// Separates NDJSON ingress from independently owned stdout egress.
    ///
    /// The receive half retains the exact bounded reader and codec state of
    /// this transport. Its private sink is never used for application output;
    /// the returned send half exclusively owns the supplied writer, allowing a
    /// request-owned child to commit a response while the owner remains in a
    /// blocking receive operation.
    #[must_use]
    pub fn into_split(self) -> (StdioRecvHalf<R>, StdioSendHalf<W>) {
        let Self {
            reader,
            writer,
            codec,
            line_buffer,
            closed,
        } = self;
        let mut send_codec = Codec::new();
        send_codec.set_max_message_size(codec.max_message_size());
        let terminal = Arc::new(AtomicBool::new(closed));

        (
            StdioRecvHalf {
                transport: StdioTransport {
                    reader,
                    writer: Some(std::io::sink()),
                    codec,
                    line_buffer,
                    closed,
                },
                terminal: Arc::clone(&terminal),
            },
            StdioSendHalf {
                writer,
                codec: send_codec,
                closed,
                terminal,
            },
        )
    }

    /// Returns whether this transport has entered a terminal state.
    ///
    /// In particular, a receive timeout leaves the transport open when no
    /// frame bytes were consumed, but latches it closed when a partial frame
    /// was consumed. Strict [`Self::recv_until`] also closes after consuming a
    /// complete late frame; [`Self::recv_until_with_completion`] instead gives
    /// that aligned frame to a request-policy owner while keeping the transport
    /// open.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Receives one blocking frame and reports its decode-completion instant.
    ///
    /// This preserves the timestamp taken immediately after successful decode
    /// and before the final context checkpoint. Callers that can only observe
    /// deadlines at complete-frame boundaries can therefore avoid charging
    /// later checkpoint or scheduling delay to the peer.
    ///
    /// # Errors
    ///
    /// Returns the same closure, cancellation, I/O, and codec errors as
    /// [`Transport::recv`].
    pub fn recv_with_completion(
        &mut self,
        cx: &Cx,
    ) -> Result<(JsonRpcMessage, Instant), TransportError> {
        self.recv_with_readiness(cx, |_, _| Ok(()))
    }

    /// Receives one complete NDJSON frame and dispatches it by JSON-RPC
    /// direction without emitting a reverse frame.
    ///
    /// The caller retains the request and response handlers across calls, so
    /// it can correlate interleaved responses while independently handling
    /// inbound requests or notifications. Exactly one handler runs for an
    /// admitted frame. A framing or codec error runs neither handler and this
    /// transport never fabricates a parse or invalid-request response.
    ///
    /// # Errors
    ///
    /// Returns the same cancellation, closure, I/O, and codec errors as
    /// [`Self::recv_with_completion`].
    pub fn dispatch_next<RequestHandler, ResponseHandler>(
        &mut self,
        cx: &Cx,
        on_request: &mut RequestHandler,
        on_response: &mut ResponseHandler,
    ) -> Result<(), TransportError>
    where
        RequestHandler: FnMut(JsonRpcRequest),
        ResponseHandler: FnMut(JsonRpcResponse),
    {
        match self.recv_with_completion(cx)?.0 {
            JsonRpcMessage::Request(request) => on_request(request),
            JsonRpcMessage::Response(response) => on_response(response),
        }
        Ok(())
    }

    /// Receives one complete frame and routes a response to its exact waiter.
    ///
    /// The waiter map uses the protocol's canonical correlation key, so
    /// mathematically equivalent integer spellings resolve to the same owner
    /// while string IDs remain distinct. A response consumes only its own
    /// waiter; an unknown or missing ID is delivered solely to
    /// `on_uncorrelated_response` and cannot wake, cancel, or otherwise alter
    /// an unrelated request. Requests and identifier-free notifications remain
    /// on the inbound direction and retain wire order with respect to every
    /// other inbound request.
    ///
    /// The method writes nothing. In particular, malformed framing and codec
    /// failures run no handler and never synthesize a reverse JSON-RPC error.
    /// A caller cancellation observed by [`Self::recv_with_completion`] also
    /// leaves the waiter registry untouched.
    ///
    /// # Errors
    ///
    /// Returns the framing, codec, closure, I/O, or cancellation error from
    /// [`Self::recv_with_completion`].
    pub fn dispatch_next_multiplexed<RequestHandler, Waiter, ResponseHandler, UnmatchedHandler>(
        &mut self,
        cx: &Cx,
        waiters: &mut HashMap<CorrelationKey, Waiter>,
        on_request: &mut RequestHandler,
        on_response: &mut ResponseHandler,
        on_uncorrelated_response: &mut UnmatchedHandler,
    ) -> Result<(), TransportError>
    where
        RequestHandler: FnMut(JsonRpcRequest),
        ResponseHandler: FnMut(Waiter, JsonRpcResponse),
        UnmatchedHandler: FnMut(JsonRpcResponse),
    {
        match self.recv_with_completion(cx)?.0 {
            JsonRpcMessage::Request(request) => on_request(request),
            JsonRpcMessage::Response(response) => {
                let waiter = response
                    .id
                    .as_ref()
                    .and_then(|id| id.correlation_key().ok())
                    .and_then(|key| waiters.remove(&key));
                if let Some(waiter) = waiter {
                    on_response(waiter, response);
                } else {
                    on_uncorrelated_response(response);
                }
            }
        }
        Ok(())
    }

    /// Encodes and sends a message, appending newline.
    fn write_message(&mut self, message: &JsonRpcMessage) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        let bytes = match message {
            JsonRpcMessage::Request(req) => self.codec.encode_request(req)?,
            JsonRpcMessage::Response(resp) => self.codec.encode_response(resp)?,
        };
        self.write_encoded(&bytes)
    }

    fn write_encoded(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        let writer = self.writer.as_mut().ok_or(TransportError::Closed)?;
        if let Err(error) = writer.write_all(bytes) {
            self.closed = true;
            return Err(TransportError::Io(error));
        }
        if let Err(error) = writer.flush() {
            self.closed = true;
            return Err(TransportError::Io(error));
        }
        Ok(())
    }

    fn frame_len(&self) -> usize {
        let without_lf = self
            .line_buffer
            .strip_suffix(b"\n")
            .unwrap_or(&self.line_buffer);
        without_lf.strip_suffix(b"\r").unwrap_or(without_lf).len()
    }

    fn abort_pending_read(&mut self, error: TransportError) -> TransportError {
        // Returning after any part of a frame has left BufReader would discard
        // the only copy of that prefix. Reusing the stream could then treat the
        // remaining suffix as a new JSON-RPC frame.
        if !self.line_buffer.is_empty() {
            self.closed = true;
        }
        self.line_buffer.clear();
        error
    }

    fn latch_consumed_read_failure(&mut self, error: TransportError) -> TransportError {
        // A complete frame (including an ignored empty line) has already been
        // removed from the stream. If its completion checkpoint fails, callers
        // must not retry and silently skip that frame.
        self.closed = true;
        self.line_buffer.clear();
        error
    }

    /// Reads a line into the reusable byte buffer without allocating beyond
    /// the codec's configured frame limit (plus a possible CRLF delimiter).
    fn read_line_with_readiness<F>(
        &mut self,
        cx: &Cx,
        wait_for_readiness: &mut F,
    ) -> Result<usize, TransportError>
    where
        F: FnMut(&BufReader<R>, &Cx) -> Result<(), TransportError>,
    {
        self.line_buffer.clear();
        let max_frame_size = self.codec.max_message_size();
        let wire_limit = max_frame_size.saturating_add(2);

        loop {
            if let Err(error) = stdio_checkpoint(cx) {
                return Err(self.abort_pending_read(error));
            }

            if let Err(error) = wait_for_readiness(&self.reader, cx) {
                return Err(self.abort_pending_read(error));
            }

            let available = match self.reader.fill_buf() {
                Ok(available) => available,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    if let Err(error) = stdio_checkpoint(cx) {
                        return Err(self.abort_pending_read(error));
                    }
                    continue;
                }
                Err(error) => {
                    self.closed = true;
                    self.line_buffer.clear();
                    return Err(TransportError::Io(error));
                }
            };
            if available.is_empty() {
                if self.line_buffer.is_empty() {
                    self.closed = true;
                    return Err(TransportError::Closed);
                }
                let frame_len = self.frame_len();
                if frame_len > max_frame_size {
                    self.closed = true;
                    self.line_buffer.clear();
                    return Err(TransportError::Codec(CodecError::MessageTooLarge(
                        frame_len,
                    )));
                }
                return Ok(frame_len);
            }

            let newline = available.iter().position(|byte| *byte == b'\n');
            let bytes_to_consume = newline.map_or(available.len(), |position| position + 1);
            let projected = self.line_buffer.len().saturating_add(bytes_to_consume);
            if projected > wire_limit {
                self.closed = true;
                self.line_buffer.clear();
                return Err(TransportError::Codec(CodecError::MessageTooLarge(
                    projected,
                )));
            }

            self.line_buffer
                .extend_from_slice(&available[..bytes_to_consume]);
            self.reader.consume(bytes_to_consume);

            if newline.is_some() {
                let frame_len = self.frame_len();
                if frame_len > max_frame_size {
                    self.closed = true;
                    self.line_buffer.clear();
                    return Err(TransportError::Codec(CodecError::MessageTooLarge(
                        frame_len,
                    )));
                }
                return Ok(frame_len);
            }
        }
    }

    fn recv_with_readiness<F>(
        &mut self,
        cx: &Cx,
        mut wait_for_readiness: F,
    ) -> Result<(JsonRpcMessage, Instant), TransportError>
    where
        F: FnMut(&BufReader<R>, &Cx) -> Result<(), TransportError>,
    {
        if self.closed {
            return Err(TransportError::Closed);
        }

        loop {
            let frame_len = match self.read_line_with_readiness(cx, &mut wait_for_readiness) {
                Ok(frame_len) => frame_len,
                Err(
                    error @ (TransportError::Closed
                    | TransportError::Codec(CodecError::MessageTooLarge(_))),
                ) => {
                    self.closed = true;
                    return Err(error);
                }
                Err(error) => return Err(error),
            };
            if let Err(error) = stdio_checkpoint(cx) {
                return Err(self.latch_consumed_read_failure(error));
            }

            if frame_len == 0 {
                continue;
            }

            let message = self
                .codec
                .decode_complete_message(&self.line_buffer[..frame_len])?;
            let completed_at = Instant::now();
            if let Err(error) = stdio_checkpoint(cx) {
                return Err(self.latch_consumed_read_failure(error));
            }
            return Ok((message, completed_at));
        }
    }
}

#[cfg(unix)]
fn wait_for_unix_readiness<R: AsFd, F: FnMut() -> bool>(
    reader: &BufReader<R>,
    cx: &Cx,
    deadline: Option<Instant>,
    should_stop: &mut F,
) -> Result<(), TransportError> {
    loop {
        if should_stop() {
            return Err(TransportError::Cancelled);
        }
        let remaining = match deadline {
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(TransportError::ReceiveDeadlineExceeded);
                }
                Some(deadline.duration_since(now))
            }
            None => None,
        };

        // BufReader may already hold a complete frame or a prefix read
        // alongside an earlier frame. Calling poll in that case could wait
        // despite bytes already being available in userspace. The caller runs
        // a checkpoint before invoking this helper, and the deadline check
        // above must still precede consumption of buffered bytes.
        if !reader.buffer().is_empty() {
            return Ok(());
        }

        let wait = remaining.map_or(STDIO_READINESS_POLL_SLICE, |remaining| {
            remaining.min(STDIO_READINESS_POLL_SLICE)
        });
        let timeout = Timespec::try_from(wait).map_err(|_| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "stdio readiness interval exceeds the platform clock range",
            ))
        })?;
        let mut descriptors = [PollFd::new(reader.get_ref(), PollFlags::IN)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => {
                if should_stop() {
                    return Err(TransportError::Cancelled);
                }
                stdio_checkpoint(cx)?;
            }
            Ok(_) => {
                if should_stop() {
                    return Err(TransportError::Cancelled);
                }
                return Ok(());
            }
            Err(rustix::io::Errno::INTR) => {
                if should_stop() {
                    return Err(TransportError::Cancelled);
                }
                stdio_checkpoint(cx)?;
            }
            Err(error) => return Err(TransportError::Io(error.into())),
        }
    }
}

#[cfg(unix)]
impl<R: Read + AsFd, W: Write> StdioTransport<R, W> {
    /// Receives one frame and reports when its complete decode finished.
    ///
    /// Unlike [`Self::recv_until`], this preserves a complete, framing-aligned
    /// message when decoding finishes after `deadline`. For ordinary Unix
    /// pipes (including `ChildStdout`), readiness checks before empty-buffer
    /// fills keep silence and partial frames observable at the deadline.
    /// Arbitrary `Read + AsFd` implementations are not preempted if their own
    /// `read` blocks after readiness. Callers that own request-level timeout
    /// policy can validate and route a consumed message before selecting their
    /// local timeout outcome.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ReceiveDeadlineExceeded`] when the explicit
    /// deadline expires before a complete frame is available. A partial-frame
    /// deadline latches the transport closed, while a silent deadline leaves
    /// it reusable. Context cancellation and all I/O, closure, and codec errors
    /// follow [`Transport::recv`].
    pub fn recv_until_with_completion(
        &mut self,
        cx: &Cx,
        deadline: Option<Instant>,
    ) -> Result<(JsonRpcMessage, Instant), TransportError> {
        let mut never_stop = || false;
        self.recv_with_readiness(cx, |reader, cx| {
            wait_for_unix_readiness(reader, cx, deadline, &mut never_stop)
        })
    }

    /// Receives one frame with deadline checks around ordinary Unix pipe reads.
    ///
    /// Readiness is polled in short slices before each empty-`BufReader` fill,
    /// so cancellation, context budgets, and `deadline` remain observable even
    /// when a peer is silent or stops midway through an NDJSON frame. A final
    /// checkpoint and deadline check run after complete frame decoding. Failure
    /// there is terminal because the frame has already been consumed. This
    /// Unix-specific API is used for child-process pipes. It does not preempt
    /// an arbitrary `Read + AsFd` implementation that blocks after reporting
    /// readiness; generic [`Transport::recv`] retains its ordinary blocking
    /// `Read` contract.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ReceiveDeadlineExceeded`] at the explicit
    /// deadline, [`TransportError::Timeout`] at a context deadline,
    /// [`TransportError::Cancelled`] for explicit cancellation or quota
    /// exhaustion, or the same I/O, closure, and codec errors as
    /// [`Transport::recv`].
    pub fn recv_until(
        &mut self,
        cx: &Cx,
        deadline: Option<Instant>,
    ) -> Result<JsonRpcMessage, TransportError> {
        let (message, completed_at) = self.recv_until_with_completion(cx, deadline)?;

        if deadline.is_some_and(|deadline| completed_at >= deadline) {
            return Err(self.latch_consumed_read_failure(TransportError::ReceiveDeadlineExceeded));
        }
        Ok(message)
    }

    /// Receives one frame while also observing an internal, non-maskable stop
    /// predicate between readiness polls.
    ///
    /// The predicate is for terminal transport-owner failure/wakeup state, not
    /// caller cancellation. Caller cancellation, budgets, and masking continue
    /// to use the supplied [`Cx`]. Any true stop outcome latches the connection
    /// closed; when it races a consumed prefix, complete frame, EOF, or receive
    /// failure, that terminal owner stop wins.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Cancelled`] when `should_stop` becomes true,
    /// or the same deadline, cancellation, I/O, closure, and codec errors as
    /// [`Self::recv_until`].
    pub fn recv_until_or_stopped<F>(
        &mut self,
        cx: &Cx,
        deadline: Option<Instant>,
        mut should_stop: F,
    ) -> Result<JsonRpcMessage, TransportError>
    where
        F: FnMut() -> bool,
    {
        let result = self.recv_with_readiness(cx, |reader, cx| {
            wait_for_unix_readiness(reader, cx, deadline, &mut should_stop)
        });
        let (message, completed_at) = match result {
            Ok(completed) => completed,
            Err(error) => {
                // A transport-owner failure can race EOF or another read
                // error after the readiness helper's last predicate check.
                // Recheck before exposing that error so callers cannot
                // accidentally classify a connection-fatal owner failure as
                // clean closure.
                if should_stop() {
                    return Err(self.latch_consumed_read_failure(TransportError::Cancelled));
                }
                return Err(error);
            }
        };

        if should_stop() {
            return Err(self.latch_consumed_read_failure(TransportError::Cancelled));
        }
        if deadline.is_some_and(|deadline| completed_at >= deadline) {
            return Err(self.latch_consumed_read_failure(TransportError::ReceiveDeadlineExceeded));
        }
        Ok(message)
    }
}

impl StdioTransport<std::io::Stdin, std::io::Stdout> {
    /// Creates a transport using standard stdin/stdout.
    ///
    /// This is the primary constructor for MCP servers running as subprocess.
    #[must_use]
    pub fn stdio() -> Self {
        Self::new(std::io::stdin(), std::io::stdout())
    }
}

impl<R: Read> StdioTransport<R, std::process::ChildStdin> {
    /// Closes the child stdin and reaps the exact child within a bounded grace
    /// period, escalating once when voluntary exit does not occur.
    ///
    /// The caller context is checked before stdin close, so cancellation before
    /// that write-side commit leaves both the transport and child untouched.
    /// Once stdin has been closed, cleanup deliberately no longer observes the
    /// request context: the connection owns reaping and must not leave a child
    /// running because its original request was cancelled. This transport does
    /// not select, probe, or change a protocol era from child output.
    ///
    /// The returned flag is `true` exactly when forced termination was needed.
    ///
    /// # Errors
    ///
    /// Returns cancellation before close, I/O failure, or a close failure after
    /// the child has still been reaped.
    pub fn close_and_reap_child(
        &mut self,
        cx: &Cx,
        child: &mut std::process::Child,
        grace: std::time::Duration,
    ) -> Result<(std::process::ExitStatus, bool), TransportError> {
        stdio_checkpoint(cx)?;
        let close_error = Transport::close(self).err();
        let deadline = Instant::now()
            .checked_add(grace)
            .unwrap_or_else(Instant::now);
        let mut forced = false;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(TransportError::Io)? {
                break status;
            }
            let now = Instant::now();
            if now >= deadline {
                forced = true;
                child.kill().map_err(TransportError::Io)?;
                break child.wait().map_err(TransportError::Io)?;
            }
            std::thread::sleep((deadline - now).min(std::time::Duration::from_millis(10)));
        };
        if let Some(error) = close_error {
            Err(error)
        } else {
            Ok((status, forced))
        }
    }
}

#[cfg(unix)]
impl<R, W: AsFd> StdioTransport<R, W> {
    fn try_write_atomic_control(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        if bytes.len() > STDIO_ATOMIC_CONTROL_FRAME_MAX {
            return Err(TransportError::ControlFrameTooLarge {
                size: bytes.len(),
                max: STDIO_ATOMIC_CONTROL_FRAME_MAX,
            });
        }

        let writer = self.writer.as_mut().ok_or(TransportError::Closed)?;
        let original_flags = match fcntl_getfl(&*writer) {
            Ok(flags) => flags,
            Err(error) => {
                self.closed = true;
                return Err(TransportError::Io(error.into()));
            }
        };
        if let Err(error) = fcntl_setfl(&*writer, original_flags | OFlags::NONBLOCK) {
            self.closed = true;
            return Err(TransportError::Io(error.into()));
        }

        // Use the descriptor directly so a custom `Write` implementation
        // cannot buffer the frame or block before reaching the pipe.
        let write_result = rustix::io::write(&*writer, bytes);
        let restore_result = fcntl_setfl(&*writer, original_flags);
        let result = match (write_result, restore_result) {
            (Ok(written), Ok(())) if written == bytes.len() => Ok(()),
            (Ok(_), Ok(())) => Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "stdio control frame was not written atomically",
            ))),
            (Err(error), _) => Err(TransportError::Io(error.into())),
            (Ok(_), Err(error)) => Err(TransportError::Io(error.into())),
        };
        if result.is_err() {
            self.closed = true;
        }
        result
    }
}

#[cfg(unix)]
impl<R> StdioTransport<R, std::process::ChildStdin> {
    /// Attempts one small connection-control write without blocking.
    ///
    /// This capability is intentionally available only for the owned,
    /// unbuffered child-stdin pipe used by the direct MCP client. The encoded
    /// frame must fit the POSIX minimum atomic pipe-write bound. The descriptor
    /// is switched to nonblocking mode for exactly one write syscall and then
    /// restored. A short write, full pipe, flag-restoration failure, or any
    /// other I/O error latches the transport closed so a caller cannot continue
    /// after an ambiguous control disposition.
    ///
    /// The caller must retain exclusive ownership of the child pipe and must
    /// not duplicate its descriptor. This operation deliberately performs no
    /// request-context checkpoint and no potentially blocking flush.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ControlFrameTooLarge`] when a valid encoded
    /// message exceeds the atomic control-frame bound, a codec error when the
    /// message itself cannot be encoded, or an I/O/closed error when the frame
    /// cannot be committed immediately and completely.
    pub fn try_send_control_message(
        &mut self,
        message: &JsonRpcMessage,
    ) -> Result<(), TransportError> {
        let bytes = match message {
            JsonRpcMessage::Request(request) => self.codec.encode_request(request)?,
            JsonRpcMessage::Response(response) => self.codec.encode_response(response)?,
        };
        self.try_write_atomic_control(&bytes)
    }
}

impl<R: Read, W: Write> Transport for StdioTransport<R, W> {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        // The checkpoint is the cancellation point; the blocking commit that
        // follows is intentionally not claimed to be interruptible.
        stdio_checkpoint(cx)?;

        self.write_message(message)
    }

    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        self.recv_with_completion(cx).map(|(message, _)| message)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        if self.closed {
            drop(self.writer.take());
            return Ok(());
        }
        self.closed = true;
        let Some(mut writer) = self.writer.take() else {
            return Ok(());
        };

        // Taking the writer makes closure terminal even if flushing fails. In
        // the subprocess client this drops ChildStdin before process cleanup,
        // allowing a cooperative server to observe EOF and exit normally.
        let flush_result = writer.flush();
        drop(writer);
        flush_result.map_err(TransportError::Io)
    }
}

/// Independently owned bounded NDJSON receive half for stdio transport.
pub struct StdioRecvHalf<R> {
    // Reuse the complete reader implementation with an inert private sink so
    // the framing limits, partial-frame terminal behavior, and checkpoints
    // remain identical to `StdioTransport::recv`.
    transport: StdioTransport<R, std::io::Sink>,
    terminal: Arc<AtomicBool>,
}

impl<R> StdioRecvHalf<R> {
    /// Returns whether either split half has entered a terminal state.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.terminal.load(Ordering::Acquire)
    }
}

impl<R: Read> TransportRecvHalf for StdioRecvHalf<R> {
    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        if self.is_closed() {
            return Err(TransportError::Closed);
        }

        let result = self.transport.recv(cx);
        if self.transport.is_closed() {
            self.terminal.store(true, Ordering::Release);
        }
        if self.is_closed() && result.is_ok() {
            return Err(TransportError::Closed);
        }
        result
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.terminal.store(true, Ordering::Release);
        self.transport.close()
    }
}

/// Independently owned NDJSON send half for stdio transport.
pub struct StdioSendHalf<W> {
    writer: Option<W>,
    codec: Codec,
    closed: bool,
    terminal: Arc<AtomicBool>,
}

impl<W: Write> StdioSendHalf<W> {
    fn mark_closed(&mut self) {
        self.closed = true;
        self.terminal.store(true, Ordering::Release);
    }

    /// Returns whether either split half has entered a terminal state.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed || self.terminal.load(Ordering::Acquire)
    }

    /// Reserves this split sender for one cancellation-preflighted frame.
    pub fn reserve_send(&mut self, cx: &Cx) -> Result<StdioSendPermit<'_, W>, TransportError> {
        if self.is_closed() || self.writer.is_none() {
            return Err(TransportError::Closed);
        }
        stdio_checkpoint(cx)?;
        Ok(StdioSendPermit { send_half: self })
    }

    fn write_encoded(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        let result = {
            let writer = self.writer.as_mut().ok_or(TransportError::Closed)?;
            writer.write_all(bytes).and_then(|()| writer.flush())
        };
        if let Err(error) = result {
            self.mark_closed();
            return Err(TransportError::Io(error));
        }
        Ok(())
    }
}

/// A committed split-send reservation that performs no additional checkpoint.
pub struct StdioSendPermit<'a, W> {
    send_half: &'a mut StdioSendHalf<W>,
}

impl<W: Write> StdioSendPermit<'_, W> {
    /// Commits one JSON-RPC message after the reservation preflight.
    pub fn send(self, message: &JsonRpcMessage) -> Result<(), TransportError> {
        if self.send_half.is_closed() {
            return Err(TransportError::Closed);
        }
        let bytes = match message {
            JsonRpcMessage::Request(request) => self.send_half.codec.encode_request(request)?,
            JsonRpcMessage::Response(response) => self.send_half.codec.encode_response(response)?,
        };
        self.send_half.write_encoded(&bytes)
    }

    /// Commits one request after the reservation preflight.
    pub fn send_request(self, request: &JsonRpcRequest) -> Result<(), TransportError> {
        if self.send_half.is_closed() {
            return Err(TransportError::Closed);
        }
        let bytes = self.send_half.codec.encode_request(request)?;
        self.send_half.write_encoded(&bytes)
    }

    /// Commits one response after the reservation preflight.
    pub fn send_response(self, response: &JsonRpcResponse) -> Result<(), TransportError> {
        if self.send_half.is_closed() {
            return Err(TransportError::Closed);
        }
        let bytes = self.send_half.codec.encode_response(response)?;
        self.send_half.write_encoded(&bytes)
    }
}

#[cfg(unix)]
impl<W: Write + AsFd> StdioSendHalf<W> {
    fn try_write_atomic_control(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if self.is_closed() {
            return Err(TransportError::Closed);
        }
        if bytes.len() > STDIO_ATOMIC_CONTROL_FRAME_MAX {
            return Err(TransportError::ControlFrameTooLarge {
                size: bytes.len(),
                max: STDIO_ATOMIC_CONTROL_FRAME_MAX,
            });
        }

        let result = (|| {
            let writer = self.writer.as_mut().ok_or(TransportError::Closed)?;
            let original_flags =
                fcntl_getfl(&*writer).map_err(|error| TransportError::Io(error.into()))?;
            fcntl_setfl(&*writer, original_flags | OFlags::NONBLOCK)
                .map_err(|error| TransportError::Io(error.into()))?;

            let write_result = rustix::io::write(&*writer, bytes);
            let restore_result = fcntl_setfl(&*writer, original_flags);
            match (write_result, restore_result) {
                (Ok(written), Ok(())) if written == bytes.len() => Ok(()),
                (Ok(_), Ok(())) => Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "stdio control frame was not written atomically",
                ))),
                (Err(error), _) => Err(TransportError::Io(error.into())),
                (Ok(_), Err(error)) => Err(TransportError::Io(error.into())),
            }
        })();
        if result.is_err() {
            self.mark_closed();
        }
        result
    }
}

#[cfg(unix)]
impl StdioSendHalf<std::process::ChildStdin> {
    /// Attempts one bounded, atomic control write without a request checkpoint.
    pub fn try_send_control_message(
        &mut self,
        message: &JsonRpcMessage,
    ) -> Result<(), TransportError> {
        let bytes = match message {
            JsonRpcMessage::Request(request) => self.codec.encode_request(request)?,
            JsonRpcMessage::Response(response) => self.codec.encode_response(response)?,
        };
        self.try_write_atomic_control(&bytes)
    }
}

impl<W: Write + Send> TransportSendHalf for StdioSendHalf<W> {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        self.reserve_send(cx)?.send(message)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        if self.is_closed() {
            self.mark_closed();
            drop(self.writer.take());
            return Ok(());
        }
        self.mark_closed();
        let Some(mut writer) = self.writer.take() else {
            return Ok(());
        };

        let flush_result = writer.flush();
        drop(writer);
        flush_result.map_err(TransportError::Io)
    }
}

/// Helper to create request/response without cloning for internal use.
impl<R: Read, W: Write> StdioTransport<R, W> {
    /// Send a request directly (avoids clone in trait method).
    pub fn send_request_direct(
        &mut self,
        cx: &Cx,
        request: &JsonRpcRequest,
    ) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        stdio_checkpoint(cx)?;
        let bytes = self.codec.encode_request(request)?;
        self.write_encoded(&bytes)
    }

    /// Send a response directly (avoids clone in trait method).
    pub fn send_response_direct(
        &mut self,
        cx: &Cx,
        response: &JsonRpcResponse,
    ) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        stdio_checkpoint(cx)?;
        let bytes = self.codec.encode_response(response)?;
        self.write_encoded(&bytes)
    }
}

impl<R: Read, W: Write> TwoPhaseTransport for StdioTransport<R, W> {
    type Writer = W;

    fn reserve_send(&mut self, cx: &Cx) -> Result<SendPermit<'_, Self::Writer>, TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        // This checkpoint is the cancellation point. The permit's commit phase
        // performs no further checkpoint.
        stdio_checkpoint(cx)?;

        // Return permit that allows the send to proceed
        let writer = self.writer.as_mut().ok_or(TransportError::Closed)?;
        Ok(SendPermit::new(writer, &self.codec, &mut self.closed))
    }
}

// =============================================================================
// AsyncStdioTransport - Production async I/O transport
// =============================================================================

/// Async stdio transport with explicit context checkpoints.
///
/// This is the production transport for MCP servers. It uses async I/O
/// wrappers and receives an asupersync capability context.
///
/// # Cancellation behavior
///
/// - Runs the full context checkpoint before I/O and after a consumed frame
/// - Maps context deadline exhaustion to `TransportError::Timeout`
/// - Returns `TransportError::Cancelled` for other cancellation or quota exhaustion
///
/// # Example
///
/// ```ignore
/// use fastmcp_transport::{AsyncStdioTransport, Transport};
/// use asupersync::Cx;
///
/// let mut transport = AsyncStdioTransport::new();
/// let cx = Cx::for_testing();
///
/// // Receive messages until EOF or cancellation
/// loop {
///     match transport.recv(&cx) {
///         Ok(msg) => process_message(msg),
///         Err(TransportError::Closed) => break,
///         Err(TransportError::Cancelled) => {
///             eprintln!("Request cancelled");
///             break;
///         }
///         Err(e) => return Err(e),
///     }
/// }
/// ```
pub struct AsyncStdioTransport {
    reader: AsyncLineReader,
    writer: AsyncStdout,
    codec: Codec,
    closed: bool,
}

impl AsyncStdioTransport {
    /// Creates a new async stdio transport.
    ///
    /// This is the primary constructor for MCP servers running as subprocess.
    /// Uses async I/O wrappers that integrate with asupersync's cancellation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            reader: AsyncLineReader::new(),
            writer: AsyncStdout::new(),
            codec: Codec::new(),
            closed: false,
        }
    }

    fn write_encoded(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        // Admission happens at the caller's full context checkpoint. Treat the
        // frame write and flush as one non-interruptible commit so a raw cancel
        // flag cannot defeat masking or split an admitted NDJSON frame.
        if let Err(error) = self.writer.write_all_unchecked(bytes) {
            self.closed = true;
            return Err(TransportError::Io(error));
        }
        if let Err(error) = self.writer.flush_unchecked() {
            self.closed = true;
            return Err(TransportError::Io(error));
        }
        Ok(())
    }

    fn latch_read_error(&mut self, cx: &Cx, error: BoundedLineReadError) -> TransportError {
        // AsyncLineReader deliberately leaves an oversized suffix unread and
        // owns any partially consumed prefix only for the duration of one
        // call. Every error after admission therefore ends this byte stream.
        self.closed = true;
        self.reader = AsyncLineReader::new();
        match error {
            BoundedLineReadError::Io(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                stdio_checkpoint(cx)
                    .err()
                    .unwrap_or(TransportError::Cancelled)
            }
            BoundedLineReadError::Io(error) => TransportError::Io(error),
            BoundedLineReadError::TooLarge(size) => {
                TransportError::Codec(CodecError::MessageTooLarge(size))
            }
        }
    }

    fn latch_consumed_checkpoint_failure(&mut self, error: TransportError) -> TransportError {
        self.closed = true;
        self.reader = AsyncLineReader::new();
        error
    }
}

impl Default for AsyncStdioTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for AsyncStdioTransport {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        stdio_checkpoint(cx)?;

        let bytes = match message {
            JsonRpcMessage::Request(req) => self.codec.encode_request(req)?,
            JsonRpcMessage::Response(resp) => self.codec.encode_response(resp)?,
        };

        // The checkpoint above admits one complete frame commit. Every commit
        // error is terminal because the NDJSON frame may be partial.
        self.write_encoded(&bytes)
    }

    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        stdio_checkpoint(cx)?;

        // Read non-empty line with cancellation checking
        let line = match self
            .reader
            .read_non_empty_line_bounded(cx, self.codec.max_message_size())
        {
            Ok(Some(line)) => line,
            Ok(None) => {
                self.closed = true;
                return Err(TransportError::Closed);
            }
            Err(error) => return Err(self.latch_read_error(cx, error)),
        };

        if let Err(error) = stdio_checkpoint(cx) {
            // The frame has left stdin, so discard the borrowed parser buffer
            // and make the failure terminal rather than silently skipping it
            // on a retry.
            self.closed = true;
            self.reader = AsyncLineReader::new();
            return Err(error);
        }

        // Apply the same strict admission policy as all other ingress paths.
        let message = self.codec.decode_complete_message(line)?;

        if let Err(error) = stdio_checkpoint(cx) {
            return Err(self.latch_consumed_checkpoint_failure(error));
        }

        Ok(message)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.writer.flush_unchecked()?;
        Ok(())
    }
}

impl AsyncStdioTransport {
    /// Send a request directly (avoids clone in trait method).
    pub fn send_request_direct(
        &mut self,
        cx: &Cx,
        request: &JsonRpcRequest,
    ) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        stdio_checkpoint(cx)?;

        let bytes = self.codec.encode_request(request)?;

        self.write_encoded(&bytes)
    }

    /// Send a response directly (avoids clone in trait method).
    pub fn send_response_direct(
        &mut self,
        cx: &Cx,
        response: &JsonRpcResponse,
    ) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        stdio_checkpoint(cx)?;

        let bytes = self.codec.encode_response(response)?;

        self.write_encoded(&bytes)
    }
}

impl TwoPhaseTransport for AsyncStdioTransport {
    type Writer = AsyncStdout;

    fn reserve_send(&mut self, cx: &Cx) -> Result<SendPermit<'_, Self::Writer>, TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        // This checkpoint is the cancellation point. The permit's commit phase
        // performs no further checkpoint.
        stdio_checkpoint(cx)?;

        // Return permit that allows the send to proceed
        // The commit phase uses Write trait impl which bypasses cancellation checks
        Ok(SendPermit::new(
            &mut self.writer,
            &self.codec,
            &mut self.closed,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::Cursor;
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;
    #[cfg(unix)]
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    #[cfg(unix)]
    use std::sync::{Mutex, mpsc};
    #[cfg(unix)]
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    struct TestChildGuard {
        child: Option<std::process::Child>,
    }

    #[cfg(unix)]
    impl TestChildGuard {
        fn new(child: std::process::Child) -> Self {
            Self { child: Some(child) }
        }

        fn child_mut(&mut self) -> &mut std::process::Child {
            self.child.as_mut().expect("test child already reaped")
        }

        fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
            let mut child = self.child.take().expect("test child already reaped");
            child.wait()
        }
    }

    #[cfg(unix)]
    impl Drop for TestChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    struct DropAwareWriter {
        dropped: Arc<AtomicBool>,
        fail_flush: bool,
        bytes: Vec<u8>,
    }

    impl Write for DropAwareWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if self.fail_flush {
                Err(std::io::Error::other("flush failed"))
            } else {
                Ok(())
            }
        }
    }

    #[cfg(unix)]
    struct GatedReader {
        inner: UnixStream,
        started: mpsc::Sender<()>,
        continue_read: mpsc::Receiver<()>,
        first_read: bool,
    }

    #[cfg(unix)]
    impl Read for GatedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.first_read {
                self.first_read = true;
                self.started
                    .send(())
                    .map_err(|_| std::io::Error::other("gated reader start receiver dropped"))?;
                self.continue_read
                    .recv()
                    .map_err(|_| std::io::Error::other("gated reader continuation dropped"))?;
            }
            self.inner.read(buffer)
        }
    }

    #[cfg(unix)]
    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    #[cfg(unix)]
    impl Write for SharedWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            let mut output = self
                .0
                .lock()
                .map_err(|_| std::io::Error::other("shared writer lock poisoned"))?;
            output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Drop for DropAwareWriter {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[derive(Default)]
    struct PartialWriteThenFail {
        bytes: Vec<u8>,
        wrote_partial_prefix: bool,
    }

    impl Write for PartialWriteThenFail {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            if self.wrote_partial_prefix {
                return Err(std::io::Error::other("write failed after partial frame"));
            }
            let written = buffer.len().min(8);
            self.bytes.extend_from_slice(&buffer[..written]);
            self.wrote_partial_prefix = true;
            Ok(written)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct ByteAtATime {
        inner: Cursor<Vec<u8>>,
    }

    impl Read for ByteAtATime {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let limit = buffer.len().min(1);
            self.inner.read(&mut buffer[..limit])
        }
    }

    struct CancelAfterFirstByte {
        cx: Cx,
        emitted: bool,
    }

    impl Read for CancelAfterFirstByte {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.emitted {
                return Ok(0);
            }
            buffer[0] = b'{';
            self.emitted = true;
            self.cx.set_cancel_requested(true);
            Ok(1)
        }
    }

    struct CancelAfterCompleteFrame {
        cx: Cx,
        inner: Cursor<Vec<u8>>,
    }

    impl Read for CancelAfterCompleteFrame {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let read = self.inner.read(buffer)?;
            if self.inner.position()
                == u64::try_from(self.inner.get_ref().len()).unwrap_or(u64::MAX)
            {
                self.cx.set_cancel_requested(true);
            }
            Ok(read)
        }
    }

    #[cfg(unix)]
    struct SlowReadyReader {
        inner: UnixStream,
        delay: Duration,
    }

    #[cfg(unix)]
    impl Read for SlowReadyReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.delay);
            self.inner.read(buffer)
        }
    }

    #[cfg(unix)]
    impl std::os::fd::AsFd for SlowReadyReader {
        fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
            std::os::fd::AsFd::as_fd(&self.inner)
        }
    }

    #[derive(Default)]
    struct OneByteThenReadError {
        emitted: bool,
    }

    impl Read for OneByteThenReadError {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.emitted {
                return Err(std::io::Error::other("read failed after frame prefix"));
            }
            buffer[0] = b'{';
            self.emitted = true;
            Ok(1)
        }
    }

    enum DeterministicReadStep {
        Bytes(Vec<u8>),
        Interrupted,
        Eof,
    }

    struct DeterministicInterruptedReader {
        steps: VecDeque<DeterministicReadStep>,
        cancel_on_interrupt: Option<Cx>,
    }

    impl Read for DeterministicInterruptedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let Some(step) = self.steps.pop_front() else {
                return Ok(0);
            };
            match step {
                DeterministicReadStep::Bytes(mut bytes) => {
                    let read = bytes.len().min(buffer.len());
                    buffer[..read].copy_from_slice(&bytes[..read]);
                    if read < bytes.len() {
                        let remaining = bytes.split_off(read);
                        self.steps
                            .push_front(DeterministicReadStep::Bytes(remaining));
                    }
                    Ok(read)
                }
                DeterministicReadStep::Interrupted => {
                    if let Some(cx) = &self.cancel_on_interrupt {
                        cx.set_cancel_requested(true);
                    }
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "deterministic transient fill interruption",
                    ))
                }
                DeterministicReadStep::Eof => Ok(0),
            }
        }
    }

    #[test]
    fn test_send_receive_roundtrip() {
        // Create a transport with a buffer as both reader and writer
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"test\",\"id\":1}\n";
        let reader = Cursor::new(input.to_vec());
        let writer = Vec::new();

        let mut transport = StdioTransport::new(reader, writer);

        // Use Cx::for_testing() for unit tests
        let cx = Cx::for_testing();
        let msg = transport.recv(&cx).unwrap();
        assert!(matches!(&msg, JsonRpcMessage::Request(_)));
        if let JsonRpcMessage::Request(req) = msg {
            assert_eq!(req.method, "test");
        }
    }

    #[test]
    fn test_send_message() {
        let reader = Cursor::new(Vec::new());
        let writer = Vec::new();

        let mut transport = StdioTransport::new(reader, writer);

        let cx = Cx::for_testing();
        let request = JsonRpcRequest::new("test/method", None, 1i64);
        transport.send_request_direct(&cx, &request).unwrap();
    }

    #[test]
    fn test_eof_returns_closed() {
        // Empty input = immediate EOF
        let reader = Cursor::new(Vec::new());
        let writer = Vec::new();

        let mut transport = StdioTransport::new(reader, writer);

        let cx = Cx::for_testing();
        let result = transport.recv(&cx);
        assert!(matches!(result, Err(TransportError::Closed)));
    }

    #[test]
    fn reality_check_regression_stdio_retries_interrupted_fill_without_losing_prefix() {
        let reader = DeterministicInterruptedReader {
            steps: VecDeque::from([
                DeterministicReadStep::Bytes(br#"{"jsonrpc":"2.0","meth"#.to_vec()),
                DeterministicReadStep::Interrupted,
                DeterministicReadStep::Bytes(b"od\":\"eintr\",\"id\":1}\n".to_vec()),
                DeterministicReadStep::Eof,
            ]),
            cancel_on_interrupt: None,
        };
        let mut transport = StdioTransport::new(reader, Vec::new());

        let message = transport
            .recv(&Cx::for_testing())
            .expect("a transient fill interruption must preserve the frame prefix");

        assert!(matches!(
            message,
            JsonRpcMessage::Request(ref request) if request.method == "eintr"
        ));
        assert!(!transport.closed);
    }

    #[test]
    fn reality_check_regression_stdio_checks_context_before_interrupted_retry() {
        let cx = Cx::for_testing();
        let reader = DeterministicInterruptedReader {
            steps: VecDeque::from([
                DeterministicReadStep::Bytes(br#"{"jsonrpc":"2.0","meth"#.to_vec()),
                DeterministicReadStep::Interrupted,
                DeterministicReadStep::Bytes(b"od\":\"must-not-run\",\"id\":1}\n".to_vec()),
            ]),
            cancel_on_interrupt: Some(cx.clone()),
        };
        let mut transport = StdioTransport::new(reader, Vec::new());

        assert!(matches!(
            transport.recv(&cx),
            Err(TransportError::Cancelled)
        ));
        assert!(transport.closed);
        assert!(transport.line_buffer.is_empty());
    }

    #[test]
    fn test_skip_empty_lines() {
        // Input with empty lines before the actual message
        let input = b"\n\n{\"jsonrpc\":\"2.0\",\"method\":\"test\",\"id\":1}\n";
        let reader = Cursor::new(input.to_vec());
        let writer = Vec::new();

        let mut transport = StdioTransport::new(reader, writer);

        let cx = Cx::for_testing();
        let msg = transport.recv(&cx).unwrap();
        assert!(matches!(&msg, JsonRpcMessage::Request(_)));
        if let JsonRpcMessage::Request(req) = msg {
            assert_eq!(req.method, "test");
        }
    }

    #[test]
    fn test_recv_rejects_oversized_line() {
        let request = JsonRpcRequest::new("test/method", None, 1i64);
        let line = serde_json::to_vec(&request).unwrap();
        let mut input = line.clone();
        input.push(b'\n');
        let reader = Cursor::new(input);
        let writer = Vec::new();

        let mut transport = StdioTransport::new(reader, writer);
        transport
            .codec
            .set_max_message_size(line.len().saturating_sub(1));

        let cx = Cx::for_testing();
        let result = transport.recv(&cx);
        assert!(matches!(
            result,
            Err(TransportError::Codec(CodecError::MessageTooLarge(_)))
        ));
        assert!(transport.closed);
        assert!(transport.line_buffer.capacity() <= 4096);

        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        assert!(matches!(
            transport.recv(&cancelled),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn cancellation_after_consuming_a_frame_prefix_latches_closed() {
        let cx = Cx::for_testing();
        let reader = CancelAfterFirstByte {
            cx: cx.clone(),
            emitted: false,
        };
        let mut transport = StdioTransport::new(reader, Vec::new());

        assert!(matches!(
            transport.recv(&cx),
            Err(TransportError::Cancelled)
        ));
        assert!(transport.closed);
        assert!(transport.line_buffer.is_empty());
        assert!(matches!(transport.recv(&cx), Err(TransportError::Closed)));
    }

    #[test]
    fn checkpoint_contract_observes_budgets_cancellation_and_masking() {
        let deadline_cx = Cx::for_testing_with_budget(
            asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
        );
        assert!(matches!(
            stdio_checkpoint(&deadline_cx),
            Err(TransportError::Timeout)
        ));

        let quota_cx = Cx::for_testing_with_budget(asupersync::Budget::new().with_poll_quota(0));
        assert!(matches!(
            stdio_checkpoint(&quota_cx),
            Err(TransportError::Cancelled)
        ));

        let masked_deadline_cx = Cx::for_testing_with_budget(
            asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
        );
        masked_deadline_cx.masked(|| {
            stdio_checkpoint(&masked_deadline_cx)
                .expect("masking defers deadline enforcement at the checkpoint");
        });
        assert!(matches!(
            stdio_checkpoint(&masked_deadline_cx),
            Err(TransportError::Timeout)
        ));

        let masked_cancel_cx = Cx::for_testing();
        masked_cancel_cx.set_cancel_requested(true);
        masked_cancel_cx.masked(|| {
            stdio_checkpoint(&masked_cancel_cx)
                .expect("masking defers explicit cancellation at the checkpoint");
        });
        assert!(matches!(
            stdio_checkpoint(&masked_cancel_cx),
            Err(TransportError::Cancelled)
        ));
    }

    #[test]
    fn pre_read_budget_failure_is_retryable_while_masked() {
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"masked\",\"id\":1}\n";
        let mut transport = StdioTransport::new(Cursor::new(input.to_vec()), Vec::new());
        let cx = Cx::for_testing_with_budget(
            asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
        );

        assert!(matches!(transport.recv(&cx), Err(TransportError::Timeout)));
        assert!(!transport.closed);
        assert!(transport.line_buffer.is_empty());

        let message = cx
            .masked(|| transport.recv(&cx))
            .expect("no bytes were consumed before the masked retry");
        assert!(matches!(
            message,
            JsonRpcMessage::Request(ref request) if request.method == "masked"
        ));
    }

    #[test]
    fn cancellation_after_consuming_a_complete_frame_latches_closed() {
        let cx = Cx::for_testing();
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"complete\",\"id\":1}\n";
        let reader = CancelAfterCompleteFrame {
            cx: cx.clone(),
            inner: Cursor::new(input.to_vec()),
        };
        let mut transport = StdioTransport::new(reader, Vec::new());

        assert!(matches!(
            transport.recv(&cx),
            Err(TransportError::Cancelled)
        ));
        assert!(transport.closed);
        assert!(transport.line_buffer.is_empty());
        assert!(matches!(transport.recv(&cx), Err(TransportError::Closed)));
    }

    #[cfg(unix)]
    #[test]
    fn recv_until_times_out_while_peer_is_silent() {
        let (_silent_peer, reader) = UnixStream::pair().expect("create socket pair");
        let mut transport = StdioTransport::new(reader, Vec::new());
        let cx = Cx::for_testing();
        let started = Instant::now();
        let deadline = started + Duration::from_millis(40);

        assert!(matches!(
            transport.recv_until(&cx, Some(deadline)),
            Err(TransportError::ReceiveDeadlineExceeded)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!transport.closed);
    }

    #[cfg(unix)]
    #[test]
    fn reality_check_regression_internal_stop_wakes_masked_silent_stdio_receive() {
        let (_silent_peer, reader) = UnixStream::pair().expect("create socket pair");
        let mut transport = StdioTransport::new(reader, Vec::new());
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let trigger = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            stop_for_thread.store(true, Ordering::Release);
        });
        let cx = Cx::for_testing();
        let started = Instant::now();

        let result = cx
            .masked(|| transport.recv_until_or_stopped(&cx, None, || stop.load(Ordering::Acquire)));
        trigger.join().expect("stop trigger must not panic");

        assert!(matches!(result, Err(TransportError::Cancelled)));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(transport.closed);
        assert!(matches!(transport.recv(&cx), Err(TransportError::Closed)));
    }

    #[cfg(unix)]
    #[test]
    fn reality_check_regression_internal_stop_wins_concurrent_eof() {
        let (peer, reader) = UnixStream::pair().expect("create socket pair");
        drop(peer);
        let mut transport = StdioTransport::new(reader, Vec::new());
        let cx = Cx::for_testing();
        let checks = std::cell::Cell::new(0_u8);

        let result = transport.recv_until_or_stopped(&cx, None, || {
            let next = checks.get().saturating_add(1);
            checks.set(next);
            // The readiness path checks before polling and after the EOF/HUP
            // readiness event. Turn the latch on only for the final check
            // after `recv_with_readiness` has classified the empty read.
            next >= 3
        });

        assert!(matches!(result, Err(TransportError::Cancelled)));
        assert!(checks.get() >= 3);
        assert!(transport.closed);
    }

    #[cfg(unix)]
    #[test]
    fn recv_until_times_out_and_closes_after_partial_frame() {
        let (mut peer, reader) = UnixStream::pair().expect("create socket pair");
        peer.write_all(br#"{"jsonrpc":"2.0","method":"partial""#)
            .expect("write frame prefix");
        peer.flush().expect("flush frame prefix");

        let mut transport = StdioTransport::new(reader, Vec::new());
        let cx = Cx::for_testing();
        let started = Instant::now();
        let deadline = started + Duration::from_millis(40);

        assert!(matches!(
            transport.recv_until(&cx, Some(deadline)),
            Err(TransportError::ReceiveDeadlineExceeded)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(transport.closed);
        assert!(transport.line_buffer.is_empty());
        assert!(matches!(
            transport.recv_until(&cx, None),
            Err(TransportError::Closed)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn recv_until_decodes_a_ready_complete_frame() {
        let (mut peer, reader) = UnixStream::pair().expect("create socket pair");
        peer.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"ready\",\"id\":1}\n")
            .expect("write complete frame");
        peer.flush().expect("flush complete frame");

        let mut transport = StdioTransport::new(reader, Vec::new());
        let deadline = Instant::now() + Duration::from_secs(1);
        let message = transport
            .recv_until(&Cx::for_testing(), Some(deadline))
            .expect("receive ready frame");

        let JsonRpcMessage::Request(request) = message else {
            panic!("expected request");
        };
        assert_eq!(request.method, "ready");
    }

    #[cfg(unix)]
    #[test]
    fn recv_until_latches_when_deadline_expires_during_a_ready_read() {
        let (mut peer, reader) = UnixStream::pair().expect("create socket pair");
        peer.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"slow\",\"id\":1}\n")
            .expect("write complete frame");
        peer.flush().expect("flush complete frame");

        let reader = SlowReadyReader {
            inner: reader,
            delay: Duration::from_millis(200),
        };
        let mut transport = StdioTransport::new(reader, Vec::new());
        let deadline = Instant::now() + Duration::from_millis(100);

        assert!(matches!(
            transport.recv_until(&Cx::for_testing(), Some(deadline)),
            Err(TransportError::ReceiveDeadlineExceeded)
        ));
        assert!(transport.closed);
        assert!(transport.line_buffer.is_empty());
        assert!(matches!(
            transport.recv_until(&Cx::for_testing(), None),
            Err(TransportError::Closed)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn recv_until_with_completion_preserves_a_complete_late_frame() {
        let (mut peer, reader) = UnixStream::pair().expect("create socket pair");
        peer.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"slow\",\"id\":1}\n")
            .expect("write complete frame");
        peer.flush().expect("flush complete frame");

        let reader = SlowReadyReader {
            inner: reader,
            delay: Duration::from_millis(200),
        };
        let mut transport = StdioTransport::new(reader, Vec::new());
        let deadline = Instant::now() + Duration::from_millis(100);

        let (message, completed_at) = transport
            .recv_until_with_completion(&Cx::for_testing(), Some(deadline))
            .expect("a complete frame remains available to its policy owner");

        assert!(completed_at >= deadline);
        assert!(!transport.is_closed());
        let JsonRpcMessage::Request(request) = message else {
            panic!("expected request");
        };
        assert_eq!(request.method, "slow");
    }

    #[cfg(unix)]
    #[test]
    fn internal_stdio_b_lifecycle_positive() {
        let mut child = TestChildGuard::new(
            Command::new("sh")
                .args([
                    "-c",
                    "IFS= read -r line; test -n \"$line\"; cat >/dev/null; exit 0",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn stdio lifecycle child"),
        );
        let writer = child.child_mut().stdin.take().expect("child stdin");
        let reader = child.child_mut().stdout.take().expect("child stdout");
        let mut transport = StdioTransport::new(reader, writer);
        let control = JsonRpcMessage::Request(JsonRpcRequest::notification(
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": "request-8"})),
        ));
        transport
            .try_send_control_message(&control)
            .expect("reserved control capacity commits one complete cancellation frame");

        let (status, forced) = transport
            .close_and_reap_child(
                &Cx::for_testing(),
                child.child_mut(),
                Duration::from_secs(2),
            )
            .expect("closing stdin lets the exact child exit and reap");

        assert!(
            status.success(),
            "the child observed the committed control frame"
        );
        assert!(!forced, "EOF-driven child exit must not require escalation");
        assert!(
            transport.is_closed(),
            "lifecycle close rejects later application writes"
        );
        assert!(
            child
                .child_mut()
                .try_wait()
                .expect("inspect reaped child")
                .is_some(),
            "a returned lifecycle outcome is reaped, not merely signalled"
        );
    }

    #[cfg(unix)]
    #[test]
    fn internal_stdio_b_lifecycle_planted_negative() {
        let mut child = TestChildGuard::new(
            Command::new("sh")
                .args([
                    "-c",
                    "IFS= read -r line; test -n \"$line\"; cat >/dev/null; exit 0",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn stdio lifecycle child"),
        );
        let writer = child.child_mut().stdin.take().expect("child stdin");
        let reader = child.child_mut().stdout.take().expect("child stdout");
        let mut transport = StdioTransport::new(reader, writer);
        let control = JsonRpcMessage::Request(JsonRpcRequest::notification(
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": "request-8"})),
        ));
        transport
            .try_send_control_message(&control)
            .expect("the same reserved control frame commits before the plant");
        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);

        let error = transport
            .close_and_reap_child(&cancelled, child.child_mut(), Duration::from_secs(2))
            .expect_err("one changed cancellation bit refuses before stdin close");

        assert!(matches!(error, TransportError::Cancelled));
        assert!(
            !transport.is_closed(),
            "pre-close cancellation leaves the transport write side unchanged"
        );
        assert!(
            child
                .child_mut()
                .try_wait()
                .expect("inspect live child")
                .is_none(),
            "pre-close cancellation cannot reap or terminate the unrelated child"
        );

        let (status, forced) = transport
            .close_and_reap_child(
                &Cx::for_testing(),
                child.child_mut(),
                Duration::from_secs(2),
            )
            .expect("fresh connection cleanup reaps the still-live child");
        assert!(status.success());
        assert!(!forced);
    }

    #[cfg(unix)]
    #[test]
    fn nonblocking_control_send_commits_one_complete_frame() {
        let mut child = TestChildGuard::new(
            Command::new("sh")
                .args(["-c", "IFS= read -r line; printf '%s\\n' \"$line\""])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn child-pipe reader"),
        );
        let writer = child.child_mut().stdin.take().expect("child stdin");
        let peer = child.child_mut().stdout.take().expect("child stdout");
        let mut transport = StdioTransport::new(Cursor::new(Vec::<u8>::new()), writer);
        let request = JsonRpcRequest::notification(
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": 7})),
        );

        transport
            .try_send_control_message(&JsonRpcMessage::Request(request))
            .expect("small control frame must commit immediately");

        let mut peer_transport = StdioTransport::new(peer, Vec::new());
        let decoded = peer_transport
            .recv_until(
                &Cx::for_testing(),
                Some(Instant::now() + Duration::from_secs(2)),
            )
            .expect("read control frame before the bounded test deadline");
        let JsonRpcMessage::Request(decoded) = decoded else {
            panic!("expected cancellation request");
        };
        assert_eq!(decoded.method, "notifications/cancelled");
        assert_eq!(decoded.id, None);
        assert!(!transport.is_closed());
        assert!(child.wait().expect("reap child-pipe reader").success());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_control_capacity_accepts_512_and_rejects_513_without_closing() {
        let mut child = TestChildGuard::new(
            Command::new("sh")
                .args(["-c", "exec sleep 60"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn bounded control-capacity peer"),
        );
        let writer = child.child_mut().stdin.take().expect("child stdin");
        let mut transport = StdioTransport::new(Cursor::new(Vec::<u8>::new()), writer);

        transport
            .try_write_atomic_control(&[b'x'; STDIO_ATOMIC_CONTROL_FRAME_MAX])
            .expect("the exact POSIX minimum atomic bound must be admitted");
        assert!(!transport.is_closed());

        let error = transport
            .try_write_atomic_control(&[b'x'; STDIO_ATOMIC_CONTROL_FRAME_MAX + 1])
            .expect_err("one byte above atomic capacity must be rejected before I/O");
        assert!(matches!(
            error,
            TransportError::ControlFrameTooLarge {
                size: 513,
                max: 512
            }
        ));
        assert!(
            !transport.is_closed(),
            "a pre-commit capacity rejection is not an ambiguous pipe failure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn encoded_oversized_control_reports_capacity_not_codec_failure() {
        let mut child = TestChildGuard::new(
            Command::new("sh")
                .args(["-c", "exec sleep 60"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn bounded oversized-control peer"),
        );
        let writer = child.child_mut().stdin.take().expect("child stdin");
        let mut transport = StdioTransport::new(Cursor::new(Vec::<u8>::new()), writer);
        let request = JsonRpcRequest::notification(
            "notifications/cancelled",
            Some(serde_json::json!({
                "requestId": 7,
                "reason": "x".repeat(STDIO_ATOMIC_CONTROL_FRAME_MAX)
            })),
        );

        let error = transport
            .try_send_control_message(&JsonRpcMessage::Request(request))
            .expect_err("valid JSON-RPC can exceed the atomic control capacity");
        assert!(matches!(
            error,
            TransportError::ControlFrameTooLarge {
                size,
                max: STDIO_ATOMIC_CONTROL_FRAME_MAX
            } if size > STDIO_ATOMIC_CONTROL_FRAME_MAX
        ));
        assert!(!transport.is_closed());
    }

    #[cfg(unix)]
    #[test]
    fn nonblocking_control_send_fails_boundedly_when_peer_does_not_read() {
        let mut child = TestChildGuard::new(
            Command::new("sh")
                .args(["-c", "exec sleep 60"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn non-reading child"),
        );
        let writer = child.child_mut().stdin.take().expect("child stdin");
        let mut transport = StdioTransport::new(Cursor::new(Vec::<u8>::new()), writer);
        let request = JsonRpcRequest::notification(
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": 7})),
        );
        let message = JsonRpcMessage::Request(request);

        let error = (0..100_000)
            .find_map(|_| transport.try_send_control_message(&message).err())
            .expect("a non-reading peer must eventually exhaust finite pipe capacity");

        let TransportError::Io(error) = error else {
            panic!("full nonblocking pipe must report an I/O readiness error");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(matches!(child.child_mut().try_wait(), Ok(None)));
        assert!(transport.is_closed());
    }

    #[test]
    fn read_error_after_consuming_a_frame_prefix_latches_closed() {
        let mut transport = StdioTransport::new(OneByteThenReadError::default(), Vec::new());
        let cx = Cx::for_testing();

        assert!(matches!(transport.recv(&cx), Err(TransportError::Io(_))));
        assert!(transport.closed);
        assert!(transport.line_buffer.is_empty());
        assert!(matches!(transport.recv(&cx), Err(TransportError::Closed)));
    }

    #[test]
    fn test_recv_accepts_exact_limit_frame_with_crlf() {
        let line = br#"{"jsonrpc":"2.0","method":"exact","id":1}"#;
        let mut input = line.to_vec();
        input.extend_from_slice(b"\r\n");
        let mut transport = StdioTransport::new(Cursor::new(input), Vec::new());
        transport.codec.set_max_message_size(line.len());

        let message = transport.recv(&Cx::for_testing()).unwrap();

        let JsonRpcMessage::Request(request) = message else {
            panic!("expected request");
        };
        assert_eq!(request.method, "exact");
    }

    #[test]
    fn test_recv_accepts_utf8_split_across_underlying_reads() {
        let input = "{\"jsonrpc\":\"2.0\",\"method\":\"méthod\",\"id\":1}\n";
        let reader = ByteAtATime {
            inner: Cursor::new(input.as_bytes().to_vec()),
        };
        let mut transport = StdioTransport::new(reader, Vec::new());

        let message = transport.recv(&Cx::for_testing()).unwrap();

        let JsonRpcMessage::Request(request) = message else {
            panic!("expected request");
        };
        assert_eq!(request.method, "méthod");
    }

    #[test]
    fn test_recv_rejects_escaped_duplicate_object_member() {
        let input =
            b"{\"jsonrpc\":\"2.0\",\"method\":\"first\",\"m\\u0065thod\":\"second\",\"id\":1}\n";
        let reader = Cursor::new(input.to_vec());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);

        let error = transport.recv(&Cx::for_testing()).unwrap_err();

        assert!(matches!(
            error,
            TransportError::Codec(CodecError::InvalidMessage {
                kind: crate::InvalidMessageKind::Request,
                ..
            })
        ));
        assert!(error.to_string().contains("duplicate JSON object member"));
    }

    #[test]
    fn test_cancellation_on_recv() {
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"test\",\"id\":1}\n";
        let reader = Cursor::new(input.to_vec());
        let writer = Vec::new();

        let mut transport = StdioTransport::new(reader, writer);

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let result = transport.recv(&cx);
        assert!(matches!(result, Err(TransportError::Cancelled)));
    }

    #[test]
    fn test_cancellation_on_send() {
        let reader = Cursor::new(Vec::new());
        let writer = Vec::new();

        let mut transport = StdioTransport::new(reader, writer);

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let request = JsonRpcRequest::new("test/method", None, 1i64);
        let result = transport.send_request_direct(&cx, &request);
        assert!(matches!(result, Err(TransportError::Cancelled)));
    }

    #[test]
    fn stdio_split_halves_preserve_full_duplex_bounded_ndjson() {
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}\n\
                      {\"jsonrpc\":\"2.0\",\"result\":{\"accepted\":true},\"id\":2}\n";
        let mut output = Vec::new();
        let cx = Cx::for_testing();

        {
            let transport = StdioTransport::new(Cursor::new(input.to_vec()), &mut output);
            let (mut recv_half, mut send_half) = transport.into_split();

            let JsonRpcMessage::Request(request) = recv_half.recv(&cx).expect("split request")
            else {
                panic!("expected inbound request");
            };
            assert_eq!(request.method, "tools/list");

            send_half
                .send(
                    &cx,
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        fastmcp_protocol::RequestId::Number(1),
                        serde_json::json!({"tools": []}),
                    )),
                )
                .expect("split response");

            let JsonRpcMessage::Response(response) = recv_half.recv(&cx).expect("split response")
            else {
                panic!("expected inbound response");
            };
            assert_eq!(response.id, Some(fastmcp_protocol::RequestId::Number(2)));
        }

        let mut output_reader = StdioTransport::new(Cursor::new(output), Vec::new());
        let JsonRpcMessage::Response(response) = output_reader
            .recv(&Cx::for_testing())
            .expect("bounded split output")
        else {
            panic!("expected split output response");
        };
        assert_eq!(response.id, Some(fastmcp_protocol::RequestId::Number(1)));
    }

    #[cfg(unix)]
    #[test]
    fn stdio_split_send_commits_while_recv_is_blocked() {
        let (mut peer, reader) = UnixStream::pair().expect("create split peer");
        let (started_tx, started_rx) = mpsc::channel();
        let (continue_tx, continue_rx) = mpsc::channel();
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer = SharedWriter(Arc::clone(&output));
        let transport = StdioTransport::new(
            GatedReader {
                inner: reader,
                started: started_tx,
                continue_read: continue_rx,
                first_read: false,
            },
            writer,
        );
        let (mut recv_half, mut send_half) = transport.into_split();

        let receive = std::thread::spawn(move || recv_half.recv(&Cx::for_testing()));
        started_rx
            .recv()
            .expect("receive half must block before ingress is released");

        send_half
            .send(
                &Cx::for_testing(),
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    fastmcp_protocol::RequestId::Number(1),
                    serde_json::json!({"committed": true}),
                )),
            )
            .expect("split response must commit while receive is blocked");

        continue_tx.send(()).expect("release blocked split receive");
        peer.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":2}\n")
            .expect("write split ingress");
        let JsonRpcMessage::Request(request) = receive
            .join()
            .expect("split receive thread must not panic")
            .expect("split ingress request")
        else {
            panic!("expected split ingress request");
        };
        assert_eq!(request.id, Some(fastmcp_protocol::RequestId::Number(2)));

        let bytes = output.lock().expect("shared split output lock").clone();
        let mut output_reader = StdioTransport::new(Cursor::new(bytes), Vec::new());
        assert!(matches!(
            output_reader.recv(&Cx::for_testing()),
            Ok(JsonRpcMessage::Response(_))
        ));
    }

    #[test]
    fn stdio_split_send_rejects_after_close_without_writing() {
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}\n";
        let mut output = Vec::new();
        let cx = Cx::for_testing();

        {
            let transport = StdioTransport::new(Cursor::new(input.to_vec()), &mut output);
            let (mut recv_half, mut send_half) = transport.into_split();

            assert!(matches!(
                recv_half.recv(&cx),
                Ok(JsonRpcMessage::Request(_))
            ));
            send_half.close().expect("close split writer");
            assert!(matches!(
                send_half.send(
                    &cx,
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        fastmcp_protocol::RequestId::Number(1),
                        serde_json::json!({"tools": []}),
                    )),
                ),
                Err(TransportError::Closed)
            ));
        }

        assert!(output.is_empty(), "closed send half must not write a frame");
    }

    #[test]
    fn stdio_split_reserve_send_commits_after_preflight_cancellation() {
        let mut output = Vec::new();
        let cx = Cx::for_testing();

        {
            let transport = StdioTransport::new(Cursor::new(Vec::new()), &mut output);
            let (_recv_half, mut send_half) = transport.into_split();
            let permit = send_half.reserve_send(&cx).expect("reserve split response");
            cx.set_cancel_requested(true);

            permit
                .send_response(&JsonRpcResponse::success(
                    fastmcp_protocol::RequestId::Number(7),
                    serde_json::json!({"committed": true}),
                ))
                .expect("reserved split response must commit without another checkpoint");
        }

        let mut output_reader = StdioTransport::new(Cursor::new(output), Vec::new());
        let JsonRpcMessage::Response(response) = output_reader
            .recv(&Cx::for_testing())
            .expect("reserved split output")
        else {
            panic!("expected reserved split response");
        };
        assert_eq!(response.id, Some(fastmcp_protocol::RequestId::Number(7)));
    }

    #[test]
    fn stdio_split_terminal_state_propagates_between_halves() {
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}\n";
        let writer = DropAwareWriter {
            dropped: Arc::new(AtomicBool::new(false)),
            fail_flush: true,
            bytes: Vec::new(),
        };
        let transport = StdioTransport::new(Cursor::new(input.to_vec()), writer);
        let (mut recv_half, mut send_half) = transport.into_split();

        let error = send_half
            .send(
                &Cx::for_testing(),
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    fastmcp_protocol::RequestId::Number(1),
                    serde_json::json!({"tools": []}),
                )),
            )
            .expect_err("failed split write must be terminal");
        assert!(matches!(error, TransportError::Io(_)));
        assert!(send_half.is_closed());
        assert!(recv_half.is_closed());
        assert!(matches!(
            recv_half.recv(&Cx::for_testing()),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn stdio_split_preserves_codec_limit_for_outbound_commit() {
        let mut transport = StdioTransport::new(Cursor::new(Vec::new()), Vec::new());
        transport.codec.set_max_message_size(128);
        let (recv_half, send_half) = transport.into_split();

        assert_eq!(recv_half.transport.codec.max_message_size(), 128);
        assert_eq!(send_half.codec.max_message_size(), 128);
    }

    #[test]
    fn test_two_phase_send_success() {
        let reader = Cursor::new(Vec::new());
        let writer = Vec::new();

        let mut transport = StdioTransport::new(reader, writer);

        let cx = Cx::for_testing();

        // Reserve a send slot
        let permit = transport.reserve_send(&cx).unwrap();

        // Send a request via the permit
        let request = JsonRpcRequest::new("test/method", None, 1i64);
        permit.send_request(&request).unwrap();
    }

    #[test]
    fn test_two_phase_send_cancellation_on_reserve() {
        let reader = Cursor::new(Vec::new());
        let writer = Vec::new();

        let mut transport = StdioTransport::new(reader, writer);

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        // Reservation should fail when cancelled
        let result = transport.reserve_send(&cx);
        assert!(matches!(result, Err(TransportError::Cancelled)));
    }

    #[test]
    fn test_two_phase_send_message() {
        let reader = Cursor::new(Vec::new());
        let writer = Vec::new();

        let mut transport = StdioTransport::new(reader, writer);

        let cx = Cx::for_testing();

        // Reserve and send using the generic send method
        let permit = transport.reserve_send(&cx).unwrap();
        let request = JsonRpcRequest::new("test/method", None, 1i64);
        let message = JsonRpcMessage::Request(request);
        permit.send(&message).unwrap();
    }

    #[test]
    fn partial_two_phase_write_latches_stdio_transport_closed() {
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"unread\",\"id\":2}\n";
        let mut transport =
            StdioTransport::new(Cursor::new(input.to_vec()), PartialWriteThenFail::default());
        let cx = Cx::for_testing();
        let request = JsonRpcRequest::new("tools/call", None, 1_i64);

        let error = transport
            .reserve_send(&cx)
            .unwrap()
            .send_request(&request)
            .unwrap_err();

        assert!(matches!(error, TransportError::Io(_)));
        assert!(transport.closed);
        let writer = transport.writer.as_ref().unwrap();
        assert!(!writer.bytes.is_empty());
        assert!(!writer.bytes.ends_with(b"\n"));
        assert!(matches!(
            transport.send(&cx, &JsonRpcMessage::Request(request.clone())),
            Err(TransportError::Closed)
        ));
        assert!(matches!(transport.recv(&cx), Err(TransportError::Closed)));
        assert!(matches!(
            transport.reserve_send(&cx),
            Err(TransportError::Closed)
        ));
        assert!(transport.close().is_ok());
        assert!(transport.writer.is_none());
    }

    #[test]
    fn prewrite_codec_failure_does_not_close_stdio_transport() {
        let mut transport = StdioTransport::new(Cursor::new(Vec::new()), Vec::new());
        let cx = Cx::for_testing();
        let invalid = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            result: None,
            error: None,
            id: Some(fastmcp_protocol::RequestId::Number(1)),
        };

        assert!(matches!(
            transport.send_response_direct(&cx, &invalid),
            Err(TransportError::Codec(CodecError::Json(_)))
        ));
        assert!(!transport.closed);

        transport
            .send_request_direct(&cx, &JsonRpcRequest::new("still-open", None, 2_i64))
            .unwrap();
        assert!(!transport.writer.as_ref().unwrap().is_empty());
    }

    // =========================================================================
    // E2E Stdio NDJSON Tests (bd-2kv / bd-swyn)
    // =========================================================================

    #[test]
    fn e2e_ndjson_multiple_messages_in_sequence() {
        // Simulate multiple JSON-RPC messages in NDJSON format
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"init\",\"id\":1}\n\
                      {\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":2}\n\
                      {\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"test\"},\"id\":3}\n";

        let reader = Cursor::new(input.to_vec());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);
        let cx = Cx::for_testing();

        // Receive first message
        let msg1 = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg1, JsonRpcMessage::Request(_)),
            "Expected request"
        );
        let JsonRpcMessage::Request(req) = msg1 else {
            return;
        };
        assert_eq!(req.method, "init");

        // Receive second message
        let msg2 = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg2, JsonRpcMessage::Request(_)),
            "Expected request"
        );
        let JsonRpcMessage::Request(req) = msg2 else {
            return;
        };
        assert_eq!(req.method, "tools/list");

        // Receive third message
        let msg3 = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg3, JsonRpcMessage::Request(_)),
            "Expected request"
        );
        let JsonRpcMessage::Request(req) = msg3 else {
            return;
        };
        assert_eq!(req.method, "tools/call");
        assert!(req.params.is_some());

        // Fourth recv should return EOF (Closed)
        let result = transport.recv(&cx);
        assert!(matches!(result, Err(TransportError::Closed)));
    }

    #[test]
    fn internal_stdio_a_dispatch_positive() {
        let input = b"{\"jsonrpc\":\"2.0\",\"result\":{\"ok\":true},\"id\":\"request-7\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":\"request-8\"}\n";
        assert_eq!(input.split(|byte| *byte == b'\n').count(), 4);
        assert!(input.ends_with(b"\n"));
        let mut transport = StdioTransport::new(Cursor::new(input.to_vec()), Vec::new());
        let cx = Cx::for_testing();
        let mut requests = Vec::new();
        let mut responses = Vec::new();
        let mut on_request = |request: JsonRpcRequest| {
            requests.push((
                request.method,
                request
                    .id
                    .map(|id| serde_json::to_value(id).expect("request ID is serializable")),
            ));
        };
        let mut on_response = |response: JsonRpcResponse| {
            responses.push(serde_json::to_value(response.id).expect("response ID is serializable"));
        };

        for _ in 0..3 {
            transport
                .dispatch_next(&cx, &mut on_request, &mut on_response)
                .expect("each complete newline frame dispatches exactly once");
        }

        assert_eq!(
            responses,
            vec![serde_json::json!("request-7")],
            "the response remains correlated with its exact wire ID"
        );
        assert_eq!(
            requests,
            vec![
                ("notifications/progress".to_owned(), None),
                (
                    "tools/list".to_owned(),
                    Some(serde_json::json!("request-8"))
                ),
            ],
            "request and notification frames retain order while responses multiplex separately"
        );
        assert!(
            transport.writer.as_ref().expect("open writer").is_empty(),
            "bidirectional dispatch never invents a reverse response"
        );
    }

    #[test]
    fn internal_stdio_a_dispatch_planted_negative() {
        let valid = b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":\"request-8\"}\n";
        let forbidden = b"{\"jsonrpc\":\"2.0\",\"method\":\"tools\n/list\",\"id\":\"request-8\"}\n";
        let mut restored = forbidden.to_vec();
        let embedded_newline = restored
            .iter()
            .position(|byte| *byte == b'\n')
            .expect("the planted frame contains an embedded newline");
        restored.remove(embedded_newline);
        assert_eq!(
            restored, valid,
            "the planted negative differs only by one forbidden embedded newline byte"
        );

        let mut transport = StdioTransport::new(Cursor::new(forbidden.to_vec()), Vec::new());
        let cx = Cx::for_testing();
        let mut request_count = 0;
        let mut response_count = 0;
        let error = transport
            .dispatch_next(&cx, &mut |_| request_count += 1, &mut |_| {
                response_count += 1
            })
            .expect_err("an embedded newline must reject before either direction dispatches");

        assert!(matches!(error, TransportError::Codec(_)));
        assert_eq!(
            request_count, 0,
            "rejected framing cannot dispatch a request"
        );
        assert_eq!(
            response_count, 0,
            "rejected framing cannot dispatch a response"
        );
        assert!(
            transport.writer.as_ref().expect("open writer").is_empty(),
            "a rejected inbound frame never emits a reverse parse or invalid-request response"
        );
    }

    #[test]
    fn e2e_ndjson_request_response_flow() {
        // Test a typical request/response flow
        let input = b"{\"jsonrpc\":\"2.0\",\"result\":{\"success\":true},\"id\":1}\n";

        let reader = Cursor::new(input.to_vec());
        let mut output = Vec::new();
        let mut transport = StdioTransport::new(reader, Cursor::new(&mut output));
        let cx = Cx::for_testing();

        // Send a request
        let request = JsonRpcRequest::new(
            "test/method",
            Some(serde_json::json!({"key": "value"})),
            1i64,
        );
        transport.send_request_direct(&cx, &request).unwrap();

        // Receive response
        let msg = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg, JsonRpcMessage::Response(_)),
            "Expected response"
        );
        let JsonRpcMessage::Response(resp) = msg else {
            return;
        };
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn e2e_ndjson_handles_mixed_empty_lines() {
        // NDJSON should skip empty lines
        let input = b"\n\n{\"jsonrpc\":\"2.0\",\"method\":\"test1\",\"id\":1}\n\n\n{\"jsonrpc\":\"2.0\",\"method\":\"test2\",\"id\":2}\n\n";

        let reader = Cursor::new(input.to_vec());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);
        let cx = Cx::for_testing();

        // Should receive both messages despite empty lines
        let msg1 = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg1, JsonRpcMessage::Request(_)),
            "Expected request"
        );
        let JsonRpcMessage::Request(req) = msg1 else {
            return;
        };
        assert_eq!(req.method, "test1");

        let msg2 = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg2, JsonRpcMessage::Request(_)),
            "Expected request"
        );
        let JsonRpcMessage::Request(req) = msg2 else {
            return;
        };
        assert_eq!(req.method, "test2");
    }

    #[test]
    fn e2e_ndjson_handles_unicode_content() {
        // Test UTF-8 handling in NDJSON
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"test\",\"params\":{\"message\":\"\xC3\xA9\xC3\xA8\xC3\xAA\xE4\xB8\xAD\xE6\x96\x87\xF0\x9F\x91\x8B\"},\"id\":1}\n";

        let reader = Cursor::new(input.to_vec());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);
        let cx = Cx::for_testing();

        let msg = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg, JsonRpcMessage::Request(_)),
            "Expected request"
        );
        let JsonRpcMessage::Request(req) = msg else {
            return;
        };
        assert_eq!(req.method, "test");
        let params = req.params.as_ref().unwrap();
        let message = params.get("message").unwrap().as_str().unwrap();
        // Contains: éèê中文👋
        assert!(message.contains("é"));
        assert!(message.contains("中"));
        assert!(message.contains("👋"));
    }

    #[test]
    fn e2e_ndjson_large_message() {
        // Test handling of larger messages
        let large_data = "x".repeat(100_000);
        let message = format!(
            "{{\"jsonrpc\":\"2.0\",\"method\":\"test\",\"params\":{{\"data\":\"{}\"}},\"id\":1}}\n",
            large_data
        );

        let reader = Cursor::new(message.into_bytes());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);
        let cx = Cx::for_testing();

        let msg = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg, JsonRpcMessage::Request(_)),
            "Expected request"
        );
        let JsonRpcMessage::Request(req) = msg else {
            return;
        };
        assert_eq!(req.method, "test");
        let params = req.params.as_ref().unwrap();
        let data = params.get("data").unwrap().as_str().unwrap();
        assert_eq!(data.len(), 100_000);
    }

    #[test]
    fn e2e_ndjson_notification() {
        // Test JSON-RPC notifications (requests without id)
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";

        let reader = Cursor::new(input.to_vec());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);
        let cx = Cx::for_testing();

        let msg = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg, JsonRpcMessage::Request(_)),
            "Expected request/notification"
        );
        let JsonRpcMessage::Request(req) = msg else {
            return;
        };
        assert_eq!(req.method, "notifications/initialized");
        assert!(req.id.is_none());
    }

    #[test]
    fn e2e_ndjson_error_response() {
        // Test JSON-RPC error response parsing
        let input = b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":1}\n";

        let reader = Cursor::new(input.to_vec());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);
        let cx = Cx::for_testing();

        let msg = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg, JsonRpcMessage::Response(_)),
            "Expected response"
        );
        let JsonRpcMessage::Response(resp) = msg else {
            return;
        };
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        let error = resp.error.unwrap();
        assert_eq!(error.code, -32601);
        assert_eq!(error.message, "Method not found");
    }

    #[test]
    fn e2e_ndjson_malformed_json_error() {
        // Test handling of malformed JSON
        let input = b"{invalid json\n";

        let reader = Cursor::new(input.to_vec());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);
        let cx = Cx::for_testing();

        let result = transport.recv(&cx);
        assert!(matches!(result, Err(TransportError::Codec(_))));
    }

    #[test]
    fn e2e_ndjson_bidirectional_flow() {
        // Test bidirectional communication (simulated)
        let input = b"{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[]},\"id\":1}\n";
        let reader = Cursor::new(input.to_vec());
        let mut output = Vec::new();

        // Create transport with a writable output buffer
        {
            let mut transport = StdioTransport::new(reader, &mut output);
            let cx = Cx::for_testing();

            // Send a request
            let request = JsonRpcRequest::new("tools/list", None, 1i64);
            transport.send_request_direct(&cx, &request).unwrap();

            // Receive response
            let msg = transport.recv(&cx).unwrap();
            assert!(matches!(msg, JsonRpcMessage::Response(_)));
        }

        // Verify the sent message is valid NDJSON
        let sent = String::from_utf8(output).unwrap();
        assert!(sent.ends_with('\n'));
        assert!(sent.contains("\"method\":\"tools/list\""));
        assert!(sent.contains("\"jsonrpc\":\"2.0\""));
    }

    #[test]
    fn e2e_ndjson_response_with_complex_result() {
        // Test response with complex nested result
        let input = b"{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[{\"name\":\"tool1\",\"description\":\"A test tool\",\"inputSchema\":{\"type\":\"object\"}}]},\"id\":1}\n";

        let reader = Cursor::new(input.to_vec());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);
        let cx = Cx::for_testing();

        let msg = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg, JsonRpcMessage::Response(_)),
            "Expected response"
        );
        let JsonRpcMessage::Response(resp) = msg else {
            return;
        };
        let result = resp.result.unwrap();
        let tools = result.get("tools").unwrap().as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].get("name").unwrap(), "tool1");
    }

    #[test]
    fn e2e_two_phase_send_multiple_messages() {
        // Test multiple two-phase sends in sequence
        let reader = Cursor::new(Vec::new());
        let mut output = Vec::new();

        {
            let mut transport = StdioTransport::new(reader, &mut output);
            let cx = Cx::for_testing();

            // Send multiple messages using two-phase pattern
            for i in 1..=5 {
                let permit = transport.reserve_send(&cx).unwrap();
                let request = JsonRpcRequest::new(format!("method_{i}"), None, i as i64);
                permit.send_request(&request).unwrap();
            }
        }

        // Verify all messages were sent as valid NDJSON
        let sent = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = sent.lines().collect();
        assert_eq!(lines.len(), 5);

        for (i, line) in lines.iter().enumerate() {
            let expected_method = format!("method_{}", i + 1);
            assert!(line.contains(&expected_method));
        }
    }

    #[test]
    fn e2e_transport_close_flushes() {
        let reader = Cursor::new(Vec::new());
        let mut output = Vec::new();

        {
            let mut transport = StdioTransport::new(reader, &mut output);
            let cx = Cx::for_testing();

            // Send a message
            let request = JsonRpcRequest::new("test", None, 1i64);
            transport.send_request_direct(&cx, &request).unwrap();

            // Close should flush
            transport.close().unwrap();
        }

        // Verify data was flushed
        let sent = String::from_utf8(output).unwrap();
        assert!(!sent.is_empty());
        assert!(sent.contains("\"method\":\"test\""));
    }

    #[test]
    fn close_drops_writer_and_is_terminal_and_idempotent() {
        let dropped = Arc::new(AtomicBool::new(false));
        let writer = DropAwareWriter {
            dropped: Arc::clone(&dropped),
            fail_flush: false,
            bytes: Vec::new(),
        };
        let mut transport = StdioTransport::new(Cursor::new(Vec::new()), writer);

        transport.close().unwrap();

        assert!(dropped.load(Ordering::SeqCst));
        transport.close().unwrap();

        let cx = Cx::for_testing();
        let request = JsonRpcRequest::new("test", None, 1_i64);
        assert!(matches!(
            transport.send(&cx, &JsonRpcMessage::Request(request.clone())),
            Err(TransportError::Closed)
        ));
        assert!(matches!(
            transport.send_request_direct(&cx, &request),
            Err(TransportError::Closed)
        ));
        assert!(matches!(
            transport.reserve_send(&cx),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn close_drops_writer_even_when_flush_fails() {
        let dropped = Arc::new(AtomicBool::new(false));
        let writer = DropAwareWriter {
            dropped: Arc::clone(&dropped),
            fail_flush: true,
            bytes: Vec::new(),
        };
        let mut transport = StdioTransport::new(Cursor::new(Vec::new()), writer);

        assert!(matches!(transport.close(), Err(TransportError::Io(_))));
        assert!(dropped.load(Ordering::SeqCst));
        assert!(transport.close().is_ok());
    }

    #[test]
    fn async_stdio_bounded_read_failures_latch_closed() {
        let active_cx = Cx::for_testing();
        let mut oversized = AsyncStdioTransport::new();
        assert!(matches!(
            oversized.latch_read_error(&active_cx, BoundedLineReadError::TooLarge(42)),
            TransportError::Codec(CodecError::MessageTooLarge(42))
        ));
        assert!(oversized.closed);

        let cancelled_cx = Cx::for_testing();
        cancelled_cx.set_cancel_requested(true);
        let mut cancelled = AsyncStdioTransport::new();
        assert!(matches!(
            cancelled.latch_read_error(
                &cancelled_cx,
                BoundedLineReadError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled after a partial read",
                )),
            ),
            TransportError::Cancelled
        ));
        assert!(cancelled.closed);

        let deadline_cx = Cx::for_testing_with_budget(
            asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
        );
        let mut timed_out = AsyncStdioTransport::new();
        assert!(matches!(
            timed_out.latch_read_error(
                &deadline_cx,
                BoundedLineReadError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "deadline after a partial read",
                )),
            ),
            TransportError::Timeout
        ));
        assert!(timed_out.closed);
    }

    // =========================================================================
    // Additional coverage tests (bd-19vz)
    // =========================================================================

    #[test]
    fn send_response_direct_writes_valid_ndjson() {
        let reader = Cursor::new(Vec::new());
        let mut output = Vec::new();

        {
            let mut transport = StdioTransport::new(reader, &mut output);
            let cx = Cx::for_testing();

            let response = JsonRpcResponse {
                jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
                result: Some(serde_json::json!({"ok": true})),
                error: None,
                id: Some(fastmcp_protocol::RequestId::Number(42)),
            };
            transport.send_response_direct(&cx, &response).unwrap();
        }

        let sent = String::from_utf8(output).unwrap();
        assert!(sent.ends_with('\n'));
        assert!(sent.contains("\"result\""));
        assert!(sent.contains("\"ok\":true") || sent.contains("\"ok\": true"));
    }

    #[test]
    fn send_response_direct_cancelled() {
        let reader = Cursor::new(Vec::new());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let response = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            result: Some(serde_json::json!(null)),
            error: None,
            id: Some(fastmcp_protocol::RequestId::Number(1)),
        };
        let result = transport.send_response_direct(&cx, &response);
        assert!(matches!(result, Err(TransportError::Cancelled)));
    }

    #[test]
    fn transport_send_trait_method_with_response() {
        let reader = Cursor::new(Vec::new());
        let mut output = Vec::new();

        {
            let mut transport = StdioTransport::new(reader, &mut output);
            let cx = Cx::for_testing();

            let response = JsonRpcResponse {
                jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
                result: Some(serde_json::json!({"status": "done"})),
                error: None,
                id: Some(fastmcp_protocol::RequestId::Number(1)),
            };
            transport
                .send(&cx, &JsonRpcMessage::Response(response))
                .unwrap();
        }

        let sent = String::from_utf8(output).unwrap();
        assert!(sent.contains("\"status\""));
    }

    #[test]
    fn transport_send_trait_cancelled() {
        let reader = Cursor::new(Vec::new());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let request = JsonRpcRequest::new("test", None, 1i64);
        let result = transport.send(&cx, &JsonRpcMessage::Request(request));
        assert!(matches!(result, Err(TransportError::Cancelled)));
    }

    #[test]
    fn two_phase_send_response_via_permit() {
        let reader = Cursor::new(Vec::new());
        let mut output = Vec::new();

        {
            let mut transport = StdioTransport::new(reader, &mut output);
            let cx = Cx::for_testing();

            let permit = transport.reserve_send(&cx).unwrap();
            let response = JsonRpcResponse {
                jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
                result: Some(serde_json::json!({"v": 1})),
                error: None,
                id: Some(fastmcp_protocol::RequestId::Number(1)),
            };
            permit.send_response(&response).unwrap();
        }

        let sent = String::from_utf8(output).unwrap();
        assert!(sent.contains("\"result\""));
    }

    #[test]
    fn recv_handles_crlf_line_endings() {
        // Windows-style CRLF should be handled correctly
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"test\",\"id\":1}\r\n";
        let reader = Cursor::new(input.to_vec());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);
        let cx = Cx::for_testing();

        let msg = transport.recv(&cx).unwrap();
        if let JsonRpcMessage::Request(req) = msg {
            assert_eq!(req.method, "test");
        } else {
            panic!("Expected request");
        }
    }
}
