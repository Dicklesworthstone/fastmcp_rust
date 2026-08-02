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

use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::time::{Duration, Instant};

use asupersync::Cx;
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};
#[cfg(unix)]
use rustix::event::{PollFd, PollFlags, Timespec, poll};

use crate::async_io::{AsyncLineReader, AsyncStdout, BoundedLineReadError};
use crate::{Codec, CodecError, SendPermit, Transport, TransportError, TwoPhaseTransport};

#[cfg(unix)]
const STDIO_READINESS_POLL_SLICE: Duration = Duration::from_millis(10);

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
    ) -> Result<JsonRpcMessage, TransportError>
    where
        F: FnMut(&BufReader<R>, &Cx) -> Result<(), TransportError>,
    {
        if self.closed {
            return Err(TransportError::Closed);
        }

        loop {
            let frame_len = match self.read_line_with_readiness(cx, &mut wait_for_readiness) {
                Ok(frame_len) => frame_len,
                Err(error @ TransportError::Closed)
                | Err(error @ TransportError::Codec(CodecError::MessageTooLarge(_))) => {
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
            if let Err(error) = stdio_checkpoint(cx) {
                return Err(self.latch_consumed_read_failure(error));
            }
            return Ok(message);
        }
    }
}

#[cfg(unix)]
fn wait_for_unix_readiness<R: AsFd>(
    reader: &BufReader<R>,
    cx: &Cx,
    deadline: Option<Instant>,
) -> Result<(), TransportError> {
    loop {
        let remaining = match deadline {
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(TransportError::Timeout);
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
            Ok(0) => stdio_checkpoint(cx)?,
            Ok(_) => return Ok(()),
            Err(rustix::io::Errno::INTR) => stdio_checkpoint(cx)?,
            Err(error) => return Err(TransportError::Io(error.into())),
        }
    }
}

#[cfg(unix)]
impl<R: Read + AsFd, W: Write> StdioTransport<R, W> {
    /// Receives one frame while bounding every potentially blocking pipe read.
    ///
    /// Readiness is polled in short slices before each empty-`BufReader` fill,
    /// so cancellation, context budgets, and `deadline` remain observable even
    /// when a peer is silent or stops midway through an NDJSON frame. A final
    /// checkpoint and deadline check run after complete frame decoding. Failure
    /// there is terminal because the frame has already been consumed. This
    /// Unix-specific API is used for child-process pipes; generic
    /// [`Transport::recv`] retains its ordinary blocking `Read` contract.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Timeout`] at the explicit deadline or a context
    /// deadline, [`TransportError::Cancelled`] for explicit cancellation or
    /// quota exhaustion, or the same I/O, closure, and codec errors as
    /// [`Transport::recv`].
    pub fn recv_until(
        &mut self,
        cx: &Cx,
        deadline: Option<Instant>,
    ) -> Result<JsonRpcMessage, TransportError> {
        let message = self.recv_with_readiness(cx, |reader, cx| {
            wait_for_unix_readiness(reader, cx, deadline)
        })?;

        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(self.latch_consumed_read_failure(TransportError::Timeout));
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
        self.recv_with_readiness(cx, |_, _| Ok(()))
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
    use std::io::Cursor;
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    #[cfg(unix)]
    use std::time::{Duration, Instant};

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
            Err(TransportError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!transport.closed);
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
            Err(TransportError::Timeout)
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
            Err(TransportError::Timeout)
        ));
        assert!(transport.closed);
        assert!(transport.line_buffer.is_empty());
        assert!(matches!(
            transport.recv_until(&Cx::for_testing(), None),
            Err(TransportError::Closed)
        ));
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
