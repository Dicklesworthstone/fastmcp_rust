//! Standard I/O transport for MCP.
//!
//! This is the primary transport for MCP servers running as subprocess.
//! Uses newline-delimited JSON (NDJSON) framing.
//!
//! # Cancel-Safety
//!
//! The stdio transport integrates with asupersync's capability context:
//! - Checks `cx.is_cancel_requested()` before blocking operations
//! - Uses async I/O wrappers that integrate with cancellation
//! - Properly handles EOF as transport closure
//!
//! # Async I/O Integration
//!
//! This module provides two transport implementations:
//!
//! - [`StdioTransport`]: Generic transport for any `Read`/`Write` types (for testing)
//! - [`AsyncStdioTransport`]: Production transport using async I/O wrappers
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

use asupersync::{Budget, Cx};
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};

use crate::async_io::{AsyncLineReader, AsyncStdout};
use crate::{Codec, CodecError, SendPermit, Transport, TransportError, TwoPhaseTransport};

/// Stdio transport implementation.
///
/// Reads from stdin and writes to stdout using NDJSON framing.
/// Integrates with asupersync for cancel-correct operation.
///
/// # Wire Format
///
/// Messages are newline-delimited JSON:
/// - Each message is serialized as a single line of JSON
/// - Lines are terminated by `\n` (LF, not CRLF)
/// - Empty lines are ignored
/// - UTF-8 encoding is required
pub struct StdioTransport<R, W> {
    reader: BufReader<R>,
    writer: W,
    codec: Codec,
    line_buffer: String,
}

impl<R: Read, W: Write> StdioTransport<R, W> {
    /// Creates a new stdio transport with custom reader/writer.
    ///
    /// This is useful for testing with mock I/O.
    #[must_use]
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            codec: Codec::new(),
            line_buffer: String::with_capacity(4096),
        }
    }

    /// Encodes and sends a message, appending newline.
    fn write_message(&mut self, message: &JsonRpcMessage) -> Result<(), TransportError> {
        let bytes = match message {
            JsonRpcMessage::Request(req) => self.codec.encode_request(req)?,
            JsonRpcMessage::Response(resp) => self.codec.encode_response(resp)?,
        };
        self.writer.write_all(&bytes)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Reads a line from the reader, handling EOF.
    fn read_line(&mut self) -> Result<&str, TransportError> {
        self.line_buffer.clear();
        let bytes_read = self.reader.read_line(&mut self.line_buffer)?;

        if bytes_read == 0 {
            return Err(TransportError::Closed);
        }

        // Trim trailing newline
        let line_len = {
            let line = self
                .line_buffer
                .trim_end_matches('\n')
                .trim_end_matches('\r');
            line.len()
        };
        if line_len > self.codec.max_message_size() {
            self.line_buffer.clear();
            return Err(TransportError::Codec(CodecError::MessageTooLarge(line_len)));
        }
        let line = self
            .line_buffer
            .trim_end_matches('\n')
            .trim_end_matches('\r');
        Ok(line)
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
        // Check for cancellation before I/O
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        self.write_message(message)
    }

    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        // Check for cancellation before blocking read
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        // Read lines until we get a non-empty one
        loop {
            let line = self.read_line()?;

            // Skip empty lines
            if line.is_empty() {
                // Check cancellation between reads
                if cx.is_cancel_requested() {
                    return Err(TransportError::Cancelled);
                }
                continue;
            }

            // Parse the JSON message
            let message: JsonRpcMessage = serde_json::from_str(line)
                .map_err(|e| TransportError::Codec(crate::CodecError::Json(e)))?;

            return Ok(message);
        }
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.writer.flush()?;
        Ok(())
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
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }
        let bytes = self.codec.encode_request(request)?;
        self.writer.write_all(&bytes)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Send a response directly (avoids clone in trait method).
    pub fn send_response_direct(
        &mut self,
        cx: &Cx,
        response: &JsonRpcResponse,
    ) -> Result<(), TransportError> {
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }
        let bytes = self.codec.encode_response(response)?;
        self.writer.write_all(&bytes)?;
        self.writer.flush()?;
        Ok(())
    }
}

impl<R: Read, W: Write> TwoPhaseTransport for StdioTransport<R, W> {
    type Writer = W;

    fn reserve_send(&mut self, cx: &Cx) -> Result<SendPermit<'_, Self::Writer>, TransportError> {
        // Check cancellation - this is the cancellation point
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        // Return permit that allows the send to proceed
        Ok(SendPermit::new(&mut self.writer, &self.codec))
    }
}

// =============================================================================
// AsyncStdioTransport - Production async I/O transport
// =============================================================================

/// Async stdio transport with integrated cancellation support.
///
/// This is the production transport for MCP servers. It uses async I/O
/// wrappers that integrate with asupersync's capability context for
/// proper cancellation handling.
///
/// # Cancel-Safety
///
/// - Checks `cx.is_cancel_requested()` before and during blocking I/O
/// - Returns `TransportError::Cancelled` when cancellation is detected
/// - Integrates with asupersync's structured concurrency model
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
        }
    }
}

impl Default for AsyncStdioTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for AsyncStdioTransport {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        // Check for cancellation before I/O
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        let bytes = match message {
            JsonRpcMessage::Request(req) => self.codec.encode_request(req)?,
            JsonRpcMessage::Response(resp) => self.codec.encode_response(resp)?,
        };

        // Use async-aware write with cancellation checking
        self.writer.write_all_sync(cx, &bytes).map_err(|e| {
            if e.kind() == std::io::ErrorKind::Interrupted {
                TransportError::Cancelled
            } else {
                TransportError::Io(e)
            }
        })?;

        self.writer.flush_sync(cx).map_err(|e| {
            if e.kind() == std::io::ErrorKind::Interrupted {
                TransportError::Cancelled
            } else {
                TransportError::Io(e)
            }
        })?;

        Ok(())
    }

    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        // Check for cancellation before blocking read
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        // Read non-empty line with cancellation checking
        let line = self
            .reader
            .read_non_empty_line(cx)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    TransportError::Cancelled
                } else {
                    TransportError::Io(e)
                }
            })?
            .ok_or(TransportError::Closed)?;

        if line.len() > self.codec.max_message_size() {
            return Err(TransportError::Codec(CodecError::MessageTooLarge(
                line.len(),
            )));
        }

        // Parse the JSON message
        let message: JsonRpcMessage = serde_json::from_str(&line)
            .map_err(|e| TransportError::Codec(crate::CodecError::Json(e)))?;

        Ok(message)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        // Use an infinite budget context for close - ensures flush completes
        // without cancellation (close should always complete)
        let cx = Cx::for_request_with_budget(Budget::INFINITE);
        self.writer.flush_sync(&cx)?;
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
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        let bytes = self.codec.encode_request(request)?;

        self.writer.write_all_sync(cx, &bytes).map_err(|e| {
            if e.kind() == std::io::ErrorKind::Interrupted {
                TransportError::Cancelled
            } else {
                TransportError::Io(e)
            }
        })?;

        self.writer.flush_sync(cx).map_err(|e| {
            if e.kind() == std::io::ErrorKind::Interrupted {
                TransportError::Cancelled
            } else {
                TransportError::Io(e)
            }
        })
    }

    /// Send a response directly (avoids clone in trait method).
    pub fn send_response_direct(
        &mut self,
        cx: &Cx,
        response: &JsonRpcResponse,
    ) -> Result<(), TransportError> {
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        let bytes = self.codec.encode_response(response)?;

        self.writer.write_all_sync(cx, &bytes).map_err(|e| {
            if e.kind() == std::io::ErrorKind::Interrupted {
                TransportError::Cancelled
            } else {
                TransportError::Io(e)
            }
        })?;

        self.writer.flush_sync(cx).map_err(|e| {
            if e.kind() == std::io::ErrorKind::Interrupted {
                TransportError::Cancelled
            } else {
                TransportError::Io(e)
            }
        })
    }
}

impl TwoPhaseTransport for AsyncStdioTransport {
    type Writer = AsyncStdout;

    fn reserve_send(&mut self, cx: &Cx) -> Result<SendPermit<'_, Self::Writer>, TransportError> {
        // Check cancellation - this is the cancellation point
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        // Return permit that allows the send to proceed
        // The commit phase uses Write trait impl which bypasses cancellation checks
        Ok(SendPermit::new(&mut self.writer, &self.codec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
        match msg1 {
            JsonRpcMessage::Request(req) => assert_eq!(req.method, "init"),
            _ => panic!("Expected request"),
        }

        // Receive second message
        let msg2 = transport.recv(&cx).unwrap();
        match msg2 {
            JsonRpcMessage::Request(req) => assert_eq!(req.method, "tools/list"),
            _ => panic!("Expected request"),
        }

        // Receive third message
        let msg3 = transport.recv(&cx).unwrap();
        match msg3 {
            JsonRpcMessage::Request(req) => {
                assert_eq!(req.method, "tools/call");
                assert!(req.params.is_some());
            }
            _ => panic!("Expected request"),
        }

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
        match msg {
            JsonRpcMessage::Response(resp) => {
                assert!(resp.result.is_some());
                assert!(resp.error.is_none());
            }
            _ => panic!("Expected response"),
        }
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
        match msg1 {
            JsonRpcMessage::Request(req) => assert_eq!(req.method, "test1"),
            _ => panic!("Expected request"),
        }

        let msg2 = transport.recv(&cx).unwrap();
        match msg2 {
            JsonRpcMessage::Request(req) => assert_eq!(req.method, "test2"),
            _ => panic!("Expected request"),
        }
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
        match msg {
            JsonRpcMessage::Request(req) => {
                assert_eq!(req.method, "test");
                let params = req.params.as_ref().unwrap();
                let message = params.get("message").unwrap().as_str().unwrap();
                // Contains: éèê中文👋
                assert!(message.contains("é"));
                assert!(message.contains("中"));
                assert!(message.contains("👋"));
            }
            _ => panic!("Expected request"),
        }
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
        match msg {
            JsonRpcMessage::Request(req) => {
                assert_eq!(req.method, "test");
                let params = req.params.as_ref().unwrap();
                let data = params.get("data").unwrap().as_str().unwrap();
                assert_eq!(data.len(), 100_000);
            }
            _ => panic!("Expected request"),
        }
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
        match msg {
            JsonRpcMessage::Request(req) => {
                assert_eq!(req.method, "notifications/initialized");
                assert!(req.id.is_none());
            }
            _ => panic!("Expected request/notification"),
        }
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
        match msg {
            JsonRpcMessage::Response(resp) => {
                assert!(resp.result.is_none());
                assert!(resp.error.is_some());
                let error = resp.error.unwrap();
                assert_eq!(error.code, -32601);
                assert_eq!(error.message, "Method not found");
            }
            _ => panic!("Expected response"),
        }
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

        // Create transport with a writeable output buffer
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
        match msg {
            JsonRpcMessage::Response(resp) => {
                let result = resp.result.unwrap();
                let tools = result.get("tools").unwrap().as_array().unwrap();
                assert_eq!(tools.len(), 1);
                assert_eq!(tools[0].get("name").unwrap(), "tool1");
            }
            _ => panic!("Expected response"),
        }
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
}
