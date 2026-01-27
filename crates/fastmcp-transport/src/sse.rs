//! Server-Sent Events (SSE) transport for MCP.
//!
//! SSE provides a unidirectional event stream from server to client, with
//! client-to-server communication handled via HTTP POST requests.
//!
//! # MCP SSE Protocol
//!
//! The MCP SSE transport works as follows:
//!
//! 1. **Client connects** to the server's SSE endpoint
//! 2. **Server sends `endpoint` event** containing the POST URL for client messages
//! 3. **Client sends requests** via HTTP POST to the endpoint URL
//! 4. **Server sends responses** as `message` events on the SSE stream
//!
//! # Wire Format
//!
//! SSE events follow the standard format:
//! ```text
//! event: <event-type>
//! data: <JSON payload>
//!
//! ```
//!
//! Event types:
//! - `endpoint`: Contains the URL for client POST requests
//! - `message`: Contains a JSON-RPC message (request or response)
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_transport::sse::{SseEvent, SseEventType, SseWriter};
//! use fastmcp_protocol::JsonRpcResponse;
//!
//! // Create an SSE writer for the response stream
//! let mut writer = SseWriter::new(response_body);
//!
//! // Send the endpoint event first
//! writer.write_endpoint("http://localhost:8080/mcp/messages")?;
//!
//! // Send JSON-RPC responses as message events
//! let response = JsonRpcResponse { /* ... */ };
//! writer.write_response(&response)?;
//! ```
//!
//! # Cancel-Safety
//!
//! This module integrates with asupersync's capability context:
//! - Writers check `cx.is_cancel_requested()` before I/O operations
//! - Readers properly handle partial event data
//! - All operations respect budget constraints
//!
//! # Integration Note
//!
//! This module provides SSE event handling but does NOT include an HTTP server.
//! You'll need to integrate with an HTTP server framework that works with
//! asupersync (or use the provided adapters if available).

use std::io::{BufRead, BufReader, Read, Write};

use asupersync::Cx;
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};

use crate::{Codec, CodecError, Transport, TransportError};

// =============================================================================
// SSE Event Types
// =============================================================================

/// SSE event types used by MCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseEventType {
    /// The `endpoint` event sent by the server to indicate the POST URL.
    Endpoint,
    /// The `message` event containing a JSON-RPC message.
    Message,
}

impl SseEventType {
    /// Returns the event type string for SSE format.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            SseEventType::Endpoint => "endpoint",
            SseEventType::Message => "message",
        }
    }

    /// Parse an event type from a string.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "endpoint" => Some(SseEventType::Endpoint),
            "message" => Some(SseEventType::Message),
            _ => None,
        }
    }
}

/// A parsed SSE event.
#[derive(Debug, Clone)]
pub struct SseEvent {
    /// The event type.
    pub event_type: SseEventType,
    /// The event data (JSON string for messages, URL for endpoint).
    pub data: String,
    /// Optional event ID for reconnection.
    pub id: Option<String>,
    /// Optional retry interval in milliseconds.
    pub retry: Option<u64>,
}

impl SseEvent {
    /// Creates a new endpoint event with the given POST URL.
    #[must_use]
    pub fn endpoint(url: impl Into<String>) -> Self {
        Self {
            event_type: SseEventType::Endpoint,
            data: url.into(),
            id: None,
            retry: None,
        }
    }

    /// Creates a new message event with the given JSON data.
    #[must_use]
    pub fn message(data: impl Into<String>) -> Self {
        Self {
            event_type: SseEventType::Message,
            data: data.into(),
            id: None,
            retry: None,
        }
    }

    /// Sets the event ID.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Sets the retry interval.
    #[must_use]
    pub fn with_retry(mut self, retry_ms: u64) -> Self {
        self.retry = Some(retry_ms);
        self
    }

    /// Serialize the event to SSE format.
    ///
    /// # Returns
    ///
    /// The SSE-formatted event as bytes, including the trailing blank line.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.data.len() + 64);

        // Event type
        output.extend_from_slice(b"event: ");
        output.extend_from_slice(self.event_type.as_str().as_bytes());
        output.push(b'\n');

        // Optional ID
        if let Some(ref id) = self.id {
            output.extend_from_slice(b"id: ");
            output.extend_from_slice(id.as_bytes());
            output.push(b'\n');
        }

        // Optional retry
        if let Some(retry) = self.retry {
            output.extend_from_slice(b"retry: ");
            output.extend_from_slice(retry.to_string().as_bytes());
            output.push(b'\n');
        }

        // Data (handle multi-line data by prefixing each line with "data: ")
        for line in self.data.lines() {
            output.extend_from_slice(b"data: ");
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        }

        // If data doesn't have lines (empty), still send one data line
        if self.data.is_empty() {
            output.extend_from_slice(b"data: \n");
        }

        // Blank line to terminate the event
        output.push(b'\n');

        output
    }
}

// =============================================================================
// SSE Writer
// =============================================================================

/// Writer for SSE event streams.
///
/// This writes properly formatted SSE events to any `Write` implementation.
/// It handles JSON-RPC message serialization and event formatting.
///
/// # Example
///
/// ```ignore
/// let mut writer = SseWriter::new(tcp_stream);
///
/// // Send endpoint event
/// writer.write_endpoint("http://localhost:8080/messages")?;
///
/// // Send a response
/// writer.write_message(&JsonRpcMessage::Response(response))?;
/// ```
pub struct SseWriter<W> {
    writer: W,
    codec: Codec,
    event_counter: u64,
}

impl<W: Write> SseWriter<W> {
    /// Creates a new SSE writer.
    #[must_use]
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            codec: Codec::new(),
            event_counter: 0,
        }
    }

    /// Writes an SSE event.
    ///
    /// # Cancel-Safety
    ///
    /// Checks for cancellation before writing.
    pub fn write_event(&mut self, cx: &Cx, event: &SseEvent) -> Result<(), TransportError> {
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        let bytes = event.to_bytes();
        self.writer.write_all(&bytes)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Writes the endpoint event with the POST URL.
    ///
    /// This should be the first event sent when a client connects.
    pub fn write_endpoint(&mut self, cx: &Cx, url: &str) -> Result<(), TransportError> {
        let event = SseEvent::endpoint(url);
        self.write_event(cx, &event)
    }

    /// Writes a JSON-RPC message as an SSE message event.
    pub fn write_message(
        &mut self,
        cx: &Cx,
        message: &JsonRpcMessage,
    ) -> Result<(), TransportError> {
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        let json = match message {
            JsonRpcMessage::Request(req) => {
                // Encode without newline (SSE adds its own framing)
                serde_json::to_string(req).map_err(CodecError::Json)?
            }
            JsonRpcMessage::Response(resp) => {
                serde_json::to_string(resp).map_err(CodecError::Json)?
            }
        };

        self.event_counter += 1;
        let event = SseEvent::message(json).with_id(self.event_counter.to_string());
        self.write_event(cx, &event)
    }

    /// Writes a JSON-RPC response as an SSE message event.
    pub fn write_response(
        &mut self,
        cx: &Cx,
        response: &JsonRpcResponse,
    ) -> Result<(), TransportError> {
        self.write_message(cx, &JsonRpcMessage::Response(response.clone()))
    }

    /// Writes a JSON-RPC request as an SSE message event.
    ///
    /// Note: In typical MCP SSE usage, the server sends responses and the
    /// client sends requests via POST. This method is provided for flexibility.
    pub fn write_request(
        &mut self,
        cx: &Cx,
        request: &JsonRpcRequest,
    ) -> Result<(), TransportError> {
        self.write_message(cx, &JsonRpcMessage::Request(request.clone()))
    }

    /// Sends a comment (for keep-alive).
    ///
    /// SSE comments start with `:` and are ignored by the client.
    /// They're useful for keeping connections alive.
    pub fn write_comment(&mut self, cx: &Cx, comment: &str) -> Result<(), TransportError> {
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        // Comments are lines starting with ':'
        self.writer.write_all(b": ")?;
        self.writer.write_all(comment.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }

    /// Sends a keep-alive comment.
    pub fn keep_alive(&mut self, cx: &Cx) -> Result<(), TransportError> {
        self.write_comment(cx, "keep-alive")
    }

    /// Returns a reference to the underlying writer.
    pub fn inner(&self) -> &W {
        &self.writer
    }

    /// Returns a mutable reference to the underlying writer.
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Consumes the writer and returns the underlying writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

// =============================================================================
// SSE Reader
// =============================================================================

/// Maximum line size for SSE events (64KB should be generous for JSON-RPC).
const MAX_SSE_LINE_SIZE: usize = 64 * 1024;

/// Reader for SSE event streams.
///
/// Parses SSE events from any `Read` implementation.
///
/// # Example
///
/// ```ignore
/// let mut reader = SseReader::new(tcp_stream);
///
/// loop {
///     match reader.read_event(&cx)? {
///         Some(event) => handle_event(event),
///         None => break, // EOF
///     }
/// }
/// ```
pub struct SseReader<R> {
    reader: BufReader<R>,
    line_buffer: String,
    /// Maximum line size to prevent memory exhaustion.
    max_line_size: usize,
}

impl<R: Read> SseReader<R> {
    /// Creates a new SSE reader.
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            line_buffer: String::with_capacity(4096),
            max_line_size: MAX_SSE_LINE_SIZE,
        }
    }

    /// Reads a line with size limit to prevent memory exhaustion.
    ///
    /// Returns the number of bytes read, or an error if the line exceeds
    /// the maximum size.
    fn read_line_bounded(&mut self) -> Result<usize, std::io::Error> {
        use std::io::BufRead;

        let mut total_read = 0;
        loop {
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                // EOF
                return Ok(total_read);
            }

            // Find newline in available buffer
            let newline_pos = available.iter().position(|&b| b == b'\n');
            let bytes_to_consume = match newline_pos {
                Some(pos) => pos + 1, // Include the newline
                None => available.len(),
            };

            // Check if this would exceed our limit
            if self.line_buffer.len() + bytes_to_consume > self.max_line_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "SSE line exceeds maximum size of {} bytes",
                        self.max_line_size
                    ),
                ));
            }

            // Convert bytes to string and append
            let chunk = &available[..bytes_to_consume];
            let chunk_str = std::str::from_utf8(chunk).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid UTF-8: {e}"))
            })?;
            self.line_buffer.push_str(chunk_str);
            total_read += bytes_to_consume;

            self.reader.consume(bytes_to_consume);

            if newline_pos.is_some() {
                // Found newline, done with this line
                return Ok(total_read);
            }
        }
    }

    /// Reads the next SSE event.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(event))`: An event was successfully read
    /// - `Ok(None)`: EOF reached
    /// - `Err(_)`: An error occurred
    ///
    /// # Cancel-Safety
    ///
    /// Checks for cancellation between reads.
    pub fn read_event(&mut self, cx: &Cx) -> Result<Option<SseEvent>, TransportError> {
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        let mut event_type: Option<SseEventType> = None;
        let mut unknown_event = false;
        let mut data_lines: Vec<String> = Vec::new();
        let mut total_data_size: usize = 0;
        let mut event_id: Option<String> = None;
        let mut retry: Option<u64> = None;

        // Maximum total event data size (1MB should be generous)
        const MAX_EVENT_DATA_SIZE: usize = 1024 * 1024;

        loop {
            self.line_buffer.clear();
            let bytes_read = self.read_line_bounded()?;

            if bytes_read == 0 {
                // EOF
                return Ok(None);
            }

            // Check cancellation between lines
            if cx.is_cancel_requested() {
                return Err(TransportError::Cancelled);
            }

            let line = self
                .line_buffer
                .trim_end_matches(|c| c == '\n' || c == '\r');

            // Empty line = end of event
            if line.is_empty() {
                if unknown_event {
                    event_type = None;
                    data_lines.clear();
                    total_data_size = 0;
                    event_id = None;
                    retry = None;
                    unknown_event = false;
                    continue;
                }
                if event_type.is_some() || !data_lines.is_empty() {
                    // We have an event to return
                    let data = data_lines.join("\n");
                    return Ok(Some(SseEvent {
                        event_type: event_type.unwrap_or(SseEventType::Message),
                        data,
                        id: event_id,
                        retry,
                    }));
                }
                // Empty event, continue reading
                continue;
            }

            // Comment line (starts with ':')
            if line.starts_with(':') {
                continue;
            }

            // Parse field: value
            if let Some((field, value)) = line.split_once(':') {
                // SSE spec: if value starts with space, trim one space
                let value = value.strip_prefix(' ').unwrap_or(value);

                match field {
                    "event" => {
                        if let Some(parsed) = SseEventType::from_str(value) {
                            event_type = Some(parsed);
                            unknown_event = false;
                        } else {
                            event_type = None;
                            unknown_event = true;
                        }
                    }
                    "data" => {
                        // Check accumulated data size to prevent memory exhaustion
                        total_data_size = total_data_size.saturating_add(value.len() + 1); // +1 for newline
                        if total_data_size > MAX_EVENT_DATA_SIZE {
                            return Err(TransportError::Io(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!(
                                    "SSE event data exceeds maximum size of {} bytes",
                                    MAX_EVENT_DATA_SIZE
                                ),
                            )));
                        }
                        data_lines.push(value.to_string());
                    }
                    "id" => {
                        event_id = Some(value.to_string());
                    }
                    "retry" => {
                        retry = value.parse().ok();
                    }
                    _ => {
                        // Unknown field, ignore per SSE spec
                    }
                }
            }
        }
    }

    /// Reads the next message event and parses it as a JSON-RPC message.
    ///
    /// Skips non-message events (like endpoint events).
    ///
    /// # Returns
    ///
    /// - `Ok(Some(message))`: A message was successfully read
    /// - `Ok(None)`: EOF reached
    /// - `Err(_)`: An error occurred
    pub fn read_message(&mut self, cx: &Cx) -> Result<Option<JsonRpcMessage>, TransportError> {
        loop {
            match self.read_event(cx)? {
                Some(event) => {
                    if event.event_type == SseEventType::Message {
                        let message: JsonRpcMessage = serde_json::from_str(&event.data)
                            .map_err(|e| TransportError::Codec(CodecError::Json(e)))?;
                        return Ok(Some(message));
                    }
                    // Skip non-message events
                    continue;
                }
                None => return Ok(None),
            }
        }
    }

    /// Reads the endpoint event and returns the POST URL.
    ///
    /// This should be called once when the SSE connection is established.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(url))`: The endpoint URL
    /// - `Ok(None)`: EOF reached before endpoint event
    /// - `Err(_)`: An error occurred
    pub fn read_endpoint(&mut self, cx: &Cx) -> Result<Option<String>, TransportError> {
        loop {
            match self.read_event(cx)? {
                Some(event) => {
                    if event.event_type == SseEventType::Endpoint {
                        return Ok(Some(event.data));
                    }
                    // Skip non-endpoint events (shouldn't happen at start)
                    continue;
                }
                None => return Ok(None),
            }
        }
    }

    /// Returns a reference to the underlying reader.
    pub fn inner(&self) -> &BufReader<R> {
        &self.reader
    }
}

// =============================================================================
// SSE Transport (Server-Side)
// =============================================================================

/// Server-side SSE transport.
///
/// This transport is designed for the server side of an MCP SSE connection:
/// - Receives requests from an HTTP POST handler (via `inject_request`)
/// - Sends responses via the SSE event stream
///
/// # Architecture
///
/// The SSE transport is split because of the protocol's nature:
/// - The SSE stream (this transport's writer) is one-way to the client
/// - Client requests come in via separate HTTP POST requests
///
/// A typical integration looks like:
///
/// ```ignore
/// // HTTP handler for SSE connection
/// fn sse_handler(req: Request) -> Response {
///     let (tx, rx) = channel();
///     let transport = SseServerTransport::new(response_writer, rx);
///
///     // Run the MCP server with this transport
///     server.run(transport);
/// }
///
/// // HTTP handler for POST requests
/// fn post_handler(req: Request) {
///     let message: JsonRpcRequest = parse_body(&req);
///     tx.send(message).unwrap();
/// }
/// ```
///
/// # Note
///
/// This is a basic implementation. For production use, you'll need to integrate
/// with an HTTP server and handle the POST endpoint separately.
pub struct SseServerTransport<W, R> {
    writer: SseWriter<W>,
    /// Channel or queue for receiving requests from POST handler.
    request_source: R,
    endpoint_sent: bool,
    endpoint_url: String,
}

impl<W: Write, R: Iterator<Item = JsonRpcRequest>> SseServerTransport<W, R> {
    /// Creates a new SSE server transport.
    ///
    /// # Arguments
    ///
    /// * `writer` - The SSE stream writer (response body)
    /// * `request_source` - Source of requests from POST handler
    /// * `endpoint_url` - The URL to advertise for client POST requests
    #[must_use]
    pub fn new(writer: W, request_source: R, endpoint_url: impl Into<String>) -> Self {
        Self {
            writer: SseWriter::new(writer),
            request_source,
            endpoint_sent: false,
            endpoint_url: endpoint_url.into(),
        }
    }

    /// Sends the endpoint event if not already sent.
    fn ensure_endpoint_sent(&mut self, cx: &Cx) -> Result<(), TransportError> {
        if !self.endpoint_sent {
            self.writer.write_endpoint(cx, &self.endpoint_url)?;
            self.endpoint_sent = true;
        }
        Ok(())
    }
}

impl<W: Write, R: Iterator<Item = JsonRpcRequest>> Transport for SseServerTransport<W, R> {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        self.ensure_endpoint_sent(cx)?;
        self.writer.write_message(cx, message)
    }

    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        // Get next request from the request source (POST handler)
        match self.request_source.next() {
            Some(request) => Ok(JsonRpcMessage::Request(request)),
            None => Err(TransportError::Closed),
        }
    }

    fn close(&mut self) -> Result<(), TransportError> {
        // SSE connections don't have a graceful close mechanism
        // Just flush and let the connection drop
        self.writer.inner_mut().flush()?;
        Ok(())
    }
}

// =============================================================================
// SSE Client Transport
// =============================================================================

/// Client-side SSE transport.
///
/// This transport is designed for the client side of an MCP SSE connection:
/// - Receives responses via SSE event stream
/// - Sends requests via HTTP POST (using provided sender)
///
/// # Architecture
///
/// ```ignore
/// // Connect to SSE endpoint
/// let sse_stream = http_client.get(sse_url).send()?;
/// let (tx, rx) = channel();
///
/// // Create transport
/// let transport = SseClientTransport::new(sse_stream, tx);
///
/// // Read endpoint URL
/// let post_url = transport.read_endpoint(&cx)?;
///
/// // Use transport for MCP client
/// client.run(transport);
/// ```
pub struct SseClientTransport<R, W> {
    reader: SseReader<R>,
    /// Sender for POST requests (injected into HTTP client)
    request_sink: W,
    codec: Codec,
}

impl<R: Read, W: Write> SseClientTransport<R, W> {
    /// Creates a new SSE client transport.
    ///
    /// # Arguments
    ///
    /// * `reader` - The SSE event stream reader
    /// * `request_sink` - Sink for outgoing requests (typically an HTTP POST body)
    #[must_use]
    pub fn new(reader: R, request_sink: W) -> Self {
        Self {
            reader: SseReader::new(reader),
            request_sink,
            codec: Codec::new(),
        }
    }

    /// Reads the endpoint URL from the SSE stream.
    ///
    /// This should be called once when the connection is established.
    pub fn read_endpoint(&mut self, cx: &Cx) -> Result<Option<String>, TransportError> {
        self.reader.read_endpoint(cx)
    }
}

impl<R: Read, W: Write> Transport for SseClientTransport<R, W> {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        // Send via POST (write to request sink)
        let bytes = match message {
            JsonRpcMessage::Request(req) => self.codec.encode_request(req)?,
            JsonRpcMessage::Response(resp) => self.codec.encode_response(resp)?,
        };

        self.request_sink.write_all(&bytes)?;
        self.request_sink.flush()?;
        Ok(())
    }

    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        match self.reader.read_message(cx)? {
            Some(message) => Ok(message),
            None => Err(TransportError::Closed),
        }
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.request_sink.flush()?;
        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_sse_event_endpoint() {
        let event = SseEvent::endpoint("http://localhost:8080/messages");
        let bytes = event.to_bytes();
        let output = String::from_utf8(bytes).unwrap();

        assert!(output.contains("event: endpoint\n"));
        assert!(output.contains("data: http://localhost:8080/messages\n"));
        assert!(output.ends_with("\n\n")); // Blank line terminator
    }

    #[test]
    fn test_sse_event_message() {
        let event = SseEvent::message(r#"{"jsonrpc":"2.0","id":1}"#).with_id("42");
        let bytes = event.to_bytes();
        let output = String::from_utf8(bytes).unwrap();

        assert!(output.contains("event: message\n"));
        assert!(output.contains("id: 42\n"));
        assert!(output.contains(r#"data: {"jsonrpc":"2.0","id":1}"#));
    }

    #[test]
    fn test_sse_event_with_retry() {
        let event = SseEvent::message("test").with_retry(5000);
        let bytes = event.to_bytes();
        let output = String::from_utf8(bytes).unwrap();

        assert!(output.contains("retry: 5000\n"));
    }

    #[test]
    fn test_sse_event_multiline_data() {
        let event = SseEvent::message("line1\nline2\nline3");
        let bytes = event.to_bytes();
        let output = String::from_utf8(bytes).unwrap();

        assert!(output.contains("data: line1\n"));
        assert!(output.contains("data: line2\n"));
        assert!(output.contains("data: line3\n"));
    }

    #[test]
    fn test_sse_reader_simple_event() {
        let input = b"event: message\ndata: hello\n\n";
        let reader = Cursor::new(input.to_vec());
        let mut sse_reader = SseReader::new(reader);

        let cx = Cx::for_testing();
        let event = sse_reader.read_event(&cx).unwrap().unwrap();

        assert_eq!(event.event_type, SseEventType::Message);
        assert_eq!(event.data, "hello");
    }

    #[test]
    fn test_sse_reader_with_id() {
        let input = b"event: message\nid: 42\ndata: test\n\n";
        let reader = Cursor::new(input.to_vec());
        let mut sse_reader = SseReader::new(reader);

        let cx = Cx::for_testing();
        let event = sse_reader.read_event(&cx).unwrap().unwrap();

        assert_eq!(event.id, Some("42".to_string()));
    }

    #[test]
    fn test_sse_reader_multiline_data() {
        let input = b"event: message\ndata: line1\ndata: line2\n\n";
        let reader = Cursor::new(input.to_vec());
        let mut sse_reader = SseReader::new(reader);

        let cx = Cx::for_testing();
        let event = sse_reader.read_event(&cx).unwrap().unwrap();

        assert_eq!(event.data, "line1\nline2");
    }

    #[test]
    fn test_sse_reader_skips_comments() {
        let input = b": this is a comment\nevent: message\ndata: hello\n\n";
        let reader = Cursor::new(input.to_vec());
        let mut sse_reader = SseReader::new(reader);

        let cx = Cx::for_testing();
        let event = sse_reader.read_event(&cx).unwrap().unwrap();

        assert_eq!(event.data, "hello");
    }

    #[test]
    fn test_sse_reader_skips_unknown_events() {
        let input = b"event: ping\ndata: keep-alive\n\n\
event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}\n\n";
        let reader = Cursor::new(input.to_vec());
        let mut sse_reader = SseReader::new(reader);

        let cx = Cx::for_testing();
        let message = sse_reader.read_message(&cx).unwrap().unwrap();

        assert!(
            matches!(message, JsonRpcMessage::Request(_)),
            "Expected request"
        );
        if let JsonRpcMessage::Request(req) = message {
            assert_eq!(req.method, "ping");
        }
    }

    #[test]
    fn test_sse_reader_eof() {
        let input = b"";
        let reader = Cursor::new(input.to_vec());
        let mut sse_reader = SseReader::new(reader);

        let cx = Cx::for_testing();
        let result = sse_reader.read_event(&cx).unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_sse_reader_endpoint_event() {
        let input = b"event: endpoint\ndata: http://localhost/post\n\n";
        let reader = Cursor::new(input.to_vec());
        let mut sse_reader = SseReader::new(reader);

        let cx = Cx::for_testing();
        let url = sse_reader.read_endpoint(&cx).unwrap().unwrap();

        assert_eq!(url, "http://localhost/post");
    }

    #[test]
    fn test_sse_writer_endpoint() {
        let buffer = Vec::new();
        let mut writer = SseWriter::new(buffer);

        let cx = Cx::for_testing();
        writer
            .write_endpoint(&cx, "http://localhost:8080/messages")
            .unwrap();

        let output = String::from_utf8(writer.into_inner()).unwrap();
        assert!(output.contains("event: endpoint\n"));
        assert!(output.contains("data: http://localhost:8080/messages\n"));
    }

    #[test]
    fn test_sse_writer_keep_alive() {
        let buffer = Vec::new();
        let mut writer = SseWriter::new(buffer);

        let cx = Cx::for_testing();
        writer.keep_alive(&cx).unwrap();

        let output = String::from_utf8(writer.into_inner()).unwrap();
        assert!(output.contains(": keep-alive\n"));
    }

    #[test]
    fn test_sse_roundtrip() {
        // Write an event
        let write_buffer = Vec::new();
        let mut writer = SseWriter::new(write_buffer);

        let cx = Cx::for_testing();
        let message = JsonRpcMessage::Response(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(serde_json::json!({"status": "ok"})),
            error: None,
            id: Some(fastmcp_protocol::RequestId::Number(1)),
        });

        writer.write_message(&cx, &message).unwrap();
        let written = writer.into_inner();

        // Read it back
        let mut reader = SseReader::new(Cursor::new(written));
        let read_message = reader.read_message(&cx).unwrap().unwrap();

        assert!(
            matches!(read_message, JsonRpcMessage::Response(_)),
            "Expected response"
        );
        if let JsonRpcMessage::Response(resp) = read_message {
            assert_eq!(resp.result, Some(serde_json::json!({"status": "ok"})));
        }
    }

    #[test]
    fn test_sse_reader_cancellation() {
        let input = b"event: message\ndata: hello\n\n";
        let reader = Cursor::new(input.to_vec());
        let mut sse_reader = SseReader::new(reader);

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let result = sse_reader.read_event(&cx);
        assert!(matches!(result, Err(TransportError::Cancelled)));
    }

    #[test]
    fn test_sse_writer_cancellation() {
        let buffer = Vec::new();
        let mut writer = SseWriter::new(buffer);

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let result = writer.write_endpoint(&cx, "http://test");
        assert!(matches!(result, Err(TransportError::Cancelled)));
    }
}
