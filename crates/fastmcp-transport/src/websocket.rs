//! WebSocket transport for MCP.
//!
//! This module provides WebSocket-based transport for bidirectional MCP
//! communication. Unlike SSE (server-push only), WebSocket allows both
//! client and server to send messages at any time.
//!
//! # Wire Format
//!
//! MCP over WebSocket uses:
//! - Text frames for JSON-RPC messages (one message per frame)
//! - Standard JSON-RPC request/response format
//! - Optional ping/pong for keep-alive
//!
//! # Architecture
//!
//! This implementation provides low-level WebSocket message framing.
//! It does not include HTTP upgrade handling. The caller must provide an
//! already-upgraded reader and writer.
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_transport::websocket::{WsTransport, WsFrame};
//!
//! // After HTTP upgrade, you have a bidirectional byte stream
//! let transport = WsTransport::new(reader, writer);
//!
//! // Receive a message
//! let msg = transport.recv(&cx)?;
//!
//! // Send a response
//! transport.send(&cx, &response)?;
//! ```
//!
//! # Cancellation behavior
//!
//! Operations check `cx.checkpoint()` before entering their I/O paths. The
//! caller-provided blocking reader or writer is not made interruptible by that
//! preflight check.

use std::io::{BufReader, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asupersync::Cx;
use fastmcp_core::{WebSocketMask, draw_websocket_mask};

use crate::{Codec, Transport, TransportError, TransportRecvHalf, TransportSendHalf};
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};

fn websocket_checkpoint(cx: &Cx) -> Result<(), TransportError> {
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

/// WebSocket frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsFrameType {
    /// Continuation frame (for fragmented messages).
    Continuation,
    /// Text frame containing UTF-8 data (used for JSON-RPC).
    Text,
    /// Binary frame.
    Binary,
    /// Close frame.
    Close,
    /// Ping frame (keep-alive).
    Ping,
    /// Pong frame (keep-alive response).
    Pong,
}

impl WsFrameType {
    /// Returns the opcode for this frame type.
    fn opcode(&self) -> u8 {
        match self {
            WsFrameType::Continuation => 0x00,
            WsFrameType::Text => 0x01,
            WsFrameType::Binary => 0x02,
            WsFrameType::Close => 0x08,
            WsFrameType::Ping => 0x09,
            WsFrameType::Pong => 0x0A,
        }
    }

    /// Parses a frame type from an opcode.
    fn from_opcode(opcode: u8) -> Option<Self> {
        match opcode {
            0x00 => Some(WsFrameType::Continuation),
            0x01 => Some(WsFrameType::Text),
            0x02 => Some(WsFrameType::Binary),
            0x08 => Some(WsFrameType::Close),
            0x09 => Some(WsFrameType::Ping),
            0x0A => Some(WsFrameType::Pong),
            _ => None,
        }
    }
}

/// A WebSocket frame.
#[derive(Debug, Clone)]
pub struct WsFrame {
    /// Frame type.
    pub frame_type: WsFrameType,
    /// Frame payload.
    pub payload: Vec<u8>,
    /// Whether this is the final frame in a message.
    pub fin: bool,
}

impl WsFrame {
    /// Creates a new text frame with the given payload.
    #[must_use]
    pub fn text(payload: impl Into<String>) -> Self {
        Self {
            frame_type: WsFrameType::Text,
            payload: payload.into().into_bytes(),
            fin: true,
        }
    }

    /// Creates a new close frame.
    #[must_use]
    pub fn close() -> Self {
        Self {
            frame_type: WsFrameType::Close,
            payload: Vec::new(),
            fin: true,
        }
    }

    /// Creates a new ping frame.
    #[must_use]
    pub fn ping(payload: Vec<u8>) -> Self {
        Self {
            frame_type: WsFrameType::Ping,
            payload,
            fin: true,
        }
    }

    /// Creates a new pong frame.
    #[must_use]
    pub fn pong(payload: Vec<u8>) -> Self {
        Self {
            frame_type: WsFrameType::Pong,
            payload,
            fin: true,
        }
    }

    /// Returns the payload as a UTF-8 string if this is a text frame.
    pub fn as_text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.payload)
    }
}

fn websocket_invalid_data(message: impl Into<String>) -> TransportError {
    TransportError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}

fn validate_close_payload(payload: &[u8]) -> Result<(), TransportError> {
    if payload.len() == 1 {
        return Err(websocket_invalid_data(
            "WebSocket close payload cannot contain a one-byte status code",
        ));
    }
    if payload.len() < 2 {
        return Ok(());
    }

    let status = u16::from_be_bytes([payload[0], payload[1]]);
    let status_is_allowed = matches!(status, 1000..=1003 | 1007..=1014 | 3000..=4999);
    if !status_is_allowed {
        return Err(websocket_invalid_data(format!(
            "Invalid WebSocket close status code: {status}"
        )));
    }
    std::str::from_utf8(&payload[2..])
        .map_err(|_| websocket_invalid_data("WebSocket close reason must be valid UTF-8"))?;
    Ok(())
}

fn validate_outbound_frame(frame: &WsFrame) -> Result<(), TransportError> {
    if matches!(
        frame.frame_type,
        WsFrameType::Close | WsFrameType::Ping | WsFrameType::Pong
    ) {
        if !frame.fin {
            return Err(websocket_invalid_data(
                "Fragmented WebSocket control frames are not allowed",
            ));
        }
        if frame.payload.len() > 125 {
            return Err(websocket_invalid_data(
                "WebSocket control frame payload exceeds 125 bytes",
            ));
        }
    }
    if frame.frame_type == WsFrameType::Close {
        validate_close_payload(&frame.payload)?;
    }
    // A complete text message must be valid UTF-8 even when callers bypass
    // WsFrame::text and populate the public fields directly. Fragmented text
    // is validated by the stateful transport once its final continuation is
    // assembled; a standalone frame writer cannot validate it in isolation.
    if frame.frame_type == WsFrameType::Text && frame.fin {
        std::str::from_utf8(&frame.payload)
            .map_err(|_| websocket_invalid_data("WebSocket text payload must be valid UTF-8"))?;
    }
    Ok(())
}

fn invalid_utf8_close_frame() -> WsFrame {
    WsFrame {
        frame_type: WsFrameType::Close,
        payload: 1007_u16.to_be_bytes().to_vec(),
        fin: true,
    }
}

/// Local endpoint role used to enforce RFC 6455 mask direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointRole {
    /// A server endpoint receives masked frames from a client.
    Server,
    /// A client endpoint receives unmasked frames from a server.
    Client,
}

impl EndpointRole {
    fn validate_peer_mask(self, masked: bool) -> Result<(), TransportError> {
        let violation = match (self, masked) {
            (Self::Server, false) => {
                Some("Client-to-server WebSocket frames MUST be masked per RFC 6455")
            }
            (Self::Client, true) => {
                Some("Server-to-client WebSocket frames MUST NOT be masked per RFC 6455")
            }
            _ => None,
        };

        if let Some(message) = violation {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message,
            )));
        }

        Ok(())
    }
}

/// WebSocket frame reader.
///
/// Reads WebSocket frames from an underlying byte stream.
/// Handles frame parsing according to RFC 6455.
pub struct WsReader<R> {
    reader: BufReader<R>,
    max_frame_size: usize,
    endpoint_role: EndpointRole,
}

impl<R: Read> WsReader<R> {
    /// Creates a new WebSocket reader for server-side use.
    ///
    /// Per RFC 6455, servers MUST reject unmasked frames from clients.
    pub fn new(reader: R) -> Self {
        Self::with_role(reader, EndpointRole::Server)
    }

    /// Creates a new WebSocket reader for client-side use.
    ///
    /// Per RFC 6455, clients MUST reject masked frames from servers.
    pub fn new_client(reader: R) -> Self {
        Self::with_role(reader, EndpointRole::Client)
    }

    /// Creates a new WebSocket reader for an explicit endpoint role.
    fn with_role(reader: R, endpoint_role: EndpointRole) -> Self {
        Self {
            reader: BufReader::new(reader),
            max_frame_size: 10 * 1024 * 1024,
            endpoint_role,
        }
    }

    /// Reads the next WebSocket frame.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame is malformed or I/O fails.
    pub fn read_frame(&mut self) -> Result<WsFrame, TransportError> {
        // Read first two bytes (header)
        let mut header = [0u8; 2];
        self.reader.read_exact(&mut header)?;

        let fin = (header[0] & 0x80) != 0;
        let rsv = header[0] & 0x70;
        let opcode = header[0] & 0x0F;
        let masked = (header[1] & 0x80) != 0;
        let payload_len_code = header[1] & 0x7F;
        let mut payload_len = u64::from(payload_len_code);

        if rsv != 0 {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WebSocket RSV bits set but no extensions are supported",
            )));
        }

        // RFC 6455 Section 5.1 makes mask direction endpoint-specific for every
        // frame, including control and continuation frames.
        self.endpoint_role.validate_peer_mask(masked)?;

        // The opcode is fully known from the first header byte. Rejecting it
        // before extended lengths and payload allocation prevents malformed
        // reserved frames from forcing a maximum-sized read first.
        let frame_type = WsFrameType::from_opcode(opcode)
            .ok_or_else(|| websocket_invalid_data(format!("Unknown WebSocket opcode: {opcode}")))?;

        // Extended payload length
        if payload_len_code == 126 {
            let mut ext = [0u8; 2];
            self.reader.read_exact(&mut ext)?;
            payload_len = u16::from_be_bytes(ext) as u64;
            if payload_len < 126 {
                return Err(websocket_invalid_data(
                    "Non-minimal WebSocket payload-length encoding",
                ));
            }
        } else if payload_len_code == 127 {
            let mut ext = [0u8; 8];
            self.reader.read_exact(&mut ext)?;
            if ext[0] & 0x80 != 0 {
                return Err(websocket_invalid_data(
                    "WebSocket payload length exceeds the RFC 6455 63-bit range",
                ));
            }
            payload_len = u64::from_be_bytes(ext);
            if u16::try_from(payload_len).is_ok() {
                return Err(websocket_invalid_data(
                    "Non-minimal WebSocket payload-length encoding",
                ));
            }
        }

        let is_control = matches!(opcode, 0x08..=0x0A);
        if is_control && !fin {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Fragmented control frames are not allowed",
            )));
        }
        if is_control && payload_len > 125 {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Control frame payload too large",
            )));
        }

        let max_frame_size = self.max_frame_size as u64;
        if payload_len > max_frame_size {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("WebSocket frame too large: {payload_len} bytes"),
            )));
        }
        if payload_len > usize::MAX as u64 {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WebSocket frame length exceeds platform limits",
            )));
        }

        // Read masking key if present (client -> server frames are masked)
        let mask_key = if masked {
            let mut key = [0u8; 4];
            self.reader.read_exact(&mut key)?;
            Some(key)
        } else {
            None
        };

        // Read payload
        let mut payload = vec![0u8; payload_len as usize];
        self.reader.read_exact(&mut payload)?;

        // Unmask if necessary
        if let Some(key) = mask_key {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[i % 4];
            }
        }

        if frame_type == WsFrameType::Close {
            validate_close_payload(&payload)?;
        }

        Ok(WsFrame {
            frame_type,
            payload,
            fin,
        })
    }
}

/// WebSocket frame writer.
///
/// Writes WebSocket frames to an underlying byte stream.
/// Server frames are unmasked per RFC 6455.
pub struct WsWriter<W> {
    writer: W,
}

impl<W: Write> WsWriter<W> {
    /// Creates a new WebSocket writer.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Writes a WebSocket frame.
    ///
    /// # Errors
    ///
    /// Returns an error if I/O fails.
    pub fn write_frame(&mut self, frame: &WsFrame) -> Result<(), TransportError> {
        validate_outbound_frame(frame)?;

        // First byte: FIN + opcode
        let byte1 = if frame.fin { 0x80 } else { 0x00 } | frame.frame_type.opcode();

        // Second byte: mask bit (0 for server) + payload length
        let payload_len = frame.payload.len();

        if payload_len < 126 {
            self.writer.write_all(&[byte1, payload_len as u8])?;
        } else if payload_len < 65536 {
            self.writer.write_all(&[byte1, 126])?;
            self.writer.write_all(&(payload_len as u16).to_be_bytes())?;
        } else {
            self.writer.write_all(&[byte1, 127])?;
            self.writer.write_all(&(payload_len as u64).to_be_bytes())?;
        }

        // Write payload (unmasked for server -> client)
        self.writer.write_all(&frame.payload)?;
        self.writer.flush()?;

        Ok(())
    }
}

/// WebSocket transport for MCP.
///
/// Provides bidirectional message passing over WebSocket.
/// Messages are JSON-RPC encoded as text frames.
///
/// # Example
///
/// ```ignore
/// let transport = WsTransport::new(tcp_read, tcp_write);
///
/// // Receive a message
/// match transport.recv(&cx)? {
///     JsonRpcMessage::Request(req) => {
///         // Handle request and send response
///         let response = handle_request(req);
///         transport.send(&cx, &JsonRpcMessage::Response(response))?;
///     }
///     _ => {}
/// }
/// ```
pub struct WsTransport<R, W> {
    reader: WsReader<R>,
    writer: WsWriter<W>,
    codec: Codec,
    fragment_buffer: Vec<u8>,
    fragmented_text: bool,
    max_message_size: usize,
    closed: bool,
}

impl<R: Read, W: Write> WsTransport<R, W> {
    /// Creates a new WebSocket transport.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: WsReader::new(reader),
            writer: WsWriter::new(writer),
            codec: Codec::new(),
            fragment_buffer: Vec::new(),
            fragmented_text: false,
            max_message_size: 10 * 1024 * 1024,
            closed: false,
        }
    }

    /// Separates server-side WebSocket ingress from egress.
    ///
    /// The returned halves retain the server wire direction: incoming frames
    /// must be masked and outgoing frames are unmasked. The receive half holds
    /// a shared control-frame writer solely for RFC 6455 ping/pong and close
    /// handshakes; application messages remain exclusively owned by the send
    /// half.
    #[must_use]
    pub fn into_split(self) -> (WsServerRecvHalf<R, W>, WsServerSendHalf<W>) {
        let Self {
            reader,
            writer,
            codec,
            fragment_buffer,
            fragmented_text,
            max_message_size,
            closed,
        } = self;
        let writer = SharedWsWriter::new(writer, closed);
        let mut send_codec = Codec::new();
        send_codec.set_max_message_size(codec.max_message_size());

        (
            WsServerRecvHalf {
                reader,
                writer: writer.clone(),
                codec,
                fragment_buffer,
                fragmented_text,
                max_message_size,
                closed,
            },
            WsServerSendHalf {
                writer,
                codec: send_codec,
            },
        )
    }

    /// Sends a JSON-RPC message over the WebSocket.
    ///
    /// # Cancel-Safety
    ///
    /// Checks for cancellation before sending.
    ///
    /// # Errors
    ///
    /// Returns an error if cancelled, the connection is closed, or I/O fails.
    pub fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        // Check cancellation.
        websocket_checkpoint(cx)?;

        // Encode message
        let bytes = match message {
            JsonRpcMessage::Request(req) => self.codec.encode_request(req)?,
            JsonRpcMessage::Response(resp) => self.codec.encode_response(resp)?,
        };

        // Convert to string (strip trailing newline from NDJSON format)
        let text = String::from_utf8(bytes).map_err(|e| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid UTF-8 in message: {e}"),
            ))
        })?;
        let text = text.trim_end();

        // Send as text frame
        let frame = WsFrame::text(text);
        if let Err(error) = self.writer.write_frame(&frame) {
            self.closed = true;
            self.fragment_buffer.clear();
            self.fragmented_text = false;
            return Err(error);
        }

        Ok(())
    }

    /// Receives the next JSON-RPC message from the WebSocket.
    ///
    /// Handles control frames (ping/pong) automatically.
    /// Handles message fragmentation (Continuation frames).
    ///
    /// # Cancel-Safety
    ///
    /// Checks for cancellation before blocking.
    ///
    /// # Errors
    ///
    /// Returns an error if cancelled, the connection is closed, or parsing fails.
    pub fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        loop {
            if self.closed {
                return Err(TransportError::Closed);
            }
            // Check cancellation.
            websocket_checkpoint(cx)?;

            // Read next frame
            let frame = match self.reader.read_frame() {
                Ok(frame) => frame,
                Err(error) => {
                    self.closed = true;
                    self.fragment_buffer.clear();
                    self.fragmented_text = false;
                    return Err(error);
                }
            };

            match frame.frame_type {
                WsFrameType::Text => {
                    if self.fragmented_text {
                        self.fragment_buffer.clear();
                        self.fragmented_text = false;
                        self.closed = true;
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Received Text frame while inside fragmented message",
                        )));
                    }

                    if frame.fin {
                        // Complete message in single frame
                        return self.decode_message(frame.payload);
                    }

                    // Start of fragmented message
                    self.fragmented_text = true;
                    let next_len = self
                        .fragment_buffer
                        .len()
                        .saturating_add(frame.payload.len());
                    if next_len > self.max_message_size {
                        self.fragment_buffer.clear();
                        self.fragmented_text = false;
                        self.closed = true;
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Fragmented message exceeds size limit",
                        )));
                    }
                    self.fragment_buffer.extend(frame.payload);
                    continue;
                }
                WsFrameType::Continuation => {
                    if !self.fragmented_text {
                        self.closed = true;
                        self.fragment_buffer.clear();
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Received Continuation frame without start frame",
                        )));
                    }

                    let next_len = self
                        .fragment_buffer
                        .len()
                        .saturating_add(frame.payload.len());
                    if next_len > self.max_message_size {
                        self.fragment_buffer.clear();
                        self.fragmented_text = false;
                        self.closed = true;
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Fragmented message exceeds size limit",
                        )));
                    }
                    self.fragment_buffer.extend(frame.payload);

                    if frame.fin {
                        // End of fragmented message
                        let payload = std::mem::take(&mut self.fragment_buffer);
                        self.fragmented_text = false;
                        return self.decode_message(payload);
                    }

                    // More fragments to come
                    continue;
                }
                WsFrameType::Binary => {
                    if self.fragmented_text {
                        self.fragment_buffer.clear();
                        self.fragmented_text = false;
                    }
                    self.closed = true;
                    return Err(TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Binary WebSocket messages are not supported by MCP",
                    )));
                }
                WsFrameType::Close => {
                    self.closed = true;
                    self.fragment_buffer.clear();
                    self.fragmented_text = false;
                    let close_reply = WsFrame {
                        frame_type: WsFrameType::Close,
                        payload: frame.payload,
                        fin: true,
                    };
                    self.writer.write_frame(&close_reply)?;
                    return Err(TransportError::Closed);
                }
                WsFrameType::Ping => {
                    // Auto-respond with pong
                    let pong = WsFrame::pong(frame.payload);
                    if let Err(error) = self.writer.write_frame(&pong) {
                        self.closed = true;
                        self.fragment_buffer.clear();
                        self.fragmented_text = false;
                        return Err(error);
                    }
                    continue;
                }
                WsFrameType::Pong => {
                    // Ignore pong frames
                    continue;
                }
            }
        }
    }

    /// Decodes a payload into a JSON-RPC message.
    fn decode_message(&mut self, payload: Vec<u8>) -> Result<JsonRpcMessage, TransportError> {
        if let Err(error) = std::str::from_utf8(&payload) {
            self.closed = true;
            self.fragment_buffer.clear();
            self.fragmented_text = false;
            // RFC 6455 assigns 1007 to inconsistent text data. The close write
            // is best-effort: the primary error still explains why the peer
            // connection became terminal.
            let _close_result = self.writer.write_frame(&invalid_utf8_close_frame());
            return Err(websocket_invalid_data(format!(
                "Invalid UTF-8 in WebSocket text message: {error}"
            )));
        }
        Ok(self.codec.decode_complete_message(&payload)?)
    }

    /// Sends a close frame and shuts down the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if I/O fails.
    pub fn close(&mut self) -> Result<(), TransportError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.fragment_buffer.clear();
        self.fragmented_text = false;
        let frame = WsFrame::close();
        self.writer.write_frame(&frame)?;
        Ok(())
    }

    /// Sends a request through this transport.
    ///
    /// Convenience method that wraps a request in a message.
    pub fn send_request(
        &mut self,
        cx: &Cx,
        request: &JsonRpcRequest,
    ) -> Result<(), TransportError> {
        self.send(cx, &JsonRpcMessage::Request(request.clone()))
    }

    /// Sends a response through this transport.
    ///
    /// Convenience method that wraps a response in a message.
    pub fn send_response(
        &mut self,
        cx: &Cx,
        response: &JsonRpcResponse,
    ) -> Result<(), TransportError> {
        self.send(cx, &JsonRpcMessage::Response(response.clone()))
    }

    /// Sends a ping frame.
    ///
    /// # Errors
    ///
    /// Returns an error if I/O fails.
    pub fn ping(&mut self) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        let frame = WsFrame::ping(Vec::new());
        if let Err(error) = self.writer.write_frame(&frame) {
            self.closed = true;
            self.fragment_buffer.clear();
            self.fragmented_text = false;
            return Err(error);
        }
        Ok(())
    }
}

impl<R: Read, W: Write> Transport for WsTransport<R, W> {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        WsTransport::send(self, cx, message)
    }

    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        WsTransport::recv(self, cx)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        WsTransport::close(self)
    }
}

/// Client-side WebSocket mask generation.
///
/// Clients must mask frames per RFC 6455. This struct provides
/// frame writing with proper masking using cryptographically secure
/// random mask keys.
pub struct WsClientWriter<W> {
    writer: W,
}

fn map_mask_draw_error<E>(error: E) -> TransportError
where
    E: std::error::Error + Send + Sync + 'static,
{
    TransportError::Io(std::io::Error::other(error))
}

impl<W: Write> WsClientWriter<W> {
    /// Creates a new client WebSocket writer.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Generates a cryptographically secure mask key.
    ///
    /// RFC 6455 Section 5.3: The masking key MUST be unpredictable.
    fn generate_mask() -> Result<[u8; 4], TransportError> {
        draw_websocket_mask()
            .map(WebSocketMask::into_bytes)
            .map_err(map_mask_draw_error)
    }

    /// Writes a WebSocket frame with client masking.
    ///
    /// # Errors
    ///
    /// Returns an error if I/O fails.
    pub fn write_frame(&mut self, frame: &WsFrame) -> Result<(), TransportError> {
        self.write_frame_with_mask_draw(frame, Self::generate_mask)
    }

    fn write_frame_with_mask_draw<F>(
        &mut self,
        frame: &WsFrame,
        draw_mask: F,
    ) -> Result<(), TransportError>
    where
        F: FnOnce() -> Result<[u8; 4], TransportError>,
    {
        validate_outbound_frame(frame)?;

        // Draw before emitting any header bytes. RNG failure is terminal and
        // cannot leave a partial frame on the stream.
        let mask = draw_mask()?;

        // First byte: FIN + opcode
        let byte1 = if frame.fin { 0x80 } else { 0x00 } | frame.frame_type.opcode();

        // Second byte: mask bit (1 for client) + payload length
        let payload_len = frame.payload.len();
        let mask_bit = 0x80u8;

        if payload_len < 126 {
            self.writer
                .write_all(&[byte1, mask_bit | payload_len as u8])?;
        } else if payload_len < 65536 {
            self.writer.write_all(&[byte1, mask_bit | 126])?;
            self.writer.write_all(&(payload_len as u16).to_be_bytes())?;
        } else {
            self.writer.write_all(&[byte1, mask_bit | 127])?;
            self.writer.write_all(&(payload_len as u64).to_be_bytes())?;
        }

        // Write mask key (cryptographically random per RFC 6455)
        self.writer.write_all(&mask)?;

        // Write masked payload
        let masked: Vec<u8> = frame
            .payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        self.writer.write_all(&masked)?;
        self.writer.flush()?;

        Ok(())
    }
}

/// Client-side WebSocket transport.
///
/// Similar to `WsTransport` but masks outgoing frames as required
/// for client-to-server communication per RFC 6455.
pub struct WsClientTransport<R, W> {
    reader: WsReader<R>,
    writer: WsClientWriter<W>,
    codec: Codec,
    fragment_buffer: Vec<u8>,
    fragmented_text: bool,
    max_message_size: usize,
    closed: bool,
}

impl<R: Read, W: Write> WsClientTransport<R, W> {
    /// Creates a new client WebSocket transport.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            // Client requires unmasked frames from the server.
            reader: WsReader::new_client(reader),
            writer: WsClientWriter::new(writer),
            codec: Codec::new(),
            fragment_buffer: Vec::new(),
            fragmented_text: false,
            max_message_size: 10 * 1024 * 1024,
            closed: false,
        }
    }

    /// Separates client-side WebSocket ingress from egress.
    ///
    /// The returned halves retain the client wire direction: incoming frames
    /// must be unmasked and outgoing frames are masked. The receive half holds
    /// a shared control-frame writer solely for RFC 6455 ping/pong and close
    /// handshakes; application messages remain exclusively owned by the send
    /// half.
    #[must_use]
    pub fn into_split(self) -> (WsClientRecvHalf<R, W>, WsClientSendHalf<W>) {
        let Self {
            reader,
            writer,
            codec,
            fragment_buffer,
            fragmented_text,
            max_message_size,
            closed,
        } = self;
        let writer = SharedWsWriter::new(writer, closed);
        let mut send_codec = Codec::new();
        send_codec.set_max_message_size(codec.max_message_size());

        (
            WsClientRecvHalf {
                reader,
                writer: writer.clone(),
                codec,
                fragment_buffer,
                fragmented_text,
                max_message_size,
                closed,
            },
            WsClientSendHalf {
                writer,
                codec: send_codec,
            },
        )
    }

    /// Sends a JSON-RPC message over the WebSocket.
    ///
    /// The frame will be masked as required for clients.
    ///
    /// # Cancel-Safety
    ///
    /// Checks for cancellation before sending.
    ///
    /// # Errors
    ///
    /// Returns an error if cancelled, the connection is closed, or I/O fails.
    pub fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        // Check cancellation.
        websocket_checkpoint(cx)?;

        // Encode message
        let bytes = match message {
            JsonRpcMessage::Request(req) => self.codec.encode_request(req)?,
            JsonRpcMessage::Response(resp) => self.codec.encode_response(resp)?,
        };

        // Convert to string (strip trailing newline from NDJSON format)
        let text = String::from_utf8(bytes).map_err(|e| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid UTF-8 in message: {e}"),
            ))
        })?;
        let text = text.trim_end();

        // Send as text frame (masked)
        let frame = WsFrame::text(text);
        if let Err(error) = self.writer.write_frame(&frame) {
            self.closed = true;
            self.fragment_buffer.clear();
            self.fragmented_text = false;
            return Err(error);
        }

        Ok(())
    }

    /// Receives the next JSON-RPC message from the WebSocket.
    ///
    /// Handles control frames (ping/pong) automatically.
    ///
    /// # Cancel-Safety
    ///
    /// Checks for cancellation before blocking.
    ///
    /// # Errors
    ///
    /// Returns an error if cancelled, the connection is closed, or parsing fails.
    pub fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        loop {
            if self.closed {
                return Err(TransportError::Closed);
            }
            // Check cancellation.
            websocket_checkpoint(cx)?;

            // Read next frame
            let frame = match self.reader.read_frame() {
                Ok(frame) => frame,
                Err(error) => {
                    self.closed = true;
                    self.fragment_buffer.clear();
                    self.fragmented_text = false;
                    return Err(error);
                }
            };

            match frame.frame_type {
                WsFrameType::Text => {
                    if self.fragmented_text {
                        self.fragment_buffer.clear();
                        self.fragmented_text = false;
                        self.closed = true;
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Received Text frame while inside fragmented message",
                        )));
                    }

                    if frame.fin {
                        // Complete message in single frame
                        return self.decode_message(frame.payload);
                    }

                    // Start of fragmented message
                    self.fragmented_text = true;
                    let next_len = self
                        .fragment_buffer
                        .len()
                        .saturating_add(frame.payload.len());
                    if next_len > self.max_message_size {
                        self.fragment_buffer.clear();
                        self.fragmented_text = false;
                        self.closed = true;
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Fragmented message exceeds size limit",
                        )));
                    }
                    self.fragment_buffer.extend(frame.payload);
                    continue;
                }
                WsFrameType::Continuation => {
                    if !self.fragmented_text {
                        self.closed = true;
                        self.fragment_buffer.clear();
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Received Continuation frame without start frame",
                        )));
                    }

                    let next_len = self
                        .fragment_buffer
                        .len()
                        .saturating_add(frame.payload.len());
                    if next_len > self.max_message_size {
                        self.fragment_buffer.clear();
                        self.fragmented_text = false;
                        self.closed = true;
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Fragmented message exceeds size limit",
                        )));
                    }
                    self.fragment_buffer.extend(frame.payload);

                    if frame.fin {
                        // End of fragmented message
                        let payload = std::mem::take(&mut self.fragment_buffer);
                        self.fragmented_text = false;
                        return self.decode_message(payload);
                    }

                    // More fragments to come
                    continue;
                }
                WsFrameType::Binary => {
                    if self.fragmented_text {
                        self.fragment_buffer.clear();
                        self.fragmented_text = false;
                    }
                    self.closed = true;
                    return Err(TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Binary WebSocket messages are not supported by MCP",
                    )));
                }
                WsFrameType::Close => {
                    self.closed = true;
                    self.fragment_buffer.clear();
                    self.fragmented_text = false;
                    let close_reply = WsFrame {
                        frame_type: WsFrameType::Close,
                        payload: frame.payload,
                        fin: true,
                    };
                    self.writer.write_frame(&close_reply)?;
                    return Err(TransportError::Closed);
                }
                WsFrameType::Ping => {
                    // Respond with pong (masked)
                    let pong = WsFrame::pong(frame.payload);
                    if let Err(error) = self.writer.write_frame(&pong) {
                        self.closed = true;
                        self.fragment_buffer.clear();
                        self.fragmented_text = false;
                        return Err(error);
                    }
                    continue;
                }
                WsFrameType::Pong => {
                    continue;
                }
            }
        }
    }

    /// Decodes a payload into a JSON-RPC message.
    fn decode_message(&mut self, payload: Vec<u8>) -> Result<JsonRpcMessage, TransportError> {
        if let Err(error) = std::str::from_utf8(&payload) {
            self.closed = true;
            self.fragment_buffer.clear();
            self.fragmented_text = false;
            let _close_result = self.writer.write_frame(&invalid_utf8_close_frame());
            return Err(websocket_invalid_data(format!(
                "Invalid UTF-8 in WebSocket text message: {error}"
            )));
        }
        Ok(self.codec.decode_complete_message(&payload)?)
    }

    /// Sends a close frame.
    ///
    /// # Errors
    ///
    /// Returns an error if I/O fails.
    pub fn close(&mut self) -> Result<(), TransportError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.fragment_buffer.clear();
        self.fragmented_text = false;
        let frame = WsFrame::close();
        self.writer.write_frame(&frame)?;
        Ok(())
    }
}

impl<R: Read, W: Write> Transport for WsClientTransport<R, W> {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        WsClientTransport::send(self, cx, message)
    }

    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        WsClientTransport::recv(self, cx)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        WsClientTransport::close(self)
    }
}

trait WsFrameSink {
    fn write_ws_frame(&mut self, frame: &WsFrame) -> Result<(), TransportError>;
}

impl<W: Write> WsFrameSink for WsWriter<W> {
    fn write_ws_frame(&mut self, frame: &WsFrame) -> Result<(), TransportError> {
        self.write_frame(frame)
    }
}

impl<W: Write> WsFrameSink for WsClientWriter<W> {
    fn write_ws_frame(&mut self, frame: &WsFrame) -> Result<(), TransportError> {
        self.write_frame(frame)
    }
}

struct SplitWsWriter<F> {
    writer: F,
    closed: bool,
}

struct SharedWsWriter<F> {
    inner: Arc<std::sync::Mutex<SplitWsWriter<F>>>,
    terminal: Arc<AtomicBool>,
}

impl<F> Clone for SharedWsWriter<F> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            terminal: Arc::clone(&self.terminal),
        }
    }
}

impl<F> SharedWsWriter<F>
where
    F: WsFrameSink,
{
    fn new(writer: F, closed: bool) -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(SplitWsWriter { writer, closed })),
            terminal: Arc::new(AtomicBool::new(closed)),
        }
    }

    fn with_writer<T>(
        &self,
        operation: impl FnOnce(&mut SplitWsWriter<F>) -> Result<T, TransportError>,
    ) -> Result<T, TransportError> {
        let mut writer = self.inner.lock().map_err(|_| {
            self.terminal.store(true, Ordering::Release);
            TransportError::Io(std::io::Error::other(
                "WebSocket split writer lock poisoned",
            ))
        })?;
        operation(&mut writer)
    }

    fn is_closed(&self) -> bool {
        self.terminal.load(Ordering::Acquire)
    }

    fn send_frame(&self, frame: &WsFrame) -> Result<(), TransportError> {
        if self.is_closed() {
            return Err(TransportError::Closed);
        }
        self.with_writer(|writer| {
            if writer.closed {
                return Err(TransportError::Closed);
            }
            if let Err(error) = writer.writer.write_ws_frame(frame) {
                writer.closed = true;
                self.terminal.store(true, Ordering::Release);
                return Err(error);
            }
            Ok(())
        })
    }

    fn close_with_frame(&self, frame: WsFrame) -> Result<(), TransportError> {
        self.terminal.store(true, Ordering::Release);
        self.with_writer(|writer| {
            if writer.closed {
                return Ok(());
            }
            writer.closed = true;
            writer.writer.write_ws_frame(&frame)
        })
    }

    fn terminate(&self) {
        self.terminal.store(true, Ordering::Release);
        if let Ok(mut writer) = self.inner.lock() {
            writer.closed = true;
        }
    }
}

fn send_split_message<F>(
    writer: &SharedWsWriter<F>,
    codec: &Codec,
    cx: &Cx,
    message: &JsonRpcMessage,
) -> Result<(), TransportError>
where
    F: WsFrameSink,
{
    if writer.is_closed() {
        return Err(TransportError::Closed);
    }
    websocket_checkpoint(cx)?;

    let bytes = match message {
        JsonRpcMessage::Request(request) => codec.encode_request(request)?,
        JsonRpcMessage::Response(response) => codec.encode_response(response)?,
    };
    let text = String::from_utf8(bytes)
        .map_err(|error| websocket_invalid_data(format!("Invalid UTF-8 in message: {error}")))?;
    writer.send_frame(&WsFrame::text(text.trim_end()))
}

fn terminate_split_receive<F>(
    writer: &SharedWsWriter<F>,
    fragment_buffer: &mut Vec<u8>,
    fragmented_text: &mut bool,
    closed: &mut bool,
) where
    F: WsFrameSink,
{
    *closed = true;
    fragment_buffer.clear();
    *fragmented_text = false;
    writer.terminate();
}

fn recv_split_message<R, F>(
    reader: &mut WsReader<R>,
    writer: &SharedWsWriter<F>,
    codec: &Codec,
    fragment_buffer: &mut Vec<u8>,
    fragmented_text: &mut bool,
    max_message_size: usize,
    closed: &mut bool,
    cx: &Cx,
) -> Result<JsonRpcMessage, TransportError>
where
    R: Read,
    F: WsFrameSink,
{
    loop {
        if *closed || writer.is_closed() {
            return Err(TransportError::Closed);
        }
        websocket_checkpoint(cx)?;

        let frame = match reader.read_frame() {
            Ok(frame) => frame,
            Err(error) => {
                terminate_split_receive(writer, fragment_buffer, fragmented_text, closed);
                return Err(error);
            }
        };

        match frame.frame_type {
            WsFrameType::Text => {
                if *fragmented_text {
                    terminate_split_receive(writer, fragment_buffer, fragmented_text, closed);
                    return Err(websocket_invalid_data(
                        "Received Text frame while inside fragmented message",
                    ));
                }
                if frame.fin {
                    if let Err(error) = std::str::from_utf8(&frame.payload) {
                        *closed = true;
                        fragment_buffer.clear();
                        *fragmented_text = false;
                        let _close_result = writer.close_with_frame(invalid_utf8_close_frame());
                        return Err(websocket_invalid_data(format!(
                            "Invalid UTF-8 in WebSocket text message: {error}"
                        )));
                    }
                    return codec
                        .decode_complete_message(&frame.payload)
                        .map_err(Into::into);
                }

                *fragmented_text = true;
                let next_len = fragment_buffer.len().saturating_add(frame.payload.len());
                if next_len > max_message_size {
                    terminate_split_receive(writer, fragment_buffer, fragmented_text, closed);
                    return Err(websocket_invalid_data(
                        "Fragmented message exceeds size limit",
                    ));
                }
                fragment_buffer.extend(frame.payload);
            }
            WsFrameType::Continuation => {
                if !*fragmented_text {
                    terminate_split_receive(writer, fragment_buffer, fragmented_text, closed);
                    return Err(websocket_invalid_data(
                        "Received Continuation frame without start frame",
                    ));
                }

                let next_len = fragment_buffer.len().saturating_add(frame.payload.len());
                if next_len > max_message_size {
                    terminate_split_receive(writer, fragment_buffer, fragmented_text, closed);
                    return Err(websocket_invalid_data(
                        "Fragmented message exceeds size limit",
                    ));
                }
                fragment_buffer.extend(frame.payload);
                if frame.fin {
                    let payload = std::mem::take(fragment_buffer);
                    *fragmented_text = false;
                    if let Err(error) = std::str::from_utf8(&payload) {
                        *closed = true;
                        fragment_buffer.clear();
                        *fragmented_text = false;
                        let _close_result = writer.close_with_frame(invalid_utf8_close_frame());
                        return Err(websocket_invalid_data(format!(
                            "Invalid UTF-8 in WebSocket text message: {error}"
                        )));
                    }
                    return codec.decode_complete_message(&payload).map_err(Into::into);
                }
            }
            WsFrameType::Binary => {
                terminate_split_receive(writer, fragment_buffer, fragmented_text, closed);
                return Err(websocket_invalid_data(
                    "Binary WebSocket messages are not supported by MCP",
                ));
            }
            WsFrameType::Close => {
                *closed = true;
                fragment_buffer.clear();
                *fragmented_text = false;
                writer.close_with_frame(WsFrame {
                    frame_type: WsFrameType::Close,
                    payload: frame.payload,
                    fin: true,
                })?;
                return Err(TransportError::Closed);
            }
            WsFrameType::Ping => {
                if let Err(error) = writer.send_frame(&WsFrame::pong(frame.payload)) {
                    terminate_split_receive(writer, fragment_buffer, fragmented_text, closed);
                    return Err(error);
                }
            }
            WsFrameType::Pong => {}
        }
    }
}

/// Independently owned server-side WebSocket ingress.
pub struct WsServerRecvHalf<R, W> {
    reader: WsReader<R>,
    writer: SharedWsWriter<WsWriter<W>>,
    codec: Codec,
    fragment_buffer: Vec<u8>,
    fragmented_text: bool,
    max_message_size: usize,
    closed: bool,
}

impl<R: Read, W: Write> TransportRecvHalf for WsServerRecvHalf<R, W> {
    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        recv_split_message(
            &mut self.reader,
            &self.writer,
            &self.codec,
            &mut self.fragment_buffer,
            &mut self.fragmented_text,
            self.max_message_size,
            &mut self.closed,
            cx,
        )
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.closed = true;
        self.fragment_buffer.clear();
        self.fragmented_text = false;
        self.writer.close_with_frame(WsFrame::close())
    }
}

/// Independently owned server-side WebSocket egress.
pub struct WsServerSendHalf<W> {
    writer: SharedWsWriter<WsWriter<W>>,
    codec: Codec,
}

impl<W: Write + Send> TransportSendHalf for WsServerSendHalf<W> {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        send_split_message(&self.writer, &self.codec, cx, message)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.writer.close_with_frame(WsFrame::close())
    }
}

/// Independently owned client-side WebSocket ingress.
pub struct WsClientRecvHalf<R, W> {
    reader: WsReader<R>,
    writer: SharedWsWriter<WsClientWriter<W>>,
    codec: Codec,
    fragment_buffer: Vec<u8>,
    fragmented_text: bool,
    max_message_size: usize,
    closed: bool,
}

impl<R: Read, W: Write> TransportRecvHalf for WsClientRecvHalf<R, W> {
    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        recv_split_message(
            &mut self.reader,
            &self.writer,
            &self.codec,
            &mut self.fragment_buffer,
            &mut self.fragmented_text,
            self.max_message_size,
            &mut self.closed,
            cx,
        )
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.closed = true;
        self.fragment_buffer.clear();
        self.fragmented_text = false;
        self.writer.close_with_frame(WsFrame::close())
    }
}

/// Independently owned client-side WebSocket egress.
pub struct WsClientSendHalf<W> {
    writer: SharedWsWriter<WsClientWriter<W>>,
    codec: Codec,
}

impl<W: Write + Send> TransportSendHalf for WsClientSendHalf<W> {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        send_split_message(&self.writer, &self.codec, cx, message)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.writer.close_with_frame(WsFrame::close())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CodecError;
    use fastmcp_protocol::RequestId;
    use std::io::Cursor;

    #[test]
    fn test_frame_type_opcode_roundtrip() {
        for frame_type in [
            WsFrameType::Text,
            WsFrameType::Binary,
            WsFrameType::Close,
            WsFrameType::Ping,
            WsFrameType::Pong,
        ] {
            let opcode = frame_type.opcode();
            let parsed = WsFrameType::from_opcode(opcode);
            assert_eq!(parsed, Some(frame_type));
        }
    }

    #[test]
    fn test_frame_text() {
        let frame = WsFrame::text("hello");
        assert_eq!(frame.frame_type, WsFrameType::Text);
        assert_eq!(frame.as_text().unwrap(), "hello");
        assert!(frame.fin);
    }

    #[test]
    fn test_frame_close() {
        let frame = WsFrame::close();
        assert_eq!(frame.frame_type, WsFrameType::Close);
        assert!(frame.payload.is_empty());
        assert!(frame.fin);
    }

    #[test]
    fn test_frame_ping_pong() {
        let ping = WsFrame::ping(vec![1, 2, 3]);
        assert_eq!(ping.frame_type, WsFrameType::Ping);
        assert_eq!(ping.payload, vec![1, 2, 3]);

        let pong = WsFrame::pong(vec![1, 2, 3]);
        assert_eq!(pong.frame_type, WsFrameType::Pong);
        assert_eq!(pong.payload, vec![1, 2, 3]);
    }

    #[test]
    fn test_write_read_small_frame() {
        let mut buffer = Vec::new();

        // Write frame (server-side, unmasked)
        {
            let mut writer = WsWriter::new(&mut buffer);
            let frame = WsFrame::text("hello");
            writer.write_frame(&frame).unwrap();
        }

        // Read frame back (client-side, accepts unmasked)
        let mut reader = WsReader::new_client(Cursor::new(buffer));
        let frame = reader.read_frame().unwrap();

        assert_eq!(frame.frame_type, WsFrameType::Text);
        assert_eq!(frame.as_text().unwrap(), "hello");
        assert!(frame.fin);
    }

    #[test]
    fn test_write_read_medium_frame() {
        // 200 bytes - uses extended length (126)
        let payload = "x".repeat(200);
        let mut buffer = Vec::new();

        {
            let mut writer = WsWriter::new(&mut buffer);
            let frame = WsFrame::text(&payload);
            writer.write_frame(&frame).unwrap();
        }

        // Client-side reader accepts unmasked frames
        let mut reader = WsReader::new_client(Cursor::new(buffer));
        let frame = reader.read_frame().unwrap();

        assert_eq!(frame.as_text().unwrap(), payload);
    }

    #[test]
    fn test_write_read_large_frame() {
        // 70000 bytes - uses extended length (127)
        let payload = "x".repeat(70000);
        let mut buffer = Vec::new();

        {
            let mut writer = WsWriter::new(&mut buffer);
            let frame = WsFrame::text(&payload);
            writer.write_frame(&frame).unwrap();
        }

        // Client-side reader accepts unmasked frames
        let mut reader = WsReader::new_client(Cursor::new(buffer));
        let frame = reader.read_frame().unwrap();

        assert_eq!(frame.as_text().unwrap(), payload);
    }

    #[test]
    fn test_client_writer_masks_frames() {
        let mut buffer = Vec::new();

        {
            let mut writer = WsClientWriter::new(&mut buffer);
            let frame = WsFrame::text("hi");
            writer.write_frame(&frame).unwrap();
        }

        assert_eq!(buffer.len(), 8);
        assert_eq!(buffer[0], 0x81);
        assert_ne!(buffer[1] & 0x80, 0, "Mask bit should be set for client");
        assert_eq!(buffer[6], b'h' ^ buffer[2]);
        assert_eq!(buffer[7], b'i' ^ buffer[3]);

        let mut reader = WsReader::new(Cursor::new(buffer));
        assert_eq!(reader.read_frame().unwrap().as_text().unwrap(), "hi");
    }

    #[test]
    fn client_writer_applies_injected_mask_exactly_once() {
        let mut buffer = Vec::new();
        let draw_calls = std::cell::Cell::new(0);

        {
            let mut writer = WsClientWriter::new(&mut buffer);
            writer
                .write_frame_with_mask_draw(&WsFrame::text("hi"), || {
                    draw_calls.set(draw_calls.get() + 1);
                    Ok([0x12, 0x34, 0x56, 0x78])
                })
                .unwrap();
        }

        assert_eq!(draw_calls.get(), 1);
        assert_eq!(buffer, vec![0x81, 0x82, 0x12, 0x34, 0x56, 0x78, 0x7a, 0x5d]);
    }

    #[test]
    fn client_writer_mask_failure_precedes_all_output() {
        #[derive(Debug)]
        struct ForcedMaskDrawError;

        impl std::fmt::Display for ForcedMaskDrawError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("forced WebSocket mask draw failure")
            }
        }

        impl std::error::Error for ForcedMaskDrawError {}

        let mut buffer = Vec::new();
        let draw_calls = std::cell::Cell::new(0);
        let result = {
            let mut writer = WsClientWriter::new(&mut buffer);
            writer.write_frame_with_mask_draw(&WsFrame::text("hi"), || {
                draw_calls.set(draw_calls.get() + 1);
                Err(map_mask_draw_error(ForcedMaskDrawError))
            })
        };

        let error = match result {
            Err(TransportError::Io(error)) => error,
            other => panic!("expected mask-draw I/O error, got {other:?}"),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        // `io::Error::source()` reflects the wrapped error's own source chain,
        // which is empty here. `get_ref()` is the contract for recovering the
        // directly wrapped typed error.
        assert!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<ForcedMaskDrawError>())
                .is_some()
        );
        assert_eq!(draw_calls.get(), 1);
        assert!(buffer.is_empty());
    }

    #[test]
    fn client_writer_draws_fresh_mask_for_every_frame_including_empty() {
        let mut buffer = Vec::new();
        let draw_calls = std::cell::Cell::new(0);

        {
            let mut writer = WsClientWriter::new(&mut buffer);
            writer
                .write_frame_with_mask_draw(&WsFrame::text("x"), || {
                    draw_calls.set(draw_calls.get() + 1);
                    Ok([0x01, 0x02, 0x03, 0x04])
                })
                .unwrap();
            writer
                .write_frame_with_mask_draw(&WsFrame::close(), || {
                    draw_calls.set(draw_calls.get() + 1);
                    Ok([0x05, 0x06, 0x07, 0x08])
                })
                .unwrap();
        }

        assert_eq!(draw_calls.get(), 2);
        assert_eq!(&buffer[..6], &[0x81, 0x81, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(buffer[6], b'x' ^ 0x01);
        assert_eq!(&buffer[7..], &[0x88, 0x80, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_read_masked_frame() {
        // Build a masked frame manually
        let payload = b"test";
        let mask = [0x12, 0x34, 0x56, 0x78];
        let masked_payload: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();

        let mut buffer = Vec::new();
        buffer.push(0x81); // FIN + Text opcode
        buffer.push(0x80 | payload.len() as u8); // Mask bit + length
        buffer.extend_from_slice(&mask);
        buffer.extend_from_slice(&masked_payload);

        let mut reader = WsReader::new(Cursor::new(buffer));
        let frame = reader.read_frame().unwrap();

        assert_eq!(frame.as_text().unwrap(), "test");
    }

    #[test]
    fn test_reader_rejects_oversized_frame() {
        // Build a masked frame for server-side testing
        let mask = [0x12, 0x34, 0x56, 0x78];
        let payload = b"hey";
        let masked: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();

        let mut buffer = Vec::new();
        buffer.push(0x81); // FIN + Text opcode
        buffer.push(0x80 | 0x03); // Mask bit + 3-byte payload
        buffer.extend_from_slice(&mask);
        buffer.extend_from_slice(&masked);

        let mut reader = WsReader::new(Cursor::new(buffer));
        reader.max_frame_size = 2;

        let err = reader.read_frame().unwrap_err();
        assert!(matches!(
            err,
            TransportError::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn test_reader_rejects_control_frame_over_125() {
        let mut buffer = Vec::new();
        buffer.push(0x89); // FIN + Ping opcode
        buffer.push(0x80 | 126); // Mask bit + Extended length (not allowed for control frames)
        buffer.extend_from_slice(&126u16.to_be_bytes());
        buffer.extend_from_slice(&[0, 0, 0, 0]); // Mask key

        let mut reader = WsReader::new(Cursor::new(buffer));
        let err = reader.read_frame().unwrap_err();
        assert!(matches!(
            err,
            TransportError::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn test_reader_rejects_fragmented_control_frame() {
        let mut buffer = Vec::new();
        buffer.push(0x09); // FIN=0 + Ping opcode
        buffer.push(0x80); // Mask bit + Zero payload
        buffer.extend_from_slice(&[0, 0, 0, 0]); // Mask key

        let mut reader = WsReader::new(Cursor::new(buffer));
        let err = reader.read_frame().unwrap_err();
        assert!(matches!(
            err,
            TransportError::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn reader_rejects_reserved_opcode_before_reading_its_payload() {
        // The mask bit is direction-correct, but the reserved opcode is known
        // from these two bytes. No mask key or payload bytes are supplied.
        let mut reader = WsReader::new(Cursor::new(vec![0x83, 0x80 | 127]));

        let error = reader.read_frame().unwrap_err();

        assert!(matches!(
            error,
            TransportError::Io(ref source)
                if source.kind() == std::io::ErrorKind::InvalidData
                    && source.to_string().contains("Unknown WebSocket opcode")
        ));
    }

    #[test]
    fn reader_rejects_non_minimal_extended_payload_lengths() {
        let mut sixteen_bit = vec![0x81, 0x80 | 126];
        sixteen_bit.extend_from_slice(&125_u16.to_be_bytes());
        let mut reader = WsReader::new(Cursor::new(sixteen_bit));
        let error = reader.read_frame().unwrap_err();
        assert!(error.to_string().contains("Non-minimal"));

        let mut sixty_four_bit = vec![0x81, 0x80 | 127];
        sixty_four_bit.extend_from_slice(&u64::from(u16::MAX).to_be_bytes());
        let mut reader = WsReader::new(Cursor::new(sixty_four_bit));
        let error = reader.read_frame().unwrap_err();
        assert!(error.to_string().contains("Non-minimal"));
    }

    #[test]
    fn reader_rejects_invalid_close_payloads() {
        let one_byte = build_masked_frame(0x08, true, &[0x03]);
        let mut reader = WsReader::new(Cursor::new(one_byte));
        assert!(
            reader
                .read_frame()
                .unwrap_err()
                .to_string()
                .contains("one-byte")
        );

        let reserved_status = build_masked_frame(0x08, true, &1005_u16.to_be_bytes());
        let mut reader = WsReader::new(Cursor::new(reserved_status));
        assert!(
            reader
                .read_frame()
                .unwrap_err()
                .to_string()
                .contains("status code")
        );

        let mut invalid_reason = 1000_u16.to_be_bytes().to_vec();
        invalid_reason.push(0xff);
        let invalid_reason = build_masked_frame(0x08, true, &invalid_reason);
        let mut reader = WsReader::new(Cursor::new(invalid_reason));
        assert!(
            reader
                .read_frame()
                .unwrap_err()
                .to_string()
                .contains("UTF-8")
        );
    }

    #[test]
    fn writers_reject_invalid_control_frames_before_emitting_bytes_or_drawing_a_mask() {
        let invalid = WsFrame {
            frame_type: WsFrameType::Ping,
            payload: vec![0; 126],
            fin: true,
        };
        let mut server_output = Vec::new();
        {
            let mut server_writer = WsWriter::new(&mut server_output);
            assert!(server_writer.write_frame(&invalid).is_err());
        }
        assert!(server_output.is_empty());

        let draw_calls = std::cell::Cell::new(0);
        let mut client_output = Vec::new();
        {
            let mut client_writer = WsClientWriter::new(&mut client_output);
            let error = client_writer.write_frame_with_mask_draw(&invalid, || {
                draw_calls.set(draw_calls.get() + 1);
                Ok([1, 2, 3, 4])
            });
            assert!(error.is_err());
        }
        assert_eq!(draw_calls.get(), 0);
        assert!(client_output.is_empty());
    }

    #[test]
    fn writers_reject_complete_invalid_utf8_text_before_emitting_bytes_or_drawing_a_mask() {
        let invalid = WsFrame {
            frame_type: WsFrameType::Text,
            payload: vec![0xff],
            fin: true,
        };

        let mut server_output = Vec::new();
        {
            let mut server_writer = WsWriter::new(&mut server_output);
            assert!(server_writer.write_frame(&invalid).is_err());
        }
        assert!(server_output.is_empty());

        let draw_calls = std::cell::Cell::new(0);
        let mut client_output = Vec::new();
        {
            let mut client_writer = WsClientWriter::new(&mut client_output);
            let error = client_writer.write_frame_with_mask_draw(&invalid, || {
                draw_calls.set(draw_calls.get() + 1);
                Ok([1, 2, 3, 4])
            });
            assert!(error.is_err());
        }
        assert_eq!(draw_calls.get(), 0);
        assert!(client_output.is_empty());
    }

    #[test]
    fn test_reader_rejects_rsv_bits() {
        let mut buffer = Vec::new();
        buffer.push(0xC1); // FIN + RSV1 + Text opcode
        buffer.push(0x80); // Mask bit set + Zero payload
        buffer.extend_from_slice(&[0, 0, 0, 0]); // Mask key

        let mut reader = WsReader::new(Cursor::new(buffer));
        let err = reader.read_frame().unwrap_err();
        assert!(matches!(
            err,
            TransportError::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn test_server_rejects_unmasked_client_frames() {
        // RFC 6455 Section 5.1: Server MUST reject unmasked frames
        let mut buffer = Vec::new();
        buffer.push(0x81); // FIN + Text opcode
        buffer.push(0x05); // NO mask bit + 5-byte payload
        buffer.extend_from_slice(b"hello");

        // Server-side reader (requires masking)
        let mut reader = WsReader::new(Cursor::new(buffer));
        let err = reader.read_frame().unwrap_err();
        assert!(matches!(
            err,
            TransportError::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn test_client_accepts_unmasked_server_frames() {
        // Clients receive unmasked frames from servers
        let mut buffer = Vec::new();
        buffer.push(0x81); // FIN + Text opcode
        buffer.push(0x05); // NO mask bit + 5-byte payload
        buffer.extend_from_slice(b"hello");

        // Client-side reader (does not require masking)
        let mut reader = WsReader::new_client(Cursor::new(buffer));
        let frame = reader.read_frame().unwrap();
        assert_eq!(frame.as_text().unwrap(), "hello");
    }

    #[test]
    fn test_client_reader_rejects_masked_server_frames_for_every_frame_class() {
        let cases: [(&str, u8, bool, &[u8]); 7] = [
            ("text", 0x01, true, b"text"),
            ("fragmented text", 0x01, false, b"fragment"),
            ("continuation", 0x00, true, b"continuation"),
            ("binary", 0x02, true, b"binary"),
            ("close", 0x08, true, b""),
            ("ping", 0x09, true, b"ping"),
            ("pong", 0x0A, true, b"pong"),
        ];

        for (name, opcode, fin, payload) in cases {
            let mut reader =
                WsReader::new_client(Cursor::new(build_masked_frame(opcode, fin, payload)));
            let error = match reader.read_frame() {
                Ok(frame) => panic!("client accepted masked {name} frame: {frame:?}"),
                Err(error) => error,
            };

            assert!(
                matches!(
                    error,
                    TransportError::Io(ref source)
                        if source.kind() == std::io::ErrorKind::InvalidData
                ),
                "masked {name} frame did not fail with InvalidData: {error:?}"
            );
        }
    }

    /// Helper to build a masked WebSocket frame for testing server-side code.
    ///
    fn build_masked_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mask = [0x12, 0x34, 0x56, 0x78];
        let masked: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();

        let mut frame = Vec::new();
        let byte1 = if fin { 0x80 } else { 0x00 } | opcode;
        frame.push(byte1);

        // Mask bit + payload length (including extended length encodings).
        let payload_len = payload.len();
        if payload_len < 126 {
            frame.push(0x80 | payload_len as u8);
        } else if payload_len < 65536 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }

        frame.extend_from_slice(&mask);
        frame.extend_from_slice(&masked);
        frame
    }

    fn build_unmasked_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.push((if fin { 0x80 } else { 0x00 }) | opcode);
        assert!(
            payload.len() < 126,
            "test helper only supports short frames"
        );
        frame.push(payload.len() as u8);
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn client_transport_rejects_masked_server_data_frame() {
        let input =
            build_masked_frame(0x01, true, br#"{"jsonrpc":"2.0","method":"masked","id":1}"#);
        let mut transport = WsClientTransport::new(Cursor::new(input), Vec::new());

        let error = transport.recv(&Cx::for_testing()).unwrap_err();

        assert!(matches!(
            error,
            TransportError::Io(ref source)
                if source.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn client_transport_rejects_masked_server_fragment_before_buffering() {
        let input = build_masked_frame(0x01, false, b"fragment");
        let mut transport = WsClientTransport::new(Cursor::new(input), Vec::new());

        let error = transport.recv(&Cx::for_testing()).unwrap_err();

        assert!(matches!(
            error,
            TransportError::Io(ref source)
                if source.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(!transport.fragmented_text);
        assert!(transport.fragment_buffer.is_empty());
    }

    #[test]
    fn client_transport_rejects_masked_server_ping_without_replying() {
        let input = build_masked_frame(0x09, true, b"ping");
        let mut transport = WsClientTransport::new(Cursor::new(input), Vec::new());

        let error = transport.recv(&Cx::for_testing()).unwrap_err();

        assert!(matches!(
            error,
            TransportError::Io(ref source)
                if source.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(transport.writer.writer.is_empty());
    }

    #[test]
    fn server_accepts_fragmented_text_with_empty_first_fragment() {
        let payload = br#"{"jsonrpc":"2.0","method":"empty-first","id":1}"#;
        let mut input = build_masked_frame(0x01, false, b"");
        input.extend(build_masked_frame(0x00, true, payload));
        let mut transport = WsTransport::new(Cursor::new(input), Vec::new());

        let message = transport.recv(&Cx::for_testing()).unwrap();

        let JsonRpcMessage::Request(request) = message else {
            panic!("expected request");
        };
        assert_eq!(request.method, "empty-first");
    }

    #[test]
    fn client_accepts_fragmented_text_with_empty_first_fragment() {
        let payload = br#"{"jsonrpc":"2.0","method":"empty-first","id":1}"#;
        let mut input = build_unmasked_frame(0x01, false, b"");
        input.extend(build_unmasked_frame(0x00, true, payload));
        let mut transport = WsClientTransport::new(Cursor::new(input), Vec::new());

        let message = transport.recv(&Cx::for_testing()).unwrap();

        let JsonRpcMessage::Request(request) = message else {
            panic!("expected request");
        };
        assert_eq!(request.method, "empty-first");
    }

    #[test]
    fn websocket_split_halves_preserve_full_duplex_server_and_client_directions() {
        let cx = Cx::for_testing();
        let server_request = br#"{"jsonrpc":"2.0","method":"server/split","id":7}"#;
        let (mut server_recv, mut server_send) = WsTransport::new(
            Cursor::new(build_masked_frame(0x01, true, server_request)),
            Vec::new(),
        )
        .into_split();

        let JsonRpcMessage::Request(request) = server_recv.recv(&cx).expect("server split receive")
        else {
            panic!("server split must preserve a client request");
        };
        assert_eq!(request.method, "server/split");
        server_send
            .send(
                &cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    RequestId::Number(7),
                    serde_json::json!({"server": true}),
                )),
            )
            .expect("server split response");
        server_send.close().expect("server split close");

        let server_output = server_send
            .writer
            .inner
            .lock()
            .expect("server split writer lock")
            .writer
            .writer
            .clone();
        let mut client_reader = WsReader::new_client(Cursor::new(server_output));
        let response = client_reader
            .read_frame()
            .expect("unmasked server response");
        assert_eq!(response.frame_type, WsFrameType::Text);
        assert_eq!(
            client_reader.read_frame().expect("server close").frame_type,
            WsFrameType::Close
        );

        let client_response = br#"{"jsonrpc":"2.0","id":8,"result":{"client":true}}"#;
        let (mut client_recv, mut client_send) = WsClientTransport::new(
            Cursor::new(build_unmasked_frame(0x01, true, client_response)),
            Vec::new(),
        )
        .into_split();

        let JsonRpcMessage::Response(response) =
            client_recv.recv(&cx).expect("client split receive")
        else {
            panic!("client split must preserve a server response");
        };
        assert_eq!(response.id, Some(RequestId::Number(8)));
        client_send
            .send(
                &cx,
                &JsonRpcMessage::Request(JsonRpcRequest::new("client/split", None, 8_i64)),
            )
            .expect("client split request");
        client_send.close().expect("client split close");

        let client_output = client_send
            .writer
            .inner
            .lock()
            .expect("client split writer lock")
            .writer
            .writer
            .clone();
        let mut server_reader = WsReader::new(Cursor::new(client_output));
        let request = server_reader.read_frame().expect("masked client request");
        assert_eq!(request.frame_type, WsFrameType::Text);
        assert_eq!(
            server_reader.read_frame().expect("client close").frame_type,
            WsFrameType::Close
        );
    }

    #[test]
    fn websocket_split_preserves_server_and_client_codec_limits() {
        let mut server = WsTransport::new(Cursor::new(Vec::new()), Vec::new());
        server.codec.set_max_message_size(128);
        let (server_recv, server_send) = server.into_split();
        assert_eq!(server_recv.codec.max_message_size(), 128);
        assert_eq!(server_send.codec.max_message_size(), 128);

        let mut client = WsClientTransport::new(Cursor::new(Vec::new()), Vec::new());
        client.codec.set_max_message_size(256);
        let (client_recv, client_send) = client.into_split();
        assert_eq!(client_recv.codec.max_message_size(), 256);
        assert_eq!(client_send.codec.max_message_size(), 256);
    }

    #[test]
    fn websocket_split_cancelled_send_writes_no_frame() {
        let (_recv_half, mut send_half) =
            WsTransport::new(Cursor::new(Vec::new()), Vec::new()).into_split();
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        assert!(matches!(
            send_half.send(
                &cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    RequestId::Number(1),
                    serde_json::json!({"cancelled": false}),
                )),
            ),
            Err(TransportError::Cancelled)
        ));
        assert!(
            send_half
                .writer
                .inner
                .lock()
                .expect("split writer lock")
                .writer
                .writer
                .is_empty()
        );
    }

    #[test]
    fn websocket_split_close_makes_pending_ingress_terminal() {
        let request = br#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
        let (mut recv_half, mut send_half) = WsTransport::new(
            Cursor::new(build_masked_frame(0x01, true, request)),
            Vec::new(),
        )
        .into_split();

        send_half.close().expect("close split writer");
        assert!(matches!(
            recv_half.recv(&Cx::for_testing()),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn websocket_split_terminal_close_wins_over_cancelled_context() {
        let (mut recv_half, mut send_half) =
            WsTransport::new(Cursor::new(Vec::new()), Vec::new()).into_split();
        send_half.close().expect("close split writer");
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        assert!(matches!(recv_half.recv(&cx), Err(TransportError::Closed)));
        assert!(matches!(
            send_half.send(
                &cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    RequestId::Number(1),
                    serde_json::json!({"closed": true}),
                )),
            ),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn websocket_server_split_rejects_unmasked_client_frame_without_control_write() {
        let request = br#"{"jsonrpc":"2.0","method":"server/split","id":7}"#;
        let (mut recv_half, mut send_half) = WsTransport::new(
            Cursor::new(build_unmasked_frame(0x01, true, request)),
            Vec::new(),
        )
        .into_split();

        let error = recv_half.recv(&Cx::for_testing()).unwrap_err();
        assert!(matches!(
            error,
            TransportError::Io(ref source) if source.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            send_half.send(
                &Cx::for_testing(),
                &JsonRpcMessage::Request(JsonRpcRequest::new("client/split", None, 8_i64)),
            ),
            Err(TransportError::Closed)
        ));
        assert!(
            send_half
                .writer
                .inner
                .lock()
                .expect("server split writer lock")
                .writer
                .writer
                .is_empty()
        );
    }

    #[test]
    fn server_rejects_invalid_utf8_text_with_close_1007_and_latches_closed() {
        let input = build_masked_frame(0x01, true, &[0xff]);
        let mut transport = WsTransport::new(Cursor::new(input), Vec::new());

        let error = transport.recv(&Cx::for_testing()).unwrap_err();

        assert!(matches!(
            error,
            TransportError::Io(ref source)
                if source.kind() == std::io::ErrorKind::InvalidData
                    && source.to_string().contains("UTF-8")
        ));
        assert!(transport.closed);
        assert!(transport.fragment_buffer.is_empty());
        assert!(!transport.fragmented_text);
        assert_eq!(transport.writer.writer, [0x88, 0x02, 0x03, 0xef]);

        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        assert!(matches!(
            transport.recv(&cancelled),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn client_rejects_invalid_utf8_text_with_masked_close_1007_and_latches_closed() {
        let input = build_unmasked_frame(0x01, true, &[0xff]);
        let mut transport = WsClientTransport::new(Cursor::new(input), Vec::new());

        let error = transport.recv(&Cx::for_testing()).unwrap_err();

        assert!(matches!(
            error,
            TransportError::Io(ref source)
                if source.kind() == std::io::ErrorKind::InvalidData
                    && source.to_string().contains("UTF-8")
        ));
        assert!(transport.closed);
        assert!(transport.fragment_buffer.is_empty());
        assert!(!transport.fragmented_text);

        let mut close_reader = WsReader::new(Cursor::new(transport.writer.writer.as_slice()));
        let close = close_reader.read_frame().unwrap();
        assert_eq!(close.frame_type, WsFrameType::Close);
        assert_eq!(close.payload, 1007_u16.to_be_bytes());
    }

    #[test]
    fn fragmented_invalid_utf8_is_rejected_only_after_complete_message_assembly() {
        let mut input = build_masked_frame(0x01, false, &[0xf0]);
        input.extend(build_masked_frame(0x00, true, &[0x28]));
        let mut transport = WsTransport::new(Cursor::new(input), Vec::new());

        assert!(matches!(
            transport.recv(&Cx::for_testing()),
            Err(TransportError::Io(ref source))
                if source.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(transport.closed);
        assert!(transport.fragment_buffer.is_empty());
        assert!(!transport.fragmented_text);
        assert_eq!(transport.writer.writer, [0x88, 0x02, 0x03, 0xef]);
    }

    #[test]
    fn terminal_frame_read_error_clears_fragment_state() {
        let mut input = build_masked_frame(0x01, false, b"prefix");
        // Reserved opcode is a terminal framing error.
        input.extend(build_masked_frame(0x03, true, b"bad"));
        let mut transport = WsTransport::new(Cursor::new(input), Vec::new());

        assert!(matches!(
            transport.recv(&Cx::for_testing()),
            Err(TransportError::Io(_))
        ));
        assert!(transport.closed);
        assert!(transport.fragment_buffer.is_empty());
        assert!(!transport.fragmented_text);
    }

    #[test]
    fn test_fragmented_message_size_limit() {
        // Build masked frames (client -> server)
        let mut buffer = Vec::new();
        // Text frame start (FIN=0, opcode=Text)
        buffer.extend(build_masked_frame(0x01, false, b"hello"));
        // Continuation frame end (FIN=1, opcode=Continuation)
        buffer.extend(build_masked_frame(0x00, true, b"world"));

        let cx = Cx::for_testing();
        let writer: Vec<u8> = Vec::new();
        let mut transport = WsTransport::new(Cursor::new(buffer), writer);
        transport.max_message_size = 8;

        let err = transport.recv(&cx).unwrap_err();
        assert!(matches!(
            err,
            TransportError::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn test_transport_rejects_escaped_duplicate_object_member() {
        let payload = br#"{"jsonrpc":"2.0","method":"first","m\u0065thod":"second","id":1}"#;
        let frame = build_masked_frame(0x01, true, payload);
        let writer = Vec::new();
        let mut transport = WsTransport::new(Cursor::new(frame), writer);

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
    fn test_rejects_interleaved_binary_during_fragmentation() {
        // RFC 6455 Section 5.4: Data frames MUST NOT be interleaved
        // Build masked frames (client -> server)
        let mut buffer = Vec::new();
        // Text frame start (FIN=0, opcode=Text)
        buffer.extend(build_masked_frame(0x01, false, b"hello"));
        // Binary frame (interleaved - MUST be rejected)
        buffer.extend(build_masked_frame(0x02, true, b"bad"));

        let cx = Cx::for_testing();
        let writer: Vec<u8> = Vec::new();
        let mut transport = WsTransport::new(Cursor::new(buffer), writer);

        let err = transport.recv(&cx).unwrap_err();
        assert!(matches!(
            err,
            TransportError::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn test_transport_roundtrip() {
        use fastmcp_protocol::RequestId;

        // Create a pipe using in-memory buffers
        // Simulating server -> client: server writes unmasked, client reads unmasked
        let mut write_buf = Vec::new();

        // Server writes a request (unmasked)
        {
            let cx = Cx::for_testing();
            let reader: &[u8] = &[];
            let mut transport = WsTransport::new(reader, &mut write_buf);

            let request = JsonRpcRequest {
                jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
                id: Some(RequestId::Number(1)),
                method: "test".to_string(),
                params: None,
            };

            transport.send_request(&cx, &request).unwrap();
        }

        // Client reads the request (accepts unmasked frames from server)
        {
            let cx = Cx::for_testing();
            let writer: Vec<u8> = Vec::new();
            let mut transport = WsClientTransport::new(Cursor::new(write_buf), writer);

            let msg = transport.recv(&cx).unwrap();
            assert!(
                matches!(msg, JsonRpcMessage::Request(_)),
                "Expected request"
            );
            if let JsonRpcMessage::Request(req) = msg {
                assert_eq!(req.method, "test");
                assert_eq!(req.id, Some(RequestId::Number(1)));
            }
        }
    }

    #[test]
    fn test_close_frame_returns_closed_error() {
        // Build a masked close frame (simulating client -> server)
        let mut buffer = Vec::new();
        buffer.push(0x88); // FIN + Close opcode
        buffer.push(0x80); // Masked, 0 payload length
        buffer.extend_from_slice(&[0u8; 4]); // Mask key (zeros work for empty payload)

        let cx = Cx::for_testing();
        let writer: Vec<u8> = Vec::new();
        let mut transport = WsTransport::new(Cursor::new(buffer), writer);

        let result = transport.recv(&cx);
        assert!(matches!(result, Err(TransportError::Closed)));
        assert_eq!(transport.writer.writer, vec![0x88, 0x00]);

        let request = JsonRpcRequest::new("after-close", None, 1_i64);
        assert!(matches!(
            transport.send_request(&cx, &request),
            Err(TransportError::Closed)
        ));
        assert!(matches!(transport.recv(&cx), Err(TransportError::Closed)));
    }

    #[test]
    fn server_and_client_echo_valid_peer_close_payloads_before_latching_closed() {
        let mut payload = 1000_u16.to_be_bytes().to_vec();
        payload.extend_from_slice(b"done");

        let server_input = build_masked_frame(0x08, true, &payload);
        let mut server = WsTransport::new(Cursor::new(server_input), Vec::new());
        assert!(matches!(
            server.recv(&Cx::for_testing()),
            Err(TransportError::Closed)
        ));
        assert_eq!(server.writer.writer[0], 0x88);
        assert_eq!(usize::from(server.writer.writer[1]), payload.len());
        assert_eq!(&server.writer.writer[2..], payload);

        let client_input = build_unmasked_frame(0x08, true, &payload);
        let mut client = WsClientTransport::new(Cursor::new(client_input), Vec::new());
        assert!(matches!(
            client.recv(&Cx::for_testing()),
            Err(TransportError::Closed)
        ));
        let mut echoed = WsReader::new(Cursor::new(client.writer.writer.as_slice()));
        let echoed = echoed.read_frame().expect("client close reply is masked");
        assert_eq!(echoed.frame_type, WsFrameType::Close);
        assert_eq!(echoed.payload, payload);
    }

    #[test]
    fn test_ping_auto_pong() {
        // Build masked frames (simulating client -> server)
        let mut buffer = Vec::new();

        // Ping frame (masked, opcode 0x09)
        buffer.extend(build_masked_frame(0x09, true, b"ping"));

        // Text frame with JSON-RPC (masked, opcode 0x01)
        let text = r#"{"jsonrpc":"2.0","id":1,"method":"test"}"#;
        buffer.extend(build_masked_frame(0x01, true, text.as_bytes()));

        let mut response_buf = Vec::new();

        let cx = Cx::for_testing();
        let mut transport = WsTransport::new(Cursor::new(buffer), &mut response_buf);

        // Should skip ping (auto-pong) and return the text message
        let msg = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg, JsonRpcMessage::Request(_)),
            "Expected request"
        );
        if let JsonRpcMessage::Request(req) = msg {
            assert_eq!(req.method, "test");
        }

        // Check that pong was written
        assert!(!response_buf.is_empty());
        assert_eq!(response_buf[0] & 0x0F, 0x0A); // Pong opcode
    }

    // =========================================================================
    // E2E WebSocket Tests (bd-2kv / bd-2gyv)
    // =========================================================================

    #[test]
    fn e2e_ws_bidirectional_message_flow() {
        use fastmcp_protocol::RequestId;

        // Simulate a full bidirectional message flow
        // Server-side processing of multiple requests and responses

        let mut request_buffer = Vec::new();

        // Build multiple masked requests (client -> server)
        let req1 = r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#;
        let req2 = r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#;
        let req3 = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"test"},"id":3}"#;

        request_buffer.extend(build_masked_frame(0x01, true, req1.as_bytes()));
        request_buffer.extend(build_masked_frame(0x01, true, req2.as_bytes()));
        request_buffer.extend(build_masked_frame(0x01, true, req3.as_bytes()));

        let mut response_buffer = Vec::new();
        let cx = Cx::for_testing();

        {
            let mut transport = WsTransport::new(Cursor::new(request_buffer), &mut response_buffer);

            // Receive and process each request
            for expected_id in 1..=3 {
                let msg = transport.recv(&cx).unwrap();
                assert!(
                    matches!(msg, JsonRpcMessage::Request(_)),
                    "Expected request"
                );
                let JsonRpcMessage::Request(req) = msg else {
                    return;
                };

                assert_eq!(req.id, Some(RequestId::Number(expected_id)));

                // Send response
                let response = JsonRpcResponse {
                    jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
                    result: Some(serde_json::json!({"ok": true})),
                    error: None,
                    id: req.id,
                };
                transport.send_response(&cx, &response).unwrap();
            }
        }

        // Verify responses were written (unmasked for server -> client)
        assert!(!response_buffer.is_empty());
        // Each response should be a separate text frame
        #[allow(clippy::naive_bytecount)]
        let frame_count = response_buffer
            .iter()
            .filter(|&&b| b == 0x81) // FIN + Text opcode
            .count();
        assert_eq!(frame_count, 3, "Expected 3 response frames");
    }

    #[test]
    fn e2e_ws_fragmented_message_assembly() {
        // Test receiving a fragmented JSON-RPC message
        let full_msg =
            r#"{"jsonrpc":"2.0","method":"test","params":{"data":"hello world"},"id":1}"#;
        let mid = full_msg.len() / 2;

        let mut buffer = Vec::new();
        // First fragment (FIN=0, opcode=Text)
        buffer.extend(build_masked_frame(0x01, false, &full_msg.as_bytes()[..mid]));
        // Continuation fragment (FIN=1, opcode=Continuation)
        buffer.extend(build_masked_frame(0x00, true, &full_msg.as_bytes()[mid..]));

        let cx = Cx::for_testing();
        let writer: Vec<u8> = Vec::new();
        let mut transport = WsTransport::new(Cursor::new(buffer), writer);

        let msg = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg, JsonRpcMessage::Request(_)),
            "Expected request"
        );
        let JsonRpcMessage::Request(req) = msg else {
            return;
        };
        assert_eq!(req.method, "test");
        let params = req.params.unwrap();
        assert_eq!(params.get("data").unwrap(), "hello world");
    }

    #[test]
    fn e2e_ws_interleaved_ping_during_operation() {
        // Test that ping/pong doesn't disrupt normal message flow
        let mut buffer = Vec::new();

        // Message 1
        buffer.extend(build_masked_frame(
            0x01,
            true,
            r#"{"jsonrpc":"2.0","method":"msg1","id":1}"#.as_bytes(),
        ));
        // Ping (should be handled automatically)
        buffer.extend(build_masked_frame(0x09, true, b"keepalive"));
        // Message 2
        buffer.extend(build_masked_frame(
            0x01,
            true,
            r#"{"jsonrpc":"2.0","method":"msg2","id":2}"#.as_bytes(),
        ));
        // Another ping
        buffer.extend(build_masked_frame(0x09, true, b"alive"));
        // Message 3
        buffer.extend(build_masked_frame(
            0x01,
            true,
            r#"{"jsonrpc":"2.0","method":"msg3","id":3}"#.as_bytes(),
        ));

        let mut response_buffer = Vec::new();
        let cx = Cx::for_testing();
        let mut transport = WsTransport::new(Cursor::new(buffer), &mut response_buffer);

        // Should receive all 3 messages, with pings handled automatically
        for i in 1..=3 {
            let msg = transport.recv(&cx).unwrap();
            assert!(
                matches!(msg, JsonRpcMessage::Request(_)),
                "Expected request"
            );
            let JsonRpcMessage::Request(req) = msg else {
                return;
            };
            assert_eq!(req.method, format!("msg{i}"));
        }

        // Verify pongs were sent - the response buffer should contain pong frames
        // Pong frames have opcode 0x0A and FIN bit set (0x8A)
        // Just verify we have some response data (pongs are there)
        assert!(
            !response_buffer.is_empty(),
            "Expected pong responses to be written"
        );
    }

    #[test]
    fn e2e_ws_graceful_close() {
        // Test graceful close handshake
        let mut buffer = Vec::new();
        // Message followed by close
        buffer.extend(build_masked_frame(
            0x01,
            true,
            r#"{"jsonrpc":"2.0","method":"last","id":1}"#.as_bytes(),
        ));
        buffer.extend(build_masked_frame(0x08, true, &[])); // Close frame

        let mut response_buffer = Vec::new();
        let cx = Cx::for_testing();
        let mut transport = WsTransport::new(Cursor::new(buffer), &mut response_buffer);

        // Receive the message
        let msg = transport.recv(&cx).unwrap();
        assert!(matches!(msg, JsonRpcMessage::Request(_)));

        // Next recv should return Closed
        let result = transport.recv(&cx);
        assert!(matches!(result, Err(TransportError::Closed)));
    }

    #[test]
    fn e2e_ws_cancellation_respected() {
        let buffer = build_masked_frame(
            0x01,
            true,
            r#"{"jsonrpc":"2.0","method":"test","id":1}"#.as_bytes(),
        );

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let writer: Vec<u8> = Vec::new();
        let mut transport = WsTransport::new(Cursor::new(buffer), writer);

        // Recv should respect cancellation
        let result = transport.recv(&cx);
        assert!(matches!(result, Err(TransportError::Cancelled)));
    }

    #[test]
    fn e2e_ws_send_cancellation_respected() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let reader: &[u8] = &[];
        let mut writer = Vec::new();
        let mut transport = WsTransport::new(reader, &mut writer);

        let request = JsonRpcRequest::new("test", None, 1i64);
        let result = transport.send_request(&cx, &request);
        assert!(matches!(result, Err(TransportError::Cancelled)));

        // Nothing should be written
        assert!(writer.is_empty());
    }

    #[test]
    fn e2e_ws_unicode_in_messages() {
        // Test Unicode handling in WebSocket text frames
        let unicode_msg =
            r#"{"jsonrpc":"2.0","method":"test","params":{"text":"Hello 世界 👋 éèê"},"id":1}"#;
        let buffer = build_masked_frame(0x01, true, unicode_msg.as_bytes());

        let cx = Cx::for_testing();
        let writer: Vec<u8> = Vec::new();
        let mut transport = WsTransport::new(Cursor::new(buffer), writer);

        let msg = transport.recv(&cx).unwrap();
        assert!(
            matches!(msg, JsonRpcMessage::Request(_)),
            "Expected request"
        );
        let JsonRpcMessage::Request(req) = msg else {
            return;
        };
        let params = req.params.unwrap();
        let text = params.get("text").unwrap().as_str().unwrap();
        assert!(text.contains("世界"));
        assert!(text.contains("👋"));
        assert!(text.contains("éèê"));
    }

    #[test]
    fn e2e_ws_client_server_full_flow() {
        use fastmcp_protocol::RequestId;

        // Full client-server flow with proper masking

        // 1. Client sends masked request
        let mut client_to_server = Vec::new();
        {
            let mut writer = WsClientWriter::new(&mut client_to_server);
            let request = r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#;
            writer.write_frame(&WsFrame::text(request)).unwrap();
        }

        // 2. Server receives and processes
        let mut server_response = Vec::new();
        {
            let cx = Cx::for_testing();
            let mut transport =
                WsTransport::new(Cursor::new(client_to_server.clone()), &mut server_response);

            let msg = transport.recv(&cx).unwrap();
            if let JsonRpcMessage::Request(req) = msg {
                assert_eq!(req.method, "initialize");

                // Send response (unmasked)
                let response = JsonRpcResponse {
                    jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
                    result: Some(serde_json::json!({"capabilities": {}})),
                    error: None,
                    id: Some(RequestId::Number(1)),
                };
                transport.send_response(&cx, &response).unwrap();
            }
        }

        // 3. Client receives response
        {
            let cx = Cx::for_testing();
            let mut transport =
                WsClientTransport::new(Cursor::new(server_response), Vec::<u8>::new());

            let msg = transport.recv(&cx).unwrap();
            assert!(
                matches!(msg, JsonRpcMessage::Response(_)),
                "Expected response"
            );
            let JsonRpcMessage::Response(resp) = msg else {
                return;
            };
            assert_eq!(resp.id, Some(RequestId::Number(1)));
            assert!(resp.result.is_some());
        }
    }

    #[test]
    fn ws_continuation_opcode_roundtrip() {
        let ft = WsFrameType::Continuation;
        assert_eq!(WsFrameType::from_opcode(ft.opcode()), Some(ft));
    }

    #[test]
    fn ws_unknown_opcode_returns_none() {
        assert_eq!(WsFrameType::from_opcode(0x03), None);
        assert_eq!(WsFrameType::from_opcode(0x0F), None);
    }

    #[test]
    fn ws_frame_as_text_non_utf8_returns_error() {
        let frame = WsFrame {
            frame_type: WsFrameType::Text,
            payload: vec![0xFF, 0xFE],
            fin: true,
        };
        assert!(frame.as_text().is_err());
    }

    #[test]
    fn ws_transport_close_sends_close_frame() {
        let reader: &[u8] = &[];
        let mut output = Vec::new();
        let mut transport = WsTransport::new(reader, &mut output);
        transport.close().unwrap();
        transport.close().expect("close is idempotent");

        let cx = Cx::for_testing();
        let request = JsonRpcRequest::new("after-close", None, 1_i64);
        assert!(matches!(
            transport.send_request(&cx, &request),
            Err(TransportError::Closed)
        ));
        assert!(matches!(transport.ping(), Err(TransportError::Closed)));
        assert!(matches!(transport.recv(&cx), Err(TransportError::Closed)));

        // Close frame: FIN + opcode 0x08 = 0x88, payload length 0
        assert_eq!(output, [0x88, 0x00]);
    }

    #[test]
    fn ws_transport_ping_sends_ping_frame() {
        let reader: &[u8] = &[];
        let mut output = Vec::new();
        let mut transport = WsTransport::new(reader, &mut output);
        transport.ping().unwrap();

        // Ping frame: FIN + opcode 0x09 = 0x89, payload length 0
        assert!(output.len() >= 2);
        assert_eq!(output[0], 0x89);
        assert_eq!(output[1], 0x00);
    }

    #[test]
    fn ws_client_transport_send_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let reader: &[u8] = &[];
        let mut writer = Vec::new();
        let mut transport = WsClientTransport::new(reader, &mut writer);

        let request = JsonRpcRequest::new("test", None, 1i64);
        let result = transport.send(&cx, &JsonRpcMessage::Request(request));
        assert!(matches!(result, Err(TransportError::Cancelled)));
        assert!(writer.is_empty());
    }

    #[test]
    fn ws_server_rejects_binary_message_outside_fragmentation() {
        let input = build_masked_frame(0x02, true, b"binary-data");
        let mut transport = WsTransport::new(Cursor::new(input), Vec::new());

        let error = transport.recv(&Cx::for_testing()).unwrap_err();

        assert!(matches!(
            error,
            TransportError::Io(ref source)
                if source.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn ws_client_rejects_binary_message_outside_fragmentation() {
        let input = build_unmasked_frame(0x02, true, b"binary-data");
        let mut transport = WsClientTransport::new(Cursor::new(input), Vec::new());

        let error = transport.recv(&Cx::for_testing()).unwrap_err();

        assert!(matches!(
            error,
            TransportError::Io(ref source)
                if source.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn ws_pong_frame_skipped() {
        // Pong frame followed by a text message
        let mut buffer = Vec::new();
        buffer.extend(build_masked_frame(0x0A, true, b"pong-payload"));
        buffer.extend(build_masked_frame(
            0x01,
            true,
            r#"{"jsonrpc":"2.0","method":"after_pong","id":2}"#.as_bytes(),
        ));

        let cx = Cx::for_testing();
        let writer: Vec<u8> = Vec::new();
        let mut transport = WsTransport::new(Cursor::new(buffer), writer);

        let msg = transport.recv(&cx).unwrap();
        let JsonRpcMessage::Request(req) = msg else {
            panic!("expected request");
        };
        assert_eq!(req.method, "after_pong");
    }

    #[test]
    fn websocket_mask_ownership_and_fallbacks_are_denied() {
        let source = include_str!("websocket.rs");
        let production = source
            .split_once("\n#[cfg(test)]")
            .map_or(source, |(production, _)| production);

        assert_eq!(production.matches("draw_websocket_mask()").count(), 1);
        assert_eq!(
            production.matches(".map_err(map_mask_draw_error)").count(),
            1
        );
        assert!(!production.contains("getrandom::"));
        assert!(!production.contains("draw_security_identifier"));

        let writer_impl_start = production
            .find("impl<W: Write> WsClientWriter<W> {")
            .expect("client writer implementation marker");
        let writer_impl_end = production[writer_impl_start..]
            .find("/// Client-side WebSocket transport.")
            .map(|offset| writer_impl_start + offset)
            .expect("client writer implementation end marker");
        let writer_impl = &production[writer_impl_start..writer_impl_end];
        let mask_decl = writer_impl
            .lines()
            .find(|line| line.contains("fn generate_mask()"))
            .expect("mask helper declaration")
            .trim_start();
        let injected_decl = writer_impl
            .lines()
            .find(|line| line.contains("fn write_frame_with_mask_draw"))
            .expect("injected mask helper declaration")
            .trim_start();
        assert!(mask_decl.starts_with("fn generate_mask()"));
        assert!(injected_decl.starts_with("fn write_frame_with_mask_draw"));
        assert_eq!(
            writer_impl
                .matches("self.write_frame_with_mask_draw(frame, Self::generate_mask)")
                .count(),
            1
        );

        for fallback in [
            "SystemTime",
            "Instant",
            "process::",
            "thread::",
            "Atomic",
            "rand::",
        ] {
            assert!(
                !writer_impl.contains(fallback),
                "WebSocket mask fallback found: {fallback}"
            );
        }
    }
}
