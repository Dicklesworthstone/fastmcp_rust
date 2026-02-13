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
//! It does NOT include HTTP upgrade handling - that should be done by
//! your HTTP server (e.g., hyper, axum, warp) before handing off the
//! upgraded connection to this transport.
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
//! # Cancel-Safety
//!
//! All operations check `cx.checkpoint()` before blocking I/O.
//! The transport integrates with asupersync's structured concurrency.

use std::io::{BufReader, Read, Write};

use asupersync::Cx;

use crate::{Codec, Transport, TransportError};
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};

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

/// WebSocket frame reader.
///
/// Reads WebSocket frames from an underlying byte stream.
/// Handles frame parsing according to RFC 6455.
pub struct WsReader<R> {
    reader: BufReader<R>,
    max_frame_size: usize,
    /// Whether to require masking (true for server-side, false for client-side).
    /// Per RFC 6455: servers MUST reject unmasked client frames.
    require_mask: bool,
}

impl<R: Read> WsReader<R> {
    /// Creates a new WebSocket reader for server-side use.
    ///
    /// Per RFC 6455, servers MUST reject unmasked frames from clients.
    pub fn new(reader: R) -> Self {
        Self::with_config(reader, true)
    }

    /// Creates a new WebSocket reader for client-side use.
    ///
    /// Clients receive unmasked frames from servers per RFC 6455.
    pub fn new_client(reader: R) -> Self {
        Self::with_config(reader, false)
    }

    /// Creates a new WebSocket reader with explicit mask requirement.
    fn with_config(reader: R, require_mask: bool) -> Self {
        Self {
            reader: BufReader::new(reader),
            max_frame_size: 10 * 1024 * 1024,
            require_mask,
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
        let mut payload_len = (header[1] & 0x7F) as u64;

        if rsv != 0 {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WebSocket RSV bits set but no extensions are supported",
            )));
        }

        // Extended payload length
        if payload_len == 126 {
            let mut ext = [0u8; 2];
            self.reader.read_exact(&mut ext)?;
            payload_len = u16::from_be_bytes(ext) as u64;
        } else if payload_len == 127 {
            let mut ext = [0u8; 8];
            self.reader.read_exact(&mut ext)?;
            payload_len = u64::from_be_bytes(ext);
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

        // RFC 6455 Section 5.1: Server MUST close connection if client frame is unmasked
        if self.require_mask && !masked {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Client frames MUST be masked per RFC 6455",
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

        let frame_type = WsFrameType::from_opcode(opcode).ok_or_else(|| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown WebSocket opcode: {opcode}"),
            ))
        })?;

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
    max_message_size: usize,
}

impl<R: Read, W: Write> WsTransport<R, W> {
    /// Creates a new WebSocket transport.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: WsReader::new(reader),
            writer: WsWriter::new(writer),
            codec: Codec::new(),
            fragment_buffer: Vec::new(),
            max_message_size: 10 * 1024 * 1024,
        }
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
        // Check cancellation
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

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
        self.writer.write_frame(&frame)?;

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
            // Check cancellation
            if cx.is_cancel_requested() {
                return Err(TransportError::Cancelled);
            }

            // Read next frame
            let frame = self.reader.read_frame()?;

            match frame.frame_type {
                WsFrameType::Text => {
                    if !self.fragment_buffer.is_empty() {
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
                    let next_len = self
                        .fragment_buffer
                        .len()
                        .saturating_add(frame.payload.len());
                    if next_len > self.max_message_size {
                        self.fragment_buffer.clear();
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Fragmented message exceeds size limit",
                        )));
                    }
                    self.fragment_buffer.extend(frame.payload);
                    continue;
                }
                WsFrameType::Continuation => {
                    if self.fragment_buffer.is_empty() {
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
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Fragmented message exceeds size limit",
                        )));
                    }
                    self.fragment_buffer.extend(frame.payload);

                    if frame.fin {
                        // End of fragmented message
                        let payload = std::mem::take(&mut self.fragment_buffer);
                        return self.decode_message(payload);
                    }

                    // More fragments to come
                    continue;
                }
                WsFrameType::Binary => {
                    // Per RFC 6455 Section 5.4, data frames MUST NOT be interleaved
                    // during fragmentation. Reject if we're inside a fragmented message.
                    if !self.fragment_buffer.is_empty() {
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Received Binary frame while inside fragmented message",
                        )));
                    }
                    // Binary frames not used by MCP, skip otherwise
                    continue;
                }
                WsFrameType::Close => {
                    return Err(TransportError::Closed);
                }
                WsFrameType::Ping => {
                    // Auto-respond with pong
                    let pong = WsFrame::pong(frame.payload);
                    self.writer.write_frame(&pong)?;
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
        // Parse JSON-RPC message
        let text = String::from_utf8(payload).map_err(|e| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid UTF-8: {e}"),
            ))
        })?;

        // Add newline for codec and decode
        let mut input = text.as_bytes().to_vec();
        input.push(b'\n');

        let messages = self.codec.decode(&input)?;
        if let Some(msg) = messages.into_iter().next() {
            return Ok(msg);
        }

        // This shouldn't happen for a complete message unless it was empty or just whitespace
        Err(TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Received empty message",
        )))
    }

    /// Sends a close frame and shuts down the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if I/O fails.
    pub fn close(&mut self) -> Result<(), TransportError> {
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
        let frame = WsFrame::ping(Vec::new());
        self.writer.write_frame(&frame)?;
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

impl<W: Write> WsClientWriter<W> {
    /// Creates a new client WebSocket writer.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Generates a cryptographically secure mask key.
    ///
    /// RFC 6455 Section 5.3: The masking key MUST be unpredictable.
    fn generate_mask() -> Result<[u8; 4], TransportError> {
        let mut mask = [0u8; 4];
        // Use CSPRNG for unpredictable mask keys per RFC 6455
        getrandom::fill(&mut mask).map_err(|e| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("getrandom failed: {e}"),
            ))
        })?;
        Ok(mask)
    }

    /// Writes a WebSocket frame with client masking.
    ///
    /// # Errors
    ///
    /// Returns an error if I/O fails.
    pub fn write_frame(&mut self, frame: &WsFrame) -> Result<(), TransportError> {
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
        let mask = Self::generate_mask()?;
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
    max_message_size: usize,
}

impl<R: Read, W: Write> WsClientTransport<R, W> {
    /// Creates a new client WebSocket transport.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            // Client receives unmasked frames from server
            reader: WsReader::new_client(reader),
            writer: WsClientWriter::new(writer),
            codec: Codec::new(),
            fragment_buffer: Vec::new(),
            max_message_size: 10 * 1024 * 1024,
        }
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
        // Check cancellation
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

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
        self.writer.write_frame(&frame)?;

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
            // Check cancellation
            if cx.is_cancel_requested() {
                return Err(TransportError::Cancelled);
            }

            // Read next frame
            let frame = self.reader.read_frame()?;

            match frame.frame_type {
                WsFrameType::Text => {
                    if !self.fragment_buffer.is_empty() {
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
                    let next_len = self
                        .fragment_buffer
                        .len()
                        .saturating_add(frame.payload.len());
                    if next_len > self.max_message_size {
                        self.fragment_buffer.clear();
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Fragmented message exceeds size limit",
                        )));
                    }
                    self.fragment_buffer.extend(frame.payload);
                    continue;
                }
                WsFrameType::Continuation => {
                    if self.fragment_buffer.is_empty() {
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
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Fragmented message exceeds size limit",
                        )));
                    }
                    self.fragment_buffer.extend(frame.payload);

                    if frame.fin {
                        // End of fragmented message
                        let payload = std::mem::take(&mut self.fragment_buffer);
                        return self.decode_message(payload);
                    }

                    // More fragments to come
                    continue;
                }
                WsFrameType::Binary => {
                    // Per RFC 6455 Section 5.4, data frames MUST NOT be interleaved
                    // during fragmentation. Reject if we're inside a fragmented message.
                    if !self.fragment_buffer.is_empty() {
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Received Binary frame while inside fragmented message",
                        )));
                    }
                    // Binary frames not used by MCP, skip otherwise
                    continue;
                }
                WsFrameType::Close => {
                    return Err(TransportError::Closed);
                }
                WsFrameType::Ping => {
                    // Respond with pong (masked)
                    let pong = WsFrame::pong(frame.payload);
                    self.writer.write_frame(&pong)?;
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
        let text = String::from_utf8(payload).map_err(|e| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid UTF-8: {e}"),
            ))
        })?;

        let mut input = text.as_bytes().to_vec();
        input.push(b'\n');

        let messages = self.codec.decode(&input)?;
        if let Some(msg) = messages.into_iter().next() {
            return Ok(msg);
        }

        Err(TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Received empty message",
        )))
    }

    /// Sends a close frame.
    ///
    /// # Errors
    ///
    /// Returns an error if I/O fails.
    pub fn close(&mut self) -> Result<(), TransportError> {
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

#[cfg(test)]
mod tests {
    use super::*;
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

        // Check that mask bit is set (second byte has 0x80 bit)
        assert!(buffer.len() >= 2);
        assert_ne!(buffer[1] & 0x80, 0, "Mask bit should be set for client");
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

        // Close frame: FIN + opcode 0x08 = 0x88, payload length 0
        assert!(output.len() >= 2);
        assert_eq!(output[0], 0x88);
        assert_eq!(output[1], 0x00);
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
    fn ws_binary_frame_skipped_outside_fragmentation() {
        // Binary frame (non-fragmented) followed by a text message
        let mut buffer = Vec::new();
        buffer.extend(build_masked_frame(0x02, true, b"binary-data"));
        buffer.extend(build_masked_frame(
            0x01,
            true,
            r#"{"jsonrpc":"2.0","method":"after_binary","id":1}"#.as_bytes(),
        ));

        let cx = Cx::for_testing();
        let writer: Vec<u8> = Vec::new();
        let mut transport = WsTransport::new(Cursor::new(buffer), writer);

        let msg = transport.recv(&cx).unwrap();
        let JsonRpcMessage::Request(req) = msg else {
            panic!("expected request");
        };
        assert_eq!(req.method, "after_binary");
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
}
