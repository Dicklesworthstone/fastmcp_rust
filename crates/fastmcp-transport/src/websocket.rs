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
}

impl<R: Read> WsReader<R> {
    /// Creates a new WebSocket reader.
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
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
        let opcode = header[0] & 0x0F;
        let masked = (header[1] & 0x80) != 0;
        let mut payload_len = (header[1] & 0x7F) as u64;

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
}

impl<R: Read, W: Write> WsTransport<R, W> {
    /// Creates a new WebSocket transport.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: WsReader::new(reader),
            writer: WsWriter::new(writer),
            codec: Codec::new(),
            fragment_buffer: Vec::new(),
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
                    // Binary frames not used by MCP, skip
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
/// frame writing with proper masking.
pub struct WsClientWriter<W> {
    writer: W,
    mask_counter: u32,
}

impl<W: Write> WsClientWriter<W> {
    /// Creates a new client WebSocket writer.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            mask_counter: 0,
        }
    }

    /// Generates a simple mask key.
    ///
    /// For production use, this should use a cryptographically secure RNG.
    /// This implementation uses a simple counter for deterministic testing.
    fn generate_mask(&mut self) -> [u8; 4] {
        self.mask_counter = self.mask_counter.wrapping_add(0x12345678);
        self.mask_counter.to_le_bytes()
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

        // Write mask key
        let mask = self.generate_mask();
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
}

impl<R: Read, W: Write> WsClientTransport<R, W> {
    /// Creates a new client WebSocket transport.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: WsReader::new(reader),
            writer: WsClientWriter::new(writer),
            codec: Codec::new(),
            fragment_buffer: Vec::new(),
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

        // Write frame
        {
            let mut writer = WsWriter::new(&mut buffer);
            let frame = WsFrame::text("hello");
            writer.write_frame(&frame).unwrap();
        }

        // Read frame back
        let mut reader = WsReader::new(Cursor::new(buffer));
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

        let mut reader = WsReader::new(Cursor::new(buffer));
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

        let mut reader = WsReader::new(Cursor::new(buffer));
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
    fn test_transport_roundtrip() {
        use fastmcp_protocol::RequestId;

        // Create a pipe using in-memory buffers
        let mut write_buf = Vec::new();

        // Write a request
        {
            let cx = Cx::for_testing();
            let reader: &[u8] = &[];
            let mut transport = WsTransport::new(reader, &mut write_buf);

            let request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(RequestId::Number(1)),
                method: "test".to_string(),
                params: None,
            };

            transport.send_request(&cx, &request).unwrap();
        }

        // Read it back
        {
            let cx = Cx::for_testing();
            let writer: Vec<u8> = Vec::new();
            let mut transport = WsTransport::new(Cursor::new(write_buf), writer);

            let msg = transport.recv(&cx).unwrap();
            match msg {
                JsonRpcMessage::Request(req) => {
                    assert_eq!(req.method, "test");
                    assert_eq!(req.id, Some(RequestId::Number(1)));
                }
                _ => panic!("Expected request"),
            }
        }
    }

    #[test]
    fn test_close_frame_returns_closed_error() {
        // Build a close frame
        let mut buffer = Vec::new();
        buffer.push(0x88); // FIN + Close opcode
        buffer.push(0x00); // No payload

        let cx = Cx::for_testing();
        let writer: Vec<u8> = Vec::new();
        let mut transport = WsTransport::new(Cursor::new(buffer), writer);

        let result = transport.recv(&cx);
        assert!(matches!(result, Err(TransportError::Closed)));
    }

    #[test]
    fn test_ping_auto_pong() {
        // Build a ping frame followed by a text frame
        let mut buffer = Vec::new();

        // Ping frame
        buffer.push(0x89); // FIN + Ping opcode
        buffer.push(0x04); // 4-byte payload
        buffer.extend_from_slice(b"ping");

        // Text frame with JSON-RPC
        let text = r#"{"jsonrpc":"2.0","id":1,"method":"test"}"#;
        buffer.push(0x81); // FIN + Text opcode
        buffer.push(text.len() as u8);
        buffer.extend_from_slice(text.as_bytes());

        let mut response_buf = Vec::new();

        let cx = Cx::for_testing();
        let mut transport = WsTransport::new(Cursor::new(buffer), &mut response_buf);

        // Should skip ping (auto-pong) and return the text message
        let msg = transport.recv(&cx).unwrap();
        match msg {
            JsonRpcMessage::Request(req) => {
                assert_eq!(req.method, "test");
            }
            _ => panic!("Expected request"),
        }

        // Check that pong was written
        assert!(!response_buf.is_empty());
        assert_eq!(response_buf[0] & 0x0F, 0x0A); // Pong opcode
    }
}
