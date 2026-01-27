//! Transport layer for FastMCP.
//!
//! This crate provides transport implementations for MCP communication:
//! - **Stdio**: Standard input/output (primary transport)
//! - **SSE**: Server-Sent Events (HTTP-based streaming)
//! - **WebSocket**: Bidirectional web sockets
//!
//! # Transport Design
//!
//! Transports are designed around asupersync's principles:
//!
//! - **Cancel-correctness**: All operations check cancellation via `Cx::checkpoint()`
//! - **Two-phase sends**: Use reserve/commit pattern to prevent message loss
//! - **Budget awareness**: Operations respect the request's budget constraints
//!
//! # Wire Format
//!
//! MCP uses newline-delimited JSON (NDJSON) for message framing:
//! - Each message is a single line of JSON
//! - Messages are separated by `\n`
//! - UTF-8 encoding is required

#![forbid(unsafe_code)]
#![allow(dead_code)]

mod async_io;
mod codec;
pub mod event_store;
pub mod http;
pub mod memory;
pub mod sse;
mod stdio;
pub mod websocket;

pub use async_io::{AsyncLineReader, AsyncStdin, AsyncStdout};

pub use codec::{Codec, CodecError};
pub use stdio::{AsyncStdioTransport, StdioTransport};

use asupersync::Cx;
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};

/// Transport trait for cancel-correct message passing.
///
/// All transports must integrate with asupersync's capability context (`Cx`)
/// for cancellation checking and budget enforcement.
///
/// # Cancel-Safety
///
/// Implementations should:
/// - Call `cx.checkpoint()` before blocking operations
/// - Use two-phase patterns (reserve/commit) where applicable
/// - Respect budget constraints from the context
///
/// # Example
///
/// ```ignore
/// impl Transport for MyTransport {
///     fn send(&mut self, cx: &Cx, msg: &JsonRpcMessage) -> Result<(), TransportError> {
///         cx.checkpoint()?;  // Check for cancellation
///         let bytes = self.codec.encode(msg)?;
///         self.write_all(&bytes)?;
///         Ok(())
///     }
/// }
/// ```
pub trait Transport {
    /// Send a JSON-RPC message through this transport.
    ///
    /// # Cancel-Safety
    ///
    /// This operation checks for cancellation before sending.
    /// If cancelled, the message is not sent.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport is closed, an I/O error occurs,
    /// or the request has been cancelled.
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError>;

    /// Receive the next JSON-RPC message from this transport.
    ///
    /// # Cancel-Safety
    ///
    /// This operation checks for cancellation while waiting for data.
    /// If cancelled, returns `TransportError::Cancelled`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport is closed, an I/O error occurs,
    /// or the request has been cancelled.
    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError>;

    /// Send a request through this transport.
    ///
    /// Convenience method that wraps a request in a message.
    fn send_request(&mut self, cx: &Cx, request: &JsonRpcRequest) -> Result<(), TransportError> {
        self.send(cx, &JsonRpcMessage::Request(request.clone()))
    }

    /// Send a response through this transport.
    ///
    /// Convenience method that wraps a response in a message.
    fn send_response(&mut self, cx: &Cx, response: &JsonRpcResponse) -> Result<(), TransportError> {
        self.send(cx, &JsonRpcMessage::Response(response.clone()))
    }

    /// Close the transport gracefully.
    ///
    /// This flushes any pending data and releases resources.
    fn close(&mut self) -> Result<(), TransportError>;
}

/// Transport error types.
#[derive(Debug)]
pub enum TransportError {
    /// I/O error during read or write.
    Io(std::io::Error),
    /// Transport was closed (EOF or explicit close).
    Closed,
    /// Codec error (JSON parsing or encoding).
    Codec(CodecError),
    /// Connection timeout.
    Timeout,
    /// Request was cancelled.
    Cancelled,
}

impl TransportError {
    /// Returns true if this is a cancellation error.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, TransportError::Cancelled)
    }

    /// Returns true if this is an EOF/closed condition.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(self, TransportError::Closed)
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "I/O error: {e}"),
            TransportError::Closed => write!(f, "Transport closed"),
            TransportError::Codec(e) => write!(f, "Codec error: {e}"),
            TransportError::Timeout => write!(f, "Connection timeout"),
            TransportError::Cancelled => write!(f, "Request cancelled"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::Io(e) => Some(e),
            TransportError::Codec(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for TransportError {
    fn from(err: std::io::Error) -> Self {
        TransportError::Io(err)
    }
}

impl From<CodecError> for TransportError {
    fn from(err: CodecError) -> Self {
        TransportError::Codec(err)
    }
}

// =============================================================================
// Two-Phase Send Protocol
// =============================================================================

/// A permit for sending a message via two-phase commit.
///
/// This implements the reserve/commit pattern for cancel-safe message sending:
/// 1. **Reserve**: Allocate the permit (cancellable)
/// 2. **Commit**: Send the message (infallible after reserve)
///
/// # Cancel-Safety
///
/// The reservation phase is the cancellation point. Once you have a permit,
/// the send will complete. This ensures no message loss on cancellation:
///
/// ```ignore
/// // Cancel-safe pattern:
/// let permit = transport.reserve_send(cx)?;  // Can be cancelled here
/// permit.send(message);                       // Always succeeds
/// ```
///
/// # Example
///
/// ```ignore
/// use fastmcp_transport::{AsyncStdioTransport, TwoPhaseTransport};
/// use asupersync::Cx;
///
/// let mut transport = AsyncStdioTransport::new();
/// let cx = Cx::for_testing();
///
/// // Reserve a send slot (cancellable)
/// let permit = transport.reserve_send(&cx)?;
///
/// // At this point, we're committed - send is infallible
/// permit.send(&JsonRpcMessage::Request(request));
/// ```
pub struct SendPermit<'a, W: std::io::Write> {
    writer: &'a mut W,
    codec: &'a Codec,
}

impl<'a, W: std::io::Write> SendPermit<'a, W> {
    /// Creates a new send permit.
    ///
    /// This is an internal constructor. Use `TwoPhaseTransport::reserve_send()`
    /// to obtain a permit.
    fn new(writer: &'a mut W, codec: &'a Codec) -> Self {
        Self { writer, codec }
    }

    /// Commits the send by writing the message.
    ///
    /// This method is synchronous and, from the protocol's perspective,
    /// infallible after reservation. I/O errors are returned but the
    /// reservation is consumed regardless.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying write fails. However, the permit
    /// is consumed and the reservation is released.
    pub fn send(self, message: &JsonRpcMessage) -> Result<(), TransportError> {
        let bytes = match message {
            JsonRpcMessage::Request(req) => self.codec.encode_request(req)?,
            JsonRpcMessage::Response(resp) => self.codec.encode_response(resp)?,
        };

        self.writer.write_all(&bytes)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Commits the send by writing a request.
    ///
    /// Convenience method for sending a request directly.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying write fails.
    pub fn send_request(self, request: &JsonRpcRequest) -> Result<(), TransportError> {
        let bytes = self.codec.encode_request(request)?;
        self.writer.write_all(&bytes)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Commits the send by writing a response.
    ///
    /// Convenience method for sending a response directly.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying write fails.
    pub fn send_response(self, response: &JsonRpcResponse) -> Result<(), TransportError> {
        let bytes = self.codec.encode_response(response)?;
        self.writer.write_all(&bytes)?;
        self.writer.flush()?;
        Ok(())
    }
}

/// Extension trait for two-phase send operations.
///
/// This trait adds the reserve/commit pattern to transports. The pattern
/// ensures cancel-safety by making the reservation the cancellation point:
///
/// - **Reserve phase**: Check cancellation, allocate resources
/// - **Commit phase**: Actually send (synchronous, infallible from protocol perspective)
///
/// # Why Two-Phase?
///
/// Without two-phase:
/// ```ignore
/// // BROKEN: Can lose messages on cancel
/// async fn bad_send(cx: &Cx, msg: Message) {
///     let serialized = serialize(&msg);  // Work done
///     cx.checkpoint()?;                   // Cancel here = lost message!
///     writer.write(&serialized).await;
/// }
/// ```
///
/// With two-phase:
/// ```ignore
/// // CORRECT: Either fully sent or not started
/// async fn good_send(cx: &Cx, msg: Message) {
///     let permit = transport.reserve_send(cx)?;  // Cancel here = no work lost
///     // After reserve, commit is synchronous and infallible
///     permit.send(msg);
/// }
/// ```
pub trait TwoPhaseTransport: Transport {
    /// The writer type for permits.
    type Writer: std::io::Write;

    /// Reserve a send slot.
    ///
    /// This is the cancellation point for sends. If this succeeds, the
    /// subsequent `permit.send()` will complete.
    ///
    /// # Errors
    ///
    /// Returns `TransportError::Cancelled` if the request has been cancelled.
    fn reserve_send(&mut self, cx: &Cx) -> Result<SendPermit<'_, Self::Writer>, TransportError>;
}
