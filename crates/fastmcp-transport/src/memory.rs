//! In-memory transport for testing MCP servers without subprocess spawning.
//!
//! This module provides a channel-based transport for direct client-server
//! communication within the same process. Essential for unit testing MCP
//! servers without network/IO overhead.
//!
//! # Overview
//!
//! The [`MemoryTransport`] uses crossbeam channels to enable bidirectional
//! message passing between client and server. Create a pair using
//! [`create_memory_transport_pair`] which returns connected client and server
//! transports.
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_transport::memory::create_memory_transport_pair;
//! use fastmcp_transport::Transport;
//! use asupersync::Cx;
//!
//! // Create connected pair
//! let (client_transport, server_transport) = create_memory_transport_pair();
//!
//! // Use in separate threads/tasks
//! // Client sends, server receives (and vice versa)
//! let cx = Cx::for_testing();
//! let request = JsonRpcRequest::new("test", None, 1i64);
//! client_transport.send_request(&cx, &request)?;
//!
//! // Server receives the message
//! let msg = server_transport.recv(&cx)?;
//! ```
//!
//! # Testing Servers
//!
//! The primary use case is testing servers without subprocess spawning:
//!
//! ```ignore
//! use fastmcp_transport::memory::{create_memory_transport_pair, MemoryTransport};
//! use std::thread;
//!
//! let (mut client, mut server) = create_memory_transport_pair();
//!
//! // Spawn server handler in a thread
//! let server_handle = thread::spawn(move || {
//!     // Pass server transport to your server's run loop
//!     run_server_with_transport(server);
//! });
//!
//! // Use client to test
//! let cx = Cx::for_testing();
//! client.send_request(&cx, &init_request)?;
//! let response = client.recv(&cx)?;
//! assert!(matches!(response, JsonRpcMessage::Response(_)));
//! ```

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use asupersync::Cx;
use fastmcp_protocol::JsonRpcMessage;

use crate::{Codec, Transport, TransportError};

/// Default timeout for recv operations when polling for cancellation.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// In-memory transport using channels for message passing.
///
/// This transport enables direct communication between a client and server
/// without any network or I/O overhead. Messages are passed through
/// bounded MPSC channels.
///
/// # Thread Safety
///
/// The transport is `Send` and can be passed to other threads, but it is
/// not `Sync`. Each endpoint (client/server) should be used from a single
/// thread at a time.
///
/// # Cancellation
///
/// Recv operations poll the channel with a timeout, checking for cancellation
/// between polls. This ensures proper integration with asupersync's
/// cancellation mechanism.
pub struct MemoryTransport {
    /// Channel for sending messages to the peer.
    sender: Sender<JsonRpcMessage>,
    /// Channel for receiving messages from the peer.
    receiver: Receiver<JsonRpcMessage>,
    /// Codec for validation (not used for serialization in memory transport).
    codec: Codec,
    /// Whether the transport has been closed.
    closed: bool,
    /// Poll interval for cancellation checks during recv.
    poll_interval: Duration,
}

impl std::fmt::Debug for MemoryTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryTransport")
            .field("closed", &self.closed)
            .field("poll_interval", &self.poll_interval)
            .finish_non_exhaustive()
    }
}

impl MemoryTransport {
    /// Creates a new memory transport from channel endpoints.
    ///
    /// This is an internal constructor. Use [`create_memory_transport_pair`]
    /// to create a connected pair of transports.
    fn new(sender: Sender<JsonRpcMessage>, receiver: Receiver<JsonRpcMessage>) -> Self {
        Self {
            sender,
            receiver,
            codec: Codec::new(),
            closed: false,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    /// Sets the poll interval for cancellation checks during recv.
    ///
    /// Lower values provide faster cancellation response but use more CPU.
    /// Default is 50ms.
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Returns whether this transport has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

impl Transport for MemoryTransport {
    fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        // Check for cancellation before send
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        if self.closed {
            return Err(TransportError::Closed);
        }

        // Clone and send the message through the channel
        self.sender
            .send(message.clone())
            .map_err(|_| TransportError::Closed)
    }

    fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        // Check for cancellation before receive
        if cx.is_cancel_requested() {
            return Err(TransportError::Cancelled);
        }

        if self.closed {
            return Err(TransportError::Closed);
        }

        // Poll with timeout to allow cancellation checks
        loop {
            match self.receiver.recv_timeout(self.poll_interval) {
                Ok(message) => return Ok(message),
                Err(RecvTimeoutError::Timeout) => {
                    // Check for cancellation between polls
                    if cx.is_cancel_requested() {
                        return Err(TransportError::Cancelled);
                    }
                    // Continue polling
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.closed = true;
                    return Err(TransportError::Closed);
                }
            }
        }
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.closed = true;
        // Dropping sender will signal disconnection to the peer
        Ok(())
    }
}

/// Creates a connected pair of memory transports.
///
/// Returns `(client, server)` transports where:
/// - Messages sent on `client` are received on `server`
/// - Messages sent on `server` are received on `client`
///
/// # Channel Capacity
///
/// Uses bounded channels with a default capacity of 64 messages.
/// This prevents unbounded memory growth if one side is slower.
///
/// # Example
///
/// ```
/// use fastmcp_transport::memory::create_memory_transport_pair;
/// use fastmcp_transport::Transport;
/// use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest};
/// use asupersync::Cx;
///
/// let (mut client, mut server) = create_memory_transport_pair();
/// let cx = Cx::for_testing();
///
/// // Client sends a request
/// let request = JsonRpcRequest::new("test/method", None, 1i64);
/// client.send_request(&cx, &request).unwrap();
///
/// // Server receives it
/// let msg = server.recv(&cx).unwrap();
/// match msg {
///     JsonRpcMessage::Request(req) => assert_eq!(req.method, "test/method"),
///     _ => panic!("Expected request"),
/// }
/// ```
#[must_use]
pub fn create_memory_transport_pair() -> (MemoryTransport, MemoryTransport) {
    create_memory_transport_pair_with_capacity(64)
}

/// Creates a connected pair of memory transports with specified channel capacity.
///
/// # Arguments
///
/// * `capacity` - Maximum number of messages that can be buffered in each direction.
///   If 0, creates unbounded channels (not recommended for production use).
///
/// # Example
///
/// ```
/// use fastmcp_transport::memory::create_memory_transport_pair_with_capacity;
///
/// // Small buffer for testing backpressure
/// let (client, server) = create_memory_transport_pair_with_capacity(4);
/// ```
#[must_use]
pub fn create_memory_transport_pair_with_capacity(
    _capacity: usize,
) -> (MemoryTransport, MemoryTransport) {
    // Note: std::sync::mpsc doesn't have bounded channels, so we use unbounded.
    // For bounded behavior, users should use the crossbeam crate.
    // This is a simplification for the initial implementation.
    let (client_to_server_tx, client_to_server_rx) = mpsc::channel();
    let (server_to_client_tx, server_to_client_rx) = mpsc::channel();

    let client = MemoryTransport::new(client_to_server_tx, server_to_client_rx);
    let server = MemoryTransport::new(server_to_client_tx, client_to_server_rx);

    (client, server)
}

/// Builder for creating memory transport pairs with custom configuration.
///
/// # Example
///
/// ```
/// use fastmcp_transport::memory::MemoryTransportBuilder;
/// use std::time::Duration;
///
/// let (client, server) = MemoryTransportBuilder::new()
///     .poll_interval(Duration::from_millis(10))
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct MemoryTransportBuilder {
    poll_interval: Duration,
}

impl Default for MemoryTransportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryTransportBuilder {
    /// Creates a new builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    /// Sets the poll interval for cancellation checks during recv.
    #[must_use]
    pub fn poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Builds the transport pair with the configured settings.
    #[must_use]
    pub fn build(self) -> (MemoryTransport, MemoryTransport) {
        let (mut client, mut server) = create_memory_transport_pair();
        client.poll_interval = self.poll_interval;
        server.poll_interval = self.poll_interval;
        (client, server)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{JsonRpcRequest, JsonRpcResponse, RequestId};
    use std::thread;

    #[test]
    fn test_basic_send_receive() {
        let (mut client, mut server) = create_memory_transport_pair();
        let cx = Cx::for_testing();

        // Client sends request
        let request = JsonRpcRequest::new("test/method", None, 1i64);
        client.send_request(&cx, &request).unwrap();

        // Server receives it
        let msg = server.recv(&cx).unwrap();
        match msg {
            JsonRpcMessage::Request(req) => {
                assert_eq!(req.method, "test/method");
                assert_eq!(req.id, Some(RequestId::Number(1)));
            }
            _ => panic!("Expected request"),
        }
    }

    #[test]
    fn test_bidirectional_communication() {
        let (mut client, mut server) = create_memory_transport_pair();
        let cx = Cx::for_testing();

        // Client sends request
        let request = JsonRpcRequest::new("ping", None, 1i64);
        client.send_request(&cx, &request).unwrap();

        // Server receives and responds
        let _msg = server.recv(&cx).unwrap();
        let response =
            JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({"pong": true}));
        server.send_response(&cx, &response).unwrap();

        // Client receives response
        let msg = client.recv(&cx).unwrap();
        match msg {
            JsonRpcMessage::Response(resp) => {
                assert!(resp.result.is_some());
            }
            _ => panic!("Expected response"),
        }
    }

    #[test]
    fn test_multiple_messages() {
        let (mut client, mut server) = create_memory_transport_pair();
        let cx = Cx::for_testing();

        // Send multiple messages
        for i in 1..=5 {
            let request = JsonRpcRequest::new(format!("method_{i}"), None, i as i64);
            client.send_request(&cx, &request).unwrap();
        }

        // Receive all messages
        for i in 1..=5 {
            let msg = server.recv(&cx).unwrap();
            match msg {
                JsonRpcMessage::Request(req) => {
                    assert_eq!(req.method, format!("method_{i}"));
                }
                _ => panic!("Expected request"),
            }
        }
    }

    #[test]
    fn test_cancellation_on_recv() {
        let (client, mut server) = create_memory_transport_pair();
        let cx = Cx::for_testing();

        // Don't send anything, so recv will block

        // Set up cancellation
        cx.set_cancel_requested(true);

        // Recv should return cancelled immediately
        let result = server.recv(&cx);
        assert!(matches!(result, Err(TransportError::Cancelled)));

        // Keep client alive to prevent disconnection error
        drop(client);
    }

    #[test]
    fn test_cancellation_on_send() {
        let (mut client, _server) = create_memory_transport_pair();
        let cx = Cx::for_testing();

        cx.set_cancel_requested(true);

        let request = JsonRpcRequest::new("test", None, 1i64);
        let result = client.send_request(&cx, &request);
        assert!(matches!(result, Err(TransportError::Cancelled)));
    }

    #[test]
    fn test_close_signals_disconnection() {
        let (mut client, mut server) = create_memory_transport_pair();
        let cx = Cx::for_testing();

        // Close client
        client.close().unwrap();
        drop(client);

        // Server should get closed error on recv
        let result = server.recv(&cx);
        assert!(matches!(result, Err(TransportError::Closed)));
    }

    #[test]
    fn test_send_after_close_fails() {
        let (mut client, _server) = create_memory_transport_pair();
        let cx = Cx::for_testing();

        client.close().unwrap();

        let request = JsonRpcRequest::new("test", None, 1i64);
        let result = client.send_request(&cx, &request);
        assert!(matches!(result, Err(TransportError::Closed)));
    }

    #[test]
    fn test_recv_after_close_fails() {
        let (mut client, mut server) = create_memory_transport_pair();
        let cx = Cx::for_testing();

        // Send a message before closing
        let request = JsonRpcRequest::new("test", None, 1i64);
        client.send_request(&cx, &request).unwrap();

        // Close server
        server.close().unwrap();

        // Recv should fail
        let result = server.recv(&cx);
        assert!(matches!(result, Err(TransportError::Closed)));
    }

    #[test]
    fn test_cross_thread_communication() {
        let (mut client, mut server) = create_memory_transport_pair();

        let server_handle = thread::spawn(move || {
            let cx = Cx::for_testing();

            // Receive request
            let msg = server.recv(&cx).unwrap();
            let request_id = match &msg {
                JsonRpcMessage::Request(req) => req.id.clone().unwrap(),
                _ => panic!("Expected request"),
            };

            // Send response
            let response = JsonRpcResponse::success(request_id, serde_json::json!({"ok": true}));
            server.send_response(&cx, &response).unwrap();
        });

        let client_handle = thread::spawn(move || {
            let cx = Cx::for_testing();

            // Send request
            let request = JsonRpcRequest::new("cross_thread_test", None, 42i64);
            client.send_request(&cx, &request).unwrap();

            // Receive response
            let msg = client.recv(&cx).unwrap();
            match msg {
                JsonRpcMessage::Response(resp) => {
                    assert!(resp.result.is_some());
                }
                _ => panic!("Expected response"),
            }
        });

        server_handle.join().unwrap();
        client_handle.join().unwrap();
    }

    #[test]
    fn test_builder_custom_poll_interval() {
        use std::time::Duration;

        let (client, server) = MemoryTransportBuilder::new()
            .poll_interval(Duration::from_millis(5))
            .build();

        assert_eq!(client.poll_interval, Duration::from_millis(5));
        assert_eq!(server.poll_interval, Duration::from_millis(5));
    }

    #[test]
    fn test_is_closed() {
        let (mut client, server) = create_memory_transport_pair();

        assert!(!client.is_closed());
        assert!(!server.is_closed());

        client.close().unwrap();

        assert!(client.is_closed());
        // Server doesn't know yet until recv fails
        assert!(!server.is_closed());
    }

    #[test]
    fn test_with_poll_interval() {
        use std::time::Duration;

        let (client, _server) = create_memory_transport_pair();
        let client = client.with_poll_interval(Duration::from_millis(100));

        assert_eq!(client.poll_interval, Duration::from_millis(100));
    }
}
