//! Test server builder for creating servers with real handlers.
//!
//! Provides a builder pattern for constructing test servers that use
//! actual handler implementations via MemoryTransport.

use fastmcp_server::{Router, Server, ServerBuilder};
use fastmcp_transport::memory::{create_memory_transport_pair, MemoryTransport};

/// Builder for creating test servers with real handlers.
///
/// Creates servers that communicate via `MemoryTransport` for
/// in-process testing without subprocess spawning.
///
/// # Example
///
/// ```ignore
/// use fastmcp::testing::prelude::*;
///
/// // Create a simple test server
/// let (router, client_transport, server_transport) = TestServer::builder()
///     .with_name("test-server")
///     .build();
///
/// // Use client_transport to communicate with server
/// ```
pub struct TestServerBuilder {
    /// Server name.
    name: String,
    /// Server version.
    version: String,
    /// Request timeout in seconds.
    request_timeout: Option<u64>,
}

impl Default for TestServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestServerBuilder {
    /// Creates a new test server builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "test-server".to_string(),
            version: "1.0.0".to_string(),
            request_timeout: None,
        }
    }

    /// Sets the server name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Sets the server version.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Sets the request timeout in seconds.
    #[must_use]
    pub fn with_request_timeout(mut self, secs: u64) -> Self {
        self.request_timeout = Some(secs);
        self
    }

    /// Builds the test server and returns it with a client transport.
    ///
    /// Returns a tuple of:
    /// - `Router`: The configured router (use with server run loop)
    /// - `MemoryTransport`: Client-side transport for sending requests
    /// - `MemoryTransport`: Server-side transport for the server run loop
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (router, client_transport, server_transport) = TestServer::builder()
    ///     .build();
    ///
    /// // Run server in a thread
    /// std::thread::spawn(move || {
    ///     // Use router and server_transport
    /// });
    ///
    /// // Use client_transport for testing
    /// ```
    #[must_use]
    pub fn build(self) -> (Router, MemoryTransport, MemoryTransport) {
        // Create connected transport pair
        let (client_transport, server_transport) = create_memory_transport_pair();

        // Build empty router - handlers should be added via Router methods
        let router = Router::new();

        (router, client_transport, server_transport)
    }

    /// Builds a full `ServerBuilder` for more control.
    ///
    /// Use this when you need access to the full server builder API.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (builder, client_transport, server_transport) = TestServer::builder()
    ///     .build_server_builder();
    ///
    /// // Customize further with the real server builder
    /// let server = builder
    ///     .instructions("Test server")
    ///     .build();
    /// ```
    #[must_use]
    pub fn build_server_builder(self) -> (ServerBuilder, MemoryTransport, MemoryTransport) {
        let (client_transport, server_transport) = create_memory_transport_pair();

        let mut builder = Server::new(&self.name, &self.version);

        if let Some(timeout) = self.request_timeout {
            builder = builder.request_timeout(timeout);
        }

        (builder, client_transport, server_transport)
    }
}

/// Convenience wrapper for `TestServerBuilder`.
pub struct TestServer;

impl TestServer {
    /// Creates a new test server builder.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (router, client, server) = TestServer::builder()
    ///     .with_name("my-test-server")
    ///     .build();
    /// ```
    #[must_use]
    pub fn builder() -> TestServerBuilder {
        TestServerBuilder::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let builder = TestServerBuilder::new();
        assert_eq!(builder.name, "test-server");
        assert_eq!(builder.version, "1.0.0");
    }

    #[test]
    fn test_builder_customization() {
        let builder = TestServerBuilder::new()
            .with_name("custom-server")
            .with_version("2.0.0")
            .with_request_timeout(30);

        assert_eq!(builder.name, "custom-server");
        assert_eq!(builder.version, "2.0.0");
        assert_eq!(builder.request_timeout, Some(30));
    }

    #[test]
    fn test_build_creates_transport_pair() {
        let (router, client_transport, server_transport) = TestServer::builder().build();

        // Verify transports are not closed
        assert!(!client_transport.is_closed());
        assert!(!server_transport.is_closed());

        // Router should be empty (no handlers added)
        assert!(router.tools().is_empty());
    }
}
