//! Test server builder for creating servers with real handlers.
//!
//! Provides a builder pattern for constructing test servers that use
//! actual handler implementations via MemoryTransport.

use fastmcp_server::{Server, ServerBuilder};
use fastmcp_transport::memory::{MemoryTransport, create_memory_transport_pair};

/// Builder for creating test servers with real handlers.
///
/// Creates servers that communicate via `MemoryTransport` for
/// in-process testing without subprocess spawning.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::prelude::*;
///
/// // Create a simple test server
/// let (builder, client_transport, server_transport) = TestServer::builder()
///     .with_name("test-server")
///     .build();
/// let server = builder.build();
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

    /// Builds a configured server builder and its connected transports.
    ///
    /// Returns a tuple of:
    /// - `ServerBuilder`: Preserves the name, version, and request timeout;
    ///   register handlers and call its `build()` before running the server
    /// - `MemoryTransport`: Client-side transport for sending requests
    /// - `MemoryTransport`: Server-side transport for the server run loop
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (builder, client_transport, server_transport) = TestServer::builder()
    ///     .build();
    /// let server = builder.instructions("Test server").build();
    ///
    /// // Run server in a background thread (omitted here). Prefer using the
    /// // higher-level E2E harness helpers in this crate which join threads on drop.
    ///
    /// // Use client_transport for testing
    /// ```
    #[must_use]
    pub fn build(self) -> (ServerBuilder, MemoryTransport, MemoryTransport) {
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
    /// let (builder, client_transport, server_transport) = TestServer::builder()
    ///     .with_name("my-test-server")
    ///     .build();
    /// let server = builder.build();
    /// ```
    #[must_use]
    pub fn builder() -> TestServerBuilder {
        TestServerBuilder::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use asupersync::Cx;
    use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
    use fastmcp_core::{McpContext, McpOutcome, McpResult, Outcome};
    use fastmcp_protocol::{
        CompleteResult, Content, FinalCallToolResult, JsonRpcMessage, JsonRpcRequest,
        JsonRpcResponse, Tool,
    };
    use fastmcp_server::{BoxFuture, ToolExecutionMode, ToolHandler};
    use serde_json::json;

    /// The test owns the runtime; both the production pump and client borrow it.
    fn exchange(
        server: Server,
        mut client: MemoryTransport,
        transport: MemoryTransport,
        method: &str,
        mut params: serde_json::Value,
    ) -> JsonRpcResponse {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        });
        let request = JsonRpcRequest::new(method, Some(params), 1_i64);
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().expect("test reactor"))
            .blocking_threads(2, 16)
            .build()
            .expect("caller-owned test runtime");
        runtime.block_on(async move {
            let cx = Cx::current().expect("caller context");
            let dispatch_cx = cx.clone();
            let (recv, send) = transport.into_split();
            let (completed, mut completion) = asupersync::channel::oneshot::channel();
            let _pump = cx
                .spawn_blocking(move |pump_cx| {
                    let result = server.run_split_transport_returning_with_dispatch_cx(
                        &pump_cx,
                        &dispatch_cx,
                        recv,
                        send,
                    );
                    let _ = completed.send_blocking(result);
                })
                .expect("admit server pump");
            let response = asupersync::time::timeout(cx.now(), Duration::from_secs(10), async {
                client
                    .send_async(&cx, &JsonRpcMessage::Request(request))
                    .await
                    .expect("send real Memory request");
                loop {
                    if let JsonRpcMessage::Response(response) = client
                        .recv_async(&cx)
                        .await
                        .expect("receive server response")
                    {
                        break response;
                    }
                }
            })
            .await;
            drop(client);
            // Read the pump's own result; its task wrapper can report cancellation
            // after the server has already completed normal region shutdown.
            asupersync::time::timeout(cx.now(), Duration::from_secs(10), async {
                loop {
                    match completion.try_recv() {
                        Ok(result) => break result.expect("server cleanup settles"),
                        Err(asupersync::channel::oneshot::TryRecvError::Closed) => {
                            panic!("server pump exited without its result");
                        }
                        Err(asupersync::channel::oneshot::TryRecvError::Empty) => {
                            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                        }
                    }
                }
            })
            .await
            .expect("bounded server cleanup");
            response.expect("bounded Memory exchange")
        })
    }

    #[test]
    fn configured_build_preserves_identity() {
        for (name, version) in [
            ("alpha-test-server", "2.3.4"),
            ("beta-test-server", "5.6.7"),
        ] {
            let (builder, client, transport) = TestServer::builder()
                .with_name(name)
                .with_version(version)
                .build();
            let response = exchange(
                builder.build(),
                client,
                transport,
                "server/discover",
                json!({}),
            );
            assert!(response.error.is_none(), "{response:?}");
            let result = response.result.expect("discovery result");
            let identity = &result["_meta"]["io.modelcontextprotocol/serverInfo"];
            assert_eq!(identity["name"], name);
            assert_eq!(identity["version"], version);
        }
    }

    struct DelayedEffect {
        started: Arc<AtomicUsize>,
        completed: Arc<AtomicUsize>,
        settled: Arc<AtomicUsize>,
    }

    struct Settlement(Arc<AtomicUsize>);

    impl Drop for Settlement {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl ToolHandler for DelayedEffect {
        fn definition(&self) -> Tool {
            Tool {
                name: "delayed_effect".to_owned(),
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn execution_mode(&self) -> ToolExecutionMode {
            ToolExecutionMode::Async
        }

        fn call(
            &self,
            _ctx: &McpContext,
            _arguments: serde_json::Value,
        ) -> McpResult<Vec<Content>> {
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(vec![Content::text("effect completed")])
        }

        fn call_final_async<'a>(
            &'a self,
            ctx: &'a McpContext,
            arguments: serde_json::Value,
        ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalCallToolResult>>> {
            Box::pin(async move {
                self.started.fetch_add(1, Ordering::SeqCst);
                let _settlement = Settlement(Arc::clone(&self.settled));
                asupersync::time::sleep(ctx.cx().now(), Duration::from_millis(1_100)).await;
                if ctx.checkpoint().is_err() {
                    return Outcome::Err(fastmcp_core::McpError::request_cancelled());
                }
                match self.call_final(ctx, arguments) {
                    Ok(result) => Outcome::Ok(result),
                    Err(error) => Outcome::Err(error),
                }
            })
        }
    }

    #[test]
    fn configured_build_enforces_timeout() {
        // The same handler crosses only the one-second ceiling. Default and
        // zero retain ServerBuilder's documented ordinary/unbounded behavior.
        for timeout in [Some(1), Some(2), None, Some(0)] {
            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let settled = Arc::new(AtomicUsize::new(0));
            let mut test_builder = TestServer::builder();
            if let Some(seconds) = timeout {
                test_builder = test_builder.with_request_timeout(seconds);
            }
            let (builder, client, transport) = test_builder.build();
            let server = builder
                .tool(DelayedEffect {
                    started: Arc::clone(&started),
                    completed: Arc::clone(&completed),
                    settled: Arc::clone(&settled),
                })
                .build();
            let response = exchange(
                server,
                client,
                transport,
                "tools/call",
                json!({"name": "delayed_effect", "arguments": {}}),
            );
            assert_eq!(started.load(Ordering::SeqCst), 1, "{response:?}");
            assert_eq!(settled.load(Ordering::SeqCst), 1, "handler must settle");
            if timeout == Some(1) {
                assert_eq!(completed.load(Ordering::SeqCst), 0, "no late effect");
                assert_eq!(
                    response.error.expect("deadline error").code,
                    i32::from(fastmcp_core::McpErrorCode::RequestCancelled).into()
                );
            } else {
                assert!(response.error.is_none(), "{response:?}");
                assert_eq!(completed.load(Ordering::SeqCst), 1);
                assert_eq!(
                    response.result.expect("tool result")["content"][0]["text"],
                    "effect completed"
                );
            }
        }
    }

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
        let (builder, client_transport, server_transport) = TestServer::builder().build();

        // Verify transports are not closed
        assert!(!client_transport.is_closed());
        assert!(!server_transport.is_closed());

        assert!(builder.build().tools().is_empty());
    }

    // =========================================================================
    // Additional coverage tests (bd-297e)
    // =========================================================================

    #[test]
    fn default_trait_matches_new() {
        let default_builder = TestServerBuilder::default();
        let new_builder = TestServerBuilder::new();
        assert_eq!(default_builder.name, new_builder.name);
        assert_eq!(default_builder.version, new_builder.version);
        assert_eq!(default_builder.request_timeout, new_builder.request_timeout);
    }

    #[test]
    fn test_server_builder_convenience() {
        let builder = TestServer::builder();
        assert_eq!(builder.name, "test-server");
    }

    #[test]
    fn build_without_timeout() {
        let (_builder, client, server) = TestServer::builder().with_name("sb-test").build();

        assert!(!client.is_closed());
        assert!(!server.is_closed());
    }

    #[test]
    fn build_with_timeout() {
        let (_builder, client, server) = TestServer::builder().with_request_timeout(60).build();

        assert!(!client.is_closed());
        assert!(!server.is_closed());
    }

    #[test]
    fn build_returns_independent_transports() {
        let (_builder, client, server) = TestServer::builder().build();

        // Closing one should not close the other immediately in terms of is_closed()
        // (MemoryTransport uses channels; closing one side makes recv on the other fail)
        drop(client);
        // server transport itself is not marked closed by dropping the peer
        // (it's the channel that becomes disconnected, not the transport's own state)
        assert!(!server.is_closed());
    }
}
