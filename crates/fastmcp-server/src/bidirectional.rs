//! Bidirectional request handling for server-to-client communication.
//!
//! This module provides the infrastructure for server-initiated requests to clients,
//! such as:
//! - `sampling/createMessage` - Request LLM completion from the client
//! - `elicitation/elicit` - Request user input from the client
//! - `roots/list` - Request filesystem roots from the client
//!
//! # Architecture
//!
//! The MCP protocol is bidirectional: while clients typically send requests to servers,
//! servers can also send requests to clients. This creates a challenge because the
//! server's main loop is typically blocking on `recv()`.
//!
//! The solution is a message dispatcher pattern:
//! 1. A background task continuously reads from the transport
//! 2. Incoming messages are routed based on whether they're requests or responses
//! 3. Responses are matched to pending requests via their ID
//! 4. Requests are dispatched to handlers
//!
//! # Usage
//!
//! ```ignore
//! use fastmcp_server::bidirectional::RequestDispatcher;
//!
//! let dispatcher = RequestDispatcher::new();
//!
//! // Send a request and await the response
//! let response = dispatcher.send_request(
//!     &cx,
//!     "sampling/createMessage",
//!     params,
//! ).await?;
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::{
    ElicitationAction, ElicitationMode, ElicitationRequest, ElicitationResponse, ElicitationSender,
    McpError, McpErrorCode, McpResult, SamplingRequest, SamplingResponse, SamplingRole,
    SamplingSender, SamplingStopReason,
};
use fastmcp_protocol::{JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId};

// ============================================================================
// Pending Request Tracking
// ============================================================================

/// A oneshot channel for receiving a response.
type ResponseSender = std::sync::mpsc::Sender<Result<serde_json::Value, JsonRpcError>>;
type ResponseReceiver = std::sync::mpsc::Receiver<Result<serde_json::Value, JsonRpcError>>;

/// Tracks pending server-to-client requests.
///
/// When the server sends a request to the client, it registers a response sender
/// here. When a response arrives, the dispatcher routes it to the correct sender.
#[derive(Debug)]
pub struct PendingRequests {
    /// Map from request ID to response sender.
    pending: Mutex<HashMap<RequestId, ResponseSender>>,
    /// Counter for generating unique request IDs.
    next_id: AtomicU64,
}

impl PendingRequests {
    fn lock_pending(&self) -> std::sync::MutexGuard<'_, HashMap<RequestId, ResponseSender>> {
        match self.pending.lock() {
            Ok(guard) => guard,
            // Prefer availability over panic if another task panicked while holding the lock.
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Creates a new pending request tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            // Start at a high number to avoid collision with client request IDs
            next_id: AtomicU64::new(1_000_000),
        }
    }

    /// Generates a new unique request ID.
    #[allow(clippy::cast_possible_wrap)]
    pub fn next_request_id(&self) -> RequestId {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        RequestId::Number(id as i64)
    }

    /// Registers a pending request and returns a receiver for the response.
    pub fn register(&self, id: RequestId) -> ResponseReceiver {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut pending = self.lock_pending();
        pending.insert(id, tx);
        rx
    }

    /// Routes a response to the appropriate pending request.
    ///
    /// Returns `true` if the response was routed, `false` if no matching request was found.
    pub fn route_response(&self, response: &JsonRpcResponse) -> bool {
        let Some(ref id) = response.id else {
            return false;
        };

        let sender = {
            let mut pending = self.lock_pending();
            pending.remove(id)
        };

        if let Some(sender) = sender {
            let result = if let Some(ref error) = response.error {
                Err(error.clone())
            } else {
                Ok(response.result.clone().unwrap_or(serde_json::Value::Null))
            };
            // Ignore send errors (receiver may have been dropped due to cancellation)
            let _ = sender.send(result);
            true
        } else {
            false
        }
    }

    /// Removes a pending request (e.g., on timeout or cancellation).
    pub fn remove(&self, id: &RequestId) {
        let mut pending = self.lock_pending();
        pending.remove(id);
    }

    /// Cancels all pending requests with a connection closed error.
    pub fn cancel_all(&self) {
        let mut pending = self.lock_pending();
        for (_, sender) in pending.drain() {
            let _ = sender.send(Err(JsonRpcError {
                code: McpErrorCode::InternalError.into(),
                message: "Connection closed".to_string(),
                data: None,
            }));
        }
    }
}

impl Default for PendingRequests {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Transport Request Sender
// ============================================================================

/// Callback type for sending messages through the transport.
pub type TransportSendFn = Arc<dyn Fn(&JsonRpcMessage) -> Result<(), String> + Send + Sync>;

/// Sends server-to-client requests through the transport.
///
/// This struct provides a way to send requests to the client and await responses.
/// It works in conjunction with [`PendingRequests`] to track in-flight requests.
#[derive(Clone)]
pub struct RequestSender {
    /// Pending request tracker.
    pending: Arc<PendingRequests>,
    /// Transport send callback.
    send_fn: TransportSendFn,
}

impl RequestSender {
    /// Creates a new request sender.
    pub fn new(pending: Arc<PendingRequests>, send_fn: TransportSendFn) -> Self {
        Self { pending, send_fn }
    }

    /// Sends a request to the client and waits for a response.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The transport send fails
    /// - The request times out (based on budget)
    /// - The client returns an error response
    /// - The connection is closed
    pub fn send_request<T: serde::de::DeserializeOwned>(
        &self,
        cx: &Cx,
        method: &str,
        params: serde_json::Value,
    ) -> McpResult<T> {
        let id = self.pending.next_request_id();
        let receiver = self.pending.register(id.clone());

        let request = JsonRpcRequest::new(method.to_string(), Some(params), id.clone());
        let message = JsonRpcMessage::Request(request);

        // Send the request through the transport
        if let Err(e) = (self.send_fn)(&message) {
            self.pending.remove(&id);
            return Err(McpError::internal_error(format!(
                "Failed to send request: {}",
                e
            )));
        }

        // Wait for response while observing cancellation/budget via checkpoints.
        //
        // This uses periodic `recv_timeout` polling so we can call `cx.checkpoint()`
        // to notice budget exhaustion or explicit cancellation.
        let tick = Duration::from_millis(25);
        loop {
            if cx.checkpoint().is_err() {
                self.pending.remove(&id);
                return Err(McpError::request_cancelled());
            }

            match receiver.recv_timeout(tick) {
                Ok(Ok(value)) => {
                    return serde_json::from_value(value).map_err(|e| {
                        McpError::internal_error(format!("Failed to parse response: {e}"))
                    });
                }
                Ok(Err(error)) => {
                    return Err(McpError::new(McpErrorCode::from(error.code), error.message));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Keep waiting, but allow budget/cancellation to be observed.
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(McpError::internal_error(
                        "Response channel closed unexpectedly",
                    ));
                }
            }
        }
    }
}

impl std::fmt::Debug for RequestSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestSender")
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Sampling Sender Implementation
// ============================================================================

/// Sends sampling requests to the client via the transport.
#[derive(Clone)]
pub struct TransportSamplingSender {
    sender: RequestSender,
}

impl TransportSamplingSender {
    /// Creates a new transport-backed sampling sender.
    pub fn new(sender: RequestSender) -> Self {
        Self { sender }
    }
}

impl SamplingSender for TransportSamplingSender {
    fn create_message(
        &self,
        request: SamplingRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = McpResult<SamplingResponse>> + Send + '_>>
    {
        Box::pin(async move {
            // Convert to protocol types
            let params = fastmcp_protocol::CreateMessageParams {
                messages: request
                    .messages
                    .into_iter()
                    .map(|m| fastmcp_protocol::SamplingMessage {
                        role: match m.role {
                            SamplingRole::User => fastmcp_protocol::Role::User,
                            SamplingRole::Assistant => fastmcp_protocol::Role::Assistant,
                        },
                        content: fastmcp_protocol::SamplingContent::Text { text: m.text },
                    })
                    .collect(),
                max_tokens: request.max_tokens,
                system_prompt: request.system_prompt,
                temperature: request.temperature,
                stop_sequences: request.stop_sequences,
                model_preferences: if request.model_hints.is_empty() {
                    None
                } else {
                    Some(fastmcp_protocol::ModelPreferences {
                        hints: request
                            .model_hints
                            .into_iter()
                            .map(|name| fastmcp_protocol::ModelHint { name: Some(name) })
                            .collect(),
                        ..Default::default()
                    })
                },
                include_context: None,
                meta: None,
            };

            let params_value = serde_json::to_value(&params)
                .map_err(|e| McpError::internal_error(format!("Failed to serialize: {}", e)))?;

            // Create a request-scoped Cx for this server-initiated request.
            let cx = Cx::for_request();

            let result: fastmcp_protocol::CreateMessageResult =
                self.sender
                    .send_request(&cx, "sampling/createMessage", params_value)?;

            Ok(SamplingResponse {
                text: match result.content {
                    fastmcp_protocol::SamplingContent::Text { text } => text,
                    fastmcp_protocol::SamplingContent::Image { data, mime_type } => {
                        format!("[image: {} bytes, type: {}]", data.len(), mime_type)
                    }
                },
                model: result.model,
                stop_reason: match result.stop_reason {
                    fastmcp_protocol::StopReason::EndTurn => SamplingStopReason::EndTurn,
                    fastmcp_protocol::StopReason::StopSequence => SamplingStopReason::StopSequence,
                    fastmcp_protocol::StopReason::MaxTokens => SamplingStopReason::MaxTokens,
                },
            })
        })
    }
}

// ============================================================================
// Elicitation Sender Implementation
// ============================================================================

/// Sends elicitation requests to the client via the transport.
#[derive(Clone)]
pub struct TransportElicitationSender {
    sender: RequestSender,
}

impl TransportElicitationSender {
    /// Creates a new transport-backed elicitation sender.
    pub fn new(sender: RequestSender) -> Self {
        Self { sender }
    }
}

impl ElicitationSender for TransportElicitationSender {
    fn elicit(
        &self,
        request: ElicitationRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = McpResult<ElicitationResponse>> + Send + '_>,
    > {
        Box::pin(async move {
            let params_value = match request.mode {
                ElicitationMode::Form => {
                    let params = fastmcp_protocol::ElicitRequestFormParams {
                        mode: fastmcp_protocol::ElicitMode::Form,
                        message: request.message.clone(),
                        requested_schema: request.schema.unwrap_or(serde_json::json!({})),
                    };
                    serde_json::to_value(&params).map_err(|e| {
                        McpError::internal_error(format!("Failed to serialize: {}", e))
                    })?
                }
                ElicitationMode::Url => {
                    let params = fastmcp_protocol::ElicitRequestUrlParams {
                        mode: fastmcp_protocol::ElicitMode::Url,
                        message: request.message.clone(),
                        url: request.url.unwrap_or_default(),
                        elicitation_id: request.elicitation_id.unwrap_or_default(),
                    };
                    serde_json::to_value(&params).map_err(|e| {
                        McpError::internal_error(format!("Failed to serialize: {}", e))
                    })?
                }
            };

            // Create a request-scoped Cx for this server-initiated request.
            let cx = Cx::for_request();

            let result: fastmcp_protocol::ElicitResult =
                self.sender
                    .send_request(&cx, "elicitation/elicit", params_value)?;

            // Convert HashMap<String, ElicitContentValue> to HashMap<String, serde_json::Value>
            let content = result.content.map(|content_map| {
                let mut map = std::collections::HashMap::new();
                for (key, value) in content_map {
                    let json_value = match value {
                        fastmcp_protocol::ElicitContentValue::Null => serde_json::Value::Null,
                        fastmcp_protocol::ElicitContentValue::Bool(b) => serde_json::Value::Bool(b),
                        fastmcp_protocol::ElicitContentValue::Int(i) => {
                            serde_json::Value::Number(i.into())
                        }
                        fastmcp_protocol::ElicitContentValue::Float(f) => {
                            serde_json::Number::from_f64(f)
                                .map(serde_json::Value::Number)
                                .unwrap_or(serde_json::Value::Null)
                        }
                        fastmcp_protocol::ElicitContentValue::String(s) => {
                            serde_json::Value::String(s)
                        }
                        fastmcp_protocol::ElicitContentValue::StringArray(arr) => {
                            serde_json::Value::Array(
                                arr.into_iter().map(serde_json::Value::String).collect(),
                            )
                        }
                    };
                    map.insert(key, json_value);
                }
                map
            });

            Ok(ElicitationResponse {
                action: match result.action {
                    fastmcp_protocol::ElicitAction::Accept => ElicitationAction::Accept,
                    fastmcp_protocol::ElicitAction::Decline => ElicitationAction::Decline,
                    fastmcp_protocol::ElicitAction::Cancel => ElicitationAction::Cancel,
                },
                content,
            })
        })
    }
}

// ============================================================================
// Roots Provider Implementation
// ============================================================================

/// Provider for filesystem roots from the client.
#[derive(Clone)]
pub struct TransportRootsProvider {
    sender: RequestSender,
}

impl TransportRootsProvider {
    /// Creates a new transport-backed roots provider.
    pub fn new(sender: RequestSender) -> Self {
        Self { sender }
    }

    /// Lists the filesystem roots from the client.
    pub fn list_roots(&self) -> McpResult<Vec<fastmcp_protocol::Root>> {
        let cx = Cx::for_request();
        let result: fastmcp_protocol::ListRootsResult =
            self.sender
                .send_request(&cx, "roots/list", serde_json::json!({}))?;
        Ok(result.roots)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_requests_register_and_route() {
        let pending = PendingRequests::new();

        // Register a request
        let id = pending.next_request_id();
        let receiver = pending.register(id.clone());

        // Simulate a response
        let response = JsonRpcResponse::success(id, serde_json::json!({"result": "ok"}));
        assert!(pending.route_response(&response));

        // Receive the response
        let result = receiver.recv().unwrap();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::json!({"result": "ok"}));
    }

    #[test]
    fn test_pending_requests_error_response() {
        let pending = PendingRequests::new();

        let id = pending.next_request_id();
        let receiver = pending.register(id.clone());

        // Simulate an error response
        let response = JsonRpcResponse::error(
            Some(id),
            JsonRpcError {
                code: -32600,
                message: "Invalid request".to_string(),
                data: None,
            },
        );
        assert!(pending.route_response(&response));

        // Receive the error
        let result = receiver.recv().unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().message, "Invalid request");
    }

    #[test]
    fn test_pending_requests_cancel_all() {
        let pending = PendingRequests::new();

        let id1 = pending.next_request_id();
        let id2 = pending.next_request_id();
        let receiver1 = pending.register(id1);
        let receiver2 = pending.register(id2);

        // Cancel all
        pending.cancel_all();

        // Both should receive errors
        let result1 = receiver1.recv().unwrap();
        let result2 = receiver2.recv().unwrap();
        assert!(result1.is_err());
        assert!(result2.is_err());
    }

    #[test]
    fn test_route_unknown_response() {
        let pending = PendingRequests::new();

        // Route a response with unknown ID
        let response = JsonRpcResponse::success(
            RequestId::Number(999999),
            serde_json::json!({"result": "ok"}),
        );
        assert!(!pending.route_response(&response));
    }

    // ── PendingRequests additional coverage ───────────────────────────

    #[test]
    fn pending_requests_default_is_same_as_new() {
        let pr = PendingRequests::default();
        let id = pr.next_request_id();
        // IDs start at 1_000_000
        assert_eq!(id, RequestId::Number(1_000_000));
    }

    #[test]
    fn pending_requests_ids_are_sequential() {
        let pr = PendingRequests::new();
        let id1 = pr.next_request_id();
        let id2 = pr.next_request_id();
        let id3 = pr.next_request_id();
        assert_eq!(id1, RequestId::Number(1_000_000));
        assert_eq!(id2, RequestId::Number(1_000_001));
        assert_eq!(id3, RequestId::Number(1_000_002));
    }

    #[test]
    fn pending_requests_remove_prevents_routing() {
        let pr = PendingRequests::new();
        let id = pr.next_request_id();
        let _receiver = pr.register(id.clone());

        // Remove the pending request
        pr.remove(&id);

        // Routing should fail now
        let response = JsonRpcResponse::success(id, serde_json::json!(null));
        assert!(!pr.route_response(&response));
    }

    #[test]
    fn pending_requests_route_response_without_id_returns_false() {
        let pr = PendingRequests::new();
        // A response with no id
        let response = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed("2.0"),
            id: None,
            result: Some(serde_json::json!(null)),
            error: None,
        };
        assert!(!pr.route_response(&response));
    }

    #[test]
    fn pending_requests_route_response_with_null_result() {
        let pr = PendingRequests::new();
        let id = pr.next_request_id();
        let receiver = pr.register(id.clone());

        // Response with no result field (result is None → becomes Null)
        let response = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed("2.0"),
            id: Some(id),
            result: None,
            error: None,
        };
        assert!(pr.route_response(&response));

        let result = receiver.recv().unwrap().unwrap();
        assert_eq!(result, serde_json::Value::Null);
    }

    #[test]
    fn pending_requests_route_after_receiver_dropped_does_not_panic() {
        let pr = PendingRequests::new();
        let id = pr.next_request_id();
        let receiver = pr.register(id.clone());

        // Drop the receiver
        drop(receiver);

        // Routing should still succeed (sender.send returns Err but is ignored)
        let response = JsonRpcResponse::success(id, serde_json::json!(42));
        assert!(pr.route_response(&response));
    }

    #[test]
    fn pending_requests_cancel_all_clears_pending() {
        let pr = PendingRequests::new();
        let id = pr.next_request_id();
        let _receiver = pr.register(id.clone());

        pr.cancel_all();

        // No more pending requests to route to
        let response = JsonRpcResponse::success(id, serde_json::json!(null));
        assert!(!pr.route_response(&response));
    }

    #[test]
    fn pending_requests_cancel_all_empty_is_noop() {
        let pr = PendingRequests::new();
        // Should not panic on empty
        pr.cancel_all();
    }

    #[test]
    fn pending_requests_debug_format() {
        let pr = PendingRequests::new();
        let debug = format!("{:?}", pr);
        assert!(debug.contains("PendingRequests"));
    }

    // ── RequestSender ────────────────────────────────────────────────

    #[test]
    fn request_sender_debug_format() {
        let pending = Arc::new(PendingRequests::new());
        let send_fn: TransportSendFn = Arc::new(|_| Ok(()));
        let sender = RequestSender::new(pending, send_fn);
        let debug = format!("{:?}", sender);
        assert!(debug.contains("RequestSender"));
    }

    #[test]
    fn request_sender_transport_failure_returns_error() {
        let pending = Arc::new(PendingRequests::new());
        let send_fn: TransportSendFn = Arc::new(|_| Err("transport down".to_string()));
        let sender = RequestSender::new(pending, send_fn);

        let cx = Cx::for_testing();
        let result: McpResult<serde_json::Value> =
            sender.send_request(&cx, "test/method", serde_json::json!({}));
        let err = result.unwrap_err();
        assert!(err.message.contains("Failed to send request"));
        assert!(err.message.contains("transport down"));
    }

    #[test]
    fn request_sender_transport_failure_cleans_up_pending() {
        let pending = Arc::new(PendingRequests::new());
        let send_fn: TransportSendFn = Arc::new(|_| Err("fail".to_string()));
        let sender = RequestSender::new(Arc::clone(&pending), send_fn);

        let cx = Cx::for_testing();
        let _err: McpResult<serde_json::Value> =
            sender.send_request(&cx, "test/method", serde_json::json!({}));

        // The pending request should have been cleaned up
        let id = RequestId::Number(1_000_000); // first ID
        let response = JsonRpcResponse::success(id, serde_json::json!(null));
        assert!(!pending.route_response(&response));
    }

    #[test]
    fn request_sender_clone() {
        let pending = Arc::new(PendingRequests::new());
        let send_fn: TransportSendFn = Arc::new(|_| Ok(()));
        let sender = RequestSender::new(pending, send_fn);
        let cloned = sender.clone();
        let debug = format!("{:?}", cloned);
        assert!(debug.contains("RequestSender"));
    }

    // ── RequestSender send_request paths ─────────────────────────────

    #[test]
    fn request_sender_success_path() {
        let pending = Arc::new(PendingRequests::new());
        let pending_clone = Arc::clone(&pending);
        let send_fn: TransportSendFn = Arc::new(move |msg| {
            if let JsonRpcMessage::Request(req) = msg {
                let id = req.id.clone().unwrap();
                let response = JsonRpcResponse::success(id, serde_json::json!({"answer": 42}));
                pending_clone.route_response(&response);
            }
            Ok(())
        });
        let sender = RequestSender::new(Arc::clone(&pending), send_fn);
        let cx = Cx::for_testing();
        let result: McpResult<serde_json::Value> =
            sender.send_request(&cx, "test/method", serde_json::json!({}));
        let value = result.unwrap();
        assert_eq!(value["answer"], 42);
    }

    #[test]
    fn request_sender_error_response_path() {
        let pending = Arc::new(PendingRequests::new());
        let pending_clone = Arc::clone(&pending);
        let send_fn: TransportSendFn = Arc::new(move |msg| {
            if let JsonRpcMessage::Request(req) = msg {
                let id = req.id.clone().unwrap();
                let response = JsonRpcResponse::error(
                    Some(id),
                    JsonRpcError {
                        code: -32600,
                        message: "bad request".to_string(),
                        data: None,
                    },
                );
                pending_clone.route_response(&response);
            }
            Ok(())
        });
        let sender = RequestSender::new(Arc::clone(&pending), send_fn);
        let cx = Cx::for_testing();
        let result: McpResult<serde_json::Value> =
            sender.send_request(&cx, "test/method", serde_json::json!({}));
        let err = result.unwrap_err();
        assert!(err.message.contains("bad request"));
    }

    #[test]
    fn request_sender_disconnected_path() {
        let pending = Arc::new(PendingRequests::new());
        let pending_clone = Arc::clone(&pending);
        let send_fn: TransportSendFn = Arc::new(move |msg| {
            if let JsonRpcMessage::Request(req) = msg {
                let id = req.id.clone().unwrap();
                // Remove the pending entry so tx is dropped, causing Disconnected
                pending_clone.remove(&id);
            }
            Ok(())
        });
        let sender = RequestSender::new(Arc::clone(&pending), send_fn);
        let cx = Cx::for_testing();
        let result: McpResult<serde_json::Value> =
            sender.send_request(&cx, "test/method", serde_json::json!({}));
        let err = result.unwrap_err();
        assert!(err.message.contains("Response channel closed"));
    }

    #[test]
    fn request_sender_deserialization_error() {
        let pending = Arc::new(PendingRequests::new());
        let pending_clone = Arc::clone(&pending);
        let send_fn: TransportSendFn = Arc::new(move |msg| {
            if let JsonRpcMessage::Request(req) = msg {
                let id = req.id.clone().unwrap();
                // Return a string value, which won't deserialize to Vec<String>
                let response =
                    JsonRpcResponse::success(id, serde_json::json!("not a vec of strings"));
                pending_clone.route_response(&response);
            }
            Ok(())
        });
        let sender = RequestSender::new(Arc::clone(&pending), send_fn);
        let cx = Cx::for_testing();
        let result: McpResult<Vec<String>> =
            sender.send_request(&cx, "test/method", serde_json::json!({}));
        let err = result.unwrap_err();
        assert!(err.message.contains("Failed to parse response"));
    }

    // ── cancel_all error details ─────────────────────────────────────

    #[test]
    fn cancel_all_sends_connection_closed_error() {
        let pr = PendingRequests::new();
        let id = pr.next_request_id();
        let receiver = pr.register(id);
        pr.cancel_all();
        let result = receiver.recv().unwrap();
        let err = result.unwrap_err();
        assert_eq!(err.code, i32::from(McpErrorCode::InternalError));
        assert!(err.message.contains("Connection closed"));
        assert!(err.data.is_none());
    }

    // ── route_response with error containing data ────────────────────

    #[test]
    fn route_response_error_with_data() {
        let pr = PendingRequests::new();
        let id = pr.next_request_id();
        let receiver = pr.register(id.clone());
        let response = JsonRpcResponse::error(
            Some(id),
            JsonRpcError {
                code: -32001,
                message: "custom error".to_string(),
                data: Some(serde_json::json!({"detail": "extra info"})),
            },
        );
        assert!(pr.route_response(&response));
        let result = receiver.recv().unwrap();
        let err = result.unwrap_err();
        assert_eq!(err.code, -32001);
        assert!(err.message.contains("custom error"));
        assert!(err.data.is_some());
    }

    // ── Multiple concurrent register/route ───────────────────────────

    #[test]
    fn pending_requests_multiple_register_and_route_independently() {
        let pr = PendingRequests::new();
        let id1 = pr.next_request_id();
        let id2 = pr.next_request_id();
        let id3 = pr.next_request_id();
        let rx1 = pr.register(id1.clone());
        let rx2 = pr.register(id2.clone());
        let rx3 = pr.register(id3.clone());

        // Route them out of order
        let r2 = JsonRpcResponse::success(id2.clone(), serde_json::json!("second"));
        let r3 = JsonRpcResponse::success(id3.clone(), serde_json::json!("third"));
        let r1 = JsonRpcResponse::success(id1.clone(), serde_json::json!("first"));
        assert!(pr.route_response(&r2));
        assert!(pr.route_response(&r3));
        assert!(pr.route_response(&r1));

        assert_eq!(rx1.recv().unwrap().unwrap(), serde_json::json!("first"));
        assert_eq!(rx2.recv().unwrap().unwrap(), serde_json::json!("second"));
        assert_eq!(rx3.recv().unwrap().unwrap(), serde_json::json!("third"));
    }

    // ── Register same id overwrites ──────────────────────────────────

    #[test]
    fn pending_requests_register_same_id_overwrites() {
        let pr = PendingRequests::new();
        let id = pr.next_request_id();
        let _rx1 = pr.register(id.clone());
        let rx2 = pr.register(id.clone()); // overwrites

        let response = JsonRpcResponse::success(id, serde_json::json!("response"));
        assert!(pr.route_response(&response));

        // rx2 should receive the response (it replaced rx1)
        let result = rx2.recv().unwrap().unwrap();
        assert_eq!(result, serde_json::json!("response"));
    }

    // ── Transport sender constructors ────────────────────────────────

    #[test]
    fn transport_sampling_sender_new_and_clone() {
        let pending = Arc::new(PendingRequests::new());
        let send_fn: TransportSendFn = Arc::new(|_| Ok(()));
        let sender = RequestSender::new(pending, send_fn);
        let sampling = TransportSamplingSender::new(sender);
        let _cloned = sampling.clone();
    }

    #[test]
    fn transport_elicitation_sender_new_and_clone() {
        let pending = Arc::new(PendingRequests::new());
        let send_fn: TransportSendFn = Arc::new(|_| Ok(()));
        let sender = RequestSender::new(pending, send_fn);
        let elicitation = TransportElicitationSender::new(sender);
        let _cloned = elicitation.clone();
    }

    #[test]
    fn transport_roots_provider_new_and_clone() {
        let pending = Arc::new(PendingRequests::new());
        let send_fn: TransportSendFn = Arc::new(|_| Ok(()));
        let sender = RequestSender::new(pending, send_fn);
        let roots = TransportRootsProvider::new(sender);
        let _cloned = roots.clone();
    }

    // ── lock_pending with poisoned mutex ─────────────────────────────

    #[test]
    fn pending_requests_lock_pending_recovers_from_poison() {
        let pr = Arc::new(PendingRequests::new());
        let id = pr.next_request_id();
        let rx = pr.register(id.clone());

        // Poison the mutex by panicking while holding the lock
        let pr2 = Arc::clone(&pr);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = pr2.pending.lock().unwrap();
            panic!("intentional poison");
        }));

        // lock_pending should recover from poison (into_inner)
        // Routing should still work
        let response = JsonRpcResponse::success(id, serde_json::json!("recovered"));
        assert!(pr.route_response(&response));
        let result = rx.recv().unwrap().unwrap();
        assert_eq!(result, serde_json::json!("recovered"));
    }

    // ── TransportSamplingSender — create_message ─────────────────────

    fn make_sender_with_responder(
        responder: impl Fn(&JsonRpcRequest) -> serde_json::Value + Send + Sync + 'static,
    ) -> RequestSender {
        let pending = Arc::new(PendingRequests::new());
        let pending_clone = Arc::clone(&pending);
        let send_fn: TransportSendFn = Arc::new(move |msg| {
            if let JsonRpcMessage::Request(req) = msg {
                let id = req.id.clone().unwrap();
                let result = responder(req);
                let response = JsonRpcResponse::success(id, result);
                pending_clone.route_response(&response);
            }
            Ok(())
        });
        RequestSender::new(pending, send_fn)
    }

    #[test]
    fn transport_sampling_sender_create_message_text() {
        let sender = make_sender_with_responder(|_| {
            serde_json::json!({
                "content": {"type": "text", "text": "Hello world"},
                "role": "assistant",
                "model": "test-model",
                "stopReason": "endTurn"
            })
        });
        let sampling = TransportSamplingSender::new(sender);

        let request = SamplingRequest {
            messages: vec![fastmcp_core::SamplingRequestMessage {
                role: SamplingRole::User,
                text: "Hi".to_string(),
            }],
            max_tokens: 100,
            system_prompt: Some("Be helpful".to_string()),
            temperature: Some(0.7),
            stop_sequences: vec!["STOP".to_string()],
            model_hints: vec![],
        };

        let future = SamplingSender::create_message(&sampling, request);
        let result = fastmcp_core::block_on(future).unwrap();
        assert_eq!(result.text, "Hello world");
        assert_eq!(result.model, "test-model");
        assert!(matches!(result.stop_reason, SamplingStopReason::EndTurn));
    }

    #[test]
    fn transport_sampling_sender_create_message_image() {
        let sender = make_sender_with_responder(|_| {
            serde_json::json!({
                "content": {"type": "image", "data": "aW1hZ2VkYXRh", "mimeType": "image/png"},
                "role": "assistant",
                "model": "vision-model",
                "stopReason": "maxTokens"
            })
        });
        let sampling = TransportSamplingSender::new(sender);

        let request = SamplingRequest {
            messages: vec![fastmcp_core::SamplingRequestMessage {
                role: SamplingRole::User,
                text: "Describe image".to_string(),
            }],
            max_tokens: 50,
            system_prompt: None,
            temperature: None,
            stop_sequences: vec![],
            model_hints: vec![],
        };

        let future = SamplingSender::create_message(&sampling, request);
        let result = fastmcp_core::block_on(future).unwrap();
        // Image content is formatted as "[image: N bytes, type: ...]"
        assert!(result.text.contains("image"));
        assert!(result.text.contains("image/png"));
        assert_eq!(result.model, "vision-model");
        assert!(matches!(result.stop_reason, SamplingStopReason::MaxTokens));
    }

    #[test]
    fn transport_sampling_sender_create_message_with_model_hints() {
        let sender = make_sender_with_responder(|req| {
            // Verify model_preferences was sent
            let params: serde_json::Value =
                serde_json::from_value(req.params.clone().unwrap()).unwrap();
            assert!(params["modelPreferences"]["hints"].is_array());
            serde_json::json!({
                "content": {"type": "text", "text": "ok"},
                "role": "assistant",
                "model": "preferred",
                "stopReason": "stopSequence"
            })
        });
        let sampling = TransportSamplingSender::new(sender);

        let request = SamplingRequest {
            messages: vec![fastmcp_core::SamplingRequestMessage {
                role: SamplingRole::User,
                text: "Hi".to_string(),
            }],
            max_tokens: 10,
            system_prompt: None,
            temperature: None,
            stop_sequences: vec![],
            model_hints: vec!["claude-3".to_string()],
        };

        let future = SamplingSender::create_message(&sampling, request);
        let result = fastmcp_core::block_on(future).unwrap();
        assert!(matches!(
            result.stop_reason,
            SamplingStopReason::StopSequence
        ));
    }

    #[test]
    fn transport_sampling_sender_create_message_assistant_role() {
        let sender = make_sender_with_responder(|req| {
            let params: serde_json::Value =
                serde_json::from_value(req.params.clone().unwrap()).unwrap();
            assert_eq!(params["messages"][0]["role"], "assistant");
            serde_json::json!({
                "content": {"type": "text", "text": "continued"},
                "role": "assistant",
                "model": "m",
                "stopReason": "endTurn"
            })
        });
        let sampling = TransportSamplingSender::new(sender);

        let request = SamplingRequest {
            messages: vec![fastmcp_core::SamplingRequestMessage {
                role: SamplingRole::Assistant,
                text: "Previous response".to_string(),
            }],
            max_tokens: 10,
            system_prompt: None,
            temperature: None,
            stop_sequences: vec![],
            model_hints: vec![],
        };

        let future = SamplingSender::create_message(&sampling, request);
        let result = fastmcp_core::block_on(future).unwrap();
        assert_eq!(result.text, "continued");
    }

    // ── TransportElicitationSender — elicit ──────────────────────────

    #[test]
    fn transport_elicitation_sender_form_accept_with_content() {
        let sender = make_sender_with_responder(|req| {
            let params: serde_json::Value =
                serde_json::from_value(req.params.clone().unwrap()).unwrap();
            assert_eq!(params["mode"], "form");
            serde_json::json!({
                "action": "accept",
                "content": {
                    "name": "Alice",
                    "age": 30,
                    "active": true,
                    "score": 9.5,
                    "tags": ["a", "b"],
                    "empty": null
                }
            })
        });
        let elicitation = TransportElicitationSender::new(sender);

        let request = ElicitationRequest {
            message: "Fill the form".to_string(),
            mode: ElicitationMode::Form,
            schema: Some(serde_json::json!({"type": "object"})),
            url: None,
            elicitation_id: None,
        };

        let future = ElicitationSender::elicit(&elicitation, request);
        let result = fastmcp_core::block_on(future).unwrap();
        assert!(matches!(result.action, ElicitationAction::Accept));
        let content = result.content.unwrap();
        assert_eq!(content["name"], serde_json::json!("Alice"));
        assert_eq!(content["age"], serde_json::json!(30));
        assert_eq!(content["active"], serde_json::json!(true));
        assert_eq!(content["score"], serde_json::json!(9.5));
        assert_eq!(content["tags"], serde_json::json!(["a", "b"]));
        assert_eq!(content["empty"], serde_json::Value::Null);
    }

    #[test]
    fn transport_elicitation_sender_form_decline() {
        let sender = make_sender_with_responder(|_| {
            serde_json::json!({
                "action": "decline"
            })
        });
        let elicitation = TransportElicitationSender::new(sender);

        let request = ElicitationRequest {
            message: "Confirm?".to_string(),
            mode: ElicitationMode::Form,
            schema: None,
            url: None,
            elicitation_id: None,
        };

        let future = ElicitationSender::elicit(&elicitation, request);
        let result = fastmcp_core::block_on(future).unwrap();
        assert!(matches!(result.action, ElicitationAction::Decline));
        assert!(result.content.is_none());
    }

    #[test]
    fn transport_elicitation_sender_url_mode() {
        let sender = make_sender_with_responder(|req| {
            let params: serde_json::Value =
                serde_json::from_value(req.params.clone().unwrap()).unwrap();
            assert_eq!(params["mode"], "url");
            assert_eq!(params["url"], "https://example.com/auth");
            serde_json::json!({
                "action": "cancel"
            })
        });
        let elicitation = TransportElicitationSender::new(sender);

        let request = ElicitationRequest {
            message: "Please authenticate".to_string(),
            mode: ElicitationMode::Url,
            schema: None,
            url: Some("https://example.com/auth".to_string()),
            elicitation_id: Some("eid-123".to_string()),
        };

        let future = ElicitationSender::elicit(&elicitation, request);
        let result = fastmcp_core::block_on(future).unwrap();
        assert!(matches!(result.action, ElicitationAction::Cancel));
    }

    // ── TransportRootsProvider — list_roots ──────────────────────────

    #[test]
    fn transport_roots_provider_list_roots() {
        let sender = make_sender_with_responder(|_| {
            serde_json::json!({
                "roots": [
                    {"uri": "file:///home/user/project", "name": "Project"},
                    {"uri": "file:///tmp"}
                ]
            })
        });
        let roots = TransportRootsProvider::new(sender);
        let result = roots.list_roots().unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].uri, "file:///home/user/project");
        assert_eq!(result[0].name, Some("Project".to_string()));
        assert_eq!(result[1].uri, "file:///tmp");
        assert!(result[1].name.is_none());
    }

    #[test]
    fn transport_roots_provider_empty_roots() {
        let sender = make_sender_with_responder(|_| serde_json::json!({ "roots": [] }));
        let roots = TransportRootsProvider::new(sender);
        let result = roots.list_roots().unwrap();
        assert!(result.is_empty());
    }

    // ── RequestSender ID cleanup after success ───────────────────────

    // ── RequestSender — cancelled cx path ──────────────────────────

    #[test]
    fn request_sender_cancelled_cx_returns_cancelled_error() {
        let pending = Arc::new(PendingRequests::new());
        // Transport succeeds but never sends a response
        let send_fn: TransportSendFn = Arc::new(|_| Ok(()));
        let sender = RequestSender::new(Arc::clone(&pending), send_fn);

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let result: McpResult<serde_json::Value> =
            sender.send_request(&cx, "test/cancel", serde_json::json!({}));
        let err = result.unwrap_err();
        assert_eq!(err.code, McpErrorCode::RequestCancelled);
    }

    // ── ElicitationSender url mode with None url/elicitation_id ──

    #[test]
    fn transport_elicitation_sender_url_mode_defaults() {
        let sender = make_sender_with_responder(|req| {
            let params: serde_json::Value =
                serde_json::from_value(req.params.clone().unwrap()).unwrap();
            assert_eq!(params["mode"], "url");
            // url and elicitation_id default to empty strings
            assert_eq!(params["url"], "");
            assert_eq!(params["elicitationId"], "");
            serde_json::json!({ "action": "accept" })
        });
        let elicitation = TransportElicitationSender::new(sender);

        let request = ElicitationRequest {
            message: "Auth".to_string(),
            mode: ElicitationMode::Url,
            schema: None,
            url: None,
            elicitation_id: None,
        };

        let future = ElicitationSender::elicit(&elicitation, request);
        let result = fastmcp_core::block_on(future).unwrap();
        assert!(matches!(result.action, ElicitationAction::Accept));
    }

    // ── TransportRootsProvider — transport failure ───────────────

    #[test]
    fn transport_roots_provider_transport_failure() {
        let pending = Arc::new(PendingRequests::new());
        let send_fn: TransportSendFn = Arc::new(|_| Err("network error".to_string()));
        let sender = RequestSender::new(pending, send_fn);
        let roots = TransportRootsProvider::new(sender);

        let result = roots.list_roots();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .message
                .contains("Failed to send request")
        );
    }

    // ── SamplingSender — transport failure ───────────────────────

    #[test]
    fn transport_sampling_sender_transport_failure() {
        let pending = Arc::new(PendingRequests::new());
        let send_fn: TransportSendFn = Arc::new(|_| Err("connection reset".to_string()));
        let sender = RequestSender::new(pending, send_fn);
        let sampling = TransportSamplingSender::new(sender);

        let request = SamplingRequest {
            messages: vec![fastmcp_core::SamplingRequestMessage {
                role: SamplingRole::User,
                text: "Hi".to_string(),
            }],
            max_tokens: 10,
            system_prompt: None,
            temperature: None,
            stop_sequences: vec![],
            model_hints: vec![],
        };

        let future = SamplingSender::create_message(&sampling, request);
        let result = fastmcp_core::block_on(future);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .message
                .contains("Failed to send request")
        );
    }

    // ── SamplingSender — multiple messages ───────────────────────

    #[test]
    fn transport_sampling_sender_multiple_messages() {
        let sender = make_sender_with_responder(|req| {
            let params: serde_json::Value =
                serde_json::from_value(req.params.clone().unwrap()).unwrap();
            let messages = params["messages"].as_array().unwrap();
            assert_eq!(messages.len(), 3);
            assert_eq!(messages[0]["role"], "user");
            assert_eq!(messages[1]["role"], "assistant");
            assert_eq!(messages[2]["role"], "user");
            serde_json::json!({
                "content": {"type": "text", "text": "done"},
                "role": "assistant",
                "model": "m",
                "stopReason": "endTurn"
            })
        });
        let sampling = TransportSamplingSender::new(sender);

        let request = SamplingRequest {
            messages: vec![
                fastmcp_core::SamplingRequestMessage {
                    role: SamplingRole::User,
                    text: "Hello".to_string(),
                },
                fastmcp_core::SamplingRequestMessage {
                    role: SamplingRole::Assistant,
                    text: "Hi".to_string(),
                },
                fastmcp_core::SamplingRequestMessage {
                    role: SamplingRole::User,
                    text: "Follow up".to_string(),
                },
            ],
            max_tokens: 100,
            system_prompt: None,
            temperature: None,
            stop_sequences: vec![],
            model_hints: vec![],
        };

        let future = SamplingSender::create_message(&sampling, request);
        let result = fastmcp_core::block_on(future).unwrap();
        assert_eq!(result.text, "done");
    }

    // ── RequestSender — ID cleanup after success ────────────────

    #[test]
    fn request_sender_id_cleaned_from_pending_after_success() {
        let pending = Arc::new(PendingRequests::new());
        let pending_clone = Arc::clone(&pending);
        let send_fn: TransportSendFn = Arc::new(move |msg| {
            if let JsonRpcMessage::Request(req) = msg {
                let id = req.id.clone().unwrap();
                let response = JsonRpcResponse::success(id, serde_json::json!(null));
                pending_clone.route_response(&response);
            }
            Ok(())
        });
        let sender = RequestSender::new(Arc::clone(&pending), send_fn);
        let cx = Cx::for_testing();
        let _: serde_json::Value = sender
            .send_request(&cx, "test/method", serde_json::json!({}))
            .unwrap();

        // The pending request should have been consumed by route_response
        let first_id = RequestId::Number(1_000_000);
        let response = JsonRpcResponse::success(first_id, serde_json::json!(null));
        assert!(!pending.route_response(&response));
    }
}
