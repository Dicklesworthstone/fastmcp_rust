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
        let mut pending = self.pending.lock().unwrap();
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
            let mut pending = self.pending.lock().unwrap();
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
        let mut pending = self.pending.lock().unwrap();
        pending.remove(id);
    }

    /// Cancels all pending requests with a connection closed error.
    pub fn cancel_all(&self) {
        let mut pending = self.pending.lock().unwrap();
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
        _cx: &Cx,
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

        // Wait for response
        // TODO: Add timeout based on budget
        match receiver.recv() {
            Ok(Ok(value)) => serde_json::from_value(value)
                .map_err(|e| McpError::internal_error(format!("Failed to parse response: {}", e))),
            Ok(Err(error)) => Err(McpError::new(McpErrorCode::from(error.code), error.message)),
            Err(_) => Err(McpError::internal_error(
                "Response channel closed unexpectedly",
            )),
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

            // Create a temporary Cx for the request
            let cx = Cx::for_testing();

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

            // Create a temporary Cx for the request
            let cx = Cx::for_testing();

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
        let cx = Cx::for_testing();
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
}
