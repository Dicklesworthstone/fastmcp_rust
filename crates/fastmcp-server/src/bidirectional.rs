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
//! // Send a request and await the response
//! let response = request_sender.send_request(
//!     &cx,
//!     "sampling/createMessage",
//!     params,
//! ).await?;
//! ```

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::channel::oneshot::RecvError;
use fastmcp_core::{
    ElicitationAction, ElicitationMode, ElicitationRequest, ElicitationResponse, ElicitationSender,
    McpError, McpErrorCode, McpRequestCancellation, McpResult, SamplingRequest, SamplingResponse,
    SamplingRole, SamplingSender, SamplingStopReason,
};
use fastmcp_protocol::{JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId};

/// Default maximum number of concurrent server-to-client requests.
pub const DEFAULT_MAX_IN_FLIGHT_REQUESTS: usize = 1_024;

/// Absolute maximum accepted by [`PendingRequests::with_max_in_flight`].
pub const HARD_MAX_IN_FLIGHT_REQUESTS: usize = 16_384;

const FIRST_SERVER_REQUEST_ID: i64 = 1_000_000;
const INVALID_LIMIT_ERROR: &str = "Invalid bidirectional request limit";
const IN_FLIGHT_LIMIT_ERROR: &str = "Bidirectional request limit reached";
const REQUEST_ID_EXHAUSTED_ERROR: &str = "Bidirectional request IDs exhausted";
const INVALID_RESPONSE_ERROR: &str = "Invalid JSON-RPC response";
const REMOTE_RESPONSE_ERROR: &str = "Client returned an error response";
const CONNECTION_CLOSED_ERROR: &str = "Bidirectional connection closed";
const TRANSPORT_SEND_ERROR: &str = "Failed to send bidirectional request";
const RESPONSE_CHANNEL_ERROR: &str = "Bidirectional response channel closed";
const RESPONSE_PAYLOAD_ERROR: &str = "Invalid bidirectional response payload";
const REQUEST_PAYLOAD_ERROR: &str = "Failed to serialize bidirectional request payload";
const INVALID_ELICITATION_REQUEST_ERROR: &str = "Invalid elicitation request";

// ============================================================================
// Pending Request Tracking
// ============================================================================

/// A bounded, single-use channel for receiving a response.
type PendingResponse = McpResult<serde_json::Value>;
type ResponseSender = oneshot::Sender<PendingResponse>;
type ResponseReceiver = oneshot::Receiver<PendingResponse>;

#[derive(Debug)]
struct PendingState {
    requests: HashMap<RequestId, PendingRequest>,
    next_id: Option<i64>,
    closed: bool,
}

#[derive(Debug)]
struct PendingRequest {
    sender: ResponseSender,
    request_cancellation: Option<McpRequestCancellation>,
}

/// Tracks pending server-to-client requests.
///
/// When the server sends a request to the client, it registers a response sender
/// here. When a response arrives, the dispatcher routes it to the correct sender.
#[derive(Debug)]
pub struct PendingRequests {
    state: Mutex<PendingState>,
    max_in_flight: usize,
}

impl PendingRequests {
    pub(crate) fn validate_max_in_flight(max_in_flight: usize) -> McpResult<()> {
        if !(1..=HARD_MAX_IN_FLIGHT_REQUESTS).contains(&max_in_flight) {
            return Err(McpError::new(
                McpErrorCode::InvalidParams,
                INVALID_LIMIT_ERROR,
            ));
        }
        Ok(())
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, PendingState> {
        match self.state.lock() {
            Ok(guard) => guard,
            // Prefer availability over panic if another task panicked while holding the lock.
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Creates a new pending request tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(PendingState {
                requests: HashMap::new(),
                next_id: Some(FIRST_SERVER_REQUEST_ID),
                closed: false,
            }),
            max_in_flight: DEFAULT_MAX_IN_FLIGHT_REQUESTS,
        }
    }

    /// Creates a tracker with a caller-selected finite in-flight limit.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` when `max_in_flight` is zero or exceeds
    /// [`HARD_MAX_IN_FLIGHT_REQUESTS`].
    pub fn with_max_in_flight(max_in_flight: usize) -> McpResult<Self> {
        Self::validate_max_in_flight(max_in_flight)?;

        Ok(Self {
            state: Mutex::new(PendingState {
                requests: HashMap::new(),
                next_id: Some(FIRST_SERVER_REQUEST_ID),
                closed: false,
            }),
            max_in_flight,
        })
    }

    /// Returns the configured maximum number of in-flight requests.
    #[must_use]
    pub const fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    /// Returns the current number of in-flight requests.
    #[must_use]
    pub fn in_flight_len(&self) -> usize {
        self.lock_state().requests.len()
    }

    /// Atomically allocates a collision-free ID and registers its response
    /// channel. Allocation scans at most `max_in_flight + 1` candidates.
    fn register(&self) -> McpResult<(RequestId, ResponseReceiver)> {
        self.register_with_cancellation(None)
    }

    fn register_with_cancellation(
        &self,
        request_cancellation: Option<McpRequestCancellation>,
    ) -> McpResult<(RequestId, ResponseReceiver)> {
        let mut state = self.lock_state();
        if state.closed {
            return Err(McpError::internal_error(CONNECTION_CLOSED_ERROR));
        }
        if state.requests.len() >= self.max_in_flight {
            return Err(McpError::internal_error(IN_FLIGHT_LIMIT_ERROR));
        }

        for _ in 0..=self.max_in_flight {
            let Some(candidate) = state.next_id else {
                return Err(McpError::internal_error(REQUEST_ID_EXHAUSTED_ERROR));
            };
            let id = RequestId::Number(candidate);
            state.next_id = candidate.checked_add(1);

            if let Entry::Vacant(entry) = state.requests.entry(id.clone()) {
                let (sender, receiver) = oneshot::channel();
                entry.insert(PendingRequest {
                    sender,
                    request_cancellation,
                });
                return Ok((id, receiver));
            }
        }

        Err(McpError::internal_error(REQUEST_ID_EXHAUSTED_ERROR))
    }

    /// Routes a response to the appropriate pending request.
    ///
    /// Returns `true` if the response was routed, `false` if no matching request was found.
    pub fn route_response(&self, response: &JsonRpcResponse) -> bool {
        let Some(ref id) = response.id else {
            return false;
        };

        // Validate every response invariant before consuming the waiter. This
        // also rejects manually-constructed values that bypass serde's guards.
        let validated = ValidatedResponse::from_response(response);

        let sender = {
            let mut state = self.lock_state();
            state.requests.remove(id)
        };

        if let Some(pending) = sender {
            let outcome = validated.into_pending_response();
            // The response path is synchronous, so use the immediate bounded
            // oneshot bridge. Receiver dropout returns the value and is safe to
            // ignore after the map entry has been removed.
            let _ = pending.sender.send_blocking(outcome);
            true
        } else {
            false
        }
    }

    /// Removes a pending request (e.g., on timeout or cancellation).
    pub fn remove(&self, id: &RequestId) {
        let mut state = self.lock_state();
        state.requests.remove(id);
    }

    /// Wakes pending server-to-client calls whose owning incoming request is
    /// terminal, without mutating the caller-owned connection context.
    pub(crate) fn cancel_cancelled(&self) -> usize {
        let cancelled = {
            let mut state = self.lock_state();
            let ids: Vec<RequestId> = state
                .requests
                .iter()
                .filter_map(|(id, pending)| {
                    pending
                        .request_cancellation
                        .as_ref()
                        .is_some_and(McpRequestCancellation::is_terminal)
                        .then(|| id.clone())
                })
                .collect();
            ids.into_iter()
                .filter_map(|id| state.requests.remove(&id))
                .collect::<Vec<_>>()
        };
        let count = cancelled.len();
        for pending in cancelled {
            let _ = pending
                .sender
                .send_blocking(Err(McpError::request_cancelled()));
        }
        count
    }

    /// Permanently closes the tracker and cancels every pending request.
    ///
    /// Closing is irreversible: later registration attempts fail with the
    /// same fixed connection-closed error. This prevents a request racing with
    /// connection teardown from installing an orphaned waiter after the drain.
    pub fn cancel_all(&self) {
        let senders: Vec<PendingRequest> = {
            let mut state = self.lock_state();
            state.closed = true;
            state.requests.drain().map(|(_, pending)| pending).collect()
        };
        for pending in senders {
            let _ = pending
                .sender
                .send_blocking(Err(McpError::internal_error(CONNECTION_CLOSED_ERROR)));
        }
    }

    #[cfg(test)]
    fn set_next_id_for_test(&self, next_id: i64) {
        self.lock_state().next_id = Some(next_id);
    }
}

enum ValidatedResponse<'a> {
    Success(&'a serde_json::Value),
    Error(&'a JsonRpcError),
    Invalid,
}

impl<'a> ValidatedResponse<'a> {
    fn from_response(response: &'a JsonRpcResponse) -> Self {
        if response.validate().is_err() {
            return Self::Invalid;
        }

        match (&response.result, &response.error) {
            (Some(result), None) => Self::Success(result),
            (None, Some(error)) => Self::Error(error),
            (Some(_), Some(_)) | (None, None) => Self::Invalid,
        }
    }

    fn into_pending_response(self) -> PendingResponse {
        match self {
            Self::Success(result) => Ok(result.clone()),
            Self::Error(error) => Err(McpError::new(
                McpErrorCode::from(error.code),
                REMOTE_RESPONSE_ERROR,
            )),
            Self::Invalid => Err(McpError::internal_error(INVALID_RESPONSE_ERROR)),
        }
    }
}

impl Default for PendingRequests {
    fn default() -> Self {
        Self::new()
    }
}

/// Removes a registered waiter if its request future is cancelled or dropped
/// before a response consumes the map entry.
struct PendingRequestGuard<'a> {
    pending: &'a PendingRequests,
    id: RequestId,
}

impl Drop for PendingRequestGuard<'_> {
    fn drop(&mut self) {
        self.pending.remove(&self.id);
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
    /// Request-local cancellation domain installed by server dispatch.
    request_cancellation: Option<McpRequestCancellation>,
}

impl RequestSender {
    /// Creates a new request sender.
    pub fn new(pending: Arc<PendingRequests>, send_fn: TransportSendFn) -> Self {
        Self {
            pending,
            send_fn,
            request_cancellation: None,
        }
    }

    pub(crate) fn for_request(&self, request_cancellation: McpRequestCancellation) -> Self {
        Self {
            pending: Arc::clone(&self.pending),
            send_fn: Arc::clone(&self.send_fn),
            request_cancellation: Some(request_cancellation),
        }
    }

    fn request_is_terminal(&self) -> bool {
        self.request_cancellation
            .as_ref()
            .is_some_and(McpRequestCancellation::is_terminal)
    }

    /// Sends a request to the client and waits for a response.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The finite in-flight request limit is reached
    /// - The transport send fails
    /// - The request times out (based on budget)
    /// - The client returns an error response
    /// - The response envelope or typed payload is invalid
    /// - The connection is closed
    pub async fn send_request<T: serde::de::DeserializeOwned>(
        &self,
        cx: &Cx,
        method: &str,
        params: serde_json::Value,
    ) -> McpResult<T> {
        if cx.checkpoint().is_err() || self.request_is_terminal() {
            return Err(McpError::request_cancelled());
        }

        let (id, mut receiver) = self
            .pending
            .register_with_cancellation(self.request_cancellation.clone())?;
        let _guard = PendingRequestGuard {
            pending: self.pending.as_ref(),
            id: id.clone(),
        };
        if cx.checkpoint().is_err() || self.request_is_terminal() {
            return Err(McpError::request_cancelled());
        }

        let request = JsonRpcRequest::new(method.to_string(), Some(params), id.clone());
        let message = JsonRpcMessage::Request(request);

        // Send the request through the transport
        if (self.send_fn)(&message).is_err() {
            return Err(McpError::internal_error(TRANSPORT_SEND_ERROR));
        }

        let response = if let Some(request_cancellation) = &self.request_cancellation {
            let mut receive = std::pin::pin!(receiver.recv(cx));
            let mut terminated = std::pin::pin!(request_cancellation.terminated());

            poll_fn(|task_cx| {
                // Request termination owns ties: check before polling either
                // source, after arming its waiter, and once more after polling
                // the response future.
                if request_cancellation.is_terminal() {
                    return Poll::Ready(Err(McpError::request_cancelled()));
                }
                if terminated.as_mut().poll(task_cx).is_ready() {
                    return Poll::Ready(Err(McpError::request_cancelled()));
                }

                let receive_poll = receive.as_mut().poll(task_cx);
                if request_cancellation.is_terminal() {
                    return Poll::Ready(Err(McpError::request_cancelled()));
                }
                match receive_poll {
                    Poll::Ready(Ok(response)) => Poll::Ready(response),
                    Poll::Ready(Err(RecvError::Cancelled)) => {
                        Poll::Ready(Err(McpError::request_cancelled()))
                    }
                    Poll::Ready(Err(RecvError::Closed | RecvError::PolledAfterCompletion)) => {
                        Poll::Ready(Err(McpError::internal_error(RESPONSE_CHANNEL_ERROR)))
                    }
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?
        } else {
            match receiver.recv(cx).await {
                Ok(response) => response?,
                Err(RecvError::Cancelled) => return Err(McpError::request_cancelled()),
                Err(RecvError::Closed | RecvError::PolledAfterCompletion) => {
                    return Err(McpError::internal_error(RESPONSE_CHANNEL_ERROR));
                }
            }
        };

        // A response and cancellation may become visible together. Preserve
        // caller cancellation/budget precedence before decoding peer data.
        if cx.checkpoint().is_err() || self.request_is_terminal() {
            return Err(McpError::request_cancelled());
        }

        serde_json::from_value(response)
            .map_err(|_| McpError::internal_error(RESPONSE_PAYLOAD_ERROR))
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
                .map_err(|_| McpError::internal_error(REQUEST_PAYLOAD_ERROR))?;

            let cx = Cx::current().ok_or_else(|| {
                McpError::internal_error("No current asupersync Cx for sampling request")
            })?;

            let result: fastmcp_protocol::CreateMessageResult = self
                .sender
                .send_request(&cx, "sampling/createMessage", params_value)
                .await?;

            if result.role != fastmcp_protocol::Role::Assistant {
                return Err(McpError::internal_error(RESPONSE_PAYLOAD_ERROR));
            }

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
            let request_mode = request.mode;
            let params_value = match request_mode {
                ElicitationMode::Form => {
                    let requested_schema = request.schema.ok_or_else(|| {
                        McpError::invalid_params(INVALID_ELICITATION_REQUEST_ERROR)
                    })?;
                    let params = fastmcp_protocol::ElicitRequestFormParams {
                        mode: fastmcp_protocol::ElicitMode::Form,
                        message: request.message.clone(),
                        requested_schema,
                    };
                    serde_json::to_value(&params)
                        .map_err(|_| McpError::internal_error(REQUEST_PAYLOAD_ERROR))?
                }
                ElicitationMode::Url => {
                    let url = request
                        .url
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                            McpError::invalid_params(INVALID_ELICITATION_REQUEST_ERROR)
                        })?;
                    let elicitation_id = request
                        .elicitation_id
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                        McpError::invalid_params(INVALID_ELICITATION_REQUEST_ERROR)
                    })?;
                    let params = fastmcp_protocol::ElicitRequestUrlParams {
                        mode: fastmcp_protocol::ElicitMode::Url,
                        message: request.message.clone(),
                        url,
                        elicitation_id,
                    };
                    serde_json::to_value(&params)
                        .map_err(|_| McpError::internal_error(REQUEST_PAYLOAD_ERROR))?
                }
            };

            let cx = Cx::current().ok_or_else(|| {
                McpError::internal_error("No current asupersync Cx for elicitation request")
            })?;

            let result: fastmcp_protocol::ElicitResult = self
                .sender
                .send_request(&cx, "elicitation/elicit", params_value)
                .await?;

            let action = match result.action {
                fastmcp_protocol::ElicitAction::Accept => ElicitationAction::Accept,
                fastmcp_protocol::ElicitAction::Decline => ElicitationAction::Decline,
                fastmcp_protocol::ElicitAction::Cancel => ElicitationAction::Cancel,
            };

            // Decline/cancel content is not accepted form data. It remains a
            // wire-level SHOULD deviation in the full protocol design, but
            // this legacy core response has no quarantine slot, so discard it
            // instead of exposing it to business logic. Accepted URL mode must
            // never carry in-band form content.
            let content = match (request_mode, result.action, result.content) {
                (ElicitationMode::Form, fastmcp_protocol::ElicitAction::Accept, Some(content)) => {
                    content
                }
                (ElicitationMode::Form, fastmcp_protocol::ElicitAction::Accept, None)
                | (ElicitationMode::Url, fastmcp_protocol::ElicitAction::Accept, Some(_)) => {
                    return Err(McpError::internal_error(RESPONSE_PAYLOAD_ERROR));
                }
                (
                    _,
                    fastmcp_protocol::ElicitAction::Decline
                    | fastmcp_protocol::ElicitAction::Cancel,
                    _,
                )
                | (ElicitationMode::Url, fastmcp_protocol::ElicitAction::Accept, None) => {
                    return Ok(ElicitationResponse {
                        action,
                        content: None,
                    });
                }
            };

            // Convert HashMap<String, ElicitContentValue> to HashMap<String, serde_json::Value>.
            let content = {
                let mut map = std::collections::HashMap::new();
                for (key, value) in content {
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
                Some(map)
            };

            Ok(ElicitationResponse { action, content })
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
    pub async fn list_roots(&self, cx: &Cx) -> McpResult<Vec<fastmcp_protocol::Root>> {
        let result: fastmcp_protocol::ListRootsResult = self
            .sender
            .send_request(cx, "roots/list", serde_json::json!({}))
            .await?;
        Ok(result.roots)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_core::block_on;

    fn receive_pending(mut receiver: ResponseReceiver) -> PendingResponse {
        let cx = Cx::for_testing();
        block_on(receiver.recv(&cx)).expect("pending response channel must remain connected")
    }

    #[test]
    fn test_pending_requests_register_and_route() {
        let pending = PendingRequests::new();

        // Register a request
        let (id, receiver) = pending.register().unwrap();

        // Simulate a response
        let response = JsonRpcResponse::success(id, serde_json::json!({"result": "ok"}));
        assert!(pending.route_response(&response));

        // Receive the response
        let result = receive_pending(receiver);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::json!({"result": "ok"}));
    }

    #[test]
    fn test_pending_requests_error_response() {
        let pending = PendingRequests::new();

        let (id, receiver) = pending.register().unwrap();

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
        let result = receive_pending(receiver);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().message, REMOTE_RESPONSE_ERROR);
    }

    #[test]
    fn test_pending_requests_cancel_all() {
        let pending = PendingRequests::new();

        let (_, receiver1) = pending.register().unwrap();
        let (_, receiver2) = pending.register().unwrap();

        // Cancel all
        pending.cancel_all();

        // Both should receive errors
        let result1 = receive_pending(receiver1);
        let result2 = receive_pending(receiver2);
        assert!(result1.is_err());
        assert!(result2.is_err());
    }

    #[test]
    fn request_local_cancellation_wakes_a_pending_bidirectional_wait() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct WakeFlag(AtomicBool);

        impl std::task::Wake for WakeFlag {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Release);
            }
        }

        let pending = Arc::new(PendingRequests::new());
        let sent = Arc::new(AtomicBool::new(false));
        let sent_flag = Arc::clone(&sent);
        let sender = RequestSender::new(
            Arc::clone(&pending),
            Arc::new(move |_| {
                sent_flag.store(true, Ordering::Release);
                Ok(())
            }),
        );
        let cancellation = McpRequestCancellation::new();
        let scoped = sender.for_request(cancellation.clone());
        let cx = Cx::for_testing();
        let mut future = Box::pin(scoped.send_request::<serde_json::Value>(
            &cx,
            "test/request-local-cancellation",
            serde_json::json!({}),
        ));
        let wake_flag = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = std::task::Waker::from(Arc::clone(&wake_flag));
        let mut task_cx = std::task::Context::from_waker(&waker);

        assert!(std::future::Future::poll(future.as_mut(), &mut task_cx).is_pending());
        assert!(sent.load(Ordering::Acquire));
        assert_eq!(pending.in_flight_len(), 1);

        assert!(cancellation.cancel());
        assert!(wake_flag.0.load(Ordering::Acquire));
        let error = block_on(future).unwrap_err();
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert_eq!(pending.in_flight_len(), 0);
    }

    #[test]
    fn request_finalization_wakes_and_removes_a_pending_bidirectional_wait() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct WakeFlag(AtomicBool);

        impl std::task::Wake for WakeFlag {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Release);
            }
        }

        let pending = Arc::new(PendingRequests::new());
        let sender = RequestSender::new(Arc::clone(&pending), Arc::new(|_| Ok(())));
        let cancellation = McpRequestCancellation::new();
        let scoped = sender.for_request(cancellation.clone());
        let cx = Cx::for_testing();
        let mut future = Box::pin(scoped.send_request::<serde_json::Value>(
            &cx,
            "test/request-finalization",
            serde_json::json!({}),
        ));
        let wake_flag = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = std::task::Waker::from(Arc::clone(&wake_flag));
        let mut task_cx = std::task::Context::from_waker(&waker);

        assert!(std::future::Future::poll(future.as_mut(), &mut task_cx).is_pending());
        assert_eq!(pending.in_flight_len(), 1);
        assert!(cancellation.begin_finalization());
        assert!(wake_flag.0.load(Ordering::Acquire));

        let error = block_on(future).expect_err("finalization must terminate the retained wait");
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert_eq!(pending.in_flight_len(), 0);
    }

    #[test]
    fn request_local_cancellation_wins_when_response_is_already_ready() {
        let pending = Arc::new(PendingRequests::new());
        let pending_for_send = Arc::clone(&pending);
        let cancellation = McpRequestCancellation::new();
        let cancellation_for_send = cancellation.clone();
        let sender = RequestSender::new(
            Arc::clone(&pending),
            Arc::new(move |message| {
                let JsonRpcMessage::Request(request) = message else {
                    return Err("expected request".to_string());
                };
                let id = request
                    .id
                    .clone()
                    .ok_or_else(|| "expected request id".to_string())?;
                let response = JsonRpcResponse::success(id, serde_json::json!({"ready": true}));
                if !pending_for_send.route_response(&response) {
                    return Err("response was not routed".to_string());
                }
                let _ = cancellation_for_send.cancel();
                Ok(())
            }),
        )
        .for_request(cancellation);
        let cx = Cx::for_testing();

        let error = block_on(sender.send_request::<serde_json::Value>(
            &cx,
            "test/cancellation-precedence",
            serde_json::json!({}),
        ))
        .expect_err("request-local cancellation must own an observable tie");

        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert_eq!(pending.in_flight_len(), 0);
        assert!(!cx.is_cancel_requested());
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
        let (id, _receiver) = pr.register().unwrap();
        // IDs start at 1_000_000
        assert_eq!(id, RequestId::Number(1_000_000));
        assert_eq!(pr.max_in_flight(), DEFAULT_MAX_IN_FLIGHT_REQUESTS);
    }

    #[test]
    fn pending_requests_ids_are_sequential() {
        let pr = PendingRequests::new();
        let (id1, _receiver1) = pr.register().unwrap();
        let (id2, _receiver2) = pr.register().unwrap();
        let (id3, _receiver3) = pr.register().unwrap();
        assert_eq!(id1, RequestId::Number(1_000_000));
        assert_eq!(id2, RequestId::Number(1_000_001));
        assert_eq!(id3, RequestId::Number(1_000_002));
    }

    #[test]
    fn pending_requests_limit_configuration_has_exact_hard_boundary() {
        let at_hard_limit =
            PendingRequests::with_max_in_flight(HARD_MAX_IN_FLIGHT_REQUESTS).unwrap();
        assert_eq!(at_hard_limit.max_in_flight(), HARD_MAX_IN_FLIGHT_REQUESTS);

        for invalid in [0, HARD_MAX_IN_FLIGHT_REQUESTS + 1] {
            let error = PendingRequests::with_max_in_flight(invalid).unwrap_err();
            assert_eq!(error.code, McpErrorCode::InvalidParams);
            assert_eq!(error.message, INVALID_LIMIT_ERROR);
        }
    }

    #[test]
    fn pending_requests_enforces_exact_in_flight_boundary_and_recovers_capacity() {
        let pr = PendingRequests::with_max_in_flight(2).unwrap();
        let (id1, receiver1) = pr.register().unwrap();
        let (_id2, _receiver2) = pr.register().unwrap();
        assert_eq!(pr.in_flight_len(), 2);

        let error = pr.register().unwrap_err();
        assert_eq!(error.code, McpErrorCode::InternalError);
        assert_eq!(error.message, IN_FLIGHT_LIMIT_ERROR);

        let response = JsonRpcResponse::success(id1, serde_json::json!(1));
        assert!(pr.route_response(&response));
        assert_eq!(receive_pending(receiver1).unwrap(), serde_json::json!(1));
        assert_eq!(pr.in_flight_len(), 1);

        let (_id3, _receiver3) = pr.register().unwrap();
        assert_eq!(pr.in_flight_len(), 2);
    }

    #[test]
    fn pending_request_ids_fail_closed_before_wrap_or_reuse() {
        let pr = PendingRequests::with_max_in_flight(4).unwrap();
        pr.set_next_id_for_test(i64::MAX);
        let (max_id, _max_receiver) = pr.register().unwrap();
        assert_eq!(max_id, RequestId::Number(i64::MAX));

        let exhausted = pr
            .register()
            .expect_err("request IDs must never wrap back to an earlier value");
        assert_eq!(exhausted.message, REQUEST_ID_EXHAUSTED_ERROR);
        assert_eq!(pr.in_flight_len(), 1);

        pr.remove(&max_id);
        let still_exhausted = pr
            .register()
            .expect_err("exhaustion must remain permanent after the last waiter leaves");
        assert_eq!(still_exhausted.message, REQUEST_ID_EXHAUSTED_ERROR);
    }

    #[test]
    fn pending_requests_remove_prevents_routing() {
        let pr = PendingRequests::new();
        let (id, _receiver) = pr.register().unwrap();

        // Remove the pending request
        pr.remove(&id);

        // Routing should fail now
        let response = JsonRpcResponse::success(id, serde_json::json!(null));
        assert!(!pr.route_response(&response));
    }

    #[test]
    fn pending_requests_route_response_without_id_returns_false() {
        let pr = PendingRequests::new();
        let (id, receiver) = pr.register().unwrap();
        // A response with no id
        let response = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed("2.0"),
            id: None,
            result: Some(serde_json::json!(null)),
            error: None,
        };
        assert!(!pr.route_response(&response));
        assert_eq!(pr.in_flight_len(), 1);

        let response = JsonRpcResponse::success(id, serde_json::json!(42));
        assert!(pr.route_response(&response));
        assert_eq!(receive_pending(receiver).unwrap(), serde_json::json!(42));
    }

    #[test]
    fn pending_requests_route_response_with_explicit_null_result() {
        let pr = PendingRequests::new();
        let (id, receiver) = pr.register().unwrap();

        // An explicit JSON null is a present and valid success result.
        let response = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed("2.0"),
            id: Some(id),
            result: Some(serde_json::Value::Null),
            error: None,
        };
        assert!(pr.route_response(&response));

        let result = receive_pending(receiver).unwrap();
        assert_eq!(result, serde_json::Value::Null);
    }

    #[test]
    fn pending_requests_rejects_invalid_response_shapes_and_versions() {
        let cases = [
            (
                Some(serde_json::Value::Null),
                Some(JsonRpcError {
                    code: -32_603,
                    message: "secret both-member detail".to_string(),
                    data: Some(serde_json::json!({"secret": true})),
                }),
                "2.0",
            ),
            (None, None, "2.0"),
            (Some(serde_json::Value::Null), None, "1.0"),
        ];

        for (result, error, version) in cases {
            let pr = PendingRequests::new();
            let (id, receiver) = pr.register().unwrap();
            let response = JsonRpcResponse {
                jsonrpc: std::borrow::Cow::Borrowed(version),
                result,
                error,
                id: Some(id),
            };

            assert!(pr.route_response(&response));
            let error = receive_pending(receiver).unwrap_err();
            assert_eq!(error.code, McpErrorCode::InternalError);
            assert_eq!(error.message, INVALID_RESPONSE_ERROR);
            assert!(error.data.is_none());
            assert_eq!(pr.in_flight_len(), 0);
        }
    }

    #[test]
    fn pending_requests_route_after_receiver_dropped_does_not_panic() {
        let pr = PendingRequests::new();
        let (id, receiver) = pr.register().unwrap();

        // Drop the receiver
        drop(receiver);

        // Routing should still succeed (sender.send returns Err but is ignored)
        let response = JsonRpcResponse::success(id, serde_json::json!(42));
        assert!(pr.route_response(&response));
    }

    #[test]
    fn pending_requests_cancel_all_clears_pending() {
        let pr = PendingRequests::new();
        let (id, _receiver) = pr.register().unwrap();

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
    fn pending_requests_cancel_all_permanently_rejects_new_waiters() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let pending = Arc::new(PendingRequests::new());
        let (_, receiver) = pending.register().unwrap();

        pending.cancel_all();
        pending.cancel_all();

        let cancelled = receive_pending(receiver).unwrap_err();
        assert_eq!(cancelled.code, McpErrorCode::InternalError);
        assert_eq!(cancelled.message, CONNECTION_CLOSED_ERROR);
        assert_eq!(pending.in_flight_len(), 0);

        let registration_error = pending.register().unwrap_err();
        assert_eq!(registration_error.code, McpErrorCode::InternalError);
        assert_eq!(registration_error.message, CONNECTION_CLOSED_ERROR);

        let send_called = Arc::new(AtomicBool::new(false));
        let send_called_for_callback = Arc::clone(&send_called);
        let sender = RequestSender::new(
            Arc::clone(&pending),
            Arc::new(move |_| {
                send_called_for_callback.store(true, Ordering::Release);
                Ok(())
            }),
        );
        let cx = Cx::for_testing();
        let error = block_on(sender.send_request::<serde_json::Value>(
            &cx,
            "test/after-close",
            serde_json::json!({}),
        ))
        .unwrap_err();
        assert_eq!(error.code, McpErrorCode::InternalError);
        assert_eq!(error.message, CONNECTION_CLOSED_ERROR);
        assert!(!send_called.load(Ordering::Acquire));
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
            block_on(sender.send_request(&cx, "test/method", serde_json::json!({})));
        let err = result.unwrap_err();
        assert_eq!(err.message, TRANSPORT_SEND_ERROR);
        assert!(!err.message.contains("transport down"));
    }

    #[test]
    fn request_sender_transport_failure_cleans_up_pending() {
        let pending = Arc::new(PendingRequests::new());
        let send_fn: TransportSendFn = Arc::new(|_| Err("fail".to_string()));
        let sender = RequestSender::new(Arc::clone(&pending), send_fn);

        let cx = Cx::for_testing();
        let _error: McpResult<serde_json::Value> =
            block_on(sender.send_request(&cx, "test/method", serde_json::json!({})));

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

    #[test]
    fn dropping_request_future_releases_in_flight_capacity() {
        let pending = Arc::new(PendingRequests::with_max_in_flight(1).unwrap());
        let send_fn: TransportSendFn = Arc::new(|_| Ok(()));
        let sender = RequestSender::new(Arc::clone(&pending), send_fn);
        let cx = Cx::for_testing();
        {
            let mut future = Box::pin(sender.send_request::<serde_json::Value>(
                &cx,
                "test/method",
                serde_json::json!({}),
            ));
            let waker = std::task::Waker::noop();
            let mut task_cx = std::task::Context::from_waker(waker);

            assert!(std::future::Future::poll(future.as_mut(), &mut task_cx).is_pending());
            assert_eq!(pending.in_flight_len(), 1);
        }
        assert_eq!(pending.in_flight_len(), 0);
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
            block_on(sender.send_request(&cx, "test/method", serde_json::json!({})));
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
            block_on(sender.send_request(&cx, "test/method", serde_json::json!({})));
        let err = result.unwrap_err();
        assert_eq!(err.message, REMOTE_RESPONSE_ERROR);
        assert!(!err.message.contains("bad request"));
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
            block_on(sender.send_request(&cx, "test/method", serde_json::json!({})));
        let err = result.unwrap_err();
        assert_eq!(err.message, RESPONSE_CHANNEL_ERROR);
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
            block_on(sender.send_request(&cx, "test/method", serde_json::json!({})));
        let err = result.unwrap_err();
        assert_eq!(err.message, RESPONSE_PAYLOAD_ERROR);
        assert!(!err.message.contains("expected"));
    }

    // ── cancel_all error details ─────────────────────────────────────

    #[test]
    fn cancel_all_sends_connection_closed_error() {
        let pr = PendingRequests::new();
        let (_, receiver) = pr.register().unwrap();
        pr.cancel_all();
        let result = receive_pending(receiver);
        let err = result.unwrap_err();
        assert_eq!(err.code, McpErrorCode::InternalError);
        assert_eq!(err.message, CONNECTION_CLOSED_ERROR);
        assert!(err.data.is_none());
    }

    // ── route_response with error containing data ────────────────────

    #[test]
    fn route_response_error_with_data() {
        let pr = PendingRequests::new();
        let (id, receiver) = pr.register().unwrap();
        let response = JsonRpcResponse::error(
            Some(id),
            JsonRpcError {
                code: -32001,
                message: "custom error".to_string(),
                data: Some(serde_json::json!({"detail": "extra info"})),
            },
        );
        assert!(pr.route_response(&response));
        let result = receive_pending(receiver);
        let err = result.unwrap_err();
        assert_eq!(err.code, McpErrorCode::ResourceNotFound);
        assert_eq!(err.message, REMOTE_RESPONSE_ERROR);
        assert!(err.data.is_none());
    }

    // ── Multiple concurrent register/route ───────────────────────────

    #[test]
    fn pending_requests_multiple_register_and_route_independently() {
        let pr = PendingRequests::new();
        let (id1, rx1) = pr.register().unwrap();
        let (id2, rx2) = pr.register().unwrap();
        let (id3, rx3) = pr.register().unwrap();

        // Route them out of order
        let r2 = JsonRpcResponse::success(id2.clone(), serde_json::json!("second"));
        let r3 = JsonRpcResponse::success(id3.clone(), serde_json::json!("third"));
        let r1 = JsonRpcResponse::success(id1.clone(), serde_json::json!("first"));
        assert!(pr.route_response(&r2));
        assert!(pr.route_response(&r3));
        assert!(pr.route_response(&r1));

        assert_eq!(receive_pending(rx1).unwrap(), serde_json::json!("first"));
        assert_eq!(receive_pending(rx2).unwrap(), serde_json::json!("second"));
        assert_eq!(receive_pending(rx3).unwrap(), serde_json::json!("third"));
    }

    #[test]
    fn pending_request_trackers_isolate_identical_wire_ids() {
        let connection_a = PendingRequests::new();
        let connection_b = PendingRequests::new();
        let (id_a, receiver_a) = connection_a.register().unwrap();
        let (id_b, receiver_b) = connection_b.register().unwrap();
        assert_eq!(id_a, id_b);

        let response = JsonRpcResponse::success(id_b, serde_json::json!("connection-b"));
        assert!(connection_b.route_response(&response));
        assert_eq!(
            receive_pending(receiver_b).unwrap(),
            serde_json::json!("connection-b")
        );
        assert_eq!(connection_b.in_flight_len(), 0);

        // Routing on B cannot consume A's same-numbered waiter because the
        // registry itself is the immutable connection ownership boundary.
        assert_eq!(connection_a.in_flight_len(), 1);
        connection_a.cancel_all();
        let error = receive_pending(receiver_a).unwrap_err();
        assert_eq!(error.message, CONNECTION_CLOSED_ERROR);
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

    // ── lock_state with poisoned mutex ───────────────────────────────

    #[test]
    fn pending_requests_lock_state_recovers_from_poison() {
        let pr = Arc::new(PendingRequests::new());
        let (id, receiver) = pr.register().unwrap();

        // Poison the mutex by panicking while holding the lock
        let pr2 = Arc::clone(&pr);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = pr2.state.lock().unwrap();
            panic!("intentional poison");
        }));

        // lock_state should recover from poison (into_inner)
        // Routing should still work
        let response = JsonRpcResponse::success(id, serde_json::json!("recovered"));
        assert!(pr.route_response(&response));
        let result = receive_pending(receiver).unwrap();
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

    #[test]
    fn transport_sampling_sender_rejects_non_assistant_result_role() {
        let sender = make_sender_with_responder(|_| {
            serde_json::json!({
                "content": {"type": "text", "text": "not authoritative"},
                "role": "user",
                "model": "m",
                "stopReason": "endTurn"
            })
        });
        let sampling = TransportSamplingSender::new(sender);
        let request = SamplingRequest::prompt("Hi", 10);

        let error = fastmcp_core::block_on(SamplingSender::create_message(&sampling, request))
            .expect_err("sampling results must retain the documented assistant role");

        assert_eq!(error.message, RESPONSE_PAYLOAD_ERROR);
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
            schema: Some(serde_json::json!({"type": "object"})),
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
        let cx = Cx::for_testing();
        let result = block_on(roots.list_roots(&cx)).unwrap();
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
        let cx = Cx::for_testing();
        let result = block_on(roots.list_roots(&cx)).unwrap();
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
            block_on(sender.send_request(&cx, "test/cancel", serde_json::json!({})));
        let err = result.unwrap_err();
        assert_eq!(err.code, McpErrorCode::RequestCancelled);
    }

    // ── Elicitation request/response validation ─────────────────

    #[test]
    fn transport_elicitation_sender_rejects_missing_url_fields_before_send() {
        let sender = make_sender_with_responder(|_| {
            panic!("an invalid URL elicitation must not reach the transport")
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
        let error = fastmcp_core::block_on(future)
            .expect_err("missing URL fields must be a local input error");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(error.message, INVALID_ELICITATION_REQUEST_ERROR);
    }

    #[test]
    fn transport_elicitation_sender_rejects_accepted_form_without_content() {
        let sender = make_sender_with_responder(|_| serde_json::json!({ "action": "accept" }));
        let elicitation = TransportElicitationSender::new(sender);
        let request = ElicitationRequest::form(
            "Fill the form",
            serde_json::json!({
                "type": "object"
            }),
        );

        let error = fastmcp_core::block_on(ElicitationSender::elicit(&elicitation, request))
            .expect_err("accepted form mode must carry form content");
        assert_eq!(error.message, RESPONSE_PAYLOAD_ERROR);
    }

    #[test]
    fn transport_elicitation_sender_rejects_accepted_url_content() {
        let sender = make_sender_with_responder(|_| {
            serde_json::json!({
                "action": "accept",
                "content": {"credential": "must-not-be-exposed"}
            })
        });
        let elicitation = TransportElicitationSender::new(sender);
        let request = ElicitationRequest::url("Authenticate", "https://example.com", "eid-1");

        let error = fastmcp_core::block_on(ElicitationSender::elicit(&elicitation, request))
            .expect_err("accepted URL mode must not expose in-band content");
        assert_eq!(error.message, RESPONSE_PAYLOAD_ERROR);
        assert!(!error.message.contains("credential"));
    }

    #[test]
    fn transport_elicitation_sender_does_not_expose_non_accept_content() {
        let sender = make_sender_with_responder(|_| {
            serde_json::json!({
                "action": "decline",
                "content": {"credential": "must-not-be-exposed"}
            })
        });
        let elicitation = TransportElicitationSender::new(sender);
        let request = ElicitationRequest::form(
            "Fill the form",
            serde_json::json!({
                "type": "object"
            }),
        );

        let result = fastmcp_core::block_on(ElicitationSender::elicit(&elicitation, request))
            .expect("decline content is a SHOULD deviation, not accepted data");
        assert_eq!(result.action, ElicitationAction::Decline);
        assert!(result.content.is_none());
    }

    // ── TransportRootsProvider — transport failure ───────────────

    #[test]
    fn transport_roots_provider_transport_failure() {
        let pending = Arc::new(PendingRequests::new());
        let send_fn: TransportSendFn = Arc::new(|_| Err("network error".to_string()));
        let sender = RequestSender::new(pending, send_fn);
        let roots = TransportRootsProvider::new(sender);

        let cx = Cx::for_testing();
        let result = block_on(roots.list_roots(&cx));
        assert_eq!(result.unwrap_err().message, TRANSPORT_SEND_ERROR);
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
        assert_eq!(result.unwrap_err().message, TRANSPORT_SEND_ERROR);
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
        let _: serde_json::Value =
            block_on(sender.send_request(&cx, "test/method", serde_json::json!({}))).unwrap();

        // The pending request should have been consumed by route_response
        let first_id = RequestId::Number(1_000_000);
        let response = JsonRpcResponse::success(first_id, serde_json::json!(null));
        assert!(!pending.route_response(&response));
    }
}
