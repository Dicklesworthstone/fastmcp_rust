//! MCP context with asupersync integration.
//!
//! [`McpContext`] wraps asupersync's [`Cx`] to provide request-scoped
//! capabilities for MCP message handling (tools, resources, prompts).

use std::sync::Arc;

use asupersync::types::CancelReason;
use asupersync::{Budget, Cx, Outcome, RegionId, TaskId};

use crate::{AUTH_STATE_KEY, AuthContext, SessionState};

// ============================================================================
// Notification Sender
// ============================================================================

/// Trait for sending notifications back to the client.
///
/// This is implemented by the server's transport layer to allow handlers
/// to send progress updates and other notifications during execution.
pub trait NotificationSender: Send + Sync {
    /// Sends a progress notification to the client.
    ///
    /// # Arguments
    ///
    /// * `progress` - Current progress value
    /// * `total` - Optional total for determinate progress
    /// * `message` - Optional message describing current status
    fn send_progress(&self, progress: f64, total: Option<f64>, message: Option<&str>);
}

// ============================================================================
// Sampling Sender
// ============================================================================

/// Trait for sending sampling requests to the client.
///
/// Sampling allows the server to request LLM completions from the client.
/// This enables agentic workflows where tools can leverage the client's
/// LLM capabilities.
pub trait SamplingSender: Send + Sync {
    /// Sends a sampling/createMessage request to the client.
    ///
    /// # Arguments
    ///
    /// * `request` - The sampling request parameters
    ///
    /// # Returns
    ///
    /// The sampling response from the client, or an error if sampling failed
    /// or the client doesn't support sampling.
    fn create_message(
        &self,
        request: SamplingRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::McpResult<SamplingResponse>> + Send + '_>,
    >;
}

/// Parameters for a sampling request.
#[derive(Debug, Clone)]
pub struct SamplingRequest {
    /// Conversation messages.
    pub messages: Vec<SamplingRequestMessage>,
    /// Maximum tokens to generate.
    pub max_tokens: u32,
    /// Optional system prompt.
    pub system_prompt: Option<String>,
    /// Sampling temperature (0.0 to 2.0).
    pub temperature: Option<f64>,
    /// Stop sequences to end generation.
    pub stop_sequences: Vec<String>,
    /// Model hints for preference.
    pub model_hints: Vec<String>,
}

impl SamplingRequest {
    /// Creates a new sampling request with the given messages and max tokens.
    #[must_use]
    pub fn new(messages: Vec<SamplingRequestMessage>, max_tokens: u32) -> Self {
        Self {
            messages,
            max_tokens,
            system_prompt: None,
            temperature: None,
            stop_sequences: Vec::new(),
            model_hints: Vec::new(),
        }
    }

    /// Creates a simple user prompt request.
    #[must_use]
    pub fn prompt(text: impl Into<String>, max_tokens: u32) -> Self {
        Self::new(vec![SamplingRequestMessage::user(text)], max_tokens)
    }

    /// Sets the system prompt.
    #[must_use]
    pub fn with_system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(prompt.into());
        self
    }

    /// Sets the temperature.
    #[must_use]
    pub fn with_temperature(mut self, temp: f64) -> Self {
        self.temperature = Some(temp);
        self
    }

    /// Adds stop sequences.
    #[must_use]
    pub fn with_stop_sequences(mut self, sequences: Vec<String>) -> Self {
        self.stop_sequences = sequences;
        self
    }

    /// Adds model hints.
    #[must_use]
    pub fn with_model_hints(mut self, hints: Vec<String>) -> Self {
        self.model_hints = hints;
        self
    }
}

/// A message in a sampling request.
#[derive(Debug, Clone)]
pub struct SamplingRequestMessage {
    /// Message role.
    pub role: SamplingRole,
    /// Message text content.
    pub text: String,
}

impl SamplingRequestMessage {
    /// Creates a user message.
    #[must_use]
    pub fn user(text: impl Into<String>) -> Self {
        Self {
            role: SamplingRole::User,
            text: text.into(),
        }
    }

    /// Creates an assistant message.
    #[must_use]
    pub fn assistant(text: impl Into<String>) -> Self {
        Self {
            role: SamplingRole::Assistant,
            text: text.into(),
        }
    }
}

/// Role in a sampling message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplingRole {
    /// User message.
    User,
    /// Assistant message.
    Assistant,
}

/// Response from a sampling request.
#[derive(Debug, Clone)]
pub struct SamplingResponse {
    /// Generated text content.
    pub text: String,
    /// Model that was used.
    pub model: String,
    /// Reason generation stopped.
    pub stop_reason: SamplingStopReason,
}

impl SamplingResponse {
    /// Creates a new sampling response.
    #[must_use]
    pub fn new(text: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            model: model.into(),
            stop_reason: SamplingStopReason::EndTurn,
        }
    }
}

/// Stop reason for sampling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SamplingStopReason {
    /// End of natural turn.
    #[default]
    EndTurn,
    /// Hit stop sequence.
    StopSequence,
    /// Hit max tokens limit.
    MaxTokens,
}

/// A no-op sampling sender that always returns an error.
///
/// Used when the client doesn't support sampling.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpSamplingSender;

impl SamplingSender for NoOpSamplingSender {
    fn create_message(
        &self,
        _request: SamplingRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::McpResult<SamplingResponse>> + Send + '_>,
    > {
        Box::pin(async {
            Err(crate::McpError::new(
                crate::McpErrorCode::InvalidRequest,
                "Sampling not supported: client does not have sampling capability",
            ))
        })
    }
}

/// A no-op notification sender used when progress reporting is disabled.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpNotificationSender;

impl NotificationSender for NoOpNotificationSender {
    fn send_progress(&self, _progress: f64, _total: Option<f64>, _message: Option<&str>) {
        // No-op: progress reporting disabled
    }
}

/// Progress reporter that wraps a notification sender with a progress token.
///
/// This is the concrete type stored in McpContext that handles sending
/// progress notifications with the correct token.
#[derive(Clone)]
pub struct ProgressReporter {
    sender: Arc<dyn NotificationSender>,
}

impl ProgressReporter {
    /// Creates a new progress reporter with the given sender.
    pub fn new(sender: Arc<dyn NotificationSender>) -> Self {
        Self { sender }
    }

    /// Reports progress to the client.
    ///
    /// # Arguments
    ///
    /// * `progress` - Current progress value (0.0 to 1.0 for fractional, or absolute)
    /// * `message` - Optional message describing current status
    pub fn report(&self, progress: f64, message: Option<&str>) {
        self.sender.send_progress(progress, None, message);
    }

    /// Reports progress with a total for determinate progress bars.
    ///
    /// # Arguments
    ///
    /// * `progress` - Current progress value
    /// * `total` - Total expected value
    /// * `message` - Optional message describing current status
    pub fn report_with_total(&self, progress: f64, total: f64, message: Option<&str>) {
        self.sender.send_progress(progress, Some(total), message);
    }
}

impl std::fmt::Debug for ProgressReporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressReporter").finish_non_exhaustive()
    }
}

/// MCP context that wraps asupersync's capability context.
///
/// `McpContext` provides access to:
/// - Request-scoped identity (request ID, trace context)
/// - Cancellation checkpoints for cancel-safe handlers
/// - Budget/deadline awareness for timeout enforcement
/// - Region-scoped spawning for background work
/// - Sampling capability for LLM completions (if client supports it)
///
/// # Example
///
/// ```ignore
/// async fn my_tool(ctx: &McpContext, args: MyArgs) -> McpResult<Value> {
///     // Check for client disconnect
///     ctx.checkpoint()?;
///
///     // Do work with budget awareness
///     let remaining = ctx.budget();
///
///     // Request an LLM completion (if available)
///     let response = ctx.sample("Write a haiku about Rust", 100).await?;
///
///     // Return result
///     Ok(json!({"result": response.text}))
/// }
/// ```
#[derive(Clone)]
pub struct McpContext {
    /// The underlying capability context.
    cx: Cx,
    /// Unique request identifier for tracing (from JSON-RPC id).
    request_id: u64,
    /// Optional progress reporter for long-running operations.
    progress_reporter: Option<ProgressReporter>,
    /// Session state for per-session key-value storage.
    state: Option<SessionState>,
    /// Optional sampling sender for LLM completions.
    sampling_sender: Option<Arc<dyn SamplingSender>>,
}

impl std::fmt::Debug for McpContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpContext")
            .field("cx", &self.cx)
            .field("request_id", &self.request_id)
            .field("progress_reporter", &self.progress_reporter)
            .field("state", &self.state.is_some())
            .field("sampling_sender", &self.sampling_sender.is_some())
            .finish()
    }
}

impl McpContext {
    /// Creates a new MCP context from an asupersync Cx.
    ///
    /// This is typically called by the server when processing a new request,
    /// creating a new region for the request lifecycle.
    #[must_use]
    pub fn new(cx: Cx, request_id: u64) -> Self {
        Self {
            cx,
            request_id,
            progress_reporter: None,
            state: None,
            sampling_sender: None,
        }
    }

    /// Creates a new MCP context with session state.
    ///
    /// Use this constructor when session state should be accessible to handlers.
    #[must_use]
    pub fn with_state(cx: Cx, request_id: u64, state: SessionState) -> Self {
        Self {
            cx,
            request_id,
            progress_reporter: None,
            state: Some(state),
            sampling_sender: None,
        }
    }

    /// Creates a new MCP context with progress reporting enabled.
    ///
    /// Use this constructor when the client has provided a progress token
    /// and expects progress notifications.
    #[must_use]
    pub fn with_progress(cx: Cx, request_id: u64, reporter: ProgressReporter) -> Self {
        Self {
            cx,
            request_id,
            progress_reporter: Some(reporter),
            state: None,
            sampling_sender: None,
        }
    }

    /// Creates a new MCP context with both state and progress reporting.
    #[must_use]
    pub fn with_state_and_progress(
        cx: Cx,
        request_id: u64,
        state: SessionState,
        reporter: ProgressReporter,
    ) -> Self {
        Self {
            cx,
            request_id,
            progress_reporter: Some(reporter),
            state: Some(state),
            sampling_sender: None,
        }
    }

    /// Sets the sampling sender for this context.
    ///
    /// This enables the `sample()` method to request LLM completions from
    /// the client.
    #[must_use]
    pub fn with_sampling(mut self, sender: Arc<dyn SamplingSender>) -> Self {
        self.sampling_sender = Some(sender);
        self
    }

    /// Returns whether progress reporting is enabled for this context.
    #[must_use]
    pub fn has_progress_reporter(&self) -> bool {
        self.progress_reporter.is_some()
    }

    /// Reports progress on the current operation.
    ///
    /// If progress reporting is not enabled (no progress token was provided),
    /// this method does nothing.
    ///
    /// # Arguments
    ///
    /// * `progress` - Current progress value (0.0 to 1.0 for fractional progress)
    /// * `message` - Optional message describing current status
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn process_files(ctx: &McpContext, files: &[File]) -> McpResult<()> {
    ///     for (i, file) in files.iter().enumerate() {
    ///         ctx.report_progress(i as f64 / files.len() as f64, Some("Processing files"));
    ///         process_file(file).await?;
    ///     }
    ///     ctx.report_progress(1.0, Some("Complete"));
    ///     Ok(())
    /// }
    /// ```
    pub fn report_progress(&self, progress: f64, message: Option<&str>) {
        if let Some(ref reporter) = self.progress_reporter {
            reporter.report(progress, message);
        }
    }

    /// Reports progress with explicit total for determinate progress bars.
    ///
    /// If progress reporting is not enabled, this method does nothing.
    ///
    /// # Arguments
    ///
    /// * `progress` - Current progress value
    /// * `total` - Total expected value
    /// * `message` - Optional message describing current status
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn process_items(ctx: &McpContext, items: &[Item]) -> McpResult<()> {
    ///     let total = items.len() as f64;
    ///     for (i, item) in items.iter().enumerate() {
    ///         ctx.report_progress_with_total(i as f64, total, Some(&format!("Item {}", i)));
    ///         process_item(item).await?;
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn report_progress_with_total(&self, progress: f64, total: f64, message: Option<&str>) {
        if let Some(ref reporter) = self.progress_reporter {
            reporter.report_with_total(progress, total, message);
        }
    }

    /// Returns the unique request identifier.
    ///
    /// This corresponds to the JSON-RPC request ID and is useful for
    /// logging and tracing across the request lifecycle.
    #[must_use]
    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Returns the underlying region ID from asupersync.
    ///
    /// The region represents the request's lifecycle scope - all spawned
    /// tasks belong to this region and will be cleaned up when the
    /// request completes or is cancelled.
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.cx.region_id()
    }

    /// Returns the current task ID.
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.cx.task_id()
    }

    /// Returns the current budget.
    ///
    /// The budget represents the remaining computational resources (time, polls)
    /// available for this request. When exhausted, the request should be
    /// cancelled gracefully.
    #[must_use]
    pub fn budget(&self) -> Budget {
        self.cx.budget()
    }

    /// Checks if cancellation has been requested.
    ///
    /// This includes client disconnection, timeout, or explicit cancellation.
    /// Handlers should check this periodically and exit early if true.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cx.is_cancel_requested() || self.cx.budget().is_exhausted()
    }

    /// Cooperative cancellation checkpoint.
    ///
    /// Call this at natural suspension points in your handler to allow
    /// graceful cancellation. Returns `Err` if cancellation is pending.
    ///
    /// # Errors
    ///
    /// Returns an error if the request has been cancelled and cancellation
    /// is not currently masked.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn process_items(ctx: &McpContext, items: Vec<Item>) -> McpResult<()> {
    ///     for item in items {
    ///         ctx.checkpoint()?;  // Allow cancellation between items
    ///         process_item(item).await?;
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn checkpoint(&self) -> Result<(), CancelledError> {
        self.cx.checkpoint().map_err(|_| CancelledError)?;
        if self.cx.budget().is_exhausted() {
            return Err(CancelledError);
        }
        Ok(())
    }

    /// Executes a closure with cancellation masked.
    ///
    /// While masked, `checkpoint()` will not return an error even if
    /// cancellation is pending. Use this for critical sections that
    /// must complete atomically.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Commit transaction - must not be interrupted
    /// ctx.masked(|| {
    ///     db.commit().await?;
    ///     Ok(())
    /// })
    /// ```
    pub fn masked<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        self.cx.masked(f)
    }

    /// Records a trace event for this request.
    ///
    /// Events are associated with the request's trace context and can be
    /// used for debugging and observability.
    pub fn trace(&self, message: &str) {
        self.cx.trace(message);
    }

    /// Returns a reference to the underlying asupersync Cx.
    ///
    /// Use this when you need direct access to asupersync primitives,
    /// such as spawning tasks or using combinators.
    #[must_use]
    pub fn cx(&self) -> &Cx {
        &self.cx
    }

    // ========================================================================
    // Session State Access
    // ========================================================================

    /// Gets a value from session state by key.
    ///
    /// Returns `None` if:
    /// - Session state is not available (context created without state)
    /// - The key doesn't exist
    /// - Deserialization to type `T` fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn my_tool(ctx: &McpContext, args: MyArgs) -> McpResult<Value> {
    ///     // Get a counter from session state
    ///     let count: Option<i32> = ctx.get_state("counter");
    ///     let count = count.unwrap_or(0);
    ///     // ... use count ...
    ///     Ok(json!({"count": count}))
    /// }
    /// ```
    #[must_use]
    pub fn get_state<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.state.as_ref()?.get(key)
    }

    /// Returns the authentication context for this request, if available.
    #[must_use]
    pub fn auth(&self) -> Option<AuthContext> {
        self.state.as_ref()?.get(AUTH_STATE_KEY)
    }

    /// Stores authentication context into session state.
    ///
    /// Returns `false` if session state is unavailable or serialization fails.
    pub fn set_auth(&self, auth: AuthContext) -> bool {
        let Some(state) = self.state.as_ref() else {
            return false;
        };
        state.set(AUTH_STATE_KEY, auth)
    }

    /// Sets a value in session state.
    ///
    /// The value persists across requests within the same session.
    /// Returns `true` if the value was successfully stored.
    /// Returns `false` if session state is not available or serialization fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn my_tool(ctx: &McpContext, args: MyArgs) -> McpResult<Value> {
    ///     // Increment a counter in session state
    ///     let count: i32 = ctx.get_state("counter").unwrap_or(0);
    ///     ctx.set_state("counter", count + 1);
    ///     Ok(json!({"new_count": count + 1}))
    /// }
    /// ```
    pub fn set_state<T: serde::Serialize>(&self, key: impl Into<String>, value: T) -> bool {
        match &self.state {
            Some(state) => state.set(key, value),
            None => false,
        }
    }

    /// Removes a value from session state.
    ///
    /// Returns the previous value if it existed, or `None` if:
    /// - Session state is not available
    /// - The key didn't exist
    pub fn remove_state(&self, key: &str) -> Option<serde_json::Value> {
        self.state.as_ref()?.remove(key)
    }

    /// Checks if a key exists in session state.
    ///
    /// Returns `false` if session state is not available.
    #[must_use]
    pub fn has_state(&self, key: &str) -> bool {
        self.state.as_ref().is_some_and(|s| s.contains(key))
    }

    /// Returns whether session state is available in this context.
    #[must_use]
    pub fn has_session_state(&self) -> bool {
        self.state.is_some()
    }

    // ========================================================================
    // Sampling (LLM Completions)
    // ========================================================================

    /// Returns whether sampling is available in this context.
    ///
    /// Sampling is available when the client has advertised sampling
    /// capability and a sampling sender has been configured.
    #[must_use]
    pub fn can_sample(&self) -> bool {
        self.sampling_sender.is_some()
    }

    /// Requests an LLM completion from the client.
    ///
    /// This is a convenience method for simple text prompts. For more control
    /// over the request, use [`sample_with_request`](Self::sample_with_request).
    ///
    /// # Arguments
    ///
    /// * `prompt` - The prompt text to send (as a user message)
    /// * `max_tokens` - Maximum number of tokens to generate
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The client doesn't support sampling
    /// - The sampling request fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn my_tool(ctx: &McpContext, topic: String) -> McpResult<String> {
    ///     let response = ctx.sample(&format!("Write a haiku about {topic}"), 100).await?;
    ///     Ok(response.text)
    /// }
    /// ```
    pub async fn sample(
        &self,
        prompt: impl Into<String>,
        max_tokens: u32,
    ) -> crate::McpResult<SamplingResponse> {
        let request = SamplingRequest::prompt(prompt, max_tokens);
        self.sample_with_request(request).await
    }

    /// Requests an LLM completion with full control over the request.
    ///
    /// # Arguments
    ///
    /// * `request` - The full sampling request parameters
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The client doesn't support sampling
    /// - The sampling request fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn my_tool(ctx: &McpContext) -> McpResult<String> {
    ///     let request = SamplingRequest::new(
    ///         vec![
    ///             SamplingRequestMessage::user("Hello!"),
    ///             SamplingRequestMessage::assistant("Hi! How can I help?"),
    ///             SamplingRequestMessage::user("Tell me a joke."),
    ///         ],
    ///         200,
    ///     )
    ///     .with_system_prompt("You are a helpful and funny assistant.")
    ///     .with_temperature(0.8);
    ///
    ///     let response = ctx.sample_with_request(request).await?;
    ///     Ok(response.text)
    /// }
    /// ```
    pub async fn sample_with_request(
        &self,
        request: SamplingRequest,
    ) -> crate::McpResult<SamplingResponse> {
        let sender = self.sampling_sender.as_ref().ok_or_else(|| {
            crate::McpError::new(
                crate::McpErrorCode::InvalidRequest,
                "Sampling not available: client does not support sampling capability",
            )
        })?;

        sender.create_message(request).await
    }

    // ========================================================================
    // Parallel Combinators
    // ========================================================================

    /// Waits for all futures to complete and returns their results.
    ///
    /// This is the N-of-N combinator: all futures must complete before
    /// returning. Results are returned in the same order as input futures.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let futures = vec![
    ///     Box::pin(fetch_user(1)),
    ///     Box::pin(fetch_user(2)),
    ///     Box::pin(fetch_user(3)),
    /// ];
    /// let users = ctx.join_all(futures).await;
    /// ```
    pub async fn join_all<T: Send + 'static>(
        &self,
        futures: Vec<crate::combinator::BoxFuture<'_, T>>,
    ) -> Vec<T> {
        crate::combinator::join_all(&self.cx, futures).await
    }

    /// Races multiple futures, returning the first to complete.
    ///
    /// This is the 1-of-N combinator: the first future to complete wins,
    /// and all others are cancelled and drained.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let futures = vec![
    ///     Box::pin(fetch_from_primary()),
    ///     Box::pin(fetch_from_replica()),
    /// ];
    /// let result = ctx.race(futures).await?;
    /// ```
    pub async fn race<T: Send + 'static>(
        &self,
        futures: Vec<crate::combinator::BoxFuture<'_, T>>,
    ) -> crate::McpResult<T> {
        crate::combinator::race(&self.cx, futures).await
    }

    /// Waits for M of N futures to complete successfully.
    ///
    /// Returns when `required` futures have completed successfully.
    /// Remaining futures are cancelled.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let futures = vec![
    ///     Box::pin(write_to_replica(1)),
    ///     Box::pin(write_to_replica(2)),
    ///     Box::pin(write_to_replica(3)),
    /// ];
    /// let result = ctx.quorum(2, futures).await?;
    /// ```
    pub async fn quorum<T: Send + 'static>(
        &self,
        required: usize,
        futures: Vec<crate::combinator::BoxFuture<'_, crate::McpResult<T>>>,
    ) -> crate::McpResult<crate::combinator::QuorumResult<T>> {
        crate::combinator::quorum(&self.cx, required, futures).await
    }

    /// Races futures and returns the first successful result.
    ///
    /// Unlike `race` which returns the first to complete (success or failure),
    /// `first_ok` returns the first to complete successfully.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let futures = vec![
    ///     Box::pin(try_primary()),
    ///     Box::pin(try_fallback()),
    /// ];
    /// let result = ctx.first_ok(futures).await?;
    /// ```
    pub async fn first_ok<T: Send + 'static>(
        &self,
        futures: Vec<crate::combinator::BoxFuture<'_, crate::McpResult<T>>>,
    ) -> crate::McpResult<T> {
        crate::combinator::first_ok(&self.cx, futures).await
    }
}

/// Error returned when a request has been cancelled.
///
/// This is returned by `checkpoint()` when the request should stop
/// processing. The server will convert this to an appropriate MCP
/// error response.
#[derive(Debug, Clone, Copy)]
pub struct CancelledError;

impl std::fmt::Display for CancelledError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request cancelled")
    }
}

impl std::error::Error for CancelledError {}

/// Extension trait for converting MCP results to asupersync Outcome.
///
/// This bridges the MCP error model with asupersync's 4-valued outcome
/// (Ok, Err, Cancelled, Panicked).
pub trait IntoOutcome<T, E> {
    /// Converts this result into an asupersync Outcome.
    fn into_outcome(self) -> Outcome<T, E>;
}

impl<T, E> IntoOutcome<T, E> for Result<T, E> {
    fn into_outcome(self) -> Outcome<T, E> {
        match self {
            Ok(v) => Outcome::Ok(v),
            Err(e) => Outcome::Err(e),
        }
    }
}

impl<T, E> IntoOutcome<T, E> for Result<T, CancelledError>
where
    E: Default,
{
    fn into_outcome(self) -> Outcome<T, E> {
        match self {
            Ok(v) => Outcome::Ok(v),
            Err(CancelledError) => Outcome::Cancelled(CancelReason::user("request cancelled")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_context_creation() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 42);

        assert_eq!(ctx.request_id(), 42);
    }

    #[test]
    fn test_mcp_context_not_cancelled_initially() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);

        assert!(!ctx.is_cancelled());
    }

    #[test]
    fn test_mcp_context_checkpoint_success() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);

        // Should succeed when not cancelled
        assert!(ctx.checkpoint().is_ok());
    }

    #[test]
    fn test_mcp_context_checkpoint_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let ctx = McpContext::new(cx, 1);

        // Should fail when cancelled
        assert!(ctx.checkpoint().is_err());
    }

    #[test]
    fn test_mcp_context_checkpoint_budget_exhausted() {
        let cx = Cx::for_testing_with_budget(Budget::ZERO);
        let ctx = McpContext::new(cx, 1);

        // Should fail when budget is exhausted
        assert!(ctx.checkpoint().is_err());
    }

    #[test]
    fn test_mcp_context_masked_section() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);

        // masked() should execute the closure and return its value
        let result = ctx.masked(|| 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_mcp_context_budget() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);

        // Budget should be available
        let budget = ctx.budget();
        // For testing Cx, budget should not be exhausted
        assert!(!budget.is_exhausted());
    }

    #[test]
    fn test_cancelled_error_display() {
        let err = CancelledError;
        assert_eq!(err.to_string(), "request cancelled");
    }

    #[test]
    fn test_into_outcome_ok() {
        let result: Result<i32, CancelledError> = Ok(42);
        let outcome: Outcome<i32, CancelledError> = result.into_outcome();
        assert!(matches!(outcome, Outcome::Ok(42)));
    }

    #[test]
    fn test_into_outcome_cancelled() {
        let result: Result<i32, CancelledError> = Err(CancelledError);
        let outcome: Outcome<i32, ()> = result.into_outcome();
        assert!(matches!(outcome, Outcome::Cancelled(_)));
    }

    #[test]
    fn test_mcp_context_no_progress_reporter_by_default() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        assert!(!ctx.has_progress_reporter());
    }

    #[test]
    fn test_mcp_context_with_progress_reporter() {
        let cx = Cx::for_testing();
        let sender = Arc::new(NoOpNotificationSender);
        let reporter = ProgressReporter::new(sender);
        let ctx = McpContext::with_progress(cx, 1, reporter);
        assert!(ctx.has_progress_reporter());
    }

    #[test]
    fn test_report_progress_without_reporter() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        // Should not panic when no reporter is set
        ctx.report_progress(0.5, Some("test"));
        ctx.report_progress_with_total(5.0, 10.0, None);
    }

    #[test]
    fn test_report_progress_with_reporter() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingSender {
            count: AtomicU32,
        }

        impl NotificationSender for CountingSender {
            fn send_progress(&self, _progress: f64, _total: Option<f64>, _message: Option<&str>) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = Cx::for_testing();
        let sender = Arc::new(CountingSender {
            count: AtomicU32::new(0),
        });
        let reporter = ProgressReporter::new(sender.clone());
        let ctx = McpContext::with_progress(cx, 1, reporter);

        ctx.report_progress(0.25, Some("step 1"));
        ctx.report_progress(0.5, None);
        ctx.report_progress_with_total(3.0, 4.0, Some("step 3"));

        assert_eq!(sender.count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_progress_reporter_debug() {
        let sender = Arc::new(NoOpNotificationSender);
        let reporter = ProgressReporter::new(sender);
        let debug = format!("{reporter:?}");
        assert!(debug.contains("ProgressReporter"));
    }

    #[test]
    fn test_noop_notification_sender() {
        let sender = NoOpNotificationSender;
        // Should not panic
        sender.send_progress(0.5, Some(1.0), Some("test"));
    }

    // Session state tests
    #[test]
    fn test_mcp_context_no_session_state_by_default() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        assert!(!ctx.has_session_state());
    }

    #[test]
    fn test_mcp_context_with_session_state() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let ctx = McpContext::with_state(cx, 1, state);
        assert!(ctx.has_session_state());
    }

    #[test]
    fn test_mcp_context_get_set_state() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let ctx = McpContext::with_state(cx, 1, state);

        // Set a value
        assert!(ctx.set_state("counter", 42));

        // Get the value back
        let value: Option<i32> = ctx.get_state("counter");
        assert_eq!(value, Some(42));
    }

    #[test]
    fn test_mcp_context_state_not_available() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);

        // set_state returns false when state is not available
        assert!(!ctx.set_state("key", "value"));

        // get_state returns None when state is not available
        let value: Option<String> = ctx.get_state("key");
        assert!(value.is_none());
    }

    #[test]
    fn test_mcp_context_has_state() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let ctx = McpContext::with_state(cx, 1, state);

        assert!(!ctx.has_state("missing"));

        ctx.set_state("present", true);
        assert!(ctx.has_state("present"));
    }

    #[test]
    fn test_mcp_context_remove_state() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let ctx = McpContext::with_state(cx, 1, state);

        ctx.set_state("key", "value");
        assert!(ctx.has_state("key"));

        let removed = ctx.remove_state("key");
        assert!(removed.is_some());
        assert!(!ctx.has_state("key"));
    }

    #[test]
    fn test_mcp_context_with_state_and_progress() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let sender = Arc::new(NoOpNotificationSender);
        let reporter = ProgressReporter::new(sender);

        let ctx = McpContext::with_state_and_progress(cx, 1, state, reporter);

        assert!(ctx.has_session_state());
        assert!(ctx.has_progress_reporter());
    }
}
