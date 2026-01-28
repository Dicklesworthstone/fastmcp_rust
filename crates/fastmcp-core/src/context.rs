//! MCP context with asupersync integration.
//!
//! [`McpContext`] wraps asupersync's [`Cx`] to provide request-scoped
//! capabilities for MCP message handling (tools, resources, prompts).

use std::future::Future;
use std::pin::Pin;
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

// ============================================================================
// Elicitation Sender
// ============================================================================

/// Trait for sending elicitation requests to the client.
///
/// Elicitation allows the server to request user input from the client.
/// This enables interactive workflows where tools can prompt users for
/// additional information.
pub trait ElicitationSender: Send + Sync {
    /// Sends an elicitation/create request to the client.
    ///
    /// # Arguments
    ///
    /// * `request` - The elicitation request parameters
    ///
    /// # Returns
    ///
    /// The elicitation response from the client, or an error if elicitation
    /// failed or the client doesn't support elicitation.
    fn elicit(
        &self,
        request: ElicitationRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::McpResult<ElicitationResponse>> + Send + '_>,
    >;
}

/// Parameters for an elicitation request.
#[derive(Debug, Clone)]
pub struct ElicitationRequest {
    /// Mode of elicitation (form or URL).
    pub mode: ElicitationMode,
    /// Message to present to the user.
    pub message: String,
    /// For form mode: JSON Schema for the expected response.
    pub schema: Option<serde_json::Value>,
    /// For URL mode: URL to navigate to.
    pub url: Option<String>,
    /// For URL mode: Unique elicitation ID.
    pub elicitation_id: Option<String>,
}

impl ElicitationRequest {
    /// Creates a form mode elicitation request.
    #[must_use]
    pub fn form(message: impl Into<String>, schema: serde_json::Value) -> Self {
        Self {
            mode: ElicitationMode::Form,
            message: message.into(),
            schema: Some(schema),
            url: None,
            elicitation_id: None,
        }
    }

    /// Creates a URL mode elicitation request.
    #[must_use]
    pub fn url(
        message: impl Into<String>,
        url: impl Into<String>,
        elicitation_id: impl Into<String>,
    ) -> Self {
        Self {
            mode: ElicitationMode::Url,
            message: message.into(),
            schema: None,
            url: Some(url.into()),
            elicitation_id: Some(elicitation_id.into()),
        }
    }
}

/// Mode of elicitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElicitationMode {
    /// Form mode - collect user input via in-band form.
    Form,
    /// URL mode - redirect user to external URL.
    Url,
}

/// Response from an elicitation request.
#[derive(Debug, Clone)]
pub struct ElicitationResponse {
    /// User's action (accept, decline, cancel).
    pub action: ElicitationAction,
    /// Form data (only present when action is Accept and mode is Form).
    pub content: Option<std::collections::HashMap<String, serde_json::Value>>,
}

impl ElicitationResponse {
    /// Creates an accepted response with form data.
    #[must_use]
    pub fn accept(content: std::collections::HashMap<String, serde_json::Value>) -> Self {
        Self {
            action: ElicitationAction::Accept,
            content: Some(content),
        }
    }

    /// Creates an accepted response for URL mode (no content).
    #[must_use]
    pub fn accept_url() -> Self {
        Self {
            action: ElicitationAction::Accept,
            content: None,
        }
    }

    /// Creates a declined response.
    #[must_use]
    pub fn decline() -> Self {
        Self {
            action: ElicitationAction::Decline,
            content: None,
        }
    }

    /// Creates a cancelled response.
    #[must_use]
    pub fn cancel() -> Self {
        Self {
            action: ElicitationAction::Cancel,
            content: None,
        }
    }

    /// Returns true if the user accepted.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        matches!(self.action, ElicitationAction::Accept)
    }

    /// Returns true if the user declined.
    #[must_use]
    pub fn is_declined(&self) -> bool {
        matches!(self.action, ElicitationAction::Decline)
    }

    /// Returns true if the user cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self.action, ElicitationAction::Cancel)
    }

    /// Gets a string value from the form content.
    #[must_use]
    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.content.as_ref()?.get(key)?.as_str()
    }

    /// Gets a boolean value from the form content.
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.content.as_ref()?.get(key)?.as_bool()
    }

    /// Gets an integer value from the form content.
    #[must_use]
    pub fn get_int(&self, key: &str) -> Option<i64> {
        self.content.as_ref()?.get(key)?.as_i64()
    }
}

/// Action taken by the user in response to elicitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElicitationAction {
    /// User accepted/submitted the form.
    Accept,
    /// User explicitly declined.
    Decline,
    /// User dismissed without choice.
    Cancel,
}

/// A no-op elicitation sender that always returns an error.
///
/// Used when the client doesn't support elicitation.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpElicitationSender;

impl ElicitationSender for NoOpElicitationSender {
    fn elicit(
        &self,
        _request: ElicitationRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::McpResult<ElicitationResponse>> + Send + '_>,
    > {
        Box::pin(async {
            Err(crate::McpError::new(
                crate::McpErrorCode::InvalidRequest,
                "Elicitation not supported: client does not have elicitation capability",
            ))
        })
    }
}

// ============================================================================
// Resource Reader (Cross-Component Access)
// ============================================================================

/// Maximum depth for nested resource reads to prevent infinite recursion.
pub const MAX_RESOURCE_READ_DEPTH: u32 = 10;

/// A single item of resource content.
///
/// Mirrors the protocol's ResourceContent but lives in core to avoid
/// circular dependencies.
#[derive(Debug, Clone)]
pub struct ResourceContentItem {
    /// Resource URI.
    pub uri: String,
    /// MIME type.
    pub mime_type: Option<String>,
    /// Text content (if text).
    pub text: Option<String>,
    /// Binary content (if blob, base64-encoded).
    pub blob: Option<String>,
}

impl ResourceContentItem {
    /// Creates a text resource content item.
    #[must_use]
    pub fn text(uri: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            mime_type: Some("text/plain".to_string()),
            text: Some(text.into()),
            blob: None,
        }
    }

    /// Creates a JSON resource content item.
    #[must_use]
    pub fn json(uri: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            mime_type: Some("application/json".to_string()),
            text: Some(text.into()),
            blob: None,
        }
    }

    /// Creates a binary resource content item.
    #[must_use]
    pub fn blob(
        uri: impl Into<String>,
        mime_type: impl Into<String>,
        blob: impl Into<String>,
    ) -> Self {
        Self {
            uri: uri.into(),
            mime_type: Some(mime_type.into()),
            text: None,
            blob: Some(blob.into()),
        }
    }

    /// Returns the text content, if present.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// Returns the blob content, if present.
    #[must_use]
    pub fn as_blob(&self) -> Option<&str> {
        self.blob.as_deref()
    }

    /// Returns true if this is a text resource.
    #[must_use]
    pub fn is_text(&self) -> bool {
        self.text.is_some()
    }

    /// Returns true if this is a blob resource.
    #[must_use]
    pub fn is_blob(&self) -> bool {
        self.blob.is_some()
    }
}

/// Result of reading a resource.
#[derive(Debug, Clone)]
pub struct ResourceReadResult {
    /// The content items.
    pub contents: Vec<ResourceContentItem>,
}

impl ResourceReadResult {
    /// Creates a new resource read result with the given contents.
    #[must_use]
    pub fn new(contents: Vec<ResourceContentItem>) -> Self {
        Self { contents }
    }

    /// Creates a single-item text result.
    #[must_use]
    pub fn text(uri: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            contents: vec![ResourceContentItem::text(uri, text)],
        }
    }

    /// Returns the first text content, if present.
    #[must_use]
    pub fn first_text(&self) -> Option<&str> {
        self.contents.first().and_then(|c| c.as_text())
    }

    /// Returns the first blob content, if present.
    #[must_use]
    pub fn first_blob(&self) -> Option<&str> {
        self.contents.first().and_then(|c| c.as_blob())
    }
}

/// Trait for reading resources from within handlers.
///
/// This trait is implemented by the server's Router to allow tools,
/// resources, and prompts to read other resources. It enables
/// cross-component composition and code reuse.
///
/// The trait uses boxed futures to avoid complex lifetime issues
/// with async traits.
pub trait ResourceReader: Send + Sync {
    /// Reads a resource by URI.
    ///
    /// # Arguments
    ///
    /// * `cx` - The asupersync context
    /// * `uri` - The resource URI to read
    /// * `depth` - Current recursion depth (to prevent infinite loops)
    ///
    /// # Returns
    ///
    /// The resource contents, or an error if the resource doesn't exist
    /// or reading fails.
    fn read_resource(
        &self,
        cx: &Cx,
        uri: &str,
        depth: u32,
    ) -> Pin<Box<dyn Future<Output = crate::McpResult<ResourceReadResult>> + Send + '_>>;
}

// ============================================================================
// Tool Caller (Cross-Component Access)
// ============================================================================

/// Maximum depth for nested tool calls to prevent infinite recursion.
pub const MAX_TOOL_CALL_DEPTH: u32 = 10;

/// A single item of content returned from a tool call.
///
/// Mirrors the protocol's Content type but lives in core to avoid
/// circular dependencies.
#[derive(Debug, Clone)]
pub enum ToolContentItem {
    /// Text content.
    Text {
        /// The text content.
        text: String,
    },
    /// Image content (base64-encoded).
    Image {
        /// Base64-encoded image data.
        data: String,
        /// MIME type of the image.
        mime_type: String,
    },
    /// Embedded resource reference.
    Resource {
        /// Resource URI.
        uri: String,
        /// MIME type.
        mime_type: Option<String>,
        /// Text content.
        text: Option<String>,
    },
}

impl ToolContentItem {
    /// Creates a text content item.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }

    /// Returns the text content, if this is a text item.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text { text } => Some(text),
            _ => None,
        }
    }

    /// Returns true if this is a text content item.
    #[must_use]
    pub fn is_text(&self) -> bool {
        matches!(self, Self::Text { .. })
    }
}

/// Result of calling a tool.
#[derive(Debug, Clone)]
pub struct ToolCallResult {
    /// The content items returned by the tool.
    pub content: Vec<ToolContentItem>,
    /// Whether the tool returned an error.
    pub is_error: bool,
}

impl ToolCallResult {
    /// Creates a successful tool result with the given content.
    #[must_use]
    pub fn success(content: Vec<ToolContentItem>) -> Self {
        Self {
            content,
            is_error: false,
        }
    }

    /// Creates a successful tool result with a single text item.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContentItem::text(text)],
            is_error: false,
        }
    }

    /// Creates an error tool result.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContentItem::text(message)],
            is_error: true,
        }
    }

    /// Returns the first text content, if present.
    #[must_use]
    pub fn first_text(&self) -> Option<&str> {
        self.content.first().and_then(|c| c.as_text())
    }
}

/// Trait for calling tools from within handlers.
///
/// This trait is implemented by the server's Router to allow tools,
/// resources, and prompts to call other tools. It enables
/// cross-component composition and code reuse.
///
/// The trait uses boxed futures to avoid complex lifetime issues
/// with async traits.
pub trait ToolCaller: Send + Sync {
    /// Calls a tool by name with the given arguments.
    ///
    /// # Arguments
    ///
    /// * `cx` - The asupersync context
    /// * `name` - The tool name to call
    /// * `args` - The arguments as a JSON value
    /// * `depth` - Current recursion depth (to prevent infinite loops)
    ///
    /// # Returns
    ///
    /// The tool result, or an error if the tool doesn't exist
    /// or execution fails.
    fn call_tool(
        &self,
        cx: &Cx,
        name: &str,
        args: serde_json::Value,
        depth: u32,
    ) -> Pin<Box<dyn Future<Output = crate::McpResult<ToolCallResult>> + Send + '_>>;
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
/// - Elicitation capability for user input requests (if client supports it)
/// - Cross-component resource reading (if router is attached)
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
///     // Request user input (if available)
///     let input = ctx.elicit_form("Enter your name", schema).await?;
///
///     // Read a resource from within a tool
///     let config = ctx.read_resource("config://app").await?;
///
///     // Call another tool from within a tool
///     let result = ctx.call_tool("other_tool", json!({"arg": "value"})).await?;
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
    /// Optional elicitation sender for user input requests.
    elicitation_sender: Option<Arc<dyn ElicitationSender>>,
    /// Optional resource reader for cross-component access.
    resource_reader: Option<Arc<dyn ResourceReader>>,
    /// Current resource read depth (to prevent infinite recursion).
    resource_read_depth: u32,
    /// Optional tool caller for cross-component access.
    tool_caller: Option<Arc<dyn ToolCaller>>,
    /// Current tool call depth (to prevent infinite recursion).
    tool_call_depth: u32,
}

impl std::fmt::Debug for McpContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpContext")
            .field("cx", &self.cx)
            .field("request_id", &self.request_id)
            .field("progress_reporter", &self.progress_reporter)
            .field("state", &self.state.is_some())
            .field("sampling_sender", &self.sampling_sender.is_some())
            .field("elicitation_sender", &self.elicitation_sender.is_some())
            .field("resource_reader", &self.resource_reader.is_some())
            .field("resource_read_depth", &self.resource_read_depth)
            .field("tool_caller", &self.tool_caller.is_some())
            .field("tool_call_depth", &self.tool_call_depth)
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
            elicitation_sender: None,
            resource_reader: None,
            resource_read_depth: 0,
            tool_caller: None,
            tool_call_depth: 0,
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
            elicitation_sender: None,
            resource_reader: None,
            resource_read_depth: 0,
            tool_caller: None,
            tool_call_depth: 0,
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
            elicitation_sender: None,
            resource_reader: None,
            resource_read_depth: 0,
            tool_caller: None,
            tool_call_depth: 0,
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
            elicitation_sender: None,
            resource_reader: None,
            resource_read_depth: 0,
            tool_caller: None,
            tool_call_depth: 0,
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

    /// Sets the elicitation sender for this context.
    ///
    /// This enables the `elicit()` methods to request user input from
    /// the client.
    #[must_use]
    pub fn with_elicitation(mut self, sender: Arc<dyn ElicitationSender>) -> Self {
        self.elicitation_sender = Some(sender);
        self
    }

    /// Sets the resource reader for this context.
    ///
    /// This enables the `read_resource()` methods to read resources from
    /// within tool, resource, or prompt handlers.
    #[must_use]
    pub fn with_resource_reader(mut self, reader: Arc<dyn ResourceReader>) -> Self {
        self.resource_reader = Some(reader);
        self
    }

    /// Sets the resource read depth for this context.
    ///
    /// This is used internally to track recursion depth when reading
    /// resources from within resource handlers.
    #[must_use]
    pub fn with_resource_read_depth(mut self, depth: u32) -> Self {
        self.resource_read_depth = depth;
        self
    }

    /// Sets the tool caller for this context.
    ///
    /// This enables the `call_tool()` methods to call other tools from
    /// within tool, resource, or prompt handlers.
    #[must_use]
    pub fn with_tool_caller(mut self, caller: Arc<dyn ToolCaller>) -> Self {
        self.tool_caller = Some(caller);
        self
    }

    /// Sets the tool call depth for this context.
    ///
    /// This is used internally to track recursion depth when calling
    /// tools from within tool handlers.
    #[must_use]
    pub fn with_tool_call_depth(mut self, depth: u32) -> Self {
        self.tool_call_depth = depth;
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
    // Elicitation (User Input Requests)
    // ========================================================================

    /// Returns whether elicitation is available in this context.
    ///
    /// Elicitation is available when the client has advertised elicitation
    /// capability and an elicitation sender has been configured.
    #[must_use]
    pub fn can_elicit(&self) -> bool {
        self.elicitation_sender.is_some()
    }

    /// Requests user input via a form.
    ///
    /// This presents a form to the user with fields defined by the JSON schema.
    /// The user can accept (submit the form), decline, or cancel.
    ///
    /// # Arguments
    ///
    /// * `message` - Message to display explaining what input is needed
    /// * `schema` - JSON Schema defining the form fields
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The client doesn't support elicitation
    /// - The elicitation request fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn my_tool(ctx: &McpContext) -> McpResult<String> {
    ///     let schema = serde_json::json!({
    ///         "type": "object",
    ///         "properties": {
    ///             "name": {"type": "string"},
    ///             "age": {"type": "integer"}
    ///         },
    ///         "required": ["name"]
    ///     });
    ///     let response = ctx.elicit_form("Please enter your details", schema).await?;
    ///     if response.is_accepted() {
    ///         let name = response.get_string("name").unwrap_or("Unknown");
    ///         Ok(format!("Hello, {name}!"))
    ///     } else {
    ///         Ok("User declined input".to_string())
    ///     }
    /// }
    /// ```
    pub async fn elicit_form(
        &self,
        message: impl Into<String>,
        schema: serde_json::Value,
    ) -> crate::McpResult<ElicitationResponse> {
        let request = ElicitationRequest::form(message, schema);
        self.elicit_with_request(request).await
    }

    /// Requests user interaction via an external URL.
    ///
    /// This directs the user to an external URL for sensitive operations like
    /// OAuth flows, payment processing, or credential collection.
    ///
    /// # Arguments
    ///
    /// * `message` - Message to display explaining why the URL visit is needed
    /// * `url` - The URL the user should navigate to
    /// * `elicitation_id` - Unique ID for tracking this elicitation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The client doesn't support elicitation
    /// - The elicitation request fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn my_tool(ctx: &McpContext) -> McpResult<String> {
    ///     let response = ctx.elicit_url(
    ///         "Please authenticate with your GitHub account",
    ///         "https://github.com/login/oauth/authorize?...",
    ///         "github-auth-12345",
    ///     ).await?;
    ///     if response.is_accepted() {
    ///         Ok("Authentication successful".to_string())
    ///     } else {
    ///         Ok("Authentication cancelled".to_string())
    ///     }
    /// }
    /// ```
    pub async fn elicit_url(
        &self,
        message: impl Into<String>,
        url: impl Into<String>,
        elicitation_id: impl Into<String>,
    ) -> crate::McpResult<ElicitationResponse> {
        let request = ElicitationRequest::url(message, url, elicitation_id);
        self.elicit_with_request(request).await
    }

    /// Requests user input with full control over the request.
    ///
    /// # Arguments
    ///
    /// * `request` - The full elicitation request parameters
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The client doesn't support elicitation
    /// - The elicitation request fails
    pub async fn elicit_with_request(
        &self,
        request: ElicitationRequest,
    ) -> crate::McpResult<ElicitationResponse> {
        let sender = self.elicitation_sender.as_ref().ok_or_else(|| {
            crate::McpError::new(
                crate::McpErrorCode::InvalidRequest,
                "Elicitation not available: client does not support elicitation capability",
            )
        })?;

        sender.elicit(request).await
    }

    // ========================================================================
    // Resource Reading (Cross-Component Access)
    // ========================================================================

    /// Returns whether resource reading is available in this context.
    ///
    /// Resource reading is available when a resource reader (Router) has
    /// been attached to this context.
    #[must_use]
    pub fn can_read_resources(&self) -> bool {
        self.resource_reader.is_some()
    }

    /// Returns the current resource read depth.
    ///
    /// This is used to track recursion when resources read other resources.
    #[must_use]
    pub fn resource_read_depth(&self) -> u32 {
        self.resource_read_depth
    }

    /// Reads a resource by URI.
    ///
    /// This allows tools, resources, and prompts to read other resources
    /// configured on the same server. This enables composition and code reuse.
    ///
    /// # Arguments
    ///
    /// * `uri` - The resource URI to read
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No resource reader is available (context not configured for resource access)
    /// - The resource is not found
    /// - Maximum recursion depth is exceeded
    /// - The resource read fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// #[tool]
    /// async fn process_config(ctx: &McpContext) -> Result<String, ToolError> {
    ///     let config = ctx.read_resource("config://app").await?;
    ///     let text = config.first_text()
    ///         .ok_or(ToolError::InvalidConfig)?;
    ///     Ok(format!("Config loaded: {}", text))
    /// }
    /// ```
    pub async fn read_resource(&self, uri: &str) -> crate::McpResult<ResourceReadResult> {
        // Check if we have a resource reader
        let reader = self.resource_reader.as_ref().ok_or_else(|| {
            crate::McpError::new(
                crate::McpErrorCode::InternalError,
                "Resource reading not available: no router attached to context",
            )
        })?;

        // Check recursion depth
        if self.resource_read_depth >= MAX_RESOURCE_READ_DEPTH {
            return Err(crate::McpError::new(
                crate::McpErrorCode::InternalError,
                format!(
                    "Maximum resource read depth ({}) exceeded; possible infinite recursion",
                    MAX_RESOURCE_READ_DEPTH
                ),
            ));
        }

        // Read the resource with incremented depth
        reader
            .read_resource(&self.cx, uri, self.resource_read_depth + 1)
            .await
    }

    /// Reads a resource and extracts the text content.
    ///
    /// This is a convenience method that reads a resource and returns
    /// the first text content item.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The resource read fails
    /// - The resource has no text content
    ///
    /// # Example
    ///
    /// ```ignore
    /// let text = ctx.read_resource_text("file://readme.md").await?;
    /// println!("Content: {}", text);
    /// ```
    pub async fn read_resource_text(&self, uri: &str) -> crate::McpResult<String> {
        let result = self.read_resource(uri).await?;
        result.first_text().map(String::from).ok_or_else(|| {
            crate::McpError::new(
                crate::McpErrorCode::InternalError,
                format!("Resource '{}' has no text content", uri),
            )
        })
    }

    /// Reads a resource and parses it as JSON.
    ///
    /// This is a convenience method that reads a resource and deserializes
    /// the text content as JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The resource read fails
    /// - The resource has no text content
    /// - JSON deserialization fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// #[derive(Deserialize)]
    /// struct Config {
    ///     database_url: String,
    /// }
    ///
    /// let config: Config = ctx.read_resource_json("config://app").await?;
    /// println!("Database: {}", config.database_url);
    /// ```
    pub async fn read_resource_json<T: serde::de::DeserializeOwned>(
        &self,
        uri: &str,
    ) -> crate::McpResult<T> {
        let text = self.read_resource_text(uri).await?;
        serde_json::from_str(&text).map_err(|e| {
            crate::McpError::new(
                crate::McpErrorCode::InternalError,
                format!("Failed to parse resource '{}' as JSON: {}", uri, e),
            )
        })
    }

    // ========================================================================
    // Tool Calling (Cross-Component Access)
    // ========================================================================

    /// Returns whether tool calling is available in this context.
    ///
    /// Tool calling is available when a tool caller (Router) has
    /// been attached to this context.
    #[must_use]
    pub fn can_call_tools(&self) -> bool {
        self.tool_caller.is_some()
    }

    /// Returns the current tool call depth.
    ///
    /// This is used to track recursion when tools call other tools.
    #[must_use]
    pub fn tool_call_depth(&self) -> u32 {
        self.tool_call_depth
    }

    /// Calls a tool by name with the given arguments.
    ///
    /// This allows tools, resources, and prompts to call other tools
    /// configured on the same server. This enables composition and code reuse.
    ///
    /// # Arguments
    ///
    /// * `name` - The tool name to call
    /// * `args` - The arguments as a JSON value
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No tool caller is available (context not configured for tool access)
    /// - The tool is not found
    /// - Maximum recursion depth is exceeded
    /// - The tool execution fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// #[tool]
    /// async fn double_add(ctx: &McpContext, a: i32, b: i32) -> Result<i32, ToolError> {
    ///     let sum: i32 = ctx.call_tool_json("add", json!({"a": a, "b": b})).await?;
    ///     Ok(sum * 2)
    /// }
    /// ```
    pub async fn call_tool(
        &self,
        name: &str,
        args: serde_json::Value,
    ) -> crate::McpResult<ToolCallResult> {
        // Check if we have a tool caller
        let caller = self.tool_caller.as_ref().ok_or_else(|| {
            crate::McpError::new(
                crate::McpErrorCode::InternalError,
                "Tool calling not available: no router attached to context",
            )
        })?;

        // Check recursion depth
        if self.tool_call_depth >= MAX_TOOL_CALL_DEPTH {
            return Err(crate::McpError::new(
                crate::McpErrorCode::InternalError,
                format!(
                    "Maximum tool call depth ({}) exceeded calling '{}'; possible infinite recursion",
                    MAX_TOOL_CALL_DEPTH, name
                ),
            ));
        }

        // Call the tool with incremented depth
        caller
            .call_tool(&self.cx, name, args, self.tool_call_depth + 1)
            .await
    }

    /// Calls a tool and extracts the text content.
    ///
    /// This is a convenience method that calls a tool and returns
    /// the first text content item.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The tool call fails
    /// - The tool returns an error result
    /// - The tool has no text content
    ///
    /// # Example
    ///
    /// ```ignore
    /// let greeting = ctx.call_tool_text("greet", json!({"name": "World"})).await?;
    /// println!("Result: {}", greeting);
    /// ```
    pub async fn call_tool_text(
        &self,
        name: &str,
        args: serde_json::Value,
    ) -> crate::McpResult<String> {
        let result = self.call_tool(name, args).await?;

        // Check if tool returned an error
        if result.is_error {
            let error_msg = result.first_text().unwrap_or("Tool returned an error");
            return Err(crate::McpError::new(
                crate::McpErrorCode::InternalError,
                format!("Tool '{}' failed: {}", name, error_msg),
            ));
        }

        result.first_text().map(String::from).ok_or_else(|| {
            crate::McpError::new(
                crate::McpErrorCode::InternalError,
                format!("Tool '{}' returned no text content", name),
            )
        })
    }

    /// Calls a tool and parses the result as JSON.
    ///
    /// This is a convenience method that calls a tool and deserializes
    /// the text content as JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The tool call fails
    /// - The tool returns an error result
    /// - The tool has no text content
    /// - JSON deserialization fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// #[derive(Deserialize)]
    /// struct ComputeResult {
    ///     value: i64,
    /// }
    ///
    /// let result: ComputeResult = ctx.call_tool_json("compute", json!({"x": 5})).await?;
    /// println!("Result: {}", result.value);
    /// ```
    pub async fn call_tool_json<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
        args: serde_json::Value,
    ) -> crate::McpResult<T> {
        let text = self.call_tool_text(name, args).await?;
        serde_json::from_str(&text).map_err(|e| {
            crate::McpError::new(
                crate::McpErrorCode::InternalError,
                format!("Failed to parse tool '{}' result as JSON: {}", name, e),
            )
        })
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
