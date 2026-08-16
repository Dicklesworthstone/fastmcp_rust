//! MCP context with asupersync integration.
//!
//! [`McpContext`] wraps asupersync's [`Cx`] to provide request-scoped
//! capabilities for MCP message handling (tools, resources, prompts).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use asupersync::sync::Notify;
use asupersync::types::{CancelReason, MAX_MASK_DEPTH};
use asupersync::{Budget, Cx, Outcome, RegionId, TaskId, Time};

#[cfg(test)]
use asupersync::time::wall_now;

use crate::{AuthContext, SessionState};

const REQUEST_LEASE_UNMANAGED: u8 = 0;
const REQUEST_LEASE_ACTIVE: u8 = 1;
const REQUEST_LEASE_CLOSED: u8 = 2;
const REQUEST_CANCELLATION_ACTIVE: u8 = 0;
const REQUEST_CANCELLATION_CANCELLED: u8 = 1;
const REQUEST_CANCELLATION_FINALIZING: u8 = 2;
const REQUEST_AUTH_UNCOMMITTED: u8 = 0;
const REQUEST_AUTH_ANONYMOUS: u8 = 1;
const REQUEST_AUTH_AUTHENTICATED: u8 = 2;

/// Clone-shared cooperative cancellation state for one FastMCP request.
///
/// This is an internal cross-crate integration type. It deliberately does not
/// cancel the caller-owned [`Cx`], because that context may be shared by a
/// connection loop or sibling requests. Request-owned runtime cancellation and
/// drain still require the child-region primitive tracked by FND-04.
#[derive(Debug, Default)]
struct McpRequestCancellationInner {
    state: AtomicU8,
    notify: Notify,
}

#[derive(Clone, Debug, Default)]
#[doc(hidden)]
pub struct McpRequestCancellation {
    inner: Arc<McpRequestCancellationInner>,
}

impl McpRequestCancellation {
    /// Creates an independent FastMCP request-cancellation domain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cooperative cancellation without mutating the ambient [`Cx`].
    pub fn cancel(&self) -> bool {
        let cancelled = self
            .inner
            .state
            .compare_exchange(
                REQUEST_CANCELLATION_ACTIVE,
                REQUEST_CANCELLATION_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if cancelled {
            self.notify_terminal_waiters();
        }
        cancelled
    }

    fn notify_terminal_waiters(&self) {
        // A user-supplied waker is allowed to panic. Terminal state is already
        // authoritative at this point, so contain that panic after Notify has
        // attempted to wake the registered waiter set.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.inner.notify.notify_waiters();
        }));
    }

    /// Returns whether cooperative request cancellation has been requested.
    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        self.inner.state.load(Ordering::Acquire) == REQUEST_CANCELLATION_CANCELLED
    }

    /// Returns whether cancellation or response finalization owns the request.
    ///
    /// This deliberately uses one atomic snapshot. Combining separate
    /// cancellation and finalization reads can miss an `ACTIVE -> CANCELLED`
    /// transition that occurs between those reads.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.inner.state.load(Ordering::Acquire) != REQUEST_CANCELLATION_ACTIVE
    }

    /// Waits until request-local cancellation wins the terminal race.
    ///
    /// The wait is cancel-safe and uses an armed notification followed by a
    /// state recheck, so cancellation cannot be lost between observing the
    /// atomic state and parking the current task.
    pub async fn cancelled(&self) {
        self.inner
            .notify
            .wait_until(|| self.is_cancel_requested())
            .await;
    }

    /// Waits until cancellation or response finalization owns the request.
    ///
    /// Reverse requests use this terminal wait so retained work cannot remain
    /// parked after the owning incoming request has begun finalization.
    pub async fn terminated(&self) {
        self.inner.notify.wait_until(|| self.is_terminal()).await;
    }

    /// Atomically closes the cancellation race before response finalization.
    ///
    /// Returns `false` only when cancellation linearized first. Once this
    /// returns `true`, later cancellation attempts are rejected. Repeated calls
    /// by the response path are idempotent.
    #[must_use]
    pub fn begin_finalization(&self) -> bool {
        loop {
            match self.inner.state.load(Ordering::Acquire) {
                REQUEST_CANCELLATION_ACTIVE => {
                    if self
                        .inner
                        .state
                        .compare_exchange(
                            REQUEST_CANCELLATION_ACTIVE,
                            REQUEST_CANCELLATION_FINALIZING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        self.notify_terminal_waiters();
                        return true;
                    }
                }
                REQUEST_CANCELLATION_CANCELLED => return false,
                REQUEST_CANCELLATION_FINALIZING => return true,
                _ => return false,
            }
        }
    }

    /// Returns whether response finalization already owns the terminal race.
    #[must_use]
    pub fn is_finalizing(&self) -> bool {
        self.inner.state.load(Ordering::Acquire) == REQUEST_CANCELLATION_FINALIZING
    }
}

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

    /// Sends one exact-number final progress notification.
    ///
    /// The default deliberately does nothing. Existing and legacy senders
    /// therefore cannot accidentally emit a final wire model merely because a
    /// handler calls the typed progress API. Senders that explicitly support
    /// the final protocol override this method and retain each JSON-number
    /// lexeme through serialization.
    fn send_progress_exact(
        &self,
        _progress: serde_json::Number,
        _total: Option<serde_json::Number>,
        _message: Option<&str>,
    ) {
    }

    /// Sends one `notifications/message` log frame to the client.
    ///
    /// The default emits nothing so progress-only senders stay inert. Server
    /// dispatch installs a sender that writes the MCP log notification after
    /// the client has selected a minimum level with `logging/setLevel`.
    fn send_log(&self, _level: McpLogLevel, _logger: Option<&str>, _data: serde_json::Value) {}

    /// Sends one catalog `list_changed` notification after a session mutation.
    ///
    /// The default emits nothing so progress-only senders stay inert. Server
    /// dispatch installs a sender that writes the matching
    /// `notifications/{tools,resources,prompts}/list_changed` frame.
    fn send_catalog_changed(&self, _kind: McpCatalogKind) {}

    /// Sends `notifications/resources/updated` for one subscribed URI.
    ///
    /// The default emits nothing. Server dispatch installs a sender that
    /// writes the resource-update frame to the current session.
    fn send_resource_updated(&self, _uri: &str) {}
}

/// Which MCP catalog changed after a session enable/disable mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpCatalogKind {
    Tools,
    Resources,
    Prompts,
}

/// Publishes catalog and resource-update events to modern `subscriptions/listen`
/// streams. Session JSON-RPC notifications stay on [`NotificationSender`].
pub trait CatalogChangePublisher: Send + Sync {
    /// Returns whether at least one live listener accepted the catalog event.
    fn publish_catalog_changed(&self, kind: McpCatalogKind) -> bool;
    /// Returns whether at least one live listener accepted the resource update.
    fn publish_resource_updated(&self, uri: &str) -> bool;
}

/// MCP syslog-style log severity used by handler `ctx.info()` and friends.
///
/// Ranking matches the protocol `LogLevel` order: debug is lowest, emergency
/// is highest. A server must not emit a notification until the client has
/// selected a minimum level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum McpLogLevel {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl McpLogLevel {
    /// Wire token used by `notifications/message`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
            Self::Alert => "alert",
            Self::Emergency => "emergency",
        }
    }

    /// Syslog-style rank used to compare a message against the client floor.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Debug => 1,
            Self::Info => 2,
            Self::Notice => 3,
            Self::Warning => 4,
            Self::Error => 5,
            Self::Critical => 6,
            Self::Alert => 7,
            Self::Emergency => 8,
        }
    }
}

// ============================================================================
// Roots Provider
// ============================================================================

/// A filesystem root supplied by the connected client.
///
/// This deliberately lives in core rather than the wire crate: a handler's
/// authority to inspect client roots must not introduce a core-to-protocol
/// dependency cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRoot {
    /// Root URI, normally a `file://` URI.
    pub uri: String,
    /// Optional human-readable display name.
    pub name: Option<String>,
}

impl ClientRoot {
    /// Creates an unnamed client root.
    #[must_use]
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            name: None,
        }
    }

    /// Creates a named client root.
    #[must_use]
    pub fn with_name(uri: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            name: Some(name.into()),
        }
    }
}

/// Capability for listing filesystem roots from the connected client.
pub trait RootsProvider: Send + Sync {
    /// Lists the roots currently exposed by the client.
    fn list_roots(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::McpResult<Vec<ClientRoot>>> + Send + '_>,
    >;
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SamplingStopReason {
    /// End of natural turn.
    #[default]
    EndTurn,
    /// Hit stop sequence.
    StopSequence,
    /// Hit max tokens limit.
    MaxTokens,
    /// The peer omitted the optional wire-level stop reason.
    Unspecified,
    /// An open provider-defined wire-level stop reason.
    Other(String),
}

impl SamplingStopReason {
    /// Converts an optional wire-level stop reason without narrowing an open
    /// provider value.
    #[must_use]
    pub fn from_wire_value(value: Option<String>) -> Self {
        match value {
            Some(value) => match value.as_str() {
                "endTurn" => Self::EndTurn,
                "stopSequence" => Self::StopSequence,
                "maxTokens" => Self::MaxTokens,
                _ => Self::Other(value),
            },
            None => Self::Unspecified,
        }
    }

    /// Returns the optional wire-level value without changing an open provider
    /// value.
    #[must_use]
    pub fn as_wire_value(&self) -> Option<&str> {
        match self {
            Self::EndTurn => Some("endTurn"),
            Self::StopSequence => Some("stopSequence"),
            Self::MaxTokens => Some("maxTokens"),
            Self::Unspecified => None,
            Self::Other(value) => Some(value),
        }
    }
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
    /// * `context` - The originating MCP request context
    /// * `uri` - The resource URI to read
    /// * `depth` - Current recursion depth (to prevent infinite loops)
    ///
    /// # Returns
    ///
    /// The resource contents, or an error if the resource doesn't exist
    /// or reading fails.
    fn read_resource<'a>(
        &'a self,
        context: &'a McpContext,
        uri: &'a str,
        depth: u32,
    ) -> Pin<Box<dyn Future<Output = crate::McpResult<ResourceReadResult>> + Send + 'a>>;
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
    /// Audio content (base64-encoded).
    Audio {
        /// Base64-encoded audio data.
        data: String,
        /// MIME type of the audio.
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
        /// Binary content (base64 blob).
        blob: Option<String>,
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
    /// * `context` - The originating MCP request context
    /// * `name` - The tool name to call
    /// * `args` - The arguments as a JSON value
    /// * `depth` - Current recursion depth (to prevent infinite loops)
    ///
    /// # Returns
    ///
    /// The tool result, or an error if the tool doesn't exist
    /// or execution fails.
    fn call_tool<'a>(
        &'a self,
        context: &'a McpContext,
        name: &'a str,
        args: serde_json::Value,
        depth: u32,
    ) -> Pin<Box<dyn Future<Output = crate::McpResult<ToolCallResult>> + Send + 'a>>;
}

// ============================================================================
// Prompt Caller (Cross-Component Access)
// ============================================================================

/// Maximum depth for nested prompt gets to prevent infinite recursion.
pub const MAX_PROMPT_GET_DEPTH: u32 = 10;

/// Role of one prompt message returned through [`McpContext::get_prompt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptMessageRole {
    /// User-authored prompt turn.
    User,
    /// Assistant-authored prompt turn.
    Assistant,
}

/// One prompt message returned through [`McpContext::get_prompt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptMessageItem {
    /// Message role.
    pub role: PromptMessageRole,
    /// Text content when the handler authored a text block.
    pub text: Option<String>,
}

impl PromptMessageItem {
    /// Creates a user text message.
    #[must_use]
    pub fn user_text(text: impl Into<String>) -> Self {
        Self {
            role: PromptMessageRole::User,
            text: Some(text.into()),
        }
    }

    /// Returns the text content, if present.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        self.text.as_deref()
    }
}

/// Result of getting a prompt from within a handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptGetResult {
    /// Optional prompt description from the catalog definition.
    pub description: Option<String>,
    /// Messages returned by the prompt handler.
    pub messages: Vec<PromptMessageItem>,
}

impl PromptGetResult {
    /// Creates a prompt result with the given messages.
    #[must_use]
    pub fn new(messages: Vec<PromptMessageItem>) -> Self {
        Self {
            description: None,
            messages,
        }
    }

    /// Returns the first text message, if present.
    #[must_use]
    pub fn first_text(&self) -> Option<&str> {
        self.messages.iter().find_map(PromptMessageItem::as_text)
    }
}

/// Trait for getting prompts from within handlers.
///
/// This trait is implemented by the server's Router to allow tools,
/// resources, and prompts to get other prompts. It enables
/// cross-component composition and code reuse.
pub trait PromptCaller: Send + Sync {
    /// Gets a prompt by name with the given arguments.
    fn get_prompt<'a>(
        &'a self,
        context: &'a McpContext,
        name: &'a str,
        arguments: std::collections::HashMap<String, String>,
        depth: u32,
    ) -> Pin<Box<dyn Future<Output = crate::McpResult<PromptGetResult>> + Send + 'a>>;
}

// ============================================================================
// Capabilities Info
// ============================================================================

/// Client capability information accessible from handlers.
///
/// This provides a simplified view of what capabilities the connected client
/// supports. Use this to adapt handler behavior based on client capabilities.
#[derive(Debug, Clone, Default)]
pub struct ClientCapabilityInfo {
    /// Whether the client supports sampling (LLM completions).
    pub sampling: bool,
    /// Whether the client supports elicitation (user input requests).
    pub elicitation: bool,
    /// Whether the client supports form-mode elicitation.
    pub elicitation_form: bool,
    /// Whether the client supports URL-mode elicitation.
    pub elicitation_url: bool,
    /// Whether the client supports roots listing.
    pub roots: bool,
    /// Whether the client wants list_changed notifications for roots.
    pub roots_list_changed: bool,
}

impl ClientCapabilityInfo {
    /// Creates a new empty capability info (no capabilities).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates capability info with sampling enabled.
    #[must_use]
    pub fn with_sampling(mut self) -> Self {
        self.sampling = true;
        self
    }

    /// Creates capability info with elicitation enabled.
    #[must_use]
    pub fn with_elicitation(mut self, form: bool, url: bool) -> Self {
        self.elicitation = form || url;
        self.elicitation_form = form;
        self.elicitation_url = url;
        self
    }

    /// Creates capability info with roots enabled.
    #[must_use]
    pub fn with_roots(mut self, list_changed: bool) -> Self {
        self.roots = true;
        self.roots_list_changed = list_changed;
        self
    }
}

/// Handler-visible slice of the self-reported modern client Implementation.
///
/// This is not authority. It is the request `_meta` identity the peer
/// advertised. Name and version are always present when this value exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientImplementationInfo {
    /// Programmatic client name.
    pub name: String,
    /// Client version.
    pub version: String,
    /// Optional display title. An empty present title remains present.
    pub title: Option<String>,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Optional website identity as advertised, not validated as authority.
    pub website_url: Option<String>,
    /// Optional icon source URIs in wire order.
    pub icon_sources: Vec<String>,
}

impl ClientImplementationInfo {
    /// Constructs a handler-visible identity from required nonempty fields.
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            title: None,
            description: None,
            website_url: None,
            icon_sources: Vec::new(),
        }
    }

    /// Returns whether any Implementation extras beyond name/version are present.
    #[must_use]
    pub fn has_extras(&self) -> bool {
        self.title.is_some()
            || self.description.is_some()
            || self.website_url.is_some()
            || !self.icon_sources.is_empty()
    }
}

/// Server capability information accessible from handlers.
///
/// This provides a simplified view of what capabilities this server advertises.
#[derive(Debug, Clone, Default)]
pub struct ServerCapabilityInfo {
    /// Whether the server supports tools.
    pub tools: bool,
    /// Whether the server supports resources.
    pub resources: bool,
    /// Whether resources support subscriptions.
    pub resources_subscribe: bool,
    /// Whether the server supports prompts.
    pub prompts: bool,
    /// Whether the server supports logging.
    pub logging: bool,
}

impl ServerCapabilityInfo {
    /// Creates a new empty server capability info.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates capability info with tools enabled.
    #[must_use]
    pub fn with_tools(mut self) -> Self {
        self.tools = true;
        self
    }

    /// Creates capability info with resources enabled.
    #[must_use]
    pub fn with_resources(mut self, subscribe: bool) -> Self {
        self.resources = true;
        self.resources_subscribe = subscribe;
        self
    }

    /// Creates capability info with prompts enabled.
    #[must_use]
    pub fn with_prompts(mut self) -> Self {
        self.prompts = true;
        self
    }

    /// Creates capability info with logging enabled.
    #[must_use]
    pub fn with_logging(mut self) -> Self {
        self.logging = true;
        self
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
    // The request progress marker, retained opaquely as its wire JSON. Core
    // is the base layer and does not depend on the protocol crate's typed
    // `ProgressMarker`; callers convert at the boundary. The value round-trips
    // losslessly for proxy-relay correlation.
    marker: Option<serde_json::Value>,
}

impl ProgressReporter {
    /// Creates a new progress reporter with the given sender.
    pub fn new(sender: Arc<dyn NotificationSender>) -> Self {
        Self {
            sender,
            marker: None,
        }
    }

    /// Creates a reporter which retains the request marker it will emit.
    ///
    /// Proxy routes use this marker to correlate an upstream progress frame
    /// before relaying it through this request's downstream reporter.
    #[must_use]
    pub fn with_marker(marker: serde_json::Value, sender: Arc<dyn NotificationSender>) -> Self {
        Self {
            sender,
            marker: Some(marker),
        }
    }

    /// Returns the request marker owned by this reporter, when it has one.
    #[must_use]
    pub fn marker(&self) -> Option<&serde_json::Value> {
        self.marker.as_ref()
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

    /// Reports final progress without converting JSON-number lexemes through
    /// `f64`.
    ///
    /// The supplied numbers may exceed IEEE-754 range when the installed
    /// sender supports the final protocol. A legacy sender receives the trait
    /// default, which emits nothing.
    pub fn report_exact(
        &self,
        progress: serde_json::Number,
        total: Option<serde_json::Number>,
        message: Option<&str>,
    ) {
        self.sender.send_progress_exact(progress, total, message);
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
/// - Cooperative budget/deadline visibility and checkpoints
/// - Access to the caller-supplied `Cx` for runtime primitives
/// - Sampling capability for LLM completions (if client supports it)
/// - Elicitation capability for user input requests (if client supports it)
/// - Cross-component resource reading (if router is attached)
///
/// Every constructor establishes a new request-accounting domain. Derive
/// another context for the same request by cloning the originating
/// `McpContext` and applying consuming builders; constructing a new context
/// around a cloned [`Cx`] would reset FastMCP's request-local accounting.
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
    /// An optional framework-owned ceiling applied to the ambient budget.
    ///
    /// This is composed with `cx.budget()` on every read so an inner operation
    /// can tighten, but never relax, the caller's current budget.
    budget_state: Arc<Mutex<FrameworkBudgetState>>,
    /// Mask depth for framework-owned ceilings. The underlying Cx tracks its
    /// own cancellation mask, but it cannot see a ceiling held only here.
    framework_mask_depth: Arc<AtomicU32>,
    /// Serializes transitions between the Cx mask and the framework mask.
    ///
    /// Checkpoint and cost-accounting operations take this lock while they
    /// observe both layers, so they cannot see a half-entered or half-exited
    /// mask when another clone enters [`McpContext::masked`].
    mask_transition: Arc<Mutex<()>>,
    /// Operation-local absolute deadline inherited by ordinary clones.
    ///
    /// Unlike the request budget ledger, this value is intentionally not
    /// shared when a consuming builder tightens a derived context. A nested
    /// handler timeout must bound that handler without permanently shortening
    /// its parent's remaining request lifetime.
    operation_deadline: Option<Time>,
    /// Clone-shared request capability lease.
    ///
    /// Server dispatch closes this lease when the request finishes. FastMCP
    /// capability calls begun after closure are rejected. This is not a drain
    /// barrier for an already-running call and cannot revoke direct access to
    /// the caller-owned [`Cx`]; request-owned runtime isolation remains a
    /// separate lifecycle requirement.
    request_lease: Arc<AtomicU8>,
    /// FastMCP-owned cooperative cancellation for this request domain.
    request_cancellation: McpRequestCancellation,
    /// Unique request identifier for tracing (from JSON-RPC id).
    request_id: u64,
    /// Optional progress reporter for long-running operations.
    progress_reporter: Option<ProgressReporter>,
    /// Session state for per-session key-value storage.
    state: Option<SessionState>,
    /// Session cache partition captured when cache lookup is admitted.
    cache_admission_partition: Arc<Mutex<Option<([u8; 32], u64)>>>,
    /// Cache middleware instances that short-circuited response generation.
    response_cache_hits: Arc<Mutex<Vec<u64>>>,
    /// Request-scoped authentication context.
    auth: Arc<Mutex<Option<AuthContext>>>,
    /// Write-once authentication admission state, including committed anonymous
    /// requests whose handler-visible [`Self::auth`] value remains `None`.
    auth_state: Arc<AtomicU8>,
    /// Optional sampling sender for LLM completions.
    sampling_sender: Option<Arc<dyn SamplingSender>>,
    /// Optional elicitation sender for user input requests.
    elicitation_sender: Option<Arc<dyn ElicitationSender>>,
    /// Optional roots provider for filesystem boundaries exposed by the client.
    roots_provider: Option<Arc<dyn RootsProvider>>,
    /// Optional resource reader for cross-component access.
    resource_reader: Option<Arc<dyn ResourceReader>>,
    /// Current resource read depth (to prevent infinite recursion).
    resource_read_depth: u32,
    /// Optional tool caller for cross-component access.
    tool_caller: Option<Arc<dyn ToolCaller>>,
    /// Current tool call depth (to prevent infinite recursion).
    tool_call_depth: u32,
    /// Optional prompt caller for cross-component access.
    prompt_caller: Option<Arc<dyn PromptCaller>>,
    /// Current prompt get depth (to prevent infinite recursion).
    prompt_get_depth: u32,
    /// Client capability information.
    client_capabilities: Option<ClientCapabilityInfo>,
    /// Self-reported modern client Implementation identity, when advertised.
    client_implementation: Option<ClientImplementationInfo>,
    /// Server capability information.
    server_capabilities: Option<ServerCapabilityInfo>,
    /// Optional log sender for `notifications/message`.
    log_sender: Option<Arc<dyn NotificationSender>>,
    /// Minimum severity the connected client asked to receive.
    ///
    /// `None` means the client has not sent `logging/setLevel`; MCP forbids
    /// emitting log notifications until that floor exists.
    min_log_level: Option<McpLogLevel>,
    /// Resource URIs this session has subscribed to.
    resource_subscriptions: Option<Arc<std::collections::HashSet<String>>>,
    /// Optional publisher for modern `subscriptions/listen` catalog events.
    catalog_publisher: Option<Arc<dyn CatalogChangePublisher>>,
}

impl std::fmt::Debug for McpContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let budget_state = *self
            .budget_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f.debug_struct("McpContext")
            .field("cx", &self.cx)
            .field("budget_ceiling", &budget_state.ceiling)
            .field("ambient_poll_debits", &budget_state.ambient_poll_debits)
            .field("ambient_cost_debits", &budget_state.ambient_cost_debits)
            .field("deferred_overrun", &budget_state.deferred_overrun)
            .field(
                "framework_mask_depth",
                &self.framework_mask_depth.load(Ordering::Relaxed),
            )
            .field("operation_deadline", &self.operation_deadline)
            .field("request_lease_active", &self.request_scope_is_active())
            .field(
                "request_cancel_requested",
                &self.request_cancellation.is_cancel_requested(),
            )
            .field("request_id", &self.request_id)
            .field("progress_reporter", &self.progress_reporter)
            .field("state", &self.state.is_some())
            .field(
                "cache_admission_partition",
                &self
                    .cache_admission_partition
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_some(),
            )
            .field(
                "response_cache_hit_count",
                &self
                    .response_cache_hits
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len(),
            )
            .field(
                "auth",
                &self
                    .auth
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_some(),
            )
            .field(
                "auth_committed",
                &(self.auth_state.load(Ordering::Acquire) != REQUEST_AUTH_UNCOMMITTED),
            )
            .field("sampling_sender", &self.sampling_sender.is_some())
            .field("elicitation_sender", &self.elicitation_sender.is_some())
            .field("roots_provider", &self.roots_provider.is_some())
            .field("resource_reader", &self.resource_reader.is_some())
            .field("resource_read_depth", &self.resource_read_depth)
            .field("tool_caller", &self.tool_caller.is_some())
            .field("tool_call_depth", &self.tool_call_depth)
            .field("prompt_caller", &self.prompt_caller.is_some())
            .field("prompt_get_depth", &self.prompt_get_depth)
            .field("client_capabilities", &self.client_capabilities)
            .field("client_implementation", &self.client_implementation)
            .field("server_capabilities", &self.server_capabilities)
            .field("log_sender", &self.log_sender.is_some())
            .field("min_log_level", &self.min_log_level)
            .field(
                "resource_subscription_count",
                &self
                    .resource_subscriptions
                    .as_ref()
                    .map_or(0, |uris| uris.len()),
            )
            .field("catalog_publisher", &self.catalog_publisher.is_some())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FrameworkBudgetState {
    ceiling: Option<Budget>,
    /// Cumulative request-local poll units charged against the ambient Cx
    /// snapshot without mutating its clone-shared runtime budget.
    ambient_poll_debits: u32,
    /// Cumulative request-local cost charged against the ambient Cx snapshot.
    ///
    /// Asupersync 0.3.9 exposes the ambient budget as a read-only snapshot, so
    /// FastMCP cannot mutate the supplied Cx's internal quota. Keeping the
    /// cumulative debit here makes admission real and clone-shared without
    /// claiming ownership of, or cancelling, that ambient context.
    ambient_cost_debits: u64,
    /// A masked admission attempted to exceed a finite framework/ambient
    /// dimension. Exact depletion to zero is valid; only an actual overrun
    /// sets this terminal request-local condition.
    deferred_overrun: bool,
}

impl FrameworkBudgetState {
    fn adjusted_ambient(self, mut ambient: Budget) -> Budget {
        if ambient.poll_quota != u32::MAX {
            ambient.poll_quota = ambient.poll_quota.saturating_sub(self.ambient_poll_debits);
        }
        if let Some(remaining) = ambient.cost_quota.as_mut() {
            *remaining = remaining.saturating_sub(self.ambient_cost_debits);
        }
        ambient
    }

    fn effective(self, ambient: Budget) -> Budget {
        let ambient = self.adjusted_ambient(ambient);
        self.ceiling
            .map_or(ambient, |ceiling| ambient.meet(ceiling))
    }
}

struct FrameworkMaskGuard<'a> {
    depth: &'a AtomicU32,
}

/// RAII owner for a server-installed [`McpContext`] request lease.
///
/// This is an internal cross-crate integration type. Dropping it rejects new
/// FastMCP capability calls from every context clone in the request domain.
#[doc(hidden)]
pub struct McpContextLeaseGuard {
    lease: Arc<AtomicU8>,
}

impl std::fmt::Debug for McpContextLeaseGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpContextLeaseGuard")
            .field(
                "active",
                &(self.lease.load(Ordering::Acquire) == REQUEST_LEASE_ACTIVE),
            )
            .finish()
    }
}

impl Drop for McpContextLeaseGuard {
    fn drop(&mut self) {
        self.lease.store(REQUEST_LEASE_CLOSED, Ordering::Release);
    }
}

impl Drop for FrameworkMaskGuard<'_> {
    fn drop(&mut self) {
        self.depth.fetch_sub(1, Ordering::SeqCst);
    }
}

impl McpContext {
    /// Creates a new MCP context from an asupersync Cx.
    ///
    /// This wraps the supplied context; it does not create or own a child
    /// region. Request-owned cancellation/drain must come from the caller's
    /// runtime lifecycle. This constructor establishes a new request-accounting
    /// domain even when `cx` is itself a clone. Same-request derivations must
    /// clone the resulting `McpContext` and use its consuming builders.
    #[must_use]
    pub fn new(cx: Cx, request_id: u64) -> Self {
        Self {
            cx,
            budget_state: Arc::new(Mutex::new(FrameworkBudgetState::default())),
            framework_mask_depth: Arc::new(AtomicU32::new(0)),
            mask_transition: Arc::new(Mutex::new(())),
            operation_deadline: None,
            request_lease: Arc::new(AtomicU8::new(REQUEST_LEASE_UNMANAGED)),
            request_cancellation: McpRequestCancellation::new(),
            request_id,
            progress_reporter: None,
            state: None,
            cache_admission_partition: Arc::new(Mutex::new(None)),
            response_cache_hits: Arc::new(Mutex::new(Vec::new())),
            auth: Arc::new(Mutex::new(None)),
            auth_state: Arc::new(AtomicU8::new(REQUEST_AUTH_UNCOMMITTED)),
            sampling_sender: None,
            elicitation_sender: None,
            roots_provider: None,
            resource_reader: None,
            resource_read_depth: 0,
            tool_caller: None,
            tool_call_depth: 0,
            prompt_caller: None,
            prompt_get_depth: 0,
            client_capabilities: None,
            client_implementation: None,
            server_capabilities: None,
            log_sender: None,
            min_log_level: None,
            resource_subscriptions: None,
            catalog_publisher: None,
        }
    }

    /// Creates a new MCP context with session state.
    ///
    /// Use this constructor when session state should be accessible to handlers.
    /// It establishes a new request-accounting domain; clone an existing
    /// `McpContext` when deriving another context for the same request.
    #[must_use]
    pub fn with_state(cx: Cx, request_id: u64, state: SessionState) -> Self {
        Self {
            cx,
            budget_state: Arc::new(Mutex::new(FrameworkBudgetState::default())),
            framework_mask_depth: Arc::new(AtomicU32::new(0)),
            mask_transition: Arc::new(Mutex::new(())),
            operation_deadline: None,
            request_lease: Arc::new(AtomicU8::new(REQUEST_LEASE_UNMANAGED)),
            request_cancellation: McpRequestCancellation::new(),
            request_id,
            progress_reporter: None,
            state: Some(state),
            cache_admission_partition: Arc::new(Mutex::new(None)),
            response_cache_hits: Arc::new(Mutex::new(Vec::new())),
            auth: Arc::new(Mutex::new(None)),
            auth_state: Arc::new(AtomicU8::new(REQUEST_AUTH_UNCOMMITTED)),
            sampling_sender: None,
            elicitation_sender: None,
            roots_provider: None,
            resource_reader: None,
            resource_read_depth: 0,
            tool_caller: None,
            tool_call_depth: 0,
            prompt_caller: None,
            prompt_get_depth: 0,
            client_capabilities: None,
            client_implementation: None,
            server_capabilities: None,
            log_sender: None,
            min_log_level: None,
            resource_subscriptions: None,
            catalog_publisher: None,
        }
    }

    /// Creates a new MCP context with progress reporting enabled.
    ///
    /// Use this constructor when the client has provided a progress token
    /// and expects progress notifications. It establishes a new
    /// request-accounting domain; use [`Self::with_progress_reporter`] on a
    /// clone when attaching progress reporting within an existing request.
    #[must_use]
    pub fn with_progress(cx: Cx, request_id: u64, reporter: ProgressReporter) -> Self {
        Self {
            cx,
            budget_state: Arc::new(Mutex::new(FrameworkBudgetState::default())),
            framework_mask_depth: Arc::new(AtomicU32::new(0)),
            mask_transition: Arc::new(Mutex::new(())),
            operation_deadline: None,
            request_lease: Arc::new(AtomicU8::new(REQUEST_LEASE_UNMANAGED)),
            request_cancellation: McpRequestCancellation::new(),
            request_id,
            progress_reporter: Some(reporter),
            state: None,
            cache_admission_partition: Arc::new(Mutex::new(None)),
            response_cache_hits: Arc::new(Mutex::new(Vec::new())),
            auth: Arc::new(Mutex::new(None)),
            auth_state: Arc::new(AtomicU8::new(REQUEST_AUTH_UNCOMMITTED)),
            sampling_sender: None,
            elicitation_sender: None,
            roots_provider: None,
            resource_reader: None,
            resource_read_depth: 0,
            tool_caller: None,
            tool_call_depth: 0,
            prompt_caller: None,
            prompt_get_depth: 0,
            client_capabilities: None,
            client_implementation: None,
            server_capabilities: None,
            log_sender: None,
            min_log_level: None,
            resource_subscriptions: None,
            catalog_publisher: None,
        }
    }

    /// Creates a new MCP context with both state and progress reporting.
    ///
    /// This constructor establishes a new request-accounting domain. Clone an
    /// existing `McpContext` and apply consuming builders when deriving another
    /// context for the same request.
    #[must_use]
    pub fn with_state_and_progress(
        cx: Cx,
        request_id: u64,
        state: SessionState,
        reporter: ProgressReporter,
    ) -> Self {
        Self {
            cx,
            budget_state: Arc::new(Mutex::new(FrameworkBudgetState::default())),
            framework_mask_depth: Arc::new(AtomicU32::new(0)),
            mask_transition: Arc::new(Mutex::new(())),
            operation_deadline: None,
            request_lease: Arc::new(AtomicU8::new(REQUEST_LEASE_UNMANAGED)),
            request_cancellation: McpRequestCancellation::new(),
            request_id,
            progress_reporter: Some(reporter),
            state: Some(state),
            cache_admission_partition: Arc::new(Mutex::new(None)),
            response_cache_hits: Arc::new(Mutex::new(Vec::new())),
            auth: Arc::new(Mutex::new(None)),
            auth_state: Arc::new(AtomicU8::new(REQUEST_AUTH_UNCOMMITTED)),
            sampling_sender: None,
            elicitation_sender: None,
            roots_provider: None,
            resource_reader: None,
            resource_read_depth: 0,
            tool_caller: None,
            tool_call_depth: 0,
            prompt_caller: None,
            prompt_get_depth: 0,
            client_capabilities: None,
            client_implementation: None,
            server_capabilities: None,
            log_sender: None,
            min_log_level: None,
            resource_subscriptions: None,
            catalog_publisher: None,
        }
    }

    /// Attaches a progress reporter without changing the request-accounting domain.
    ///
    /// This consuming builder preserves the shared budget, mask, authentication,
    /// and other request-scoped state inherited from the context being consumed.
    /// Use it on a clone when deriving a progress-enabled context for the same
    /// request.
    #[must_use]
    pub fn with_progress_reporter(mut self, reporter: ProgressReporter) -> Self {
        self.progress_reporter = Some(reporter);
        self
    }

    /// Installs the sender used by [`Self::info`] and the other log helpers.
    #[must_use]
    pub fn with_log_sender(mut self, sender: Arc<dyn NotificationSender>) -> Self {
        self.log_sender = Some(sender);
        self
    }

    /// Sets the client-selected minimum log level for this request.
    ///
    /// `None` keeps log notifications suppressed, matching MCP's rule that a
    /// server must not emit `notifications/message` until `logging/setLevel`.
    #[must_use]
    pub fn with_min_log_level(mut self, level: Option<McpLogLevel>) -> Self {
        self.min_log_level = level;
        self
    }

    /// Returns the client-selected minimum log level for this request.
    ///
    /// `None` means the client has not opted into `notifications/message`.
    #[must_use]
    pub fn min_log_level(&self) -> Option<McpLogLevel> {
        self.min_log_level
    }

    /// Records the resource URIs this session has subscribed to.
    #[must_use]
    pub fn with_resource_subscriptions(
        mut self,
        uris: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.resource_subscriptions = Some(Arc::new(uris.into_iter().map(Into::into).collect()));
        self
    }

    /// Installs the modern `subscriptions/listen` catalog publisher.
    #[must_use]
    pub fn with_catalog_publisher(mut self, publisher: Arc<dyn CatalogChangePublisher>) -> Self {
        self.catalog_publisher = Some(publisher);
        self
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

    /// Sets the roots provider for this context.
    ///
    /// This enables [`list_roots`](Self::list_roots) for the current request.
    #[must_use]
    pub fn with_roots_provider(mut self, provider: Arc<dyn RootsProvider>) -> Self {
        self.roots_provider = Some(provider);
        self
    }

    /// Tightens the budget visible through this MCP context.
    ///
    /// The supplied ceiling is met with both the ambient [`Cx`] budget and
    /// any ceiling already installed on the context. Consequently,
    /// `Budget::INFINITE`, an absent deadline, or a later deadline cannot
    /// relax a tighter caller-owned limit. The ceiling and its remaining
    /// quotas are request-owned and shared by every clone of this context;
    /// tightening one clone is therefore visible to all of them.
    #[must_use]
    pub fn with_budget_ceiling(self, ceiling: Budget) -> Self {
        {
            let mut current = self
                .budget_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            current.ceiling = Some(
                current
                    .ceiling
                    .map_or(ceiling, |budget| budget.meet(ceiling)),
            );
        }
        self
    }

    /// Tightens only this derived operation's absolute deadline.
    ///
    /// Ordinary clones inherit the resulting deadline, but the context from
    /// which this consuming builder was derived is unchanged. This is the
    /// correct boundary for handler-local timeout metadata: nested work sees
    /// the tighter deadline while its parent request retains its own lifetime.
    /// `None` adds no deadline and can never relax an inherited one.
    #[must_use]
    pub fn with_operation_deadline(mut self, deadline: Option<Time>) -> Self {
        if let Some(deadline) = deadline {
            self.operation_deadline = Some(
                self.operation_deadline
                    .map_or(deadline, |current| current.min(deadline)),
            );
        }
        self
    }

    /// Installs the server-created cooperative cancellation domain.
    ///
    /// This must be done before request dispatch begins. Ordinary context
    /// clones preserve the same domain.
    #[doc(hidden)]
    #[must_use]
    pub fn with_request_cancellation(mut self, cancellation: McpRequestCancellation) -> Self {
        // Request cancellation authority is installed exactly once, before
        // the server activates the request lease. A handler holding an active
        // clone cannot swap in a fresh token and escape peer cancellation.
        if self.request_lease.load(Ordering::Acquire) == REQUEST_LEASE_UNMANAGED {
            self.request_cancellation = cancellation;
        }
        self
    }

    /// Installs a clone-shared request lease and returns the scoped context
    /// with its RAII owner.
    ///
    /// The server keeps the guard for exactly one dispatch. Once the guard is
    /// dropped, retained context clones fail liveness checks and FastMCP
    /// capability calls begun afterward are rejected. A context that already
    /// belongs to a request scope returns `None`, so an expired clone cannot
    /// mint fresh authority. This lease does not drain calls already in
    /// progress or revoke the caller-owned [`Cx`].
    #[doc(hidden)]
    #[must_use]
    pub fn begin_request_scope(self) -> Option<(Self, McpContextLeaseGuard)> {
        if self
            .request_lease
            .compare_exchange(
                REQUEST_LEASE_UNMANAGED,
                REQUEST_LEASE_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }
        let guard = McpContextLeaseGuard {
            lease: Arc::clone(&self.request_lease),
        };
        Some((self, guard))
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
        self.resource_read_depth = self.resource_read_depth.max(depth);
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
        self.tool_call_depth = self.tool_call_depth.max(depth);
        self
    }

    /// Sets the prompt caller for this context.
    ///
    /// This enables the `get_prompt()` methods to get other prompts from
    /// within tool, resource, or prompt handlers.
    #[must_use]
    pub fn with_prompt_caller(mut self, caller: Arc<dyn PromptCaller>) -> Self {
        self.prompt_caller = Some(caller);
        self
    }

    /// Sets the prompt get depth for this context.
    ///
    /// This is used internally to track recursion depth when getting
    /// prompts from within handlers.
    #[must_use]
    pub fn with_prompt_get_depth(mut self, depth: u32) -> Self {
        self.prompt_get_depth = self.prompt_get_depth.max(depth);
        self
    }

    /// Sets the client capability information for this context.
    ///
    /// This enables handlers to check what capabilities the connected
    /// client supports.
    #[must_use]
    pub fn with_client_capabilities(mut self, capabilities: ClientCapabilityInfo) -> Self {
        self.client_capabilities = Some(capabilities);
        self
    }

    /// Attaches the self-reported modern client Implementation identity.
    #[must_use]
    pub fn with_client_implementation(mut self, identity: ClientImplementationInfo) -> Self {
        self.client_implementation = Some(identity);
        self
    }

    /// Sets the server capability information for this context.
    ///
    /// This enables handlers to check what capabilities this server
    /// advertises.
    #[must_use]
    pub fn with_server_capabilities(mut self, capabilities: ServerCapabilityInfo) -> Self {
        self.server_capabilities = Some(capabilities);
        self
    }

    /// Returns whether progress reporting is enabled for this context.
    #[must_use]
    pub fn has_progress_reporter(&self) -> bool {
        self.ensure_live().is_ok() && self.progress_reporter.is_some()
    }

    /// Returns the progress marker installed for this request, when available.
    ///
    /// A reporter without a marker cannot establish ownership of upstream
    /// progress frames and therefore must not cause proxy forwarding.
    #[must_use]
    pub fn progress_marker(&self) -> Option<&serde_json::Value> {
        self.ensure_live()
            .ok()
            .and_then(|()| self.progress_reporter.as_ref()?.marker())
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
        if self.ensure_live().is_ok()
            && let Some(ref reporter) = self.progress_reporter
        {
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
        if self.ensure_live().is_ok()
            && let Some(ref reporter) = self.progress_reporter
        {
            reporter.report_with_total(progress, total, message);
        }
    }

    /// Reports final progress while retaining the caller's exact JSON-number
    /// lexemes.
    ///
    /// This is a no-op unless the current request installed a final-capable
    /// progress reporter. The legacy `f64` progress APIs remain unchanged.
    pub fn report_progress_exact(
        &self,
        progress: serde_json::Number,
        total: Option<serde_json::Number>,
        message: Option<&str>,
    ) {
        if self.ensure_live().is_ok()
            && let Some(ref reporter) = self.progress_reporter
        {
            reporter.report_exact(progress, total, message);
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
    /// This is the region of the caller-supplied [`Cx`]. FastMCP does not
    /// currently create a request-owned child region, so this identifier must
    /// not be interpreted as proof that spawned work is scoped to, cancelled
    /// with, or drained before completion of this MCP request.
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.cx.region_id()
    }

    /// Returns the current task ID.
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.cx.task_id()
    }

    fn apply_operation_deadline(&self, budget: Budget) -> Budget {
        self.operation_deadline.map_or(budget, |deadline| {
            budget.meet(Budget::new().with_deadline(deadline))
        })
    }

    fn request_scope_is_active(&self) -> bool {
        self.request_lease.load(Ordering::Acquire) != REQUEST_LEASE_CLOSED
    }

    /// Returns the current budget.
    ///
    /// The budget is a remaining-balance snapshot. A zero poll or cost balance
    /// records exact depletion; it does not retroactively fail the operation
    /// that consumed the final unit. Use [`ensure_live`](Self::ensure_live) for
    /// terminal liveness and [`checkpoint`](Self::checkpoint) or
    /// [`consume_cost`](Self::consume_cost) for dimension-specific admission.
    #[must_use]
    pub fn budget(&self) -> Budget {
        let ambient = self.cx.budget();
        let state = *self
            .budget_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.apply_operation_deadline(state.effective(ambient))
    }

    /// Checks if cancellation has been requested.
    ///
    /// This includes client disconnection, timeout, or explicit cancellation.
    /// Handlers should check this periodically and exit early if true.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.ensure_live().is_err()
    }

    /// Returns the cooperative cancellation domain owned by this request.
    ///
    /// Long-running framework integrations may await this handle instead of
    /// polling [`Self::is_cancelled`].  Cloning the handle never grants a way
    /// to replace the request's cancellation authority; it observes the same
    /// request-local transition installed before dispatch.
    #[must_use]
    pub fn request_cancellation(&self) -> McpRequestCancellation {
        self.request_cancellation.clone()
    }

    /// Checks terminal request liveness without charging a poll or cost unit.
    ///
    /// A finite quota that was exactly depleted is not itself a failed
    /// operation. The next dimension-specific admission fails when it asks for
    /// unavailable work. This method rejects only explicit cancellation, an
    /// expired effective deadline, or a real overrun deferred by
    /// [`masked`](Self::masked). Explicit cancellation includes both the
    /// caller-owned [`Cx`] signal and FastMCP's request-local cooperative
    /// signal; the latter never mutates the ambient context.
    ///
    /// # Errors
    ///
    /// Returns [`CancelledError`] when a terminal liveness condition is
    /// observable outside a cancellation mask.
    pub fn ensure_live(&self) -> Result<(), CancelledError> {
        if !self.request_scope_is_active() {
            return Err(CancelledError);
        }
        let _mask_transition = self
            .mask_transition
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.framework_mask_depth.load(Ordering::SeqCst) > 0 {
            return Ok(());
        }

        let ambient = self.cx.budget();
        let now = self.cx.now();
        let state = *self
            .budget_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let effective = self.apply_operation_deadline(state.effective(ambient));
        if self.request_cancellation.is_cancel_requested()
            || self.cx.is_cancel_requested()
            || effective.is_past_deadline(now)
            || state.deferred_overrun
        {
            return Err(CancelledError);
        }
        Ok(())
    }

    /// Cooperative cancellation checkpoint.
    ///
    /// Call this at natural suspension points in your handler to allow
    /// graceful cancellation. Returns `Err` if cancellation is pending.
    ///
    /// # Errors
    ///
    /// Returns an error if the request has been cancelled and cancellation
    /// is not currently masked. Each admitted checkpoint consumes one unit
    /// from both a finite framework-owned poll ceiling and a finite ambient
    /// [`Cx`] poll snapshot. FastMCP records ambient debits in a clone-shared
    /// request ledger; it does not mutate or cancel the caller-owned context.
    ///
    /// This method intentionally does not call [`Cx::checkpoint`]. In the
    /// pinned runtime that API treats a zero cost balance as aggregate budget
    /// exhaustion and mutates the clone-shared cancellation state, even though
    /// this operation admits only the poll dimension. FastMCP observes the
    /// supplied context's cancellation flag and deadline without poisoning a
    /// caller-owned context shared by other request domains.
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
        if !self.request_scope_is_active() {
            return Err(CancelledError);
        }
        let _mask_transition = self
            .mask_transition
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let masked = self.framework_mask_depth.load(Ordering::SeqCst) > 0;
        let ambient = self.cx.budget();
        let now = self.cx.now();
        let mut state = self
            .budget_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let adjusted_ambient = state.adjusted_ambient(ambient);
        let effective = self.apply_operation_deadline(
            state
                .ceiling
                .map_or(adjusted_ambient, |ceiling| adjusted_ambient.meet(ceiling)),
        );
        let poll_unavailable = effective.poll_quota == 0;
        let past_deadline = effective.is_past_deadline(now);
        let cancelled =
            self.request_cancellation.is_cancel_requested() || self.cx.is_cancel_requested();
        let deferred_overrun = state.deferred_overrun;

        if !masked && (cancelled || poll_unavailable || past_deadline || deferred_overrun) {
            return Err(CancelledError);
        }

        if poll_unavailable {
            debug_assert!(masked);
            state.deferred_overrun = true;
        }

        if adjusted_ambient.poll_quota != u32::MAX {
            state.ambient_poll_debits = state.ambient_poll_debits.saturating_add(1);
        }

        if let Some(budget) = state.ceiling.as_mut()
            && budget.poll_quota != u32::MAX
        {
            if budget.consume_poll().is_none() {
                debug_assert!(masked);
                state.deferred_overrun = true;
            }
        }

        Ok(())
    }

    /// Debits abstract cost units from the request budget.
    ///
    /// Cost is application-defined and is deliberately separate from poll
    /// accounting: [`checkpoint`](Self::checkpoint) never guesses an
    /// operation's cost. A successful debit is visible through
    /// [`budget`](Self::budget) and every clone of this context. If the
    /// request is explicitly cancelled or expired, or the effective ambient/
    /// ceiling cost budget has fewer than `cost` units remaining, this returns
    /// [`CancelledError`] without a partial debit. Poll accounting remains the
    /// responsibility of [`checkpoint`](Self::checkpoint); this method does
    /// not acknowledge cancellation or consume a poll checkpoint.
    ///
    /// Asupersync exposes the supplied [`Cx`] budget as a read-only snapshot.
    /// FastMCP therefore records cumulative, clone-shared request-local debits
    /// and subtracts them from the current ambient snapshot without mutating or
    /// cancelling the caller-owned Cx. A framework cost ceiling, when present,
    /// is debited independently under the same lock. A zero-unit debit succeeds
    /// at a zero cost quota, but still observes explicit cancellation and an
    /// expired deadline.
    ///
    /// Inside [`masked`](Self::masked), enforcement remains deferred just as
    /// it is for checkpoints. Affordable debits are still recorded, while an
    /// over-budget debit leaves the effective cost budget exhausted so the
    /// exhaustion is observed as soon as the mask is released. A nonbinding
    /// underlying cost dimension can still retain a positive balance.
    ///
    /// # Errors
    ///
    /// Returns an error when the debit cannot be admitted and cancellation is
    /// not currently masked.
    pub fn consume_cost(&self, cost: u64) -> Result<(), CancelledError> {
        if !self.request_scope_is_active() {
            return Err(CancelledError);
        }
        let _mask_transition = self
            .mask_transition
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let masked = self.framework_mask_depth.load(Ordering::SeqCst) > 0;
        let ambient = self.cx.budget();
        let now = self.cx.now();
        let mut state = self
            .budget_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let effective = self.apply_operation_deadline(state.effective(ambient));
        let enough_cost = effective
            .cost_quota
            .is_none_or(|remaining| remaining >= cost);
        let past_deadline = effective.is_past_deadline(now);
        let cancelled =
            self.request_cancellation.is_cancel_requested() || self.cx.is_cancel_requested();

        if !masked && (cancelled || past_deadline || state.deferred_overrun || !enough_cost) {
            return Err(CancelledError);
        }

        if !enough_cost {
            debug_assert!(masked);
            state.deferred_overrun = true;
        }
        state.ambient_cost_debits = state.ambient_cost_debits.saturating_add(cost);
        if let Some(budget) = state.ceiling.as_mut()
            && !budget.consume_cost(cost)
        {
            debug_assert!(masked);
            budget.cost_quota = Some(0);
        }

        Ok(())
    }

    /// Executes a closure with cancellation masked.
    ///
    /// While masked, `checkpoint()` will not return an error even if
    /// cancellation is pending. Use this for critical sections that
    /// must complete atomically.
    ///
    /// Masking is request-context-wide: this context and all of its clones
    /// share both the underlying [`Cx`] mask and the framework ceiling mask.
    /// Independently cancellable concurrent work therefore requires distinct
    /// runtime-owned child contexts rather than clones of one `McpContext`.
    ///
    /// This method masks only the synchronous execution of `f`. Passing an
    /// async block merely constructs a future while masked; polling that future
    /// after this method returns is not protected. Asynchronous critical
    /// sections require a runtime-owned structured cancellation scope.
    ///
    /// # Errors
    ///
    /// Returns [`CancelledError`] if this context's request lease has already
    /// closed or the framework mask depth cannot be incremented.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Commit transaction - must not be interrupted
    /// ctx.masked(|| db.commit_synchronously())?;
    /// ```
    pub fn masked<F, R>(&self, f: F) -> Result<R, CancelledError>
    where
        F: FnOnce() -> R,
    {
        if !self.request_scope_is_active() {
            return Err(CancelledError);
        }
        let entry_transition = self
            .mask_transition
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.framework_mask_depth.load(Ordering::SeqCst) >= MAX_MASK_DEPTH {
            return Err(CancelledError);
        }
        if self
            .framework_mask_depth
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |depth| {
                depth.checked_add(1)
            })
            .is_err()
        {
            return Err(CancelledError);
        }
        let framework_mask = FrameworkMaskGuard {
            depth: &self.framework_mask_depth,
        };
        let masked_outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.cx.masked(|| {
                drop(entry_transition);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
                let exit_transition = self
                    .mask_transition
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (outcome, exit_transition)
            })
        }));
        let (outcome, exit_transition) = match masked_outcome {
            Ok(result) => result,
            Err(_runtime_mask_failure) => {
                let exit_transition = self
                    .mask_transition
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                drop(framework_mask);
                drop(exit_transition);
                return Err(CancelledError);
            }
        };
        drop(framework_mask);
        drop(exit_transition);

        match outcome {
            Ok(result) => Ok(result),
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    /// Records a trace event for this request.
    ///
    /// Events are associated with the request's trace context and can be
    /// used for debugging and observability.
    pub fn trace(&self, message: &str) {
        if self.ensure_live().is_ok() {
            self.cx.trace(message);
        }
    }

    /// Emits a debug `notifications/message` when the client asked for that floor.
    pub fn debug(&self, message: impl AsRef<str>) {
        self.log(McpLogLevel::Debug, message);
    }

    /// Emits an info `notifications/message` when the client asked for that floor.
    pub fn info(&self, message: impl AsRef<str>) {
        self.log(McpLogLevel::Info, message);
    }

    /// Emits a notice `notifications/message` when the client asked for that floor.
    pub fn notice(&self, message: impl AsRef<str>) {
        self.log(McpLogLevel::Notice, message);
    }

    /// Emits a warning `notifications/message` when the client asked for that floor.
    pub fn warning(&self, message: impl AsRef<str>) {
        self.log(McpLogLevel::Warning, message);
    }

    /// Emits an error `notifications/message` when the client asked for that floor.
    pub fn error(&self, message: impl AsRef<str>) {
        self.log(McpLogLevel::Error, message);
    }

    /// Emits one MCP log notification if the client floor admits `level`.
    ///
    /// Missing floor, missing sender, or a cancelled request are silent
    /// no-ops so handlers can log without branching on transport wiring.
    pub fn log(&self, level: McpLogLevel, message: impl AsRef<str>) {
        self.log_data(
            level,
            serde_json::Value::String(message.as_ref().to_owned()),
        );
    }

    /// Emits one MCP log notification with caller-owned JSON data.
    pub fn log_data(&self, level: McpLogLevel, data: serde_json::Value) {
        if self.ensure_live().is_err() {
            return;
        }
        let Some(min_level) = self.min_log_level else {
            return;
        };
        if level.rank() < min_level.rank() {
            return;
        }
        if let Some(sender) = self.log_sender.as_ref() {
            sender.send_log(level, Some("fastmcp"), data);
        }
    }

    /// Notifies subscribers that `uri` changed.
    ///
    /// Returns `true` when a 2024 session subscriber received
    /// `notifications/resources/updated` or at least one modern
    /// `subscriptions/listen` stream accepted the event.
    pub fn notify_resource_updated(&self, uri: impl AsRef<str>) -> bool {
        if self.ensure_live().is_err() {
            return false;
        }
        let uri = uri.as_ref();
        let mut delivered = false;
        if self
            .resource_subscriptions
            .as_ref()
            .is_some_and(|uris| uris.contains(uri))
            && let Some(sender) = self.log_sender.as_ref()
        {
            sender.send_resource_updated(uri);
            delivered = true;
        }
        if let Some(publisher) = self.catalog_publisher.as_ref()
            && publisher.publish_resource_updated(uri)
        {
            delivered = true;
        }
        delivered
    }

    /// Returns a reference to the underlying asupersync Cx.
    ///
    /// Use this when you need direct access to asupersync primitives,
    /// such as spawning tasks or using combinators. Direct Cx checkpoints and
    /// budget snapshots do not observe FastMCP's framework ceiling, cumulative
    /// cost ledger, or two-layer mask transition; request admission code must
    /// use [`checkpoint`](Self::checkpoint), [`consume_cost`](Self::consume_cost),
    /// and [`budget`](Self::budget) instead. Conversely, masking the raw `Cx`
    /// does not mask FastMCP admission checks: code that calls back into this
    /// context must use [`masked`](Self::masked). The raw handle also cannot be
    /// revoked when the FastMCP request lease closes, so it must not be retained
    /// or used as an independently owned request capability.
    #[must_use]
    pub fn cx(&self) -> &Cx {
        &self.cx
    }

    /// Admits one final dual-era result as a four-valued MCP outcome.
    ///
    /// The result retains both its `Modern`/`Legacy` branch and the caller's
    /// exact terminal-reason type. This context performs its normal request
    /// liveness check before admitting a newly completed result, so ambient
    /// `Cx` cancellation, request-local cancellation, lease closure, and
    /// bounded framework admission continue to win without creating a runtime.
    #[must_use]
    pub fn final_result_outcome<TypedResult, LegacyResult, TerminalReason>(
        &self,
        result: crate::combinator::FinalRequestResult<TypedResult, LegacyResult, TerminalReason>,
    ) -> crate::McpOutcome<
        crate::combinator::FinalRequestResult<TypedResult, LegacyResult, TerminalReason>,
    > {
        if self.ensure_live().is_err() {
            return Outcome::Cancelled(self.final_result_cancellation_reason());
        }
        Outcome::Ok(result)
    }

    /// Preserves an already-terminal request outcome while admitting an `Ok` final result.
    ///
    /// A supplied cancellation reason or panic payload is returned unchanged;
    /// only an `Ok` result is subject to the context's current liveness check.
    #[must_use]
    pub fn adapt_final_request_outcome<TypedResult, LegacyResult, TerminalReason>(
        &self,
        outcome: crate::McpOutcome<
            crate::combinator::FinalRequestResult<TypedResult, LegacyResult, TerminalReason>,
        >,
    ) -> crate::McpOutcome<
        crate::combinator::FinalRequestResult<TypedResult, LegacyResult, TerminalReason>,
    > {
        match outcome {
            Outcome::Ok(result) => self.final_result_outcome(result),
            Outcome::Err(error) => Outcome::Err(error),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    fn final_result_cancellation_reason(&self) -> CancelReason {
        self.cx.cancel_reason().unwrap_or_else(|| {
            if self.request_cancellation.is_cancel_requested() {
                CancelReason::user("FastMCP request-local cancellation")
            } else if !self.request_scope_is_active() {
                CancelReason::user("FastMCP request lease closed")
            } else {
                CancelReason::user("FastMCP request liveness rejected final result")
            }
        })
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
        if !self.request_scope_is_active() {
            return None;
        }
        self.state.as_ref()?.get(key)
    }

    /// Returns the authentication context for this request, if available.
    #[must_use]
    pub fn auth(&self) -> Option<AuthContext> {
        if !self.request_scope_is_active() {
            return None;
        }
        self.auth
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Commits authentication context for this request if the slot is empty.
    ///
    /// The slot is write-once across all context clones. Authentication
    /// providers may use an isolated staging context, and the server commits
    /// the successful result to the shared request context. Middleware,
    /// handlers, and nested dispatch cannot replace that committed principal.
    /// Returns `false` if the request lease is closed or an identity has
    /// already been committed.
    pub fn set_auth(&self, auth: AuthContext) -> bool {
        if self.ensure_live().is_err() {
            return false;
        }
        let mut slot = self
            .auth
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.auth_state.load(Ordering::Acquire) != REQUEST_AUTH_UNCOMMITTED {
            return false;
        }
        *slot = Some(auth);
        self.auth_state
            .store(REQUEST_AUTH_AUTHENTICATED, Ordering::Release);
        true
    }

    /// Commits this request as unauthenticated without exposing an empty
    /// [`AuthContext`] to handlers.
    ///
    /// This is a write-once internal admission marker. It prevents later
    /// middleware from forging handler-visible authentication while allowing
    /// cache middleware to distinguish admitted anonymous traffic from an
    /// authentication flow that has not completed.
    #[doc(hidden)]
    pub fn commit_anonymous_auth(&self) -> bool {
        if self.ensure_live().is_err() {
            return false;
        }
        let slot = self
            .auth
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.auth_state.load(Ordering::Acquire) != REQUEST_AUTH_UNCOMMITTED || slot.is_some() {
            return false;
        }
        self.auth_state
            .store(REQUEST_AUTH_ANONYMOUS, Ordering::Release);
        true
    }

    /// Returns the committed cache authorization partition.
    ///
    /// The outer `Option` distinguishes incomplete admission from a committed
    /// request. The inner `Option` is `None` for anonymous admission and
    /// contains the complete handler-visible authenticated facts otherwise.
    #[doc(hidden)]
    #[must_use]
    pub fn cache_auth_partition(&self) -> Option<Option<AuthContext>> {
        if !self.request_scope_is_active() {
            return None;
        }
        let slot = self
            .auth
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match self.auth_state.load(Ordering::Acquire) {
            REQUEST_AUTH_ANONYMOUS => Some(None),
            REQUEST_AUTH_AUTHENTICATED => slot.clone().map(Some),
            _ => None,
        }
    }

    /// Returns a cloned context with request-local auth attached.
    #[must_use]
    pub fn with_auth(self, auth: AuthContext) -> Self {
        let _ = self.set_auth(auth);
        self
    }

    /// Returns a derived context with an isolated authentication staging slot.
    ///
    /// Only budget accounting, cancellation, masking, and request identity
    /// remain shared. Session state, nested dispatch, progress, sampling,
    /// elicitation, and roots are removed from the staging view so
    /// authentication code cannot exercise handler authority and a handler
    /// cannot use this method to forge a principal for nested dispatch.
    #[must_use]
    pub fn with_isolated_auth(mut self) -> Self {
        let already_committed = self.auth_state.load(Ordering::Acquire) != REQUEST_AUTH_UNCOMMITTED;
        if already_committed {
            return self;
        }
        self.auth = Arc::new(Mutex::new(None));
        self.auth_state = Arc::new(AtomicU8::new(REQUEST_AUTH_UNCOMMITTED));
        self.state = None;
        self.progress_reporter = None;
        self.sampling_sender = None;
        self.elicitation_sender = None;
        self.roots_provider = None;
        self.resource_reader = None;
        self.tool_caller = None;
        self.prompt_caller = None;
        self
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
        if self.ensure_live().is_err() {
            return false;
        }
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
        if self.ensure_live().is_err() {
            return None;
        }
        self.state.as_ref()?.remove(key)
    }

    /// Checks if a key exists in session state.
    ///
    /// Returns `false` if session state is not available.
    #[must_use]
    pub fn has_state(&self, key: &str) -> bool {
        self.request_scope_is_active() && self.state.as_ref().is_some_and(|s| s.contains(key))
    }

    /// Returns whether session state is available in this context.
    #[must_use]
    pub fn has_session_state(&self) -> bool {
        self.request_scope_is_active() && self.state.is_some()
    }

    /// Returns whether attached session state is request-local, not durable.
    #[doc(hidden)]
    #[must_use]
    pub fn session_is_ephemeral(&self) -> bool {
        self.request_scope_is_active()
            && self.state.as_ref().is_some_and(SessionState::is_ephemeral)
    }

    /// Returns the session state attached to this context, if any.
    ///
    /// Final dispatch uses this shared bag so a later inbound on the same
    /// modern connection still sees `disable_*` mutations from earlier
    /// requests. Cloning the returned value shares the underlying store.
    #[must_use]
    pub fn session_state(&self) -> Option<&SessionState> {
        self.state.as_ref()
    }

    /// Returns the opaque cache partition and mutation revision for this
    /// request's session state.
    ///
    /// This is an internal cross-crate integration hook. It returns `None`
    /// when the request is no longer live or the state cannot provide a safe
    /// stable partition. Cache implementations must additionally partition by
    /// all response-relevant authenticated facts.
    #[doc(hidden)]
    #[must_use]
    pub fn session_cache_partition(&self) -> Option<([u8; 32], u64)> {
        if !self.request_scope_is_active() {
            return None;
        }
        self.state.as_ref()?.cache_partition()
    }

    /// Captures the current session cache partition for this request.
    ///
    /// Repeated callers receive the same partition only while session state has
    /// not changed. This lets cache middleware prove that a response completed
    /// against the same state revision used for lookup.
    #[doc(hidden)]
    #[must_use]
    pub fn begin_session_cache_partition(&self) -> Option<([u8; 32], u64)> {
        let current = self.session_cache_partition()?;
        let mut admitted = self
            .cache_admission_partition
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *admitted {
            None => {
                *admitted = Some(current);
                Some(current)
            }
            Some(existing) if existing == current => Some(existing),
            Some(_) => None,
        }
    }

    /// Returns the admitted cache partition only if the state revision is
    /// unchanged at response completion.
    #[doc(hidden)]
    #[must_use]
    pub fn complete_session_cache_partition(&self) -> Option<([u8; 32], u64)> {
        if !self.request_scope_is_active() {
            return None;
        }
        let admitted = *self
            .cache_admission_partition
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let admitted = admitted?;
        (self.state.as_ref()?.cache_partition() == Some(admitted)).then_some(admitted)
    }

    /// Marks that one middleware instance produced this request's response from
    /// a cache hit.
    #[doc(hidden)]
    pub fn mark_response_cache_hit(&self, cache_id: u64) -> bool {
        const MAX_CACHE_MIDDLEWARE_PER_REQUEST: usize = 64;
        if !self.request_scope_is_active() || cache_id == 0 {
            return false;
        }
        let mut hits = self
            .response_cache_hits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if hits.contains(&cache_id) {
            return true;
        }
        if hits.len() >= MAX_CACHE_MIDDLEWARE_PER_REQUEST || hits.try_reserve(1).is_err() {
            return false;
        }
        hits.push(cache_id);
        true
    }

    /// Returns whether a specific middleware instance produced this request's
    /// response from cache.
    #[doc(hidden)]
    #[must_use]
    pub fn response_was_cache_hit(&self, cache_id: u64) -> bool {
        self.request_scope_is_active()
            && cache_id != 0
            && self
                .response_cache_hits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&cache_id)
    }

    /// Returns whether any response-cache middleware served this request.
    #[doc(hidden)]
    #[must_use]
    pub fn response_was_served_from_cache(&self) -> bool {
        self.request_scope_is_active()
            && !self
                .response_cache_hits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
    }

    // ========================================================================
    // Capabilities Access
    // ========================================================================

    /// Returns the client capability information, if available.
    ///
    /// Capabilities are set by the server after initialization and reflect
    /// what the connected client supports.
    #[must_use]
    pub fn client_capabilities(&self) -> Option<&ClientCapabilityInfo> {
        self.client_capabilities.as_ref()
    }

    /// Returns the self-reported modern client Implementation, if advertised.
    ///
    /// This is request `_meta` identity, not authentication. A missing value
    /// means the peer did not send `io.modelcontextprotocol/clientInfo`.
    #[must_use]
    pub fn client_implementation(&self) -> Option<&ClientImplementationInfo> {
        self.client_implementation.as_ref()
    }

    /// Returns the server capability information, if available.
    ///
    /// Reflects what capabilities this server advertises.
    #[must_use]
    pub fn server_capabilities(&self) -> Option<&ServerCapabilityInfo> {
        self.server_capabilities.as_ref()
    }

    /// Returns whether the client supports sampling (LLM completions).
    ///
    /// This is a convenience method that checks the client capabilities.
    /// Returns `false` if capabilities are not yet available (before initialization).
    #[must_use]
    pub fn client_supports_sampling(&self) -> bool {
        self.client_capabilities
            .as_ref()
            .is_some_and(|c| c.sampling)
    }

    /// Returns whether the client supports elicitation (user input requests).
    ///
    /// This is a convenience method that checks the client capabilities.
    /// Returns `false` if capabilities are not yet available.
    #[must_use]
    pub fn client_supports_elicitation(&self) -> bool {
        self.client_capabilities
            .as_ref()
            .is_some_and(|c| c.elicitation)
    }

    /// Returns whether the client supports form-mode elicitation.
    #[must_use]
    pub fn client_supports_elicitation_form(&self) -> bool {
        self.client_capabilities
            .as_ref()
            .is_some_and(|c| c.elicitation_form)
    }

    /// Returns whether the client supports URL-mode elicitation.
    #[must_use]
    pub fn client_supports_elicitation_url(&self) -> bool {
        self.client_capabilities
            .as_ref()
            .is_some_and(|c| c.elicitation_url)
    }

    /// Returns whether the client supports roots listing.
    ///
    /// This is a convenience method that checks the client capabilities.
    /// Returns `false` if capabilities are not yet available.
    #[must_use]
    pub fn client_supports_roots(&self) -> bool {
        self.client_capabilities.as_ref().is_some_and(|c| c.roots)
    }

    // ========================================================================
    // Dynamic Component Enable/Disable
    // ========================================================================

    /// Session state key for disabled tools.
    const DISABLED_TOOLS_KEY: &'static str = "fastmcp.disabled_tools";
    /// Session state key for disabled resources.
    const DISABLED_RESOURCES_KEY: &'static str = "fastmcp.disabled_resources";
    /// Session state key for disabled prompts.
    const DISABLED_PROMPTS_KEY: &'static str = "fastmcp.disabled_prompts";

    /// Disables a tool for this session.
    ///
    /// Disabled tools will not appear in `tools/list` responses and will return
    /// an error if called directly. This is useful for adapting available
    /// functionality based on user permissions, feature flags, or runtime conditions.
    ///
    /// Returns `true` if the operation succeeded, `false` if session state is unavailable.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn my_tool(ctx: &McpContext) -> McpResult<String> {
    ///     // Disable the "admin_tool" for this session
    ///     ctx.disable_tool("admin_tool");
    ///     Ok("Admin tool disabled".to_string())
    /// }
    /// ```
    pub fn disable_tool(&self, name: impl Into<String>) -> bool {
        self.add_to_disabled_set(Self::DISABLED_TOOLS_KEY, name.into(), McpCatalogKind::Tools)
    }

    /// Enables a previously disabled tool for this session.
    ///
    /// Returns `true` if the operation succeeded, `false` if session state is unavailable.
    pub fn enable_tool(&self, name: &str) -> bool {
        self.remove_from_disabled_set(Self::DISABLED_TOOLS_KEY, name, McpCatalogKind::Tools)
    }

    /// Returns whether a tool is enabled (not disabled) for this session.
    ///
    /// Tools are enabled by default unless explicitly disabled.
    #[must_use]
    pub fn is_tool_enabled(&self, name: &str) -> bool {
        self.request_scope_is_active() && !self.is_in_disabled_set(Self::DISABLED_TOOLS_KEY, name)
    }

    /// Disables a resource for this session.
    ///
    /// Disabled resources will not appear in `resources/list` responses and will
    /// return an error if read directly.
    ///
    /// Returns `true` if the operation succeeded, `false` if session state is unavailable.
    pub fn disable_resource(&self, uri: impl Into<String>) -> bool {
        self.add_to_disabled_set(
            Self::DISABLED_RESOURCES_KEY,
            uri.into(),
            McpCatalogKind::Resources,
        )
    }

    /// Enables a previously disabled resource for this session.
    ///
    /// Returns `true` if the operation succeeded, `false` if session state is unavailable.
    pub fn enable_resource(&self, uri: &str) -> bool {
        self.remove_from_disabled_set(Self::DISABLED_RESOURCES_KEY, uri, McpCatalogKind::Resources)
    }

    /// Returns whether a resource is enabled (not disabled) for this session.
    ///
    /// Resources are enabled by default unless explicitly disabled.
    #[must_use]
    pub fn is_resource_enabled(&self, uri: &str) -> bool {
        self.request_scope_is_active()
            && !self.is_in_disabled_set(Self::DISABLED_RESOURCES_KEY, uri)
    }

    /// Disables a prompt for this session.
    ///
    /// Disabled prompts will not appear in `prompts/list` responses and will
    /// return an error if retrieved directly.
    ///
    /// Returns `true` if the operation succeeded, `false` if session state is unavailable.
    pub fn disable_prompt(&self, name: impl Into<String>) -> bool {
        self.add_to_disabled_set(
            Self::DISABLED_PROMPTS_KEY,
            name.into(),
            McpCatalogKind::Prompts,
        )
    }

    /// Enables a previously disabled prompt for this session.
    ///
    /// Returns `true` if the operation succeeded, `false` if session state is unavailable.
    pub fn enable_prompt(&self, name: &str) -> bool {
        self.remove_from_disabled_set(Self::DISABLED_PROMPTS_KEY, name, McpCatalogKind::Prompts)
    }

    /// Returns whether a prompt is enabled (not disabled) for this session.
    ///
    /// Prompts are enabled by default unless explicitly disabled.
    #[must_use]
    pub fn is_prompt_enabled(&self, name: &str) -> bool {
        self.request_scope_is_active() && !self.is_in_disabled_set(Self::DISABLED_PROMPTS_KEY, name)
    }

    /// Returns the set of disabled tools for this session.
    #[must_use]
    pub fn disabled_tools(&self) -> std::collections::HashSet<String> {
        self.get_disabled_set(Self::DISABLED_TOOLS_KEY)
    }

    /// Returns the set of disabled resources for this session.
    #[must_use]
    pub fn disabled_resources(&self) -> std::collections::HashSet<String> {
        self.get_disabled_set(Self::DISABLED_RESOURCES_KEY)
    }

    /// Returns the set of disabled prompts for this session.
    #[must_use]
    pub fn disabled_prompts(&self) -> std::collections::HashSet<String> {
        self.get_disabled_set(Self::DISABLED_PROMPTS_KEY)
    }

    // Helper: Add a name to a disabled set
    fn add_to_disabled_set(&self, key: &str, name: String, kind: McpCatalogKind) -> bool {
        if self.ensure_live().is_err() {
            return false;
        }
        let Some(state) = self.state.as_ref() else {
            return false;
        };
        let mut set: std::collections::HashSet<String> = state.get(key).unwrap_or_default();
        let changed = set.insert(name);
        let stored = state.set(key, set);
        if stored && changed {
            self.emit_catalog_changed(kind);
        }
        stored
    }

    // Helper: Remove a name from a disabled set
    fn remove_from_disabled_set(&self, key: &str, name: &str, kind: McpCatalogKind) -> bool {
        if self.ensure_live().is_err() {
            return false;
        }
        let Some(state) = self.state.as_ref() else {
            return false;
        };
        let mut set: std::collections::HashSet<String> = state.get(key).unwrap_or_default();
        let changed = set.remove(name);
        let stored = state.set(key, set);
        if stored && changed {
            self.emit_catalog_changed(kind);
        }
        stored
    }

    fn emit_catalog_changed(&self, kind: McpCatalogKind) {
        if let Some(sender) = self.log_sender.as_ref() {
            sender.send_catalog_changed(kind);
        }
        if let Some(publisher) = self.catalog_publisher.as_ref() {
            let _ = publisher.publish_catalog_changed(kind);
        }
    }

    // Helper: Check if a name is in a disabled set
    fn is_in_disabled_set(&self, key: &str, name: &str) -> bool {
        if !self.request_scope_is_active() {
            return false;
        }
        let Some(state) = self.state.as_ref() else {
            return false;
        };
        let set: std::collections::HashSet<String> = state.get(key).unwrap_or_default();
        set.contains(name)
    }

    // Helper: Get the full disabled set
    fn get_disabled_set(&self, key: &str) -> std::collections::HashSet<String> {
        if !self.request_scope_is_active() {
            return std::collections::HashSet::new();
        }
        self.state
            .as_ref()
            .and_then(|s| s.get(key))
            .unwrap_or_default()
    }

    // ========================================================================
    // Client Roots
    // ========================================================================

    /// Returns whether client roots are available in this context.
    #[must_use]
    pub fn can_list_roots(&self) -> bool {
        self.ensure_live().is_ok() && self.roots_provider.is_some()
    }

    /// Lists the filesystem roots exposed by the connected client.
    ///
    /// # Errors
    ///
    /// Returns an error when the client did not advertise roots, the transport
    /// cannot complete the reverse request, or this request is cancelled.
    pub async fn list_roots(&self) -> crate::McpResult<Vec<ClientRoot>> {
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        let provider = self.roots_provider.as_ref().ok_or_else(|| {
            crate::McpError::new(
                crate::McpErrorCode::InvalidRequest,
                "Roots not available: client does not support roots capability",
            )
        })?;

        let roots = provider.list_roots().await?;
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        Ok(roots)
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
        self.ensure_live().is_ok() && self.sampling_sender.is_some()
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
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        let sender = self.sampling_sender.as_ref().ok_or_else(|| {
            crate::McpError::new(
                crate::McpErrorCode::InvalidRequest,
                "Sampling not available: client does not support sampling capability",
            )
        })?;

        let response = sender.create_message(request).await?;
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        Ok(response)
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
        self.ensure_live().is_ok() && self.elicitation_sender.is_some()
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
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        let sender = self.elicitation_sender.as_ref().ok_or_else(|| {
            crate::McpError::new(
                crate::McpErrorCode::InvalidRequest,
                "Elicitation not available: client does not support elicitation capability",
            )
        })?;

        let response = sender.elicit(request).await?;
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        Ok(response)
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
        self.ensure_live().is_ok() && self.resource_reader.is_some()
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
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        // Check if we have a resource reader
        let reader = self.resource_reader.as_ref().ok_or_else(|| {
            crate::McpError::new(
                crate::McpErrorCode::InternalError,
                "Resource reading not available: no router attached to context",
            )
        })?;

        // Use one effective nesting depth across all cross-component APIs so
        // alternating tool -> resource -> prompt cycles cannot reset a
        // type-specific counter.
        let nested_dispatch_depth = self.nested_dispatch_depth();
        if nested_dispatch_depth >= MAX_RESOURCE_READ_DEPTH {
            return Err(crate::McpError::new(
                crate::McpErrorCode::InternalError,
                format!(
                    "Maximum resource read depth ({}) exceeded; possible infinite recursion",
                    MAX_RESOURCE_READ_DEPTH
                ),
            ));
        }

        // Read the resource with incremented depth
        let result = reader
            .read_resource(self, uri, nested_dispatch_depth + 1)
            .await?;
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        Ok(result)
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
        self.ensure_live().is_ok() && self.tool_caller.is_some()
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
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        // Check if we have a tool caller
        let caller = self.tool_caller.as_ref().ok_or_else(|| {
            crate::McpError::new(
                crate::McpErrorCode::InternalError,
                "Tool calling not available: no router attached to context",
            )
        })?;

        // Share the effective depth with resource reads and prompt gets so
        // alternating cycles are bounded just like same-kind recursion.
        let nested_dispatch_depth = self.nested_dispatch_depth();
        if nested_dispatch_depth >= MAX_TOOL_CALL_DEPTH {
            return Err(crate::McpError::new(
                crate::McpErrorCode::InternalError,
                format!(
                    "Maximum tool call depth ({}) exceeded calling '{}'; possible infinite recursion",
                    MAX_TOOL_CALL_DEPTH, name
                ),
            ));
        }

        // Call the tool with incremented depth
        let result = caller
            .call_tool(self, name, args, nested_dispatch_depth + 1)
            .await?;
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        Ok(result)
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
    // Prompt Getting (Cross-Component Access)
    // ========================================================================

    /// Returns whether prompt getting is available in this context.
    #[must_use]
    pub fn can_get_prompts(&self) -> bool {
        self.ensure_live().is_ok() && self.prompt_caller.is_some()
    }

    /// Returns the current prompt get depth.
    #[must_use]
    pub fn prompt_get_depth(&self) -> u32 {
        self.prompt_get_depth
    }

    fn nested_dispatch_depth(&self) -> u32 {
        self.resource_read_depth
            .max(self.tool_call_depth)
            .max(self.prompt_get_depth)
    }

    /// Gets a prompt by name with the given arguments.
    ///
    /// This allows tools, resources, and prompts to get other prompts
    /// configured on the same server.
    pub async fn get_prompt(
        &self,
        name: &str,
        arguments: std::collections::HashMap<String, String>,
    ) -> crate::McpResult<PromptGetResult> {
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        let caller = self.prompt_caller.as_ref().ok_or_else(|| {
            crate::McpError::new(
                crate::McpErrorCode::InternalError,
                "Prompt getting not available: no router attached to context",
            )
        })?;

        let nested_dispatch_depth = self.nested_dispatch_depth();
        if nested_dispatch_depth >= MAX_PROMPT_GET_DEPTH {
            return Err(crate::McpError::new(
                crate::McpErrorCode::InternalError,
                format!(
                    "Maximum prompt get depth ({}) exceeded getting '{}'; possible infinite recursion",
                    MAX_PROMPT_GET_DEPTH, name
                ),
            ));
        }

        let result = caller
            .get_prompt(self, name, arguments, nested_dispatch_depth + 1)
            .await?;
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        Ok(result)
    }

    /// Gets a prompt and extracts the first text message.
    pub async fn get_prompt_text(
        &self,
        name: &str,
        arguments: std::collections::HashMap<String, String>,
    ) -> crate::McpResult<String> {
        let result = self.get_prompt(name, arguments).await?;
        result.first_text().map(String::from).ok_or_else(|| {
            crate::McpError::new(
                crate::McpErrorCode::InternalError,
                format!("Prompt '{}' returned no text content", name),
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
    /// let users = ctx.join_all(futures).await?;
    /// ```
    pub async fn join_all<T: Send + 'static>(
        &self,
        futures: Vec<crate::combinator::BoxFuture<'_, T>>,
    ) -> crate::McpResult<Vec<T>> {
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        let results = crate::combinator::join_all(&self.cx, futures).await;
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        Ok(results)
    }

    /// Races multiple futures, returning the first to complete.
    ///
    /// This is the 1-of-N combinator: the first future to complete wins,
    /// and all other supplied futures are dropped. Dropping a future does not
    /// cancel or drain work that it spawned independently; such work must live
    /// in a caller-owned structured scope with an explicit join obligation.
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
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        let result = crate::combinator::race(&self.cx, futures).await;
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        result
    }

    /// Waits for M of N futures to complete successfully.
    ///
    /// Returns when `required` futures have completed successfully.
    /// Remaining supplied futures are dropped. Independently spawned work is
    /// neither cancelled nor drained by dropping its parent future.
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
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        let result = crate::combinator::quorum(&self.cx, required, futures).await;
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        result
    }

    /// Races futures and returns the first successful result.
    ///
    /// Unlike `race` which returns the first to complete (success or failure),
    /// `first_ok` returns the first to complete successfully. Once a result is
    /// selected, the remaining supplied futures are dropped; independently
    /// spawned work is not cancelled or drained.
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
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        let result = crate::combinator::first_ok(&self.cx, futures).await;
        self.ensure_live()
            .map_err(|_| crate::McpError::request_cancelled())?;
        result
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
    fn request_local_cancellation_does_not_cancel_shared_ambient_context() {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let request =
            McpContext::new(cx.clone(), 1).with_request_cancellation(cancellation.clone());
        let sibling = McpContext::new(cx.clone(), 2);

        cancellation.cancel();

        assert!(request.ensure_live().is_err());
        assert!(request.checkpoint().is_err());
        assert!(sibling.ensure_live().is_ok());
        assert!(!cx.is_cancel_requested());
    }

    #[test]
    fn context_exposes_its_request_local_cancellation_handle() {
        let cancellation = McpRequestCancellation::new();
        let context =
            McpContext::new(Cx::for_testing(), 1).with_request_cancellation(cancellation.clone());

        let observed = context.request_cancellation();
        assert!(observed.cancel());
        assert!(cancellation.is_cancel_requested());
        assert!(context.is_cancelled());
    }

    #[test]
    fn request_local_cancelled_future_registers_and_is_woken_without_polling() {
        use std::sync::atomic::AtomicBool;

        struct WakeFlag(AtomicBool);

        impl std::task::Wake for WakeFlag {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Release);
            }
        }

        let cancellation = McpRequestCancellation::new();
        let wake_flag = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = std::task::Waker::from(Arc::clone(&wake_flag));
        let mut task_cx = std::task::Context::from_waker(&waker);
        let mut future = Box::pin(cancellation.cancelled());

        assert!(std::future::Future::poll(future.as_mut(), &mut task_cx).is_pending());
        assert!(cancellation.cancel());
        assert!(wake_flag.0.load(Ordering::Acquire));
        assert!(std::future::Future::poll(future.as_mut(), &mut task_cx).is_ready());
    }

    #[test]
    fn request_local_cancelled_future_observes_preexisting_cancellation() {
        let cancellation = McpRequestCancellation::new();
        assert!(cancellation.cancel());

        let mut future = Box::pin(cancellation.cancelled());
        let waker = std::task::Waker::noop();
        let mut task_cx = std::task::Context::from_waker(waker);

        assert!(std::future::Future::poll(future.as_mut(), &mut task_cx).is_ready());
    }

    #[test]
    fn request_terminal_future_is_woken_when_finalization_wins() {
        use std::sync::atomic::AtomicBool;

        struct WakeFlag(AtomicBool);

        impl std::task::Wake for WakeFlag {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Release);
            }
        }

        let cancellation = McpRequestCancellation::new();
        let wake_flag = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = std::task::Waker::from(Arc::clone(&wake_flag));
        let mut task_cx = std::task::Context::from_waker(&waker);
        let mut future = Box::pin(cancellation.terminated());

        assert!(!cancellation.is_terminal());
        assert!(std::future::Future::poll(future.as_mut(), &mut task_cx).is_pending());
        assert!(cancellation.begin_finalization());
        assert!(cancellation.is_terminal());
        assert!(wake_flag.0.load(Ordering::Acquire));
        assert!(std::future::Future::poll(future.as_mut(), &mut task_cx).is_ready());
    }

    #[test]
    fn request_local_cancellation_is_deferred_inside_framework_mask() {
        let cancellation = McpRequestCancellation::new();
        let ctx =
            McpContext::new(Cx::for_testing(), 1).with_request_cancellation(cancellation.clone());

        let checkpoint = ctx
            .masked(|| {
                cancellation.cancel();
                ctx.checkpoint()
            })
            .expect("framework mask should be admitted");

        assert!(checkpoint.is_ok());
        assert!(ctx.ensure_live().is_err());
    }

    #[test]
    fn request_local_cancellation_stops_state_and_capability_effects() {
        let state = SessionState::new();
        assert!(state.set("existing", 1_u32));
        let cancellation = McpRequestCancellation::new();
        let ctx = McpContext::with_state(Cx::for_testing(), 1, state.clone())
            .with_sampling(Arc::new(NoOpSamplingSender))
            .with_elicitation(Arc::new(NoOpElicitationSender))
            .with_request_cancellation(cancellation.clone());

        assert!(ctx.can_sample());
        assert!(ctx.can_elicit());
        assert!(cancellation.cancel());

        assert!(!ctx.set_state("late", 2_u32));
        assert!(ctx.remove_state("existing").is_none());
        assert!(!ctx.disable_tool("late-tool"));
        assert!(!ctx.disable_resource("late://resource"));
        assert!(!ctx.disable_prompt("late-prompt"));
        assert!(!ctx.can_sample());
        assert!(!ctx.can_elicit());
        assert_eq!(state.get::<u32>("existing"), Some(1));
        assert!(!state.contains("late"));
    }

    #[test]
    fn admitted_mask_allows_critical_state_commit_before_cancellation_surfaces() {
        let state = SessionState::new();
        let cancellation = McpRequestCancellation::new();
        let ctx = McpContext::with_state(Cx::for_testing(), 1, state.clone())
            .with_request_cancellation(cancellation.clone());

        let committed = ctx
            .masked(|| {
                assert!(cancellation.cancel());
                ctx.set_state("critical-commit", true)
            })
            .expect("mask should be admitted before cancellation");

        assert!(committed);
        assert_eq!(state.get::<bool>("critical-commit"), Some(true));
        assert!(ctx.ensure_live().is_err());
    }

    #[test]
    fn active_request_clone_cannot_replace_cancellation_authority() {
        let original = McpRequestCancellation::new();
        let replacement = McpRequestCancellation::new();
        let root =
            McpContext::new(Cx::for_testing(), 1).with_request_cancellation(original.clone());
        let (scoped, _guard) = root
            .begin_request_scope()
            .expect("new context should activate one request lease");
        let attempted_escape = scoped
            .clone()
            .with_request_cancellation(replacement.clone());

        assert!(original.cancel());
        assert!(attempted_escape.ensure_live().is_err());
        assert!(!replacement.is_cancel_requested());
    }

    #[test]
    fn request_finalization_and_cancellation_have_one_atomic_winner() {
        let cancellation_wins = McpRequestCancellation::new();
        assert!(cancellation_wins.cancel());
        assert!(!cancellation_wins.begin_finalization());
        assert!(cancellation_wins.is_cancel_requested());
        assert!(cancellation_wins.is_terminal());

        let finalization_wins = McpRequestCancellation::new();
        assert!(finalization_wins.begin_finalization());
        assert!(finalization_wins.is_finalizing());
        assert!(finalization_wins.is_terminal());
        assert!(!finalization_wins.cancel());
        assert!(!finalization_wins.is_cancel_requested());
    }

    #[test]
    fn test_mcp_context_checkpoint_budget_exhausted() {
        let cx = Cx::for_testing_with_budget(Budget::ZERO);
        let ctx = McpContext::new(cx, 1);

        // Should fail when budget is exhausted
        assert!(ctx.checkpoint().is_err());
    }

    #[test]
    fn checkpoint_does_not_treat_zero_cost_as_poll_exhaustion() {
        let budget = Budget::new().with_poll_quota(2).with_cost_quota(0);
        let cx = Cx::for_testing_with_budget(budget);
        let ctx = McpContext::new(cx.clone(), 1);

        assert!(ctx.checkpoint().is_ok());
        assert!(!cx.is_cancel_requested());
        assert_eq!(ctx.budget().cost_quota, Some(0));
    }

    #[test]
    fn closed_request_lease_cannot_be_revived_or_use_framework_capabilities() {
        let state = SessionState::new();
        let root = McpContext::with_state(Cx::for_testing(), 1, state);
        let clone_created_before_scope = root.clone();
        let (scoped, guard) = root
            .begin_request_scope()
            .expect("new context should create one request lease");
        let escaped = scoped.clone();
        drop(guard);

        assert!(escaped.ensure_live().is_err());
        assert!(escaped.checkpoint().is_err());
        assert!(escaped.consume_cost(0).is_err());
        assert!(escaped.masked(|| 42).is_err());
        assert!(!escaped.set_auth(AuthContext::with_subject("late")));
        assert!(!escaped.set_state("late", true));
        assert!(escaped.auth().is_none());
        assert!(!escaped.can_call_tools());
        assert!(!escaped.can_read_resources());
        assert!(clone_created_before_scope.ensure_live().is_err());

        assert!(clone_created_before_scope.begin_request_scope().is_none());
    }

    #[test]
    fn test_mcp_context_masked_section() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);

        // masked() should execute the closure and return its value
        let result = ctx.masked(|| 42).expect("mask should be admitted");
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
    fn budget_ceiling_is_monotone_and_visible_to_checkpoints() {
        let ambient_deadline = wall_now().saturating_add_nanos(5_000_000_000);
        let tighter_deadline = ambient_deadline.saturating_sub_nanos(1_000_000_000);
        let later_deadline = ambient_deadline.saturating_add_nanos(1_000_000_000);
        let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(ambient_deadline));
        let ctx = McpContext::new(cx, 1)
            .with_budget_ceiling(Budget::new().with_deadline(tighter_deadline))
            .with_budget_ceiling(Budget::new().with_deadline(later_deadline));

        assert_eq!(ctx.budget().deadline, Some(tighter_deadline));
        assert!(ctx.checkpoint().is_ok());
    }

    #[test]
    fn operation_deadline_tightens_child_without_leaking_to_parent() {
        let parent_deadline = wall_now().saturating_add_nanos(5_000_000_000);
        let child_deadline = parent_deadline.saturating_sub_nanos(1_000_000_000);
        let parent = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_deadline(parent_deadline));
        let child = parent.clone().with_operation_deadline(Some(child_deadline));
        let grandchild = child.clone().with_operation_deadline(None);

        assert_eq!(parent.budget().deadline, Some(parent_deadline));
        assert_eq!(child.budget().deadline, Some(child_deadline));
        assert_eq!(grandchild.budget().deadline, Some(child_deadline));
    }

    #[test]
    fn framework_poll_ceiling_drains_across_clones_at_n_plus_one() {
        const LIMIT: u32 = 3;

        let ctx = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_poll_quota(LIMIT));
        let clone = ctx.clone();

        for admitted in 0..LIMIT {
            let result = if admitted % 2 == 0 {
                ctx.checkpoint()
            } else {
                clone.checkpoint()
            };
            assert!(result.is_ok(), "checkpoint {} should fit", admitted + 1);
            let expected = LIMIT - admitted - 1;
            assert_eq!(ctx.budget().poll_quota, expected);
            assert_eq!(clone.budget().poll_quota, expected);
        }

        assert!(clone.checkpoint().is_err(), "checkpoint N+1 must fail");
        assert_eq!(ctx.budget().poll_quota, 0);
        assert!(!ctx.cx().is_cancel_requested());
    }

    #[test]
    fn ambient_poll_budget_drains_across_clones_without_mutating_cx() {
        const LIMIT: u32 = 3;

        let cx = Cx::for_testing_with_budget(Budget::new().with_poll_quota(LIMIT));
        let ctx = McpContext::new(cx.clone(), 1);
        let clone = ctx.clone();

        for admitted in 0..LIMIT {
            let result = if admitted % 2 == 0 {
                ctx.checkpoint()
            } else {
                clone.checkpoint()
            };
            assert!(
                result.is_ok(),
                "ambient checkpoint {} should fit",
                admitted + 1
            );
            assert_eq!(ctx.budget().poll_quota, LIMIT - admitted - 1);
        }

        let debits_before_rejection = ctx
            .budget_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ambient_poll_debits;
        assert!(
            clone.checkpoint().is_err(),
            "ambient checkpoint N+1 must fail"
        );
        assert_eq!(
            ctx.budget_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .ambient_poll_debits,
            debits_before_rejection,
            "a rejected checkpoint must not partially debit the ledger"
        );
        assert_eq!(ctx.budget().poll_quota, 0);
        assert_eq!(cx.budget().poll_quota, LIMIT);
        assert!(!cx.is_cancel_requested());
        assert!(ctx.ensure_live().is_ok());
    }

    #[test]
    fn tighter_ambient_poll_limit_does_not_debit_looser_ceiling_on_rejection() {
        let cx = Cx::for_testing_with_budget(Budget::new().with_poll_quota(2));
        let ctx =
            McpContext::new(cx.clone(), 1).with_budget_ceiling(Budget::new().with_poll_quota(3));

        assert!(ctx.checkpoint().is_ok());
        assert!(ctx.checkpoint().is_ok());
        assert!(ctx.checkpoint().is_err());

        let state = *ctx
            .budget_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.ambient_poll_debits, 2);
        assert_eq!(state.ceiling.map(|budget| budget.poll_quota), Some(1));
        assert_eq!(cx.budget().poll_quota, 2);
    }

    #[test]
    fn framework_cost_ceiling_drains_across_clones_at_n_plus_one() {
        const LIMIT: u64 = 3;

        let ctx = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_cost_quota(LIMIT));
        let clone = ctx.clone();

        for admitted in 0..LIMIT {
            let result = if admitted % 2 == 0 {
                ctx.consume_cost(1)
            } else {
                clone.consume_cost(1)
            };
            assert!(result.is_ok(), "cost debit {} should fit", admitted + 1);
            let expected = Some(LIMIT - admitted - 1);
            assert_eq!(ctx.budget().cost_quota, expected);
            assert_eq!(clone.budget().cost_quota, expected);
        }

        assert!(clone.consume_cost(1).is_err(), "cost debit N+1 must fail");
        assert_eq!(ctx.budget().cost_quota, Some(0));
        assert!(!ctx.cx().is_cancel_requested());
        assert!(
            ctx.ensure_live().is_ok(),
            "an exactly admitted final debit is not an overrun"
        );
    }

    #[test]
    fn framework_poll_and_cost_debits_are_independent() {
        let ctx = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_poll_quota(2).with_cost_quota(2));

        assert!(ctx.checkpoint().is_ok());
        assert_eq!(ctx.budget().poll_quota, 1);
        assert_eq!(ctx.budget().cost_quota, Some(2));

        assert!(ctx.consume_cost(1).is_ok());
        assert_eq!(ctx.budget().poll_quota, 1);
        assert_eq!(ctx.budget().cost_quota, Some(1));
    }

    #[test]
    fn exact_poll_depletion_is_live_until_the_next_poll_admission() {
        let ctx = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_poll_quota(1));

        assert!(ctx.checkpoint().is_ok());
        assert_eq!(ctx.budget().poll_quota, 0);
        assert!(ctx.ensure_live().is_ok());
        assert!(ctx.checkpoint().is_err());
    }

    #[test]
    fn zero_framework_quotas_fail_without_cancelling_ambient_context() {
        let poll_ctx = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_poll_quota(0));
        let cost_ctx = McpContext::new(Cx::for_testing(), 2)
            .with_budget_ceiling(Budget::new().with_cost_quota(0));

        assert!(poll_ctx.checkpoint().is_err());
        assert_eq!(poll_ctx.budget().poll_quota, 0);
        assert!(!poll_ctx.cx().is_cancel_requested());

        assert!(cost_ctx.consume_cost(0).is_ok());
        assert!(cost_ctx.consume_cost(1).is_err());
        assert_eq!(cost_ctx.budget().cost_quota, Some(0));
        assert!(!cost_ctx.cx().is_cancel_requested());
    }

    #[test]
    fn oversized_framework_cost_debit_is_atomic() {
        let ctx = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_cost_quota(2));

        assert!(ctx.consume_cost(3).is_err());
        assert_eq!(ctx.budget().cost_quota, Some(2));
        assert!(ctx.consume_cost(2).is_ok());
        assert_eq!(ctx.budget().cost_quota, Some(0));
        assert!(ctx.consume_cost(1).is_err());
    }

    #[test]
    fn zero_ambient_cost_quota_prevents_framework_cost_debit() {
        let ambient = Budget::new().with_cost_quota(0);
        let ctx = McpContext::new(Cx::for_testing_with_budget(ambient), 1)
            .with_budget_ceiling(Budget::new().with_cost_quota(3));

        assert!(ctx.consume_cost(1).is_err());
        assert_eq!(ctx.budget().cost_quota, Some(0));
    }

    #[test]
    fn positive_ambient_cost_quota_drains_cumulatively_across_clones() {
        const LIMIT: u64 = 3;
        let ambient = Budget::new().with_cost_quota(LIMIT);
        let ctx = McpContext::new(Cx::for_testing_with_budget(ambient), 1);
        let clone = ctx.clone();

        for admitted in 0..LIMIT {
            let result = if admitted % 2 == 0 {
                ctx.consume_cost(1)
            } else {
                clone.consume_cost(1)
            };
            assert!(result.is_ok(), "ambient debit {} should fit", admitted + 1);
            assert_eq!(ctx.budget().cost_quota, Some(LIMIT - admitted - 1));
        }

        assert!(
            clone.consume_cost(1).is_err(),
            "ambient debit N+1 must fail"
        );
        assert_eq!(ctx.budget().cost_quota, Some(0));
        assert_eq!(
            ctx.cx().budget().cost_quota,
            Some(LIMIT),
            "request-local accounting must not mutate the caller-owned Cx"
        );
    }

    #[test]
    fn rejected_cost_debit_does_not_record_an_ambient_checkpoint() {
        let cx = Cx::for_testing_with_budget(Budget::new().with_cost_quota(2));
        let ctx = McpContext::new(cx, 1);
        let before = ctx.cx().checkpoint_state().checkpoint_count;

        assert!(ctx.consume_cost(3).is_err());
        assert_eq!(ctx.cx().checkpoint_state().checkpoint_count, before);
        assert_eq!(ctx.budget().cost_quota, Some(2));
    }

    #[test]
    fn zero_cost_debit_observes_explicit_cancellation() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let ctx = McpContext::new(cx, 1);

        assert!(ctx.consume_cost(0).is_err());
    }

    #[test]
    fn expired_request_ceiling_fails_without_cancelling_ambient_context() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1)
            .with_budget_ceiling(Budget::new().with_deadline(asupersync::Time::ZERO));

        assert!(ctx.is_cancelled());
        assert!(ctx.checkpoint().is_err());
        assert!(!ctx.cx().is_cancel_requested());
    }

    #[test]
    fn framework_budget_ceiling_is_deferred_while_masked() {
        let ctx = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_deadline(asupersync::Time::ZERO));

        assert!(
            ctx.masked(|| ctx.checkpoint())
                .expect("mask should be admitted")
                .is_ok()
        );
        assert!(ctx.checkpoint().is_err());
    }

    #[test]
    fn framework_poll_debits_continue_while_enforcement_is_masked() {
        let ctx = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_poll_quota(1));

        ctx.masked(|| {
            assert!(ctx.checkpoint().is_ok());
            assert_eq!(ctx.budget().poll_quota, 0);
            assert!(ctx.checkpoint().is_ok());
        })
        .expect("mask should be admitted");

        assert!(ctx.checkpoint().is_err());
    }

    #[test]
    fn masked_cost_overage_saturates_framework_ceiling() {
        let ctx = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_cost_quota(2));

        assert!(
            ctx.masked(|| ctx.consume_cost(3))
                .expect("mask should be admitted")
                .is_ok()
        );
        assert_eq!(ctx.budget().cost_quota, Some(0));
        assert!(ctx.ensure_live().is_err());
        assert!(ctx.consume_cost(1).is_err());
    }

    #[test]
    fn masked_exact_cost_depletion_does_not_become_a_deferred_overrun() {
        let ctx = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_cost_quota(2));

        assert!(
            ctx.masked(|| ctx.consume_cost(2))
                .expect("mask should be admitted")
                .is_ok()
        );
        assert_eq!(ctx.budget().cost_quota, Some(0));
        assert!(ctx.ensure_live().is_ok());
        assert!(ctx.consume_cost(0).is_ok());
        assert!(ctx.consume_cost(1).is_err());
    }

    #[test]
    fn masked_cost_overage_saturates_tighter_ambient_quota() {
        let ambient = Budget::new().with_cost_quota(2);
        let ctx = McpContext::new(Cx::for_testing_with_budget(ambient), 1)
            .with_budget_ceiling(Budget::new().with_cost_quota(10));

        assert!(
            ctx.masked(|| ctx.consume_cost(3))
                .expect("mask should be admitted")
                .is_ok()
        );
        assert_eq!(ctx.budget().cost_quota, Some(0));
        assert_eq!(
            ctx.budget_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .ceiling
                .and_then(|budget| budget.cost_quota),
            Some(7),
            "the looser framework ceiling is still debited independently"
        );
        assert!(ctx.consume_cost(1).is_err());
    }

    #[test]
    fn framework_mask_is_shared_with_clones_and_restored_after_exit() {
        let ctx = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_poll_quota(0));
        let clone = ctx.clone();

        assert!(
            ctx.masked(|| clone.checkpoint())
                .expect("mask should be admitted")
                .is_ok()
        );
        assert!(clone.checkpoint().is_err());
    }

    #[test]
    fn framework_mask_depth_is_restored_after_unwind() {
        let ctx = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_deadline(asupersync::Time::ZERO));

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = ctx.masked(|| panic!("test-only masked-section panic"));
        }));

        assert!(ctx.checkpoint().is_err());
        assert_eq!(ctx.framework_mask_depth.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_cancelled_error_display() {
        let err = CancelledError;
        assert_eq!(err.to_string(), "request cancelled");
    }

    #[test]
    fn handler_log_respects_client_floor_and_missing_floor() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        struct CaptureSender(Arc<Mutex<Vec<(McpLogLevel, String)>>>);
        impl NotificationSender for CaptureSender {
            fn send_progress(&self, _progress: f64, _total: Option<f64>, _message: Option<&str>) {}
            fn send_log(&self, level: McpLogLevel, _logger: Option<&str>, data: serde_json::Value) {
                self.0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((level, data.as_str().unwrap_or_default().to_owned()));
            }
        }

        let silent = McpContext::new(Cx::for_testing(), 1)
            .with_log_sender(Arc::new(CaptureSender(Arc::clone(&captured))));
        silent.info("before-floor");
        assert!(captured.lock().expect("lock").is_empty());

        let ctx = silent.with_min_log_level(Some(McpLogLevel::Info));
        assert_eq!(ctx.min_log_level(), Some(McpLogLevel::Info));
        ctx.debug("too-low");
        ctx.info("admitted");
        ctx.warning("also-admitted");
        let emitted = captured.lock().expect("lock").clone();
        assert_eq!(
            emitted,
            vec![
                (McpLogLevel::Info, "admitted".to_owned()),
                (McpLogLevel::Warning, "also-admitted".to_owned()),
            ]
        );
    }

    #[test]
    fn catalog_change_emits_only_when_the_disabled_set_mutates() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        struct CaptureSender(Arc<Mutex<Vec<McpCatalogKind>>>);
        impl NotificationSender for CaptureSender {
            fn send_progress(&self, _progress: f64, _total: Option<f64>, _message: Option<&str>) {}
            fn send_catalog_changed(&self, kind: McpCatalogKind) {
                self.0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(kind);
            }
        }

        let ctx = McpContext::with_state(Cx::for_testing(), 1, SessionState::new())
            .with_log_sender(Arc::new(CaptureSender(Arc::clone(&captured))));
        assert!(ctx.disable_tool("admin"));
        assert!(ctx.disable_tool("admin"));
        assert!(ctx.enable_tool("admin"));
        assert!(ctx.enable_tool("admin"));
        assert!(ctx.disable_resource("file://secret"));
        assert!(ctx.disable_prompt("hidden"));
        assert_eq!(
            *captured.lock().expect("lock"),
            vec![
                McpCatalogKind::Tools,
                McpCatalogKind::Tools,
                McpCatalogKind::Resources,
                McpCatalogKind::Prompts,
            ]
        );
    }

    #[test]
    fn catalog_publisher_receives_mutations_even_without_a_session_sender() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        struct CapturePublisher(Arc<Mutex<Vec<McpCatalogKind>>>);
        impl CatalogChangePublisher for CapturePublisher {
            fn publish_catalog_changed(&self, kind: McpCatalogKind) -> bool {
                self.0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(kind);
                true
            }
            fn publish_resource_updated(&self, _uri: &str) -> bool {
                false
            }
        }

        let ctx = McpContext::with_state(Cx::for_testing(), 1, SessionState::new())
            .with_catalog_publisher(Arc::new(CapturePublisher(Arc::clone(&captured))));
        assert!(ctx.disable_tool("admin"));
        assert!(ctx.disable_tool("admin"));
        assert_eq!(*captured.lock().expect("lock"), vec![McpCatalogKind::Tools]);
    }

    #[test]
    fn notify_resource_updated_requires_a_live_subscription() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        struct CaptureSender(Arc<Mutex<Vec<String>>>);
        impl NotificationSender for CaptureSender {
            fn send_progress(&self, _progress: f64, _total: Option<f64>, _message: Option<&str>) {}
            fn send_resource_updated(&self, uri: &str) {
                self.0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(uri.to_owned());
            }
        }

        let ctx = McpContext::new(Cx::for_testing(), 1)
            .with_log_sender(Arc::new(CaptureSender(Arc::clone(&captured))))
            .with_resource_subscriptions(["file:///watched.txt"]);
        assert!(!ctx.notify_resource_updated("file:///other.txt"));
        assert!(ctx.notify_resource_updated("file:///watched.txt"));
        assert_eq!(
            *captured.lock().expect("lock"),
            vec!["file:///watched.txt".to_owned()]
        );
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
    fn progress_reporter_builder_preserves_request_accounting_domain() {
        let ctx = McpContext::new(Cx::for_testing(), 1)
            .with_budget_ceiling(Budget::new().with_cost_quota(5));
        let reporter = ProgressReporter::new(Arc::new(NoOpNotificationSender));
        let derived = ctx.clone().with_progress_reporter(reporter);

        assert!(derived.has_progress_reporter());
        assert!(!ctx.has_progress_reporter());
        assert!(ctx.consume_cost(3).is_ok());
        assert_eq!(derived.budget().cost_quota, Some(2));
    }

    #[test]
    fn isolated_auth_stages_identity_without_handler_capabilities() {
        let root = McpContext::with_state(Cx::for_testing(), 1, SessionState::new())
            .with_budget_ceiling(Budget::new().with_cost_quota(2))
            .with_sampling(Arc::new(NoOpSamplingSender))
            .with_elicitation(Arc::new(NoOpElicitationSender))
            .with_roots_provider(Arc::new(FixedRootsProvider));
        let staged = root.clone().with_isolated_auth();

        assert!(staged.auth().is_none());
        assert!(!staged.has_session_state());
        assert!(!staged.can_sample());
        assert!(!staged.can_elicit());
        assert!(!staged.can_list_roots());
        assert!(!staged.can_read_resources());
        assert!(!staged.can_call_tools());
        assert!(staged.set_auth(AuthContext::with_subject("tentative")));
        assert_eq!(
            staged.auth().and_then(|auth| auth.subject),
            Some("tentative".to_string())
        );
        assert_eq!(root.auth().and_then(|auth| auth.subject), None);

        assert!(root.set_auth(AuthContext::with_subject("committed")));
        let attempted_reisolation = root.clone().with_isolated_auth();
        assert_eq!(
            attempted_reisolation.auth().and_then(|auth| auth.subject),
            Some("committed".to_string())
        );

        assert!(staged.consume_cost(1).is_ok());
        assert_eq!(root.budget().cost_quota, Some(1));
    }

    #[test]
    fn committed_anonymous_auth_is_hidden_and_write_once() {
        let ctx = McpContext::with_state(Cx::for_testing(), 1, SessionState::new());

        assert!(ctx.commit_anonymous_auth());
        assert!(ctx.auth().is_none());
        assert!(matches!(ctx.cache_auth_partition(), Some(None)));
        assert!(!ctx.set_auth(AuthContext::with_subject("forged")));
        assert!(!ctx.commit_anonymous_auth());

        let clone = ctx.clone();
        assert!(clone.auth().is_none());
        assert!(matches!(clone.cache_auth_partition(), Some(None)));
    }

    #[test]
    fn authenticated_cache_partition_contains_committed_facts() {
        let ctx = McpContext::new(Cx::for_testing(), 1);
        assert!(ctx.set_auth(AuthContext::with_subject("alice")));

        let Some(Some(auth)) = ctx.cache_auth_partition() else {
            panic!("authenticated admission must expose cache partition facts");
        };
        assert_eq!(auth.subject.as_deref(), Some("alice"));
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
    fn request_local_cancellation_suppresses_subsequent_progress() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingSender {
            count: AtomicU32,
        }

        impl NotificationSender for CountingSender {
            fn send_progress(&self, _progress: f64, _total: Option<f64>, _message: Option<&str>) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        let sender = Arc::new(CountingSender {
            count: AtomicU32::new(0),
        });
        let cancellation = McpRequestCancellation::new();
        let ctx =
            McpContext::with_progress(Cx::for_testing(), 1, ProgressReporter::new(sender.clone()))
                .with_request_cancellation(cancellation.clone());

        ctx.report_progress(0.25, Some("before cancellation"));
        assert!(cancellation.cancel());
        ctx.report_progress(0.5, Some("after cancellation"));

        assert_eq!(sender.count.load(Ordering::SeqCst), 1);
        assert!(!ctx.has_progress_reporter());
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
    fn cache_admission_fails_if_session_state_changes_before_completion() {
        let state = SessionState::new();
        let ctx = McpContext::with_state(Cx::for_testing(), 1, state.clone());
        let admitted = ctx
            .begin_session_cache_partition()
            .expect("test platform must provide cache-partition entropy");
        assert_eq!(ctx.complete_session_cache_partition(), Some(admitted));

        assert!(state.set("changed", true));
        assert!(ctx.complete_session_cache_partition().is_none());
        assert!(ctx.begin_session_cache_partition().is_none());
    }

    #[test]
    fn response_cache_hit_markers_are_middleware_specific() {
        let ctx = McpContext::new(Cx::for_testing(), 1);
        assert!(ctx.mark_response_cache_hit(10));
        assert!(ctx.response_was_cache_hit(10));
        assert!(!ctx.response_was_cache_hit(11));
        assert!(!ctx.mark_response_cache_hit(0));
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

    #[test]
    fn test_mcp_context_auth_is_request_local() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let ctx = McpContext::with_state(cx, 1, state.clone());

        assert!(ctx.set_auth(AuthContext::with_subject("alice")));

        assert_eq!(
            ctx.auth().and_then(|auth| auth.subject),
            Some("alice".to_string())
        );
        assert!(
            state.is_empty(),
            "request auth must not be persisted into session state"
        );
    }

    #[test]
    fn test_mcp_context_clones_share_request_auth() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let cloned = ctx.clone();

        assert!(cloned.set_auth(AuthContext::with_subject("bob")));

        assert_eq!(
            ctx.auth().and_then(|auth| auth.subject),
            Some("bob".to_string())
        );
    }

    #[test]
    fn committed_request_auth_is_write_once_across_clones() {
        let ctx =
            McpContext::new(Cx::for_testing(), 1).with_auth(AuthContext::with_subject("verified"));
        let clone = ctx.clone();

        assert!(!clone.set_auth(AuthContext::with_subject("replacement")));
        assert_eq!(
            ctx.auth().and_then(|auth| auth.subject),
            Some("verified".to_string())
        );
    }

    #[test]
    fn test_new_mcp_contexts_do_not_share_request_auth_even_with_same_cx() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let first = McpContext::with_state(cx.clone(), 7, state.clone());
        let second = McpContext::with_state(cx, 7, state);

        assert!(first.set_auth(AuthContext::with_subject("carol")));

        assert!(second.auth().is_none());
    }

    #[test]
    fn test_new_mcp_contexts_do_not_share_request_auth_across_requests() {
        let state = SessionState::new();
        let first = McpContext::with_state(Cx::for_testing(), 7, state.clone());
        let second = McpContext::with_state(Cx::for_testing(), 8, state);

        assert!(first.set_auth(AuthContext::with_subject("dave")));

        assert_eq!(
            first.auth().and_then(|auth| auth.subject),
            Some("dave".to_string())
        );
        assert!(second.auth().is_none());
    }

    #[test]
    fn test_mcp_context_drop_does_not_leak_request_auth() {
        let cx = Cx::for_testing();

        {
            let ctx = McpContext::new(cx.clone(), 9);
            assert!(ctx.set_auth(AuthContext::with_subject("erin")));
        }

        assert!(
            McpContext::new(cx, 9).auth().is_none(),
            "fresh contexts must start without inherited request auth"
        );
    }

    // ========================================================================
    // Dynamic Enable/Disable Tests
    // ========================================================================

    #[test]
    fn test_mcp_context_tools_enabled_by_default() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let ctx = McpContext::with_state(cx, 1, state);

        assert!(ctx.is_tool_enabled("any_tool"));
        assert!(ctx.is_tool_enabled("another_tool"));
    }

    #[test]
    fn test_mcp_context_disable_enable_tool() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let ctx = McpContext::with_state(cx, 1, state);

        // Tool is enabled by default
        assert!(ctx.is_tool_enabled("my_tool"));

        // Disable the tool
        assert!(ctx.disable_tool("my_tool"));
        assert!(!ctx.is_tool_enabled("my_tool"));
        assert!(ctx.is_tool_enabled("other_tool"));

        // Re-enable the tool
        assert!(ctx.enable_tool("my_tool"));
        assert!(ctx.is_tool_enabled("my_tool"));
    }

    #[test]
    fn test_mcp_context_disable_enable_resource() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let ctx = McpContext::with_state(cx, 1, state);

        // Resource is enabled by default
        assert!(ctx.is_resource_enabled("file://secret"));

        // Disable the resource
        assert!(ctx.disable_resource("file://secret"));
        assert!(!ctx.is_resource_enabled("file://secret"));
        assert!(ctx.is_resource_enabled("file://public"));

        // Re-enable the resource
        assert!(ctx.enable_resource("file://secret"));
        assert!(ctx.is_resource_enabled("file://secret"));
    }

    #[test]
    fn test_mcp_context_disable_enable_prompt() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let ctx = McpContext::with_state(cx, 1, state);

        // Prompt is enabled by default
        assert!(ctx.is_prompt_enabled("admin_prompt"));

        // Disable the prompt
        assert!(ctx.disable_prompt("admin_prompt"));
        assert!(!ctx.is_prompt_enabled("admin_prompt"));
        assert!(ctx.is_prompt_enabled("user_prompt"));

        // Re-enable the prompt
        assert!(ctx.enable_prompt("admin_prompt"));
        assert!(ctx.is_prompt_enabled("admin_prompt"));
    }

    #[test]
    fn test_mcp_context_disable_multiple_tools() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let ctx = McpContext::with_state(cx, 1, state);

        ctx.disable_tool("tool1");
        ctx.disable_tool("tool2");
        ctx.disable_tool("tool3");

        assert!(!ctx.is_tool_enabled("tool1"));
        assert!(!ctx.is_tool_enabled("tool2"));
        assert!(!ctx.is_tool_enabled("tool3"));
        assert!(ctx.is_tool_enabled("tool4"));

        let disabled = ctx.disabled_tools();
        assert_eq!(disabled.len(), 3);
        assert!(disabled.contains("tool1"));
        assert!(disabled.contains("tool2"));
        assert!(disabled.contains("tool3"));
    }

    #[test]
    fn test_mcp_context_disabled_sets_empty_by_default() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let ctx = McpContext::with_state(cx, 1, state);

        assert!(ctx.disabled_tools().is_empty());
        assert!(ctx.disabled_resources().is_empty());
        assert!(ctx.disabled_prompts().is_empty());
    }

    #[test]
    fn test_mcp_context_enable_disable_no_state() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);

        // Without session state, disable returns false
        assert!(!ctx.disable_tool("tool"));
        assert!(!ctx.enable_tool("tool"));

        // But is_enabled returns true (default is enabled)
        assert!(ctx.is_tool_enabled("tool"));
    }

    #[test]
    fn test_mcp_context_disabled_state_persists_across_contexts() {
        let state = SessionState::new();

        // First context disables a tool
        {
            let cx = Cx::for_testing();
            let ctx = McpContext::with_state(cx, 1, state.clone());
            ctx.disable_tool("shared_tool");
        }

        // Second context (same session state) sees the disabled tool
        {
            let cx = Cx::for_testing();
            let ctx = McpContext::with_state(cx, 2, state.clone());
            assert!(!ctx.is_tool_enabled("shared_tool"));
        }
    }

    // ========================================================================
    // Capabilities Tests
    // ========================================================================

    #[test]
    fn test_mcp_context_no_capabilities_by_default() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);

        assert!(ctx.client_capabilities().is_none());
        assert!(ctx.server_capabilities().is_none());
        assert!(!ctx.client_supports_sampling());
        assert!(!ctx.client_supports_elicitation());
        assert!(!ctx.client_supports_roots());
    }

    #[test]
    fn test_mcp_context_with_client_capabilities() {
        let cx = Cx::for_testing();
        let caps = ClientCapabilityInfo::new()
            .with_sampling()
            .with_elicitation(true, false)
            .with_roots(true);

        let ctx = McpContext::new(cx, 1).with_client_capabilities(caps);

        assert!(ctx.client_capabilities().is_some());
        assert!(ctx.client_supports_sampling());
        assert!(ctx.client_supports_elicitation());
        assert!(ctx.client_supports_elicitation_form());
        assert!(!ctx.client_supports_elicitation_url());
        assert!(ctx.client_supports_roots());
    }

    #[test]
    fn test_mcp_context_with_client_implementation() {
        let cx = Cx::for_testing();
        let mut identity = ClientImplementationInfo::new("e2e-client", "1.0.0");
        identity.title = Some("Client Title".to_owned());
        let ctx = McpContext::new(cx, 1).with_client_implementation(identity);
        let observed = ctx
            .client_implementation()
            .expect("the attached identity must be retained");
        assert_eq!(observed.name, "e2e-client");
        assert_eq!(observed.title.as_deref(), Some("Client Title"));
        assert!(observed.has_extras());
        let bare = McpContext::new(Cx::for_testing(), 2);
        assert!(bare.client_implementation().is_none());
    }

    #[test]
    fn test_mcp_context_with_server_capabilities() {
        let cx = Cx::for_testing();
        let caps = ServerCapabilityInfo::new()
            .with_tools()
            .with_resources(true)
            .with_prompts()
            .with_logging();

        let ctx = McpContext::new(cx, 1).with_server_capabilities(caps);

        let server_caps = ctx.server_capabilities().unwrap();
        assert!(server_caps.tools);
        assert!(server_caps.resources);
        assert!(server_caps.resources_subscribe);
        assert!(server_caps.prompts);
        assert!(server_caps.logging);
    }

    #[test]
    fn test_client_capability_info_builders() {
        let caps = ClientCapabilityInfo::new();
        assert!(!caps.sampling);
        assert!(!caps.elicitation);
        assert!(!caps.roots);

        let caps = caps.with_sampling();
        assert!(caps.sampling);

        let caps = ClientCapabilityInfo::new().with_elicitation(true, true);
        assert!(caps.elicitation);
        assert!(caps.elicitation_form);
        assert!(caps.elicitation_url);

        let caps = ClientCapabilityInfo::new().with_roots(false);
        assert!(caps.roots);
        assert!(!caps.roots_list_changed);
    }

    #[test]
    fn test_server_capability_info_builders() {
        let caps = ServerCapabilityInfo::new();
        assert!(!caps.tools);
        assert!(!caps.resources);
        assert!(!caps.prompts);
        assert!(!caps.logging);

        let caps = caps
            .with_tools()
            .with_resources(false)
            .with_prompts()
            .with_logging();
        assert!(caps.tools);
        assert!(caps.resources);
        assert!(!caps.resources_subscribe);
        assert!(caps.prompts);
        assert!(caps.logging);
    }

    // ========================================================================
    // ResourceContentItem Tests
    // ========================================================================

    #[test]
    fn test_resource_content_item_text() {
        let item = ResourceContentItem::text("test://uri", "hello");
        assert_eq!(item.uri, "test://uri");
        assert_eq!(item.mime_type.as_deref(), Some("text/plain"));
        assert_eq!(item.as_text(), Some("hello"));
        assert!(item.as_blob().is_none());
        assert!(item.is_text());
        assert!(!item.is_blob());
    }

    #[test]
    fn test_resource_content_item_json() {
        let item = ResourceContentItem::json("data://config", r#"{"key":"val"}"#);
        assert_eq!(item.uri, "data://config");
        assert_eq!(item.mime_type.as_deref(), Some("application/json"));
        assert_eq!(item.as_text(), Some(r#"{"key":"val"}"#));
        assert!(item.is_text());
        assert!(!item.is_blob());
    }

    #[test]
    fn test_resource_content_item_blob() {
        let item = ResourceContentItem::blob("binary://data", "application/octet-stream", "AQID");
        assert_eq!(item.uri, "binary://data");
        assert_eq!(item.mime_type.as_deref(), Some("application/octet-stream"));
        assert!(item.as_text().is_none());
        assert_eq!(item.as_blob(), Some("AQID"));
        assert!(!item.is_text());
        assert!(item.is_blob());
    }

    // ========================================================================
    // ResourceReadResult Tests
    // ========================================================================

    #[test]
    fn test_resource_read_result_text() {
        let result = ResourceReadResult::text("test://doc", "content");
        assert_eq!(result.first_text(), Some("content"));
        assert!(result.first_blob().is_none());
        assert_eq!(result.contents.len(), 1);
    }

    #[test]
    fn test_resource_read_result_new_multiple() {
        let result = ResourceReadResult::new(vec![
            ResourceContentItem::text("a://1", "first"),
            ResourceContentItem::blob("b://2", "image/png", "base64data"),
        ]);
        assert_eq!(result.contents.len(), 2);
        // first_text returns the first item's text
        assert_eq!(result.first_text(), Some("first"));
        // first_blob returns None because the first item is text
        assert!(result.first_blob().is_none());
    }

    #[test]
    fn test_resource_read_result_empty() {
        let result = ResourceReadResult::new(vec![]);
        assert!(result.first_text().is_none());
        assert!(result.first_blob().is_none());
    }

    #[test]
    fn test_resource_read_result_blob_first() {
        let result = ResourceReadResult::new(vec![ResourceContentItem::blob(
            "b://1",
            "image/png",
            "data",
        )]);
        assert!(result.first_text().is_none());
        assert_eq!(result.first_blob(), Some("data"));
    }

    // ========================================================================
    // ToolContentItem Tests
    // ========================================================================

    #[test]
    fn test_tool_content_item_text() {
        let item = ToolContentItem::text("hello");
        assert_eq!(item.as_text(), Some("hello"));
        assert!(item.is_text());
    }

    #[test]
    fn test_tool_content_item_image() {
        let item = ToolContentItem::Image {
            data: "base64img".to_string(),
            mime_type: "image/png".to_string(),
        };
        assert!(item.as_text().is_none());
        assert!(!item.is_text());
    }

    #[test]
    fn test_tool_content_item_audio() {
        let item = ToolContentItem::Audio {
            data: "base64audio".to_string(),
            mime_type: "audio/wav".to_string(),
        };
        assert!(item.as_text().is_none());
        assert!(!item.is_text());
    }

    #[test]
    fn test_tool_content_item_resource() {
        let item = ToolContentItem::Resource {
            uri: "file://test".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some("embedded".to_string()),
            blob: None,
        };
        assert!(item.as_text().is_none());
        assert!(!item.is_text());
    }

    // ========================================================================
    // ToolCallResult Tests
    // ========================================================================

    #[test]
    fn test_tool_call_result_success() {
        let result = ToolCallResult::success(vec![
            ToolContentItem::text("item1"),
            ToolContentItem::text("item2"),
        ]);
        assert!(!result.is_error);
        assert_eq!(result.content.len(), 2);
        assert_eq!(result.first_text(), Some("item1"));
    }

    #[test]
    fn test_tool_call_result_text() {
        let result = ToolCallResult::text("simple output");
        assert!(!result.is_error);
        assert_eq!(result.content.len(), 1);
        assert_eq!(result.first_text(), Some("simple output"));
    }

    #[test]
    fn test_tool_call_result_error() {
        let result = ToolCallResult::error("something failed");
        assert!(result.is_error);
        assert_eq!(result.first_text(), Some("something failed"));
    }

    #[test]
    fn test_tool_call_result_empty() {
        let result = ToolCallResult::success(vec![]);
        assert!(!result.is_error);
        assert!(result.first_text().is_none());
    }

    // ========================================================================
    // ElicitationResponse Tests
    // ========================================================================

    #[test]
    fn test_elicitation_response_accept() {
        let mut data = std::collections::HashMap::new();
        data.insert("name".to_string(), serde_json::json!("Alice"));
        data.insert("age".to_string(), serde_json::json!(30));
        data.insert("active".to_string(), serde_json::json!(true));

        let resp = ElicitationResponse::accept(data);
        assert!(resp.is_accepted());
        assert!(!resp.is_declined());
        assert!(!resp.is_cancelled());
        assert_eq!(resp.get_string("name"), Some("Alice"));
        assert_eq!(resp.get_int("age"), Some(30));
        assert_eq!(resp.get_bool("active"), Some(true));
    }

    #[test]
    fn test_elicitation_response_accept_url() {
        let resp = ElicitationResponse::accept_url();
        assert!(resp.is_accepted());
        assert!(resp.content.is_none());
        assert!(resp.get_string("anything").is_none());
    }

    #[test]
    fn test_elicitation_response_decline() {
        let resp = ElicitationResponse::decline();
        assert!(!resp.is_accepted());
        assert!(resp.is_declined());
        assert!(!resp.is_cancelled());
        assert!(resp.get_string("key").is_none());
    }

    #[test]
    fn test_elicitation_response_cancel() {
        let resp = ElicitationResponse::cancel();
        assert!(!resp.is_accepted());
        assert!(!resp.is_declined());
        assert!(resp.is_cancelled());
    }

    #[test]
    fn test_elicitation_response_missing_key() {
        let mut data = std::collections::HashMap::new();
        data.insert("exists".to_string(), serde_json::json!("value"));
        let resp = ElicitationResponse::accept(data);

        assert!(resp.get_string("missing").is_none());
        assert!(resp.get_bool("missing").is_none());
        assert!(resp.get_int("missing").is_none());
    }

    #[test]
    fn test_elicitation_response_type_mismatch() {
        let mut data = std::collections::HashMap::new();
        data.insert("num".to_string(), serde_json::json!(42));
        let resp = ElicitationResponse::accept(data);

        // get_string on a number returns None
        assert!(resp.get_string("num").is_none());
        // get_bool on a number returns None
        assert!(resp.get_bool("num").is_none());
        // get_int on a number returns Some
        assert_eq!(resp.get_int("num"), Some(42));
    }

    // ========================================================================
    // Capability Check Tests (can_sample, can_elicit, etc.)
    // ========================================================================

    #[test]
    fn test_can_sample_false_by_default() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        assert!(!ctx.can_sample());
    }

    #[test]
    fn test_can_elicit_false_by_default() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        assert!(!ctx.can_elicit());
    }

    #[test]
    fn test_can_read_resources_false_by_default() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        assert!(!ctx.can_read_resources());
    }

    #[test]
    fn test_can_call_tools_false_by_default() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        assert!(!ctx.can_call_tools());
    }

    #[test]
    fn test_resource_read_depth_default() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        assert_eq!(ctx.resource_read_depth(), 0);
    }

    #[test]
    fn test_tool_call_depth_default() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        assert_eq!(ctx.tool_call_depth(), 0);
    }

    // ========================================================================
    // Additional coverage tests (bd-3fcm)
    // ========================================================================

    #[test]
    fn sampling_request_builder_chain() {
        let req = SamplingRequest::prompt("hello", 100)
            .with_system_prompt("You are helpful")
            .with_temperature(0.7)
            .with_stop_sequences(vec!["STOP".into()])
            .with_model_hints(vec!["gpt-4".into()]);

        assert_eq!(req.messages.len(), 1);
        assert_eq!(req.max_tokens, 100);
        assert_eq!(req.system_prompt.as_deref(), Some("You are helpful"));
        assert_eq!(req.temperature, Some(0.7));
        assert_eq!(req.stop_sequences, vec!["STOP"]);
        assert_eq!(req.model_hints, vec!["gpt-4"]);
    }

    #[test]
    fn sampling_request_message_roles() {
        let user = SamplingRequestMessage::user("hi");
        assert_eq!(user.role, SamplingRole::User);
        assert_eq!(user.text, "hi");

        let asst = SamplingRequestMessage::assistant("hello");
        assert_eq!(asst.role, SamplingRole::Assistant);
        assert_eq!(asst.text, "hello");
    }

    #[test]
    fn sampling_response_new_default_stop_reason() {
        let resp = SamplingResponse::new("output", "model-1");
        assert_eq!(resp.text, "output");
        assert_eq!(resp.model, "model-1");
        assert_eq!(resp.stop_reason, SamplingStopReason::EndTurn);
        assert_eq!(SamplingStopReason::default(), SamplingStopReason::EndTurn);
    }

    #[test]
    fn sampling_stop_reason_round_trips_optional_open_wire_values() {
        let absent = SamplingStopReason::from_wire_value(None);
        assert_eq!(absent, SamplingStopReason::Unspecified);
        assert_eq!(absent.as_wire_value(), None);

        let provider =
            SamplingStopReason::from_wire_value(Some("provider_safety_limit".to_owned()));
        assert_eq!(
            provider,
            SamplingStopReason::Other("provider_safety_limit".to_owned())
        );
        assert_eq!(provider.as_wire_value(), Some("provider_safety_limit"));
    }

    #[test]
    fn noop_sampling_sender_returns_error() {
        let sender = NoOpSamplingSender;
        let req = SamplingRequest::prompt("test", 10);
        let result = crate::block_on(sender.create_message(req));
        assert!(result.is_err());
    }

    #[test]
    fn noop_elicitation_sender_returns_error() {
        let sender = NoOpElicitationSender;
        let req = ElicitationRequest::form("msg", serde_json::json!({}));
        let result = crate::block_on(sender.elicit(req));
        assert!(result.is_err());
    }

    #[test]
    fn elicitation_request_form_constructor() {
        let req = ElicitationRequest::form("Enter name", serde_json::json!({"type": "string"}));
        assert_eq!(req.mode, ElicitationMode::Form);
        assert_eq!(req.message, "Enter name");
        assert!(req.schema.is_some());
        assert!(req.url.is_none());
        assert!(req.elicitation_id.is_none());
    }

    #[test]
    fn elicitation_request_url_constructor() {
        let req = ElicitationRequest::url("Login", "https://example.com", "id-1");
        assert_eq!(req.mode, ElicitationMode::Url);
        assert_eq!(req.message, "Login");
        assert_eq!(req.url.as_deref(), Some("https://example.com"));
        assert_eq!(req.elicitation_id.as_deref(), Some("id-1"));
        assert!(req.schema.is_none());
    }

    #[test]
    fn mcp_context_with_sampling_enables_can_sample() {
        let cx = Cx::for_testing();
        let sender = Arc::new(NoOpSamplingSender);
        let ctx = McpContext::new(cx, 1).with_sampling(sender);
        assert!(ctx.can_sample());
    }

    #[test]
    fn mcp_context_with_elicitation_enables_can_elicit() {
        let cx = Cx::for_testing();
        let sender = Arc::new(NoOpElicitationSender);
        let ctx = McpContext::new(cx, 1).with_elicitation(sender);
        assert!(ctx.can_elicit());
    }

    struct FixedRootsProvider;

    impl RootsProvider for FixedRootsProvider {
        fn list_roots(
            &self,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = crate::McpResult<Vec<ClientRoot>>> + Send + '_>,
        > {
            Box::pin(async {
                Ok(vec![
                    ClientRoot::with_name("file:///workspace", "workspace"),
                    ClientRoot::new("file:///tmp"),
                ])
            })
        }
    }

    #[test]
    fn mcp_context_roots_provider_returns_client_roots() {
        let ctx =
            McpContext::new(Cx::for_testing(), 1).with_roots_provider(Arc::new(FixedRootsProvider));

        assert!(ctx.can_list_roots());
        let roots = crate::block_on(ctx.list_roots()).expect("configured roots provider succeeds");
        assert_eq!(
            roots,
            vec![
                ClientRoot::with_name("file:///workspace", "workspace"),
                ClientRoot::new("file:///tmp"),
            ]
        );
    }

    #[test]
    fn mcp_context_without_roots_provider_rejects_without_authority() {
        let ctx = McpContext::new(Cx::for_testing(), 1);

        assert!(!ctx.can_list_roots());
        let error = crate::block_on(ctx.list_roots())
            .expect_err("without only the roots provider, the context must reject the request");
        assert_eq!(error.code, crate::McpErrorCode::InvalidRequest);
        assert_eq!(
            error.message,
            "Roots not available: client does not support roots capability"
        );
    }

    #[test]
    fn mcp_context_depth_setters() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1)
            .with_resource_read_depth(3)
            .with_tool_call_depth(5);
        assert_eq!(ctx.resource_read_depth(), 3);
        assert_eq!(ctx.tool_call_depth(), 5);

        let attempted_reset = ctx.with_resource_read_depth(0).with_tool_call_depth(0);
        assert_eq!(attempted_reset.resource_read_depth(), 3);
        assert_eq!(attempted_reset.tool_call_depth(), 5);
    }

    #[test]
    fn mcp_context_debug_includes_request_id() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 99);
        let debug = format!("{ctx:?}");
        assert!(debug.contains("request_id: 99"));
    }

    #[test]
    fn mcp_context_cx_and_trace() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        // cx() should return a reference without panic
        let _ = ctx.cx();
        // trace() should not panic
        ctx.trace("test event");
    }

    #[test]
    fn final_result_outcome_preserves_dual_era_and_terminal_reason() {
        use crate::combinator::{DualEraFinalResult, FinalRequestResult};

        let context = McpContext::new(Cx::for_testing(), 1);
        let modern = context.final_result_outcome(
            FinalRequestResult::<u64, String, &'static str>::modern("typed-final", 42),
        );
        let legacy =
            context.final_result_outcome(FinalRequestResult::<u64, String, &'static str>::legacy(
                "legacy-final",
                "legacy wire result".to_owned(),
            ));

        let Outcome::Ok(modern) = modern else {
            panic!("live context admits the modern final result");
        };
        assert_eq!(modern.terminal_reason(), &"typed-final");
        assert_eq!(modern.result(), &DualEraFinalResult::Modern(42));

        let Outcome::Ok(legacy) = legacy else {
            panic!("live context admits the legacy final result");
        };
        assert_eq!(legacy.terminal_reason(), &"legacy-final");
        assert_eq!(
            legacy.result(),
            &DualEraFinalResult::Legacy("legacy wire result".to_owned())
        );
    }

    #[test]
    fn final_result_outcome_cancellation_negative_preserves_cx_reason() {
        use crate::combinator::FinalRequestResult;
        use asupersync::types::CancelKind;

        let cx = Cx::for_testing();
        cx.cancel_with(CancelKind::Timeout, Some("final-result race"));
        let expected_reason = cx
            .cancel_reason()
            .expect("cancel_with records the caller-owned terminal reason");
        let context = McpContext::new(cx, 1);

        let outcome = context.final_result_outcome(
            FinalRequestResult::<u64, String, &'static str>::modern("typed-final", 42),
        );

        let Outcome::Cancelled(reason) = outcome else {
            panic!("changing only caller cancellation rejects the same final result");
        };
        assert_eq!(reason, expected_reason);
    }

    #[test]
    fn final_result_outcome_panic_negative_preserves_payload() {
        use crate::combinator::FinalRequestResult;
        use asupersync::types::{CancelKind, PanicPayload};

        type Final = FinalRequestResult<u64, String, &'static str>;

        let cx = Cx::for_testing();
        cx.cancel_with(CancelKind::Timeout, Some("competing terminal state"));
        let context = McpContext::new(cx, 1);
        let payload = PanicPayload::new("final typed result panicked");
        let source: crate::McpOutcome<Final> = Outcome::Panicked(payload.clone());

        let outcome = context.adapt_final_request_outcome(source);

        let Outcome::Panicked(actual) = outcome else {
            panic!("changing only the source terminal state to panic preserves panic");
        };
        assert_eq!(actual, payload);
    }
}
