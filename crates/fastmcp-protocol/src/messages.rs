//! MCP protocol messages.
//!
//! Request and response types for all MCP methods.

use serde::{Deserialize, Serialize};

use crate::jsonrpc::RequestId;
use crate::types::{
    ClientCapabilities, ClientInfo, Content, Prompt, PromptMessage, Resource, ResourceContent,
    ResourceTemplate, ServerCapabilities, ServerInfo, Tool,
};

// ============================================================================
// Progress Token
// ============================================================================

/// Progress token used to correlate progress notifications with requests.
///
/// Per MCP spec, progress tokens can be either strings or integers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProgressToken {
    /// String progress token.
    String(String),
    /// Integer progress token.
    Number(i64),
}

impl From<String> for ProgressToken {
    fn from(s: String) -> Self {
        ProgressToken::String(s)
    }
}

impl From<&str> for ProgressToken {
    fn from(s: &str) -> Self {
        ProgressToken::String(s.to_owned())
    }
}

impl From<i64> for ProgressToken {
    fn from(n: i64) -> Self {
        ProgressToken::Number(n)
    }
}

impl std::fmt::Display for ProgressToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProgressToken::String(s) => write!(f, "{s}"),
            ProgressToken::Number(n) => write!(f, "{n}"),
        }
    }
}

/// Request metadata containing optional progress token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestMeta {
    /// Progress token for receiving progress notifications.
    #[serde(rename = "progressToken", skip_serializing_if = "Option::is_none")]
    pub progress_token: Option<ProgressToken>,
}

// ============================================================================
// Initialize
// ============================================================================

/// Initialize request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeParams {
    /// Protocol version requested.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Client capabilities.
    pub capabilities: ClientCapabilities,
    /// Client info.
    #[serde(rename = "clientInfo")]
    pub client_info: ClientInfo,
}

/// Initialize response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    /// Protocol version accepted.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Server capabilities.
    pub capabilities: ServerCapabilities,
    /// Server info.
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
    /// Optional instructions for the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

// ============================================================================
// Tools
// ============================================================================

/// tools/list request params.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListToolsParams {
    /// Cursor for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Only include tools with ALL of these tags (AND logic).
    #[serde(
        rename = "includeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_tags: Option<Vec<String>>,
    /// Exclude tools with ANY of these tags (OR logic).
    #[serde(
        rename = "excludeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_tags: Option<Vec<String>>,
}

/// tools/list response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListToolsResult {
    /// List of available tools.
    pub tools: Vec<Tool>,
    /// Next cursor for pagination.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// tools/call request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolParams {
    /// Tool name to call.
    pub name: String,
    /// Tool arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<serde_json::Value>,
    /// Request metadata (progress token, etc.).
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<RequestMeta>,
}

/// tools/call response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolResult {
    /// Tool output content.
    pub content: Vec<Content>,
    /// Whether the tool call errored.
    #[serde(
        rename = "isError",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub is_error: bool,
}

// ============================================================================
// Resources
// ============================================================================

/// resources/list request params.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListResourcesParams {
    /// Cursor for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Only include resources with ALL of these tags (AND logic).
    #[serde(
        rename = "includeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_tags: Option<Vec<String>>,
    /// Exclude resources with ANY of these tags (OR logic).
    #[serde(
        rename = "excludeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_tags: Option<Vec<String>>,
}

/// resources/list response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResourcesResult {
    /// List of available resources.
    pub resources: Vec<Resource>,
    /// Next cursor for pagination.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// resources/templates/list request params.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListResourceTemplatesParams {
    /// Cursor for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Only include templates with ALL of these tags (AND logic).
    #[serde(
        rename = "includeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_tags: Option<Vec<String>>,
    /// Exclude templates with ANY of these tags (OR logic).
    #[serde(
        rename = "excludeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_tags: Option<Vec<String>>,
}

/// resources/templates/list response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResourceTemplatesResult {
    /// List of resource templates.
    #[serde(rename = "resourceTemplates")]
    pub resource_templates: Vec<ResourceTemplate>,
}

/// resources/read request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResourceParams {
    /// Resource URI to read.
    pub uri: String,
    /// Request metadata (progress token, etc.).
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<RequestMeta>,
}

/// resources/read response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResourceResult {
    /// Resource contents.
    pub contents: Vec<ResourceContent>,
}

/// resources/subscribe request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeResourceParams {
    /// Resource URI to subscribe to.
    pub uri: String,
}

/// resources/unsubscribe request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsubscribeResourceParams {
    /// Resource URI to unsubscribe from.
    pub uri: String,
}

// ============================================================================
// Prompts
// ============================================================================

/// prompts/list request params.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListPromptsParams {
    /// Cursor for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Only include prompts with ALL of these tags (AND logic).
    #[serde(
        rename = "includeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_tags: Option<Vec<String>>,
    /// Exclude prompts with ANY of these tags (OR logic).
    #[serde(
        rename = "excludeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_tags: Option<Vec<String>>,
}

/// prompts/list response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListPromptsResult {
    /// List of available prompts.
    pub prompts: Vec<Prompt>,
    /// Next cursor for pagination.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// prompts/get request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPromptParams {
    /// Prompt name.
    pub name: String,
    /// Prompt arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<std::collections::HashMap<String, String>>,
    /// Request metadata (progress token, etc.).
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<RequestMeta>,
}

/// prompts/get response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPromptResult {
    /// Optional prompt description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Prompt messages.
    pub messages: Vec<PromptMessage>,
}

// ============================================================================
// Logging
// ============================================================================

/// Log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Debug level.
    Debug,
    /// Info level.
    Info,
    /// Warning level.
    Warning,
    /// Error level.
    Error,
}

/// logging/setLevel request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetLogLevelParams {
    /// The log level to set.
    pub level: LogLevel,
}

// ============================================================================
// Notifications
// ============================================================================

/// Cancelled notification params.
///
/// Sent by either party to request cancellation of an in-progress request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelledParams {
    /// The ID of the request to cancel.
    #[serde(rename = "requestId")]
    pub request_id: RequestId,
    /// Optional reason for cancellation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether the sender wants to await cleanup completion.
    #[serde(rename = "awaitCleanup", skip_serializing_if = "Option::is_none")]
    pub await_cleanup: Option<bool>,
}

/// Progress notification params.
///
/// Sent from server to client to report progress on a long-running operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressParams {
    /// Progress token (from original request's `_meta.progressToken`).
    #[serde(rename = "progressToken")]
    pub progress_token: ProgressToken,
    /// Progress value (0.0 to 1.0, or absolute values for indeterminate progress).
    pub progress: f64,
    /// Total expected progress (optional, for determinate progress).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    /// Optional progress message describing current status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ProgressParams {
    /// Creates a new progress notification.
    #[must_use]
    pub fn new(token: impl Into<ProgressToken>, progress: f64) -> Self {
        Self {
            progress_token: token.into(),
            progress,
            total: None,
            message: None,
        }
    }

    /// Creates a progress notification with total (determinate progress).
    #[must_use]
    pub fn with_total(token: impl Into<ProgressToken>, progress: f64, total: f64) -> Self {
        Self {
            progress_token: token.into(),
            progress,
            total: Some(total),
            message: None,
        }
    }

    /// Adds a message to the progress notification.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Returns the progress as a fraction (0.0 to 1.0) if total is known.
    #[must_use]
    pub fn fraction(&self) -> Option<f64> {
        self.total
            .map(|t| if t > 0.0 { self.progress / t } else { 0.0 })
    }
}

/// Resource updated notification params.
///
/// Sent from server to client when a subscribed resource changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUpdatedNotificationParams {
    /// Updated resource URI.
    pub uri: String,
}

/// Log message notification params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMessageParams {
    /// Log level.
    pub level: LogLevel,
    /// Logger name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logger: Option<String>,
    /// Log message data.
    pub data: serde_json::Value,
}

// ============================================================================
// Background Tasks (Docket/SEP-1686)
// ============================================================================

use crate::types::{TaskId, TaskInfo, TaskResult, TaskStatus};

/// tasks/list request params.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListTasksParams {
    /// Cursor for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Filter by task status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<TaskStatus>,
}

/// tasks/list response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListTasksResult {
    /// List of tasks.
    pub tasks: Vec<TaskInfo>,
    /// Next cursor for pagination.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// tasks/get request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTaskParams {
    /// Task ID to retrieve.
    pub id: TaskId,
}

/// tasks/get response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTaskResult {
    /// Task information.
    pub task: TaskInfo,
    /// Task result (if completed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<TaskResult>,
}

/// tasks/cancel request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelTaskParams {
    /// Task ID to cancel.
    pub id: TaskId,
    /// Reason for cancellation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// tasks/cancel response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelTaskResult {
    /// Whether the cancellation was successful.
    pub cancelled: bool,
    /// Updated task information.
    pub task: TaskInfo,
}

/// tasks/submit request params.
///
/// Used to submit a new background task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTaskParams {
    /// Task type identifier.
    #[serde(rename = "taskType")]
    pub task_type: String,
    /// Task parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// tasks/submit response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTaskResult {
    /// Created task information.
    pub task: TaskInfo,
}

/// Task status change notification params.
///
/// Sent from server to client when a task status changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStatusNotificationParams {
    /// Task ID.
    pub id: TaskId,
    /// New task status.
    pub status: TaskStatus,
    /// Progress (0.0 to 1.0, if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<f64>,
    /// Progress message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Error message (if failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Task result (if completed successfully).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<TaskResult>,
}

// ============================================================================
// Sampling (Server-to-Client LLM requests)
// ============================================================================

use crate::types::{ModelPreferences, SamplingContent, SamplingMessage, StopReason};

/// sampling/createMessage request params.
///
/// Sent from server to client to request an LLM completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMessageParams {
    /// Conversation messages.
    pub messages: Vec<SamplingMessage>,
    /// Maximum tokens to generate.
    #[serde(rename = "maxTokens")]
    pub max_tokens: u32,
    /// Optional system prompt.
    #[serde(rename = "systemPrompt", skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    /// Sampling temperature (0.0 to 2.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Stop sequences to end generation.
    #[serde(
        rename = "stopSequences",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub stop_sequences: Vec<String>,
    /// Model preferences/hints.
    #[serde(rename = "modelPreferences", skip_serializing_if = "Option::is_none")]
    pub model_preferences: Option<ModelPreferences>,
    /// Include context from MCP servers.
    #[serde(rename = "includeContext", skip_serializing_if = "Option::is_none")]
    pub include_context: Option<IncludeContext>,
    /// Request metadata.
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<RequestMeta>,
}

impl CreateMessageParams {
    /// Creates a new sampling request with default settings.
    #[must_use]
    pub fn new(messages: Vec<SamplingMessage>, max_tokens: u32) -> Self {
        Self {
            messages,
            max_tokens,
            system_prompt: None,
            temperature: None,
            stop_sequences: Vec::new(),
            model_preferences: None,
            include_context: None,
            meta: None,
        }
    }

    /// Sets the system prompt.
    #[must_use]
    pub fn with_system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(prompt.into());
        self
    }

    /// Sets the sampling temperature.
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
}

/// Context inclusion mode for sampling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IncludeContext {
    /// Include no MCP context.
    None,
    /// Include context from the current server only.
    ThisServer,
    /// Include context from all connected MCP servers.
    AllServers,
}

/// sampling/createMessage response result.
///
/// Returned by the client with the LLM completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMessageResult {
    /// Generated content.
    pub content: SamplingContent,
    /// Role of the generated message (always "assistant").
    pub role: crate::types::Role,
    /// Model that was used.
    pub model: String,
    /// Reason generation stopped.
    #[serde(rename = "stopReason")]
    pub stop_reason: StopReason,
}

impl CreateMessageResult {
    /// Creates a new text completion result.
    #[must_use]
    pub fn text(text: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            content: SamplingContent::Text { text: text.into() },
            role: crate::types::Role::Assistant,
            model: model.into(),
            stop_reason: StopReason::EndTurn,
        }
    }

    /// Sets the stop reason.
    #[must_use]
    pub fn with_stop_reason(mut self, reason: StopReason) -> Self {
        self.stop_reason = reason;
        self
    }

    /// Returns the text content if this is a text response.
    #[must_use]
    pub fn text_content(&self) -> Option<&str> {
        match &self.content {
            SamplingContent::Text { text } => Some(text),
            SamplingContent::Image { .. } => None,
        }
    }
}

// ============================================================================
// Roots (Client-to-Server filesystem roots)
// ============================================================================

use crate::types::Root;

/// roots/list request params.
///
/// Sent from server to client to request the list of available filesystem roots.
/// This request has no parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListRootsParams {}

/// roots/list response result.
///
/// Returned by the client with the list of available filesystem roots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRootsResult {
    /// The list of available roots.
    pub roots: Vec<Root>,
}

impl ListRootsResult {
    /// Creates a new empty result.
    #[must_use]
    pub fn empty() -> Self {
        Self { roots: Vec::new() }
    }

    /// Creates a result with the given roots.
    #[must_use]
    pub fn new(roots: Vec<Root>) -> Self {
        Self { roots }
    }
}

/// Notification params for roots/list_changed.
///
/// Sent by the client when the list of roots changes.
/// This notification has no parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RootsListChangedNotificationParams {}

// ============================================================================
// Elicitation (Server-to-Client user input requests)
// ============================================================================

/// JSON Schema for elicitation requests.
///
/// Must be an object schema with flat properties (no nesting).
/// Only primitive types (string, number, integer, boolean) are allowed.
pub type ElicitRequestedSchema = serde_json::Value;

/// Parameters for form mode elicitation requests.
///
/// Form mode collects non-sensitive information from the user via an in-band form
/// rendered by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitRequestFormParams {
    /// The elicitation mode (always "form" for this type).
    pub mode: ElicitMode,
    /// The message to present to the user describing what information is being requested.
    pub message: String,
    /// A restricted subset of JSON Schema defining the structure of expected response.
    /// Only top-level properties are allowed, without nesting.
    #[serde(rename = "requestedSchema")]
    pub requested_schema: ElicitRequestedSchema,
}

impl ElicitRequestFormParams {
    /// Creates a new form elicitation request.
    #[must_use]
    pub fn new(message: impl Into<String>, schema: serde_json::Value) -> Self {
        Self {
            mode: ElicitMode::Form,
            message: message.into(),
            requested_schema: schema,
        }
    }
}

/// Parameters for URL mode elicitation requests.
///
/// URL mode directs users to external URLs for sensitive out-of-band interactions
/// like OAuth flows, credential collection, or payment processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitRequestUrlParams {
    /// The elicitation mode (always "url" for this type).
    pub mode: ElicitMode,
    /// The message to present to the user explaining why the interaction is needed.
    pub message: String,
    /// The URL that the user should navigate to.
    pub url: String,
    /// The ID of the elicitation, which must be unique within the context of the server.
    /// The client MUST treat this ID as an opaque value.
    #[serde(rename = "elicitationId")]
    pub elicitation_id: String,
}

impl ElicitRequestUrlParams {
    /// Creates a new URL elicitation request.
    #[must_use]
    pub fn new(
        message: impl Into<String>,
        url: impl Into<String>,
        elicitation_id: impl Into<String>,
    ) -> Self {
        Self {
            mode: ElicitMode::Url,
            message: message.into(),
            url: url.into(),
            elicitation_id: elicitation_id.into(),
        }
    }
}

/// Elicitation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElicitMode {
    /// Form mode - collect user input via in-band form.
    Form,
    /// URL mode - redirect user to external URL.
    Url,
}

/// Parameters for elicitation requests (either form or URL mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ElicitRequestParams {
    /// Form mode elicitation.
    Form(ElicitRequestFormParams),
    /// URL mode elicitation.
    Url(ElicitRequestUrlParams),
}

impl ElicitRequestParams {
    /// Creates a form mode elicitation request.
    #[must_use]
    pub fn form(message: impl Into<String>, schema: serde_json::Value) -> Self {
        Self::Form(ElicitRequestFormParams::new(message, schema))
    }

    /// Creates a URL mode elicitation request.
    #[must_use]
    pub fn url(
        message: impl Into<String>,
        url: impl Into<String>,
        elicitation_id: impl Into<String>,
    ) -> Self {
        Self::Url(ElicitRequestUrlParams::new(message, url, elicitation_id))
    }

    /// Returns the mode of this elicitation request.
    #[must_use]
    pub fn mode(&self) -> ElicitMode {
        match self {
            Self::Form(_) => ElicitMode::Form,
            Self::Url(_) => ElicitMode::Url,
        }
    }

    /// Returns the message for this elicitation request.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Form(f) => &f.message,
            Self::Url(u) => &u.message,
        }
    }
}

/// User action in response to an elicitation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElicitAction {
    /// User submitted the form/confirmed the action (or consented to URL navigation).
    Accept,
    /// User explicitly declined the action.
    Decline,
    /// User dismissed without making an explicit choice.
    Cancel,
}

/// Content type for elicitation responses.
///
/// Values can be strings, integers, floats, booleans, arrays of strings, or null.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ElicitContentValue {
    /// Null value.
    Null,
    /// Boolean value.
    Bool(bool),
    /// Integer value.
    Int(i64),
    /// Float value.
    Float(f64),
    /// String value.
    String(String),
    /// Array of strings (for multi-select).
    StringArray(Vec<String>),
}

impl From<bool> for ElicitContentValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

impl From<i64> for ElicitContentValue {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}

impl From<f64> for ElicitContentValue {
    fn from(v: f64) -> Self {
        Self::Float(v)
    }
}

impl From<String> for ElicitContentValue {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<&str> for ElicitContentValue {
    fn from(v: &str) -> Self {
        Self::String(v.to_owned())
    }
}

impl From<Vec<String>> for ElicitContentValue {
    fn from(v: Vec<String>) -> Self {
        Self::StringArray(v)
    }
}

impl<T: Into<ElicitContentValue>> From<Option<T>> for ElicitContentValue {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(v) => v.into(),
            None => Self::Null,
        }
    }
}

/// elicitation/create response result.
///
/// The client's response to an elicitation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitResult {
    /// The user action in response to the elicitation.
    pub action: ElicitAction,
    /// The submitted form data, only present when action is "accept" in form mode.
    /// Contains values matching the requested schema.
    /// For URL mode, this field is omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<std::collections::HashMap<String, ElicitContentValue>>,
}

impl ElicitResult {
    /// Creates an accept result with form data.
    #[must_use]
    pub fn accept(content: std::collections::HashMap<String, ElicitContentValue>) -> Self {
        Self {
            action: ElicitAction::Accept,
            content: Some(content),
        }
    }

    /// Creates an accept result for URL mode (no content).
    #[must_use]
    pub fn accept_url() -> Self {
        Self {
            action: ElicitAction::Accept,
            content: None,
        }
    }

    /// Creates a decline result.
    #[must_use]
    pub fn decline() -> Self {
        Self {
            action: ElicitAction::Decline,
            content: None,
        }
    }

    /// Creates a cancel result.
    #[must_use]
    pub fn cancel() -> Self {
        Self {
            action: ElicitAction::Cancel,
            content: None,
        }
    }

    /// Returns true if the user accepted the elicitation.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        matches!(self.action, ElicitAction::Accept)
    }

    /// Returns true if the user declined the elicitation.
    #[must_use]
    pub fn is_declined(&self) -> bool {
        matches!(self.action, ElicitAction::Decline)
    }

    /// Returns true if the user cancelled the elicitation.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self.action, ElicitAction::Cancel)
    }

    /// Gets a string value from the content.
    #[must_use]
    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.content.as_ref().and_then(|c| {
            c.get(key).and_then(|v| match v {
                ElicitContentValue::String(s) => Some(s.as_str()),
                _ => None,
            })
        })
    }

    /// Gets a boolean value from the content.
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.content.as_ref().and_then(|c| {
            c.get(key).and_then(|v| match v {
                ElicitContentValue::Bool(b) => Some(*b),
                _ => None,
            })
        })
    }

    /// Gets an integer value from the content.
    #[must_use]
    pub fn get_int(&self, key: &str) -> Option<i64> {
        self.content.as_ref().and_then(|c| {
            c.get(key).and_then(|v| match v {
                ElicitContentValue::Int(i) => Some(*i),
                _ => None,
            })
        })
    }
}

/// Elicitation complete notification params.
///
/// Sent from server to client when a URL mode elicitation has been completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitCompleteNotificationParams {
    /// The unique identifier of the elicitation that was completed.
    #[serde(rename = "elicitationId")]
    pub elicitation_id: String,
}

impl ElicitCompleteNotificationParams {
    /// Creates a new elicitation complete notification.
    #[must_use]
    pub fn new(elicitation_id: impl Into<String>) -> Self {
        Self {
            elicitation_id: elicitation_id.into(),
        }
    }
}

/// Error data for URL elicitation required errors.
///
/// Servers return this when a request cannot be processed until one or more
/// URL mode elicitations are completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationRequiredErrorData {
    /// List of URL mode elicitations that must be completed.
    pub elicitations: Vec<ElicitRequestUrlParams>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_resource_templates_params_serialization() {
        let params = ListResourceTemplatesParams::default();
        let value = serde_json::to_value(&params).expect("serialize params");
        assert_eq!(value, serde_json::json!({}));

        let params = ListResourceTemplatesParams {
            cursor: Some("next".to_string()),
            ..Default::default()
        };
        let value = serde_json::to_value(&params).expect("serialize params with cursor");
        assert_eq!(value, serde_json::json!({ "cursor": "next" }));
    }

    #[test]
    fn list_resource_templates_result_serialization() {
        let result = ListResourceTemplatesResult {
            resource_templates: vec![ResourceTemplate {
                uri_template: "resource://{id}".to_string(),
                name: "Resource Template".to_string(),
                description: Some("Template description".to_string()),
                mime_type: Some("text/plain".to_string()),
                icon: None,
                version: None,
                tags: vec![],
            }],
        };

        let value = serde_json::to_value(&result).expect("serialize result");
        let templates = value
            .get("resourceTemplates")
            .expect("resourceTemplates key");
        let template = templates.get(0).expect("first resource template");

        assert_eq!(template["uriTemplate"], "resource://{id}");
        assert_eq!(template["name"], "Resource Template");
        assert_eq!(template["description"], "Template description");
        assert_eq!(template["mimeType"], "text/plain");
    }

    #[test]
    fn resource_updated_notification_serialization() {
        let params = ResourceUpdatedNotificationParams {
            uri: "resource://test".to_string(),
        };
        let value = serde_json::to_value(&params).expect("serialize params");
        assert_eq!(value, serde_json::json!({ "uri": "resource://test" }));
    }

    #[test]
    fn subscribe_unsubscribe_resource_params_serialization() {
        let subscribe = SubscribeResourceParams {
            uri: "resource://alpha".to_string(),
        };
        let value = serde_json::to_value(&subscribe).expect("serialize subscribe params");
        assert_eq!(value, serde_json::json!({ "uri": "resource://alpha" }));

        let unsubscribe = UnsubscribeResourceParams {
            uri: "resource://alpha".to_string(),
        };
        let value = serde_json::to_value(&unsubscribe).expect("serialize unsubscribe params");
        assert_eq!(value, serde_json::json!({ "uri": "resource://alpha" }));
    }

    #[test]
    fn logging_params_serialization() {
        let set_level = SetLogLevelParams {
            level: LogLevel::Warning,
        };
        let value = serde_json::to_value(&set_level).expect("serialize setLevel");
        assert_eq!(value, serde_json::json!({ "level": "warning" }));

        let log_message = LogMessageParams {
            level: LogLevel::Info,
            logger: Some("fastmcp::server".to_string()),
            data: serde_json::Value::String("hello".to_string()),
        };
        let value = serde_json::to_value(&log_message).expect("serialize log message");
        assert_eq!(value["level"], "info");
        assert_eq!(value["logger"], "fastmcp::server");
        assert_eq!(value["data"], "hello");
    }

    #[test]
    fn list_tasks_params_serialization() {
        let params = ListTasksParams {
            cursor: None,
            status: None,
        };
        let value = serde_json::to_value(&params).expect("serialize list tasks params");
        assert_eq!(value, serde_json::json!({}));

        let params = ListTasksParams {
            cursor: Some("next".to_string()),
            status: Some(TaskStatus::Running),
        };
        let value = serde_json::to_value(&params).expect("serialize list tasks params");
        assert_eq!(
            value,
            serde_json::json!({"cursor": "next", "status": "running"})
        );
    }

    #[test]
    fn submit_task_params_serialization() {
        let params = SubmitTaskParams {
            task_type: "demo".to_string(),
            params: None,
        };
        let value = serde_json::to_value(&params).expect("serialize submit task params");
        assert_eq!(value, serde_json::json!({"taskType": "demo"}));

        let params = SubmitTaskParams {
            task_type: "demo".to_string(),
            params: Some(serde_json::json!({"payload": 1})),
        };
        let value = serde_json::to_value(&params).expect("serialize submit task params");
        assert_eq!(
            value,
            serde_json::json!({"taskType": "demo", "params": {"payload": 1}})
        );
    }

    #[test]
    fn task_status_notification_serialization() {
        let params = TaskStatusNotificationParams {
            id: TaskId::from_string("task-1"),
            status: TaskStatus::Running,
            progress: Some(0.5),
            message: Some("halfway".to_string()),
            error: None,
            result: None,
        };
        let value = serde_json::to_value(&params).expect("serialize task status notification");
        assert_eq!(
            value,
            serde_json::json!({
                "id": "task-1",
                "status": "running",
                "progress": 0.5,
                "message": "halfway"
            })
        );
    }

    // ========================================================================
    // Sampling Tests
    // ========================================================================

    #[test]
    fn create_message_params_minimal() {
        let params = CreateMessageParams::new(vec![SamplingMessage::user("Hello")], 100);
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["maxTokens"], 100);
        assert!(value["messages"].is_array());
        assert!(value.get("systemPrompt").is_none());
        assert!(value.get("temperature").is_none());
    }

    #[test]
    fn create_message_params_full() {
        let params = CreateMessageParams::new(
            vec![
                SamplingMessage::user("Hello"),
                SamplingMessage::assistant("Hi there!"),
            ],
            500,
        )
        .with_system_prompt("You are helpful")
        .with_temperature(0.7)
        .with_stop_sequences(vec!["END".to_string()]);

        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["maxTokens"], 500);
        assert_eq!(value["systemPrompt"], "You are helpful");
        assert_eq!(value["temperature"], 0.7);
        assert_eq!(value["stopSequences"][0], "END");
        assert_eq!(value["messages"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn create_message_result_text() {
        let result = CreateMessageResult::text("Hello!", "claude-3");
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["content"]["type"], "text");
        assert_eq!(value["content"]["text"], "Hello!");
        assert_eq!(value["model"], "claude-3");
        assert_eq!(value["role"], "assistant");
        assert_eq!(value["stopReason"], "endTurn");
    }

    #[test]
    fn create_message_result_max_tokens() {
        use crate::types::StopReason;

        let result =
            CreateMessageResult::text("Truncated", "gpt-4").with_stop_reason(StopReason::MaxTokens);
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["stopReason"], "maxTokens");
    }

    #[test]
    fn sampling_message_user() {
        let msg = SamplingMessage::user("Test message");
        let value = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(value["role"], "user");
        assert_eq!(value["content"]["type"], "text");
        assert_eq!(value["content"]["text"], "Test message");
    }

    #[test]
    fn sampling_message_assistant() {
        let msg = SamplingMessage::assistant("Response");
        let value = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(value["role"], "assistant");
        assert_eq!(value["content"]["type"], "text");
        assert_eq!(value["content"]["text"], "Response");
    }

    #[test]
    fn sampling_content_image() {
        let content = SamplingContent::Image {
            data: "base64data".to_string(),
            mime_type: "image/png".to_string(),
        };
        let value = serde_json::to_value(&content).expect("serialize");
        assert_eq!(value["type"], "image");
        assert_eq!(value["data"], "base64data");
        assert_eq!(value["mimeType"], "image/png");
    }

    #[test]
    fn include_context_serialization() {
        let none = IncludeContext::None;
        let this = IncludeContext::ThisServer;
        let all = IncludeContext::AllServers;

        assert_eq!(serde_json::to_value(none).unwrap(), "none");
        assert_eq!(serde_json::to_value(this).unwrap(), "thisServer");
        assert_eq!(serde_json::to_value(all).unwrap(), "allServers");
    }

    #[test]
    fn create_message_result_text_content() {
        let result = CreateMessageResult::text("Hello!", "model");
        assert_eq!(result.text_content(), Some("Hello!"));

        let result = CreateMessageResult {
            content: SamplingContent::Image {
                data: "data".to_string(),
                mime_type: "image/png".to_string(),
            },
            role: crate::types::Role::Assistant,
            model: "model".to_string(),
            stop_reason: StopReason::EndTurn,
        };
        assert_eq!(result.text_content(), None);
    }

    // ========================================================================
    // Elicitation Tests
    // ========================================================================

    #[test]
    fn elicit_form_params_serialization() {
        let params = ElicitRequestFormParams::new(
            "Please enter your name",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"}
                },
                "required": ["name"]
            }),
        );
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["mode"], "form");
        assert_eq!(value["message"], "Please enter your name");
        assert!(value["requestedSchema"]["properties"]["name"].is_object());
    }

    #[test]
    fn elicit_url_params_serialization() {
        let params = ElicitRequestUrlParams::new(
            "Please authenticate",
            "https://auth.example.com/oauth",
            "elicit-12345",
        );
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["mode"], "url");
        assert_eq!(value["message"], "Please authenticate");
        assert_eq!(value["url"], "https://auth.example.com/oauth");
        assert_eq!(value["elicitationId"], "elicit-12345");
    }

    #[test]
    fn elicit_request_params_untagged() {
        let form = ElicitRequestParams::form(
            "Enter name",
            serde_json::json!({"type": "object", "properties": {}}),
        );
        assert_eq!(form.mode(), ElicitMode::Form);
        assert_eq!(form.message(), "Enter name");

        let url = ElicitRequestParams::url("Auth required", "https://example.com", "id-1");
        assert_eq!(url.mode(), ElicitMode::Url);
        assert_eq!(url.message(), "Auth required");
    }

    #[test]
    fn elicit_result_accept_with_content() {
        let mut content = std::collections::HashMap::new();
        content.insert(
            "name".to_string(),
            ElicitContentValue::String("Alice".to_string()),
        );
        content.insert("age".to_string(), ElicitContentValue::Int(30));
        content.insert("active".to_string(), ElicitContentValue::Bool(true));

        let result = ElicitResult::accept(content);
        assert!(result.is_accepted());
        assert!(!result.is_declined());
        assert!(!result.is_cancelled());
        assert_eq!(result.get_string("name"), Some("Alice"));
        assert_eq!(result.get_int("age"), Some(30));
        assert_eq!(result.get_bool("active"), Some(true));
    }

    #[test]
    fn elicit_result_serialization() {
        let result = ElicitResult::decline();
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["action"], "decline");
        assert!(value.get("content").is_none());

        let result = ElicitResult::cancel();
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["action"], "cancel");
    }

    #[test]
    fn elicit_content_value_conversions() {
        let s: ElicitContentValue = "hello".into();
        assert!(matches!(s, ElicitContentValue::String(_)));

        let i: ElicitContentValue = 42i64.into();
        assert!(matches!(i, ElicitContentValue::Int(42)));

        let b: ElicitContentValue = true.into();
        assert!(matches!(b, ElicitContentValue::Bool(true)));

        let f: ElicitContentValue = 1.23.into();
        assert!(matches!(f, ElicitContentValue::Float(_)));

        let arr: ElicitContentValue = vec!["a".to_string(), "b".to_string()].into();
        assert!(matches!(arr, ElicitContentValue::StringArray(_)));

        let none: ElicitContentValue = None::<String>.into();
        assert!(matches!(none, ElicitContentValue::Null));
    }

    #[test]
    fn elicit_complete_notification_serialization() {
        let params = ElicitCompleteNotificationParams::new("elicit-12345");
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["elicitationId"], "elicit-12345");
    }

    #[test]
    fn elicitation_capability_modes() {
        use crate::types::ElicitationCapability;

        let form_only = ElicitationCapability::form();
        assert!(form_only.supports_form());
        assert!(!form_only.supports_url());

        let url_only = ElicitationCapability::url();
        assert!(!url_only.supports_form());
        assert!(url_only.supports_url());

        let both = ElicitationCapability::both();
        assert!(both.supports_form());
        assert!(both.supports_url());
    }

    // ========================================================================
    // Roots tests
    // ========================================================================

    #[test]
    fn root_new() {
        use crate::types::Root;

        let root = Root::new("file:///home/user/project");
        assert_eq!(root.uri, "file:///home/user/project");
        assert!(root.name.is_none());
    }

    #[test]
    fn root_with_name() {
        use crate::types::Root;

        let root = Root::with_name("file:///home/user/project", "My Project");
        assert_eq!(root.uri, "file:///home/user/project");
        assert_eq!(root.name, Some("My Project".to_string()));
    }

    #[test]
    fn root_serialization() {
        use crate::types::Root;

        let root = Root::with_name("file:///home/user/project", "My Project");
        let json = serde_json::to_value(&root).expect("serialize");
        assert_eq!(json["uri"], "file:///home/user/project");
        assert_eq!(json["name"], "My Project");

        // Without name
        let root_no_name = Root::new("file:///tmp");
        let json = serde_json::to_value(&root_no_name).expect("serialize");
        assert_eq!(json["uri"], "file:///tmp");
        assert!(json.get("name").is_none());
    }

    #[test]
    fn list_roots_result_empty() {
        let result = ListRootsResult::empty();
        assert!(result.roots.is_empty());
    }

    #[test]
    fn list_roots_result_serialization() {
        use crate::types::Root;

        let result = ListRootsResult::new(vec![
            Root::with_name("file:///home/user/frontend", "Frontend"),
            Root::with_name("file:///home/user/backend", "Backend"),
        ]);

        let json = serde_json::to_value(&result).expect("serialize");
        let roots = json["roots"].as_array().expect("roots array");
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0]["uri"], "file:///home/user/frontend");
        assert_eq!(roots[0]["name"], "Frontend");
        assert_eq!(roots[1]["uri"], "file:///home/user/backend");
        assert_eq!(roots[1]["name"], "Backend");
    }

    #[test]
    fn roots_capability_serialization() {
        use crate::types::RootsCapability;

        // With listChanged = true
        let cap = RootsCapability { list_changed: true };
        let json = serde_json::to_value(&cap).expect("serialize");
        assert_eq!(json["listChanged"], true);

        // With listChanged = false (should be omitted)
        let cap = RootsCapability::default();
        let json = serde_json::to_value(&cap).expect("serialize");
        assert!(json.get("listChanged").is_none());
    }

    // ========================================================================
    // Component Version Metadata Tests
    // ========================================================================

    #[test]
    fn tool_version_serialization() {
        use crate::types::Tool;

        // Tool without version (should omit version field)
        let tool = Tool {
            name: "my_tool".to_string(),
            description: Some("A test tool".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        assert!(json.get("version").is_none());

        // Tool with version
        let tool = Tool {
            name: "my_tool".to_string(),
            description: Some("A test tool".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            icon: None,
            version: Some("1.2.3".to_string()),
            tags: vec![],
            annotations: None,
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        assert_eq!(json["version"], "1.2.3");
    }

    #[test]
    fn resource_version_serialization() {
        use crate::types::Resource;

        // Resource without version
        let resource = Resource {
            uri: "file://test".to_string(),
            name: "Test Resource".to_string(),
            description: None,
            mime_type: Some("text/plain".to_string()),
            icon: None,
            version: None,
            tags: vec![],
        };
        let json = serde_json::to_value(&resource).expect("serialize");
        assert!(json.get("version").is_none());

        // Resource with version
        let resource = Resource {
            uri: "file://test".to_string(),
            name: "Test Resource".to_string(),
            description: None,
            mime_type: Some("text/plain".to_string()),
            icon: None,
            version: Some("2.0.0".to_string()),
            tags: vec![],
        };
        let json = serde_json::to_value(&resource).expect("serialize");
        assert_eq!(json["version"], "2.0.0");
    }

    #[test]
    fn prompt_version_serialization() {
        use crate::types::Prompt;

        // Prompt without version
        let prompt = Prompt {
            name: "greeting".to_string(),
            description: Some("A greeting prompt".to_string()),
            arguments: vec![],
            icon: None,
            version: None,
            tags: vec![],
        };
        let json = serde_json::to_value(&prompt).expect("serialize");
        assert!(json.get("version").is_none());

        // Prompt with version
        let prompt = Prompt {
            name: "greeting".to_string(),
            description: Some("A greeting prompt".to_string()),
            arguments: vec![],
            icon: None,
            version: Some("0.1.0".to_string()),
            tags: vec![],
        };
        let json = serde_json::to_value(&prompt).expect("serialize");
        assert_eq!(json["version"], "0.1.0");
    }

    #[test]
    fn resource_template_version_serialization() {
        // ResourceTemplate without version
        let template = ResourceTemplate {
            uri_template: "file://{path}".to_string(),
            name: "Files".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let json = serde_json::to_value(&template).expect("serialize");
        assert!(json.get("version").is_none());

        // ResourceTemplate with version
        let template = ResourceTemplate {
            uri_template: "file://{path}".to_string(),
            name: "Files".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: Some("3.0.0".to_string()),
            tags: vec![],
        };
        let json = serde_json::to_value(&template).expect("serialize");
        assert_eq!(json["version"], "3.0.0");
    }

    #[test]
    fn version_deserialization() {
        use crate::types::{Prompt, Resource, Tool};

        // Deserialize tool without version
        let json = serde_json::json!({
            "name": "tool",
            "inputSchema": {"type": "object"}
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        assert!(tool.version.is_none());

        // Deserialize tool with version
        let json = serde_json::json!({
            "name": "tool",
            "inputSchema": {"type": "object"},
            "version": "1.0.0"
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        assert_eq!(tool.version, Some("1.0.0".to_string()));

        // Deserialize resource without version
        let json = serde_json::json!({
            "uri": "file://test",
            "name": "Test"
        });
        let resource: Resource = serde_json::from_value(json).expect("deserialize");
        assert!(resource.version.is_none());

        // Deserialize prompt without version
        let json = serde_json::json!({
            "name": "prompt"
        });
        let prompt: Prompt = serde_json::from_value(json).expect("deserialize");
        assert!(prompt.version.is_none());
    }

    // ========================================================================
    // Tags Serialization Tests
    // ========================================================================

    #[test]
    fn tool_tags_serialization() {
        use crate::types::Tool;

        // Tool without tags (empty vec should not appear in JSON)
        let tool = Tool {
            name: "my_tool".to_string(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        assert!(
            json.get("tags").is_none(),
            "Empty tags should not appear in JSON"
        );

        // Tool with tags
        let tool = Tool {
            name: "my_tool".to_string(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            icon: None,
            version: None,
            tags: vec!["api".to_string(), "database".to_string()],
            annotations: None,
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        assert_eq!(json["tags"], serde_json::json!(["api", "database"]));
    }

    #[test]
    fn resource_tags_serialization() {
        use crate::types::Resource;

        // Resource without tags
        let resource = Resource {
            uri: "file://test".to_string(),
            name: "Test Resource".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let json = serde_json::to_value(&resource).expect("serialize");
        assert!(
            json.get("tags").is_none(),
            "Empty tags should not appear in JSON"
        );

        // Resource with tags
        let resource = Resource {
            uri: "file://test".to_string(),
            name: "Test Resource".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["files".to_string(), "readonly".to_string()],
        };
        let json = serde_json::to_value(&resource).expect("serialize");
        assert_eq!(json["tags"], serde_json::json!(["files", "readonly"]));
    }

    #[test]
    fn prompt_tags_serialization() {
        use crate::types::Prompt;

        // Prompt without tags
        let prompt = Prompt {
            name: "greeting".to_string(),
            description: None,
            arguments: vec![],
            icon: None,
            version: None,
            tags: vec![],
        };
        let json = serde_json::to_value(&prompt).expect("serialize");
        assert!(
            json.get("tags").is_none(),
            "Empty tags should not appear in JSON"
        );

        // Prompt with tags
        let prompt = Prompt {
            name: "greeting".to_string(),
            description: None,
            arguments: vec![],
            icon: None,
            version: None,
            tags: vec!["templates".to_string(), "onboarding".to_string()],
        };
        let json = serde_json::to_value(&prompt).expect("serialize");
        assert_eq!(json["tags"], serde_json::json!(["templates", "onboarding"]));
    }

    #[test]
    fn resource_template_tags_serialization() {
        // ResourceTemplate without tags
        let template = ResourceTemplate {
            uri_template: "file://{path}".to_string(),
            name: "Files".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let json = serde_json::to_value(&template).expect("serialize");
        assert!(
            json.get("tags").is_none(),
            "Empty tags should not appear in JSON"
        );

        // ResourceTemplate with tags
        let template = ResourceTemplate {
            uri_template: "file://{path}".to_string(),
            name: "Files".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["filesystem".to_string()],
        };
        let json = serde_json::to_value(&template).expect("serialize");
        assert_eq!(json["tags"], serde_json::json!(["filesystem"]));
    }

    #[test]
    fn tags_deserialization() {
        use crate::types::{Prompt, Resource, Tool};

        // Deserialize tool without tags field
        let json = serde_json::json!({
            "name": "tool",
            "inputSchema": {"type": "object"}
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        assert!(tool.tags.is_empty());

        // Deserialize tool with tags
        let json = serde_json::json!({
            "name": "tool",
            "inputSchema": {"type": "object"},
            "tags": ["compute", "heavy"]
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        assert_eq!(tool.tags, vec!["compute", "heavy"]);

        // Deserialize resource without tags
        let json = serde_json::json!({
            "uri": "file://test",
            "name": "Test"
        });
        let resource: Resource = serde_json::from_value(json).expect("deserialize");
        assert!(resource.tags.is_empty());

        // Deserialize resource with tags
        let json = serde_json::json!({
            "uri": "file://test",
            "name": "Test",
            "tags": ["data"]
        });
        let resource: Resource = serde_json::from_value(json).expect("deserialize");
        assert_eq!(resource.tags, vec!["data"]);

        // Deserialize prompt without tags
        let json = serde_json::json!({
            "name": "prompt"
        });
        let prompt: Prompt = serde_json::from_value(json).expect("deserialize");
        assert!(prompt.tags.is_empty());

        // Deserialize prompt with tags
        let json = serde_json::json!({
            "name": "prompt",
            "tags": ["greeting", "onboarding"]
        });
        let prompt: Prompt = serde_json::from_value(json).expect("deserialize");
        assert_eq!(prompt.tags, vec!["greeting", "onboarding"]);
    }

    // ========================================================================
    // Tool Annotations Serialization Tests
    // ========================================================================

    #[test]
    fn tool_annotations_serialization() {
        use crate::types::{Tool, ToolAnnotations};

        // Tool without annotations (None should not appear in JSON)
        let tool = Tool {
            name: "my_tool".to_string(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        assert!(
            json.get("annotations").is_none(),
            "None annotations should not appear in JSON"
        );

        // Tool with annotations
        let tool = Tool {
            name: "delete_file".to_string(),
            description: Some("Deletes a file".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            icon: None,
            version: None,
            tags: vec![],
            annotations: Some(
                ToolAnnotations::new()
                    .destructive(true)
                    .idempotent(false)
                    .read_only(false),
            ),
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        let annotations = json.get("annotations").expect("annotations field");
        assert_eq!(annotations["destructive"], true);
        assert_eq!(annotations["idempotent"], false);
        assert_eq!(annotations["readOnly"], false);
        assert!(annotations.get("openWorldHint").is_none());

        // Tool with read_only annotation
        let tool = Tool {
            name: "get_status".to_string(),
            description: Some("Gets status".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            icon: None,
            version: None,
            tags: vec![],
            annotations: Some(ToolAnnotations::new().read_only(true)),
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        let annotations = json.get("annotations").expect("annotations field");
        assert_eq!(annotations["readOnly"], true);
        assert!(annotations.get("destructive").is_none());
    }

    #[test]
    fn tool_annotations_deserialization() {
        use crate::types::Tool;

        // Deserialize tool without annotations
        let json = serde_json::json!({
            "name": "tool",
            "inputSchema": {"type": "object"}
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        assert!(tool.annotations.is_none());

        // Deserialize tool with annotations
        let json = serde_json::json!({
            "name": "delete_tool",
            "inputSchema": {"type": "object"},
            "annotations": {
                "destructive": true,
                "idempotent": false,
                "readOnly": false,
                "openWorldHint": "May delete any file"
            }
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        let annotations = tool.annotations.expect("annotations present");
        assert_eq!(annotations.destructive, Some(true));
        assert_eq!(annotations.idempotent, Some(false));
        assert_eq!(annotations.read_only, Some(false));
        assert_eq!(
            annotations.open_world_hint,
            Some("May delete any file".to_string())
        );
    }

    #[test]
    fn tool_annotations_builder() {
        use crate::types::ToolAnnotations;

        let annotations = ToolAnnotations::new()
            .destructive(true)
            .idempotent(true)
            .read_only(false)
            .open_world_hint("Handles unknown inputs gracefully");

        assert_eq!(annotations.destructive, Some(true));
        assert_eq!(annotations.idempotent, Some(true));
        assert_eq!(annotations.read_only, Some(false));
        assert_eq!(
            annotations.open_world_hint,
            Some("Handles unknown inputs gracefully".to_string())
        );
        assert!(!annotations.is_empty());

        // Empty annotations
        let empty = ToolAnnotations::new();
        assert!(empty.is_empty());
    }
}
