//! Request router for MCP servers.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::Poll;
use std::time::Duration;

#[cfg(test)]
use asupersync::time::wall_now;
use asupersync::types::Time;
use asupersync::{Budget, Cx, Outcome};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fastmcp_core::logging::{debug, targets, trace};
use fastmcp_core::{
    McpContext, McpError, McpErrorCode, McpOutcome, McpResult, SessionState, block_on,
    sha256_bounded,
};
use fastmcp_protocol::common_types::{
    AbsoluteUri, Annotations, EmbeddedResourceContents, OpenMetadata, RawIcon,
};
use fastmcp_protocol::methods::COMPLETION_COMPLETE;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    CacheScope, CallToolParams, CallToolResult, CompleteResult, Content, CoreRequest, CoreResult,
    FinalCallToolParams, FinalCallToolResult, FinalCompletionParams, FinalCompletionResult,
    FinalCoreRequest, FinalCoreResult, FinalListParams, FinalListPromptsResult,
    FinalListResourceTemplatesResult, FinalListResourcesResult, FinalListToolsResult, FinalPrompt,
    FinalPromptArgument, FinalReadResourceParams, FinalReadResourceResult, FinalResource,
    FinalResourceTemplate, FinalTool, FinalToolAnnotations, GetPromptParams, GetPromptResult,
    InitializeParams, InitializeResult, JsonRpcRequest, LegacyCompletionParams,
    LegacyCompletionResult, LegacyCoreRequest, ListPromptsParams, ListPromptsResult,
    ListResourceTemplatesParams, ListResourceTemplatesResult, ListResourcesParams,
    ListResourcesResult, ListToolsParams, ListToolsResult, PROTOCOL_VERSION, ProgressMarker,
    Prompt, ReadResourceParams, ReadResourceResult, Resource, ResourceContent, ResourceTemplate,
    ServerBehavior, ServerBehaviorRegistry, Tool, validate, validate_strict,
};
#[cfg(test)]
use fastmcp_protocol::{
    CancelTaskParams, CancelTaskResult, GetTaskParams, GetTaskResult, ListTasksParams,
    ListTasksResult, SubmitTaskParams, SubmitTaskResult,
};

use crate::handler::{
    BidirectionalSenders, BoxFuture, ProgressNotificationSender, UriParams, empty_final_result_meta,
};
#[cfg(test)]
use crate::tasks::SharedTaskManager;

use crate::Session;
use crate::handler::{
    BoxedCompletionHandler, BoxedPromptHandler, BoxedResourceHandler, BoxedToolHandler,
    CompletionHandler, PromptHandler, ResourceHandler, ToolHandler,
};

/// Type alias for a notification sender callback.
///
/// This callback is used to send notifications (like progress updates) back to the client
/// during request handling. The callback receives a JSON-RPC request (notification format).
pub type NotificationSender = Arc<dyn Fn(JsonRpcRequest) + Send + Sync>;

/// Allowlisted transport provenance attached to a sanitized inbound request.
///
/// This deliberately contains no peer address, headers, cookies, or
/// credentials. Transport implementations retain those raw values inside their
/// authentication boundary and pass only one of these validated facts to the
/// server dispatch layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundRequestTransport {
    /// Standard input/output framing.
    Stdio,
    /// Streamable HTTP request handling.
    Http,
    /// Server-sent events transport.
    Sse,
    /// WebSocket transport.
    WebSocket,
    /// In-process transport used by embeddings and tests.
    Memory,
}

/// Sanitized, immutable ingress facts for one server dispatch.
///
/// The type intentionally has no `Clone`, `Serialize`, or `Debug`
/// implementation. In particular, it offers no channel for raw headers or
/// credentials: a transport must authenticate privately and construct this
/// context from its allowlisted provenance only. The server creates a fresh
/// request-scoped [`McpContext`] from these facts for every dispatch.
pub struct InboundRequestContext {
    cx: Cx,
    request_id: u64,
    transport: InboundRequestTransport,
}

impl InboundRequestContext {
    /// Creates sanitized facts after transport-owned authentication and request
    /// metadata validation have completed.
    #[must_use]
    pub fn new(cx: Cx, request_id: u64, transport: InboundRequestTransport) -> Self {
        Self {
            cx,
            request_id,
            transport,
        }
    }

    /// Returns the transport's allowlisted provenance fact.
    #[must_use]
    pub const fn transport(&self) -> InboundRequestTransport {
        self.transport
    }

    /// Returns the request identity selected by the transport.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub(crate) fn request_context(&self) -> McpContext {
        McpContext::new(self.cx.clone(), self.request_id)
    }
}

/// Tag filtering parameters for list operations.
#[derive(Debug, Clone, Default)]
pub struct TagFilters<'a> {
    /// Only include components with ALL of these tags (AND logic).
    pub include: Option<&'a [String]>,
    /// Exclude components with ANY of these tags (OR logic).
    pub exclude: Option<&'a [String]>,
}

impl<'a> TagFilters<'a> {
    /// Creates tag filters from include and exclude vectors.
    pub fn new(include: Option<&'a Vec<String>>, exclude: Option<&'a Vec<String>>) -> Self {
        Self {
            include: include.map(|v| v.as_slice()),
            exclude: exclude.map(|v| v.as_slice()),
        }
    }

    /// Returns true if the given component tags pass the filter.
    ///
    /// - Include filter: component must have ALL include tags (AND logic)
    /// - Exclude filter: component is rejected if it has ANY exclude tag (OR logic)
    /// - Tag matching is case-insensitive
    pub fn matches(&self, component_tags: &[String]) -> bool {
        // Normalize component tags to lowercase for comparison
        let component_tags_lower: Vec<String> =
            component_tags.iter().map(|t| t.to_lowercase()).collect();

        // Include filter: must have ALL specified tags
        if let Some(include) = self.include {
            // Empty include array means no filter (all pass)
            if !include.is_empty() {
                for tag in include {
                    let tag_lower = tag.to_lowercase();
                    if !component_tags_lower.contains(&tag_lower) {
                        return false;
                    }
                }
            }
        }

        // Exclude filter: rejected if has ANY specified tag
        if let Some(exclude) = self.exclude {
            for tag in exclude {
                let tag_lower = tag.to_lowercase();
                if component_tags_lower.contains(&tag_lower) {
                    return false;
                }
            }
        }

        true
    }
}

fn decode_cursor_offset(cursor: Option<&str>) -> McpResult<usize> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };

    let decoded = BASE64_STANDARD.decode(cursor).map_err(|_| {
        McpError::invalid_params("Invalid cursor (base64 decode failed)".to_string())
    })?;
    let v: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|_| McpError::invalid_params("Invalid cursor (JSON parse failed)".to_string()))?;
    let offset = v
        .get("offset")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| McpError::invalid_params("Invalid cursor (missing offset)".to_string()))?;

    usize::try_from(offset)
        .map_err(|_| McpError::invalid_params("Invalid cursor (offset too large)".to_string()))
}

fn parse_stateless_params<T: serde::de::DeserializeOwned>(
    params: Option<serde_json::Value>,
) -> McpResult<T> {
    let value = params.ok_or_else(|| McpError::invalid_params("Missing required parameters"))?;
    serde_json::from_value(value).map_err(|error| McpError::invalid_params(error.to_string()))
}

fn parse_stateless_params_or_default<T: serde::de::DeserializeOwned + Default>(
    params: Option<serde_json::Value>,
) -> McpResult<T> {
    match params {
        Some(value) => serde_json::from_value(value)
            .map_err(|error| McpError::invalid_params(error.to_string())),
        None => Ok(T::default()),
    }
}

/// Converts a completed stateless handler result through the final result
/// contract while preserving the original typed [`McpError`] on refusal.
fn encode_stateless_handler_result<T: serde::Serialize>(
    result: McpResult<T>,
) -> McpResult<serde_json::Value> {
    encode_final_complete_result(result?)
}

/// Encodes a handler-authored final tool result without reprojecting it through
/// the legacy result surface. This preserves the complete result's metadata
/// and inert open members under the protocol-owned final codec.
fn encode_final_tools_call_result(
    result: McpResult<CompleteResult<FinalCallToolResult>>,
) -> McpResult<serde_json::Value> {
    let result = result?;
    let encoded = CoreResult::Final(FinalCoreResult::ToolsCall {
        result,
        diagnostic: None,
    })
    .encode()
    .map_err(|error| McpError::internal_error(error.to_string()))?;
    serde_json::from_str(&encoded).map_err(McpError::from)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FinalCacheHintPolicy {
    list_ttl_ms: u64,
    resource_read_ttl_ms: u64,
    scope: CacheScope,
}

impl Default for FinalCacheHintPolicy {
    fn default() -> Self {
        Self {
            list_ttl_ms: 5 * 60 * 1_000,
            resource_read_ttl_ms: 60 * 60 * 1_000,
            scope: CacheScope::Private,
        }
    }
}

/// Encodes a server-authored final payload through the selected method's exact
/// `FinalCoreResult` composition. This preserves typed catalog and cache
/// fields instead of inserting unvalidated JSON after serialization.
fn encode_final_core_result<T>(
    result: McpResult<T>,
    select: impl FnOnce(CompleteResult<T>) -> FinalCoreResult,
) -> McpResult<serde_json::Value> {
    let result = CompleteResult::new(result?, empty_final_result_meta()?);
    let encoded = CoreResult::Final(select(result))
        .encode()
        .map_err(|error| McpError::internal_error(error.to_string()))?;
    serde_json::from_str(&encoded).map_err(McpError::from)
}

fn project_final_tool_annotations(
    annotations: fastmcp_protocol::ToolAnnotations,
) -> FinalToolAnnotations {
    FinalToolAnnotations {
        title: None,
        destructive: annotations.destructive,
        idempotent: annotations.idempotent,
        read_only: annotations.read_only,
        open_world_hint: annotations.open_world_hint,
    }
}

fn project_final_resource_catalog_entry(
    resource: Resource,
    title: Option<String>,
    icons: Option<Vec<RawIcon>>,
    annotations: Option<Annotations>,
    meta: Option<OpenMetadata>,
) -> McpResult<FinalResource> {
    let uri = AbsoluteUri::parse(resource.uri).map_err(|error| {
        McpError::internal_error(format!(
            "legacy resource URI cannot be projected into the final catalog: {error}",
        ))
    })?;
    Ok(FinalResource {
        uri,
        name: resource.name,
        title,
        description: resource.description,
        icons,
        mime_type: resource.mime_type,
        size: None,
        annotations,
        meta,
    })
}

fn promote_resource_content(resource: ResourceContent) -> McpResult<EmbeddedResourceContents> {
    let uri = AbsoluteUri::parse(resource.uri).map_err(|error| {
        McpError::internal_error(format!(
            "legacy resource content cannot be projected into the final result: {error}",
        ))
    })?;
    match (resource.text, resource.blob) {
        (Some(text), None) => Ok(EmbeddedResourceContents::Text {
            uri,
            text,
            mime_type: resource.mime_type,
        }),
        (None, Some(blob)) => Ok(EmbeddedResourceContents::Blob {
            uri,
            blob,
            mime_type: resource.mime_type,
        }),
        _ => Err(McpError::internal_error(
            "legacy resource content cannot be promoted without exactly one text or blob payload",
        )),
    }
}

fn legacy_list_tools_params(params: FinalListParams) -> ListToolsParams {
    ListToolsParams {
        cursor: params.cursor,
        include_tags: params.include_tags,
        exclude_tags: params.exclude_tags,
    }
}

fn legacy_list_resources_params(params: FinalListParams) -> ListResourcesParams {
    ListResourcesParams {
        cursor: params.cursor,
        include_tags: params.include_tags,
        exclude_tags: params.exclude_tags,
    }
}

fn legacy_list_resource_templates_params(params: FinalListParams) -> ListResourceTemplatesParams {
    ListResourceTemplatesParams {
        cursor: params.cursor,
        include_tags: params.include_tags,
        exclude_tags: params.exclude_tags,
    }
}

fn legacy_list_prompts_params(params: FinalListParams) -> ListPromptsParams {
    ListPromptsParams {
        cursor: params.cursor,
        include_tags: params.include_tags,
        exclude_tags: params.exclude_tags,
    }
}

fn legacy_read_resource_params(params: FinalReadResourceParams) -> ReadResourceParams {
    ReadResourceParams {
        uri: params.uri.as_str().to_owned(),
        meta: None,
    }
}

fn encode_cursor_offset(offset: usize) -> String {
    let payload = serde_json::json!({ "offset": offset });
    let bytes = serde_json::to_vec(&payload).expect("cursor state must serialize");
    BASE64_STANDARD.encode(bytes)
}

const SANITIZED_HANDLER_PANIC_MESSAGE: &str = "Internal server error";
static NEXT_HANDLER_INCIDENT_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum number of peer-controlled label bytes admitted to the log-key hash.
///
/// Labels longer than this retain their exact byte length in logs, but their
/// correlation key covers only this bounded prefix. This keeps observability
/// useful without allowing an attacker to turn debug logging into unbounded
/// hashing work.
const LOG_LABEL_HASH_INPUT_LIMIT: usize = 4 * 1024;
const LOG_LABEL_DIGEST_PREFIX_BYTES: usize = 8;

#[derive(Clone, Copy)]
struct SafeLogLabel {
    byte_len: usize,
    hashed_bytes: usize,
    digest_prefix: [u8; LOG_LABEL_DIGEST_PREFIX_BYTES],
}

impl std::fmt::Display for SafeLogLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bytes={},sha256_prefix=", self.byte_len)?;
        for byte in self.digest_prefix {
            write!(f, "{byte:02x}")?;
        }
        if self.hashed_bytes < self.byte_len {
            write!(f, ",hashed_prefix_bytes={}", self.hashed_bytes)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for SafeLogLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

fn safe_log_label(value: &str) -> SafeLogLabel {
    let bytes = value.as_bytes();
    let hashed_bytes = bytes.len().min(LOG_LABEL_HASH_INPUT_LIMIT);
    let bounded_prefix = &bytes[..hashed_bytes];
    let mut digest_prefix = [0_u8; LOG_LABEL_DIGEST_PREFIX_BYTES];
    if let Ok(digest) = sha256_bounded(bounded_prefix, LOG_LABEL_HASH_INPUT_LIMIT) {
        digest_prefix.copy_from_slice(&digest.as_bytes()[..LOG_LABEL_DIGEST_PREFIX_BYTES]);
    }

    SafeLogLabel {
        byte_len: bytes.len(),
        hashed_bytes,
        digest_prefix,
    }
}

fn duplicate_registration_error(component: &'static str, key: &str) -> McpError {
    McpError::invalid_request(format!(
        "{component} already exists; component_key={}",
        safe_log_label(key)
    ))
}

fn compose_handler_budget(
    ambient: Budget,
    server_or_request: Budget,
    handler_timeout: Option<Duration>,
    now: Time,
) -> Budget {
    let inherited = ambient.meet(server_or_request);
    match handler_timeout {
        Some(timeout) if !timeout.is_zero() => inherited.tightened_by_timeout(now, timeout),
        Some(_) | None => inherited,
    }
}

fn budget_error(ctx: &McpContext) -> Option<McpError> {
    if ctx.ensure_live().is_err() {
        return Some(McpError::request_cancelled());
    }
    None
}

fn sanitized_handler_panic(_request_lifetime: &Cx, handler_class: &'static str) -> McpError {
    let incident_id = NEXT_HANDLER_INCIDENT_ID.fetch_add(1, Ordering::Relaxed);
    log::error!(
        target: "fastmcp_rust::handler",
        "handler terminated unexpectedly; incident_id={incident_id}; class={handler_class}; detail=panic_payload_redacted"
    );
    McpError::internal_error(SANITIZED_HANDLER_PANIC_MESSAGE)
}

fn sanitized_handler_internal_error(
    _request_lifetime: &Cx,
    handler_class: &'static str,
) -> McpError {
    let incident_id = NEXT_HANDLER_INCIDENT_ID.fetch_add(1, Ordering::Relaxed);
    log::error!(
        target: "fastmcp_rust::handler",
        "handler returned an opaque internal failure; incident_id={incident_id}; class={handler_class}; detail=internal_error_redacted"
    );
    McpError::internal_error(SANITIZED_HANDLER_PANIC_MESSAGE)
}

fn sanitize_handler_error(cx: &Cx, handler_class: &'static str, error: McpError) -> McpError {
    if error.code == McpErrorCode::InternalError {
        sanitized_handler_internal_error(cx, handler_class)
    } else {
        error
    }
}

const fn is_framework_terminal_tool_error(code: McpErrorCode) -> bool {
    matches!(
        code,
        McpErrorCode::InternalError | McpErrorCode::RequestCancelled
    )
}

fn read_handler_timeout(
    cx: &Cx,
    handler_class: &'static str,
    read: impl FnOnce() -> Option<Duration>,
) -> McpResult<Option<Duration>> {
    crate::catch_extension_unwind(read)
        .map_err(|_payload| sanitized_handler_panic(cx, handler_class))
}

fn run_handler<'a, T>(
    ctx: &McpContext,
    budget: Budget,
    handler_class: &'static str,
    make_future: impl FnOnce() -> BoxFuture<'a, McpOutcome<T>>,
) -> McpResult<McpOutcome<T>> {
    if let Some(error) = budget_error(ctx) {
        return Err(error);
    }

    let execution = crate::catch_extension_unwind(|| {
        let future = make_future();
        match budget.deadline {
            Some(deadline) => block_on(async move {
                asupersync::time::timeout_at(deadline, future)
                    .await
                    .map_err(|_elapsed| ())
            }),
            None => Ok(block_on(future)),
        }
    });

    match execution {
        Err(_payload) => Err(sanitized_handler_panic(ctx.cx(), handler_class)),
        Ok(Err(())) => Err(McpError::new(
            McpErrorCode::RequestCancelled,
            "Request timeout exceeded",
        )),
        Ok(Ok(outcome)) => {
            if let Some(error) = budget_error(ctx) {
                Err(error)
            } else {
                Ok(outcome)
            }
        }
    }
}

/// Drives one handler future without entering the legacy blocking dispatcher.
///
/// The future stays inside its request-owned child task: timeout drops the
/// pending future, and dropping the parent task's join cancels the child before
/// the parent can complete. This helper deliberately receives the child Cx
/// separately from the framework context so modern handlers can propagate that
/// structured capability to their own nested work.
async fn run_handler_in_request<'a, T>(
    ctx: &'a McpContext,
    request_cx: &'a Cx,
    budget: Budget,
    handler_class: &'static str,
    make_future: impl FnOnce(&'a Cx) -> BoxFuture<'a, McpOutcome<T>>,
) -> McpResult<McpOutcome<T>> {
    if request_cx.is_cancel_requested() || budget_error(ctx).is_some() {
        return Err(McpError::request_cancelled());
    }

    let future = crate::catch_extension_unwind(|| make_future(request_cx))
        .map_err(|_payload| sanitized_handler_panic(ctx.cx(), handler_class))?;
    let mut future = future;
    let poll_handler = std::future::poll_fn(|task_cx| {
        match crate::catch_extension_unwind(|| future.as_mut().poll(task_cx)) {
            Ok(Poll::Ready(outcome)) => Poll::Ready(Ok(outcome)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_payload) => Poll::Ready(Err(())),
        }
    });

    let outcome = match budget.deadline {
        Some(deadline) => match asupersync::time::timeout_at(deadline, poll_handler).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(())) => return Err(sanitized_handler_panic(ctx.cx(), handler_class)),
            Err(_elapsed) => {
                return Err(McpError::new(
                    McpErrorCode::RequestCancelled,
                    "Request timeout exceeded",
                ));
            }
        },
        None => match poll_handler.await {
            Ok(outcome) => outcome,
            Err(()) => return Err(sanitized_handler_panic(ctx.cx(), handler_class)),
        },
    };

    if request_cx.is_cancel_requested() || budget_error(ctx).is_some() {
        Err(McpError::request_cancelled())
    } else {
        Ok(outcome)
    }
}

fn derive_handler_context(
    request_ctx: &McpContext,
    progress_marker: Option<ProgressMarker>,
    notification_sender: Option<&NotificationSender>,
    bidirectional_senders: Option<&BidirectionalSenders>,
) -> McpContext {
    trace!(
        target: targets::HANDLER,
        "Deriving handler context for request {}",
        request_ctx.request_id()
    );
    let mut handler_ctx = request_ctx.clone();

    if let (Some(marker), Some(sender)) = (progress_marker, notification_sender) {
        let sender = sender.clone();
        let reporter = ProgressNotificationSender::new(marker, move |request| {
            sender(request);
        })
        .into_reporter();
        handler_ctx = handler_ctx.with_progress_reporter(reporter);
    }

    if let Some(senders) = bidirectional_senders {
        if let Some(ref sampling) = senders.sampling {
            handler_ctx = handler_ctx.with_sampling(sampling.clone());
        }
        if let Some(ref elicitation) = senders.elicitation {
            handler_ctx = handler_ctx.with_elicitation(elicitation.clone());
        }
    }

    handler_ctx
}

/// Routes MCP requests to the appropriate handlers.
pub struct Router {
    tools: HashMap<String, BoxedToolHandler>,
    tool_order: Vec<String>,
    completion_handler: Option<BoxedCompletionHandler>,
    resources: HashMap<String, BoxedResourceHandler>,
    resource_order: Vec<String>,
    prompts: HashMap<String, BoxedPromptHandler>,
    prompt_order: Vec<String>,
    resource_templates: HashMap<String, ResourceTemplateEntry>,
    resource_template_order: Vec<String>,
    /// Pre-sorted template keys by specificity (most specific first).
    /// Updated whenever templates are added/modified.
    sorted_template_keys: Vec<String>,
    /// Whether to enforce strict input validation (reject extra properties).
    strict_input_validation: bool,
    /// Optional list page size for cursor-based pagination.
    ///
    /// When `None`, list methods return all items in a single response and
    /// `nextCursor` is always omitted.
    list_page_size: Option<usize>,
    /// Cache policy emitted on exact modern catalog and resource-read results.
    final_cache_hints: FinalCacheHintPolicy,
}

impl Router {
    /// Creates a new empty router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            tool_order: Vec::new(),
            completion_handler: None,
            resources: HashMap::new(),
            resource_order: Vec::new(),
            prompts: HashMap::new(),
            prompt_order: Vec::new(),
            resource_templates: HashMap::new(),
            resource_template_order: Vec::new(),
            sorted_template_keys: Vec::new(),
            strict_input_validation: false,
            list_page_size: None,
            final_cache_hints: FinalCacheHintPolicy::default(),
        }
    }

    /// Sets the list pagination page size.
    ///
    /// When set, list methods (`tools/list`, `resources/list`,
    /// `resources/templates/list`, and `prompts/list`) will page results using
    /// opaque base64 cursors.
    pub fn set_list_page_size(&mut self, page_size: Option<usize>) {
        self.list_page_size = page_size.filter(|n| *n > 0);
    }

    /// Sets the cache hints emitted by final catalog and resource-read
    /// responses. The default is a five-minute private catalog TTL and a
    /// one-hour private resource-read TTL.
    pub fn set_final_cache_hint_policy(
        &mut self,
        list_ttl_ms: u64,
        resource_read_ttl_ms: u64,
        scope: CacheScope,
    ) {
        self.final_cache_hints = FinalCacheHintPolicy {
            list_ttl_ms,
            resource_read_ttl_ms,
            scope,
        };
    }

    /// Returns the active final cache-hint policy as
    /// `(list_ttl_ms, resource_read_ttl_ms, scope)`.
    #[must_use]
    pub const fn final_cache_hint_policy(&self) -> (u64, u64, CacheScope) {
        (
            self.final_cache_hints.list_ttl_ms,
            self.final_cache_hints.resource_read_ttl_ms,
            self.final_cache_hints.scope,
        )
    }

    /// Sets whether to use strict input validation.
    ///
    /// When enabled, tool input validation will reject any properties not
    /// explicitly defined in the tool's input schema (enforces `additionalProperties: false`).
    ///
    /// When disabled (default), extra properties are allowed unless the schema
    /// explicitly sets `additionalProperties: false`.
    pub fn set_strict_input_validation(&mut self, strict: bool) {
        self.strict_input_validation = strict;
    }

    /// Returns whether strict input validation is enabled.
    #[must_use]
    pub fn strict_input_validation(&self) -> bool {
        self.strict_input_validation
    }

    /// Rebuilds the sorted template keys vector.
    /// Called after any modification to resource_templates.
    fn rebuild_sorted_template_keys(&mut self) {
        self.sorted_template_keys = self.resource_templates.keys().cloned().collect();
        self.sorted_template_keys.sort_by(|a, b| {
            let entry_a = &self.resource_templates[a];
            let entry_b = &self.resource_templates[b];
            let (a_literals, a_literal_segments, a_segments) = entry_a.matcher.specificity();
            let (b_literals, b_literal_segments, b_segments) = entry_b.matcher.specificity();
            b_literals
                .cmp(&a_literals)
                .then(b_literal_segments.cmp(&a_literal_segments))
                .then(b_segments.cmp(&a_segments))
                .then_with(|| a.cmp(b))
        });
    }

    /// Adds a tool handler.
    ///
    /// If a tool with the same name already exists, it will be replaced.
    /// Use [`add_tool_with_behavior`](Self::add_tool_with_behavior) for
    /// finer control over duplicate handling.
    pub fn add_tool<H: ToolHandler + 'static>(&mut self, handler: H) {
        let def = handler.definition();
        let is_new = !self.tools.contains_key(&def.name);
        self.tools.insert(def.name.clone(), Box::new(handler));
        if is_new {
            self.tool_order.push(def.name);
        }
    }

    /// Adds a tool handler with specified duplicate behavior.
    ///
    /// Returns `Err` if behavior is [`crate::DuplicateBehavior::Error`] and the
    /// tool name already exists.
    pub fn add_tool_with_behavior<H: ToolHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        let def = handler.definition();
        let name = &def.name;

        let existed = self.tools.contains_key(name);
        if existed {
            match behavior {
                crate::DuplicateBehavior::Error => {
                    return Err(duplicate_registration_error("Tool", name));
                }
                crate::DuplicateBehavior::Warn => {
                    log::warn!(
                        target: "fastmcp_rust::router",
                        "tool already exists, keeping original; tool_key={}",
                        safe_log_label(name)
                    );
                    return Ok(());
                }
                crate::DuplicateBehavior::Replace => {
                    log::debug!(
                        target: "fastmcp_rust::router",
                        "replacing tool; tool_key={}",
                        safe_log_label(name)
                    );
                    // Fall through to insert
                }
                crate::DuplicateBehavior::Ignore => {
                    return Ok(());
                }
            }
        }

        self.tools.insert(def.name.clone(), Box::new(handler));
        if !existed {
            self.tool_order.push(def.name);
        }
        Ok(())
    }

    /// Registers the handler for `completion/complete`.
    ///
    /// Completion has one server-wide dispatch target rather than a catalog
    /// entry. Re-registering replaces the prior target, matching the ordinary
    /// component registration semantics.
    pub fn add_completion_handler<H: CompletionHandler + 'static>(&mut self, handler: H) {
        self.completion_handler = Some(Box::new(handler));
    }

    /// Returns whether a `completion/complete` handler is installed.
    #[must_use]
    pub fn has_completion_handler(&self) -> bool {
        self.completion_handler.is_some()
    }

    /// Adds a resource handler.
    ///
    /// If a resource with the same URI already exists, it will be replaced.
    /// Use [`add_resource_with_behavior`](Self::add_resource_with_behavior) for
    /// finer control over duplicate handling.
    pub fn add_resource<H: ResourceHandler + 'static>(&mut self, handler: H) {
        let template = handler.template();
        let def = handler.definition();
        let boxed: BoxedResourceHandler = Box::new(handler);

        if let Some(template) = template {
            let is_new = !self.resource_templates.contains_key(&template.uri_template);
            let entry = ResourceTemplateEntry {
                matcher: UriTemplate::new(&template.uri_template),
                template: template.clone(),
                handler: Some(boxed),
            };
            self.resource_templates
                .insert(template.uri_template.clone(), entry);
            if is_new {
                self.resource_template_order.push(template.uri_template);
            }
            self.rebuild_sorted_template_keys();
        } else {
            let is_new = !self.resources.contains_key(&def.uri);
            self.resources.insert(def.uri.clone(), boxed);
            if is_new {
                self.resource_order.push(def.uri);
            }
        }
    }

    /// Adds a resource handler with specified duplicate behavior.
    ///
    /// Returns `Err` if behavior is [`crate::DuplicateBehavior::Error`] and the
    /// resource URI already exists.
    pub fn add_resource_with_behavior<H: ResourceHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        let template = handler.template();
        let def = handler.definition();

        // Check for duplicates
        let key = match template.as_ref() {
            Some(template) => template.uri_template.clone(),
            None => def.uri.clone(),
        };

        let exists = if template.is_some() {
            self.resource_templates.contains_key(&key)
        } else {
            self.resources.contains_key(&key)
        };

        if exists {
            match behavior {
                crate::DuplicateBehavior::Error => {
                    return Err(duplicate_registration_error("Resource", &key));
                }
                crate::DuplicateBehavior::Warn => {
                    log::warn!(
                        target: "fastmcp_rust::router",
                        "resource already exists, keeping original; resource_key={}",
                        safe_log_label(&key)
                    );
                    return Ok(());
                }
                crate::DuplicateBehavior::Replace => {
                    log::debug!(
                        target: "fastmcp_rust::router",
                        "replacing resource; resource_key={}",
                        safe_log_label(&key)
                    );
                    // Fall through to insert
                }
                crate::DuplicateBehavior::Ignore => {
                    return Ok(());
                }
            }
        }

        // Actually add the resource
        let boxed: BoxedResourceHandler = Box::new(handler);

        if let Some(template) = template {
            let is_new = !self.resource_templates.contains_key(&template.uri_template);
            let entry = ResourceTemplateEntry {
                matcher: UriTemplate::new(&template.uri_template),
                template: template.clone(),
                handler: Some(boxed),
            };
            self.resource_templates
                .insert(template.uri_template.clone(), entry);
            if is_new {
                self.resource_template_order.push(template.uri_template);
            }
            self.rebuild_sorted_template_keys();
        } else {
            let is_new = !self.resources.contains_key(&def.uri);
            self.resources.insert(def.uri.clone(), boxed);
            if is_new {
                self.resource_order.push(def.uri);
            }
        }

        Ok(())
    }

    /// Adds a resource template definition.
    ///
    /// If a template with the same URI template already exists, its definition
    /// is replaced while any registered handler is retained. Use
    /// [`add_resource_template_with_behavior`](Self::add_resource_template_with_behavior)
    /// for finer control over duplicate handling.
    pub fn add_resource_template(&mut self, template: ResourceTemplate) {
        let _ =
            self.add_resource_template_with_behavior(template, crate::DuplicateBehavior::Replace);
    }

    /// Adds a resource template definition with specified duplicate behavior.
    ///
    /// Replacing a definition retains an existing handler registered for the
    /// same URI template. Returns `Err` when behavior is
    /// [`crate::DuplicateBehavior::Error`] and the URI template already exists.
    pub fn add_resource_template_with_behavior(
        &mut self,
        template: ResourceTemplate,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        let key = template.uri_template.clone();
        let existed = self.resource_templates.contains_key(&key);

        if existed {
            match behavior {
                crate::DuplicateBehavior::Error => {
                    return Err(duplicate_registration_error("Resource template", &key));
                }
                crate::DuplicateBehavior::Warn => {
                    log::warn!(
                        target: "fastmcp_rust::router",
                        "resource template already exists, keeping original; template_key={}",
                        safe_log_label(&key)
                    );
                    return Ok(());
                }
                crate::DuplicateBehavior::Replace => {
                    log::debug!(
                        target: "fastmcp_rust::router",
                        "replacing resource template definition; template_key={}",
                        safe_log_label(&key)
                    );
                }
                crate::DuplicateBehavior::Ignore => return Ok(()),
            }
        }

        let matcher = UriTemplate::new(&key);
        let entry = ResourceTemplateEntry {
            matcher,
            template: template.clone(),
            handler: None,
        };
        let needs_rebuild = match self.resource_templates.get_mut(&key) {
            Some(existing) => {
                existing.template = template;
                existing.matcher = entry.matcher;
                false // Key already exists, order unchanged
            }
            None => {
                self.resource_templates.insert(key.clone(), entry);
                true // New key added, need to rebuild
            }
        };
        if needs_rebuild {
            self.resource_template_order.push(key);
            self.rebuild_sorted_template_keys();
        }
        Ok(())
    }

    /// Adds a prompt handler.
    ///
    /// If a prompt with the same name already exists, it will be replaced.
    /// Use [`add_prompt_with_behavior`](Self::add_prompt_with_behavior) for
    /// finer control over duplicate handling.
    pub fn add_prompt<H: PromptHandler + 'static>(&mut self, handler: H) {
        let def = handler.definition();
        let is_new = !self.prompts.contains_key(&def.name);
        self.prompts.insert(def.name.clone(), Box::new(handler));
        if is_new {
            self.prompt_order.push(def.name);
        }
    }

    /// Adds a prompt handler with specified duplicate behavior.
    ///
    /// Returns `Err` if behavior is [`crate::DuplicateBehavior::Error`] and the
    /// prompt name already exists.
    pub fn add_prompt_with_behavior<H: PromptHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        let def = handler.definition();
        let name = &def.name;

        let existed = self.prompts.contains_key(name);
        if existed {
            match behavior {
                crate::DuplicateBehavior::Error => {
                    return Err(duplicate_registration_error("Prompt", name));
                }
                crate::DuplicateBehavior::Warn => {
                    log::warn!(
                        target: "fastmcp_rust::router",
                        "prompt already exists, keeping original; prompt_key={}",
                        safe_log_label(name)
                    );
                    return Ok(());
                }
                crate::DuplicateBehavior::Replace => {
                    log::debug!(
                        target: "fastmcp_rust::router",
                        "replacing prompt; prompt_key={}",
                        safe_log_label(name)
                    );
                    // Fall through to insert
                }
                crate::DuplicateBehavior::Ignore => {
                    return Ok(());
                }
            }
        }

        self.prompts.insert(def.name.clone(), Box::new(handler));
        if !existed {
            self.prompt_order.push(def.name);
        }
        Ok(())
    }

    /// Returns all tool definitions.
    #[must_use]
    pub fn tools(&self) -> Vec<Tool> {
        self.tool_order
            .iter()
            .filter_map(|name| self.tools.get(name))
            .map(|h| h.definition())
            .collect()
    }

    /// Returns tool definitions filtered by session state and tags.
    ///
    /// Tools that have been disabled in the session state will not be included.
    /// If tag filters are provided, tools must match the include/exclude criteria.
    #[must_use]
    pub fn tools_filtered(
        &self,
        session_state: Option<&SessionState>,
        tag_filters: Option<&TagFilters<'_>>,
    ) -> Vec<Tool> {
        self.tool_order
            .iter()
            .filter_map(|name| self.tools.get(name))
            .filter_map(|h| {
                let def = h.definition();
                // Check session state filter
                if let Some(state) = session_state {
                    if !state.is_tool_enabled(&def.name) {
                        return None;
                    }
                }
                // Check tag filters
                if let Some(filters) = tag_filters {
                    if !filters.matches(&def.tags) {
                        return None;
                    }
                }
                Some(def)
            })
            .collect()
    }

    /// Returns all resource definitions.
    #[must_use]
    pub fn resources(&self) -> Vec<Resource> {
        self.resource_order
            .iter()
            .filter_map(|uri| self.resources.get(uri))
            .map(|h| h.definition())
            .collect()
    }

    /// Returns resource definitions filtered by session state and tags.
    ///
    /// Resources that have been disabled in the session state will not be included.
    /// If tag filters are provided, resources must match the include/exclude criteria.
    #[must_use]
    pub fn resources_filtered(
        &self,
        session_state: Option<&SessionState>,
        tag_filters: Option<&TagFilters<'_>>,
    ) -> Vec<Resource> {
        self.resource_order
            .iter()
            .filter_map(|uri| self.resources.get(uri))
            .filter_map(|h| {
                let def = h.definition();
                // Check session state filter
                if let Some(state) = session_state {
                    if !state.is_resource_enabled(&def.uri) {
                        return None;
                    }
                }
                // Check tag filters
                if let Some(filters) = tag_filters {
                    if !filters.matches(&def.tags) {
                        return None;
                    }
                }
                Some(def)
            })
            .collect()
    }

    /// Returns all resource templates.
    #[must_use]
    pub fn resource_templates(&self) -> Vec<ResourceTemplate> {
        self.resource_template_order
            .iter()
            .filter_map(|t| self.resource_templates.get(t))
            .map(|entry| entry.template.clone())
            .collect()
    }

    /// Returns resource templates filtered by session state and tags.
    ///
    /// Templates that have been disabled in the session state will not be included.
    /// If tag filters are provided, templates must match the include/exclude criteria.
    #[must_use]
    pub fn resource_templates_filtered(
        &self,
        session_state: Option<&SessionState>,
        tag_filters: Option<&TagFilters<'_>>,
    ) -> Vec<ResourceTemplate> {
        self.resource_template_order
            .iter()
            .filter_map(|t| self.resource_templates.get(t))
            .filter_map(|entry| {
                // Check session state filter
                if let Some(state) = session_state {
                    if !state.is_resource_enabled(&entry.template.uri_template) {
                        return None;
                    }
                }
                // Check tag filters
                if let Some(filters) = tag_filters {
                    if !filters.matches(&entry.template.tags) {
                        return None;
                    }
                }
                Some(entry.template.clone())
            })
            .collect()
    }

    /// Returns all prompt definitions.
    #[must_use]
    pub fn prompts(&self) -> Vec<Prompt> {
        self.prompt_order
            .iter()
            .filter_map(|name| self.prompts.get(name))
            .map(|h| h.definition())
            .collect()
    }

    /// Returns prompt definitions filtered by session state and tags.
    ///
    /// Prompts that have been disabled in the session state will not be included.
    /// If tag filters are provided, prompts must match the include/exclude criteria.
    #[must_use]
    pub fn prompts_filtered(
        &self,
        session_state: Option<&SessionState>,
        tag_filters: Option<&TagFilters<'_>>,
    ) -> Vec<Prompt> {
        self.prompt_order
            .iter()
            .filter_map(|name| self.prompts.get(name))
            .filter_map(|h| {
                let def = h.definition();
                // Check session state filter
                if let Some(state) = session_state {
                    if !state.is_prompt_enabled(&def.name) {
                        return None;
                    }
                }
                // Check tag filters
                if let Some(filters) = tag_filters {
                    if !filters.matches(&def.tags) {
                        return None;
                    }
                }
                Some(def)
            })
            .collect()
    }

    /// Returns the number of registered tools.
    #[must_use]
    pub fn tools_count(&self) -> usize {
        self.tools.len()
    }

    /// Returns the number of registered resources.
    #[must_use]
    pub fn resources_count(&self) -> usize {
        self.resources.len()
    }

    /// Returns the number of registered resource templates.
    #[must_use]
    pub fn resource_templates_count(&self) -> usize {
        self.resource_templates.len()
    }

    /// Returns the number of registered prompts.
    #[must_use]
    pub fn prompts_count(&self) -> usize {
        self.prompts.len()
    }

    /// Returns the immutable behavior registry for final server discovery.
    ///
    /// This records only APIs backed by this router's installed catalog. The
    /// modern stateless dispatcher has no logging-request emitter,
    /// list-change producer, subscription listener, or resource-update
    /// delivery path, so none of those behaviors can be advertised merely
    /// because adjacent legacy code compiled.
    #[must_use]
    pub(crate) fn server_discovery_behavior_registry(&self) -> ServerBehaviorRegistry {
        let mut behaviors = Vec::with_capacity(4);
        if self.completion_handler.is_some() {
            behaviors.push(ServerBehavior::CompletionComplete);
        }
        if !self.tool_order.is_empty() {
            behaviors.push(ServerBehavior::ToolsList);
        }
        if !self.resource_order.is_empty() || !self.resource_template_order.is_empty() {
            behaviors.push(ServerBehavior::ResourcesList);
        }
        if !self.prompt_order.is_empty() {
            behaviors.push(ServerBehavior::PromptsList);
        }
        ServerBehaviorRegistry::from_behaviors(behaviors)
    }

    /// Gets a tool handler by name.
    #[must_use]
    pub fn get_tool(&self, name: &str) -> Option<&BoxedToolHandler> {
        self.tools.get(name)
    }

    /// Gets a resource handler by URI.
    #[must_use]
    pub fn get_resource(&self, uri: &str) -> Option<&BoxedResourceHandler> {
        self.resources.get(uri)
    }

    /// Gets a resource template by URI template.
    #[must_use]
    pub fn get_resource_template(&self, uri_template: &str) -> Option<&ResourceTemplate> {
        self.resource_templates
            .get(uri_template)
            .map(|entry| &entry.template)
    }

    /// Returns true if a resource exists for the given URI (static or template match).
    #[must_use]
    pub fn resource_exists(&self, uri: &str) -> bool {
        self.resolve_resource(uri).is_some()
    }

    fn resolve_resource(&self, uri: &str) -> Option<ResolvedResource<'_>> {
        if let Some(handler) = self.resources.get(uri) {
            return Some(ResolvedResource {
                handler,
                params: UriParams::new(),
            });
        }

        // Use pre-sorted template keys to avoid sorting on every lookup
        for key in &self.sorted_template_keys {
            let entry = &self.resource_templates[key];
            let Some(handler) = entry.handler.as_ref() else {
                continue;
            };
            if let Some(params) = entry.matcher.matches(uri) {
                return Some(ResolvedResource { handler, params });
            }
        }

        None
    }

    /// Gets a prompt handler by name.
    #[must_use]
    pub fn get_prompt(&self, name: &str) -> Option<&BoxedPromptHandler> {
        self.prompts.get(name)
    }

    // ========================================================================
    // Request Dispatch Methods
    // ========================================================================

    /// Handles the initialize request.
    pub fn handle_initialize(
        &self,
        request_ctx: &McpContext,
        session: &mut Session,
        params: InitializeParams,
        instructions: Option<&str>,
    ) -> McpResult<InitializeResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        debug!(
            target: targets::SESSION,
            "preparing session initialization; client_key={}",
            safe_log_label(&params.client_info.name)
        );

        // Initialize the session
        session.initialize(
            params.client_info,
            params.capabilities,
            PROTOCOL_VERSION.to_string(),
        );

        Ok(InitializeResult {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: session.server_capabilities().clone(),
            server_info: session.server_info().clone(),
            instructions: instructions.map(String::from),
        })
    }

    /// Dispatches one exact legacy `completion/complete` request.
    ///
    /// This route decodes through the dual-era core contract before invoking
    /// the installed handler. In particular, a final `_meta` object remains a
    /// cross-era error even though the legacy parameter shape is otherwise
    /// intentionally open.
    pub(crate) fn dispatch_legacy_completion(
        &self,
        request_ctx: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<serde_json::Value> {
        if request.method != COMPLETION_COMPLETE {
            return Err(McpError::method_not_found(&request.method));
        }

        let request = CoreRequest::decode(
            ProtocolEra::Legacy2024,
            COMPLETION_COMPLETE,
            request.params.as_ref(),
        )
        .map_err(|error| McpError::invalid_params(error.to_string()))?;
        let CoreRequest::Legacy(LegacyCoreRequest::Completion(params)) = request else {
            return Err(McpError::internal_error(
                "legacy completion dispatch selected another core request",
            ));
        };

        serde_json::to_value(self.handle_completion_legacy(request_ctx, params)?)
            .map_err(McpError::from)
    }

    /// Handles one exact MCP 2024-11-05 completion request.
    pub fn handle_completion_legacy(
        &self,
        request_ctx: &McpContext,
        params: LegacyCompletionParams,
    ) -> McpResult<LegacyCompletionResult> {
        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let handler = self
            .completion_handler
            .as_ref()
            .ok_or_else(|| McpError::method_not_found(COMPLETION_COMPLETE))?;
        let handler_ctx = derive_handler_context(request_ctx, None, None, None);
        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "completion_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let handler_ctx = handler_ctx.with_operation_deadline(effective_budget.deadline);
        let outcome = run_handler(&handler_ctx, effective_budget, "completion", || {
            handler.complete_legacy_async(&handler_ctx, params)
        })?;

        let completion = match outcome {
            Outcome::Ok(completion) => completion,
            Outcome::Err(error) => {
                return Err(sanitize_handler_error(
                    request_ctx.cx(),
                    "completion",
                    error,
                ));
            }
            Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => {
                return Err(sanitized_handler_panic(request_ctx.cx(), "completion"));
            }
        };

        Ok(LegacyCompletionResult { completion })
    }

    async fn handle_completion_final_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: FinalCompletionParams,
    ) -> McpResult<FinalCompletionResult> {
        let dispatch_started_at = request_ctx.cx().now();
        if request_cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let handler = self
            .completion_handler
            .as_ref()
            .ok_or_else(|| McpError::method_not_found(COMPLETION_COMPLETE))?;
        let handler_ctx = derive_handler_context(request_ctx, None, None, None);
        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "completion_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let handler_ctx = handler_ctx.with_operation_deadline(effective_budget.deadline);
        let outcome = run_handler_in_request(
            &handler_ctx,
            request_cx,
            effective_budget,
            "completion",
            |child_cx| handler.complete_final_async_in_request(&handler_ctx, child_cx, params),
        )
        .await?;

        let completion = match outcome {
            Outcome::Ok(completion) => completion,
            Outcome::Err(error) => {
                return Err(sanitize_handler_error(
                    request_ctx.cx(),
                    "completion",
                    error,
                ));
            }
            Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => {
                return Err(sanitized_handler_panic(request_ctx.cx(), "completion"));
            }
        };

        Ok(FinalCompletionResult { completion })
    }

    /// Dispatches a request without connection or session state.
    ///
    /// This is the modern server-side routing seam. It deliberately has no
    /// `Session` argument: list results come from the immutable router catalog,
    /// and handler invocations receive a fresh state bag that cannot be shared
    /// with another request or connection. Every successful response is
    /// re-emitted through the final complete-result contract. State-bearing
    /// lifecycle methods and exact 2024-11-05 wire results stay on the legacy
    /// adapter rather than acquiring accidental modern semantics.
    pub(crate) fn dispatch_stateless(
        &self,
        request_ctx: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<serde_json::Value> {
        // The connection-oriented server adapter remains synchronous today.
        // Keep its ordered compatibility semantics here; modern runtime entry
        // points must use `dispatch_stateless_owned` below instead of sharing
        // this blocking bridge.
        block_on(self.dispatch_stateless_in_request(request_ctx, request_ctx.cx(), request))
    }

    /// Dispatches one modern request in a request-owned structured child task.
    ///
    /// The caller owns the returned future. It owns exactly one child task,
    /// waits for that task to finish, and cancellation of that wait aborts the
    /// child through `TaskHandle::join` before control returns. No task is
    /// detached: a result is produced only after the handler task has reached a
    /// terminal state. The child Cx is propagated to the modern handler hooks
    /// so their nested work remains in the same request lifetime.
    pub(crate) async fn dispatch_stateless_owned(
        self: Arc<Self>,
        request_ctx: McpContext,
        request: JsonRpcRequest,
    ) -> McpResult<serde_json::Value> {
        if let Some(error) = budget_error(&request_ctx) {
            return Err(error);
        }

        let join_cx = request_ctx.cx().clone();
        let dispatch_ctx = request_ctx.clone();
        let mut task = request_ctx
            .cx()
            .spawn(move |child_cx| async move {
                self.dispatch_stateless_in_request(&dispatch_ctx, &child_cx, &request)
                    .await
            })
            .map_err(|_error| {
                McpError::internal_error("request-owned modern dispatch could not be scheduled")
            })?;

        match task.join(&join_cx).await {
            Ok(result) => result,
            Err(asupersync::runtime::JoinError::Panicked(_payload)) => {
                Err(sanitized_handler_panic(&join_cx, "modern_dispatch"))
            }
            Err(_error) => Err(McpError::request_cancelled()),
        }
    }

    async fn dispatch_stateless_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        request: &JsonRpcRequest,
    ) -> McpResult<serde_json::Value> {
        if request_cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let params = request.params.clone();
        let result = match request.method.as_str() {
            "ping" => encode_stateless_handler_result(Ok(serde_json::json!({})))?,
            COMPLETION_COMPLETE => {
                let request = CoreRequest::decode(
                    ProtocolEra::Modern2026,
                    COMPLETION_COMPLETE,
                    params.as_ref(),
                )
                .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::Completion(params)) = request else {
                    return Err(McpError::internal_error(
                        "modern completion dispatch selected another core request",
                    ));
                };
                encode_stateless_handler_result(
                    self.handle_completion_final_in_request(request_ctx, request_cx, params)
                        .await,
                )?
            }
            "tools/list" => {
                let request =
                    CoreRequest::decode(ProtocolEra::Modern2026, "tools/list", params.as_ref())
                        .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::ToolsList(params)) = &request else {
                    return Err(McpError::internal_error(
                        "modern tools/list dispatch selected another core request",
                    ));
                };
                let result = self.handle_tools_list(
                    request_ctx,
                    legacy_list_tools_params(params.clone()),
                    None,
                );
                encode_final_core_result(
                    result.and_then(|result| {
                        self.project_final_tools_list(request_ctx, result, self.final_cache_hints)
                    }),
                    |result| FinalCoreResult::ToolsList {
                        result,
                        diagnostic: None,
                    },
                )?
            }
            "tools/call" => {
                let request =
                    CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", params.as_ref())
                        .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::ToolsCall(params)) = request else {
                    return Err(McpError::internal_error(
                        "modern tools/call dispatch selected another core request",
                    ));
                };
                encode_final_tools_call_result(
                    self.handle_tools_call_final_in_request(
                        request_ctx,
                        request_cx,
                        params,
                        SessionState::new(),
                        None,
                        None,
                    )
                    .await,
                )?
            }
            "resources/list" => {
                let request =
                    CoreRequest::decode(ProtocolEra::Modern2026, "resources/list", params.as_ref())
                        .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::ResourcesList(params)) = &request else {
                    return Err(McpError::internal_error(
                        "modern resources/list dispatch selected another core request",
                    ));
                };
                let result = self.handle_resources_list(
                    request_ctx,
                    legacy_list_resources_params(params.clone()),
                    None,
                );
                encode_final_core_result(
                    result.and_then(|result| {
                        self.project_final_resources_list(
                            request_ctx,
                            result,
                            self.final_cache_hints,
                        )
                    }),
                    |result| FinalCoreResult::ResourcesList {
                        result,
                        diagnostic: None,
                    },
                )?
            }
            "resources/templates/list" => {
                let request = CoreRequest::decode(
                    ProtocolEra::Modern2026,
                    "resources/templates/list",
                    params.as_ref(),
                )
                .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::ResourceTemplatesList(params)) = &request
                else {
                    return Err(McpError::internal_error(
                        "modern resources/templates/list dispatch selected another core request",
                    ));
                };
                let result = self.handle_resource_templates_list(
                    request_ctx,
                    legacy_list_resource_templates_params(params.clone()),
                    None,
                );
                encode_final_core_result(
                    result.and_then(|result| {
                        self.project_final_resource_templates_list(
                            request_ctx,
                            result,
                            self.final_cache_hints,
                        )
                    }),
                    |result| FinalCoreResult::ResourceTemplatesList {
                        result,
                        diagnostic: None,
                    },
                )?
            }
            "resources/read" => {
                let request =
                    CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", params.as_ref())
                        .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::ResourcesRead(params)) = &request else {
                    return Err(McpError::internal_error(
                        "modern resources/read dispatch selected another core request",
                    ));
                };
                let params = legacy_read_resource_params(params.clone());
                let result = self
                    .handle_resources_read_in_request(
                        request_ctx,
                        request_cx,
                        &params,
                        SessionState::new(),
                        None,
                        None,
                    )
                    .await;
                encode_final_core_result(
                    result.and_then(|result| {
                        Self::project_final_resources_read(result, self.final_cache_hints)
                    }),
                    |result| FinalCoreResult::ResourcesRead {
                        result,
                        diagnostic: None,
                    },
                )?
            }
            "prompts/list" => {
                let request =
                    CoreRequest::decode(ProtocolEra::Modern2026, "prompts/list", params.as_ref())
                        .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::PromptsList(params)) = &request else {
                    return Err(McpError::internal_error(
                        "modern prompts/list dispatch selected another core request",
                    ));
                };
                let result = self.handle_prompts_list(
                    request_ctx,
                    legacy_list_prompts_params(params.clone()),
                    None,
                );
                encode_final_core_result(
                    result.and_then(|result| {
                        self.project_final_prompts_list(request_ctx, result, self.final_cache_hints)
                    }),
                    |result| FinalCoreResult::PromptsList {
                        result,
                        diagnostic: None,
                    },
                )?
            }
            "prompts/get" => {
                let params = parse_stateless_params(params)?;
                encode_stateless_handler_result(
                    self.handle_prompts_get_in_request(
                        request_ctx,
                        request_cx,
                        params,
                        SessionState::new(),
                        None,
                        None,
                    )
                    .await,
                )?
            }
            _ => return Err(McpError::method_not_found(&request.method)),
        };

        if request_cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        Ok(result)
    }

    /// Handles the tools/list request.
    ///
    /// If session_state is provided, disabled tools will be filtered out.
    /// If include_tags/exclude_tags are provided, tools are filtered by tags.
    pub fn handle_tools_list(
        &self,
        request_ctx: &McpContext,
        params: ListToolsParams,
        session_state: Option<&SessionState>,
    ) -> McpResult<ListToolsResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let tag_filters =
            TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let tag_filters = if params.include_tags.is_some() || params.exclude_tags.is_some() {
            Some(&tag_filters)
        } else {
            None
        };
        let tools =
            crate::catch_extension_unwind(|| self.tools_filtered(session_state, tag_filters))
                .map_err(|_payload| sanitized_handler_panic(request_ctx.cx(), "tool_definition"))?;
        let Some(page_size) = self.list_page_size else {
            return Ok(ListToolsResult {
                tools,
                next_cursor: None,
            });
        };

        let offset = decode_cursor_offset(params.cursor.as_deref())?;
        let end = offset.saturating_add(page_size).min(tools.len());
        let next_cursor = if end < tools.len() {
            Some(encode_cursor_offset(end))
        } else {
            None
        };
        Ok(ListToolsResult {
            tools: tools.get(offset..end).unwrap_or_default().to_vec(),
            next_cursor,
        })
    }

    fn project_final_tools_list(
        &self,
        request_ctx: &McpContext,
        result: ListToolsResult,
        cache_hints: FinalCacheHintPolicy,
    ) -> McpResult<FinalListToolsResult> {
        let tools = result
            .tools
            .into_iter()
            .map(|tool| {
                let handler = self.tools.get(&tool.name).ok_or_else(|| {
                    McpError::internal_error("listed tool is absent from the router catalog")
                })?;
                let (title, icons, meta) = crate::catch_extension_unwind(|| {
                    (
                        handler.final_title().map(str::to_owned),
                        handler.final_icons().map(|icons| icons.to_vec()),
                        handler.final_metadata().cloned(),
                    )
                })
                .map_err(|_payload| sanitized_handler_panic(request_ctx.cx(), "tool_definition"))?;

                Ok(FinalTool {
                    name: tool.name,
                    title,
                    description: tool.description,
                    input_schema: tool.input_schema,
                    output_schema: tool.output_schema,
                    annotations: tool.annotations.map(project_final_tool_annotations),
                    icons,
                    meta,
                })
            })
            .collect::<McpResult<Vec<_>>>()?;
        Ok(FinalListToolsResult {
            tools,
            next_cursor: result.next_cursor,
            ttl_ms: cache_hints.list_ttl_ms,
            cache_scope: cache_hints.scope,
        })
    }

    fn project_final_resources_list(
        &self,
        request_ctx: &McpContext,
        result: ListResourcesResult,
        cache_hints: FinalCacheHintPolicy,
    ) -> McpResult<FinalListResourcesResult> {
        let resources = result
            .resources
            .into_iter()
            .map(|resource| {
                let handler = self.resources.get(&resource.uri).ok_or_else(|| {
                    McpError::internal_error("listed resource is absent from the router catalog")
                })?;
                let (title, icons, annotations, meta) = crate::catch_extension_unwind(|| {
                    (
                        handler.final_title().map(str::to_owned),
                        handler.final_icons().map(|icons| icons.to_vec()),
                        handler.final_annotations().cloned(),
                        handler.final_metadata().cloned(),
                    )
                })
                .map_err(|_payload| {
                    sanitized_handler_panic(request_ctx.cx(), "resource_definition")
                })?;
                project_final_resource_catalog_entry(resource, title, icons, annotations, meta)
            })
            .collect::<McpResult<Vec<_>>>()?;
        Ok(FinalListResourcesResult {
            resources,
            next_cursor: result.next_cursor,
            ttl_ms: cache_hints.list_ttl_ms,
            cache_scope: cache_hints.scope,
        })
    }

    fn project_final_resource_templates_list(
        &self,
        request_ctx: &McpContext,
        result: ListResourceTemplatesResult,
        cache_hints: FinalCacheHintPolicy,
    ) -> McpResult<FinalListResourceTemplatesResult> {
        let resource_templates = result
            .resource_templates
            .into_iter()
            .map(|template| {
                let entry = self
                    .resource_templates
                    .get(&template.uri_template)
                    .ok_or_else(|| {
                        McpError::internal_error(
                            "listed resource template is absent from the router catalog",
                        )
                    })?;
                let (title, icons, annotations, meta) = match entry.handler.as_deref() {
                    Some(handler) => crate::catch_extension_unwind(|| {
                        (
                            handler.final_template_title().map(str::to_owned),
                            handler.final_template_icons().map(|icons| icons.to_vec()),
                            handler.final_template_annotations().cloned(),
                            handler.final_template_metadata().cloned(),
                        )
                    })
                    .map_err(|_payload| {
                        sanitized_handler_panic(request_ctx.cx(), "resource_definition")
                    })?,
                    None => (None, None, None, None),
                };

                Ok(FinalResourceTemplate {
                    uri_template: template.uri_template,
                    name: template.name,
                    title,
                    description: template.description,
                    icons,
                    mime_type: template.mime_type,
                    annotations,
                    meta,
                })
            })
            .collect::<McpResult<Vec<_>>>()?;
        Ok(FinalListResourceTemplatesResult {
            resource_templates,
            next_cursor: result.next_cursor,
            ttl_ms: cache_hints.list_ttl_ms,
            cache_scope: cache_hints.scope,
        })
    }

    fn project_final_prompts_list(
        &self,
        request_ctx: &McpContext,
        result: ListPromptsResult,
        cache_hints: FinalCacheHintPolicy,
    ) -> McpResult<FinalListPromptsResult> {
        let prompts = result
            .prompts
            .into_iter()
            .map(|prompt| {
                let handler = self.prompts.get(&prompt.name).ok_or_else(|| {
                    McpError::internal_error("listed prompt is absent from the router catalog")
                })?;
                let (title, icons, meta) = crate::catch_extension_unwind(|| {
                    (
                        handler.final_title().map(str::to_owned),
                        handler.final_icons().map(|icons| icons.to_vec()),
                        handler.final_metadata().cloned(),
                    )
                })
                .map_err(|_payload| {
                    sanitized_handler_panic(request_ctx.cx(), "prompt_definition")
                })?;
                let Prompt {
                    name,
                    description,
                    arguments,
                    ..
                } = prompt;
                let arguments = (!arguments.is_empty()).then(|| {
                    arguments
                        .into_iter()
                        .map(|argument| FinalPromptArgument {
                            name: argument.name,
                            title: None,
                            description: argument.description,
                            required: Some(argument.required),
                        })
                        .collect()
                });
                Ok(FinalPrompt {
                    name,
                    title,
                    description,
                    icons,
                    arguments,
                    meta,
                })
            })
            .collect::<McpResult<Vec<_>>>()?;
        Ok(FinalListPromptsResult {
            prompts,
            next_cursor: result.next_cursor,
            ttl_ms: cache_hints.list_ttl_ms,
            cache_scope: cache_hints.scope,
        })
    }

    fn project_final_resources_read(
        result: ReadResourceResult,
        cache_hints: FinalCacheHintPolicy,
    ) -> McpResult<FinalReadResourceResult> {
        let contents = result
            .contents
            .into_iter()
            .map(promote_resource_content)
            .collect::<McpResult<Vec<_>>>()?;
        Ok(FinalReadResourceResult {
            contents,
            ttl_ms: cache_hints.resource_read_ttl_ms,
            cache_scope: cache_hints.scope,
        })
    }

    /// Handles the tools/call request.
    ///
    /// # Arguments
    ///
    /// * `request_ctx` - Request authority for cancellation, identity, auth, and accounting
    /// * `params` - The tool call parameters including tool name and arguments
    /// * `session_state` - Session state for per-session storage
    /// * `notification_sender` - Optional callback for sending progress notifications
    /// * `bidirectional_senders` - Optional senders for sampling/elicitation
    pub fn handle_tools_call(
        &self,
        request_ctx: &McpContext,
        params: CallToolParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<CallToolResult> {
        debug!(
            target: targets::HANDLER,
            "calling tool; tool_key={}; arguments_present={}",
            safe_log_label(&params.name),
            params.arguments.is_some()
        );

        // Anchor every relative ceiling once at dispatch entry. Definition/schema
        // work and timeout metadata lookup are part of this operation and must
        // not reset a handler-declared window by taking a later clock sample.
        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        // Check if tool is disabled for this session
        if !session_state.is_tool_enabled(&params.name) {
            return Err(McpError::new(
                McpErrorCode::MethodNotFound,
                format!("Tool '{}' is disabled for this session", params.name),
            ));
        }

        // Find the tool handler
        let handler = self
            .tools
            .get(&params.name)
            .ok_or_else(|| McpError::method_not_found(&format!("tool: {}", params.name)))?;

        // Validate arguments against the tool's input schema
        // Default to empty object since MCP tool arguments are always objects
        let arguments = params.arguments.unwrap_or_else(|| serde_json::json!({}));
        let tool_def = crate::catch_extension_unwind(|| handler.definition())
            .map_err(|_payload| sanitized_handler_panic(request_ctx.cx(), "tool_definition"))?;

        // Use strict or lenient validation based on configuration
        let validation_result = if self.strict_input_validation {
            validate_strict(&tool_def.input_schema, &arguments)
        } else {
            validate(&tool_def.input_schema, &arguments)
        };

        if let Err(validation_errors) = validation_result {
            let error_messages: Vec<String> = validation_errors
                .iter()
                .map(|e| format!("{}: {}", e.path, e.message))
                .collect();
            return Err(McpError::invalid_params(format!(
                "Input validation failed: {}",
                error_messages.join("; ")
            )));
        }

        // Extract progress marker from request metadata
        let progress_marker: Option<ProgressMarker> =
            params.meta.as_ref().and_then(|m| m.progress_marker.clone());

        // Clone the request authority so auth, budget accounting, cancellation,
        // and mask state remain shared with middleware and nested operations.
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
        );

        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "tool_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);

        // Call the handler asynchronously - returns McpOutcome (4-valued)
        let outcome = run_handler(&ctx, effective_budget, "tool", || {
            handler.call_async(&ctx, arguments)
        })?;
        match outcome {
            Outcome::Ok(content) => Ok(CallToolResult {
                content,
                is_error: false,
            }),
            Outcome::Err(e) => {
                let e = sanitize_handler_error(request_ctx.cx(), "tool", e);
                if is_framework_terminal_tool_error(e.code) {
                    return Err(e);
                }

                // Tool errors are returned as content with is_error=true
                Ok(CallToolResult {
                    content: vec![Content::Text { text: e.message }],
                    is_error: true,
                })
            }
            Outcome::Cancelled(_) => {
                // Cancelled requests are reported as JSON-RPC errors
                Err(McpError::request_cancelled())
            }
            Outcome::Panicked(_payload) => Err(sanitized_handler_panic(request_ctx.cx(), "tool")),
        }
    }

    async fn handle_tools_call_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: CallToolParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<CallToolResult> {
        debug!(
            target: targets::HANDLER,
            "calling modern tool; tool_key={}; arguments_present={}",
            safe_log_label(&params.name),
            params.arguments.is_some()
        );

        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        if !session_state.is_tool_enabled(&params.name) {
            return Err(McpError::new(
                McpErrorCode::MethodNotFound,
                format!("Tool '{}' is disabled for this session", params.name),
            ));
        }

        let handler = self
            .tools
            .get(&params.name)
            .ok_or_else(|| McpError::method_not_found(&format!("tool: {}", params.name)))?;
        let arguments = params.arguments.unwrap_or_else(|| serde_json::json!({}));
        let tool_def = crate::catch_extension_unwind(|| handler.definition())
            .map_err(|_payload| sanitized_handler_panic(request_ctx.cx(), "tool_definition"))?;
        let validation_result = if self.strict_input_validation {
            validate_strict(&tool_def.input_schema, &arguments)
        } else {
            validate(&tool_def.input_schema, &arguments)
        };
        if let Err(validation_errors) = validation_result {
            let error_messages: Vec<String> = validation_errors
                .iter()
                .map(|error| format!("{}: {}", error.path, error.message))
                .collect();
            return Err(McpError::invalid_params(format!(
                "Input validation failed: {}",
                error_messages.join("; ")
            )));
        }

        let progress_marker = params
            .meta
            .as_ref()
            .and_then(|meta| meta.progress_marker.clone());
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
        );
        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "tool_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);
        let outcome =
            run_handler_in_request(&ctx, request_cx, effective_budget, "tool", |child_cx| {
                handler.call_async_in_request(&ctx, child_cx, arguments)
            })
            .await?;

        match outcome {
            Outcome::Ok(content) => Ok(CallToolResult {
                content,
                is_error: false,
            }),
            Outcome::Err(error) => {
                let error = sanitize_handler_error(request_ctx.cx(), "tool", error);
                if is_framework_terminal_tool_error(error.code) {
                    return Err(error);
                }
                Ok(CallToolResult {
                    content: vec![Content::Text {
                        text: error.message,
                    }],
                    is_error: true,
                })
            }
            Outcome::Cancelled(_) => Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => Err(sanitized_handler_panic(request_ctx.cx(), "tool")),
        }
    }

    /// Handles one final MCP 2026-07-28 `tools/call` request.
    ///
    /// Legacy dispatch remains on [`Self::handle_tools_call`], including its
    /// exact `CallToolResult` behavior. Final dispatch calls the final handler
    /// hook directly and encodes the returned complete result with the typed
    /// core result codec.
    async fn handle_tools_call_final_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: FinalCallToolParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<CompleteResult<FinalCallToolResult>> {
        debug!(
            target: targets::HANDLER,
            "calling final tool; tool_key={}; arguments_present={}",
            safe_log_label(&params.name),
            params.arguments.is_some()
        );

        let dispatch_started_at = request_ctx.cx().now();
        if request_cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        if !session_state.is_tool_enabled(&params.name) {
            return Err(McpError::new(
                McpErrorCode::MethodNotFound,
                format!("Tool '{}' is disabled for this session", params.name),
            ));
        }

        let handler = self
            .tools
            .get(&params.name)
            .ok_or_else(|| McpError::method_not_found(&format!("tool: {}", params.name)))?;
        let arguments = params.arguments.unwrap_or_else(|| serde_json::json!({}));
        let tool_def = crate::catch_extension_unwind(|| handler.definition())
            .map_err(|_payload| sanitized_handler_panic(request_ctx.cx(), "tool_definition"))?;
        let validation_result = if self.strict_input_validation {
            validate_strict(&tool_def.input_schema, &arguments)
        } else {
            validate(&tool_def.input_schema, &arguments)
        };
        if let Err(validation_errors) = validation_result {
            let error_messages: Vec<String> = validation_errors
                .iter()
                .map(|error| format!("{}: {}", error.path, error.message))
                .collect();
            return Err(McpError::invalid_params(format!(
                "Input validation failed: {}",
                error_messages.join("; ")
            )));
        }

        let ctx = derive_handler_context(
            request_ctx,
            None,
            notification_sender,
            bidirectional_senders,
        );
        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "tool_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);
        let outcome =
            run_handler_in_request(&ctx, request_cx, effective_budget, "tool", |child_cx| {
                handler.call_final_async_in_request(&ctx, child_cx, arguments)
            })
            .await?;

        match outcome {
            Outcome::Ok(result) => Ok(result),
            Outcome::Err(error) => {
                let error = sanitize_handler_error(request_ctx.cx(), "tool", error);
                if is_framework_terminal_tool_error(error.code) {
                    return Err(error);
                }
                let mut result =
                    crate::handler::promote_legacy_tool_content(vec![Content::Text {
                        text: error.message,
                    }])?;
                result.payload.is_error = true;
                Ok(result)
            }
            Outcome::Cancelled(_) => Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => Err(sanitized_handler_panic(request_ctx.cx(), "tool")),
        }
    }

    /// Handles the resources/list request.
    ///
    /// If session_state is provided, disabled resources will be filtered out.
    /// If include_tags/exclude_tags are provided, resources are filtered by tags.
    pub fn handle_resources_list(
        &self,
        request_ctx: &McpContext,
        params: ListResourcesParams,
        session_state: Option<&SessionState>,
    ) -> McpResult<ListResourcesResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let tag_filters =
            TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let tag_filters = if params.include_tags.is_some() || params.exclude_tags.is_some() {
            Some(&tag_filters)
        } else {
            None
        };
        let resources = crate::catch_extension_unwind(|| {
            self.resources_filtered(session_state, tag_filters)
        })
        .map_err(|_payload| sanitized_handler_panic(request_ctx.cx(), "resource_definition"))?;
        let Some(page_size) = self.list_page_size else {
            return Ok(ListResourcesResult {
                resources,
                next_cursor: None,
            });
        };

        let offset = decode_cursor_offset(params.cursor.as_deref())?;
        let end = offset.saturating_add(page_size).min(resources.len());
        let next_cursor = if end < resources.len() {
            Some(encode_cursor_offset(end))
        } else {
            None
        };
        Ok(ListResourcesResult {
            resources: resources.get(offset..end).unwrap_or_default().to_vec(),
            next_cursor,
        })
    }

    /// Handles the resources/templates/list request.
    ///
    /// If session_state is provided, disabled resource templates will be filtered out.
    /// If include_tags/exclude_tags are provided, templates are filtered by tags.
    pub fn handle_resource_templates_list(
        &self,
        request_ctx: &McpContext,
        params: ListResourceTemplatesParams,
        session_state: Option<&SessionState>,
    ) -> McpResult<ListResourceTemplatesResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let tag_filters =
            TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let tag_filters = if params.include_tags.is_some() || params.exclude_tags.is_some() {
            Some(&tag_filters)
        } else {
            None
        };
        let templates = self.resource_templates_filtered(session_state, tag_filters);
        let Some(page_size) = self.list_page_size else {
            return Ok(ListResourceTemplatesResult {
                resource_templates: templates,
                next_cursor: None,
            });
        };

        let offset = decode_cursor_offset(params.cursor.as_deref())?;
        let end = offset.saturating_add(page_size).min(templates.len());
        let next_cursor = if end < templates.len() {
            Some(encode_cursor_offset(end))
        } else {
            None
        };
        Ok(ListResourceTemplatesResult {
            resource_templates: templates.get(offset..end).unwrap_or_default().to_vec(),
            next_cursor,
        })
    }

    /// Handles the resources/read request.
    ///
    /// # Arguments
    ///
    /// * `request_ctx` - Request authority for cancellation, identity, auth, and accounting
    /// * `params` - The resource read parameters including URI
    /// * `session_state` - Session state for per-session storage
    /// * `notification_sender` - Optional callback for sending progress notifications
    /// * `bidirectional_senders` - Optional senders for sampling/elicitation
    pub fn handle_resources_read(
        &self,
        request_ctx: &McpContext,
        params: &ReadResourceParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<ReadResourceResult> {
        debug!(
            target: targets::HANDLER,
            "reading resource; resource_key={}",
            safe_log_label(&params.uri)
        );

        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        // Check if resource is disabled for this session
        if !session_state.is_resource_enabled(&params.uri) {
            return Err(McpError::new(
                McpErrorCode::ResourceNotFound,
                format!("Resource '{}' is disabled for this session", params.uri),
            ));
        }

        let resolved = self
            .resolve_resource(&params.uri)
            .ok_or_else(|| McpError::resource_not_found(&params.uri))?;

        // Extract progress marker from request metadata
        let progress_marker: Option<ProgressMarker> =
            params.meta.as_ref().and_then(|m| m.progress_marker.clone());

        // Clone the request authority so auth, budget accounting, cancellation,
        // and mask state remain shared with middleware and nested operations.
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
        );

        let handler_timeout = read_handler_timeout(request_ctx.cx(), "resource_timeout", || {
            resolved.handler.timeout()
        })?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);

        // Read the resource asynchronously - returns McpOutcome (4-valued)
        let outcome = run_handler(&ctx, effective_budget, "resource", || {
            resolved
                .handler
                .read_async_with_uri(&ctx, &params.uri, &resolved.params)
        })?;

        // Convert 4-valued Outcome to McpResult for JSON-RPC response
        let contents = match outcome {
            Outcome::Ok(contents) => contents,
            Outcome::Err(error) => {
                return Err(sanitize_handler_error(request_ctx.cx(), "resource", error));
            }
            Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => {
                return Err(sanitized_handler_panic(request_ctx.cx(), "resource"));
            }
        };

        Ok(ReadResourceResult { contents })
    }

    async fn handle_resources_read_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: &ReadResourceParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<ReadResourceResult> {
        debug!(
            target: targets::HANDLER,
            "reading modern resource; resource_key={}",
            safe_log_label(&params.uri)
        );

        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        if !session_state.is_resource_enabled(&params.uri) {
            return Err(McpError::new(
                McpErrorCode::ResourceNotFound,
                format!("Resource '{}' is disabled for this session", params.uri),
            ));
        }

        let resolved = self
            .resolve_resource(&params.uri)
            .ok_or_else(|| McpError::resource_not_found(&params.uri))?;
        let progress_marker = params
            .meta
            .as_ref()
            .and_then(|meta| meta.progress_marker.clone());
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
        );
        let handler_timeout = read_handler_timeout(request_ctx.cx(), "resource_timeout", || {
            resolved.handler.timeout()
        })?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);
        let outcome =
            run_handler_in_request(&ctx, request_cx, effective_budget, "resource", |child_cx| {
                resolved.handler.read_async_with_uri_in_request(
                    &ctx,
                    child_cx,
                    &params.uri,
                    &resolved.params,
                )
            })
            .await?;

        let contents = match outcome {
            Outcome::Ok(contents) => contents,
            Outcome::Err(error) => {
                return Err(sanitize_handler_error(request_ctx.cx(), "resource", error));
            }
            Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => {
                return Err(sanitized_handler_panic(request_ctx.cx(), "resource"));
            }
        };

        Ok(ReadResourceResult { contents })
    }

    /// Handles the prompts/list request.
    ///
    /// If session_state is provided, disabled prompts will be filtered out.
    /// If include_tags/exclude_tags are provided, prompts are filtered by tags.
    pub fn handle_prompts_list(
        &self,
        request_ctx: &McpContext,
        params: ListPromptsParams,
        session_state: Option<&SessionState>,
    ) -> McpResult<ListPromptsResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let tag_filters =
            TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let tag_filters = if params.include_tags.is_some() || params.exclude_tags.is_some() {
            Some(&tag_filters)
        } else {
            None
        };
        let prompts =
            crate::catch_extension_unwind(|| self.prompts_filtered(session_state, tag_filters))
                .map_err(|_payload| {
                    sanitized_handler_panic(request_ctx.cx(), "prompt_definition")
                })?;
        let Some(page_size) = self.list_page_size else {
            return Ok(ListPromptsResult {
                prompts,
                next_cursor: None,
            });
        };

        let offset = decode_cursor_offset(params.cursor.as_deref())?;
        let end = offset.saturating_add(page_size).min(prompts.len());
        let next_cursor = if end < prompts.len() {
            Some(encode_cursor_offset(end))
        } else {
            None
        };
        Ok(ListPromptsResult {
            prompts: prompts.get(offset..end).unwrap_or_default().to_vec(),
            next_cursor,
        })
    }

    /// Handles the prompts/get request.
    ///
    /// # Arguments
    ///
    /// * `request_ctx` - Request authority for cancellation, identity, auth, and accounting
    /// * `params` - The prompt get parameters including name and arguments
    /// * `session_state` - Session state for per-session storage
    /// * `notification_sender` - Optional callback for sending progress notifications
    /// * `bidirectional_senders` - Optional senders for sampling/elicitation
    pub fn handle_prompts_get(
        &self,
        request_ctx: &McpContext,
        params: GetPromptParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<GetPromptResult> {
        debug!(
            target: targets::HANDLER,
            "getting prompt; prompt_key={}; arguments_present={}",
            safe_log_label(&params.name),
            params.arguments.is_some()
        );

        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        // Check if prompt is disabled for this session
        if !session_state.is_prompt_enabled(&params.name) {
            return Err(McpError::new(
                McpErrorCode::PromptNotFound,
                format!("Prompt '{}' is disabled for this session", params.name),
            ));
        }

        // Find the prompt handler
        let handler = self.prompts.get(&params.name).ok_or_else(|| {
            McpError::new(
                fastmcp_core::McpErrorCode::PromptNotFound,
                format!("Prompt not found: {}", params.name),
            )
        })?;
        let description = crate::catch_extension_unwind(|| handler.definition().description)
            .map_err(|_payload| sanitized_handler_panic(request_ctx.cx(), "prompt_definition"))?;

        // Extract progress marker from request metadata
        let progress_marker: Option<ProgressMarker> =
            params.meta.as_ref().and_then(|m| m.progress_marker.clone());

        // Clone the request authority so auth, budget accounting, cancellation,
        // and mask state remain shared with middleware and nested operations.
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
        );

        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "prompt_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);

        // Get the prompt asynchronously - returns McpOutcome (4-valued)
        let arguments = params.arguments.unwrap_or_default();
        let outcome = run_handler(&ctx, effective_budget, "prompt", || {
            handler.get_async(&ctx, arguments)
        })?;

        // Convert 4-valued Outcome to McpResult for JSON-RPC response
        let messages = match outcome {
            Outcome::Ok(messages) => messages,
            Outcome::Err(error) => {
                return Err(sanitize_handler_error(request_ctx.cx(), "prompt", error));
            }
            Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => {
                return Err(sanitized_handler_panic(request_ctx.cx(), "prompt"));
            }
        };

        Ok(GetPromptResult {
            description,
            messages,
        })
    }

    async fn handle_prompts_get_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: GetPromptParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<GetPromptResult> {
        debug!(
            target: targets::HANDLER,
            "getting modern prompt; prompt_key={}; arguments_present={}",
            safe_log_label(&params.name),
            params.arguments.is_some()
        );

        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        if !session_state.is_prompt_enabled(&params.name) {
            return Err(McpError::new(
                McpErrorCode::PromptNotFound,
                format!("Prompt '{}' is disabled for this session", params.name),
            ));
        }

        let handler = self.prompts.get(&params.name).ok_or_else(|| {
            McpError::new(
                McpErrorCode::PromptNotFound,
                format!("Prompt not found: {}", params.name),
            )
        })?;
        let description = crate::catch_extension_unwind(|| handler.definition().description)
            .map_err(|_payload| sanitized_handler_panic(request_ctx.cx(), "prompt_definition"))?;
        let progress_marker = params
            .meta
            .as_ref()
            .and_then(|meta| meta.progress_marker.clone());
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
        );
        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "prompt_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);
        let arguments = params.arguments.unwrap_or_default();
        let outcome =
            run_handler_in_request(&ctx, request_cx, effective_budget, "prompt", |child_cx| {
                handler.get_async_in_request(&ctx, child_cx, arguments)
            })
            .await?;

        let messages = match outcome {
            Outcome::Ok(messages) => messages,
            Outcome::Err(error) => {
                return Err(sanitize_handler_error(request_ctx.cx(), "prompt", error));
            }
            Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => {
                return Err(sanitized_handler_panic(request_ctx.cx(), "prompt"));
            }
        };

        Ok(GetPromptResult {
            description,
            messages,
        })
    }

    // ========================================================================
    // Task Dispatch Methods (Docket/SEP-1686)
    // ========================================================================

    /// Handles the tasks/list request.
    ///
    /// Lists all background tasks, optionally filtered by status.
    #[cfg(test)]
    pub fn handle_tasks_list(
        &self,
        request_ctx: &McpContext,
        params: ListTasksParams,
        task_manager: Option<&SharedTaskManager>,
    ) -> McpResult<ListTasksResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let task_manager = task_manager.ok_or_else(|| {
            McpError::new(
                McpErrorCode::MethodNotFound,
                "Background tasks not enabled on this server",
            )
        })?;

        debug!(
            target: targets::HANDLER,
            "listing tasks; status_filter_present={}",
            params.status.is_some()
        );

        let mut tasks = task_manager.list_tasks(params.status);
        // Stable ordering for pagination: created_at then id.
        tasks.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.0.cmp(&b.id.0))
        });

        let limit = params.limit.unwrap_or(50).max(1) as usize;
        let offset = decode_cursor_offset(params.cursor.as_deref())?;
        let end = offset.saturating_add(limit).min(tasks.len());
        let next_cursor = if end < tasks.len() {
            Some(encode_cursor_offset(end))
        } else {
            None
        };

        Ok(ListTasksResult {
            tasks: tasks.get(offset..end).unwrap_or_default().to_vec(),
            next_cursor,
        })
    }

    /// Handles the tasks/get request.
    ///
    /// Gets information about a specific task, including its result if completed.
    #[cfg(test)]
    pub fn handle_tasks_get(
        &self,
        request_ctx: &McpContext,
        params: GetTaskParams,
        task_manager: Option<&SharedTaskManager>,
    ) -> McpResult<GetTaskResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let task_manager = task_manager.ok_or_else(|| {
            McpError::new(
                McpErrorCode::MethodNotFound,
                "Background tasks not enabled on this server",
            )
        })?;

        debug!(
            target: targets::HANDLER,
            "getting task; task_key={}",
            safe_log_label(params.id.as_str())
        );

        let task = task_manager
            .get_info(&params.id)
            .ok_or_else(|| McpError::invalid_params(format!("Task not found: {}", params.id)))?;

        let result = task_manager.get_result(&params.id);

        Ok(GetTaskResult { task, result })
    }

    /// Handles the tasks/cancel request.
    ///
    /// Requests cancellation of a running or pending task.
    #[cfg(test)]
    pub fn handle_tasks_cancel(
        &self,
        request_ctx: &McpContext,
        params: CancelTaskParams,
        task_manager: Option<&SharedTaskManager>,
    ) -> McpResult<CancelTaskResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let task_manager = task_manager.ok_or_else(|| {
            McpError::new(
                McpErrorCode::MethodNotFound,
                "Background tasks not enabled on this server",
            )
        })?;

        debug!(
            target: targets::HANDLER,
            "cancelling task; task_key={}; reason_present={}",
            safe_log_label(params.id.as_str()),
            params.reason.is_some()
        );

        let task = task_manager.cancel(&params.id, params.reason)?;

        Ok(CancelTaskResult {
            cancelled: true,
            task,
        })
    }

    /// Handles the tasks/submit request.
    ///
    /// Submits a new background task for execution.
    #[cfg(test)]
    pub fn handle_tasks_submit(
        &self,
        request_ctx: &McpContext,
        params: SubmitTaskParams,
        task_manager: Option<&SharedTaskManager>,
    ) -> McpResult<SubmitTaskResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let task_manager = task_manager.ok_or_else(|| {
            McpError::new(
                McpErrorCode::MethodNotFound,
                "Background tasks not enabled on this server",
            )
        })?;

        debug!(
            target: targets::HANDLER,
            "submitting task; task_type_key={}; params_present={}",
            safe_log_label(&params.task_type),
            params.params.is_some()
        );

        let task_id = task_manager.submit(request_ctx.cx(), &params.task_type, params.params)?;
        let task = task_manager
            .get_info(&task_id)
            .ok_or_else(|| McpError::internal_error("Task created but not found"))?;

        Ok(SubmitTaskResult { task })
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Mount/Composition Support
// ============================================================================

/// Result of a mount operation.
#[derive(Debug, Default)]
pub struct MountResult {
    /// Number of tools mounted.
    pub tools: usize,
    /// Number of resources mounted.
    pub resources: usize,
    /// Number of resource templates mounted.
    pub resource_templates: usize,
    /// Number of prompts mounted.
    pub prompts: usize,
    /// Any warnings generated during mounting (e.g., name conflicts).
    pub warnings: Vec<String>,
    /// Errors that caused the mount operation to be rejected.
    ///
    /// A rejected mount does not mutate the destination router.
    pub errors: Vec<String>,
}

impl MountResult {
    /// Returns true if any components were mounted.
    #[must_use]
    pub fn has_components(&self) -> bool {
        self.tools > 0 || self.resources > 0 || self.resource_templates > 0 || self.prompts > 0
    }

    /// Returns true if mounting was not rejected.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }

    fn merge(&mut self, other: Self) {
        self.tools += other.tools;
        self.resources += other.resources;
        self.resource_templates += other.resource_templates;
        self.prompts += other.prompts;
        self.warnings.extend(other.warnings);
        self.errors.extend(other.errors);
    }
}

#[derive(Clone, Copy)]
enum MountSelection {
    All,
    Tools,
    Resources,
    Prompts,
}

impl MountSelection {
    const fn includes_tools(self) -> bool {
        matches!(self, Self::All | Self::Tools)
    }

    const fn includes_resources(self) -> bool {
        matches!(self, Self::All | Self::Resources)
    }

    const fn includes_prompts(self) -> bool {
        matches!(self, Self::All | Self::Prompts)
    }
}

impl Router {
    /// Applies a prefix to a name or URI.
    fn apply_prefix(name: &str, prefix: Option<&str>) -> String {
        match prefix {
            Some(p) if !p.is_empty() => format!("{}/{}", p, name),
            _ => name.to_string(),
        }
    }

    /// Validates a prefix string.
    ///
    /// Prefixes must be alphanumeric plus underscores and hyphens,
    /// and cannot contain slashes.
    fn validate_prefix(prefix: &str) -> Result<(), String> {
        if prefix.is_empty() {
            return Ok(());
        }
        if prefix.contains('/') {
            return Err("Invalid mount prefix: slashes are not permitted".to_string());
        }
        // Allow alphanumeric, underscore, hyphen
        for ch in prefix.chars() {
            if !ch.is_alphanumeric() && ch != '_' && ch != '-' {
                return Err(
                    "Invalid mount prefix: invalid characters are not permitted".to_string()
                );
            }
        }
        Ok(())
    }

    fn mount_preflight(
        &self,
        other: &Self,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
        selection: MountSelection,
    ) -> MountResult {
        let mut result = MountResult::default();

        if let Some(prefix) = prefix {
            if let Err(error) = Self::validate_prefix(prefix) {
                // Keep the warning for callers of the original API while also
                // recording the rejection as a real failure.
                result.warnings.push(error.clone());
                result.errors.push(error);
                return result;
            }
        }

        if behavior != crate::DuplicateBehavior::Error {
            return result;
        }

        let mut conflicts = Vec::new();
        if selection.includes_tools() {
            for name in other.tools.keys() {
                let mounted_name = Self::apply_prefix(name, prefix);
                if self.tools.contains_key(&mounted_name) {
                    conflicts.push(("Tool", mounted_name));
                }
            }
        }
        if selection.includes_resources() {
            for uri in other.resources.keys() {
                let mounted_uri = Self::apply_prefix(uri, prefix);
                if self.resources.contains_key(&mounted_uri) {
                    conflicts.push(("Resource", mounted_uri));
                }
            }
            for uri_template in other.resource_templates.keys() {
                let mounted_uri_template = Self::apply_prefix(uri_template, prefix);
                if self.resource_templates.contains_key(&mounted_uri_template) {
                    conflicts.push(("Resource template", mounted_uri_template));
                }
            }
        }
        if selection.includes_prompts() {
            for name in other.prompts.keys() {
                let mounted_name = Self::apply_prefix(name, prefix);
                if self.prompts.contains_key(&mounted_name) {
                    conflicts.push(("Prompt", mounted_name));
                }
            }
        }

        conflicts.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(&b.1)));
        result
            .errors
            .extend(conflicts.into_iter().map(|(kind, key)| {
                format!(
                    "Mount rejected because {kind} already exists; component_key={}",
                    safe_log_label(&key)
                )
            }));
        result
    }

    fn should_mount_duplicate(
        behavior: crate::DuplicateBehavior,
        kind: &'static str,
        key: &str,
        result: &mut MountResult,
    ) -> bool {
        match behavior {
            crate::DuplicateBehavior::Error => {
                result.errors.push(format!(
                    "Mount rejected because {kind} already exists; component_key={}",
                    safe_log_label(key)
                ));
                false
            }
            crate::DuplicateBehavior::Warn => {
                result.warnings.push(format!(
                    "{kind} already exists, keeping original; component_key={}",
                    safe_log_label(key)
                ));
                false
            }
            crate::DuplicateBehavior::Replace => {
                result.warnings.push(format!(
                    "{kind} already exists, replacing original; component_key={}",
                    safe_log_label(key)
                ));
                true
            }
            crate::DuplicateBehavior::Ignore => false,
        }
    }

    /// Mounts all handlers from another router with an optional prefix.
    ///
    /// This consumes the source router and moves its handlers into this router.
    /// Names/URIs are prefixed with `prefix/` if a prefix is provided.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut main_router = Router::new();
    /// let db_router = Router::new();
    /// // ... add handlers to db_router ...
    ///
    /// main_router.mount(db_router, Some("db"));
    /// // Tool "query" becomes "db/query"
    /// ```
    pub fn mount(&mut self, other: Router, prefix: Option<&str>) -> MountResult {
        self.mount_with_behavior(other, prefix, crate::DuplicateBehavior::Replace)
    }

    /// Mounts all handlers using the specified duplicate behavior.
    ///
    /// Prefix validation happens before any destination mutation. With
    /// [`crate::DuplicateBehavior::Error`], every selected component is
    /// preflighted and any conflict rejects the entire mount atomically.
    pub fn mount_with_behavior(
        &mut self,
        other: Router,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        let preflight = self.mount_preflight(&other, prefix, behavior, MountSelection::All);
        if !preflight.is_success() {
            return preflight;
        }

        let mut result = preflight;

        let Router {
            tools,
            tool_order,
            resources,
            resource_order,
            prompts,
            prompt_order,
            resource_templates,
            resource_template_order,
            ..
        } = other;

        // Mount tools
        result.merge(self.mount_tools_from(tools, tool_order, prefix, behavior));

        // Mount resources
        result.merge(self.mount_resources_from(resources, resource_order, prefix, behavior));

        // Mount resource templates
        result.merge(self.mount_resource_templates_from(
            resource_templates,
            resource_template_order,
            prefix,
            behavior,
        ));

        // Mount prompts
        result.merge(self.mount_prompts_from(prompts, prompt_order, prefix, behavior));

        // Log mount result
        if result.has_components() {
            debug!(
                target: targets::HANDLER,
                "mounted {} tools, {} resources, {} templates, {} prompts; prefix_present={}; prefix_key={}",
                result.tools,
                result.resources,
                result.resource_templates,
                result.prompts,
                prefix.is_some(),
                safe_log_label(prefix.unwrap_or_default())
            );
        }

        result
    }

    /// Mounts only tools from a router.
    pub fn mount_tools(&mut self, other: Router, prefix: Option<&str>) -> MountResult {
        self.mount_tools_with_behavior(other, prefix, crate::DuplicateBehavior::Replace)
    }

    /// Mounts only tools using the specified duplicate behavior.
    pub fn mount_tools_with_behavior(
        &mut self,
        other: Router,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        let preflight = self.mount_preflight(&other, prefix, behavior, MountSelection::Tools);
        if !preflight.is_success() {
            return preflight;
        }
        self.mount_tools_from(other.tools, other.tool_order, prefix, behavior)
    }

    /// Internal: mount tools from a HashMap.
    fn mount_tools_from(
        &mut self,
        mut tools: HashMap<String, BoxedToolHandler>,
        tool_order: Vec<String>,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        use crate::handler::MountedToolHandler;

        let mut result = MountResult::default();

        for name in tool_order {
            let Some(handler) = tools.remove(&name) else {
                continue;
            };
            let mounted_name = Self::apply_prefix(&name, prefix);
            trace!(
                target: targets::HANDLER,
                "mounting tool; source_key={}; mounted_key={}",
                safe_log_label(&name),
                safe_log_label(&mounted_name)
            );

            // Check for conflicts
            let existed = self.tools.contains_key(&mounted_name);
            if existed
                && !Self::should_mount_duplicate(behavior, "Tool", &mounted_name, &mut result)
            {
                continue;
            }

            // Wrap with mounted name and insert
            let mounted = MountedToolHandler::new(handler, mounted_name.clone());
            let needs_order_push = !existed && !self.tool_order.iter().any(|n| n == &mounted_name);
            self.tools.insert(mounted_name.clone(), Box::new(mounted));
            if needs_order_push {
                self.tool_order.push(mounted_name);
            }
            result.tools += 1;
        }

        if !tools.is_empty() {
            // Defensive: older Routers or unusual construction could leave items untracked by
            // tool_order. Mount them deterministically to avoid HashMap iteration order leaks.
            let mut remaining: Vec<(String, BoxedToolHandler)> = tools.into_iter().collect();
            remaining.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, handler) in remaining {
                let mounted_name = Self::apply_prefix(&name, prefix);

                let existed = self.tools.contains_key(&mounted_name);
                if existed
                    && !Self::should_mount_duplicate(behavior, "Tool", &mounted_name, &mut result)
                {
                    continue;
                }

                let mounted = MountedToolHandler::new(handler, mounted_name.clone());
                self.tools.insert(mounted_name.clone(), Box::new(mounted));
                if !existed && !self.tool_order.iter().any(|n| n == &mounted_name) {
                    self.tool_order.push(mounted_name);
                }
                result.tools += 1;
            }
        }

        result
    }

    /// Mounts only resources from a router.
    pub fn mount_resources(&mut self, other: Router, prefix: Option<&str>) -> MountResult {
        self.mount_resources_with_behavior(other, prefix, crate::DuplicateBehavior::Replace)
    }

    /// Mounts resources and resource templates using the specified duplicate
    /// behavior.
    pub fn mount_resources_with_behavior(
        &mut self,
        other: Router,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        let preflight = self.mount_preflight(&other, prefix, behavior, MountSelection::Resources);
        if !preflight.is_success() {
            return preflight;
        }

        let Router {
            resources,
            resource_order,
            resource_templates,
            resource_template_order,
            ..
        } = other;
        let mut result = preflight;
        result.merge(self.mount_resources_from(resources, resource_order, prefix, behavior));
        let template_result = self.mount_resource_templates_from(
            resource_templates,
            resource_template_order,
            prefix,
            behavior,
        );
        result.merge(template_result);
        result
    }

    /// Internal: mount resources from a HashMap.
    fn mount_resources_from(
        &mut self,
        mut resources: HashMap<String, BoxedResourceHandler>,
        resource_order: Vec<String>,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        use crate::handler::MountedResourceHandler;

        let mut result = MountResult::default();

        for uri in resource_order {
            let Some(handler) = resources.remove(&uri) else {
                continue;
            };
            let mounted_uri = Self::apply_prefix(&uri, prefix);
            trace!(
                target: targets::HANDLER,
                "mounting resource; source_key={}; mounted_key={}",
                safe_log_label(&uri),
                safe_log_label(&mounted_uri)
            );

            // Check for conflicts
            let existed = self.resources.contains_key(&mounted_uri);
            if existed
                && !Self::should_mount_duplicate(behavior, "Resource", &mounted_uri, &mut result)
            {
                continue;
            }

            // Wrap with mounted URI and insert
            let mounted = MountedResourceHandler::new(handler, uri.clone(), mounted_uri.clone());
            let needs_order_push =
                !existed && !self.resource_order.iter().any(|u| u == &mounted_uri);
            self.resources
                .insert(mounted_uri.clone(), Box::new(mounted));
            if needs_order_push {
                self.resource_order.push(mounted_uri);
            }
            result.resources += 1;
        }

        if !resources.is_empty() {
            let mut remaining: Vec<(String, BoxedResourceHandler)> =
                resources.into_iter().collect();
            remaining.sort_by(|a, b| a.0.cmp(&b.0));
            for (uri, handler) in remaining {
                let mounted_uri = Self::apply_prefix(&uri, prefix);

                let existed = self.resources.contains_key(&mounted_uri);
                if existed
                    && !Self::should_mount_duplicate(
                        behavior,
                        "Resource",
                        &mounted_uri,
                        &mut result,
                    )
                {
                    continue;
                }

                let mounted = MountedResourceHandler::new(handler, uri, mounted_uri.clone());
                self.resources
                    .insert(mounted_uri.clone(), Box::new(mounted));
                if !existed && !self.resource_order.iter().any(|u| u == &mounted_uri) {
                    self.resource_order.push(mounted_uri);
                }
                result.resources += 1;
            }
        }

        result
    }

    /// Internal: mount resource templates from a HashMap.
    fn mount_resource_templates_from(
        &mut self,
        mut templates: HashMap<String, ResourceTemplateEntry>,
        resource_template_order: Vec<String>,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        use crate::handler::MountedResourceHandler;

        let mut result = MountResult::default();

        for uri_template in resource_template_order {
            let Some(entry) = templates.remove(&uri_template) else {
                continue;
            };
            let mounted_uri_template = Self::apply_prefix(&uri_template, prefix);
            trace!(
                target: targets::HANDLER,
                "mounting resource template; source_key={}; mounted_key={}",
                safe_log_label(&uri_template),
                safe_log_label(&mounted_uri_template)
            );

            // Check for conflicts
            let existed = self.resource_templates.contains_key(&mounted_uri_template);
            if existed
                && !Self::should_mount_duplicate(
                    behavior,
                    "Resource template",
                    &mounted_uri_template,
                    &mut result,
                )
            {
                continue;
            }

            // Create new template with mounted URI
            let mut mounted_template = entry.template.clone();
            mounted_template.uri_template = mounted_uri_template.clone();

            // Wrap handler if present
            let mounted_handler = entry.handler.map(|h| {
                let wrapped: BoxedResourceHandler =
                    Box::new(MountedResourceHandler::with_template(
                        h,
                        uri_template.clone(),
                        mounted_uri_template.clone(),
                        mounted_template.clone(),
                    ));
                wrapped
            });

            // Create new entry with mounted template
            let mounted_entry = ResourceTemplateEntry {
                matcher: UriTemplate::new(&mounted_uri_template),
                template: mounted_template,
                handler: mounted_handler,
            };

            let needs_order_push = !existed
                && !self
                    .resource_template_order
                    .iter()
                    .any(|t| t == &mounted_uri_template);
            self.resource_templates
                .insert(mounted_uri_template.clone(), mounted_entry);
            if needs_order_push {
                self.resource_template_order.push(mounted_uri_template);
            }
            result.resource_templates += 1;
        }

        if !templates.is_empty() {
            let mut remaining: Vec<(String, ResourceTemplateEntry)> =
                templates.into_iter().collect();
            remaining.sort_by(|a, b| a.0.cmp(&b.0));
            for (uri_template, entry) in remaining {
                let mounted_uri_template = Self::apply_prefix(&uri_template, prefix);

                let existed = self.resource_templates.contains_key(&mounted_uri_template);
                if existed
                    && !Self::should_mount_duplicate(
                        behavior,
                        "Resource template",
                        &mounted_uri_template,
                        &mut result,
                    )
                {
                    continue;
                }

                let mut mounted_template = entry.template.clone();
                mounted_template.uri_template = mounted_uri_template.clone();

                let mounted_handler = entry.handler.map(|h| {
                    let wrapped: BoxedResourceHandler =
                        Box::new(MountedResourceHandler::with_template(
                            h,
                            uri_template,
                            mounted_uri_template.clone(),
                            mounted_template.clone(),
                        ));
                    wrapped
                });

                let mounted_entry = ResourceTemplateEntry {
                    matcher: UriTemplate::new(&mounted_uri_template),
                    template: mounted_template,
                    handler: mounted_handler,
                };

                self.resource_templates
                    .insert(mounted_uri_template.clone(), mounted_entry);
                if !existed
                    && !self
                        .resource_template_order
                        .iter()
                        .any(|t| t == &mounted_uri_template)
                {
                    self.resource_template_order
                        .push(mounted_uri_template.clone());
                }
                result.resource_templates += 1;
            }
        }

        // Rebuild sorted keys if we added templates
        if result.resource_templates > 0 {
            self.rebuild_sorted_template_keys();
        }

        result
    }

    /// Mounts only prompts from a router.
    pub fn mount_prompts(&mut self, other: Router, prefix: Option<&str>) -> MountResult {
        self.mount_prompts_with_behavior(other, prefix, crate::DuplicateBehavior::Replace)
    }

    /// Mounts only prompts using the specified duplicate behavior.
    pub fn mount_prompts_with_behavior(
        &mut self,
        other: Router,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        let preflight = self.mount_preflight(&other, prefix, behavior, MountSelection::Prompts);
        if !preflight.is_success() {
            return preflight;
        }
        self.mount_prompts_from(other.prompts, other.prompt_order, prefix, behavior)
    }

    /// Internal: mount prompts from a HashMap.
    fn mount_prompts_from(
        &mut self,
        mut prompts: HashMap<String, BoxedPromptHandler>,
        prompt_order: Vec<String>,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        use crate::handler::MountedPromptHandler;

        let mut result = MountResult::default();

        for name in prompt_order {
            let Some(handler) = prompts.remove(&name) else {
                continue;
            };
            let mounted_name = Self::apply_prefix(&name, prefix);
            trace!(
                target: targets::HANDLER,
                "mounting prompt; source_key={}; mounted_key={}",
                safe_log_label(&name),
                safe_log_label(&mounted_name)
            );

            // Check for conflicts
            let existed = self.prompts.contains_key(&mounted_name);
            if existed
                && !Self::should_mount_duplicate(behavior, "Prompt", &mounted_name, &mut result)
            {
                continue;
            }

            // Wrap with mounted name and insert
            let mounted = MountedPromptHandler::new(handler, mounted_name.clone());
            let needs_order_push =
                !existed && !self.prompt_order.iter().any(|n| n == &mounted_name);
            self.prompts.insert(mounted_name.clone(), Box::new(mounted));
            if needs_order_push {
                self.prompt_order.push(mounted_name);
            }
            result.prompts += 1;
        }

        if !prompts.is_empty() {
            let mut remaining: Vec<(String, BoxedPromptHandler)> = prompts.into_iter().collect();
            remaining.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, handler) in remaining {
                let mounted_name = Self::apply_prefix(&name, prefix);

                let existed = self.prompts.contains_key(&mounted_name);
                if existed
                    && !Self::should_mount_duplicate(behavior, "Prompt", &mounted_name, &mut result)
                {
                    continue;
                }

                let mounted = MountedPromptHandler::new(handler, mounted_name.clone());
                self.prompts.insert(mounted_name.clone(), Box::new(mounted));
                if !existed && !self.prompt_order.iter().any(|n| n == &mounted_name) {
                    self.prompt_order.push(mounted_name);
                }
                result.prompts += 1;
            }
        }

        result
    }

    /// Consumes the router and returns its internal handlers.
    ///
    /// This is used internally for mounting operations.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        HashMap<String, BoxedToolHandler>,
        HashMap<String, BoxedResourceHandler>,
        HashMap<String, ResourceTemplateEntry>,
        HashMap<String, BoxedPromptHandler>,
    ) {
        (
            self.tools,
            self.resources,
            self.resource_templates,
            self.prompts,
        )
    }
}

struct ResolvedResource<'a> {
    handler: &'a BoxedResourceHandler,
    params: UriParams,
}

/// Entry for a resource template with its matcher and optional handler.
pub(crate) struct ResourceTemplateEntry {
    pub(crate) matcher: UriTemplate,
    pub(crate) template: ResourceTemplate,
    pub(crate) handler: Option<BoxedResourceHandler>,
}

/// A parsed URI template for matching resource URIs.
#[derive(Debug, Clone)]
pub(crate) struct UriTemplate {
    pattern: String,
    segments: Vec<UriSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UriTemplateError {
    UnclosedParam,
    UnmatchedClose,
    EmptyParam,
    UnsupportedOperator,
    InvalidParamName,
    DuplicateParam(String),
    TooComplex,
}

impl UriTemplateError {
    const fn log_class(&self) -> &'static str {
        match self {
            Self::UnclosedParam => "unclosed_parameter",
            Self::UnmatchedClose => "unmatched_close",
            Self::EmptyParam => "empty_parameter",
            Self::UnsupportedOperator => "unsupported_operator",
            Self::InvalidParamName => "invalid_parameter_name",
            Self::DuplicateParam(_) => "duplicate_parameter",
            Self::TooComplex => "too_complex",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UriExpansion {
    Simple,
    Reserved,
}

#[derive(Debug, Clone)]
enum UriSegment {
    Literal(String),
    Param {
        name: String,
        expansion: UriExpansion,
    },
}

// Matching an interior reserved expansion may require trying more than one
// occurrence of its following literal. Bound recursion, input bytes, literal
// scans, capture validation, decoding, and aggregate split work so an
// adversarial URI cannot turn template matching into unbounded work.
const MAX_URI_TEMPLATE_MATCH_SEGMENTS: usize = 256;
const MAX_URI_TEMPLATE_INPUT_BYTES: usize = 64 * 1_024;
const MAX_URI_TEMPLATE_MATCH_WORK_BYTES: usize = 1_024 * 1_024;
const MAX_URI_TEMPLATE_SPLIT_ATTEMPTS: usize = 4_096;

impl UriTemplate {
    /// Creates a new URI template from a pattern.
    ///
    /// If the pattern is invalid, logs a warning and returns a template
    /// that will never match any URI (fail-safe behavior).
    fn new(pattern: &str) -> Self {
        Self::try_new(pattern).unwrap_or_else(|err| {
            fastmcp_core::logging::warn!(
                target: targets::HANDLER,
                "invalid URI template; template_key={}; error_class={}; using non-matching fallback",
                safe_log_label(pattern),
                err.log_class()
            );
            // Return a template with no segments that can never match
            Self {
                pattern: pattern.to_string(),
                segments: vec![UriSegment::Literal("\0INVALID\0".to_string())],
            }
        })
    }

    /// Attempts to create a URI template, returning an error if invalid.
    fn try_new(pattern: &str) -> Result<Self, UriTemplateError> {
        Self::parse(pattern)
    }

    fn parse(pattern: &str) -> Result<Self, UriTemplateError> {
        let mut segments = Vec::new();
        let mut literal = String::new();
        let mut chars = pattern.chars().peekable();
        let mut seen = std::collections::HashSet::new();

        while let Some(ch) = chars.next() {
            match ch {
                '{' => {
                    if matches!(chars.peek(), Some('{')) {
                        let _ = chars.next();
                        literal.push('{');
                        continue;
                    }

                    if !literal.is_empty() {
                        segments.push(UriSegment::Literal(std::mem::take(&mut literal)));
                        if segments.len() > MAX_URI_TEMPLATE_MATCH_SEGMENTS {
                            return Err(UriTemplateError::TooComplex);
                        }
                    }

                    let mut expression = String::new();
                    let mut closed = false;
                    for next in chars.by_ref() {
                        if next == '}' {
                            closed = true;
                            break;
                        }
                        expression.push(next);
                    }

                    if !closed {
                        return Err(UriTemplateError::UnclosedParam);
                    }

                    if expression.is_empty() {
                        return Err(UriTemplateError::EmptyParam);
                    }

                    let (expansion, name) = match expression.as_bytes().first().copied() {
                        Some(b'+') => (UriExpansion::Reserved, &expression[1..]),
                        Some(b'#' | b'.' | b'/' | b';' | b'?' | b'&') => {
                            return Err(UriTemplateError::UnsupportedOperator);
                        }
                        Some(_) => (UriExpansion::Simple, expression.as_str()),
                        None => return Err(UriTemplateError::EmptyParam),
                    };

                    if name.is_empty() {
                        return Err(UriTemplateError::EmptyParam);
                    }
                    if !is_valid_uri_variable_name(name) {
                        return Err(UriTemplateError::InvalidParamName);
                    }
                    if !seen.insert(name.to_string()) {
                        return Err(UriTemplateError::DuplicateParam(name.to_string()));
                    }
                    segments.push(UriSegment::Param {
                        name: name.to_string(),
                        expansion,
                    });
                    if segments.len() > MAX_URI_TEMPLATE_MATCH_SEGMENTS {
                        return Err(UriTemplateError::TooComplex);
                    }
                }
                '}' => {
                    if matches!(chars.peek(), Some('}')) {
                        let _ = chars.next();
                        literal.push('}');
                        continue;
                    }
                    return Err(UriTemplateError::UnmatchedClose);
                }
                _ => literal.push(ch),
            }
        }

        if !literal.is_empty() {
            segments.push(UriSegment::Literal(literal));
            if segments.len() > MAX_URI_TEMPLATE_MATCH_SEGMENTS {
                return Err(UriTemplateError::TooComplex);
            }
        }

        Ok(Self {
            pattern: pattern.to_string(),
            segments,
        })
    }

    fn specificity(&self) -> (usize, usize, usize) {
        let mut literal_len = 0usize;
        let mut literal_segments = 0usize;
        for segment in &self.segments {
            if let UriSegment::Literal(lit) = segment {
                literal_len += lit.len();
                literal_segments += 1;
            }
        }
        (literal_len, literal_segments, self.segments.len())
    }

    fn matches(&self, uri: &str) -> Option<UriParams> {
        if self.segments.len() > MAX_URI_TEMPLATE_MATCH_SEGMENTS
            || uri.len() > MAX_URI_TEMPLATE_INPUT_BYTES
        {
            return None;
        }

        let mut captures = Vec::new();
        captures.try_reserve(self.segments.len()).ok()?;
        let mut split_attempts = 0usize;
        let mut remaining_work = MAX_URI_TEMPLATE_MATCH_WORK_BYTES;
        match_uri_segments(
            &self.segments,
            0,
            uri,
            0,
            &mut captures,
            &mut split_attempts,
            &mut remaining_work,
        )
    }
}

fn match_uri_segments<'template, 'uri>(
    segments: &'template [UriSegment],
    segment_index: usize,
    uri: &'uri str,
    offset: usize,
    captures: &mut Vec<(&'template str, &'uri str)>,
    split_attempts: &mut usize,
    remaining_work: &mut usize,
) -> Option<UriParams> {
    let Some(segment) = segments.get(segment_index) else {
        if offset != uri.len() {
            return None;
        }

        // Delay decoding and allocation until a complete structural match is
        // found. Failed backtracking candidates therefore retain only slices
        // into the pattern and input URI.
        let mut params = UriParams::new();
        params.try_reserve(captures.len()).ok()?;
        for &(name, raw_value) in captures.iter() {
            consume_uri_template_match_work(remaining_work, raw_value.len())?;
            params.insert(name.to_string(), percent_decode(raw_value)?);
        }
        return Some(params);
    };

    let remainder = uri.get(offset..)?;
    match segment {
        UriSegment::Literal(literal) => {
            consume_uri_template_match_work(remaining_work, literal.len())?;
            remainder.strip_prefix(literal)?;
            match_uri_segments(
                segments,
                segment_index + 1,
                uri,
                offset.checked_add(literal.len())?,
                captures,
                split_attempts,
                remaining_work,
            )
        }
        UriSegment::Param { name, expansion } => match segments.get(segment_index + 1) {
            Some(UriSegment::Param { .. }) => None,
            Some(UriSegment::Literal(literal)) => {
                // Try delimiters from right to left. Reserved expansions are
                // greedy, but a later delimiter may make the remaining
                // template impossible, so retain bounded backtracking.
                consume_uri_template_match_work(remaining_work, remainder.len())?;
                for (delimiter_offset, _) in remainder.rmatch_indices(literal.as_str()) {
                    *split_attempts = split_attempts.checked_add(1)?;
                    if *split_attempts > MAX_URI_TEMPLATE_SPLIT_ATTEMPTS {
                        return None;
                    }

                    let raw_value = &remainder[..delimiter_offset];
                    if raw_value.is_empty() {
                        continue;
                    }
                    consume_uri_template_match_work(remaining_work, raw_value.len())?;
                    if !raw_capture_is_valid(raw_value, *expansion) {
                        continue;
                    }

                    captures.push((name.as_str(), raw_value));
                    let matched = match_uri_segments(
                        segments,
                        segment_index + 1,
                        uri,
                        offset.checked_add(delimiter_offset)?,
                        captures,
                        split_attempts,
                        remaining_work,
                    );
                    captures.pop();
                    if matched.is_some() {
                        return matched;
                    }
                }
                None
            }
            None => {
                if remainder.is_empty() {
                    return None;
                }
                consume_uri_template_match_work(remaining_work, remainder.len())?;
                if !raw_capture_is_valid(remainder, *expansion) {
                    return None;
                }

                captures.push((name.as_str(), remainder));
                let matched = match_uri_segments(
                    segments,
                    segment_index + 1,
                    uri,
                    uri.len(),
                    captures,
                    split_attempts,
                    remaining_work,
                );
                captures.pop();
                matched
            }
        },
    }
}

fn consume_uri_template_match_work(remaining_work: &mut usize, bytes: usize) -> Option<()> {
    *remaining_work = (*remaining_work).checked_sub(bytes)?;
    Some(())
}

/// Validates the raw character grammar for the supported RFC 6570 expansion
/// subset. Simple expansions admit only unreserved ASCII or valid `%HH`
/// triplets; reserved expansions additionally admit RFC 3986 reserved ASCII.
fn raw_capture_is_valid(raw: &str, expansion: UriExpansion) -> bool {
    let bytes = raw.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || from_hex(bytes[index + 1]).is_none()
                || from_hex(bytes[index + 2]).is_none()
            {
                return false;
            }
            index += 3;
            continue;
        }

        if is_uri_unreserved(byte) || (expansion == UriExpansion::Reserved && is_uri_reserved(byte))
        {
            index += 1;
            continue;
        }
        return false;
    }
    true
}

const fn is_uri_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

const fn is_uri_reserved(byte: u8) -> bool {
    matches!(
        byte,
        b':' | b'/'
            | b'?'
            | b'#'
            | b'['
            | b']'
            | b'@'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
    )
}

/// Validates the unencoded ASCII subset of an RFC 6570 variable name.
///
/// A variable name is one or more non-empty dot-separated components made up
/// of ASCII letters, digits, or `_`. Percent-encoded names, variable lists,
/// explode modifiers, and prefix modifiers are intentionally outside the
/// narrow template subset implemented by this matcher.
fn is_valid_uri_variable_name(name: &str) -> bool {
    name.split('.').all(|component| {
        !component.is_empty()
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn percent_decode(input: &str) -> Option<String> {
    if !input.as_bytes().contains(&b'%') {
        return Some(input.to_string());
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = bytes[i + 1];
                let lo = bytes[i + 2];
                let value = (from_hex(hi)? << 4) | from_hex(lo)?;
                out.push(value);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// ============================================================================
// Resource Reader Implementation
// ============================================================================

use fastmcp_core::{
    MAX_RESOURCE_READ_DEPTH, ResourceContentItem, ResourceReadResult, ResourceReader,
};
use std::pin::Pin;

/// A wrapper that implements `ResourceReader` for a shared `Router`.
///
/// This allows handlers to read resources from within tool/resource/prompt
/// handlers, enabling cross-component access.
#[derive(Clone)]
enum RouterAccess {
    Shared(Arc<Router>),
    RequestScoped(Weak<Router>),
}

impl RouterAccess {
    fn upgrade(&self) -> McpResult<Arc<Router>> {
        match self {
            Self::Shared(router) => Ok(Arc::clone(router)),
            Self::RequestScoped(router) => router.upgrade().ok_or_else(|| {
                McpError::new(
                    McpErrorCode::RequestCancelled,
                    "Request router is no longer available",
                )
            }),
        }
    }
}

pub(crate) struct RouterResourceReader {
    /// Access to the router without extending a server request's lifetime.
    router: RouterAccess,
    /// Session state for handlers.
    session_state: SessionState,
}

impl RouterResourceReader {
    /// Creates a new resource reader with the given router and session state.
    #[must_use]
    pub(crate) fn new(router: Arc<Router>, session_state: SessionState) -> Self {
        Self {
            router: RouterAccess::Shared(router),
            session_state,
        }
    }

    pub(crate) fn request_scoped(router: Weak<Router>, session_state: SessionState) -> Self {
        Self {
            router: RouterAccess::RequestScoped(router),
            session_state,
        }
    }

    fn from_access(router: RouterAccess, session_state: SessionState) -> Self {
        Self {
            router,
            session_state,
        }
    }
}

impl ResourceReader for RouterResourceReader {
    fn read_resource<'a>(
        &'a self,
        parent_ctx: &'a McpContext,
        uri: &'a str,
        depth: u32,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = fastmcp_core::McpResult<ResourceReadResult>>
                + Send
                + 'a,
        >,
    > {
        // Check recursion depth
        if depth > MAX_RESOURCE_READ_DEPTH {
            return Box::pin(async move {
                Err(McpError::new(
                    McpErrorCode::InternalError,
                    format!(
                        "Maximum resource read depth ({}) exceeded",
                        MAX_RESOURCE_READ_DEPTH
                    ),
                ))
            });
        }

        // Clone what we need for the async block
        let parent_ctx = parent_ctx.clone();
        let uri = uri.to_string();
        let router_access = self.router.clone();
        let session_state = self.session_state.clone();

        Box::pin(async move {
            debug!(
                target: targets::HANDLER,
                "cross-component resource read; resource_key={}; depth={}; request={}",
                safe_log_label(&uri),
                depth,
                parent_ctx.request_id()
            );
            let router = router_access.upgrade()?;
            let operation_started_at = parent_ctx.cx().now();
            if let Some(error) = budget_error(&parent_ctx) {
                return Err(error);
            }
            if !session_state.is_resource_enabled(&uri) {
                return Err(McpError::new(
                    McpErrorCode::ResourceNotFound,
                    format!("Resource '{}' is disabled for this session", uri),
                ));
            }

            // Resolve the resource
            let resolved = router.resolve_resource(&uri).ok_or_else(|| {
                McpError::new(
                    McpErrorCode::ResourceNotFound,
                    format!("Resource not found: {}", uri),
                )
            })?;
            let handler_timeout =
                read_handler_timeout(parent_ctx.cx(), "resource_timeout", || {
                    resolved.handler.timeout()
                })?;
            let effective_budget = compose_handler_budget(
                parent_ctx.cx().budget(),
                parent_ctx.budget(),
                handler_timeout,
                operation_started_at,
            );

            // Derive the child from the parent request authority, preserving
            // auth, mask state, budget accounting, and request identity.
            let nested_router = router_access.clone();
            let nested_state = session_state.clone();
            let child_ctx = parent_ctx
                .clone()
                .with_operation_deadline(effective_budget.deadline)
                .with_resource_read_depth(depth)
                .with_tool_call_depth(depth)
                .with_tool_caller(Arc::new(RouterToolCaller::from_access(
                    nested_router.clone(),
                    nested_state.clone(),
                )))
                .with_resource_reader(Arc::new(RouterResourceReader::from_access(
                    nested_router,
                    nested_state,
                )));

            // Read the resource
            let outcome = run_handler(&child_ctx, effective_budget, "resource", || {
                resolved
                    .handler
                    .read_async_with_uri(&child_ctx, &uri, &resolved.params)
            })?;

            // Convert outcome to result
            let contents = match outcome {
                Outcome::Ok(contents) => contents,
                Outcome::Err(error) => {
                    return Err(sanitize_handler_error(parent_ctx.cx(), "resource", error));
                }
                Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
                Outcome::Panicked(_payload) => {
                    return Err(sanitized_handler_panic(parent_ctx.cx(), "resource"));
                }
            };

            // Convert protocol ResourceContent to core ResourceContentItem
            let items: Vec<ResourceContentItem> = contents
                .into_iter()
                .map(|c| ResourceContentItem {
                    uri: c.uri,
                    mime_type: c.mime_type,
                    text: c.text,
                    blob: c.blob,
                })
                .collect();

            Ok(ResourceReadResult::new(items))
        })
    }
}

// ============================================================================
// Tool Caller Implementation
// ============================================================================

use fastmcp_core::{MAX_TOOL_CALL_DEPTH, ToolCallResult, ToolCaller, ToolContentItem};

/// A wrapper that implements `ToolCaller` for a shared `Router`.
///
/// This allows handlers to call other tools from within tool/resource/prompt
/// handlers, enabling cross-component access.
pub(crate) struct RouterToolCaller {
    /// Access to the router without extending a server request's lifetime.
    router: RouterAccess,
    /// Session state for handlers.
    session_state: SessionState,
}

impl RouterToolCaller {
    /// Creates a new tool caller with the given router and session state.
    #[must_use]
    pub(crate) fn new(router: Arc<Router>, session_state: SessionState) -> Self {
        Self {
            router: RouterAccess::Shared(router),
            session_state,
        }
    }

    pub(crate) fn request_scoped(router: Weak<Router>, session_state: SessionState) -> Self {
        Self {
            router: RouterAccess::RequestScoped(router),
            session_state,
        }
    }

    fn from_access(router: RouterAccess, session_state: SessionState) -> Self {
        Self {
            router,
            session_state,
        }
    }
}

impl ToolCaller for RouterToolCaller {
    fn call_tool<'a>(
        &'a self,
        parent_ctx: &'a McpContext,
        name: &'a str,
        args: serde_json::Value,
        depth: u32,
    ) -> Pin<
        Box<dyn std::future::Future<Output = fastmcp_core::McpResult<ToolCallResult>> + Send + 'a>,
    > {
        // Check recursion depth
        if depth > MAX_TOOL_CALL_DEPTH {
            return Box::pin(async move {
                Err(McpError::new(
                    McpErrorCode::InternalError,
                    format!("Maximum tool call depth ({}) exceeded", MAX_TOOL_CALL_DEPTH),
                ))
            });
        }

        // Clone what we need for the async block
        let parent_ctx = parent_ctx.clone();
        let name = name.to_string();
        let router_access = self.router.clone();
        let session_state = self.session_state.clone();

        Box::pin(async move {
            debug!(
                target: targets::HANDLER,
                "cross-component tool call; tool_key={}; depth={}; request={}",
                safe_log_label(&name),
                depth,
                parent_ctx.request_id()
            );
            let router = router_access.upgrade()?;
            let operation_started_at = parent_ctx.cx().now();
            if let Some(error) = budget_error(&parent_ctx) {
                return Err(error);
            }
            if !session_state.is_tool_enabled(&name) {
                return Err(McpError::new(
                    McpErrorCode::MethodNotFound,
                    format!("Tool '{}' is disabled for this session", name),
                ));
            }

            // Find the tool handler
            let handler = router
                .tools
                .get(&name)
                .ok_or_else(|| McpError::method_not_found(&format!("tool: {}", name)))?;

            // Validate arguments against the tool's input schema
            let tool_def = crate::catch_extension_unwind(|| handler.definition())
                .map_err(|_payload| sanitized_handler_panic(parent_ctx.cx(), "tool_definition"))?;

            // Use strict or lenient validation based on router configuration
            let validation_result = if router.strict_input_validation {
                validate_strict(&tool_def.input_schema, &args)
            } else {
                validate(&tool_def.input_schema, &args)
            };

            if let Err(validation_errors) = validation_result {
                let error_messages: Vec<String> = validation_errors
                    .iter()
                    .map(|e| format!("{}: {}", e.path, e.message))
                    .collect();
                return Err(McpError::invalid_params(format!(
                    "Input validation failed: {}",
                    error_messages.join("; ")
                )));
            }
            let handler_timeout =
                read_handler_timeout(parent_ctx.cx(), "tool_timeout", || handler.timeout())?;
            let effective_budget = compose_handler_budget(
                parent_ctx.cx().budget(),
                parent_ctx.budget(),
                handler_timeout,
                operation_started_at,
            );

            // Derive the child from the parent request authority, preserving
            // auth, mask state, budget accounting, and request identity.
            let nested_router = router_access.clone();
            let nested_state = session_state.clone();
            let child_ctx = parent_ctx
                .clone()
                .with_operation_deadline(effective_budget.deadline)
                .with_tool_call_depth(depth)
                .with_resource_read_depth(depth)
                .with_tool_caller(Arc::new(RouterToolCaller::from_access(
                    nested_router.clone(),
                    nested_state.clone(),
                )))
                .with_resource_reader(Arc::new(RouterResourceReader::from_access(
                    nested_router,
                    nested_state,
                )));

            // Call the tool
            let outcome = run_handler(&child_ctx, effective_budget, "tool", || {
                handler.call_async(&child_ctx, args)
            })?;

            // Convert outcome to result
            match outcome {
                Outcome::Ok(content) => {
                    // Convert protocol Content to core ToolContentItem
                    let items: Vec<ToolContentItem> = content
                        .into_iter()
                        .map(|c| match c {
                            Content::Text { text } => ToolContentItem::Text { text },
                            Content::Image { data, mime_type } => {
                                ToolContentItem::Image { data, mime_type }
                            }
                            Content::Audio { data, mime_type } => {
                                ToolContentItem::Audio { data, mime_type }
                            }
                            Content::Resource { resource } => ToolContentItem::Resource {
                                uri: resource.uri,
                                mime_type: resource.mime_type,
                                text: resource.text,
                                blob: resource.blob,
                            },
                        })
                        .collect();

                    Ok(ToolCallResult::success(items))
                }
                Outcome::Err(e) => {
                    let e = sanitize_handler_error(parent_ctx.cx(), "tool", e);
                    if is_framework_terminal_tool_error(e.code) {
                        return Err(e);
                    }
                    // Tool errors become error results, not failures
                    Ok(ToolCallResult::error(e.message))
                }
                Outcome::Cancelled(_) => Err(McpError::request_cancelled()),
                Outcome::Panicked(_payload) => {
                    Err(sanitized_handler_panic(parent_ctx.cx(), "tool"))
                }
            }
        })
    }
}

#[cfg(test)]
mod safe_log_label_tests {
    use super::{LOG_LABEL_HASH_INPUT_LIMIT, UriTemplateError, safe_log_label};

    #[test]
    fn safe_label_is_deterministic_non_verbatim_metadata() {
        let canary = "router-log-canary-secret";
        let first = format!("{}", safe_log_label(canary));
        let second = format!("{:?}", safe_log_label(canary));

        assert_eq!(first, second);
        assert!(first.contains(&format!("bytes={}", canary.len())));
        assert!(first.contains("sha256_prefix="));
        assert!(!first.contains(canary));
        assert_ne!(first, format!("{}", safe_log_label("different-label")));
    }

    #[test]
    fn safe_label_hashing_is_bounded_for_oversized_input() {
        let oversized = "x".repeat(LOG_LABEL_HASH_INPUT_LIMIT + 37);
        let rendered = format!("{}", safe_log_label(&oversized));

        assert!(rendered.contains(&format!("bytes={}", oversized.len())));
        assert!(rendered.contains(&format!("hashed_prefix_bytes={LOG_LABEL_HASH_INPUT_LIMIT}")));
        assert!(!rendered.contains(&oversized));
    }

    #[test]
    fn uri_template_error_log_class_never_exposes_parameter() {
        let canary = "template-parameter-canary-secret";
        let error = UriTemplateError::DuplicateParam(canary.to_string());
        let class = error.log_class();

        assert_eq!(class, "duplicate_parameter");
        assert!(!class.contains(canary));
    }

    #[test]
    fn source_has_no_verbatim_argument_or_label_log_formats() {
        let source = include_str!("router.rs");
        let forbidden = [
            concat!("Tool ", "arguments:"),
            concat!("Prompt ", "arguments:"),
            concat!("Calling ", "tool: {}"),
            concat!("Reading ", "resource: {}"),
            concat!("Getting ", "prompt: {}"),
            concat!("Cross-component tool ", "call: {}"),
            concat!("Cross-component resource ", "read: {}"),
            concat!("Invalid URI template ", "'{}'"),
        ];

        for format in forbidden {
            assert!(!source.contains(format), "raw log format remains: {format}");
        }
    }
}

#[cfg(test)]
mod uri_template_tests {
    use super::{
        MAX_URI_TEMPLATE_INPUT_BYTES, MAX_URI_TEMPLATE_MATCH_SEGMENTS, UriTemplate,
        UriTemplateError,
    };

    #[test]
    fn uri_template_matches_simple_param() {
        let matcher = UriTemplate::new("file://{path}");
        let params = matcher.matches("file://foo").expect("match");
        assert_eq!(params.get("path").map(String::as_str), Some("foo"));
    }

    #[test]
    fn uri_template_simple_trailing_param_rejects_raw_slash() {
        let matcher = UriTemplate::new("file://{path}");
        assert!(matcher.matches("file://foo/bar").is_none());

        let params = matcher
            .matches("file://foo%2Fbar")
            .expect("percent-encoded slash remains part of a simple expansion");
        assert_eq!(params.get("path").map(String::as_str), Some("foo/bar"));
    }

    #[test]
    fn uri_template_simple_capture_enforces_rfc6570_raw_grammar() {
        let matcher = UriTemplate::new("file://{path}");
        let params = matcher
            .matches("file://alpha-._~09%2Ftail")
            .expect("unreserved ASCII and encoded reserved bytes are valid");
        assert_eq!(
            params.get("path").map(String::as_str),
            Some("alpha-._~09/tail")
        );

        for raw in [
            "a:b",
            "a?b",
            "a#b",
            "a@b",
            "a b",
            "a\\b",
            "a\u{0001}b",
            "café",
            "%",
            "%2",
            "%2G",
            "%FF",
        ] {
            let uri = format!("file://{raw}");
            assert!(
                matcher.matches(&uri).is_none(),
                "invalid simple capture was accepted: {raw:?}"
            );
        }
    }

    #[test]
    fn uri_template_reserved_capture_enforces_rfc6570_raw_grammar() {
        let matcher = UriTemplate::new("file://{+path}");
        let raw = "a:/?#[]@!$&'()*+,;=z%2Ftail";
        let params = matcher
            .matches(&format!("file://{raw}"))
            .expect("reserved expansion should admit RFC 3986 reserved ASCII");
        assert_eq!(
            params.get("path").map(String::as_str),
            Some("a:/?#[]@!$&'()*+,;=z/tail")
        );

        for raw in ["a b", "a\\b", "a\u{007f}b", "café", "%", "%GG"] {
            let uri = format!("file://{raw}");
            assert!(
                matcher.matches(&uri).is_none(),
                "invalid reserved capture was accepted: {raw:?}"
            );
        }
    }

    #[test]
    fn uri_template_matches_multiple_params() {
        let matcher = UriTemplate::new("db://{table}/{id}");
        let params = matcher.matches("db://users/42").expect("match");
        assert_eq!(params.get("table").map(String::as_str), Some("users"));
        assert_eq!(params.get("id").map(String::as_str), Some("42"));
    }

    #[test]
    fn uri_template_rejects_extra_segments() {
        let matcher = UriTemplate::new("db://{table}/{id}");
        assert!(matcher.matches("db://users/42/extra").is_none());
    }

    #[test]
    fn uri_template_rejects_extra_segments_with_literal_path() {
        let matcher = UriTemplate::new("db://{table}/items/{id}");
        let params = matcher.matches("db://users/items/42").expect("match");
        assert_eq!(params.get("table").map(String::as_str), Some("users"));
        assert_eq!(params.get("id").map(String::as_str), Some("42"));
        assert!(matcher.matches("db://users/items/42/extra").is_none());
    }

    #[test]
    fn uri_template_decodes_percent_encoded_values() {
        let matcher = UriTemplate::new("file://{path}");
        let params = matcher.matches("file://foo%2Fbar").expect("match");
        assert_eq!(params.get("path").map(String::as_str), Some("foo/bar"));
    }

    #[test]
    fn uri_template_reserved_trailing_param_matches_nested_path() {
        let matcher = UriTemplate::new("asset://{bucket}/{+path}");
        let params = matcher
            .matches("asset://public/images/icons/mark.svg")
            .expect("reserved trailing expansion should consume slashes");

        assert_eq!(params.get("bucket").map(String::as_str), Some("public"));
        assert_eq!(
            params.get("path").map(String::as_str),
            Some("images/icons/mark.svg")
        );
        assert!(params.get("+path").is_none());
    }

    #[test]
    fn uri_template_simple_trailing_param_preserves_multi_param_slash_rule() {
        let matcher = UriTemplate::new("asset://{bucket}/{path}");

        assert!(
            matcher
                .matches("asset://public/images/icons/mark.svg")
                .is_none()
        );
    }

    #[test]
    fn uri_template_simple_interior_param_cannot_cross_path_segments() {
        let simple = UriTemplate::new("db://{tenant}/items/{id}");
        assert!(simple.matches("db://a/b/items/1").is_none());

        let encoded = simple
            .matches("db://a%2Fb/items/1")
            .expect("an encoded slash remains part of one simple expansion");
        assert_eq!(encoded.get("tenant").map(String::as_str), Some("a/b"));
        assert_eq!(encoded.get("id").map(String::as_str), Some("1"));

        let reserved = UriTemplate::new("db://{+tenant}/items/{id}");
        let params = reserved
            .matches("db://a/b/items/1")
            .expect("reserved expansion may consume path separators");
        assert_eq!(params.get("tenant").map(String::as_str), Some("a/b"));
        assert_eq!(params.get("id").map(String::as_str), Some("1"));
    }

    #[test]
    fn uri_template_reserved_interior_param_backtracks_greedily() {
        let matcher = UriTemplate::new("db://{+tenant}/items/{id}");
        let params = matcher
            .matches("db://a/items/b/items/1")
            .expect("reserved expansion should use the last viable delimiter");

        assert_eq!(params.get("tenant").map(String::as_str), Some("a/items/b"));
        assert_eq!(params.get("id").map(String::as_str), Some("1"));
    }

    #[test]
    fn uri_template_reserved_param_percent_decodes_exactly_once() {
        let matcher = UriTemplate::new("file://{+path}");
        let params = matcher
            .matches("file://dir%20one/nested%252Fname")
            .expect("match");

        assert_eq!(
            params.get("path").map(String::as_str),
            Some("dir one/nested%2Fname")
        );
        assert!(matcher.matches("file://nested%2Gname").is_none());
    }

    #[test]
    fn uri_template_supports_escaped_braces() {
        let matcher = UriTemplate::new("file://{{literal}}/{id}");
        let params = matcher.matches("file://{literal}/123").expect("match");
        assert_eq!(params.get("id").map(String::as_str), Some("123"));
    }

    #[test]
    fn uri_template_rejects_empty_param() {
        let err = UriTemplate::parse("file://{}/x").unwrap_err();
        assert_eq!(err, UriTemplateError::EmptyParam);
    }

    #[test]
    fn uri_template_rejects_unmatched_close() {
        let err = UriTemplate::parse("file://}x").unwrap_err();
        assert_eq!(err, UriTemplateError::UnmatchedClose);
    }

    #[test]
    fn uri_template_rejects_duplicate_params() {
        let err = UriTemplate::parse("db://{id}/{id}").unwrap_err();
        assert_eq!(err, UriTemplateError::DuplicateParam("id".to_string()));
    }

    #[test]
    fn uri_template_rejects_duplicate_simple_and_reserved_params() {
        let err = UriTemplate::parse("db://{id}/{+id}").unwrap_err();
        assert_eq!(err, UriTemplateError::DuplicateParam("id".to_string()));
    }

    #[test]
    fn uri_template_rejects_unsupported_operators() {
        for operator in ['#', '.', '/', ';', '?', '&'] {
            let pattern = format!("resource://{{{operator}name}}");
            assert_eq!(
                UriTemplate::parse(&pattern).unwrap_err(),
                UriTemplateError::UnsupportedOperator,
                "operator {operator} should be rejected"
            );
        }
    }

    #[test]
    fn uri_template_rejects_invalid_parameter_names_and_modifiers() {
        for pattern in [
            "resource://{bad-name}",
            "resource://{bad.}",
            "resource://{bad..name}",
            "resource://{name,other}",
            "resource://{name*}",
            "resource://{name:3}",
            "resource://{+bad-name}",
        ] {
            assert_eq!(
                UriTemplate::parse(pattern).unwrap_err(),
                UriTemplateError::InvalidParamName,
                "invalid parameter expression should be rejected: {pattern}"
            );
        }

        assert_eq!(
            UriTemplate::parse("resource://{+}").unwrap_err(),
            UriTemplateError::EmptyParam
        );
    }

    #[test]
    fn uri_template_rejects_unclosed_param() {
        let err = UriTemplate::parse("file://{path").unwrap_err();
        assert_eq!(err, UriTemplateError::UnclosedParam);
    }

    #[test]
    fn uri_template_parse_rejects_excessive_segment_count() {
        let mut boundary = String::new();
        for index in 0..(MAX_URI_TEMPLATE_MATCH_SEGMENTS / 2) {
            boundary.push('x');
            boundary.push_str(&format!("{{value_{index}}}"));
        }
        let parsed = UriTemplate::parse(&boundary).expect("segment boundary should be accepted");
        assert_eq!(parsed.segments.len(), MAX_URI_TEMPLATE_MATCH_SEGMENTS);

        boundary.push('x');
        boundary.push_str("{one_more}");
        assert_eq!(
            UriTemplate::parse(&boundary).unwrap_err(),
            UriTemplateError::TooComplex
        );
    }

    #[test]
    fn uri_template_match_rejects_input_above_byte_limit() {
        let matcher = UriTemplate::new("{+value}");
        let boundary = "a".repeat(MAX_URI_TEMPLATE_INPUT_BYTES);
        let params = matcher
            .matches(&boundary)
            .expect("input at the byte boundary should match");
        assert_eq!(
            params.get("value").map(String::len),
            Some(MAX_URI_TEMPLATE_INPUT_BYTES)
        );

        let oversized = "a".repeat(MAX_URI_TEMPLATE_INPUT_BYTES + 1);
        assert!(matcher.matches(&oversized).is_none());
    }

    #[test]
    fn uri_template_repeated_literal_attack_fails_closed() {
        let matcher = UriTemplate::new("{+left}x{middle}/END");
        let mut attack = "x/".repeat((MAX_URI_TEMPLATE_INPUT_BYTES - 3) / 2);
        attack.push_str("END");

        assert!(attack.len() <= MAX_URI_TEMPLATE_INPUT_BYTES);
        assert!(matcher.matches(&attack).is_none());
    }

    #[test]
    fn uri_template_specificity_literal_only() {
        let t = UriTemplate::new("file://exact/path");
        let (lit_len, lit_segs, total_segs) = t.specificity();
        assert_eq!(lit_len, "file://exact/path".len());
        assert_eq!(lit_segs, 1);
        assert_eq!(total_segs, 1);
    }

    #[test]
    fn uri_template_specificity_with_params() {
        let t = UriTemplate::new("db://{table}/items/{id}");
        let (lit_len, lit_segs, total_segs) = t.specificity();
        assert_eq!(lit_len, "db://".len() + "/items/".len());
        assert_eq!(lit_segs, 2);
        assert_eq!(total_segs, 4); // "db://", {table}, "/items/", {id}
    }

    #[test]
    fn uri_template_no_match_on_literal_mismatch() {
        let t = UriTemplate::new("file://exact");
        assert!(t.matches("file://other").is_none());
    }

    #[test]
    fn uri_template_rejects_empty_param_value() {
        let t = UriTemplate::new("db://{table}/items/{id}");
        // table would be empty
        assert!(t.matches("db:///items/42").is_none());
    }

    #[test]
    fn uri_template_debug_and_clone() {
        let t = UriTemplate::new("file://{path}");
        let debug = format!("{:?}", t);
        assert!(debug.contains("file://{path}"));
        let cloned = t.clone();
        assert!(cloned.matches("file://test").is_some());
    }

    #[test]
    fn uri_template_escaped_close_brace() {
        let t = UriTemplate::new("file://{{a}}/{id}");
        let params = t.matches("file://{a}/42").expect("match");
        assert_eq!(params.get("id").map(String::as_str), Some("42"));
    }

    #[test]
    fn uri_template_try_new_ok() {
        let t = UriTemplate::try_new("file://{path}");
        assert!(t.is_ok());
    }

    #[test]
    fn uri_template_try_new_err() {
        let t = UriTemplate::try_new("file://{");
        assert!(t.is_err());
    }

    #[test]
    fn uri_template_new_invalid_returns_non_matching() {
        // Invalid template: UriTemplate::new should log a warning and return
        // a template that never matches any URI (fail-safe).
        let t = UriTemplate::new("file://{");
        assert!(t.matches("file://anything").is_none());
        assert!(t.matches("").is_none());
    }

    #[test]
    fn uri_template_literal_only_no_match_empty() {
        let t = UriTemplate::new("file://exact");
        assert!(t.matches("").is_none());
        assert!(t.matches("file://exact").is_some());
    }

    #[test]
    fn uri_template_multiple_params_empty_last() {
        // Last param must not be empty
        let t = UriTemplate::new("db://{table}/{id}");
        assert!(t.matches("db://users/").is_none());
    }

    #[test]
    fn uri_template_adjacent_params_not_supported() {
        // Two adjacent params (no literal between them) should fail to match
        let t = UriTemplate::new("{a}{b}");
        assert!(t.matches("xy").is_none());
    }

    #[test]
    fn uri_template_escaped_double_close_brace() {
        // Escaped closing braces: }} -> }
        let t = UriTemplate::new("a}}b/{id}");
        let params = t.matches("a}b/42").expect("match");
        assert_eq!(params.get("id").map(String::as_str), Some("42"));
    }

    #[test]
    fn uri_template_specificity_param_only() {
        let t = UriTemplate::new("{all}");
        let (lit_len, lit_segs, total_segs) = t.specificity();
        assert_eq!(lit_len, 0);
        assert_eq!(lit_segs, 0);
        assert_eq!(total_segs, 1);
    }
}

#[cfg(test)]
mod percent_decode_tests {
    use super::{from_hex, percent_decode};

    #[test]
    fn no_percent_passthrough() {
        assert_eq!(percent_decode("hello"), Some("hello".to_string()));
    }

    #[test]
    fn basic_percent_decode() {
        assert_eq!(percent_decode("foo%20bar"), Some("foo bar".to_string()));
    }

    #[test]
    fn truncated_percent_returns_none() {
        assert!(percent_decode("foo%2").is_none());
    }

    #[test]
    fn invalid_hex_returns_none() {
        assert!(percent_decode("foo%GG").is_none());
    }

    #[test]
    fn from_hex_digits() {
        assert_eq!(from_hex(b'0'), Some(0));
        assert_eq!(from_hex(b'9'), Some(9));
        assert_eq!(from_hex(b'a'), Some(10));
        assert_eq!(from_hex(b'f'), Some(15));
        assert_eq!(from_hex(b'A'), Some(10));
        assert_eq!(from_hex(b'F'), Some(15));
        assert_eq!(from_hex(b'G'), None);
    }
}

#[cfg(test)]
mod cursor_tests {
    use super::{decode_cursor_offset, encode_cursor_offset};

    #[test]
    fn roundtrip_zero() {
        let encoded = encode_cursor_offset(0);
        let decoded = decode_cursor_offset(Some(&encoded)).unwrap();
        assert_eq!(decoded, 0);
    }

    #[test]
    fn roundtrip_large_offset() {
        let encoded = encode_cursor_offset(12345);
        let decoded = decode_cursor_offset(Some(&encoded)).unwrap();
        assert_eq!(decoded, 12345);
    }

    #[test]
    fn none_cursor_returns_zero() {
        assert_eq!(decode_cursor_offset(None).unwrap(), 0);
    }

    #[test]
    fn invalid_base64_returns_error() {
        let err = decode_cursor_offset(Some("not-valid-base64!!!")).unwrap_err();
        assert!(err.message.contains("base64"));
    }

    #[test]
    fn valid_base64_but_not_json_returns_error() {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"not json");
        let err = decode_cursor_offset(Some(&encoded)).unwrap_err();
        assert!(err.message.contains("JSON"));
    }

    #[test]
    fn valid_json_but_no_offset_returns_error() {
        let payload = serde_json::json!({"other": 1});
        let bytes = serde_json::to_vec(&payload).unwrap();
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let err = decode_cursor_offset(Some(&encoded)).unwrap_err();
        assert!(err.message.contains("offset"));
    }
}

#[cfg(test)]
mod tag_filter_tests {
    use super::TagFilters;

    #[test]
    fn no_filters_matches_anything() {
        let f = TagFilters::default();
        assert!(f.matches(&[]));
        assert!(f.matches(&["a".to_string()]));
    }

    #[test]
    fn include_filter_requires_all_tags() {
        let include = vec!["a".to_string(), "b".to_string()];
        let f = TagFilters::new(Some(&include), None);
        assert!(f.matches(&["a".to_string(), "b".to_string(), "c".to_string()]));
        assert!(!f.matches(&["a".to_string()])); // missing "b"
    }

    #[test]
    fn exclude_filter_rejects_any_tag() {
        let exclude = vec!["x".to_string()];
        let f = TagFilters::new(None, Some(&exclude));
        assert!(f.matches(&["a".to_string(), "b".to_string()]));
        assert!(!f.matches(&["a".to_string(), "x".to_string()]));
    }

    #[test]
    fn include_and_exclude_combined() {
        let include = vec!["a".to_string()];
        let exclude = vec!["b".to_string()];
        let f = TagFilters::new(Some(&include), Some(&exclude));
        assert!(f.matches(&["a".to_string()]));
        assert!(!f.matches(&["a".to_string(), "b".to_string()])); // excluded
        assert!(!f.matches(&["c".to_string()])); // missing "a"
    }

    #[test]
    fn case_insensitive_matching() {
        let include = vec!["Alpha".to_string()];
        let f = TagFilters::new(Some(&include), None);
        assert!(f.matches(&["alpha".to_string()]));
        assert!(f.matches(&["ALPHA".to_string()]));
    }

    #[test]
    fn empty_include_array_passes_all() {
        let include: Vec<String> = vec![];
        let f = TagFilters::new(Some(&include), None);
        assert!(f.matches(&[]));
        assert!(f.matches(&["anything".to_string()]));
    }

    #[test]
    fn tag_filters_debug() {
        let f = TagFilters::default();
        let debug = format!("{:?}", f);
        assert!(debug.contains("TagFilters"));
    }
}

#[cfg(test)]
mod router_tests {
    use super::*;
    use crate::handler::{CompletionHandler, PromptHandler, ResourceHandler, ToolHandler};
    use asupersync::channel::oneshot;
    use asupersync::runtime::{RuntimeBuilder, RuntimeHandle};
    use asupersync::types::CancelKind;
    use fastmcp_core::{McpContext, McpResult, SessionState};
    use fastmcp_protocol::common_types::{
        Annotations, ContentBlock, EmbeddedResourceContents, OpenMetadata, RawIcon,
    };
    use fastmcp_protocol::{
        CompleteResult, CompletionValues, Content, FinalCallToolResult, FinalCompletionParams,
        LegacyCompletionParams, Prompt, PromptArgument, PromptMessage, Resource, ResourceContent,
        ResourceTemplate, Tool,
    };
    use std::fmt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::Poll;

    fn request_context(
        cx: &Cx,
        request_id: u64,
        budget: Budget,
        state: &SessionState,
    ) -> McpContext {
        McpContext::with_state(cx.clone(), request_id, state.clone()).with_budget_ceiling(budget)
    }

    async fn yield_once() {
        let mut yielded = false;
        std::future::poll_fn(|task_cx| {
            if std::mem::replace(&mut yielded, true) {
                Poll::Ready(())
            } else {
                task_cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
    }

    fn spawn_owned_modern_request(
        runtime: &RuntimeHandle,
        router: Arc<Router>,
        request_context_id: u64,
        wire_id: &'static str,
        label: &'static str,
        control_sender: Option<oneshot::Sender<Cx>>,
    ) -> oneshot::Receiver<McpResult<serde_json::Value>> {
        let (response_sender, response_receiver) = oneshot::channel();
        runtime
            .try_spawn_with_cx(move |request_cx| {
                if let Some(control_sender) = control_sender {
                    control_sender
                        .send_blocking(request_cx.clone())
                        .expect("the cancellation controller remains available");
                }
                let request_ctx = McpContext::new(request_cx, request_context_id);
                let request = JsonRpcRequest::new(
                    "tools/call",
                    Some(serde_json::json!({
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                        "name": "concurrent-modern-tool",
                        "arguments": {"request": label},
                    })),
                    wire_id,
                );
                async move {
                    let result = router.dispatch_stateless_owned(request_ctx, request).await;
                    response_sender
                        .send_blocking(result)
                        .expect("the modern dispatch observer remains available");
                }
            })
            .expect("the runtime admits the request owner");
        response_receiver
    }

    // ── Stub handlers ──────────────────────────────────────────────────

    struct NamedTool {
        name: String,
        tags: Vec<String>,
    }

    impl NamedTool {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                tags: vec![],
            }
        }
        fn with_tags(name: &str, tags: Vec<String>) -> Self {
            Self {
                name: name.to_string(),
                tags,
            }
        }
    }

    impl ToolHandler for NamedTool {
        fn definition(&self) -> Tool {
            Tool {
                name: self.name.clone(),
                description: Some(format!("Tool {}", self.name)),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: self.tags.clone(),
                annotations: None,
            }
        }
        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text(format!("called {}", self.name))])
        }
    }

    static MACRO_DUAL_ERA_TOOL_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn final_tool_complete_result(
        payload: FinalCallToolResult,
    ) -> CompleteResult<FinalCallToolResult> {
        let params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
            "name": "macro_dual_era_tool",
        });
        let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params))
            .expect("test final tools/call request");
        let mut wire = serde_json::to_value(payload).expect("final tool payload serializes");
        wire.as_object_mut()
            .expect("final tool payload is an object")
            .insert("resultType".to_owned(), serde_json::json!("complete"));
        let encoded = serde_json::to_string(&wire).expect("final tool wire serializes");
        let CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) = request
            .decode_result(&encoded)
            .expect("typed final tools/call result")
        else {
            panic!("typed final tools/call result is selected");
        };
        result
    }

    #[fastmcp_derive::tool]
    fn macro_dual_era_tool() -> CompleteResult<FinalCallToolResult> {
        MACRO_DUAL_ERA_TOOL_CALLS.fetch_add(1, Ordering::SeqCst);
        final_tool_complete_result(FinalCallToolResult {
            content: vec![ContentBlock::text("macro final tool result")],
            is_error: false,
            structured_content: Some(serde_json::json!({"weather":"clear"})),
        })
    }

    struct FinalCatalogTool {
        metadata: OpenMetadata,
        icons: Vec<RawIcon>,
    }

    impl ToolHandler for FinalCatalogTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "final-catalog-tool".to_owned(),
                description: Some("final catalog description".to_owned()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: Some(serde_json::json!({"type": "object"})),
                icon: Some(fastmcp_protocol::Icon::new("https://legacy.test/icon.png")),
                version: Some("legacy-version".to_owned()),
                tags: vec!["legacy-tag".to_owned()],
                annotations: None,
            }
        }

        fn final_title(&self) -> Option<&str> {
            Some("Final Catalog Tool")
        }

        fn final_icons(&self) -> Option<&[RawIcon]> {
            Some(&self.icons)
        }

        fn final_metadata(&self) -> Option<&OpenMetadata> {
            Some(&self.metadata)
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text("legacy final catalog result")])
        }
    }

    struct FinalCatalogResource {
        metadata: OpenMetadata,
        icons: Vec<RawIcon>,
        annotations: Annotations,
    }

    impl ResourceHandler for FinalCatalogResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "file:///final-catalog-resource".to_owned(),
                name: "final-catalog-resource".to_owned(),
                description: Some("final resource description".to_owned()),
                mime_type: Some("text/plain".to_owned()),
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn final_title(&self) -> Option<&str> {
            Some("Final Catalog Resource")
        }

        fn final_icons(&self) -> Option<&[RawIcon]> {
            Some(&self.icons)
        }

        fn final_annotations(&self) -> Option<&Annotations> {
            Some(&self.annotations)
        }

        fn final_metadata(&self) -> Option<&OpenMetadata> {
            Some(&self.metadata)
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(Vec::new())
        }
    }

    struct FinalCatalogResourceTemplate {
        metadata: OpenMetadata,
        icons: Vec<RawIcon>,
        annotations: Annotations,
    }

    impl ResourceHandler for FinalCatalogResourceTemplate {
        fn definition(&self) -> Resource {
            Resource {
                uri: "template://placeholder".to_owned(),
                name: "final-catalog-template".to_owned(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn template(&self) -> Option<ResourceTemplate> {
            Some(ResourceTemplate {
                uri_template: "template://{id}".to_owned(),
                name: "final-catalog-template".to_owned(),
                description: Some("final template description".to_owned()),
                mime_type: Some("application/json".to_owned()),
                icon: None,
                version: None,
                tags: Vec::new(),
            })
        }

        fn final_template_title(&self) -> Option<&str> {
            Some("Final Catalog Template")
        }

        fn final_template_icons(&self) -> Option<&[RawIcon]> {
            Some(&self.icons)
        }

        fn final_template_annotations(&self) -> Option<&Annotations> {
            Some(&self.annotations)
        }

        fn final_template_metadata(&self) -> Option<&OpenMetadata> {
            Some(&self.metadata)
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(Vec::new())
        }
    }

    struct FinalCatalogPrompt {
        metadata: OpenMetadata,
        icons: Vec<RawIcon>,
    }

    impl PromptHandler for FinalCatalogPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "final-catalog-prompt".to_owned(),
                description: Some("final prompt description".to_owned()),
                arguments: vec![PromptArgument {
                    name: "optional-argument".to_owned(),
                    description: Some("must remain explicitly false".to_owned()),
                    required: false,
                }],
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn final_title(&self) -> Option<&str> {
            Some("Final Catalog Prompt")
        }

        fn final_icons(&self) -> Option<&[RawIcon]> {
            Some(&self.icons)
        }

        fn final_metadata(&self) -> Option<&OpenMetadata> {
            Some(&self.metadata)
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Ok(Vec::new())
        }
    }

    struct EchoCompletion;

    impl CompletionHandler for EchoCompletion {
        fn complete_legacy(
            &self,
            _ctx: &McpContext,
            params: LegacyCompletionParams,
        ) -> McpResult<CompletionValues> {
            Ok(CompletionValues {
                values: vec![format!("{}ging", params.argument.value)],
                total: Some(1),
                has_more: Some(false),
            })
        }

        fn complete_final(
            &self,
            _ctx: &McpContext,
            params: FinalCompletionParams,
        ) -> McpResult<CompletionValues> {
            Ok(CompletionValues {
                values: vec![format!("{}ging", params.argument.value)],
                total: Some(1),
                has_more: Some(false),
            })
        }
    }

    struct ConcurrentModernTool {
        started: Arc<AtomicUsize>,
        completed: Arc<Mutex<Vec<String>>>,
    }

    impl ConcurrentModernTool {
        fn new(started: Arc<AtomicUsize>, completed: Arc<Mutex<Vec<String>>>) -> Self {
            Self { started, completed }
        }
    }

    impl ToolHandler for ConcurrentModernTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "concurrent-modern-tool".to_string(),
                description: Some("deterministic modern dispatch probe".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["request"],
                    "properties": {"request": {"type": "string"}},
                }),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Err(McpError::internal_error(
                "concurrent modern dispatch requires the async request hook",
            ))
        }

        fn call_async_in_request<'a>(
            &'a self,
            ctx: &'a McpContext,
            request_cx: &'a Cx,
            arguments: serde_json::Value,
        ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
            Box::pin(async move {
                let label = arguments
                    .get("request")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("missing")
                    .to_string();
                self.started.fetch_add(1, Ordering::SeqCst);

                while self.started.load(Ordering::SeqCst) < 2 {
                    if ctx.checkpoint().is_err() || request_cx.is_cancel_requested() {
                        return Outcome::Cancelled(asupersync::CancelReason::user(
                            "request cancelled before concurrent admission",
                        ));
                    }
                    yield_once().await;
                }

                if label == "cancelled" {
                    loop {
                        if ctx.checkpoint().is_err() || request_cx.is_cancel_requested() {
                            return Outcome::Cancelled(asupersync::CancelReason::user(
                                "request cancellation observed by child Cx",
                            ));
                        }
                        yield_once().await;
                    }
                }

                if ctx.checkpoint().is_err() || request_cx.is_cancel_requested() {
                    return Outcome::Cancelled(asupersync::CancelReason::user(
                        "request cancelled before completion",
                    ));
                }
                self.completed
                    .lock()
                    .expect("completion probe lock is not poisoned")
                    .push(label.clone());
                Outcome::Ok(vec![Content::text(label)])
            })
        }
    }

    struct ErrorTool {
        name: &'static str,
        code: McpErrorCode,
    }

    impl ToolHandler for ErrorTool {
        fn definition(&self) -> Tool {
            Tool {
                name: self.name.to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Err(McpError::new(self.code, "nested tool error"))
        }
    }

    struct AlternatingTool {
        calls: Arc<AtomicU64>,
    }

    impl ToolHandler for AlternatingTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "alternating_tool".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Err(McpError::internal_error("async alternating tool only"))
        }

        fn call_async<'a>(
            &'a self,
            ctx: &'a McpContext,
            _arguments: serde_json::Value,
        ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                match ctx.read_resource("loop://resource").await {
                    Ok(_) => Outcome::Ok(vec![Content::text("unexpected completion")]),
                    Err(error) => Outcome::Err(error),
                }
            })
        }
    }

    struct NamedResource {
        uri: String,
        tags: Vec<String>,
    }

    impl NamedResource {
        fn new(uri: &str) -> Self {
            Self {
                uri: uri.to_string(),
                tags: vec![],
            }
        }
        fn with_tags(uri: &str, tags: Vec<String>) -> Self {
            Self {
                uri: uri.to_string(),
                tags,
            }
        }
    }

    impl ResourceHandler for NamedResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: self.uri.clone(),
                name: self.uri.clone(),
                description: None,
                mime_type: Some("text/plain".to_string()),
                icon: None,
                version: None,
                tags: self.tags.clone(),
            }
        }
        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![ResourceContent {
                uri: self.uri.clone(),
                mime_type: Some("text/plain".to_string()),
                text: Some("content".to_string()),
                blob: None,
            }])
        }
    }

    struct AlternatingResource {
        calls: Arc<AtomicU64>,
    }

    impl ResourceHandler for AlternatingResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "loop://resource".to_string(),
                name: "alternating-resource".to_string(),
                description: None,
                mime_type: Some("text/plain".to_string()),
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Err(McpError::internal_error("async alternating resource only"))
        }

        fn read_async<'a>(
            &'a self,
            ctx: &'a McpContext,
        ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                match ctx
                    .call_tool("alternating_tool", serde_json::json!({}))
                    .await
                {
                    Ok(_) => Outcome::Ok(vec![ResourceContent {
                        uri: "loop://resource".to_string(),
                        mime_type: Some("text/plain".to_string()),
                        text: Some("unexpected completion".to_string()),
                        blob: None,
                    }]),
                    Err(error) => Outcome::Err(error),
                }
            })
        }
    }

    struct CostLedgerTool {
        remaining_after_parent_debit: Arc<AtomicU64>,
        remaining_after_nested_read: Arc<AtomicU64>,
    }

    impl ToolHandler for CostLedgerTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "cost_ledger_tool".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Err(McpError::internal_error("async cost-ledger tool only"))
        }

        fn call_async<'a>(
            &'a self,
            ctx: &'a McpContext,
            _arguments: serde_json::Value,
        ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
            Box::pin(async move {
                if ctx.consume_cost(1).is_err() {
                    return Outcome::Err(McpError::request_cancelled());
                }
                self.remaining_after_parent_debit.store(
                    ctx.budget()
                        .cost_quota
                        .expect("test request has finite cost quota"),
                    Ordering::Relaxed,
                );

                if let Err(error) = ctx.read_resource("cost://nested").await {
                    return Outcome::Err(error);
                }
                self.remaining_after_nested_read.store(
                    ctx.budget()
                        .cost_quota
                        .expect("test request has finite cost quota"),
                    Ordering::Relaxed,
                );
                Outcome::Ok(vec![Content::text("shared ledger")])
            })
        }
    }

    struct CostLedgerResource {
        remaining_after_nested_debit: Arc<AtomicU64>,
    }

    impl ResourceHandler for CostLedgerResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "cost://nested".to_string(),
                name: "cost-ledger-resource".to_string(),
                description: None,
                mime_type: Some("text/plain".to_string()),
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            ctx.consume_cost(1)
                .map_err(|_| McpError::request_cancelled())?;
            self.remaining_after_nested_debit.store(
                ctx.budget()
                    .cost_quota
                    .expect("test request has finite cost quota"),
                Ordering::Relaxed,
            );
            Ok(vec![ResourceContent {
                uri: "cost://nested".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("nested debit".to_string()),
                blob: None,
            }])
        }
    }

    struct NamedPrompt {
        name: String,
        tags: Vec<String>,
    }

    impl NamedPrompt {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                tags: vec![],
            }
        }
        fn with_tags(name: &str, tags: Vec<String>) -> Self {
            Self {
                name: name.to_string(),
                tags,
            }
        }
    }

    impl PromptHandler for NamedPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: self.name.clone(),
                description: Some(format!("Prompt {}", self.name)),
                arguments: vec![],
                icon: None,
                version: None,
                tags: self.tags.clone(),
            }
        }
        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Ok(vec![])
        }
    }

    fn marked_template(uri_template: &str, marker: &str) -> ResourceTemplate {
        ResourceTemplate {
            uri_template: uri_template.to_string(),
            name: marker.to_string(),
            description: Some(marker.to_string()),
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![marker.to_string()],
        }
    }

    fn marked_router(marker: &str) -> Router {
        let mut router = Router::new();
        router.add_tool(NamedTool::with_tags(
            "duplicate_tool",
            vec![marker.to_string()],
        ));
        router.add_resource(NamedResource::with_tags(
            "duplicate://resource",
            vec![marker.to_string()],
        ));
        router.add_resource_template(marked_template("duplicate://{item}", marker));
        router.add_prompt(NamedPrompt::with_tags(
            "duplicate_prompt",
            vec![marker.to_string()],
        ));
        router
    }

    fn assert_router_marker(router: &Router, marker: &str) {
        assert_eq!(
            router
                .get_tool("duplicate_tool")
                .expect("tool exists")
                .definition()
                .tags,
            vec![marker.to_string()]
        );
        assert_eq!(
            router
                .get_resource("duplicate://resource")
                .expect("resource exists")
                .definition()
                .tags,
            vec![marker.to_string()]
        );
        assert_eq!(
            router
                .get_resource_template("duplicate://{item}")
                .expect("resource template exists")
                .tags,
            vec![marker.to_string()]
        );
        assert_eq!(
            router
                .get_prompt("duplicate_prompt")
                .expect("prompt exists")
                .definition()
                .tags,
            vec![marker.to_string()]
        );
    }

    struct BudgetProbeTool {
        timeout: Option<Duration>,
        delay: Duration,
        observed_deadline: Arc<Mutex<Option<Time>>>,
        timeout_read: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ToolHandler for BudgetProbeTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "budget_probe".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn timeout(&self) -> Option<Duration> {
            self.timeout_read.store(true, Ordering::Relaxed);
            self.timeout
        }

        fn call(&self, ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            *self
                .observed_deadline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = ctx.budget().deadline;
            if !self.delay.is_zero() {
                std::thread::sleep(self.delay);
            }
            Ok(vec![Content::text("completed")])
        }
    }

    struct SlowDefinitionTool {
        definition_reads: Arc<AtomicU64>,
        called: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ToolHandler for SlowDefinitionTool {
        fn definition(&self) -> Tool {
            if self.definition_reads.fetch_add(1, Ordering::Relaxed) > 0 {
                std::thread::sleep(Duration::from_millis(15));
            }
            Tool {
                name: "slow_definition".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn timeout(&self) -> Option<Duration> {
            Some(Duration::from_millis(1))
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            self.called.store(true, Ordering::Relaxed);
            Ok(vec![Content::text("must not run")])
        }
    }

    const PANIC_CANARY: &str = "Bearer peer-secret\n\u{001b}[31mred\u{001b}[0m\u{001b}]8;;https://invalid\u{0007}link\u{202e}";

    struct PanickingDisplay(String);

    impl fmt::Display for PanickingDisplay {
        fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("display-must-not-run: {}", self.0);
        }
    }

    struct UnwindingPanicTool {
        payload: String,
        non_string: bool,
    }

    impl ToolHandler for UnwindingPanicTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "panic_tool".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            unreachable!("the async override is the handler boundary under test")
        }

        fn call_async<'a>(
            &'a self,
            _ctx: &'a McpContext,
            _arguments: serde_json::Value,
        ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
            Box::pin(async move {
                if self.non_string {
                    std::panic::panic_any(PanickingDisplay(self.payload.clone()));
                }
                panic!("{}", self.payload);
            })
        }
    }

    struct OutcomePanicTool(String);

    impl ToolHandler for OutcomePanicTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "outcome_panic_tool".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            unreachable!("the async override is the handler boundary under test")
        }

        fn call_async<'a>(
            &'a self,
            _ctx: &'a McpContext,
            _arguments: serde_json::Value,
        ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
            Box::pin(async move {
                Outcome::Panicked(asupersync::types::PanicPayload::new(self.0.clone()))
            })
        }
    }

    struct OpaqueInternalTool;

    impl ToolHandler for OpaqueInternalTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "opaque_internal_tool".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Err(McpError::with_data(
                McpErrorCode::InternalError,
                PANIC_CANARY,
                serde_json::json!({"secret": PANIC_CANARY}),
            ))
        }
    }

    struct OpaqueInternalResource;

    impl ResourceHandler for OpaqueInternalResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "opaque://internal".to_string(),
                name: "opaque-internal-resource".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Err(McpError::with_data(
                McpErrorCode::InternalError,
                PANIC_CANARY,
                serde_json::json!({"secret": PANIC_CANARY}),
            ))
        }
    }

    struct OpaqueInternalPrompt;

    impl PromptHandler for OpaqueInternalPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "opaque_internal_prompt".to_string(),
                description: None,
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Err(McpError::with_data(
                McpErrorCode::InternalError,
                PANIC_CANARY,
                serde_json::json!({"secret": PANIC_CANARY}),
            ))
        }
    }

    struct PanicResource;

    impl ResourceHandler for PanicResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "panic://resource".to_string(),
                name: "panic-resource".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            panic!("{PANIC_CANARY}")
        }
    }

    struct PanicPrompt;

    impl PromptHandler for PanicPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "panic_prompt".to_string(),
                description: None,
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            panic!("{PANIC_CANARY}")
        }
    }

    struct DefinitionPanicTool(std::sync::atomic::AtomicBool);

    impl ToolHandler for DefinitionPanicTool {
        fn definition(&self) -> Tool {
            if self.0.swap(true, Ordering::Relaxed) {
                panic!("{PANIC_CANARY}");
            }
            Tool {
                name: "definition_panic_tool".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![])
        }
    }

    struct DefinitionPanicResource(std::sync::atomic::AtomicBool);

    impl ResourceHandler for DefinitionPanicResource {
        fn definition(&self) -> Resource {
            if self.0.swap(true, Ordering::Relaxed) {
                panic!("{PANIC_CANARY}");
            }
            Resource {
                uri: "panic://definition".to_string(),
                name: "definition-panic-resource".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![])
        }
    }

    struct TemplatePanicResource(std::sync::atomic::AtomicBool);

    impl ResourceHandler for TemplatePanicResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "panic-template://placeholder".to_string(),
                name: "template-panic-resource".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn template(&self) -> Option<ResourceTemplate> {
            if self.0.swap(true, Ordering::Relaxed) {
                panic!("{PANIC_CANARY}");
            }
            Some(ResourceTemplate {
                uri_template: "panic-template://{id}".to_string(),
                name: "template-panic-resource".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            })
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            unreachable!("templated reads use read_with_uri")
        }

        fn read_with_uri(
            &self,
            _ctx: &McpContext,
            uri: &str,
            _params: &UriParams,
        ) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: None,
                text: Some("template-content".to_string()),
                blob: None,
            }])
        }
    }

    struct DefinitionPanicPrompt(std::sync::atomic::AtomicBool);

    impl PromptHandler for DefinitionPanicPrompt {
        fn definition(&self) -> Prompt {
            if self.0.swap(true, Ordering::Relaxed) {
                panic!("{PANIC_CANARY}");
            }
            Prompt {
                name: "definition_panic_prompt".to_string(),
                description: None,
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Ok(vec![])
        }
    }

    // ── Router::new ────────────────────────────────────────────────────

    #[test]
    fn new_router_is_empty() {
        let r = Router::new();
        assert_eq!(r.tools_count(), 0);
        assert_eq!(r.resources_count(), 0);
        assert_eq!(r.resource_templates_count(), 0);
        assert_eq!(r.prompts_count(), 0);
        assert!(r.tools().is_empty());
        assert!(r.resources().is_empty());
        assert!(r.resource_templates().is_empty());
        assert!(r.prompts().is_empty());
    }

    #[test]
    fn default_router_is_empty() {
        let r = Router::default();
        assert_eq!(r.tools_count(), 0);
    }

    // ── add_tool / get_tool ────────────────────────────────────────────

    #[test]
    fn add_and_get_tool() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("my_tool"));
        assert_eq!(r.tools_count(), 1);
        assert!(r.get_tool("my_tool").is_some());
        assert!(r.get_tool("other").is_none());
    }

    #[test]
    fn add_tool_replace_on_duplicate() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("t"));
        r.add_tool(NamedTool::new("t"));
        assert_eq!(r.tools_count(), 1);
        // Order preserved (only one entry)
        assert_eq!(r.tools().len(), 1);
    }

    #[test]
    fn tools_returns_definitions_in_order() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("b"));
        r.add_tool(NamedTool::new("a"));
        let names: Vec<_> = r.tools().iter().map(|t| t.name.clone()).collect();
        assert_eq!(names, vec!["b", "a"]); // insertion order
    }

    // ── add_tool_with_behavior ─────────────────────────────────────────

    #[test]
    fn add_tool_behavior_error_on_duplicate() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("t"));
        let err = r
            .add_tool_with_behavior(NamedTool::new("t"), crate::DuplicateBehavior::Error)
            .unwrap_err();
        assert!(err.message.contains("already exists"));
    }

    #[test]
    fn add_tool_behavior_warn_keeps_original() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("t"));
        r.add_tool_with_behavior(NamedTool::new("t"), crate::DuplicateBehavior::Warn)
            .unwrap();
        assert_eq!(r.tools_count(), 1);
    }

    #[test]
    fn add_tool_behavior_replace() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("t"));
        r.add_tool_with_behavior(NamedTool::new("t"), crate::DuplicateBehavior::Replace)
            .unwrap();
        assert_eq!(r.tools_count(), 1);
    }

    #[test]
    fn add_tool_behavior_ignore() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("t"));
        r.add_tool_with_behavior(NamedTool::new("t"), crate::DuplicateBehavior::Ignore)
            .unwrap();
        assert_eq!(r.tools_count(), 1);
    }

    #[test]
    fn add_tool_behavior_new_tool_ok() {
        let mut r = Router::new();
        r.add_tool_with_behavior(NamedTool::new("t"), crate::DuplicateBehavior::Error)
            .unwrap();
        assert_eq!(r.tools_count(), 1);
    }

    // ── add_resource / get_resource ────────────────────────────────────

    #[test]
    fn add_and_get_resource() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a.txt"));
        assert_eq!(r.resources_count(), 1);
        assert!(r.get_resource("file:///a.txt").is_some());
        assert!(r.get_resource("file:///b.txt").is_none());
    }

    #[test]
    fn resources_returns_definitions_in_order() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///b"));
        r.add_resource(NamedResource::new("file:///a"));
        let uris: Vec<_> = r.resources().iter().map(|res| res.uri.clone()).collect();
        assert_eq!(uris, vec!["file:///b", "file:///a"]);
    }

    // ── add_resource_with_behavior ─────────────────────────────────────

    #[test]
    fn add_resource_behavior_error_on_duplicate() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        let err = r
            .add_resource_with_behavior(
                NamedResource::new("file:///a"),
                crate::DuplicateBehavior::Error,
            )
            .unwrap_err();
        assert!(err.message.contains("already exists"));
    }

    #[test]
    fn add_resource_behavior_ignore() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource_with_behavior(
            NamedResource::new("file:///a"),
            crate::DuplicateBehavior::Ignore,
        )
        .unwrap();
        assert_eq!(r.resources_count(), 1);
    }

    // ── add_prompt / get_prompt ────────────────────────────────────────

    #[test]
    fn add_and_get_prompt() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("greet"));
        assert_eq!(r.prompts_count(), 1);
        assert!(r.get_prompt("greet").is_some());
        assert!(r.get_prompt("other").is_none());
    }

    #[test]
    fn prompts_returns_definitions_in_order() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("z"));
        r.add_prompt(NamedPrompt::new("a"));
        let names: Vec<_> = r.prompts().iter().map(|p| p.name.clone()).collect();
        assert_eq!(names, vec!["z", "a"]);
    }

    // ── add_prompt_with_behavior ───────────────────────────────────────

    #[test]
    fn add_prompt_behavior_error_on_duplicate() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        let err = r
            .add_prompt_with_behavior(NamedPrompt::new("p"), crate::DuplicateBehavior::Error)
            .unwrap_err();
        assert!(err.message.contains("already exists"));
    }

    #[test]
    fn add_prompt_behavior_warn_keeps_original() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        r.add_prompt_with_behavior(NamedPrompt::new("p"), crate::DuplicateBehavior::Warn)
            .unwrap();
        assert_eq!(r.prompts_count(), 1);
    }

    #[test]
    fn duplicate_registration_errors_do_not_echo_peer_identifiers() {
        let canary = "raw-peer-identifier-canary";

        let mut tools = Router::new();
        tools.add_tool(NamedTool::new(canary));
        let tool_error = tools
            .add_tool_with_behavior(NamedTool::new(canary), crate::DuplicateBehavior::Error)
            .unwrap_err();

        let mut resources = Router::new();
        resources.add_resource(NamedResource::new(canary));
        let resource_error = resources
            .add_resource_with_behavior(NamedResource::new(canary), crate::DuplicateBehavior::Error)
            .unwrap_err();

        let mut templates = Router::new();
        templates.add_resource_template(marked_template(canary, "original"));
        let template_error = templates
            .add_resource_template_with_behavior(
                marked_template(canary, "incoming"),
                crate::DuplicateBehavior::Error,
            )
            .unwrap_err();

        let mut prompts = Router::new();
        prompts.add_prompt(NamedPrompt::new(canary));
        let prompt_error = prompts
            .add_prompt_with_behavior(NamedPrompt::new(canary), crate::DuplicateBehavior::Error)
            .unwrap_err();

        for error in [tool_error, resource_error, template_error, prompt_error] {
            assert!(error.message.contains("already exists"));
            assert!(!error.message.contains(canary));
        }
    }

    // ── add_resource_template ──────────────────────────────────────────

    #[test]
    fn add_resource_template_and_list() {
        let mut r = Router::new();
        let tmpl = ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        r.add_resource_template(tmpl);
        assert_eq!(r.resource_templates_count(), 1);
        assert!(r.get_resource_template("db://{table}").is_some());
        assert!(r.get_resource_template("db://{other}").is_none());
    }

    #[test]
    fn add_resource_template_replaces_existing() {
        let mut r = Router::new();
        let tmpl1 = ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db1".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let tmpl2 = ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db2".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        r.add_resource_template(tmpl1);
        r.add_resource_template(tmpl2);
        assert_eq!(r.resource_templates_count(), 1);
        let tmpl = r.get_resource_template("db://{table}").unwrap();
        assert_eq!(tmpl.name, "db2");
    }

    #[test]
    fn add_resource_template_with_behavior_preserves_or_replaces_identity() {
        for behavior in [
            crate::DuplicateBehavior::Warn,
            crate::DuplicateBehavior::Ignore,
            crate::DuplicateBehavior::Error,
        ] {
            let mut router = Router::new();
            router.add_resource_template(marked_template("peer://{secret}", "original"));
            let result = router.add_resource_template_with_behavior(
                marked_template("peer://{secret}", "incoming"),
                behavior,
            );

            if behavior == crate::DuplicateBehavior::Error {
                let error = result.expect_err("Error policy rejects the duplicate");
                assert!(error.message.contains("already exists"));
                assert!(!error.message.contains("peer://{secret}"));
            } else {
                result.expect("Warn and Ignore keep the original");
            }
            assert_eq!(router.resource_templates_count(), 1);
            assert_eq!(
                router
                    .get_resource_template("peer://{secret}")
                    .expect("original template remains")
                    .name,
                "original"
            );
        }

        let mut router = Router::new();
        router.add_resource_template(marked_template("peer://{secret}", "original"));
        router
            .add_resource_template_with_behavior(
                marked_template("peer://{secret}", "incoming"),
                crate::DuplicateBehavior::Replace,
            )
            .expect("Replace accepts the duplicate");
        assert_eq!(router.resource_templates_count(), 1);
        assert_eq!(
            router
                .get_resource_template("peer://{secret}")
                .expect("replacement template exists")
                .name,
            "incoming"
        );
    }

    // ── resource_exists / resolve_resource ──────────────────────────────

    #[test]
    fn resource_exists_for_static_resource() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a.txt"));
        assert!(r.resource_exists("file:///a.txt"));
        assert!(!r.resource_exists("file:///b.txt"));
    }

    // ── strict_input_validation ────────────────────────────────────────

    #[test]
    fn strict_input_validation_default_off() {
        let r = Router::new();
        assert!(!r.strict_input_validation());
    }

    #[test]
    fn set_strict_input_validation() {
        let mut r = Router::new();
        r.set_strict_input_validation(true);
        assert!(r.strict_input_validation());
        r.set_strict_input_validation(false);
        assert!(!r.strict_input_validation());
    }

    // ── set_list_page_size ─────────────────────────────────────────────

    #[test]
    fn set_list_page_size_zero_treated_as_none() {
        let mut r = Router::new();
        r.set_list_page_size(Some(0));
        // Zero page size is filtered to None
        assert!(r.list_page_size.is_none());
    }

    #[test]
    fn set_list_page_size_positive() {
        let mut r = Router::new();
        r.set_list_page_size(Some(10));
        assert_eq!(r.list_page_size, Some(10));
    }

    #[test]
    fn set_list_page_size_none() {
        let mut r = Router::new();
        r.set_list_page_size(Some(10));
        r.set_list_page_size(None);
        assert!(r.list_page_size.is_none());
    }

    // ── tools_filtered ─────────────────────────────────────────────────

    #[test]
    fn tools_filtered_no_filters_returns_all() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("a"));
        r.add_tool(NamedTool::new("b"));
        let tools = r.tools_filtered(None, None);
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn tools_filtered_by_session_state_disables() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("a"));
        r.add_tool(NamedTool::new("b"));
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> = ["a".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_tools", &disabled);
        let tools = r.tools_filtered(Some(&state), None);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "b");
    }

    #[test]
    fn tools_filtered_by_tags() {
        let mut r = Router::new();
        r.add_tool(NamedTool::with_tags("a", vec!["db".to_string()]));
        r.add_tool(NamedTool::with_tags("b", vec!["web".to_string()]));
        let include = vec!["db".to_string()];
        let filters = TagFilters::new(Some(&include), None);
        let tools = r.tools_filtered(None, Some(&filters));
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "a");
    }

    // ── resources_filtered ─────────────────────────────────────────────

    #[test]
    fn resources_filtered_by_session_state() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource(NamedResource::new("file:///b"));
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["file:///a".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_resources", &disabled);
        let res = r.resources_filtered(Some(&state), None);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].uri, "file:///b");
    }

    // ── prompts_filtered ───────────────────────────────────────────────

    #[test]
    fn prompts_filtered_by_session_state() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("a"));
        r.add_prompt(NamedPrompt::new("b"));
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> = ["a".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_prompts", &disabled);
        let prompts = r.prompts_filtered(Some(&state), None);
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "b");
    }

    #[test]
    fn prompts_filtered_by_tags() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::with_tags("a", vec!["internal".to_string()]));
        r.add_prompt(NamedPrompt::with_tags("b", vec!["public".to_string()]));
        let exclude = vec!["internal".to_string()];
        let filters = TagFilters::new(None, Some(&exclude));
        let prompts = r.prompts_filtered(None, Some(&filters));
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "b");
    }

    // ── resource_templates_filtered ────────────────────────────────────

    #[test]
    fn resource_templates_filtered_by_session_state() {
        let mut r = Router::new();
        r.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["admin".to_string()],
        });
        r.add_resource_template(ResourceTemplate {
            uri_template: "cache://{key}".to_string(),
            name: "cache".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["db://{table}".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_resources", &disabled);
        let tmpls = r.resource_templates_filtered(Some(&state), None);
        assert_eq!(tmpls.len(), 1);
        assert_eq!(tmpls[0].name, "cache");
    }

    // ── apply_prefix / validate_prefix ─────────────────────────────────

    #[test]
    fn apply_prefix_with_prefix() {
        assert_eq!(Router::apply_prefix("tool", Some("ns")), "ns/tool");
    }

    #[test]
    fn apply_prefix_no_prefix() {
        assert_eq!(Router::apply_prefix("tool", None), "tool");
    }

    #[test]
    fn apply_prefix_empty_prefix() {
        assert_eq!(Router::apply_prefix("tool", Some("")), "tool");
    }

    #[test]
    fn validate_prefix_valid() {
        assert!(Router::validate_prefix("my-prefix_1").is_ok());
    }

    #[test]
    fn validate_prefix_empty_is_ok() {
        assert!(Router::validate_prefix("").is_ok());
    }

    #[test]
    fn validate_prefix_rejects_slashes() {
        let err = Router::validate_prefix("a/b").unwrap_err();
        assert!(err.contains("slashes"));
    }

    #[test]
    fn validate_prefix_rejects_special_chars() {
        let err = Router::validate_prefix("a@b").unwrap_err();
        assert!(err.contains("invalid character"));
    }

    // ── MountResult ────────────────────────────────────────────────────

    #[test]
    fn mount_result_default_has_no_components() {
        let r = MountResult::default();
        assert!(!r.has_components());
        assert!(r.is_success());
    }

    #[test]
    fn mount_result_with_tools_has_components() {
        let mut r = MountResult::default();
        r.tools = 1;
        assert!(r.has_components());
    }

    #[test]
    fn mount_result_debug() {
        let r = MountResult::default();
        let debug = format!("{:?}", r);
        assert!(debug.contains("MountResult"));
    }

    // ── mount ──────────────────────────────────────────────────────────

    #[test]
    fn mount_tools_with_prefix() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("query"));
        let result = main.mount(sub, Some("db"));
        assert_eq!(result.tools, 1);
        assert!(main.get_tool("db/query").is_some());
        assert!(main.get_tool("query").is_none());
    }

    #[test]
    fn mount_without_prefix() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("query"));
        let result = main.mount(sub, None);
        assert_eq!(result.tools, 1);
        assert!(main.get_tool("query").is_some());
    }

    #[test]
    fn mount_resources_with_prefix() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_resource(NamedResource::new("file:///a"));
        let result = main.mount(sub, Some("ns"));
        assert_eq!(result.resources, 1);
        assert!(main.get_resource("ns/file:///a").is_some());

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let read = main
            .handle_resources_read(
                &request_ctx,
                &ReadResourceParams {
                    uri: "ns/file:///a".to_string(),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("mounted resource is readable through its public URI");
        assert_eq!(read.contents[0].uri, "ns/file:///a");
    }

    #[test]
    fn mounting_resource_does_not_requery_one_shot_definition() {
        let mut source = Router::new();
        source.add_resource(DefinitionPanicResource(std::sync::atomic::AtomicBool::new(
            false,
        )));
        let mut destination = Router::new();

        let result = destination.mount_resources(source, Some("ns"));

        assert!(result.is_success());
        assert_eq!(result.resources, 1);
        assert!(destination.get_resource("ns/panic://definition").is_some());
    }

    #[test]
    fn mounting_resource_template_does_not_requery_one_shot_template() {
        let mut source = Router::new();
        source.add_resource(TemplatePanicResource(std::sync::atomic::AtomicBool::new(
            false,
        )));
        let mut destination = Router::new();

        let result = destination.mount_resources(source, Some("ns"));

        assert!(result.is_success());
        assert_eq!(result.resource_templates, 1);
        assert!(
            destination
                .get_resource_template("ns/panic-template://{id}")
                .is_some()
        );
    }

    #[test]
    fn nested_resource_mounts_translate_both_namespace_layers() {
        let mut leaf = Router::new();
        leaf.add_resource(NamedResource::new("file:///a"));

        let mut middle = Router::new();
        assert!(middle.mount(leaf, Some("ns")).is_success());
        let mut outer = Router::new();
        assert!(outer.mount(middle, Some("ns")).is_success());

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let read = outer
            .handle_resources_read(
                &request_ctx,
                &ReadResourceParams {
                    uri: "ns/ns/file:///a".to_string(),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("nested mounted resource is readable");
        assert_eq!(read.contents[0].uri, "ns/ns/file:///a");
    }

    #[test]
    fn nested_resource_template_mounts_translate_every_namespace_layer() {
        struct TemplatedResource;

        impl ResourceHandler for TemplatedResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "db://placeholder".to_string(),
                    name: "database".to_string(),
                    description: None,
                    mime_type: Some("text/plain".to_string()),
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }

            fn template(&self) -> Option<ResourceTemplate> {
                Some(ResourceTemplate {
                    uri_template: "db://{table}".to_string(),
                    name: "database".to_string(),
                    description: None,
                    mime_type: Some("text/plain".to_string()),
                    icon: None,
                    version: None,
                    tags: vec![],
                })
            }

            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                unreachable!("templated reads use read_with_uri")
            }

            fn read_with_uri(
                &self,
                _ctx: &McpContext,
                uri: &str,
                params: &UriParams,
            ) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some("text/plain".to_string()),
                    text: params.get("table").cloned(),
                    blob: None,
                }])
            }
        }

        let mut source = Router::new();
        source.add_resource(TemplatedResource);
        let mut middle = Router::new();
        assert!(middle.mount_resources(source, Some("peer")).is_success());
        let mut mounted = Router::new();
        assert!(mounted.mount_resources(middle, Some("peer")).is_success());

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let read = mounted
            .handle_resources_read(
                &request_ctx,
                &ReadResourceParams {
                    uri: "peer/peer/db://users".to_string(),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("mounted template is readable through its public URI");
        assert_eq!(read.contents[0].uri, "peer/peer/db://users");
        assert_eq!(read.contents[0].text.as_deref(), Some("users"));
    }

    #[test]
    fn handle_resources_read_resolves_true_async_mounted_template_and_translates_uri() {
        struct AsyncTemplatedResource {
            observed: Arc<Mutex<Option<(String, String)>>>,
        }

        impl ResourceHandler for AsyncTemplatedResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "async-db://placeholder".to_string(),
                    name: "async-database".to_string(),
                    description: None,
                    mime_type: Some("text/plain".to_string()),
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }

            fn template(&self) -> Option<ResourceTemplate> {
                Some(ResourceTemplate {
                    uri_template: "async-db://{table}".to_string(),
                    name: "async-database".to_string(),
                    description: None,
                    mime_type: Some("text/plain".to_string()),
                    icon: None,
                    version: None,
                    tags: vec![],
                })
            }

            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                unreachable!("router must dispatch templated resources through the async override")
            }

            fn read_with_uri(
                &self,
                _ctx: &McpContext,
                _uri: &str,
                _params: &UriParams,
            ) -> McpResult<Vec<ResourceContent>> {
                unreachable!("router must not fall back to the synchronous templated read")
            }

            fn read_async_with_uri<'a>(
                &'a self,
                _ctx: &'a McpContext,
                uri: &'a str,
                params: &'a UriParams,
            ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
                Box::pin(async move {
                    let mut first_poll = true;
                    std::future::poll_fn(move |waker| {
                        if std::mem::take(&mut first_poll) {
                            waker.waker().wake_by_ref();
                            std::task::Poll::Pending
                        } else {
                            std::task::Poll::Ready(())
                        }
                    })
                    .await;
                    let Some(table) = params.get("table").cloned() else {
                        return Outcome::Err(McpError::invalid_params(
                            "mounted template did not resolve its table parameter",
                        ));
                    };
                    *self.observed.lock().expect("observation mutex poisoned") =
                        Some((uri.to_string(), table.clone()));
                    Outcome::Ok(vec![ResourceContent {
                        uri: uri.to_string(),
                        mime_type: Some("text/plain".to_string()),
                        text: Some(format!("async table {table}")),
                        blob: None,
                    }])
                })
            }
        }

        let observed = Arc::new(Mutex::new(None));
        let mut source = Router::new();
        source.add_resource(AsyncTemplatedResource {
            observed: Arc::clone(&observed),
        });
        let mut mounted = Router::new();
        let mount_result = mounted.mount_resources(source, Some("peer"));
        assert!(mount_result.is_success());
        assert_eq!(mount_result.resource_templates, 1);

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let read = mounted
            .handle_resources_read(
                &request_ctx,
                &ReadResourceParams {
                    uri: "peer/async-db://users".to_string(),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("true-async mounted template is readable through its public URI");

        assert_eq!(read.contents.len(), 1);
        assert_eq!(read.contents[0].uri, "peer/async-db://users");
        assert_eq!(read.contents[0].text.as_deref(), Some("async table users"));
        assert_eq!(
            *observed.lock().expect("observation mutex poisoned"),
            Some(("async-db://users".to_string(), "users".to_string()))
        );
    }

    #[test]
    fn mount_prompts_with_prefix() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_prompt(NamedPrompt::new("greet"));
        let result = main.mount(sub, Some("ns"));
        assert_eq!(result.prompts, 1);
        assert!(main.get_prompt("ns/greet").is_some());
    }

    #[test]
    fn mount_warns_on_conflict() {
        let mut main = Router::new();
        main.add_tool(NamedTool::new("t"));
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("t"));
        let result = main.mount(sub, None);
        assert_eq!(result.tools, 1);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("already exists"));
    }

    #[test]
    fn mount_rejects_invalid_prefix_without_mutating() {
        let mut main = Router::new();
        main.add_tool(NamedTool::new("original"));
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("incoming"));
        let result = main.mount(sub, Some("bad/prefix"));
        assert!(!result.is_success());
        assert_eq!(result.tools, 0);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("slashes"));
        assert!(!result.errors[0].contains("bad/prefix"));
        assert_eq!(main.tools_count(), 1);
        assert!(main.get_tool("original").is_some());
        assert!(main.get_tool("bad/prefix/incoming").is_none());
    }

    #[test]
    fn mount_with_behavior_honors_policy_for_every_component_kind() {
        for behavior in [
            crate::DuplicateBehavior::Warn,
            crate::DuplicateBehavior::Ignore,
            crate::DuplicateBehavior::Replace,
            crate::DuplicateBehavior::Error,
        ] {
            let mut main = marked_router("original");
            let mut sub = marked_router("incoming");
            if behavior == crate::DuplicateBehavior::Error {
                sub.add_tool(NamedTool::new("unique_tool"));
            }

            let result = main.mount_with_behavior(sub, None, behavior);
            let replaced = behavior == crate::DuplicateBehavior::Replace;
            let rejected = behavior == crate::DuplicateBehavior::Error;
            let expected_mounted = if replaced { 1 } else { 0 };

            assert_eq!(result.is_success(), !rejected);
            assert_eq!(result.tools, expected_mounted);
            assert_eq!(result.resources, expected_mounted);
            assert_eq!(result.resource_templates, expected_mounted);
            assert_eq!(result.prompts, expected_mounted);
            assert_eq!(result.errors.len(), if rejected { 4 } else { 0 });
            assert_eq!(
                result.warnings.len(),
                if matches!(
                    behavior,
                    crate::DuplicateBehavior::Warn | crate::DuplicateBehavior::Replace
                ) {
                    4
                } else {
                    0
                }
            );
            assert_router_marker(&main, if replaced { "incoming" } else { "original" });
            assert!(main.get_tool("unique_tool").is_none());

            for message in result.warnings.iter().chain(&result.errors) {
                assert!(!message.contains("duplicate_tool"));
                assert!(!message.contains("duplicate://resource"));
                assert!(!message.contains("duplicate://{item}"));
                assert!(!message.contains("duplicate_prompt"));
            }
        }
    }

    #[test]
    fn behavior_aware_partial_mounts_preflight_error_atomically() {
        let mut tools = Router::new();
        tools.add_tool(NamedTool::with_tags("same", vec!["original".to_string()]));
        let mut tool_source = Router::new();
        tool_source.add_tool(NamedTool::with_tags("same", vec!["incoming".to_string()]));
        tool_source.add_tool(NamedTool::new("unique"));
        let tool_result =
            tools.mount_tools_with_behavior(tool_source, None, crate::DuplicateBehavior::Error);
        assert!(!tool_result.is_success());
        assert_eq!(tool_result.tools, 0);
        assert_eq!(tools.tools_count(), 1);
        assert_eq!(
            tools.get_tool("same").unwrap().definition().tags,
            vec!["original".to_string()]
        );
        assert!(tools.get_tool("unique").is_none());

        let mut resources = Router::new();
        resources.add_resource(NamedResource::with_tags(
            "same://resource",
            vec!["original".to_string()],
        ));
        let mut resource_source = Router::new();
        resource_source.add_resource(NamedResource::with_tags(
            "same://resource",
            vec!["incoming".to_string()],
        ));
        resource_source.add_resource_template(marked_template("unique://{item}", "incoming"));
        let resource_result = resources.mount_resources_with_behavior(
            resource_source,
            None,
            crate::DuplicateBehavior::Error,
        );
        assert!(!resource_result.is_success());
        assert_eq!(resource_result.resources, 0);
        assert_eq!(resource_result.resource_templates, 0);
        assert_eq!(resources.resources_count(), 1);
        assert_eq!(resources.resource_templates_count(), 0);
        assert_eq!(
            resources
                .get_resource("same://resource")
                .unwrap()
                .definition()
                .tags,
            vec!["original".to_string()]
        );

        let mut prompts = Router::new();
        prompts.add_prompt(NamedPrompt::with_tags("same", vec!["original".to_string()]));
        let mut prompt_source = Router::new();
        prompt_source.add_prompt(NamedPrompt::with_tags("same", vec!["incoming".to_string()]));
        prompt_source.add_prompt(NamedPrompt::new("unique"));
        let prompt_result = prompts.mount_prompts_with_behavior(
            prompt_source,
            None,
            crate::DuplicateBehavior::Error,
        );
        assert!(!prompt_result.is_success());
        assert_eq!(prompt_result.prompts, 0);
        assert_eq!(prompts.prompts_count(), 1);
        assert_eq!(
            prompts.get_prompt("same").unwrap().definition().tags,
            vec!["original".to_string()]
        );
        assert!(prompts.get_prompt("unique").is_none());
    }

    #[test]
    fn full_error_mount_is_atomic_across_component_kinds() {
        let mut main = Router::new();
        main.add_tool(NamedTool::with_tags(
            "conflict",
            vec!["original".to_string()],
        ));

        let mut sub = Router::new();
        sub.add_tool(NamedTool::with_tags(
            "conflict",
            vec!["incoming".to_string()],
        ));
        sub.add_resource(NamedResource::new("unique://resource"));
        sub.add_resource_template(marked_template("unique://{item}", "incoming"));
        sub.add_prompt(NamedPrompt::new("unique_prompt"));

        let result = main.mount_with_behavior(sub, None, crate::DuplicateBehavior::Error);
        assert!(!result.is_success());
        assert_eq!(result.errors.len(), 1);
        assert!(!result.has_components());
        assert_eq!(main.tools_count(), 1);
        assert_eq!(main.resources_count(), 0);
        assert_eq!(main.resource_templates_count(), 0);
        assert_eq!(main.prompts_count(), 0);
        assert_eq!(
            main.get_tool("conflict").unwrap().definition().tags,
            vec!["original".to_string()]
        );
    }

    #[test]
    fn invalid_prefix_rejects_every_partial_mount_without_mutation() {
        let mut tools = Router::new();
        let mut tool_source = Router::new();
        tool_source.add_tool(NamedTool::new("tool"));
        let tool_result = tools.mount_tools_with_behavior(
            tool_source,
            Some("peer/secret"),
            crate::DuplicateBehavior::Replace,
        );
        assert!(!tool_result.is_success());
        assert_eq!(tools.tools_count(), 0);

        let mut resources = Router::new();
        let mut resource_source = Router::new();
        resource_source.add_resource(NamedResource::new("resource://value"));
        resource_source.add_resource_template(marked_template("template://{value}", "incoming"));
        let resource_result = resources.mount_resources_with_behavior(
            resource_source,
            Some("peer/secret"),
            crate::DuplicateBehavior::Replace,
        );
        assert!(!resource_result.is_success());
        assert_eq!(resources.resources_count(), 0);
        assert_eq!(resources.resource_templates_count(), 0);

        let mut prompts = Router::new();
        let mut prompt_source = Router::new();
        prompt_source.add_prompt(NamedPrompt::new("prompt"));
        let prompt_result = prompts.mount_prompts_with_behavior(
            prompt_source,
            Some("peer/secret"),
            crate::DuplicateBehavior::Replace,
        );
        assert!(!prompt_result.is_success());
        assert_eq!(prompts.prompts_count(), 0);

        for result in [tool_result, resource_result, prompt_result] {
            assert_eq!(result.errors.len(), 1);
            assert!(!result.errors[0].contains("peer/secret"));
            assert!(!result.has_components());
        }
    }

    // ── mount_tools / mount_resources / mount_prompts ──────────────────

    #[test]
    fn mount_tools_only() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("t1"));
        sub.add_prompt(NamedPrompt::new("p1"));
        let result = main.mount_tools(sub, Some("ns"));
        assert_eq!(result.tools, 1);
        assert!(main.get_tool("ns/t1").is_some());
        assert_eq!(main.prompts_count(), 0); // prompts not mounted
    }

    #[test]
    fn mount_prompts_only() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("t1"));
        sub.add_prompt(NamedPrompt::new("p1"));
        let result = main.mount_prompts(sub, Some("ns"));
        assert_eq!(result.prompts, 1);
        assert!(main.get_prompt("ns/p1").is_some());
        assert_eq!(main.tools_count(), 0); // tools not mounted
    }

    // ── handle_tools_list pagination ───────────────────────────────────

    #[test]
    fn handle_tools_list_no_pagination() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("a"));
        r.add_tool(NamedTool::new("b"));
        let cx = Cx::for_testing();
        let params = ListToolsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.tools.len(), 2);
        assert!(result.next_cursor.is_none());
    }

    #[test]
    fn handle_tools_list_with_pagination() {
        let mut r = Router::new();
        r.set_list_page_size(Some(1));
        r.add_tool(NamedTool::new("a"));
        r.add_tool(NamedTool::new("b"));
        let cx = Cx::for_testing();
        let request_ctx = McpContext::new(cx, 1);

        // First page
        let params = ListToolsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "a");
        assert!(result.next_cursor.is_some());

        // Second page
        let params = ListToolsParams {
            cursor: result.next_cursor,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "b");
        assert!(result.next_cursor.is_none());
    }

    #[test]
    fn handle_tools_list_with_tag_filter() {
        let mut r = Router::new();
        r.add_tool(NamedTool::with_tags("a", vec!["db".to_string()]));
        r.add_tool(NamedTool::with_tags("b", vec!["web".to_string()]));
        let cx = Cx::for_testing();
        let params = ListToolsParams {
            cursor: None,
            include_tags: Some(vec!["db".to_string()]),
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "a");
    }

    // ── handle_resources_list pagination ───────────────────────────────

    #[test]
    fn handle_resources_list_no_pagination() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        let cx = Cx::for_testing();
        let params = ListResourcesParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_resources_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.resources.len(), 1);
        assert!(result.next_cursor.is_none());
    }

    #[test]
    fn handle_resources_list_with_pagination() {
        let mut r = Router::new();
        r.set_list_page_size(Some(1));
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource(NamedResource::new("file:///b"));
        let cx = Cx::for_testing();
        let params = ListResourcesParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_resources_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.resources.len(), 1);
        assert!(result.next_cursor.is_some());
    }

    // ── handle_prompts_list pagination ─────────────────────────────────

    #[test]
    fn handle_prompts_list_no_pagination() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("greet"));
        let cx = Cx::for_testing();
        let params = ListPromptsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_prompts_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.prompts.len(), 1);
        assert!(result.next_cursor.is_none());
    }

    // ── handle_resource_templates_list ──────────────────────────────────

    #[test]
    fn handle_resource_templates_list_no_pagination() {
        let mut r = Router::new();
        r.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let cx = Cx::for_testing();
        let params = ListResourceTemplatesParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r
            .handle_resource_templates_list(&request_ctx, params, None)
            .unwrap();
        assert_eq!(result.resource_templates.len(), 1);
        assert!(result.next_cursor.is_none());
    }

    // ── handle_initialize ──────────────────────────────────────────────

    #[test]
    fn handle_initialize_returns_protocol_version() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let mut session = Session::new(
            fastmcp_protocol::ServerInfo {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
            fastmcp_protocol::ServerCapabilities::default(),
        );
        let params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: fastmcp_protocol::ClientCapabilities::default(),
            client_info: fastmcp_protocol::ClientInfo {
                name: "test-client".to_string(),
                version: "1.0".to_string(),
            },
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r
            .handle_initialize(
                &request_ctx,
                &mut session,
                params,
                Some("test instructions"),
            )
            .unwrap();
        assert_eq!(result.protocol_version, PROTOCOL_VERSION);
        assert_eq!(result.server_info.name, "test");
        assert_eq!(result.instructions.as_deref(), Some("test instructions"));
    }

    #[test]
    fn handle_initialize_no_instructions() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let mut session = Session::new(
            fastmcp_protocol::ServerInfo {
                name: "srv".to_string(),
                version: "0.1".to_string(),
            },
            fastmcp_protocol::ServerCapabilities::default(),
        );
        let params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: fastmcp_protocol::ClientCapabilities::default(),
            client_info: fastmcp_protocol::ClientInfo {
                name: "c".to_string(),
                version: "0.1".to_string(),
            },
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r
            .handle_initialize(&request_ctx, &mut session, params, None)
            .unwrap();
        assert!(result.instructions.is_none());
    }

    // ── handle_tasks_list/get/cancel/submit without manager ────────────

    #[test]
    fn handle_tasks_list_no_manager_errors() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let params = ListTasksParams {
            cursor: None,
            status: None,
            limit: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let err = r.handle_tasks_list(&request_ctx, params, None).unwrap_err();
        assert!(err.message.contains("not enabled"));
    }

    #[test]
    fn handle_tasks_get_no_manager_errors() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let params = GetTaskParams {
            id: fastmcp_protocol::TaskId("test-id".to_string()),
        };
        let request_ctx = McpContext::new(cx, 1);
        let err = r.handle_tasks_get(&request_ctx, params, None).unwrap_err();
        assert!(err.message.contains("not enabled"));
    }

    #[test]
    fn handle_tasks_cancel_no_manager_errors() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let params = CancelTaskParams {
            id: fastmcp_protocol::TaskId("test-id".to_string()),
            reason: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let err = r
            .handle_tasks_cancel(&request_ctx, params, None)
            .unwrap_err();
        assert!(err.message.contains("not enabled"));
    }

    #[test]
    fn handle_tasks_submit_no_manager_errors() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let params = SubmitTaskParams {
            task_type: "test".to_string(),
            params: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let err = r
            .handle_tasks_submit(&request_ctx, params, None)
            .unwrap_err();
        assert!(err.message.contains("not enabled"));
    }

    // ── add_resource_with_behavior (Warn / Replace) ─────────────────────

    #[test]
    fn add_resource_behavior_warn_keeps_original() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource_with_behavior(
            NamedResource::new("file:///a"),
            crate::DuplicateBehavior::Warn,
        )
        .unwrap();
        assert_eq!(r.resources_count(), 1);
    }

    #[test]
    fn add_resource_behavior_replace() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource_with_behavior(
            NamedResource::new("file:///a"),
            crate::DuplicateBehavior::Replace,
        )
        .unwrap();
        assert_eq!(r.resources_count(), 1);
    }

    #[test]
    fn add_resource_behavior_new_resource_ok() {
        let mut r = Router::new();
        r.add_resource_with_behavior(
            NamedResource::new("file:///a"),
            crate::DuplicateBehavior::Error,
        )
        .unwrap();
        assert_eq!(r.resources_count(), 1);
    }

    // ── add_prompt_with_behavior (Replace / Ignore / new) ───────────────

    #[test]
    fn add_prompt_behavior_replace() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        r.add_prompt_with_behavior(NamedPrompt::new("p"), crate::DuplicateBehavior::Replace)
            .unwrap();
        assert_eq!(r.prompts_count(), 1);
    }

    #[test]
    fn add_prompt_behavior_ignore() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        r.add_prompt_with_behavior(NamedPrompt::new("p"), crate::DuplicateBehavior::Ignore)
            .unwrap();
        assert_eq!(r.prompts_count(), 1);
    }

    #[test]
    fn add_prompt_behavior_new_prompt_ok() {
        let mut r = Router::new();
        r.add_prompt_with_behavior(NamedPrompt::new("p"), crate::DuplicateBehavior::Error)
            .unwrap();
        assert_eq!(r.prompts_count(), 1);
    }

    // ── add_resource / add_prompt duplicate replace ─────────────────────

    #[test]
    fn add_resource_replaces_on_duplicate() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource(NamedResource::new("file:///a"));
        assert_eq!(r.resources_count(), 1);
        assert_eq!(r.resources().len(), 1);
    }

    #[test]
    fn add_prompt_replaces_on_duplicate() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        r.add_prompt(NamedPrompt::new("p"));
        assert_eq!(r.prompts_count(), 1);
        assert_eq!(r.prompts().len(), 1);
    }

    // ── resource_exists for template match ──────────────────────────────

    #[test]
    fn resource_exists_for_template_match() {
        struct DbResource;
        impl ResourceHandler for DbResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "db://placeholder".to_string(),
                    name: "db".to_string(),
                    description: None,
                    mime_type: Some("text/plain".to_string()),
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }
            fn template(&self) -> Option<ResourceTemplate> {
                Some(ResourceTemplate {
                    uri_template: "db://{table}".to_string(),
                    name: "db".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                })
            }
            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<fastmcp_protocol::ResourceContent>> {
                Ok(vec![])
            }
        }
        let mut r = Router::new();
        r.add_resource(DbResource);
        assert!(r.resource_exists("db://users"));
        assert!(!r.resource_exists("file://other"));
    }

    // ── resources_filtered by tags ──────────────────────────────────────

    #[test]
    fn resources_filtered_by_tags() {
        let mut r = Router::new();
        r.add_resource(NamedResource::with_tags(
            "file:///a",
            vec!["internal".to_string()],
        ));
        r.add_resource(NamedResource::with_tags(
            "file:///b",
            vec!["public".to_string()],
        ));
        let include = vec!["public".to_string()];
        let filters = TagFilters::new(Some(&include), None);
        let res = r.resources_filtered(None, Some(&filters));
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].uri, "file:///b");
    }

    // ── resource_templates_filtered by tags ─────────────────────────────

    #[test]
    fn resource_templates_filtered_by_tags() {
        let mut r = Router::new();
        r.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["admin".to_string()],
        });
        r.add_resource_template(ResourceTemplate {
            uri_template: "cache://{key}".to_string(),
            name: "cache".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["public".to_string()],
        });
        let exclude = vec!["admin".to_string()];
        let filters = TagFilters::new(None, Some(&exclude));
        let tmpls = r.resource_templates_filtered(None, Some(&filters));
        assert_eq!(tmpls.len(), 1);
        assert_eq!(tmpls[0].name, "cache");
    }

    // ── handle_tools_list with session state ────────────────────────────

    #[test]
    fn handle_tools_list_with_session_state_filter() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("a"));
        r.add_tool(NamedTool::new("b"));
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> = ["a".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_tools", &disabled);
        let params = ListToolsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let result = r
            .handle_tools_list(&request_ctx, params, Some(&state))
            .unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "b");
    }

    // ── handle_resources_list with tag filter ────────────────────────────

    #[test]
    fn handle_resources_list_with_tag_filter() {
        let mut r = Router::new();
        r.add_resource(NamedResource::with_tags(
            "file:///a",
            vec!["db".to_string()],
        ));
        r.add_resource(NamedResource::with_tags(
            "file:///b",
            vec!["web".to_string()],
        ));
        let cx = Cx::for_testing();
        let params = ListResourcesParams {
            cursor: None,
            include_tags: Some(vec!["web".to_string()]),
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_resources_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.resources[0].uri, "file:///b");
    }

    // ── handle_prompts_list with pagination ──────────────────────────────

    #[test]
    fn handle_prompts_list_with_pagination() {
        let mut r = Router::new();
        r.set_list_page_size(Some(1));
        r.add_prompt(NamedPrompt::new("a"));
        r.add_prompt(NamedPrompt::new("b"));
        let cx = Cx::for_testing();
        let params = ListPromptsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_prompts_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.prompts.len(), 1);
        assert_eq!(result.prompts[0].name, "a");
        assert!(result.next_cursor.is_some());

        let params = ListPromptsParams {
            cursor: result.next_cursor,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r.handle_prompts_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.prompts.len(), 1);
        assert_eq!(result.prompts[0].name, "b");
        assert!(result.next_cursor.is_none());
    }

    // ── handle_prompts_list with tag filter ──────────────────────────────

    #[test]
    fn handle_prompts_list_with_tag_filter() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::with_tags("a", vec!["internal".to_string()]));
        r.add_prompt(NamedPrompt::with_tags("b", vec!["public".to_string()]));
        let cx = Cx::for_testing();
        let params = ListPromptsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: Some(vec!["internal".to_string()]),
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_prompts_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.prompts.len(), 1);
        assert_eq!(result.prompts[0].name, "b");
    }

    // ── handle_resource_templates_list with pagination ───────────────────

    #[test]
    fn handle_resource_templates_list_with_pagination() {
        let mut r = Router::new();
        r.set_list_page_size(Some(1));
        r.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        r.add_resource_template(ResourceTemplate {
            uri_template: "cache://{key}".to_string(),
            name: "cache".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let cx = Cx::for_testing();
        let request_ctx = McpContext::new(cx, 1);
        let params = ListResourceTemplatesParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r
            .handle_resource_templates_list(&request_ctx, params, None)
            .unwrap();
        assert_eq!(result.resource_templates.len(), 1);
        assert!(result.next_cursor.is_some());

        let params = ListResourceTemplatesParams {
            cursor: result.next_cursor,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r
            .handle_resource_templates_list(&request_ctx, params, None)
            .unwrap();
        assert_eq!(result.resource_templates.len(), 1);
        assert!(result.next_cursor.is_none());
    }

    // ── handle_resource_templates_list with tag filter ───────────────────

    #[test]
    fn handle_resource_templates_list_with_tag_filter() {
        let mut r = Router::new();
        r.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["admin".to_string()],
        });
        r.add_resource_template(ResourceTemplate {
            uri_template: "cache://{key}".to_string(),
            name: "cache".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["public".to_string()],
        });
        let cx = Cx::for_testing();
        let params = ListResourceTemplatesParams {
            cursor: None,
            include_tags: Some(vec!["public".to_string()]),
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r
            .handle_resource_templates_list(&request_ctx, params, None)
            .unwrap();
        assert_eq!(result.resource_templates.len(), 1);
        assert_eq!(result.resource_templates[0].name, "cache");
    }

    // ── mount_resources (selective method) ───────────────────────────────

    #[test]
    fn mount_resources_only() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_resource(NamedResource::new("file:///a"));
        sub.add_tool(NamedTool::new("t1"));
        sub.add_resource_template(ResourceTemplate {
            uri_template: "db://{t}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let result = main.mount_resources(sub, Some("ns"));
        assert_eq!(result.resources, 1);
        assert_eq!(result.resource_templates, 1);
        assert!(main.get_resource("ns/file:///a").is_some());
        assert_eq!(main.tools_count(), 0); // tools not mounted
    }

    // ── MountResult has_components with all fields ──────────────────────

    #[test]
    fn mount_result_with_resources_has_components() {
        let mut r = MountResult::default();
        r.resources = 1;
        assert!(r.has_components());
    }

    #[test]
    fn mount_result_with_templates_has_components() {
        let mut r = MountResult::default();
        r.resource_templates = 1;
        assert!(r.has_components());
    }

    #[test]
    fn mount_result_with_prompts_has_components() {
        let mut r = MountResult::default();
        r.prompts = 1;
        assert!(r.has_components());
    }

    #[test]
    fn mount_result_is_success_with_warnings() {
        let mut r = MountResult::default();
        r.warnings.push("something".to_string());
        assert!(r.is_success());
    }

    #[test]
    fn mount_result_reports_errors_as_failure() {
        let mut result = MountResult::default();
        result.errors.push("mount rejected".to_string());
        assert!(!result.is_success());
        assert!(!result.has_components());
    }

    // ── mount with all component types ──────────────────────────────────

    #[test]
    fn mount_all_component_types() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("t1"));
        sub.add_resource(NamedResource::new("file:///r1"));
        sub.add_prompt(NamedPrompt::new("p1"));
        sub.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let result = main.mount(sub, Some("ns"));
        assert_eq!(result.tools, 1);
        assert_eq!(result.resources, 1);
        assert_eq!(result.prompts, 1);
        assert_eq!(result.resource_templates, 1);
        assert!(result.has_components());
        assert!(main.get_tool("ns/t1").is_some());
        assert!(main.get_resource("ns/file:///r1").is_some());
        assert!(main.get_prompt("ns/p1").is_some());
    }

    // ── mount resource conflict warnings ────────────────────────────────

    #[test]
    fn mount_warns_on_resource_conflict() {
        let mut main = Router::new();
        main.add_resource(NamedResource::new("file:///a"));
        let mut sub = Router::new();
        sub.add_resource(NamedResource::new("file:///a"));
        let result = main.mount(sub, None);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("Resource"));
    }

    #[test]
    fn mount_warns_on_prompt_conflict() {
        let mut main = Router::new();
        main.add_prompt(NamedPrompt::new("p"));
        let mut sub = Router::new();
        sub.add_prompt(NamedPrompt::new("p"));
        let result = main.mount(sub, None);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("Prompt"));
    }

    // ── TagFilters::clone ───────────────────────────────────────────────

    #[test]
    fn tag_filters_clone() {
        let include = vec!["a".to_string()];
        let f = TagFilters::new(Some(&include), None);
        let cloned = f.clone();
        assert!(cloned.matches(&["a".to_string()]));
        assert!(!cloned.matches(&["b".to_string()]));
    }

    // ── handle_tools_list with pagination AND tags ───────────────────────

    #[test]
    fn handle_tools_list_pagination_with_tags() {
        let mut r = Router::new();
        r.set_list_page_size(Some(1));
        r.add_tool(NamedTool::with_tags("a", vec!["db".to_string()]));
        r.add_tool(NamedTool::with_tags("b", vec!["db".to_string()]));
        r.add_tool(NamedTool::with_tags("c", vec!["web".to_string()]));
        let cx = Cx::for_testing();
        let request_ctx = McpContext::new(cx, 1);

        // Only "db" tagged tools, page 1
        let params = ListToolsParams {
            cursor: None,
            include_tags: Some(vec!["db".to_string()]),
            exclude_tags: None,
        };
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "a");
        assert!(result.next_cursor.is_some());

        // Page 2
        let params = ListToolsParams {
            cursor: result.next_cursor,
            include_tags: Some(vec!["db".to_string()]),
            exclude_tags: None,
        };
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "b");
        assert!(result.next_cursor.is_none());
    }

    // ── handle_resources_list with session state filter ──────────────────

    #[test]
    fn handle_resources_list_with_session_state_filter() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource(NamedResource::new("file:///b"));
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["file:///a".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_resources", &disabled);
        let params = ListResourcesParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let result = r
            .handle_resources_list(&request_ctx, params, Some(&state))
            .unwrap();
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.resources[0].uri, "file:///b");
    }

    // ── handle_prompts_list with session state filter ────────────────────

    #[test]
    fn handle_prompts_list_with_session_state_filter() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("a"));
        r.add_prompt(NamedPrompt::new("b"));
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> = ["a".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_prompts", &disabled);
        let params = ListPromptsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let result = r
            .handle_prompts_list(&request_ctx, params, Some(&state))
            .unwrap();
        assert_eq!(result.prompts.len(), 1);
        assert_eq!(result.prompts[0].name, "b");
    }

    // ── resource_templates_filtered by session + tags combined ───────────

    #[test]
    fn resource_templates_filtered_session_and_tags_combined() {
        let mut r = Router::new();
        r.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["admin".to_string()],
        });
        r.add_resource_template(ResourceTemplate {
            uri_template: "cache://{key}".to_string(),
            name: "cache".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["admin".to_string()],
        });
        r.add_resource_template(ResourceTemplate {
            uri_template: "log://{entry}".to_string(),
            name: "log".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["public".to_string()],
        });
        // Disable db template via session state
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["db://{table}".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_resources", &disabled);
        // Also filter by admin tag
        let include = vec!["admin".to_string()];
        let filters = TagFilters::new(Some(&include), None);
        let tmpls = r.resource_templates_filtered(Some(&state), Some(&filters));
        // db is disabled, log doesn't have admin tag => only cache
        assert_eq!(tmpls.len(), 1);
        assert_eq!(tmpls[0].name, "cache");
    }

    // ── mount_tools warns on template conflict ──────────────────────────

    #[test]
    fn mount_resource_template_warns_on_conflict() {
        let mut main = Router::new();
        main.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let mut sub = Router::new();
        sub.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db2".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let result = main.mount(sub, None);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("Resource template"));
    }

    // ── handle_tools_call: tool disabled via session ─────────────────────

    #[test]
    fn handle_tools_call_disabled_tool_returns_error() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("my_tool"));
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["my_tool".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_tools", &disabled);
        let params = CallToolParams {
            name: "my_tool".to_string(),
            arguments: None,
            meta: None,
        };
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_tools_call(&request_ctx, params, state, None, None)
            .unwrap_err();
        assert!(err.message.contains("disabled"));
    }

    // ── handle_tools_call: success path ──────────────────────────────────

    #[test]
    fn handle_tools_call_success() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("echo"));
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let params = CallToolParams {
            name: "echo".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let result = r
            .handle_tools_call(&request_ctx, params, state, None, None)
            .unwrap();
        assert!(!result.is_error);
        assert!(!result.content.is_empty());
    }

    // ── handle_tools_call: not found ─────────────────────────────────────

    #[test]
    fn handle_tools_call_not_found() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let params = CallToolParams {
            name: "missing".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_tools_call(&request_ctx, params, state, None, None)
            .unwrap_err();
        assert!(err.message.contains("missing"));
    }

    // ── handle_tools_call: zero poll balance without poll admission ──────

    #[test]
    fn handle_tools_call_zero_poll_balance_allows_handler_without_checkpoint() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("t"));
        let cx = Cx::for_testing();
        let budget = Budget::unlimited().with_poll_quota(0);
        let params = CallToolParams {
            name: "t".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let result = r
            .handle_tools_call(&request_ctx, params, state, None, None)
            .expect("a zero balance is not a retroactive failure");
        assert!(!result.is_error);
    }

    #[test]
    fn handle_tools_call_defers_pending_cancellation_inside_context_mask() {
        let mut router = Router::new();
        router.add_tool(NamedTool::new("t"));
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let params = || CallToolParams {
            name: "t".to_string(),
            arguments: None,
            meta: None,
        };

        let masked_result = request_ctx
            .masked(|| router.handle_tools_call(&request_ctx, params(), state.clone(), None, None))
            .expect("mask should be admitted");
        assert!(masked_result.is_ok());

        let unmasked_error = router
            .handle_tools_call(&request_ctx, params(), state, None, None)
            .expect_err("pending cancellation should surface after mask exit");
        assert_eq!(unmasked_error.code, McpErrorCode::RequestCancelled);
    }

    // ── handle_resources_read: resource disabled via session ──────────────

    #[test]
    fn handle_resources_read_disabled_resource_returns_error() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///secret"));
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["file:///secret".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_resources", &disabled);
        let params = ReadResourceParams {
            uri: "file:///secret".to_string(),
            meta: None,
        };
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_resources_read(&request_ctx, &params, state, None, None)
            .unwrap_err();
        assert!(err.message.contains("disabled"));
    }

    // ── handle_resources_read: success path ──────────────────────────────

    #[test]
    fn handle_resources_read_success() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let params = ReadResourceParams {
            uri: "file:///a".to_string(),
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let result = r
            .handle_resources_read(&request_ctx, &params, state, None, None)
            .unwrap();
        assert_eq!(result.contents.len(), 1);
        assert_eq!(result.contents[0].uri, "file:///a");
    }

    // ── handle_resources_read: not found ─────────────────────────────────

    #[test]
    fn handle_resources_read_not_found() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let params = ReadResourceParams {
            uri: "file:///nonexistent".to_string(),
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_resources_read(&request_ctx, &params, state, None, None)
            .unwrap_err();
        assert!(err.message.contains("nonexistent") || err.message.contains("not found"));
    }

    // ── handle_resources_read: zero poll balance without admission ───────

    #[test]
    fn handle_resources_read_zero_poll_balance_allows_handler_without_checkpoint() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        let cx = Cx::for_testing();
        let budget = Budget::unlimited().with_poll_quota(0);
        let params = ReadResourceParams {
            uri: "file:///a".to_string(),
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let result = r
            .handle_resources_read(&request_ctx, &params, state, None, None)
            .expect("a zero balance is not a retroactive failure");
        assert_eq!(result.contents.len(), 1);
    }

    // ── handle_prompts_get: prompt disabled via session ───────────────────

    #[test]
    fn handle_prompts_get_disabled_prompt_returns_error() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("secret_prompt"));
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["secret_prompt".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_prompts", &disabled);
        let params = GetPromptParams {
            name: "secret_prompt".to_string(),
            arguments: None,
            meta: None,
        };
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_prompts_get(&request_ctx, params, state, None, None)
            .unwrap_err();
        assert!(err.message.contains("disabled"));
    }

    // ── handle_prompts_get: success path ─────────────────────────────────

    #[test]
    fn handle_prompts_get_success() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("greet"));
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let params = GetPromptParams {
            name: "greet".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let result = r
            .handle_prompts_get(&request_ctx, params, state, None, None)
            .unwrap();
        assert!(result.description.is_some());
    }

    // ── handle_prompts_get: not found ────────────────────────────────────

    #[test]
    fn handle_prompts_get_not_found() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let params = GetPromptParams {
            name: "missing".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_prompts_get(&request_ctx, params, state, None, None)
            .unwrap_err();
        assert!(err.message.contains("missing") || err.message.contains("not found"));
    }

    // ── handle_prompts_get: zero poll balance without admission ──────────

    #[test]
    fn handle_prompts_get_zero_poll_balance_allows_handler_without_checkpoint() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        let cx = Cx::for_testing();
        let budget = Budget::unlimited().with_poll_quota(0);
        let params = GetPromptParams {
            name: "p".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let result = r
            .handle_prompts_get(&request_ctx, params, state, None, None)
            .expect("a zero balance is not a retroactive failure");
        assert!(result.messages.is_empty());
    }

    #[test]
    fn handler_budget_composition_uses_exact_earliest_deadline() {
        let now = Time::from_secs(100);
        let at = |seconds| Budget::new().with_deadline(Time::from_secs(seconds));
        let cases = [
            (Budget::INFINITE, Budget::INFINITE, None, None),
            (at(110), Budget::INFINITE, None, Some(Time::from_secs(110))),
            (Budget::INFINITE, at(115), None, Some(Time::from_secs(115))),
            (
                at(110),
                at(115),
                Some(Duration::from_secs(30)),
                Some(Time::from_secs(110)),
            ),
            (
                at(140),
                at(130),
                Some(Duration::from_secs(5)),
                Some(Time::from_secs(105)),
            ),
            (
                at(110),
                at(115),
                Some(Duration::ZERO),
                Some(Time::from_secs(110)),
            ),
            (
                at(90),
                at(115),
                Some(Duration::from_secs(5)),
                Some(Time::from_secs(90)),
            ),
            (
                Budget::INFINITE,
                Budget::new().with_deadline(Time::from_nanos(u64::MAX - 1)),
                Some(Duration::MAX),
                Some(Time::from_nanos(u64::MAX - 1)),
            ),
        ];

        for (ambient, request, handler, expected) in cases {
            assert_eq!(
                compose_handler_budget(ambient, request, handler, now).deadline,
                expected
            );
        }
    }

    #[test]
    fn alternating_tool_resource_recursion_uses_one_effective_depth() {
        let calls = Arc::new(AtomicU64::new(0));
        let mut router = Router::new();
        router.add_tool(AlternatingTool {
            calls: Arc::clone(&calls),
        });
        router.add_resource(AlternatingResource {
            calls: Arc::clone(&calls),
        });
        let router = Arc::new(router);
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = McpContext::with_state(cx, 1, state.clone())
            .with_tool_caller(Arc::new(RouterToolCaller::new(
                Arc::clone(&router),
                state.clone(),
            )))
            .with_resource_reader(Arc::new(RouterResourceReader::new(
                Arc::clone(&router),
                state.clone(),
            )));

        let error = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "alternating_tool".to_string(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect_err("alternating recursion must stop at the shared depth limit");

        assert_eq!(error.code, McpErrorCode::InternalError);
        assert!(error.message.contains("Maximum resource read depth"));
        assert_eq!(calls.load(Ordering::Relaxed), 11);
    }

    #[test]
    fn nested_tool_resource_call_shares_parent_cost_ledger() {
        let remaining_after_parent_debit = Arc::new(AtomicU64::new(u64::MAX));
        let remaining_after_nested_debit = Arc::new(AtomicU64::new(u64::MAX));
        let remaining_after_nested_read = Arc::new(AtomicU64::new(u64::MAX));
        let mut router = Router::new();
        router.add_tool(CostLedgerTool {
            remaining_after_parent_debit: Arc::clone(&remaining_after_parent_debit),
            remaining_after_nested_read: Arc::clone(&remaining_after_nested_read),
        });
        router.add_resource(CostLedgerResource {
            remaining_after_nested_debit: Arc::clone(&remaining_after_nested_debit),
        });

        let router = Arc::new(router);
        let state = SessionState::new();
        let cx = Cx::for_testing_with_budget(Budget::new().with_cost_quota(3));
        let request_ctx = McpContext::with_state(cx, 77, state.clone())
            .with_tool_caller(Arc::new(RouterToolCaller::new(
                Arc::clone(&router),
                state.clone(),
            )))
            .with_resource_reader(Arc::new(RouterResourceReader::new(router, state)));

        let result = block_on(request_ctx.call_tool("cost_ledger_tool", serde_json::json!({})))
            .expect("parent and nested debits fit the shared cost quota");

        assert!(!result.is_error);
        assert_eq!(remaining_after_parent_debit.load(Ordering::Relaxed), 2);
        assert_eq!(remaining_after_nested_debit.load(Ordering::Relaxed), 1);
        assert_eq!(remaining_after_nested_read.load(Ordering::Relaxed), 1);
        assert_eq!(request_ctx.budget().cost_quota, Some(1));
    }

    #[test]
    fn nested_tool_calls_preserve_framework_terminal_errors() {
        let mut router = Router::new();
        router.add_tool(ErrorTool {
            name: "nested_cancelled",
            code: McpErrorCode::RequestCancelled,
        });
        router.add_tool(ErrorTool {
            name: "nested_internal",
            code: McpErrorCode::InternalError,
        });
        router.add_tool(ErrorTool {
            name: "nested_tool_failure",
            code: McpErrorCode::ToolExecutionError,
        });
        let router = Arc::new(router);
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = McpContext::with_state(cx, 88, state.clone())
            .with_tool_caller(Arc::new(RouterToolCaller::new(Arc::clone(&router), state)));

        for (name, expected) in [
            ("nested_cancelled", McpErrorCode::RequestCancelled),
            ("nested_internal", McpErrorCode::InternalError),
        ] {
            let error = block_on(request_ctx.call_tool(name, serde_json::json!({})))
                .expect_err("framework terminal errors must remain outer failures");
            assert_eq!(error.code, expected);
        }

        let tool_failure =
            block_on(request_ctx.call_tool("nested_tool_failure", serde_json::json!({})))
                .expect("ordinary tool failures remain protocol-level tool results");
        assert!(tool_failure.is_error);
    }

    #[test]
    fn manual_handler_timeout_is_read_exposed_and_enforced() {
        let observed_deadline = Arc::new(Mutex::new(None));
        let timeout_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut router = Router::new();
        router.add_tool(BudgetProbeTool {
            timeout: Some(Duration::from_millis(1)),
            delay: Duration::from_millis(15),
            observed_deadline: Arc::clone(&observed_deadline),
            timeout_read: Arc::clone(&timeout_read),
        });
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let error = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "budget_probe".to_string(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect_err("the handler deadline must reject a late completion");

        assert!(timeout_read.load(Ordering::Relaxed));
        assert!(
            observed_deadline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some()
        );
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert_eq!(error.message, "Request timeout exceeded");
        assert!(!cx.is_cancel_requested());
    }

    #[test]
    fn handler_timeout_is_anchored_before_definition_and_validation_work() {
        let definition_reads = Arc::new(AtomicU64::new(0));
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut router = Router::new();
        router.add_tool(SlowDefinitionTool {
            definition_reads: Arc::clone(&definition_reads),
            called: Arc::clone(&called),
        });
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);

        let error = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "slow_definition".to_string(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect_err("pre-handler framework work must not reset the handler deadline");

        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert_eq!(error.message, "Request timeout exceeded");
        assert!(!called.load(Ordering::Relaxed));
        assert_eq!(definition_reads.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn zero_handler_timeout_cannot_relax_request_deadline() {
        let observed_deadline = Arc::new(Mutex::new(None));
        let timeout_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let request_deadline = wall_now().saturating_add_nanos(5_000_000_000);
        let mut router = Router::new();
        router.add_tool(BudgetProbeTool {
            timeout: Some(Duration::ZERO),
            delay: Duration::ZERO,
            observed_deadline: Arc::clone(&observed_deadline),
            timeout_read: Arc::clone(&timeout_read),
        });
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(
            &cx,
            1,
            Budget::new().with_deadline(request_deadline),
            &state,
        );
        router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "budget_probe".to_string(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("zero adds no ceiling but preserves the request deadline");

        assert!(timeout_read.load(Ordering::Relaxed));
        assert_eq!(
            *observed_deadline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(request_deadline)
        );
    }

    #[test]
    fn ambient_deadline_remains_visible_when_server_and_handler_are_looser() {
        let observed_deadline = Arc::new(Mutex::new(None));
        let timeout_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ambient_deadline = wall_now().saturating_add_nanos(2_000_000_000);
        let request_deadline = ambient_deadline.saturating_add_nanos(2_000_000_000);
        let mut router = Router::new();
        router.add_tool(BudgetProbeTool {
            timeout: Some(Duration::from_secs(10)),
            delay: Duration::ZERO,
            observed_deadline: Arc::clone(&observed_deadline),
            timeout_read,
        });
        let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(ambient_deadline));
        let state = SessionState::new();
        let request_ctx = request_context(
            &cx,
            1,
            Budget::new().with_deadline(request_deadline),
            &state,
        );
        router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "budget_probe".to_string(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("looser inner limits must preserve the ambient deadline");

        assert_eq!(
            *observed_deadline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(ambient_deadline)
        );
    }

    fn assert_sanitized_panic_tool(handler: impl ToolHandler + 'static, name: &str) {
        let mut router = Router::new();
        router.add_tool(handler);
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let error = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: name.to_string(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect_err("panic must terminate as a sanitized protocol error");
        let wire = serde_json::to_string(&error).expect("error serializes");
        assert_eq!(error.code, McpErrorCode::InternalError);
        assert_eq!(error.message, SANITIZED_HANDLER_PANIC_MESSAGE);
        assert_eq!(error.data, None);
        assert!(!wire.contains(PANIC_CANARY));
        assert!(!wire.contains("Bearer"));
        assert!(!wire.contains("secret"));
        assert!(!wire.contains("peer-secret"));
        assert!(!wire.contains("\u{001b}"));
        assert!(wire.len() < 256);
        assert!(!cx.is_cancel_requested());
    }

    #[test]
    fn unwinding_string_and_non_string_panics_have_one_fixed_peer_error() {
        assert_sanitized_panic_tool(
            UnwindingPanicTool {
                payload: "Bearer actual-secret".to_string(),
                non_string: false,
            },
            "panic_tool",
        );
        assert_sanitized_panic_tool(
            UnwindingPanicTool {
                payload: PANIC_CANARY.to_string(),
                non_string: true,
            },
            "panic_tool",
        );
    }

    #[test]
    fn four_valued_panic_payload_is_never_rendered_for_peer() {
        assert_sanitized_panic_tool(
            OutcomePanicTool(format!("{PANIC_CANARY}{}", "y".repeat(64 * 1024))),
            "outcome_panic_tool",
        );
    }

    #[test]
    fn opaque_internal_handler_errors_use_the_fixed_peer_contract() {
        let cx = Cx::for_testing();

        let mut tool_router = Router::new();
        tool_router.add_tool(OpaqueInternalTool);
        let tool_state = SessionState::new();
        let tool_ctx = request_context(&cx, 1, Budget::INFINITE, &tool_state);
        let tool_error = tool_router
            .handle_tools_call(
                &tool_ctx,
                CallToolParams {
                    name: "opaque_internal_tool".to_string(),
                    arguments: None,
                    meta: None,
                },
                tool_state,
                None,
                None,
            )
            .expect_err("opaque internal tool errors must remain protocol failures");

        let mut resource_router = Router::new();
        resource_router.add_resource(OpaqueInternalResource);
        let resource_state = SessionState::new();
        let resource_ctx = request_context(&cx, 2, Budget::INFINITE, &resource_state);
        let resource_error = resource_router
            .handle_resources_read(
                &resource_ctx,
                &ReadResourceParams {
                    uri: "opaque://internal".to_string(),
                    meta: None,
                },
                resource_state,
                None,
                None,
            )
            .expect_err("opaque internal resource errors must be sanitized");

        let mut prompt_router = Router::new();
        prompt_router.add_prompt(OpaqueInternalPrompt);
        let prompt_state = SessionState::new();
        let prompt_ctx = request_context(&cx, 3, Budget::INFINITE, &prompt_state);
        let prompt_error = prompt_router
            .handle_prompts_get(
                &prompt_ctx,
                GetPromptParams {
                    name: "opaque_internal_prompt".to_string(),
                    arguments: None,
                    meta: None,
                },
                prompt_state,
                None,
                None,
            )
            .expect_err("opaque internal prompt errors must be sanitized");

        for error in [tool_error, resource_error, prompt_error] {
            let wire = serde_json::to_string(&error).expect("error serializes");
            assert_eq!(error.code, McpErrorCode::InternalError);
            assert_eq!(error.message, SANITIZED_HANDLER_PANIC_MESSAGE);
            assert_eq!(error.data, None);
            assert!(!wire.contains(PANIC_CANARY));
            assert!(wire.len() < 256);
        }
    }

    #[test]
    fn resource_and_prompt_panics_use_same_sanitized_contract() {
        let mut resource_router = Router::new();
        resource_router.add_resource(PanicResource);
        let resource_cx = Cx::for_testing();
        let resource_state = SessionState::new();
        let resource_ctx = request_context(&resource_cx, 1, Budget::INFINITE, &resource_state);
        let resource_error = resource_router
            .handle_resources_read(
                &resource_ctx,
                &ReadResourceParams {
                    uri: "panic://resource".to_string(),
                    meta: None,
                },
                resource_state,
                None,
                None,
            )
            .expect_err("resource panic must be sanitized");
        assert_eq!(resource_error.message, SANITIZED_HANDLER_PANIC_MESSAGE);

        let mut prompt_router = Router::new();
        prompt_router.add_prompt(PanicPrompt);
        let prompt_cx = Cx::for_testing();
        let prompt_state = SessionState::new();
        let prompt_ctx = request_context(&prompt_cx, 1, Budget::INFINITE, &prompt_state);
        let prompt_error = prompt_router
            .handle_prompts_get(
                &prompt_ctx,
                GetPromptParams {
                    name: "panic_prompt".to_string(),
                    arguments: None,
                    meta: None,
                },
                prompt_state,
                None,
                None,
            )
            .expect_err("prompt panic must be sanitized");
        assert_eq!(prompt_error.message, SANITIZED_HANDLER_PANIC_MESSAGE);

        for error in [resource_error, prompt_error] {
            let wire = serde_json::to_string(&error).expect("error serializes");
            assert!(!wire.contains(PANIC_CANARY));
            assert!(wire.len() < 256);
        }
    }

    #[test]
    fn list_definition_panics_use_the_same_sanitized_contract() {
        let cx = Cx::for_testing();
        let request_ctx = McpContext::new(cx, 1);

        let mut tool_router = Router::new();
        tool_router.add_tool(DefinitionPanicTool(std::sync::atomic::AtomicBool::new(
            false,
        )));
        let tool_error = tool_router
            .handle_tools_list(&request_ctx, ListToolsParams::default(), None)
            .expect_err("tool definition panic must be sanitized");

        let mut resource_router = Router::new();
        resource_router.add_resource(DefinitionPanicResource(std::sync::atomic::AtomicBool::new(
            false,
        )));
        let resource_error = resource_router
            .handle_resources_list(&request_ctx, ListResourcesParams::default(), None)
            .expect_err("resource definition panic must be sanitized");

        let mut prompt_router = Router::new();
        prompt_router.add_prompt(DefinitionPanicPrompt(std::sync::atomic::AtomicBool::new(
            false,
        )));
        let prompt_error = prompt_router
            .handle_prompts_list(&request_ctx, ListPromptsParams::default(), None)
            .expect_err("prompt definition panic must be sanitized");

        for error in [tool_error, resource_error, prompt_error] {
            let wire = serde_json::to_string(&error).expect("error serializes");
            assert_eq!(error.code, McpErrorCode::InternalError);
            assert_eq!(error.message, SANITIZED_HANDLER_PANIC_MESSAGE);
            assert_eq!(error.data, None);
            assert!(!wire.contains(PANIC_CANARY));
            assert!(wire.len() < 256);
        }
    }

    // ── add_resource_with_behavior: template resource Error ───────────────

    #[test]
    fn add_resource_with_behavior_template_error_on_duplicate() {
        struct TmplResource;
        impl ResourceHandler for TmplResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "db://placeholder".to_string(),
                    name: "db".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }
            fn template(&self) -> Option<ResourceTemplate> {
                Some(ResourceTemplate {
                    uri_template: "db://{table}".to_string(),
                    name: "db".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                })
            }
            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![])
            }
        }
        let mut r = Router::new();
        r.add_resource(TmplResource);
        let err = r
            .add_resource_with_behavior(TmplResource, crate::DuplicateBehavior::Error)
            .unwrap_err();
        assert!(err.message.contains("already exists"));
    }

    // ── add_resource_with_behavior: template resource Ignore ─────────────

    #[test]
    fn add_resource_with_behavior_template_ignore_on_duplicate() {
        struct TmplResource2;
        impl ResourceHandler for TmplResource2 {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "cache://placeholder".to_string(),
                    name: "cache".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }
            fn template(&self) -> Option<ResourceTemplate> {
                Some(ResourceTemplate {
                    uri_template: "cache://{key}".to_string(),
                    name: "cache".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                })
            }
            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![])
            }
        }
        let mut r = Router::new();
        r.add_resource(TmplResource2);
        r.add_resource_with_behavior(TmplResource2, crate::DuplicateBehavior::Ignore)
            .unwrap();
        assert_eq!(r.resource_templates_count(), 1);
    }

    // ── add_resource_with_behavior: template resource Warn ───────────────

    #[test]
    fn add_resource_with_behavior_template_warn_on_duplicate() {
        struct TmplResource3;
        impl ResourceHandler for TmplResource3 {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "log://placeholder".to_string(),
                    name: "log".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }
            fn template(&self) -> Option<ResourceTemplate> {
                Some(ResourceTemplate {
                    uri_template: "log://{entry}".to_string(),
                    name: "log".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                })
            }
            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![])
            }
        }
        let mut r = Router::new();
        r.add_resource(TmplResource3);
        r.add_resource_with_behavior(TmplResource3, crate::DuplicateBehavior::Warn)
            .unwrap();
        assert_eq!(r.resource_templates_count(), 1);
    }

    // ── mount_tools warns on conflict ────────────────────────────────

    #[test]
    fn mount_tools_warns_on_tool_conflict() {
        let mut main = Router::new();
        main.add_tool(NamedTool::new("t"));
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("t"));
        let result = main.mount_tools(sub, None);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("Tool"));
    }

    // ── mount_prompts warns on conflict ──────────────────────────────────

    #[test]
    fn mount_prompts_warns_on_prompt_conflict() {
        let mut main = Router::new();
        main.add_prompt(NamedPrompt::new("p"));
        let mut sub = Router::new();
        sub.add_prompt(NamedPrompt::new("p"));
        let result = main.mount_prompts(sub, None);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("Prompt"));
    }

    // ── invalid cursor returns error ─────────────────────────────────────

    #[test]
    fn invalid_cursor_returns_error() {
        let mut r = Router::new();
        r.set_list_page_size(Some(1));
        r.add_tool(NamedTool::new("a"));
        let cx = Cx::for_testing();
        let params = ListToolsParams {
            cursor: Some("not-valid-base64!!!".to_string()),
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let err = r.handle_tools_list(&request_ctx, params, None).unwrap_err();
        assert!(err.message.contains("cursor") || err.message.contains("Invalid"));
    }

    // ── set_list_page_size zero is treated as None ───────────────────────

    #[test]
    fn set_list_page_size_zero_disables_pagination() {
        let mut r = Router::new();
        r.set_list_page_size(Some(0));
        r.add_tool(NamedTool::new("a"));
        r.add_tool(NamedTool::new("b"));
        let cx = Cx::for_testing();
        let params = ListToolsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        // With page_size = 0, all items returned (no pagination)
        assert_eq!(result.tools.len(), 2);
        assert!(result.next_cursor.is_none());
    }

    // ── strict_input_validation getter ───────────────────────────────────

    #[test]
    fn strict_input_validation_toggle() {
        let mut r = Router::new();
        assert!(!r.strict_input_validation());
        r.set_strict_input_validation(true);
        assert!(r.strict_input_validation());
        r.set_strict_input_validation(false);
        assert!(!r.strict_input_validation());
    }

    // ── cx-cancelled early return paths ──────────────────────────────────

    #[test]
    fn handle_tools_call_cancelled_cx_returns_error() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("t"));
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let budget = Budget::INFINITE;
        let params = CallToolParams {
            name: "t".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_tools_call(&request_ctx, params, state, None, None)
            .unwrap_err();
        assert_eq!(err.code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn handle_resources_read_cancelled_cx_returns_error() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a.txt"));
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let budget = Budget::INFINITE;
        let params = ReadResourceParams {
            uri: "file:///a.txt".to_string(),
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_resources_read(&request_ctx, &params, state, None, None)
            .unwrap_err();
        assert_eq!(err.code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn handle_prompts_get_cancelled_cx_returns_error() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let budget = Budget::INFINITE;
        let params = GetPromptParams {
            name: "p".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_prompts_get(&request_ctx, params, state, None, None)
            .unwrap_err();
        assert_eq!(err.code, McpErrorCode::RequestCancelled);
    }

    // ── handle_tasks with real task manager ──────────────────────────────

    #[test]
    fn handle_tasks_list_with_manager_returns_tasks() {
        use crate::tasks::TaskManager;
        let r = Router::new();
        let cx = Cx::for_testing();
        let tm = TaskManager::new_for_testing();
        tm.register_handler("analyze", |_cx, _params| async {
            Ok(serde_json::json!({}))
        });
        let _ = tm.submit(&cx, "analyze", None).unwrap();
        let _ = tm.submit(&cx, "analyze", None).unwrap();
        let shared = tm.into_shared();
        let params = ListTasksParams {
            cursor: None,
            status: None,
            limit: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r
            .handle_tasks_list(&request_ctx, params, Some(&shared))
            .unwrap();
        assert_eq!(result.tasks.len(), 2);
    }

    #[test]
    fn handle_tasks_get_with_manager_returns_task() {
        use crate::tasks::TaskManager;
        let r = Router::new();
        let cx = Cx::for_testing();
        let tm = TaskManager::new_for_testing();
        tm.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = tm.submit(&cx, "t", None).unwrap();
        let shared = tm.into_shared();
        let params = GetTaskParams { id: id.clone() };
        let request_ctx = McpContext::new(cx, 1);
        let result = r
            .handle_tasks_get(&request_ctx, params, Some(&shared))
            .unwrap();
        assert_eq!(result.task.id, id);
        assert!(result.result.is_none());
    }

    #[test]
    fn handle_tasks_get_task_not_found() {
        use crate::tasks::TaskManager;
        use fastmcp_protocol::TaskId;
        let r = Router::new();
        let cx = Cx::for_testing();
        let tm = TaskManager::new_for_testing();
        let shared = tm.into_shared();
        let params = GetTaskParams {
            id: TaskId::from_string("nonexistent".to_string()),
        };
        let request_ctx = McpContext::new(cx, 1);
        let err = r
            .handle_tasks_get(&request_ctx, params, Some(&shared))
            .unwrap_err();
        assert!(err.message.contains("not found"));
    }

    #[test]
    fn completion_handler_dispatches_exact_legacy_and_final_contracts() {
        let mut router = Router::new();
        assert!(!router.has_completion_handler());
        router.add_completion_handler(EchoCompletion);
        assert!(router.has_completion_handler());
        assert!(
            router
                .server_discovery_behavior_registry()
                .contains(ServerBehavior::CompletionComplete),
            "discovery advertises completion only after the handler is installed"
        );

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 87, Budget::INFINITE, &state);
        let legacy_request = JsonRpcRequest::new(
            COMPLETION_COMPLETE,
            Some(serde_json::json!({
                "ref": {"type": "ref/prompt", "name": "deploy"},
                "argument": {"name": "environment", "value": "sta"},
            })),
            87_i64,
        );
        let legacy = router
            .dispatch_legacy_completion(&request_ctx, &legacy_request)
            .expect("the exact legacy request reaches the registered completion handler");
        assert!(
            legacy.get("resultType").is_none(),
            "the exact legacy completion result remains discriminator-free"
        );
        assert_eq!(
            legacy["completion"]["values"],
            serde_json::json!(["staging"])
        );

        let modern = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    COMPLETION_COMPLETE,
                    Some(serde_json::json!({
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                        "ref": {"type": "ref/prompt", "name": "deploy"},
                        "argument": {"name": "environment", "value": "sta"},
                    })),
                    88_i64,
                ),
            )
            .expect("the final request reaches the same registered completion handler");
        assert_eq!(
            modern.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(modern.get("completion"), legacy.get("completion"));
    }

    #[test]
    fn completion_handler_rejects_one_field_final_metadata_in_legacy_request() {
        let mut router = Router::new();
        router.add_completion_handler(EchoCompletion);
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 89, Budget::INFINITE, &state);
        let baseline = JsonRpcRequest::new(
            COMPLETION_COMPLETE,
            Some(serde_json::json!({
                "ref": {"type": "ref/prompt", "name": "deploy"},
                "argument": {"name": "environment", "value": "sta"},
            })),
            89_i64,
        );
        let mut planted = baseline.clone();
        planted
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("completion parameters are an object")
            .insert(
                "_meta".to_string(),
                serde_json::json!({
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                }),
            );

        assert_eq!(baseline.method, planted.method);
        assert_eq!(baseline.id, planted.id);
        assert_eq!(
            baseline
                .params
                .as_ref()
                .and_then(|params| params.get("ref")),
            planted.params.as_ref().and_then(|params| params.get("ref")),
            "the final metadata object is the sole planted dimension"
        );
        let catalog_before = router.has_completion_handler();
        let planted_before = serde_json::to_vec(&planted).expect("planted request serializes");

        let baseline_result = router
            .dispatch_legacy_completion(&request_ctx, &baseline)
            .expect("the baseline legacy completion request is accepted");
        let error = router
            .dispatch_legacy_completion(&request_ctx, &planted)
            .expect_err("only final metadata is refused in the exact legacy request");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            serde_json::to_vec(&planted).expect("rejected request serializes"),
            planted_before,
            "cross-era rejection cannot mutate caller-owned completion parameters"
        );
        assert_eq!(
            router.has_completion_handler(),
            catalog_before,
            "cross-era rejection cannot alter the installed completion handler"
        );
        assert_eq!(
            router
                .dispatch_legacy_completion(&request_ctx, &baseline)
                .expect("the baseline remains accepted after the planted rejection"),
            baseline_result,
            "the one-field rejection cannot alter the accepted legacy completion result"
        );
    }

    #[test]
    fn macro_tool_dispatches_exact_legacy_and_final_complete_results() {
        let mut router = Router::new();
        MACRO_DUAL_ERA_TOOL_CALLS.store(0, Ordering::SeqCst);
        router.add_tool(MacroDualEraTool);
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 91, Budget::INFINITE, &state);

        let legacy = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "macro_dual_era_tool".to_string(),
                    arguments: Some(serde_json::json!({})),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("the legacy adapter still invokes the registered handler");
        let legacy_wire = serde_json::to_value(&legacy).expect("legacy result serializes");
        assert!(
            legacy_wire.get("resultType").is_none(),
            "the exact legacy result shape remains unchanged"
        );
        assert_eq!(legacy_wire["content"][0]["text"], "macro final tool result");

        let modern = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    "tools/call",
                    Some(serde_json::json!({
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                        "name": "macro_dual_era_tool",
                        "arguments": {},
                    })),
                    91_i64,
                ),
            )
            .expect("the modern router invokes the same installed handler");

        assert_eq!(
            modern.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(modern.get("content"), legacy_wire.get("content"));
        assert_eq!(modern.get("isError"), legacy_wire.get("isError"));
        assert!(modern.get("serverInfo").is_none());
        assert_eq!(
            modern["structuredContent"],
            serde_json::json!({"weather": "clear"})
        );
        assert_eq!(MACRO_DUAL_ERA_TOOL_CALLS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn macro_tool_final_metadata_negative_is_non_mutating() {
        let mut router = Router::new();
        MACRO_DUAL_ERA_TOOL_CALLS.store(0, Ordering::SeqCst);
        router.add_tool(MacroDualEraTool);
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 92, Budget::INFINITE, &state);
        let baseline = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "name": "macro_dual_era_tool",
                "arguments": {},
            })),
            92_i64,
        );
        let mut planted = baseline.clone();
        planted
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("tools/call parameters are an object")
            .remove("_meta");

        assert_eq!(baseline.method, planted.method);
        assert_eq!(baseline.id, planted.id);
        assert_eq!(
            baseline
                .params
                .as_ref()
                .and_then(|params| params.get("name")),
            planted
                .params
                .as_ref()
                .and_then(|params| params.get("name")),
            "the final metadata object is the sole planted dimension"
        );
        let catalog_before = serde_json::to_vec(&router.tools()).expect("catalog serializes");
        let planted_before = serde_json::to_vec(&planted).expect("request serializes");

        let baseline_result = router
            .dispatch_stateless(&request_ctx, &baseline)
            .expect("the baseline invokes the registered handler");
        assert_eq!(
            baseline_result.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(MACRO_DUAL_ERA_TOOL_CALLS.load(Ordering::SeqCst), 1);

        let error = router
            .dispatch_stateless(&request_ctx, &planted)
            .expect_err("only final metadata is refused");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            serde_json::to_vec(&planted).expect("rejected request serializes"),
            planted_before,
            "typed refusal cannot mutate caller-owned input"
        );
        assert_eq!(
            serde_json::to_vec(&router.tools()).expect("catalog serializes"),
            catalog_before,
            "typed refusal cannot mutate the installed handler catalog"
        );
        assert_eq!(
            MACRO_DUAL_ERA_TOOL_CALLS.load(Ordering::SeqCst),
            1,
            "metadata refusal cannot invoke the macro-generated tool"
        );
        assert_eq!(
            router
                .dispatch_stateless(&request_ctx, &baseline)
                .expect("the unchanged baseline remains accepted after the rejection"),
            baseline_result,
            "the one-field rejection cannot alter the accepted final result"
        );
        assert_eq!(MACRO_DUAL_ERA_TOOL_CALLS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn final_catalog_preserves_resource_template_and_prompt_fields() {
        let resource_metadata = OpenMetadata::try_from_entries([(
            "com.example/resource".to_owned(),
            serde_json::json!({"source": "resource-handler"}),
        )])
        .expect("resource metadata is valid");
        let template_metadata = OpenMetadata::try_from_entries([(
            "com.example/template".to_owned(),
            serde_json::json!({"source": "template-handler"}),
        )])
        .expect("template metadata is valid");
        let prompt_metadata = OpenMetadata::try_from_entries([(
            "com.example/prompt".to_owned(),
            serde_json::json!({"source": "prompt-handler"}),
        )])
        .expect("prompt metadata is valid");
        let resource_annotations = Annotations {
            audience: None,
            priority: Some(0.25),
            last_modified: Some("2026-08-08T00:00:00Z".to_owned()),
        };
        let template_annotations = Annotations {
            audience: None,
            priority: Some(0.75),
            last_modified: Some("2026-08-08T00:00:01Z".to_owned()),
        };
        let resource_icon = RawIcon::try_with_details(
            "https://example.test/resource.png",
            Some("image/png".to_owned()),
            Some(vec!["32x32".to_owned()]),
            None,
        )
        .expect("resource icon is valid");
        let template_icon = RawIcon::try_with_details(
            "https://example.test/template.png",
            Some("image/png".to_owned()),
            Some(vec!["48x48".to_owned()]),
            None,
        )
        .expect("template icon is valid");
        let prompt_icon = RawIcon::try_with_details(
            "https://example.test/prompt.png",
            Some("image/png".to_owned()),
            Some(vec!["64x64".to_owned()]),
            None,
        )
        .expect("prompt icon is valid");

        let mut router = Router::new();
        router.add_resource(FinalCatalogResource {
            metadata: resource_metadata,
            icons: vec![resource_icon],
            annotations: resource_annotations,
        });
        router.add_resource(FinalCatalogResourceTemplate {
            metadata: template_metadata,
            icons: vec![template_icon],
            annotations: template_annotations,
        });
        router.add_prompt(FinalCatalogPrompt {
            metadata: prompt_metadata,
            icons: vec![prompt_icon],
        });

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 96, Budget::INFINITE, &state);
        let final_metadata = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        });

        let resources = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    "resources/list",
                    Some(serde_json::json!({"_meta": final_metadata.clone()})),
                    96_i64,
                ),
            )
            .expect("final resource catalog is encoded");
        assert_eq!(resources["resources"][0]["title"], "Final Catalog Resource");
        assert_eq!(
            resources["resources"][0]["icons"][0]["src"],
            "https://example.test/resource.png"
        );
        assert_eq!(resources["resources"][0]["annotations"]["priority"], 0.25);
        assert_eq!(
            resources["resources"][0]["_meta"]["com.example/resource"]["source"],
            "resource-handler"
        );

        let templates = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    "resources/templates/list",
                    Some(serde_json::json!({"_meta": final_metadata.clone()})),
                    97_i64,
                ),
            )
            .expect("final resource-template catalog is encoded");
        assert_eq!(
            templates["resourceTemplates"][0]["title"],
            "Final Catalog Template"
        );
        assert_eq!(
            templates["resourceTemplates"][0]["icons"][0]["src"],
            "https://example.test/template.png"
        );
        assert_eq!(
            templates["resourceTemplates"][0]["annotations"]["priority"],
            0.75
        );
        assert_eq!(
            templates["resourceTemplates"][0]["_meta"]["com.example/template"]["source"],
            "template-handler"
        );

        let prompts = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    "prompts/list",
                    Some(serde_json::json!({"_meta": final_metadata})),
                    98_i64,
                ),
            )
            .expect("final prompt catalog is encoded");
        assert_eq!(prompts["prompts"][0]["title"], "Final Catalog Prompt");
        assert_eq!(
            prompts["prompts"][0]["icons"][0]["src"],
            "https://example.test/prompt.png"
        );
        assert_eq!(
            prompts["prompts"][0]["_meta"]["com.example/prompt"]["source"],
            "prompt-handler"
        );
        assert_eq!(prompts["prompts"][0]["arguments"][0]["required"], false);
    }

    #[test]
    fn final_resource_catalog_missing_metadata_is_non_mutating() {
        let metadata = OpenMetadata::try_from_entries([(
            "com.example/resource".to_owned(),
            serde_json::json!({"source": "resource-handler"}),
        )])
        .expect("resource metadata is valid");
        let icon = RawIcon::try_with_details(
            "https://example.test/resource.png",
            Some("image/png".to_owned()),
            None,
            None,
        )
        .expect("resource icon is valid");
        let mut router = Router::new();
        router.add_resource(FinalCatalogResource {
            metadata,
            icons: vec![icon],
            annotations: Annotations::default(),
        });
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 99, Budget::INFINITE, &state);
        let baseline = JsonRpcRequest::new(
            "resources/list",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            })),
            99_i64,
        );
        let mut planted = baseline.clone();
        planted
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("final resource-list parameters are an object")
            .remove("_meta");

        assert_eq!(baseline.method, planted.method);
        assert_eq!(baseline.id, planted.id);
        assert_eq!(
            baseline
                .params
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .map(serde_json::Map::len),
            Some(1),
            "the final metadata object is the sole baseline parameter"
        );
        assert_eq!(
            planted
                .params
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .map(serde_json::Map::len),
            Some(0),
            "the planted request differs only by final metadata removal"
        );
        let catalog_before = serde_json::to_vec(&router.resources()).expect("catalog serializes");
        let planted_before = serde_json::to_vec(&planted).expect("request serializes");
        let baseline_result = router
            .dispatch_stateless(&request_ctx, &baseline)
            .expect("final baseline is accepted");
        assert_eq!(
            baseline_result["resources"][0]["title"],
            "Final Catalog Resource"
        );

        let error = router
            .dispatch_stateless(&request_ctx, &planted)
            .expect_err("only final request metadata is refused");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            serde_json::to_vec(&planted).expect("rejected request serializes"),
            planted_before,
            "the one-field rejection cannot mutate caller-owned input"
        );
        assert_eq!(
            serde_json::to_vec(&router.resources()).expect("catalog serializes"),
            catalog_before,
            "the one-field rejection cannot mutate the resource catalog"
        );
        assert_eq!(
            router
                .dispatch_stateless(&request_ctx, &baseline)
                .expect("the baseline remains accepted after rejection"),
            baseline_result,
            "the one-field rejection cannot alter final field preservation"
        );
    }

    #[test]
    fn core_request_decode_result_round_trips_final_catalog_and_read_cache_hints() {
        let metadata = OpenMetadata::try_from_entries([(
            "com.example/catalog".to_owned(),
            serde_json::json!({"source": "handler"}),
        )])
        .expect("valid final catalog metadata");
        let icon = RawIcon::try_with_details(
            "https://example.test/tool.png",
            Some("image/png".to_owned()),
            Some(vec!["48x48".to_owned()]),
            None,
        )
        .expect("valid final icon");
        let mut router = Router::new();
        router.set_final_cache_hint_policy(123, 456, CacheScope::Private);
        router.add_tool(FinalCatalogTool {
            metadata,
            icons: vec![icon],
        });
        router.add_resource(NamedResource::new("file:///catalog-resource"));
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 93, Budget::INFINITE, &state);

        let legacy = router
            .handle_tools_list(&request_ctx, ListToolsParams::default(), None)
            .expect("legacy catalog remains available");
        let legacy_wire = serde_json::to_value(&legacy).expect("legacy catalog serializes");
        assert!(legacy_wire.get("ttlMs").is_none());
        assert!(legacy_wire.get("cacheScope").is_none());
        assert!(legacy_wire["tools"][0].get("icon").is_some());
        assert!(legacy_wire["tools"][0].get("version").is_some());
        assert!(legacy_wire["tools"][0].get("tags").is_some());

        let final_list_params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        });
        let final_list_request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            "tools/list",
            Some(&final_list_params),
        )
        .expect("final catalog request decodes through the public core surface");
        let modern_list = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new("tools/list", Some(final_list_params), 93_i64),
            )
            .expect("final catalog is projected through the exact model");
        assert_eq!(modern_list["resultType"], "complete");
        assert_eq!(modern_list["ttlMs"], 123);
        assert_eq!(modern_list["cacheScope"], "private");
        assert_eq!(modern_list["tools"][0]["title"], "Final Catalog Tool");
        assert_eq!(
            modern_list["tools"][0]["icons"][0]["sizes"],
            serde_json::json!(["48x48"])
        );
        assert_eq!(
            modern_list["tools"][0]["_meta"]["com.example/catalog"]["source"],
            "handler"
        );
        assert_eq!(modern_list["tools"][0]["outputSchema"]["type"], "object");
        assert!(modern_list["tools"][0].get("icon").is_none());
        assert!(modern_list["tools"][0].get("version").is_none());
        assert!(modern_list["tools"][0].get("tags").is_none());
        let modern_list_wire =
            serde_json::to_string(&modern_list).expect("final catalog response serializes");
        let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = final_list_request
            .decode_result(&modern_list_wire)
            .expect("final catalog response decodes through the public core surface")
        else {
            panic!("tools/list selects the exact final catalog result");
        };
        assert_eq!(result.payload.ttl_ms, 123);
        assert_eq!(result.payload.cache_scope, CacheScope::Private);
        let final_tool = result
            .payload
            .tools
            .first()
            .expect("final catalog contains the registered tool");
        assert_eq!(final_tool.title.as_deref(), Some("Final Catalog Tool"));
        assert_eq!(
            final_tool
                .icons
                .as_ref()
                .and_then(|icons| icons.first())
                .map(|icon| icon.src.as_str()),
            Some("https://example.test/tool.png")
        );
        assert_eq!(
            final_tool
                .meta
                .as_ref()
                .and_then(|metadata| metadata.get("com.example/catalog"))
                .and_then(|value| value.get("source"))
                .and_then(serde_json::Value::as_str),
            Some("handler")
        );
        assert_eq!(
            final_tool
                .output_schema
                .as_ref()
                .and_then(|schema| schema.get("type"))
                .and_then(serde_json::Value::as_str),
            Some("object")
        );

        let final_read_params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
            "uri": "file:///catalog-resource",
        });
        let final_read_request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            "resources/read",
            Some(&final_read_params),
        )
        .expect("final resource-read request decodes through the public core surface");
        let modern_read = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new("resources/read", Some(final_read_params), 94_i64),
            )
            .expect("final resource content is projected through the final model");
        assert_eq!(modern_read["ttlMs"], 456);
        assert_eq!(modern_read["cacheScope"], "private");
        assert_eq!(
            modern_read["contents"][0]["uri"],
            "file:///catalog-resource"
        );
        assert_eq!(modern_read["contents"][0]["text"], "content");
        let modern_read_wire =
            serde_json::to_string(&modern_read).expect("final resource-read response serializes");
        let CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. }) = final_read_request
            .decode_result(&modern_read_wire)
            .expect("final resource-read response decodes through the public core surface")
        else {
            panic!("resources/read selects the exact final read result");
        };
        assert_eq!(result.payload.ttl_ms, 456);
        assert_eq!(result.payload.cache_scope, CacheScope::Private);
        assert!(matches!(
            result.payload.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == "content"
        ));
    }

    #[test]
    fn final_catalog_missing_metadata_is_non_mutating() {
        let mut router = Router::new();
        router.add_tool(NamedTool::new("metadata-guarded-tool"));
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 95, Budget::INFINITE, &state);
        let baseline = JsonRpcRequest::new(
            "tools/list",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            })),
            95_i64,
        );
        let mut planted = baseline.clone();
        planted
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("final list parameters are an object")
            .remove("_meta");
        assert_eq!(baseline.method, planted.method);
        assert_eq!(baseline.id, planted.id);
        let catalog_before = serde_json::to_vec(&router.tools()).expect("catalog serializes");
        let planted_before = serde_json::to_vec(&planted).expect("request serializes");

        let baseline_result = router
            .dispatch_stateless(&request_ctx, &baseline)
            .expect("the final baseline is accepted");
        let error = router
            .dispatch_stateless(&request_ctx, &planted)
            .expect_err("only missing final metadata is refused");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            serde_json::to_vec(&planted).expect("rejected request serializes"),
            planted_before,
            "the rejected one-field request remains unchanged"
        );
        assert_eq!(
            serde_json::to_vec(&router.tools()).expect("catalog serializes"),
            catalog_before,
            "the rejected one-field request cannot mutate the catalog"
        );
        assert_eq!(
            router
                .dispatch_stateless(&request_ctx, &baseline)
                .expect("the unchanged final baseline remains accepted"),
            baseline_result,
            "the rejection cannot alter final cache hints or catalog projection"
        );
    }

    #[test]
    fn srv_04_modern_owned_dispatch_runs_requests_concurrently() {
        let started = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(Mutex::new(Vec::new()));
        let mut router = Router::new();
        router.add_tool(ConcurrentModernTool::new(
            Arc::clone(&started),
            Arc::clone(&completed),
        ));
        let router = Arc::new(router);
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("the test runtime is available");
        let runtime_handle = runtime.handle();
        let mut first = spawn_owned_modern_request(
            &runtime_handle,
            Arc::clone(&router),
            401,
            "modern-one",
            "one",
            None,
        );
        let mut second =
            spawn_owned_modern_request(&runtime_handle, router, 402, "modern-two", "two", None);

        let (first, second) = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs an observer context");
            let first = first
                .recv(&cx)
                .await
                .expect("the first owner reports a terminal result");
            let second = second
                .recv(&cx)
                .await
                .expect("the second owner reports a terminal result");
            (first, second)
        });
        let first = first.expect("the first modern request completes");
        let second = second.expect("the second modern request completes");

        assert_eq!(started.load(Ordering::SeqCst), 2);
        assert_eq!(
            first.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(
            second.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        let mut completed = completed
            .lock()
            .expect("completion probe lock is not poisoned")
            .clone();
        completed.sort();
        assert_eq!(completed, vec!["one".to_string(), "two".to_string()]);
    }

    #[test]
    fn srv_04_modern_owned_cancellation_does_not_change_sibling() {
        let started = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(Mutex::new(Vec::new()));
        let mut router = Router::new();
        router.add_tool(ConcurrentModernTool::new(
            Arc::clone(&started),
            Arc::clone(&completed),
        ));
        let router = Arc::new(router);
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("the test runtime is available");
        let runtime_handle = runtime.handle();
        let (cancel_control_sender, mut cancel_control) = oneshot::channel();
        let mut cancelled = spawn_owned_modern_request(
            &runtime_handle,
            Arc::clone(&router),
            403,
            "modern-cancelled",
            "cancelled",
            Some(cancel_control_sender),
        );
        let mut sibling = spawn_owned_modern_request(
            &runtime_handle,
            router,
            404,
            "modern-sibling",
            "sibling",
            None,
        );

        let (cancelled, sibling) = runtime.block_on(async {
            let observer_cx = Cx::current().expect("block_on installs an observer context");
            let cancelled_cx = cancel_control
                .recv(&observer_cx)
                .await
                .expect("the request owner exposes its cancellation context");
            while started.load(Ordering::SeqCst) < 2 {
                yield_once().await;
            }
            cancelled_cx.cancel_with(CancelKind::User, Some("test single-request cancellation"));
            let cancelled = cancelled
                .recv(&observer_cx)
                .await
                .expect("the cancelled owner reports a terminal result");
            let sibling = sibling
                .recv(&observer_cx)
                .await
                .expect("the sibling owner reports a terminal result");
            (cancelled, sibling)
        });

        let cancelled = cancelled.expect_err("only the selected request is cancelled");
        assert_eq!(cancelled.code, McpErrorCode::RequestCancelled);
        let sibling = sibling.expect("the sibling completes despite peer cancellation");
        assert_eq!(
            sibling.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(
            completed
                .lock()
                .expect("completion probe lock is not poisoned")
                .as_slice(),
            ["sibling"],
            "cancelling one request cannot add, remove, or alter sibling completion"
        );
    }

    #[test]
    fn mount_result_with_warning_and_no_error_is_successful() {
        let result = MountResult {
            tools: 0,
            resources: 0,
            resource_templates: 0,
            prompts: 0,
            warnings: vec!["something".to_string()],
            errors: vec![],
        };
        assert!(result.is_success());
        assert!(!result.has_components());
    }
}
