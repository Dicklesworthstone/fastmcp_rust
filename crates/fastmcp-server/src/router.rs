//! Request router for MCP servers.

use std::collections::HashMap;
use std::sync::Arc;

use asupersync::time::wall_now;
use asupersync::{Budget, Cx, Outcome};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fastmcp_core::logging::{debug, targets, trace};
use fastmcp_core::{
    AuthContext, McpContext, McpError, McpErrorCode, McpResult, OutcomeExt, SessionState, block_on,
};
use fastmcp_protocol::{
    CallToolParams, CallToolResult, CancelTaskParams, CancelTaskResult, Content, GetPromptParams,
    GetPromptResult, GetTaskParams, GetTaskResult, InitializeParams, InitializeResult,
    JsonRpcRequest, ListPromptsParams, ListPromptsResult, ListResourceTemplatesParams,
    ListResourceTemplatesResult, ListResourcesParams, ListResourcesResult, ListTasksParams,
    ListTasksResult, ListToolsParams, ListToolsResult, PROTOCOL_VERSION, ProgressMarker, Prompt,
    ReadResourceParams, ReadResourceResult, Resource, ResourceTemplate, SubmitTaskParams,
    SubmitTaskResult, Tool, validate, validate_strict,
};

use crate::handler::{BidirectionalSenders, UriParams, create_context_with_progress_and_senders};
use crate::tasks::SharedTaskManager;

use crate::Session;
use crate::handler::{
    BoxedPromptHandler, BoxedResourceHandler, BoxedToolHandler, PromptHandler, ResourceHandler,
    ToolHandler,
};

/// Type alias for a notification sender callback.
///
/// This callback is used to send notifications (like progress updates) back to the client
/// during request handling. The callback receives a JSON-RPC request (notification format).
pub type NotificationSender = Arc<dyn Fn(JsonRpcRequest) + Send + Sync>;

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

fn encode_cursor_offset(offset: usize) -> String {
    let payload = serde_json::json!({ "offset": offset });
    let bytes = serde_json::to_vec(&payload).expect("cursor state must serialize");
    BASE64_STANDARD.encode(bytes)
}

/// Routes MCP requests to the appropriate handlers.
pub struct Router {
    tools: HashMap<String, BoxedToolHandler>,
    tool_order: Vec<String>,
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
}

impl Router {
    /// Creates a new empty router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            tool_order: Vec::new(),
            resources: HashMap::new(),
            resource_order: Vec::new(),
            prompts: HashMap::new(),
            prompt_order: Vec::new(),
            resource_templates: HashMap::new(),
            resource_template_order: Vec::new(),
            sorted_template_keys: Vec::new(),
            strict_input_validation: false,
            list_page_size: None,
        }
    }

    /// Sets the list pagination page size.
    ///
    /// When set, list methods (`tools/list`, `resources/list`, `resources/templates/list`,
    /// `prompts/list`, `tasks/list`) will page results using opaque base64 cursors.
    pub fn set_list_page_size(&mut self, page_size: Option<usize>) {
        self.list_page_size = page_size.filter(|n| *n > 0);
    }

    pub(crate) fn tool_is_read_only(&self, name: &str) -> bool {
        self.tools
            .get(name)
            .and_then(|handler| handler.definition().annotations)
            .and_then(|annotations| annotations.read_only)
            .unwrap_or(false)
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
                    return Err(McpError::invalid_request(format!(
                        "Tool '{}' already exists",
                        name
                    )));
                }
                crate::DuplicateBehavior::Warn => {
                    log::warn!(target: "fastmcp_rust::router", "Tool '{}' already exists, keeping original", name);
                    return Ok(());
                }
                crate::DuplicateBehavior::Replace => {
                    log::debug!(target: "fastmcp_rust::router", "Replacing tool '{}'", name);
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
                    return Err(McpError::invalid_request(format!(
                        "Resource '{}' already exists",
                        key
                    )));
                }
                crate::DuplicateBehavior::Warn => {
                    log::warn!(target: "fastmcp_rust::router", "Resource '{}' already exists, keeping original", key);
                    return Ok(());
                }
                crate::DuplicateBehavior::Replace => {
                    log::debug!(target: "fastmcp_rust::router", "Replacing resource '{}'", key);
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
    pub fn add_resource_template(&mut self, template: ResourceTemplate) {
        let key = template.uri_template.clone();
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
                    return Err(McpError::invalid_request(format!(
                        "Prompt '{}' already exists",
                        name
                    )));
                }
                crate::DuplicateBehavior::Warn => {
                    log::warn!(target: "fastmcp_rust::router", "Prompt '{}' already exists, keeping original", name);
                    return Ok(());
                }
                crate::DuplicateBehavior::Replace => {
                    log::debug!(target: "fastmcp_rust::router", "Replacing prompt '{}'", name);
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
        _cx: &Cx,
        session: &mut Session,
        params: InitializeParams,
        instructions: Option<&str>,
    ) -> McpResult<InitializeResult> {
        debug!(
            target: targets::SESSION,
            "Initializing session with client: {:?}",
            params.client_info.name
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

    /// Handles the tools/list request.
    ///
    /// If session_state is provided, disabled tools will be filtered out.
    /// If include_tags/exclude_tags are provided, tools are filtered by tags.
    pub fn handle_tools_list(
        &self,
        _cx: &Cx,
        params: ListToolsParams,
        session_state: Option<&SessionState>,
    ) -> McpResult<ListToolsResult> {
        let tag_filters =
            TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let tag_filters = if params.include_tags.is_some() || params.exclude_tags.is_some() {
            Some(&tag_filters)
        } else {
            None
        };
        let tools = self.tools_filtered(session_state, tag_filters);
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

    /// Handles the tools/call request.
    ///
    /// # Arguments
    ///
    /// * `cx` - The asupersync context for cancellation and tracing
    /// * `request_id` - Internal request ID for tracking
    /// * `params` - The tool call parameters including tool name and arguments
    /// * `budget` - Request budget for timeout enforcement
    /// * `session_state` - Session state for per-session storage
    /// * `notification_sender` - Optional callback for sending progress notifications
    /// * `bidirectional_senders` - Optional senders for sampling/elicitation
    pub fn handle_tools_call(
        &self,
        cx: &Cx,
        request_id: u64,
        params: CallToolParams,
        budget: &Budget,
        session_state: SessionState,
        auth: Option<AuthContext>,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<CallToolResult> {
        debug!(target: targets::HANDLER, "Calling tool: {}", params.name);
        trace!(target: targets::HANDLER, "Tool arguments: {:?}", params.arguments);

        // Check cancellation
        if cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }

        // Check budget exhaustion
        if budget.is_exhausted() {
            return Err(McpError::new(
                McpErrorCode::RequestCancelled,
                "Request budget exhausted",
            ));
        }
        if budget.is_past_deadline(wall_now()) {
            return Err(McpError::new(
                McpErrorCode::RequestCancelled,
                "Request timeout exceeded",
            ));
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
        let tool_def = handler.definition();

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

        // Create context for the handler with progress reporting, session state, and bidirectional senders
        let mut ctx = match (progress_marker, notification_sender) {
            (Some(marker), Some(sender)) => {
                let sender = sender.clone();
                create_context_with_progress_and_senders(
                    cx.clone(),
                    request_id,
                    Some(marker),
                    Some(session_state),
                    move |req| {
                        sender(req);
                    },
                    bidirectional_senders,
                )
            }
            _ => {
                let mut ctx = McpContext::with_state(cx.clone(), request_id, session_state);
                // Attach bidirectional senders even without progress
                if let Some(senders) = bidirectional_senders {
                    if let Some(ref sampling) = senders.sampling {
                        ctx = ctx.with_sampling(sampling.clone());
                    }
                    if let Some(ref elicitation) = senders.elicitation {
                        ctx = ctx.with_elicitation(elicitation.clone());
                    }
                }
                ctx
            }
        };
        if let Some(auth) = auth {
            ctx = ctx.with_auth(auth);
        }

        // Call the handler asynchronously - returns McpOutcome (4-valued)
        let outcome = block_on(handler.call_async(&ctx, arguments));
        match outcome {
            Outcome::Ok(content) => Ok(CallToolResult {
                content,
                is_error: false,
            }),
            Outcome::Err(e) => {
                // If the request was cancelled, propagate the error as a JSON-RPC error.
                if matches!(e.code, McpErrorCode::RequestCancelled) {
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
            Outcome::Panicked(payload) => {
                // Panics become internal errors
                Err(McpError::internal_error(format!(
                    "Handler panic: {}",
                    payload.message()
                )))
            }
        }
    }

    /// Handles the resources/list request.
    ///
    /// If session_state is provided, disabled resources will be filtered out.
    /// If include_tags/exclude_tags are provided, resources are filtered by tags.
    pub fn handle_resources_list(
        &self,
        _cx: &Cx,
        params: ListResourcesParams,
        session_state: Option<&SessionState>,
    ) -> McpResult<ListResourcesResult> {
        let tag_filters =
            TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let tag_filters = if params.include_tags.is_some() || params.exclude_tags.is_some() {
            Some(&tag_filters)
        } else {
            None
        };
        let resources = self.resources_filtered(session_state, tag_filters);
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
        _cx: &Cx,
        params: ListResourceTemplatesParams,
        session_state: Option<&SessionState>,
    ) -> McpResult<ListResourceTemplatesResult> {
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
    /// * `cx` - The asupersync context for cancellation and tracing
    /// * `request_id` - Internal request ID for tracking
    /// * `params` - The resource read parameters including URI
    /// * `budget` - Request budget for timeout enforcement
    /// * `session_state` - Session state for per-session storage
    /// * `notification_sender` - Optional callback for sending progress notifications
    /// * `bidirectional_senders` - Optional senders for sampling/elicitation
    pub fn handle_resources_read(
        &self,
        cx: &Cx,
        request_id: u64,
        params: &ReadResourceParams,
        budget: &Budget,
        session_state: SessionState,
        auth: Option<AuthContext>,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<ReadResourceResult> {
        debug!(target: targets::HANDLER, "Reading resource: {}", params.uri);

        // Check cancellation
        if cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }

        // Check budget exhaustion
        if budget.is_exhausted() {
            return Err(McpError::new(
                McpErrorCode::RequestCancelled,
                "Request budget exhausted",
            ));
        }
        if budget.is_past_deadline(wall_now()) {
            return Err(McpError::new(
                McpErrorCode::RequestCancelled,
                "Request timeout exceeded",
            ));
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

        // Create context for the handler with progress reporting, session state, and bidirectional senders
        let mut ctx = match (progress_marker, notification_sender) {
            (Some(marker), Some(sender)) => {
                let sender = sender.clone();
                create_context_with_progress_and_senders(
                    cx.clone(),
                    request_id,
                    Some(marker),
                    Some(session_state),
                    move |req| {
                        sender(req);
                    },
                    bidirectional_senders,
                )
            }
            _ => {
                let mut ctx = McpContext::with_state(cx.clone(), request_id, session_state);
                // Attach bidirectional senders even without progress
                if let Some(senders) = bidirectional_senders {
                    if let Some(ref sampling) = senders.sampling {
                        ctx = ctx.with_sampling(sampling.clone());
                    }
                    if let Some(ref elicitation) = senders.elicitation {
                        ctx = ctx.with_elicitation(elicitation.clone());
                    }
                }
                ctx
            }
        };
        if let Some(auth) = auth {
            ctx = ctx.with_auth(auth);
        }

        // Read the resource asynchronously - returns McpOutcome (4-valued)
        let outcome = block_on(resolved.handler.read_async_with_uri(
            &ctx,
            &params.uri,
            &resolved.params,
        ));

        // Convert 4-valued Outcome to McpResult for JSON-RPC response
        let contents = outcome.into_mcp_result()?;

        Ok(ReadResourceResult { contents })
    }

    /// Handles the prompts/list request.
    ///
    /// If session_state is provided, disabled prompts will be filtered out.
    /// If include_tags/exclude_tags are provided, prompts are filtered by tags.
    pub fn handle_prompts_list(
        &self,
        _cx: &Cx,
        params: ListPromptsParams,
        session_state: Option<&SessionState>,
    ) -> McpResult<ListPromptsResult> {
        let tag_filters =
            TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let tag_filters = if params.include_tags.is_some() || params.exclude_tags.is_some() {
            Some(&tag_filters)
        } else {
            None
        };
        let prompts = self.prompts_filtered(session_state, tag_filters);
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
    /// * `cx` - The asupersync context for cancellation and tracing
    /// * `request_id` - Internal request ID for tracking
    /// * `params` - The prompt get parameters including name and arguments
    /// * `budget` - Request budget for timeout enforcement
    /// * `session_state` - Session state for per-session storage
    /// * `notification_sender` - Optional callback for sending progress notifications
    /// * `bidirectional_senders` - Optional senders for sampling/elicitation
    pub fn handle_prompts_get(
        &self,
        cx: &Cx,
        request_id: u64,
        params: GetPromptParams,
        budget: &Budget,
        session_state: SessionState,
        auth: Option<AuthContext>,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<GetPromptResult> {
        debug!(target: targets::HANDLER, "Getting prompt: {}", params.name);
        trace!(target: targets::HANDLER, "Prompt arguments: {:?}", params.arguments);

        // Check cancellation
        if cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }

        // Check budget exhaustion
        if budget.is_exhausted() {
            return Err(McpError::new(
                McpErrorCode::RequestCancelled,
                "Request budget exhausted",
            ));
        }
        if budget.is_past_deadline(wall_now()) {
            return Err(McpError::new(
                McpErrorCode::RequestCancelled,
                "Request timeout exceeded",
            ));
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

        // Extract progress marker from request metadata
        let progress_marker: Option<ProgressMarker> =
            params.meta.as_ref().and_then(|m| m.progress_marker.clone());

        // Create context for the handler with progress reporting, session state, and bidirectional senders
        let mut ctx = match (progress_marker, notification_sender) {
            (Some(marker), Some(sender)) => {
                let sender = sender.clone();
                create_context_with_progress_and_senders(
                    cx.clone(),
                    request_id,
                    Some(marker),
                    Some(session_state),
                    move |req| {
                        sender(req);
                    },
                    bidirectional_senders,
                )
            }
            _ => {
                let mut ctx = McpContext::with_state(cx.clone(), request_id, session_state);
                // Attach bidirectional senders even without progress
                if let Some(senders) = bidirectional_senders {
                    if let Some(ref sampling) = senders.sampling {
                        ctx = ctx.with_sampling(sampling.clone());
                    }
                    if let Some(ref elicitation) = senders.elicitation {
                        ctx = ctx.with_elicitation(elicitation.clone());
                    }
                }
                ctx
            }
        };
        if let Some(auth) = auth {
            ctx = ctx.with_auth(auth);
        }

        // Get the prompt asynchronously - returns McpOutcome (4-valued)
        let arguments = params.arguments.unwrap_or_default();
        let outcome = block_on(handler.get_async(&ctx, arguments));

        // Convert 4-valued Outcome to McpResult for JSON-RPC response
        let messages = outcome.into_mcp_result()?;

        Ok(GetPromptResult {
            description: handler.definition().description,
            messages,
        })
    }

    // ========================================================================
    // Task Dispatch Methods (Docket/SEP-1686)
    // ========================================================================

    /// Handles the tasks/list request.
    ///
    /// Lists all background tasks, optionally filtered by status.
    pub fn handle_tasks_list(
        &self,
        _cx: &Cx,
        params: ListTasksParams,
        task_manager: Option<&SharedTaskManager>,
    ) -> McpResult<ListTasksResult> {
        let task_manager = task_manager.ok_or_else(|| {
            McpError::new(
                McpErrorCode::MethodNotFound,
                "Background tasks not enabled on this server",
            )
        })?;

        debug!(target: targets::HANDLER, "Listing tasks (status filter: {:?})", params.status);

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
    pub fn handle_tasks_get(
        &self,
        _cx: &Cx,
        params: GetTaskParams,
        task_manager: Option<&SharedTaskManager>,
    ) -> McpResult<GetTaskResult> {
        let task_manager = task_manager.ok_or_else(|| {
            McpError::new(
                McpErrorCode::MethodNotFound,
                "Background tasks not enabled on this server",
            )
        })?;

        debug!(target: targets::HANDLER, "Getting task: {}", params.id);

        let task = task_manager
            .get_info(&params.id)
            .ok_or_else(|| McpError::invalid_params(format!("Task not found: {}", params.id)))?;

        let result = task_manager.get_result(&params.id);

        Ok(GetTaskResult { task, result })
    }

    /// Handles the tasks/cancel request.
    ///
    /// Requests cancellation of a running or pending task.
    pub fn handle_tasks_cancel(
        &self,
        _cx: &Cx,
        params: CancelTaskParams,
        task_manager: Option<&SharedTaskManager>,
    ) -> McpResult<CancelTaskResult> {
        let task_manager = task_manager.ok_or_else(|| {
            McpError::new(
                McpErrorCode::MethodNotFound,
                "Background tasks not enabled on this server",
            )
        })?;

        debug!(target: targets::HANDLER, "Cancelling task: {}", params.id);

        let task = task_manager.cancel(&params.id, params.reason)?;

        Ok(CancelTaskResult {
            cancelled: true,
            task,
        })
    }

    /// Handles the tasks/submit request.
    ///
    /// Submits a new background task for execution.
    pub fn handle_tasks_submit(
        &self,
        cx: &Cx,
        params: SubmitTaskParams,
        task_manager: Option<&SharedTaskManager>,
    ) -> McpResult<SubmitTaskResult> {
        let task_manager = task_manager.ok_or_else(|| {
            McpError::new(
                McpErrorCode::MethodNotFound,
                "Background tasks not enabled on this server",
            )
        })?;

        debug!(target: targets::HANDLER, "Submitting task: {}", params.task_type);

        let task_id = task_manager.submit(cx, &params.task_type, params.params)?;
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
}

impl MountResult {
    /// Returns true if any components were mounted.
    #[must_use]
    pub fn has_components(&self) -> bool {
        self.tools > 0 || self.resources > 0 || self.resource_templates > 0 || self.prompts > 0
    }

    /// Returns true if mounting was successful (currently always true).
    #[must_use]
    pub fn is_success(&self) -> bool {
        true
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
            return Err(format!("Prefix cannot contain slashes: '{}'", prefix));
        }
        // Allow alphanumeric, underscore, hyphen
        for ch in prefix.chars() {
            if !ch.is_alphanumeric() && ch != '_' && ch != '-' {
                return Err(format!(
                    "Prefix contains invalid character '{}': '{}'",
                    ch, prefix
                ));
            }
        }
        Ok(())
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
        let mut result = MountResult::default();

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

        // Validate prefix
        if let Some(p) = prefix {
            if let Err(e) = Self::validate_prefix(p) {
                result.warnings.push(e);
                // Continue anyway, but log the warning
            }
        }

        // Mount tools
        let tool_result = self.mount_tools_from(tools, tool_order, prefix);
        result.tools = tool_result.tools;
        result.warnings.extend(tool_result.warnings);

        // Mount resources
        let resource_result = self.mount_resources_from(resources, resource_order, prefix);
        result.resources = resource_result.resources;
        result.warnings.extend(resource_result.warnings);

        // Mount resource templates
        let template_result =
            self.mount_resource_templates_from(resource_templates, resource_template_order, prefix);
        result.resource_templates = template_result.resource_templates;
        result.warnings.extend(template_result.warnings);

        // Mount prompts
        let prompt_result = self.mount_prompts_from(prompts, prompt_order, prefix);
        result.prompts = prompt_result.prompts;
        result.warnings.extend(prompt_result.warnings);

        // Log mount result
        if result.has_components() {
            debug!(
                target: targets::HANDLER,
                "Mounted {} tools, {} resources, {} templates, {} prompts (prefix: {:?})",
                result.tools,
                result.resources,
                result.resource_templates,
                result.prompts,
                prefix
            );
        }

        result
    }

    /// Mounts only tools from a router.
    pub fn mount_tools(&mut self, other: Router, prefix: Option<&str>) -> MountResult {
        self.mount_tools_from(other.tools, other.tool_order, prefix)
    }

    /// Internal: mount tools from a HashMap.
    fn mount_tools_from(
        &mut self,
        mut tools: HashMap<String, BoxedToolHandler>,
        tool_order: Vec<String>,
        prefix: Option<&str>,
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
                "Mounting tool '{}' as '{}'",
                name,
                mounted_name
            );

            // Check for conflicts
            let existed = self.tools.contains_key(&mounted_name);
            if existed {
                result.warnings.push(format!(
                    "Tool '{}' already exists, will be overwritten",
                    mounted_name
                ));
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
                if existed {
                    result.warnings.push(format!(
                        "Tool '{}' already exists, will be overwritten",
                        mounted_name
                    ));
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
        let mut result = self.mount_resources_from(other.resources, other.resource_order, prefix);
        let template_result = self.mount_resource_templates_from(
            other.resource_templates,
            other.resource_template_order,
            prefix,
        );
        result.resource_templates = template_result.resource_templates;
        result.warnings.extend(template_result.warnings);
        result
    }

    /// Internal: mount resources from a HashMap.
    fn mount_resources_from(
        &mut self,
        mut resources: HashMap<String, BoxedResourceHandler>,
        resource_order: Vec<String>,
        prefix: Option<&str>,
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
                "Mounting resource '{}' as '{}'",
                uri,
                mounted_uri
            );

            // Check for conflicts
            let existed = self.resources.contains_key(&mounted_uri);
            if existed {
                result.warnings.push(format!(
                    "Resource '{}' already exists, will be overwritten",
                    mounted_uri
                ));
            }

            // Wrap with mounted URI and insert
            let mounted = MountedResourceHandler::new(handler, mounted_uri.clone());
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
                if existed {
                    result.warnings.push(format!(
                        "Resource '{}' already exists, will be overwritten",
                        mounted_uri
                    ));
                }

                let mounted = MountedResourceHandler::new(handler, mounted_uri.clone());
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
                "Mounting resource template '{}' as '{}'",
                uri_template,
                mounted_uri_template
            );

            // Check for conflicts
            let existed = self.resource_templates.contains_key(&mounted_uri_template);
            if existed {
                result.warnings.push(format!(
                    "Resource template '{}' already exists, will be overwritten",
                    mounted_uri_template
                ));
            }

            // Create new template with mounted URI
            let mut mounted_template = entry.template.clone();
            mounted_template.uri_template = mounted_uri_template.clone();

            // Wrap handler if present
            let mounted_handler = entry.handler.map(|h| {
                let wrapped: BoxedResourceHandler =
                    Box::new(MountedResourceHandler::with_template(
                        h,
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
                if existed {
                    result.warnings.push(format!(
                        "Resource template '{}' already exists, will be overwritten",
                        mounted_uri_template
                    ));
                }

                let mut mounted_template = entry.template.clone();
                mounted_template.uri_template = mounted_uri_template.clone();

                let mounted_handler = entry.handler.map(|h| {
                    let wrapped: BoxedResourceHandler =
                        Box::new(MountedResourceHandler::with_template(
                            h,
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
        self.mount_prompts_from(other.prompts, other.prompt_order, prefix)
    }

    /// Internal: mount prompts from a HashMap.
    fn mount_prompts_from(
        &mut self,
        mut prompts: HashMap<String, BoxedPromptHandler>,
        prompt_order: Vec<String>,
        prefix: Option<&str>,
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
                "Mounting prompt '{}' as '{}'",
                name,
                mounted_name
            );

            // Check for conflicts
            let existed = self.prompts.contains_key(&mounted_name);
            if existed {
                result.warnings.push(format!(
                    "Prompt '{}' already exists, will be overwritten",
                    mounted_name
                ));
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
                if existed {
                    result.warnings.push(format!(
                        "Prompt '{}' already exists, will be overwritten",
                        mounted_name
                    ));
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
    DuplicateParam(String),
}

#[derive(Debug, Clone)]
enum UriSegment {
    Literal(String),
    Param(String),
}

impl UriTemplate {
    /// Creates a new URI template from a pattern.
    ///
    /// If the pattern is invalid, logs a warning and returns a template
    /// that will never match any URI (fail-safe behavior).
    fn new(pattern: &str) -> Self {
        Self::try_new(pattern).unwrap_or_else(|err| {
            fastmcp_core::logging::warn!(
                target: targets::HANDLER,
                "Invalid URI template '{}': {:?}, using non-matching fallback",
                pattern,
                err
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
                    }

                    let mut name = String::new();
                    let mut closed = false;
                    for next in chars.by_ref() {
                        if next == '}' {
                            closed = true;
                            break;
                        }
                        name.push(next);
                    }

                    if !closed {
                        return Err(UriTemplateError::UnclosedParam);
                    }

                    if name.is_empty() {
                        return Err(UriTemplateError::EmptyParam);
                    }
                    if !seen.insert(name.clone()) {
                        return Err(UriTemplateError::DuplicateParam(name));
                    }
                    segments.push(UriSegment::Param(name));
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
        let mut params = UriParams::new();
        let mut remainder = uri;
        let mut iter = self.segments.iter().peekable();

        while let Some(segment) = iter.next() {
            match segment {
                UriSegment::Literal(lit) => {
                    remainder = remainder.strip_prefix(lit)?;
                }
                UriSegment::Param(name) => {
                    let next_literal = iter.peek().and_then(|next| match next {
                        UriSegment::Literal(lit) => Some(lit.as_str()),
                        UriSegment::Param(_) => None,
                    });

                    if next_literal.is_none() && iter.peek().is_some() {
                        return None;
                    }

                    if let Some(literal) = next_literal {
                        let idx = remainder.find(literal)?;
                        let value = &remainder[..idx];
                        if value.is_empty() {
                            return None;
                        }
                        let value = percent_decode(value)?;
                        params.insert(name.clone(), value);
                        remainder = &remainder[idx..];
                    } else {
                        // Last param: only allow "/" when this is the sole param.
                        // Multi-param templates should not let the tail param
                        // consume extra path segments.
                        if remainder.is_empty() {
                            return None;
                        }

                        let allow_slash_in_last_param = self
                            .segments
                            .iter()
                            .filter(|seg| matches!(seg, UriSegment::Param(_)))
                            .count()
                            == 1;

                        let end_idx = if allow_slash_in_last_param {
                            remainder.len()
                        } else {
                            remainder.find('/').unwrap_or(remainder.len())
                        };

                        let value = &remainder[..end_idx];
                        if value.is_empty() {
                            return None;
                        }
                        let value = percent_decode(value)?;
                        params.insert(name.clone(), value);
                        remainder = &remainder[end_idx..];
                    }
                }
            }
        }

        if remainder.is_empty() {
            Some(params)
        } else {
            None
        }
    }
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
pub struct RouterResourceReader {
    /// The shared router.
    router: Arc<Router>,
    /// Session state for handlers.
    session_state: SessionState,
}

impl RouterResourceReader {
    /// Creates a new resource reader with the given router and session state.
    #[must_use]
    pub fn new(router: Arc<Router>, session_state: SessionState) -> Self {
        Self {
            router,
            session_state,
        }
    }
}

impl ResourceReader for RouterResourceReader {
    fn read_resource(
        &self,
        cx: &Cx,
        uri: &str,
        auth: Option<AuthContext>,
        depth: u32,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = fastmcp_core::McpResult<ResourceReadResult>>
                + Send
                + '_,
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
        let cx = cx.clone();
        let uri = uri.to_string();
        let router = self.router.clone();
        let session_state = self.session_state.clone();

        Box::pin(async move {
            debug!(target: targets::HANDLER, "Cross-component resource read: {} (depth: {})", uri, depth);

            // Resolve the resource
            let resolved = router.resolve_resource(&uri).ok_or_else(|| {
                McpError::new(
                    McpErrorCode::ResourceNotFound,
                    format!("Resource not found: {}", uri),
                )
            })?;

            // Create a child context with incremented depth
            // Clone router again for the nested reader (the original is borrowed by resolved)
            let nested_router = router.clone();
            let nested_state = session_state.clone();
            let mut child_ctx = McpContext::with_state(cx.clone(), 0, session_state)
                .with_resource_read_depth(depth)
                .with_tool_caller(Arc::new(RouterToolCaller::new(
                    nested_router.clone(),
                    nested_state.clone(),
                )))
                .with_resource_reader(Arc::new(RouterResourceReader::new(
                    nested_router,
                    nested_state,
                )));
            if let Some(auth) = auth {
                child_ctx = child_ctx.with_auth(auth);
            }

            // Read the resource
            let outcome = block_on(resolved.handler.read_async_with_uri(
                &child_ctx,
                &uri,
                &resolved.params,
            ));

            // Convert outcome to result
            let contents = outcome.into_mcp_result()?;

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
pub struct RouterToolCaller {
    /// The shared router.
    router: Arc<Router>,
    /// Session state for handlers.
    session_state: SessionState,
}

impl RouterToolCaller {
    /// Creates a new tool caller with the given router and session state.
    #[must_use]
    pub fn new(router: Arc<Router>, session_state: SessionState) -> Self {
        Self {
            router,
            session_state,
        }
    }
}

impl ToolCaller for RouterToolCaller {
    fn call_tool(
        &self,
        cx: &Cx,
        name: &str,
        args: serde_json::Value,
        auth: Option<AuthContext>,
        depth: u32,
    ) -> Pin<
        Box<dyn std::future::Future<Output = fastmcp_core::McpResult<ToolCallResult>> + Send + '_>,
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
        let cx = cx.clone();
        let name = name.to_string();
        let router = self.router.clone();
        let session_state = self.session_state.clone();

        Box::pin(async move {
            debug!(target: targets::HANDLER, "Cross-component tool call: {} (depth: {})", name, depth);

            // Find the tool handler
            let handler = router
                .tools
                .get(&name)
                .ok_or_else(|| McpError::method_not_found(&format!("tool: {}", name)))?;

            // Validate arguments against the tool's input schema
            let tool_def = handler.definition();

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

            // Create a child context with incremented depth
            // Clone router again for nested calls
            let nested_router = router.clone();
            let nested_state = session_state.clone();
            let mut child_ctx = McpContext::with_state(cx.clone(), 0, session_state)
                .with_tool_call_depth(depth)
                .with_tool_caller(Arc::new(RouterToolCaller::new(
                    nested_router.clone(),
                    nested_state.clone(),
                )))
                .with_resource_reader(Arc::new(RouterResourceReader::new(
                    nested_router,
                    nested_state,
                )));
            if let Some(auth) = auth {
                child_ctx = child_ctx.with_auth(auth);
            }

            // Call the tool
            let outcome = block_on(handler.call_async(&child_ctx, args));

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
                    // Tool errors become error results, not failures
                    Ok(ToolCallResult::error(e.message))
                }
                Outcome::Cancelled(_) => Err(McpError::request_cancelled()),
                Outcome::Panicked(payload) => Err(McpError::internal_error(format!(
                    "Handler panic: {}",
                    payload.message()
                ))),
            }
        })
    }
}

#[cfg(test)]
mod uri_template_tests {
    use super::{UriTemplate, UriTemplateError};

    #[test]
    fn uri_template_matches_simple_param() {
        let matcher = UriTemplate::new("file://{path}");
        let params = matcher.matches("file://foo").expect("match");
        assert_eq!(params.get("path").map(String::as_str), Some("foo"));
    }

    #[test]
    fn uri_template_allows_slash_in_trailing_param() {
        let matcher = UriTemplate::new("file://{path}");
        let params = matcher.matches("file://foo/bar").expect("match");
        assert_eq!(params.get("path").map(String::as_str), Some("foo/bar"));
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
    fn uri_template_rejects_unclosed_param() {
        let err = UriTemplate::parse("file://{path").unwrap_err();
        assert_eq!(err, UriTemplateError::UnclosedParam);
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
    use crate::handler::{PromptHandler, ResourceHandler, ToolHandler};
    use fastmcp_core::{McpContext, McpResult, SessionState};
    use fastmcp_protocol::{Content, Prompt, PromptMessage, Resource, ResourceContent, Tool};

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
    fn mount_warns_on_invalid_prefix() {
        let mut main = Router::new();
        let sub = Router::new();
        let result = main.mount(sub, Some("bad/prefix"));
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("slashes"));
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
        let result = r.handle_tools_list(&cx, params, None).unwrap();
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

        // First page
        let params = ListToolsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r.handle_tools_list(&cx, params, None).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "a");
        assert!(result.next_cursor.is_some());

        // Second page
        let params = ListToolsParams {
            cursor: result.next_cursor,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r.handle_tools_list(&cx, params, None).unwrap();
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
        let result = r.handle_tools_list(&cx, params, None).unwrap();
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
        let result = r.handle_resources_list(&cx, params, None).unwrap();
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
        let result = r.handle_resources_list(&cx, params, None).unwrap();
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
        let result = r.handle_prompts_list(&cx, params, None).unwrap();
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
        let result = r.handle_resource_templates_list(&cx, params, None).unwrap();
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
        let result = r
            .handle_initialize(&cx, &mut session, params, Some("test instructions"))
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
        let result = r
            .handle_initialize(&cx, &mut session, params, None)
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
        let err = r.handle_tasks_list(&cx, params, None).unwrap_err();
        assert!(err.message.contains("not enabled"));
    }

    #[test]
    fn handle_tasks_get_no_manager_errors() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let params = GetTaskParams {
            id: fastmcp_protocol::TaskId("test-id".to_string()),
        };
        let err = r.handle_tasks_get(&cx, params, None).unwrap_err();
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
        let err = r.handle_tasks_cancel(&cx, params, None).unwrap_err();
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
        let err = r.handle_tasks_submit(&cx, params, None).unwrap_err();
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
        let result = r.handle_tools_list(&cx, params, Some(&state)).unwrap();
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
        let result = r.handle_resources_list(&cx, params, None).unwrap();
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
        let result = r.handle_prompts_list(&cx, params, None).unwrap();
        assert_eq!(result.prompts.len(), 1);
        assert_eq!(result.prompts[0].name, "a");
        assert!(result.next_cursor.is_some());

        let params = ListPromptsParams {
            cursor: result.next_cursor,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r.handle_prompts_list(&cx, params, None).unwrap();
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
        let result = r.handle_prompts_list(&cx, params, None).unwrap();
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
        let params = ListResourceTemplatesParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r.handle_resource_templates_list(&cx, params, None).unwrap();
        assert_eq!(result.resource_templates.len(), 1);
        assert!(result.next_cursor.is_some());

        let params = ListResourceTemplatesParams {
            cursor: result.next_cursor,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r.handle_resource_templates_list(&cx, params, None).unwrap();
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
        let result = r.handle_resource_templates_list(&cx, params, None).unwrap();
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
        assert!(r.is_success()); // always true
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

        // Only "db" tagged tools, page 1
        let params = ListToolsParams {
            cursor: None,
            include_tags: Some(vec!["db".to_string()]),
            exclude_tags: None,
        };
        let result = r.handle_tools_list(&cx, params, None).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "a");
        assert!(result.next_cursor.is_some());

        // Page 2
        let params = ListToolsParams {
            cursor: result.next_cursor,
            include_tags: Some(vec!["db".to_string()]),
            exclude_tags: None,
        };
        let result = r.handle_tools_list(&cx, params, None).unwrap();
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
        let result = r.handle_resources_list(&cx, params, Some(&state)).unwrap();
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
        let result = r.handle_prompts_list(&cx, params, Some(&state)).unwrap();
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
        let err = r
            .handle_tools_call(&cx, 1, params, &budget, state, None, None, None)
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
        let result = r
            .handle_tools_call(
                &cx,
                1,
                params,
                &budget,
                SessionState::new(),
                None,
                None,
                None,
            )
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
        let err = r
            .handle_tools_call(
                &cx,
                1,
                params,
                &budget,
                SessionState::new(),
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(err.message.contains("missing"));
    }

    // ── handle_tools_call: budget exhausted ──────────────────────────────

    #[test]
    fn handle_tools_call_budget_exhausted() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("t"));
        let cx = Cx::for_testing();
        let budget = Budget::unlimited().with_poll_quota(0);
        let params = CallToolParams {
            name: "t".to_string(),
            arguments: None,
            meta: None,
        };
        let err = r
            .handle_tools_call(
                &cx,
                1,
                params,
                &budget,
                SessionState::new(),
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(
            err.message.contains("budget") || err.message.contains("exhausted"),
            "unexpected error: {}",
            err.message
        );
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
        let err = r
            .handle_resources_read(&cx, 1, &params, &budget, state, None, None, None)
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
        let result = r
            .handle_resources_read(
                &cx,
                1,
                &params,
                &budget,
                SessionState::new(),
                None,
                None,
                None,
            )
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
        let err = r
            .handle_resources_read(
                &cx,
                1,
                &params,
                &budget,
                SessionState::new(),
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(err.message.contains("nonexistent") || err.message.contains("not found"));
    }

    // ── handle_resources_read: budget exhausted ──────────────────────────

    #[test]
    fn handle_resources_read_budget_exhausted() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        let cx = Cx::for_testing();
        let budget = Budget::unlimited().with_poll_quota(0);
        let params = ReadResourceParams {
            uri: "file:///a".to_string(),
            meta: None,
        };
        let err = r
            .handle_resources_read(
                &cx,
                1,
                &params,
                &budget,
                SessionState::new(),
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(
            err.message.contains("budget") || err.message.contains("exhausted"),
            "unexpected error: {}",
            err.message
        );
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
        let err = r
            .handle_prompts_get(&cx, 1, params, &budget, state, None, None, None)
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
        let result = r
            .handle_prompts_get(
                &cx,
                1,
                params,
                &budget,
                SessionState::new(),
                None,
                None,
                None,
            )
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
        let err = r
            .handle_prompts_get(
                &cx,
                1,
                params,
                &budget,
                SessionState::new(),
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(err.message.contains("missing") || err.message.contains("not found"));
    }

    // ── handle_prompts_get: budget exhausted ─────────────────────────────

    #[test]
    fn handle_prompts_get_budget_exhausted() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        let cx = Cx::for_testing();
        let budget = Budget::unlimited().with_poll_quota(0);
        let params = GetPromptParams {
            name: "p".to_string(),
            arguments: None,
            meta: None,
        };
        let err = r
            .handle_prompts_get(
                &cx,
                1,
                params,
                &budget,
                SessionState::new(),
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(
            err.message.contains("budget") || err.message.contains("exhausted"),
            "unexpected error: {}",
            err.message
        );
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
        let err = r.handle_tools_list(&cx, params, None).unwrap_err();
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
        let result = r.handle_tools_list(&cx, params, None).unwrap();
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
        let err = r
            .handle_tools_call(
                &cx,
                1,
                params,
                &budget,
                SessionState::new(),
                None,
                None,
                None,
            )
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
        let err = r
            .handle_resources_read(
                &cx,
                1,
                &params,
                &budget,
                SessionState::new(),
                None,
                None,
                None,
            )
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
        let err = r
            .handle_prompts_get(
                &cx,
                1,
                params,
                &budget,
                SessionState::new(),
                None,
                None,
                None,
            )
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
        let result = r.handle_tasks_list(&cx, params, Some(&shared)).unwrap();
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
        let result = r.handle_tasks_get(&cx, params, Some(&shared)).unwrap();
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
        let err = r.handle_tasks_get(&cx, params, Some(&shared)).unwrap_err();
        assert!(err.message.contains("not found"));
    }

    #[test]
    fn mount_result_is_success_always_true() {
        let result = MountResult {
            tools: 0,
            resources: 0,
            resource_templates: 0,
            prompts: 0,
            warnings: vec!["something".to_string()],
        };
        assert!(result.is_success());
        assert!(!result.has_components());
    }
}
