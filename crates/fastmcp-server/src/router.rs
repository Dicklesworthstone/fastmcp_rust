//! Request router for MCP servers.

use std::collections::HashMap;
use std::sync::Arc;

use asupersync::{Budget, Cx, Outcome};
use fastmcp_core::logging::{debug, targets, trace};
use fastmcp_core::{
    McpContext, McpError, McpErrorCode, McpResult, OutcomeExt, SessionState, block_on,
};
use fastmcp_protocol::{
    CallToolParams, CallToolResult, CancelTaskParams, CancelTaskResult, Content, GetPromptParams,
    GetPromptResult, GetTaskParams, GetTaskResult, InitializeParams, InitializeResult,
    JsonRpcRequest, ListPromptsParams, ListPromptsResult, ListResourceTemplatesParams,
    ListResourceTemplatesResult, ListResourcesParams, ListResourcesResult, ListTasksParams,
    ListTasksResult, ListToolsParams, ListToolsResult, PROTOCOL_VERSION, ProgressToken, Prompt,
    ReadResourceParams, ReadResourceResult, Resource, ResourceTemplate, SubmitTaskParams,
    SubmitTaskResult, Tool, validate,
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

/// Routes MCP requests to the appropriate handlers.
pub struct Router {
    tools: HashMap<String, BoxedToolHandler>,
    resources: HashMap<String, BoxedResourceHandler>,
    prompts: HashMap<String, BoxedPromptHandler>,
    resource_templates: HashMap<String, ResourceTemplateEntry>,
}

impl Router {
    /// Creates a new empty router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            resources: HashMap::new(),
            prompts: HashMap::new(),
            resource_templates: HashMap::new(),
        }
    }

    /// Adds a tool handler.
    pub fn add_tool<H: ToolHandler + 'static>(&mut self, handler: H) {
        let def = handler.definition();
        self.tools.insert(def.name.clone(), Box::new(handler));
    }

    /// Adds a resource handler.
    pub fn add_resource<H: ResourceHandler + 'static>(&mut self, handler: H) {
        let template = handler.template();
        let def = handler.definition();
        let boxed: BoxedResourceHandler = Box::new(handler);

        if let Some(template) = template {
            let entry = ResourceTemplateEntry {
                matcher: UriTemplate::new(&template.uri_template),
                template: template.clone(),
                handler: Some(boxed),
            };
            self.resource_templates
                .insert(template.uri_template.clone(), entry);
        } else {
            self.resources.insert(def.uri.clone(), boxed);
        }
    }

    /// Adds a resource template definition.
    pub fn add_resource_template(&mut self, template: ResourceTemplate) {
        let matcher = UriTemplate::new(&template.uri_template);
        let entry = ResourceTemplateEntry {
            matcher,
            template: template.clone(),
            handler: None,
        };
        match self.resource_templates.get_mut(&template.uri_template) {
            Some(existing) => {
                existing.template = template;
                existing.matcher = entry.matcher;
            }
            None => {
                self.resource_templates
                    .insert(template.uri_template.clone(), entry);
            }
        }
    }

    /// Adds a prompt handler.
    pub fn add_prompt<H: PromptHandler + 'static>(&mut self, handler: H) {
        let def = handler.definition();
        self.prompts.insert(def.name.clone(), Box::new(handler));
    }

    /// Returns all tool definitions.
    #[must_use]
    pub fn tools(&self) -> Vec<Tool> {
        self.tools.values().map(|h| h.definition()).collect()
    }

    /// Returns all resource definitions.
    #[must_use]
    pub fn resources(&self) -> Vec<Resource> {
        self.resources.values().map(|h| h.definition()).collect()
    }

    /// Returns all resource templates.
    #[must_use]
    pub fn resource_templates(&self) -> Vec<ResourceTemplate> {
        let mut templates: Vec<ResourceTemplate> = self
            .resource_templates
            .values()
            .map(|entry| entry.template.clone())
            .collect();
        templates.sort_by(|a, b| a.uri_template.cmp(&b.uri_template));
        templates
    }

    /// Returns all prompt definitions.
    #[must_use]
    pub fn prompts(&self) -> Vec<Prompt> {
        self.prompts.values().map(|h| h.definition()).collect()
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

        let mut candidates: Vec<&ResourceTemplateEntry> =
            self.resource_templates.values().collect();
        candidates.sort_by(|a, b| {
            let (a_literals, a_literal_segments, a_segments) = a.matcher.specificity();
            let (b_literals, b_literal_segments, b_segments) = b.matcher.specificity();
            b_literals
                .cmp(&a_literals)
                .then(b_literal_segments.cmp(&a_literal_segments))
                .then(b_segments.cmp(&a_segments))
                .then_with(|| a.template.uri_template.cmp(&b.template.uri_template))
        });

        for entry in candidates {
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
    pub fn handle_tools_list(
        &self,
        _cx: &Cx,
        _params: ListToolsParams,
    ) -> McpResult<ListToolsResult> {
        Ok(ListToolsResult {
            tools: self.tools(),
            next_cursor: None,
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

        // Find the tool handler
        let handler = self
            .tools
            .get(&params.name)
            .ok_or_else(|| McpError::method_not_found(&format!("tool: {}", params.name)))?;

        // Validate arguments against the tool's input schema
        // Default to empty object since MCP tool arguments are always objects
        let arguments = params.arguments.unwrap_or_else(|| serde_json::json!({}));
        let tool_def = handler.definition();
        if let Err(validation_errors) = validate(&tool_def.input_schema, &arguments) {
            let error_messages: Vec<String> = validation_errors
                .iter()
                .map(|e| format!("{}: {}", e.path, e.message))
                .collect();
            return Err(McpError::invalid_params(format!(
                "Input validation failed: {}",
                error_messages.join("; ")
            )));
        }

        // Extract progress token from request metadata
        let progress_token: Option<ProgressToken> =
            params.meta.as_ref().and_then(|m| m.progress_token.clone());

        // Create context for the handler with progress reporting, session state, and bidirectional senders
        let ctx = match (progress_token, notification_sender) {
            (Some(token), Some(sender)) => {
                let sender = sender.clone();
                create_context_with_progress_and_senders(
                    cx.clone(),
                    request_id,
                    Some(token),
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
    pub fn handle_resources_list(
        &self,
        _cx: &Cx,
        _params: ListResourcesParams,
    ) -> McpResult<ListResourcesResult> {
        Ok(ListResourcesResult {
            resources: self.resources(),
            next_cursor: None,
        })
    }

    /// Handles the resources/templates/list request.
    pub fn handle_resource_templates_list(
        &self,
        _cx: &Cx,
        _params: ListResourceTemplatesParams,
    ) -> McpResult<ListResourceTemplatesResult> {
        Ok(ListResourceTemplatesResult {
            resource_templates: self.resource_templates(),
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

        let resolved = self
            .resolve_resource(&params.uri)
            .ok_or_else(|| McpError::resource_not_found(&params.uri))?;

        // Extract progress token from request metadata
        let progress_token: Option<ProgressToken> =
            params.meta.as_ref().and_then(|m| m.progress_token.clone());

        // Create context for the handler with progress reporting, session state, and bidirectional senders
        let ctx = match (progress_token, notification_sender) {
            (Some(token), Some(sender)) => {
                let sender = sender.clone();
                create_context_with_progress_and_senders(
                    cx.clone(),
                    request_id,
                    Some(token),
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
    pub fn handle_prompts_list(
        &self,
        _cx: &Cx,
        _params: ListPromptsParams,
    ) -> McpResult<ListPromptsResult> {
        Ok(ListPromptsResult {
            prompts: self.prompts(),
            next_cursor: None,
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

        // Find the prompt handler
        let handler = self.prompts.get(&params.name).ok_or_else(|| {
            McpError::new(
                fastmcp_core::McpErrorCode::PromptNotFound,
                format!("Prompt not found: {}", params.name),
            )
        })?;

        // Extract progress token from request metadata
        let progress_token: Option<ProgressToken> =
            params.meta.as_ref().and_then(|m| m.progress_token.clone());

        // Create context for the handler with progress reporting, session state, and bidirectional senders
        let ctx = match (progress_token, notification_sender) {
            (Some(token), Some(sender)) => {
                let sender = sender.clone();
                create_context_with_progress_and_senders(
                    cx.clone(),
                    request_id,
                    Some(token),
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

        let tasks = task_manager.list_tasks(params.status);
        Ok(ListTasksResult {
            tasks,
            next_cursor: None, // Pagination not yet implemented
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

struct ResolvedResource<'a> {
    handler: &'a BoxedResourceHandler,
    params: UriParams,
}

struct ResourceTemplateEntry {
    matcher: UriTemplate,
    template: ResourceTemplate,
    handler: Option<BoxedResourceHandler>,
}

#[derive(Debug, Clone)]
struct UriTemplate {
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
}
