//! Request router for MCP servers.

use std::collections::HashMap;
use std::sync::Arc;

use asupersync::{Budget, Cx, Outcome};
use fastmcp_core::logging::{debug, targets, trace};
use fastmcp_core::{McpContext, McpError, McpErrorCode, McpResult, OutcomeExt, block_on};
use fastmcp_protocol::{
    CallToolParams, CallToolResult, Content, GetPromptParams, GetPromptResult, InitializeParams,
    InitializeResult, JsonRpcRequest, ListPromptsParams, ListPromptsResult,
    ListResourceTemplatesParams, ListResourceTemplatesResult, ListResourcesParams,
    ListResourcesResult, ListToolsParams, ListToolsResult, PROTOCOL_VERSION, ProgressToken, Prompt,
    ReadResourceParams, ReadResourceResult, Resource, ResourceTemplate, Tool, validate,
};

use crate::handler::create_context_with_progress;

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
    resource_templates: HashMap<String, ResourceTemplate>,
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
        let def = handler.definition();
        self.resources.insert(def.uri.clone(), Box::new(handler));
    }

    /// Adds a resource template definition.
    pub fn add_resource_template(&mut self, template: ResourceTemplate) {
        self.resource_templates
            .insert(template.uri_template.clone(), template);
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
        self.resource_templates.values().cloned().collect()
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
        self.resource_templates.get(uri_template)
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
    /// * `notification_sender` - Optional callback for sending progress notifications
    pub fn handle_tools_call(
        &self,
        cx: &Cx,
        request_id: u64,
        params: CallToolParams,
        budget: &Budget,
        notification_sender: Option<&NotificationSender>,
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

        // Create context for the handler with progress reporting if token provided
        let ctx = match (progress_token, notification_sender) {
            (Some(token), Some(sender)) => {
                let sender = sender.clone();
                create_context_with_progress(cx.clone(), request_id, Some(token), move |req| {
                    sender(req);
                })
            }
            _ => McpContext::new(cx.clone(), request_id),
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
    /// * `notification_sender` - Optional callback for sending progress notifications
    pub fn handle_resources_read(
        &self,
        cx: &Cx,
        request_id: u64,
        params: &ReadResourceParams,
        budget: &Budget,
        notification_sender: Option<&NotificationSender>,
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

        // Find the resource handler
        let handler = self
            .resources
            .get(&params.uri)
            .ok_or_else(|| McpError::resource_not_found(&params.uri))?;

        // Extract progress token from request metadata
        let progress_token: Option<ProgressToken> =
            params.meta.as_ref().and_then(|m| m.progress_token.clone());

        // Create context for the handler with progress reporting if token provided
        let ctx = match (progress_token, notification_sender) {
            (Some(token), Some(sender)) => {
                let sender = sender.clone();
                create_context_with_progress(cx.clone(), request_id, Some(token), move |req| {
                    sender(req);
                })
            }
            _ => McpContext::new(cx.clone(), request_id),
        };

        // Read the resource asynchronously - returns McpOutcome (4-valued)
        let outcome = block_on(handler.read_async(&ctx));

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
    /// * `notification_sender` - Optional callback for sending progress notifications
    pub fn handle_prompts_get(
        &self,
        cx: &Cx,
        request_id: u64,
        params: GetPromptParams,
        budget: &Budget,
        notification_sender: Option<&NotificationSender>,
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

        // Create context for the handler with progress reporting if token provided
        let ctx = match (progress_token, notification_sender) {
            (Some(token), Some(sender)) => {
                let sender = sender.clone();
                create_context_with_progress(cx.clone(), request_id, Some(token), move |req| {
                    sender(req);
                })
            }
            _ => McpContext::new(cx.clone(), request_id),
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
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}
