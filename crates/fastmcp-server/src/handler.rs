//! Handler traits for tools, resources, and prompts.
//!
//! Handlers support both synchronous and asynchronous execution patterns:
//!
//! - **Sync handlers**: Implement `call()`, `read()`, or `get()` directly
//! - **Async handlers**: Override `call_async()`, `read_async()`, or `get_async()`
//!
//! The router always calls the async variants, which by default delegate to
//! the sync versions. This allows gradual migration to async without breaking
//! existing code.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use fastmcp_core::{
    McpContext, McpOutcome, McpResult, NotificationSender, Outcome, ProgressReporter,
};
use fastmcp_protocol::{
    Content, JsonRpcRequest, ProgressParams, ProgressToken, Prompt, PromptMessage, Resource,
    ResourceContent, Tool,
};

// ============================================================================
// Progress Notification Sender
// ============================================================================

/// A notification sender that sends progress notifications via a callback.
///
/// This is the server-side implementation used to send notifications back
/// to the client during handler execution.
pub struct ProgressNotificationSender<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    /// The progress token from the original request.
    token: ProgressToken,
    /// Callback to send notifications.
    send_fn: F,
}

impl<F> ProgressNotificationSender<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    /// Creates a new progress notification sender.
    pub fn new(token: ProgressToken, send_fn: F) -> Self {
        Self { token, send_fn }
    }

    /// Creates a progress reporter from this sender.
    pub fn into_reporter(self) -> ProgressReporter
    where
        Self: 'static,
    {
        ProgressReporter::new(Arc::new(self))
    }
}

impl<F> NotificationSender for ProgressNotificationSender<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    fn send_progress(&self, progress: f64, total: Option<f64>, message: Option<&str>) {
        let params = match total {
            Some(t) => ProgressParams::with_total(self.token.clone(), progress, t),
            None => ProgressParams::new(self.token.clone(), progress),
        };

        let params = if let Some(msg) = message {
            params.with_message(msg)
        } else {
            params
        };

        // Create a notification (request without id)
        let notification = JsonRpcRequest::notification(
            "notifications/progress",
            Some(serde_json::to_value(&params).unwrap_or_default()),
        );

        (self.send_fn)(notification);
    }
}

impl<F> std::fmt::Debug for ProgressNotificationSender<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressNotificationSender")
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

/// Helper to create an McpContext with progress reporting if a token is provided.
pub fn create_context_with_progress<F>(
    cx: asupersync::Cx,
    request_id: u64,
    progress_token: Option<ProgressToken>,
    send_fn: F,
) -> McpContext
where
    F: Fn(JsonRpcRequest) + Send + Sync + 'static,
{
    match progress_token {
        Some(token) => {
            let sender = ProgressNotificationSender::new(token, send_fn);
            McpContext::with_progress(cx, request_id, sender.into_reporter())
        }
        None => McpContext::new(cx, request_id),
    }
}

/// A boxed future for async handler results.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Handler for a tool.
///
/// This trait is typically implemented via the `#[tool]` macro.
///
/// # Sync vs Async
///
/// By default, implement `call()` for synchronous execution. For async tools,
/// override `call_async()` instead. The router always calls `call_async()`,
/// which defaults to running `call()` in an async block.
///
/// # Return Type
///
/// Async handlers return `McpOutcome<Vec<Content>>`, a 4-valued type supporting:
/// - `Ok(content)` - Successful result
/// - `Err(McpError)` - Recoverable error
/// - `Cancelled` - Request was cancelled
/// - `Panicked` - Unrecoverable failure
pub trait ToolHandler: Send + Sync {
    /// Returns the tool definition.
    fn definition(&self) -> Tool;

    /// Calls the tool synchronously with the given arguments.
    ///
    /// This is the default implementation point. Override this for simple
    /// synchronous tools. Returns `McpResult` which is converted to `McpOutcome`
    /// by the async wrapper.
    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>>;

    /// Calls the tool asynchronously with the given arguments.
    ///
    /// Override this for tools that need true async execution (e.g., I/O-bound
    /// operations, database queries, HTTP requests).
    ///
    /// Returns `McpOutcome` to properly represent all four states: success,
    /// error, cancellation, and panic.
    ///
    /// The default implementation delegates to the sync `call()` method and
    /// converts the `McpResult` to `McpOutcome`.
    fn call_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        Box::pin(async move {
            match self.call(ctx, arguments) {
                Ok(v) => Outcome::Ok(v),
                Err(e) => Outcome::Err(e),
            }
        })
    }
}

/// Handler for a resource.
///
/// This trait is typically implemented via the `#[resource]` macro.
///
/// # Sync vs Async
///
/// By default, implement `read()` for synchronous execution. For async resources,
/// override `read_async()` instead. The router always calls `read_async()`,
/// which defaults to running `read()` in an async block.
///
/// # Return Type
///
/// Async handlers return `McpOutcome<Vec<ResourceContent>>`, a 4-valued type.
pub trait ResourceHandler: Send + Sync {
    /// Returns the resource definition.
    fn definition(&self) -> Resource;

    /// Reads the resource content synchronously.
    ///
    /// This is the default implementation point. Override this for simple
    /// synchronous resources. Returns `McpResult` which is converted to `McpOutcome`
    /// by the async wrapper.
    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>>;

    /// Reads the resource content asynchronously.
    ///
    /// Override this for resources that need true async execution (e.g., file I/O,
    /// database queries, remote fetches).
    ///
    /// Returns `McpOutcome` to properly represent all four states.
    ///
    /// The default implementation delegates to the sync `read()` method.
    fn read_async<'a>(
        &'a self,
        ctx: &'a McpContext,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        Box::pin(async move {
            match self.read(ctx) {
                Ok(v) => Outcome::Ok(v),
                Err(e) => Outcome::Err(e),
            }
        })
    }
}

/// Handler for a prompt.
///
/// This trait is typically implemented via the `#[prompt]` macro.
///
/// # Sync vs Async
///
/// By default, implement `get()` for synchronous execution. For async prompts,
/// override `get_async()` instead. The router always calls `get_async()`,
/// which defaults to running `get()` in an async block.
///
/// # Return Type
///
/// Async handlers return `McpOutcome<Vec<PromptMessage>>`, a 4-valued type.
pub trait PromptHandler: Send + Sync {
    /// Returns the prompt definition.
    fn definition(&self) -> Prompt;

    /// Gets the prompt messages synchronously with the given arguments.
    ///
    /// This is the default implementation point. Override this for simple
    /// synchronous prompts. Returns `McpResult` which is converted to `McpOutcome`
    /// by the async wrapper.
    fn get(
        &self,
        ctx: &McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>>;

    /// Gets the prompt messages asynchronously with the given arguments.
    ///
    /// Override this for prompts that need true async execution (e.g., template
    /// fetching, dynamic content generation).
    ///
    /// Returns `McpOutcome` to properly represent all four states.
    ///
    /// The default implementation delegates to the sync `get()` method.
    fn get_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<Vec<PromptMessage>>> {
        Box::pin(async move {
            match self.get(ctx, arguments) {
                Ok(v) => Outcome::Ok(v),
                Err(e) => Outcome::Err(e),
            }
        })
    }
}

/// A boxed tool handler.
pub type BoxedToolHandler = Box<dyn ToolHandler>;

/// A boxed resource handler.
pub type BoxedResourceHandler = Box<dyn ResourceHandler>;

/// A boxed prompt handler.
pub type BoxedPromptHandler = Box<dyn PromptHandler>;
