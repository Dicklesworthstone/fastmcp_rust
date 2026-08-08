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

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::{
    McpContext, McpError, McpOutcome, McpResult, NotificationSender, Outcome, ProgressReporter,
    SessionState,
};
use fastmcp_protocol::common_types::{
    AbsoluteUri, Annotations, ContentBlock, EmbeddedResourceContents, OpenMetadata, RawIcon,
};
use fastmcp_protocol::{
    CompleteResult, CompletionValues, Content, CoreResultDiscriminatorPolicy, DecodedResult,
    FinalCallToolResult, FinalCompletionParams, Icon, JsonRpcRequest, LegacyCompletionParams,
    ProgressMarker, ProgressParams, Prompt, PromptMessage, Resource, ResourceContent,
    ResourceTemplate, ResultMeta, ResultPeerEra, Tool, ToolAnnotations, decode_peer_result,
    encode_result,
};

// ============================================================================
// Progress Notification Sender
// ============================================================================

/// A notification sender that sends progress notifications via a callback.
///
/// This is the server-side implementation used to send notifications back
/// to the client during handler execution. It rejects non-finite numeric
/// fields and serialization failures, and contains callback panics so a
/// reporting failure cannot unwind through the request handler.
///
/// This adapter does not provide monotonicity enforcement, rate limiting, or
/// a bounded delivery queue.
pub struct ProgressNotificationSender<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    /// The progress marker from the original request.
    marker: ProgressMarker,
    /// Callback to send notifications.
    send_fn: F,
}

impl<F> ProgressNotificationSender<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    /// Creates a new progress notification sender.
    pub fn new(marker: ProgressMarker, send_fn: F) -> Self {
        Self { marker, send_fn }
    }

    /// Creates a progress reporter from this sender.
    pub fn into_reporter(self) -> ProgressReporter
    where
        Self: 'static,
    {
        ProgressReporter::new(Arc::new(self))
    }

    fn send_progress_with_serializer<E>(
        &self,
        progress: f64,
        total: Option<f64>,
        message: Option<&str>,
        serialize: impl FnOnce(&ProgressParams) -> Result<serde_json::Value, E>,
    ) {
        if !progress.is_finite() || total.is_some_and(|value| !value.is_finite()) {
            log::warn!(
                target: "fastmcp_rust::handler",
                "progress notification rejected; reason=non_finite_numeric_value"
            );
            return;
        }

        let params = match total {
            Some(value) => ProgressParams::with_total(self.marker.clone(), progress, value),
            None => ProgressParams::new(self.marker.clone(), progress),
        };

        let params = if let Some(value) = message {
            params.with_message(value)
        } else {
            params
        };

        let Ok(serialized_params) = serialize(&params) else {
            log::warn!(
                target: "fastmcp_rust::handler",
                "progress notification rejected; reason=serialization_failure"
            );
            return;
        };

        let notification =
            JsonRpcRequest::notification("notifications/progress", Some(serialized_params));
        if crate::catch_extension_unwind(|| (self.send_fn)(notification)).is_err() {
            log::error!(
                target: "fastmcp_rust::handler",
                "progress notification callback terminated unexpectedly; detail=panic_payload_redacted"
            );
        }
    }
}

impl<F> NotificationSender for ProgressNotificationSender<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    fn send_progress(&self, progress: f64, total: Option<f64>, message: Option<&str>) {
        self.send_progress_with_serializer(progress, total, message, |params| {
            serde_json::to_value(params)
        });
    }
}

impl<F> std::fmt::Debug for ProgressNotificationSender<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressNotificationSender")
            .finish_non_exhaustive()
    }
}

/// Configuration for bidirectional senders to attach to context.
#[derive(Clone, Default)]
pub struct BidirectionalSenders {
    /// Optional sampling sender for LLM completions.
    pub sampling: Option<Arc<dyn fastmcp_core::SamplingSender>>,
    /// Optional elicitation sender for user input requests.
    pub elicitation: Option<Arc<dyn fastmcp_core::ElicitationSender>>,
}

impl BidirectionalSenders {
    /// Creates empty senders (no bidirectional features).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the sampling sender.
    #[must_use]
    pub fn with_sampling(mut self, sender: Arc<dyn fastmcp_core::SamplingSender>) -> Self {
        self.sampling = Some(sender);
        self
    }

    /// Sets the elicitation sender.
    #[must_use]
    pub fn with_elicitation(mut self, sender: Arc<dyn fastmcp_core::ElicitationSender>) -> Self {
        self.elicitation = Some(sender);
        self
    }
}

impl std::fmt::Debug for BidirectionalSenders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BidirectionalSenders")
            .field("sampling", &self.sampling.is_some())
            .field("elicitation", &self.elicitation.is_some())
            .finish()
    }
}

/// Helper to create an McpContext with optional progress reporting and session state.
pub fn create_context_with_progress<F>(
    cx: asupersync::Cx,
    request_id: u64,
    progress_marker: Option<ProgressMarker>,
    state: Option<SessionState>,
    send_fn: F,
) -> McpContext
where
    F: Fn(JsonRpcRequest) + Send + Sync + 'static,
{
    create_context_with_progress_and_senders(cx, request_id, progress_marker, state, send_fn, None)
}

/// Helper to create an McpContext with optional progress reporting, session state, and bidirectional senders.
pub fn create_context_with_progress_and_senders<F>(
    cx: asupersync::Cx,
    request_id: u64,
    progress_marker: Option<ProgressMarker>,
    state: Option<SessionState>,
    send_fn: F,
    senders: Option<&BidirectionalSenders>,
) -> McpContext
where
    F: Fn(JsonRpcRequest) + Send + Sync + 'static,
{
    let mut ctx = match (progress_marker, state) {
        (Some(marker), Some(state)) => {
            let sender = ProgressNotificationSender::new(marker, send_fn);
            McpContext::with_state_and_progress(cx, request_id, state, sender.into_reporter())
        }
        (Some(marker), None) => {
            let sender = ProgressNotificationSender::new(marker, send_fn);
            McpContext::with_progress(cx, request_id, sender.into_reporter())
        }
        (None, Some(state)) => McpContext::with_state(cx, request_id, state),
        (None, None) => McpContext::new(cx, request_id),
    };

    // Attach bidirectional senders if provided
    if let Some(senders) = senders {
        if let Some(ref sampling) = senders.sampling {
            ctx = ctx.with_sampling(sampling.clone());
        }
        if let Some(ref elicitation) = senders.elicitation {
            ctx = ctx.with_elicitation(elicitation.clone());
        }
    }

    ctx
}

/// A boxed future for async handler results.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// URI template parameters extracted from a matched resource URI.
pub type UriParams = HashMap<String, String>;

/// Encodes a router-produced modern success through the final result contract.
///
/// Legacy dispatch continues to serialize its method-specific result structs
/// directly. The stateless router, by contrast, calls this helper after a
/// shipped handler has completed so every successful modern response carries
/// the explicit `resultType: "complete"` discriminator and is admitted by the
/// same bounded protocol codec used for peer results. Method-specific payloads
/// may not pre-populate the discriminator; only this boundary selects it.
pub(crate) fn encode_final_complete_result<T: serde::Serialize>(
    payload: T,
) -> McpResult<serde_json::Value> {
    let serde_json::Value::Object(mut members) =
        serde_json::to_value(payload).map_err(McpError::from)?
    else {
        return Err(McpError::internal_error(
            "modern complete result payload must serialize as an object",
        ));
    };

    if members.contains_key("resultType") {
        return Err(McpError::internal_error(
            "modern complete result payload must not select a result type",
        ));
    }
    members.insert(
        "resultType".to_string(),
        serde_json::Value::String("complete".to_string()),
    );

    let encoded = serde_json::to_string(&members).map_err(McpError::from)?;
    let (decoded, diagnostic) = decode_peer_result(
        &encoded,
        ResultPeerEra::Modern,
        &CoreResultDiscriminatorPolicy,
    )
    .map_err(|_| McpError::internal_error("modern complete result violates the final contract"))?;

    if diagnostic.is_some() || !matches!(decoded, DecodedResult::Complete(_)) {
        return Err(McpError::internal_error(
            "modern complete result violates the final contract",
        ));
    }

    serde_json::from_str(&encode_result(&decoded)).map_err(McpError::from)
}

/// Returns empty metadata for a server-authored final complete result.
///
/// Final method codecs reject a synthesized `serverInfo`. The protocol result
/// algebra exposes metadata through decoded complete results, so obtain the
/// canonical empty instance through that same bounded decoder.
pub(crate) fn empty_final_result_meta() -> McpResult<ResultMeta> {
    let (decoded, diagnostic) = decode_peer_result(
        r#"{"resultType":"complete"}"#,
        ResultPeerEra::Modern,
        &CoreResultDiscriminatorPolicy,
    )
    .map_err(|_| McpError::internal_error("empty final result metadata is invalid"))?;
    if diagnostic.is_some() {
        return Err(McpError::internal_error(
            "empty final result metadata must select the complete discriminator",
        ));
    }
    let DecodedResult::Complete(empty_result) = decoded else {
        return Err(McpError::internal_error(
            "empty final result metadata must select the complete result",
        ));
    };
    Ok(empty_result.meta)
}

/// Promotes an exact legacy tool payload into the final complete-result algebra.
///
/// This is the compatibility direction used by legacy-only tool handlers when
/// a final request reaches the router. Every legacy content variant is mapped
/// without discarding information; malformed legacy embedded resources are
/// refused rather than authored as a different final resource.
pub(crate) fn promote_legacy_tool_content(
    content: Vec<Content>,
) -> McpResult<CompleteResult<FinalCallToolResult>> {
    let content = content
        .into_iter()
        .map(|content| match content {
            Content::Text { text } => Ok(ContentBlock::Text {
                text,
                annotations: None,
                meta: None,
            }),
            Content::Image { data, mime_type } => Ok(ContentBlock::Image {
                data,
                mime_type,
                annotations: None,
                meta: None,
            }),
            Content::Audio { data, mime_type } => Ok(ContentBlock::Audio {
                data,
                mime_type,
                annotations: None,
                meta: None,
            }),
            Content::Resource { resource } => {
                let uri = AbsoluteUri::parse(resource.uri).map_err(|error| {
                    McpError::internal_error(format!(
                        "legacy tool resource cannot be promoted to the final handler result: {error}",
                    ))
                })?;
                let embedded = match (resource.text, resource.blob) {
                    (Some(text), None) => EmbeddedResourceContents::Text {
                        uri,
                        text,
                        mime_type: resource.mime_type,
                    },
                    (None, Some(blob)) => EmbeddedResourceContents::Blob {
                        uri,
                        blob,
                        mime_type: resource.mime_type,
                    },
                    _ => {
                        return Err(McpError::internal_error(
                            "legacy tool resource cannot be promoted without exactly one text or blob payload",
                        ));
                    }
                };
                Ok(ContentBlock::Resource {
                    resource: embedded,
                    annotations: None,
                    meta: None,
                })
            }
        })
        .collect::<McpResult<Vec<_>>>()?;

    Ok(CompleteResult::new(
        FinalCallToolResult {
            content,
            is_error: false,
            structured_content: None,
        },
        empty_final_result_meta()?,
    ))
}

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

    /// Returns the tool's icon, if any.
    ///
    /// Default implementation returns `None`. Override to provide an icon.
    /// Note: Icons can also be set directly in `definition()`.
    fn icon(&self) -> Option<&Icon> {
        None
    }

    /// Returns the tool's version, if any.
    ///
    /// Default implementation returns `None`. Override to provide a version.
    /// Note: Version can also be set directly in `definition()`.
    fn version(&self) -> Option<&str> {
        None
    }

    /// Returns the tool's tags for filtering and organization.
    ///
    /// Default implementation returns an empty slice. Override to provide tags.
    /// Note: Tags can also be set directly in `definition()`.
    fn tags(&self) -> &[String] {
        &[]
    }

    /// Returns the tool's annotations providing behavioral hints.
    ///
    /// Default implementation returns `None`. Override to provide annotations
    /// like `destructive`, `idempotent`, `read_only`, or `open_world_hint`.
    /// Note: Annotations can also be set directly in `definition()`.
    fn annotations(&self) -> Option<&ToolAnnotations> {
        None
    }

    /// Returns the tool's output schema (JSON Schema).
    ///
    /// Default implementation returns `None`. Override to provide a schema
    /// that describes the structure of the tool's output.
    /// Note: Output schema can also be set directly in `definition()`.
    fn output_schema(&self) -> Option<serde_json::Value> {
        None
    }

    /// Returns the final display title for this tool.
    ///
    /// This final-only field is deliberately separate from the legacy tool
    /// definition so modern catalog projection never synthesizes or leaks a
    /// legacy version/tag field.
    fn final_title(&self) -> Option<&str> {
        None
    }

    /// Returns the validated final icon set for this tool.
    ///
    /// A legacy singular icon is not projected automatically because its
    /// optional source and scalar size hint do not form an exact final icon.
    fn final_icons(&self) -> Option<&[RawIcon]> {
        None
    }

    /// Returns final open metadata for this tool's catalog entry.
    fn final_metadata(&self) -> Option<&OpenMetadata> {
        None
    }

    /// Returns the tool's custom timeout duration.
    ///
    /// Default implementation returns `None`, meaning no additional handler
    /// ceiling is added. Override to specify a per-handler timeout.
    ///
    /// A non-zero value tightens the ambient/request/server budget. It never
    /// replaces or relaxes an earlier absolute deadline. A zero value is
    /// treated like `None` and therefore cannot disable an outer timeout.
    /// Pending async work is dropped when the legacy synchronous dispatcher's
    /// timer observes a comparable deadline, and a late completion is rejected.
    /// The dispatcher does not drive a caller's foreign virtual clock. This
    /// cannot preempt a blocking synchronous `call()` or guarantee child-work
    /// drain; handlers must still cooperate with [`McpContext::checkpoint`].
    fn timeout(&self) -> Option<Duration> {
        None
    }

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

    /// Calls the tool through the final MCP 2026-07-28 result surface.
    ///
    /// Legacy-only handlers retain their exact [`Self::call`] result and are
    /// promoted without loss into a complete final result. Handlers that
    /// author final-only metadata, annotations, resource links, or a tool
    /// error result should override this method (or its async counterpart) so
    /// the router can preserve the supplied final result algebra exactly.
    fn call_final(
        &self,
        ctx: &McpContext,
        arguments: serde_json::Value,
    ) -> McpResult<CompleteResult<FinalCallToolResult>> {
        promote_legacy_tool_content(self.call(ctx, arguments)?)
    }

    /// Asynchronously calls the tool through the final result surface.
    ///
    /// The default delegates to [`Self::call_final`].
    fn call_final_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalCallToolResult>>> {
        Box::pin(async move {
            match self.call_final(ctx, arguments) {
                Ok(value) => Outcome::Ok(value),
                Err(error) => Outcome::Err(error),
            }
        })
    }

    /// Calls the tool from a request-owned structured child.
    ///
    /// Modern router dispatch supplies the child [`Cx`] that owns this handler
    /// invocation. Implementations that spawn or otherwise coordinate nested
    /// work must use this context so cancellation and completion remain within
    /// the request's structured lifetime. Existing handlers keep their exact
    /// behavior through the default delegation to [`Self::call_async`].
    fn call_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        self.call_async(ctx, arguments)
    }

    /// Calls the tool's final result hook from a request-owned child.
    ///
    /// Existing final async handlers keep their behavior through the default
    /// delegation to [`Self::call_final_async`].
    fn call_final_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalCallToolResult>>> {
        self.call_final_async(ctx, arguments)
    }
}

/// Handler for a resource.
///
/// This trait is typically implemented via the `#[resource]` macro.
///
/// # Sync vs Async
///
/// By default, implement `read()` for synchronous execution. For async resources,
/// override `read_async()` instead. The router uses `read_async_with_uri()` so
/// implementations can access matched URI parameters when needed; its default
/// implementation delegates to `read_async()` or `read_with_uri()`.
///
/// # Return Type
///
/// Async handlers return `McpOutcome<Vec<ResourceContent>>`, a 4-valued type.
pub trait ResourceHandler: Send + Sync {
    /// Returns the resource definition.
    fn definition(&self) -> Resource;

    /// Returns the resource template definition, if this resource uses a URI template.
    fn template(&self) -> Option<ResourceTemplate> {
        None
    }

    /// Returns the final display title for this concrete resource.
    fn final_title(&self) -> Option<&str> {
        None
    }

    /// Returns the final icon set for this concrete resource.
    fn final_icons(&self) -> Option<&[RawIcon]> {
        None
    }

    /// Returns the final annotations for this concrete resource.
    fn final_annotations(&self) -> Option<&Annotations> {
        None
    }

    /// Returns final open metadata for this concrete resource.
    fn final_metadata(&self) -> Option<&OpenMetadata> {
        None
    }

    /// Returns the final display title for this resource template.
    ///
    /// This is used only when [`Self::template`] returns `Some`.
    fn final_template_title(&self) -> Option<&str> {
        None
    }

    /// Returns the final icon set for this resource template.
    ///
    /// This is used only when [`Self::template`] returns `Some`.
    fn final_template_icons(&self) -> Option<&[RawIcon]> {
        None
    }

    /// Returns the final annotations for this resource template.
    ///
    /// This is used only when [`Self::template`] returns `Some`.
    fn final_template_annotations(&self) -> Option<&Annotations> {
        None
    }

    /// Returns final open metadata for this resource template.
    ///
    /// This is used only when [`Self::template`] returns `Some`.
    fn final_template_metadata(&self) -> Option<&OpenMetadata> {
        None
    }

    /// Returns the resource's icon, if any.
    ///
    /// Default implementation returns `None`. Override to provide an icon.
    /// Note: Icons can also be set directly in `definition()`.
    fn icon(&self) -> Option<&Icon> {
        None
    }

    /// Returns the resource's version, if any.
    ///
    /// Default implementation returns `None`. Override to provide a version.
    /// Note: Version can also be set directly in `definition()`.
    fn version(&self) -> Option<&str> {
        None
    }

    /// Returns the resource's tags for filtering and organization.
    ///
    /// Default implementation returns an empty slice. Override to provide tags.
    /// Note: Tags can also be set directly in `definition()`.
    fn tags(&self) -> &[String] {
        &[]
    }

    /// Returns the resource's custom timeout duration.
    ///
    /// Default implementation returns `None`, meaning no additional handler
    /// ceiling is added. A non-zero value only tightens outer budgets; zero
    /// cannot disable an ambient, request, or server deadline.
    /// A blocking synchronous `read()` cannot be preempted; if it returns
    /// after the deadline, its result is rejected.
    fn timeout(&self) -> Option<Duration> {
        None
    }

    /// Reads the resource content synchronously.
    ///
    /// This is the default implementation point. Override this for simple
    /// synchronous resources. Returns `McpResult` which is converted to `McpOutcome`
    /// by the async wrapper.
    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>>;

    /// Reads the resource content synchronously with the matched URI and parameters.
    ///
    /// Default implementation ignores URI params and delegates to `read()`.
    fn read_with_uri(
        &self,
        ctx: &McpContext,
        _uri: &str,
        _params: &UriParams,
    ) -> McpResult<Vec<ResourceContent>> {
        self.read(ctx)
    }

    /// Reads the resource content asynchronously with the matched URI and parameters.
    ///
    /// Default implementation delegates to the sync `read_with_uri()` method.
    fn read_async_with_uri<'a>(
        &'a self,
        ctx: &'a McpContext,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        Box::pin(async move {
            if params.is_empty() {
                self.read_async(ctx).await
            } else {
                match self.read_with_uri(ctx, uri, params) {
                    Ok(v) => Outcome::Ok(v),
                    Err(e) => Outcome::Err(e),
                }
            }
        })
    }

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

    /// Reads the resource from a request-owned structured child.
    ///
    /// Modern router dispatch supplies the child [`Cx`] that owns this read.
    /// Implementations with nested asynchronous work must retain this context
    /// rather than creating detached work. Existing handlers preserve their
    /// exact behavior through the default delegation.
    fn read_async_with_uri_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        self.read_async_with_uri(ctx, uri, params)
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

    /// Returns the final display title for this prompt.
    fn final_title(&self) -> Option<&str> {
        None
    }

    /// Returns the final icon set for this prompt.
    fn final_icons(&self) -> Option<&[RawIcon]> {
        None
    }

    /// Returns final open metadata for this prompt.
    fn final_metadata(&self) -> Option<&OpenMetadata> {
        None
    }

    /// Returns the prompt's icon, if any.
    ///
    /// Default implementation returns `None`. Override to provide an icon.
    /// Note: Icons can also be set directly in `definition()`.
    fn icon(&self) -> Option<&Icon> {
        None
    }

    /// Returns the prompt's version, if any.
    ///
    /// Default implementation returns `None`. Override to provide a version.
    /// Note: Version can also be set directly in `definition()`.
    fn version(&self) -> Option<&str> {
        None
    }

    /// Returns the prompt's tags for filtering and organization.
    ///
    /// Default implementation returns an empty slice. Override to provide tags.
    /// Note: Tags can also be set directly in `definition()`.
    fn tags(&self) -> &[String] {
        &[]
    }

    /// Returns the prompt's custom timeout duration.
    ///
    /// Default implementation returns `None`, meaning no additional handler
    /// ceiling is added. A non-zero value only tightens outer budgets; zero
    /// cannot disable an ambient, request, or server deadline.
    /// A blocking synchronous `get()` cannot be preempted; if it returns
    /// after the deadline, its result is rejected.
    fn timeout(&self) -> Option<Duration> {
        None
    }

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

    /// Gets the prompt from a request-owned structured child.
    ///
    /// Modern router dispatch supplies the child [`Cx`] that owns this prompt
    /// evaluation. Existing handlers preserve their exact behavior through the
    /// default delegation to [`Self::get_async`].
    fn get_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<Vec<PromptMessage>>> {
        self.get_async(ctx, arguments)
    }
}

/// Handler for `completion/complete` in both supported protocol eras.
///
/// The two request parameter types deliberately remain distinct: the final
/// form carries required request metadata and optional completion context,
/// while the exact legacy form does not. Both callbacks return the shared
/// completion value payload; the router selects the era-specific result
/// envelope and final `resultType` contract.
pub trait CompletionHandler: Send + Sync {
    /// Returns an optional handler-specific timeout.
    ///
    /// A non-zero timeout tightens the request budget and cannot relax an
    /// existing deadline. Zero is treated as no handler-specific timeout.
    fn timeout(&self) -> Option<Duration> {
        None
    }

    /// Completes one exact MCP 2024-11-05 request.
    fn complete_legacy(
        &self,
        ctx: &McpContext,
        params: LegacyCompletionParams,
    ) -> McpResult<CompletionValues>;

    /// Completes one final MCP 2026-07-28 request.
    fn complete_final(
        &self,
        ctx: &McpContext,
        params: FinalCompletionParams,
    ) -> McpResult<CompletionValues>;

    /// Asynchronously completes one exact legacy request.
    ///
    /// The default delegates to [`Self::complete_legacy`].
    fn complete_legacy_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        params: LegacyCompletionParams,
    ) -> BoxFuture<'a, McpOutcome<CompletionValues>> {
        Box::pin(async move {
            match self.complete_legacy(ctx, params) {
                Ok(values) => Outcome::Ok(values),
                Err(error) => Outcome::Err(error),
            }
        })
    }

    /// Asynchronously completes one final request.
    ///
    /// The default delegates to [`Self::complete_final`].
    fn complete_final_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        params: FinalCompletionParams,
    ) -> BoxFuture<'a, McpOutcome<CompletionValues>> {
        Box::pin(async move {
            match self.complete_final(ctx, params) {
                Ok(values) => Outcome::Ok(values),
                Err(error) => Outcome::Err(error),
            }
        })
    }

    /// Completes one final request from its request-owned structured child.
    ///
    /// Implementations with nested asynchronous work must use `request_cx`
    /// so cancellation remains owned by the originating modern request.
    fn complete_final_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        params: FinalCompletionParams,
    ) -> BoxFuture<'a, McpOutcome<CompletionValues>> {
        self.complete_final_async(ctx, params)
    }
}

/// A boxed tool handler.
pub type BoxedToolHandler = Box<dyn ToolHandler>;

/// A boxed resource handler.
pub type BoxedResourceHandler = Box<dyn ResourceHandler>;

/// A boxed prompt handler.
pub type BoxedPromptHandler = Box<dyn PromptHandler>;

/// A boxed completion handler.
pub type BoxedCompletionHandler = Box<dyn CompletionHandler>;

// ============================================================================
// Mounted Handler Wrappers
// ============================================================================

/// A wrapper for a tool handler that overrides its name.
///
/// Used by `mount()` to prefix tool names when mounting from another server.
pub struct MountedToolHandler {
    inner: BoxedToolHandler,
    mounted_name: String,
}

impl MountedToolHandler {
    /// Creates a new mounted tool handler with the given name.
    pub fn new(inner: BoxedToolHandler, mounted_name: String) -> Self {
        Self {
            inner,
            mounted_name,
        }
    }
}

impl ToolHandler for MountedToolHandler {
    fn definition(&self) -> Tool {
        let mut def = self.inner.definition();
        def.name.clone_from(&self.mounted_name);
        def
    }

    fn icon(&self) -> Option<&Icon> {
        self.inner.icon()
    }

    fn version(&self) -> Option<&str> {
        self.inner.version()
    }

    fn tags(&self) -> &[String] {
        self.inner.tags()
    }

    fn annotations(&self) -> Option<&ToolAnnotations> {
        self.inner.annotations()
    }

    fn output_schema(&self) -> Option<serde_json::Value> {
        self.inner.output_schema()
    }

    fn final_title(&self) -> Option<&str> {
        self.inner.final_title()
    }

    fn final_icons(&self) -> Option<&[RawIcon]> {
        self.inner.final_icons()
    }

    fn final_metadata(&self) -> Option<&OpenMetadata> {
        self.inner.final_metadata()
    }

    fn timeout(&self) -> Option<Duration> {
        self.inner.timeout()
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        self.inner.call(ctx, arguments)
    }

    fn call_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        self.inner.call_async(ctx, arguments)
    }

    fn call_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        self.inner.call_async_in_request(ctx, request_cx, arguments)
    }

    fn call_final(
        &self,
        ctx: &McpContext,
        arguments: serde_json::Value,
    ) -> McpResult<CompleteResult<FinalCallToolResult>> {
        self.inner.call_final(ctx, arguments)
    }

    fn call_final_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalCallToolResult>>> {
        self.inner.call_final_async(ctx, arguments)
    }

    fn call_final_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalCallToolResult>>> {
        self.inner
            .call_final_async_in_request(ctx, request_cx, arguments)
    }
}

/// A wrapper for a resource handler that overrides its URI.
///
/// Used by `mount()` to prefix resource URIs when mounting from another server.
pub struct MountedResourceHandler {
    inner: BoxedResourceHandler,
    source_uri: String,
    mounted_uri: String,
    mount_prefix: Option<String>,
    mounted_template: Option<ResourceTemplate>,
}

impl MountedResourceHandler {
    /// Creates a mounted resource handler from authoritative source and
    /// destination registry keys.
    pub fn new(inner: BoxedResourceHandler, source_uri: String, mounted_uri: String) -> Self {
        let mount_prefix = Self::infer_mount_prefix(&source_uri, &mounted_uri);
        Self {
            inner,
            source_uri,
            mounted_uri,
            mount_prefix,
            mounted_template: None,
        }
    }

    /// Creates a new mounted resource handler with a mounted template.
    pub fn with_template(
        inner: BoxedResourceHandler,
        source_uri: String,
        mounted_uri: String,
        mounted_template: ResourceTemplate,
    ) -> Self {
        let mount_prefix = Self::infer_mount_prefix(&source_uri, &mounted_uri);
        Self {
            inner,
            source_uri,
            mounted_uri,
            mount_prefix,
            mounted_template: Some(mounted_template),
        }
    }

    fn infer_mount_prefix(source_uri: &str, mounted_uri: &str) -> Option<String> {
        mounted_uri
            .strip_suffix(source_uri)
            .filter(|prefix| !prefix.is_empty())
            .map(str::to_string)
    }

    fn translate_incoming_uri(&self, uri: &str) -> McpResult<String> {
        if uri == self.mounted_uri {
            return Ok(self.source_uri.clone());
        }
        match &self.mount_prefix {
            Some(prefix) => uri.strip_prefix(prefix).map(str::to_string).ok_or_else(|| {
                McpError::invalid_params("Resource URI does not match the mounted namespace")
            }),
            None if self.mounted_uri == self.source_uri => Ok(uri.to_string()),
            None => Err(McpError::invalid_params(
                "Resource URI does not match the mounted resource",
            )),
        }
    }

    fn translate_outgoing_contents(
        &self,
        mut contents: Vec<ResourceContent>,
    ) -> Vec<ResourceContent> {
        for content in &mut contents {
            if let Some(prefix) = &self.mount_prefix {
                content.uri = format!("{prefix}{}", content.uri);
            } else if content.uri == self.source_uri {
                content.uri.clone_from(&self.mounted_uri);
            }
        }
        contents
    }
}

impl ResourceHandler for MountedResourceHandler {
    fn definition(&self) -> Resource {
        let mut def = self.inner.definition();
        def.uri.clone_from(&self.mounted_uri);
        def
    }

    fn template(&self) -> Option<ResourceTemplate> {
        self.mounted_template.clone()
    }

    fn final_title(&self) -> Option<&str> {
        self.inner.final_title()
    }

    fn final_icons(&self) -> Option<&[RawIcon]> {
        self.inner.final_icons()
    }

    fn final_annotations(&self) -> Option<&Annotations> {
        self.inner.final_annotations()
    }

    fn final_metadata(&self) -> Option<&OpenMetadata> {
        self.inner.final_metadata()
    }

    fn final_template_title(&self) -> Option<&str> {
        self.inner.final_template_title()
    }

    fn final_template_icons(&self) -> Option<&[RawIcon]> {
        self.inner.final_template_icons()
    }

    fn final_template_annotations(&self) -> Option<&Annotations> {
        self.inner.final_template_annotations()
    }

    fn final_template_metadata(&self) -> Option<&OpenMetadata> {
        self.inner.final_template_metadata()
    }

    fn icon(&self) -> Option<&Icon> {
        self.inner.icon()
    }

    fn version(&self) -> Option<&str> {
        self.inner.version()
    }

    fn tags(&self) -> &[String] {
        self.inner.tags()
    }

    fn timeout(&self) -> Option<Duration> {
        self.inner.timeout()
    }

    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        self.inner
            .read(ctx)
            .map(|contents| self.translate_outgoing_contents(contents))
    }

    fn read_with_uri(
        &self,
        ctx: &McpContext,
        uri: &str,
        params: &UriParams,
    ) -> McpResult<Vec<ResourceContent>> {
        let source_uri = self.translate_incoming_uri(uri)?;
        self.inner
            .read_with_uri(ctx, &source_uri, params)
            .map(|contents| self.translate_outgoing_contents(contents))
    }

    fn read_async_with_uri<'a>(
        &'a self,
        ctx: &'a McpContext,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        Box::pin(async move {
            let source_uri = match self.translate_incoming_uri(uri) {
                Ok(source_uri) => source_uri,
                Err(error) => return Outcome::Err(error),
            };
            self.inner
                .read_async_with_uri(ctx, &source_uri, params)
                .await
                .map(|contents| self.translate_outgoing_contents(contents))
        })
    }

    fn read_async<'a>(
        &'a self,
        ctx: &'a McpContext,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        Box::pin(async move {
            self.inner
                .read_async(ctx)
                .await
                .map(|contents| self.translate_outgoing_contents(contents))
        })
    }

    fn read_async_with_uri_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        Box::pin(async move {
            let source_uri = match self.translate_incoming_uri(uri) {
                Ok(source_uri) => source_uri,
                Err(error) => return Outcome::Err(error),
            };
            self.inner
                .read_async_with_uri_in_request(ctx, request_cx, &source_uri, params)
                .await
                .map(|contents| self.translate_outgoing_contents(contents))
        })
    }
}

/// A wrapper for a prompt handler that overrides its name.
///
/// Used by `mount()` to prefix prompt names when mounting from another server.
pub struct MountedPromptHandler {
    inner: BoxedPromptHandler,
    mounted_name: String,
}

impl MountedPromptHandler {
    /// Creates a new mounted prompt handler with the given name.
    pub fn new(inner: BoxedPromptHandler, mounted_name: String) -> Self {
        Self {
            inner,
            mounted_name,
        }
    }
}

impl PromptHandler for MountedPromptHandler {
    fn definition(&self) -> Prompt {
        let mut def = self.inner.definition();
        def.name.clone_from(&self.mounted_name);
        def
    }

    fn final_title(&self) -> Option<&str> {
        self.inner.final_title()
    }

    fn final_icons(&self) -> Option<&[RawIcon]> {
        self.inner.final_icons()
    }

    fn final_metadata(&self) -> Option<&OpenMetadata> {
        self.inner.final_metadata()
    }

    fn icon(&self) -> Option<&Icon> {
        self.inner.icon()
    }

    fn version(&self) -> Option<&str> {
        self.inner.version()
    }

    fn tags(&self) -> &[String] {
        self.inner.tags()
    }

    fn timeout(&self) -> Option<Duration> {
        self.inner.timeout()
    }

    fn get(
        &self,
        ctx: &McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        self.inner.get(ctx, arguments)
    }

    fn get_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<Vec<PromptMessage>>> {
        self.inner.get_async(ctx, arguments)
    }

    fn get_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<Vec<PromptMessage>>> {
        self.inner.get_async_in_request(ctx, request_cx, arguments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::Cx;
    use std::sync::{Mutex, OnceLock};

    #[test]
    fn handler_final_complete_contract_positive() {
        let payload = serde_json::json!({
            "content": [{"type": "text", "text": "shipped handler result"}],
            "isError": false,
        });

        let encoded = encode_final_complete_result(payload.clone())
            .expect("a complete handler payload is admitted by the final result contract");

        assert_eq!(
            encoded.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(encoded.get("content"), payload.get("content"));
        assert_eq!(encoded.get("isError"), payload.get("isError"));
    }

    #[test]
    fn handler_final_complete_contract_planted_negative() {
        let baseline = serde_json::json!({
            "content": [{"type": "text", "text": "shipped handler result"}],
            "isError": false,
        });
        let mut planted = baseline.clone();
        planted
            .as_object_mut()
            .expect("complete payload is an object")
            .insert(
                "resultType".to_string(),
                serde_json::json!("input_required"),
            );

        assert_eq!(
            baseline.get("content"),
            planted.get("content"),
            "the discriminator is the sole planted dimension"
        );
        assert_eq!(baseline.get("isError"), planted.get("isError"));
        let planted_before = planted.clone();

        encode_final_complete_result(baseline)
            .expect("the baseline must remain a valid complete payload");
        let error = encode_final_complete_result(planted.clone())
            .expect_err("a handler cannot preselect a different final result discriminator");

        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);
        assert_eq!(
            planted, planted_before,
            "the rejected payload remains unchanged for callers that retry or log it"
        );
    }

    fn custom_icon() -> &'static Icon {
        static ICON: OnceLock<Icon> = OnceLock::new();
        ICON.get_or_init(|| Icon::new("https://example.test/component.svg"))
    }

    // ── ProgressNotificationSender ───────────────────────────────────

    #[test]
    fn progress_sender_sends_notification_without_total() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender = ProgressNotificationSender::new(ProgressMarker::from("tok-1"), move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        sender.send_progress(0.5, None, None);

        let messages = sent.lock().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].method, "notifications/progress");
        let params = messages[0].params.as_ref().unwrap();
        assert_eq!(params["progress"], 0.5);
        assert!(params.get("total").is_none() || params["total"].is_null());
    }

    #[test]
    fn progress_sender_sends_notification_with_total() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender = ProgressNotificationSender::new(ProgressMarker::from("tok-2"), move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        sender.send_progress(3.0, Some(10.0), None);

        let messages = sent.lock().unwrap();
        let params = messages[0].params.as_ref().unwrap();
        assert_eq!(params["progress"], 3.0);
        assert_eq!(params["total"], 10.0);
    }

    #[test]
    fn progress_sender_sends_notification_with_message() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender = ProgressNotificationSender::new(ProgressMarker::from("tok-3"), move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        sender.send_progress(1.0, Some(5.0), Some("loading"));

        let messages = sent.lock().unwrap();
        let params = messages[0].params.as_ref().unwrap();
        assert_eq!(params["message"], "loading");
    }

    #[test]
    fn progress_sender_rejects_non_finite_progress_and_total() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender =
            ProgressNotificationSender::new(ProgressMarker::from("finite-check"), move |request| {
                sent_clone.lock().unwrap().push(request);
            });

        for (progress, total) in [
            (f64::NAN, None),
            (f64::INFINITY, None),
            (f64::NEG_INFINITY, None),
            (1.0, Some(f64::NAN)),
            (1.0, Some(f64::INFINITY)),
            (1.0, Some(f64::NEG_INFINITY)),
        ] {
            sender.send_progress(progress, total, Some("must not be sent"));
        }

        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn progress_sender_rejects_serialization_failure() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender = ProgressNotificationSender::new(
            ProgressMarker::from("serialization-check"),
            move |request| {
                sent_clone.lock().unwrap().push(request);
            },
        );

        sender.send_progress_with_serializer(1.0, Some(2.0), None, |_| {
            Result::<serde_json::Value, ()>::Err(())
        });

        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn progress_sender_contains_callback_panic() {
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let callback_attempts = Arc::clone(&attempts);
        let sender =
            ProgressNotificationSender::new(ProgressMarker::from("panic-check"), move |_request| {
                callback_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                panic!("progress callback panic payload");
            });

        sender.send_progress(1.0, Some(2.0), None);

        assert_eq!(attempts.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn progress_sender_debug_redacts_marker() {
        let canary = "progress-marker-debug-canary";
        let sender = ProgressNotificationSender::new(ProgressMarker::from(canary), |_| {});
        let debug = format!("{:?}", sender);

        assert!(debug.contains("ProgressNotificationSender"));
        assert!(!debug.contains(canary));
        assert!(!debug.contains("marker"));
    }

    #[test]
    fn progress_sender_into_reporter() {
        let sender = ProgressNotificationSender::new(ProgressMarker::from("tok-rpt"), |_| {});
        let _reporter = sender.into_reporter();
    }

    // ── BidirectionalSenders ─────────────────────────────────────────

    #[test]
    fn bidirectional_senders_default_is_empty() {
        let senders = BidirectionalSenders::new();
        assert!(senders.sampling.is_none());
        assert!(senders.elicitation.is_none());
    }

    #[test]
    fn bidirectional_senders_debug_shows_presence() {
        let senders = BidirectionalSenders::new();
        let debug = format!("{:?}", senders);
        assert!(debug.contains("sampling: false"));
        assert!(debug.contains("elicitation: false"));
    }

    // ── create_context_with_progress ─────────────────────────────────

    #[test]
    fn create_context_no_progress_no_state() {
        let cx = Cx::for_testing();
        let ctx = create_context_with_progress(cx, 42, None, None, |_| {});
        assert_eq!(ctx.request_id(), 42);
    }

    #[test]
    fn create_context_with_progress_marker() {
        let cx = Cx::for_testing();
        let marker = ProgressMarker::from("ctx-pm");
        let ctx = create_context_with_progress(cx, 7, Some(marker), None, |_| {});
        assert_eq!(ctx.request_id(), 7);
    }

    #[test]
    fn create_context_with_state_only() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        state.set("k", &"v");
        let ctx = create_context_with_progress(cx, 10, None, Some(state), |_| {});
        let val: Option<String> = ctx.get_state("k");
        assert_eq!(val.as_deref(), Some("v"));
    }

    #[test]
    fn create_context_with_progress_and_state() {
        let cx = Cx::for_testing();
        let marker = ProgressMarker::from("both");
        let state = SessionState::new();
        let ctx = create_context_with_progress(cx, 99, Some(marker), Some(state), |_| {});
        assert_eq!(ctx.request_id(), 99);
    }

    // ── Minimal ToolHandler impl for testing ─────────────────────────

    struct StubTool;

    impl ToolHandler for StubTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "stub".to_string(),
                description: Some("a stub tool".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text(format!("echo: {args}"))])
        }
    }

    #[test]
    fn tool_handler_defaults_return_none() {
        let tool = StubTool;
        assert!(tool.icon().is_none());
        assert!(tool.version().is_none());
        assert!(tool.tags().is_empty());
        assert!(tool.annotations().is_none());
        assert!(tool.output_schema().is_none());
        assert!(tool.timeout().is_none());
    }

    #[test]
    fn tool_handler_call_sync() {
        let tool = StubTool;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let result = tool.call(&ctx, serde_json::json!({"x": 1})).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn tool_handler_final_surface_promotes_legacy_content_without_changing_legacy_call() {
        let tool = StubTool;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let legacy = tool
            .call(&ctx, serde_json::json!({"x": 1}))
            .expect("legacy handler result");
        let final_result = tool
            .call_final(&ctx, serde_json::json!({"x": 1}))
            .expect("legacy handler promotes into the final result algebra");

        assert!(matches!(legacy.as_slice(), [Content::Text { .. }]));
        assert!(matches!(
            final_result.payload.content.as_slice(),
            [ContentBlock::Text { .. }]
        ));
        assert!(final_result.meta.server_info.is_none());
    }

    #[test]
    fn tool_handler_final_catalog_accessors_preserve_final_only_fields() {
        struct FinalCatalogTool {
            metadata: OpenMetadata,
            icons: Vec<RawIcon>,
        }

        impl ToolHandler for FinalCatalogTool {
            fn definition(&self) -> Tool {
                (StubTool).definition()
            }

            fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
                Ok(vec![Content::text("final catalog")])
            }

            fn final_title(&self) -> Option<&str> {
                Some("Final Title")
            }

            fn final_icons(&self) -> Option<&[RawIcon]> {
                Some(&self.icons)
            }

            fn final_metadata(&self) -> Option<&OpenMetadata> {
                Some(&self.metadata)
            }
        }

        let metadata = OpenMetadata::try_from_entries([(
            "com.example/catalog".to_owned(),
            serde_json::json!({"preserve": true}),
        )])
        .expect("final metadata");
        let icons = vec![RawIcon::try_new("https://example.test/icon.png").expect("final icon")];
        let tool = FinalCatalogTool { metadata, icons };

        assert_eq!(tool.final_title(), Some("Final Title"));
        assert_eq!(tool.final_icons().map(<[RawIcon]>::len), Some(1));
        assert_eq!(
            tool.final_metadata()
                .and_then(|metadata| metadata.get("com.example/catalog")),
            Some(&serde_json::json!({"preserve": true}))
        );
        assert!(tool.output_schema().is_none());
    }

    #[test]
    fn tool_handler_call_sync_error() {
        struct FailTool;
        impl ToolHandler for FailTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "fail".to_string(),
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
                Err(McpError::internal_error("boom"))
            }
        }

        let tool = FailTool;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let err = tool.call(&ctx, serde_json::json!({})).unwrap_err();
        assert!(err.message.contains("boom"));
    }

    // ── Minimal ResourceHandler impl for testing ─────────────────────

    struct StubResource;

    impl ResourceHandler for StubResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "file:///stub".to_string(),
                name: "stub".to_string(),
                description: None,
                mime_type: Some("text/plain".to_string()),
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![ResourceContent {
                uri: "file:///stub".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("hello".to_string()),
                blob: None,
            }])
        }
    }

    #[test]
    fn resource_handler_defaults_return_none() {
        let res = StubResource;
        assert!(res.template().is_none());
        assert!(res.icon().is_none());
        assert!(res.version().is_none());
        assert!(res.tags().is_empty());
        assert!(res.timeout().is_none());
    }

    #[test]
    fn resource_handler_read_with_uri_delegates_to_read() {
        let res = StubResource;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let params = UriParams::new();
        let result = res.read_with_uri(&ctx, "file:///stub", &params).unwrap();
        assert_eq!(result.len(), 1);
    }

    // ── Minimal PromptHandler impl for testing ───────────────────────

    struct StubPrompt;

    impl PromptHandler for StubPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "stub".to_string(),
                description: Some("a stub prompt".to_string()),
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _arguments: HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Ok(vec![])
        }
    }

    #[test]
    fn prompt_handler_defaults_return_none() {
        let prompt = StubPrompt;
        assert!(prompt.icon().is_none());
        assert!(prompt.version().is_none());
        assert!(prompt.tags().is_empty());
        assert!(prompt.timeout().is_none());
    }

    // ── MountedToolHandler ───────────────────────────────────────────

    #[test]
    fn mounted_tool_handler_overrides_name() {
        let inner = Box::new(StubTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "prefix_stub".to_string());
        let def = mounted.definition();
        assert_eq!(def.name, "prefix_stub");
        assert_eq!(def.description.as_deref(), Some("a stub tool"));
    }

    #[test]
    fn mounted_tool_handler_delegates_defaults() {
        let inner = Box::new(StubTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "m_stub".to_string());
        assert!(mounted.tags().is_empty());
        assert!(mounted.annotations().is_none());
        assert!(mounted.output_schema().is_none());
        assert!(mounted.timeout().is_none());
    }

    #[test]
    fn mounted_tool_handler_delegates_call() {
        let inner = Box::new(StubTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "m_stub".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let result = mounted.call(&ctx, serde_json::json!({})).unwrap();
        assert!(!result.is_empty());
    }

    // ── MountedResourceHandler ───────────────────────────────────────

    #[test]
    fn mounted_resource_handler_overrides_uri() {
        let inner = Box::new(StubResource) as BoxedResourceHandler;
        let mounted = MountedResourceHandler::new(
            inner,
            "file:///stub".to_string(),
            "file:///mounted".to_string(),
        );
        let def = mounted.definition();
        assert_eq!(def.uri, "file:///mounted");
        assert_eq!(def.name, "stub");
    }

    #[test]
    fn mounted_resource_handler_template_none_by_default() {
        let inner = Box::new(StubResource) as BoxedResourceHandler;
        let mounted =
            MountedResourceHandler::new(inner, "file:///stub".to_string(), "file:///m".to_string());
        assert!(mounted.template().is_none());
    }

    #[test]
    fn mounted_resource_handler_with_template() {
        let inner = Box::new(StubResource) as BoxedResourceHandler;
        let tmpl = ResourceTemplate {
            uri_template: "file:///items/{id}".to_string(),
            name: "items".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let mounted = MountedResourceHandler::with_template(
            inner,
            "file:///items/{id}".to_string(),
            "file:///items/{id}".to_string(),
            tmpl,
        );
        let t = mounted.template().expect("template set");
        assert_eq!(t.uri_template, "file:///items/{id}");
    }

    #[test]
    fn mounted_resource_handler_delegates_read() {
        let inner = Box::new(StubResource) as BoxedResourceHandler;
        let mounted =
            MountedResourceHandler::new(inner, "file:///stub".to_string(), "file:///m".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let result = mounted.read(&ctx).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].uri, "file:///m");
    }

    #[test]
    fn mounted_resource_handler_delegates_tags() {
        let inner = Box::new(StubResource) as BoxedResourceHandler;
        let mounted =
            MountedResourceHandler::new(inner, "file:///stub".to_string(), "file:///m".to_string());
        assert!(mounted.tags().is_empty());
    }

    // ── MountedPromptHandler ─────────────────────────────────────────

    #[test]
    fn mounted_prompt_handler_overrides_name() {
        let inner = Box::new(StubPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns_stub".to_string());
        let def = mounted.definition();
        assert_eq!(def.name, "ns_stub");
        assert_eq!(def.description.as_deref(), Some("a stub prompt"));
    }

    #[test]
    fn mounted_prompt_handler_delegates_defaults() {
        let inner = Box::new(StubPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns_stub".to_string());
        assert!(mounted.tags().is_empty());
        assert!(mounted.timeout().is_none());
    }

    #[test]
    fn mounted_prompt_handler_delegates_get() {
        let inner = Box::new(StubPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns_stub".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let result = mounted.get(&ctx, HashMap::new()).unwrap();
        assert!(result.is_empty());
    }

    // ── BidirectionalSenders builders ────────────────────────────────

    struct DummySamplingSender;
    impl fastmcp_core::SamplingSender for DummySamplingSender {
        fn create_message(
            &self,
            _request: fastmcp_core::SamplingRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = McpResult<fastmcp_core::SamplingResponse>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Err(McpError::internal_error("stub")) })
        }
    }

    struct DummyElicitationSender;
    impl fastmcp_core::ElicitationSender for DummyElicitationSender {
        fn elicit(
            &self,
            _request: fastmcp_core::ElicitationRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = McpResult<fastmcp_core::ElicitationResponse>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Err(McpError::internal_error("stub")) })
        }
    }

    #[test]
    fn bidirectional_senders_with_sampling() {
        let senders =
            BidirectionalSenders::new().with_sampling(Arc::new(DummySamplingSender) as Arc<_>);
        assert!(senders.sampling.is_some());
        assert!(senders.elicitation.is_none());
    }

    #[test]
    fn bidirectional_senders_with_elicitation() {
        let senders = BidirectionalSenders::new()
            .with_elicitation(Arc::new(DummyElicitationSender) as Arc<_>);
        assert!(senders.sampling.is_none());
        assert!(senders.elicitation.is_some());
    }

    #[test]
    fn bidirectional_senders_with_both() {
        let senders = BidirectionalSenders::new()
            .with_sampling(Arc::new(DummySamplingSender) as Arc<_>)
            .with_elicitation(Arc::new(DummyElicitationSender) as Arc<_>);
        assert!(senders.sampling.is_some());
        assert!(senders.elicitation.is_some());
    }

    #[test]
    fn bidirectional_senders_clone() {
        let senders =
            BidirectionalSenders::new().with_sampling(Arc::new(DummySamplingSender) as Arc<_>);
        let cloned = senders.clone();
        assert!(cloned.sampling.is_some());
    }

    #[test]
    fn bidirectional_senders_debug_with_present() {
        let senders = BidirectionalSenders::new()
            .with_sampling(Arc::new(DummySamplingSender) as Arc<_>)
            .with_elicitation(Arc::new(DummyElicitationSender) as Arc<_>);
        let debug = format!("{:?}", senders);
        assert!(debug.contains("sampling: true"));
        assert!(debug.contains("elicitation: true"));
    }

    // ── create_context_with_progress_and_senders ─────────────────────

    #[test]
    fn create_context_with_senders_sampling() {
        let cx = Cx::for_testing();
        let senders =
            BidirectionalSenders::new().with_sampling(Arc::new(DummySamplingSender) as Arc<_>);
        let ctx =
            create_context_with_progress_and_senders(cx, 1, None, None, |_| {}, Some(&senders));
        assert_eq!(ctx.request_id(), 1);
    }

    #[test]
    fn create_context_with_senders_elicitation() {
        let cx = Cx::for_testing();
        let senders = BidirectionalSenders::new()
            .with_elicitation(Arc::new(DummyElicitationSender) as Arc<_>);
        let ctx =
            create_context_with_progress_and_senders(cx, 2, None, None, |_| {}, Some(&senders));
        assert_eq!(ctx.request_id(), 2);
    }

    #[test]
    fn create_context_with_senders_and_progress() {
        let cx = Cx::for_testing();
        let marker = ProgressMarker::from("sp");
        let senders =
            BidirectionalSenders::new().with_sampling(Arc::new(DummySamplingSender) as Arc<_>);
        let ctx = create_context_with_progress_and_senders(
            cx,
            3,
            Some(marker),
            None,
            |_| {},
            Some(&senders),
        );
        assert_eq!(ctx.request_id(), 3);
    }

    #[test]
    fn create_context_with_senders_and_state() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        state.set("key", &"val");
        let senders = BidirectionalSenders::new()
            .with_elicitation(Arc::new(DummyElicitationSender) as Arc<_>);
        let ctx = create_context_with_progress_and_senders(
            cx,
            4,
            None,
            Some(state),
            |_| {},
            Some(&senders),
        );
        let val: Option<String> = ctx.get_state("key");
        assert_eq!(val.as_deref(), Some("val"));
    }

    #[test]
    fn create_context_with_all_options() {
        let cx = Cx::for_testing();
        let marker = ProgressMarker::from("all");
        let state = SessionState::new();
        let senders = BidirectionalSenders::new()
            .with_sampling(Arc::new(DummySamplingSender) as Arc<_>)
            .with_elicitation(Arc::new(DummyElicitationSender) as Arc<_>);
        let ctx = create_context_with_progress_and_senders(
            cx,
            5,
            Some(marker),
            Some(state),
            |_| {},
            Some(&senders),
        );
        assert_eq!(ctx.request_id(), 5);
    }

    #[test]
    fn create_context_with_senders_none() {
        let cx = Cx::for_testing();
        let ctx = create_context_with_progress_and_senders(cx, 6, None, None, |_| {}, None);
        assert_eq!(ctx.request_id(), 6);
    }

    // ── ToolHandler with overrides ───────────────────────────────────

    struct CustomTool;
    impl ToolHandler for CustomTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "custom".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn icon(&self) -> Option<&Icon> {
            Some(custom_icon())
        }

        fn version(&self) -> Option<&str> {
            Some("2.0")
        }

        fn timeout(&self) -> Option<Duration> {
            Some(Duration::from_secs(60))
        }

        fn output_schema(&self) -> Option<serde_json::Value> {
            Some(serde_json::json!({"type": "string"}))
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text("custom")])
        }
    }

    #[test]
    fn tool_handler_custom_version() {
        assert_eq!(CustomTool.version(), Some("2.0"));
    }

    #[test]
    fn tool_handler_custom_icon() {
        assert_eq!(
            CustomTool.icon().and_then(|icon| icon.src.as_deref()),
            Some("https://example.test/component.svg")
        );
    }

    #[test]
    fn tool_handler_custom_timeout() {
        assert_eq!(CustomTool.timeout(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn tool_handler_custom_output_schema() {
        let schema = CustomTool.output_schema().unwrap();
        assert_eq!(schema["type"], "string");
    }

    // ── ResourceHandler with overrides ───────────────────────────────

    struct CustomResource;
    impl ResourceHandler for CustomResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "file:///custom".to_string(),
                name: "custom".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn version(&self) -> Option<&str> {
            Some("1.5")
        }

        fn icon(&self) -> Option<&Icon> {
            Some(custom_icon())
        }

        fn timeout(&self) -> Option<Duration> {
            Some(Duration::from_secs(30))
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![ResourceContent {
                uri: "file:///custom".to_string(),
                mime_type: None,
                text: Some("data".to_string()),
                blob: None,
            }])
        }

        fn read_with_uri(
            &self,
            _ctx: &McpContext,
            uri: &str,
            params: &UriParams,
        ) -> McpResult<Vec<ResourceContent>> {
            let id = params.get("id").cloned().unwrap_or_default();
            Ok(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: None,
                text: Some(format!("item:{id}")),
                blob: None,
            }])
        }
    }

    #[test]
    fn resource_handler_custom_version() {
        assert_eq!(CustomResource.version(), Some("1.5"));
    }

    #[test]
    fn resource_handler_custom_icon() {
        assert_eq!(
            CustomResource.icon().and_then(|icon| icon.src.as_deref()),
            Some("https://example.test/component.svg")
        );
    }

    #[test]
    fn resource_handler_custom_timeout() {
        assert_eq!(CustomResource.timeout(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn resource_handler_read_with_uri_custom() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let mut params = UriParams::new();
        params.insert("id".to_string(), "42".to_string());
        let result = CustomResource
            .read_with_uri(&ctx, "file:///items/42", &params)
            .unwrap();
        assert_eq!(result[0].text.as_deref(), Some("item:42"));
    }

    // ── PromptHandler with overrides ─────────────────────────────────

    struct CustomPrompt;
    impl PromptHandler for CustomPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "custom".to_string(),
                description: None,
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn version(&self) -> Option<&str> {
            Some("3.0")
        }

        fn icon(&self) -> Option<&Icon> {
            Some(custom_icon())
        }

        fn timeout(&self) -> Option<Duration> {
            Some(Duration::from_secs(10))
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Ok(vec![])
        }
    }

    #[test]
    fn prompt_handler_custom_version() {
        assert_eq!(CustomPrompt.version(), Some("3.0"));
    }

    #[test]
    fn prompt_handler_custom_icon() {
        assert_eq!(
            CustomPrompt.icon().and_then(|icon| icon.src.as_deref()),
            Some("https://example.test/component.svg")
        );
    }

    #[test]
    fn prompt_handler_custom_timeout() {
        assert_eq!(CustomPrompt.timeout(), Some(Duration::from_secs(10)));
    }

    // ── MountedToolHandler icon/version delegation ───────────────────

    #[test]
    fn mounted_tool_handler_delegates_icon_and_version() {
        let inner = Box::new(CustomTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "m_custom".to_string());
        assert_eq!(mounted.version(), Some("2.0"));
        assert_eq!(
            mounted.icon().and_then(|icon| icon.src.as_deref()),
            Some("https://example.test/component.svg")
        );
    }

    #[test]
    fn mounted_tool_handler_delegates_timeout() {
        let inner = Box::new(CustomTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "m_custom".to_string());
        assert_eq!(mounted.timeout(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn mounted_tool_handler_delegates_output_schema() {
        let inner = Box::new(CustomTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "m_custom".to_string());
        let schema = mounted.output_schema().unwrap();
        assert_eq!(schema["type"], "string");
    }

    // ── MountedResourceHandler delegates ─────────────────────────────

    #[test]
    fn mounted_resource_handler_delegates_icon_and_version() {
        let inner = Box::new(CustomResource) as BoxedResourceHandler;
        let mounted = MountedResourceHandler::new(
            inner,
            "file:///custom".to_string(),
            "ns/file:///custom".to_string(),
        );
        assert_eq!(mounted.version(), Some("1.5"));
        assert_eq!(
            mounted.icon().and_then(|icon| icon.src.as_deref()),
            Some("https://example.test/component.svg")
        );
    }

    #[test]
    fn mounted_resource_handler_delegates_read_with_uri() {
        let inner = Box::new(CustomResource) as BoxedResourceHandler;
        let mounted = MountedResourceHandler::new(
            inner,
            "file:///custom".to_string(),
            "ns/file:///custom".to_string(),
        );
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let mut params = UriParams::new();
        params.insert("id".to_string(), "99".to_string());
        let result = mounted
            .read_with_uri(&ctx, "ns/file:///items/99", &params)
            .unwrap();
        assert_eq!(result[0].text.as_deref(), Some("item:99"));
        assert_eq!(result[0].uri, "ns/file:///items/99");
        assert!(
            mounted
                .read_with_uri(&ctx, "other/file:///items/99", &params)
                .is_err()
        );
    }

    #[test]
    fn mounted_resource_handler_delegates_timeout() {
        let inner = Box::new(CustomResource) as BoxedResourceHandler;
        let mounted = MountedResourceHandler::new(
            inner,
            "file:///custom".to_string(),
            "file:///m".to_string(),
        );
        assert_eq!(mounted.timeout(), Some(Duration::from_secs(30)));
    }

    // ── MountedPromptHandler delegates ───────────────────────────────

    #[test]
    fn mounted_prompt_handler_delegates_icon_and_version() {
        let inner = Box::new(CustomPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns_custom".to_string());
        assert_eq!(mounted.version(), Some("3.0"));
        assert_eq!(
            mounted.icon().and_then(|icon| icon.src.as_deref()),
            Some("https://example.test/component.svg")
        );
    }

    #[test]
    fn mounted_prompt_handler_delegates_timeout() {
        let inner = Box::new(CustomPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns_custom".to_string());
        assert_eq!(mounted.timeout(), Some(Duration::from_secs(10)));
    }

    #[test]
    fn mounted_prompt_handler_delegates_get_with_args() {
        let inner = Box::new(StubPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let mut args = HashMap::new();
        args.insert("key".to_string(), "value".to_string());
        let result = mounted.get(&ctx, args).unwrap();
        assert!(result.is_empty());
    }

    // ── ProgressNotificationSender multiple sends ────────────────────

    #[test]
    fn progress_sender_multiple_notifications() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender = ProgressNotificationSender::new(ProgressMarker::from("multi"), move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        sender.send_progress(0.0, Some(100.0), Some("starting"));
        sender.send_progress(50.0, Some(100.0), None);
        sender.send_progress(100.0, Some(100.0), Some("done"));

        let messages = sent.lock().unwrap();
        assert_eq!(messages.len(), 3);
    }

    // ── ToolHandler with custom tags and annotations ────────────────

    struct TaggedTool;
    impl ToolHandler for TaggedTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "tagged".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec!["db".to_string(), "read".to_string()],
                annotations: Some(ToolAnnotations {
                    destructive: Some(false),
                    idempotent: Some(true),
                    read_only: Some(true),
                    open_world_hint: None,
                }),
            }
        }
        fn tags(&self) -> &[String] {
            // Return from definition for consistency
            &[]
        }
        fn annotations(&self) -> Option<&ToolAnnotations> {
            None
        }
        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text("tagged")])
        }
    }

    #[test]
    fn tool_definition_includes_tags_and_annotations() {
        let def = TaggedTool.definition();
        assert_eq!(def.tags, vec!["db".to_string(), "read".to_string()]);
        let ann = def.annotations.unwrap();
        assert_eq!(ann.destructive, Some(false));
        assert_eq!(ann.idempotent, Some(true));
        assert_eq!(ann.read_only, Some(true));
    }

    // ── Async delegation via block_on ───────────────────────────────

    #[test]
    fn tool_call_async_delegates_to_sync() {
        let tool = StubTool;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(tool.call_async(&ctx, serde_json::json!({"x": 1})));
        match outcome {
            Outcome::Ok(content) => assert!(!content.is_empty()),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn resource_read_async_delegates_to_sync() {
        let res = StubResource;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(res.read_async(&ctx));
        match outcome {
            Outcome::Ok(content) => {
                assert_eq!(content.len(), 1);
                assert_eq!(content[0].text.as_deref(), Some("hello"));
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn resource_read_async_with_uri_empty_params_uses_read_async() {
        let res = StubResource;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let params = UriParams::new(); // empty
        let outcome =
            fastmcp_core::block_on(res.read_async_with_uri(&ctx, "file:///stub", &params));
        match outcome {
            Outcome::Ok(content) => assert_eq!(content[0].text.as_deref(), Some("hello")),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn resource_read_async_with_uri_nonempty_params_uses_read_with_uri() {
        let res = CustomResource;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let mut params = UriParams::new();
        params.insert("id".to_string(), "7".to_string());
        let outcome =
            fastmcp_core::block_on(res.read_async_with_uri(&ctx, "file:///items/7", &params));
        match outcome {
            Outcome::Ok(content) => assert_eq!(content[0].text.as_deref(), Some("item:7")),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn prompt_get_async_delegates_to_sync() {
        let prompt = StubPrompt;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(prompt.get_async(&ctx, HashMap::new()));
        match outcome {
            Outcome::Ok(messages) => assert!(messages.is_empty()),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    // ── Async error delegation ──────────────────────────────────────

    #[test]
    fn tool_call_async_propagates_error() {
        struct ErrTool;
        impl ToolHandler for ErrTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "err".to_string(),
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
                Err(McpError::internal_error("async-err"))
            }
        }
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(ErrTool.call_async(&ctx, serde_json::json!({})));
        match outcome {
            Outcome::Err(e) => assert!(e.message.contains("async-err")),
            other => panic!("expected Err, got {:?}", other),
        }
    }

    // ── MountedToolHandler async delegation ──────────────────────────

    #[test]
    fn mounted_tool_handler_delegates_call_async() {
        let inner = Box::new(StubTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "m_stub".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(mounted.call_async(&ctx, serde_json::json!({})));
        match outcome {
            Outcome::Ok(content) => assert!(!content.is_empty()),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    // ── MountedResourceHandler async delegation ─────────────────────

    #[test]
    fn mounted_resource_handler_delegates_read_async() {
        let inner = Box::new(StubResource) as BoxedResourceHandler;
        let mounted =
            MountedResourceHandler::new(inner, "file:///stub".to_string(), "file:///m".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(mounted.read_async(&ctx));
        match outcome {
            Outcome::Ok(content) => {
                assert_eq!(content.len(), 1);
                assert_eq!(content[0].uri, "file:///m");
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn mounted_resource_handler_delegates_read_async_with_uri() {
        let inner = Box::new(CustomResource) as BoxedResourceHandler;
        let mounted = MountedResourceHandler::new(
            inner,
            "file:///custom".to_string(),
            "ns/file:///custom".to_string(),
        );
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let mut params = UriParams::new();
        params.insert("id".to_string(), "5".to_string());
        let outcome = fastmcp_core::block_on(mounted.read_async_with_uri(
            &ctx,
            "ns/file:///items/5",
            &params,
        ));
        match outcome {
            Outcome::Ok(content) => {
                assert_eq!(content[0].text.as_deref(), Some("item:5"));
                assert_eq!(content[0].uri, "ns/file:///items/5");
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn mounted_resource_template_translates_true_async_request_and_result_uri() {
        struct AsyncTemplateResource;

        impl ResourceHandler for AsyncTemplateResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "db://placeholder".to_string(),
                    name: "async-template".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }

            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                panic!("the true-async override must be used")
            }

            fn read_async_with_uri<'a>(
                &'a self,
                _ctx: &'a McpContext,
                uri: &'a str,
                params: &'a UriParams,
            ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
                Box::pin(async move {
                    Outcome::Ok(vec![ResourceContent {
                        uri: uri.to_string(),
                        mime_type: None,
                        text: params.get("table").cloned(),
                        blob: None,
                    }])
                })
            }
        }

        let mounted = MountedResourceHandler::with_template(
            Box::new(AsyncTemplateResource),
            "db://{table}".to_string(),
            "ns/db://{table}".to_string(),
            ResourceTemplate {
                uri_template: "ns/db://{table}".to_string(),
                name: "async-template".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            },
        );
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let params = UriParams::from([("table".to_string(), "users".to_string())]);

        let outcome =
            fastmcp_core::block_on(mounted.read_async_with_uri(&ctx, "ns/db://users", &params));
        match outcome {
            Outcome::Ok(contents) => {
                assert_eq!(contents[0].uri, "ns/db://users");
                assert_eq!(contents[0].text.as_deref(), Some("users"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    // ── MountedPromptHandler async delegation ────────────────────────

    #[test]
    fn mounted_prompt_handler_delegates_get_async() {
        let inner = Box::new(StubPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(mounted.get_async(&ctx, HashMap::new()));
        match outcome {
            Outcome::Ok(messages) => assert!(messages.is_empty()),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    // ── Additional coverage ─────────────────────────────────────────

    #[test]
    fn progress_sender_with_message_but_no_total() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender = ProgressNotificationSender::new(ProgressMarker::from("tok-msg"), move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        sender.send_progress(2.0, None, Some("processing"));

        let messages = sent.lock().unwrap();
        let params = messages[0].params.as_ref().unwrap();
        assert_eq!(params["progress"], 2.0);
        assert_eq!(params["message"], "processing");
        assert!(params.get("total").is_none() || params["total"].is_null());
    }

    #[test]
    fn progress_notification_includes_progress_token() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender =
            ProgressNotificationSender::new(ProgressMarker::from("my-token"), move |req| {
                sent_clone.lock().unwrap().push(req);
            });

        sender.send_progress(1.0, None, None);

        let messages = sent.lock().unwrap();
        let params = messages[0].params.as_ref().unwrap();
        assert_eq!(params["progressToken"], "my-token");
    }

    #[test]
    fn resource_read_async_propagates_error() {
        struct ErrResource;
        impl ResourceHandler for ErrResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "file:///err".to_string(),
                    name: "err".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }
            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                Err(McpError::internal_error("read-fail"))
            }
        }

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(ErrResource.read_async(&ctx));
        match outcome {
            Outcome::Err(e) => assert!(e.message.contains("read-fail")),
            other => panic!("expected Err, got {:?}", other),
        }
    }

    #[test]
    fn prompt_get_async_propagates_error() {
        struct ErrPrompt;
        impl PromptHandler for ErrPrompt {
            fn definition(&self) -> Prompt {
                Prompt {
                    name: "err".to_string(),
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
                _args: HashMap<String, String>,
            ) -> McpResult<Vec<PromptMessage>> {
                Err(McpError::internal_error("get-fail"))
            }
        }

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(ErrPrompt.get_async(&ctx, HashMap::new()));
        match outcome {
            Outcome::Err(e) => assert!(e.message.contains("get-fail")),
            other => panic!("expected Err, got {:?}", other),
        }
    }

    #[test]
    fn resource_read_async_with_uri_nonempty_params_propagates_error() {
        struct ErrWithUri;
        impl ResourceHandler for ErrWithUri {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "file:///err".to_string(),
                    name: "err".to_string(),
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
            fn read_with_uri(
                &self,
                _ctx: &McpContext,
                _uri: &str,
                _params: &UriParams,
            ) -> McpResult<Vec<ResourceContent>> {
                Err(McpError::internal_error("uri-fail"))
            }
        }

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let mut params = UriParams::new();
        params.insert("id".to_string(), "1".to_string());
        let outcome =
            fastmcp_core::block_on(ErrWithUri.read_async_with_uri(&ctx, "file:///err", &params));
        match outcome {
            Outcome::Err(e) => assert!(e.message.contains("uri-fail")),
            other => panic!("expected Err, got {:?}", other),
        }
    }

    #[test]
    fn mounted_tool_definition_preserves_inner_fields() {
        let inner = Box::new(StubTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "renamed".to_string());
        let def = mounted.definition();
        assert_eq!(def.name, "renamed");
        assert_eq!(def.description.as_deref(), Some("a stub tool"));
        assert_eq!(def.input_schema, serde_json::json!({"type": "object"}));
    }
}
